namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixWait.finish`, which finishes a woken thread's call through the
/// finishing function of the call's family: it answers exactly what that
/// function answers, in the case named as the call's park is
/// (`FinishOracle.agree`), and refuses a thread parked in a reserved call.
///
/// The property here puts a thread to sleep in each kind of call this library
/// parks a thread in, under both flavours, and then lets the process's leader
/// give the call what it waits for, signal the sleeper, change the signal's
/// disposition, close the descriptors the call names, make one non-blocking,
/// and let time pass, between wakes and finishes; after each of those, every
/// thread a wake would wake is finished both ways. `TestMultiProcessFuzz` holds
/// `finish` to the same oracle over its interleavings of several processes.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixWaitFinish =

    /// The thread that sleeps. Thread 0, the leader, makes every other call.
    let private sleeper : int = 1

    let private port : uint16 = 5000us

    /// A kind of call the sleeper sleeps in.
    [<RequireQualifiedAccess>]
    type private Sleep =
        | PipeRead
        | PipeWrite
        | Poll
        | EpollWait
        | Kevent
        | Flock
        | Accept
        | ConnectionRead
        | ConnectionWrite
        | InotifyRead
        | SigSuspend
        | Pause

    /// The kinds of call a thread of `flavour` can sleep in.
    let private sleepsOn (flavour : SimulatedUnixFlavour) : Sleep list =
        let common =
            [
                Sleep.PipeRead
                Sleep.PipeWrite
                Sleep.Poll
                Sleep.Flock
                Sleep.Accept
                Sleep.ConnectionRead
                Sleep.ConnectionWrite
                Sleep.SigSuspend
                Sleep.Pause
            ]

        match flavour with
        | SimulatedUnixFlavour.Linux -> common @ [ Sleep.EpollWait ; Sleep.InotifyRead ]
        | SimulatedUnixFlavour.Darwin -> common @ [ Sleep.Kevent ]

    /// Something the leader does, or the client does to the machine, while the
    /// sleeper sleeps.
    [<RequireQualifiedAccess>]
    type private Event =
        /// The leader gives the sleeper's call what it waits for: a byte, room,
        /// a connection, the lock let go of, a record; or, for a `sigsuspend`
        /// or `pause`, SIGUSR1.
        | Ready
        /// The leader sends the sleeper SIGUSR1.
        | Signal
        /// The leader installs a handler for SIGUSR1, with `SA_RESTART` or not.
        | Catch of restart : bool
        /// The leader ignores SIGUSR1.
        | Ignore
        /// The leader resets SIGUSR1 to its default, which terminates.
        | Default
        /// The leader closes the descriptor the sleeper's call was made
        /// through.
        | CloseThrough
        /// The leader closes the descriptor it gives the call what it waits
        /// for through: the pipe's other end, the peer socket, the lock's
        /// other holder.
        | CloseFar
        /// The leader makes the description the sleeper's call was made
        /// through non-blocking.
        | NonBlocking
        /// Ten milliseconds pass, past a timed wait's five.
        | Advance
        /// The client asks `UnixWait.wake`, and keeps the system it answers.
        | Wake
        /// The client finishes the sleeper's call through `UnixWait.finish`,
        /// if it has been woken, and returns the sleeper to user mode if the
        /// call answered.
        | Finish

    type private Case =
        {
            Flavour : SimulatedUnixFlavour
            Sleep : Sleep
            /// SIGUSR1's handler has `SA_RESTART`.
            Restart : bool
            /// A `poll`, `epoll_wait` or `kevent` waits five milliseconds,
            /// rather than for ever.
            Timed : bool
            Events : Event list
        }

    let private eventGen : Gen<Event> =
        Gen.frequency
            [
                4, Gen.constant Event.Ready
                4, Gen.constant Event.Signal
                2, Gen.map Event.Catch (Gen.elements [ true ; false ])
                2, Gen.constant Event.Ignore
                1, Gen.constant Event.Default
                1, Gen.constant Event.CloseThrough
                1, Gen.constant Event.CloseFar
                1, Gen.constant Event.NonBlocking
                1, Gen.constant Event.Advance
                4, Gen.constant Event.Wake
                4, Gen.constant Event.Finish
            ]

    let private caseGen : Gen<Case> =
        gen {
            let! flavour = Gen.elements [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]
            let! sleep = Gen.elements (sleepsOn flavour)
            let! restart = Gen.elements [ true ; false ]
            let! timed = Gen.elements [ true ; false ]
            let! length = Gen.choose (1, 12)
            let! events = Gen.listOfLength length eventGen

            return
                {
                    Flavour = flavour
                    Sleep = sleep
                    Restart = restart
                    Timed = timed
                    Events = events
                }
        }

    /// The machine, and what the sleeper's call names.
    type private World =
        {
            System : UnixSystem<int, string>
            /// The descriptor the sleeper's call was made through, until the
            /// leader closes it.
            Through : int option
            /// The descriptor the leader gives the call what it waits for
            /// through, until the leader closes it.
            Far : int option
            /// How many directories the leader has made, for an inotify read.
            Made : int
        }

    let private usr1 (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGUSR1

    /// `system` after the leader's call, the leader returned to user mode.
    let private returned (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        ReturnsToUser.untilResumed (Callers.leader system) system

    /// `disposition` installed for `signal` by the leader.
    let private install
        (signal : Signal)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let signo =
            Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) signal

        match UnixSignal.sigaction (Callers.leader system) signo (Some disposition) system with
        | Ok (_, system) -> returned system
        | Error error -> failwith $"sigaction of %O{signal}: %O{error}"

    let private handler (restart : bool) : SignalDisposition<string> =
        SignalDisposition.Catch
            { SignalCatch.ofHandler "h" with
                Restart = restart
            }

    let private pipe (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        match UnixPipe.pipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (r, w), system -> r, w, returned system
        | other, _ -> failwith $"pipe2: %A{other}"

    let private nonBlocking (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixDescriptor.setNonBlocking (Callers.leader system) fd true system
        |> snd
        |> returned

    /// A write by the leader of `count` bytes to `fd`, whatever it answers.
    let private leaderWrite (fd : int) (count : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match
            WriteOutcomes.admitThenWrite
                0
                fd
                UserBuffer.Mapped
                (ImmutableArray.Create<byte> (Array.zeroCreate<byte> count))
                system
        with
        | Ok (WriteStep.Returns (_, system))
        | Ok (WriteStep.ReturnsRaising (_, _, system)) -> returned system
        | other -> failwith $"the leader's write to fd %d{fd}: %A{other}"

    /// The leader's writes of 64 KiB through `fd`, then of one byte, each until
    /// `EAGAIN`, `fd` left blocking.
    let private fill (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let system = nonBlocking fd system

        let rec go (chunk : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match
                WriteOutcomes.admitThenWrite
                    0
                    fd
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> chunk))
                    system
            with
            | Ok (WriteStep.Returns (WriteAnswer.Completed _, system)) -> go chunk (returned system)
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.EAGAIN, system)) -> returned system
            | other -> failwith $"filling fd %d{fd}: %A{other}"

        let system = system |> go 65536 |> go 1

        UnixDescriptor.setNonBlocking (Callers.leader system) fd false system
        |> snd
        |> returned

    /// A read by the leader of up to 64 KiB from `fd`, which must be
    /// non-blocking, whatever it answers.
    let private leaderRead (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixReadWrite.read (Callers.leader system) fd UserBuffer.Mapped 65536UL system with
        | ReadOutcome.Answered _, system -> returned system
        | other, _ -> failwith $"the leader's read of fd %d{fd}: %A{other}"

    /// A connected loopback pair, made by the leader: the connecting socket's
    /// descriptor, blocking, then the accepted one's, non-blocking.
    let private tcpPair (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        let leader = Callers.leader system
        let listener, system = KeventWorld.listenerAtAs leader port system
        let client, system = KeventWorld.streamAs leader false system

        let system =
            match KeventWorld.connectAs leader client port system with
            | SyscallAnswer.Completed 0L, system -> returned system
            | other -> failwith $"connect: %A{other}"

        let server, system = KeventWorld.acceptAs leader listener system
        let system = KeventWorld.closeAs leader listener system
        client, server, nonBlocking server system

    let private sleeps<'Answer, 'Refusal>
        (what : string)
        (isPark : 'Answer -> bool)
        (outcome : Result<'Answer * UnixSystem<int, string>, 'Refusal>)
        : UnixSystem<int, string>
        =
        match outcome with
        | Ok (answer, system) when isPark answer -> system
        | other -> failwith $"expected the %s{what} to sleep, got %A{other}"

    /// The world of `case` with the sleeper asleep in its call.
    let private asleep (case : Case) : World =
        let platform = HostPlatform.platformOf case.Flavour

        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn sleeper
            |> install Signal.SIGUSR1 (handler case.Restart)
            |> install Signal.SIGPIPE SignalDisposition.Ignore

        let s (system : UnixSystem<int, string>) = Callers.thread sleeper system
        let milliseconds = if case.Timed then 5 else -1

        let world (through : int option) (far : int option) (system : UnixSystem<int, string>) : World =
            {
                System = system
                Through = through
                Far = far
                Made = 0
            }

        match case.Sleep with
        | Sleep.PipeRead ->
            let r, w, system = pipe system

            UnixReadWrite.tryRead (s system) r UserBuffer.Mapped 16UL system
            |> sleeps
                "read"
                (fun outcome ->
                    match outcome with
                    | ReadOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some r) (Some w)
        | Sleep.PipeWrite ->
            let r, w, system = pipe system
            let system = system |> fill w |> nonBlocking r

            match
                WriteOutcomes.admitThenWrite
                    sleeper
                    w
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> 5000))
                    system
            with
            | Ok (WriteStep.WouldBlock (_, system)) -> world (Some w) (Some r) system
            | other -> failwith $"expected the write to sleep, got %A{other}"
        | Sleep.Poll ->
            let r, w, system = pipe system

            UnixPoll.tryPoll
                (s system)
                [
                    {
                        Fd = r
                        Events = 0x0001s
                    }
                ]
                milliseconds
                system
            |> sleeps
                "poll"
                (fun outcome ->
                    match outcome with
                    | PollOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some r) (Some w)
        | Sleep.EpollWait ->
            let leader = Callers.leader system
            let listener, system = KeventWorld.listenerAtAs leader port system

            let epoll, system =
                match UnixPoll.epollCreate1 leader 0 system with
                | Ok (fd, system) -> fd, returned system
                | Error error -> failwith $"epoll_create1: %O{error}"

            let system =
                match
                    UnixPoll.epollCtl
                        leader
                        epoll
                        1
                        listener
                        (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 7UL))
                        system
                with
                | EpollCtlAnswer.Changed, system -> returned system
                | other -> failwith $"epoll_ctl: %A{other}"

            UnixPoll.tryEpollWait (s system) epoll 1 UserBuffer.Mapped milliseconds system
            |> sleeps
                "epoll_wait"
                (fun outcome ->
                    match outcome with
                    | EpollWaitOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some epoll) (Some listener)
        | Sleep.Kevent ->
            let leader = Callers.leader system
            let listener, system = KeventWorld.listenerAtAs leader port system
            let kq, system = KeventWorld.kqueueAs leader system

            let system =
                match KeventWorld.applyAs leader kq [ KeventWorld.change listener -1s 0x0001us 7UL ] 0 system with
                | KeventOutcome.Answered [], system -> returned system
                | other, _ -> failwith $"registering EVFILT_READ: %A{other}"

            let timeout =
                if case.Timed then
                    KeventTimeout.Readable (0L, 5_000_000L)
                else
                    KeventTimeout.Null

            UnixKqueue.tryKevent (s system) kq 0 [] 1 UserBuffer.Mapped timeout system
            |> sleeps
                "kevent"
                (fun outcome ->
                    match outcome with
                    | KeventOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some kq) (Some listener)
        | Sleep.Flock ->
            let flags =
                OpenFlagWords.bitOf (UnixSystem.platform system) OpenFlagBit.Create ||| 2

            let opened (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
                match OpenOutcomes.openPath flags (PathArg.ofText "/lock") 0o644 system with
                | Ok (SyscallAnswer.Completed fd, system) -> int fd, returned system
                | other -> failwith $"open: %A{other}"

            let holder, system = opened system
            let waiter, system = opened system

            let system =
                match UnixDescriptor.tryFlock (Callers.leader system) holder 2 system with
                | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> returned system
                | other -> failwith $"the holder's flock: %A{other}"

            UnixDescriptor.tryFlock (s system) waiter 2 system
            |> sleeps
                "flock"
                (fun outcome ->
                    match outcome with
                    | SyscallOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some waiter) (Some holder)
        | Sleep.Accept ->
            let listener, system = KeventWorld.listenerAtAs (Callers.leader system) port system

            UnixConnection.tryAccept (s system) listener UserBuffer.Mapped 16u system
            |> sleeps
                "accept"
                (fun outcome ->
                    match outcome with
                    | AcceptOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some listener) None
        | Sleep.ConnectionRead ->
            let client, server, system = tcpPair system

            UnixReadWrite.tryRead (s system) client UserBuffer.Mapped 16UL system
            |> sleeps
                "TCP read"
                (fun outcome ->
                    match outcome with
                    | ReadOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some client) (Some server)
        | Sleep.ConnectionWrite ->
            let client, server, system = tcpPair system
            let system = fill client system

            match
                WriteOutcomes.admitThenWrite
                    sleeper
                    client
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> 5000))
                    system
            with
            | Ok (WriteStep.WouldBlock (_, system)) -> world (Some client) (Some server) system
            | other -> failwith $"expected the TCP write to sleep, got %A{other}"
        | Sleep.InotifyRead ->
            let fd, system =
                match UnixInotify.inotifyInit1 (Callers.leader system) 0 system with
                | Ok (fd, system) -> fd, returned system
                | Error error -> failwith $"inotify_init1: %O{error}"

            let system =
                match Eager.tryInotifyAddWatch fd (PathArg.ofText "/") 0x100u system with
                | Ok (_, system) -> returned system
                | Error refusal -> failwith $"inotify_add_watch: %A{refusal}"

            UnixReadWrite.tryRead (s system) fd UserBuffer.Mapped 4096UL system
            |> sleeps
                "inotify read"
                (fun outcome ->
                    match outcome with
                    | ReadOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world (Some fd) None
        | Sleep.SigSuspend ->
            UnixSignal.trySigsuspend (s system) SignalMask.empty system
            |> sleeps
                "sigsuspend"
                (fun outcome ->
                    match outcome with
                    | SigsuspendOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world None None
        | Sleep.Pause ->
            UnixSignal.tryPause (s system) system
            |> sleeps
                "pause"
                (fun outcome ->
                    match outcome with
                    | SigsuspendOutcome.WouldBlock _ -> true
                    | _ -> false
                )
            |> world None None

    /// The sleeper's return to user mode after its call answered or was
    /// interrupted, each handler it takes running and returning: the system
    /// it runs its own code in, or `None` if the return ended the process or
    /// was refused.
    let private returnOfSleeper (system : UnixSystem<int, string>) : UnixSystem<int, string> option =
        let caller = Callers.thread sleeper system

        match UnixSignal.tryOnReturnToUser caller system with
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes _, system)) -> Some system
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, _), system)) ->
            Some (ReturnsToUser.handlersReturn caller frames system)
        | Ok (ProcessFate.Continues (outcome, _)) -> failwith $"the sleeper's return took %A{outcome}"
        | Ok (ProcessFate.ProcessEnded _)
        | Error _ -> None

    /// The sleeper's call, finished through `UnixWait.finish` if it has been
    /// woken: the system after, the sleeper asleep again or returned to user
    /// mode; `system` itself if it has not been woken, or the finish was
    /// refused; or `None` if the process ended.
    let private finishSleeper (system : UnixSystem<int, string>) : UnixSystem<int, string> option =
        let woken =
            match UnixThreadTable.parkOf sleeper (Lone.threads system) with
            | Some {
                       State = ParkState.Woken _
                   } -> true
            | _ -> false

        if not woken then
            Some system
        else

        let caller = Callers.thread sleeper system

        let write
            (progress : CallProgress<PausedWrite<int, string>, ProcessFate<WriteOutcome<int>, int, string>>)
            : UnixSystem<int, string> option
            =
            let fate =
                match progress with
                | CallProgress.Answered fate -> Ok fate
                | CallProgress.NeedsCopyIn paused ->
                    let range = PausedWrite.copyRange paused

                    UnixReadWrite.tryWriteWithBytes
                        (ImmutableArray.Create<byte> (Array.zeroCreate<byte> range.ByteCount))
                        paused

            match fate with
            | Ok (ProcessFate.Continues (WriteOutcome.WouldBlock _, system)) -> Some system
            | Ok (ProcessFate.Continues (_, system)) -> returnOfSleeper system
            | Ok (ProcessFate.ProcessEnded _) -> None
            | Error _ -> Some system

        let answered (sleepsAgain : bool) (after : UnixSystem<int, string>) : UnixSystem<int, string> option =
            if sleepsAgain then Some after else returnOfSleeper after

        match UnixWait.tryFinish caller system with
        | Error _ -> Some system
        | Ok (FinishedCall.PipeWrite progress)
        | Ok (FinishedCall.ConnectionWrite progress) -> write progress
        | Ok (FinishedCall.EpollWait (outcome, after)) -> answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.Kevent (outcome, after)) -> answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.Flock (outcome, after)) -> answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.Poll (outcome, after))
        | Ok (FinishedCall.KqueuePoll (outcome, after)) -> answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.Accept (outcome, after)) -> answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.PipeRead (outcome, after))
        | Ok (FinishedCall.ConnectionRead (outcome, after))
        | Ok (FinishedCall.InotifyRead (outcome, after)) ->
            answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.SigSuspend (outcome, after)) -> answered (UnionCaseName.ofValue outcome = "WouldBlock") after
        | Ok (FinishedCall.Sleep _)
        | Ok (FinishedCall.FifoOpen _)
        | Ok (FinishedCall.Select _)
        | Ok (FinishedCall.SignalWait _)
        | Ok (FinishedCall.DatagramReceive _)
        | Ok (FinishedCall.DatagramSend _)
        | Ok (FinishedCall.Connect _) -> failwith "finish answered a reserved park, which nothing parks a thread in"

    /// `world` after `event`, or `None` if it ended the process. A leader's call
    /// the library refuses changes nothing.
    let private apply (sleep : Sleep) (event : Event) (world : World) : World option =
        let system = world.System
        let leader = Callers.leader system

        let signal (system : UnixSystem<int, string>) : UnixSystem<int, string> option =
            match UnixSignal.pthreadKill leader sleeper (usr1 system) system with
            | Ok (ProcessFate.Continues (_, system)) -> Some (returned system)
            | Ok (ProcessFate.ProcessEnded _) -> None
            | Error error -> failwith $"pthread_kill: %O{error}"

        let withSystem (system : UnixSystem<int, string>) : World option =
            Some
                { world with
                    System = system
                }

        try
            match event with
            | Event.Ready ->
                match sleep, world.Far with
                | Sleep.PipeRead, Some w
                | Sleep.Poll, Some w -> withSystem (leaderWrite w 1 system)
                | Sleep.PipeWrite, Some r
                | Sleep.ConnectionWrite, Some r -> withSystem (leaderRead r system)
                | Sleep.ConnectionRead, Some server -> withSystem (leaderWrite server 100 system)
                | Sleep.Flock, Some holder ->
                    match UnixDescriptor.flock leader holder 8 system with
                    | SyscallOutcome.Answered _, system -> withSystem (returned system)
                    | other -> failwith $"the holder's unlock: %A{other}"
                | Sleep.EpollWait, _
                | Sleep.Kevent, _
                | Sleep.Accept, _ ->
                    let _, system = KeventWorld.clientAs leader port system
                    withSystem (returned system)
                | Sleep.InotifyRead, _ ->
                    match UnixNamespace.mkdir leader (PathArg.ofText $"/d%d{world.Made}") 0o755 system with
                    | _, system ->
                        Some
                            { world with
                                System = returned system
                                Made = world.Made + 1
                            }
                | Sleep.SigSuspend, _
                | Sleep.Pause, _ ->
                    signal system
                    |> Option.map (fun system ->
                        { world with
                            System = system
                        }
                    )
                | Sleep.PipeRead, None
                | Sleep.Poll, None
                | Sleep.PipeWrite, None
                | Sleep.ConnectionWrite, None
                | Sleep.ConnectionRead, None
                | Sleep.Flock, None -> Some world
            | Event.Signal ->
                signal system
                |> Option.map (fun system ->
                    { world with
                        System = system
                    }
                )
            | Event.Catch restart -> withSystem (install Signal.SIGUSR1 (handler restart) system)
            | Event.Ignore -> withSystem (install Signal.SIGUSR1 SignalDisposition.Ignore system)
            | Event.Default -> withSystem (install Signal.SIGUSR1 SignalDisposition.Default system)
            | Event.CloseThrough ->
                match world.Through with
                | None -> Some world
                | Some fd ->
                    match UnixDescriptor.close leader fd system with
                    | _, system ->
                        Some
                            { world with
                                System = returned system
                                Through = None
                            }
            | Event.CloseFar ->
                match world.Far with
                | None -> Some world
                | Some fd ->
                    match UnixDescriptor.close leader fd system with
                    | _, system ->
                        Some
                            { world with
                                System = returned system
                                Far = None
                            }
            | Event.NonBlocking ->
                match world.Through with
                | None -> Some world
                | Some fd -> withSystem (nonBlocking fd system)
            | Event.Advance -> withSystem (UnixSystem.advanceClock 10_000_000L system)
            | Event.Wake -> withSystem (snd (UnixWait.wake system))
            | Event.Finish -> finishSleeper system |> Option.bind withSystem
        with :? UnmodelledException ->
            Some world

    /// `FinishOracle.agree` for every thread a wake of `system` would wake, in
    /// the system the wake answers, each label counted.
    let private agreeForWoken (cover : string -> unit) (system : UnixSystem<int, string>) : unit =
        let _, woken = UnixWait.wake system

        for KeyValue (thread, state) in Lone.threads woken do
            match UnixThreadState.park state with
            | Some {
                       State = ParkState.Woken _
                   } -> cover (FinishOracle.agree (Callers.thread thread woken) woken)
            | Some {
                       State = ParkState.Asleep
                   }
            | None -> ()

    let private property (cover : string -> unit) (case : Case) : unit =
        let world = asleep case
        agreeForWoken cover world.System

        (Some world, case.Events)
        ||> List.fold (fun world event ->
            match world with
            | None -> None
            | Some world ->
                let after = apply case.Sleep event world

                match after with
                | Some after -> agreeForWoken cover after.System
                | None -> ()

                after
        )
        |> ignore

    /// The labels `FinishOracle.agree` gave whose kind is `kind` and whose
    /// outcome `outcome` accepts, summed.
    let private reached (coverage : Coverage<string>) (kind : string) (outcome : string -> bool) : int =
        coverage.Reached
        |> List.sumBy (fun (label : string, count) ->
            match label.Split ([| ' ' |], 2) with
            | [| labelKind ; rest |] when labelKind = kind ->
                let outcomeName = rest.Split([| ',' |]).[0]
                if outcome outcomeName then count else 0
            | _ -> 0
        )

    /// For every woken thread of every world the events reach, `UnixWait.finish`
    /// answers exactly what the finishing function of its call's family
    /// answers, in the case named as its park is. Every kind of call this
    /// library parks a thread in is finished both ways, as an answer and as an
    /// interruption (a `sigsuspend` or `pause` only ever as an interruption);
    /// and an answer that leaves the thread a signal to take, a write stopped
    /// at its copy, and a refusal are reached.
    [<Test>]
    let ``finish answers what each woken call's own finishing function answers`` () : unit =
        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 600) (Arb.fromGen caseGen) property

        let interrupted (outcome : string) : bool = outcome = "Interrupted"

        let answer (outcome : string) : bool =
            not (List.contains outcome [ "Interrupted" ; "WouldBlock" ; "refused" ])

        // Each floor is about a third of what the fixed sample reached when
        // this was written: a kind, how often a finish of it was interrupted,
        // and how often it answered, neither asleep again nor refused.
        let floors =
            [
                "Accept", 18, Some 71
                "ConnectionRead", 6, Some 47
                "ConnectionWrite", 24, Some 38
                "EpollWait", 11, Some 19
                "Flock", 11, Some 37
                "InotifyRead", 8, Some 22
                "Kevent", 13, Some 17
                "KqueuePoll", 9, Some 14
                "PipeRead", 13, Some 70
                "PipeWrite", 15, Some 47
                "Poll", 3, Some 16
                // A `sigsuspend` or `pause` ends only as an interruption.
                "SigSuspend", 78, None
            ]

        for kind, interruptions, answers in floors do
            reached coverage kind interrupted |> shouldBeGreaterThan interruptions

            match answers with
            | Some answers -> reached coverage kind answer |> shouldBeGreaterThan answers
            | None -> reached coverage kind answer |> shouldEqual 0

        let labelled (part : string) : int =
            coverage.Reached
            |> List.sumBy (fun (label : string, count) -> if label.Contains part then count else 0)

        labelled "owing SignalDue" |> shouldBeGreaterThan 60
        labelled "NeedsCopyIn" |> shouldBeGreaterThan 45
        labelled "refused" |> shouldBeGreaterThan 90

    /// A thread parked in each of the reserved calls, which nothing parks a
    /// thread in yet, as the tests of each reserved park forge one, the
    /// descriptions they hold being the standard input's.
    let private reservedParks (system : UnixSystem<int, string>) : ParkedSyscall list =
        let stdin =
            match FileDescriptorRegistry.tryFindId 0 (Lone.fileDescriptors system) with
            | Some id -> id
            | None -> failwith "fd 0 names no description"

        let numbering = SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)

        [
            ParkedSyscall.Sleep
                {
                    Deadline = 1_000_000L
                    Remainder = SleepRemainder.Unreported
                }
            ParkedSyscall.FifoOpen
                {
                    Opener = stdin
                    Descriptor = 3
                    PartnerOpens = 0L
                }
            ParkedSyscall.Select
                {
                    ParkedSelect.Deadline = None
                }
            ParkedSyscall.SignalWait
                {
                    Awaited = SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR1)
                    Deadline = None
                    Destination = None
                }
            ParkedSyscall.DatagramReceive
                {
                    ParkedDatagramReceive.Socket = stdin
                }
            ParkedSyscall.DatagramSend
                {
                    ParkedDatagramSend.Socket = stdin
                }
            ParkedSyscall.Connect
                {
                    ParkedConnect.Socket = stdin
                }
        ]

    /// `finish` of a woken thread parked in a reserved call refuses, as a call
    /// the model does not cover: `UnmodelledException` from `UnixWait.finish`,
    /// naming it, and `FinishRefusal.Reserved` of the park from the internal
    /// `tryFinish`. Every reserved park is one.
    [<Test>]
    let ``finish refuses a thread woken in a reserved call`` () : unit =
        for flavour in [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ] do
            let awake =
                UnixSystem.initial<int, string> (HostPlatform.platformOf flavour)
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
                |> Threads.spawn sleeper

            let parks = reservedParks awake

            parks
            |> List.map UnionCaseName.ofValue
            |> shouldEqual
                [
                    "Sleep"
                    "FifoOpen"
                    "Select"
                    "SignalWait"
                    "DatagramReceive"
                    "DatagramSend"
                    "Connect"
                ]

            for parked in parks do
                let woken = awake |> Lone.Parking.park sleeper parked |> ForgedPark.woken sleeper
                let caller = Callers.thread sleeper woken

                match UnixWait.tryFinish caller woken with
                | Error (FinishRefusal.Reserved refused) -> refused |> shouldEqual parked
                | Error refusal -> failwith $"%O{flavour}, %A{parked}: refused with %A{refusal}"
                | Ok finished ->
                    failwith $"%O{flavour}, %A{parked}: answered FinishedCall.%s{UnionCaseName.ofValue finished}"

                let thrown =
                    try
                        UnixWait.finish caller woken |> ignore<FinishedCall<int, string>>
                        None
                    with e ->
                        Some e

                match thrown with
                | Some (:? UnmodelledException as e) -> e.Message.StartsWith "UnixWait.finish: " |> shouldEqual true
                | other -> failwith $"%O{flavour}, %A{parked}: expected UnmodelledException, got %A{other}"
