namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A sleeping call that two of the things that end its sleep reach one after
/// the other, the first having woken its thread and the second arriving before
/// the woken thread's call is finished.
///
/// `docs/probes/first-wake` measured, on Linux 6.18.5 and Darwin 27.0.0, a
/// thread asleep in each blocking call, held off the processor while two
/// events were made in turn: the call's own event (a connection, an unlock,
/// bytes, room), a caught signal, the call's deadline, a close of the kqueue
/// it waits on, or the far end of its pipe or socket going. And two threads
/// asleep in one call, the one the queue wakes first signalled, to see whether
/// the other still waits behind it. Every held row is replayed here as a
/// client makes it: each event a step, `UnixWait.wake` after each, and then
/// the woken calls finished, the first sleeper's before the other's.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFirstWake =

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    let private port : uint16 = 5000us

    // ------------------------------------------------------------------
    // The probe's rows
    // ------------------------------------------------------------------

    [<RequireQualifiedAccess>]
    type private Event =
        | Own
        | Signal
        | Deadline
        | Drain
        | Close

    type private Row =
        {
            Flavour : SimulatedUnixFlavour
            Call : string
            Sleepers : int
            First : Event
            Second : Event
            /// What the held trials answered, as the probe prints it; where no
            /// trial could hold (the second event cannot come between), what
            /// every trial answered.
            Answer : string
            Line : string
        }

    let private eventOf (name : string) : Event =
        match name with
        | "own" -> Event.Own
        | "signal" -> Event.Signal
        | "deadline" -> Event.Deadline
        | "drain" -> Event.Drain
        | "close" -> Event.Close
        | other -> failwith $"no event %s{other}"

    let private summaryPattern : Regex =
        Regex
            @"^(linux|darwin) call=(\S+) sleepers=([12]) order=(\w+),(\w+) summary held=(\d+)/10((?: \[[^\]]+\]x\d+)*) unheld:((?: \[[^\]]+\]x\d+)*)$"

    let private answerPattern : Regex = Regex @"\[([^\]]+)\]x\d+"

    /// The summary of each row of `flavour`'s committed output.
    let private rows (flavour : SimulatedUnixFlavour) : Row list =
        let name =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.first-wake.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.first-wake.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new System.IO.StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.filter (fun line -> line.Contains " summary ")
        |> Array.map (fun line ->
            let m = summaryPattern.Match line

            if not m.Success then
                failwith $"not a summary of the probe: %s{line}"

            let answers (group : int) : string list =
                answerPattern.Matches m.Groups.[group].Value
                |> Seq.map (fun answer -> answer.Groups.[1].Value)
                |> List.ofSeq

            // Every held trial of a row answered alike; a row in which none
            // held is one whose second event waits for the sleeper to leave
            // its call, so every trial answers as the first event alone does.
            let answer =
                match answers 7, answers 8 with
                | [ held ], _ -> held
                | [], [ unheld ] -> unheld
                | held, unheld -> failwith $"no single answer (held %A{held}, unheld %A{unheld}): %s{line}"

            {
                Flavour = flavour
                Call = m.Groups.[2].Value
                Sleepers = int m.Groups.[3].Value
                First = eventOf m.Groups.[4].Value
                Second = eventOf m.Groups.[5].Value
                Answer = answer
                Line = line
            }
        )
        |> List.ofArray

    // ------------------------------------------------------------------
    // Each call, made asleep as the probe made it
    // ------------------------------------------------------------------

    let private leader (system : UnixSystem<int, string>) : Caller<int> = Callers.leader system

    let private signo (signal : Signal) (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) signal

    let private installed
        (signal : Signal)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction (leader system) (signo signal system) (Some disposition) system with
        | SigactionAnswer.Completed _, system -> system
        | SigactionAnswer.Failed error, _ -> failwith $"sigaction failed with %O{error}"

    let private pipe (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        match UnixPipe.tryPipe2 (leader system) 0 UserBuffer.Mapped system with
        | Ok (Pipe2Answer.Created (r, w), system) -> r, w, system
        | other -> failwith $"pipe2: %A{other}"

    let private nonBlocking (fd : int) (value : bool) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixDescriptor.setNonBlocking (leader system) fd value system |> snd

    /// The leader's non-blocking writes of 64 KiB through `fd` until `EAGAIN`,
    /// then of one byte until `EAGAIN`, `fd` left blocking.
    let private fill (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let rec go (chunk : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match
                WriteOutcomes.admitThenWrite
                    0
                    fd
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> chunk))
                    system
            with
            | Ok (WriteStep.Returns (WriteAnswer.Completed _, system)) -> go chunk system
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.EAGAIN, system)) -> system
            | other -> failwith $"filling fd %d{fd}: %A{other}"

        system |> nonBlocking fd true |> go 65536 |> go 1 |> nonBlocking fd false

    /// The leader's non-blocking reads through `fd` until `EAGAIN`, `fd` left
    /// non-blocking.
    let private drain (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let rec go (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixReadWrite.tryRead (leader system) fd UserBuffer.Mapped 65536UL system with
            | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) when bytes.Length > 0 -> go system
            | Ok (ReadOutcome.Answered (ReadAnswer.Failed UnixError.EAGAIN), system) -> system
            | other -> failwith $"draining fd %d{fd}: %A{other}"

        system |> nonBlocking fd true |> go

    /// A connected loopback pair, both ends blocking: the connecting socket's
    /// descriptor, then the accepted one's.
    let private tcpPair (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        let listener, system = KeventWorld.listenerAt port system
        let client, system = KeventWorld.stream false system

        let system =
            match KeventWorld.connect client port system with
            | SyscallAnswer.Completed 0L, system -> system
            | other, _ -> failwith $"connect: %A{other}"

        let server, system = KeventWorld.accept listener system
        let system = KeventWorld.close listener system
        client, server, nonBlocking server false system

    let private writeOne (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match WriteOutcomes.admitThenWrite 0 fd UserBuffer.Mapped (ImmutableArray.Create<byte> [| 7uy |]) system with
        | Ok (WriteStep.Returns (WriteAnswer.Completed 1L, system)) -> system
        | other -> failwith $"writing a byte through fd %d{fd}: %A{other}"

    let private sleeps<'Answer, 'Refusal>
        (what : string)
        (isPark : 'Answer -> bool)
        (outcome : Result<'Answer * UnixSystem<int, string>, 'Refusal>)
        : UnixSystem<int, string>
        =
        match outcome with
        | Ok (answer, system) when isPark answer -> system
        | other -> failwith $"expected the %s{what} to sleep, got %A{other}"

    let private readParks (outcome : ReadOutcome) : bool =
        match outcome with
        | ReadOutcome.WouldBlock _ -> true
        | _ -> false

    /// How a woken call finished, as the probe prints it: the answer, or
    /// `asleep` for a call asleep again, or `refused` with why.
    type private Finished =
        | Answered of answer : string * system : UnixSystem<int, string>
        | Asleep of system : UnixSystem<int, string>
        | Refused of why : string

    /// A machine with its sleepers asleep in one call, and what the events
    /// and the finishing do to it.
    type private World =
        {
            System : UnixSystem<int, string>
            Own : UnixSystem<int, string> -> UnixSystem<int, string>
            Close : UnixSystem<int, string> -> UnixSystem<int, string>
            Drain : UnixSystem<int, string> -> UnixSystem<int, string>
            Finish : int -> UnixSystem<int, string> -> Finished
        }

    let private interrupted (thread : int) (system : UnixSystem<int, string>) : Finished =
        match Interruptions.settle (Callers.thread thread system) system with
        | Settled.Ends (InterruptedCall.FailsWithEintr, _, system) -> Answered ("EINTR", system)
        | other -> failwith $"thread %d{thread}'s return after its interrupted call: %A{other}"

    let private errnoName (error : UnixError) : string =
        match error with
        | UnixError.EBADF -> "EBADF"
        | UnixError.EPIPE -> "EPIPE"
        | UnixError.ECONNRESET -> "ECONNRESET"
        | other -> $"%O{other}"

    let private notOn (flavour : SimulatedUnixFlavour) (call : string) : 'a =
        failwith $"%O{flavour} has no call %s{call} here"

    /// The machine of `flavour` with thread 1, and for two sleepers then
    /// thread 2, asleep in `call`, a `poll`, `epoll_wait` or `kevent` with a
    /// timeout of 100 ms where `timed`; SIGUSR1 caught by a handler installed
    /// without `SA_RESTART`, and SIGPIPE ignored.
    let private world (flavour : SimulatedUnixFlavour) (call : string) (sleepers : int) (timed : bool) : World =
        let milliseconds = if timed then 100 else -1

        let system =
            UnixSystem.initial<int, string> (HostPlatform.platformOf flavour)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn 1
            |> Threads.spawn 2
            |> installed Signal.SIGUSR1 (SignalDisposition.Catch (SignalCatch.ofHandler "h1"))
            |> installed Signal.SIGPIPE SignalDisposition.Ignore

        let parkAll (park : int -> UnixSystem<int, string> -> UnixSystem<int, string>) system =
            List.fold (fun system thread -> park thread system) system [ 1..sleepers ]

        let none (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            failwith $"the %s{call} has no such event"

        match call with
        | "accept" ->
            let listener, system = KeventWorld.listenerAt port system

            let park (thread : int) (system : UnixSystem<int, string>) =
                UnixConnection.tryAccept (Callers.thread thread system) listener UserBuffer.Mapped 16u 0 system
                |> sleeps
                    "accept"
                    (fun outcome ->
                        match outcome with
                        | AcceptOutcome.WouldBlock _ -> true
                        | _ -> false
                    )

            {
                System = parkAll park system
                Own = fun system -> KeventWorld.client port system |> snd
                Close = none
                Drain = none
                Finish =
                    fun thread system ->
                        match UnixConnection.tryFinishAccept (Callers.thread thread system) system with
                        | Ok (AcceptOutcome.Accepted _, system) -> Answered ("accepted", system)
                        | Ok (AcceptOutcome.Interrupted, system) -> interrupted thread system
                        | Ok (AcceptOutcome.WouldBlock _, system) -> Asleep system
                        | Error refusal -> Refused $"%A{refusal}"
                        | other -> failwith $"finishing the accept: %A{other}"
            }
        | "flock" ->
            let flags =
                OpenFlagWords.bitOf (UnixSystem.platform system) OpenFlagBit.Create ||| 2

            let opened (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
                match OpenOutcomes.openPath (PathArg.ofText "/lock") flags 0o644 system with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                | other -> failwith $"open: %A{other}"

            let holder, system = opened system
            let waiter, system = opened system

            let system =
                match UnixDescriptor.tryFlock (leader system) holder 2 system with
                | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> system
                | other -> failwith $"the holder's flock: %A{other}"

            let park (thread : int) (system : UnixSystem<int, string>) =
                UnixDescriptor.tryFlock (Callers.thread thread system) waiter 2 system
                |> sleeps
                    "flock"
                    (fun outcome ->
                        match outcome with
                        | SyscallOutcome.WouldBlock _ -> true
                        | _ -> false
                    )

            {
                System = parkAll park system
                Own =
                    fun system ->
                        match UnixDescriptor.tryFlock (leader system) holder 8 system with
                        | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> system
                        | other -> failwith $"the holder's unlock: %A{other}"
                Close = none
                Drain = none
                Finish =
                    fun thread system ->
                        match UnixDescriptor.tryFlockAcquire (Callers.thread thread system) system with
                        | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed n), system) ->
                            Answered ($"%d{n}", system)
                        | Ok (SyscallOutcome.Interrupted, system) -> interrupted thread system
                        | Ok (SyscallOutcome.WouldBlock _, system) -> Asleep system
                        | Error refusal -> Refused $"%A{refusal}"
                        | other -> failwith $"finishing the flock: %A{other}"
            }
        | "read"
        | "tcp-read" ->
            let fd, far, system = if call = "read" then pipe system else tcpPair system

            let park (thread : int) (system : UnixSystem<int, string>) =
                UnixReadWrite.tryRead (Callers.thread thread system) fd UserBuffer.Mapped 1UL system
                |> sleeps call readParks

            {
                System = parkAll park system
                Own = writeOne far
                Close =
                    if call = "read" then
                        KeventWorld.close far
                    else
                        fun system ->
                            match UnixConnection.tryShutdown (leader system) far 1 system with
                            | Ok (ShutdownAnswer.Shut, system) -> system
                            | other -> failwith $"shutdown: %A{other}"
                Drain = none
                Finish =
                    fun thread system ->
                        match UnixReadWrite.tryFinishRead (Callers.thread thread system) system with
                        | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) ->
                            Answered ($"%d{bytes.Length}", system)
                        | Ok (ReadOutcome.Answered (ReadAnswer.Failed error), system) ->
                            Answered (errnoName error, system)
                        | Ok (ReadOutcome.Interrupted, system) -> interrupted thread system
                        | Ok (ReadOutcome.WouldBlock _, system) -> Asleep system
                        | Error refusal -> Refused $"%A{refusal}"
                        | other -> failwith $"finishing the %s{call}: %A{other}"
            }
        | "write"
        | "tcp-write" ->
            let fd, far, system =
                if call = "write" then
                    let r, w, system = pipe system
                    w, r, system
                else
                    tcpPair system

            let system = fill fd system
            let count = if call = "write" then 1 else 1000

            let park (thread : int) (system : UnixSystem<int, string>) =
                match
                    WriteOutcomes.admitThenWrite
                        thread
                        fd
                        UserBuffer.Mapped
                        (ImmutableArray.Create<byte> (Array.zeroCreate<byte> count))
                        system
                with
                | Ok (WriteStep.WouldBlock (_, system)) -> system
                | other -> failwith $"expected the %s{call} to sleep, got %A{other}"

            {
                System = parkAll park system
                Own = drain far
                Close = KeventWorld.close far
                Drain = none
                Finish =
                    fun thread system ->
                        match
                            WriteOutcomes.finishWrite
                                thread
                                (fun _ n -> ImmutableArray.Create<byte> (Array.zeroCreate<byte> n))
                                system
                        with
                        | Ok (WriteStep.Returns (WriteAnswer.Completed n, system))
                        | Ok (WriteStep.ReturnsRaising (WriteAnswer.Completed n, _, system)) ->
                            Answered ($"%d{n}", system)
                        | Ok (WriteStep.Returns (WriteAnswer.Failed error, system))
                        | Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed error, _, system)) ->
                            Answered (errnoName error, system)
                        | Ok (WriteStep.Interrupted system) -> interrupted thread system
                        | Ok (WriteStep.WouldBlock (_, system)) -> Asleep system
                        | Error refusal -> Refused $"%A{refusal}"
                        | other -> failwith $"finishing the %s{call}: %A{other}"
            }
        | "poll" ->
            let r, w, system = pipe system

            let park (thread : int) (system : UnixSystem<int, string>) =
                UnixPoll.tryPoll
                    (Callers.thread thread system)
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

            {
                System = parkAll park system
                Own = writeOne w
                Close = none
                Drain = none
                Finish =
                    fun thread system ->
                        match UnixPoll.tryFinishPoll (Callers.thread thread system) system with
                        | Ok (PollOutcome.Answered (_, n), system) -> Answered ($"%d{n}", system)
                        | Ok (PollOutcome.Interrupted, system) -> interrupted thread system
                        | Ok (PollOutcome.WouldBlock _, system) -> Asleep system
                        | Error refusal -> Refused $"%A{refusal}"
                        | other -> failwith $"finishing the poll: %A{other}"
            }
        | "events" ->
            let client, server, system = tcpPair system

            match flavour with
            | SimulatedUnixFlavour.Linux ->
                // Edge-triggered, where the probe's was level-triggered, which
                // this library does not model: see `divergent`.
                let epoll, system =
                    match UnixPoll.tryEpollCreate1 (leader system) 0 system with
                    | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                    | other -> failwith $"epoll_create1: %A{other}"

                let system =
                    match
                        UnixPoll.tryEpollCtl
                            (leader system)
                            epoll
                            1
                            client
                            (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 7UL))
                            system
                    with
                    | Ok (EpollCtlAnswer.Changed, system) -> system
                    | other -> failwith $"epoll_ctl: %A{other}"

                let park (thread : int) (system : UnixSystem<int, string>) =
                    UnixPoll.tryEpollWait (Callers.thread thread system) epoll 1 UserBuffer.Mapped milliseconds system
                    |> sleeps
                        "epoll_wait"
                        (fun outcome ->
                            match outcome with
                            | EpollWaitOutcome.WouldBlock _ -> true
                            | _ -> false
                        )

                {
                    System = parkAll park system
                    Own = writeOne server
                    Close = none
                    Drain = none
                    Finish =
                        fun thread system ->
                            match UnixPoll.tryFinishEpollWait (Callers.thread thread system) system with
                            | Ok (EpollWaitOutcome.Answered events, system) ->
                                Answered ($"%d{List.length events}", system)
                            | Ok (EpollWaitOutcome.Interrupted, system) -> interrupted thread system
                            | Ok (EpollWaitOutcome.WouldBlock _, system) -> Asleep system
                            | Error refusal -> Refused $"%A{refusal}"
                            | other -> failwith $"finishing the epoll_wait: %A{other}"
                }
            | SimulatedUnixFlavour.Darwin ->
                let kq, system = KeventWorld.kqueue system

                let system =
                    match
                        KeventWorld.applyAs (leader system) kq [ KeventWorld.change client -1s 0x0001us 7UL ] 0 system
                    with
                    | KeventOutcome.Answered [], system -> system
                    | other, _ -> failwith $"registering EVFILT_READ: %A{other}"

                let timeout =
                    if timed then
                        TimespecArgument.Readable
                            {
                                Seconds = 0L
                                Nanoseconds = 100_000_000L
                            }
                    else
                        TimespecArgument.Null

                let park (thread : int) (system : UnixSystem<int, string>) =
                    UnixKqueue.tryKevent (Callers.thread thread system) kq 0 [] 1 UserBuffer.Mapped timeout system
                    |> sleeps
                        "kevent"
                        (fun outcome ->
                            match outcome with
                            | KeventOutcome.WouldBlock _ -> true
                            | _ -> false
                        )

                {
                    System = parkAll park system
                    Own = writeOne server
                    Close = none
                    Drain = KeventWorld.close kq
                    Finish =
                        fun thread system ->
                            match UnixKqueue.tryFinishKevent (Callers.thread thread system) system with
                            | Ok (KeventOutcome.Answered events, system) -> Answered ($"%d{List.length events}", system)
                            | Ok (KeventOutcome.Failed error, system) -> Answered (errnoName error, system)
                            | Ok (KeventOutcome.Interrupted, system) -> interrupted thread system
                            | Ok (KeventOutcome.WouldBlock _, system) -> Asleep system
                            | Error refusal -> Refused $"%A{refusal}"
                            | other -> failwith $"finishing the kevent: %A{other}"
                }
        | _ -> notOn flavour call

    let private isWoken (thread : int) (system : UnixSystem<int, string>) : bool =
        match Lone.parkOf thread system with
        | Some {
                   State = ParkState.Woken _
               } -> true
        | _ -> false

    let private wake (system : UnixSystem<int, string>) : UnixSystem<int, string> = UnixWait.wake system |> snd

    /// What this library answers for `row`, printed as the probe prints it.
    let private replay (row : Row) : string =
        let timed = row.First = Event.Deadline || row.Second = Event.Deadline
        let w = world row.Flavour row.Call row.Sleepers timed

        // The sleeper the queue wakes first: the first to sleep, but for an
        // epoll instance, the last.
        let front, other =
            match row.Sleepers, row.Flavour, row.Call with
            | 1, _, _ -> 1, None
            | _, SimulatedUnixFlavour.Linux, "events" -> 2, Some 1
            | _ -> 1, Some 2

        let deadline =
            match UnixWait.deadlines w.System with
            | [] -> None
            | deadlines -> Some (List.min deadlines)

        let apply (event : Event) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match event with
            | Event.Own -> w.Own system
            | Event.Close -> w.Close system
            | Event.Drain -> w.Drain system
            | Event.Signal ->
                match UnixSignal.tryPthreadKill (leader system) front (signo Signal.SIGUSR1 system) system with
                | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) -> system
                | other -> failwith $"pthread_kill: %A{other}"
            | Event.Deadline ->
                match deadline with
                | Some deadline -> UnixSystem.advanceClock (deadline - UnixSystem.nanosecondsSinceBoot system) system
                | None -> failwith "the call waits for no deadline"

        let system = w.System |> apply row.First |> wake

        if not (isWoken front system) then
            failwith $"the first event did not wake the sleeper: %s{row.Line}"

        let system = system |> apply row.Second |> wake
        let otherWoken = other |> Option.map (fun other -> isWoken other system)

        let describe (finished : Finished) : string =
            match finished with
            | Answered (answer, _) -> answer
            | Asleep _ -> "asleep"
            | Refused why -> $"refused: %s{why}"

        let frontFinished = w.Finish front system

        match other, otherWoken, frontFinished with
        | None, _, finished -> $"front=%s{describe finished}"
        | Some other, Some otherWoken, (Answered (_, system) | Asleep system) ->
            // The other sleeper, finished once the first has: woken by now, or
            // asleep, it may be woken by what the first left.
            let rec settle (attempts : int) (system : UnixSystem<int, string>) : string =
                let system = wake system

                if attempts = 0 || not (isWoken other system) then
                    "asleep"
                else

                match w.Finish other system with
                | Asleep system -> settle (attempts - 1) system
                | finished -> describe finished

            $"front=%s{describe frontFinished} other-woken=%d{if otherWoken then 1 else 0} other=%s{settle 3 system}"
        | Some _, _, finished -> $"front=%s{describe finished}"

    /// What this library answers for `row` where that is not what the probe
    /// saw.
    let private divergent (row : Row) : string option =
        match row.Flavour, row.Call, row.Sleepers, row.First, row.Second with
        // The probe's epoll_wait was level-triggered, which this library does
        // not model; edge-triggered, the event the first sleeper took is not
        // there for the other.
        | SimulatedUnixFlavour.Linux, "events", 2, _, _ -> Some (row.Answer.Replace ("other=1", "other=asleep"))
        // Darwin's woken accepter fails with EINTR, and the connection whose
        // wake it took stays queued with the other accepter asleep; this
        // library wakes a sleeper from the state alone, so it would wake the
        // other, and refuses instead.
        | SimulatedUnixFlavour.Darwin, "accept", 2, Event.Own, Event.Signal ->
            Some "front=refused: SignalBesideConsumedWake"
        | _ -> None

    [<TestCaseSource(nameof flavours)>]
    let ``every row of the probe replays`` (flavour : SimulatedUnixFlavour) : unit =
        let rows = rows flavour

        // A control, so that this cannot pass by reading no rows.
        rows.Length
        |> shouldEqual (
            match flavour with
            | SimulatedUnixFlavour.Linux -> 38
            | SimulatedUnixFlavour.Darwin -> 44
        )

        let mismatches =
            [
                for row in rows do
                    let expected = divergent row |> Option.defaultValue row.Answer
                    let actual = replay row

                    // A refusal is matched on the case that names it.
                    let matches =
                        actual = expected
                        || (expected.Contains "refused: " && actual.StartsWith expected)

                    if not matches then
                        yield $"%s{row.Line}: expected %s{expected}, got %s{actual}"
            ]

        if not mismatches.IsEmpty then
            let listed = String.concat "\n" mismatches
            failwith $"%d{mismatches.Length} rows differ:\n%s{listed}"

    /// A Darwin `flock` woken by the unlock and signalled before it is
    /// finished fails with EINTR (`docs/probes/first-wake`, the flock rows),
    /// and takes no lock: the holder can lock again without waiting.
    [<Test>]
    let ``an interrupted Darwin flock takes no lock`` () : unit =
        let system =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn 1
            |> installed Signal.SIGUSR1 (SignalDisposition.Catch (SignalCatch.ofHandler "h1"))

        let flags =
            OpenFlagWords.bitOf (UnixSystem.platform system) OpenFlagBit.Create ||| 2

        let opened (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
            match OpenOutcomes.openPath (PathArg.ofText "/lock") flags 0o644 system with
            | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
            | other -> failwith $"open: %A{other}"

        let holder, system = opened system
        let waiter, system = opened system

        let lockedBy (caller : Caller<int>) (fd : int) (operation : int) (system : UnixSystem<int, string>) =
            match UnixDescriptor.tryFlock caller fd operation system with
            | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> system
            | other -> failwith $"flock %d{operation} through fd %d{fd}: %A{other}"

        let system = lockedBy (leader system) holder 2 system

        let system =
            match UnixDescriptor.tryFlock (Callers.thread 1 system) waiter 2 system with
            | Ok (SyscallOutcome.WouldBlock _, system) -> system
            | other -> failwith $"expected the waiter's flock to sleep, got %A{other}"

        let system = lockedBy (leader system) holder 8 system |> wake

        isWoken 1 system |> shouldEqual true

        let system =
            match UnixSignal.tryPthreadKill (leader system) 1 (signo Signal.SIGUSR1 system) system with
            | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) -> wake system
            | other -> failwith $"pthread_kill: %A{other}"

        let system =
            match UnixDescriptor.tryFlockAcquire (Callers.thread 1 system) system with
            | Ok (SyscallOutcome.Interrupted, system) -> system
            | other -> failwith $"expected the flock to be interrupted, got %A{other}"

        // LOCK_EX | LOCK_NB: granted only if the waiter took nothing.
        lockedBy (leader system) holder 6 system |> ignore<UnixSystem<int, string>>
