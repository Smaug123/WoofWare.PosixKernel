namespace WoofWare.PosixKernel.Test

open System
open NUnit.Framework
open WoofWare.PosixKernel

/// A `close(2)` costs time independent of how many processes, open file
/// descriptions, epoll instances, kqueues and sleeping Darwin polls the rest
/// of the machine holds: finding the epoll instances that register the
/// description it destroys, the kqueues and the sleeping polls' kqueues that
/// registered through the descriptor, must not walk every one on the machine.
/// Measured by the bytes a close allocates, which unlike time do not move with
/// the host's load: a close on a machine of four times the processes may
/// allocate a little more, for the deeper maps it looks things up in, and one
/// that visits every description or poll allocates about four times as much.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCloseRegistrationCost =

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    let private launch (platform : SimulatedUnixPlatform) : ProcessLaunch<int> =
        ProcessLaunch.create platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A new pipe of `caller`'s process: its read end, its write end, and the
    /// system.
    let private pipe (caller : Caller<int>) (system : UnixSystem<int, unit>) : int * int * UnixSystem<int, unit> =
        match UnixPipe.pipe2 caller 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (readFd, writeFd), system -> readFd, writeFd, resume caller system
        | answer, _ -> failwith $"expected pipe2 to make a pipe: %A{answer}"

    /// A new TCP socket of `caller`'s process.
    let private socket (caller : Caller<int>) (system : UnixSystem<int, unit>) : int * UnixSystem<int, unit> =
        // `AF_INET`, `SOCK_STREAM`, on both flavours.
        match UnixSocket.socket caller 2 1 0 system with
        | Ok (fd, system) -> fd, resume caller system
        | Error error -> failwith $"expected socket to make a socket: %O{error}"

    /// `caller`'s process makes an epoll instance and registers `fd` in it.
    let private epollWatching
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let epfd, system =
            match UnixPoll.epollCreate1 caller 0 system with
            | Ok (epfd, system) -> epfd, resume caller system
            | Error error -> failwith $"expected epoll_create1 to make an instance: %O{error}"

        // `EPOLL_CTL_ADD`.
        match
            UnixPoll.epollCtl
                caller
                epfd
                1
                fd
                (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 0UL))
                system
        with
        | EpollCtlAnswer.Changed, system -> resume caller system
        | answer, _ -> failwith $"expected epoll_ctl to register fd %d{fd}: %A{answer}"

    /// `caller`'s process makes a kqueue and registers `fd`'s read filter in it.
    let private kqueueWatching
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let kq, system = UnixKqueue.kqueue caller system
        let system = resume caller system

        let change : Kevent =
            {
                Ident = uint64 fd
                Filter = KeventFilter.Read
                Flags = KeventFlags.Add
                FilterFlags = 0u
                Data = 0L
                UserData = 0UL
            }

        match
            UnixKqueue.kevent
                caller
                kq
                1
                [ change ]
                0
                UserBuffer.Mapped
                (TimespecArgument.Readable
                    {
                        Seconds = 0L
                        Nanoseconds = 0L
                    })
                system
        with
        | KeventOutcome.Failed error, _ -> failwith $"expected kevent to register fd %d{fd}: %O{error}"
        | KeventOutcome.WouldBlock _, _ -> failwith "expected kevent with no room for events not to wait"
        | _, system -> resume caller system

    /// What each process on the machine holds besides its standard streams;
    /// the process that closes holds it too.
    type private Holding =
        /// Nothing.
        | Nothing
        /// A socket, registered in an epoll instance of the process's own.
        | EpollOnSocket
        /// A socket, registered in a kqueue of the process's own.
        | KqueueOnSocket
        /// A pipe, which the process's thread is asleep in `poll` on: on
        /// Darwin, a kqueue the machine keeps for the call.
        | SleepingPoll

    /// Gives `caller`'s process what `holding` says, and answers the
    /// descriptor it holds it through, if any.
    let private hold
        (holding : Holding)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : int option * UnixSystem<int, unit>
        =
        match holding with
        | Holding.Nothing -> None, system
        | Holding.EpollOnSocket ->
            let fd, system = socket caller system
            Some fd, epollWatching fd caller system
        | Holding.KqueueOnSocket ->
            let fd, system = socket caller system
            Some fd, kqueueWatching fd caller system
        | Holding.SleepingPoll ->
            let readFd, _, system = pipe caller system
            Some readFd, system

    /// `caller`'s thread goes to sleep in `poll` on `fd`.
    let private sleepsInPoll
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let entry : PollEntry =
            {
                Fd = fd
                // `POLLIN`.
                Events = 1s
            }

        match UnixPoll.poll caller [ entry ] -1 system with
        | PollOutcome.WouldBlock _, system -> system
        | outcome, _ -> failwith $"expected the poll to sleep: %A{outcome}"

    /// A machine of `count` processes besides the first, each holding what
    /// `holding` says, and the first holding it too; with the first's caller
    /// and the descriptor it will close, which is the one through which it
    /// holds what `holding` says, or a pipe's read end.
    let private machine
        (platform : SimulatedUnixPlatform)
        (holding : Holding)
        (count : int)
        : UnixSystem<int, unit> * Caller<int> * int
        =
        let booted = UnixSystem.initial platform |> UnixBootImage.boot (launch platform)
        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0

        let fd, system =
            match hold holding leader booted with
            | Some fd, system -> fd, system
            | None, system ->
                let readFd, _, system = pipe leader system
                readFd, system

        let system =
            (system, [ 1..count ])
            ||> List.fold (fun system _ ->
                let pid, system = UnixSystem.launch (launch platform) system
                let caller = Caller.make pid 0

                match hold holding caller system with
                | Some fd, system when holding = Holding.SleepingPoll -> sleepsInPoll fd caller system
                | _, system -> system
            )

        let _, system = UnixWait.wake system
        system, leader, fd

    /// The fewest bytes one close of `fd` by `caller` allocates, of several.
    let private closeBytes (caller : Caller<int>) (fd : int) (system : UnixSystem<int, unit>) : int64 =
        let close () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()

            match UnixDescriptor.close caller fd system with
            | SyscallAnswer.Completed 0L, _ -> ()
            | outcome, _ -> failwith $"expected the close of fd %d{fd} to succeed: %A{outcome}"

            GC.GetAllocatedBytesForCurrentThread () - before

        close () |> ignore
        List.init 5 (fun _ -> close ()) |> List.min

    [<TestCase("linux", "nothing")>]
    [<TestCase("linux", "epoll")>]
    [<TestCase("darwin", "nothing")>]
    [<TestCase("darwin", "kqueue")>]
    [<TestCase("darwin", "poll")>]
    let ``a close on a machine of four times the processes allocates about as much``
        (flavour : string)
        (held : string)
        : unit
        =
        let platform =
            match flavour with
            | "linux" -> SimulatedUnixPlatform.linuxX64
            | "darwin" -> SimulatedUnixPlatform.macOsArm64
            | flavour -> failwith $"no platform for %s{flavour}"

        let holding =
            match held with
            | "nothing" -> Holding.Nothing
            | "epoll" -> Holding.EpollOnSocket
            | "kqueue" -> Holding.KqueueOnSocket
            | "poll" -> Holding.SleepingPoll
            | held -> failwith $"no holding for %s{held}"

        let fewer =
            let system, leader, fd = machine platform holding 100
            closeBytes leader fd system

        let more =
            let system, leader, fd = machine platform holding 400
            closeBytes leader fd system

        // Lookups in maps four times as large give a ratio a little over 1,
        // and visiting every description or every poll about 4.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith $"%d{fewer} bytes a close beside 100 processes, and %d{more} beside 400: %.2f{ratio} times as much"

    /// `caller`'s process registers `fd` in its epoll instance `epfd`.
    let private epollAdd
        (caller : Caller<int>)
        (epfd : int)
        (fd : int)
        (system : UnixSystem<int, unit>)
        : EpollCtlAnswer * UnixSystem<int, unit>
        =
        // `EPOLL_CTL_ADD`.
        UnixPoll.epollCtl
            caller
            epfd
            1
            fd
            (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 0UL))
            system

    /// `caller`'s process registers `fd`'s read filter in its kqueue `kq`.
    let private keventAdd
        (caller : Caller<int>)
        (kq : int)
        (fd : int)
        (system : UnixSystem<int, unit>)
        : KeventOutcome * UnixSystem<int, unit>
        =
        let change : Kevent =
            {
                Ident = uint64 fd
                Filter = KeventFilter.Read
                Flags = KeventFlags.Add ||| KeventFlags.Clear
                FilterFlags = 0u
                Data = 0L
                UserData = 0UL
            }

        UnixKqueue.kevent
            caller
            kq
            1
            [ change ]
            0
            UserBuffer.Mapped
            (TimespecArgument.Readable
                {
                    Seconds = 0L
                    Nanoseconds = 0L
                })
            system

    /// The fewest bytes one registration of a socket allocates, of several,
    /// in an epoll instance (Linux) or a kqueue (Darwin) that registers
    /// `count` sockets already.
    let private registrationBytes (platform : SimulatedUnixPlatform) (count : int) : int64 =
        let booted = UnixSystem.initial platform |> UnixBootImage.boot (launch platform)
        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0
        let linux = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Linux

        let instance, system =
            if linux then
                match UnixPoll.epollCreate1 leader 0 booted with
                | Ok (epfd, system) -> epfd, resume leader system
                | Error error -> failwith $"expected epoll_create1 to make an instance: %O{error}"
            else
                let kq, system = UnixKqueue.kqueue leader booted
                kq, resume leader system

        let register (fd : int) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
            if linux then
                match epollAdd leader instance fd system with
                | EpollCtlAnswer.Changed, system -> resume leader system
                | answer, _ -> failwith $"expected epoll_ctl to register fd %d{fd}: %A{answer}"
            else
                match keventAdd leader instance fd system with
                | KeventOutcome.Failed error, _ -> failwith $"expected kevent to register fd %d{fd}: %O{error}"
                | KeventOutcome.WouldBlock _, _ -> failwith "expected kevent with no room for events not to wait"
                | _, system -> resume leader system

        let system =
            (system, [ 1..count ])
            ||> List.fold (fun system _ ->
                let fd, system = socket leader system
                register fd system
            )

        // Every idle socket is ready, so the instance has queued each; a wait
        // takes them, so that the registration measured queues behind none.
        let system =
            if linux then
                match UnixPoll.epollWait leader instance (count + 1) UserBuffer.Mapped 0 system with
                | EpollWaitOutcome.Answered _, system -> resume leader system
                | outcome, _ -> failwith $"expected epoll_wait to answer at once: %A{outcome}"
            else
                match
                    UnixKqueue.kevent
                        leader
                        instance
                        0
                        []
                        (count + 1)
                        UserBuffer.Mapped
                        (TimespecArgument.Readable
                            {
                                Seconds = 0L
                                Nanoseconds = 0L
                            })
                        system
                with
                | KeventOutcome.Failed error, _ -> failwith $"expected kevent to answer at once: %O{error}"
                | KeventOutcome.WouldBlock _, _ -> failwith "expected kevent with a zero timeout not to wait"
                | _, system -> resume leader system

        let fd, system = socket leader system

        let once () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()
            register fd system |> ignore<UnixSystem<int, unit>>
            GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a registration in an instance of four times the registrations allocates about as much``
        (flavour : string)
        : unit
        =
        let platform =
            match flavour with
            | "linux" -> SimulatedUnixPlatform.linuxX64
            | "darwin" -> SimulatedUnixPlatform.macOsArm64
            | flavour -> failwith $"no platform for %s{flavour}"

        // 4 × 50 sockets stay under the 256 descriptors a Darwin process may
        // have.
        let fewer = registrationBytes platform 50
        let more = registrationBytes platform 200

        // Lookups in maps four times as large give a ratio a little over 1,
        // and visiting every registration the instance holds about 4.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith
                $"%d{fewer} bytes a registration beside 50 others, and %d{more} beside 200: %.2f{ratio} times as much"

    /// The fewest bytes, of several, that the last close of a socket
    /// allocates when one epoll instance registers it through `aliases`
    /// descriptors, every registration pending.
    let private lastCloseBytes (aliases : int) : int64 =
        let platform = SimulatedUnixPlatform.linuxX64
        let booted = UnixSystem.initial platform |> UnixBootImage.boot (launch platform)
        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0
        let fd, system = socket leader booted

        let epfd, system =
            match UnixPoll.epollCreate1 leader 0 system with
            | Ok (epfd, system) -> epfd, resume leader system
            | Error error -> failwith $"expected epoll_create1 to make an instance: %O{error}"

        let copies, system =
            (([], system), [ 2..aliases ])
            ||> List.fold (fun (copies, system) _ ->
                match UnixDescriptor.dup leader fd system with
                | SyscallAnswer.Completed copy, system -> int copy :: copies, resume leader system
                | answer, _ -> failwith $"expected dup to copy fd %d{fd}: %A{answer}"
            )

        // An idle socket is ready, so each registration is pending as it is
        // made.
        let system =
            (system, fd :: copies)
            ||> List.fold (fun system alias ->
                match epollAdd leader epfd alias system with
                | EpollCtlAnswer.Changed, system -> resume leader system
                | answer, _ -> failwith $"expected epoll_ctl to register fd %d{alias}: %A{answer}"
            )

        let system =
            (system, copies)
            ||> List.fold (fun system alias ->
                match UnixDescriptor.close leader alias system with
                | SyscallAnswer.Completed 0L, system -> resume leader system
                | outcome, _ -> failwith $"expected the close of fd %d{alias} to succeed: %A{outcome}"
            )

        closeBytes leader fd system

    [<Test>]
    let ``the last close of a description an instance registers eight times as often allocates about eight times as much``
        ()
        : unit
        =
        let fewer = lastCloseBytes 50
        let more = lastCloseBytes 400

        // Growth linear in the registrations, with a lookup for each, gives a
        // ratio a little over 8, and purging the ready list once for each
        // registration about 64.
        let ratio = float more / float fewer

        if ratio > 16.0 then
            failwith
                $"%d{fewer} bytes the last close of a description registered 50 times, and %d{more} of one registered 400 times: %.2f{ratio} times as much"
