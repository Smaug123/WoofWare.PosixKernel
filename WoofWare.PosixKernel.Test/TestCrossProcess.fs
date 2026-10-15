namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What one process in a `UnixSystem` does to another through the machine
/// they share: a connection or a close in one waking a call asleep in
/// another, a kqueue or a Darwin `poll` in one seeing a socket event another
/// caused, and one process's end closing everything it held.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCrossProcess =

    // ------------------------------------------------- each description's counts

    /// One step of `countsKernel`'s walk, made in the process at index `proc`
    /// (modulo how many there are): a `dup` of its descriptor at index `fd`,
    /// or a `read` by its thread `thread` of its descriptor at index `fd`
    /// among those naming its own pipe's read end, which sleeps.
    [<RequireQualifiedAccess>]
    type private CountStep =
        | Dup of proc : int * fd : int
        | Read of proc : int * thread : int * fd : int

    let private countThreads : int = 3

    let private countStepGen : Gen<CountStep> =
        let small = Gen.choose (0, 63)

        Gen.oneof
            [
                Gen.map2 (fun p fd -> CountStep.Dup (p, fd)) small small
                Gen.map3 (fun p t fd -> CountStep.Read (p, t, fd)) small small small
            ]

    /// A kernel of `count` processes, each of which has made a pipe of its
    /// own, after `steps`; and the description each thread a step's `read`
    /// put to sleep waits on, by the test's own reckoning.
    let private countsKernel
        (platform : SimulatedUnixPlatform)
        (count : int)
        (steps : CountStep list)
        : ProcessId list * UnixSystem<int, string> * Map<Caller<int>, OpenFileDescriptionId>
        =
        let pids, system = Machines.withThreads platform count countThreads

        // Each process's pipe's read end, which no one writes to, so a read of
        // it sleeps; standing input is at its end, so a read of it would not.
        let readEnds, system =
            ((Map.empty, system), pids)
            ||> List.fold (fun (readEnds, system) pid ->
                match UnixPipe.tryPipe2 (Caller.make pid 0) 0 UserBuffer.Mapped system with
                | Ok (Pipe2Answer.Created (readFd, _), system) ->
                    let id =
                        FileDescriptorRegistry.tryFindId readFd (UnixSystem.fileDescriptors pid system)
                        |> Option.get

                    Map.add pid id readEnds, system
                | other -> failwith $"pipe2 in %O{pid}: %A{other}"
            )

        let pidAt (index : int) : ProcessId = pids.[index % pids.Length]

        let fds (pid : ProcessId) (system : UnixSystem<int, string>) : (int * OpenFileDescriptionId) list =
            FileDescriptorRegistry.fds (UnixSystem.fileDescriptors pid system) |> Map.toList

        ((system, Map.empty), steps)
        ||> List.fold (fun (system, asleep) step ->
            match step with
            | CountStep.Dup (proc, fd) ->
                let pid = pidAt proc

                let awake =
                    Proc.threads pid system
                    |> Map.tryFindKey (fun _ state -> (UnixThreadState.parkedIn state).IsNone)

                match awake with
                | None -> system, asleep
                | Some thread ->
                    let fds = fds pid system
                    let fd, _ = fds.[fd % fds.Length]

                    match UnixDescriptor.tryDup (Caller.make pid thread) fd system with
                    | Ok (SyscallAnswer.Completed _, system) -> system, asleep
                    | other -> failwith $"dup of %d{fd} in %O{pid}: %A{other}"
            | CountStep.Read (proc, thread, fd) ->
                let caller = Caller.make (pidAt proc) (thread % countThreads)

                if Map.containsKey caller asleep then
                    system, asleep
                else
                    let readEnd = readEnds.[Caller.processId caller]

                    let candidates =
                        fds (Caller.processId caller) system |> List.filter (snd >> (=) readEnd)

                    let fd, id = candidates.[fd % candidates.Length]

                    match UnixReadWrite.tryRead caller fd UserBuffer.Mapped 4UL system with
                    | Ok (ReadOutcome.WouldBlock _, system) -> system, Map.add caller id asleep
                    | other -> failwith $"read of the empty pipe at %d{fd} by %O{caller}: %A{other}"
        )
        |> fun (system, asleep) -> pids, system, asleep

    /// Which count a test pushed from the truth, and whether above it.
    [<RequireQualifiedAccess>]
    type private Corrupted =
        | Descriptors of above : bool
        | Holds of above : bool

    /// The open file table keeps, for each description, a count of the
    /// descriptors naming it in every process's table and of the holds the
    /// calls asleep in every process have on it, and the kernel's
    /// `checkInvariants` holds each to every table and every park: one count
    /// pushed either way from the truth, in a description of any process, is
    /// reported, and nothing else is.
    [<Test>]
    let ``checkInvariants reports exactly a description whose count disagrees, in one process or among several``
        ()
        : unit
        =
        // Which corruptions were checked in a description of a process other
        // than the first, on a machine of several.
        let reached : Map<Corrupted, int> ref = ref Map.empty

        let property (platform : SimulatedUnixPlatform) (count : int) (steps : CountStep list) : unit =
            let pids, system, asleep = countsKernel platform count steps
            Machines.assertClean system

            let named =
                pids
                |> List.collect (fun pid ->
                    FileDescriptorRegistry.fds (UnixSystem.fileDescriptors pid system)
                    |> Map.toList
                    |> List.map (fun (_, id) -> id, pid)
                )

            let held =
                asleep
                |> Map.toList
                |> List.map (fun (caller, id) -> id, Caller.processId caller)

            let openFiles =
                FileDescriptorRegistry.openFiles (UnixSystem.fileDescriptors pids.[0] system)

            // The machine's open file table, which every process's registry
            // reads, rewritten through the first process's.
            let rewritten (f : FileDescriptorRegistry -> FileDescriptorRegistry) : UnixSystem<int, string> =
                Proc.withFileDescriptors pids.[0] (f (Proc.fileDescriptors pids.[0] system)) system

            let sorted (defects : UnixSystemDefect<int> list) : UnixSystemDefect<int> list =
                List.sortBy (sprintf "%A") defects

            for id in OpenFileTable.descriptions openFiles |> Map.keys do
                let naming = named |> List.filter (fst >> (=) id) |> List.length
                let holding = held |> List.filter (fst >> (=) id) |> List.length

                OpenFileTable.descriptorCount id openFiles |> shouldEqual (Some naming)
                OpenFileTable.holdCount id openFiles |> shouldEqual (Some holding)

                let elsewhere =
                    count > 1
                    && (named @ held)
                       |> List.exists (fun (other, pid) -> other = id && pid <> pids.[0])

                let reach (corrupted : Corrupted) : unit =
                    if elsewhere then
                        reached.Value <- Map.change corrupted (Option.defaultValue 0 >> (+) 1 >> Some) reached.Value

                for wrong in [ 0 .. naming + 2 ] |> List.filter ((<>) naming) do
                    let corrupted =
                        rewritten (FileDescriptorRegistry.Unchecked.setDescriptorCount id wrong)

                    let expected =
                        [
                            yield
                                UnixSystemDefect.OpenFiles (
                                    FileDescriptorRegistryDefect.DescriptorCountMismatch (id, wrong, naming)
                                )
                            // A description no descriptor names and no call
                            // holds is a leak besides.
                            if wrong = 0 && holding = 0 then
                                yield UnixSystemDefect.UnreferencedDescription id
                        ]

                    sorted (UnixSystem.checkInvariants corrupted) |> shouldEqual (sorted expected)
                    reach (Corrupted.Descriptors (wrong > naming))

                for wrong in [ 0 .. holding + 2 ] |> List.filter ((<>) holding) do
                    let corrupted =
                        let rec toward (openFiles : OpenFileTable) : OpenFileTable =
                            match OpenFileTable.holdCount id openFiles with
                            | Some n when n < wrong -> toward (OpenFileTable.hold id openFiles)
                            | Some n when n > wrong -> toward (OpenFileTable.releaseHold id openFiles)
                            | _ -> openFiles

                        rewritten (FileDescriptorRegistry.mapOpenFiles toward)

                    UnixSystem.checkInvariants corrupted
                    |> shouldEqual [ UnixSystemDefect.HoldCountMismatch (id, wrong, holding) ]

                    reach (Corrupted.Holds (wrong > holding))

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 100,
            Prop.forAll
                (Arb.fromGen (Gen.zip3 (Gen.elements Machines.platforms) (Gen.choose (1, 3)) (Gen.listOf countStepGen)))
                (fun (platform, count, steps) -> property platform count steps)
        )

        for corrupted in
            [
                Corrupted.Descriptors false
                Corrupted.Descriptors true
                Corrupted.Holds false
                Corrupted.Holds true
            ] do
            Map.tryFind corrupted reached.Value
            |> Option.defaultValue 0
            |> shouldBeGreaterThan 10

    // ------------------------------------------------------- Darwin kqueues

    let private darwin : SimulatedUnixPlatform = SimulatedUnixPlatform.macOsArm64

    let private addClear : uint16 = KeventFlags.Add ||| KeventFlags.Clear

    /// The events one `kevent` wait on `kq`, with room for `room`, reports at
    /// once in the view of `pid`.
    let private reported
        (pid : ProcessId)
        (kq : int)
        (room : int)
        (machine : UnixSystem<int, string>)
        : Kevent list * UnixSystem<int, string>
        =
        Machines.inProcess
            pid
            (fun view ->
                match KeventWorld.applyIn pid kq [] room view with
                | KeventOutcome.Answered events, view -> events, view
                | other, _ -> failwith $"kevent on fd %d{kq}: %A{other}"
            )
            machine

    let private summary (events : Kevent list) : (uint64 * int16 * int64 * uint64) list =
        events
        |> List.map (fun event -> event.Ident, event.Filter, event.Data, event.UserData)

    [<Test>]
    let ``a connection from another process activates the listener's registration in its kqueue`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let (listener, kq), machine =
            Machines.inProcess
                b
                (fun view ->
                    let listener, view = KeventWorld.listenerAtIn b 8080us view
                    let kq, view = KeventWorld.kqueueIn b view
                    (listener, kq), KeventWorld.registerIn b kq listener KeventFilter.Read addClear 7UL view
                )
                machine

        // The connecting socket takes the same number in its own process as
        // the listener has in the other, so an activation that read the
        // registration's descriptor in the connecting process's table would
        // find the connecting socket instead.
        let client, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
        client |> shouldEqual listener
        Machines.assertClean machine

        let events, machine = reported b kq 4 machine
        summary events |> shouldEqual [ uint64 listener, KeventFilter.Read, 1L, 7UL ]
        Machines.assertClean machine

        // EV_CLEAR: reported once.
        reported b kq 4 machine |> fst |> shouldEqual []

    [<Test>]
    let ``another process's close of its end activates the peer's READ registration with EOF`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let listener, machine =
            Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

        let client, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine

        let (accepted, kq), machine =
            Machines.inProcess
                b
                (fun view ->
                    let accepted, view = KeventWorld.acceptIn b listener view
                    let kq, view = KeventWorld.kqueueIn b view
                    (accepted, kq), KeventWorld.registerIn b kq accepted KeventFilter.Read addClear 9UL view
                )
                machine

        reported b kq 4 machine |> fst |> shouldEqual []

        let machine = Machines.doIn a (KeventWorld.closeIn a client) machine
        Machines.assertClean machine

        let events, machine = reported b kq 4 machine

        events
        |> List.map (fun event -> event.Ident, event.Filter, event.Flags &&& KeventFlags.Eof <> 0us, event.UserData)
        |> shouldEqual [ uint64 accepted, KeventFilter.Read, true, 9UL ]

        Machines.assertClean machine

    [<Test>]
    let ``a close in one process leaves another process's registrations through the same number`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let (listener, kq), machine =
            Machines.inProcess
                b
                (fun view ->
                    let listener, view = KeventWorld.listenerAtIn b 8080us view
                    let kq, view = KeventWorld.kqueueIn b view
                    (listener, kq), KeventWorld.registerIn b kq listener KeventFilter.Read addClear 7UL view
                )
                machine

        // The other process opens and closes the same number.
        let own, machine = Machines.inProcess a (KeventWorld.streamIn a true) machine
        own |> shouldEqual listener
        let machine = Machines.doIn a (KeventWorld.closeIn a own) machine
        Machines.assertClean machine

        let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine

        reported b kq 4 machine
        |> fst
        |> summary
        |> shouldEqual [ uint64 listener, KeventFilter.Read, 1L, 7UL ]

    // -------------------------------------------------------- Darwin poll

    let private pollIn : int16 = 0x0001s
    let private pollHup : int16 = 0x0010s

    let private entry (fd : int) (events : int16) : PollEntry =
        {
            Fd = fd
            Events = events
        }

    /// `thread` of `pid` polls `entries` with no timeout, and sleeps.
    let private sleepInPoll
        (pid : ProcessId)
        (thread : int)
        (entries : PollEntry list)
        (machine : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        Machines.doIn
            pid
            (fun view ->
                match UnixPoll.tryPoll (Caller.make pid thread) entries -1 view with
                | Ok (PollOutcome.WouldBlock _, view) -> view
                | other -> failwith $"poll: expected to sleep, got %A{other}"
            )
            machine

    /// The `poll` `thread` of `pid` sleeps in, finished.
    let private finishPoll
        (pid : ProcessId)
        (thread : int)
        (machine : UnixSystem<int, string>)
        : PollOutcome * UnixSystem<int, string>
        =
        Machines.inProcess
            pid
            (fun view ->
                let view = Woken.caller (Caller.make pid thread) view

                match UnixPoll.tryFinishPoll (Caller.make pid thread) view with
                | Ok finished -> finished
                | Error refusal -> failwith $"finishPoll: %A{refusal}"
            )
            machine

    [<Test>]
    let ``a connection from another process wakes a sleeping poll on the listener`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let listener, machine =
            Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

        let machine = sleepInPoll b 1 [ entry listener pollIn ] machine
        Machines.assertClean machine

        Machines.wakes machine |> shouldEqual []

        let client, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
        client |> shouldEqual listener
        Machines.assertClean machine

        Machines.wakes machine
        |> shouldEqual [ (b, 1), Set.singleton WakePrimitive.KqueuePollReportable ]

        let outcome, machine = finishPoll b 1 machine
        outcome |> shouldEqual (PollOutcome.Answered ([ pollIn ], 1))
        Machines.assertClean machine

    [<Test>]
    let ``another process's close wakes a sleeping poll on the peer with a hang-up`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let listener, machine =
            Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

        let client, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine

        let accepted, machine =
            Machines.inProcess b (KeventWorld.acceptIn b listener) machine

        let machine = sleepInPoll b 1 [ entry accepted pollIn ] machine

        let machine = Machines.doIn a (KeventWorld.closeIn a client) machine
        Machines.assertClean machine

        Machines.wakes machine
        |> shouldEqual [ (b, 1), Set.singleton WakePrimitive.KqueuePollReportable ]

        let outcome, machine = finishPoll b 1 machine
        outcome |> shouldEqual (PollOutcome.Answered ([ pollIn ||| pollHup ], 1))
        Machines.assertClean machine

    [<Test>]
    let ``a close in one process leaves another process's sleeping poll's filters through the same number`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let listener, machine =
            Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

        let machine = sleepInPoll b 1 [ entry listener pollIn ] machine
        let own, machine = Machines.inProcess a (KeventWorld.streamIn a true) machine
        own |> shouldEqual listener
        let machine = Machines.doIn a (KeventWorld.closeIn a own) machine
        let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
        Machines.assertClean machine

        finishPoll b 1 machine
        |> fst
        |> shouldEqual (PollOutcome.Answered ([ pollIn ], 1))

    // ------------------------------------------------------ the machine's wakes

    /// `thread` of `pid` accepts on the blocking listener `listener`, which holds
    /// nothing, and sleeps.
    let private sleepInAccept
        (pid : ProcessId)
        (thread : int)
        (listener : int)
        (machine : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        Machines.doIn
            pid
            (fun view ->
                match UnixConnection.tryAccept (Caller.make pid thread) listener UserBuffer.Mapped 16u view with
                | Ok (AcceptOutcome.WouldBlock _, view) -> view
                | other -> failwith $"accept: expected to sleep, got %A{other}"
            )
            machine

    let private finishAccept
        (pid : ProcessId)
        (thread : int)
        (machine : UnixSystem<int, string>)
        : AcceptOutcome * UnixSystem<int, string>
        =
        Machines.inProcess
            pid
            (fun view ->
                let view = Woken.caller (Caller.make pid thread) view

                match UnixConnection.tryFinishAccept (Caller.make pid thread) view with
                | Ok finished -> finished
                | Error refusal -> failwith $"finishAccept: %A{refusal}"
            )
            machine

    [<Test>]
    let ``a connection from another process wakes an accept asleep on the listener`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]

            let listener, machine =
                Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

            let machine = sleepInAccept b 1 listener machine
            Machines.assertClean machine
            Machines.wakes machine |> shouldEqual []

            let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
            Machines.assertClean machine

            let listenerId = KeventWorld.idOfIn b listener (Machines.viewOf b machine)

            let woken, machine = Machines.wake machine

            woken
            |> shouldEqual [ (b, 1), Set.singleton (WakePrimitive.AcceptQueueNonEmpty listenerId) ]

            match finishAccept b 1 machine with
            | AcceptOutcome.Accepted _, machine -> Machines.assertClean machine
            | other, _ -> failwith $"finishAccept: %A{other}"

    [<Test>]
    let ``a connection from another process wakes an epoll_wait on an instance watching the listener`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a, b = pids.[0], pids.[1]

        let (listener, epoll), machine =
            Machines.inProcess
                b
                (fun view ->
                    let listener, view = KeventWorld.listenerAtIn b 8080us view

                    let epoll, view =
                        match UnixPoll.tryEpollCreate1 (Caller.make b (Proc.leader b view)) 0 view with
                        | Ok (Ok created) -> created
                        | other -> failwith $"epoll_create1: %A{other}"

                    let view =
                        match
                            UnixPoll.tryEpollCtl
                                (Caller.make b (Proc.leader b view))
                                epoll
                                1
                                listener
                                (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 5UL))
                                view
                        with
                        | Ok (EpollCtlAnswer.Changed, view) -> view
                        | other -> failwith $"epoll_ctl: %A{other}"

                    (listener, epoll), view
                )
                machine

        let machine =
            Machines.doIn
                b
                (fun view ->
                    match UnixPoll.tryEpollWait (Caller.make b 1) epoll 4 UserBuffer.Mapped -1 view with
                    | Ok (EpollWaitOutcome.WouldBlock _, view) -> view
                    | other -> failwith $"epoll_wait: expected to sleep, got %A{other}"
                )
                machine

        Machines.wakes machine |> shouldEqual []

        let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
        Machines.assertClean machine

        let epollId = KeventWorld.idOfIn b epoll (Machines.viewOf b machine)

        let woken, machine = Machines.wake machine

        woken
        |> shouldEqual [ (b, 1), Set.singleton (WakePrimitive.EpollEventDeliverable epollId) ]

        let outcome, machine =
            Machines.inProcess
                b
                (fun view ->
                    match UnixPoll.tryFinishEpollWait (Caller.make b 1) view with
                    | Ok finished -> finished
                    | Error refusal -> failwith $"finishEpollWait: %A{refusal}"
                )
                machine

        outcome |> shouldEqual (EpollWaitOutcome.Answered [ 5UL, EpollEvents.In ])
        ignore listener
        Machines.assertClean machine

    [<Test>]
    let ``another process's close wakes an epoll_wait watching the peer, with the half-close`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a, b = pids.[0], pids.[1]

        let listener, machine =
            Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

        let client, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine

        let epoll, machine =
            Machines.inProcess
                b
                (fun view ->
                    let accepted, view = KeventWorld.acceptIn b listener view

                    let epoll, view =
                        match UnixPoll.tryEpollCreate1 (Caller.make b (Proc.leader b view)) 0 view with
                        | Ok (Ok created) -> created
                        | other -> failwith $"epoll_create1: %A{other}"

                    let view =
                        match
                            UnixPoll.tryEpollCtl
                                (Caller.make b (Proc.leader b view))
                                epoll
                                1
                                accepted
                                (EpollEventArgument.Readable (EpollEvents.RdHup ||| EpollEvents.EdgeTriggered, 6UL))
                                view
                        with
                        | Ok (EpollCtlAnswer.Changed, view) -> view
                        | other -> failwith $"epoll_ctl: %A{other}"

                    epoll, view
                )
                machine

        let machine =
            Machines.doIn
                b
                (fun view ->
                    match UnixPoll.tryEpollWait (Caller.make b 1) epoll 4 UserBuffer.Mapped -1 view with
                    | Ok (EpollWaitOutcome.WouldBlock _, view) -> view
                    | other -> failwith $"epoll_wait: expected to sleep, got %A{other}"
                )
                machine

        Machines.wakes machine |> shouldEqual []

        let machine = Machines.doIn a (KeventWorld.closeIn a client) machine
        Machines.assertClean machine

        let machine = Machines.waking [ b, 1 ] machine

        let outcome, machine =
            Machines.inProcess
                b
                (fun view ->
                    match UnixPoll.tryFinishEpollWait (Caller.make b 1) view with
                    | Ok finished -> finished
                    | Error refusal -> failwith $"finishEpollWait: %A{refusal}"
                )
                machine

        outcome |> shouldEqual (EpollWaitOutcome.Answered [ 6UL, EpollEvents.RdHup ])
        Machines.assertClean machine

    [<Test>]
    let ``a connection from another process wakes a kevent wait on a kqueue watching the listener`` () : unit =
        let pids, machine = Machines.ofCount darwin 2
        let a, b = pids.[0], pids.[1]

        let (listener, kq), machine =
            Machines.inProcess
                b
                (fun view ->
                    let listener, view = KeventWorld.listenerAtIn b 8080us view
                    let kq, view = KeventWorld.kqueueIn b view
                    (listener, kq), KeventWorld.registerIn b kq listener KeventFilter.Read addClear 7UL view
                )
                machine

        let machine =
            Machines.doIn
                b
                (fun view ->
                    match
                        UnixKqueue.tryKevent (Caller.make b 1) kq 0 [] 4 UserBuffer.Mapped KeventTimeout.Null view
                    with
                    | Ok (KeventOutcome.WouldBlock _, view) -> view
                    | other -> failwith $"kevent: expected to sleep, got %A{other}"
                )
                machine

        Machines.wakes machine |> shouldEqual []

        let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
        Machines.assertClean machine

        let kqueueId = KeventWorld.idOfIn b kq (Machines.viewOf b machine)

        let woken, machine = Machines.wake machine

        woken
        |> shouldEqual [ (b, 1), Set.singleton (WakePrimitive.KqueueEventDeliverable kqueueId) ]

        let outcome, machine =
            Machines.inProcess
                b
                (fun view ->
                    match UnixKqueue.tryFinishKevent (Caller.make b 1) view with
                    | Ok finished -> finished
                    | Error refusal -> failwith $"finishKevent: %A{refusal}"
                )
                machine

        match outcome with
        | KeventOutcome.Answered events -> summary events |> shouldEqual [ uint64 listener, KeventFilter.Read, 1L, 7UL ]
        | other -> failwith $"finishKevent: %A{other}"

        Machines.assertClean machine

    [<Test>]
    let ``a lock released in one process wakes an flock asleep on the same file in another`` () : unit =
        let lockEx = 2
        let lockUn = 8

        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]

            let openShared (pid : ProcessId) (view : UnixSystem<int, string>) : int * UnixSystem<int, string> =
                match
                    OpenFlagWords.openPathIn
                        pid
                        {
                            Access = FileAccessMode.ReadWrite
                            Create = true
                            Exclusive = false
                            Truncate = false
                            NoFollow = false
                            CloseOnExec = false
                            Synchronous = false
                            DataSynchronous = false
                            Directory = false
                        }
                        (PathArg.ofText "/locked")
                        0o644
                        view
                with
                | Ok (SyscallAnswer.Completed fd, view) -> int fd, view
                | other -> failwith $"open: %A{other}"

            let flock (pid : ProcessId) (thread : int) (fd : int) (operation : int) (view : UnixSystem<int, string>) =
                match UnixDescriptor.tryFlock (Caller.make pid thread) fd operation view with
                | Ok answered -> answered
                | Error refusal -> failwith $"flock: %A{refusal}"

            let held, machine = Machines.inProcess a (openShared a) machine
            let waiting, machine = Machines.inProcess b (openShared b) machine

            let outcome, machine = Machines.inProcess a (flock a 1 held lockEx) machine
            outcome |> shouldEqual (SyscallOutcome.Answered (SyscallAnswer.Completed 0L))

            let outcome, machine = Machines.inProcess b (flock b 1 waiting lockEx) machine

            match outcome with
            | SyscallOutcome.WouldBlock _ -> ()
            | other -> failwith $"the second flock: expected to sleep, got %A{other}"

            Machines.assertClean machine
            Machines.wakes machine |> shouldEqual []

            let outcome, machine = Machines.inProcess a (flock a 1 held lockUn) machine
            outcome |> shouldEqual (SyscallOutcome.Answered (SyscallAnswer.Completed 0L))

            let waitingId = KeventWorld.idOfIn b waiting (Machines.viewOf b machine)

            let woken, machine = Machines.wake machine

            woken
            |> shouldEqual
                [
                    (b, 1), Set.singleton (WakePrimitive.FlockGrantable (waitingId, FlockMode.Exclusive))
                ]

            let outcome, machine =
                Machines.inProcess
                    b
                    (fun view ->
                        match UnixDescriptor.tryFlockAcquire (Caller.make b 1) view with
                        | Ok finished -> finished
                        | Error refusal -> failwith $"flockAcquire: %A{refusal}"
                    )
                    machine

            outcome |> shouldEqual (SyscallOutcome.Answered (SyscallAnswer.Completed 0L))
            Machines.assertClean machine

    [<Test>]
    let ``the machine wakes in park order across processes, and one waiter of an exclusive queue`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]

            let listenerA, machine =
                Machines.inProcess a (KeventWorld.listenerAtIn a 8080us) machine

            let listenerB, machine =
                Machines.inProcess b (KeventWorld.listenerAtIn b 8081us) machine

            // Parked in this order: b's 1, a's 1, b's 2, the last two on the
            // listeners the first two are not.
            let machine =
                machine
                |> sleepInAccept b 1 listenerB
                |> sleepInAccept a 1 listenerA
                |> sleepInAccept b 2 listenerB

            Machines.wakes machine |> shouldEqual []

            // One connection to each, made by the other process's third thread.
            let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8081us) machine
            let _, machine = Machines.inProcess b (KeventWorld.clientIn b 8080us) machine
            Machines.assertClean machine

            // Park order, not process order; and of b's two accepters on one
            // listener holding one connection, the one that parked first.
            let machine = Machines.waking [ b, 1 ; a, 1 ] machine

            // A woken accepter that has not yet finished stands for the
            // connection, so its queue wakes nobody else meanwhile.
            Machines.wakes machine |> shouldEqual []

    // ------------------------------------------------------- a process's end

    /// `pid`'s thread 0 calls `exit_group(status)`, which ends the process.
    let private exitIn
        (pid : ProcessId)
        (status : int32)
        (machine : UnixSystem<int, string>)
        : Result<ProcessTermination * UnixSystem<int, string>, ProcessEndRefusal>
        =
        UnixThreadLifecycle.tryExitGroup (Caller.make pid 0) status (Machines.viewOf pid machine)
        |> Result.map (fun (ended, machine) -> EndedProcess.termination ended, machine)

    let private exitedOk (pid : ProcessId) (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
        match exitIn pid 0 machine with
        | Ok (ProcessTermination.Exited _, machine) -> machine
        | Ok (other, _) -> failwith $"exit_group: the process ended by %O{other}, not by its exit"
        | Error refusal -> failwith $"exit_group: %s{ProcessEndRefusal.describe refusal}"

    /// A call that ends a process, made by its thread 0.
    [<RequireQualifiedAccess>]
    type private Ending =
        /// `exit_group(0)`.
        | ExitGroup
        /// `kill(2)` of SIGKILL, to the process itself.
        | Kill
        /// `raise(3)` of SIGTERM.
        | Raise
        /// SIGTERM blocked, raised and unblocked, each call followed by the
        /// return to user mode, the last of which ends the process.
        | ReturnToUser
        /// Every other thread exits, and then thread 0, the leader and the
        /// last.
        | LastThread
        /// A write of one byte into a new pipe whose read end is closed, which
        /// raises SIGPIPE at its default.
        | BrokenPipe

    /// Every `Ending` a process on `platform` can take: Darwin refuses the
    /// last thread's exit.
    let private endingsOn (platform : SimulatedUnixPlatform) : Ending list =
        [
            Ending.ExitGroup
            Ending.Kill
            Ending.Raise
            Ending.ReturnToUser
            if SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Linux then
                Ending.LastThread
            Ending.BrokenPipe
        ]

    /// The process `pid`, all of whose threads run, ended by `ending`: the
    /// system the call that ended it answered.
    let private endedBy
        (ending : Ending)
        (pid : ProcessId)
        (machine : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let caller = Caller.make pid 0
        let numbering = SimulatedUnixPlatform.signalNumbering (UnixSystem.platform machine)
        let sigterm = Signal.toRawSignoUnder numbering Signal.SIGTERM

        let ended (call : string) (fate : ProcessFate<'Outcome, int, string>) : UnixSystem<int, string> =
            match fate with
            | ProcessFate.ProcessEnded (_, machine) -> machine
            | ProcessFate.Continues (outcome, _) ->
                failwith $"%A{ending}: %s{call} left the process running, answering %A{outcome}"

        let returned (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixSignal.onReturnToUser caller machine with
            | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, machine) -> machine
            | other -> failwith $"%A{ending}: the return to user mode answered %A{other}"

        let mask (how : SignalMaskChange) (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
            let how =
                match SimulatedUnixPlatform.flavour (UnixSystem.platform machine), how with
                | SimulatedUnixFlavour.Linux, SignalMaskChange.Block -> 0
                | SimulatedUnixFlavour.Linux, _ -> 1
                | SimulatedUnixFlavour.Darwin, SignalMaskChange.Block -> 1
                | SimulatedUnixFlavour.Darwin, _ -> 2

            let set = SignalMask.ofSignals numbering (Set.singleton Signal.SIGTERM)

            match UnixSignal.pthreadSigmask caller how (Some set) machine with
            | Ok (_, machine) -> machine
            | Error errno -> failwith $"%A{ending}: pthread_sigmask: %O{errno}"

        match ending with
        | Ending.ExitGroup -> UnixThreadLifecycle.exitGroup caller 0 machine |> snd
        | Ending.Kill ->
            match UnixSignal.kill caller (ProcessId.toInt32 pid) 9 machine with
            | Ok fate -> ended "kill" fate
            | Error errno -> failwith $"kill: %O{errno}"
        | Ending.Raise ->
            match UnixSignal.pthreadKill caller 0 sigterm machine with
            | Ok fate -> ended "pthread_kill" fate
            | Error errno -> failwith $"pthread_kill: %O{errno}"
        | Ending.ReturnToUser ->
            let machine = machine |> mask SignalMaskChange.Block |> returned

            let machine =
                match UnixSignal.pthreadKill caller 0 sigterm machine with
                | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, machine)) -> returned machine
                | other -> failwith $"pthread_kill of a blocked SIGTERM: %A{other}"

            machine
            |> mask SignalMaskChange.Unblock
            |> UnixSignal.onReturnToUser caller
            |> ended "onReturnToUser"
        | Ending.LastThread ->
            let others =
                UnixSystem.threads pid machine |> Map.keys |> Seq.filter ((<>) 0) |> List.ofSeq

            let machine =
                (machine, others)
                ||> List.fold (fun machine thread ->
                    match UnixThreadLifecycle.exitThread (Caller.make pid thread) 0 machine with
                    | ProcessFate.Continues ((), machine) -> machine
                    | other -> failwith $"thread %d{thread}'s exit: %A{other}"
                )

            UnixThreadLifecycle.exitThread caller 0 machine
            |> ended "the last thread's exit"
        | Ending.BrokenPipe ->
            match UnixPipe.pipe2 caller 0 UserBuffer.Mapped machine with
            | Pipe2Answer.Created (readFd, writeFd), machine ->
                let machine =
                    match UnixDescriptor.close caller readFd machine with
                    | SyscallAnswer.Completed 0L, machine -> machine
                    | other, _ -> failwith $"close: %A{other}"

                match UnixReadWrite.write caller writeFd UserBuffer.Mapped 1UL machine with
                | CallProgress.Answered fate -> ended "write" fate
                | CallProgress.NeedsCopyIn paused ->
                    UnixReadWrite.writeWithBytes (ImmutableArray.Create 0uy) paused |> ended "write"
            | other -> failwith $"pipe2: %A{other}"

    /// A `dup2` of `oldFd` onto `newFd`, and the close of `oldFd`, by the
    /// leader of the process `pid`.
    let private dup2
        (pid : ProcessId)
        (oldFd : int)
        (newFd : int)
        (view : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixDescriptor.tryDup2 (Caller.make pid (Proc.leader pid view)) oldFd newFd view with
        | Ok (SyscallAnswer.Completed fd, view) when int fd = newFd -> KeventWorld.closeIn pid oldFd view
        | other -> failwith $"dup2 %d{oldFd} %d{newFd}: %A{other}"

    [<Test>]
    let ``an ended process is gone from the machine, and no call can be made in it`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]
            let machine = exitedOk a machine

            Machines.processIds machine |> shouldEqual (Set.singleton b)
            Machines.focus a machine |> shouldEqual None
            Machines.assertClean machine

            let error =
                Assert.Throws<System.InvalidOperationException> (fun () ->
                    UnixSystem.step (Caller.make a 0) Syscall.GetProcessId machine |> ignore
                )

            error.Message |> shouldContainText $"holds no process %O{a}"

    [<Test>]
    let ``a process alone on its machine ends on the machine it ran on, leaving no process`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 1
            let view = Machines.viewOf pids.[0] machine

            match UnixThreadLifecycle.tryExitGroup (Callers.thread 0 view) 3 view with
            | Ok (ended, after) ->
                EndedProcess.termination ended
                |> shouldEqual (
                    ProcessTermination.Exited (ExitStatus.ofExitArgument (SimulatedUnixPlatform.flavour platform) 3)
                )

                EndedProcess.processId ended |> shouldEqual pids.[0]
                EndedMachine.assertNoneLeft after
                Machines.assertClean after
            | Error refusal -> failwith $"exit_group: %s{ProcessEndRefusal.describe refusal}"

    /// Every delivery `machine` has made, oldest first, with each one's bytes.
    let private deliveries (machine : UnixSystem<int, string>) : (ExternalEndpoint * byte list) list =
        DeliveryLog.toList machine.Machine.Delivered
        |> List.map (fun delivery -> delivery.Endpoint, List.ofSeq delivery.Bytes)

    /// `pid`'s thread 0 writes `text` to its descriptor `fd`, which takes all of it.
    let private writeIn
        (pid : ProcessId)
        (fd : int)
        (text : string)
        (machine : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let bytes = ImmutableArray.CreateRange (System.Text.Encoding.ASCII.GetBytes text)

        Machines.doIn
            pid
            (fun view ->
                match WriteOutcomes.writeBytesAs (Caller.make pid 0) fd bytes view with
                | Ok (WriteStep.Returns (WriteAnswer.Completed written, view)) when int written = bytes.Length -> view
                | other -> failwith $"write %d{fd} %s{text}: %A{other}"
            )
            machine

    [<Test>]
    let ``a process's end leaves what every process delivered to its launched pipes as it was`` () : unit =
        // A client reads a process's standard output after the process has ended, from
        // the deliveries its launched pipes made: closing those pipes at the end must not
        // take any of them back, nor reorder them among another process's.
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]

            let machine =
                machine |> writeIn a 1 "a out" |> writeIn b 1 "b out" |> writeIn a 2 "a err"

            let before = deliveries machine

            before
            |> List.map fst
            |> shouldEqual [ ExternalEndpoint (a, 1) ; ExternalEndpoint (b, 1) ; ExternalEndpoint (a, 2) ]

            let machine = exitedOk a machine
            deliveries machine |> shouldEqual before

            let machine = writeIn b 2 "b err" machine
            let machine = exitedOk b machine

            deliveries machine
            |> shouldEqual (before @ [ ExternalEndpoint (b, 2), List.ofSeq "b err"B ])

    [<Test>]
    let ``a process's end sends each peer its FIN in the order each flavour releases them`` () : unit =
        // Replays `exit-close-order.c` sections O and D: the ending process
        // holds three connections, made in the order 1, 2, 3, at the
        // descriptors `layout` gives each, and the other watches their peers in
        // one wait, registered in yet another order. Section D's first
        // connection is at a second descriptor as well, a dup. The probe's
        // process exits; every other call that ends a process closes its
        // descriptors as the exit does.
        let sections =
            [
                [ 12 ; 10 ; 11 ], None, [ 1UL ; 3UL ; 2UL ], [ 1UL ; 3UL ; 2UL ]
                [ 10 ; 11 ; 12 ], Some 22, [ 1UL ; 3UL ; 2UL ], [ 3UL ; 2UL ; 1UL ]
            ]

        for platform in Machines.platforms do
            for ending, (layout, alias, linux, darwin) in List.allPairs (endingsOn platform) sections do
                let pids, machine = Machines.ofCount platform 2
                let a, b = pids.[0], pids.[1]

                let listener, machine =
                    Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine

                let connect (target : int) (machine : UnixSystem<int, string>) =
                    let client, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
                    let machine = Machines.doIn a (dup2 a client target) machine

                    let accepted, machine =
                        Machines.inProcess b (KeventWorld.acceptIn b listener) machine

                    accepted, machine

                let s1, machine = connect layout.[0] machine
                let s2, machine = connect layout.[1] machine
                let s3, machine = connect layout.[2] machine

                let machine =
                    match alias with
                    | None -> machine
                    | Some alias ->
                        Machines.doIn
                            a
                            (fun view ->
                                match
                                    UnixDescriptor.tryDup2 (Caller.make a (Proc.leader a view)) layout.[0] alias view
                                with
                                | Ok (SyscallAnswer.Completed _, view) -> view
                                | other -> failwith $"dup2: %A{other}"
                            )
                            machine

                let registered = [ s3, 3UL ; s1, 1UL ; s2, 2UL ]

                let report, machine =
                    match SimulatedUnixPlatform.flavour platform with
                    | SimulatedUnixFlavour.Linux ->
                        let epoll, machine =
                            Machines.inProcess
                                b
                                (fun view ->
                                    let epoll, view =
                                        match UnixPoll.tryEpollCreate1 (Caller.make b (Proc.leader b view)) 0 view with
                                        | Ok (Ok created) -> created
                                        | other -> failwith $"epoll_create1: %A{other}"

                                    let view =
                                        (view, registered)
                                        ||> List.fold (fun view (fd, data) ->
                                            match
                                                UnixPoll.tryEpollCtl
                                                    (Caller.make b (Proc.leader b view))
                                                    epoll
                                                    1
                                                    fd
                                                    (EpollEventArgument.Readable (
                                                        EpollEvents.In
                                                        ||| EpollEvents.RdHup
                                                        ||| EpollEvents.EdgeTriggered,
                                                        data
                                                    ))
                                                    view
                                            with
                                            | Ok (EpollCtlAnswer.Changed, view) -> view
                                            | other -> failwith $"epoll_ctl: %A{other}"
                                        )

                                    epoll, view
                                )
                                machine

                        let report (machine : UnixSystem<int, string>) =
                            Machines.inProcess
                                b
                                (fun view ->
                                    match UnixPoll.tryEpollWait (Caller.make b 4) epoll 8 UserBuffer.Mapped 0 view with
                                    | Ok (EpollWaitOutcome.Answered events, view) -> List.map fst events, view
                                    | other -> failwith $"epoll_wait: %A{other}"
                                )
                                machine

                        report, machine
                    | SimulatedUnixFlavour.Darwin ->
                        let kq, machine =
                            Machines.inProcess
                                b
                                (fun view ->
                                    let kq, view = KeventWorld.kqueueIn b view

                                    kq,
                                    (view, registered)
                                    ||> List.fold (fun view (fd, data) ->
                                        KeventWorld.registerIn b kq fd KeventFilter.Read addClear data view
                                    )
                                )
                                machine

                        let report (machine : UnixSystem<int, string>) =
                            let events, machine = reported b kq 8 machine
                            events |> List.map (fun event -> event.UserData), machine

                        report, machine

                report machine |> fst |> shouldEqual []

                let machine = endedBy ending a machine
                Machines.assertClean machine

                let expected =
                    match SimulatedUnixPlatform.flavour platform with
                    | SimulatedUnixFlavour.Linux -> linux
                    | SimulatedUnixFlavour.Darwin -> darwin

                (ending, layout, report machine |> fst)
                |> shouldEqual (ending, layout, expected)

    [<Test>]
    let ``a process's end closes its pipes, kqueues and epoll instances, and lets its locks go`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]
            let lockEx = 2

            let openLocked (pid : ProcessId) (view : UnixSystem<int, string>) : int * UnixSystem<int, string> =
                match
                    OpenFlagWords.openPathIn
                        pid
                        {
                            Access = FileAccessMode.ReadWrite
                            Create = true
                            Exclusive = false
                            Truncate = false
                            NoFollow = false
                            CloseOnExec = false
                            Synchronous = false
                            DataSynchronous = false
                            Directory = false
                        }
                        (PathArg.ofText "/locked")
                        0o644
                        view
                with
                | Ok (SyscallAnswer.Completed fd, view) -> int fd, view
                | other -> failwith $"open: %A{other}"

            let held, machine = Machines.inProcess a (openLocked a) machine

            let machine =
                Machines.doIn
                    a
                    (fun view ->
                        match UnixDescriptor.tryFlock (Caller.make a 1) held lockEx view with
                        | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), view) -> view
                        | other -> failwith $"flock: %A{other}"
                    )
                    machine

            // A pipe, and the flavour's event queue.
            let machine =
                Machines.doIn
                    a
                    (fun view ->
                        let view =
                            match UnixPipe.tryPipe2 (Caller.make a (Proc.leader a view)) 0 UserBuffer.Mapped view with
                            | Ok (_, view) -> view
                            | Error refusal -> failwith $"pipe2: %A{refusal}"

                        match SimulatedUnixPlatform.flavour platform with
                        | SimulatedUnixFlavour.Linux ->
                            match UnixPoll.tryEpollCreate1 (Caller.make a (Proc.leader a view)) 0 view with
                            | Ok (Ok (_, view)) -> view
                            | other -> failwith $"epoll_create1: %A{other}"
                        | SimulatedUnixFlavour.Darwin -> KeventWorld.kqueueIn a view |> snd
                    )
                    machine

            let waiting, machine = Machines.inProcess b (openLocked b) machine

            let machine =
                Machines.doIn
                    b
                    (fun view ->
                        match UnixDescriptor.tryFlock (Caller.make b 1) waiting lockEx view with
                        | Ok (SyscallOutcome.WouldBlock _, view) -> view
                        | other -> failwith $"flock: expected to sleep, got %A{other}"
                    )
                    machine

            let named (pid : ProcessId) (view : UnixSystem<int, string>) : Set<OpenFileDescriptionId> =
                FileDescriptorRegistry.fds (UnixSystem.fileDescriptors pid view)
                |> Map.values
                |> Set.ofSeq

            let survivors = named b (Machines.viewOf b machine)
            let machine = exitedOk a machine
            Machines.assertClean machine

            // Only the survivor's descriptions are left, and its lock is free.
            OpenFileTable.descriptions (UnixSystem.openFiles (Machines.viewOf b machine))
            |> Map.keys
            |> Set.ofSeq
            |> shouldEqual survivors

            Machines.waking [ b, 1 ] machine |> ignore<UnixSystem<int, string>>

    /// A listener's release resets each client still in its queue
    /// (`tcp-shutdown.c` section Q, docs/plans/2026-10-08-tcp-shutdown-linger),
    /// so the end of the listener's process resets another process's clients
    /// queued there, and wakes what waits on them as any reset does: a read
    /// asleep on one, a `poll` asleep on another, and that one's registration
    /// in an epoll instance (Linux) or a kqueue (Darwin).
    [<Test>]
    let ``a process's end resets another process's clients queued in its listener, and wakes their waiters`` () : unit =
        for platform in Machines.platforms do
            let flavour = SimulatedUnixPlatform.flavour platform
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]
            let _, machine = Machines.inProcess a (KeventWorld.listenerAtIn a 8080us) machine

            // A blocking client, whose read sleeps.
            let reader, machine =
                Machines.inProcess
                    b
                    (fun view ->
                        let fd, view = KeventWorld.streamIn b false view

                        match KeventWorld.connectIn b fd 8080us view with
                        | SyscallAnswer.Completed 0L, view -> fd, view
                        | other, _ -> failwith $"connect: %A{other}"
                    )
                    machine

            let machine =
                Machines.doIn
                    b
                    (fun view ->
                        match UnixReadWrite.tryRead (Caller.make b 1) reader UserBuffer.Mapped 4096UL view with
                        | Ok (ReadOutcome.WouldBlock _, view) -> view
                        | other -> failwith $"read: expected to sleep, got %A{other}"
                    )
                    machine

            // A non-blocking client, registered edge-triggered and polled.
            let watched, machine = Machines.inProcess b (KeventWorld.clientIn b 8080us) machine

            let queue, machine =
                Machines.inProcess
                    b
                    (fun view ->
                        match flavour with
                        | SimulatedUnixFlavour.Linux ->
                            let epoll, view =
                                match UnixPoll.tryEpollCreate1 (Caller.make b (Proc.leader b view)) 0 view with
                                | Ok (Ok created) -> created
                                | other -> failwith $"epoll_create1: %A{other}"

                            let interest =
                                EpollEvents.In
                                ||| EpollEvents.Out
                                ||| EpollEvents.RdHup
                                ||| EpollEvents.EdgeTriggered

                            match
                                UnixPoll.tryEpollCtl
                                    (Caller.make b (Proc.leader b view))
                                    epoll
                                    1
                                    watched
                                    (EpollEventArgument.Readable (interest, 7UL))
                                    view
                            with
                            | Ok (EpollCtlAnswer.Changed, view) -> epoll, view
                            | other -> failwith $"epoll_ctl: %A{other}"
                        | SimulatedUnixFlavour.Darwin ->
                            let kq, view = KeventWorld.kqueueIn b view
                            kq, KeventWorld.registerIn b kq watched KeventFilter.Read addClear 7UL view
                    )
                    machine

            // What the queue reports at once, in b's view.
            let drain (machine : UnixSystem<int, string>) : string list * UnixSystem<int, string> =
                Machines.inProcess
                    b
                    (fun view ->
                        match flavour with
                        | SimulatedUnixFlavour.Linux ->
                            match UnixPoll.tryEpollWait (Caller.make b 3) queue 8 UserBuffer.Mapped 0 view with
                            | Ok (EpollWaitOutcome.Answered events, view) ->
                                events |> List.map (fun (data, events) -> $"%d{data} 0x%x{events}"), view
                            | other -> failwith $"epoll_wait: %A{other}"
                        | SimulatedUnixFlavour.Darwin ->
                            match KeventWorld.applyIn b queue [] 8 view with
                            | KeventOutcome.Answered events, view ->
                                events
                                |> List.map (fun event ->
                                    let eof =
                                        if event.Flags &&& KeventFlags.Eof <> 0us then
                                            " EOF"
                                        else
                                            ""

                                    $"%d{event.UserData}%s{eof} %d{event.FilterFlags}"
                                ),
                                view
                            | other, _ -> failwith $"kevent: %A{other}"
                    )
                    machine

            let _, machine = drain machine
            let machine = sleepInPoll b 2 [ entry watched pollIn ] machine
            Machines.assertClean machine
            Machines.wakes machine |> shouldEqual []

            let machine = exitedOk a machine
            Machines.assertClean machine

            let kind (primitive : WakePrimitive) : string =
                match primitive with
                | WakePrimitive.ConnectionReadable _ -> "a read"
                | WakePrimitive.DescriptorReady _
                | WakePrimitive.KqueuePollReportable -> "a poll"
                | other -> failwith $"unexpected wake %A{other}"

            let woken, machine = Machines.wake machine

            woken
            |> List.map (fun (thread, fired) -> thread, fired |> Set.map kind)
            |> shouldEqual [ (b, 1), Set.singleton "a read" ; (b, 2), Set.singleton "a poll" ]

            let read, machine =
                Machines.inProcess
                    b
                    (fun view ->
                        match UnixReadWrite.tryFinishRead (Caller.make b 1) view with
                        | Ok (ReadOutcome.Answered answer, view) -> answer, view
                        | other -> failwith $"finishRead: %A{other}"
                    )
                    machine

            read |> shouldEqual (ReadAnswer.Failed UnixError.ECONNRESET)

            let polled, machine = finishPoll b 2 machine

            polled
            |> shouldEqual (
                match flavour with
                | SimulatedUnixFlavour.Linux -> PollOutcome.Answered ([ pollIn ||| 0x0008s ||| pollHup ], 1)
                | SimulatedUnixFlavour.Darwin -> PollOutcome.Answered ([ pollIn ||| pollHup ], 1)
            )

            let reported, machine = drain machine

            reported
            |> shouldEqual (
                match flavour with
                | SimulatedUnixFlavour.Linux -> [ "7 0x201d" ]
                | SimulatedUnixFlavour.Darwin -> [ "7 EOF 54" ]
            )

            // The listener's port is free again.
            let _, machine = Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine
            Machines.assertClean machine

    /// The measured lines of `listener-exit-order.c`
    /// (docs/plans/2026-10-08-tcp-shutdown-linger) for `flavour`, embedded.
    let private listenerExitOrder (flavour : SimulatedUnixFlavour) : string list =
        let resource =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.listenerExitOrder.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.listenerExitOrder.darwin.txt"

        use stream =
            match System.Reflection.Assembly.GetExecutingAssembly().GetManifestResourceStream resource with
            | null -> failwith $"embedded resource %s{resource} not found"
            | stream -> stream

        use reader = new System.IO.StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> Array.filter (fun line -> line <> "")
        |> Array.toList

    /// `listener-exit-order.c` made on the machine: a process whose listener
    /// holds another process's client queued, and whose connected socket's
    /// peer is that other process's, ends with the two at descriptors 10 and
    /// 11 in either order; the other process's queue of events reports the
    /// FIN and the reset in the order the end released them, which is the
    /// order of the descriptors, a listener's release taking its place among
    /// the rest. Printed as the probe prints it.
    [<Test>]
    let ``a process's end releases its listener where its descriptor falls among the rest, as each flavour was measured to``
        ()
        : unit
        =
        for platform in Machines.platforms do
            let flavour = SimulatedUnixPlatform.flavour platform

            let replayed (ending : Ending) (listenerFirst : bool) : string =
                let pids, machine = Machines.ofCount platform 2
                let child, parent = pids.[0], pids.[1]

                let parentListener, machine =
                    Machines.inProcess parent (KeventWorld.listenerAtIn parent 8081us) machine

                let machine =
                    Machines.doIn
                        child
                        (fun view ->
                            let listener, view = KeventWorld.listenerAtIn child 8080us view
                            let connected, view = KeventWorld.streamIn child false view

                            let view =
                                match KeventWorld.connectIn child connected 8081us view with
                                | SyscallAnswer.Completed 0L, view -> view
                                | other, _ -> failwith $"connect: %A{other}"

                            let listenerAt, connectedAt = if listenerFirst then 10, 11 else 11, 10
                            view |> dup2 child listener listenerAt |> dup2 child connected connectedAt
                        )
                        machine

                let c, machine =
                    Machines.inProcess parent (KeventWorld.acceptIn parent parentListener) machine

                let q, machine =
                    Machines.inProcess parent (KeventWorld.clientIn parent 8080us) machine

                let queue, machine =
                    Machines.inProcess
                        parent
                        (fun view ->
                            match flavour with
                            | SimulatedUnixFlavour.Linux ->
                                let epoll, view =
                                    match
                                        UnixPoll.tryEpollCreate1 (Caller.make parent (Proc.leader parent view)) 0 view
                                    with
                                    | Ok (Ok created) -> created
                                    | other -> failwith $"epoll_create1: %A{other}"

                                let interest =
                                    EpollEvents.In
                                    ||| EpollEvents.Out
                                    ||| EpollEvents.RdHup
                                    ||| EpollEvents.EdgeTriggered

                                let add (fd : int) (data : char) (view : UnixSystem<int, string>) =
                                    match
                                        UnixPoll.tryEpollCtl
                                            (Caller.make parent (Proc.leader parent view))
                                            epoll
                                            1
                                            fd
                                            (EpollEventArgument.Readable (interest, uint64 data))
                                            view
                                    with
                                    | Ok (EpollCtlAnswer.Changed, view) -> view
                                    | other -> failwith $"epoll_ctl: %A{other}"

                                epoll, view |> add c 'c' |> add q 'q'
                            | SimulatedUnixFlavour.Darwin ->
                                let kq, view = KeventWorld.kqueueIn parent view

                                kq,
                                view
                                |> KeventWorld.registerIn parent kq c KeventFilter.Read addClear (uint64 'c')
                                |> KeventWorld.registerIn parent kq q KeventFilter.Read addClear (uint64 'q')
                        )
                        machine

                let events (machine : UnixSystem<int, string>) : string list * UnixSystem<int, string> =
                    Machines.inProcess
                        parent
                        (fun view ->
                            match flavour with
                            | SimulatedUnixFlavour.Linux ->
                                match
                                    UnixPoll.tryEpollWait (Caller.make parent 3) queue 4 UserBuffer.Mapped 0 view
                                with
                                | Ok (EpollWaitOutcome.Answered events, view) ->
                                    events |> List.map (fun (data, events) -> $"%c{char data}(0x%x{events})"), view
                                | other -> failwith $"epoll_wait: %A{other}"
                            | SimulatedUnixFlavour.Darwin ->
                                match KeventWorld.applyIn parent queue [] 4 view with
                                | KeventOutcome.Answered events, view ->
                                    events
                                    |> List.map (fun event ->
                                        let eof = if event.Flags &&& KeventFlags.Eof <> 0us then "EOF" else ""
                                        $"%c{char event.UserData}(%s{eof}/%d{event.FilterFlags})"
                                    ),
                                    view
                                | other, _ -> failwith $"kevent: %A{other}"
                        )
                        machine

                let _, machine = events machine
                let machine = endedBy ending child machine
                Machines.assertClean machine
                let reported, _ = events machine

                let layout =
                    if listenerFirst then
                        "10, connected socket at 11"
                    else
                        "11, connected socket at 10"

                let reported = reported |> List.map (fun event -> event + " ") |> String.concat ""
                $"listener at %s{layout}: %s{reported}"

            let measured = listenerExitOrder flavour
            measured |> List.length |> shouldEqual 10

            // The probe's process exits; every other call that ends a process
            // closes its descriptors as the exit does.
            for ending in endingsOn platform do
                (ending,
                 [
                     for _ in 1..5 do
                         replayed ending true
                         replayed ending false
                 ])
                |> shouldEqual (ending, measured)

    [<Test>]
    let ``a process's end closes its listener and its own queued client, in either order`` () : unit =
        for platform in Machines.platforms do
            for listenerHigher in [ true ; false ] do
                let pids, machine = Machines.ofCount platform 2
                let a = pids.[0]

                let machine =
                    Machines.doIn
                        a
                        (fun view ->
                            let listener, view = KeventWorld.listenerAtIn a 8080us view
                            let client, view = KeventWorld.clientIn a 8080us view

                            if listenerHigher then
                                dup2 a listener 9 view
                            else
                                dup2 a client 9 view
                        )
                        machine

                let machine = exitedOk a machine
                Machines.assertClean machine

    [<Test>]
    let ``a process's end releases what only its sleeping calls held, and its directory`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a, b = pids.[0], pids.[1]

        // Under Linux a sleeping accept holds its listener past the close of
        // its last descriptor.
        let listener, machine =
            Machines.inProcess a (KeventWorld.listenerAtIn a 8080us) machine

        let machine = sleepInAccept a 1 listener machine
        let machine = Machines.doIn a (KeventWorld.closeIn a listener) machine

        // ...and a stands in a directory b has removed.
        let machine =
            Machines.doIn
                a
                (fun view ->
                    Answered.mkdir (Caller.make a (Proc.leader a view)) (PathArg.ofText "/d") 0o755 view
                    |> snd
                )
                machine

        let machine =
            Machines.doIn
                a
                (fun view ->
                    Answered.chdir (Caller.make a (Proc.leader a view)) (PathArg.ofText "/d") view
                    |> snd
                )
                machine

        let standing = (Proc.state a (Machines.viewOf a machine)).CurrentDirectoryInode

        let machine =
            Machines.doIn
                b
                (fun view ->
                    Answered.rmdir (Caller.make b (Proc.leader b view)) (UnixPath.parseOrFail "test" "/d") view
                    |> snd
                )
                machine

        Machines.assertClean machine

        let machine = exitedOk a machine
        Machines.assertClean machine

        let view = Machines.viewOf b machine
        VirtualFileSystem.tryGet standing view.Machine.FileSystem |> shouldEqual None

        // The listener's port is free again.
        let _, machine = Machines.inProcess b (KeventWorld.listenerAtIn b 8080us) machine
        Machines.assertClean machine

    [<Test>]
    let ``the last process's end leaves a machine of none, every descriptor closed`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 1

            let machine =
                Machines.doIn
                    pids.[0]
                    (fun view ->
                        let listener, view = KeventWorld.listenerAt 8080us view
                        let client, view = KeventWorld.clientIn pids.[0] 8080us view
                        let _, view = KeventWorld.accept listener view
                        ignore client
                        view
                    )
                    machine

            match exitIn pids.[0] 3 machine with
            | Ok (_, machine) ->
                Machines.processIds machine |> shouldEqual Set.empty
                Machines.checkInvariants machine |> shouldEqual []
                OpenFileTable.descriptions machine.Machine.OpenFiles |> shouldEqual Map.empty
                machine.Machine.Sockets |> shouldEqual Map.empty
                machine.Machine.Connections |> shouldEqual Map.empty
            | Error refusal -> failwith $"exit_group: %s{ProcessEndRefusal.describe refusal}"

    /// Nothing yet passes a descriptor from one process to another, so no queue
    /// a kernel wakes one waiter of is shared by two processes. `fork` would
    /// share one; this forges the state it would leave, the other process's
    /// table naming the listener's description too, to hold the machine's
    /// wakes to choosing across processes.
    [<Test>]
    let ``a woken call in one process keeps a shared listener from waking another process's accepter`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a, b = pids.[0], pids.[1]

        let listener, machine =
            Machines.inProcess a (KeventWorld.listenerAtIn a 8080us) machine

        let shared = 9

        let machine =
            let listenerId = KeventWorld.idOfIn a listener (Machines.viewOf a machine)

            let named (pid : ProcessId) =
                FileDescriptorRegistry.fds (UnixSystem.fileDescriptors pid (Machines.viewOf pid machine))

            Machines.doIn
                b
                (fun view ->
                    let fds = named b |> Map.add shared listenerId
                    let openFiles = UnixSystem.openFiles view

                    let forged =
                        FileDescriptorRegistry.Unchecked.ofParts
                            SimulatedUnixFlavour.Linux
                            fds
                            (OpenFileTable.descriptions openFiles)
                            (OpenFileDescriptionId 1000L)

                    // Each description counts the descriptors naming it in
                    // both tables.
                    let forged =
                        (forged, named a |> Map.toList |> List.countBy snd)
                        ||> List.fold (fun registry (id, inA) ->
                            let inB = fds |> Map.filter (fun _ named -> named = id) |> Map.count
                            FileDescriptorRegistry.Unchecked.setDescriptorCount id (inA + inB) registry
                        )

                    Proc.withFileDescriptors b forged view
                )
                machine

        Machines.checkInvariants machine |> shouldEqual []

        // a's accepter parks first, then b's, on the one listener; then a
        // connection is queued.
        let machine = machine |> sleepInAccept a 1 listener |> sleepInAccept b 1 shared
        let _, machine = Machines.inProcess b (KeventWorld.clientIn b 8080us) machine
        Machines.checkInvariants machine |> shouldEqual []

        let woken = Machines.waking [ a, 1 ] machine

        // Either woken and not yet finished stands for the connection, in
        // whichever process, so the other does not wake.
        Machines.wakes woken |> shouldEqual []

        Machines.wakes (ForgedPark.wokenCaller (Caller.make b 1) machine)
        |> shouldEqual []

    [<Test>]
    let ``a file one process has open outlives its unlink by another, until it is closed`` () : unit =
        for platform in Machines.platforms do
            let pids, machine = Machines.ofCount platform 2
            let a, b = pids.[0], pids.[1]

            let opened, machine =
                Machines.inProcess
                    b
                    (fun view ->
                        match
                            OpenFlagWords.openPathIn
                                b
                                {
                                    Access = FileAccessMode.ReadWrite
                                    Create = true
                                    Exclusive = false
                                    Truncate = false
                                    NoFollow = false
                                    CloseOnExec = false
                                    Synchronous = false
                                    DataSynchronous = false
                                    Directory = false
                                }
                                (PathArg.ofText "/shared")
                                0o644
                                view
                        with
                        | Ok (SyscallAnswer.Completed fd, view) -> int fd, view
                        | other -> failwith $"open: %A{other}"
                    )
                    machine

            let inode =
                match UnixSystem.descriptorTarget b opened (Machines.viewOf b machine) with
                | Some (OpenFileTarget.File (inode, _)) -> inode
                | other -> failwith $"the descriptor names %A{other}"

            let answer, machine =
                Machines.inProcess
                    a
                    (fun view ->
                        Answered.unlink
                            (Caller.make a (Proc.leader a view))
                            (UnixPath.parseOrFail "test" "/shared")
                            view
                    )
                    machine

            answer |> shouldEqual (SyscallAnswer.Completed 0L)
            Machines.assertClean machine

            VirtualFileSystem.tryGet inode (UnixSystem.fileSystem (Machines.viewOf a machine))
            |> Option.isSome
            |> shouldEqual true

            let machine = Machines.doIn b (KeventWorld.closeIn b opened) machine
            Machines.assertClean machine

            VirtualFileSystem.tryGet inode (UnixSystem.fileSystem (Machines.viewOf a machine))
            |> shouldEqual None

    [<Test>]
    let ``a process's end releases what the call that ended it let go of`` () : unit =
        // Under Linux a sleeping write holds its pipe end past the close of its
        // descriptor. The reader's close then lets the write finish into
        // SIGPIPE, which ends the process; the finish has let go of the write
        // end already, so no park records it.
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a = pids.[0]

        let write (thread : int) (fd : int) (count : int) (view : UnixSystem<int, string>) =
            WriteOutcomes.admitThenWriteAs
                (Caller.make a thread)
                fd
                UserBuffer.Mapped
                (ImmutableArray.Create<byte> (Array.zeroCreate<byte> count))
                view

        let (reader, writer), machine =
            Machines.inProcess
                a
                (fun view ->
                    match UnixPipe.tryPipe2 (Caller.make a (Proc.leader a view)) 0 UserBuffer.Mapped view with
                    | Ok (Pipe2Answer.Created (reader, writer), view) -> (reader, writer), view
                    | other -> failwith $"pipe2: %A{other}"
                )
                machine

        let pipe =
            match UnixSystem.descriptorTarget a reader (Machines.viewOf a machine) with
            | Some (OpenFileTarget.Pipe (pipe, _)) -> pipe
            | other -> failwith $"the read end names %A{other}"

        let machine =
            Machines.doIn
                a
                (fun view ->
                    let view =
                        match write 0 writer 65536 view with
                        | Ok (WriteStep.Returns (WriteAnswer.Completed 65536L, view)) -> view
                        | other -> failwith $"filling the pipe: %A{other}"

                    match write 1 writer 1 view with
                    | Ok (WriteStep.WouldBlock (_, view)) -> view
                    | other -> failwith $"the write: expected to sleep, got %A{other}"
                )
                machine

        let machine =
            machine
            |> Machines.doIn a (KeventWorld.closeIn a writer)
            |> Machines.doIn a (KeventWorld.closeIn a reader)

        Machines.assertClean machine

        match UnixReadWrite.tryAdmitFinishWrite 1 (Proc.view a machine) with
        | Ok (WriteStep.ProcessEnded (_, dead)) ->
            let machine = ProcessView.unfocusWithout dead
            Machines.assertClean machine
            machine.Machine.Pipes |> Map.containsKey pipe |> shouldEqual false
        | other -> failwith $"finishing the write: expected the process to end, got %A{other}"

    [<Test>]
    let ``a process's end lets a listener only its sleeping accept held go after its own client`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a = pids.[0]

        let listener, machine =
            Machines.inProcess a (KeventWorld.listenerAtIn a 8080us) machine

        let machine = sleepInAccept a 1 listener machine
        let machine = Machines.doIn a (KeventWorld.closeIn a listener) machine
        let _, machine = Machines.inProcess a (KeventWorld.clientIn a 8080us) machine
        Machines.assertClean machine

        let machine = exitedOk a machine
        Machines.assertClean machine

    // ------------------------------------------------------- inotify

    /// `inotify_init1(flags)` and a watch of `path` for `mask`, by the leader
    /// of the process `pid` in `view`: the instance's descriptor.
    let private watching
        (pid : ProcessId)
        (flags : int)
        (path : string)
        (mask : uint32)
        (view : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let fd, view =
            match UnixInotify.tryInotifyInit1 (Caller.make pid (Proc.leader pid view)) flags view with
            | Ok (Ok created) -> created
            | other -> failwith $"inotify_init1: %A{other}"

        match
            Eager.tryInotifyAddWatchAs (Caller.make pid (Proc.leader pid view)) fd (PathArg.ofText path) mask view
        with
        | Ok (SyscallAnswer.Completed _, view) -> fd, view
        | other -> failwith $"inotify_add_watch(%s{path}): %A{other}"

    /// The bytes the instance `fd` of `pid` holds, as `FIONREAD` reports them.
    let private queuedBytes (pid : ProcessId) (fd : int) (machine : UnixSystem<int, string>) : int =
        let view = Machines.viewOf pid machine

        match UnixDescriptor.tryBytesAvailable (Caller.make pid (Proc.leader pid view)) fd UserBuffer.Mapped view with
        | Ok (BytesAvailableAnswer.Reported count) -> count
        | other -> failwith $"FIONREAD on %d{fd}: %A{other}"

    /// `open(path, O_WRONLY|O_CREAT|O_EXCL)` and its close, by the process
    /// `pid` in `view`.
    let private create (pid : ProcessId) (path : string) (view : UnixSystem<int, string>) : UnixSystem<int, string> =
        match
            OpenFlagWords.openPathIn
                pid
                {
                    Access = FileAccessMode.WriteOnly
                    Create = true
                    Exclusive = true
                    Truncate = false
                    NoFollow = false
                    CloseOnExec = false
                    Synchronous = false
                    DataSynchronous = false
                    Directory = false
                }
                (PathArg.ofText path)
                0o644
                view
        with
        | Ok (SyscallAnswer.Completed fd, view) -> KeventWorld.closeIn pid (int fd) view
        | other -> failwith $"open(%s{path}): %A{other}"

    let private inCreate : uint32 = 0x100u

    [<Test>]
    let ``a file another process creates wakes a read asleep on an instance watching its directory`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a, b = pids.[0], pids.[1]

        let machine =
            Machines.doIn
                a
                (fun view ->
                    Answered.mkdir (Caller.make a (Proc.leader a view)) (PathArg.ofText "/d") 0o755 view
                    |> snd
                )
                machine

        // Blocking, so that the read sleeps.
        let fd, machine = Machines.inProcess a (watching a 0 "/d" inCreate) machine

        let machine =
            Machines.doIn
                a
                (fun view ->
                    match UnixReadWrite.tryRead (Caller.make a 1) fd UserBuffer.Mapped 4096UL view with
                    | Ok (ReadOutcome.WouldBlock _, view) -> view
                    | other -> failwith $"read: expected to sleep, got %A{other}"
                )
                machine

        Machines.assertClean machine
        Machines.wakes machine |> shouldEqual []

        let machine = Machines.doIn b (create b "/d/x") machine
        Machines.assertClean machine

        let instance = KeventWorld.idOfIn a fd (Machines.viewOf a machine)

        let woken, machine = Machines.wake machine

        woken
        |> shouldEqual [ (a, 1), Set.singleton (WakePrimitive.InotifyRecordQueued instance) ]

        let records, machine =
            Machines.inProcess
                a
                (fun view ->
                    match UnixReadWrite.tryFinishRead (Caller.make a 1) view with
                    | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), view) ->
                        InotifyReplay.parse bytes |> List.map InotifyReplay.render, view
                    | other -> failwith $"finishRead: %A{other}"
                )
                machine

        Machines.assertClean machine
        records |> shouldEqual [ "wd=1 mask=CREATE cookie=0 len=16 name=\"x\"" ]

    [<Test>]
    let ``a change queues on each process's instance exactly when that instance watches it`` () : unit =
        let pids, machine = Machines.ofCount SimulatedUnixPlatform.linuxX64 2
        let a, b = pids.[0], pids.[1]

        let machine =
            machine
            |> Machines.doIn
                a
                (fun view ->
                    Answered.mkdir (Caller.make a (Proc.leader a view)) (PathArg.ofText "/d") 0o755 view
                    |> snd
                )
            |> Machines.doIn
                a
                (fun view ->
                    Answered.mkdir (Caller.make a (Proc.leader a view)) (PathArg.ofText "/e") 0o755 view
                    |> snd
                )

        let inA, machine = Machines.inProcess a (watching a 0x800 "/d" inCreate) machine
        let inB, machine = Machines.inProcess b (watching b 0x800 "/e" inCreate) machine

        // A change in a process's own view, to what its own instance watches,
        // and to what the other process's instance watches.
        let machine = Machines.doIn a (create a "/d/x") machine
        Machines.assertClean machine
        queuedBytes a inA machine |> shouldEqual 32
        queuedBytes b inB machine |> shouldEqual 0

        let machine = Machines.doIn a (create a "/e/y") machine
        Machines.assertClean machine
        queuedBytes a inA machine |> shouldEqual 32
        queuedBytes b inB machine |> shouldEqual 32

        // A change neither watches.
        let machine = Machines.doIn b (create b "/z") machine
        Machines.assertClean machine
        queuedBytes a inA machine |> shouldEqual 32
        queuedBytes b inB machine |> shouldEqual 32
