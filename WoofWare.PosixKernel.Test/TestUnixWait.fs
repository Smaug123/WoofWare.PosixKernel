namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open Microsoft.FSharp.Reflection
open NUnit.Framework
open WoofWare.PosixKernel

/// Park order, and which parked threads a system wakes.
///
/// The epoll half of `UnixWait.wakes` lives in `TestUnixSystemStep` and
/// `TestEpollWait`, beside the epoll fixtures that can make an epoll instance
/// deliverable.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixWait =

    let private withRegistry
        (registry : FileDescriptorRegistry)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        Lone.withFileDescriptors registry system

    let private idOf (fd : int) (system : UnixSystem<int, string>) : OpenFileDescriptionId =
        match FileDescriptorRegistry.tryFindWithId fd (Lone.fileDescriptors system) with
        | Some (id, _) -> id
        | None -> failwith $"fd %d{fd} names no description"

    let private withThread (name : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        Threads.ensure name system

    /// Two epoll instances, which contend under `flock` because they share one
    /// anonymous inode, with an exclusive lock held through `locker`; and threads 1 to 4.
    let private world : UnixSystem<int, string> * int * OpenFileDescriptionId * OpenFileDescriptionId =
        let system =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let lockerFd, registry =
            FileDescriptorRegistry.createEpoll
                (SimulatedUnixPlatform.flavour (UnixSystem.platform system))
                (Lone.fileDescriptors system)

        let blockedFd, registry =
            FileDescriptorRegistry.createEpoll SimulatedUnixFlavour.Linux registry

        let registry =
            match FileDescriptorRegistry.flock lockerFd (FlockRequest.Acquire FlockMode.Exclusive) registry with
            | registry, None -> registry
            | _, Some error -> failwith $"expected the lock to be granted, got %O{error}"

        let system =
            withRegistry registry system
            |> withThread 1
            |> withThread 2
            |> withThread 3
            |> withThread 4

        system, lockerFd, idOf lockerFd system, idOf blockedFd system

    let private system : UnixSystem<int, string> =
        let system, _, _, _ = world
        system

    let private lockerFd : int =
        let _, fd, _, _ = world
        fd

    let private locker : OpenFileDescriptionId =
        let _, _, locker, _ = world
        locker

    let private blocked : OpenFileDescriptionId =
        let _, _, _, blocked = world
        blocked

    /// The park each thread makes: 1 and 2 wait on an epoll instance, 3 and 4 for a
    /// lock, so that both kinds of park are in the table at once.
    let private parkOfThread (thread : int) : ParkedSyscall =
        if thread <= 2 then
            ParkedSyscall.EpollWait
                {
                    Epoll = blocked
                    MaxEvents = 1
                    Buffer = UserBuffer.Mapped
                    Deadline = None
                }
        else
            ParkedSyscall.Flock
                {
                    Requester = blocked
                    Mode = FlockMode.Exclusive
                }

    let private releaseLock (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match FileDescriptorRegistry.flock lockerFd FlockRequest.Release (Lone.fileDescriptors system) with
        | registry, None -> withRegistry registry system
        | _, Some error -> failwith $"expected the release to succeed, got %O{error}"

    [<RequireQualifiedAccess>]
    type private Op =
        | Park of thread : int
        | Unpark of thread : int
        | AdvanceClock of nanoseconds : int64
        | CreateEpoll
        | Register of thread : int

    let private opGen : Gen<Op> =
        let thread = Gen.choose (1, 4)

        Gen.frequency
            [
                4, thread |> Gen.map Op.Park
                2, thread |> Gen.map Op.Unpark
                1, Gen.choose (0, 1000) |> Gen.map (int64 >> Op.AdvanceClock)
                1, Gen.constant Op.CreateEpoll
                1, Gen.choose (5, 1000) |> Gen.map Op.Register
            ]

    let private apply (op : Op) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match op with
        | Op.Park thread ->
            // A re-park is a woken thread's.
            let system =
                match Lone.parkOf thread system with
                | Some _ -> ForgedPark.woken thread system
                | None -> system

            Lone.Parking.park thread (parkOfThread thread) system
        | Op.Unpark thread -> Lone.UnixParkState.unpark thread system
        | Op.AdvanceClock nanoseconds -> UnixSystem.advanceClock nanoseconds system
        | Op.CreateEpoll ->
            let _, registry =
                FileDescriptorRegistry.createEpoll
                    (SimulatedUnixPlatform.flavour (UnixSystem.platform system))
                    (Lone.fileDescriptors system)

            withRegistry registry system
        | Op.Register thread ->
            if Map.containsKey thread (Lone.threadMap system) then
                system
            else
                withThread thread system

    /// The parks a walk must make.
    [<RequireQualifiedAccess>]
    type private ParkLabel =
        /// A park by a thread already parked.
        | Repark

    [<Test>]
    let ``park order is strictly increasing, and survives unrelated changes`` () : unit =
        let property (cover : ParkLabel -> unit) (ops : Op list) : unit =
            ((system, None), ops)
            ||> List.fold (fun (before, lastMinted : ParkOrdinal option) op ->
                let after = apply op before

                let subject =
                    match op with
                    | Op.Park thread
                    | Op.Unpark thread -> Some thread
                    | Op.AdvanceClock _
                    | Op.CreateEpoll
                    | Op.Register _ -> None

                // Every other thread keeps its park, ordinal and all.
                for thread in Map.keys (Lone.threadMap before) do
                    if Some thread <> subject then
                        Lone.parkOf thread after |> shouldEqual (Lone.parkOf thread before)

                UnixSystem.checkInvariants after |> shouldEqual []

                match op with
                | Op.Park thread ->
                    if (Lone.parkOf thread before).IsSome then
                        cover ParkLabel.Repark

                    match Lone.parkOf thread after with
                    | None -> failwith "expected the park to be recorded"
                    | Some park ->
                        park.Syscall |> shouldEqual (parkOfThread thread)
                        park.State |> shouldEqual ParkState.Asleep

                        match lastMinted with
                        | Some last -> park.Ordinal |> shouldBeGreaterThan last
                        | None -> ()

                        after, Some park.Ordinal
                | Op.Unpark thread ->
                    Lone.parkOf thread after |> shouldEqual None
                    after, lastMinted
                | Op.AdvanceClock _
                | Op.CreateEpoll
                | Op.Register _ -> after, lastMinted
            )
            |> ignore

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 300) (Arb.fromGen (Gen.listOf opGen)) property

        // Counted over the fixed sample.
        coverage.Count ParkLabel.Repark |> shouldBeGreaterThan 50

    [<Test>]
    let ``a released lock wakes every waiter, in the order they parked`` () : unit =
        // Parked against the table's own key order, so that park order is told apart from it.
        let parked =
            system
            |> Lone.Parking.park 4 (parkOfThread 4)
            |> Lone.Parking.park 3 (parkOfThread 3)

        let fired =
            Set.singleton (WakePrimitive.FlockGrantable (blocked, FlockMode.Exclusive))

        Lone.wakes parked |> shouldEqual []

        Lone.wakes (releaseLock parked) |> shouldEqual [ 4, fired ; 3, fired ]

        // A re-park, a woken waiter's, moves the waiter behind every park already made.
        let reparked = parked |> ForgedPark.woken 4 |> Lone.Parking.park 4 (parkOfThread 4)

        Lone.wakes (releaseLock reparked) |> shouldEqual [ 3, fired ; 4, fired ]

    [<Test>]
    let ``a woken thread keeps its park, records what woke it, and is not woken again`` () : unit =
        let fired =
            Set.singleton (WakePrimitive.FlockGrantable (blocked, FlockMode.Exclusive))

        let parked =
            system
            |> Lone.Parking.park 3 (parkOfThread 3)
            |> Lone.Parking.park 4 (parkOfThread 4)

        let released = releaseLock parked
        let woken, after = Lone.wake released
        woken |> shouldEqual [ 3, fired ; 4, fired ]

        for thread in [ 3 ; 4 ] do
            let before = Lone.parkOf thread released |> Option.get
            before.State |> shouldEqual ParkState.Asleep

            Lone.parkOf thread after
            |> shouldEqual (
                Some
                    { before with
                        State = ParkState.Woken fired
                    }
            )

        // Nothing else moved.
        after
        |> ForgedThread.threadsAsIn (Lone.pid released) released
        |> shouldEqual released

        Lone.wake after |> fst |> shouldEqual []
        UnixWait.satisfied (Callers.thread 3 after) after |> shouldEqual (Some fired)

    [<Test>]
    let ``a sweep that wakes nobody answers a system equal to the one it was given, which answers itself after``
        ()
        : unit
        =
        let parked =
            system
            |> Lone.Parking.park 3 (parkOfThread 3)
            |> Lone.Parking.park 1 (parkOfThread 1)

        let woken, after = UnixWait.wake parked
        woken |> shouldEqual []
        after |> shouldEqual parked

        obj.ReferenceEquals (Kernel.machine after, Kernel.machine parked)
        |> shouldEqual true

        obj.ReferenceEquals (Kernel.scheduling after, Kernel.scheduling parked)
        |> shouldEqual true

        obj.ReferenceEquals (after.Processes, parked.Processes) |> shouldEqual true

        let woken, again = UnixWait.wake after
        woken |> shouldEqual []
        obj.ReferenceEquals (again, after) |> shouldEqual true

    /// Under Linux, a pipe's readers queue exclusively. Two readers sleep on an
    /// empty pipe, and the client names neither of them to the kernel: the
    /// kernel's own parks say who sleeps and who has been woken.
    [<Test>]
    let ``a woken waiter holds its exclusive queue until it finishes, whatever the client remembers`` () : unit =
        let system =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure 1
            |> Threads.ensure 2

        let readFd, writeFd, system =
            match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
            | Ok (Pipe2Answer.Created (readFd, writeFd), system) -> readFd, writeFd, system
            | other -> failwith $"pipe2 did not make a pipe: %A{other}"

        let reads (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixReadWrite.tryRead (Callers.thread thread system) readFd UserBuffer.Mapped 1UL system with
            | Ok (ReadOutcome.WouldBlock _, system) -> system
            | other -> failwith $"expected thread %d{thread}'s read to sleep, got %A{other}"

        let writesOne (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match
                WriteOutcomes.admitThenWrite
                    0
                    writeFd
                    UserBuffer.Mapped
                    (System.Collections.Immutable.ImmutableArray.Create 7uy)
                    system
            with
            | Ok (WriteStep.Returns (WriteAnswer.Completed 1L, system)) -> system
            | other -> failwith $"expected the write to complete, got %A{other}"

        let system = system |> reads 1 |> reads 2 |> writesOne

        // The byte wakes the reader that parked first.
        let system = Lone.waking [ 1 ] system

        // Woken and not yet finished, thread 1 stands for the byte: a second sweep, and one
        // after another byte, wake nobody else.
        Lone.wakes system |> shouldEqual []
        let system = writesOne system
        Lone.wakes system |> shouldEqual []

        // Thread 1 takes a byte, and then thread 2 wakes for the other.
        let system =
            match UnixReadWrite.tryFinishRead (Callers.thread 1 system) system with
            | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) when bytes.Length = 1 -> system
            | other -> failwith $"expected thread 1's read to take a byte, got %A{other}"

        Lone.waking [ 2 ] system |> ignore<UnixSystem<int, string>>

    [<Test>]
    let ``deadlines are those of the sleeping threads, not of the woken`` () : unit =
        let waitUntil (deadline : int64) : ParkedSyscall =
            ParkedSyscall.EpollWait
                {
                    Epoll = blocked
                    MaxEvents = 1
                    Buffer = UserBuffer.Mapped
                    Deadline = Some deadline
                }

        let parked =
            system
            |> Lone.Parking.park 1 (waitUntil 5L)
            |> Lone.Parking.park 2 (waitUntil 9L)

        Lone.deadlines parked |> shouldEqual [ 5L ; 9L ]

        let woken = UnixSystem.advanceClock 5L parked |> Lone.waking [ 1 ]

        Lone.deadlines woken |> shouldEqual [ 9L ]

    [<Test>]
    let ``a quiet epoll instance wakes none of its waiters, however many there are`` () : unit =
        // An exclusive wake is about a deliverable event, not about sharing an epoll instance.
        let parked =
            system
            |> Lone.Parking.park 1 (parkOfThread 1)
            |> Lone.Parking.park 2 (parkOfThread 2)

        Lone.wakes parked |> shouldEqual []

    [<Test>]
    let ``clearing a park lets another syscall park`` () : unit =
        // The refusal below is about an *unclosed* park, not about a thread's history: a
        // completion that clears its record leaves the thread free to block in anything.
        let cleared =
            let parked = system |> Lone.Parking.park 1 (parkOfThread 1)

            Lone.UnixParkState.unpark 1 parked

        Lone.Parking.park 1 (parkOfThread 3) cleared
        |> Lone.parkedIn 1
        |> shouldEqual (Some (parkOfThread 3))

    [<Test>]
    let ``a park of a different syscall over an existing one is refused`` () : unit =
        let parked = system |> Lone.Parking.park 1 (parkOfThread 1)

        let exn =
            Assert.Throws<exn> (fun () -> Lone.Parking.park 1 (parkOfThread 3) parked |> ignore)

        exn.Message |> shouldContainText "without clearing the first"

    [<Test>]
    let ``a park's state moves only by a wake and a woken thread's re-park`` () : unit =
        let parked = system |> Lone.Parking.park 1 (parkOfThread 1)
        let park = Lone.parkOf 1 parked |> Option.get
        park.State |> shouldEqual ParkState.Asleep

        let woken =
            { park with
                State = ParkState.Woken (Set.singleton WakePrimitive.SignalDeliverable)
            }

        // A re-park of a thread nothing has woken.
        let exn =
            Assert.Throws<exn> (fun () -> Lone.Parking.park 1 (parkOfThread 1) parked |> ignore)

        exn.Message |> shouldContainText "made only of a woken park"

        // A park that starts woken.
        let exn =
            Assert.Throws<exn> (fun () -> ForgedThread.parked (Callers.thread 2 system) woken system |> ignore)

        exn.Message |> shouldContainText "woken already"

        // A rewrite in place that changes the state.
        let exn =
            Assert.Throws<exn> (fun () -> ForgedThread.parked (Callers.thread 1 parked) woken parked |> ignore)

        exn.Message |> shouldContainText "changes its state"

        // A woken thread's re-park, asleep again; and a rewrite in place that keeps the
        // state.
        let wokenSystem = ForgedPark.woken 1 parked
        let reparked = Lone.Parking.park 1 (parkOfThread 1) wokenSystem

        (Lone.parkOf 1 reparked |> Option.get).State |> shouldEqual ParkState.Asleep

        let wokenPark = Lone.parkOf 1 wokenSystem |> Option.get

        ForgedThread.parked (Callers.thread 1 wokenSystem) wokenPark wokenSystem
        |> Lone.parkOf 1
        |> shouldEqual (Some wokenPark)

        // A park is woken once.
        let exn =
            Assert.Throws<exn> (fun () ->
                ForgedThread.woken
                    (Callers.thread 1 wokenSystem)
                    (Set.singleton WakePrimitive.SignalDeliverable)
                    wokenSystem
                |> ignore
            )

        exn.Message |> shouldContainText "woken already"

    /// Every park the library makes goes through `Parking.parkWaiting`, which
    /// a Debug build holds to the call's having nothing to wake it yet, a
    /// signal aside.
    [<Test>]
    let ``parkWaiting refuses a park whose own condition already holds, a signal aside`` () : unit =
#if DEBUG
        // The lock the call waits for is free.
        let exn =
            Assert.Throws<exn> (fun () -> Lone.Parking.parkWaiting 3 (parkOfThread 3) (releaseLock system) |> ignore)

        exn.Message |> shouldContainText "FlockGrantable"

        // Held, it parks.
        Lone.Parking.parkWaiting 3 (parkOfThread 3) system
        |> Lone.parkedIn 3
        |> shouldEqual (Some (parkOfThread 3))

        // A signal deliverable to the thread is the finishing call's to
        // answer, not a reason to refuse the park.
        let signalled =
            system
            |> Lone.mapProc (fun proc ->
                { proc with
                    Signals =
                        proc.Signals
                        |> SignalState.setDisposition
                            (Kernel.signalNumbering system)
                            Signal.SIGUSR1
                            (SignalDisposition.Catch (SignalCatch.ofHandler "h"))
                        |> SignalState.enqueue
                            (Kernel.signalNumbering system)
                            {
                                Signal = Signal.SIGUSR1
                                Target = ValueSome 1
                            }
                }
            )

        let parked = Lone.Parking.parkWaiting 1 (parkOfThread 1) signalled

        UnixWait.satisfied (Callers.thread 1 parked) parked
        |> shouldEqual (Some (Set.singleton WakePrimitive.SignalDeliverable))
#else
        Assert.Ignore "parkWaiting checks a park's condition only in a Debug build."
#endif

    /// The exclusive queue each park waits on, as `UnixWait.wakes` states it: an
    /// `epoll_wait` on its epoll instance, an `accept` on its listener, and under
    /// Linux a pipe `read` on the pipe's readers and a pipe `write` on its
    /// writers. A call a close has ended waits on none, and so does every other.
    let private statedQueues
        (linux : bool)
        (pipeOf : OpenFileDescriptionId -> PipeId option)
        (parked : ParkedSyscall)
        : ExclusiveWaitQueue list
        =
        match parked with
        | ParkedSyscall.EpollWait wait -> [ ExclusiveWaitQueue.Epoll wait.Epoll ]
        | ParkedSyscall.Accept accept ->
            SleepTarget.description accept.Listener
            |> Option.map ExclusiveWaitQueue.Listener
            |> Option.toList
        | ParkedSyscall.PipeRead read when linux ->
            SleepTarget.description read.Reader
            |> Option.bind pipeOf
            |> Option.map ExclusiveWaitQueue.PipeReaders
            |> Option.toList
        | ParkedSyscall.PipeWrite write when linux ->
            SleepTarget.description write.Writer
            |> Option.bind pipeOf
            |> Option.map ExclusiveWaitQueue.PipeWriters
            |> Option.toList
        | ParkedSyscall.PipeRead _
        | ParkedSyscall.PipeWrite _
        | ParkedSyscall.Flock _
        | ParkedSyscall.Kevent _
        | ParkedSyscall.Poll _
        | ParkedSyscall.KqueuePoll _
        | ParkedSyscall.ConnectionRead _
        | ParkedSyscall.ConnectionWrite _
        | ParkedSyscall.SigSuspend
        | ParkedSyscall.Sleep _
        | ParkedSyscall.SignalWait _
        | ParkedSyscall.FifoOpen _
        | ParkedSyscall.InotifyRead _
        | ParkedSyscall.Select _
        | ParkedSyscall.DatagramReceive _
        | ParkedSyscall.DatagramSend _
        | ParkedSyscall.Connect _
        | ParkedSyscall.Futex _ -> []

    /// A park of every kind, waiting on `description` wherever a park waits on
    /// one, with and without a deadline where it may have one, and each call a
    /// close can end both waiting and ended.
    let private parksOn (description : OpenFileDescriptionId) : ParkedSyscall list =
        [
            for deadline in [ None ; Some 5L ] do
                ParkedSyscall.EpollWait
                    {
                        Epoll = description
                        MaxEvents = 1
                        Buffer = UserBuffer.Mapped
                        Deadline = deadline
                    }

                ParkedSyscall.Kevent
                    {
                        Kqueue = description
                        Fd = 3
                        MaxEvents = 1
                        Buffer = UserBuffer.Mapped
                        Deadline = deadline
                    }

                ParkedSyscall.Poll
                    {
                        Entries = [ ParkedPollEntry.Watched (3, description, 1s) ; ParkedPollEntry.Ignored 4 ]
                        Deadline = deadline
                    }

                ParkedSyscall.KqueuePoll
                    {
                        Entries =
                            [
                                {
                                    Fd = 3
                                    Events = 1s
                                }
                            ]
                        Queue = PollQueueId 0L
                        Deadline = deadline
                    }

                ParkedSyscall.Select
                    {
                        Deadline = deadline
                    }

                ParkedSyscall.SignalWait
                    {
                        Awaited = SignalMask.empty
                        Deadline = deadline
                        Destination = None
                    }

                for taken in [ false ; true ] do
                    ParkedSyscall.Futex
                        {
                            FutexAddress = 0x1000UL
                            FutexTimeout =
                                match deadline with
                                | None -> FutexTimeout.Untimed
                                | Some deadline -> FutexTimeout.Until deadline
                            FutexBitset = UnixFutex.FutexBitsetMatchAny
                            TakenByWake = taken
                        }

                    match deadline with
                    | None -> ()
                    | Some deadline ->
                        ParkedSyscall.Futex
                            {
                                FutexAddress = 0x1000UL
                                FutexTimeout = FutexTimeout.At deadline
                                FutexBitset = 1u
                                TakenByWake = taken
                            }

            for taken in [ false ; true ] do
                ParkedSyscall.Futex
                    {
                        FutexAddress = 0x1000UL
                        FutexTimeout = FutexTimeout.Unbounded
                        FutexBitset = UnixFutex.FutexBitsetMatchAny
                        TakenByWake = taken
                    }

            for mode in [ FlockMode.Shared ; FlockMode.Exclusive ] do
                ParkedSyscall.Flock
                    {
                        Requester = description
                        Mode = mode
                    }

            for ended in [ false ; true ] do
                let target (object : 'Object) : SleepTarget<'Object> =
                    if ended then
                        SleepTarget.EndedByClose object
                    else
                        SleepTarget.Waiting (description, 3)

                ParkedSyscall.Accept
                    {
                        Listener = target (SocketId 0L)
                        Destination = UserBuffer.Mapped
                        DeclaredLength = 16u
                    }

                ParkedSyscall.PipeRead
                    {
                        Reader = target (PipeId 0L)
                        Buffer = UserBuffer.Mapped
                        Count = 1
                    }

                ParkedSyscall.PipeWrite
                    {
                        Writer = target (PipeId 0L)
                        Buffer = UserBuffer.Mapped
                        Count = 2
                        Written = 1
                        ReadsSeen = 0L
                    }

                ParkedSyscall.ConnectionRead
                    {
                        Socket = target (SocketId 0L)
                        Buffer = UserBuffer.Mapped
                        Count = 1
                        Call = TcpReceiveCall.Read
                    }

                ParkedSyscall.ConnectionWrite
                    {
                        Socket = target (SocketId 0L)
                        Buffer = UserBuffer.Mapped
                        Count = 2
                        Written = 1
                        Call = TcpSendCall.Write
                    }

            ParkedSyscall.SigSuspend

            ParkedSyscall.Sleep
                {
                    Deadline = 5L
                    Remainder = SleepRemainder.Unreported
                }

            ParkedSyscall.FifoOpen
                {
                    Opener = description
                    Descriptor = 3
                    PartnerOpens = 0L
                }

            ParkedSyscall.InotifyRead
                {
                    Instance = description
                    Buffer = UserBuffer.Mapped
                    Count = 16
                }

            ParkedSyscall.DatagramReceive
                {
                    Socket = description
                }

            ParkedSyscall.DatagramSend
                {
                    Socket = description
                }

            ParkedSyscall.Connect
                {
                    Socket = description
                }
        ]

    /// The exclusive queues a park waits on are those its own wake condition's
    /// primitives name, so a woken thread stands in the way on exactly the
    /// queues it was woken from. Exhaustive over every kind of park, waiting on
    /// each end of a pipe, on a socket and on a description the table does not
    /// hold, under both flavours.
    [<Test>]
    let ``a park waits on the exclusive queues its wake condition names, and on no other`` () : unit =
        let parkKind (parked : ParkedSyscall) : string =
            (FSharpValue.GetUnionFields (parked, typeof<ParkedSyscall>) |> fst).Name

        let queueKind (queue : ExclusiveWaitQueue) : string =
            match queue with
            | ExclusiveWaitQueue.Epoll _ -> "Epoll"
            | ExclusiveWaitQueue.Listener _ -> "Listener"
            | ExclusiveWaitQueue.PipeReaders _ -> "PipeReaders"
            | ExclusiveWaitQueue.PipeWriters _ -> "PipeWriters"

        let kinds =
            FSharpType.GetUnionCases typeof<ParkedSyscall>
            |> Array.map (fun case -> case.Name)
            |> Set.ofArray

        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            let system =
                UnixSystem.initial<int, string> platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let readFd, writeFd, system =
                match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
                | Ok (Pipe2Answer.Created (readFd, writeFd), system) -> readFd, writeFd, system
                | other -> failwith $"pipe2 did not make a pipe: %A{other}"

            let socketFd, system =
                match
                    UnixSocket.socket (Callers.leader system) SimulatedUnixPlatform.internetAddressFamily 1 0 system
                with
                | DescriptorAnswer.Returned fd, system -> fd, system
                | DescriptorAnswer.Failed error, _ -> failwith $"socket failed with %O{error}"

            let linux = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Linux

            let pipeOf (description : OpenFileDescriptionId) : PipeId option =
                match OpenFileTable.tryFind description (UnixSystem.openFiles system) with
                | Some {
                           Target = OpenFileTarget.Pipe (pipeId, _)
                       } -> Some pipeId
                | Some _
                | None -> None

            let descriptions =
                [
                    idOf readFd system
                    idOf writeFd system
                    idOf socketFd system
                    OpenFileDescriptionId 999_999L
                ]

            let parks = descriptions |> List.collect parksOn

            parks |> List.map parkKind |> Set.ofList |> shouldEqual kinds

            let mismatches =
                parks
                |> List.choose (fun parked ->
                    let stated = statedQueues linux pipeOf parked

                    let derived =
                        WakeCondition.ofPark parked
                        |> WakeCondition.primitives
                        |> List.choose (Parking.exclusiveQueueOf (Kernel.machine system))
                        |> List.distinct

                    if derived <> stated then
                        Some $"%O{platform}: %A{parked} waits on %A{derived}, where wakes states %A{stated}"
                    else
                        None
                )

            mismatches |> shouldEqual []

            // Every kind of queue the flavour has is reached, so that the
            // comparison is not vacuous for any of them.
            parks
            |> List.collect (statedQueues linux pipeOf)
            |> List.map queueKind
            |> Set.ofList
            |> shouldEqual (
                if linux then
                    Set.ofList [ "Epoll" ; "Listener" ; "PipeReaders" ; "PipeWriters" ]
                else
                    Set.ofList [ "Epoll" ; "Listener" ]
            )
