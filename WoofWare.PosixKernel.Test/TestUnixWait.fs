namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
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
            FileDescriptorRegistry.createEpoll (Lone.fileDescriptors system)

        let blockedFd, registry = FileDescriptorRegistry.createEpoll registry

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
        | Op.Park thread -> UnixWait.park thread (parkOfThread thread) system
        | Op.Unpark thread -> UnixParkState.unpark thread system
        | Op.AdvanceClock nanoseconds ->
            { system with
                Scheduling = UnixSchedulingState.advanceClock nanoseconds system.Scheduling
            }
        | Op.CreateEpoll ->
            let _, registry = FileDescriptorRegistry.createEpoll (Lone.fileDescriptors system)

            withRegistry registry system
        | Op.Register thread ->
            if Map.containsKey thread (Lone.threads system) then
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
                for thread in Map.keys (Lone.threads before) do
                    if Some thread <> subject then
                        UnixThreadTable.parkOf thread (Lone.threads after)
                        |> shouldEqual (UnixThreadTable.parkOf thread (Lone.threads before))

                UnixSystem.checkInvariants after |> shouldEqual []

                match op with
                | Op.Park thread ->
                    if (UnixThreadTable.parkOf thread (Lone.threads before)).IsSome then
                        cover ParkLabel.Repark

                    match UnixThreadTable.parkOf thread (Lone.threads after) with
                    | None -> failwith "expected the park to be recorded"
                    | Some park ->
                        park.Syscall |> shouldEqual (parkOfThread thread)

                        match lastMinted with
                        | Some last -> park.Ordinal |> shouldBeGreaterThan last
                        | None -> ()

                        after, Some park.Ordinal
                | Op.Unpark thread ->
                    UnixThreadTable.parkOf thread (Lone.threads after) |> shouldEqual None
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
            system |> UnixWait.park 4 (parkOfThread 4) |> UnixWait.park 3 (parkOfThread 3)

        let asleep = Set.ofList [ 3 ; 4 ]

        let fired =
            Set.singleton (WakePrimitive.FlockGrantable (blocked, FlockMode.Exclusive))

        UnixWait.wakes asleep parked |> shouldEqual []

        UnixWait.wakes asleep (releaseLock parked)
        |> shouldEqual [ 4, fired ; 3, fired ]

        // A re-park moves the waiter behind every park already made.
        let reparked = parked |> UnixWait.park 4 (parkOfThread 4)

        UnixWait.wakes asleep (releaseLock reparked)
        |> shouldEqual [ 3, fired ; 4, fired ]

    [<Test>]
    let ``only the threads the client holds asleep are woken`` () : unit =
        // A woken thread keeps its park until its call finishes, so the park alone would wake
        // it a second time.
        let released =
            system
            |> UnixWait.park 3 (parkOfThread 3)
            |> UnixWait.park 4 (parkOfThread 4)
            |> releaseLock

        UnixWait.wakes (Set.singleton 4) released
        |> shouldEqual (
            [
                4, Set.singleton (WakePrimitive.FlockGrantable (blocked, FlockMode.Exclusive))
            ]
        )

    [<Test>]
    let ``a thread held asleep with no park is a client bug`` () : unit =
        let exn =
            Assert.Throws<exn> (fun () -> UnixWait.wakes (Set.singleton 1) system |> ignore)

        exn.Message |> shouldContainText "records no park"

        let exn =
            Assert.Throws<exn> (fun () -> UnixWait.deadlines (Set.singleton 1) system |> ignore)

        exn.Message |> shouldContainText "records no park"

    [<Test>]
    let ``a quiet epoll instance wakes none of its waiters, however many there are`` () : unit =
        // An exclusive wake is about a deliverable event, not about sharing an epoll instance.
        let parked =
            system |> UnixWait.park 1 (parkOfThread 1) |> UnixWait.park 2 (parkOfThread 2)

        UnixWait.wakes (Set.ofList [ 1 ; 2 ]) parked |> shouldEqual []

    [<Test>]
    let ``clearing a park lets another syscall park`` () : unit =
        // The refusal below is about an *unclosed* park, not about a thread's history: a
        // completion that clears its record leaves the thread free to block in anything.
        let cleared =
            let parked = system |> UnixWait.park 1 (parkOfThread 1)

            UnixParkState.unpark 1 parked

        UnixWait.park 1 (parkOfThread 3) cleared
        |> fun system -> UnixThreadTable.parkedFor 1 (Lone.threads system)
        |> shouldEqual (Some (parkOfThread 3))

    [<Test>]
    let ``a park of a different syscall over an existing one is refused`` () : unit =
        let parked = system |> UnixWait.park 1 (parkOfThread 1)

        let exn =
            Assert.Throws<exn> (fun () -> UnixWait.park 1 (parkOfThread 3) parked |> ignore)

        exn.Message |> shouldContainText "without clearing the first"
