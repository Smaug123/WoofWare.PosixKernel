namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The kernel keeps the keys of the processes with a thread parked in a
/// syscall (`ProcessTable.withParks`), and each process the names of its
/// parked threads (`UnixThreadTable.parked`), which a sweep of the sleeping
/// threads reads rather than every process and thread. Over random walks of
/// real calls, among them threads parking, waking, finishing, starting and
/// exiting, and processes launching and ending, those name exactly the parked
/// threads a scan of every thread finds, and `UnixWait.wake` and
/// `UnixWait.deadlines` answer what the reference sweep (`ReferenceWake`)
/// answers given the threads that scan finds asleep.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSleeperIndex =

    /// A seed for a walk's own `System.Random`, from the whole range, and with
    /// no shrinker: a smaller seed is another walk, not a simpler one.
    let private walkSeed : Arbitrary<int> = Arb.fromGen (Gen.choose (0, Int32.MaxValue))

    /// What a walk's steps reached, each counted every time a step does.
    [<RequireQualifiedAccess>]
    type private Label =
        | Launched
        | Spawned
        | ThreadExited
        | ProcessEndedWithParks
        | Parked
        | ParkedWithDeadline
        | Woke
        | WokenUnfinished
        /// A woken thread's call finished, answering or sleeping again.
        | Finished
        | Dispatched

    /// Every thread a scan of every process's threads finds parked, asleep or
    /// woken, with whether it is asleep.
    let private scanned (system : UnixSystem<int, string>) : Map<ProcessId * int, bool> =
        UnixSystem.processIds system
        |> Seq.collect (fun pid ->
            UnixSystem.threads pid system
            |> Map.toSeq
            |> Seq.choose (fun (thread, state) ->
                match UnixThreadState.park state with
                | Some park ->
                    let asleep =
                        match park.State with
                        | ParkState.Asleep -> true
                        | ParkState.Woken _ -> false

                    Some ((pid, thread), asleep)
                | None -> None
            )
        )
        |> Map.ofSeq

    /// Every thread the kernel's record of parked threads names: each process
    /// it names as having one, and in each the threads it names.
    let private indexed (system : UnixSystem<int, string>) : Set<ProcessId * int> =
        ProcessTable.withParks system.Processes
        |> Seq.collect (fun key ->
            let pid = ProcessId.parseOrFail "TestSleeperIndex" key
            let slot = ProcessTable.find "TestSleeperIndex" key system.Processes
            UnixThreadTable.parked slot.Threads |> Seq.map (fun thread -> pid, thread)
        )
        |> Set.ofSeq

    /// The index and the sweeps agree with a scan of `system`.
    let private agrees (system : UnixSystem<int, string>) : unit =
        UnixSystem.checkInvariants system |> shouldEqual []

        let parked = scanned system
        indexed system |> shouldEqual (parked |> Map.keys |> Set.ofSeq)

        let asleep =
            parked
            |> Map.filter (fun _ asleep -> asleep)
            |> Map.keys
            |> Seq.map (fun (pid, thread) -> Caller.make pid thread)
            |> Set.ofSeq

        let answer, after = UnixWait.wake system
        answer |> shouldEqual (ReferenceWake.wakes asleep system)
        UnixWait.deadlines system |> shouldEqual (ReferenceWake.deadlines asleep system)
        UnixSystem.checkInvariants after |> shouldEqual []

    /// The thread `thread` of `pid` is running its own code: parked in no
    /// call and owing no return to user mode.
    let private running (pid : ProcessId) (thread : int) (system : UnixSystem<int, string>) : bool =
        let threads = Proc.threadTable pid system

        UnixThreadTable.contains thread threads
        && (UnixThreadTable.parkOf thread threads).IsNone
        && (UnixThreadTable.owedBy thread threads).IsNone

    /// `system` with every thread that owes a return to user mode returned,
    /// which ends its process if it takes a signal whose default is to.
    let rec private settle (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let owing =
            UnixSystem.processIds system
            |> Seq.collect (fun pid ->
                UnixSystem.threads pid system
                |> Map.keys
                |> Seq.filter (fun thread ->
                    let threads = Proc.threadTable pid system

                    (UnixThreadTable.parkOf thread threads).IsNone
                    && (UnixThreadTable.owedBy thread threads).IsSome
                )
                |> Seq.map (fun thread -> Caller.make pid thread)
            )
            |> Seq.tryHead

        match owing with
        | None -> system
        | Some caller ->
            match UnixSignal.onReturnToUser caller system with
            | ProcessFate.Continues (ReturnToUserOutcome.Resumes _, system) -> settle system
            | ProcessFate.ProcessEnded (_, system) -> settle system
            | ProcessFate.Continues (outcome, _) -> failwith $"%O{caller} returned to user mode with %A{outcome}"

    /// The system a finished call left, for the calls a walk parks threads in.
    let private finishedSystem (finished : FinishedCall<int, string>) : UnixSystem<int, string> =
        match finished with
        | FinishedCall.PipeRead (_, system)
        | FinishedCall.Poll (_, system)
        | FinishedCall.KqueuePoll (_, system)
        | FinishedCall.SigSuspend (_, system) -> system
        | other -> failwith $"a walk parks no thread in the call that answered %A{other}"

    /// The read end and write end of every pipe each process has made, as the
    /// walk recorded them; a descriptor closed since is still recorded, and a
    /// call on it fails with `EBADF`.
    type private Pipes = Map<ProcessId, (int * int) list>

    /// One random step of a walk from `system`, by a thread `random` chooses,
    /// or the system unchanged if the step it chose does not apply.
    let private step
        (platform : SimulatedUnixPlatform)
        (random : Random)
        (cover : Label -> unit)
        (pipes : Pipes)
        (system : UnixSystem<int, string>)
        : Pipes * UnixSystem<int, string>
        =
        let pids = UnixSystem.processIds system |> Set.toArray
        let pid = pids.[random.Next pids.Length]
        let threads = UnixSystem.threads pid system |> Map.keys |> Array.ofSeq

        // A running thread if the process has one, since most steps are calls,
        // which only a running thread makes.
        let thread =
            match threads |> Array.filter (fun thread -> running pid thread system) with
            | [||] -> threads.[random.Next threads.Length]
            | runners -> runners.[random.Next runners.Length]

        let caller = Caller.make pid thread
        let own = Map.tryFind pid pipes |> Option.defaultValue []

        let pick () : (int * int) option =
            if own.IsEmpty then
                None
            else
                Some own.[random.Next own.Length]

        match random.Next 18 with
        | 0 when pids.Length < 4 ->
            let pid, system = UnixSystem.launch (Machines.launchOn platform) system
            cover Label.Launched
            Map.add pid [] pipes, system
        | 1 when running pid thread system && threads.Length < 5 ->
            let child = (Array.max threads) + 1

            match UnixThreadLifecycle.spawn caller child (CpuId 0) system with
            | SpawnAnswer.Spawned _, system ->
                cover Label.Spawned
                pipes, system
            | answer, _ -> failwith $"spawning %d{child}: %A{answer}"
        | 2 when running pid thread system && thread <> Proc.leader pid system ->
            match UnixThreadLifecycle.tryExitThread caller 0 system with
            | Ok (ProcessFate.Continues ((), system)) ->
                cover Label.ThreadExited
                pipes, system
            | Ok (ProcessFate.ProcessEnded (_, system)) -> Map.remove pid pipes, system
            | Error _ -> pipes, system
        | 3 when running pid thread system && random.Next 3 = 0 ->
            if not (UnixThreadTable.parked (Proc.threadTable pid system)).IsEmpty then
                cover Label.ProcessEndedWithParks

            let _, system = UnixThreadLifecycle.exitGroup caller 0 system
            Map.remove pid pipes, system
        | 4 when running pid thread system && own.Length < 4 ->
            match UnixPipe.pipe2 caller 0 UserBuffer.Mapped system with
            | Pipe2Answer.Created (readFd, writeFd), system -> Map.add pid (own @ [ readFd, writeFd ]) pipes, system
            | answer, _ -> failwith $"pipe2: %A{answer}"
        | 5 when running pid thread system ->
            match pick () with
            | None -> pipes, system
            | Some (readFd, _) ->
                match UnixReadWrite.read caller readFd UserBuffer.Mapped 1UL system with
                | ReadOutcome.WouldBlock _, system ->
                    cover Label.Parked
                    pipes, system
                | _, system -> pipes, system
        | 6 when running pid thread system ->
            match pick () with
            | None -> pipes, system
            | Some (readFd, _) ->
                let entry : PollEntry =
                    {
                        Fd = readFd
                        // `POLLIN`.
                        Events = 1s
                    }

                match UnixPoll.poll caller [ entry ] (1 + random.Next 5) system with
                | PollOutcome.WouldBlock _, system ->
                    cover Label.ParkedWithDeadline
                    pipes, system
                | _, system -> pipes, system
        | 7 when running pid thread system && random.Next 2 = 0 ->
            match UnixSignal.pause caller system with
            | SigsuspendOutcome.WouldBlock _, system ->
                cover Label.Parked
                pipes, system
            | outcome, _ -> failwith $"pause: %A{outcome}"
        | 8
        | 16 when running pid thread system ->
            match pick () with
            | None -> pipes, system
            | Some (_, writeFd) ->
                match UnixReadWrite.write caller writeFd UserBuffer.Mapped 1UL system with
                | CallProgress.Answered (ProcessFate.Continues (_, system)) -> pipes, system
                | CallProgress.Answered (ProcessFate.ProcessEnded (_, system)) -> Map.remove pid pipes, system
                | CallProgress.NeedsCopyIn paused ->
                    match UnixReadWrite.writeWithBytes (ImmutableArray.Create<byte> 1uy) paused with
                    | ProcessFate.Continues (_, system), None -> pipes, system
                    | ProcessFate.ProcessEnded (_, system), None -> Map.remove pid pipes, system
                    | _, Some delivery -> failwith $"a write into a pipe the process made delivered %A{delivery}"
        | 9 when running pid thread system ->
            match pick () with
            | None -> pipes, system
            | Some (readFd, writeFd) ->
                let fd = if random.Next 2 = 0 then readFd else writeFd
                // A close this kernel refuses, such as of a descriptor a
                // sleeping `poll` watches, changes nothing.
                match UnixDescriptor.tryClose caller fd system with
                | Ok (_, system) -> pipes, system
                | Error _ -> pipes, system
        | 10 when running pid thread system && random.Next 4 = 0 ->
            // `SIGTERM`, whose default ends the process, sent to itself.
            match UnixSignal.kill caller (ProcessId.toInt32 pid) 15 system with
            | ProcessFate.Continues (KillAnswer.Completed _, system) -> pipes, system
            | ProcessFate.ProcessEnded (_, system) -> Map.remove pid pipes, system
            | ProcessFate.Continues (KillAnswer.Failed error, _) -> failwith $"kill: %O{error}"
        | 11
        | 12 ->
            let woken, system = UnixWait.wake system

            if not woken.IsEmpty then
                cover Label.Woke

            pipes, system
        | 13
        | 14 ->
            let woken =
                scanned system
                |> Map.filter (fun _ asleep -> not asleep)
                |> Map.keys
                |> Array.ofSeq

            if woken.Length = 0 then
                pipes, system
            else
                let pid, thread = woken.[random.Next woken.Length]

                let caller = Caller.make pid thread

                // A finish this kernel refuses, such as of a Darwin poll both
                // ready and past its deadline, changes nothing.
                match UnixWait.tryFinish caller (ParkedCall.ofThread caller system) system with
                | Error _ -> pipes, system
                | Ok finished ->
                    cover Label.Finished
                    pipes, finishedSystem finished
        | 15 -> pipes, UnixSystem.advanceClock (int64 (random.Next 3_000_000)) system
        | 17 ->
            cover Label.Dispatched
            pipes, UnixScheduling.dispatch caller (CpuId (random.Next 2)) system
        | _ -> pipes, system

    let private twoProcessors (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial<int, string> platform
        |> UnixBootImage.tryWithProcessorCount 2
        |> Configured.expectOk ProcessorCountRefusal.describe
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A walk of `length` steps from a machine of `platform`, checking the
    /// index and the sweeps at each; a step from a machine with no process left
    /// launches one.
    let private walk (cover : Label -> unit) (platform : SimulatedUnixPlatform) (seed : int) (length : int) : unit =
        let random = Random seed

        let rec go (remaining : int) (pipes : Pipes) (system : UnixSystem<int, string>) : unit =
            agrees system

            if remaining > 0 && (UnixSystem.processIds system).IsEmpty then
                let pid, system = UnixSystem.launch (Machines.launchOn platform) system
                go (remaining - 1) (Map.add pid [] pipes) system
            else
                let woken = scanned system |> Map.exists (fun _ asleep -> not asleep)

                if woken then
                    cover Label.WokenUnfinished

                if remaining > 0 then
                    let pipes, system = step platform random cover pipes system
                    go (remaining - 1) pipes (settle system)

        let booted = twoProcessors platform
        go length (Map.ofList [ Lone.pid booted, [] ]) booted

    [<Test>]
    let ``the record of parked threads names exactly the parked threads, and the sweep answers as a full scan does``
        ()
        : unit
        =
        let property (cover : Label -> unit) (seed : int) : unit =
            for platform in Machines.platforms do
                walk cover platform seed 150

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 100) walkSeed property

        // A third of what the fixed sample reached when this was written.
        coverage.Count Label.Launched |> shouldBeGreaterThan 340
        coverage.Count Label.Spawned |> shouldBeGreaterThan 280
        coverage.Count Label.ThreadExited |> shouldBeGreaterThan 55
        coverage.Count Label.ProcessEndedWithParks |> shouldBeGreaterThan 10
        coverage.Count Label.Parked |> shouldBeGreaterThan 200
        coverage.Count Label.ParkedWithDeadline |> shouldBeGreaterThan 50
        coverage.Count Label.Woke |> shouldBeGreaterThan 40
        coverage.Count Label.WokenUnfinished |> shouldBeGreaterThan 300
        coverage.Count Label.Finished |> shouldBeGreaterThan 38
        coverage.Count Label.Dispatched |> shouldBeGreaterThan 540

    /// The keys of `table`'s processes with a parked thread, and the parked
    /// threads of each, found by asking every thread.
    let private scannedTable (table : ProcessTable<int, string>) : Map<int32, Set<int>> =
        ProcessTable.slots table
        |> Map.map (fun _ slot ->
            UnixThreadTable.byName slot.Threads
            |> Map.filter (fun _ state -> state.Parked.IsSome)
            |> Map.keys
            |> Set.ofSeq
        )
        |> Map.filter (fun _ parked -> not parked.IsEmpty)

    /// The same, as the tables' own records name them.
    let private indexedTable (table : ProcessTable<int, string>) : Map<int32, Set<int>> =
        ProcessTable.withParks table
        |> Seq.map (fun key -> key, UnixThreadTable.parked (ProcessTable.find "TestSleeperIndex" key table).Threads)
        |> Map.ofSeq

    [<Test>]
    let ``the tables' records of parked threads survive random walks of the tables' own changes`` () : unit =
        let booted = twoProcessors SimulatedUnixPlatform.linuxX64
        let proc = Proc.state (Lone.pid booted) booted
        let state = UnixThreadTable.get 0 (Lone.threadTable booted)

        let property (seed : int) : unit =
            let random = Random seed
            let mutable table : ProcessTable<int, string> = ProcessTable.empty
            let mutable ordinal = 0L

            // A park with a fresh ordinal, as a park or a re-park makes.
            let park () : ThreadPark =
                ordinal <- ordinal + 1L

                {
                    Syscall = ParkedSyscall.SigSuspend
                    Ordinal = ParkOrdinal ordinal
                    State = ParkState.Asleep
                }

            for _ in 1..200 do
                let key = random.Next 5
                let name = random.Next 4

                let threads =
                    match ProcessTable.tryFind key table with
                    | Some slot -> slot.Threads
                    | None -> UnixThreadTable.empty

                let threads =
                    match UnixThreadTable.tryFind name threads, random.Next 6 with
                    | None, _ -> UnixThreadTable.add name state.Cpu state.OsThreadId threads
                    | Some {
                               Parked = None
                               Owes = None
                           },
                      0 -> UnixThreadTable.withPark name (park ()) threads
                    | Some {
                               Parked = None
                           },
                      1 -> UnixThreadTable.remove name threads
                    | Some {
                               Parked = Some {
                                                 State = ParkState.Asleep
                                             }
                           },
                      2 -> UnixThreadTable.markWoken name (Set.singleton (WakePrimitive.DeadlinePassed 0L)) threads
                    | Some {
                               Parked = Some {
                                                 State = ParkState.Woken _
                                             }
                           },
                      2 -> UnixThreadTable.withPark name (park ()) threads
                    | Some {
                               Parked = Some _
                           },
                      3 -> UnixThreadTable.unpark name threads
                    | Some {
                               Parked = None
                               Owes = None
                           },
                      4 -> UnixThreadTable.owe name OwedReturn.SignalDue threads
                    | Some _, 4 -> UnixThreadTable.settle name threads
                    | Some _, _ -> UnixThreadTable.withCpu name (CpuId (random.Next 2)) threads

                UnixThreadTable.parkedNamesFresh threads |> shouldEqual true

                table <-
                    match random.Next 8 with
                    | 0 -> ProcessTable.remove key table
                    | _ ->
                        ProcessTable.add
                            key
                            {
                                Process = proc
                                Threads = threads
                                Leader = 0
                            }
                            table

                indexedTable table |> shouldEqual (scannedTable table)
                ProcessTable.parksFresh table |> shouldEqual true

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 200, Prop.forAll walkSeed property)
