namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// One step of the scheduling property, on a machine of several processes.
///
/// Every index is reduced modulo the number of candidates the step can be
/// taken by, and a step with none is skipped. Each process's leader, thread 0,
/// never parks, so it can always write the byte that wakes a reader, and end
/// the process.
[<RequireQualifiedAccess>]
type SchedulingOp =
    /// The process's leader creates a thread on the processor `cpu`, modulo the
    /// machine's count.
    | Spawn of proc : int * cpu : int
    /// The client dispatches a live thread, parked or not: to `cpu` modulo the
    /// count, or with `beyond`, to a processor the machine does not have.
    | Dispatch of thread : int * cpu : int * beyond : int option
    /// The client dispatches a thread it has woken and not yet finished, to
    /// `cpu` modulo the count: how a woken thread gets back onto a processor.
    | DispatchWoken of thread : int * cpu : int
    /// A thread other than a leader reads a byte from its process's pipe, which
    /// parks it if the pipe is empty.
    | Park of proc : int
    /// The process's leader writes a byte into its pipe, and the client asks
    /// which of the readers it holds asleep that wakes.
    | Wake of proc : int
    /// The client finishes a woken read, which returns or parks again.
    | Finish of thread : int
    /// A thread that may exit does: a leader only when it is its process's last.
    | ExitThread of thread : int
    /// The process's leader calls `exit_group`.
    | EndProcess of proc : int
    /// A process is launched, its leader on `cpu`, modulo the count.
    | Launch of cpu : int

/// `UnixScheduling` against a reference that derives what runs where from the
/// history of events alone, rather than from a record it updates: a thread runs
/// on a processor exactly when the most recent event naming the thread or that
/// processor is the thread's dispatch there; a thread's processor is that of its
/// latest dispatch, or else the one it was created on. The events are creation,
/// dispatch, park and exit.
///
/// Run on a machine of 1 to 4 processors and 1 to 3 processes, with at most 6
/// threads, on Linux and Darwin.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixScheduling =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 300

    let private maxThreads : int = 6
    let private maxProcesses : int = 3

    [<RequireQualifiedAccess>]
    type private Event =
        | Created of serial : int * cpu : CpuId
        | Dispatched of serial : int * cpu : CpuId
        | Parked of serial : int
        | Exited of serial : int

    type private Live =
        {
            Pid : ProcessId
            Name : int
            /// Unique across the run, so that the reference never confuses two
            /// threads however names and IDs are reused.
            Serial : int
            /// Parked in its read, and held asleep by the client.
            Asleep : bool
            /// Parked in its read, and woken, but not yet finished.
            Woken : bool
        }

    type private World =
        {
            Platform : SimulatedUnixPlatform
            Count : int
            Machine : UnixSystem<int, string>
            /// In creation order.
            Live : Live list
            NextName : Map<ProcessId, int>
            NextSerial : int
            /// Newest first.
            Events : Event list
        }

    // --- the reference ---

    /// The processor `serial` runs on: its latest event is its dispatch to a
    /// processor no later event dispatches another thread to.
    let private runningOracle (serial : int) (events : Event list) : CpuId option =
        let rec go (dispatchedSince : Set<CpuId>) (events : Event list) : CpuId option =
            match events with
            | [] -> None
            | Event.Dispatched (s, cpu) :: _ when s = serial ->
                if Set.contains cpu dispatchedSince then None else Some cpu
            | Event.Dispatched (_, cpu) :: rest -> go (Set.add cpu dispatchedSince) rest
            | Event.Created (s, _) :: _
            | Event.Parked s :: _
            | Event.Exited s :: _ when s = serial -> None
            | _ :: rest -> go dispatchedSince rest

        go Set.empty events

    let private cpuOracle (serial : int) (events : Event list) : CpuId =
        events
        |> List.pick (fun event ->
            match event with
            | Event.Dispatched (s, cpu)
            | Event.Created (s, cpu) when s = serial -> Some cpu
            | _ -> None
        )

    /// Whether `serial`'s latest event is a dispatch: so that, if it is not
    /// running, another thread was dispatched to its processor since.
    let private lastDispatched (serial : int) (events : Event list) : bool =
        events
        |> List.tryPick (fun event ->
            match event with
            | Event.Dispatched (s, _) when s = serial -> Some true
            | Event.Created (s, _)
            | Event.Parked s
            | Event.Exited s when s = serial -> Some false
            | _ -> None
        )
        |> Option.defaultValue false

    // --- the run ---

    /// A path the generated runs must reach.
    [<RequireQualifiedAccess>]
    type private Reached =
        /// A Linux `getcpu`, refused, by a thread not parked whose processor a
        /// later dispatch has taken.
        | DisplacedGetCpu
        /// A dispatch of a thread woken from a park.
        | WokenDispatched
        /// A dispatch onto a processor a thread of another process is running on.
        | CrossProcessDisplacement
        /// A dispatch onto a processor the machine does not have, which throws.
        | BeyondDispatch

    let private throws (f : unit -> 'a) : bool =
        try
            f () |> ignore<'a>
            false
        with _ ->
            true

    let private viewOf (pid : ProcessId) (world : World) : UnixSystem<int, string> = Machines.viewOf pid world.Machine

    let private withPipe (pid : ProcessId) (machine : UnixSystem<int, string>) : UnixSystem<int, string> =
        machine
        |> Machines.doIn
            pid
            (fun view ->
                match UnixPipe.tryPipe2 (Caller.make pid (Proc.leader pid view)) 0 UserBuffer.Mapped view with
                | Ok (Pipe2Answer.Created (3, 4), view) -> view
                | other -> failwith $"pipe2: %A{other}"
            )

    let private launch (cpu : int) (world : World) : World =
        if Map.count world.NextName >= maxProcesses || List.length world.Live >= maxThreads then
            world
        else

        let cpu = CpuId (cpu % world.Count)

        match
            Machines.tryLaunch (Launched.launch world.Platform UnixSystem.pipedStandardStreams 0 cpu) world.Machine
        with
        | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"
        | Ok (pid, machine) ->
            { world with
                Machine = withPipe pid machine
                Live =
                    world.Live
                    @ [
                        {
                            Pid = pid
                            Name = 0
                            Serial = world.NextSerial
                            Asleep = false
                            Woken = false
                        }
                    ]
                NextName = Map.add pid 1 world.NextName
                NextSerial = world.NextSerial + 1
                Events = Event.Created (world.NextSerial, cpu) :: world.Events
            }

    let private initialWorld (platform : SimulatedUnixPlatform) (count : int) (leaderCpu : int) : World =
        let leaderCpu = CpuId (leaderCpu % count)

        let system =
            UnixSystem.initial platform
            |> UnixBootImage.tryWithProcessorCount count
            |> Configured.expectOk ProcessorCountRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 leaderCpu

        let pid = Lone.pid system

        {
            Platform = platform
            Count = count
            Machine = Machines.ofSystem system |> withPipe pid
            Live =
                [
                    {
                        Pid = pid
                        Name = 0
                        Serial = 0
                        Asleep = false
                        Woken = false
                    }
                ]
            NextName = Map.ofList [ pid, 1 ]
            NextSerial = 1
            Events = [ Event.Created (0, leaderCpu) ]
        }

    let private pick (index : int) (candidates : 'a list) : 'a option =
        match candidates with
        | [] -> None
        | _ -> Some (List.item (index % List.length candidates) candidates)

    let private processes (world : World) : ProcessId list =
        world.NextName |> Map.keys |> List.ofSeq

    let private replace (thread : Live) (world : World) : World =
        { world with
            Live =
                world.Live
                |> List.map (fun live -> if live.Serial = thread.Serial then thread else live)
        }

    /// The process `pid` ended: every thread of it exits.
    let private ended (pid : ProcessId) (world : World) : World =
        let dying = world.Live |> List.filter (fun live -> live.Pid = pid)

        { world with
            Live = world.Live |> List.filter (fun live -> live.Pid <> pid)
            NextName = Map.remove pid world.NextName
            Events =
                (dying |> List.rev |> List.map (fun live -> Event.Exited live.Serial))
                @ world.Events
        }

    let private beyondCpus (count : int) : int list =
        [ -1 ; count ; count + 1 ; Int32.MinValue ; Int32.MaxValue ]

    let rec private apply (cover : Reached -> unit) (op : SchedulingOp) (world : World) : World =
        match op with
        | SchedulingOp.Launch cpu -> launch cpu world
        | SchedulingOp.Spawn (proc, cpu) ->
            match pick proc (processes world) with
            | Some pid when List.length world.Live < maxThreads ->
                let name = world.NextName.[pid]
                let cpu = CpuId (cpu % world.Count)

                let machine =
                    world.Machine
                    |> Machines.doIn
                        pid
                        (fun view ->
                            match UnixThreadLifecycle.trySpawn (Caller.make pid 0) name cpu view with
                            | Ok (SpawnAnswer.Spawned _, view) -> view
                            | other -> failwith $"spawn: %A{other}"
                        )

                { world with
                    Machine = machine
                    Live =
                        world.Live
                        @ [
                            {
                                Pid = pid
                                Name = name
                                Serial = world.NextSerial
                                Asleep = false
                                Woken = false
                            }
                        ]
                    NextName = Map.add pid (name + 1) world.NextName
                    NextSerial = world.NextSerial + 1
                    Events = Event.Created (world.NextSerial, cpu) :: world.Events
                }
            | Some _
            | None -> world
        | SchedulingOp.Dispatch (index, cpu, beyond) ->
            match pick index world.Live with
            | None -> world
            | Some thread ->
                match beyond with
                | Some k ->
                    let cpus = beyondCpus world.Count
                    let cpu = CpuId (List.item (k % List.length cpus) cpus)
                    cover Reached.BeyondDispatch

                    throws (fun () ->
                        UnixScheduling.dispatch (Caller.make thread.Pid thread.Name) cpu (viewOf thread.Pid world)
                    )
                    |> shouldEqual true

                    world
                | None ->
                    let cpu = CpuId (cpu % world.Count)

                    if thread.Woken then
                        cover Reached.WokenDispatched

                    let displacesAnotherProcess =
                        world.Live
                        |> List.exists (fun other ->
                            other.Pid <> thread.Pid && runningOracle other.Serial world.Events = Some cpu
                        )

                    if displacesAnotherProcess then
                        cover Reached.CrossProcessDisplacement

                    { world with
                        Machine =
                            world.Machine
                            |> Machines.doIn
                                thread.Pid
                                (UnixScheduling.dispatch (Caller.make thread.Pid thread.Name) cpu)
                        Events = Event.Dispatched (thread.Serial, cpu) :: world.Events
                    }
        | SchedulingOp.DispatchWoken (index, cpu) ->
            match pick index (world.Live |> List.filter (fun live -> live.Woken)) with
            | None -> world
            | Some thread ->
                apply cover (SchedulingOp.Dispatch (List.findIndex ((=) thread) world.Live, cpu, None)) world
        | SchedulingOp.Park proc ->
            let candidates =
                world.Live
                |> List.filter (fun live -> live.Name <> 0 && not live.Asleep && not live.Woken)

            match pick proc candidates with
            | None -> world
            | Some thread ->
                let outcome, machine =
                    world.Machine
                    |> Machines.inProcess
                        thread.Pid
                        (fun view ->
                            match
                                UnixReadWrite.tryRead (Caller.make thread.Pid thread.Name) 3 UserBuffer.Mapped 1UL view
                            with
                            | Ok (ReadOutcome.WouldBlock _, view) -> true, view
                            | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), view) when bytes.Length = 1 ->
                                false, view
                            | other -> failwith $"read: %A{other}"
                        )

                let world =
                    { world with
                        Machine = machine
                    }

                if outcome then
                    { replace
                          { thread with
                              Asleep = true
                          }
                          world with
                        Events = Event.Parked thread.Serial :: world.Events
                    }
                else
                    world
        | SchedulingOp.Wake proc ->
            match pick proc (processes world) with
            | None -> world
            | Some pid ->
                let machine =
                    world.Machine
                    |> Machines.doIn
                        pid
                        (fun view ->
                            match
                                WriteOutcomes.admitThenWriteAs
                                    (Caller.make pid 0)
                                    4
                                    UserBuffer.Mapped
                                    (ImmutableArray.Create 1uy)
                                    view
                            with
                            | Ok (WriteStep.Returns (WriteAnswer.Completed 1L, view)) -> view
                            | other -> failwith $"write: %A{other}"
                        )

                let asleep =
                    world.Live
                    |> List.filter (fun live -> live.Asleep)
                    |> List.groupBy (fun live -> live.Pid)
                    |> List.map (fun (pid, threads) -> pid, threads |> List.map (fun live -> live.Name) |> Set.ofList)
                    |> Map.ofList

                let woken = Machines.wakes asleep machine |> List.map fst |> Set.ofList

                { world with
                    Machine = machine
                    Live =
                        world.Live
                        |> List.map (fun live ->
                            if Set.contains (live.Pid, live.Name) woken then
                                { live with
                                    Asleep = false
                                    Woken = true
                                }
                            else
                                live
                        )
                }
        | SchedulingOp.Finish index ->
            match pick index (world.Live |> List.filter (fun live -> live.Woken)) with
            | None -> world
            | Some thread ->
                let parksAgain, machine =
                    world.Machine
                    |> Machines.inProcess
                        thread.Pid
                        (fun view ->
                            match UnixReadWrite.tryFinishRead (Caller.make thread.Pid thread.Name) view with
                            | Ok (ReadOutcome.WouldBlock _, view) -> true, view
                            | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), view) when bytes.Length = 1 ->
                                false, view
                            | other -> failwith $"finishRead: %A{other}"
                        )

                let world =
                    replace
                        { thread with
                            Asleep = parksAgain
                            Woken = false
                        }
                        { world with
                            Machine = machine
                        }

                if parksAgain then
                    { world with
                        Events = Event.Parked thread.Serial :: world.Events
                    }
                else
                    world
        | SchedulingOp.ExitThread index ->
            let darwin =
                SimulatedUnixPlatform.flavour world.Platform = SimulatedUnixFlavour.Darwin

            let candidates =
                world.Live
                |> List.filter (fun live ->
                    let alone =
                        world.Live |> List.forall (fun other -> other.Pid <> live.Pid || other = live)

                    not live.Asleep
                    && not live.Woken
                    && (live.Name <> 0 || alone)
                    && not (darwin && alone)
                )

            match pick index candidates with
            | None -> world
            | Some thread ->
                match
                    UnixThreadLifecycle.tryExitThread (Caller.make thread.Pid thread.Name) 0 (viewOf thread.Pid world)
                with
                | Ok (ProcessFate.Continues ((), view)) ->
                    { world with
                        Machine = Machines.unfocus view world.Machine
                        Live = world.Live |> List.filter (fun live -> live.Serial <> thread.Serial)
                        Events = Event.Exited thread.Serial :: world.Events
                    }
                | Ok (ProcessFate.ProcessEnded (_, machine)) ->
                    { world with
                        Machine = machine
                    }
                    |> ended thread.Pid
                | Error refusal -> failwith $"exitThread: %s{ThreadExitRefusal.describe refusal}"
        | SchedulingOp.EndProcess proc ->
            match pick proc (processes world) with
            | None -> world
            | Some pid ->
                let _, machine =
                    UnixThreadLifecycle.exitGroup (Caller.make pid 0) 0 (viewOf pid world)

                { world with
                    Machine = machine
                }
                |> ended pid

    /// Everything the reference says, asked of the library.
    let private check (cover : Reached -> unit) (world : World) : unit =
        Machines.assertClean world.Machine

        let linux =
            SimulatedUnixPlatform.flavour world.Platform = SimulatedUnixFlavour.Linux

        for thread in world.Live do
            let view = viewOf thread.Pid world
            let running = runningOracle thread.Serial world.Events

            let context () : string =
                $"%A{thread}, after %A{List.rev world.Events}"

            let caller = Caller.make thread.Pid thread.Name

            UnixScheduling.runningOn caller view
            |> fun answered ->
                if answered <> running then
                    failwith $"runningOn %A{answered}: %s{context ()}"

            (UnixThreadTable.get thread.Name (Proc.threads thread.Pid view)).Cpu
            |> shouldEqual (cpuOracle thread.Serial world.Events)

            let parked = thread.Asleep || thread.Woken

            match running with
            | Some cpu ->
                if not (obj.ReferenceEquals (UnixScheduling.dispatch caller cpu view, view)) then
                    failwith $"re-dispatching to %O{cpu} changed the system: %s{context ()}"
            | None -> ()

            if linux then
                match running with
                | Some cpu when not parked ->
                    UnixScheduling.tryGetcpu caller view
                    |> shouldEqual (
                        Ok
                            {
                                Cpu = cpu
                                Node = NumaNode 0
                            }
                    )
                | Some _
                | None ->
                    if not parked && lastDispatched thread.Serial world.Events then
                        cover Reached.DisplacedGetCpu

                    if not (throws (fun () -> UnixScheduling.tryGetcpu caller view)) then
                        failwith $"getcpu answered for a thread not running, or parked: %s{context ()}"
            elif parked then
                if not (throws (fun () -> UnixScheduling.tryGetcpu caller view)) then
                    failwith $"getcpu answered for a parked thread: %s{context ()}"
            else
                UnixScheduling.tryGetcpu caller view
                |> shouldEqual (Error (GetCpuRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin))

    let private op : Gen<SchedulingOp> =
        let index = Gen.choose (0, 1000)

        Gen.frequency
            [
                10, Gen.map2 (fun p c -> SchedulingOp.Spawn (p, c)) index index
                36, Gen.map3 (fun t c b -> SchedulingOp.Dispatch (t, c, None)) index index index
                4, Gen.map3 (fun t c b -> SchedulingOp.Dispatch (t, c, Some b)) index index index
                14, Gen.map2 (fun t c -> SchedulingOp.DispatchWoken (t, c)) index index
                12, Gen.map SchedulingOp.Park index
                10, Gen.map SchedulingOp.Wake index
                8, Gen.map SchedulingOp.Finish index
                6, Gen.map SchedulingOp.ExitThread index
                3, Gen.map SchedulingOp.EndProcess index
                7, Gen.map SchedulingOp.Launch index
            ]

    let private run : Gen<SimulatedUnixPlatform * int * int * int * SchedulingOp list> =
        gen {
            let! platform =
                Gen.frequency
                    [
                        3, Gen.constant SimulatedUnixPlatform.linuxX64
                        1, Gen.constant SimulatedUnixPlatform.macOsArm64
                    ]

            let! count = Gen.choose (1, 4)
            let! leaderCpu = Gen.choose (0, 1000)
            let! processes = Gen.choose (1, maxProcesses)
            let! length = Gen.choose (1, 60)
            let! ops = Gen.listOfLength length op
            return platform, count, leaderCpu, processes, ops
        }

    [<Test>]
    let ``what runs where agrees with the history of dispatches, parks and exits`` () : unit =
        let property
            (cover : Reached -> unit)
            (platform : SimulatedUnixPlatform, count : int, leaderCpu : int, processes : int, ops)
            : unit
            =
            let world =
                (initialWorld platform count leaderCpu, [ 2..processes ])
                ||> List.fold (fun world p -> launch (leaderCpu + p) world)

            check cover world

            (world, ops)
            ||> List.fold (fun world op ->
                let world = apply cover op world
                check cover world
                world
            )
            |> ignore<World>

        let reached = CoverageSample.check propertyConfig (Arb.fromGen run) property

        // Thirteen fresh runs of 300 reached at least 3278 displaced getcpus,
        // 91 woken dispatches, 544 displacements across processes and 256
        // dispatches beyond the machine. Each floor is a third of that or less,
        // so a generator change that starves one fails here rather than
        // passing on the others. The floors are counted over the fixed sample
        // `CoverageSample.check` draws, so a run cannot miss one by chance.
        let floors =
            [
                "a displaced thread's getcpu", reached.Count Reached.DisplacedGetCpu, 1000
                "a woken thread dispatched while parked", reached.Count Reached.WokenDispatched, 30
                "a displacement across processes", reached.Count Reached.CrossProcessDisplacement, 180
                "a dispatch beyond the machine", reached.Count Reached.BeyondDispatch, 85
            ]

        for name, count, floor in floors do
            if count < floor then
                failwith $"%s{name}: reached %d{count} times over the run, below the floor of %d{floor}"

    [<Test>]
    let ``two processes dispatched onto one processor in turn displace each other`` () : unit =
        // The shape a client with one global interleaving produces: one thread
        // per step, from whichever process, onto the same processor indices.
        let pids, machine = Machines.withThreads SimulatedUnixPlatform.linuxX64 2 1

        let first, second =
            match pids with
            | [ first ; second ] -> first, second
            | other -> failwith $"expected two processes, got %A{other}"

        let runningOn (pid : ProcessId) (machine : UnixSystem<int, string>) : CpuId option =
            UnixScheduling.runningOn (Caller.make pid 0) (Machines.viewOf pid machine)

        let getcpu (pid : ProcessId) (machine : UnixSystem<int, string>) : bool =
            not (throws (fun () -> UnixScheduling.tryGetcpu (Caller.make pid 0) (Machines.viewOf pid machine)))

        let mutable machine = machine

        for round in 1..3 do
            for pid, other in [ first, second ; second, first ] do
                machine <- Machines.doIn pid (UnixScheduling.dispatch (Caller.make pid 0) (CpuId 0)) machine
                runningOn pid machine |> shouldEqual (Some (CpuId 0))
                runningOn other machine |> shouldEqual None
                getcpu pid machine |> shouldEqual true
                getcpu other machine |> shouldEqual false
                // The displaced thread keeps the processor as its own.
                (UnixThreadTable.get 0 (Proc.threads other (Machines.viewOf other machine))).Cpu
                |> shouldEqual (CpuId 0)

                Machines.assertClean machine

    [<Test>]
    let ``a dispatch elsewhere leaves the thread's previous processor idle`` () : unit =
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> UnixBootImage.tryWithProcessorCount 2
            |> Configured.expectOk ProcessorCountRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn 1

        let leader = Callers.thread 0 system

        let system =
            system
            |> UnixScheduling.dispatch leader (CpuId 0)
            |> UnixScheduling.dispatch leader (CpuId 1)

        system.Scheduling.Occupants
        |> shouldEqual (Map.ofList [ CpuId 1, (UnixThreadTable.get 0 (Lone.threads system)).OsThreadId ])

        UnixScheduling.runningOn (Callers.thread 0 system) system
        |> shouldEqual (Some (CpuId 1))

        UnixScheduling.runningOn (Callers.thread 1 system) system |> shouldEqual None
        UnixSystem.checkInvariants system |> shouldEqual []

    [<Test>]
    let ``getcpu is refused under Darwin, which has none`` () : unit =
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.macOsArm64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> fun system -> UnixScheduling.dispatch (Callers.thread 0 system) (CpuId 0) system

        UnixScheduling.tryGetcpu (Callers.thread 0 system) system
        |> shouldEqual (Error (GetCpuRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin))

        UnixScheduling.runningOn (Callers.thread 0 system) system
        |> shouldEqual (Some (CpuId 0))

    [<Test>]
    let ``runningOn answers None for a name that is no thread`` () : unit =
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> fun system -> UnixScheduling.dispatch (Callers.thread 0 system) (CpuId 0) system

        UnixScheduling.runningOn (Callers.thread 7 system) system |> shouldEqual None

    // --- the machine's record, forged ---

    /// `machine` with the processors' occupants replaced by `occupants`, as no
    /// public route can do.
    let private withOccupants
        (occupants : (CpuId * OsThreadId) list)
        (machine : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        { machine with
            Scheduling =
                { machine.Scheduling with
                    Occupants = Map.ofList occupants
                }
        }

    let private threadIdOf (pid : ProcessId) (thread : int) (machine : UnixSystem<int, string>) : OsThreadId =
        (UnixThreadTable.get thread (Proc.threads pid (Machines.viewOf pid machine))).OsThreadId

    [<Test>]
    let ``checkInvariants reports an occupied processor the machine does not have`` () : unit =
        let pids, machine =
            Machines.withThreadsOn
                (UnixBootImage.tryWithProcessorCount 2
                 >> Configured.expectOk ProcessorCountRefusal.describe)
                SimulatedUnixPlatform.linuxX64
                1
                1

        let pid = List.exactlyOne pids
        let leader = threadIdOf pid 0 machine
        let forged = withOccupants [ CpuId 2, leader ] machine

        let defects = Machines.checkInvariants forged

        defects
        |> List.contains (UnixSystemDefect.OccupiedCpuBeyondMachine (CpuId 2, leader, 2))
        |> shouldEqual true

    [<Test>]
    let ``checkInvariants reports an occupant no live thread is, and only where it can tell`` () : unit =
        let pids, machine = Machines.withThreads SimulatedUnixPlatform.linuxX64 2 1

        let first, second =
            match pids with
            | [ first ; second ] -> first, second
            | other -> failwith $"expected two processes, got %A{other}"

        let secondLeader = threadIdOf second 0 machine

        // The thread ID of a thread that has exited.
        let nobody, machine =
            let machine = Machines.doIn first (Threads.spawnIn first 1) machine
            let nobody = threadIdOf first 1 machine

            let exited =
                Machines.doIn
                    first
                    (fun view ->
                        match UnixThreadLifecycle.tryExitThread (Caller.make first 1) 0 view with
                        | Ok (ProcessFate.Continues ((), view)) -> view
                        | other -> failwith $"exitThread: %A{other}"
                    )
                    machine

            nobody, exited

        // A thread ID no thread holds is reported.
        let forged = withOccupants [ CpuId 0, nobody ] machine
        let defect = UnixSystemDefect.OccupantWithoutThread (CpuId 0, nobody)

        Machines.checkInvariants forged |> shouldEqual [ defect ]

        // Another process's running thread is no defect.
        let shared = withOccupants [ CpuId 0, secondLeader ] machine
        Machines.checkInvariants shared |> shouldEqual []

    [<Test>]
    let ``checkInvariants reports a running thread whose processor is another`` () : unit =
        let pids, machine =
            Machines.withThreadsOn
                (UnixBootImage.tryWithProcessorCount 2
                 >> Configured.expectOk ProcessorCountRefusal.describe)
                SimulatedUnixPlatform.linuxX64
                1
                1

        let pid = List.exactlyOne pids
        // The leader was created on processor 0.
        let forged = withOccupants [ CpuId 1, threadIdOf pid 0 machine ] machine

        Machines.checkInvariants forged
        |> shouldEqual [ UnixSystemDefect.OccupantOnAnotherCpu (Caller.make pid 0, CpuId 1, CpuId 0) ]

    [<Test>]
    let ``re-dispatching a running thread allocates nothing`` () : unit =
        // A client reports the thread it runs before every instruction, and almost every
        // report names the thread already running, so that report must cost no garbage.
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> UnixBootImage.tryWithProcessorCount 2
            |> Configured.expectOk ProcessorCountRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn 1

        // Made once, as a client makes the callers of its threads once.
        let first = Callers.thread 0 system
        let second = Callers.thread 1 system

        let system =
            system
            |> UnixScheduling.dispatch first (CpuId 0)
            |> UnixScheduling.dispatch second (CpuId 1)

        // Made once, as a client reads them off the thread rather than constructing them.
        let zero = CpuId 0
        let one = CpuId 1

        let redispatch () : bool =
            obj.ReferenceEquals (UnixScheduling.dispatch first zero system, system)
            && obj.ReferenceEquals (UnixScheduling.dispatch second one system, system)

        // Warm up, so that nothing the first calls do once is counted.
        for _ in 1..100 do
            redispatch () |> shouldEqual true

        let before = GC.GetAllocatedBytesForCurrentThread ()
        let mutable unchanged = true

        for _ in 1..1000 do
            unchanged <- redispatch () && unchanged

        let allocated = GC.GetAllocatedBytesForCurrentThread () - before
        unchanged |> shouldEqual true
        allocated |> shouldEqual 0L
