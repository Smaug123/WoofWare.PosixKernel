namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Threads joining and leaving a process, and the process ending:
/// `UnixThreadLifecycle.spawn`, `UnixThreadLifecycle.exitThread` and
/// `UnixThreadLifecycle.exitGroup`. Every system here has thread 0 as its leader.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixThreadLifecycle =

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    let private withThread (name : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        Threads.ensure name system

    let private mapSignals
        (f : SignalState<int, string> -> SignalState<int, string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals = f proc.Signals
            }
        )

    /// `system` with `entry` generated, without deciding whether it takes
    /// effect at once (`SignalState.enqueue`).
    let private enqueueIn (entry : PendingSignal<int>) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        mapSignals (SignalState.enqueue (Lone.UnixSystemState.signalNumbering system) entry) system

    /// A system with one epoll instance (a kqueue on Darwin), which a thread can park on
    /// in `flock`, and that instance's description.
    let private world (platform : SimulatedUnixPlatform) : UnixSystem<int, string> * OpenFileDescriptionId =
        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let create =
            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux -> FileDescriptorRegistry.createEpoll SimulatedUnixFlavour.Linux
            | SimulatedUnixFlavour.Darwin ->
                FileDescriptorRegistry.createKqueue SimulatedUnixFlavour.Darwin (Lone.proc system).ProcessId

        let fd, registry = create (Lone.fileDescriptors system)

        let id =
            match FileDescriptorRegistry.tryFindWithId fd registry with
            | Some (id, _) -> id
            | None -> failwith $"fd %d{fd} names no description"

        Lone.withFileDescriptors registry system, id

    let private flockOn (queue : OpenFileDescriptionId) : ParkedSyscall =
        ParkedSyscall.Flock
            {
                Requester = queue
                Mode = FlockMode.Exclusive
            }

    let private exitOrFail (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixThreadLifecycle.tryExitThread (Callers.thread thread system) 0 system with
        | Ok (ProcessFate.Continues ((), system)) -> system
        | Ok (ProcessFate.ProcessEnded (ended, _)) ->
            failwith $"expected the process to carry on, but it ended: %O{EndedProcess.termination ended}"
        | Error refusal -> failwith $"expected the exit to be answered, got: %s{ThreadExitRefusal.describe refusal}"

    [<Test>]
    let ``a thread's own pending signals are discarded at its exit, and the process's stay`` () : unit =
        // Measured on Linux 6.18.5 and Darwin 27.0.0 by
        // `docs/plans/2026-08-23-posix-kernel-extraction/thread-exit-pending.c`: a signal
        // pending on an exiting thread alone is never delivered afterwards, nor pending on
        // any other thread, whether the others block it or not.
        for platform in platforms do
            let system, _ = world platform

            let system =
                system
                |> withThread 1
                |> withThread 2
                |> HandlerFrames.enterIn "h" 1 (Set.ofList [ Signal.SIGUSR1 ; Signal.SIGUSR2 ])
                |> HandlerFrames.enterIn "h" 2 (Set.singleton Signal.SIGUSR2)
                |> enqueueIn (
                    {
                        Signal = Signal.SIGUSR1
                        Target = ValueSome 1
                    }
                )
                |> enqueueIn (
                    {
                        Signal = Signal.SIGUSR2
                        Target = ValueNone
                    }
                )
                |> enqueueIn (
                    {
                        Signal = Signal.SIGUSR2
                        Target = ValueSome 2
                    }
                )
                // The process's SIGUSR2 is deliverable to the leader, which
                // blocks nothing, so it owes a return to user mode, as it would
                // had the signal been sent.
                |> Lone.mapThreads (UnixThreadTable.owe 0 OwedReturn.SignalDue)

            let after = exitOrFail 1 system

            Lone.threads after |> Map.keys |> List.ofSeq |> shouldEqual [ 0 ; 2 ]

            SignalState.pending (Lone.proc after).Signals
            |> shouldEqual
                [
                    {
                        Signal = Signal.SIGUSR2
                        Target = ValueNone
                    }
                    {
                        Signal = Signal.SIGUSR2
                        Target = ValueSome 2
                    }
                ]

            SignalState.threadsWithFrames (Lone.proc after).Signals
            |> shouldEqual (Set.singleton 2)

            SignalState.maskOf 2 (Lone.proc after).Signals
            |> SignalMask.signals
            |> shouldEqual (Set.singleton Signal.SIGUSR2)

            UnixSystem.checkInvariants after |> shouldEqual []

    [<Test>]
    let ``a parked thread's exit is refused, and names the park`` () : unit =
        for platform in platforms do
            let system, queue = world platform

            let system =
                system |> withThread 1 |> withThread 2 |> Lone.Parking.park 2 (flockOn queue)

            let park =
                match UnixThreadTable.parkOf 2 (Lone.threads system) with
                | Some park -> park
                | None -> failwith "expected thread 2 to be parked"

            let refused =
                Assert.Throws<System.InvalidOperationException> (fun () ->
                    UnixThreadLifecycle.tryExitThread (Callers.thread 2 system) 0 system |> ignore
                )

            refused.Message
            |> shouldContainText $"UnixThreadLifecycle.exitThread: thread 2 is parked in %A{park.Syscall}"

    /// The leader and one other thread, which leaves, so that what follows is about
    /// being *last* rather than about being alone from the start. The leader, which
    /// stays, blocks a signal and has one pending on it alone.
    let private lastThreadStanding (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let system, _ = world platform

        system
        |> withThread 1
        |> exitOrFail 1
        |> HandlerFrames.enterIn "h" 0 (Set.singleton Signal.SIGUSR1)
        |> enqueueIn (
            {
                Signal = Signal.SIGUSR1
                Target = ValueSome 0
            }
        )

    [<Test>]
    let ``on Linux the last thread's exit ends the process, with that thread's status`` () : unit =
        // Measured on Linux 6.18.5 (aarch64 and x86-64) by
        // `docs/plans/2026-08-23-posix-kernel-extraction/last-thread-exit-status.c`: the
        // raw thread-exit syscall of the last thread ends the process, with its own
        // argument's low 8 bits. The last thread here is the leader, since a leader
        // cannot exit before the others.
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.linuxArm64 ] do
            let system = lastThreadStanding platform

            for status, kept in [ 0, 0 ; 5, 5 ; 256, 0 ; 263, 7 ; -1, 255 ; System.Int32.MinValue, 0 ] do
                match UnixThreadLifecycle.tryExitThread (Callers.thread 0 system) status system with
                | Ok (ProcessFate.ProcessEnded (ended, after)) ->
                    match EndedProcess.termination ended with
                    | ProcessTermination.Exited exitStatus ->
                        (status, ExitStatus.waitidStatus exitStatus) |> shouldEqual (status, kept)
                    | other -> failwith $"expected an exit, got %O{other}"

                    // The last thread's exit ends the process as `exit_group` does.
                    EndedMachine.assertNoneLeft after
                    EndedMachine.assertAsExit (Callers.thread 0 system) system after
                | other -> failwith $"expected the process to end, got %A{other}"

    [<Test>]
    let ``on Darwin the last thread's exit is refused`` () : unit =
        let standing = lastThreadStanding SimulatedUnixPlatform.macOsArm64

        UnixThreadLifecycle.tryExitThread (Callers.thread 0 standing) 0 standing
        |> shouldEqual (Error (ThreadExitRefusal.LastThreadOnDarwin 0))

    [<Test>]
    let ``the leader's exit is refused while another thread lives, and answered once it is last`` () : unit =
        // Measured on Linux 6.18.5 and Darwin 27.0.0 by
        // `docs/plans/2026-08-23-posix-kernel-extraction/leader-exits-first.c`: the
        // process carries on without its leader, which this library does not model.
        for platform in platforms do
            let system, _ = world platform
            let system = system |> withThread 1 |> withThread 2

            UnixThreadLifecycle.tryExitThread (Callers.thread 0 system) 0 system
            |> shouldEqual (Error (ThreadExitRefusal.LeaderBeforeOthers 0))

            let system = system |> exitOrFail 1

            UnixThreadLifecycle.tryExitThread (Callers.thread 0 system) 0 system
            |> shouldEqual (Error (ThreadExitRefusal.LeaderBeforeOthers 0))

            let system = system |> exitOrFail 2

            match
                SimulatedUnixPlatform.flavour platform,
                UnixThreadLifecycle.tryExitThread (Callers.thread 0 system) 0 system
            with
            | SimulatedUnixFlavour.Linux, Ok (ProcessFate.ProcessEnded _) -> ()
            | SimulatedUnixFlavour.Darwin, Error (ThreadExitRefusal.LastThreadOnDarwin 0) -> ()
            | flavour, other ->
                failwith $"%O{flavour}: expected the lone leader's exit to be the last thread's, got %A{other}"

    [<Test>]
    let ``a parked leader's exit is refused as parked`` () : unit =
        // The park is the first thing a thread in a syscall is refused for, whoever it is.
        for platform in platforms do
            let system, queue = world platform
            let system = system |> withThread 1 |> Lone.Parking.park 0 (flockOn queue)
            let park = UnixThreadTable.parkOf 0 (Lone.threads system) |> Option.get

            let refused =
                Assert.Throws<System.InvalidOperationException> (fun () ->
                    UnixThreadLifecycle.tryExitThread (Callers.thread 0 system) 0 system |> ignore
                )

            refused.Message
            |> shouldContainText $"UnixThreadLifecycle.exitThread: thread 0 is parked in %A{park.Syscall}"

    [<Test>]
    let ``exit_group ends the process with the flavour's status, parked threads included`` () : unit =
        for platform in platforms do
            let system, queue = world platform

            let system =
                system
                |> withThread 1
                |> withThread 2
                |> withThread 3
                |> Lone.Parking.park 3 (flockOn queue)
                |> HandlerFrames.enterIn "h" 2 (Set.singleton Signal.SIGUSR2)
                |> enqueueIn (
                    {
                        Signal = Signal.SIGUSR2
                        Target = ValueSome 2
                    }
                )
                |> enqueueIn (
                    {
                        Signal = Signal.SIGUSR1
                        Target = ValueNone
                    }
                )

            let ended, after =
                UnixThreadLifecycle.exitGroup (Callers.thread 1 system) 257 system

            let expected =
                match SimulatedUnixPlatform.flavour platform with
                | SimulatedUnixFlavour.Linux -> 1
                | SimulatedUnixFlavour.Darwin -> 257

            match EndedProcess.termination ended with
            | ProcessTermination.Exited status -> ExitStatus.waitidStatus status |> shouldEqual expected
            | other -> failwith $"expected an exit, got %O{other}"

            EndedProcess.processId ended |> shouldEqual (Lone.pid system)
            // The parked thread's call goes with it, and so does the description
            // its `flock` waits on, once the descriptors are closed.
            EndedMachine.assertNoneLeft after

    [<Test>]
    let ``exit_group from a parked thread, or one that was never registered, fails loudly`` () : unit =
        let system, queue = world SimulatedUnixPlatform.linuxX64

        let system =
            system |> withThread 1 |> withThread 2 |> Lone.Parking.park 2 (flockOn queue)

        let parked =
            Assert.Throws<System.InvalidOperationException> (fun () ->
                UnixThreadLifecycle.exitGroup (Callers.thread 2 system) 0 system
                |> ignore<EndedProcess * UnixSystem<int, string>>
            )

        parked.Message |> shouldContainText "parked"

        let unknown =
            Assert.Throws<System.InvalidOperationException> (fun () ->
                UnixThreadLifecycle.exitGroup (Callers.thread 3 system) 0 system
                |> ignore<EndedProcess * UnixSystem<int, string>>
            )

        unknown.Message |> shouldContainText "names no thread"

    [<Test>]
    let ``exiting a thread that was never registered fails loudly`` () : unit =
        let system, _ = world SimulatedUnixPlatform.linuxX64
        let system = system |> withThread 1 |> withThread 2

        let exn =
            Assert.Throws<System.InvalidOperationException> (fun () ->
                UnixThreadLifecycle.tryExitThread (Callers.thread 3 system) 0 system
                |> ignore<Result<ProcessFate<unit, int, string>, ThreadExitRefusal<int>>>
            )

        exn.Message |> shouldContainText "names no thread"

    [<Test>]
    let ``spawning a name that is already a thread, or onto a processor the machine lacks, is the client's mistake``
        ()
        : unit
        =
        for platform in platforms do
            let system, _ = world platform
            let system = system |> withThread 1

            let taken =
                Assert.Throws<System.ArgumentException> (fun () ->
                    UnixThreadLifecycle.spawn (Callers.thread 0 system) 1 (CpuId 0) system
                    |> ignore<SpawnAnswer * UnixSystem<int, string>>
                )

            taken.ParamName |> shouldEqual "child"
            taken.Message |> shouldContainText "already names a thread"

            let count = UnixSystem.processorCount system

            for cpu in [ count ; count + 1 ; -1 ] do
                let beyond =
                    Assert.Throws<System.ArgumentOutOfRangeException> (fun () ->
                        UnixThreadLifecycle.spawn (Callers.thread 0 system) 2 (CpuId cpu) system
                        |> ignore<SpawnAnswer * UnixSystem<int, string>>
                    )

                beyond.ParamName |> shouldEqual "cpu"

    /// One step of a generated sequence, naming threads 0 to 4.
    [<RequireQualifiedAccess>]
    type private Op =
        /// `call`, made by `thread` through `UnixSystem.tryStep`.
        | Call of thread : int * call : Syscall<int, string>
        | Block of thread : int * Signal
        | Unblock of thread : int * Signal
        | EnqueueOnThread of thread : int * Signal
        | EnqueueOnProcess of Signal
        | Park of thread : int
        | Unpark of thread : int

    let private opGen (numbering : SignalNumbering) : Gen<Op> =
        let thread = Gen.choose (0, 4)

        // SIGCHLD's default is to ignore it, so it exercises both flavours' rules for an
        // ignored signal that is blocked; the rest terminate by default.
        let signal =
            Gen.elements
                [
                    Signal.SIGUSR1
                    Signal.SIGUSR2
                    Signal.SIGTERM
                    Signal.SIGHUP
                    Signal.SIGCHLD
                ]

        // Weighted towards the edges of the bits either flavour keeps.
        let status =
            Gen.oneof
                [
                    Gen.choose (-3, 260)
                    Gen.elements
                        [
                            0xffffff
                            0x1000000
                            0x1000007
                            System.Int32.MaxValue
                            System.Int32.MinValue
                        ]
                    ArbMap.defaults |> ArbMap.generate<int32>
                ]

        // `pthread_sigmask(SIG_BLOCK)` of the signal.
        let block (signal : Signal) : Syscall<int, string> =
            Syscall.PthreadSigMask (
                MaskHow.block numbering,
                Some (SignalMask.ofSignals numbering (Set.singleton signal))
            )

        Gen.frequency
            [
                4,
                Gen.zip thread thread
                |> Gen.map (fun (parent, child) -> Op.Call (parent, Syscall.Spawn (child, CpuId 0)))
                3, Gen.zip thread signal |> Gen.map Op.Block
                1, Gen.zip thread signal |> Gen.map Op.Unblock
                2,
                Gen.zip thread signal
                |> Gen.map (fun (thread, signal) -> Op.Call (thread, block signal))
                3, Gen.zip thread signal |> Gen.map Op.EnqueueOnThread
                1, signal |> Gen.map Op.EnqueueOnProcess
                1, thread |> Gen.map Op.Park
                1, thread |> Gen.map Op.Unpark
                3,
                Gen.zip thread status
                |> Gen.map (fun (thread, status) -> Op.Call (thread, Syscall.ExitThread status))
                1,
                Gen.zip thread status
                |> Gen.map (fun (thread, status) -> Op.Call (thread, Syscall.ExitGroup status))
            ]

    /// What the table must say about which threads exist, kept by a model that knows
    /// nothing of signals: the threads spawned and not since exited, and the ones of
    /// those that are parked.
    type private Model =
        {
            Live : Set<int>
            Parked : Set<int>
        }

    /// The paths the property exists for, so that a generator change which stops
    /// reaching one is noticed.
    [<RequireQualifiedAccess>]
    type private LifecycleLabel =
        | ExitsDroppingAMask
        | ExitsDroppingOwnPending
        | ExitsKeepingProcessPending
        | RefusedParked
        | RefusedLeaderFirst
        | SpawnsInheritingAMask
        | RefusedLast
        | EndedByLastExit
        | EndedByExitGroup
        | EndedWithParkedThread

    /// The per-thread entries the system holds, each of which must name a thread.
    let private orphans (system : UnixSystem<int, string>) : string list =
        let threads = Lone.threads system |> Map.keys |> Set.ofSeq

        let frames =
            Set.difference (SignalState.threadsWithFrames (Lone.proc system).Signals) threads
            |> Set.toList
            |> List.map (fun t -> $"frames of %d{t}")

        let masks =
            Set.difference (SignalState.threadsWithMasks (Lone.proc system).Signals) threads
            |> Set.toList
            |> List.map (fun t -> $"mask of %d{t}")

        let pending =
            SignalState.pending (Lone.proc system).Signals
            |> List.choose (fun entry ->
                match entry.Target with
                | ValueSome t when not (Set.contains t threads) -> Some $"%O{entry.Signal} pending on %d{t}"
                | ValueSome _
                | ValueNone -> None
            )

        frames @ masks @ pending

    /// What the flavour keeps of an exit status, written out independently of
    /// `ExitStatus.ofExitArgument`.
    let private kept (platform : SimulatedUnixPlatform) (status : int32) : int32 =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> status &&& 0xff
        | SimulatedUnixFlavour.Darwin -> status &&& 0xffffff

    /// Check a process that ended, by a call `caller` made in `before`: it
    /// exited with what the flavour keeps of `status`, and the system it left
    /// holds no process, and is what `exit_group` by `caller` leaves of
    /// `before`.
    let private assertExited
        (platform : SimulatedUnixPlatform)
        (status : int32)
        (caller : Caller<int>)
        (before : UnixSystem<int, string>)
        ((ended, after) : EndedProcess * UnixSystem<int, string>)
        : unit
        =
        match EndedProcess.termination ended with
        | ProcessTermination.Exited exitStatus ->
            ExitStatus.waitidStatus exitStatus |> shouldEqual (kept platform status)
        | other -> failwith $"expected an exit, got %O{other}"

        EndedProcess.processId ended |> shouldEqual (Lone.pid before)
        EndedMachine.assertNoneLeft after
        EndedMachine.assertAsExit caller before after

    let private runProperty (platform : SimulatedUnixPlatform) : Coverage<LifecycleLabel> =
        let initial, queue = world platform

        let step
            (cover : LifecycleLabel -> unit)
            ((system, model) : UnixSystem<int, string> * Model)
            (op : Op)
            : UnixSystem<int, string> * Model
            =
            let live (thread : int) = Set.contains thread model.Live

            let after, model' =
                match op with
                | Op.Call (parent, (Syscall.Spawn (child, _) as call)) when
                    live parent && not (Set.contains parent model.Parked) && not (live child)
                    ->
                    let after =
                        match UnixSystem.tryStep (Callers.thread parent system) call system with
                        | Ok (SteppedCall.Spawn (SpawnAnswer.Spawned _, after)) -> after
                        | Ok (SteppedCall.Spawn (SpawnAnswer.Failed error, _)) ->
                            failwith $"spawning %d{child} from %d{parent} failed with %O{error}"
                        | Ok other -> failwith $"spawning %d{child} from %d{parent} answered %A{Stepped.view other}"
                        | Error refusal ->
                            failwith
                                $"spawning %d{child} from %d{parent} was refused: %s{SyscallRefusal.describe refusal}"

                    // The child starts with its parent's mask, and nothing
                    // pending on it.
                    let parentMask = SignalState.maskOf parent (Lone.proc system).Signals

                    SignalState.maskOf child (Lone.proc after).Signals |> shouldEqual parentMask
                    SignalState.maskOf parent (Lone.proc after).Signals |> shouldEqual parentMask
                    SignalState.framesOf child (Lone.proc after).Signals |> shouldEqual []

                    if not (SignalMask.isEmpty parentMask) then
                        cover LifecycleLabel.SpawnsInheritingAMask

                    SignalState.pending (Lone.proc after).Signals
                    |> shouldEqual (SignalState.pending (Lone.proc system).Signals)

                    after,
                    { model with
                        Live = Set.add child model.Live
                    }
                | Op.Block (thread, signal) when live thread ->
                    let threads = Lone.threads system |> Map.keys |> Set.ofSeq

                    match
                        HandlerFrames.tryEnter
                            (Lone.UnixSystemState.signalNumbering system)
                            "h"
                            (Lone.leader system)
                            threads
                            thread
                            (Set.singleton signal)
                            (Lone.proc system).Signals
                    with
                    | Some signals -> mapSignals (fun _ -> signals) system, model
                    | None -> system, model
                | Op.Unblock (thread, _) when
                    live thread
                    && not (List.isEmpty (SignalState.framesOf thread (Lone.proc system).Signals))
                    ->
                    mapSignals (HandlerFrames.leave thread) system, model
                | Op.Call (thread, (Syscall.PthreadSigMask _ as call)) when
                    live thread && not (Set.contains thread model.Parked)
                    ->
                    match UnixSystem.tryStep (Callers.thread thread system) call system with
                    | Ok (SteppedCall.PthreadSigMask (Ok (_, after))) -> after, model
                    | Ok (SteppedCall.PthreadSigMask (Error errno)) ->
                        failwith $"pthread_sigmask(SIG_BLOCK) failed with %O{errno}"
                    | other -> failwith $"pthread_sigmask(SIG_BLOCK) answered %A{Result.map Stepped.view other}"
                | Op.EnqueueOnThread (thread, signal) when live thread ->
                    enqueueIn
                        ({
                            Signal = signal
                            Target = ValueSome thread
                        })
                        system,
                    model
                | Op.EnqueueOnProcess signal ->
                    enqueueIn
                        ({
                            Signal = signal
                            Target = ValueNone
                        })
                        system,
                    model
                | Op.Park thread when live thread ->
                    // A re-park is a woken thread's.
                    let system =
                        if Set.contains thread model.Parked then
                            ForgedPark.woken thread system
                        else
                            system

                    Lone.Parking.park thread (flockOn queue) system,
                    { model with
                        Parked = Set.add thread model.Parked
                    }
                | Op.Unpark thread when live thread ->
                    Lone.UnixParkState.unpark thread system,
                    { model with
                        Parked = Set.remove thread model.Parked
                    }
                | Op.Call (thread, (Syscall.ExitGroup status as call)) when
                    live thread && not (Set.contains thread model.Parked)
                    ->
                    // An ended process has no state to carry on with, so the run goes on
                    // from the one it ended in, as if the call had not been made.
                    let caller = Callers.thread thread system

                    match UnixSystem.tryStep caller call system with
                    | Ok (SteppedCall.ExitGroup (ended, after)) ->
                        assertExited platform status caller system (ended, after)
                    | other -> failwith $"exit_group answered %A{Result.map Stepped.view other}"

                    cover LifecycleLabel.EndedByExitGroup

                    if not model.Parked.IsEmpty then
                        cover LifecycleLabel.EndedWithParkedThread

                    system, model
                | Op.Call (thread, (Syscall.ExitThread status as call)) when live thread ->
                    let result () =
                        UnixSystem.tryStep (Callers.thread thread system) call system

                    if Set.contains thread model.Parked then
                        let park = UnixThreadTable.parkOf thread (Lone.threads system) |> Option.get

                        let refused =
                            Assert.Throws<System.InvalidOperationException> (fun () -> result () |> ignore)

                        refused.Message
                        |> shouldContainText $"thread %d{thread} is parked in %A{park.Syscall}"

                        cover LifecycleLabel.RefusedParked
                        system, model
                    elif thread = 0 && model.Live.Count > 1 then
                        match result () with
                        | Error (SyscallRefusal.ExitThread refusal) ->
                            refusal |> shouldEqual (ThreadExitRefusal.LeaderBeforeOthers thread)
                        | other ->
                            failwith $"expected the leader's exit to be refused, got %A{Result.map Stepped.view other}"

                        cover LifecycleLabel.RefusedLeaderFirst
                        system, model
                    elif model.Live.Count = 1 then
                        match SimulatedUnixPlatform.flavour platform with
                        | SimulatedUnixFlavour.Linux ->
                            match result () with
                            | Ok (SteppedCall.ExitThread (ProcessFate.ProcessEnded (ended, after))) ->
                                assertExited platform status (Callers.thread thread system) system (ended, after)
                            | other ->
                                failwith
                                    $"expected the last thread's exit to end the process, got %A{Result.map Stepped.view other}"

                            cover LifecycleLabel.EndedByLastExit
                        | SimulatedUnixFlavour.Darwin ->
                            match result () with
                            | Error (SyscallRefusal.ExitThread refusal) ->
                                refusal |> shouldEqual (ThreadExitRefusal.LastThreadOnDarwin thread)
                            | other ->
                                failwith
                                    $"expected the last thread's exit to be refused, got %A{Result.map Stepped.view other}"

                            cover LifecycleLabel.RefusedLast

                        // As for `ExitGroup`: the run goes on from the state before.
                        system, model
                    else
                        let after =
                            match result () with
                            | Ok (SteppedCall.ExitThread (ProcessFate.Continues ((), after))) -> after
                            | Ok (SteppedCall.ExitThread (ProcessFate.ProcessEnded (ended, _))) ->
                                failwith
                                    $"expected thread %d{thread}'s exit to leave the process running, but it ended: %O{EndedProcess.termination ended}"
                            | Ok other -> failwith $"thread %d{thread}'s exit answered %A{Stepped.view other}"
                            | Error refusal ->
                                failwith
                                    $"expected thread %d{thread}'s exit to be answered, got: %s{SyscallRefusal.describe refusal}"

                        let signalsBefore = (Lone.proc system).Signals
                        let signalsAfter = (Lone.proc after).Signals

                        // Everything held for `thread` alone goes, and nothing else changes.
                        SignalState.pending signalsAfter
                        |> shouldEqual (
                            SignalState.pending signalsBefore
                            |> List.filter (fun entry -> entry.Target <> ValueSome thread)
                        )

                        SignalState.threadsWithFrames signalsAfter
                        |> shouldEqual (Set.remove thread (SignalState.threadsWithFrames signalsBefore))

                        SignalState.threadsWithMasks signalsAfter
                        |> shouldEqual (Set.remove thread (SignalState.threadsWithMasks signalsBefore))

                        for other in Set.remove thread model.Live do
                            SignalState.framesOf other signalsAfter
                            |> shouldEqual (SignalState.framesOf other signalsBefore)

                            SignalState.maskOf other signalsAfter
                            |> shouldEqual (SignalState.maskOf other signalsBefore)

                        SignalState.dispositions signalsAfter
                        |> shouldEqual (SignalState.dispositions signalsBefore)

                        Lone.threads after |> shouldEqual (Map.remove thread (Lone.threads system))

                        // The thread's ID is freed, and nothing else on the
                        // machine moves.
                        ThreadIdAllocator.live after.Machine.ThreadIds
                        |> shouldEqual (
                            Set.remove
                                (UnixThreadState.osThreadId (UnixThreadTable.get thread (Lone.threads system)))
                                (ThreadIdAllocator.live system.Machine.ThreadIds)
                        )

                        { after.Machine with
                            ThreadIds = system.Machine.ThreadIds
                        }
                        |> shouldEqual system.Machine

                        { (Lone.proc after) with
                            Signals = signalsBefore
                        }
                        |> shouldEqual (Lone.proc system)

                        if not (SignalMask.isEmpty (SignalState.maskOf thread signalsBefore)) then
                            cover LifecycleLabel.ExitsDroppingAMask

                        if
                            SignalState.pending signalsBefore
                            |> List.exists (fun entry -> entry.Target = ValueSome thread)
                        then
                            cover LifecycleLabel.ExitsDroppingOwnPending

                        if
                            SignalState.pending signalsBefore
                            |> List.exists (fun entry -> entry.Target = ValueNone)
                        then
                            cover LifecycleLabel.ExitsKeepingProcessPending

                        after,
                        { model with
                            Live = Set.remove thread model.Live
                        }
                // Every other op names a thread that does not exist, or is a call
                // by a parked thread other than its exit, or spawns onto a live
                // thread, which no client does.
                | Op.Call (_, Syscall.Spawn _)
                | Op.Call (_, Syscall.PthreadSigMask _)
                | Op.Call (_, Syscall.ExitThread _)
                | Op.Call (_, Syscall.ExitGroup _)
                | Op.Block _
                | Op.Unblock _
                | Op.EnqueueOnThread _
                | Op.Park _
                | Op.Unpark _ -> system, model
                | Op.Call (_, other) ->
                    failwith $"%s{UnionCaseName.ofValue other} is not generated by TestUnixThreadLifecycle's sequences"

            // This property puts signals in the state directly rather than
            // sending them, so a thread can have a signal deliverable to it
            // where a sent signal would have been taken, or ended the process,
            // at once. Which return a client makes is not this property's
            // subject: every debt is settled before the next op, and the
            // invariant that a thread with a deliverable signal owes a return
            // is not asked of states built so.
            let after =
                after
                |> Lone.mapThreads (fun threads ->
                    (threads, Map.keys threads |> List.ofSeq)
                    ||> List.fold (fun threads name -> UnixThreadTable.settle name threads)
                )

            // The thread set is exactly the model's, and no per-thread entry outlives its thread.
            Lone.threads after |> Map.keys |> Set.ofSeq |> shouldEqual model'.Live
            orphans after |> shouldEqual []

            UnixSystem.checkInvariants after
            |> List.filter (fun defect ->
                match defect with
                | UnixSystemDefect.SignalDeliverableWithoutOwedReturn _ -> false
                | _ -> true
            )
            |> shouldEqual []

            after, model'

        let property (cover : LifecycleLabel -> unit) (ops : Op list) : unit =
            ((initial,
              {
                  Live = Set.singleton 0
                  Parked = Set.empty
              }),
             ops)
            ||> List.fold (step cover)
            |> ignore<UnixSystem<int, string> * Model>

        CoverageSample.check
            (Config.QuickThrowOnFailure.WithMaxTest 1000)
            (Arb.fromGen (Gen.listOf (opGen (SimulatedUnixPlatform.signalNumbering platform))))
            property

    [<TestCaseSource(nameof platforms)>]
    let ``the thread set follows spawns and exits, no per-thread entry outlives its thread, and the process ends as its flavour says``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let coverage = runProperty platform

        // Counted over the fixed sample, so a floor fails when a generator change
        // stops reaching the path, not by chance. Each sits at least four
        // standard deviations below the count that 1000 cases reach: measured
        // over 30 runs per flavour, the rarest is `EndedWithParkedThread`, at a
        // mean of 30 and a standard deviation of 7.
        coverage.Count LifecycleLabel.ExitsDroppingAMask |> shouldBeGreaterThan 20
        coverage.Count LifecycleLabel.ExitsDroppingOwnPending |> shouldBeGreaterThan 20

        coverage.Count LifecycleLabel.ExitsKeepingProcessPending
        |> shouldBeGreaterThan 20

        coverage.Count LifecycleLabel.RefusedParked |> shouldBeGreaterThan 20
        coverage.Count LifecycleLabel.RefusedLeaderFirst |> shouldBeGreaterThan 20
        coverage.Count LifecycleLabel.SpawnsInheritingAMask |> shouldBeGreaterThan 20
        coverage.Count LifecycleLabel.EndedByExitGroup |> shouldBeGreaterThan 50
        coverage.Count LifecycleLabel.EndedWithParkedThread |> shouldBeGreaterThan 3

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            coverage.Count LifecycleLabel.EndedByLastExit |> shouldBeGreaterThan 20
            coverage.Count LifecycleLabel.RefusedLast |> shouldEqual 0
        | SimulatedUnixFlavour.Darwin ->
            coverage.Count LifecycleLabel.RefusedLast |> shouldBeGreaterThan 20
            coverage.Count LifecycleLabel.EndedByLastExit |> shouldEqual 0
