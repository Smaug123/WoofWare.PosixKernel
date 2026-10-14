namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open WoofWare.PosixKernel

/// Several processes on one `SimulatedMachine`, for a test that drives each
/// through its own view. Every test outside `TestSimulatedMachine` reaches the
/// `SimulatedMachine` module through here, so that a change to how a machine
/// holds its processes changes this module rather than every test.
[<RequireQualifiedAccess>]
module internal Machines =

    /// The machine `system` runs on, holding `system`'s process as its only
    /// one.
    let ofSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : SimulatedMachine<'Thread, 'Handler>
        =
        SimulatedMachine.ofSystem system

    /// The ID of a new process started on `machine` as `launch` describes,
    /// and the machine with it; or the refusal to start it.
    let tryLaunch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : Result<ProcessId * SimulatedMachine<'Thread, 'Handler>, ProcessCreationRefusal>
        =
        SimulatedMachine.tryLaunch launch machine

    /// The process ID of every process on `machine`.
    let processIds<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : Set<ProcessId>
        =
        SimulatedMachine.processIds machine

    /// The view of `machine` from the process `pid`, or `None` if no process
    /// on it has that ID.
    let focus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler> option
        =
        SimulatedMachine.focus pid machine

    /// `view` written back into `machine`, failing loudly if `view` is not a
    /// view of `machine` as it stands.
    let unfocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : UnixSystem<'Thread, 'Handler>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : SimulatedMachine<'Thread, 'Handler>
        =
        SimulatedMachine.unfocus view machine

    /// Whether `machine` holds `view`'s process and threads exactly as `view`
    /// has them, by identity.
    let holdsProcessOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : UnixSystem<'Thread, 'Handler>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : bool
        =
        SimulatedMachine.holdsProcessOf view machine

    /// `f` in the view of `pid`, written back; or `None` if no process on
    /// `machine` has that ID.
    let inView<'Thread, 'Handler, 'Result when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : UnixSystem<'Thread, 'Handler> -> 'Result * UnixSystem<'Thread, 'Handler>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : ('Result * SimulatedMachine<'Thread, 'Handler>) option
        =
        SimulatedMachine.inView pid f machine

    /// `UnixSystem.step` of `call` by `thread` of the process `pid`, with a
    /// refusal answered as the `Error`; `None` if no process on `machine` has
    /// that ID.
    let tryStep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (thread : 'Thread)
        (call : Syscall)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : (Result<SyscallOutcome, SyscallRefusal<'Thread>> * SimulatedMachine<'Thread, 'Handler>) option
        =
        SimulatedMachine.tryStep (Caller.make pid thread) call machine

    /// `UnixSystem.step` of `call` by `thread` of the process `pid`, with a
    /// refusal raised; `None` if no process on `machine` has that ID.
    let step<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (thread : 'Thread)
        (call : Syscall)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : (SyscallOutcome * SimulatedMachine<'Thread, 'Handler>) option
        =
        SimulatedMachine.step (Caller.make pid thread) call machine

    /// How the process `ended` ended, and `machine` with that process ended
    /// on it and its descriptors closed; or the refusal to end it.
    let tryEndProcess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (ended : EndedProcess<'Thread, 'Handler>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : Result<ProcessTermination * SimulatedMachine<'Thread, 'Handler>, ProcessEndRefusal>
        =
        SimulatedMachine.tryEndProcess ended machine

    /// How the process `ended`, which ran alone on its machine, ended, and that
    /// machine with the process ended on it; or the refusal to end it.
    let tryEndLoneProcess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (ended : EndedProcess<'Thread, 'Handler>)
        : Result<ProcessTermination * SimulatedMachine<'Thread, 'Handler>, ProcessEndRefusal>
        =
        SimulatedMachine.tryEndLoneProcess ended

    /// Which of the threads in `asleep`, by process, `machine` wakes, and
    /// what woke each.
    let wakes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (asleep : Map<ProcessId, Set<'Thread>>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : ((ProcessId * 'Thread) * Set<WakePrimitive>) list
        =
        SimulatedMachine.wakes asleep machine

    /// `wakes`, answered from `memo` when it can tell that `machine` wakes
    /// none of `asleep`, and the memo for the next call.
    let wakesRemembering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (memo : WakeSweepMemo<'Thread, 'Handler>)
        (asleep : Map<ProcessId, Set<'Thread>>)
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : ((ProcessId * 'Thread) * Set<WakePrimitive>) list * WakeSweepMemo<'Thread, 'Handler>
        =
        SimulatedMachine.wakesRemembering memo asleep machine

    /// Every rule `machine` breaks, across all its processes.
    let checkInvariants<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (machine : SimulatedMachine<'Thread, 'Handler>)
        : SimulatedMachineDefect<'Thread> list
        =
        SimulatedMachine.checkInvariants machine

    /// A launch of a process on `platform` with the three piped standard
    /// streams and one thread, 0, on processor 0.
    let launchOn (platform : SimulatedUnixPlatform) : ProcessLaunch<int> =
        Launched.launch platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A machine of `platform`, booted from an image `configure` configured,
    /// with `count` processes, the first booted and the rest launched, each
    /// with threads 0 to `threads - 1`, and their process IDs in that order.
    let withThreadsOn
        (configure : UnixBootImage<int, string> -> UnixBootImage<int, string>)
        (platform : SimulatedUnixPlatform)
        (count : int)
        (threads : int)
        : ProcessId list * SimulatedMachine<int, string>
        =
        let first =
            UnixSystem.initial<int, string> platform
            |> configure
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let pids, machine =
            (([ Lone.pid first ], ofSystem first), [ 2..count ])
            ||> List.fold (fun (pids, machine) _ ->
                match tryLaunch (launchOn platform) machine with
                | Ok (pid, machine) -> pids @ [ pid ], machine
                | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"
            )

        let machine =
            (machine, pids)
            ||> List.fold (fun machine pid ->
                match
                    inView
                        pid
                        (fun view -> (), ([ 1 .. threads - 1 ], view) ||> List.foldBack (Threads.ensureIn pid))
                        machine
                with
                | Some ((), machine) -> machine
                | None -> failwith $"no process %O{pid}"
            )

        pids, machine

    /// `withThreadsOn` with the image as `UnixSystem.initial` makes it.
    let withThreads
        (platform : SimulatedUnixPlatform)
        (count : int)
        (threads : int)
        : ProcessId list * SimulatedMachine<int, string>
        =
        withThreadsOn id platform count threads

    /// `withThreads` with threads 0 to 4 in each process, as `KeventWorld`'s
    /// helpers expect.
    let ofCount (platform : SimulatedUnixPlatform) (count : int) : ProcessId list * SimulatedMachine<int, string> =
        withThreads platform count 5

    /// The view of `pid`, which must be on `machine`.
    let viewOf (pid : ProcessId) (machine : SimulatedMachine<int, string>) : UnixSystem<int, string> =
        match focus pid machine with
        | Some view -> view
        | None -> failwith $"no process %O{pid}"

    /// `f` in the view of `pid`, written back.
    let inProcess
        (pid : ProcessId)
        (f : UnixSystem<int, string> -> 'a * UnixSystem<int, string>)
        (machine : SimulatedMachine<int, string>)
        : 'a * SimulatedMachine<int, string>
        =
        match inView pid f machine with
        | Some answered -> answered
        | None -> failwith $"no process %O{pid}"

    /// `f` in the view of `pid`, written back, for an `f` that answers nothing.
    let doIn
        (pid : ProcessId)
        (f : UnixSystem<int, string> -> UnixSystem<int, string>)
        (machine : SimulatedMachine<int, string>)
        : SimulatedMachine<int, string>
        =
        inProcess pid (fun view -> (), f view) machine |> snd

    /// Every invariant of `machine` holds: the machine's own, each view's, each
    /// process's descriptor table's as one view of it sees it, and the
    /// filesystem's.
    let assertClean (machine : SimulatedMachine<int, string>) : unit =
        checkInvariants machine |> shouldEqual []

        for pid in processIds machine do
            let view = viewOf pid machine
            UnixSystem.checkInvariants view |> shouldEqual []

            FileDescriptorRegistry.checkInvariants (UnixSystem.fileDescriptors pid view)
            |> shouldEqual []

            VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes view) view.Machine.FileSystem
            |> shouldEqual []

    let platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]
