namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open WoofWare.PosixKernel

/// Several processes in one `UnixSystem`, for a test that drives each by
/// naming it. Every test of several processes reaches them through here, so
/// that a change to how a system holds its processes changes this module
/// rather than every test.
[<RequireQualifiedAccess>]
module internal Machines =

    /// Fail the test unless `system` holds the process `pid`.
    let private require<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : unit
        =
        if not (Set.contains pid (UnixSystem.processIds system)) then
            failwith $"Machines.%s{operation}: no process %O{pid}; the system holds %A{UnixSystem.processIds system}"

    /// The system a booted `system` is: itself, holding its first process.
    let ofSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        system

    /// The ID of a new process started in `system` as `launch` describes,
    /// and the system with it; or the refusal to start it.
    let tryLaunch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ProcessId * UnixSystem<'Thread, 'Handler>, ProcessCreationRefusal>
        =
        UnixSystem.tryLaunch launch system

    /// The process ID of every process in `system`.
    let processIds<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Set<ProcessId>
        =
        UnixSystem.processIds system

    /// `system`, in which the process `pid`'s calls are made, or `None` if it
    /// holds no process with that ID.
    let focus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler> option
        =
        if Set.contains pid (UnixSystem.processIds system) then
            Some system
        else
            None

    /// The system after a call made in `after`, which is the system itself.
    let unfocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (after : UnixSystem<'Thread, 'Handler>)
        (_ : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        after

    /// `f` of `system`, made by the process `pid`; or `None` if `system` holds
    /// no process with that ID.
    let inView<'Thread, 'Handler, 'Result when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : UnixSystem<'Thread, 'Handler> -> 'Result * UnixSystem<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ('Result * UnixSystem<'Thread, 'Handler>) option
        =
        focus pid system |> Option.map f

    /// `UnixSystem.step` of `call` by `thread` of the process `pid`, with a
    /// refusal answered as the `Error`; `None` if `system` holds no process
    /// with that ID.
    let tryStep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (thread : 'Thread)
        (call : Syscall<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SteppedCall<'Thread, 'Handler>, SyscallRefusal<'Thread>> option
        =
        focus pid system
        |> Option.map (UnixSystem.tryStep (Caller.make pid thread) call)

    /// `UnixSystem.step` of `call` by `thread` of the process `pid`, with a
    /// refusal raised; `None` if `system` holds no process with that ID.
    let step<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (thread : 'Thread)
        (call : Syscall<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : SteppedCall<'Thread, 'Handler> option
        =
        focus pid system |> Option.map (UnixSystem.step (Caller.make pid thread) call)

    /// Which sleeping threads `system` wakes, by process, and what woke each;
    /// and the system with them woken (`UnixWait.wake`).
    let wake<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ((ProcessId * 'Thread) * Set<WakePrimitive>) list * UnixSystem<'Thread, 'Handler>
        =
        let woken, system = UnixWait.wake system

        woken
        |> List.map (fun (caller, fired) -> (Caller.processId caller, Caller.thread caller), fired),
        system

    /// The sleeping threads `wake` would wake, by process, and what would wake
    /// each: its answer, for a test that asks only who wakes.
    let wakes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ((ProcessId * 'Thread) * Set<WakePrimitive>) list
        =
        fst (wake system)

    /// `system` after `wake`, which must wake exactly the threads `expected`
    /// names, by process, in that order.
    let waking<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (expected : (ProcessId * 'Thread) list)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let woken, system = wake system
        woken |> List.map fst |> shouldEqual expected
        system

    /// Which threads of each process are asleep in a call (`ParkState.Asleep`),
    /// and which have been woken and are yet to finish theirs.
    let parkStates<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Set<ProcessId * 'Thread> * Set<ProcessId * 'Thread>
        =
        let parked =
            UnixSystem.processIds system
            |> Seq.collect (fun pid ->
                UnixSystem.threads pid system
                |> Map.toSeq
                |> Seq.choose (fun (thread, state) ->
                    UnixThreadState.park state |> Option.map (fun park -> (pid, thread), park.State)
                )
            )
            |> List.ofSeq

        let asleep =
            parked
            |> List.choose (fun (key, state) ->
                match state with
                | ParkState.Asleep -> Some key
                | ParkState.Woken _ -> None
            )
            |> Set.ofList

        let woken =
            parked
            |> List.choose (fun (key, state) ->
                match state with
                | ParkState.Woken _ -> Some key
                | ParkState.Asleep -> None
            )
            |> Set.ofList

        asleep, woken

    /// Every rule `system` breaks, across all its processes.
    let checkInvariants<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystemDefect<'Thread> list
        =
        UnixSystem.checkInvariants system

    /// A launch of a process on `platform` with the three piped standard
    /// streams and one thread, 0, on processor 0.
    let launchOn (platform : SimulatedUnixPlatform) : ProcessLaunch<int> =
        Launched.launch platform UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A system of `platform`, booted from an image `configure` configured,
    /// with `count` processes, the first booted and the rest launched, each
    /// with threads 0 to `threads - 1`, and their process IDs in that order.
    let withThreadsOn
        (configure : UnixBootImage<int, string> -> UnixBootImage<int, string>)
        (platform : SimulatedUnixPlatform)
        (count : int)
        (threads : int)
        : ProcessId list * UnixSystem<int, string>
        =
        let first =
            UnixSystem.initial<int, string> platform
            |> configure
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let pids, system =
            (([ Lone.pid first ], first), [ 2..count ])
            ||> List.fold (fun (pids, system) _ ->
                match tryLaunch (launchOn platform) system with
                | Ok (pid, system) -> pids @ [ pid ], system
                | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"
            )

        let system =
            (system, pids)
            ||> List.fold (fun system pid -> ([ 1 .. threads - 1 ], system) ||> List.foldBack (Threads.ensureIn pid))

        pids, system

    /// `withThreadsOn` with the image as `UnixSystem.initial` makes it.
    let withThreads
        (platform : SimulatedUnixPlatform)
        (count : int)
        (threads : int)
        : ProcessId list * UnixSystem<int, string>
        =
        withThreadsOn id platform count threads

    /// `withThreads` with threads 0 to 4 in each process, as `KeventWorld`'s
    /// helpers expect.
    let ofCount (platform : SimulatedUnixPlatform) (count : int) : ProcessId list * UnixSystem<int, string> =
        withThreads platform count 5

    /// `system`, which must hold the process `pid`.
    let viewOf (pid : ProcessId) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        require "viewOf" pid system
        system

    /// `f` of `system`, made by the process `pid`, which `system` must hold.
    let inProcess
        (pid : ProcessId)
        (f : UnixSystem<int, string> -> 'a * UnixSystem<int, string>)
        (system : UnixSystem<int, string>)
        : 'a * UnixSystem<int, string>
        =
        require "inProcess" pid system
        f system

    /// `inProcess`, for an `f` that answers nothing.
    let doIn
        (pid : ProcessId)
        (f : UnixSystem<int, string> -> UnixSystem<int, string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        inProcess pid (fun system -> (), f system) system |> snd

    /// Every invariant of `system` holds: its own, across every process, and
    /// the filesystem's.
    let assertClean (system : UnixSystem<int, string>) : unit =
        checkInvariants system |> shouldEqual []

        VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes system) system.Machine.FileSystem
        |> shouldEqual []

    let platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]
