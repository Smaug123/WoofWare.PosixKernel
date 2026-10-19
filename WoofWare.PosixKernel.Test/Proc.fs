namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A test's reach into the internals of the process `pid` of a system that
/// may hold others: its own state, each of its threads, its leader, and its
/// descriptor table with the machine's open file descriptions; and the view
/// of the system from it, for a test that calls a function working on one
/// process's view. Every test reads and writes those through here, or through
/// `Lone` on a system holding one process, and forges a thread's state through
/// `ForgedThread`, rather than through the `UnixSystem` record's fields or
/// `UnixSystemState`, so that a change to what a `UnixSystem` holds changes
/// these modules and `Kernel` alone (`scripts/check-test-boundaries.py`).
///
/// Each function fails loudly unless `system` holds the process `pid`.
[<RequireQualifiedAccess>]
module internal Proc =

    let private slot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessSlot<'Thread, 'Handler>
        =
        match ProcessTable.tryFind (ProcessId.toInt32 pid) system.Processes with
        | Some slot -> slot
        | None ->
            failwith
                $"Proc.%s{operation}: asked about process %O{pid}, but the system holds the processes %A{UnixSystem.processIds system}"

    let private mapSlot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (pid : ProcessId)
        (f : ProcessSlot<'Thread, 'Handler> -> ProcessSlot<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let slot = slot operation pid system

        { system with
            Processes = ProcessTable.add (ProcessId.toInt32 pid) (f slot) system.Processes
        }

    /// The view of `system` from the process `pid`: what a function that works
    /// on one process's view, such as a call's body, takes.
    let view<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        match ProcessView.tryFocus pid system with
        | Some view -> view
        | None ->
            failwith
                $"Proc.view: asked about process %O{pid}, but the system holds the processes %A{UnixSystem.processIds system}"

    /// The system `view` is a view of, with the view's process as the view
    /// has it.
    let unview<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : ProcessView<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        ProcessView.unfocus view

    /// The system `view` is a view of, without the view's process, which has
    /// ended. Fails loudly if the process still has a thread.
    let unviewWithout<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : ProcessView<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        ProcessView.unfocusWithout view

    /// `unview` of a view whose process carries on, and `unviewWithout` of one
    /// whose process has ended, as `Shape.map` takes them.
    let unfocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Unfocus<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>> =
        {
            Back = unview
            Without = unviewWithout
        }

    /// `f` in the view of `pid`, and the system its view is a view of.
    let inView<'Thread, 'Handler, 'Result when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : ProcessView<'Thread, 'Handler> -> 'Result * ProcessView<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Result * UnixSystem<'Thread, 'Handler>
        =
        let result, view = f (view pid system)
        result, unview view

    /// The process `pid`'s own state.
    let state<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixProcessState<'Thread, 'Handler>
        =
        (slot "state" pid system).Process

    /// `system` with the process `pid`'s own state rewritten by `f`.
    let mapState<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : UnixProcessState<'Thread, 'Handler> -> UnixProcessState<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        mapSlot
            "mapState"
            pid
            (fun slot ->
                { slot with
                    Process = f slot.Process
                }
            )
            system

    /// The process `pid`'s thread table, as the internal functions of
    /// `UnixThreadTable` take it: for the tests of the table itself, and for
    /// `ForgedThread`. Every other test asks about one thread at a time
    /// (`thread`, `parkOf`, `parkedIn`, `owedBy`), or reads `threadMap`.
    let threadTable<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : ThreadTable<'Thread>
        =
        (slot "threadTable" pid system).Threads

    /// `system` with the process `pid`'s thread table rewritten by `f`: for
    /// `ForgedThread`, through which every test forges a thread's state.
    let mapThreadTable<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : ThreadTable<'Thread> -> ThreadTable<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        mapSlot
            "mapThreadTable"
            pid
            (fun slot ->
                { slot with
                    Threads = f slot.Threads
                }
            )
            system

    /// The process `pid`'s threads, by the client's name for each, read from
    /// its thread table rather than through `UnixSystem.threads`, so that a
    /// test may hold the one to the other.
    let threadMap<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<'Thread, UnixThreadState>
        =
        UnixThreadTable.byName (threadTable pid system)

    /// The thread `caller` names, as a client reads it (`UnixSystem.threads`).
    /// Fails loudly unless its process has that thread.
    let thread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixThreadState
        =
        let threads = UnixSystem.threads (Caller.processId caller) system

        match Map.tryFind (Caller.thread caller) threads with
        | Some state -> state
        | None ->
            failwith
                $"Proc.thread: asked about %O{caller}, but its process has the threads %A{Map.keys threads |> List.ofSeq}"

    /// The park the thread `caller` names is in, with its place in park order,
    /// if it is parked (`UnixThreadState.park`).
    let parkOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ThreadPark option
        =
        UnixThreadState.park (thread caller system)

    /// The syscall the thread `caller` names is parked in, if any
    /// (`UnixThreadState.parkedIn`).
    let parkedIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ParkedSyscall option
        =
        UnixThreadState.parkedIn (thread caller system)

    /// What the thread `caller` names owes before it makes another call, if
    /// anything (`UnixThreadState.Owes`).
    let owedBy<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : OwedReturn option
        =
        (thread caller system).Owes

    /// The process `pid`'s leader: the thread it started with.
    let leader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Thread
        =
        (slot "leader" pid system).Leader

    /// `system` with `leader` recorded as the process `pid`'s leader, whether
    /// or not it is one of that process's threads.
    let withLeader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (leader : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        mapSlot
            "withLeader"
            pid
            (fun slot ->
                { slot with
                    Leader = leader
                }
            )
            system

    /// `system` with the process `pid` held under the ID `renumbered` instead,
    /// its own state recording that ID too, and nothing else changed: neither
    /// the machine's record of process IDs nor any other process.
    let renumber<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (renumbered : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let slot = slot "renumber" pid system

        { system with
            Processes =
                system.Processes
                |> ProcessTable.remove (ProcessId.toInt32 pid)
                |> ProcessTable.add
                    (ProcessId.toInt32 renumbered)
                    { slot with
                        Process =
                            { slot.Process with
                                ProcessId = renumbered
                            }
                    }
        }

    /// The process `pid`'s descriptor table, read against the machine's open
    /// file descriptions.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        UnixSystemState.fileDescriptors (view pid system)

    /// `system` with `registry`'s descriptor table as the process `pid`'s, and
    /// its open file descriptions as the machine's.
    let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (registry : FileDescriptorRegistry)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        view pid system |> UnixSystemState.withFileDescriptors registry |> unview
