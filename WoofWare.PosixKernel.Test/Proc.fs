namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A test's reach into the internals of the process `pid` of a system that
/// may hold others: its own state, its threads, its leader, and its
/// descriptor table with the machine's open file descriptions; and the view
/// of the system from it, for a test that calls a function working on one
/// process's view. Every test reads and writes those through here, or through
/// `Lone` on a system holding one process, rather than through the
/// `UnixSystem` record's fields or `UnixSystemState`, so that a change to what
/// a `UnixSystem` holds changes these modules alone.
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
        match Map.tryFind (ProcessId.toInt32 pid) system.Processes with
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
            Processes = Map.add (ProcessId.toInt32 pid) (f slot) system.Processes
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

    /// `unview` of a view whose process carries on, and the system without
    /// the process of one whose process has ended, as `Shape.map` takes them.
    let unfocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Unfocus<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>> =
        {
            Back = unview
            Without = ProcessView.unfocusWithout
        }

    /// `unfocus` of the views a call by `thread` answered: `thread` owes a
    /// return to user mode in each view whose process carries on, as
    /// `Entry.call` leaves it (`OwedReturns.markIfDue`).
    let unfocusAfterCallBy<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        : Unfocus<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>>
        =
        {
            Back = OwedReturns.markIfDue thread >> unview
            Without = ProcessView.unfocusWithout
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

    /// The process `pid`'s threads, by the client's name for each.
    let threads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<'Thread, UnixThreadState>
        =
        (slot "threads" pid system).Threads

    /// `system` with the process `pid`'s threads rewritten by `f`.
    let mapThreads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : Map<'Thread, UnixThreadState> -> Map<'Thread, UnixThreadState>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        mapSlot
            "mapThreads"
            pid
            (fun slot ->
                { slot with
                    Threads = f slot.Threads
                }
            )
            system

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
