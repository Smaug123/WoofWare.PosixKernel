namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A test's reach into the internals of the process `pid` on a machine that
/// may hold others: its own state, its threads, its leader, and its
/// descriptor table with the machine's open file descriptions. Every test
/// reads and writes those through here, or through `Lone` on a machine holding
/// one process, rather than through the `UnixSystem` record's fields or
/// `UnixSystemState`, so that a change to what a `UnixSystem` holds changes
/// these modules alone.
///
/// Each function fails loudly unless `system` is the view of `pid`.
[<RequireQualifiedAccess>]
module internal Proc =

    let private requireView<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : unit
        =
        if system.Process.ProcessId <> pid then
            failwith
                $"Proc.%s{operation}: asked about process %O{pid} in the view of process %O{system.Process.ProcessId}"

    /// The process `pid`'s own state.
    let state<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixProcessState<'Thread, 'Handler>
        =
        requireView "state" pid system
        system.Process

    /// `system` with the process `pid`'s own state rewritten by `f`.
    let mapState<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : UnixProcessState<'Thread, 'Handler> -> UnixProcessState<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        requireView "mapState" pid system

        { system with
            Process = f system.Process
        }

    /// The process `pid`'s threads, by the client's name for each.
    let threads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<'Thread, UnixThreadState>
        =
        requireView "threads" pid system
        system.Threads

    /// `system` with the process `pid`'s threads rewritten by `f`.
    let mapThreads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (f : Map<'Thread, UnixThreadState> -> Map<'Thread, UnixThreadState>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        requireView "mapThreads" pid system

        { system with
            Threads = f system.Threads
        }

    /// The process `pid`'s leader: the thread it started with.
    let leader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Thread
        =
        requireView "leader" pid system
        system.Leader

    /// `system` with `leader` recorded as the process `pid`'s leader, whether
    /// or not it is one of that process's threads.
    let withLeader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (leader : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        requireView "withLeader" pid system

        { system with
            Leader = leader
        }

    /// The process `pid`'s descriptor table, read against the machine's open
    /// file descriptions.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        requireView "fileDescriptors" pid system
        UnixSystemState.fileDescriptors system

    /// `system` with `registry`'s descriptor table as the process `pid`'s, and
    /// its open file descriptions as the machine's.
    let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (registry : FileDescriptorRegistry)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        requireView "withFileDescriptors" pid system
        UnixSystemState.withFileDescriptors registry system
