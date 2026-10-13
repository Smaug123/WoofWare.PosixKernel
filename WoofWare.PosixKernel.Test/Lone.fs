namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// A test's reach into the internals of the only process on a machine: its own
/// state, its threads, its leader, and its descriptor table with the machine's
/// open file descriptions. Every test reads and writes those through here
/// rather than through the `UnixSystem` record's fields or `UnixSystemState`,
/// so that a change to what a `UnixSystem` holds changes this module alone.
[<RequireQualifiedAccess>]
module internal Lone =

    /// The only process's own state.
    let proc<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixProcessState<'Thread, 'Handler>
        =
        system.Process

    /// `system` with the only process's own state rewritten by `f`.
    let mapProc<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : UnixProcessState<'Thread, 'Handler> -> UnixProcessState<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Process = f system.Process
        }

    /// The only process's threads, by the client's name for each.
    let threads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<'Thread, UnixThreadState>
        =
        system.Threads

    /// `system` with the only process's threads rewritten by `f`.
    let mapThreads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : Map<'Thread, UnixThreadState> -> Map<'Thread, UnixThreadState>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Threads = f system.Threads
        }

    /// The only process's leader: the thread it started with.
    let leader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Thread
        =
        system.Leader

    /// `system` with `leader` recorded as the only process's leader, whether or
    /// not it is one of the process's threads.
    let withLeader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (leader : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Leader = leader
        }

    /// The only process's descriptor table, read against the machine's open
    /// file descriptions.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        UnixSystemState.fileDescriptors system

    /// `system` with `registry`'s descriptor table as the only process's, and
    /// its open file descriptions as the machine's.
    let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (registry : FileDescriptorRegistry)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        UnixSystemState.withFileDescriptors registry system

    /// `system` with the machine's open file descriptions rewritten by `f`.
    let mapOpenFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : OpenFileTable -> OpenFileTable)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        UnixSystemState.mapOpenFiles f system

    /// `system` with the machine's record of the directories processes stand
    /// in saying where the only process stands: for a test that has moved the
    /// process's current directory by hand.
    let restand<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Machine =
                { system.Machine with
                    CurrentDirectories = Map.ofList [ system.Process.CurrentDirectoryInode, 1 ]
                }
        }
