namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `Proc` for a test of a machine holding one process: the same reach into
/// that process's internals, without naming it.
///
/// Each function fails loudly unless the machine holds exactly one process, and
/// each that reaches into the process also unless `system` is the view of it,
/// as `Proc`'s do. A test of a machine holding several names the process,
/// through `Proc`.
[<RequireQualifiedAccess>]
module internal Lone =

    let private only<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessId
        =
        match Set.toList (ProcessIdTable.live system.Machine.ProcessIds) with
        | [ pid ] -> pid
        | live -> failwith $"Lone.%s{operation}: the machine holds the processes %A{live}, not exactly one"

    /// The ID of the only process on the machine: for a helper that takes the
    /// process as `Proc` does, to call it on a machine holding one.
    let pid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessId
        =
        only "pid" system

    /// The only process's own state.
    let proc<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixProcessState<'Thread, 'Handler>
        =
        Proc.state (only "proc" system) system

    /// `system` with the only process's own state rewritten by `f`.
    let mapProc<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : UnixProcessState<'Thread, 'Handler> -> UnixProcessState<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.mapState (only "mapProc" system) f system

    /// The only process's threads, by the client's name for each.
    let threads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<'Thread, UnixThreadState>
        =
        Proc.threads (only "threads" system) system

    /// `system` with the only process's threads rewritten by `f`.
    let mapThreads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : Map<'Thread, UnixThreadState> -> Map<'Thread, UnixThreadState>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.mapThreads (only "mapThreads" system) f system

    /// The only process's leader: the thread it started with.
    let leader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Thread
        =
        Proc.leader (only "leader" system) system

    /// `system` with `leader` recorded as the only process's leader, whether or
    /// not it is one of the process's threads.
    let withLeader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (leader : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.withLeader (only "withLeader" system) leader system

    /// The only process's descriptor table, read against the machine's open
    /// file descriptions.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        Proc.fileDescriptors (only "fileDescriptors" system) system

    /// `system` with `registry`'s descriptor table as the only process's, and
    /// its open file descriptions as the machine's.
    let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (registry : FileDescriptorRegistry)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.withFileDescriptors (only "withFileDescriptors" system) registry system

    /// `system` with the machine's open file descriptions rewritten by `f`.
    let mapOpenFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (f : OpenFileTable -> OpenFileTable)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        only "mapOpenFiles" system |> ignore
        UnixSystemState.mapOpenFiles f system

    /// `system` with the machine's record of the directories processes stand
    /// in saying where the only process stands: for a test that has moved the
    /// process's current directory by hand.
    let restand<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let standing = (Proc.state (only "restand" system) system).CurrentDirectoryInode

        { system with
            Machine =
                { system.Machine with
                    CurrentDirectories = Map.ofList [ standing, 1 ]
                }
        }
