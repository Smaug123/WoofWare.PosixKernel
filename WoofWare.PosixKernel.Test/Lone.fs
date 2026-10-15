namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `Proc` for a test of a system holding one process: the same reach into
/// that process's internals, without naming it.
///
/// Each function fails loudly unless the system holds exactly one process. A
/// test of a system holding several names the process, through `Proc`.
[<RequireQualifiedAccess>]
module internal Lone =

    let private only<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessId
        =
        match Set.toList (UnixSystem.processIds system) with
        | [ pid ] -> pid
        | live -> failwith $"Lone.%s{operation}: the system holds the processes %A{live}, not exactly one"

    /// The ID of the only process on the machine: for a helper that takes the
    /// process as `Proc` does, to call it on a machine holding one.
    let pid<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessId
        =
        only "pid" system

    /// The view of `system` from its only process: what a function that works
    /// on one process's view, such as a call's body, takes.
    let view<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        Proc.view (only "view" system) system

    /// The system `view` is a view of, with the view's process as the view
    /// has it.
    let unview<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (view : ProcessView<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        Proc.unview view

    /// `unview` of a view whose process carries on, and the system without
    /// the process of one whose process has ended, as `Shape.map` takes them.
    let unfocus<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        : Unfocus<ProcessView<'Thread, 'Handler>, UnixSystem<'Thread, 'Handler>> =
        Proc.unfocus

    /// `f` in the view of the only process, and the system its view is a view
    /// of.
    let inView<'Thread, 'Handler, 'Result when 'Thread : comparison and 'Handler : equality>
        (f : ProcessView<'Thread, 'Handler> -> 'Result * ProcessView<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Result * UnixSystem<'Thread, 'Handler>
        =
        Proc.inView (only "inView" system) f system

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

        { system with
            Machine =
                { system.Machine with
                    OpenFiles = f system.Machine.OpenFiles
                }
        }

    /// `UnixWait.wake` of the only process's threads, each woken thread
    /// answered by its name, and the system with them woken.
    let wake<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ('Thread * Set<WakePrimitive>) list * UnixSystem<'Thread, 'Handler>
        =
        only "wake" system |> ignore
        let woken, system = UnixWait.wake system
        woken |> List.map (fun (caller, fired) -> Caller.thread caller, fired), system

    /// The threads of the only process that `UnixWait.wake` would wake, each
    /// answered by its name: `wake`'s answer, for a test that asks only who
    /// wakes, and finishes no call in the system it was asked of.
    let wakes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ('Thread * Set<WakePrimitive>) list
        =
        fst (wake system)

    /// `system` after `UnixWait.wake`, which must wake exactly the threads of
    /// the only process `expected` names, in that order.
    let waking<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (expected : 'Thread list)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let woken, system = wake system
        let woken = woken |> List.map fst

        if woken <> expected then
            failwith $"Lone.waking: expected UnixWait.wake to wake %A{expected}, but it woke %A{woken}"

        system

    /// `UnixWait.deadlines` of the only process's sleeping threads.
    let deadlines<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : int64 list
        =
        only "deadlines" system |> ignore
        UnixWait.deadlines system

    /// The only process's threads asleep in a call (`ParkState.Asleep`).
    let asleep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Set<'Thread>
        =
        threads system
        |> Map.toSeq
        |> Seq.choose (fun (thread, state) ->
            match UnixThreadState.park state with
            | Some {
                       State = ParkState.Asleep
                   } -> Some thread
            | Some _
            | None -> None
        )
        |> Set.ofSeq

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

    // The library's functions that work on one process's view, which tests
    // call directly, each made in the view of the only process: they take the
    // system, focus it (`view`), and put back each view they answer
    // (`unview`). A test of a system holding several processes focuses one
    // through `Proc.view`.

    /// `WoofWare.PosixKernel.UnixSystemState`'s readers and writers, made in
    /// the view of the only process.
    [<RequireQualifiedAccess>]
    module UnixSystemState =
        /// The numbering the system's signals are read under: its machine's
        /// platform's, whichever process asks.
        let signalNumbering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (system : UnixSystem<'Thread, 'Handler>)
            : SignalNumbering
            =
            SimulatedUnixPlatform.signalNumbering system.Machine.UnixPlatform

        let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (system : UnixSystem<'Thread, 'Handler>)
            : FileDescriptorRegistry
            =
            fileDescriptors system

        let withFileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (registry : FileDescriptorRegistry)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            withFileDescriptors registry system

    /// `WoofWare.PosixKernel.Parking`'s parks, made in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module Parking =
        let park<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (parked : ParkedSyscall)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            view system |> WoofWare.PosixKernel.Parking.park thread parked |> unview

        let parkWaiting<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (parked : ParkedSyscall)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            view system |> WoofWare.PosixKernel.Parking.parkWaiting thread parked |> unview

    /// `WoofWare.PosixKernel.UnixParkState`, made in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module UnixParkState =
        let setPark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (park : ThreadPark)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            view system |> WoofWare.PosixKernel.UnixParkState.setPark thread park |> unview

        let unpark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            view system |> WoofWare.PosixKernel.UnixParkState.unpark thread |> unview

    /// `WoofWare.PosixKernel.WakeCondition`, asked in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module WakeCondition =
        let satisfied<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (condition : WakeCondition)
            (system : UnixSystem<'Thread, 'Handler>)
            : Set<WakePrimitive>
            =
            WoofWare.PosixKernel.WakeCondition.satisfied thread condition (view system)

    /// `WoofWare.PosixKernel.ObjectLifetime`, made in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module ObjectLifetime =
        let forgetIfUnheld<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (inode : InodeNumber)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            view system
            |> WoofWare.PosixKernel.ObjectLifetime.forgetIfUnheld inode
            |> unview

        let releaseUnreferencedUnrefusable<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (caller : string)
            (descriptions : OpenFileDescriptionId list)
            (system : UnixSystem<'Thread, 'Handler>)
            : UnixSystem<'Thread, 'Handler>
            =
            view system
            |> WoofWare.PosixKernel.ObjectLifetime.releaseUnreferencedUnrefusable caller descriptions
            |> unview

    /// `WoofWare.PosixKernel.EpollReadyList`, made in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module EpollReadyList =
        let drain<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (epollId : OpenFileDescriptionId)
            (maxCount : int)
            (system : UnixSystem<'Thread, 'Handler>)
            : (uint64 * uint32) list * UnixSystem<'Thread, 'Handler>
            =
            let events, after =
                WoofWare.PosixKernel.EpollReadyList.drain epollId maxCount (view system)

            events, unview after

        let hasDeliverableEvent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (epollId : OpenFileDescriptionId)
            (system : UnixSystem<'Thread, 'Handler>)
            : bool
            =
            WoofWare.PosixKernel.EpollReadyList.hasDeliverableEvent epollId (view system)

    /// `WoofWare.PosixKernel.LinuxReadiness`, read in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module LinuxReadiness =
        let ofDescription<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (targetId : OpenFileDescriptionId)
            (system : UnixSystem<'Thread, 'Handler>)
            : uint32
            =
            WoofWare.PosixKernel.LinuxReadiness.ofDescription targetId (view system)

    /// `answer`, with the view it holds put back.
    let private unviewed<'Answer, 'Thread, 'Handler, 'Refusal when 'Thread : comparison and 'Handler : equality>
        (answer : Result<'Answer * ProcessView<'Thread, 'Handler>, 'Refusal>)
        : Result<'Answer * UnixSystem<'Thread, 'Handler>, 'Refusal>
        =
        answer |> Result.map (fun (answer, after) -> answer, unview after)

    /// `WoofWare.PosixKernel.UnixConnection`'s steps, made in the view of the
    /// only process.
    [<RequireQualifiedAccess>]
    module UnixConnection =
        let acceptConnection<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (socketId : SocketId)
            (system : UnixSystem<'Thread, 'Handler>)
            : int * TcpConnection * UnixSystem<'Thread, 'Handler>
            =
            let fd, connection, after =
                WoofWare.PosixKernel.UnixConnection.acceptConnection socketId (view system)

            fd, connection, unview after

        let connectDecoded<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (socketId : SocketId)
            (nonBlocking : bool)
            (declaredLength : uint32)
            (address : ConnectAddress)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, ConnectRefusal>
            =
            WoofWare.PosixKernel.UnixConnection.connectDecoded socketId nonBlocking declaredLength address (view system)
            |> unviewed

        let connectSocket<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (socketId : SocketId)
            (nonBlocking : bool)
            (declaredLength : uint32)
            (copied : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, ConnectRefusal>
            =
            WoofWare.PosixKernel.UnixConnection.connectSocket socketId nonBlocking declaredLength copied (view system)
            |> unviewed

        let tryConnectBytes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (destination : UserBuffer)
            (declaredLength : uint32)
            (copied : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, ConnectRefusal>
            =
            WoofWare.PosixKernel.UnixConnection.tryConnectBytes fd destination declaredLength copied (view system)
            |> unviewed

    /// `WoofWare.PosixKernel.UnixDescriptor`'s steps, made in the view of the
    /// only process.
    [<RequireQualifiedAccess>]
    module UnixDescriptor =
        let truncateAt<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (through : ReachedThrough)
            (inode : InodeNumber)
            (length : int64)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<UnixSystem<'Thread, 'Handler>, TruncationRefusal>
            =
            WoofWare.PosixKernel.UnixDescriptor.truncateAt through inode length (view system)
            |> Result.map unview

    /// `WoofWare.PosixKernel.UnixNamespace`'s steps after the path is copied
    /// in, made in the view of the only process.
    [<RequireQualifiedAccess>]
    module UnixNamespace =
        let mkdirParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (path : UnixPath)
            (mode : int)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, PathRefusal>
            =
            WoofWare.PosixKernel.UnixNamespace.mkdirParsed directory path mode (view system)
            |> unviewed

        let openPathParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (flags : OpenFlags)
            (path : UnixPath)
            (mode : int)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, OpenRefusal>
            =
            WoofWare.PosixKernel.UnixNamespace.openPathParsed directory flags path mode (view system)
            |> unviewed

        let readlinkParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (path : UnixPath)
            (destination : UserBuffer)
            (capacity : int)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<ReadLinkAnswer, ReadLinkRefusal>
            =
            WoofWare.PosixKernel.UnixNamespace.readlinkParsed directory path destination capacity (view system)

        let rmdirParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RemovalRefusal>
            =
            WoofWare.PosixKernel.UnixNamespace.rmdirParsed directory path (view system)
            |> unviewed

        let unlinkParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, RemovalRefusal>
            =
            WoofWare.PosixKernel.UnixNamespace.unlinkParsed directory path (view system)
            |> unviewed

    /// `WoofWare.PosixKernel.UnixPathResolution`'s walks and steps after the
    /// path is copied in, made in the view of the only process.
    [<RequireQualifiedAccess>]
    module UnixPathResolution =
        let chdirParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, PathRefusal>
            =
            WoofWare.PosixKernel.UnixPathResolution.chdirParsed path (view system)
            |> unviewed

        let chmodParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (policy : SymlinkPolicy)
            (path : UnixPath)
            (mode : int)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, ChModRefusal>
            =
            WoofWare.PosixKernel.UnixPathResolution.chmodParsed directory policy path mode (view system)
            |> unviewed

        let chownParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (policy : SymlinkPolicy)
            (path : UnixPath)
            (user : UserId option)
            (group : GroupId option)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, ChOwnRefusal>
            =
            WoofWare.PosixKernel.UnixPathResolution.chownParsed directory policy path user group (view system)
            |> unviewed

        let copyIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (argument : PathArgumentBytes)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<UnixPath, UnixError>
            =
            WoofWare.PosixKernel.UnixPathResolution.copyIn argument (view system)

        let resolvePath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (policy : SymlinkPolicy)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<InodeNumber, PathFailure>
            =
            WoofWare.PosixKernel.UnixPathResolution.resolvePath directory policy path (view system)

        let resolvePathFull<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (policy : SymlinkPolicy)
            (trailingSeparatorPolicy : TrailingSeparatorPolicy)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<Resolution, PathFailure>
            =
            WoofWare.PosixKernel.UnixPathResolution.resolvePathFull
                directory
                policy
                trailingSeparatorPolicy
                path
                (view system)

        let resolvePathParent<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (policy : SymlinkPolicy)
            (trailingSeparatorPolicy : TrailingSeparatorPolicy)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<PausedResolution, PathFailure>
            =
            WoofWare.PosixKernel.UnixPathResolution.resolvePathParent
                directory
                policy
                trailingSeparatorPolicy
                path
                (view system)

        let statOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (inode : InodeNumber)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<FileStatus, StatRefusal> option
            =
            WoofWare.PosixKernel.UnixPathResolution.statOf inode (view system)

        let statParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (policy : SymlinkPolicy)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<FileStatusAnswer, StatRefusal>
            =
            WoofWare.PosixKernel.UnixPathResolution.statParsed directory policy path (view system)

        let statfsParsed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<FileSystemStatisticsAnswer, PathRefusal>
            =
            WoofWare.PosixKernel.UnixPathResolution.statfsParsed path (view system)

        let walkStart<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (directory : AtDirectory)
            (path : UnixPath)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<InodeNumber, UnixError>
            =
            WoofWare.PosixKernel.UnixPathResolution.walkStart directory path (view system)

    /// `answer`, with the view the step holds put back.
    let private unviewedStep<'Answer, 'Thread, 'Handler, 'Refusal when 'Thread : comparison and 'Handler : equality>
        (answer : Result<WriteStep<'Answer, ProcessView<'Thread, 'Handler>, 'Thread>, 'Refusal>)
        : Result<WriteStep<'Answer, UnixSystem<'Thread, 'Handler>, 'Thread>, 'Refusal>
        =
        answer |> Result.map (WriteStep.map unfocus)

    /// `WoofWare.PosixKernel.UnixReadWrite`'s steps either side of the copy,
    /// made in the view of the only process.
    [<RequireQualifiedAccess>]
    module UnixReadWrite =
        let tryAdmitWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (fd : int)
            (buffer : UserBuffer)
            (count : uint64)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteStep<WriteAdmission, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryAdmitWrite thread fd buffer count (view system)
            |> unviewedStep

        let tryAdmitSend<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (fd : int)
            (buffer : UserBuffer)
            (count : uint64)
            (flags : int)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteStep<WriteAdmission, UnixSystem<'Thread, 'Handler>, 'Thread>, SendRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryAdmitSend thread fd buffer count flags (view system)
            |> unviewedStep

        let tryAdmitFinishWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteStep<WriteResumption, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryAdmitFinishWrite thread (view system)
            |> unviewedStep

        let tryAdmitPWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (buffer : UserBuffer)
            (count : uint64)
            (offset : int64)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<PWriteAdmission, PWriteRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryAdmitPWrite fd buffer count offset (view system)

        let tryApplyPWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (offset : int64)
            (into : PWriteInto)
            (bytes : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteAnswer * UnixSystem<'Thread, 'Handler>, PWriteRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryApplyPWrite fd offset into bytes (view system)
            |> unviewed

        let tryApplyResumedWrite<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (into : WriteResumed)
            (bytes : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryApplyResumedWrite thread into bytes (view system)
            |> unviewedStep

        let tryApplySend<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (into : WriteInto)
            (bytes : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, SendRefusal>
            =
            WoofWare.PosixKernel.UnixReadWrite.tryApplySend into bytes (view system)
            |> unviewedStep

        /// `tryApplyWrite` of a `write` through `fd`, marked as a `write`
        /// is (`UnixReadWrite.markedThrough`).
        let tryApplyWriteThrough<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (into : WriteInto)
            (bytes : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>, WriteRefusal>
            =
            let before = view system

            WoofWare.PosixKernel.UnixReadWrite.tryApplyWrite into bytes before
            |> Result.map (WoofWare.PosixKernel.UnixReadWrite.markedThrough fd before)
            |> unviewedStep

        /// `applyWriteThenSleep` of a `write` through `fd`, marked as a
        /// `write` is (`UnixReadWrite.markedThrough`).
        let applyWriteThenSleepThrough<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (fd : int)
            (total : int)
            (into : WriteIntoThenSleep)
            (bytes : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>
            =
            let before = view system

            WoofWare.PosixKernel.UnixReadWrite.applyWriteThenSleep thread total into bytes before
            |> WoofWare.PosixKernel.UnixReadWrite.markedThrough fd before
            |> WriteStep.map unfocus

        /// `applyWriteThenSleep`, unmarked, as a `send` makes it.
        let applyWriteThenSleep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (thread : 'Thread)
            (total : int)
            (into : WriteIntoThenSleep)
            (bytes : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : WriteStep<WriteAnswer, UnixSystem<'Thread, 'Handler>, 'Thread>
            =
            WoofWare.PosixKernel.UnixReadWrite.applyWriteThenSleep thread total into bytes (view system)
            |> WriteStep.map unfocus

    /// `WoofWare.PosixKernel.UnixSocket`'s steps either side of the copy,
    /// made in the view of the only process.
    [<RequireQualifiedAccess>]
    module UnixSocket =
        let bindDecoded<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (declaredLength : uint32)
            (copied : CopiedInternetSockaddr)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<BindAnswer * UnixSystem<'Thread, 'Handler>, BindRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.bindDecoded fd declaredLength copied (view system)
            |> unviewed

        let tryAdmitGetSockOpt<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (level : int)
            (optionName : int)
            (value : UserBuffer)
            (length : UserBuffer)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<GetSockOptAdmission, SocketOptionRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.tryAdmitGetSockOpt fd level optionName value length (view system)

        let tryAdmitSetSockOpt<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (level : int)
            (optionName : int)
            (value : UserBuffer)
            (optionLength : uint32)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SetSockOptAdmission, SocketOptionRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.tryAdmitSetSockOpt fd level optionName value optionLength (view system)

        let tryAdmitSockaddrCopy<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (syscall : SockaddrCopySyscall)
            (fd : int)
            (destination : UserBuffer)
            (declaredLength : uint32)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SockaddrCopyAdmission, SockaddrCopyRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.tryAdmitSockaddrCopy syscall fd destination declaredLength (view system)

        let tryBindBytes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (destination : UserBuffer)
            (declaredLength : uint32)
            (copied : System.Collections.Immutable.ImmutableArray<byte>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<BindAnswer * UnixSystem<'Thread, 'Handler>, BindRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.tryBindBytes fd destination declaredLength copied (view system)
            |> unviewed

        let tryGetsockoptLength<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (level : int)
            (optionName : int)
            (value : UserBuffer)
            (length : UserBuffer)
            (declaredLength : uint32 option)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<GetSockOptAnswer * UnixSystem<'Thread, 'Handler>, SocketOptionRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.tryGetsockoptLength
                fd
                level
                optionName
                value
                length
                declaredLength
                (view system)
            |> unviewed

        let trySetsockoptBytes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (fd : int)
            (level : int)
            (optionName : int)
            (value : UserBuffer)
            (optionLength : uint32)
            (supplied : System.Collections.Immutable.ImmutableArray<byte> option)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<SetSockOptAnswer * UnixSystem<'Thread, 'Handler>, SocketOptionRefusal>
            =
            WoofWare.PosixKernel.UnixSocket.trySetsockoptBytes
                fd
                level
                optionName
                value
                optionLength
                supplied
                (view system)
            |> unviewed

    /// `WoofWare.PosixKernel.ProcessSignal`, made in the view of the only
    /// process.
    [<RequireQualifiedAccess>]
    module ProcessSignal =
        let generate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (entry : PendingSignal<'Thread>)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<Result<ProcessFate<KillOutcome, 'Thread, 'Handler>, ProcessEndRefusal>, SignalReceiverRefusal>
            =
            WoofWare.PosixKernel.ProcessSignal.generate entry (view system)
            |> Result.map (Result.map (Shape.map unfocus Shape.fate))

    /// `WoofWare.PosixKernel.UnixThreadLifecycle`, made in the view of the
    /// only process.
    [<RequireQualifiedAccess>]
    module UnixThreadLifecycle =
        let tryEndProcess<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
            (termination : ProcessTermination)
            (system : UnixSystem<'Thread, 'Handler>)
            : Result<EndedProcess * UnixSystem<'Thread, 'Handler>, ProcessEndRefusal>
            =
            WoofWare.PosixKernel.UnixThreadLifecycle.tryEndProcess termination (view system)
            |> Shape.map unfocus (Shape.result Shape.ended)
