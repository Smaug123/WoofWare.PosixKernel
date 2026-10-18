namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// Why this kernel will not answer a syscall `UnixSystem.step` was asked to
/// make: the refusal of the call's own function, named for the call's
/// `Syscall` case, or a reserved call, which this library does not model yet.
/// The client decides what a refusal means for it; nothing here is recoverable
/// by retrying.
[<RequireQualifiedAccess>]
type internal SyscallRefusal<'Thread> =
    | Dup of DescriptorLimitRefusal
    | Dup2 of Dup2Refusal<'Thread>
    | Dup3 of Dup3Refusal<'Thread>
    | Fcntl of FcntlRefusal
    | LSeek of LSeekRefusal
    | FLock of FLockRefusal
    | FTruncate of TruncationRefusal
    | PosixFAdvise of PosixFadviseRefusal
    | Close of CloseRefusal<'Thread>
    | BytesAvailable of BytesAvailableRefusal
    | FileClone of FileCloneRefusal
    | GetGroups of GetGroupsRefusal
    | Stat of StatRefusal
    | FStat of FStatRefusal
    | FStatAt of FStatAtRefusal
    | ChMod of ChModRefusal
    | FChMod of FChModRefusal
    | FChModAt of FChModAtRefusal
    | ChOwn of ChOwnRefusal
    | LChOwn of ChOwnRefusal
    | FChOwn of FChOwnRefusal
    | FChOwnAt of FChOwnAtRefusal
    | UTimensAt of UTimensAtRefusal
    | StatFs of PathRefusal
    | GetCwd of GetCwdRefusal
    | ChDir of PathRefusal
    | Access of AccessRefusal
    | FAccessAt of AccessRefusal
    | Open of OpenRefusal
    | OpenAt of OpenRefusal
    | ReadLink of ReadLinkRefusal
    | ReadLinkAt of ReadLinkRefusal
    | ReadDirectoryEntry of ReadDirectoryRefusal
    | MkDir of PathRefusal
    | MkDirAt of PathRefusal
    | MkNod of MkNodRefusal
    | MkNodAt of MkNodRefusal
    | Unlink of RemovalRefusal
    | RmDir of RemovalRefusal
    | UnlinkAt of UnlinkAtRefusal
    | Rename of RenameRefusal
    | RenameAt of RenameRefusal
    | CloneFile of CloneFileRefusal
    | Symlink of SymlinkRefusal
    | SymlinkAt of SymlinkRefusal
    | Link of LinkRefusal
    | LinkAt of LinkRefusal
    | Read of ReadRefusal
    | Recv of ReceiveRefusal
    | PRead of PReadRefusal
    | Write of WriteRefusal
    | Send of SendRefusal
    | PWrite of PWriteRefusal
    | CopyFileRange of CopyFileRangeRefusal
    | Pipe2 of Pipe2Refusal
    | Socket of SocketRefusal
    | Bind of BindRefusal
    | Connect of ConnectRefusal
    | Listen of ListenRefusal
    | Accept of AcceptRefusal
    | Shutdown of ShutdownRefusal
    | GetSockName of GetSockNameRefusal
    | GetPeerName of GetSockNameRefusal
    | SetSockOpt of SocketOptionRefusal
    | GetSockOpt of SocketOptionRefusal
    | Poll of PollRefusal
    | EpollCreate1 of EpollCreateRefusal
    | EpollCtl of EpollCtlRefusal
    | EpollWait of EpollWaitRefusal
    | Kqueue of KqueueRefusal
    | Kevent of KeventRefusal
    | InotifyInit1 of InotifyRefusal
    | InotifyAddWatch of InotifyAddWatchRefusal
    | InotifyRmWatch of InotifyRefusal
    | Kill of KillRefusal
    | PthreadKill of ThreadKillRefusal
    | SigProcMask of SigprocmaskRefusal<'Thread>
    | SigSuspend of SigsuspendRefusal
    | RtSigSuspend of SigsuspendRefusal
    | Pause of SigsuspendRefusal
    | ClockGetTime of ClockGettimeRefusal
    | GetRandom of GetRandomRefusal
    | GetEntropy of GetEntropyRefusal
    | GetResUid of GetIdsRefusal
    | GetResGid of GetIdsRefusal
    | SetResUid of SetIdsRefusal
    | SetResGid of SetIdsRefusal
    | SetGroups of SetGroupsRefusal
    | Spawn of SpawnRefusal<'Thread>
    | ExitThread of ThreadExitRefusal<'Thread>
    | ExitGroup of ProcessEndRefusal
    | GetCpu of GetCpuRefusal
    | Futex of FutexRefusal
    /// The call is `call`, a reserved case: this library does not model the
    /// call it names yet.
    | Reserved of call : string

[<RequireQualifiedAccess>]
module internal SyscallRefusal =
    /// What this kernel knows about why it cannot answer, after the name of
    /// the syscall it refused. The client supplies its own half: which thread
    /// made the call.
    let describe<'Thread> (refusal : SyscallRefusal<'Thread>) : string =
        match refusal with
        | SyscallRefusal.Dup refusal -> $"dup: %s{DescriptorLimitRefusal.describe refusal}"
        | SyscallRefusal.Dup2 refusal -> $"dup2: %s{Dup2Refusal.describe refusal}"
        | SyscallRefusal.Dup3 refusal -> $"dup3: %s{Dup3Refusal.describe refusal}"
        | SyscallRefusal.Fcntl refusal -> $"fcntl: %s{FcntlRefusal.describe refusal}"
        | SyscallRefusal.LSeek refusal -> $"lseek: %s{LSeekRefusal.describe refusal}"
        | SyscallRefusal.FLock refusal -> $"flock: %s{FLockRefusal.describe refusal}"
        | SyscallRefusal.FTruncate refusal -> $"ftruncate: %s{TruncationRefusal.describe refusal}"
        | SyscallRefusal.PosixFAdvise refusal -> $"posix_fadvise: %s{PosixFadviseRefusal.describe refusal}"
        | SyscallRefusal.Close refusal -> $"close: %s{CloseRefusal.describe refusal}"
        | SyscallRefusal.BytesAvailable refusal -> $"ioctl(FIONREAD): %s{BytesAvailableRefusal.describe refusal}"
        | SyscallRefusal.FileClone refusal -> $"ioctl(FICLONE): %s{FileCloneRefusal.describe refusal}"
        | SyscallRefusal.GetGroups refusal -> $"getgroups: %s{GetGroupsRefusal.describe refusal}"
        | SyscallRefusal.Stat refusal -> $"stat: %s{StatRefusal.describe refusal}"
        | SyscallRefusal.FStat refusal -> $"fstat: %s{FStatRefusal.describe refusal}"
        | SyscallRefusal.FStatAt refusal -> $"fstatat: %s{FStatAtRefusal.describe refusal}"
        | SyscallRefusal.ChMod refusal -> $"chmod: %s{ChModRefusal.describe refusal}"
        | SyscallRefusal.FChMod refusal -> $"fchmod: %s{FChModRefusal.describe refusal}"
        | SyscallRefusal.FChModAt refusal -> $"fchmodat: %s{FChModAtRefusal.describe refusal}"
        | SyscallRefusal.ChOwn refusal -> $"chown: %s{ChOwnRefusal.describe refusal}"
        | SyscallRefusal.LChOwn refusal -> $"lchown: %s{ChOwnRefusal.describe refusal}"
        | SyscallRefusal.FChOwn refusal -> $"fchown: %s{FChOwnRefusal.describe refusal}"
        | SyscallRefusal.FChOwnAt refusal -> $"fchownat: %s{FChOwnAtRefusal.describe refusal}"
        | SyscallRefusal.UTimensAt refusal -> $"utimensat: %s{UTimensAtRefusal.describe refusal}"
        | SyscallRefusal.StatFs refusal -> $"statfs: %s{PathRefusal.describe refusal}"
        | SyscallRefusal.GetCwd refusal -> $"getcwd: %s{GetCwdRefusal.describe refusal}"
        | SyscallRefusal.ChDir refusal -> $"chdir: %s{PathRefusal.describe refusal}"
        | SyscallRefusal.Access refusal -> $"access: %s{AccessRefusal.describe refusal}"
        | SyscallRefusal.FAccessAt refusal -> $"faccessat: %s{AccessRefusal.describe refusal}"
        | SyscallRefusal.Open refusal -> $"open: %s{OpenRefusal.describe refusal}"
        | SyscallRefusal.OpenAt refusal -> $"openat: %s{OpenRefusal.describe refusal}"
        | SyscallRefusal.ReadLink refusal -> $"readlink: %s{ReadLinkRefusal.describe refusal}"
        | SyscallRefusal.ReadLinkAt refusal -> $"readlinkat: %s{ReadLinkRefusal.describe refusal}"
        | SyscallRefusal.ReadDirectoryEntry refusal ->
            $"getdents or getdirentries: %s{ReadDirectoryRefusal.describe refusal}"
        | SyscallRefusal.MkDir refusal -> $"mkdir: %s{PathRefusal.describe refusal}"
        | SyscallRefusal.MkDirAt refusal -> $"mkdirat: %s{PathRefusal.describe refusal}"
        | SyscallRefusal.MkNod refusal -> $"mknod: %s{MkNodRefusal.describe refusal}"
        | SyscallRefusal.MkNodAt refusal -> $"mknodat: %s{MkNodRefusal.describe refusal}"
        | SyscallRefusal.Unlink refusal -> $"unlink: %s{RemovalRefusal.describe refusal}"
        | SyscallRefusal.RmDir refusal -> $"rmdir: %s{RemovalRefusal.describe refusal}"
        | SyscallRefusal.UnlinkAt refusal -> $"unlinkat: %s{UnlinkAtRefusal.describe refusal}"
        | SyscallRefusal.Rename refusal -> $"rename: %s{RenameRefusal.describe refusal}"
        | SyscallRefusal.RenameAt refusal -> $"renameat: %s{RenameRefusal.describe refusal}"
        | SyscallRefusal.CloneFile refusal -> $"clonefile: %s{CloneFileRefusal.describe refusal}"
        | SyscallRefusal.Symlink refusal -> $"symlink: %s{SymlinkRefusal.describe refusal}"
        | SyscallRefusal.SymlinkAt refusal -> $"symlinkat: %s{SymlinkRefusal.describe refusal}"
        | SyscallRefusal.Link refusal -> $"link: %s{LinkRefusal.describe refusal}"
        | SyscallRefusal.LinkAt refusal -> $"linkat: %s{LinkRefusal.describe refusal}"
        | SyscallRefusal.Read refusal -> $"read: %s{ReadRefusal.describe refusal}"
        | SyscallRefusal.Recv refusal -> $"recv: %s{ReceiveRefusal.describe refusal}"
        | SyscallRefusal.PRead refusal -> $"pread: %s{PReadRefusal.describe refusal}"
        | SyscallRefusal.Write refusal -> $"write: %s{WriteRefusal.describe refusal}"
        | SyscallRefusal.Send refusal -> $"send: %s{SendRefusal.describe refusal}"
        | SyscallRefusal.PWrite refusal -> $"pwrite: %s{PWriteRefusal.describe refusal}"
        | SyscallRefusal.CopyFileRange refusal -> $"copy_file_range: %s{CopyFileRangeRefusal.describe refusal}"
        | SyscallRefusal.Pipe2 refusal -> $"pipe2: %s{Pipe2Refusal.describe refusal}"
        | SyscallRefusal.Socket refusal -> $"socket: %s{SocketRefusal.describe refusal}"
        | SyscallRefusal.Bind refusal -> $"bind: %s{BindRefusal.describe refusal}"
        | SyscallRefusal.Connect refusal -> $"connect: %s{ConnectRefusal.describe refusal}"
        | SyscallRefusal.Listen refusal -> $"listen: %s{ListenRefusal.describe refusal}"
        | SyscallRefusal.Accept refusal -> $"accept: %s{AcceptRefusal.describe refusal}"
        | SyscallRefusal.Shutdown refusal -> $"shutdown: %s{ShutdownRefusal.describe refusal}"
        | SyscallRefusal.GetSockName refusal -> $"getsockname: %s{GetSockNameRefusal.describe refusal}"
        | SyscallRefusal.GetPeerName refusal -> $"getpeername: %s{GetSockNameRefusal.describe refusal}"
        | SyscallRefusal.SetSockOpt refusal -> $"setsockopt: %s{SocketOptionRefusal.describe refusal}"
        | SyscallRefusal.GetSockOpt refusal -> $"getsockopt: %s{SocketOptionRefusal.describe refusal}"
        | SyscallRefusal.Poll refusal -> $"poll: %s{PollRefusal.describe refusal}"
        | SyscallRefusal.EpollCreate1 refusal -> $"epoll_create1: %s{EpollCreateRefusal.describe refusal}"
        | SyscallRefusal.EpollCtl refusal -> $"epoll_ctl: %s{EpollCtlRefusal.describe refusal}"
        | SyscallRefusal.EpollWait refusal -> $"epoll_wait: %s{EpollWaitRefusal.describe refusal}"
        | SyscallRefusal.Kqueue refusal -> $"kqueue: %s{KqueueRefusal.describe refusal}"
        | SyscallRefusal.Kevent refusal -> $"kevent: %s{KeventRefusal.describe refusal}"
        | SyscallRefusal.InotifyInit1 refusal -> $"inotify_init1: %s{InotifyRefusal.describe refusal}"
        | SyscallRefusal.InotifyAddWatch refusal -> $"inotify_add_watch: %s{InotifyAddWatchRefusal.describe refusal}"
        | SyscallRefusal.InotifyRmWatch refusal -> $"inotify_rm_watch: %s{InotifyRefusal.describe refusal}"
        | SyscallRefusal.Kill refusal -> $"kill: %s{KillRefusal.describe refusal}"
        | SyscallRefusal.PthreadKill refusal -> $"pthread_kill: %s{ThreadKillRefusal.describe refusal}"
        | SyscallRefusal.SigProcMask refusal -> $"sigprocmask: %s{SigprocmaskRefusal.describe refusal}"
        | SyscallRefusal.SigSuspend refusal -> $"sigsuspend: %s{SigsuspendRefusal.describe refusal}"
        | SyscallRefusal.RtSigSuspend refusal -> $"rt_sigsuspend: %s{SigsuspendRefusal.describe refusal}"
        | SyscallRefusal.Pause refusal -> $"pause: %s{SigsuspendRefusal.describe refusal}"
        | SyscallRefusal.ClockGetTime refusal -> $"clock_gettime: %s{ClockGettimeRefusal.describe refusal}"
        | SyscallRefusal.GetRandom refusal -> $"getrandom: %s{GetRandomRefusal.describe refusal}"
        | SyscallRefusal.GetEntropy refusal -> $"getentropy: %s{GetEntropyRefusal.describe refusal}"
        | SyscallRefusal.GetResUid refusal -> $"getresuid: %s{GetIdsRefusal.describe refusal}"
        | SyscallRefusal.GetResGid refusal -> $"getresgid: %s{GetIdsRefusal.describe refusal}"
        | SyscallRefusal.SetResUid refusal -> $"setresuid: %s{SetIdsRefusal.describe refusal}"
        | SyscallRefusal.SetResGid refusal -> $"setresgid: %s{SetIdsRefusal.describe refusal}"
        | SyscallRefusal.SetGroups refusal -> $"setgroups: %s{SetGroupsRefusal.describe refusal}"
        | SyscallRefusal.Spawn refusal -> $"clone(CLONE_THREAD): %s{SpawnRefusal.describe refusal}"
        | SyscallRefusal.ExitThread refusal -> $"exit: %s{ThreadExitRefusal.describe refusal}"
        | SyscallRefusal.ExitGroup refusal -> $"exit_group: %s{ProcessEndRefusal.describe refusal}"
        | SyscallRefusal.GetCpu refusal -> $"getcpu: %s{GetCpuRefusal.describe refusal}"
        | SyscallRefusal.Futex refusal -> $"futex: %s{FutexRefusal.describe refusal}"
        | SyscallRefusal.Reserved call ->
            $"%s{call} is a reserved case: this library does not model the call it names yet, and nothing makes one."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SyscallRefusal<'Thread>) : RefusalKind =
        match refusal with
        | SyscallRefusal.Dup _ -> RefusalKind.Unmodelled
        | SyscallRefusal.Dup2 inner -> Dup2Refusal.kind inner
        | SyscallRefusal.Dup3 inner -> Dup3Refusal.kind inner
        | SyscallRefusal.Fcntl inner -> FcntlRefusal.kind inner
        | SyscallRefusal.LSeek inner -> LSeekRefusal.kind inner
        | SyscallRefusal.FLock inner -> FLockRefusal.kind inner
        | SyscallRefusal.FTruncate inner -> TruncationRefusal.kind inner
        | SyscallRefusal.PosixFAdvise inner -> PosixFadviseRefusal.kind inner
        | SyscallRefusal.Close inner -> CloseRefusal.kind inner
        | SyscallRefusal.BytesAvailable inner -> BytesAvailableRefusal.kind inner
        | SyscallRefusal.FileClone inner -> FileCloneRefusal.kind inner
        | SyscallRefusal.GetGroups inner -> GetGroupsRefusal.kind inner
        | SyscallRefusal.Stat inner -> StatRefusal.kind inner
        | SyscallRefusal.FStat inner -> FStatRefusal.kind inner
        | SyscallRefusal.FStatAt inner -> FStatAtRefusal.kind inner
        | SyscallRefusal.ChMod inner -> ChModRefusal.kind inner
        | SyscallRefusal.FChMod inner -> FChModRefusal.kind inner
        | SyscallRefusal.FChModAt inner -> FChModAtRefusal.kind inner
        | SyscallRefusal.ChOwn inner -> ChOwnRefusal.kind inner
        | SyscallRefusal.LChOwn inner -> ChOwnRefusal.kind inner
        | SyscallRefusal.FChOwn inner -> FChOwnRefusal.kind inner
        | SyscallRefusal.FChOwnAt inner -> FChOwnAtRefusal.kind inner
        | SyscallRefusal.UTimensAt inner -> UTimensAtRefusal.kind inner
        | SyscallRefusal.StatFs inner -> PathRefusal.kind inner
        | SyscallRefusal.GetCwd inner -> GetCwdRefusal.kind inner
        | SyscallRefusal.ChDir inner -> PathRefusal.kind inner
        | SyscallRefusal.Access inner -> AccessRefusal.kind inner
        | SyscallRefusal.FAccessAt inner -> AccessRefusal.kind inner
        | SyscallRefusal.Open inner -> OpenRefusal.kind inner
        | SyscallRefusal.OpenAt inner -> OpenRefusal.kind inner
        | SyscallRefusal.ReadLink inner -> ReadLinkRefusal.kind inner
        | SyscallRefusal.ReadLinkAt inner -> ReadLinkRefusal.kind inner
        | SyscallRefusal.ReadDirectoryEntry inner -> ReadDirectoryRefusal.kind inner
        | SyscallRefusal.MkDir inner -> PathRefusal.kind inner
        | SyscallRefusal.MkDirAt inner -> PathRefusal.kind inner
        | SyscallRefusal.MkNod inner -> MkNodRefusal.kind inner
        | SyscallRefusal.MkNodAt inner -> MkNodRefusal.kind inner
        | SyscallRefusal.Unlink inner -> RemovalRefusal.kind inner
        | SyscallRefusal.RmDir inner -> RemovalRefusal.kind inner
        | SyscallRefusal.UnlinkAt inner -> UnlinkAtRefusal.kind inner
        | SyscallRefusal.Rename inner -> RenameRefusal.kind inner
        | SyscallRefusal.RenameAt inner -> RenameRefusal.kind inner
        | SyscallRefusal.CloneFile inner -> CloneFileRefusal.kind inner
        | SyscallRefusal.Symlink inner -> SymlinkRefusal.kind inner
        | SyscallRefusal.SymlinkAt inner -> SymlinkRefusal.kind inner
        | SyscallRefusal.Link inner -> LinkRefusal.kind inner
        | SyscallRefusal.LinkAt inner -> LinkRefusal.kind inner
        | SyscallRefusal.Read inner -> ReadRefusal.kind inner
        | SyscallRefusal.Recv inner -> ReceiveRefusal.kind inner
        | SyscallRefusal.PRead inner -> PReadRefusal.kind inner
        | SyscallRefusal.Write inner -> WriteRefusal.kind inner
        | SyscallRefusal.Send inner -> SendRefusal.kind inner
        | SyscallRefusal.PWrite inner -> PWriteRefusal.kind inner
        | SyscallRefusal.CopyFileRange inner -> CopyFileRangeRefusal.kind inner
        | SyscallRefusal.Pipe2 inner -> Pipe2Refusal.kind inner
        | SyscallRefusal.Socket inner -> SocketRefusal.kind inner
        | SyscallRefusal.Bind inner -> BindRefusal.kind inner
        | SyscallRefusal.Connect inner -> ConnectRefusal.kind inner
        | SyscallRefusal.Listen inner -> ListenRefusal.kind inner
        | SyscallRefusal.Accept inner -> AcceptRefusal.kind inner
        | SyscallRefusal.Shutdown inner -> ShutdownRefusal.kind inner
        | SyscallRefusal.GetSockName inner -> GetSockNameRefusal.kind inner
        | SyscallRefusal.GetPeerName inner -> GetSockNameRefusal.kind inner
        | SyscallRefusal.SetSockOpt inner -> SocketOptionRefusal.kind inner
        | SyscallRefusal.GetSockOpt inner -> SocketOptionRefusal.kind inner
        | SyscallRefusal.Poll inner -> PollRefusal.kind inner
        | SyscallRefusal.EpollCreate1 inner -> EpollCreateRefusal.kind inner
        | SyscallRefusal.EpollCtl inner -> EpollCtlRefusal.kind inner
        | SyscallRefusal.EpollWait inner -> EpollWaitRefusal.kind inner
        | SyscallRefusal.Kqueue inner -> KqueueRefusal.kind inner
        | SyscallRefusal.Kevent inner -> KeventRefusal.kind inner
        | SyscallRefusal.InotifyInit1 inner -> InotifyRefusal.kind inner
        | SyscallRefusal.InotifyAddWatch inner -> InotifyAddWatchRefusal.kind inner
        | SyscallRefusal.InotifyRmWatch inner -> InotifyRefusal.kind inner
        | SyscallRefusal.Kill inner -> KillRefusal.kind inner
        | SyscallRefusal.PthreadKill inner -> ThreadKillRefusal.kind inner
        | SyscallRefusal.SigProcMask inner -> SigprocmaskRefusal.kind inner
        | SyscallRefusal.SigSuspend inner -> SigsuspendRefusal.kind inner
        | SyscallRefusal.RtSigSuspend inner -> SigsuspendRefusal.kind inner
        | SyscallRefusal.Pause inner -> SigsuspendRefusal.kind inner
        | SyscallRefusal.ClockGetTime inner -> ClockGettimeRefusal.kind inner
        | SyscallRefusal.GetRandom inner -> GetRandomRefusal.kind inner
        | SyscallRefusal.GetEntropy inner -> GetEntropyRefusal.kind inner
        | SyscallRefusal.GetResUid inner -> GetIdsRefusal.kind inner
        | SyscallRefusal.GetResGid inner -> GetIdsRefusal.kind inner
        | SyscallRefusal.SetResUid inner -> SetIdsRefusal.kind inner
        | SyscallRefusal.SetResGid inner -> SetIdsRefusal.kind inner
        | SyscallRefusal.SetGroups inner -> SetGroupsRefusal.kind inner
        | SyscallRefusal.Spawn inner -> SpawnRefusal.kind inner
        | SyscallRefusal.ExitThread inner -> ThreadExitRefusal.kind inner
        | SyscallRefusal.ExitGroup inner -> ProcessEndRefusal.kind inner
        | SyscallRefusal.GetCpu inner -> GetCpuRefusal.kind inner
        | SyscallRefusal.Futex inner -> FutexRefusal.kind inner
        | SyscallRefusal.Reserved _ -> RefusalKind.Unmodelled

/// A way this system's tables disagree with each other — a state no kernel
/// could be in, and which the operations here exist to keep unreachable.
/// `UnixSystem.checkInvariants` returns these.
///
/// Separate from `VirtualFileSystemDefect` because every case here is a claim
/// about *two* tables at once, which that module cannot see: it is defined in
/// a file that compiles before this one. A descriptor table's own defects are
/// reported inside one of these.
///
/// Some cases concern the machine, and read facts that every process on it
/// contributes to; the rest concern one process, and name it, or the thread
/// they concern by its `Caller`.
///
/// A defect is a bug in this library, and its cases are not public: a client
/// reports one with `UnixSystemDefect.describe`, and has no reason to branch on
/// which rule broke. Any version may add a rule or remove one, for instance
/// when the types come to make a state it forbids unrepresentable.
[<RequireQualifiedAccess>]
type UnixSystemDefect<'Thread> =
    internal
    /// A live open file description names a socket the socket table does not
    /// hold, so resolving that descriptor would fail.
    | DanglingSocket of description : OpenFileDescriptionId * socket : SocketId
    /// The socket table holds a socket no live description names.
    ///
    /// A leak, and deliberately a defect rather than a tolerated state: every
    /// way to make a socket — `UnixSocket.socket`, or `UnixConnection.accept`
    /// materialising a queued connection — hands back a descriptor at once,
    /// so an unreferenced socket means a close forgot to clean up. A
    /// connection awaiting accept is held on its listener's queue, not as a
    /// socket, which is what lets this rule stay strict.
    | UnreferencedSocket of socket : SocketId
    /// A socket in the table has an identity at or above the next one to
    /// allocate, so a future `socket(2)` would mint a duplicate.
    | NextSocketIdNotFresh of nextSocketId : SocketId * existing : SocketId
    /// `CurrentDirectoryInode` names something the filesystem does not hold, or
    /// holds as something other than a directory — so every relative path a
    /// process passes would resolve from a place that is not a directory.
    ///
    /// Deliberately *not* "the inode is reachable from the root": a real process
    /// keeps its current directory alive after the last name for it has gone,
    /// and the held inode is what expresses that.
    | CurrentDirectoryIsNotADirectory of processId : ProcessId * inode : InodeNumber
    /// A live open file description names an inode the filesystem does not
    /// hold, so reading or `fstat`ing that descriptor would fail.
    ///
    /// The mirror image of `VirtualFileSystemDefect.UnreachableFromRoot`: that
    /// one catches an orphan nothing holds, and this one catches an inode freed
    /// while something still held it. Between them they bracket the reaping
    /// rule, so an inode freed too late is caught there and one freed too
    /// early is caught here.
    | DanglingOpenInode of description : OpenFileDescriptionId * inode : InodeNumber
    /// A description names an inode as the wrong kind of object: a
    /// `OpenFileTarget.File` onto a directory or a device, an
    /// `OpenFileTarget.Directory` onto anything but a directory, or an
    /// `OpenFileTarget.CharacterDevice` onto anything but the node of the device
    /// it names, or an `OpenFileTarget.Fifo` onto anything but a FIFO. `open` chooses the target by what it opened, so a directory's
    /// position is always a place in its entries and never a byte offset, and a
    /// device's operations are the driver's own.
    | DescriptionKindMismatch of description : OpenFileDescriptionId * inode : InodeNumber
    /// A socket's phase references a connection the connection table does not
    /// hold.
    | DanglingConnection of socket : SocketId * connection : ConnectionId
    /// A listener's accept queue references a connection the connection table
    /// does not hold.
    | DanglingQueuedConnection of listener : SocketId * connection : ConnectionId
    /// The connection table holds a connection no socket phase and no accept
    /// queue references — a leak `UnixDescriptor.close`'s sweep should have caught.
    | OrphanConnection of connection : ConnectionId
    /// One connection sits in two accept-queue slots (in one queue or two),
    /// so accepting it twice would materialise two sockets onto one
    /// connection.
    | DuplicateQueuedConnection of connection : ConnectionId
    /// More than one socket holds one end of a connection: two established as
    /// its client, or as its server, or an accepted server end while a
    /// listener still queues the connection (where its server end is before
    /// `accept(2)`). `holders` names each, in socket-table order, and a
    /// listener once however often it queues the connection.
    | ConnectionEndHeldTwice of connection : ConnectionId * connectionEnd : ConnectionEnd * holders : SocketId list
    /// A connection's bytes and end states break the rules its transfer keeps,
    /// each stated in `violations`: a buffer
    /// holding more than its capacity, bytes in flight to an end that was
    /// reset or closed, a FIN arrived ahead of bytes sent before it, an end
    /// told of an ending its peer never made, and so on.
    | TcpTransferBroken of connection : ConnectionId * violations : string list
    /// A connection's transfer rules are of `rules`, but the machine is
    /// `flavour`-flavoured.
    | TcpTransferNotOfFlavour of
        connection : ConnectionId *
        rules : SimulatedUnixFlavour *
        flavour : SimulatedUnixFlavour
    /// A connection records the exchange of its FINs as complete at
    /// `recorded`, where both FINs have arrived exactly when it records an
    /// instant, and that instant is not after the machine's clock.
    | FinsExchangedAtDisagrees of connection : ConnectionId * recorded : int64 option
    /// An end is in TIME_WAIT at `local`, towards `remote`, from an instant
    /// after the machine's clock, or filed under a four-tuple not its own.
    | TimeWaitMisrecorded of local : Ipv4Endpoint * remote : Ipv4Endpoint
    /// An end is in TIME_WAIT on the four-tuple between `local` and `remote`,
    /// which `connection`, no reset having reached it, occupies too: a connect
    /// that takes a TIME_WAIT's four-tuple over ends it.
    | TimeWaitBesideConnection of local : Ipv4Endpoint * remote : Ipv4Endpoint * connection : ConnectionId
    /// The machine's TIME_WAIT sysctls are another flavour's.
    | TimeWaitSysctlsNotOfFlavour of flavour : SimulatedUnixFlavour
    /// The socket `socket` is the `connectionEnd` end of `connection`, or is
    /// the listener whose accept queue holds its server end, which the
    /// connection records as closed.
    | ConnectionEndClosedUnderSocket of connection : ConnectionId * connectionEnd : ConnectionEnd * socket : SocketId
    /// The connection records its `connectionEnd` end as open, but no socket
    /// is that end and, for a server end, no listener queues the connection:
    /// its socket closed without the connection being told.
    | ConnectionEndOpenWithoutHolder of connection : ConnectionId * connectionEnd : ConnectionEnd
    /// A socket's phase is one its kind cannot enter: a datagram socket
    /// listening or holding a stream connection, or a non-datagram socket
    /// holding a datagram peer.
    | SocketPhaseKindMismatch of socket : SocketId * kind : SocketKind * phase : SocketPhase
    /// A connection in the table has an identity at or above the next one to
    /// allocate, so a future connect would mint a duplicate.
    | NextConnectionIdNotFresh of nextConnectionId : ConnectionId * existing : ConnectionId
    /// An event registration, an epoll instance's or a kqueue's, records
    /// an ADD ordinal at or above the
    /// next one to mint, so some future ADD would repeat it — and the
    /// ordinal's whole job is to order same-signal ties, which a repeat
    /// leaves unspecified.
    | EventRegistrationOrdinalNotFresh of next : int64 * queue : OpenFileDescriptionId * registeredAt : int64
    /// Two event registrations record the same ADD ordinal. Ordinals
    /// are minted from one monotonic counter, so a duplicate means two ADDs
    /// were stamped with one mint — and a same-signal tie between the pair
    /// would have no measured order.
    | DuplicateEventRegistrationOrdinal of registeredAt : int64
    /// A thread is parked on an open file description the table does not hold,
    /// so its wait can never be satisfied, and asking `UnixWait.wake` about
    /// it crashes. A park holds what it names until the call returns, so
    /// this is a park recorded without the description, or one destroyed
    /// without the park being consulted.
    | ParkedOnAbsentDescription of thread : Caller<'Thread> * description : OpenFileDescriptionId
    /// An open file description survives that no descriptor names and no
    /// syscall in flight holds (`ParkedSyscall.descriptions`). A real kernel
    /// frees a file when its last reference goes, so this is a leak: a close,
    /// or the return of a call that held it, failed to release it.
    | UnreferencedDescription of description : OpenFileDescriptionId
    /// A description records `recorded` holds by syscalls in flight, where the
    /// parks of every process's threads name it `parks` times
    /// (`ParkedSyscall.descriptions`). The holds are what keep a description
    /// alive once no descriptor names it, so one too few lets a close destroy
    /// what a sleeping call still waits on, and one too many leaks it.
    | HoldCountMismatch of description : OpenFileDescriptionId * recorded : int * parks : int
    /// No descriptor names the open file description of the connected stream
    /// socket `socket`, whose `SO_LINGER` is on, and only syscalls in flight
    /// hold it. The socket is closed when the last of those calls returns, and
    /// that close is one this kernel may refuse (`DescriptionReleaseRefusal.DarwinAbortBehindQueuedFin`,
    /// `DescriptionReleaseRefusal.LingeringClose`), which a call's return has
    /// no way to answer. `close` refuses the close that would leave the socket
    /// so (`CloseRefusal.LingeringCloseDeferredToCall`).
    | LingeringSocketHeldOnlyByCalls of description : OpenFileDescriptionId * socket : SocketId
    /// A thread is parked in an `epoll_wait` on a description that is not an
    /// epoll instance, which no wait could have produced.
    | ParkedEpollWaitOnNonEpoll of
        thread : Caller<'Thread> *
        description : OpenFileDescriptionId *
        target : OpenFileTarget
    /// A thread is parked in a `kevent` on a description that is not a kqueue,
    /// which no wait could have produced and on which `UnixWait.wake`
    /// crashes.
    | ParkedKeventOnNonKqueue of
        thread : Caller<'Thread> *
        description : OpenFileDescriptionId *
        target : OpenFileTarget
    /// A thread is parked in a `kevent` on a kqueue that has not been drained,
    /// and the descriptor the call was made through no longer names that
    /// kqueue (`current` is what it names now). Closing that descriptor drains
    /// the kqueue, so this is a park recorded without `kevent` or a descriptor
    /// closed around it.
    | ParkedKeventDescriptorRebound of
        thread : Caller<'Thread> *
        fd : int *
        kqueue : OpenFileDescriptionId *
        current : OpenFileDescriptionId option
    /// A thread is parked in a `kevent` for `maxEvents` events, which is not
    /// positive: such a call returns at once.
    | ParkedKeventCountNotPositive of thread : Caller<'Thread> * maxEvents : int
    /// The process's descriptor `fd` names, or a `kevent` wait of one of its
    /// threads made through `fd` sleeps on, the kqueue `kqueue`, which the
    /// process `owner` owns (`KqueueState.Owner`). A kqueue's registrations
    /// name descriptors in its owner's table, so this process would read
    /// them against the wrong one; and only the process that created a kqueue
    /// has a descriptor onto it.
    | KqueueOfAnotherProcess of processId : ProcessId * fd : int * kqueue : OpenFileDescriptionId * owner : ProcessId
    /// An open file description names an object this flavour's kernel does
    /// not have: an epoll instance or a device under Darwin, or a kqueue under
    /// Linux.
    | DescriptionNotOfFlavour of
        description : OpenFileDescriptionId *
        target : OpenFileTarget *
        flavour : SimulatedUnixFlavour
    /// A descriptor is open at or above the bound this kernel assumes the
    /// process's `RLIMIT_NOFILE` reaches (`SimulatedUnixPlatform.descriptorBound`),
    /// which no call hands out.
    | DescriptorAtOrAboveBound of processId : ProcessId * fd : int * bound : int
    /// A descriptor's flags are the other flavour's, not those of the
    /// machine's `flavour` (`DescriptorFlags.flavour`).
    | DescriptorFlagsNotOfFlavour of
        processId : ProcessId *
        fd : int *
        flags : DescriptorFlags *
        flavour : SimulatedUnixFlavour
    /// A description's status is the other flavour's, not that of the
    /// machine's `flavour` (`OpenFileStatus.flavour`).
    | StatusNotOfFlavour of
        description : OpenFileDescriptionId *
        status : OpenFileStatus *
        flavour : SimulatedUnixFlavour
    /// A Darwin description holds an `flock` lock and its status does not
    /// record that one was granted (`OpenFileStatus.Darwin`'s `flocked`).
    | FlockHeldNotRecorded of description : OpenFileDescriptionId
    /// A thread is parked in a `poll` watching an event queue, which `poll`
    /// refuses before it parks and whose readiness is not modelled.
    | ParkedPollOnEventQueue of thread : Caller<'Thread> * description : OpenFileDescriptionId
    /// A thread's parked `poll` watches `fd` on the description it named when
    /// the call went to sleep, and `fd` now names `current` instead. `close`
    /// refuses to close a descriptor a parked poll watches, so this is a park
    /// recorded without `poll` or a descriptor closed around it.
    | ParkedPollDescriptorRebound of
        thread : Caller<'Thread> *
        fd : int *
        watched : OpenFileDescriptionId *
        current : OpenFileDescriptionId option
    /// A thread's parked Darwin `poll` registers a filter through `fd`, which is
    /// not open (`target` is `None`) or names something other than a socket
    /// whose filters are modelled or a pipe. Closing a descriptor removes its
    /// registrations, a poll registers on nothing else, and a regular file's
    /// filters are always ready, so they report before the call can sleep.
    | ParkedKqueuePollRegistrationTarget of thread : Caller<'Thread> * fd : int * target : OpenFileTarget option
    /// A thread's parked Darwin `poll` attributes the registration `key` to
    /// entry `entry`, which the call does not have.
    | ParkedKqueuePollEntryOutOfRange of thread : Caller<'Thread> * key : (int * KqueueFilter) * entry : int
    /// A thread's parked Darwin `poll` lists `key` as activated where the list
    /// may not hold it: `key` is not registered, is listed twice, or is not a
    /// socket's filter (see `PollQueue.Active`).
    | ParkedKqueuePollActiveMalformed of thread : Caller<'Thread> * key : (int * KqueueFilter)
    /// A thread's parked Darwin `poll` registers the socket filter `key`, which is
    /// ready, and does not list it as activated: whatever made it ready did not
    /// activate it, so the call would sleep through what a real one wakes for.
    | ParkedKqueuePollActivationMissed of thread : Caller<'Thread> * key : (int * KqueueFilter)
    /// A thread's parked Darwin `poll` registers the filter `key` as attached to
    /// the socket `attached` (`None`: to none), through a descriptor naming the
    /// socket `named` (`None`: something other than a socket). A poll attaches
    /// a socket's filter, and only a socket's, to the socket its descriptor
    /// names, and closing the descriptor removes the filter, so the two agree
    /// for as long as it lasts.
    | ParkedKqueuePollAttachedElsewhere of
        thread : Caller<'Thread> *
        key : (int * KqueueFilter) *
        attached : SocketId option *
        named : SocketId option
    /// A thread is parked in a Darwin `poll` whose kqueue (`ParkedKqueuePoll.Queue`)
    /// is not on the machine. The park holds it until the park ends.
    | ParkedOnAbsentPollQueue of thread : Caller<'Thread> * queue : PollQueueId
    /// A thread is parked in a Darwin `poll` whose kqueue another process,
    /// `owner`, made. A poll's kqueue is its own call's.
    | PollQueueOfAnotherProcess of thread : Caller<'Thread> * queue : PollQueueId * owner : ProcessId
    /// The machine holds a sleeping Darwin poll's kqueue that `parks` parks
    /// name, rather than exactly one: it is made as its call sleeps, and
    /// destroyed as the park naming it ends.
    | PollQueueNotHeldOnce of queue : PollQueueId * parks : int
    /// The machine holds a sleeping Darwin poll's kqueue whose identity is not
    /// below the counter it is minted from.
    | PollQueueIdNotFresh of next : PollQueueId * existing : PollQueueId
    /// A thread is parked in an `accept` on a description that is not a listening
    /// socket, which no accept could have produced and on which
    /// `UnixWait.wake` crashes.
    | ParkedAcceptOnNonListener of thread : Caller<'Thread> * description : OpenFileDescriptionId
    /// A thread is asleep in an `accept` on a listener a close has drained
    /// (`ListenState.Drained`): the close that drains a listener ends every
    /// accept asleep on it, and `accept` refuses to sleep on one.
    | ParkedAcceptOnDrainedListener of thread : Caller<'Thread> * description : OpenFileDescriptionId
    /// Under Darwin, a thread is asleep in an `accept`, or a pipe or connection
    /// transfer, made through `fd`, which no longer names the description the
    /// call sleeps on
    /// (`current` is what it names now). Closing that descriptor ends the call,
    /// so this is a park recorded without the syscall or a descriptor closed
    /// around it.
    | ParkedCallDescriptorRebound of
        thread : Caller<'Thread> *
        fd : int *
        description : OpenFileDescriptionId *
        current : OpenFileDescriptionId option
    /// Under Linux, a thread's `accept`, or pipe or connection transfer, records
    /// that a close has ended it (`SleepTarget.EndedByClose`), which only
    /// Darwin's close does.
    | ParkedCallEndedByCloseUnderLinux of thread : Caller<'Thread>
    /// Under Linux, a listener records that a close has drained it
    /// (`ListenState.Drained`), which only Darwin's close does.
    | ListenerDrainedUnderLinux of socket : SocketId
    /// A thread is asleep in a pipe `read` or `write` through a description that
    /// names something other than the pipe end the call needs, which no such
    /// call could have produced and on which `UnixWait.wake` crashes.
    | ParkedPipeTransferOnWrongTarget of
        thread : Caller<'Thread> *
        description : OpenFileDescriptionId *
        target : OpenFileTarget
    /// A thread is asleep in a pipe transfer whose progress no call could have
    /// made: a read of nothing, or a write of `count` bytes with `written` of
    /// them in, where a sleeping write has put in at least none and fewer than
    /// all.
    | ParkedPipeTransferProgress of thread : Caller<'Thread> * count : int * written : int
    /// A thread is asleep in a `read`, `recv`, `write` or `send` of a connected
    /// socket through a description that names something other than an end
    /// of a connection,
    /// which no such call could have produced and on which
    /// `UnixWait.wake` crashes.
    | ParkedConnectionTransferOnNonConnection of thread : Caller<'Thread> * description : OpenFileDescriptionId
    /// A thread is asleep in a connection transfer whose progress no call could
    /// have made: a read of nothing but a Linux `recv`, or a write of `count`
    /// bytes with `written` of them taken, where a sleeping write has taken at
    /// least none and fewer than all.
    | ParkedConnectionTransferProgress of thread : Caller<'Thread> * count : int * written : int
    /// A thread's park records an ordinal at or above the next one to mint, so
    /// some future park would repeat it, and the two waiters' order would be
    /// unspecified.
    | ParkOrdinalNotFresh of next : ParkOrdinal * thread : Caller<'Thread> * ordinal : ParkOrdinal
    /// Two threads' parks record the same ordinal. Ordinals are minted from one
    /// monotonic counter, so a duplicate means two parks were stamped with one
    /// mint.
    | DuplicateParkOrdinal of ordinal : ParkOrdinal
    /// A listening socket has no address: `listen(2)` binds an unbound socket
    /// before it listens, and a connect looks listeners up by their binding,
    /// so this one can never be reached.
    | ListenerWithoutBinding of socket : SocketId
    /// A socket that this kernel gives no address -- an IPv6 one with
    /// `IPV6_V6ONLY` on, or a Unix-domain one -- is listening, connected or
    /// latched by a refusal, each of which only a socket with an address
    /// reaches.
    | UnaddressableSocketInPhase of socket : SocketId * addressing : SocketAddressing * phase : SocketPhase
    /// A socket holds a binding that no syscall of this kernel makes: an
    /// `Inet6V6Only` socket's IPv6 binding, a dual-mode socket's
    /// `DualModeBinding.Native` one, or a Unix-domain socket's name. This
    /// kernel has no IPv6 transport and binds no Unix-domain socket, so every
    /// binding it makes is an IPv4 one.
    | UnmodelledBindingHeld of socket : SocketId * addressing : SocketAddressing
    /// A datagram socket's peer (`SocketPhase.DatagramPeer`) is an address in
    /// a family other than the socket's own `domain`, where `connect(2)` sets
    /// a peer only in the socket's own family.
    | DatagramPeerOfAnotherFamily of socket : SocketId * domain : SocketDomain * peer : SocketAddress
    /// A bound socket holds port 0, which is how a process *asks* for a port and
    /// never one it is given, with one exception: a datagram socket whose
    /// Linux `connect(AF_UNSPEC)` kept a locked concrete address and dropped
    /// an unlocked port is half-bound at `address:0`, which is measured and
    /// is what a later `bind` or `connect` completes.
    | BoundToPortZero of socket : SocketId
    /// A thread the table does not hold has handler frames.
    | HandlerFramesWithoutThread of thread : Caller<'Thread>
    /// A thread the table does not hold has a signal mask.
    | MaskWithoutThread of thread : Caller<'Thread>
    /// A thread the table does not hold has a mask for a `sigsuspend(2)` to
    /// restore.
    | MaskToRestoreWithoutThread of thread : Caller<'Thread>
    /// A thread asleep in a syscall other than `sigsuspend(2)` has a mask for a
    /// `sigsuspend` to restore. A thread has one only while it is in that call or
    /// returning from it, and a thread returns to user mode before it makes
    /// another call.
    | MaskToRestoreOutsideSigsuspend of thread : Caller<'Thread> * parked : ParkedSyscall
    /// A thread asleep in `sigsuspend(2)` has no mask to restore, so its return
    /// would leave it with the call's temporary mask.
    | SigsuspendWithoutMaskToRestore of thread : Caller<'Thread>
    /// A pending signal is directed at a thread the table does not hold, so it
    /// can never be delivered and sits in the queue for the rest of the run.
    | PendingSignalTargetWithoutThread of thread : Caller<'Thread> * signal : Signal
    /// The machine's mount claims a filesystem type its flavour cannot report,
    /// so `fstatfs` on a file would answer a fact no such machine could tell.
    | FileSystemTypeNotReportable of flavour : SimulatedUnixFlavour * fileSystemType : EmulatedFileSystemType
    /// The machine's buffer check is not one its platform can have: an up-front
    /// screen on a platform that has none or the other way about, or a limit no
    /// machine of the platform's architecture has been observed to have. See
    /// `UnixMachineState.isUserBufferCheckOf`.
    | UserBufferCheckNotOfPlatform of platform : SimulatedUnixPlatform * check : UserBufferCheck
    /// The process holds more supplementary groups than its machine's
    /// platform lets any process hold (`SimulatedUnixPlatform.supplementaryGroupLimit`).
    | TooManySupplementaryGroups of processId : ProcessId * count : int * limit : int
    /// The process's file-mode creation mask holds a bit its machine's
    /// platform's `umask(2)` never stores (`SimulatedUnixPlatform.umaskStoredBits`),
    /// so every creation would clear a bit no kernel of that flavour clears.
    | UmaskNotOfPlatform of processId : ProcessId * umask : PermissionBits * platform : SimulatedUnixPlatform
    /// The process's leader is not one of its threads. A running process always has
    /// its leader, since the leader cannot exit while another thread lives.
    | LeaderWithoutThread of leader : Caller<'Thread>
    /// Two live threads report the same thread ID, so a lock that records its owner
    /// by thread ID would take either for the other.
    | DuplicateOsThreadId of id : OsThreadId * threads : Caller<'Thread> list
    /// On Linux, the leader's thread ID is not the process ID, which it always is.
    | LeaderThreadIdNotProcessId of leader : Caller<'Thread> * id : OsThreadId * pid : ProcessId
    /// A thread's ID is one the machine's counter could not have handed out:
    /// at or above the greatest `pid_max` Linux takes
    /// (`ThreadIdAllocator.linuxPidMaxCeiling`), or not yet reached on Darwin,
    /// where a later thread could be given the same ID.
    | OsThreadIdNotMintable of thread : Caller<'Thread> * id : OsThreadId * allocator : ThreadIdAllocator
    /// The machine's thread ID counter is not its flavour's: a Linux counter on a
    /// Darwin machine, or the other way about.
    | ThreadIdAllocatorNotOfFlavour of flavour : SimulatedUnixFlavour * allocator : ThreadIdAllocator
    /// The machine's thread ID allocator records as live the IDs in
    /// `withoutThread`, which no thread holds, and does not record those in
    /// `notRecorded`, which threads hold. The allocator hands out only IDs it
    /// does not record as live, so one it fails to record could be handed to a
    /// second thread, and one it records for no thread is never handed out again.
    | LiveThreadIdsMismatch of withoutThread : Set<OsThreadId> * notRecorded : Set<OsThreadId>
    /// The machine records as live the process IDs in `withoutProcess`, which
    /// no process on it has, and does not record those in `notRecorded`, which
    /// processes on it have. A new process is never given an ID the machine
    /// records, so one it fails to record could be given to a second process.
    | LiveProcessIdsMismatch of withoutProcess : Set<ProcessId> * notRecorded : Set<ProcessId>
    /// The machine's process ID counter is not its flavour's: Darwin's own
    /// counter on a Linux machine, which takes process IDs from its thread IDs,
    /// or the other way about.
    | ProcessIdCounterNotOfFlavour of flavour : SimulatedUnixFlavour * counter : ProcessIdCounter
    /// On Darwin, a live process's ID is at or above the counter's next, so a
    /// later process could be given it.
    | ProcessIdNotBelowCounter of pid : ProcessId * next : int32
    /// The machine records `recorded` processes standing in the directory
    /// `inode`, where `standing`
    /// processes on it have it as their current directory. One too few lets a
    /// removal by another process free a directory a process stands in.
    | CurrentDirectoryHoldMismatch of inode : InodeNumber * recorded : int * standing : int
    /// A kqueue is owned (`KqueueState.Owner`) by `owner`, which is no live
    /// process on the machine. Its registrations name descriptors in that
    /// process's table, which no longer exists.
    | KqueueOwnerNotLive of kqueue : OpenFileDescriptionId * owner : ProcessId
    /// A live open file description names a pipe the pipe table does not hold.
    | DanglingPipe of description : OpenFileDescriptionId * pipe : PipeId
    /// The pipe table holds a pipe neither of whose ends is open: no live
    /// description names either end, and the client holds neither. A close that
    /// should have freed it did not.
    | UnreferencedPipe of pipe : PipeId
    /// A pipe the client drains holds bytes. The client reads every byte the
    /// moment it is written, so a write into such a pipe leaves it empty.
    | DrainedPipeHoldsBytes of pipe : PipeId * held : int
    /// The client is asleep in a write into a pipe that has room for some of
    /// what it has left. It writes whenever a read makes room, so a pipe it
    /// supplies is always as full as it can make it.
    | SuppliedPipeHasRoom of pipe : PipeId
    /// A pipe in the table has an identity at or above the next one to
    /// allocate, so a future `pipe2` would mint a duplicate.
    | NextPipeIdNotFresh of nextPipeId : PipeId * existing : PipeId
    /// A pipe end reports an inode number at or above the next one to mint, so
    /// a future pipe would report it too.
    | PipeInodeNotFresh of next : InodeNumber * pipe : PipeId * inode : InodeNumber
    /// Two pipe ends that are not two ends of one Linux pipe report the same
    /// inode number, so a process comparing them would take them for one pipe.
    | DuplicatePipeInode of inode : InodeNumber
    /// A pipe holds a buffer, or reports inode numbers, of a shape its
    /// machine's flavour does not give a pipe: see `PipeBuffer.isOf` and
    /// `PipeInodes`.
    | PipeNotOfPlatform of pipe : PipeId * platform : SimulatedUnixPlatform
    /// The machine's pipes report a device no machine of its flavour reports
    /// for them: a negative one, or on Darwin anything but 0.
    | PipeDeviceNotOfFlavour of device : int64 * flavour : SimulatedUnixFlavour
    /// The machine sets an `fs.protected_*` sysctl its flavour does not have:
    /// anything but `ProtectedFiles.off` on Darwin.
    | ProtectedFilesNotOfFlavour of protection : ProtectedFiles * flavour : SimulatedUnixFlavour
    /// The symbolic link at `inode` has permission bits no link of the
    /// platform's flavour can have: anything but 0o777 on Linux, which creates
    /// every link with those bits and never changes them. A Darwin link can
    /// have any bits, since `fchmodat(2)` changes them
    /// (`SimulatedUnixPlatform.symlinkModeChange`).
    | SymlinkPermissionsNotOfFlavour of
        inode : InodeNumber *
        permissions : PermissionBits *
        flavour : SimulatedUnixFlavour
    /// The thread `thread` is on the logical processor `cpu`, which is not one of
    /// the machine's `processorCount`, numbered from 0. See
    /// `UnixThreadState.cpu`.
    | CpuBeyondMachine of thread : Caller<'Thread> * cpu : CpuId * processorCount : int
    /// The machine records the thread with thread ID `occupant` as running on
    /// the logical processor `cpu`, which is not one of its `processorCount`,
    /// numbered from 0. See `UnixScheduling`.
    | OccupiedCpuBeyondMachine of cpu : CpuId * occupant : OsThreadId * processorCount : int
    /// The machine records the thread with thread ID `occupant` as running on
    /// the logical processor `cpu`, and no live thread has that thread ID: a
    /// thread left the processor without the machine recording it.
    | OccupantWithoutThread of cpu : CpuId * occupant : OsThreadId
    /// The machine records `thread` as running on the logical processor
    /// `occupied`, and the thread's own processor is `cpu`: a running thread's
    /// processor is the one it runs on (`UnixThreadState.cpu`).
    | OccupantOnAnotherCpu of thread : Caller<'Thread> * occupied : CpuId * cpu : CpuId
    /// A thread is parked in a syscall that nothing in this version parks a thread
    /// in, such as `ParkedSyscall.Sleep`, `ParkedSyscall.FifoOpen`,
    /// `ParkedSyscall.Select` or `ParkedSyscall.SignalWait`: a case reserved
    /// for behaviour not yet modelled, which no call produces and no finishing
    /// call answers.
    | ReservedPark of thread : Caller<'Thread> * parked : ParkedSyscall
    /// A thread is parked in a read of an inotify instance through the open file
    /// description `description`, which names `target` rather than an
    /// inotify instance.
    | ParkedInotifyReadOnNonInotify of
        thread : Caller<'Thread> *
        description : OpenFileDescriptionId *
        target : OpenFileTarget
    /// The machine's inotify limits are ones `UnixBootImage.withInotifyLimits`
    /// refuses: not all positive, or a queue too long for `ioctl(FIONREAD)` to
    /// count.
    | InotifyLimitsNotAdmissible of limits : InotifyLimits
    /// `user` holds `count` inotify instances, more than the machine's
    /// `InotifyLimits.MaxUserInstances`, `limit`: `inotify_init1` answers
    /// `EMFILE` for the one past it.
    | InotifyInstancesBeyondLimit of user : UserId * count : int * limit : int
    /// `user`'s inotify instances hold `count` watches, more than the
    /// machine's `InotifyLimits.MaxUserWatches`, `limit`: `inotify_add_watch`
    /// answers `ENOSPC` for the one past it.
    | InotifyWatchesBeyondLimit of user : UserId * count : int * limit : int
    /// The inotify instance `instance` queues `count` records, more than one
    /// past the machine's `InotifyLimits.MaxQueuedEvents`, `limit`: the queue
    /// stops at the limit, and then takes one `IN_Q_OVERFLOW` record.
    | InotifyQueueBeyondLimit of instance : OpenFileDescriptionId * count : int * limit : int
    /// The inotify instance `instance` holds the watch `watch` of `inode`,
    /// which the filesystem no longer holds: a watch ends when its inode goes
    /// for inotify, which is at the latest when the inode is forgotten.
    | InotifyWatchOfForgottenInode of instance : OpenFileDescriptionId * watch : WatchDescriptor * inode : InodeNumber
    /// The description `description`, onto `inode`, records that it was
    /// opened through the name `name` in `parent`, not since unlinked, and
    /// that directory does not bind that name to `inode`: a rename of the
    /// name would have moved the record, and an unlink of it marked it.
    | OpenedThroughNameUnbound of
        description : OpenFileDescriptionId *
        inode : InodeNumber *
        parent : InodeNumber *
        name : DirectoryEntryName
    /// The description `description` records that it was opened through a
    /// name, since unlinked, in `parent`, which is not a directory the
    /// filesystem holds: the name holds its directory, as Linux's dentry
    /// holds its parent's (`UnixMachineState.heldInodes`).
    | OpenedThroughParentGone of description : OpenFileDescriptionId * parent : InodeNumber
    /// The description `description`, onto `inode`, records that it was
    /// opened through no name, and `inode` is neither the root nor a mounted
    /// filesystem's root, the only inodes a walk reaches through none.
    | OpenedThroughNoNameNotRoot of description : OpenFileDescriptionId * inode : InodeNumber
    /// The description `description`, onto `inode`, records that it was
    /// opened through a directory removed while it was last named in
    /// `oldParent`, and `inode` is not a directory whose ".." is `oldParent`
    /// and which `oldParent` does not name.
    | OpenedThroughRemovedDirectoryNamed of
        description : OpenFileDescriptionId *
        inode : InodeNumber *
        oldParent : InodeNumber
    /// A socket is in a phase that nothing in this version puts a socket in,
    /// such as `SocketPhase.Connecting`: a case reserved for behaviour not yet
    /// modelled.
    | ReservedSocketPhase of socket : SocketId * phase : SocketPhase
    /// A socket's binding no longer holds its port (`PortHold.GivenBack`),
    /// and the socket is not one a refused TCP connect, the only thing that
    /// gives a port back, leaves so: a stream socket in `SocketPhase.Refused`,
    /// or under Linux an idle one, whose port, under Linux, `bind(2)` did not
    /// choose.
    | PortGivenBackOutsideRefusal of socket : SocketId * phase : SocketPhase
    /// The filesystem mounted at `root` is `mounted`, which is not what the
    /// machine says it mounted at `/dev` (`UnixMachineState.DeviceMount`),
    /// whose configuration `stat(2)` and `statfs(2)` report for it.
    | MountNotDeviceMount of root : InodeNumber * mounted : MountedFileSystem * deviceMount : MountedFileSystem
    /// One of `FileDescriptorRegistry.checkDescriptorTableInvariants`'s
    /// defects, in the descriptor table of the process `processId`.
    | DescriptorTable of processId : ProcessId * defect : FileDescriptorRegistryDefect
    /// A defect in the open file table's own rules, read against every
    /// process's descriptor table: among them, a description whose count of
    /// the descriptors naming it is not the number of descriptors in every
    /// process that do.
    | OpenFiles of defect : FileDescriptorRegistryDefect
    /// The process held under the process ID `key` records the process ID
    /// `recorded`. A call is made in a process found by its key, whose own
    /// state says its ID, so the two must agree.
    | SlotUnderAnotherProcessId of key : ProcessId * recorded : ProcessId
    /// More than one process records the process ID `processId`.
    | DuplicateProcessId of processId : ProcessId
    /// A thread in no syscall has `signal` pending, unblocked by its mask, in
    /// a set it takes signals from as it returns to user mode, and owes no
    /// return to user mode, so it could make another call before taking the
    /// signal. A real thread takes a signal deliverable to it before it runs
    /// more of its own code.
    | SignalDeliverableWithoutOwedReturn of thread : Caller<'Thread> * signal : Signal

[<RequireQualifiedAccess>]
module UnixSystemDefect =
    /// The defect, for a bug report: the rule that does not hold, by the name
    /// this library's source gives it, and the values that break it.
    let describe<'Thread> (defect : UnixSystemDefect<'Thread>) : string =
        $"the system's tables disagree with each other, in a state no kernel could be in, which is a bug in this library: %A{defect}"

/// Why `UnixBootImage.withFileSystem` refuses a seed: it describes a filesystem
/// no kernel of the machine's flavour could have mounted.
[<RequireQualifiedAccess>]
type internal FileSystemSeedFault =
    /// The seed holds a directory entry whose name is past this flavour's
    /// `NAME_MAX`, so it describes a filesystem no kernel of that flavour could
    /// have mounted: `stat` of the name would answer ENAMETOOLONG while
    /// `readdir` listed it.
    | SeedNameTooLong of name : DirectoryEntryName * flavour : SimulatedUnixFlavour
    /// The seed holds a directory entry whose name this flavour's filesystem
    /// will not bind (see `SimulatedUnixPlatform.bindableEntryNames`): on
    /// Darwin, a name that is not valid UTF-8. No kernel of that flavour could
    /// have created it, and a process there could not create it either.
    | SeedNameNotBindable of name : DirectoryEntryName * flavour : SimulatedUnixFlavour
    /// The seed binds `dev` at its root to something other than an empty
    /// directory. The kernel mounts its device filesystem there at boot, and a
    /// mount over a populated directory would hide what it holds.
    | SeedCoversDeviceFileSystem of name : DirectoryEntryName
    /// The seed has a directory binding both `first` and `second`, on a flavour
    /// whose filesystem takes a name as reaching the entry bound under any
    /// canonically equivalent Unicode spelling of it (Darwin's APFS), and so
    /// binds at most one spelling of a name in a directory. Whether `first`
    /// and `second` are two spellings of one name is beyond this library, which
    /// holds no Unicode tables. Unmodelled.
    | SeedNamesPossiblyEquivalent of
        first : DirectoryEntryName *
        second : DirectoryEntryName *
        flavour : SimulatedUnixFlavour
    /// The seed holds a symbolic link, bound under `name`, whose target is
    /// longer than this flavour's `symlink(2)` will copy in (`PATH_MAX` less
    /// its NUL: 1023 bytes on Darwin, 4095 on Linux), so no process of that
    /// flavour could have created it.
    | SeedSymlinkTargetTooLong of name : DirectoryEntryName * flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal FileSystemSeedFault =
    /// What this library knows about why it refused the seed, for a client
    /// composing a diagnostic that names its own knob.
    let describe (fault : FileSystemSeedFault) : string =
        match fault with
        | FileSystemSeedFault.SeedNameTooLong (name, flavour) ->
            $"the seed holds a directory entry named %s{DirectoryEntryName.toEscaped name}, which is past the %O{flavour} flavour's NAME_MAX, so no kernel of that flavour could have mounted the filesystem it describes. Shorten the name, or simulate a flavour whose NAME_MAX admits it."
        | FileSystemSeedFault.SeedNameNotBindable (name, flavour) ->
            $"the seed holds a directory entry named %s{DirectoryEntryName.toEscaped name}, which a %O{flavour} filesystem will not bind (on Darwin, a name that is not valid UTF-8), so no kernel of that flavour could have created it. Rename the entry, or simulate a flavour that binds it."
        | FileSystemSeedFault.SeedCoversDeviceFileSystem name ->
            $"the seed binds %s{DirectoryEntryName.toEscaped name} at its root to something other than an empty directory, and the kernel mounts its device filesystem there at boot, which would hide what the seed put there. Leave it out of the seed: the kernel supplies /dev itself."
        | FileSystemSeedFault.SeedNamesPossiblyEquivalent (first, second, flavour) ->
            $"the seed has a directory holding both %s{DirectoryEntryName.toEscaped first} and %s{DirectoryEntryName.toEscaped second}. A %O{flavour} filesystem takes a name as reaching the entry bound under any canonically equivalent Unicode spelling of it, so it holds at most one spelling of a name in a directory, and this library holds no Unicode tables to decide whether these two are spellings of one name. Keep one of them in that directory."
        | FileSystemSeedFault.SeedSymlinkTargetTooLong (name, flavour) ->
            $"the seed holds a symbolic link named %s{DirectoryEntryName.toEscaped name} whose target is longer than a %O{flavour} kernel's symlink(2) copies in (PATH_MAX less its NUL), so no process of that flavour could have created it. Shorten the target, or simulate a flavour whose PATH_MAX admits it."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FileSystemSeedFault) : RefusalKind =
        match refusal with
        | FileSystemSeedFault.SeedNameTooLong _ -> RefusalKind.Contradictory "seed"
        | FileSystemSeedFault.SeedNameNotBindable _ -> RefusalKind.Contradictory "seed"
        | FileSystemSeedFault.SeedCoversDeviceFileSystem _ -> RefusalKind.Contradictory "seed"
        | FileSystemSeedFault.SeedNamesPossiblyEquivalent _ -> RefusalKind.Unmodelled
        | FileSystemSeedFault.SeedSymlinkTargetTooLong _ -> RefusalKind.Contradictory "seed"

/// Why `UnixSystem.launch` will not start a process.
[<RequireQualifiedAccess>]
type internal ProcessCreationRefusal =
    /// The launch itself is refused; see `LaunchRefusal`.
    | Launch of LaunchRefusal
    /// On Linux, every ID the machine would hand out, from 300 up to its
    /// `pid_max`, is a live thread's, so `fork(2)` would answer EAGAIN.
    | NoFreeProcessId
    /// On Darwin, the process ID counter has reached `pidMax`
    /// (`ProcessIdTable.darwinPidMax`). xnu wraps it back to 100, skipping IDs
    /// in use; that has not been measured, so this library does not wrap.
    | DarwinPidMaxReached of pidMax : int32
    /// On Darwin, the 64-bit thread ID counter has reached the top of its
    /// range, so the new process's leader would take an ID beyond it; what
    /// Darwin does then has not been measured.
    | DarwinThreadIdCounterExhausted

[<RequireQualifiedAccess>]
module internal ProcessCreationRefusal =
    /// What this library knows about why it would not start the process, for
    /// a client composing a diagnostic that names its own knob.
    let describe (refusal : ProcessCreationRefusal) : string =
        match refusal with
        | ProcessCreationRefusal.Launch refusal -> LaunchRefusal.describe refusal
        | ProcessCreationRefusal.NoFreeProcessId ->
            "every process ID the machine would hand out is a live thread's, so fork(2) would answer EAGAIN."
        | ProcessCreationRefusal.DarwinPidMaxReached pidMax ->
            $"the machine's process ID counter has reached Darwin's PID_MAX %d{pidMax}; what Darwin does next (xnu's source wraps to 100) has not been measured."
        | ProcessCreationRefusal.DarwinThreadIdCounterExhausted ->
            "the machine's thread ID counter has reached the top of its 64-bit range, so the new process's leader would take an ID beyond it; what Darwin does then has not been measured."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ProcessCreationRefusal) : RefusalKind =
        match refusal with
        | ProcessCreationRefusal.Launch inner -> LaunchRefusal.kind inner
        | ProcessCreationRefusal.NoFreeProcessId -> RefusalKind.Unmodelled
        | ProcessCreationRefusal.DarwinPidMaxReached _ -> RefusalKind.Unmodelled
        | ProcessCreationRefusal.DarwinThreadIdCounterExhausted -> RefusalKind.Unmodelled

[<RequireQualifiedAccess>]
module UnixSystem =

    /// Mount `mount` over the root's `dev`, as the kernel does at boot, with a
    /// node for each device it has a driver for, all made at the epoch and
    /// owned by root. The root directory's times do not move.
    ///
    /// The directory and its nodes have the modes a measured devtmpfs and devfs
    /// report: 0755 and 0555 respectively for the directory, 0666 for each
    /// node.
    let internal mountDeviceFileSystem
        (mount : DeviceFileSystemMount)
        (filesystem : VirtualFileSystem)
        : Result<VirtualFileSystem, MountFault>
        =
        let root =
            {
                User = UserId.root
                Group = GroupId.parseOrFail "UnixSystem.mountDeviceFileSystem" 0u
            }

        let permissions, devices =
            match mount with
            | DeviceFileSystemMount.Devtmpfs _ ->
                PermissionBits 0o755,
                CharacterDevice.all
                |> List.map (fun device -> CharacterDevice.name device, device, CharacterDevice.permissions device)
            | DeviceFileSystemMount.Devfs -> PermissionBits 0o555, []

        // Measured by `docs/probes/devtmpfs-times` over three boots of Linux
        // 6.18.5 aarch64: devtmpfs makes its root and these nodes before the
        // realtime clock is first set, so every one of their times is the
        // uptime then, 0 to 4 ms past the epoch, whatever the clock later
        // reads and whenever the root filesystem was made. The exact
        // milliseconds depend on how fast the kernel booted, which nothing
        // here states, so this is the epoch itself. An x86 kernel, which reads
        // a CMOS clock before devtmpfs runs, has not been measured.
        VirtualFileSystem.mountAtRoot
            (DeviceFileSystemMount.mounted mount)
            (DirectoryEntryName.parseOrFail "UnixSystem.mountDeviceFileSystem" "dev")
            permissions
            root
            devices
            UnixTimestamp.epoch
            filesystem

    /// The first thread of the process `pid`, which it started with: its
    /// thread-group leader.
    let leader<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : 'Thread
        =
        Entry.query "UnixSystem.leader" pid (fun (system : ProcessView<'Thread, 'Handler>) -> system.Leader) system

    /// Every thread the process `pid` has, by the client's name for it, which
    /// `UnixThreadState`'s readers read. A name the process has no thread by,
    /// because the thread was never created or has exited, has no entry.
    let threads<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<'Thread, UnixThreadState>
        =
        Entry.query "UnixSystem.threads" pid (fun (system : ProcessView<'Thread, 'Handler>) -> system.Threads) system

    /// Every write that has reached a client draining one of the machine's
    /// pipes, oldest first: the bytes the outside world has received from the
    /// machine's processes. No process can read them back.
    ///
    /// A client reads what its own ends received by filtering on
    /// `Delivery.Endpoint`, which names the process the pipe was launched into
    /// as well as the descriptor. The log is one for the whole machine, so the
    /// order of writes across endpoints is kept. It grows without bound.
    let delivered<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : DeliveryLog
        =
        UnixMachineState.delivered system.Machine

    /// The signal state of the process `pid`, which `SignalState`'s queries
    /// read.
    let signals<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        Entry.query
            "UnixSystem.signals"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> UnixProcessState.signals system.Process)
            system

    /// The environment the process `pid` was started with: the `envp` that
    /// `execve(2)` received, entry by entry, in order. Each entry is held
    /// exactly as given, whether or not it is `NAME=VALUE`.
    ///
    /// This is the exec-time image, not the C library's `environ`:
    /// `setenv(3)` and `putenv(3)` change the process's own copy in user
    /// space, which this library does not model.
    let environment<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixByteString list
        =
        Entry.query
            "UnixSystem.environment"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> UnixProcessState.environment system.Process)
            system

    /// The path of the executable that started the process `pid`, or `None` if
    /// it has none. `None` is an answer rather than a missing value: this library
    /// models no `exec(2)`, so a process has a path only if its launch set one
    /// (`ProcessLaunch.withProcessPath`). The path is not resolved against the
    /// filesystem, so a client that wants it to name a file seeds the file.
    let processPath<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : AbsoluteUnixPath option
        =
        Entry.query
            "UnixSystem.processPath"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> UnixProcessState.processPath system.Process)
            system

    /// The platform the machine impersonates.
    let platform<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : SimulatedUnixPlatform
        =
        UnixMachineState.platform system.Machine

    /// The number of logical processors the machine reports to the process:
    /// at least 1, and fixed at boot (`UnixBootImage.withProcessorCount`).
    let processorCount<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : int
        =
        UnixMachineState.processorCount system.Machine

    /// How long the machine has been up, to the nanosecond. Only `advanceClock`
    /// moves it. A process reads the same instant through
    /// `UnixClock.clockGettime`, at the granularity its flavour reports.
    let nanosecondsSinceBoot<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : int64
        =
        UnixSchedulingState.nanosecondsSinceBoot system.Scheduling

    /// Let `nanoseconds` pass on the machine: every clock it has moves forward
    /// by that much. Advancing by zero changes nothing.
    ///
    /// Throws for a negative amount, since no clock this kernel models runs
    /// backwards, and for one that would take the uptime past
    /// `Int64.MaxValue` nanoseconds (about 292 years).
    let advanceClock<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (nanoseconds : int64)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        { system with
            Scheduling = UnixSchedulingState.advanceClock nanoseconds system.Scheduling
        }

    /// The descriptor table of the process `pid`, which
    /// `FileDescriptorRegistry`'s queries read: every descriptor it holds, and
    /// the open file description each names.
    let fileDescriptors<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : FileDescriptorRegistry
        =
        Entry.query
            "UnixSystem.fileDescriptors"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> UnixSystemState.fileDescriptors system)
            system

    /// The machine's open file descriptions, which `OpenFileTable`'s queries
    /// read: every one any descriptor names, and any a call in flight holds.
    let openFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : OpenFileTable
        =
        system.Machine.OpenFiles

    /// The machine's filesystem, which `VirtualFileSystem`'s queries read.
    let fileSystem<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : VirtualFileSystem
        =
        system.Machine.FileSystem

    /// The inode of the directory the process `pid` is standing in. The path
    /// `getcwd(3)` reports is `UnixPathResolution.currentDirectoryPath`.
    let currentDirectoryInode<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : InodeNumber
        =
        Entry.query
            "UnixSystem.currentDirectoryInode"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> system.Process.CurrentDirectoryInode)
            system

    /// Who the process `pid` is: all six of its IDs, and its supplementary
    /// groups.
    let credentials<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : Credentials
        =
        Entry.query
            "UnixSystem.credentials"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> system.Process.Credentials)
            system

    /// The file-mode creation mask of the process `pid`, without replacing it
    /// as `umask` does.
    let fileModeCreationMask<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (system : UnixSystem<'Thread, 'Handler>)
        : PermissionBits
        =
        Entry.query
            "UnixSystem.fileModeCreationMask"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) -> system.Process.Umask)
            system

    /// The machine's entropy pool, from which every random-bytes syscall draws.
    let entropyPool<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : EntropyPool
        =
        system.Machine.EntropyPool

    /// The lowest port a process without privilege may bind
    /// (`UnixBootImage.withUnprivilegedPortStart`).
    let unprivilegedPortStart<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : uint16
        =
        system.Machine.UnprivilegedPortStart

    /// The range a `bind(2)` of port 0 draws from, inclusive at both ends.
    let ephemeralPortRange<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : uint16 * uint16
        =
        system.Machine.EphemeralPortRange

    /// The machine's `somaxconn` sysctl (`net.core.somaxconn` on Linux,
    /// `kern.ipc.somaxconn` on Darwin): the ceiling `listen(2)` clamps its
    /// backlog to. See `UnixBootImage.withSoMaxConn`.
    let soMaxConn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : int
        =
        system.Machine.SoMaxConn

    /// The mount the machine's root filesystem claims to be: its type and what
    /// `statfs(2)` reports about it. Fixed for the run, since this library
    /// models no `mount(2)`; see `UnixBootImage.withMount`.
    let mount<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : EmulatedMount
        =
        system.Machine.Mount

    /// The machine's `fs.protected_*` sysctls. See
    /// `UnixBootImage.withProtectedFiles`.
    let protectedFiles<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : ProtectedFiles
        =
        system.Machine.ProtectedFiles

    /// Every pipe with an end open, by identity: an end an open file
    /// description names, or one the client holds (`PipeState.heldByClient`).
    let pipes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Map<PipeId, PipeState>
        =
        system.Machine.Pipes

    /// The realtime clock's reading, to the nanosecond: the boot time plus
    /// `nanosecondsSinceBoot`. This is the instant the kernel stamps on an
    /// inode it changes. `clock_gettime(CLOCK_REALTIME)` reports the same
    /// clock, at the granularity its flavour reports it at.
    let realtime<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixTimestamp
        =
        UnixMachineState.realtime system.Scheduling system.Machine

    /// Whether, and where, the machine's kernel screens a read or write buffer
    /// before performing the operation. See `UnixBootImage.withUserAddressLimit`.
    let userBufferCheck<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UserBufferCheck
        =
        UnixMachineState.userBufferCheck system.Machine

    /// The socket `socketId` names, or `None` if the machine holds none by
    /// that identity: a socket goes when its last open file description does,
    /// so an identity read from a descriptor that has since closed names
    /// nothing.
    let socket<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (system : UnixSystem<'Thread, 'Handler>)
        : SocketDescription option
        =
        Map.tryFind socketId system.Machine.Sockets

    /// The kqueue of the sleeping Darwin `poll` whose park names `queue`
    /// (`ParkedKqueuePoll.Queue`), or `None` if the machine holds none by that
    /// identity.
    let pollQueue<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (queue : PollQueueId)
        (system : UnixSystem<'Thread, 'Handler>)
        : PollQueue option
        =
        Map.tryFind queue system.Machine.PollQueues

    /// The pipe `pipeId` names. Loudly partial, as `UnixMachineState.pipe` is.
    let internal pipe<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pipeId : PipeId)
        (system : UnixSystem<'Thread, 'Handler>)
        : PipeState
        =
        UnixMachineState.pipe pipeId system.Machine

    /// How ready the socket `socketId` is. See
    /// `UnixMachineState.socketReadinessLevel`.
    let internal socketReadinessLevel<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (system : UnixSystem<'Thread, 'Handler>)
        : ReadinessLevel
        =
        UnixMachineState.socketReadinessLevel socketId system.Machine

    /// What the descriptor `fd` of the process `pid` names, or `None` if the
    /// process has no such descriptor open.
    let descriptorTarget<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (pid : ProcessId)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : OpenFileTarget option
        =
        Entry.query
            "UnixSystem.descriptorTarget"
            pid
            (fun (system : ProcessView<'Thread, 'Handler>) ->
                FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system)
            )
            system

    /// The ID of every process the system holds, of which a query can ask and
    /// in which a call can be made.
    let processIds<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : Set<ProcessId>
        =
        system.Processes
        |> Map.keys
        |> Seq.map (ProcessId.parseOrFail "UnixSystem.processIds")
        |> Set.ofSeq

    /// `processId` once `Entry` has admitted its caller.
    let private processIdIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessId
        =
        system.Process.ProcessId

    /// The process ID, as `getpid(2)` reports it to `caller`.
    ///
    /// Total, and changes nothing: `getpid` cannot fail.
    let processId<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessId
        =
        Entry.call "UnixSystem.processId" CallerRequirement.Running caller Shape.answer processIdIn system

    /// `umask` once `Entry` has admitted its caller.
    let private umaskIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (mask : int)
        (system : ProcessView<'Thread, 'Handler>)
        : PermissionBits * ProcessView<'Thread, 'Handler>
        =
        let kept =
            mask
            &&& PermissionBits.toInt (SimulatedUnixPlatform.umaskStoredBits system.Machine.UnixPlatform)
            |> PermissionBits.parseOrFail "UnixSystem.umask"

        system.Process.Umask,
        { system with
            Process =
                { system.Process with
                    Umask = kept
                }
        }

    /// `umask(2)`, made by `caller`: make `mask` the process's file-mode
    /// creation mask, and answer the mask it replaces.
    ///
    /// `mask` is raw, as the kernel takes it. The process keeps only the bits
    /// `SimulatedUnixPlatform.umaskStoredBits` names, 0o777 on Linux and 0o7777
    /// on Darwin, and ignores the rest, so a later call answers `mask` narrowed
    /// to those bits. Total: `umask` cannot fail.
    ///
    /// The mask is the process's, shared by all its threads: measured on both,
    /// a thread's `umask` is what every other thread's next call answers.
    let umask<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (mask : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : PermissionBits * UnixSystem<'Thread, 'Handler>
        =
        Entry.call "UnixSystem.umask" CallerRequirement.Running caller Shape.withSystem (umaskIn mask) system

    /// `step`, with a refusal answered as the `Error` rather than raised.
    ///
    /// Each call `step` makes is made through its own family's function, whose
    /// `Entry` checks `caller` before anything else; a reserved call checks
    /// `caller` here, before it is refused.
    let internal tryStep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (call : Syscall<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SteppedCall<'Thread, 'Handler>, SyscallRefusal<'Thread>>
        =
        let reserved (call : string) : Result<SteppedCall<'Thread, 'Handler>, SyscallRefusal<'Thread>> =
            Entry.admit "UnixSystem.step" CallerRequirement.Running caller system
            Error (SyscallRefusal.Reserved call)

        match call with
        | Syscall.Dup fd ->
            UnixDescriptor.tryDup caller fd system
            |> Result.map SteppedCall.Dup
            |> Result.mapError SyscallRefusal.Dup
        | Syscall.Dup2 (oldFd, newFd) ->
            UnixDescriptor.tryDup2 caller oldFd newFd system
            |> Result.map SteppedCall.Dup2
            |> Result.mapError SyscallRefusal.Dup2
        | Syscall.Dup3 (oldFd, newFd, flags) ->
            UnixDescriptor.tryDup3 caller oldFd newFd flags system
            |> Result.map SteppedCall.Dup3
            |> Result.mapError SyscallRefusal.Dup3
        | Syscall.Fcntl (fd, command, argument) ->
            UnixDescriptor.tryFcntl caller fd command argument system
            |> Result.map SteppedCall.Fcntl
            |> Result.mapError SyscallRefusal.Fcntl
        | Syscall.LSeek (fd, offset, whence) ->
            UnixDescriptor.tryLseek caller fd offset whence system
            |> Result.map SteppedCall.LSeek
            |> Result.mapError SyscallRefusal.LSeek
        | Syscall.FLock (fd, operation) ->
            UnixDescriptor.tryFlock caller fd operation system
            |> Result.map SteppedCall.FLock
            |> Result.mapError SyscallRefusal.FLock
        | Syscall.FTruncate (fd, length) ->
            UnixDescriptor.tryFtruncate caller fd length system
            |> Result.map SteppedCall.FTruncate
            |> Result.mapError SyscallRefusal.FTruncate
        | Syscall.PosixFAdvise (fd, offset, length, advice) ->
            UnixDescriptor.tryPosixFadvise caller fd offset length advice system
            |> Result.map SteppedCall.PosixFAdvise
            |> Result.mapError SyscallRefusal.PosixFAdvise
        | Syscall.Close fd ->
            UnixDescriptor.tryClose caller fd system
            |> Result.map SteppedCall.Close
            |> Result.mapError SyscallRefusal.Close
        | Syscall.BytesAvailable (fd, destination) ->
            UnixDescriptor.tryBytesAvailable caller fd destination system
            |> Result.map SteppedCall.BytesAvailable
            |> Result.mapError SyscallRefusal.BytesAvailable
        | Syscall.FileClone (destination, source) ->
            UnixDescriptor.tryFileClone caller destination source system
            |> Result.map SteppedCall.FileClone
            |> Result.mapError SyscallRefusal.FileClone
        | Syscall.TerminalAttributes fd ->
            Ok (SteppedCall.TerminalAttributes (UnixDescriptor.terminalAttributes caller fd system))
        | Syscall.GetEffectiveUserId ->
            Ok (SteppedCall.GetEffectiveUserId (UnixDescriptor.effectiveUserId caller system))
        | Syscall.GetEffectiveGroupId ->
            Ok (SteppedCall.GetEffectiveGroupId (UnixDescriptor.effectiveGroupId caller system))
        | Syscall.GetGroups (size, destination) ->
            UnixDescriptor.tryGetgroups caller destination size system
            |> Result.map SteppedCall.GetGroups
            |> Result.mapError SyscallRefusal.GetGroups
        | Syscall.Stat (policy, path) ->
            UnixPathResolution.tryStat caller policy path system
            |> Result.map SteppedCall.Stat
            |> Result.mapError SyscallRefusal.Stat
        | Syscall.FStat fd ->
            UnixPathResolution.tryFstat caller fd system
            |> Result.map SteppedCall.FStat
            |> Result.mapError SyscallRefusal.FStat
        | Syscall.FStatAt (dirfd, path, flags) ->
            UnixPathResolution.tryFstatat caller dirfd path flags system
            |> Result.map SteppedCall.FStatAt
            |> Result.mapError SyscallRefusal.FStatAt
        | Syscall.ChMod (path, mode) ->
            UnixPathResolution.tryChmod caller path mode system
            |> Result.map SteppedCall.ChMod
            |> Result.mapError SyscallRefusal.ChMod
        | Syscall.FChMod (fd, mode) ->
            UnixPathResolution.tryFchmod caller fd mode system
            |> Result.map SteppedCall.FChMod
            |> Result.mapError SyscallRefusal.FChMod
        | Syscall.FChModAt (dirfd, path, mode, flags) ->
            UnixPathResolution.tryFchmodat caller dirfd path mode flags system
            |> Result.map SteppedCall.FChModAt
            |> Result.mapError SyscallRefusal.FChModAt
        | Syscall.ChOwn (path, user, group) ->
            UnixPathResolution.tryChown caller path user group system
            |> Result.map SteppedCall.ChOwn
            |> Result.mapError SyscallRefusal.ChOwn
        | Syscall.LChOwn (path, user, group) ->
            UnixPathResolution.tryLchown caller path user group system
            |> Result.map SteppedCall.LChOwn
            |> Result.mapError SyscallRefusal.LChOwn
        | Syscall.FChOwn (fd, user, group) ->
            UnixPathResolution.tryFchown caller fd user group system
            |> Result.map SteppedCall.FChOwn
            |> Result.mapError SyscallRefusal.FChOwn
        | Syscall.FChOwnAt (dirfd, path, user, group, flags) ->
            UnixPathResolution.tryFchownat caller dirfd path user group flags system
            |> Result.map SteppedCall.FChOwnAt
            |> Result.mapError SyscallRefusal.FChOwnAt
        | Syscall.UTimensAt (dirfd, path, times, flags) ->
            UnixPathResolution.tryUtimensat caller dirfd path times flags system
            |> Result.map SteppedCall.UTimensAt
            |> Result.mapError SyscallRefusal.UTimensAt
        | Syscall.StatFs path ->
            UnixPathResolution.tryStatfs caller path system
            |> Result.map SteppedCall.StatFs
            |> Result.mapError SyscallRefusal.StatFs
        | Syscall.FStatFs fd -> Ok (SteppedCall.FStatFs (UnixPathResolution.fstatfs caller fd system))
        | Syscall.GetCwd (destination, capacity) ->
            UnixPathResolution.tryGetcwd caller destination capacity system
            |> Result.map SteppedCall.GetCwd
            |> Result.mapError SyscallRefusal.GetCwd
        | Syscall.ChDir path ->
            UnixPathResolution.tryChdir caller path system
            |> Result.map SteppedCall.ChDir
            |> Result.mapError SyscallRefusal.ChDir
        | Syscall.Access (path, mode) ->
            UnixPathResolution.tryAccess caller mode system
            |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)
            |> Result.map SteppedCall.Access
            |> Result.mapError SyscallRefusal.Access
        | Syscall.FAccessAt (dirfd, path, mode, flags) ->
            UnixPathResolution.tryFaccessat caller dirfd mode flags system
            |> CallProgress.resumeWith (UnixPathResolution.tryAccessWithPath path)
            |> Result.map SteppedCall.FAccessAt
            |> Result.mapError SyscallRefusal.FAccessAt
        | Syscall.Open (path, flags, mode) ->
            UnixNamespace.tryOpenPath caller flags path mode system
            |> Result.map SteppedCall.Open
            |> Result.mapError SyscallRefusal.Open
        | Syscall.OpenAt (dirfd, path, flags, mode) ->
            UnixNamespace.tryOpenat caller dirfd path flags mode system
            |> Result.map SteppedCall.OpenAt
            |> Result.mapError SyscallRefusal.OpenAt
        | Syscall.ReadLink (path, destination, capacity) ->
            UnixNamespace.tryReadlink caller path destination capacity system
            |> Result.map SteppedCall.ReadLink
            |> Result.mapError SyscallRefusal.ReadLink
        | Syscall.ReadLinkAt (dirfd, path, destination, capacity) ->
            UnixNamespace.tryReadlinkat caller dirfd path destination capacity system
            |> Result.map SteppedCall.ReadLinkAt
            |> Result.mapError SyscallRefusal.ReadLinkAt
        | Syscall.ReadDirectoryEntry fd ->
            UnixNamespace.tryReadDirectoryEntry caller fd system
            |> Result.map SteppedCall.ReadDirectoryEntry
            |> Result.mapError SyscallRefusal.ReadDirectoryEntry
        | Syscall.MkDir (path, mode) ->
            UnixNamespace.tryMkdir caller path mode system
            |> Result.map SteppedCall.MkDir
            |> Result.mapError SyscallRefusal.MkDir
        | Syscall.MkDirAt (dirfd, path, mode) ->
            UnixNamespace.tryMkdirat caller dirfd path mode system
            |> Result.map SteppedCall.MkDirAt
            |> Result.mapError SyscallRefusal.MkDirAt
        | Syscall.MkNod (path, mode, dev) ->
            UnixNamespace.tryMknod caller path mode dev system
            |> Result.map SteppedCall.MkNod
            |> Result.mapError SyscallRefusal.MkNod
        | Syscall.MkNodAt (dirfd, path, mode, dev) ->
            UnixNamespace.tryMknodat caller dirfd path mode dev system
            |> Result.map SteppedCall.MkNodAt
            |> Result.mapError SyscallRefusal.MkNodAt
        | Syscall.Unlink path ->
            UnixNamespace.tryUnlink caller path system
            |> Result.map SteppedCall.Unlink
            |> Result.mapError SyscallRefusal.Unlink
        | Syscall.RmDir path ->
            UnixNamespace.tryRmdir caller path system
            |> Result.map SteppedCall.RmDir
            |> Result.mapError SyscallRefusal.RmDir
        | Syscall.UnlinkAt (dirfd, path, flags) ->
            UnixNamespace.tryUnlinkat caller dirfd path flags system
            |> Result.map SteppedCall.UnlinkAt
            |> Result.mapError SyscallRefusal.UnlinkAt
        | Syscall.Rename (source, destination) ->
            UnixNamespace.tryRename caller source system
            |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination destination)
            |> Result.map SteppedCall.Rename
            |> Result.mapError SyscallRefusal.Rename
        | Syscall.RenameAt (olddirfd, oldpath, newdirfd, newpath) ->
            UnixNamespace.tryRenameat caller olddirfd oldpath newdirfd system
            |> CallProgress.resumeWith (UnixNamespace.tryRenameWithDestination newpath)
            |> Result.map SteppedCall.RenameAt
            |> Result.mapError SyscallRefusal.RenameAt
        | Syscall.CloneFile (source, destination, flags) ->
            UnixNamespace.tryCloneFile caller flags system
            |> CallProgress.resumeWith (fun paused ->
                UnixNamespace.tryCloneFileWithSource source paused
                |> CallProgress.resumeWith (UnixNamespace.tryCloneFileWithDestination destination)
            )
            |> Result.map SteppedCall.CloneFile
            |> Result.mapError SyscallRefusal.CloneFile
        | Syscall.Symlink (target, path) ->
            Ok (UnixNamespace.symlink caller target system)
            |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)
            |> Result.map SteppedCall.Symlink
            |> Result.mapError SyscallRefusal.Symlink
        | Syscall.SymlinkAt (target, dirfd, path) ->
            Ok (UnixNamespace.symlinkat caller target dirfd system)
            |> CallProgress.resumeWith (UnixNamespace.trySymlinkWithPath path)
            |> Result.map SteppedCall.SymlinkAt
            |> Result.mapError SyscallRefusal.SymlinkAt
        | Syscall.Link (oldpath, newpath) ->
            UnixNamespace.tryLink caller oldpath system
            |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)
            |> Result.map SteppedCall.Link
            |> Result.mapError SyscallRefusal.Link
        | Syscall.LinkAt (olddirfd, oldpath, newdirfd, newpath, flags) ->
            UnixNamespace.tryLinkat caller olddirfd oldpath newdirfd flags system
            |> CallProgress.resumeWith (UnixNamespace.tryLinkWithDestination newpath)
            |> Result.map SteppedCall.LinkAt
            |> Result.mapError SyscallRefusal.LinkAt
        | Syscall.Read (fd, buffer, count) ->
            UnixReadWrite.tryRead caller fd buffer count system
            |> Result.map SteppedCall.Read
            |> Result.mapError SyscallRefusal.Read
        | Syscall.Recv (fd, buffer, count, flags) ->
            UnixReadWrite.tryRecv caller fd buffer count flags system
            |> Result.map SteppedCall.Recv
            |> Result.mapError SyscallRefusal.Recv
        | Syscall.RecvFrom _ -> reserved "Syscall.RecvFrom"
        | Syscall.RecvMsg _ -> reserved "Syscall.RecvMsg"
        | Syscall.PRead (fd, buffer, count, offset) ->
            UnixReadWrite.tryPread caller fd buffer count offset system
            |> Result.map SteppedCall.PRead
            |> Result.mapError SyscallRefusal.PRead
        | Syscall.Write (fd, buffer, count) ->
            CopiedArgument.copyBytes
                "UnixSystem.step of Syscall.Write"
                PausedWrite.copyRange
                UnixReadWrite.tryWriteWithBytes
                buffer
                (fun buffer -> UnixReadWrite.tryWrite caller fd buffer count system)
            |> Result.map SteppedCall.Write
            |> Result.mapError SyscallRefusal.Write
        | Syscall.Send (fd, buffer, count, flags) ->
            CopiedArgument.copyBytes
                "UnixSystem.step of Syscall.Send"
                PausedSend.copyRange
                UnixReadWrite.trySendWithBytes
                buffer
                (fun buffer -> UnixReadWrite.trySend caller fd buffer count flags system)
            |> Result.map SteppedCall.Send
            |> Result.mapError SyscallRefusal.Send
        | Syscall.SendTo _ -> reserved "Syscall.SendTo"
        | Syscall.SendMsg _ -> reserved "Syscall.SendMsg"
        | Syscall.PWrite (fd, buffer, count, offset) ->
            CopiedArgument.copyBytes
                "UnixSystem.step of Syscall.PWrite"
                PausedPWrite.copyRange
                UnixReadWrite.tryPwriteWithBytes
                buffer
                (fun buffer -> UnixReadWrite.tryPwrite caller fd buffer count offset system)
            |> Result.map SteppedCall.PWrite
            |> Result.mapError SyscallRefusal.PWrite
        | Syscall.CopyFileRange (inFd, outFd, length, flags) ->
            UnixReadWrite.tryCopyFileRange caller inFd outFd length flags system
            |> Result.map SteppedCall.CopyFileRange
            |> Result.mapError SyscallRefusal.CopyFileRange
        | Syscall.Pipe2 (destination, flags) ->
            UnixPipe.tryPipe2 caller flags destination system
            |> Result.map SteppedCall.Pipe2
            |> Result.mapError SyscallRefusal.Pipe2
        | Syscall.Socket (domain, socketType, protocol) ->
            UnixSocket.trySocket caller domain socketType protocol system
            |> Result.map SteppedCall.Socket
            |> Result.mapError SyscallRefusal.Socket
        | Syscall.Bind (fd, address, declaredLength) ->
            CopiedArgument.copyBytes
                "UnixSystem.step of Syscall.Bind"
                PausedBind.copyRange
                UnixSocket.tryBindWithAddress
                address
                (fun address -> UnixSocket.tryBind caller fd address declaredLength system)
            |> Result.map SteppedCall.Bind
            |> Result.mapError SyscallRefusal.Bind
        | Syscall.Connect (fd, address, declaredLength) ->
            CopiedArgument.copyBytes
                "UnixSystem.step of Syscall.Connect"
                PausedConnect.copyRange
                UnixConnection.tryConnectWithAddress
                address
                (fun address -> UnixConnection.tryConnect caller fd address declaredLength system)
            |> Result.map SteppedCall.Connect
            |> Result.mapError SyscallRefusal.Connect
        | Syscall.Listen (fd, backlog) ->
            UnixSocket.tryListen caller fd backlog system
            |> Result.map SteppedCall.Listen
            |> Result.mapError SyscallRefusal.Listen
        | Syscall.Accept (fd, destination, declaredLength) ->
            UnixConnection.tryAccept caller fd destination declaredLength system
            |> Result.map SteppedCall.Accept
            |> Result.mapError SyscallRefusal.Accept
        | Syscall.Shutdown (fd, how) ->
            UnixConnection.tryShutdown caller fd how system
            |> Result.map SteppedCall.Shutdown
            |> Result.mapError SyscallRefusal.Shutdown
        | Syscall.GetSockName (fd, destination, declaredLength) ->
            UnixSocket.tryGetsockname caller fd destination declaredLength system
            |> Result.map SteppedCall.GetSockName
            |> Result.mapError SyscallRefusal.GetSockName
        | Syscall.GetPeerName (fd, destination, declaredLength) ->
            UnixSocket.tryGetpeername caller fd destination declaredLength system
            |> Result.map SteppedCall.GetPeerName
            |> Result.mapError SyscallRefusal.GetPeerName
        | Syscall.SetSockOpt (fd, level, optionName, value, optionLength) ->
            CopiedArgument.copyBytes
                "UnixSystem.step of Syscall.SetSockOpt"
                PausedSetSockOpt.copyRange
                UnixSocket.trySetsockoptWithValue
                value
                (fun value -> UnixSocket.trySetsockopt caller fd level optionName value optionLength system)
            |> Result.map SteppedCall.SetSockOpt
            |> Result.mapError SyscallRefusal.SetSockOpt
        | Syscall.GetSockOpt (fd, level, optionName, value, length) ->
            CopiedArgument.copyValue
                "UnixSystem.step of Syscall.GetSockOpt"
                UnixSocket.tryGetsockoptWithLength
                length
                (fun length -> UnixSocket.tryGetsockopt caller fd level optionName value length system)
            |> Result.map SteppedCall.GetSockOpt
            |> Result.mapError SyscallRefusal.GetSockOpt
        | Syscall.Poll (entries, milliseconds) ->
            UnixPoll.tryPoll caller entries milliseconds system
            |> Result.map SteppedCall.Poll
            |> Result.mapError SyscallRefusal.Poll
        | Syscall.Select _ -> reserved "Syscall.Select"
        | Syscall.PSelect _ -> reserved "Syscall.PSelect"
        | Syscall.EpollCreate1 flags ->
            UnixPoll.tryEpollCreate1 caller flags system
            |> Result.map SteppedCall.EpollCreate1
            |> Result.mapError SyscallRefusal.EpollCreate1
        | Syscall.EpollCtl (epfd, op, fd, event) ->
            UnixPoll.tryEpollCtl caller epfd op fd event system
            |> Result.map SteppedCall.EpollCtl
            |> Result.mapError SyscallRefusal.EpollCtl
        | Syscall.EpollWait (epfd, buffer, maxEvents, milliseconds) ->
            UnixPoll.tryEpollWait caller epfd maxEvents buffer milliseconds system
            |> Result.map SteppedCall.EpollWait
            |> Result.mapError SyscallRefusal.EpollWait
        | Syscall.Kqueue ->
            UnixKqueue.tryKqueue caller system
            |> Result.map SteppedCall.Kqueue
            |> Result.mapError SyscallRefusal.Kqueue
        | Syscall.Kevent (kq, changes, nchanges, eventlist, nevents, timeout) ->
            UnixKqueue.tryKevent caller kq nchanges changes nevents eventlist timeout system
            |> Result.map SteppedCall.Kevent
            |> Result.mapError SyscallRefusal.Kevent
        | Syscall.InotifyInit1 flags ->
            UnixInotify.tryInotifyInit1 caller flags system
            |> Result.map SteppedCall.InotifyInit1
            |> Result.mapError SyscallRefusal.InotifyInit1
        | Syscall.InotifyAddWatch (fd, path, mask) ->
            UnixInotify.tryInotifyAddWatch caller fd mask system
            |> CallProgress.resumeWith (UnixInotify.tryInotifyAddWatchWithPath path)
            |> Result.map SteppedCall.InotifyAddWatch
            |> Result.mapError SyscallRefusal.InotifyAddWatch
        | Syscall.InotifyRmWatch (fd, wd) ->
            UnixInotify.tryInotifyRmWatch caller fd wd system
            |> Result.map SteppedCall.InotifyRmWatch
            |> Result.mapError SyscallRefusal.InotifyRmWatch
        | Syscall.Kill (pid, signo) ->
            UnixSignal.tryKill caller pid signo system
            |> Result.map SteppedCall.Kill
            |> Result.mapError SyscallRefusal.Kill
        | Syscall.PthreadKill (target, signo) ->
            UnixSignal.tryPthreadKill caller target signo system
            |> Result.map SteppedCall.PthreadKill
            |> Result.mapError SyscallRefusal.PthreadKill
        | Syscall.SigAction (signo, newAction) ->
            Ok (SteppedCall.SigAction (UnixSignal.sigaction caller signo newAction system))
        | Syscall.SigActionSyscall (signo, newAction) ->
            Ok (SteppedCall.SigActionSyscall (UnixSignal.sigactionSyscall caller signo newAction system))
        | Syscall.PthreadSigMask (how, set) ->
            Ok (SteppedCall.PthreadSigMask (UnixSignal.pthreadSigmask caller how set system))
        | Syscall.SigProcMask (how, set) ->
            UnixSignal.trySigprocmask caller how set system
            |> Result.map SteppedCall.SigProcMask
            |> Result.mapError SyscallRefusal.SigProcMask
        | Syscall.RtSigProcMask (how, set, sigsetSize) ->
            Ok (SteppedCall.RtSigProcMask (UnixSignal.rtSigprocmask caller how set sigsetSize system))
        | Syscall.SigPending -> Ok (SteppedCall.SigPending (UnixSignal.sigpending caller system))
        | Syscall.SigSuspend mask ->
            UnixSignal.trySigsuspend caller mask system
            |> Result.map SteppedCall.SigSuspend
            |> Result.mapError SyscallRefusal.SigSuspend
        | Syscall.RtSigSuspend (mask, sigsetSize) ->
            UnixSignal.tryRtSigsuspend caller mask sigsetSize system
            |> Result.map SteppedCall.RtSigSuspend
            |> Result.mapError SyscallRefusal.RtSigSuspend
        | Syscall.Pause ->
            UnixSignal.tryPause caller system
            |> Result.map SteppedCall.Pause
            |> Result.mapError SyscallRefusal.Pause
        | Syscall.SigReturn frame -> Ok (SteppedCall.SigReturn (UnixSignal.sigreturn caller frame system))
        | Syscall.SigWait _ -> reserved "Syscall.SigWait"
        | Syscall.SigWaitInfo _ -> reserved "Syscall.SigWaitInfo"
        | Syscall.SigTimedWait _ -> reserved "Syscall.SigTimedWait"
        | Syscall.ClockGetTime clockId ->
            UnixClock.tryClockGettime caller clockId system
            |> Result.map SteppedCall.ClockGetTime
            |> Result.mapError SyscallRefusal.ClockGetTime
        | Syscall.GetTimeOfDay -> Ok (SteppedCall.GetTimeOfDay (UnixClock.gettimeofday caller system))
        | Syscall.Nanosleep _ -> reserved "Syscall.Nanosleep"
        | Syscall.ClockNanosleep _ -> reserved "Syscall.ClockNanosleep"
        | Syscall.GetRandom (buffer, count, flags) ->
            UnixEntropy.tryGetRandom caller buffer count flags system
            |> Result.map SteppedCall.GetRandom
            |> Result.mapError SyscallRefusal.GetRandom
        | Syscall.GetEntropy (buffer, length) ->
            UnixEntropy.tryGetEntropy caller buffer length system
            |> Result.map SteppedCall.GetEntropy
            |> Result.mapError SyscallRefusal.GetEntropy
        | Syscall.GetProcessId -> Ok (SteppedCall.GetProcessId (processId caller system))
        | Syscall.UMask mask -> Ok (SteppedCall.UMask (umask caller mask system))
        | Syscall.GetResUid (real, effective, saved) ->
            UnixCredentials.tryGetresuid caller real effective saved system
            |> Result.map SteppedCall.GetResUid
            |> Result.mapError SyscallRefusal.GetResUid
        | Syscall.GetResGid (real, effective, saved) ->
            UnixCredentials.tryGetresgid caller real effective saved system
            |> Result.map SteppedCall.GetResGid
            |> Result.mapError SyscallRefusal.GetResGid
        | Syscall.SetResUid (real, effective, saved) ->
            UnixCredentials.trySetresuid caller real effective saved system
            |> Result.map SteppedCall.SetResUid
            |> Result.mapError SyscallRefusal.SetResUid
        | Syscall.SetResGid (real, effective, saved) ->
            UnixCredentials.trySetresgid caller real effective saved system
            |> Result.map SteppedCall.SetResGid
            |> Result.mapError SyscallRefusal.SetResGid
        | Syscall.SetGroups (size, words) ->
            UnixCredentials.trySetgroups caller size words system
            |> Result.map SteppedCall.SetGroups
            |> Result.mapError SyscallRefusal.SetGroups
        | Syscall.Spawn (child, cpu) ->
            UnixThreadLifecycle.trySpawn caller child cpu system
            |> Result.map SteppedCall.Spawn
            |> Result.mapError SyscallRefusal.Spawn
        | Syscall.ExitThread status ->
            UnixThreadLifecycle.tryExitThread caller status system
            |> Result.map SteppedCall.ExitThread
            |> Result.mapError SyscallRefusal.ExitThread
        | Syscall.ExitGroup status ->
            UnixThreadLifecycle.tryExitGroup caller status system
            |> Result.map SteppedCall.ExitGroup
            |> Result.mapError SyscallRefusal.ExitGroup
        | Syscall.GetCpu ->
            UnixScheduling.tryGetcpu caller system
            |> Result.map SteppedCall.GetCpu
            |> Result.mapError SyscallRefusal.GetCpu
        | Syscall.Futex (address, op, value, word, timeout) ->
            CopiedArgument.copyValue
                "UnixSystem.step of Syscall.Futex"
                UnixFutex.tryFutexWithWord
                word
                (fun buffer -> UnixFutex.tryFutex caller address op value buffer timeout system)
            |> Result.map SteppedCall.Futex
            |> Result.mapError SyscallRefusal.Futex

    /// <summary>
    /// Make the call `call` names, by `caller`, through that call's own
    /// function, and answer the `SteppedCall` case of the same name, holding
    /// what the function answers.
    /// </summary>
    /// <remarks>
    /// For a client that wants one surface to log, replay or generate calls
    /// through. Where a call's own function has a narrower type, or answers
    /// before the call copies from the caller's memory, that function is the
    /// one to prefer.
    ///
    /// A call that copies from the caller's memory reads what that memory held
    /// from `call`, where the call's function stops for it, and goes on through
    /// the function's resumption, so `step` never stops partway. A buffer the
    /// call reads is copied from where the paused call's `copyRange` says, so
    /// a `CopiedArgument.Readable` must hold at least the bytes up to the end
    /// of that range; it may hold more, which are not read.
    ///
    /// `caller` must be a thread of one of the system's processes, parked in no
    /// syscall and owing no return to user mode, whatever the call, as the
    /// call's own function requires. A call whose own function fails loudly on
    /// arguments no client following its documentation passes, such as a
    /// `SigReturn` of a frame that is not the thread's innermost, fails so
    /// through `step` too.
    ///
    /// A call that can end the process answers as its own function does: the
    /// `ProcessFate` of `Kill`, `PthreadKill` and `ExitThread` is
    /// `ProcessFate.ProcessEnded` when the call ended it, and `ExitGroup`
    /// answers how the process ended beside the system without it. A
    /// `SigSuspend`, `RtSigSuspend` or `Pause` may answer
    /// `SigsuspendOutcome.Interrupted`, and the thread then owes its return to
    /// user mode, as after the call made through its own function.
    ///
    /// A reserved case (`Syscall.Nanosleep`, `ClockNanosleep`, `Select`,
    /// `PSelect`, `SigWait`, `SigWaitInfo`, `SigTimedWait`, `RecvFrom`,
    /// `RecvMsg`, `SendTo` and `SendMsg`) is refused: this library does not
    /// model those calls yet.
    /// </remarks>
    /// <exception cref="T:System.InvalidOperationException">`caller` is not a thread of one of the system's processes, or is asleep in another syscall, or owes a return to user mode. A `CopiedArgument.Readable` buffer ends before the bytes the call copies from it do, or is the default `ImmutableArray`.</exception>
    /// <exception cref="T:System.PlatformNotSupportedException">The flavour has no `dup3`. This kernel is not Linux-flavoured, and only Linux has `copy_file_range`. This kernel is not Linux-flavoured, and `FICLONE` is a Linux request. This kernel is not Darwin-flavoured, and only Darwin has `clonefile`. This flavour has no such call: Darwin declares neither `setresuid` nor `setresgid`, nor `getresuid` nor `getresgid`. This kernel is of `flavour` (Darwin), which has no inotify: no Darwin kernel has the call, so there is no answer to measure. The simulated platform's libc has no `posix_fadvise` (`SimulatedUnixPlatform.providesPosixFadvise` is `false`), so no program could have made the call and there is no answer to give. This kernel is not Linux-flavoured, and only Linux has epoll. This kernel is not Darwin-flavoured, and only Darwin has kqueue. The simulated kernel has no `getrandom` system call, or no `getentropy` system call. This kernel is not Linux-flavoured, and only Linux has `getcpu`.</exception>
    let step<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (call : Syscall<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : SteppedCall<'Thread, 'Handler>
        =
        tryStep caller call system
        |> Refusal.orRaise "UnixSystem.step" SyscallRefusal.kind SyscallRefusal.describe

    /// Every way the machine's tables disagree with each other or with the
    /// processes on it: the clauses of `checkInvariants` that concern the
    /// machine, each of which reads facts that every process on it contributes
    /// to.
    ///
    /// The socket table and the pipe table against the open file descriptions,
    /// each pipe and the pipe device against the platform, the connection
    /// table against the sockets that reference it, the open file descriptions
    /// against the filesystem and the platform, each description against the
    /// descriptors and calls that reference it and its holds against every
    /// process's parks, the park and event registration ordinals against the
    /// machine's counters, the thread ID allocator against every process's
    /// threads, each processor's occupant against the threads, and the machine's
    /// filesystem type, buffer check and symbolic links against its platform.
    ///
    /// `processes` is every process on the machine, each with its threads.
    let internal machineDefects<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (processes : (UnixProcessState<'Thread, 'Handler> * Map<'Thread, UnixThreadState>) list)
        (scheduling : UnixSchedulingState)
        (machine : UnixMachineState)
        : UnixSystemDefect<'Thread> list
        =
        let allThreads : (Caller<'Thread> * UnixThreadState) list =
            processes
            |> List.collect (fun (proc, threads) ->
                threads
                |> Map.toList
                |> List.map (fun (thread, state) -> Caller.make proc.ProcessId thread, state)
            )


        let named =
            OpenFileTable.descriptions machine.OpenFiles
            |> Map.toList
            |> List.choose (fun (id, description) ->
                match description.Target with
                | OpenFileTarget.Kqueue _
                | OpenFileTarget.Epoll _
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Fifo _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Pipe _ -> None
                | OpenFileTarget.Socket socketId -> Some (id, socketId)
            )

        let dangling =
            named
            |> List.filter (fun (_, socketId) -> not (Map.containsKey socketId machine.Sockets))
            |> List.map UnixSystemDefect.DanglingSocket

        let namedIds = named |> List.map snd |> Set.ofList

        let unreferenced =
            machine.Sockets
            |> Map.toList
            |> List.map fst
            |> List.filter (fun socketId -> not (Set.contains socketId namedIds))
            |> List.map UnixSystemDefect.UnreferencedSocket

        // Against the table rather than against the descriptions: the table is
        // where a socket lives, so it is the table that must stay below the
        // counter even once a socket can outlive every descriptor of it.
        let freshness =
            machine.Sockets
            |> Map.toList
            |> List.map fst
            |> List.filter (fun socketId -> socketId >= machine.NextSocketId)
            |> List.map (fun socketId -> UnixSystemDefect.NextSocketIdNotFresh (machine.NextSocketId, socketId))

        let foreignObjects =
            let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

            OpenFileTable.descriptions machine.OpenFiles
            |> Map.toList
            |> List.choose (fun (id, description) ->
                match description.Target, flavour with
                | OpenFileTarget.Epoll _, SimulatedUnixFlavour.Darwin
                | OpenFileTarget.Inotify _, SimulatedUnixFlavour.Darwin
                | OpenFileTarget.Kqueue _, SimulatedUnixFlavour.Linux
                // Only Linux's devtmpfs holds a device's node.
                | OpenFileTarget.CharacterDevice _, SimulatedUnixFlavour.Darwin ->
                    Some (UnixSystemDefect.DescriptionNotOfFlavour (id, description.Target, flavour))
                | OpenFileTarget.Epoll _, SimulatedUnixFlavour.Linux
                | OpenFileTarget.Inotify _, SimulatedUnixFlavour.Linux
                | OpenFileTarget.Kqueue _, SimulatedUnixFlavour.Darwin
                | OpenFileTarget.CharacterDevice _, SimulatedUnixFlavour.Linux
                | OpenFileTarget.File _, _
                | OpenFileTarget.Directory _, _
                | OpenFileTarget.Socket _, _
                | OpenFileTarget.Fifo _, _
                | OpenFileTarget.Pipe _, _ -> None
            )

        let danglingInodes =
            machine.OpenFiles
            |> OpenFileTable.descriptions
            |> Map.toList
            |> List.choose (fun (id, description) ->
                match description.Target with
                | OpenFileTarget.File (inode, _) ->
                    match VirtualFileSystem.tryGetContent inode machine.FileSystem with
                    | None -> Some (UnixSystemDefect.DanglingOpenInode (id, inode))
                    | Some (InodeContent.Directory _)
                    | Some (InodeContent.CharacterDevice _)
                    | Some (InodeContent.Socket _)
                    | Some (InodeContent.Fifo _) -> Some (UnixSystemDefect.DescriptionKindMismatch (id, inode))
                    | Some (InodeContent.RegularFile _)
                    | Some (InodeContent.Symlink _) -> None
                | OpenFileTarget.Directory (inode, _) ->
                    match VirtualFileSystem.tryGetContent inode machine.FileSystem with
                    | None -> Some (UnixSystemDefect.DanglingOpenInode (id, inode))
                    | Some (InodeContent.Directory _) -> None
                    | Some (InodeContent.RegularFile _)
                    | Some (InodeContent.CharacterDevice _)
                    | Some (InodeContent.Socket _)
                    | Some (InodeContent.Fifo _)
                    | Some (InodeContent.Symlink _) -> Some (UnixSystemDefect.DescriptionKindMismatch (id, inode))
                | OpenFileTarget.CharacterDevice (inode, device, _) ->
                    match VirtualFileSystem.tryGetContent inode machine.FileSystem with
                    | None -> Some (UnixSystemDefect.DanglingOpenInode (id, inode))
                    | Some (InodeContent.CharacterDevice (node, _)) when node = device -> None
                    | Some (InodeContent.CharacterDevice _)
                    | Some (InodeContent.Directory _)
                    | Some (InodeContent.RegularFile _)
                    | Some (InodeContent.Socket _)
                    | Some (InodeContent.Fifo _)
                    | Some (InodeContent.Symlink _) -> Some (UnixSystemDefect.DescriptionKindMismatch (id, inode))
                | OpenFileTarget.Fifo (inode, _) ->
                    match VirtualFileSystem.tryGetContent inode machine.FileSystem with
                    | None -> Some (UnixSystemDefect.DanglingOpenInode (id, inode))
                    | Some (InodeContent.Fifo _) -> None
                    | Some (InodeContent.RegularFile _)
                    | Some (InodeContent.Directory _)
                    | Some (InodeContent.CharacterDevice _)
                    | Some (InodeContent.Socket _)
                    | Some (InodeContent.Symlink _) -> Some (UnixSystemDefect.DescriptionKindMismatch (id, inode))
                | OpenFileTarget.Kqueue _
                | OpenFileTarget.Epoll _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Socket _
                | OpenFileTarget.Pipe _ -> None
            )

        // The name each description onto an inode was opened through, against
        // the graph.
        let openedThrough =
            let graph = machine.FileSystem

            OpenFileTable.toSeqOpenedThrough machine.OpenFiles
            |> Seq.choose (fun (id, description, through) ->
                let inode =
                    match OpenFileDescription.object id description with
                    | OpenFileObject.File inode -> inode
                    | other ->
                        failwith
                            $"UnixSystem.checkInvariants: description %O{id} records the name it was opened through, and is onto %A{other}, not an inode, which OpenFileTable.create refuses (this is a bug in this library)."

                match through with
                | ReachedThrough.Name (dentry, false) ->
                    match VirtualFileSystem.tryGetDirectory dentry.Parent graph with
                    | Some parent when Map.tryFind dentry.Name parent.Entries = Some inode -> None
                    | Some _
                    | None -> Some (UnixSystemDefect.OpenedThroughNameUnbound (id, inode, dentry.Parent, dentry.Name))
                | ReachedThrough.Name (dentry, true) ->
                    match VirtualFileSystem.tryGetDirectory dentry.Parent graph with
                    | Some _ -> None
                    | None -> Some (UnixSystemDefect.OpenedThroughParentGone (id, dentry.Parent))
                | ReachedThrough.Unnamed ->
                    if
                        inode = VirtualFileSystem.root graph
                        || (VirtualFileSystem.mountOf inode graph).IsSome
                    then
                        None
                    else
                        Some (UnixSystemDefect.OpenedThroughNoNameNotRoot (id, inode))
                | ReachedThrough.RemovedDirectory oldParent ->
                    let named =
                        match VirtualFileSystem.tryGetDirectory oldParent graph with
                        | Some parent -> parent.Entries |> Map.exists (fun _ bound -> bound = inode)
                        | None -> false

                    match VirtualFileSystem.tryGetDirectory inode graph with
                    | Some directory when directory.Parent = oldParent && not named -> None
                    | Some _
                    | None -> Some (UnixSystemDefect.OpenedThroughRemovedDirectoryNamed (id, inode, oldParent))
            )
            |> List.ofSeq

        // The machine's inotify limits, and each user's instances and watches
        // and each instance's queue against them.
        let inotify =
            let limits = machine.InotifyLimits

            let limitsDefects =
                if InotifyLimits.admissible limits then
                    []
                else
                    [ UnixSystemDefect.InotifyLimitsNotAdmissible limits ]

            let instances =
                OpenFileTable.toSeq machine.OpenFiles
                |> Seq.choose (fun (id, description) ->
                    match description.Target with
                    | OpenFileTarget.Inotify state -> Some (id, state)
                    | OpenFileTarget.Epoll _
                    | OpenFileTarget.Kqueue _
                    | OpenFileTarget.File _
                    | OpenFileTarget.Directory _
                    | OpenFileTarget.Socket _
                    | OpenFileTarget.CharacterDevice _
                    | OpenFileTarget.Fifo _
                    | OpenFileTarget.Pipe _ -> None
                )
                |> Seq.toList

            let byUser = instances |> List.groupBy (fun (_, state) -> state.Owner)

            let instanceCounts =
                byUser
                |> List.choose (fun (user, held) ->
                    if List.length held > limits.MaxUserInstances then
                        Some (
                            UnixSystemDefect.InotifyInstancesBeyondLimit (
                                user,
                                List.length held,
                                limits.MaxUserInstances
                            )
                        )
                    else
                        None
                )

            let watchCounts =
                byUser
                |> List.choose (fun (user, held) ->
                    let watches = held |> List.sumBy (fun (_, state) -> Map.count state.Watches)

                    if watches > limits.MaxUserWatches then
                        Some (UnixSystemDefect.InotifyWatchesBeyondLimit (user, watches, limits.MaxUserWatches))
                    else
                        None
                )

            let queues =
                instances
                |> List.choose (fun (id, state) ->
                    let count = InotifyQueue.length state.Queue

                    if int64 count > int64 limits.MaxQueuedEvents + 1L then
                        Some (UnixSystemDefect.InotifyQueueBeyondLimit (id, count, limits.MaxQueuedEvents))
                    else
                        None
                )

            let forgottenWatches =
                instances
                |> List.collect (fun (id, state) ->
                    state.Watches
                    |> Map.toList
                    |> List.choose (fun (watch, watched) ->
                        match VirtualFileSystem.tryGet watched.Inode machine.FileSystem with
                        | Some _ -> None
                        | None -> Some (UnixSystemDefect.InotifyWatchOfForgottenInode (id, watch, watched.Inode))
                    )
                )

            limitsDefects @ instanceCounts @ watchCounts @ queues @ forgottenWatches

        // Every reference any socket makes to a connection: as the end it is
        // (`Some`), or through an accept queue (`None`), which has its own
        // defect case and its own no-duplicates rule.
        let connectionReferences =
            machine.Sockets
            |> Map.toList
            |> List.collect (fun (socketId, socket) ->
                match socket.Phase with
                | SocketPhase.Established (connection, connectionEnd) -> [ socketId, connection, Some connectionEnd ]
                | SocketPhase.EstablishedPendingReport connection ->
                    [ socketId, connection, Some ConnectionEnd.Client ]
                | SocketPhase.Listening listenState ->
                    ListenState.connections listenState
                    |> List.map (fun connection -> socketId, connection, None)
                | SocketPhase.Idle
                | SocketPhase.Refused _
                | SocketPhase.DatagramPeer _
                // A connect in flight has no connection yet.
                | SocketPhase.Connecting _ -> []
            )

        let danglingConnections =
            connectionReferences
            |> List.filter (fun (_, connection, _) -> not (Map.containsKey connection machine.Connections))
            |> List.map (fun (socketId, connection, heldAs) ->
                match heldAs with
                | None -> UnixSystemDefect.DanglingQueuedConnection (socketId, connection)
                | Some _ -> UnixSystemDefect.DanglingConnection (socketId, connection)
            )

        let referencedConnections =
            connectionReferences
            |> List.map (fun (_, connection, _) -> connection)
            |> Set.ofList

        let orphanConnections =
            machine.Connections
            |> Map.toList
            |> List.map fst
            |> List.filter (fun connection -> not (Set.contains connection referencedConnections))
            |> List.map UnixSystemDefect.OrphanConnection

        let duplicateQueued =
            connectionReferences
            |> List.choose (fun (_, connection, heldAs) ->
                match heldAs with
                | None -> Some connection
                | Some _ -> None
            )
            |> List.countBy id
            |> List.filter (fun (_, count) -> count > 1)
            |> List.map (fun (connection, _) -> UnixSystemDefect.DuplicateQueuedConnection connection)

        // A connection has one client and one server. Until `accept(2)` the
        // server end is the listener's queue entry, so the server end is held
        // once in all, queued or accepted. A listener counts once however
        // often it queues the connection: that is `DuplicateQueuedConnection`.
        let connectionEndsHeldTwice =
            connectionReferences
            |> List.groupBy (fun (_, connection, _) -> connection)
            |> List.collect (fun (connection, references) ->
                [ ConnectionEnd.Client ; ConnectionEnd.Server ]
                |> List.choose (fun connectionEnd ->
                    let holders =
                        references
                        |> List.choose (fun (socketId, _, heldAs) ->
                            let holdsThisEnd =
                                match heldAs with
                                | Some held -> held = connectionEnd
                                | None -> connectionEnd = ConnectionEnd.Server

                            if holdsThisEnd then Some socketId else None
                        )
                        |> List.distinct

                    if List.length holders > 1 then
                        Some (UnixSystemDefect.ConnectionEndHeldTwice (connection, connectionEnd, holders))
                    else
                        None
                )
            )

        // Each connection's transfer against its own rules, the machine's
        // flavour, and the sockets that are its ends: an end is closed exactly
        // when no socket holds it, a queued server end counting as held.
        let transferDefects =
            machine.Connections
            |> Map.toList
            |> List.collect (fun (connection, tcp) ->
                let broken =
                    match TcpTransfer.violations tcp.Transfer with
                    | [] -> []
                    | violations -> [ UnixSystemDefect.TcpTransferBroken (connection, violations) ]

                let rulesFlavour =
                    match tcp.Transfer.Rules with
                    | TcpTransferRules.Linux _ -> SimulatedUnixFlavour.Linux
                    | TcpTransferRules.Darwin _ -> SimulatedUnixFlavour.Darwin

                let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

                let ofFlavour =
                    if rulesFlavour = flavour then
                        []
                    else
                        [ UnixSystemDefect.TcpTransferNotOfFlavour (connection, rulesFlavour, flavour) ]

                let exchangeStamp =
                    match TcpTransfer.exchangeComplete tcp.Transfer, tcp.FinsExchangedAt with
                    | true, Some exchanged when exchanged <= scheduling.NanosecondsSinceBoot -> []
                    | false, None -> []
                    | _, recorded -> [ UnixSystemDefect.FinsExchangedAtDisagrees (connection, recorded) ]

                // An orphan has no holder of either end, which
                // `OrphanConnection` reports alone.
                let ends =
                    if not (Set.contains connection referencedConnections) then
                        []
                    else

                    [ ConnectionEnd.Client ; ConnectionEnd.Server ]
                    |> List.collect (fun connectionEnd ->
                        let holders =
                            connectionReferences
                            |> List.choose (fun (socketId, referenced, heldAs) ->
                                let holdsThisEnd =
                                    match heldAs with
                                    | Some held -> held = connectionEnd
                                    | None -> connectionEnd = ConnectionEnd.Server

                                if referenced = connection && holdsThisEnd then
                                    Some socketId
                                else
                                    None
                            )
                            |> List.distinct

                        match (TcpTransfer.towards connectionEnd tcp.Transfer).Receiver, holders with
                        | TcpEndState.Closed _, [] -> []
                        | TcpEndState.Closed _, holders ->
                            holders
                            |> List.map (fun socketId ->
                                UnixSystemDefect.ConnectionEndClosedUnderSocket (connection, connectionEnd, socketId)
                            )
                        | _, [] -> [ UnixSystemDefect.ConnectionEndOpenWithoutHolder (connection, connectionEnd) ]
                        | _, _ -> []
                    )

                broken @ ofFlavour @ exchangeStamp @ ends
            )

        // Each end in TIME_WAIT against the clock, the key it is filed under,
        // and the connections still on the machine; and the TIME_WAIT
        // sysctls against the flavour.
        let timeWaitDefects =
            let sysctls =
                match SimulatedUnixPlatform.flavour machine.UnixPlatform, machine.TcpTimeWait with
                | SimulatedUnixFlavour.Linux, TcpTimeWaitSysctls.Linux _
                | SimulatedUnixFlavour.Darwin, TcpTimeWaitSysctls.Darwin _ -> []
                | flavour, _ -> [ UnixSystemDefect.TimeWaitSysctlsNotOfFlavour flavour ]

            let entries =
                machine.TimeWaits
                |> Map.toList
                |> List.collect (fun ((local, remote), timeWait) ->
                    let misrecorded =
                        if
                            timeWait.Local <> local
                            || timeWait.Remote <> remote
                            || timeWait.EnteredAt > scheduling.NanosecondsSinceBoot
                        then
                            [ UnixSystemDefect.TimeWaitMisrecorded (local, remote) ]
                        else
                            []

                    let beside =
                        machine.Connections
                        |> Map.toList
                        |> List.choose (fun (connection, tcp) ->
                            if
                                not (UnixMachineState.resetReleasedTuple tcp)
                                && ((tcp.ClientAddress = local && tcp.ServerAddress = remote)
                                    || (tcp.ClientAddress = remote && tcp.ServerAddress = local))
                            then
                                Some (UnixSystemDefect.TimeWaitBesideConnection (local, remote, connection))
                            else
                                None
                        )

                    misrecorded @ beside
                )

            sysctls @ entries

        let phaseKindMismatches =
            machine.Sockets
            |> Map.toList
            |> List.choose (fun (socketId, socket) ->
                let mismatched =
                    match socket.Kind, socket.Phase with
                    | SocketKind.Datagram, SocketPhase.Idle
                    | SocketKind.Datagram, SocketPhase.DatagramPeer _ -> false
                    | SocketKind.Datagram, _ -> true
                    | _, SocketPhase.DatagramPeer _ -> true
                    | _, _ -> false

                if mismatched then
                    Some (UnixSystemDefect.SocketPhaseKindMismatch (socketId, socket.Kind, socket.Phase))
                else
                    None
            )

        let drainedUnderLinux =
            match SimulatedUnixPlatform.flavour machine.UnixPlatform with
            | SimulatedUnixFlavour.Darwin -> []
            | SimulatedUnixFlavour.Linux ->
                machine.Sockets
                |> Map.toList
                |> List.choose (fun (socketId, socket) ->
                    match socket.Phase with
                    | SocketPhase.Listening {
                                                Drained = true
                                            } -> Some (UnixSystemDefect.ListenerDrainedUnderLinux socketId)
                    | _ -> None
                )

        let connectionFreshness =
            machine.Connections
            |> Map.toList
            |> List.map fst
            |> List.filter (fun connection -> connection >= machine.NextConnectionId)
            |> List.map (fun connection ->
                UnixSystemDefect.NextConnectionIdNotFresh (machine.NextConnectionId, connection)
            )

        let registrationOrdinals =
            machine.OpenFiles
            |> OpenFileTable.descriptions
            |> Map.toList
            |> List.collect (fun (queueId, description) ->
                match description.Target with
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.Socket _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Fifo _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Pipe _ -> []
                | OpenFileTarget.Kqueue state ->
                    state.Registrations
                    |> Map.toList
                    |> List.map (fun (_, registration) -> queueId, registration.RegisteredAt)
                | OpenFileTarget.Epoll epollState ->
                    epollState.Registrations
                    |> Map.toList
                    |> List.map (fun (_, registration) -> queueId, registration.RegisteredAt)
            )

        let ordinalFreshness =
            registrationOrdinals
            |> List.filter (fun (_, registeredAt) -> registeredAt >= machine.NextEventRegistrationOrdinal)
            |> List.map (fun (queueId, registeredAt) ->
                UnixSystemDefect.EventRegistrationOrdinalNotFresh (
                    machine.NextEventRegistrationOrdinal,
                    queueId,
                    registeredAt
                )
            )

        let ordinalDuplicates =
            registrationOrdinals
            |> List.countBy snd
            |> List.filter (fun (_, count) -> count > 1)
            |> List.map (fun (registeredAt, _) -> UnixSystemDefect.DuplicateEventRegistrationOrdinal registeredAt)

        // Each description's status against the machine's flavour, and a
        // Darwin description's lock against the grant its status records.
        let statusOfFlavour =
            let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

            OpenFileTable.descriptions machine.OpenFiles
            |> Map.toList
            |> List.collect (fun (id, description) ->
                let status = description.Status

                let unrecorded =
                    match status with
                    | OpenFileStatus.Darwin (flocked = flocked) -> description.Flock.IsSome && not flocked
                    | OpenFileStatus.Linux _ -> false

                [
                    if OpenFileStatus.flavour status <> flavour then
                        yield UnixSystemDefect.StatusNotOfFlavour (id, status, flavour)
                    if unrecorded then
                        yield UnixSystemDefect.FlockHeldNotRecorded id
                ]
            )

        // Every description is referenced: by a descriptor, or by a call in
        // flight that holds it. Both counts are the description's own: the
        // descriptors', which `OpenFileTable.checkInvariants` holds to the
        // descriptor tables, and the holds, which `holdCounts` holds to the
        // parks.
        let unreferencedDescriptions =
            OpenFileTable.descriptions machine.OpenFiles
            |> Map.toList
            |> List.map fst
            |> List.filter (fun id ->
                OpenFileTable.descriptorCount id machine.OpenFiles = Some 0
                && OpenFileTable.holdCount id machine.OpenFiles = Some 0
            )
            |> List.map UnixSystemDefect.UnreferencedDescription

        // A socket whose release `SO_LINGER` could have refused is never left
        // for a call's return to release, which could not refuse it.
        let lingeringHeldOnlyByCalls =
            OpenFileTable.descriptions machine.OpenFiles
            |> Map.toList
            |> List.choose (fun (id, description) ->
                match description.Target with
                | OpenFileTarget.Socket socketId when
                    OpenFileTable.descriptorCount id machine.OpenFiles = Some 0
                    && OpenFileTable.holdCount id machine.OpenFiles
                       |> Option.exists (fun holds -> holds > 0)
                    ->
                    // A description onto an absent socket is `DanglingSocket`'s.
                    match Map.tryFind socketId machine.Sockets with
                    | Some socket when ObjectLifetime.lingerCanRefuseRelease socket ->
                        Some (UnixSystemDefect.LingeringSocketHeldOnlyByCalls (id, socketId))
                    | Some _
                    | None -> None
                | OpenFileTarget.Socket _
                | OpenFileTarget.Kqueue _
                | OpenFileTarget.Epoll _
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Fifo _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Pipe _ -> None
            )

        // Each description's holds against the parks of every process's threads:
        // one for each time a park names it. A park naming a description the
        // table does not hold is `ParkedOnAbsentDescription`'s.
        let holdCounts =
            let implied =
                allThreads
                |> List.collect (fun (_, state) ->
                    match state.Parked with
                    | None -> []
                    | Some park -> ParkedSyscall.descriptions park.Syscall
                )
                |> List.countBy id
                |> Map.ofList

            OpenFileTable.descriptions machine.OpenFiles
            |> Map.toList
            |> List.choose (fun (id, _) ->
                let recorded = OpenFileTable.holdCount id machine.OpenFiles |> Option.defaultValue 0
                let parks = Map.tryFind id implied |> Option.defaultValue 0

                if recorded = parks then
                    None
                else
                    Some (UnixSystemDefect.HoldCountMismatch (id, recorded, parks))
            )

        // Each sleeping Darwin poll's kqueue against the parks of every
        // process's threads: exactly one names it. A park naming one the machine
        // does not hold is `ParkedOnAbsentPollQueue`'s.
        let pollQueueParks =
            let parks =
                allThreads
                |> List.choose (fun (_, state) ->
                    match state.Parked with
                    | Some {
                               Syscall = ParkedSyscall.KqueuePoll poll
                           } -> Some poll.Queue
                    | Some _
                    | None -> None
                )
                |> List.countBy id
                |> Map.ofList

            machine.PollQueues
            |> Map.toList
            |> List.choose (fun (queue, _) ->
                match Map.tryFind queue parks |> Option.defaultValue 0 with
                | 1 -> None
                | count -> Some (UnixSystemDefect.PollQueueNotHeldOnce (queue, count))
            )

        let pollQueueFreshness =
            machine.PollQueues
            |> Map.toList
            |> List.filter (fun (queue, _) -> queue >= machine.NextPollQueueId)
            |> List.map (fun (queue, _) -> UnixSystemDefect.PollQueueIdNotFresh (machine.NextPollQueueId, queue))


        let parkOrdinals =
            allThreads
            |> List.choose (fun (thread, state) -> state.Parked |> Option.map (fun park -> thread, park.Ordinal))

        let parkOrdinalFreshness =
            parkOrdinals
            |> List.filter (fun (_, ordinal) -> ordinal >= machine.NextParkOrdinal)
            |> List.map (fun (thread, ordinal) ->
                UnixSystemDefect.ParkOrdinalNotFresh (machine.NextParkOrdinal, thread, ordinal)
            )

        let parkOrdinalDuplicates =
            parkOrdinals
            |> List.countBy snd
            |> List.filter (fun (_, count) -> count > 1)
            |> List.map (fun (ordinal, _) -> UnixSystemDefect.DuplicateParkOrdinal ordinal)

        // Addresses no bind, listen or connect could have produced.
        let bindings =
            machine.Sockets
            |> Map.toList
            |> List.collect (fun (socketId, socket) ->
                let unboundListener =
                    match socket.Phase with
                    | SocketPhase.Listening _ when not (SocketAddressing.isBound socket.Addressing) ->
                        [ UnixSystemDefect.ListenerWithoutBinding socketId ]
                    | _ -> []

                let unaddressable =
                    match socket.Addressing, socket.Phase with
                    | (SocketAddressing.Inet6V6Only _ | SocketAddressing.Unix _), SocketPhase.Idle
                    | (SocketAddressing.Inet _ | SocketAddressing.Inet6DualMode _), _ -> []
                    | (SocketAddressing.Inet6V6Only _ | SocketAddressing.Unix _) as addressing, phase ->
                        [ UnixSystemDefect.UnaddressableSocketInPhase (socketId, addressing, phase) ]

                let unmodelledBinding =
                    match socket.Addressing with
                    | SocketAddressing.Inet _
                    | SocketAddressing.Inet6DualMode None
                    | SocketAddressing.Inet6DualMode (Some (DualModeBinding.Mapped _))
                    | SocketAddressing.Inet6V6Only None
                    | SocketAddressing.Unix None -> []
                    | SocketAddressing.Inet6DualMode (Some (DualModeBinding.Native _))
                    | SocketAddressing.Inet6V6Only (Some _)
                    | SocketAddressing.Unix (Some _) ->
                        [ UnixSystemDefect.UnmodelledBindingHeld (socketId, socket.Addressing) ]

                let peerFamily =
                    match socket.Phase with
                    | SocketPhase.DatagramPeer peer ->
                        let peerDomain =
                            match peer with
                            | SocketAddress.Inet _ -> SocketDomain.Inet
                            | SocketAddress.Inet6 _ -> SocketDomain.Inet6
                            | SocketAddress.Unix _ -> SocketDomain.Unix

                        if peerDomain = socket.Domain then
                            []
                        else
                            [ UnixSystemDefect.DatagramPeerOfAnotherFamily (socketId, socket.Domain, peer) ]
                    | SocketPhase.Idle
                    | SocketPhase.Listening _
                    | SocketPhase.EstablishedPendingReport _
                    | SocketPhase.Established _
                    | SocketPhase.Refused _
                    | SocketPhase.Connecting _ -> []

                // Nothing in this version puts a socket in it.
                let reservedPhase =
                    match socket.Phase with
                    | SocketPhase.Connecting _ -> [ UnixSystemDefect.ReservedSocketPhase (socketId, socket.Phase) ]
                    | SocketPhase.Idle
                    | SocketPhase.Listening _
                    | SocketPhase.EstablishedPendingReport _
                    | SocketPhase.Established _
                    | SocketPhase.Refused _
                    | SocketPhase.DatagramPeer _ -> []

                let portZero =
                    match socket.Ipv4Binding with
                    | Some binding when binding.Endpoint.Port = 0us ->
                        let halfBound =
                            // Only Linux's `connect(AF_UNSPEC)` produces this,
                            // and it always leaves the socket idle.
                            SimulatedUnixPlatform.flavour machine.UnixPlatform = SimulatedUnixFlavour.Linux
                            && socket.Kind = SocketKind.Datagram
                            && socket.Phase = SocketPhase.Idle
                            && not binding.LockedPort
                            && (
                                match binding.LockedAddress with
                                | Some locked -> locked <> Ipv4Address.any && locked = binding.Endpoint.Address
                                | None -> false
                            )

                        if halfBound then
                            []
                        else
                            [ UnixSystemDefect.BoundToPortZero socketId ]
                    | _ -> []

                let portGivenBack =
                    match socket.Ipv4Binding with
                    | Some binding when not (PortHold.isHeld binding.PortHold) ->
                        let refusalLeftIt =
                            socket.Kind = SocketKind.Stream
                            && SimulatedUnixPlatform.refusalReleasesPort machine.UnixPlatform binding.LockedPort
                            && (
                                match socket.Phase, SimulatedUnixPlatform.flavour machine.UnixPlatform with
                                | SocketPhase.Refused _, _ -> true
                                | SocketPhase.Idle, SimulatedUnixFlavour.Linux -> true
                                | _ -> false
                            )

                        if refusalLeftIt then
                            []
                        else
                            [ UnixSystemDefect.PortGivenBackOutsideRefusal (socketId, socket.Phase) ]
                    | _ -> []

                unboundListener
                @ unaddressable
                @ unmodelledBinding
                @ peerFamily
                @ reservedPhase
                @ portZero
                @ portGivenBack
            )

        let fileSystemType =
            let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

            let fsType = EmulatedMount.fileSystemType machine.Mount

            if EmulatedFileSystemType.isReportableUnder flavour fsType then
                []
            else
                [ UnixSystemDefect.FileSystemTypeNotReportable (flavour, fsType) ]

        // The graph records which filesystem it has mounted, and the machine
        // the configuration of that mount; the two must name one filesystem.
        let deviceMount =
            let expected = DeviceFileSystemMount.mounted machine.DeviceMount

            VirtualFileSystem.mounts machine.FileSystem
            |> Map.toList
            |> List.filter (fun (_, mount) -> mount.FileSystem <> expected)
            |> List.map (fun (root, mount) -> UnixSystemDefect.MountNotDeviceMount (root, mount.FileSystem, expected))

        let protectedFiles =
            let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform

            if UnixMachineState.isProtectedFilesOf flavour machine.ProtectedFiles then
                []
            else
                [
                    UnixSystemDefect.ProtectedFilesNotOfFlavour (machine.ProtectedFiles, flavour)
                ]

        let userBufferCheck =
            if UnixMachineState.isUserBufferCheckOf machine.UnixPlatform machine.UserBufferCheck then
                []
            else
                [
                    UnixSystemDefect.UserBufferCheckNotOfPlatform (machine.UnixPlatform, machine.UserBufferCheck)
                ]

        // Every symbolic link's bits are ones its flavour creates a link with,
        // under the umask that would leave exactly those bits, unless the
        // flavour changes a link's bits afterwards, which makes any bits ones a
        // link can have.
        let symlinkPermissions =
            let platform = machine.UnixPlatform

            match SimulatedUnixPlatform.symlinkModeChange platform with
            | SymlinkModeChange.ChangesLink -> []
            | SymlinkModeChange.NotSupported ->

            VirtualFileSystem.inodes machine.FileSystem
            |> Map.toList
            |> List.choose (fun (inode, entry) ->
                match entry.Content with
                | InodeContent.Symlink (_, bits) ->
                    let umask =
                        PermissionBits.parseOrFail
                            "UnixSystem.checkInvariants"
                            (0o777 &&& ~~~(PermissionBits.toInt bits))

                    if SimulatedUnixPlatform.symlinkCreationPermissions platform umask = bits then
                        None
                    else
                        Some (
                            UnixSystemDefect.SymlinkPermissionsNotOfFlavour (
                                inode,
                                bits,
                                SimulatedUnixPlatform.flavour platform
                            )
                        )
                | InodeContent.RegularFile _
                | InodeContent.Directory _
                | InodeContent.Socket _
                | InodeContent.Fifo _
                | InodeContent.CharacterDevice _ -> None
            )

        // The machine's thread ID allocator against the threads of every process
        // on it: the allocator is its flavour's, no two threads share an ID, every
        // ID is one the counter could have handed out, and the IDs the
        // allocator records as live are exactly the threads', so none can be
        // handed out again while its thread lives.
        let threadIds =
            let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform
            let allocator = machine.ThreadIds

            let allocatorFlavour =
                match flavour, allocator.Counter with
                | SimulatedUnixFlavour.Linux, ThreadIdCounter.Linux _
                | SimulatedUnixFlavour.Darwin, ThreadIdCounter.Darwin _ -> []
                | SimulatedUnixFlavour.Linux, ThreadIdCounter.Darwin _
                | SimulatedUnixFlavour.Darwin, ThreadIdCounter.Linux _ ->
                    [ UnixSystemDefect.ThreadIdAllocatorNotOfFlavour (flavour, allocator) ]

            let duplicates =
                allThreads
                |> List.groupBy (fun (_, state) -> state.OsThreadId)
                |> List.choose (fun (id, holders) ->
                    match holders with
                    | []
                    | [ _ ] -> None
                    | _ -> Some (UnixSystemDefect.DuplicateOsThreadId (id, List.map fst holders))
                )

            let unmintable =
                allThreads
                |> List.filter (fun (_, state) -> not (ThreadIdAllocator.couldHaveMinted state.OsThreadId allocator))
                |> List.map (fun (thread, state) ->
                    UnixSystemDefect.OsThreadIdNotMintable (thread, state.OsThreadId, allocator)
                )

            let live =
                let held = allThreads |> List.map (fun (_, state) -> state.OsThreadId) |> Set.ofList
                let recorded = ThreadIdAllocator.live allocator

                if held = recorded then
                    []
                else
                    [
                        UnixSystemDefect.LiveThreadIdsMismatch (
                            Set.difference recorded held,
                            Set.difference held recorded
                        )
                    ]

            allocatorFlavour @ duplicates @ unmintable @ live

        // Each processor's occupant against the machine and the threads: the
        // processor is the machine's, the occupant is a live thread, and that
        // thread's processor is the one it occupies.
        let occupants =
            let byThreadId =
                allThreads
                |> List.map (fun (thread, state) -> state.OsThreadId, (thread, state))
                |> Map.ofList

            scheduling.Occupants
            |> Map.toList
            |> List.collect (fun (cpu, occupant) ->
                let beyond =
                    if UnixMachineState.hasProcessor cpu machine then
                        []
                    else
                        [
                            UnixSystemDefect.OccupiedCpuBeyondMachine (cpu, occupant, machine.ProcessorCount)
                        ]

                let thread =
                    match Map.tryFind occupant byThreadId with
                    | Some (thread, state) ->
                        if state.Cpu = cpu then
                            []
                        else
                            [ UnixSystemDefect.OccupantOnAnotherCpu (thread, cpu, state.Cpu) ]
                    | None -> [ UnixSystemDefect.OccupantWithoutThread (cpu, occupant) ]

                beyond @ thread
            )

        // The process table against the processes: the counter is the
        // flavour's, Darwin's is past every live ID, and the live IDs are the
        // processes'.
        let processIds =
            let flavour = SimulatedUnixPlatform.flavour machine.UnixPlatform
            let table = machine.ProcessIds

            let counter =
                match flavour, table.Counter with
                | SimulatedUnixFlavour.Linux, ProcessIdCounter.ThreadIds -> []
                | SimulatedUnixFlavour.Darwin, ProcessIdCounter.Darwin next ->
                    table.Live
                    |> Set.toList
                    |> List.filter (fun pid -> ProcessId.toInt32 pid >= next)
                    |> List.map (fun pid -> UnixSystemDefect.ProcessIdNotBelowCounter (pid, next))
                | SimulatedUnixFlavour.Linux, ProcessIdCounter.Darwin _
                | SimulatedUnixFlavour.Darwin, ProcessIdCounter.ThreadIds ->
                    [ UnixSystemDefect.ProcessIdCounterNotOfFlavour (flavour, table.Counter) ]

            let live =
                let held = processes |> List.map (fun (proc, _) -> proc.ProcessId) |> Set.ofList

                let recorded = ProcessIdTable.live table

                if held = recorded then
                    []
                else
                    [
                        UnixSystemDefect.LiveProcessIdsMismatch (
                            Set.difference recorded held,
                            Set.difference held recorded
                        )
                    ]

            counter @ live

        // The current directory holds against the processes standing in them.
        let currentDirectories =
            let standing =
                processes
                |> List.countBy (fun (proc, _) -> proc.CurrentDirectoryInode)
                |> Map.ofList

            Set.union (Map.keys standing |> Set.ofSeq) (Map.keys machine.CurrentDirectories |> Set.ofSeq)
            |> Set.toList
            |> List.choose (fun inode ->
                let recorded = Map.tryFind inode machine.CurrentDirectories |> Option.defaultValue 0
                let standing = Map.tryFind inode standing |> Option.defaultValue 0

                if recorded = standing then
                    None
                else
                    Some (UnixSystemDefect.CurrentDirectoryHoldMismatch (inode, recorded, standing))
            )

        // Every kqueue belongs to a live process, whose table its registrations
        // are read in.
        let kqueueOwners =
            OpenFileTable.toSeq machine.OpenFiles
            |> Seq.choose (fun (id, description) ->
                match description.Target with
                | OpenFileTarget.Kqueue state when
                    not (Set.contains state.Owner (ProcessIdTable.live machine.ProcessIds))
                    ->
                    Some (UnixSystemDefect.KqueueOwnerNotLive (id, state.Owner))
                | OpenFileTarget.Kqueue _
                | OpenFileTarget.Epoll _
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.Socket _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Fifo _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Pipe _ -> None
            )
            |> Seq.toList


        // The pipe table against the descriptions naming its pipes, and each
        // pipe against its machine, as for sockets above.
        let pipes =
            let platform = machine.UnixPlatform
            let flavour = SimulatedUnixPlatform.flavour platform

            let named =
                OpenFileTable.descriptions machine.OpenFiles
                |> Map.toList
                |> List.choose (fun (id, description) ->
                    match description.Target with
                    | OpenFileTarget.Pipe (pipeId, _) -> Some (id, pipeId)
                    | OpenFileTarget.Fifo _
                    | OpenFileTarget.Inotify _
                    | OpenFileTarget.Kqueue _
                    | OpenFileTarget.Epoll _
                    | OpenFileTarget.File _
                    | OpenFileTarget.Directory _
                    | OpenFileTarget.CharacterDevice _
                    | OpenFileTarget.Socket _ -> None
                )

            let dangling =
                named
                |> List.filter (fun (_, pipeId) -> not (Map.containsKey pipeId machine.Pipes))
                |> List.map UnixSystemDefect.DanglingPipe

            let namedIds = named |> List.map snd |> Set.ofList

            let unreferenced =
                machine.Pipes
                |> Map.toList
                |> List.filter (fun (pipeId, pipe) ->
                    not (Set.contains pipeId namedIds)
                    && not (PipeState.heldByClient PipeEnd.Read pipe)
                    && not (PipeState.heldByClient PipeEnd.Write pipe)
                )
                |> List.map (fst >> UnixSystemDefect.UnreferencedPipe)

            let undrained =
                machine.Pipes
                |> Map.toList
                |> List.choose (fun (pipeId, pipe) ->
                    let held = PipeBuffer.held pipe.Buffer

                    match PipeState.drainedBy pipe with
                    | Some _ when held > 0 -> Some (UnixSystemDefect.DrainedPipeHoldsBytes (pipeId, held))
                    | Some _
                    | None -> None
                )

            let unsupplied =
                machine.Pipes
                |> Map.toList
                |> List.filter (fun (_, pipe) -> PipeState.clientWriteCouldProceed pipe)
                |> List.map (fst >> UnixSystemDefect.SuppliedPipeHasRoom)

            let freshness =
                machine.Pipes
                |> Map.toList
                |> List.map fst
                |> List.filter (fun pipeId -> pipeId >= machine.NextPipeId)
                |> List.map (fun pipeId -> UnixSystemDefect.NextPipeIdNotFresh (machine.NextPipeId, pipeId))

            let inodes =
                machine.Pipes
                |> Map.toList
                |> List.collect (fun (pipeId, pipe) ->
                    match pipe.Origin with
                    | PipeOrigin.Launched _ -> []
                    | PipeOrigin.Made status ->
                        match status.Inodes with
                        | PipeInodes.Shared inode -> [ pipeId, inode ]
                        | PipeInodes.PerEnd (readEnd, writeEnd) -> [ pipeId, readEnd ; pipeId, writeEnd ]
                )

            let inodeFreshness =
                inodes
                |> List.filter (fun (_, inode) -> inode >= machine.NextPipeInode)
                |> List.map (fun (pipeId, inode) ->
                    UnixSystemDefect.PipeInodeNotFresh (machine.NextPipeInode, pipeId, inode)
                )

            let inodeDuplicates =
                inodes
                |> List.countBy snd
                |> List.filter (fun (_, count) -> count > 1)
                |> List.map (fun (inode, _) -> UnixSystemDefect.DuplicatePipeInode inode)

            let shapes =
                machine.Pipes
                |> Map.toList
                |> List.choose (fun (pipeId, pipe) ->
                    let inodesOfFlavour =
                        match pipe.Origin with
                        | PipeOrigin.Launched _ -> true
                        | PipeOrigin.Made status ->
                            match status.Inodes, flavour with
                            | PipeInodes.Shared _, SimulatedUnixFlavour.Linux
                            | PipeInodes.PerEnd _, SimulatedUnixFlavour.Darwin -> true
                            | PipeInodes.Shared _, SimulatedUnixFlavour.Darwin
                            | PipeInodes.PerEnd _, SimulatedUnixFlavour.Linux -> false

                    if inodesOfFlavour && PipeBuffer.isOf platform pipe.Buffer then
                        None
                    else
                        Some (UnixSystemDefect.PipeNotOfPlatform (pipeId, platform))
                )

            let device =
                let device = machine.PipeDevice

                let ofFlavour =
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> device >= 0L
                    | SimulatedUnixFlavour.Darwin -> device = 0L

                if ofFlavour then
                    []
                else
                    [ UnixSystemDefect.PipeDeviceNotOfFlavour (device, flavour) ]

            dangling
            @ unreferenced
            @ undrained
            @ unsupplied
            @ freshness
            @ inodeFreshness
            @ inodeDuplicates
            @ shapes
            @ device


        dangling
        @ unreferenced
        @ freshness
        @ foreignObjects
        @ danglingInodes
        @ openedThrough
        @ danglingConnections
        @ orphanConnections
        @ duplicateQueued
        @ connectionEndsHeldTwice
        @ transferDefects
        @ timeWaitDefects
        @ phaseKindMismatches
        @ drainedUnderLinux
        @ connectionFreshness
        @ ordinalFreshness
        @ ordinalDuplicates
        @ statusOfFlavour
        @ unreferencedDescriptions
        @ lingeringHeldOnlyByCalls
        @ holdCounts
        @ pollQueueParks
        @ pollQueueFreshness
        @ parkOrdinalFreshness
        @ parkOrdinalDuplicates
        @ bindings
        @ fileSystemType
        @ deviceMount
        @ protectedFiles
        @ symlinkPermissions
        @ userBufferCheck
        @ threadIds
        @ occupants
        @ processIds
        @ currentDirectories
        @ kqueueOwners
        @ pipes
        @ inotify


    /// Every way one process disagrees with itself or with the machine: the
    /// clauses of `checkInvariants` that concern the process `system` is the
    /// view of. The current directory against the filesystem, each
    /// descriptor against the bound and the flavour's descriptor flags, each
    /// thread's park against the descriptor table and the machine, each kqueue
    /// a descriptor or a `kevent` wait names against its owner, the signal
    /// state against the thread table, the leader against the threads, each thread's
    /// processor against the machine's, and the process's supplementary groups
    /// and file-mode creation mask against its platform.
    let private processDefects<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        : UnixSystemDefect<'Thread> list
        =
        let pid = system.ProcessId

        let caller (thread : 'Thread) : Caller<'Thread> = Caller.make pid thread


        let currentDirectory =
            match VirtualFileSystem.tryGetContent system.Process.CurrentDirectoryInode system.Machine.FileSystem with
            | Some (InodeContent.Directory _) -> []
            | Some (InodeContent.RegularFile _)
            | Some (InodeContent.Socket _)
            | Some (InodeContent.Fifo _)
            | Some (InodeContent.CharacterDevice _)
            | Some (InodeContent.Symlink _)
            | None ->
                [
                    UnixSystemDefect.CurrentDirectoryIsNotADirectory (pid, system.Process.CurrentDirectoryInode)
                ]

        let beyondBound =
            let bound = SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform

            FileDescriptorRegistry.fds (UnixSystemState.fileDescriptors system)
            |> Map.toList
            |> List.filter (fun (fd, _) -> fd >= bound)
            |> List.map (fun (fd, _) -> UnixSystemDefect.DescriptorAtOrAboveBound (pid, fd, bound))

        // Each descriptor's flags against the machine's flavour.
        let flagsOfFlavour =
            let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
            let registry = UnixSystemState.fileDescriptors system

            FileDescriptorRegistry.fds registry
            |> Map.toList
            |> List.choose (fun (fd, _) ->
                match FileDescriptorRegistry.tryFindFlags fd registry with
                | Some flags when DescriptorFlags.flavour flags <> flavour ->
                    Some (UnixSystemDefect.DescriptorFlagsNotOfFlavour (pid, fd, flags, flavour))
                | Some _
                | None -> None
            )


        // Each thread's park against the descriptor table. A park names what the
        // thread waits on, and the wake reads the description back; the park
        // holds it until the call returns, so an absent one was parked on
        // without going through the syscall or destroyed around it.
        let parks =
            let descriptions = OpenFileTable.descriptions system.Machine.OpenFiles

            let darwin =
                match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
                | SimulatedUnixFlavour.Linux -> false
                | SimulatedUnixFlavour.Darwin -> true

            // Under Darwin a close of the descriptor a sleeping accept, or pipe
            // or connection transfer, was made through ends the call, so while it sleeps the
            // descriptor still names what it sleeps on. Under Linux the close
            // leaves it asleep, and the number is not consulted.
            let enteredThrough (thread : 'Thread) (fd : int) (description : OpenFileDescriptionId) =
                match FileDescriptorRegistry.tryFindId fd (UnixSystemState.fileDescriptors system) with
                | Some current when current = description -> []
                | _ when not darwin -> []
                | current ->
                    [
                        UnixSystemDefect.ParkedCallDescriptorRebound (caller thread, fd, description, current)
                    ]

            let endedByClose (thread : 'Thread) =
                if darwin then
                    []
                else
                    [ UnixSystemDefect.ParkedCallEndedByCloseUnderLinux (caller thread) ]

            // What is wrong with what a connection transfer sleeps on.
            let connectionTarget (thread : 'Thread) (target : SleepTarget<SocketId>) =
                match target with
                | SleepTarget.EndedByClose _ -> endedByClose thread
                | SleepTarget.Waiting (description, fd) ->

                match Map.tryFind description descriptions with
                | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, description) ]
                | Some found ->
                    let connected =
                        match found.Target with
                        | OpenFileTarget.Socket socketId ->
                            match Map.tryFind socketId system.Machine.Sockets with
                            | Some socket -> (SocketPhase.connectionEnd socket.Phase).IsSome
                            | None -> false
                        | OpenFileTarget.File _
                        | OpenFileTarget.Directory _
                        | OpenFileTarget.CharacterDevice _
                        | OpenFileTarget.Fifo _
                        | OpenFileTarget.Inotify _
                        | OpenFileTarget.Pipe _
                        | OpenFileTarget.Kqueue _
                        | OpenFileTarget.Epoll _ -> false

                    if connected then
                        enteredThrough thread fd description
                    else
                        [
                            UnixSystemDefect.ParkedConnectionTransferOnNonConnection (caller thread, description)
                        ]

            system.Threads
            |> Map.toList
            |> List.collect (fun (thread, state) ->
                match state.Parked |> Option.map (fun park -> park.Syscall) with
                | None -> []
                // Names no description.
                | Some ParkedSyscall.SigSuspend
                | Some (ParkedSyscall.Futex _) -> []
                | Some (ParkedSyscall.Sleep _ as parked)
                | Some (ParkedSyscall.FifoOpen _ as parked)
                | Some (ParkedSyscall.Select _ as parked)
                | Some (ParkedSyscall.SignalWait _ as parked)
                | Some (ParkedSyscall.DatagramReceive _ as parked)
                | Some (ParkedSyscall.DatagramSend _ as parked)
                | Some (ParkedSyscall.Connect _ as parked) -> [ UnixSystemDefect.ReservedPark (caller thread, parked) ]
                | Some (ParkedSyscall.InotifyRead read) ->
                    match Map.tryFind read.Instance descriptions with
                    | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, read.Instance) ]
                    | Some description ->
                        match description.Target with
                        | OpenFileTarget.Inotify _ -> []
                        | OpenFileTarget.Epoll _
                        | OpenFileTarget.Kqueue _
                        | OpenFileTarget.File _
                        | OpenFileTarget.Directory _
                        | OpenFileTarget.Socket _
                        | OpenFileTarget.CharacterDevice _
                        | OpenFileTarget.Fifo _
                        | OpenFileTarget.Pipe _ ->
                            [
                                UnixSystemDefect.ParkedInotifyReadOnNonInotify (
                                    caller thread,
                                    read.Instance,
                                    description.Target
                                )
                            ]
                | Some (ParkedSyscall.Flock parked) ->
                    if Map.containsKey parked.Requester descriptions then
                        []
                    else
                        [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, parked.Requester) ]
                | Some (ParkedSyscall.EpollWait wait) ->
                    match Map.tryFind wait.Epoll descriptions with
                    | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, wait.Epoll) ]
                    | Some description ->
                        match description.Target with
                        | OpenFileTarget.Epoll _ -> []
                        | OpenFileTarget.Kqueue _
                        | OpenFileTarget.File _
                        | OpenFileTarget.Directory _
                        | OpenFileTarget.Socket _
                        | OpenFileTarget.CharacterDevice _
                        | OpenFileTarget.Fifo _
                        | OpenFileTarget.Inotify _
                        | OpenFileTarget.Pipe _ ->
                            [
                                UnixSystemDefect.ParkedEpollWaitOnNonEpoll (
                                    caller thread,
                                    wait.Epoll,
                                    description.Target
                                )
                            ]
                | Some (ParkedSyscall.Kevent wait) ->
                    let count =
                        if wait.MaxEvents > 0 then
                            []
                        else
                            [
                                UnixSystemDefect.ParkedKeventCountNotPositive (caller thread, wait.MaxEvents)
                            ]

                    let target =
                        match Map.tryFind wait.Kqueue descriptions with
                        | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, wait.Kqueue) ]
                        | Some description ->
                            match description.Target with
                            | OpenFileTarget.Kqueue state ->
                                match
                                    FileDescriptorRegistry.tryFindId wait.Fd (UnixSystemState.fileDescriptors system)
                                with
                                | Some current when current = wait.Kqueue -> []
                                | _ when state.Drained -> []
                                | current ->
                                    [
                                        UnixSystemDefect.ParkedKeventDescriptorRebound (
                                            caller thread,
                                            wait.Fd,
                                            wait.Kqueue,
                                            current
                                        )
                                    ]
                            | OpenFileTarget.Epoll _
                            | OpenFileTarget.File _
                            | OpenFileTarget.Directory _
                            | OpenFileTarget.CharacterDevice _
                            | OpenFileTarget.Socket _
                            | OpenFileTarget.Fifo _
                            | OpenFileTarget.Inotify _
                            | OpenFileTarget.Pipe _ ->
                                [
                                    UnixSystemDefect.ParkedKeventOnNonKqueue (
                                        caller thread,
                                        wait.Kqueue,
                                        description.Target
                                    )
                                ]

                    count @ target
                | Some (ParkedSyscall.Poll parked) ->
                    parked.Entries
                    |> List.collect (fun entry ->
                        match entry with
                        | ParkedPollEntry.Ignored _ -> []
                        | ParkedPollEntry.Watched (fd, watched, _) ->
                            match Map.tryFind watched descriptions with
                            | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, watched) ]
                            | Some description ->
                                let target =
                                    match description.Target with
                                    | OpenFileTarget.Kqueue _
                                    | OpenFileTarget.Epoll _ ->
                                        [ UnixSystemDefect.ParkedPollOnEventQueue (caller thread, watched) ]
                                    | OpenFileTarget.File _
                                    | OpenFileTarget.Directory _
                                    | OpenFileTarget.Socket _
                                    | OpenFileTarget.CharacterDevice _
                                    | OpenFileTarget.Fifo _
                                    | OpenFileTarget.Inotify _
                                    | OpenFileTarget.Pipe _ -> []

                                let rebound =
                                    match
                                        FileDescriptorRegistry.tryFindId fd (UnixSystemState.fileDescriptors system)
                                    with
                                    | Some current when current = watched -> []
                                    | current ->
                                        [
                                            UnixSystemDefect.ParkedPollDescriptorRebound (
                                                caller thread,
                                                fd,
                                                watched,
                                                current
                                            )
                                        ]

                                target @ rebound
                    )
                | Some (ParkedSyscall.KqueuePoll poll) ->
                    match Map.tryFind poll.Queue system.Machine.PollQueues with
                    | None -> [ UnixSystemDefect.ParkedOnAbsentPollQueue (caller thread, poll.Queue) ]
                    | Some queue when queue.Owner <> system.Process.ProcessId ->
                        [
                            UnixSystemDefect.PollQueueOfAnotherProcess (caller thread, poll.Queue, queue.Owner)
                        ]
                    | Some queue ->

                    let entries = List.length poll.Entries

                    let socketOf (fd : int) : SocketId option =
                        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
                        | Some (OpenFileTarget.Socket socketId) -> Some socketId
                        | Some _
                        | None -> None

                    let attachments =
                        queue.Registrations
                        |> Map.toList
                        |> List.choose (fun ((fd, _ as key), registration) ->
                            let named = socketOf fd

                            // A closed descriptor is `ParkedKqueuePollRegistrationTarget`'s.
                            let fdOpen =
                                (FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system))
                                    .IsSome

                            if registration.Socket = named || not fdOpen then
                                None
                            else
                                Some (
                                    UnixSystemDefect.ParkedKqueuePollAttachedElsewhere (
                                        caller thread,
                                        key,
                                        registration.Socket,
                                        named
                                    )
                                )
                        )

                    let registrations =
                        queue.Registrations
                        |> Map.toList
                        |> List.collect (fun ((fd, filter as key), registration) ->
                            let target =
                                match
                                    FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system)
                                with
                                | Some (OpenFileTarget.Socket socketId) as target ->
                                    match Map.tryFind socketId system.Machine.Sockets with
                                    | Some socket when DarwinReadiness.modelsSocket socket ->
                                        if
                                            not (List.contains key queue.Active)
                                            && Option.isSome (DarwinReadiness.ofSocket filter socketId system.Machine)
                                        then
                                            [ UnixSystemDefect.ParkedKqueuePollActivationMissed (caller thread, key) ]
                                        else
                                            []
                                    | Some _
                                    | None ->
                                        [
                                            UnixSystemDefect.ParkedKqueuePollRegistrationTarget (
                                                caller thread,
                                                fd,
                                                target
                                            )
                                        ]
                                | Some (OpenFileTarget.Pipe _) -> []
                                | target ->
                                    [
                                        UnixSystemDefect.ParkedKqueuePollRegistrationTarget (
                                            caller thread,
                                            fd,
                                            target
                                        )
                                    ]

                            let entry =
                                if registration.Entry >= 0 && registration.Entry < entries then
                                    []
                                else
                                    [
                                        UnixSystemDefect.ParkedKqueuePollEntryOutOfRange (
                                            caller thread,
                                            key,
                                            registration.Entry
                                        )
                                    ]

                            target @ entry
                        )

                    let active =
                        queue.Active
                        |> List.indexed
                        |> List.choose (fun (index, (fd, _ as key)) ->
                            let repeated = queue.Active |> List.take index |> List.contains key

                            if
                                repeated
                                || not (Map.containsKey key queue.Registrations)
                                || Option.isNone (socketOf fd)
                            then
                                Some (UnixSystemDefect.ParkedKqueuePollActiveMalformed (caller thread, key))
                            else
                                None
                        )

                    attachments @ registrations @ active
                | Some (ParkedSyscall.Accept accept) ->
                    match accept.Listener with
                    | SleepTarget.EndedByClose _ -> endedByClose thread
                    | SleepTarget.Waiting (listener, fd) ->

                    match Map.tryFind listener descriptions with
                    | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, listener) ]
                    | Some description ->
                        let listening =
                            match description.Target with
                            | OpenFileTarget.Socket socketId ->
                                match Map.tryFind socketId system.Machine.Sockets with
                                | Some {
                                           Phase = SocketPhase.Listening listenState
                                       } -> Some listenState.Drained
                                | Some _
                                | None -> None
                            | OpenFileTarget.File _
                            | OpenFileTarget.Directory _
                            | OpenFileTarget.CharacterDevice _
                            | OpenFileTarget.Fifo _
                            | OpenFileTarget.Inotify _
                            | OpenFileTarget.Pipe _
                            | OpenFileTarget.Kqueue _
                            | OpenFileTarget.Epoll _ -> None

                        match listening with
                        | None -> [ UnixSystemDefect.ParkedAcceptOnNonListener (caller thread, listener) ]
                        | Some true -> [ UnixSystemDefect.ParkedAcceptOnDrainedListener (caller thread, listener) ]
                        | Some false -> enteredThrough thread fd listener
                | Some (ParkedSyscall.PipeRead read) ->
                    let progress =
                        if read.Count > 0 then
                            []
                        else
                            [ UnixSystemDefect.ParkedPipeTransferProgress (caller thread, read.Count, 0) ]

                    let target =
                        match read.Reader with
                        | SleepTarget.EndedByClose _ -> endedByClose thread
                        | SleepTarget.Waiting (reader, fd) ->

                        match Map.tryFind reader descriptions with
                        | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, reader) ]
                        | Some description ->
                            match description.Target with
                            | OpenFileTarget.Pipe (_, PipeEnd.Read) -> enteredThrough thread fd reader
                            | target ->
                                [
                                    UnixSystemDefect.ParkedPipeTransferOnWrongTarget (caller thread, reader, target)
                                ]

                    progress @ target
                | Some (ParkedSyscall.PipeWrite write) ->
                    let progress =
                        if write.Written >= 0 && write.Written < write.Count then
                            []
                        else
                            [
                                UnixSystemDefect.ParkedPipeTransferProgress (caller thread, write.Count, write.Written)
                            ]

                    let target =
                        match write.Writer with
                        | SleepTarget.EndedByClose _ -> endedByClose thread
                        | SleepTarget.Waiting (writer, fd) ->

                        match Map.tryFind writer descriptions with
                        | None -> [ UnixSystemDefect.ParkedOnAbsentDescription (caller thread, writer) ]
                        | Some description ->
                            match description.Target with
                            | OpenFileTarget.Pipe (_, PipeEnd.Write) -> enteredThrough thread fd writer
                            | target ->
                                [
                                    UnixSystemDefect.ParkedPipeTransferOnWrongTarget (caller thread, writer, target)
                                ]

                    progress @ target
                | Some (ParkedSyscall.ConnectionRead read) ->
                    // Only a Linux `recv` sleeps asking for nothing.
                    let mayAskNothing =
                        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform, read.Call with
                        | SimulatedUnixFlavour.Linux, TcpReceiveCall.Receive
                        | SimulatedUnixFlavour.Linux, TcpReceiveCall.Peek -> true
                        | SimulatedUnixFlavour.Linux, TcpReceiveCall.Read
                        | SimulatedUnixFlavour.Darwin, _ -> false

                    let progress =
                        if read.Count > 0 || (read.Count = 0 && mayAskNothing) then
                            []
                        else
                            [
                                UnixSystemDefect.ParkedConnectionTransferProgress (caller thread, read.Count, 0)
                            ]

                    progress @ connectionTarget thread read.Socket
                | Some (ParkedSyscall.ConnectionWrite write) ->
                    let progress =
                        if write.Written >= 0 && write.Written < write.Count then
                            []
                        else
                            [
                                UnixSystemDefect.ParkedConnectionTransferProgress (
                                    caller thread,
                                    write.Count,
                                    write.Written
                                )
                            ]

                    progress @ connectionTarget thread write.Socket
            )


        // Every kqueue a descriptor of this process names, or a `kevent` wait of
        // one of its threads sleeps on, is one this process owns, since its
        // registrations' descriptor numbers are read in its owner's table.
        let kqueueOwners =
            let ownedElsewhere (kqueue : OpenFileDescriptionId) : ProcessId option =
                match OpenFileTable.tryFind kqueue system.Machine.OpenFiles with
                | Some {
                           Target = OpenFileTarget.Kqueue state
                       } when state.Owner <> system.Process.ProcessId -> Some state.Owner
                | Some _
                | None -> None

            let named =
                FileDescriptorRegistry.fds (UnixSystemState.fileDescriptors system)
                |> Map.toList
                |> List.choose (fun (fd, kqueue) ->
                    ownedElsewhere kqueue
                    |> Option.map (fun owner -> UnixSystemDefect.KqueueOfAnotherProcess (pid, fd, kqueue, owner))
                )

            let waited =
                system.Threads
                |> Map.toList
                |> List.choose (fun (_, state) ->
                    match state.Parked with
                    | Some {
                               Syscall = ParkedSyscall.Kevent wait
                           } ->
                        ownedElsewhere wait.Kqueue
                        |> Option.map (fun owner ->
                            UnixSystemDefect.KqueueOfAnotherProcess (pid, wait.Fd, wait.Kqueue, owner)
                        )
                    | Some _
                    | None -> None
                )

            List.distinct (named @ waited)


        // The signal state against the thread table: every thread it names must
        // be one, or the delivery that reads it has nowhere to go.
        let signals =
            let signals = system.Process.Signals

            let frames =
                SignalState.threadsWithFrames signals
                |> Set.toList
                |> List.filter (fun thread -> not (Map.containsKey thread system.Threads))
                |> List.map (caller >> UnixSystemDefect.HandlerFramesWithoutThread)

            let masks =
                SignalState.threadsWithMasks signals
                |> Set.toList
                |> List.filter (fun thread -> not (Map.containsKey thread system.Threads))
                |> List.map (caller >> UnixSystemDefect.MaskWithoutThread)

            // A mask to restore exists from a `sigsuspend` until its thread
            // returns to user mode, so exactly while the thread is parked in the
            // call or has been answered and not yet returned; which of those
            // two is true is the client's, so what is checked is that no thread
            // parked in anything else has one, and every thread parked in it does.
            let toRestore =
                let restoring = SignalState.threadsWithMasksToRestore signals

                let orphaned =
                    restoring
                    |> Set.toList
                    |> List.filter (fun thread -> not (Map.containsKey thread system.Threads))
                    |> List.map (caller >> UnixSystemDefect.MaskToRestoreWithoutThread)

                let parked =
                    system.Threads
                    |> Map.toList
                    |> List.choose (fun (thread, state) ->
                        match UnixThreadState.park state with
                        | Some {
                                   Syscall = ParkedSyscall.SigSuspend
                               } when not (Set.contains thread restoring) ->
                            Some (UnixSystemDefect.SigsuspendWithoutMaskToRestore (caller thread))
                        | Some {
                                   Syscall = ParkedSyscall.SigSuspend
                               } -> None
                        | Some park when Set.contains thread restoring ->
                            Some (UnixSystemDefect.MaskToRestoreOutsideSigsuspend (caller thread, park.Syscall))
                        | Some _
                        | None -> None
                    )

                orphaned @ parked

            let targets =
                SignalState.pending signals
                |> List.choose (fun entry ->
                    match entry.Target with
                    | ValueSome thread when not (Map.containsKey thread system.Threads) ->
                        Some (UnixSystemDefect.PendingSignalTargetWithoutThread (caller thread, entry.Signal))
                    | ValueSome _
                    | ValueNone -> None
                )

            // A thread owes its return to user mode from the moment a signal
            // is deliverable to it, so one in no syscall that owes nothing has
            // none. Not the other way round: a thread whose signal another
            // thread has since discarded still owes its return, which then
            // takes nothing.
            let undue =
                system.Threads
                |> Map.toList
                |> List.choose (fun (thread, state) ->
                    match state.Parked, state.Owes with
                    | None, None ->
                        match OwedReturns.deliverable thread system with
                        | ValueSome signal ->
                            Some (UnixSystemDefect.SignalDeliverableWithoutOwedReturn (caller thread, signal))
                        | ValueNone -> None
                    | Some _, _
                    | None, Some _ -> None
                )

            frames @ masks @ toRestore @ targets @ undue

        let supplementaryGroups =
            let count = List.length system.Process.Credentials.SupplementaryGroups

            let limit =
                SimulatedUnixPlatform.supplementaryGroupLimit system.Machine.UnixPlatform

            if count > limit then
                [ UnixSystemDefect.TooManySupplementaryGroups (pid, count, limit) ]
            else
                []

        let umask =
            let platform = system.Machine.UnixPlatform
            let stored = PermissionBits.toInt (SimulatedUnixPlatform.umaskStoredBits platform)

            if PermissionBits.toInt system.Process.Umask &&& ~~~stored <> 0 then
                [ UnixSystemDefect.UmaskNotOfPlatform (pid, system.Process.Umask, platform) ]
            else
                []

        // The process's leader against its threads: it is one, and on Linux its
        // thread ID is the process ID.
        let leader =
            match Map.tryFind system.Leader system.Threads with
            | None -> [ UnixSystemDefect.LeaderWithoutThread (caller system.Leader) ]
            | Some state ->
                match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
                | SimulatedUnixFlavour.Linux when
                    OsThreadId.toUInt64 state.OsThreadId
                    <> uint64 (ProcessId.toInt32 system.Process.ProcessId)
                    ->
                    [
                        UnixSystemDefect.LeaderThreadIdNotProcessId (
                            caller system.Leader,
                            state.OsThreadId,
                            system.Process.ProcessId
                        )
                    ]
                | SimulatedUnixFlavour.Linux
                | SimulatedUnixFlavour.Darwin -> []

        let cpus =
            system.Threads
            |> Map.toList
            |> List.filter (fun (_, state) -> not (UnixMachineState.hasProcessor state.Cpu system.Machine))
            |> List.map (fun (thread, state) ->
                UnixSystemDefect.CpuBeyondMachine (caller thread, state.Cpu, system.Machine.ProcessorCount)
            )

        currentDirectory
        @ beyondBound
        @ flagsOfFlavour
        @ parks
        @ kqueueOwners
        @ signals
        @ supplementaryGroups
        @ umask
        @ leader
        @ cpus


    /// Every way this system's tables disagree with each other: the machine's
    /// clauses, which read facts every process on the machine contributes to;
    /// each process's own, read against the machine; each process's
    /// descriptor table's, a descriptor naming a description the machine does
    /// not hold, and a registration of a kqueue the process owns made through
    /// a descriptor that is closed or names no socket; the open file table's
    /// own rules, read against every process's descriptor table; and that each
    /// process is held under its own process ID, and no two have one.
    ///
    /// The filesystem's own rules are `VirtualFileSystem.checkInvariants`'s,
    /// and are not repeated here. It takes a `pinned` argument, which is what
    /// `pinnedInodes` computes, so a caller wanting the whole picture pairs this
    /// with
    /// `VirtualFileSystem.checkInvariants (ObjectLifetime.pinnedInodes system) system.Machine.FileSystem`.
    ///
    /// A client that holds its own references into these tables owes its own
    /// rules about them on top of these.
    let checkInvariants<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystemDefect<'Thread> list
        =
        let slots =
            system.Processes
            |> Map.toList
            |> List.map (fun (key, slot) -> ProcessId.parseOrFail "UnixSystem.checkInvariants" key, slot)

        let machine =
            machineDefects
                (slots |> List.map (fun (_, slot) -> slot.Process, slot.Threads))
                system.Scheduling
                system.Machine

        let processes =
            slots
            |> List.collect (fun (pid, slot) -> processDefects (ProcessView.ofSlot pid slot system))

        let tables =
            slots
            |> List.collect (fun (pid, slot) ->
                FileDescriptorRegistry.ofTables slot.Process.FileDescriptors system.Machine.OpenFiles
                |> FileDescriptorRegistry.checkDescriptorTableInvariants slot.Process.ProcessId
                |> List.map (fun defect -> UnixSystemDefect.DescriptorTable (pid, defect))
            )

        let openFiles =
            OpenFileTable.checkInvariants
                (slots |> List.map (fun (_, slot) -> slot.Process.FileDescriptors))
                system.Machine.OpenFiles
            |> List.map UnixSystemDefect.OpenFiles

        let misplaced =
            slots
            |> List.choose (fun (key, slot) ->
                if slot.Process.ProcessId = key then
                    None
                else
                    Some (UnixSystemDefect.SlotUnderAnotherProcessId (key, slot.Process.ProcessId))
            )

        let duplicates =
            slots
            |> List.countBy (fun (_, slot) -> slot.Process.ProcessId)
            |> List.filter (fun (_, count) -> count > 1)
            |> List.map (fst >> UnixSystemDefect.DuplicateProcessId)

        machine @ processes @ tables @ openFiles @ misplaced @ duplicates

    /// Logical-processor count a freshly-minted simulated process reports.
    /// One, because only single-processor behaviour has been exercised
    /// end-to-end, and because a fixed default is a prerequisite for
    /// replayability.
    /// A client that wants to exercise multi-processor code paths raises it with
    /// `UnixBootImage.withProcessorCount`.
    [<Literal>]
    let defaultProcessorCount : int = 1

    /// The `fs.inotify` sysctls a freshly-minted machine has: 128 instances
    /// and 8192 watches per user, and 16384 records queued per instance.
    ///
    /// The first and third are Linux's defaults (measured on Linux 6.18.5,
    /// `inotify-probe.c` section O). Linux derives the second from the
    /// machine's memory and clamps it to between 8192 and 1048576, so 8192,
    /// the floor every machine meets, rather than the 8982 the measuring
    /// machine had. A client simulating another machine sets them with
    /// `UnixBootImage.withInotifyLimits`. Only a Linux-flavoured machine reads
    /// them.
    let defaultInotifyLimits : InotifyLimits =
        {
            MaxUserInstances = 128
            MaxUserWatches = 8192
            MaxQueuedEvents = 16384
        }

    /// The buffer check a freshly-minted machine on `platform` applies: none up
    /// front where the platform screens nothing, and otherwise a screen at the
    /// commonest `TASK_SIZE_MAX` of the platform's architecture, which is
    /// four-level paging on x86-64 and a 48-bit virtual address on arm64. A client
    /// simulating a machine with a different address-space width sets it with
    /// `UnixBootImage.withUserAddressLimit`.
    let defaultUserBufferCheck (platform : SimulatedUnixPlatform) : UserBufferCheck =
        if SimulatedUnixPlatform.screensUserBufferUpFront platform then
            match SimulatedUnixPlatform.architecture platform with
            | SimulatedUnixArchitecture.X64 ->
                UserBufferCheck.BeforeOperation ObservedUserAddressLimit.X64FourLevelPaging
            | SimulatedUnixArchitecture.Arm64 ->
                UserBufferCheck.BeforeOperation ObservedUserAddressLimit.Arm64FortyEightBit
        else
            UserBufferCheck.AtCopyTime

    /// Unix platform identity a freshly-minted simulated process reports:
    /// Linux/x64. A client chooses another by passing it to `initial`.
    let defaultUnixPlatform : SimulatedUnixPlatform = SimulatedUnixPlatform.linuxX64

    /// Current working directory a freshly-minted simulated process reports.
    /// The root, because it is the one directory that exists on every Unix and
    /// needs no name invented for it, and the one directory every filesystem
    /// this library can hold is guaranteed to have. (`init` itself starts at
    /// `/`, so this is not even an unusual cwd for a real process.) It is also
    /// the honest answer for a simulation that declines to read the host's: a
    /// process nobody has told where it is claims nothing beyond the root. A
    /// client that wants a particular directory sets it with
    /// `ProcessLaunch.withCurrentDirectory`.
    let defaultCurrentDirectory : AbsoluteUnixPath = LaunchDefaults.currentDirectory

    /// Executable path a freshly-minted simulated process reports: none at all.
    ///
    /// This library models no `exec(2)`, so there is no file that started this
    /// process, and the emulated filesystem holds no image of one. `None` is
    /// therefore the only true answer, and it is a *modelled* Unix state rather
    /// than an invention: on both flavours, resolving a live process's
    /// executable with `realpath` fails with ENOENT once that executable has
    /// been unlinked. Measured on both, by having a process unlink its own
    /// executable before first asking for its path.
    ///
    /// A client that wants a particular executable sets it with
    /// `ProcessLaunch.withProcessPath`.
    let defaultProcessPath : AbsoluteUnixPath option = LaunchDefaults.processPath

    /// The range `bind(2)` draws from when asked for port 0, on a machine of
    /// this flavour that has not configured it.
    ///
    /// A sysctl on both platforms rather than a property of the kernel image,
    /// so a host may set it to anything; but each flavour ships a default, and
    /// a Darwin machine draws from Darwin's. Measured: Linux's
    /// `ip_local_port_range` reads 32768-60999, and Darwin's
    /// `net.inet.ip.portrange.first`/`last` read 49152-65535 (macOS 26,
    /// 2026-09-08).
    let defaultEphemeralPortRange (flavour : SimulatedUnixFlavour) : uint16 * uint16 =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 32768us, 60999us
        | SimulatedUnixFlavour.Darwin -> 49152us, 65535us

    /// The lowest port a process without privilege may bind, on a machine
    /// that has not configured it: 1024 on both flavours.
    ///
    /// Linux's is the sysctl `net.ipv4.ip_unprivileged_port_start`, which a
    /// host may set (`UnixBootImage.withUnprivilegedPortStart`), and which
    /// reads 1024 by default. Darwin's is not configurable. Measured: binding
    /// 1023 to loopback is `EACCES` for an unprivileged caller on both, and
    /// 1024 succeeds.
    let defaultUnprivilegedPortStart : uint16 = 1024us

    /// The addresses this machine holds, as `bind(2)` decides whether an address
    /// is assignable. Loopback only: this library models no interface a process
    /// could reach, so anything else would be an address no packet could arrive on.
    ///
    /// `127.0.0.0/8` rather than `127.0.0.1/32` because that is what Linux
    /// assigns to `lo`, and the flavours read the list differently — see
    /// `UnixBootImage.withLocalIpv4Addresses`.
    let defaultLocalIpv4Addresses : Ipv4Address list = [ Ipv4Address.loopback ]

    /// The prefixes Linux's local routing table holds, which it will `bind(2)`
    /// any address inside. Loopback's `127.0.0.0/8` is the one every Linux has,
    /// and is why `127.9.9.9` binds there and not on Darwin.
    let defaultLocalRoutes : Ipv4Prefix list = [ Ipv4Prefix.loopbackNetwork ]

    /// Effective user ID a freshly-minted simulated process runs as.
    ///
    /// Not 0: a process that defaulted to root would silently take the
    /// privileged branch of every check the kernel makes and every check it
    /// makes about itself (`geteuid() == 0`) — the uninteresting one, and not
    /// the one most programs are written for.
    /// Instead the first interactive user each flavour creates: 1000 on the
    /// Ubuntu-shaped Linux, and 501 on macOS (measured, `id -u` of the first
    /// account on a macOS 26 machine, 2026-09-08). A client that wants root says
    /// so with `ProcessLaunch.withCredentials`.
    let defaultUserId (flavour : SimulatedUnixFlavour) : UserId = LaunchDefaults.userId flavour

    /// Effective group ID a freshly-minted simulated process runs as: the
    /// first user's primary group, which is a user-private group numbered as
    /// the user on Linux and `staff` (20) on macOS (measured with the uid).
    let defaultGroupId (flavour : SimulatedUnixFlavour) : GroupId = LaunchDefaults.groupId flavour

    /// Credentials a freshly-minted simulated process runs with: real,
    /// effective and saved IDs all `defaultUserId` and `defaultGroupId`, and no
    /// supplementary groups.
    let defaultCredentials (flavour : SimulatedUnixFlavour) : Credentials = LaunchDefaults.credentials flavour

    /// File-mode creation mask a freshly-minted simulated process reports.
    /// 0o022 because that is what essentially every Unix login shell and service
    /// manager sets, and because it is the mask the existing seed defaults were
    /// written against (`SeedEntry.defaultPermsForRegularFile` is 0o666 with
    /// these bits cleared). Measured as the mask a process inherits on both
    /// flavours. A client chooses otherwise with `ProcessLaunch.withUmask`, and
    /// the process itself with `umask`.
    let defaultUmask : PermissionBits = LaunchDefaults.umask

    /// Whether a freshly-minted simulated process writes a core dump when a
    /// signal kills it: never, as under an `RLIMIT_CORE` of 0. A dump is a
    /// file the simulated process would leave behind, which a client has to
    /// ask for. A client chooses otherwise with
    /// `ProcessLaunch.withCoreDumps`.
    let defaultCoreDumps : CoreDumps = LaunchDefaults.coreDumps

    /// The `RLIMIT_SIGPENDING` a freshly-minted Linux process starts with:
    /// 4505. Linux computes the default at boot from the machine's memory (half
    /// its `threads-max`, so about 4000 per GiB); 4505 is what Linux 6.18.5
    /// computed for the 1 GiB machine the library's signal probes ran on
    /// (`docs/probes/rt-queue-limit`). A client modelling another machine
    /// chooses its value with `ProcessLaunch.withPendingSignalLimit`. A Darwin
    /// process has no such limit.
    let defaultPendingSignalLimit : uint64 = LaunchDefaults.pendingSignalLimit

    /// Process ID a freshly-minted simulated process reports: 4242.
    ///
    /// Not 1, which is the ID of a PID namespace's init process. A kernel
    /// treats init specially — a signal it has not installed a handler for is
    /// not delivered to it from inside its own namespace, so `kill -9` on
    /// itself does nothing — and a default that took that branch would be
    /// modelling a container's entry point rather than an ordinary process.
    /// A client chooses otherwise with `withProcessId`.
    let defaultProcessId : ProcessId =
        // Measured on Linux 6.18.5 in a container: `sh` running as pid 1
        // survives both `kill -9 $$` and `kill -TERM $$`, where the same
        // shell as pid 2 dies with status 137. Otherwise the number is
        // arbitrary; it differs from every other default ID here so that a
        // caller reading the wrong one fails a test that uses the defaults.
        ProcessId.parseOrFail "UnixSystem.defaultProcessId" 4242

    /// Seed for the entropy pool a freshly-minted machine boots with: the
    /// first 64 bits of the fractional part of pi. Any value would do; a
    /// constant nobody chose for its bits is the least arbitrary one.
    ///
    /// A client whose recorded runs must replay bit-for-bit depends on this
    /// value, because every byte the pool hands out follows from it. A client
    /// chooses another with `UnixBootImage.withEntropySeed`.
    let defaultEntropySeed : uint64 = 0x243F6A8885A308D3UL

    /// The `pid_max` a freshly-minted Linux machine has: 4194304, the most Linux
    /// allows, so that thread IDs are reused only after that many have been
    /// handed out. The administrator chooses otherwise with `writePidMaxSysctl`.
    ///
    /// A Darwin machine has no such setting.
    let defaultPidMax : int32 =
        // Measured in Apple's `container` VM (Linux 6.18.5, 2026-09-26), where
        // `kernel.pid_max` reads 4194304; `pid-allocation.c` measured that this is
        // the greatest value the sysctl accepts.
        ThreadIdAllocator.linuxPidMaxCeiling

    /// The launch table of a process started with each of its standard streams
    /// redirected to a pipe of its own, as a shell's `cmd < a | b 2> c` and
    /// most test harnesses do: descriptor 0 reads a pipe whose writer supplied
    /// nothing, and descriptors 1 and 2 write to pipes the client drains. A
    /// client supplying bytes on standard input replaces entry 0 with
    /// `LaunchDescriptor.Supplied` of them, and one that closed the reader of
    /// an output stream before the process started replaces its entry with
    /// `LaunchDescriptor.Gone`.
    ///
    /// Not the only shape a real process can inherit, and not the terminal one.
    /// Under a tty, descriptors 0, 1 and 2 are `dup`s of a single `O_RDWR`
    /// description: measured via `forkpty`, setting `O_NONBLOCK` through
    /// descriptor 1 becomes visible on 0 and 2, and `write(0, _, _)` succeeds.
    let pipedStandardStreams : Map<int, LaunchDescriptor> =
        Map.ofList
            [
                0, LaunchDescriptor.Supplied ImmutableArray.Empty
                1, LaunchDescriptor.Drained
                2, LaunchDescriptor.Drained
            ]

    /// The boot image of a machine of the given platform: no processes, no
    /// sockets, no connections, and an empty filesystem. Configure it with the
    /// setters in `UnixBootImage`, then `UnixBootImage.boot` it, which launches
    /// its first process, for its first syscall.
    ///
    /// The first process's ID is `defaultProcessId`, and so is its leader's
    /// thread ID: on Linux because it always is, and on Darwin as the start of a
    /// quiet machine's counter. A client moves them with
    /// `UnixBootImage.withProcessId` and `UnixBootImage.withLeaderThreadId`.
    ///
    /// The fields the platform *fixes* are derived from it rather than
    /// taken as arguments — `SoMaxConn`, the TCP buffer sysctls, `Mount`, and the platform
    /// itself — because a machine whose flavour and those disagree is one no
    /// real system could be: `EmulatedFileSystemType.isReportableUnder` says
    /// outright that a Darwin kernel never reports tmpfs. Building the record
    /// by hand is what lets that state exist, so the constructor is also the
    /// rule.
    ///
    /// The ephemeral port range is the flavour's shipped default too, though a
    /// host may set it: it is what a default machine of that flavour reports,
    /// not a fact of its kernel image. The buffer check is the platform's
    /// default too, though its limit is a property of the machine's paging
    /// depth rather than of its kernel. All of these are configuration a
    /// caller overrides with the setters in `UnixBootImage`, which is also how
    /// a caller supplies a non-empty filesystem or a different address list.
    let initial<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (platform : SimulatedUnixPlatform)
        : UnixBootImage<'Thread, 'Handler>
        =
        // `SimulatedUnixPlatform.create` validates at construction, so a value
        // of the type is already a platform some Unix could be; this catches
        // the one value that bypasses that, the forged `Unchecked.defaultof`,
        // whose null release would otherwise reach a process as its `uname -r`.
        let platform = SimulatedUnixPlatform.assertValid "UnixSystem.initial" platform
        let flavour = SimulatedUnixPlatform.flavour platform

        let deviceMount = DeviceFileSystemMount.defaultFor flavour

        let filesystem =
            match
                VirtualFileSystem.empty
                    (SimulatedUnixPlatform.entryNameMatching platform)
                    UnixTimestamp.epoch
                    (InodeOwner.ofProcess (defaultCredentials flavour))
                |> mountDeviceFileSystem deviceMount
            with
            | Ok filesystem -> filesystem
            | Error fault ->
                failwith
                    $"UnixSystem.initial: mounting the device filesystem over an empty root failed with %A{fault} (this is a bug in this library)."

        let threadIds, processIds =
            match flavour with
            | SimulatedUnixFlavour.Linux ->
                ThreadIdAllocator.startLinux "UnixSystem.initial" defaultPidMax defaultProcessId
                |> snd,
                ProcessIdTable.linux
            | SimulatedUnixFlavour.Darwin ->
                ThreadIdAllocator.startDarwin "UnixSystem.initial" (uint64 (ProcessId.toInt32 defaultProcessId))
                |> snd,
                ProcessIdTable.darwinAfter defaultProcessId

        {
            Machine =
                {
                    OpenFiles = OpenFileTable.empty
                    Sockets = Map.empty
                    Pipes = Map.empty
                    NextPipeId = PipeId 0L
                    Delivered = DeliveryLog.empty
                    // Any start would do; one, because no filesystem hands out
                    // inode 0.
                    NextPipeInode = InodeNumber 1L
                    PipeDevice = UnixMachineState.defaultPipeDevice flavour
                    Connections = Map.empty
                    TimeWaits = Map.empty
                    TcpTimeWait = UnixMachineState.defaultTcpTimeWait flavour
                    NextConnectionId = ConnectionId 0L
                    NextEventRegistrationOrdinal = 0L
                    NextParkOrdinal = ParkOrdinal 0L
                    PollQueues = Map.empty
                    NextPollQueueId = PollQueueId 0L
                    ThreadIds = threadIds
                    ProcessIds = processIds
                    CurrentDirectories = Map.empty
                    NextSocketId = SocketId 0L
                    NextEphemeralPort = fst (defaultEphemeralPortRange flavour)
                    EphemeralPortRange = defaultEphemeralPortRange flavour
                    UnprivilegedPortStart = defaultUnprivilegedPortStart
                    SoMaxConn = UnixMachineState.defaultSoMaxConn flavour
                    InotifyLimits = defaultInotifyLimits
                    TcpSendSpace = UnixMachineState.defaultTcpSendSpace flavour
                    Ipv6OnlyByDefault = false
                    TcpReceiveSpace = UnixMachineState.defaultTcpReceiveSpace flavour
                    TcpSendSpaceMax = UnixMachineState.defaultTcpSendSpaceMax flavour
                    LocalIpv4Addresses = defaultLocalIpv4Addresses
                    LocalRoutes = defaultLocalRoutes
                    BootTime = UnixTimestamp.epoch
                    EntropyPool = EntropyPool.ofSeed defaultEntropySeed
                    ProcessorCount = defaultProcessorCount
                    UserBufferCheck = defaultUserBufferCheck platform
                    UnixPlatform = platform
                    CommittedFileSystem = CommittedFileSystem.initial filesystem
                    Mount = EmulatedMount.defaultFor flavour
                    DeviceMount = deviceMount
                    ProtectedFiles = ProtectedFiles.off
                }
            ProcessId = defaultProcessId
        }

    /// The machine's administrator writes Linux's `kernel.pid_max` sysctl
    /// (through `/proc/sys`), which a sysctl allows at any time, the machine
    /// running or not: the thread IDs handed out from then on are below it, and
    /// once they reach it they start again from 300, skipping those still in use.
    ///
    /// Any value from 301 to 4194304 is accepted, including one at or below a live
    /// thread's ID: as on Linux, that thread keeps its ID, and the next thread
    /// takes its ID from 300 up.
    ///
    /// Not configuration, which is `UnixBootImage`'s, but the outside world
    /// acting on a running machine, as `UnixSystem.advanceClock` is.
    ///
    /// Throws for a Darwin machine, which has no such setting, and for a value
    /// outside 301 to 4194304 (`ThreadIdAllocator.linuxPidMaxFloor` to
    /// `ThreadIdAllocator.linuxPidMaxCeiling`), which Linux's sysctl answers
    /// with EINVAL.
    let writePidMaxSysctl<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (context : string)
        (pidMax : int32)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        // Measured on Linux 6.18.5 aarch64 by
        // `docs/plans/2026-08-23-posix-kernel-extraction/pid-max-below-live.c`:
        // with process 5000 and its thread 5001 alive, writes of 1000, 5000, 5001,
        // 5002 and 400 each take; both keep their IDs, `kill` and `tgkill` still
        // find them, and the threads started after each write get 300, 301, and
        // on up.
        let threadIds = ThreadIdAllocator.withPidMax context pidMax system.Machine.ThreadIds

        { system with
            Machine =
                { system.Machine with
                    ThreadIds = threadIds
                }
        }

    /// `launch`, with a refusal answered as the `Error` rather than raised.
    let internal tryLaunch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ProcessId * UnixSystem<'Thread, 'Handler>, ProcessCreationRefusal>
        =
        let current = system.Machine

        let allocated =
            match current.ProcessIds.Counter with
            | ProcessIdCounter.ThreadIds ->
                match ThreadIdAllocator.allocate current.ThreadIds with
                | ThreadIdAllocation.Failed _ -> Error ProcessCreationRefusal.NoFreeProcessId
                | ThreadIdAllocation.DarwinCounterExhausted ->
                    failwith
                        "UnixSystem.launch: Linux's thread ID allocator answered that Darwin's counter is exhausted (this is a bug in this library)."
                | ThreadIdAllocation.Issued (leader, threadIds) ->
                    let pid =
                        ProcessId.parseOrFail "UnixSystem.launch" (int32 (OsThreadId.toUInt64 leader))

                    Ok (
                        pid,
                        leader,
                        { current with
                            ThreadIds = threadIds
                        }
                    )
            | ProcessIdCounter.Darwin _ ->
                match ProcessIdTable.nextDarwin current.ProcessIds with
                | None -> Error (ProcessCreationRefusal.DarwinPidMaxReached ProcessIdTable.darwinPidMax)
                | Some (pid, processIds) ->
                    match ThreadIdAllocator.allocate current.ThreadIds with
                    | ThreadIdAllocation.Failed error ->
                        failwith
                            $"UnixSystem.launch: Darwin's thread ID counter answered %O{error}, which it never does (this is a bug in this library)."
                    | ThreadIdAllocation.DarwinCounterExhausted ->
                        Error ProcessCreationRefusal.DarwinThreadIdCounterExhausted
                    | ThreadIdAllocation.Issued (leader, threadIds) ->
                        Ok (
                            pid,
                            leader,
                            { current with
                                ThreadIds = threadIds
                                ProcessIds = processIds
                            }
                        )

        match allocated with
        | Error refusal -> Error refusal
        | Ok (pid, leaderThreadId, allocatedMachine) ->

        if Map.containsKey (ProcessId.toInt32 pid) system.Processes then
            failwith
                $"UnixSystem.launch: the kernel chose process ID %O{pid}, which a process on the machine already has (this is a bug in this library)."

        match ProcessLaunch.launchOnto launch pid leaderThreadId allocatedMachine with
        | Error refusal -> Error (ProcessCreationRefusal.Launch refusal)
        | Ok (launched, proc, threads) ->
            let slot : ProcessSlot<'Thread, 'Handler> =
                {
                    Process = proc
                    Threads = threads
                    Leader = ProcessLaunch.leader launch
                }

            Ok (
                pid,
                { system with
                    Machine = launched
                    Processes = Map.add (ProcessId.toInt32 pid) slot system.Processes
                }
            )

    /// <summary>
    /// Start a new process on the machine, as `launch` describes it: the
    /// process ID the kernel chose for it, and the system with it on.
    ///
    /// On Linux the process's ID is its leader's thread ID, the next the
    /// machine's thread ID counter hands out, so it is no live process's or
    /// thread's. On Darwin it is the next from a process ID counter of its own,
    /// which started one past the first process's ID, and the leader's thread
    /// ID is the next from the 64-bit thread ID counter.
    ///
    /// Refuses a launch `UnixBootImage.boot` would refuse, and a machine with
    /// no process ID left to hand out.
    /// </summary>
    /// <exception cref="T:System.ArgumentException">The path does not resolve in the seeded filesystem at all. Carries what the walk answered. The walk refused the path as too long. Distinguished from `DoesNotResolve` because the directory may well be present: it is a *length* that is unusable, and the remedy is to shorten something rather than to go looking for a missing directory.  Which length is deliberately not said, because the walk does not say: `ENAMETOOLONG` is one errno covering a component past this flavour's `NAME_MAX` and — on a flavour that re-checks, which is Darwin — a symbolic link whose expansion would carry the whole path past `PATH_MAX`. A real kernel conflates them too. Splitting the case would need the path walk to report which limit it hit, which every other caller of the walk would pay for.  Carries the flavour so that a fault which outlives the call still says whose limits were in force -- 255 CJK characters name a directory a Darwin process can start in and a Linux one cannot, and only Darwin re-checks a splice at all. The path resolves, to something that is not a directory. The launch puts its leader on the logical processor `cpu`, and the machine has `processorCount`, numbered from 0, which do not include it. Contradictory: no kernel runs a thread on a processor it does not have.</exception>
    /// <exception cref="T:System.InvalidOperationException">The launch was described for the platform `launch`, and the machine is `machine`: the description was checked against the wrong platform's rules.</exception>
    let launch<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (launch : ProcessLaunch<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : ProcessId * UnixSystem<'Thread, 'Handler>
        =
        tryLaunch launch system
        |> Refusal.orRaise "UnixSystem.launch" ProcessCreationRefusal.kind ProcessCreationRefusal.describe
