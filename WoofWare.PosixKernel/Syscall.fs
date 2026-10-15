namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// An argument a call copies in from the caller's memory, as a `Syscall` case
/// holds it: what that memory held, or, where the caller has nothing to copy,
/// the reason, as `UserBuffer`'s cases give it for a buffer.
[<RequireQualifiedAccess>]
type CopiedArgument<'T> =
    /// The address names real storage, which held `contents`: of a buffer of
    /// bytes, at least as many bytes as the call copies.
    | Readable of contents : 'T
    /// As `UserBuffer.Unmapped`: an address naming no storage.
    | Unmapped of address : uint64
    /// As `UserBuffer.Opaque`: real memory whose contents the caller cannot
    /// produce.
    | Opaque
    /// As `UserBuffer.Addressless`: not an address at all.
    | Addressless

/// The arguments of a `nanosleep(2)`: what `Syscall.Nanosleep` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.Nanosleep`.
[<NoComparison>]
type NanosleepArguments =
    // What it holds is the design of the sleep (`docs/design/nanosleep-options.md`).
    internal | NanosleepArguments

/// The arguments of a `clock_nanosleep(2)`: what `Syscall.ClockNanosleep`
/// holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.ClockNanosleep`.
[<NoComparison>]
type ClockNanosleepArguments =
    // What it holds is the design of the sleep (`docs/design/nanosleep-options.md`).
    internal | ClockNanosleepArguments

/// The arguments of a `select(2)`: what `Syscall.Select` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.Select`.
[<NoComparison>]
type SelectArguments =
    // What it holds is the design of the select (`docs/design/select-park-options.md`).
    internal | SelectArguments

/// The arguments of a `pselect(2)`: what `Syscall.PSelect` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.PSelect`.
[<NoComparison>]
type PSelectArguments =
    // What it holds is the design of the select (`docs/design/select-park-options.md`).
    internal | PSelectArguments

/// The arguments of a `sigwait(3)`: what `Syscall.SigWait` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SigWait`.
[<NoComparison>]
type SigWaitArguments =
    // What it holds is the design of the signal wait (`docs/design/sigwait-options.md`).
    internal | SigWaitArguments

/// The arguments of a `sigwaitinfo(2)`: what `Syscall.SigWaitInfo` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SigWaitInfo`.
[<NoComparison>]
type SigWaitInfoArguments =
    // What it holds is the design of the signal wait (`docs/design/sigwait-options.md`).
    internal | SigWaitInfoArguments

/// The arguments of a `sigtimedwait(2)`: what `Syscall.SigTimedWait` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SigTimedWait`.
[<NoComparison>]
type SigTimedWaitArguments =
    // What it holds is the design of the signal wait (`docs/design/sigwait-options.md`).
    internal | SigTimedWaitArguments

/// The arguments of a `recvfrom(2)`: what `Syscall.RecvFrom` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.RecvFrom`.
[<NoComparison>]
type RecvFromArguments =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | RecvFromArguments

/// The arguments of a `recvmsg(2)`: what `Syscall.RecvMsg` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.RecvMsg`.
[<NoComparison>]
type RecvMsgArguments =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | RecvMsgArguments

/// The arguments of a `sendto(2)`: what `Syscall.SendTo` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SendTo`.
[<NoComparison>]
type SendToArguments =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | SendToArguments

/// The arguments of a `sendmsg(2)`: what `Syscall.SendMsg` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SendMsg`.
[<NoComparison>]
type SendMsgArguments =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | SendMsgArguments

/// A request to this kernel, as a value: one case for each call a thread makes
/// of it, named for the call and holding the call's arguments, for a client
/// that wants one surface to log, replay or generate calls through.
/// `UnixSystem.step` makes the call a case names through that call's own
/// function, and answers the `SteppedCall` case of the same name.
///
/// Each argument is as the call's own function takes it, in the order the
/// call's C prototype takes them, which is not always the function's: raw
/// where the kernel validates it, in the flavour's own numbering, and
/// classified where only the client can classify it.
///
/// An argument the kernel copies in from the caller's memory is what that
/// memory held, so that no call stops partway for it: a pathname is its bytes
/// (`PathArgumentBytes`), and a buffer of bytes, a `sockaddr` or a length cell
/// is a `CopiedArgument`. A buffer the call writes to stays a `UserBuffer`,
/// since what the call writes there is in its answer.
///
/// `Nanosleep`, `ClockNanosleep`, `Select`, `PSelect`, `SigWait`,
/// `SigWaitInfo`, `SigTimedWait`, `RecvFrom`, `RecvMsg`, `SendTo` and
/// `SendMsg` are reserved: this kernel does not model those calls yet, their
/// arguments' types have internal representations, and nothing in this
/// version makes one.
[<RequireQualifiedAccess ; NoComparison>]
type Syscall<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// `dup(2)`, as `UnixDescriptor.dup` makes it.
    | Dup of fd : int
    /// `dup2(2)`, as `UnixDescriptor.dup2` makes it.
    | Dup2 of oldFd : int * newFd : int
    /// `dup3(2)`, as `UnixDescriptor.dup3` makes it. `flags` is raw, in
    /// Linux's numbering.
    | Dup3 of oldFd : int * newFd : int * flags : int
    /// `fcntl(2)`, as `UnixDescriptor.fcntl` makes it. `command` and
    /// `argument` are raw, in the flavour's `fcntl.h` numbering.
    | Fcntl of fd : int * command : int * argument : int
    /// `lseek(2)`, as `UnixDescriptor.lseek` makes it.
    | LSeek of fd : int * offset : int64 * whence : int
    /// `flock(2)`, as `UnixDescriptor.flock` makes it. `operation` is raw:
    /// which combinations of LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB are legal, and
    /// what an illegal one earns, is behaviour this kernel models and models
    /// per flavour.
    | FLock of fd : int * operation : int
    /// `ftruncate(2)`, as `UnixDescriptor.ftruncate` makes it.
    | FTruncate of fd : int * length : int64
    /// `posix_fadvise(3)`, as `UnixDescriptor.posixFadvise` makes it.
    | PosixFAdvise of fd : int * offset : int64 * length : int64 * advice : int
    /// `close(2)`, as `UnixDescriptor.close` makes it.
    | Close of fd : int
    /// `ioctl(fd, FIONREAD, destination)`, as `UnixDescriptor.bytesAvailable`
    /// makes it.
    | BytesAvailable of fd : int * destination : UserBuffer
    /// `ioctl(destination, FICLONE, source)`, as `UnixDescriptor.fileClone`
    /// makes it.
    | FileClone of destination : int * source : int
    /// `tcgetattr(3)`, as `UnixDescriptor.terminalAttributes` makes it.
    | TerminalAttributes of fd : int
    /// `geteuid(2)`, as `UnixDescriptor.effectiveUserId` makes it.
    | GetEffectiveUserId
    /// `getegid(2)`, as `UnixDescriptor.effectiveGroupId` makes it.
    | GetEffectiveGroupId
    /// `getgroups(2)`, as `UnixDescriptor.getgroups` makes it.
    | GetGroups of size : int * destination : UserBuffer
    /// `stat(2)` or `lstat(2)`, as `UnixPathResolution.stat` makes it:
    /// `policy` says which.
    | Stat of policy : SymlinkPolicy * path : PathArgumentBytes
    /// `fstat(2)`, as `UnixPathResolution.fstat` makes it.
    | FStat of fd : int
    /// `fstatat(2)`, as `UnixPathResolution.fstatat` makes it.
    | FStatAt of dirfd : int * path : PathArgumentBytes * flags : int
    /// `chmod(2)`, as `UnixPathResolution.chmod` makes it.
    | ChMod of path : PathArgumentBytes * mode : int
    /// `fchmod(2)`, as `UnixPathResolution.fchmod` makes it. `mode` is raw.
    | FChMod of fd : int * mode : int
    /// `fchmodat(2)`, as `UnixPathResolution.fchmodat` makes it. `dirfd`,
    /// `mode` and `flags` are raw: each flavour numbers `AT_FDCWD` and the
    /// flags its own way, and which bits of `mode` the inode gets is behaviour
    /// this kernel models.
    | FChModAt of dirfd : int * path : PathArgumentBytes * mode : int * flags : int
    /// `chown(2)`, as `UnixPathResolution.chown` makes it. `None` is
    /// `(uid_t)-1` or `(gid_t)-1`: leave that ID as it is.
    | ChOwn of path : PathArgumentBytes * user : UserId option * group : GroupId option
    /// `lchown(2)`, as `UnixPathResolution.lchown` makes it, with `None` as
    /// for `ChOwn`.
    | LChOwn of path : PathArgumentBytes * user : UserId option * group : GroupId option
    /// `fchown(2)`, as `UnixPathResolution.fchown` makes it, with `None` as
    /// for `ChOwn`.
    | FChOwn of fd : int * user : UserId option * group : GroupId option
    /// `fchownat(2)`, as `UnixPathResolution.fchownat` makes it, with `None`
    /// as for `ChOwn`. `dirfd` and `flags` are raw.
    | FChOwnAt of dirfd : int * path : PathArgumentBytes * user : UserId option * group : GroupId option * flags : int
    /// `utimensat(2)`, as `UnixPathResolution.utimensat` makes it. `dirfd` and
    /// `flags` are raw, and `times` holds the fields the caller stored, which
    /// each flavour reads its own way. A null `path` means something of its
    /// own on Linux: `futimens(3)` is, on Linux, this with `fd` as `dirfd`, a
    /// null `path` and no flags.
    | UTimensAt of dirfd : int * path : NullablePathArgument * times : TimesArgument * flags : int
    /// `statfs(2)`, as `UnixPathResolution.statfs` makes it.
    | StatFs of path : PathArgumentBytes
    /// `fstatfs(2)`, as `UnixPathResolution.fstatfs` makes it.
    | FStatFs of fd : int
    /// `getcwd(3)`, as `UnixPathResolution.getcwd` makes it.
    | GetCwd of destination : UserBuffer * capacity : uint64
    /// `chdir(2)`, as `UnixPathResolution.chdir` makes it.
    | ChDir of path : PathArgumentBytes
    /// `access(2)`, as `UnixPathResolution.access` makes it, then
    /// `UnixPathResolution.accessWithPath` of `path`.
    | Access of path : PathArgumentBytes * mode : int
    /// `faccessat(2)`, as `UnixPathResolution.faccessat` makes it, then
    /// `UnixPathResolution.accessWithPath` of `path`. `dirfd`, `mode` and
    /// `flags` are raw: each flavour numbers `AT_FDCWD` and the flags its own
    /// way, and which bits of `mode` are rejected is behaviour this kernel
    /// models per flavour.
    | FAccessAt of dirfd : int * path : PathArgumentBytes * mode : int * flags : int
    /// `open(2)`, as `UnixNamespace.openPath` makes it.
    | Open of path : PathArgumentBytes * flags : int * mode : int
    /// `openat(2)`, as `UnixNamespace.openat` makes it.
    | OpenAt of dirfd : int * path : PathArgumentBytes * flags : int * mode : int
    /// `readlink(2)`, as `UnixNamespace.readlink` makes it.
    | ReadLink of path : PathArgumentBytes * destination : UserBuffer * capacity : int
    /// `readlinkat(2)`, as `UnixNamespace.readlinkat` makes it.
    | ReadLinkAt of dirfd : int * path : PathArgumentBytes * destination : UserBuffer * capacity : int
    /// One entry of `getdents(2)` or `getdirentries(2)`, as
    /// `UnixNamespace.readDirectoryEntry` makes it.
    | ReadDirectoryEntry of fd : int
    /// `mkdir(2)`, as `UnixNamespace.mkdir` makes it.
    | MkDir of path : PathArgumentBytes * mode : int
    /// `mkdirat(2)`, as `UnixNamespace.mkdirat` makes it. `dirfd` and `mode`
    /// are raw: how `mode` combines with the umask and with the parent's
    /// set-group-ID bit is behaviour this kernel models, and models per
    /// flavour.
    | MkDirAt of dirfd : int * path : PathArgumentBytes * mode : int
    /// `mknod(2)`, as `UnixNamespace.mknod` makes it.
    | MkNod of path : PathArgumentBytes * mode : int * dev : uint32
    /// `mknodat(2)`, as `UnixNamespace.mknodat` makes it.
    | MkNodAt of dirfd : int * path : PathArgumentBytes * mode : int * dev : uint32
    /// `unlink(2)`, as `UnixNamespace.unlink` makes it.
    | Unlink of path : PathArgumentBytes
    /// `rmdir(2)`, as `UnixNamespace.rmdir` makes it.
    | RmDir of path : PathArgumentBytes
    /// `unlinkat(2)`, as `UnixNamespace.unlinkat` makes it. `dirfd` and
    /// `flags` are raw: each flavour numbers `AT_FDCWD` and `AT_REMOVEDIR` its
    /// own way, and which other bits it rejects is behaviour this kernel
    /// models per flavour.
    | UnlinkAt of dirfd : int * path : PathArgumentBytes * flags : int
    /// `rename(2)`, as `UnixNamespace.rename` makes it, then
    /// `UnixNamespace.renameWithDestination` of `destination`.
    | Rename of source : PathArgumentBytes * destination : PathArgumentBytes
    /// `renameat(2)`, as `UnixNamespace.renameat` makes it, then
    /// `UnixNamespace.renameWithDestination` of `newpath`.
    | RenameAt of olddirfd : int * oldpath : PathArgumentBytes * newdirfd : int * newpath : PathArgumentBytes
    /// Darwin's `clonefile(2)`, as `UnixNamespace.cloneFile` makes it, then
    /// `UnixNamespace.cloneFileWithSource` of `source` and
    /// `UnixNamespace.cloneFileWithDestination` of `destination`. `flags` is
    /// raw.
    | CloneFile of source : PathArgumentBytes * destination : PathArgumentBytes * flags : int
    /// `symlink(2)`, as `UnixNamespace.symlink` makes it, then
    /// `UnixNamespace.symlinkWithPath` of `path`.
    | Symlink of target : PathArgumentBytes * path : PathArgumentBytes
    /// `symlinkat(2)`, as `UnixNamespace.symlinkat` makes it, then
    /// `UnixNamespace.symlinkWithPath` of `path`. `dirfd` is raw.
    | SymlinkAt of target : PathArgumentBytes * dirfd : int * path : PathArgumentBytes
    /// `link(2)`, as `UnixNamespace.link` makes it, then
    /// `UnixNamespace.linkWithDestination` of `newpath`.
    | Link of oldpath : PathArgumentBytes * newpath : PathArgumentBytes
    /// `linkat(2)`, as `UnixNamespace.linkat` makes it, then
    /// `UnixNamespace.linkWithDestination` of `newpath`. `olddirfd`,
    /// `newdirfd` and `flags` are raw.
    | LinkAt of
        olddirfd : int *
        oldpath : PathArgumentBytes *
        newdirfd : int *
        newpath : PathArgumentBytes *
        flags : int
    /// `read(2)`, as `UnixReadWrite.read` makes it.
    | Read of fd : int * buffer : UserBuffer * count : uint64
    /// `recv(2)`, as `UnixReadWrite.recv` makes it.
    | Recv of fd : int * buffer : UserBuffer * count : uint64 * flags : int
    /// `recvfrom(2)`. Reserved: see `RecvFromArguments`.
    | RecvFrom of arguments : RecvFromArguments
    /// `recvmsg(2)`. Reserved: see `RecvMsgArguments`.
    | RecvMsg of arguments : RecvMsgArguments
    /// `pread(2)`, as `UnixReadWrite.pread` makes it.
    | PRead of fd : int * buffer : UserBuffer * count : uint64 * offset : int64
    /// `write(2)`, as `UnixReadWrite.write` makes it, then
    /// `UnixReadWrite.writeWithBytes` of the bytes of `buffer` it copies.
    | Write of fd : int * buffer : CopiedArgument<ImmutableArray<byte>> * count : uint64
    /// `send(2)`, as `UnixReadWrite.send` makes it, then
    /// `UnixReadWrite.sendWithBytes` of the bytes of `buffer` it copies.
    | Send of fd : int * buffer : CopiedArgument<ImmutableArray<byte>> * count : uint64 * flags : int
    /// `sendto(2)`. Reserved: see `SendToArguments`.
    | SendTo of arguments : SendToArguments
    /// `sendmsg(2)`. Reserved: see `SendMsgArguments`.
    | SendMsg of arguments : SendMsgArguments
    /// `pwrite(2)`, as `UnixReadWrite.pwrite` makes it, then
    /// `UnixReadWrite.pwriteWithBytes` of the bytes of `buffer` it copies.
    | PWrite of fd : int * buffer : CopiedArgument<ImmutableArray<byte>> * count : uint64 * offset : int64
    /// `copy_file_range(2)` at both descriptions' own offsets, as
    /// `UnixReadWrite.copyFileRange` makes it. `length` is the `size_t` asked
    /// for and `flags` is raw, since any flag is refused.
    | CopyFileRange of inFd : int * outFd : int * length : uint64 * flags : int
    /// `pipe2(2)`, and `pipe(2)` as `pipe2` with no flags, as
    /// `UnixPipe.pipe2` makes it.
    | Pipe2 of destination : UserBuffer * flags : int
    /// `socket(2)`, as `UnixSocket.socket` makes it.
    | Socket of domain : int * socketType : int * protocol : int
    /// `bind(2)`, as `UnixSocket.bind` makes it, then
    /// `UnixSocket.bindWithAddress` of the bytes of `address` it copies.
    | Bind of fd : int * address : CopiedArgument<ImmutableArray<byte>> * declaredLength : uint32
    /// `connect(2)`, as `UnixConnection.connect` makes it, then
    /// `UnixConnection.connectWithAddress` of the bytes of `address` it
    /// copies.
    | Connect of fd : int * address : CopiedArgument<ImmutableArray<byte>> * declaredLength : uint32
    /// `listen(2)`, as `UnixSocket.listen` makes it.
    | Listen of fd : int * backlog : int
    /// `accept(2)`, as `UnixConnection.accept` makes it.
    | Accept of fd : int * destination : UserBuffer * declaredLength : uint32
    /// `shutdown(2)`, as `UnixConnection.shutdown` makes it.
    | Shutdown of fd : int * how : int
    /// `getsockname(2)`, as `UnixSocket.getsockname` makes it.
    | GetSockName of fd : int * destination : UserBuffer * declaredLength : uint32
    /// `getpeername(2)`, as `UnixSocket.getpeername` makes it.
    | GetPeerName of fd : int * destination : UserBuffer * declaredLength : uint32
    /// `setsockopt(2)`, as `UnixSocket.setsockopt` makes it, then
    /// `UnixSocket.setsockoptWithValue` of the bytes of `value` it copies.
    | SetSockOpt of
        fd : int *
        level : int *
        optionName : int *
        value : CopiedArgument<ImmutableArray<byte>> *
        optionLength : uint32
    /// `getsockopt(2)`, as `UnixSocket.getsockopt` makes it, then
    /// `UnixSocket.getsockoptWithLength` of the `socklen_t` the length cell
    /// holds.
    | GetSockOpt of fd : int * level : int * optionName : int * value : UserBuffer * length : CopiedArgument<uint32>
    /// `poll(2)`, as `UnixPoll.poll` makes it.
    | Poll of entries : PollEntry list * milliseconds : int
    /// `select(2)`. Reserved: see `SelectArguments`.
    | Select of arguments : SelectArguments
    /// `pselect(2)`. Reserved: see `PSelectArguments`.
    | PSelect of arguments : PSelectArguments
    /// `epoll_create1(2)`, as `UnixPoll.epollCreate1` makes it.
    | EpollCreate1 of flags : int
    /// `epoll_ctl(2)`, as `UnixPoll.epollCtl` makes it.
    | EpollCtl of epfd : int * op : int * fd : int * event : EpollEventArgument
    /// `epoll_wait(2)`, as `UnixPoll.epollWait` makes it.
    | EpollWait of epfd : int * buffer : UserBuffer * maxEvents : int * milliseconds : int
    /// Darwin's `kqueue(2)`, as `UnixKqueue.kqueue` makes it.
    | Kqueue
    /// Darwin's `kevent(2)`, as `UnixKqueue.kevent` makes it.
    | Kevent of
        kq : int *
        changes : Kevent list *
        nchanges : int *
        eventlist : UserBuffer *
        nevents : int *
        timeout : KeventTimeout
    /// `inotify_init1(2)`, as `UnixInotify.inotifyInit1` makes it. `flags` is
    /// raw, in Linux's numbering.
    | InotifyInit1 of flags : int
    /// `inotify_add_watch(2)`, as `UnixInotify.inotifyAddWatch` makes it, then
    /// `UnixInotify.inotifyAddWatchWithPath` of `path`.
    | InotifyAddWatch of fd : int * path : PathArgumentBytes * mask : uint32
    /// `inotify_rm_watch(2)` of the watch descriptor `wd`, as
    /// `UnixInotify.inotifyRmWatch` makes it.
    | InotifyRmWatch of fd : int * wd : int
    /// `kill(2)`, as `UnixSignal.kill` makes it.
    | Kill of pid : int * signo : int
    /// `pthread_kill(3)` and `raise(3)`, as `UnixSignal.pthreadKill` makes it.
    | PthreadKill of target : 'Thread * signo : int
    /// `sigaction(3)`, as `UnixSignal.sigaction` makes it.
    | SigAction of signo : int * newAction : SignalDisposition<'Handler> option
    /// `sigaction(2)`, Linux's `rt_sigaction`, as
    /// `UnixSignal.sigactionSyscall` makes it.
    | SigActionSyscall of signo : int * newAction : SignalDisposition<'Handler> option
    /// `pthread_sigmask(3)`, as `UnixSignal.pthreadSigmask` makes it.
    | PthreadSigMask of how : int * set : SignalMask option
    /// `sigprocmask(3)` on Linux and `sigprocmask(2)` on Darwin, as
    /// `UnixSignal.sigprocmask` makes it.
    | SigProcMask of how : int * set : SignalMask option
    /// Linux's `rt_sigprocmask(2)`, as `UnixSignal.rtSigprocmask` makes it.
    | RtSigProcMask of how : int * set : SignalMask option * sigsetSize : uint64
    /// `sigpending(2)`, as `UnixSignal.sigpending` makes it.
    | SigPending
    /// `sigsuspend(2)`, as `UnixSignal.sigsuspend` makes it.
    | SigSuspend of mask : SignalMask
    /// Linux's `rt_sigsuspend(2)`, as `UnixSignal.rtSigsuspend` makes it.
    | RtSigSuspend of mask : SignalMask * sigsetSize : uint64
    /// `pause(2)`, as `UnixSignal.pause` makes it.
    | Pause
    /// `sigreturn(2)`, as `UnixSignal.sigreturn` makes it.
    | SigReturn of frame : HandlerFrameId
    /// `sigwait(3)`. Reserved: see `SigWaitArguments`.
    | SigWait of arguments : SigWaitArguments
    /// `sigwaitinfo(2)`. Reserved: see `SigWaitInfoArguments`.
    | SigWaitInfo of arguments : SigWaitInfoArguments
    /// `sigtimedwait(2)`. Reserved: see `SigTimedWaitArguments`.
    | SigTimedWait of arguments : SigTimedWaitArguments
    /// `clock_gettime(2)`, as `UnixClock.clockGettime` makes it.
    | ClockGetTime of clockId : int
    /// `gettimeofday(2)`, as `UnixClock.gettimeofday` makes it.
    | GetTimeOfDay
    /// `nanosleep(2)`. Reserved: see `NanosleepArguments`.
    | Nanosleep of arguments : NanosleepArguments
    /// `clock_nanosleep(2)`. Reserved: see `ClockNanosleepArguments`.
    | ClockNanosleep of arguments : ClockNanosleepArguments
    /// Linux's `getrandom(2)`, as `UnixEntropy.getRandom` makes it.
    | GetRandom of buffer : UserBuffer * count : uint64 * flags : uint32
    /// Darwin's `getentropy(2)`, as `UnixEntropy.getEntropy` makes it.
    | GetEntropy of buffer : UserBuffer * length : uint64
    /// `getpid(2)`, as `UnixSystem.processId` makes it.
    | GetProcessId
    /// `umask(2)`, as `UnixSystem.umask` makes it. `mask` is raw: which of its
    /// bits the process keeps is behaviour this kernel models, and models per
    /// flavour.
    | UMask of mask : int
    /// `getresuid(2)`, as `UnixCredentials.getresuid` makes it.
    | GetResUid of real : UserBuffer * effective : UserBuffer * saved : UserBuffer
    /// `getresgid(2)`, as `UnixCredentials.getresgid` makes it.
    | GetResGid of real : UserBuffer * effective : UserBuffer * saved : UserBuffer
    /// `setresuid(2)`, as `UnixCredentials.setresuid` makes it. `None` is
    /// `(uid_t)-1`: leave that ID as it is.
    | SetResUid of real : UserId option * effective : UserId option * saved : UserId option
    /// `setresgid(2)`, as `UnixCredentials.setresgid` makes it. `None` is
    /// `(gid_t)-1`: leave that ID as it is.
    | SetResGid of real : GroupId option * effective : GroupId option * saved : GroupId option
    /// `setgroups(2)` of a list of `size` groups, whose words are as the caller
    /// read them, as `UnixCredentials.setgroups` makes it.
    | SetGroups of size : int * words : GroupListWords
    /// `clone(2)` with `CLONE_THREAD`, as `pthread_create(3)` makes it and
    /// `UnixThreadLifecycle.spawn` makes it here.
    | Spawn of child : 'Thread * cpu : CpuId
    /// Linux's thread `exit(2)`, as `pthread_exit(3)` makes it and
    /// `UnixThreadLifecycle.exitThread` makes it here.
    | ExitThread of status : int
    /// `exit_group(2)`, as `exit(3)` and `_exit(2)` make it and
    /// `UnixThreadLifecycle.exitGroup` makes it here.
    | ExitGroup of status : int
    /// Linux's `getcpu(2)`, as `UnixScheduling.getcpu` makes it.
    | GetCpu

/// What `UnixSystem.step` answers for a `Syscall.Nanosleep`: what
/// `SteppedCall.Nanosleep` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.Nanosleep`.
[<NoEquality ; NoComparison>]
type SteppedNanosleep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the sleep (`docs/design/nanosleep-options.md`).
    internal | SteppedNanosleep

/// What `UnixSystem.step` answers for a `Syscall.ClockNanosleep`: what
/// `SteppedCall.ClockNanosleep` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.ClockNanosleep`.
[<NoEquality ; NoComparison>]
type SteppedClockNanosleep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the sleep (`docs/design/nanosleep-options.md`).
    internal | SteppedClockNanosleep

/// What `UnixSystem.step` answers for a `Syscall.Select`: what
/// `SteppedCall.Select` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.Select`.
[<NoEquality ; NoComparison>]
type SteppedSelect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the select (`docs/design/select-park-options.md`).
    internal | SteppedSelect

/// What `UnixSystem.step` answers for a `Syscall.PSelect`: what
/// `SteppedCall.PSelect` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.PSelect`.
[<NoEquality ; NoComparison>]
type SteppedPSelect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the select (`docs/design/select-park-options.md`).
    internal | SteppedPSelect

/// What `UnixSystem.step` answers for a `Syscall.SigWait`: what
/// `SteppedCall.SigWait` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SigWait`.
[<NoEquality ; NoComparison>]
type SteppedSigWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the signal wait (`docs/design/sigwait-options.md`).
    internal | SteppedSigWait

/// What `UnixSystem.step` answers for a `Syscall.SigWaitInfo`: what
/// `SteppedCall.SigWaitInfo` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SigWaitInfo`.
[<NoEquality ; NoComparison>]
type SteppedSigWaitInfo<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the signal wait (`docs/design/sigwait-options.md`).
    internal | SteppedSigWaitInfo

/// What `UnixSystem.step` answers for a `Syscall.SigTimedWait`: what
/// `SteppedCall.SigTimedWait` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SigTimedWait`.
[<NoEquality ; NoComparison>]
type SteppedSigTimedWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the signal wait (`docs/design/sigwait-options.md`).
    internal | SteppedSigTimedWait

/// What `UnixSystem.step` answers for a `Syscall.RecvFrom`: what
/// `SteppedCall.RecvFrom` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.RecvFrom`.
[<NoEquality ; NoComparison>]
type SteppedRecvFrom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | SteppedRecvFrom

/// What `UnixSystem.step` answers for a `Syscall.RecvMsg`: what
/// `SteppedCall.RecvMsg` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.RecvMsg`.
[<NoEquality ; NoComparison>]
type SteppedRecvMsg<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | SteppedRecvMsg

/// What `UnixSystem.step` answers for a `Syscall.SendTo`: what
/// `SteppedCall.SendTo` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SendTo`.
[<NoEquality ; NoComparison>]
type SteppedSendTo<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | SteppedSendTo

/// What `UnixSystem.step` answers for a `Syscall.SendMsg`: what
/// `SteppedCall.SendMsg` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `Syscall.SendMsg`.
[<NoEquality ; NoComparison>]
type SteppedSendMsg<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | SteppedSendMsg

/// What `UnixSystem.step` answered: one case for each case of `Syscall`, named
/// as that case is and in the same order, holding exactly what the call's own
/// function answers. For a call that stops partway to copy from the caller's
/// memory, that is what its resumption answers once given what the `Syscall`
/// case holds, since `step` never stops partway.
///
/// So a case holds the system the call left wherever the call's function
/// answers one, and none where the function answers none because the call
/// cannot change anything (`GetEffectiveUserId`, `FStat`), when the system is
/// still the one the call was made in. As the functions' answers do, a case
/// may hold the calling thread asleep in the call, or the call interrupted by
/// a signal (`SyscallOutcome.Interrupted`), whose end the thread's return to
/// user mode says.
///
/// The cases of the reserved calls hold types whose representations are
/// internal, and nothing in this version makes one.
[<RequireQualifiedAccess>]
[<NoEquality ; NoComparison>]
type SteppedCall<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// What `UnixDescriptor.dup` answers.
    | Dup of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.dup2` answers.
    | Dup2 of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.dup3` answers.
    | Dup3 of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.fcntl` answers.
    | Fcntl of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.lseek` answers.
    | LSeek of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.flock` answers.
    | FLock of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.ftruncate` answers.
    | FTruncate of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.posixFadvise` answers.
    | PosixFAdvise of answer : FileAdviceAnswer
    /// What `UnixDescriptor.close` answers.
    | Close of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixDescriptor.bytesAvailable` answers.
    | BytesAvailable of answer : BytesAvailableAnswer
    /// What `UnixDescriptor.fileClone` answers.
    | FileClone of error : UnixError
    /// What `UnixDescriptor.terminalAttributes` answers.
    | TerminalAttributes of answer : TerminalAttributesAnswer
    /// What `UnixDescriptor.effectiveUserId` answers.
    | GetEffectiveUserId of user : UserId
    /// What `UnixDescriptor.effectiveGroupId` answers.
    | GetEffectiveGroupId of group : GroupId
    /// What `UnixDescriptor.getgroups` answers.
    | GetGroups of answer : GetGroupsAnswer
    /// What `UnixPathResolution.stat` answers.
    | Stat of answer : FileStatusAnswer
    /// What `UnixPathResolution.fstat` answers.
    | FStat of answer : FileStatusAnswer
    /// What `UnixPathResolution.fstatat` answers.
    | FStatAt of answer : FileStatusAnswer
    /// What `UnixPathResolution.chmod` answers.
    | ChMod of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.fchmod` answers.
    | FChMod of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.fchmodat` answers.
    | FChModAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.chown` answers.
    | ChOwn of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.lchown` answers.
    | LChOwn of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.fchown` answers.
    | FChOwn of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.fchownat` answers.
    | FChOwnAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.utimensat` answers.
    | UTimensAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.statfs` answers.
    | StatFs of answer : FileSystemStatisticsAnswer
    /// What `UnixPathResolution.fstatfs` answers.
    | FStatFs of answer : FileSystemStatisticsAnswer
    /// What `UnixPathResolution.getcwd` answers.
    | GetCwd of answer : GetCwdAnswer
    /// What `UnixPathResolution.chdir` answers.
    | ChDir of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPathResolution.access` answers, or
    /// `UnixPathResolution.accessWithPath` after it.
    | Access of answer : SyscallAnswer
    /// What `UnixPathResolution.faccessat` answers, or
    /// `UnixPathResolution.accessWithPath` after it.
    | FAccessAt of answer : SyscallAnswer
    /// What `UnixNamespace.openPath` answers.
    | Open of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.openat` answers.
    | OpenAt of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.readlink` answers.
    | ReadLink of answer : ReadLinkAnswer
    /// What `UnixNamespace.readlinkat` answers.
    | ReadLinkAt of answer : ReadLinkAnswer
    /// What `UnixNamespace.readDirectoryEntry` answers.
    | ReadDirectoryEntry of answer : ReadDirectoryAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.mkdir` answers.
    | MkDir of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.mkdirat` answers.
    | MkDirAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.mknod` answers.
    | MkNod of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.mknodat` answers.
    | MkNodAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.unlink` answers.
    | Unlink of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.rmdir` answers.
    | RmDir of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.unlinkat` answers.
    | UnlinkAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.rename` answers, or
    /// `UnixNamespace.renameWithDestination` after it.
    | Rename of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.renameat` answers, or
    /// `UnixNamespace.renameWithDestination` after it.
    | RenameAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.cloneFile` answers, or what the resumptions after
    /// it answer.
    | CloneFile of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.symlink` answers, or
    /// `UnixNamespace.symlinkWithPath` after it.
    | Symlink of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.symlinkat` answers, or
    /// `UnixNamespace.symlinkWithPath` after it.
    | SymlinkAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.link` answers, or
    /// `UnixNamespace.linkWithDestination` after it.
    | Link of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixNamespace.linkat` answers, or
    /// `UnixNamespace.linkWithDestination` after it.
    | LinkAt of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixReadWrite.read` answers.
    | Read of outcome : ReadOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixReadWrite.recv` answers.
    | Recv of outcome : ReadOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `recvfrom(2)`. Reserved: see `SteppedRecvFrom`.
    | RecvFrom of stepped : SteppedRecvFrom<'Thread, 'Handler>
    /// A `recvmsg(2)`. Reserved: see `SteppedRecvMsg`.
    | RecvMsg of stepped : SteppedRecvMsg<'Thread, 'Handler>
    /// What `UnixReadWrite.pread` answers.
    | PRead of answer : ReadAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixReadWrite.write` answers, or
    /// `UnixReadWrite.writeWithBytes` after it.
    | Write of fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>
    /// What `UnixReadWrite.send` answers, or `UnixReadWrite.sendWithBytes`
    /// after it.
    | Send of fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>
    /// A `sendto(2)`. Reserved: see `SteppedSendTo`.
    | SendTo of stepped : SteppedSendTo<'Thread, 'Handler>
    /// A `sendmsg(2)`. Reserved: see `SteppedSendMsg`.
    | SendMsg of stepped : SteppedSendMsg<'Thread, 'Handler>
    /// What `UnixReadWrite.pwrite` answers, or `UnixReadWrite.pwriteWithBytes`
    /// after it.
    | PWrite of answer : WriteAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixReadWrite.copyFileRange` answers.
    | CopyFileRange of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPipe.pipe2` answers.
    | Pipe2 of answer : Pipe2Answer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSocket.socket` answers.
    | Socket of result : Result<int * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixSocket.bind` answers, or `UnixSocket.bindWithAddress` after
    /// it.
    | Bind of answer : BindAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixConnection.connect` answers, or
    /// `UnixConnection.connectWithAddress` after it.
    | Connect of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSocket.listen` answers.
    | Listen of answer : ListenAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixConnection.accept` answers.
    | Accept of outcome : AcceptOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixConnection.shutdown` answers.
    | Shutdown of answer : ShutdownAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSocket.getsockname` answers.
    | GetSockName of answer : GetSockNameAnswer
    /// What `UnixSocket.getpeername` answers.
    | GetPeerName of answer : GetSockNameAnswer
    /// What `UnixSocket.setsockopt` answers, or
    /// `UnixSocket.setsockoptWithValue` after it.
    | SetSockOpt of answer : SetSockOptAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSocket.getsockopt` answers, or
    /// `UnixSocket.getsockoptWithLength` after it.
    | GetSockOpt of answer : GetSockOptAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPoll.poll` answers.
    | Poll of outcome : PollOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `select(2)`. Reserved: see `SteppedSelect`.
    | Select of stepped : SteppedSelect<'Thread, 'Handler>
    /// A `pselect(2)`. Reserved: see `SteppedPSelect`.
    | PSelect of stepped : SteppedPSelect<'Thread, 'Handler>
    /// What `UnixPoll.epollCreate1` answers.
    | EpollCreate1 of result : Result<int * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixPoll.epollCtl` answers.
    | EpollCtl of answer : EpollCtlAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixPoll.epollWait` answers.
    | EpollWait of outcome : EpollWaitOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixKqueue.kqueue` answers.
    | Kqueue of fd : int * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixKqueue.kevent` answers.
    | Kevent of outcome : KeventOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixInotify.inotifyInit1` answers.
    | InotifyInit1 of result : Result<int * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixInotify.inotifyAddWatch` answers, or
    /// `UnixInotify.inotifyAddWatchWithPath` after it.
    | InotifyAddWatch of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixInotify.inotifyRmWatch` answers.
    | InotifyRmWatch of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSignal.kill` answers.
    | Kill of result : Result<ProcessFate<KillOutcome, 'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.pthreadKill` answers.
    | PthreadKill of result : Result<ProcessFate<KillOutcome, 'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.sigaction` answers.
    | SigAction of result : Result<SignalDisposition<'Handler> * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.sigactionSyscall` answers.
    | SigActionSyscall of result : Result<SignalDisposition<'Handler> * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.pthreadSigmask` answers.
    | PthreadSigMask of result : Result<SignalMask * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.sigprocmask` answers.
    | SigProcMask of result : Result<SignalMask * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.rtSigprocmask` answers.
    | RtSigProcMask of result : Result<SignalMask * UnixSystem<'Thread, 'Handler>, UnixError>
    /// What `UnixSignal.sigpending` answers.
    | SigPending of pending : SignalMask
    /// What `UnixSignal.sigsuspend` answers.
    | SigSuspend of outcome : SigsuspendOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSignal.rtSigsuspend` answers.
    | RtSigSuspend of outcome : SigsuspendOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSignal.pause` answers.
    | Pause of outcome : SigsuspendOutcome * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSignal.sigreturn` answers.
    | SigReturn of system : UnixSystem<'Thread, 'Handler>
    /// A `sigwait(3)`. Reserved: see `SteppedSigWait`.
    | SigWait of stepped : SteppedSigWait<'Thread, 'Handler>
    /// A `sigwaitinfo(2)`. Reserved: see `SteppedSigWaitInfo`.
    | SigWaitInfo of stepped : SteppedSigWaitInfo<'Thread, 'Handler>
    /// A `sigtimedwait(2)`. Reserved: see `SteppedSigTimedWait`.
    | SigTimedWait of stepped : SteppedSigTimedWait<'Thread, 'Handler>
    /// What `UnixClock.clockGettime` answers.
    | ClockGetTime of result : Result<UnixTimestamp, UnixError>
    /// What `UnixClock.gettimeofday` answers.
    | GetTimeOfDay of time : UnixTimestamp
    /// A `nanosleep(2)`. Reserved: see `SteppedNanosleep`.
    | Nanosleep of stepped : SteppedNanosleep<'Thread, 'Handler>
    /// A `clock_nanosleep(2)`. Reserved: see `SteppedClockNanosleep`.
    | ClockNanosleep of stepped : SteppedClockNanosleep<'Thread, 'Handler>
    /// What `UnixEntropy.getRandom` answers.
    | GetRandom of answer : GetRandomAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixEntropy.getEntropy` answers.
    | GetEntropy of answer : GetEntropyAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixSystem.processId` answers.
    | GetProcessId of pid : ProcessId
    /// What `UnixSystem.umask` answers: the mask `mask` replaced.
    | UMask of previous : PermissionBits * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixCredentials.getresuid` answers.
    | GetResUid of answer : GetIdsAnswer<UserId>
    /// What `UnixCredentials.getresgid` answers.
    | GetResGid of answer : GetIdsAnswer<GroupId>
    /// What `UnixCredentials.setresuid` answers.
    | SetResUid of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixCredentials.setresgid` answers.
    | SetResGid of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixCredentials.setgroups` answers.
    | SetGroups of answer : SyscallAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixThreadLifecycle.spawn` answers.
    | Spawn of answer : SpawnAnswer * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixThreadLifecycle.exitThread` answers.
    | ExitThread of fate : ProcessFate<unit, 'Thread, 'Handler>
    /// What `UnixThreadLifecycle.exitGroup` answers: how the process ended,
    /// and the system without it.
    | ExitGroup of ended : EndedProcess * system : UnixSystem<'Thread, 'Handler>
    /// What `UnixScheduling.getcpu` answers.
    | GetCpu of answer : GetCpuAnswer
