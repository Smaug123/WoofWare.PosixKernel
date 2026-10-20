namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Every public function that takes a `Caller` checks it, through `Entry`,
/// before it does anything else: a caller in a process the system does not
/// hold, a thread the process does not have, a parked thread making a call or returning to user
/// mode, a thread making a call before the return to user mode it owes, and an
/// unparked thread at a finishing function each throw
/// `InvalidOperationException`, naming the function; the caller each
/// requirement admits does not. A query about a process, or about a thread,
/// checks only that the system holds the process.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCallerChecks =

    /// Which callers a public function admits.
    [<RequireQualifiedAccess>]
    type private Admits =
        /// A call: a thread parked in no syscall.
        | Running
        /// A finishing function: a thread parked in the call it finishes, which
        /// `world` parks `thread` in, and woken.
        | Finishing of thread : int
        /// The return to user mode: a thread parked in no syscall.
        | Returning
        /// A dispatch: any thread of the process, parked or not.
        | AnyThread
        /// A query about a process, or about a thread of it, which checks the
        /// process alone.
        | Process

    /// A public function, made by a caller in a system: what it answers is
    /// thrown away, since only whether it throws matters here.
    type private Call =
        {
            /// The name the function's refusals give it.
            Name : string
            Admits : Admits
            /// The flavours under which it is made: every flavour, but for a
            /// finishing function, only those whose `world` can park a thread
            /// in the call it finishes.
            On : SimulatedUnixFlavour list
            Make : Caller<int> -> UnixSystem<int, string> -> unit
        }

    /// The descriptor `world` gives a listener that thread 3 is parked in an
    /// `accept` of.
    let private listenerFd : int = 20

    /// The thread `world` parks in a `poll`, under every flavour.
    let private poller : int = 4

    /// The thread `world` parks in an `epoll_wait` under Linux, and in a
    /// `kevent` under Darwin.
    let private eventWaiter : int = 5

    /// The thread `world` parks in a `read` of an empty pipe.
    let private pipeReader : int = 6

    /// The thread `world` parks in a `write` to a full pipe.
    let private pipeWriter : int = 7

    /// The thread `world` parks in a `sigsuspend`.
    let private suspender : int = 1

    /// The thread `world` parks in a `pause`.
    let private pauser : int = 8

    /// The thread `world` leaves owing a return to user mode for a caught
    /// signal it sent itself.
    let private signalDebtor : int = 9

    /// The thread `world` leaves owing the return to user mode that ends a
    /// `sigsuspend` a caught signal interrupted.
    let private interruptedDebtor : int = 10

    /// A thread neither process has.
    let private absent : int = 11

    let private everyFlavour : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    /// One call of each public function of the families that take a caller:
    /// the descriptor, pipe, socket, poll, kqueue, read/write and inotify
    /// calls on the standard streams, which every flavour gives as pipes, and
    /// the path and namespace calls on the root directory, so that a call's
    /// `dirfd` is never looked up.
    let private calls : Call list =
        let root = PathArg.ofText "/"
        let file = PathArg.ofText "/f"

        let running (name : string) (make : Caller<int> -> UnixSystem<int, string> -> unit) : Call =
            {
                Name = name
                Admits = Admits.Running
                On = everyFlavour
                Make = make
            }

        let finishing
            (name : string)
            (sleeper : int)
            (on : SimulatedUnixFlavour list)
            (make : Caller<int> -> UnixSystem<int, string> -> unit)
            : Call
            =
            {
                Name = name
                Admits = Admits.Finishing sleeper
                On = on
                Make = make
            }

        let returning (name : string) (make : Caller<int> -> UnixSystem<int, string> -> unit) : Call =
            {
                Name = name
                Admits = Admits.Returning
                On = everyFlavour
                Make = make
            }

        let anyThread (name : string) (make : Caller<int> -> UnixSystem<int, string> -> unit) : Call =
            {
                Name = name
                Admits = Admits.AnyThread
                On = everyFlavour
                Make = make
            }

        let query (name : string) (make : Caller<int> -> UnixSystem<int, string> -> unit) : Call =
            {
                Name = name
                Admits = Admits.Process
                On = everyFlavour
                Make = make
            }

        let socketOption (system : UnixSystem<int, string>) : int * int =
            let platform = UnixSystem.platform system
            SimulatedUnixPlatform.socketOptionLevel platform, SimulatedUnixPlatform.reuseAddressOption platform

        [
            running
                "UnixCredentials.geteuid"
                (fun caller system -> UnixCredentials.geteuid caller system |> ignore<UserId>)
            running
                "UnixCredentials.getegid"
                (fun caller system -> UnixCredentials.getegid caller system |> ignore<GroupId>)
            running
                "UnixCredentials.getgroups"
                (fun caller system ->
                    UnixCredentials.getgroups caller UserBuffer.Mapped 0 system
                    |> ignore<GetGroupsAnswer>
                )
            running "UnixDescriptor.dup" (fun caller system -> UnixDescriptor.dup caller 0 system |> ignore)
            running "UnixDescriptor.dup2" (fun caller system -> UnixDescriptor.dup2 caller 0 5 system |> ignore)
            running "UnixDescriptor.dup3" (fun caller system -> UnixDescriptor.dup3 caller 0 5 0 system |> ignore)
            running
                "UnixDescriptor.fcntl"
                (fun caller system -> UnixDescriptor.fcntl caller 0 FcntlNumbering.GetStatusFlags 0 system |> ignore)
            running
                "UnixDescriptor.setNonBlocking"
                (fun caller system -> UnixDescriptor.setNonBlocking caller 0 true system |> ignore)
            running
                "UnixDescriptor.isNonBlocking"
                (fun caller system -> UnixDescriptor.isNonBlocking caller 0 system |> ignore<bool option>)
            running "UnixDescriptor.lseek" (fun caller system -> UnixDescriptor.lseek caller 0 0L 0 system |> ignore)
            // LOCK_SH, which a pipe end takes at once on Linux.
            running "UnixDescriptor.flock" (fun caller system -> UnixDescriptor.flock caller 0 1 system |> ignore)
            running
                "UnixDescriptor.ftruncate"
                (fun caller system -> UnixDescriptor.ftruncate caller 0 0L system |> ignore)
            running
                "UnixDescriptor.posixFadvise"
                (fun caller system -> UnixDescriptor.posixFadvise caller 0 0L 0L 0 system |> ignore<FileAdviceAnswer>)
            running "UnixDescriptor.close" (fun caller system -> UnixDescriptor.close caller 0 system |> ignore)
            running
                "UnixDescriptor.bytesAvailable"
                (fun caller system ->
                    UnixDescriptor.bytesAvailable caller 0 UserBuffer.Mapped system
                    |> ignore<BytesAvailableAnswer>
                )
            running
                "UnixDescriptor.fileClone"
                (fun caller system -> UnixDescriptor.fileClone caller 0 1 system |> ignore)
            running
                "UnixDescriptor.terminalAttributes"
                (fun caller system ->
                    UnixDescriptor.terminalAttributes caller 0 system
                    |> ignore<TerminalAttributesAnswer>
                )
            running "UnixPipe.pipe2" (fun caller system -> UnixPipe.pipe2 caller 0 UserBuffer.Mapped system |> ignore)
            finishing
                "UnixDescriptor.flockAcquire"
                2
                everyFlavour
                (fun caller system -> UnixDescriptor.flockAcquire caller system |> ignore)
            // AF_INET and SOCK_STREAM are 2 and 1 under both flavours.
            running "UnixSocket.socket" (fun caller system -> UnixSocket.socket caller 2 1 0 system |> ignore)
            running
                "UnixSocket.bind"
                (fun caller system -> UnixSocket.bind caller 0 UserBuffer.Mapped 16u system |> ignore)
            running "UnixSocket.listen" (fun caller system -> UnixSocket.listen caller 0 8 system |> ignore)
            running
                "UnixSocket.getsockname"
                (fun caller system ->
                    UnixSocket.getsockname caller 0 UserBuffer.Mapped 16u system
                    |> ignore<GetSockNameAnswer>
                )
            running
                "UnixSocket.getpeername"
                (fun caller system ->
                    UnixSocket.getpeername caller 0 UserBuffer.Mapped 16u system
                    |> ignore<GetSockNameAnswer>
                )
            running
                "UnixSocket.setsockopt"
                (fun caller system ->
                    let level, option = socketOption system

                    UnixSocket.setsockopt caller 0 level option UserBuffer.Mapped 4u system
                    |> ignore
                )
            running
                "UnixSocket.getsockopt"
                (fun caller system ->
                    let level, option = socketOption system

                    UnixSocket.getsockopt caller 0 level option UserBuffer.Mapped UserBuffer.Mapped system
                    |> ignore
                )
            running
                "UnixConnection.connect"
                (fun caller system -> UnixConnection.connect caller 0 UserBuffer.Mapped 16u system |> ignore)
            running
                "UnixConnection.accept"
                (fun caller system -> UnixConnection.accept caller 0 UserBuffer.Mapped 16u 0 system |> ignore)
            running "UnixConnection.shutdown" (fun caller system -> UnixConnection.shutdown caller 0 2 system |> ignore)
            finishing
                "UnixConnection.finishAccept"
                3
                everyFlavour
                (fun caller system -> UnixConnection.finishAccept caller system |> ignore)
            running "UnixPoll.poll" (fun caller system -> UnixPoll.poll caller [] 0 system |> ignore)
            finishing
                "UnixPoll.finishPoll"
                poller
                everyFlavour
                (fun caller system -> UnixPoll.finishPoll caller system |> ignore)
            // Each epoll call names the standard input, which is no epoll
            // instance. Darwin refuses every one, but only once the caller is
            // checked.
            running "UnixPoll.epollCreate1" (fun caller system -> UnixPoll.epollCreate1 caller 0 system |> ignore)
            running
                "UnixPoll.epollCtl"
                (fun caller system ->
                    UnixPoll.epollCtl caller 0 1 1 (EpollEventArgument.Readable (EpollEvents.In, 0UL)) system
                    |> ignore
                )
            running
                "UnixPoll.epollWait"
                (fun caller system -> UnixPoll.epollWait caller 0 1 UserBuffer.Mapped 0 system |> ignore)
            finishing
                "UnixPoll.finishEpollWait"
                eventWaiter
                [ SimulatedUnixFlavour.Linux ]
                (fun caller system -> UnixPoll.finishEpollWait caller system |> ignore)
            // Likewise each kqueue call, which Linux refuses.
            running "UnixKqueue.kqueue" (fun caller system -> UnixKqueue.kqueue caller system |> ignore)
            running
                "UnixKqueue.kevent"
                (fun caller system ->
                    UnixKqueue.kevent
                        caller
                        0
                        0
                        []
                        1
                        UserBuffer.Mapped
                        (TimespecArgument.Readable
                            {
                                Seconds = 0L
                                Nanoseconds = 0L
                            })
                        system
                    |> ignore
                )
            finishing
                "UnixKqueue.finishKevent"
                eventWaiter
                [ SimulatedUnixFlavour.Darwin ]
                (fun caller system -> UnixKqueue.finishKevent caller system |> ignore)
            // Each read and write of nothing, so that an admitted caller's call
            // answers at once. Darwin has no `copy_file_range`, but refuses it
            // only once the caller is checked.
            running
                "UnixReadWrite.read"
                (fun caller system -> UnixReadWrite.read caller 0 UserBuffer.Mapped 0UL system |> ignore)
            running
                "UnixReadWrite.recv"
                (fun caller system -> UnixReadWrite.recv caller 0 UserBuffer.Mapped 0UL 0 system |> ignore)
            running
                "UnixReadWrite.pread"
                (fun caller system -> UnixReadWrite.pread caller 0 UserBuffer.Mapped 0UL 0L system |> ignore)
            running
                "UnixReadWrite.write"
                (fun caller system -> UnixReadWrite.write caller 1 UserBuffer.Mapped 0UL system |> ignore)
            running
                "UnixReadWrite.send"
                (fun caller system -> UnixReadWrite.send caller 1 UserBuffer.Mapped 0UL 0 system |> ignore)
            running
                "UnixReadWrite.pwrite"
                (fun caller system -> UnixReadWrite.pwrite caller 1 UserBuffer.Mapped 0UL 0L system |> ignore)
            running
                "UnixReadWrite.copyFileRange"
                (fun caller system -> UnixReadWrite.copyFileRange caller 0 1 0UL 0 system |> ignore)
            finishing
                "UnixReadWrite.finishRead"
                pipeReader
                everyFlavour
                (fun caller system -> UnixReadWrite.finishRead caller system |> ignore)
            finishing
                "UnixReadWrite.finishWrite"
                pipeWriter
                everyFlavour
                (fun caller system -> UnixReadWrite.finishWrite caller system |> ignore)
            running
                "UnixPathResolution.stat"
                (fun caller system ->
                    UnixPathResolution.stat caller SymlinkPolicy.Follow root system
                    |> ignore<FileStatusAnswer>
                )
            running
                "UnixPathResolution.fstat"
                (fun caller system -> UnixPathResolution.fstat caller 0 system |> ignore<FileStatusAnswer>)
            running
                "UnixPathResolution.fstatat"
                (fun caller system -> UnixPathResolution.fstatat caller 0 root 0 system |> ignore<FileStatusAnswer>)
            running
                "UnixPathResolution.chmod"
                (fun caller system -> UnixPathResolution.chmod caller root 0o755 system |> ignore)
            running
                "UnixPathResolution.fchmod"
                (fun caller system -> UnixPathResolution.fchmod caller 0 0o600 system |> ignore)
            running
                "UnixPathResolution.fchmodat"
                (fun caller system -> UnixPathResolution.fchmodat caller 0 root 0o755 0 system |> ignore)
            running
                "UnixPathResolution.chown"
                (fun caller system -> UnixPathResolution.chown caller root None None system |> ignore)
            running
                "UnixPathResolution.lchown"
                (fun caller system -> UnixPathResolution.lchown caller root None None system |> ignore)
            running
                "UnixPathResolution.fchown"
                (fun caller system -> UnixPathResolution.fchown caller 0 None None system |> ignore)
            running
                "UnixPathResolution.fchownat"
                (fun caller system -> UnixPathResolution.fchownat caller 0 root None None 0 system |> ignore)
            running
                "UnixPathResolution.utimensat"
                (fun caller system ->
                    UnixPathResolution.utimensat
                        caller
                        0
                        (NullablePathArgument.NotNull root)
                        TimesArgument.Null
                        0
                        system
                    |> ignore
                )
            running
                "UnixPathResolution.statfs"
                (fun caller system ->
                    UnixPathResolution.statfs caller root system
                    |> ignore<FileSystemStatisticsAnswer>
                )
            running
                "UnixPathResolution.fstatfs"
                (fun caller system -> UnixPathResolution.fstatfs caller 0 system |> ignore<FileSystemStatisticsAnswer>)
            running
                "UnixPathResolution.getcwd"
                (fun caller system ->
                    UnixPathResolution.getcwd caller UserBuffer.Mapped 4096UL system
                    |> ignore<GetCwdAnswer>
                )
            running
                "UnixPathResolution.chdir"
                (fun caller system -> UnixPathResolution.chdir caller root system |> ignore)
            // R_OK.
            running
                "UnixPathResolution.access"
                (fun caller system -> UnixPathResolution.access caller 4 system |> ignore)
            running
                "UnixPathResolution.faccessat"
                (fun caller system -> UnixPathResolution.faccessat caller 0 4 0 system |> ignore)
            running
                "UnixCredentials.getresuid"
                (fun caller system ->
                    UnixCredentials.getresuid caller UserBuffer.Mapped UserBuffer.Mapped UserBuffer.Mapped system
                    |> ignore<GetIdsAnswer<UserId>>
                )
            running
                "UnixCredentials.getresgid"
                (fun caller system ->
                    UnixCredentials.getresgid caller UserBuffer.Mapped UserBuffer.Mapped UserBuffer.Mapped system
                    |> ignore<GetIdsAnswer<GroupId>>
                )
            running
                "UnixCredentials.setresuid"
                (fun caller system -> UnixCredentials.setresuid caller None None None system |> ignore)
            running
                "UnixCredentials.setresgid"
                (fun caller system -> UnixCredentials.setresgid caller None None None system |> ignore)
            running
                "UnixCredentials.setgroups"
                (fun caller system -> UnixCredentials.setgroups caller 0 (GroupListWords.Readable []) system |> ignore)
            running
                "UnixClock.gettimeofday"
                (fun caller system -> UnixClock.gettimeofday caller system |> ignore<UnixTimestamp>)
            running
                "UnixClock.clockGettime"
                (fun caller system -> UnixClock.clockGettime caller 0 system |> ignore<ClockGettimeAnswer>)
            running
                "UnixEntropy.getRandom"
                (fun caller system -> UnixEntropy.getRandom caller UserBuffer.Mapped 8UL 0u system |> ignore)
            running
                "UnixEntropy.getEntropy"
                (fun caller system -> UnixEntropy.getEntropy caller UserBuffer.Mapped 8UL system |> ignore)
            running
                "UnixNamespace.openPath"
                (fun caller system -> UnixNamespace.openPath caller root 0 0 system |> ignore)
            running
                "UnixNamespace.openat"
                (fun caller system -> UnixNamespace.openat caller 0 root 0 0 system |> ignore)
            running
                "UnixNamespace.readlink"
                (fun caller system ->
                    UnixNamespace.readlink caller root UserBuffer.Mapped 64 system
                    |> ignore<ReadLinkAnswer>
                )
            running
                "UnixNamespace.readlinkat"
                (fun caller system ->
                    UnixNamespace.readlinkat caller 0 root UserBuffer.Mapped 64 system
                    |> ignore<ReadLinkAnswer>
                )
            running
                "UnixNamespace.readDirectoryEntry"
                (fun caller system -> UnixNamespace.readDirectoryEntry caller 0 system |> ignore)
            running "UnixNamespace.mkdir" (fun caller system -> UnixNamespace.mkdir caller root 0o755 system |> ignore)
            running
                "UnixNamespace.mkdirat"
                (fun caller system -> UnixNamespace.mkdirat caller 0 root 0o755 system |> ignore)
            // S_IFREG, which each flavour makes as a creating open does.
            running
                "UnixNamespace.mknod"
                (fun caller system -> UnixNamespace.mknod caller file 0o100644 0u system |> ignore)
            running
                "UnixNamespace.mknodat"
                (fun caller system -> UnixNamespace.mknodat caller 0 file 0o100644 0u system |> ignore)
            running "UnixNamespace.unlink" (fun caller system -> UnixNamespace.unlink caller root system |> ignore)
            running "UnixNamespace.rmdir" (fun caller system -> UnixNamespace.rmdir caller root system |> ignore)
            running
                "UnixNamespace.unlinkat"
                (fun caller system -> UnixNamespace.unlinkat caller 0 root 0 system |> ignore)
            running "UnixNamespace.rename" (fun caller system -> UnixNamespace.rename caller root system |> ignore)
            running
                "UnixNamespace.renameat"
                (fun caller system -> UnixNamespace.renameat caller 0 root 0 system |> ignore)
            running "UnixNamespace.cloneFile" (fun caller system -> UnixNamespace.cloneFile caller 0 system |> ignore)
            running "UnixNamespace.symlink" (fun caller system -> UnixNamespace.symlink caller root system |> ignore)
            running
                "UnixNamespace.symlinkat"
                (fun caller system -> UnixNamespace.symlinkat caller root 0 system |> ignore)
            running "UnixNamespace.link" (fun caller system -> UnixNamespace.link caller root system |> ignore)
            running
                "UnixNamespace.linkat"
                (fun caller system -> UnixNamespace.linkat caller 0 root 0 0 system |> ignore)
            running "UnixInotify.inotifyInit1" (fun caller system -> UnixInotify.inotifyInit1 caller 0 system |> ignore)
            // IN_CREATE.
            running
                "UnixInotify.inotifyAddWatch"
                (fun caller system -> UnixInotify.inotifyAddWatch caller 0 0x100u system |> ignore)
            running
                "UnixInotify.inotifyRmWatch"
                (fun caller system -> UnixInotify.inotifyRmWatch caller 0 1 system |> ignore)
            // Signal number 0 sends nothing.
            running
                "UnixSignal.kill"
                (fun caller system ->
                    UnixSignal.kill caller (ProcessId.toInt32 (Caller.processId caller)) 0 system
                    |> ignore
                )
            running "UnixSignal.pthreadKill" (fun caller system -> UnixSignal.pthreadKill caller 0 0 system |> ignore)
            // SIGUSR1's disposition, asked for and left as it is. 10 is SIGUSR1 on
            // Linux and SIGBUS on Darwin, a signal either way.
            running "UnixSignal.sigaction" (fun caller system -> UnixSignal.sigaction caller 10 None system |> ignore)
            running
                "UnixSignal.sigactionSyscall"
                (fun caller system -> UnixSignal.sigactionSyscall caller 10 None system |> ignore)
            // A NULL set asks for the mask, whatever `how` is. Darwin has no
            // `rt_sigprocmask`, but refuses it only once the caller is checked.
            running
                "UnixSignal.pthreadSigmask"
                (fun caller system -> UnixSignal.pthreadSigmask caller 0 None system |> ignore)
            running
                "UnixSignal.sigprocmask"
                (fun caller system -> UnixSignal.sigprocmask caller 0 None system |> ignore)
            running
                "UnixSignal.rtSigprocmask"
                (fun caller system -> UnixSignal.rtSigprocmask caller 0 None 8UL system |> ignore)
            running
                "UnixSignal.sigpending"
                (fun caller system -> UnixSignal.sigpending caller system |> ignore<SignalMask>)
            running
                "UnixSignal.sigsuspend"
                (fun caller system -> UnixSignal.sigsuspend caller SignalMask.empty system |> ignore)
            running
                "UnixSignal.rtSigsuspend"
                (fun caller system -> UnixSignal.rtSigsuspend caller SignalMask.empty 8UL system |> ignore)
            running "UnixSignal.pause" (fun caller system -> UnixSignal.pause caller system |> ignore)
            finishing
                "UnixSignal.finishSigsuspend"
                suspender
                everyFlavour
                (fun caller system -> UnixSignal.finishSigsuspend caller system |> ignore)
            finishing
                "UnixSignal.finishSigsuspend"
                pauser
                everyFlavour
                (fun caller system -> UnixSignal.finishSigsuspend caller system |> ignore)
            // `UnixWait.finish`, which finishes each of those, of each sleeper.
            for sleeper in [ 2 ; 3 ; poller ; eventWaiter ; pipeReader ; pipeWriter ; suspender ; pauser ] do
                finishing
                    "UnixWait.finish"
                    sleeper
                    everyFlavour
                    (fun caller system -> UnixWait.finish caller system |> ignore<FinishedCall<int, string>>)
            // The thread has no handler frame, which `sigreturn` refuses only once
            // the caller is checked.
            running
                "UnixSignal.sigreturn"
                (fun caller system -> UnixSignal.sigreturn caller (HandlerFrameId 0L) system |> ignore)
            returning
                "UnixSignal.onReturnToUser"
                (fun caller system -> UnixSignal.onReturnToUser caller system |> ignore)
            running
                "UnixThreadLifecycle.spawn"
                (fun caller system -> UnixThreadLifecycle.spawn caller 20 (CpuId 0) system |> ignore)
            // The leader's exit, while other threads live, is refused once the
            // caller is checked.
            running
                "UnixThreadLifecycle.exitThread"
                (fun caller system -> UnixThreadLifecycle.exitThread caller 0 system |> ignore)
            running
                "UnixThreadLifecycle.exitGroup"
                (fun caller system ->
                    UnixThreadLifecycle.exitGroup caller 0 system
                    |> ignore<EndedProcess * UnixSystem<int, string>>
                )
            anyThread
                "UnixScheduling.dispatch"
                (fun caller system -> UnixScheduling.dispatch caller (CpuId 0) system |> ignore)
            // No thread has been dispatched, and `getcpu` of a thread not running
            // throws `InvalidOperationException` too, so the caller is
            // dispatched first wherever `dispatch` admits it. Darwin has no
            // `getcpu`, which it refuses once the caller is checked.
            running
                "UnixScheduling.getcpu"
                (fun caller system ->
                    let system =
                        try
                            UnixScheduling.dispatch caller (CpuId 0) system
                        with :? InvalidOperationException ->
                            system

                    UnixScheduling.getcpu caller system |> ignore<GetCpuAnswer>
                )
            running "UnixSystem.processId" (fun caller system -> UnixSystem.processId caller system |> ignore)
            running "UnixSystem.umask" (fun caller system -> UnixSystem.umask caller 0o022 system |> ignore)
            // Each case of `step` is made through its own function, which names
            // itself: `getpid`'s is `UnixSystem.processId`.
            running
                "UnixSystem.processId"
                (fun caller system -> UnixSystem.step caller Syscall.GetProcessId system |> ignore)
            running "UnixDescriptor.dup" (fun caller system -> UnixSystem.step caller (Syscall.Dup 0) system |> ignore)
            running
                "UnixSystem.umask"
                (fun caller system -> UnixSystem.step caller (Syscall.UMask 0o022) system |> ignore)
            query
                "UnixScheduling.runningOn"
                (fun caller system -> UnixScheduling.runningOn caller system |> ignore<CpuId option>)
            query
                "UnixWait.satisfied"
                (fun caller system -> UnixWait.satisfied caller system |> ignore<Set<WakePrimitive> option>)
            query "UnixSignal.owesReturn" (fun caller system -> UnixSignal.owesReturn caller system |> ignore<bool>)
            query
                "UnixSystem.leader"
                (fun caller system -> UnixSystem.leader (Caller.processId caller) system |> ignore<int>)
            query
                "UnixSystem.threads"
                (fun caller system -> UnixSystem.threads (Caller.processId caller) system |> ignore)
            query
                "UnixSystem.signals"
                (fun caller system -> UnixSystem.signals (Caller.processId caller) system |> ignore)
            query
                "UnixSystem.environment"
                (fun caller system -> UnixSystem.environment (Caller.processId caller) system |> ignore)
            query
                "UnixSystem.processPath"
                (fun caller system -> UnixSystem.processPath (Caller.processId caller) system |> ignore)
            query
                "UnixSystem.fileDescriptors"
                (fun caller system -> UnixSystem.fileDescriptors (Caller.processId caller) system |> ignore)
            query
                "UnixSystem.currentDirectoryInode"
                (fun caller system ->
                    UnixSystem.currentDirectoryInode (Caller.processId caller) system
                    |> ignore<InodeNumber>
                )
            query
                "UnixSystem.credentials"
                (fun caller system -> UnixSystem.credentials (Caller.processId caller) system |> ignore)
            query
                "UnixSystem.fileModeCreationMask"
                (fun caller system ->
                    UnixSystem.fileModeCreationMask (Caller.processId caller) system
                    |> ignore<PermissionBits>
                )
            query
                "UnixSystem.descriptorTarget"
                (fun caller system -> UnixSystem.descriptorTarget (Caller.processId caller) 0 system |> ignore)
            query
                "UnixPathResolution.currentDirectoryPath"
                (fun caller system ->
                    UnixPathResolution.currentDirectoryPath (Caller.processId caller) system
                    |> ignore
                )
        ]

    /// What each requirement refuses, by the thread the caller names: what the
    /// message says.
    [<RequireQualifiedAccess>]
    type private Refused =
        | NoProcess
        | Absent
        | Parked
        | Unparked
        | Asleep
        | NotReturning
        | OwesSignal
        | OwesInterrupted

    let private reason (refused : Refused) : string =
        match refused with
        | Refused.NoProcess -> "but the system holds no process"
        | Refused.Absent -> "is not one of the process's threads"
        | Refused.Parked -> "and is making another call"
        | Refused.Unparked -> "is not parked, so there is no call to finish"
        | Refused.Asleep -> "and nothing has woken it"
        | Refused.NotReturning -> "so it is not returning to user mode"
        | Refused.OwesSignal -> "a signal is deliverable to it"
        | Refused.OwesInterrupted -> "interrupted its last call"

    /// A machine of `platform` holding two processes, each with threads 0 to 10,
    /// and the view of the first, in which thread 2 is parked in an `flock` of
    /// a pipe it made (so that `flockAcquire` admits it), thread 3 in an
    /// `accept` of a listener at `listenerFd` (so that `finishAccept` admits
    /// it), `poller` in a `poll`, `eventWaiter` in an `epoll_wait` (Linux) or a
    /// `kevent` (Darwin) of a queue the leader made, `pipeReader` in a `read`
    /// of an empty pipe and `pipeWriter` in a `write` to a full one, each of
    /// a pipe the leader made, `suspender` in a `sigsuspend` and `pauser` in a
    /// `pause`; in which `signalDebtor` and `interruptedDebtor` owe a return to
    /// user mode; and the IDs of the two processes.
    let private world (platform : SimulatedUnixPlatform) : ProcessId * ProcessId * UnixSystem<int, string> =
        let pids, machine = Machines.withThreads platform 2 11
        let own, other = pids.[0], pids.[1]
        let view = Machines.viewOf own machine

        let view =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin ->
                // Darwin refuses an `flock` of a pipe, so its waiter is parked
                // as the library would park it.
                Proc.view own view
                |> Parking.park
                    2
                    (ParkedSyscall.Flock
                        {
                            ParkedFlock.Requester =
                                FileDescriptorRegistry.tryFindId 0 (Proc.fileDescriptors own view) |> Option.get
                            Mode = FlockMode.Exclusive
                        })
                |> Proc.unview
            | SimulatedUnixFlavour.Linux ->
                // Both ends of a pipe are one object to `flock`, so the write
                // end's lock waits on the read end's.
                let reader, writer, view =
                    match UnixPipe.pipe2 (Caller.make own 0) 0 UserBuffer.Mapped view with
                    | Pipe2Answer.Created (reader, writer), view -> reader, writer, view
                    | other, _ -> failwith $"pipe2: %A{other}"

                let lockExclusive = 2

                match UnixDescriptor.flock (Caller.make own 0) reader lockExclusive view with
                | SyscallOutcome.Answered (SyscallAnswer.Completed 0L), view ->
                    match UnixDescriptor.flock (Caller.make own 2) writer lockExclusive view with
                    | SyscallOutcome.WouldBlock _, view -> view
                    | other -> failwith $"the second flock: expected it to sleep, got %A{other}"
                | other -> failwith $"the first flock: %A{other}"

        let view =
            let leader = Caller.make own 0

            let listener, view =
                NewSocket.createAs leader SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp view

            let address =
                CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 8080us)

            let view =
                match CopyIn.bindAs leader listener UserBuffer.Mapped 16u address view with
                | Ok (BindAnswer.Bound _, view) -> view
                | other -> failwith $"bind of the listener: %A{other}"

            let view =
                match UnixSocket.listen leader listener 8 view with
                | ListenAnswer.Listening _, view -> view
                | other -> failwith $"listen: %A{other}"

            // Out of the way of the descriptors the calls above name.
            let view =
                match UnixDescriptor.dup2 leader listener listenerFd view with
                | DescriptorAnswer.Returned _, view -> UnixDescriptor.close leader listener view |> snd
                | other -> failwith $"dup2 of the listener: %A{other}"

            match UnixConnection.accept (Caller.make own 3) listenerFd UserBuffer.Mapped 16u 0 view with
            | AcceptOutcome.WouldBlock _, view -> view
            | other -> failwith $"the accept: expected it to sleep, got %A{other}"

        // Nothing to watch and no deadline: it sleeps until a signal.
        let view =
            match UnixPoll.poll (Caller.make own poller) [] -1 view with
            | PollOutcome.WouldBlock _, view -> view
            | other -> failwith $"the poll: expected it to sleep, got %A{other}"

        let view =
            let leader = Caller.make own 0
            let waiter = Caller.make own eventWaiter

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux ->
                match UnixPoll.epollCreate1 leader 0 view with
                | DescriptorAnswer.Returned epoll, view ->
                    match UnixPoll.epollWait waiter epoll 1 UserBuffer.Mapped -1 view with
                    | EpollWaitOutcome.WouldBlock _, view -> view
                    | other -> failwith $"the epoll_wait: expected it to sleep, got %A{other}"
                | DescriptorAnswer.Failed error, _ -> failwith $"epoll_create1: %O{error}"
            | SimulatedUnixFlavour.Darwin ->
                let kq, view =
                    match UnixKqueue.kqueue leader view with
                    | DescriptorAnswer.Returned kq, view -> kq, view
                    | DescriptorAnswer.Failed error, _ -> failwith $"kqueue: %O{error}"

                match UnixKqueue.kevent waiter kq 0 [] 1 UserBuffer.Mapped TimespecArgument.Null view with
                | KeventOutcome.WouldBlock _, view -> view
                | other -> failwith $"the kevent: expected it to sleep, got %A{other}"

        let pipe (view : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
            match UnixPipe.pipe2 (Caller.make own 0) 0 UserBuffer.Mapped view with
            | Pipe2Answer.Created (reader, writer), view -> reader, writer, view
            | other, _ -> failwith $"pipe2: %A{other}"

        let view =
            let reader, _, view = pipe view

            match UnixReadWrite.read (Caller.make own pipeReader) reader UserBuffer.Mapped 1UL view with
            | ReadOutcome.WouldBlock _, view -> view
            | other -> failwith $"the read: expected it to sleep, got %A{other}"

        // More than either flavour's pipe holds, so the write puts in what
        // fits and sleeps for the rest.
        let view =
            let _, writer, view = pipe view
            let count = 1 <<< 20

            match UnixReadWrite.write (Caller.make own pipeWriter) writer UserBuffer.Mapped (uint64 count) view with
            | CallProgress.NeedsCopyIn paused ->
                let range = PausedWrite.copyRange paused

                match
                    UnixReadWrite.writeWithBytes
                        (ImmutableArray.Create<byte> (Array.zeroCreate<byte> range.ByteCount))
                        paused
                with
                | ProcessFate.Continues (WriteOutcome.WouldBlock _, view), None -> view
                | other -> failwith $"the write: expected it to sleep, got %A{other}"
            | CallProgress.Answered other -> failwith $"the write: expected it to copy, got %A{other}"

        // No signal is pending, so each sleeps.
        let view =
            match UnixSignal.sigsuspend (Caller.make own suspender) SignalMask.empty view with
            | SigsuspendOutcome.WouldBlock _, view -> view
            | other -> failwith $"the sigsuspend: expected it to sleep, got %A{other}"

        let view =
            match UnixSignal.pause (Caller.make own pauser) view with
            | SigsuspendOutcome.WouldBlock _, view -> view
            | other -> failwith $"the pause: expected it to sleep, got %A{other}"

        // SIGUSR1 caught. `signalDebtor` sends it to itself, and takes it only
        // as it returns to user mode; the leader sends it to
        // `interruptedDebtor` while that thread blocks it, and it interrupts a
        // `sigsuspend` whose mask lets it through as the call is made, the
        // thread taking it as it returns from the call.
        let view =
            let leader = Caller.make own 0
            let numbering = SimulatedUnixPlatform.signalNumbering platform
            let usr1 = Signal.toRawSignoUnder numbering Signal.SIGUSR1

            let send (sender : Caller<int>) (target : int) (view : UnixSystem<int, string>) : UnixSystem<int, string> =
                match UnixSignal.pthreadKill sender target usr1 view with
                | ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, view) -> view
                | other -> failwith $"pthread_kill of %d{target}: %A{other}"

            let view =
                match
                    UnixSignal.sigaction leader usr1 (Some (SignalDisposition.Catch (SignalCatch.ofHandler "h"))) view
                with
                | SigactionAnswer.Completed _, view -> view
                | SigactionAnswer.Failed error, _ -> failwith $"sigaction: %O{error}"

            let view =
                let usr1Mask = SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR1)

                match
                    UnixSignal.pthreadSigmask
                        (Caller.make own interruptedDebtor)
                        (MaskHow.block numbering)
                        (Some usr1Mask)
                        view
                with
                | SignalMaskAnswer.Completed _, view -> view
                | SignalMaskAnswer.Failed error, _ -> failwith $"pthread_sigmask: %O{error}"

            let view =
                send leader interruptedDebtor view
                |> send (Caller.make own signalDebtor) signalDebtor

            match UnixSignal.sigsuspend (Caller.make own interruptedDebtor) SignalMask.empty view with
            | SigsuspendOutcome.Interrupted, view -> view
            | other -> failwith $"the sigsuspend: expected the pending signal to interrupt it, got %A{other}"

        own, other, view

    /// Every public function that takes a caller, or asks about a process,
    /// refuses each caller its requirement refuses, with `InvalidOperationException` naming
    /// it and saying why, before it does anything else, so even where the
    /// flavour would refuse the call itself (`dup3`, epoll and `copy_file_range`
    /// on Darwin, kqueue on Linux); and does not refuse the caller its
    /// requirement admits.
    [<Test>]
    let ``every function that takes a caller or a process checks it first`` () : unit =
        let mismatches =
            [
                for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
                    let own, other, view = world platform
                    let ghost = ProcessId.parseOrFail "TestCallerChecks" 77

                    // Each sleeper of `own` woken, as `UnixWait.wake` would leave it
                    // had what it waits for come and gone.
                    let wokenView =
                        (view, UnixSystem.threads own view)
                        ||> Map.fold (fun view thread state ->
                            match UnixThreadState.parkedIn state with
                            | Some _ -> ForgedPark.wokenCaller (Caller.make own thread) view
                            | None -> view
                        )

                    let flavour = SimulatedUnixPlatform.flavour platform

                    for call in calls |> List.filter (fun call -> List.contains flavour call.On) do
                        let asleepCases : (Caller<int> * Refused option) list =
                            match call.Admits with
                            | Admits.Running ->
                                [
                                    Caller.make own 0, None
                                    Caller.make other 0, None
                                    Caller.make ghost 0, Some Refused.NoProcess
                                    Caller.make own absent, Some Refused.Absent
                                    Caller.make own 1, Some Refused.Parked
                                    Caller.make own signalDebtor, Some Refused.OwesSignal
                                    Caller.make own interruptedDebtor, Some Refused.OwesInterrupted
                                ]
                            | Admits.Finishing sleeper ->
                                [
                                    Caller.make own sleeper, Some Refused.Asleep
                                    Caller.make other sleeper, Some Refused.Unparked
                                    Caller.make ghost sleeper, Some Refused.NoProcess
                                    Caller.make own absent, Some Refused.Absent
                                    Caller.make own 0, Some Refused.Unparked
                                ]
                            | Admits.Returning ->
                                [
                                    Caller.make own 0, None
                                    Caller.make other 0, None
                                    Caller.make ghost 0, Some Refused.NoProcess
                                    Caller.make own absent, Some Refused.Absent
                                    Caller.make own suspender, Some Refused.NotReturning
                                    Caller.make own signalDebtor, None
                                    Caller.make own interruptedDebtor, None
                                ]
                            | Admits.AnyThread ->
                                [
                                    Caller.make own 0, None
                                    Caller.make own suspender, None
                                    Caller.make other 0, None
                                    Caller.make ghost 0, Some Refused.NoProcess
                                    Caller.make own absent, Some Refused.Absent
                                ]
                            | Admits.Process ->
                                [
                                    Caller.make own 0, None
                                    Caller.make own suspender, None
                                    Caller.make own absent, None
                                    Caller.make other 0, None
                                    Caller.make ghost 0, Some Refused.NoProcess
                                ]

                        // With every sleeper woken, a finishing function admits its own.
                        let wokenCases : (Caller<int> * Refused option) list =
                            match call.Admits with
                            | Admits.Finishing sleeper -> [ Caller.make own sleeper, None ]
                            | Admits.Running
                            | Admits.Returning
                            | Admits.AnyThread
                            | Admits.Process -> []

                        let cases =
                            (asleepCases |> List.map (fun (caller, expected) -> caller, expected, view, ""))
                            @ (wokenCases
                               |> List.map (fun (caller, expected) -> caller, expected, wokenView, ", woken"))

                        for caller, expected, view, woken in cases do
                            let case = $"%O{platform}, %s{call.Name} by %O{caller}%s{woken}"

                            let thrown =
                                try
                                    call.Make caller view
                                    None
                                with e ->
                                    Some e

                            match expected, thrown with
                            | None, Some (:? InvalidOperationException as e) ->
                                yield $"%s{case}: expected admission, refused: %s{e.Message}"
                            | None, _ -> ()
                            | Some refused, Some (:? InvalidOperationException as e) ->
                                if
                                    not (e.Message.StartsWith $"%s{call.Name}: " && e.Message.Contains (reason refused))
                                then
                                    yield
                                        $"%s{case}: refused, but the message does not name the function and say %s{reason refused}: %s{e.Message}"
                            | Some refused, Some e ->
                                yield
                                    $"%s{case}: expected InvalidOperationException (%A{refused}), threw %s{e.GetType().Name}: %s{e.Message}"
                            | Some refused, None -> yield $"%s{case}: expected refusal (%A{refused}), was admitted"
            ]

        mismatches |> shouldEqual []

    /// `UnixSignal.owesReturn` answers `true` for the two threads `world`
    /// leaves owing a return to user mode, one for a signal deliverable to it
    /// and one for the call a signal interrupted, and `false` for every thread
    /// parked in a call, asleep or woken, for a thread a call admits, and for
    /// a name that is no thread: exactly the threads a call refuses for the
    /// return they owe.
    [<Test>]
    let ``owesReturn answers true for exactly the threads a call refuses for the return they owe`` () : unit =
        let mismatches =
            [
                for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
                    let own, other, view = world platform

                    let wokenView =
                        (view, UnixSystem.threads own view)
                        ||> Map.fold (fun view thread state ->
                            match UnixThreadState.parkedIn state with
                            | Some _ -> ForgedPark.wokenCaller (Caller.make own thread) view
                            | None -> view
                        )

                    for view, woken in [ view, "" ; wokenView, ", woken" ] do
                        for caller in
                            [
                                for thread in 0..absent do
                                    Caller.make own thread
                                Caller.make other 0
                            ] do
                            let case = $"%O{platform}, %O{caller}%s{woken}"
                            let owes = UnixSignal.owesReturn caller view

                            let refusedForReturn =
                                try
                                    UnixSystem.processId caller view |> ignore<ProcessId>
                                    false
                                with :? InvalidOperationException as e ->
                                    e.Message.Contains (reason Refused.OwesSignal)
                                    || e.Message.Contains (reason Refused.OwesInterrupted)

                            let debtor =
                                Caller.processId caller = own
                                && (Caller.thread caller = signalDebtor || Caller.thread caller = interruptedDebtor)

                            if owes <> refusedForReturn || owes <> debtor then
                                yield
                                    $"%s{case}: owesReturn answered %b{owes}; a call was refused for the return: %b{refusedForReturn}; a debtor: %b{debtor}"
            ]

        mismatches |> shouldEqual []
