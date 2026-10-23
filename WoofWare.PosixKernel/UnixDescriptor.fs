namespace WoofWare.PosixKernel

/// Which of the two non-portable `lseek` extensions a raw `whence` names on the
/// simulated platform. Linux numbers `SEEK_DATA` 3 and `SEEK_HOLE` 4; Darwin
/// transposes them, which is why the raw number alone names no operation.
[<RequireQualifiedAccess>]
type internal SeekExtension =
    | SeekData
    | SeekHole

/// What `lseek`'s `SEEK_END` counts from on one descriptor.
[<RequireQualifiedAccess>]
type private SeekEndBasis =
    /// The seek is `SEEK_SET` or `SEEK_CUR`, which never ask.
    | NotConsulted
    | Size of size : int64
    /// The file takes no `SEEK_END` at all, whatever the offset.
    | Fails of error : UnixError

/// Why this kernel will not answer an `lseek`.
///
/// Distinct from an errno: an errno is an answer, and these are the inputs for
/// which this library has measured what real kernels do and found no single
/// answer to give.
[<RequireQualifiedAccess>]
type internal LSeekRefusal =
    /// `SEEK_DATA` or `SEEK_HOLE` on a seekable file.
    | Sparseness of whence : int * meaning : SeekExtension
    /// `SEEK_END` on a directory whose size this kernel cannot state: one on an
    /// NFS mount.
    | DirectoryEnd of inode : InodeNumber
    /// `SEEK_CUR` on a directory that has been read part of the way through.
    ///
    /// Both kernels answer, but with a value only their own filesystem mints:
    /// tmpfs reports the offset of the next entry it will yield, APFS a count of
    /// entries returned under a per-directory sequence number in the high 32
    /// bits. This kernel's position is a name, and no number stands for it.
    | DirectoryPosition of inode : InodeNumber

[<RequireQualifiedAccess>]
module internal LSeekRefusal =
    /// What this kernel knows about why it cannot answer, for a client composing
    /// a diagnostic. The client supplies its own half — which entry point, which
    /// descriptor — because those are things it decoded and this library never
    /// saw.
    let describe (refusal : LSeekRefusal) : string =
        match refusal with
        | LSeekRefusal.Sparseness (whence, meaning) ->
            let named =
                match meaning with
                | SeekExtension.SeekData -> "SEEK_DATA"
                | SeekExtension.SeekHole -> "SEEK_HOLE"

            $"whence %d{whence} is %s{named} on the simulated platform. This kernel keeps a file's sparseness as the pages a write has filled, but has not measured how coarsely each filesystem reports its holes, so it cannot say where a real one would put the data and holes; and the two platforms transpose the numbers (3 is SEEK_DATA on Linux and SEEK_HOLE on Darwin), so the raw value does not name one operation."
        | LSeekRefusal.DirectoryEnd inode ->
            $"inode %O{inode} is a directory on an NFS mount, and was asked to seek relative to its end. An NFS directory's size is whatever the server's own filesystem reports, which nothing in this machine determines, so this kernel cannot say where the end is. SEEK_SET and SEEK_CUR on a directory are portable and are supported, as is SEEK_END on a tmpfs or APFS directory."
        | LSeekRefusal.DirectoryPosition inode ->
            $"inode %O{inode} is a directory that this description has read part of the way through, and SEEK_CUR asks where it is. A real kernel answers with its own filesystem's resumption cookie (the next entry's offset on tmpfs; a sequence number and an entry count on APFS), which is not a number this kernel's position corresponds to. SEEK_CUR is answered at the start of a directory, and after a SEEK_SET or SEEK_END moved the description."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : LSeekRefusal) : RefusalKind =
        match refusal with
        | LSeekRefusal.Sparseness _ -> RefusalKind.Unmodelled
        | LSeekRefusal.DirectoryEnd _ -> RefusalKind.Unmodelled
        | LSeekRefusal.DirectoryPosition _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer an `flock`.
///
/// Every case but `Interruption` is a measured divergence between the two
/// flavours that this library models Linux's side of. Darwin's `flock` is
/// unmodelled not because its return codes are unknown — they are measured,
/// and named in each case's description — but because what they leave the
/// *lock state* as is not, which is what a model would have to commit to.
[<RequireQualifiedAccess>]
type internal FLockRefusal =
    /// Not exactly one of LOCK_SH/LOCK_EX/LOCK_UN, optionally with LOCK_NB.
    | DarwinMalformedOperation of operation : int
    /// A pipe.
    | DarwinPipe of pipe : PipeId
    /// A kqueue.
    | DarwinKqueue
    | DarwinSocket of socket : SocketId
    /// An acquire by a description that already holds a lock. Only a conversion
    /// can expose the keep-versus-drop divergence, and only when it fails —
    /// refused on the request rather than on the outcome, so that the refusal is
    /// a property of what was asked rather than of who else held a lock.
    | DarwinConversion
    /// The acquisition was asleep and a signal is pending for the thread, and this
    /// library will not say how the signal ends it.
    | Interruption of SyscallInterruptionRefusal

[<RequireQualifiedAccess>]
module internal FLockRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half — which entry point, and which of its callers could have
    /// reached it.
    let describe (refusal : FLockRefusal) : string =
        match refusal with
        | FLockRefusal.DarwinMalformedOperation operation ->
            $"operation %d{operation} is malformed (not exactly one of LOCK_SH/LOCK_EX/LOCK_UN, optionally with LOCK_NB), which Linux rejects with EINVAL unless LOCK_MAND (bit 32) is set, in which case it ignores the request and answers 0, and which Darwin does not treat uniformly -- measured, Darwin answers EBADF for 0, a bare LOCK_NB and unknown bits alone, but *succeeds* for LOCK_SH|LOCK_EX, LOCK_UN|LOCK_SH and LOCK_SH with an unknown bit."
        | FLockRefusal.DarwinPipe pipe ->
            $"the descriptor is an end of pipe %O{pipe}. Linux permits `flock` on a pipe, with both ends contending as one object; Darwin refuses it with ENOTSUP (raw 45, and note Darwin numbers ENOTSUP and EOPNOTSUPP differently, 45 against 102, while Linux gives both 95) on every pipe."
        | FLockRefusal.DarwinKqueue ->
            "the descriptor is a kqueue. Darwin refuses `flock` on one with ENOTSUP (raw 45), for every operation including LOCK_UN, where Linux permits it on an epoll descriptor and returns 0."
        | FLockRefusal.DarwinSocket socket ->
            $"the descriptor is socket %O{socket}. Linux permits `flock` on a socket and returns 0; Darwin refuses it with ENOTSUP (raw 45)."
        | FLockRefusal.DarwinConversion ->
            "the descriptor is converting a lock it already holds. Should that conversion fail, Linux leaves the description holding *nothing* (`flock` removes the old lock before establishing the new one, and the two steps are not atomic) while Darwin leaves the old lock in place -- measured on both, and indistinguishable from the return code, which is EWOULDBLOCK either way."
        | FLockRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FLockRefusal) : RefusalKind =
        match refusal with
        | FLockRefusal.DarwinMalformedOperation _ -> RefusalKind.Unmodelled
        | FLockRefusal.DarwinPipe _ -> RefusalKind.Unmodelled
        | FLockRefusal.DarwinKqueue -> RefusalKind.Unmodelled
        | FLockRefusal.DarwinSocket _ -> RefusalKind.Unmodelled
        | FLockRefusal.DarwinConversion -> RefusalKind.Unmodelled
        | FLockRefusal.Interruption inner -> SyscallInterruptionRefusal.kind inner

/// Why this kernel will not answer a `posix_fadvise(2)`.
[<RequireQualifiedAccess>]
type internal PosixFadviseRefusal =
    /// The simulated platform's libc has no `posix_fadvise`
    /// (`SimulatedUnixPlatform.providesPosixFadvise` is `false`), so no program
    /// could have made the call and there is no answer to give.
    | NotProvided

[<RequireQualifiedAccess>]
module internal PosixFadviseRefusal =
    /// What this kernel knows about why it cannot answer.
    let describe (refusal : PosixFadviseRefusal) : string =
        match refusal with
        | PosixFadviseRefusal.NotProvided ->
            "the simulated platform's C library has no posix_fadvise, so no program could have made the call and there is no answer to give."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : PosixFadviseRefusal) : RefusalKind =
        match refusal with
        | PosixFadviseRefusal.NotProvided -> RefusalKind.NotOnPlatform

/// What `posix_fadvise(2)` answered.
///
/// Not `SyscallAnswer`, because `posix_fadvise` reports failure differently from
/// every other call here: it *returns* the error number and leaves errno
/// untouched, which is why the failure case names an error but no sentinel for a
/// caller to return.
[<RequireQualifiedAccess>]
type FileAdviceAnswer =
    /// The hint was accepted. It changes nothing this kernel represents; a real
    /// kernel would adjust its readahead.
    | Completed
    /// The call returns `error` — as a positive number, not through errno.
    | Failed of error : UnixError

/// Why this kernel will not commit a truncation.
[<RequireQualifiedAccess>]
type internal TruncationRefusal =
    /// Longer than this kernel can represent. A real filesystem answers without
    /// difficulty — measured on ext4 and APFS alike, `ftruncate` to three
    /// gigabytes succeeds and leaves a sparse file — so this is a limit of the
    /// model, and refusing beats reporting an errno no kernel would produce for
    /// that length.
    | ExceedsRepresentableLength of inode : InodeNumber * length : int64

[<RequireQualifiedAccess>]
module internal TruncationRefusal =
    let describe (refusal : TruncationRefusal) : string =
        match refusal with
        | TruncationRefusal.ExceedsRepresentableLength (inode, length) ->
            $"inode %O{inode} was asked to become %d{length} bytes, which is longer than the %d{VirtualFileSystem.maxFileLength} bytes this kernel can represent. A real filesystem answers this without difficulty -- measured on ext4 and APFS alike, ftruncate to three gigabytes succeeds and leaves a sparse file -- so this is a limit of the model, and refusing is better than reporting an errno no kernel would have produced for that length."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : TruncationRefusal) : RefusalKind =
        match refusal with
        | TruncationRefusal.ExceedsRepresentableLength _ -> RefusalKind.Unmodelled

/// Why a Darwin close that ends a sleeping pipe `write` cannot be answered: the
/// write raises `SIGPIPE` for the process as it returns, before the close does,
/// and what that signal does is something a close has no way to report.
[<RequireQualifiedAccess>]
type internal EndedWriteSignalRefusal =
    /// `SIGPIPE`'s disposition is the default, so the signal ends the process.
    | TerminatesProcess
    /// The process is process ID 1, and what an init process does with a
    /// signal it has no handler for is not modelled.
    | InitProcess
    /// Which thread would take the signal is not modelled.
    | Receiver of SignalReceiverRefusal

[<RequireQualifiedAccess>]
module internal EndedWriteSignalRefusal =
    /// What this kernel knows about why it cannot say what the `SIGPIPE`
    /// that the ended write raises does.
    let describe (refusal : EndedWriteSignalRefusal) : string =
        match refusal with
        | EndedWriteSignalRefusal.TerminatesProcess ->
            "SIGPIPE's disposition is the default, so the signal ends the process, which a close has no answer to report."
        | EndedWriteSignalRefusal.InitProcess ->
            "the process is process ID 1, and what an init process does with a signal it has no handler for is not modelled."
        | EndedWriteSignalRefusal.Receiver refusal ->
            $"which thread would take the signal is not modelled: %s{SignalReceiverRefusal.describe refusal}"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : EndedWriteSignalRefusal) : RefusalKind =
        match refusal with
        | EndedWriteSignalRefusal.TerminatesProcess -> RefusalKind.Unmodelled
        | EndedWriteSignalRefusal.InitProcess -> RefusalKind.Unmodelled
        | EndedWriteSignalRefusal.Receiver inner -> SignalReceiverRefusal.kind inner

/// Why this kernel will not close a descriptor.
///
/// Generic in what names a thread because most of them are about a thread parked
/// in a wait, and which one that is cannot be recomputed by the client:
/// nothing stops two threads parking on the same event queue, so a client repeating the
/// search could name a different one from the one this refusal is about.
///
/// Under Linux a sleeping call holds the description it sleeps on, so a close
/// under it is served: the description outlives its last descriptor until the
/// call returns. Under Darwin a close of the descriptor a sleeping `accept`,
/// pipe `read`, pipe `write` or `kevent` was made through ends the call, which
/// is modelled, so it is served; the Darwin cases here are the ones this
/// kernel does not model.
[<RequireQualifiedAccess>]
type internal CloseRefusal<'Thread> =
    /// Releasing the description destroys an object in a state this kernel
    /// has not measured.
    | Release of DescriptionReleaseRefusal
    /// Any descriptor onto an open file description that `thread` is parked on
    /// an `flock` of, under the Darwin flavour.
    | DarwinFlockedDescriptorWithWaiter of description : OpenFileDescriptionId * thread : 'Thread
    /// The descriptor `fd`, which `thread` is parked in a Linux-flavoured
    /// `poll(2)` watching.
    ///
    /// Refused because Linux's sleeping poll keeps the file it found, which
    /// this kernel represents, but when it wakes it looks the number up again
    /// and reports what the number names by then, and it is woken only by the
    /// files it found: a wake that finds nothing ready under the number sleeps
    /// again until the next one. This kernel's wake conditions are levels, not
    /// edges, so such a poll would be woken again at once, for ever. A Darwin
    /// poll's watched descriptor closes: the close removes the filters
    /// registered through it from the kqueue the poll made, as Darwin does.
    | PolledDescriptor of fd : int * thread : 'Thread
    /// The descriptor a `read` or `write` of a pipe or a connected socket by
    /// `thread`, asleep on the open file description `description`, was made
    /// through, under the Darwin flavour, when the call has something besides
    /// the close to answer: bytes to read, room to write into, a FIN or a
    /// reset, a signal with a handler to take, or (a pipe write whose
    /// description has become non-blocking) a read to give up at. Or a close
    /// that would drain a UDP socket on which `thread` is asleep in a receive
    /// with a datagram, the error or a signal to take.
    ///
    /// Darwin's close ends such a call (a pipe read with end of file, a pipe
    /// write with `EPIPE`, a socket's either with `EBADF`), and which of the
    /// close and what had already woken the call it answers is unmeasured.
    | DarwinWokenTransfer of description : OpenFileDescriptionId * thread : 'Thread
    /// The close would end the pipe `write` `thread` is asleep in, under the
    /// Darwin flavour, and the `SIGPIPE` that write raises as it returns is one
    /// this kernel cannot answer (`refusal`).
    | DarwinEndedWriteSignal of thread : 'Thread * refusal : EndedWriteSignalRefusal
    /// The descriptor is the last one onto the open file description of the
    /// connected stream socket `socket`, whose `SO_LINGER` is on, and `thread`'s
    /// call in flight still holds that description, so the close would leave
    /// the socket to be closed when that call returns.
    ///
    /// Under Linux a close of the last descriptor onto a socket a `read` or
    /// `write` sleeps on answers 0 and leaves the call holding the socket
    /// (measured, `tcp-blocking.c` sections R-close and W-close). This kernel
    /// refuses some closes under `SO_LINGER` (`DescriptionReleaseRefusal.DarwinAbortBehindQueuedFin`,
    /// `DescriptionReleaseRefusal.LingeringClose`), and whether such a close
    /// would be refused depends on state that changes before the call returns:
    /// the peer, the FINs, and the bytes still unsent. A call's return has no refusal to
    /// answer with, so the close is refused here instead, whatever the linger
    /// time.
    | LingeringCloseDeferredToCall of socket : SocketId * thread : 'Thread

[<RequireQualifiedAccess>]
module internal CloseRefusal =
    /// What this kernel knows about why it cannot close the descriptor. The
    /// client supplies its own half — which entry point, which descriptor
    /// number, and what it would have to build to lift the refusal.
    let describe (refusal : CloseRefusal<'Thread>) : string =
        match refusal with
        | CloseRefusal.DarwinFlockedDescriptorWithWaiter (description, thread) ->
            $"the descriptor names open file description %O{description}, and thread %O{thread} is parked on an `flock` of it. Measured on Darwin (open-file-references.c section D), closing the descriptor the flock was entered through does not return until the flock has, whether or not a dup keeps the description: the close blocks until the lock is granted or a signal ends the flock. This kernel models no close that sleeps, nor which descriptor a call was entered through."
        | CloseRefusal.PolledDescriptor (fd, thread) ->
            $"thread %O{thread} is parked in a poll(2) watching fd %d{fd}. Measured on Linux (poll-timeout.c), the sleeping poll keeps the file it found: the close does not wake it, the closed file can still wake it (a datagram sent to a closed UDP socket's address did), and when it wakes it looks the number up again, answering POLLNVAL if the number is free and the new file's readiness if another open took the number. This kernel keeps the file alive, but a poll woken by that file and finding nothing under the number sleeps again until the file's next wake-up, an edge, where this kernel's wake conditions are levels: the poll would be woken again at once, for ever."
        | CloseRefusal.DarwinWokenTransfer (description, thread) ->
            $"thread %O{thread} is asleep in a read or write of open file description %O{description}, a pipe end or a connected socket, made through this descriptor, and the call has something besides the close to answer: bytes, room, a FIN or a reset, a signal, or a read to give up at. Measured on Darwin (close-ends-call.c sections P1-P7, tcp-blocking.c sections R-close and W-close), closing the descriptor a sleeping read or write was made through ends it: a pipe read with end of file, a pipe write with EPIPE, and a socket's either with EBADF. Which of that and what had already woken the call a kernel answers is unmeasured: no probe has held a woken call off the CPU until a close, since Darwin has no SCHED_FIFO, and a woken call in a stopped process finishes in the kernel all the same (pipe-blocking.c section N4)."
        | CloseRefusal.DarwinEndedWriteSignal (thread, refusal) ->
            $"the close ends the pipe write thread %O{thread} is asleep in through this descriptor. Measured on Darwin (close-ends-call.c sections P2-P4), that write answers EPIPE and raises SIGPIPE for the process as it returns, which it does before the close does; but %s{EndedWriteSignalRefusal.describe refusal}"
        | CloseRefusal.LingeringCloseDeferredToCall (socket, thread) ->
            $"the descriptor is the last one onto connected socket %O{socket}, whose SO_LINGER is on, and thread %O{thread} is in a call that still holds it. Measured on Linux (tcp-blocking.c sections R-close and W-close), the close answers 0 and the socket is closed when that call returns. Under SO_LINGER that close would be abortive (a time of zero) or would wait for unsent bytes (a positive time), which this kernel refuses in some states, and the call can change the state before it returns; this kernel models no refusal at a call's return, nor a close deferred to one under SO_LINGER."
        | CloseRefusal.Release refusal -> DescriptionReleaseRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : CloseRefusal<'Thread>) : RefusalKind =
        match refusal with
        | CloseRefusal.Release inner -> DescriptionReleaseRefusal.kind inner
        | CloseRefusal.DarwinFlockedDescriptorWithWaiter _ -> RefusalKind.Unmodelled
        | CloseRefusal.PolledDescriptor _ -> RefusalKind.Unmodelled
        | CloseRefusal.DarwinWokenTransfer _ -> RefusalKind.Unmodelled
        | CloseRefusal.DarwinEndedWriteSignal (_, inner) -> EndedWriteSignalRefusal.kind inner
        | CloseRefusal.LingeringCloseDeferredToCall _ -> RefusalKind.Unmodelled

/// A status flag the flavour's `fcntl(F_SETFL)` would set, and this kernel
/// does not model.
[<RequireQualifiedAccess>]
type UnmodelledStatusFlag =
    /// `O_APPEND`, on both flavours.
    | Append
    /// `O_ASYNC` (Linux's `FASYNC`), on both flavours.
    | Asynchronous
    /// Linux's `O_DIRECT`.
    | Direct
    /// Linux's `O_NOATIME`.
    | NoAccessTime

[<RequireQualifiedAccess>]
module UnmodelledStatusFlag =
    /// The flag's name in the flavour's `<fcntl.h>`.
    let name (flag : UnmodelledStatusFlag) : string =
        match flag with
        | UnmodelledStatusFlag.Append -> "O_APPEND"
        | UnmodelledStatusFlag.Asynchronous -> "O_ASYNC"
        | UnmodelledStatusFlag.Direct -> "O_DIRECT"
        | UnmodelledStatusFlag.NoAccessTime -> "O_NOATIME"

/// Why this kernel will not answer an `fcntl(2)`.
[<RequireQualifiedAccess>]
type internal FcntlRefusal =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// The command is none of `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_GETFD`,
    /// `F_SETFD`, `F_GETFL` and `F_SETFL` in the flavour's numbering.
    | UnmodelledCommand of command : int
    /// An `F_SETFL` word would set these flags, which change what later calls
    /// on the description do, in ways this kernel does not model.
    | UnmodelledStatusFlags of word : int * flags : UnmodelledStatusFlag list

[<RequireQualifiedAccess>]
module internal FcntlRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point asked, and what it should do instead.
    let describe (refusal : FcntlRefusal) : string =
        match refusal with
        | FcntlRefusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | FcntlRefusal.UnmodelledCommand command ->
            $"fcntl command %d{command} is none of F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL and F_SETFL in this flavour's numbering. Both kernels answer EBADF for a descriptor that is not open whatever the command, and that is answered; what a command they know does is not modelled."
        | FcntlRefusal.UnmodelledStatusFlags (word, flags) ->
            let names = flags |> List.map UnmodelledStatusFlag.name |> String.concat ", "
            $"F_SETFL with 0x%x{word} would set %s{names}, which change what later reads and writes on the description do (or, for O_NOATIME and O_DIRECT, answer EPERM or EINVAL depending on the file's owner and filesystem), and this kernel models none of that."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FcntlRefusal) : RefusalKind =
        match refusal with
        | FcntlRefusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | FcntlRefusal.UnmodelledCommand _ -> RefusalKind.Unmodelled
        | FcntlRefusal.UnmodelledStatusFlags _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer a `dup2(2)`.
[<RequireQualifiedAccess>]
type internal Dup2Refusal<'Thread> =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// The target is open, and this kernel will not close it (`refusal`): a
    /// `dup2` onto an open descriptor closes it as `close(2)` does, sleeping
    /// calls and all.
    | ClosingTarget of refusal : CloseRefusal<'Thread>

[<RequireQualifiedAccess>]
module internal Dup2Refusal =
    /// What this kernel knows about why it cannot answer.
    let describe (refusal : Dup2Refusal<'Thread>) : string =
        match refusal with
        | Dup2Refusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | Dup2Refusal.ClosingTarget refusal ->
            $"the target descriptor is open, and dup2 closes it as close(2) does, which this kernel will not do here: %s{CloseRefusal.describe refusal}"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : Dup2Refusal<'Thread>) : RefusalKind =
        match refusal with
        | Dup2Refusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | Dup2Refusal.ClosingTarget inner -> CloseRefusal.kind inner

/// Why this kernel will not answer a `dup3(2)`.
[<RequireQualifiedAccess>]
type internal Dup3Refusal<'Thread> =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// The flavour has no `dup3`.
    | NotProvided of flavour : SimulatedUnixFlavour
    /// As `Dup2Refusal.ClosingTarget`.
    | ClosingTarget of refusal : CloseRefusal<'Thread>

[<RequireQualifiedAccess>]
module internal Dup3Refusal =
    /// What this kernel knows about why it cannot answer.
    let describe (refusal : Dup3Refusal<'Thread>) : string =
        match refusal with
        | Dup3Refusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | Dup3Refusal.NotProvided flavour ->
            $"this kernel is %O{flavour}-flavoured, and only Linux has dup3; no program could have made the call."
        | Dup3Refusal.ClosingTarget refusal ->
            $"the target descriptor is open, and dup3 closes it as close(2) does, which this kernel will not do here: %s{CloseRefusal.describe refusal}"

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : Dup3Refusal<'Thread>) : RefusalKind =
        match refusal with
        | Dup3Refusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | Dup3Refusal.NotProvided _ -> RefusalKind.NotOnPlatform
        | Dup3Refusal.ClosingTarget inner -> CloseRefusal.kind inner

/// What a change to a descriptor's `O_NONBLOCK` answered.
///
/// Store and answer are separate because for a kqueue they disagree: its bit
/// toggles and the call still reports a failure.
[<RequireQualifiedAccess>]
type SetNonBlockingAnswer =
    /// The flag is now what the caller asked for, and the call succeeded.
    | Set
    /// The call failed with this errno.
    ///
    /// The system still comes back, and the flag may have changed with it: on a
    /// kqueue the bit toggles and the answer is `ENOTTY` anyway.
    | Failed of error : UnixError

/// What `ioctl(fd, FIONREAD, &count)` answered.
[<RequireQualifiedAccess>]
type BytesAvailableAnswer =
    /// The call returned 0, having written `count` into the caller's `int`.
    | Reported of count : int
    /// The call returned -1 with this errno, and wrote nothing.
    | Failed of error : UnixError

/// Why this kernel will not answer an `ioctl(FIONREAD)`.
[<RequireQualifiedAccess>]
type internal BytesAvailableRefusal =
    /// The destination has no answer at the copy.
    | Buffer of BufferRefusal
    /// The descriptor `fd` names something other than a pipe or a connected
    /// TCP socket, for which what `FIONREAD` answers is not modelled.
    | UnmodelledTarget of fd : int

[<RequireQualifiedAccess>]
module internal BytesAvailableRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point asked.
    let describe (refusal : BytesAvailableRefusal) : string =
        match refusal with
        | BytesAvailableRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | BytesAvailableRefusal.UnmodelledTarget fd ->
            $"fd %d{fd} is neither an end of a pipe nor a connected TCP socket, and FIONREAD is answered here for those only. The other kinds answer per kind and per flavour (measured, pipe-syscalls.c): a regular file reports its size less the offset on both; a directory is ENOTTY on Linux and reports a number of its own on Darwin; a socket reports what it has queued; an epoll instance is EINVAL and a kqueue ENOTTY. Model the kind before answering."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : BytesAvailableRefusal) : RefusalKind =
        match refusal with
        | BytesAvailableRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | BytesAvailableRefusal.UnmodelledTarget _ -> RefusalKind.Unmodelled

/// The settings of a terminal, as `tcgetattr(3)` writes them into the
/// caller's `struct termios`.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `TerminalAttributesAnswer.Attributes`.
type TerminalSettings =
    // What it holds is the design of terminals, which this kernel does not
    // model yet.
    internal | TerminalSettings

/// What `tcgetattr(3)` answered, which is also what `isatty(3)` answers: it is
/// `tcgetattr` with the answer reduced to 1 or 0 and the errno left as it was.
[<RequireQualifiedAccess>]
type TerminalAttributesAnswer =
    /// `tcgetattr` returns -1 and `isatty` returns 0, each with this errno.
    | NotATerminal of error : UnixError
    /// `fd` is a terminal: `tcgetattr` returns 0, having written `settings`
    /// into the caller's `struct termios`, and `isatty` returns 1.
    ///
    /// Reserved: nothing this kernel models is a terminal, so nothing in this
    /// version answers it.
    | Attributes of settings : TerminalSettings

/// Why this kernel will not answer an `ioctl(2)` of `FICLONE`.
[<RequireQualifiedAccess>]
type internal FileCloneRefusal =
    /// This kernel is not Linux-flavoured, and `FICLONE` is a Linux request.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// Both descriptors name regular files on a mount of this type, whose
    /// answer to a clone request is unmeasured.
    | UnmeasuredFileSystem of fileSystem : EmulatedFileSystemType

[<RequireQualifiedAccess>]
module internal FileCloneRefusal =
    /// What this kernel knows about why it will not answer. A client adds which
    /// entry point asked, and with which descriptors.
    let describe (refusal : FileCloneRefusal) : string =
        match refusal with
        | FileCloneRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and FICLONE is a Linux ioctl request."
        | FileCloneRefusal.UnmeasuredFileSystem fileSystem ->
            $"both descriptors name regular files on a %O{fileSystem} mount. Whether a clone request succeeds there depends on the filesystem (tmpfs answers EOPNOTSUPP; Btrfs and XFS share the source's extents), and this filesystem's answer has not been measured."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FileCloneRefusal) : RefusalKind =
        match refusal with
        | FileCloneRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | FileCloneRefusal.UnmeasuredFileSystem _ -> RefusalKind.Unmodelled

/// Which filesystem an open object lives on, for a call that refuses to work
/// across two.
[<RequireQualifiedAccess>]
type private ObjectFileSystem =
    /// A file or directory, on the root filesystem (`None`) or on the
    /// filesystem mounted at `mountedRoot`.
    | Mounted of mountedRoot : InodeNumber option
    | Pseudo of PseudoFileSystem

/// Why a file descriptor cannot be seeked, as a *fault* rather than as the errno
/// it becomes.
///
/// Not a `UnixError`, because `lseek` orders the two faults differently per
/// flavour: measured, Linux validates `whence` between them while Darwin does
/// not, so an ordering written over errnos would let a future third fault
/// inherit whichever position its errno's arm happened to occupy.
[<RequireQualifiedAccess>]
type private DescriptorFault =
    /// No such descriptor in the process's table; `EBADF`. Precedes everything
    /// else on both platforms.
    | NotOpen
    /// The descriptor names something with no file offset — a pipe; `ESPIPE`.
    | NotSeekable

/// Each flavour's `<fcntl.h>` numbers for the `fcntl(2)` commands
/// `UnixDescriptor.fcntl` models, and for `FD_CLOEXEC`.
[<RequireQualifiedAccess>]
module FcntlNumbering =
    /// `F_DUPFD`, on both flavours.
    [<Literal>]
    let DuplicateAtOrAbove : int = 0

    /// `F_GETFD`, on both flavours.
    [<Literal>]
    let GetDescriptorFlags : int = 1

    /// `F_SETFD`, on both flavours.
    [<Literal>]
    let SetDescriptorFlags : int = 2

    /// `F_GETFL`, on both flavours.
    [<Literal>]
    let GetStatusFlags : int = 3

    /// `F_SETFL`, on both flavours.
    [<Literal>]
    let SetStatusFlags : int = 4

    /// `F_DUPFD_CLOEXEC`: Linux's 1030, Darwin's 67.
    let duplicateCloseOnExec (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 1030
        | SimulatedUnixFlavour.Darwin -> 67

    /// `FD_CLOEXEC`, on both flavours.
    [<Literal>]
    let CloseOnExec : int = 1

    /// Darwin's `FD_CLOFORK`.
    [<Literal>]
    let DarwinCloseOnFork : int = 2

[<RequireQualifiedAccess>]
module UnixDescriptor =

    /// `tryDup` once `Entry` has admitted its caller.
    let private tryDupIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DescriptorAnswer * ProcessView<'Thread, 'Handler>, DescriptorLimitRefusal>
        =
        let registry = UnixSystemState.fileDescriptors system

        // Measured (`fcntl-dup.c`, LIMIT rows): EBADF ahead of the allocation.
        match FileDescriptorRegistry.tryFindId fd registry with
        | None -> Ok (DescriptorAnswer.Failed UnixError.EBADF, system)
        | Some _ ->

        match
            FileDescriptorRegistry.room (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform) 0 1 registry
        with
        | Error refusal -> Error refusal
        | Ok () ->

        match FileDescriptorRegistry.dup (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform) fd registry with
        | Ok (newFd, registry) ->
            Ok (DescriptorAnswer.Returned newFd, UnixSystemState.withFileDescriptors registry system)
        | Error FileDescriptorDupError.BadFd ->
            failwith
                $"UnixDescriptor.dup: fd %d{fd} was open a moment ago and is not now (this is a bug in this library)."

    /// `dup`, with a refusal answered as the `Error` rather than raised.
    let internal tryDup<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, DescriptorLimitRefusal>
        =
        Entry.call
            "UnixDescriptor.dup"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryDupIn fd)
            system

    /// `dup(2)`: the lowest non-negative descriptor not in use, sharing `fd`'s
    /// open file description. EBADF is its only failure, and comes first: a
    /// descriptor that is not open is EBADF even when the new one would reach
    /// the bound (`SimulatedUnixPlatform.descriptorBound`), which is otherwise
    /// refused.
    let dup<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : DescriptorAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryDup caller fd system
        |> Refusal.orRaise "UnixDescriptor.dup" DescriptorLimitRefusal.kind DescriptorLimitRefusal.describe

    /// `tryLseek` once `Entry` has admitted its caller.
    let private tryLseekIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (offset : int64)
        (whence : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, LSeekRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        // POSIX's numbering, and both platforms' `<unistd.h>` — for these three. It
        // stops here; 3 and 4 are handled below and are *not* portable.
        let seekSet = 0
        let seekCur = 1
        let seekEnd = 2
        let seekMax = 4

        // The two orderings below are measured, and this is the syscall where
        // they differ most. On a single-fault input the platforms agree on
        // every row; they part company on two:
        //
        //   input                       Linux    Darwin
        //   pipe + whence 99            EINVAL   ESPIPE
        //   pipe + whence 99 + overflow EINVAL   ESPIPE
        //
        // So Linux validates `whence` before it asks whether the object is
        // seekable, and Darwin the other way round. The descriptor itself
        // precedes both on either platform — `lseek(badfd, ..)` is EBADF for
        // every whence and offset measured, including 99, 3, 4 and INT64_MAX —
        // and the offset arithmetic follows both, pinned by
        // `lseek(pipe, -1, SEEK_SET)` = ESPIPE on both (seekability first) and
        // `lseek(f, 1, 99)` from INT64_MAX = EINVAL on both (whence first).
        let whenceValid = whence >= seekSet && whence <= seekMax

        let target =
            FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system)

        let descriptorFault : DescriptorFault option =
            match target with
            | None -> Some DescriptorFault.NotOpen
            | Some (OpenFileTarget.Pipe _) ->
                // Not seekable: `lseek` on a pipe is ESPIPE on both platforms
                // whichever end it is.
                Some DescriptorFault.NotSeekable
            // Measured: Darwin refuses `lseek` on a kqueue with ESPIPE, while
            // Linux gives an epoll descriptor `noop_llseek`, which succeeds and
            // reports 0 without consulting the offset or moving anything. So a
            // kqueue has a descriptor fault here and an epoll instance has none;
            // the epoll success is served below, after the whence check the
            // syscall still applies.
            | Some (OpenFileTarget.Kqueue _) -> Some DescriptorFault.NotSeekable
            // Measured on both flavours: `lseek` on a FIFO is ESPIPE, as on a
            // pipe.
            | Some (OpenFileTarget.Fifo _) -> Some DescriptorFault.NotSeekable
            | Some (OpenFileTarget.Epoll _) -> None
            // An inotify instance's `lseek` is `noop_llseek` too: measured
            // (`inotify-probe.c` row I lseek), 0 for `SEEK_SET`, `SEEK_CUR` and
            // `SEEK_END`, at offsets 0 and 5.
            | Some (OpenFileTarget.Inotify _) -> None
            | Some (OpenFileTarget.Socket _) ->
                // Unseekable on both, unlike the epoll instance above: measured, both
                // platforms answer ESPIPE for every whence in 0..4 and every
                // offset, `-1` and `INT64_MAX` alike. The whence-ordering
                // divergence still shows through this, and is exactly what the
                // ladder below reproduces — measured, `lseek(sock, 0, 9)` is
                // EINVAL on Linux (whence checked first) and ESPIPE on Darwin
                // (seekability checked first).
                Some DescriptorFault.NotSeekable
            | Some (OpenFileTarget.File _)
            | Some (OpenFileTarget.Directory _)
            | Some (OpenFileTarget.CharacterDevice _) -> None

        let ordered : UnixError option =
            match descriptorFault with
            | Some DescriptorFault.NotOpen ->
                // Ahead of everything on both platforms.
                Some UnixError.EBADF
            | notOpenRejected ->

            let unseekable =
                match notOpenRejected with
                | Some DescriptorFault.NotSeekable -> true
                | Some DescriptorFault.NotOpen
                | None -> false

            match flavour with
            | SimulatedUnixFlavour.Linux ->
                if not whenceValid then Some UnixError.EINVAL
                elif unseekable then Some UnixError.ESPIPE
                else None
            | SimulatedUnixFlavour.Darwin ->
                if unseekable then Some UnixError.ESPIPE
                elif not whenceValid then Some UnixError.EINVAL
                else None

        match ordered with
        | Some error -> Ok (SyscallAnswer.Failed error, system)
        | None ->

        // Linux's `noop_llseek`, for an epoll instance (a kqueue answered ESPIPE
        // above). It returns the file position unchanged, and an
        // epoll descriptor's is always 0, so the answer is 0 for every input
        // that gets here — measured for `SEEK_SET` with offset -1 and with
        // INT64_MAX alike, and for whence 3 and 4.
        //
        // Ahead of the SEEK_DATA/SEEK_HOLE refusal below, which is why that
        // refusal is not simply hoisted to the whence check: it is a statement
        // about a *file's* sparseness, and an epoll instance has none. The syscall's own
        // `whence <= SEEK_MAX` guard still applies and has already run, so
        // whence 5 and above were rejected as EINVAL.
        match target with
        | Some (OpenFileTarget.Epoll _)
        | Some (OpenFileTarget.Inotify _) -> Ok (SyscallAnswer.Completed 0L, system)
        // A device keeps no position, and answers 0 for every whence in 0..4
        // and every offset, negative and `INT64_MAX` included (`devices.c` and
        // `devices-l2.c`, LSEEK rows): `/dev/null`'s `null_lseek` resets a
        // position nothing moves, and `/dev/urandom`'s is `noop_llseek`.
        | Some (OpenFileTarget.CharacterDevice _) -> Ok (SyscallAnswer.Completed 0L, system)
        // Each of these answered EBADF or ESPIPE above.
        | None
        | Some (OpenFileTarget.Kqueue _)
        | Some (OpenFileTarget.Fifo _)
        | Some (OpenFileTarget.Pipe _)
        | Some (OpenFileTarget.Socket _) ->
            failwith
                $"UnixDescriptor.lseek: fd %d{fd} names %A{target}, which the descriptor checks above should have answered (this is a bug in this library)"
        | Some (OpenFileTarget.File _)
        | Some (OpenFileTarget.Directory _) ->

        // Whence *validity* is settled; whence *semantics* is not, and the two
        // sit at different points in Linux's order — which is why refusing 3 and
        // 4 up front would be wrong. Measured, `lseek(badfd, 0, 3)` is EBADF and
        // `lseek(pipe, 0, 3)` is ESPIPE on both platforms, so a caller reaching
        // here with whence 3 or 4 really is asking about a seekable file's
        // sparseness.
        if whence > seekEnd then
            let meaning =
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    if whence = 3 then
                        SeekExtension.SeekData
                    else
                        SeekExtension.SeekHole
                | SimulatedUnixFlavour.Darwin ->
                    if whence = 3 then
                        SeekExtension.SeekHole
                    else
                        SeekExtension.SeekData

            Error (LSeekRefusal.Sparseness (whence, meaning))
        else

        let seekWhence =
            if whence = seekSet then
                SeekWhence.Set
            elif whence = seekCur then
                SeekWhence.Current
            elif whence = seekEnd then
                SeekWhence.End
            else
                failwith
                    $"UnixDescriptor.lseek: whence %d{whence} passed the validity and semantics checks but is not one of SEEK_SET, SEEK_CUR or SEEK_END (this is a bug in this library)"

        // A directory's position is a number only at its start and where an
        // `lseek` put it; anywhere else it is a name (see
        // `LSeekRefusal.DirectoryPosition`).
        let inode, current =
            match target with
            | Some (OpenFileTarget.File (inode, current)) -> inode, Ok current
            | Some (OpenFileTarget.Directory (inode, DirectoryPosition.Cursor DirectoryCursor.Start)) -> inode, Ok 0L
            | Some (OpenFileTarget.Directory (inode, DirectoryPosition.Unenumerable offset)) -> inode, Ok offset
            | Some (OpenFileTarget.Directory (inode, DirectoryPosition.Cursor _)) ->
                inode, Error (LSeekRefusal.DirectoryPosition inode)
            | _ ->
                failwith
                    $"UnixDescriptor.lseek: fd %d{fd} is not a seekable file, but the descriptor checks above did not reject it (this is a bug in this library)"

        let entry =
            VirtualFileSystem.get "UnixDescriptor.lseek" inode system.Machine.FileSystem

        // The content is inspected only where a size is wanted, which is
        // `SEEK_END` alone. Some directories have none this kernel will state,
        // and a symlink should not be here at all — but `SEEK_SET` and
        // `SEEK_CUR` ask neither question, so neither may fire on those paths.
        let basis : Result<SeekEndBasis, LSeekRefusal> =
            match seekWhence with
            | SeekWhence.Set
            | SeekWhence.Current -> Ok SeekEndBasis.NotConsulted
            | SeekWhence.End ->
                match entry.Content with
                | InodeContent.RegularFile (contents, _) -> Ok (SeekEndBasis.Size (FileContents.length contents))
                | InodeContent.CharacterDevice _ ->
                    failwith
                        $"UnixDescriptor.lseek: fd %d{fd} names inode %O{inode}, which is a character device, through a description of a regular file. A description of a device is OpenFileTarget.CharacterDevice, and UnixSystem.checkInvariants reports this one as DescriptionKindMismatch (this is a bug in this library)."
                | InodeContent.Socket _ ->
                    failwith
                        $"UnixDescriptor.lseek: fd %d{fd} names inode %O{inode}, which is a socket. Nothing in this version makes one: InodeContent.Socket is unreachable until pathname sockets are modelled (this is a bug in this library)."
                | InodeContent.Fifo _ ->
                    failwith
                        $"UnixDescriptor.lseek: fd %d{fd} names inode %O{inode}, which is a FIFO. Nothing in this version makes one: InodeContent.Fifo is unreachable until FIFOs are modelled (this is a bug in this library)."
                | InodeContent.Symlink _ ->
                    // Not reachable: `open` resolves symlinks, so no descriptor
                    // names one. Stated rather than folded in so that an
                    // `O_PATH`-style descriptor finds a decision here.
                    failwith
                        $"UnixDescriptor.lseek: fd %d{fd} names inode %O{inode}, which is a symbolic link. `open` resolves symlinks, so no descriptor should name one; if this is reachable, decide what seeking a link through a descriptor means (this is a bug in this library)."
                | InodeContent.Directory directory ->
                    // Measured 2026-09-23 on every step of the histories
                    // `EmulatedFileSystemType.directorySize` records, and at 0,
                    // 1, 5 and 37 entries for offsets INT64_MIN, -10000,
                    // -size-1, -size, -size+1, -1, 0, 1, 7, 2^40 and
                    // INT64_MAX-size-1 .. INT64_MAX.
                    match UnixMachineState.fileSystemOf inode system.Machine with
                    // Linux 6.18.5: EINVAL for every offset, leaving the
                    // position where it was. A tmpfs directory's `llseek`
                    // takes `SEEK_SET` and `SEEK_CUR` only.
                    | InodeFileSystem.Typed EmulatedFileSystemType.Tmpfs -> Ok (SeekEndBasis.Fails UnixError.EINVAL)
                    // Darwin 27.0 (`docs/probes/devfs-darwin`, DIRFD rows): the
                    // size `stat` reports, as on APFS, whose arithmetic is
                    // Darwin's `lseek` for any vnode.
                    | InodeFileSystem.Devfs ->
                        Ok (SeekEndBasis.Size (Devfs.directorySize inode system.Machine.FileSystem))
                    // macOS 26.6: exactly a regular file's arithmetic over the
                    // size `stat` reports — EINVAL below zero, EOVERFLOW past
                    // INT64_MAX.
                    | InodeFileSystem.Typed EmulatedFileSystemType.Apfs ->
                        match
                            EmulatedFileSystemType.directorySize EmulatedFileSystemType.Apfs directory.Entries.Count
                        with
                        | Some size -> Ok (SeekEndBasis.Size size)
                        | None ->
                            failwith
                                "UnixDescriptor.lseek: EmulatedFileSystemType.directorySize states no size for an APFS directory, which is what SEEK_END on one is measured from (this is a bug in this library)"
                    // The size is the server's, as for `stat`.
                    | InodeFileSystem.Typed EmulatedFileSystemType.Nfs -> Error (LSeekRefusal.DirectoryEnd inode)

        match basis with
        | Error refusal -> Error refusal
        | Ok (SeekEndBasis.Fails error) -> Ok (SyscallAnswer.Failed error, system)
        | Ok basis ->

        let sizeOf =
            lazy
                match basis with
                | SeekEndBasis.Size size -> size
                | SeekEndBasis.NotConsulted
                | SeekEndBasis.Fails _ ->
                    failwith
                        "UnixDescriptor.lseek: the file size was consulted on a path that does not consult it (this is a bug in this library)"

        let current =
            match seekWhence, current with
            | SeekWhence.Current, current -> current
            // `seekTarget` does not consult the current position for these, so
            // a directory part of the way through is no obstacle to them.
            | SeekWhence.Set, current
            | SeekWhence.End, current -> current |> Result.defaultValue 0L |> Ok

        match current with
        | Error refusal -> Error refusal
        | Ok current ->

        match VirtualFileSystem.seekTarget seekWhence current sizeOf offset with
        | Error SeekFault.Negative ->
            // EINVAL on both, and the offset is left where it was — measured, a
            // failed `lseek` does not move the description.
            Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
        | Error SeekFault.Overflow ->
            // The one place the *errno* differs rather than the ordering.
            // Measured on a tmpfs-backed file, so that the filesystem is held
            // constant: `lseek(f, INT64_MAX-4, SEEK_END)` on a 5-byte file is
            // EINVAL on Linux and EOVERFLOW on Darwin.
            match flavour with
            | SimulatedUnixFlavour.Linux -> Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
            | SimulatedUnixFlavour.Darwin -> Ok (SyscallAnswer.Failed UnixError.EOVERFLOW, system)
        | Ok position ->

        let registry =
            match target with
            | Some (OpenFileTarget.Directory _) ->
                // Measured on both, with the arithmetic above exactly a regular
                // file's (EINVAL below zero; EINVAL on Linux and EOVERFLOW on
                // Darwin past INT64_MAX): any non-negative offset is accepted and
                // reported back, and offset 0 rewinds to the first entry.
                let directoryPosition =
                    if position = 0L then
                        DirectoryPosition.Cursor DirectoryCursor.Start
                    else
                        DirectoryPosition.Unenumerable position

                FileDescriptorRegistry.setDirectoryPosition
                    fd
                    directoryPosition
                    (UnixSystemState.fileDescriptors system)
            | _ -> FileDescriptorRegistry.setOffset fd position (UnixSystemState.fileDescriptors system)

        Ok (SyscallAnswer.Completed position, UnixSystemState.withFileDescriptors registry system)

    /// `lseek`, with a refusal answered as the `Error` rather than raised.
    let internal tryLseek<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (offset : int64)
        (whence : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, LSeekRefusal>
        =
        Entry.call
            "UnixDescriptor.lseek"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryLseekIn fd offset whence)
            system

    /// `lseek(2)`: move `fd`'s file offset and report where it lands.
    ///
    /// On a directory, the position is where the next read of its entries
    /// resumes, and offset 0 rewinds to the first of them.
    ///
    /// Refuses the inputs whose answer this kernel cannot state: `SEEK_DATA`
    /// and `SEEK_HOLE`, `SEEK_END` on a directory whose size it cannot state,
    /// and `SEEK_CUR` on a directory read part of the way through.
    let lseek<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (offset : int64)
        (whence : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryLseek caller fd offset whence system
        |> Refusal.orRaise "UnixDescriptor.lseek" LSeekRefusal.kind LSeekRefusal.describe

    /// Commit a truncation of the regular file `inode` to `length`, together with
    /// the `mtime`, `ctime` and set-ID bits it moves.
    ///
    /// Shared by `ftruncate` and by `open`'s `O_TRUNC`, which are the same
    /// operation with the same measured consequences — the mode rule, the
    /// timestamp rule and the truncate-to-the-same-length rule all agree between
    /// them on both platforms.
    ///
    /// Not short-circuited when the file is already that length: unlike a write
    /// of no bytes, a truncation that moves no bytes still stamps the inode.
    ///
    /// The caller reached the file `through` a path or a descriptor, by a
    /// name: a regular file is reached no other way.
    let internal truncateAt<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (through : ReachedThrough)
        (inode : InodeNumber)
        (length : int64)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ProcessView<'Thread, 'Handler>, TruncationRefusal>
        =
        let now = UnixMachineState.realtime system.Scheduling system.Machine
        let rule = SimulatedUnixPlatform.setIdBitsOnTruncation system.Machine.UnixPlatform

        match
            VirtualFileSystem.truncateFile inode length rule system.Process.Credentials now system.Machine.FileSystem
        with
        | Ok mutation ->
            // Linux's `do_truncate` sets the size and the modification time,
            // and the mode when it clears a set-ID bit, which the mutation
            // reports as a change of attributes.
            let set =
                { AttributesSet.none with
                    Size = true
                    ModificationTime = true
                    Mode =
                        VfsMutation.changes mutation
                        |> List.exists (fun change ->
                            match change with
                            | FsChange.AttributesChanged _ -> true
                            | FsChange.ContentChanged _
                            | FsChange.EntryAdded _
                            | FsChange.EntryRemoved _
                            | FsChange.EntryMoved _
                            | FsChange.InodeForgotten _ -> false
                        )
                }

            Ok
                { system with
                    Machine =
                        UnixMachineState.commitFileSystem
                            (ChangeNotice.SetAttributes (through, set))
                            mutation
                            system.Machine
                }
        | Error (FileTruncationRefusal.WouldExceedMaxLength length) ->
            Error (TruncationRefusal.ExceedsRepresentableLength (inode, length))

    /// `tryFtruncate` once `Entry` has admitted its caller.
    let private tryFtruncateIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (length : int64)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, TruncationRefusal>
        =
        // **Ahead of the descriptor**, measured on both platforms: the same
        // unknown fd is EBADF with a length of 0 and EINVAL with a length of -1,
        // so the length really is validated first rather than the two faults
        // merely sharing an errno.
        if length < 0L then
            Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
        else

        match FileDescriptorRegistry.tryFindReached fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (SyscallAnswer.Failed UnixError.EBADF, system)
        | Some reached ->

        let description = reached.Description

        match description.Target with
        | OpenFileTarget.Pipe _
        | OpenFileTarget.Kqueue _
        | OpenFileTarget.Epoll _
        // Measured (`inotify-descriptor-probe.c` row D ftruncate).
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Socket _
        | OpenFileTarget.CharacterDevice _ ->
            // EINVAL on both platforms for every object that is not a regular
            // file: measured on a pipe (either end), an INET socket, a UNIX
            // socket, an epoll instance and a kqueue, and on Linux on `/dev/null`
            // and `/dev/urandom`, through descriptors opened for reading as
            // well as for writing (`devices.c`, FTRUNCATE rows). Unlike `pread`/`pwrite` there
            // is no unseekable-versus-unwritable tie for the platforms to break
            // differently, so this arm deliberately carries no Darwin flag.
            Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
        | OpenFileTarget.Fifo (inode, _) -> ReservedFifo.fail "UnixDescriptor.ftruncate" inode
        | OpenFileTarget.File (inode, _)
        | OpenFileTarget.Directory (inode, _) ->

        // A descriptor not open for writing is EINVAL rather than EBADF —
        // `ftruncate(2)` differs from `write(2)` here, and it is measured on both
        // platforms.
        //
        // This is also what makes a *directory* descriptor answer EINVAL without
        // a type check: one can only ever be opened `O_RDONLY`, `open` answering
        // EISDIR for every write access mode. Adding a type check here would be a
        // mistake as well as redundant — EISDIR is what path-based `truncate(2)`
        // answers for a directory, where `ftruncate(2)` answers EINVAL.
        if not (FileAccessMode.permitsWrite description.AccessMode) then
            Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
        else

        let id = reached.Id

        // Measured on Darwin 27.0.0 (`fcntl-dup.c`, WRITTEN rows): a truncation
        // that succeeds marks the description written, even to the length the
        // file already had; one that fails does not.
        let through = ReachedDescription.through "UnixDescriptor.ftruncate" reached

        truncateAt through inode length system
        |> Result.map (fun system ->
            SyscallAnswer.Completed 0L,
            UnixSystemState.mapOpenFiles (OpenFileTable.mapStatus id OpenFileStatus.markWritten) system
        )

    /// `ftruncate`, with a refusal answered as the `Error` rather than raised.
    let internal tryFtruncate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (length : int64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, TruncationRefusal>
        =
        Entry.call
            "UnixDescriptor.ftruncate"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryFtruncateIn fd length)
            system

    /// `ftruncate(2)`: set a regular file's length through a descriptor open for
    /// writing.
    let ftruncate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (length : int64)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryFtruncate caller fd length system
        |> Refusal.orRaise "UnixDescriptor.ftruncate" TruncationRefusal.kind TruncationRefusal.describe

    /// `tryPosixFadvise` once `Entry` has admitted its caller.
    let private tryPosixFadviseIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (offset : int64)
        (length : int64)
        (advice : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<FileAdviceAnswer, PosixFadviseRefusal>
        =
        // Measured, the offset is never validated at all: a negative one, and
        // one whose sum with the length overflows, both succeed.
        ignore<int64> offset

        if not (SimulatedUnixPlatform.providesPosixFadvise system.Machine.UnixPlatform) then
            Error PosixFadviseRefusal.NotProvided
        else

        match FileDescriptorRegistry.tryFind fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (FileAdviceAnswer.Failed UnixError.EBADF)
        | Some description ->

        match description.Target with
        | OpenFileTarget.Pipe _ ->
            // Measured on both ends of a real pipe, and ahead of the length and
            // advice screens below: the pipe test sits in the syscall entry,
            // where the range and advice checks belong to the generic path it
            // dispatches to.
            Ok (FileAdviceAnswer.Failed UnixError.ESPIPE)
        // Only Linux provides the call, and its `generic_fadvise` answers
        // ESPIPE for any inode that is `S_ISFIFO`: the test that answers it
        // for a pipe.
        | OpenFileTarget.Fifo _ -> Ok (FileAdviceAnswer.Failed UnixError.ESPIPE)
        | OpenFileTarget.File _
        | OpenFileTarget.Directory _
        | OpenFileTarget.Kqueue _
        | OpenFileTarget.Epoll _
        // Measured: advice 0 over the whole of an inotify instance succeeds
        // (`inotify-descriptor-probe.c` row D fadvise).
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Socket _
        | OpenFileTarget.CharacterDevice _ ->

        // The generic path every non-pipe reaches screens the length and the
        // advice, and both answer EINVAL, so their relative order is invisible.
        // All six advices then behave identically, this kernel modelling no
        // readahead for them to steer.
        if length < 0L || advice < 0 || advice > 5 then
            Ok (FileAdviceAnswer.Failed UnixError.EINVAL)
        else
            Ok FileAdviceAnswer.Completed

    /// `posixFadvise`, with a refusal answered as the `Error` rather than raised.
    let internal tryPosixFadvise<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (offset : int64)
        (length : int64)
        (advice : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<FileAdviceAnswer, PosixFadviseRefusal>
        =
        Entry.call
            "UnixDescriptor.posixFadvise"
            CallerRequirement.Running
            caller
            Shape.answer
            (tryPosixFadviseIn fd offset length advice)
            system

    /// <summary>
    /// `posix_fadvise(2)`: tell the kernel how a region of `fd` will be read.
    ///
    /// `advice` is the platform's raw `POSIX_FADV_*` number. Linux accepts 0
    /// (`NORMAL`) to 5 (`NOREUSE`) on x86-64 and aarch64 alike, and answers any
    /// other value EINVAL, but only once the descriptor has been screened: a
    /// closed descriptor is EBADF and a pipe ESPIPE whatever the advice.
    ///
    /// Refused where the platform's libc has no such call (Darwin): no program
    /// could have made it.
    ///
    /// A pure hint: this kernel models no readahead, so a `Completed` answer
    /// leaves the system exactly as it arrived. That is why no system comes
    /// back.
    ///
    /// The rows this implements are measured on Linux 6.18.5 aarch64 by
    /// `docs/probes/fadvise/fadvise.py`. The path they exercise
    /// (`ksys_fadvise64_64` and `generic_fadvise`) is architecture-independent,
    /// and the advice numbering is `&lt;linux/fadvise.h&gt;`'s on both; x86-64 is not
    /// separately measured. Two rows contradict what "not seekable" would
    /// predict: a socket and an epoll instance both succeed, and only a pipe
    /// answers ESPIPE.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">The simulated platform's libc has no `posix_fadvise` (`SimulatedUnixPlatform.providesPosixFadvise` is `false`), so no program could have made the call and there is no answer to give.</exception>
    let posixFadvise<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (offset : int64)
        (length : int64)
        (advice : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : FileAdviceAnswer
        =
        tryPosixFadvise caller fd offset length advice system
        |> Refusal.orRaise "UnixDescriptor.posixFadvise" PosixFadviseRefusal.kind PosixFadviseRefusal.describe

    /// `tryFlock` once `Entry` has admitted its caller.
    let private tryFlockIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (operation : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, FLockRefusal>
        =
        // Unlike a foreign-function layer's error and open-flag encodings, these
        // are *not* values anything translates: `flock(2)` takes them verbatim,
        // and Linux and Darwin happen to agree on all four — measured on both
        // rather than assumed.
        let lockShared = 1
        let lockExclusive = 2
        let lockNonBlocking = 4
        let lockUnlock = 8
        let lockMandatory = 32

        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        let nonBlocking = operation &&& lockNonBlocking <> 0
        let mode = operation &&& ~~~lockNonBlocking

        let descriptor =
            FileDescriptorRegistry.tryFind fd (UnixSystemState.fileDescriptors system)

        // Where the descriptor is looked up relative to the operation screens
        // parts the flavours, and both are measured
        // (`docs/probes/flock/lock-mand.py`): Linux screens the operation
        // first, so a closed descriptor with a malformed operation is EINVAL,
        // and a `LOCK_MAND` request is answered 0 -- mandatory locking was
        // removed in 5.15 and the request is ignored -- before anything is
        // looked up, closed descriptors included. Darwin looks the descriptor
        // up first, so a closed one is EBADF whatever the operation.
        match flavour, descriptor with
        | SimulatedUnixFlavour.Linux, _ when operation &&& lockMandatory <> 0 ->
            Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system)
        | SimulatedUnixFlavour.Darwin, None ->
            Ok (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EBADF), system)
        | _ ->

        let request : FlockRequest option =
            if mode = lockUnlock then
                Some FlockRequest.Release
            elif mode = lockShared then
                Some (FlockRequest.Acquire FlockMode.Shared)
            elif mode = lockExclusive then
                Some (FlockRequest.Acquire FlockMode.Exclusive)
            else
                None

        // Linux validates strictly: exactly one of SH/EX/UN, optionally with NB,
        // and nothing else. Darwin is laxer *and* uses a different errno.
        match request with
        | None ->
            match flavour with
            | SimulatedUnixFlavour.Linux -> Ok (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EINVAL), system)
            | SimulatedUnixFlavour.Darwin -> Error (FLockRefusal.DarwinMalformedOperation operation)
        | Some request ->

        // Whether a FIFO's descriptions contend is unmeasured on both flavours.
        match descriptor with
        | Some {
                   Target = OpenFileTarget.Fifo (inode, _)
               } -> ReservedFifo.fail "UnixDescriptor.flock" inode
        | Some _
        | None -> ()

        // The remaining divergences are all about a descriptor already resolved,
        // so they are checked here rather than in the registry: that module
        // models one coherent set of rules. An unknown fd is EBADF on both
        // platforms, so there is nothing to refuse for one.
        let darwinRefusal : FLockRefusal option =
            match flavour, descriptor with
            | SimulatedUnixFlavour.Linux, _
            | _, None -> None
            | SimulatedUnixFlavour.Darwin, Some description ->
                match description.Target with
                | OpenFileTarget.Pipe (pipeId, _) -> Some (FLockRefusal.DarwinPipe pipeId)
                | OpenFileTarget.Kqueue _ -> Some FLockRefusal.DarwinKqueue
                | OpenFileTarget.Epoll _ ->
                    failwith
                        "UnixDescriptor.flock: a Darwin-flavoured kernel holds an epoll instance, which only Linux has (this is a bug in the caller's state construction)."
                | OpenFileTarget.Inotify _ ->
                    failwith
                        "UnixDescriptor.flock: a Darwin-flavoured kernel holds an inotify instance, which only Linux has (this is a bug in the caller's state construction)."
                | OpenFileTarget.CharacterDevice _ ->
                    failwith
                        "UnixDescriptor.flock: a Darwin-flavoured kernel holds a description of a device, which only Linux's devtmpfs gives (this is a bug in the caller's state construction)."
                | OpenFileTarget.Socket socketId -> Some (FLockRefusal.DarwinSocket socketId)
                | OpenFileTarget.Fifo (inode, _) -> ReservedFifo.fail "UnixDescriptor.flock" inode
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _ ->
                    match request, description.Flock with
                    | FlockRequest.Acquire _, Some _ -> Some FLockRefusal.DarwinConversion
                    | _, _ -> None

        match darwinRefusal with
        | Some refusal -> Error refusal
        | None ->

        // The table advances even when the call fails: a conversion that could
        // not be granted has already dropped the caller's old lock. So the new
        // table is committed *before* the outcome is inspected, and every branch
        // below reports from `advanced`.
        let registry, error =
            FileDescriptorRegistry.flock fd request (UnixSystemState.fileDescriptors system)

        let registry =
            match error, request, FileDescriptorRegistry.tryFindId fd registry with
            | None, FlockRequest.Acquire _, Some id ->
                FileDescriptorRegistry.mapOpenFiles
                    (OpenFileTable.mapStatus id OpenFileStatus.recordFlockGrant)
                    registry
            | _ -> registry

        let advanced = UnixSystemState.withFileDescriptors registry system

        match error with
        | Some FlockError.BadFd -> Ok (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EBADF), advanced)
        | Some FlockError.WouldBlock ->
            if nonBlocking then
                Ok (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EAGAIN), advanced)
            else

            // A blocking acquisition that *can* be satisfied is served above, so
            // only genuine contention reaches here. Parking must never quietly
            // become the non-blocking answer, which would hand the caller an
            // EWOULDBLOCK no kernel would have produced.
            let requested =
                match request with
                | FlockRequest.Acquire mode -> mode
                | FlockRequest.Release ->
                    // `FileDescriptorRegistry.flock` grants every release, so a
                    // release cannot be what contended.
                    failwith
                        $"flock: fd %d{fd} reported contention for a release, which cannot contend (this is a bug in this library)"

            // The requester is the description rather than the descriptor: a
            // `dup` of `fd` waits on the same lock, and a wake keyed on the
            // number would miss a waiter that had closed the one it asked
            // through.
            let requester =
                match FileDescriptorRegistry.tryFindId fd (UnixSystemState.fileDescriptors system) with
                | Some id -> id
                | None ->
                    failwith
                        $"flock: fd %d{fd} reported contention but names no open file description (this is a bug in this library)"

            let parked =
                ParkedSyscall.Flock
                    {
                        ParkedFlock.Requester = requester
                        Mode = requested
                    }

            // The condition is derived from the record rather than built beside
            // it, so a thread cannot be parked on one lock while a client polls
            // for another.
            Ok (SyscallOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked advanced)
        | None -> Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), advanced)

    /// `flock`, with a refusal answered as the `Error` rather than raised.
    let internal tryFlock<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (operation : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, FLockRefusal>
        =
        Entry.call
            "UnixDescriptor.flock"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryFlockIn (Caller.thread caller) fd operation)
            system

    /// `flock(2)`, made by `caller`: take, convert or release an advisory lock on
    /// `fd`'s open file description.
    ///
    /// Models Linux's rules and refuses under Darwin rather than guessing, for
    /// each measured divergence: a malformed operation, a pipe, a kqueue, a
    /// socket, and an acquisition by a description that already holds a lock.
    ///
    /// A blocking acquisition that another description's lock stands in the way
    /// of answers `SyscallOutcome.WouldBlock`, in the system a real kernel would
    /// have slept in — which is not the system the call arrived with, because
    /// the caller's own old lock has already gone — and that system records
    /// the caller's thread as parked on the lock. The record is what `close` reads to refuse
    /// destroying the description, and what `flockAcquire` finishes from once
    /// the condition holds. A parked `flock` is finished through `flockAcquire`,
    /// never re-issued.
    let flock<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (operation : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFlock caller fd operation system
        |> Refusal.orRaise "UnixDescriptor.flock" FLockRefusal.kind FLockRefusal.describe

    /// `tryFlockAcquire` once `Entry` has admitted its caller.
    let internal tryFlockAcquireIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, FLockRefusal>
        =
        let requester, mode =
            UnixThreadTable.expectParked
                "UnixDescriptor.flockAcquire"
                (fun parked ->
                    match parked with
                    | ParkedSyscall.Flock parked -> Some (parked.Requester, parked.Mode)
                    | _ -> None
                )
                thread
                system.Threads

        match OpenFileTable.tryFind requester system.Machine.OpenFiles with
        | None ->
            failwith
                $"UnixDescriptor.flockAcquire: open file description %O{requester} is not in the table, but thread %O{thread} is parked on an flock of it, and a park holds its description until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."
        | Some description ->

        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform, description.Flock with
        | SimulatedUnixFlavour.Darwin, Some _ -> Error FLockRefusal.DarwinConversion
        | SimulatedUnixFlavour.Darwin, None
        | SimulatedUnixFlavour.Linux, _ ->

        let openFiles, error =
            OpenFileTable.flockOn requester (FlockRequest.Acquire mode) system.Machine.OpenFiles

        let openFiles =
            match error with
            | None -> OpenFileTable.mapStatus requester OpenFileStatus.recordFlockGrant openFiles
            | Some _ -> openFiles

        let advanced = UnixSystemState.mapOpenFiles (fun _ -> openFiles) system

        // The call returns: its park goes, and with it the call's reference to
        // the description, which goes too if no descriptor names it any more
        // (`open-file-references.c` sections D and F: the lock it was granted
        // goes with it).
        let finishedFrom (system : ProcessView<'Thread, 'Handler>) : ProcessView<'Thread, 'Handler> =
            let unparked = UnixParkState.unpark thread system

            // A socket has one description, so no other description's lock can
            // obstruct an `flock` of one, and such a call never sleeps.
            ObjectLifetime.releaseUnreferencedUnrefusable "UnixDescriptor.flockAcquire" [ requester ] unparked

        let finished () = finishedFrom advanced

        match error with
        | Some FlockError.BadFd ->
            // `flockOn` never resolves a descriptor, so it has no bad one to
            // report.
            failwith
                $"UnixDescriptor.flockAcquire: acquiring on open file description %O{requester} reported EBADF, which only a descriptor lookup can produce (this is a bug in this library)."
        | Some FlockError.WouldBlock ->
            match SyscallInterruption.ofPark thread advanced with
            | Error refusal -> Error (FLockRefusal.Interruption refusal)
            | Ok (Some interruption) ->
                Ok (SyscallOutcome.Interrupted, OwedReturns.interrupt thread interruption (finished ()))
            | Ok None ->
                // Beaten: the waiter sleeps again on the same record, re-queued behind
                // every park already made, as a real kernel re-queues it.
                let parked =
                    ParkedSyscall.Flock
                        {
                            ParkedFlock.Requester = requester
                            Mode = mode
                        }

                Ok (SyscallOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked advanced)
        | None ->
            // Measured on Linux 6.18.5 (`signal-interrupt-requeue.c`, section
            // D): a lock that can be granted beats a pending signal. On Darwin
            // a pending signal beats it (`SyscallInterruption.beforeCompleting`),
            // and the lock is not taken.
            match SyscallInterruption.beforeCompleting thread advanced with
            | Error refusal -> Error (FLockRefusal.Interruption refusal)
            | Ok SyscallInterruption.Completion.Completes ->
                Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), finished ())
            | Ok (SyscallInterruption.Completion.Interrupted interruption) ->
                // Darwin refuses a conversion (`DarwinConversion`), so the
                // description held no lock to have dropped, and takes none.
                Ok (SyscallOutcome.Interrupted, OwedReturns.interrupt thread interruption (finishedFrom system))

    /// `flockAcquire`, with a refusal answered as the `Error` rather than raised.
    let internal tryFlockAcquire<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, FLockRefusal>
        =
        Entry.call
            "UnixDescriptor.flockAcquire"
            CallerRequirement.Woken
            caller
            (Shape.result Shape.withSystem)
            (tryFlockAcquireIn (Caller.thread caller))
            system

    /// Finish the `flock` acquisition `caller` parked in, against the open file
    /// description its park record names.
    ///
    /// From the record rather than by re-issuing `flock` with the descriptor
    /// the call was made through, and not as a convenience: descriptor numbers
    /// are allocated lowest-free and reused as soon as they are freed, so a
    /// `close` of that number elsewhere can leave it naming a different object
    /// by the time the lock frees. A real kernel has no such hazard: the
    /// sleeping call holds the file, and the park holds the description, which
    /// outlives its last descriptor until this call returns and goes then,
    /// taking with it any lock it was granted. `caller` must be parked in an
    /// `flock`, and woken (`UnixWait.wake`).
    ///
    /// A grant clears the park record. `WouldBlock`, with the same condition
    /// and the thread re-parked on the same record behind every other park, is
    /// the answer when the lock has been taken since the waiter was woken. That is the ordinary case rather than
    /// an edge one: a release wakes every waiter and they race, so all but one
    /// of them find it gone.
    ///
    /// When the lock cannot be granted, or under Darwin even when it can, and
    /// the thread would take a signal as it returned to user mode, the signal
    /// interrupts the call
    /// (`SyscallOutcome.Interrupted`): the park is cleared, a conversion's old
    /// lock stays dropped, as it is while the call sleeps, and the thread's
    /// return to user mode (`UnixSignal.onReturnToUser`) says whether the call
    /// fails with `EINTR` or restarts.
    ///
    /// Most of what `flock` screens is not re-screened, because a screen over
    /// facts that cannot change is spent: the operation bits were validated
    /// before the park, and this signature makes a malformed resume
    /// unrepresentable; the Darwin refusals for a pipe, a socket and a kqueue
    /// are about the description's object kind, which never changes.
    /// `DarwinConversion` is the exception, because it screens *mutable* state —
    /// while this thread held nothing, another through a `dup` of its descriptor
    /// could have taken a lock on this same description, which Darwin serves as
    /// a first acquisition, and the resume is then the conversion whose
    /// keep-versus-drop divergence is unmeasured.
    let flockAcquire<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFlockAcquire caller system
        |> Refusal.orRaise "UnixDescriptor.flockAcquire" FLockRefusal.kind FLockRefusal.describe

    /// `tryBytesAvailable` once `Entry` has admitted its caller.
    let private tryBytesAvailableIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (destination : UserBuffer)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<BytesAvailableAnswer * ProcessView<'Thread, 'Handler>, BytesAvailableRefusal>
        =
        // A UDP socket's count: on Linux the oldest datagram's length, which
        // a call finding the reader queue empty refills it to read, before it
        // writes the count, so the refill stands though the destination
        // faults (`udp-release.c` in docs/plans/2026-10-18-udp-data-path); on
        // Darwin the receive buffer's byte count (`udp-transfer.c` F).
        let system, datagrams =
            match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) when
                SocketTable.receivesDatagrams (UnixMachineState.socket socketId system.Machine)
                ->
                let count, receiver =
                    DatagramReceiver.queried (UnixMachineState.datagramReceiver socketId system.Machine)

                { system with
                    Machine = UnixMachineState.withDatagramReceiver socketId receiver system.Machine
                },
                Some count
            | _ -> system, None

        // Measured by pipe-syscalls.c on both flavours: a descriptor that is not
        // open is EBADF through a bad pointer, and a pipe end is EFAULT through
        // one -- NULL included, and the write end included, though it reports 0
        // on Darwin.
        let held =
            match datagrams with
            | Some count -> Ok (Ok count)
            | None ->

            match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
            | None -> Ok (Error UnixError.EBADF)
            | Some (OpenFileTarget.File _)
            | Some (OpenFileTarget.Directory _)
            | Some (OpenFileTarget.Kqueue _)
            | Some (OpenFileTarget.Epoll _)
            // Measured to differ by flavour on the write side, and needing the
            // FIFO's channel, which is not modelled.
            | Some (OpenFileTarget.Fifo _) -> Error (BytesAvailableRefusal.UnmodelledTarget fd)
            | Some (OpenFileTarget.Socket socketId) ->
                // A connected TCP socket reports the bytes in its receive
                // buffer, on both flavours, after a FIN or a reset too
                // (measured, `tcp-transfer.c` section S). Every other phase is
                // unmodelled.
                match SocketPhase.connectionEnd (UnixMachineState.socket socketId system.Machine).Phase with
                | None -> Error (BytesAvailableRefusal.UnmodelledTarget fd)
                | Some (connectionId, connectionEnd) ->
                    Ok (
                        Ok (
                            TcpTransfer.readable
                                connectionEnd
                                (UnixMachineState.connection connectionId system.Machine).Transfer
                        )
                    )
            | Some (OpenFileTarget.CharacterDevice (_, device, _)) ->
                // The driver's own answer, without the destination: Linux asks the
                // inode whether it is a regular file before it would write one.
                Ok (Error (CharacterDevice.unrecognisedIoctl device))
            | Some (OpenFileTarget.Inotify state) ->
                // The bytes a read of every queued record would return
                // (measured, `inotify-probe.c` section R), written to the
                // destination after they are counted, so an unmapped one is
                // EFAULT (`inotify-descriptor-probe.c` row D fionread-null).
                // `InotifyLimits.largestQueuedEvents` keeps the count within an
                // `int`.
                let bytes = InotifyQueue.byteCount state.Queue

                if bytes > int64 System.Int32.MaxValue then
                    failwith
                        $"UnixDescriptor.bytesAvailable: fd %d{fd} names an inotify instance holding %d{bytes} bytes of records, more than an int holds, which InotifyLimits.largestQueuedEvents exists to prevent; UnixSystem.checkInvariants reports the machine's limits as InotifyLimitsNotAdmissible or the queue as InotifyQueueBeyondLimit (this is a bug in this library, or in a caller that assembled the state by hand)."

                Ok (Ok (int bytes))
            | Some (OpenFileTarget.Pipe (pipeId, pipeEnd)) ->

            let held = PipeBuffer.held (UnixMachineState.pipe pipeId system.Machine).Buffer

            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform, pipeEnd with
            | SimulatedUnixFlavour.Linux, _
            | SimulatedUnixFlavour.Darwin, PipeEnd.Read -> Ok (Ok held)
            | SimulatedUnixFlavour.Darwin, PipeEnd.Write -> Ok (Ok 0)

        match held with
        | Error refusal -> Error refusal
        | Ok (Error error) -> Ok (BytesAvailableAnswer.Failed error, system)
        | Ok (Ok count) ->

        match destination with
        | UserBuffer.Unmapped _ -> Ok (BytesAvailableAnswer.Failed UnixError.EFAULT, system)
        | UserBuffer.Opaque -> Error (BytesAvailableRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
        | UserBuffer.Addressless -> Error (BytesAvailableRefusal.Buffer BufferRefusal.AddresslessAtTransfer)
        | UserBuffer.Mapped -> Ok (BytesAvailableAnswer.Reported count, system)

    /// `bytesAvailable`, with a refusal answered as the `Error` rather than raised.
    let internal tryBytesAvailable<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<BytesAvailableAnswer * UnixSystem<'Thread, 'Handler>, BytesAvailableRefusal>
        =
        Entry.call
            "UnixDescriptor.bytesAvailable"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryBytesAvailableIn fd destination)
            system

    /// `ioctl(fd, FIONREAD, &count)`: how many bytes a read of the pipe end or
    /// connected TCP socket `fd` names could take now, written into the
    /// caller's `int` at `destination`.
    ///
    /// On Linux both ends of a pipe report the bytes the pipe holds, even once
    /// the read end has closed; on Darwin the read end reports them and the
    /// write end reports 0. A connected socket reports what waits in its
    /// receive buffer. A UDP socket reports, on Linux, the oldest datagram's
    /// length, and on Darwin its receive buffer's count, which charges each
    /// datagram its source address and a control record beside its bytes. EBADF for a descriptor that is not open, whatever the
    /// destination; EFAULT for an unmapped destination, whatever is held. A
    /// device answers its driver's errno whatever the destination: under
    /// Linux, `ENOTTY` for `/dev/null` and `EINVAL` for `/dev/urandom`.
    /// Refused for every other descriptor.
    ///
    /// The system comes back with the answer, changed only for a Linux UDP
    /// socket, whose call moves the datagrams that have arrived into the
    /// queue a receive takes from, as Linux's does, which decides when the
    /// receive buffer has room again.
    let bytesAvailable<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (system : UnixSystem<'Thread, 'Handler>)
        : BytesAvailableAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryBytesAvailable caller fd destination system
        |> Refusal.orRaise "UnixDescriptor.bytesAvailable" BytesAvailableRefusal.kind BytesAvailableRefusal.describe

    /// The errno a `FICLONE` from `source` to `destination` fails with: no
    /// filesystem this kernel answers for can share contents.
    let private fileCloneFailure<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : int)
        (source : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<UnixError, FileCloneRefusal>
        =
        // Measured on Linux 6.18.5 (`copy-file-syscalls.c`, tmpfs and ext4
        // alike) over every pair of a file opened read-only, write-only and
        // read-write, a directory, each end of a pipe, a socket, an epoll
        // instance, a closed descriptor and 9999: either missing is EBADF; then
        // two objects on different filesystems (a file against a pipe, a pipe
        // against a socket) are EXDEV, a directory with anything on its own
        // filesystem is EISDIR, two pipe ends, two sockets or two epoll
        // instances are EINVAL, a read-only destination or a write-only source
        // is EBADF, and two regular files are EOPNOTSUPP, empty or not, and the
        // same description included. ext4 answers as tmpfs does. A device
        // against a regular file is EXDEV either way round, and two devices
        // are EINVAL (`devices-l2.c`, FICLONE rows).
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (FileCloneRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        let registry = UnixSystemState.fileDescriptors system

        match FileDescriptorRegistry.tryFind destination registry, FileDescriptorRegistry.tryFind source registry with
        | None, _
        | _, None -> Ok UnixError.EBADF
        | Some destinationDescription, Some sourceDescription ->

        let fileSystemOf (description : OpenFileDescription) : ObjectFileSystem =
            match description.Target with
            | OpenFileTarget.File (inode, _)
            | OpenFileTarget.Directory (inode, _)
            | OpenFileTarget.CharacterDevice (inode, _, _)
            // A FIFO's inode is on the filesystem its path is on, and the
            // later screen answers EINVAL for it there:
            // `generic_remap_file_range_prep` refuses any inode that is not
            // `S_ISREG`.
            | OpenFileTarget.Fifo (inode, _) ->
                ObjectFileSystem.Mounted (VirtualFileSystem.mountedRootOf inode system.Machine.FileSystem)
            | OpenFileTarget.Pipe _ -> ObjectFileSystem.Pseudo PseudoFileSystem.Pipe
            | OpenFileTarget.Socket _ -> ObjectFileSystem.Pseudo PseudoFileSystem.Socket
            | OpenFileTarget.Epoll _
            // Measured: FICLONE between two inotify instances is EINVAL
            // (`inotify-descriptor-probe.c` row D ficlone-two-instances).
            | OpenFileTarget.Inotify _ -> ObjectFileSystem.Pseudo PseudoFileSystem.AnonymousInode
            | OpenFileTarget.Kqueue _ ->
                failwith
                    "UnixDescriptor.fileClone: a Linux-flavoured kernel holds a kqueue, which only Darwin has (this is a bug in the caller's state construction)."

        let isDirectory (description : OpenFileDescription) : bool =
            match description.Target with
            | OpenFileTarget.Directory _ -> true
            | OpenFileTarget.File _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _
            | OpenFileTarget.Socket _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.Epoll _ -> false

        let isRegularFile (description : OpenFileDescription) : bool =
            match description.Target with
            | OpenFileTarget.File _ -> true
            | OpenFileTarget.Directory _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _
            | OpenFileTarget.Socket _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.Epoll _ -> false

        if fileSystemOf destinationDescription <> fileSystemOf sourceDescription then
            Ok UnixError.EXDEV
        elif isDirectory destinationDescription || isDirectory sourceDescription then
            Ok UnixError.EISDIR
        elif not (isRegularFile destinationDescription && isRegularFile sourceDescription) then
            Ok UnixError.EINVAL
        elif
            not (FileAccessMode.permitsWrite destinationDescription.AccessMode)
            || not (FileAccessMode.permitsRead sourceDescription.AccessMode)
        then
            Ok UnixError.EBADF
        else

        match EmulatedMount.fileSystemType system.Machine.Mount with
        | EmulatedFileSystemType.Tmpfs -> Ok UnixError.EOPNOTSUPP
        | EmulatedFileSystemType.Apfs
        | EmulatedFileSystemType.Nfs as fileSystem -> Error (FileCloneRefusal.UnmeasuredFileSystem fileSystem)

    /// `tryFileClone` once `Entry` has admitted its caller.
    let private tryFileCloneIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : int)
        (source : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, FileCloneRefusal>
        =
        fileCloneFailure destination source system
        |> Result.map (fun error -> SyscallAnswer.Failed error, system)

    /// `fileClone`, with a refusal answered as the `Error` rather than raised.
    let internal tryFileClone<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (destination : int)
        (source : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, FileCloneRefusal>
        =
        Entry.call
            "UnixDescriptor.fileClone"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryFileCloneIn destination source)
            system

    /// <summary>
    /// `ioctl(destination, FICLONE, source)`: make the file `destination` names
    /// share the contents of the file `source` names.
    ///
    /// No filesystem this kernel answers for can share contents, so the answer
    /// is always `SyscallAnswer.Failed`: EBADF for a descriptor the process
    /// does not hold, EXDEV for two objects on different filesystems, EISDIR
    /// if either is a directory, EINVAL if either is not a regular file, EBADF
    /// for a destination not open for writing or a source not open for
    /// reading, and otherwise EOPNOTSUPP on a tmpfs. The system comes back
    /// unchanged; a clone that succeeded would change the destination.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Linux-flavoured, and `FICLONE` is a Linux request.</exception>
    let fileClone<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (destination : int)
        (source : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryFileClone caller destination source system
        |> Refusal.orRaise "UnixDescriptor.fileClone" FileCloneRefusal.kind FileCloneRefusal.describe

    /// `terminalAttributes` once `Entry` has admitted its caller.
    let private terminalAttributesIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : TerminalAttributesAnswer
        =
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        // Measured by pipe-syscalls.c, through isatty, tcgetattr and
        // TIOCGWINSZ alike, which agree on every row:
        //
        //   descriptor                          Linux    Darwin
        //   not open                            EBADF    EBADF
        //   regular file, directory, pipe end   ENOTTY   ENOTTY
        //   TCP or UDP socket, IPv4 or IPv6     ENOTTY   ENXIO
        //   Unix-domain socket, either kind     ENOTTY   EOPNOTSUPP
        //   epoll instance / kqueue             EINVAL   ENOTTY
        //   inotify instance                    ENOTTY   -
        //
        // (the inotify row by `inotify-descriptor-probe.c`, row D isatty),
        // and a device answers what its driver does
        // (`CharacterDevice.unrecognisedIoctl`).
        let error =
            match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
            | None -> UnixError.EBADF
            | Some (OpenFileTarget.File _)
            | Some (OpenFileTarget.Directory _)
            | Some (OpenFileTarget.Pipe _) -> UnixError.ENOTTY
            | Some (OpenFileTarget.CharacterDevice (_, device, _)) -> CharacterDevice.unrecognisedIoctl device
            | Some (OpenFileTarget.Epoll _) -> UnixError.EINVAL
            | Some (OpenFileTarget.Inotify _) -> UnixError.ENOTTY
            | Some (OpenFileTarget.Kqueue _) -> UnixError.ENOTTY
            | Some (OpenFileTarget.Fifo (inode, _)) -> ReservedFifo.fail "UnixDescriptor.terminalAttributes" inode
            | Some (OpenFileTarget.Socket socketId) ->
                match flavour, (UnixMachineState.socket socketId system.Machine).Domain with
                | SimulatedUnixFlavour.Linux, _ -> UnixError.ENOTTY
                | SimulatedUnixFlavour.Darwin, SocketDomain.Inet
                | SimulatedUnixFlavour.Darwin, SocketDomain.Inet6 -> UnixError.ENXIO
                | SimulatedUnixFlavour.Darwin, SocketDomain.Unix -> UnixError.EOPNOTSUPP

        TerminalAttributesAnswer.NotATerminal error

    /// `tcgetattr(3)`, and so `isatty(3)`: whether `fd` is a terminal. None of
    /// the objects this kernel models is one, so the answer is always
    /// `TerminalAttributesAnswer.NotATerminal`, with the errno saying why not,
    /// which depends on the object and the flavour.
    ///
    /// Changes nothing.
    let terminalAttributes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : TerminalAttributesAnswer
        =
        Entry.call
            "UnixDescriptor.terminalAttributes"
            CallerRequirement.Running
            caller
            Shape.answer
            (terminalAttributesIn fd)
            system

    /// Which of the closing process's parked calls a close looks at.
    [<RequireQualifiedAccess>]
    type internal ParksExamined =
        /// Those holding the description the closed descriptor names
        /// (`ParkedSyscall.descriptions`), which are the only ones a close can
        /// act on, found without visiting the threads when no call holds it.
        | Holding
        /// Every one: what `Holding` must answer the same as.
        | Every

    // `FileDescriptorRegistry.dropDescriptor` cannot do this itself: the
    // socket table is the machine's rather than the process's, whether an
    // inode is still named is a question about the filesystem, and what a
    // sleeping call holds is the thread table's.
    /// `tryClose` once `Entry` has admitted its caller, looking at the parked
    /// calls `examined` names.
    let internal tryCloseExamining<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (examined : ParksExamined)
        (fd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, CloseRefusal<'Thread>>
        =
        match FileDescriptorRegistry.tryFindWithId fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (SyscallAnswer.Failed UnixError.EBADF, system)
        | Some (closingId, closing) ->

        let parked () : ('Thread * ParkedSyscall) list =
            UnixThreadTable.byName system.Threads
            |> Map.toList
            |> List.choose (fun (thread, state) -> state.Parked |> Option.map (fun park -> thread, park.Syscall))

        // Every park this close acts on holds the closing description. A
        // sleep entered through `fd` holds the description it names
        // (`SleepTarget.Waiting`), as does an flock, `epoll_wait`, `kevent` or
        // inotify read of it. A Linux poll watching `fd` holds the description
        // it found there, which is the one `fd` names, since a park whose
        // watched descriptor names another is a defect
        // (`UnixSystemDefect.ParkedPollDescriptorRebound`). A Darwin poll
        // holds nothing, and what a close does to it goes through its kqueue
        // (`KqueuePoll.dropRegistrationsThrough`), not through `parks`. The
        // open file table counts the holds (`OpenFileTable.holdCount`, which
        // `UnixSystem.checkInvariants` keeps equal to the parks'), so with
        // none there is no park to look at, and no thread to visit.
        let parks : ('Thread * ParkedSyscall) list =
            match examined with
            | ParksExamined.Every -> parked ()
            | ParksExamined.Holding ->
                match OpenFileTable.holdCount closingId system.Machine.OpenFiles with
                | Some 0 -> []
                | Some _ ->
                    parked ()
                    |> List.filter (fun (_, parked) -> List.contains closingId (ParkedSyscall.descriptions parked))
                | None ->
                    failwith
                        $"UnixDescriptor.close: fd %d{fd} names open file description %O{closingId}, which the open file table does not hold (this is a bug in this library)."

        let darwin =
            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux -> false
            | SimulatedUnixFlavour.Darwin -> true

        // Whether `target` is a sleep on the closing description that was made
        // through the closing descriptor.
        let enteredHere (target : SleepTarget<'Object>) : bool =
            match target with
            | SleepTarget.Waiting (description, entered) -> description = closingId && entered = fd
            | SleepTarget.EndedByClose _ -> false

        // Measured on Darwin 27.0.0 (`close-ends-call.c` sections A3, A4 and
        // A7, `tcp-close-drain.c`, and `udp-sleepers.c` V11, V12 and V24 to
        // V29 in docs/plans/2026-10-18-udp-data-path): closing the descriptor
        // that an accept, a read or write of a connection, or a receive on a
        // UDP socket sleeps through drains the socket. It ends every such call
        // asleep on the socket, through that descriptor or a dup of it and in
        // either direction, and leaves the socket drained
        // (`SocketDescription.Drained`). A call asleep through a
        // dup alone drains nothing (`tcp-close-drain.c` T1, T13), and nor does
        // a poll through the descriptor closed (T19). Every call asleep on the
        // socket is this process's, since nothing passes a descriptor to
        // another.
        let drainsSocket =
            darwin
            && parks
               |> List.exists (fun (_, parked) ->
                   match parked with
                   | ParkedSyscall.Accept accept -> enteredHere accept.Listener
                   | ParkedSyscall.ConnectionRead read -> enteredHere read.Socket
                   | ParkedSyscall.ConnectionWrite write -> enteredHere write.Socket
                   | ParkedSyscall.DatagramReceive receive -> enteredHere receive.Socket
                   // Reserved: nothing parks a thread in it yet. A Darwin select
                   // through the descriptor closed drains a socket too
                   // (`tcp-close-drain.c` T20), but holds no description, so
                   // `parks` never shows it.
                   | ParkedSyscall.Select _
                   | ParkedSyscall.EpollWait _
                   | ParkedSyscall.Kevent _
                   | ParkedSyscall.Flock _
                   | ParkedSyscall.Poll _
                   | ParkedSyscall.KqueuePoll _
                   | ParkedSyscall.PipeRead _
                   | ParkedSyscall.PipeWrite _
                   | ParkedSyscall.SigSuspend
                   | ParkedSyscall.Sleep _
                   | ParkedSyscall.SignalWait _
                   | ParkedSyscall.DatagramSend _
                   | ParkedSyscall.Connect _
                   | ParkedSyscall.Futex _
                   | ParkedSyscall.FifoOpen _
                   | ParkedSyscall.InotifyRead _ -> false
               )

        // Whether the drain ends `target`'s call: it sleeps on the closing
        // description, through whichever descriptor.
        let drainedHere (target : SleepTarget<'Object>) : bool =
            drainsSocket && SleepTarget.description target = Some closingId

        // Under Darwin, a close of the descriptor an flock was entered through
        // does not return until the flock has (measured,
        // `open-file-references.c` section D), and the park does not record
        // which descriptor that was, so any close onto the description
        // refuses. Checked against the park record rather than a thread's run
        // state, so the window between a wake and the woken thread's re-entry is
        // covered too.
        let darwinRefusal : CloseRefusal<'Thread> option =
            if not darwin then
                None
            else
                parks
                |> List.tryPick (fun (thread, parked) ->
                    match parked with
                    | ParkedSyscall.EpollWait wait when wait.Epoll = closingId ->
                        failwith
                            $"UnixDescriptor.close: thread %O{thread} is parked in an epoll_wait on %O{closingId} under the Darwin flavour, which has no epoll (this is a bug in the caller's state construction)."
                    | ParkedSyscall.InotifyRead read when read.Instance = closingId ->
                        failwith
                            $"UnixDescriptor.close: thread %O{thread} is parked in a read of the inotify instance %O{closingId} under the Darwin flavour, which has no inotify (this is a bug in the caller's state construction)."
                    | ParkedSyscall.Flock parked when parked.Requester = closingId ->
                        Some (CloseRefusal.DarwinFlockedDescriptorWithWaiter (closingId, thread))
                    | ParkedSyscall.PipeRead read when enteredHere read.Reader ->
                        // Measured (`close-ends-call.c` sections P1, P6): the
                        // close ends the read with end of file, which is what a
                        // read woken by the last writer closing answers too.
                        match
                            WakeCondition.satisfied thread (WakeCondition.ofPark parked) system
                            |> Set.filter (fun primitive ->
                                match primitive with
                                | WakePrimitive.PipeWriteEndClosed _ -> false
                                | _ -> true
                            )
                            |> Set.isEmpty
                        with
                        | true -> None
                        | false -> Some (CloseRefusal.DarwinWokenTransfer (closingId, thread))
                    | ParkedSyscall.PipeWrite write when enteredHere write.Writer ->
                        // Measured (`close-ends-call.c` sections P2-P4): the
                        // close ends the write with EPIPE whatever it had put
                        // in, which is what a write woken by the last reader
                        // closing answers too.
                        match
                            WakeCondition.satisfied thread (WakeCondition.ofPark parked) system
                            |> Set.filter (fun primitive ->
                                match primitive with
                                | WakePrimitive.PipeReadEndClosed _ -> false
                                | _ -> true
                            )
                            |> Set.isEmpty
                        with
                        | true -> None
                        | false -> Some (CloseRefusal.DarwinWokenTransfer (closingId, thread))
                    | ParkedSyscall.ConnectionRead {
                                                       Socket = socket
                                                   }
                    | ParkedSyscall.ConnectionWrite {
                                                        Socket = socket
                                                    } when drainedHere socket ->
                        // Measured (`tcp-blocking.c` sections R-close and
                        // W-close, `tcp-close-drain.c`): the drain ends the
                        // call with EBADF. Nothing else answers a transfer so,
                        // so any wake at all is one the close races.
                        if Set.isEmpty (WakeCondition.satisfied thread (WakeCondition.ofPark parked) system) then
                            None
                        else
                            Some (CloseRefusal.DarwinWokenTransfer (closingId, thread))
                    | ParkedSyscall.DatagramReceive receive when drainedHere receive.Socket ->
                        // Measured (`udp-sleepers.c` V11, V12): the drain ends
                        // the receive with EBADF, as above.
                        if Set.isEmpty (WakeCondition.satisfied thread (WakeCondition.ofPark parked) system) then
                            None
                        else
                            Some (CloseRefusal.DarwinWokenTransfer (closingId, thread))
                    | ParkedSyscall.EpollWait _
                    | ParkedSyscall.Kevent _
                    | ParkedSyscall.Accept _
                    | ParkedSyscall.PipeRead _
                    | ParkedSyscall.PipeWrite _
                    | ParkedSyscall.ConnectionRead _
                    | ParkedSyscall.ConnectionWrite _
                    | ParkedSyscall.Flock _
                    | ParkedSyscall.Poll _
                    | ParkedSyscall.SigSuspend
                    | ParkedSyscall.Sleep _
                    | ParkedSyscall.Select _
                    | ParkedSyscall.SignalWait _
                    | ParkedSyscall.DatagramReceive _
                    | ParkedSyscall.DatagramSend _
                    | ParkedSyscall.Connect _
                    | ParkedSyscall.Futex _
                    // No descriptor names a FIFO open's description until the call
                    // installs it, so no close reaches it.
                    | ParkedSyscall.FifoOpen _
                    | ParkedSyscall.InotifyRead _
                    // A Darwin poll's filters go with the descriptor (below).
                    | ParkedSyscall.KqueuePoll _ -> None
                )

        match darwinRefusal with
        | Some refusal -> Error refusal
        | None ->

        // A real poll looks each descriptor up again whenever it wakes, so
        // closing one it watches changes what it reports -- by number, not by
        // description, so a `dup` keeping the description alive does not help.
        let pollRefusal : CloseRefusal<'Thread> option =
            parks
            |> List.tryPick (fun (thread, parked) ->
                match parked with
                | ParkedSyscall.Poll parked ->
                    let watches =
                        parked.Entries
                        |> List.exists (fun entry ->
                            match entry with
                            | ParkedPollEntry.Watched (watched, _, _) -> watched = fd
                            | ParkedPollEntry.Ignored _ -> false
                        )

                    if watches then
                        Some (CloseRefusal.PolledDescriptor (fd, thread))
                    else
                        None
                | ParkedSyscall.Flock _
                | ParkedSyscall.EpollWait _
                | ParkedSyscall.Kevent _
                | ParkedSyscall.KqueuePoll _
                | ParkedSyscall.Accept _
                | ParkedSyscall.PipeRead _
                | ParkedSyscall.PipeWrite _
                | ParkedSyscall.SigSuspend
                | ParkedSyscall.Sleep _
                | ParkedSyscall.Select _
                | ParkedSyscall.SignalWait _
                | ParkedSyscall.DatagramReceive _
                | ParkedSyscall.DatagramSend _
                | ParkedSyscall.Connect _
                | ParkedSyscall.Futex _
                | ParkedSyscall.FifoOpen _
                | ParkedSyscall.InotifyRead _
                | ParkedSyscall.ConnectionRead _
                | ParkedSyscall.ConnectionWrite _ -> None
            )

        match pollRefusal with
        | Some refusal -> Error refusal
        | None ->

        // Measured on Darwin 27.0.0 (`close-ends-call.c`): closing the
        // descriptor a sleeping call was made through ends the call before the
        // close returns. A pipe `read` or `write` ends alone, and every call
        // asleep through that descriptor with it (section P5), but none asleep
        // through a `dup` (P6, P7, and `tcp-close-drain.c` P1-P4). A drain
        // ends every accept and connection transfer on the socket (above).
        // Each ended call has returned by the time the close does, so it holds
        // nothing from here on: its description goes now if no descriptor
        // names it, and the pipe's timestamps move now (P8). What it answers
        // waits in its park for its finishing call.
        let pipeOfClosing () : PipeId =
            match closing.Target with
            | OpenFileTarget.Pipe (pipeId, _) -> pipeId
            | target ->
                failwith
                    $"UnixDescriptor.close: a pipe transfer sleeps through fd %d{fd}, which names %A{target} rather than a pipe end (this is a bug in this library, or in a caller that assembled the state by hand)."

        let socketOfClosing () : SocketId =
            match closing.Target with
            | OpenFileTarget.Socket socketId -> socketId
            | target ->
                failwith
                    $"UnixDescriptor.close: an accept or a connection transfer sleeps through fd %d{fd}, which names %A{target} rather than a socket (this is a bug in this library, or in a caller that assembled the state by hand)."

        let ended (parked : ParkedSyscall) : ParkedSyscall option =
            match parked with
            | ParkedSyscall.Accept accept when drainedHere accept.Listener ->
                Some (
                    ParkedSyscall.Accept
                        { accept with
                            Listener = SleepTarget.EndedByClose (socketOfClosing ())
                        }
                )
            | ParkedSyscall.PipeRead read when darwin && enteredHere read.Reader ->
                Some (
                    ParkedSyscall.PipeRead
                        { read with
                            Reader = SleepTarget.EndedByClose (pipeOfClosing ())
                        }
                )
            | ParkedSyscall.PipeWrite write when darwin && enteredHere write.Writer ->
                Some (
                    ParkedSyscall.PipeWrite
                        { write with
                            Writer = SleepTarget.EndedByClose (pipeOfClosing ())
                        }
                )
            | ParkedSyscall.ConnectionRead read when drainedHere read.Socket ->
                Some (
                    ParkedSyscall.ConnectionRead
                        { read with
                            Socket = SleepTarget.EndedByClose (socketOfClosing ())
                        }
                )
            | ParkedSyscall.ConnectionWrite write when drainedHere write.Socket ->
                Some (
                    ParkedSyscall.ConnectionWrite
                        { write with
                            Socket = SleepTarget.EndedByClose (socketOfClosing ())
                        }
                )
            | ParkedSyscall.DatagramReceive receive when drainedHere receive.Socket ->
                Some (
                    ParkedSyscall.DatagramReceive
                        { receive with
                            Socket = SleepTarget.EndedByClose (socketOfClosing ())
                        }
                )
            | ParkedSyscall.Accept _
            | ParkedSyscall.PipeRead _
            | ParkedSyscall.PipeWrite _
            | ParkedSyscall.ConnectionRead _
            | ParkedSyscall.ConnectionWrite _
            | ParkedSyscall.EpollWait _
            | ParkedSyscall.Kevent _
            | ParkedSyscall.Flock _
            | ParkedSyscall.Poll _
            | ParkedSyscall.SigSuspend
            | ParkedSyscall.Sleep _
            | ParkedSyscall.SignalWait _
            // No descriptor names a FIFO open's description until the call
            // installs it, so no close reaches it.
            | ParkedSyscall.FifoOpen _
            // Only Linux has inotify, and its close leaves the read asleep
            // (measured, `inotify-probe.c` row B close-under-read).
            | ParkedSyscall.InotifyRead _
            // Reserved: nothing parks a thread in it yet. Darwin's close of a
            // selected descriptor will end it, with EBADF (measured,
            // `docs/probes/select-park` row E1); Linux's leaves it asleep. A
            // Darwin select holds nothing (`ParkedSyscall.descriptions`), so
            // `parks` never shows it here: ending it needs another way to find
            // the selects watching `fd`.
            | ParkedSyscall.Select _
            // Linux's close leaves a receive asleep (measured,
            // `udp-sleepers.c` V11), and so does a Darwin one that drains
            // nothing.
            | ParkedSyscall.DatagramReceive _
            // Reserved: nothing parks a thread in it yet.
            | ParkedSyscall.DatagramSend _
            // Reserved: nothing parks a thread in it yet, and no Darwin connect
            // sleeps.
            | ParkedSyscall.Connect _
            // Only Linux has futex, and a futex wait holds no description.
            | ParkedSyscall.Futex _
            | ParkedSyscall.KqueuePoll _ -> None

        let endedCalls =
            parks
            |> List.choose (fun (thread, parked) -> ended parked |> Option.map (fun ended -> thread, ended))

        let machine =
            (system.Machine, endedCalls)
            ||> List.fold (fun machine (_, ended) ->
                match ended with
                | ParkedSyscall.PipeRead {
                                             Reader = SleepTarget.EndedByClose pipeId
                                         } -> UnixMachineState.touchedByPipeRead pipeId system.Scheduling machine
                | ParkedSyscall.PipeWrite {
                                              Writer = SleepTarget.EndedByClose pipeId
                                          } -> UnixMachineState.touchedByPipeWrite pipeId system.Scheduling machine
                | _ -> machine
            )

        let machine =
            if not drainsSocket then
                machine
            else
                let socketId = socketOfClosing ()

                { machine with
                    Sockets =
                        SocketTable.set
                            socketId
                            { UnixMachineState.socket socketId machine with
                                Drained = true
                            }
                            machine.Sockets
                }

        // Each ended call keeps its park, for its finishing call to read, and
        // lets go of the hold it had on what it slept on.
        let ended =
            ({ system with
                Machine = machine
             },
             endedCalls)
            ||> List.fold (fun system (thread, ended) ->
                match UnixThreadTable.parkOf thread system.Threads with
                | Some park ->
                    UnixParkState.setPark
                        thread
                        { park with
                            Syscall = ended
                        }
                        system
                | None ->
                    failwith
                        $"UnixDescriptor.close: thread %O{thread} was parked a moment ago and is not now (this is a bug in this library)."
            )

        let machine = ended.Machine

        // Measured (`close-ends-call.c` sections P2-P4 and P7): each write the
        // close ends raises SIGPIPE for the process as it returns, which is
        // before the close returns, so the signal's disposition is the one it
        // has now, whatever it is by the time the write's thread finishes.
        let signalled =
            (Ok ended, endedCalls)
            ||> List.fold (fun signalled (thread, endedCall) ->
                match signalled, endedCall with
                | Error refusal, _ -> Error refusal
                | Ok signalled,
                  ParkedSyscall.PipeWrite {
                                              Writer = SleepTarget.EndedByClose _
                                          } ->
                    if ProcessSignal.isInit signalled then
                        Error (CloseRefusal.DarwinEndedWriteSignal (thread, EndedWriteSignalRefusal.InitProcess))
                    else

                    match
                        ProcessSignal.effect
                            SignalSender.Kernel
                            {
                                Signal = Signal.SIGPIPE
                                Target = ValueNone
                            }
                            signalled
                    with
                    | Ok (SignalEffect.Applied (KillOutcome.ProcessRuns, signalled)) -> Ok signalled
                    | Ok (SignalEffect.Kills _) ->
                        Error (CloseRefusal.DarwinEndedWriteSignal (thread, EndedWriteSignalRefusal.TerminatesProcess))
                    | Ok SignalEffect.QueueFull ->
                        failwith
                            "UnixDescriptor.close: SIGPIPE found the queue full, which only a real-time signal sent by tgkill can (this is a bug in this library)."
                    | Ok (SignalEffect.Applied (KillOutcome.ProcessStopped signal, _)) ->
                        failwith
                            $"UnixDescriptor.close: generating %O{signal} for a pipe write the close ended stopped the process, but SIGPIPE's default is to terminate on every flavour (this is a bug in this library)."
                    | Error refusal ->
                        Error (CloseRefusal.DarwinEndedWriteSignal (thread, EndedWriteSignalRefusal.Receiver refusal))
                | Ok signalled, _ -> Ok signalled
            )

        match signalled with
        | Error refusal -> Error refusal
        | Ok signalled ->

        let signals = signalled.Process.Signals
        // As the signals left them: the thread a SIGPIPE is deliverable to
        // owes a return to user mode.
        let threads = signalled.Threads

        // Measured on Darwin 27.0.0 (`fcntl-dup.c`, WRITTEN rows): an ended
        // write that had moved bytes returns having written, which marks the
        // description it was made through, as any such write does; a dup that
        // keeps the description shows it.
        let openFiles =
            let endedHavingWritten =
                endedCalls
                |> List.exists (fun (_, ended) ->
                    match ended with
                    | ParkedSyscall.PipeWrite write -> write.Written > 0
                    // A `send` marks nothing, ended or not (measured,
                    // `tcp-recv-send.c` section W).
                    | ParkedSyscall.ConnectionWrite write ->
                        write.Written > 0
                        && (
                            match write.Call with
                            | TcpSendCall.Write -> true
                            | TcpSendCall.Send _ -> false
                        )
                    | ParkedSyscall.ConnectionRead _
                    | ParkedSyscall.PipeRead _
                    | ParkedSyscall.Accept _
                    | ParkedSyscall.EpollWait _
                    | ParkedSyscall.Kevent _
                    | ParkedSyscall.Flock _
                    | ParkedSyscall.Poll _
                    | ParkedSyscall.SigSuspend
                    | ParkedSyscall.Sleep _
                    | ParkedSyscall.Select _
                    | ParkedSyscall.SignalWait _
                    | ParkedSyscall.DatagramReceive _
                    | ParkedSyscall.DatagramSend _
                    | ParkedSyscall.Connect _
                    | ParkedSyscall.Futex _
                    | ParkedSyscall.FifoOpen _
                    | ParkedSyscall.InotifyRead _
                    | ParkedSyscall.KqueuePoll _ -> false
                )

            if endedHavingWritten then
                OpenFileTable.mapStatus closingId OpenFileStatus.markWritten machine.OpenFiles
            else
                machine.OpenFiles

        let system =
            { system with
                Machine =
                    { machine with
                        OpenFiles = openFiles
                    }
                Process =
                    { system.Process with
                        Signals = signals
                    }
                Threads = threads
            }

        let registry, destroyed =
            match
                FileDescriptorRegistry.dropDescriptor
                    system.Process.ProcessId
                    fd
                    (UnixSystemState.fileDescriptors system)
            with
            | Ok dropped -> dropped
            | Error FileDescriptorCloseError.BadFd ->
                failwith
                    $"UnixDescriptor.close: fd %d{fd} named open file description %O{closingId} (%A{closing.Target}) a moment ago, and the registry now calls it a bad descriptor (this is a bug in this library)."

        // The description outlives its last descriptor only while calls hold
        // it (under Darwin, those the close has not ended), and the socket's
        // close then happens as the last of them returns, which has no refusal
        // to answer with. Under `SO_LINGER` that close may be one this kernel
        // refuses, so it is refused now instead.
        let deferredUnderLinger : CloseRefusal<'Thread> option =
            match destroyed, closing.Target with
            | None, OpenFileTarget.Socket socketId when
                OpenFileTable.descriptorCount closingId (FileDescriptorRegistry.openFiles registry) = Some 0
                && ObjectLifetime.lingerCanRefuseRelease (UnixMachineState.socket socketId system.Machine)
                ->
                let holder =
                    UnixThreadTable.byName threads
                    |> Map.toSeq
                    |> Seq.tryPick (fun (thread, state) ->
                        match state.Parked with
                        | Some park when List.contains closingId (ParkedSyscall.descriptions park.Syscall) ->
                            Some thread
                        | Some _
                        | None -> None
                    )

                match holder with
                | Some thread -> Some (CloseRefusal.LingeringCloseDeferredToCall (socketId, thread))
                | None ->
                    failwith
                        $"UnixDescriptor.close: closing fd %d{fd} left open file description %O{closingId} with no descriptor and undestroyed, but no thread of this process is parked in a call that holds it (this is a bug in this library)."
            | None, _
            | Some _, _ -> None

        match deferredUnderLinger with
        | Some refusal -> Error refusal
        | None ->

        // Measured on Darwin 27.0.0 (`kqueue-kevent.c`, sections E and F):
        // closing a descriptor a thread is asleep in `kevent` through drains the
        // kqueue, which ends that wait and every other wait on the kqueue with
        // EBADF, and leaves every later wait on it EBADF too. Closing one no
        // waiter entered through changes nothing. A waiter holds the kqueue
        // (`ParkedSyscall.descriptions`), so a close that drains it has not
        // destroyed it, even when it closed the last descriptor: the kqueue
        // goes as the last call holding it returns.
        //
        // Checked against the park records rather than a thread's run state: a
        // woken waiter has not left the call yet.
        let registry =
            match closing.Target with
            | OpenFileTarget.Kqueue _ ->
                let enteredHere =
                    parks
                    |> List.exists (fun (_, parked) ->
                        match parked with
                        | ParkedSyscall.Kevent wait -> wait.Kqueue = closingId && wait.Fd = fd
                        | ParkedSyscall.EpollWait _
                        | ParkedSyscall.Flock _
                        | ParkedSyscall.Poll _
                        | ParkedSyscall.KqueuePoll _
                        | ParkedSyscall.Accept _
                        | ParkedSyscall.PipeRead _
                        | ParkedSyscall.PipeWrite _
                        | ParkedSyscall.SigSuspend
                        | ParkedSyscall.Sleep _
                        | ParkedSyscall.Select _
                        | ParkedSyscall.SignalWait _
                        | ParkedSyscall.DatagramReceive _
                        | ParkedSyscall.DatagramSend _
                        | ParkedSyscall.Connect _
                        | ParkedSyscall.Futex _
                        | ParkedSyscall.FifoOpen _
                        | ParkedSyscall.InotifyRead _
                        | ParkedSyscall.ConnectionRead _
                        | ParkedSyscall.ConnectionWrite _ -> false
                    )

                if enteredHere then
                    FileDescriptorRegistry.mapOpenFiles (OpenFileTable.drainKqueue closingId) registry
                else
                    registry
            | OpenFileTarget.Epoll _
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Socket _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _ -> registry

        let closed = UnixSystemState.withFileDescriptors registry system

        // `dropDescriptor` removed the kqueue registrations made through `fd`
        // from every kqueue the process owns; a sleeping Darwin poll's kqueue
        // is the call's own, so it loses them here (measured, `poll-timeout.c`
        // section E: the entry then reports nothing, and the poll sleeps on to
        // its timeout).
        let closed =
            { closed with
                Machine = KqueuePoll.dropRegistrationsThrough system.Process.ProcessId fd closed.Machine
            }

        match destroyed with
        | None -> Ok (SyscallAnswer.Completed 0L, closed)
        | Some destroyed ->

        match ObjectLifetime.releaseDestroyed destroyed closed with
        | Error refusal -> Error (CloseRefusal.Release refusal)
        | Ok released -> Ok (SyscallAnswer.Completed 0L, released)

    /// `close`, with a refusal answered as the `Error` rather than raised.
    let internal tryClose<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, CloseRefusal<'Thread>>
        =
        Entry.call
            "UnixDescriptor.close"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryCloseExamining ParksExamined.Holding fd)
            system

    /// `close(2)`: drop `fd` from the process's table, together with the
    /// description it named if nothing references that any more, and the kernel
    /// objects the description was the last reference to — the socket, the
    /// connections nothing else references, the pipe, and the inode whose last
    /// name had already gone.
    ///
    /// A description is referenced by every descriptor naming it and by every
    /// syscall in flight that holds it (`ParkedSyscall.descriptions`), as a
    /// real kernel holds a file for a call that sleeps on it. So under Linux a
    /// close under a sleeping call is served, and the call sleeps on: the
    /// description goes when the call returns, which is when its finishing call
    /// releases it. That is refused for a connected socket whose `SO_LINGER`
    /// is on, whose close this kernel may refuse when the call returns. Under Darwin a close of the
    /// descriptor a `kevent` sleeps through is served too, and drains the
    /// kqueue, which ends that wait and every other on
    /// the kqueue; the kqueue goes as the last of them returns, if no
    /// descriptor names it by then.
    ///
    /// Under Darwin a close of the descriptor a sleeping pipe `read` or `write`
    /// was made through ends every such call made through it, and none made
    /// through another descriptor: the read with end of file, the write with
    /// `EPIPE` and `SIGPIPE`, whatever it had put in. A close of the
    /// descriptor that a sleeping `accept`, a sleeping `read` or `write` of a
    /// connected socket, or a sleeping receive on a UDP socket, was made
    /// through drains the socket (`SocketDescription.Drained`): it ends every
    /// such call asleep on the socket, through any descriptor, an accept with
    /// `ECONNABORTED` and a transfer or receive with `EBADF`, whatever it had
    /// taken, and no signal. A close
    /// with such a call asleep only through another descriptor drains
    /// nothing. Darwin's close returns only once
    /// such a call has, so an ended call holds nothing from the close on
    /// (`SleepTarget.EndedByClose`): the description goes at the close if no
    /// descriptor names it, the pipe's timestamps move as the call's return
    /// moves them, an ended write's `SIGPIPE` is generated for the process
    /// (refused where that would end the process),
    /// and the thread, still parked, learns its answer from its finishing call. A close that would end a
    /// pipe or connection transfer that something had already woken is
    /// refused.
    ///
    /// Every kqueue registration made through `fd` goes with it, in each kqueue
    /// the process owns and in the kqueue of every
    /// sleeping Darwin `poll` of the process's own (`PollQueue`), whose entry
    /// then reports nothing.
    ///
    /// EBADF is its only errno.
    let close<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryClose caller fd system
        |> Refusal.orRaise "UnixDescriptor.close" CloseRefusal.kind CloseRefusal.describe

    /// What an `fcntl(2)` command number names, among the commands modelled.
    [<RequireQualifiedAccess>]
    type private FcntlCommand =
        /// `F_DUPFD`, or with `closeOnExec` `F_DUPFD_CLOEXEC`.
        | DuplicateAtOrAbove of closeOnExec : bool
        /// `F_GETFD`.
        | GetDescriptorFlags
        /// `F_SETFD`.
        | SetDescriptorFlags
        /// `F_GETFL`.
        | GetStatusFlags
        /// `F_SETFL`.
        | SetStatusFlags

    let private decodeCommand (flavour : SimulatedUnixFlavour) (command : int) : FcntlCommand option =
        match command with
        | FcntlNumbering.DuplicateAtOrAbove -> Some (FcntlCommand.DuplicateAtOrAbove false)
        | FcntlNumbering.GetDescriptorFlags -> Some FcntlCommand.GetDescriptorFlags
        | FcntlNumbering.SetDescriptorFlags -> Some FcntlCommand.SetDescriptorFlags
        | FcntlNumbering.GetStatusFlags -> Some FcntlCommand.GetStatusFlags
        | FcntlNumbering.SetStatusFlags -> Some FcntlCommand.SetStatusFlags
        | command when command = FcntlNumbering.duplicateCloseOnExec flavour ->
            Some (FcntlCommand.DuplicateAtOrAbove true)
        | _ -> None

    /// The flavour's `O_NONBLOCK`.
    let private nonBlockingBit (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> OpenFlagNumbering.LinuxNonBlock
        | SimulatedUnixFlavour.Darwin -> OpenFlagNumbering.DarwinNonBlock

    /// The word `F_GETFL` reports for `description` on `platform`.
    let private statusWord (platform : SimulatedUnixPlatform) (description : OpenFileDescription) : int =
        let bit (condition : bool) (value : int) : int = if condition then value else 0
        let architecture = SimulatedUnixPlatform.architecture platform

        let accessMode =
            match description.AccessMode with
            | FileAccessMode.ReadOnly -> 0
            | FileAccessMode.WriteOnly -> 1
            | FileAccessMode.ReadWrite -> 2

        let status = OpenFileStatus.flagBits architecture description.Status

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            // Measured (`fcntl-dup.c`, KIND rows): a 64-bit kernel's `open(2)`
            // adds O_LARGEFILE to every description it makes, and nothing else
            // that makes a description does.
            let madeByOpen =
                match description.Target with
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Fifo _ -> true
                | OpenFileTarget.Pipe _
                | OpenFileTarget.Socket _
                | OpenFileTarget.Epoll _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Kqueue _ -> false

            accessMode
            ||| bit description.NonBlocking OpenFlagNumbering.LinuxNonBlock
            ||| status
            ||| bit madeByOpen (OpenFlagNumbering.linuxLargeFile architecture)
        | SimulatedUnixFlavour.Darwin ->
            accessMode
            ||| bit description.NonBlocking OpenFlagNumbering.DarwinNonBlock
            ||| status

    /// Store `registry` as `system`'s descriptor table and open file descriptions.
    let private withRegistry<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (registry : FileDescriptorRegistry)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        UnixSystemState.withFileDescriptors registry system

    /// `tryFcntl` once `Entry` has admitted its caller.
    let private tryFcntlIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (command : int)
        (argument : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, FcntlRefusal>
        =
        let platform = system.Machine.UnixPlatform
        let flavour = SimulatedUnixPlatform.flavour platform
        let registry = UnixSystemState.fileDescriptors system

        // Measured on both (`fcntl-dup.c`, LIMIT rows): the descriptor is looked
        // up before the command is read, so an unknown command on a closed
        // descriptor is EBADF, and before F_DUPFD's argument is.
        match FileDescriptorRegistry.tryFindWithId fd registry with
        | None -> Ok (SyscallAnswer.Failed UnixError.EBADF, system)
        | Some (id, description) ->

        match decodeCommand flavour command with
        | None -> Error (FcntlRefusal.UnmodelledCommand command)
        | Some FcntlCommand.GetStatusFlags ->
            Ok (SyscallAnswer.Completed (int64 (statusWord platform description)), system)
        | Some FcntlCommand.SetStatusFlags ->
            // Measured (`fcntl-dup.c`, SETFL rows, every bit on every kind):
            // these are the only bits each flavour's F_SETFL changes.
            let unmodelled =
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    [
                        OpenFlagNumbering.LinuxAppend, UnmodelledStatusFlag.Append
                        OpenFlagNumbering.LinuxAsynchronous, UnmodelledStatusFlag.Asynchronous
                        OpenFlagNumbering.linuxDirect (SimulatedUnixPlatform.architecture platform),
                        UnmodelledStatusFlag.Direct
                        OpenFlagNumbering.LinuxNoAccessTime, UnmodelledStatusFlag.NoAccessTime
                    ]
                | SimulatedUnixFlavour.Darwin ->
                    [
                        OpenFlagNumbering.DarwinAppend, UnmodelledStatusFlag.Append
                        OpenFlagNumbering.DarwinAsynchronous, UnmodelledStatusFlag.Asynchronous
                    ]
                |> List.filter (fun (bit, _) -> argument &&& bit <> 0)
                |> List.map snd

            if not unmodelled.IsEmpty then
                Error (FcntlRefusal.UnmodelledStatusFlags (argument, unmodelled))
            else

            let registry =
                FileDescriptorRegistry.setNonBlocking fd (argument &&& nonBlockingBit flavour <> 0) registry
                |> FileDescriptorRegistry.mapOpenFiles (OpenFileTable.mapStatus id (OpenFileStatus.setFlags argument))

            match flavour with
            | SimulatedUnixFlavour.Linux -> Ok (SyscallAnswer.Completed 0L, withRegistry registry system)
            | SimulatedUnixFlavour.Darwin ->

            // Measured: Darwin stores the flags and then asks the file to take
            // O_NONBLOCK, which a kqueue answers ENOTTY, every time.
            match description.Target with
            | OpenFileTarget.Kqueue _ -> Ok (SyscallAnswer.Failed UnixError.ENOTTY, withRegistry registry system)
            | OpenFileTarget.Fifo (inode, _) -> ReservedFifo.fail "UnixDescriptor.fcntl" inode
            | OpenFileTarget.Inotify _ ->
                failwith
                    $"UnixDescriptor.fcntl: fd %d{fd} names an inotify instance under the Darwin flavour, which has no inotify (this is a bug in the caller's state construction)."
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.Pipe _
            | OpenFileTarget.Socket _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Epoll _ -> Ok (SyscallAnswer.Completed 0L, withRegistry registry system)
        | Some FcntlCommand.GetDescriptorFlags ->
            let flags =
                match FileDescriptorRegistry.tryFindFlags fd registry with
                | Some flags -> flags
                | None ->
                    failwith
                        $"UnixDescriptor.fcntl: fd %d{fd} named a description a moment ago and has no flags now (this is a bug in this library)."

            let bit (condition : bool) (value : int) : int = if condition then value else 0

            let word =
                match flags with
                | DescriptorFlags.Linux (closeOnExec = closeOnExec) -> bit closeOnExec FcntlNumbering.CloseOnExec
                | DescriptorFlags.Darwin (closeOnExec = closeOnExec ; closeOnFork = closeOnFork) ->
                    bit closeOnExec FcntlNumbering.CloseOnExec
                    ||| bit closeOnFork FcntlNumbering.DarwinCloseOnFork

            Ok (SyscallAnswer.Completed (int64 word), system)
        | Some FcntlCommand.SetDescriptorFlags ->
            // Measured (`fcntl-dup.c`, SETFD rows, every bit): Linux keeps bit
            // 0 and Darwin bits 0 and 1, and every other bit is ignored.
            let closeOnExec = argument &&& FcntlNumbering.CloseOnExec <> 0

            let flags =
                match flavour with
                | SimulatedUnixFlavour.Linux -> DescriptorFlags.Linux (closeOnExec = closeOnExec)
                | SimulatedUnixFlavour.Darwin ->
                    DescriptorFlags.Darwin (
                        closeOnExec = closeOnExec,
                        closeOnFork = (argument &&& FcntlNumbering.DarwinCloseOnFork <> 0)
                    )

            Ok (SyscallAnswer.Completed 0L, withRegistry (FileDescriptorRegistry.setFlags fd flags registry) system)
        | Some (FcntlCommand.DuplicateAtOrAbove closeOnExec) ->
            if argument < 0 then
                Ok (SyscallAnswer.Failed UnixError.EINVAL, system)
            else

            // Measured (`fcntl-dup.c`, LIMIT rows): EBADF and a negative
            // argument's EINVAL come ahead of the limit; an argument at or
            // above it is EINVAL, and a full table EMFILE, at a limit of the
            // bound, and a descriptor at a higher one.
            match FileDescriptorRegistry.room (SimulatedUnixPlatform.descriptorBound platform) argument 1 registry with
            | Error refusal -> Error (FcntlRefusal.DescriptorLimit refusal)
            | Ok () ->

            let flags = DescriptorFlags.closingOnExec flavour closeOnExec

            match FileDescriptorRegistry.dupAtOrAbove fd argument flags registry with
            | None ->
                failwith
                    $"UnixDescriptor.fcntl: no descriptor at or above %d{argument} is free, though one below the bound was a moment ago (this is a bug in this library)."
            | Some (newFd, registry) -> Ok (SyscallAnswer.Completed (int64 newFd), withRegistry registry system)

    /// `fcntl`, with a refusal answered as the `Error` rather than raised.
    let internal tryFcntl<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (command : int)
        (argument : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallAnswer * UnixSystem<'Thread, 'Handler>, FcntlRefusal>
        =
        Entry.call
            "UnixDescriptor.fcntl"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryFcntlIn fd command argument)
            system

    /// `fcntl(fd, command, argument)`, for the commands that manage
    /// descriptors and status flags: `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_GETFD`,
    /// `F_SETFD`, `F_GETFL` and `F_SETFL`.
    ///
    /// `command` and `argument` are raw, as a caller of the flavour's libc
    /// passes them, in its `<fcntl.h>` numbering: Linux's `F_DUPFD_CLOEXEC` is
    /// 1030 and Darwin's 67, and the status flags are numbered as `open(2)`'s.
    ///
    /// A descriptor that is not open is `EBADF`, whatever the command. Then:
    ///
    /// - `F_GETFL` answers the access mode and the status flags of the
    ///   description: `O_NONBLOCK`, `O_SYNC` and `O_DSYNC` on both flavours;
    ///   on Linux, `O_DIRECTORY` and `O_NOFOLLOW` as `open(2)` was given them,
    ///   and `O_LARGEFILE` for every description `open(2)` made; on Darwin, its
    ///   own `0x10000` once the description has been written through and
    ///   `0x4000` once a lock has been granted to it (`OpenFileStatus.Darwin`).
    /// - `F_SETFL` sets `O_NONBLOCK` from `argument`, and on Darwin `O_SYNC`
    ///   and `O_DSYNC` too, and ignores every other bit the flavour does not
    ///   change, the access mode included; so a word `F_GETFL` reported may be
    ///   given back. A word that would set `O_APPEND` or `O_ASYNC`, or Linux's
    ///   `O_DIRECT` or `O_NOATIME`, is refused.
    ///   On a Darwin kqueue the flags are stored and the call answers `ENOTTY`.
    /// - `F_GETFD` answers the descriptor's `FD_CLOEXEC` (1), and on Darwin its
    ///   `FD_CLOFORK` (2); `F_SETFD` sets them from those bits of `argument`
    ///   and ignores the rest.
    /// - `F_DUPFD` makes the lowest descriptor not in use at or above
    ///   `argument` name the same description, with neither descriptor flag;
    ///   `F_DUPFD_CLOEXEC` gives it `FD_CLOEXEC`. A negative `argument` is
    ///   `EINVAL`.
    ///
    /// An `F_DUPFD` whose descriptor would lie at or above the bound
    /// (`SimulatedUnixPlatform.descriptorBound`) is refused, after `EBADF` and
    /// a negative argument's `EINVAL`. Every other command is refused.
    let fcntl<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (command : int)
        (argument : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryFcntl caller fd command argument system
        |> Refusal.orRaise "UnixDescriptor.fcntl" FcntlRefusal.kind FcntlRefusal.describe

    /// `dup2` and `dup3` once the screens peculiar to `dup3` have passed: make
    /// `newFd` name the description `oldFd` names, with `flags`, closing it
    /// first if it is open.
    let private duplicateOnto<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (oldFd : int)
        (newFd : int)
        (flags : DescriptorFlags)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DescriptorAnswer * ProcessView<'Thread, 'Handler>, Dup2Refusal<'Thread>>
        =
        let registry = UnixSystemState.fileDescriptors system
        let bound = SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform

        // Measured (`fcntl-dup.c`, DUP2 rows): a negative target, and a source
        // that is not open, are each EBADF, and leave an open target open,
        // whatever the limit. A good source onto a target at or above the
        // limit is EBADF too, so onto one at or above the bound the answer
        // turns on the limit.
        if newFd < 0 || (FileDescriptorRegistry.tryFindId oldFd registry).IsNone then
            Ok (DescriptorAnswer.Failed UnixError.EBADF, system)
        elif oldFd = newFd then
            Ok (DescriptorAnswer.Returned newFd, system)
        elif newFd >= bound then
            Error (
                Dup2Refusal.DescriptorLimit
                    {
                        Descriptor = newFd
                        Bound = bound
                    }
            )
        else

        // Measured (`fcntl-dup.c`, ONTO and SLEEP rows): an open target is
        // closed as close(2) closes it, on both flavours: its description is
        // released if nothing else holds it, and a call asleep through it fares
        // exactly as under close(2) (close-ends-call.c), Darwin's dup2 blocking
        // where its close blocks. So the close is close's own.
        let closed =
            match FileDescriptorRegistry.tryFindId newFd registry with
            | None -> Ok system
            | Some _ ->
                match tryCloseExamining ParksExamined.Holding newFd system with
                | Error refusal -> Error (Dup2Refusal.ClosingTarget refusal)
                | Ok (SyscallAnswer.Completed _, system) -> Ok system
                | Ok (SyscallAnswer.Failed error, _) ->
                    failwith
                        $"UnixDescriptor.dup2: closing the open target %d{newFd} answered %O{error}, but close's only errno is EBADF for a descriptor that is not open (this is a bug in this library)."

        closed
        |> Result.map (fun system ->
            DescriptorAnswer.Returned newFd,
            withRegistry
                (FileDescriptorRegistry.installAt oldFd newFd flags (UnixSystemState.fileDescriptors system))
                system
        )

    /// `tryDup2` once `Entry` has admitted its caller.
    let private tryDup2In<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (oldFd : int)
        (newFd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DescriptorAnswer * ProcessView<'Thread, 'Handler>, Dup2Refusal<'Thread>>
        =
        duplicateOnto
            oldFd
            newFd
            (DescriptorFlags.none (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform))
            system

    /// `dup2`, with a refusal answered as the `Error` rather than raised.
    let internal tryDup2<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (oldFd : int)
        (newFd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, Dup2Refusal<'Thread>>
        =
        Entry.call
            "UnixDescriptor.dup2"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryDup2In oldFd newFd)
            system

    /// `dup2(2)`: make `newFd` name the open file description `oldFd` names,
    /// with neither descriptor flag, and answer `newFd`.
    ///
    /// A negative `newFd`, or an `oldFd` that is not open, is `EBADF`, and
    /// changes nothing. `dup2(fd, fd)` of an open `fd` answers `fd` and changes
    /// nothing, its flags included. An open `newFd` is closed first as
    /// `close(2)` closes it, with everything that does to the description it
    /// named and to calls asleep through it, and is refused where `close` is;
    /// so is one naming the same description as
    /// `oldFd`, whose flags the `dup2` then clears.
    ///
    /// A `newFd` at or above the bound (`SimulatedUnixPlatform.descriptorBound`)
    /// is refused, after the `EBADF`s.
    let dup2<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (oldFd : int)
        (newFd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : DescriptorAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryDup2 caller oldFd newFd system
        |> Refusal.orRaise "UnixDescriptor.dup2" Dup2Refusal.kind Dup2Refusal.describe

    /// `tryDup3` once `Entry` has admitted its caller.
    let private tryDup3In<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (oldFd : int)
        (newFd : int)
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DescriptorAnswer * ProcessView<'Thread, 'Handler>, Dup3Refusal<'Thread>>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (Dup3Refusal.NotProvided SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        // Measured (`fcntl-dup.c`, DUP2 rows): the flags first, then the same
        // descriptor on both sides, then dup2's EBADFs.
        if flags &&& ~~~OpenFlagNumbering.LinuxCloseOnExec <> 0 then
            Ok (DescriptorAnswer.Failed UnixError.EINVAL, system)
        elif oldFd = newFd then
            Ok (DescriptorAnswer.Failed UnixError.EINVAL, system)
        else

        let descriptorFlags =
            DescriptorFlags.Linux (closeOnExec = (flags &&& OpenFlagNumbering.LinuxCloseOnExec <> 0))

        duplicateOnto oldFd newFd descriptorFlags system
        |> Result.mapError (fun refusal ->
            match refusal with
            | Dup2Refusal.ClosingTarget refusal -> Dup3Refusal.ClosingTarget refusal
            | Dup2Refusal.DescriptorLimit refusal -> Dup3Refusal.DescriptorLimit refusal
        )

    /// `dup3`, with a refusal answered as the `Error` rather than raised.
    let internal tryDup3<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (oldFd : int)
        (newFd : int)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<DescriptorAnswer * UnixSystem<'Thread, 'Handler>, Dup3Refusal<'Thread>>
        =
        Entry.call
            "UnixDescriptor.dup3"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryDup3In oldFd newFd flags)
            system

    /// <summary>
    /// `dup3(2)`: `dup2`, but `flags` may carry `O_CLOEXEC` in Linux's
    /// numbering, which gives `newFd` `FD_CLOEXEC`, and `oldFd` and `newFd`
    /// must differ.
    ///
    /// Any other bit in `flags` is `EINVAL`, ahead of everything; then the same
    /// descriptor on both sides is `EINVAL`, open or not; then `dup2`'s
    /// answers and refusals. Refused under the Darwin flavour, which has no
    /// `dup3`.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">The flavour has no `dup3`.</exception>
    let dup3<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (oldFd : int)
        (newFd : int)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : DescriptorAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryDup3 caller oldFd newFd flags system
        |> Refusal.orRaise "UnixDescriptor.dup3" Dup3Refusal.kind Dup3Refusal.describe

    /// `setNonBlocking` once `Entry` has admitted its caller.
    let private setNonBlockingIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (isNonBlocking : bool)
        (system : ProcessView<'Thread, 'Handler>)
        : SetNonBlockingAnswer * ProcessView<'Thread, 'Handler>
        =
        let bit = nonBlockingBit (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)

        // A word F_GETFL reported holds no flag F_SETFL refuses, since no
        // description carries one, so neither call is refused.
        let unrefused (operation : string) (result : Result<'a, FcntlRefusal>) : 'a =
            match result with
            | Ok answer -> answer
            | Error refusal ->
                failwith
                    $"UnixDescriptor.setNonBlocking: %s{operation} on fd %d{fd} was refused (%s{FcntlRefusal.describe refusal}), but it carries only what F_GETFL reported (this is a bug in this library)."

        match unrefused "F_GETFL" (tryFcntlIn fd FcntlNumbering.GetStatusFlags 0 system) with
        | SyscallAnswer.Failed error, system -> SetNonBlockingAnswer.Failed error, system
        | SyscallAnswer.Completed word, system ->

        let word =
            if isNonBlocking then
                int word ||| bit
            else
                int word &&& ~~~bit

        match unrefused "F_SETFL" (tryFcntlIn fd FcntlNumbering.SetStatusFlags word system) with
        | SyscallAnswer.Completed _, system -> SetNonBlockingAnswer.Set, system
        | SyscallAnswer.Failed error, system -> SetNonBlockingAnswer.Failed error, system

    /// Set or clear `O_NONBLOCK` on the open file description `fd` names, as
    /// `fcntl(fd, F_GETFL)` and then `fcntl(fd, F_SETFL, word)` with the bit
    /// changed do; the flag is shared with every descriptor naming the
    /// description.
    ///
    /// `EBADF` for a descriptor that is not open. On a Darwin kqueue the flag
    /// is set and the answer is `ENOTTY` (see `SetNonBlockingAnswer.Failed`).
    let setNonBlocking<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (isNonBlocking : bool)
        (system : UnixSystem<'Thread, 'Handler>)
        : SetNonBlockingAnswer * UnixSystem<'Thread, 'Handler>
        =
        Entry.call
            "UnixDescriptor.setNonBlocking"
            CallerRequirement.Running
            caller
            Shape.withSystem
            (setNonBlockingIn fd isNonBlocking)
            system

    /// `isNonBlocking` once `Entry` has admitted its caller.
    let private isNonBlockingIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (system : ProcessView<'Thread, 'Handler>)
        : bool option
        =
        let bit = nonBlockingBit (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)

        match tryFcntlIn fd FcntlNumbering.GetStatusFlags 0 system with
        | Ok (SyscallAnswer.Completed word, _) -> Some (int word &&& bit <> 0)
        | Ok (SyscallAnswer.Failed UnixError.EBADF, _) -> None
        | Ok (SyscallAnswer.Failed error, _) ->
            failwith
                $"UnixDescriptor.isNonBlocking: F_GETFL on fd %d{fd} answered %O{error}, but its only errno is EBADF (this is a bug in this library)."
        | Error refusal ->
            failwith
                $"UnixDescriptor.isNonBlocking: F_GETFL on fd %d{fd} was refused (%s{FcntlRefusal.describe refusal}), but it is a modelled command (this is a bug in this library)."

    /// Whether the open file description `fd` names carries `O_NONBLOCK`, as
    /// `fcntl(fd, F_GETFL)` reports it; `None` for a descriptor that is not
    /// open, which `F_GETFL` answers `EBADF`.
    let isNonBlocking<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : bool option
        =
        Entry.call
            "UnixDescriptor.isNonBlocking"
            CallerRequirement.Running
            caller
            Shape.answer
            (isNonBlockingIn fd)
            system
