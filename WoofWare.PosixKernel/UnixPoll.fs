namespace WoofWare.PosixKernel

/// Why this kernel will not answer a `poll`.
///
/// Distinct from an errno: an errno is an answer, and these are the inputs for
/// which this library has measured what real kernels do and found no single
/// answer to give.
[<RequireQualifiedAccess>]
type internal PollRefusal =
    /// The entry names an event queue, which this kernel does not answer
    /// `poll(2)` for: under Linux an epoll instance, whatever was asked; under
    /// Darwin a kqueue asked for a bit that registers `EVFILT_READ` on it.
    ///
    /// Reachable in a way epoll's equivalent is not: `epoll_ctl` screens the
    /// targets it will accept, and `poll(2)` accepts any descriptor.
    | UnmodelledTarget of fd : int
    /// Under Darwin, the entry asks a socket of a kind whose kqueue filters
    /// this kernel does not model (anything but a stream socket of `AF_INET`
    /// or `AF_INET6`) for a bit that registers one.
    | UnmodelledSocket of fd : int * domain : SocketDomain * kind : SocketKind
    /// Under Linux, the entry names a socket of a kind whose readiness this
    /// kernel does not model, whatever was
    /// asked: `HUP` is reported unasked, so even `events = 0` reads the level.
    ///
    /// That is an `AF_UNIX` `SOCK_SEQPACKET` socket. Its `poll` row is
    /// measured but its epoll one is not, and the two waiters read one level,
    /// so answering `poll` alone would make epoll delivery answer from an
    /// inference.
    | UnmeasuredSocketKind of fd : int * domain : SocketDomain * kind : SocketKind
    /// Under Darwin, nothing is ready and the call would sleep with an
    /// `EVFILT_VNODE` filter registered on the regular file or directory `fd`
    /// names: such a filter reports only when the file changes, which this
    /// kernel does not model.
    | UnmodelledVnodeWait of fd : int
    /// Under Darwin, nothing is ready and the call would sleep with a timeout
    /// of `milliseconds`, which is negative and not -1.
    ///
    /// Darwin waits for ever on -1 alone. By its source it reads any other
    /// timeout as an unsigned count of milliseconds, so -2 would wait about
    /// 49.7 days: no measurement can tell that from waiting for ever, and a
    /// client that advances its clock to the next deadline would reach it at
    /// once.
    | UnmeasuredNegativeTimeout of milliseconds : int
    /// The call has `count` entries, more than `assumedLimit` and no more
    /// than `PollEntryCount.ceiling` of `flavour`, and so whether it fails
    /// with `EINVAL` depends on the process's `RLIMIT_NOFILE` soft limit,
    /// which this kernel does not model: it assumes only that the limit is at
    /// least `assumedLimit`, `SimulatedUnixPlatform.descriptorBound`.
    ///
    /// Measured (`docs/probes/poll-entry-count`, and `poll-darwin.c` section
    /// N): a count above the soft limit fails, and one at or below it does
    /// not, under Linux for every process and under Darwin for one that is
    /// not root. Darwin fails root's only when it also exceeds `FD_SETSIZE`
    /// (1024), so for root this is a count from 1025 to `OPEN_MAX`.
    | UnmodelledEntryCount of flavour : SimulatedUnixFlavour * count : int * assumedLimit : int
    /// Under Darwin, a sleeping call was woken both with something to report
    /// and past its deadline, and has something to report now. Darwin answers
    /// whichever reached the sleeping thread first, which a wake that found
    /// both does not say.
    | EventsBesideDeadline
    /// Nothing is ready, and the timeout ends past the last instant the
    /// machine's monotonic clock (`UnixSystem.nanosecondsSinceBoot`,
    /// an `int64` of nanoseconds) can represent: `nanosecondsSinceBoot` plus
    /// `timeoutMilliseconds` overflows it.
    | DeadlineBeyondClock of nanosecondsSinceBoot : int64 * timeoutMilliseconds : int
    /// The poll was asleep and a signal is pending for the thread, and this
    /// library will not say how the signal ends it.
    | Interruption of SyscallInterruptionRefusal

/// What became of a `poll(2)` this kernel could answer.
[<RequireQualifiedAccess>]
type PollOutcome =
    /// `poll` returned: the `revents` for each entry, in order, raw bits in the
    /// flavour's own `<poll.h>` numbering, and the return value, which counts
    /// the entries carrying anything.
    | Answered of revents : int16 list * count : int
    /// `poll` failed with this errno: `EINVAL` for more entries than any
    /// process's `RLIMIT_NOFILE` lets it name, which is more than 10240 under
    /// Darwin and more than 2147483584 under Linux.
    | Failed of error : UnixError
    /// `poll` did not return. The calling thread is parked, and sleeps until
    /// `UnixWait.wake` wakes it; then
    /// `UnixPoll.finishPoll` finishes the call.
    | WouldBlock of WakeCondition
    /// The call was asleep, and a signal interrupted it. The thread is no
    /// longer parked, and owes a return to user mode
    /// (`UnixSignal.onReturnToUser`), which it makes before any other call:
    /// that return says whether the call fails with `EINTR` or restarts.
    ///
    /// Only a finishing call answers this.
    | Interrupted

/// How many entries a `poll(2)` may name.
[<RequireQualifiedAccess>]
module internal PollEntryCount =
    /// The most entries a `poll(2)` under `flavour` can name and pass the
    /// screen against the process's `RLIMIT_NOFILE`, for the largest limit a
    /// process can have: every count above it fails with `EINVAL`, whatever
    /// the limit.
    let ceiling (flavour : SimulatedUnixFlavour) : int =
        // Measured by `docs/probes/poll-entry-count` and `poll-darwin.c`
        // section N.
        match flavour with
        // The most `fs.nr_open` takes, on aarch64 and x86-64 alike (section
        // C): `setrlimit` refuses a limit above `fs.nr_open` even to root, and
        // a process keeps its limit when `fs.nr_open` is lowered, so no soft
        // limit exceeds the most it ever was. Linux screens nothing else.
        | SimulatedUnixFlavour.Linux -> 2147483584
        // `OPEN_MAX`, which Darwin screens beside the limit.
        | SimulatedUnixFlavour.Darwin -> 10240

    /// The most entries a `poll(2)` under `flavour`, by a process with
    /// `privilege`, passes the screen with whatever its soft limit: Darwin
    /// screens root against the limit only past `FD_SETSIZE` (1024).
    let private limitFree (flavour : SimulatedUnixFlavour) (privilege : CallerPrivilege) (assumedLimit : int) : int =
        // Measured by `docs/probes/poll-entry-count` section D on Darwin
        // 27.0.0, with the soft limit at 256: root's 257, 1023 and 1024 pass
        // and 1025 fails, where uid 501's 257 fails.
        match flavour, privilege with
        | SimulatedUnixFlavour.Darwin, CallerPrivilege.Privileged -> max assumedLimit 1024
        | SimulatedUnixFlavour.Darwin, CallerPrivilege.Unprivileged
        | SimulatedUnixFlavour.Linux, _ -> assumedLimit

    /// The errno a `poll(2)` of `count` entries, by a process with `privilege`,
    /// fails with before it reads any entry, if any; or the refusal, where
    /// that depends on the process's `RLIMIT_NOFILE` soft limit.
    let screen
        (platform : SimulatedUnixPlatform)
        (privilege : CallerPrivilege)
        (count : int)
        : Result<UnixError option, PollRefusal>
        =
        let flavour = SimulatedUnixPlatform.flavour platform
        let assumedLimit = SimulatedUnixPlatform.descriptorBound platform

        if count > ceiling flavour then
            Ok (Some UnixError.EINVAL)
        elif count > limitFree flavour privilege assumedLimit then
            Error (PollRefusal.UnmodelledEntryCount (flavour, count, assumedLimit))
        else
            Ok None

[<RequireQualifiedAccess>]
module internal PollRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point asked, and what it should do instead.
    let describe (refusal : PollRefusal) : string =
        match refusal with
        | PollRefusal.UnmodelledTarget fd ->
            $"fd %d{fd} names an event queue (an epoll instance, or a kqueue asked for a read bit), which this kernel does not answer `poll(2)` for. An event queue's own readiness depends on re-reading what it has queued, and what that leaves queued is unmeasured; model that before answering."
        | PollRefusal.UnmodelledSocket (fd, domain, kind) ->
            $"fd %d{fd} is a %O{kind} socket in %O{domain}, and the entry asks for a bit that registers a kqueue filter on it. This kernel models those filters for IPv4 and IPv6 stream sockets only: what activates a datagram socket's filters is not modelled, and a Unix-domain socket's are not measured."
        | PollRefusal.UnmeasuredSocketKind (fd, domain, kind) ->
            $"fd %d{fd} is a %O{kind} socket in %O{domain}, whose readiness level this kernel does not model. poll(2) and epoll read one level, and only poll's has been measured for this kind (OUT|HUP|WRNORM|WRBAND when fresh); measure what an epoll wait reports for one before answering either."
        | PollRefusal.UnmodelledVnodeWait fd ->
            $"nothing is ready, and the poll would sleep with an EVFILT_VNODE filter registered on fd %d{fd} for a vnode bit (POLLEXTEND, POLLATTRIB, POLLNLINK or POLLWRITE). That filter reports when the file changes, which this kernel does not model."
        | PollRefusal.UnmeasuredNegativeTimeout milliseconds ->
            $"nothing is ready, and the timeout is %d{milliseconds}ms. Darwin waits for ever on -1 alone, and by its source reads any other negative timeout as an unsigned count of milliseconds (about 49.7 days for -2), which no measurement can tell from waiting for ever."
        | PollRefusal.UnmodelledEntryCount (SimulatedUnixFlavour.Linux, count, assumedLimit) ->
            $"the poll has %d{count} entries, more than %d{assumedLimit} and no more than %d{PollEntryCount.ceiling SimulatedUnixFlavour.Linux}, the most fs.nr_open (and so any RLIMIT_NOFILE) can be. Linux answers EINVAL for such a count exactly when it exceeds the process's RLIMIT_NOFILE soft limit, which this kernel does not model: it assumes only that the limit is at least %d{assumedLimit}."
        | PollRefusal.UnmodelledEntryCount (SimulatedUnixFlavour.Darwin, count, assumedLimit) ->
            $"the poll has %d{count} entries, more than %d{assumedLimit} (more than FD_SETSIZE, 1024, for root) and no more than OPEN_MAX (%d{PollEntryCount.ceiling SimulatedUnixFlavour.Darwin}). Darwin answers EINVAL for such a count exactly when it exceeds the process's RLIMIT_NOFILE soft limit (for root, only when it also exceeds 1024), and this kernel does not model the limit: it assumes only that it is at least %d{assumedLimit}."
        | PollRefusal.EventsBesideDeadline ->
            "a thread asleep in poll was woken both with something to report and past its deadline (0), and has something to report now. Darwin answers whichever reached the sleeping thread first, which the wake does not say."
        | PollRefusal.DeadlineBeyondClock (now, timeoutMilliseconds) ->
            $"the machine has been up for %d{now} ns and the timeout is %d{timeoutMilliseconds}ms, which ends past the last nanosecond the monotonic clock can represent. Linux's source saturates such a deadline, making the wait infinite, but that is unmeasured."
        | PollRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : PollRefusal) : RefusalKind =
        match refusal with
        | PollRefusal.UnmodelledTarget _ -> RefusalKind.Unmodelled
        | PollRefusal.UnmodelledSocket _ -> RefusalKind.Unmodelled
        | PollRefusal.UnmeasuredSocketKind _ -> RefusalKind.Unmodelled
        | PollRefusal.UnmodelledVnodeWait _ -> RefusalKind.Unmodelled
        | PollRefusal.UnmeasuredNegativeTimeout _ -> RefusalKind.Unmodelled
        | PollRefusal.UnmodelledEntryCount _ -> RefusalKind.Unmodelled
        | PollRefusal.EventsBesideDeadline -> RefusalKind.Unmodelled
        | PollRefusal.DeadlineBeyondClock _ -> RefusalKind.Unmodelled
        | PollRefusal.Interruption inner -> SyscallInterruptionRefusal.kind inner

/// The flags `epoll_create1(2)` accepts, in Linux's numbering.
[<RequireQualifiedAccess>]
module EpollCreateFlags =
    /// `EPOLL_CLOEXEC`: give the new descriptor `FD_CLOEXEC`. The same value
    /// as `O_CLOEXEC`.
    [<Literal>]
    let CloseOnExec : int = OpenFlagNumbering.LinuxCloseOnExec

/// Why this kernel will not answer an `epoll_create1(2)`.
[<RequireQualifiedAccess>]
type internal EpollCreateRefusal =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// This kernel is not Linux-flavoured, and only Linux has epoll.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal EpollCreateRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which of its entry points asked.
    let describe (refusal : EpollCreateRefusal) : string =
        match refusal with
        | EpollCreateRefusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | EpollCreateRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and epoll_create1 exists on Linux only. This flavour's counterpart is kqueue (UnixKqueue.kqueue)."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : EpollCreateRefusal) : RefusalKind =
        match refusal with
        | EpollCreateRefusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | EpollCreateRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform

/// What became of an `epoll_wait(2)` this kernel could answer.
[<RequireQualifiedAccess>]
type EpollWaitOutcome =
    /// `epoll_wait` failed with this errno.
    ///
    /// The call as first made changes nothing when it fails. A finishing call
    /// never fails: a signal interrupts it (`Interrupted`), and what its walk
    /// of the epoll instance consumed stays consumed.
    | Failed of error : UnixError
    /// `epoll_wait` returned these events, in delivery order: each the
    /// registration's `data` and the `events` written for it, in Linux's
    /// `<sys/epoll.h>` numbering (`EpollEvents`). Empty when the call timed
    /// out, or had a timeout of 0 and found nothing.
    | Answered of events : (uint64 * uint32) list
    /// `epoll_wait` did not return. The calling thread is parked, and sleeps
    /// until `UnixWait.satisfied` of the thread is non-empty and
    /// `UnixWait.wake` wakes it; then `UnixPoll.finishEpollWait` finishes the
    /// call.
    | WouldBlock of WakeCondition
    /// The call was asleep, and a signal interrupted it. The thread is no
    /// longer parked, and owes a return to user mode
    /// (`UnixSignal.onReturnToUser`), which it makes before any other call:
    /// that return says whether the call fails with `EINTR` or restarts.
    ///
    /// Only a finishing call answers this.
    | Interrupted

/// Why this kernel will not answer an `epoll_wait(2)`.
[<RequireQualifiedAccess>]
type internal EpollWaitRefusal =
    /// This kernel is not Linux-flavoured, and only Linux has epoll.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// The buffer reached the up-front address screen and has no address to
    /// screen.
    | Buffer of BufferRefusal
    /// The wait has events to deliver, and the buffer is unmapped, so copying
    /// them out faults.
    ///
    /// Linux answers EFAULT only when the first event's copy faults, and a
    /// real buffer can be partly mapped; which of the walked entries stay
    /// pending after a fault is unmeasured.
    | UnmeasuredCopyOutFault of epoll : OpenFileDescriptionId
    /// Nothing is deliverable, and the timeout ends past the last instant the
    /// machine's monotonic clock (`UnixSystem.nanosecondsSinceBoot`, an
    /// `int64` of nanoseconds) can represent: `nanosecondsSinceBoot` plus
    /// `timeoutMilliseconds` overflows it.
    | DeadlineBeyondClock of nanosecondsSinceBoot : int64 * timeoutMilliseconds : int
    /// The wait was asleep and a signal is pending for the thread, and this
    /// library will not say how the signal ends it.
    | Interruption of SyscallInterruptionRefusal

[<RequireQualifiedAccess>]
module internal EpollWaitRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point asked, and what it actually passed.
    let describe (refusal : EpollWaitRefusal) : string =
        match refusal with
        | EpollWaitRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and epoll_wait exists on Linux only. This flavour's counterpart is kevent (UnixKqueue.kevent)."
        | EpollWaitRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | EpollWaitRefusal.UnmeasuredCopyOutFault epoll ->
            $"the epoll instance %O{epoll} has events to deliver, so this call copies them out -- but the buffer is unmapped, so that copy faults. Which of the events the walk took stay pending after the fault, and whether the call answers EFAULT or the count copied before it, are unmeasured."
        | EpollWaitRefusal.DeadlineBeyondClock (now, timeoutMilliseconds) ->
            $"the machine has been up for %d{now} ns and the timeout is %d{timeoutMilliseconds}ms, which ends past the last nanosecond the monotonic clock can represent. Linux's source saturates such a deadline, making the wait infinite, but that is unmeasured."
        | EpollWaitRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : EpollWaitRefusal) : RefusalKind =
        match refusal with
        | EpollWaitRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | EpollWaitRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | EpollWaitRefusal.UnmeasuredCopyOutFault _ -> RefusalKind.Unmodelled
        | EpollWaitRefusal.DeadlineBeyondClock _ -> RefusalKind.Unmodelled
        | EpollWaitRefusal.Interruption inner -> SyscallInterruptionRefusal.kind inner

/// The `event` argument of `epoll_ctl(2)`, as the kernel's copy-in finds it.
///
/// The caller classifies it, because only the caller knows what its memory
/// holds; the consequence is the kernel's, which is `EFAULT` for any operation
/// but `EPOLL_CTL_DEL` (which never reads it) ahead of every other check.
[<RequireQualifiedAccess>]
type EpollEventArgument =
    /// The pointer names a whole readable `struct epoll_event`, holding these.
    /// `events` is in Linux's `<sys/epoll.h>` numbering (`EpollEvents`), and
    /// may carry any bits: `epoll_ctl` rejects none of them outright.
    | Readable of events : uint32 * data : uint64
    /// The pointer is null, or does not name a whole readable
    /// `struct epoll_event`.
    | Unreadable

/// Why `epoll_ctl(2)` failed, in the order Linux decides them.
///
/// Measured on Linux 6.18.5 by `epoll-ctl.c`
/// (docs/plans/2026-08-23-posix-kernel-extraction), which tried every
/// combination of seven kinds of `epfd`, fourteen kinds of target, nine
/// operation values, a null and a real event pointer, and 36 event masks;
/// each adjacent pair below is separated by an input that provokes exactly one
/// of the two.
[<RequireQualifiedAccess>]
type EpollCtlError =
    /// The event could not be read, for an operation that reads one (every
    /// operation value but `EPOLL_CTL_DEL`, including unrecognised ones);
    /// `EFAULT`. First of everything.
    | EventUnreadable
    /// `epfd` is not a live descriptor; `EBADF`.
    | BadEpollFd
    /// The target fd is not a live descriptor; `EBADF`.
    | BadTargetFd
    /// The target supports no poll -- a regular file or a directory; `EPERM`.
    /// Ahead of the not-an-epoll-instance check, so a file as both epoll instance and target is
    /// `EPERM`.
    | TargetNotPollable
    /// `epfd` is not an epoll instance, or `epfd` and the target name the same
    /// open file description (a `dup` of the epoll instance included); `EINVAL`.
    | NotAnEpollInstance
    /// The event carries `EPOLLEXCLUSIVE` where it is not permitted: on
    /// `EPOLL_CTL_MOD`, or on `EPOLL_CTL_ADD` with an epoll instance as the
    /// target or with any bit outside `EPOLLIN`, `EPOLLOUT`, `EPOLLERR`,
    /// `EPOLLHUP`, `EPOLLWAKEUP`, `EPOLLET` and `EPOLLEXCLUSIVE` itself;
    /// `EINVAL`. Ahead of the table, so it wins over `EEXIST` and `ENOENT`.
    | ExclusiveNotPermitted
    /// `EPOLL_CTL_ADD` of a target already registered; `EEXIST`.
    | AlreadyRegistered
    /// `EPOLL_CTL_MOD` or `EPOLL_CTL_DEL` of a target not registered;
    /// `ENOENT`.
    | NotRegistered
    /// The operation is none of `EPOLL_CTL_ADD`, `EPOLL_CTL_DEL` and
    /// `EPOLL_CTL_MOD`; `EINVAL`. Last: every check above still applies to
    /// it, the copy-in included.
    | UnrecognisedOperation

[<RequireQualifiedAccess>]
module EpollCtlError =
    /// The errno `epoll_ctl(2)` answers for this failure.
    ///
    /// Not injective: two failures share `EBADF` and three share `EINVAL`, so a
    /// client wanting to know *which* keeps the case.
    let toErrno (error : EpollCtlError) : UnixError =
        match error with
        | EpollCtlError.EventUnreadable -> UnixError.EFAULT
        | EpollCtlError.BadEpollFd
        | EpollCtlError.BadTargetFd -> UnixError.EBADF
        | EpollCtlError.TargetNotPollable -> UnixError.EPERM
        | EpollCtlError.NotAnEpollInstance
        | EpollCtlError.ExclusiveNotPermitted
        | EpollCtlError.UnrecognisedOperation -> UnixError.EINVAL
        | EpollCtlError.AlreadyRegistered -> UnixError.EEXIST
        | EpollCtlError.NotRegistered -> UnixError.ENOENT

/// What `epoll_ctl(2)` answered.
[<RequireQualifiedAccess>]
type EpollCtlAnswer =
    /// Applied. The system this rides with carries the new interest table, and
    /// the ready list if the change made the target pending.
    | Changed
    /// `epoll_ctl(2)` failed. Nothing changed: the system comes back as it
    /// was.
    | Failed of reason : EpollCtlError

/// Why this kernel will not answer an `epoll_ctl(2)`.
///
/// Distinct from a `Failed` answer: that is `epoll_ctl(2)` refusing, and this is
/// this library having nothing to say. Every refusal but `UnmodelledFlavour`
/// is given only where the real call would succeed, having passed every check
/// that could fail it; so a call that would fail is answered with its failure
/// whatever it asks for.
[<RequireQualifiedAccess>]
type internal EpollCtlRefusal =
    /// This kernel is not Linux-flavoured, and only Linux has epoll.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// An `EPOLL_CTL_ADD` whose target is itself an epoll instance.
    ///
    /// Linux accepts one, subject to a loop check and a nesting depth of at
    /// most four epoll instances (`ELOOP` beyond either). This library does not model
    /// what a nested epoll instance reports or how a wake propagates through it.
    | NestedEpoll of targetFd : int
    /// The event carries `EPOLLEXCLUSIVE`, which changes which of several epoll instances
    /// on one target a wake reaches. This library's wakes reach every epoll instance.
    | Exclusive
    /// The event carries `EPOLLONESHOT`, which disarms the registration once it
    /// has reported. This library's registrations stay armed.
    | OneShot
    /// The event carries `EPOLLWAKEUP`. The kernel keeps it only for a caller
    /// with `CAP_BLOCK_SUSPEND` on a kernel built with power management, and
    /// silently clears it otherwise; this library models neither.
    | WakeUp
    /// The event lacks `EPOLLET`, asking to be level-triggered. This library's epoll
    /// models edge-triggered registrations only: a wait consumes every entry it
    /// walks and never re-arms a still-ready one, so a wait after a partly
    /// drained level would sleep where a real `epoll_wait` returns again.
    | LevelTriggered
    /// An `EPOLL_CTL_ADD` whose target is an end of a pipe the process made.
    /// An edge-triggered registration reports what the pipe's own wakes
    /// signal, and which transfers and closes signal a pipe's waiters, and with
    /// which events, is not measured.
    | PipeTarget of targetFd : int
    /// An `EPOLL_CTL_ADD` whose target is a socket of a kind whose readiness
    /// this kernel does not model: an
    /// `AF_UNIX` `SOCK_SEQPACKET` socket, which Linux registers. What a wait
    /// reports for one is unmeasured.
    | UnmeasuredSocketKind of targetFd : int * domain : SocketDomain * kind : SocketKind

[<RequireQualifiedAccess>]
module internal EpollCtlRefusal =
    /// What this kernel knows about why it will not answer. The client supplies
    /// its own half -- which of its entry points was asked, and on whose
    /// behalf.
    let describe (refusal : EpollCtlRefusal) : string =
        match refusal with
        | EpollCtlRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and epoll_ctl exists on Linux only. This flavour's counterpart is a kevent changelist (UnixKqueue.kevent)."
        | EpollCtlRefusal.NestedEpoll targetFd ->
            $"fd %d{targetFd} is itself an epoll instance. Linux would register it (subject to a loop check and a nesting depth of four, both ELOOP), but what a nested epoll instance reports and how a wake propagates through one are not modelled."
        | EpollCtlRefusal.Exclusive ->
            "the event carries EPOLLEXCLUSIVE, and the registration would succeed. An exclusive registration changes which of several epoll instances on one target a wake reaches, and this library's wakes reach every epoll instance. Model wake-one delivery before answering."
        | EpollCtlRefusal.OneShot ->
            "the event carries EPOLLONESHOT, and the registration would succeed. A one-shot registration disarms once it has reported until a MOD re-arms it, and this library's registrations stay armed. Model disarming before answering."
        | EpollCtlRefusal.WakeUp ->
            "the event carries EPOLLWAKEUP, and the registration would succeed. The kernel keeps the bit only for a caller with CAP_BLOCK_SUSPEND on a kernel built with power management, clearing it silently otherwise, and this library models neither capabilities nor wakeup sources."
        | EpollCtlRefusal.PipeTarget targetFd ->
            $"fd %d{targetFd} is an end of a pipe the process made, and the registration would succeed. An edge-triggered registration is made pending by the wakes its target signals, and which reads, writes and closes signal a pipe's waiters, with which events, is unmeasured: Linux's pipe_write, for one, wakes readers on every write once a waiter has polled the pipe, not only on the write that makes it non-empty. poll(2) on a pipe is answered; measure the pipe's wakes before registering one."
        | EpollCtlRefusal.UnmeasuredSocketKind (targetFd, domain, kind) ->
            $"fd %d{targetFd} is a %O{kind} socket in %O{domain}, and the registration would succeed. What an epoll wait reports for this kind is unmeasured: only poll(2)'s level is (OUT|HUP|WRNORM|WRBAND when fresh), and the two waiters read one level, which this kernel will not infer from one of them. Measure an epoll wait on one before registering it."
        | EpollCtlRefusal.LevelTriggered ->
            "the event lacks EPOLLET, asking to be level-triggered, and the registration would succeed. This library's epoll models edge-triggered registrations only: the ready list is consumed as it is drained and a still-ready entry is never re-armed, so a wait after a partly drained level would sleep where a real epoll_wait returns again. Register with EPOLLET, or model level-triggering before answering."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : EpollCtlRefusal) : RefusalKind =
        match refusal with
        | EpollCtlRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | EpollCtlRefusal.NestedEpoll _ -> RefusalKind.Unmodelled
        | EpollCtlRefusal.Exclusive -> RefusalKind.Unmodelled
        | EpollCtlRefusal.OneShot -> RefusalKind.Unmodelled
        | EpollCtlRefusal.WakeUp -> RefusalKind.Unmodelled
        | EpollCtlRefusal.LevelTriggered -> RefusalKind.Unmodelled
        | EpollCtlRefusal.PipeTarget _ -> RefusalKind.Unmodelled
        | EpollCtlRefusal.UnmeasuredSocketKind _ -> RefusalKind.Unmodelled

[<RequireQualifiedAccess>]
module UnixPoll =

    /// `epoll_wait(2)`'s four screens, in Linux's order: the epoll instance to
    /// wait on, an errno to fail with, or the buffer's refusal.
    ///
    /// The order is measured on Linux 6.18.5 rather than read off the kernel
    /// source: the widely-reproduced `do_epoll_wait` listing checks `maxevents`
    /// and `access_ok` *before* `fdget`, and current kernels do not.
    ///
    /// Changes nothing: everything a wait does before it reaches the instance
    /// is a question.
    let private admitEpollWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (maxEvents : int)
        (buffer : UserBuffer)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<Result<OpenFileDescriptionId, UnixError>, BufferRefusal>
        =
        // Measured on 6.18.5, each adjacent pair separated by an input that
        // provokes exactly one of the two: descriptor, then `maxevents`, then
        // the buffer, then is-it-an-epoll-instance.
        match FileDescriptorRegistry.tryFindWithId fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (Error UnixError.EBADF)
        | Some (epoll, description) ->

        let architecture = SimulatedUnixPlatform.architecture system.Machine.UnixPlatform

        // The kernel's predicate is `maxevents <= 0 || maxevents > EP_MAX_EVENTS`.
        // Measured (`epoll-wait.c`, section G): a negative maxevents is
        // screened exactly as zero is.
        if maxEvents <= 0 || maxEvents > LinuxEpollLimits.maxEvents architecture then
            Ok (Error UnixError.EINVAL)
        else

        // The byte range `access_ok(events, maxevents * sizeof(struct
        // epoll_event))` screens. This multiplication is safe only *below* the
        // cap just applied, which is what `EP_MAX_EVENTS` exists for: it is
        // `INT_MAX / eventSize`, so every count that reaches here has a product
        // inside `int32`.
        let bufferExtent =
            uint64 maxEvents * uint64 (LinuxEpollLimits.eventSize architecture)

        // Not a mappedness check. On 64-bit Linux `access_ok` only rejects
        // ranges reaching into the kernel half, so a merely-unmapped userspace
        // address passes and the wait then blocks, faulting at delivery --
        // which is why this must not eagerly demand that the buffer be real
        // before sleeping.
        match
            UserBufferCheck.faultsBeforeOperationFor
                (UnixMachineState.userBufferCheck system.Machine)
                buffer
                bufferExtent
        with
        | Error refusal -> Error refusal
        | Ok true -> Ok (Error UnixError.EFAULT)
        | Ok false ->

        match description.Target with
        | OpenFileTarget.File _
        | OpenFileTarget.Directory _
        | OpenFileTarget.Socket _
        | OpenFileTarget.CharacterDevice _
        | OpenFileTarget.Fifo _
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Pipe _ ->
            // A live descriptor onto the wrong kind of object. EINVAL is epoll's
            // own answer for it, and it is the last of the four screens --
            // behind the buffer, which is why an unmappable buffer on a
            // non-epoll descriptor is EFAULT rather than this.
            //
            // A socket is measured to be exactly like the other two here rather
            // than assumed to be: `epoll_wait` on a socket fd is EINVAL, and
            // EFAULT still wins ahead of it for an unmappable buffer.
            Ok (Error UnixError.EINVAL)
        | OpenFileTarget.Kqueue _ ->
            failwith
                $"UnixPoll.epollWait: fd %d{fd} names a kqueue, which a Linux-flavoured kernel cannot hold (this is a bug in the caller's state construction)."
        | OpenFileTarget.Epoll _ -> Ok (Ok epoll)

    /// `tryEpollCtl` once `Entry` has admitted its caller.
    let private tryEpollCtlIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (epfd : int)
        (op : int)
        (fd : int)
        (event : EpollEventArgument)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<EpollCtlAnswer * ProcessView<'Thread, 'Handler>, EpollCtlRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (EpollCtlRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        let failed (error : EpollCtlError) =
            Ok (EpollCtlAnswer.Failed error, system)

        // Linux's `EPOLL_CTL_*` values.
        let add = 1
        let del = 2
        let modify = 3

        // Measured on 6.18.5 (`epoll-ctl.c`), each step separated from the
        // next by an input that provokes exactly one of the two. The copy-in
        // comes first, and is skipped for DEL alone: an unrecognised op reads
        // the event too.
        let readEvent =
            if op = del then
                Ok (0u, 0UL)
            else
                match event with
                | EpollEventArgument.Readable (events, data) -> Ok (events, data)
                | EpollEventArgument.Unreadable -> Error ()

        match readEvent with
        | Error () -> failed EpollCtlError.EventUnreadable
        | Ok (events, data) ->

        let registry = UnixSystemState.fileDescriptors system

        match FileDescriptorRegistry.tryFindWithId epfd registry with
        | None -> failed EpollCtlError.BadEpollFd
        | Some (epollId, epollDescription) ->

        match FileDescriptorRegistry.tryFindWithId fd registry with
        | None -> failed EpollCtlError.BadTargetFd
        | Some (targetId, targetDescription) ->

        // `file_can_poll`: the target must have a `->poll` handler, which a
        // regular file and a directory lack.
        match targetDescription.Target with
        | OpenFileTarget.File _
        | OpenFileTarget.Directory _
        // Measured on `/dev/null` and `/dev/urandom` for ADD and MOD, through
        // descriptors opened for reading and for writing (`devices.c`, EPOLL
        // rows): neither driver has a poll operation either.
        | OpenFileTarget.CharacterDevice _ -> failed EpollCtlError.TargetNotPollable
        | OpenFileTarget.Kqueue _ ->
            failwith
                $"UnixPoll.epollCtl: fd %d{fd} names a kqueue, which a Linux-flavoured kernel cannot hold (this is a bug in the caller's state construction)."
        | OpenFileTarget.Fifo (inode, _) -> ReservedFifo.fail "UnixPoll.epollCtl" inode
        | OpenFileTarget.Epoll _
        // Measured (`inotify-probe.c` section P): an ADD of an inotify
        // instance succeeds.
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Socket _
        | OpenFileTarget.Pipe _ ->

        // One kernel test, `f.file == tf.file || !is_file_epoll(f.file)`, so
        // one answer: a `dup` of the epoll instance as target is this, not success.
        let epollState =
            match epollDescription.Target with
            | OpenFileTarget.Epoll epollState when epollId <> targetId -> Some epollState
            | OpenFileTarget.Epoll _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.Socket _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _ -> None

        match epollState with
        | None -> failed EpollCtlError.NotAnEpollInstance
        | Some epollState ->

        let targetIsEpoll =
            match targetDescription.Target with
            | OpenFileTarget.Epoll _ -> true
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.Socket _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _ -> false

        // The EPOLLEXCLUSIVE screen, ahead of the table (so ahead of EEXIST
        // and ENOENT) and applied to ADD and MOD only: 20000 random masks for
        // each of six (op, table state) rows found no exception to it.
        let exclusivePermitted =
            EpollEvents.In
            ||| EpollEvents.Out
            ||| EpollEvents.Err
            ||| EpollEvents.Hup
            ||| EpollEvents.WakeUp
            ||| EpollEvents.EdgeTriggered
            ||| EpollEvents.Exclusive

        let exclusive = events &&& EpollEvents.Exclusive <> 0u

        if
            exclusive
            && (op = modify
                || op = add && (targetIsEpoll || events &&& ~~~exclusivePermitted <> 0u))
        then
            failed EpollCtlError.ExclusiveNotPermitted
        // Where Linux runs its loop and depth checks, which cannot fail on any
        // table this library builds (it never holds a nested epoll instance) but which
        // precede EEXIST in the kernel.
        elif op = add && targetIsEpoll then
            Error (EpollCtlRefusal.NestedEpoll fd)
        else

        let key = fd, targetId
        let registered = Map.containsKey key epollState.Registrations

        // The modes this library's epoll does not model, refused only where the call
        // would otherwise commit.
        let unmodelledMode : EpollCtlRefusal option =
            if exclusive then
                Some EpollCtlRefusal.Exclusive
            elif events &&& EpollEvents.OneShot <> 0u then
                Some EpollCtlRefusal.OneShot
            elif events &&& EpollEvents.WakeUp <> 0u then
                Some EpollCtlRefusal.WakeUp
            elif events &&& EpollEvents.EdgeTriggered = 0u then
                Some EpollCtlRefusal.LevelTriggered
            else
                None

        // `epoll_ctl` forces these two into every stored mask (measured through
        // `/proc/self/fdinfo`, `fdinfo.c`).
        let stored = events ||| EpollEvents.Err ||| EpollEvents.Hup

        // An ADD or MOD whose target is ready under the new mask makes the
        // registration pending at that moment (measured rows E, I and K), and
        // a MOD of an entry already pending leaves its place alone (row L).
        let pendIfReady (system : ProcessView<'Thread, 'Handler>) : ProcessView<'Thread, 'Handler> =
            let alreadyPending = List.contains key epollState.Ready

            // The ADD's or MOD's poll of the target (`LinuxReadiness.polled`).
            let polled = LinuxReadiness.polled targetId system

            if
                not alreadyPending
                && LinuxReadiness.ofDescription targetId system &&& stored <> 0u
            then
                UnixSystemState.mapOpenFiles (OpenFileTable.appendEpollReady epollId key) polled
            else
                polled

        // A pipe the process was launched with is answered: its far end is the
        // client's, so every wake it can signal is one this kernel knows. The
        // read end of a pipe the client supplies is woken by the client's
        // write into the pipe a read emptied, and by its close, which
        // `UnixReadWrite.read` signals (measured, supplied-pipe-epoll.c);
        // once the client has closed, nothing wakes it, since a read wakes the
        // read end's waiters only after it slept, and none here does (measured
        // there too: reads of a pipe whose writer had closed woke nothing). A
        // drained pipe's read end is the client's, and its write end is woken
        // only by the client's drain of a write that filled it, which
        // `UnixReadWrite.write` signals (measured, drained-pipe-epoll.c). A
        // pipe whose reader was gone before the process started never changes:
        // nothing is ever taken into it or out of it.
        let targetIsPipe =
            match targetDescription.Target with
            | OpenFileTarget.Pipe (pipeId, _) ->
                match (UnixMachineState.pipe pipeId system.Machine).Origin with
                | PipeOrigin.Made _ -> true
                | PipeOrigin.Launched _ -> false
            | OpenFileTarget.File _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Directory _
            | OpenFileTarget.Socket _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.Epoll _ -> false

        // A socket whose readiness this kernel does not model is refused at
        // the commit, as a made pipe is.
        let unmodelledSocket : EpollCtlRefusal option =
            match targetDescription.Target with
            | OpenFileTarget.Socket socketId ->
                let socket = UnixMachineState.socket socketId system.Machine

                if LinuxReadiness.modelsSocket socket then
                    None
                else
                    Some (EpollCtlRefusal.UnmeasuredSocketKind (fd, socket.Domain, socket.Kind))
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.Epoll _ -> None

        if op = add then
            if registered then
                failed EpollCtlError.AlreadyRegistered
            else

            match unmodelledMode with
            | Some refusal -> Error refusal
            | None ->

            if targetIsPipe then
                Error (EpollCtlRefusal.PipeTarget fd)
            else

            match unmodelledSocket with
            | Some refusal -> Error refusal
            | None ->

            let ordinal = system.Machine.NextEventRegistrationOrdinal

            let registration =
                {
                    Events = stored
                    Data = data
                    RegisteredAt = ordinal
                }

            let system =
                { system with
                    Machine =
                        { system.Machine with
                            NextEventRegistrationOrdinal = ordinal + 1L
                        }
                }
                |> UnixSystemState.mapOpenFiles (OpenFileTable.addEpollRegistration epollId key registration)

            Ok (EpollCtlAnswer.Changed, pendIfReady system)
        elif op = del then
            if registered then
                Ok (
                    EpollCtlAnswer.Changed,
                    UnixSystemState.mapOpenFiles (OpenFileTable.removeEpollRegistration epollId key) system
                )
            else
                failed EpollCtlError.NotRegistered
        elif op = modify then
            if not registered then
                failed EpollCtlError.NotRegistered
            else

            match unmodelledMode with
            | Some refusal -> Error refusal
            | None ->

            // No stored mask here carries EPOLLEXCLUSIVE, whose MOD the kernel
            // would answer EINVAL, because an exclusive ADD is refused.
            let system =
                UnixSystemState.mapOpenFiles (OpenFileTable.modifyEpollRegistration epollId key stored data) system

            Ok (EpollCtlAnswer.Changed, pendIfReady system)
        else
            failed EpollCtlError.UnrecognisedOperation

    /// `epollCtl`, with a refusal answered as the `Error` rather than raised.
    let internal tryEpollCtl<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (epfd : int)
        (op : int)
        (fd : int)
        (event : EpollEventArgument)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<EpollCtlAnswer * UnixSystem<'Thread, 'Handler>, EpollCtlRefusal>
        =
        Entry.call
            "UnixPoll.epollCtl"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryEpollCtlIn epfd op fd event)
            system

    /// <summary>
    /// `epoll_ctl(2)`: apply `op` to the interest table of the epoll instance
    /// `epfd` names, for the target `fd` names, with the `event` the caller
    /// passed.
    ///
    /// `op` is the raw operation value, in Linux's numbering: `EPOLL_CTL_ADD`
    /// is 1, `EPOLL_CTL_DEL` 2 and `EPOLL_CTL_MOD` 3, and every other value is
    /// answered as Linux answers it. `event` is what the kernel's copy-in finds
    /// (see `EpollEventArgument`); it is not read for `EPOLL_CTL_DEL`.
    ///
    /// Under the Linux flavour every failure is answered, in Linux's order (see
    /// `EpollCtlError`), and so is every `EPOLL_CTL_DEL` and every `ADD` or
    /// `MOD` of an edge-triggered registration without `EPOLLEXCLUSIVE`,
    /// `EPOLLONESHOT` or `EPOLLWAKEUP`, whatever other bits it carries. The
    /// registration stores the caller's `events` with `EPOLLERR` and `EPOLLHUP`
    /// added, and a wait reports the target's readiness masked by that; an
    /// `ADD` or `MOD` whose target is ready under the new
    /// mask makes the registration pending at once, and a `MOD` of an entry
    /// already pending leaves its place alone. An `ADD` or `MOD` that would
    /// succeed with one of the modes this library does not model, and an
    /// `ADD` of another epoll instance, are refused.
    /// Under the Darwin flavour every call is refused: Darwin has no epoll.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Linux-flavoured, and only Linux has epoll.</exception>
    let epollCtl<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (epfd : int)
        (op : int)
        (fd : int)
        (event : EpollEventArgument)
        (system : UnixSystem<'Thread, 'Handler>)
        : EpollCtlAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryEpollCtl caller epfd op fd event system
        |> Refusal.orRaise "UnixPoll.epollCtl" EpollCtlRefusal.kind EpollCtlRefusal.describe

    // Linux's `<poll.h>` numbering: the bits a Linux-flavoured `poll(2)` reads
    // in `events` and writes in `revents`.
    //
    // Measured 2026-09-23 on Linux 6.18.5 aarch64 (glibc 2.41) by
    // `docs/plans/2026-08-23-posix-kernel-extraction/poll-alphabet.c`, which
    // printed the header and then polled every object and state
    // `LinuxReadiness.ofDescription` answers for with all 65536 request masks
    // at timeout 0. On every object, every answer was `level & (events |
    // POLLERR | POLLHUP)` and `rv` counted exactly the entries with a non-zero
    // `revents`; a descriptor that is not open answered `POLLNVAL` alone to all
    // 65536; no request failed.
    //
    // No modelled object presents `POLLPRI`, `POLLRDBAND` or `POLLMSG`.
    // `POLLREMOVE` (0x1000), the unassigned
    // 0x0800 and the kernel-internal 0x4000 and 0x8000 were never reported
    // either, which is the shape of `do_pollfd`: it reads a request through
    // `demangle_poll`, which maps only the named bits other than `POLLREMOVE`,
    // so the rest never reach the filter the level is masked by. That held
    // for 0x8000 even on a socket with `SO_BUSY_POLL` set, the one case in
    // which a socket's own poll handler adds that bit to its mask.
    let private linuxPollErr : int16 = 0x0008s
    let private linuxPollHup : int16 = 0x0010s
    let private linuxPollNval : int16 = 0x0020s

    /// What `entry` reports right now under the Linux flavour, as `do_pollfd`
    /// computes it: by looking its descriptor up afresh.
    let private reportOne<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        (entry : PollEntry)
        : Result<int16, PollRefusal>
        =
        if entry.Fd < 0 then
            // Measured on both kernels: a negative descriptor is ignored,
            // reports nothing, and does not count towards the return value.
            // It is not an error and not NVAL.
            Ok 0s
        else

        match FileDescriptorRegistry.tryFindWithId entry.Fd (UnixSystemState.fileDescriptors system) with
        | None ->
            // POLLNVAL is a statement about the entry, not a readiness
            // level: measured, it is reported alone, whatever was asked
            // for, `events = 0` included.
            Ok linuxPollNval
        | Some (descriptionId, description) ->

        // `do_pollfd`'s own shape: the level, filtered by the request with
        // POLLERR and POLLHUP added whatever was asked. The level's bits all
        // lie below 0x10000, where `<poll.h>` and `<sys/epoll.h>` share their
        // numbering.
        let answer () : int16 =
            int16 (LinuxReadiness.ofDescription descriptionId system)
            &&& (entry.Events ||| linuxPollErr ||| linuxPollHup)

        match description.Target with
        // Measured on Linux (`poll-alphabet.c`): POLLIN|POLLRDNORM when an
        // event is deliverable, nothing otherwise, under the same
        // `level & (events | POLLERR | POLLHUP)` rule. Refused anyway,
        // because the kernel computes that level by re-polling the ready
        // list, and whether the walk drops a stale entry, as `drain` does,
        // is unmeasured.
        | OpenFileTarget.Kqueue _
        | OpenFileTarget.Epoll _ -> Error (PollRefusal.UnmodelledTarget entry.Fd)
        | OpenFileTarget.Socket socketId ->
            let socket = UnixMachineState.socket socketId system.Machine

            if LinuxReadiness.modelsSocket socket then
                Ok (answer ())
            else
                // Refused whatever was asked: `HUP` is reported unasked, so
                // even `events = 0` reads the level.
                Error (PollRefusal.UnmeasuredSocketKind (entry.Fd, socket.Domain, socket.Kind))
        | OpenFileTarget.File _
        | OpenFileTarget.Directory _
        | OpenFileTarget.CharacterDevice _
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Pipe _ -> Ok (answer ())
        // Measured to differ from a pipe's: no POLLHUP for a reader until a
        // writer has opened.
        | OpenFileTarget.Fifo (inode, _) -> ReservedFifo.fail "UnixPoll.poll" inode

    /// Every entry's report, in list order, stopping at the first entry that
    /// cannot be answered: a real `poll` inspects its entries in order, so that
    /// is the entry a refusal names.
    let private scan<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : ProcessView<'Thread, 'Handler>)
        (entries : PollEntry list)
        : Result<int16 list * int, PollRefusal>
        =
        let rec report (remaining : PollEntry list) (acc : int16 list) : Result<int16 list, PollRefusal> =
            match remaining with
            | [] -> Ok (List.rev acc)
            | entry :: rest ->
                match reportOne system entry with
                | Error refusal -> Error refusal
                | Ok events -> report rest (events :: acc)

        match report entries [] with
        | Error refusal -> Error refusal
        | Ok reported ->
            let triggered =
                reported |> List.filter (fun revents -> revents <> 0s) |> List.length

            Ok (reported, triggered)

    /// What a Linux `poll` of `entries` does besides reporting: each open
    /// descriptor's target is polled (`LinuxReadiness.polled`).
    let private polledEntries<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (entries : PollEntry list)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        (system, entries)
        ||> List.fold (fun system entry ->
            if entry.Fd < 0 then
                system
            else
                match FileDescriptorRegistry.tryFindId entry.Fd (UnixSystemState.fileDescriptors system) with
                | Some description -> LinuxReadiness.polled description system
                | None -> system
        )

    let private nanosecondsPerMillisecond : int64 = 1_000_000L

    /// The deadline a relative timeout of `milliseconds` sets at `now`, as both
    /// `poll(2)` and `epoll_wait(2)` read one: `None` for a negative timeout,
    /// which is infinite; and an `Error` for a positive one whose deadline the
    /// clock cannot represent.
    ///
    /// Measured (`poll-timeout.c` and `epoll-wait.c`): Linux turns a timeout of
    /// `ms` into a deadline `ms` milliseconds from now on the monotonic clock,
    /// and never returns before it; every negative timeout is infinite.
    /// Returning at the deadline is this library's answer; a real wait returns
    /// at or a little after it.
    ///
    /// Must not be asked of a timeout of 0, which never sleeps at all.
    let private relativeDeadline (now : int64) (milliseconds : int) : Result<int64 option, unit> =
        if milliseconds = 0 then
            failwith
                "UnixPoll.relativeDeadline: a timeout of 0 answers at once and sets no deadline (this is a bug in this library)."
        elif milliseconds < 0 then
            Ok None
        else
            let timeout = int64 milliseconds * nanosecondsPerMillisecond

            // Linux saturates such a deadline and so waits for ever, by reading
            // of its source rather than by measurement, which would take 292
            // years of uptime; so the caller refuses rather than answers.
            if now > System.Int64.MaxValue - timeout then
                Error ()
            else
                Ok (Some (now + timeout))

    /// A Linux-flavoured `poll(2)`, after the parked-thread check: see `poll`.
    let private linuxPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<PollOutcome * ProcessView<'Thread, 'Handler>, PollRefusal>
        =
        // Measured (`docs/probes/poll-entry-count`, section A): ahead of the
        // scan, and of the timeout.
        match
            PollEntryCount.screen
                system.Machine.UnixPlatform
                (UnixProcessState.callerPrivilege system.Process)
                (List.length entries)
        with
        | Error refusal -> Error refusal
        | Ok (Some error) -> Ok (PollOutcome.Failed error, system)
        | Ok None ->

        match scan system entries with
        | Error refusal -> Error refusal
        | Ok (reported, triggered) ->

        let system = polledEntries entries system

        if triggered > 0 || milliseconds = 0 then
            Ok (PollOutcome.Answered (reported, triggered), system)
        else

        // Every entry carries nothing, so every non-negative descriptor is open
        // (a closed one would carry NVAL): the park records the description
        // each named, which is what a real poll sleeps on.
        let parkedEntries =
            entries
            |> List.map (fun entry ->
                if entry.Fd < 0 then
                    ParkedPollEntry.Ignored entry.Fd
                else
                    match FileDescriptorRegistry.tryFindId entry.Fd (UnixSystemState.fileDescriptors system) with
                    | Some description -> ParkedPollEntry.Watched (entry.Fd, description, entry.Events)
                    | None ->
                        failwith
                            $"UnixPoll.poll: fd %d{entry.Fd} reported nothing but names no open file description, where a closed descriptor reports POLLNVAL (this is a bug in this library)."
            )

        let now = system.Scheduling.NanosecondsSinceBoot

        match relativeDeadline now milliseconds with
        | Error () -> Error (PollRefusal.DeadlineBeyondClock (now, milliseconds))
        | Ok deadline ->

        let parked =
            ParkedSyscall.Poll
                {
                    Entries = parkedEntries
                    Deadline = deadline
                }

        Ok (PollOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked system)

    /// Finish the Linux-flavoured `poll` `thread` is parked in: see `finishPoll`.
    let private finishLinuxPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (parked : ParkedPoll)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<PollOutcome * ProcessView<'Thread, 'Handler>, PollRefusal>
        =
        let entries =
            parked.Entries
            |> List.map (fun entry ->
                match entry with
                | ParkedPollEntry.Ignored fd ->
                    {
                        PollEntry.Fd = fd
                        Events = 0s
                    }
                | ParkedPollEntry.Watched (fd, description, events) ->
                    if (OpenFileTable.tryFind description system.Machine.OpenFiles).IsNone then
                        failwith
                            $"UnixPoll.finishPoll: thread %O{thread}'s poll watches open file description %O{description}, which is not in the table, but a park holds its descriptions until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."

                    match FileDescriptorRegistry.tryFindId fd (UnixSystemState.fileDescriptors system) with
                    | Some current when current = description ->
                        {
                            PollEntry.Fd = fd
                            Events = events
                        }
                    | other ->
                        failwith
                            $"UnixPoll.finishPoll: thread %O{thread}'s poll watches fd %d{fd} on open file description %O{description}, but fd %d{fd} now names %A{other}. `close` refuses to close a descriptor a parked poll watches (this is a bug in this library, or in a caller that closed it without UnixDescriptor.close)."
            )

        match scan system entries with
        | Error refusal -> Error refusal
        | Ok (reported, triggered) ->

        let system = polledEntries entries system

        let timedOut = WakeCondition.deadlinePassed parked.Deadline system

        let finished = (UnixParkState.unpark thread system)

        // Measured on Linux 6.18.5 (`signal-interrupt-requeue.c`, sections D
        // and E), with the sleeper held off the CPU until both held: a ready
        // descriptor beats a pending signal, and a pending signal beats an
        // expired deadline, whichever came first.
        if triggered > 0 then
            match SyscallInterruption.beforeCompleting thread system with
            | Error refusal -> Error (PollRefusal.Interruption refusal)
            | Ok SyscallInterruption.Completion.Completes -> Ok (PollOutcome.Answered (reported, triggered), finished)
            | Ok (SyscallInterruption.Completion.Interrupted interruption) ->
                Ok (PollOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
        else

        match SyscallInterruption.ofPark thread system with
        | Error refusal -> Error (PollRefusal.Interruption refusal)
        | Ok (Some interruption) -> Ok (PollOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
        | Ok None ->

        if timedOut then
            Ok (PollOutcome.Answered (reported, triggered), finished)
        else
            let parkedAgain = ParkedSyscall.Poll parked

            Ok (
                PollOutcome.WouldBlock (WakeCondition.ofPark parkedAgain),
                Parking.parkWaiting thread parkedAgain system
            )

    /// What registering one group of an entry's filters does.
    [<RequireQualifiedAccess>]
    type private DarwinRegistration =
        /// The registration fails, and the entry answers `POLLNVAL`.
        | Fails
        /// The filter registers, attached to `socket` when the descriptor names
        /// one.
        | Registers of filter : KqueueFilter * socket : SocketId option
        /// An `EVFILT_VNODE` registers on a regular file or a directory. It
        /// reports only when the file changes, which nothing here does while
        /// a call runs, so it reports nothing to a call that does not sleep.
        | RegistersVnode

    /// Which groups of filters `events` registers, in the order `poll`
    /// registers them: `EVFILT_READ` (with `EV_OOBAND` when `true`),
    /// `EVFILT_WRITE`, then `EVFILT_VNODE`.
    let private darwinGroups (events : int16) : (KqueueFilter * bool) option list =
        [
            if events &&& DarwinPollEvents.ReadGroup <> 0s then
                Some (KqueueFilter.Read, events &&& DarwinPollEvents.OutOfBandGroup <> 0s)
            if events &&& DarwinPollEvents.WriteGroup <> 0s then
                Some (KqueueFilter.Write, false)
            if events &&& DarwinPollEvents.VnodeGroup <> 0s then
                None
        ]

    /// What registering `group` (a read or write filter, or `None` for
    /// `EVFILT_VNODE`) through the descriptor `fd` does.
    let private darwinRegistration<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (group : KqueueFilter option)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DarwinRegistration, PollRefusal>
        =
        // Measured on Darwin 27.0.0 (`poll-darwin.c` section S), each row of
        // which agreed with XNU's own filters: a descriptor that is not open
        // registers nothing (EBADF); `EVFILT_VNODE` registers on a vnode
        // alone, so on a regular file or a directory, and fails (EINVAL) on a
        // socket, a pipe and a kqueue; read and write filters fail on a
        // directory, and a kqueue takes a read filter but not a write one.
        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system), group with
        | None, _ -> Ok DarwinRegistration.Fails
        | Some (OpenFileTarget.Socket _), None
        | Some (OpenFileTarget.Pipe _), None
        | Some (OpenFileTarget.Kqueue _), None -> Ok DarwinRegistration.Fails
        | Some (OpenFileTarget.File _), None
        | Some (OpenFileTarget.Directory _), None -> Ok DarwinRegistration.RegistersVnode
        | Some (OpenFileTarget.Directory _), Some _ -> Ok DarwinRegistration.Fails
        | Some (OpenFileTarget.File _), Some filter
        | Some (OpenFileTarget.Pipe _), Some filter -> Ok (DarwinRegistration.Registers (filter, None))
        | Some (OpenFileTarget.Socket socketId), Some filter ->
            let socket = UnixMachineState.socket socketId system.Machine

            if DarwinReadiness.modelsSocket socket then
                Ok (DarwinRegistration.Registers (filter, Some socketId))
            else
                Error (PollRefusal.UnmodelledSocket (fd, socket.Domain, socket.Kind))
        | Some (OpenFileTarget.Kqueue _), Some KqueueFilter.Write -> Ok DarwinRegistration.Fails
        | Some (OpenFileTarget.Kqueue _), Some KqueueFilter.Read -> Error (PollRefusal.UnmodelledTarget fd)
        | Some (OpenFileTarget.Kqueue _), Some KqueueFilter.Timer -> ReservedTimerFilter.fail "UnixPoll.poll"
        | Some (OpenFileTarget.Epoll _), _ ->
            failwith
                $"UnixPoll.poll: fd %d{fd} names an epoll instance, which a Darwin-flavoured kernel cannot hold (this is a bug in the caller's state construction)."
        | Some (OpenFileTarget.Inotify _), _ ->
            failwith
                $"UnixPoll.poll: fd %d{fd} names an inotify instance, which a Darwin-flavoured kernel cannot hold (this is a bug in the caller's state construction)."
        | Some (OpenFileTarget.CharacterDevice _), _ ->
            failwith
                $"UnixPoll.poll: fd %d{fd} names a character device, which a Darwin-flavoured kernel cannot hold: its device filesystem is not modelled, so no path opens one (this is a bug in the caller's state construction)."
        | Some (OpenFileTarget.Fifo (inode, _)), _ -> ReservedFifo.fail "UnixPoll.poll" inode

    /// Register every entry's filters, as `poll_nocancel` does before it scans:
    /// each entry's `revents` so far (`POLLNVAL` for an entry whose
    /// registration failed, 0 otherwise), the registrations, and the
    /// descriptors an `EVFILT_VNODE` registered on.
    let private darwinRegister<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (entries : PollEntry list)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<int16 list * Map<int * KqueueFilter, PollRegistration> * int list, PollRefusal>
        =
        let rec registerGroups
            (index : int)
            (entry : PollEntry)
            (groups : (KqueueFilter * bool) option list)
            (registrations : Map<int * KqueueFilter, PollRegistration>)
            (vnodes : int list)
            : Result<bool * Map<int * KqueueFilter, PollRegistration> * int list, PollRefusal>
            =
            match groups with
            | [] -> Ok (false, registrations, vnodes)
            | group :: rest ->

            match darwinRegistration entry.Fd (group |> Option.map fst) system with
            | Error refusal -> Error refusal
            // The first group that fails ends the entry's registration, and the
            // groups registered before it stay registered (measured,
            // `poll-darwin.c` M3: `IN|EXTEND` on a socket answers `IN|NVAL`
            // beside another entry).
            | Ok DarwinRegistration.Fails -> Ok (true, registrations, vnodes)
            | Ok DarwinRegistration.RegistersVnode -> registerGroups index entry rest registrations (entry.Fd :: vnodes)
            | Ok (DarwinRegistration.Registers (filter, socket)) ->
                let outOfBand =
                    match group with
                    | Some (_, outOfBand) -> outOfBand
                    | None -> false

                let key = entry.Fd, filter

                // A pair an earlier entry registered is registered again, which
                // keeps its flags and its place and gives it this entry
                // (measured, `poll-darwin.c` M1 and M17-M24).
                let registration =
                    match Map.tryFind key registrations with
                    | Some existing ->
                        { existing with
                            Entry = index
                        }
                    | None ->
                        {
                            Entry = index
                            OutOfBand = outOfBand
                            RegisteredAt = Map.count registrations
                            Socket = socket
                        }

                registerGroups index entry rest (Map.add key registration registrations) vnodes

        let folded =
            ((Ok ([], Map.empty, [])
             : Result<int16 list * Map<int * KqueueFilter, PollRegistration> * int list, PollRefusal>),
             List.indexed entries)
            ||> List.fold (fun state (index, entry) ->
                match state with
                | Error refusal -> Error refusal
                | Ok (revents, registrations, vnodes) ->

                if entry.Fd < 0 then
                    Ok (0s :: revents, registrations, vnodes)
                else

                match registerGroups index entry (darwinGroups entry.Events) registrations vnodes with
                | Error refusal -> Error refusal
                | Ok (failed, registrations, vnodes) ->
                    let answer = if failed then DarwinPollEvents.Nval else 0s
                    Ok (answer :: revents, registrations, vnodes)
            )

        folded
        |> Result.map (fun (revents, registrations, vnodes) -> List.rev revents, registrations, List.rev vnodes)

    /// How many entries carry anything: `poll`'s return value.
    let private triggered (revents : int16 list) : int =
        revents |> List.filter (fun revents -> revents <> 0s) |> List.length

    /// A Darwin-flavoured `poll(2)`, after the parked-thread check: see `poll`.
    let private darwinPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<PollOutcome * ProcessView<'Thread, 'Handler>, PollRefusal>
        =
        let count = List.length entries

        // Measured (`docs/probes/poll-entry-count`, and `poll-darwin.c`
        // section N): ahead of the registrations, and of the copy-in's EFAULT.
        match
            PollEntryCount.screen system.Machine.UnixPlatform (UnixProcessState.callerPrivilege system.Process) count
        with
        | Error refusal -> Error refusal
        | Ok (Some error) -> Ok (PollOutcome.Failed error, system)
        | Ok None ->

        match darwinRegister entries system with
        | Error refusal -> Error refusal
        | Ok (revents, registrations, vnodes) ->

        // `poll_nocancel` scans only if some entry registered, so a call whose
        // every entry failed answers POLLNVAL for each and nothing else
        // (measured, `poll-darwin.c` M4), where a failure beside an entry that
        // did not fail -- a negative descriptor included -- still lets the
        // failing entry's earlier filters report (M3, M5).
        let failedAll =
            count > 0
            && revents |> List.forall (fun revents -> revents = DarwinPollEvents.Nval)

        if failedAll then
            Ok (PollOutcome.Answered (revents, count), system)
        else

        let active = KqueuePoll.activeAtRegistration registrations system

        let revents, registrations, active =
            KqueuePoll.scan entries revents registrations active system

        let reported = triggered revents

        // A failed registration makes the scan immediate, but it has already
        // put POLLNVAL in that entry, so it is counted here too.
        if reported > 0 || milliseconds = 0 then
            Ok (PollOutcome.Answered (revents, reported), system)
        elif milliseconds < -1 then
            Error (PollRefusal.UnmeasuredNegativeTimeout milliseconds)
        else

        match vnodes with
        | fd :: _ -> Error (PollRefusal.UnmodelledVnodeWait fd)
        | [] ->

        let now = system.Scheduling.NanosecondsSinceBoot

        let deadline =
            if milliseconds = -1 then
                Ok None
            else
                relativeDeadline now milliseconds

        match deadline with
        | Error () -> Error (PollRefusal.DeadlineBeyondClock (now, milliseconds))
        | Ok deadline ->

        let queue, machine =
            UnixMachineState.addPollQueue
                {
                    Owner = system.Process.ProcessId
                    Registrations = registrations
                    Active = active
                }
                system.Machine

        let parked =
            ParkedSyscall.KqueuePoll
                {
                    Entries = entries
                    Queue = queue
                    Deadline = deadline
                }

        let system =
            { system with
                Machine = machine
            }

        Ok (PollOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked system)

    /// Finish the Darwin-flavoured `poll` `thread` is parked in: see `finishPoll`.
    let private finishDarwinPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (parked : ParkedKqueuePoll)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<PollOutcome * ProcessView<'Thread, 'Handler>, PollRefusal>
        =
        let zero = parked.Entries |> List.map (fun _ -> 0s)
        let queue = UnixMachineState.pollQueue parked.Queue system.Machine

        let revents, registrations, active =
            KqueuePoll.scan parked.Entries zero queue.Registrations queue.Active system

        let reported = triggered revents

        let timedOut = WakeCondition.deadlinePassed parked.Deadline system

        let finished = (UnixParkState.unpark thread system)

        // Measured on Darwin 27.0.0 (`docs/probes/first-wake`, the poll rows):
        // held off the CPU from its wake until a second wake-up had come, a
        // woken poll answered what woke it: a report, 0 for its deadline, or
        // EINTR for a signal, whatever came second. Woken by a report and
        // something else, it gives the report's answer where there is nothing
        // to report any more, since its scan then finds nothing and it waits
        // again; and otherwise, as when woken by both its deadline and a
        // signal, it cannot be told which came first.
        let fired = SyscallInterruption.wokenBy thread system
        let byReport = Set.contains WakePrimitive.KqueuePollReportable fired

        let byDeadline =
            fired
            |> Set.exists (fun primitive ->
                match primitive with
                | WakePrimitive.DeadlinePassed _ -> true
                | _ -> false
            )

        let bySignal = Set.contains WakePrimitive.SignalDeliverable fired

        let signalBeside =
            PollRefusal.Interruption (SyscallInterruptionRefusal.SignalBesideCompletion SimulatedUnixFlavour.Darwin)

        match byReport, byDeadline, bySignal with
        | true, true, _ when reported > 0 -> Error PollRefusal.EventsBesideDeadline
        | true, false, true when reported > 0 -> Error signalBeside
        | false, true, true -> Error signalBeside
        | false, true, false -> Ok (PollOutcome.Answered (zero, 0), finished)
        | false, false, true ->
            match SyscallInterruption.ofPark thread system with
            | Error refusal -> Error (PollRefusal.Interruption refusal)
            | Ok (Some interruption) -> Ok (PollOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
            | Ok None ->
                failwith
                    $"UnixPoll.finishPoll: a signal woke thread %O{thread}'s Darwin poll, which a signal gone by its finish fails with EINTR or is refused, and SyscallInterruption.ofPark says it sleeps on (this is a bug in this library)."
        | true, _, _
        | false, false, false ->

        if reported > 0 then
            Ok (PollOutcome.Answered (revents, reported), finished)
        elif timedOut then
            // What woke it has gone, and its deadline has passed since: it
            // waits again, and whether a pending signal or the deadline then
            // ends that wait is unmeasured.
            match SyscallInterruption.beforeCompleting thread system with
            | Error refusal -> Error (PollRefusal.Interruption refusal)
            | Ok SyscallInterruption.Completion.Completes -> Ok (PollOutcome.Answered (zero, 0), finished)
            | Ok (SyscallInterruption.Completion.Interrupted _) -> Error signalBeside
        else

        match SyscallInterruption.ofPark thread system with
        | Error refusal -> Error (PollRefusal.Interruption refusal)
        | Ok (Some interruption) -> Ok (PollOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
        | Ok None ->
            // Whatever woke the thread has gone again. Its scan consumed what
            // reported without adding anything, and dropped what is no longer
            // ready, as a woken real poll's does, and it sleeps on, keeping its
            // kqueue.
            let parkedAgain = ParkedSyscall.KqueuePoll parked

            let system =
                { system with
                    Machine =
                        UnixMachineState.setPollQueue
                            parked.Queue
                            { queue with
                                Registrations = registrations
                                Active = active
                            }
                            system.Machine
                }

            Ok (
                PollOutcome.WouldBlock (WakeCondition.ofPark parkedAgain),
                Parking.parkWaiting thread parkedAgain system
            )

    /// `tryPoll` once `Entry` has admitted its caller.
    let private tryPollIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<PollOutcome * ProcessView<'Thread, 'Handler>, PollRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux -> linuxPoll thread entries milliseconds system
        | SimulatedUnixFlavour.Darwin -> darwinPoll thread entries milliseconds system

    /// `poll`, with a refusal answered as the `Error` rather than raised.
    let internal tryPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<PollOutcome * UnixSystem<'Thread, 'Handler>, PollRefusal>
        =
        Entry.call
            "UnixPoll.poll"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryPollIn (Caller.thread caller) entries milliseconds)
            system

    /// `poll(2)`: what each entry reports, and how many entries carry anything;
    /// or, when nothing does and the timeout lets it, the calling thread sleeps.
    ///
    /// Each entry's `Events`, and each `revents` answered for it, is the raw
    /// bits in the simulated flavour's own `<poll.h>` numbering. The count is
    /// `poll(2)`'s own return value, and it is neither the number of entries
    /// nor the number of *conditions*: it counts entries carrying something.
    /// A negative descriptor reports nothing and is not counted.
    ///
    /// **Under Linux** every bit is answered as a real kernel answers it: each
    /// named bit is reported when the descriptor presents it and the entry
    /// asked for it, `POLLERR` and `POLLHUP` whether asked for or not, and
    /// `POLLNVAL` alone for a descriptor that is not open. A bit Linux does not
    /// read (`POLLREMOVE`, 0x0800, 0x4000 and 0x8000) is ignored, as it is
    /// there. A call with more than 2147483584 entries fails with `EINVAL`.
    /// Refused: more than 1024 entries and at most 2147483584; and an entry
    /// naming an epoll instance.
    ///
    /// **Under Darwin** the call is answered as XNU builds it, over a kqueue it
    /// makes for its own use: each entry registers `EVFILT_READ` for any of
    /// `IN|RDNORM|PRI|RDBAND|HUP`, `EVFILT_WRITE` for any of `OUT|WRBAND`, and
    /// `EVFILT_VNODE` for any of the vnode bits (see `DarwinPollEvents`); an
    /// entry whose registration fails answers `POLLNVAL`; and each filter's
    /// report is folded into its entry's `revents`. So a request
    /// of none of those bits reports nothing, even for a descriptor that is not
    /// open; one descriptor named by several entries reports into the last of
    /// them alone; and a reported hang-up suppresses `POLLOUT`. A call with
    /// more than 10240 entries fails with `EINVAL`. Refused: more than 256
    /// entries and at most 10240; a socket
    /// whose filters are not modelled; a kqueue asked for a read bit; and a
    /// call that would sleep with a vnode filter registered, or with a
    /// negative timeout other than -1.
    ///
    /// `milliseconds` is read as the flavour reads it. Zero answers now. A
    /// positive timeout, when nothing is reported, parks the caller's thread
    /// until something is or `milliseconds` have passed on the machine's
    /// monotonic clock, whichever is first; at the deadline and not before, the call finishes
    /// with 0. -1 is infinite on both, and under Linux so is every negative
    /// timeout. A wait with nothing to watch and no deadline parks until a
    /// signal ends it. A foreign-function layer that screens some negative
    /// values itself does that before calling.
    ///
    /// A poll with anything to report is answered at every timeout. The system
    /// comes back unchanged unless the thread parked.
    ///
    /// The caller's thread must not already be parked: a thread blocks in one
    /// syscall at a time, and a parked `poll` is finished with `finishPoll`.
    let poll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (entries : PollEntry list)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : PollOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryPoll caller entries milliseconds system
        |> Refusal.orRaise "UnixPoll.poll" PollRefusal.kind PollRefusal.describe

    /// `tryFinishPoll` once `Entry` has admitted its caller.
    let internal tryFinishPollIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<PollOutcome * ProcessView<'Thread, 'Handler>, PollRefusal>
        =
        UnixThreadTable.expectParked
            "UnixPoll.finishPoll"
            (fun held ->
                match held with
                | ParkedSyscall.Poll parked ->
                    // `close` refuses to close a descriptor a parked Linux poll
                    // watches, so each description the call held is still named by its
                    // descriptor; released all the same, as every finishing call
                    // releases what its park held.
                    finishLinuxPoll thread parked system
                    |> Result.map (fun (outcome, after) ->
                        outcome,
                        ObjectLifetime.releaseUnreferencedUnrefusable
                            "UnixPoll.finishPoll"
                            (ParkedSyscall.descriptions held)
                            after
                    )
                    |> Some
                // A Darwin poll holds no description (see `ParkedSyscall.descriptions`),
                // so its return releases nothing.
                | ParkedSyscall.KqueuePoll parked -> Some (finishDarwinPoll thread parked system)
                | _ -> None
            )
            thread
            system.Threads

    /// `finishPoll`, with a refusal answered as the `Error` rather than raised.
    let internal tryFinishPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<PollOutcome * UnixSystem<'Thread, 'Handler>, PollRefusal>
        =
        Entry.call
            "UnixPoll.finishPoll"
            CallerRequirement.Woken
            caller
            (Shape.result Shape.withSystem)
            (tryFinishPollIn (Caller.thread caller))
            system

    /// Finish the `poll` `caller` parked in, as a woken real poll does, and
    /// answer.
    ///
    /// **Under Linux** it scans the entries the call was made with, not
    /// whatever the caller's array holds now, looking each descriptor up
    /// afresh; `close` refuses to close one a parked poll watches, so each
    /// still names the description the call went to sleep on. It answers the
    /// count when any entry carries anything, whether or not the deadline has
    /// passed or a signal is pending too; `Interrupted` when the thread would
    /// take a signal as it returned to user mode, whether or not the deadline
    /// has passed; and 0, with every `revents` 0, when only the deadline has.
    ///
    /// **Under Darwin** it scans the kqueue the call made for itself, which a
    /// close of a watched descriptor has left without that descriptor's
    /// filters. It answers as what woke the thread (`ParkState.Woken`) says,
    /// whatever has happened since: for something to report, the count it
    /// finds; for the deadline, 0; for a signal, `Interrupted`, which the
    /// thread's return to user mode then ends, failing the call with `EINTR`
    /// even if another thread has ignored the signal since. Woken by
    /// something to report and finding nothing, it answers 0 if the deadline
    /// has passed and `Interrupted` if the thread would take a signal as it
    /// returned to user mode. It refuses a wake that found two of these whose
    /// answers differ, since Darwin answers whichever reached the sleeping
    /// thread first; a call with a timeout whose waking signal has gone; and
    /// one woken by something to report, finding nothing past its deadline
    /// with a signal pending, which are unmeasured.
    ///
    /// Otherwise it re-parks the thread on the same call and deadline, since
    /// whatever woke it has gone again. An answer clears the park.
    ///
    /// `caller` must be parked in a `poll`, and woken (`UnixWait.wake`).
    let finishPoll<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : PollOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFinishPoll caller system
        |> Refusal.orRaise "UnixPoll.finishPoll" PollRefusal.kind PollRefusal.describe

    /// `tryEpollCreate1` once `Entry` has admitted its caller.
    let private tryEpollCreate1In<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<Result<int * ProcessView<'Thread, 'Handler>, UnixError>, EpollCreateRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (EpollCreateRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        // Measured on 6.18.5 (`epoll-wait.c`, section A): 0 and EPOLL_CLOEXEC
        // create an epoll instance; every other single bit, EPOLL_CLOEXEC beside any other
        // bit, -1 and INT_MIN are EINVAL.
        if flags &&& ~~~EpollCreateFlags.CloseOnExec <> 0 then
            Ok (Error UnixError.EINVAL)
        else

        // Measured (`fcntl-dup.c`, LIMIT rows): the flags' EINVAL ahead of the
        // descriptor.
        match
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)
        with
        | Error refusal -> Error (EpollCreateRefusal.DescriptorLimit refusal)
        | Ok () ->

        let fd, registry =
            FileDescriptorRegistry.createEpoll
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                (UnixSystemState.fileDescriptors system)

        let registry =
            FileDescriptorRegistry.setFlags
                fd
                (DescriptorFlags.closingOnExec
                    (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                    (flags &&& EpollCreateFlags.CloseOnExec <> 0))
                registry

        Ok (Ok (fd, UnixSystemState.withFileDescriptors registry system))

    /// `epollCreate1`, with a refusal answered as the `Error` rather than raised.
    let internal tryEpollCreate1<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<Result<int * UnixSystem<'Thread, 'Handler>, UnixError>, EpollCreateRefusal>
        =
        Entry.call
            "UnixPoll.epollCreate1"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.result Shape.withSystem))
            (tryEpollCreate1In flags)
            system

    /// <summary>
    /// `epoll_create1(2)`: create an epoll instance and a descriptor onto it, the
    /// lowest one not in use.
    ///
    /// `flags` is Linux's: 0, or `EpollCreateFlags.CloseOnExec`, which gives
    /// the new descriptor `FD_CLOEXEC`. Any other bit is `EINVAL`, and changes
    /// nothing.
    ///
    /// Under the Darwin flavour every call is refused: Darwin has no epoll.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Linux-flavoured, and only Linux has epoll.</exception>
    let epollCreate1<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<int * UnixSystem<'Thread, 'Handler>, UnixError>
        =
        tryEpollCreate1 caller flags system
        |> Refusal.orRaise "UnixPoll.epollCreate1" EpollCreateRefusal.kind EpollCreateRefusal.describe

    /// Whether the events `delivered` can be copied out to `buffer`: a call
    /// that delivers nothing copies nothing, and so never looks at the buffer.
    let private copyOut
        (epoll : OpenFileDescriptionId)
        (buffer : UserBuffer)
        (delivered : (uint64 * uint32) list)
        : Result<unit, EpollWaitRefusal>
        =
        if List.isEmpty delivered then
            Ok ()
        else
            match buffer with
            | UserBuffer.Mapped -> Ok ()
            | UserBuffer.Unmapped _ -> Error (EpollWaitRefusal.UnmeasuredCopyOutFault epoll)
            | UserBuffer.Opaque -> Error (EpollWaitRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
            | UserBuffer.Addressless -> Error (EpollWaitRefusal.Buffer BufferRefusal.AddresslessAtTransfer)

    /// Park `thread` in a wait on the epoll instance `epoll` for up to
    /// `maxEvents` events, until `deadline`.
    let private parkEpollWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (epoll : OpenFileDescriptionId)
        (maxEvents : int)
        (buffer : UserBuffer)
        (deadline : int64 option)
        (system : ProcessView<'Thread, 'Handler>)
        : EpollWaitOutcome * ProcessView<'Thread, 'Handler>
        =
        let parked =
            ParkedSyscall.EpollWait
                {
                    Epoll = epoll
                    MaxEvents = maxEvents
                    Buffer = buffer
                    Deadline = deadline
                }

        EpollWaitOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked system

    /// `tryEpollWait` once `Entry` has admitted its caller.
    let private tryEpollWaitIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (epfd : int)
        (maxEvents : int)
        (buffer : UserBuffer)
        (milliseconds : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<EpollWaitOutcome * ProcessView<'Thread, 'Handler>, EpollWaitRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (EpollWaitRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        match admitEpollWait epfd maxEvents buffer system with
        | Error refusal -> Error (EpollWaitRefusal.Buffer refusal)
        | Ok (Error error) -> Ok (EpollWaitOutcome.Failed error, system)
        | Ok (Ok epoll) ->

        let delivered, system = EpollReadyList.drain epoll maxEvents system

        // Measured (`epoll-wait.c`, sections B and C): a wait that finds
        // something answers at once whatever the timeout, and one that finds
        // nothing answers at once for a timeout of 0.
        if not (List.isEmpty delivered) || milliseconds = 0 then
            copyOut epoll buffer delivered
            |> Result.map (fun () -> EpollWaitOutcome.Answered delivered, system)
        else

        let now = system.Scheduling.NanosecondsSinceBoot

        match relativeDeadline now milliseconds with
        | Error () -> Error (EpollWaitRefusal.DeadlineBeyondClock (now, milliseconds))
        | Ok deadline -> Ok (parkEpollWait thread epoll maxEvents buffer deadline system)

    /// `epollWait`, with a refusal answered as the `Error` rather than raised.
    let internal tryEpollWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (epfd : int)
        (maxEvents : int)
        (buffer : UserBuffer)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<EpollWaitOutcome * UnixSystem<'Thread, 'Handler>, EpollWaitRefusal>
        =
        Entry.call
            "UnixPoll.epollWait"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryEpollWaitIn (Caller.thread caller) epfd maxEvents buffer milliseconds)
            system

    /// <summary>
    /// `epoll_wait(2)`, made by `caller`: take up to `maxEvents` events off the
    /// epoll instance `epfd` names, sleeping for up to `milliseconds` if it has
    /// none.
    ///
    /// Every argument check is answered, in Linux's order: `EBADF` for a
    /// descriptor that is not open, then `EINVAL` for a `maxEvents` that is not
    /// positive or exceeds the architecture's bound, then `EFAULT` for a buffer
    /// reaching into kernel space (see `UserBufferCheck.BeforeOperation`), then
    /// `EINVAL` for a descriptor that is not an epoll instance. A failure
    /// changes nothing.
    ///
    /// Delivery walks the epoll instance's pending registrations in order, reporting each
    /// one whose target is still ready and consuming each one walked, stale or
    /// not; the entries a full `maxEvents` spared stay pending in order. A wait
    /// that finds something answers it
    /// whatever the timeout. One that finds nothing answers no events at once
    /// for a timeout of 0; parks the caller's thread for a positive timeout
    /// until an event is deliverable or `milliseconds` have passed on the
    /// machine's monotonic clock; and parks it until an event is deliverable for any negative
    /// timeout, which is infinite. A parked wait is finished with
    /// `finishEpollWait`. The walk's consumption stands whether or not the call
    /// then sleeps.
    ///
    /// A call that delivers events copies them out to `buffer`, which must be
    /// `Mapped`: this library does not answer for a copy that faults or a buffer
    /// whose bytes it cannot hold, and refuses it. A call that delivers
    /// nothing never looks at the buffer past the screen.
    ///
    /// Of several threads parked on one epoll instance, one event wakes one of them (see
    /// `UnixWait.wake`).
    ///
    /// The caller's thread must not already be parked. Under the Darwin flavour
    /// every call is refused: Darwin has no epoll.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Linux-flavoured, and only Linux has epoll.</exception>
    let epollWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (epfd : int)
        (maxEvents : int)
        (buffer : UserBuffer)
        (milliseconds : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : EpollWaitOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryEpollWait caller epfd maxEvents buffer milliseconds system
        |> Refusal.orRaise "UnixPoll.epollWait" EpollWaitRefusal.kind EpollWaitRefusal.describe

    let private finishEpollWaitHolding<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<EpollWaitOutcome * ProcessView<'Thread, 'Handler>, EpollWaitRefusal>
        =
        let parked =
            UnixThreadTable.expectParked
                "UnixPoll.finishEpollWait"
                (fun parked ->
                    match parked with
                    | ParkedSyscall.EpollWait parked -> Some parked
                    | _ -> None
                )
                thread
                system.Threads

        let delivered, system = EpollReadyList.drain parked.Epoll parked.MaxEvents system

        let timedOut = WakeCondition.deadlinePassed parked.Deadline system

        let finished = (UnixParkState.unpark thread system)

        // Measured on Linux 6.18.5 (`signal-interrupt-requeue.c`, sections D
        // and E), with the sleeper held off the CPU until both held: an event
        // beats a pending signal, and so does an expired deadline, whichever
        // came first.
        if not (List.isEmpty delivered) || timedOut then
            match SyscallInterruption.beforeCompleting thread system with
            | Error refusal -> Error (EpollWaitRefusal.Interruption refusal)
            | Ok SyscallInterruption.Completion.Completes ->
                copyOut parked.Epoll parked.Buffer delivered
                |> Result.map (fun () -> EpollWaitOutcome.Answered delivered, finished)
            | Ok (SyscallInterruption.Completion.Interrupted interruption) ->
                Ok (EpollWaitOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
        else

        match SyscallInterruption.ofPark thread system with
        | Error refusal -> Error (EpollWaitRefusal.Interruption refusal)
        | Ok (Some interruption) ->
            Ok (EpollWaitOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
        | Ok None -> Ok (parkEpollWait thread parked.Epoll parked.MaxEvents parked.Buffer parked.Deadline system)

    /// `tryFinishEpollWait` once `Entry` has admitted its caller.
    let internal tryFinishEpollWaitIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<EpollWaitOutcome * ProcessView<'Thread, 'Handler>, EpollWaitRefusal>
        =
        let held =
            match UnixThreadTable.parkedFor thread system.Threads with
            | Some parked -> ParkedSyscall.descriptions parked
            | None -> []

        // The call's reference to the epoll instance goes as it returns, and with it the
        // epoll instance, if no descriptor names it any more (`open-file-references.c`
        // section E).
        finishEpollWaitHolding thread system
        |> Result.map (fun (outcome, after) ->
            outcome, ObjectLifetime.releaseUnreferencedUnrefusable "UnixPoll.finishEpollWait" held after
        )

    /// `finishEpollWait`, with a refusal answered as the `Error` rather than raised.
    let internal tryFinishEpollWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<EpollWaitOutcome * UnixSystem<'Thread, 'Handler>, EpollWaitRefusal>
        =
        Entry.call
            "UnixPoll.finishEpollWait"
            CallerRequirement.Woken
            caller
            (Shape.result Shape.withSystem)
            (tryFinishEpollWaitIn (Caller.thread caller))
            system

    /// <summary>
    /// Finish the wait on an epoll instance that `caller` is parked in: walk
    /// the epoll instance again, as a woken real wait does, and answer.
    ///
    /// Delivers from the epoll instance the call was made on and with the `maxEvents` it
    /// was made with, not whatever the caller's arguments hold now: the parked
    /// call holds the epoll instance's open file description, which outlives its last
    /// descriptor until the call returns, and goes then.
    ///
    /// Answers the events it finds, whether or not the deadline has passed or a
    /// signal is pending too (measured, `epoll-wait.c` section E: an event and
    /// an expired deadline both holding as the waiter runs report the event);
    /// no events when the deadline has passed, whether or not a signal is
    /// pending; `Interrupted` when the thread would take a signal as it
    /// returned to user mode, or when a signal woke the thread and has gone
    /// since (another thread ignored it), whose return then fails the call with
    /// `EINTR`; and otherwise re-parks the thread on the same epoll instance and deadline, since
    /// whatever woke it has gone again. A re-park goes to the back of park
    /// order, which puts it first in line for the epoll instance's next event. An answer
    /// clears the park. A call with a timeout whose waking signal has gone is
    /// refused, since what it does is unmeasured.
    ///
    /// Delivering events copies them out to the buffer the call was made with;
    /// see `epollWait` for the buffers that refuses.
    ///
    /// `caller` must be parked in an `epoll_wait`, and woken (`UnixWait.wake`).
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">This kernel is not Linux-flavoured, and only Linux has epoll.</exception>
    let finishEpollWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : EpollWaitOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFinishEpollWait caller system
        |> Refusal.orRaise "UnixPoll.finishEpollWait" EpollWaitRefusal.kind EpollWaitRefusal.describe
