namespace WoofWare.PosixKernel

/// <summary>
/// Index of one of the simulated process's logical processors.
/// </summary>
/// <example>
/// As reported to a process by <c>sched_getcpu(3)</c>.
/// </example>
type CpuId =
    | CpuId of int

    /// <summary>
    /// A human-readable description of the CPU ID.
    /// </summary>
    override this.ToString () =
        match this with
        | CpuId.CpuId i -> $"<cpu #%i{i}>"

/// One thread's in-flight `epoll_wait`: the state the syscall captured when it
/// was entered, which outlives anything the process does to its arguments
/// afterwards. The epoll instance is held by *description identity*, exactly as
/// the real syscall holds a file reference: the fd the wait was called through
/// is never consulted again, and the instance lives at least as long as the
/// wait (`ParkedSyscall.descriptions`).
type ParkedEpollWait =
    {
        /// <summary>
        /// The open file description of the epoll instance being waited on.
        /// </summary>
        Epoll : OpenFileDescriptionId
        /// <summary>
        /// The <c>maxevents</c> the call was made with.
        /// </summary>
        MaxEvents : int
        /// The buffer the call was given to copy events out to, as the caller
        /// classified it when the call was entered.
        Buffer : UserBuffer
        /// The instant, in nanoseconds since boot, at which the wait stops and
        /// returns no events; or `None` for a wait that lasts until an event is
        /// deliverable.
        Deadline : int64 option
    }

/// One thread's in-flight `kevent(2)` wait on a kqueue: the state the call
/// captured when it was entered.
type ParkedKevent =
    {
        /// The open file description of the kqueue being waited on.
        ///
        /// Held as the real call holds a file reference: the kqueue lives at
        /// least as long as the wait (`ParkedSyscall.descriptions`), so a close
        /// of `Fd` drains it rather than destroying it under the wait.
        Kqueue : OpenFileDescriptionId
        /// The descriptor the call was made through.
        ///
        /// Kept beside the description because a close of this descriptor, and
        /// of no other, ends the wait (see `WakePrimitive.KqueueDrained`).
        Fd : int
        /// The `nevents` the call was made with: positive, since a call with
        /// none to take returns at once.
        MaxEvents : int
        /// The eventlist the call was given to copy events out to, as the
        /// caller classified it when the call was entered.
        Buffer : UserBuffer
        /// The instant, in nanoseconds since boot, at which the wait stops and
        /// returns no events; or `None` for a wait with a null timeout.
        Deadline : int64 option
    }

/// <summary>
/// One thread's in-flight <c>flock</c> acquisition: which open file description it is
/// waiting to lock, and how.
/// </summary>
/// <remarks>
/// This is exactly the payload of the <c>WakePrimitive.FlockGrantable</c> that parked it.
/// </remarks>
type ParkedFlock =
    {
        /// <summary>
        /// The open file description whose lock is being waited for.
        /// </summary>
        Requester : OpenFileDescriptionId
        /// <summary>
        /// The lock that the caller asked for.
        /// </summary>
        /// <remarks>
        /// This is <i>not</i> necessarily a lock which is currently held.
        /// In the case of a "conversion" (<c>flock(2)</c>'s term for re-acquiring a lock in a different
        /// mode on a description which already holds a lock), the kernel may already have dropped whatever lock
        /// this description held; Linux models conversion as "drop-then-reacquire".
        /// So this is what it will hold if the acquisition ever completes, not necessarily what it holds
        /// now.
        /// (This is Linux-specific behaviour; Darwin keeps the lock which a failed conversion would have dropped.)
        /// </remarks>
        Mode : FlockMode
    }

/// One entry of a `poll(2)` call, as its caller supplied it: `struct pollfd`'s
/// `fd` and `events`, without the `revents` the kernel writes back.
type PollEntry =
    {
        /// The descriptor to poll. A negative one is not an error: measured on
        /// both kernels, it is ignored, reports nothing, and does not count
        /// towards the return value.
        Fd : int
        /// What the caller asked about: `events`, as raw bits in the simulated
        /// flavour's own `<poll.h>` numbering.
        ///
        /// Under Linux, `POLLERR`, `POLLHUP` and `POLLNVAL` are reported whether
        /// or not they appear here. Under Darwin, a request names kqueue filters
        /// rather than conditions, and a request of none of the bits that
        /// register one (`ERR`, `NVAL` and the bits above `POLLWRITE` among
        /// them) reports nothing at all, even for a descriptor that is not open.
        Events : int16
    }

/// One entry of a parked Linux-flavoured `poll(2)`, as the call captured it
/// when it went to sleep.
[<RequireQualifiedAccess>]
type ParkedPollEntry =
    /// A negative descriptor, which `poll` ignores: it reports nothing and
    /// waits on nothing.
    | Ignored of fd : int
    /// The descriptor `fd`, asked for `events` (raw bits in the flavour's own
    /// `<poll.h>` numbering), and the open file description `fd` named when the
    /// call went to sleep.
    ///
    /// Both halves are kept because a real poll uses both: it sleeps on the
    /// description it found, which it holds, and when it wakes it looks `fd` up
    /// again. `close` refuses to close `fd` while this entry waits, so the two
    /// stay in step.
    | Watched of fd : int * description : OpenFileDescriptionId * events : int16

/// One thread's in-flight Linux-flavoured `poll(2)`: every entry the call was made with, in order,
/// and when it times out.
type ParkedPoll =
    {
        /// The entries, in the caller's order, which is the order the finishing
        /// call reports `revents` in.
        Entries : ParkedPollEntry list
        /// The instant, in nanoseconds since boot, at which the call stops
        /// waiting and returns 0; or `None` for a call that waits until a
        /// descriptor is ready.
        Deadline : int64 option
    }

/// One filter a Darwin-flavoured `poll(2)` registered in the kqueue it makes
/// for its own use, keyed beside it by the descriptor number and the filter.
///
/// Darwin's `poll` registers, for each entry, one filter per group of the bits
/// it asks for, each added once only (`EV_ONESHOT`): the first report it makes
/// removes it, whether or not that report adds anything to the entry.
type internal PollRegistration =
    {
        /// The index, in the call's entries, of the entry the filter reports
        /// into: the last entry naming this descriptor and filter, since a
        /// later entry's registration of the same pair replaces the earlier's
        /// `udata` rather than adding a filter (measured).
        Entry : int
        /// Whether the entry that first registered the pair asked for
        /// `POLLPRI` or `POLLRDBAND`, which registers `EVFILT_READ` with
        /// `EV_OOBAND`. A later entry's registration keeps the first one's
        /// flags (measured). A socket's filter ignores the flag; every other
        /// target's reports it back, and `poll` then answers `POLLPRI` and
        /// `POLLRDBAND` for a ready read.
        OutOfBand : bool
        /// Where the pair's first registration stands in the order the call
        /// made them. One event that activates several registrations of a
        /// socket's filter, made through different descriptors onto it,
        /// queues the latest-made first, as it does in a kqueue `kevent` fills.
        RegisteredAt : int
        /// For a socket's filter, the socket the descriptor named when the
        /// call registered it: what the filter is attached to, so that an
        /// event on the socket reaches it whichever process's call caused the
        /// event, without reading any descriptor table. `None` for a pipe's or
        /// a regular file's filter, which nothing activates (see
        /// `PollQueue.Active`).
        Socket : SocketId option
    }

/// The identity of the kqueue a Darwin `poll(2)` made for its own use
/// (`PollQueue`). Minted from a counter the machine keeps, and never reused.
type PollQueueId =
    | PollQueueId of int64

    /// A human-readable description of the identity.
    override this.ToString () =
        match this with
        | PollQueueId.PollQueueId i -> $"<poll queue #%i{i}>"

/// The kqueue a Darwin `poll(2)` made for its own use, while the call sleeps.
///
/// Darwin builds `poll` over kqueue: the call registers a filter per group of
/// requested bits in a kqueue that has no descriptor, and translates what the
/// filters report back into `revents`. A sleeping call keeps that kqueue, and
/// what it reports when it wakes depends on what has been activated in it, and
/// in which order -- not only on what its descriptors present then.
///
/// Held on the machine rather than in the call's park, because a socket event
/// in any process's call activates its filters, as one does a kqueue's. It
/// lives exactly as long as the park
/// naming it (`ParkedKqueuePoll.Queue`): the park's end destroys it.
///
/// Its representation is internal, so a later version may change what a
/// registration holds and what it is attached to without breaking a client. A
/// client reads one through `PollQueue.registered`, `PollQueue.entry` and
/// `PollQueue.activated`, and builds none.
type PollQueue =
    internal
        {
            /// The process whose `poll` made the queue, whose descriptor table its
            /// registrations' descriptor numbers are read in.
            Owner : ProcessId
            /// The filters still registered: those that have not yet reported, keyed
            /// by descriptor number and filter. Closing a descriptor removes every
            /// one made through it, as it does from a kqueue a process holds.
            Registrations : Map<int * KqueueFilter, PollRegistration>
            /// The registrations of sockets' filters something has activated since
            /// the call last scanned, in the order they were activated: the order
            /// a scan reports them in, which decides whether a reported `POLLHUP`
            /// suppresses a socket's `POLLOUT`. Always a subset of
            /// `Registrations`, with no duplicates, naming sockets alone.
            ///
            /// A pipe's filters are not listed: every operation that makes one
            /// ready activates it (measured), and the order a pipe entry's two
            /// filters report in cannot change what the entry answers, so a scan
            /// reports a pipe's registration exactly while its filter is ready.
            Active : (int * KqueueFilter) list
        }

/// What a client reads of a sleeping Darwin poll's kqueue (`UnixSystem.pollQueue`).
[<RequireQualifiedAccess>]
module PollQueue =
    /// The filters the call registered that have not yet reported, each as the
    /// descriptor it was registered through and its filter, in ascending order.
    let registered (queue : PollQueue) : (int * KqueueFilter) list =
        queue.Registrations |> Map.toList |> List.map fst

    /// The index, in the call's entries, of the entry that the filter `filter`
    /// registered through `fd` reports into; `None` when no such filter is
    /// registered. Where several entries name the same descriptor and filter,
    /// it is the last of them.
    let entry (fd : int) (filter : KqueueFilter) (queue : PollQueue) : int option =
        queue.Registrations
        |> Map.tryFind (fd, filter)
        |> Option.map (fun (registration : PollRegistration) -> registration.Entry)

    /// The registered filters that something has activated since the call
    /// last scanned, in the order they were activated, which is the order the
    /// call reports them in. In this version only a socket's filters are
    /// listed: the call reports a pipe's filter exactly while it is ready.
    let activated (queue : PollQueue) : (int * KqueueFilter) list = queue.Active

/// One thread's in-flight Darwin-flavoured `poll(2)`: its entries, the kqueue
/// the call made for its own use, and when it times out.
type ParkedKqueuePoll =
    {
        /// The entries, in the caller's order, which is the order the
        /// finishing call reports `revents` in.
        Entries : PollEntry list
        /// The kqueue the call made for its own use, held on the machine. The
        /// park holds it: it is destroyed when the park ends.
        Queue : PollQueueId
        /// The instant, in nanoseconds since boot, at which the call stops
        /// waiting and returns 0; or `None` for a call that waits until
        /// something is reported.
        Deadline : int64 option
    }

/// What a sleeping call that waits on one open file description waits on, or
/// that a close has ended it: the state of a blocking `accept(2)`, or of a
/// blocking `read(2)` or `write(2)` of a pipe or a connected stream socket.
///
/// `'Object` names the kernel object the call waited on, by the machine's own
/// identity for it (a `SocketId` or a `PipeId`), for a call that no longer
/// holds a description to name it by.
[<RequireQualifiedAccess>]
type SleepTarget<'Object> =
    /// The call waits on the open file description `description`, which it
    /// holds, having been made through the descriptor `fd`.
    ///
    /// Held by description rather than by descriptor: a `dup` of the descriptor
    /// names the same description, and the call keeps it whatever is closed.
    /// Under Darwin, `fd` names `description` for as long as the call waits,
    /// since a close of it ends the call (`EndedByClose`). Under Linux a close
    /// of `fd` leaves the call waiting, so the number can be freed, and taken
    /// by a later open, while the call sleeps; nothing reads it there.
    | Waiting of description : OpenFileDescriptionId * fd : int
    /// Under Darwin, a close has ended the call, which waited on `object`. It
    /// holds nothing, and its finishing call answers what the close left it.
    ///
    /// A pipe transfer is ended by a close of the descriptor it was made
    /// through. An accept, a connection transfer or a UDP receive is ended by
    /// a close of the descriptor that any such call asleep on the same socket
    /// was made through, which drains the socket (see
    /// `SocketDescription.Drained`).
    | EndedByClose of object : 'Object

[<RequireQualifiedAccess>]
module SleepTarget =
    /// The open file description the call waits on and holds, or `None` once a
    /// close has ended it.
    let description<'Object> (target : SleepTarget<'Object>) : OpenFileDescriptionId option =
        match target with
        | SleepTarget.Waiting (description, _) -> Some description
        | SleepTarget.EndedByClose _ -> None

/// One thread's in-flight blocking `accept(2)`: the listening socket it waits on
/// for a connection, and where the connection's peer address goes when one
/// arrives.
type ParkedAccept =
    {
        /// The open file description of the listening socket the call was made
        /// through, and the descriptor it was made through; or the listening
        /// socket, once a close has ended the call.
        ///
        /// Under Linux the descriptor the call came through can be closed while
        /// it sleeps, the last one included, leaving the listener to the call.
        Listener : SleepTarget<SocketId>
        /// Where the peer address is to be copied out to, as the caller
        /// classified it when the call was entered.
        Destination : UserBuffer
        /// How many bytes of the peer address the caller's length cell allows
        /// to be written: the 32-bit word in the cell, which Linux reads as an
        /// `int` and Darwin as a `socklen_t` (see `UnixConnection.accept`).
        ///
        /// This is the length the call was entered with. Darwin reads the
        /// caller's cell then; Linux reads it only when it copies the address
        /// out, after the wait, so under Linux this is right for a caller whose
        /// cell nothing writes while the call sleeps. `None` for a NULL
        /// destination, whose cell neither flavour reads.
        DeclaredLength : uint32 option
        /// Whether the call's flags carried Linux's `SOCK_NONBLOCK`, so that
        /// the socket it makes is non-blocking. Never under Darwin, which has
        /// no `accept4`.
        NewSocketNonBlocking : bool
        /// Whether the call's flags carried Linux's `SOCK_CLOEXEC`, so that the
        /// descriptor it makes has `FD_CLOEXEC`. Never under Darwin.
        NewSocketCloseOnExec : bool
    }

/// One thread's in-flight blocking `read(2)` of a pipe that held nothing while a
/// write end was open.
type ParkedPipeRead =
    {
        /// The open file description of the pipe's read end the call was made
        /// through, and the descriptor it was made through; or the pipe, once a
        /// close has ended the call.
        Reader : SleepTarget<PipeId>
        /// Where the bytes are to be copied out to, as the caller classified it
        /// when the call was entered. Nothing is copied before the call sleeps,
        /// so a buffer naming no storage faults only once there is something to
        /// copy.
        Buffer : UserBuffer
        /// The most bytes the call takes: its count, after the platform's limit
        /// on one call's transfer. Never zero, since a read of nothing returns
        /// at once.
        Count : int
    }

/// One thread's in-flight blocking `write(2)` into a pipe that had no room for all
/// of it.
///
/// Holds no bytes. A sleeping write copies from the caller's buffer as room
/// appears, so bytes a process writes into its buffer while the call sleeps
/// are the bytes that reach the pipe; the call that finishes the write asks
/// the caller for them then.
type ParkedPipeWrite =
    {
        /// The open file description of the pipe's write end the call was made
        /// through, and the descriptor it was made through; or the pipe, once a
        /// close has ended the call.
        Writer : SleepTarget<PipeId>
        /// Where the bytes come from, as the caller classified it when the call
        /// was entered.
        Buffer : UserBuffer
        /// How many bytes the call writes in all: its count, after the
        /// platform's limit on one call's transfer.
        Count : int
        /// How many of them, from the start, are already in the pipe: less than
        /// `Count`.
        Written : int
        /// The pipe's `PipeState.Reads` when the write went to sleep: a read
        /// since then is one that woke it, on Darwin.
        ReadsSeen : int64
    }

/// Which call reads from a TCP connection.
[<RequireQualifiedAccess>]
type TcpReceiveCall =
    /// `read(2)`.
    | Read
    /// `recv(2)` without `MSG_PEEK`.
    | Receive
    /// `recv(2)` with `MSG_PEEK`: the bytes stay queued.
    | Peek

/// Which call writes to a TCP connection, as far as what it does differs.
[<RequireQualifiedAccess>]
type TcpSendCall =
    /// `write(2)`: an `EPIPE` raises `SIGPIPE`, and on Darwin a write that
    /// moves bytes marks its description written.
    | Write
    /// `send(2)`, which marks no description written. With `noSignal`
    /// (`MSG_NOSIGNAL`), an `EPIPE` raises no `SIGPIPE`.
    | Send of noSignal : bool

/// One thread's in-flight blocking `read(2)` or `recv(2)` of a connected stream
/// socket that had nothing to answer: no bytes, no FIN and no reset.
type ParkedConnectionRead =
    {
        /// The open file description of the socket the call was made through,
        /// and the descriptor it was made through; or the socket, once a close
        /// has ended the call.
        Socket : SleepTarget<SocketId>
        /// Where the bytes are to be copied out to, as the caller classified it
        /// when the call was entered. Nothing is copied before the call sleeps.
        Buffer : UserBuffer
        /// The most bytes the call takes: its count, after the platform's limit
        /// on one call's transfer. Zero only for a Linux `recv(2)`, which
        /// sleeps until there is something to answer even when it asks for
        /// nothing; a `read(2)` of nothing, and a Darwin `recv(2)` of nothing,
        /// return at once.
        Count : int
        /// Which call it is.
        Call : TcpReceiveCall
    }

/// One thread's in-flight blocking `write(2)` or `send(2)` to a connected stream
/// socket whose buffers had no room for all of it.
///
/// Holds no bytes, as `ParkedPipeWrite` holds none: the call that finishes the
/// write asks the caller for the next of them as room appears.
type ParkedConnectionWrite =
    {
        /// The open file description of the socket the call was made through,
        /// and the descriptor it was made through; or the socket, once a close
        /// has ended the call.
        Socket : SleepTarget<SocketId>
        /// Where the bytes come from, as the caller classified it when the call
        /// was entered.
        Buffer : UserBuffer
        /// How many bytes the call writes in all: its count, after the
        /// platform's limit on one call's transfer.
        Count : int
        /// How many of them, from the start, the connection has taken already:
        /// less than `Count`.
        Written : int
        /// Which call it is.
        Call : TcpSendCall
    }

/// What an interrupted sleep reports of the time it had left: whether
/// `nanosleep(2)` or a relative `clock_nanosleep(2)` writes its `rem` argument.
/// Fixed when the call is made.
[<RequireQualifiedAccess>]
type SleepRemainder =
    /// Nothing is written: the call was made with a null `rem`, or is a
    /// `clock_nanosleep` with `TIMER_ABSTIME`, which never writes it.
    | Unreported
    /// An interrupted call reports the nanoseconds from the instant it is
    /// interrupted to `until`, or 0 if `until` has passed, and writes them to
    /// `destination`.
    ///
    /// `until` is in nanoseconds since boot, on the same clock as
    /// `ParkedSleep.Deadline`. Under Linux it is the deadline (plus the thread's
    /// timer slack, were that modelled). Under Darwin it is the C library's own
    /// completion time, which its 32-bit arithmetic on seconds makes differ
    /// from the deadline for requests of about 2^32 seconds or more.
    ///
    /// `destination` is `rem` as the caller classified it when the call was
    /// entered. Under Linux the kernel writes it, and an interrupted call whose
    /// `destination` it cannot write fails with `EFAULT` instead of `EINTR`.
    /// Under Darwin the C library writes it, so the kernel does not consult it.
    | Reported of until : int64 * destination : UserBuffer

/// One thread's in-flight `nanosleep(2)` or `clock_nanosleep(2)`: the state the
/// call fixed when it was entered.
///
/// Reserved: nothing parks a thread in a sleep yet (`ParkedSyscall.Sleep`).
type ParkedSleep =
    {
        /// The instant, in nanoseconds since boot on the machine's virtual
        /// clock, at which the sleep runs its course and the call returns 0. A
        /// request whose end would lie past `Int64.MaxValue` nanoseconds since
        /// boot ends there, as Linux saturates its deadline at `KTIME_MAX`.
        Deadline : int64
        /// What an interrupted call reports of the time it had left.
        Remainder : SleepRemainder
    }

/// One thread's in-flight blocking `open(2)` or `openat(2)` of one end of a
/// FIFO, asleep until the other end is opened.
///
/// Reserved: nothing parks a thread in a FIFO open yet (`ParkedSyscall.FifoOpen`).
type ParkedFifoOpen =
    {
        /// The open file description the call made before it slept, and holds
        /// while it sleeps. Through it the sleeping call counts as an open end
        /// of the kind its access mode names, as it does on both flavours: a
        /// partner's non-blocking open succeeds against it, and a signal that
        /// ends the call releases it.
        Opener : OpenFileDescriptionId
        /// The descriptor number the call took before it slept, at which it
        /// installs the description once it completes. Meanwhile no other call
        /// is given that number, and `fcntl(2)` and `close(2)` of it answer
        /// `EBADF`, on both flavours; a `dup2(2)` onto it answers `EBUSY` under
        /// Linux, and under Darwin waits for the open to complete.
        Descriptor : int
        /// How many opens of the partner end the FIFO had seen when the call
        /// slept. The call completes once the FIFO has seen more, even if every
        /// partner has closed again by then, on both flavours.
        PartnerOpens : int64
    }

/// One thread's in-flight blocking `read(2)` of an inotify instance that held no
/// record.
type ParkedInotifyRead =
    {
        /// The open file description of the instance the call was made
        /// through, which it holds while it sleeps. A close of every descriptor
        /// naming it leaves the call asleep (measured, `inotify-probe.c`
        /// section B), so nothing ends the call but a record or a signal.
        Instance : OpenFileDescriptionId
        /// Where the records are to be copied out to, as the caller classified
        /// it when the call was entered. Nothing is copied before the call
        /// sleeps, so a buffer naming no storage faults only once there is a
        /// record to copy.
        Buffer : UserBuffer
        /// The most bytes the call takes: its count, after the platform's
        /// limit on one call's transfer. May be 0, or less than the record the
        /// call wakes to, which it then answers `EINVAL` for.
        Count : int
    }

/// One thread's in-flight `select(2)` or `pselect(2)`: the state the call fixed
/// when it was entered.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client reads a select's wait through
/// `WakeCondition.ofPark`, and builds none. Nothing in this version makes one:
/// see `ParkedSyscall.Select`.
type ParkedSelect =
    internal
        {
            // What the two flavours' parks must hold beyond this is not
            // settled: Darwin's call ends with EBADF when a selected
            // descriptor is closed, Linux's sleeps on and reports it, and
            // Darwin's readiness for each set is unmeasured
            // (`docs/probes/select-park`).
            /// The instant, in nanoseconds since boot, at which the call stops
            /// waiting and returns 0; or `None` for a call with a null timeout.
            Deadline : int64 option
        }

/// One thread's in-flight `sigwait(3)`, `sigwaitinfo(2)` or `sigtimedwait(2)`:
/// Linux's `rt_sigtimedwait(2)` or Darwin's `__sigwait`, asleep until a signal
/// in a set is pending. The state the call fixed when it was entered.
///
/// Reserved: nothing parks a thread in a signal wait yet
/// (`ParkedSyscall.SignalWait`).
type ParkedSignalWait =
    {
        /// The signals the call takes, from the set its caller passed. They
        /// need not be blocked: on both flavours the call takes an awaited
        /// signal that arrives unblocked with a handler, and the handler does
        /// not run.
        Awaited : SignalMask
        /// The instant, in nanoseconds since boot on the machine's virtual
        /// clock, at which a Linux call with a timeout gives up and answers
        /// `EAGAIN`. Fixed at the call: Linux never writes the remaining time
        /// back. `None` for a call with no timeout, which is every Darwin call,
        /// since Darwin has `sigwait(3)` alone.
        Deadline : int64 option
        /// Where the kernel reports the signal the call takes, as the caller
        /// classified it when the call was entered: Linux writes a `siginfo_t`
        /// to `info`, and Darwin an `int` to `sig`. `None` when that pointer
        /// is null, which both kernels test for, and then write nothing. On
        /// both flavours a destination the kernel cannot write fails the call
        /// with `EFAULT`, and the signal is taken all the same.
        Destination : UserBuffer option
    }

/// Which receiving call a `ParkedDatagramReceive` is, with what of its
/// arguments it still needs once it is woken.
[<RequireQualifiedAccess>]
type internal ParkedDatagramReceiveCall =
    /// `read(2)`.
    | Read
    /// `recv(2)`, peeking or not.
    | Receive of peek : bool
    /// `recvfrom(2)`, peeking or not, with Linux's `MSG_TRUNC` or not, and
    /// where its source goes: the source buffer, and the length cell, with
    /// what the cell held if the call read it before it slept. Darwin reads
    /// a cell that is not NULL before anything else, Linux only once it uses
    /// it.
    | ReceiveFrom of
        peek : bool *
        truncate : bool *
        source : UserBuffer *
        sourceLength : UserBuffer *
        lengthRead : uint32 option

/// One thread's in-flight blocking receive on a UDP socket that had nothing
/// to answer: a `read(2)`, `recv(2)` or `recvfrom(2)`.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none.
type ParkedDatagramReceive =
    internal
        {
            /// The open file description of the socket the call was made
            /// through, which it holds while it sleeps, and the descriptor it
            /// was made through; or the socket, once a Darwin close has ended
            /// the call.
            Socket : SleepTarget<SocketId>
            /// Where the datagram's bytes are to be copied out to, as the
            /// caller classified it when the call was entered.
            Buffer : UserBuffer
            /// The most bytes the call takes: its count, as at most one call's
            /// worth.
            Count : int
            Call : ParkedDatagramReceiveCall
            /// Under Linux, whether a datagram or the ICMP error arriving at
            /// the socket has chosen this call as the one sleeper it wakes
            /// (`WakePrimitive.DatagramReceivable`). Never under Darwin.
            Chosen : bool
        }

/// One thread's in-flight blocking send of a datagram on a Unix-domain socket
/// whose receiver, or whose own send buffer, had no room for it: a Linux
/// `write(2)`, `send(2)`, `sendto(2)` or `sendmsg(2)`.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.DatagramSend`.
type ParkedDatagramSend =
    internal
        {
            // What else it must hold is the datagram data path's design: the
            // datagram's destination, and which of Linux's two waits (the
            // receiver's queue, or the sender's buffer) it is in.
            /// The open file description of the socket the call was made
            /// through, which it holds while it sleeps.
            Socket : OpenFileDescriptionId
        }

/// One thread's in-flight blocking `connect(2)` to a listener whose accept queue
/// was full.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.Connect`.
type ParkedConnect =
    internal
        {
            // What else it must hold is the design of the connect that sleeps:
            // for TCP, the SYN retransmit schedule (the attempt, the next
            // deadline, the destination); for a Unix-domain stream, the
            // listener and the name the call looked up, which it looks up again
            // when it wakes (`docs/probes/connect-park`).
            /// The open file description of the connecting socket, through
            /// which the call was made, and which it holds while it sleeps.
            Socket : OpenFileDescriptionId
        }

/// When a Linux `futex(2)` wait (`FUTEX_WAIT_PRIVATE` or
/// `FUTEX_WAIT_BITSET_PRIVATE`) times out.
[<RequireQualifiedAccess>]
type FutexTimeout =
    /// The wait was made with no timeout: only a wake or a signal ends it.
    | Untimed
    /// The wait was made with a relative timeout (`FUTEX_WAIT_PRIVATE`), and
    /// answers `ETIMEDOUT` at this instant, in nanoseconds since boot. The call
    /// made again would time out later, so a restart that keeps this instant
    /// is not the call made again.
    | Until of nanosecondsSinceBoot : int64
    /// The wait was made with a timeout so long that Linux saturates it: at
    /// least `KTIME_SEC_MAX` (9223372036) seconds, or a relative one that ends
    /// past the last instant the clock can represent (`Int64.MaxValue`
    /// nanoseconds since boot). It never times out, so `UnixWait.deadlines`
    /// holds no deadline for it, but it is a wait with a timeout: a signal
    /// whose handler was installed with `SA_RESTART` still ends it with
    /// `EINTR`.
    | Unbounded
    /// The wait was made with an absolute timeout (`FUTEX_WAIT_BITSET_PRIVATE`),
    /// and answers `ETIMEDOUT` at this instant, in nanoseconds since boot,
    /// which may be before boot. A deadline on the realtime clock is converted
    /// as the call is made, which is exact because this kernel's realtime clock
    /// never steps (`UnixBootImage.withBootTime`). The call made again names
    /// the same instant.
    | At of nanosecondsSinceBoot : int64

[<RequireQualifiedAccess>]
module internal FutexTimeout =
    /// The instant a wait with `timeout` times out, if it ever does.
    let deadline (timeout : FutexTimeout) : int64 option =
        match timeout with
        | FutexTimeout.Until deadline
        | FutexTimeout.At deadline -> Some deadline
        | FutexTimeout.Untimed
        | FutexTimeout.Unbounded -> None

/// One thread's in-flight Linux `futex(2)` wait (`FUTEX_WAIT_PRIVATE` or
/// `FUTEX_WAIT_BITSET_PRIVATE`): the address it waits on, when it times out,
/// the bitset it waits with, and whether a wake has taken it off the queue of
/// that address.
///
/// A process's waiters on one address form one queue, in the order they
/// parked (`ThreadPark.Ordinal`). No other process's wake reaches it.
type ParkedFutex =
    {
        /// The user address the thread waits on.
        FutexAddress : uint64
        /// When the wait times out.
        FutexTimeout : FutexTimeout
        /// The bitset the thread waits with: a wake takes it only if the
        /// wake's own bitset shares a bit with this one. Never 0; a
        /// `FUTEX_WAIT_PRIVATE` waits with `FUTEX_BITSET_MATCH_ANY`
        /// (`0xFFFFFFFF`).
        FutexBitset : uint32
        /// Whether a `FUTEX_WAKE_PRIVATE` or `FUTEX_WAKE_BITSET_PRIVATE` has
        /// taken the thread off its queue, so that the wait answers 0, whatever
        /// else has woken it.
        TakenByWake : bool
    }

/// <summary>
/// The syscall a thread is blocked in, if it is blocked in one.
/// </summary>
/// <remarks>
/// One case per parking syscall.
///
/// This is stored as a single field on the thread holding it, because
/// a thread blocks in at most one syscall at a time.
///
/// Each case's payload is its own syscall's business: what parks a
/// thread is generally arbitrary state specific to that syscall.
/// </remarks>
[<RequireQualifiedAccess>]
type ParkedSyscall =
    | EpollWait of ParkedEpollWait
    | Kevent of ParkedKevent
    | Flock of ParkedFlock
    | Poll of ParkedPoll
    | KqueuePoll of ParkedKqueuePoll
    | Accept of ParkedAccept
    | PipeRead of ParkedPipeRead
    | PipeWrite of ParkedPipeWrite
    | ConnectionRead of ParkedConnectionRead
    | ConnectionWrite of ParkedConnectionWrite
    /// `sigsuspend(2)`, or `pause(2)`, which is `sigsuspend` with the mask the
    /// thread already has (`UnixSignal.pause`). Carries nothing: the temporary
    /// mask is the thread's mask while it sleeps, and the mask the call replaced
    /// is the signal state's (`SignalState.maskToRestore`), because it outlives
    /// the park, until the thread returns to user mode.
    | SigSuspend
    /// `nanosleep(2)`, or `clock_nanosleep(2)`. Waits for its deadline or for
    /// a signal with a handler, and holds no open file description.
    ///
    /// Reserved: nothing parks a thread in it yet, and no finishing call answers
    /// one. `UnixSystem.checkInvariants` reports a thread parked in it as a
    /// defect.
    | Sleep of ParkedSleep
    /// A blocking `open(2)` or `openat(2)` of one end of a FIFO, waiting for
    /// the other end to be opened or for a signal with a handler. Holds the
    /// open file description it made (`ParkedFifoOpen.Opener`).
    ///
    /// Reserved: nothing parks a thread in it yet, and no finishing call answers
    /// one. `UnixSystem.checkInvariants` reports a thread parked in it as a
    /// defect.
    | FifoOpen of ParkedFifoOpen
    /// A blocking `read(2)` of an inotify instance, waiting for a record or for
    /// a signal with a handler. Holds the instance (`ParkedInotifyRead.Instance`).
    | InotifyRead of ParkedInotifyRead
    /// `select(2)` or `pselect(2)`, waiting for a descriptor in one of its sets
    /// to be ready, for its deadline, or for a signal with a handler.
    ///
    /// Reserved: nothing parks a thread in it yet, and no finishing call answers
    /// one. `UnixSystem.checkInvariants` reports a thread parked in it as a
    /// defect.
    | Select of ParkedSelect
    /// `sigwait(3)`, `sigwaitinfo(2)` or `sigtimedwait(2)`: waiting for a
    /// signal in its set to be pending, for its deadline if it has one, or,
    /// under Linux, for a signal with a handler outside its set. Holds no open
    /// file description.
    ///
    /// Reserved: nothing parks a thread in it yet, and no finishing call answers
    /// one. `UnixSystem.checkInvariants` reports a thread parked in it as a
    /// defect.
    | SignalWait of ParkedSignalWait
    /// A blocking receive on a UDP socket, connected or not, through
    /// `read(2)`, `recv(2)` or `recvfrom(2)`: it sleeps until a datagram or
    /// the ICMP error arrives, on both flavours, or a signal with a handler
    /// interrupts it, or, under Darwin, a close ends it. Holds the socket's
    /// open file description until a close ends it.
    ///
    /// A Unix-domain datagram socket's receive, and `recvmsg(2)`, park no
    /// thread yet.
    | DatagramReceive of ParkedDatagramReceive
    /// A blocking send of a datagram on a Unix-domain socket, which under Linux
    /// sleeps while the receiver's queue or the sender's own buffer is full. A
    /// UDP send never sleeps, and a Darwin Unix-domain send that has no room
    /// fails with `ENOBUFS`. Holds the socket's open file description.
    ///
    /// Reserved: nothing parks a thread in it yet, and no finishing call answers
    /// one. `UnixSystem.checkInvariants` reports a thread parked in it as a
    /// defect.
    | DatagramSend of ParkedDatagramSend
    /// A blocking `connect(2)` to a listener whose accept queue is full, under
    /// Linux: a TCP connect sleeps until a retransmitted SYN finds room, and a
    /// Unix-domain stream connect until the listener has room or is gone. A
    /// Darwin connect never sleeps. Holds the connecting socket's open file
    /// description.
    ///
    /// Reserved: nothing parks a thread in it yet, and no finishing call answers
    /// one. `UnixSystem.checkInvariants` reports a thread parked in it as a
    /// defect.
    | Connect of ParkedConnect
    /// A Linux `futex(2)` wait (`FUTEX_WAIT_PRIVATE` or
    /// `FUTEX_WAIT_BITSET_PRIVATE`), waiting for a wake on its address to take
    /// it, for its deadline if it has one, or for a signal with a handler.
    /// Holds no open file description.
    | Futex of ParkedFutex

[<RequireQualifiedAccess>]
module ParkedSyscall =
    /// The open file descriptions the call holds while it is in flight, as a
    /// real syscall holds a reference to each file it found: each stays alive
    /// until the call returns, whatever descriptors are closed meanwhile.
    ///
    /// An accept, or a pipe or connection transfer, a Darwin close has ended
    /// (`SleepTarget.EndedByClose`) holds none: it returned, as far as the
    /// kernel is concerned, before the close did.
    ///
    /// A Linux `poll` holds every description it watches, as Linux's holds each
    /// file whose wait queue it sleeps on; a Darwin one holds none.
    let descriptions (parked : ParkedSyscall) : OpenFileDescriptionId list =
        match parked with
        | ParkedSyscall.EpollWait wait -> [ wait.Epoll ]
        | ParkedSyscall.Kevent wait -> [ wait.Kqueue ]
        | ParkedSyscall.Flock parked -> [ parked.Requester ]
        | ParkedSyscall.Poll poll ->
            poll.Entries
            |> List.choose (fun entry ->
                match entry with
                | ParkedPollEntry.Ignored _ -> None
                | ParkedPollEntry.Watched (_, description, _) -> Some description
            )
        // XNU's poll holds no file across its sleep: a filter it registered
        // goes when the descriptor it was registered through closes
        // (`knote_fdclose`), and the file with it if that was the last
        // reference. Measured (`poll-timeout.c` section E): a datagram sent to
        // the address of a socket closed under a sleeping Darwin poll wakes
        // nothing. The kqueue it made is its own (`ParkedKqueuePoll.Queue`).
        | ParkedSyscall.KqueuePoll _ -> []
        // A call a close has ended holds nothing: Darwin's close does not
        // return until the call has, and the call's reference goes as it does.
        | ParkedSyscall.Accept accept -> SleepTarget.description accept.Listener |> Option.toList
        | ParkedSyscall.PipeRead read -> SleepTarget.description read.Reader |> Option.toList
        | ParkedSyscall.PipeWrite write -> SleepTarget.description write.Writer |> Option.toList
        | ParkedSyscall.ConnectionRead read -> SleepTarget.description read.Socket |> Option.toList
        | ParkedSyscall.ConnectionWrite write -> SleepTarget.description write.Socket |> Option.toList
        | ParkedSyscall.SigSuspend
        | ParkedSyscall.Sleep _ -> []
        | ParkedSyscall.FifoOpen fifoOpen -> [ fifoOpen.Opener ]
        | ParkedSyscall.InotifyRead read -> [ read.Instance ]
        // Reserved, and holding nothing yet: Linux's will hold the description
        // behind each selected descriptor, as its `poll` does.
        | ParkedSyscall.Select _ -> []
        | ParkedSyscall.SignalWait _ -> []
        // Measured under Linux (`docs/probes/datagram-park`, row R3): a close
        // of the descriptor leaves a sleeping receive holding the socket.
        | ParkedSyscall.DatagramReceive receive -> SleepTarget.description receive.Socket |> Option.toList
        | ParkedSyscall.DatagramSend send -> [ send.Socket ]
        | ParkedSyscall.Connect connect -> [ connect.Socket ]
        | ParkedSyscall.Futex _ -> []

/// Where one park stands in the order every park on this machine was made in.
///
/// Minted from a counter the machine keeps as each thread parks, so of any two
/// threads parked at once, the one parked earlier holds the smaller ordinal.
/// A kernel that wakes one waiter of several reads this to decide which.
type ParkOrdinal =
    | ParkOrdinal of int64

    /// A human-readable description of the ordinal.
    override this.ToString () =
        match this with
        | ParkOrdinal.ParkOrdinal i -> $"<park #%i{i}>"

/// Whether a thread parked in a syscall still sleeps, or has been woken and has
/// yet to finish its call.
[<RequireQualifiedAccess>]
type ParkState =
    /// The thread sleeps. `UnixWait.wake` asks its call's wake condition, and
    /// wakes it once the condition holds.
    | Asleep
    /// `UnixWait.wake` has woken the thread, for `fired`, the primitives of its
    /// call's wake condition that held then, and the call's finishing function
    /// has not yet run. Never empty.
    ///
    /// On each queue its call waits on whose waiters a kernel wakes one at a
    /// time, the thread stands for whatever woke it, so no other waiter there
    /// wakes until the thread has finished its call or slept again.
    | Woken of fired : Set<WakePrimitive>

/// One thread's park: the syscall it is blocked in, where the park stands in the
/// order parks were made in, and whether the thread has been woken.
type ThreadPark =
    {
        /// The syscall the thread is blocked in, with the state it was entered with.
        Syscall : ParkedSyscall
        /// When the thread parked, relative to every other park.
        ///
        /// A re-park (a woken waiter that finds its condition gone and sleeps
        /// again) mints a fresh one, as a real kernel queues such a waiter
        /// afresh.
        Ordinal : ParkOrdinal
        /// Whether the thread still sleeps, or has been woken and has yet to
        /// finish its call.
        ///
        /// A park starts `ParkState.Asleep`, `UnixWait.wake` makes it
        /// `ParkState.Woken`, and only a woken thread's call is finished. A
        /// re-park is asleep again: the waiter waits for a new wake.
        State : ParkState
    }

/// What the emulated kernel knows about one thread — one scheduling entity, what
/// `gettid(2)` names.
///
/// A process starts with one, its leader (`ProcessLaunch.create`), every thread it creates adds
/// one (`UnixThreadLifecycle.spawn`), and the thread's exit removes it
/// (`UnixThreadLifecycle.exitThread`), so the table holds an entry for each thread
/// from its creation until its exit. That is what makes the record total:
/// `Cpu` and `OsThreadId` have no truthful default, so a `Map` of each would
/// have no honest answer for an absent key, and the answer is that there is
/// never an absent key rather than that a default exists.
///
/// The per-thread errno is *not* here. On a real Unix errno lives in libc, not
/// in the kernel: the kernel returns an error code and the syscall wrapper
/// stores it, so the slot belongs to the client.
type UnixThreadState =
    internal
        {
            /// The simulated logical processor this thread last ran on, or, before
            /// the client first dispatches it, the one its creator named to
            /// `UnixThreadLifecycle.spawn`, or to `ProcessLaunch.create` for a
            /// process's leader: Linux's `task_cpu`. Always one the machine has,
            /// in `[0, UnixMachineState.ProcessorCount)`.
            ///
            /// Only `UnixScheduling.dispatch` changes it. A thread keeps it when it
            /// stops running, by parking or by another thread's dispatch to the
            /// processor, as a blocked Linux thread keeps its last processor
            /// (`docs/plans/2026-08-23-posix-kernel-extraction/cpu-placement.c`,
            /// section `sleeper`). Whether the thread is running there is the
            /// machine's record (`UnixSchedulingState.Occupants`), which
            /// `UnixScheduling.runningOn` reads; `sched_getcpu(3)` reports this
            /// only while the thread runs.
            Cpu : CpuId
            /// The OS thread identifier this thread reports, as `gettid(2)` does.
            ///
            /// Minted by the machine's `ThreadIdAllocator` when the thread is created,
            /// and fixed from then on. No two live threads share one. On Linux an exited
            /// thread's id comes back once the counter wraps at `pid_max`, so a stale
            /// owner identity recorded by a user-space lock can then be mistaken for a
            /// live owner, as it can on a real Linux.
            OsThreadId : OsThreadId
            /// The syscall this thread is blocked in, and where that park stands in park
            /// order, if it is blocked in one.
            ///
            /// A real kernel holds a blocked thread's in-flight syscall arguments on
            /// its stack; this is that. Three readers, and they must agree, which is
            /// why there is one of it: the re-entry consults it rather than the
            /// caller's argument cells, which the process may have written since;
            /// whatever a client polls to decide the call can be finished reads it
            /// to learn what the call is waiting for; and the machine's open file
            /// table counts a hold on each description it names
            /// (`ParkedSyscall.descriptions`, `OpenFileTable.holdCount`), so the
            /// description lives until the call returns.
            ///
            /// Every payload holds kernel objects by *identity*, never by descriptor
            /// number: a sleeping thread keeps the object rather than the number, and
            /// descriptor numbers are reused as soon as they are free.
            Parked : ThreadPark option
            /// Why the thread must return to user mode before it makes another
            /// call, if it must: a signal interrupted its last call, or a signal
            /// is deliverable to it. `UnixSignal.onReturnToUser` clears it. Never
            /// set on a parked thread: a thread parks only in a call, which it
            /// cannot make while it owes a return, and takes a signal only once
            /// it has left the park.
            Owes : OwedReturn option
        }

/// Reading one thread.
///
/// A client gets a thread's state by looking its name up in `UnixSystem.threads`,
/// which holds no entry for a name the process has no thread by, so each reader
/// here answers for every state it can be given.
[<RequireQualifiedAccess>]
module UnixThreadState =

    /// The logical processor `thread` last ran on, or, before the client first
    /// dispatched it (`UnixScheduling.dispatch`), the one its creator named.
    /// Whether it is running there now is `UnixScheduling.runningOn`'s answer.
    let cpu (thread : UnixThreadState) : CpuId = thread.Cpu

    /// The OS thread ID `thread` reports, as `gettid(2)` does: fixed when the
    /// thread is created, and held by no other live thread on the machine.
    let osThreadId (thread : UnixThreadState) : OsThreadId = thread.OsThreadId

    /// The syscall `thread` is blocked in, and where that park stands in park
    /// order, if it is blocked in one. The park holds kernel objects by
    /// identity, never by descriptor number: a sleeping thread keeps the object
    /// rather than the number, and descriptor numbers are reused as soon as
    /// they are free.
    let park (thread : UnixThreadState) : ThreadPark option = thread.Parked

    /// The syscall `thread` is blocked in, if it is blocked in one: `park`
    /// without its place in park order.
    let parkedIn (thread : UnixThreadState) : ParkedSyscall option =
        thread.Parked |> Option.map (fun park -> park.Syscall)

/// The threads one process owns, by whatever a client uses to name one, with
/// the names of those parked in a syscall.
///
/// Its representation is private to this file, so that the functions of
/// `UnixThreadTable`, which keep the names of the parked threads with every
/// change to a thread, are the only way to change one; a sweep of the sleeping
/// threads (`UnixWait.wake`) reads those names rather than every thread.
type internal ThreadTable<'Thread when 'Thread : comparison> =
    private
        {
            /// Every thread of the process, by its name.
            ByName : Map<'Thread, UnixThreadState>
            /// The names of the threads in `ByName` whose `Parked` is `Some`,
            /// and of no others.
            ParkedNames : Set<'Thread>
        }

/// The threads a simulated process owns, by whatever a client uses to name one.
///
/// Generic in the thread name for the same reason `SignalState` is: the identity
/// of a scheduling entity is the client's, not this library's.
[<RequireQualifiedAccess>]
module UnixThreadTable =

    /// A process's threads before it has any.
    let internal empty<'Thread when 'Thread : comparison> : ThreadTable<'Thread> =
        {
            ByName = Map.empty
            ParkedNames = Set.empty
        }

    /// Every thread of `table`, by its name.
    let internal byName<'Thread when 'Thread : comparison>
        (table : ThreadTable<'Thread>)
        : Map<'Thread, UnixThreadState>
        =
        table.ByName

    /// The names of the threads of `table` that are parked in a syscall, asleep
    /// or woken.
    let internal parked<'Thread when 'Thread : comparison> (table : ThreadTable<'Thread>) : Set<'Thread> =
        table.ParkedNames

    /// The names of the threads of `threads` that are parked in a syscall,
    /// found by asking every thread.
    let private parkedOf<'Thread when 'Thread : comparison> (threads : Map<'Thread, UnixThreadState>) : Set<'Thread> =
        (Set.empty, threads)
        ||> Map.fold (fun parked name state ->
            match state.Parked with
            | Some _ -> Set.add name parked
            | None -> parked
        )

    /// The table of exactly the threads `threads` holds.
    let internal ofMap<'Thread when 'Thread : comparison>
        (threads : Map<'Thread, UnixThreadState>)
        : ThreadTable<'Thread>
        =
        {
            ByName = threads
            ParkedNames = parkedOf threads
        }

    /// Whether the names `table` keeps of its parked threads are those a scan
    /// of every thread finds.
    let internal parkedNamesFresh<'Thread when 'Thread : comparison> (table : ThreadTable<'Thread>) : bool =
        parkedOf table.ByName = table.ParkedNames

    /// `table` with `name`'s thread as `state`, and `name` among the parked
    /// threads' names exactly if `state` is parked: the one way a thread is
    /// written.
    let private put<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (state : UnixThreadState)
        (table : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let parkedNames =
            match state.Parked with
            | Some _ when not (Set.contains name table.ParkedNames) -> Set.add name table.ParkedNames
            | None when Set.contains name table.ParkedNames -> Set.remove name table.ParkedNames
            | Some _
            | None -> table.ParkedNames

        {
            ByName = Map.add name state table.ByName
            ParkedNames = parkedNames
        }

    /// `table` without `name`'s thread, which has exited; `table` itself if it
    /// has no thread by that name.
    ///
    /// Fails loudly if the thread is parked: a thread leaves its park before it
    /// leaves the table, since its park holds descriptions only the park's end
    /// lets go of (`UnixParkState.unpark`).
    let internal remove<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (table : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        match Map.tryFind name table.ByName with
        | None -> table
        | Some {
                   Parked = Some park
               } ->
            failwith
                $"UnixThreadTable.remove: thread %O{name} is leaving the table while parked in %A{park.Syscall}. A thread leaves its park, which lets go of what the park holds, before it exits (this is a bug in this library)."
        | Some _ ->
            {
                ByName = Map.remove name table.ByName
                ParkedNames = table.ParkedNames
            }

    /// The thread `name` is, or `None` if `table` has no thread by that name.
    let internal tryFind<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (table : ThreadTable<'Thread>)
        : UnixThreadState option
        =
        Map.tryFind name table.ByName

    /// Whether `table` has a thread named `name`.
    let internal contains<'Thread when 'Thread : comparison> (name : 'Thread) (table : ThreadTable<'Thread>) : bool =
        Map.containsKey name table.ByName

    /// The thread `name` is.
    ///
    /// Total, and loudly partial rather than an option: every thread is added
    /// when it is created and removed only when it exits, so a name that
    /// resolves to nothing is a client bug rather than anything a process did.
    let internal get<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : UnixThreadState
        =
        // `TryGetValue` rather than `Map.tryFind`, whose option a client that asks once per
        // instruction (`UnixScheduling.dispatch`) would allocate every time.
        let mutable thread = Unchecked.defaultof<UnixThreadState>

        if threads.ByName.TryGetValue (name, &thread) then
            thread
        else
            failwith
                $"UnixThreadTable.get: %O{name} names no thread. Every thread enters the table when it is created, as its process's leader or by `UnixThreadLifecycle.spawn`, and leaves it when the thread exits, so this one was never created or has already exited (this is a bug in the client)."

    /// Add the thread for a newly-created scheduling entity.
    ///
    /// Internal so that the only routes by which a thread enters the table are
    /// a process's launch and `UnixThreadLifecycle.spawn`, which mint its id.
    let internal add<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (cpu : CpuId)
        (osThreadId : OsThreadId)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        if Map.containsKey name threads.ByName then
            failwith
                $"UnixThreadTable.add: %O{name} already names a thread. A thread is created once, and adding it again would silently discard whatever the first creation recorded (this is a bug in the client)."

        put
            name
            {
                Cpu = cpu
                OsThreadId = osThreadId
                Parked = None
                Owes = None
            }
            threads

    /// The syscall `name` is blocked in, if any. Fails loudly, as `get` does,
    /// for a name that is not a thread; a client reads `UnixThreadState.parkedIn`
    /// of the state it looked up instead.
    let internal parkedFor<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : ParkedSyscall option
        =
        UnixThreadState.parkedIn (get name threads)

    /// The park `name` is in, with its place in park order, if it is parked.
    let internal parkOf<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : ThreadPark option
        =
        (get name threads).Parked

    /// The thread `name` is, failing with `InvalidOperationException` unless it
    /// is one of `threads`: `operation` names the function the client called,
    /// which only one of the process's threads may call.
    let internal requireThread<'Thread when 'Thread : comparison>
        (operation : string)
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : UnixThreadState
        =
        // `TryGetValue` rather than `Map.tryFind`, as in `get`: every read and
        // write asks this.
        let mutable thread = Unchecked.defaultof<UnixThreadState>

        if not (threads.ByName.TryGetValue (name, &thread)) then
            invalidOp
                $"%s{operation}: thread %O{name} is not one of the process's threads: the thread table names no thread %O{name}, which was never created or has already exited (this is a bug in the client)."

        thread

    /// Fails with `InvalidOperationException` unless `name` is a thread asleep
    /// in no syscall and owing no return to user mode, as the thread making a
    /// call must be: `operation` names the function the client called. A thread
    /// blocks in one syscall at a time, and a call it is asleep in is finished,
    /// not made again; and a thread runs its own code, which is what makes a
    /// call, only once it has returned to user mode.
    let internal requireIssuer<'Thread when 'Thread : comparison>
        (operation : string)
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : unit
        =
        let thread = requireThread operation name threads

        match thread.Parked, thread.Owes with
        | Some park, _ ->
            invalidOp
                $"%s{operation}: thread %O{name} is parked in %A{park.Syscall}, and is making another call. A thread blocks in one syscall at a time: the call it is parked in is finished by that call's finishing function, not made again, and that call's completion must clear its record before the thread makes any other (this is a bug in the client)."
        | None, Some (OwedReturn.Interrupted interruption) ->
            invalidOp
                $"%s{operation}: thread %O{name} is making a call, but a signal (%O{interruption.Signal}) interrupted its last call, and it has not returned to user mode since. That return decides how the interrupted call ends, and a thread makes a call only from user mode: the client calls `UnixSignal.onReturnToUser` for it first (this is a bug in the client)."
        | None, Some OwedReturn.SignalDue ->
            invalidOp
                $"%s{operation}: thread %O{name} is making a call, but a signal is deliverable to it, which it takes as it returns to user mode, and it has not returned since. A thread runs no more of its own code, so makes no call, before it takes a signal deliverable to it: the client calls `UnixSignal.onReturnToUser` for it first (this is a bug in the client)."
        | None, None -> ()

    /// Fails with `InvalidOperationException` unless `name` is a thread asleep
    /// in no syscall, as a thread returning to user mode must be: `operation`
    /// names the function the client called. A thread asleep in a syscall
    /// returns to user mode only once the syscall has answered.
    let internal requireReturning<'Thread when 'Thread : comparison>
        (operation : string)
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : unit
        =
        match (requireThread operation name threads).Parked with
        | Some park ->
            invalidOp
                $"%s{operation}: thread %O{name} is asleep in %A{park.Syscall}, so it is not returning to user mode. A signal ends that sleep through the syscall's finishing call (this is a bug in the client)."
        | None -> ()

    /// The syscall `name` is parked in, failing with `InvalidOperationException`
    /// unless it is a thread parked in one: `operation` names the finishing
    /// function the client called, which only a thread whose call answered
    /// `WouldBlock` may call.
    let internal requireParked<'Thread when 'Thread : comparison>
        (operation : string)
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : ParkedSyscall
        =
        match (requireThread operation name threads).Parked with
        | None ->
            invalidOp
                $"%s{operation}: thread %O{name} is not parked, so there is no call to finish. Only a thread whose call answered `WouldBlock` finishes one here (this is a bug in the client)."
        | Some park -> park.Syscall

    /// Fails with `InvalidOperationException` unless `name` is a thread parked
    /// in a syscall that `UnixWait.wake` has woken, as the thread whose call a
    /// finishing function finishes must be: `operation` names the finishing
    /// function the client called.
    let internal requireWoken<'Thread when 'Thread : comparison>
        (operation : string)
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : unit
        =
        match (requireThread operation name threads).Parked with
        | None ->
            invalidOp
                $"%s{operation}: thread %O{name} is not parked, so there is no call to finish. Only a thread whose call answered `WouldBlock`, and which `UnixWait.wake` has since woken, finishes one here (this is a bug in the client)."
        | Some {
                   Syscall = parked
                   State = ParkState.Asleep
               } ->
            invalidOp
                $"%s{operation}: thread %O{name} is asleep in %A{parked}, and nothing has woken it. `UnixWait.wake` wakes a thread once its call can get further, and only a woken thread's call is finished (this is a bug in the client)."
        | Some {
                   State = ParkState.Woken _
               } -> ()

    /// What `choose` answers for the syscall `name` is parked in, failing with
    /// `InvalidOperationException` as `requireParked` does, or if `choose`
    /// answers `None` for that syscall: `operation` names the finishing function
    /// the client called.
    let internal expectParked<'Thread, 'Expected when 'Thread : comparison>
        (operation : string)
        (choose : ParkedSyscall -> 'Expected option)
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : 'Expected
        =
        let parked = requireParked operation name threads

        match choose parked with
        | Some expected -> expected
        | None ->
            invalidOp
                $"%s{operation}: thread %O{name} is parked in %A{parked}, which is not a call this finishes (this is a bug in the client)."

    /// Record that `name` is in `park`.
    ///
    /// Refuses to replace a park of one syscall with a park of another. A thread
    /// runs no user code between a wake and its re-entry into the syscall it
    /// woke from, so the only lawful writes are onto an absent record and onto a
    /// park of the same syscall — the re-park a beaten waiter performs. Anything
    /// else means a completion path failed to clear its record, and without this
    /// the next park would quietly overwrite the evidence: the invariant check is
    /// a test-time oracle, so this is where a live run gets told.
    ///
    /// Equality is deliberately not required of a same-syscall re-park. A
    /// re-parking call may lawfully revise its own re-entry state — a timeout
    /// with less of itself left to run is the obvious future instance — and that
    /// is the syscall's business rather than this table's.
    ///
    /// Refuses too a write that moves a park's state other than as a wake and a
    /// re-park move it. A park onto an absent record is asleep. A write that
    /// keeps the park's ordinal rewrites the park in place, as a Darwin close
    /// rewrites the call it ends, and keeps its state. A write with a fresh
    /// ordinal is a re-park, which only a woken thread's finishing call makes,
    /// and puts the thread asleep again. `markWoken` is the one way a park
    /// becomes woken.
    ///
    /// The table alone: it moves no hold on an open file description. Internal
    /// so that `Parking.park`, which mints the ordinal, and `UnixParkState`,
    /// which moves the holds, are the ways a park is written.
    let internal withPark<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (park : ThreadPark)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let existing = get name threads

        match existing.Owes with
        | Some owed ->
            failwith
                $"UnixThreadTable.withPark: thread %O{name} owes a return to user mode (%A{owed}), and is being parked in %A{park}. A thread parks only in a call it makes, which it cannot make before that return (this is a bug in this library)."
        | None -> ()

        // Which syscall a park is of, and nothing else about it.
        let kind (parked : ParkedSyscall) : int =
            match parked with
            | ParkedSyscall.EpollWait _ -> 0
            | ParkedSyscall.Flock _ -> 1
            | ParkedSyscall.Poll _ -> 2
            | ParkedSyscall.Accept _ -> 3
            | ParkedSyscall.PipeRead _ -> 4
            | ParkedSyscall.PipeWrite _ -> 5
            | ParkedSyscall.Kevent _ -> 6
            | ParkedSyscall.KqueuePoll _ -> 7
            | ParkedSyscall.ConnectionRead _ -> 8
            | ParkedSyscall.ConnectionWrite _ -> 9
            | ParkedSyscall.SigSuspend -> 10
            | ParkedSyscall.Sleep _ -> 11
            | ParkedSyscall.FifoOpen _ -> 12
            | ParkedSyscall.InotifyRead _ -> 13
            | ParkedSyscall.Select _ -> 14
            | ParkedSyscall.SignalWait _ -> 15
            | ParkedSyscall.DatagramReceive _ -> 16
            | ParkedSyscall.DatagramSend _ -> 17
            | ParkedSyscall.Connect _ -> 18
            | ParkedSyscall.Futex _ -> 19

        let sameSyscall =
            match existing.Parked with
            | None -> true
            | Some existing -> kind existing.Syscall = kind park.Syscall

        if not sameSyscall then
            failwith
                $"UnixThreadTable.withPark: thread %O{name} is parked in %A{existing.Parked} and something is parking it in %A{park} without clearing the first. A thread blocks in one syscall at a time, so the earlier park's completion failed to clear its record."

        match existing.Parked, park.State with
        | None, ParkState.Asleep -> ()
        | None, ParkState.Woken _ ->
            failwith
                $"UnixThreadTable.withPark: thread %O{name} is parking in %A{park}, woken already. A park starts asleep, and only `UnixWait.wake` wakes it (this is a bug in this library)."
        | Some before, _ when before.Ordinal = park.Ordinal ->
            if before.State <> park.State then
                failwith
                    $"UnixThreadTable.withPark: thread %O{name}'s park %A{before} is being rewritten in place as %A{park}, which changes its state. A rewrite keeps the park's state, and only `UnixWait.wake` wakes a park (this is a bug in this library)."
        | Some {
                   State = ParkState.Woken _
               },
          ParkState.Asleep -> ()
        | Some before, _ ->
            failwith
                $"UnixThreadTable.withPark: thread %O{name} is parked in %A{before} and is being parked again as %A{park}. A re-park is a woken thread's going back to sleep, so it is made only of a woken park, and is asleep (this is a bug in this library)."

        put
            name
            { existing with
                Parked = Some park
            }
            threads

    /// Record that `UnixWait.wake` has woken `name`, asleep in a syscall, for
    /// `fired`, the primitives of its call's wake condition that hold: its park
    /// keeps its syscall and its place in park order, and becomes
    /// `ParkState.Woken`.
    ///
    /// Fails loudly unless `name` is parked and asleep, and if `fired` is
    /// empty: a thread is woken for something.
    let internal markWoken<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (fired : Set<WakePrimitive>)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let existing = get name threads

        if Set.isEmpty fired then
            failwith
                $"UnixThreadTable.markWoken: thread %O{name} is being woken for nothing. A thread wakes once a primitive of its wake condition holds (this is a bug in this library)."

        match existing.Parked with
        | Some ({
                    State = ParkState.Asleep
                } as park) ->
            put
                name
                { existing with
                    Parked =
                        Some
                            { park with
                                State = ParkState.Woken fired
                            }
                }
                threads
        | Some park ->
            failwith
                $"UnixThreadTable.markWoken: thread %O{name} is in %A{park}, woken already, and is being woken again for %A{fired} (this is a bug in this library)."
        | None ->
            failwith
                $"UnixThreadTable.markWoken: thread %O{name} is parked in no syscall, and is being woken for %A{fired} (this is a bug in this library)."

    /// What `name` owes before it makes another call, if anything: see
    /// `UnixThreadState.Owes`.
    let internal owedBy<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : OwedReturn option
        =
        (get name threads).Owes

    /// Record that `name` must return to user mode, for `owed`, before it makes
    /// another call.
    ///
    /// Fails loudly if `name` is parked, or already owes a return: a thread
    /// owes one only once its call has answered, and the return clears it
    /// before the thread can make another.
    let internal owe<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (owed : OwedReturn)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let existing = get name threads

        match existing.Parked, existing.Owes with
        | Some park, _ ->
            failwith
                $"UnixThreadTable.owe: thread %O{name} is parked in %A{park.Syscall}, so it is not returning to user mode, and cannot owe that return %A{owed} (this is a bug in this library)."
        | None, Some before ->
            failwith
                $"UnixThreadTable.owe: thread %O{name} already owes a return to user mode (%A{before}), and is being marked again (%A{owed}); a return clears the first before the thread can make the call that would set the second (this is a bug in this library)."
        | None, None ->
            put
                name
                { existing with
                    Owes = Some owed
                }
                threads

    /// Record that `name` has returned to user mode: it owes nothing.
    let internal settle<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let existing = get name threads

        match existing.Owes with
        | None -> threads
        | Some _ ->
            put
                name
                { existing with
                    Owes = None
                }
                threads

    /// Record that `name` is no longer parked: its syscall has finished.
    ///
    /// The table alone: the holds the park took stay recorded in the open file
    /// table, where `UnixSystem.checkInvariants` reports them
    /// (`HoldCountMismatch`). `UnixParkState.unpark` ends a park and lets go of
    /// its holds.
    let internal unpark<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let existing = get name threads

        put
            name
            { existing with
                Parked = None
            }
            threads

    /// Record that `name` last ran on `cpu`: see `UnixThreadState.Cpu`.
    let internal withCpu<'Thread when 'Thread : comparison>
        (name : 'Thread)
        (cpu : CpuId)
        (threads : ThreadTable<'Thread>)
        : ThreadTable<'Thread>
        =
        let existing = get name threads

        put
            name
            { existing with
                Cpu = cpu
            }
            threads

    /// Compare the table against the threads a client believes are live,
    /// answering those it has no entry for and those it has an entry for but
    /// the client does not.
    ///
    /// Answers both sets rather than raising, so the client reports them in its
    /// own vocabulary: this library has no opinion on what a defect is called.
    let reconcile<'Thread when 'Thread : comparison>
        (live : Set<'Thread>)
        (threads : Map<'Thread, UnixThreadState>)
        : 'Thread list * 'Thread list
        =
        let named = threads |> Map.toList |> List.map fst |> Set.ofList
        Set.difference live named |> Set.toList, Set.difference named live |> Set.toList
