namespace WoofWare.PosixKernel

/// One thing a thread parked in a syscall can be waiting for, which holds or does
/// not of a given system.
///
/// A primitive names live kernel objects rather than a snapshot of them, and
/// stays true to what a real kernel waits on rather than to what is convenient
/// to evaluate. The park a primitive comes from holds the open file
/// descriptions it names (`ParkedSyscall.descriptions`), so they stay alive
/// while something waits on them.
[<RequireQualifiedAccess>]
type WakePrimitive =
    /// An `flock` acquisition of `mode` by the open file description
    /// `requester`, parked because another description naming the same object
    /// holds a conflicting lock.
    ///
    /// Note what this does *not* say: nothing about which description obstructs
    /// it. A waiter waits for its lock to become available, not for a particular
    /// holder to go away — a new acquirer between the release and the wake puts
    /// it back to sleep, as it does on a real kernel.
    ///
    /// `requester` is the open file description rather than the descriptor the
    /// call was made through, because the lock belongs to the description: a
    /// `dup` of that descriptor waits on the same lock, and the number itself is
    /// reusable while the description lives on.
    | FlockGrantable of requester : OpenFileDescriptionId * mode : FlockMode
    /// A wait for events on the epoll instance the open file description
    /// `epoll` names, parked because the instance had nothing to deliver.
    ///
    /// Carries no event count, unlike the record a client parks with: how many
    /// events the caller asked for decides what the *finishing* call copies out,
    /// and says nothing about whether it can finish at all. A single deliverable
    /// event satisfies a wait for any number of them.
    ///
    /// `epoll` is the open file description rather than the descriptor, for the
    /// reason `FlockGrantable`'s requester is: the number can be closed and
    /// reused while the wait sleeps, and a `dup` of it waits on the same epoll instance.
    | EpollEventDeliverable of epoll : OpenFileDescriptionId
    /// The kqueue the open file description `kqueue` names has been drained:
    /// a `close(2)` of a descriptor a `kevent` wait on it was entered through
    /// has ended every wait on it (see `UnixDescriptor.close`).
    | KqueueDrained of kqueue : OpenFileDescriptionId
    /// A wait for events on the kqueue the open file description `kqueue`
    /// names would report at least one now.
    ///
    /// Every waiter on one kqueue wakes for it, and the first to finish takes
    /// what it reports; the rest wait again.
    | KqueueEventDeliverable of kqueue : OpenFileDescriptionId
    /// The open file description `description` presents at least one of
    /// `conditions`, in the numbering `<poll.h>` and `<sys/epoll.h>` share.
    ///
    /// What a `poll(2)` entry waits for, with `conditions` its request plus the
    /// `POLLERR` and `POLLHUP` a poll reports unasked. It never waits on a
    /// epoll instance, whose level is not modelled.
    | DescriptorReady of description : OpenFileDescriptionId * conditions : uint32
    /// The Darwin `poll` the waiting thread is asleep in would report something
    /// were it to scan the kqueue it made for itself now.
    ///
    /// Names no kernel object, as `SignalDeliverable` names none: the kqueue
    /// is the waiter's own, named by its park (`ParkedKqueuePoll.Queue`). Holds only
    /// once a scan would add something to some entry's `revents`: a filter
    /// activated whose report would add nothing does not wake the waiter here,
    /// where a real kernel wakes it to find nothing and sleep again, having
    /// consumed the registration. Answering when the waiter next scans is the
    /// schedule in which it had not yet run.
    | KqueuePollReportable
    /// The listening socket the open file description `listener` names holds a
    /// completed connection in its accept queue.
    ///
    /// What a blocking `accept(2)` waits for. `listener` is the description
    /// rather than the socket, as for the other primitives: it is what the call
    /// holds.
    | AcceptQueueNonEmpty of listener : OpenFileDescriptionId
    /// The pipe whose read end the open file description `reader` names holds
    /// bytes.
    ///
    /// What a blocking `read(2)` of an empty pipe waits for, beside
    /// `PipeWriteEndClosed`. Two primitives rather than one because a kernel
    /// wakes its sleeping readers differently for the two: bytes arriving wake
    /// one of them on Linux, and the last writer closing wakes them all.
    | PipeHasBytes of reader : OpenFileDescriptionId
    /// The pipe whose read end the open file description `reader` names has no
    /// write end open, so a read of it answers end of file.
    | PipeWriteEndClosed of reader : OpenFileDescriptionId
    /// The pipe whose write end the open file description `writer` names has
    /// room for a sleeping write of `count` bytes, the first `written` of them
    /// already in, to put more in.
    ///
    /// What a blocking `write(2)` into a pipe with no room for the rest of it
    /// waits for, beside `PipeReadEndClosed`. Carries the write's progress
    /// because whether a write of at most `PIPE_BUF` bytes can resume depends on
    /// how many it has to put in, which it takes whole or not at all.
    | PipeHasRoom of writer : OpenFileDescriptionId * count : int * written : int
    /// The pipe whose write end the open file description `writer` names has
    /// no read end open, so a write into it answers `EPIPE`.
    | PipeReadEndClosed of writer : OpenFileDescriptionId
    /// Under Darwin, the open file description `writer` carries `O_NONBLOCK`,
    /// and a read has taken bytes from the pipe whose write end it names since
    /// it had seen `reads` of them (`PipeState.Reads`). Never under Linux.
    ///
    /// Darwin wakes every writer asleep on a pipe at each read, room or not,
    /// and one that still cannot write, through a description that has become
    /// non-blocking, gives up; Linux wakes a writer only once it can write.
    /// What a write of at most `PIPE_BUF` bytes waits for besides room for all
    /// of it, which `PipeHasRoom` is.
    | PipeReadWhileNonBlocking of writer : OpenFileDescriptionId * reads : int64
    /// The connected stream socket the open file description `reader` names
    /// has an answer for a read: bytes, a FIN or a reset.
    ///
    /// What a blocking `read(2)` of a connected socket with nothing to answer
    /// waits for. One primitive, unlike a pipe's two, because every reader
    /// asleep on a socket wakes for each of them, under either flavour.
    | ConnectionReadable of reader : OpenFileDescriptionId
    /// The connected stream socket the open file description `writer` names
    /// wakes a write asleep with `remaining` of its bytes not yet taken: room,
    /// by the flavour's rule, or a reset.
    ///
    /// What a blocking `write(2)` to a connected socket with no room for the
    /// rest of it waits for. Carries what is left because Darwin's rule
    /// depends on it: room for all of a short remainder wakes the writer, and
    /// otherwise only room of the send buffer's low-water mark does.
    | ConnectionWritable of writer : OpenFileDescriptionId * remaining : int
    /// Under Darwin, a close has ended the blocking `accept`, or the blocking
    /// `read` or `write` of a pipe or a connected socket, the waiting thread is
    /// asleep in (`SleepTarget.EndedByClose`).
    ///
    /// Names no kernel object, as `SignalDeliverable` names none: the call
    /// holds none any more, and what it answers is in the waiter's own park.
    /// Every wait of those calls waits for it, so that a condition handed
    /// out as the call went to sleep still says when the close ends it. Never
    /// holds under Linux, whose close leaves such a call asleep.
    | EndedByClose
    /// The machine's monotonic clock (`UnixSystem.nanosecondsSinceBoot`)
    /// has reached `nanosecondsSinceBoot`.
    ///
    /// Absolute rather than relative, so that it means the same instant however
    /// often it is asked: a syscall's relative timeout becomes one of these when
    /// the call parks.
    | DeadlinePassed of nanosecondsSinceBoot : int64
    /// A signal with a handler is deliverable to the thread that waits: were it to
    /// return to user mode now, it would run that handler. For a thread in
    /// `sigsuspend`, any signal its temporary mask lets through that its
    /// finishing call would act on.
    ///
    /// Names no kernel object, because what it asks about is the waiter itself:
    /// a condition is always some thread's, and `satisfied` is told whose. Every
    /// park waits for it, since every sleep this library models is one a signal
    /// interrupts; `SyscallInterruption.ruleOf` says how the interrupted call
    /// then ends.
    | SignalDeliverable
    /// The FIFO whose end the open file description `opener` names has seen
    /// more than `opens` opens of the other end: of the write end for an
    /// `opener` opened for reading, and of the read end for one opened for
    /// writing. One opened for both never sleeps.
    ///
    /// What a blocking open of one end of a FIFO waits for. A count rather
    /// than "a partner is open" because a partner that opens and closes again
    /// before the sleeper runs still completes its open, on both flavours.
    /// `opener` is the description the sleeping call made and holds
    /// (`ParkedFifoOpen.Opener`).
    ///
    /// Reserved: nothing parks a thread in a FIFO open yet, so no condition this
    /// library hands out contains it.
    | FifoPartnerOpened of opener : OpenFileDescriptionId * opens : int64
    /// The inotify instance the open file description `reader` names holds a
    /// record.
    ///
    /// What a blocking `read(2)` of an instance that held none waits for.
    /// Every reader asleep on the instance wakes for it, and the first to run
    /// takes the record, which a change to what the instance watches queues,
    /// in any process, or `inotify_rm_watch(2)`.
    | InotifyRecordQueued of reader : OpenFileDescriptionId
    /// A signal in `awaited` is pending to the thread that waits.
    ///
    /// What a signal wait (`sigwait(3)`, `sigwaitinfo(2)`, `sigtimedwait(2)`)
    /// waits for. `awaited` is the call's set (`ParkedSignalWait.Awaited`).
    /// Not `SignalDeliverable`: an awaited signal is taken by the call rather
    /// than delivered, and is commonly blocked, or at its default action.
    ///
    /// Reserved: nothing parks a thread in a signal wait yet, so no condition
    /// this library hands out contains it.
    | AwaitedSignalPending of awaited : SignalMask
    /// The listening socket `listener` has room in its accept queue for one
    /// more connection, or can no longer take one: it has been closed or shut
    /// down, so that a connect asleep on it wakes to be refused.
    ///
    /// What a blocking Linux Unix-domain stream `connect(2)` to a full listener
    /// waits for. Names the listener by the machine's identity for the socket,
    /// since the sleeping call holds the socket and no description of it. A
    /// TCP connect to a full listener waits for its SYN retransmit instead
    /// (`DeadlinePassed`), and looks for room only then.
    ///
    /// Reserved: nothing parks a thread in a connect yet, so no condition this
    /// library hands out contains it.
    | AcceptQueueHasRoom of listener : SocketId
    /// A `FUTEX_WAKE_PRIVATE` has taken the waiting thread off the queue of the
    /// address its `FUTEX_WAIT_PRIVATE` waits on (`ParkedFutex.TakenByWake`).
    ///
    /// Names no kernel object, as `SignalDeliverable` names none: what it asks
    /// about is the waiter's own park, which the wake marks. A wake chooses its
    /// waiters as it is made, so once this holds it holds until the wait
    /// returns.
    | FutexWakeTaken
