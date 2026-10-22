namespace WoofWare.PosixKernel

/// What finishing a woken `nanosleep(2)` or `clock_nanosleep(2)` answers:
/// what `FinishedCall.Sleep` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.Sleep`.
[<NoEquality ; NoComparison>]
type FinishedSleep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the sleep's finishing function
    // (`docs/design/nanosleep-options.md`).
    internal | FinishedSleep

/// What finishing a woken blocking `open(2)` of one end of a FIFO answers:
/// what `FinishedCall.FifoOpen` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.FifoOpen`.
[<NoEquality ; NoComparison>]
type FinishedFifoOpen<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the FIFO open's finishing function
    // (`docs/design/fifo-open-options.md`).
    internal | FinishedFifoOpen

/// What finishing a woken `select(2)` or `pselect(2)` answers: what
/// `FinishedCall.Select` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.Select`.
[<NoEquality ; NoComparison>]
type FinishedSelect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the select's finishing function
    // (`docs/design/select-park-options.md`).
    internal | FinishedSelect

/// What finishing a woken `sigwait(3)`, `sigwaitinfo(2)` or `sigtimedwait(2)`
/// answers: what `FinishedCall.SignalWait` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.SignalWait`.
[<NoEquality ; NoComparison>]
type FinishedSignalWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the signal wait's finishing function
    // (`docs/design/sigwait-options.md`).
    internal | FinishedSignalWait

/// What finishing a woken blocking receive on a datagram socket answers: what
/// `FinishedCall.DatagramReceive` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.DatagramReceive`.
[<NoEquality ; NoComparison>]
type FinishedDatagramReceive<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | FinishedDatagramReceive

/// What finishing a woken blocking send of a datagram answers: what
/// `FinishedCall.DatagramSend` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.DatagramSend`.
[<NoEquality ; NoComparison>]
type FinishedDatagramSend<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the datagram data path
    // (`docs/design/datagram-park-options.md`).
    internal | FinishedDatagramSend

/// What finishing a woken blocking `connect(2)` answers: what
/// `FinishedCall.Connect` holds.
///
/// Its representation is internal, so a later version may change what it
/// holds without breaking a client; a client builds none. Nothing in this
/// version makes one: see `ParkedSyscall.Connect`.
[<NoEquality ; NoComparison>]
type FinishedConnect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    // What it holds is the design of the connect that sleeps
    // (`docs/design/connect-park-options.md`).
    internal | FinishedConnect

/// What a woken thread's call answered once `UnixWait.finish` finished it: one
/// case for each kind of call a thread parks in, named as that kind's
/// `ParkedSyscall` case is, holding exactly what that kind's own finishing
/// function answers. For a write, which stops partway to copy from the
/// caller's buffer, that is what its resumption answers once given what the
/// buffer of the `Syscall` that `finish` was given holds, since `finish` never
/// stops partway.
///
/// As those answers do, it may hold the call's answer, the thread asleep in
/// the call again, waiting for a new wake, or the call interrupted by a signal
/// (`Interrupted`), whose end the thread's return to user mode says.
///
/// The cases of the reserved parks, `Sleep`, `FifoOpen`, `Select`,
/// `SignalWait`, `DatagramReceive`, `DatagramSend` and `Connect`, hold types
/// whose representations are internal. Nothing parks a thread in any of them
/// yet, so `UnixWait.finish` answers none of them.
[<RequireQualifiedAccess>]
[<NoEquality ; NoComparison>]
type FinishedCall<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// An `epoll_wait(2)`, as `UnixPoll.finishEpollWait` answers it.
    | EpollWait of outcome : EpollWaitOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `kevent(2)`, as `UnixKqueue.finishKevent` answers it.
    | Kevent of outcome : KeventOutcome * system : UnixSystem<'Thread, 'Handler>
    /// An `flock(2)`, as `UnixDescriptor.flockAcquire` answers it.
    | Flock of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A Linux `poll(2)`, as `UnixPoll.finishPoll` answers it.
    | Poll of outcome : PollOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A Darwin `poll(2)`, as `UnixPoll.finishPoll` answers it.
    | KqueuePoll of outcome : PollOutcome * system : UnixSystem<'Thread, 'Handler>
    /// An `accept(2)`, as `UnixConnection.finishAccept` answers it.
    | Accept of outcome : AcceptOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `read(2)` of a pipe, as `UnixReadWrite.finishRead` answers it.
    | PipeRead of outcome : ReadOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `write(2)` to a pipe, as `UnixReadWrite.finishWrite` answers it, or
    /// `UnixReadWrite.writeWithBytes` after it.
    | PipeWrite of fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>
    /// A `read(2)` or `recv(2)` of a connected socket, as
    /// `UnixReadWrite.finishRead` answers it.
    | ConnectionRead of outcome : ReadOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `write(2)` or `send(2)` to a connected socket, as
    /// `UnixReadWrite.finishWrite` answers it, or
    /// `UnixReadWrite.writeWithBytes` after it.
    | ConnectionWrite of fate : ProcessFate<WriteOutcome<'Thread>, 'Thread, 'Handler>
    /// A `sigsuspend(2)`, `rt_sigsuspend(2)` or `pause(2)`, as
    /// `UnixSignal.finishSigsuspend` answers it.
    | SigSuspend of outcome : SigsuspendOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `nanosleep(2)` or `clock_nanosleep(2)`. Reserved: see
    /// `FinishedSleep`.
    | Sleep of finished : FinishedSleep<'Thread, 'Handler>
    /// A blocking `open(2)` of one end of a FIFO. Reserved: see
    /// `FinishedFifoOpen`.
    | FifoOpen of finished : FinishedFifoOpen<'Thread, 'Handler>
    /// A `read(2)` of an inotify instance, as `UnixReadWrite.finishRead`
    /// answers it.
    | InotifyRead of outcome : ReadOutcome * system : UnixSystem<'Thread, 'Handler>
    /// A `select(2)` or `pselect(2)`. Reserved: see `FinishedSelect`.
    | Select of finished : FinishedSelect<'Thread, 'Handler>
    /// A `sigwait(3)`, `sigwaitinfo(2)` or `sigtimedwait(2)`. Reserved: see
    /// `FinishedSignalWait`.
    | SignalWait of finished : FinishedSignalWait<'Thread, 'Handler>
    /// A blocking receive on a datagram socket. Reserved: see
    /// `FinishedDatagramReceive`.
    | DatagramReceive of finished : FinishedDatagramReceive<'Thread, 'Handler>
    /// A blocking send of a datagram. Reserved: see `FinishedDatagramSend`.
    | DatagramSend of finished : FinishedDatagramSend<'Thread, 'Handler>
    /// A blocking `connect(2)`. Reserved: see `FinishedConnect`.
    | Connect of finished : FinishedConnect<'Thread, 'Handler>
    /// A Linux `futex(2)` wait, as `UnixFutex.finishFutexWait` answers it.
    | Futex of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>

/// What a woken call's finishing body answered, before `Entry` makes a kernel
/// of its views: a `FinishedCall` of a modelled park whose systems are
/// `'View`s.
[<RequireQualifiedAccess>]
[<NoEquality ; NoComparison>]
type internal ViewFinishedCall<'View, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    | EpollWait of outcome : EpollWaitOutcome * view : 'View
    | Kevent of outcome : KeventOutcome * view : 'View
    | Flock of outcome : SyscallOutcome * view : 'View
    | Poll of outcome : PollOutcome * view : 'View
    | KqueuePoll of outcome : PollOutcome * view : 'View
    | Accept of outcome : AcceptOutcome * view : 'View
    | PipeRead of outcome : ReadOutcome * view : 'View
    | PipeWrite of fate : ViewFate<WriteOutcome<'Thread>, 'View>
    | ConnectionRead of outcome : ReadOutcome * view : 'View
    | ConnectionWrite of fate : ViewFate<WriteOutcome<'Thread>, 'View>
    | SigSuspend of outcome : SigsuspendOutcome * view : 'View
    | InotifyRead of outcome : ReadOutcome * view : 'View
    | Futex of outcome : SyscallOutcome * view : 'View

/// Why this library will not finish a woken call (`UnixWait.finish`): the
/// refusal of the finishing function of the call's family, a reserved park,
/// which has none, or a `Syscall` that does not describe the call.
[<RequireQualifiedAccess>]
type internal FinishRefusal =
    | Flock of FLockRefusal
    | Accept of AcceptRefusal
    | Poll of PollRefusal
    | EpollWait of EpollWaitRefusal
    | Kevent of KeventRefusal
    | Read of ReadRefusal
    | Write of WriteRefusal
    | Sigsuspend of SigsuspendRefusal
    | Futex of FutexRefusal
    /// The thread is parked in `parked`, a reserved park: nothing parks a
    /// thread in one yet, and no finishing function finishes one.
    | Reserved of parked : ParkedSyscall
    /// The thread is parked in `parked`, which no call of the `Syscall` case
    /// given parks a thread in.
    | NotTheParkedCall of parked : ParkedSyscall
    /// The thread is parked in `parked`, a write that stopped to copy from a
    /// buffer it was made with as readable, which the `Syscall` now gives as
    /// `buffer`.
    | UnreadableBuffer of parked : ParkedSyscall * buffer : UserBuffer

[<RequireQualifiedAccess>]
module internal FinishRefusal =
    /// What this kernel knows about why it cannot answer: the family's own
    /// description of its refusal.
    let describe (refusal : FinishRefusal) : string =
        match refusal with
        | FinishRefusal.Flock refusal -> FLockRefusal.describe refusal
        | FinishRefusal.Accept refusal -> AcceptRefusal.describe refusal
        | FinishRefusal.Poll refusal -> PollRefusal.describe refusal
        | FinishRefusal.EpollWait refusal -> EpollWaitRefusal.describe refusal
        | FinishRefusal.Kevent refusal -> KeventRefusal.describe refusal
        | FinishRefusal.Read refusal -> ReadRefusal.describe refusal
        | FinishRefusal.Write refusal -> WriteRefusal.describe refusal
        | FinishRefusal.Sigsuspend refusal -> SigsuspendRefusal.describe refusal
        | FinishRefusal.Futex refusal -> FutexRefusal.describe refusal
        | FinishRefusal.Reserved parked ->
            $"the thread is parked in %A{parked}, a call this library parks no thread in yet, and has no finishing function for."
        | FinishRefusal.NotTheParkedCall parked ->
            $"the thread is parked in %A{parked}, which no call of the Syscall case given parks a thread in; pass the Syscall the thread made."
        | FinishRefusal.UnreadableBuffer (parked, buffer) ->
            $"the thread is parked in %A{parked}, a write made with a readable buffer, which stopped to copy from it; the Syscall gives the buffer as %A{buffer}, and this library does not model a write's buffer ceasing to be readable while the call sleeps."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FinishRefusal) : RefusalKind =
        match refusal with
        | FinishRefusal.Flock refusal -> FLockRefusal.kind refusal
        | FinishRefusal.Accept refusal -> AcceptRefusal.kind refusal
        | FinishRefusal.Poll refusal -> PollRefusal.kind refusal
        | FinishRefusal.EpollWait refusal -> EpollWaitRefusal.kind refusal
        | FinishRefusal.Kevent refusal -> KeventRefusal.kind refusal
        | FinishRefusal.Read refusal -> ReadRefusal.kind refusal
        | FinishRefusal.Write refusal -> WriteRefusal.kind refusal
        | FinishRefusal.Sigsuspend refusal -> SigsuspendRefusal.kind refusal
        | FinishRefusal.Futex refusal -> FutexRefusal.kind refusal
        | FinishRefusal.Reserved _ -> RefusalKind.Unmodelled
        | FinishRefusal.NotTheParkedCall _ -> RefusalKind.Contradictory "call"
        | FinishRefusal.UnreadableBuffer _ -> RefusalKind.Unmodelled

/// Deciding which parked threads a system wakes, and finishing a woken
/// thread's call.
///
/// Wakes are pulled rather than pushed: nothing that makes a condition true
/// wakes anyone. A client asks `wake` of each state it reaches instead, so no
/// producer can forget to wake a waiter.
[<RequireQualifiedAccess>]
module UnixWait =

    /// `satisfied` once `Entry` has admitted the process.
    let private satisfiedIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Set<WakePrimitive> option
        =
        UnixThreadTable.tryFind thread system.Threads
        |> Option.bind UnixThreadState.parkedIn
        |> Option.map (fun parked -> WakeCondition.satisfied thread (WakeCondition.ofPark parked) system)

    /// The primitives of the wake condition of the call `caller` is parked in
    /// (`WakeCondition.ofPark`) which hold of `system`, or `None` if `caller` is
    /// not parked in a call, including when its process has no thread by that
    /// name. Asked of a thread asleep or woken alike, and changes nothing.
    ///
    /// An empty set means the call would get no further now. A non-empty one
    /// is what lets `wake` wake the thread, and is not enough on its own: a
    /// queue whose waiters a kernel wakes one at a time wakes only one of
    /// them, which only `wake` chooses. This asks about one thread alone,
    /// which is cheaper.
    ///
    /// The condition is read from the park, which holds every open file
    /// description it names until the call returns, so it is never asked
    /// about a description that has gone.
    let satisfied<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Set<WakePrimitive> option
        =
        Entry.query "UnixWait.satisfied" (Caller.processId caller) (satisfiedIn (Caller.thread caller)) system

    /// The park of `thread`, which the threads of the process whose slot is
    /// `slot` name among their parked ones (`UnixThreadTable.parked`); fails
    /// loudly if it has none.
    let private namedPark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (slot : ProcessSlot<'Thread, 'Handler>)
        (thread : 'Thread)
        : ThreadPark
        =
        match UnixThreadTable.parkOf thread slot.Threads with
        | Some park -> park
        | None ->
            failwith
                $"%s{operation}: the process's threads name %O{thread} among their parked ones, and it is parked in no syscall (this is a bug in this library)."

    /// Every park on the machine, each with its thread's caller, in process ID
    /// order and, within a process, in the order of its threads' names.
    ///
    /// Read from the processes the kernel names as having a parked thread
    /// (`ProcessTable.withParks`), and from the threads each of those names
    /// as parked, so it takes time in the number of parked threads, however
    /// many processes and threads there are besides.
    let private parks<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * ThreadPark) list
        =
        (ProcessTable.withParks system.Processes, [])
        ||> Set.foldBack (fun key parks ->
            let pid = ProcessId.parseOrFail operation key
            let slot = ProcessTable.find operation key system.Processes

            (UnixThreadTable.parked slot.Threads, parks)
            ||> Set.foldBack (fun thread parks -> (Caller.make pid thread, namedPark operation slot thread) :: parks)
        )

    /// The sleeping threads `system` wakes now, in the order they parked, each
    /// with the primitives of its wake condition which hold: what `wake`
    /// answers, before it records the wakes. And the earliest deadline any
    /// sleeping thread's call waits for (`deadlines`), which a system whose
    /// sweep woke nobody remembers.
    let private sweep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * Set<WakePrimitive>) list * int64 voption
        =
        let machine = system.Machine

        // One pass over the parks, in which each sleeping thread's condition is
        // made once and asked of the view from its own process, which is made
        // once for all the process's threads. Only the processes with a parked
        // thread are visited, and in each only its parked threads, as `parks`
        // visits them.
        let struct (satisfied, earliest) =
            (struct ([], ValueNone), ProcessTable.withParks system.Processes)
            ||> Set.fold (fun acc key ->
                let pid = ProcessId.parseOrFail "UnixWait.wake" key
                let slot = ProcessTable.find "UnixWait.wake" key system.Processes
                let view = lazy (ProcessView.ofSlot pid slot system)

                (acc, UnixThreadTable.parked slot.Threads)
                ||> Set.fold (fun (struct (satisfied, earliest) as acc) thread ->
                    let park = namedPark "UnixWait.wake" slot thread

                    match park.State with
                    | ParkState.Woken _ -> acc
                    | ParkState.Asleep ->
                        let condition = WakeCondition.ofPark park.Syscall

                        let earliest =
                            (earliest, WakeCondition.deadlines condition)
                            ||> List.fold (fun earliest deadline ->
                                match earliest with
                                | ValueSome sooner when sooner <= deadline -> earliest
                                | ValueSome _
                                | ValueNone -> ValueSome deadline
                            )

                        let fired = WakeCondition.satisfied thread condition view.Value

                        if Set.isEmpty fired then
                            struct (satisfied, earliest)
                        else
                            struct ((park.Ordinal, Caller.make pid thread, fired) :: satisfied, earliest)
                )
            )

        match satisfied with
        | [] -> [], earliest
        | satisfied ->

        let satisfied = satisfied |> List.sortBy (fun (ordinal, _, _) -> ordinal)
        let parks = parks "UnixWait.wake" system

        // Measured on Linux 6.18.5 (`epoll-wait.c`, section F): `epoll_wait`
        // queues its waiters exclusively at the *front* of the epoll instance's wait
        // queue, so each signal wakes exactly one of them, the one that parked
        // last; three threads parked in any order returned in the reverse of
        // it, one per datagram, in 60 trials of 60, and a thread that waited
        // again went back to the front every time.
        //
        // Measured on Linux 6.18.5 and Darwin 27.0.0 (`blocking-accept.c`,
        // section B): a blocking `accept` is the other way round. Each
        // connection woke exactly one of three accepters, the one that parked
        // *first*, in 60 trials of 60 on each; and a thread that accepted again
        // went to the back of the queue every time, in 20 of 20.
        //
        // A real kernel wakes one waiter per *signal*, and this sweep sees only
        // states, so it cannot tell a second signal from the first one seen
        // again. So a woken waiter that has yet to finish stands for every
        // signal since it was woken, and nobody else on its queue wakes until
        // it has taken what woke it or parked again. Where a real second signal
        // would have woken another waiter (two connections back to back woke
        // two accepters, in 50 of 50 on each flavour), whichever of the two ran
        // first would have taken the first; this answers the schedule in which
        // the first one ran first. Every answer is one a real kernel gives, and
        // the schedules in which the second waiter runs first are not reached.
        //
        // Measured on Linux 6.18.5 and Darwin 27.0.0 (`pipe-blocking.c`,
        // sections A and B): on Linux each 1-byte write woke exactly one of
        // three readers asleep on an empty pipe, the one that parked *first*,
        // in 60 trials of 60, and a reader that read again went to the back;
        // writers asleep on a full pipe likewise, a freed slot at a time. On
        // Darwin exactly one returned per write too, but not by park order (the
        // first-parked won 6 to 10 of each 10): every sleeper wakes and they
        // race, which is the client scheduler's to decide. The last writer or
        // reader closing wakes every sleeper on the other end on both, as
        // Linux's `pipe_release` does.
        //
        // Measured on Darwin 27.0.0 (`kqueue-kevent.c`, section E5): a close
        // that drains a kqueue ends every `kevent` wait on it at once, whichever
        // descriptor each was entered through. And the waiters on one kqueue
        // showed no fixed order when an event arrived
        // (`signal-interrupt-requeue.c`, section C), which is every sleeper
        // waking to race.
        //
        // Measured on Linux 6.18.5 and Darwin 27.0.0 (`tcp-blocking.c`,
        // section R-order): three readers asleep on one connected socket, and
        // three 1-byte writes, returned in no fixed order on either (Linux
        // gave "201" in 8 trials of 10 and "210" in 2, the last to park
        // first; Darwin "012" in 7 and "021" in 3). Both kernels queue a
        // socket's sleepers non-exclusively, so every one wakes and they
        // race, as Darwin's pipe waiters do. Writers asleep on a socket are
        // queued the same way in both kernels' source (Linux's
        // `sk_stream_wait_memory`, Darwin's `sbwait`), which no probe has
        // measured.
        //
        // Waiters on an `flock` are the opposite, deliberately: a release
        // wakes every blocker and they race, as `flock(2)` does, and which of
        // them wins is not observable from userspace on any platform. Waking
        // them all does not invent a winner; it leaves the choice to the
        // client's scheduler. A `poll` queues itself on each description it
        // watches non-exclusively, so every poller of a description that
        // becomes ready wakes; and a deadline, like a signal, is each waiter's
        // own.
        // A thread woken and not yet finished stands for whatever woke it: on
        // the queue of each primitive that held as it woke, and on no queue
        // for a signal or a deadline alone. Measured on Linux 6.18.5 and
        // Darwin 27.0.0 (`docs/probes/first-wake`, the two-sleeper rows): with
        // the first accepter, pipe reader or epoll waiter signalled, and held
        // off the CPU, the next connection, byte or event woke the other
        // sleeper too, and on Darwin the other accepted the connection while
        // the first failed with EINTR.
        let finishing : Set<ExclusiveWaitQueue> =
            parks
            |> List.collect (fun (_, park) ->
                match park.State with
                | ParkState.Woken fired -> fired |> Set.toList |> List.choose (Parking.exclusiveQueueOf machine)
                | ParkState.Asleep -> []
            )
            |> Set.ofList

        let chosen : Map<ExclusiveWaitQueue, Caller<'Thread>> =
            satisfied
            |> List.collect (fun (ordinal, thread, fired) ->
                fired
                |> Set.toList
                |> List.choose (fun primitive ->
                    Parking.exclusiveQueueOf machine primitive
                    |> Option.map (fun queue -> queue, (ordinal, thread))
                )
            )
            |> List.groupBy fst
            |> List.choose (fun (queue, waiters) ->
                if Set.contains queue finishing then
                    None
                else
                    let waiters = waiters |> List.map snd

                    let _, woken =
                        match queue with
                        | ExclusiveWaitQueue.Epoll _ -> List.maxBy fst waiters
                        | ExclusiveWaitQueue.Listener _
                        | ExclusiveWaitQueue.PipeReaders _
                        | ExclusiveWaitQueue.PipeWriters _ -> List.minBy fst waiters

                    Some (queue, woken)
            )
            |> Map.ofList

        satisfied
        |> List.filter (fun (_, thread, fired) ->
            fired
            |> Set.exists (fun primitive ->
                match Parking.exclusiveQueueOf machine primitive with
                | Some queue -> Map.tryFind queue chosen = Some thread
                | None -> true
            )
        )
        |> List.map (fun (_, caller, fired) -> caller, fired),
        earliest

    /// Every deadline the sleeping threads' calls are waiting for, in
    /// nanoseconds since boot, with a repeat for each park that waits for it. A
    /// woken thread's call is not counted: the thread is already the client's
    /// to run.
    ///
    /// What a client with nothing runnable reads to learn how far it may advance
    /// the clock before one of these calls times out.
    let deadlines<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : int64 list
        =
        parks "UnixWait.deadlines" system
        |> List.collect (fun (_, park) ->
            match park.State with
            | ParkState.Asleep -> WakeCondition.deadlines (WakeCondition.ofPark park.Syscall)
            | ParkState.Woken _ -> []
        )

    /// `system`, whose sweep woke no thread, remembering that sweep: what it
    /// read, and `earliest`, the earliest deadline a sleeping thread waits
    /// for.
    let private remembering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (earliest : int64 voption)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let remembered : RememberedSweep<'Thread, 'Handler> =
            {
                Machine = system.Machine
                Processes = system.Processes
                EarliestDeadline = earliest
#if DEBUG
                HitsSinceSweep = 0
#endif
            }

        { system with
            Sweep =
                {
                    Remembered = ValueSome remembered
                }
        }

    /// The sleeping threads `system` wakes now, in the order they parked, each
    /// with the primitives of its wake condition which hold; and the system
    /// with each of them woken (`ParkState.Woken`). If none wakes, the system
    /// answered is equal to `system`.
    ///
    /// A woken thread stays parked until the finishing function of the call it
    /// is parked in finishes it, and only a woken thread's call may be
    /// finished. Until then it is not asked again: it is the client's to run,
    /// when it chooses.
    ///
    /// A waiter whose `flock` has become grantable, whose polled descriptor is
    /// ready, whose deadline has passed, or to which a signal with a handler is
    /// deliverable wakes, whoever else is waiting for the same thing. Waiters on an epoll instance, and waiters in `accept`
    /// on a listener, queue exclusively: something to take wakes one of them,
    /// the one that parked *last* on an epoll instance and the one that
    /// parked *first* on a listener. Under Linux, so do the waiters in `read`
    /// for a pipe's bytes and those in `write` for its room, the one that
    /// parked first waking; under Darwin every one of them wakes. Waiters in
    /// `read` or `write` on a connected socket all wake, under either
    /// flavour. Exclusive
    /// queues wake none while any thread parked on the same queue has been woken
    /// by something to take from it and has not yet finished its call, since
    /// that thread will take it; one a signal or its deadline alone woke holds
    /// no queue. The
    /// end of a pipe closing
    /// wakes every waiter on the other end, under either flavour; and an event
    /// to report, or a close that drains a kqueue, wakes every waiter in
    /// `kevent` on it.
    ///
    /// Each thread's condition is asked of its own process, so a condition
    /// another process's call has made true (a connection queued on a
    /// listener, a peer's FIN, a lock let go of) wakes it here; and where a
    /// kernel wakes one waiter of a queue at a time, the one is chosen across
    /// every process, by the order of the machine's parks.
    ///
    /// A woken thread is owed no success: several waiters for one lock all wake,
    /// and all but one find it taken again and re-park, asleep.
    ///
    /// A client asks this of every state it reaches, so it is cheap for a state
    /// in which nothing it reads has changed. A system remembers the last
    /// sweep of it that woke no thread, and `wake` answers from that, asking no
    /// wake condition and answering `system` itself, while nothing that sweep
    /// read has changed but the clock, and the clock has not reached the
    /// earliest deadline any sleeping thread waits for. Nothing a syscall can
    /// change counts as unchanged unless it is the same value, so a call that
    /// changes the system makes the next `wake` sweep; moving the clock
    /// (`UnixSystem.advanceClock`), a call that changes nothing, and reporting
    /// a thread running on the processor it is already on
    /// (`UnixScheduling.dispatch`) do not. A sweep that wakes no thread answers
    /// a new system, which remembers it; so a client keeps the system this
    /// answers, rather than the one it asked of. What a system remembers is no
    /// part of its value: two systems that differ only in it are equal.
    ///
    /// A Debug build checks some of the answers it gives from what a system
    /// remembers against a sweep, failing loudly if they differ.
    let wake<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * Set<WakePrimitive>) list * UnixSystem<'Thread, 'Handler>
        =
        match system.Sweep.Remembered with
        | ValueSome remembered when WakeMemo.covers remembered system.Machine system.Scheduling system.Processes ->
#if DEBUG
            let hits = System.Threading.Interlocked.Increment &remembered.HitsSinceSweep - 1

            if WakeMemo.crossChecks hits then
                match sweep system with
                | [], _ -> ()
                | woken, _ ->
                    failwith
                        $"UnixWait.wake: the system's memo says it wakes no thread, but a sweep wakes %A{woken}, at answer %d{hits} since the memo's sweep (this is a bug in this library)."
#endif
            [], system
        | ValueSome _
        | ValueNone ->

        match sweep system with
        | [], earliest -> [], remembering earliest system
        | woken, _ ->
            let processes =
                (system.Processes, woken)
                ||> List.fold (fun processes (caller, fired) ->
                    let key = ProcessId.toInt32 (Caller.processId caller)
                    let slot = ProcessTable.find "UnixWait.wake" key processes

                    ProcessTable.add
                        key
                        { slot with
                            Threads = UnixThreadTable.markWoken (Caller.thread caller) fired slot.Threads
                        }
                        processes
                )

            woken,
            { system with
                Processes = processes
                Sweep = WakeMemo.none
            }

    /// The `FinishedCall` of what `tryFinishIn` answered, each view in it put
    /// back through `shapes` where the shape of that family's own finishing
    /// function puts it: `finish`'s cases, for `Shape.union`.
    let private finishedCases<'View, 'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (shapes : ShapeMap<'View, UnixSystem<'Thread, 'Handler>>)
        (finished : ViewFinishedCall<'View, 'Thread, 'Handler>)
        : FinishedCall<'Thread, 'Handler>
        =
        match finished with
        | ViewFinishedCall.EpollWait (outcome, view) ->
            shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.EpollWait
        | ViewFinishedCall.Kevent (outcome, view) -> shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.Kevent
        | ViewFinishedCall.Flock (outcome, view) -> shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.Flock
        | ViewFinishedCall.Poll (outcome, view) -> shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.Poll
        | ViewFinishedCall.KqueuePoll (outcome, view) ->
            shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.KqueuePoll
        | ViewFinishedCall.Accept (outcome, view) -> shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.Accept
        | ViewFinishedCall.PipeRead (outcome, view) ->
            shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.PipeRead
        | ViewFinishedCall.PipeWrite fate -> shapes.Map Shape.fate fate |> FinishedCall.PipeWrite
        | ViewFinishedCall.ConnectionRead (outcome, view) ->
            shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.ConnectionRead
        | ViewFinishedCall.ConnectionWrite fate -> shapes.Map Shape.fate fate |> FinishedCall.ConnectionWrite
        | ViewFinishedCall.SigSuspend (outcome, view) ->
            shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.SigSuspend
        | ViewFinishedCall.InotifyRead (outcome, view) ->
            shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.InotifyRead
        | ViewFinishedCall.Futex (outcome, view) -> shapes.Map Shape.withSystem (outcome, view) |> FinishedCall.Futex

    /// Whether a thread parked in `parked` could have parked there in a call
    /// of `call`'s case. A reserved park is made by no call.
    let private parksIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (parked : ParkedSyscall)
        (call : Syscall<'Thread, 'Handler>)
        : bool
        =
        match parked, call with
        | ParkedSyscall.EpollWait _, Syscall.EpollWait _
        | ParkedSyscall.Kevent _, Syscall.Kevent _
        | ParkedSyscall.Flock _, Syscall.FLock _
        | ParkedSyscall.Poll _, Syscall.Poll _
        | ParkedSyscall.KqueuePoll _, Syscall.Poll _
        | ParkedSyscall.Accept _, Syscall.Accept _
        | ParkedSyscall.PipeRead _, Syscall.Read _
        | ParkedSyscall.PipeWrite _, Syscall.Write _
        | ParkedSyscall.InotifyRead _, Syscall.Read _
        | ParkedSyscall.SigSuspend, (Syscall.SigSuspend _ | Syscall.RtSigSuspend _ | Syscall.Pause)
        | ParkedSyscall.Futex _, Syscall.Futex _ -> true
        | ParkedSyscall.ConnectionRead read, (Syscall.Read _ | Syscall.Recv _) ->
            match read.Call, call with
            | TcpReceiveCall.Read, Syscall.Read _
            | (TcpReceiveCall.Receive | TcpReceiveCall.Peek), Syscall.Recv _ -> true
            | _, _ -> false
        | ParkedSyscall.ConnectionWrite write, (Syscall.Write _ | Syscall.Send _ | Syscall.SendTo _) ->
            match write.Call, call with
            | TcpSendCall.Write, Syscall.Write _
            | TcpSendCall.Send _, Syscall.Send _ -> true
            // A `sendto` with no destination is a `send`; with one, it parks in
            // no connection.
            | TcpSendCall.Send _, Syscall.SendTo (_, _, _, _, destination, _) ->
                destination = CopiedArgument.Unmapped 0UL
            | _, _ -> false
        | _, _ -> false

    /// The woken `write` or `send` `thread` is parked in, finished by
    /// `UnixReadWrite`'s finishing body, and, where that stops at its copy,
    /// resumed with the bytes it names of the buffer `call` holds.
    let private tryFinishWriteIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (parked : ParkedSyscall)
        (call : Syscall<'Thread, 'Handler>)
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ViewFate<WriteOutcome<'Thread>, ProcessView<'Thread, 'Handler>>, FinishRefusal>
        =
        match UnixReadWrite.tryFinishWriteIn thread system with
        | Error refusal -> Error (FinishRefusal.Write refusal)
        | Ok (CallProgress.Answered fate) -> Ok fate
        | Ok (CallProgress.NeedsCopyIn paused) ->
            let buffer =
                match call with
                | Syscall.Write (_, buffer, _)
                | Syscall.Send (_, buffer, _, _)
                | Syscall.SendTo (_, buffer, _, _, _, _) -> buffer
                | _ ->
                    failwith
                        $"UnixWait.finish: the thread is parked in %A{parked}, a write, but was admitted with a Syscall that is not a write, a send or a sendto (this is a bug in this library)."

            match buffer with
            | CopiedArgument.Readable contents ->
                let bytes =
                    CopiedArgument.slice "UnixWait.finish" (PausedWrite.copyRange paused) contents

                match UnixReadWrite.tryWriteWithBytesIn bytes paused with
                | Error refusal -> Error (FinishRefusal.Write refusal)
                | Ok (fate, None) -> Ok fate
                // A blocking write into a pipe a client drains never sleeps, so
                // a woken write is never into one.
                | Ok (_, Some delivery) ->
                    failwith
                        $"UnixWait.finish: the woken write the thread is parked in, %A{parked}, delivered %A{delivery} out of the machine, which only a write into a pipe a client drains does, and such a write never sleeps (this is a bug in this library)."
            | CopiedArgument.Unmapped _
            | CopiedArgument.Opaque
            | CopiedArgument.Addressless ->
                Error (FinishRefusal.UnreadableBuffer (parked, CopiedArgument.userBuffer buffer))

    /// `tryFinish` once `Entry` has admitted its caller: the call `thread` is
    /// parked in, which `call` describes, finished by the finishing body of
    /// its family.
    let private tryFinishIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (call : Syscall<'Thread, 'Handler>)
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ViewFinishedCall<ProcessView<'Thread, 'Handler>, 'Thread, 'Handler>, FinishRefusal>
        =
        let parked = UnixThreadTable.requireParked "UnixWait.finish" thread system.Threads

        match parked with
        | ParkedSyscall.Sleep _
        | ParkedSyscall.FifoOpen _
        | ParkedSyscall.Select _
        | ParkedSyscall.SignalWait _
        | ParkedSyscall.DatagramReceive _
        | ParkedSyscall.DatagramSend _
        | ParkedSyscall.Connect _ -> Error (FinishRefusal.Reserved parked)
        | _ when not (parksIn parked call) -> Error (FinishRefusal.NotTheParkedCall parked)
        | ParkedSyscall.EpollWait _ ->
            UnixPoll.tryFinishEpollWaitIn thread system
            |> Result.map ViewFinishedCall.EpollWait
            |> Result.mapError FinishRefusal.EpollWait
        | ParkedSyscall.Kevent _ ->
            UnixKqueue.tryFinishKeventIn thread system
            |> Result.map ViewFinishedCall.Kevent
            |> Result.mapError FinishRefusal.Kevent
        | ParkedSyscall.Flock _ ->
            UnixDescriptor.tryFlockAcquireIn thread system
            |> Result.map ViewFinishedCall.Flock
            |> Result.mapError FinishRefusal.Flock
        | ParkedSyscall.Poll _ ->
            UnixPoll.tryFinishPollIn thread system
            |> Result.map ViewFinishedCall.Poll
            |> Result.mapError FinishRefusal.Poll
        | ParkedSyscall.KqueuePoll _ ->
            UnixPoll.tryFinishPollIn thread system
            |> Result.map ViewFinishedCall.KqueuePoll
            |> Result.mapError FinishRefusal.Poll
        | ParkedSyscall.Accept _ ->
            UnixConnection.tryFinishAcceptIn thread system
            |> Result.map ViewFinishedCall.Accept
            |> Result.mapError FinishRefusal.Accept
        | ParkedSyscall.PipeRead _ ->
            UnixReadWrite.tryFinishReadIn thread system
            |> Result.map ViewFinishedCall.PipeRead
            |> Result.mapError FinishRefusal.Read
        | ParkedSyscall.PipeWrite _ ->
            tryFinishWriteIn parked call thread system
            |> Result.map ViewFinishedCall.PipeWrite
        | ParkedSyscall.ConnectionRead _ ->
            UnixReadWrite.tryFinishReadIn thread system
            |> Result.map ViewFinishedCall.ConnectionRead
            |> Result.mapError FinishRefusal.Read
        | ParkedSyscall.ConnectionWrite _ ->
            tryFinishWriteIn parked call thread system
            |> Result.map ViewFinishedCall.ConnectionWrite
        | ParkedSyscall.SigSuspend ->
            UnixSignal.tryFinishSigsuspendIn thread system
            |> Result.map ViewFinishedCall.SigSuspend
            |> Result.mapError FinishRefusal.Sigsuspend
        | ParkedSyscall.InotifyRead _ ->
            UnixReadWrite.tryFinishReadIn thread system
            |> Result.map ViewFinishedCall.InotifyRead
            |> Result.mapError FinishRefusal.Read
        | ParkedSyscall.Futex _ ->
            UnixFutex.tryFinishFutexWaitIn thread system
            |> Result.map ViewFinishedCall.Futex
            |> Result.mapError FinishRefusal.Futex

    /// `finish`, with a refusal answered as the `Error` rather than raised.
    let internal tryFinish<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (call : Syscall<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<FinishedCall<'Thread, 'Handler>, FinishRefusal>
        =
        Entry.call
            "UnixWait.finish"
            CallerRequirement.Woken
            caller
            (Shape.result (Shape.union finishedCases))
            (tryFinishIn call (Caller.thread caller))
            system

    /// Finish the call `caller` is parked in, once `wake` has woken it, through
    /// the finishing function of that call's family, and answer the
    /// `FinishedCall` case named as the call's `ParkedSyscall` case is, holding
    /// exactly what that function answers.
    ///
    /// `call` is the `Syscall` the thread made, as `UnixSystem.step` takes it,
    /// with what the caller's memory holds now: a woken write copies the next
    /// of its bytes from its buffer as the buffer is when the call is
    /// finished, and `finish` hands the write's resumption, which
    /// `UnixReadWrite.writeWithBytes` is, the bytes of `call`'s buffer it
    /// copies, so that it never stops partway. Every other call is finished
    /// without reading `call`'s arguments.
    ///
    /// So it answers as that function would: the call's answer, which clears the
    /// park; the thread parked again, asleep, for a new wake, where what woke it
    /// has gone; or `Interrupted`, after which the thread owes its return to
    /// user mode (`UnixSignal.onReturnToUser`), which says how the call ends. A
    /// client that wants that function's own answer type calls it instead.
    ///
    /// Throws `InvalidOperationException` unless `caller` is a thread of one of
    /// the system's processes, parked in a call and woken, and
    /// `UnmodelledException` for a thread parked in one of the reserved calls
    /// (`ParkedSyscall.Sleep`, `FifoOpen`, `Select`, `SignalWait`,
    /// `DatagramReceive`, `DatagramSend` and `Connect`), which nothing parks a
    /// thread in yet. Throws `ArgumentException` if `call`'s case is not one
    /// that parks a thread where `caller` is parked (`Syscall.Write` for a
    /// write to a pipe, and `Syscall.Write` for a write to a connected socket
    /// and `Syscall.Send` for a send to one, or `Syscall.SendTo` with a NULL
    /// destination, which is that send). For a write that copies, throws
    /// `InvalidOperationException` if `call`'s buffer holds contents that end
    /// before the bytes it copies, as `step` does, and `UnmodelledException`
    /// if `call` gives the buffer as anything but readable, which it was when
    /// the call was made. Otherwise it throws what the family's finishing
    /// function throws.
    let finish<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (call : Syscall<'Thread, 'Handler>)
        (system : UnixSystem<'Thread, 'Handler>)
        : FinishedCall<'Thread, 'Handler>
        =
        tryFinish caller call system
        |> Refusal.orRaise "UnixWait.finish" FinishRefusal.kind FinishRefusal.describe
