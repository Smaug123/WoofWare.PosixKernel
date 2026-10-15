namespace WoofWare.PosixKernel

/// A wait queue whose waiters a real kernel wakes one at a time.
[<RequireQualifiedAccess>]
type internal ExclusiveWaitQueue =
    /// The waiters in `epoll_wait` on the epoll instance this description names.
    | Epoll of OpenFileDescriptionId
    /// The waiters in `accept` on the listening socket this description names.
    | Listener of OpenFileDescriptionId
    /// The waiters in `read` for bytes from this pipe.
    | PipeReaders of PipeId
    /// The waiters in `write` for room in this pipe.
    | PipeWriters of PipeId

/// What a sweep of a machine's sleeping threads that woke none of them read:
/// everything a wake condition is asked of but the clock, and the earliest
/// deadline any of those threads waits for.
type internal RememberedSweep<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    {
        Machine : UnixMachineState
        Processes : Map<int32, ProcessSlot<'Thread, 'Handler>>
        Asleep : Set<Caller<'Thread>>
        /// The earliest `WakePrimitive.DeadlinePassed` among the wake
        /// conditions of the threads in `Asleep`, if any has one.
        EarliestDeadline : int64 voption
    }

/// What `UnixWait.wakesRemembering` remembers between calls, so that it
/// can tell, without asking any wake condition, that a system wakes no thread:
/// the last sweep it made, if that sweep woke none.
///
/// Opaque. A client starts from `WakeSweepMemo.empty`, and passes each call the
/// memo the last one answered.
[<ReferenceEquality>]
type WakeSweepMemo<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    internal
        {
            Remembered : RememberedSweep<'Thread, 'Handler> voption
#if DEBUG
            /// How many answers `UnixWait.wakesRemembering` has given from `Remembered`
            /// since it was swept, which decides the ones it checks against a sweep
            /// (`WakeSweepMemo.crossChecks`).
            HitsSinceSweep : int
#endif
        }

[<RequireQualifiedAccess>]
module WakeSweepMemo =
    /// A memo that remembers no sweep, so the next call sweeps.
    let empty<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> : WakeSweepMemo<'Thread, 'Handler> =
        {
            Remembered = ValueNone
#if DEBUG
            HitsSinceSweep = 0
#endif
        }

    /// How many of the first answers after a sweep a Debug build checks every one of: see
    /// `crossChecks`.
    [<Literal>]
    let internal CrossCheckedFirst : int = 8

    /// After the first `CrossCheckedFirst`, a Debug build checks one answer in this many: see
    /// `crossChecks`.
    [<Literal>]
    let internal CrossCheckedEvery : int = 64

    /// Whether a Debug build checks against a sweep the answer a memo gives when it has already
    /// given `hits` since its sweep: every one of the first `CrossCheckedFirst`, and one in every
    /// `CrossCheckedEvery` after them. A count rather than a draw, so that which answers are
    /// checked is the same on every run.
    ///
    /// A memo that answers wrongly goes on answering wrongly until something it compares changes,
    /// so a check one in every `CrossCheckedEvery` answers still catches it, within that many
    /// answers, unless something changes first.
    let internal crossChecks (hits : int) : bool =
        hits < CrossCheckedFirst || hits % CrossCheckedEvery = 0

    /// Whether `machine` and `processes` are the machine state and every
    /// process's state and threads that `remembered` read, the same values
    /// rather than equal ones, and `asleep` is the threads `remembered` was
    /// asked about: whether everything a wake condition reads but the clock is
    /// as `remembered` found it.
    let internal readsSame<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (remembered : RememberedSweep<'Thread, 'Handler>)
        (asleep : Set<Caller<'Thread>>)
        (machine : UnixMachineState)
        (processes : Map<int32, ProcessSlot<'Thread, 'Handler>>)
        : bool
        =
        let sameSlots () : bool =
            remembered.Processes.Count = processes.Count
            && processes
               |> Map.forall (fun processId slot ->
                   match remembered.Processes.TryGetValue processId with
                   | true, before ->
                       // The leader is not compared: it is fixed when its
                       // process is launched, and every launch makes a new
                       // process state, so the same state means the same leader.
                       LanguagePrimitives.PhysicalEquality before.Process slot.Process
                       && LanguagePrimitives.PhysicalEquality before.Threads slot.Threads
                   | false, _ -> false
               )

        LanguagePrimitives.PhysicalEquality remembered.Machine machine
        && sameSlots ()
        && (LanguagePrimitives.PhysicalEquality remembered.Asleep asleep
            || remembered.Asleep = asleep)

    /// Whether a sweep of a system would wake no thread because `remembered`
    /// woke none: whether it `readsSame` as `remembered`, and the clock has not
    /// reached the earliest deadline any thread in `asleep` waits for.
    ///
    /// The clock is the one input a wake condition reads that changes between
    /// syscalls, and only `WakePrimitive.DeadlinePassed` reads it; so with
    /// everything else the same and the clock short of every deadline, each
    /// primitive holds or does not exactly as it did, and the sweep's answer
    /// is the same.
    let internal covers<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (remembered : RememberedSweep<'Thread, 'Handler>)
        (asleep : Set<Caller<'Thread>>)
        (machine : UnixMachineState)
        (scheduling : UnixSchedulingState)
        (processes : Map<int32, ProcessSlot<'Thread, 'Handler>>)
        : bool
        =
        (match remembered.EarliestDeadline with
         | ValueNone -> true
         | ValueSome deadline -> scheduling.NanosecondsSinceBoot < deadline)
        && readsSame remembered asleep machine processes

/// Parking a thread in a syscall, and deciding which parked threads a system wakes.
///
/// Wakes are pulled rather than pushed: nothing that makes a condition true
/// wakes anyone. A client asks `wakes` of each state it reaches instead, so no
/// producer can forget to wake a waiter.
[<RequireQualifiedAccess>]
module UnixWait =

    /// The pipe the open file description `description` names an end of, if
    /// `machine`'s table holds it and it names one.
    let private pipeOf (machine : UnixMachineState) (description : OpenFileDescriptionId) : PipeId option =
        match OpenFileTable.tryFind description machine.OpenFiles with
        | Some {
                   Target = OpenFileTarget.Pipe (pipeId, _)
               } -> Some pipeId
        | Some _
        | None -> None

    /// The queue a call waiting for `primitive` sleeps on, under `machine`'s
    /// flavour, if a real kernel wakes that queue's waiters one at a time.
    let internal exclusiveQueueOf (machine : UnixMachineState) (primitive : WakePrimitive) : ExclusiveWaitQueue option =
        let linux =
            match SimulatedUnixPlatform.flavour machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux -> true
            | SimulatedUnixFlavour.Darwin -> false

        // A pipe's description is looked up leniently: `WakeCondition.satisfied`
        // has already failed loudly for one that is gone or names something
        // else, for every thread it was asked about, but a thread woken and not
        // yet finished is not asked.
        match primitive with
        | WakePrimitive.EpollEventDeliverable epoll -> Some (ExclusiveWaitQueue.Epoll epoll)
        | WakePrimitive.AcceptQueueNonEmpty listener -> Some (ExclusiveWaitQueue.Listener listener)
        | WakePrimitive.PipeHasBytes reader when linux ->
            pipeOf machine reader |> Option.map ExclusiveWaitQueue.PipeReaders
        | WakePrimitive.PipeHasRoom (writer, _, _) when linux ->
            pipeOf machine writer |> Option.map ExclusiveWaitQueue.PipeWriters
        | WakePrimitive.PipeHasBytes _
        | WakePrimitive.PipeHasRoom _
        | WakePrimitive.PipeWriteEndClosed _
        | WakePrimitive.PipeReadEndClosed _
        | WakePrimitive.PipeReadWhileNonBlocking _
        | WakePrimitive.ConnectionReadable _
        | WakePrimitive.ConnectionWritable _
        | WakePrimitive.FlockGrantable _
        | WakePrimitive.KqueueDrained _
        | WakePrimitive.KqueueEventDeliverable _
        | WakePrimitive.KqueuePollReportable
        | WakePrimitive.DescriptorReady _
        | WakePrimitive.DeadlinePassed _
        | WakePrimitive.SignalDeliverable
        | WakePrimitive.EndedByClose
        // A partner's open wakes every opener asleep on the FIFO, on both
        // flavours (measured, two sleepers of two).
        | WakePrimitive.FifoPartnerOpened _
        // `inotify_read` waits on the instance's queue non-exclusively, so
        // a record wakes every reader asleep on it, and the first to run
        // takes it (from Linux's source; which reader runs first is not
        // observable). Measured (`inotify-descriptor-probe.c` row S
        // two-sleepers-one-record): of two readers, one took the record.
        | WakePrimitive.InotifyRecordQueued _
        // A signal is pending to the thread it was sent to, or, sent to the
        // process, to whichever thread the receiver rule picks. No wait queue
        // is shared.
        | WakePrimitive.AwaitedSignalPending _ -> None
        // Reserved, and in no condition yet. Linux's `unix_wait_for_peer`
        // waits exclusively on the listener's `peer_wait`, which the
        // connect that sleeps will model.
        | WakePrimitive.AcceptQueueHasRoom _ -> None

    /// The queues the call `parked` sleeps on, under `machine`'s flavour, whose
    /// waiters a real kernel wakes one at a time: those of the primitives of its
    /// wake condition (`exclusiveQueueOf`).
    let internal exclusiveQueuesOfPark (machine : UnixMachineState) (parked : ParkedSyscall) : ExclusiveWaitQueue list =
        WakeCondition.ofPark parked
        |> WakeCondition.primitives
        |> List.choose (exclusiveQueueOf machine)
        |> List.distinct

    /// Record that `thread` has parked in `parked`, placing it after every park
    /// made before it, and taking the holds the call keeps on the open file
    /// descriptions it names (`ParkedSyscall.descriptions`). A thread that sleeps
    /// is no longer running, so it leaves its processor idle
    /// (`UnixSchedulingState.Occupants`).
    ///
    /// Refuses to replace a park of one syscall with a park of another, and
    /// otherwise accepts a re-park of the same syscall, which moves the thread to
    /// the back of park order and lets go of the holds the earlier park took.
    let internal park<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (parked : ParkedSyscall)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        let (ParkOrdinal.ParkOrdinal ordinal) = system.Machine.NextParkOrdinal
        let state = UnixThreadTable.get thread system.Threads

        let threadPark =
            {
                Syscall = parked
                Ordinal = system.Machine.NextParkOrdinal
            }

        { system with
            Machine =
                { system.Machine with
                    NextParkOrdinal = ParkOrdinal.ParkOrdinal (ordinal + 1L)
                }
            Scheduling = UnixSchedulingState.vacate state.Cpu state.OsThreadId system.Scheduling
        }
        |> UnixParkState.setPark thread threadPark

    /// Park `thread` in `parked`, as `park` does, for a call that sleeps
    /// because nothing its wake condition waits for, a signal aside, holds
    /// yet. A Debug build fails loudly if something does.
    let internal parkWaiting<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (parked : ParkedSyscall)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        let asleep = park thread parked system

#if DEBUG
        // A call whose own condition held as it parked would be woken at once,
        // and its finishing call would find what it waited for, or, if the
        // finisher and the condition disagreed, park it again for ever. A
        // signal is the exception: a call parks whatever signal is pending,
        // and its finishing call decides what one does to it.
        match
            WakeCondition.ofPark parked
            |> WakeCondition.primitives
            |> List.filter (fun primitive -> primitive <> WakePrimitive.SignalDeliverable)
        with
        | [] -> ()
        | first :: rest ->
            let unsignalled =
                WakeCondition.AnyOf (WakeCondition.Primitive first, List.map WakeCondition.Primitive rest)

            let held = WakeCondition.satisfied thread unsignalled asleep

            if not (Set.isEmpty held) then
                failwith
                    $"UnixWait.parkWaiting: thread %O{thread} parks in %A{parked}, but %A{held} of its own wake condition already hold, so a client would wake it at once (this is a bug in this library)."
#endif

        asleep

    /// `satisfied` once `Entry` has admitted the process.
    let private satisfiedIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Set<WakePrimitive> option
        =
        Map.tryFind thread system.Threads
        |> Option.bind UnixThreadState.parkedIn
        |> Option.map (fun parked -> WakeCondition.satisfied thread (WakeCondition.ofPark parked) system)

    /// The primitives of the wake condition of the call `caller` is parked in
    /// (`WakeCondition.ofPark`) which hold of `system`, or `None` if `caller` is
    /// not parked in a call, including when its process has no thread by that
    /// name.
    ///
    /// An empty set means the call would get no further now. A non-empty one
    /// is what lets `wakes` name the thread, and is not enough on its own: a
    /// queue whose waiters a kernel wakes one at a time wakes only one of
    /// them, so a client that holds several threads asleep asks `wakes`. This
    /// asks about one thread alone, which is cheaper.
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

    /// The threads of `asleep` that `system` wakes now, in the order they parked,
    /// each with the primitives of its wake condition which hold.
    ///
    /// `asleep` is the client's: the threads it is holding asleep in a syscall,
    /// in every process. Every one must be parked. A thread the client has woken
    /// keeps its park until its call finishes, so the parks alone cannot say who
    /// is asleep.
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
    /// and has not yet finished its call (that is, is parked but not in
    /// `asleep`), since that thread will take it. The end of a pipe closing
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
    /// and all but one find it taken again and re-park.
    ///
    /// Fails loudly if `asleep` names a thread of a process `system` does not
    /// hold, or a thread parked in no call.
    let wakes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (asleep : Set<Caller<'Thread>>)
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * Set<WakePrimitive>) list
        =
        let machine = system.Machine

        let satisfied =
            asleep
            |> Set.toList
            |> List.choose (fun caller ->
                let pid = Caller.processId caller
                let thread = Caller.thread caller

                let slot =
                    match Map.tryFind (ProcessId.toInt32 pid) system.Processes with
                    | Some slot -> slot
                    | None ->
                        failwith
                            $"UnixWait.wakes: the system holds no process %O{pid}, but the client holds its thread %O{thread} asleep (this is a bug in the client)."

                match UnixThreadTable.parkOf thread slot.Threads with
                | None ->
                    failwith
                        $"UnixWait.wakes: thread %O{thread} of process %O{pid} is asleep in a syscall but records no park, so nothing says what it waits for. A park is recorded by `UnixWait.park` when the thread goes to sleep (this is a bug in the client)."
                | Some park ->
                    let fired =
                        ProcessView.ofSlot pid slot system
                        |> WakeCondition.satisfied thread (WakeCondition.ofPark park.Syscall)

                    if Set.isEmpty fired then
                        None
                    else
                        Some (park.Ordinal, caller, fired)
            )
            |> List.sortBy (fun (ordinal, _, _) -> ordinal)

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
        // A thread woken and not yet finished stands, on each queue its own
        // call waits on exclusively, for whatever woke it.
        let finishing : Set<ExclusiveWaitQueue> =
            system.Processes
            |> Seq.collect (fun (KeyValue (key, slot)) ->
                let pid = ProcessId.parseOrFail "UnixWait.wakes" key

                slot.Threads
                |> Map.toSeq
                |> Seq.filter (fun (thread, _) -> not (Set.contains (Caller.make pid thread) asleep))
            )
            |> Seq.collect (fun (_, state) ->
                match state.Parked with
                | Some park -> exclusiveQueuesOfPark machine park.Syscall
                | None -> []
            )
            |> Set.ofSeq

        let chosen : Map<ExclusiveWaitQueue, Caller<'Thread>> =
            satisfied
            |> List.collect (fun (ordinal, thread, fired) ->
                fired
                |> Set.toList
                |> List.choose (fun primitive ->
                    exclusiveQueueOf machine primitive
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
                match exclusiveQueueOf machine primitive with
                | Some queue -> Map.tryFind queue chosen = Some thread
                | None -> true
            )
        )
        |> List.map (fun (_, caller, fired) -> caller, fired)

    /// Every deadline the parks of `asleep` are waiting for, in nanoseconds since
    /// boot, with a repeat for each park that waits for it.
    ///
    /// What a client with nothing runnable reads to learn how far it may advance
    /// the clock before one of these calls times out. `asleep` means what it
    /// means to `wakes`, and this fails loudly where `wakes` does.
    let deadlines<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (asleep : Set<Caller<'Thread>>)
        (system : UnixSystem<'Thread, 'Handler>)
        : int64 list
        =
        asleep
        |> Set.toList
        |> List.collect (fun caller ->
            let pid = Caller.processId caller
            let thread = Caller.thread caller

            let slot =
                match Map.tryFind (ProcessId.toInt32 pid) system.Processes with
                | Some slot -> slot
                | None ->
                    failwith
                        $"UnixWait.deadlines: the system holds no process %O{pid}, but the client holds its thread %O{thread} asleep (this is a bug in the client)."

            match UnixThreadTable.parkOf thread slot.Threads with
            | None ->
                failwith
                    $"UnixWait.deadlines: thread %O{thread} of process %O{pid} is asleep in a syscall but records no park, so nothing says what it waits for. A park is recorded by `UnixWait.park` when the thread goes to sleep (this is a bug in the client)."
            | Some park -> WakeCondition.deadlines (WakeCondition.ofPark park.Syscall)
        )

    /// `wakes`, which a client asks of every state it reaches, made cheap for
    /// the states in which nothing it reads has changed: the threads it wakes,
    /// and the memo to pass the next call.
    ///
    /// Answers that no thread wakes, without asking any wake condition, when
    /// `memo` remembers a sweep that woke none, and nothing that sweep read has
    /// changed since but the clock, which has not reached the earliest
    /// deadline any thread in `asleep` waits for. Nothing a syscall can change
    /// counts as unchanged unless it is the same value, so a client that makes
    /// a syscall that changes the system is swept afresh; a client that only
    /// moves the clock (`UnixSystem.advanceClock`), makes a call that changes
    /// nothing, or reports which thread runs where (`UnixScheduling.dispatch`,
    /// to a processor the thread is already on) is not. Otherwise sweeps as
    /// `wakes` does, and remembers the sweep if it woke nobody.
    ///
    /// The answer is always `wakes`'s, and `memo` decides only how much work it
    /// takes. Fails loudly where `wakes` does.
    ///
    /// A Debug build checks some of the answers the memo gives against a sweep,
    /// failing loudly if they differ, and answers a new memo after each of them,
    /// which counts them.
    let wakesRemembering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (memo : WakeSweepMemo<'Thread, 'Handler>)
        (asleep : Set<Caller<'Thread>>)
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * Set<WakePrimitive>) list * WakeSweepMemo<'Thread, 'Handler>
        =
        match memo.Remembered with
        | ValueSome remembered when
            WakeSweepMemo.covers remembered asleep system.Machine system.Scheduling system.Processes
            ->
#if DEBUG
            if WakeSweepMemo.crossChecks memo.HitsSinceSweep then
                match wakes asleep system with
                | [] -> ()
                | woken ->
                    failwith
                        $"UnixWait.wakesRemembering: the memo says the system wakes no thread, but a sweep wakes %A{woken}, at answer %d{memo.HitsSinceSweep} since the memo's sweep (this is a bug in this library)."

            [],
            { memo with
                HitsSinceSweep = memo.HitsSinceSweep + 1
            }
#else
            [], memo
#endif
        | ValueSome _
        | ValueNone ->

        match wakes asleep system with
        | _ :: _ as woken -> woken, WakeSweepMemo.empty
        | [] ->
            // `wakes` has failed loudly already for a thread asleep in no park.
            let deadlines = deadlines asleep system

            let earliest =
                match deadlines with
                | [] -> ValueNone
                | deadlines -> ValueSome (List.min deadlines)

            [],
            {
                Remembered =
                    ValueSome
                        {
                            Machine = system.Machine
                            Processes = system.Processes
                            Asleep = asleep
                            EarliestDeadline = earliest
                        }
#if DEBUG
                HitsSinceSweep = 0
#endif
            }
