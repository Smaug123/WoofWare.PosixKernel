namespace WoofWare.PosixKernel

/// Deciding which parked threads a system wakes.
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
        Map.tryFind thread system.Threads
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

    /// Every park on the machine, each with its thread's caller and the slot of
    /// its process, in process ID order and, within a process, in the order of
    /// its threads' names.
    let private parks<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (operation : string)
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * ProcessSlot<'Thread, 'Handler> * ThreadPark) list
        =
        system.Processes
        |> Seq.collect (fun (KeyValue (key, slot)) ->
            let pid = ProcessId.parseOrFail operation key

            slot.Threads
            |> Seq.choose (fun (KeyValue (thread, state)) ->
                state.Parked |> Option.map (fun park -> Caller.make pid thread, slot, park)
            )
        )
        |> List.ofSeq

    /// The sleeping threads `system` wakes now, in the order they parked, each
    /// with the primitives of its wake condition which hold: what `wake`
    /// answers, before it records the wakes.
    let private wakesAmong<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : (Caller<'Thread> * Set<WakePrimitive>) list
        =
        let machine = system.Machine
        let parks = parks "UnixWait.wake" system

        let satisfied =
            parks
            |> List.choose (fun (caller, slot, park) ->
                match park.State with
                | ParkState.Woken _ -> None
                | ParkState.Asleep ->
                    let thread = Caller.thread caller

                    let fired =
                        ProcessView.ofSlot (Caller.processId caller) slot system
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
            parks
            |> List.collect (fun (_, _, park) ->
                match park.State with
                | ParkState.Woken _ -> Parking.exclusiveQueuesOfPark machine park.Syscall
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
        |> List.map (fun (_, caller, fired) -> caller, fired)

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
        |> List.collect (fun (_, _, park) ->
            match park.State with
            | ParkState.Asleep -> WakeCondition.deadlines (WakeCondition.ofPark park.Syscall)
            | ParkState.Woken _ -> []
        )

    /// `system`, whose sweep woke no thread, remembering that sweep: what it
    /// read, and the earliest deadline a sleeping thread waits for.
    let private remembering<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let earliest =
            match deadlines system with
            | [] -> ValueNone
            | deadlines -> ValueSome (List.min deadlines)

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
    /// and has not yet finished its call, since that thread will take it. The
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
                match wakesAmong system with
                | [] -> ()
                | woken ->
                    failwith
                        $"UnixWait.wake: the system's memo says it wakes no thread, but a sweep wakes %A{woken}, at answer %d{hits} since the memo's sweep (this is a bug in this library)."
#endif
            [], system
        | ValueSome _
        | ValueNone ->

        match wakesAmong system with
        | [] -> [], remembering system
        | woken ->
            let processes =
                (system.Processes, woken)
                ||> List.fold (fun processes (caller, fired) ->
                    let key = ProcessId.toInt32 (Caller.processId caller)
                    let slot = Map.find key processes

                    Map.add
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
