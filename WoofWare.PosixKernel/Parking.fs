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

/// Making and reading the wake memo a kernel carries (`UnixSystem.Sweep`).
[<RequireQualifiedAccess>]
module internal WakeMemo =
    /// A memo that remembers no sweep, so the next `UnixWait.wake` sweeps.
    let none<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> : WakeMemo<'Thread, 'Handler> =
        {
            Remembered = ValueNone
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

    /// Whether `processes` holds, under the same IDs, every process's state
    /// and threads that `remembered` read, the same values rather than equal
    /// ones.
    let private sameSlots<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (remembered : RememberedSweep<'Thread, 'Handler>)
        (processes : Map<int32, ProcessSlot<'Thread, 'Handler>>)
        : bool
        =
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

    /// Whether `machine` and `processes` are the machine state and every
    /// process's state and threads that `remembered` read, the same values
    /// rather than equal ones: whether everything a wake condition reads but
    /// the clock, and which threads sleep, are as `remembered` found them.
    let internal readsSame<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (remembered : RememberedSweep<'Thread, 'Handler>)
        (machine : UnixMachineState)
        (processes : Map<int32, ProcessSlot<'Thread, 'Handler>>)
        : bool
        =
        // `sameSlots`, which allocates, only when the process map is another
        // value: it is the same one after a clock advance, a dispatch to the
        // processor a thread is already on, and a call that changed nothing.
        LanguagePrimitives.PhysicalEquality remembered.Machine machine
        && (LanguagePrimitives.PhysicalEquality remembered.Processes processes
            || sameSlots remembered processes)

    /// Whether a sweep of a system would wake no thread because `remembered`
    /// woke none: whether it `readsSame` as `remembered`, and the clock has not
    /// reached the earliest deadline any sleeping thread waits for.
    ///
    /// The clock is the one input a wake condition reads that changes between
    /// syscalls, and only `WakePrimitive.DeadlinePassed` reads it; so with
    /// everything else the same and the clock short of every deadline, each
    /// primitive holds or does not exactly as it did, and the sweep's answer
    /// is the same.
    let internal covers<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (remembered : RememberedSweep<'Thread, 'Handler>)
        (machine : UnixMachineState)
        (scheduling : UnixSchedulingState)
        (processes : Map<int32, ProcessSlot<'Thread, 'Handler>>)
        : bool
        =
        (match remembered.EarliestDeadline with
         | ValueNone -> true
         | ValueSome deadline -> scheduling.NanosecondsSinceBoot < deadline)
        && readsSame remembered machine processes

/// Parking a thread in a syscall, and the wait queues whose waiters a real
/// kernel wakes one at a time, which `UnixWait.wake` reads.
[<RequireQualifiedAccess>]
module internal Parking =

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

    /// Record that `thread` has parked in `parked`, asleep, placing it after
    /// every park made before it, and taking the holds the call keeps on the
    /// open file descriptions it names (`ParkedSyscall.descriptions`). A thread
    /// that sleeps is no longer running, so it leaves its processor idle
    /// (`UnixSchedulingState.Occupants`).
    ///
    /// Refuses to replace a park of one syscall with a park of another, and
    /// otherwise accepts a re-park of the same syscall by a woken thread, which
    /// puts it asleep again, moves it to the back of park order and lets go of
    /// the holds the earlier park took.
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
                State = ParkState.Asleep
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
                    $"Parking.parkWaiting: thread %O{thread} parks in %A{parked}, but %A{held} of its own wake condition already hold, so a client would wake it at once (this is a bug in this library)."
#endif

        asleep
