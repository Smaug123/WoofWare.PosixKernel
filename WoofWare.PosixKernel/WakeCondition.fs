namespace WoofWare.PosixKernel

/// What a thread parked in a syscall is waiting for: one primitive, or the first
/// of several.
///
/// Data, and deliberately transparent: a client that cannot make progress needs
/// to *read* a condition as well as evaluate it — for example, to advance the
/// virtual clock to the nearest deadline when nothing is runnable, which
/// `UnixWait.deadlines` answers from the parks' conditions and a predicate could
/// not. So no case may carry a function.
[<RequireQualifiedAccess>]
type WakeCondition =
    /// Wait for this one primitive.
    | Primitive of WakePrimitive
    /// Wait until any of these holds. Never empty: a wait for any of nothing
    /// could never end.
    ///
    /// Only the set of primitives it contains matters, so nesting and repetition
    /// are immaterial: `satisfied` of an `AnyOf` is the union of `satisfied` of
    /// its members.
    | AnyOf of first : WakeCondition * rest : WakeCondition list

[<RequireQualifiedAccess>]
module WakeCondition =

    /// Whether the machine's monotonic clock has reached `deadline`, if the call
    /// has one: what `WakePrimitive.DeadlinePassed` waits for.
    let internal deadlinePassed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (deadline : int64 option)
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        match deadline with
        | Some deadline -> system.Scheduling.NanosecondsSinceBoot >= deadline
        | None -> false

    /// The pipe the open file description `description` names `pipeEnd` of, and
    /// that pipe; fails loudly, naming the waiter's `primitive`, for a
    /// description that is gone or names something else.
    let private pipeOfWaiter<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (primitive : WakePrimitive)
        (description : OpenFileDescriptionId)
        (pipeEnd : PipeEnd)
        (system : ProcessView<'Thread, 'Handler>)
        : PipeId * PipeState
        =
        match OpenFileTable.tryFind description system.Machine.OpenFiles with
        | None ->
            failwith
                $"WakeCondition.satisfied: open file description %O{description} is not in the table, but a thread waits on it (%A{primitive}), and a park holds what it waits on until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."
        | Some found ->
            match found.Target with
            | OpenFileTarget.Pipe (pipeId, named) when named = pipeEnd ->
                pipeId, UnixMachineState.pipe pipeId system.Machine
            | target ->
                failwith
                    $"WakeCondition.satisfied: a thread waits on open file description %O{description} for %A{primitive}, but the description names %A{target} rather than the %A{pipeEnd} end of a pipe (this is a bug in the caller that recorded the park)."

    /// The connection the socket the open file description `description` names
    /// is an end of, which end, and its transfer; fails loudly, naming the
    /// waiter's `primitive`, for a description that is gone or names
    /// something else.
    let private connectionOfWaiter<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (primitive : WakePrimitive)
        (description : OpenFileDescriptionId)
        (system : ProcessView<'Thread, 'Handler>)
        : ConnectionEnd * TcpTransfer
        =
        match OpenFileTable.tryFind description system.Machine.OpenFiles with
        | None ->
            failwith
                $"WakeCondition.satisfied: open file description %O{description} is not in the table, but a thread waits on it (%A{primitive}), and a park holds what it waits on until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."
        | Some found ->
            let phase =
                match found.Target with
                | OpenFileTarget.Socket socketId -> Some (UnixMachineState.socket socketId system.Machine).Phase
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Fifo _
                | OpenFileTarget.Pipe _
                | OpenFileTarget.Kqueue _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Epoll _ -> None

            match phase |> Option.bind SocketPhase.connectionEnd with
            | Some (connectionId, connectionEnd) ->
                connectionEnd, (UnixMachineState.connection connectionId system.Machine).Transfer
            | None ->
                failwith
                    $"WakeCondition.satisfied: a thread waits on open file description %O{description} for %A{primitive}, but the description names %A{found.Target} (%A{phase}) rather than an end of a connection. Nothing takes a socket out of a connection while a descriptor or a call holds it, so the park was recorded on one that was never connected (this is a bug in the caller that recorded it)."

    /// Whether a close has ended the call `thread` is asleep in.
    let private endedByClose<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        match
            Map.tryFind thread system.Threads
            |> Option.bind UnixThreadState.park
            |> Option.map (fun park -> park.Syscall)
        with
        | Some (ParkedSyscall.Accept {
                                         Listener = SleepTarget.EndedByClose _
                                     })
        | Some (ParkedSyscall.PipeRead {
                                           Reader = SleepTarget.EndedByClose _
                                       })
        | Some (ParkedSyscall.PipeWrite {
                                            Writer = SleepTarget.EndedByClose _
                                        })
        | Some (ParkedSyscall.ConnectionRead {
                                                 Socket = SleepTarget.EndedByClose _
                                             })
        | Some (ParkedSyscall.ConnectionWrite {
                                                  Socket = SleepTarget.EndedByClose _
                                              }) -> true
        | Some (ParkedSyscall.Accept _)
        | Some (ParkedSyscall.PipeRead _)
        | Some (ParkedSyscall.PipeWrite _)
        | Some (ParkedSyscall.ConnectionRead _)
        | Some (ParkedSyscall.ConnectionWrite _)
        | Some (ParkedSyscall.EpollWait _)
        | Some (ParkedSyscall.Kevent _)
        | Some (ParkedSyscall.Flock _)
        | Some (ParkedSyscall.Poll _)
        | Some (ParkedSyscall.KqueuePoll _)
        | Some ParkedSyscall.SigSuspend
        | Some (ParkedSyscall.Sleep _)
        | Some (ParkedSyscall.SignalWait _)
        | Some (ParkedSyscall.FifoOpen _)
        // Only Linux has inotify, and its close leaves the read asleep.
        | Some (ParkedSyscall.InotifyRead _)
        | Some (ParkedSyscall.Select _)
        | Some (ParkedSyscall.DatagramReceive _)
        | Some (ParkedSyscall.DatagramSend _)
        | Some (ParkedSyscall.Connect _)
        // Only Linux has futex, and nothing a close does reaches one.
        | Some (ParkedSyscall.Futex _)
        | None -> false

    /// Every primitive `condition` waits for, in order, repeats and all.
    let rec internal primitives (condition : WakeCondition) : WakePrimitive list =
        match condition with
        | WakeCondition.Primitive primitive -> [ primitive ]
        | WakeCondition.AnyOf (first, rest) -> primitives first @ List.collect primitives rest

    // A primitive that names a description no longer in the table has had its
    // wait broken underneath it: see `satisfied`.
    let private holds<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (primitive : WakePrimitive)
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        match primitive with
        | WakePrimitive.FlockGrantable (requester, mode) ->
            let openFiles = system.Machine.OpenFiles

            match OpenFileTable.tryFind requester openFiles with
            | None ->
                failwith
                    $"WakeCondition.satisfied: open file description %O{requester} is not in the table, but a thread is parked on an flock of it, and a park holds what it waits on until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."
            | Some description ->
                OpenFileTable.flockConflicts (OpenFileDescription.object requester description) requester mode openFiles
                |> not
        | WakePrimitive.EpollEventDeliverable epoll -> EpollReadyList.hasDeliverableEvent epoll system
        | WakePrimitive.KqueueEventDeliverable kqueue -> KqueueQueue.hasDeliverableEvent kqueue system
        | WakePrimitive.KqueuePollReportable -> KqueuePoll.reportable thread system
        | WakePrimitive.KqueueDrained kqueue ->
            match OpenFileTable.tryFind kqueue system.Machine.OpenFiles with
            | None ->
                failwith
                    $"WakeCondition.satisfied: open file description %O{kqueue} is not in the table, but a thread waits in kevent on it, and a park holds what it waits on until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."
            | Some description ->
                match description.Target with
                | OpenFileTarget.Kqueue state -> state.Drained
                | OpenFileTarget.File _
                | OpenFileTarget.Directory _
                | OpenFileTarget.CharacterDevice _
                | OpenFileTarget.Socket _
                | OpenFileTarget.Fifo _
                | OpenFileTarget.Pipe _
                | OpenFileTarget.Inotify _
                | OpenFileTarget.Epoll _ ->
                    failwith
                        $"WakeCondition.satisfied: a thread waits in kevent on open file description %O{kqueue}, which names %A{description.Target} rather than a kqueue (this is a bug in the caller that recorded the park)."
        | WakePrimitive.DescriptorReady (description, conditions) ->
            if (OpenFileTable.tryFind description system.Machine.OpenFiles).IsNone then
                failwith
                    $"WakeCondition.satisfied: open file description %O{description} is not in the table, but a thread waits for it to become ready, and a park holds what it waits on until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."

            LinuxReadiness.ofDescription description system &&& conditions <> 0u
        | WakePrimitive.AcceptQueueNonEmpty listener ->
            match OpenFileTable.tryFind listener system.Machine.OpenFiles with
            | None ->
                failwith
                    $"WakeCondition.satisfied: open file description %O{listener} is not in the table, but a thread is parked in an accept on it, and a park holds what it waits on until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."
            | Some description ->

            match description.Target with
            | OpenFileTarget.Socket socketId ->
                match (UnixMachineState.socket socketId system.Machine).Phase with
                | SocketPhase.Listening listenState -> not (List.isEmpty listenState.Queue)
                | phase ->
                    failwith
                        $"WakeCondition.satisfied: a thread is parked in an accept on socket %O{socketId}, which is in %A{phase} rather than listening. Nothing takes a live listener out of listening, so the park was recorded on a socket that was never one (this is a bug in the caller that recorded it)."
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Pipe _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Epoll _ ->
                failwith
                    $"WakeCondition.satisfied: a thread is parked in an accept on open file description %O{listener}, which names %A{description.Target} rather than a socket (this is a bug in the caller that recorded it)."
        | WakePrimitive.PipeHasBytes reader ->
            let _, pipe = pipeOfWaiter primitive reader PipeEnd.Read system
            PipeBuffer.held pipe.Buffer > 0
        | WakePrimitive.PipeWriteEndClosed reader ->
            let pipeId, pipe = pipeOfWaiter primitive reader PipeEnd.Read system
            not (UnixMachineState.pipeEndOpen pipeId pipe PipeEnd.Write system.Machine)
        | WakePrimitive.PipeHasRoom (writer, count, written) ->
            let _, pipe = pipeOfWaiter primitive writer PipeEnd.Write system
            PipeBuffer.resumeTakes count written pipe.Buffer > 0
        | WakePrimitive.PipeReadEndClosed writer ->
            let pipeId, pipe = pipeOfWaiter primitive writer PipeEnd.Write system
            not (UnixMachineState.pipeEndOpen pipeId pipe PipeEnd.Read system.Machine)
        | WakePrimitive.PipeReadWhileNonBlocking (writer, reads) ->
            let _, pipe = pipeOfWaiter primitive writer PipeEnd.Write system

            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Linux -> false
            | SimulatedUnixFlavour.Darwin ->
                pipe.Reads > reads
                && (OpenFileTable.get "WakeCondition" writer system.Machine.OpenFiles).NonBlocking
        | WakePrimitive.ConnectionReadable reader ->
            let connectionEnd, transfer = connectionOfWaiter primitive reader system
            TcpTransfer.readAnswers connectionEnd transfer
        | WakePrimitive.ConnectionWritable (writer, remaining) ->
            let connectionEnd, transfer = connectionOfWaiter primitive writer system
            TcpTransfer.writeResumes connectionEnd remaining transfer
        | WakePrimitive.DeadlinePassed deadline -> deadlinePassed (Some deadline) system
        | WakePrimitive.SignalDeliverable -> SyscallInterruption.wakes thread system
        // `satisfied` answers a call a close has ended before it asks any
        // primitive, so this is asked only of one no close has ended.
        | WakePrimitive.EndedByClose -> false
        | WakePrimitive.FifoPartnerOpened _ ->
            failwith
                $"WakeCondition.satisfied: thread %O{thread} waits for %A{primitive}, but this library keeps no count of a FIFO's opens to evaluate it against: nothing parks a thread in a FIFO open yet (`ParkedSyscall.FifoOpen` is reserved), so the park was recorded by hand (this is a bug in the caller that recorded it)."
        | WakePrimitive.AcceptQueueHasRoom _ ->
            failwith
                $"WakeCondition.satisfied: thread %O{thread} waits for %A{primitive}, but nothing parks a thread in a connect yet (`ParkedSyscall.Connect` is reserved), so the park was recorded by hand (this is a bug in the caller that recorded it)."
        | WakePrimitive.InotifyRecordQueued reader ->
            not (
                InotifyQueue.isEmpty
                    (OpenFileTable.inotifyState "WakeCondition.satisfied" reader system.Machine.OpenFiles).Queue
            )
        | WakePrimitive.AwaitedSignalPending _ ->
            failwith
                $"WakeCondition.satisfied: thread %O{thread} waits for %A{primitive}, but nothing parks a thread in a signal wait yet (`ParkedSyscall.SignalWait` is reserved), and which pending signals such a wait may take is not modelled, so the park was recorded by hand (this is a bug in the caller that recorded it)."
        | WakePrimitive.FutexWakeTaken ->
            match Map.tryFind thread system.Threads |> Option.bind UnixThreadState.parkedIn with
            | Some (ParkedSyscall.Futex wait) -> wait.TakenByWake
            | parked ->
                failwith
                    $"WakeCondition.satisfied: thread %O{thread} waits for %A{primitive}, which only a futex wait waits for, but it is parked in %A{parked} (this is a bug in the caller that recorded the park)."

    /// The primitives of `condition`, the wake condition of `thread`, which hold of
    /// `system`: empty exactly when the syscall that parked on it would get no
    /// further now.
    ///
    /// A set rather than a yes or no so that the call which finishes the wait
    /// can tell *why* it woke — an event, or its deadline — which a real kernel
    /// reports differently.
    ///
    /// Pure, and cheap enough to poll. It is never a promise that finishing
    /// succeeds: another thread can take the lock in between, and the caller
    /// then parks again.
    ///
    /// **A condition is only ever asked of a system whose kernel objects it
    /// still names.** A waiter on a real kernel holds a reference to the open
    /// file it waits on, so that file cannot be destroyed underneath it, and a
    /// park here does the same: the descriptions it names outlive their last
    /// descriptor until the call returns. Asking about a description that has
    /// gone means a park was ended or a description destroyed some other way,
    /// and it fails loudly rather than answering: the honest answers are
    /// "grantable", which wakes the thread into an `EBADF` no kernel produces,
    /// and "not yet", which sleeps forever.
    ///
    /// Internal because a condition built by hand, or kept from a park that
    /// has since ended, can name a description that has gone. A client asks
    /// `UnixWait.satisfied` about a thread, which reads the condition from the
    /// thread's own park, and that park holds what it names.
    ///
    /// A thread whose call a close has ended (`WakePrimitive.EndedByClose`)
    /// answers that primitive alone: the call holds nothing any more, and the
    /// descriptions its other primitives name may have gone with the close.
    let internal satisfied<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (condition : WakeCondition)
        (system : ProcessView<'Thread, 'Handler>)
        : Set<WakePrimitive>
        =
        let rec live (condition : WakeCondition) : Set<WakePrimitive> =
            match condition with
            | WakeCondition.Primitive primitive ->
                if holds thread primitive system then
                    Set.singleton primitive
                else
                    Set.empty
            | WakeCondition.AnyOf (first, rest) ->
                (live first, rest)
                ||> List.fold (fun acc condition -> Set.union acc (live condition))

        if endedByClose thread system then
            if List.contains WakePrimitive.EndedByClose (primitives condition) then
                Set.singleton WakePrimitive.EndedByClose
            else
                failwith
                    $"WakeCondition.satisfied: a close has ended the call thread %O{thread} is asleep in, and it was asked about %A{condition}, which does not wait for that, so is not the wake condition of the call (this is a bug in the caller)."
        else
            live condition

    /// Every deadline in `condition`, in nanoseconds since boot, one per
    /// `DeadlinePassed` it contains.
    ///
    /// Internal because the condition alone will not always say when a park
    /// times out: a timerfd's next expiry depends on its current setting, which
    /// only the system holds. Clients read `UnixWait.deadlines`, which takes the
    /// system.
    let rec internal deadlines (condition : WakeCondition) : int64 list =
        match condition with
        | WakeCondition.Primitive (WakePrimitive.DeadlinePassed deadline) -> [ deadline ]
        | WakeCondition.Primitive (WakePrimitive.FlockGrantable _)
        | WakeCondition.Primitive (WakePrimitive.EpollEventDeliverable _)
        | WakeCondition.Primitive (WakePrimitive.KqueueDrained _)
        | WakeCondition.Primitive (WakePrimitive.KqueueEventDeliverable _)
        | WakeCondition.Primitive WakePrimitive.KqueuePollReportable
        | WakeCondition.Primitive (WakePrimitive.DescriptorReady _)
        | WakeCondition.Primitive (WakePrimitive.AcceptQueueNonEmpty _)
        | WakeCondition.Primitive (WakePrimitive.PipeHasBytes _)
        | WakeCondition.Primitive (WakePrimitive.PipeWriteEndClosed _)
        | WakeCondition.Primitive (WakePrimitive.PipeHasRoom _)
        | WakeCondition.Primitive (WakePrimitive.PipeReadEndClosed _)
        | WakeCondition.Primitive (WakePrimitive.PipeReadWhileNonBlocking _)
        | WakeCondition.Primitive (WakePrimitive.ConnectionReadable _)
        | WakeCondition.Primitive (WakePrimitive.ConnectionWritable _)
        | WakeCondition.Primitive WakePrimitive.SignalDeliverable
        | WakeCondition.Primitive WakePrimitive.EndedByClose
        | WakeCondition.Primitive (WakePrimitive.FifoPartnerOpened _)
        | WakeCondition.Primitive (WakePrimitive.InotifyRecordQueued _)
        | WakeCondition.Primitive (WakePrimitive.AwaitedSignalPending _)
        | WakeCondition.Primitive (WakePrimitive.AcceptQueueHasRoom _)
        | WakeCondition.Primitive WakePrimitive.FutexWakeTaken -> []
        | WakeCondition.AnyOf (first, rest) -> deadlines first @ List.collect deadlines rest

    /// What the thread holding `parked` is waiting for: what its syscall waits
    /// for, or a signal (`WakePrimitive.SignalDeliverable`), whichever comes
    /// first.
    ///
    /// The direction that generalises, and the one every reader of a park should
    /// use. A record is *richer* than its condition — a parked `epoll_wait` also carries
    /// the event count its finishing call will copy out with, which no condition
    /// mentions — so record to condition is total where condition to record is
    /// not. A parked `poll` that watches no descriptor and has no deadline waits
    /// for a signal alone, and so does a parked `sigsuspend`.
    ///
    /// Deriving rather than storing the condition beside the record is what stops
    /// the two disagreeing: a client cannot park a thread on one object while
    /// polling for another, because the thing polled *is* the thing parked on.
    let ofPark (parked : ParkedSyscall) : WakeCondition =
        let ended = WakeCondition.Primitive WakePrimitive.EndedByClose

        let own : WakeCondition list =
            match parked with
            | ParkedSyscall.Flock parked ->
                [
                    WakeCondition.Primitive (WakePrimitive.FlockGrantable (parked.Requester, parked.Mode))
                ]
            | ParkedSyscall.EpollWait wait ->
                let deliverable =
                    WakeCondition.Primitive (WakePrimitive.EpollEventDeliverable wait.Epoll)

                match wait.Deadline with
                | None -> [ deliverable ]
                | Some deadline ->
                    [
                        deliverable
                        WakeCondition.Primitive (WakePrimitive.DeadlinePassed deadline)
                    ]
            | ParkedSyscall.Kevent wait ->
                let deliverable =
                    WakeCondition.Primitive (WakePrimitive.KqueueEventDeliverable wait.Kqueue)

                let drained = WakeCondition.Primitive (WakePrimitive.KqueueDrained wait.Kqueue)

                match wait.Deadline with
                | None -> [ deliverable ; drained ]
                | Some deadline ->
                    [
                        deliverable
                        drained
                        WakeCondition.Primitive (WakePrimitive.DeadlinePassed deadline)
                    ]
            | ParkedSyscall.Poll poll ->
                let watched =
                    poll.Entries
                    |> List.choose (fun entry ->
                        match entry with
                        | ParkedPollEntry.Ignored _ -> None
                        | ParkedPollEntry.Watched (_, description, events) ->
                            // Through `uint16`, so that a request with its top bit
                            // set does not sign-extend into bits above `<poll.h>`.
                            let conditions = uint32 (uint16 events) ||| EpollEvents.Err ||| EpollEvents.Hup
                            Some (WakeCondition.Primitive (WakePrimitive.DescriptorReady (description, conditions)))
                    )

                let deadline =
                    poll.Deadline
                    |> Option.map (WakePrimitive.DeadlinePassed >> WakeCondition.Primitive)
                    |> Option.toList

                watched @ deadline
            | ParkedSyscall.KqueuePoll poll ->
                let deadline =
                    poll.Deadline
                    |> Option.map (WakePrimitive.DeadlinePassed >> WakeCondition.Primitive)
                    |> Option.toList

                WakeCondition.Primitive WakePrimitive.KqueuePollReportable :: deadline
            | ParkedSyscall.Accept accept ->
                match accept.Listener with
                | SleepTarget.EndedByClose _ -> [ ended ]
                | SleepTarget.Waiting (listener, _) ->
                    // No deadline: `SO_RCVTIMEO`, which bounds a Linux accept, is an
                    // option `setsockopt` refuses to set.
                    [ WakeCondition.Primitive (WakePrimitive.AcceptQueueNonEmpty listener) ; ended ]
            | ParkedSyscall.PipeRead read ->
                match read.Reader with
                | SleepTarget.EndedByClose _ -> [ ended ]
                | SleepTarget.Waiting (reader, _) ->
                    [
                        WakeCondition.Primitive (WakePrimitive.PipeHasBytes reader)
                        WakeCondition.Primitive (WakePrimitive.PipeWriteEndClosed reader)
                        ended
                    ]
            | ParkedSyscall.PipeWrite write ->
                match write.Writer with
                | SleepTarget.EndedByClose _ -> [ ended ]
                | SleepTarget.Waiting (writer, _) ->
                    [
                        WakeCondition.Primitive (WakePrimitive.PipeHasRoom (writer, write.Count, write.Written))
                        WakeCondition.Primitive (WakePrimitive.PipeReadEndClosed writer)
                        WakeCondition.Primitive (WakePrimitive.PipeReadWhileNonBlocking (writer, write.ReadsSeen))
                        ended
                    ]
            | ParkedSyscall.ConnectionRead read ->
                match read.Socket with
                | SleepTarget.EndedByClose _ -> [ ended ]
                | SleepTarget.Waiting (reader, _) ->
                    // No deadline: `SO_RCVTIMEO`, which would bound the wait, is
                    // an option `setsockopt` refuses to set.
                    [ WakeCondition.Primitive (WakePrimitive.ConnectionReadable reader) ; ended ]
            | ParkedSyscall.ConnectionWrite write ->
                match write.Socket with
                | SleepTarget.EndedByClose _ -> [ ended ]
                | SleepTarget.Waiting (writer, _) ->
                    // No deadline, as for a read: `setsockopt` refuses to set
                    // `SO_SNDTIMEO`.
                    [
                        WakeCondition.Primitive (WakePrimitive.ConnectionWritable (writer, write.Count - write.Written))
                        ended
                    ]
            // A signal alone ends it.
            | ParkedSyscall.SigSuspend -> []
            // Its deadline, or a signal.
            | ParkedSyscall.Sleep sleep -> [ WakeCondition.Primitive (WakePrimitive.DeadlinePassed sleep.Deadline) ]
            // A partner's open, or a signal. No close ends it: no descriptor
            // names its description until the call installs one.
            | ParkedSyscall.FifoOpen fifoOpen ->
                [
                    WakeCondition.Primitive (WakePrimitive.FifoPartnerOpened (fifoOpen.Opener, fifoOpen.PartnerOpens))
                ]
            // A record, or a signal. No close ends it, since only Linux has
            // inotify.
            | ParkedSyscall.InotifyRead read ->
                [ WakeCondition.Primitive (WakePrimitive.InotifyRecordQueued read.Instance) ]
            // Its deadline, or a signal. The descriptors it waits on join this
            // when something parks a thread in it.
            | ParkedSyscall.Select select ->
                select.Deadline
                |> Option.map (WakePrimitive.DeadlinePassed >> WakeCondition.Primitive)
                |> Option.toList
            // An awaited signal, its deadline, or (below, as for every park) a
            // signal with a handler outside its set. Under Darwin a signal
            // outside the set does not end the call (measured,
            // `docs/probes/sigwait`): its handler runs only once the call
            // returns. Saying so for a Darwin thread in a signal wait is
            // `SignalDeliverable`'s evaluation's, which is not modelled:
            // evaluating this condition fails at `AwaitedSignalPending`.
            | ParkedSyscall.SignalWait wait ->
                let deadline =
                    wait.Deadline
                    |> Option.map (WakePrimitive.DeadlinePassed >> WakeCondition.Primitive)
                    |> Option.toList

                WakeCondition.Primitive (WakePrimitive.AwaitedSignalPending wait.Awaited)
                :: deadline
            // A signal alone, while they are reserved: what a datagram transfer
            // waits for joins this when something parks a thread in one.
            | ParkedSyscall.DatagramReceive _
            | ParkedSyscall.DatagramSend _ -> []
            // A signal alone, while it is reserved: a retransmit deadline, or
            // room in the listener's queue, joins this when something parks a
            // thread in it.
            | ParkedSyscall.Connect _ -> []
            // A wake that takes it, its deadline, or a signal.
            | ParkedSyscall.Futex wait ->
                let deadline =
                    wait.FutexDeadline
                    |> Option.map (WakePrimitive.DeadlinePassed >> WakeCondition.Primitive)
                    |> Option.toList

                WakeCondition.Primitive WakePrimitive.FutexWakeTaken :: deadline

        let signal = WakeCondition.Primitive WakePrimitive.SignalDeliverable

        match own with
        | [] -> signal
        | first :: rest -> WakeCondition.AnyOf (first, rest @ [ signal ])

/// What became of a request this kernel could answer, where "answer" may be
/// "the calling thread sleeps".
[<RequireQualifiedAccess>]
type SyscallOutcome =
    /// The entry point returned.
    | Answered of SyscallAnswer
    /// The entry point did not return. The calling thread sleeps until
    /// `UnixWait.wake` wakes it, and then
    /// finishes the call; what sleeping means, and when to re-ask, are the client's
    /// scheduler's business, which is why this library has no opinion on either.
    ///
    /// **Finishing is not re-issuing the original call.** The syscall's
    /// arguments named a descriptor; the condition names the kernel object that
    /// descriptor stood for, and a sleeping thread keeps the object rather than
    /// the number. Descriptor numbers are reused as soon as they are free, so a
    /// `close` of the number this call was made through can leave that number
    /// naming something else entirely by the time the waiter wakes, while the
    /// object lives on for the waiter. `ParkedEpollWait` holds its epoll instance by
    /// description identity for exactly this reason.
    ///
    /// The system this rides with is the one a real kernel sleeps *in*, not the
    /// one the call arrived with: `flock` removes the caller's old lock before
    /// it establishes the new one, so a parked conversion is already holding
    /// nothing. That advance is the whole reason blocking is an outcome here
    /// rather than a refusal, which by design carries no system at all.
    | WouldBlock of WakeCondition
    /// The call was asleep, and a signal interrupted it. The thread is no longer
    /// parked, and owes a return to user mode (`UnixSignal.onReturnToUser`),
    /// which it makes before any other call: that return says whether the call
    /// fails with `EINTR` or restarts, from the signals as they are then.
    ///
    /// Only a finishing call answers this, never the call as first made.
    | Interrupted
