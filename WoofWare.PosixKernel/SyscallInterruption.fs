namespace WoofWare.PosixKernel

/// Why this library will not say how a signal ends the syscall a thread is asleep
/// in.
[<RequireQualifiedAccess>]
type internal SyscallInterruptionRefusal =
    /// The library will not say what the thread takes as it returns to user
    /// mode.
    | Receiver of SignalReceiverRefusal
    /// The first signal the thread would take as it returns to user mode is at
    /// its default disposition, which terminates, stops or continues the
    /// process, rather than caught.
    | DefaultAction of signal : Signal
    /// The syscall has its own answer to give and a signal with a handler is
    /// deliverable to the thread too, under a flavour whose kernel answers,
    /// for this syscall, whichever of the two reached the sleeping thread
    /// first; and both had reached it by the time `UnixWait.wake` woke it, or
    /// the one that woke it does not say which came first.
    | SignalBesideCompletion of flavour : SimulatedUnixFlavour
    /// A signal woke the thread asleep in the syscall, and by the time the
    /// syscall is finished the thread would take no signal as it returned to
    /// user mode: another thread has discarded the signal, or the thread
    /// blocks it. Whether the syscall then ends or sleeps on is unmeasured.
    | WakingSignalGone
    /// A signal woke the thread asleep in a futex wait with a relative timeout
    /// (`FutexTimeout.Until`), and by
    /// the time the call is finished the thread would take no signal as it
    /// returned to user mode. The wait then restarts with its first deadline,
    /// reading the word at its address again, which only the caller can read;
    /// and a caller making the call again gives it a later deadline.
    | FutexRestartKeepsDeadline

[<RequireQualifiedAccess>]
module internal SyscallInterruptionRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which call was asleep, and in which thread.
    let describe (refusal : SyscallInterruptionRefusal) : string =
        match refusal with
        | SyscallInterruptionRefusal.Receiver refusal ->
            $"a signal is pending for a thread asleep in a syscall, and this kernel will not say what the thread takes as it returns to user mode: %s{SignalReceiverRefusal.describe refusal}"
        | SyscallInterruptionRefusal.DefaultAction signal ->
            $"the first signal a thread asleep in a syscall would take is %O{signal}, at a default disposition that terminates, stops or continues the process, and what that does to the syscall is unmeasured."
        | SyscallInterruptionRefusal.SignalBesideCompletion flavour ->
            $"a thread asleep in a syscall has both the syscall's own answer and a signal with a handler waiting for it. Under the %O{flavour} flavour the kernel answers, for this syscall, whichever of the two reached the sleeping thread first, and what woke the thread does not say which did."
        | SyscallInterruptionRefusal.WakingSignalGone ->
            "a signal woke a thread asleep in a syscall, and by the time the syscall was finished the thread would take no signal as it returned to user mode: another thread had discarded the signal, or the thread blocked it. Whether the syscall then ends with EINTR or sleeps on is unmeasured."
        | SyscallInterruptionRefusal.FutexRestartKeepsDeadline ->
            "a signal woke a thread asleep in a futex wait with a relative timeout, and by the time the call was finished the thread would take no signal as it returned to user mode. Linux restarts such a wait with its first deadline, reading the word at its address again; only the caller can read that word, and a caller making the call again with its own arguments gives the wait a later deadline."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SyscallInterruptionRefusal) : RefusalKind =
        match refusal with
        | SyscallInterruptionRefusal.Receiver inner -> SignalReceiverRefusal.kind inner
        | SyscallInterruptionRefusal.DefaultAction _ -> RefusalKind.Unmodelled
        | SyscallInterruptionRefusal.SignalBesideCompletion _ -> RefusalKind.Unmodelled
        | SyscallInterruptionRefusal.WakingSignalGone -> RefusalKind.Unmodelled
        | SyscallInterruptionRefusal.FutexRestartKeepsDeadline -> RefusalKind.Unmodelled

/// Why this library will not answer a `sigsuspend(2)` or `pause(2)`, or the
/// finishing of one: something it does not model, rather than an error a
/// kernel would report.
[<RequireQualifiedAccess>]
type internal SigsuspendRefusal =
    /// The library will not say what the thread takes as it returns to user
    /// mode.
    | Receiver of SignalReceiverRefusal
    /// The first signal the thread would take under the temporary mask is
    /// `signal`, at its default, which stops the process. Stopped and then
    /// continued with no handler run, a real kernel restarts the call, so that
    /// it sleeps on under the temporary mask (measured on both flavours); this
    /// library models no stopped process for the call to sleep on in.
    | DefaultStop of signal : Signal
    /// Under Darwin, the thread could take a pending SIGCONT under the temporary
    /// mask, ignored or at its default. Darwin leaves one generated while the
    /// thread blocked it pending under such a mask, without ending the call, and
    /// does not end it even once a handler is installed for the signal, until
    /// another signal ends the call and both are delivered (measured). This
    /// library wakes a sleeping thread from the state alone, so cannot leave a
    /// signal it could deliver undelivered. One generated during the sleep
    /// never gets here: the temporary mask lets it through, so it is
    /// discarded as it is sent (measured).
    | DarwinPendingContinue

[<RequireQualifiedAccess>]
module internal SigsuspendRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which call was made, and by which thread.
    let describe (refusal : SigsuspendRefusal) : string =
        match refusal with
        | SigsuspendRefusal.Receiver refusal ->
            $"a thread in sigsuspend would take a signal, and this kernel will not say what it takes as it returns to user mode: %s{SignalReceiverRefusal.describe refusal}"
        | SigsuspendRefusal.DefaultStop signal ->
            $"the first signal a thread in sigsuspend would take is %O{signal}, at its default, which stops the process. A real kernel restarts the call once the process is continued, if no handler has run, and this kernel models no stopped process."
        | SigsuspendRefusal.DarwinPendingContinue ->
            "under Darwin, a thread in sigsuspend could take a pending SIGCONT, ignored or at its default. Darwin was measured to leave such a signal pending without ending the call until another signal does, which this kernel cannot express: it wakes a sleeping thread whenever the state holds something for it to take."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SigsuspendRefusal) : RefusalKind =
        match refusal with
        | SigsuspendRefusal.Receiver inner -> SignalReceiverRefusal.kind inner
        | SigsuspendRefusal.DefaultStop _ -> RefusalKind.Unmodelled
        | SigsuspendRefusal.DarwinPendingContinue -> RefusalKind.Unmodelled

[<RequireQualifiedAccess>]
[<CompilationRepresentation(CompilationRepresentationFlags.ModuleSuffix)>]
module SyscallInterruption =

    /// How the syscall `parked` records ends under `flavour` when a signal with
    /// a handler interrupts it.
    ///
    /// A park `flavour` never makes (an `epoll_wait` under Darwin, a `kevent`
    /// under Linux) is answered as the flavour that makes it ends it. So is a
    /// signal wait (`ParkedSyscall.SignalWait`, reserved) under Darwin, where a
    /// handler does not end one: it is answered as Linux ends it.
    let ruleOf (flavour : SimulatedUnixFlavour) (parked : ParkedSyscall) : SignalRestartRule =
        // Measured on Linux 6.18.5 and Darwin 25.6.0
        // (`docs/plans/2026-08-23-posix-kernel-extraction/signal-sigaction-flags.c`),
        // each call blocked and signalled 50 ms in: `flock` and `accept` returned
        // EINTR without SA_RESTART and completed with it; `poll` with a timeout
        // of -1 or 300 ms, and `epoll_wait` on Linux and `kevent` on Darwin,
        // returned EINTR either way. A `poll` that watches nothing fails with
        // EINTR either way too, measured on Linux 6.18.5 and Darwin 27.0.0
        // (`signal-interrupt-requeue.c`, section A).
        //
        // A receive with `SO_RCVTIMEO` set is where the flavours part (Linux
        // EINTR, Darwin restarts), and Linux's accept answers EINTR under a
        // timeout for the same reason (`sock_intr_errno`). A parked accept never
        // has one: `setsockopt` refuses to set `SO_RCVTIMEO`.
        //
        // Measured on Linux 6.18.5 and Darwin 27.0.0 (`pipe-blocking.c`,
        // sections C and D): a `read` of an empty pipe, and a `write` into a
        // full one that had put nothing in, returned EINTR without SA_RESTART
        // and went on sleeping with it. A write that had put bytes in returns
        // their count either way, which its finishing call answers before it
        // asks this.
        //
        // Measured on Linux 6.18.5 and Darwin 27.0.0 (`tcp-blocking.c`,
        // sections R-eintr, R-restart and W-empty): the same of a `read` of a
        // connected socket with nothing to answer, and of a `write` to one that
        // had taken nothing. `SO_RCVTIMEO` and `SO_SNDTIMEO`, under which
        // Linux's `sock_intr_errno` answers EINTR instead, cannot be set.
        match parked with
        | ParkedSyscall.Flock _
        | ParkedSyscall.Accept _
        | ParkedSyscall.PipeRead _
        | ParkedSyscall.PipeWrite _
        | ParkedSyscall.ConnectionRead _
        | ParkedSyscall.ConnectionWrite _ -> SignalRestartRule.RestartsUnderSaRestart
        // Measured on Linux 6.18.5 (`inotify-probe.c` section B): a read of an
        // inotify instance with no record returned EINTR without SA_RESTART,
        // and went on sleeping with it to return the next record.
        | ParkedSyscall.InotifyRead _ -> SignalRestartRule.RestartsUnderSaRestart
        | ParkedSyscall.EpollWait _
        | ParkedSyscall.Kevent _
        | ParkedSyscall.Poll _
        | ParkedSyscall.KqueuePoll _ -> SignalRestartRule.FailsWithEintr
        // Measured on Linux 6.18.5 and Darwin 27.0.0 (`sigsuspend-mask.c`, the
        // "handler" and "pause-handler" rows): EINTR under SA_RESTART too.
        | ParkedSyscall.SigSuspend -> SignalRestartRule.FailsWithEintr
        // Measured on Linux 6.18.5 and Darwin 27.0.0: a `nanosleep` a caught
        // signal interrupts answers EINTR under SA_RESTART too, and is never
        // restarted.
        | ParkedSyscall.Sleep _ -> SignalRestartRule.FailsWithEintr
        // Measured on Linux 6.18.5 and Darwin 27.0.0, for an open of either end
        // signalled into its sleep: EINTR without SA_RESTART on both. With it,
        // Linux's call sleeps on and completes once a partner opens, and
        // Darwin's answers EINTR.
        | ParkedSyscall.FifoOpen _ ->
            match flavour with
            | SimulatedUnixFlavour.Linux -> SignalRestartRule.RestartsUnderSaRestart
            | SimulatedUnixFlavour.Darwin -> SignalRestartRule.FailsWithEintr
        // Measured on Linux 6.18.5 and Darwin 27.0.0
        // (`docs/probes/select-park`, row A3): a `select` a caught signal
        // interrupts answers EINTR under SA_RESTART too.
        | ParkedSyscall.Select _ -> SignalRestartRule.FailsWithEintr
        // Measured on Linux 6.18.5 (`docs/probes/sigwait`, the "outside" rows):
        // `rt_sigtimedwait` a handler's signal outside its set interrupts
        // answers EINTR under SA_RESTART too. On Darwin 27.0.0 such a signal
        // does not end `__sigwait` at all: the call sleeps on, and the handler
        // runs once it returns. So no rule applies there, and this answers
        // Linux's.
        | ParkedSyscall.SignalWait _ -> SignalRestartRule.FailsWithEintr
        // Measured on Linux 6.18.5 and Darwin 27.0.0
        // (`docs/probes/datagram-park`, rows R2 and S4): a receive on a UDP or
        // Unix-domain datagram socket returned EINTR without SA_RESTART and
        // went on sleeping with it, and so did a Linux Unix-domain datagram
        // send. A Darwin one never sleeps.
        | ParkedSyscall.DatagramReceive _
        | ParkedSyscall.DatagramSend _ -> SignalRestartRule.RestartsUnderSaRestart
        // Measured on Linux 6.18.5 (`docs/probes/connect-park`, rows T3 and
        // U3): a TCP or Unix-domain connect asleep on a full listener returned
        // EINTR without SA_RESTART and went on sleeping with it. A Darwin
        // connect never sleeps.
        | ParkedSyscall.Connect _ -> SignalRestartRule.RestartsUnderSaRestart
        // Measured on Linux 6.18.5 (`docs/probes/futex` and
        // `docs/probes/futex-bitset`, the "signal" rows): a wait with no
        // timeout returned EINTR without SA_RESTART and went on sleeping with
        // it; one with a timeout, relative or absolute on either clock,
        // returned EINTR either way.
        | ParkedSyscall.Futex wait ->
            match wait.FutexTimeout with
            | FutexTimeout.Untimed -> SignalRestartRule.RestartsUnderSaRestart
            | FutexTimeout.Until _
            | FutexTimeout.At _
            | FutexTimeout.Unbounded -> SignalRestartRule.FailsWithEintr

    /// What a thread in `sigsuspend` does now, its temporary mask in force.
    [<RequireQualifiedAccess>]
    type internal Suspension<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
        /// The call ends: the thread's return to user mode would make
        /// `delivery`, running a handler or applying a default that terminates
        /// the process. The signals are as the call leaves them, for that
        /// return to take from.
        | Ends of delivery : SignalDelivery<'Thread, 'Handler> * signals : SignalState<'Thread, 'Handler>
        /// The call sleeps on, with these signals.
        | Sleeps of SignalState<'Thread, 'Handler>

    /// What the `sigsuspend` `thread` is in does, with `signals` holding its
    /// temporary mask and the mask to restore: what the thread would take as it
    /// returned to user mode decides it.
    let internal suspension<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        (signals : SignalState<'Thread, 'Handler>)
        : Result<Suspension<'Thread, 'Handler>, SigsuspendRefusal>
        =
        let threads = UnixThreadTable.byName system.Threads |> Map.keys |> Set.ofSeq
        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        let rec decide
            (signals : SignalState<'Thread, 'Handler>)
            : Result<Suspension<'Thread, 'Handler>, SigsuspendRefusal>
            =
            match
                SignalState.takeOnReturn
                    (UnixSystemState.signalNumbering system)
                    system.Process.CoreDumps
                    system.Leader
                    threads
                    thread
                    signals
            with
            | Error refusal -> Error (SigsuspendRefusal.Receiver refusal)
            // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/sigsuspend-mask.c`
            // on Linux 6.18.5 and Darwin 27.0.0: a caught signal ended the call
            // with EINTR once its handler had run, whether it was pending as the
            // call was made or sent during it, SA_RESTART or not; and a TERM at
            // its default killed the process, sent during the call or pending
            // before it and unblocked by the temporary mask.
            | Ok (Some (SignalDelivery.RunHandlers _ as delivery), _)
            | Ok (Some (SignalDelivery.DefaultTerminate _ as delivery), _) -> Ok (Suspension.Ends (delivery, signals))
            // Measured: stopped and continued with no handler run, the call slept
            // on, on both flavours.
            | Ok (Some (SignalDelivery.DefaultStop signal), _) -> Error (SigsuspendRefusal.DefaultStop signal)
            | Ok (Some (SignalDelivery.DefaultContinue _), taken) ->
                match flavour with
                // Measured: a SIGCONT at its default, blocked and pending, which
                // the temporary mask unblocked, ended nothing, and was never
                // delivered to a handler installed afterwards: Linux takes and
                // discards it, then restarts the call (`-ERESTARTNOHAND` with no
                // handler run).
                | SimulatedUnixFlavour.Linux -> decide taken
                | SimulatedUnixFlavour.Darwin -> Error SigsuspendRefusal.DarwinPendingContinue
            | Ok (None, walked) ->
                match flavour with
                // Measured: an ignored signal, blocked and pending, which the
                // temporary mask unblocked, ended nothing, and was never delivered
                // to a handler installed afterwards. The return to user mode
                // discards it, as Linux's does, and the call restarts.
                | SimulatedUnixFlavour.Linux -> Ok (Suspension.Sleeps walked)
                // Darwin discards an ignored signal at generation, SIGCONT apart,
                // so a walk that discards something has found a SIGCONT, which
                // Darwin was measured to leave pending.
                | SimulatedUnixFlavour.Darwin ->
                    if walked = signals then
                        Ok (Suspension.Sleeps signals)
                    else
                        Error SigsuspendRefusal.DarwinPendingContinue

        decide signals

    /// The handler frames `thread` would get, innermost first, were it to return
    /// to user mode now: empty when it would run no handler.
    let private framesOnReturn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<HandlerFrame<'Thread, 'Handler> list, SyscallInterruptionRefusal>
        =
        let threads = UnixThreadTable.byName system.Threads |> Map.keys |> Set.ofSeq

        // Only asked: the walk's own state (the frames pushed, the ignored
        // signals discarded) is dropped. The thread returns to user mode for real
        // once its syscall has answered.
        match
            SignalState.onReturnToUser
                (UnixSystemState.signalNumbering system)
                system.Process.CoreDumps
                system.Leader
                threads
                thread
                system.Process.Signals
        with
        | Error refusal -> Error (SyscallInterruptionRefusal.Receiver refusal)
        | Ok (None, _) -> Ok []
        | Ok (Some (SignalDelivery.RunHandlers frames), _) -> Ok frames
        | Ok (Some (SignalDelivery.DefaultTerminate (signal, _)), _)
        | Ok (Some (SignalDelivery.DefaultStop signal), _)
        | Ok (Some (SignalDelivery.DefaultContinue signal), _) ->
            Error (SyscallInterruptionRefusal.DefaultAction signal)

    /// Whether `thread`, asleep in a syscall, is woken by a signal now: it would
    /// run a handler as it returned to user mode, or this library refuses to say
    /// what it would do, which the syscall's finishing call then reports. A thread
    /// in `sigsuspend` is woken also when what it could take would change the
    /// signal state, which its finishing call commits before it sleeps again.
    let internal wakes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        // Nothing pending is no handler to run, and every sleeping thread is
        // asked this on every poll of its wake condition, so it answers without
        // walking the signal state.
        if List.isEmpty (SignalState.pending system.Process.Signals) then
            false
        else

        match UnixThreadTable.parkedFor thread system.Threads with
        // A sigsuspend decides for itself what a signal it could take does to
        // it: a woken one finishes, parks again having discarded what Linux
        // discards, or refuses what this library cannot say. Only a call that
        // would sleep on unchanged stays asleep, so that every refusal
        // `UnixSignal.finishSigsuspend` makes is reached.
        | Some ParkedSyscall.SigSuspend ->
            match suspension thread system system.Process.Signals with
            | Ok (Suspension.Sleeps signals) -> signals <> system.Process.Signals
            | Ok (Suspension.Ends _)
            | Error _ -> true
        | Some _
        | None ->

        match framesOnReturn thread system with
        | Ok [] -> false
        | Ok (_ :: _)
        | Error _ -> true

    /// Whether a signal ends the sleep of `thread` now, whatever the handlers'
    /// flags: whether the thread would take one as it returned to user mode,
    /// running its handler or applying its default. For a syscall that,
    /// interrupted, returns what it has done so far rather than failing or
    /// restarting, as a write that has put bytes into a pipe does. `Error`
    /// where this library will not say what the thread takes as it returns.
    let internal interrupts<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<bool, SyscallInterruptionRefusal>
        =
        // A default that terminates the process ends the sleep as a handler
        // does (`docs/probes/disposition-before-return`, the `dfl` rows): the
        // call answers, and the return then ends the process.
        match
            SignalState.takeOnReturn
                (UnixSystemState.signalNumbering system)
                system.Process.CoreDumps
                system.Leader
                (UnixThreadTable.byName system.Threads |> Map.keys |> Set.ofSeq)
                thread
                system.Process.Signals
        with
        | Error refusal -> Error (SyscallInterruptionRefusal.Receiver refusal)
        | Ok (delivery, _) -> Ok delivery.IsSome

    /// How the syscall `parked` records ends under `flavour` if a signal
    /// interrupted it and, by the time its thread returns to user mode, no
    /// handler runs: the signal has been discarded, or the thread blocks it.
    /// `ofPark` asks it too, of a call a signal woke whose signal has gone by
    /// the time the call is finished.
    let internal withoutHandler (flavour : SimulatedUnixFlavour) (parked : ParkedSyscall) : UnhandledInterruption =
        // Measured on Linux 6.18.5 and Darwin 27.0.0
        // (`docs/probes/disposition-before-return`, the held `ign` rows): the
        // sleeping thread signalled with a caught signal that another thread
        // then ignored before the sleeper ran. No handler ran; Linux's
        // epoll_wait and Darwin's poll and kevent answered EINTR, and every
        // other call went on sleeping, which is what restarting it does. Each
        // call was measured without a timeout: a Linux `poll` with one restarts
        // with what is left of it (`restart_syscall`), which the call as first
        // made does not, and the others' timeouts are unmeasured.
        let measuredWithoutTimeout (deadline : int64 option) (outcome : InterruptedCall) : UnhandledInterruption =
            match deadline with
            | None -> UnhandledInterruption.Ends outcome
            | Some _ -> UnhandledInterruption.Unmeasured

        match flavour, parked with
        | _, ParkedSyscall.SigSuspend
        | _, ParkedSyscall.Flock _
        | _, ParkedSyscall.Accept _
        | _, ParkedSyscall.PipeRead _
        | _, ParkedSyscall.PipeWrite _
        | _, ParkedSyscall.ConnectionRead _
        | _, ParkedSyscall.ConnectionWrite _ -> UnhandledInterruption.Ends InterruptedCall.Restarts
        | SimulatedUnixFlavour.Linux, ParkedSyscall.InotifyRead _ -> UnhandledInterruption.Ends InterruptedCall.Restarts
        | SimulatedUnixFlavour.Linux, ParkedSyscall.Poll poll ->
            match poll.Deadline with
            | None -> UnhandledInterruption.Ends InterruptedCall.Restarts
            | Some _ -> UnhandledInterruption.RestartsWithRemainingTime
        | SimulatedUnixFlavour.Linux, ParkedSyscall.EpollWait wait ->
            measuredWithoutTimeout wait.Deadline InterruptedCall.FailsWithEintr
        | SimulatedUnixFlavour.Darwin, ParkedSyscall.KqueuePoll poll ->
            measuredWithoutTimeout poll.Deadline InterruptedCall.FailsWithEintr
        | SimulatedUnixFlavour.Darwin, ParkedSyscall.Kevent wait ->
            measuredWithoutTimeout wait.Deadline InterruptedCall.FailsWithEintr
        // Measured on Linux 6.18.5 (`docs/probes/futex` and
        // `docs/probes/futex-bitset`, the "stop" rows): a wait stopped and
        // continued, no handler run, went on sleeping, and one with a timeout
        // still timed out at its first deadline. A saturated timeout's first
        // deadline never comes, and the call made again with the same
        // arguments saturates too (a later "now" only overflows further), and
        // an absolute deadline is the instant the call made again names, so
        // each restarts as the call made again.
        | SimulatedUnixFlavour.Linux, ParkedSyscall.Futex wait ->
            match wait.FutexTimeout with
            | FutexTimeout.Untimed
            | FutexTimeout.At _
            | FutexTimeout.Unbounded -> UnhandledInterruption.Ends InterruptedCall.Restarts
            | FutexTimeout.Until _ -> UnhandledInterruption.RestartsWithRemainingTime
        // A park the flavour never makes, and the reserved parks.
        | SimulatedUnixFlavour.Darwin, ParkedSyscall.InotifyRead _
        | SimulatedUnixFlavour.Darwin, ParkedSyscall.Poll _
        | SimulatedUnixFlavour.Darwin, ParkedSyscall.EpollWait _
        | SimulatedUnixFlavour.Linux, ParkedSyscall.KqueuePoll _
        | SimulatedUnixFlavour.Linux, ParkedSyscall.Kevent _
        | _, ParkedSyscall.Sleep _
        | _, ParkedSyscall.FifoOpen _
        | _, ParkedSyscall.Select _
        | _, ParkedSyscall.SignalWait _
        | _, ParkedSyscall.DatagramReceive _
        | _, ParkedSyscall.DatagramSend _
        | _, ParkedSyscall.Connect _
        | SimulatedUnixFlavour.Darwin, ParkedSyscall.Futex _ -> UnhandledInterruption.Unmeasured

    /// Whether the syscall `parked` records, restarted, reads the caller's
    /// memory again, so that only the caller can restart it: a restart this
    /// kernel makes by putting the thread back to sleep would answer from
    /// what the memory held when the call was first made.
    ///
    /// A futex wait reads the word at its address again (measured on Linux
    /// 6.18.5, `docs/probes/futex`: a word changed while the wait slept made
    /// its restart answer `EAGAIN`, after a handler under `SA_RESTART` and
    /// after a stop alike).
    let private restartRereadsCallerMemory (parked : ParkedSyscall) : bool =
        match parked with
        | ParkedSyscall.Futex _ -> true
        | ParkedSyscall.EpollWait _
        | ParkedSyscall.Kevent _
        | ParkedSyscall.Flock _
        | ParkedSyscall.Poll _
        | ParkedSyscall.KqueuePoll _
        | ParkedSyscall.Accept _
        | ParkedSyscall.PipeRead _
        | ParkedSyscall.PipeWrite _
        | ParkedSyscall.ConnectionRead _
        | ParkedSyscall.ConnectionWrite _
        | ParkedSyscall.SigSuspend
        | ParkedSyscall.Sleep _
        | ParkedSyscall.FifoOpen _
        | ParkedSyscall.InotifyRead _
        | ParkedSyscall.Select _
        | ParkedSyscall.SignalWait _
        | ParkedSyscall.DatagramReceive _
        | ParkedSyscall.DatagramSend _
        | ParkedSyscall.Connect _ -> false

    /// How the handlers of `frames`, innermost first, end a syscall whose rule
    /// is `rule`: `Error` of the signals whose handlers were installed with
    /// `SA_RESTART` and of those whose were not, where they disagree about a
    /// syscall that `SA_RESTART` restarts.
    let internal byHandlers<'Thread, 'Handler>
        (rule : SignalRestartRule)
        (frames : HandlerFrame<'Thread, 'Handler> list)
        : Result<InterruptedCall, Signal list * Signal list>
        =
        match rule with
        | SignalRestartRule.FailsWithEintr -> Ok InterruptedCall.FailsWithEintr
        | SignalRestartRule.RestartsUnderSaRestart ->
            // Every frame is pushed before any handler runs, and a kernel decides
            // the syscall's fate as it pushes the first. While the handlers agree
            // the order cannot matter, and which one decides when they disagree
            // is unmeasured.
            let restarting, failing =
                frames |> List.partition (fun frame -> frame.Action.Restart)

            match restarting, failing with
            | _, [] -> Ok InterruptedCall.Restarts
            | [], _ -> Ok InterruptedCall.FailsWithEintr
            | _, _ ->
                Error (
                    restarting |> List.map (fun frame -> frame.Entry.Signal),
                    failing |> List.map (fun frame -> frame.Entry.Signal)
                )

    /// The interruption of the syscall `parked` records under `flavour`, by a
    /// signal the thread's return to user mode would take as `delivery`.
    let internal interruptionOf<'Thread, 'Handler>
        (flavour : SimulatedUnixFlavour)
        (parked : ParkedSyscall)
        (delivery : SignalDelivery<'Thread, 'Handler>)
        : Interruption
        =
        let rule = ruleOf flavour parked

        let signal, atInterruption =
            match delivery with
            | SignalDelivery.RunHandlers frames ->
                // Innermost first: the first signal taken is the outermost frame's.
                (List.last frames).Entry.Signal, Result.toOption (byHandlers rule frames)
            | SignalDelivery.DefaultTerminate (signal, _)
            | SignalDelivery.DefaultStop signal
            | SignalDelivery.DefaultContinue signal -> signal, None

        {
            Signal = Some signal
            Rule = rule
            Unhandled = withoutHandler flavour parked
            AtInterruption = atInterruption
        }

    /// What a woken syscall that has its own answer to give does with it.
    [<RequireQualifiedAccess>]
    type internal Completion =
        /// It gives the answer; any signal deliverable to the thread is taken
        /// as the thread returns to user mode.
        | Completes
        /// A signal interrupts it instead.
        | Interrupted of Interruption

    /// Whether the syscall `thread` is asleep in gives its own answer, now that
    /// it has one, or a signal interrupts it: a finishing call asks this before
    /// it answers, and refuses what this refuses.
    ///
    /// Under Linux it gives the answer, whatever signal is pending: the handlers
    /// run as the thread returns. Under Darwin a signal with a handler
    /// deliverable to the thread interrupts it.
    let internal beforeCompleting<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<Completion, SyscallInterruptionRefusal>
        =
        // Measured (`signal-interrupt-requeue.c`, section D): with the sleeper
        // held off the CPU until both held, Linux 6.18.5 answered with the
        // readiness every time, for epoll_wait, poll, accept and flock,
        // whichever came first.
        //
        // Measured on Darwin 27.0.0 and Linux 6.18.5 (`docs/probes/first-wake`):
        // with the sleeper held off the CPU from its wake until both held, a
        // Darwin accept, flock, pipe read or write, or socket read or write
        // answered EINTR in both orders of its own wake and the signal, and
        // of the far end's close and the signal (Linux answering the wake, as
        // here, but for a socket write; see `UnixReadWrite.finishWrite`).
        // XNU's `_sleep` looks for a signal after any wake of a sleep that
        // signals may end. `signal-interrupt-requeue.c` section F, and
        // `pipe-blocking.c` section J, saw the order decide on Darwin with the
        // process stopped; by XNU's source a stop takes effect only as a
        // thread returns to user mode, so a sleeper the first wake woke ran
        // its call to the end before the second came, and those rows agree
        // with these.
        //
        // Darwin's `poll` and `kevent`, which answer what woke them, and its
        // pipe write whose reader has gone, whose close waits for the writer
        // to leave its call, decide for themselves.
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux -> Ok Completion.Completes
        | SimulatedUnixFlavour.Darwin ->
            match framesOnReturn thread system with
            | Ok [] -> Ok Completion.Completes
            | Ok frames ->
                match UnixThreadTable.parkOf thread system.Threads with
                | Some park ->
                    Ok (
                        Completion.Interrupted (
                            interruptionOf SimulatedUnixFlavour.Darwin park.Syscall (SignalDelivery.RunHandlers frames)
                        )
                    )
                | None ->
                    failwith
                        $"SyscallInterruption.beforeCompleting: thread %O{thread} is not asleep in a syscall, so it has no answer of one to give (this is a bug in the caller)."
            | Error refusal -> Error refusal

    /// What `UnixWait.wake` found holding of the wake condition of the call
    /// `thread` is asleep in as it woke the thread (`ParkState.Woken`).
    ///
    /// Fails loudly if `thread` is not parked in a syscall, and woken.
    let internal wokenBy<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Set<WakePrimitive>
        =
        match UnixThreadTable.parkOf thread system.Threads with
        | Some {
                   State = ParkState.Woken fired
               } -> fired
        | other ->
            failwith
                $"SyscallInterruption.wokenBy: thread %O{thread} is parked as %A{other}, and only a woken thread's call is finished (this is a bug in the caller)."

    /// How a signal interrupts the syscall `thread` is asleep in, if one does
    /// now: `None` when none does, and the finishing call goes on as if no
    /// signal had come. The thread's return to user mode decides how an
    /// interrupted syscall ends, from the signals as they are at that return.
    ///
    /// A signal interrupts the syscall when the thread would take one as it
    /// returned to user mode now. When it would take none, but a signal woke
    /// it (`ParkState.Woken` for `WakePrimitive.SignalDeliverable`), the
    /// syscall ends as `withoutHandler` says a return that runs no handler
    /// ends it: interrupted where that fails it with `EINTR`; not, so that it
    /// sleeps on, where that restarts it; and refused where that is
    /// unmeasured.
    ///
    /// A finishing call asks this only once it has found that the syscall has
    /// nothing else to answer: a wait whose own condition holds answers that,
    /// and the handlers run as it returns.
    ///
    /// Fails loudly if `thread` is not parked in a syscall, and woken.
    let internal ofPark<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<Interruption option, SyscallInterruptionRefusal>
        =
        let park =
            match UnixThreadTable.parkOf thread system.Threads with
            | Some park -> park
            | None ->
                failwith
                    $"SyscallInterruption.ofPark: thread %O{thread} is not asleep in a syscall, so no signal can interrupt one (this is a bug in the caller)."

        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform
        let threads = UnixThreadTable.byName system.Threads |> Map.keys |> Set.ofSeq

        // Only asked: the walk's own state is dropped. The thread returns to
        // user mode for real once its syscall has answered.
        match
            SignalState.takeOnReturn
                (UnixSystemState.signalNumbering system)
                system.Process.CoreDumps
                system.Leader
                threads
                thread
                system.Process.Signals
        with
        | Error refusal -> Error (SyscallInterruptionRefusal.Receiver refusal)
        | Ok (Some delivery, _) -> Ok (Some (interruptionOf flavour park.Syscall delivery))
        | Ok (None, _) ->

        match park.State with
        | ParkState.Woken fired when Set.contains WakePrimitive.SignalDeliverable fired ->
            // Measured on Linux 6.18.5 and Darwin 27.0.0
            // (`docs/probes/disposition-before-return`, the held `ign` rows): a
            // caught signal woke the sleeper, and another thread ignored it
            // before the sleeper ran. No handler ran. Linux's epoll_wait
            // (`linux call=epoll`) and Darwin's poll and kevent (`darwin
            // call=poll`, `darwin call=kevent`) failed with EINTR, and every
            // other call went on sleeping, under SA_RESTART and without.
            //
            // The probe made the change before the woken sleeper ran at all, so
            // both before its call was finished and before it returned to user
            // mode. So one measurement covers a change made before the finish,
            // decided here, and one made between the finish and the return,
            // which `withoutHandler` decides at the return; both follow its
            // table. The rows say which calls fail rather than sleep on, and
            // not why, and nothing here supposes a reason.
            //
            // Sleeping on is the restart those rows saw, made without a return
            // to user mode: the park keeps the call's arguments and its
            // deadline, as Linux's restart of a `poll` with a timeout keeps
            // what is left of it (`RestartsWithRemainingTime`). Where the end
            // is unmeasured (a wait with a timeout), so is whether the call
            // sleeps on.
            //
            // A call whose restart reads the caller's memory again cannot sleep
            // on here, since only the caller can read it: it is interrupted
            // instead, and restarts as its thread returns to user mode, where
            // the caller makes it again. Where that restart would keep a
            // deadline the caller's call cannot, it is refused.
            let interrupted (ending : InterruptedCall) : Interruption option =
                Some
                    {
                        Signal = None
                        Rule = ruleOf flavour park.Syscall
                        Unhandled = UnhandledInterruption.Ends ending
                        AtInterruption = Some ending
                    }

            match withoutHandler flavour park.Syscall with
            | UnhandledInterruption.Ends InterruptedCall.FailsWithEintr ->
                Ok (interrupted InterruptedCall.FailsWithEintr)
            | UnhandledInterruption.Ends InterruptedCall.Restarts when restartRereadsCallerMemory park.Syscall ->
                Ok (interrupted InterruptedCall.Restarts)
            | UnhandledInterruption.RestartsWithRemainingTime when restartRereadsCallerMemory park.Syscall ->
                Error SyscallInterruptionRefusal.FutexRestartKeepsDeadline
            | UnhandledInterruption.Ends InterruptedCall.Restarts
            | UnhandledInterruption.RestartsWithRemainingTime -> Ok None
            | UnhandledInterruption.Unmeasured -> Error SyscallInterruptionRefusal.WakingSignalGone
        // Whatever woke the thread was its call's own condition, which the
        // finishing call has found gone again.
        | ParkState.Woken _ -> Ok None
        | ParkState.Asleep ->
            failwith
                $"SyscallInterruption.ofPark: thread %O{thread} is asleep in %A{park.Syscall}, and only a woken thread's call is finished (this is a bug in the caller)."
