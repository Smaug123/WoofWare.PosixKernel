namespace WoofWare.PosixKernel

/// A handler as `sigaction(2)` installs it: the handler itself, and the mask
/// and flags that say what happens around it.
type SignalCatch<'Handler> =
    {
        /// What runs. What it is belongs to the client; this library stores it
        /// and hands it back in the handler frame of each delivery.
        Handler : 'Handler
        /// `sa_mask`: the signals blocked while the handler runs, on top of the
        /// mask in force when it was delivered. The kernel drops SIGKILL and
        /// SIGSTOP from it, so `SignalState` never stores either, and keeps
        /// every other bit, one that names no signal included (Darwin's bit 31;
        /// see `SignalMask`).
        Mask : SignalMask
        /// `SA_NODEFER`: the signal itself is not blocked while its handler
        /// runs, so a second instance can interrupt it.
        NoDefer : bool
        /// `SA_RESETHAND`: delivering the signal resets its disposition to the
        /// default, except where the flavour keeps the handler (Darwin's
        /// SIGILL and SIGTRAP). It does not imply `SA_NODEFER`.
        ResetHand : bool
        /// `SA_RESTART`: a system call the handler interrupts is restarted
        /// rather than failing with `EINTR`, where the call is one that can be.
        Restart : bool
    }

[<RequireQualifiedAccess>]
module SignalCatch =
    /// `handler` with an empty `sa_mask` and no flags.
    let ofHandler<'Handler> (handler : 'Handler) : SignalCatch<'Handler> =
        {
            Handler = handler
            Mask = SignalMask.empty
            NoDefer = false
            ResetHand = false
            Restart = false
        }

/// What a process does with a signal delivered to it: what `sigaction(2)`
/// sets.
[<RequireQualifiedAccess>]
type SignalDisposition<'Handler> =
    /// `SIG_DFL`: the signal's kernel default, `Signal.defaultDispositionUnder`.
    | Default
    /// `SIG_IGN`: the signal is discarded.
    | Ignore
    /// A handler is installed, with its mask and flags.
    | Catch of SignalCatch<'Handler>

/// Whether a process that a signal kills writes a core dump, when the
/// signal's default action dumps core (`Signal.dumpsCoreUnder`). A parent's
/// `wait(2)` reports the outcome as the status's core flag (`WCOREDUMP`).
///
/// On a real system this is the net effect of the process's `RLIMIT_CORE`,
/// the machine's core-file settings and whether a dump could be written where
/// they say, so it is configuration rather than a fact about the kernel.
///
/// Linux also writes no dump for a process whose dumpable flag is clear, which
/// a change of its effective IDs can set or clear. This library starts every
/// process dumpable, since it models no `exec(2)` of a set-ID program, and
/// `CoreDumps` is not that flag: see `Suppressed`.
[<RequireQualifiedAccess>]
type CoreDumps =
    /// No dump is written, as under an `RLIMIT_CORE` of 0: for a reason that a
    /// change of the process's IDs leaves in place, so `UnixCredentials`'
    /// calls keep a process at `Suppressed`.
    | Suppressed
    /// Every death by a signal whose default action dumps core writes one.
    | Written

/// A pending signal, and the set it is pending in. `Target = ValueNone` is the
/// process's own set, which `kill(2)` adds to; `ValueSome thread` is `thread`'s
/// own set, which `pthread_kill(3)` adds to, and which only `thread` can take a
/// signal from.
type PendingSignal<'Thread> =
    {
        Signal : Signal
        Target : 'Thread voption
    }

/// Which handler frame a delivery pushed: the name `UnixSignal.sigreturn`
/// takes it back by. Unique within one `SignalState`, and never reused.
[<Struct>]
type HandlerFrameId = | HandlerFrameId of int64

/// One handler the kernel has set up to run on a thread: the frame it pushes on
/// the thread's stack when it delivers a caught signal, which the handler's
/// return (`sigreturn(2)`) pops.
type HandlerFrame<'Thread, 'Handler> =
    {
        Id : HandlerFrameId
        /// The signal delivered, and the pending set it was taken from.
        Entry : PendingSignal<'Thread>
        /// The disposition the signal was delivered under.
        Action : SignalCatch<'Handler>
        /// The thread's signal mask when the signal was delivered, which
        /// `sigreturn` restores exactly, whatever the handler did to the mask
        /// while it ran. Delivery sets the thread's mask to this, `Action.Mask`,
        /// and the signal itself unless `Action.NoDefer`; the mask a handler
        /// starts under is the thread's mask (`SignalState.maskOf`) when it
        /// begins to run.
        SavedMask : SignalMask
    }

/// What the kernel does with the signals a thread takes as it returns to user
/// mode: run handlers, or apply a signal's kernel default.
/// `UnixSignal.onReturnToUser` answers it as the `ReturnToUserOutcome` of the
/// same case, whose docstrings state what each means for a client, or, for a
/// default that terminates the process, applies it and answers the ended
/// process.
[<RequireQualifiedAccess>]
type internal SignalDelivery<'Thread, 'Handler> =
    /// `ReturnToUserOutcome.RunHandlers`. Never empty.
    | RunHandlers of frames : HandlerFrame<'Thread, 'Handler> list
    /// `ProcessFate.ProcessEnded` of `UnixSignal.onReturnToUser`, before the
    /// process is ended.
    | DefaultTerminate of signal : Signal * coreDumped : bool
    /// `ReturnToUserOutcome.ProcessStopped`.
    | DefaultStop of Signal
    /// `ReturnToUserOutcome.ContinueDiscarded`.
    | DefaultContinue of Signal

/// How `sigprocmask(2)` changes a mask, which its `how` argument names.
[<RequireQualifiedAccess>]
type internal SignalMaskChange =
    /// `SIG_BLOCK`: add the set to the mask.
    | Block
    /// `SIG_UNBLOCK`: take the set out of the mask.
    | Unblock
    /// `SIG_SETMASK`: the mask becomes the set.
    | SetMask

/// What a pending instance of a signal holds against Linux's
/// `RLIMIT_SIGPENDING`, the bound on the signals queued for one user.
[<RequireQualifiedAccess>]
type internal PendingCharge =
    /// No bound applies to it: an instance under Darwin, which has no such
    /// bound, or one `SignalState.enqueue` placed.
    | Unbounded
    /// Linux allocated it a queue entry, which counts against `user`: the
    /// receiving process's real user when the signal was sent.
    | Charged of user : UserId
    /// Linux could allocate it no queue entry, so it is the pending bit alone:
    /// it counts against no user, and an allocated instance of its signal
    /// arriving in its set replaces it rather than queueing behind it.
    | Bare

/// A pending instance of a signal, and what it holds against
/// `RLIMIT_SIGPENDING`.
type internal QueuedSignal<'Thread> =
    {
        Entry : PendingSignal<'Thread>
        Charge : PendingCharge
    }

/// How a signal was sent, which decides whether Linux queues it past
/// `RLIMIT_SIGPENDING`.
[<RequireQualifiedAccess>]
type internal SignalSender =
    /// `kill(2)`: a standard signal is queued past the limit, and a real-time
    /// one past it is lost, or kept as the bare bit.
    | Kill
    /// `tgkill(2)`, as `pthread_kill(3)` makes it: a standard signal past the
    /// limit is kept as the bare bit, and a real-time one fails with `EAGAIN`.
    | ThreadKill
    /// The kernel itself, as for a write's `SIGPIPE`: queued past the limit.
    | Kernel

/// What generating a signal counts against, as `SignalState.generate` is told.
[<RequireQualifiedAccess>]
type internal QueueAccount =
    /// No bound applies: Darwin.
    | Unbounded
    /// Linux: the receiving process's real `user`, how many signals are queued
    /// for that user in every other process on the machine, the receiving
    /// process's `RLIMIT_SIGPENDING`, and how the signal was sent.
    | Limited of user : UserId * queuedElsewhere : int * limit : uint64 * sender : SignalSender

/// Pure, deterministic model of the simulator's signal-handling state.
///
/// The shape is deliberately small:
///   * `Dispositions` — what `sigaction(2)` has set for each signal: its
///     default, ignored, or caught by a client's handler. A signal absent
///     from the map has its default.
///   * `Blocked` — each thread's signal mask, which `sigprocmask(2)` and
///     delivery set and `sigreturn(2)` restores. A thread absent from the map
///     blocks nothing.
///   * `Frames` — each thread's stack of handler frames, each holding the mask
///     its `sigreturn` restores.
///   * `MasksToRestore` — for each thread in `sigsuspend(2)`, the mask it had
///     before the call replaced it, which it gets back as the call returns.
///   * `Pending` — the signals generated and not yet delivered: the process's
///     own set, and each thread's.
///
/// One instance of this type belongs to each simulated process. A client reads
/// it out of a system (`UnixSystem.signals`), and changes it only through the
/// signal calls (`UnixSignal`) and a thread's leaving (`UnixThreadLifecycle`);
/// the data shape is exercised by property tests against a
/// structurally-different reference oracle.
///
/// The state's signals are read under its machine's numbering
/// (`SimulatedUnixPlatform.signalNumbering`), which the state does not hold:
/// every operation that reads a signal is handed it as `numbering`. Every
/// `Signal` stored here is one that numbering has, and every operation
/// checks the signal it is handed before touching the state. The operations
/// are the only route in (the representation is private), so the tables and
/// queue never hold SIGKILL or SIGSTOP in a mask, a disposition for SIGKILL
/// or SIGSTOP, a stored `Default`, or a signal the numbering does not have.
type SignalState<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            /// Never holds `SignalDisposition.Default`: an absent key is the
            /// default, and a stored one would make two states that behave
            /// identically compare unequal.
            Dispositions : Map<Signal, SignalDisposition<'Handler>>
            /// Each thread's signal mask. Never holds an empty mask, for the
            /// same reason `Dispositions` holds no default; and never SIGKILL
            /// or SIGSTOP, which a kernel drops from every mask it stores.
            Blocked : Map<'Thread, SignalMask>
            /// For each thread in `sigsuspend(2)` or `pause(2)`, from the call
            /// until the thread next returns to user mode: the mask the call
            /// replaced with its temporary one. Linux's `saved_sigmask`, Darwin's
            /// `uu_oldmask`. An absent thread is in neither call; a present one may
            /// hold an empty mask, which it is restored to.
            MasksToRestore : Map<'Thread, SignalMask>
            /// Each thread's handler frames, innermost first. Never holds an
            /// empty stack, for the same reason `Dispositions` holds no
            /// default.
            Frames : Map<'Thread, HandlerFrame<'Thread, 'Handler> list>
            /// The id the next frame pushed gets.
            NextFrame : int64
            /// Every pending entry, sorted by its set and then by `pickRank`,
            /// which is the order a thread takes the signals of one set in; the
            /// instances of one real-time signal, the only entries that can tie,
            /// stay in the order they were generated. Kept sorted rather than in
            /// generation order because no kernel delivers in generation order,
            /// so two states holding the same signals would otherwise compare
            /// unequal while behaving identically. Pending sets are tiny in
            /// practice, so a sorted list does. Each instance carries what it
            /// holds against `RLIMIT_SIGPENDING`; under Linux a `Bare`
            /// real-time instance is the only instance of its signal in its
            /// set.
            Pending : QueuedSignal<'Thread> list
        }

/// What generating a signal does to the process at once, as decided by
/// `SignalState.generate`. Anything else it does happens later, through the
/// pending sets and `SignalState.onReturnToUser`.
[<RequireQualifiedAccess>]
type internal SignalGeneration<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// The process carries on, with these signals. The signal is pending, or
    /// coalesced into an instance already pending, or discarded because it is
    /// ignored.
    | ProcessContinues of SignalState<'Thread, 'Handler>
    /// The signal terminates the process: its disposition is the default,
    /// which is to terminate, and some thread could receive it. A
    /// parent's `wait` reports the core flag iff `coreDumped`. There is no
    /// state to carry on with, because the process has ended.
    | ProcessTerminated of signal : Signal * coreDumped : bool
    /// The signal stops the whole process, which has these signals: its
    /// disposition is the default, which is to stop, and some thread could
    /// receive it.
    | ProcessStopped of signal : Signal * SignalState<'Thread, 'Handler>
    /// Nothing happened: the signal is a real-time one sent by `tgkill(2)`,
    /// and the receiving user's queue is at its `RLIMIT_SIGPENDING`, so the
    /// call fails with `EAGAIN`.
    | QueueFull

/// Why this library will not say what a process's signal does: a case it does
/// not model, rather than one a kernel refuses.
[<RequireQualifiedAccess>]
type internal SignalReceiverRefusal =
    /// `signal` is sent to the process as a whole, and its leader blocks it
    /// while another thread does not, so some thread other than the leader would
    /// take it: a caught one to run its handler, and under Linux's numbering an
    /// ignored one (SIGCONT at its default included) to discard it, which
    /// Linux leaves pending on the process until then. Which thread differs
    /// between flavours, and on Linux depends on which threads took earlier
    /// signals; this library delivers a process's own signals to its leader
    /// only.
    | LeaderBlocks of signal : Signal
    /// Returning to user mode, a thread would take `signal`, whose default stops
    /// or continues the process, after handler frames were pushed for other
    /// signals at the same return. What a stopped process does with frames
    /// already pushed has not been measured.
    | DefaultBehindHandlers of signal : Signal
    /// Under Darwin's numbering, `signal`, a standard signal, would be left
    /// pending on the process as a whole while an instance of it is pending on
    /// the leader alone, or the other way round. Darwin holds the two as one
    /// instance: it puts a signal sent to the process in the pending set of
    /// the thread it chooses to take it, which is the leader whenever this
    /// library answers. This library keeps the process's set apart from each
    /// thread's.
    | PendingForProcessAndLeader of signal : Signal
    /// Under Linux's numbering, `signal`, caught, is sent to the process as a
    /// whole while its leader, which does not block it, is not running and
    /// already has a signal to take, and another thread does not block it.
    /// Linux then wakes that other thread, and whichever of the two returns to
    /// user mode first takes the process's signals, lowest first: the other
    /// thread may run every handler and the leader's call restart, or each may
    /// take some. Which returns first is scheduling, and this library delivers
    /// a process's own signals to its leader only.
    | LeaderAlreadySignalled of signal : Signal

[<RequireQualifiedAccess>]
module internal SignalReceiverRefusal =
    /// What this kernel knows about why it cannot say what the signal does.
    /// The client supplies its own half: which call or return reached it, and
    /// in which thread.
    let describe (refusal : SignalReceiverRefusal) : string =
        match refusal with
        | SignalReceiverRefusal.LeaderBlocks signal ->
            $"%O{signal} is sent to the process as a whole, and the process's leader blocks it while another thread does not, so a thread other than the leader would take it: a caught signal to run its handler, and under Linux an ignored one (SIGCONT at its default included) to discard it, which Linux leaves pending on the process until then. Which thread differs between flavours, and on Linux depends on which threads took earlier signals; this kernel delivers a process's own signals to its leader only."
        | SignalReceiverRefusal.DefaultBehindHandlers signal ->
            $"returning to user mode, a thread would take %O{signal}, whose default stops or continues the process, after handler frames were pushed for other signals at the same return. What a stopped process does with frames already pushed has not been measured."
        | SignalReceiverRefusal.PendingForProcessAndLeader signal ->
            $"under Darwin, %O{signal} would be left pending on the process as a whole while an instance of it is pending on the leader alone, or the other way round. Darwin holds the two as one instance, and this kernel keeps the process's pending set apart from each thread's."
        | SignalReceiverRefusal.LeaderAlreadySignalled signal ->
            $"under Linux, %O{signal} is sent to the process as a whole while its leader, which does not block it, is not running and already has a signal to take, and another thread does not block it. Linux then wakes that other thread, and whichever of the two returns to user mode first takes the process's signals, lowest first, so the other thread may run every handler and the leader's call restart, or each may take some. Which returns first is scheduling, and this kernel delivers a process's own signals to its leader only."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : SignalReceiverRefusal) : RefusalKind =
        match refusal with
        | SignalReceiverRefusal.LeaderBlocks _ -> RefusalKind.Unmodelled
        | SignalReceiverRefusal.DefaultBehindHandlers _ -> RefusalKind.Unmodelled
        | SignalReceiverRefusal.PendingForProcessAndLeader _ -> RefusalKind.Unmodelled
        | SignalReceiverRefusal.LeaderAlreadySignalled _ -> RefusalKind.Unmodelled

[<RequireQualifiedAccess>]
module SignalState =
    /// Validate a signal at the operation boundary: a loud failure if it is
    /// not a signal under this numbering at all. A client can build a signal
    /// one numbering lacks (`SIGPWR` for a Darwin process, or a `RealTime`
    /// out of range), which no kernel mask or disposition table could hold;
    /// the callers that produced a signal from a raw signo honestly went
    /// through `Signal.ofRawSignoUnder`, which refuses those, so reaching this
    /// failure means a client built one some other way.
    let private parseUnder (operation : string) (numbering : SignalNumbering) (signal : Signal) : Signal =
        if Signal.existsUnder numbering signal then
            signal
        else
            failwith
                $"SignalState.%s{operation}: %O{signal} is not a signal under the %O{numbering} numbering; a raw signo should have been refused at the caller's own boundary, via Signal.ofRawSignoUnder."

    /// SIGKILL and SIGSTOP, for which the kernel holds no disposition but the
    /// default. Narrower than `Signal.isUncatchableUnder`, which adds the two
    /// numbers glibc's `sigaction` refuses on top of the kernel's refusal.
    let internal kernelHoldsOnlyDefault (signal : Signal) : bool =
        match signal with
        | Signal.SIGKILL
        | Signal.SIGSTOP -> true
        | _ -> false

    /// What a signal generated under `disposition` does once a thread could
    /// take it.
    [<RequireQualifiedAccess>]
    type private Effect =
        /// It is pending until that thread takes it and runs its handler.
        | Caught
        /// It is discarded: `SIG_IGN`, or `SIG_DFL` for a signal whose default
        /// is to discard it or to continue the process, which, never stopped
        /// here, has nothing to continue. Linux's `sig_handler_ignored` counts
        /// SIGCONT at its default the same way.
        | Ignored
        /// Its default terminates the process.
        | Terminates
        /// Its default stops the process.
        | Stops

    let private effectOf
        (numbering : SignalNumbering)
        (disposition : SignalDisposition<'Handler>)
        (signal : Signal)
        : Effect
        =
        match disposition with
        | SignalDisposition.Catch _ -> Effect.Caught
        | SignalDisposition.Ignore -> Effect.Ignored
        | SignalDisposition.Default ->
            match Signal.defaultDispositionUnder numbering signal with
            | DefaultDisposition.Ignore
            | DefaultDisposition.Continue -> Effect.Ignored
            | DefaultDisposition.Terminate -> Effect.Terminates
            | DefaultDisposition.Stop -> Effect.Stops

    /// Whether `disposition` ignores `signal` (see `Effect.Ignored`).
    let private ignores
        (numbering : SignalNumbering)
        (disposition : SignalDisposition<'Handler>)
        (signal : Signal)
        : bool
        =
        effectOf numbering disposition signal = Effect.Ignored

    /// `mask` as a kernel holds it: without SIGKILL and SIGSTOP, which it drops
    /// silently, and with every other bit, one that names no signal included.
    /// Throws `ArgumentException`, naming `parameter`, the argument the client
    /// passed the mask in, on a mask made under another numbering, whose bits
    /// name other signals.
    ///
    /// Measured by the signal fuzzer's harness
    /// (`WoofWare.PosixKernel.Test/signalFuzz/harness.c`) on Linux 6.18.5 and
    /// Darwin 27.0.0: a handler whose `sa_mask` named both read neither back in
    /// its mask while it ran. And by
    /// `docs/plans/2026-08-23-posix-kernel-extraction/sigaction-mask-bits.c` on
    /// the same two: an `sa_mask` of every bit was stored and held while the
    /// handler ran less exactly those two, so with Darwin's bit 31 and Linux's
    /// 32 and 33, through glibc and the raw `rt_sigaction` alike.
    let private maskable
        (operation : string)
        (parameter : string)
        (numbering : SignalNumbering)
        (mask : SignalMask)
        : SignalMask
        =
        match SignalMask.numbering mask with
        | ValueSome other when other <> numbering ->
            raise (
                Refusal.exceptionOf
                    $"SignalState.%s{operation}"
                    (RefusalKind.Contradictory parameter)
                    $"the mask %O{mask} was made under the %O{other} numbering, and this process reads signals under %O{numbering}."
            )
        | _ -> SignalMask.without (Set.ofList [ Signal.SIGKILL ; Signal.SIGSTOP ]) mask

    let private withDisposition
        (signal : Signal)
        (disposition : SignalDisposition<'Handler>)
        (dispositions : Map<Signal, SignalDisposition<'Handler>>)
        : Map<Signal, SignalDisposition<'Handler>>
        =
        match disposition with
        | SignalDisposition.Default -> Map.remove signal dispositions
        | SignalDisposition.Ignore
        | SignalDisposition.Catch _ -> Map.add signal disposition dispositions

    /// The signal state a process starts with: no handler frames, so nothing
    /// blocked, nothing pending, and every signal at its default except those in
    /// `inheritedIgnores`, which are ignored. `execve(2)` resets every caught
    /// signal to its default but keeps ignored ones ignored, so a launcher
    /// can start a process with signals already ignored (as `nohup` does).
    ///
    /// `numbering` is the platform's (`SimulatedUnixPlatform.signalNumbering`),
    /// as for every operation on the state.
    ///
    /// Fails loud on a signal the numbering does not have, and on SIGKILL or
    /// SIGSTOP, which no process can have ignored.
    let internal initial
        (numbering : SignalNumbering)
        (inheritedIgnores : Set<Signal>)
        : SignalState<'Thread, 'Handler>
        =
        let dispositions =
            (Map.empty, inheritedIgnores)
            ||> Set.fold (fun dispositions signal ->
                let signal = parseUnder "initial" numbering signal

                if kernelHoldsOnlyDefault signal then
                    failwith
                        $"SignalState.initial: %O{signal} under the %O{numbering} numbering cannot have been left ignored; the kernel holds no disposition for it but the default."

                Map.add signal SignalDisposition.Ignore dispositions
            )

        {
            Dispositions = dispositions
            Blocked = Map.empty
            MasksToRestore = Map.empty
            Frames = Map.empty
            NextFrame = 0L
            Pending = []
        }

    /// What a delivery of `signal` would do now. A client asks
    /// `UnixSignal.sigaction`.
    let internal disposition
        (numbering : SignalNumbering)
        (signal : Signal)
        (state : SignalState<'Thread, 'Handler>)
        : SignalDisposition<'Handler>
        =
        match Map.tryFind (parseUnder "disposition" numbering signal) state.Dispositions with
        | Some disposition -> disposition
        | None -> SignalDisposition.Default

    /// Every signal whose disposition is not the default.
    let internal dispositions (state : SignalState<'Thread, 'Handler>) : Map<Signal, SignalDisposition<'Handler>> =
        state.Dispositions

    /// Set `signal`'s disposition, as `sigaction(2)` does. A client calls
    /// `UnixSignal.sigaction`, which refuses what the kernel refuses before
    /// it gets here.
    ///
    /// A disposition that ignores the signal discards every instance of it
    /// already pending, for every thread and for the process: `SIG_IGN`, and
    /// `SIG_DFL` for a signal whose default is to discard it or to continue
    /// the process (so a pending SIGCONT is discarded by restoring its
    /// default). Any other disposition leaves pending instances to be
    /// delivered under it.
    ///
    /// Fails loud on SIGKILL and SIGSTOP, for which the kernel refuses any
    /// disposition, and `UnixSignal.sigaction` answers EINVAL.
    let internal setDisposition
        (numbering : SignalNumbering)
        (signal : Signal)
        (disposition : SignalDisposition<'Handler>)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        let signal = parseUnder "setDisposition" numbering signal

        if kernelHoldsOnlyDefault signal then
            failwith
                $"SignalState.setDisposition: no kernel disposition but the default can exist for %O{signal} under the %O{numbering} numbering; UnixSignal.sigaction refuses it with EINVAL before it reaches here."

        let disposition =
            match disposition with
            | SignalDisposition.Default
            | SignalDisposition.Ignore -> disposition
            | SignalDisposition.Catch action ->
                SignalDisposition.Catch
                    { action with
                        Mask = maskable "setDisposition" "newAction" numbering action.Mask
                    }

        // Measured on Linux 6.18.5 and Darwin 25.6.0 (2026-09-23), and swept
        // again on Linux 6.18.5 and Darwin 27.0.0 (2026-09-26) over every
        // signal sigaction accepts, from each of SIG_DFL, SIG_IGN and a
        // handler to each of those and a second handler, blocked and pending
        // in either direction
        // (docs/plans/2026-08-23-posix-kernel-extraction/signal-disposition-table.c):
        // exactly the changes to a disposition that `ignores` the signal
        // emptied sigpending, whatever the disposition before, and the rest
        // were delivered once unblocked.
        let pending =
            if ignores numbering disposition signal then
                state.Pending |> List.filter (fun queued -> queued.Entry.Signal <> signal)
            else
                state.Pending

        { state with
            Dispositions = withDisposition signal disposition state.Dispositions
            Pending = pending
        }

    /// `thread`'s handler frames, innermost first: the ones
    /// `UnixSignal.onReturnToUser` has pushed and `UnixSignal.sigreturn` has not
    /// yet popped.
    let framesOf (thread : 'Thread) (state : SignalState<'Thread, 'Handler>) : HandlerFrame<'Thread, 'Handler> list =
        match Map.tryFind thread state.Frames with
        | Some frames -> frames
        | None -> []

    /// Every thread with a handler frame.
    let threadsWithFrames (state : SignalState<'Thread, 'Handler>) : Set<'Thread> =
        state.Frames |> Map.keys |> Set.ofSeq

    /// `thread`'s signal mask: what `sigprocmask(2)` would answer as its old
    /// mask.
    let maskOf (thread : 'Thread) (state : SignalState<'Thread, 'Handler>) : SignalMask =
        match Map.tryFind thread state.Blocked with
        | Some mask -> mask
        | None -> SignalMask.empty

    /// Every thread whose mask blocks anything.
    let threadsWithMasks (state : SignalState<'Thread, 'Handler>) : Set<'Thread> =
        state.Blocked |> Map.keys |> Set.ofSeq

    /// `state` with `thread`'s mask `mask`, already screened by `maskable`.
    let private withMask
        (thread : 'Thread)
        (mask : SignalMask)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        { state with
            Blocked =
                if SignalMask.isEmpty mask then
                    Map.remove thread state.Blocked
                else
                    Map.add thread mask state.Blocked
        }

    /// `thread`'s mask changed by `change` with `set`, as `sigprocmask(2)`
    /// changes it: SIGKILL and SIGSTOP are dropped from the result silently,
    /// and every other bit is kept, one that names no signal included. A
    /// client calls `UnixSignal.pthreadSigmask` or its neighbours, which decode
    /// `how` and screen what the C library screens first.
    ///
    /// Throws `ArgumentException` on a set made under another numbering.
    let internal changeMask
        (numbering : SignalNumbering)
        (change : SignalMaskChange)
        (set : SignalMask)
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        let set = maskable "changeMask" "set" numbering set
        let current = maskOf thread state

        let changed =
            match change with
            | SignalMaskChange.Block -> SignalMask.union current set
            | SignalMaskChange.Unblock -> SignalMask.difference current set
            | SignalMaskChange.SetMask -> set

        withMask thread changed state

    /// `state` with `child` given `parent`'s mask, as a new thread starts with
    /// its creator's.
    let internal inheritMask
        (parent : 'Thread)
        (child : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        withMask child (maskOf parent state) state

    /// The mask `thread` gets back once the `sigsuspend(2)` or `pause(2)` it is
    /// in returns: `Some` from the call until the thread next returns to user
    /// mode (`UnixSignal.onReturnToUser`), and `None` otherwise.
    let maskToRestore (thread : 'Thread) (state : SignalState<'Thread, 'Handler>) : SignalMask option =
        Map.tryFind thread state.MasksToRestore

    /// Every thread with a mask to restore: those in `sigsuspend(2)` or
    /// `pause(2)`, and those whose call has ended and which have not yet
    /// returned to user mode.
    let threadsWithMasksToRestore (state : SignalState<'Thread, 'Handler>) : Set<'Thread> =
        state.MasksToRestore |> Map.keys |> Set.ofSeq

    /// `sigsuspend(2)`'s change to `thread`'s mask: `temporary` replaces it, SIGKILL
    /// and SIGSTOP dropped silently and every other bit kept, and the mask it
    /// replaces is kept to be restored as the thread returns to user mode
    /// (`onReturnToUser`). Only `thread`'s mask changes, on both flavours.
    ///
    /// Fails loudly if `thread` already has a mask to restore (a client that
    /// made a second call without returning to user mode from the first), and
    /// throws `ArgumentException` on a mask made under another numbering.
    let internal suspend
        (numbering : SignalNumbering)
        (thread : 'Thread)
        (temporary : SignalMask)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        if Map.containsKey thread state.MasksToRestore then
            failwith
                $"SignalState.suspend: thread %O{thread} already has a mask to restore from an earlier sigsuspend, so it has not returned to user mode since, and cannot be making another call (this is a bug in the client)."

        let temporary = maskable "suspend" "mask" numbering temporary

        { state with
            MasksToRestore = Map.add thread (maskOf thread state) state.MasksToRestore
        }
        |> withMask thread temporary

    /// Drop everything held for `thread` alone: its mask, the mask a
    /// `sigsuspend(2)` it was in would have restored, its handler frames, and
    /// the signals pending on it alone, which are discarded rather than
    /// passed on to another thread.
    /// Signals pending on the process stay for another thread to take.
    ///
    /// For a thread that has exited.
    let internal forgetThread
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        // Discarded, not passed to the process: measured on Linux 6.18.5 and Darwin
        // 27.0.0 by `docs/plans/2026-08-23-posix-kernel-extraction/thread-exit-pending.c`.
        // A signal pending on an exiting thread alone was never delivered afterwards,
        // nor pending on the thread that remained, whether that thread blocked it or not.
        { state with
            Blocked = Map.remove thread state.Blocked
            MasksToRestore = Map.remove thread state.MasksToRestore
            Frames = Map.remove thread state.Frames
            Pending =
                state.Pending
                |> List.filter (fun queued -> queued.Entry.Target <> ValueSome thread)
        }

    /// The first half of generating `signal` (checked), common to `enqueue`
    /// and `generate`: `None` if the kernel discards it before it has any
    /// effect at all, and otherwise the state once its generation has
    /// discarded any pending instance of the opposite kind of signal.
    ///
    /// Darwin discards an ignored signal first, whatever any mask says, and
    /// SIGCONT alone is never discarded there. Linux discards nothing yet: an
    /// ignored signal is dropped later, once it is known some thread could
    /// receive it, and a blocked one stays pending.
    ///
    /// What survives that discards the opposite kind, on every thread and on
    /// the process: a stop signal (default Stop) discards a pending SIGCONT,
    /// and SIGCONT discards every pending stop signal, whatever the
    /// dispositions of either.
    let private beginGeneration
        (numbering : SignalNumbering)
        (signal : Signal)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler> option
        =
        // Measured 2026-09-26 on Linux 6.18.5 and Darwin 27.0.0
        // (docs/plans/2026-08-23-posix-kernel-extraction/signal-disposition-table.c,
        // parts "fl" and "fu"): every ordered pair of distinct signals from
        // SIGTSTP, SIGTTIN, SIGTTOU, SIGCONT and a SIGUSR1 control, under
        // every pair of SIG_DFL, SIG_IGN and a handler, each generated
        // process- or thread-directed, both blocked; and each stop signal and
        // SIGCONT generated unblocked against a pending one of the other
        // kind. The only departure from "the opposite kind is discarded" is
        // Darwin's ignored stop signal, which discards nothing, being itself
        // discarded first. The same Darwin rows on 25.6.0, with handlers
        // only, agree.
        let disposition =
            match Map.tryFind signal state.Dispositions with
            | Some disposition -> disposition
            | None -> SignalDisposition.Default

        if
            ignores numbering disposition signal
            && not (Signal.blockedIgnoredSignalStaysPendingUnder numbering signal)
        then
            None
        else

        let opposite : DefaultDisposition option =
            match Signal.defaultDispositionUnder numbering signal with
            | DefaultDisposition.Stop -> Some DefaultDisposition.Continue
            | DefaultDisposition.Continue -> Some DefaultDisposition.Stop
            | DefaultDisposition.Terminate
            | DefaultDisposition.Ignore -> None

        match opposite with
        | None -> Some state
        | Some opposite ->
            let pending =
                state.Pending
                |> List.filter (fun queued -> Signal.defaultDispositionUnder numbering queued.Entry.Signal <> opposite)

            if List.length pending = List.length state.Pending then
                Some state
            else
                Some
                    { state with
                        Pending = pending
                    }

    /// Where `signal` comes in the order a thread takes the signals of one pending
    /// set, lowest first.
    let private pickRank (numbering : SignalNumbering) (signal : Signal) : int * int =
        // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/signal-pick-order.c`
        // on Linux 6.18.5 (aarch64) and Darwin 25.6.0 and 27.0.0, whose rows
        // `TestSignalPickOrder` replays: every standard catchable signal, blocked,
        // generated in 42 orders, process- and thread-directed, then drained by
        // sigwait and by handlers that block each other; on Linux also with every
        // real-time signal, in 20 orders. Generation order never mattered. Darwin
        // took the lowest number first; Linux took SIGILL, SIGTRAP, SIGBUS, SIGFPE,
        // SIGSEGV and SIGSYS first (its `next_signal` calls them synchronous), then
        // the lowest number, so every real-time signal after every standard one.
        let signo = Signal.toRawSignoUnder numbering signal

        match numbering with
        | SignalNumbering.Linux ->
            match signal with
            | Signal.SIGILL
            | Signal.SIGTRAP
            | Signal.SIGBUS
            | Signal.SIGFPE
            | Signal.SIGSEGV
            | Signal.SIGSYS -> 0, signo
            | _ -> 1, signo
        | SignalNumbering.Darwin -> 0, signo

    /// The queueing half of generation, on an entry `beginGeneration` let
    /// through, holding `charge`: coalesce a standard signal already pending in
    /// its set, and otherwise add it to its set in its place in the pick order,
    /// after any instance of the same real-time signal already there. A `Bare`
    /// real-time instance is dropped where its signal is pending in its set
    /// already, and an allocated one replaces a `Bare` one of its signal.
    let private admit
        (numbering : SignalNumbering)
        (entry : PendingSignal<'Thread>)
        (charge : PendingCharge)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        let sameSet (queued : QueuedSignal<'Thread>) : bool =
            queued.Entry.Signal = entry.Signal && queued.Entry.Target = entry.Target

        let realTime = Signal.isRealTimeUnder numbering entry.Signal

        let queued =
            {
                Entry = entry
                Charge = charge
            }

        // Measured by `docs/probes/rt-queue-limit` (section `bare`) on Linux
        // 6.18.5: a real-time kill with no room, beside an allocated instance of
        // its signal, was lost; an allocated instance sent beside a bare one was
        // delivered once, with its own information, the bare one gone.
        if not realTime && List.exists sameSet state.Pending then
            state
        else

        match charge with
        | PendingCharge.Bare when List.exists sameSet state.Pending -> state
        | PendingCharge.Charged _ when
            state.Pending
            |> List.exists (fun pending -> sameSet pending && pending.Charge = PendingCharge.Bare)
            ->
            { state with
                Pending =
                    state.Pending
                    |> List.map (fun pending ->
                        if sameSet pending && pending.Charge = PendingCharge.Bare then
                            queued
                        else
                            pending
                    )
            }
        | PendingCharge.Bare
        | PendingCharge.Charged _
        | PendingCharge.Unbounded ->
            let key (pending : PendingSignal<'Thread>) : 'Thread voption * (int * int) =
                pending.Target, pickRank numbering pending.Signal

            let entryKey = key entry

            let precedes (pending : QueuedSignal<'Thread>) : bool =
                compare (key pending.Entry) entryKey <= 0

            { state with
                Pending =
                    List.takeWhile precedes state.Pending
                    @ (queued :: List.skipWhile precedes state.Pending)
            }

    /// Add a generated signal to its pending set, checking it first, without
    /// deciding whether it takes effect at once (see `generate`,
    /// which does).
    ///
    /// A signal whose disposition at generation is "ignore" — `SIG_IGN`, or
    /// the default where that discards it or continues the process — never
    /// becomes pending under Darwin's rule, whatever any mask says, unless it
    /// is SIGCONT; under
    /// Linux's it becomes pending and stays so exactly as long as no receiver
    /// could take it (see `onReturnToUser` for the delivery half of the rule).
    ///
    /// A stop signal discards any pending SIGCONT as it is generated, and
    /// SIGCONT discards any pending stop signal, on every thread and on the
    /// process; under Darwin's rule an ignored stop signal is discarded
    /// before it can.
    ///
    /// A standard signal that is already pending in the same pending set is
    /// discarded: a kernel holds at most one pending instance of a standard
    /// signal per set, and `Target` is the set — `ValueNone` the process-wide
    /// one, `ValueSome t` the thread's own. Measured on Linux 6.18.5 and
    /// Darwin 25.6.0: three process-directed `SIGUSR1` while blocked deliver
    /// once; and the sets are separate keys — a process-directed plus a
    /// thread-directed `SIGUSR2` deliver twice on Linux, and on Darwin when
    /// the thread is not the leader. A real-time signal (Linux's 32..64; see
    /// `Signal.isRealTimeUnder`) queues without coalescing.
    ///
    /// One measured divergence is not modelled here: Darwin delivers a
    /// process-directed and a thread-directed instance once, not twice, when
    /// the thread is the leader (measured on Darwin 27.0.0 by
    /// `docs/plans/2026-08-23-posix-kernel-extraction/raise-sweep.c`), because it puts a signal sent to the process
    /// in the pending set of the thread it chooses to take it. `generate`
    /// refuses to leave such a pair pending
    /// (`SignalReceiverRefusal.PendingForProcessAndLeader`); this function,
    /// which is not told the leader, holds them apart.
    let internal enqueue
        (numbering : SignalNumbering)
        (entry : PendingSignal<'Thread>)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        let entry =
            { entry with
                Signal = parseUnder "enqueue" numbering entry.Signal
            }

        match beginGeneration numbering entry.Signal state with
        | None -> state
        | Some state -> admit numbering entry PendingCharge.Unbounded state

    /// How many pending instances hold a queue entry charged to `user`.
    let internal chargedTo (user : UserId) (state : SignalState<'Thread, 'Handler>) : int =
        state.Pending
        |> List.sumBy (fun queued ->
            match queued.Charge with
            | PendingCharge.Charged charged when charged = user -> 1
            | PendingCharge.Charged _
            | PendingCharge.Unbounded
            | PendingCharge.Bare -> 0
        )

    /// Which thread could take a pending signal now.
    [<RequireQualifiedAccess>]
    type private Receiver<'Thread> =
        /// This thread would take it.
        | Thread of 'Thread
        /// It is the process's own, the leader blocks it, and another thread does not.
        | BeyondLeader
        /// Every thread that could take it blocks it.
        | Nobody

    /// Fails loudly unless `leader` and `thread` are both among `threads`: each is a
    /// bug in the client.
    let private checkThread (operation : string) (threads : Set<'Thread>) (role : string) (thread : 'Thread) : unit =
        if not (Set.contains thread threads) then
            failwith
                $"SignalState.%s{operation}: the %s{role} %O{thread} is not one of the process's threads %O{threads}."

    /// Which thread could take `entry` now: its target, for a signal pending on
    /// one thread; and for one pending on the process, the leader, unless it blocks
    /// the signal.
    let private receiverFor
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (entry : PendingSignal<'Thread>)
        (state : SignalState<'Thread, 'Handler>)
        : Receiver<'Thread>
        =
        let blocks (thread : 'Thread) : bool =
            SignalMask.contains entry.Signal (maskOf thread state)

        match entry.Target with
        | ValueSome target ->
            if not (Set.contains target threads) then
                failwith
                    $"SignalState: %O{entry.Signal} is pending on %O{target} alone, which is not one of the process's threads %O{threads}; a thread's own signals should have left with it (forgetThread)."

            if blocks target then
                Receiver.Nobody
            else
                Receiver.Thread target
        | ValueNone ->
            // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/signal-receiver.c`
            // on Linux 6.18.5 (aarch64, and x86-64 under Rosetta) and Darwin 25.6.0
            // and 27.0.0: with four threads handling SIGUSR1, each set of them
            // blocking it, each sender, and eight sends in a row, every send went to
            // the main thread whenever it did not block the signal (192 rows, 1536
            // sends, per flavour), whoever sent it and whether the others slept or
            // spun. When the main thread blocked it, Darwin chose the first-created
            // thread that did not, and Linux the next such thread from a cursor that
            // earlier deliveries move (`curr_target`).
            if not (blocks leader) then
                Receiver.Thread leader
            elif threads |> Set.exists (fun thread -> not (blocks thread)) then
                Receiver.BeyondLeader
            else
                Receiver.Nobody

    /// Whether a death by `signal` writes a core dump under `coreDumps`.
    let private dumpsCore (coreDumps : CoreDumps) (numbering : SignalNumbering) (signal : Signal) : bool =
        match coreDumps with
        | CoreDumps.Suppressed -> false
        | CoreDumps.Written -> Signal.dumpsCoreUnder numbering signal

    /// A pending signal that is deliverable to `thread`: one its mask lets
    /// through, in a set it takes from as it returns to user mode. That is its
    /// own set; the process's, if it is the process's `leader`; and, under
    /// Linux's numbering, the process's where the leader blocks the signal,
    /// since any of Linux's threads takes from the process's set. The first
    /// such in `pending`'s order, or `ValueNone` where there is none.
    ///
    /// Reads no disposition: the thread takes such a signal as it returns,
    /// whether that runs a handler, applies a default or discards it, and
    /// whether or not `takeOnReturn` refuses to say which.
    let internal deliverable
        (numbering : SignalNumbering)
        (leader : 'Thread)
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : Signal voption
        =
        // Every call that may make a signal deliverable asks this of a
        // thread, so nothing pending answers without reading a mask.
        if List.isEmpty state.Pending then
            ValueNone
        else

        let mask = maskOf thread state

        let takesFrom (entry : PendingSignal<'Thread>) : bool =
            match entry.Target with
            | ValueSome target -> target = thread
            | ValueNone ->
                thread = leader
                || (
                    match numbering with
                    | SignalNumbering.Linux -> SignalMask.contains entry.Signal (maskOf leader state)
                    | SignalNumbering.Darwin -> false
                )

        match
            state.Pending
            |> List.tryFind (fun queued -> takesFrom queued.Entry && not (SignalMask.contains queued.Entry.Signal mask))
        with
        | Some queued -> ValueSome queued.Entry.Signal
        | None -> ValueNone

    /// Generate `entry`: decide what it does to the process at once, and queue
    /// it (see `enqueue`) if its effect, if any, comes later.
    ///
    /// `threads` are the process's threads, and `leader` is the one of them that
    /// takes the signals sent to the process as a whole: a signal pending on the
    /// process can be received by the leader, and by no other thread while the
    /// leader does not block it.
    ///
    /// What the signal does, and what is refused, are as `UnixSignal.kill`
    /// states; a termination's core flag is as `coreDumps` decides. What a
    /// signal left pending holds against `RLIMIT_SIGPENDING` is as `queue`
    /// says, and a real-time signal sent by `tgkill(2)` past that limit is
    /// `QueueFull`. `leaderRunning` says whether the leader is running on a
    /// processor, out of any sleep, as Linux's `task_curr` does.
    ///
    /// Fails loudly unless `leader` is among `threads`, on a signal aimed at a
    /// thread that is not, and on a `QueueAccount.Limited` under Darwin's
    /// numbering.
    let internal generate
        (numbering : SignalNumbering)
        (coreDumps : CoreDumps)
        (queue : QueueAccount)
        (leader : 'Thread)
        (leaderRunning : bool)
        (threads : Set<'Thread>)
        (entry : PendingSignal<'Thread>)
        (state : SignalState<'Thread, 'Handler>)
        : Result<SignalGeneration<'Thread, 'Handler>, SignalReceiverRefusal>
        =
        checkThread "generate" threads "leader" leader

        let entry =
            { entry with
                Signal = parseUnder "generate" numbering entry.Signal
            }

        match beginGeneration numbering entry.Signal state with
        | None -> Ok (SignalGeneration.ProcessContinues state)
        | Some state ->

        // Measured by `docs/probes/rt-queue-limit` on Linux 6.18.5, as root and
        // as uid 1000 alike: the limit counts the instances queued for the
        // receiving process's real user, in every process of that user, and a
        // send needs the count below the limit. Past it, kill queued a standard
        // signal anyway, and kept a real-time one as the bare pending bit (or
        // lost it, beside an instance of its signal); tgkill kept a standard
        // signal as the bare bit and failed a real-time one with EAGAIN; a bare
        // instance counted against nothing. A discarded or coalesced signal is
        // never allocated, so the count is read once `beginGeneration` has run;
        // and an ignored signal its receiver does not block is discarded
        // before the allocation (section `ignored`: at a limit of 0, tgkill of
        // an ignored real-time signal answered 0 unblocked and EAGAIN blocked).
        let charge : PendingCharge voption =
            match queue with
            | QueueAccount.Unbounded -> ValueSome PendingCharge.Unbounded
            | QueueAccount.Limited (user, queuedElsewhere, limit, sender) ->
                match numbering with
                | SignalNumbering.Darwin ->
                    failwith
                        $"SignalState.generate: %O{entry.Signal} is counted against RLIMIT_SIGPENDING under Darwin's numbering, which has no such limit (this is a bug in this library)."
                | SignalNumbering.Linux ->

                let realTime = Signal.isRealTimeUnder numbering entry.Signal
                let queued = queuedElsewhere + chargedTo user state
                let room = uint64 queued < limit

                let overrides =
                    not realTime
                    && (
                        match sender with
                        | SignalSender.Kill
                        | SignalSender.Kernel -> true
                        | SignalSender.ThreadKill -> false
                    )

                if room || overrides then
                    ValueSome (PendingCharge.Charged user)
                else
                    match sender with
                    | SignalSender.ThreadKill when realTime -> ValueNone
                    | SignalSender.ThreadKill
                    | SignalSender.Kill
                    | SignalSender.Kernel -> ValueSome PendingCharge.Bare

        let receiver = receiverFor leader threads entry state

        let effect =
            effectOf numbering (disposition numbering entry.Signal state) entry.Signal

        let discardedAsIgnored =
            match receiver, effect with
            | Receiver.Thread _, Effect.Ignored -> true
            | _, _ -> false

        match charge with
        | ValueNone when not discardedAsIgnored -> Ok SignalGeneration.QueueFull
        | ValueNone
        | ValueSome _ ->

        // Reached with no charge only for a signal discarded as ignored, which
        // is never admitted.
        let charge = charge |> ValueOption.defaultValue PendingCharge.Bare

        // Linux decides this at generation (`complete_signal` takes the whole
        // thread group down for a fatal signal as soon as it has found a thread
        // that wants it), and SIGKILL is immediate on Darwin too. For any other
        // fatal or stopping signal, both kernels act when the receiving thread
        // next returns to user mode, which for a self-directed signal is the
        // return from the very call that generated it. They differ only in what
        // *other* threads could run in between, which this approximates as
        // nothing. Which thread receives such a signal does not matter, since it
        // acts on the whole process, so it is answered even when the leader
        // blocks it.
        // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/raise-sweep.c`
        // on Darwin 27.0.0, with every catchable signal blocked by every thread:
        // a `kill(2)` of the process and a `raise(3)` on the main thread, in
        // either order, by either thread, in a process of one thread or two,
        // were delivered once, to the main thread; a `kill` and a
        // `pthread_kill` of the second thread were delivered once to each.
        // Linux 6.18.5 delivered the first pair twice.
        let leftPending () : Result<SignalGeneration<'Thread, 'Handler>, SignalReceiverRefusal> =
            let mergesOnDarwin =
                match numbering with
                | SignalNumbering.Linux -> false
                | SignalNumbering.Darwin ->
                    let partner =
                        match entry.Target with
                        | ValueNone -> ValueSome (ValueSome leader)
                        | ValueSome target when target = leader -> ValueSome ValueNone
                        | ValueSome _ -> ValueNone

                    match partner with
                    | ValueNone -> false
                    | ValueSome partner ->
                        state.Pending
                        |> List.exists (fun pending ->
                            pending.Entry.Signal = entry.Signal && pending.Entry.Target = partner
                        )

            if mergesOnDarwin then
                Error (SignalReceiverRefusal.PendingForProcessAndLeader entry.Signal)
            else
                Ok (SignalGeneration.ProcessContinues (admit numbering entry charge state))

        // Linux's `complete_signal` hands a signal sent to the process to the
        // leader only while the leader wants it (`wants_signal`): it is running,
        // or it has no signal to take already (`TIF_SIGPENDING`). Otherwise it
        // wakes the next thread that wants it, and the threads it has woken take
        // from the process's set, lowest first, in whichever order they return
        // to user mode. Measured by `docs/probes/process-signal-pair` on Linux
        // 6.18.5: with the leader asleep in poll and two signals sent by a second
        // thread, the sender, or a third thread where the sender blocked both,
        // ran both handlers and the leader's poll restarted, or the leader ran
        // both, or each ran one; a running leader took both, and a standard
        // signal already pending was coalesced and woke nobody. Darwin gave both
        // to the leader.
        // Beside `RLIMIT_SIGPENDING`: Linux allocates before it chooses a thread,
        // so `QueueFull` above is answered first; it is only ever a thread's own
        // signal, which this rule never meets. A real-time kill past the limit,
        // kept bare or lost beside an instance, still goes on to choose and wake
        // a thread (`complete_signal` runs after `out_set`), so the rule applies
        // to it as to any other.
        let wokenBeyondLeader () : bool =
            match numbering, entry.Target with
            | SignalNumbering.Darwin, _
            | SignalNumbering.Linux, ValueSome _ -> false
            | SignalNumbering.Linux, ValueNone ->
                let coalesced =
                    not (Signal.isRealTimeUnder numbering entry.Signal)
                    && state.Pending
                       |> List.exists (fun pending ->
                           pending.Entry.Signal = entry.Signal && pending.Entry.Target.IsNone
                       )

                not leaderRunning
                && not coalesced
                && (deliverable numbering leader leader state).IsSome
                && threads
                   |> Set.exists (fun thread ->
                       thread <> leader && not (SignalMask.contains entry.Signal (maskOf thread state))
                   )

        match receiver, effect with
        | Receiver.Nobody, _ -> leftPending ()
        | Receiver.BeyondLeader, Effect.Caught -> Error (SignalReceiverRefusal.LeaderBlocks entry.Signal)
        | Receiver.Thread _, Effect.Caught when wokenBeyondLeader () ->
            Error (SignalReceiverRefusal.LeaderAlreadySignalled entry.Signal)
        | Receiver.Thread _, Effect.Caught -> leftPending ()
        // Discarded without ever being pending, on both kernels, SIGCONT at
        // its default included: Linux decides by the mask of the thread the
        // signal is aimed at (the leader, for one sent to the process), and
        // Darwin by whether a thread it could hand the signal to does not
        // block it. Measured by
        // `docs/plans/2026-08-23-posix-kernel-extraction/sigcont-generation.c`
        // on Linux 6.18.5 and Darwin 27.0.0: a thread that blocked it never saw
        // it through sigpending, a handler installed afterwards never ran, and
        // a thread asleep in poll or sigsuspend slept on. Were it queued
        // instead, it would sit there until the client next asked
        // `onReturnToUser`, and a handler installed in between would receive a
        // signal that was ignored when it was sent.
        | Receiver.Thread _, Effect.Ignored -> Ok (SignalGeneration.ProcessContinues state)
        | Receiver.BeyondLeader, Effect.Ignored ->
            match numbering with
            // Measured by the same probe, with SIGCONT under SIG_IGN and at its
            // default, SIGUSR1 under SIG_IGN and SIGURG at its default: Linux
            // queued each on the process (the leader saw it through sigpending
            // straight after the kill) for another thread to take and discard.
            | SignalNumbering.Linux -> Error (SignalReceiverRefusal.LeaderBlocks entry.Signal)
            // Darwin handed it to a thread that did not block it, which
            // discarded it: only SIGCONT gets here, every other ignored signal
            // having been discarded by `beginGeneration`.
            | SignalNumbering.Darwin -> Ok (SignalGeneration.ProcessContinues state)
        | _, Effect.Terminates ->
            Ok (SignalGeneration.ProcessTerminated (entry.Signal, dumpsCore coreDumps numbering entry.Signal))
        | _, Effect.Stops -> Ok (SignalGeneration.ProcessStopped (entry.Signal, state))

    /// Every pending entry: the process's own set first, then each thread's, each set in the order a thread
    /// takes its signals (see `pendingFor`).
    let pending (state : SignalState<'Thread, 'Handler>) : PendingSignal<'Thread> list =
        state.Pending |> List.map (fun queued -> queued.Entry)

    /// Every pending instance, in `pending`'s order, with what it holds against
    /// `RLIMIT_SIGPENDING`.
    let internal queued (state : SignalState<'Thread, 'Handler>) : QueuedSignal<'Thread> list = state.Pending

    /// The pending signals `thread` could take, in the order it would take them
    /// were it to block none: its own, and if it is the process's `leader`, the
    /// process's too.
    ///
    /// Within one set, Darwin takes the lowest-numbered signal first, and Linux
    /// takes SIGILL, SIGTRAP, SIGBUS, SIGFPE, SIGSEGV and SIGSYS first and then
    /// the lowest-numbered; several instances of one real-time signal come in
    /// the order they were generated. Linux takes every signal of the thread's own
    /// set before any of the process's; Darwin takes the two as one set.
    /// `numbering` says which: it is the machine's
    /// (`SimulatedUnixPlatform.signalNumbering`).
    let pendingFor
        (numbering : SignalNumbering)
        (leader : 'Thread)
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : PendingSignal<'Thread> list
        =
        let own =
            pending state |> List.filter (fun entry -> entry.Target = ValueSome thread)

        let shared =
            if thread = leader then
                pending state |> List.filter (fun entry -> entry.Target.IsNone)
            else
                []

        match numbering with
        // Measured by the pair sweep of `signal-pick-order.c` (see `pickRank`):
        // every ordered pair of distinct standard signals, the first directed at
        // the main thread and the second at the process, both blocked by it.
        // Linux delivered the thread's first in all 806 pairs that the
        // stop/continue flush left both of; Darwin, the lower-numbered first.
        | SignalNumbering.Linux -> own @ shared
        // A stable sort, so the thread's own instance of a signal comes before the
        // process's; nothing measured decides between the two, and no other
        // signal can fall between them.
        | SignalNumbering.Darwin -> own @ shared |> List.sortBy (fun entry -> pickRank numbering entry.Signal)

    /// What `sigpending(2)` answers for `thread`: the signals pending that it
    /// would see and that its mask blocks. It sees its own set, and the
    /// process's: on Linux whichever thread asks, and on Darwin only if it is the
    /// process's `leader`. `numbering` says which: it is the machine's
    /// (`SimulatedUnixPlatform.signalNumbering`).
    ///
    /// Measured on Linux 6.18.5 and Darwin 27.0.0 by
    /// `docs/plans/2026-08-23-posix-kernel-extraction/sigpending-scope.c`: with
    /// a main thread and a second both blocking SIGUSR1, a `kill` of the
    /// process by either showed SIGUSR1 to both on Linux, and to the main
    /// thread alone on Darwin, which puts a signal sent to the process in the
    /// set of the thread it chooses, the main thread whenever every thread
    /// blocks it. A `pthread_kill` showed only to its target, on both.
    ///
    /// A pending signal the thread does not block is left out, as Linux's
    /// `do_sigpending` leaves it out. No thread can see one: it takes such a
    /// signal as it returns to user mode, before it can ask.
    let pendingBlocked
        (numbering : SignalNumbering)
        (leader : 'Thread)
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : SignalMask
        =
        let sees (entry : PendingSignal<'Thread>) : bool =
            match entry.Target with
            | ValueSome target -> target = thread
            | ValueNone ->
                match numbering with
                | SignalNumbering.Linux -> true
                | SignalNumbering.Darwin -> thread = leader

        let mask = maskOf thread state

        pending state
        |> List.filter (fun entry -> sees entry && SignalMask.contains entry.Signal mask)
        |> List.map (fun entry -> entry.Signal)
        |> Set.ofList
        |> SignalMask.ofSignals numbering

    /// Where a thread's mask stands once a handler for `signal` is delivered to it
    /// under `action`, from `mask`.
    let private maskDuring
        (numbering : SignalNumbering)
        (mask : SignalMask)
        (signal : Signal)
        (action : SignalCatch<'Handler>)
        : SignalMask
        =
        // Measured by the signal fuzzer's harness
        // (`WoofWare.PosixKernel.Test/signalFuzz/harness.c`) on Linux 6.18.5 and
        // Darwin 27.0.0, and by
        // `docs/plans/2026-08-23-posix-kernel-extraction/signal-sigaction-flags.c`
        // on Linux 6.18.5 and Darwin 25.6.0: the mask inside a handler is the
        // mask at delivery, `sa_mask`, and the signal unless `SA_NODEFER`;
        // `SA_RESETHAND` does not imply `SA_NODEFER`.
        let blocked =
            if action.NoDefer then
                SignalMask.union mask action.Mask
            else
                SignalMask.union mask action.Mask |> SignalMask.add numbering signal

        // Both masks were screened as they were set, by `changeMask`,
        // `suspend` and `setDisposition`; the last took the handler's mask as
        // `UnixSignal.sigaction`'s `newAction`.
        maskable "onReturnToUser" "newAction" numbering blocked

    /// Whether delivering `signal` under `SA_RESETHAND` resets its disposition.
    let private resetsHand (numbering : SignalNumbering) (signal : Signal) : bool =
        // Measured by
        // `docs/plans/2026-08-23-posix-kernel-extraction/signal-sigaction-flags.c`
        // over every catchable standard signal, and by the signal fuzzer's
        // harness: Linux resets every one; Darwin every one but SIGILL and
        // SIGTRAP, which keep their handler, as POSIX permits.
        match numbering with
        | SignalNumbering.Linux -> true
        | SignalNumbering.Darwin ->
            match signal with
            | Signal.SIGILL
            | Signal.SIGTRAP -> false
            | _ -> true

    /// What `thread` takes as it returns to user mode, as `onReturnToUser`
    /// decides, except that a mask to restore is left where it is: the
    /// outermost frame saves it all the same. For a caller that asks what the
    /// return would do, and keeps the walk's discards, without the thread
    /// returning yet.
    let internal takeOnReturn
        (numbering : SignalNumbering)
        (coreDumps : CoreDumps)
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : Result<SignalDelivery<'Thread, 'Handler> option * SignalState<'Thread, 'Handler>, SignalReceiverRefusal>
        =
        checkThread "onReturnToUser" threads "leader" leader
        checkThread "onReturnToUser" threads "thread asked" thread

        // A signal pending on the process that the leader blocks and another
        // thread does not. Linux's threads all take from the process's pending
        // set, so a thread that does not block it takes it as it returns; where
        // its default ends or stops the whole process, which thread does not
        // matter, as `generate` reasons at generation, and it is answered. Linux
        // 6.18.5 was measured so (`docs/probes/non-leader-unblock`): sent while
        // both threads blocked it, a TERM or TSTP at its default that the
        // second thread unblocked, or let through a `sigsuspend`'s mask,
        // killed or stopped the process before that call returned. Darwin
        // 27.0.0 left each pending on the main thread instead, having put it in
        // that thread's set as it was sent, which this library does not hold
        // apart from the process's; so under Darwin, as for a caught or ignored
        // signal, it is refused.
        let takenBeyondLeader (entry : PendingSignal<'Thread>) : bool =
            match numbering, effectOf numbering (disposition numbering entry.Signal state) entry.Signal with
            | SignalNumbering.Linux, Effect.Terminates
            | SignalNumbering.Linux, Effect.Stops -> true
            | SignalNumbering.Linux, Effect.Caught
            | SignalNumbering.Linux, Effect.Ignored
            | SignalNumbering.Darwin, _ -> false

        let beyondLeader, refused =
            pending state
            |> List.filter (fun entry ->
                match receiverFor leader threads entry state with
                | Receiver.BeyondLeader -> true
                | Receiver.Thread _
                | Receiver.Nobody -> false
            )
            |> List.partition takenBeyondLeader

        match refused with
        | entry :: _ -> Error (SignalReceiverRefusal.LeaderBlocks entry.Signal)
        | [] ->

        // The first entry equal to `entry` gone from `pending`: within one set,
        // the order `pendingFor` walks is the order `Pending` holds, so this is
        // the instance the walk reached.
        let rec without
            (entry : PendingSignal<'Thread>)
            (pending : QueuedSignal<'Thread> list)
            : QueuedSignal<'Thread> list
            =
            match pending with
            | [] -> failwith $"SignalState.onReturnToUser: walked to %O{entry}, which is not pending."
            | head :: tail when head.Entry = entry -> tail
            | head :: tail -> head :: without entry tail

        let taken (entry : PendingSignal<'Thread>) (state : SignalState<'Thread, 'Handler>) =
            { state with
                Pending = without entry state.Pending
            }

        // A single pass is enough: pushing a frame only ever adds to the mask,
        // so an entry the walk has skipped as blocked stays blocked until the
        // walk is over.
        let rec walk
            (pushed : HandlerFrame<'Thread, 'Handler> list)
            (state : SignalState<'Thread, 'Handler>)
            (candidates : PendingSignal<'Thread> list)
            : Result<SignalDelivery<'Thread, 'Handler> option * SignalState<'Thread, 'Handler>, SignalReceiverRefusal>
            =
            let finished () =
                match pushed with
                | [] -> Ok (None, state)
                | _ -> Ok (Some (SignalDelivery.RunHandlers pushed), state)

            let unlessFramesPushed (entry : PendingSignal<'Thread>) (delivery : SignalDelivery<'Thread, 'Handler>) =
                match pushed with
                | [] -> Ok (Some delivery, taken entry state)
                | _ -> Error (SignalReceiverRefusal.DefaultBehindHandlers entry.Signal)

            match candidates with
            | [] -> finished ()
            | entry :: rest ->

            // A blocked SIGCONT at its default stays pending too: measured on
            // Linux 6.18.5 and Darwin 27.0.0 by
            // `docs/plans/2026-08-23-posix-kernel-extraction/sigpending-scope.c`,
            // whose `sigpending` reported it after the `kill` that generated
            // it had returned.
            if SignalMask.contains entry.Signal (maskOf thread state) then
                walk pushed state rest
            else

            match disposition numbering entry.Signal state with
            | SignalDisposition.Catch action ->
                let current = maskOf thread state

                // The first frame of a return from `sigsuspend` saves the mask
                // the call replaced; see `onReturnToUser`.
                let saved =
                    match pushed, Map.tryFind thread state.MasksToRestore with
                    | [], Some restore -> restore
                    | _, _ -> current

                let frame =
                    {
                        Id = HandlerFrameId state.NextFrame
                        Entry = entry
                        Action = action
                        SavedMask = saved
                    }

                let dispositions =
                    if action.ResetHand && resetsHand numbering entry.Signal then
                        Map.remove entry.Signal state.Dispositions
                    else
                        state.Dispositions

                let state =
                    { taken entry state with
                        Dispositions = dispositions
                        Frames = Map.add thread (frame :: framesOf thread state) state.Frames
                        NextFrame = state.NextFrame + 1L
                    }
                    |> withMask thread (maskDuring numbering current entry.Signal action)

                walk (frame :: pushed) state rest
            // Discarded with no action: drop the entry and keep walking — a
            // later entry may still deliver now.
            | SignalDisposition.Ignore -> walk pushed (taken entry state) rest
            | SignalDisposition.Default ->
                match Signal.defaultDispositionUnder numbering entry.Signal with
                | DefaultDisposition.Ignore -> walk pushed (taken entry state) rest
                | DefaultDisposition.Terminate ->
                    // Fatal whatever frames were pushed before it: measured by
                    // the signal fuzzer, which delivers a caught signal and a
                    // fatal one at the same return and sees no handler run.
                    Ok (
                        Some (
                            SignalDelivery.DefaultTerminate (entry.Signal, dumpsCore coreDumps numbering entry.Signal)
                        ),
                        taken entry state
                    )
                | DefaultDisposition.Stop -> unlessFramesPushed entry (SignalDelivery.DefaultStop entry.Signal)
                | DefaultDisposition.Continue -> unlessFramesPushed entry (SignalDelivery.DefaultContinue entry.Signal)

        // The leader walks the process's whole set already; another thread
        // takes, after its own, those of the process's that it can, which only
        // Linux has. Its mask decides each as the walk reaches it.
        let candidates =
            if thread = leader then
                pendingFor numbering leader thread state
            else
                pendingFor numbering leader thread state @ beyondLeader

        walk [] state candidates

    /// What `thread` takes as it returns to user mode, by the rules
    /// `UnixSignal.onReturnToUser` states: `threads` and `leader` are as
    /// `generate` takes them, so `thread` takes the process's own signals as well
    /// as its own only if it is the leader, or, under Linux, one the leader
    /// blocks whose default ends or stops the process, and a termination's core
    /// flag is as `coreDumps` decides.
    ///
    /// Returns the possibly-updated state in every case, because an answer can
    /// change the state without producing an action (an ignored signal is
    /// discarded), and a caller that dropped the no-action state would replay
    /// those discards forever.
    ///
    /// Fails loudly unless `leader` and `thread` are among `threads`, and on a
    /// signal pending on a thread that is not.
    let internal onReturnToUser
        (numbering : SignalNumbering)
        (coreDumps : CoreDumps)
        (leader : 'Thread)
        (threads : Set<'Thread>)
        (thread : 'Thread)
        (state : SignalState<'Thread, 'Handler>)
        : Result<SignalDelivery<'Thread, 'Handler> option * SignalState<'Thread, 'Handler>, SignalReceiverRefusal>
        =
        takeOnReturn numbering coreDumps leader threads thread state
        |> Result.map (fun (delivery, after) ->
            match Map.tryFind thread after.MasksToRestore with
            | None -> delivery, after
            | Some restore ->
                let cleared =
                    { after with
                        MasksToRestore = Map.remove thread after.MasksToRestore
                    }

                // Measured by
                // `docs/plans/2026-08-23-posix-kernel-extraction/sigsuspend-mask.c`
                // on Linux 6.18.5 and Darwin 27.0.0: the outermost frame saved the
                // mask from before the call, and the mask after the call was that
                // mask. A return that runs no handler restores it too (Linux's
                // `restore_saved_sigmask`); the frames then hold it otherwise.
                // A default SIGCONT is no action, and Linux's `get_signal`
                // goes on past it, under the temporary mask, to the next
                // signal, which the client's next ask takes.
                match delivery with
                | Some (SignalDelivery.DefaultContinue _) -> delivery, after
                | Some (SignalDelivery.RunHandlers _)
                | Some (SignalDelivery.DefaultTerminate _)
                | Some (SignalDelivery.DefaultStop _)
                | None ->
                    if after.NextFrame <> state.NextFrame then
                        delivery, cleared
                    else
                        delivery, withMask thread restore cleared
        )

    /// `sigreturn(2)`: pop `thread`'s innermost frame, `frame`, as
    /// `UnixSignal.sigreturn` states.
    ///
    /// Throws `ArgumentException` unless `frame` is `thread`'s innermost frame:
    /// handlers return innermost first, so anything else is a bug in the client.
    let internal sigreturn
        (thread : 'Thread)
        (frame : HandlerFrameId)
        (state : SignalState<'Thread, 'Handler>)
        : SignalState<'Thread, 'Handler>
        =
        match framesOf thread state with
        | innermost :: rest when innermost.Id = frame ->
            // Measured by the signals research's `sigaction_flags.c` on Linux
            // 6.18.5 and Darwin 25.6.0: a handler that unblocked SIGHUP and
            // blocked SIGTERM returned to exactly the mask at delivery.
            { state with
                Frames =
                    match rest with
                    | [] -> Map.remove thread state.Frames
                    | _ -> Map.add thread rest state.Frames
            }
            |> withMask thread innermost.SavedMask
        | frames ->
            raise (
                Refusal.exceptionOf
                    "UnixSignal.sigreturn"
                    (RefusalKind.Contradictory "frame")
                    $"%O{frame} is not thread %O{thread}'s innermost handler frame (its frames, innermost first, are %O{frames |> List.map (fun f -> f.Id)})."
            )
