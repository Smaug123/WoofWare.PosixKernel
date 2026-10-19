namespace WoofWare.PosixKernel

/// What a syscall a thread is asleep in does when a signal with a handler is to
/// be delivered to that thread before the syscall has anything else to answer.
[<RequireQualifiedAccess>]
type SignalRestartRule =
    /// The syscall fails with `EINTR`, whatever flags the handler was
    /// installed with.
    | FailsWithEintr
    /// The syscall is restarted if the handler was installed with
    /// `SA_RESTART`, and fails with `EINTR` otherwise.
    | RestartsUnderSaRestart

/// How a syscall a signal interrupted ends, as the thread that made it returns
/// to user mode (`UnixSignal.onReturnToUser`).
[<RequireQualifiedAccess>]
type InterruptedCall =
    /// The call fails with `EINTR`: once the handlers the return pushed, if
    /// any, have returned, the call returns -1.
    | FailsWithEintr
    /// The call restarts, and never returns: once the handlers the return
    /// pushed, if any, have returned, the client makes the call again with
    /// the arguments it was first made with, descriptor numbers included, as
    /// a real kernel re-executes it.
    | Restarts

/// How a syscall a signal interrupted ends if its thread returns to user mode
/// running no handler: by then the signal has been discarded, or the thread
/// blocks it.
[<RequireQualifiedAccess>]
type internal UnhandledInterruption =
    /// The call ends so.
    | Ends of InterruptedCall
    /// The call is a Linux `poll`, or a futex wait with a relative timeout,
    /// which restarts with what is left of its timeout (`restart_syscall`): not
    /// the call as first made.
    | RestartsWithRemainingTime
    /// What the call does is unmeasured: no flavour parks a thread in it yet,
    /// or this flavour does not.
    | Unmeasured

/// A thread's syscall that a signal interrupted: what the thread's return to
/// user mode reads to decide how the call ends.
type internal Interruption =
    {
        /// The first signal the thread would have taken had it returned to user
        /// mode as the call was interrupted: `None` where it would have taken
        /// none, the signal that woke the call having gone by the time the call
        /// was finished.
        Signal : Signal option
        /// How the call ends if a handler runs as the thread returns.
        Rule : SignalRestartRule
        /// How the call ends if no handler runs as the thread returns.
        Unhandled : UnhandledInterruption
        /// How the call would have ended had the thread returned to user mode
        /// as it was interrupted: as the handlers it would have run say, or, had
        /// it taken no signal, as `Unhandled` says. `None` where that return
        /// would have applied a default rather than run a handler, or run
        /// handlers that disagree under `SA_RESTART`.
        AtInterruption : InterruptedCall option
    }

/// Why a thread must return to user mode before it makes another call.
[<RequireQualifiedAccess>]
type internal OwedReturn =
    /// A signal became deliverable to the thread while it was in no syscall,
    /// or as it left one; or a return to user mode it began is not over
    /// (`ReturnToUserOutcome.ContinueDiscarded`). The thread takes its signals
    /// as it returns, whatever has become of that one since.
    | SignalDue
    /// A signal interrupted the thread's last call, and the thread's return to
    /// user mode decides how the call ends.
    | Interrupted of Interruption
