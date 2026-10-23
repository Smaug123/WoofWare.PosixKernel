namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// What a signal generated for the only process on a machine is counted
/// against, as `ProcessSignal.effect` tells `SignalState.generate`, for a test
/// that compares a call with the generation it makes.
[<RequireQualifiedAccess>]
module internal QueueAccounts =

    /// The process's `RLIMIT_SIGPENDING`, if its flavour has one, with nothing
    /// queued for its user in any other process: there is none.
    let ofLone<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (sender : SignalSender)
        (system : UnixSystem<'Thread, 'Handler>)
        : QueueAccount
        =
        let proc = Lone.proc system

        match proc.PendingSignalLimit with
        | ValueNone -> QueueAccount.Unbounded
        | ValueSome limit -> QueueAccount.Limited (proc.Credentials.RealUser, 0, limit, sender)
