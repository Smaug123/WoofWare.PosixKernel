namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// The return to user mode as it answered before a call a signal interrupted
/// answered `Interrupted` and left its end to the return: one case per case of
/// `WoofWare.PosixKernel.ReturnToUserOutcome`, without `interrupted`.
///
/// A transcript recorded before then prints these, so a test whose recorded
/// corpus holds such transcripts prints each return through `ofReturn`, and
/// the corpus is held to the library mechanically.
[<RequireQualifiedAccess>]
type internal ReturnBeforeInterrupted<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    | Resumes
    | RunHandlers of frames : HandlerFrame<'Thread, 'Handler> list
    | ProcessStopped of signal : Signal
    | ContinueDiscarded of signal : Signal

/// Translating answers into their shapes before calls a signal interrupted
/// answered `Interrupted`.
[<RequireQualifiedAccess>]
module internal AnswersBeforeInterrupted =

    /// `outcome`, a return from a call no signal interrupted, as it was
    /// answered then. Fails for a return from an interrupted call, which the
    /// transcript has no shape for.
    let ofReturn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (outcome : ReturnToUserOutcome<'Thread, 'Handler>)
        : ReturnBeforeInterrupted<'Thread, 'Handler>
        =
        match outcome with
        | ReturnToUserOutcome.Resumes None -> ReturnBeforeInterrupted.Resumes
        | ReturnToUserOutcome.RunHandlers (frames, None) -> ReturnBeforeInterrupted.RunHandlers frames
        | ReturnToUserOutcome.ProcessStopped signal -> ReturnBeforeInterrupted.ProcessStopped signal
        | ReturnToUserOutcome.ContinueDiscarded signal -> ReturnBeforeInterrupted.ContinueDiscarded signal
        | ReturnToUserOutcome.Resumes (Some _)
        | ReturnToUserOutcome.RunHandlers (_, Some _) ->
            failwith $"AnswersBeforeInterrupted.ofReturn: %A{outcome} is the return from an interrupted call"

    /// `fate`, a return's, with its outcome as it was answered then.
    let ofReturnFate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fate : ProcessFate<ReturnToUserOutcome<'Thread, 'Handler>, 'Thread, 'Handler>)
        : ProcessFate<ReturnBeforeInterrupted<'Thread, 'Handler>, 'Thread, 'Handler>
        =
        match fate with
        | ProcessFate.Continues (outcome, system) -> ProcessFate.Continues (ofReturn outcome, system)
        | ProcessFate.ProcessEnded (ended, system) -> ProcessFate.ProcessEnded (ended, system)
