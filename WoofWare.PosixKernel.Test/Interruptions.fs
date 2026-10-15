namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// How a call a signal interrupted ends, as the thread that made it returns to
/// user mode: the call answered `Interrupted`, and the return says whether it
/// fails with `EINTR` or restarts.
[<RequireQualifiedAccess>]
type internal Settled<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    /// The return said how the call ends, having pushed `frames` (empty for
    /// none), and left `system`.
    | Ends of
        call : InterruptedCall *
        frames : HandlerFrame<'Thread, 'Handler> list *
        system : UnixSystem<'Thread, 'Handler>
    /// The return ended the process.
    | ProcessEnded of ended : EndedProcess * system : UnixSystem<'Thread, 'Handler>
    /// The return was refused.
    | Refused of ReturnToUserRefusal

/// A thread's return to user mode after a call no signal interrupted.
[<RequireQualifiedAccess>]
module internal ReturnsToUser =

    /// The thread `caller` names, returning to user mode until it takes
    /// nothing more, every handler it takes running and returning
    /// (`handlersReturn`). Fails the test on anything else.
    let rec untilResumed<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        match UnixSignal.tryOnReturnToUser caller system with
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system)) -> system
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, None), system)) ->
            handlersReturn caller frames system
        | other -> failwith $"ReturnsToUser: returning %O{caller} to user mode: %A{other}"

    /// The handler of each of `frames`, innermost first, returning
    /// (`sigreturn`), and the thread `caller` names returning to user mode
    /// after each (`untilResumed`), as it does from a `sigreturn`: one may
    /// restore a mask that lets a pending signal through.
    and handlersReturn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (frames : HandlerFrame<'Thread, 'Handler> list)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        (system, frames)
        ||> List.fold (fun system frame -> UnixSignal.sigreturn caller frame.Id system |> untilResumed caller)

/// Translating the answers of a call a signal interrupted into the end the
/// process sees, for a test whose table states that end as a finishing call
/// once answered it: `EINTR`, or a restart.
[<RequireQualifiedAccess>]
module internal Interruptions =

    /// The thread `caller` names, whose call answered `Interrupted` in
    /// `system`, returned to user mode. Fails the test if the return says
    /// nothing of the interrupted call.
    let settle<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Settled<'Thread, 'Handler>
        =
        match UnixSignal.tryOnReturnToUser caller system with
        | Error refusal -> Settled.Refused refusal
        | Ok (ProcessFate.ProcessEnded (ended, system)) -> Settled.ProcessEnded (ended, system)
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes (Some call), system)) ->
            Settled.Ends (call, [], system)
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, Some call), system)) ->
            Settled.Ends (call, frames, system)
        | Ok other ->
            failwith
                $"Interruptions.settle: %O{caller}'s return after an interrupted call said nothing of it: %A{other}"

    /// `settle`, and then every handler the return pushed run and returned,
    /// the thread returning to user mode from each `sigreturn`
    /// (`ReturnsToUser.handlersReturn`): how the call ends, and the system as
    /// the thread next runs its own code, which for a call that restarts is
    /// the call made again. `Error` where the return is refused; fails the
    /// test where it ends the process.
    let handled<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<InterruptedCall * UnixSystem<'Thread, 'Handler>, ReturnToUserRefusal>
        =
        match settle caller system with
        | Settled.Refused refusal -> Error refusal
        | Settled.ProcessEnded _ as ended ->
            failwith $"Interruptions.handled: %O{caller}'s return ended the process: %A{ended}"
        | Settled.Ends (call, frames, system) -> Ok (call, ReturnsToUser.handlersReturn caller frames system)

    /// `settle`, for a test that expects the return to end the call: how it
    /// ends, the frames the return pushed, and the system it left.
    let ends<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : InterruptedCall * HandlerFrame<'Thread, 'Handler> list * UnixSystem<'Thread, 'Handler>
        =
        match settle caller system with
        | Settled.Ends (call, frames, system) -> call, frames, system
        | other -> failwith $"Interruptions.ends: expected %O{caller}'s return to end its call, got %A{other}"
