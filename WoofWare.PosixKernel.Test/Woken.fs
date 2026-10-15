namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Waking a parked thread before its call is finished, as a client does: only a
/// thread `UnixWait.wake` has woken may have its call finished.
[<RequireQualifiedAccess>]
module internal Woken =

    /// `system` with the thread `caller` names woken: `system` itself if that
    /// thread's park is woken already, and otherwise the system `UnixWait.wake`
    /// answers, failing the test unless that sweep wakes the thread. Every
    /// other thread the sweep wakes is woken too, as it is for a client.
    let caller<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        let state =
            UnixSystem.threads (Caller.processId caller) system
            |> Map.tryFind (Caller.thread caller)
            |> Option.bind UnixThreadState.park
            |> Option.map (fun park -> park.State)

        match state with
        | Some (ParkState.Woken _) -> system
        | Some ParkState.Asleep
        | None ->
            let woken, after = UnixWait.wake system

            if woken |> List.exists (fun (wokenCaller, _) -> wokenCaller = caller) then
                after
            else
                failwith $"Woken.caller: expected UnixWait.wake to wake %O{caller} (%A{state}), but it woke %A{woken}"

    /// `caller` of the thread `name` of the only process on the machine.
    let thread<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (name : 'Thread)
        (system : UnixSystem<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler>
        =
        caller (Callers.thread name system) system
