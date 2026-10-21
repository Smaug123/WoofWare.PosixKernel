namespace WoofWare.PosixKernel.Test

open System.Reflection
open FsUnitTyped
open Microsoft.FSharp.Reflection
open WoofWare.PosixKernel

/// A `SteppedCall`, which has no equality of its own, as a value a test can
/// compare: the name of its case, and its fields; and what it says of the
/// process and the system it left.
[<RequireQualifiedAccess>]
module internal Stepped =

    /// The name of `stepped`'s case, and its fields in order, each compared by
    /// F#'s structural equality.
    let view<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (stepped : SteppedCall<'Thread, 'Handler>)
        : string * obj list
        =
        let case, fields =
            FSharpValue.GetUnionFields (stepped, typeof<SteppedCall<'Thread, 'Handler>>, BindingFlags.Public)

        case.Name, List.ofArray fields

    /// Fails unless `actual` is `expected`: the same case, holding equal fields.
    let shouldBe<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (expected : SteppedCall<'Thread, 'Handler>)
        (actual : SteppedCall<'Thread, 'Handler>)
        : unit
        =
        view actual |> shouldEqual (view expected)

    /// As `shouldBe`, of what `UnixSystem.tryStep` answers: the same refusal, or
    /// the same case holding equal fields.
    let resultShouldBe<'Thread, 'Handler, 'Refusal
        when 'Thread : comparison and 'Handler : equality and 'Refusal : equality>
        (expected : Result<SteppedCall<'Thread, 'Handler>, 'Refusal>)
        (actual : Result<SteppedCall<'Thread, 'Handler>, 'Refusal>)
        : unit
        =
        Result.map view actual |> shouldEqual (Result.map view expected)

    /// The `SyscallAnswer` `stepped` holds, with the system beside it where its
    /// case holds one; `None` for a case that holds no `SyscallAnswer`.
    let syscallAnswer<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (stepped : SteppedCall<'Thread, 'Handler>)
        : (SyscallAnswer * UnixSystem<'Thread, 'Handler> option) option
        =
        match view stepped with
        | _, [ :? SyscallAnswer as answer ] -> Some (answer, None)
        | _, [ :? SyscallAnswer as answer ; :? UnixSystem<'Thread, 'Handler> as system ] -> Some (answer, Some system)
        | _ -> None

    /// Every system `stepped` holds, found by walking its fields and the
    /// fields of every union and tuple among them: what `SteppedCall.system`
    /// answers, by a route that names no case.
    let heldSystems<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (stepped : SteppedCall<'Thread, 'Handler>)
        : UnixSystem<'Thread, 'Handler> list
        =
        let rec walk (value : obj) : UnixSystem<'Thread, 'Handler> list =
            match value with
            | null -> []
            | :? UnixSystem<'Thread, 'Handler> as system -> [ system ]
            | _ ->
                let t = value.GetType ()

                if FSharpType.IsTuple t then
                    FSharpValue.GetTupleFields value |> List.ofArray |> List.collect walk
                elif FSharpType.IsUnion (t, true) then
                    let _, fields = FSharpValue.GetUnionFields (value, t, true)
                    fields |> List.ofArray |> List.collect walk
                else
                    []

        walk (box stepped)

    /// The system `caller`'s call left, if its thread is not asleep in it and
    /// its process carries on: `SteppedCall.system` of `madeIn`, the system the
    /// call was made in.
    let carriedOn
        (caller : Caller<int>)
        (madeIn : UnixSystem<int, string>)
        (stepped : SteppedCall<int, string>)
        : UnixSystem<int, string> option
        =
        let system = SteppedCall.system madeIn stepped
        let pid = Caller.processId caller

        if not (Set.contains pid (UnixSystem.processIds system)) then
            None
        else
            match Map.tryFind (Caller.thread caller) (UnixSystem.threads pid system) with
            | Some state when Option.isSome (UnixThreadState.park state) -> None
            | Some _
            | None -> Some system

    /// Whether `stepped` is the end of the calling process: the call's
    /// `ProcessFate.ProcessEnded`, or an `exit_group`'s.
    let endsProcess (stepped : SteppedCall<int, string>) : bool =
        match stepped with
        | SteppedCall.Kill (ProcessFate.ProcessEnded _)
        | SteppedCall.PthreadKill (ProcessFate.ProcessEnded _)
        | SteppedCall.ExitThread (ProcessFate.ProcessEnded _)
        | SteppedCall.ExitGroup _ -> true
        | _ -> false

    /// Whether `stepped` is a call a signal interrupted as it was made.
    let interrupted (stepped : SteppedCall<int, string>) : bool =
        match stepped with
        | SteppedCall.SigSuspend (SigsuspendOutcome.Interrupted, _)
        | SteppedCall.RtSigSuspend (SigsuspendOutcome.Interrupted, _)
        | SteppedCall.Pause (SigsuspendOutcome.Interrupted, _) -> true
        | _ -> false
