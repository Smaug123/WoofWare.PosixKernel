namespace WoofWare.PosixKernel.Test

open System.Reflection
open FsUnitTyped
open Microsoft.FSharp.Reflection
open WoofWare.PosixKernel

/// A `SteppedCall`, which has no equality of its own, as a value a test can
/// compare: the name of its case, and its fields.
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
