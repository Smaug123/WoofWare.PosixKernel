namespace WoofWare.PosixKernel.Test

open FsUnitTyped

/// Assertions cheap enough for every step of a property test: each compares
/// with F# equality, and builds its failure message, and NUnit's constraint,
/// only when the comparison fails.
[<RequireQualifiedAccess>]
module internal Expect =

    /// Fails, naming `where ()`, unless `actual` equals `expected`.
    let equal<'a when 'a : equality> (where : unit -> string) (expected : 'a) (actual : 'a) : unit =
        if actual <> expected then
            (where (), actual) |> shouldEqual (where (), expected)

    /// Fails, naming `where ()` and the elements, unless `actual` is empty.
    let empty<'a when 'a : equality> (where : unit -> string) (actual : 'a list) : unit =
        match actual with
        | [] -> ()
        | _ -> (where (), actual) |> shouldEqual (where (), [])
