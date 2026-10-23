namespace WoofWare.PosixKernel.Test

open System.Reflection
open Microsoft.FSharp.Reflection

/// The name of a union value's case, as `%A` prints it first, looked up
/// rather than formatted: `%A` reflects over the union's cases on every call.
[<RequireQualifiedAccess>]
module internal UnionCaseName =

    let private flags : BindingFlags = BindingFlags.Public ||| BindingFlags.NonPublic

    type private Names<'a> () =
        static member val Tag : obj -> int =
            if not (FSharpType.IsUnion (typeof<'a>, flags)) then
                failwith $"UnionCaseName: %s{typeof<'a>.FullName} is not a union"

            FSharpValue.PreComputeUnionTagReader (typeof<'a>, flags)

        static member val Names : string[] =
            FSharpType.GetUnionCases (typeof<'a>, flags)
            |> Array.map (fun case -> case.Name)

    /// The name of `value`'s case.
    let ofValue<'a> (value : 'a) : string =
        Names<'a>.Names.[Names<'a>.Tag (box value)]
