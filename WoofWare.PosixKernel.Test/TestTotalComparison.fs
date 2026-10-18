namespace WoofWare.PosixKernel.Test

open System
open System.Collections
open System.Collections.Immutable
open System.Reflection
open FsUnitTyped
open Microsoft.FSharp.Reflection
open NUnit.Framework
open WoofWare.PosixKernel

/// A record the compiler gives structural comparison, over a field whose comparison throws.
type private ComparesImmutableArray =
    {
        Bytes : ImmutableArray<byte>
    }

/// A record the compiler gives structural comparison, over a field whose comparison is total.
type private ComparesByteString =
    {
        Name : UnixByteString
    }

/// `ImmutableArray<T>` satisfies F#'s `comparison` constraint through its
/// `IStructuralComparable`, which throws `ArgumentException` on two arrays of different
/// lengths. So a record or union the compiler gives structural comparison over such a field
/// type-checks under `compare`, `Set` and `Map`, then throws when two of its values differ in
/// an array's length. This fixture finds every record and union in the library whose generated
/// comparison reaches an `ImmutableArray`, so that each is `[<NoComparison>]` (a compile error
/// at the misuse) or has comparison of its own that is total.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestTotalComparison =

    let private comparable (ty : Type) : bool =
        typeof<IStructuralComparable>.IsAssignableFrom ty
        || typeof<IComparable>.IsAssignableFrom ty

    let private customComparison (ty : Type) : bool =
        ty.IsDefined (typeof<CustomComparisonAttribute>, false)

    /// The field types a value of `ty` compares through, if F# generates `ty`'s comparison.
    let private comparedThrough (ty : Type) : Type list option =
        if ty.IsGenericParameter || not (comparable ty) || customComparison ty then
            None
        elif ty.IsArray then
            Some [ ty.GetElementType () ]
        elif FSharpType.IsTuple ty then
            Some (List.ofArray (FSharpType.GetTupleElements ty))
        elif FSharpType.IsRecord (ty, true) then
            FSharpType.GetRecordFields (ty, true)
            |> Array.map (fun (p : PropertyInfo) -> p.PropertyType)
            |> List.ofArray
            |> Some
        elif FSharpType.IsUnion (ty, true) then
            FSharpType.GetUnionCases (ty, true)
            |> Array.collect (fun (case : UnionCaseInfo) -> case.GetFields ())
            |> Array.map (fun (p : PropertyInfo) -> p.PropertyType)
            |> List.ofArray
            |> Some
        elif
            ty.IsGenericType
            && (ty.GetGenericTypeDefinition () = typedefof<Map<int, int>>
                || ty.GetGenericTypeDefinition () = typedefof<Set<int>>)
        then
            Some (List.ofArray (ty.GetGenericArguments ()))
        else
            None

    let private isImmutableArray (ty : Type) : bool =
        ty.IsGenericType
        && ty.GetGenericTypeDefinition () = typedefof<ImmutableArray<int>>

    /// The chain of field types by which `ty`'s generated comparison reaches an
    /// `ImmutableArray`, outermost first, or `None` if it reaches none.
    let reachesImmutableArray (ty : Type) : Type list option =
        let rec go (visited : Set<string>) (path : Type list) (ty : Type) : Type list option =
            let key = ty.ToString ()

            if isImmutableArray ty then
                Some (List.rev (ty :: path))
            elif Set.contains key visited then
                None
            else

            match comparedThrough ty with
            | None -> None
            | Some fields -> fields |> List.tryPick (go (Set.add key visited) (ty :: path))

        go Set.empty [] ty

    /// The library's records and unions, without the classes F# compiles union cases into.
    let private libraryStructuralTypes : Type list =
        typeof<UnixError>.Assembly.GetTypes ()
        |> Array.filter (fun (ty : Type) ->
            FSharpType.IsRecord (ty, true)
            || (FSharpType.IsUnion (ty, true)
                && not (not (isNull ty.BaseType) && FSharpType.IsUnion (ty.BaseType, true)))
        )
        |> List.ofArray

    [<Test>]
    let ``no record or union in the library compares through an ImmutableArray`` () =
        let offenders =
            libraryStructuralTypes
            |> List.choose (fun (ty : Type) ->
                reachesImmutableArray ty
                |> Option.map (fun (path : Type list) ->
                    path |> List.map (fun (t : Type) -> t.ToString ()) |> String.concat " -> "
                )
            )
            |> List.sort

        // Spelled out rather than through `shouldEqual`, which truncates a long list.
        if not offenders.IsEmpty then
            Assert.Fail (String.concat "\n" offenders)

    /// The search would be vacuously green if it never saw the library's types.
    [<Test>]
    let ``the search sees the library's records and unions`` () =
        libraryStructuralTypes |> List.contains typeof<SeedEntry> |> shouldEqual true
        libraryStructuralTypes |> List.contains typeof<UnixError> |> shouldEqual true

    /// The failure the search stands in for, on a record it reports.
    [<Test>]
    let ``a record the search reports does throw under compare`` () =
        reachesImmutableArray typeof<ComparesImmutableArray>
        |> Option.isSome
        |> shouldEqual true

        let short =
            {
                Bytes = ImmutableArray.Create<byte> [| 1uy |]
            }

        let long =
            {
                Bytes = ImmutableArray.Create<byte> [| 1uy ; 2uy |]
            }

        Assert.Throws<ArgumentException> (fun () -> compare short long |> ignore)
        |> ignore

    /// The search does not report a field whose type defines a total comparison of its own.
    [<Test>]
    let ``a record over a byte string is not reported, and compares`` () =
        reachesImmutableArray typeof<ComparesByteString> |> shouldEqual None

        let name (s : string) : ComparesByteString =
            {
                Name =
                    match UnixByteString.ofString s with
                    | Ok name -> name
                    | Error defect -> failwith $"%A{defect}"
            }

        compare (name "a") (name "ab") |> sign |> shouldEqual -1

    /// The search follows generic instantiations, which is how a `Syscall` reaches the bytes
    /// in a `CopiedArgument<ImmutableArray<byte>>`.
    [<Test>]
    let ``the search follows type arguments`` () =
        reachesImmutableArray typeof<ImmutableArray<byte> option list>
        |> Option.isSome
        |> shouldEqual true

        reachesImmutableArray typeof<Map<int, ImmutableArray<byte> * int>>
        |> Option.isSome
        |> shouldEqual true

        reachesImmutableArray typeof<Map<int, string>> |> shouldEqual None
