namespace WoofWare.PosixKernel.Test

open System
open System.Reflection
open FsUnitTyped
open Microsoft.FSharp.Reflection
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnionCaseName.ofValue` stands in for the first word of `%A`, so the two
/// must agree on every case of every union it is asked about.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnionCaseName =

    let private flags : BindingFlags = BindingFlags.Public ||| BindingFlags.NonPublic

    /// One value of each of the union's cases, each field its type's default.
    let private everyCase<'a when 'a : equality> () : 'a list =
        FSharpType.GetUnionCases (typeof<'a>, flags)
        |> Array.map (fun case ->
            let fields =
                case.GetFields ()
                |> Array.map (fun field ->
                    if field.PropertyType.IsValueType then
                        Activator.CreateInstance field.PropertyType
                    else
                        null
                )

            FSharpValue.MakeUnion (case, fields, flags) :?> 'a
        )
        |> List.ofArray

    let private agreesWithFormatting<'a when 'a : equality> () : unit =
        let values = everyCase<'a> ()
        values |> shouldNotEqual []

        for value in values do
            UnionCaseName.ofValue value
            |> shouldEqual ((sprintf "%A" value).Split([| ' ' ; '\n' |]).[0])

    [<Test>]
    let ``every UnixError's name is the first word %A prints`` () : unit = agreesWithFormatting<UnixError> ()

    [<Test>]
    let ``every WakePrimitive's name is the first word %A prints`` () : unit = agreesWithFormatting<WakePrimitive> ()

    [<Test>]
    let ``every BindRefusal's name is the first word %A prints`` () : unit = agreesWithFormatting<BindRefusal> ()

    [<Test>]
    let ``every ConnectRefusal's name is the first word %A prints`` () : unit = agreesWithFormatting<ConnectRefusal> ()

    [<Test>]
    let ``every FcntlOp's name is the first word %A prints`` () : unit = agreesWithFormatting<FcntlOp> ()

    [<Test>]
    let ``a type that is no union is refused`` () : unit =
        Assert.Throws<TypeInitializationException> (fun () -> UnionCaseName.ofValue 3 |> ignore)
        |> ignore
