namespace WoofWare.PosixKernel.Test

open System
open System.Diagnostics
open System.Reflection
open System.Reflection.Emit
open FsUnitTyped
open NUnit.Framework

/// NUnit runs a fixture with no `Parallelizable` attribute on its own, after
/// every parallel fixture has finished, so a fixture that says nothing costs CI
/// its whole duration with three cores idle. Every fixture therefore says which
/// it is: `[<Parallelizable(ParallelScope.All)>]`, or `[<NonParallelizable>]`
/// with a comment saying what it would disturb.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFixtureParallelism =

    let private fixtures : Lazy<Type[]> =
        lazy
            Assembly.GetExecutingAssembly().GetTypes ()
            |> Array.filter (fun t -> t.IsDefined (typeof<TestFixtureAttribute>, false))

    let private isParallel (fixture : Type) : bool =
        match fixture.GetCustomAttribute<ParallelizableAttribute> false with
        | null -> false
        | attribute -> attribute.Scope <> ParallelScope.None

    [<Test>]
    let ``every fixture says whether it runs in parallel`` () : unit =
        fixtures.Value.Length |> shouldBeGreaterThan 200

        fixtures.Value
        |> Array.filter (fun t -> not (t.IsDefined (typeof<ParallelizableAttribute>, false)))
        |> Array.map (fun t -> t.FullName)
        |> Array.sort
        |> shouldEqual [||]

    /// Every one-byte and two-byte IL opcode, by its value.
    let private opCodes : Lazy<Map<int, OpCode>> =
        lazy
            typeof<OpCodes>.GetFields (BindingFlags.Public ||| BindingFlags.Static)
            |> Array.map (fun (field : FieldInfo) -> field.GetValue (null : obj) :?> OpCode)
            |> Array.map (fun code -> int (uint16 code.Value), code)
            |> Map.ofArray

    let private operandSize (body : byte[]) (at : int) (operand : OperandType) : int =
        match operand with
        | OperandType.InlineNone -> 0
        | OperandType.ShortInlineBrTarget
        | OperandType.ShortInlineI
        | OperandType.ShortInlineVar -> 1
        | OperandType.InlineVar -> 2
        | OperandType.InlineI8
        | OperandType.InlineR -> 8
        | OperandType.InlineSwitch -> 4 + 4 * BitConverter.ToInt32 (body, at)
        | _ -> 4

    /// The methods `method`'s body calls or constructs through, walking its IL
    /// one instruction at a time.
    let private callees (method : MethodBase) : MethodBase list =
        match method.GetMethodBody () with
        | null -> []
        | body ->
            let il = body.GetILAsByteArray ()
            let mutable at = 0
            let found = ResizeArray<MethodBase> ()

            while at < il.Length do
                let value, width =
                    if il.[at] = 0xFEuy then
                        (0xFE00 ||| int il.[at + 1]), 2
                    else
                        int il.[at], 1

                let code =
                    match Map.tryFind value opCodes.Value with
                    | Some code -> code
                    | None -> failwith $"%s{method.DeclaringType.FullName}.%s{method.Name}: no opcode 0x%x{value}"

                at <- at + width

                if code.OperandType = OperandType.InlineMethod then
                    let token = BitConverter.ToInt32 (il, at)

                    match
                        (try
                            Some (method.Module.ResolveMethod token)
                         with :? ArgumentException ->
                             None)
                    with
                    | Some callee -> found.Add callee
                    | None -> ()

                at <- at + operandSize il at code.OperandType

            List.ofSeq found

    /// The fixture's own methods and those of every type nested in it, where
    /// F# puts the closures its tests are made of.
    let rec private methodsWithin (t : Type) : MethodBase list =
        let flags =
            BindingFlags.Public
            ||| BindingFlags.NonPublic
            ||| BindingFlags.Static
            ||| BindingFlags.Instance
            ||| BindingFlags.DeclaredOnly

        [
            yield! t.GetMethods flags |> Seq.cast<MethodBase>
            yield! t.GetConstructors flags |> Seq.cast<MethodBase>
            for nested in t.GetNestedTypes flags do
                yield! methodsWithin nested
        ]

    let private startsProcesses (fixture : Type) : bool =
        methodsWithin fixture
        |> List.exists (fun method ->
            callees method
            |> List.exists (fun callee -> callee.DeclaringType = typeof<Process> && callee.Name = "Start")
        )

    /// A child process inherits every descriptor the test host holds without
    /// close-on-exec, which includes every raw socket a host test opens
    /// through libc: a child started beside it would hold the socket's
    /// endpoint after the test closed it, and the test's next bind of that
    /// endpoint would find it taken.
    [<Test>]
    let ``no fixture that starts a process runs in parallel`` () : unit =
        let starting = fixtures.Value |> Array.filter startsProcesses

        // Not vacuous: the README's code blocks run under `dotnet fsi`.
        starting |> Array.map (fun t -> t.Name) |> shouldContain "TestReadme"

        starting
        |> Array.filter isParallel
        |> Array.map (fun t -> t.FullName)
        |> Array.sort
        |> shouldEqual [||]
