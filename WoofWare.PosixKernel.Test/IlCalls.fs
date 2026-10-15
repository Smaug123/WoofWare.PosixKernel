namespace WoofWare.PosixKernel.Test

open System
open System.Reflection
open System.Reflection.Emit

/// What a method's body calls, read from its IL one instruction at a time.
[<RequireQualifiedAccess>]
module internal IlCalls =

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

    /// The methods `method`'s body calls, constructs through or takes a
    /// pointer to, each resolved in the generic context of `method` and of the
    /// type that declares it; `Error` describes a method token that does not
    /// resolve there.
    let callees (method : MethodBase) : Result<MethodBase, string> list =
        match method.GetMethodBody () with
        | null -> []
        | body ->
            let il = body.GetILAsByteArray ()

            let typeArguments =
                if method.DeclaringType.IsGenericType then
                    method.DeclaringType.GetGenericArguments ()
                else
                    null

            let methodArguments =
                if method.IsGenericMethod then
                    method.GetGenericArguments ()
                else
                    null

            let mutable at = 0
            let found = ResizeArray<Result<MethodBase, string>> ()

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

                    try
                        found.Add (Ok (method.Module.ResolveMethod (token, typeArguments, methodArguments)))
                    with :? ArgumentException as e ->
                        found.Add (
                            Error
                                $"%s{method.DeclaringType.FullName}.%s{method.Name}: token 0x%08x{token} does not resolve: %s{e.Message}"
                        )

                at <- at + operandSize il at code.OperandType

            List.ofSeq found

    /// The methods and constructors `t` declares and those of every type
    /// nested in it, where F# puts the closures a function is made of.
    let rec methodsWithin (t : Type) : MethodBase list =
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
