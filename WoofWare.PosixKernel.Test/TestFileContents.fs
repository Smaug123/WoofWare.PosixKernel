namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `FileContents` held to a naive model: the file as one byte array, and the
/// set of pages a write has filled since a truncation last cut them away.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestFileContents =

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 1000

    let private page : int = FileContents.pageSize

    [<RequireQualifiedAccess>]
    type private Op =
        | Write of offset : int64 * bytes : byte[]
        | Truncate of length : int64

        override this.ToString () : string =
            match this with
            | Op.Write (offset, bytes) ->
                $"Write (%d{offset}, %d{bytes.Length} bytes starting %A{Array.truncate 4 bytes})"
            | Op.Truncate length -> $"Truncate %d{length}"

    /// The model: the bytes, and which pages hold data.
    type private Model =
        {
            Bytes : byte[]
            Held : Set<int64>
        }

    let private pagesCovering (offset : int64) (count : int64) : Set<int64> =
        if count = 0L then
            Set.empty
        else
            Set.ofSeq (seq { offset / int64 page .. (offset + count - 1L) / int64 page })

    let private modelOf (bytes : byte[]) : Model =
        {
            Bytes = bytes
            Held = pagesCovering 0L (int64 bytes.Length)
        }

    let private applyModel (model : Model) (op : Op) : Model =
        match op with
        | Op.Write (_, [||]) -> model
        | Op.Write (offset, bytes) ->
            let offset = int offset
            let length = max model.Bytes.Length (offset + bytes.Length)
            let result = Array.zeroCreate<byte> length
            Array.blit model.Bytes 0 result 0 model.Bytes.Length
            Array.blit bytes 0 result offset bytes.Length

            {
                Bytes = result
                Held = Set.union model.Held (pagesCovering (int64 offset) (int64 bytes.Length))
            }
        | Op.Truncate length ->
            let length = int length

            {
                Bytes = Array.init length (fun i -> if i < model.Bytes.Length then model.Bytes.[i] else 0uy)
                Held = model.Held |> Set.filter (fun index -> index * int64 page < int64 length)
            }

    let private apply (contents : FileContents) (op : Op) : FileContents =
        match op with
        | Op.Write (offset, bytes) -> FileContents.write offset (ImmutableArray.CreateRange bytes) contents
        | Op.Truncate length -> FileContents.truncate length contents

    /// A position near a page boundary, near the start, or anywhere in the
    /// first few pages, so that every way a range can sit across a boundary
    /// comes up often.
    let private position : Gen<int64> =
        Gen.frequency
            [
                3,
                gen {
                    let! index = Gen.choose (0, 4)
                    let! delta = Gen.choose (-3, 3)
                    return max 0L (int64 (index * page + delta))
                }
                1, Gen.choose (0, 12) |> Gen.map int64
                1, Gen.choose (0, 5 * page) |> Gen.map int64
            ]

    /// Bytes of a length that is short, or close to a page or two: filled from
    /// a seed rather than drawn one by one, which would make the long ones slow.
    let private bytesGen : Gen<byte[]> =
        gen {
            let! length =
                Gen.frequency
                    [
                        4, Gen.choose (0, 10)
                        1, Gen.elements [ page - 1 ; page ; page + 1 ; 2 * page + 1 ]
                    ]

            let! seed = Gen.choose (0, 255)
            // Zero is a byte like any other here, so that a page a write filled
            // with zeroes is told apart from a hole by `Held` alone.
            return Array.init length (fun i -> byte ((seed + i * 7) % 256))
        }

    let private opGen : Gen<Op> =
        Gen.frequency
            [
                3,
                gen {
                    let! offset = position
                    let! bytes = bytesGen
                    return Op.Write (offset, bytes)
                }
                1, position |> Gen.map Op.Truncate
            ]

    let private caseGen : Gen<byte[] * Op list> =
        gen {
            let! initial = bytesGen
            let! ops = Gen.listOf opGen |> Gen.resize 12
            return initial, ops
        }

    let private bytesOf (contents : FileContents) : byte[] =
        FileContents.toImmutableArray contents |> Seq.toArray

    let private agrees (model : Model) (contents : FileContents) : bool =
        FileContents.invariantViolation contents = None
        && FileContents.length contents = int64 model.Bytes.Length
        && bytesOf contents = model.Bytes
        && Set.ofList (FileContents.heldPages contents) = model.Held

    [<Test>]
    let ``every write and truncation agrees with the naive model`` () : unit =
        let property (initial : byte[], ops : Op list) : bool =
            let source = ImmutableArray.CreateRange initial
            let start = FileContents.ofImmutableArray source, modelOf (Array.copy initial)

            // Every intermediate value is kept, and checked again at the end:
            // a later operation must not have changed an earlier value.
            let states =
                (start, ops)
                ||> List.scan (fun (contents, model) op -> apply contents op, applyModel model op)

            List.forall (fun (contents, model) -> agrees model contents) states
            // The file shares the array it was made from, which nothing may
            // write through.
            && Seq.toArray source = initial

        Check.One (config, Prop.forAll (Arb.fromGen caseGen) property)

    [<Test>]
    let ``a read is the naive slice`` () : unit =
        let gen =
            gen {
                let! initial, ops = caseGen
                let! offset = position
                let! count = Gen.frequency [ 3, Gen.choose (0, 10) ; 1, Gen.choose (0, 3 * page) ]
                return initial, ops, offset, count
            }

        let property (initial : byte[], ops : Op list, offset : int64, count : int) : bool =
            let contents =
                (FileContents.ofImmutableArray (ImmutableArray.CreateRange initial), ops)
                ||> List.fold apply

            let model = (modelOf initial, ops) ||> List.fold applyModel
            let read = FileContents.read offset count contents |> Seq.toArray

            let expected =
                if offset >= int64 model.Bytes.Length then
                    [||]
                else
                    Array.sub model.Bytes (int offset) (min count (model.Bytes.Length - int offset))

            read = expected

        Check.One (config, Prop.forAll (Arb.fromGen gen) property)

    /// Equal exactly when the bytes and the holes agree, and ordered
    /// consistently with that. Drawn from a small alphabet, so that two
    /// histories often reach the same value.
    [<Test>]
    let ``equality is of the bytes and the holes, and comparison agrees with it`` () : unit =
        let smallOp : Gen<Op> =
            Gen.frequency
                [
                    3,
                    gen {
                        let! offset = Gen.elements [ 0L ; 1L ; int64 page - 1L ; int64 page ; 2L * int64 page ]
                        let! bytes = Gen.elements [ [||] ; [| 0uy |] ; [| 1uy |] ; [| 0uy ; 0uy |] ]
                        return Op.Write (offset, bytes)
                    }
                    1, Gen.elements [ 0L ; 1L ; int64 page ; int64 page + 1L ] |> Gen.map Op.Truncate
                ]

        let history = Gen.listOf smallOp |> Gen.resize 4

        let property (left : Op list, right : Op list) : bool =
            let x = (FileContents.empty, left) ||> List.fold apply
            let y = (FileContents.empty, right) ||> List.fold apply

            let sameBytesAndHoles =
                bytesOf x = bytesOf y && FileContents.heldPages x = FileContents.heldPages y

            (x = y) = sameBytesAndHoles
            && (compare x y = 0) = (x = y)
            && sign (compare x y) = -sign(compare y x)
            && (x <> y || hash x = hash y)

        Check.One (config, Prop.forAll (Arb.fromGen (Gen.zip history history)) property)

    [<Test>]
    let ``a file made from an array shares it rather than copying it`` () : unit =
        let bytes = ImmutableArray.CreateRange (Array.create (16 * 1024 * 1024) 1uy)
        let before = GC.GetAllocatedBytesForCurrentThread ()
        let contents = FileContents.ofImmutableArray bytes
        let allocated = GC.GetAllocatedBytesForCurrentThread () - before

        // A Map entry for each of 4096 pages, about 3 MiB of them by insertion,
        // and none of their bytes: a copy would be more than the whole file.
        if allocated > int64 bytes.Length / 2L then
            failwith $"making a 16 MiB file from an array allocated %d{allocated} bytes"

        FileContents.length contents |> shouldEqual (int64 bytes.Length)

    [<Test>]
    let ``a write past the end leaves a hole and holds only the pages it touched`` () : unit =
        let contents =
            FileContents.empty
            |> FileContents.write (10L * int64 page + 5L) (ImmutableArray.CreateRange [ 7uy ])

        FileContents.length contents |> shouldEqual (10L * int64 page + 6L)
        FileContents.heldPages contents |> shouldEqual [ 10L ]

        FileContents.read 0L 4 contents
        |> List.ofSeq
        |> shouldEqual [ 0uy ; 0uy ; 0uy ; 0uy ]

    [<Test>]
    let ``a file can be far longer than one array`` () : unit =
        let length = 1L <<< 40

        let contents =
            FileContents.empty
            |> FileContents.truncate length
            |> FileContents.write (length - 2L) (ImmutableArray.CreateRange [ 1uy ; 2uy ])

        FileContents.length contents |> shouldEqual length

        FileContents.read (length - 3L) 8 contents
        |> List.ofSeq
        |> shouldEqual [ 0uy ; 1uy ; 2uy ]

        FileContents.invariantViolation contents |> shouldEqual None

        Assert.Throws<ArgumentException> (fun () -> FileContents.toImmutableArray contents |> ignore)
        |> ignore

    [<Test>]
    let ``a default ImmutableArray is not an empty file`` () : unit =
        Assert.Throws<ArgumentException> (fun () ->
            FileContents.ofImmutableArray Unchecked.defaultof<ImmutableArray<byte>>
            |> ignore
        )
        |> ignore

    [<Test>]
    let ``formatting shows the length and the first bytes`` () : unit =
        let contents =
            FileContents.ofImmutableArray (ImmutableArray.CreateRange [ 1uy ; 0xABuy ])

        let expected = "FileContents (2 bytes, 1 pages held: 01 ab)"
        sprintf "%A" contents |> shouldEqual expected
        string contents |> shouldEqual expected
