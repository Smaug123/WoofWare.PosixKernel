namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What a write into a pipe a client drains delivers: exactly the bytes it
/// moved, to the end the pipe was launched for, in the write's own answer; and
/// none of those bytes kept in the system it leaves, so that a process that
/// writes without end does not grow the system with what it wrote.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDeliveries =

    let private platforms : SimulatedUnixPlatform list =
        [
            SimulatedUnixPlatform.linuxX64
            SimulatedUnixPlatform.linuxArm64
            SimulatedUnixPlatform.macOsArm64
        ]

    /// A process launched with its output streams drained by the client.
    let private initialOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// Writes to standard output and standard error, each of a count of bytes
    /// that crosses the pipe's capacity now and then.
    let private writesGen : Gen<SimulatedUnixPlatform * (int * int) list> =
        Gen.zip
            (Gen.elements platforms)
            (Gen.listOf (Gen.zip (Gen.elements [ 1 ; 2 ]) (Gen.choose (0, 300)))
             |> Gen.resize 30)

    /// The system after the blocking writes `writes`, each of `fd` and a
    /// count, by the leader of `initialOn platform`, the `index`th of them
    /// writing `fill index` of each position in its buffer; and what each
    /// write delivered, oldest first.
    let private written
        (platform : SimulatedUnixPlatform)
        (fill : int -> int -> byte)
        (writes : (int * int) list)
        : UnixSystem<int, string> * (ImmutableArray<byte> * Delivery option) list
        =
        ((initialOn platform, []), List.indexed writes)
        ||> List.fold (fun (system, delivered) (index, (fd, count)) ->
            let bytes = ImmutableArray.Create<byte> (Array.init count (fill index))

            match WriteOutcomes.writeDelivering fd bytes system with
            | Ok ((WriteAnswer.Completed moved, after), delivery) ->
                moved |> shouldEqual (int64 count)
                after, (bytes, delivery) :: delivered
            | other -> failwith $"write(%d{fd}, %d{count} bytes) answered %A{Result.map (fst >> fst) other}"
        )
        |> fun (system, delivered) -> system, List.rev delivered

    [<Test>]
    let ``each write to a drained stream delivers exactly the bytes it moved, to its own end`` () : unit =
        let property (platform : SimulatedUnixPlatform, writes : (int * int) list) : unit =
            let after, delivered = written platform (fun index i -> byte (index + i)) writes

            (writes, delivered)
            ||> List.iter2 (fun (fd, count) (bytes, delivery) ->
                // A write that moved no bytes delivers nothing.
                let expected =
                    if count = 0 then
                        None
                    else
                        Some
                            {
                                Endpoint = ExternalEndpoint (Lone.pid after, fd)
                                Bytes = bytes
                            }

                delivery |> shouldEqual expected
            )

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 200, Prop.forAll (Arb.fromGen writesGen) property)

    [<Test>]
    let ``the system writes to a drained stream leave holds none of the bytes they delivered`` () : unit =
        // The same writes, of the same counts and different bytes, leave the
        // same system: whatever the system keeps of a delivery, it is not its
        // bytes.
        let property (platform : SimulatedUnixPlatform, writes : (int * int) list) : unit =
            let counted, _ = written platform (fun index i -> byte (index + i + 1)) writes
            let zeroed, _ = written platform (fun _ _ -> 0uy) writes

            // NUnit's comparison walks the systems reflectively, so it is not
            // asked to describe the difference.
            if counted <> zeroed then
                failwith $"%O{platform}: writes %A{writes} of different bytes left different systems"

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 200, Prop.forAll (Arb.fromGen writesGen) property)

    /// Few endpoints and short payloads over a small alphabet, so that two
    /// generated deliveries are often equal and the equality property sees both
    /// verdicts.
    let private deliveryGen : Gen<Delivery> =
        gen {
            let! fd = Gen.elements [ 1 ; 2 ]
            let! bytes = Gen.listOf (Gen.elements [ 0uy ; 1uy ]) |> Gen.resize 3

            return
                {
                    Endpoint = ExternalEndpoint (UnixSystem.defaultProcessId, fd)
                    Bytes = ImmutableArray.CreateRange bytes
                }
        }

    [<Test>]
    let ``two deliveries are equal exactly when their ends and bytes are`` () : unit =
        // Each built over an array of its own, so that equality cannot pass by
        // comparing the arrays' identity.
        let property (left : Delivery, right : Delivery) : unit =
            let copy (delivery : Delivery) : Delivery =
                { delivery with
                    Bytes = ImmutableArray.CreateRange (Array.ofSeq delivery.Bytes)
                }

            let expected =
                left.Endpoint = right.Endpoint && List.ofSeq left.Bytes = List.ofSeq right.Bytes

            (copy left = copy right) |> shouldEqual expected

            if expected then
                hash (copy left) |> shouldEqual (hash (copy right))

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 2000,
            Prop.forAll (Arb.fromGen (Gen.zip deliveryGen deliveryGen)) property
        )
