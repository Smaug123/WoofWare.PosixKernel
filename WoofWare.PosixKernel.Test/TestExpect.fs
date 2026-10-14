namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework

/// The property tests' per-step checks go through `Expect`, so a check that
/// never fails would leave every one of them green.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestExpect =

    let private failureOf (check : unit -> unit) : string =
        let exn = Assert.Throws<AssertionException> (fun () -> check ())
        exn.Message

    [<Test>]
    let ``equal passes equal values without naming where`` () : unit =
        Expect.equal (fun () -> failwith "where was asked for") [ 1 ; 2 ] [ 1 ; 2 ]

    [<Test>]
    let ``equal fails unequal values, naming where`` () : unit =
        failureOf (fun () -> Expect.equal (fun () -> "step 7") 1 2)
        |> shouldContainText "step 7"

    [<Test>]
    let ``empty passes an empty list without naming where`` () : unit =
        Expect.empty (fun () -> failwith "where was asked for") ([] : string list)

    [<Test>]
    let ``empty fails a non-empty list, naming where and the elements`` () : unit =
        let message = failureOf (fun () -> Expect.empty (fun () -> "step 7") [ "a defect" ])
        message |> shouldContainText "step 7"
        message |> shouldContainText "a defect"
