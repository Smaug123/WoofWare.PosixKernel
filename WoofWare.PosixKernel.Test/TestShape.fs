namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `Shape`, which says where the systems sit in a call's answer: each primitive
/// puts back exactly the systems it says sit there, each once, and changes
/// nothing else, however the primitives nest.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestShape =

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    /// What `put` makes of the view `view`: never a value an answer could
    /// already hold.
    let private kernel (view : int) : string = $"kernel %d{view}"

    /// What `Shape.map` makes of `answer` through `shape`, with a `put` that
    /// marks each view it puts back, beside the views `put` was given, in the
    /// order it was given them.
    let private mapMarked<'InView, 'InKernel>
        (shape : Shape<int, string, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel * int list
        =
        let given = ResizeArray<int> ()

        let put (view : int) : string =
            given.Add view
            kernel view

        let mapped = Shape.map put shape answer
        mapped, List.ofSeq given

    /// For every generated answer, `Shape.map` through `shape` makes what
    /// `expected` says, from the views `expected` says, in that order. The
    /// views are `int`s, so an answer whose other parts are `int`s too would
    /// show a shape that put back what it should have left.
    let private holds<'InView, 'InKernel when 'InKernel : equality>
        (shape : Shape<int, string, 'InView, 'InKernel>)
        (expected : 'InView -> 'InKernel * int list)
        : unit
        =
        let property (answer : 'InView) : unit =
            mapMarked shape answer |> shouldEqual (expected answer)

        Check.One (config, Prop.forAll (Arb.fromGen (ArbMap.defaults |> ArbMap.generate<'InView>)) property)

    /// `Shape.answer` leaves an answer as it is, even one of the view's type.
    [<Test>]
    let ``answer puts nothing back`` () : unit =
        holds Shape.answer (fun (answer : int * Result<int, int>) -> answer, [])

    /// `Shape.system` puts back the system that is the answer.
    [<Test>]
    let ``system puts back the answer`` () : unit =
        holds Shape.system (fun (view : int) -> kernel view, [ view ])

    /// `Shape.withSystem` puts back the second of a pair, and leaves the first.
    [<Test>]
    let ``withSystem puts back the system beside the answer`` () : unit =
        holds Shape.withSystem (fun ((answer, view) : int * int) -> (answer, kernel view), [ view ])

    /// `Shape.result` puts back what its `Ok` shape says, and leaves an `Error`.
    [<Test>]
    let ``result puts back what its Ok shape says and leaves an Error`` () : unit =
        holds
            (Shape.result Shape.withSystem)
            (fun (result : Result<int * int, int>) ->
                match result with
                | Ok (answer, view) -> Ok (answer, kernel view), [ view ]
                | Error error -> Error error, []
            )

    /// `Shape.progress` puts back what its answered shape says, and leaves a
    /// paused call's value, which holds its own system.
    [<Test>]
    let ``progress puts back what its answered shape says and leaves a paused value`` () : unit =
        holds
            (Shape.progress Shape.withSystem)
            (fun (progress : CallProgress<int, int * int>) ->
                match progress with
                | CallProgress.Answered (answer, view) -> CallProgress.Answered (answer, kernel view), [ view ]
                | CallProgress.NeedsCopyIn paused -> CallProgress.NeedsCopyIn paused, []
            )

    /// The primitives nest, each putting back what its own part of the answer
    /// holds.
    [<Test>]
    let ``nested shapes put back what each level says`` () : unit =
        holds
            (Shape.result (Shape.progress (Shape.result Shape.system)))
            (fun (answer : Result<CallProgress<int, Result<int, int>>, int>) ->
                match answer with
                | Ok (CallProgress.Answered (Ok view)) -> Ok (CallProgress.Answered (Ok (kernel view))), [ view ]
                | Ok (CallProgress.Answered (Error error)) -> Ok (CallProgress.Answered (Error error)), []
                | Ok (CallProgress.NeedsCopyIn paused) -> Ok (CallProgress.NeedsCopyIn paused), []
                | Error error -> Error error, []
            )

        holds
            (Shape.progress (Shape.result Shape.answer))
            (fun (answer : CallProgress<int, Result<int, int>>) -> answer, [])

    /// The view of a booted system's process, which `Shape.map` puts back as a
    /// system whose clock has moved on, so that putting one back twice, or not
    /// at all, shows.
    let private system () : ProcessView<int, string> =
        UnixSystem.initial SimulatedUnixPlatform.linuxX64
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> Lone.view

    let private same<'T when 'T : not struct> (expected : 'T) (actual : 'T) : bool =
        obj.ReferenceEquals (expected, actual)

    /// What `Shape.map` makes of `answer` through `shape`, with a `put` that
    /// moves the clock on, beside each system `put` was given and what it made
    /// of that, in the order it was given them.
    let private mapSystems<'InView, 'InKernel>
        (shape : Shape<ProcessView<int, string>, UnixSystem<int, string>, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel * (ProcessView<int, string> * UnixSystem<int, string>) list
        =
        let given = ResizeArray<ProcessView<int, string> * UnixSystem<int, string>> ()

        let put (view : ProcessView<int, string>) : UnixSystem<int, string> =
            let kernel = ProcessView.unfocus view |> UnixSystem.advanceClock 1L
            given.Add (view, kernel)
            kernel

        let mapped = Shape.map put shape answer
        mapped, List.ofSeq given

    /// Whether `put` was given exactly `view`, once, and `kernel` is what it
    /// made of it.
    let private putOnce
        (view : ProcessView<int, string>)
        (kernel : UnixSystem<int, string>)
        (given : (ProcessView<int, string> * UnixSystem<int, string>) list)
        : bool
        =
        match given with
        | [ given, made ] -> same view given && same made kernel
        | _ -> false

    /// `Shape.fate` puts back the system a process carries on as, and leaves
    /// the outcome beside it.
    [<Test>]
    let ``fate puts back the system a process continues as`` () : unit =
        let view = system ()
        let outcome = obj ()

        match mapSystems Shape.fate (ViewFate.Continues (outcome, view)) with
        | ProcessFate.Continues (outcome', kernel), given ->
            same outcome outcome' |> shouldEqual true
            putOnce view kernel given |> shouldEqual true
        | ProcessFate.ProcessEnded _, _ -> failwith "a process that continued came back ended"

    /// `Shape.fate` and `Shape.ended` leave a process that ended as it is.
    [<Test>]
    let ``fate and ended leave an ended process`` () : unit =
        let ended =
            UnixThreadLifecycle.endProcess (ProcessTermination.Signaled (Signal.SIGKILL, false)) (system ())

        match mapSystems Shape.fate (ViewFate.ProcessEnded ended : ViewFate<obj, _, _>) with
        | ProcessFate.ProcessEnded ended', given ->
            same ended ended' |> shouldEqual true
            given |> shouldBeEmpty
        | ProcessFate.Continues _, _ -> failwith "an ended process came back continuing"

        let ended', given = mapSystems Shape.ended ended
        same ended ended' |> shouldEqual true
        given |> shouldBeEmpty

    /// `kill`'s shape and `write`'s put back the system a process carries on
    /// as, at the depth it sits, and nothing in an errno or a paused call.
    [<Test>]
    let ``fate nested as kill and write answer puts back the system it holds`` () : unit =
        let view = system ()
        let outcome = obj ()

        match
            mapSystems
                (Shape.result (Shape.result Shape.fate))
                (Ok (Ok (ViewFate.Continues (outcome, view))) : Result<Result<ViewFate<obj, _, _>, UnixError>, obj>)
        with
        | Ok (Ok (ProcessFate.Continues (outcome', kernel))), given ->
            same outcome outcome' |> shouldEqual true
            putOnce view kernel given |> shouldEqual true
        | other, _ -> failwith $"kill's shape answered %A{other}"

        match
            mapSystems
                (Shape.result (Shape.result Shape.fate))
                (Ok (Error UnixError.ESRCH) : Result<Result<ViewFate<obj, _, _>, UnixError>, obj>)
        with
        | Ok (Error UnixError.ESRCH), given -> given |> shouldBeEmpty
        | other, _ -> failwith $"kill's shape answered %A{other}"

        match
            mapSystems
                (Shape.result (Shape.progress Shape.fate))
                (Ok (CallProgress.Answered (ViewFate.Continues (outcome, view)))
                : Result<CallProgress<obj, ViewFate<obj, _, _>>, obj>)
        with
        | Ok (CallProgress.Answered (ProcessFate.Continues (outcome', kernel))), given ->
            same outcome outcome' |> shouldEqual true
            putOnce view kernel given |> shouldEqual true
        | other, _ -> failwith $"write's shape answered %A{other}"

        let paused = obj ()

        match
            mapSystems
                (Shape.result (Shape.progress Shape.fate))
                (Ok (CallProgress.NeedsCopyIn paused) : Result<CallProgress<obj, ViewFate<obj, _, _>>, obj>)
        with
        | Ok (CallProgress.NeedsCopyIn paused'), given ->
            same paused paused' |> shouldEqual true
            given |> shouldBeEmpty
        | other, _ -> failwith $"write's shape answered %A{other}"
