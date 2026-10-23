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

    /// What `unfocus.Back` makes of the view `view`: never a value an answer
    /// could already hold.
    let private kernel (view : int) : string = $"kernel %d{view}"

    /// What `unfocus.Without` makes of the view `view`: never a value an
    /// answer could already hold, nor one `kernel` makes.
    let private without (view : int) : string = $"without %d{view}"

    /// What `Shape.map` makes of `answer` through `shape`, with an `unfocus`
    /// whose two halves mark each view they are given differently, beside the
    /// views they were given, in the order they were given them.
    let private mapMarked<'InView, 'InKernel>
        (shape : Shape<int, string, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel * int list
        =
        let given = ResizeArray<int> ()

        let unfocus : Unfocus<int, string> =
            {
                Back =
                    fun view ->
                        given.Add view
                        kernel view
                Without =
                    fun view ->
                        given.Add view
                        without view
            }

        let mapped = Shape.map unfocus shape answer
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

    /// What `Shape.map` makes of `answer` through `shape`, with an `unfocus`
    /// whose halves move the clock on, `Back` by one nanosecond and `Without`
    /// by two, beside each system either was given, which half it was given
    /// to, and what that made of it, in the order they were given them.
    let private mapSystems<'InView, 'InKernel>
        (shape : Shape<ProcessView<int, string>, UnixSystem<int, string>, 'InView, 'InKernel>)
        (answer : 'InView)
        : 'InKernel * (string * ProcessView<int, string> * UnixSystem<int, string>) list
        =
        let given =
            ResizeArray<string * ProcessView<int, string> * UnixSystem<int, string>> ()

        let unfocus : Unfocus<ProcessView<int, string>, UnixSystem<int, string>> =
            {
                Back =
                    fun view ->
                        let kernel = Proc.unview view |> UnixSystem.advanceClock 1L
                        given.Add ("back", view, kernel)
                        kernel
                Without =
                    fun view ->
                        let kernel = Proc.unviewWithout view |> UnixSystem.advanceClock 2L
                        given.Add ("without", view, kernel)
                        kernel
            }

        let mapped = Shape.map unfocus shape answer
        mapped, List.ofSeq given

    /// Whether `half` alone was given anything, and exactly `view`, once, and
    /// `kernel` is what it made of it.
    let private givenOnce
        (half : string)
        (view : ProcessView<int, string>)
        (kernel : UnixSystem<int, string>)
        (given : (string * ProcessView<int, string> * UnixSystem<int, string>) list)
        : bool
        =
        match given with
        | [ givenTo, given, made ] -> givenTo = half && same view given && same made kernel
        | _ -> false

    /// Whether `unfocus.Back` alone was given anything, and exactly `view`,
    /// once, and `kernel` is what it made of it.
    let private putOnce
        (view : ProcessView<int, string>)
        (kernel : UnixSystem<int, string>)
        (given : (string * ProcessView<int, string> * UnixSystem<int, string>) list)
        : bool
        =
        givenOnce "back" view kernel given

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

    /// `Shape.fate` and `Shape.ended` make the kernel without a process that
    /// ended of the view it ended in, through `unfocus.Without` alone, once,
    /// and leave how it ended beside it.
    [<Test>]
    let ``fate and ended make the kernel without an ended process`` () : unit =
        let ended, dead =
            match
                UnixThreadLifecycle.tryEndProcess (ProcessTermination.Signaled (Signal.SIGKILL, false)) (system ())
            with
            | Ok ended -> ended
            | Error refusal -> failwith $"ending the process: %s{ProcessEndRefusal.describe refusal}"

        match mapSystems Shape.fate (ViewFate.ProcessEnded (ended, dead) : ViewFate<obj, _>) with
        | ProcessFate.ProcessEnded (ended', kernel), given ->
            same ended ended' |> shouldEqual true
            givenOnce "without" dead kernel given |> shouldEqual true
        | ProcessFate.Continues _, _ -> failwith "an ended process came back continuing"

        let (ended', kernel), given = mapSystems Shape.ended (ended, dead)
        same ended ended' |> shouldEqual true
        givenOnce "without" dead kernel given |> shouldEqual true

        match mapSystems (Shape.result Shape.ended) (Ok (ended, dead) : Result<_, obj>) with
        | Ok (ended', kernel), given ->
            same ended ended' |> shouldEqual true
            givenOnce "without" dead kernel given |> shouldEqual true
        | Error _, _ -> failwith "an ended process came back an error"

    /// `Shape.ended` with views that are `int`s: what is left of each is
    /// `unfocus.Without`'s, never `unfocus.Back`'s, and how the process ended
    /// is left as it is.
    [<Test>]
    let ``ended makes what is left of the view it is given without the process`` () : unit =
        let ended : EndedProcess =
            {
                Termination = ProcessTermination.Signaled (Signal.SIGKILL, false)
                ProcessId = ProcessId.parseOrFail "TestShape" 7
            }

        let property (view : int) : unit =
            let (ended', made), given = mapMarked Shape.ended (ended, view)
            same ended ended' |> shouldEqual true
            (made, given) |> shouldEqual (without view, [ view ])

        Check.One (config, Prop.forAll (Arb.fromGen (ArbMap.defaults |> ArbMap.generate<int>)) property)

    /// `kill`'s shape and `write`'s put back the system a process carries on
    /// as, at the depth it sits, and nothing in an errno or a paused call.
    [<Test>]
    let ``fate nested as kill and write answer puts back the system it holds`` () : unit =
        let view = system ()
        let outcome = obj ()

        match
            mapSystems
                (Shape.result (Shape.result Shape.fate))
                (Ok (Ok (ViewFate.Continues (outcome, view))) : Result<Result<ViewFate<obj, _>, UnixError>, obj>)
        with
        | Ok (Ok (ProcessFate.Continues (outcome', kernel))), given ->
            same outcome outcome' |> shouldEqual true
            putOnce view kernel given |> shouldEqual true
        | other, _ -> failwith $"kill's shape answered %A{other}"

        match
            mapSystems
                (Shape.result (Shape.result Shape.fate))
                (Ok (Error UnixError.ESRCH) : Result<Result<ViewFate<obj, _>, UnixError>, obj>)
        with
        | Ok (Error UnixError.ESRCH), given -> given |> shouldBeEmpty
        | other, _ -> failwith $"kill's shape answered %A{other}"

        match
            mapSystems
                (Shape.result (Shape.progress Shape.fate))
                (Ok (CallProgress.Answered (ViewFate.Continues (outcome, view)))
                : Result<CallProgress<obj, ViewFate<obj, _>>, obj>)
        with
        | Ok (CallProgress.Answered (ProcessFate.Continues (outcome', kernel))), given ->
            same outcome outcome' |> shouldEqual true
            putOnce view kernel given |> shouldEqual true
        | other, _ -> failwith $"write's shape answered %A{other}"

        let paused = obj ()

        match
            mapSystems
                (Shape.result (Shape.progress Shape.fate))
                (Ok (CallProgress.NeedsCopyIn paused) : Result<CallProgress<obj, ViewFate<obj, _>>, obj>)
        with
        | Ok (CallProgress.NeedsCopyIn paused'), given ->
            same paused paused' |> shouldEqual true
            given |> shouldBeEmpty
        | other, _ -> failwith $"write's shape answered %A{other}"

    /// How the process `unionOfThree`'s third case says ended.
    let private exited : EndedProcess =
        {
            Termination = ProcessTermination.Signaled (Signal.SIGTERM, false)
            ProcessId = ProcessId.parseOrFail "TestShape" 7
        }

    /// A union for `Shape.union`, with a case each of whose parts a shape of
    /// its own puts back: a system beside an answer (`withSystem`), a `Result`
    /// of a system (`result system`), and what is left of a process that
    /// ended (`ended`, beside `exited`).
    let private unionOfThree
        : Shape<
              int,
              string,
              Choice<int * int, Result<int, int>, int>,
              Choice<int * string, Result<string, int>, EndedProcess * string>
           > =
        Shape.union (fun (shapes : ShapeMap<int, string>) (answer : Choice<int * int, Result<int, int>, int>) ->
            match answer with
            | Choice1Of3 pair -> Choice1Of3 (shapes.Map Shape.withSystem pair)
            | Choice2Of3 result -> Choice2Of3 (shapes.Map (Shape.result Shape.system) result)
            | Choice3Of3 view -> Choice3Of3 (shapes.Map Shape.ended (exited, view))
        )

    /// `Shape.union` puts back each case's views as the shape that case hands
    /// its part says, each once, through `Back` or `Without` as that shape
    /// does, and leaves the rest as it is.
    [<Test>]
    let ``union puts back what each case's shape says`` () : unit =
        let property (answer : Choice<int * int, Result<int, int>, int>) : unit =
            let mapped, given = mapMarked unionOfThree answer

            match answer, mapped with
            | Choice1Of3 (answer, view), Choice1Of3 pair ->
                (pair, given) |> shouldEqual ((answer, kernel view), [ view ])
            | Choice2Of3 (Ok view), Choice2Of3 result -> (result, given) |> shouldEqual (Ok (kernel view), [ view ])
            | Choice2Of3 (Error error), Choice2Of3 result -> (result, given) |> shouldEqual (Error error, [])
            | Choice3Of3 view, Choice3Of3 (ended, made) ->
                same exited ended |> shouldEqual true
                (made, given) |> shouldEqual (without view, [ view ])
            | answer, mapped -> failwith $"%A{answer} came back as another case: %A{mapped}"

        Check.One (
            config,
            Prop.forAll
                (Arb.fromGen (ArbMap.defaults |> ArbMap.generate<Choice<int * int, Result<int, int>, int>>))
                property
        )
