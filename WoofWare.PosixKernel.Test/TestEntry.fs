namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A `Caller`, and `Entry`, the way into a call: which callers each requirement
/// admits, and that a call answers what its body gave, in each shape of
/// answer.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestEntry =

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    /// What a thread named in a caller is doing, as a requirement reads it.
    [<RequireQualifiedAccess>]
    type private ThreadState =
        | Absent
        | Unparked
        /// Parked, and asleep.
        | Asleep
        /// Parked, and woken.
        | Woken

    /// Each of the systems the table runs over, with a thread in each state:
    /// the leader 0 running, 1 parked and asleep, 2 parked and woken, and 7 no
    /// thread at all.
    let private systems () : (string * UnixSystem<int, string> * (int * ThreadState) list) list =
        [
            "Linux", SimulatedUnixPlatform.linuxX64
            "Darwin", SimulatedUnixPlatform.macOsArm64
        ]
        |> List.map (fun (flavour, platform) ->
            let system =
                UnixSystem.initial platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
                |> Threads.spawn 1
                |> Threads.spawn 2
                |> Lone.UnixWait.park 1 ParkedSyscall.SigSuspend
                |> Lone.UnixWait.park 2 ParkedSyscall.SigSuspend
                |> ForgedPark.woken 2

            flavour,
            system,
            [
                0, ThreadState.Unparked
                1, ThreadState.Asleep
                2, ThreadState.Woken
                7, ThreadState.Absent
            ]
        )

    let private requirements : CallerRequirement list =
        [
            CallerRequirement.Running
            CallerRequirement.Woken
            CallerRequirement.Returning
            CallerRequirement.Exists
        ]

    /// What the message says when `requirement` refuses a thread in `state` of
    /// the system's own process, or `None` if it admits it.
    let private refusal (requirement : CallerRequirement) (state : ThreadState) : string option =
        match requirement, state with
        | _, ThreadState.Absent -> Some "is not one of the process's threads"
        | CallerRequirement.Running, ThreadState.Asleep
        | CallerRequirement.Running, ThreadState.Woken -> Some "and is making another call"
        | CallerRequirement.Returning, ThreadState.Asleep
        | CallerRequirement.Returning, ThreadState.Woken -> Some "so it is not returning to user mode"
        | CallerRequirement.Woken, ThreadState.Unparked -> Some "is not parked, so there is no call to finish"
        | CallerRequirement.Woken, ThreadState.Asleep -> Some "and nothing has woken it"
        | CallerRequirement.Running, ThreadState.Unparked
        | CallerRequirement.Returning, ThreadState.Unparked
        | CallerRequirement.Woken, ThreadState.Woken
        | CallerRequirement.Exists, ThreadState.Unparked
        | CallerRequirement.Exists, ThreadState.Asleep
        | CallerRequirement.Exists, ThreadState.Woken -> None

    let private operation : string = "TestEntry.call"

    /// One way into a call: `Enter` makes the call through `Entry.call` with
    /// one shape, with a body that hands `seen` the view it is given and
    /// answers something no other call could, and says whether the call
    /// answered exactly that, each view in it put back into the kernel.
    type private Way =
        {
            Name : string
            Enter :
                CallerRequirement
                    -> Caller<int>
                    -> UnixSystem<int, string>
                    -> (ProcessView<int, string> -> unit)
                    -> bool
        }

    /// A view other than `view`, for a body to answer with.
    let private changed (view : ProcessView<int, string>) : ProcessView<int, string> =
        { view with
            Scheduling = UnixSchedulingState.advanceClock 1L view.Scheduling
        }

    let private same<'T when 'T : not struct> (expected : 'T) (actual : 'T) : bool =
        obj.ReferenceEquals (expected, actual)

    /// Whether `left` is the kernel `answered`, the view a body answered with,
    /// puts back into: a new value, with the view's process and machine.
    let private putBack (answered : ProcessView<int, string> option ref) (left : UnixSystem<int, string>) : bool =
        match answered.Value with
        | Some view -> left = ProcessView.unfocus view
        | None -> false

    /// The process `view` is the view of, ended: how, and the view of it with
    /// no thread or descriptor left.
    let private ended (view : ProcessView<int, string>) : EndedProcess * ProcessView<int, string> =
        match UnixThreadLifecycle.tryEndProcess (ProcessTermination.Signaled (Signal.SIGKILL, false)) view with
        | Ok ended -> ended
        | Error refusal -> failwith $"ending the process: %s{ProcessEndRefusal.describe refusal}"

    /// Whether `left` is the kernel `answered`, the view a body answered as
    /// its process ended, leaves without that process.
    let private leftWithout
        (answered : (EndedProcess * ProcessView<int, string>) option ref)
        (ended : EndedProcess)
        (left : UnixSystem<int, string>)
        : bool
        =
        match answered.Value with
        | Some (answeredEnded, dead) ->
            same answeredEnded ended
            && left = ProcessView.unfocusWithout dead
            && not (Set.contains (EndedProcess.processId ended) (UnixSystem.processIds left))
        | None -> false

    let private ways : Way list =
        [
            {
                Name = "answer"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        Entry.call
                            operation
                            requirement
                            caller
                            Shape.answer
                            (fun view ->
                                seen view
                                sentinel
                            )
                            system
                        |> same sentinel
            }
            {
                Name = "system"
                Enter =
                    fun requirement caller system seen ->
                        let answered = ref None

                        Entry.call
                            operation
                            requirement
                            caller
                            Shape.system
                            (fun view ->
                                seen view
                                answered.Value <- Some (changed view)
                                answered.Value.Value
                            )
                            system
                        |> putBack answered
            }
            {
                Name = "system, unchanged"
                Enter =
                    fun requirement caller system seen ->
                        Entry.call
                            operation
                            requirement
                            caller
                            Shape.system
                            (fun view ->
                                seen view
                                view
                            )
                            system
                        |> same system
            }
            {
                Name = "withSystem"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let answered = ref None

                        let answer, left =
                            Entry.call
                                operation
                                requirement
                                caller
                                Shape.withSystem
                                (fun view ->
                                    seen view
                                    answered.Value <- Some (changed view)
                                    sentinel, answered.Value.Value
                                )
                                system

                        same sentinel answer && putBack answered left
            }
            {
                Name = "result withSystem, Ok"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let answered = ref None

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                (Shape.result Shape.withSystem)
                                (fun view ->
                                    seen view
                                    answered.Value <- Some (changed view)
                                    Ok (sentinel, answered.Value.Value)
                                )
                                system
                        with
                        | Ok (answer, left) -> same sentinel answer && putBack answered left
                        | Error (_ : obj) -> false
            }
            {
                Name = "result withSystem, Error"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                (Shape.result Shape.withSystem)
                                (fun view ->
                                    seen view
                                    Error sentinel
                                )
                                system
                        with
                        | Ok ((_ : obj), _) -> false
                        | Error error -> same sentinel error
            }
            {
                Name = "fate, Continues"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let answered = ref None

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                Shape.fate
                                (fun view ->
                                    seen view
                                    answered.Value <- Some (changed view)
                                    ViewFate.Continues (sentinel, answered.Value.Value)
                                )
                                system
                        with
                        | ProcessFate.Continues (outcome, left) -> same sentinel outcome && putBack answered left
                        | ProcessFate.ProcessEnded _ -> false
            }
            {
                Name = "fate, ProcessEnded"
                Enter =
                    fun requirement caller system seen ->
                        let answered = ref None

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                Shape.fate
                                (fun view ->
                                    seen view
                                    answered.Value <- Some (ended view)
                                    ViewFate.ProcessEnded answered.Value.Value
                                )
                                system
                        with
                        | ProcessFate.Continues ((_ : obj), _) -> false
                        | ProcessFate.ProcessEnded (ended, left) -> leftWithout answered ended left
            }
            {
                Name = "ended"
                Enter =
                    fun requirement caller system seen ->
                        let answered = ref None

                        Entry.call
                            operation
                            requirement
                            caller
                            Shape.ended
                            (fun view ->
                                seen view
                                answered.Value <- Some (ended view)
                                answered.Value.Value
                            )
                            system
                        |> fun (ended, left) -> leftWithout answered ended left
            }
            {
                Name = "progress withSystem, Answered"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let answered = ref None

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                (Shape.progress Shape.withSystem)
                                (fun view ->
                                    seen view
                                    answered.Value <- Some (changed view)
                                    CallProgress.Answered (sentinel, answered.Value.Value)
                                )
                                system
                        with
                        | CallProgress.Answered (answer, left) -> same sentinel answer && putBack answered left
                        | CallProgress.NeedsCopyIn (_ : obj) -> false
            }
            {
                Name = "progress withSystem, NeedsCopyIn"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                (Shape.progress Shape.withSystem)
                                (fun view ->
                                    seen view
                                    CallProgress.NeedsCopyIn sentinel
                                )
                                system
                        with
                        | CallProgress.Answered ((_ : obj), _) -> false
                        | CallProgress.NeedsCopyIn paused -> same sentinel paused
            }
            {
                Name = "result (result fate), as kill answers"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let answered = ref None

                        match
                            Entry.call
                                operation
                                requirement
                                caller
                                (Shape.result (Shape.result Shape.fate))
                                (fun view ->
                                    seen view
                                    answered.Value <- Some (changed view)
                                    Ok (Ok (ViewFate.Continues (sentinel, answered.Value.Value)))
                                )
                                system
                        with
                        | Ok (Ok (ProcessFate.Continues (outcome, left))) ->
                            same sentinel outcome && putBack answered left
                        | Ok (Ok (ProcessFate.ProcessEnded _))
                        | Ok (Error (_ : UnixError))
                        | Error (_ : obj) -> false
            }
        ]

    /// Every requirement, through `Entry.call` with every shape, of a caller in
    /// the system's own process and in one it does not hold, naming a thread in
    /// each state. A caller in a process the system does not hold is refused
    /// whatever its thread, before its thread is asked about; one in the
    /// system's own is refused exactly where `refusal` says. A refused call
    /// throws `InvalidOperationException`, naming the operation and why, and
    /// never runs the body; an admitted one runs it once, on the view of the
    /// caller's process, and answers exactly what it answered, each view put
    /// back.
    [<Test>]
    let ``each way in admits exactly the callers its requirement allows, and answers what the body answers`` () : unit =
        let mismatches =
            [
                for flavour, system, threads in systems () do
                    let own = Lone.pid system
                    let other = ProcessId.parse (ProcessId.toInt32 own + 1) |> Option.get

                    for way in ways do
                        for requirement in requirements do
                            for pid in [ own ; other ] do
                                for thread, state in threads do
                                    let case =
                                        $"%s{flavour}, %s{way.Name}, %A{requirement}, thread %d{thread} (%A{state}) of process %O{pid}"

                                    let expected =
                                        if pid <> own then
                                            Some "but the system holds no process"
                                        else
                                            refusal requirement state

                                    let seen = ResizeArray<ProcessView<int, string>> ()

                                    let outcome =
                                        try
                                            Ok (way.Enter requirement (Caller.make pid thread) system seen.Add)
                                        with e ->
                                            Error e

                                    match expected, outcome with
                                    | None, Ok passedThrough ->
                                        if seen.Count <> 1 || seen.[0] <> Proc.view own system then
                                            yield
                                                $"%s{case}: admitted, but the body ran %d{seen.Count} times, not once on the view of the caller's process"

                                        if not passedThrough then
                                            yield $"%s{case}: admitted, but did not answer what the body answered"
                                    | None, Error e ->
                                        yield $"%s{case}: expected admission, threw %s{e.GetType().Name}: %s{e.Message}"
                                    | Some reason, Ok _ ->
                                        yield $"%s{case}: expected refusal (%s{reason}), was admitted"
                                    | Some reason, Error e ->
                                        if e.GetType () <> typeof<InvalidOperationException> then
                                            yield
                                                $"%s{case}: threw %s{e.GetType().Name}, not InvalidOperationException: %s{e.Message}"
                                        elif not (e.Message.Contains operation && e.Message.Contains reason) then
                                            yield
                                                $"%s{case}: refused, but the message does not name the operation and say %s{reason}: %s{e.Message}"

                                        if seen.Count <> 0 then
                                            yield $"%s{case}: refused, but the body ran %d{seen.Count} times"
            ]

        mismatches |> shouldEqual []

    /// A resumed call answers what its resumption gave, with each view in it
    /// put back into the kernel as the resumption left it, in every shape a
    /// resumption answers.
    [<Test>]
    let ``a resumed call answers what its resumption gave`` () : unit =
        for flavour, system, _ in systems () do
            let sentinel = obj ()
            let leader = Lone.leader system
            let after = changed (Lone.view system)
            let answered = ref (Some after)
            let ended = ended (Lone.view system)

            let answers : (string * bool) list =
                [
                    "withSystem",
                    (let answer, left = Entry.resume leader Shape.withSystem (sentinel, after)
                     same sentinel answer && putBack answered left)

                    "result (progress withSystem), Answered",
                    (match
                        Entry.resume
                            leader
                            (Shape.result (Shape.progress Shape.withSystem))
                            (Ok (CallProgress.Answered (sentinel, after)))
                     with
                     | Ok (CallProgress.Answered (answer, left)) -> same sentinel answer && putBack answered left
                     | Ok (CallProgress.NeedsCopyIn (_ : obj))
                     | Error (_ : obj) -> false)

                    "result (progress withSystem), NeedsCopyIn",
                    (match
                        Entry.resume
                            leader
                            (Shape.result (Shape.progress Shape.withSystem))
                            (Ok (CallProgress.NeedsCopyIn sentinel)
                            : Result<CallProgress<obj, obj * ProcessView<int, string>>, obj>)
                     with
                     | Ok (CallProgress.NeedsCopyIn paused) -> same sentinel paused
                     | Ok (CallProgress.Answered ((_ : obj), _))
                     | Error (_ : obj) -> false)

                    "result fate, Continues",
                    (match
                        Entry.resume leader (Shape.result Shape.fate) (Ok (ViewFate.Continues (sentinel, after)))
                     with
                     | Ok (ProcessFate.Continues (outcome, left)) -> same sentinel outcome && putBack answered left
                     | Ok (ProcessFate.ProcessEnded _)
                     | Error (_ : obj) -> false)

                    "result fate, ProcessEnded",
                    (match Entry.resume leader (Shape.result Shape.fate) (Ok (ViewFate.ProcessEnded ended)) with
                     | Ok (ProcessFate.ProcessEnded (answered, left)) -> leftWithout (ref (Some ended)) answered left
                     | Ok (ProcessFate.Continues ((_ : obj), _))
                     | Error (_ : obj) -> false)
                ]

            answers
            |> List.filter (snd >> not)
            |> List.map (fun (name, _) -> $"%s{flavour}, %s{name}")
            |> shouldEqual []

    let private callerParts : Gen<int32 * int> =
        Gen.zip (Gen.choose (1, Int32.MaxValue)) (ArbMap.defaults |> ArbMap.generate<int>)

    /// A caller is its process and its thread: each reads back as it was made.
    [<Test>]
    let ``a caller reads back the process and thread it was made of`` () : unit =
        let property (pid : int32, thread : int) : unit =
            let caller = Caller.make (ProcessId.parse pid |> Option.get) thread
            ProcessId.toInt32 (Caller.processId caller) |> shouldEqual pid
            Caller.thread caller |> shouldEqual thread

        Check.One (config, Prop.forAll (Arb.fromGen callerParts) property)

    /// Two callers are equal, and order, as their (process, thread) pairs do.
    [<Test>]
    let ``callers compare as their process and thread pairs do`` () : unit =
        // Small ranges, so that equal processes and equal threads are common.
        let small : Gen<int32 * int> = Gen.zip (Gen.choose (1, 3)) (Gen.choose (-2, 2))

        let property ((pid, thread) : int32 * int, (pid', thread') : int32 * int) : unit =
            let caller = Caller.make (ProcessId.parse pid |> Option.get) thread
            let caller' = Caller.make (ProcessId.parse pid' |> Option.get) thread'
            (caller = caller') |> shouldEqual ((pid, thread) = (pid', thread'))

            compare caller caller'
            |> sign
            |> shouldEqual (compare (pid, thread) (pid', thread') |> sign)

            (hash caller = hash caller' || caller <> caller') |> shouldEqual true

        Check.One (config, Prop.forAll (Arb.fromGen (Gen.zip small small)) property)
