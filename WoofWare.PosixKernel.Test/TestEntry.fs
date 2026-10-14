namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A `Caller`, and `Entry`, the way into a call: which callers each requirement
/// admits, and that each shape of answer passes through untouched.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestEntry =

    let private config : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    /// What a thread named in a caller is doing, as a requirement reads it.
    [<RequireQualifiedAccess>]
    type private ThreadState =
        | Absent
        | Unparked
        | Parked

    /// Each of the systems the table runs over, with a thread in each state:
    /// the leader 0 running, 1 parked, and 7 no thread at all.
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
                |> UnixWait.park 1 ParkedSyscall.SigSuspend

            flavour, system, [ 0, ThreadState.Unparked ; 1, ThreadState.Parked ; 7, ThreadState.Absent ]
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
        | CallerRequirement.Running, ThreadState.Parked -> Some "and is making another call"
        | CallerRequirement.Returning, ThreadState.Parked -> Some "so it is not returning to user mode"
        | CallerRequirement.Woken, ThreadState.Unparked -> Some "is not parked, so there is no call to finish"
        | CallerRequirement.Running, ThreadState.Unparked
        | CallerRequirement.Returning, ThreadState.Unparked
        | CallerRequirement.Woken, ThreadState.Parked
        | CallerRequirement.Exists, ThreadState.Unparked
        | CallerRequirement.Exists, ThreadState.Parked -> None

    let private operation : string = "TestEntry.call"

    /// One way into a call: `Enter` makes the call through one of `Entry`'s
    /// functions, with a body that hands `seen` the system it is given and
    /// answers something no other call could, and says whether the function
    /// answered exactly that.
    type private Shape =
        {
            Name : string
            Enter :
                CallerRequirement -> Caller<int> -> UnixSystem<int, string> -> (UnixSystem<int, string> -> unit) -> bool
        }

    /// A system other than `system`, for a body to answer with.
    let private changed (system : UnixSystem<int, string>) : UnixSystem<int, string> = UnixSystem.advanceClock 1L system

    let private same<'T when 'T : not struct> (expected : 'T) (actual : 'T) : bool =
        obj.ReferenceEquals (expected, actual)

    let private shapes : Shape list =
        [
            {
                Name = "answer"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        Entry.answer
                            operation
                            requirement
                            caller
                            (fun system ->
                                seen system
                                sentinel
                            )
                            system
                        |> same sentinel
            }
            {
                Name = "withSystem"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let after = changed system

                        let answer, left =
                            Entry.withSystem
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
                                    sentinel, after
                                )
                                system

                        same sentinel answer && same after left
            }
            {
                Name = "result, Ok"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()
                        let after = changed system

                        match
                            Entry.result
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
                                    Ok (sentinel, after)
                                )
                                system
                        with
                        | Ok (answer, left) -> same sentinel answer && same after left
                        | Error (_ : obj) -> false
            }
            {
                Name = "result, Error"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        match
                            Entry.result
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
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
                        let after = changed system

                        match
                            Entry.fate
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
                                    ProcessFate.Continues (sentinel, after)
                                )
                                system
                        with
                        | ProcessFate.Continues (outcome, left) -> same sentinel outcome && same after left
                        | ProcessFate.ProcessEnded _ -> false
            }
            {
                Name = "fate, ProcessEnded"
                Enter =
                    fun requirement caller system seen ->
                        let ended =
                            UnixThreadLifecycle.endProcess (ProcessTermination.Signaled (Signal.SIGKILL, false)) system

                        match
                            Entry.fate
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
                                    ProcessFate.ProcessEnded ended
                                )
                                system
                        with
                        | ProcessFate.Continues ((_ : obj), _) -> false
                        | ProcessFate.ProcessEnded answered -> same ended answered
            }
            {
                Name = "progress, Answered"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        match
                            Entry.progress
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
                                    CallProgress.Answered sentinel
                                )
                                system
                        with
                        | CallProgress.Answered answer -> same sentinel answer
                        | CallProgress.NeedsCopyIn (_ : obj) -> false
            }
            {
                Name = "progress, NeedsCopyIn"
                Enter =
                    fun requirement caller system seen ->
                        let sentinel = obj ()

                        match
                            Entry.progress
                                operation
                                requirement
                                caller
                                (fun system ->
                                    seen system
                                    CallProgress.NeedsCopyIn sentinel
                                )
                                system
                        with
                        | CallProgress.Answered (_ : obj) -> false
                        | CallProgress.NeedsCopyIn paused -> same sentinel paused
            }
        ]

    /// Every requirement, through every way in, of a caller in the system's own
    /// process and in another, naming a thread in each state. A caller in
    /// another process is refused whatever its thread, before its thread is
    /// asked about; one in the system's own is refused exactly where `refusal`
    /// says. A refused call throws `InvalidOperationException`, naming the
    /// operation and why, and never runs the body; an admitted one runs it once,
    /// on the system it was given, and answers exactly what it answered.
    [<Test>]
    let ``each way in admits exactly the callers its requirement allows, and answers what the body answers`` () : unit =
        let mismatches =
            [
                for flavour, system, threads in systems () do
                    let own = Lone.pid system
                    let other = ProcessId.parse (ProcessId.toInt32 own + 1) |> Option.get

                    for shape in shapes do
                        for requirement in requirements do
                            for pid in [ own ; other ] do
                                for thread, state in threads do
                                    let case =
                                        $"%s{flavour}, %s{shape.Name}, %A{requirement}, thread %d{thread} (%A{state}) of process %O{pid}"

                                    let expected =
                                        if pid <> own then
                                            Some "but the system holds process"
                                        else
                                            refusal requirement state

                                    let seen = ResizeArray<UnixSystem<int, string>> ()

                                    let outcome =
                                        try
                                            Ok (shape.Enter requirement (Caller.make pid thread) system seen.Add)
                                        with e ->
                                            Error e

                                    match expected, outcome with
                                    | None, Ok passedThrough ->
                                        if seen.Count <> 1 || not (same system seen.[0]) then
                                            yield
                                                $"%s{case}: admitted, but the body ran %d{seen.Count} times, not once on the system given"

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
