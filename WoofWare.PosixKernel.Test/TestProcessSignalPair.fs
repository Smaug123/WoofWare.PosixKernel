namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Two signals sent to the process in a row by a thread other than the leader,
/// held to `docs/probes/process-signal-pair`: which thread runs each handler,
/// and how a `poll` the leader is asleep in ends.
///
/// There, on Linux, while the leader was asleep in `poll` with the first signal
/// still to take, the second woke the sender instead, which took both signals
/// as it returned, lowest first, unless the leader got to them first: across
/// 200 trials, the sender ran both handlers and the leader's poll restarted,
/// or the leader ran both, or each ran one. Darwin gave both to the leader.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestProcessSignalPair =

    /// What the leader does while the second thread sends.
    [<RequireQualifiedAccess>]
    type private LeaderDoes =
        /// Asleep in `poll(NULL, 0, -1)`.
        | Polls
        /// Running its own code, on processor 1.
        | Spins

    /// One configuration of the probe.
    type private Row =
        {
            Flavour : SimulatedUnixFlavour
            Leader : LeaderDoes
            /// The leader takes the first signal, and is asleep in `poll` again,
            /// before the second is sent.
            LeaderRanBetween : bool
            /// The sender blocks both signals.
            SenderBlocks : bool
            /// A third thread, which blocks neither, is asleep in `poll`.
            Idler : bool
            /// Under `LeaderDoes.Spins`, the sender runs on the leader's processor.
            SameProcessor : bool
            /// Under `LeaderDoes.Polls`, the client dispatches the leader to a
            /// processor while it is asleep, which leaves it asleep.
            DispatchedAsleep : bool
            First : Signal
            Second : Signal
        }

    let private nameOf (signal : Signal) : string =
        match signal with
        | Signal.SIGUSR1 -> "USR1"
        | Signal.SIGUSR2 -> "USR2"
        // glibc's SIGRTMIN, which the probe names RTMIN+0, is the kernel's 34.
        | Signal.RealTime offset -> $"RTMIN+%d{offset - 2}"
        | other -> failwith $"the probe sends no %O{other}"

    let private signalNamed (name : string) : Signal =
        match name with
        | "USR1" -> Signal.SIGUSR1
        | "USR2" -> Signal.SIGUSR2
        | name when name.StartsWith ("RTMIN+", StringComparison.Ordinal) ->
            Signal.RealTime (Int32.Parse (name.Substring "RTMIN+".Length) + 2)
        | name -> failwith $"the probe sends no %s{name}"

    let private leaderThread : int = 0
    let private sender : int = 1
    let private idler : int = 2

    let private who (thread : int) : string =
        if thread = leaderThread then "L"
        elif thread = sender then "T"
        else "U"

    /// The handlers `frames` start, innermost first, each followed by its
    /// `sigreturn` and the thread's return to user mode, which may push more:
    /// each handler as `<thread>:<signal>`, in the order the handlers start.
    let rec private runHandlers
        (thread : int)
        (frames : HandlerFrame<int, string> list)
        (system : UnixSystem<int, string>)
        : string list * UnixSystem<int, string>
        =
        ((List.empty, system), frames)
        ||> List.fold (fun (started, system) frame ->
            let started = started @ [ $"%s{who thread}:%s{frame.Action.Handler}" ]
            let caller = Callers.thread thread system
            let system = UnixSignal.sigreturn caller frame.Id system
            let more, system = returnRecording thread system
            started @ more, system
        )

    /// The thread's return to user mode from a call no signal interrupted,
    /// running every handler it takes.
    and private returnRecording
        (thread : int)
        (system : UnixSystem<int, string>)
        : string list * UnixSystem<int, string>
        =
        match UnixSignal.tryOnReturnToUser (Callers.thread thread system) system with
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system)) -> [], system
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, None), system)) ->
            runHandlers thread frames system
        | other -> failwith $"thread %d{thread} returning to user mode: %A{other}"

    /// The leader asleep in `poll`, woken and its call finished: `eintr` and the
    /// handlers its return ran if the poll failed with EINTR, or nothing and
    /// `asleep` if it slept on or restarted.
    let private leaderPollEnds (system : UnixSystem<int, string>) : string * string list * UnixSystem<int, string> =
        let _, system = UnixWait.wake system
        let caller = Callers.thread leaderThread system

        match
            UnixSystem.threads (Lone.pid system) system
            |> Map.find leaderThread
            |> UnixThreadState.park
        with
        | Some park when park.State = ParkState.Asleep -> "asleep", [], system
        | Some _ ->
            match UnixPoll.finishPoll caller system with
            | PollOutcome.WouldBlock _, system -> "asleep", [], system
            | PollOutcome.Interrupted, system ->
                match Interruptions.settle caller system with
                | Settled.Ends (InterruptedCall.FailsWithEintr, frames, system) ->
                    let started, system = runHandlers leaderThread frames system
                    "eintr", started, system
                | Settled.Ends (InterruptedCall.Restarts, frames, system) ->
                    let started, system = runHandlers leaderThread frames system

                    match UnixPoll.poll caller [] -1 system with
                    | PollOutcome.WouldBlock _, system -> "asleep", started, system
                    | other, _ -> failwith $"the leader's restarted poll: %A{other}"
                | other -> failwith $"the leader's interrupted poll: %A{other}"
            | other, _ -> failwith $"the leader's poll: %A{other}"
        | None -> failwith "the leader is not asleep in its poll"

    let private leaderPolls (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixPoll.poll (Callers.thread leaderThread system) [] -1 system with
        | PollOutcome.WouldBlock _, system -> system
        | other, _ -> failwith $"the leader's poll did not sleep: %A{other}"

    /// What the model says of `row`: the probe's outcome, without its `lsw=`,
    /// or `Error` of the second kill's refusal.
    let private modelled (row : Row) : Result<string, string> =
        let platform = HostPlatform.platformOf row.Flavour
        let numbering = SimulatedUnixPlatform.signalNumbering platform

        let booted =
            UnixSystem.initial platform
            |> UnixBootImage.withProcessorCount 4
            |> Launched.boot UnixSystem.pipedStandardStreams leaderThread (CpuId 0)
            |> Threads.spawn sender

        let booted = if row.Idler then Threads.spawn idler booted else booted

        let install (signal : Signal) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let action = SignalDisposition.Catch (SignalCatch.ofHandler (nameOf signal))

            match
                UnixSignal.sigaction
                    (Callers.thread leaderThread system)
                    (Signal.toRawSignoUnder numbering signal)
                    (Some action)
                    system
            with
            | SigactionAnswer.Completed _, system ->
                ReturnsToUser.untilResumed (Callers.thread leaderThread system) system
            | SigactionAnswer.Failed errno, _ -> failwith $"sigaction: %O{errno}"

        let system = booted |> install row.First |> install row.Second

        let system =
            if row.SenderBlocks then
                let mask = SignalMask.ofSignals numbering (Set.ofList [ row.First ; row.Second ])

                match
                    UnixSignal.pthreadSigmask
                        (Callers.thread sender system)
                        (MaskHow.block numbering)
                        (Some mask)
                        system
                with
                | SignalMaskAnswer.Completed _, system ->
                    ReturnsToUser.untilResumed (Callers.thread sender system) system
                | SignalMaskAnswer.Failed errno, _ -> failwith $"pthread_sigmask: %O{errno}"
            else
                system

        let system =
            if row.Idler then
                match UnixPoll.poll (Callers.thread idler system) [] -1 system with
                | PollOutcome.WouldBlock _, system -> system
                | other, _ -> failwith $"the idler's poll did not sleep: %A{other}"
            else
                system

        let system =
            match row.Leader with
            | LeaderDoes.Polls ->
                let system = leaderPolls system

                if row.DispatchedAsleep then
                    UnixScheduling.dispatch (Callers.thread leaderThread system) (CpuId 1) system
                else
                    system
            | LeaderDoes.Spins ->
                system
                |> UnixScheduling.dispatch (Callers.thread leaderThread system) (CpuId 1)
                |> UnixScheduling.dispatch
                    (Callers.thread sender system)
                    (if row.SameProcessor then CpuId 1 else CpuId 2)

        let kill (signal : Signal) (system : UnixSystem<int, string>) =
            UnixSignal.tryKill
                (Callers.thread sender system)
                (ProcessId.toInt32 (Lone.pid system))
                (Signal.toRawSignoUnder numbering signal)
                system

        match kill row.First system with
        | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) ->
            let senderStarted, system = returnRecording sender system

            let between, polls, system =
                if row.LeaderRanBetween then
                    let ending, started, system = leaderPollEnds system

                    if ending <> "eintr" then
                        failwith $"the leader's first poll ended %s{ending} before the second signal"

                    started, [ ending ], leaderPolls system
                else
                    [], [], system

            match kill row.Second system with
            | Error refusal -> Error (KillRefusal.describe refusal)
            | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) ->
                let senderAfter, system = returnRecording sender system

                let leaderStarted, polls =
                    match row.Leader with
                    | LeaderDoes.Spins -> fst (returnRecording leaderThread system), []
                    | LeaderDoes.Polls ->
                        let ending, started, _ = leaderPollEnds system
                        let polls = polls @ [ ending ]

                        // The probe's leader polls again after an EINTR, and
                        // the sender's SIGWINCH ends the poll it is asleep in.
                        let polls = if ending = "eintr" then polls @ [ "asleep" ] else polls

                        started, polls

                let handlers =
                    match senderStarted @ between @ senderAfter @ leaderStarted with
                    | [] -> "nothing"
                    | started -> String.Join (",", started)

                let polls =
                    polls
                    |> List.mapi (fun i ending ->
                        let ending = if ending = "asleep" then "woken" else ending
                        $" poll%d{i + 1}=%s{ending}"
                    )
                    |> String.concat ""

                Ok (handlers + polls)
            | Ok other -> failwith $"the second kill: %A{other}"
        | other -> failwith $"the first kill: %A{other}"

    let private resource (flavour : SimulatedUnixFlavour) : string =
        match flavour with
        | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.process-signal-pair.linux.txt"
        | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.process-signal-pair.darwin.txt"

    [<Literal>]
    let private RowPattern =
        @"^leader=(poll|spin) gap=(none|ran) others=(T|T-blocks|T-blocks\+U) cpus=(free|same|apart) A=(\S+) B=(\S+) count=(\d+)/(\d+) outcome: (.*)$"

    /// Every configuration of one flavour's output, with each outcome measured
    /// and how many trials gave it, most first, summed over the placements the
    /// model does not distinguish. An outcome whose child was killed (`end=`)
    /// is left out.
    let private measured (flavour : SimulatedUnixFlavour) : (Row * (string * int) list) list =
        let name = resource flavour

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))
        |> List.map (fun line ->
            let m = Regex.Match (line, RowPattern)

            if not m.Success then
                failwith $"%s{name}: unrecognised row: %s{line}"

            let row =
                {
                    Flavour = flavour
                    Leader =
                        if m.Groups.[1].Value = "poll" then
                            LeaderDoes.Polls
                        else
                            LeaderDoes.Spins
                    LeaderRanBetween = m.Groups.[2].Value = "ran"
                    SenderBlocks = m.Groups.[3].Value <> "T"
                    Idler = m.Groups.[3].Value = "T-blocks+U"
                    // A sleeping leader runs nowhere, so where the probe pinned
                    // the threads changes nothing the model is told, and the
                    // placements' outcomes are counted together.
                    SameProcessor = m.Groups.[1].Value = "spin" && m.Groups.[4].Value = "same"
                    DispatchedAsleep = false
                    First = signalNamed m.Groups.[5].Value
                    Second = signalNamed m.Groups.[6].Value
                }

            let outcome = Regex.Replace(m.Groups.[9].Value, @" lsw=\d+", "").Trim ()
            row, (outcome, Int32.Parse m.Groups.[7].Value)
        )
        |> List.filter (fun (_, (outcome, _)) -> not (outcome.Contains "end="))
        |> List.groupBy fst
        |> List.map (fun (row, outcomes) ->
            let summed =
                outcomes
                |> List.map snd
                |> List.groupBy fst
                |> List.map (fun (outcome, counts) -> outcome, List.sumBy snd counts)
                |> List.sortByDescending snd

            row, summed
        )

    /// Whether a thread other than the leader ran a handler in `outcome`.
    let private beyondLeader (outcome : string) : bool =
        outcome.Contains "T:" || outcome.Contains "U:"

    let private replay (flavour : SimulatedUnixFlavour) : int * int =
        let rows = measured flavour
        rows |> List.isEmpty |> shouldEqual false
        let mutable answered = 0
        let mutable refused = 0

        for row, outcomes in rows do
            match modelled row with
            | Ok outcome ->
                // The model answers one interleaving: the leader takes what it
                // takes after both kills (or between them, where the row says so).
                // The probe's most frequent outcome is that interleaving's.
                if outcome <> fst (List.head outcomes) then
                    failwith $"%A{row}: the model answers %s{outcome}, where the probe measured %A{outcomes}"

                answered <- answered + 1
            | Error refusal ->
                if not (outcomes |> List.exists (fun (outcome, _) -> beyondLeader outcome)) then
                    failwith
                        $"%A{row}: the model refuses (%s{refusal}), where the probe's leader ran every handler: %A{outcomes}"

                refused <- refused + 1

        answered, refused

    [<Test>]
    let ``Linux: every configuration measured is answered as the probe's leader took it, or refused where another thread took a signal``
        ()
        =
        let answered, refused = replay SimulatedUnixFlavour.Linux
        // Every configuration in which the sender, or the idler, ran a handler.
        refused |> shouldBeGreaterThan 0
        answered |> shouldBeGreaterThan 0

    [<Test>]
    let ``Darwin: every configuration measured is answered as the probe's leader took it`` () =
        let answered, refused = replay SimulatedUnixFlavour.Darwin
        refused |> shouldEqual 0
        answered |> shouldBeGreaterThan 0

    [<TestCase false>]
    [<TestCase true>]
    let ``Linux: a second signal sent to the process while the asleep leader has the first to take is refused``
        (dispatchedAsleep : bool)
        =
        let row =
            {
                Flavour = SimulatedUnixFlavour.Linux
                Leader = LeaderDoes.Polls
                LeaderRanBetween = false
                SenderBlocks = false
                Idler = false
                SameProcessor = false
                DispatchedAsleep = dispatchedAsleep
                First = Signal.SIGUSR1
                Second = Signal.SIGUSR2
            }

        match modelled row with
        | Error refusal -> refusal |> shouldContainText "SIGUSR2"
        | Ok outcome -> failwith $"expected the second kill to be refused; the model answered %s{outcome}"
