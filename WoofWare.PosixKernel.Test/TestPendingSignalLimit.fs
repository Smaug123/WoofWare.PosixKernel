namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Linux's `RLIMIT_SIGPENDING`, held to `docs/probes/rt-queue-limit`: the
/// signals queued for a process's real user, in all that user's processes, are
/// counted against the receiving process's limit; past it, `kill` queues a
/// standard signal anyway and keeps a real-time one as the bare pending bit
/// (or loses it beside an instance of its signal), and `pthread_kill` keeps a
/// standard signal as the bare bit and fails a real-time one with `EAGAIN`. A
/// bare instance counts against nothing, and an allocated instance of its
/// signal arriving in its set replaces it.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPendingSignalLimit =

    // ---------------- The queue against a reference ---------------- //

    /// The reference: Linux's own representation of a pending set, a bit per
    /// signal and a list of allocated entries, each charged to a user.
    type private Reference =
        {
            Bits : Set<int voption * Signal>
            /// Every allocated entry, in the order allocated: its set, signal and user.
            Entries : (int voption * Signal * UserId) list
        }

    let private referenceEmpty : Reference =
        {
            Bits = Set.empty
            Entries = []
        }

    /// The instances the reference holds for one set and signal, as the model
    /// states them.
    let private referenceInstances (r : Reference) (key : int voption * Signal) : PendingCharge list =
        let entries =
            r.Entries
            |> List.choose (fun (target, signal, user) ->
                if (target, signal) = key then
                    Some (PendingCharge.Charged user)
                else
                    None
            )

        match entries with
        | [] when Set.contains key r.Bits -> [ PendingCharge.Bare ]
        | entries -> entries

    /// Linux's `__send_signal_locked` with every receiver blocking the signal:
    /// `None` for `EAGAIN`.
    let private referenceSend
        (sender : SignalSender)
        (key : int voption * Signal)
        (user : UserId)
        (elsewhere : int)
        (limit : uint64)
        (r : Reference)
        : Reference option
        =
        let _, signal = key
        let realTime = Signal.isRealTimeUnder SignalNumbering.Linux signal

        if not realTime && Set.contains key r.Bits then
            Some r
        else
            let count =
                elsewhere
                + (r.Entries |> List.filter (fun (_, _, charged) -> charged = user) |> List.length)

            let overrides = not realTime && sender <> SignalSender.ThreadKill

            if uint64 count < limit || overrides then
                Some
                    {
                        Bits = Set.add key r.Bits
                        Entries = r.Entries @ [ fst key, signal, user ]
                    }
            elif realTime && sender = SignalSender.ThreadKill then
                None
            else
                Some
                    { r with
                        Bits = Set.add key r.Bits
                    }

    /// Linux's `collect_signal`: the first entry for the key, the bit cleared
    /// once no entry for it is left.
    let private referenceTake (key : int voption * Signal) (r : Reference) : Reference =
        let rec dropFirst (entries : (int voption * Signal * UserId) list) =
            match entries with
            | [] -> []
            | (target, signal, _) :: rest when (target, signal) = key -> rest
            | head :: rest -> head :: dropFirst rest

        let entries = dropFirst r.Entries

        let stillQueued =
            entries |> List.exists (fun (target, signal, _) -> (target, signal) = key)

        {
            Bits = if stillQueued then r.Bits else Set.remove key r.Bits
            Entries = entries
        }

    let private referenceDiscard (signal : Signal) (r : Reference) : Reference =
        {
            Bits = r.Bits |> Set.filter (fun (_, s) -> s <> signal)
            Entries = r.Entries |> List.filter (fun (_, s, _) -> s <> signal)
        }

    let private t0 : int = 0

    let private poolSignals : Signal list =
        [
            Signal.SIGUSR1
            Signal.SIGUSR2
            Signal.RealTime 2
            Signal.RealTime 3
            Signal.RealTime 4
        ]

    [<RequireQualifiedAccess>]
    type private QueueOp =
        | Send of
            sender : SignalSender *
            toThread : bool *
            signal : Signal *
            user : UserId *
            elsewhere : int *
            limit : uint64
        /// The thread takes one instance of the signal, its own set's first.
        | Take of signal : Signal
        /// The signal is ignored, which discards every instance, and caught again.
        | Discard of signal : Signal

    let private users : UserId list =
        [
            UserId.parseOrFail "TestPendingSignalLimit" 1000u
            UserId.parseOrFail "TestPendingSignalLimit" 1001u
        ]

    let private opGen : Gen<QueueOp> =
        let send =
            gen {
                let! sender = Gen.elements [ SignalSender.Kill ; SignalSender.ThreadKill ; SignalSender.Kernel ]
                let! toThread = Gen.elements [ false ; true ]
                let! signal = Gen.elements poolSignals
                let! user = Gen.elements users
                let! elsewhere = Gen.choose (0, 3)
                let! limit = Gen.choose (0, 5)
                return QueueOp.Send (sender, toThread, signal, user, elsewhere, uint64 limit)
            }

        Gen.frequency
            [
                6, send
                3, Gen.elements poolSignals |> Gen.map QueueOp.Take
                1, Gen.elements poolSignals |> Gen.map QueueOp.Discard
            ]

    let private numbering : SignalNumbering = SignalNumbering.Linux

    let private poolMask : SignalMask =
        SignalMask.ofSignals numbering (Set.ofList poolSignals)

    let private caught : SignalDisposition<string> =
        SignalDisposition.Catch (SignalCatch.ofHandler "h")

    /// A process of one thread that catches every signal of the pool and
    /// blocks them all.
    let private blockedState : SignalState<int, string> =
        let state =
            (SignalState.initial numbering Set.empty, poolSignals)
            ||> List.fold (fun state signal -> SignalState.setDisposition numbering signal caught state)

        SignalState.changeMask numbering SignalMaskChange.Block poolMask t0 state

    /// Every instance the model holds, by set and signal, as the reference
    /// states them.
    let private modelInstances (state : SignalState<int, string>) : Map<int voption * Signal, PendingCharge list> =
        SignalState.queued state
        |> List.groupBy (fun queued -> queued.Entry.Target, queued.Entry.Signal)
        |> List.map (fun (key, instances) -> key, instances |> List.map (fun queued -> queued.Charge))
        |> Map.ofList

    let private allKeys : (int voption * Signal) list =
        [
            for target in [ ValueNone ; ValueSome t0 ] do
                for signal in poolSignals do
                    yield target, signal
        ]

    [<Test>]
    let ``what Linux queues past the limit agrees with a reference holding its bits and entries`` () : unit =
        let property (ops : QueueOp list) : unit =
            let mutable state = blockedState
            let mutable r = referenceEmpty

            for op in ops do
                match op with
                | QueueOp.Send (sender, toThread, signal, user, elsewhere, limit) ->
                    let target = if toThread then ValueSome t0 else ValueNone

                    let generated =
                        SignalState.generate
                            numbering
                            CoreDumps.Suppressed
                            (QueueAccount.Limited (user, elsewhere, limit, sender))
                            t0
                            true
                            (Set.singleton t0)
                            {
                                Signal = signal
                                Target = target
                            }
                            state

                    match generated, referenceSend sender (target, signal) user elsewhere limit r with
                    | Ok (SignalGeneration.ProcessContinues after), Some expected ->
                        state <- after
                        r <- expected
                    | Ok SignalGeneration.QueueFull, None -> ()
                    | actual, expected -> failwith $"%A{op}: the model answered %A{actual}, the reference %A{expected}"
                | QueueOp.Take signal ->
                    let own = referenceInstances r (ValueSome t0, signal)
                    let shared = referenceInstances r (ValueNone, signal)

                    let only = SignalMask.ofSignals numbering (Set.singleton signal)

                    let unblocked =
                        SignalState.changeMask numbering SignalMaskChange.Unblock only t0 state

                    match
                        SignalState.onReturnToUser numbering CoreDumps.Suppressed t0 (Set.singleton t0) t0 unblocked
                    with
                    | Ok (Some (SignalDelivery.RunHandlers [ frame ]), after) ->
                        let key =
                            if not own.IsEmpty then
                                (ValueSome t0, signal)
                            elif not shared.IsEmpty then
                                (ValueNone, signal)
                            else
                                failwith $"%A{op}: the model delivered %A{frame}, which the reference does not hold"

                        frame.Entry
                        |> shouldEqual
                            {
                                Signal = signal
                                Target = fst key
                            }

                        r <- referenceTake key r

                        state <-
                            SignalState.sigreturn t0 frame.Id after
                            |> SignalState.changeMask numbering SignalMaskChange.Block only t0
                    | Ok (None, _) when own.IsEmpty && shared.IsEmpty -> ()
                    | other -> failwith $"%A{op}: the model's return answered %A{other}"
                | QueueOp.Discard signal ->
                    state <-
                        state
                        |> SignalState.setDisposition numbering signal SignalDisposition.Ignore
                        |> SignalState.setDisposition numbering signal caught

                    r <- referenceDiscard signal r

                let model = modelInstances state

                for key in allKeys do
                    let actual = Map.tryFind key model |> Option.defaultValue []
                    let expected = referenceInstances r key

                    if actual <> expected then
                        failwith
                            $"after %A{op}: %A{key} holds %A{actual} in the model and %A{expected} in the reference"

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 1000,
            Prop.forAll (Arb.fromGen (Gen.listOf opGen |> Gen.map (List.truncate 40))) property
        )

    /// Linux allocates a queue entry before it chooses the thread to wake: a
    /// real-time `tgkill` past the limit is `EAGAIN`, wherever the leader is,
    /// and a real-time `kill` past it, kept bare or lost, still chooses, so
    /// `SignalReceiverRefusal.LeaderAlreadySignalled` holds for it as for any
    /// other signal sent to the process.
    [<Test>]
    let ``the limit is consulted before the receiving thread is chosen`` () : unit =
        let t1 = 1
        let threads = Set.ofList [ t0 ; t1 ]
        let user = List.head users
        let signal = Signal.RealTime 2

        let generate
            (sender : SignalSender)
            (leaderRunning : bool)
            (target : int voption)
            (state : SignalState<int, string>)
            =
            SignalState.generate
                numbering
                CoreDumps.Suppressed
                (QueueAccount.Limited (user, 0, 1UL, sender))
                t0
                leaderRunning
                threads
                {
                    Signal = signal
                    Target = target
                }
                state

        // A caught real-time signal pending on the process, which the leader,
        // blocking nothing, has to take: the user's queue is now full.
        let pending =
            match
                SignalState.initial numbering Set.empty
                |> SignalState.setDisposition numbering signal caught
                |> generate SignalSender.Kill false ValueNone
            with
            | Ok (SignalGeneration.ProcessContinues state) -> state
            | other -> failwith $"the first kill: %A{other}"

        match generate SignalSender.Kill false ValueNone pending with
        | Error (SignalReceiverRefusal.LeaderAlreadySignalled refused) -> refused |> shouldEqual signal
        | other -> failwith $"a second kill past the limit, the leader asleep: %A{other}"

        // Running, the leader is the one woken; the instance past the limit is
        // lost beside the one pending.
        match generate SignalSender.Kill true ValueNone pending with
        | Ok (SignalGeneration.ProcessContinues state) -> state |> shouldEqual pending
        | other -> failwith $"a second kill past the limit, the leader running: %A{other}"

        for leaderRunning in [ false ; true ] do
            match generate SignalSender.ThreadKill leaderRunning (ValueSome t1) pending with
            | Ok SignalGeneration.QueueFull -> ()
            | other -> failwith $"a tgkill past the limit (leader running: %b{leaderRunning}): %A{other}"

    // ---------------- Calls, held to the probe ---------------- //

    let private output (uid : int) : string =
        let name = $"WoofWare.PosixKernel.Test.rt-queue-limit.linux-uid%d{uid}.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)
        reader.ReadToEnd ()

    /// The probe's row that starts `prefix`, in both users' outputs, which must
    /// agree.
    let private measuredRow (prefix : string) : string =
        let rowIn (uid : int) =
            (output uid).Split '\n'
            |> Array.filter (fun line -> line.StartsWith (prefix, StringComparison.Ordinal))
            |> Array.exactlyOne

        let root = rowIn 0
        rowIn 1000 |> shouldEqual root
        root

    /// The probe's drained instances, as `signal/pid`, sorted: what a model
    /// holds says only whether the sender's information survived.
    let private drainedOf (row : string) : string list =
        let drained =
            row.Substring (row.IndexOf ("drained:", StringComparison.Ordinal) + "drained:".Length)

        drained.Split (' ', StringSplitOptions.RemoveEmptyEntries)
        |> Array.filter (fun word -> not (word.StartsWith ("count=", StringComparison.Ordinal)))
        |> Array.map (fun word ->
            let parts = word.Split '/'
            $"%s{parts.[0]}/%s{parts.[2]}"
        )
        |> Array.sort
        |> List.ofArray

    let private probeName (signal : Signal) : string =
        match signal with
        | Signal.SIGUSR1 -> "USR1"
        | Signal.RealTime offset -> $"RTMIN+%d{offset - 2}"
        | other -> failwith $"the probe sends no %O{other}"

    let private rtmin : Signal = Signal.RealTime 2
    let private rtmin1 : Signal = Signal.RealTime 3

    /// A Linux machine whose processes each have `limit`, and the first of
    /// them, which blocks the probe's signals and catches them.
    let private bootWith (limit : uint64) : UnixSystem<int, string> =
        let blockAndCatch (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let leader = Callers.leader system

            let system =
                (system, [ Signal.SIGUSR1 ; rtmin ; rtmin1 ])
                ||> List.fold (fun system signal ->
                    match
                        UnixSignal.sigaction leader (Signal.toRawSignoUnder numbering signal) (Some caught) system
                    with
                    | Ok (_, system) -> ReturnsToUser.untilResumed leader system
                    | Error errno -> failwith $"sigaction: %O{errno}"
                )

            let mask =
                SignalMask.ofSignals numbering (Set.ofList [ Signal.SIGUSR1 ; rtmin ; rtmin1 ])

            match UnixSignal.pthreadSigmask leader (MaskHow.block numbering) (Some mask) system with
            | Ok (_, system) -> ReturnsToUser.untilResumed leader system
            | Error errno -> failwith $"pthread_sigmask: %O{errno}"

        UnixSystem.initial SimulatedUnixPlatform.linuxX64
        |> Launched.bootWith (ProcessLaunch.withPendingSignalLimit limit) UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> blockAndCatch

    /// `kill(getpid(), signal)` or `pthread_kill(self, signal)` by the
    /// process's thread 0: `0` or the errno's name.
    let private send
        (pid : ProcessId)
        (method : string)
        (signal : Signal)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        let caller = Caller.make pid 0
        let signo = Signal.toRawSignoUnder numbering signal

        let answer =
            match method with
            | "kill" -> UnixSignal.kill caller (ProcessId.toInt32 pid) signo system
            | "pthread_kill" -> UnixSignal.pthreadKill caller 0 signo system
            | other -> failwith $"no method %s{other}"

        match answer with
        | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> "0", ReturnsToUser.untilResumed caller system
        | Ok other -> failwith $"%s{method} of %O{signal}: %A{other}"
        | Error errno -> string<UnixError> errno, system

    /// Thread 0 of the first process takes one instance of `signal`: unblocks
    /// it, runs its handler and blocks it again.
    let private takeOne
        (pid : ProcessId)
        (signal : Signal)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let leader = Caller.make pid 0
        let only = SignalMask.ofSignals numbering (Set.singleton signal)

        let system =
            match UnixSignal.pthreadSigmask leader (MaskHow.unblock numbering) (Some only) system with
            | Ok (_, system) -> system
            | Error errno -> failwith $"pthread_sigmask: %O{errno}"

        let system =
            match UnixSignal.onReturnToUser leader system with
            | ProcessFate.Continues (ReturnToUserOutcome.RunHandlers ([ frame ], None), system) ->
                UnixSignal.sigreturn leader frame.Id system
            | other -> failwith $"taking %O{signal}: %A{other}"

        match UnixSignal.pthreadSigmask leader (MaskHow.block numbering) (Some only) system with
        | Ok (_, system) -> ReturnsToUser.untilResumed leader system
        | Error errno -> failwith $"pthread_sigmask: %O{errno}"

    /// The probe's `sigq=` for the default user: every instance charged to it,
    /// in every process, over the first process's limit.
    let private sigq (pid : ProcessId) (limit : uint64) (system : UnixSystem<int, string>) : string =
        let user = (UnixSystem.credentials pid system).RealUser

        let count =
            UnixSystem.processIds system
            |> Seq.sumBy (fun pid -> SignalState.chargedTo user (UnixSystem.signals pid system))

        $"sigq=%d{count}/%d{limit}"

    /// What the first process holds, as `drainedOf` states the probe's.
    let private drained (pid : ProcessId) (system : UnixSystem<int, string>) : string list =
        SignalState.queued (UnixSystem.signals pid system)
        |> List.map (fun queued ->
            let pid =
                match queued.Charge with
                | PendingCharge.Charged _ -> "pid=own"
                | PendingCharge.Bare -> "pid=0"
                | PendingCharge.Unbounded -> failwith "a Linux call queued an unbounded instance"

            $"%s{probeName queued.Entry.Signal}/%s{pid}"
        )
        |> List.sort

    [<TestCase("kill", 4)>]
    [<TestCase("pthread_kill", 4)>]
    [<TestCase("kill", 0)>]
    [<TestCase("pthread_kill", 0)>]
    let ``eight sends of one signal answer, count and queue as measured`` (method : string, limit : int) : unit =
        for signal in [ rtmin ; Signal.SIGUSR1 ] do
            let prefix =
                $"section=send limit=%d{limit} method=%s{method} sig=%s{probeName signal} answers:"

            let row = measuredRow prefix
            let system = bootWith (uint64 limit)
            let pid = Lone.pid system

            let answers, system =
                ((List.empty, system), [ 1..8 ])
                ||> List.fold (fun (answers, system) _ ->
                    let answer, system = send pid method signal system
                    answers @ [ answer ], system
                )

            let modelled =
                $"""%s{prefix} %s{String.Join (" ", answers)} %s{sigq pid (uint64 limit) system} drained:"""

            if not (row.StartsWith (modelled, StringComparison.Ordinal)) then
                failwith $"model: %s{modelled}\nprobe: %s{row}"

            drained pid system |> shouldEqual (drainedOf row)

    [<TestCase("kill", "USR1")>]
    [<TestCase("kill", "RTMIN+1")>]
    [<TestCase("pthread_kill", "USR1")>]
    [<TestCase("pthread_kill", "RTMIN+1")>]
    let ``a send past a limit filled with real-time signals answers, counts and queues as measured``
        (method : string, name : string)
        : unit
        =
        let signal = if name = "USR1" then Signal.SIGUSR1 else rtmin1

        let row =
            measuredRow $"section=mixed limit=4 fill=sigqueue(RTMIN)x4 then method=%s{method} sig=%s{name} "

        let system = bootWith 4UL
        let pid = Lone.pid system

        // The model has no sigqueue: its allocation is pthread_kill's, within
        // the limit.
        let system =
            (system, [ 1..4 ])
            ||> List.fold (fun system _ ->
                match send pid "pthread_kill" rtmin system with
                | "0", system -> system
                | answer, _ -> failwith $"filling: %s{answer}"
            )

        let answer, system = send pid method signal system

        row.Contains $" answer=%s{answer} %s{sigq pid 4UL system} drained:"
        |> shouldEqual true

        drained pid system |> shouldEqual (drainedOf row)

    [<TestCase "kill">]
    [<TestCase "pthread_kill">]
    let ``the limit counts what another process of the same user holds`` (method : string) : unit =
        let row =
            measuredRow $"section=user limit=4 sibling-holds=4 method=%s{method} sig=RTMIN "

        let system = bootWith 4UL
        let pid = Lone.pid system

        // A sibling of the same user (every launch has the default
        // credentials), holding four real-time signals it sent itself.
        let launch =
            Launched.launch SimulatedUnixPlatform.linuxX64 UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> ProcessLaunch.withPendingSignalLimit 4UL

        let sibling, system = UnixSystem.launch launch system
        let siblingThread = Caller.make sibling 0
        let only = SignalMask.ofSignals numbering (Set.singleton rtmin)

        let system =
            match UnixSignal.sigaction siblingThread (Signal.toRawSignoUnder numbering rtmin) (Some caught) system with
            | Ok (_, system) -> ReturnsToUser.untilResumed siblingThread system
            | Error errno -> failwith $"sigaction: %O{errno}"

        let system =
            match UnixSignal.pthreadSigmask siblingThread (MaskHow.block numbering) (Some only) system with
            | Ok (_, system) -> ReturnsToUser.untilResumed siblingThread system
            | Error errno -> failwith $"pthread_sigmask: %O{errno}"

        let system =
            (system, [ 1..4 ])
            ||> List.fold (fun system _ ->
                match send sibling "pthread_kill" rtmin system with
                | "0", system -> system
                | answer, _ -> failwith $"the sibling's fill: %s{answer}"
            )

        let answer, system = send pid method rtmin system

        row.Contains $" answer=%s{answer} %s{sigq pid 4UL system} drained:"
        |> shouldEqual true

        drained pid system |> shouldEqual (drainedOf row)

    [<Test>]
    let ``a bare real-time instance gives way to an allocated one of its signal`` () : unit =
        let row = measuredRow "section=bare row=rt-bare-then-allocated "
        let system = bootWith 1UL
        let pid = Lone.pid system
        let fill, system = send pid "pthread_kill" rtmin system
        let bare, system = send pid "kill" rtmin1 system
        let before = sigq pid 1UL system
        let system = takeOne pid rtmin system
        let afterTake = sigq pid 1UL system
        // The probe's sigqueue to the process, which allocates as kill does.
        let allocated, system = send pid "kill" rtmin1 system

        [ fill ; bare ; allocated ] |> shouldEqual [ "0" ; "0" ; "0" ]

        row.Contains
            $"%s{before} took-RTMIN+0:SI_QUEUE/pid=own %s{afterTake} sigqueue(RTMIN+1)=0 %s{sigq pid 1UL system} drained:"
        |> shouldEqual true

        drained pid system |> shouldEqual (drainedOf row)

    [<Test>]
    let ``a real-time kill past the limit beside an allocated instance of its signal is lost`` () : unit =
        let row = measuredRow "section=bare row=rt-allocated-then-bare "
        let system = bootWith 1UL
        let pid = Lone.pid system
        let allocated, system = send pid "kill" rtmin1 system
        let lost, system = send pid "kill" rtmin1 system
        [ allocated ; lost ] |> shouldEqual [ "0" ; "0" ]
        row.Contains $" %s{sigq pid 1UL system} drained:" |> shouldEqual true
        drained pid system |> shouldEqual (drainedOf row)

    [<Test>]
    let ``a bare standard instance counts against nothing`` () : unit =
        let row = measuredRow "section=bare row=standard-bare-counts "
        let system = bootWith 1UL
        let pid = Lone.pid system
        let fill, system = send pid "pthread_kill" rtmin system
        let bare, system = send pid "pthread_kill" Signal.SIGUSR1 system
        let before = sigq pid 1UL system
        let system = takeOne pid rtmin system
        let afterTake = sigq pid 1UL system
        let allocated, system = send pid "pthread_kill" rtmin1 system
        [ fill ; bare ; allocated ] |> shouldEqual [ "0" ; "0" ; "0" ]

        row.Contains
            $"%s{before} took-RTMIN+0:SI_QUEUE/pid=own %s{afterTake} sigqueue(RTMIN+1)=0 %s{sigq pid 1UL system} drained:"
        |> shouldEqual true

        drained pid system |> shouldEqual (drainedOf row)

    [<Test>]
    let ``a bare standard instance coalesces, and the process's own set queues past the limit`` () : unit =
        let row = measuredRow "section=bare row=standard-bare-twice-then-kill "
        let system = bootWith 0UL
        let pid = Lone.pid system
        let first, system = send pid "pthread_kill" Signal.SIGUSR1 system
        let second, system = send pid "pthread_kill" Signal.SIGUSR1 system
        let killed, system = send pid "kill" Signal.SIGUSR1 system
        [ first ; second ; killed ] |> shouldEqual [ "0" ; "0" ; "0" ]
        row.Contains $" %s{sigq pid 0UL system} drained:" |> shouldEqual true
        drained pid system |> shouldEqual (drainedOf row)

    [<TestCase false>]
    [<TestCase true>]
    let ``an ignored real-time signal is discarded before the limit is consulted, unless it is blocked``
        (blocked : bool)
        : unit
        =
        let row =
            measuredRow
                $"""section=ignored limit=0 sig=RTMIN(SIG_IGN) %s{if blocked then "blocked" else "unblocked"} """

        let system = bootWith 0UL
        let pid = Lone.pid system
        let leader = Caller.make pid 0
        let only = SignalMask.ofSignals numbering (Set.singleton rtmin)

        let system =
            match
                UnixSignal.sigaction
                    leader
                    (Signal.toRawSignoUnder numbering rtmin)
                    (Some SignalDisposition.Ignore)
                    system
            with
            | Ok (_, system) -> ReturnsToUser.untilResumed leader system
            | Error errno -> failwith $"sigaction: %O{errno}"

        let system =
            if blocked then
                system
            else
                match UnixSignal.pthreadSigmask leader (MaskHow.unblock numbering) (Some only) system with
                | Ok (_, system) -> ReturnsToUser.untilResumed leader system
                | Error errno -> failwith $"pthread_sigmask: %O{errno}"

        let threadKilled, system = send pid "pthread_kill" rtmin system
        let killed, system = send pid "kill" rtmin system

        row.Contains $"pthread_kill=%s{threadKilled} kill=%s{killed} %s{sigq pid 0UL system} "
        |> shouldEqual true

        drained pid system |> shouldEqual (drainedOf row)

    // ---------------- The launch setting ---------------- //

    [<Test>]
    let ``a Linux process starts with the default limit, and a launch sets another`` () : unit =
        let defaulted : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        (Lone.proc defaulted).PendingSignalLimit
        |> shouldEqual (ValueSome UnixSystem.defaultPendingSignalLimit)

        UnixSystem.defaultPendingSignalLimit |> shouldEqual 4505UL
        (Lone.proc (bootWith 7UL)).PendingSignalLimit |> shouldEqual (ValueSome 7UL)

    [<Test>]
    let ``Darwin has no RLIMIT_SIGPENDING: the setting is refused and its processes hold no limit`` () : unit =
        let launch =
            Launched.launch SimulatedUnixPlatform.macOsArm64 UnixSystem.pipedStandardStreams 0 (CpuId 0)

        Assert.Throws<PlatformNotSupportedException> (fun () ->
            ProcessLaunch.withPendingSignalLimit 4UL launch |> ignore<ProcessLaunch<int>>
        )
        |> ignore<PlatformNotSupportedException>

        let booted : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.macOsArm64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        (Lone.proc booted).PendingSignalLimit |> shouldEqual ValueNone
