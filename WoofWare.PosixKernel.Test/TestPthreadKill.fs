namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixSignal.pthreadKill`, held to the rows of
/// `docs/plans/2026-08-23-posix-kernel-extraction/raise-sweep.c`, measured on
/// Linux 6.18.5 (aarch64, glibc 2.41) and Darwin 27.0.0 (arm64).
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPthreadKill =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    let private leader : int = 0
    let private worker : int = 1

    let private systemOnWith
        (configure : UnixBootImage<int, string> -> UnixBootImage<int, string>)
        (flavour : SimulatedUnixFlavour)
        : UnixSystem<int, string>
        =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> configure
        |> Launched.boot UnixSystem.pipedStandardStreams leader (CpuId 0)

    let private systemLaunchedWith
        (configure : ProcessLaunch<int> -> ProcessLaunch<int>)
        (flavour : SimulatedUnixFlavour)
        : UnixSystem<int, string>
        =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.bootWith configure UnixSystem.pipedStandardStreams leader (CpuId 0)

    let private systemOn (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> = systemOnWith id flavour

    let private withWorker (system : UnixSystem<int, string>) : UnixSystem<int, string> = Threads.spawn worker system

    let private numberingOf (flavour : SimulatedUnixFlavour) : SignalNumbering =
        SimulatedUnixPlatform.signalNumbering (HostPlatform.platformOf flavour)

    let private self (system : UnixSystem<int, string>) : int32 = ProcessId.toInt32 (Lone.pid system)

    /// The highest signal number, written out rather than taken from
    /// `Signal.highestSignoUnder`, so that this oracle and the implementation
    /// share nothing but the measurement.
    let private highestSigno (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 64
        | SimulatedUnixFlavour.Darwin -> 31

    /// The numbers a thread can be sent with `pthread_kill`: every signal but
    /// glibc's own 32 and 33, measured to be refused with EINVAL though
    /// `kill(2)` sends them.
    let private sendable (flavour : SimulatedUnixFlavour) (signo : int) : bool =
        signo = 0
        || signo >= 1
           && signo <= highestSigno flavour
           && not (flavour = SimulatedUnixFlavour.Linux && (signo = 32 || signo = 33))

    /// Every signal a handler can be installed for: the probe's
    /// `all_catchable`.
    let private catchable (flavour : SimulatedUnixFlavour) : int list =
        [ 1 .. highestSigno flavour ]
        |> List.filter (fun signo ->
            match flavour, signo with
            | _, 9 -> false
            | SimulatedUnixFlavour.Linux, (19 | 32 | 33) -> false
            | SimulatedUnixFlavour.Darwin, 17 -> false
            | _ -> true
        )

    let private signoGen : Gen<int> =
        Gen.oneof
            [
                Gen.choose (-3, 70)
                Gen.elements [ Int32.MinValue ; Int32.MinValue + 1 ; Int32.MaxValue ; 128 ; 255 ; 1000 ]
                ArbMap.defaults |> ArbMap.generate<int>
            ]

    let private answer (system : UnixSystem<int, string>) (target : int) (signo : int) : string =
        match UnixSignal.tryPthreadKill (Callers.leader system) target signo system with
        | Ok (Ok _) -> "OK"
        | Ok (Error errno) -> $"%O{errno}"
        | Error refusal -> $"refused %O{refusal}"

    /// The probe's `args` rows: `raise` and `pthread_kill(pthread_self())`
    /// answered alike on both flavours, row for row.
    [<Test>]
    let ``pthread_kill of the calling thread answers the measured rows`` () : unit =
        let rows : (int * string * string) list =
            [
                // signo, Linux, Darwin
                0, "OK", "OK"
                -1, "EINVAL", "EINVAL"
                1, "OK", "OK"
                31, "OK", "OK"
                32, "EINVAL", "EINVAL"
                33, "EINVAL", "EINVAL"
                34, "OK", "EINVAL"
                64, "OK", "EINVAL"
                65, "EINVAL", "EINVAL"
                66, "EINVAL", "EINVAL"
                128, "EINVAL", "EINVAL"
                1000, "EINVAL", "EINVAL"
                Int32.MinValue, "EINVAL", "EINVAL"
                Int32.MaxValue, "EINVAL", "EINVAL"
            ]

        for signo, onLinux, onDarwin in rows do
            (signo, answer (systemOn SimulatedUnixFlavour.Linux) leader signo)
            |> shouldEqual (signo, onLinux)

            (signo, answer (systemOn SimulatedUnixFlavour.Darwin) leader signo)
            |> shouldEqual (signo, onDarwin)

    [<Test>]
    let ``pthread_kill is EINVAL exactly when the number cannot be sent, and otherwise generates the signal at its target``
        ()
        : unit
        =
        let gen =
            gen {
                let! flavour = Gen.elements flavours
                let! signo = signoGen
                let! target = Gen.elements [ leader ; worker ]
                let! coreDumps = Gen.elements [ CoreDumps.Suppressed ; CoreDumps.Written ]
                // A handler frame on either thread, blocking a few signals, so
                // that some sends find their target blocking them.
                let! framed = Gen.elements [ None ; Some leader ; Some worker ]
                let! blocked = Gen.subListOf [ 1 ; 2 ; 10 ; 15 ; 20 ; 28 ; 29 ; 34 ]
                return flavour, signo, target, coreDumps, framed, blocked
            }

        let property
            (
                flavour : SimulatedUnixFlavour,
                signo : int,
                target : int,
                coreDumps : CoreDumps,
                framed : int option,
                blocked : int list
            )
            : unit
            =
            let numbering = numberingOf flavour

            let system =
                let system =
                    systemLaunchedWith (ProcessLaunch.withCoreDumps coreDumps) flavour |> withWorker

                match framed with
                | None -> system
                | Some thread ->
                    let mask =
                        blocked
                        |> List.choose (fun signo -> Signal.ofRawSignoUnder numbering signo |> ValueOption.toOption)
                        |> Set.ofList

                    HandlerFrames.enterIn "h" thread mask system

            match UnixSignal.tryPthreadKill (Callers.leader system) target signo system, sendable flavour signo with
            | Ok (Error errno), false -> errno |> shouldEqual UnixError.EINVAL
            | Ok (Ok outcome), true ->
                let expected =
                    if signo = 0 then
                        SignalGeneration.ProcessContinues (Lone.proc system).Signals
                    else
                        match
                            SignalState.generate
                                (Lone.UnixSystemState.signalNumbering system)
                                coreDumps
                                leader
                                (Set.ofList [ leader ; worker ])
                                {
                                    Signal =
                                        match
                                            Signal.ofRawSignoUnder (Lone.UnixSystemState.signalNumbering system) signo
                                        with
                                        | ValueSome signal -> signal
                                        | ValueNone -> failwith $"%d{signo} was sent, so it is a signal"
                                    Target = ValueSome target
                                }
                                (Lone.proc system).Signals
                        with
                        | Ok generation -> generation
                        | Error refusal -> failwith $"generating %d{signo} at %d{target} was refused: %O{refusal}"

                let survivor (after : UnixSystem<int, string>) : unit =
                    after
                    |> Lone.mapProc (fun proc ->
                        { proc with
                            Signals = (Lone.proc system).Signals
                        }
                    )
                    |> shouldEqual system

                match outcome, expected with
                | ProcessFate.Continues (KillOutcome.ProcessRuns, after), SignalGeneration.ProcessContinues signals ->
                    (Lone.proc after).Signals |> shouldEqual signals
                    survivor after
                | ProcessFate.Continues (KillOutcome.ProcessStopped stoppedBy, after),
                  SignalGeneration.ProcessStopped (signal, signals) ->
                    stoppedBy |> shouldEqual signal
                    (Lone.proc after).Signals |> shouldEqual signals
                    survivor after
                | ProcessFate.ProcessEnded ended, SignalGeneration.ProcessTerminated (signal, coreDumped) ->
                    ended.Termination
                    |> shouldEqual (ProcessTermination.Signaled (signal, coreDumped))

                    EndedMachine.assertThreadsGone system ended
                | _ ->
                    failwith
                        $"pthread_kill(%d{target}, %d{signo}) under %O{flavour} answered %O{outcome}, but generating it is %O{expected}"
            | other, valid ->
                failwith $"pthread_kill(%d{target}, %d{signo}) under %O{flavour}: sendable=%b{valid}, got %O{other}"

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen gen) property)

    /// Every delivery of `signal` to `thread` from here on: `thread` returns to user
    /// mode, runs each handler frame it is given and returns from it, until it
    /// is given nothing more. Fails on any delivery but a handler frame.
    let private drain
        (signal : Signal)
        (thread : int)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let rec go (count : int) (rounds : int) (system : UnixSystem<int, string>) =
            if rounds > 100 then
                failwith $"%O{thread} was still being given signals after 100 returns"

            match UnixSignal.tryOnReturnToUser (Callers.thread thread system) system with
            | Error refusal -> failwith $"onReturnToUser %O{thread} refused: %O{refusal}"
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, system)) -> count, system
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers frames, system)) ->
                let ofSignal =
                    frames |> List.filter (fun frame -> frame.Entry.Signal = signal) |> List.length

                let system =
                    (system, frames)
                    ||> List.fold (fun system frame ->
                        UnixSignal.sigreturn (Callers.thread thread system) frame.Id system
                    )

                go (count + ofSignal) (rounds + 1) system
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped _, _) as other)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ContinueDiscarded _, _) as other)
            | Ok (ProcessFate.ProcessEnded _ as other) -> failwith $"onReturnToUser %O{thread} answered %A{other}"

        go 0 0 system

    let private catchIn (signal : Signal) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    SignalState.setDisposition
                        (Lone.UnixSystemState.signalNumbering system)
                        signal
                        (SignalDisposition.Catch (SignalCatch.ofHandler "h"))
                        proc.Signals
            }
        )

    /// `thread` inside a handler that blocks `signal`, entered through a carrier
    /// other than `signal`.
    let private blocking (signal : Signal) (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let carrier =
            if signal = HandlerFrames.carrier then
                Signal.SIGWINCH
            else
                HandlerFrames.carrier

        let threads = Lone.threads system |> Map.keys |> Set.ofSeq

        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    HandlerFrames.enterVia
                        (Lone.UnixSystemState.signalNumbering system)
                        carrier
                        "carrier"
                        (Lone.leader system)
                        threads
                        thread
                        (Set.singleton signal)
                        proc.Signals
            }
        )

    let private leave (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals = HandlerFrames.leave thread proc.Signals
            }
        )

    let private continues
        (what : string)
        (answer : Result<Result<ProcessFate<KillOutcome, int, string>, UnixError>, 'Refusal>)
        =
        match answer with
        | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> system
        | other -> failwith $"%s{what}: %O{other}"

    /// The probe's `handler` rows: a caught signal raised by either thread runs
    /// its handler on that thread, before `raise` returns, and on no other.
    [<Test>]
    let ``a caught signal raised by a thread is taken by that thread alone, at its next return to user mode``
        ()
        : unit
        =
        for flavour in flavours do
            let numbering = numberingOf flavour

            for signo in catchable flavour do
                let signal = Signal.ofRawSignoUnder numbering signo |> ValueOption.get

                for raiser in [ leader ; worker ] do
                    let bystander = if raiser = leader then worker else leader

                    let raised =
                        systemOn flavour
                        |> withWorker
                        |> catchIn signal
                        |> (fun system -> UnixSignal.tryPthreadKill (Callers.thread raiser system) raiser signo system)
                        |> continues $"%O{flavour} raise %d{signo} on %d{raiser}"

                    let atBystander, raised = drain signal bystander raised
                    let atRaiser, _ = drain signal raiser raised

                    (flavour, signo, raiser, atRaiser, atBystander)
                    |> shouldEqual (flavour, signo, raiser, 1, 0)

    /// The probe's `blocked` rows: a signal a thread raises while it blocks it
    /// stays pending on that thread, though another thread does not block it, and
    /// the raiser takes it once it unblocks it.
    [<Test>]
    let ``a signal a thread raises while blocking it waits for that thread, whoever else could take it`` () : unit =
        for flavour in flavours do
            let numbering = numberingOf flavour

            for signo in catchable flavour do
                let signal = Signal.ofRawSignoUnder numbering signo |> ValueOption.get

                for raiser in [ leader ; worker ] do
                    let bystander = if raiser = leader then worker else leader

                    let raised =
                        systemOn flavour
                        |> withWorker
                        |> catchIn signal
                        |> blocking signal raiser
                        |> (fun system -> UnixSignal.tryPthreadKill (Callers.thread raiser system) raiser signo system)
                        |> continues $"%O{flavour} raise %d{signo} on %d{raiser}"

                    let atBystander, raised = drain signal bystander raised
                    let whileBlocked, raised = drain signal raiser raised

                    SignalState.pending (Lone.proc raised).Signals
                    |> shouldEqual
                        [
                            {
                                Signal = signal
                                Target = ValueSome raiser
                            }
                        ]

                    let afterUnblock, _ = raised |> leave raiser |> drain signal raiser

                    (flavour, signo, raiser, atBystander, whileBlocked, afterUnblock)
                    |> shouldEqual (flavour, signo, raiser, 0, 0, 1)

    /// One of the probe's `pair` shapes: what every thread blocks, which sends are
    /// made, and how many instances each thread took, main then worker, once each
    /// unblocked in turn, main first. `None` where this library refuses.
    type private PairShape =
        {
            Name : string
            Threads : int list
            /// `kill(2)`, or `pthread_kill` of the thread named.
            Sends : int option list
            Linux : (int * int) option
            Darwin : (int * int) option
        }

    let private pairShapes : PairShape list =
        // Measured with every signal `catchable` names, the same for each; the
        // sender of a `kill` does not matter to this library, so the probe's
        // shapes 4 and 5 (the worker kills) are 2 and 3 here. Darwin took the
        // kill and the main thread's raise as one instance, the Darwin rows
        // this library refuses.
        [
            {
                Name = "one thread: kill, raise"
                Threads = [ leader ]
                Sends = [ None ; Some leader ]
                Linux = Some (2, 0)
                Darwin = None
            }
            {
                Name = "one thread: raise, kill"
                Threads = [ leader ]
                Sends = [ Some leader ; None ]
                Linux = Some (2, 0)
                Darwin = None
            }
            {
                Name = "two threads: kill, raise on main"
                Threads = [ leader ; worker ]
                Sends = [ None ; Some leader ]
                Linux = Some (2, 0)
                Darwin = None
            }
            {
                Name = "two threads: kill, pthread_kill of the worker"
                Threads = [ leader ; worker ]
                Sends = [ None ; Some worker ]
                Linux = Some (1, 1)
                Darwin = Some (1, 1)
            }
        ]

    [<Test>]
    let ``a signal sent to the process and one sent to a thread are held as the probe measured, or refused`` () : unit =
        for flavour in flavours do
            let numbering = numberingOf flavour

            for signo in catchable flavour do
                let signal = Signal.ofRawSignoUnder numbering signo |> ValueOption.get

                for shape in pairShapes do
                    let start =
                        let system = systemOn flavour

                        let system =
                            if List.contains worker shape.Threads then
                                withWorker system
                            else
                                system

                        (catchIn signal system, shape.Threads)
                        ||> List.fold (fun system thread -> blocking signal thread system)

                    let send (system : UnixSystem<int, string>) (target : int option) =
                        match target with
                        | None ->
                            match UnixSignal.tryKill (Callers.leader system) (self system) signo system with
                            | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> Ok system
                            | Error (KillRefusal.Receiver refusal) -> Error refusal
                            | other -> failwith $"kill: %O{other}"
                        | Some thread ->
                            match UnixSignal.tryPthreadKill (Callers.leader system) thread signo system with
                            | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> Ok system
                            | Error (ThreadKillRefusal.Receiver refusal) -> Error refusal
                            | other -> failwith $"pthread_kill: %O{other}"

                    let sent =
                        (Ok start, shape.Sends)
                        ||> List.fold (fun system target -> system |> Result.bind (fun system -> send system target))

                    let expected =
                        match flavour with
                        | SimulatedUnixFlavour.Linux -> shape.Linux
                        | SimulatedUnixFlavour.Darwin -> shape.Darwin

                    match sent, expected with
                    | Ok sent, Some (onMain, onWorker) ->
                        let atMain, sent = sent |> leave leader |> drain signal leader

                        let atWorker =
                            if List.contains worker shape.Threads then
                                sent |> leave worker |> drain signal worker |> fst
                            else
                                0

                        (flavour, signo, shape.Name, atMain, atWorker)
                        |> shouldEqual (flavour, signo, shape.Name, onMain, onWorker)
                    | Error refusal, None ->
                        refusal |> shouldEqual (SignalReceiverRefusal.PendingForProcessAndLeader signal)
                    | _ -> failwith $"%O{flavour} %d{signo} %s{shape.Name}: expected %A{expected}, got %A{sent}"

    [<Test>]
    let ``Darwin's refusal is only of a signal that would be left pending`` () : unit =
        // SIGTERM pending on the process, at its default disposition, with the
        // leader no longer blocking it: raising it at the leader kills the
        // process rather than leaving a second instance.
        let numbering = numberingOf SimulatedUnixFlavour.Darwin

        let pendingOnProcess (signal : Signal) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let signo = Signal.toRawSignoUnder numbering signal

            system
            |> catchIn signal
            |> blocking signal leader
            |> fun system -> UnixSignal.tryKill (Callers.leader system) (self system) signo system
            |> continues "kill"
            |> leave leader
            |> fun system ->
                system
                |> Lone.mapProc (fun proc ->
                    { proc with
                        Signals =
                            SignalState.setDisposition
                                (Lone.UnixSystemState.signalNumbering system)
                                signal
                                SignalDisposition.Default
                                proc.Signals
                    }
                )

        let system = systemOn SimulatedUnixFlavour.Darwin |> pendingOnProcess Signal.SIGTERM

        match UnixSignal.tryPthreadKill (Callers.leader system) leader 15 system with
        | Ok (Ok (ProcessFate.ProcessEnded ended)) ->
            ended.Termination
            |> shouldEqual (ProcessTermination.Signaled (Signal.SIGTERM, false))
        | other -> failwith $"raise SIGTERM: %O{other}"

    [<Test>]
    let ``a default SIGCONT the leader does not block is discarded as it is sent, leaving nothing to merge with``
        ()
        : unit
        =
        // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/sigcont-generation.c`
        // on Linux 6.18.5 and Darwin 27.0.0: discarded at generation, as an
        // ignored signal is.
        for flavour in flavours do
            let system = systemOn flavour
            let sigcont = Signal.toRawSignoUnder (numberingOf flavour) Signal.SIGCONT

            let sent =
                UnixSignal.tryKill (Callers.leader system) (self system) sigcont system
                |> continues "kill SIGCONT"

            SignalState.pending (Lone.proc sent).Signals |> shouldEqual []

            UnixSignal.tryPthreadKill (Callers.leader sent) leader sigcont sent
            |> continues "raise SIGCONT"
            |> fun system -> SignalState.pending (Lone.proc system).Signals
            |> shouldEqual []

    [<Test>]
    let ``Darwin's refusal covers SIGCONT at its default, which the leader blocks`` () : unit =
        // Pending on the process, so a raise of it at the leader would be the
        // second instance.
        let darwin = systemOn SimulatedUnixFlavour.Darwin |> blocking Signal.SIGCONT leader

        let sigcont =
            Signal.toRawSignoUnder (numberingOf SimulatedUnixFlavour.Darwin) Signal.SIGCONT

        let sent =
            UnixSignal.tryKill (Callers.leader darwin) (self darwin) sigcont darwin
            |> continues "kill SIGCONT"

        UnixSignal.tryPthreadKill (Callers.leader sent) leader sigcont sent
        |> shouldEqual (
            Error (ThreadKillRefusal.Receiver (SignalReceiverRefusal.PendingForProcessAndLeader Signal.SIGCONT))
        )

        // Linux keeps the two apart, as Darwin does for another thread.
        let linux = systemOn SimulatedUnixFlavour.Linux |> blocking Signal.SIGCONT leader

        let sigcont =
            Signal.toRawSignoUnder (numberingOf SimulatedUnixFlavour.Linux) Signal.SIGCONT

        let sent =
            UnixSignal.tryKill (Callers.leader linux) (self linux) sigcont linux
            |> continues "kill SIGCONT"

        UnixSignal.tryPthreadKill (Callers.leader sent) leader sigcont sent
        |> continues "raise SIGCONT"
        |> fun system -> SignalState.pending (Lone.proc system).Signals |> List.length
        |> shouldEqual 2

    [<Test>]
    let ``pthread_kill by an init process is refused`` () : unit =
        for flavour in flavours do
            let init =
                systemOnWith (Launched.processId (ProcessId.parseOrFail "test" 1)) flavour

            UnixSignal.tryPthreadKill (Callers.leader init) leader 15 init
            |> shouldEqual (Error ThreadKillRefusal.InitProcess)

    [<Test>]
    let ``pthread_kill of a thread the process does not have fails loudly`` () : unit =
        for flavour in flavours do
            for signo in [ 0 ; -1 ; 15 ] do
                let system = systemOn flavour

                Assert.Throws<exn> (fun () ->
                    UnixSignal.tryPthreadKill (Callers.leader system) worker signo system
                    |> ignore<_>
                )
                |> ignore<exn>
