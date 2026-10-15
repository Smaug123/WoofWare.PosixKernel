namespace WoofWare.PosixKernel.Test

open System
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixSignal =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    let private systemOnWith
        (configure : UnixBootImage<int, string> -> UnixBootImage<int, string>)
        (flavour : SimulatedUnixFlavour)
        : UnixSystem<int, string>
        =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> configure
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private systemLaunchedWith
        (configure : ProcessLaunch<int> -> ProcessLaunch<int>)
        (flavour : SimulatedUnixFlavour)
        : UnixSystem<int, string>
        =
        UnixSystem.initial (HostPlatform.platformOf flavour)
        |> Launched.bootWith configure UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private systemOn (flavour : SimulatedUnixFlavour) : UnixSystem<int, string> = systemOnWith id flavour

    let private linux : UnixSystem<int, string> = systemOn SimulatedUnixFlavour.Linux

    /// A Linux process booted with `pid`.
    let private linuxWithPid (pid : int32) : UnixSystem<int, string> =
        systemOnWith (Launched.processId (ProcessId.parseOrFail "test" pid)) SimulatedUnixFlavour.Linux

    let private self : int32 = ProcessId.toInt32 (Lone.pid linux)

    /// The highest signal number `kill(2)` accepts, written out rather than
    /// taken from `Signal.highestSignoUnder`, so that this oracle and the
    /// implementation share nothing but the measurement.
    let private highestSigno (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 64
        | SimulatedUnixFlavour.Darwin -> 31

    /// A signal number from anywhere in `int`, weighted towards the edges of the
    /// valid range, where an off-by-one would show.
    let private signoGen : Gen<int> =
        Gen.oneof
            [
                Gen.choose (-3, 70)
                Gen.elements [ Int32.MinValue ; Int32.MinValue + 1 ; Int32.MaxValue ; 255 ; 256 ; 1000 ]
                ArbMap.defaults |> ArbMap.generate<int>
            ]

    [<Test>]
    let ``kill of the calling process with SIGKILL ends it`` () : unit =
        let system = linux |> HandlerFrames.enterIn "h" 0 (Set.singleton Signal.SIGUSR1)

        match UnixSignal.tryKill (Callers.leader system) self 9 system with
        | Ok (Ok (ProcessFate.ProcessEnded (ended, after))) ->
            EndedProcess.termination ended
            |> shouldEqual (ProcessTermination.Signaled (Signal.SIGKILL, false))

            EndedProcess.processId ended |> shouldEqual (Lone.pid system)
            EndedMachine.assertAsExit (Callers.leader system) system after
        | other -> failwith $"unexpected answer: %O{other}"

    [<Test>]
    let ``a death by a signal that dumps core carries the core flag exactly when the process writes dumps`` () : unit =
        // SIGQUIT dumps core on both flavours; SIGTERM on neither.
        for flavour in flavours do
            for coreDumps in [ CoreDumps.Suppressed ; CoreDumps.Written ] do
                let system = systemLaunchedWith (ProcessLaunch.withCoreDumps coreDumps) flavour

                let death (signo : int) : ProcessTermination =
                    match UnixSignal.tryKill (Callers.leader system) self signo system with
                    | Ok (Ok (ProcessFate.ProcessEnded (ended, _))) -> EndedProcess.termination ended
                    | other -> failwith $"kill(self, %d{signo}) under %O{flavour}: %O{other}"

                death 3
                |> shouldEqual (ProcessTermination.Signaled (Signal.SIGQUIT, coreDumps = CoreDumps.Written))

                death 15 |> shouldEqual (ProcessTermination.Signaled (Signal.SIGTERM, false))

    [<Test>]
    let ``the null signal to the calling process changes nothing`` () : unit =
        for flavour in flavours do
            let system = systemOn flavour

            UnixSignal.tryKill (Callers.leader system) self 0 system
            |> shouldEqual (Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))))

    [<Test>]
    let ``a signal the calling process cannot yet receive is left pending`` () : unit =
        // Its only thread is in a handler that blocks SIGTERM, so SIGTERM waits
        // in the process-wide pending set.
        let blocking = linux |> HandlerFrames.enterIn "h" 0 (Set.singleton Signal.SIGTERM)

        match UnixSignal.tryKill (Callers.leader blocking) self 15 blocking with
        | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after))) ->
            SignalState.pending (Lone.proc after).Signals
            |> shouldEqual
                [
                    {
                        Signal = Signal.SIGTERM
                        Target = ValueNone
                    }
                ]
        | other -> failwith $"unexpected answer: %O{other}"

    [<Test>]
    let ``kill is answered only for the calling process`` () : unit =
        // A pid that differs from the caller's by one, so a comparison against
        // the wrong field (or an off-by-one) is caught.
        UnixSignal.tryKill (Callers.leader linux) (self + 1) 0 linux
        |> shouldEqual (Error (KillRefusal.OtherProcess (self + 1)))

        for pid in [ 0 ; -1 ; -self ; Int32.MinValue ] do
            UnixSignal.tryKill (Callers.leader linux) pid 0 linux
            |> shouldEqual (Error (KillRefusal.ProcessGroup pid))

        // The same pid is the caller's own once the process is configured with it.
        let configured = linuxWithPid (self + 1)

        UnixSignal.tryKill (Callers.leader configured) (self + 1) 0 configured
        |> shouldEqual (Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, configured))))

    [<Test>]
    let ``kill by an init process is refused`` () : unit =
        let init = linuxWithPid 1

        UnixSignal.tryKill (Callers.leader init) 1 9 init
        |> shouldEqual (Error KillRefusal.InitProcess)

    /// Measured by `docs/plans/2026-08-23-posix-kernel-extraction/kill-arguments.c`
    /// on Linux 6.18.5 and Darwin 25.6.0: the rows with the calling process as
    /// the target. 32 and 64 are signals on Linux (the probe sent them to its
    /// own child rather than to itself, and both were accepted) and are past
    /// Darwin's `NSIG` of 32.
    [<Test>]
    let ``kill of the calling process answers the measured rows`` () : unit =
        let answer (flavour : SimulatedUnixFlavour) (signo : int) : string =
            let system = systemOn flavour

            match UnixSignal.tryKill (Callers.leader system) self signo system with
            | Ok (Ok _) -> "OK"
            | Ok (Error errno) -> $"%O{errno}"
            | Error refusal -> $"refused %O{refusal}"

        let rows : (int * string * string) list =
            [
                // signo, Linux, Darwin
                0, "OK", "OK"
                -1, "EINVAL", "EINVAL"
                65, "EINVAL", "EINVAL"
                1000, "EINVAL", "EINVAL"
                Int32.MinValue, "EINVAL", "EINVAL"
                32, "OK", "EINVAL"
                64, "OK", "EINVAL"
            ]

        for signo, onLinux, onDarwin in rows do
            (signo, answer SimulatedUnixFlavour.Linux signo) |> shouldEqual (signo, onLinux)

            (signo, answer SimulatedUnixFlavour.Darwin signo)
            |> shouldEqual (signo, onDarwin)

    [<Test>]
    let ``kill of the calling process is EINVAL exactly when the number is neither 0 nor a signal`` () : unit =
        let gen =
            gen {
                let! flavour = Gen.elements flavours
                let! signo = signoGen
                let! coreDumps = Gen.elements [ CoreDumps.Suppressed ; CoreDumps.Written ]
                return flavour, signo, coreDumps
            }

        let property (flavour : SimulatedUnixFlavour, signo : int, coreDumps : CoreDumps) : unit =
            let system = systemLaunchedWith (ProcessLaunch.withCoreDumps coreDumps) flavour

            let valid = signo >= 0 && signo <= highestSigno flavour

            match UnixSignal.tryKill (Callers.leader system) self signo system, valid with
            | Ok (Error errno), false -> errno |> shouldEqual UnixError.EINVAL
            | Ok (Ok outcome), true ->
                // A valid number is sent, and sending is exactly generating
                // the signal it names at the whole process.
                let expected =
                    if signo = 0 then
                        SignalGeneration.ProcessContinues (Lone.proc system).Signals
                    else
                        match
                            SignalState.generate
                                (Lone.UnixSystemState.signalNumbering system)
                                coreDumps
                                0
                                (Set.singleton 0)
                                {
                                    Signal =
                                        match
                                            Signal.ofRawSignoUnder (Lone.UnixSystemState.signalNumbering system) signo
                                        with
                                        | ValueSome signal -> signal
                                        | ValueNone -> failwith $"%d{signo} was sent, so it is a signal"
                                    Target = ValueNone
                                }
                                (Lone.proc system).Signals
                        with
                        | Ok generation -> generation
                        | Error refusal -> failwith $"generating %d{signo} was refused: %O{refusal}"

                // Everything but the signals is untouched by a process that
                // carries on or stops.
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
                | ProcessFate.ProcessEnded (ended, after), SignalGeneration.ProcessTerminated (signal, coreDumped) ->
                    EndedProcess.termination ended
                    |> shouldEqual (ProcessTermination.Signaled (signal, coreDumped))

                    EndedMachine.assertAsExit (Callers.leader system) system after
                | _ ->
                    failwith
                        $"kill(self, %d{signo}) under %O{flavour} answered %O{outcome}, but generating it is %O{expected}"

            | other, _ -> failwith $"kill(self, %d{signo}) under %O{flavour}: valid=%b{valid}, got %O{other}"

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen gen) property)

    /// Linux finds the target before it looks at the signal number: `kill(2)`
    /// of a pid naming no process is ESRCH whatever the number, where Darwin
    /// says EINVAL (measured, `kill-arguments.c`). Whether a pid names a process
    /// is exactly what this kernel cannot know, so a number it would call
    /// EINVAL for the calling process must still be refused for another.
    [<Test>]
    let ``kill of any other target is refused whatever the signal number`` () : unit =
        let gen =
            gen {
                let! flavour = Gen.elements flavours
                let! pid = ArbMap.defaults |> ArbMap.generate<int> |> Gen.filter (fun pid -> pid <> self)
                let! signo = signoGen
                return flavour, pid, signo
            }

        let property (flavour : SimulatedUnixFlavour, pid : int, signo : int) : unit =
            let system = systemOn flavour

            match UnixSignal.tryKill (Callers.leader system) pid signo system with
            | Error (KillRefusal.OtherProcess refused) when pid > 0 -> refused |> shouldEqual pid
            | Error (KillRefusal.ProcessGroup refused) when pid <= 0 -> refused |> shouldEqual pid
            | other -> failwith $"kill(%d{pid}, %d{signo}) under %O{flavour}: expected a refusal, got %O{other}"

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen gen) property)

    // ------------- A default that terminates, taken on return ------------- //

    /// `SIG_BLOCK` and `SIG_UNBLOCK` as each `<signal.h>` numbers them.
    let private sigBlock (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 0
        | SimulatedUnixFlavour.Darwin -> 1

    let private sigUnblock (flavour : SimulatedUnixFlavour) : int = sigBlock flavour + 1

    /// The signals a death is checked for, each with the core flag its death
    /// carries under `coreDumps`: SIGQUIT dumps core on both flavours, and
    /// SIGTERM on neither.
    let private fatalSignals (coreDumps : CoreDumps) : (Signal * bool) list =
        [ Signal.SIGTERM, false ; Signal.SIGQUIT, (coreDumps = CoreDumps.Written) ]

    /// A process of `flavour` whose only thread blocks `signal`, which it has
    /// sent itself with `kill(2)`, so that it is pending at its default.
    let private pendingBehindMask
        (flavour : SimulatedUnixFlavour)
        (coreDumps : CoreDumps)
        (signal : Signal)
        : UnixSystem<int, string>
        =
        let system = systemLaunchedWith (ProcessLaunch.withCoreDumps coreDumps) flavour
        let numbering = Lone.UnixSystemState.signalNumbering system
        let only = SignalMask.ofSignals numbering (Set.singleton signal)

        let system =
            match UnixSignal.pthreadSigmask (Callers.thread 0 system) (sigBlock flavour) (Some only) system with
            | Ok (_, system) -> system
            | Error errno -> failwith $"pthread_sigmask: %O{errno}"

        match UnixSignal.tryKill (Callers.leader system) self (Signal.toRawSignoUnder numbering signal) system with
        | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> system
        | other -> failwith $"kill(self, %O{signal}) under %O{flavour}: %O{other}"

    /// The process `before` was, ended by `onReturnToUser` of its only thread:
    /// how it ended. The system it leaves holds no process, and is what
    /// `exit_group` leaves of `before`.
    let private endedOnReturn (before : UnixSystem<int, string>) : ProcessTermination =
        match UnixSignal.tryOnReturnToUser (Callers.thread 0 before) before with
        | Ok (ProcessFate.ProcessEnded (ended, after)) ->
            EndedProcess.processId ended |> shouldEqual (Lone.pid before)
            EndedMachine.assertNoneLeft after
            EndedMachine.assertAsExit (Callers.thread 0 before) before after
            EndedProcess.termination ended
        | other -> failwith $"onReturnToUser answered %O{other}"

    [<Test>]
    let ``a pending default that terminates, which sigsuspend unblocks, ends the process as the thread returns``
        ()
        : unit
        =
        for flavour in flavours do
            for coreDumps in [ CoreDumps.Suppressed ; CoreDumps.Written ] do
                for signal, coreDumped in fatalSignals coreDumps do
                    let suspended =
                        let pending = pendingBehindMask flavour coreDumps signal

                        match UnixSignal.trySigsuspend (Callers.thread 0 pending) SignalMask.empty pending with
                        | Ok (SigsuspendOutcome.Failed UnixError.EINTR, system) -> system
                        | other -> failwith $"sigsuspend under %O{flavour}: %O{other}"

                    let expected = ProcessTermination.Signaled (signal, coreDumped)
                    endedOnReturn suspended |> shouldEqual expected

    [<Test>]
    let ``a pending default that terminates, which pthread_sigmask unblocks, ends the process as the thread returns``
        ()
        : unit
        =
        for flavour in flavours do
            for coreDumps in [ CoreDumps.Suppressed ; CoreDumps.Written ] do
                for signal, coreDumped in fatalSignals coreDumps do
                    let pending = pendingBehindMask flavour coreDumps signal
                    let numbering = Lone.UnixSystemState.signalNumbering pending
                    let only = SignalMask.ofSignals numbering (Set.singleton signal)

                    let unblocked =
                        match
                            UnixSignal.pthreadSigmask
                                (Callers.thread 0 pending)
                                (sigUnblock flavour)
                                (Some only)
                                pending
                        with
                        | Ok (_, system) -> system
                        | Error errno -> failwith $"pthread_sigmask: %O{errno}"

                    let expected = ProcessTermination.Signaled (signal, coreDumped)
                    endedOnReturn unblocked |> shouldEqual expected

    /// The signals the property below sends, between them at every default
    /// action: SIGTERM and SIGHUP terminate, SIGQUIT terminates with a core
    /// dump, SIGCHLD is ignored, SIGCONT continues and SIGTSTP stops.
    let private returnPool : Signal list =
        [
            Signal.SIGTERM
            Signal.SIGHUP
            Signal.SIGQUIT
            Signal.SIGUSR1
            Signal.SIGCHLD
            Signal.SIGCONT
            Signal.SIGTSTP
        ]

    /// One send: `kill(2)` of the calling process when `target` is `None`, and
    /// `pthread_kill(3)` of the thread `target` names otherwise.
    type private Send =
        {
            Target : int option
            Signal : Signal
        }

    type private ReturnCase =
        {
            Flavour : SimulatedUnixFlavour
            CoreDumps : CoreDumps
            /// How many threads the process has, numbered from 0, its leader.
            Threads : int
            Dispositions : (Signal * SignalDisposition<string>) list
            /// Each thread's mask while the signals are sent.
            BlockedWhileSent : Set<Signal> list
            Sends : Send list
            /// The thread that returns to user mode, and the mask it does so under.
            Returning : int
            MaskOnReturn : Set<Signal>
        }

    let private returnCaseGen : Gen<ReturnCase> =
        gen {
            let! flavour = Gen.elements flavours
            let! coreDumps = Gen.elements [ CoreDumps.Suppressed ; CoreDumps.Written ]
            let! threads = Gen.choose (1, 2)

            let disposition : Gen<SignalDisposition<string>> =
                Gen.frequency
                    [
                        3, Gen.constant SignalDisposition.Default
                        1, Gen.constant SignalDisposition.Ignore
                        1, Gen.constant (SignalDisposition.Catch (SignalCatch.ofHandler "h"))
                    ]

            let! dispositions = Gen.listOfLength returnPool.Length disposition
            let someSignals = Gen.subListOf returnPool |> Gen.map Set.ofList

            // Mostly everything blocked, so that the sends stay pending rather
            // than taking their defaults at once.
            let blocked =
                Gen.frequency [ 3, Gen.constant (Set.ofList returnPool) ; 1, someSignals ]

            let! blockedWhileSent = Gen.listOfLength threads blocked

            let send =
                gen {
                    let! target = Gen.elements (None :: List.init threads Some)
                    let! signal = Gen.elements returnPool

                    return
                        {
                            Target = target
                            Signal = signal
                        }
                }

            let! sends = Gen.choose (0, 5) |> Gen.bind (fun n -> Gen.listOfLength n send)
            let! returning = Gen.choose (0, threads - 1)
            let! maskOnReturn = someSignals

            return
                {
                    Flavour = flavour
                    CoreDumps = coreDumps
                    Threads = threads
                    Dispositions = List.zip returnPool dispositions
                    BlockedWhileSent = blockedWhileSent
                    Sends = sends
                    Returning = returning
                    MaskOnReturn = maskOnReturn
                }
        }

    /// The process `case` describes, with its signals sent: `None` if a send
    /// stopped or ended it at once, as `kill` and `pthread_kill` answer that.
    /// The paths of a return to user mode that the property must reach.
    [<RequireQualifiedAccess>]
    type private ReturnLabel =
        /// A default that terminates ended the process.
        | Ended
        /// Such an ending dumped core.
        | DumpedCore
        /// The return pushed handler frames.
        | RanHandlers

    let private sentFor (case : ReturnCase) : UnixSystem<int, string> option =
        let setMask (thread : int) (signals : Set<Signal>) (system : UnixSystem<int, string>) =
            let mask =
                SignalMask.ofSignals (Lone.UnixSystemState.signalNumbering system) signals

            match
                UnixSignal.pthreadSigmask (Callers.thread thread system) (sigBlock case.Flavour + 2) (Some mask) system
            with
            | Ok (_, system) -> system
            | Error errno -> failwith $"pthread_sigmask: %O{errno}"

        let booted =
            systemLaunchedWith (ProcessLaunch.withCoreDumps case.CoreDumps) case.Flavour
            |> fun system ->
                (system, [ 1 .. case.Threads - 1 ])
                ||> List.fold (fun system thread -> Threads.spawn thread system)

        let configured =
            (booted, case.Dispositions)
            ||> List.fold (fun system (signal, disposition) ->
                match
                    UnixSignal.sigaction
                        (Callers.leader system)
                        (Signal.toRawSignoUnder (Lone.UnixSystemState.signalNumbering system) signal)
                        (Some disposition)
                        system
                with
                | Ok (_, system) -> system
                | Error errno -> failwith $"sigaction of %O{signal}: %O{errno}"
            )

        let masked =
            (configured, List.indexed case.BlockedWhileSent)
            ||> List.fold (fun system (thread, signals) -> setMask thread signals system)

        let sent =
            (Some masked, case.Sends)
            ||> List.fold (fun system send ->
                match system with
                | None -> None
                | Some system ->

                let signo =
                    Signal.toRawSignoUnder (Lone.UnixSystemState.signalNumbering system) send.Signal

                let answer =
                    match send.Target with
                    | None ->
                        UnixSignal.tryKill (Callers.leader system) self signo system
                        |> Result.mapError (fun refusal -> $"%O{refusal}")
                    | Some thread ->
                        UnixSignal.tryPthreadKill (Callers.leader system) thread signo system
                        |> Result.mapError (fun refusal -> $"%O{refusal}")

                match answer with
                | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> Some system
                | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessStopped _, _)))
                | Ok (Ok (ProcessFate.ProcessEnded _)) -> None
                // A signal the leader blocks and another thread does not is
                // refused; the send is skipped.
                | Error _ -> Some system
                | Ok (Error errno) -> failwith $"sending %O{send.Signal}: %O{errno}"
            )

        sent |> Option.map (setMask case.Returning case.MaskOnReturn)

    [<Test>]
    let ``a thread's return to user mode answers what the signal state decides, and a default that terminates ends the process``
        ()
        : unit
        =
        let property (cover : ReturnLabel -> unit) (case : ReturnCase) : unit =
            match sentFor case with
            | None -> ()
            | Some system ->

            let threads = Lone.threads system |> Map.keys |> Set.ofSeq

            let decided =
                SignalState.onReturnToUser
                    (Lone.UnixSystemState.signalNumbering system)
                    (Lone.proc system).CoreDumps
                    (Lone.leader system)
                    threads
                    case.Returning
                    (Lone.proc system).Signals

            let withSignals (signals : SignalState<int, string>) : UnixSystem<int, string> =
                system
                |> Lone.mapProc (fun proc ->
                    { proc with
                        Signals = signals
                    }
                )

            match UnixSignal.tryOnReturnToUser (Callers.thread case.Returning system) system, decided with
            | Error refusal, Error expected -> refusal |> shouldEqual (ReturnToUserRefusal.Receiver expected)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, after)), Ok (None, signals) ->
                after |> shouldEqual (withSignals signals)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers frames, after)),
              Ok (Some (SignalDelivery.RunHandlers expected), signals) ->
                cover ReturnLabel.RanHandlers
                frames |> shouldEqual expected
                after |> shouldEqual (withSignals signals)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped signal, after)),
              Ok (Some (SignalDelivery.DefaultStop expected), signals) ->
                signal |> shouldEqual expected
                after |> shouldEqual (withSignals signals)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ContinueDiscarded signal, after)),
              Ok (Some (SignalDelivery.DefaultContinue expected), signals) ->
                signal |> shouldEqual expected
                after |> shouldEqual (withSignals signals)
            | Ok (ProcessFate.ProcessEnded (death, after)),
              Ok (Some (SignalDelivery.DefaultTerminate (signal, coreDumped)), _) ->
                cover ReturnLabel.Ended

                if coreDumped then
                    cover ReturnLabel.DumpedCore

                // Of the pool, SIGQUIT alone dumps core, on both flavours.
                coreDumped
                |> shouldEqual (signal = Signal.SIGQUIT && case.CoreDumps = CoreDumps.Written)

                EndedProcess.termination death
                |> shouldEqual (ProcessTermination.Signaled (signal, coreDumped))

                EndedMachine.assertNoneLeft after
                EndedMachine.assertAsExit (Callers.thread case.Returning system) system after
            | actual, expected ->
                failwith $"onReturnToUser answered %A{actual}, but the signal state decided %A{expected}"

        let coverage =
            CoverageSample.check (Config.QuickThrowOnFailure.WithMaxTest 2000) (Arb.fromGen returnCaseGen) property

        // Each about a third of what the fixed sample reaches.
        coverage.Count ReturnLabel.Ended |> shouldBeGreaterThan 121
        coverage.Count ReturnLabel.DumpedCore |> shouldBeGreaterThan 15
        coverage.Count ReturnLabel.RanHandlers |> shouldBeGreaterThan 59
