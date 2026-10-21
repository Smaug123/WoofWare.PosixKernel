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
        | Ok (ProcessFate.ProcessEnded (ended, after)) ->
            EndedProcess.termination ended
            |> shouldEqual (ProcessTermination.Signaled (Signal.SIGKILL, false))

            EndedProcess.processId ended |> shouldEqual (Lone.pid system)
            EndedMachine.assertAsExit (Callers.leader system) system after
        | other -> failwith $"unexpected answer: %O{other}"

    [<Test>]
    let ``sigreturn of a frame that is not the thread's innermost is the client's mistake`` () : unit =
        for flavour in flavours do
            let refused (frame : HandlerFrameId) (system : UnixSystem<int, string>) : unit =
                let exn =
                    Assert.Throws<ArgumentException> (fun () ->
                        UnixSignal.sigreturn (Callers.leader system) frame system
                        |> ignore<UnixSystem<int, string>>
                    )

                exn.ParamName |> shouldEqual "frame"

            let none = systemOn flavour
            refused (HandlerFrameId 0L) none

            let twice =
                none
                |> HandlerFrames.enterIn "outer" 0 Set.empty
                |> HandlerFrames.enterIn "inner" 0 Set.empty

            match SignalState.framesOf 0 (Lone.proc twice).Signals with
            | [ inner ; outer ] ->
                refused outer.Id twice

                UnixSignal.sigreturn (Callers.leader twice) inner.Id twice
                |> fun system -> SignalState.framesOf 0 (Lone.proc system).Signals
                |> List.map (fun frame -> frame.Id)
                |> shouldEqual [ outer.Id ]
            | frames -> failwith $"expected two frames, got %A{frames}"

    [<Test>]
    let ``a death by a signal that dumps core carries the core flag exactly when the process writes dumps`` () : unit =
        // SIGQUIT dumps core on both flavours; SIGTERM on neither.
        for flavour in flavours do
            for coreDumps in [ CoreDumps.Suppressed ; CoreDumps.Written ] do
                let system = systemLaunchedWith (ProcessLaunch.withCoreDumps coreDumps) flavour

                let death (signo : int) : ProcessTermination =
                    match UnixSignal.tryKill (Callers.leader system) self signo system with
                    | Ok (ProcessFate.ProcessEnded (ended, _)) -> EndedProcess.termination ended
                    | other -> failwith $"kill(self, %d{signo}) under %O{flavour}: %O{other}"

                death 3
                |> shouldEqual (ProcessTermination.Signaled (Signal.SIGQUIT, coreDumps = CoreDumps.Written))

                death 15 |> shouldEqual (ProcessTermination.Signaled (Signal.SIGTERM, false))

    [<Test>]
    let ``the null signal to the calling process changes nothing`` () : unit =
        for flavour in flavours do
            let system = systemOn flavour

            UnixSignal.tryKill (Callers.leader system) self 0 system
            |> shouldEqual (Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)))

    [<Test>]
    let ``a signal the calling process cannot yet receive is left pending`` () : unit =
        // Its only thread is in a handler that blocks SIGTERM, so SIGTERM waits
        // in the process-wide pending set.
        let blocking = linux |> HandlerFrames.enterIn "h" 0 (Set.singleton Signal.SIGTERM)

        match UnixSignal.tryKill (Callers.leader blocking) self 15 blocking with
        | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, after)) ->
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
    let ``kill of a pid next to the caller's, which names nothing, is ESRCH`` () : unit =
        // A pid that differs from the caller's by one, so a comparison against
        // the wrong field (or an off-by-one) is caught.
        UnixSignal.tryKill (Callers.leader linux) (self + 1) 0 linux
        |> shouldEqual (Ok (ProcessFate.Continues (KillAnswer.Failed UnixError.ESRCH, linux)))

        for pid in [ 0 ; -1 ; -self ; Int32.MinValue ] do
            UnixSignal.tryKill (Callers.leader linux) pid 0 linux
            |> shouldEqual (Error (KillRefusal.ProcessGroup pid))

        // The same pid is the caller's own once the process is configured with it.
        let configured = linuxWithPid (self + 1)

        UnixSignal.tryKill (Callers.leader configured) (self + 1) 0 configured
        |> shouldEqual (Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, configured)))

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
            | Ok (ProcessFate.Continues (KillAnswer.Completed _, _))
            | Ok (ProcessFate.ProcessEnded _) -> "OK"
            | Ok (ProcessFate.Continues (KillAnswer.Failed errno, after)) ->
                after |> shouldEqual system
                $"%O{errno}"
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
            | Ok (ProcessFate.Continues (KillAnswer.Failed errno, after)), false ->
                errno |> shouldEqual UnixError.EINVAL
                after |> shouldEqual system
            | Ok outcome, true ->
                // A valid number is sent, and sending is exactly generating
                // the signal it names at the whole process.
                let expected =
                    if signo = 0 then
                        SignalGeneration.ProcessContinues (Lone.proc system).Signals
                    else
                        match
                            SignalState.generate
                                (Kernel.signalNumbering system)
                                coreDumps
                                (QueueAccounts.ofLone SignalSender.Kill system)
                                0
                                false
                                (Set.singleton 0)
                                {
                                    Signal =
                                        match Signal.ofRawSignoUnder (Kernel.signalNumbering system) signo with
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
                | ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, after),
                  SignalGeneration.ProcessContinues signals ->
                    (Lone.proc after).Signals |> shouldEqual signals
                    survivor after
                | ProcessFate.Continues (KillAnswer.Completed (KillOutcome.ProcessStopped stoppedBy), after),
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
    /// says EINVAL (measured, `kill-arguments.c`). In a machine of one process
    /// with one thread, every positive pid but the caller's and 1 names
    /// nothing; 1 and every pid of 0 or below are refused whatever the number.
    [<Test>]
    let ``kill of any other target is ESRCH, after Darwin's EINVAL, or refused`` () : unit =
        let gen =
            gen {
                let! flavour = Gen.elements flavours
                let! pid = ArbMap.defaults |> ArbMap.generate<int> |> Gen.filter (fun pid -> pid <> self)
                let! signo = signoGen
                return flavour, pid, signo
            }

        let property (flavour : SimulatedUnixFlavour, pid : int, signo : int) : unit =
            let system = systemOn flavour

            let invalid =
                signo <> 0
                && (Signal.ofRawSignoUnder (HostPlatform.signalNumberingOf flavour) signo).IsNone

            match UnixSignal.tryKill (Callers.leader system) pid signo system with
            | Error (KillRefusal.ProcessGroup refused) when pid <= 0 -> refused |> shouldEqual pid
            | Error KillRefusal.ProcessOne when pid = 1 -> ()
            | Ok (ProcessFate.Continues (KillAnswer.Failed UnixError.EINVAL, after)) when
                pid > 1 && flavour = SimulatedUnixFlavour.Darwin && invalid && after = system
                ->
                ()
            | Ok (ProcessFate.Continues (KillAnswer.Failed UnixError.ESRCH, after)) when
                pid > 1
                && (flavour = SimulatedUnixFlavour.Linux || not invalid)
                && after = system
                ->
                ()
            | other -> failwith $"kill(%d{pid}, %d{signo}) under %O{flavour}: got %O{other}"

        Check.One (propertyConfig, Prop.forAll (Arb.fromGen gen) property)

    // ------------- A default that terminates, taken on return ------------- //

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
        let numbering = Kernel.signalNumbering system
        let only = SignalMask.ofSignals numbering (Set.singleton signal)

        let system =
            match UnixSignal.pthreadSigmask (Callers.thread 0 system) (MaskHow.block numbering) (Some only) system with
            | SignalMaskAnswer.Completed _, system -> system
            | SignalMaskAnswer.Failed errno, _ -> failwith $"pthread_sigmask: %O{errno}"

        match UnixSignal.tryKill (Callers.leader system) self (Signal.toRawSignoUnder numbering signal) system with
        | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) -> system
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
                        | Ok (SigsuspendOutcome.Interrupted, system) -> system
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
                    let numbering = Kernel.signalNumbering pending
                    let only = SignalMask.ofSignals numbering (Set.singleton signal)

                    let unblocked =
                        match
                            UnixSignal.pthreadSigmask
                                (Callers.thread 0 pending)
                                (MaskHow.unblock numbering)
                                (Some only)
                                pending
                        with
                        | SignalMaskAnswer.Completed _, system -> system
                        | SignalMaskAnswer.Failed errno, _ -> failwith $"pthread_sigmask: %O{errno}"

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

    /// The thread that sends `ReturnCase.Sends`: none of the case's, and
    /// blocking every signal, so that it takes none of them. A send leaves its
    /// sender owing a return to user mode when the sender would take what it
    /// sent, so a thread of the case would have to take each before its next
    /// send.
    let private sender : int = 9

    let private sentFor (case : ReturnCase) : UnixSystem<int, string> option =
        let setMask (thread : int) (signals : Set<Signal>) (system : UnixSystem<int, string>) =
            let numbering = Kernel.signalNumbering system
            let mask = SignalMask.ofSignals numbering signals

            match
                UnixSignal.pthreadSigmask (Callers.thread thread system) (MaskHow.setMask numbering) (Some mask) system
            with
            | SignalMaskAnswer.Completed _, system -> system
            | SignalMaskAnswer.Failed errno, _ -> failwith $"pthread_sigmask: %O{errno}"

        let booted =
            systemLaunchedWith (ProcessLaunch.withCoreDumps case.CoreDumps) case.Flavour
            |> fun system ->
                (system, [ 1 .. case.Threads - 1 ] @ [ sender ])
                ||> List.fold (fun system thread -> Threads.spawn thread system)
            |> setMask sender (Set.ofList returnPool)

        let configured =
            (booted, case.Dispositions)
            ||> List.fold (fun system (signal, disposition) ->
                match
                    UnixSignal.sigaction
                        (Callers.leader system)
                        (Signal.toRawSignoUnder (Kernel.signalNumbering system) signal)
                        (Some disposition)
                        system
                with
                | SigactionAnswer.Completed _, system -> system
                | SigactionAnswer.Failed errno, _ -> failwith $"sigaction of %O{signal}: %O{errno}"
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

                let signo = Signal.toRawSignoUnder (Kernel.signalNumbering system) send.Signal

                let answer =
                    match send.Target with
                    | None ->
                        UnixSignal.tryKill (Callers.thread sender system) self signo system
                        |> Result.mapError (fun refusal -> $"%O{refusal}")
                    | Some thread ->
                        UnixSignal.tryPthreadKill (Callers.thread sender system) thread signo system
                        |> Result.mapError (fun refusal -> $"%O{refusal}")

                match answer with
                | Ok (ProcessFate.Continues (KillAnswer.Completed KillOutcome.ProcessRuns, system)) -> Some system
                | Ok (ProcessFate.Continues (KillAnswer.Completed (KillOutcome.ProcessStopped _), _))
                | Ok (ProcessFate.ProcessEnded _) -> None
                // A signal the leader blocks and another thread does not is
                // refused; the send is skipped.
                | Error _ -> Some system
                | Ok (ProcessFate.Continues (KillAnswer.Failed errno, _)) ->
                    failwith $"sending %O{send.Signal}: %O{errno}"
            )

        // The mask the returning thread returns under, written into the state
        // rather than set by a mask call: a send may have made a signal
        // deliverable to the thread under the mask it was sent under, and a
        // thread that owes a return to user mode makes no call.
        let maskedOnReturn (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let numbering = Kernel.signalNumbering system

            system
            |> Lone.mapProc (fun proc ->
                { proc with
                    Signals =
                        SignalState.changeMask
                            numbering
                            SignalMaskChange.SetMask
                            (SignalMask.ofSignals numbering case.MaskOnReturn)
                            case.Returning
                            proc.Signals
                }
            )

        sent |> Option.map maskedOnReturn

    [<Test>]
    let ``a thread's return to user mode answers what the signal state decides, and a default that terminates ends the process``
        ()
        : unit
        =
        let property (cover : ReturnLabel -> unit) (case : ReturnCase) : unit =
            match sentFor case with
            | None -> ()
            | Some system ->

            let threads = Lone.threadMap system |> Map.keys |> Set.ofSeq

            let decided =
                SignalState.onReturnToUser
                    (Kernel.signalNumbering system)
                    (Lone.proc system).CoreDumps
                    (Lone.leader system)
                    threads
                    case.Returning
                    (Lone.proc system).Signals

            // Whether, under `signals`, a signal is deliverable to `thread`: one
            // its mask lets through, of its own set, of the process's if it is
            // the leader, and under Linux of the process's where the leader
            // blocks it.
            let deliverable (signals : SignalState<int, string>) (thread : int) : bool =
                let leader = Lone.leader system

                SignalState.pending signals
                |> List.exists (fun entry ->
                    not (SignalMask.contains entry.Signal (SignalState.maskOf thread signals))
                    && (
                        match entry.Target with
                        | ValueSome target -> target = thread
                        | ValueNone ->
                            thread = leader
                            || (case.Flavour = SimulatedUnixFlavour.Linux
                                && SignalMask.contains entry.Signal (SignalState.maskOf leader signals))
                    )
                )

            // The system with `signals`, as a return that `goesOn` or is over
            // leaves it: the returning thread owing the rest of a return that
            // goes on. One that is over leaves the thread owing the rest where
            // a signal is still deliverable to it; and, for the leader, whose
            // frames may come to block a signal of the process's, each other
            // thread owing one where such a signal is now deliverable to it.
            let withSignalsAfter (goesOn : bool) (signals : SignalState<int, string>) : UnixSystem<int, string> =
                let returned =
                    system
                    |> Lone.mapProc (fun proc ->
                        { proc with
                            Signals = signals
                        }
                    )
                    |> ForgedThread.settled (Callers.thread case.Returning system)

                if goesOn then
                    returned
                    |> ForgedThread.owing (Callers.thread case.Returning system) OwedReturn.SignalDue
                else

                let marked =
                    if case.Returning = Lone.leader system then
                        threads
                    else
                        Set.singleton case.Returning

                (returned, marked)
                ||> Set.fold (fun returned thread ->
                    match Lone.owedBy thread returned with
                    | None when deliverable signals thread ->
                        returned
                        |> ForgedThread.owing (Callers.thread thread returned) OwedReturn.SignalDue
                    | Some _
                    | None -> returned
                )

            let withSignals : SignalState<int, string> -> UnixSystem<int, string> =
                withSignalsAfter false

            match UnixSignal.tryOnReturnToUser (Callers.thread case.Returning system) system, decided with
            | Error refusal, Error expected -> refusal |> shouldEqual (ReturnToUserRefusal.Receiver expected)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes None, after)), Ok (None, signals) ->
                after |> shouldEqual (withSignals signals)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers (frames, None), after)),
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

                // The return is not over: the thread owes the rest of it.
                after |> shouldEqual (withSignalsAfter true signals)
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
