namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A call a caught signal interrupted, whose signal another thread's
/// `sigaction` makes undeliverable before the interrupted thread returns to
/// user mode.
///
/// `docs/probes/disposition-before-return` measured what a real kernel does
/// there: no kernel answers the interrupted call's EINTR without running a
/// handler for it, unless the call is one that fails with EINTR when no
/// handler runs at all.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDispositionBeforeReturn =

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    /// The thread that sleeps in `pause`.
    let private sleeper : int = 1

    let private platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform = HostPlatform.platformOf flavour

    let private signo (flavour : SimulatedUnixFlavour) (signal : Signal) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (platformOf flavour)) signal

    let private install
        (flavour : SimulatedUnixFlavour)
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction (Callers.leader system) (signo flavour Signal.SIGUSR1) (Some disposition) system with
        | Ok (_, system) -> system
        | Error error -> failwith $"sigaction failed with %O{error}"

    /// What the program sees of its `pause`, once the sleeper has returned to
    /// user mode.
    [<RequireQualifiedAccess>]
    type private Seen =
        /// `pause` returned -1 with EINTR, having run this many handlers first.
        | Eintr of handlers : int
        /// The process ended.
        | Ended
        /// Anything else.
        | Other of string

    /// Thread 1 pauses, the leader sends it SIGUSR1, caught by a handler; the
    /// sleeper is woken and its call finished; then the leader installs `later`
    /// for SIGUSR1, and the sleeper returns to user mode.
    let private run (flavour : SimulatedUnixFlavour) (later : SignalDisposition<string>) : Seen =
        let system =
            UnixSystem.initial<int, string> (platformOf flavour)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn sleeper
            |> install flavour (SignalDisposition.Catch (SignalCatch.ofHandler "h"))

        let system =
            match UnixSignal.pause (Callers.thread sleeper system) system with
            | SigsuspendOutcome.WouldBlock _, system -> system
            | other -> failwith $"expected pause to sleep, got %A{other}"

        let system =
            match UnixSignal.pthreadKill (Callers.leader system) sleeper (signo flavour Signal.SIGUSR1) system with
            | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> system
            | other -> failwith $"expected the signal to be sent, got %A{other}"

        let system = Woken.thread sleeper system

        let finished, system =
            UnixSignal.finishSigsuspend (Callers.thread sleeper system) system

        let system = install flavour later system

        match finished, UnixSignal.onReturnToUser (Callers.thread sleeper system) system with
        | _, ProcessFate.ProcessEnded _ -> Seen.Ended
        | SigsuspendOutcome.Failed UnixError.EINTR, ProcessFate.Continues (ReturnToUserOutcome.Resumes, _) ->
            Seen.Eintr 0
        | SigsuspendOutcome.Failed UnixError.EINTR, ProcessFate.Continues (ReturnToUserOutcome.RunHandlers frames, _) ->
            Seen.Eintr frames.Length
        | finished, returned -> Seen.Other $"%A{finished}, then %A{returned}"

    [<TestCaseSource(nameof flavours)>]
    let ``an interrupted pause never answers EINTR with no handler run`` (flavour : SimulatedUnixFlavour) : unit =
        match run flavour SignalDisposition.Ignore with
        | Seen.Eintr 0 -> failwith "pause returned EINTR, and no handler ran"
        | _ -> ()

    [<TestCaseSource(nameof flavours)>]
    let ``a default that terminates ends the process at the return`` (flavour : SimulatedUnixFlavour) : unit =
        run flavour SignalDisposition.Default |> shouldEqual Seen.Ended
