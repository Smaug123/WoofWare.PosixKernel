namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A call a caught signal interrupted, whose signal another thread's
/// `sigaction` changes before the interrupted thread returns to user mode.
///
/// `docs/probes/disposition-before-return` measured, on Linux 6.18.5 and
/// Darwin 27.0.0, a sleeping thread signalled with a caught SIGUSR1 (handler
/// h1, with `SA_RESTART` or without) whose disposition the main thread then
/// changed before the sleeper ran: left as it was, ignored, reset to its
/// default (which terminates), or swapped for handler h2 with the other
/// `SA_RESTART`. Every row is replayed here three times: with the change made
/// after the woken sleeper's call has answered `Interrupted` and before its
/// return to user mode, where this library decides the call's end; with the
/// change made after the sleeper is woken and before its call is finished, as
/// the probe made it; and with the change made before the client's sweep has
/// woken the sleeper.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDispositionBeforeReturn =

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    /// The thread that sleeps.
    let private sleeper : int = 1

    let private port : uint16 = 5000us

    let private platformOf (flavour : SimulatedUnixFlavour) : SimulatedUnixPlatform = HostPlatform.platformOf flavour

    let private usr1 (system : UnixSystem<int, string>) : int32 =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (UnixSystem.platform system)) Signal.SIGUSR1

    let private handler (name : string) (restart : bool) : SignalDisposition<string> =
        SignalDisposition.Catch
            { SignalCatch.ofHandler name with
                Restart = restart
            }

    /// `disposition` installed for SIGUSR1 by the process's leader.
    let private install
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match UnixSignal.sigaction (Callers.leader system) (usr1 system) (Some disposition) system with
        | Ok (_, system) -> system
        | Error error -> failwith $"sigaction failed with %O{error}"

    // ------------------------------------------------------------------
    // The probe's rows
    // ------------------------------------------------------------------

    /// What the main thread did to SIGUSR1 between the signal and the
    /// sleeper's return.
    [<RequireQualifiedAccess>]
    type private Change =
        | Nothing
        | Ignore
        | Default
        | Swap

    /// How the sleeper's call ended, as the probe saw it: which handler ran,
    /// if any, and whether the call returned EINTR or went on sleeping, which
    /// is what a restart does; or the process died of SIGUSR1.
    [<RequireQualifiedAccess>]
    type private Seen =
        | Eintr of handler : string option
        | Restarts of handler : string option
        | Killed
        /// The library will not say.
        | Refused of ReturnToUserRefusal

    type private Row =
        {
            Flavour : SimulatedUnixFlavour
            Call : string
            Restart : bool
            Change : Change
            Seen : Seen
            Line : string
        }

    let private rowPattern : Regex =
        Regex
            @"^(linux|darwin) call=(\S+) restart=([01]) change=(none|ign|dfl|swap) mode=held .*?(?:returned-before-release=([01]) ret=(\S+) errno=(.+?) h1=(\d) h2=(\d) release-handler=\d )?end=(\S+)$"

    /// The held rows of `flavour`'s committed output.
    let private rows (flavour : SimulatedUnixFlavour) : Row list =
        let name =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.disposition-before-return.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.disposition-before-return.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new System.IO.StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.filter (fun line -> line.Contains " mode=held")
        |> Array.map (fun line ->
            let m = rowPattern.Match line

            if not m.Success then
                failwith $"not a row of the probe: %s{line}"

            let change =
                match m.Groups.[4].Value with
                | "none" -> Change.Nothing
                | "ign" -> Change.Ignore
                | "dfl" -> Change.Default
                | _ -> Change.Swap

            let seen =
                if m.Groups.[10].Value.StartsWith "signal" then
                    Seen.Killed
                else

                let ran =
                    match m.Groups.[8].Value, m.Groups.[9].Value with
                    | "1", "0" -> Some "h1"
                    | "0", "1" -> Some "h2"
                    | "0", "0" -> None
                    | h1, h2 -> failwith $"both handlers ran (%s{h1}, %s{h2}): %s{line}"

                match m.Groups.[5].Value with
                | "1" ->
                    (m.Groups.[6].Value, m.Groups.[7].Value)
                    |> shouldEqual ("-1", "Interrupted system call")

                    Seen.Eintr ran
                | "0" -> Seen.Restarts ran
                | other -> failwith $"returned-before-release=%s{other}: %s{line}"

            {
                Flavour = flavour
                Call = m.Groups.[2].Value
                Restart = m.Groups.[3].Value = "1"
                Change = change
                Seen = seen
                Line = line
            }
        )
        |> List.ofArray

    // ------------------------------------------------------------------
    // Each call, made asleep as the probe made it
    // ------------------------------------------------------------------

    /// `system` once the leader has sent the sleeper SIGUSR1.
    let private signalled (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixSignal.tryPthreadKill (Callers.leader system) sleeper (usr1 system) system with
        | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) -> system
        | other -> failwith $"pthread_kill: %A{other}"

    let private pipe (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
        | Ok (Pipe2Answer.Created (r, w), system) -> r, w, system
        | other -> failwith $"pipe2: %A{other}"

    /// The leader's non-blocking writes of 64 KiB through `fd` until `EAGAIN`,
    /// then of one byte until `EAGAIN`, `fd` left blocking.
    let private fill (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) fd true system

        let rec go (chunk : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match
                WriteOutcomes.admitThenWrite
                    0
                    fd
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> chunk))
                    system
            with
            | Ok (WriteStep.Returns (WriteAnswer.Completed _, system)) -> go chunk system
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.EAGAIN, system)) -> system
            | other -> failwith $"filling fd %d{fd}: %A{other}"

        let system = system |> go 65536 |> go 1
        UnixDescriptor.setNonBlocking (Callers.leader system) fd false system |> snd

    /// A connected loopback pair, both ends blocking: the connecting socket's
    /// descriptor, then the accepted one's.
    let private tcpPair (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        let listener, system = KeventWorld.listenerAt port system
        let client, system = KeventWorld.stream false system

        let system =
            match KeventWorld.connect client port system with
            | SyscallAnswer.Completed 0L, system -> system
            | other, _ -> failwith $"connect: %A{other}"

        let server, system = KeventWorld.accept listener system
        let system = KeventWorld.close listener system

        let _, system =
            UnixDescriptor.setNonBlocking (Callers.leader system) server false system

        client, server, system

    let private sleeps<'Answer, 'Refusal>
        (what : string)
        (isPark : 'Answer -> bool)
        (outcome : Result<'Answer * UnixSystem<int, string>, 'Refusal>)
        : UnixSystem<int, string>
        =
        match outcome with
        | Ok (answer, system) when isPark answer -> system
        | other -> failwith $"expected the %s{what} to sleep, got %A{other}"

    let private readParks (outcome : ReadOutcome) : bool =
        match outcome with
        | ReadOutcome.WouldBlock _ -> true
        | _ -> false

    /// `system` with the sleeper asleep in `call`, made on `flavour`; a
    /// `poll`, `epoll_wait` or `kevent` with a timeout of `milliseconds`, or
    /// none for -1, and every other call with none.
    let private asleepWithTimeoutIn
        (flavour : SimulatedUnixFlavour)
        (call : string)
        (milliseconds : int)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let s (system : UnixSystem<int, string>) = Callers.thread sleeper system

        match flavour, call with
        | _, "pause" ->
            match UnixSignal.tryPause (s system) system with
            | Ok (SigsuspendOutcome.WouldBlock _, system) -> system
            | other -> failwith $"expected the pause to sleep, got %A{other}"
        | _, "sigsuspend" ->
            match UnixSignal.trySigsuspend (s system) SignalMask.empty system with
            | Ok (SigsuspendOutcome.WouldBlock _, system) -> system
            | other -> failwith $"expected the sigsuspend to sleep, got %A{other}"
        | _, "read" ->
            let r, _, system = pipe system

            UnixReadWrite.tryRead (s system) r UserBuffer.Mapped 1UL system
            |> sleeps "read" readParks
        | _, "write" ->
            let _, w, system = pipe system
            let system = fill w system

            match
                WriteOutcomes.admitThenWrite sleeper w UserBuffer.Mapped (ImmutableArray.Create<byte> [| 7uy |]) system
            with
            | Ok (WriteStep.WouldBlock (_, system)) -> system
            | other -> failwith $"expected the write to sleep, got %A{other}"
        | _, "poll" ->
            let r, _, system = pipe system

            UnixPoll.tryPoll
                (s system)
                [
                    {
                        Fd = r
                        Events = 0x0001s
                    }
                ]
                milliseconds
                system
            |> sleeps
                "poll"
                (fun outcome ->
                    match outcome with
                    | PollOutcome.WouldBlock _ -> true
                    | _ -> false
                )
        | SimulatedUnixFlavour.Linux, "epoll" ->
            // A listener with nothing queued, edge-triggered, where the probe's
            // was an empty pipe, level-triggered, neither of which this library
            // models under epoll: neither is ready, and the signal ends the
            // wait alike.
            let listener, system = KeventWorld.listenerAt port system

            let epoll, system =
                match UnixPoll.tryEpollCreate1 (Callers.leader system) 0 system with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                | other -> failwith $"epoll_create1: %A{other}"

            let system =
                match
                    UnixPoll.tryEpollCtl
                        (Callers.leader system)
                        epoll
                        1
                        listener
                        (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.EdgeTriggered, 7UL))
                        system
                with
                | Ok (EpollCtlAnswer.Changed, system) -> system
                | other -> failwith $"epoll_ctl: %A{other}"

            UnixPoll.tryEpollWait (s system) epoll 1 UserBuffer.Mapped milliseconds system
            |> sleeps
                "epoll_wait"
                (fun outcome ->
                    match outcome with
                    | EpollWaitOutcome.WouldBlock _ -> true
                    | _ -> false
                )
        | SimulatedUnixFlavour.Darwin, "kevent" ->
            // EVFILT_READ of a listener with nothing queued, where the probe's
            // was of an empty pipe, whose filter this library does not model:
            // neither is ready, and the signal ends the wait alike.
            let listener, system = KeventWorld.listenerAt port system
            let kq, system = KeventWorld.kqueue system

            let system =
                match
                    KeventWorld.applyAs
                        (Callers.leader system)
                        kq
                        [ KeventWorld.change listener -1s 0x0001us 7UL ]
                        0
                        system
                with
                | KeventOutcome.Answered [], system -> system
                | other, _ -> failwith $"registering EVFILT_READ: %A{other}"

            let timeout =
                if milliseconds < 0 then
                    TimespecArgument.Null
                else
                    TimespecArgument.Readable
                        {
                            Seconds = int64 (milliseconds / 1000)
                            Nanoseconds = int64 (milliseconds % 1000) * 1_000_000L
                        }

            UnixKqueue.tryKevent (s system) kq 0 [] 1 UserBuffer.Mapped timeout system
            |> sleeps
                "kevent"
                (fun outcome ->
                    match outcome with
                    | KeventOutcome.WouldBlock _ -> true
                    | _ -> false
                )
        | _, "flock" ->
            let flags =
                OpenFlagWords.bitOf (UnixSystem.platform system) OpenFlagBit.Create ||| 2

            let opened (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
                match OpenOutcomes.openPath (PathArg.ofText "/lock") flags 0o644 system with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                | other -> failwith $"open: %A{other}"

            let holder, system = opened system
            let waiter, system = opened system

            let system =
                match UnixDescriptor.tryFlock (Callers.leader system) holder 2 system with
                | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> system
                | other -> failwith $"the holder's flock: %A{other}"

            UnixDescriptor.tryFlock (s system) waiter 2 system
            |> sleeps
                "flock"
                (fun outcome ->
                    match outcome with
                    | SyscallOutcome.WouldBlock _ -> true
                    | _ -> false
                )
        | _, "accept" ->
            let listener, system = KeventWorld.listenerAt port system

            UnixConnection.tryAccept (s system) listener UserBuffer.Mapped 16u system
            |> sleeps
                "accept"
                (fun outcome ->
                    match outcome with
                    | AcceptOutcome.WouldBlock _ -> true
                    | _ -> false
                )
        | _, "tcp-read" ->
            let client, _, system = tcpPair system

            UnixReadWrite.tryRead (s system) client UserBuffer.Mapped 1UL system
            |> sleeps "TCP read" readParks
        | _, "tcp-write" ->
            let client, _, system = tcpPair system
            let system = fill client system

            match
                WriteOutcomes.admitThenWrite
                    sleeper
                    client
                    UserBuffer.Mapped
                    (ImmutableArray.Create<byte> (Array.zeroCreate<byte> 1000))
                    system
            with
            | Ok (WriteStep.WouldBlock (_, system)) -> system
            | other -> failwith $"expected the TCP write to sleep, got %A{other}"
        | SimulatedUnixFlavour.Linux, "inotify" ->
            let fd, system =
                match UnixInotify.tryInotifyInit1 (Callers.leader system) 0 system with
                | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                | other -> failwith $"inotify_init1: %A{other}"

            let system =
                match Eager.tryInotifyAddWatch fd (PathArg.ofText "/") 0x100u system with
                | Ok (_, system) -> system
                | Error refusal -> failwith $"inotify_add_watch: %A{refusal}"

            UnixReadWrite.tryRead (s system) fd UserBuffer.Mapped 4096UL system
            |> sleeps "inotify read" readParks
        | _ -> failwith $"%O{flavour} has no call %s{call} here"

    /// `system` with the sleeper asleep in `call`, made on `flavour`, with no
    /// timeout.
    let private asleepIn
        (flavour : SimulatedUnixFlavour)
        (call : string)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        asleepWithTimeoutIn flavour call -1 system

    /// A machine of `flavour` whose sleeper is asleep in `call`, with a
    /// timeout of `milliseconds` where `asleepWithTimeoutIn` gives it one, and
    /// SIGUSR1 caught by h1, installed with `SA_RESTART` or not as `restart`
    /// says.
    let private asleep
        (flavour : SimulatedUnixFlavour)
        (call : string)
        (restart : bool)
        (milliseconds : int)
        : UnixSystem<int, string>
        =
        UnixSystem.initial<int, string> (platformOf flavour)
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> Threads.spawn sleeper
        |> install (handler "h1" restart)
        |> asleepWithTimeoutIn flavour call milliseconds

    /// How the woken sleeper's call finished: `Interrupted`, or asleep again.
    [<RequireQualifiedAccess>]
    type private Finished =
        | Interrupted of UnixSystem<int, string>
        | SleepsOn

    let private finish (call : string) (system : UnixSystem<int, string>) : Finished =
        let s = Callers.thread sleeper system

        let unexpected (other : obj) : Finished =
            failwith $"finishing the %s{call}: %A{other}"

        match call with
        | "pause"
        | "sigsuspend" ->
            match UnixSignal.tryFinishSigsuspend s system with
            | Ok (SigsuspendOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (SigsuspendOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | "read"
        | "tcp-read"
        | "inotify" ->
            match UnixReadWrite.tryFinishRead s system with
            | Ok (ReadOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (ReadOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | "write"
        | "tcp-write" ->
            match UnixReadWrite.tryFinishWrite s system with
            | Ok (CallProgress.Answered (ProcessFate.Continues (WriteOutcome.Interrupted, system))) ->
                Finished.Interrupted system
            | Ok (CallProgress.Answered (ProcessFate.Continues (WriteOutcome.WouldBlock _, _))) -> Finished.SleepsOn
            | other -> unexpected other
        | "poll" ->
            match UnixPoll.tryFinishPoll s system with
            | Ok (PollOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (PollOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | "epoll" ->
            match UnixPoll.tryFinishEpollWait s system with
            | Ok (EpollWaitOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (EpollWaitOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | "kevent" ->
            match UnixKqueue.tryFinishKevent s system with
            | Ok (KeventOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (KeventOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | "flock" ->
            match UnixDescriptor.tryFlockAcquire s system with
            | Ok (SyscallOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (SyscallOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | "accept" ->
            match UnixConnection.tryFinishAccept s system with
            | Ok (AcceptOutcome.Interrupted, system) -> Finished.Interrupted system
            | Ok (AcceptOutcome.WouldBlock _, _) -> Finished.SleepsOn
            | other -> unexpected other
        | _ -> failwith $"no call %s{call}"

    /// The sleeper's return to user mode from its interrupted call.
    let private returned (system : UnixSystem<int, string>) : Seen =
        let ran (frames : HandlerFrame<int, string> list) : string option =
            match frames with
            | [] -> None
            | [ frame ] -> Some frame.Action.Handler
            | frames -> failwith $"the return pushed %d{frames.Length} frames"

        match Interruptions.settle (Callers.thread sleeper system) system with
        | Settled.Ends (InterruptedCall.FailsWithEintr, frames, _) -> Seen.Eintr (ran frames)
        | Settled.Ends (InterruptedCall.Restarts, frames, _) -> Seen.Restarts (ran frames)
        | Settled.ProcessEnded (ended, _) ->
            EndedProcess.termination ended
            |> shouldEqual (ProcessTermination.Signaled (Signal.SIGUSR1, false))

            Seen.Killed
        | Settled.Refused refusal -> Seen.Refused refusal

    /// When the change comes: after the woken sleeper's call has answered
    /// (`AfterFinish`); after the client's sweep has woken the sleeper and
    /// before its call is finished (`BeforeFinish`), which is where the probe
    /// made it, a real kernel waking the sleeper as the signal is sent; or
    /// before that sweep (`BeforeWake`), which only a client that skips the
    /// sweep after the `pthread_kill` reaches.
    [<RequireQualifiedAccess>]
    type private Window =
        | AfterFinish
        | BeforeFinish
        | BeforeWake

    /// What this library answers for `row`, with the change made in `window`.
    let private replay (window : Window) (row : Row) : Seen =
        let change (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match row.Change with
            | Change.Nothing -> system
            | Change.Ignore -> install SignalDisposition.Ignore system
            | Change.Default -> install SignalDisposition.Default system
            | Change.Swap -> install (handler "h2" (not row.Restart)) system

        let system = asleep row.Flavour row.Call row.Restart -1 |> signalled

        let finished (system : UnixSystem<int, string>) : Seen =
            match finish row.Call system with
            | Finished.Interrupted system -> returned system
            // Nothing the sleeper takes is left, so it goes on sleeping, no
            // handler run.
            | Finished.SleepsOn -> Seen.Restarts None

        match window with
        | Window.AfterFinish ->
            match finish row.Call (Woken.thread sleeper system) with
            | Finished.Interrupted system -> returned (change system)
            | Finished.SleepsOn -> failwith "the signal woke the sleeper, which slept on"
        | Window.BeforeFinish -> finished (change (Woken.thread sleeper system))
        | Window.BeforeWake ->
            let system = change system
            let woken, system = UnixWait.wake system

            if woken |> List.exists (fun (caller, _) -> caller = Callers.thread sleeper system) then
                finished system
            else
                // Nothing woke the sleeper, which sleeps on, no handler run.
                Seen.Restarts None

    /// What this library answers for `row`, with the change made in `window`,
    /// where that is not what the probe saw.
    let private divergent (window : Window) (row : Row) : Seen option =
        let darwinChanged =
            Seen.Refused (
                ReturnToUserRefusal.ChangedSinceInterruption (Some Signal.SIGUSR1, SimulatedUnixFlavour.Darwin)
            )

        let restartable =
            [ "read" ; "write" ; "flock" ; "accept" ; "tcp-read" ; "tcp-write" ]

        match window, row.Flavour, row.Change with
        // Darwin's `_sleep` reads SA_RESTART as the woken thread runs, by its
        // source, which the probe's hold cannot tell from the return, so a
        // return whose end differs from the one it would have had as the
        // call was interrupted is refused: an ignored signal, after h1 would
        // have failed the call with EINTR, where it then sleeps on; and a swap
        // to h2's other SA_RESTART, for a call SA_RESTART restarts.
        | Window.AfterFinish, SimulatedUnixFlavour.Darwin, Change.Ignore when
            row.Call = "pause" || row.Call = "sigsuspend"
            ->
            Some darwinChanged
        | Window.AfterFinish, SimulatedUnixFlavour.Darwin, Change.Ignore when
            List.contains row.Call restartable && not row.Restart
            ->
            Some darwinChanged
        | Window.AfterFinish, SimulatedUnixFlavour.Darwin, Change.Swap when List.contains row.Call restartable ->
            Some darwinChanged
        // A real kernel wakes the sleeper as the signal is sent, and this
        // library as the client's sweep finds it deliverable. With the signal
        // ignored before that sweep, nothing wakes the sleeper, which sleeps
        // on, where Linux's epoll_wait and Darwin's poll and kevent fail with
        // EINTR. Every other call sleeps on either way.
        | Window.BeforeWake, SimulatedUnixFlavour.Linux, Change.Ignore when row.Call = "epoll" ->
            Some (Seen.Restarts None)
        | Window.BeforeWake, SimulatedUnixFlavour.Darwin, Change.Ignore when row.Call = "poll" || row.Call = "kevent" ->
            Some (Seen.Restarts None)
        | _ -> None

    [<TestCaseSource(nameof flavours)>]
    let ``every held row of the probe replays, changed after the call answers, before, or before the wake``
        (flavour : SimulatedUnixFlavour)
        : unit
        =
        let rows = rows flavour

        // A control, so that this cannot pass by reading no rows: every call
        // under both flags and all four changes.
        rows.Length
        |> shouldEqual (
            match flavour with
            | SimulatedUnixFlavour.Linux -> 88
            | SimulatedUnixFlavour.Darwin -> 80
        )

        let mismatches =
            [
                for window in [ Window.AfterFinish ; Window.BeforeFinish ; Window.BeforeWake ] do
                    for row in rows do
                        let expected = divergent window row |> Option.defaultValue row.Seen
                        let actual = replay window row

                        if actual <> expected then
                            yield $"%A{window} %s{row.Line}: expected %A{expected}, got %A{actual}"
            ]

        mismatches |> shouldEqual []

    /// The bug the probe's `ign` rows measure: a `pause` a caught signal
    /// interrupted, whose signal another thread ignores before the paused
    /// thread returns to user mode.
    let private pauseIgnored (flavour : SimulatedUnixFlavour) : Seen =
        replay
            Window.AfterFinish
            {
                Flavour = flavour
                Call = "pause"
                Restart = false
                Change = Change.Ignore
                Seen = Seen.Killed
                Line = "pause, ignored after it answered"
            }

    [<TestCaseSource(nameof flavours)>]
    let ``an interrupted pause never answers EINTR with no handler run`` (flavour : SimulatedUnixFlavour) : unit =
        match flavour, pauseIgnored flavour with
        | _, Seen.Eintr None -> failwith "pause returned EINTR, and no handler ran"
        // Linux restarts it, as measured.
        | SimulatedUnixFlavour.Linux, seen -> seen |> shouldEqual (Seen.Restarts None)
        // Darwin may decide as the woken thread runs, and is refused.
        | SimulatedUnixFlavour.Darwin, seen ->
            seen
            |> shouldEqual (
                Seen.Refused (
                    ReturnToUserRefusal.ChangedSinceInterruption (Some Signal.SIGUSR1, SimulatedUnixFlavour.Darwin)
                )
            )

    [<TestCaseSource(nameof flavours)>]
    let ``a default that terminates ends the process at the return`` (flavour : SimulatedUnixFlavour) : unit =
        replay
            Window.AfterFinish
            {
                Flavour = flavour
                Call = "pause"
                Restart = false
                Change = Change.Default
                Seen = Seen.Killed
                Line = "pause, reset to its default after it answered"
            }
        |> shouldEqual Seen.Killed

    [<Test>]
    let ``a Linux pause that restarts sleeps again when it is made again`` () : unit =
        let system =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn sleeper
            |> install (handler "h1" false)
            |> asleepIn SimulatedUnixFlavour.Linux "pause"

        let system =
            match finish "pause" (Woken.thread sleeper (signalled system)) with
            | Finished.Interrupted system -> install SignalDisposition.Ignore system
            | Finished.SleepsOn -> failwith "the signal woke the sleeper, which slept on"

        // Until it returns, the interrupted thread makes no call.
        Assert.Throws<System.InvalidOperationException> (fun () ->
            UnixSignal.pause (Callers.thread sleeper system) system |> ignore
        )
        |> ignore<System.InvalidOperationException>

        match Interruptions.settle (Callers.thread sleeper system) system with
        | Settled.Ends (InterruptedCall.Restarts, [], system) ->
            match UnixSignal.pause (Callers.thread sleeper system) system with
            | SigsuspendOutcome.WouldBlock _, system ->
                UnixThreadState.parkedIn (Lone.threadMap system).[sleeper]
                |> shouldEqual (Some ParkedSyscall.SigSuspend)
            | other -> failwith $"the pause made again: %A{other}"
        | other -> failwith $"the return: %A{other}"

    /// The sleeper asleep in `call` on `flavour` with a timeout of a second,
    /// and the deadline it waits for.
    let private asleepForASecond (flavour : SimulatedUnixFlavour) (call : string) : UnixSystem<int, string> * int64 =
        let system = asleep flavour call false 1000

        match UnixWait.deadlines system with
        | [ deadline ] -> system, deadline
        | other -> failwith $"expected the %s{call} to wait for one deadline, got %A{other}"

    /// `system` once SIGUSR1 has woken the sleeper and the leader has then
    /// ignored it, before the sleeper's call is finished.
    let private wokenThenIgnored (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        signalled system |> Woken.thread sleeper |> install SignalDisposition.Ignore

    [<TestCaseSource(nameof flavours)>]
    let ``a call whose waking signal is ignored before it is finished sleeps again there, or is interrupted to fail``
        (flavour : SimulatedUnixFlavour)
        : unit
        =
        // A call the probe saw sleep on is put back to sleep by its finishing
        // call, which is its restart, rather than interrupted for its return
        // to restart it; one the probe saw fail with EINTR is interrupted.
        let ignored = rows flavour |> List.filter (fun row -> row.Change = Change.Ignore)

        // A control, so that this cannot pass by reading no rows: every call
        // under both flags.
        ignored.Length
        |> shouldEqual (
            match flavour with
            | SimulatedUnixFlavour.Linux -> 22
            | SimulatedUnixFlavour.Darwin -> 20
        )

        let mismatches =
            [
                for row in ignored do
                    let finished =
                        asleep row.Flavour row.Call row.Restart -1
                        |> wokenThenIgnored
                        |> finish row.Call

                    match row.Seen, finished with
                    | Seen.Restarts None, Finished.SleepsOn
                    | Seen.Eintr None, Finished.Interrupted _ -> ()
                    | seen, Finished.SleepsOn -> yield $"%s{row.Line}: the probe saw %A{seen}, and it slept again"
                    | seen, Finished.Interrupted _ ->
                        yield $"%s{row.Line}: the probe saw %A{seen}, and it was interrupted"
            ]

        mismatches |> shouldEqual []

    [<Test>]
    let ``a Linux poll with a timeout, its waking signal ignored before it is finished, sleeps on to its deadline``
        ()
        : unit
        =
        // Linux restarts such a poll with what is left of its timeout
        // (`SyscallInterruption.withoutHandler`), which sleeping on to the
        // same deadline is.
        let system, deadline = asleepForASecond SimulatedUnixFlavour.Linux "poll"
        let system = wokenThenIgnored system

        match UnixPoll.tryFinishPoll (Callers.thread sleeper system) system with
        | Ok (PollOutcome.WouldBlock _, system) -> UnixWait.deadlines system |> shouldEqual [ deadline ]
        | other -> failwith $"finishing the poll: %A{other}"

    /// Each flavour's waits that fail with `EINTR` once their waking signal
    /// has gone, which `docs/probes/disposition-before-return` measured only
    /// without a timeout.
    let private timedUnmeasured : TestCaseData list =
        [
            SimulatedUnixFlavour.Linux, "epoll"
            SimulatedUnixFlavour.Darwin, "poll"
            SimulatedUnixFlavour.Darwin, "kevent"
        ]
        |> List.map (fun (flavour, call) -> TestCaseData (flavour, call))

    [<TestCaseSource(nameof timedUnmeasured)>]
    let ``a timed wait the probe measured untimed, its waking signal ignored before it is finished, is refused``
        (flavour : SimulatedUnixFlavour, call : string)
        : unit
        =
        let system = asleepForASecond flavour call |> fst |> wokenThenIgnored
        let s = Callers.thread sleeper system

        let refusal =
            match call with
            | "epoll" ->
                match UnixPoll.tryFinishEpollWait s system with
                | Error (EpollWaitRefusal.Interruption refusal) -> refusal
                | other -> failwith $"finishing the epoll_wait: %A{other}"
            | "poll" ->
                match UnixPoll.tryFinishPoll s system with
                | Error (PollRefusal.Interruption refusal) -> refusal
                | other -> failwith $"finishing the poll: %A{other}"
            | _ ->
                match UnixKqueue.tryFinishKevent s system with
                | Error (KeventRefusal.Interruption refusal) -> refusal
                | other -> failwith $"finishing the kevent: %A{other}"

        refusal |> shouldEqual SyscallInterruptionRefusal.WakingSignalGone
