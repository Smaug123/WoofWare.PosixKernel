namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which thread receives a signal sent to the whole process, held to the rows of
/// `docs/plans/2026-08-23-posix-kernel-extraction/signal-receiver.c`, checked in
/// as `signalReceiver/linux.txt` (Linux 6.18.5, aarch64) and
/// `signalReceiver/darwin.txt` (Darwin 27.0.0).
///
/// There, four threads (T0 the main thread) handled SIGUSR1, each set of them
/// short of all four blocked it, and each thread in turn sent it eight times.
/// Whenever T0 did not block it, every send went to T0; the library models that.
/// When T0 blocked it, the flavours chose another thread each by its own rule,
/// Linux's depending on earlier sends; the library refuses those.
///
/// And what such a signal did once a thread other than T0 unblocked it, sent
/// while every thread blocked it, held to the rows of
/// `docs/probes/non-leader-unblock`.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSignalReceiver =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 500

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    /// A system of four threads, 0 its leader, under `flavour`, with SIGUSR1
    /// at `disposition`, and every thread in `blocking` inside a handler that
    /// blocks it.
    let private systemWith
        (flavour : SimulatedUnixFlavour)
        (disposition : SignalDisposition<string>)
        (blocking : Set<int>)
        : UnixSystem<int, string>
        =
        let system =
            UnixSystem.initial (HostPlatform.platformOf flavour)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.spawn 1
            |> Threads.spawn 2
            |> Threads.spawn 3

        let system =
            { system with
                Process =
                    { system.Process with
                        Signals = SignalState.setDisposition Signal.SIGUSR1 disposition system.Process.Signals
                    }
            }

        (system, blocking)
        ||> Set.fold (fun system thread -> HandlerFrames.enterIn "carrier" thread (Set.singleton Signal.SIGUSR1) system)

    let private usr1 (flavour : SimulatedUnixFlavour) : int =
        Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering (HostPlatform.platformOf flavour)) Signal.SIGUSR1

    let private self (system : UnixSystem<int, string>) : int32 =
        ProcessId.toInt32 (UnixSystem.processId system)

    /// The handler frames each of the four threads takes next, in thread order:
    /// `None` for a thread that takes nothing.
    let private takenBy (system : UnixSystem<int, string>) : HandlerFrame<int, string> list option list =
        [ 0..3 ]
        |> List.map (fun thread ->
            match UnixSignal.tryOnReturnToUser thread system with
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, _)) -> None
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers frames, _)) -> Some frames
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped _, _) as other)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ContinueDiscarded _, _) as other)
            | Ok (ProcessFate.ProcessEnded _ as other) -> failwith $"thread %d{thread} took %A{other}"
            | Error refusal -> failwith $"thread %d{thread} was refused: %O{refusal}"
        )

    /// Send SIGUSR1 to the process, and say which threads take it.
    let private receivers (flavour : SimulatedUnixFlavour) (blocking : Set<int>) : Result<int list, KillRefusal> =
        let system =
            systemWith flavour (SignalDisposition.Catch (SignalCatch.ofHandler "h")) blocking

        match UnixSignal.tryKill (self system) (usr1 flavour) system with
        | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))) ->
            takenBy system
            |> List.indexed
            |> List.choose (fun (thread, delivery) ->
                match delivery with
                | Some [ frame ] when frame.Entry.Signal = Signal.SIGUSR1 && frame.Action.Handler = "h" -> Some thread
                | None -> None
                | Some other -> failwith $"thread %d{thread} took %A{other}"
            )
            |> Ok
        | Ok other -> failwith $"kill did not leave the signal to be taken: %A{other}"
        | Error refusal -> Error refusal

    let private rows (flavour : string) : string list =
        let assembly = Assembly.GetExecutingAssembly ()
        let name = $"WoofWare.PosixKernel.Test.signalReceiver.%s{flavour}.txt"

        use stream =
            match assembly.GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))

    [<Literal>]
    let private RowPattern =
        @"^(sleep|spin) +round\d blocked=\{((?:T\d)*)\} sender=T(\d) receivers:((?: T\d)+)$"

    /// Replay every row of one flavour's file, answering how many rows the model
    /// answered and how many it refused.
    let private replay (flavour : SimulatedUnixFlavour) (file : string) : int * int =
        let mutable answered = 0
        let mutable refused = 0

        for line in rows file do
            let row = Regex.Match (line, RowPattern)

            if not row.Success then
                failwith $"%s{file}: unrecognised row: %s{line}"

            let threadsIn (text : string) : int list =
                Regex.Matches (text, @"T(\d)")
                |> Seq.map (fun m -> Int32.Parse m.Groups.[1].Value)
                |> Seq.toList

            let blocking = threadsIn row.Groups.[2].Value |> Set.ofList
            let measured = threadsIn row.Groups.[4].Value |> List.distinct

            match receivers flavour blocking with
            | Ok taken ->
                if taken <> measured then
                    failwith
                        $"%s{file}: the model gave the signal to %A{taken}, the kernel to %A{measured}, in: %s{line}"

                answered <- answered + 1
            | Error refusal ->
                refusal
                |> shouldEqual (KillRefusal.Receiver (SignalReceiverRefusal.LeaderBlocks Signal.SIGUSR1))

                // Refused exactly when the kernel gave it to another thread.
                if List.contains 0 measured then
                    failwith $"%s{file}: the model refused a signal the kernel gave to the leader, in: %s{line}"

                refused <- refused + 1

        answered, refused

    [<Test>]
    let ``every Linux row of the receiver probe`` () : unit =
        // 2 idle modes x 3 rounds x 4 senders: 8 sets without T0 are answered,
        // and 7 with it refused.
        replay SimulatedUnixFlavour.Linux "linux" |> shouldEqual (192, 168)

    [<Test>]
    let ``every Darwin row of the receiver probe`` () : unit =
        replay SimulatedUnixFlavour.Darwin "darwin" |> shouldEqual (192, 168)

    [<Test>]
    let ``a caught signal sent to the process goes to the leader whatever the other threads block`` () : unit =
        let property (flavour : SimulatedUnixFlavour) (others : bool list) : unit =
            let blocking =
                others
                |> List.truncate 3
                |> List.indexed
                |> List.choose (fun (i, blocks) -> if blocks then Some (i + 1) else None)
                |> Set.ofList

            receivers flavour blocking |> shouldEqual (Ok [ 0 ])

        Check.One (propertyConfig, property)

    [<Test>]
    let ``a signal every thread blocks is left pending on the process`` () : unit =
        for flavour in flavours do
            let system =
                systemWith flavour (SignalDisposition.Catch (SignalCatch.ofHandler "h")) (Set.ofList [ 0..3 ])

            match UnixSignal.tryKill (self system) (usr1 flavour) system with
            | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after))) ->
                SignalState.pending after.Process.Signals
                |> shouldEqual
                    [
                        {
                            Signal = Signal.SIGUSR1
                            Target = ValueNone
                        }
                    ]

                takenBy after |> shouldEqual [ None ; None ; None ; None ]
            | other -> failwith $"%O{flavour}: %A{other}"

    [<Test>]
    let ``a signal whose default ends the process is answered when the leader blocks it`` () : unit =
        // Which thread receives it does not matter: SIGUSR1 at its default ends the
        // process.
        for flavour in flavours do
            let system = systemWith flavour SignalDisposition.Default (Set.ofList [ 0 ; 2 ])

            match UnixSignal.tryKill (self system) (usr1 flavour) system with
            | Ok (Ok (ProcessFate.ProcessEnded ended)) ->
                ended.Termination
                |> shouldEqual (ProcessTermination.Signaled (Signal.SIGUSR1, false))
            | other -> failwith $"%O{flavour}: %A{other}"

    [<Test>]
    let ``an ignored signal the leader blocks is discarded under Darwin and refused under Linux`` () : unit =
        // Measured by `docs/plans/2026-08-23-posix-kernel-extraction/sigcont-generation.c`
        // (the "gen USR1 IGN" rows): Darwin hands it to a thread that does not
        // block it, which discards it; Linux leaves it pending on the process,
        // where the leader's sigpending sees it, until another thread takes it.
        for flavour in flavours do
            let system = systemWith flavour SignalDisposition.Ignore (Set.ofList [ 0 ; 2 ])

            match flavour, UnixSignal.tryKill (self system) (usr1 flavour) system with
            | SimulatedUnixFlavour.Darwin, Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after))) ->
                SignalState.pending after.Process.Signals |> shouldBeEmpty
            | SimulatedUnixFlavour.Linux, Error refusal ->
                refusal
                |> shouldEqual (KillRefusal.Receiver (SignalReceiverRefusal.LeaderBlocks Signal.SIGUSR1))
            | _, other -> failwith $"%O{flavour}: %A{other}"

    [<Test>]
    let ``every thread is refused while a pending caught signal could reach only a thread other than the leader``
        ()
        : unit
        =
        // Pending while every thread blocks it; then thread 2 unblocks it, so a real
        // kernel gives it to thread 2 at once.
        for flavour in flavours do
            let system =
                systemWith flavour (SignalDisposition.Catch (SignalCatch.ofHandler "h")) (Set.ofList [ 0..3 ])

            match UnixSignal.tryKill (self system) (usr1 flavour) system with
            | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after))) ->
                let after =
                    { after with
                        Process =
                            { after.Process with
                                Signals = HandlerFrames.leave 2 after.Process.Signals
                            }
                    }

                for thread in 0..3 do
                    match UnixSignal.tryOnReturnToUser thread after with
                    | Error refusal -> refusal |> shouldEqual (SignalReceiverRefusal.LeaderBlocks Signal.SIGUSR1)
                    | Ok answer -> failwith $"%O{flavour}: thread %d{thread} was answered %A{answer}"
            | other -> failwith $"%O{flavour}: %A{other}"

    [<Test>]
    let ``a signal pending on one thread alone is taken by that thread only`` () : unit =
        for flavour in flavours do
            let system =
                systemWith flavour (SignalDisposition.Catch (SignalCatch.ofHandler "h")) Set.empty

            let signals =
                SignalState.enqueue
                    {
                        Signal = Signal.SIGUSR1
                        Target = ValueSome 2
                    }
                    system.Process.Signals

            let system =
                { system with
                    Process =
                        { system.Process with
                            Signals = signals
                        }
                }

            match takenBy system with
            | [ None ; None ; Some [ frame ] ; None ] ->
                frame.Entry
                |> shouldEqual
                    {
                        Signal = Signal.SIGUSR1
                        Target = ValueSome 2
                    }

                frame.Action.Handler |> shouldEqual "h"
            | other -> failwith $"%O{flavour}: expected thread 2 alone to take it, got %A{other}"

    [<Test>]
    let ``asking for a thread that does not exist fails loudly`` () : unit =
        let system =
            systemWith SimulatedUnixFlavour.Linux (SignalDisposition.Catch (SignalCatch.ofHandler "h")) Set.empty

        let exn =
            Assert.Throws<exn> (fun () -> UnixSignal.tryOnReturnToUser 7 system |> ignore)

        exn.Message |> shouldContainText "not one of the process's threads"

    [<Test>]
    let ``a pending signal whose default ends the process is taken under Linux by the thread that unblocks it``
        ()
        : unit
        =
        // Pending while every thread blocks it; then thread 2 unblocks it. Linux's
        // threads all take from the process's pending set, so thread 2 takes it as
        // it returns, and SIGUSR1 at its default ends the process; the others,
        // which block it, run on meanwhile. Darwin hands a signal sent to the
        // process to its leader as it is sent, which this library does not hold
        // apart from the process's set, so it refuses.
        for flavour in flavours do
            let system = systemWith flavour SignalDisposition.Default (Set.ofList [ 0..3 ])

            match UnixSignal.tryKill (self system) (usr1 flavour) system with
            | Ok (Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, after))) ->
                let after =
                    { after with
                        Process =
                            { after.Process with
                                Signals = HandlerFrames.leave 2 after.Process.Signals
                            }
                    }

                for thread in 0..3 do
                    match flavour, thread, UnixSignal.tryOnReturnToUser thread after with
                    | SimulatedUnixFlavour.Linux, 2, Ok (ProcessFate.ProcessEnded ended) ->
                        EndedProcess.termination ended
                        |> shouldEqual (ProcessTermination.Signaled (Signal.SIGUSR1, false))
                    | SimulatedUnixFlavour.Linux, _, Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, resumed)) when
                        thread <> 2
                        ->
                        SignalState.pending resumed.Process.Signals
                        |> shouldEqual (SignalState.pending after.Process.Signals)
                    | SimulatedUnixFlavour.Darwin, _, Error refusal ->
                        refusal |> shouldEqual (SignalReceiverRefusal.LeaderBlocks Signal.SIGUSR1)
                    | _, _, other -> failwith $"%O{flavour}: thread %d{thread} was answered %A{other}"
            | other -> failwith $"%O{flavour}: %A{other}"

    /// How a row of `docs/probes/non-leader-unblock` ended: the process ran on
    /// with no handler run, a handler ran on a thread (0 the main thread), or a
    /// signal killed or stopped the process.
    [<RequireQualifiedAccess>]
    type private UnblockEnd =
        | RanOn
        | Handled of thread : int
        | Killed of Signal
        | Stopped of Signal

    /// One row of the probe: the signal, whether it was caught, which thread
    /// changed its mask (`none`, `main`, `second`, or `second-ss` for a
    /// `sigsuspend` with an empty mask), what each thread's `sigpending` showed
    /// after the `kill`, and how the process ended.
    type private UnblockRow =
        {
            Line : string
            Signal : Signal
            Caught : bool
            Who : string
            MainPending : uint64
            SecondPending : uint64
            End : UnblockEnd
        }

    let private unblockRows (flavour : SimulatedUnixFlavour) : UnblockRow list =
        let numbering =
            SimulatedUnixPlatform.signalNumbering (HostPlatform.platformOf flavour)

        let name =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.non-leader-unblock.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.non-leader-unblock.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        let signalOf (signo : string) : Signal =
            match Signal.ofRawSignoUnder numbering (Int32.Parse signo) with
            | ValueSome signal -> signal
            | ValueNone -> failwith $"%s{name}: %s{signo} is no signal under %O{numbering}"

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> Array.toList
        |> List.filter (fun line -> not (line.StartsWith ("#", StringComparison.Ordinal)))
        |> List.map (fun line ->
            let row =
                Regex.Match (
                    line,
                    @"^sig=(\d+)\((default|caught)\) who=(none|main|second|second-ss) main-pending=([0-9a-f]+) second-pending=([0-9a-f]+)(.*) end=(exit0|signal(\d+)|stopped(\d+))$"
                )

            if not row.Success then
                failwith $"%s{name}: unrecognised row: %s{line}"

            let handledOn =
                match Regex.Match(row.Groups.[6].Value, @"handler-on=(main|second)").Groups.[1].Value with
                | "main" -> Some 0
                | "second" -> Some 1
                | _ -> None

            let ended =
                match row.Groups.[7].Value, handledOn with
                | "exit0", Some thread -> UnblockEnd.Handled thread
                | "exit0", None -> UnblockEnd.RanOn
                | _ when row.Groups.[8].Success -> UnblockEnd.Killed (signalOf row.Groups.[8].Value)
                | _ -> UnblockEnd.Stopped (signalOf row.Groups.[9].Value)

            {
                Line = line
                Signal = signalOf row.Groups.[1].Value
                Caught = row.Groups.[2].Value = "caught"
                Who = row.Groups.[3].Value
                MainPending = Convert.ToUInt64 (row.Groups.[4].Value, 16)
                SecondPending = Convert.ToUInt64 (row.Groups.[5].Value, 16)
                End = ended
            }
        )

    /// What the model answers for `row`: how the process ends, or the refusal,
    /// described. Asserts on the way that each thread's `sigpending` after the
    /// `kill` is what the probe printed.
    let private modelUnblock (flavour : SimulatedUnixFlavour) (row : UnblockRow) : Result<UnblockEnd, string> =
        let platform = HostPlatform.platformOf flavour
        let numbering = SimulatedUnixPlatform.signalNumbering platform
        let signo = Signal.toRawSignoUnder numbering row.Signal
        let only = SignalMask.ofSignals numbering (Set.singleton row.Signal)

        let how (change : SignalMaskChange) : int =
            match flavour, change with
            | SimulatedUnixFlavour.Linux, SignalMaskChange.Block -> 0
            | SimulatedUnixFlavour.Linux, SignalMaskChange.Unblock -> 1
            | SimulatedUnixFlavour.Darwin, SignalMaskChange.Block -> 1
            | SimulatedUnixFlavour.Darwin, SignalMaskChange.Unblock -> 2
            | _, SignalMaskChange.SetMask -> failwith "unused"

        let resumes (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match UnixSignal.tryOnReturnToUser thread system with
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, system)) -> system
            | other -> failwith $"%s{row.Line}: thread %d{thread} did not resume: %A{other}"

        let mask (thread : int) (change : SignalMaskChange) (system : UnixSystem<int, string>) =
            match UnixSignal.pthreadSigmask thread (how change) (Some only) system with
            | Ok (_, system) -> system
            | Error errno -> failwith $"%s{row.Line}: pthread_sigmask: %O{errno}"

        let booted =
            UnixSystem.initial platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let booted =
            if row.Caught then
                match
                    UnixSignal.sigaction signo (Some (SignalDisposition.Catch (SignalCatch.ofHandler "h"))) booted
                with
                | Ok (_, system) -> resumes 0 system
                | Error errno -> failwith $"%s{row.Line}: sigaction: %O{errno}"
            else
                booted

        // The main thread blocks it and creates the second, which inherits the
        // mask; then it sends the signal to the process.
        let blocked =
            booted |> mask 0 SignalMaskChange.Block |> resumes 0 |> Threads.spawn 1

        let sent =
            match UnixSignal.kill (ProcessId.toInt32 (UnixSystem.processId blocked)) signo blocked with
            | Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system)) -> resumes 0 system
            | other -> failwith $"%s{row.Line}: kill: %A{other}"

        (UnixSignal.sigpending 0 sent |> SignalMask.toWord, UnixSignal.sigpending 1 sent |> SignalMask.toWord)
        |> shouldEqual (row.MainPending, row.SecondPending)

        let returned (thread : int) (system : UnixSystem<int, string>) : Result<UnblockEnd, string> =
            match UnixSignal.tryOnReturnToUser thread system with
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, _)) -> Ok UnblockEnd.RanOn
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers [ frame ], _)) when
                frame.Entry.Signal = row.Signal
                ->
                Ok (UnblockEnd.Handled thread)
            | Ok (ProcessFate.Continues (ReturnToUserOutcome.ProcessStopped signal, _)) ->
                Ok (UnblockEnd.Stopped signal)
            | Ok (ProcessFate.ProcessEnded ended) ->
                match EndedProcess.termination ended with
                | ProcessTermination.Signaled (signal, _) -> Ok (UnblockEnd.Killed signal)
                | other -> failwith $"%s{row.Line}: the process ended by %A{other}"
            | Ok other -> failwith $"%s{row.Line}: thread %d{thread} answered %A{other}"
            | Error refusal -> Error (SignalReceiverRefusal.describe refusal)

        match row.Who with
        | "none" ->
            match returned 1 sent with
            | Ok UnblockEnd.RanOn -> returned 0 sent
            | other -> other
        | "main" -> returned 0 (mask 0 SignalMaskChange.Unblock sent)
        | "second" -> returned 1 (mask 1 SignalMaskChange.Unblock sent)
        | "second-ss" ->
            match UnixSignal.trySigsuspend 1 SignalMask.empty sent with
            | Ok (SigsuspendOutcome.Failed UnixError.EINTR, interrupted) -> returned 1 interrupted
            | Ok (SigsuspendOutcome.WouldBlock _, asleep) -> returned 0 asleep
            | Ok other -> failwith $"%s{row.Line}: sigsuspend answered %A{other}"
            | Error refusal -> Error (SigsuspendRefusal.describe refusal)
        | who -> failwith $"%s{row.Line}: unrecognised thread %s{who}"

    /// Replay every row of one flavour's output of
    /// `docs/probes/non-leader-unblock`: each answered row as the kernel ended
    /// it, and the rest refused. Answers the rows refused, by signal and by
    /// the thread that changed its mask.
    let private replayUnblock (flavour : SimulatedUnixFlavour) : (Signal * string) list =
        let rows = unblockRows flavour

        // A control, so that this cannot pass by reading no rows.
        rows.Length |> shouldEqual 12

        rows
        |> List.choose (fun row ->
            match modelUnblock flavour row with
            | Ok ended ->
                if ended <> row.End then
                    failwith $"%O{flavour}: the model ended %A{ended}, the kernel %A{row.End}, in: %s{row.Line}"

                None
            | Error _ -> Some (row.Signal, row.Who)
        )

    [<Test>]
    let ``every Linux row of the non-leader unblock probe`` () : unit =
        // A caught signal that a thread other than the leader takes is the
        // receiver rule this library does not model, and a stop in sigsuspend
        // is refused as the call's own.
        replayUnblock SimulatedUnixFlavour.Linux
        |> shouldEqual
            [
                Signal.SIGTSTP, "second-ss"
                Signal.SIGUSR1, "second"
                Signal.SIGUSR1, "second-ss"
            ]

    [<Test>]
    let ``every Darwin row of the non-leader unblock probe`` () : unit =
        // Darwin left each signal pending on the main thread, where a second
        // thread's unblocking did not reach it; this library refuses those.
        replayUnblock SimulatedUnixFlavour.Darwin
        |> shouldEqual
            [
                Signal.SIGTERM, "second"
                Signal.SIGTERM, "second-ss"
                Signal.SIGTSTP, "second"
                Signal.SIGTSTP, "second-ss"
                Signal.SIGUSR1, "second"
                Signal.SIGUSR1, "second-ss"
            ]
