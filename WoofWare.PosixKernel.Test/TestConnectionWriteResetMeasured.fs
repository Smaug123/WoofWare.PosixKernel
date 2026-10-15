namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A blocking write to a connected socket whose own bytes make the peer's
/// kernel answer with a reset: the peer has closed, or has shut its side so
/// that bytes arriving there reset the connection. Every row of
/// `docs/probes/connection-write-reset` (measured 2026-10-14 on Linux 6.18.5
/// aarch64 and Darwin 27.0.0 arm64) is replayed against the model, with each
/// flavour's default buffers.
///
/// Linux's write never sleeps there: it returns the count it took, leaving
/// `EPIPE` pending. Darwin's sleeps until the reset arrives, on another
/// thread, and then answers `EPIPE` and raises `SIGPIPE`; this kernel
/// delivers the reset with the bytes that provoke it, so its write parks with
/// its wake condition already holding, and is woken at once.
///
/// Two things measured are not modelled, and the replay says so where it
/// meets them rather than comparing them: the count a Linux write takes
/// before the reset stops it (524288 bytes, or 589347 for a woken write, of a
/// 4 MiB send buffer; this kernel counts bytes, not segments, and takes the
/// send buffer's room), and Darwin's reset arriving while the write is still
/// copying, which answers `ECONNRESET` without `SIGPIPE` and without sleeping.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
[<Order(TestOrder.LongRunning)>]
module TestConnectionWriteResetMeasured =

    /// One line of a probe output, its tab-separated `key=value` fields by
    /// key; a field without `=` is kept under its position.
    type private Line =
        {
            Text : string
            Section : string
            Fields : Map<string, string>
            Positional : string list
        }

    let private parse (text : string) : Line =
        match text.Split '\t' |> List.ofArray with
        | [] -> failwith "an empty line"
        | section :: rest ->
            {
                Text = text
                Section = section
                Fields =
                    rest
                    |> List.choose (fun field ->
                        match field.IndexOf '=' with
                        | -1 -> None
                        | at -> Some (field.Substring (0, at), field.Substring (at + 1))
                    )
                    |> Map.ofList
                Positional = rest |> List.filter (fun field -> not (field.Contains '='))
            }

    let private field (key : string) (line : Line) : string =
        match Map.tryFind key line.Fields with
        | Some value -> value
        | None -> failwith $"no %s{key} in: %s{line.Text}"

    let private resource (platform : SimulatedUnixPlatform) : string =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> "linux"
        | SimulatedUnixFlavour.Darwin -> "darwin"

    let private lines (platform : SimulatedUnixPlatform) : Line list =
        let name =
            $"WoofWare.PosixKernel.Test.connection-write-reset.%s{resource platform}.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        match
            reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
            |> List.ofArray
        with
        | [] -> failwith $"%s{name} is empty"
        | header :: rows ->
            let expected =
                match SimulatedUnixPlatform.flavour platform with
                | SimulatedUnixFlavour.Linux -> "uname: Linux 6.18.5 aarch64"
                | SimulatedUnixFlavour.Darwin -> "uname: Darwin 27.0.0 arm64"

            header |> shouldEqual expected
            rows |> List.map parse

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxArm64 ; SimulatedUnixPlatform.macOsArm64 ]

    let private port : uint16 = 6200us

    /// A system on `platform` with threads 0 and 1, `SIGPIPE` and `SIGUSR1`
    /// caught, without `SA_RESTART`, as the probe has them.
    let private systemOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure 1

        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    proc.Signals
                    |> SignalState.setDisposition
                        (Lone.UnixSystemState.signalNumbering system)
                        Signal.SIGPIPE
                        (SignalDisposition.Catch (SignalCatch.ofHandler "pipe"))
                    |> SignalState.setDisposition
                        (Lone.UnixSystemState.signalNumbering system)
                        Signal.SIGUSR1
                        (SignalDisposition.Catch (SignalCatch.ofHandler "usr1"))
            }
        )

    /// A connected pair on `system`, both blocking: the connecting socket's
    /// descriptor (the probe's `c`), then the accepted one's (`p`).
    let private pair (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
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

    let private shut (fd : int) (how : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixConnection.tryShutdown (Callers.leader system) fd how system with
        | Ok (ShutdownAnswer.Shut, after) -> after
        | other -> failwith $"shutdown(%d{fd}, %d{how}): %A{other}"

    /// The probe's peer states: `p` with nothing done, closed, or shut down.
    let private peerIn (peer : string) (server : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match peer with
        | "open" -> system
        | "close" -> KeventWorld.close server system
        | "shut_rd" -> shut server 0 system
        | "shut_rdwr" -> shut server 2 system
        | other -> failwith $"unknown peer state %s{other}"

    /// `thread` returns to user mode, running every handler it takes.
    let rec private returnToUser (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixSignal.tryOnReturnToUser (Callers.thread thread system) system with
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.Resumes, system)) -> system
        | Ok (ProcessFate.Continues (ReturnToUserOutcome.RunHandlers frames, system)) ->
            (system, frames)
            ||> List.fold (fun system frame -> UnixSignal.sigreturn (Callers.thread thread system) frame.Id system)
            |> returnToUser thread
        | other -> failwith $"returning thread %d{thread} to user mode: %A{other}"

    /// What a call that returned answered, as the probe prints it, with a
    /// count of more than `exact` bytes printed as `count`, since the counts
    /// a write of a large buffer takes are not modelled; and how many
    /// `SIGPIPE`s it raised.
    let private answered
        (exact : int)
        (outcome : Result<WriteStep<WriteAnswer, UnixSystem<int, string>, int>, WriteRefusal>)
        : string * int * UnixSystem<int, string>
        =
        let shown (answer : WriteAnswer) : string =
            match answer with
            | WriteAnswer.Completed n when n > int64 exact -> "count"
            | WriteAnswer.Completed n -> string n
            | WriteAnswer.Failed error -> $"-1 %A{error}"

        match outcome with
        | Ok (WriteStep.Returns (answer, system)) -> shown answer, 0, system
        | Ok (WriteStep.ReturnsRaising (answer, raised, system)) when raised.Signal = Signal.SIGPIPE ->
            shown answer, 1, system
        | other -> failwith $"expected the write to return, got %A{other}"

    let private bytesOf (count : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Seq.init count (fun i -> byte (i % 251)))

    /// The woken write of thread 1, finished, given `bytes`.
    let private finish (bytes : ImmutableArray<byte>) (system : UnixSystem<int, string>) =
        WriteOutcomes.finishWrite 1 (fun offset count -> ImmutableArray.Create (bytes, offset, count)) system

    let private soError (fd : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        match KeventWorld.readSocketError fd system with
        | GetSockOptAnswer.Reported (OptionValue.Int 0), system -> "0", system
        | GetSockOptAnswer.Reported (OptionValue.Int raw), system ->
            match
                UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering system.Machine.UnixPlatform) raw
            with
            | Some error -> $"%A{error}", system
            | None -> failwith $"SO_ERROR read %d{raw}, which names no error"
        | other -> failwith $"SO_ERROR: %A{other}"

    /// A section A row as the probe printed it, or as the model came to it.
    type private RowA =
        {
            /// Whether the call had not returned 300 ms in.
            Asleep : bool
            /// Whether the writer slept in the call.
            Slept : bool
            Answer : string
            SigPipe : int
            SoError : string
            Second : string
            SecondSigPipe : int
        }

    let private measuredA (line : Line) : RowA =
        let count = int (field "N" line)

        let answer =
            match field "answer" line with
            | numeric when not (numeric.StartsWith "-1") && int64 numeric > 100L && count > 100 -> "count"
            | other -> other

        {
            Asleep = List.contains "asleep_at_300ms_then" line.Positional
            Slept = int (field "slept" line) > 0
            Answer = answer
            SigPipe = int (field "sigpipe" line)
            SoError = field "so_error" line
            Second = field "second_write" line
            SecondSigPipe = int (field "second_sigpipe" line)
        }

    /// Section A in the model: a blocking write of `count` bytes by thread 1
    /// to `c`, with `p` in `peer`.
    let private modelA (platform : SimulatedUnixPlatform) (peer : string) (count : int) : RowA =
        let client, server, system = pair (systemOn platform)
        let system = peerIn peer server system
        let bytes = bytesOf count

        let asleep, slept, (answer, sigPipe, system) =
            match WriteOutcomes.admitThenWrite 1 client UserBuffer.Mapped bytes system with
            | Ok (WriteStep.WouldBlock (_, parked)) ->
                match Lone.wake parked with
                // Asleep only until the reset its own bytes provoked, which
                // has arrived.
                | [ 1, _ ], parked -> false, true, answered 100 (finish bytes parked)
                | [], _ ->
                    // Asleep for room: the probe ends the write 300 ms in by
                    // closing `p`, or by shutting `c` down if `p` is closed.
                    let ended =
                        if peer = "close" then
                            shut client 2 parked
                        else
                            KeventWorld.close server parked

                    match Lone.wake ended with
                    | [ 1, _ ], ended -> true, true, answered 100 (finish bytes ended)
                    | other, _ -> failwith $"%O{platform} %s{peer}: the write was not woken by its end: %A{other}"
                | other, _ -> failwith $"%O{platform} %s{peer}: %A{other}"
            | written -> false, false, answered 100 written

        let system = returnToUser 1 system
        let soError, system = soError client system

        let _, system =
            UnixDescriptor.setNonBlocking (Callers.leader system) client true system

        let second, secondSigPipe, _ =
            WriteOutcomes.admitThenWrite 1 client UserBuffer.Mapped (bytesOf 100) system
            |> answered 100

        {
            Asleep = asleep
            Slept = slept
            Answer = answer
            SigPipe = sigPipe
            SoError = soError
            Second = second
            SecondSigPipe = secondSigPipe
        }

    /// Section A: every row, against the model.
    [<Test>]
    let ``a write whose own bytes reset the connection answers as section A measured`` () : unit =
        for platform in platforms do
            let darwin = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin
            let rows = lines platform |> List.filter (fun line -> line.Section = "A")
            rows |> List.length |> shouldEqual 24

            for line in rows do
                let peer = List.head line.Positional
                let count = int (field "N" line)
                let measured = measuredA line
                let modelled = modelA platform peer count

                let expected =
                    match measured with
                    // The reset reached Darwin's writer while it was still
                    // copying, which answers ECONNRESET without SIGPIPE or a
                    // sleep. This kernel delivers the reset with the bytes
                    // that provoke it, so its writer always reaches the sleep,
                    // which the reset then ends as the rows that slept show.
                    | {
                          Answer = "-1 ECONNRESET"
                          Slept = false
                      } when darwin ->
                        { measured with
                            Slept = true
                            Answer = "-1 EPIPE"
                            SigPipe = 1
                        }
                    // On Darwin the reset arrives after the call has
                    // returned, so how much of it SO_ERROR and a second
                    // write see depends on how soon they ask: the model's
                    // reset has always arrived.
                    | _ when darwin && count = 100 && peer <> "open" ->
                        { measured with
                            SoError = modelled.SoError
                            Second = modelled.Second
                            SecondSigPipe = modelled.SecondSigPipe
                        }
                    | _ -> measured

                if modelled <> expected then
                    failwith $"%O{platform}: %s{line.Text}\nmodelled %A{modelled}\nexpected %A{expected}"

    /// Section B: a signal sent to the writer over and over, from before the
    /// write until it returns. Where a row's write never sleeps (Linux's
    /// writes that reset), or sleeps only for room, the model answers what
    /// the row did; where Darwin's sleep ends in a race between the signal and
    /// the reset, the model refuses, as it refuses every Darwin race between a
    /// signal and the call's own answer.
    [<Test>]
    let ``a signal beside a write whose own bytes reset the connection answers as section B measured`` () : unit =
        for platform in platforms do
            let tallies =
                lines platform
                |> List.filter (fun line -> line.Section = "B" && List.contains "tally" line.Positional)

            tallies |> List.length |> shouldEqual 4

            for line in tallies do
                let peer = List.head line.Positional
                let counts = int ((field "count" line).Split(' ').[0])
                let raced = int (field "ECONNRESET" line) + int (field "EPIPE" line)
                let client, server, system = pair (systemOn platform)
                let system = peerIn peer server system

                let system =
                    system
                    |> Lone.mapProc (fun proc ->
                        { proc with
                            Signals =
                                SignalState.enqueue
                                    (Lone.UnixSystemState.signalNumbering system)
                                    {
                                        Signal = Signal.SIGUSR1
                                        Target = ValueSome 1
                                    }
                                    proc.Signals
                        }
                    )

                let bytes = bytesOf (8 <<< 20)

                let outcome =
                    match WriteOutcomes.admitThenWrite 1 client UserBuffer.Mapped bytes system with
                    | Ok (WriteStep.WouldBlock (_, parked)) ->
                        let parked = Lone.waking [ 1 ] parked
                        finish bytes parked
                    | written -> written

                match outcome with
                | Ok (WriteStep.Returns (WriteAnswer.Completed n, _)) when raced = 0 && counts = 20 ->
                    n |> shouldBeGreaterThan 0L
                | Error (WriteRefusal.Interruption (SyscallInterruptionRefusal.SignalBesideCompletion SimulatedUnixFlavour.Darwin)) when
                    raced > 0
                    ->
                    ()
                | other -> failwith $"%O{platform}: %s{line.Text}\nmodelled %A{other}"

    /// Section C, Linux: a write asleep with the buffers full, woken once the
    /// reader has drained everything and closed, returns at once with more
    /// than it had taken before, raising nothing and leaving EPIPE pending.
    [<Test>]
    let ``a woken Linux write whose own bytes reset the connection returns at once, as section C measured`` () : unit =
        let platform = SimulatedUnixPlatform.linuxArm64
        let rows = lines platform |> List.filter (fun line -> line.Section = "C")
        rows |> List.length |> shouldEqual 10

        for line in rows do
            field "answer" line
            |> int64
            |> shouldBeGreaterThan (int64 (field "drained" line))

            field "answer" line |> int64 |> shouldBeSmallerThan (8L <<< 20)
            field "sigpipe" line |> shouldEqual "0"
            field "so_error" line |> shouldEqual "EPIPE"

        let client, server, system = pair (systemOn platform)

        // The measured write took 589347 bytes once woken, leaving most of its
        // 8 MiB untaken; this kernel's takes the send buffer's room, 4 MiB,
        // which would leave nothing of 8 MiB. Twice that leaves the woken
        // write bytes it cannot take, as the measured one had.
        let bytes = bytesOf (16 <<< 20)

        let system =
            match WriteOutcomes.admitThenWrite 1 client UserBuffer.Mapped bytes system with
            | Ok (WriteStep.WouldBlock (_, system)) -> system
            | other -> failwith $"expected the write to sleep, got %A{other}"

        // The hog's drain: everything the reader holds, and everything still
        // on its way to it, read without blocking.
        let _, system =
            UnixDescriptor.setNonBlocking (Callers.leader system) server true system

        let rec drain (total : int64) (system : UnixSystem<int, string>) =
            match
                UnixReadWrite.tryRead (Callers.thread 0 system) server UserBuffer.Mapped (uint64 (1 <<< 22)) system
            with
            | Ok (ReadOutcome.Answered (ReadAnswer.Completed got), system) when got.Length > 0 ->
                drain (total + int64 got.Length) system
            | Ok (ReadOutcome.Answered (ReadAnswer.Failed UnixError.EAGAIN), system) -> total, system
            | other -> failwith $"draining: %A{other}"

        let drained, system = drain 0L system
        let system = KeventWorld.close server system
        let system = Lone.waking [ 1 ] system

        match finish bytes system with
        | Ok (WriteStep.Returns (WriteAnswer.Completed n, after)) ->
            n |> shouldBeGreaterThan drained
            n |> shouldBeSmallerThan (int64 bytes.Length)
            UnixThreadTable.parkedFor 1 (Lone.threads after) |> shouldEqual None
            soError client after |> fst |> shouldEqual "EPIPE"
        | other -> failwith $"expected the woken write to return, got %A{other}"
