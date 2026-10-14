namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A process launched with an output stream whose reader the client closed
/// before it started (`LaunchDescriptor.Gone`): every write there answers
/// EPIPE and raises SIGPIPE, as a write into any pipe with no reader does,
/// while the other streams carry on as launched.
///
/// The oracle is a reference small enough to read at a glance: a write to a
/// gone stream raises SIGPIPE at the writing thread on Linux and at the process
/// on Darwin, except Linux's zero-length write, which answers 0; what the
/// signal does is the disposition's to say; and a write to a drained stream
/// is delivered whole.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestStreamReaderGone =

    let private platforms : SimulatedUnixPlatform list =
        [
            SimulatedUnixPlatform.linuxX64
            SimulatedUnixPlatform.linuxArm64
            SimulatedUnixPlatform.macOsArm64
        ]

    let private payload (seed : int) (count : int) : ImmutableArray<byte> =
        ImmutableArray.Create<byte> (Array.init count (fun i -> byte ((seed + i) % 251)))

    /// The launch table with standard output and standard error each drained or
    /// gone, as `gone` says of descriptors 1 and 2.
    let private launch (gone : Set<int>) : Map<int, LaunchDescriptor> =
        (UnixSystem.pipedStandardStreams, gone)
        ||> Set.fold (fun table fd -> Map.add fd LaunchDescriptor.Gone table)

    let private withSigPipe
        (disposition : SignalDisposition<string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    SignalState.setDisposition
                        (UnixSystemState.signalNumbering system)
                        Signal.SIGPIPE
                        disposition
                        proc.Signals
            }
        )

    /// A process with a leader, 0, and a worker, 1.
    let private systemOn
        (platform : SimulatedUnixPlatform)
        (gone : Set<int>)
        (disposition : SignalDisposition<string>)
        : UnixSystem<int, string>
        =
        UnixSystem.initial platform
        |> Launched.boot (launch gone) 0 (CpuId 0)
        |> Threads.spawn 1
        |> withSigPipe disposition

    let private sigPipeFrom (flavour : SimulatedUnixFlavour) (thread : int) : PendingSignal<int> =
        {
            Signal = Signal.SIGPIPE
            Target =
                match flavour with
                | SimulatedUnixFlavour.Linux -> ValueSome thread
                | SimulatedUnixFlavour.Darwin -> ValueNone
        }

    let private dispositions : SignalDisposition<string> list =
        [
            SignalDisposition.Default
            SignalDisposition.Ignore
            SignalDisposition.Catch (SignalCatch.ofHandler "on SIGPIPE")
        ]

    let private assertSound (context : string) (system : UnixSystem<int, string>) : unit =
        match UnixSystem.checkInvariants system with
        | [] -> ()
        | defects -> failwith $"%s{context}: %A{defects}"

    [<Test>]
    let ``every write to a launched output stream answers as the reference says, gone or drained`` () : unit =
        let property
            (
                platform : SimulatedUnixPlatform,
                gone : Set<int>,
                disposition : SignalDisposition<string>,
                ops : (int * int * int) list
            )
            : unit
            =
            let flavour = SimulatedUnixPlatform.flavour platform
            let mutable system = systemOn platform gone disposition
            let mutable delivered : (int * byte list) list = []
            let mutable pending : Set<PendingSignal<int>> = Set.empty
            let mutable ended = false

            for i, (thread, fd, count) in List.indexed ops |> Seq.takeWhile (fun _ -> not ended) do
                let where =
                    $"%O{platform}, gone %A{gone}, %A{disposition}, call %d{i}: thread %d{thread} writes %d{count} to fd %d{fd}"

                let bytes = payload i count

                let actual = WriteOutcomes.admitThenWrite thread fd UserBuffer.Mapped bytes system

                if Set.contains fd gone && not (flavour = SimulatedUnixFlavour.Linux && count = 0) then
                    let raised = sigPipeFrom flavour thread

                    match disposition, actual with
                    | SignalDisposition.Default, Ok (WriteStep.ProcessEnded endedProcess) ->
                        endedProcess.Termination
                        |> shouldEqual (ProcessTermination.Signaled (Signal.SIGPIPE, false))

                        ended <- true
                    | SignalDisposition.Ignore,
                      Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed UnixError.EPIPE, signal, after)) ->
                        signal |> shouldEqual raised
                        after |> shouldEqual system
                    | SignalDisposition.Catch _,
                      Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed UnixError.EPIPE, signal, after)) ->
                        signal |> shouldEqual raised
                        pending <- Set.add raised pending

                        Set.ofList (SignalState.pending (Lone.proc after).Signals)
                        |> shouldEqual pending

                        after
                        |> Lone.mapProc (fun proc ->
                            { proc with
                                Signals = (Lone.proc system).Signals
                            }
                        )
                        |> shouldEqual system

                        system <- after
                    | _ -> failwith $"%s{where}: expected EPIPE and SIGPIPE, got %A{actual}"
                else
                    match actual with
                    | Ok (WriteStep.Returns (WriteAnswer.Completed written, after)) ->
                        written |> shouldEqual (int64 count)

                        if count > 0 then
                            delivered <- (fd, List.ofSeq bytes) :: delivered

                        system <- after
                    | other -> failwith $"%s{where}: expected the whole write, got %A{other}"

                assertSound where system

                let log =
                    DeliveryLog.toList system.Machine.Delivered
                    |> List.map (fun delivery ->
                        let (ExternalEndpoint (launchedInto, fd)) = delivery.Endpoint
                        launchedInto |> shouldEqual (Lone.pid system)
                        fd, List.ofSeq delivery.Bytes
                    )

                // NUnit's comparison walks each byte reflectively, and the log
                // grows every step, so it is asked only to describe a mismatch.
                if log <> List.rev delivered then
                    log |> shouldEqual (List.rev delivered)

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! goneOut = Gen.elements [ true ; false ]
                let! goneErr = Gen.elements [ true ; false ]
                let! disposition = Gen.elements dispositions

                let op =
                    Gen.zip3
                        (Gen.elements [ 0 ; 1 ])
                        (Gen.elements [ 1 ; 2 ])
                        (Gen.frequency [ 1, Gen.constant 0 ; 4, Gen.choose (1, 3000) ; 1, Gen.constant 70000 ])

                let! ops = Gen.listOf op |> Gen.map (List.truncate 30)

                let gone =
                    Set.union
                        (if goneOut then Set.singleton 1 else Set.empty)
                        (if goneErr then Set.singleton 2 else Set.empty)

                return platform, gone, disposition, ops
            }

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 200, Prop.forAll (Arb.fromGen gen) property)

    /// The Darwin signal is the process's, which its leader takes; one the
    /// leader blocks while another thread does not would go to that other thread,
    /// which is not modelled. Linux's is the writing thread's own, so the same
    /// write from the blocking leader leaves it pending there.
    [<Test>]
    let ``a caught SIGPIPE that only a thread other than the leader could take is refused on Darwin`` () : unit =
        for platform in platforms do
            let system =
                systemOn platform (Set.singleton 1) (SignalDisposition.Catch (SignalCatch.ofHandler "on SIGPIPE"))

            let threads = Lone.threads system |> Map.keys |> Set.ofSeq

            let system =
                system
                |> Lone.mapProc (fun proc ->
                    { proc with
                        Signals =
                            HandlerFrames.enter
                                (UnixSystemState.signalNumbering system)
                                "carrier"
                                (Lone.leader system)
                                threads
                                (Lone.leader system)
                                (Set.singleton Signal.SIGPIPE)
                                proc.Signals
                    }
                )

            let actual =
                WriteOutcomes.admitThenWrite (Lone.leader system) 1 UserBuffer.Mapped (payload 0 5) system

            match SimulatedUnixPlatform.flavour platform, actual with
            | SimulatedUnixFlavour.Darwin,
              Error (WriteRefusal.SignalReceiver (_, SignalReceiverRefusal.LeaderBlocks Signal.SIGPIPE)) -> ()
            | SimulatedUnixFlavour.Linux,
              Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed UnixError.EPIPE, signal, after)) ->
                signal
                |> shouldEqual (sigPipeFrom SimulatedUnixFlavour.Linux (Lone.leader system))

                SignalState.pending (Lone.proc after).Signals |> shouldEqual [ signal ]
            | flavour, other -> failwith $"%O{flavour}: %A{other}"

    /// A gone stream's write end polls as a pipe's with no reader does, and
    /// closing it frees the pipe, which nothing else holds.
    [<Test>]
    let ``a gone stream polls ERR on Linux, and its pipe goes with its last descriptor`` () : unit =
        for platform in platforms do
            let system = systemOn platform (Set.singleton 1) SignalDisposition.Ignore

            let pipe =
                match FileDescriptorRegistry.tryFindTarget 1 (Lone.fileDescriptors system) with
                | Some (OpenFileTarget.Pipe (pipeId, PipeEnd.Write)) -> pipeId
                | other -> failwith $"fd 1 is %A{other}"

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin -> ()
            | SimulatedUnixFlavour.Linux ->
                let id =
                    FileDescriptorRegistry.tryFindId 1 (Lone.fileDescriptors system) |> Option.get

                // OUT|WRNORM, the empty pipe having room, and ERR: measured
                // (pipe-epipe-sweep.c), 0xc through `poll(POLLOUT)`.
                LinuxReadiness.ofDescription id system
                |> shouldEqual (EpollEvents.Out ||| EpollEvents.WrNorm ||| EpollEvents.Err)

            assertSound "launched" system

            let closed =
                match UnixDescriptor.tryClose (Callers.leader system) 1 system with
                | Ok (SyscallAnswer.Completed 0L, system) -> system
                | other -> failwith $"close 1: %A{other}"

            Map.containsKey pipe closed.Machine.Pipes |> shouldEqual false
            assertSound "closed" closed

    /// A write is made by one of the process's threads, which the signal it may
    /// raise is aimed at; a thread the process does not have is the client's
    /// mistake, refused before anything is answered.
    [<Test>]
    let ``a write by a thread the process does not have fails loudly`` () : unit =
        for platform in platforms do
            let system = systemOn platform Set.empty SignalDisposition.Ignore

            for fd in [ 1 ; 99 ] do
                let admit =
                    Assert.Throws<System.InvalidOperationException> (fun () ->
                        UnixReadWrite.tryWrite (Callers.thread 7 system) fd UserBuffer.Mapped 1UL system
                        |> ignore
                    )

                admit.Message
                |> shouldContainText "thread 7 is not one of the process's threads"

                let write =
                    Assert.Throws<System.InvalidOperationException> (fun () ->
                        WriteOutcomes.writeBytes 7 fd (payload 0 1) system
                        |> ignore<Result<WriteStep<WriteAnswer, int, string>, WriteRefusal>>
                    )

                write.Message
                |> shouldContainText "thread 7 is not one of the process's threads"

    /// Process ID 1 is an init process, which ignores a signal it has no
    /// handler for; that is not modelled, so its broken-pipe write is refused,
    /// as `kill` refuses it. Linux's zero-length write raises nothing, so it is
    /// answered.
    [<Test>]
    let ``a broken-pipe write by process ID 1 is refused`` () : unit =
        for platform in platforms do
            for disposition in dispositions do
                let system =
                    UnixSystem.initial platform
                    |> Launched.processId (ProcessId.parseOrFail "test" 1)
                    |> Launched.boot (launch (Set.singleton 1)) 0 (CpuId 0)
                    |> withSigPipe disposition

                match WriteOutcomes.admitThenWrite (Lone.leader system) 1 UserBuffer.Mapped (payload 0 5) system with
                | Error (WriteRefusal.InitProcess _) -> ()
                | other -> failwith $"%O{platform}, %A{disposition}: %A{other}"

                match
                    SimulatedUnixPlatform.flavour platform,
                    WriteOutcomes.writeBytes (Lone.leader system) 1 ImmutableArray.Empty system
                with
                | SimulatedUnixFlavour.Linux, Ok (WriteStep.Returns (WriteAnswer.Completed 0L, _))
                | SimulatedUnixFlavour.Darwin, Error (WriteRefusal.InitProcess _) -> ()
                | flavour, other -> failwith $"%O{flavour}, %A{disposition}, zero-length: %A{other}"
