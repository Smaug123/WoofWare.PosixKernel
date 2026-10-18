namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The standard streams of a process launched with `UnixSystem.pipedStandardStreams`
/// answer as the standard streams did before they were pipe ends: standard
/// input at end of file, each output stream a whole write recorded entry for
/// entry, and the readiness constants of the launch shape.
///
/// The oracle is a reference model of that earlier behaviour, small enough to
/// read at a glance. It knows nothing of pipes: a descriptor names a stream
/// (input, output or error) or something else, and a write to an output stream
/// appends to one log. The property drives both through the same random
/// sequence of descriptor operations and requires every stream answer and the
/// whole log to agree, the log as what the client draining each launched pipe
/// received.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestLaunchedStreams =

    [<RequireQualifiedAccess>]
    type private Stream =
        | Input
        | Output
        | Error

    [<RequireQualifiedAccess>]
    type private ReferenceKind =
        | Stream of Stream
        /// A pipe end the process made, which the reference does not model.
        | Other

    type private ReferenceDescription =
        {
            Kind : ReferenceKind
            NonBlocking : bool
        }

    /// The earlier standard streams, and the log of writes to them, newest first.
    type private Reference =
        {
            Fds : Map<int, int>
            Descriptions : Map<int, ReferenceDescription>
            NextId : int
            Log : (Stream * byte list) list
        }

    [<RequireQualifiedAccess>]
    type private Op =
        /// A call made through `UnixSystem.step`.
        | Call of Syscall<int, string>
        /// `UnixDescriptor.setNonBlocking`: `fcntl(F_GETFL)`, then `fcntl(F_SETFL)`.
        | SetNonBlocking of fd : int * value : bool
        /// The readiness Linux's `poll(2)` reports for the description `fd` names.
        | Poll of fd : int

    /// What one operation answered, in terms both sides share.
    [<RequireQualifiedAccess>]
    type private Answer =
        | Wrote of int64
        | WriteFailed of UnixError
        | ReadBytes of int
        | ReadFailed of UnixError
        | Syscall of SyscallAnswer
        | NonBlocking of SetNonBlockingAnswer
        | Level of uint32

    let private initialReference : Reference =
        let stream (kind : Stream) =
            {
                Kind = ReferenceKind.Stream kind
                NonBlocking = false
            }

        {
            Fds = Map.ofList [ 0, 0 ; 1, 1 ; 2, 2 ]
            Descriptions = Map.ofList [ 0, stream Stream.Input ; 1, stream Stream.Output ; 2, stream Stream.Error ]
            NextId = 3
            Log = []
        }

    let private lowestFree (fds : Map<int, int>) : int =
        Seq.initInfinite id |> Seq.find (fun fd -> not (Map.containsKey fd fds))

    let private referenceDescription (fd : int) (reference : Reference) : ReferenceDescription option =
        Map.tryFind fd reference.Fds
        |> Option.map (fun id -> reference.Descriptions.[id])

    let private payload (seed : int) (count : int) : ImmutableArray<byte> =
        ImmutableArray.Create<byte> (Array.init count (fun i -> byte ((seed * 31 + i) % 251)))

    /// What the earlier model did with the bytes the client received.
    let private streamOf (pid : ProcessId) (endpoint : ExternalEndpoint) : Stream =
        match endpoint with
        | ExternalEndpoint (launchedInto, 1) when launchedInto = pid -> Stream.Output
        | ExternalEndpoint (launchedInto, 2) when launchedInto = pid -> Stream.Error
        | other ->
            failwith $"a delivery reached %O{other}, which pipedStandardStreams does not drain for process %O{pid}"

    let private deliveredLog (system : UnixSystem<int, string>) : (Stream * byte list) list =
        DeliveryLog.toList (Kernel.machine system).Delivered
        |> List.map (fun delivery -> streamOf (Lone.pid system) delivery.Endpoint, List.ofSeq delivery.Bytes)

    /// One write as a client issues it: admitted, and then given the bytes the
    /// admission asked for. A pipe the process made can lose its reader, and a
    /// write into it then raises SIGPIPE, which the process ignores here
    /// (`initialSystem`), so the write answers EPIPE. `Error None` is a write
    /// that sleeps, and `Error (Some refusal)` one the system refused.
    let private write
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<int, string>)
        : Result<WriteAnswer * UnixSystem<int, string>, WriteRefusal option>
        =
        match WriteOutcomes.admitThenWrite (Lone.leader system) fd UserBuffer.Mapped bytes system with
        | Error refusal -> Error (Some refusal)
        | Ok (WriteStep.Returns (answer, after))
        | Ok (WriteStep.ReturnsRaising (answer, _, after)) -> Ok (answer, after)
        | Ok (WriteStep.ProcessEnded _ as outcome) ->
            failwith $"a write ended the process, whose SIGPIPE is ignored: %A{outcome}"
        | Ok (WriteStep.WouldBlock _) -> Error None
        | Ok (WriteStep.Interrupted _ as outcome) -> failwith $"a write that never slept restarted: %A{outcome}"

    /// What the earlier standard streams answered, if the descriptor named one
    /// (`None` for a descriptor the reference does not model), and the
    /// reference afterwards. `Error ()` is the earlier model's refusal: a
    /// non-blocking write longer than an empty pipe holds.
    let private referenceStep (op : Op) (reference : Reference) : Result<Answer option * Reference, unit> =
        match op with
        | Op.Call (Syscall.Write (fd, buffer, count)) ->
            let bytes =
                match buffer with
                | CopiedArgument.Readable bytes -> bytes
                | CopiedArgument.Unmapped _
                | CopiedArgument.Opaque
                | CopiedArgument.Addressless -> failwith $"the property makes no such buffer: %A{buffer}"

            match referenceDescription fd reference with
            | None -> Ok (Some (Answer.WriteFailed UnixError.EBADF), reference)
            | Some {
                       Kind = ReferenceKind.Other
                   } -> Ok (None, reference)
            | Some {
                       Kind = ReferenceKind.Stream Stream.Input
                   } -> Ok (Some (Answer.WriteFailed UnixError.EBADF), reference)
            | Some {
                       Kind = ReferenceKind.Stream stream
                       NonBlocking = nonBlocking
                   } ->
                if count = 0UL then
                    Ok (Some (Answer.Wrote 0L), reference)
                elif nonBlocking && count > 65536UL then
                    Error ()
                else
                    Ok (
                        Some (Answer.Wrote (int64 count)),
                        { reference with
                            Log = (stream, List.ofSeq bytes) :: reference.Log
                        }
                    )
        | Op.Call (Syscall.Read (fd, _, _)) ->
            match referenceDescription fd reference with
            | None -> Ok (Some (Answer.ReadFailed UnixError.EBADF), reference)
            | Some {
                       Kind = ReferenceKind.Other
                   } -> Ok (None, reference)
            | Some {
                       Kind = ReferenceKind.Stream Stream.Input
                   } -> Ok (Some (Answer.ReadBytes 0), reference)
            | Some {
                       Kind = ReferenceKind.Stream _
                   } -> Ok (Some (Answer.ReadFailed UnixError.EBADF), reference)
        | Op.Call (Syscall.Dup fd) ->
            match Map.tryFind fd reference.Fds with
            | None -> Ok (Some (Answer.Syscall (SyscallAnswer.Failed UnixError.EBADF)), reference)
            | Some id ->
                let newFd = lowestFree reference.Fds

                Ok (
                    Some (Answer.Syscall (SyscallAnswer.Completed (int64 newFd))),
                    { reference with
                        Fds = Map.add newFd id reference.Fds
                    }
                )
        | Op.Call (Syscall.Close fd) ->
            match Map.tryFind fd reference.Fds with
            | None -> Ok (Some (Answer.Syscall (SyscallAnswer.Failed UnixError.EBADF)), reference)
            | Some id ->
                let fds = Map.remove fd reference.Fds

                let descriptions =
                    if fds |> Map.exists (fun _ other -> other = id) then
                        reference.Descriptions
                    else
                        Map.remove id reference.Descriptions

                Ok (
                    Some (Answer.Syscall (SyscallAnswer.Completed 0L)),
                    { reference with
                        Fds = fds
                        Descriptions = descriptions
                    }
                )
        | Op.SetNonBlocking (fd, value) ->
            match Map.tryFind fd reference.Fds with
            | None -> Ok (Some (Answer.NonBlocking (SetNonBlockingAnswer.Failed UnixError.EBADF)), reference)
            | Some id ->
                let description = reference.Descriptions.[id]

                let answer =
                    match description.Kind with
                    | ReferenceKind.Stream _ -> Some (Answer.NonBlocking SetNonBlockingAnswer.Set)
                    | ReferenceKind.Other -> None

                Ok (
                    answer,
                    { reference with
                        Descriptions =
                            Map.add
                                id
                                { description with
                                    NonBlocking = value
                                }
                                reference.Descriptions
                    }
                )
        | Op.Poll fd ->
            match referenceDescription fd reference with
            | Some {
                       Kind = ReferenceKind.Stream Stream.Input
                   } -> Ok (Some (Answer.Level EpollEvents.Hup), reference)
            | Some {
                       Kind = ReferenceKind.Stream _
                   } -> Ok (Some (Answer.Level (EpollEvents.Out ||| EpollEvents.WrNorm)), reference)
            | Some {
                       Kind = ReferenceKind.Other
                   }
            | None -> Ok (None, reference)
        | Op.Call (Syscall.Pipe2 _) ->
            let readFd = lowestFree reference.Fds
            let fds = Map.add readFd reference.NextId reference.Fds
            let writeFd = lowestFree fds

            let other =
                {
                    Kind = ReferenceKind.Other
                    NonBlocking = true
                }

            Ok (
                None,
                { reference with
                    Fds = Map.add writeFd (reference.NextId + 1) fds
                    Descriptions =
                        reference.Descriptions
                        |> Map.add reference.NextId other
                        |> Map.add (reference.NextId + 1) other
                    NextId = reference.NextId + 2
                }
            )
        | Op.Call other ->
            failwith $"Syscall.%s{UnionCaseName.ofValue other} is not generated by the launched streams' property"

    /// A process launched with `UnixSystem.pipedStandardStreams`, ignoring
    /// SIGPIPE.
    let private initialSystem (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    SignalState.setDisposition
                        (Kernel.signalNumbering system)
                        Signal.SIGPIPE
                        SignalDisposition.Ignore
                        proc.Signals
            }
        )

    /// What the `write(2)` of `bytes` through `fd` by the only process's
    /// leader answers through the call's own functions, held to the same
    /// write made a step at a time (`WriteOutcomes.admitThenWrite`), in the
    /// shape `UnixSystem.step` answers it.
    let private writtenThroughSteps
        (fd : int)
        (bytes : ImmutableArray<byte>)
        (system : UnixSystem<int, string>)
        : Result<ProcessFate<WriteOutcome<int>, int, string>, WriteRefusal>
        =
        WriteOutcomes.admitThenWrite (Lone.leader system) fd UserBuffer.Mapped bytes system
        |> Result.map (fun step ->
            match step with
            | WriteStep.Returns (answer, after) -> ProcessFate.Continues (WriteOutcome.Returns answer, after)
            | WriteStep.ReturnsRaising (answer, signal, after) ->
                ProcessFate.Continues (WriteOutcome.ReturnsRaising (answer, signal), after)
            | WriteStep.ProcessEnded (ended, after) -> ProcessFate.ProcessEnded (ended, after)
            | WriteStep.WouldBlock (condition, after) ->
                ProcessFate.Continues (WriteOutcome.WouldBlock condition, after)
            | WriteStep.Interrupted after -> ProcessFate.Continues (WriteOutcome.Interrupted, after)
        )

    /// What a write's `fate` says, without the system it holds.
    let private outcomeOf
        (fate : ProcessFate<WriteOutcome<int>, int, string>)
        : Choice<WriteOutcome<int>, EndedProcess>
        =
        match fate with
        | ProcessFate.Continues (outcome, _) -> Choice1Of2 outcome
        | ProcessFate.ProcessEnded (ended, _) -> Choice2Of2 ended

    /// What the launched streams answer, or `None` where the system refused or
    /// the call would sleep, and the system afterwards.
    let private systemStep (op : Op) (system : UnixSystem<int, string>) : (Answer * UnixSystem<int, string>) option =
        let stepped (call : Syscall<int, string>) : Result<SteppedCall<int, string>, SyscallRefusal<int>> =
            UnixSystem.tryStep (Callers.leader system) call system

        let unexpected
            (call : Syscall<int, string>)
            (answered : SteppedCall<int, string>)
            : (Answer * UnixSystem<int, string>) option
            =
            failwith $"Syscall.%s{UnionCaseName.ofValue call} answered SteppedCall.%s{UnionCaseName.ofValue answered}"

        match op with
        | Op.Call (Syscall.Write (fd, buffer, _) as call) ->
            let answered = stepped call

            let bytes =
                match buffer with
                | CopiedArgument.Readable bytes -> bytes
                | CopiedArgument.Unmapped _
                | CopiedArgument.Opaque
                | CopiedArgument.Addressless -> failwith $"the property makes no such buffer: %A{buffer}"

            // The same write through the call's own functions, held to it made
            // a step at a time, answers alike and leaves the same system.
            let throughSteps = writtenThroughSteps fd bytes system

            match answered, throughSteps with
            | Ok (SteppedCall.Write fate), Ok steps when fate = steps -> ()
            | Error (SyscallRefusal.Write refusal), Error steps when refusal = steps -> ()
            | Ok (SteppedCall.Write fate), _ ->
                failwith
                    $"%A{call}: UnixSystem.tryStep answered %A{outcomeOf fate}, and the call's own functions %A{Result.map outcomeOf throughSteps}, or left another system"
            | Error refusal, _ ->
                failwith
                    $"%A{call}: UnixSystem.tryStep refused it (%s{SyscallRefusal.describe refusal}), and the call's own functions answered %A{Result.map outcomeOf throughSteps}"
            | Ok other, _ -> unexpected call other |> ignore

            match answered with
            | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns answer, after)))
            | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.ReturnsRaising (answer, _), after))) ->
                // A pipe the process made can lose its reader, and a write
                // into it then raises SIGPIPE, which the process ignores here
                // (`initialSystem`), so the write answers EPIPE.
                match answer with
                | WriteAnswer.Completed written -> Some (Answer.Wrote written, after)
                | WriteAnswer.Failed error -> Some (Answer.WriteFailed error, after)
            | Ok (SteppedCall.Write (ProcessFate.ProcessEnded _ as fate)) ->
                failwith $"a write ended the process, whose SIGPIPE is ignored: %A{fate}"
            | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.WouldBlock _, _))) -> None
            | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Interrupted, _) as fate)) ->
                failwith $"a write that never slept restarted: %A{fate}"
            | Ok other -> unexpected call other
            | Error _ -> None
        | Op.Call (Syscall.Read _ as call) ->
            match stepped call with
            | Ok (SteppedCall.Read (ReadOutcome.Answered (ReadAnswer.Completed bytes), after)) ->
                Some (Answer.ReadBytes bytes.Length, after)
            | Ok (SteppedCall.Read (ReadOutcome.Answered (ReadAnswer.Failed error), after)) ->
                Some (Answer.ReadFailed error, after)
            | Ok (SteppedCall.Read (ReadOutcome.Answered (ReadAnswer.Drawn _), _)) ->
                failwith "a read of a stream drew from the entropy pool"
            // A read that sleeps, on a pipe the process made, which the
            // earlier streams had no notion of.
            | Ok (SteppedCall.Read (ReadOutcome.WouldBlock _, _)) -> None
            | Ok (SteppedCall.Read (ReadOutcome.Interrupted, _)) -> failwith "a read that never slept was interrupted"
            | Ok other -> unexpected call other
            | Error _ -> None
        | Op.Call (Syscall.Dup _ as call) ->
            match stepped call with
            | Ok (SteppedCall.Dup (answer, after)) -> Some (Answer.Syscall answer, after)
            | Ok other -> unexpected call other
            | Error refusal -> failwith $"dup was refused: %s{SyscallRefusal.describe refusal}"
        | Op.Call (Syscall.Close _ as call) ->
            match stepped call with
            | Ok (SteppedCall.Close (answer, after)) -> Some (Answer.Syscall answer, after)
            | Ok other -> unexpected call other
            | Error _ -> None
        | Op.Call (Syscall.Pipe2 _ as call) ->
            match stepped call with
            | Ok (SteppedCall.Pipe2 (Pipe2Answer.Created _, after)) ->
                Some (Answer.Syscall (SyscallAnswer.Completed 0L), after)
            | Ok (SteppedCall.Pipe2 (Pipe2Answer.Failed error, after)) ->
                Some (Answer.Syscall (SyscallAnswer.Failed error), after)
            | Ok other -> unexpected call other
            | Error _ -> None
        | Op.Call other ->
            failwith $"Syscall.%s{UnionCaseName.ofValue other} is not generated by the launched streams' property"
        | Op.SetNonBlocking (fd, value) ->
            let answer, after =
                UnixDescriptor.setNonBlocking (Callers.leader system) fd value system

            Some (Answer.NonBlocking answer, after)
        | Op.Poll fd ->
            match FileDescriptorRegistry.tryFindId fd (Lone.fileDescriptors system) with
            | None -> Some (Answer.Level 0u, system)
            | Some id -> Some (Answer.Level (Lone.LinuxReadiness.ofDescription id system), system)

    let private platforms : SimulatedUnixPlatform list =
        [
            SimulatedUnixPlatform.linuxX64
            SimulatedUnixPlatform.linuxArm64
            SimulatedUnixPlatform.macOsArm64
        ]

    /// An operation of a process on `platform`.
    let private opGen (platform : SimulatedUnixPlatform) : Gen<Op> =
        let fd = Gen.choose (0, 6)

        let count =
            Gen.frequency
                [
                    8, Gen.choose (0, 64)
                    2, Gen.choose (0, 70000)
                    1, Gen.elements [ 0 ; 1 ; 4096 ; 65536 ; 65537 ; 200000 ]
                ]

        Gen.frequency
            [
                6,
                gen {
                    let! fd = fd
                    let! count = count
                    let! seed = Gen.choose (0, 250)

                    return Op.Call (Syscall.Write (fd, CopiedArgument.Readable (payload seed count), uint64 count))
                }
                2, Gen.map2 (fun fd count -> Op.Call (Syscall.Read (fd, UserBuffer.Mapped, uint64 count))) fd count
                2, Gen.map (fun fd -> Op.Call (Syscall.Dup fd)) fd
                2, Gen.map (fun fd -> Op.Call (Syscall.Close fd)) fd
                2, Gen.map2 (fun fd value -> Op.SetNonBlocking (fd, value)) fd (Gen.elements [ true ; false ])
                1, Gen.map Op.Poll fd
                1, Gen.constant (Op.Call (Syscall.Pipe2 (UserBuffer.Mapped, OpenFlagWords.nonBlock platform)))
            ]

    [<Test>]
    let ``the launched standard streams answer and log as the earlier standard streams did`` () : unit =
        let property (platform : SimulatedUnixPlatform, ops : Op list) : unit =
            let linux =
                match SimulatedUnixPlatform.flavour platform with
                | SimulatedUnixFlavour.Linux -> true
                | SimulatedUnixFlavour.Darwin -> false

            let rec run (index : int) (ops : Op list) (reference : Reference) (system : UnixSystem<int, string>) =
                UnixSystem.checkInvariants system |> shouldEqual []
                let delivered = deliveredLog system
                let logged = List.rev reference.Log

                // NUnit's comparison walks each byte reflectively, and the log
                // grows every step, so it is asked only to describe a mismatch.
                if delivered <> logged then
                    delivered |> shouldEqual logged

                match ops with
                | [] -> ()
                // Darwin's readiness is not modelled, by either side.
                | Op.Poll _ :: rest when not linux -> run (index + 1) rest reference system
                | op :: rest ->

                match referenceStep op reference with
                // The earlier process ended here, refused; nothing after it
                // happened, so nothing after it can be compared.
                | Error () -> ()
                | Ok (expected, reference) ->

                match systemStep op system, expected with
                | None, Some expected ->
                    failwith
                        $"step %d{index}, %A{op}: the reference answered %A{expected}, the launched streams refused"
                // Both refuse an operation on a pipe the process made where a
                // real kernel would wait or signal, and the process ends there.
                | None, None -> ()
                | Some (answer, after), expected ->
                    match expected with
                    | Some expected when answer <> expected ->
                        failwith
                            $"step %d{index}, %A{op}: the reference answered %A{expected}, the launched streams %A{answer}"
                    | Some _
                    | None -> run (index + 1) rest reference after

            run 0 ops initialReference (initialSystem platform)

        let gen =
            gen {
                let! platform = Gen.elements platforms
                let! ops = Gen.listOf (opGen platform) |> Gen.map (List.truncate 60)
                return platform, ops
            }

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 400, Prop.forAll (Arb.fromGen gen) property)

    /// What one edge-triggered `EPOLLOUT` registration on standard output
    /// reports at once, and then after each of `writes`: the rows of
    /// drained-pipe-epoll.c, which wrote into a pipe and drained it at once, on
    /// Linux 6.18.5.
    let private edgesAfter (writes : int list) : bool * bool list =
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let epoll, system =
            match UnixPoll.tryEpollCreate1 (Callers.leader system) 0 system with
            | Ok (Ok (epoll, system)) -> epoll, system
            | other -> failwith $"%A{other}"

        let queueId =
            match FileDescriptorRegistry.tryFindId epoll (Lone.fileDescriptors system) with
            | Some id -> id
            | None -> failwith "the epoll instance is not open"

        let system =
            match
                UnixPoll.tryEpollCtl
                    (Callers.leader system)
                    epoll
                    1
                    1
                    (EpollEventArgument.Readable (EpollEvents.Out ||| EpollEvents.EdgeTriggered, 7UL))
                    system
            with
            | Ok (EpollCtlAnswer.Changed, system) -> system
            | other -> failwith $"%A{other}"

        let reported (system : UnixSystem<int, string>) : bool * UnixSystem<int, string> =
            let rows, system = Lone.EpollReadyList.drain queueId 4 system
            not rows.IsEmpty, system

        let atAdd, system = reported system

        let _, edges =
            ((system, []), writes)
            ||> List.fold (fun (system, edges) count ->
                match write 1 (payload count count) system with
                | Ok (WriteAnswer.Completed written, system) when written = int64 count ->
                    UnixSystem.checkInvariants system |> shouldEqual []
                    let edge, system = reported system
                    system, edge :: edges
                | other -> failwith $"write of %d{count} answered %A{Result.map fst other}"
            )

        atAdd, List.rev edges

    [<Test>]
    let ``standard output's write end is woken by the client's drain exactly when a write filled the pipe`` () : unit =
        // The registration is ready at once, as on the host. 61440 bytes take
        // fifteen of the sixteen slots and leave one free; 65535 and 65536 take
        // all sixteen.
        edgesAfter [ 1 ; 100 ; 4096 ; 4097 ; 32768 ; 61440 ; 65535 ; 65536 ; 1 ; 200000 ]
        |> shouldEqual (true, [ false ; false ; false ; false ; false ; false ; true ; true ; false ; true ])

    [<Test>]
    let ``standard input and output may be registered with epoll, and a pipe the process made may not`` () : unit =
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let epoll, system =
            match UnixPoll.tryEpollCreate1 (Callers.leader system) 0 system with
            | Ok (Ok (epoll, system)) -> epoll, system
            | other -> failwith $"%A{other}"

        let edge = EpollEvents.In ||| EpollEvents.Out ||| EpollEvents.EdgeTriggered

        for fd in [ 0 ; 1 ; 2 ] do
            match
                UnixPoll.tryEpollCtl (Callers.leader system) epoll 1 fd (EpollEventArgument.Readable (edge, 0UL)) system
            with
            | Ok (EpollCtlAnswer.Changed, _) -> ()
            | other -> failwith $"fd %d{fd}: %A{other}"

        let readFd, system =
            match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
            | Ok (Pipe2Answer.Created (readFd, _), system) -> readFd, system
            | other -> failwith $"%A{other}"

        match
            UnixPoll.tryEpollCtl (Callers.leader system) epoll 1 readFd (EpollEventArgument.Readable (edge, 0UL)) system
        with
        | Error (EpollCtlRefusal.PipeTarget refused) -> refused |> shouldEqual readFd
        | other -> failwith $"%A{other}"

    let private pipeOf (fd : int) (system : UnixSystem<int, string>) : PipeId =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Pipe (pipeId, _)) -> pipeId
        | other -> failwith $"fd %d{fd} is %A{other}, not a pipe end"

    /// Closing every launched descriptor frees standard input's pipe, whose
    /// writer had already gone, and leaves the output pipes, whose read ends the
    /// client still holds.
    [<Test>]
    let ``a launched pipe lives while the client holds its far end`` () : unit =
        for platform in platforms do
            let system : UnixSystem<int, string> =
                UnixSystem.initial platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let input, output, error = pipeOf 0 system, pipeOf 1 system, pipeOf 2 system

            let closed =
                (system, [ 0 ; 1 ; 2 ])
                ||> List.fold (fun system fd ->
                    match UnixDescriptor.tryClose (Callers.leader system) fd system with
                    | Ok (SyscallAnswer.Completed 0L, system) -> system
                    | other -> failwith $"close %d{fd}: %A{other}"
                )

            UnixSystem.pipes closed
            |> Map.keys
            |> Set.ofSeq
            |> shouldEqual (Set.ofList [ output ; error ])

            Map.containsKey input (UnixSystem.pipes closed) |> shouldEqual false
            UnixSystem.checkInvariants closed |> shouldEqual []

    [<Test>]
    let ``a drained pipe holding bytes is a defect`` () : unit =
        for platform in platforms do
            let system : UnixSystem<int, string> =
                UnixSystem.initial platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let output = pipeOf 1 system
            let pipe = UnixMachineState.pipe output (Kernel.machine system)

            let forged =
                Kernel.mapMachine
                    (fun machine ->
                        { machine with
                            Pipes =
                                Map.add
                                    output
                                    { pipe with
                                        Buffer = snd (PipeBuffer.write (payload 0 5) pipe.Buffer)
                                    }
                                    machine.Pipes
                        }
                    )
                    system

            UnixSystem.checkInvariants forged
            |> shouldEqual [ UnixSystemDefect.DrainedPipeHoldsBytes (output, 5) ]
