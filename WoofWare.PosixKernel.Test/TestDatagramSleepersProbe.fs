namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Threads asleep in receives on one UDP socket, and what wakes which of them,
/// as `udp-sleepers.c` (docs/plans/2026-10-18-udp-data-path, plan section
/// 2.16) made them on each flavour: every row it recorded is made again in
/// this kernel, its sleepers parked in the same calls in the same order and
/// its events made between them, and after each event every sleeper must
/// stand as it did there.
///
/// A real kernel's woken threads run when its scheduler says. Here a woken
/// thread runs when the replay finishes it, and the replay finishes first,
/// in the order they returned there, the threads the row saw return after
/// the event, then every other woken thread. So where Darwin wakes every
/// sleeper and they race, the replay takes the race's outcome from the row,
/// and holds the model to answering it; and where a woken thread finds
/// nothing and sleeps again, the row must show it asleep. On Linux, which
/// wakes one sleeper per arrival, a sleeper the model woke that slept again
/// shows in the row's count of its sleeps.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramSleepersProbe =

    /// A kernel the probe ran on, as this library models it, and the embedded
    /// resource holding what the probe printed there.
    type private Recording =
        {
            Platform : SimulatedUnixPlatform
            Resource : string
        }

    let private recordings : Map<string, Recording> =
        [
            "darwin 27.0",
            {
                Platform = SimulatedUnixPlatform.macOsArm64
                Resource = "WoofWare.PosixKernel.Test.udpSleepers.darwin.txt"
            }
            "6.18.5 container",
            {
                Platform = SimulatedUnixPlatform.linuxArm64
                Resource = "WoofWare.PosixKernel.Test.udpSleepers.linux.txt"
            }
        ]
        |> Map.ofList

    let private recordingNames : string list = recordings |> Map.keys |> List.ofSeq

    // ------------------------------------------------------------ the rows

    /// One sleeper as a row saw it after an event.
    [<RequireQualifiedAccess>]
    type private Seen =
        /// Asleep, having gone to sleep `sleeps` more times since it parked
        /// (Linux only).
        | Asleep of sleeps : int option
        /// Not yet parked: a late sleeper before its "park" event.
        | Unparked
        /// Returned `answer`, the `order`th of the row's sleepers to return.
        | Returned of answer : string * order : int

    /// What a row printed after one of its steps: how many had returned, and
    /// each sleeper.
    type private Observation =
        {
            When : string
            Returned : int
            Sleepers : Seen list
        }

    /// A recorded row.
    type private Row =
        {
            Name : string
            /// Each sleeper's kind and the descriptor it sleeps through:
            /// "fd", "dup" or "latedup".
            Sleepers : (string * string) list
            Events : string list
            Observations : Observation list
            CloseAnswered : string option
            Holds : string
            SoError : int
        }

    let private lines (recording : Recording) : string list =
        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream recording.Resource with
            | null -> failwith $"embedded resource %s{recording.Resource} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> Array.filter (fun line -> line.StartsWith "V")
        |> List.ofArray

    let private seen (state : string) : Seen =
        let asleep = Regex.Match (state, @"^asleep(?: sleeps\+(\d+))?$")

        if asleep.Success then
            if asleep.Groups.[1].Success then
                Seen.Asleep (Some (int asleep.Groups.[1].Value))
            else
                Seen.Asleep None
        elif state = "unparked" then
            Seen.Unparked
        else
            let returned = Regex.Match (state, @"^(.*) #(\d+)$")

            if not returned.Success then
                failwith $"unrecognised sleeper state %s{state}"

            Seen.Returned (returned.Groups.[1].Value, int returned.Groups.[2].Value)

    let private rows (recording : Recording) : Row list =
        let all = lines recording

        let headers =
            all
            |> List.choose (fun line ->
                let m = Regex.Match (line, @"^(V\d+): sleepers (.*); events (.*)$")
                if m.Success then Some m else None
            )

        headers
        |> List.map (fun header ->
            let name = header.Groups.[1].Value

            let sleepers =
                header.Groups.[2].Value.Split ' '
                |> Array.map (fun sleeper ->
                    match sleeper.Split '@' with
                    | [| kind ; through |] -> kind, through
                    | _ -> failwith $"%s{name}: unrecognised sleeper %s{sleeper}"
                )
                |> List.ofArray

            let events = header.Groups.[3].Value.Split ' ' |> List.ofArray

            let observations =
                all
                |> List.choose (fun line ->
                    let m =
                        Regex.Match (line, "^" + Regex.Escape name + @" (parked|after [\w ]+): (\d+) returned;(.*)$")

                    if not m.Success then
                        None
                    else
                        let sleepers =
                            Regex.Matches (m.Groups.[3].Value, @"\[(\d+) (\w+) ([^\]]*)\]")
                            |> Seq.map (fun s -> seen s.Groups.[3].Value)
                            |> List.ofSeq

                        Some
                            {
                                When = m.Groups.[1].Value
                                Returned = int m.Groups.[2].Value
                                Sleepers = sleepers
                            }
                )

            let closeAnswered =
                all
                |> List.tryPick (fun line ->
                    let m = Regex.Match (line, "^" + Regex.Escape name + @": close answered (.*)$")
                    if m.Success then Some m.Groups.[1].Value else None
                )

            let holds, soError =
                all
                |> List.pick (fun line ->
                    let m =
                        Regex.Match (
                            line,
                            "^" + Regex.Escape name + @": then the socket holds (.*); SO_ERROR=(-?\d+)$"
                        )

                    if m.Success then
                        Some (m.Groups.[1].Value, int m.Groups.[2].Value)
                    else
                        None
                )

            {
                Name = name
                Sleepers = sleepers
                Events = events
                Observations = observations
                CloseAnswered = closeAnswered
                Holds = holds
                SoError = soError
            }
        )

    // ------------------------------------------------------------ the model

    type private World = UnixSystem<int, string>

    /// The leader, which makes every call but the sleepers' own.
    let private leader : int = 0

    /// The thread sleeper `index` sleeps in.
    let private threadOf (index : int) : int = index + 1

    let private flavourOf (system : World) : SimulatedUnixFlavour =
        SimulatedUnixPlatform.flavour (UnixSystem.platform system)

    let private flag (system : World) (message : MessageFlag) : int =
        MessageFlag.number (flavourOf system) message |> Option.get

    let private returned (thread : int) (system : World) : World =
        ReturnsToUser.untilResumed (Callers.thread thread system) system

    /// The leader's call, refused or not, and the leader back in user mode.
    let private leaderStep (call : Syscall<int, string>) (system : World) : SteppedCall<int, string> =
        match UnixSystem.tryStep (Callers.thread leader system) call system with
        | Ok stepped -> stepped
        | Error refusal -> failwith $"the leader's %A{call} was refused: %s{SyscallRefusal.describe refusal}"

    let private udp (system : World) : int * World =
        match leaderStep (Syscall.Socket (SimulatedUnixPlatform.internetAddressFamily, 2, 0)) system with
        | SteppedCall.Socket (DescriptorAnswer.Returned fd, system) -> fd, returned leader system
        | other -> failwith $"socket: %A{other}"

    let private inet (system : World) (endpoint : Ipv4Endpoint) : ImmutableArray<byte> =
        ImmutableArray.Create<byte> (
            CopyIn.blob (UnixSystem.platform system) SimulatedUnixPlatform.internetAddressFamily endpoint
        )

    let private loopbackAt (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private bindTo (fd : int) (port : uint16) (system : World) : World =
        match leaderStep (Syscall.Bind (fd, CopiedArgument.Readable (inet system (loopbackAt port)), 16u)) system with
        | SteppedCall.Bind (BindAnswer.Bound _, system) -> returned leader system
        | other -> failwith $"bind: %A{other}"

    let private portOf (fd : int) (system : World) : uint16 =
        match leaderStep (Syscall.GetSockName (fd, UserBuffer.Mapped, 16u)) system with
        | SteppedCall.GetSockName (GetSockNameAnswer.Reported (copied, _)) -> (CopyOut.endpoint copied).Port
        | other -> failwith $"getsockname: %A{other}"

    let private bound (system : World) : int * World =
        let fd, system = udp system
        fd, bindTo fd 0us system

    let private closeAs (fd : int) (system : World) : string * World =
        match leaderStep (Syscall.Close fd) system with
        | SteppedCall.Close (SyscallAnswer.Completed value, system) -> $"%d{value}", returned leader system
        | SteppedCall.Close (SyscallAnswer.Failed error, system) -> $"-1 %O{error}", returned leader system
        | other -> failwith $"close: %A{other}"

    let private sendTo (fd : int) (text : string) (port : uint16) (system : World) : World =
        let bytes = ImmutableArray.Create<byte> (Encoding.ASCII.GetBytes text)

        let call =
            Syscall.SendTo (
                fd,
                CopiedArgument.Readable bytes,
                uint64 bytes.Length,
                0,
                CopiedArgument.Readable (inet system (loopbackAt port)),
                16u
            )

        match leaderStep call system with
        | SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns _, system)) -> returned leader system
        | other -> failwith $"sendto: %A{other}"

    let private sendThrough (fd : int) (system : World) : World =
        let bytes = ImmutableArray.Create<byte> [| byte 'x' |]

        match leaderStep (Syscall.Send (fd, CopiedArgument.Readable bytes, 1UL, 0)) system with
        | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.Returns _, system)) -> returned leader system
        | other -> failwith $"send: %A{other}"

    /// Every datagram `fd` holds, as the probe's `drain_text` prints them.
    let private drainText (fd : int) (system : World) : string * World =
        let dontWait = flag system MessageFlag.DontWait

        let rec go (seen : string list) (system : World) =
            match leaderStep (Syscall.Recv (fd, UserBuffer.Mapped, 63UL, dontWait)) system with
            | SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) ->
                go (Encoding.ASCII.GetString (bytes.AsSpan ()) :: seen) (returned leader system)
            | SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Failed UnixError.EAGAIN), system) ->
                List.rev seen, returned leader system
            | SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Failed UnixError.ECONNREFUSED), system) ->
                go ("ECONNREFUSED" :: seen) (returned leader system)
            | other -> failwith $"recv: %A{other}"

        match go [] system with
        | [], system -> "none", system
        | seen, system -> String.Join ("|", seen), system

    let private soError (fd : int) (system : World) : int =
        let platform = UnixSystem.platform system

        let call =
            Syscall.GetSockOpt (
                fd,
                SimulatedUnixPlatform.socketOptionLevel platform,
                SimulatedUnixPlatform.socketErrorOption platform,
                UserBuffer.Mapped,
                CopiedArgument.Readable 4u
            )

        match leaderStep call system with
        | SteppedCall.GetSockOpt (answer, _) -> OptionValue.readInt answer
        | other -> failwith $"SO_ERROR: %A{other}"

    /// What the length cell of a `kind` of sleeper holds, and the call it
    /// makes through `fd`.
    let private cellOf (kind : string) : uint32 =
        if kind = "cellneg" then UInt32.MaxValue else 16u

    let private callOf (system : World) (kind : string) (fd : int) : Syscall<int, string> =
        let recvFrom (count : uint64) (flags : int) (source : UserBuffer) (cell : CopiedArgument<uint32>) =
            Syscall.RecvFrom (fd, UserBuffer.Mapped, count, flags, source, cell)

        match kind with
        | "take" -> Syscall.Recv (fd, UserBuffer.Mapped, 16UL, 0)
        | "peek" -> Syscall.Recv (fd, UserBuffer.Mapped, 16UL, flag system MessageFlag.Peek)
        | "zero" -> Syscall.Recv (fd, UserBuffer.Mapped, 0UL, 0)
        | "read" -> Syscall.Read (fd, UserBuffer.Mapped, 16UL)
        | "readzero" -> Syscall.Read (fd, UserBuffer.Mapped, 0UL)
        | "waitall" -> Syscall.Recv (fd, UserBuffer.Mapped, 16UL, flag system MessageFlag.WaitAll)
        | "badbuf" -> Syscall.Recv (fd, UserBuffer.Unmapped 1UL, 16UL, 0)
        | "from" -> recvFrom 16UL 0 UserBuffer.Mapped (CopiedArgument.Readable 16u)
        | "fromtrunc" -> recvFrom 2UL (flag system MessageFlag.Truncate) UserBuffer.Mapped (CopiedArgument.Readable 16u)
        | "cellnull" -> recvFrom 16UL 0 UserBuffer.Mapped (CopiedArgument.Unmapped 0UL)
        | "cellbad" -> recvFrom 16UL 0 UserBuffer.Mapped (CopiedArgument.Unmapped 1UL)
        | "cellneg" -> recvFrom 16UL 0 UserBuffer.Mapped (CopiedArgument.Readable UInt32.MaxValue)
        | "addrbad" -> recvFrom 16UL 0 (UserBuffer.Unmapped 1UL) (CopiedArgument.Readable 16u)
        | _ -> failwith $"unknown kind %s{kind}"

    /// A sleeper's answer, as the probe's `describe` prints it.
    let private readShown (kind : string) (answer : ReadAnswer) : string =
        match answer with
        | ReadAnswer.Failed error -> $"-1 %O{error}"
        | ReadAnswer.Completed bytes when bytes.IsEmpty || kind = "badbuf" -> $"%d{bytes.Length}"
        | ReadAnswer.Completed bytes -> $"%d{bytes.Length} '%s{Encoding.ASCII.GetString (bytes.AsSpan ())}'"
        | ReadAnswer.Drawn _ -> failwith "a socket read drew entropy"

    let private recvFromShown (kind : string) (senderPort : uint16) (answer : RecvFromAnswer) : string =
        match answer with
        | RecvFromAnswer.Failed error
        | RecvFromAnswer.FailedAfterReceiving (error, _, _) -> $"-1 %O{error}"
        | RecvFromAnswer.Received (bytes, returned, source) ->
            let text =
                if returned > 0L then
                    $"%d{returned} '%s{Encoding.ASCII.GetString (bytes.AsSpan ())}'"
                else
                    $"%d{returned}"

            let cell =
                match source with
                | PeerAddressCopy.Written (_, length) -> uint32 length
                | PeerAddressCopy.NotRequested -> cellOf kind

            let cellShown =
                if List.contains kind [ "from" ; "fromtrunc" ; "cellneg" ; "addrbad" ] then
                    $" cell=%d{cell}"
                else
                    ""

            let sourceShown =
                if List.contains kind [ "from" ; "fromtrunc" ; "cellnull" ; "cellneg" ] then
                    match source with
                    | PeerAddressCopy.Written (written, _) when written.Length >= 4 ->
                        let port = (uint16 written.[2] <<< 8) ||| uint16 written.[3]

                        if port = senderPort then
                            " source=sender"
                        else
                            $" source=%d{port}"
                    | PeerAddressCopy.Written _
                    | PeerAddressCopy.NotRequested -> " source=unwritten"
                else
                    ""

            text + cellShown + sourceShown

    /// One sleeper as the model has it.
    type private Sleeper =
        {
            Kind : string
            Fd : int
            Started : bool
            Answer : (string * int) option
            /// How many times its call has gone back to sleep since it parked.
            Reparks : int
        }

    /// The model's run of a row so far.
    type private Run =
        {
            System : World
            R : int
            /// The port the sleepers' socket is bound to.
            RPort : uint16
            D : int
            Sender : int
            SenderPort : uint16
            /// The port nobody held that the sleepers' socket is connected
            /// to, for a row whose events raise the ICMP error.
            Peer : uint16
            PeerSocket : int option
            Closed : bool
            Sent : int
            Sleepers : Sleeper list
            Returned : int
            CloseAnswered : string option
            /// Why the model refused a call of the row, if it did.
            Refused : string option
        }

    let private texts : string list =
        [ "one" ; "two" ; "three" ; "four" ; "five" ; "six" ]

    let private withSleeper (index : int) (update : Sleeper -> Sleeper) (run : Run) : Run =
        { run with
            Sleepers =
                run.Sleepers
                |> List.mapi (fun i sleeper -> if i = index then update sleeper else sleeper)
        }

    let private answered (index : int) (answer : string) (system : World) (run : Run) : Run =
        let order = run.Returned + 1

        { run with
            System = system
            Returned = order
        }
        |> withSleeper
            index
            (fun sleeper ->
                { sleeper with
                    Answer = Some (answer, order)
                }
            )

    /// The run after sleeper `index`'s call answered `outcome`, read by
    /// `answerOf`, in `system`: back in user mode if it returned, asleep if
    /// it parked.
    let private afterCall
        (index : int)
        (reparked : bool)
        (outcome : Choice<string, unit, unit>)
        (system : World)
        (run : Run)
        : Run
        =
        let thread = threadOf index

        match outcome with
        | Choice1Of3 answer -> answered index answer (returned thread system) run
        | Choice2Of3 () ->
            { run with
                System = system
            }
            |> withSleeper
                index
                (fun sleeper ->
                    { sleeper with
                        Reparks = if reparked then sleeper.Reparks + 1 else sleeper.Reparks
                    }
                )
        | Choice3Of3 () ->
            match Interruptions.handled (Callers.thread thread system) system with
            | Ok (InterruptedCall.FailsWithEintr, system) -> answered index "-1 EINTR" system run
            | Ok (InterruptedCall.Restarts, _) -> failwith $"sleeper %d{index}'s call restarted, with no SA_RESTART"
            | Error refusal -> failwith $"sleeper %d{index}'s return was refused: %A{refusal}"

    let private readOutcome (kind : string) (outcome : ReadOutcome) : Choice<string, unit, unit> =
        match outcome with
        | ReadOutcome.Answered answer -> Choice1Of3 (readShown kind answer)
        | ReadOutcome.WouldBlock _ -> Choice2Of3 ()
        | ReadOutcome.Interrupted -> Choice3Of3 ()

    let private recvFromOutcome (kind : string) (run : Run) (outcome : RecvFromOutcome) : Choice<string, unit, unit> =
        match outcome with
        | RecvFromOutcome.Answered answer -> Choice1Of3 (recvFromShown kind run.SenderPort answer)
        | RecvFromOutcome.WouldBlock _ -> Choice2Of3 ()
        | RecvFromOutcome.Interrupted -> Choice3Of3 ()

    /// Sleeper `index` making its call.
    let private park (index : int) (run : Run) : Run =
        let sleeper = run.Sleepers.[index]
        let thread = threadOf index
        let system = Threads.ensure thread run.System

        let started =
            withSleeper
                index
                (fun sleeper ->
                    { sleeper with
                        Started = true
                    }
                )
                run

        match UnixSystem.tryStep (Callers.thread thread system) (callOf system sleeper.Kind sleeper.Fd) system with
        | Error refusal ->
            { started with
                Refused = Some $"sleeper %d{index}'s call: %s{SyscallRefusal.describe refusal}"
            }
        | Ok (SteppedCall.Recv (outcome, system))
        | Ok (SteppedCall.Read (outcome, system)) ->
            afterCall index false (readOutcome sleeper.Kind outcome) system started
        | Ok (SteppedCall.RecvFrom (outcome, system)) ->
            afterCall index false (recvFromOutcome sleeper.Kind started outcome) system started
        | Ok other -> failwith $"sleeper %d{index}'s call answered %A{other}"

    /// The woken sleeper `index`'s call finished.
    let private finish (index : int) (run : Run) : Run =
        let sleeper = run.Sleepers.[index]
        let system = run.System
        let caller = Callers.thread (threadOf index) system

        // The call the sleeper made, with what its length cell held, which a
        // Linux call reads once its datagram has come.
        let call =
            match ParkedCall.ofThread caller system with
            | Syscall.RecvFrom (fd, buffer, count, flags, source, CopiedArgument.Readable _) ->
                Syscall.RecvFrom (fd, buffer, count, flags, source, CopiedArgument.Readable (cellOf sleeper.Kind))
            | call -> call

        match UnixWait.tryFinish caller call system with
        | Error refusal ->
            { run with
                Refused = Some $"finishing sleeper %d{index}: %s{FinishRefusal.describe refusal}"
            }
        | Ok (FinishedCall.DatagramReceive (FinishedDatagramReceive.Read (outcome, system))) ->
            afterCall index true (readOutcome sleeper.Kind outcome) system run
        | Ok (FinishedCall.DatagramReceive (FinishedDatagramReceive.RecvFrom (outcome, system))) ->
            afterCall index true (recvFromOutcome sleeper.Kind run outcome) system run
        | Ok other -> failwith $"finishing sleeper %d{index} answered %A{other}"

    /// The run once every sleeper a wake wakes has been finished, again and
    /// again until a wake wakes none: first those `returnedNext` names, in
    /// that order, then the rest in the order of their indices.
    let private settle (returnedNext : int list) (run : Run) : Run =
        let rec go (rounds : int) (run : Run) : Run =
            if rounds > 20 || run.Refused.IsSome then
                run
            else

            let woken, system = UnixWait.wake run.System

            let woken =
                woken
                |> List.map (fun (caller, _) -> Caller.thread caller - 1)
                |> List.filter (fun index -> index >= 0)

            match woken with
            | [] ->
                { run with
                    System = system
                }
            | woken ->
                let first = returnedNext |> List.filter (fun index -> List.contains index woken)

                let rest =
                    woken |> List.filter (fun index -> not (List.contains index first)) |> List.sort

                ({ run with
                    System = system
                 },
                 first @ rest)
                ||> List.fold (fun run index -> if run.Refused.IsSome then run else finish index run)
                |> go (rounds + 1)

        go 0 run

    let private milliseconds (count : int64) (run : Run) : Run =
        { run with
            System = UnixSystem.advanceClock (count * 1_000_000L) run.System
        }

    /// The sleepers the row saw return by `observation` that had not by
    /// `before`, in the order they returned.
    let private returnedBetween (before : Observation) (observation : Observation) : int list =
        List.zip before.Sleepers observation.Sleepers
        |> List.mapi (fun index (was, now) -> index, was, now)
        |> List.choose (fun (index, was, now) ->
            match was, now with
            | Seen.Returned _, _ -> None
            | _, Seen.Returned (_, order) -> Some (order, index)
            | _ -> None
        )
        |> List.sort
        |> List.map snd

    let private event (name : string) (run : Run) : Run =
        match name with
        | "datagram"
        | "two" ->
            let times = if name = "two" then 2 else 1
            let port = run.RPort

            (run, [ 1..times ])
            ||> List.fold (fun run _ ->
                { run with
                    System = sendTo run.Sender texts.[run.Sent] port run.System
                    Sent = run.Sent + 1
                }
            )
        | "error" ->
            { run with
                System = sendThrough run.R run.System
            }
        | "peer" ->
            let port = run.RPort

            let peerSocket, system =
                match run.PeerSocket with
                | Some fd -> fd, run.System
                | None ->
                    let fd, system = udp run.System
                    fd, bindTo fd run.Peer system

            { run with
                System = sendTo peerSocket texts.[run.Sent] port system
                PeerSocket = Some peerSocket
                SenderPort = run.Peer
                Sent = run.Sent + 1
            }
        | "close" ->
            let answer, system = closeAs run.R run.System

            { run with
                System = system
                Closed = true
                CloseAnswered = Some answer
            }
        | "park" ->
            let index =
                run.Sleepers
                |> List.findIndex (fun sleeper -> not sleeper.Started && sleeper.Fd = run.D)

            park index run |> milliseconds 50L
        | "nothing" -> run
        | _ -> failwith $"unknown event %s{name}"

    /// What the model's run shows of each sleeper, as the row prints it.
    let private shownBy (run : Run) : Seen list =
        let linux = flavourOf run.System = SimulatedUnixFlavour.Linux

        run.Sleepers
        |> List.map (fun sleeper ->
            match sleeper.Answer with
            | Some (answer, order) -> Seen.Returned (answer, order)
            | None when not sleeper.Started -> Seen.Unparked
            | None -> Seen.Asleep (if linux then Some sleeper.Reparks else None)
        )

    /// The model's run of `row`, and where it parted from the row.
    let private replayRow (platform : SimulatedUnixPlatform) (row : Row) : Run * string list =
        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams leader (CpuId 0)

        let usr1 =
            Signal.toRawSignoUnder (SimulatedUnixPlatform.signalNumbering platform) Signal.SIGUSR1

        let system =
            match
                leaderStep (Syscall.SigAction (usr1, Some (SignalDisposition.Catch (SignalCatch.ofHandler "h")))) system
            with
            | SteppedCall.SigAction (SigactionAnswer.Completed _, system) -> returned leader system
            | other -> failwith $"sigaction: %A{other}"

        let connected =
            row.Events |> List.exists (fun event -> event = "error" || event = "peer")

        let r, system = bound system

        let peer, system =
            if connected then
                let unheld, system = bound system
                let port = portOf unheld system
                let _, system = closeAs unheld system

                match
                    leaderStep
                        (Syscall.Connect (r, CopiedArgument.Readable (inet system (loopbackAt port)), 16u))
                        system
                with
                | SteppedCall.Connect (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) ->
                    port, returned leader system
                | other -> failwith $"connect: %A{other}"
            else
                0us, system

        let d, system =
            match leaderStep (Syscall.Dup r) system with
            | SteppedCall.Dup (DescriptorAnswer.Returned fd, system) -> fd, returned leader system
            | other -> failwith $"dup: %A{other}"

        let sender, system = bound system

        let run =
            {
                System = system
                R = r
                RPort = portOf r system
                D = d
                Sender = sender
                SenderPort = portOf sender system
                Peer = peer
                PeerSocket = None
                Closed = false
                Sent = 0
                Sleepers =
                    row.Sleepers
                    |> List.map (fun (kind, through) ->
                        {
                            Kind = kind
                            Fd = (if through = "fd" then r else d)
                            Started = false
                            Answer = None
                            Reparks = 0
                        }
                    )
                Returned = 0
                CloseAnswered = None
                Refused = None
            }

        let observed (whenSeen : string) : Observation =
            match
                row.Observations
                |> List.tryFind (fun observation -> observation.When = whenSeen)
            with
            | Some observation -> observation
            | None -> failwith $"%s{row.Name}: no observation %s{whenSeen}"

        let differences (observation : Observation) (run : Run) : string list =
            let shown = shownBy run

            [
                for defect in UnixSystem.checkInvariants run.System do
                    $"%s{row.Name} %s{observation.When}: %s{UnixSystemDefect.describe defect}"
                if run.Returned <> observation.Returned then
                    $"%s{row.Name} %s{observation.When}: %d{run.Returned} returned, measured %d{observation.Returned}"
                for index, (model, measured) in List.indexed (List.zip shown observation.Sleepers) do
                    match model, measured with
                    // Darwin prints no count of sleeps.
                    | Seen.Asleep _, Seen.Asleep None -> ()
                    | model, measured when model = measured -> ()
                    | model, measured ->
                        $"%s{row.Name} %s{observation.When}: sleeper %d{index} is %A{model}, measured %A{measured}"
            ]

        // The initial parks, 50 ms apart.
        let parked = observed "parked"

        let run =
            (run, List.indexed row.Sleepers)
            ||> List.fold (fun run (index, (_, through)) ->
                if through = "latedup" || run.Refused.IsSome then
                    run
                else
                    park index run |> milliseconds 50L
            )

        let mutable found = differences parked run
        let mutable previous = parked

        let run =
            (run, List.indexed row.Events)
            ||> List.fold (fun run (index, name) ->
                if run.Refused.IsSome then
                    run
                else

                // The probe names each observation by its event, so two of one
                // event are told apart by order.
                let observation =
                    row.Observations
                    |> List.filter (fun observation -> observation.When = $"after %s{name}")
                    |> List.item (row.Events |> List.take index |> List.filter ((=) name) |> List.length)

                let run =
                    run
                    |> event name
                    |> milliseconds 100L
                    |> settle (returnedBetween previous observation)

                if run.Refused.IsNone then
                    found <- found @ differences observation run

                previous <- observation
                run
            )

        if run.Refused.IsSome then
            run, found
        else

        // A signal to every sleeper still asleep.
        let signalled = observed "after the signal"

        let run =
            (run, List.indexed run.Sleepers)
            ||> List.fold (fun run (index, sleeper) ->
                if sleeper.Started && sleeper.Answer.IsNone then
                    match leaderStep (Syscall.PthreadKill (threadOf index, usr1)) run.System with
                    | SteppedCall.PthreadKill (ProcessFate.Continues (KillAnswer.Completed _, system)) ->
                        { run with
                            System = returned leader system
                        }
                    | other -> failwith $"pthread_kill: %A{other}"
                else
                    run
            )
            |> settle (returnedBetween previous signalled)

        if run.Refused.IsSome then
            run, found
        else

        let live = if run.Closed then run.D else run.R
        let holds, system = drainText live run.System
        let error = soError live system

        let tail =
            [
                if differences signalled run <> [] then
                    yield! differences signalled run
                if run.CloseAnswered <> row.CloseAnswered then
                    $"%s{row.Name}: close answered %A{run.CloseAnswered}, measured %A{row.CloseAnswered}"
                if holds <> row.Holds then
                    $"%s{row.Name}: the socket holds %s{holds}, measured %s{row.Holds}"
                if error <> row.SoError then
                    $"%s{row.Name}: SO_ERROR %d{error}, measured %d{row.SoError}"
            ]

        run, found @ tail

    /// Whether the model refuses `row` on `platform`, as it is meant to:
    /// `MSG_WAITALL`, which it does not model, and a Darwin receive into a
    /// buffer nothing maps, which strips the datagram it leaves.
    let private refuses (platform : SimulatedUnixPlatform) (row : Row) : bool =
        row.Sleepers
        |> List.exists (fun (kind, _) ->
            kind = "waitall"
            || (kind = "badbuf"
                && SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin)
        )

    [<TestCaseSource(nameof recordingNames)>]
    let ``every row the probe recorded is the model's`` (name : string) : unit =
        let recording = recordings.[name]
        let rows = rows recording
        rows |> List.length |> shouldEqual 30

        let differences =
            rows
            |> List.collect (fun row ->
                let run, found = replayRow recording.Platform row

                match run.Refused, refuses recording.Platform row with
                | Some _, true -> []
                | None, false -> found
                | Some refusal, false -> [ $"%s{row.Name}: refused, %s{refusal}" ]
                | None, true -> [ $"%s{row.Name}: answered, where the model refuses it" ]
            )

        differences |> shouldEqual []
