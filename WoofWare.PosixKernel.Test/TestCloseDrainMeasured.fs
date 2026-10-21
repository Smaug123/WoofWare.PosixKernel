namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `tcp-close-drain.c` (docs/plans/2026-10-07-tcp-byte-transfer), replayed: what
/// a close does to calls asleep on a connected TCP socket or a pipe end through
/// a `dup` of the descriptor closed, and to calls made through the dup later.
///
/// Each row of each flavour's committed output is run again on the library:
/// the same sleepers, each a thread of its own, and the same events, each
/// followed by every woken call finished. After the setup and after each event,
/// every sleeper's state must be the one the row reports: unparked, asleep, or
/// returned with the same count or errno. Then what is queued for the dup, what
/// the peer holds and the dup has yet to send, and Darwin's `FWASWRITTEN` on
/// the dup's description, must be as the row reports them.
///
/// Rows and parts of rows that no model state could reproduce are left out,
/// each for a reason given beside it.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestCloseDrainMeasured =

    [<RequireQualifiedAccess>]
    type private Kind =
        | Read
        | Recv
        | Peek
        | Write
        | Big
        | Poll
        | Select

    [<RequireQualifiedAccess>]
    type private Via =
        | Fd
        | Dup
        | Later

    type private SleeperSpec =
        {
            Kind : Kind
            Via : Via
        }

    /// A sleeper as a row reports it, the order it returned in left out.
    [<RequireQualifiedAccess>]
    type private State =
        | Unparked
        | Asleep
        | Count of int64
        | Failed of string

    [<RequireQualifiedAccess>]
    type private Line =
        /// Each sleeper's state, and the order it returned in, if it has.
        | Report of label : string * states : State list * returned : int option list
        | Close of answer : string
        | NonBlockingRecv of answer : string
        | Poll of count : int * revents : int
        | Then of queued : int * status : int * inFlight : int option

    type private Row =
        {
            Name : string
            Pipe : bool
            Sleepers : SleeperSpec list
            Events : string list
            Lines : Line list
        }

    let private lines (resource : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.%s{resource}"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    let private kindOf (name : string) : Kind =
        match name with
        | "read" -> Kind.Read
        | "recv" -> Kind.Recv
        | "peek" -> Kind.Peek
        | "write" -> Kind.Write
        | "big" -> Kind.Big
        | "poll" -> Kind.Poll
        | "select" -> Kind.Select
        | other -> failwith $"no such sleeper kind: %s{other}"

    let private viaOf (name : string) : Via =
        match name with
        | "fd" -> Via.Fd
        | "dup" -> Via.Dup
        | "later" -> Via.Later
        | other -> failwith $"no such sleeper descriptor: %s{other}"

    let private returnedOf (text : string) : int option =
        let m = Regex.Match (text, " #(\\d+)$")
        if m.Success then Some (int m.Groups.[1].Value) else None

    let private stateOf (text : string) : State =
        let text = Regex.Replace (text, " #\\d+$", "")

        match text with
        | "unparked" -> State.Unparked
        | "asleep" -> State.Asleep
        | _ when text.StartsWith "-1 " -> State.Failed (text.Substring 3)
        | _ -> State.Count (Int64.Parse (text.Split(' ').[0]))

    let private header = Regex "^(\\w+): (tcp|pipe), sleepers (.*); events (.*)$"
    let private report = Regex "^(\\w+) (parked|after [\\w ]+): \\d+ returned;(.*)$"
    let private sleeper = Regex "\\[\\d+ (\\w+)@(\\w+) ([^\\]]*)\\]"
    let private closeLine = Regex "^(\\w+): close answered (-?\\d+ \\S+) in \\d+ ms$"

    let private recvLine =
        Regex "^(\\w+): recv\\(dup, MSG_DONTWAIT\\) answered (-?\\d+ \\S+)$"

    let private pollLine =
        Regex "^(\\w+): poll\\(dup, IN\\|OUT, 0\\) answered (\\d+) revents=0x([0-9a-f]+)$"

    let private thenLine =
        Regex
            "^(\\w+): then (\\d+) bytes queued for the (?:dup|read end); dup's F_GETFL 0x([0-9a-f]+)(?:; peer holds (\\d+), dup has (\\d+) unsent)?; sigpipe \\d+$"

    let private rowsOf (resource : string) : Row list =
        let parseLine (text : string) : string * Line =
            let m = report.Match text

            if m.Success then
                let sleepers = sleeper.Matches m.Groups.[3].Value |> List.ofSeq
                let states = sleepers |> List.map (fun s -> stateOf s.Groups.[3].Value)
                let returned = sleepers |> List.map (fun s -> returnedOf s.Groups.[3].Value)
                m.Groups.[1].Value, Line.Report (m.Groups.[2].Value, states, returned)
            else

            let m = closeLine.Match text

            if m.Success then
                m.Groups.[1].Value, Line.Close m.Groups.[2].Value
            else

            let m = recvLine.Match text

            if m.Success then
                m.Groups.[1].Value, Line.NonBlockingRecv m.Groups.[2].Value
            else

            let m = pollLine.Match text

            if m.Success then
                m.Groups.[1].Value, Line.Poll (int m.Groups.[2].Value, Convert.ToInt32 (m.Groups.[3].Value, 16))
            else

            let m = thenLine.Match text

            if m.Success then
                let inFlight =
                    if m.Groups.[4].Success then
                        Some (int m.Groups.[4].Value + int m.Groups.[5].Value)
                    else
                        None

                m.Groups.[1].Value,
                Line.Then (int m.Groups.[2].Value, Convert.ToInt32 (m.Groups.[3].Value, 16), inFlight)
            else
                failwith $"%s{resource}: an unrecognised line: %s{text}"

        let rec go (rows : Row list) (remaining : string list) : Row list =
            match remaining with
            | [] -> List.rev rows
            | first :: rest ->
                let m = header.Match first

                if not m.Success then
                    failwith $"%s{resource}: expected a row's header, got %s{first}"

                let name = m.Groups.[1].Value

                let sleepers =
                    m.Groups.[3].Value.Split ' '
                    |> Array.map (fun spec ->
                        match spec.Split '@' with
                        | [| kind ; via |] ->
                            {
                                Kind = kindOf kind
                                Via = viaOf via
                            }
                        | _ -> failwith $"%s{resource}: a malformed sleeper: %s{spec}"
                    )
                    |> List.ofArray

                let mine, rest =
                    rest
                    |> List.partition (fun line -> not (header.IsMatch line) && fst (parseLine line) = name)

                let row =
                    {
                        Name = name
                        Pipe = m.Groups.[2].Value = "pipe"
                        Sleepers = sleepers
                        Events = m.Groups.[4].Value.Split ' ' |> List.ofArray
                        Lines = mine |> List.map (parseLine >> snd)
                    }

                go (row :: rows) rest

        go [] (lines resource)

    let private payload (seed : int) (count : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Seq.init count (fun i -> byte ((seed * 37 + i) % 251)))

    /// TCP buffers as small as each flavour admits, as `TestBlockingConnection`
    /// has them.
    let private small (image : UnixBootImage<int, string>) : UnixBootImage<int, string> =
        match SimulatedUnixPlatform.flavour (UnixBootImage.platform image) with
        | SimulatedUnixFlavour.Linux ->
            image
            |> UnixBootImage.tryWithTcpSendSpaceMax (Some 30000)
            |> Configured.expectOk TcpSendSpaceMaxRefusal.describe
            |> UnixBootImage.tryWithTcpReceiveSpace (Some 10000)
            |> Configured.expectOk TcpReceiveSpaceRefusal.describe
        | SimulatedUnixFlavour.Darwin ->
            image
            |> UnixBootImage.tryWithTcpSendSpace (Some UnixMachineState.darwinLoopbackSendPipe)
            |> Configured.expectOk TcpSendSpaceRefusal.describe
            |> UnixBootImage.tryWithTcpReceiveSpace (Some UnixMachineState.darwinLoopbackReceivePipe)
            |> Configured.expectOk TcpReceiveSpaceRefusal.describe

    /// Threads 0 to 3: thread 0 makes the events' calls, and sleeper `i` is
    /// thread `i + 1`.
    /// `SIGPIPE` is ignored, where the probe caught it: a close that ends a
    /// pipe write raises it, and a library close cannot run a handler.
    let private systemOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial<int, string> platform
            |> small
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> fun system -> ([ 0 ; 1 ; 2 ; 3 ], system) ||> List.foldBack Threads.ensure

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

    let private port : uint16 = 6200us

    let private connected (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
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

    let private nonBlocking (fd : int) (value : bool) (system : UnixSystem<int, string>) =
        UnixDescriptor.setNonBlocking (Callers.leader system) fd value system |> snd

    let private flags (system : UnixSystem<int, string>) (flags : MessageFlag list) : int =
        MessageFlag.encode (SimulatedUnixPlatform.flavour (UnixSystem.platform system)) flags
        |> Option.get

    /// `fd`'s buffers full, by thread 0's sends (TCP) or writes (a pipe)
    /// through a non-blocking description of `count` bytes and then of one,
    /// until `EAGAIN`, and the description blocking again.
    let private filled (pipe : bool) (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let rec fill (count : int) (system : UnixSystem<int, string>) =
            let step =
                if pipe then
                    WriteOutcomes.admitThenWrite 0 fd UserBuffer.Mapped (payload 1 count) system
                else
                    WriteOutcomes.admitThenSend 0 fd UserBuffer.Mapped (payload 1 count) 0 system
                    |> Result.mapError (fun refusal -> failwith $"send refused: %s{SendRefusal.describe refusal}")

            match step with
            | Ok (WriteStep.Returns (WriteAnswer.Completed _, system)) -> fill count system
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.EAGAIN, system)) ->
                if count = 1 then system else fill 1 system
            | other -> failwith $"filling fd %d{fd}: %A{other}"

        system |> nonBlocking fd true |> fill 65536 |> nonBlocking fd false

    /// Thread 0 reads `fd` through a non-blocking description until `EAGAIN`.
    let private emptied (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let rec empty (system : UnixSystem<int, string>) =
            match UnixReadWrite.tryRead (Callers.thread 0 system) fd UserBuffer.Mapped 65536UL system with
            | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) when bytes.Length > 0 -> empty system
            | Ok (ReadOutcome.Answered (ReadAnswer.Failed UnixError.EAGAIN), system) -> system
            | other -> failwith $"emptying fd %d{fd}: %A{other}"

        system |> nonBlocking fd true |> empty |> nonBlocking fd false

    let private available (fd : int) (system : UnixSystem<int, string>) : int =
        match UnixDescriptor.tryBytesAvailable (Callers.leader system) fd UserBuffer.Mapped system with
        | Ok (BytesAvailableAnswer.Reported count, _) -> count
        | other -> failwith $"FIONREAD of fd %d{fd}: %A{other}"

    let private markedWritten (fd : int) (system : UnixSystem<int, string>) : bool =
        match FileDescriptorRegistry.tryFindWithId fd (Lone.fileDescriptors system) with
        | Some (_, description) ->
            match description.Status with
            | OpenFileStatus.Darwin (written = written) -> written
            | OpenFileStatus.Linux _ -> false
        | None -> failwith $"fd %d{fd} names no description"

    /// The bytes still on their way from `fd`'s socket to the peer: in its
    /// send buffer, and in the peer's receive buffer.
    let private inFlight (peer : int) (fd : int) (system : UnixSystem<int, string>) : int =
        let socket =
            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) -> socketId
            | other -> failwith $"fd %d{fd} names %A{other}"

        let machine = Kernel.machine system

        let unsent =
            match SocketPhase.connectionEnd (UnixMachineState.socket socket machine).Phase with
            | Some (connection, connectionEnd) ->
                let transfer = (UnixMachineState.connection connection machine).Transfer

                match connectionEnd with
                | ConnectionEnd.Client -> ByteQueue.length transfer.ToServer.Sending
                | ConnectionEnd.Server -> ByteQueue.length transfer.ToClient.Sending
            | None -> failwith $"fd %d{fd} is not connected"

        available peer system + unsent

    let private ofRead (outcome : Result<ReadOutcome * UnixSystem<int, string>, ReadRefusal>) =
        match outcome with
        | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), after) -> State.Count (int64 bytes.Length), after
        | Ok (ReadOutcome.Answered (ReadAnswer.Failed error), after) -> State.Failed (string<UnixError> error), after
        | Ok (ReadOutcome.WouldBlock _, after) -> State.Asleep, after
        | other -> failwith $"a read came to %A{other}"

    let private ofWrite (outcome : Result<WriteStep<WriteAnswer, UnixSystem<int, string>, int>, WriteRefusal>) =
        match outcome with
        | Ok (WriteStep.Returns (WriteAnswer.Completed n, after)) -> State.Count n, after
        | Ok (WriteStep.Returns (WriteAnswer.Failed error, after))
        | Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed error, _, after)) ->
            State.Failed (string<UnixError> error), after
        | Ok (WriteStep.WouldBlock (_, after)) -> State.Asleep, after
        | other -> failwith $"a write came to %A{other}"

    /// A write's bytes: 1000 of them, or for `Big` more than the buffers hold.
    let private bytesFor (kind : Kind) (system : UnixSystem<int, string>) : ImmutableArray<byte> =
        match kind with
        | Kind.Big ->
            let capacity =
                match SimulatedUnixPlatform.flavour (UnixSystem.platform system) with
                | SimulatedUnixFlavour.Linux -> 30000 + 10000
                | SimulatedUnixFlavour.Darwin ->
                    UnixMachineState.darwinLoopbackSendPipe
                    + UnixMachineState.darwinLoopbackReceivePipe

            payload 5 (4 * capacity)
        | _ -> payload 5 1000

    /// Sleeper `index`'s call through `fd`.
    let private launch
        (kind : Kind)
        (index : int)
        (fd : int)
        (system : UnixSystem<int, string>)
        : State * UnixSystem<int, string>
        =
        let caller = Callers.thread (index + 1) system

        match kind with
        | Kind.Read -> UnixReadWrite.tryRead caller fd UserBuffer.Mapped 4096UL system |> ofRead
        | Kind.Recv ->
            UnixReadWrite.tryRecv caller fd UserBuffer.Mapped 4096UL 0 system
            |> Result.mapError (fun r -> failwith $"recv refused: %s{ReceiveRefusal.describe r}")
            |> ofRead
        | Kind.Peek ->
            UnixReadWrite.tryRecv caller fd UserBuffer.Mapped 4096UL (flags system [ MessageFlag.Peek ]) system
            |> Result.mapError (fun r -> failwith $"recv refused: %s{ReceiveRefusal.describe r}")
            |> ofRead
        | Kind.Write
        | Kind.Big ->
            WriteOutcomes.admitThenWriteAs caller fd UserBuffer.Mapped (bytesFor kind system) system
            |> ofWrite
        | Kind.Poll
        | Kind.Select -> failwith $"no row with a %A{kind} sleeper is replayed"

    /// Every woken sleeper's call finished, until none is woken. Which of
    /// several woken calls runs first is the client's choice, and this one
    /// makes the host's: in the order the host's calls returned (`returned`),
    /// and those that had not returned last.
    let rec private settle
        (sleepers : SleeperSpec list)
        (returned : int option list)
        (states : State list)
        (system : UnixSystem<int, string>)
        : State list * UnixSystem<int, string>
        =
        match Lone.wake system with
        | [], _ -> states, system
        | woken, system ->
            let woken =
                woken
                |> List.sortBy (fun (thread, _) ->
                    match returned.[thread - 1] with
                    | Some order -> order, thread
                    | None -> Int32.MaxValue, thread
                )

            let states, system =
                ((states, system), woken)
                ||> List.fold (fun (states, system) (thread, _) ->
                    let index = thread - 1
                    let caller = Callers.thread thread system

                    let state, system =
                        match sleepers.[index].Kind with
                        | Kind.Read
                        | Kind.Recv
                        | Kind.Peek -> UnixReadWrite.tryFinishRead caller system |> ofRead
                        | kind ->
                            let bytes = bytesFor kind system

                            WriteOutcomes.finishWriteAs caller (fun offset count -> bytes.Slice (offset, count)) system
                            |> ofWrite

                    List.updateAt index state states, system
                )

            settle sleepers returned states system

    /// `row` run on `platform`, held to what the host answered.
    let private replay (platform : SimulatedUnixPlatform) (row : Row) : unit =
        let where (what : string) =
            $"%O{SimulatedUnixPlatform.flavour platform} %s{row.Name} %s{what}"

        // Not `shouldEqual`, whose failure NUnit records even when it is
        // caught: the test reports every row's failure at once.
        let check (what : string) (expected : 'a) (actual : 'a) : unit =
            if expected <> actual then
                failwith (where $"%s{what}: expected %A{expected}, got %A{actual}")

        let writers = row.Sleepers.Head.Kind = Kind.Write

        let anyWriter =
            row.Sleepers |> List.exists (fun s -> s.Kind = Kind.Write || s.Kind = Kind.Big)

        let system = systemOn platform

        // `under` is the descriptor the row closes, and `other` what its events
        // act on.
        let under, other, system =
            if row.Pipe then
                let (r, w), system = FcntlWorld.pipe 0 system

                if writers then w, r, filled true w system else r, w, system
            else
                let client, server, system = connected system
                client, server, (if anyWriter then filled false client system else system)

        let dup, system = KeventWorld.dup under system

        let states, system =
            ((List.replicate row.Sleepers.Length State.Unparked, system), List.indexed row.Sleepers)
            ||> List.fold (fun (states, system) (index, spec) ->
                match spec.Via with
                | Via.Later -> states, system
                | Via.Fd
                | Via.Dup ->
                    let state, system =
                        launch spec.Kind index (if spec.Via = Via.Fd then under else dup) system

                    List.updateAt index state states, system
            )

        let mutable states = states
        let mutable system = system
        let mutable expected = row.Lines

        // The order the host's calls returned in, as the report after the
        // step being settled says.
        let returnedNext () : int option list =
            match expected with
            | Line.Report (_, _, returned) :: _ -> returned
            | _ -> List.replicate row.Sleepers.Length None

        let next () : Line =
            match expected with
            | line :: rest ->
                expected <- rest
                line
            | [] -> failwith (where "ran out of lines")

        let expectReport (label : string) =
            match next () with
            | Line.Report (reported, reportedStates, _) ->
                check "the report" label reported

                if states <> reportedStates then
                    failwith (where $"%s{label}: expected %A{reportedStates}, got %A{states}")
            | other -> failwith (where $"expected the report %s{label}, got %A{other}")

        check "invariants" [] (UnixSystem.checkInvariants system)
        expectReport "parked"

        for event in row.Events do
            match event with
            | "close" ->
                let answer, after =
                    match UnixDescriptor.tryClose (Callers.leader system) under system with
                    | Ok (SyscallAnswer.Completed 0L, after) -> "0 0", after
                    | other -> failwith (where $"close: %A{other}")

                match next () with
                | Line.Close reported -> check "the close" reported answer
                | other -> failwith (where $"expected the close, got %A{other}")

                system <- after
            | "write" ->
                match WriteOutcomes.admitThenWrite 0 other UserBuffer.Mapped (payload 9 3) system with
                | Ok (WriteStep.Returns (WriteAnswer.Completed 3L, after)) -> system <- after
                | other -> failwith (where $"the peer's write: %A{other}")
            | "fin" ->
                match UnixConnection.tryShutdown (Callers.leader system) other 1 system with
                | Ok (ShutdownAnswer.Shut, after) -> system <- after
                | other -> failwith (where $"shutdown: %A{other}")
            | "room" ->
                // The host reads until a second passes with nothing to read,
                // so what the writers it wakes write meanwhile is read too.
                let rec room (states : State list) (system : UnixSystem<int, string>) =
                    let settled, after =
                        settle row.Sleepers (returnedNext ()) states (emptied other system)

                    if settled = states then
                        settled, after
                    else
                        room settled after

                let settled, after = room states system
                states <- settled
                system <- after
            | "park" ->
                let index =
                    List.indexed row.Sleepers
                    |> List.find (fun (index, spec) -> spec.Via = Via.Later && states.[index] = State.Unparked)
                    |> fst

                let state, after = launch row.Sleepers.[index].Kind index dup system
                states <- List.updateAt index state states
                system <- after
            | "nb" ->
                let answer, after =
                    match
                        UnixReadWrite.tryRecv
                            (Callers.thread 0 system)
                            dup
                            UserBuffer.Mapped
                            4096UL
                            (flags system [ MessageFlag.DontWait ])
                            system
                    with
                    | Ok (ReadOutcome.Answered (ReadAnswer.Completed bytes), after) -> $"%d{bytes.Length} 0", after
                    | Ok (ReadOutcome.Answered (ReadAnswer.Failed error), after) -> $"-1 %O{error}", after
                    | other -> failwith (where $"the non-blocking recv: %A{other}")

                match next () with
                | Line.NonBlockingRecv reported -> check "the non-blocking recv" reported answer
                | other -> failwith (where $"expected the non-blocking recv, got %A{other}")

                system <- after
            | "poll0" ->
                match
                    UnixPoll.tryPoll
                        (Callers.thread 0 system)
                        [
                            {
                                Fd = dup
                                Events = 0x5s
                            }
                        ]
                        0
                        system
                with
                | Ok (PollOutcome.Answered ([ revents ], count), _) ->
                    match next () with
                    | Line.Poll (reportedCount, reportedRevents) ->
                        check "the poll" (reportedCount, reportedRevents) (count, int revents)
                    | other -> failwith (where $"expected the poll, got %A{other}")
                | other -> failwith (where $"poll: %A{other}")
            | other -> failwith (where $"no such event: %s{other}")

            let settled, after = settle row.Sleepers (returnedNext ()) states system
            states <- settled
            system <- after
            check $"invariants after %s{event}" [] (UnixSystem.checkInvariants system)
            expectReport $"after %s{event}"

        // The probe then signals whatever still sleeps, which ends it with
        // EINTR on both flavours whatever the close did; the signal tests of
        // `TestBlockingConnection` and `TestBlockingPipe` hold that.
        match next () with
        | Line.Report ("after the signal", _, _) -> ()
        | other -> failwith (where $"expected the report after the signal, got %A{other}")

        match next () with
        | Line.Then (queued, status, reportedInFlight) ->
            let queuedFor = if row.Pipe && writers then other else dup
            check "the bytes queued" queued (available queuedFor system)
            check "FWASWRITTEN" (status &&& 0x10000 <> 0) (markedWritten dup system)

            match reportedInFlight with
            | None -> ()
            | Some reported ->
                let actual = inFlight other dup system

                // How much of a `Big` write the host's buffers held is theirs.
                if row.Sleepers |> List.exists (fun s -> s.Kind = Kind.Big) then
                    check "whether bytes are in flight" (reported > 0) (actual > 0)
                else
                    check "the bytes in flight" reported actual
        | other -> failwith (where $"expected the row's last line, got %A{other}")

        match expected with
        | [] -> ()
        | rest -> failwith (where $"lines left over: %A{rest}")

    /// Rows that the library cannot be run through, and why.
    let private unreplayed (flavour : SimulatedUnixFlavour) (name : string) : bool =
        match flavour, name with
        // A poll and a select asleep through the closed descriptor: what the
        // close does to the dup's reader is replayed, but no state of the
        // library has a select asleep (`ParkedSyscall.Select` is reserved),
        // and a Darwin poll asleep is a kqueue registration, which the
        // library's close drops without draining anything either way.
        | _, "T19"
        | _, "T20" -> true
        // Whether Linux's 8 MiB write had finished 100 ms after the room it
        // was given depends on how fast the host moved it.
        | SimulatedUnixFlavour.Linux, "T21" -> true
        | _ -> false

    let private cases : (string * SimulatedUnixPlatform) list =
        [
            "tcpCloseDrain.darwin.txt", SimulatedUnixPlatform.macOsArm64
            "tcpCloseDrain.linux.txt", SimulatedUnixPlatform.linuxArm64
        ]

    [<Test>]
    let ``every row of tcp-close-drain replays on the library`` () : unit =
        let failures =
            [
                for resource, platform in cases do
                    let rows = rowsOf resource
                    // The probe's rows, all of them parsed.
                    rows |> List.length |> shouldEqual 27

                    for row in rows do
                        if not (unreplayed (SimulatedUnixPlatform.flavour platform) row.Name) then
                            try
                                replay platform row
                            with e ->
                                let message = e.Message.ReplaceLineEndings " "
                                yield $"%O{SimulatedUnixPlatform.flavour platform} %s{row.Name}: %s{message}"
            ]

        for failure in failures do
            printfn "%s" failure

        failures |> shouldEqual []
