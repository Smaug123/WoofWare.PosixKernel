namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What a TCP connection's TIME_WAIT holds once both of its sockets have
/// closed, replayed from both flavours' outputs of `docs/probes/time-wait`:
/// `time-wait.c` (binds over a client's and a server's TIME_WAIT, the passive
/// end's port, a connect's and a bind's search, and how long it lasts),
/// `tw-reuse.c` (when a connect takes a TIME_WAIT's four-tuple over),
/// `tw-boot.c` (Linux's first second of uptime) and `tw-stranded.c` (a FIN
/// still queued behind bytes the peer never read).
///
/// Each row replays on a machine of its own, whose clock stands where the
/// probe's did: two seconds after boot, as the probe waited, unless the row
/// says otherwise. Linux's rows narrowed each search to the one port the row
/// is about, so they replay on a machine whose ephemeral range is that port;
/// Darwin's followed its sequence of implicit ports, so they replay with the
/// allocator's cursor put on the port.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestTimeWaitMeasured =

    let private lines (resource : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.time-wait.%s{resource}.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    /// The groups `pattern` captures from `text`, if it matches.
    let private (|Matching|_|) (pattern : string) (text : string) : string list option =
        let m = Regex.Match (text, pattern)

        if m.Success then
            Some [ for i in 1 .. m.Groups.Count - 1 -> m.Groups.[i].Value ]
        else
            None

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private address (text : string) : Ipv4Address =
        match text with
        | "127.0.0.1" -> Ipv4Address.loopback
        | "0.0.0.0" -> Ipv4Address.any
        | other -> failwith $"unexpected address %s{other}"

    let private seconds (text : string) : int64 =
        int64 (Math.Round (Double.Parse text * 1000.0)) * 1_000_000L

    /// The port each row's own connection is made from, and the listeners'.
    let private port : uint16 = 44001us
    let private listenerX : uint16 = 45501us
    let private listenerY : uint16 = 45502us

    /// The probe's name for an outcome.
    let private errorName (error : UnixError option) : string =
        match error with
        | None -> "OK"
        | Some error -> $"%A{error}"

    type private Row =
        {
            System : UnixSystem<int, string>
            Flavour : SimulatedUnixFlavour
            /// The fixed listeners' descriptors.
            X : int
            Y : int
        }

    let private advance (nanoseconds : int64) (row : Row) : Row =
        { row with
            System = UnixSystem.advanceClock nanoseconds row.System
        }

    let private newSocket (reuse : bool) (row : Row) : int * Row =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp row.System

        fd,
        { row with
            System = if reuse then ReuseAddress.set true fd system else system
        }

    let private bind (fd : int) (endpoint : Ipv4Endpoint) (row : Row) : Result<BindAnswer * Row, BindRefusal> =
        CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform row.System) endpoint) row.System
        |> Result.map (fun (answer, system) ->
            answer,
            { row with
                System = system
            }
        )

    let private bindOrFail (fd : int) (endpoint : Ipv4Endpoint) (row : Row) : Row =
        match bind fd endpoint row with
        | Ok (BindAnswer.Bound _, row) -> row
        | other -> failwith $"binding %s{Ipv4Endpoint.toString endpoint}: %A{other |> Result.map fst}"

    let private listen (fd : int) (row : Row) : Result<ListenAnswer * Row, ListenRefusal> =
        UnixSocket.tryListen (Callers.leader row.System) fd 8 row.System
        |> Result.map (fun (answer, system) ->
            answer,
            { row with
                System = system
            }
        )

    let private connect (fd : int) (destination : uint16) (row : Row) : Result<SyscallAnswer * Row, ConnectRefusal> =
        CopyIn.connect
            fd
            UserBuffer.Mapped
            16u
            (CopyIn.inet (UnixSystem.platform row.System) (loopback destination))
            row.System
        |> Result.map (fun (answer, system) ->
            answer,
            { row with
                System = system
            }
        )

    let private accept (listener : int) (row : Row) : int * Row =
        match UnixConnection.tryAccept (Callers.thread 0 row.System) listener UserBuffer.Mapped 16u row.System with
        | Ok (AcceptOutcome.Accepted (accepted, _, _), system) ->
            accepted,
            { row with
                System = system
            }
        | other -> failwith $"accept: %A{other}"

    let private close (fd : int) (row : Row) : Row =
        match UnixDescriptor.tryClose (Callers.leader row.System) fd row.System with
        | Ok (SyscallAnswer.Completed 0L, system) ->
            { row with
                System = system
            }
        | other -> failwith $"close fd %d{fd}: %A{other}"

    let private boundAt (fd : int) (row : Row) : Ipv4Endpoint option =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors row.System) with
        | Some (OpenFileTarget.Socket socketId) ->
            (UnixMachineState.socket socketId (Kernel.machine row.System)).Ipv4Binding
            |> Option.map (fun binding -> binding.Endpoint)
        | other -> failwith $"fd %d{fd} is %A{other}"

    let private connected (fd : int) (row : Row) : bool =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors row.System) with
        | Some (OpenFileTarget.Socket socketId) ->
            (SocketPhase.connectionEnd (UnixMachineState.socket socketId (Kernel.machine row.System)).Phase).IsSome
        | other -> failwith $"fd %d{fd} is %A{other}"

    /// A machine of `platform` whose ephemeral range is `range`, its clock at
    /// `uptime`, with listeners carrying `SO_REUSEADDR` at X and Y.
    let private rowOn (platform : SimulatedUnixPlatform) (range : uint16 * uint16) (uptime : int64) : Row =
        let system =
            UnixSystem.initial platform
            |> UnixBootImage.tryWithEphemeralPortRange range
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let row =
            {
                System = system
                Flavour = SimulatedUnixPlatform.flavour platform
                X = -1
                Y = -1
            }
            |> advance uptime

        let listenAt (at : uint16) (row : Row) : int * Row =
            let fd, row = newSocket true row
            let row = bindOrFail fd (loopback at) row

            match listen fd row with
            | Ok (ListenAnswer.Listening _, row) -> fd, row
            | other -> failwith $"listening at %d{at}: %A{other |> Result.map fst}"

        let x, row = listenAt listenerX row
        let y, row = listenAt listenerY row

        { row with
            X = x
            Y = y
        }

    /// The machine every row starts from: Linux's range is the row's port;
    /// Darwin's runs either side of it, its cursor on it.
    let private rowFor (platform : SimulatedUnixPlatform) : Row =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> rowOn platform (port, port) 2_000_000_000L
        | SimulatedUnixFlavour.Darwin ->
            let row = rowOn platform (port - 1us, port + 3us) 2_000_000_000L

            { row with
                System =
                    Kernel.mapMachine
                        (fun machine ->
                            { machine with
                                NextEphemeralPort = port
                            }
                        )
                        row.System
            }

    /// The allocator's cursor put back on `at`, as the probe aimed its next
    /// search at it.
    let private aim (at : uint16) (row : Row) : Row =
        { row with
            System =
                Kernel.mapMachine
                    (fun machine ->
                        { machine with
                            NextEphemeralPort = at
                        }
                    )
                    row.System
        }

    /// A connection from a client carrying `SO_REUSEADDR` if `reuse`, its port
    /// `port` chosen by connect's own bind or, if `byBind`, by `bind(2)`, to
    /// the listener `listener`, ended by the client's close and then the
    /// accepted socket's: the client's end is in TIME_WAIT.
    let private clientFirstAt (at : uint16) (reuse : bool) (byBind : bool) (listener : int * uint16) (row : Row) : Row =
        let client, row = newSocket reuse row
        let row = if byBind then bindOrFail client (loopback at) row else row

        let row =
            match connect client (snd listener) row with
            | Ok (SyscallAnswer.Completed 0L, row) when boundAt client row = Some (loopback at) -> row
            | other -> failwith $"the client's connect: %A{other |> Result.map fst}"

        let server, row = accept (fst listener) row
        row |> close client |> close server

    /// `clientFirstAt` the row's port.
    let private clientFirst (reuse : bool) (byBind : bool) (listener : int * uint16) (row : Row) : Row =
        clientFirstAt port reuse byBind listener row

    /// The same connection, from a client without `SO_REUSEADDR` whose port
    /// connect's own bind chose, ended the other way: the accepted socket
    /// closes first, so the server's end is in TIME_WAIT towards the client's
    /// port.
    let private serverFirst (listener : int * uint16) (row : Row) : Row =
        let client, row = newSocket false row

        let row =
            match connect client (snd listener) row with
            | Ok (SyscallAnswer.Completed 0L, row) when boundAt client row = Some (loopback port) -> row
            | other -> failwith $"the client's connect: %A{other |> Result.map fst}"

        let server, row = accept (fst listener) row
        row |> close server |> close client

    /// A listener of the row's own, carrying `SO_REUSEADDR`, at `at`.
    let private ownListener (at : uint16) (row : Row) : int * Row =
        let fd, row = newSocket true row
        let row = bindOrFail fd (loopback at) row

        match listen fd row with
        | Ok (ListenAnswer.Listening _, row) -> fd, row
        | other -> failwith $"the row's listener at %d{at}: %A{other |> Result.map fst}"

    /// What `getsockname(2)` reports of the socket behind `fd`.
    let private nameOf (fd : int) (row : Row) : Ipv4Endpoint =
        match UnixSocket.tryGetsockname (Callers.leader row.System) fd UserBuffer.Mapped 16u row.System with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr (UnixSystem.platform row.System) bytes).Endpoint with
            | Some endpoint -> endpoint
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    /// What the probe printed of a bind by a fresh socket carrying
    /// `SO_REUSEADDR` if `reuse`, and, if `thenListen`, of the listen after
    /// one that succeeded.
    let private bindLine (thenListen : bool) (reuse : bool) (endpoint : Ipv4Endpoint) (row : Row) : string =
        let fd, row = newSocket reuse row

        match bind fd endpoint row with
        | Ok (BindAnswer.Bound _, row) when thenListen ->
            match listen fd row with
            | Ok (ListenAnswer.Listening _, _) -> "OK; listen -> OK"
            | other -> $"OK; listen -> %A{other |> Result.map fst}"
        | Ok (BindAnswer.Bound _, _) -> "OK"
        | Ok (BindAnswer.Failed error, _) -> errorName (Some error)
        | Error refusal -> $"refused %A{refusal}"

    let private errnoOf (answer : SyscallAnswer) : UnixError option =
        match answer with
        | SyscallAnswer.Completed _ -> None
        | SyscallAnswer.Failed error -> Some error

    /// What the probe printed of a search, by a fresh socket carrying
    /// `SO_REUSEADDR` if `reuse`: a connect to `destination`, or a
    /// `bind(127.0.0.1:0)`, or a `listen(2)` with no port.
    let private searchLine (what : string) (reuse : bool) (destination : uint16) (row : Row) : string =
        let fd, row = newSocket reuse row

        let outcome =
            match what with
            | "connect" ->
                connect fd destination row
                |> Result.map (fun (answer, row) -> errnoOf answer, row)
                |> Result.mapError (fun refusal -> $"%A{refusal}")
            | "bind 127.0.0.1:0" ->
                bind fd (loopback 0us) row
                |> Result.map (fun (answer, row) ->
                    (match answer with
                     | BindAnswer.Failed error -> Some error
                     | _ -> None),
                    row
                )
                |> Result.mapError (fun refusal -> $"%A{refusal}")
            | "listen" ->
                listen fd row
                |> Result.map (fun (answer, row) ->
                    (match answer with
                     | ListenAnswer.Failed error -> Some error
                     | _ -> None),
                    row
                )
                |> Result.mapError (fun refusal -> $"%A{refusal}")
            | other -> failwith $"unknown search %s{other}"

        match outcome with
        | Error refusal -> $"refused %s{refusal}"
        | Ok (error, row) ->
            let from =
                match boundAt fd row with
                | Some bound when bound.Port <> 0us -> $"T%+d{int bound.Port - int port}"
                | _ -> "none"

            $"%s{errorName error} from port %s{from}"

    let private timeWaitRow : string =
        @"^([BS])([01]) bind ([0-9.]+):T reuse=([01]) -> (.*)$"

    let private replayTimeWait (platform : SimulatedUnixPlatform) (resource : string) : int =
        let flavour = SimulatedUnixPlatform.flavour platform
        let mutable replayed = 0

        let check (line : string) (expected : string) (actual : string) : unit =
            if expected <> actual then
                failwith $"%A{flavour}: the model printed %s{actual} where the probe printed %s{expected}\n  %s{line}"

            replayed <- replayed + 1

        for line in lines resource do
            match line with
            | Matching timeWaitRow [ who ; flag ; at ; reuse ; measured ] ->
                let row = rowFor platform
                let flag = flag = "1"

                let row, endpointPort =
                    match who with
                    | "B" -> clientFirst flag false (row.X, listenerX) row, port
                    | _ ->
                        // The server's end in TIME_WAIT, at a listener of the
                        // row's own, which then closes.
                        let q = 44101us
                        let listenerFd, row = newSocket flag row
                        let row = bindOrFail listenerFd (loopback q) row

                        let row =
                            match listen listenerFd row with
                            | Ok (ListenAnswer.Listening _, row) -> row
                            | other -> failwith $"the row's listener: %A{other |> Result.map fst}"

                        let client, row = newSocket false row

                        let row =
                            match connect client q row with
                            | Ok (SyscallAnswer.Completed 0L, row) -> row
                            | other -> failwith $"the client's connect: %A{other |> Result.map fst}"

                        let server, row = accept listenerFd row
                        row |> close server |> close client |> close listenerFd, q

                check line measured (bindLine true (reuse = "1") (Ipv4Endpoint.ofParts (address at) endpointPort) row)
            | Matching @"^P bind 127\.0\.0\.1:T -> (.*)$" [ measured ] ->
                // The client's port, its FIN made after the server's arrived.
                let row = rowFor platform
                let client, row = newSocket false row

                let row =
                    match connect client listenerX row with
                    | Ok (SyscallAnswer.Completed 0L, row) -> row
                    | other -> failwith $"the client's connect: %A{other |> Result.map fst}"

                let server, row = accept row.X row
                let row = row |> close server |> close client
                check line measured (bindLine false false (loopback port) row)
            | Matching @"^P connect reuse=0 -> (.*)$" [ measured ] ->
                let row = rowFor platform
                let client, row = newSocket false row

                let row =
                    match connect client listenerX row with
                    | Ok (SyscallAnswer.Completed 0L, row) -> row
                    | other -> failwith $"the client's connect: %A{other |> Result.map fst}"

                let server, row = accept row.X row
                let row = row |> close server |> close client |> aim port
                check line measured (searchLine "connect" false listenerY row)
            | Matching @"^C([cb])([01])([xy])(\+2s)? connect reuse=[01] -> (.*)$" [ how
                                                                                    flag
                                                                                    towards
                                                                                    later
                                                                                    measured ] ->
                let flag = flag = "1"
                let row = rowFor platform
                let row = row |> clientFirst flag (how = "b") (row.X, listenerX) |> aim port
                let row = if later = "" then row else advance 2_000_000_000L row

                let destination = if towards = "x" then listenerX else listenerY

                check line measured (searchLine "connect" flag destination row)
            | Matching @"^L([bl]) (bind 127\.0\.0\.1:0|listen) reuse=([01]) -> (.*)$" [ _ ; what ; flag ; measured ] ->
                let flag = flag = "1"
                let row = rowFor platform
                let row = clientFirst flag false (row.X, listenerX) row |> aim port
                check line measured (searchLine what flag 0us row)
            | Matching @"^W bind 127\.0\.0\.1:T after ([0-9.]+) s -> OK; the last EADDRINUSE was after ([0-9.]+) s$" [ free
                                                                                                                       lastHeld ] ->
                // The model answers within the window the TIME_WAIT was
                // measured to last at least, and refuses from there on.
                let row = rowFor platform
                let row = clientFirst false false (row.X, listenerX) row
                let window = PortHolderRules.timeWaitWindow (Kernel.machine row.System).TcpTimeWait

                if window > seconds lastHeld then
                    failwith
                        $"%A{flavour}: the model's window of %d{window} ns is longer than the %s{lastHeld} s measured"

                // The probe bound once a second, so the window gives up no
                // more than that second of what was measured.
                if window <= seconds lastHeld - 1_000_000_000L then
                    failwith
                        $"%A{flavour}: the model's window of %d{window} ns falls more than a second short of the %s{lastHeld} s measured"

                for at in [ 0L ; window / 2L ; window - 1L ] do
                    bindLine false false (loopback port) (advance at row)
                    |> shouldEqual "EADDRINUSE"

                for at in [ window ; seconds free ] do
                    match bindLine false false (loopback port) (advance at row) with
                    | answer when answer.StartsWith "refused TimeWait" -> ()
                    | answer -> failwith $"%A{flavour}: %d{at} ns on, the model answered %s{answer}"

                replayed <- replayed + 1
            | Matching @"^(Linux|Darwin|net\.|/proc|uptime)" _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        replayed

    [<Test>]
    let ``Linux answers every time-wait.c row as measured`` () : unit =
        replayTimeWait SimulatedUnixPlatform.linuxX64 "linux" |> shouldEqual 39

    [<Test>]
    let ``Darwin answers every time-wait.c row as measured`` () : unit =
        replayTimeWait SimulatedUnixPlatform.macOsArm64 "darwin" |> shouldEqual 31

    let private replayReuse (platform : SimulatedUnixPlatform) (resource : string) : int =
        let flavour = SimulatedUnixPlatform.flavour platform
        let mutable replayed = 0

        let check (line : string) (expected : string) (actual : string) : unit =
            if expected <> actual then
                failwith $"%A{flavour}: the model printed %s{actual} where the probe printed %s{expected}\n  %s{line}"

            replayed <- replayed + 1

        /// What the probe printed of a connect to `destination` by the socket
        /// behind `fd`: the outcome, and whether `getsockname(2)` reported
        /// the row's port after.
        let connectLine (fd : int) (destination : uint16) (row : Row) : string * Row =
            match connect fd destination row with
            | Ok (answer, row) ->
                let from = if (nameOf fd row).Port = port then "T" else "other"
                $"%s{errorName (errnoOf answer)} from %s{from}", row
            | Error refusal -> $"refused %A{refusal}", row

        /// A bind of the socket behind `fd` to `endpoint`, as the probe
        /// printed it, with the row after.
        let bindStep (fd : int) (endpoint : Ipv4Endpoint) (row : Row) : Result<Row, string> =
            match bind fd endpoint row with
            | Ok (BindAnswer.Bound _, row) -> Ok row
            | Ok (BindAnswer.Failed error, _) -> Error (errorName (Some error))
            | Error refusal -> Error $"refused %A{refusal}"

        for line in lines resource do
            match line with
            | Matching @"^R([01])([01])@([0-9.]+) connect to X after [0-9.]+ s -> ([A-Z]+) from (T|none)$" [ tw
                                                                                                             sr
                                                                                                             delay
                                                                                                             measured
                                                                                                             from ] ->
                let row = rowFor platform

                let row =
                    row
                    |> clientFirst (tw = "1") false (row.X, listenerX)
                    |> advance (seconds delay)

                let fd, row = newSocket (sr = "1") row

                let answered =
                    match connect fd listenerX row with
                    | Ok (answer, row) ->
                        let from =
                            match boundAt fd row with
                            | Some bound when bound.Port = port -> "T"
                            | _ -> "none"

                        $"%s{errorName (errnoOf answer)} from %s{from}"
                    | Error refusal -> $"refused %A{refusal}"

                check line $"%s{measured} from %s{from}" answered
            | Matching @"^E([01])([01])@([0-9.]+) bind 127\.0\.0\.1:T -> (.*)$" [ tw ; sr ; delay ; measured ] ->
                let row = rowFor platform

                let row =
                    row
                    |> clientFirst (tw = "1") false (row.X, listenerX)
                    |> advance (seconds delay)

                let fd, row = newSocket (sr = "1") row

                let answered =
                    match bindStep fd (loopback port) row with
                    | Error answered -> answered
                    | Ok row ->
                        match connect fd listenerX row with
                        | Ok (answer, row) ->
                            let name = if (nameOf fd row).Port = port then "T" else "other"
                            let peer = if connected fd row then "X" else "ENOTCONN"

                            $"OK; connect to X -> %s{errorName (errnoOf answer)}; then getsockname port %s{name}, getpeername %s{peer}"
                        | Error refusal -> $"OK; connect refused %A{refusal}"

                check line measured answered
            | Matching @"^V([01])1@1\.5 bind 0\.0\.0\.0:T -> (.*)$" [ tw ; measured ] ->
                let row = rowFor platform

                let row =
                    row |> clientFirst (tw = "1") false (row.X, listenerX) |> advance 1_500_000_000L

                let fd, row = newSocket true row

                let answered =
                    match bindStep fd (Ipv4Endpoint.ofParts Ipv4Address.any port) row with
                    | Error answered -> answered
                    | Ok row ->
                        match connect fd listenerX row with
                        | Ok (answer, row) ->
                            let name = nameOf fd row

                            let name =
                                if name.Port = port then
                                    $"%s{Ipv4Address.toString name.Address}:T"
                                else
                                    Ipv4Endpoint.toString name

                            $"OK; connect to X -> %s{errorName (errnoOf answer)}; then getsockname %s{name}"
                        | Error refusal -> $"OK; connect refused %A{refusal}"

                check line measured answered
            | Matching @"^Z([01])([se]) (.*)$" [ tw ; how ; measured ] ->
                let z = 45650us + (if tw = "1" then 2us else 0us) + (if how = "e" then 1us else 0us)

                let row = rowFor platform
                let listener, row = ownListener z row

                let row =
                    row
                    |> clientFirst (tw = "1") false (listener, z)
                    |> close listener
                    |> advance 1_500_000_000L

                let fd, row = newSocket true row

                let first, row =
                    match how with
                    | "s" ->
                        let answered, row = connectLine fd z (aim port row)
                        $"search aimed at T; connect to Z -> %s{answered}", row
                    | _ ->
                        match bindStep fd (loopback port) row with
                        | Ok row ->
                            let answered, row = connectLine fd z row
                            $"bind 127.0.0.1:T reuse=1 -> OK; connect to Z -> %s{answered}", row
                        | Error answered -> $"bind 127.0.0.1:T reuse=1 -> %s{answered}", row

                let row = close fd row

                check
                    line
                    measured
                    $"%s{first}; then bind 127.0.0.1:T reuse=0 -> %s{bindLine false false (loopback port) row}"
            | Matching @"^Q([se])@([0-9.]+) (.*)$" [ how ; delay ; measured ] ->
                let row = rowFor platform
                let row = row |> serverFirst (row.X, listenerX) |> advance (seconds delay)
                let fd, row = newSocket true row

                let first, row =
                    match how with
                    | "s" -> Ok "search aimed at T", aim port row
                    | _ ->
                        match bindStep fd (loopback port) row with
                        | Ok row -> Ok "bind 127.0.0.1:T reuse=1 -> OK", row
                        | Error answered -> Error $"bind 127.0.0.1:T reuse=1 -> %s{answered}", row

                let answered =
                    match first with
                    | Error answered -> answered
                    | Ok first ->
                        let answered, row = connectLine fd listenerX row

                        let accepted =
                            match
                                UnixConnection.tryAccept
                                    (Callers.thread 0 row.System)
                                    row.X
                                    UserBuffer.Mapped
                                    16u
                                    row.System
                            with
                            | Ok (AcceptOutcome.Accepted _, _) -> "OK"
                            | other -> $"%A{other}"

                        $"%s{first}; connect to X -> %s{answered}; accept -> %s{accepted}"

                check line measured answered
            | Matching @"^Y([se]) (.*)$" [ how ; measured ] ->
                let z = 45660us + (if how = "e" then 1us else 0us)
                let row = rowFor platform
                let listener, row = ownListener z row

                let row =
                    row |> serverFirst (listener, z) |> close listener |> advance 1_500_000_000L

                let fd, row = newSocket true row

                let first, row =
                    match how with
                    | "s" ->
                        let answered, row = connectLine fd z (aim port row)
                        $"search aimed at T; connect to Z -> %s{answered}", row
                    | _ ->
                        match bindStep fd (loopback port) row with
                        | Ok row ->
                            let answered, row = connectLine fd z row
                            $"bind 127.0.0.1:T reuse=1 -> OK; connect to Z -> %s{answered}", row
                        | Error answered -> $"bind 127.0.0.1:T reuse=1 -> %s{answered}", row

                let row = close fd row

                check
                    line
                    measured
                    $"%s{first}; then bind 127.0.0.1:Z reuse=0 -> %s{bindLine false false (loopback z) row}"
            | Matching @"^D connect to 127\.0\.0\.1:T -> ([A-Z]+)$" [ measured ] ->
                // The probe's fresh socket took a port other than T; Linux's
                // range here is T and the port after it, its cursor on the
                // port after.
                let row =
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> rowOn platform (port, port + 1us) 2_000_000_000L
                    | SimulatedUnixFlavour.Darwin -> rowFor platform

                let row = row |> clientFirst false false (row.X, listenerX) |> aim (port + 1us)
                let fd, row = newSocket false row

                let answered =
                    match connect fd port row with
                    | Ok (answer, row) when (nameOf fd row).Port <> port -> errorName (errnoOf answer)
                    | Ok (answer, row) -> $"%s{errorName (errnoOf answer)} from T itself"
                    | Error refusal -> $"refused %A{refusal}"

                check line measured answered
            | Matching @"^(Linux|Darwin|uptime)" _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        replayed

    [<Test>]
    let ``Linux answers every tw-reuse.c row as measured`` () : unit =
        replayReuse SimulatedUnixPlatform.linuxX64 "reuse-linux" |> shouldEqual 81

    [<Test>]
    let ``Darwin answers every tw-reuse.c row as measured`` () : unit =
        replayReuse SimulatedUnixPlatform.macOsArm64 "reuse-darwin" |> shouldEqual 23

    /// `tw-boot.c`: a Linux TIME_WAIT entered in the machine's first second of
    /// uptime is never taken over by a connect's search, and one entered
    /// later is, two seconds on.
    [<Test>]
    let ``Linux answers every tw-boot.c row as measured`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let mutable replayed = 0
        let mutable ended : Map<uint16, int64> = Map.empty

        for line in lines "boot-linux" do
            match line with
            | Matching @"^T=([0-9]+) ended at uptime ([0-9.]+) s " [ at ; uptime ] ->
                ended <- Map.add (UInt16.Parse at) (seconds uptime) ended
            | Matching @"^T=([0-9]+) connect to X at uptime [0-9.]+ s, ([0-9.]+) s after -> ([A-Z]+)$" [ at
                                                                                                         after
                                                                                                         measured ] ->
                let at = UInt16.Parse at
                let row = rowOn platform (at, at) ended.[at]

                let row =
                    clientFirstAt at false false (row.X, listenerX) row |> advance (seconds after)

                let fd, row = newSocket false row

                let answered =
                    match connect fd listenerX row with
                    | Ok (answer, _) -> errorName (errnoOf answer)
                    | Error refusal -> $"refused %A{refusal}"

                if answered <> measured then
                    failwith
                        $"T=%d{at}, ended at %d{ended.[at]} ns: the model answered %s{answered}, measured %s{measured}"

                replayed <- replayed + 1
            | Matching @"^started at uptime" _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        replayed |> shouldEqual 6

    let private shutWrite (fd : int) (row : Row) : Row =
        match UnixConnection.tryShutdown (Callers.leader row.System) fd 1 row.System with
        | Ok (ShutdownAnswer.Shut, system) ->
            { row with
                System = system
            }
        | other -> failwith $"shutdown of fd %d{fd}: %A{other}"

    /// The client writes until its send buffer is full, as the probe's
    /// non-blocking writes did until `EAGAIN`.
    let private fill (fd : int) (row : Row) : Row =
        let system =
            UnixDescriptor.setNonBlocking (Callers.leader row.System) fd true row.System
            |> snd

        let chunk =
            Collections.Immutable.ImmutableArray.CreateRange (Array.create 4096 'x'B)

        let rec go (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            match WriteOutcomes.writeBytes 0 fd chunk system with
            | Ok (WriteStep.Returns (WriteAnswer.Completed _, system)) -> go system
            | Ok (WriteStep.Returns (WriteAnswer.Failed UnixError.EAGAIN, system)) -> system
            | other -> failwith $"write on fd %d{fd}: %A{other}"

        { row with
            System = go system
        }

    /// What `getsockopt(SO_ERROR)` reads on `fd`, in the probe's names.
    let private socketError (fd : int) (row : Row) : string * Row =
        let answer, system = KeventWorld.readSocketError fd row.System
        let platform = UnixSystem.platform row.System

        let name =
            match OptionValue.readInt answer with
            | 0 -> "OK"
            | raw ->
                match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) raw with
                | Some error -> errorName (Some error)
                | None -> failwith $"SO_ERROR read errno %d{raw}"

        name,
        { row with
            System = system
        }

    /// `tw-stranded.c`: a connection whose client shut its send side behind
    /// bytes the server never read, and whose server then shut its own and
    /// closed. Linux resets the client at the server's close; Darwin does
    /// not, and once the client closes too, neither end holds its port: the
    /// client's FIN never arrived, so neither end is in TIME_WAIT. Darwin's
    /// row C is not replayed: its loopback delivered the client's FIN after
    /// the server had shut its own side, so both FINs crossed, which this
    /// kernel's loopback, delivering at once, does not do.
    let private replayStranded (platform : SimulatedUnixPlatform) (resource : string) : int =
        let flavour = SimulatedUnixPlatform.flavour platform
        let mutable replayed = 0
        let mutable z = 45701us

        for line in lines resource do
            match line with
            | Matching @"^([CS]) wrote (nothing|until EAGAIN); (.*)$" [ name ; _ ; measured ] ->
                let row = rowFor platform
                let listener, row = ownListener z row
                let client, row = newSocket false row

                let row =
                    match connect client z row with
                    | Ok (SyscallAnswer.Completed 0L, row) -> row
                    | other -> failwith $"the client's connect: %A{other |> Result.map fst}"

                let clientPort =
                    match boundAt client row with
                    | Some bound -> bound.Port
                    | None -> failwith "the client is unbound"

                let server, row = accept listener row
                let row = close listener row
                let row = if name = "S" then fill client row else row
                let row = row |> shutWrite client |> shutWrite server |> close server
                let error, row = socketError client row
                let row = close client row

                let binds (row : Row) : string =
                    $"T -> %s{bindLine false false (loopback clientPort) row}, Z -> %s{bindLine false false (loopback z) row}"

                let answered =
                    $"client SO_ERROR after the server's close -> %s{error}; then bind %s{binds row}; after 1 s %s{binds (advance 1_000_000_000L row)}; after 5 s %s{binds (advance 5_000_000_000L row)}"

                z <- z + 1us

                if name = "C" && flavour = SimulatedUnixFlavour.Darwin then
                    ()
                elif answered <> measured then
                    failwith $"%A{flavour}: the model printed %s{answered} where the probe printed %s{measured}"
                else
                    replayed <- replayed + 1
            | Matching @"^(Linux|Darwin) " _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        replayed

    [<Test>]
    let ``Linux answers every tw-stranded.c row as measured`` () : unit =
        replayStranded SimulatedUnixPlatform.linuxX64 "stranded-linux" |> shouldEqual 7

    [<Test>]
    let ``Darwin answers every tw-stranded.c row S as measured`` () : unit =
        replayStranded SimulatedUnixPlatform.macOsArm64 "stranded-darwin"
        |> shouldEqual 6
