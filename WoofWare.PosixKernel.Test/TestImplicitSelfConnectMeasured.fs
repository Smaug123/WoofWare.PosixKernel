namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// A TCP `connect(2)` whose source is its own destination, with nothing
/// listening there, replayed from both flavours' outputs of
/// `docs/probes/implicit-self-connect`: the source given by connect's own
/// implicit bind taking the destination's port (rows L, D and N), or by
/// `bind(2)` (rows E).
///
/// Each row runs on a machine whose ephemeral range is the one port the probe
/// saw the kernel choose, so the model's implicit bind takes the same port.
/// Darwin's rows replay call by call. Linux connects the socket to itself, a
/// simultaneous open this library does not model, so there each row is
/// checked to be the self-connect the kernel made, and the model to refuse it.
/// Darwin's rows H and Hr, where another socket holds the port at another
/// address, replay connect by connect: the search passes the port over.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestImplicitSelfConnectMeasured =

    let private lines (flavour : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.implicit-self-connect.%s{flavour}.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    /// The groups `pattern` captures from `line`, if it matches.
    let private (|Row|_|) (pattern : string) (line : string) : string list option =
        let m = Regex.Match (line, pattern)

        if m.Success then
            Some [ for i in 1 .. m.Groups.Count - 1 -> m.Groups.[i].Value ]
        else
            None

    /// The probe's name for an answer: an errno's, or `OK`.
    let private answerName (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed _ -> "OK"
        | SyscallAnswer.Failed error -> $"%A{error}"

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    /// `a.b.c.d:port`, as the probe prints an endpoint.
    let private endpoint (text : string) : Ipv4Endpoint =
        match text.Split ':' with
        | [| address ; port |] ->
            let octets = address.Split '.' |> Array.map UInt32.Parse

            if octets.Length <> 4 then
                failwith $"unparsed address %s{text}"

            let raw = octets |> Array.fold (fun acc octet -> (acc <<< 8) ||| octet) 0u
            Ipv4Endpoint.ofParts (Ipv4Address raw) (UInt16.Parse port)
        | _ -> failwith $"unparsed endpoint %s{text}"

    /// A system whose ephemeral range is the one port `port`, with a listener
    /// at 127.0.0.1:`listenerPort` if there is one.
    let private systemOn
        (platform : SimulatedUnixPlatform)
        (port : uint16)
        (listenerPort : uint16 option)
        : UnixSystem<int, string>
        =
        let system =
            UnixSystem.initial platform
            |> UnixBootImage.tryWithEphemeralPortRange (port, port)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        match listenerPort with
        | None -> system
        | Some listenerPort ->
            let fd, system =
                NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

            let system =
                match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (loopback listenerPort)) system with
                | Ok (BindAnswer.Bound _, system) -> system
                | other -> failwith $"binding the listener: %A{other}"

            match UnixSocket.tryListen fd 64 system with
            | Ok (ListenAnswer.Listening _, system) -> system
            | other -> failwith $"listening: %A{other}"

    /// A new TCP socket, non-blocking if `nonBlocking`.
    let private newSocket (nonBlocking : bool) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        if nonBlocking then
            fd,
            UnixSystemState.withFileDescriptors
                (FileDescriptorRegistry.setNonBlocking fd true (UnixSystemState.fileDescriptors system))
                system
        else
            fd, system

    let private bindOrFail (fd : int) (at : Ipv4Endpoint) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform at) system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"bind %s{Ipv4Endpoint.toString at}: %A{other}"

    let private connect
        (fd : int)
        (destination : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : Result<SyscallAnswer * UnixSystem<int, string>, ConnectRefusal>
        =
        CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform destination) system

    /// What `getsockname(2)` (`peer` false) or `getpeername(2)` reports, as the
    /// probe prints it: `address:port`, or the errno's name.
    let private nameOf (peer : bool) (fd : int) (system : UnixSystem<int, string>) : string =
        let call =
            if peer then
                UnixSocket.tryGetpeername
            else
                UnixSocket.tryGetsockname

        match call fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr system.Machine.UnixPlatform bytes).Endpoint with
            | Some endpoint -> Ipv4Endpoint.toString endpoint
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | Ok (GetSockNameAnswer.Failed (error, _)) -> $"%A{error}"
        | Error refusal -> failwith $"fd %d{fd}: refused %A{refusal}"

    let private names : string =
        @"^([A-Z][0-9]) getsockname=(\S+) getpeername=(\S+) SO_ERROR=(\S+)$"

    let private explicitConnect : string =
        @"^(E[12]) bind ([0-9.]+:[0-9]+) -> OK; connect 127\.0\.0\.1:([0-9]+) -> ([A-Z]+)$"

    /// Lines that record nothing a replay checks: the header, the probe's own
    /// notes, and poll(2)'s answers, which say only when the probe read on.
    let private ignored : string =
        @"^(Darwin |Linux |  attempt |  range read back|[A-Z][0-9] poll -> )"

    /// One row's socket, as far as the replay has taken it.
    type private Replay =
        {
            Fd : int
            System : UnixSystem<int, string>
        }

    [<Test>]
    let ``Darwin answers each row as measured`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64
        let mutable listenerPort : uint16 option = None
        let mutable rows : Map<string, Replay> = Map.empty
        let mutable replayed : Set<string> = Set.empty
        let mutable passedOver : Map<string, int list> = Map.empty

        let check (row : string) (what : string) (measured : string) (modelled : string) : unit =
            replayed <- Set.add row replayed

            if modelled <> measured then
                failwith $"%s{row} %s{what}: measured %s{measured}, the model answered %s{modelled}"

        /// Checks a connect's answer and moves the row on to the state it left.
        let connected
            (row : string)
            (what : string)
            (measured : string)
            (fd : int)
            (result : Result<SyscallAnswer * UnixSystem<int, string>, ConnectRefusal>)
            : unit
            =
            match result with
            | Ok (answer, system) ->
                check row what measured (answerName answer)

                rows <-
                    Map.add
                        row
                        {
                            Fd = fd
                            System = system
                        }
                        rows
            | Error refusal -> failwith $"%s{row} %s{what}: measured %s{measured}, the model refused %A{refusal}"

        for line in lines "darwin" do
            match line with
            | Row @"^listener at 127\.0\.0\.1:([0-9]+) -> OK$" [ port ] -> listenerPort <- Some (UInt16.Parse port)
            | Row @"^([DN][1-4]) connect 127\.0\.0\.1:([0-9]+) -> ([A-Z]+)$" [ row ; target ; measured ] ->
                let target = UInt16.Parse target

                let fd, system =
                    systemOn platform target listenerPort |> newSocket (row.StartsWith 'N')

                connected row "connect" measured fd (connect fd (loopback target) system)
            | Row explicitConnect [ row ; bound ; target ; measured ] ->
                let fd, system = systemOn platform 40000us None |> newSocket false
                let system = bindOrFail fd (endpoint bound) system
                connected row "connect" measured fd (connect fd (loopback (UInt16.Parse target)) system)
            | Row names [ row ; local ; peer ; soError ] ->
                let replay = rows.[row]
                check row "getsockname" local (nameOf false replay.Fd replay.System)
                check row "getpeername" peer (nameOf true replay.Fd replay.System)
                soError |> shouldEqual "OK"
                UnixSystem.checkInvariants replay.System |> shouldEqual []
            | Row @"^([DN]1) fresh bind ([0-9.]+:[0-9]+) -> ([A-Z]+)$" [ row ; at ; measured ] ->
                // From a socket of its own, which the probe closes again: the
                // row goes on without it.
                let fd, system = newSocket false rows.[row].System

                match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (endpoint at)) system with
                | Ok (BindAnswer.Bound _, _) -> check row $"fresh bind %s{at}" measured "OK"
                | Ok (BindAnswer.Failed error, _) -> check row $"fresh bind %s{at}" measured $"%A{error}"
                | Error refusal -> failwith $"%s{row} fresh bind %s{at}: refused %A{refusal}"
            | Row @"^([DN]2) second connect 127\.0\.0\.1:([0-9]+) -> ([A-Z]+)$" [ row ; target ; measured ] ->
                let replay = rows.[row]

                connected
                    row
                    "second connect"
                    measured
                    replay.Fd
                    (connect replay.Fd (loopback (UInt16.Parse target)) replay.System)
            | Row @"^([DN]3) connect to the listener at 127\.0\.0\.1:([0-9]+) -> ([A-Z]+)$" [ row ; port ; measured ] ->
                let replay = rows.[row]

                connected
                    row
                    "connect to the listener"
                    measured
                    replay.Fd
                    (connect replay.Fd (loopback (UInt16.Parse port)) replay.System)
            | Row @"^([DN]4) listen -> ([A-Z]+)$" [ row ; measured ] ->
                let replay = rows.[row]

                match UnixSocket.tryListen replay.Fd 8 replay.System with
                | Ok (ListenAnswer.Listening _, system) ->
                    check row "listen" measured "OK"

                    rows <-
                        Map.add
                            row
                            { replay with
                                System = system
                            }
                            rows
                | Ok (ListenAnswer.Failed error, _) -> check row "listen" measured $"%A{error}"
                | Error refusal -> failwith $"%s{row} listen: refused %A{refusal}"
            | Row @"^(Hr?) holder bind <other address>:T -> OK$" [ _ ] -> ()
            | Row @"^(Hr?) connect 127\.0\.0\.1:T -> ECONNREFUSED from port T([+-][0-9]+)$" [ row ; offset ] ->
                let sofar = passedOver |> Map.tryFind row |> Option.defaultValue []
                passedOver <- Map.add row (Int32.Parse offset :: sofar) passedOver
            | Row ignored _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        replayed
        |> shouldEqual (Set.ofList [ "D1" ; "D2" ; "D3" ; "D4" ; "N1" ; "N2" ; "N3" ; "N4" ; "E1" ; "E2" ])

        // Rows H and Hr: with another socket holding T at another local
        // address, with SO_REUSEADDR on every socket or on none, the sequence
        // went past T without taking it.
        passedOver |> Map.keys |> Set.ofSeq |> shouldEqual (Set.ofList [ "H" ; "Hr" ])

        for KeyValue (row, offsets) in passedOver do
            let taken = List.rev offsets

            if
                List.contains 0 taken
                || not (List.exists (fun offset -> offset < 0) taken)
                || not (List.exists (fun offset -> offset > 0) taken)
            then
                failwith $"row %s{row}: the ports taken, relative to T, were %A{taken}, which do not pass over T"

            // The model's search passes over it as Darwin's did: six fresh
            // sockets connecting in turn, each closed once refused, from a
            // cursor one below T, take the ports the probe's took.
            let reuse = row = "Hr"
            let elsewhere = Ipv4Address 0x0A000005u
            let target = 40001us

            let system =
                UnixSystem.initial platform
                |> UnixBootImage.withLocalIpv4Addresses [ Ipv4Address.loopback ; elsewhere ] []
                |> UnixBootImage.tryWithEphemeralPortRange (target - 1us, target + 5us)
                |> Configured.expectOk EphemeralPortRangeRefusal.describe
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let holder, system = newSocket false system

            let system =
                if reuse then
                    ReuseAddress.set true holder system
                else
                    system

            let system = bindOrFail holder (Ipv4Endpoint.ofParts elsewhere target) system

            let modelTaken, _ =
                (([], system), taken)
                ||> List.fold (fun (modelTaken, system) _ ->
                    let fd, system = newSocket false system
                    let system = if reuse then ReuseAddress.set true fd system else system

                    match connect fd (loopback target) system with
                    | Ok (SyscallAnswer.Failed UnixError.ECONNREFUSED, system) ->
                        let port = (endpoint (nameOf false fd system)).Port

                        match UnixDescriptor.tryClose (Callers.leader system) fd system with
                        | Ok (SyscallAnswer.Completed 0L, system) -> modelTaken @ [ int port - int target ], system
                        | other -> failwith $"row %s{row}: closing the refused socket answered %A{other}"
                    | other -> failwith $"row %s{row}: the model answered %A{other}"
                )

            if modelTaken <> taken then
                failwith $"row %s{row}: the model's connects took %A{modelTaken} relative to T, measured %A{taken}"

    [<Test>]
    let ``Linux connected each self-tuple to itself, which the model refuses`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let all = lines "linux"

        /// The getsockname and getpeername the probe printed for `row`.
        let namesOf (row : string) : string * string =
            all
            |> List.pick (fun line ->
                match line with
                | Row names [ named ; local ; peer ; _ ] when named = row -> Some (local, peer)
                | _ -> None
            )

        /// Checks that the kernel connected `row`'s socket to itself, and that
        /// the model refused to.
        let selfConnect
            (row : string)
            (port : uint16)
            (result : Result<SyscallAnswer * UnixSystem<int, string>, ConnectRefusal>)
            : unit
            =
            let own = Ipv4Endpoint.toString (loopback port)

            if namesOf row <> (own, own) then
                failwith $"%s{row}: the kernel did not connect the socket to itself: %A{namesOf row}"

            match result with
            | Error (ConnectRefusal.SimultaneousOpen destination) ->
                destination |> shouldEqual (SocketAddress.Inet (loopback port))
            | other -> failwith $"%s{row}: the kernel connected the socket to itself, and the model answered %A{other}"

        let mutable replayed : Set<string> = Set.empty

        for line in all do
            match line with
            | Row @"^(L[0-2]) (blocking|non-blocking) range \[([0-9]+), ([0-9]+)\] connect 127\.0\.0\.1:([0-9]+) -> ([A-Z]+)$" [ row
                                                                                                                                 mode
                                                                                                                                 low
                                                                                                                                 high
                                                                                                                                 target
                                                                                                                                 measured ] ->
                low |> shouldEqual high
                let port = UInt16.Parse low
                let target = UInt16.Parse target
                let fd, system = systemOn platform port None |> newSocket (mode = "non-blocking")
                let result = connect fd (loopback target) system
                replayed <- Set.add row replayed

                if port = target then
                    selfConnect row target result
                else
                    // The control: a port of its own, refused by the reset.
                    match result with
                    | Ok (answer, system) ->
                        answerName answer |> shouldEqual measured
                        (nameOf false fd system, nameOf true fd system) |> shouldEqual (namesOf row)
                    | Error refusal -> failwith $"%s{row}: the model refused %A{refusal}"
            | Row explicitConnect [ row ; bound ; target ; _ ] ->
                let fd, system = systemOn platform 40000us None |> newSocket false
                let system = bindOrFail fd (endpoint bound) system
                let target = UInt16.Parse target
                replayed <- Set.add row replayed
                selfConnect row target (connect fd (loopback target) system)
            | _ -> ()

        replayed |> shouldEqual (Set.ofList [ "L0" ; "L1" ; "L2" ; "E1" ; "E2" ])
