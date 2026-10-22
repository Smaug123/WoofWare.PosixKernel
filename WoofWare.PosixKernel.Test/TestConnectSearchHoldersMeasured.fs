namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which ports a TCP connect's implicit bind passes over, for each kind of
/// thing that holds a port, replayed from both flavours' outputs of
/// `docs/probes/connect-search-holders`.
///
/// Linux's rows each narrowed the searching socket's range to the one port
/// the holder held, so each replays on a machine whose ephemeral range is that
/// port. Darwin's rows followed its sequence of implicit ports past the
/// holder, so each replays on a machine whose small range starts one below
/// the holder's port, with the allocator's cursor put where the probe had
/// walked Darwin's.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestConnectSearchHoldersMeasured =

    let private lines (flavour : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.connect-search-holders.%s{flavour}.txt"

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

    /// A dotted quad as the probe prints one.
    let private parseAddress (text : string) : Ipv4Address =
        match text.Split '.' |> Array.map Byte.Parse with
        | [| a ; b ; c ; d |] -> Ipv4Address ((uint32 a <<< 24) ||| (uint32 b <<< 16) ||| (uint32 c <<< 8) ||| uint32 d)
        | _ -> failwith $"not an IPv4 address: %s{text}"

    /// The listeners the probe's connects aim at: the holders' at X, the
    /// searches' at Y.
    let private listenerX : uint16 = 45401us
    let private listenerY : uint16 = 45402us

    /// Where nothing listens: Darwin's refused connects aim here.
    let private closedPort : uint16 = 1us

    /// A machine whose ephemeral range is `low..high`, with `extra` among its
    /// addresses, and listeners at 127.0.0.1:`listenerX` and `listenerY`,
    /// each carrying `SO_REUSEADDR` as the probe's did. Answers the
    /// listeners' descriptors too.
    let private systemOn
        (platform : SimulatedUnixPlatform)
        (extra : Ipv4Address list)
        (low : uint16, high : uint16)
        : UnixSystem<int, string> * int * int
        =
        let system =
            UnixSystem.initial platform
            |> UnixBootImage.withLocalIpv4Addresses
                (UnixSystem.defaultLocalIpv4Addresses @ extra)
                UnixSystem.defaultLocalRoutes
            |> UnixBootImage.tryWithEphemeralPortRange (low, high)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let listenAt (port : uint16) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
            let fd, system =
                NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

            let system = ReuseAddress.set true fd system

            let system =
                match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (loopback port)) system with
                | Ok (BindAnswer.Bound _, system) -> system
                | other -> failwith $"binding the listener at %d{port}: %A{other}"

            match UnixSocket.tryListen (Callers.leader system) fd 128 system with
            | Ok (ListenAnswer.Listening _, system) -> fd, system
            | other -> failwith $"listening at %d{port}: %A{other}"

        let x, system = listenAt listenerX system
        let y, system = listenAt listenerY system
        system, x, y

    let private newSocket (reuse : bool) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        fd, (if reuse then ReuseAddress.set true fd system else system)

    let private bindOrFail (fd : int) (endpoint : Ipv4Endpoint) (system : UnixSystem<int, string>) =
        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) endpoint) system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"binding %s{Ipv4Endpoint.toString endpoint}: %A{other}"

    let private connect
        (fd : int)
        (port : uint16)
        (system : UnixSystem<int, string>)
        : Result<SyscallAnswer * UnixSystem<int, string>, ConnectRefusal>
        =
        CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) (loopback port)) system

    let private connectOrFail (fd : int) (port : uint16) (system : UnixSystem<int, string>) =
        match connect fd port system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"connecting fd %d{fd} to %d{port}: %A{other}"

    let private acceptOrFail (listener : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixConnection.tryAccept (Callers.thread 0 system) listener UserBuffer.Mapped (Some 16u) 0 system with
        | Ok (AcceptOutcome.Accepted (accepted, _), system) -> accepted, system
        | other -> failwith $"accepting on fd %d{listener}: %A{other}"

    let private closeOrFail (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"closing fd %d{fd}: %A{other}"

    /// The endpoint the socket behind `fd` reports, as the probe prints it.
    let private nameOf (fd : int) (system : UnixSystem<int, string>) : string =
        match UnixSocket.tryGetsockname (Callers.leader system) fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr (UnixSystem.platform system) bytes).Endpoint with
            | Some endpoint -> Ipv4Endpoint.toString endpoint
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    let private portOf (fd : int) (system : UnixSystem<int, string>) : uint16 =
        match UnixSocket.tryGetsockname (Callers.leader system) fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr (UnixSystem.platform system) bytes).Endpoint with
            | Some endpoint -> endpoint.Port
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    /// Whether connect's own implicit bind gives the probe's holder `kind`
    /// its port.
    let private implicitHolder (kind : string) : bool =
        kind.StartsWith 'c' || kind = "f" || kind = "fr"

    /// Puts the probe's holder `kind` at `at`, connecting the connected ones
    /// to the listener `x`; answers what getsockname reports for it before
    /// any close. A holder whose port its own connect chooses takes the
    /// first port the machine's range offers.
    let private place
        (kind : string)
        (at : Ipv4Endpoint)
        (x : int)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        let fd, system = newSocket (kind.EndsWith 'r') system

        let connected (system : UnixSystem<int, string>) =
            let system = connectOrFail fd listenerX system
            let _server, system = acceptOrFail x system
            system

        let system =
            match kind with
            | "i"
            | "ir"
            | "o" -> bindOrFail fd at system
            | "L" ->
                let system = bindOrFail fd at system

                match UnixSocket.tryListen (Callers.leader system) fd 8 system with
                | Ok (ListenAnswer.Listening _, system) -> system
                | other -> failwith $"holder L: listen answered %A{other}"
            | "e"
            | "er"
            | "fe" -> bindOrFail fd at system |> connected
            | "c"
            | "cr"
            | "f"
            | "fr" -> connected system
            | other -> failwith $"unknown holder %s{other}"

        let name = nameOf fd system

        let system =
            if kind.StartsWith 'f' then
                closeOrFail fd system
            else
                system

        name, system

    let private linuxRow : string =
        @"^([a-zA-Z]+)/(s|sr) T=([0-9]+) holder OK at (\S+?)(, closed)?; connect to Y -> ([A-Z]+) getsockname=(\S+)$"

    [<Test>]
    let ``Linux's connect passes over exactly the holders it was measured to`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let mutable replayed = 0

        for line in lines "linux" do
            match line with
            | Matching linuxRow [ kind ; search ; port ; held ; _ ; measured ; reported ] ->
                let port = UInt16.Parse port
                let heldAt = (held.Split ':').[0] |> parseAddress
                let system, x, _ = systemOn platform [] (port, port)
                let heldName, system = place kind (Ipv4Endpoint.ofParts heldAt port) x system

                if heldName <> held then
                    failwith $"%s{kind}/%s{search}: the holder is at %s{heldName}, measured at %s{held}"

                let fd, system = newSocket (search = "sr") system

                let answered, name =
                    match connect fd listenerY system with
                    | Ok (SyscallAnswer.Completed 0L, system) -> "OK", nameOf fd system
                    | Ok (SyscallAnswer.Failed error, system) -> $"%A{error}", nameOf fd system
                    | other -> failwith $"%s{kind}/%s{search}: the model answered %A{other}"

                if (answered, name) <> (measured, reported) then
                    failwith $"%s{kind}/%s{search}: the model answered %s{answered} from %s{name}\n  measured: %s{line}"

                replayed <- replayed + 1
            | Matching @"^Linux " _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        // Eleven holders, two searches.
        replayed |> shouldEqual 22

    /// One Darwin row: its holder, where the probe put it, and the ports its
    /// searches took, relative to T.
    type private DarwinRow =
        {
            Holder : string
            Search : string
            HeldAt : Ipv4Endpoint
            Walked : bool
            Taken : int list
        }

    let private darwinRows : DarwinRow list =
        let holderLine =
            @"^([a-zA-Z]+)/(s|sr) holder OK at ([0-9.]+):([0-9]+)(?:, closed)? \(T=([0-9]+)\)$"

        let walkedLine =
            @"^[a-zA-Z]+/sr? walked the sequence round in [0-9]+ refused connects, ([0-9]+) of which took T$"

        let searchLine = @"^[a-zA-Z]+/sr? connect to Y -> OK from port T([+-][0-9]+)$"

        let rec parse (rows : DarwinRow list) (lines : string list) : DarwinRow list =
            match lines with
            | [] -> List.rev rows
            | Matching @"^Darwin " _ :: rest -> parse rows rest
            | Matching holderLine [ kind ; search ; address ; port ; target ] :: rest ->
                if port <> target then
                    failwith $"%s{kind}/%s{search}: the holder is at %s{port}, not at T=%s{target}"

                let walked, rest =
                    match rest with
                    | Matching walkedLine [ took ] :: rest ->
                        if took <> "0" then
                            failwith $"%s{kind}/%s{search}: %s{took} refused connects took T"

                        true, rest
                    | _ -> false, rest

                let taken, rest =
                    match rest with
                    | Matching searchLine [ a ] :: Matching searchLine [ b ] :: Matching searchLine [ c ] :: Matching searchLine [ d ] :: rest ->
                        [ a ; b ; c ; d ] |> List.map Int32.Parse, rest
                    | _ -> failwith $"%s{kind}/%s{search}: expected four searches"

                let row =
                    {
                        Holder = kind
                        Search = search
                        HeldAt = Ipv4Endpoint.ofParts (parseAddress address) (UInt16.Parse port)
                        Walked = walked
                        Taken = taken
                    }

                parse (row :: rows) rest
            | line :: _ -> failwith $"unparsed line: %s{line}"

        parse [] (lines "darwin")

    [<Test>]
    let ``Darwin's connect passes over every holder it was measured to`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64
        let rows = darwinRows

        // Eleven holders, two searches.
        List.length rows |> shouldEqual 22

        for row in rows do
            let target = row.HeldAt.Port
            let low = target - 1us
            let high = target + 4us

            let extra =
                if row.HeldAt.Address = Ipv4Address.loopback then
                    []
                else
                    [ row.HeldAt.Address ]

            let system, x, y = systemOn platform extra (low, high)

            // A holder that its own connect gives its port finds the cursor at
            // T, as the probe's refused connects left Darwin's; every other
            // holder is put there by bind(2), which does not move it.
            let system =
                if implicitHolder row.Holder then
                    Kernel.mapMachine
                        (fun machine ->
                            { machine with
                                NextEphemeralPort = target
                            }
                        )
                        system
                else
                    system

            let held, system = place row.Holder row.HeldAt x system

            if held <> Ipv4Endpoint.toString row.HeldAt then
                failwith $"%s{row.Holder}/%s{row.Search}: the holder is at %s{held}, measured at %A{row.HeldAt}"

            // The probe walked Darwin's sequence round to two below T, taking
            // ports by refused connects, none of them T. The model's cursor is
            // put two below T instead, so that a refused connect from there
            // shows the same: it takes T-1, and the next one does not take T.
            let system =
                if row.Walked then
                    let system =
                        Kernel.mapMachine
                            (fun machine ->
                                { machine with
                                    NextEphemeralPort = low
                                }
                            )
                            system

                    let refusedFrom (system : UnixSystem<int, string>) : uint16 * UnixSystem<int, string> =
                        let fd, system = newSocket false system

                        match connect fd closedPort system with
                        | Ok (SyscallAnswer.Failed UnixError.ECONNREFUSED, system) ->
                            let port = portOf fd system
                            port, closeOrFail fd system
                        | other -> failwith $"%s{row.Holder}/%s{row.Search}: a refused connect answered %A{other}"

                    let first, system = refusedFrom system
                    let second, system = refusedFrom system

                    if first <> low || second = target then
                        failwith
                            $"%s{row.Holder}/%s{row.Search}: refused connects took %d{first} and %d{second}, with T=%d{target}"

                    Kernel.mapMachine
                        (fun machine ->
                            { machine with
                                NextEphemeralPort = low
                            }
                        )
                        system
                else
                    system

            // Each search connects to Y, and then, as the probe's did, the
            // accepted socket closes and then the searching one.
            let taken, _ =
                (([], system), [ 1..4 ])
                ||> List.fold (fun (taken, system) _ ->
                    let fd, system = newSocket (row.Search = "sr") system
                    let system = connectOrFail fd listenerY system
                    let port = portOf fd system
                    let server, system = acceptOrFail y system
                    let system = closeOrFail server system |> closeOrFail fd
                    taken @ [ int port - int target ], system
                )

            if taken <> row.Taken then
                failwith
                    $"%s{row.Holder}/%s{row.Search}: the model's searches took %A{taken} relative to T, measured %A{row.Taken}"
