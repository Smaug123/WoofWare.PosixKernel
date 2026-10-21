namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Net
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which addresses an unprivileged `bind(2)` to a port below 1024 is refused
/// for, replayed cell by cell from both flavours' outputs of
/// `docs/probes/privileged-port`: every socket shape the probe made, each of
/// its addresses, at ports 1, 80, 1023 and 1024; and Darwin's run as root,
/// which binds all of them.
///
/// Every cell must be answered as measured, except those this kernel refuses
/// (`refused` lists them by row, with why), which must be refused -- so a row
/// that comes to be modelled fails here until it leaves the list.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPrivilegedPortMeasured =

    let private context : string = "TestPrivilegedPortMeasured"

    /// One measured row: a socket shape, an address, and the answer at each
    /// port.
    type private Row =
        {
            Line : string
            Socket : string
            Kind : SocketKind
            Address : string
            Answers : (uint16 * string) list
        }

    let private parseRow (line : string) : Row =
        match line.Split (' ', StringSplitOptions.RemoveEmptyEntries) |> List.ofArray with
        | socket :: kind :: address :: cells ->
            let kind =
                match kind with
                | "stream" -> SocketKind.Stream
                | "dgram" -> SocketKind.Datagram
                | other -> failwith $"unknown kind %s{other} in %s{line}"

            let answers =
                cells
                |> List.map (fun cell ->
                    match cell.Split '=' with
                    | [| port ; answer |] -> UInt16.Parse port, answer
                    | _ -> failwith $"unparsed cell %s{cell} in %s{line}"
                )

            {
                Line = line
                Socket = socket
                Kind = kind
                Address = address
                Answers = answers
            }
        | _ -> failwith $"unparsed row %s{line}"

    /// The resource holding each flavour's run as an ordinary user.
    let private unprivilegedRun (flavour : SimulatedUnixFlavour) : string =
        match flavour with
        | SimulatedUnixFlavour.Linux -> "privileged-port.linux.txt"
        | SimulatedUnixFlavour.Darwin -> "privileged-port.darwin.txt"

    /// The measured rows of the run in the resource `name`, and the uid that
    /// measured them.
    let private measured (name : string) : uint32 * Row list =
        let lines = SocketLadder.resource name |> Array.map (fun line -> line.TrimEnd '\r')

        let uid =
            lines
            |> Array.pick (fun line ->
                if line.StartsWith ("uid=", StringComparison.Ordinal) then
                    let fields = line.Split ' '

                    let parse (field : string) =
                        UInt32.Parse (field.Substring (field.IndexOf '=' + 1))

                    let all = fields |> Array.map parse

                    if all |> Array.exists (fun id -> id <> all.[0]) then
                        failwith $"%s{name}: the probe's uids differ (%s{line})"

                    Some all.[0]
                else
                    None
            )

        let rows =
            lines
            |> Array.filter (fun line ->
                line.StartsWith ("v4 ", StringComparison.Ordinal)
                || line.StartsWith ("v6 ", StringComparison.Ordinal)
                || line.StartsWith ("v6only ", StringComparison.Ordinal)
            )
            |> Array.map parseRow
            |> List.ofArray

        uid, rows

    /// Why this kernel refuses every cell of `row`, if it does.
    let private refused (row : Row) : string option =
        match row.Socket, row.Kind, row.Address with
        | "v4", _, _ -> None
        | _, SocketKind.Datagram, _ ->
            Some "an IPv6 datagram socket's addresses are not modelled (SockaddrCopyRefusal.UnmodelledInet6Kind)"
        | "v6", _, "::ffff:0.0.0.0"
        | _, _, "::"
        | _, _, "::1" ->
            Some "an IPv6 address other than a specific v4-mapped one is refused (BindRefusal.UnmodelledIpv6Address)"
        | _ -> None

    /// A booted system whose process has the probe's uid.
    let private systemOn (platform : SimulatedUnixPlatform) (uid : uint32) : UnixSystem<int, string> =
        let credentials =
            Credentials.ofIds (UserId.parseOrFail context uid) (GroupId.parseOrFail context uid) []

        UnixSystem.initial platform
        |> Launched.bootWith (Launched.credentials credentials) UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private setV6Only (fd : int) (value : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let platform = UnixSystem.platform system

        match
            Lone.UnixSocket.trySetsockoptBytes
                fd
                (SimulatedUnixPlatform.ipv6OptionLevel platform)
                (SimulatedUnixPlatform.ipv6OnlyOption platform)
                UserBuffer.Mapped
                4u
                (Some (ImmutableArray.CreateRange (SimulatedUnixPlatform.encodeCInt platform value)))
                system
        with
        | Ok (SetSockOptAnswer.Set, system) -> system
        | other -> failwith $"IPV6_V6ONLY=%d{value} answered %A{other}"

    /// What the model answers for the bind of one cell, as the probe prints
    /// it, or `REFUSED` and why.
    let private answer
        (platform : SimulatedUnixPlatform)
        (uid : uint32)
        (row : Row)
        (port : uint16)
        : string * string option
        =
        let system = systemOn platform uid

        let protocol =
            match row.Kind with
            | SocketKind.Stream -> SocketProtocol.Tcp
            | _ -> SocketProtocol.Udp

        let address = IPAddress.Parse row.Address

        let fd, system, blob, length =
            match row.Socket with
            | "v4" ->
                let fd, system = NewSocket.create SocketDomain.Inet row.Kind protocol system
                let bytes = address.GetAddressBytes ()

                let raw = bytes |> Array.fold (fun acc octet -> (acc <<< 8) ||| uint32 octet) 0u

                fd, system, CopyIn.inet platform (Ipv4Endpoint.ofParts (Ipv4Address raw) port), 16u
            | "v6"
            | "v6only" ->
                let fd, system = NewSocket.create SocketDomain.Inet6 row.Kind protocol system
                let system = setV6Only fd (if row.Socket = "v6only" then 1 else 0) system

                let blob =
                    CopyIn.blob6
                        platform
                        (SimulatedUnixPlatform.internetV6AddressFamily platform)
                        (address.GetAddressBytes ())
                        port

                fd, system, blob, 28u
            | other -> failwith $"unknown socket %s{other}"

        match CopyIn.bind fd UserBuffer.Mapped length blob system with
        | Ok (BindAnswer.Bound _, _) -> "OK", None
        | Ok (BindAnswer.Failed error, _) -> $"%A{error}", None
        | Error refusal -> "REFUSED", Some (BindRefusal.describe refusal)

    let private replay (platform : SimulatedUnixPlatform) (name : string) (expectedUid : uint32) : unit =
        let uid, rows = measured name

        if uid <> expectedUid then
            failwith $"%s{name}: the probe ran as uid %d{uid}, not %d{expectedUid}"

        let mismatches =
            [
                for row in rows do
                    let expectRefusal = (refused row).IsSome

                    for port, measured in row.Answers do
                        let expected = if expectRefusal then "REFUSED" else measured
                        let actual, why = answer platform uid row port

                        if actual <> expected then
                            let why = why |> Option.map (sprintf " (%s)") |> Option.defaultValue ""

                            $"%s{row.Line}: port %d{port} measured %s{measured}, expected %s{expected}, model answered %s{actual}%s{why}"
            ]

        if not mismatches.IsEmpty then
            failwith (String.Join ("\n", mismatches))

    [<Test>]
    let ``every Linux row is replayed`` () : unit =
        replay SimulatedUnixPlatform.linuxX64 (unprivilegedRun SimulatedUnixFlavour.Linux) 1000u

    [<Test>]
    let ``every Darwin row is replayed`` () : unit =
        replay SimulatedUnixPlatform.macOsArm64 (unprivilegedRun SimulatedUnixFlavour.Darwin) 501u

    [<Test>]
    let ``every row of Darwin's root run is replayed`` () : unit =
        replay SimulatedUnixPlatform.macOsArm64 "privileged-port.darwin-root.txt" 0u

    /// The replay checks every cell it finds, so it is only as strong as the
    /// cells it finds: each output must hold every row the probe prints.
    [<Test>]
    let ``each output holds every row the probe prints`` () : unit =
        for name in
            [
                unprivilegedRun SimulatedUnixFlavour.Linux
                unprivilegedRun SimulatedUnixFlavour.Darwin
                "privileged-port.darwin-root.txt"
            ] do
            let _, rows = measured name

            rows.Length |> shouldEqual 20

            for row in rows do
                row.Answers |> List.map fst |> shouldEqual [ 1us ; 80us ; 1023us ; 1024us ]
