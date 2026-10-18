namespace WoofWare.PosixKernel.Test

open System
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `connect(2)` to 127.0.0.2, an address inside loopback's `127.0.0.0/8` other
/// than 127.0.0.1, on the machine `UnixSystem.initial` boots (which holds
/// 127.0.0.1 and routes the whole `/8` locally), replayed from both flavours'
/// outputs of `docs/probes/loopback-alias-connect`.
///
/// Linux takes the whole `/8` as its own; Darwin holds 127.0.0.1 alone and
/// drops a SYN to any other address on the route, so its connect waits for
/// TCP's connection timer, which this kernel does not model: it refuses.
///
/// Replayed: each stream row's connect, from a socket fresh, bound to
/// 127.0.0.1:0 or bound to 0.0.0.0:0, with a wildcard listener, a listener at
/// 127.0.0.1, or nothing at the port (the probe's SO_ERROR is not compared);
/// a non-blocking row's first answer; and a datagram row's connect. Not
/// replayed: datagram delivery and `sendto(2)`, which this kernel does not
/// model, and the timed row. Every replayed row must be answered as measured,
/// except those `refused` lists, which must be refused as it says.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestLoopbackAliasConnectMeasured =

    let private port : uint16 = 5000us

    let private alias : Ipv4Address = Ipv4Address 0x7F000002u

    let private lines (flavour : SimulatedUnixFlavour) : string list =
        let name =
            match flavour with
            | SimulatedUnixFlavour.Linux -> "loopback-alias-connect.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "loopback-alias-connect.darwin.txt"

        SocketLadder.resource name
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> List.ofArray

    let private boot (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private create (kind : SocketKind) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let protocol =
            match kind with
            | SocketKind.Stream -> SocketProtocol.Tcp
            | _ -> SocketProtocol.Udp

        NewSocket.create SocketDomain.Inet kind protocol system

    let private bindTo (fd : int) (endpoint : Ipv4Endpoint) (system : UnixSystem<int, string>) =
        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform endpoint) system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"bind to %A{endpoint} answered %A{other}"

    /// A listener as the probe's letter names it: `W` at 0.0.0.0, `L` at
    /// 127.0.0.1, `N` none.
    let private withListener (letter : char) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let at =
            match letter with
            | 'W' -> Some Ipv4Address.any
            | 'L' -> Some Ipv4Address.loopback
            | 'N' -> None
            | other -> failwith $"unknown listener %c{other}"

        match at with
        | None -> system
        | Some address ->
            let l, system = create SocketKind.Stream system
            let system = bindTo l (Ipv4Endpoint.ofParts address port) system

            match UnixSocket.tryListen (Callers.leader system) l 8 system with
            | Ok (ListenAnswer.Listening _, system) -> system
            | other -> failwith $"listen answered %A{other}"

    /// A client as the probe's letter names it: `f` fresh, `b` bound to
    /// 127.0.0.1:0, `w` bound to 0.0.0.0:0.
    let private withClient
        (letter : char)
        (kind : SocketKind)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let fd, system = create kind system

        match letter with
        | 'f'
        | 'c' -> fd, system
        | 'b' -> fd, bindTo fd (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us) system
        | 'w' -> fd, bindTo fd (Ipv4Endpoint.ofParts Ipv4Address.any 0us) system
        | other -> failwith $"unknown client %c{other}"

    /// An endpoint as the probe prints one: the port is `P`, `0` or `eph`.
    let private shown (endpoint : Ipv4Endpoint) : string =
        let portText =
            if endpoint.Port = port then "P"
            elif endpoint.Port = 0us then "0"
            else "eph"

        $"%s{dotted endpoint.Address}:%s{portText}"

    let private connectTo
        (fd : int)
        (address : Ipv4Address)
        (system : UnixSystem<int, string>)
        : Result<SyscallAnswer * UnixSystem<int, string>, string>
        =
        let blob =
            CopyIn.inet system.Machine.UnixPlatform (Ipv4Endpoint.ofParts address port)

        CopyIn.connect fd UserBuffer.Mapped 16u blob system
        |> Result.mapError (fun refusal -> $"refused:%s{UnionCaseName.ofValue refusal}")

    let private answerText (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed _ -> "OK"
        | SyscallAnswer.Failed error -> string error

    /// A blocking stream row (`S` or `C`), in the probe's words without its
    /// SO_ERROR.
    let private streamRow (platform : SimulatedUnixPlatform) (label : string) (destination : string) : string =
        let listener = label.[1]
        let system = boot platform |> withListener listener
        let fd, system = withClient label.[2] SocketKind.Stream system

        let address =
            if destination = "127.0.0.2" then
                alias
            else
                Ipv4Address.loopback

        match connectTo fd address system with
        | Error refused -> refused
        | Ok (answer, after) ->
            let socket = socketOf fd after

            let peer, accepted =
                match socket.Phase with
                | SocketPhase.Established (connection, ConnectionEnd.Client) ->
                    let connection = UnixMachineState.connection connection after.Machine

                    shown connection.ServerAddress,
                    $" | accepted local=%s{shown connection.ServerAddress} peer=%s{shown connection.ClientAddress}"
                | _ -> "ENOTCONN", (if listener = 'N' then "" else " | accept: nothing queued")

            $"%s{label} connect %s{destination}:P=%s{answerText answer} local=%s{shown (local socket)} peer=%s{peer}%s{accepted}"

    /// A non-blocking stream row's first answer.
    let private nonBlockingRow (platform : SimulatedUnixPlatform) (label : string) : string =
        let system = boot platform |> withListener label.[1]
        let fd, system = withClient label.[2] SocketKind.Stream system
        let system = NonBlocking.set fd system

        match connectTo fd alias system with
        | Error refused -> refused
        | Ok (answer, _) -> $"%s{label} connect=%s{answerText answer}"

    /// A datagram row's connect.
    let private datagramRow (platform : SimulatedUnixPlatform) (label : string) : string =
        let fd, system = boot platform |> withClient 'c' SocketKind.Datagram

        match connectTo fd alias system with
        | Error refused -> refused
        | Ok (answer, after) ->
            $"%s{label} 127.0.0.2:P connect=%s{answerText answer} local=%s{shown (local (socketOf fd after))}"

    /// What the row measured, in the words the model's replay prints, or
    /// `None` for a row not replayed.
    let private replayed (line : string) : (string * string * (SimulatedUnixPlatform -> string)) option =
        let label = line.Split(' ').[0]

        if Regex.IsMatch (label, "^[SC][WLN][fbw]$") then
            let destination = line.Split(' ').[2].Split(':').[0]
            let expected = Regex.Replace (line, " SO_ERROR=\\S+", "")
            Some (label, expected, (fun platform -> streamRow platform label destination))
        elif Regex.IsMatch (label, "^B[WLN][fbw]$") then
            let expected = line.Split(' ').[0] + " " + line.Split(' ').[1]
            Some (label, expected, (fun platform -> nonBlockingRow platform label))
        elif Regex.IsMatch (label, "^D[WL]c$") then
            let fields = line.Split ' '

            Some (
                label,
                String.Join (" ", fields.[0..2]) + " " + fields.[4],
                (fun platform -> datagramRow platform label)
            )
        else
            None

    /// The rows this kernel refuses, by label, with the refusal.
    let private refused (flavour : SimulatedUnixFlavour) (label : string) : string option =
        match flavour, label.[0] with
        | SimulatedUnixFlavour.Darwin, ('S' | 'B') -> Some "refused:UnheldDestination"
        | _ -> None

    let private check (platform : SimulatedUnixPlatform) : unit =
        let flavour = SimulatedUnixPlatform.flavour platform

        let rows = lines flavour |> List.choose replayed
        // Nine of each stream kind, six controls and two datagram connects.
        rows.Length |> shouldEqual 26

        let mismatches =
            [
                for label, measured, model in rows do
                    let expected = refused flavour label |> Option.defaultValue measured
                    let actual = model platform

                    if actual <> expected then
                        $"%s{label}: measured %s{measured}\n    expected %s{expected}\n    model    %s{actual}"
            ]

        if not mismatches.IsEmpty then
            failwith (String.Join ("\n", mismatches))

    [<Test>]
    let ``every Linux row is answered as measured`` () : unit = check SimulatedUnixPlatform.linuxX64

    [<Test>]
    let ``every Darwin row is answered as measured`` () : unit = check SimulatedUnixPlatform.macOsArm64

    /// The rows above as literals: on the machine `UnixSystem.initial` boots,
    /// a stream connect from 127.0.0.1 to 127.0.0.2 completes on Linux where a
    /// wildcard listener has the port, its server end at 127.0.0.2, and is
    /// refused (ECONNREFUSED) where nothing does; on Darwin it is refused by
    /// this kernel either way, since Darwin drops the SYN.
    [<Test>]
    let ``a stream connect to 127.0.0.2 on the initial machine`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            for listener in [ 'W' ; 'N' ] do
                let system = boot platform |> withListener listener
                let fd, system = withClient 'b' SocketKind.Stream system

                match SimulatedUnixPlatform.flavour platform, listener, connectTo fd alias system with
                | SimulatedUnixFlavour.Linux, 'W', Ok (SyscallAnswer.Completed 0L, after) ->
                    match (socketOf fd after).Phase with
                    | SocketPhase.Established (connection, ConnectionEnd.Client) ->
                        (UnixMachineState.connection connection after.Machine).ServerAddress
                        |> shouldEqual (Ipv4Endpoint.ofParts alias port)
                    | phase -> failwith $"Linux: connected, yet the socket is %A{phase}"
                | SimulatedUnixFlavour.Linux, 'N', Ok (SyscallAnswer.Failed UnixError.ECONNREFUSED, _) -> ()
                | SimulatedUnixFlavour.Darwin, _, Error "refused:UnheldDestination" -> ()
                | flavour, listener, other -> failwith $"%O{flavour}, listener %c{listener}: %A{other}"
