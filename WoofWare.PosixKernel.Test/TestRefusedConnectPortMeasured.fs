namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What a TCP socket whose `connect(2)` was refused still holds of its port,
/// and what its next `bind(2)`, `listen(2)` or `connect(2)` makes of it,
/// replayed row by row from both flavours' outputs of
/// `docs/probes/refused-connect-port`.
///
/// A port the kernel chose is its own choice, which the model need not
/// share: a row is held to the measured port exactly where the kernel kept the
/// refused socket's port, and otherwise only to having chosen a different one.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestRefusedConnectPortMeasured =

    let private lines (flavour : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.refused-connect-port.%s{flavour}.txt"

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

    /// The probe's name for an answer: an errno's, or `OK`.
    let private errorName (error : UnixError option) : string =
        match error with
        | None -> "OK"
        | Some error -> $"%A{error}"

    let private answerName (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed _ -> "OK"
        | SyscallAnswer.Failed error -> errorName (Some error)

    let private listenerPort : uint16 = 45200us

    /// Nowhere anything listens, or is bound.
    let private closedPort : Ipv4Endpoint = loopback 1us

    /// A system with a listener at 127.0.0.1:`listenerPort`, whose next
    /// ephemeral port is `port`.
    let private systemOn (platform : SimulatedUnixPlatform) (port : uint16) : UnixSystem<int, string> =
        let low = max 1024 (int port - 50) |> uint16
        let high = min 65535 (int port + 50) |> uint16

        let system =
            UnixSystem.initial platform
            |> UnixBootImage.tryWithEphemeralPortRange (low, high)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        let system =
            match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (loopback listenerPort)) system with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"binding the listener: %A{other}"

        let system =
            match UnixSocket.tryListen fd 128 system with
            | Ok (ListenAnswer.Listening _, system) -> system
            | other -> failwith $"listening: %A{other}"

        { system with
            Machine =
                { system.Machine with
                    NextEphemeralPort = port
                }
        }

    let private newSocket (reuse : bool) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        fd, (if reuse then ReuseAddress.set true fd system else system)

    let private bind
        (fd : int)
        (at : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : UnixError option * UnixSystem<int, string>
        =
        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform at) system with
        | Ok (BindAnswer.Bound _, system) -> None, system
        | Ok (BindAnswer.Failed error, system) -> Some error, system
        | Error refusal -> failwith $"bind %s{Ipv4Endpoint.toString at}: refused %A{refusal}"

    let private connect
        (fd : int)
        (destination : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        match CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform destination) system with
        | Ok result -> result
        | Error refusal ->
            failwith $"connect %s{Ipv4Endpoint.toString destination}: refused %s{ConnectRefusal.describe refusal}"

    /// `getsockopt(SO_ERROR)`, as the errno's name, or `OK` for 0.
    let private takeError (fd : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let platform = system.Machine.UnixPlatform
        let level = SimulatedUnixPlatform.socketOptionLevel platform
        let optionName = SimulatedUnixPlatform.socketErrorOption platform

        match
            UnixSocket.tryGetsockoptLength fd level optionName UserBuffer.Mapped UserBuffer.Mapped (Some 4u) system
        with
        | Ok (answer, system) ->
            let raw = OptionValue.readInt answer

            let name =
                if raw = 0 then
                    "OK"
                else
                    match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) raw with
                    | Some error -> errorName (Some error)
                    | None -> failwith $"SO_ERROR read errno %d{raw}"

            name, system
        | Error refusal -> failwith $"SO_ERROR refused: %s{SocketOptionRefusal.describe refusal}"

    let private nameOf (fd : int) (system : UnixSystem<int, string>) : Ipv4Endpoint =
        match UnixSocket.tryGetsockname fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr system.Machine.UnixPlatform bytes).Endpoint with
            | Some endpoint -> endpoint
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    /// The model's name agrees with the measured one if the addresses are the
    /// same and the port is too where the kernel's was the refused socket's
    /// own; where the kernel's was another, the model's must be another too.
    let private sameName (refusedPort : uint16) (measured : Ipv4Endpoint) (modelled : Ipv4Endpoint) : bool =
        measured.Address = modelled.Address
        && (if measured.Port = refusedPort || measured.Port = 0us then
                modelled.Port = measured.Port
            else
                modelled.Port <> refusedPort && modelled.Port <> 0us)

    let private rowPattern : string =
        @"^([IZWXY])([bns])([1-5]) bind=(\S+) connect=(\S+)(?: poll=\S+)?(?: SO_ERROR=(\S+))? getsockname=(\S+) \| (.*) \| getsockname=(\S+)$"

    let private replay (flavour : string) (platform : SimulatedUnixPlatform) : unit =
        let mutable replayed = 0

        for line in lines flavour do
            match line with
            | Matching rowPattern [ provenance ; path ; action ; bound ; connected ; soError ; before ; did ; after ] ->
                let fail (what : string) =
                    failwith $"%s{provenance}%s{path}%s{action} %s{what}\n  measured: %s{line}"

                let refusedName = endpoint before
                let refusedPort = refusedName.Port
                let system = systemOn platform refusedPort
                let fd, system = newSocket false system

                let boundError, system =
                    match provenance with
                    | "I" -> None, system
                    | "Z" -> bind fd (loopback 0us) system
                    | "W" -> bind fd (Ipv4Endpoint.ofParts Ipv4Address.any 0us) system
                    | "X" -> bind fd (loopback refusedPort) system
                    | _ -> bind fd (Ipv4Endpoint.ofParts Ipv4Address.any refusedPort) system

                if errorName boundError <> bound then
                    fail $"bind answered %s{errorName boundError}"

                let system =
                    if path = "b" then
                        system
                    else
                        UnixSystemState.withFileDescriptors
                            (FileDescriptorRegistry.setNonBlocking fd true (UnixSystemState.fileDescriptors system))
                            system

                let answer, system = connect fd closedPort system

                if answerName answer <> connected then
                    fail $"connect answered %s{answerName answer}"

                let system =
                    if path = "s" then
                        let taken, system = takeError fd system

                        if taken <> soError then
                            fail $"SO_ERROR read %s{taken}"

                        system
                    else
                        system

                if not (sameName refusedPort refusedName (nameOf fd system)) then
                    fail $"getsockname reported %s{Ipv4Endpoint.toString (nameOf fd system)}"

                let check (what : string) (measured : string) (modelled : string) =
                    if modelled <> measured then
                        fail $"%s{what} answered %s{modelled}"

                let system =
                    match action, did with
                    | "1",
                      Matching @"^fresh bind 127\.0\.0\.1:[0-9]+=(\S+), 0\.0\.0\.0:[0-9]+=(\S+), reuse 127\.0\.0\.1:[0-9]+=(\S+)$" [ atLoopback
                                                                                                                                     atWildcard
                                                                                                                                     reusing ] ->
                        // Each from a socket of its own, which the probe
                        // closes again.
                        let freshBind (reuse : bool) (address : Ipv4Address) : string =
                            let other, system = newSocket reuse system
                            bind other (Ipv4Endpoint.ofParts address refusedPort) system |> fst |> errorName

                        check "fresh bind 127.0.0.1" atLoopback (freshBind false Ipv4Address.loopback)
                        check "fresh bind 0.0.0.0" atWildcard (freshBind false Ipv4Address.any)
                        check "fresh bind 127.0.0.1 with SO_REUSEADDR" reusing (freshBind true Ipv4Address.loopback)
                        system
                    | "2", Matching @"^bind 127\.0\.0\.1:0=(\S+)$" [ measured ] ->
                        let error, system = bind fd (loopback 0us) system
                        check "bind 127.0.0.1:0" measured (errorName error)
                        system
                    | "3", Matching @"^listen=(\S+)$" [ measured ] ->
                        match UnixSocket.tryListen fd 8 system with
                        | Ok (ListenAnswer.Listening _, system) ->
                            check "listen" measured "OK"
                            system
                        | Ok (ListenAnswer.Failed error, system) ->
                            check "listen" measured (errorName (Some error))
                            system
                        | Error refusal -> fail $"listen refused %A{refusal}"
                    | "4",
                      Matching @"^connect listener=(\S+) \(getsockname=(\S+)\), again=(\S+)$" [ first ; between ; second ] ->
                        let answer, system = connect fd (loopback listenerPort) system
                        check "connect to the listener" first (answerName answer)

                        if not (sameName refusedPort (endpoint between) (nameOf fd system)) then
                            fail
                                $"getsockname after the first connect reported %s{Ipv4Endpoint.toString (nameOf fd system)}"

                        let answer, system = connect fd (loopback listenerPort) system
                        check "the second connect to the listener" second (answerName answer)
                        system
                    | "5", Matching @"^connect 127\.0\.0\.1:1 again=(\S+)$" [ measured ] ->
                        let answer, system = connect fd closedPort system
                        check "connect to the closed port again" measured (answerName answer)
                        system
                    | _ -> fail "unparsed action"

                if not (sameName refusedPort (endpoint after) (nameOf fd system)) then
                    fail $"getsockname reported %s{Ipv4Endpoint.toString (nameOf fd system)} at the end"

                UnixSystem.checkInvariants system |> shouldEqual []
                replayed <- replayed + 1
            | Matching @"^(Linux|Darwin) " _
            | Matching @"^listener at 127\.0\.0\.1:45200 -> OK$" _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        // Five ways to a port, three ways to the refusal, five things done after.
        replayed |> shouldEqual 75

    [<Test>]
    let ``Linux answers every row as measured`` () : unit =
        replay "linux" SimulatedUnixPlatform.linuxX64

    [<Test>]
    let ``Darwin answers every row as measured`` () : unit =
        replay "darwin" SimulatedUnixPlatform.macOsArm64
