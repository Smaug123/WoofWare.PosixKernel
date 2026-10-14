namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which ports a TCP socket's search for an ephemeral port passes over, and
/// what `bind(2)`, `listen(2)` and `connect(2)` answer when it finds none,
/// replayed from both flavours' outputs of `docs/probes/ephemeral-search`.
///
/// Linux's rows each narrowed the searching socket's range to the one port
/// the row's holder held, so each replays on a machine whose ephemeral range
/// is that port. Darwin's were measured only with its whole range taken, so
/// they replay on a machine whose small range is taken the same way.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestEphemeralSearchMeasured =

    let private lines (flavour : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.ephemeral-search.%s{flavour}.txt"

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

    let private at (address : uint32) (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts (Ipv4Address address) port

    let private loopback (port : uint16) : Ipv4Endpoint = at 0x7F000001u port
    let private wildcard (port : uint16) : Ipv4Endpoint = at 0u port

    /// The listeners the probe's connects aim at.
    let private listenerX : uint16 = 45301us
    let private listenerY : uint16 = 45302us

    /// The probe's name for an outcome: the errno's, or `OK`.
    let private errorName (error : UnixError option) : string =
        match error with
        | None -> "OK"
        | Some error -> $"%A{error}"

    /// A machine whose ephemeral range is `low..high`, with listeners at
    /// 127.0.0.1:`listenerX` and `listenerY`, each carrying `SO_REUSEADDR` as
    /// the probe's did.
    let private systemOn (platform : SimulatedUnixPlatform) (low : uint16, high : uint16) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial platform
            |> UnixBootImage.withLocalIpv4Addresses UnixSystem.defaultLocalIpv4Addresses UnixSystem.defaultLocalRoutes
            |> UnixBootImage.tryWithEphemeralPortRange (low, high)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        [ listenerX ; listenerY ]
        |> List.fold
            (fun system port ->
                let fd, system =
                    NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

                let system = ReuseAddress.set true fd system

                let system =
                    match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (loopback port)) system with
                    | Ok (BindAnswer.Bound _, system) -> system
                    | other -> failwith $"binding the listener at %d{port}: %A{other}"

                match UnixSocket.tryListen fd 128 system with
                | Ok (ListenAnswer.Listening _, system) -> system
                | other -> failwith $"listening at %d{port}: %A{other}"
            )
            system

    let private newSocket (reuse : bool) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        fd, (if reuse then ReuseAddress.set true fd system else system)

    /// The outcome of a call, as the probe names it, or the refusal.
    type private Outcome =
        | Answered of error : UnixError option
        | Refused of refusal : string

    let private bind
        (fd : int)
        (endpoint : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : Outcome * UnixSystem<int, string>
        =
        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform endpoint) system with
        | Ok (BindAnswer.Bound _, system) -> Answered None, system
        | Ok (BindAnswer.Failed error, system) -> Answered (Some error), system
        | Error refusal -> Refused (BindRefusal.describe refusal), system

    let private listen (fd : int) (system : UnixSystem<int, string>) : Outcome * UnixSystem<int, string> =
        match UnixSocket.tryListen fd 8 system with
        | Ok (ListenAnswer.Listening _, system) -> Answered None, system
        | Ok (ListenAnswer.Failed error, system) -> Answered (Some error), system
        | Error refusal -> Refused (ListenRefusal.describe refusal), system

    let private connect
        (fd : int)
        (port : uint16)
        (system : UnixSystem<int, string>)
        : Outcome * UnixSystem<int, string>
        =
        match
            CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform (loopback port)) system
        with
        | Ok (SyscallAnswer.Completed _, system) -> Answered None, system
        | Ok (SyscallAnswer.Failed error, system) -> Answered (Some error), system
        | Error refusal -> Refused (ConnectRefusal.describe refusal), system

    /// What `getsockname(2)` reports, as the probe prints it.
    let private nameOf (fd : int) (system : UnixSystem<int, string>) : string =
        match UnixSocket.tryGetsockname fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr system.Machine.UnixPlatform bytes).Endpoint with
            | Some endpoint -> Ipv4Endpoint.toString endpoint
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    /// The search the probe names `search`, on a new socket carrying
    /// `SO_REUSEADDR` if the name ends in `r`.
    let private search (name : string) (system : UnixSystem<int, string>) : Outcome * string =
        let fd, system = newSocket (name.EndsWith 'r') system

        let outcome, system =
            match name with
            | "B"
            | "Br" -> bind fd (loopback 0us) system
            | "W"
            | "Wr" -> bind fd (wildcard 0us) system
            | "Lsr" -> listen fd system
            | "Y"
            | "Yr" -> connect fd listenerY system
            | "Xr" -> connect fd listenerX system
            | other -> failwith $"unknown search %s{other}"

        outcome, nameOf fd system

    /// The holder the probe names `kind`, at `port`, and what getsockname
    /// reports for it; `None` for the control.
    let private holder
        (kind : string)
        (port : uint16)
        (system : UnixSystem<int, string>)
        : string option * UnixSystem<int, string>
        =
        let made (fd : int) (outcome : Outcome, system : UnixSystem<int, string>) =
            match outcome with
            | Answered None -> Some (nameOf fd system), system
            | other -> failwith $"holder %s{kind} at %d{port}: %A{other}"

        let bound (reuse : bool) (endpoint : Ipv4Endpoint) (system : UnixSystem<int, string>) =
            let fd, system = newSocket reuse system
            fd, bind fd endpoint system

        match kind with
        | "none" -> None, system
        | "lr" -> bound true (loopback port) system ||> made
        | "l" -> bound false (loopback port) system ||> made
        | "wr" -> bound true (wildcard port) system ||> made
        | "or" -> bound true (at 0x7F000002u port) system ||> made
        | "Lr" ->
            let fd, (outcome, system) = bound true (loopback port) system
            made fd (outcome, system) |> ignore
            made fd (listen fd system)
        | "c"
        | "cr" ->
            let fd, system = newSocket (kind = "cr") system
            made fd (connect fd listenerX system)
        | "br" ->
            let fd, (outcome, system) = bound true (loopback port) system
            made fd (outcome, system) |> ignore
            made fd (connect fd listenerX system)
        | other -> failwith $"unknown holder %s{other}"

    let private linuxRow : string =
        @"^([a-zA-Z]+)/([A-Za-z]+) L=([0-9]+) holder (.*); [A-Za-z]+ -> ([A-Z]+) getsockname=(\S+)$"

    [<Test>]
    let ``Linux answers every row as measured`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let mutable replayed = 0

        for line in lines "linux" do
            match line with
            | Matching linuxRow [ kind ; name ; port ; held ; measured ; reported ] ->
                let port = UInt16.Parse port
                let system = systemOn platform (port, port)
                let heldName, system = holder kind port system

                match heldName, held with
                | None, "-" -> ()
                | Some heldName, Matching @"^OK at (\S+)$" [ measuredHeld ] when heldName = measuredHeld -> ()
                | _ -> failwith $"%s{kind}/%s{name}: the holder is %A{heldName}, measured %s{held}"

                match search name system with
                | Answered error, name' when errorName error = measured && name' = reported -> ()
                | outcome, name' ->
                    failwith
                        $"%s{kind}/%s{name}: the model's search answered %A{outcome} with getsockname %s{name'}\n  measured: %s{line}"

                replayed <- replayed + 1
            | Matching @"^Linux " _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        // Nine holders, eight searches.
        replayed |> shouldEqual 72

    /// Darwin's range was taken whole by sockets bound at 127.0.0.1 carrying
    /// `SO_REUSEADDR`, and every search then found no port: EADDRNOTAVAIL,
    /// leaving the socket unbound. The model's search takes no port there
    /// either, and refuses to say what Darwin answers, since for a socket
    /// carrying `SO_REUSEADDR` it may pass over a port Darwin's search would
    /// take (one an established socket holds). Once the range is free again,
    /// the search finds a port.
    [<Test>]
    let ``Darwin's search takes no port in a taken range`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64
        let low, high = 50000us, 50003us
        let mutable replayed = 0

        let taken =
            [ low..high ]
            |> List.fold
                (fun system port ->
                    let fd, system = newSocket true system

                    match bind fd (loopback port) system with
                    | Answered None, system -> system
                    | other, _ -> failwith $"taking %d{port}: %A{other}"
                )
                (systemOn platform (low, high))

        for line in lines "darwin" do
            match line with
            | Matching @"^exhausted/([A-Za-z]+) -> EADDRNOTAVAIL getsockname=0\.0\.0\.0:0$" [ name ] ->
                match search name taken with
                | Refused _, "0.0.0.0:0" -> ()
                | outcome, reported ->
                    failwith $"exhausted/%s{name}: the model answered %A{outcome}, reporting %s{reported}"

                replayed <- replayed + 1
            | Matching @"^released/W -> OK$" [] ->
                match search "W" (systemOn platform (low, high)) with
                | Answered None, _ -> ()
                | outcome, _ -> failwith $"released/W: the model answered %A{outcome}"

                replayed <- replayed + 1
            | Matching @"^(Darwin |range |filled )" _ -> ()
            | _ -> failwith $"unparsed line: %s{line}"

        replayed |> shouldEqual 8
