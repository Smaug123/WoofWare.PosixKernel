namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which combinations of Linux's `net.ipv4.ip_local_port_range` and
/// `net.ipv4.ip_unprivileged_port_start` a machine may have, and which ports
/// an unprivileged process's searches take from a range of one port, replayed
/// from `docs/probes/local-port-range` and the sysctl rows of
/// `docs/probes/unprivileged-port-start`.
///
/// Each write the probes made took the namespace from one pair of settings to
/// another, or was refused; a machine booted with the pair it aimed at boots
/// exactly where the write was taken.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestLocalPortRangeMeasured =

    let private lines (name : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.%s{name}.linux.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    /// The two settings, as the probes read them back.
    type private Settings =
        {
            Range : uint16 * uint16
            Start : uint16
        }

    /// A range as one write of two numbers, each a port, gives it.
    let private (|PortPair|_|) (text : string) : (uint16 * uint16) option =
        let m = Regex.Match (text, @"^([0-9]+) ([0-9]+)$")

        if m.Success then
            match UInt16.TryParse m.Groups.[1].Value, UInt16.TryParse m.Groups.[2].Value with
            | (true, low), (true, high) -> Some (low, high)
            | _ -> None
        else
            None

    /// A value one write of a number gives.
    let private (|Port|_|) (text : string) : uint16 option =
        if Regex.IsMatch (text, @"^[0-9]+$") then
            match UInt16.TryParse text with
            | true, value -> Some value
            | false, _ -> None
        else
            None

    /// A Linux machine booted with `settings`, or the refusal.
    let private boot (settings : Settings) : Result<UnixSystem<int, string>, string * RefusalKind> =
        UnixSystem.initial SimulatedUnixPlatform.linuxX64
        |> UnixBootImage.tryWithEphemeralPortRange settings.Range
        |> Result.mapError (fun refusal ->
            EphemeralPortRangeRefusal.describe refusal, EphemeralPortRangeRefusal.kind refusal
        )
        |> Result.bind (fun image ->
            UnixBootImage.tryWithUnprivilegedPortStart settings.Start image
            |> Result.mapError (fun refusal ->
                UnprivilegedPortStartRefusal.describe refusal, UnprivilegedPortStartRefusal.kind refusal
            )
        )
        |> Result.bind (fun image ->
            let launch =
                Launched.launch SimulatedUnixPlatform.linuxX64 UnixSystem.pipedStandardStreams 0 (CpuId 0)

            UnixBootImage.tryBoot launch image
            |> Result.mapError (fun refusal -> BootRefusal.describe refusal, BootRefusal.kind refusal)
        )

    /// Whether the model agrees with one write the probe measured: from
    /// `before`, aiming at `aimed`, answered `measured`.
    let private agrees (line : string) (aimed : Settings) (measured : string) : unit =
        match measured, boot aimed with
        | "OK", Ok system ->
            UnixSystem.ephemeralPortRange system |> shouldEqual aimed.Range
            UnixSystem.unprivilegedPortStart system |> shouldEqual aimed.Start
        | "EINVAL", Error (_, kind) ->
            match kind with
            | RefusalKind.Contradictory _
            | RefusalKind.OutOfRange _ -> ()
            | other -> failwith $"%s{line}: refused, but as %A{other}, though no Linux machine has these settings"
        | _, Ok _ -> failwith $"%s{line}: the model boots with %A{aimed}"
        | _, Error (refusal, _) -> failwith $"%s{line}: the model refuses %A{aimed}: %s{refusal}"

    let private writeRow : Regex =
        Regex
            @"^\S+ write (ip_local_port_range|ip_unprivileged_port_start) ""(.*)"" -> (\S+) \| range=(\d+) (\d+) unprivileged_start=(\d+)$"

    let private handoutHeader : Regex =
        Regex
            @"^B unprivileged_start ""(\d+)"" -> OK, range ""(\d+) (\d+)"" -> OK \| range=(\d+) (\d+) unprivileged_start=(\d+)$"

    let private defaults : Settings =
        {
            Range = UnixSystem.defaultEphemeralPortRange SimulatedUnixFlavour.Linux
            Start = UnixSystem.defaultUnprivilegedPortStart
        }

    [<Test>]
    let ``a Linux machine boots with exactly the settings the sysctls were measured to take`` () : unit =
        let mutable replayed = 0

        // Each section's rows start from the defaults, as the probe restored
        // them before each row; an O row starts where the line before it left
        // the namespace.
        let mutable current = defaults
        let mutable section = ""

        for line in lines "local-port-range" do
            let m = writeRow.Match line

            if m.Success then
                let label = line.Split(' ').[0]

                if label <> section || label = "R" || label = "U" then
                    current <- defaults
                    section <- label

                let readBack =
                    {
                        Range = UInt16.Parse m.Groups.[4].Value, UInt16.Parse m.Groups.[5].Value
                        Start = UInt16.Parse m.Groups.[6].Value
                    }

                let aimed =
                    match m.Groups.[1].Value, m.Groups.[2].Value with
                    | "ip_local_port_range", PortPair range ->
                        Some
                            { current with
                                Range = range
                            }
                    | "ip_unprivileged_port_start", Port start ->
                        Some
                            { current with
                                Start = start
                            }
                    // A write two ports cannot state: a negative number, one
                    // past 65535, or not two numbers at all.
                    | _ -> None

                match aimed with
                | Some aimed ->
                    agrees line aimed m.Groups.[3].Value
                    replayed <- replayed + 1
                | None -> ()

                current <- readBack

        // Section R's 13 writes of two ports, U's 10 of a port, and O's 15.
        replayed |> shouldEqual 38

    let private sysctlRow : Regex =
        Regex
            @"^S range ""(\d+) (\d+)"" -> OK, unprivileged_start ""(.*)"" -> (\S+) \| range=\d+ \d+ unprivileged_start=\d+$"

    [<Test>]
    let ``ip_unprivileged_port_start goes as high as the range's low end, as measured`` () : unit =
        let mutable replayed = 0

        for line in lines "unprivileged-port-start" do
            let m = sysctlRow.Match line

            if m.Success then
                match m.Groups.[3].Value with
                | Port start ->
                    let aimed =
                        {
                            Range = UInt16.Parse m.Groups.[1].Value, UInt16.Parse m.Groups.[2].Value
                            Start = start
                        }

                    agrees line aimed m.Groups.[4].Value
                    replayed <- replayed + 1
                | _ -> ()

        // Eight rows, of which 65536 and -1 are no port.
        replayed |> shouldEqual 6

    /// The listener the probe's connects aim at, bound by root before its
    /// child dropped to uid 1000.
    let private listenerPort : uint16 = 20000us

    let private unprivileged : Credentials =
        Credentials.ofIds
            (UserId.parseOrFail "TestLocalPortRangeMeasured" 1000u)
            (GroupId.parseOrFail "TestLocalPortRangeMeasured" 1000u)
            []

    /// The machine a section-B row's child ran on: the row's settings, a
    /// listener at 127.0.0.1:`listenerPort`, and a process of uid 1000.
    let private handoutMachine (settings : Settings) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> UnixBootImage.tryWithEphemeralPortRange settings.Range
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> UnixBootImage.tryWithUnprivilegedPortStart settings.Start
            |> Configured.expectOk UnprivilegedPortStartRefusal.describe
            |> Launched.bootWith (Launched.credentials unprivileged) UnixSystem.pipedStandardStreams 0 (CpuId 0)

        // Root bound it in the probe; here the listener's port is above the
        // row's unprivileged start, so uid 1000 binds it alike.
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        let platform = system.Machine.UnixPlatform

        let system =
            match
                CopyIn.bind
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback listenerPort))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"binding the listener: %A{other}"

        match UnixSocket.tryListen (Callers.leader system) fd 8 system with
        | Ok (ListenAnswer.Listening _, system) -> system
        | other -> failwith $"listening: %A{other}"

    /// A dotted quad as the probe prints one.
    let private parseAddress (text : string) : Ipv4Address =
        match text.Split '.' |> Array.map Byte.Parse with
        | [| a ; b ; c ; d |] -> Ipv4Address ((uint32 a <<< 24) ||| (uint32 b <<< 16) ||| (uint32 c <<< 8) ||| uint32 d)
        | _ -> failwith $"not an IPv4 address: %s{text}"

    let private portOf (fd : int) (system : UnixSystem<int, string>) : uint16 =
        match UnixSocket.tryGetsockname (Callers.leader system) fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr system.Machine.UnixPlatform bytes).Endpoint with
            | Some endpoint -> endpoint.Port
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"closing fd %d{fd}: %A{other}"

    /// What one of the child's calls answers in the model, and the port its
    /// socket then reports, as the probe prints them; and the system after
    /// it, with the socket closed.
    let private handout (call : string) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let platform = system.Machine.UnixPlatform
        let m = Regex.Match (call, @"^(tcp|udp) (bind|connect) (\S+):(\S+)$")

        if not m.Success then
            failwith $"unparsed call %s{call}"

        let kind, protocol =
            if m.Groups.[1].Value = "tcp" then
                SocketKind.Stream, SocketProtocol.Tcp
            else
                SocketKind.Datagram, SocketProtocol.Udp

        let fd, system = NewSocket.create SocketDomain.Inet kind protocol system
        let address = parseAddress m.Groups.[3].Value

        let answer, system =
            match m.Groups.[2].Value with
            | "bind" ->
                let endpoint = Ipv4Endpoint.ofParts address (UInt16.Parse m.Groups.[4].Value)

                match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform endpoint) system with
                | Ok (BindAnswer.Bound _, system) -> "OK", system
                | Ok (BindAnswer.Failed error, system) -> $"%A{error}", system
                | Error refusal -> failwith $"%s{call}: refused, %s{BindRefusal.describe refusal}"
            | _ ->
                let endpoint = Ipv4Endpoint.ofParts address listenerPort

                match CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet platform endpoint) system with
                | Ok (SyscallAnswer.Completed _, system) -> "OK", system
                | Ok (SyscallAnswer.Failed error, system) -> $"%A{error}", system
                | Error refusal -> failwith $"%s{call}: refused, %s{ConnectRefusal.describe refusal}"

        let port = portOf fd system
        $"%s{answer} port=%d{port}", close fd system

    [<Test>]
    let ``an unprivileged process's searches take the measured ports from a range below 1024`` () : unit =
        let rec replay (count : int) (lines : string list) : int =
            match lines with
            | [] -> count
            | header :: rest when handoutHeader.IsMatch header ->
                let m = handoutHeader.Match header

                let settings =
                    {
                        Range = UInt16.Parse m.Groups.[4].Value, UInt16.Parse m.Groups.[5].Value
                        Start = UInt16.Parse m.Groups.[6].Value
                    }

                let calls = rest |> List.takeWhile (fun line -> line.StartsWith "  ")
                let low, high = settings.Range

                ((handoutMachine settings), calls)
                ||> List.fold (fun system line ->
                    let call = Regex.Match (line, @"^  (.*) -> (\S+) port=(\d+)$")

                    if not call.Success then
                        system
                    else
                        let answered, system = handout call.Groups.[1].Value system
                        let measuredPort = UInt16.Parse call.Groups.[3].Value
                        let port = UInt16.Parse (answered.Split('=').[1])

                        // A range of two ports leaves the kernel's choice
                        // between them its own; the model's need only be one
                        // of them.
                        let portAgrees =
                            if low = high || call.Groups.[1].Value.EndsWith $":%d{measuredPort}" then
                                port = measuredPort
                            else
                                low <= port && port <= high

                        if answered.Split(' ').[0] <> call.Groups.[2].Value || not portAgrees then
                            failwith $"%s{header}\n%s{line}\n  model: %s{answered}"

                        system
                )
                |> ignore

                replay (count + 1) rest
            | _ :: rest -> replay count rest

        // Five rows: 1024-1024, 600-600, 600-601, 1-1 and 80-80.
        replay 0 (lines "local-port-range") |> shouldEqual 5
