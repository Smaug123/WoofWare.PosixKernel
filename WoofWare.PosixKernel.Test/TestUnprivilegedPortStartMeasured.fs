namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which ports an unprivileged process binds under each value of Linux's
/// `net.ipv4.ip_unprivileged_port_start`, replayed from
/// `docs/probes/unprivileged-port-start`; and Darwin, which has no such
/// setting, refusing one.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnprivilegedPortStartMeasured =

    let private lines () : string list =
        let name = "WoofWare.PosixKernel.Test.unprivileged-port-start.linux.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    let private unprivileged : Credentials =
        Credentials.ofIds
            (UserId.parseOrFail "TestUnprivilegedPortStartMeasured" 1000u)
            (GroupId.parseOrFail "TestUnprivilegedPortStartMeasured" 1000u)
            []

    /// A Linux machine whose unprivileged port start is `start`, its range at
    /// the default, with a process of uid 1000.
    let private machine (start : uint16) : UnixSystem<int, string> =
        UnixSystem.initial SimulatedUnixPlatform.linuxX64
        |> UnixBootImage.tryWithUnprivilegedPortStart start
        |> Configured.expectOk UnprivilegedPortStartRefusal.describe
        |> Launched.bootWith (Launched.credentials unprivileged) UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"closing fd %d{fd}: %A{other}"

    /// What a bind of `port` from a fresh socket of the probe's `kind`
    /// answers, as the probe prints it; and the system with the socket closed.
    let private bindOne (kind : string) (port : uint16) (system : UnixSystem<int, string>) =
        let platform = system.Machine.UnixPlatform

        let domain, socketKind, protocol, blob, length =
            match kind with
            | "v4 stream 0.0.0.0" ->
                SocketDomain.Inet,
                SocketKind.Stream,
                SocketProtocol.Tcp,
                CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.any port),
                16u
            | "v4 stream 127.0.0.1" ->
                SocketDomain.Inet,
                SocketKind.Stream,
                SocketProtocol.Tcp,
                CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port),
                16u
            | "v4 dgram 0.0.0.0" ->
                SocketDomain.Inet,
                SocketKind.Datagram,
                SocketProtocol.Udp,
                CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.any port),
                16u
            | "v4 dgram 127.0.0.1" ->
                SocketDomain.Inet,
                SocketKind.Datagram,
                SocketProtocol.Udp,
                CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port),
                16u
            | "v6 stream ::ffff:127.0.0.1" ->
                SocketDomain.Inet6,
                SocketKind.Stream,
                SocketProtocol.Tcp,
                CopyIn.inet6Mapped platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port),
                28u
            | other -> failwith $"unknown socket kind %s{other}"

        let fd, system = NewSocket.create domain socketKind protocol system

        let answer, system =
            match CopyIn.bind fd UserBuffer.Mapped length blob system with
            | Ok (BindAnswer.Bound _, system) -> "OK", system
            | Ok (BindAnswer.Failed error, system) -> $"%A{error}", system
            | Error refusal -> $"refused (%s{BindRefusal.describe refusal})", system

        answer, close fd system

    let private bindRow : Regex =
        Regex @"^  S=(\d+) uid=1000 (v[46] (?:stream|dgram) \S+) (.*)$"

    [<Test>]
    let ``an unprivileged Linux bind is EACCES exactly below the unprivileged port start`` () : unit =
        let mutable replayed = 0

        for line in lines () do
            let m = bindRow.Match line

            if m.Success then
                let start = UInt16.Parse m.Groups.[1].Value
                let kind = m.Groups.[2].Value

                (machine start, m.Groups.[3].Value.Split ' ')
                ||> Array.fold (fun system cell ->
                    match cell.Split '=' with
                    | [| port ; measured |] ->
                        let answer, system = bindOne kind (UInt16.Parse port) system

                        if answer <> measured then
                            failwith $"%s{line}\n  port %s{port}: the model answered %s{answer}"

                        replayed <- replayed + 1
                        system
                    | _ -> failwith $"unparsed cell %s{cell} in %s{line}"
                )
                |> ignore

        // Eight settings, five kinds of socket, fourteen ports.
        replayed |> shouldEqual (8 * 5 * 14)

    [<Test>]
    let ``the unprivileged port start defaults to 1024, as measured`` () : unit =
        lines ()
        |> List.exists (fun line -> line = "defaults: range=32768 60999 unprivileged_start=1024")
        |> shouldEqual true

        UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> UnixSystem.unprivilegedPortStart
        |> shouldEqual UnixSystem.defaultUnprivilegedPortStart

        UnixSystem.defaultUnprivilegedPortStart |> shouldEqual 1024us

    /// Darwin has no `ip_unprivileged_port_start`: no
    /// `net.inet.ip.portrange.reservedlow` or `reservedhigh`
    /// (`docs/probes/privileged-port`), and its privileged ports end at 1024.
    [<Test>]
    let ``Darwin refuses an unprivileged port start, having no such setting`` () : unit =
        let image = UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64

        for start in [ 0us ; 1023us ; 1024us ; 1025us ; UInt16.MaxValue ] do
            match UnixBootImage.tryWithUnprivilegedPortStart start image with
            | Error refusal ->
                refusal
                |> shouldEqual (UnprivilegedPortStartRefusal.NoSuchSetting SimulatedUnixFlavour.Darwin)

                match UnprivilegedPortStartRefusal.kind refusal with
                | RefusalKind.Contradictory _ -> ()
                | other -> failwith $"refused as %A{other}"
            | Ok _ -> failwith $"Darwin took an unprivileged port start of %d{start}"

        image
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> UnixSystem.unprivilegedPortStart
        |> shouldEqual 1024us
