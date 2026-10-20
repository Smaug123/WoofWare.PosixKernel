namespace WoofWare.PosixKernel.Test

open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The TIME_WAIT a TCP connection's first closer is left in once both of its
/// sockets have closed: what it holds, and from when.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestTimeWait =

    let private listenerPort : uint16 = 5000us

    let private platforms : SimulatedUnixPlatform list = Machines.platforms

    let private systemOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> UnixBootImage.tryWithEphemeralPortRange (40000us, 40003us)
        |> Configured.expectOk EphemeralPortRangeRefusal.describe
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A client connected to a listener at `listenerPort` and accepted, the
    /// client closed and then the accepted socket: the client's end made its
    /// FIN first. Answers the client's port.
    let private clientFirst (system : UnixSystem<int, string>) : uint16 * UnixSystem<int, string> =
        let listener, system = KeventWorld.listenerAt listenerPort system
        let client, system = KeventWorld.stream false system

        let system =
            match KeventWorld.connect client listenerPort system with
            | SyscallAnswer.Completed 0L, system -> system
            | other, _ -> failwith $"connect: %A{other}"

        let port =
            match FileDescriptorRegistry.tryFindTarget client (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
                | Some binding -> binding.Endpoint.Port
                | None -> failwith "the client is unbound"
            | other -> failwith $"the client is %A{other}"

        let accepted, system =
            match UnixConnection.tryAccept (Callers.thread 0 system) listener UserBuffer.Mapped 16u 0 system with
            | Ok (AcceptOutcome.Accepted (accepted, _, _), system) -> accepted, system
            | other -> failwith $"accept: %A{other}"

        let system = system |> KeventWorld.close client |> KeventWorld.close accepted
        port, system

    let private bindAnswer
        (reuse : bool)
        (endpoint : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : Result<BindAnswer, BindRefusal>
        =
        let fd, system = KeventWorld.stream false system
        let system = if reuse then ReuseAddress.set true fd system else system

        CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) endpoint) system
        |> Result.map fst

    /// `docs/probes/time-wait`, rows B: once both sockets have closed, the
    /// first closer's end is in TIME_WAIT, and a bind of its port carrying no
    /// `SO_REUSEADDR` is refused on both flavours.
    [<TestCaseSource(nameof platforms)>]
    let ``the first closer's port is held once both sockets have closed`` (platform : SimulatedUnixPlatform) : unit =
        let port, system = clientFirst (systemOn platform)

        bindAnswer false (Ipv4Endpoint.ofParts Ipv4Address.loopback port) system
        |> shouldEqual (Ok (BindAnswer.Failed UnixError.EADDRINUSE))

        bindAnswer false (Ipv4Endpoint.ofParts Ipv4Address.any port) system
        |> shouldEqual (Ok (BindAnswer.Failed UnixError.EADDRINUSE))

    /// A connection a reset has reached no longer occupies its four-tuple, so
    /// another connection may take that four-tuple and leave an end in
    /// TIME_WAIT on it while the reset one is still on the machine.
    [<Test>]
    let ``an end in TIME_WAIT beside a reset connection on its four-tuple is no defect`` () : unit =
        let system = systemOn SimulatedUnixPlatform.linuxX64
        let clientPort = 40100us
        let listener, system = KeventWorld.listenerAt listenerPort system

        let boundClient (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
            let fd, system = KeventWorld.stream false system
            let system = ReuseAddress.set true fd system
            let system = KeventWorld.bind fd clientPort system

            match KeventWorld.connect fd listenerPort system with
            | SyscallAnswer.Completed 0L, system -> fd, system
            | other, _ -> failwith $"connect from %d{clientPort}: %A{other}"

        // The first connection: its server closes over a byte it never read,
        // which resets the client.
        let accept (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
            match UnixConnection.tryAccept (Callers.thread 0 system) listener UserBuffer.Mapped 16u 0 system with
            | Ok (AcceptOutcome.Accepted (accepted, _, _), system) -> accepted, system
            | other -> failwith $"accept: %A{other}"

        let first, system = boundClient system
        let firstServer, system = accept system

        let system =
            match WriteOutcomes.writeBytes 0 first (System.Collections.Immutable.ImmutableArray.Create 1uy) system with
            | Ok (WriteStep.Returns (_, system)) -> system
            | other -> failwith $"write: %A{other}"

        let system = KeventWorld.close firstServer system

        // The second, on the same four-tuple, ended client first.
        let second, system = boundClient system
        let secondServer, system = accept system
        let system = system |> KeventWorld.close second |> KeventWorld.close secondServer

        (Kernel.machine system).TimeWaits
        |> Map.keys
        |> List.ofSeq
        |> shouldEqual
            [
                Ipv4Endpoint.ofParts Ipv4Address.loopback clientPort,
                Ipv4Endpoint.ofParts Ipv4Address.loopback listenerPort
            ]

        UnixSystem.checkInvariants system |> shouldEqual []

    let private loopbackAt (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private withTimeWait
        (timeWait : TcpTimeWait)
        (key : Ipv4Endpoint * Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        Kernel.mapMachine
            (fun machine ->
                { machine with
                    TimeWaits = Map.add key timeWait machine.TimeWaits
                }
            )
            system

    let private timeWaitAt (local : uint16) (remote : uint16) (enteredAt : int64) : TcpTimeWait =
        {
            Local = loopbackAt local
            Remote = loopbackAt remote
            ReuseAddress = false
            PortHold = PortHold.Connected
            SocketUid = UserId.root
            EnteredAt = enteredAt
        }

    let private advanced (nanoseconds : int64) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixSystem.advanceClock nanoseconds system

    let private acceptOn (listener : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixConnection.tryAccept (Callers.thread 0 system) listener UserBuffer.Mapped 16u 0 system with
        | Ok (AcceptOutcome.Accepted (accepted, _, _), system) -> accepted, system
        | other -> failwith $"accept: %A{other}"

    let private shutWrite (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixConnection.tryShutdown (Callers.leader system) fd 1 system with
        | Ok (ShutdownAnswer.Shut, system) -> system
        | other -> failwith $"shutdown: %A{other}"

    /// A client connected to a listener at `listenerPort`, and the socket
    /// that accepted it.
    let private connected (system : UnixSystem<int, string>) : int * int * UnixSystem<int, string> =
        let listener, system = KeventWorld.listenerAt listenerPort system
        let client, system = KeventWorld.stream false system

        let system =
            match KeventWorld.connect client listenerPort system with
            | SyscallAnswer.Completed 0L, system -> system
            | other, _ -> failwith $"connect: %A{other}"

        let accepted, system = acceptOn listener system
        client, accepted, system

    [<TestCaseSource(nameof platforms)>]
    let ``an end in TIME_WAIT from after the clock, or filed under another four-tuple, is a defect``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let system = systemOn platform |> advanced 5_000_000_000L
        let timeWait = timeWaitAt 40001us listenerPort 4_000_000_000L
        let key = timeWait.Local, timeWait.Remote

        withTimeWait timeWait key system |> UnixSystem.checkInvariants |> shouldEqual []

        withTimeWait
            { timeWait with
                SocketUid = UserId.root
                EnteredAt = 6_000_000_000L
            }
            key
            system
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.TimeWaitMisrecorded key ]

        let elsewhere = loopbackAt 40002us, timeWait.Remote

        withTimeWait timeWait elsewhere system
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.TimeWaitMisrecorded elsewhere ]

    [<TestCaseSource(nameof platforms)>]
    let ``an end in TIME_WAIT on a live connection's four-tuple is a defect, either way round``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let _, _, system = connected (systemOn platform)

        let connection, clientPort =
            match Map.toList (Kernel.machine system).Connections with
            | [ connection, tcp ] -> connection, tcp.ClientAddress.Port
            | other -> failwith $"connections: %A{other}"

        for local, remote in [ clientPort, listenerPort ; listenerPort, clientPort ] do
            let timeWait = timeWaitAt local remote 0L

            withTimeWait timeWait (timeWait.Local, timeWait.Remote) system
            |> UnixSystem.checkInvariants
            |> shouldEqual
                [
                    UnixSystemDefect.TimeWaitBesideConnection (timeWait.Local, timeWait.Remote, connection)
                ]

    [<TestCaseSource(nameof platforms)>]
    let ``another flavour's TIME_WAIT sysctls are a defect`` (platform : SimulatedUnixPlatform) : unit =
        let system = systemOn platform
        let flavour = SimulatedUnixPlatform.flavour platform

        let other =
            match flavour with
            | SimulatedUnixFlavour.Linux -> UnixMachineState.defaultTcpTimeWait SimulatedUnixFlavour.Darwin
            | SimulatedUnixFlavour.Darwin -> UnixMachineState.defaultTcpTimeWait SimulatedUnixFlavour.Linux

        Kernel.mapMachine
            (fun machine ->
                { machine with
                    TcpTimeWait = other
                }
            )
            system
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.TimeWaitSysctlsNotOfFlavour flavour ]

    /// A connection stamps when its FINs were exchanged as the second
    /// arrives, and not before.
    [<TestCaseSource(nameof platforms)>]
    let ``a stamp of the FINs' exchange that disagrees with the FINs is a defect``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let client, accepted, system =
            connected (systemOn platform |> advanced 3_000_000_000L)

        let connection = (Kernel.machine system).Connections |> Map.keys |> Seq.exactlyOne

        let stamped (stamp : int64 option) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            Kernel.mapMachine
                (fun machine ->
                    { machine with
                        Connections =
                            Map.change
                                connection
                                (Option.map (fun tcp ->
                                    { tcp with
                                        FinsExchangedAt = stamp
                                    }
                                ))
                                machine.Connections
                    }
                )
                system

        (Kernel.machine system).Connections.[connection].FinsExchangedAt
        |> shouldEqual None

        stamped (Some 1L) system
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.FinsExchangedAtDisagrees (connection, Some 1L) ]

        let system = system |> shutWrite client |> advanced 1_000_000L |> shutWrite accepted

        (Kernel.machine system).Connections.[connection].FinsExchangedAt
        |> shouldEqual (Some 3_001_000_000L)

        UnixSystem.checkInvariants system |> shouldEqual []

        stamped None system
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.FinsExchangedAtDisagrees (connection, None) ]

        stamped (Some 3_002_000_000L) system
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.FinsExchangedAtDisagrees (connection, Some 3_002_000_000L) ]

    /// The window counts from the exchange of FINs, not from the last close.
    [<TestCaseSource(nameof platforms)>]
    let ``an end enters TIME_WAIT when both FINs have arrived, though its sockets close later``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let client, accepted, system =
            connected (systemOn platform |> advanced 3_000_000_000L)

        let clientPort =
            (Seq.exactlyOne (Kernel.machine system).Connections.Values).ClientAddress.Port

        let system =
            system
            |> shutWrite client
            |> shutWrite accepted
            |> advanced 10_000_000_000L
            |> KeventWorld.close client
            |> KeventWorld.close accepted

        (Kernel.machine system).TimeWaits
        |> Map.toList
        |> List.map (fun (_, timeWait) -> timeWait.Local.Port, timeWait.EnteredAt)
        |> shouldEqual [ clientPort, 3_000_000_000L ]

    /// What is unmeasured about a connect over an end in TIME_WAIT is
    /// refused: under Linux, off loopback, and from a bound socket where the
    /// end entered TIME_WAIT in the first second of uptime.
    [<Test>]
    let ``a connect over an end in TIME_WAIT is refused off loopback and from the first second`` () : unit =
        let away (port : uint16) : Ipv4Endpoint =
            Ipv4Endpoint.ofParts (Ipv4Address 0x0A000001u) port

        let holder (local : Ipv4Endpoint) (remote : Ipv4Endpoint) (enteredAt : int64) : PortHolder =
            UnixMachineState.timeWaitHolder
                {
                    Local = local
                    Remote = remote
                    ReuseAddress = false
                    PortHold = PortHold.Connected
                    SocketUid = UserId.root
                    EnteredAt = enteredAt
                }

        let clock (flavour : SimulatedUnixFlavour) : TimeWaitClock =
            {
                Now = 5_000_000_000L
                Sysctls = UnixMachineState.defaultTcpTimeWait flavour
            }

        let linux = clock SimulatedUnixFlavour.Linux
        let offLoopback = holder (away 40001us) (away 5000us) 2_000_000_000L
        let onLoopback = holder (loopbackAt 40001us) (loopbackAt 5000us) 2_000_000_000L
        let fromBoot = holder (loopbackAt 40001us) (loopbackAt 5000us) 500_000_000L

        let search (holder : PortHolder) : PortVerdict =
            PortHolderRules.connectSearchVerdict
                SimulatedUnixFlavour.Linux
                linux
                SocketKind.Stream
                holder
                holder.Endpoint
                (Option.get holder.Peer)
                false

        search offLoopback
        |> shouldEqual (PortVerdict.Undetermined (TimeWaitRefusal.OffLoopback (away 40001us, away 5000us)))

        search onLoopback |> shouldEqual PortVerdict.Clear
        search fromBoot |> shouldEqual PortVerdict.InTheWay

        PortHolderRules.boundConnectOverTimeWait SimulatedUnixFlavour.Linux linux offLoopback
        |> shouldEqual (Error (TimeWaitRefusal.OffLoopback (away 40001us, away 5000us)))

        PortHolderRules.boundConnectOverTimeWait SimulatedUnixFlavour.Linux linux fromBoot
        |> shouldEqual (Error (TimeWaitRefusal.EnteredInFirstSecond (loopbackAt 40001us, loopbackAt 5000us)))

        PortHolderRules.boundConnectOverTimeWait SimulatedUnixFlavour.Linux linux onLoopback
        |> shouldEqual (Ok TimeWaitTakeover.TakesOver)

        PortHolderRules.boundConnectOverTimeWait
            SimulatedUnixFlavour.Darwin
            (clock SimulatedUnixFlavour.Darwin)
            offLoopback
        |> shouldEqual (Ok TimeWaitTakeover.AddressInUse)

    let private lingerZero (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let platform = UnixSystem.platform system
        let level = SimulatedUnixPlatform.socketOptionLevel platform

        let name =
            match SimulatedUnixPlatform.lingerSecondsOption platform with
            | Some name -> name
            | None -> SimulatedUnixPlatform.lingerOption platform

        let value = OptionValue.ofLinger 1 0

        match
            Lone.UnixSocket.trySetsockoptBytes fd level name UserBuffer.Mapped (uint32 value.Length) (Some value) system
        with
        | Ok (SetSockOptAnswer.Set, system) -> system
        | other -> failwith $"SO_LINGER on fd %d{fd}: %A{other}"

    /// Section L of `tcp-shutdown.c` (docs/plans/2026-10-08-tcp-shutdown-linger):
    /// once both FINs have arrived, a close under `SO_LINGER` {1, 0} is the
    /// ordinary close, and Linux then holds the closer's endpoint by the
    /// ordinary rule where Darwin frees it whichever FIN came first. So the
    /// end whose FIN came first is left in TIME_WAIT on Linux alone, whether
    /// its socket closes before its peer's or after.
    [<TestCaseSource(nameof platforms)>]
    let ``a close under SO_LINGER zero once both FINs have arrived leaves TIME_WAIT on Linux alone``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let expected =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> 1
            | SimulatedUnixFlavour.Darwin -> 0

        for abortiveFirst in [ true ; false ] do
            let client, accepted, system =
                connected (systemOn platform |> advanced 3_000_000_000L)

            // Darwin takes no linger once both sides are shut, so it is set
            // first.
            let system = system |> lingerZero client |> shutWrite client |> shutWrite accepted

            let system =
                if abortiveFirst then
                    system |> KeventWorld.close client |> KeventWorld.close accepted
                else
                    system |> KeventWorld.close accepted |> KeventWorld.close client

            (Kernel.machine system).Connections |> shouldEqual Map.empty
            (Kernel.machine system).TimeWaits.Count |> shouldEqual expected

    /// Linux's `listen(2)` asks `bind(2)`'s question again (`relisten-held.c`
    /// in docs/plans/2026-10-08-tcp-shutdown-linger), so a socket that bound
    /// beside an end in TIME_WAIT, both carrying `SO_REUSEADDR`, and then
    /// dropped the flag meets the end at its listen: `EADDRINUSE` within the
    /// window, and refused past it.
    [<Test>]
    let ``Linux's listen meets an end in TIME_WAIT as a bind would`` () : unit =
        for after in [ 2_000_000_000L ; 61_000_000_000L ] do
            let system = systemOn SimulatedUnixPlatform.linuxX64
            let listener, system = KeventWorld.listenerAt listenerPort system
            let client, system = KeventWorld.stream false system
            let system = ReuseAddress.set true client system

            let system =
                match KeventWorld.connect client listenerPort system with
                | SyscallAnswer.Completed 0L, system -> system
                | other, _ -> failwith $"connect: %A{other}"

            let clientPort =
                (Seq.exactlyOne (Kernel.machine system).Connections.Values).ClientAddress.Port

            let accepted, system = acceptOn listener system

            let system =
                system
                |> KeventWorld.close client
                |> KeventWorld.close accepted
                |> advanced after

            let fd, system = KeventWorld.stream false system
            let system = ReuseAddress.set true fd system |> KeventWorld.bind fd clientPort
            let system = ReuseAddress.set false fd system

            match UnixSocket.tryListen (Callers.leader system) fd 8 system, after < 60_000_000_000L with
            | Ok (ListenAnswer.Failed UnixError.EADDRINUSE, _), true -> ()
            | Error (ListenRefusal.TimeWait (TimeWaitRefusal.OutlivedWindow _)), false -> ()
            | other, _ -> failwith $"%d{after} ns on, listen answered %A{other}"

    /// `docs/probes/time-wait`, tw-reuse.c rows V: Darwin's connect from a
    /// socket bound at the wildcard and the port of an end in TIME_WAIT
    /// towards the destination answers `EADDRINUSE`, and the socket stays
    /// bound at the wildcard. Darwin meets the end as `in_pcbconnect` looks
    /// the four-tuple up, before any SYN, so the answer is the same where
    /// nothing listens at the destination.
    [<Test>]
    let ``Darwin's connect over an end in TIME_WAIT keeps a wildcard binding where nothing listens`` () : unit =
        let platform = SimulatedUnixPlatform.macOsArm64
        let system = systemOn platform
        let listener, system = KeventWorld.listenerAt listenerPort system
        let client, system = KeventWorld.stream false system

        let system =
            match KeventWorld.connect client listenerPort system with
            | SyscallAnswer.Completed 0L, system -> system
            | other, _ -> failwith $"connect: %A{other}"

        let clientPort =
            (Seq.exactlyOne (Kernel.machine system).Connections.Values).ClientAddress.Port

        let accepted, system = acceptOn listener system

        let system =
            system
            |> KeventWorld.close client
            |> KeventWorld.close accepted
            |> KeventWorld.close listener

        let fd, system = KeventWorld.stream false system
        let system = ReuseAddress.set true fd system
        let wildcard = Ipv4Endpoint.ofParts Ipv4Address.any clientPort

        let system =
            match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform wildcard) system with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let system =
            match KeventWorld.connect fd listenerPort system with
            | SyscallAnswer.Failed UnixError.EADDRINUSE, system -> system
            | other, _ -> failwith $"connect: %A{other}"

        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) ->
            (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding
            |> Option.map (fun binding -> binding.Endpoint)
            |> shouldEqual (Some wildcard)
        | other -> failwith $"fd %d{fd} is %A{other}"

    /// A dual-mode socket's bind of a v4-mapped address meets an end in
    /// TIME_WAIT as an IPv4 socket's bind does: `EADDRINUSE` within the
    /// window, and refused past it.
    [<TestCaseSource(nameof platforms)>]
    let ``a dual-mode bind meets an end in TIME_WAIT as an IPv4 bind does`` (platform : SimulatedUnixPlatform) : unit =
        let port, system = clientFirst (systemOn platform)

        for after in [ 2_000_000_000L ; 61_000_000_000L ] do
            let fd, system =
                NewSocket.create SocketDomain.Inet6 SocketKind.Stream SocketProtocol.Tcp (advanced after system)

            let level = SimulatedUnixPlatform.ipv6OptionLevel platform
            let name = SimulatedUnixPlatform.ipv6OnlyOption platform

            let off =
                Some (
                    System.Collections.Immutable.ImmutableArray.CreateRange (
                        SimulatedUnixPlatform.encodeCInt platform 0
                    )
                )

            let system =
                match Lone.UnixSocket.trySetsockoptBytes fd level name UserBuffer.Mapped 4u off system with
                | Ok (SetSockOptAnswer.Set, system) -> system
                | other -> failwith $"IPV6_V6ONLY: %A{other}"

            match
                CopyIn.bind fd UserBuffer.Mapped 28u (CopyIn.inet6Mapped platform (loopbackAt port)) system,
                after < 30_000_000_000L
            with
            | Ok (BindAnswer.Failed UnixError.EADDRINUSE, _), true -> ()
            | Error (BindRefusal.TimeWait (TimeWaitRefusal.OutlivedWindow _)), false -> ()
            | other, _ -> failwith $"%d{after} ns on, bind answered %A{other |> Result.map fst}"
