namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixSocket.listen`.
///
/// It takes no buffer and has no caller-side screens of its own, so unlike `bind` there
/// is nothing here that belongs to a caller: every row is `listen(2)`. The two
/// that only this tier can reach are the re-screen, which one flavour performs
/// and the other does not, and the implicit bind's exhaustion.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestListen =

    let private context : string = "TestListen"

    let private epoch : UnixTimestamp = UnixTimestamp.ofMillisecondsSinceEpoch 0L

    /// A simulated process on the flavour asked for, before anything has
    /// happened to it.
    let private systemOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)


    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private socketWith
        (kind : SocketKind)
        (binding : Ipv4Binding option)
        (reuse : bool)
        (phase : SocketPhase)
        : SocketDescription
        =
        {
            Addressing = SocketAddressing.Inet binding
            Kind = kind
            Protocol =
                if kind = SocketKind.Stream then
                    SocketProtocol.Tcp
                else
                    SocketProtocol.Udp
            ReuseAddress = reuse
            Options = SocketOptions.initial
            Phase = phase
            Uid = UserId.root
        }

    let private withSocket
        (socketId : SocketId)
        (socket : SocketDescription)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let fd, registry =
            FileDescriptorRegistry.createSocket
                (SimulatedUnixPlatform.flavour (UnixSystem.platform system))
                socketId
                (Lone.fileDescriptors system)

        let (SocketId raw) = socketId
        let (SocketId next) = (Kernel.machine system).NextSocketId

        fd,
        Kernel.mapMachine
            (fun machine ->
                { machine with
                    Sockets = Map.add socketId socket machine.Sockets
                    NextSocketId = SocketId (max next (raw + 1L))
                }
            )
            system
        |> Lone.withFileDescriptors registry

    let private boundAt (endpoint : Ipv4Endpoint) : Ipv4Binding option =
        Some
            {
                Endpoint = endpoint
                LockedAddress = Some endpoint.Address
                LockedPort = true
                PortHold = PortHold.Reserved
            }

    let private listenOrFail (fd : int) (backlog : int) (system : UnixSystem<int, string>) =
        match UnixSocket.tryListen (Callers.leader system) fd backlog system with
        | Ok result -> result
        | Error refusal -> failwith $"expected an answer, got a refusal: %s{ListenRefusal.describe refusal}"

    let private phaseOf (socketId : SocketId) (system : UnixSystem<int, string>) : SocketPhase =
        (UnixMachineState.socket socketId (Kernel.machine system)).Phase

    // ------------------------------------------------------------------
    // The happy path
    // ------------------------------------------------------------------

    [<TestCaseSource(nameof platforms)>]
    let ``a bound socket listens where it is bound`` (platform : SimulatedUnixPlatform) : unit =
        let fd, system =
            withSocket
                (SocketId 0L)
                (socketWith SocketKind.Stream (boundAt (loopback 5000us)) false SocketPhase.Idle)
                (systemOn platform)

        let answer, system = listenOrFail fd 8 system

        answer
        |> shouldEqual (ListenAnswer.Listening (SocketAddress.Inet (loopback 5000us)))

        match phaseOf (SocketId 0L) system with
        | SocketPhase.Listening listenState ->
            listenState.Backlog |> shouldEqual 8
            listenState.Queue |> shouldEqual []
        | other -> failwith $"expected Listening, got %A{other}"

    /// `listen(2)` on an unbound socket binds it to the wildcard and an
    /// ephemeral port. Measured on both — and note it does *not* go through
    /// `bind(2)`, so nothing is locked and no `SO_REUSEADDR` is set, both of
    /// which a later bind can see.
    [<TestCaseSource(nameof platforms)>]
    let ``an unbound socket is bound to the wildcard`` (platform : SimulatedUnixPlatform) : unit =
        let fd, system =
            withSocket (SocketId 0L) (socketWith SocketKind.Stream None false SocketPhase.Idle) (systemOn platform)

        let answer, system = listenOrFail fd 8 system

        let where =
            match answer with
            | ListenAnswer.Listening (SocketAddress.Inet where) -> where
            | other -> failwith $"expected an IPv4 listen, got %A{other}"

        where.Address |> shouldEqual Ipv4Address.any

        let low, high = UnixSystem.ephemeralPortRange system
        (where.Port >= low && where.Port <= high) |> shouldEqual true

        let socket = UnixMachineState.socket (SocketId 0L) (Kernel.machine system)

        socket.Ipv4Binding
        |> shouldEqual (
            Some
                {
                    Endpoint = where
                    LockedAddress = None
                    LockedPort = false
                    PortHold = PortHold.Reserved
                }
        )

        socket.ReuseAddress |> shouldEqual false

    /// Every backlog is accepted — measured, 0, -1 and INT_MAX all succeed on
    /// both — and the number is stored verbatim, because the accept-queue
    /// capacity a later connect enforces is derived from it per flavour.
    [<TestCaseSource(nameof platforms)>]
    let ``every backlog is accepted and stored verbatim`` (platform : SimulatedUnixPlatform) : unit =
        for backlog in [ 0 ; -1 ; System.Int32.MaxValue ; System.Int32.MinValue ] do
            let fd, system =
                withSocket
                    (SocketId 0L)
                    (socketWith SocketKind.Stream (boundAt (loopback 5000us)) false SocketPhase.Idle)
                    (systemOn platform)

            let _, system = listenOrFail fd backlog system

            match phaseOf (SocketId 0L) system with
            | SocketPhase.Listening listenState -> listenState.Backlog |> shouldEqual backlog
            | other -> failwith $"expected Listening, got %A{other}"

    /// A re-listen keeps the queue and updates the backlog, which is Linux's
    /// documented behaviour: `sk_max_ack_backlog` is simply re-assigned.
    [<TestCaseSource(nameof platforms)>]
    let ``a re-listen keeps the queue and updates the backlog`` (platform : SimulatedUnixPlatform) : unit =
        let queued = [ ConnectionId 7L ]

        let fd, system =
            withSocket
                (SocketId 0L)
                (socketWith
                    SocketKind.Stream
                    (boundAt (loopback 5000us))
                    false
                    (SocketPhase.Listening
                        {
                            Backlog = 8
                            Queue = List.map ForgedConnection.queued queued
                            Drained = false
                        }))
                (systemOn platform)

        let _, system = listenOrFail fd 64 system

        match phaseOf (SocketId 0L) system with
        | SocketPhase.Listening listenState ->
            listenState.Backlog |> shouldEqual 64
            ListenState.connections listenState |> shouldEqual queued
        | other -> failwith $"expected Listening, got %A{other}"

    // ------------------------------------------------------------------
    // Errnos
    // ------------------------------------------------------------------

    [<TestCaseSource(nameof platforms)>]
    let ``a descriptor that is not open is EBADF`` (platform : SimulatedUnixPlatform) : unit =
        listenOrFail 99 8 (systemOn platform)
        |> fst
        |> shouldEqual (ListenAnswer.Failed UnixError.EBADF)

    [<TestCaseSource(nameof platforms)>]
    let ``a descriptor that is not a socket is ENOTSOCK`` (platform : SimulatedUnixPlatform) : unit =
        let system = systemOn platform

        let fileFd, registry =
            FileDescriptorRegistry.openFile
                (DescriptorFlags.none (SimulatedUnixPlatform.flavour (UnixSystem.platform system)))
                (OpenFileStatus.none (SimulatedUnixPlatform.flavour (UnixSystem.platform system)))
                false
                (ForgedName.ofInode system (InodeNumber 1L))
                (InodeNumber 1L)
                FileAccessMode.ReadOnly
                (Lone.fileDescriptors system)

        let queueFd, registry =
            FileDescriptorRegistry.createEpoll SimulatedUnixFlavour.Linux registry

        let system = Lone.withFileDescriptors registry system

        for fd in [ 0 ; fileFd ; queueFd ] do
            listenOrFail fd 8 system
            |> fst
            |> shouldEqual (ListenAnswer.Failed UnixError.ENOTSOCK)

    [<TestCaseSource(nameof platforms)>]
    let ``a datagram socket is EOPNOTSUPP`` (platform : SimulatedUnixPlatform) : unit =
        let fd, system =
            withSocket
                (SocketId 0L)
                (socketWith SocketKind.Datagram (boundAt (loopback 5000us)) false SocketPhase.Idle)
                (systemOn platform)

        listenOrFail fd 8 system
        |> fst
        |> shouldEqual (ListenAnswer.Failed UnixError.EOPNOTSUPP)

    // ------------------------------------------------------------------
    // The re-screen, which is the flavour split
    // ------------------------------------------------------------------

    /// On Linux two sockets carrying `SO_REUSEADDR` may share an endpoint right
    /// up until one of them listens, and the second `listen(2)` is then
    /// EADDRINUSE — `inet_csk_listen_start` calls `get_port` a second time.
    /// Darwin's `tcp_usr_listen` asks nothing of a socket that already has a
    /// port, so the same pair listens happily.
    [<Test>]
    let ``the binding re-screen is one flavour's only`` () : unit =
        let rows =
            [
                SimulatedUnixPlatform.linuxX64, Some UnixError.EADDRINUSE
                SimulatedUnixPlatform.macOsArm64, None
            ]

        for platform, expected in rows do
            // Two reuse-carrying sockets at the same endpoint, which `bind(2)`
            // admitted on both flavours — and the *first* has already listened.
            // That last part is the whole scenario: Linux's relaxation holds
            // only while nothing listens, so a pair that both merely bound does
            // not conflict, and it is the second `listen` that finds one.
            let _, system =
                withSocket
                    (SocketId 0L)
                    (socketWith
                        SocketKind.Stream
                        (boundAt (loopback 5000us))
                        true
                        (SocketPhase.Listening
                            {
                                Backlog = 8
                                Queue = []
                                Drained = false
                            }))
                    (systemOn platform)

            let second, system =
                withSocket
                    (SocketId 1L)
                    (socketWith SocketKind.Stream (boundAt (loopback 5000us)) true SocketPhase.Idle)
                    system

            match listenOrFail second 8 system |> fst, expected with
            | ListenAnswer.Failed error, Some expected -> error |> shouldEqual expected
            | ListenAnswer.Listening (SocketAddress.Inet where), None -> where |> shouldEqual (loopback 5000us)
            | answer, expected -> failwith $"platform %O{platform}: got %A{answer}, expected %A{expected}"

    /// ...and the re-screen is not "any second listener": a socket alone at its
    /// endpoint listens on both flavours, so the row above is about the conflict
    /// rather than about listening twice. Nor does a pair that has merely
    /// *bound* conflict — Linux's relaxation holds until one of them listens,
    /// which is the row below.
    [<TestCaseSource(nameof platforms)>]
    let ``a socket alone at its endpoint always listens`` (platform : SimulatedUnixPlatform) : unit =
        let fd, system =
            withSocket
                (SocketId 0L)
                (socketWith SocketKind.Stream (boundAt (loopback 5000us)) true SocketPhase.Idle)
                (systemOn platform)

        listenOrFail fd 8 system
        |> fst
        |> shouldEqual (ListenAnswer.Listening (SocketAddress.Inet (loopback 5000us)))

    /// The other half of Linux's rule: while *neither* socket listens, two
    /// reuse-carrying bindings at one endpoint coexist, and the first `listen`
    /// finds no conflict. Without this row the one above would pass for a rule
    /// that refused any duplicate binding at all.
    [<Test>]
    let ``the first listener of a reuse-carrying pair is admitted`` () : unit =
        for platform in platforms do
            let _, system =
                withSocket
                    (SocketId 0L)
                    (socketWith SocketKind.Stream (boundAt (loopback 5000us)) true SocketPhase.Idle)
                    (systemOn platform)

            let first, system =
                withSocket
                    (SocketId 1L)
                    (socketWith SocketKind.Stream (boundAt (loopback 5000us)) true SocketPhase.Idle)
                    system

            listenOrFail first 8 system
            |> fst
            |> shouldEqual (ListenAnswer.Listening (SocketAddress.Inet (loopback 5000us)))

    // ------------------------------------------------------------------
    // Refusals
    // ------------------------------------------------------------------

    [<TestCaseSource(nameof platforms)>]
    let ``a socket in an unmodelled domain is refused`` (platform : SimulatedUnixPlatform) : unit =
        for domain, refusal in
            [
                SocketDomain.Inet6, ListenRefusal.Ipv6Listener (SocketId 0L)
                SocketDomain.Unix, ListenRefusal.UnmodelledDomain (SocketId 0L, SocketDomain.Unix)
            ] do
            let socket =
                { socketWith SocketKind.Stream None false SocketPhase.Idle with
                    Addressing = SocketAddressing.initial domain false
                }

            let fd, system = withSocket (SocketId 0L) socket (systemOn platform)

            UnixSocket.tryListen (Callers.leader system) fd 8 system
            |> shouldEqual (Error refusal)

    [<TestCaseSource(nameof platforms)>]
    let ``a socket of an unmeasured kind is refused`` (platform : SimulatedUnixPlatform) : unit =
        for kind in [ SocketKind.SeqPacket ] do
            let fd, system =
                withSocket (SocketId 0L) (socketWith kind None false SocketPhase.Idle) (systemOn platform)

            UnixSocket.tryListen (Callers.leader system) fd 8 system
            |> shouldEqual (Error (ListenRefusal.UnmeasuredKind (SocketId 0L, kind)))

    /// Only `Idle`, `Listening` and `Refused` have measured answers; the rest
    /// are refused rather than guessed at, EISCONN for a connected socket being
    /// only plausible.
    [<TestCaseSource(nameof platforms)>]
    let ``a stream socket in an unmeasured phase is refused`` (platform : SimulatedUnixPlatform) : unit =
        let phases =
            [
                SocketPhase.EstablishedPendingReport (ConnectionId 7L)
                SocketPhase.Established (ConnectionId 7L, ConnectionEnd.Client)
                SocketPhase.Established (ConnectionId 7L, ConnectionEnd.Server)
                SocketPhase.DatagramPeer (SocketAddress.Inet (loopback 9000us))
            ]

        for phase in phases do
            let fd, system =
                withSocket
                    (SocketId 0L)
                    (socketWith SocketKind.Stream (boundAt (loopback 5000us)) false phase)
                    (systemOn platform)

            UnixSocket.tryListen (Callers.leader system) fd 8 system
            |> shouldEqual (Error (ListenRefusal.UnmeasuredPhase (SocketId 0L, phase)))

    /// A socket whose connect was refused answers EINVAL, whether or not the
    /// refusal has been reported, on both flavours (measured,
    /// `docs/probes/refused-connect-port`, the rows ending in 3).
    [<TestCaseSource(nameof platforms)>]
    let ``a refused socket's listen is EINVAL`` (platform : SimulatedUnixPlatform) : unit =
        for error in [ RefusalError.Pending ; RefusalError.Reported ] do
            let fd, system =
                withSocket
                    (SocketId 0L)
                    (socketWith SocketKind.Stream (boundAt (loopback 5000us)) false (SocketPhase.Refused error))
                    (systemOn platform)

            match UnixSocket.tryListen (Callers.leader system) fd 8 system with
            | Ok (answer, after) ->
                answer |> shouldEqual (ListenAnswer.Failed UnixError.EINVAL)
                after |> shouldEqual system
            | Error refusal -> failwith $"%A{error}: refused %A{refusal}"

    /// A Linux socket whose refused connect gave its port back listens at a
    /// port of its own choosing, as one with none would (measured,
    /// `docs/probes/refused-connect-port`, row Ib3), so another socket having
    /// since bound the port it gave back is nothing to it: the screen Linux's
    /// listen makes of a binding is of the port it chooses.
    [<Test>]
    let ``a Linux socket that gave its port back listens beside whoever took it`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64
        let given = Ipv4Endpoint.ofParts Ipv4Address.any 40000us

        let givenBack =
            Some
                {
                    Endpoint = given
                    LockedAddress = None
                    LockedPort = false
                    PortHold = PortHold.GivenBack
                }

        let fd, system =
            withSocket (SocketId 0L) (socketWith SocketKind.Stream givenBack false SocketPhase.Idle) (systemOn platform)

        let _, system =
            withSocket
                (SocketId 1L)
                (socketWith SocketKind.Stream (boundAt (loopback 40000us)) false SocketPhase.Idle)
                system

        match UnixSocket.tryListen (Callers.leader system) fd 8 system with
        | Ok (ListenAnswer.Listening (SocketAddress.Inet endpoint), after) ->
            endpoint.Address |> shouldEqual Ipv4Address.any
            endpoint.Port |> shouldNotEqual 40000us
            UnixSystem.checkInvariants after |> shouldEqual []
        | other -> failwith $"listen answered %A{other}"

    /// The kind screen precedes the phase screen: a *datagram* socket in one of
    /// those phases is answered EOPNOTSUPP rather than refused, which is what
    /// keeps `DatagramPeer` from being a refusal for the sockets that legitimately
    /// hold it.
    [<TestCaseSource(nameof platforms)>]
    let ``a datagram peer is answered rather than refused`` (platform : SimulatedUnixPlatform) : unit =
        let fd, system =
            withSocket
                (SocketId 0L)
                (socketWith
                    SocketKind.Datagram
                    None
                    false
                    (SocketPhase.DatagramPeer (SocketAddress.Inet (loopback 9000us))))
                (systemOn platform)

        listenOrFail fd 8 system
        |> fst
        |> shouldEqual (ListenAnswer.Failed UnixError.EOPNOTSUPP)

    /// The implicit bind can run out of ports: Linux answers EADDRINUSE,
    /// leaving the socket unbound (measured, `docs/probes/ephemeral-search`,
    /// the rows ending in Lsr). Darwin answers EADDRNOTAVAIL, but this
    /// library's search can pass over a port Darwin's would take, so it
    /// refuses.
    [<TestCaseSource(nameof platforms)>]
    let ``an exhausted ephemeral range is answered under Linux and refused under Darwin``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let system = systemOn platform

        let system =
            Kernel.mapMachine
                (fun machine ->
                    { machine with
                        EphemeralPortRange = (40000us, 40000us)
                        NextEphemeralPort = 40000us
                    }
                )
                system

        // A socket already holding the only port in the range, at the wildcard
        // so that the implicit bind's candidate collides with it.
        let _, system =
            withSocket
                (SocketId 1L)
                (socketWith
                    SocketKind.Stream
                    (Some
                        {
                            Endpoint = Ipv4Endpoint.ofParts Ipv4Address.any 40000us
                            LockedAddress = None
                            LockedPort = false
                            PortHold = PortHold.Reserved
                        })
                    false
                    SocketPhase.Idle)
                system

        let fd, system =
            withSocket (SocketId 0L) (socketWith SocketKind.Stream None false SocketPhase.Idle) system

        let expected =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> Ok (ListenAnswer.Failed UnixError.EADDRINUSE, system)
            | SimulatedUnixFlavour.Darwin -> Error (ListenRefusal.EphemeralPortsExhausted (40000us, 40000us))

        UnixSocket.tryListen (Callers.leader system) fd 8 system |> shouldEqual expected
