namespace WoofWare.PosixKernel

/// What a port holder is, as the rules over port holders ask.
[<RequireQualifiedAccess>]
type internal PortHolderKind =
    /// An open socket that is bound and neither listening, connected nor
    /// refused: an idle stream socket, or a datagram socket with or without a
    /// default peer.
    | Idle
    /// An open stream socket whose connect was refused.
    | Refused
    /// A listening socket.
    | Listener
    /// One end of a TCP connection: a connected socket, an end whose socket
    /// has closed, or a server end waiting in an accept queue.
    | ConnectionEnd

/// How a port holder holds its endpoint's port against a bind and a search
/// for an ephemeral port.
[<RequireQualifiedAccess>]
type internal PortClaim =
    /// Outright, as a binding `bind(2)` or `listen(2)` made does
    /// (`PortHold.Reserved`).
    | Reserved
    /// For its connection's four-tuple, as a binding a stream connect's own
    /// implicit bind made does (`PortHold.Connected`).
    | Connected
    /// Against nothing: its refused connect gave the port back, its
    /// connection is done with the endpoint, or it is a server end in an
    /// accept queue, whose listener holds the port. It can still occupy a
    /// four-tuple.
    | Released

[<RequireQualifiedAccess>]
module internal PortClaim =
    /// The claim of a binding that holds its port by `hold`.
    let ofPortHold (hold : PortHold) : PortClaim =
        match hold with
        | PortHold.Reserved -> PortClaim.Reserved
        | PortHold.Connected -> PortClaim.Connected
        | PortHold.GivenBack -> PortClaim.Released

/// Something on the machine that holds a port, a TCP four-tuple, or both,
/// against a `bind(2)`, a `listen(2)`, a search for an ephemeral port, or a
/// `connect(2)`: a bound socket, or one end of a TCP connection, with or
/// without a socket.
type internal PortHolder =
    {
        /// The endpoint whose port it holds.
        Endpoint : Ipv4Endpoint
        /// What it is.
        Kind : PortHolderKind
        /// How it holds `Endpoint`'s port.
        Claim : PortClaim
        /// The `SO_REUSEADDR` it holds the port with: a socket's as it stands,
        /// and a connection end's whose socket has closed as that socket
        /// carried it when it closed.
        ReuseAddress : bool
        /// The other end's endpoint, if it is a TCP connection's end and no
        /// reset has reached the connection: it occupies the four-tuple from
        /// `Endpoint` to there.
        Peer : Ipv4Endpoint option
    }

/// How each flavour judges a port, or a four-tuple, against one port holder:
/// whether the holder stands in the way of a `bind(2)`, a `listen(2)`, a
/// search for an ephemeral port, or a `connect(2)`. A question about the
/// machine asks every holder (`UnixMachineState.portHolders`), and a port is
/// in the way if any holder stands there.
[<RequireQualifiedAccess>]
module internal PortHolderRules =

    /// Whether `holder` holds its endpoint's port at all.
    let holdsPort (holder : PortHolder) : bool =
        match holder.Claim with
        | PortClaim.Reserved
        | PortClaim.Connected -> true
        | PortClaim.Released -> false

    /// Whether `holder` holds `port`.
    let private holdsAt (holder : PortHolder) (port : uint16) : bool =
        holdsPort holder && holder.Endpoint.Port = port

    /// Whether `holder` holds `endpoint`'s port at an address overlapping
    /// `endpoint`'s.
    let private holdsOver (holder : PortHolder) (endpoint : Ipv4Endpoint) : bool =
        holdsAt holder endpoint.Port
        && Ipv4Endpoint.addressesOverlap holder.Endpoint endpoint

    /// Whether `holder` occupies the four-tuple from `source` to
    /// `destination`, as the end at `source`. The connection's other end
    /// occupies it the other way round.
    let occupiesFourTuple (holder : PortHolder) (source : Ipv4Endpoint) (destination : Ipv4Endpoint) : bool =
        holder.Endpoint = source && holder.Peer = Some destination

    /// Whether `holder` stands in the way of `bind(2)` of `candidate` by a
    /// socket carrying `SO_REUSEADDR` if `candidateReuse`: `EADDRINUSE`.
    ///
    /// Both flavours refuse two holders one port at overlapping addresses,
    /// and both relax that for `SO_REUSEADDR`, in opposite directions:
    /// Linux only while the holder is not listening and both carry the flag;
    /// Darwin, keyed on the candidate's flag alone, for addresses that differ,
    /// or for the very address a connection end holds.
    let bindMeets
        (flavour : SimulatedUnixFlavour)
        (holder : PortHolder)
        (candidate : Ipv4Endpoint)
        (candidateReuse : bool)
        : bool
        =
        holdsOver holder candidate
        && (
            // Measured on both, at loopback and the wildcard, with and without
            // the flag on either side, against idle, listening and connected
            // sockets and against a connection end whose socket has closed,
            // which holds its endpoint with the flag its socket carried then
            // (`bind-held-endpoint.c` in
            // docs/plans/2026-10-08-tcp-shutdown-linger; a replacement
            // listener bound over accepted connections). A connection end's
            // pcb is keyed by its whole four-tuple, which is why Darwin lets a
            // reuse-carrying candidate bind its exact endpoint, and why Linux's
            // rule, an accepted socket carrying its listener's flag, needs no
            // case of its own for one.
            match flavour with
            | SimulatedUnixFlavour.Linux ->
                not (holder.ReuseAddress && candidateReuse)
                || holder.Kind = PortHolderKind.Listener
            | SimulatedUnixFlavour.Darwin ->
                (holder.Endpoint.Address = candidate.Address
                 && holder.Kind <> PortHolderKind.ConnectionEnd)
                || not candidateReuse
        )

    /// Whether `holder` stands in the way of `listen(2)` on a socket already
    /// bound at `bound`, not yet listening, and carrying `SO_REUSEADDR` if
    /// `reuse`: `EADDRINUSE`.
    ///
    /// Linux asks `bind(2)`'s question again, so two sockets carrying
    /// `SO_REUSEADDR` may share an endpoint until one of them listens. Darwin
    /// asks nothing of a socket that already has a port; asking its bind
    /// question again would swap the roles it was answered under, since it
    /// keys on the candidate's flag alone, and refuse a pair it admitted.
    let listenMeets
        (flavour : SimulatedUnixFlavour)
        (holder : PortHolder)
        (bound : Ipv4Endpoint)
        (reuse : bool)
        : bool
        =
        // Linux's `inet_csk_listen_start` calls `get_port` a second time;
        // Darwin's `tcp_usr_listen` binds only a socket with no port. Both
        // measured, and a socket already listening is asked nothing on either
        // (`relisten-held.c` in docs/plans/2026-10-08-tcp-shutdown-linger).
        match flavour with
        | SimulatedUnixFlavour.Linux -> bindMeets flavour holder bound reuse
        | SimulatedUnixFlavour.Darwin -> false

    /// Whether `holder` stands in the way of a search for an ephemeral port
    /// to bind at `candidate`, by `bind(2)` of port 0 or by `listen(2)` on a
    /// socket with no port, for a socket of `transport` carrying
    /// `SO_REUSEADDR` if `candidateReuse`.
    ///
    /// A stream socket's search passes over every port a holder holds at an
    /// overlapping address, whatever either's `SO_REUSEADDR` and whether or
    /// not the holder listens, where an explicit bind beside it may be
    /// admitted. A datagram socket's search is `bind(2)`'s question.
    let bindSearchMeets
        (flavour : SimulatedUnixFlavour)
        (transport : SocketKind)
        (holder : PortHolder)
        (candidate : Ipv4Endpoint)
        (candidateReuse : bool)
        : bool
        =
        match transport with
        // Measured on Linux (`inet_csk_find_open_port`), and on Darwin for a
        // search carrying SO_REUSEADDR against holders carrying it
        // (`docs/probes/ephemeral-search`).
        | SocketKind.Stream -> holdsOver holder candidate
        // Linux's UDP search lets two sockets carrying SO_REUSEADDR share a
        // port, by its source (`udp_lib_lport_inuse`), which is unmeasured.
        | SocketKind.Datagram
        | SocketKind.SeqPacket -> bindMeets flavour holder candidate candidateReuse

    /// Whether `holder` stands in the way of a search for the port a
    /// connect's implicit bind takes, from `source` towards `destination`, for
    /// a socket of `transport` carrying `SO_REUSEADDR` if `sourceReuse`.
    ///
    /// A holder occupying the four-tuple stands in the way. Besides that,
    /// Linux's stream search passes over a port a holder holds outright, at
    /// any address, and shares one a holder holds for its own four-tuple;
    /// Darwin's passes over every port a holder holds, at any address and
    /// whatever anyone's `SO_REUSEADDR`, as a bind of the wildcard carrying
    /// no flag would. A datagram socket's search is `bind(2)`'s question.
    let connectSearchMeets
        (flavour : SimulatedUnixFlavour)
        (transport : SocketKind)
        (holder : PortHolder)
        (source : Ipv4Endpoint)
        (destination : Ipv4Endpoint)
        (sourceReuse : bool)
        : bool
        =
        occupiesFourTuple holder source destination
        || (
            match transport, flavour with
            // `__inet_hash_connect` passes over a port whose bind bucket
            // `bind(2)` or `listen(2)` made, and shares one only connect's own
            // implicit bind made; a connection end whose socket has closed
            // keeps its socket's bucket (measured,
            // `docs/probes/ephemeral-search` and
            // `docs/probes/connect-search-holders`, rows f, fr and fe).
            | SocketKind.Stream, SimulatedUnixFlavour.Linux ->
                holder.Claim = PortClaim.Reserved && holder.Endpoint.Port = source.Port
            // Darwin's implicit bind binds the wildcard before the source
            // resolves (measured, `docs/probes/implicit-self-connect`, rows H
            // and Hr, and every row of `docs/probes/connect-search-holders`).
            | SocketKind.Stream, SimulatedUnixFlavour.Darwin -> holdsAt holder source.Port
            | SocketKind.Datagram, _
            | SocketKind.SeqPacket, _ -> bindMeets flavour holder source sourceReuse
        )

    /// Whether `holder` makes Darwin drop a SYN towards `destination`, where
    /// nothing listens, rather than answer it with a reset: a socket bound at
    /// an overlapping address and doing nothing else. The connect then pends
    /// on the client's retransmissions. Linux answers every such SYN with a
    /// reset.
    let dropsSyn (flavour : SimulatedUnixFlavour) (holder : PortHolder) (destination : Ipv4Endpoint) : bool =
        // Measured: a port held by connection ends (whose pcbs are keyed by
        // the whole four-tuple) or by a refused socket answers RST on Darwin,
        // like a closed port; a bound idle one drops the SYN, and a blocking
        // connect stalled into ETIMEDOUT.
        match flavour with
        | SimulatedUnixFlavour.Linux -> false
        | SimulatedUnixFlavour.Darwin -> holder.Kind = PortHolderKind.Idle && holdsOver holder destination

    /// Whether an open socket whose connection end is done with its endpoint
    /// goes on holding its port, `bind(2)` having chosen the port if
    /// `lockedPort`: on Linux only such a port, until the socket closes, and
    /// on Darwin none.
    let openEndKeepsPort (flavour : SimulatedUnixFlavour) (lockedPort : bool) : bool =
        // Measured on both, for an end whose FIN, made after the peer's had
        // arrived, has itself arrived (`tcp-shutdown.c` section F in
        // docs/plans/2026-10-08-tcp-shutdown-linger).
        match flavour with
        | SimulatedUnixFlavour.Linux -> lockedPort
        | SimulatedUnixFlavour.Darwin -> false
