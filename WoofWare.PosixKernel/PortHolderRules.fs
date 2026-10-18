namespace WoofWare.PosixKernel

/// What a port holder is, as the rules over port holders ask.
[<RequireQualifiedAccess>]
type internal PortHolderKind =
    /// An open socket that is bound and neither listening, connected nor
    /// refused: an idle stream socket, or a datagram socket with no default
    /// peer.
    | Idle
    /// A datagram socket with a default peer.
    | DatagramPeer
    /// An open stream socket whose connect was refused.
    | Refused
    /// A listening socket.
    | Listener
    /// One end of a TCP connection: a connected socket, an end whose socket
    /// has closed, or a server end waiting in an accept queue.
    | ConnectionEnd
    /// One end of a TCP connection in TIME_WAIT, the connection's sockets
    /// both closed (`TcpTimeWait`), which it entered at `enteredAt` by the
    /// kernel clock.
    | TimeWait of enteredAt : int64

/// The sysctls that decide how long a TCP end stays in TIME_WAIT once both of
/// its connection's sockets have closed, and when a new connection may take
/// its four-tuple over: boot configuration, with each flavour's default as
/// measured.
[<RequireQualifiedAccess>]
type internal TcpTimeWaitSysctls =
    /// Linux's `net.ipv4.tcp_tw_reuse_delay`, in nanoseconds: how long after
    /// an end entered TIME_WAIT a connect's search may take its loopback
    /// four-tuple over, with `net.ipv4.tcp_tw_reuse` at its default, 2.
    /// TIME_WAIT itself lasts `TCP_TIMEWAIT_LEN`, which no sysctl sets.
    | Linux of reuseDelay : int64
    /// Darwin's `net.inet.tcp.msl`, in nanoseconds: TIME_WAIT lasts twice it.
    | Darwin of msl : int64

/// Why this kernel cannot say whether a TCP end, in TIME_WAIT or with its
/// socket closed, stands in a port's or a four-tuple's way.
[<RequireQualifiedAccess>]
type internal TimeWaitRefusal =
    /// The end at `local`, towards `remote`, entered TIME_WAIT `elapsed` ns
    /// ago, past the `window` it was measured to last at least; when it ends
    /// is unmeasured.
    | OutlivedWindow of local : Ipv4Endpoint * remote : Ipv4Endpoint * elapsed : int64 * window : int64
    /// Under Linux, a connect's search would take over the four-tuple of the
    /// end at `local`, towards `remote`, `elapsed` ns after it entered
    /// TIME_WAIT: within 10 ms of `tcp_tw_reuse_delay`, where whether it may
    /// is unmeasured.
    | NearReuseDelay of local : Ipv4Endpoint * remote : Ipv4Endpoint * elapsed : int64
    /// Under Linux, a connect would take over the four-tuple of an end in
    /// TIME_WAIT at `local`, towards `remote`, off loopback, where whether
    /// `tcp_tw_reuse` lets it is unmeasured.
    | OffLoopback of local : Ipv4Endpoint * remote : Ipv4Endpoint
    /// Under Linux, a connect from a socket bound at `local` would take over
    /// the four-tuple of an end that entered TIME_WAIT towards `remote` in the
    /// machine's first second of uptime, which a search never takes over;
    /// what such a connect does is unmeasured.
    | EnteredInFirstSecond of local : Ipv4Endpoint * remote : Ipv4Endpoint
    /// Under Darwin, a `bind(2)` by a socket carrying `binder`, not root,
    /// meets the end at `local` whose socket has closed carrying another uid,
    /// `holder`, at addresses that are not both the wildcard. Darwin refuses
    /// such a bind beside an open socket of another uid; beside an end whose
    /// socket has closed it was measured to refuse it for an end of uid 502
    /// and to admit it for one of root's, and which holds is unexplained.
    | OtherUidClosedEnd of local : Ipv4Endpoint * holder : UserId * binder : UserId

[<RequireQualifiedAccess>]
module internal TimeWaitRefusal =
    /// What this kernel knows about why it cannot answer.
    let describe (refusal : TimeWaitRefusal) : string =
        match refusal with
        | TimeWaitRefusal.OutlivedWindow (local, remote, elapsed, window) ->
            $"the connection end at %s{Ipv4Endpoint.toString local}, towards %s{Ipv4Endpoint.toString remote}, entered TIME_WAIT %d{elapsed} ns ago, and TIME_WAIT is measured to last at least %d{window} ns but not to end at any instant, so whether it still holds its port and four-tuple is unmeasured. Make the call within that window, or measure when TIME_WAIT ends."
        | TimeWaitRefusal.NearReuseDelay (local, remote, elapsed) ->
            $"a connect would take over the four-tuple of the connection end at %s{Ipv4Endpoint.toString local}, towards %s{Ipv4Endpoint.toString remote}, %d{elapsed} ns after it entered TIME_WAIT. Linux's search does so from 10 ms past tcp_tw_reuse_delay and not until 10 ms before it (measured), and between the two is unmeasured."
        | TimeWaitRefusal.OffLoopback (local, remote) ->
            $"a connect would take over the four-tuple of the connection end in TIME_WAIT at %s{Ipv4Endpoint.toString local}, towards %s{Ipv4Endpoint.toString remote}, which is not on loopback, and whether Linux's tcp_tw_reuse lets it off loopback is unmeasured."
        | TimeWaitRefusal.EnteredInFirstSecond (local, remote) ->
            $"a connect from a socket bound at %s{Ipv4Endpoint.toString local} would take over the four-tuple of a connection end that entered TIME_WAIT towards %s{Ipv4Endpoint.toString remote} in the machine's first second of uptime. Linux's search never takes such a four-tuple over (measured), and what a connect from a bound socket does is unmeasured."
        | TimeWaitRefusal.OtherUidClosedEnd (local, holder, binder) ->
            $"a bind by a socket of uid %O{binder} meets the connection end at %s{Ipv4Endpoint.toString local}, whose socket has closed carrying uid %O{holder}. Darwin refuses a bind beside an open socket of another uid at addresses that are not both the wildcard; beside an end whose socket has closed it was measured to refuse one for an end of uid 502 and to admit one for an end of root's, and which rule holds for this end is unexplained."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : TimeWaitRefusal) : RefusalKind =
        match refusal with
        | TimeWaitRefusal.OutlivedWindow _
        | TimeWaitRefusal.NearReuseDelay _
        | TimeWaitRefusal.OffLoopback _
        | TimeWaitRefusal.EnteredInFirstSecond _
        | TimeWaitRefusal.OtherUidClosedEnd _ -> RefusalKind.Unmodelled

/// Whether a holder stands in a port's or a four-tuple's way, once the time an
/// end in TIME_WAIT has spent there is counted.
[<RequireQualifiedAccess>]
type internal PortVerdict =
    /// It does not.
    | Clear
    /// It does.
    | InTheWay
    /// Whether it does is unmeasured.
    | Undetermined of refusal : TimeWaitRefusal

[<RequireQualifiedAccess>]
module internal PortVerdict =
    /// What a question asked of every holder answers: in the way if any holder
    /// is; otherwise undetermined if any holder's standing is; otherwise clear.
    let ofAll (verdicts : PortVerdict seq) : PortVerdict =
        (PortVerdict.Clear, verdicts)
        ||> Seq.fold (fun answer verdict ->
            match answer, verdict with
            | PortVerdict.InTheWay, _
            | _, PortVerdict.InTheWay -> PortVerdict.InTheWay
            | PortVerdict.Undetermined _, _ -> answer
            | PortVerdict.Clear, _ -> verdict
        )

/// What a connect from a socket bound at an end's endpoint does towards that
/// end's peer, where the end is in TIME_WAIT on that four-tuple.
[<RequireQualifiedAccess>]
type internal TimeWaitTakeover =
    /// The connect takes the four-tuple over, and the TIME_WAIT ends.
    | TakesOver
    /// The connect fails with `EADDRINUSE`, leaving the socket as it was.
    | AddressInUse

/// The kernel clock's reading and the machine's TIME_WAIT sysctls: what an
/// end in TIME_WAIT is judged by.
type internal TimeWaitClock =
    {
        /// `UnixSchedulingState.NanosecondsSinceBoot`.
        Now : int64
        Sysctls : TcpTimeWaitSysctls
    }

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

/// Whose a port holder is, as Darwin's `bind(2)` asks: the uid it carries
/// (`SocketDescription.Uid`), and whether its socket is still open.
[<RequireQualifiedAccess>]
type internal PortHolderOwner =
    /// An open socket, carrying `uid`.
    | Socket of uid : UserId
    /// A TCP end whose socket has closed, carrying the uid that socket
    /// carried: an end still in its connection, or one in TIME_WAIT.
    | ClosedSocket of uid : UserId
    /// A TCP end with no socket that never had one of its own: a server end
    /// in an accept queue, or an end a reset reached. It holds no port
    /// (`PortClaim.Released`).
    | NoSocket

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
        /// Whose it is.
        Owner : PortHolderOwner
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

    /// Whether `kind` has a foreign address: one end of a TCP connection, in
    /// TIME_WAIT or not, or a datagram socket with a default peer.
    let private hasPeer (kind : PortHolderKind) : bool =
        match kind with
        | PortHolderKind.ConnectionEnd
        | PortHolderKind.TimeWait _
        | PortHolderKind.DatagramPeer -> true
        | PortHolderKind.Idle
        | PortHolderKind.Refused
        | PortHolderKind.Listener -> false

    /// Whether `holder` occupies the four-tuple from `source` to
    /// `destination`, as the end at `source`. The connection's other end
    /// occupies it the other way round.
    let occupiesFourTuple (holder : PortHolder) (source : Ipv4Endpoint) (destination : Ipv4Endpoint) : bool =
        holder.Endpoint = source && holder.Peer = Some destination

    /// Whether `holder` stands in the way of `bind(2)` of `candidate` by a
    /// socket carrying `SO_REUSEADDR` if `candidateReuse`, where the two
    /// carry one uid or the candidate's is root's: `EADDRINUSE`.
    ///
    /// Both flavours refuse two holders one port at overlapping addresses,
    /// and both relax that for `SO_REUSEADDR`, in opposite directions:
    /// Linux only while the holder is not listening and both carry the flag;
    /// Darwin, keyed on the candidate's flag alone, for addresses that differ,
    /// or for the very address a holder with a peer holds. Darwin's rule for
    /// two uids is `bindVerdict`'s.
    let bindMeetsAtOneUid
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
            // listener bound over accepted connections), and against an end in
            // TIME_WAIT once both its sockets have closed
            // (`docs/probes/time-wait`, rows B and S); and for datagram
            // sockets, idle or with a peer, and for idle and listening stream
            // sockets, held by a process of the candidate's uid or of another
            // (`docs/probes/port-sharing`; Darwin at one uid only). Darwin's
            // lookup for a reuse-carrying candidate skips a pcb with a foreign
            // address, which is why such a candidate binds the exact endpoint
            // of a connection end or of a connected datagram socket; Linux's
            // rule, an accepted socket carrying its listener's flag, needs no
            // case of its own for one.
            //
            // Measured on Darwin 27.0 as root (`docs/probes/darwin-root/bind-uids.c`):
            // the rule holds between sockets of one uid, and whenever the
            // binder is root.
            match flavour with
            | SimulatedUnixFlavour.Linux ->
                not (holder.ReuseAddress && candidateReuse)
                || holder.Kind = PortHolderKind.Listener
            | SimulatedUnixFlavour.Darwin ->
                (holder.Endpoint.Address = candidate.Address && not (hasPeer holder.Kind))
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
        | SimulatedUnixFlavour.Linux -> bindMeetsAtOneUid flavour holder bound reuse
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
        // Measured on Linux (`inet_csk_find_open_port`), at either uid
        // pairing (`docs/probes/port-sharing`), and on Darwin for a search
        // carrying SO_REUSEADDR against holders carrying it
        // (`docs/probes/ephemeral-search`).
        | SocketKind.Stream -> holdsOver holder candidate
        // Measured on Linux, holder and search each carrying SO_REUSEADDR or
        // not, at either uid pairing (`docs/probes/port-sharing`): two
        // sockets carrying it share a port. Darwin's is taken to ask the same
        // question, which is unmeasured.
        | SocketKind.Datagram
        | SocketKind.SeqPacket -> bindMeetsAtOneUid flavour holder candidate candidateReuse

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
            | SocketKind.SeqPacket, _ -> bindMeetsAtOneUid flavour holder source sourceReuse
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

    /// How long an end stays in TIME_WAIT at least, by the machine's sysctls.
    let timeWaitWindow (sysctls : TcpTimeWaitSysctls) : int64 =
        // Measured (`docs/probes/time-wait`, row W): Linux held the port
        // 60.2 s and let it go by 61.2 s (`TCP_TIMEWAIT_LEN`, 60 s); Darwin
        // held it 30.1 s and let it go by 31.1 s, at an msl of 15 s.
        match sysctls with
        | TcpTimeWaitSysctls.Linux _ -> 60_000_000_000L
        | TcpTimeWaitSysctls.Darwin msl -> 2L * msl

    /// The refusal for `holder` if it is an end in TIME_WAIT past its window.
    let private outlived (clock : TimeWaitClock) (holder : PortHolder) : TimeWaitRefusal option =
        match holder.Kind, holder.Peer with
        | PortHolderKind.TimeWait enteredAt, Some peer ->
            let elapsed = clock.Now - enteredAt
            let window = timeWaitWindow clock.Sysctls

            if elapsed >= window then
                Some (TimeWaitRefusal.OutlivedWindow (holder.Endpoint, peer, elapsed, window))
            else
                None
        | PortHolderKind.TimeWait _, None ->
            failwith
                $"PortHolderRules: the end in TIME_WAIT at %s{Ipv4Endpoint.toString holder.Endpoint} has no peer (this is a bug in this library)."
        | PortHolderKind.Idle, _
        | PortHolderKind.DatagramPeer, _
        | PortHolderKind.Refused, _
        | PortHolderKind.Listener, _
        | PortHolderKind.ConnectionEnd, _ -> None

    /// Whether a holder that would stand in the way if `inTheWay` does, once
    /// time is counted: an end in TIME_WAIT past its window may have gone.
    let private judged (clock : TimeWaitClock) (holder : PortHolder) (inTheWay : bool) : PortVerdict =
        if not inTheWay then
            PortVerdict.Clear
        else
            match outlived clock holder with
            | Some refusal -> PortVerdict.Undetermined refusal
            | None -> PortVerdict.InTheWay

    /// Whether `holder` stands in the way of `bind(2)` of `candidate` by a
    /// socket carrying `SO_REUSEADDR` if `candidateReuse` and the uid
    /// `candidateUid`, once time is counted.
    ///
    /// `bindMeetsAtOneUid`'s rule, and on Darwin one more: a candidate that is
    /// not root's meeting a holder of another uid, at overlapping addresses
    /// that are not both the wildcard, is in the way whatever either's
    /// `SO_REUSEADDR`. Where that holder is an end whose socket has closed,
    /// the answer is undetermined (`TimeWaitRefusal.OtherUidClosedEnd`).
    /// Linux asks no owner here: it compares uids only for `SO_REUSEPORT`,
    /// which this kernel does not model.
    let bindVerdict
        (flavour : SimulatedUnixFlavour)
        (clock : TimeWaitClock)
        (holder : PortHolder)
        (candidate : Ipv4Endpoint)
        (candidateReuse : bool)
        (candidateUid : UserId)
        : PortVerdict
        =
        // Measured on Darwin 27.0 as root (`docs/probes/darwin-root/bind-uids.c`,
        // 96 rows): a binder that is not root, beside an idle or listening
        // socket of another uid, TCP or UDP, is EADDRINUSE with and without
        // SO_REUSEADDR on either side unless both addresses are the wildcard;
        // the uids compared are each socket's own, fixed when it was made
        // (CRED rows). `docs/probes/socket-creator-uid` (ACCEPT rows): the
        // same beside an accepted socket. Its control rows met the accepted
        // end in TIME_WAIT once every socket had closed (`close-order.c`
        // there: that end, every time): EADDRINUSE beside an end of uid 502,
        // and admitted beside an end of root's, which no rule here explains.
        let otherUid (uid : UserId) : bool =
            match flavour with
            | SimulatedUnixFlavour.Linux -> false
            | SimulatedUnixFlavour.Darwin ->
                candidateUid <> UserId.root
                && uid <> candidateUid
                && holdsOver holder candidate
                && not (holder.Endpoint.Address = Ipv4Address.any && candidate.Address = Ipv4Address.any)

        match holder.Owner with
        | PortHolderOwner.ClosedSocket uid when otherUid uid ->
            PortVerdict.Undetermined (TimeWaitRefusal.OtherUidClosedEnd (holder.Endpoint, uid, candidateUid))
        | PortHolderOwner.Socket uid when otherUid uid -> judged clock holder true
        | PortHolderOwner.ClosedSocket _
        | PortHolderOwner.Socket _
        | PortHolderOwner.NoSocket -> judged clock holder (bindMeetsAtOneUid flavour holder candidate candidateReuse)

    /// `listenMeets`, once time is counted.
    let listenVerdict
        (flavour : SimulatedUnixFlavour)
        (clock : TimeWaitClock)
        (holder : PortHolder)
        (bound : Ipv4Endpoint)
        (reuse : bool)
        : PortVerdict
        =
        judged clock holder (listenMeets flavour holder bound reuse)

    /// `bindSearchMeets`, once time is counted.
    let bindSearchVerdict
        (flavour : SimulatedUnixFlavour)
        (clock : TimeWaitClock)
        (transport : SocketKind)
        (holder : PortHolder)
        (candidate : Ipv4Endpoint)
        (candidateReuse : bool)
        : PortVerdict
        =
        judged clock holder (bindSearchMeets flavour transport holder candidate candidateReuse)

    /// Whether `holder`'s four-tuple has an end on loopback.
    let private onLoopback (holder : PortHolder) : bool =
        Ipv4Prefix.contains holder.Endpoint.Address Ipv4Prefix.loopbackNetwork
        || holder.Peer
           |> Option.exists (fun peer -> Ipv4Prefix.contains peer.Address Ipv4Prefix.loopbackNetwork)

    /// The machine's first second of uptime, in nanoseconds.
    let private firstSecond : int64 = 1_000_000_000L

    /// How far either side of `tcp_tw_reuse_delay` the measurement reaches.
    let private reuseDelayMargin : int64 = 10_000_000L

    /// `connectSearchMeets`, once time is counted, and with the one place a
    /// connect's search takes a four-tuple over: under Linux, an end in
    /// TIME_WAIT on loopback, connect's own bind having given its socket the
    /// port, once `tcp_tw_reuse_delay` has passed since it entered TIME_WAIT,
    /// unless it entered it in the machine's first second of uptime. A search
    /// that takes such a four-tuple over ends that TIME_WAIT.
    let connectSearchVerdict
        (flavour : SimulatedUnixFlavour)
        (clock : TimeWaitClock)
        (transport : SocketKind)
        (holder : PortHolder)
        (source : Ipv4Endpoint)
        (destination : Ipv4Endpoint)
        (sourceReuse : bool)
        : PortVerdict
        =
        match transport, flavour, holder.Kind with
        | SocketKind.Stream, SimulatedUnixFlavour.Linux, PortHolderKind.TimeWait enteredAt when
            holder.Claim <> PortClaim.Reserved
            && occupiesFourTuple holder source destination
            ->
            // Measured (`docs/probes/time-wait`, tw-reuse.c rows R, and
            // tw-boot.c): not by 0.99 s after the TIME_WAIT began, and from
            // 1.01 s, whatever SO_REUSEADDR either carries, at a
            // tcp_tw_reuse_delay of 1000 ms; never for one begun in the first
            // second of uptime. A port bind(2) gave is passed over before the
            // four-tuple is looked at (rows Cb), which `judged` answers.
            match outlived clock holder with
            | Some refusal -> PortVerdict.Undetermined refusal
            | None ->

            let delay =
                match clock.Sysctls with
                | TcpTimeWaitSysctls.Linux delay -> delay
                | TcpTimeWaitSysctls.Darwin _ ->
                    failwith
                        "PortHolderRules.connectSearchVerdict: a Linux machine carries Darwin's TIME_WAIT sysctls (this is a bug in this library: UnixSystem.checkInvariants reports it as TimeWaitSysctlsNotOfFlavour)."

            let elapsed = clock.Now - enteredAt
            let peer = Option.get holder.Peer

            if not (onLoopback holder) then
                PortVerdict.Undetermined (TimeWaitRefusal.OffLoopback (holder.Endpoint, peer))
            elif enteredAt < firstSecond then
                PortVerdict.InTheWay
            elif elapsed <= delay - reuseDelayMargin then
                PortVerdict.InTheWay
            elif elapsed >= delay + reuseDelayMargin then
                PortVerdict.Clear
            else
                PortVerdict.Undetermined (TimeWaitRefusal.NearReuseDelay (holder.Endpoint, peer, elapsed))
        | _ -> judged clock holder (connectSearchMeets flavour transport holder source destination sourceReuse)

    /// What a connect from a socket bound at `holder`'s endpoint does towards
    /// `holder`'s peer, where `holder` is an end in TIME_WAIT on that
    /// four-tuple: Linux takes the four-tuple over at once, unless the end
    /// entered TIME_WAIT in the machine's first second of uptime; Darwin
    /// answers `EADDRINUSE`.
    let boundConnectOverTimeWait
        (flavour : SimulatedUnixFlavour)
        (clock : TimeWaitClock)
        (holder : PortHolder)
        : Result<TimeWaitTakeover, TimeWaitRefusal>
        =
        // Measured (`docs/probes/time-wait`, tw-reuse.c rows E, V and Z),
        // at 0, 0.5 and 1.5 s, bound at 127.0.0.1 or the wildcard, with and
        // without a listener at the peer.
        match holder.Kind, holder.Peer with
        | PortHolderKind.TimeWait enteredAt, Some peer ->
            match outlived clock holder with
            | Some refusal -> Error refusal
            | None ->

            match flavour with
            | SimulatedUnixFlavour.Darwin -> Ok TimeWaitTakeover.AddressInUse
            | SimulatedUnixFlavour.Linux ->
                if not (onLoopback holder) then
                    Error (TimeWaitRefusal.OffLoopback (holder.Endpoint, peer))
                elif enteredAt < firstSecond then
                    Error (TimeWaitRefusal.EnteredInFirstSecond (holder.Endpoint, peer))
                else
                    Ok TimeWaitTakeover.TakesOver
        | kind, _ ->
            failwith
                $"PortHolderRules.boundConnectOverTimeWait: the holder at %s{Ipv4Endpoint.toString holder.Endpoint} is %A{kind}, not an end in TIME_WAIT (this is a bug in this library)."
