namespace WoofWare.PosixKernel

/// One TCP connection, as the emulated kernel's connection table holds it.
///
/// Keyed by `ConnectionId`, and holding the two endpoints' addresses and the
/// bytes travelling between them. The bytes are the connection's rather than
/// either socket's because a client may write before the server end has a
/// socket at all.
///
/// Deliberately no references back to the sockets on its ends: a connection
/// outlives the client that opened it (measured: close the client while its
/// connection sits in an accept queue, and `accept(2)` still returns it), and
/// the server end has no socket at all until that accept, so an end-to-socket
/// field would spend most of its life dangling or `None`. Cleanup instead
/// scans the socket table for references, which `UnixDescriptor.close` does.
type internal TcpConnection =
    {
        /// The connecting side's address — what `accept(2)` reports as the
        /// peer.
        ClientAddress : Ipv4Endpoint
        /// The accepted side's address: the destination the client connected
        /// to, with a wildcard destination already rewritten to loopback. The
        /// accepted socket's own `getsockname(2)` reports this.
        ServerAddress : Ipv4Endpoint
        /// The bytes travelling each way, and what each end knows of the
        /// connection's ending.
        Transfer : TcpTransfer
        /// When both of the connection's FINs had arrived, by the kernel
        /// clock (`UnixSchedulingState.NanosecondsSinceBoot`): when the end
        /// whose FIN was made first entered TIME_WAIT. `None` until then.
        FinsExchangedAt : int64 option
    }

/// One end of a TCP connection in TIME_WAIT once both of the connection's
/// sockets have closed and the connection itself is gone: what Linux keeps as
/// an `inet_timewait_sock`. It holds its endpoint's port, and its four-tuple,
/// until it expires.
type internal TcpTimeWait =
    {
        /// The end's own endpoint, whose port it holds.
        Local : Ipv4Endpoint
        /// The other end's endpoint: the end holds the four-tuple from
        /// `Local` to here.
        Remote : Ipv4Endpoint
        /// The `SO_REUSEADDR` the end's socket carried when it closed, which a
        /// bind of the port is judged against.
        ReuseAddress : bool
        /// How the end's socket held its port.
        PortHold : PortHold
        /// The uid the end's socket carried (`SocketDescription.Uid`).
        SocketUid : UserId
        /// When the end entered TIME_WAIT, by the kernel clock: when both of
        /// the connection's FINs had arrived.
        EnteredAt : int64
    }
