namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// What an `accept(2)` that took a connection wrote of the connection's peer
/// address.
[<RequireQualifiedAccess ; NoComparison>]
type PeerAddressCopy =
    /// The kernel wrote `copiedOut` to the start of the caller's address buffer
    /// and `reportedLength` to its length cell: the client's address as this
    /// platform's socket address structure for the listener's family (so far
    /// only ever a `struct sockaddr_in`: this kernel has no IPv6 listener), cut
    /// to the length the caller declared and so possibly empty, and that
    /// structure's untruncated size. As for `getsockname`, the declared length
    /// bounds what is written and not what is reported: a call declaring 8
    /// writes eight bytes and still reports 16.
    | Written of copiedOut : ImmutableArray<byte> * reportedLength : int
    /// The caller's address buffer was NULL, so the kernel wrote nothing: not
    /// the buffer, and not the length cell either, which it never read.
    | NotRequested

/// What became of an `accept(2)` this kernel could answer.
[<RequireQualifiedAccess ; NoComparison>]
type AcceptOutcome =
    /// The call failed with this errno, and nothing about the listener changed.
    /// The accept queue in particular is untouched: measured on both flavours,
    /// a failed `accept` leaves a queued connection queued.
    ///
    /// Answered by `finishAccept`, the thread is no longer parked in the system
    /// this rides with.
    | Failed of error : UnixError
    /// A connection was dequeued and a socket materialised onto it. `fd` is the
    /// descriptor that socket is open on, and `address` what the kernel wrote
    /// of the connection's peer address.
    | Accepted of fd : int * address : PeerAddressCopy
    /// The call failed with this errno after it had taken the oldest connection
    /// off the accept queue, and the connection is gone: its server end is
    /// closed as `close` closes an accepted socket, so the client sees an
    /// orderly shutdown and its registrations are signalled. No descriptor is
    /// allocated. The system that rides with this records all of that.
    ///
    /// Linux's answer, `EINVAL`, for a negative declared length, which it reads
    /// only once it holds the connection.
    | DroppedConnection of error : UnixError
    /// The call did not return: the listener is blocking and its accept queue
    /// is empty. The calling thread is parked, and sleeps until
    /// `UnixWait.satisfied` of the thread is non-empty and
    /// `UnixWait.wake` wakes it; then `UnixConnection.finishAccept` finishes
    /// the call.
    | WouldBlock of WakeCondition
    /// The call was asleep, and a signal interrupted it. The thread is no longer
    /// parked, and owes a return to user mode (`UnixSignal.onReturnToUser`),
    /// which it makes before any other call: that return says whether the
    /// `accept` fails with `EINTR` or restarts.
    ///
    /// Only `finishAccept` answers this.
    | Interrupted

/// Why this kernel will not answer an `accept`.
///
/// Distinct from an errno: an errno is an answer, and these are the inputs for
/// which this library has measured what real kernels do and found no single
/// answer to give.
[<RequireQualifiedAccess>]
type internal AcceptRefusal =
    /// A descriptor the call would make lies at or above the bound this kernel
    /// assumes the process's `RLIMIT_NOFILE` reaches.
    | DescriptorLimit of DescriptorLimitRefusal
    /// The descriptor is a socket in a domain whose addresses this kernel does
    /// not model, so there is no peer address to report even if the accept
    /// itself would succeed.
    | UnmodelledDomain of socket : SocketId * domain : SocketDomain
    /// The descriptor is a socket of a kind whose `accept(2)` answer is
    /// unmeasured. `SOCK_SEQPACKET` does accept connections, so answering
    /// rather than measuring would be the difference between an answer and a
    /// state change.
    | UnmeasuredKind of socket : SocketId * kind : SocketKind
    /// The accept would succeed and copy the peer address out, but the
    /// destination is one this library has no answer for: its bytes cannot be
    /// produced, or it is not an address at all.
    ///
    /// Reached only once a connection has been selected, which is what makes it
    /// worth distinguishing from `UnmeasuredCopyOutFault` beside it: here the
    /// kernel *would* have succeeded and dequeued, and it is the client that
    /// cannot represent the transfer.
    | Buffer of BufferRefusal
    /// The accept would succeed and copy the peer address out, but the
    /// destination is unmapped, so the copy faults.
    ///
    /// `getsockname` answers EFAULT for this and `accept` cannot, which is the
    /// whole reason the case exists: by the time the fault happens a connection
    /// has been taken off the queue. Measured, Linux stores the untruncated
    /// length in the caller's cell, answers EFAULT and loses the connection,
    /// while Darwin ignores the fault and succeeds; neither is an outcome this
    /// library can return, since neither a failure that writes the cell nor a
    /// success whose address the caller must not write is one.
    | UnmeasuredCopyOutFault of listener : SocketId
    /// The accept was asleep and a signal is pending for the thread, and this
    /// library will not say how the signal ends it.
    | Interruption of SyscallInterruptionRefusal
    /// The accept would sleep on a listener a close has drained
    /// (`ListenState.Drained`): its queue is empty and the description it was
    /// made through blocking.
    ///
    /// Darwin answers such a sleep with `ECONNABORTED` once anything wakes it,
    /// and a connection wakes one sleeper and stays queued, so a second sleeper
    /// sleeps on through it. This kernel wakes a sleeping accept while a
    /// connection is queued, which would wake that second sleeper too.
    | DarwinDrainedListener of listener : SocketId
    /// Under Darwin, the accept was woken by a connection on the listener the
    /// open file description `listener` names, a signal with a handler is
    /// now deliverable to its thread, and another thread is asleep in an
    /// accept on the same listener.
    ///
    /// Darwin ends the woken accept with EINTR, and the connection whose wake
    /// it took stays queued without waking the other (measured). This kernel
    /// wakes a sleeping accept for as long as a connection is queued, so it
    /// would wake the other.
    | SignalBesideConsumedWake of listener : OpenFileDescriptionId
    /// The call carries flags, which only Linux's `accept4` takes, and this
    /// kernel is of another flavour.
    | FlagsNotProvided of flavour : SimulatedUnixFlavour
    /// The call supplied a declared length for a NULL destination
    /// (`nullDestination`), which no kernel reads; or none for any other
    /// destination, whose length cell a kernel reads.
    | LengthContradictsDestination of nullDestination : bool

[<RequireQualifiedAccess>]
module internal AcceptRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point, which descriptor, and how a caller
    /// could have come by such a socket or such a buffer.
    let describe (refusal : AcceptRefusal) : string =
        match refusal with
        | AcceptRefusal.DescriptorLimit refusal -> DescriptorLimitRefusal.describe refusal
        | AcceptRefusal.UnmodelledDomain (socket, domain) ->
            $"the descriptor is socket %O{socket}, whose domain is %O{domain}. This kernel models a peer address only for IPv4: an IPv6 socket's is sixteen bytes of address plus a scope id, and a Unix-domain socket's is a *path* in the filesystem rather than a transport endpoint. Neither is a wider version of what is modelled here, so there is nothing to truncate or widen into an answer."
        | AcceptRefusal.UnmeasuredKind (socket, kind) ->
            $"the descriptor is socket %O{socket}, which is a %O{kind} socket, and what `accept(2)` answers for one is unmeasured. Measure it rather than guessing: SOCK_SEQPACKET does accept connections, so a guess of EOPNOTSUPP there would be a wrong answer rather than an approximate one."
        | AcceptRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | AcceptRefusal.UnmeasuredCopyOutFault listener ->
            $"socket %O{listener} has a connection to hand over, so this call takes it off the queue and copies the peer address out -- but the destination is unmapped, so that copy faults. Measured, Linux stores the untruncated length in the caller's length cell, answers EFAULT and loses the connection, while Darwin ignores the fault and succeeds; this kernel's accept has no outcome for either."
        | AcceptRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal
        | AcceptRefusal.SignalBesideConsumedWake listener ->
            $"an accept woken by a connection on the listener open file description %O{listener} names has a signal with a handler deliverable to its thread, and another thread is asleep in an accept on the same listener. Measured on Darwin (docs/probes/first-wake), the woken accept fails with EINTR and the connection stays queued without waking the other accepter. This kernel wakes a sleeping accept for as long as a connection is queued, so it would wake the other."
        | AcceptRefusal.DarwinDrainedListener listener ->
            $"socket %O{listener} is a listener on which a close of the descriptor an accept was asleep through has ended every accept, and this accept would sleep on it. Measured on Darwin (close-ends-call.c section A7), such a sleep answers ECONNABORTED as soon as anything wakes it, a connection or a signal, and one connection wakes one such sleeper, the connection staying queued, so a second sleeper sleeps on through it. This kernel wakes a sleeping accept for as long as a connection is queued, so it would wake every such sleeper for one connection."
        | AcceptRefusal.FlagsNotProvided flavour ->
            $"the call carries flags, and this kernel is %O{flavour}-flavoured; only Linux has accept4, so no program could have made the call."
        | AcceptRefusal.LengthContradictsDestination true ->
            "the destination is NULL, which neither flavour reads the length cell for, yet the call supplies the length the cell holds. Pass no length."
        | AcceptRefusal.LengthContradictsDestination false ->
            "the destination is not NULL, so the kernel reads the caller's length cell, yet the call supplies no length. Pass the 32-bit word the cell holds."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : AcceptRefusal) : RefusalKind =
        match refusal with
        | AcceptRefusal.DescriptorLimit _ -> RefusalKind.Unmodelled
        | AcceptRefusal.UnmodelledDomain _ -> RefusalKind.Unmodelled
        | AcceptRefusal.UnmeasuredKind _ -> RefusalKind.Unmodelled
        | AcceptRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | AcceptRefusal.UnmeasuredCopyOutFault _ -> RefusalKind.Unmodelled
        | AcceptRefusal.Interruption inner -> SyscallInterruptionRefusal.kind inner
        | AcceptRefusal.DarwinDrainedListener _ -> RefusalKind.Unmodelled
        | AcceptRefusal.SignalBesideConsumedWake _ -> RefusalKind.Unmodelled
        | AcceptRefusal.FlagsNotProvided _ -> RefusalKind.NotOnPlatform
        | AcceptRefusal.LengthContradictsDestination _ -> RefusalKind.Contradictory "declaredLength"

/// What an `accept4` flag word asks of the socket the call makes.
type internal AcceptFlags =
    {
        /// `SOCK_NONBLOCK`: the new socket's open file description is
        /// non-blocking.
        AsksNonBlocking : bool
        /// `SOCK_CLOEXEC`: the new descriptor has `FD_CLOEXEC`.
        AsksCloseOnExec : bool
    }

[<RequireQualifiedAccess>]
module internal AcceptFlags =
    /// Linux's `accept4` flag word `flags`, or `None` if it carries a bit other
    /// than `SOCK_NONBLOCK` and `SOCK_CLOEXEC`.
    let ofLinux (flags : int) : AcceptFlags option =
        if
            flags
            &&& ~~~(OpenFlagNumbering.LinuxNonBlock ||| OpenFlagNumbering.LinuxCloseOnExec)
            <> 0
        then
            None
        else
            Some
                {
                    AsksNonBlocking = flags &&& OpenFlagNumbering.LinuxNonBlock <> 0
                    AsksCloseOnExec = flags &&& OpenFlagNumbering.LinuxCloseOnExec <> 0
                }

/// Where an `accept` copies the peer address out to, as its two pointers say.
[<RequireQualifiedAccess>]
type internal AcceptDestination =
    /// The address pointer is NULL. Neither flavour copies an address or reads
    /// or writes the length cell then.
    | Null
    /// Any other address pointer, never NULL, and the 32-bit word the caller's
    /// length cell holds.
    | Buffer of destination : UserBuffer * declaredLength : uint32

[<RequireQualifiedAccess>]
module internal AcceptDestination =
    /// The destination a call names by `destination` and `declaredLength`,
    /// which is `None` exactly when `destination` is NULL.
    let parse (destination : UserBuffer) (declaredLength : uint32 option) : Result<AcceptDestination, AcceptRefusal> =
        match destination, declaredLength with
        | UserBuffer.Unmapped 0UL, None -> Ok AcceptDestination.Null
        | UserBuffer.Unmapped 0UL, Some _ -> Error (AcceptRefusal.LengthContradictsDestination true)
        | _, Some declaredLength -> Ok (AcceptDestination.Buffer (destination, declaredLength))
        | _, None -> Error (AcceptRefusal.LengthContradictsDestination false)

/// What `shutdown(2)` answered.
[<RequireQualifiedAccess>]
type ShutdownAnswer =
    /// 0.
    | Shut
    /// -1, with this errno.
    | Failed of error : UnixError

/// Why this kernel will not answer a `shutdown(2)`.
[<RequireQualifiedAccess>]
type internal ShutdownRefusal =
    /// The descriptor is a listening socket. Measured, Linux's `SHUT_RD` and
    /// `SHUT_RDWR` reset every queued connection's client, wake a sleeping
    /// `accept` with EINVAL and return the listener to an idle socket that
    /// keeps its port, and Darwin answers ENOTCONN and changes nothing
    /// (`tcp-shutdown.c` in docs/plans/2026-10-08-tcp-shutdown-linger,
    /// sections U, B, E and Q); neither is modelled yet.
    | Listener of socket : SocketId
    /// The descriptor is a socket with no connection, under Linux. Linux
    /// answers ENOTCONN, as Darwin does, but still marks the sides `how`
    /// names shut, and they stay shut through a later `connect`: measured
    /// (`tcp-shutdown.c`, section U, `fresh-then` and `udp-then`), a fresh
    /// stream socket then polls IN|RDHUP after `SHUT_RD`, and its writes once
    /// connected answer EPIPE after `SHUT_WR`. This kernel keeps no shut
    /// sides on a socket without a connection.
    | LinuxUnconnected of socket : SocketId
    /// The descriptor is a datagram socket connected to a peer, whose
    /// `shutdown(2)` is unmeasured.
    | ConnectedDatagram of socket : SocketId
    /// The descriptor is a socket in a domain this kernel models no
    /// `shutdown(2)` for.
    | UnmodelledDomain of socket : SocketId * domain : SocketDomain
    /// The descriptor is a socket of a kind whose `shutdown(2)` is
    /// unmeasured.
    | UnmeasuredKind of socket : SocketId * kind : SocketKind
    /// Under Darwin, the call would shut the receive side of `socket`, the
    /// connection's end, while `unsent` bytes the peer wrote still wait in
    /// the peer's send buffer. Measured, the peer is then reset only when a
    /// TCP timer fires, at a time that varied between runs, or not within
    /// 15 s (`tcp-shutdown.c`, sections R and X). This kernel delivers bytes
    /// as soon as there is room, and keeps no timers.
    | ReceiveShutBeforeUnsentBytes of socket : SocketId * unsent : int

[<RequireQualifiedAccess>]
module internal ShutdownRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which entry point, and which descriptor.
    let describe (refusal : ShutdownRefusal) : string =
        match refusal with
        | ShutdownRefusal.Listener socket ->
            $"the descriptor is socket %O{socket}, which is listening. Measured, Linux's SHUT_RD and SHUT_RDWR reset the clients of every queued connection, wake a sleeping accept with EINVAL and leave the socket idle with its port, while Darwin answers ENOTCONN and changes nothing; this kernel does not yet model either."
        | ShutdownRefusal.LinuxUnconnected socket ->
            $"the descriptor is socket %O{socket}, which has no connection. Linux answers ENOTCONN, but still marks the sides it was asked to shut, and they stay shut through a later connect: measured, a fresh stream socket then polls IN|RDHUP after SHUT_RD, and its writes once connected answer EPIPE after SHUT_WR. This kernel keeps no shut sides on a socket without a connection."
        | ShutdownRefusal.ConnectedDatagram socket ->
            $"the descriptor is socket %O{socket}, a datagram socket connected to a peer, and what shutdown(2) does to one is unmeasured."
        | ShutdownRefusal.UnmodelledDomain (socket, domain) ->
            $"the descriptor is socket %O{socket}, whose domain is %O{domain}, and this kernel models shutdown(2) only for IPv4 and IPv6 sockets."
        | ShutdownRefusal.UnmeasuredKind (socket, kind) ->
            $"the descriptor is socket %O{socket}, which is a %O{kind} socket, and what shutdown(2) does to one is unmeasured."
        | ShutdownRefusal.ReceiveShutBeforeUnsentBytes (socket, unsent) ->
            $"the call would shut the receive side of socket %O{socket} while %d{unsent} bytes its peer wrote still wait in the peer's send buffer. Measured on Darwin, the peer is then reset only when a TCP timer fires, at a time that varied between runs, or not within 15 s; this kernel delivers bytes as soon as there is room, and keeps no timers."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ShutdownRefusal) : RefusalKind =
        match refusal with
        | ShutdownRefusal.Listener _ -> RefusalKind.Unmodelled
        | ShutdownRefusal.LinuxUnconnected _ -> RefusalKind.Unmodelled
        | ShutdownRefusal.ConnectedDatagram _ -> RefusalKind.Unmodelled
        | ShutdownRefusal.UnmodelledDomain _ -> RefusalKind.Unmodelled
        | ShutdownRefusal.UnmeasuredKind _ -> RefusalKind.Unmodelled
        | ShutdownRefusal.ReceiveShutBeforeUnsentBytes _ -> RefusalKind.Unmodelled

/// Why this kernel will not answer a `connect(2)` at all: the call reached an
/// input whose real answer is unmeasured, or a state this library does not
/// model. The client decides what a refusal means for it; nothing here is
/// recoverable by retrying the same call.
///
/// A `SocketAddress` a case carries is a `SocketAddress.Inet`, even from a
/// dual-mode IPv6 socket: the IPv4 transport endpoint the connect resolved,
/// not the v4-mapped address the socket would present it as.
[<RequireQualifiedAccess>]
type internal ConnectRefusal =
    /// The sockaddr copy could not be admitted.
    | Copy of SockaddrCopyRefusal
    /// A seqpacket socket, whose `connect(2)` is unmeasured.
    | UnmeasuredKind of socket : SocketId * kind : SocketKind
    /// The socket has no concrete source address and the destination is not
    /// loopback, and which source a kernel resolves for it is unmeasured.
    /// `boundToWildcard` says whether the socket was bound to the wildcard or
    /// not bound at all.
    | SourceForNonLoopbackDestination of socket : SocketId * destination : SocketAddress * boundToWildcard : bool
    /// The implicit bind found every port in the ephemeral range taken, on a
    /// Darwin socket or a datagram socket: Linux answers a stream socket's
    /// `EADDRNOTAVAIL`. Darwin answers `EADDRNOTAVAIL` too, measured, but this
    /// kernel's search can pass over a port Darwin's would take; what a
    /// datagram socket's connect answers is unmeasured.
    | EphemeralPortsExhausted of range : uint16 * uint16
    /// The destination is not an address of this machine, and this library
    /// models no network to carry a packet anywhere else.
    | DestinationNotLocal of destination : SocketAddress * kind : SocketKind
    /// A stream connect to an address on one of this machine's local routes
    /// that the machine does not hold, which Darwin routes to itself and then
    /// drops the SYN to: the connect waits on TCP's connection timer, which
    /// this library does not model.
    | UnheldDestination of destination : SocketAddress
    /// The listener's accept queue is at its measured capacity. Linux drops the
    /// SYN and the client retransmits it on a timer, so a blocking connect
    /// sleeps (`ParkedSyscall.Connect`, reserved); Darwin evicts a queued
    /// connection or resets this one (measured, `docs/probes/connect-park`).
    | AcceptQueueFull of listener : SocketId * destination : SocketAddress * queued : int
    /// The resolved source equals the destination while a listener matched,
    /// which only a reuse-bound client can engineer; unmeasured.
    | SelfTuple of endpoint : SocketAddress
    /// A connection between this source and destination already exists, or,
    /// under Darwin, another datagram socket is connected from this source to
    /// this destination, and how a kernel refuses the duplicate four-tuple is
    /// unmeasured.
    | DuplicateFourTuple of source : SocketAddress * destination : SocketAddress
    /// A Linux socket whose non-blocking connect completed, and whose
    /// connection was then reset before any connect reported the completion.
    /// Linux's retry would answer the reset's pending error, or ECONNABORTED
    /// once it is taken, and disconnect the socket; unmeasured.
    | ResetBeforeReport of socket : SocketId
    /// Under Linux, the destination is the socket's own address, whether
    /// `bind(2)` gave it or the connect's own implicit bind did, with nothing
    /// listening: TCP simultaneous open, which is unmodelled.
    | SimultaneousOpen of destination : SocketAddress
    /// Darwin drops the SYN to a bound but unlistened port, and the connect
    /// pends on a retransmission schedule this library cannot honour.
    | DarwinSynDropped of destination : SocketAddress
    /// `AF_UNSPEC` on a Linux stream socket in a phase other than idle, whose
    /// `tcp_disconnect` consequences are unmeasured.
    | LinuxUnspecOnPhase of socket : SocketId * phase : SocketPhase
    /// A datagram connect to the broadcast address or a multicast group that
    /// would succeed. This library models no group membership and no
    /// interface to broadcast on, so it does not record such a peer.
    | DatagramGroupDestination of socket : SocketId * destination : SocketAddress
    /// An IPv6 socket would connect to an IPv6 address that is not v4-mapped,
    /// which needs an IPv6 transport this kernel does not have. `destination`
    /// is the `struct sockaddr_in6` the caller passed; its scope id is 0 if
    /// the caller's length stopped short of `sin6_scope_id`, as Linux reads
    /// such a length.
    | Ipv6Destination of socket : SocketId * destination : Ipv6Endpoint
    /// Whether an end in TIME_WAIT stands in the way of the port the
    /// connect's implicit bind would take, or what the connect does to an
    /// end in TIME_WAIT on its four-tuple, is unmeasured.
    | TimeWait of refusal : TimeWaitRefusal

[<RequireQualifiedAccess>]
module internal ConnectRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half -- which entry point, and which caller could have asked.
    let describe (refusal : ConnectRefusal) : string =
        match refusal with
        | ConnectRefusal.Copy refusal -> SockaddrCopyRefusal.describe refusal
        | ConnectRefusal.UnmeasuredKind (socket, kind) ->
            $"socket %O{socket} is a %O{kind} socket, and what connect(2) does for one is unmeasured, so measure it rather than guessing."
        | ConnectRefusal.SourceForNonLoopbackDestination (socket, destination, boundToWildcard) ->
            if boundToWildcard then
                $"socket %O{socket} is bound to the wildcard and is connecting to %s{SocketAddress.toString destination}, and which source address a kernel resolves the wildcard to for a destination other than 127.0.0.1 is unmeasured. Bind to a concrete address first, or connect to 127.0.0.1."
            else
                $"socket %O{socket} is unbound and is connecting to %s{SocketAddress.toString destination}, and which source address a kernel picks for a destination other than 127.0.0.1 is unmeasured. Bind the socket first, or connect to 127.0.0.1."
        | ConnectRefusal.EphemeralPortsExhausted (low, high) ->
            $"every port in the ephemeral range %d{low}-%d{high} is taken, so this implicit bind has no answer here. Darwin answers EADDRNOTAVAIL (measured), but this kernel's search can pass over a port Darwin's would take; what a Darwin datagram socket's connect answers is unmeasured, as is what a Linux one answers when its address is of the wrong family or length. Widen the machine's EphemeralPortRange."
        | ConnectRefusal.DestinationNotLocal (destination, kind) ->
            let carried =
                match kind with
                | SocketKind.Stream -> "a SYN"
                | SocketKind.Datagram -> "a datagram"
                | SocketKind.SeqPacket -> "a packet"

            $"destination %s{SocketAddress.toString destination} is not a local address of this simulated machine, and this library models no network to carry %s{carried} anywhere else. Add the address to the kernel's LocalIpv4Addresses/LocalRoutes if it should be local, or connect to loopback."
        | ConnectRefusal.UnheldDestination destination ->
            $"destination %s{SocketAddress.toString destination} is on one of this machine's local routes but is not an address it holds. Darwin routes the SYN to itself and drops it, so the connect waits: a blocking one until TCP's connection timer gives ETIMEDOUT (measured after 170 s), a non-blocking one answering EINPROGRESS and then nothing. This library has no TCP timers to end that wait. Connect to an address the machine holds."
        | ConnectRefusal.AcceptQueueFull (listener, destination, queued) ->
            $"the accept queue of listener %O{listener} at %s{SocketAddress.toString destination} already holds %d{queued} connections, its measured capacity. Linux drops the SYN, and the client retransmits it on a timer: a blocking connect sleeps until a retransmit finds room, which this library does not model yet, and a non-blocking one is left in progress. Darwin evicts a queued connection or resets this one, by a choice nothing here decides. So this connect has no faithful answer. Accept from the listener before connecting again, or listen with a larger backlog."
        | ConnectRefusal.SelfTuple endpoint ->
            $"the resolved source %s{SocketAddress.toString endpoint} equals the destination, with a listener present. What a real kernel does with this self-tuple (plausibly EINVAL on Darwin, a completed self-connect on Linux) is unmeasured, so measure it rather than guessing."
        | ConnectRefusal.DuplicateFourTuple (source, destination) ->
            $"a connection from %s{SocketAddress.toString source} to %s{SocketAddress.toString destination} already exists, and a real kernel refuses a duplicate four-tuple in ways that are unmeasured (plausibly EADDRINUSE at connect time). Measure it rather than guessing."
        | ConnectRefusal.ResetBeforeReport socket ->
            $"socket %O{socket}'s non-blocking connect completed, and its connection was reset before any connect reported the completion. Linux's retry finds the socket closed and answers the reset's pending error, or ECONNABORTED once an SO_ERROR read has taken it, and disconnects the socket, as for a refused connect; what that leaves of the socket's binding is unmeasured."
        | ConnectRefusal.SimultaneousOpen destination ->
            $"destination %s{SocketAddress.toString destination} is this socket's own address, from bind(2) or from the port this connect's implicit bind took, and nothing is listening there. Linux completes this as a TCP simultaneous open -- connecting the socket to itself -- which this library does not model."
        | ConnectRefusal.DarwinSynDropped destination ->
            $"destination %s{SocketAddress.toString destination} is bound but nothing is listening there, and Darwin *drops* such a SYN rather than answering RST: the connect pends on the client's retransmission schedule (a blocking one was measured to stall into ETIMEDOUT), which this library cannot honour deterministically. Listen on the destination socket, or connect to a fully closed port."
        | ConnectRefusal.LinuxUnspecOnPhase (socket, phase) ->
            $"AF_UNSPEC on stream socket %O{socket} in %A{phase} under Linux runs tcp_disconnect, whose consequences for this phase (a connected socket's peer, a listener's queue) are unmeasured and unmodelled."
        | ConnectRefusal.Ipv6Destination (socket, destination) ->
            $"IPv6 socket %O{socket} would connect to %s{Ipv6Endpoint.toString destination}. This kernel has no IPv6 transport: an IPv6 socket reaches only IPv4 peers, through v4-mapped addresses (::ffff:a.b.c.d), with IPV6_V6ONLY off."
        | ConnectRefusal.TimeWait refusal -> TimeWaitRefusal.describe refusal
        | ConnectRefusal.DatagramGroupDestination (socket, destination) ->
            $"datagram socket %O{socket} would connect to %s{SocketAddress.toString destination}, a broadcast or multicast destination. This kernel models no group membership and no interface to broadcast on, so it does not record such a peer. Model multicast and broadcast before connecting to either."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : ConnectRefusal) : RefusalKind =
        match refusal with
        | ConnectRefusal.Copy inner -> SockaddrCopyRefusal.kind inner
        | ConnectRefusal.UnmeasuredKind _ -> RefusalKind.Unmodelled
        | ConnectRefusal.SourceForNonLoopbackDestination _ -> RefusalKind.Unmodelled
        | ConnectRefusal.EphemeralPortsExhausted _ -> RefusalKind.Unmodelled
        | ConnectRefusal.DestinationNotLocal _ -> RefusalKind.Unmodelled
        | ConnectRefusal.UnheldDestination _ -> RefusalKind.Unmodelled
        | ConnectRefusal.AcceptQueueFull _ -> RefusalKind.Unmodelled
        | ConnectRefusal.SelfTuple _ -> RefusalKind.Unmodelled
        | ConnectRefusal.DuplicateFourTuple _ -> RefusalKind.Unmodelled
        | ConnectRefusal.ResetBeforeReport _ -> RefusalKind.Unmodelled
        | ConnectRefusal.SimultaneousOpen _ -> RefusalKind.Unmodelled
        | ConnectRefusal.DarwinSynDropped _ -> RefusalKind.Unmodelled
        | ConnectRefusal.LinuxUnspecOnPhase _ -> RefusalKind.Unmodelled
        | ConnectRefusal.DatagramGroupDestination _ -> RefusalKind.Unmodelled
        | ConnectRefusal.Ipv6Destination _ -> RefusalKind.Unmodelled
        | ConnectRefusal.TimeWait refusal -> TimeWaitRefusal.kind refusal

/// What `connect(2)`'s ladder reads out of the sockaddr it copied in, from a
/// `struct sockaddr_in` on an IPv4 socket and a `struct sockaddr_in6` on an
/// IPv6 one.
type internal ConnectAddress =
    {
        /// `sa_family`, in the platform's own numbering, when the copy reached
        /// it.
        Family : int option
        /// The family of the socket's own struct: `AF_INET` on an IPv4 socket
        /// and `AF_INET6` on an IPv6 one.
        OwnFamily : int
        /// What the platform makes of the declared length for the socket's own
        /// struct.
        LengthVerdict : BindLengthVerdict
        /// The IPv4 destination, a v4-mapped one on an IPv6 socket, when the
        /// copy reached it.
        Destination : Ipv4Endpoint option
        /// On an IPv6 socket, a destination that is not v4-mapped.
        NativeDestination : Ipv6Endpoint option
        /// The IPv4 address read with every byte past the copy as zero, which
        /// Darwin judges a broadcast or multicast destination by; `Ipv4Address.any` for a
        /// native IPv6 destination.
        ZeroFilledAddress : Ipv4Address
    }

/// A `connect(2)` stopped where the kernel copies the caller's
/// `struct sockaddr` in: `UnixConnection.connect` answers it,
/// `PausedConnect.copyRange` says which bytes of the address buffer to copy,
/// and `UnixConnection.connectWithAddress` takes them and finishes the call.
[<NoEquality ; NoComparison>]
type PausedConnect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            /// The thread that made the call, which the rest of it is made by.
            Thread : 'Thread
            Fd : int
            Address : UserBuffer
            DeclaredLength : uint32
            Range : CopyRange
            /// The system the call was made in: everything a `connect` does
            /// before the copy is a question.
            System : ProcessView<'Thread, 'Handler>
        }

[<RequireQualifiedAccess>]
module PausedConnect =
    /// The bytes of the address buffer the kernel copies: what
    /// `UnixConnection.connectWithAddress` takes. Always from the start of the
    /// buffer, and the whole of the length the caller declared, as far as the
    /// kernel reads one.
    let copyRange<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (paused : PausedConnect<'Thread, 'Handler>)
        : CopyRange
        =
        paused.Range

[<RequireQualifiedAccess>]
module UnixConnection =

    /// `connection`, completing now on `listener`, as its accept queue holds
    /// it: with the options the socket `accept(2)` makes for it will hold.
    ///
    /// Those are the listener's as they stand, copied now, as both kernels
    /// copy them onto the connection's server end as it completes
    /// (inet_csk_clone_lock; sonewconn). Darwin's `tcp_attach` then gives a
    /// socket made lingering for no time `TCP_LINGERTIME`, 120 seconds.
    /// Measured on both
    /// (`docs/plans/2026-10-08-tcp-shutdown-linger/queued-options.c`).
    let private queuedOn
        (flavour : SimulatedUnixFlavour)
        (listener : SocketDescription)
        (connection : ConnectionId)
        : QueuedConnection
        =
        let linger =
            match flavour with
            | SimulatedUnixFlavour.Darwin when
                listener.Options.Linger.Enabled && listener.Options.Linger.Hundredths = 0L
                ->
                {
                    Enabled = true
                    Hundredths = 12000L
                }
            | SimulatedUnixFlavour.Darwin
            | SimulatedUnixFlavour.Linux -> listener.Options.Linger

        {
            Connection = connection
            ReuseAddress = listener.ReuseAddress
            Options =
                { listener.Options with
                    Linger = linger
                }
        }

    /// `connect(2)` past the descriptor screens and the copy-in: the
    /// per-flavour ladder over the socket's phase, the declared length, the
    /// sockaddr's family, and the destination, for the sockaddr `copied`
    /// decodes to.
    ///
    /// Every answered row is measured (`connect_probe.c` and successors,
    /// 2026-08-21;
    /// https://github.com/Smaug123/WoofWare.PawPrint/blob/6b4aeb4fce455e8c187157ce020d1058fb0821bf/docs/plans/2026-08-21-socket-connect.md
    /// holds the table);
    /// a `ConnectRefusal` names an unmeasured or unmodellable input, and a
    /// throw is a bug in this library or in the caller's state construction.
    let internal connectDecoded<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (nonBlocking : bool)
        (declaredLength : uint32)
        (address : ConnectAddress)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
        =
        let family = address.Family
        let destination = address.Destination
        let ownFamily = address.OwnFamily
        let sock = UnixMachineState.socket socketId system.Machine
        let platform = system.Machine.UnixPlatform
        let flavour = SimulatedUnixPlatform.flavour platform
        let lengthVerdict = address.LengthVerdict

        // An IPv6 socket's connect to a native IPv6 address, which needs an
        // IPv6 transport, refused at the point the ladder would use it.
        let nativeDestination () : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal> option =
            address.NativeDestination
            |> Option.map (fun destination -> Error (ConnectRefusal.Ipv6Destination (socketId, destination)))

        // An IPv6 socket with IPV6_V6ONLY on reaches no IPv4 destination, and
        // binds nothing on the way: measured on both, at every v4-mapped
        // address including a group one and port 0 (`docs/probes/dual-mode/`,
        // A3 and G).
        let ipv6Only () : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal> option =
            match sock.Addressing, nativeDestination () with
            | SocketAddressing.Inet6V6Only _, None ->
                Some (Ok (SyscallAnswer.Failed (SimulatedUnixPlatform.ipv6OnlyConnectError platform), system))
            | SocketAddressing.Inet6V6Only _, Some native -> Some native
            | (SocketAddressing.Inet _ | SocketAddressing.Inet6DualMode _ | SocketAddressing.Unix _), _ -> None

        let declaredLength = int declaredLength

        let fail (error : UnixError) : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal> =
            Ok (SyscallAnswer.Failed error, system)

        let failed
            (error : UnixError)
            (system : ProcessView<'Thread, 'Handler>)
            : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
            =
            Ok (SyscallAnswer.Failed error, system)

        let completed
            (system : ProcessView<'Thread, 'Handler>)
            : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
            =
            Ok (SyscallAnswer.Completed 0L, system)

        let withPhase (phase : SocketPhase) (system : ProcessView<'Thread, 'Handler>) : ProcessView<'Thread, 'Handler> =
            { system with
                Machine =
                    { system.Machine with
                        Sockets =
                            Map.add
                                socketId
                                { sock with
                                    Phase = phase
                                }
                                system.Machine.Sockets
                    }
            }

        // A wildcard destination: Linux aims at the socket's own local
        // address when it has a concrete one, and at loopback otherwise; Darwin
        // aims at loopback. Measured for stream and datagram sockets alike
        // (`sockaddr-dgram-reconnect.c`, and `sockaddr-dgram-connect.c`, D, for
        // a socket with no concrete address).
        let resolveWildcard (dest : Ipv4Endpoint) : Ipv4Endpoint =
            if dest.Address <> Ipv4Address.any then
                dest
            else

            let address =
                match flavour, sock.Ipv4Binding with
                | SimulatedUnixFlavour.Linux, Some binding when binding.Endpoint.Address <> Ipv4Address.any ->
                    binding.Endpoint.Address
                | SimulatedUnixFlavour.Linux, _
                | SimulatedUnixFlavour.Darwin, _ -> Ipv4Address.loopback

            { dest with
                Address = address
            }

        let destinationIsLocal (address : Ipv4Address) : bool =
            List.contains address system.Machine.LocalIpv4Addresses
            || system.Machine.LocalRoutes |> List.exists (Ipv4Prefix.contains address)

        // What a refusal delivery leaves in the socket's binding. Measured
        // for all three provenances (implicit, bind(2) to 127.0.0.1, bind(2)
        // to 0.0.0.0): Darwin keeps the resolved source; Linux's reset
        // reverts the address to whatever bind(2) locked — the wildcard when
        // the address only ever came from source resolution — while keeping
        // the port.
        let bindingAfterRefusalDelivery (flavour : SimulatedUnixFlavour) (binding : Ipv4Binding) : Ipv4Binding =
            match flavour with
            | SimulatedUnixFlavour.Darwin -> binding
            | SimulatedUnixFlavour.Linux ->
                { binding with
                    Endpoint =
                        { binding.Endpoint with
                            Address = binding.LockedAddress |> Option.defaultValue Ipv4Address.any
                        }
                }

        // What the refusal itself does to the binding, as it arrives and
        // whether or not anything has reported it yet: it gives the port back
        // by the platform's rule, and getsockname goes on reporting it.
        let bindingOnRefusal (binding : Ipv4Binding) : Ipv4Binding =
            if SimulatedUnixPlatform.refusalReleasesPort system.Machine.UnixPlatform binding.LockedPort then
                { binding with
                    PortHold = PortHold.GivenBack
                }
            else
                binding

        // The source a connect from a socket with no concrete address resolves
        // towards `destination`, where it is measured: 127.0.0.1, towards
        // 127.0.0.1 itself or towards another address in loopback's
        // 127.0.0.0/8 that the machine does not hold (measured on both
        // flavours, `docs/probes/loopback-alias-connect`, the rows ending in
        // f, w and c: towards 127.0.0.2, from a fresh socket and from one bound
        // to 0.0.0.0:0). Towards an address the machine holds besides
        // 127.0.0.1, and off loopback, the source is the route's preferred
        // source, which is unmeasured.
        let resolvedSource (destination : Ipv4Address) : Ipv4Address option =
            let machine = system.Machine

            if destination = Ipv4Address.loopback then
                Some Ipv4Address.loopback
            elif
                Ipv4Prefix.contains destination Ipv4Prefix.loopbackNetwork
                && not (List.contains destination machine.LocalIpv4Addresses)
                && List.contains Ipv4Address.loopback machine.LocalIpv4Addresses
            then
                Some Ipv4Address.loopback
            else
                None

        // connect(2)'s implicit bind, when the socket has no local address
        // yet: the source `resolvedSource` gives, and an ephemeral port by the
        // connect search's rule (`PortHolderRules.connectSearchMeets`). A
        // destination it gives no source for is refused. `current` is the
        // binding the source is resolved from, which is the socket's own
        // unless the connect has already reset it.
        let ensureBoundFrom
            (current : Ipv4Binding option)
            (dest : Ipv4Endpoint)
            (system : ProcessView<'Thread, 'Handler>)
            : Result<Ipv4Binding * ProcessView<'Thread, 'Handler>, ConnectRefusal>
            =
            match current with
            | Some binding when not (PortHold.isHeld binding.PortHold) ->
                // A Linux refused connect gave the port back, and the socket
                // connects as one with no port: a new port, at the binding's
                // address, which a wildcard resolves to loopback (measured,
                // `docs/probes/refused-connect-port`, the rows ending in 4).
                // Darwin's refused socket never connects again.
                let address =
                    if binding.Endpoint.Address <> Ipv4Address.any then
                        Some binding.Endpoint.Address
                    // Only towards 127.0.0.1 is the source measured for a
                    // socket whose refusal gave its port back.
                    elif dest.Address = Ipv4Address.loopback then
                        Some Ipv4Address.loopback
                    else
                        None

                match address with
                | None ->
                    Error (ConnectRefusal.SourceForNonLoopbackDestination (socketId, SocketAddress.Inet dest, true))
                | Some address ->

                let candidate (port : uint16) : Ipv4Binding =
                    { binding with
                        Endpoint = Ipv4Endpoint.ofParts address port
                        PortHold = PortHold.Connected
                    }

                match
                    UnixMachineState.allocateEphemeralPort
                        system.Scheduling.NanosecondsSinceBoot
                        (EphemeralPortUse.ConnectTo dest)
                        socketId
                        sock
                        candidate
                        system.Machine
                with
                | Ok (Some (binding, machine)) ->
                    Ok (
                        binding,
                        { system with
                            Machine = machine
                        }
                    )
                | Ok None -> Error (ConnectRefusal.EphemeralPortsExhausted system.Machine.EphemeralPortRange)
                | Error refusal -> Error (ConnectRefusal.TimeWait refusal)
            | Some binding when binding.Endpoint.Port = 0us ->
                // Half-bound: a datagram dissolve kept the locked address and
                // dropped the port. Linux's `inet_autobind` gives it a port and
                // keeps the address -- measured, `127.0.0.1:0` connects from
                // `127.0.0.1:<ephemeral>`. Only a concrete locked address is
                // ever left half-bound, so the wildcard case does not arise.
                let candidate (port : uint16) : Ipv4Binding =
                    { binding with
                        Endpoint =
                            { binding.Endpoint with
                                Port = port
                            }
                    }

                match
                    UnixMachineState.allocateEphemeralPort
                        system.Scheduling.NanosecondsSinceBoot
                        (EphemeralPortUse.ConnectTo dest)
                        socketId
                        sock
                        candidate
                        system.Machine
                with
                | Ok (Some (binding, machine)) ->
                    Ok (
                        binding,
                        { system with
                            Machine = machine
                        }
                    )
                | Ok None -> Error (ConnectRefusal.EphemeralPortsExhausted system.Machine.EphemeralPortRange)
                | Error refusal -> Error (ConnectRefusal.TimeWait refusal)
            | Some binding when binding.Endpoint.Address <> Ipv4Address.any -> Ok (binding, system)
            | Some binding ->
                // A client bound to the wildcard gets a concrete source
                // address at connect — measured on both kernels, TCP and UDP
                // alike: the address becomes 127.0.0.1 for a loopback
                // destination and the port is kept, and getsockname reports
                // the rewrite afterwards, so the *binding* itself changes
                // rather than merely the connection's record of it. Which
                // source a kernel picks for any other destination is
                // unmeasured.
                match resolvedSource dest.Address with
                | None ->
                    Error (ConnectRefusal.SourceForNonLoopbackDestination (socketId, SocketAddress.Inet dest, true))
                | Some source ->

                Ok (
                    { binding with
                        Endpoint =
                            { binding.Endpoint with
                                Address = source
                            }
                    },
                    system
                )
            | None ->

            match resolvedSource dest.Address with
            | None -> Error (ConnectRefusal.SourceForNonLoopbackDestination (socketId, SocketAddress.Inet dest, false))
            | Some source ->

            let candidateAt (address : Ipv4Address) (port : uint16) : Ipv4Binding =
                {
                    Endpoint = Ipv4Endpoint.ofParts address port
                    // No bind(2) ran: a Linux refusal delivery reverts the
                    // address all the way to the wildcard.
                    LockedAddress = None
                    LockedPort = false
                    PortHold =
                        match sock.Kind with
                        | SocketKind.Stream -> PortHold.Connected
                        | SocketKind.Datagram
                        | SocketKind.SeqPacket -> PortHold.Reserved
                }

            // Linux binds a datagram socket to the wildcard and a port, as
            // bind(2) of port 0 would, before it resolves the source, so the
            // search for the port is made at the wildcard (measured,
            // `docs/probes/port-sharing`, the connect rows: a holder at
            // 127.0.0.2 stands in the way of a connect to 127.0.0.1).
            let searchedAtWildcard =
                flavour = SimulatedUnixFlavour.Linux && sock.Kind = SocketKind.Datagram

            let purpose, searchedAt =
                if searchedAtWildcard then
                    EphemeralPortUse.Reserve, Ipv4Address.any
                else
                    EphemeralPortUse.ConnectTo dest, Ipv4Address.loopback

            match
                UnixMachineState.allocateEphemeralPort
                    system.Scheduling.NanosecondsSinceBoot
                    purpose
                    socketId
                    sock
                    (candidateAt searchedAt)
                    system.Machine
            with
            | Ok (Some (binding, machine)) ->
                Ok (
                    { binding with
                        Endpoint = Ipv4Endpoint.ofParts Ipv4Address.loopback binding.Endpoint.Port
                    },
                    { system with
                        Machine = machine
                    }
                )
            | Ok None -> Error (ConnectRefusal.EphemeralPortsExhausted system.Machine.EphemeralPortRange)
            | Error refusal -> Error (ConnectRefusal.TimeWait refusal)


        let ensureBound
            (dest : Ipv4Endpoint)
            (system : ProcessView<'Thread, 'Handler>)
            : Result<Ipv4Binding * ProcessView<'Thread, 'Handler>, ConnectRefusal>
            =
            ensureBoundFrom sock.Ipv4Binding dest system

        // The ends in TIME_WAIT on the four-tuple from `source` to `dest`, as a
        // stream connect meets them once its source is settled, measured on
        // both (`docs/probes/time-wait`, tw-reuse.c rows E, V, Z, Q and Y).
        // One at the destination, towards the source, ends, and the connect
        // goes ahead. One at the source, towards the destination, is taken
        // over and ends under Linux, and makes Darwin's connect fail with
        // EADDRINUSE (`Ok (Error errno)`), leaving the socket as it was. A
        // search reaches it only where Linux's takes the four-tuple over,
        // which the rule for a socket bound there answers the same way.
        let overTimeWaits
            (source : Ipv4Endpoint)
            (dest : Ipv4Endpoint)
            (system : ProcessView<'Thread, 'Handler>)
            : Result<Result<ProcessView<'Thread, 'Handler>, UnixError>, ConnectRefusal>
            =
            let machine = UnixMachineState.endTimeWait dest source system.Machine

            match UnixMachineState.timeWaitOn source dest machine with
            | None ->
                Ok (
                    Ok
                        { system with
                            Machine = machine
                        }
                )
            | Some timeWait ->

            let clock =
                UnixMachineState.timeWaitClock system.Scheduling.NanosecondsSinceBoot machine

            match PortHolderRules.boundConnectOverTimeWait flavour clock timeWait with
            | Error refusal -> Error (ConnectRefusal.TimeWait refusal)
            | Ok TimeWaitTakeover.AddressInUse -> Ok (Error UnixError.EADDRINUSE)
            | Ok TimeWaitTakeover.TakesOver ->
                Ok (
                    Ok
                        { system with
                            Machine = UnixMachineState.endTimeWait source dest machine
                        }
                )

        // A stream connect's implicit bind, with the answer the platform gives
        // where it finds every port taken (`Ok (Error errno)`), which leaves the
        // socket as it was.
        let ensureStreamBound
            (dest : Ipv4Endpoint)
            (system : ProcessView<'Thread, 'Handler>)
            : Result<Result<Ipv4Binding * ProcessView<'Thread, 'Handler>, UnixError>, ConnectRefusal>
            =
            match ensureBound dest system with
            | Ok bound -> Ok (Ok bound)
            | Error (ConnectRefusal.EphemeralPortsExhausted (low, high)) ->
                match
                    SimulatedUnixPlatform.ephemeralPortsExhausted
                        system.Machine.UnixPlatform
                        EphemeralSearchCall.Connect
                with
                | Some error -> Ok (Error error)
                | None -> Error (ConnectRefusal.EphemeralPortsExhausted (low, high))
            | Error refusal -> Error refusal

        // The established/refused attempt, shared by both flavours once the
        // per-flavour screens have let an idle stream socket through.
        let attemptStream
            (dest : Ipv4Endpoint)
            : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
            =
            let dest = resolveWildcard dest

            if not (destinationIsLocal dest.Address) then
                Error (ConnectRefusal.DestinationNotLocal (SocketAddress.Inet dest, SocketKind.Stream))
            elif
                not (
                    SimulatedUnixPlatform.receivesStreamAt
                        system.Machine.UnixPlatform
                        system.Machine.LocalIpv4Addresses
                        system.Machine.LocalRoutes
                        dest.Address
                )
            then
                Error (ConnectRefusal.UnheldDestination (SocketAddress.Inet dest))
            else

            let listeners =
                system.Machine.Sockets
                |> Map.toList
                |> List.choose (fun (otherId, other) ->
                    match other.Phase with
                    | SocketPhase.Listening listenState ->
                        match other.Ipv4Binding with
                        | Some binding when
                            other.Kind = SocketKind.Stream
                            && binding.Endpoint.Port = dest.Port
                            && (binding.Endpoint.Address = dest.Address
                                || Ipv4Endpoint.isWildcard binding.Endpoint)
                            ->
                            Some (otherId, other, listenState, binding)
                        | _ -> None
                    | _ -> None
                )

            // A specific-address listener beats the wildcard — both kernels'
            // documented most-specific-match rule. The pair can only coexist
            // under SO_REUSEADDR, so the preference is the documented rule
            // rather than a measured one.
            let listener =
                match
                    listeners
                    |> List.tryFind (fun (_, _, _, binding) -> not (Ipv4Endpoint.isWildcard binding.Endpoint))
                with
                | Some found -> Some found
                | None -> List.tryHead listeners

            match listener with
            | Some (listenerId, listenerSocket, listenState, _) ->
                // Int64, so that the Linux `+ 1` cannot wrap when the
                // configured somaxconn is itself Int32.MaxValue.
                let capacity : int64 =
                    match flavour with
                    | SimulatedUnixFlavour.Linux ->
                        // Measured, with the sysctl set to 3 to bring the
                        // boundary in reach: listen(0) admits 1, listen(1)
                        // admits 2, listen(5) admits 6, and listen(-1) and
                        // listen(INT_MAX) both admit somaxconn + 1 — the
                        // kernel compares the backlog *unsigned* against
                        // somaxconn and clamps, and the queue then admits
                        // one more than the clamped value. The clamp also
                        // keeps the `+ 1` from overflowing on the
                        // Int32.MaxValue a parameterless Socket.Listen()
                        // passes.
                        let clamped =
                            if listenState.Backlog < 0 || listenState.Backlog > system.Machine.SoMaxConn then
                                system.Machine.SoMaxConn
                            else
                                listenState.Backlog

                        int64 clamped + 1L
                    | SimulatedUnixFlavour.Darwin ->
                        // Measured at the default sysctl of 128: listen(1)
                        // admits 1, listen(5) admits 5, and listen(0),
                        // listen(-1) and listen(INT_MAX) all admit exactly
                        // somaxconn — a non-positive or over-large backlog
                        // clamps to somaxconn, and the queue admits exactly
                        // the clamped value.
                        if listenState.Backlog <= 0 || listenState.Backlog > system.Machine.SoMaxConn then
                            int64 system.Machine.SoMaxConn
                        else
                            int64 listenState.Backlog

                if int64 (List.length listenState.Queue) >= capacity then
                    Error (
                        ConnectRefusal.AcceptQueueFull (
                            listenerId,
                            SocketAddress.Inet dest,
                            List.length listenState.Queue
                        )
                    )
                else

                let asItWas = system

                match ensureStreamBound dest system with
                | Error refusal -> Error refusal
                | Ok (Error error) -> failed error system
                | Ok (Ok (clientBinding, system)) ->

                // Two corners a REUSEADDR-bound client can engineer, each
                // refused because the real answer is unmeasured.
                if clientBinding.Endpoint = dest then
                    // A wildcard listener at P beside a reuse-bound client at
                    // 127.0.0.1:P, connecting to 127.0.0.1:P: source equals
                    // destination even though a listener matched.
                    Error (ConnectRefusal.SelfTuple (SocketAddress.Inet clientBinding.Endpoint))
                elif UnixMachineState.fourTupleOccupied socketId clientBinding.Endpoint dest system.Machine then
                    // Established tuples are unique in a real kernel; a second
                    // identical (source, destination) pair — two clients
                    // reuse-bound to one source endpoint, connecting to one
                    // listener — is refused there (plausibly EADDRINUSE),
                    // which is unmeasured.
                    Error (
                        ConnectRefusal.DuplicateFourTuple (
                            SocketAddress.Inet clientBinding.Endpoint,
                            SocketAddress.Inet dest
                        )
                    )
                else

                match overTimeWaits clientBinding.Endpoint dest system with
                | Error refusal -> Error refusal
                | Ok (Error error) -> failed error asItWas
                | Ok (Ok system) ->

                let connectionId = system.Machine.NextConnectionId
                let (ConnectionId rawConnectionId) = connectionId

                let tcpConnection =
                    {
                        ClientAddress = clientBinding.Endpoint
                        ServerAddress = dest
                        // IPv4, whatever the socket's domain: it is the only
                        // transport, and a dual-mode socket's connection over
                        // it is sized as an IPv4 one (measured, G8).
                        Transfer = TcpBufferSizing.newTransfer SocketDomain.Inet system.Machine
                        FinsExchangedAt = None
                    }

                let clientPhase =
                    if not nonBlocking then
                        SocketPhase.Established (connectionId, ConnectionEnd.Client)
                    else
                        match flavour with
                        | SimulatedUnixFlavour.Linux ->
                            // The next connect reports the completion with
                            // one SUCCESS (measured), which is what this
                            // phase defers.
                            SocketPhase.EstablishedPendingReport connectionId
                        | SimulatedUnixFlavour.Darwin ->
                            // Darwin's retry answers EISCONN directly
                            // (measured), so nothing is deferred.
                            SocketPhase.Established (connectionId, ConnectionEnd.Client)

                let system =
                    { system with
                        Machine =
                            { system.Machine with
                                Sockets =
                                    system.Machine.Sockets
                                    |> Map.add
                                        socketId
                                        { sock with
                                            Addressing =
                                                SocketAddressing.replaceBinding (Some clientBinding) sock.Addressing
                                            Phase = clientPhase
                                        }
                                    |> Map.add
                                        listenerId
                                        { listenerSocket with
                                            Phase =
                                                SocketPhase.Listening
                                                    { listenState with
                                                        // Oldest first: accept(2)
                                                        // dequeues the head.
                                                        Queue =
                                                            listenState.Queue
                                                            @ [ queuedOn flavour listenerSocket connectionId ]
                                                    }
                                        }
                                Connections = Map.add connectionId tcpConnection system.Machine.Connections
                                NextConnectionId = ConnectionId (rawConnectionId + 1L)
                            }
                    }

                // The two edges this call raises, in the measured order
                // (`order7.c`, three runs): the client's completion enters
                // the ready list *before* the listener's accept edge — the
                // client processes the SYN-ACK and becomes writable before
                // its final ACK puts the child on the accept queue. The
                // client's phase resolves in this call whether or not the
                // syscall's own answer is deferred to EINPROGRESS.
                let system =
                    system
                    |> SocketWake.signal socketId SocketWake.ConnectResolved
                    |> SocketWake.signal listenerId SocketWake.AcceptQueuePush

                if nonBlocking then
                    // The syscall itself still answers EINPROGRESS —
                    // measured on both kernels, even on loopback — and the
                    // completion is what the phase above latches.
                    failed UnixError.EINPROGRESS system
                else
                    completed system
            | None ->
                // The client's own endpoint with no listener behind it: Linux
                // completes it as a TCP simultaneous open, connecting the
                // socket to itself, which is unmodelled; Darwin answers EINVAL
                // and leaves the socket as it was. Measured for a source
                // bind(2) gave and for one connect's own implicit bind gave
                // (`docs/probes/implicit-self-connect`), which is checked
                // below, once that bind has chosen its port.
                let selfTuple
                    (system : ProcessView<'Thread, 'Handler>)
                    : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
                    =
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> Error (ConnectRefusal.SimultaneousOpen (SocketAddress.Inet dest))
                    | SimulatedUnixFlavour.Darwin -> failed UnixError.EINVAL system

                // A wildcard binding's source is 127.0.0.1 towards 127.0.0.1;
                // towards any other address it is unmeasured, and the implicit
                // bind below refuses it. A port a refused connect gave back is
                // not the socket's own: its connect chooses one, which is
                // checked below.
                match sock.Ipv4Binding with
                | Some binding when
                    PortHold.isHeld binding.PortHold
                    && binding.Endpoint.Port = dest.Port
                    && (binding.Endpoint.Address = dest.Address
                        || binding.Endpoint.Address = Ipv4Address.any
                           && dest.Address = Ipv4Address.loopback)
                    ->
                    selfTuple system
                | _ ->

                if UnixMachineState.synDropped socketId dest system.Machine then
                    Error (ConnectRefusal.DarwinSynDropped (SocketAddress.Inet dest))
                else

                // The implicit bind happens before the SYN, so a refused
                // socket has a concrete local endpoint too — measured,
                // getsockname reports 127.0.0.1 and a nonzero port while the
                // refusal is pending, on both kernels.
                let asItWas = system

                match ensureStreamBound dest system with
                | Error refusal -> Error refusal
                | Ok (Error error) -> failed error system
                | Ok (Ok (binding, system)) when binding.Endpoint = dest ->
                    // Only a socket with no port of its own gets here, one
                    // holding a port having been answered above: unbound, or
                    // under Linux one whose refused connect gave its port back.
                    // Its implicit bind took the destination's own port, which
                    // nothing else holds. Darwin keeps what that bind made, the
                    // wildcard at the port, from before the source resolved to
                    // loopback.
                    let implicitBinding =
                        { binding with
                            Endpoint =
                                { binding.Endpoint with
                                    Address = Ipv4Address.any
                                }
                        }

                    selfTuple
                        { system with
                            Machine =
                                { system.Machine with
                                    Sockets =
                                        Map.add
                                            socketId
                                            { sock with
                                                Addressing =
                                                    SocketAddressing.replaceBinding
                                                        (Some implicitBinding)
                                                        sock.Addressing
                                            }
                                            system.Machine.Sockets
                                }
                        }
                | Ok (Ok (binding, system)) ->

                match overTimeWaits binding.Endpoint dest system with
                | Error refusal -> Error refusal
                | Ok (Error error) -> failed error asItWas
                | Ok (Ok system) ->

                if not nonBlocking then
                    // The refusal is delivered inline, and the socket's fate
                    // diverges by flavour: measured, a Linux retry is a fresh
                    // attempt and a Darwin one answers EISCONN forever.
                    let phase =
                        match flavour with
                        | SimulatedUnixFlavour.Linux -> SocketPhase.Idle
                        | SimulatedUnixFlavour.Darwin -> SocketPhase.Refused RefusalError.Reported

                    let system =
                        { system with
                            Machine =
                                { system.Machine with
                                    Sockets =
                                        Map.add
                                            socketId
                                            { sock with
                                                Addressing =
                                                    SocketAddressing.replaceBinding
                                                        (Some (
                                                            bindingAfterRefusalDelivery
                                                                flavour
                                                                (bindingOnRefusal binding)
                                                        ))
                                                        sock.Addressing
                                                Phase = phase
                                            }
                                            system.Machine.Sockets
                                }
                        }

                    // The error's arrival and its reset both signal
                    // (measured separately for the deferred path, `order3.c`
                    // row M); inline delivery collapses them into this one
                    // state change, so one signal carries both.
                    let system = SocketWake.signal socketId SocketWake.ConnectResolved system

                    failed UnixError.ECONNREFUSED system
                else
                    // EINPROGRESS now, with ECONNREFUSED pending. On Linux the
                    // first later connect delivers it, unless an SO_ERROR read
                    // has taken it first. Darwin's connect never delivers it
                    // (measured).
                    let system =
                        { system with
                            Machine =
                                { system.Machine with
                                    Sockets =
                                        Map.add
                                            socketId
                                            { sock with
                                                Addressing =
                                                    SocketAddressing.replaceBinding
                                                        (Some (bindingOnRefusal binding))
                                                        sock.Addressing
                                                Phase = SocketPhase.Refused RefusalError.Pending
                                            }
                                            system.Machine.Sockets
                                }
                        }

                    // The error's arrival signals the client (measured,
                    // `order3.c` row M: the 0x201d edge).
                    let system = SocketWake.signal socketId SocketWake.ConnectResolved system

                    failed UnixError.EINPROGRESS system

        match sock.Kind with
        | SocketKind.SeqPacket -> Error (ConnectRefusal.UnmeasuredKind (socketId, sock.Kind))
        | SocketKind.Stream ->
            // The copy layer answers before any socket state on both
            // flavours: Linux's move_addr_to_kernel rejects an oversized
            // sockaddr and Darwin's getsockaddr rejects both bounds, each in
            // the syscall layer ahead of the protocol's own checks.
            match lengthVerdict with
            | BindLengthVerdict.RejectedBeforeCopy error -> fail error
            | BindLengthVerdict.Accepted
            | BindLengthVerdict.Invalid ->

            match family with
            | None ->
                // Too short to carry the family: EINVAL on both — Linux in
                // inet_stream_connect's first screen, Darwin in getsockaddr.
                fail UnixError.EINVAL
            | Some family ->

            match flavour with
            | SimulatedUnixFlavour.Linux ->
                // inet_stream_connect's order: the AF_UNSPEC branch, then
                // the state machine, then tcp_v4_connect's length and family
                // checks. Measured where a caller reaches it; the state arms'
                // precedence over the argument checks is the pinned source's.
                if family = 0 then
                    match sock.Phase with
                    | SocketPhase.Idle ->
                        // Measured: an accepted no-op, and the socket stays
                        // usable.
                        completed system
                    | phase -> Error (ConnectRefusal.LinuxUnspecOnPhase (socketId, phase))
                else

                match sock.Phase with
                // Linux answers a connect in flight EALREADY when non-blocking,
                // and a blocking one sleeps on (measured, `connect-park.c` T3).
                | SocketPhase.Connecting _ -> ReservedConnecting.fail "UnixConnection.connect" socketId
                | SocketPhase.EstablishedPendingReport connectionId when
                    (match
                        (TcpTransfer.towards
                            ConnectionEnd.Client
                            (UnixMachineState.connection connectionId system.Machine).Transfer)
                            .Receiver
                     with
                     | TcpEndState.Reset _ -> true
                     | TcpEndState.Open _
                     | TcpEndState.Closed _ -> false)
                    ->
                    Error (ConnectRefusal.ResetBeforeReport socketId)
                | SocketPhase.EstablishedPendingReport connectionId ->
                    // The one completion-reporting SUCCESS (measured). The
                    // destination is ignored, as the state transition is.
                    completed (withPhase (SocketPhase.Established (connectionId, ConnectionEnd.Client)) system)
                | SocketPhase.Refused error ->
                    // Deliver the latched refusal once, then reset: the next
                    // connect is a fresh attempt, and the source address the
                    // pending attempt resolved reverts to whatever bind(2)
                    // locked (both measured). A refusal an `SO_ERROR` read has
                    // already taken resets the same way, answering
                    // ECONNABORTED for it (measured, wherever the connect is
                    // aimed).
                    let answer =
                        match error with
                        | RefusalError.Pending -> UnixError.ECONNREFUSED
                        | RefusalError.Reported -> UnixError.ECONNABORTED

                    let system =
                        { system with
                            Machine =
                                { system.Machine with
                                    Sockets =
                                        Map.add
                                            socketId
                                            { sock with
                                                Addressing =
                                                    SocketAddressing.replaceBinding
                                                        (sock.Ipv4Binding
                                                         |> Option.map (
                                                             bindingAfterRefusalDelivery SimulatedUnixFlavour.Linux
                                                         ))
                                                        sock.Addressing
                                                Phase = SocketPhase.Idle
                                            }
                                            system.Machine.Sockets
                                }
                        }

                    // The reset signals: a registered client whose error edge
                    // was already consumed sees a fresh OUT|HUP edge after
                    // the delivering connect (measured, `order3.c` row M, and
                    // `consumed-epoll.c` R2 for the aborting one).
                    let system = SocketWake.signal socketId SocketWake.RefusalReset system

                    failed answer system
                | SocketPhase.Established _ -> fail UnixError.EISCONN
                | SocketPhase.Listening _ ->
                    // Measured: Linux answers a connect on the listening
                    // socket itself with EISCONN, where Darwin answers
                    // EOPNOTSUPP.
                    fail UnixError.EISCONN
                | SocketPhase.DatagramPeer _ ->
                    failwith
                        "UnixConnection.connectSocket: a stream socket holds SocketPhase.DatagramPeer. this kernel's socket invariants forbid that pairing, so this is a bug in the caller's state construction."
                | SocketPhase.Idle ->

                match lengthVerdict with
                | BindLengthVerdict.Invalid -> fail UnixError.EINVAL
                | BindLengthVerdict.RejectedBeforeCopy _
                | BindLengthVerdict.Accepted ->

                if family <> ownFamily then
                    fail UnixError.EAFNOSUPPORT
                else

                match ipv6Only () with
                | Some answer -> answer
                | None ->

                match nativeDestination () with
                | Some answer -> answer
                | None ->

                match destination with
                // Measured (`sockaddr-dgram-connect.c`, D and M): a broadcast
                // or multicast destination is ENETUNREACH, at every length
                // from 16 and whatever the port, before anything binds.
                | Some dest when SimulatedUnixPlatform.isBroadcastOrMulticast dest.Address -> fail UnixError.ENETUNREACH
                | Some dest -> attemptStream dest
                | None ->
                    failwith
                        "UnixConnection.connectSocket: the declared length passed the AF_INET verdict but the copy held no destination, though a length that passes it reaches `sin_addr` (this is a bug in this library)."
            | SimulatedUnixFlavour.Darwin ->
                // The state arms answer first — measured: a refused socket's
                // EISCONN beats a good destination, AF_UNSPEC and an
                // oversized sockaddr, and a connected socket's beats
                // AF_UNSPEC.
                match sock.Phase with
                // No Darwin connect is left in flight: one to a full listener
                // completes or is reset at once (measured, `connect-park.c`).
                | SocketPhase.Connecting _ -> ReservedConnecting.fail "UnixConnection.connect" socketId
                | SocketPhase.EstablishedPendingReport _ ->
                    failwith
                        "UnixConnection.connectSocket: a stream socket is in SocketPhase.EstablishedPendingReport under the Darwin flavour, which never constructs it (its retry answers EISCONN directly). This is a bug in this library, or in a caller that assembled the state by hand."
                | SocketPhase.Refused _ ->
                    // Measured, whatever the destination, and whether or not
                    // the refusal is still pending: connect never delivers it.
                    fail UnixError.EISCONN
                | SocketPhase.Established _ ->
                    // Measured, including against an AF_UNSPEC destination.
                    fail UnixError.EISCONN
                | SocketPhase.Listening _ ->
                    // Measured: EOPNOTSUPP, where Linux answers EISCONN, for
                    // AF_INET and AF_UNSPEC alike (`sockaddr-connect-ladder.c`,
                    // U and Z).
                    fail UnixError.EOPNOTSUPP
                | SocketPhase.DatagramPeer _ ->
                    failwith
                        "UnixConnection.connectSocket: a stream socket holds SocketPhase.DatagramPeer. this kernel's socket invariants forbid that pairing, so this is a bug in the caller's state construction."
                | SocketPhase.Idle ->

                // Measured (`sockaddr-connect-ladder.c`, G and U): the family
                // is judged before the length, so any family but AF_UNSPEC and
                // AF_INET is EAFNOSUPPORT at every length the copy takes, and
                // binds nothing. AF_UNSPEC is then read exactly as AF_INET.
                if family <> 0 && family <> ownFamily then
                    fail UnixError.EAFNOSUPPORT
                else

                match ipv6Only () with
                | Some answer -> answer
                | None ->

                // A broadcast or multicast destination is EAFNOSUPPORT too,
                // judged with the family and binding nothing: for AF_INET
                // before the length, reading `sin_addr` with every byte past
                // the copy as zero, and for AF_UNSPEC only at 16. Measured
                // (`sockaddr-dgram-connect.c`, D and M), the rule
                // `SimulatedUnixPlatform.bindGroupAddressRule` states for a
                // stream socket's `bind(2)`.
                let groupDestination =
                    SimulatedUnixPlatform.isBroadcastOrMulticast address.ZeroFilledAddress
                    && (family = ownFamily || lengthVerdict = BindLengthVerdict.Accepted)

                if groupDestination then
                    fail UnixError.EAFNOSUPPORT
                else

                // From here a socket with no address is bound to the wildcard
                // and an ephemeral port before the length or the port is
                // judged, and a failure keeps that binding: measured on a
                // fresh socket, EINVAL at a length other than 16 and
                // EADDRNOTAVAIL for port 0 each leave `0.0.0.0:<ephemeral>`.
                // A connect that gets past both resolves its source as
                // `attemptStream` does.
                let failBound
                    (error : UnixError)
                    : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
                    =
                    match sock.Ipv4Binding with
                    | Some _ -> fail error
                    | None ->
                        let candidate (port : uint16) : Ipv4Binding =
                            {
                                Endpoint = Ipv4Endpoint.ofParts Ipv4Address.any port
                                // No bind(2) ran.
                                LockedAddress = None
                                LockedPort = false
                                PortHold = PortHold.Connected
                            }

                        match
                            UnixMachineState.allocateEphemeralPort
                                system.Scheduling.NanosecondsSinceBoot
                                EphemeralPortUse.Reserve
                                socketId
                                sock
                                candidate
                                system.Machine
                        with
                        | Ok None -> Error (ConnectRefusal.EphemeralPortsExhausted system.Machine.EphemeralPortRange)
                        | Error refusal -> Error (ConnectRefusal.TimeWait refusal)
                        | Ok (Some (binding, machine)) ->
                            failed
                                error
                                { system with
                                    Machine =
                                        { machine with
                                            Sockets =
                                                Map.add
                                                    socketId
                                                    { sock with
                                                        Addressing =
                                                            SocketAddressing.replaceBinding
                                                                (Some binding)
                                                                sock.Addressing
                                                    }
                                                    machine.Sockets
                                        }
                                }

                match lengthVerdict with
                | BindLengthVerdict.Invalid -> failBound UnixError.EINVAL
                | BindLengthVerdict.RejectedBeforeCopy _
                | BindLengthVerdict.Accepted ->

                match nativeDestination () with
                | Some answer -> answer
                | None ->

                match destination with
                // Measured (`sockaddr-connect-ladder.c`, Z): a port of 0 is
                // EADDRNOTAVAIL whatever the address, before the address is
                // looked up -- to 0.0.0.0, 127.0.0.1, 127.0.0.2 and 8.8.8.8
                // alike.
                | Some dest when dest.Port = 0us -> failBound UnixError.EADDRNOTAVAIL
                | Some dest -> attemptStream dest
                | None ->
                    failwith
                        "UnixConnection.connectSocket: the declared length passed the AF_INET verdict but the copy held no destination, though a length that passes it reaches `sin_addr` (this is a bug in this library)."
        | SocketKind.Datagram ->
            match lengthVerdict with
            | BindLengthVerdict.RejectedBeforeCopy error -> fail error
            | BindLengthVerdict.Accepted
            | BindLengthVerdict.Invalid ->

            match family with
            | None -> fail UnixError.EINVAL
            | Some family ->

            match sock.Phase with
            | SocketPhase.Idle
            | SocketPhase.DatagramPeer _ -> ()
            | phase ->
                failwith
                    $"UnixConnection.connectSocket: a datagram socket holds %A{phase}. this kernel's socket invariants forbid that pairing, so this is a bug in the caller's state construction."

            // Darwin disconnects a connected datagram socket before it judges
            // anything the copy holds, so every connect whose length the copy
            // takes leaves it disconnected, whatever it answers (a success then
            // connects it again): its peer goes and its local address reverts
            // to the wildcard, port kept, whatever `bind(2)` locked --
            // `127.0.0.1:5556` reads back `0.0.0.0:5556`. Measured
            // (`sockaddr-connect-ladder.c`, U, and `sockaddr-dgram-connect.c`,
            // L and D).
            let disconnectedFirst : ProcessView<'Thread, 'Handler> =
                match flavour, sock.Phase, sock.Ipv4Binding with
                | SimulatedUnixFlavour.Darwin, SocketPhase.DatagramPeer _, Some binding ->
                    { system with
                        Machine =
                            { system.Machine with
                                Sockets =
                                    Map.add
                                        socketId
                                        { sock with
                                            Addressing =
                                                SocketAddressing.replaceBinding
                                                    (Some
                                                        { binding with
                                                            Endpoint =
                                                                { binding.Endpoint with
                                                                    Address = Ipv4Address.any
                                                                }
                                                        })
                                                    sock.Addressing
                                            Phase = SocketPhase.Idle
                                        }
                                        system.Machine.Sockets
                            }
                    }
                | SimulatedUnixFlavour.Darwin, SocketPhase.DatagramPeer _, None ->
                    failwith
                        "UnixConnection.connectSocket: a datagram socket holds a peer but no binding; connect binds before it records the peer, so this is a bug in this library, or in a caller that assembled the state by hand."
                | _ -> system

            if family = 0 then
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    // Linux's `udp_disconnect`, connected or not, at every
                    // length the copy takes from 2 (measured both ways,
                    // `docs/probes/udp-connect/dissolve.py`, and at every
                    // length by `sockaddr-connect-ladder.c`, U): the
                    // peer filter goes; the address reverts to the wildcard
                    // unless `bind(2)` locked a concrete one; the port is
                    // dropped unless `bind(2)` chose it. So `0.0.0.0:5555`
                    // dissolves to itself, `127.0.0.1:0`-bound-then-connected
                    // to `127.0.0.1:0` (half-bound: it rebinds freely, and a
                    // later connect keeps the address), and an implicit or
                    // `0.0.0.0:0` binding to nothing at all.
                    match sock.Phase, sock.Ipv4Binding with
                    | SocketPhase.DatagramPeer _, None ->
                        failwith
                            "UnixConnection.connectSocket: a datagram socket holds a peer but no binding; connect binds before it records the peer, so this is a bug in this library, or in a caller that assembled the state by hand."
                    | _, None ->
                        // Nothing to dissolve and nothing bound: the accepted
                        // no-op (measured).
                        completed system
                    | _, Some binding ->
                        let address =
                            match binding.LockedAddress with
                            | Some locked when locked <> Ipv4Address.any -> Some locked
                            | Some _
                            | None -> None

                        let port =
                            if binding.LockedPort then
                                Some binding.Endpoint.Port
                            else
                                None

                        let dissolved =
                            match address, port with
                            | None, None -> None
                            | _ ->
                                Some
                                    { binding with
                                        Endpoint =
                                            Ipv4Endpoint.ofParts
                                                (address |> Option.defaultValue Ipv4Address.any)
                                                (port |> Option.defaultValue 0us)
                                    }

                        completed
                            { system with
                                Machine =
                                    { system.Machine with
                                        Sockets =
                                            Map.add
                                                socketId
                                                { sock with
                                                    Addressing =
                                                        SocketAddressing.replaceBinding dissolved sock.Addressing
                                                    Phase = SocketPhase.Idle
                                                }
                                                system.Machine.Sockets
                                    }
                            }
                | SimulatedUnixFlavour.Darwin ->
                    // Measured (`sockaddr-connect-ladder.c`, U): EINVAL at
                    // every length the copy takes but 16, EAFNOSUPPORT at 16,
                    // and the disconnect below happens either way.
                    let error =
                        match lengthVerdict with
                        | BindLengthVerdict.Accepted -> UnixError.EAFNOSUPPORT
                        | BindLengthVerdict.Invalid -> UnixError.EINVAL
                        | BindLengthVerdict.RejectedBeforeCopy _ ->
                            failwith
                                "UnixConnection.connectSocket: a length the copy rejects outright reached the datagram AF_UNSPEC rule, though the datagram arm answers it first (this is a bug in this library)."

                    // The answer with and without a peer set (measured), but
                    // not before the disconnect has happened.
                    failed error disconnectedFirst
            else

            // Linux binds a datagram socket with no port to the wildcard and an
            // ephemeral port before it judges the length or the family, for
            // every family but AF_UNSPEC, and a failure keeps that binding;
            // Darwin binds nothing, and disconnects first. Measured
            // (`sockaddr-dgram-connect.c`, B, D and L).
            let failPrepared
                (error : UnixError)
                : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
                =
                match flavour with
                | SimulatedUnixFlavour.Darwin -> failed error disconnectedFirst
                | SimulatedUnixFlavour.Linux ->
                    match sock.Ipv4Binding with
                    | Some binding when binding.Endpoint.Port <> 0us -> fail error
                    | existing ->
                        // A half-bound socket keeps its address and gains a
                        // port, as `inet_autobind` does for it on success.
                        let candidate (port : uint16) : Ipv4Binding =
                            match existing with
                            | Some binding ->
                                { binding with
                                    Endpoint =
                                        { binding.Endpoint with
                                            Port = port
                                        }
                                }
                            | None ->
                                {
                                    Endpoint = Ipv4Endpoint.ofParts Ipv4Address.any port
                                    // No bind(2) ran.
                                    LockedAddress = None
                                    LockedPort = false
                                    PortHold = PortHold.Reserved
                                }

                        match
                            UnixMachineState.allocateEphemeralPort
                                system.Scheduling.NanosecondsSinceBoot
                                EphemeralPortUse.Reserve
                                socketId
                                sock
                                candidate
                                system.Machine
                        with
                        | Ok None -> Error (ConnectRefusal.EphemeralPortsExhausted system.Machine.EphemeralPortRange)
                        | Error refusal -> Error (ConnectRefusal.TimeWait refusal)
                        | Ok (Some (binding, machine)) ->
                            failed
                                error
                                { system with
                                    Machine =
                                        { machine with
                                            Sockets =
                                                Map.add
                                                    socketId
                                                    { sock with
                                                        Addressing =
                                                            SocketAddressing.replaceBinding
                                                                (Some binding)
                                                                sock.Addressing
                                                    }
                                                    machine.Sockets
                                        }
                                }

            match lengthVerdict with
            | BindLengthVerdict.Invalid -> failPrepared UnixError.EINVAL
            | BindLengthVerdict.RejectedBeforeCopy _
            | BindLengthVerdict.Accepted ->

            if family <> ownFamily then
                failPrepared UnixError.EAFNOSUPPORT
            else

            match destination with
            | None ->
                failwith
                    "UnixConnection.connectSocket: the declared length passed the AF_INET verdict but the copy held no destination, though a length that passes it reaches `sin_addr` (this is a bug in this library)."
            // Measured (`sockaddr-dgram-connect.c`, D): Darwin answers a port
            // of 0 with EADDRNOTAVAIL whatever the address, before it looks
            // the address up. Linux connects it, to no peer `getpeername(2)`
            // can read.
            | Some dest when dest.Port = 0us && flavour = SimulatedUnixFlavour.Darwin ->
                failPrepared UnixError.EADDRNOTAVAIL
            | Some dest ->

            let dest = resolveWildcard dest

            if SimulatedUnixPlatform.isBroadcastOrMulticast dest.Address then
                // Measured (`sockaddr-dgram-connect.c`, D and M): Linux answers
                // the broadcast address with EACCES, `SO_BROADCAST` being off
                // (this library models no way to set it); every other such
                // connect succeeds, aimed at a group or a broadcast this
                // library cannot carry.
                if flavour = SimulatedUnixFlavour.Linux && dest.Address = Ipv4Address.broadcast then
                    failPrepared UnixError.EACCES
                else
                    Error (ConnectRefusal.DatagramGroupDestination (socketId, SocketAddress.Inet dest))
            elif not (destinationIsLocal dest.Address) then
                Error (ConnectRefusal.DestinationNotLocal (SocketAddress.Inet dest, SocketKind.Datagram))
            else

            // A datagram connect is a peer filter, not a handshake: it
            // succeeds with nothing at the destination and a re-connect
            // re-targets, both measured. It binds implicitly just as a
            // stream connect does. On Darwin the source is resolved from the
            // binding the disconnect left, so a connected socket bound to an
            // interface address connects to loopback from 127.0.0.1, where
            // Linux keeps the interface address (`sockaddr-dgram-reconnect.c`).
            let current =
                (UnixMachineState.socket socketId disconnectedFirst.Machine).Ipv4Binding

            match ensureBoundFrom current dest disconnectedFirst with
            | Error (ConnectRefusal.EphemeralPortsExhausted (low, high)) ->
                match
                    SimulatedUnixPlatform.ephemeralPortsExhausted
                        system.Machine.UnixPlatform
                        EphemeralSearchCall.DatagramAutobind
                with
                | Some error -> failed error disconnectedFirst
                | None -> Error (ConnectRefusal.EphemeralPortsExhausted (low, high))
            | Error refusal -> Error refusal
            | Ok (binding, system) ->

            // Another datagram socket already holding this very source and
            // peer. Linux admits it: two sockets sharing a port through
            // SO_REUSEADDR both connect to one peer (`sockaddr-dgram-duplicate.c`).
            // Darwin reaches it only through a reconnect whose source is
            // resolved afresh, and how it refuses that is unmeasured.
            let duplicate =
                flavour = SimulatedUnixFlavour.Darwin
                && system.Machine.Sockets
                   |> Map.exists (fun otherId other ->
                       otherId <> socketId
                       && other.Kind = SocketKind.Datagram
                       && other.Phase = SocketPhase.DatagramPeer (SocketAddress.Inet dest)
                       && (other.Ipv4Binding |> Option.map (fun b -> b.Endpoint)) = Some binding.Endpoint
                   )

            if duplicate then
                Error (ConnectRefusal.DuplicateFourTuple (SocketAddress.Inet binding.Endpoint, SocketAddress.Inet dest))
            else

            let system =
                { system with
                    Machine =
                        { system.Machine with
                            Sockets =
                                Map.add
                                    socketId
                                    { sock with
                                        Addressing = SocketAddressing.replaceBinding (Some binding) sock.Addressing
                                        Phase = SocketPhase.DatagramPeer (SocketAddress.Inet dest)
                                    }
                                    system.Machine.Sockets
                        }
                }

            // Measured (`udp-error.c` Y1 and Y7, and `udp-transfer.c` L7, in
            // docs/plans/2026-10-18-udp-data-path): a Darwin connect that
            // connects the socket answers its pending error, and takes it,
            // the socket connected all the same; one that fails leaves the
            // error pending, as every Linux connect does.
            match flavour with
            | SimulatedUnixFlavour.Darwin when UnixMachineState.receivesDatagrams sock ->
                match DatagramReceiver.takeError (UnixMachineState.datagramReceiver socketId system.Machine) with
                | Some error, after ->
                    failed
                        error
                        { system with
                            Machine = UnixMachineState.withDatagramReceiver socketId after system.Machine
                        }
                | None, _ -> completed system
            | SimulatedUnixFlavour.Darwin
            | SimulatedUnixFlavour.Linux -> completed system

    /// What `connectDecoded` reads of `copied`, the bytes a connect on
    /// `socket` copied in, declared `declaredLength` long.
    let private connectAddress
        (platform : SimulatedUnixPlatform)
        (socket : SocketDescription)
        (declaredLength : uint32)
        (copied : ImmutableArray<byte>)
        : ConnectAddress
        =
        match socket.Domain with
        | SocketDomain.Inet ->
            let decoded = SimulatedUnixPlatform.decodeInternetSockaddr platform copied

            {
                Family = decoded.Family
                OwnFamily = SimulatedUnixPlatform.internetAddressFamily
                // connect(2) copies the sockaddr in through the same helpers
                // bind(2) uses (Linux's move_addr_to_kernel, Darwin's
                // getsockaddr), and the measured lengths agree with bind's rule
                // exactly: Linux takes 16 through 128 and answers EINVAL
                // outside, Darwin takes exactly 16, EINVAL otherwise and
                // ENAMETOOLONG past 255. So the verdict function is shared.
                LengthVerdict =
                    SimulatedUnixPlatform.bindAddressLength
                        platform
                        SimulatedUnixPlatform.internetSocketAddressSize
                        declaredLength
                Destination = decoded.Endpoint
                NativeDestination = None
                ZeroFilledAddress = decoded.ZeroFilledAddress
            }
        | SocketDomain.Inet6 ->
            let decoded = SimulatedUnixPlatform.decodeInternetV6Sockaddr platform copied

            let destination, native =
                match decoded.Destination with
                | Some (Ipv6Destination.V4Mapped endpoint) -> Some endpoint, None
                | Some (Ipv6Destination.Native endpoint) -> None, Some endpoint
                | None -> None, None

            {
                Family = decoded.Family
                OwnFamily = SimulatedUnixPlatform.internetV6AddressFamily platform
                // Measured (`docs/probes/dual-mode/`, A14 and H) to be bind's
                // rule for a `struct sockaddr_in6` too.
                LengthVerdict = SimulatedUnixPlatform.internetV6AddressLength platform declaredLength
                Destination = destination
                NativeDestination = native
                ZeroFilledAddress =
                    destination
                    |> Option.map (fun endpoint -> endpoint.Address)
                    |> Option.defaultValue Ipv4Address.any
            }
        | SocketDomain.Unix ->
            failwith
                "UnixConnection: a connect reached the ladder on a Unix-domain socket, which the sockaddr screen refuses first (this is a bug in this library)."

    /// `connect(2)` on the socket `socketId` past the descriptor screens: the
    /// ladder `connect` runs once it has looked the descriptor up, through a
    /// description whose `O_NONBLOCK` is `nonBlocking`. For a test that wants
    /// to put a kernel into a state where a connection is pending, established
    /// or refused; a syscall goes through `connect`.
    ///
    /// Internal because a `SocketId` that names no socket throws: a client
    /// reaches a socket only through a descriptor, which `connect` looks up.
    ///
    /// `copied` is the bytes a copy-in of `declaredLength` takes from real
    /// storage: exactly as many as `UnixSocket.tryAdmitSockaddrCopy` answers `Transfer` with
    /// for a mapped buffer, and none where it rejects the length before the
    /// copy. Passing any other number is refused, as a bug in the caller.
    ///
    /// The socket's domain is screened as `connect` screens it: a socket in a
    /// domain whose addresses this kernel does not read is refused, after
    /// Linux's rejection of a length its copy-in will not take, which comes
    /// before anything about the socket.
    let internal connectSocket<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (nonBlocking : bool)
        (declaredLength : uint32)
        (copied : ImmutableArray<byte>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
        =
        let platform = system.Machine.UnixPlatform

        CopyRange.require
            "UnixConnection.connectSocket"
            (CopyRange.fromStart (UnixSocket.mappedCopyLength platform declaredLength))
            copied

        let rejectedBeforeTheSocket =
            match
                SimulatedUnixPlatform.flavour platform,
                SimulatedUnixPlatform.bindAddressLength
                    platform
                    SimulatedUnixPlatform.internetSocketAddressSize
                    declaredLength
            with
            | SimulatedUnixFlavour.Linux, BindLengthVerdict.RejectedBeforeCopy error -> Some error
            | _ -> None

        match rejectedBeforeTheSocket with
        | Some error -> Ok (SyscallAnswer.Failed error, system)
        | None ->

        let socket = UnixMachineState.socket socketId system.Machine

        match UnixSocket.screenSockaddrSocket platform socketId socket declaredLength with
        | Error refusal -> Error (ConnectRefusal.Copy refusal)
        | Ok () ->

        connectDecoded socketId nonBlocking declaredLength (connectAddress platform socket declaredLength copied) system

    /// A `connect` through `fd`, given the bytes `UnixSocket.tryAdmitSockaddrCopy`
    /// said the kernel copies: the step `connectWithAddress` takes. It runs the
    /// admission again itself, and fails loudly unless `copied` is exactly what
    /// that copies.
    let internal tryConnectBytes<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (destination : UserBuffer)
        (declaredLength : uint32)
        (copied : ImmutableArray<byte>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallAnswer * ProcessView<'Thread, 'Handler>, ConnectRefusal>
        =
        match UnixSocket.tryAdmitSockaddrCopy SockaddrCopySyscall.Connect fd destination declaredLength system with
        | Error refusal -> Error (ConnectRefusal.Copy refusal)
        | Ok (SockaddrCopyAdmission.Answered error) ->
            CopyRange.require "UnixConnection.connect" (CopyRange.fromStart 0) copied
            Ok (SyscallAnswer.Failed error, system)
        | Ok (SockaddrCopyAdmission.Transfer length) ->

        CopyRange.require "UnixConnection.connect" (CopyRange.fromStart length) copied

        // `tryAdmitSockaddrCopy` reached the copy, so the descriptor is a live IPv4
        // socket; nothing between there and here could have changed that.
        let socketId =
            match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) -> socketId
            | other ->
                failwith
                    $"UnixConnection.connect: fd %d{fd} names %A{other}, yet the admission above reached the sockaddr copy, which only a socket does (this is a bug in this library)."

        // `O_NONBLOCK` is a fact about the open file description `fd` came
        // through, not about the socket, so a connect through a `dup` of a
        // non-blocking socket pends too.
        let nonBlocking =
            match FileDescriptorRegistry.tryFind fd (UnixSystemState.fileDescriptors system) with
            | Some description -> description.NonBlocking
            | None ->
                failwith
                    $"UnixConnection.connect: fd %d{fd} resolved to a socket a line above and nothing here closes it (this is a bug in this library)."

        connectDecoded
            socketId
            nonBlocking
            declaredLength
            (connectAddress
                system.Machine.UnixPlatform
                (UnixMachineState.socket socketId system.Machine)
                declaredLength
                copied)
            system

    /// What a `connect` by `thread` through `fd` answers once the kernel holds
    /// the bytes it copied: `tryConnectBytes`'s answer, as the call's outcome.
    ///
    /// No connect sleeps yet: the one that would, to a full listener, is
    /// refused (`ConnectRefusal.AcceptQueueFull`), so this always answers
    /// `SyscallOutcome.Answered`. The thread is what a connect that sleeps will
    /// park.
    let private finishConnect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (address : UserBuffer)
        (declaredLength : uint32)
        (copied : ImmutableArray<byte>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, ConnectRefusal>
        =
        ignore<'Thread> thread

        tryConnectBytes fd address declaredLength copied system
        |> Result.map (fun (answer, system) -> SyscallOutcome.Answered answer, system)

    /// `tryConnect` once `Entry` has admitted its caller.
    let private tryConnectIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (address : UserBuffer)
        (declaredLength : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedConnect<'Thread, 'Handler>, SyscallOutcome * ProcessView<'Thread, 'Handler>>,
              ConnectRefusal
           >
        =
        match UnixSocket.tryAdmitSockaddrCopy SockaddrCopySyscall.Connect fd address declaredLength system with
        | Error refusal -> Error (ConnectRefusal.Copy refusal)
        | Ok (SockaddrCopyAdmission.Answered _) ->
            finishConnect thread fd address declaredLength ImmutableArray.Empty system
            |> Result.map CallProgress.Answered
        // A copy of nothing reads nothing, so there is nothing to stop for.
        | Ok (SockaddrCopyAdmission.Transfer 0) ->
            finishConnect thread fd address declaredLength ImmutableArray.Empty system
            |> Result.map CallProgress.Answered
        | Ok (SockaddrCopyAdmission.Transfer length) ->
            {
                Thread = thread
                Fd = fd
                Address = address
                DeclaredLength = declaredLength
                Range = CopyRange.fromStart length
                System = system
            }
            |> CallProgress.NeedsCopyIn
            |> Ok

    /// `connect`, with a refusal answered as the `Error` rather than raised.
    let internal tryConnect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (address : UserBuffer)
        (declaredLength : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedConnect<'Thread, 'Handler>, SyscallOutcome * UnixSystem<'Thread, 'Handler>>,
              ConnectRefusal
           >
        =
        Entry.call
            "UnixConnection.connect"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryConnectIn (Caller.thread caller) fd address declaredLength)
            system

    /// <summary>
    /// `connect(2)`, made by `caller`: point `fd` at the address in the
    /// `struct sockaddr` the caller declared `declaredLength` bytes long at
    /// `address`, or ask what pointing it there would answer.
    /// </summary>
    /// <remarks>
    /// Every answer the call gives before the kernel copies the sockaddr in
    /// comes first, as `CallProgress.Answered`, with the system unchanged.
    /// Otherwise the call stops at the copy, and `connectWithAddress`, given
    /// the bytes `PausedConnect.copyRange` names, reads the family, port and
    /// address out of them itself. The copy is judged as `UnixSocket.bind`'s
    /// is, with one difference of order, measured: Linux's `connect` copies
    /// the sockaddr in before it asks whether the descriptor is a socket,
    /// where its `bind` and both of Darwin's ask first.
    ///
    /// A connect answers 0, or fails with the errno the syscall leaves.
    /// `EINPROGRESS` is a failure like any other, which a caller reports as it
    /// reports any other errno; the connection it defers is already settled on
    /// the socket's phase.
    ///
    /// It takes the thread, and its outcome is a `SyscallOutcome`, because under
    /// Linux a blocking connect to a listener whose accept queue is full sleeps
    /// (`ParkedSyscall.Connect`): the paused call holds the thread, so the
    /// connect `connectWithAddress` finishes can park it. No connect sleeps in
    /// this version: that one is refused. A thread that is parked already, or
    /// that the table does not hold, fails loudly.
    /// </remarks>
    let connect<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (address : UserBuffer)
        (declaredLength : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedConnect<'Thread, 'Handler>, SyscallOutcome * UnixSystem<'Thread, 'Handler>>
        =
        tryConnect caller fd address declaredLength system
        |> Refusal.orRaise "UnixConnection.connect" ConnectRefusal.kind ConnectRefusal.describe

    /// `tryConnectWithAddress` before `Entry.resume` hands back the system it
    /// answers in.
    let private tryConnectWithAddressIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (copied : ImmutableArray<byte>)
        (paused : PausedConnect<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, ConnectRefusal>
        =
        CallProgress.requirePaused "UnixConnection.connectWithAddress" "UnixConnection.connect" paused
        CopyRange.require "UnixConnection.connectWithAddress" paused.Range copied
        finishConnect paused.Thread paused.Fd paused.Address paused.DeclaredLength copied paused.System

    /// `connectWithAddress`, with a refusal answered as the `Error` rather than raised.
    let internal tryConnectWithAddress<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (copied : ImmutableArray<byte>)
        (paused : PausedConnect<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, ConnectRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryConnectWithAddressIn copied paused)

    /// <summary>
    /// The rest of the `connect` `paused` stopped: `copied`, exactly the bytes
    /// `PausedConnect.copyRange` names, is the sockaddr the kernel reads the
    /// family, port and address out of. See `connect`.
    /// </summary>
    /// <exception cref="T:System.InvalidOperationException">`copied` is not exactly `PausedConnect.copyRange`'s `ByteCount` long.</exception>
    let connectWithAddress<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (copied : ImmutableArray<byte>)
        (paused : PausedConnect<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryConnectWithAddress copied paused
        |> Refusal.orRaise "UnixConnection.connectWithAddress" ConnectRefusal.kind ConnectRefusal.describe

    /// Dequeue the oldest completed connection from `socketId`'s accept queue
    /// and materialise the server-side socket onto it: a fresh socket, bound at
    /// the connection's server address, on a fresh **blocking** descriptor.
    /// Answers the new fd and the connection, whose `ClientAddress` is what
    /// `accept(2)` reports as the peer.
    ///
    /// Blocking unconditionally, which is not the whole of `accept(2)`: on a
    /// flavour where the accepted socket inherits `O_NONBLOCK`, it inherits it
    /// from the *description the call was made through*, and a `SocketId` does
    /// not name one. `accept` applies that, having the descriptor.
    ///
    /// The state transition on its own, without the entry point's screens.
    /// `accept` is what a syscall goes through, and what a client calls.
    ///
    /// Partial: `socketId` must be a listening socket with a non-empty queue,
    /// and a descriptor below the bound (`SimulatedUnixPlatform.descriptorBound`)
    /// must be free. `accept` answers EAGAIN (or parks) for an empty one, and
    /// EINVAL/EOPNOTSUPP for a socket that is not a listening stream socket, and
    /// refuses a full table, so reaching this in any other state is a bug in
    /// the caller. Internal for that reason.
    let internal acceptConnection<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (system : ProcessView<'Thread, 'Handler>)
        : int * TcpConnection * ProcessView<'Thread, 'Handler>
        =
        match
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)
        with
        | Error refusal ->
            failwith
                $"UnixConnection.acceptConnection: %s{DescriptorLimitRefusal.describe refusal} `accept` refuses this before reaching here (this is a bug in the caller)."
        | Ok () ->

        let listener = UnixMachineState.socket socketId system.Machine

        match listener.Phase with
        | SocketPhase.Listening ({
                                     Queue = queued :: rest
                                 } as listenState) ->
            let connectionId = queued.Connection
            let tcpConnection = UnixMachineState.connection connectionId system.Machine
            let acceptedId = system.Machine.NextSocketId
            let (SocketId rawAcceptedId) = acceptedId

            let fd, registry =
                FileDescriptorRegistry.createSocket
                    (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                    acceptedId
                    (UnixSystemState.fileDescriptors system)

            let accepted =
                {
                    // The listener's domain, and its IPV6_V6ONLY with it.
                    Addressing =
                        SocketAddressing.replaceBinding
                            (Some
                                {
                                    Endpoint = tcpConnection.ServerAddress
                                    // Nothing reads this on an accepted socket:
                                    // its phase is Established for life, so no
                                    // refusal delivery can ever revert it.
                                    LockedAddress = None
                                    LockedPort = false
                                    PortHold = PortHold.Reserved
                                })
                            listener.Addressing
                    Kind = SocketKind.Stream
                    Protocol = listener.Protocol
                    ReuseAddress = queued.ReuseAddress
                    Options = queued.Options
                    Phase = SocketPhase.Established (connectionId, ConnectionEnd.Server)
                    // Measured by `docs/probes/socket-creator-uid` (ACCEPT
                    // rows), with the listener made under one uid and the
                    // accept made under another: Darwin's accepted socket
                    // carries the listener's uid, and Linux's the accepting
                    // process's effective uid at accept(2).
                    Uid =
                        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
                        | SimulatedUnixFlavour.Darwin -> listener.Uid
                        | SimulatedUnixFlavour.Linux -> system.Process.Credentials.EffectiveUser
                }

            fd,
            tcpConnection,
            { system with
                Machine =
                    { system.Machine with
                        Sockets =
                            system.Machine.Sockets
                            |> Map.add acceptedId accepted
                            |> Map.add
                                socketId
                                { listener with
                                    Phase =
                                        SocketPhase.Listening
                                            { listenState with
                                                Queue = rest
                                            }
                                }
                        NextSocketId = SocketId (rawAcceptedId + 1L)
                    }
            }
            |> UnixSystemState.withFileDescriptors registry
        | SocketPhase.Listening {
                                    Queue = []
                                } ->
            failwith
                "UnixConnection.acceptConnection: the accept queue is empty; `accept` answers EAGAIN (or parks) before reaching this (this is a bug in the caller)."
        | phase ->
            failwith
                $"UnixConnection.acceptConnection: socket %O{socketId} is in %A{phase}, not listening; `accept` screens this (this is a bug in the caller)."

    /// Take the oldest connection off `socketId`'s accept queue and close its
    /// server end at once, without a descriptor: the state `acceptConnection`
    /// followed by `close` of the accepted descriptor would leave, bar the
    /// identities those would spend.
    let private dropConnection<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        let listener = UnixMachineState.socket socketId system.Machine

        let queued, listenState =
            match listener.Phase with
            | SocketPhase.Listening ({
                                         Queue = queued :: rest
                                     } as listenState) ->
                queued,
                { listenState with
                    Queue = rest
                }
            | phase ->
                failwith
                    $"UnixConnection.dropConnection: socket %O{socketId} is in %A{phase}, not listening with a connection queued; `accept` screens this (this is a bug in this library)."

        let connectionId = queued.Connection

        let sockets =
            Map.add
                socketId
                { listener with
                    Phase = SocketPhase.Listening listenState
                }
                system.Machine.Sockets

        // The client end, if the client has not closed it, is the only socket
        // left referencing the connection: an accept queue holds a connection
        // once, and only this one held it. Closing the server end leaves the
        // client half-closed, and the connection lives while the client does.
        let clients =
            sockets
            |> Map.toList
            |> List.choose (fun (survivorId, survivor) ->
                match survivor.Phase with
                | SocketPhase.Established (c, _)
                | SocketPhase.EstablishedPendingReport c when c = connectionId -> Some survivorId
                | _ -> None
            )

        // The server end closes as `close` closes it: a FIN, or a reset if the
        // client had written to it, and abortively under the `SO_LINGER` {1, 0}
        // its connection completed with (measured, `queued-options.c` section
        // D: the client reads ECONNRESET). It keeps the SO_REUSEADDR its socket
        // would have held, the listener's when the connection completed
        // (`QueuedConnection.ReuseAddress`, measured for the socket an accept
        // returns); that a dropped connection's end keeps it too is inferred
        // from Linux's source (`sk_clone_lock` in `tcp_create_openreq_child`),
        // not measured. It holds the listener's port as an accepted socket
        // would, and carries the listener's uid: what Darwin's accepted socket
        // carries, and on Linux what the end carries until an accept takes it,
        // inferred from the same source; no rule of Linux's this kernel models
        // reads it.
        let transfer = (UnixMachineState.connection connectionId system.Machine).Transfer

        let wakes, transfer =
            if queued.Options.Linger.Enabled && queued.Options.Linger.Hundredths = 0L then
                TcpTransfer.abort ConnectionEnd.Server queued.ReuseAddress PortHold.Reserved listener.Uid transfer
            else
                TcpTransfer.close ConnectionEnd.Server queued.ReuseAddress PortHold.Reserved listener.Uid transfer

        let system =
            { system with
                Machine =
                    { UnixMachineState.withTransfer
                          system.Scheduling.NanosecondsSinceBoot
                          connectionId
                          transfer
                          system.Machine with
                        Sockets = sockets
                    }
            }

        if List.isEmpty clients then
            // The client's socket has closed too, so the connection goes, and
            // its end in TIME_WAIT, if either is, with it.
            { system with
                Machine = UnixMachineState.forgetConnection connectionId system.Machine
            }
        else
            // The edge, raised once the tables reflect the close, as `close`
            // raises it.
            system |> SocketWake.signalTransfer connectionId wakes

    /// Hand the oldest connection on `socketId`'s queue over to the caller: the
    /// half of `accept(2)` that follows the choice of a connection, shared by a
    /// call that finds one at once and a parked call that finds one on waking.
    ///
    /// `nonBlocking` is the listening description's `O_NONBLOCK` as the
    /// connection is handed over, which is what Darwin's accepted socket
    /// inherits (measured, `blocking-accept.c` section F: a flag set while the
    /// call slept was inherited). `flags` is what the call's Linux `accept4`
    /// flags asked of the new socket, which it has from the moment it exists.
    let private handOver<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socketId : SocketId)
        (nonBlocking : bool)
        (flags : AcceptFlags)
        (destination : AcceptDestination)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<AcceptOutcome * ProcessView<'Thread, 'Handler>, AcceptRefusal>
        =
        // A connection is there to take, which needs a descriptor below the
        // limit: at a limit of the bound, EMFILE (measured, `fcntl-dup.c`,
        // LIMIT rows). A Linux accept that reaches here from its park took its
        // descriptor before it slept, which this kernel does not hold for it,
        // so with none left now it is refused all the same.
        match
            FileDescriptorRegistry.room
                (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                0
                1
                (UnixSystemState.fileDescriptors system)
        with
        | Error refusal -> Error (AcceptRefusal.DescriptorLimit refusal)
        | Ok () ->

        // Take the connection, and write of its client's address what
        // `address` says.
        let take
            (address : Ipv4Endpoint -> PeerAddressCopy)
            : Result<AcceptOutcome * ProcessView<'Thread, 'Handler>, AcceptRefusal>
            =
            let acceptedFd, connection, system = acceptConnection socketId system

            // `O_NONBLOCK` inheritance is the flavour's answer rather than this
            // kernel's convenience: Darwin's `accept(2)` copies the listening
            // description's flag onto the accepted socket and Linux's does not
            // (measured; see `acceptedSocketInheritsNonBlocking`). It is inherited
            // from the description the call was made through, so a `dup` of a
            // non-blocking listener passes the flag on too. Linux's comes from
            // `SOCK_NONBLOCK` alone (measured, `docs/probes/accept4-flags`,
            // section C).
            let inherited =
                nonBlocking
                && SimulatedUnixPlatform.acceptedSocketInheritsNonBlocking system.Machine.UnixPlatform

            let registry = UnixSystemState.fileDescriptors system

            let registry =
                if inherited || flags.AsksNonBlocking then
                    FileDescriptorRegistry.setNonBlocking acceptedFd true registry
                else
                    registry

            let registry =
                if flags.AsksCloseOnExec then
                    FileDescriptorRegistry.setFlags
                        acceptedFd
                        (DescriptorFlags.closingOnExec (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform) true)
                        registry
                else
                    registry

            let system = UnixSystemState.withFileDescriptors registry system

            Ok (AcceptOutcome.Accepted (acceptedFd, address connection.ClientAddress), system)

        match destination with
        | AcceptDestination.Null ->
            // Measured on both flavours (`socket-address-length.c`, the
            // `O4 accept NULL` rows): the call takes the connection at every
            // declared length, the negative ones included on Linux, and leaves
            // the length cell as it was. Neither kernel reads the cell.
            take (fun _ -> PeerAddressCopy.NotRequested)
        | AcceptDestination.Buffer (UserBuffer.Addressless, _) ->
            // Whether the kernel reads the length cell, and whether it writes
            // anything at all, turns on whether the address is NULL, which a
            // client with no number for it cannot say.
            Error (AcceptRefusal.Buffer BufferRefusal.AddresslessAtScreen)
        | AcceptDestination.Buffer (buffer, declaredLength) ->

        // Measured (`socket-address-length.c`): Linux reads the length cell as
        // an `int` only once it holds the connection, and answers EINVAL for a
        // negative one without touching the destination -- so the connection
        // is lost.
        if
            SimulatedUnixPlatform.flavour system.Machine.UnixPlatform = SimulatedUnixFlavour.Linux
            && int declaredLength < 0
        then
            Ok (AcceptOutcome.DroppedConnection UnixError.EINVAL, dropConnection socketId system)
        else

        // The destination is screened after the queue and before the dequeue,
        // which is the only place it can go: there is nothing to copy out until
        // a connection has been selected. A call that writes nothing never looks
        // at it at all.
        let destinationRefusal =
            if declaredLength = 0u then
                None
            else
                match buffer with
                | UserBuffer.Mapped -> None
                | UserBuffer.Opaque -> Some (AcceptRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
                | UserBuffer.Unmapped _ -> Some (AcceptRefusal.UnmeasuredCopyOutFault socketId)
                | UserBuffer.Addressless ->
                    failwith
                        "UnixConnection.accept: an addressless destination reached the copy-out, but it is refused before the length is read (this is a bug in this library)."

        match destinationRefusal with
        | Some refusal -> Error refusal
        | None ->

        take (fun clientAddress ->
            PeerAddressCopy.Written (
                SimulatedUnixPlatform.copyOutInternetSockaddr system.Machine.UnixPlatform clientAddress declaredLength,
                SimulatedUnixPlatform.internetSocketAddressSize
            )
        )

    /// `tryAccept` once `Entry` has admitted its caller.
    let private tryAcceptIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (fd : int)
        (destination : UserBuffer)
        (declaredLength : uint32 option)
        (flags : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<AcceptOutcome * ProcessView<'Thread, 'Handler>, AcceptRefusal>
        =
        match AcceptDestination.parse destination declaredLength with
        | Error refusal -> Error refusal
        | Ok parsedDestination ->

        let flavour = SimulatedUnixPlatform.flavour system.Machine.UnixPlatform

        match flavour with
        | SimulatedUnixFlavour.Darwin when flags <> 0 -> Error (AcceptRefusal.FlagsNotProvided flavour)
        | SimulatedUnixFlavour.Darwin
        | SimulatedUnixFlavour.Linux ->

        // The descriptor is classified before the destination is looked at, and
        // before the accept queue is: measured on both flavours, a closed
        // descriptor answers EBADF and a non-socket ENOTSOCK whatever the
        // destination and whatever the listener would have said.
        match FileDescriptorRegistry.tryFindWithId fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (AcceptOutcome.Failed UnixError.EBADF, system)
        | Some (descriptionId, description) ->

        // Measured (`docs/probes/accept4-flags`, sections A and B): an unknown
        // flag is EINVAL right after EBADF, ahead of every other answer, the
        // descriptor limit's included, and leaves the queue alone.
        match AcceptFlags.ofLinux flags with
        | None -> Ok (AcceptOutcome.Failed UnixError.EINVAL, system)
        | Some acceptFlags ->

        // Measured (`fcntl-dup.c`, LIMIT rows): Linux takes the new descriptor
        // right after EBADF, so with none left below the limit even a file's
        // ENOTSOCK and an empty listener's EAGAIN are EMFILE. Darwin takes it
        // only with a connection to hand over (`handOver`).
        let linuxRoom =
            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Darwin -> Ok ()
            | SimulatedUnixFlavour.Linux ->
                FileDescriptorRegistry.room
                    (SimulatedUnixPlatform.descriptorBound system.Machine.UnixPlatform)
                    0
                    1
                    (UnixSystemState.fileDescriptors system)

        match linuxRoom with
        | Error refusal -> Error (AcceptRefusal.DescriptorLimit refusal)
        | Ok () ->

        match description.Target with
        | OpenFileTarget.File _
        | OpenFileTarget.Directory _
        | OpenFileTarget.CharacterDevice _
        | OpenFileTarget.Fifo _
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Pipe _
        | OpenFileTarget.Kqueue _
        | OpenFileTarget.Epoll _ -> Ok (AcceptOutcome.Failed UnixError.ENOTSOCK, system)
        | OpenFileTarget.Socket socketId ->

        let socket = UnixMachineState.socket socketId system.Machine

        match socket.Domain with
        | SocketDomain.Inet6
        | SocketDomain.Unix -> Error (AcceptRefusal.UnmodelledDomain (socketId, socket.Domain))
        | SocketDomain.Inet ->

        match socket.Kind with
        | SocketKind.Datagram ->
            // The kind check beats the listening check: measured on both, a
            // datagram socket -- which is also "not listening" -- answers
            // EOPNOTSUPP, blocking or not.
            Ok (AcceptOutcome.Failed UnixError.EOPNOTSUPP, system)
        | SocketKind.SeqPacket -> Error (AcceptRefusal.UnmeasuredKind (socketId, socket.Kind))
        | SocketKind.Stream ->

        match socket.Phase with
        | SocketPhase.Connecting _ -> ReservedConnecting.fail "UnixConnection.accept" socketId
        | SocketPhase.DatagramPeer _ ->
            failwith
                $"UnixConnection.accept: socket %O{socketId} is a stream socket holding SocketPhase.DatagramPeer, a pairing this kernel's socket invariants forbid (this is a bug in the caller's state construction)."
        | SocketPhase.Idle
        | SocketPhase.EstablishedPendingReport _
        | SocketPhase.Established _
        | SocketPhase.Refused _ ->
            // ...and the listening check beats blocking behaviour: measured on
            // both, a *blocking* non-listening socket answers EINVAL
            // immediately rather than parking. Measured for idle sockets, bound
            // or not; the other non-listening phases share the answer because it
            // is the same kernel test (Linux's TCP_LISTEN check, Darwin's
            // SO_ACCEPTCONN check).
            Ok (AcceptOutcome.Failed UnixError.EINVAL, system)
        | SocketPhase.Listening listenState ->

        match listenState.Queue with
        | [] ->
            // `O_NONBLOCK` is a fact about the open file description `fd` came
            // through, not about the socket, so an accept through a `dup` of a
            // non-blocking listener answers EAGAIN too. Measured on Darwin
            // (close-ends-call.c section A7a), a drained listener's is EAGAIN
            // too.
            if description.NonBlocking then
                Ok (AcceptOutcome.Failed UnixError.EAGAIN, system)
            elif listenState.Drained then
                Error (AcceptRefusal.DarwinDrainedListener socketId)
            else
                // Measured (`docs/probes/accept4-flags`, section D):
                // `SOCK_NONBLOCK` is the new socket's, so the call sleeps, and
                // the socket it hands over on waking has the flags.
                let parked =
                    ParkedSyscall.Accept
                        {
                            Listener = SleepTarget.Waiting (descriptionId, fd)
                            Destination = destination
                            DeclaredLength = declaredLength
                            NewSocketNonBlocking = acceptFlags.AsksNonBlocking
                            NewSocketCloseOnExec = acceptFlags.AsksCloseOnExec
                        }

                Ok (AcceptOutcome.WouldBlock (WakeCondition.ofPark parked), Parking.parkWaiting thread parked system)
        | _ :: _ -> handOver socketId description.NonBlocking acceptFlags parsedDestination system

    /// `accept`, with a refusal answered as the `Error` rather than raised.
    let internal tryAccept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (declaredLength : uint32 option)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<AcceptOutcome * UnixSystem<'Thread, 'Handler>, AcceptRefusal>
        =
        Entry.call
            "UnixConnection.accept"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryAcceptIn (Caller.thread caller) fd destination declaredLength flags)
            system

    /// `accept(2)`, made by `caller`: take the oldest completed connection off
    /// `fd`'s accept queue and hand back a descriptor onto the server side of
    /// it; or, for a blocking listener with nothing queued, sleep until a
    /// connection arrives.
    ///
    /// `destination` is where the peer address would be copied out, and
    /// `declaredLength` how much of it may be written. As for `getsockname`, the
    /// declared length **does not bound what is reported**: a call declaring 8
    /// writes eight bytes and still reports 16.
    ///
    /// `declaredLength` is the 32-bit word the caller read out of its length
    /// cell. Linux reads it as an `int`, and only once it holds a connection:
    /// a negative one fails with `EINVAL` after the connection has been taken
    /// off the queue, which loses it (`AcceptOutcome.DroppedConnection`).
    /// Darwin reads it as the `socklen_t` it is, so no length is an error there.
    ///
    /// A NULL `destination` (`UserBuffer.Unmapped 0UL`) takes no length, and
    /// `declaredLength` is then `None`; for any other destination it is `Some`,
    /// and a call that breaks either rule throws `ArgumentException`. Neither
    /// flavour reads or writes the length cell through a NULL destination, so
    /// such a call takes the connection and writes nothing
    /// (`PeerAddressCopy.NotRequested`), whatever the cell holds; a cell that is
    /// itself NULL, as in `accept(fd, NULL, NULL)`, is never dereferenced.
    ///
    /// A call that writes nothing through a destination other than NULL never
    /// looks at it: at a declared length of zero every such buffer succeeds,
    /// including one naming no storage. A `UserBuffer.Addressless` one is the
    /// exception, refused once a connection is there to take, since whether the
    /// kernel writes the length cell turns on whether it is NULL.
    ///
    /// Every `AcceptOutcome.Failed` leaves the listener exactly as it was, the
    /// queue included.
    ///
    /// A listener whose description is blocking and whose queue is empty parks
    /// the caller's thread until a connection is queued, and the call is finished with
    /// `finishAccept`. It waits for ever: `SO_RCVTIMEO`, which bounds such a
    /// wait on Linux (and not on Darwin), is an option `setsockopt` refuses to
    /// set. Of several threads parked on one listener, a connection wakes the one
    /// that parked first (see `UnixWait.wake`). The destination is not looked
    /// at before the call sleeps.
    ///
    /// Under Darwin, a close of the descriptor a sleeping accept was made
    /// through ends every accept asleep on the listener, through that
    /// descriptor or another, and leaves the listener drained
    /// (`ListenState.Drained`); see `UnixDescriptor.close`. A later accept on
    /// it that finds a connection queued takes it, and a non-blocking one that
    /// finds none answers `EAGAIN`; one that would sleep is refused.
    ///
    /// The accepted descriptor inherits `O_NONBLOCK` from the description this
    /// call was made through, on the flavours whose kernels do that: see
    /// `SimulatedUnixPlatform.acceptedSocketInheritsNonBlocking`. A client whose
    /// own sockets want one answer on every platform clears it itself.
    ///
    /// `flags` is Linux's `accept4(2)` flag word, and 0 is `accept(2)`. Its
    /// `SOCK_NONBLOCK` makes the new socket non-blocking and its `SOCK_CLOEXEC`
    /// gives the new descriptor `FD_CLOEXEC`, from the moment the call makes
    /// them, a call that slept included; neither changes whether the call
    /// itself sleeps. Any other bit is `EINVAL`, after `EBADF` and ahead of
    /// every other answer. Darwin has no `accept4`, so there a `flags` other
    /// than 0 throws `PlatformNotSupportedException`.
    ///
    /// The caller's thread must not already be parked.
    let accept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (declaredLength : uint32 option)
        (flags : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : AcceptOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryAccept caller fd destination declaredLength flags system
        |> Refusal.orRaise "UnixConnection.accept" AcceptRefusal.kind AcceptRefusal.describe

    /// Whether a thread of any process on the machine but `thread` of this one
    /// is asleep in an accept on the listener the open file description
    /// `listener` names.
    let private anotherAsleepOn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (listener : OpenFileDescriptionId)
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : bool
        =
        let asleepOnListener (state : UnixThreadState) : bool =
            match state.Parked with
            | Some {
                       State = ParkState.Asleep
                       Syscall = ParkedSyscall.Accept {
                                                          Listener = SleepTarget.Waiting (waitingOn, _)
                                                      }
                   } -> waitingOn = listener
            | _ -> false

        // Only parked threads can be asleep on it, so only those are asked.
        let anyAsleep (except : 'Thread voption) (threads : ThreadTable<'Thread>) : bool =
            UnixThreadTable.parked threads
            |> Set.exists (fun name -> except <> ValueSome name && asleepOnListener (UnixThreadTable.get name threads))

        anyAsleep (ValueSome thread) system.Threads
        || (ProcessTable.withParks system.Others
            |> Set.exists (fun key ->
                anyAsleep ValueNone (ProcessTable.find "UnixConnection.accept" key system.Others).Threads
            ))

    let private finishAcceptHolding<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<AcceptOutcome * ProcessView<'Thread, 'Handler>, AcceptRefusal>
        =
        let parked =
            UnixThreadTable.expectParked
                "UnixConnection.finishAccept"
                (fun parked ->
                    match parked with
                    | ParkedSyscall.Accept parked -> Some parked
                    | _ -> None
                )
                thread
                system.Threads

        match parked.Listener with
        | SleepTarget.EndedByClose _ ->
            // Measured on Darwin 27.0.0 (`close-ends-call.c`, sections A1-A4):
            // ECONNABORTED, whatever is queued and whatever signal is pending,
            // since a woken accept on a drained listener answers it whatever
            // woke it (section A7).
            Ok (AcceptOutcome.Failed UnixError.ECONNABORTED, (UnixParkState.unpark thread system))
        | SleepTarget.Waiting (listenerId, _) ->

        let description =
            match OpenFileTable.tryFind listenerId system.Machine.OpenFiles with
            | Some description -> description
            | None ->
                failwith
                    $"UnixConnection.finishAccept: thread %O{thread}'s accept waits on open file description %O{listenerId}, which is not in the table, but a park holds its description until the call returns (this is a bug in this library, or in a caller that ended a park without its finishing call or assembled the state by hand)."

        let socketId =
            match description.Target with
            | OpenFileTarget.Socket socketId -> socketId
            | OpenFileTarget.File _
            | OpenFileTarget.Directory _
            | OpenFileTarget.CharacterDevice _
            | OpenFileTarget.Fifo _
            | OpenFileTarget.Inotify _
            | OpenFileTarget.Pipe _
            | OpenFileTarget.Kqueue _
            | OpenFileTarget.Epoll _ ->
                failwith
                    $"UnixConnection.finishAccept: thread %O{thread}'s accept waits on open file description %O{listenerId}, which names %A{description.Target} rather than a socket. `accept` parks only on a listening socket (this is a bug in the caller that recorded the park)."

        let finished = (UnixParkState.unpark thread system)

        match (UnixMachineState.socket socketId system.Machine).Phase with
        | SocketPhase.Listening {
                                    Drained = true
                                } ->
            failwith
                $"UnixConnection.finishAccept: thread %O{thread}'s accept sleeps on socket %O{socketId}, which a close has drained. The close that drains a listener ends every accept asleep on it, and `accept` refuses to sleep on a drained one (this is a bug in this library, or in a caller that assembled the state by hand)."
        | SocketPhase.Listening {
                                    Queue = _ :: _
                                } ->
            // Measured on Linux 6.18.5 (`signal-interrupt-requeue.c`, section
            // D): a queued connection beats a pending signal. On Darwin a
            // pending signal beats it (`SyscallInterruption.beforeCompleting`).
            match SyscallInterruption.beforeCompleting thread system with
            | Error refusal -> Error (AcceptRefusal.Interruption refusal)
            | Ok SyscallInterruption.Completion.Completes ->
                let flags =
                    {
                        AsksNonBlocking = parked.NewSocketNonBlocking
                        AsksCloseOnExec = parked.NewSocketCloseOnExec
                    }

                match AcceptDestination.parse parked.Destination parked.DeclaredLength with
                | Error refusal -> Error refusal
                | Ok destination -> handOver socketId description.NonBlocking flags destination finished
            | Ok (SyscallInterruption.Completion.Interrupted interruption) ->
                // Measured on Darwin 27.0.0 (`docs/probes/first-wake`, the
                // two-sleeper accept rows): an accepter woken by a connection
                // and then signalled fails with EINTR, and the connection stays
                // queued without waking the accepter asleep behind it. This
                // library wakes a sleeper from the state alone, so would wake
                // that one for the connection, and refuses.
                let wokenByConnection =
                    SyscallInterruption.wokenBy thread system
                    |> Set.contains (WakePrimitive.AcceptQueueNonEmpty listenerId)

                if wokenByConnection && anotherAsleepOn listenerId thread system then
                    Error (AcceptRefusal.SignalBesideConsumedWake listenerId)
                else
                    Ok (AcceptOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
        | SocketPhase.Listening {
                                    Queue = []
                                } ->
            // Measured on Linux 6.18.5 and Darwin 27.0.0
            // (`signal-interrupt-requeue.c`, section B): an accepter that a
            // signal ends, restarted or calling again on EINTR, returns after
            // every accepter that parked before it, so it has left the queue.
            match SyscallInterruption.ofPark thread system with
            | Error refusal -> Error (AcceptRefusal.Interruption refusal)
            | Ok (Some interruption) ->
                Ok (AcceptOutcome.Interrupted, OwedReturns.interrupt thread interruption finished)
            | Ok None ->
                let parkedAgain = ParkedSyscall.Accept parked

                Ok (
                    AcceptOutcome.WouldBlock (WakeCondition.ofPark parkedAgain),
                    Parking.parkWaiting thread parkedAgain system
                )
        | phase ->
            failwith
                $"UnixConnection.finishAccept: thread %O{thread}'s accept waits on socket %O{socketId}, which is in %A{phase} rather than listening. Nothing takes a live listener out of listening, so the park was recorded on a socket that was never one (this is a bug in the caller that recorded it)."

    /// `tryFinishAccept` once `Entry` has admitted its caller.
    let internal tryFinishAcceptIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<AcceptOutcome * ProcessView<'Thread, 'Handler>, AcceptRefusal>
        =
        let held =
            match UnixThreadTable.parkedFor thread system.Threads with
            | Some parked -> ParkedSyscall.descriptions parked
            | None -> []

        // The call's reference to the listener goes as it returns, and with it
        // the listener, if no descriptor names it any more
        // (`open-file-references.c` section A1).
        match finishAcceptHolding thread system with
        | Error refusal -> Error refusal
        | Ok (outcome, after) ->
            Ok (outcome, ObjectLifetime.releaseUnreferencedUnrefusable "UnixConnection.finishAccept" held after)

    /// `finishAccept`, with a refusal answered as the `Error` rather than raised.
    let internal tryFinishAccept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<AcceptOutcome * UnixSystem<'Thread, 'Handler>, AcceptRefusal>
        =
        Entry.call
            "UnixConnection.finishAccept"
            CallerRequirement.Woken
            caller
            (Shape.result Shape.withSystem)
            (tryFinishAcceptIn (Caller.thread caller))
            system

    /// Finish the `accept` `caller` is parked in: look at the listener's queue
    /// again, as a woken real accept does, and answer.
    ///
    /// Hands over the oldest connection on the queue, copying its peer address
    /// out to the destination the call was entered with; see `accept` for the
    /// destinations that refuses. A queue found empty again (another caller
    /// took the connection) parks the thread again, behind every other park,
    /// which on a real kernel puts it at the back of the listener's queue of
    /// accepters. So does a listener whose description has become non-blocking
    /// while the call slept: measured on both flavours (`blocking-accept.c`
    /// section F), a sleeping accept is not woken by that, and goes on waiting.
    ///
    /// On the flavours whose accepted socket inherits `O_NONBLOCK`, it inherits
    /// the listening description's flag as it stands when the call finishes.
    ///
    /// With the queue empty, a signal the thread would take as it returned to
    /// user mode interrupts the call (`AcceptOutcome.Interrupted`), and the
    /// thread's return (`UnixSignal.onReturnToUser`) says whether it fails
    /// with `EINTR` or restarts. Either way the thread leaves the listener's
    /// queue of accepters, and issuing the call again puts it at the back. An
    /// answer, `Interrupted` included, clears the park. Under Linux a queued
    /// connection beats such a signal; under Darwin the signal beats it, and
    /// the connection stays queued. Under Darwin a call a connection woke is
    /// refused where such a signal is pending and another thread is asleep in
    /// an accept on the listener: Darwin leaves that thread asleep, the
    /// connection whose wake the first took still queued, where this library
    /// would wake it.
    ///
    /// The sleeping call holds the listener, so it outlives its last descriptor
    /// until the call returns. A listener no descriptor names goes as the call
    /// answers, resetting each connection left in its queue, as a close of the
    /// listener's last descriptor does.
    ///
    /// An accept a close has ended (`SleepTarget.EndedByClose`, under Darwin)
    /// answers `ECONNABORTED`, whatever is queued and whatever signal is
    /// pending, and leaves the queue as it is.
    ///
    /// `caller` must be parked in an accept, and woken (`UnixWait.wake`).
    let finishAccept<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : AcceptOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFinishAccept caller system
        |> Refusal.orRaise "UnixConnection.finishAccept" AcceptRefusal.kind AcceptRefusal.describe

    /// `tryShutdown` once `Entry` has admitted its caller.
    let private tryShutdownIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (fd : int)
        (how : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<ShutdownAnswer * ProcessView<'Thread, 'Handler>, ShutdownRefusal>
        =
        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
        | None -> Ok (ShutdownAnswer.Failed UnixError.EBADF, system)
        | Some target ->

        match target with
        | OpenFileTarget.File _
        | OpenFileTarget.Directory _
        | OpenFileTarget.CharacterDevice _
        | OpenFileTarget.Pipe _
        | OpenFileTarget.Kqueue _
        | OpenFileTarget.Epoll _
        | OpenFileTarget.Inotify _
        | OpenFileTarget.Fifo _ -> Ok (ShutdownAnswer.Failed UnixError.ENOTSOCK, system)
        | OpenFileTarget.Socket socketId ->

        let socket = UnixMachineState.socket socketId system.Machine

        match socket.Domain with
        | SocketDomain.Unix -> Error (ShutdownRefusal.UnmodelledDomain (socketId, socket.Domain))
        | SocketDomain.Inet
        | SocketDomain.Inet6 ->

        match socket.Kind with
        | SocketKind.SeqPacket -> Error (ShutdownRefusal.UnmeasuredKind (socketId, socket.Kind))
        | SocketKind.Stream
        | SocketKind.Datagram ->

        let parsed =
            match how with
            | 0 -> Some TcpShutdownHow.Read
            | 1 -> Some TcpShutdownHow.Write
            | 2 -> Some TcpShutdownHow.Both
            | _ -> None

        match parsed with
        | None -> Ok (ShutdownAnswer.Failed UnixError.EINVAL, system)
        | Some how ->

        let unconnected () : Result<ShutdownAnswer * ProcessView<'Thread, 'Handler>, ShutdownRefusal> =
            match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
            | SimulatedUnixFlavour.Darwin -> Ok (ShutdownAnswer.Failed UnixError.ENOTCONN, system)
            | SimulatedUnixFlavour.Linux -> Error (ShutdownRefusal.LinuxUnconnected socketId)

        match socket.Phase with
        | SocketPhase.Connecting _ -> ReservedConnecting.fail "UnixConnection.shutdown" socketId
        | SocketPhase.Listening _ -> Error (ShutdownRefusal.Listener socketId)
        | SocketPhase.DatagramPeer _ -> Error (ShutdownRefusal.ConnectedDatagram socketId)
        | SocketPhase.Idle
        | SocketPhase.Refused _ -> unconnected ()
        | SocketPhase.EstablishedPendingReport _
        | SocketPhase.Established _ ->

        let connectionId, connectionEnd =
            match SocketPhase.connectionEnd socket.Phase with
            | Some held -> held
            | None ->
                failwith
                    $"UnixConnection.shutdown: socket %O{socketId} is in %A{socket.Phase}, which holds no connection end (this is a bug in this library)."

        let transfer = (UnixMachineState.connection connectionId system.Machine).Transfer

        match TcpTransfer.shutdown connectionEnd how transfer with
        | Error (TcpShutdownRefusal.DarwinReceiveShutBeforeUnsentBytes (_, unsent)) ->
            Error (ShutdownRefusal.ReceiveShutBeforeUnsentBytes (socketId, unsent))
        | Ok (answer, wakes, transfer) ->

        // `inet_shutdown` moves a socket whose connect is still to be
        // reported to `SS_CONNECTED`.
        let phase =
            match socket.Phase with
            | SocketPhase.EstablishedPendingReport connection ->
                SocketPhase.Established (connection, ConnectionEnd.Client)
            | phase -> phase

        let system =
            { system with
                Machine =
                    { UnixMachineState.withTransfer
                          system.Scheduling.NanosecondsSinceBoot
                          connectionId
                          transfer
                          system.Machine with
                        Sockets =
                            Map.add
                                socketId
                                { socket with
                                    Phase = phase
                                }
                                system.Machine.Sockets
                    }
            }

        let answer =
            match answer with
            | TcpShutdownAnswer.Shut -> ShutdownAnswer.Shut
            | TcpShutdownAnswer.NotConnected -> ShutdownAnswer.Failed UnixError.ENOTCONN

        Ok (answer, SocketWake.signalTransfer connectionId wakes system)

    /// `shutdown`, with a refusal answered as the `Error` rather than raised.
    let internal tryShutdown<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (how : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<ShutdownAnswer * UnixSystem<'Thread, 'Handler>, ShutdownRefusal>
        =
        Entry.call
            "UnixConnection.shutdown"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryShutdownIn fd how)
            system

    /// `shutdown(2)` of `fd`, with `how` raw: `SHUT_RD` (0), `SHUT_WR` (1) or
    /// `SHUT_RDWR` (2) on both flavours.
    ///
    /// Screened in the measured order (`tcp-shutdown.c` in
    /// docs/plans/2026-10-08-tcp-shutdown-linger, section U): EBADF, then
    /// ENOTSOCK, then EINVAL for any other `how`, then the socket's state.
    /// An IPv4 or IPv6 socket with no connection answers ENOTCONN under
    /// Darwin, and is refused under Linux, which still marks the sides `how`
    /// names shut, for a later connection, where this kernel keeps no shut
    /// sides on a socket without a connection.
    ///
    /// On a connected stream socket the call shuts the sides `how` names, by
    /// each flavour's rules: shutting the send side
    /// sends a FIN behind what is still unsent; shutting the receive side makes
    /// reads answer end of file once what was queued is read, which Darwin
    /// discards. Linux answers ENOTCONN once the connection was reset or both
    /// FINs have arrived; Darwin answers ENOTCONN to a side already shut, and
    /// of `SHUT_RDWR` applies the receive side alone if the send side was
    /// already shut, and nothing if the receive side was. Every registration
    /// the call's wakes reach is signalled: on Linux every one on the socket,
    /// for every call; on Darwin the filter of each side it shut; and the
    /// peer's, when the FIN reaches it. A Linux socket whose completed connect
    /// had not been reported is reported by the call: a later `connect`
    /// answers EISCONN (measured, section U, `connect-unreported`).
    ///
    /// A parked read or write on either end may have an answer afterwards;
    /// `UnixWait.wake` finds it.
    let shutdown<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (how : int)
        (system : UnixSystem<'Thread, 'Handler>)
        : ShutdownAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryShutdown caller fd how system
        |> Refusal.orRaise "UnixConnection.shutdown" ShutdownRefusal.kind ShutdownRefusal.describe
