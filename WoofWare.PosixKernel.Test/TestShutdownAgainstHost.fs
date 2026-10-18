namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Runtime.InteropServices
open System.Threading
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `shutdown(2)` on connected loopback TCP sockets, and what each end then
/// sees, and `close(2)` under `SO_LINGER` {1, 0}: sections S, T, R, P, E, L
/// and F, and the connected rows of U, of
/// `tcp-shutdown.c` (docs/plans/2026-10-08-tcp-shutdown-linger), and the
/// binds of an endpoint an end still holds, by `bind-held-endpoint.c` beside
/// it, measured on Linux 6.18.5 aarch64 and Darwin 27.0, replayed against the
/// host the suite runs on and against this kernel's syscalls, each driven as
/// the probe drives its pair (`ShutdownProbe`). Each host falsifies its own
/// column: Darwin's here, Linux's on CI's x86-64. The kernel is held to both
/// flavours' rows on every host.
///
/// A line marked `~timing` is not compared, and a `~counts` line is compared
/// without its counts. The host ignores `SIGPIPE`, so its writes report no
/// signal, and the probe's `+SIGPIPE` is not compared against it. The listener
/// rows of E are stage 5's, and so are not replayed. This kernel forgets a
/// connection once neither socket refers to it, so the `TIME_WAIT` an end
/// whose FIN was made first leaves once both sockets have closed is
/// unmodelled, and F's lines that bind after both have closed are the
/// host's alone. The probe's fill and settles do not always bring a Darwin
/// pair to the state its rows were measured in (`fill-settling.c` beside
/// it), so a host pair waits for every byte to be acknowledged before it
/// closes an end, and a scenario whose pair still left that state is run
/// again on fresh pairs.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestShutdownAgainstHost =

    let private c : ConnectionEnd = ConnectionEnd.Client
    let private p : ConnectionEnd = ConnectionEnd.Server

    // ------------------------------------------------------------------
    // The host
    // ------------------------------------------------------------------

    [<DllImport("libc", EntryPoint = "getpeername", SetLastError = true)>]
    extern int private hostGetPeerName(int fd, byte[] address, uint32& length)

    [<DllImport("libc", EntryPoint = "shutdown", SetLastError = true)>]
    extern int private hostShutdown(int fd, int how)

    [<DllImport("libc", EntryPoint = "epoll_wait", SetLastError = true)>]
    extern int private hostEpollWait(int epfd, byte[] events, int maxEvents, int timeoutMs)

    [<DllImport("libc", EntryPoint = "kevent", SetLastError = true)>]
    extern int private hostKevent(int kq, byte[] changes, int nchanges, byte[] events, int nevents, int64[] timeout)

    [<Literal>]
    let private AF_INET = 2

    [<Literal>]
    let private SOCK_STREAM = 1

    let private lingerOption (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 13
        | SimulatedUnixFlavour.Darwin -> 0x80

    /// What the probe's `rdy` asks `poll` for: IN|OUT|PRI, and RDHUP on Linux.
    let private rdyEvents (flavour : SimulatedUnixFlavour) : int16 =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 0x2007s
        | SimulatedUnixFlavour.Darwin -> 0x7s

    /// `POLLIN`, the same on Linux and Darwin.
    let private pollIn : int16 = 0x1s

    /// How long a host drain waits, past the probe's three dry reads, for
    /// more to read before it takes EAGAIN as its answer.
    let private drainPatienceMs : int = 5000

    /// How long a Darwin host pair waits, before an end closes, for every
    /// byte an open end has sent to be acknowledged.
    let private acknowledgementPatienceMs : int = 2000

    /// Darwin's `SO_RCVBUF`, which reads back the receive buffer's size as
    /// the kernel has grown it.
    let private darwinReceiveBufferOption : int = 0x1002

    /// What Darwin's `TCP_CONNECTION_INFO` (`struct tcp_connection_info` of
    /// `<netinet/tcp.h>`) says of what an end has sent.
    type private DarwinSending =
        {
            /// `tcpi_state`, a `TCPS_*` of `<netinet/tcp_fsm.h>`.
            State : int
            /// `tcpi_snd_sbbytes`: the bytes in the send buffer, sent or not,
            /// that the peer has not acknowledged.
            Buffered : int64
            /// `tcpi_txbytes` less `tcpi_txretransmitbytes`: each byte sent
            /// counted once.
            Sent : int64
        }

    let private darwinSendingOf (fd : int) : DarwinSending =
        // sizeof (struct tcp_connection_info) on Darwin 27.0 arm64, whose
        // tcpi_snd_sbbytes is at 32, tcpi_txbytes at 64 and
        // tcpi_txretransmitbytes at 72.
        let info = Array.zeroCreate<byte> 112
        let mutable length = uint32 info.Length

        // IPPROTO_TCP, TCP_CONNECTION_INFO
        if HostCalls.getSockOptBytes (fd, 6, 0x106, info, &length) < 0 then
            failwith $"getsockopt(TCP_CONNECTION_INFO) failed with errno %d{Marshal.GetLastPInvokeError ()}"

        if length <> uint32 info.Length then
            failwith $"getsockopt(TCP_CONNECTION_INFO) gave %d{length} bytes, not %d{info.Length}"

        {
            State = int info.[0]
            Buffered = int64 (BitConverter.ToUInt32 (info, 32))
            Sent = int64 (BitConverter.ToUInt64 (info, 64) - BitConverter.ToUInt64 (info, 72))
        }

    /// The bytes a Darwin end has sent that its peer has not acknowledged,
    /// `written` being all that its writes took; `None` once its connection
    /// has been reset (`TCPS_CLOSED`) or is in `TIME_WAIT`, whose counters
    /// Darwin zeroes.
    let private darwinUnacknowledged (fd : int) (written : int64) : int64 option =
        let sending = darwinSendingOf fd

        // TCPS_ESTABLISHED (4) through TCPS_FIN_WAIT_2 (9)
        if sending.State < 4 || sending.State > 9 then
            None
        else
            let unacknowledged = sending.Sent - (written - sending.Buffered)

            if unacknowledged < 0L then
                failwith
                    $"fd %d{fd} has sent %d{sending.Sent} bytes, fewer than the %d{written - sending.Buffered} its peer has acknowledged"

            Some unacknowledged

    let private hostBuffer : byte[] = Array.zeroCreate (1 <<< 20)

    /// The size of `struct epoll_event`: packed on x86-64, padded elsewhere.
    let private epollEventSize : int =
        if RuntimeInformation.ProcessArchitecture = Architecture.X64 then
            12
        else
            16

    let private epollEvent (events : uint32) (data : uint64) : byte[] =
        let bytes = Array.zeroCreate<byte> epollEventSize
        BitConverter.GetBytes(events).CopyTo (bytes, 0)
        BitConverter.GetBytes(data).CopyTo (bytes, epollEventSize - 8)
        bytes

    /// The `struct kevent` registering `fd`'s `filter` with `flags`.
    let private keventChange (fd : int) (filter : int16) (flags : uint16) : byte[] =
        let bytes = Array.zeroCreate<byte> 32
        BitConverter.GetBytes(uint64 fd).CopyTo (bytes, 0)
        BitConverter.GetBytes(filter).CopyTo (bytes, 8)
        BitConverter.GetBytes(flags).CopyTo (bytes, 10)
        bytes

    /// Each event in a returned `struct kevent` array: ident, filter, flags,
    /// fflags, data.
    let private keventsOf (bytes : byte[]) (count : int) : (int * int16 * uint16 * uint32 * int64) list =
        [
            for k in 0 .. count - 1 do
                let at = 32 * k

                int (BitConverter.ToUInt64 (bytes, at)),
                BitConverter.ToInt16 (bytes, at + 8),
                BitConverter.ToUInt16 (bytes, at + 10),
                BitConverter.ToUInt32 (bytes, at + 12),
                BitConverter.ToInt64 (bytes, at + 16)
        ]

    let private renderKevent (data : int64) (flags : uint16) (fflags : uint32) : string =
        let eof = if flags &&& KeventFlags.Eof <> 0us then "/EOF" else ""
        $"%d{data}%s{eof}/%d{fflags}"

    /// A TCP socket as `/proc/net/tcp` or `/proc/net/tcp6` lists it.
    type private ListedTcpSocket =
        {
            /// The local address as listed: eight hex digits for IPv4, 32 for
            /// IPv6, each 32-bit word in the host's byte order.
            LocalAddress : string
            LocalPort : int
            RemotePort : int
            /// The file and line it was listed on.
            Line : string
        }

    /// Each TCP socket in this Linux host's network namespace, whichever process
    /// holds it, as `/proc/net/tcp` and `/proc/net/tcp6` list it.
    let private linuxTcpSockets () : ListedTcpSocket list =
        let portOf (field : string) : int =
            Convert.ToInt32 (field.Substring (field.LastIndexOf ':' + 1), 16)

        [
            for path in [ "/proc/net/tcp" ; "/proc/net/tcp6" ] do
                // A host without IPv6 has no tcp6, and so no IPv6 sockets.
                if path = "/proc/net/tcp" || IO.File.Exists path then
                    for line in IO.File.ReadAllLines path |> Array.skip 1 do
                        let fields = line.Split (' ', StringSplitOptions.RemoveEmptyEntries)

                        {
                            LocalAddress = fields.[1].Substring (0, fields.[1].LastIndexOf ':')
                            LocalPort = portOf fields.[1]
                            RemotePort = portOf fields.[2]
                            Line = $"%s{path}: %s{line.Trim ()}"
                        }
        ]

    /// Whether a socket on a port, at `localAddress` as `/proc/net/tcp` or
    /// `/proc/net/tcp6` lists it, would refuse an IPv4 bind of that port at
    /// the wildcard address if `wildcard` and at 127.0.0.1 otherwise: whether
    /// the two addresses overlap. An IPv6 socket at `::` counts, since a
    /// listing does not say whether it is `IPV6_V6ONLY`.
    let private refusesIpv4Bind (wildcard : bool) (localAddress : string) : bool =
        // The listing's words are in host byte order, which these literals
        // spell for a little-endian host.
        if not BitConverter.IsLittleEndian then
            failwith "a /proc/net/tcp address is read only on a little-endian host"

        let overlapsIpv4 (ipv4 : string) : bool =
            wildcard || ipv4 = "00000000" || ipv4 = "0100007F"

        match localAddress.Length with
        | 8 -> overlapsIpv4 localAddress
        | 32 ->
            let mapped = "0000000000000000FFFF0000"

            localAddress = String ('0', 32)
            || (localAddress.StartsWith (mapped, StringComparison.Ordinal)
                && overlapsIpv4 (localAddress.Substring mapped.Length))
        | _ -> failwith $"a /proc/net/tcp local address of unexpected length: %s{localAddress}"

    /// The host's IPv4 addresses outside 127.0.0.0/8, as its interfaces list
    /// them now: they come and go, as a virtual machine's bridge does.
    let private nonLoopbackIpv4Addresses () : Ipv4Address list =
        Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetUnicastAddresses ()
        |> Seq.map (fun unicast -> unicast.Address)
        |> Seq.filter (fun address -> address.AddressFamily = Net.Sockets.AddressFamily.InterNetwork)
        |> Seq.map (fun address ->
            Ipv4Address (
                Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian (ReadOnlySpan (address.GetAddressBytes ()))
            )
        )
        |> Seq.filter (fun address -> not (Ipv4Prefix.contains address Ipv4Prefix.loopbackNetwork))
        |> Seq.distinct
        |> Seq.toList

    /// Each of the host's IPv4 addresses outside 127.0.0.0/8 at which a bind
    /// of `port` without `SO_REUSEADDR` was refused with `EADDRINUSE`, so
    /// that some socket holds the port there or at the wildcard. On both
    /// flavours, a pair's own sockets, all at 127.0.0.1, never refuse such a
    /// bind, in any state `bind-held-endpoint.c` brings an end to; a socket
    /// there refuses it whether bound, listening, connected or in TIME_WAIT
    /// with no descriptor, and so does one bound or listening at the wildcard
    /// (`port-held-elsewhere.c`, C).
    let private heldElsewhere (flavour : SimulatedUnixFlavour) (port : int) : Ipv4Address list =
        let platform = HostPlatform.platformOf flavour

        let errno =
            UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform)

        nonLoopbackIpv4Addresses ()
        |> List.filter (fun address ->
            let fd = HostCalls.socket (AF_INET, SOCK_STREAM, 0)

            if fd < 0 then
                failwith $"socket failed with errno %d{Marshal.GetLastPInvokeError ()}"

            let sockaddr =
                SimulatedUnixPlatform.encodeInternetSockaddr platform (Ipv4Endpoint.ofParts address (uint16 port))

            Marshal.SetLastPInvokeError 0
            let bound = HostCalls.bind (fd, sockaddr, uint32 sockaddr.Length)
            let bindErrno = Marshal.GetLastPInvokeError ()
            HostCalls.close fd |> ignore<int>

            if bound = 0 then
                false
            elif bindErrno = errno UnixError.EADDRINUSE then
                true
            // The address has left its interface since it was listed.
            elif bindErrno = errno UnixError.EADDRNOTAVAIL then
                false
            else
                failwith
                    $"a bind of %s{Ipv4Address.toString address}:%d{port}, to look for a socket holding the port there, failed with errno %d{bindErrno}"
        )

    /// How many fresh ports `HostPair` tries for an explicit bind before it
    /// fails, each found free a moment before.
    let private explicitPortAttempts : int = 5

    /// A pair on the host, as the probe's `pair_locked` makes one.
    type private HostPair (flavour : SimulatedUnixFlavour, shape : ShutdownPairShape) =
        let platform = HostPlatform.platformOf flavour

        let check (what : string) (result : int) : unit =
            if result < 0 then
                failwith $"%s{what} failed with errno %d{Marshal.GetLastPInvokeError ()}"

        let loopbackAt (port : int) : byte[] =
            SimulatedUnixPlatform.encodeInternetSockaddr
                platform
                (Ipv4Endpoint.ofParts Ipv4Address.loopback (uint16 port))

        let portOf (fd : int) : int =
            let name = Array.zeroCreate<byte> 16
            let mutable length = 16u
            check "getsockname" (HostCalls.getSockName (fd, name, &length))
            (int name.[2] <<< 8) ||| int name.[3]

        let freePort () : int =
            let t = HostCalls.socket (AF_INET, SOCK_STREAM, 0)
            check "socket" t
            let address = loopbackAt 0
            check "bind" (HostCalls.bind (t, address, uint32 address.Length))
            let port = portOf t
            HostCalls.close t |> ignore<int>
            port

        // Binds `fd` to 127.0.0.1 at an explicit port, as the probe's
        // `pair_locked` does, choosing one that `freePort` found free. Any
        // socket on the host, such as a concurrent test's bind of port 0 or
        // its `connect`, can take that port between `freePort` releasing it
        // and this bind, so a refusal with `EADDRINUSE` tries a fresh port,
        // up to `explicitPortAttempts` times in all.
        let bindExplicitPort (fd : int) : unit =
            let addressInUse =
                UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) UnixError.EADDRINUSE

            let rec go (attempt : int) : unit =
                let port = freePort ()
                let address = loopbackAt port

                if HostCalls.bind (fd, address, uint32 address.Length) < 0 then
                    let errno = Marshal.GetLastPInvokeError ()

                    if errno = addressInUse && attempt < explicitPortAttempts then
                        go (attempt + 1)
                    else
                        failwith
                            $"bind of 127.0.0.1:%d{port} failed with errno %d{errno}, on attempt %d{attempt} of %d{explicitPortAttempts}"

            go 1

        let errorName (errno : int) : string =
            match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) errno with
            | Some error -> $"%A{error}"
            | None -> $"errno%d{errno}"

        let ans (result : int64) (errno : int) : string =
            if result < 0L then
                $"-1 %s{errorName errno}"
            else
                string result

        let settle () : unit = Thread.Sleep 30

        /// Whether `poll` finds something for a read of `fd` to answer
        /// (bytes, end of file, or an error) within `timeoutMs`.
        let readableWithin (fd : int) (timeoutMs : int) : bool =
            let eintr =
                UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) UnixError.EINTR

            let deadline = Environment.TickCount64 + int64 timeoutMs

            let rec go () =
                let entry = [| int64 (uint32 fd) ||| (int64 pollIn <<< 32) |]
                let remaining = max 0L (deadline - Environment.TickCount64)
                Marshal.SetLastPInvokeError 0
                let ready = HostCalls.pollPacked (entry, 1un, int remaining)

                if ready > 0 then
                    true
                elif ready = 0 then
                    false
                elif Marshal.GetLastPInvokeError () = eintr then
                    go ()
                else
                    failwith $"poll failed with errno %d{Marshal.GetLastPInvokeError ()}"

            go ()

        let call (f : unit -> int64) : int64 * int =
            Marshal.SetLastPInvokeError 0
            let result = f ()
            result, (if result < 0L then Marshal.GetLastPInvokeError () else 0)

        let setReuseAddress (fd : int) : unit =
            check
                "setsockopt(SO_REUSEADDR)"
                (HostCalls.setSockOpt (
                    fd,
                    SimulatedUnixPlatform.socketOptionLevel platform,
                    SimulatedUnixPlatform.reuseAddressOption platform,
                    BitConverter.GetBytes 1,
                    4u
                ))

        let mutable fds : Map<ConnectionEnd, int> = Map.empty
        let mutable edgePort : int option = None
        // c's port and p's, read once the pair has connected.
        let mutable connection : int * int = 0, 0
        let mutable foreignHolders : string list = []
        // What each end's writes have taken.
        let mutable written : Map<ConnectionEnd, int64> = Map.empty
        let mutable unsettled : string list = []
        // On Darwin, the end that the last fill left unable to take more,
        // and the size of its receive buffer when the fill ended.
        let mutable filled : (ConnectionEnd * int) option = None

        let noteWritten (e : ConnectionEnd) (count : int64) : unit =
            written <- Map.add e ((Map.tryFind e written |> Option.defaultValue 0L) + count) written

        let receiveBuffer (fd : int) : int =
            let mutable value = 0
            let mutable length = 4u

            check
                "getsockopt(SO_RCVBUF)"
                (HostCalls.getSockOptInt (
                    fd,
                    SimulatedUnixPlatform.socketOptionLevel platform,
                    darwinReceiveBufferOption,
                    &value,
                    &length
                ))

            value

        // The probe's fill stops once three writes 30 ms apart take nothing,
        // and its rows were measured where that left bytes the reader could
        // not take. Darwin sometimes grows the reader's receive buffer after
        // the fill has ended, and the reader then takes them all, and the
        // FIN queued behind them: in fill-settling.c's section G, the buffer
        // grew in exactly the runs where the FIN got through. Stops watching
        // the end.
        let checkFilled () : unit =
            match filled with
            | None -> ()
            | Some (e, size) ->
                filled <- None

                match Map.tryFind e fds with
                | None -> ()
                | Some fd ->
                    let grown = receiveBuffer fd

                    if grown > size then
                        unsettled <-
                            unsettled
                            @ [
                                $"the %A{e} end's receive buffer grew from %d{size} to %d{grown} bytes after a fill had left it unable to take more"
                            ]

        // A Darwin close that resets while the peer has yet to acknowledge
        // bytes the closer sent usually never reaches the peer: in
        // fill-settling.c's section A, every reset sent with everything
        // acknowledged arrived, and nearly every other did not. The probe's
        // rows were measured where its settles had let the acknowledgements
        // out first. That probe never found a Linux end with bytes
        // unacknowledged at a close.
        let awaitAcknowledged () : unit =
            match flavour with
            | SimulatedUnixFlavour.Linux -> ()
            | SimulatedUnixFlavour.Darwin ->
                let deadline = Environment.TickCount64 + int64 acknowledgementPatienceMs

                let outstanding () : (ConnectionEnd * int64) list =
                    [
                        for KeyValue (e, fd) in fds do
                            match darwinUnacknowledged fd (Map.tryFind e written |> Option.defaultValue 0L) with
                            | Some count when count > 0L -> e, count
                            | Some _
                            | None -> ()
                    ]

                let rec go () =
                    match outstanding () with
                    | [] -> ()
                    | waiting when Environment.TickCount64 >= deadline ->
                        for e, count in waiting do
                            unsettled <-
                                unsettled
                                @ [
                                    $"the %A{e} end had %d{count} bytes still unacknowledged %d{acknowledgementPatienceMs} ms after a close was due"
                                ]
                    | _ ->
                        Thread.Sleep 1
                        go ()

                go ()

        // A socket outside the pair can hold the pair's port, and then refuses
        // a bind of it whatever the pair's own sockets do: Linux's `connect`
        // chooses a local port that such a socket holds, provided their
        // remote endpoints differ, and on both flavours a bind of
        // 127.0.0.1:0, as the listener's and `freePort`'s are, can be given a
        // port that a socket at another of the host's addresses holds
        // (`port-held-elsewhere.c`, A). Looked for while the refused
        // candidate is still open, so that the holder cannot yet have gone.
        // Darwin lists only the caller's own sockets
        // (`port-held-elsewhere.c`, D), so there the holder is looked for by
        // binding the port at each of the host's other addresses
        // (`heldElsewhere`), which finds one there or at the wildcard and
        // cannot tell one at 127.0.0.1 from the pair's own sockets.
        let noteRefusal (wildcard : bool) (port : int) : unit =
            match flavour with
            | SimulatedUnixFlavour.Darwin ->
                let found =
                    heldElsewhere flavour port
                    |> List.map (fun address ->
                        $"a bind of %s{Ipv4Address.toString address}:%d{port} was refused, so a socket outside the pair holds that port there or at the wildcard"
                    )

                foreignHolders <- foreignHolders @ found
            | SimulatedUnixFlavour.Linux ->
                let cPort, pPort = connection

                let own (listed : ListedTcpSocket) : bool =
                    (listed.LocalPort = cPort && listed.RemotePort = pPort)
                    || (listed.LocalPort = pPort && listed.RemotePort = cPort)

                let foreign =
                    linuxTcpSockets ()
                    |> List.filter (fun listed ->
                        listed.LocalPort = port
                        && refusesIpv4Bind wildcard listed.LocalAddress
                        && not (own listed)
                    )
                    |> List.map (fun listed -> listed.Line)

                foreignHolders <- foreignHolders @ foreign

        do
            let listener = HostCalls.socket (AF_INET, SOCK_STREAM, 0)
            check "socket" listener

            match shape with
            | ShutdownPairShape.ListenerReuseAddress -> setReuseAddress listener
            | ShutdownPairShape.Plain
            | ShutdownPairShape.ClientLocked
            | ShutdownPairShape.ListenerLocked
            | ShutdownPairShape.ClientReuseAddress -> ()

            match shape with
            | ShutdownPairShape.ListenerLocked -> bindExplicitPort listener
            | ShutdownPairShape.Plain
            | ShutdownPairShape.ClientLocked
            | ShutdownPairShape.ClientReuseAddress
            | ShutdownPairShape.ListenerReuseAddress ->
                let address = loopbackAt 0
                check "bind" (HostCalls.bind (listener, address, uint32 address.Length))

            check "listen" (HostCalls.listen (listener, 4))
            let destination = loopbackAt (portOf listener)
            let client = HostCalls.socket (AF_INET, SOCK_STREAM, 0)
            check "socket" client

            match shape with
            | ShutdownPairShape.ClientLocked -> bindExplicitPort client
            | ShutdownPairShape.ClientReuseAddress -> setReuseAddress client
            | ShutdownPairShape.Plain
            | ShutdownPairShape.ListenerLocked
            | ShutdownPairShape.ListenerReuseAddress -> ()

            check "connect" (HostCalls.connect (client, destination, uint32 destination.Length))
            settle ()
            let server = HostCalls.accept (listener, 0n, 0n)
            check "accept" server
            HostCalls.close listener |> ignore<int>

            for fd in [ client ; server ] do
                if HostCalls.setNonBlocking (nativeint fd, 1) <> 0 then
                    failwith $"could not make fd %d{fd} non-blocking"

            fds <- Map.ofList [ c, client ; p, server ]
            connection <- portOf client, portOf server

        /// Each socket outside this pair that was found holding a port whose
        /// bind was refused with `EADDRINUSE`: on Linux, as `/proc/net/tcp`
        /// listed it, where its address overlaps the refused bind's; on
        /// Darwin, as `heldElsewhere` found it, at another of the host's
        /// addresses or the wildcard, which overlaps a refused wildcard bind
        /// and, from the wildcard only, a refused bind at 127.0.0.1.
        member _.ForeignHolders : string list = foreignHolders

        /// Each way this pair was found to have moved on from the state the
        /// probe measured before a call depending on it (fill-settling.c): an
        /// end whose receive buffer grew after a fill had left it unable to
        /// take more, or an end with bytes still unacknowledged when a close
        /// was due. Empty on Linux, where neither was ever found.
        member _.Unsettled : string list = unsettled

        member _.Fd (e : ConnectionEnd) : int =
            match Map.tryFind e fds with
            | Some fd -> fd
            | None -> failwith $"the %A{e} end has closed"

        member this.Read (e : ConnectionEnd) (count : int) : string =
            let result, errno =
                call (fun () -> int64 (HostCalls.read (this.Fd e, hostBuffer, unativeint count)))

            settle ()
            ans result errno

        member this.WriteAnswer (e : ConnectionEnd) (count : int) : Result<int, string> =
            let result, errno =
                call (fun () -> int64 (HostCalls.write (this.Fd e, hostBuffer, unativeint count)))

            if result > 0L then
                noteWritten e result

            settle ()

            if result < 0L then
                Error (ans result errno)
            else
                Ok (int result)

        /// Close what is still open, with `SO_LINGER` {1, 0}, as the probe's
        /// `discard` does, and the edge registration's port.
        member _.Discard () : unit =
            checkFilled ()
            let linger = Array.append (BitConverter.GetBytes 1) (BitConverter.GetBytes 0)

            for fd in Map.values fds do
                HostCalls.setSockOpt (
                    fd,
                    SimulatedUnixPlatform.socketOptionLevel platform,
                    lingerOption flavour,
                    linger,
                    8u
                )
                |> ignore<int>

                HostCalls.close fd |> ignore<int>

            fds <- Map.empty
            edgePort |> Option.iter (HostCalls.close >> ignore<int>)
            edgePort <- None

        interface IShutdownPair with
            member _.Refused = false
            member this.Read e count = this.Read e count
            member this.WriteAnswer e count = this.WriteAnswer e count

            member this.SoError e =
                let mutable value = 0
                let mutable length = 4u

                check
                    "getsockopt(SO_ERROR)"
                    (HostCalls.getSockOptInt (
                        this.Fd e,
                        SimulatedUnixPlatform.socketOptionLevel platform,
                        SimulatedUnixPlatform.socketErrorOption platform,
                        &value,
                        &length
                    ))

                if value = 0 then "0" else errorName value

            member this.Shutdown e how =
                let raw =
                    match how with
                    | TcpShutdownHow.Read -> 0
                    | TcpShutdownHow.Write -> 1
                    | TcpShutdownHow.Both -> 2

                (this :> IShutdownPair).ShutdownRaw e raw

            member this.ShutdownRaw e how =
                let result, errno = call (fun () -> int64 (hostShutdown (this.Fd e, how)))
                settle ()
                ans result errno

            member this.Close e =
                if filled |> Option.exists (fun (watched, _) -> watched = e) then
                    checkFilled ()

                awaitAcknowledged ()
                let result, errno = call (fun () -> int64 (HostCalls.close (this.Fd e)))
                fds <- Map.remove e fds
                settle ()
                ans result errno

            member this.SetLingerZero e =
                let linger = Array.append (BitConverter.GetBytes 1) (BitConverter.GetBytes 0)

                let result, errno =
                    call (fun () ->
                        int64 (
                            HostCalls.setSockOpt (
                                this.Fd e,
                                SimulatedUnixPlatform.socketOptionLevel platform,
                                lingerOption flavour,
                                linger,
                                8u
                            )
                        )
                    )

                ans result errno

            member this.Abort e =
                (this :> IShutdownPair).SetLingerZero e |> ignore<string>
                (this :> IShutdownPair).Close e

            member this.Fionread e =
                let mutable available = 0

                if HostCalls.bytesAvailable (nativeint (this.Fd e), &available) <> 0 then
                    -1
                else
                    available

            member this.Rdy e =
                let fd = this.Fd e
                let entry = [| int64 (uint32 fd) ||| (int64 (uint16 (rdyEvents flavour)) <<< 32) |]
                check "poll" (HostCalls.pollPacked (entry, 1un, 0))
                let revents = int (uint16 (entry.[0] >>> 48))

                let waiters =
                    match flavour with
                    | SimulatedUnixFlavour.Linux ->
                        let ep = HostCalls.epollCreate1 0
                        check "epoll_create1" ep

                        check
                            "epoll_ctl"
                            (HostCalls.epollCtl (ep, 1, fd, epollEvent (uint32 (rdyEvents flavour)) (uint64 fd)))

                        let out = Array.zeroCreate<byte> epollEventSize
                        let n = hostEpollWait (ep, out, 1, 0)
                        HostCalls.close ep |> ignore<int>
                        let events = if n > 0 then BitConverter.ToUInt32 (out, 0) else 0u
                        $"epoll=0x%x{events}"
                    | SimulatedUnixFlavour.Darwin ->
                        let kq = HostCalls.kqueue ()
                        check "kqueue" kq

                        let changes =
                            Array.append
                                (keventChange fd KeventFilter.Read KeventFlags.Add)
                                (keventChange fd KeventFilter.Write KeventFlags.Add)

                        check "kevent" (hostKevent (kq, changes, 2, null, 0, null))
                        let out = Array.zeroCreate<byte> 64
                        let n = hostKevent (kq, null, 0, out, 2, [| 0L ; 0L |])
                        HostCalls.close kq |> ignore<int>
                        let events = keventsOf out (max n 0)

                        let render (filter : int16) =
                            events
                            |> List.tryFind (fun (_, f, _, _, _) -> f = filter)
                            |> Option.map (fun (_, _, flags, fflags, data) -> renderKevent data flags fflags)
                            |> Option.defaultValue "-"

                        $"kq-read=%s{render KeventFilter.Read} kq-write=%s{render KeventFilter.Write}"

                $"poll=0x%x{revents} %s{waiters} fionread=%d{(this :> IShutdownPair).Fionread e}"

            member this.Fill e =
                checkFilled ()

                let rec go (total : int64) (dry : int) =
                    if dry >= 3 || total >= (64L <<< 20) then
                        total
                    else
                        let result, errno =
                            call (fun () -> int64 (HostCalls.write (this.Fd e, hostBuffer, 1048576un)))

                        if result > 0L then
                            go (total + result) 0
                        elif
                            errno = UnixError.toRawErrnoUnder
                                (SimulatedUnixPlatform.rawErrnoNumbering platform)
                                UnixError.EAGAIN
                        then
                            settle ()
                            go total (dry + 1)
                        else
                            total

                let total = go 0L 0
                noteWritten e total

                match flavour with
                | SimulatedUnixFlavour.Linux -> ()
                | SimulatedUnixFlavour.Darwin ->
                    let reader =
                        match e with
                        | ConnectionEnd.Client -> ConnectionEnd.Server
                        | ConnectionEnd.Server -> ConnectionEnd.Client

                    match Map.tryFind reader fds with
                    | Some fd -> filled <- Some (reader, receiveBuffer fd)
                    | None -> ()

                total

            // The probe's three dry reads 30 ms apart, and then, before an
            // EAGAIN is taken as the answer, a wait of up to
            // `drainPatienceMs` for the end to become readable: a loaded host
            // can hold back a queue's next bytes for longer than the probe's
            // pauses. Waiting longer changes only an answer that would
            // otherwise have depended on how soon the bytes came.
            member this.Drain e =
                if filled |> Option.exists (fun (watched, _) -> watched = e) then
                    checkFilled ()

                let eagain =
                    UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) UnixError.EAGAIN

                // `patient` is cleared by one wait that bytes did not follow,
                // so that a read which goes on answering EAGAIN however its
                // end polls cannot keep the drain going.
                let rec go (total : int64) (dry : int) (patient : bool) =
                    let result, errno =
                        call (fun () -> int64 (HostCalls.read (this.Fd e, hostBuffer, 1048576un)))

                    if result > 0L then
                        go (total + result) 0 true
                    elif result < 0L && errno = eagain && dry < 3 then
                        settle ()
                        go total (dry + 1) patient
                    elif
                        result < 0L
                        && errno = eagain
                        && patient
                        && readableWithin (this.Fd e) drainPatienceMs
                    then
                        go total 0 false
                    else
                        settle ()
                        total, ans result errno

                go 0L 0 true

            member _.Settle () = settle ()

            member this.RegisterEdges ends =
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    let ep = HostCalls.epollCreate1 0
                    check "epoll_create1" ep

                    for e in ends do
                        let fd = this.Fd e
                        check "epoll_ctl" (HostCalls.epollCtl (ep, 1, fd, epollEvent 0x80002005u (uint64 fd)))

                    edgePort <- Some ep
                | SimulatedUnixFlavour.Darwin ->
                    let kq = HostCalls.kqueue ()
                    check "kqueue" kq
                    let flags = KeventFlags.Add ||| KeventFlags.Clear

                    let changes =
                        ends
                        |> List.collect (fun e ->
                            [
                                keventChange (this.Fd e) KeventFilter.Read flags
                                keventChange (this.Fd e) KeventFilter.Write flags
                            ]
                        )

                    check "kevent" (hostKevent (kq, Array.concat changes, changes.Length, null, 0, null))
                    edgePort <- Some kq

            member _.Edges () =
                let port =
                    match edgePort with
                    | Some port -> port
                    | None -> failwith "no edge registration"

                let cFd = Map.tryFind c fds |> Option.defaultValue -1

                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    let out = Array.zeroCreate<byte> (4 * epollEventSize)
                    let n = hostEpollWait (port, out, 4, 0)

                    let events =
                        [
                            for k in 0 .. n - 1 do
                                let at = k * epollEventSize

                                int (BitConverter.ToUInt64 (out, at + epollEventSize - 8)),
                                BitConverter.ToUInt32 (out, at)
                        ]

                    let of' (isC : bool) =
                        events
                        |> List.tryFind (fun (fd, _) -> (fd = cFd) = isC)
                        |> Option.map (fun (_, e) -> $"0x%x{e}")
                        |> Option.defaultValue "-"

                    $"c=%s{of' true} p=%s{of' false}"
                | SimulatedUnixFlavour.Darwin ->
                    let out = Array.zeroCreate<byte> (4 * 32)
                    let n = hostKevent (port, null, 0, out, 4, [| 0L ; 0L |])

                    match keventsOf out (max n 0) with
                    | [] -> "-"
                    | events ->
                        events
                        |> List.map (fun (fd, filter, flags, fflags, data) ->
                            let who = if fd = cFd then "c" else "p"
                            let what = if filter = KeventFilter.Read then "read" else "write"
                            $"%s{who}-%s{what}=%s{renderKevent data flags fflags}"
                        )
                        |> String.concat " "

            member _.BindsEndpoints = true
            member this.PortOf e = portOf (this.Fd e)

            member _.BindFree port =
                let n = HostCalls.socket (AF_INET, SOCK_STREAM, 0)
                check "socket" n
                let address = loopbackAt port

                let result, errno =
                    call (fun () -> int64 (HostCalls.bind (n, address, uint32 address.Length)))

                if result < 0L && errorName errno = "EADDRINUSE" then
                    noteRefusal false port

                HostCalls.close n |> ignore<int>

                if result = 0L then "bind-ok"
                elif errorName errno = "EADDRINUSE" then "bind-EADDRINUSE"
                else ans result errno

            member _.Candidate reuse wildcard port =
                let n = HostCalls.socket (AF_INET, SOCK_STREAM, 0)
                check "socket" n

                if reuse then
                    setReuseAddress n

                let address =
                    SimulatedUnixPlatform.encodeInternetSockaddr
                        platform
                        (Ipv4Endpoint.ofParts (if wildcard then Ipv4Address.any else Ipv4Address.loopback) (uint16 port))

                let bound, bindErrno =
                    call (fun () -> int64 (HostCalls.bind (n, address, uint32 address.Length)))

                if bound < 0L && errorName bindErrno = "EADDRINUSE" then
                    noteRefusal wildcard port

                let answer =
                    if bound < 0L then
                        $"bind-%s{errorName bindErrno}"
                    else
                        let listened, listenErrno = call (fun () -> int64 (HostCalls.listen (n, 4)))

                        if listened < 0L then
                            $"bind-ok listen-%s{errorName listenErrno}"
                        else
                            "bind-ok listen-ok"

                HostCalls.close n |> ignore<int>
                answer

            member this.ReuseAddress e =
                let mutable value = 0
                let mutable length = 4u

                check
                    "getsockopt(SO_REUSEADDR)"
                    (HostCalls.getSockOptInt (
                        this.Fd e,
                        SimulatedUnixPlatform.socketOptionLevel platform,
                        SimulatedUnixPlatform.reuseAddressOption platform,
                        &value,
                        &length
                    ))

                if value <> 0 then 1 else 0

            member this.PeerName e =
                let name = Array.zeroCreate<byte> 16
                let mutable length = 16u
                Marshal.SetLastPInvokeError 0
                let result = hostGetPeerName (this.Fd e, name, &length)

                if result = 0 then
                    "ok"
                else
                    errorName (Marshal.GetLastPInvokeError ())

            member _.KeepsTimeWaitOnceBothClosed = true

    /// How many times `hostReplay` runs a scenario whose answers came from a
    /// state the probe did not measure before it fails.
    let private hostScenarioAttempts : int = 5

    /// Each scenario on a pair of its own, `concurrently` or one at a time; their
    /// lines in order. A scenario in which a pair's bind was refused while a
    /// socket outside that pair held the port (`HostPair.ForeignHolders`) is run
    /// again on fresh pairs, since that refusal is the other socket's and not
    /// the answer the scenario measures; so is one in which a pair moved on
    /// from the state the probe measured before a call that depended on it
    /// (`HostPair.Unsettled`). This fails once `hostScenarioAttempts` runs
    /// have each been spoilt so. A foreign socket can only refuse a bind
    /// that would otherwise have succeeded, so a line that survives is the
    /// pairs' own answer, except where a foreign holder came and went in the
    /// moment between the refusal and the look for it, or, on Darwin, held
    /// the port at 127.0.0.1, which it can have taken only once the pair had
    /// released it, since neither a bind of 127.0.0.1:0 nor `connect` is
    /// given a port held there (`port-held-elsewhere.c`, A). Either leaves
    /// the refusal in place.
    let private hostReplay
        (flavour : SimulatedUnixFlavour)
        (concurrently : bool)
        (scenarios : ShutdownProbe.Scenario list)
        : ShutdownLine list
        =
        let rec run (attempt : int) (scenario : ShutdownProbe.Scenario) : ShutdownLine list =
            let mutable made : HostPair list = []

            let pairOf (shape : ShutdownPairShape) : IShutdownPair =
                let pair = new HostPair (flavour, shape)
                made <- pair :: made
                pair :> IShutdownPair

            let lines =
                try
                    scenario pairOf
                finally
                    for pair in made do
                        pair.Discard ()

            let spoilt =
                [
                    for pair in made do
                        for holder in pair.ForeignHolders do
                            $"another socket held a port whose bind was refused: %s{holder}"

                        yield! pair.Unsettled
                ]

            match spoilt with
            | [] -> lines
            | _ when attempt < hostScenarioAttempts -> run (attempt + 1) scenario
            | spoilt ->
                let listed = String.concat "\n" spoilt

                failwith
                    $"each of %d{hostScenarioAttempts} runs of a scenario answered from a state the probe did not measure; in the last:\n%s{listed}"

        let scenarios = List.toArray scenarios

        (if concurrently then
             Array.Parallel.map (run 1) scenarios
         else
             Array.map (run 1) scenarios)
        |> List.concat

    let private withoutSigPipe (text : string) : string = text.Replace ("+SIGPIPE", "")

    let private hostDisagreementsOf
        (probe : ShutdownProbe.Probe)
        (section : string)
        (concurrently : bool)
        (scenarios : ShutdownProbe.Scenario list)
        : string list
        =
        let mutable found = []

        HostPlatform.onUnixHost (fun flavour ->
            found <-
                hostReplay flavour concurrently scenarios
                |> ShutdownProbe.disagreements probe flavour section withoutSigPipe
        )

        found

    let private hostDisagreements = hostDisagreementsOf ShutdownProbe.Probe.Shutdown

    /// `TcpExt: TCPTimeWaitOverflow` in the text of a Linux `/proc/net/netstat`:
    /// how many sockets in the network namespace have closed without entering
    /// TIME_WAIT, because the table of them (`tcp_max_tw_buckets`) was full.
    let private timeWaitOverflows (netstat : string) : int64 =
        // A section is a line of names and a line of values, each line
        // headed by the section's name.
        let tcpExt =
            netstat.Split ('\n', StringSplitOptions.RemoveEmptyEntries)
            |> Array.filter (fun line -> line.StartsWith ("TcpExt:", StringComparison.Ordinal))
            |> Array.map (fun line -> line.Split (' ', StringSplitOptions.RemoveEmptyEntries))

        match tcpExt with
        | [| names ; values |] when names.Length = values.Length ->
            match Array.tryFindIndex ((=) "TCPTimeWaitOverflow") names with
            | Some i -> Int64.Parse values.[i]
            | None -> failwith "/proc/net/netstat's TcpExt has no TCPTimeWaitOverflow"
        | _ -> failwith "/proc/net/netstat has no TcpExt line of names with a line of values to match"

    /// Runs `replay` and, on a Linux host, fails if any socket in the network
    /// namespace closed without entering TIME_WAIT meanwhile: such an end
    /// releases at once an endpoint it should hold, so a bind of it that was
    /// measured as refused succeeds. Elsewhere, runs `replay`.
    let private withoutTimeWaitOverflow (replay : unit -> 'a) : 'a =
        match HostPlatform.flavour () with
        | Some SimulatedUnixFlavour.Linux ->
            let read () =
                timeWaitOverflows (IO.File.ReadAllText "/proc/net/netstat")

            let before = read ()
            let result = replay ()
            let after = read ()

            if after > before then
                failwith
                    $"the host's TIME_WAIT table overflowed during the replay (TCPTimeWaitOverflow %d{before} -> %d{after}), so an end may have released an endpoint it should have held; the replay's answers do not describe the measured kernel"

            result
        | Some SimulatedUnixFlavour.Darwin
        | None -> replay ()

    [<Test>]
    let ``this host answers shutdown, and what each end then sees, as its flavour was measured (section S)`` () =
        hostDisagreements "S" true ShutdownProbe.sectionS |> shouldEqual []

    [<Test>]
    let ``this host answers shutdown twice, and after the peer's FIN or reset, as measured (section T)`` () =
        hostDisagreements "T" true ShutdownProbe.sectionT |> shouldEqual []

    [<Test>]
    let ``this host answers bytes arriving after the receive side is shut as measured (section R)`` () =
        hostDisagreements "R" true ShutdownProbe.sectionR |> shouldEqual []

    [<Test>]
    let ``this host answers a close after shutdown as measured (section P)`` () =
        hostDisagreements "P" true ShutdownProbe.sectionP |> shouldEqual []

    [<Test>]
    let ``this host reports edges after shutdown as measured (section E)`` () =
        hostDisagreements "E" true ShutdownProbe.sectionE |> shouldEqual []

    // One scenario at a time, as for section F: each binds the closer's
    // endpoint.
    [<Test>]
    let ``this host answers a close under SO_LINGER, and frees the closer's endpoint, as measured (section L)`` () =
        withoutTimeWaitOverflow (fun () -> hostDisagreements "L" false ShutdownProbe.sectionL)
        |> shouldEqual []

    // One scenario at a time: a scenario frees an endpoint and then binds it,
    // which another's connect could take in between.
    [<Test>]
    let ``this host frees an endpoint by which FIN came first, as measured (section F)`` () =
        withoutTimeWaitOverflow (fun () -> hostDisagreements "F" false ShutdownProbe.sectionF)
        |> shouldEqual []

    // One scenario at a time, as for section F.
    [<Test>]
    let ``this host answers a bind of an endpoint an end still holds as measured (bind-held-endpoint.c)`` () =
        withoutTimeWaitOverflow (fun () ->
            hostDisagreementsOf ShutdownProbe.Probe.HeldEndpoint "H" false ShutdownProbe.sectionH
        )
        |> shouldEqual []

    // A loaded host can hold back a queue's next bytes for longer than the
    // probe's three dry reads 30 ms apart; a drain that ended there would
    // report EAGAIN where the stream has more, and its FIN, still to come.
    [<Test>]
    let ``a host drain reads past a pause in what the sender sends, to the end of file`` () =
        HostPlatform.onUnixHost (fun flavour ->
            let pair = new HostPair (flavour, ShutdownPairShape.Plain)

            try
                let ends = pair :> IShutdownPair
                ends.WriteAnswer c 100 |> shouldEqual (Ok 100)

                let later =
                    Tasks.Task.Run (fun () ->
                        Thread.Sleep 500
                        let written = ends.WriteAnswer c 100
                        let shut = ends.Shutdown c TcpShutdownHow.Write
                        written, shut
                    )

                let drained = ends.Drain p
                later.Result |> shouldEqual (Ok 100, "0")
                drained |> shouldEqual (200L, "0")
            finally
                pair.Discard ()
        )

    [<Test>]
    let ``a listed socket refuses an IPv4 bind exactly where the addresses overlap`` () =
        [
            // 127.0.0.1, 127.0.0.2 and 0.0.0.0
            "0100007F"
            "0200007F"
            "00000000"
            // ::1, ::, and 127.0.0.1 and 127.0.0.2 mapped into IPv6
            "00000000000000000000000001000000"
            "00000000000000000000000000000000"
            "0000000000000000FFFF00000100007F"
            "0000000000000000FFFF00000200007F"
        ]
        |> List.map (fun address -> address, refusesIpv4Bind false address, refusesIpv4Bind true address)
        |> shouldEqual
            [
                "0100007F", true, true
                "0200007F", false, true
                "00000000", true, true
                "00000000000000000000000001000000", false, false
                "00000000000000000000000000000000", true, true
                "0000000000000000FFFF00000100007F", true, true
                "0000000000000000FFFF00000200007F", false, true
            ]

    /// A socket outside a scenario's pair held a port the scenario binds
    /// before the scenario could measure what it was written to, so its test
    /// is run again (`whilePortAlreadyHeld`).
    exception private PortAlreadyHeld of port : int

    /// Section H's `c released closed` row, reduced to one candidate: `c`
    /// releases its endpoint, and a fresh socket binds it, at the wildcard if
    /// `wildcard` and at 127.0.0.1 otherwise. On the attempts `foreignOn`
    /// names, a listener outside the pair holds the port at `foreignAt`
    /// across that bind, as another test's or another process's socket can;
    /// this raises `PortAlreadyHeld` if another socket held the port there
    /// first. Each run of the scenario is counted in `attempts`.
    ///
    /// `c` binds explicitly to a port its own `bind` chose (`ClientLocked`),
    /// which no other socket's `connect` will share, so that until `c`
    /// releases it no socket but the pair holds that port at 127.0.0.1 or the
    /// wildcard; a socket at another of the host's addresses can already hold
    /// it (`port-held-elsewhere.c`, A).
    let private releasedThenBound
        (flavour : SimulatedUnixFlavour)
        (foreignAt : Ipv4Address)
        (wildcard : bool)
        (foreignOn : int -> bool)
        (attempts : int ref)
        : ShutdownProbe.Scenario
        =
        fun pairOf ->
            attempts.Value <- attempts.Value + 1
            let s = ShutdownRecorder (pairOf ShutdownPairShape.ClientLocked)
            let port = s.PortOf c
            s.Shutdown p TcpShutdownHow.Write |> ignore<string>
            s.Close c |> ignore<string>

            let foreign =
                if foreignOn attempts.Value then
                    let fd = HostCalls.socket (AF_INET, SOCK_STREAM, 0)

                    if fd < 0 then
                        failwith $"socket failed with errno %d{Marshal.GetLastPInvokeError ()}"

                    let address =
                        SimulatedUnixPlatform.encodeInternetSockaddr
                            (HostPlatform.platformOf flavour)
                            (Ipv4Endpoint.ofParts foreignAt (uint16 port))

                    if
                        HostCalls.bind (fd, address, uint32 address.Length) <> 0
                        || HostCalls.listen (fd, 4) <> 0
                    then
                        HostCalls.close fd |> ignore<int>
                        raise (PortAlreadyHeld port)

                    Some fd
                else
                    None

            s.Emit (s.Candidate false wildcard port)
            foreign |> Option.iter (HostCalls.close >> ignore<int>)
            s.Lines

    /// Runs `test` again, up to four more times, while it raises
    /// `PortAlreadyHeld`.
    let rec private whilePortAlreadyHeld (tries : int) (test : unit -> unit) : unit =
        try
            test ()
        with PortAlreadyHeld _ when tries > 1 ->
            whilePortAlreadyHeld (tries - 1) test

    /// A foreign holder at 127.0.0.1 is told from the pair's own sockets only
    /// by Linux's listing of every socket; on Darwin, `heldElsewhere` finds
    /// one only at another address or the wildcard.
    let private onLinuxHost (action : unit -> unit) : unit =
        HostPlatform.onUnixHost (fun flavour ->
            match flavour with
            | SimulatedUnixFlavour.Linux -> action ()
            | SimulatedUnixFlavour.Darwin -> Assert.Ignore "a foreign holder at 127.0.0.1 is looked for on Linux only"
        )

    // A later attempt can meet a foreign holder of its own, so the count is
    // at least two rather than exactly two.
    [<Test>]
    let ``a host scenario whose bind another socket refused is run again`` () =
        onLinuxHost (fun () ->
            whilePortAlreadyHeld
                5
                (fun () ->
                    let attempts = ref 0

                    hostReplay
                        SimulatedUnixFlavour.Linux
                        false
                        [
                            releasedThenBound SimulatedUnixFlavour.Linux Ipv4Address.loopback false ((=) 1) attempts
                        ]
                    |> shouldEqual [ ShutdownLine.Line "bind-ok listen-ok" ]

                    attempts.Value |> shouldBeGreaterThan 1
                )
        )

    [<Test>]
    let ``a host scenario whose binds another socket always refuses fails the replay`` () =
        onLinuxHost (fun () ->
            whilePortAlreadyHeld
                5
                (fun () ->
                    let attempts = ref 0

                    let error =
                        try
                            hostReplay
                                SimulatedUnixFlavour.Linux
                                false
                                [
                                    releasedThenBound
                                        SimulatedUnixFlavour.Linux
                                        Ipv4Address.loopback
                                        false
                                        (fun _ -> true)
                                        attempts
                                ]
                            |> ignore<ShutdownLine list>

                            None
                        with
                        | PortAlreadyHeld _ -> reraise ()
                        | error -> Some error

                    match error with
                    | None -> Assert.Fail "the replay returned although every run was refused by another socket"
                    | Some error -> error.Message |> shouldContainText "another socket"

                    attempts.Value |> shouldEqual hostScenarioAttempts
                )
        )

    // `c` holds its endpoint in TIME_WAIT, so the bind's refusal is the
    // pair's own, and the scenario runs once. `ClientLocked`, as for
    // `releasedThenBound`, so that no other socket shares c's port at
    // 127.0.0.1.
    [<Test>]
    let ``a host scenario whose bind the pair itself refused is not run again`` () =
        onLinuxHost (fun () ->
            let attempts = ref 0

            let scenario : ShutdownProbe.Scenario =
                fun pairOf ->
                    attempts.Value <- attempts.Value + 1
                    let s = ShutdownRecorder (pairOf ShutdownPairShape.ClientLocked)
                    let port = s.PortOf c
                    s.Close c |> ignore<string>
                    s.Shutdown p TcpShutdownHow.Write |> ignore<string>
                    s.Emit (s.Candidate false false port)
                    s.Lines

            hostReplay SimulatedUnixFlavour.Linux false [ scenario ]
            |> shouldEqual [ ShutdownLine.Line "bind-EADDRINUSE" ]

            attempts.Value |> shouldEqual 1
        )

    /// Only a Darwin pair is watched for having moved on from the state the
    /// probe measured (`fill-settling.c`).
    let private onDarwinHost (action : unit -> unit) : unit =
        HostPlatform.onUnixHost (fun flavour ->
            match flavour with
            | SimulatedUnixFlavour.Darwin -> action ()
            | SimulatedUnixFlavour.Linux -> Assert.Ignore "a pair is watched for settling on Darwin only"
        )

    /// `c` fills; on the attempts `growOn` names, `p`'s receive buffer is
    /// then doubled, as Darwin's own growth of it can be once more bytes
    /// reach it (`fill-settling.c`'s section G). Each run of the scenario is
    /// counted in `attempts`.
    let private filledThenGrown (growOn : int -> bool) (attempts : int ref) : ShutdownProbe.Scenario =
        fun pairOf ->
            attempts.Value <- attempts.Value + 1
            let pair = pairOf ShutdownPairShape.Plain
            let s = ShutdownRecorder pair
            s.Fill c |> ignore<int64>

            if growOn attempts.Value then
                let fd =
                    match pair with
                    | :? HostPair as host -> host.Fd p
                    | _ -> failwith "hostReplay makes only host pairs"

                let level =
                    SimulatedUnixPlatform.socketOptionLevel (HostPlatform.platformOf SimulatedUnixFlavour.Darwin)

                let sizeOf () : int =
                    let mutable value = 0
                    let mutable length = 4u

                    if
                        HostCalls.getSockOptInt (fd, level, darwinReceiveBufferOption, &value, &length)
                        <> 0
                    then
                        failwith $"getsockopt(SO_RCVBUF) failed with errno %d{Marshal.GetLastPInvokeError ()}"

                    value

                let before = sizeOf ()
                let doubled = BitConverter.GetBytes (2 * before)

                if HostCalls.setSockOpt (fd, level, darwinReceiveBufferOption, doubled, 4u) <> 0 then
                    failwith $"setsockopt(SO_RCVBUF) failed with errno %d{Marshal.GetLastPInvokeError ()}"

                sizeOf () |> shouldBeGreaterThan before

            s.Emit "filled"
            s.Lines

    [<Test>]
    let ``a host scenario whose filled end's receive buffer grew is run again`` () =
        onDarwinHost (fun () ->
            let attempts = ref 0

            hostReplay SimulatedUnixFlavour.Darwin false [ filledThenGrown ((=) 1) attempts ]
            |> shouldEqual [ ShutdownLine.Line "filled" ]

            attempts.Value |> shouldBeGreaterThan 1
        )

    [<Test>]
    let ``a host scenario whose filled end's receive buffer always grows fails the replay`` () =
        onDarwinHost (fun () ->
            let attempts = ref 0

            let error =
                try
                    hostReplay SimulatedUnixFlavour.Darwin false [ filledThenGrown (fun _ -> true) attempts ]
                    |> ignore<ShutdownLine list>

                    None
                with error ->
                    Some error

            match error with
            | None -> Assert.Fail "the replay returned although every run's receive buffer grew"
            | Some error -> error.Message |> shouldContainText "receive buffer grew"

            attempts.Value |> shouldEqual hostScenarioAttempts
        )

    /// Runs `action` with one of the host's IPv4 addresses outside
    /// 127.0.0.0/8; ignores the test on a host with none, where no socket can
    /// hold a port at another address.
    let private onHostWithAddressElsewhere (action : SimulatedUnixFlavour -> Ipv4Address -> unit) : unit =
        HostPlatform.onUnixHost (fun flavour ->
            match nonLoopbackIpv4Addresses () with
            | elsewhere :: _ -> action flavour elsewhere
            | [] -> Assert.Ignore "the host has no IPv4 address outside 127.0.0.0/8"
        )

    // A bind of 127.0.0.1:0, as the listener's and `freePort`'s are, can be
    // given a port that a socket at another of the host's addresses holds,
    // and on both flavours such a socket refuses a wildcard bind of that port
    // without SO_REUSEADDR (`port-held-elsewhere.c`, A and B). A later
    // attempt can meet a holder of its own, so the count is at least two.
    [<Test>]
    let ``a host scenario whose wildcard bind a socket at another address refused is run again`` () =
        onHostWithAddressElsewhere (fun flavour elsewhere ->
            whilePortAlreadyHeld
                5
                (fun () ->
                    let attempts = ref 0

                    hostReplay flavour false [ releasedThenBound flavour elsewhere true ((=) 1) attempts ]
                    |> shouldEqual [ ShutdownLine.Line "bind-ok listen-ok" ]

                    attempts.Value |> shouldBeGreaterThan 1
                )
        )

    [<Test>]
    let ``a host scenario whose wildcard binds a socket at another address always refuses fails the replay`` () =
        onHostWithAddressElsewhere (fun flavour elsewhere ->
            whilePortAlreadyHeld
                5
                (fun () ->
                    let attempts = ref 0

                    let error =
                        try
                            hostReplay
                                flavour
                                false
                                [ releasedThenBound flavour elsewhere true (fun _ -> true) attempts ]
                            |> ignore<ShutdownLine list>

                            None
                        with
                        | PortAlreadyHeld _ -> reraise ()
                        | error -> Some error

                    match error with
                    | None -> Assert.Fail "the replay returned although every run was refused by another socket"
                    | Some error -> error.Message |> shouldContainText "another socket"

                    attempts.Value |> shouldEqual hostScenarioAttempts
                )
        )

    // `c` holds its endpoint in TIME_WAIT at 127.0.0.1, which refuses a
    // wildcard bind on both flavours (`bind-held-endpoint.c`'s `tw` rows) and
    // never a bind at another address (`port-held-elsewhere.c`, C), so the
    // scenario runs once, unless a socket elsewhere held c's port from the
    // start.
    [<Test>]
    let ``a host scenario whose wildcard bind the pair itself refused is not run again`` () =
        onHostWithAddressElsewhere (fun flavour _ ->
            whilePortAlreadyHeld
                5
                (fun () ->
                    let attempts = ref 0

                    let scenario : ShutdownProbe.Scenario =
                        fun pairOf ->
                            attempts.Value <- attempts.Value + 1
                            let s = ShutdownRecorder (pairOf ShutdownPairShape.ClientLocked)
                            let port = s.PortOf c

                            if not (List.isEmpty (heldElsewhere flavour port)) then
                                raise (PortAlreadyHeld port)

                            s.Close c |> ignore<string>
                            s.Shutdown p TcpShutdownHow.Write |> ignore<string>
                            s.Emit (s.Candidate false true port)
                            s.Lines

                    hostReplay flavour false [ scenario ]
                    |> shouldEqual [ ShutdownLine.Line "bind-EADDRINUSE" ]

                    attempts.Value |> shouldEqual 1
                )
        )

    // The shape of Linux 6.18.5's /proc/net/netstat, with most of each
    // header's names (136 for TcpExt) left out.
    [<Test>]
    let ``the TIME_WAIT overflow count is read from TcpExt's column of that name`` () =
        [
            "TcpExt: SyncookiesSent TW TWRecycled TCPTimeWaitOverflow TCPReqQFullDoCookies"
            "TcpExt: 3 25 1 25275 0"
            "IpExt: InNoRoutes TCPTimeWaitOverflow"
            "IpExt: 7 9"
            ""
        ]
        |> String.concat "\n"
        |> timeWaitOverflows
        |> shouldEqual 25275L

    [<Test>]
    let ``a netstat without the TIME_WAIT overflow count is refused`` () =
        (fun () ->
            [ "TcpExt: SyncookiesSent TW" ; "TcpExt: 3 25" ; "" ]
            |> String.concat "\n"
            |> timeWaitOverflows
            |> ignore<int64>
        )
        |> shouldFail

    [<Test>]
    let ``this Linux host reports its TIME_WAIT overflow count`` () =
        onLinuxHost (fun () ->
            IO.File.ReadAllText "/proc/net/netstat"
            |> timeWaitOverflows
            |> shouldBeGreaterThan -1L
        )

    // ------------------------------------------------------------------
    // Section U: sockets without a connection, and a `how` out of range
    // ------------------------------------------------------------------

    /// The calls section U makes, on one side or the other. Every answer is
    /// rendered as the probe prints it; `Refused` stands for a call the side
    /// will not answer.
    type private UWorld =
        {
            /// A fresh stream socket.
            Stream : unit -> int
            Datagram : unit -> int
            /// A descriptor that names no socket.
            NotSocket : unit -> int
            /// A number that names no descriptor, and that nothing else in the
            /// process can take before the call that is passed it.
            NamesNothing : unit -> int
            /// `bind` to the loopback address and port 0.
            BindAny : int -> unit
            Shutdown : int -> int -> ShutdownLine
            Close : int -> unit
            /// A stream socket whose blocking connect was refused, and that
            /// connect's answer.
            Refused : unit -> int * string
            /// The section's `connect-unreported` row for `how` (`None` for
            /// the control, which makes no shutdown).
            Unreported : int option -> ShutdownLine
            /// The section's `fresh-then` and `udp-then` rows for `how`.
            Then : int -> ShutdownLine list
            /// `shutdown` of a connected socket with `how`.
            ConnectedShutdown : int -> ShutdownLine
        }

    let private rawHowName (how : int) : string =
        match how with
        | 0 -> "RD"
        | 1 -> "WR"
        | 2 -> "RDWR"
        | other -> $"how=%d{other}"

    let private prefixed (prefix : string) (line : ShutdownLine) : ShutdownLine =
        match line with
        | ShutdownLine.Line answer -> ShutdownLine.Line (prefix + answer)
        | other -> other

    /// Every line of section U, as the probe prints them; the listener's rows
    /// are stage 5's.
    let private sectionU (w : UWorld) : ShutdownLine list =
        [
            for how in [ 0 ; 1 ; 2 ] do
                let hn = rawHowName how
                let f = w.Stream ()
                prefixed $"U\tfresh\t%s{hn}\t" (w.Shutdown f how)
                w.Close f
                let f = w.Stream ()
                w.BindAny f
                prefixed $"U\tbound\t%s{hn}\t" (w.Shutdown f how)
                w.Close f
                let u = w.Datagram ()
                prefixed $"U\tudp-unconnected\t%s{hn}\t" (w.Shutdown u how)
                w.Close u
                let n = w.NotSocket ()
                prefixed $"U\tnot-socket\t%s{hn}\t" (w.Shutdown n how)
                w.Close n
                prefixed $"U\tclosed-fd\t%s{hn}\t" (w.Shutdown (w.NamesNothing ()) how)
            for _ in 1 .. 3 * 4 do
                ShutdownLine.Elsewhere
            for how in [ 0 ; 1 ; 2 ] do
                let f, answer = w.Refused ()
                prefixed $"U\trefused(%s{answer})\t%s{rawHowName how}\t" (w.Shutdown f how)
                w.Close f
            for how in [ 3 ; -1 ] do
                let f = w.Stream ()
                prefixed $"U\tfresh\thow=%d{how}\t" (w.Shutdown f how)
                w.Close f
                let n = w.NotSocket ()
                prefixed $"U\tnot-socket\thow=%d{how}\t" (w.Shutdown n how)
                w.Close n
            w.Unreported None
            for how in [ 0 ; 1 ; 2 ] do
                w.Unreported (Some how)
            for how in [ 0 ; 1 ; 2 ] do
                yield! w.Then how
            for how in [ 3 ; -1 ] do
                prefixed $"U\tconnected\thow=%d{how}\t" (w.ConnectedShutdown how)
        ]

    /// Section U's calls on the host.
    let private hostU (flavour : SimulatedUnixFlavour) : UWorld =
        let platform = HostPlatform.platformOf flavour

        let check (what : string) (result : int) : unit =
            if result < 0 then
                failwith $"%s{what} failed with errno %d{Marshal.GetLastPInvokeError ()}"

        let errorName (errno : int) : string =
            match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) errno with
            | Some error -> $"%A{error}"
            | None -> $"errno%d{errno}"

        let call (f : unit -> int) : string =
            Marshal.SetLastPInvokeError 0
            let result = f ()
            let errno = Marshal.GetLastPInvokeError ()
            Thread.Sleep 30

            if result < 0 then
                $"-1 %s{errorName errno}"
            else
                string result

        let loopbackAt (port : int) : byte[] =
            SimulatedUnixPlatform.encodeInternetSockaddr
                platform
                (Ipv4Endpoint.ofParts Ipv4Address.loopback (uint16 port))

        let stream () =
            let fd = HostCalls.socket (AF_INET, SOCK_STREAM, 0)
            check "socket" fd
            fd

        let listening () : int * byte[] =
            let l = stream ()
            let any = loopbackAt 0
            check "bind" (HostCalls.bind (l, any, 16u))
            check "listen" (HostCalls.listen (l, 4))
            let name = Array.zeroCreate<byte> 16
            let mutable length = 16u
            check "getsockname" (HostCalls.getSockName (l, name, &length))
            l, name

        let rdy (fd : int) : string =
            let entry = [| int64 (uint32 fd) ||| (int64 (uint16 (rdyEvents flavour)) <<< 32) |]
            check "poll" (HostCalls.pollPacked (entry, 1un, 0))
            let revents = int (uint16 (entry.[0] >>> 48))

            let waiters =
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    let ep = HostCalls.epollCreate1 0
                    check "epoll_create1" ep

                    check
                        "epoll_ctl"
                        (HostCalls.epollCtl (ep, 1, fd, epollEvent (uint32 (rdyEvents flavour)) (uint64 fd)))

                    let out = Array.zeroCreate<byte> epollEventSize
                    let n = hostEpollWait (ep, out, 1, 0)
                    HostCalls.close ep |> ignore<int>
                    $"epoll=0x%x{(if n > 0 then BitConverter.ToUInt32 (out, 0) else 0u)}"
                | SimulatedUnixFlavour.Darwin ->
                    let kq = HostCalls.kqueue ()
                    check "kqueue" kq

                    let changes =
                        Array.append
                            (keventChange fd KeventFilter.Read KeventFlags.Add)
                            (keventChange fd KeventFilter.Write KeventFlags.Add)

                    check "kevent" (hostKevent (kq, changes, 2, null, 0, null))
                    let out = Array.zeroCreate<byte> 64
                    let n = hostKevent (kq, null, 0, out, 2, [| 0L ; 0L |])
                    HostCalls.close kq |> ignore<int>
                    let events = keventsOf out (max n 0)

                    let render (filter : int16) =
                        events
                        |> List.tryFind (fun (_, f, _, _, _) -> f = filter)
                        |> Option.map (fun (_, _, flags, fflags, data) -> renderKevent data flags fflags)
                        |> Option.defaultValue "-"

                    $"kq-read=%s{render KeventFilter.Read} kq-write=%s{render KeventFilter.Write}"

            let mutable available = 0
            HostCalls.bytesAvailable (nativeint fd, &available) |> ignore<int>
            $"poll=0x%x{revents} %s{waiters} fionread=%d{available}"

        let shutdownOf (fd : int) (how : int) : string = call (fun () -> hostShutdown (fd, how))

        {
            Stream = stream
            Datagram =
                fun () ->
                    let fd = HostCalls.socket (AF_INET, 2, 0)
                    check "socket" fd
                    fd
            NotSocket =
                fun () ->
                    let fds = Array.zeroCreate<int> 2

                    match HostCalls.pipe fds with
                    | 0 ->
                        HostCalls.close fds.[1] |> ignore<int>
                        fds.[0]
                    | _ -> failwith "pipe failed"
            // Any thread of the test host may open a descriptor, and so take a
            // number this replay has just freed, so the closed-fd rows ask about
            // INT_MAX, which no descriptor can ever have; `unallocatable-fd.c`
            // measured that both flavours answer it as they do a freed slot.
            NamesNothing = fun () -> Int32.MaxValue
            BindAny =
                fun fd ->
                    let any = loopbackAt 0
                    check "bind" (HostCalls.bind (fd, any, 16u))
            Shutdown = fun fd how -> ShutdownLine.Line (shutdownOf fd how)
            Close = fun fd -> HostCalls.close fd |> ignore<int>
            Refused =
                fun () ->
                    let l, name = listening ()
                    HostCalls.close l |> ignore<int>
                    let f = stream ()
                    f, call (fun () -> HostCalls.connect (f, name, 16u))
            Unreported =
                fun how ->
                    let l, name = listening ()
                    let f = stream ()
                    HostCalls.setNonBlocking (nativeint f, 1) |> ignore<int>
                    let first = call (fun () -> HostCalls.connect (f, name, 16u))

                    let sh =
                        match how with
                        | None -> "-"
                        | Some how -> shutdownOf f how

                    let again = call (fun () -> HostCalls.connect (f, name, 16u))
                    HostCalls.close f |> ignore<int>
                    HostCalls.close l |> ignore<int>

                    let name =
                        match how with
                        | None -> "none"
                        | Some how -> rawHowName how

                    ShutdownLine.Line $"U\tconnect-unreported(%s{first})\t%s{name}\tshutdown=%s{sh} connect=%s{again}"
            Then =
                fun how ->
                    let hn = rawHowName how
                    let l, name = listening ()
                    let f = stream ()
                    HostCalls.setNonBlocking (nativeint f, 1) |> ignore<int>
                    let before = rdy f
                    let sh = shutdownOf f how
                    let after = rdy f
                    HostCalls.setNonBlocking (nativeint f, 0) |> ignore<int>
                    let connected = call (fun () -> HostCalls.connect (f, name, 16u))
                    HostCalls.setNonBlocking (nativeint f, 1) |> ignore<int>
                    let peer = HostCalls.accept (l, 0n, 0n)
                    check "accept" peer
                    let written = call (fun () -> int (HostCalls.write (f, hostBuffer, 1un)))
                    HostCalls.write (peer, hostBuffer, 1un) |> ignore<nativeint>
                    Thread.Sleep 30
                    let read = call (fun () -> int (HostCalls.read (f, hostBuffer, 4096un)))
                    let rc = rdy f
                    HostCalls.close f |> ignore<int>
                    HostCalls.close peer |> ignore<int>
                    HostCalls.close l |> ignore<int>
                    let u = HostCalls.socket (AF_INET, 2, 0)
                    check "socket" u
                    let ub = rdy u
                    let us = shutdownOf u how
                    let ua = rdy u
                    HostCalls.close u |> ignore<int>

                    [
                        ShutdownLine.Line
                            $"U\tfresh-then\t%s{hn}\tshutdown=%s{sh}\trdy before\t%s{before}\trdy after\t%s{after}"
                        ShutdownLine.Line
                            $"U\tfresh-then\t%s{hn}\tconnect=%s{connected} write1=%s{written} read(after p wrote 1)=%s{read}\trdy\t%s{rc}"
                        ShutdownLine.Line $"U\tudp-then\t%s{hn}\tshutdown=%s{us}\trdy before\t%s{ub}\trdy after\t%s{ua}"
                    ]
            ConnectedShutdown =
                fun how ->
                    let pair = new HostPair (flavour, ShutdownPairShape.Plain)

                    try
                        ShutdownLine.Line ((pair :> IShutdownPair).ShutdownRaw ConnectionEnd.Client how)
                    finally
                        pair.Discard ()
        }

    [<Test>]
    let ``this host answers shutdown on sockets without a connection, and a bad how, as measured (section U)`` () =
        HostPlatform.onUnixHost (fun flavour ->
            sectionU (hostU flavour)
            |> ShutdownProbe.disagreements ShutdownProbe.Probe.Shutdown flavour "U" withoutSigPipe
            |> shouldEqual []
        )

    /// The test host is one process, any of whose threads may open a
    /// descriptor between two of section U's calls, and a new descriptor takes
    /// the lowest free number. Section U's host replay must answer as measured
    /// even when every number it closes is taken again at once.
    [<Test>]
    let ``section U's host replay answers as measured when each descriptor it closes is reopened at once`` () =
        HostPlatform.onUnixHost (fun flavour ->
            let own = Array.zeroCreate<int> 2

            if HostCalls.pipe own <> 0 then
                failwith $"pipe failed with errno %d{Marshal.GetLastPInvokeError ()}"

            let held = ResizeArray<int> ()
            let world = hostU flavour

            // Fill free numbers up to the one just closed; a number past it
            // means another thread took it first.
            let reopen (closed : int) : unit =
                let mutable copy = -1

                while copy < closed do
                    copy <- HostCalls.dup own.[0]

                    if copy < 0 then
                        failwith $"dup failed with errno %d{Marshal.GetLastPInvokeError ()}"

                    held.Add copy

            let disagreements =
                try
                    sectionU
                        { world with
                            Close =
                                fun fd ->
                                    world.Close fd
                                    reopen fd
                        }
                    |> ShutdownProbe.disagreements ShutdownProbe.Probe.Shutdown flavour "U" withoutSigPipe
                finally
                    for fd in held do
                        HostCalls.close fd |> ignore<int>

                    HostCalls.close own.[0] |> ignore<int>
                    HostCalls.close own.[1] |> ignore<int>

            disagreements |> shouldEqual []
        )

    // ------------------------------------------------------------------
    // The kernel
    // ------------------------------------------------------------------

    let private payload : byte[] = Array.init (1 <<< 20) (fun i -> byte (i * 31 + 7))

    /// A booted system of `platform`, with thread 1 for `accept` and `SIGPIPE`
    /// ignored, as the test host and the .NET runtime ignore it.
    let private kernelSystem (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Threads.ensure 1

        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals =
                    SignalState.setDisposition
                        (Kernel.signalNumbering system)
                        Signal.SIGPIPE
                        SignalDisposition.Ignore
                        proc.Signals
            }
        )

    let private kernelClose (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"closing fd %d{fd}: %A{other}"

    let private loopback (platform : SimulatedUnixPlatform) (port : int) : byte[] =
        CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback (uint16 port))

    let private kernelBind (fd : int) (port : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match CopyIn.bind fd UserBuffer.Mapped 16u (loopback (UnixSystem.platform system) port) system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"bind: %A{other}"

    let private kernelSocketOf (fd : int) (system : UnixSystem<int, string>) : SocketId =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) -> socketId
        | other -> failwith $"fd %d{fd} names %A{other}"

    /// The port a socket the kernel made is bound to.
    let private kernelPortOf (fd : int) (system : UnixSystem<int, string>) : int =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) ->
            match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
            | Some binding -> int binding.Endpoint.Port
            | None -> failwith $"fd %d{fd} is unbound"
        | other -> failwith $"fd %d{fd} names %A{other}"

    /// The explicit ports `ShutdownPairShape.ClientLocked` and
    /// `ListenerLocked` bind, outside the ephemeral range.
    let private lockedPort : int = 5100

    /// A pair in the kernel, as `HostPair` makes one on the host.
    type private KernelPair (platform : SimulatedUnixPlatform, shape : ShutdownPairShape) =
        let flavour = SimulatedUnixPlatform.flavour platform
        let mutable system = kernelSystem platform
        let mutable refused = false
        let mutable fds : Map<ConnectionEnd, int> = Map.empty
        let mutable edgePort : int option = None

        let rendered (error : UnixError) : string = $"-1 %A{error}"

        do
            let listener, s =
                NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

            let s =
                match shape with
                | ShutdownPairShape.ListenerReuseAddress -> ReuseAddress.set true listener s
                | ShutdownPairShape.Plain
                | ShutdownPairShape.ClientLocked
                | ShutdownPairShape.ListenerLocked
                | ShutdownPairShape.ClientReuseAddress -> s

            let s =
                kernelBind
                    listener
                    (match shape with
                     | ShutdownPairShape.ListenerLocked -> lockedPort
                     | ShutdownPairShape.Plain
                     | ShutdownPairShape.ClientLocked
                     | ShutdownPairShape.ClientReuseAddress
                     | ShutdownPairShape.ListenerReuseAddress -> 0)
                    s

            let s =
                match UnixSocket.tryListen (Callers.leader s) listener 4 s with
                | Ok (ListenAnswer.Listening _, s) -> s
                | other -> failwith $"listen: %A{other}"

            let port = kernelPortOf listener s

            let client, s =
                NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp s

            let s =
                match shape with
                | ShutdownPairShape.ClientLocked -> kernelBind client lockedPort s
                | ShutdownPairShape.ClientReuseAddress -> ReuseAddress.set true client s
                | ShutdownPairShape.Plain
                | ShutdownPairShape.ListenerLocked
                | ShutdownPairShape.ListenerReuseAddress -> s

            let s =
                match CopyIn.connect client UserBuffer.Mapped 16u (loopback platform port) s with
                | Ok (SyscallAnswer.Completed 0L, s) -> s
                | other -> failwith $"connect: %A{other}"

            let server, s =
                match UnixConnection.tryAccept (Callers.thread 1 s) listener UserBuffer.Mapped 16u 0 s with
                | Ok (AcceptOutcome.Accepted (accepted, _, _), s) -> accepted, s
                | other -> failwith $"accept: %A{other}"

            let s = kernelClose listener s
            let _, s = UnixDescriptor.setNonBlocking (Callers.leader s) client true s
            let _, s = UnixDescriptor.setNonBlocking (Callers.leader s) server true s
            system <- s
            fds <- Map.ofList [ c, client ; p, server ]

        member _.System : UnixSystem<int, string> = system

        member _.Fd (e : ConnectionEnd) : int =
            match Map.tryFind e fds with
            | Some fd -> fd
            | None -> failwith $"the %A{e} end has closed"

        member this.Read (e : ConnectionEnd) (count : int) : string =
            match ReadOutcomes.read (this.Fd e) UserBuffer.Mapped (uint64 count) system with
            | Ok (ReadAnswer.Completed bytes, after) ->
                system <- after
                string bytes.Length
            | Ok (ReadAnswer.Failed error, after) ->
                system <- after
                rendered error
            | other -> failwith $"a read of %d{count}: %A{other}"

        member this.WriteAnswer (e : ConnectionEnd) (count : int) : Result<int, string> =
            let bytes = ImmutableArray.Create (payload, 0, count)

            match WriteOutcomes.admitThenWrite (Lone.leader system) (this.Fd e) UserBuffer.Mapped bytes system with
            | Ok (WriteStep.Returns (WriteAnswer.Completed written, after)) ->
                system <- after
                Ok (int written)
            | Ok (WriteStep.Returns (WriteAnswer.Failed error, after)) ->
                system <- after
                Error (rendered error)
            | Ok (WriteStep.ReturnsRaising (WriteAnswer.Failed error, entry, after)) when entry.Signal = Signal.SIGPIPE ->
                system <- after
                Error (rendered error + "+SIGPIPE")
            | other -> failwith $"a write of %d{count}: %A{other}"

        interface IShutdownPair with
            member _.Refused = refused
            member this.Read e count = this.Read e count
            member this.WriteAnswer e count = this.WriteAnswer e count

            member this.SoError e =
                let level = SimulatedUnixPlatform.socketOptionLevel platform
                let optionName = SimulatedUnixPlatform.socketErrorOption platform

                match
                    Lone.UnixSocket.tryGetsockoptLength
                        (this.Fd e)
                        level
                        optionName
                        UserBuffer.Mapped
                        UserBuffer.Mapped
                        (Some 4u)
                        system
                with
                | Ok (GetSockOptAnswer.Reported (OptionValue.Int 0), after) ->
                    system <- after
                    "0"
                | Ok (GetSockOptAnswer.Reported (OptionValue.Int raw), after) ->
                    system <- after

                    match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) raw with
                    | Some error -> $"%A{error}"
                    | None -> failwith $"SO_ERROR reported %d{raw}"
                | other -> failwith $"getsockopt(SO_ERROR): %A{other}"

            member this.Shutdown e how =
                let raw =
                    match how with
                    | TcpShutdownHow.Read -> 0
                    | TcpShutdownHow.Write -> 1
                    | TcpShutdownHow.Both -> 2

                (this :> IShutdownPair).ShutdownRaw e raw

            member this.ShutdownRaw e how =
                match UnixConnection.tryShutdown (Callers.leader system) (this.Fd e) how system with
                | Ok (answer, after) ->
                    UnixSystem.checkInvariants after |> shouldEqual []
                    system <- after

                    match answer with
                    | ShutdownAnswer.Shut -> "0"
                    | ShutdownAnswer.Failed error -> rendered error
                | Error (ShutdownRefusal.ReceiveShutBeforeUnsentBytes _) ->
                    refused <- true
                    ""
                | Error refusal -> failwith $"shutdown refused: %s{ShutdownRefusal.describe refusal}"

            member this.Close e =
                match UnixDescriptor.tryClose (Callers.leader system) (this.Fd e) system with
                | Ok (SyscallAnswer.Completed 0L, after) ->
                    system <- after
                    fds <- Map.remove e fds
                    "0"
                | Error (CloseRefusal.Release (DescriptionReleaseRefusal.DarwinCloseBehindQueuedFin _))
                | Error (CloseRefusal.Release (DescriptionReleaseRefusal.DarwinAbortBehindQueuedFin _)) ->
                    refused <- true
                    ""
                | other -> failwith $"close: %A{other}"

            member this.SetLingerZero e =
                let fd = this.Fd e
                let level = SimulatedUnixPlatform.socketOptionLevel platform
                let name = lingerOption flavour
                let value = OptionValue.ofLinger 1 0

                // The kernel copies the value only where it reads it at all:
                // Darwin answers EINVAL first once both directions are shut.
                let supplied =
                    match
                        Lone.UnixSocket.tryAdmitSetSockOpt fd level name UserBuffer.Mapped (uint32 value.Length) system
                    with
                    | Ok (SetSockOptAdmission.Transfer count) -> Some (ImmutableArray.Create (value, 0, count))
                    | Ok SetSockOptAdmission.NoCopy
                    | Ok (SetSockOptAdmission.Answered _) -> None
                    | Error refusal ->
                        failwith $"setsockopt(SO_LINGER) refused: %s{SocketOptionRefusal.describe refusal}"

                match
                    Lone.UnixSocket.trySetsockoptBytes
                        fd
                        level
                        name
                        UserBuffer.Mapped
                        (uint32 value.Length)
                        supplied
                        system
                with
                | Ok (answer, after) ->
                    system <- after

                    match answer with
                    | SetSockOptAnswer.Set -> "0"
                    | SetSockOptAnswer.Failed error -> rendered error
                | Error refusal -> failwith $"setsockopt(SO_LINGER) refused: %s{SocketOptionRefusal.describe refusal}"

            member this.Abort e =
                (this :> IShutdownPair).SetLingerZero e |> ignore<string>
                (this :> IShutdownPair).Close e

            member this.Fionread e =
                match UnixDescriptor.tryBytesAvailable (Callers.leader system) (this.Fd e) UserBuffer.Mapped system with
                | Ok (BytesAvailableAnswer.Reported count, _) -> count
                | other -> failwith $"FIONREAD: %A{other}"

            member this.Rdy e =
                let fd = this.Fd e

                let revents, after =
                    match
                        UnixPoll.tryPoll
                            (Callers.leader system)
                            [
                                {
                                    Fd = fd
                                    Events = rdyEvents flavour
                                }
                            ]
                            0
                            system
                    with
                    | Ok (PollOutcome.Answered ([ revents ], _), after) -> int (uint16 revents), after
                    | other -> failwith $"poll: %A{other}"

                system <- after

                let waiters =
                    match flavour with
                    | SimulatedUnixFlavour.Linux ->
                        // This kernel models no level-triggered registration;
                        // what one would report is the socket's level, as
                        // asked for, with ERR and HUP, which are never masked.
                        let description =
                            match FileDescriptorRegistry.tryFindId fd (Lone.fileDescriptors system) with
                            | Some description -> description
                            | None -> failwith $"fd %d{fd} names no description"

                        let level = Lone.LinuxReadiness.ofDescription description system
                        $"epoll=0x%x{level &&& (uint32 (rdyEvents flavour) ||| 0x18u)}"
                    | SimulatedUnixFlavour.Darwin ->
                        let kq, s = KeventWorld.kqueue system

                        let changes =
                            [
                                KeventWorld.change fd KeventFilter.Read KeventFlags.Add 0UL
                                KeventWorld.change fd KeventFilter.Write KeventFlags.Add 0UL
                            ]

                        let events, s =
                            match
                                UnixKqueue.tryKevent
                                    (Callers.leader s)
                                    kq
                                    2
                                    changes
                                    2
                                    UserBuffer.Mapped
                                    (TimespecArgument.Readable
                                        {
                                            Seconds = 0L
                                            Nanoseconds = 0L
                                        })
                                    s
                            with
                            | Ok (KeventOutcome.Answered events, s) -> events, s
                            | other -> failwith $"kevent: %A{other}"

                        system <- kernelClose kq s

                        let render (filter : int16) =
                            events
                            |> List.tryFind (fun event -> event.Filter = filter)
                            |> Option.map (fun event -> renderKevent event.Data event.Flags event.FilterFlags)
                            |> Option.defaultValue "-"

                        $"kq-read=%s{render KeventFilter.Read} kq-write=%s{render KeventFilter.Write}"

                $"poll=0x%x{revents} %s{waiters} fionread=%d{(this :> IShutdownPair).Fionread e}"

            member this.Fill e =
                let rec go (total : int64) =
                    match this.WriteAnswer e (1 <<< 20) with
                    | Ok n -> go (total + int64 n)
                    | Error _ -> total

                go 0L

            member this.Drain e =
                let rec go (total : int64) =
                    match this.Read e (1 <<< 20) with
                    | answer when answer.StartsWith ("-", StringComparison.Ordinal) || answer = "0" -> total, answer
                    | count -> go (total + int64 count)

                go 0L

            member _.Settle () = ()

            member this.RegisterEdges ends =
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    let ep, s =
                        match UnixPoll.tryEpollCreate1 (Callers.leader system) 0 system with
                        | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
                        | other -> failwith $"epoll_create1: %A{other}"

                    let s =
                        (s, ends)
                        ||> List.fold (fun s e ->
                            let fd = this.Fd e

                            match
                                UnixPoll.tryEpollCtl
                                    (Callers.leader s)
                                    ep
                                    1
                                    fd
                                    (EpollEventArgument.Readable (0x80002005u, uint64 fd))
                                    s
                            with
                            | Ok (EpollCtlAnswer.Changed, s) -> s
                            | other -> failwith $"epoll_ctl: %A{other}"
                        )

                    system <- s
                    edgePort <- Some ep
                | SimulatedUnixFlavour.Darwin ->
                    let kq, s = KeventWorld.kqueue system
                    let flags = KeventFlags.Add ||| KeventFlags.Clear

                    let changes =
                        ends
                        |> List.collect (fun e ->
                            [
                                KeventWorld.change (this.Fd e) KeventFilter.Read flags 0UL
                                KeventWorld.change (this.Fd e) KeventFilter.Write flags 0UL
                            ]
                        )

                    let s =
                        match
                            UnixKqueue.tryKevent
                                (Callers.leader s)
                                kq
                                changes.Length
                                changes
                                0
                                UserBuffer.Mapped
                                (TimespecArgument.Readable
                                    {
                                        Seconds = 0L
                                        Nanoseconds = 0L
                                    })
                                s
                        with
                        | Ok (KeventOutcome.Answered [], s) -> s
                        | other -> failwith $"kevent: %A{other}"

                    system <- s
                    edgePort <- Some kq

            member _.Edges () =
                let port =
                    match edgePort with
                    | Some port -> port
                    | None -> failwith "no edge registration"

                let cFd = Map.tryFind c fds |> Option.defaultValue -1

                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    match UnixPoll.tryEpollWait (Callers.leader system) port 4 UserBuffer.Mapped 0 system with
                    | Ok (EpollWaitOutcome.Answered events, after) ->
                        system <- after

                        let of' (isC : bool) =
                            events
                            |> List.tryFind (fun (data, _) -> (int data = cFd) = isC)
                            |> Option.map (fun (_, e) -> $"0x%x{e}")
                            |> Option.defaultValue "-"

                        $"c=%s{of' true} p=%s{of' false}"
                    | other -> failwith $"epoll_wait: %A{other}"
                | SimulatedUnixFlavour.Darwin ->
                    match
                        UnixKqueue.tryKevent
                            (Callers.leader system)
                            port
                            0
                            []
                            4
                            UserBuffer.Mapped
                            (TimespecArgument.Readable
                                {
                                    Seconds = 0L
                                    Nanoseconds = 0L
                                })
                            system
                    with
                    | Ok (KeventOutcome.Answered [], after) ->
                        system <- after
                        "-"
                    | Ok (KeventOutcome.Answered events, after) ->
                        system <- after

                        events
                        |> List.map (fun event ->
                            let who = if int event.Ident = cFd then "c" else "p"
                            let what = if event.Filter = KeventFilter.Read then "read" else "write"
                            $"%s{who}-%s{what}=%s{renderKevent event.Data event.Flags event.FilterFlags}"
                        )
                        |> String.concat " "
                    | other -> failwith $"kevent: %A{other}"

            member _.BindsEndpoints = true
            member this.PortOf e = kernelPortOf (this.Fd e) system

            member _.BindFree port =
                let fresh, s =
                    NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

                let answer, s =
                    match CopyIn.bind fresh UserBuffer.Mapped 16u (loopback platform port) s with
                    | Ok (BindAnswer.Bound _, s) -> "bind-ok", s
                    | Ok (BindAnswer.Failed UnixError.EADDRINUSE, s) -> "bind-EADDRINUSE", s
                    | Ok (BindAnswer.Failed error, s) -> rendered error, s
                    | Error refusal -> failwith $"bind refused: %A{refusal}"

                system <- kernelClose fresh s
                answer

            member _.Candidate reuse wildcard port =
                let fresh, s =
                    NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

                let s = if reuse then ReuseAddress.set true fresh s else s

                let address =
                    CopyIn.inet
                        platform
                        (Ipv4Endpoint.ofParts (if wildcard then Ipv4Address.any else Ipv4Address.loopback) (uint16 port))

                let answer, s =
                    match CopyIn.bind fresh UserBuffer.Mapped 16u address s with
                    | Ok (BindAnswer.Bound _, s) ->
                        match UnixSocket.tryListen (Callers.leader s) fresh 4 s with
                        | Ok (ListenAnswer.Listening _, s) -> "bind-ok listen-ok", s
                        | Ok (ListenAnswer.Failed error, s) -> $"bind-ok listen-%A{error}", s
                        | Error refusal -> failwith $"listen refused: %A{refusal}"
                    | Ok (BindAnswer.Failed error, s) -> $"bind-%A{error}", s
                    | Error refusal -> failwith $"bind refused: %A{refusal}"

                system <- kernelClose fresh s
                answer

            member this.ReuseAddress e =
                let level = SimulatedUnixPlatform.socketOptionLevel platform
                let name = SimulatedUnixPlatform.reuseAddressOption platform

                match
                    Lone.UnixSocket.tryGetsockoptLength
                        (this.Fd e)
                        level
                        name
                        UserBuffer.Mapped
                        UserBuffer.Mapped
                        (Some 4u)
                        system
                with
                | Ok (answer, after) ->
                    system <- after
                    if OptionValue.readInt answer <> 0 then 1 else 0
                | Error refusal ->
                    failwith $"getsockopt(SO_REUSEADDR) refused: %s{SocketOptionRefusal.describe refusal}"

            member this.PeerName e =
                match UnixSocket.tryGetpeername (Callers.leader system) (this.Fd e) UserBuffer.Mapped 16u system with
                | Ok (GetSockNameAnswer.Reported _) -> "ok"
                | Ok (GetSockNameAnswer.Failed (error, _)) -> $"%A{error}"
                | Error refusal -> failwith $"getpeername refused: %s{GetSockNameRefusal.describe refusal}"

            member _.KeepsTimeWaitOnceBothClosed = false

    let private kernelReplay (flavour : SimulatedUnixFlavour) (scenarios : ShutdownProbe.Scenario list) =
        let platform = HostPlatform.platformOf flavour

        scenarios
        |> List.collect (fun scenario ->
            let mutable made : KernelPair list = []

            let pairOf (shape : ShutdownPairShape) : IShutdownPair =
                let pair = KernelPair (platform, shape)
                made <- pair :: made
                pair :> IShutdownPair

            let lines = scenario pairOf

            for pair in made do
                UnixSystem.checkInvariants pair.System |> shouldEqual []

            lines
        )


    /// Section U's calls in the kernel, on one system threaded through them.
    /// What a shutdown that answers ENOTCONN leaves behind (the `fresh-then`
    /// and `udp-then` rows) is held to the kernel by
    /// ``an unconnected socket's shutdown changes nothing on Darwin and is refused on Linux``.
    let private kernelU (platform : SimulatedUnixPlatform) : UWorld =
        let mutable system = kernelSystem platform

        let created (kind : SocketKind) (protocol : SocketProtocol) : int =
            let fd, after = NewSocket.create SocketDomain.Inet kind protocol system
            system <- after
            fd

        let connectAnswer (fd : int) (port : int) : string =
            match CopyIn.connect fd UserBuffer.Mapped 16u (loopback platform port) system with
            | Ok (SyscallAnswer.Completed _, after) ->
                system <- after
                "0"
            | Ok (SyscallAnswer.Failed error, after) ->
                system <- after
                $"-1 %A{error}"
            | Error refusal -> failwith $"connect refused: %s{ConnectRefusal.describe refusal}"

        let shutdownOf (fd : int) (how : int) : ShutdownLine =
            match UnixConnection.tryShutdown (Callers.leader system) fd how system with
            | Ok (answer, after) ->
                system <- after

                match answer with
                | ShutdownAnswer.Shut -> ShutdownLine.Line "0"
                | ShutdownAnswer.Failed error -> ShutdownLine.Line $"-1 %A{error}"
            | Error (ShutdownRefusal.LinuxUnconnected _) -> ShutdownLine.Refused
            | Error refusal -> failwith $"shutdown refused: %s{ShutdownRefusal.describe refusal}"

        let listening () : int * int =
            let l = created SocketKind.Stream SocketProtocol.Tcp
            system <- kernelBind l 0 system

            match UnixSocket.tryListen (Callers.leader system) l 4 system with
            | Ok (ListenAnswer.Listening _, after) -> system <- after
            | other -> failwith $"listen: %A{other}"

            l, kernelPortOf l system

        {
            Stream = fun () -> created SocketKind.Stream SocketProtocol.Tcp
            Datagram = fun () -> created SocketKind.Datagram SocketProtocol.Udp
            NotSocket =
                fun () ->
                    match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
                    | Ok (Pipe2Answer.Created (readFd, writeFd), after) ->
                        system <- kernelClose writeFd after
                        readFd
                    | other -> failwith $"pipe2: %A{other}"
            // Nothing but this replay changes `system`, so a slot it frees
            // stays free, and the closed-fd rows ask about one, as the probe's do.
            NamesNothing =
                fun () ->
                    match UnixPipe.tryPipe2 (Callers.leader system) 0 UserBuffer.Mapped system with
                    | Ok (Pipe2Answer.Created (readFd, writeFd), after) ->
                        system <- after |> kernelClose writeFd |> kernelClose readFd
                        readFd
                    | other -> failwith $"pipe2: %A{other}"
            BindAny = fun fd -> system <- kernelBind fd 0 system
            Shutdown = shutdownOf
            Close = fun fd -> system <- kernelClose fd system
            Refused =
                fun () ->
                    let l, port = listening ()
                    system <- kernelClose l system
                    let f = created SocketKind.Stream SocketProtocol.Tcp
                    f, connectAnswer f port
            Unreported =
                fun how ->
                    let l, port = listening ()
                    let f = created SocketKind.Stream SocketProtocol.Tcp
                    let _, after = UnixDescriptor.setNonBlocking (Callers.leader system) f true system
                    system <- after
                    let first = connectAnswer f port

                    let sh =
                        match how with
                        | None -> ShutdownLine.Line "-"
                        | Some how -> shutdownOf f how

                    let again = connectAnswer f port
                    system <- kernelClose f system |> kernelClose l

                    let name =
                        match how with
                        | None -> "none"
                        | Some how -> rawHowName how

                    match sh with
                    | ShutdownLine.Line answer ->
                        ShutdownLine.Line
                            $"U\tconnect-unreported(%s{first})\t%s{name}\tshutdown=%s{answer} connect=%s{again}"
                    | other -> other
            Then = fun _ -> List.replicate 3 ShutdownLine.Elsewhere
            ConnectedShutdown =
                fun how ->
                    let pair = KernelPair (platform, ShutdownPairShape.Plain)
                    ShutdownLine.Line ((pair :> IShutdownPair).ShutdownRaw ConnectionEnd.Client how)
        }

    let private flavours : SimulatedUnixFlavour list =
        [ SimulatedUnixFlavour.Linux ; SimulatedUnixFlavour.Darwin ]

    let private kernelDisagreementsOf
        (probe : ShutdownProbe.Probe)
        (section : string)
        (scenarios : ShutdownProbe.Scenario list)
        : string list
        =
        flavours
        |> List.collect (fun flavour ->
            kernelReplay flavour scenarios
            |> ShutdownProbe.disagreements probe flavour section id
        )

    let private kernelDisagreements (section : string) (scenarios : ShutdownProbe.Scenario list) : string list =
        kernelDisagreementsOf ShutdownProbe.Probe.Shutdown section scenarios

    [<Test>]
    let ``the kernel answers shutdown, and what each end then sees, as each flavour measured (section S)`` () =
        kernelDisagreements "S" ShutdownProbe.sectionS |> shouldEqual []

    [<Test>]
    let ``the kernel answers shutdown twice, and after the peer's FIN or reset, as measured (section T)`` () =
        kernelDisagreements "T" ShutdownProbe.sectionT |> shouldEqual []

    [<Test>]
    let ``the kernel answers bytes arriving after the receive side is shut as measured (section R)`` () =
        kernelDisagreements "R" ShutdownProbe.sectionR |> shouldEqual []

    [<Test>]
    let ``the kernel answers a close after shutdown as measured (section P)`` () =
        kernelDisagreements "P" ShutdownProbe.sectionP |> shouldEqual []

    [<Test>]
    let ``the kernel reports edges after shutdown as measured (section E)`` () =
        kernelDisagreements "E" ShutdownProbe.sectionE |> shouldEqual []

    [<Test>]
    let ``the kernel answers a close under SO_LINGER, and frees the closer's endpoint, as measured (section L)`` () =
        kernelDisagreements "L" ShutdownProbe.sectionL |> shouldEqual []

    [<Test>]
    let ``the kernel refuses a close under SO_LINGER only where the probe marked the outcome as waiting on a timer``
        ()
        =
        // Darwin's close under linger zero after its own FIN was queued
        // before the peer's arrived (L, cqueued-pfin): the close, both binds,
        // the peer's calls and its drain.
        [
            for flavour in flavours do
                let measured = ShutdownProbe.measured ShutdownProbe.Probe.Shutdown flavour "L"
                let replayed = kernelReplay flavour ShutdownProbe.sectionL

                for line, modelled in List.zip measured replayed do
                    if modelled = ShutdownLine.Refused then
                        line.Mark |> shouldEqual ShutdownMark.Timing

                flavour, replayed |> List.filter ((=) ShutdownLine.Refused) |> List.length
        ]
        |> shouldEqual [ SimulatedUnixFlavour.Linux, 0 ; SimulatedUnixFlavour.Darwin, 5 ]

    [<Test>]
    let ``the kernel frees an end's endpoint, open or closed, and answers getpeername as measured (section F)`` () =
        kernelDisagreements "F" ShutdownProbe.sectionF |> shouldEqual []

    [<Test>]
    let ``the kernel answers a bind of an endpoint an end still holds as measured (bind-held-endpoint.c)`` () =
        kernelDisagreementsOf ShutdownProbe.Probe.HeldEndpoint "H" ShutdownProbe.sectionH
        |> shouldEqual []

    [<Test>]
    let ``the kernel refuses only where the probe marked the outcome as waiting on a timer`` () =
        // Darwin's SHUT_RD before the peer's unsent bytes (R, p-unsent).
        [
            for flavour in flavours do
                let measured = ShutdownProbe.measured ShutdownProbe.Probe.Shutdown flavour "R"
                let replayed = kernelReplay flavour ShutdownProbe.sectionR

                for line, modelled in List.zip measured replayed do
                    if modelled = ShutdownLine.Refused then
                        line.Mark |> shouldEqual ShutdownMark.Timing

                flavour, replayed |> List.filter ((=) ShutdownLine.Refused) |> List.length
        ]
        |> shouldEqual [ SimulatedUnixFlavour.Linux, 0 ; SimulatedUnixFlavour.Darwin, 4 ]

    [<Test>]
    let ``the kernel answers shutdown on sockets without a connection, and a bad how, as measured (section U)`` () =
        for flavour in flavours do
            let replayed = sectionU (kernelU (HostPlatform.platformOf flavour))
            let measured = ShutdownProbe.measured ShutdownProbe.Probe.Shutdown flavour "U"

            // Linux's ENOTCONN to a socket without a connection still shuts its
            // sides, which this kernel does not keep, so it refuses each of
            // those rows; Darwin answers every one.
            let refusedRows =
                List.zip measured replayed
                |> List.filter (fun (_, line) -> line = ShutdownLine.Refused)
                |> List.map (fun (line, _) -> (line.Text.Split '\t').[1])
                |> List.countBy (fun row ->
                    if row.StartsWith ("refused", StringComparison.Ordinal) then
                        "refused"
                    else
                        row
                )

            match flavour with
            | SimulatedUnixFlavour.Linux ->
                refusedRows
                |> shouldEqual [ "fresh", 3 ; "bound", 3 ; "udp-unconnected", 3 ; "refused", 3 ]
            | SimulatedUnixFlavour.Darwin -> refusedRows |> shouldEqual []

            replayed
            |> List.map (fun line ->
                match line with
                | ShutdownLine.Refused -> ShutdownLine.Elsewhere
                | other -> other
            )
            |> ShutdownProbe.disagreements ShutdownProbe.Probe.Shutdown flavour "U" id
            |> shouldEqual []

    /// A socket without a connection: Darwin answers ENOTCONN and changes
    /// nothing at all (`tcp-shutdown.c`, section U, `fresh-then` and
    /// `udp-then`); Linux's ENOTCONN still shuts the sides, which this kernel
    /// does not keep on such a socket, so it refuses the call. A listener is
    /// refused on both, until its `shutdown` is modelled.
    [<Test>]
    let ``an unconnected socket's shutdown changes nothing on Darwin and is refused on Linux`` () =
        for flavour in flavours do
            let platform = HostPlatform.platformOf flavour

            for kind, protocol in
                [
                    SocketKind.Stream, SocketProtocol.Tcp
                    SocketKind.Datagram, SocketProtocol.Udp
                ] do
                for bound in [ false ; true ] do
                    for how in [ 0 ; 1 ; 2 ] do
                        let fd, system =
                            NewSocket.create SocketDomain.Inet kind protocol (kernelSystem platform)

                        let system = if bound then kernelBind fd 0 system else system
                        let socket = kernelSocketOf fd system

                        match flavour, UnixConnection.tryShutdown (Callers.leader system) fd how system with
                        | SimulatedUnixFlavour.Darwin, Ok (ShutdownAnswer.Failed UnixError.ENOTCONN, after) ->
                            after |> shouldEqual system
                        | SimulatedUnixFlavour.Linux, Error (ShutdownRefusal.LinuxUnconnected refused) ->
                            refused |> shouldEqual socket
                        | _, other -> failwith $"%A{flavour} %A{kind} bound %b{bound} how %d{how}: %A{other}"

            let listener, system =
                NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp (kernelSystem platform)

            let system = kernelBind listener 0 system

            let system =
                match UnixSocket.tryListen (Callers.leader system) listener 4 system with
                | Ok (ListenAnswer.Listening _, system) -> system
                | other -> failwith $"listen: %A{other}"

            for how in [ 0 ; 1 ; 2 ] do
                UnixConnection.tryShutdown (Callers.leader system) listener how system
                |> Result.map fst
                |> shouldEqual (Error (ShutdownRefusal.Listener (kernelSocketOf listener system)))

            // A `how` out of range is screened before the state.
            UnixConnection.tryShutdown (Callers.leader system) listener 3 system
            |> Result.map fst
            |> shouldEqual (Ok (ShutdownAnswer.Failed UnixError.EINVAL))
