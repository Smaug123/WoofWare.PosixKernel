namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// Why this kernel will not deliver a datagram.
[<RequireQualifiedAccess>]
type internal DeliveryRefusal =
    /// The sockets `sockets` are each as good a receiver for a datagram to
    /// `destination` as any other: which one a real kernel picks is not
    /// modelled.
    | Tie of destination : Ipv4Endpoint * sockets : SocketId list
    /// No socket takes a datagram from the connected socket `sender` to
    /// `destination`, which a real kernel answers with an ICMP error that
    /// leaves `ECONNREFUSED` pending at the sender; this kernel does not yet
    /// model that error.
    | Unreachable of sender : SocketId * destination : Ipv4Endpoint
    /// A destination outside loopback's 127.0.0.0/8, to which neither the
    /// source a datagram carries nor its delivery is measured.
    | BeyondLoopback of destination : Ipv4Endpoint
    /// A destination a Linux machine does not take as its own, which Linux
    /// would route off the machine.
    | Unroutable of destination : Ipv4Endpoint
    /// The socket `socket`, which a Linux connect to port 0 left with a peer
    /// whose port is 0, is bound at `destination` and connected to the
    /// datagram's source address. Linux takes such a peer as matching any
    /// source port, and how such a socket ranks beside the others is not
    /// measured.
    | ZeroPortPeer of destination : Ipv4Endpoint * socket : SocketId

[<RequireQualifiedAccess>]
module internal DeliveryRefusal =
    /// What this kernel knows about why it cannot deliver the datagram.
    let describe (refusal : DeliveryRefusal) : string =
        match refusal with
        | DeliveryRefusal.Tie (destination, sockets) ->
            let named = sockets |> List.map (sprintf "%O") |> String.concat ", "
            $"the datagram is to %s{Ipv4Endpoint.toString destination}, and sockets %s{named} are each as good a receiver for it as any other. Measured, a socket connected to the datagram's source beats one that is not, and one bound to the destination's address beats one bound to the wildcard; between two that match equally, Linux delivers to the one bound last, which this kernel does not record, and under SO_REUSEPORT a hash decides."
        | DeliveryRefusal.Unreachable (sender, destination) ->
            $"socket %O{sender}, which is connected, sends a datagram to %s{Ipv4Endpoint.toString destination}, where no socket takes it. A real kernel answers it with an ICMP port-unreachable error, which leaves ECONNREFUSED pending at the sender, and this kernel does not yet model that error."
        | DeliveryRefusal.BeyondLoopback destination ->
            $"the datagram is to %s{Ipv4Endpoint.toString destination}, outside loopback's 127.0.0.0/8, and which source address it would carry, and whether it is delivered, are not measured."
        | DeliveryRefusal.ZeroPortPeer (destination, socket) ->
            $"socket %O{socket}, bound at %s{Ipv4Endpoint.toString destination}, is connected to the datagram's source address at port 0, as Linux's connect leaves a socket connected to port 0. Linux takes a peer port of 0 as matching any source port, and how such a socket ranks beside the others bound there is not measured."
        | DeliveryRefusal.Unroutable destination ->
            $"the datagram is to %s{Ipv4Endpoint.toString destination}, which this Linux machine neither holds nor has a local route to, so Linux would send it off the machine, and this kernel models no network beyond it."

/// What became of a datagram sent on the machine.
[<RequireQualifiedAccess>]
type internal DatagramDelivered =
    /// The socket `receiver` holds it.
    | Queued of receiver : SocketId
    /// The socket `receiver` had no room for it, and it is lost.
    | Dropped of receiver : SocketId
    /// It went to an address the machine does not take as its own, which
    /// Darwin lets a datagram be sent to and delivers to no one, raising no
    /// error.
    | Unowned

/// Which UDP socket on the machine a datagram reaches.
[<RequireQualifiedAccess>]
module internal DatagramDelivery =

    /// Whether the machine takes `address` as its own for a datagram's
    /// delivery: on Linux, any address it holds or has a local route to; on
    /// Darwin, only the addresses it holds.
    let owns (machine : UnixMachineState) (address : Ipv4Address) : bool =
        // Measured (`udp-transfer.c` N and L15, in
        // docs/plans/2026-10-18-udp-data-path): a datagram to 127.0.0.2
        // reaches a Linux socket bound to the wildcard, and no Darwin socket,
        // though Darwin's connect and sendto accept the address.
        List.contains address machine.LocalIpv4Addresses
        || (SimulatedUnixPlatform.flavour machine.UnixPlatform = SimulatedUnixFlavour.Linux
            && machine.LocalRoutes |> List.exists (Ipv4Prefix.contains address))

    /// The address a datagram from a socket bound at `binding` carries as its
    /// source over loopback: the binding's own, or 127.0.0.1 for one bound
    /// to the wildcard.
    let source (binding : Ipv4Endpoint) : Ipv4Endpoint =
        // Measured (`udp-transfer.c` A2, A3 and N): a receiver reports
        // 127.0.0.1 and the sender's port for a sender unbound, bound to
        // 0.0.0.0, or bound to 127.0.0.1, and for a datagram to 127.0.0.2.
        if binding.Address = Ipv4Address.any then
            { binding with
                Address = Ipv4Address.loopback
            }
        else
            binding

    /// The socket that receives a datagram from `from` to `destination`, if
    /// one does, among the sockets on `machine`, which takes `destination`'s
    /// address as its own.
    let receiverOf
        (machine : UnixMachineState)
        (from : Ipv4Endpoint)
        (destination : Ipv4Endpoint)
        : Result<SocketId option, DeliveryRefusal>
        =
        // Measured (`udp-transfer.c` J, Q3, Q4 and Q5): a socket takes a
        // datagram at its port if it is bound to the destination's address or
        // the wildcard, and is unconnected or connected to the datagram's
        // source. A connected socket beats an unconnected one, and a specific
        // address beats the wildcard.
        let candidates =
            machine.Sockets
            |> Map.toList
            |> List.choose (fun (socketId, socket) ->
                if not (UnixMachineState.receivesDatagrams socket) then
                    None
                else

                match socket.Ipv4Binding with
                | Some binding when
                    binding.Endpoint.Port = destination.Port
                    && (binding.Endpoint.Address = destination.Address
                        || binding.Endpoint.Address = Ipv4Address.any)
                    ->
                    let specific = binding.Endpoint.Address <> Ipv4Address.any

                    match socket.Phase with
                    | SocketPhase.Idle -> Some (Ok (socketId, false, specific))
                    | SocketPhase.DatagramPeer (SocketAddress.Inet peer) when peer = from ->
                        Some (Ok (socketId, true, specific))
                    | SocketPhase.DatagramPeer (SocketAddress.Inet peer) when
                        peer.Port = 0us && peer.Address = from.Address
                        ->
                        Some (Error (DeliveryRefusal.ZeroPortPeer (destination, socketId)))
                    | SocketPhase.DatagramPeer _ -> None
                    | SocketPhase.Listening _
                    | SocketPhase.Established _
                    | SocketPhase.EstablishedPendingReport _
                    | SocketPhase.Refused _
                    | SocketPhase.Connecting _ ->
                        failwith
                            $"DatagramDelivery.receiverOf: datagram socket %O{socketId} is in %A{socket.Phase}, which UnixSystem.checkInvariants forbids a datagram socket (this is a bug in this library)."
                | Some _
                | None -> None
            )

        let atLeastAsGood (_, connected, specific) (_, otherConnected, otherSpecific) : bool =
            (connected || not otherConnected) && (specific || not otherSpecific)

        match
            candidates
            |> List.tryPick (fun candidate ->
                match candidate with
                | Error refusal -> Some refusal
                | Ok _ -> None
            )
        with
        | Some refusal -> Error refusal
        | None ->

        let candidates =
            candidates
            |> List.choose (fun candidate ->
                match candidate with
                | Ok c -> Some c
                | Error _ -> None
            )

        match candidates with
        | [] -> Ok None
        | _ ->

        // The receiver is the candidate at least as good as every other.
        // Where none is, or several are, the measurements do not decide.
        match candidates |> List.filter (fun c -> candidates |> List.forall (atLeastAsGood c)) with
        | [ (socketId, _, _) ] -> Ok (Some socketId)
        | _ ->
            let unbeaten =
                candidates
                |> List.filter (fun c ->
                    candidates
                    |> List.forall (fun other -> not (atLeastAsGood other c) || atLeastAsGood c other)
                )

            Error (DeliveryRefusal.Tie (destination, unbeaten |> List.map (fun (socketId, _, _) -> socketId)))

    /// The datagram `payload` that the connected socket `sender` sends to its
    /// peer `destination`, delivered: what became of it, with the system
    /// after it and the wakes it raised.
    ///
    /// On Linux the sender's own send raises an `EPOLLOUT` edge, and on
    /// Darwin it marks the sender as having sent, which changes what its own
    /// datagrams cost it from then on.
    let deliver<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (sender : SocketId)
        (destination : Ipv4Endpoint)
        (payload : ImmutableArray<byte>)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<DatagramDelivered * ProcessView<'Thread, 'Handler>, DeliveryRefusal>
        =
        let machine = system.Machine

        if not (Ipv4Prefix.contains destination.Address Ipv4Prefix.loopbackNetwork) then
            Error (DeliveryRefusal.BeyondLoopback destination)
        elif
            not (owns machine destination.Address)
            && SimulatedUnixPlatform.flavour machine.UnixPlatform = SimulatedUnixFlavour.Linux
        then
            Error (DeliveryRefusal.Unroutable destination)
        else

        let from =
            match (UnixMachineState.socket sender machine).Ipv4Binding with
            | Some binding when binding.Endpoint.Port <> 0us -> source binding.Endpoint
            | binding ->
                failwith
                    $"DatagramDelivery.deliver: socket %O{sender} sends a datagram with binding %A{binding}; a datagram socket that sends has a port (this is a bug in this library)."

        let receiverOfDestination =
            if owns machine destination.Address then
                receiverOf machine from destination |> Result.map Some
            else
                Ok None

        match receiverOfDestination with
        | Error refusal -> Error refusal
        | Ok (Some None) -> Error (DeliveryRefusal.Unreachable (sender, destination))
        | Ok found ->

        // The sender is marked first: a Darwin socket sending to itself pays
        // the full charge for its own datagram (`udp-mbufs.c` section 2).
        // Its own edge comes first too: measured (`udp-transfer.c` G6 and G8),
        // a Linux sender's send is an EPOLLOUT edge, reported ahead of its
        // receiver's arrival by one epoll instance watching both, and a Darwin
        // one activates no EVFILT_WRITE.
        let system =
            { system with
                Machine =
                    UnixMachineState.withDatagramReceiver
                        sender
                        (DatagramReceiver.sent (UnixMachineState.datagramReceiver sender machine))
                        machine
            }
            |> SocketWake.signal sender SocketWake.DatagramSent

        let delivered, system =
            match found with
            | None
            | Some None -> DatagramDelivered.Unowned, system
            | Some (Some receiver) ->
                let connected =
                    match (UnixMachineState.socket receiver system.Machine).Phase with
                    | SocketPhase.DatagramPeer _ -> true
                    | _ -> false

                match
                    DatagramReceiver.arrive
                        connected
                        from
                        payload
                        (UnixMachineState.datagramReceiver receiver system.Machine)
                with
                | DatagramArrival.Dropped, _ -> DatagramDelivered.Dropped receiver, system
                | DatagramArrival.Queued, after ->
                    // Measured (`udp-transfer.c` G5): every arrival is an
                    // edge, datagrams already queued or not.
                    DatagramDelivered.Queued receiver,
                    { system with
                        Machine = UnixMachineState.withDatagramReceiver receiver after system.Machine
                    }
                    |> SocketWake.signal receiver SocketWake.DataArrived

        Ok (delivered, system)
