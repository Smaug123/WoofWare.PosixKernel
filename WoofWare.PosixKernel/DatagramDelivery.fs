namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// Why this kernel will not deliver a datagram.
[<RequireQualifiedAccess>]
type internal DeliveryRefusal =
    /// The sockets `sockets` are each as good a receiver for a datagram to
    /// `destination` as any other: which one a real kernel picks is not
    /// modelled.
    | Tie of destination : Ipv4Endpoint * sockets : SocketId list
    /// No socket takes a datagram from `source` to `destination`, and the
    /// sockets `sockets` are each as good a socket as any other for the ICMP
    /// error that answers it, which a real kernel delivers as it would a
    /// datagram from `destination` to `source`.
    | ErrorTie of source : Ipv4Endpoint * destination : Ipv4Endpoint * sockets : SocketId list
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
        | DeliveryRefusal.ErrorTie (source, destination, sockets) ->
            let named = sockets |> List.map (sprintf "%O") |> String.concat ", "
            $"no socket takes the datagram from %s{Ipv4Endpoint.toString source} to %s{Ipv4Endpoint.toString destination}, and the ICMP port-unreachable error that answers it goes to the socket a datagram from %s{Ipv4Endpoint.toString destination} to %s{Ipv4Endpoint.toString source} would reach, if that socket is connected. Sockets %s{named} are each as good a socket for it as any other, and which one a real kernel picks is not modelled: Linux picks the one bound last, which this kernel does not record."
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
    /// No socket took it, and the machine's ICMP port-unreachable error left
    /// `ECONNREFUSED` pending at the socket `erred`, if it raised an error
    /// and that error reached a connected socket.
    | Unheld of erred : SocketId option

/// Where a datagram goes, decided before anything is changed.
[<RequireQualifiedAccess>]
type private DatagramFate =
    /// To an address the machine does not take as its own (`DatagramDelivered.Unowned`).
    | Unowned
    /// To the socket `receiver`.
    | Reaches of receiver : SocketId
    /// To no socket. The machine then remembers `replies`, and its error
    /// leaves `ECONNREFUSED` pending at `erred`, if it reaches a connected
    /// socket.
    | Unheld of erred : SocketId option * replies : PortUnreachableReplies

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
    /// address as its own. Reads only the UDP sockets bound at
    /// `destination`'s port, so its cost does not grow with the sockets
    /// elsewhere on the machine.
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
        // address beats the wildcard. The index hands over only the UDP
        // sockets at the port, in the order of their identities, and the
        // rest of the test below is asked of each of them as it was asked of
        // every socket.
        let candidates =
            SocketTable.datagramSocketsAt destination.Port machine.Sockets
            |> Set.toList
            |> List.choose (fun socketId ->
                let socket = UnixMachineState.socket socketId machine

                if not (SocketTable.receivesDatagrams socket) then
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

    /// Under Linux, `system` with one receive asleep on the UDP socket
    /// `socket` chosen (`ParkedDatagramReceive.Chosen`): of those no arrival
    /// has chosen yet, the one that parked first. Under Darwin, which wakes
    /// every receive on the socket, `system` itself.
    ///
    /// What a datagram's arrival at the socket does, and the ICMP error's.
    /// Measured on Linux 6.18.5 (`udp-sleepers.c` V1 to V7, in
    /// docs/plans/2026-10-18-udp-data-path): each wakes the sleeper that
    /// parked first, and no other, whether the one woken then takes what
    /// woke it or peeks and leaves it; and two datagrams back to back wake
    /// two. A receive a signal has woken, and that has not run yet, is not
    /// asleep, so it is passed over, as Linux passes over a task already
    /// woken.
    ///
    /// Reads the parked threads of every process with one, since the socket
    /// may be another process's than the sender's: it takes time in the
    /// number of parked threads, as a sweep does.
    let private chooseSleeper<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (socket : SocketId)
        (system : ProcessView<'Thread, 'Handler>)
        : ProcessView<'Thread, 'Handler>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> system
        | SimulatedUnixFlavour.Linux ->

        let openFiles = system.Machine.OpenFiles

        let unchosen (park : ThreadPark) : ParkedDatagramReceive option =
            match park with
            | {
                  Syscall = ParkedSyscall.DatagramReceive ({
                                                               Socket = SleepTarget.Waiting (description, _)
                                                               Chosen = false
                                                           } as receive)
                  State = ParkState.Asleep
              } ->
                match OpenFileTable.tryFind description openFiles with
                | Some {
                           Target = OpenFileTarget.Socket asleepOn
                       } when asleepOn = socket -> Some receive
                | Some _
                | None -> None
            | _ -> None

        // The earliest unchosen receive asleep on the socket among `threads`.
        let earliestIn
            (threads : ThreadTable<'Thread>)
            : (ParkOrdinal * 'Thread * ThreadPark * ParkedDatagramReceive) option
            =
            (None, UnixThreadTable.parked threads)
            ||> Set.fold (fun earliest thread ->
                match UnixThreadTable.parkOf thread threads with
                | None -> earliest
                | Some park ->
                    match unchosen park, earliest with
                    | None, _ -> earliest
                    | Some _, Some (ordinal, _, _, _) when ordinal < park.Ordinal -> earliest
                    | Some receive, _ -> Some (park.Ordinal, thread, park, receive)
            )

        let chosen (park : ThreadPark) (receive : ParkedDatagramReceive) : ThreadPark =
            { park with
                Syscall =
                    ParkedSyscall.DatagramReceive
                        { receive with
                            Chosen = true
                        }
            }

        let own = earliestIn system.Threads

        let other =
            (None, ProcessTable.withParks system.Others)
            ||> Set.fold (fun earliest key ->
                match
                    earliestIn (ProcessTable.find "DatagramDelivery.deliver" key system.Others).Threads, earliest
                with
                | None, _ -> earliest
                | Some (ordinal, _, _, _), Some (_, (sooner, _, _, _)) when sooner < ordinal -> earliest
                | Some found, _ -> Some (key, found)
            )

        let inOther (key : int32) (thread : 'Thread) (park : ThreadPark) (receive : ParkedDatagramReceive) =
            let slot = ProcessTable.find "DatagramDelivery.deliver" key system.Others

            { system with
                Others =
                    ProcessTable.add
                        key
                        { slot with
                            Threads = UnixThreadTable.withPark thread (chosen park receive) slot.Threads
                        }
                        system.Others
            }

        // Marking a park in place changes no hold: the park names the same
        // description as before.
        match own, other with
        | None, None -> system
        | None, Some (key, (_, thread, park, receive)) -> inOther key thread park receive
        | Some (ordinal, _, _, _), Some (key, (sooner, thread, park, receive)) when sooner < ordinal ->
            inOther key thread park receive
        | Some (_, thread, park, receive), _ ->
            { system with
                Threads = UnixThreadTable.withPark thread (chosen park receive) system.Threads
            }

    /// The datagram `payload` that the connected socket `sender` sends to its
    /// peer `destination`, delivered: what became of it, with the system
    /// after it and the wakes it raised.
    ///
    /// On Linux the sender's own send raises an `EPOLLOUT` edge, and on
    /// Darwin it marks the sender as having sent, which changes what its own
    /// datagrams cost it from then on.
    ///
    /// A datagram no socket takes is answered with an ICMP port-unreachable
    /// error by the machine's `PortUnreachableReplies`, and the error is
    /// delivered as a datagram back from `destination` would be, leaving
    /// `ECONNREFUSED` pending at the socket it reaches if that socket is
    /// connected.
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

        let fate : Result<DatagramFate, DeliveryRefusal> =
            if not (owns machine destination.Address) then
                Ok DatagramFate.Unowned
            else

            match receiverOf machine from destination with
            | Error refusal -> Error refusal
            | Ok (Some receiver) -> Ok (DatagramFate.Reaches receiver)
            | Ok None ->

            match
                PortUnreachableReplies.answer
                    system.Scheduling.NanosecondsSinceBoot
                    from
                    destination
                    machine.PortUnreachableReplies
            with
            | false, replies -> Ok (DatagramFate.Unheld (None, replies))
            | true, replies ->

            // Measured (`udp-transfer.c` L4, L10, L12, L15 and L16, in
            // docs/plans/2026-10-18-udp-data-path): the error goes to the
            // socket a datagram from the destination to the source would
            // reach, and only if that socket is connected, which is usually
            // the sender itself; an unconnected one is told nothing. Linux's
            // IP_RECVERR, which would tell it, is not settable.
            match receiverOf machine destination from with
            | Error (DeliveryRefusal.Tie (_, sockets)) -> Error (DeliveryRefusal.ErrorTie (from, destination, sockets))
            | Error refusal -> Error refusal
            | Ok None -> Ok (DatagramFate.Unheld (None, replies))
            | Ok (Some erred) ->
                match (UnixMachineState.socket erred machine).Phase with
                | SocketPhase.DatagramPeer _ -> Ok (DatagramFate.Unheld (Some erred, replies))
                | _ -> Ok (DatagramFate.Unheld (None, replies))

        match fate with
        | Error refusal -> Error refusal
        | Ok fate ->

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
            match fate with
            | DatagramFate.Unowned -> DatagramDelivered.Unowned, system
            | DatagramFate.Unheld (erred, replies) ->
                let system =
                    { system with
                        Machine =
                            { system.Machine with
                                PortUnreachableReplies = replies
                            }
                    }

                match erred with
                | None -> DatagramDelivered.Unheld None, system
                | Some erred ->
                    // Measured (`udp-error.c` Y8): one epoll registration
                    // watching the sender for IN|OUT|ET reports the send's
                    // OUT edge and the error's ERR edge together, as 0xc.
                    DatagramDelivered.Unheld (Some erred),
                    { system with
                        Machine =
                            UnixMachineState.withDatagramReceiver
                                erred
                                (DatagramReceiver.refused (UnixMachineState.datagramReceiver erred system.Machine))
                                system.Machine
                    }
                    |> SocketWake.signal erred SocketWake.ErrorRaised
                    |> chooseSleeper erred
            | DatagramFate.Reaches receiver ->
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
                // Measured (`udp-transfer.c` L13): a receiver too full to
                // take the datagram raises no error at the sender.
                | DatagramArrival.Dropped, _ -> DatagramDelivered.Dropped receiver, system
                | DatagramArrival.Queued, after ->
                    // Measured (`udp-transfer.c` G5): every arrival is an
                    // edge, datagrams already queued or not.
                    DatagramDelivered.Queued receiver,
                    { system with
                        Machine = UnixMachineState.withDatagramReceiver receiver after system.Machine
                    }
                    |> SocketWake.signal receiver SocketWake.DataArrived
                    |> chooseSleeper receiver

        Ok (delivered, system)
