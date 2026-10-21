namespace WoofWare.PosixKernel

/// Every socket on a machine, by identity, and an index of its UDP sockets by
/// the port of the IPv4 binding each holds, which is what delivering a
/// datagram reads: a real kernel finds a datagram's receiver in a hash of its
/// UDP sockets by port (Linux's `udp_table`, Darwin's `udbinfo`), not by
/// asking every socket.
///
/// The representation is private to this file, so every change to the table
/// goes through `set` or `remove`, which keep the index, and nothing else can
/// change it.
type internal SocketTable =
    private
        {
            All : Map<SocketId, SocketDescription>
            /// The UDP sockets (`SocketTable.receivesDatagrams`) holding an
            /// IPv4 binding, by the binding's port. A port no such socket is
            /// bound to has no key.
            DatagramPorts : Map<uint16, Set<SocketId>>
        }

[<RequireQualifiedAccess>]
module internal SocketTable =

    /// Whether `socket` is a UDP socket, and so has a receive side in
    /// `UnixMachineState.DatagramReceivers`: a datagram socket of an Internet
    /// domain.
    let receivesDatagrams (socket : SocketDescription) : bool =
        match socket.Kind, socket.Domain with
        | SocketKind.Datagram, SocketDomain.Inet
        | SocketKind.Datagram, SocketDomain.Inet6 -> true
        | SocketKind.Datagram, SocketDomain.Unix
        | SocketKind.Stream, _
        | SocketKind.SeqPacket, _ -> false

    /// The port under which the index files `socket`, if it files it.
    let private datagramPort (socket : SocketDescription) : uint16 option =
        if receivesDatagrams socket then
            socket.Ipv4Binding |> Option.map (fun binding -> binding.Endpoint.Port)
        else
            None

    let private unfile (socketId : SocketId) (port : uint16) (index : Map<uint16, Set<SocketId>>) =
        match Map.tryFind port index with
        | Some filed when Set.contains socketId filed ->
            let filed = Set.remove socketId filed

            if Set.isEmpty filed then
                Map.remove port index
            else
                Map.add port filed index
        | Some _
        | None ->
            failwith
                $"SocketTable: socket %O{socketId} is not filed under port %d{port}, where its binding says it is (this is a bug in this library)."

    let private file (socketId : SocketId) (port : uint16) (index : Map<uint16, Set<SocketId>>) =
        let filed = Map.tryFind port index |> Option.defaultValue Set.empty
        Map.add port (Set.add socketId filed) index

    /// A table holding no socket.
    let empty : SocketTable =
        {
            All = Map.empty
            DatagramPorts = Map.empty
        }

    /// Every socket in `table`, by identity.
    let all (table : SocketTable) : Map<SocketId, SocketDescription> = table.All

    /// The socket `socketId` names in `table`, if it names one.
    let tryFind (socketId : SocketId) (table : SocketTable) : SocketDescription option = Map.tryFind socketId table.All

    /// Whether `table` holds a socket `socketId`.
    let containsKey (socketId : SocketId) (table : SocketTable) : bool = Map.containsKey socketId table.All

    /// `table` with `socketId` naming `socket`, whether or not it named a
    /// socket before.
    let set (socketId : SocketId) (socket : SocketDescription) (table : SocketTable) : SocketTable =
        let before = Map.tryFind socketId table.All |> Option.bind datagramPort
        let after = datagramPort socket

        let index =
            if before = after then
                table.DatagramPorts
            else
                let index =
                    match before with
                    | Some port -> unfile socketId port table.DatagramPorts
                    | None -> table.DatagramPorts

                match after with
                | Some port -> file socketId port index
                | None -> index

        {
            All = Map.add socketId socket table.All
            DatagramPorts = index
        }

    /// `table` without `socketId`, which it need not hold.
    let remove (socketId : SocketId) (table : SocketTable) : SocketTable =
        match Map.tryFind socketId table.All with
        | None -> table
        | Some socket ->
            {
                All = Map.remove socketId table.All
                DatagramPorts =
                    match datagramPort socket with
                    | Some port -> unfile socketId port table.DatagramPorts
                    | None -> table.DatagramPorts
            }

    /// The UDP sockets in `table` holding an IPv4 binding at `port`, whatever
    /// its address.
    let datagramSocketsAt (port : uint16) (table : SocketTable) : Set<SocketId> =
        Map.tryFind port table.DatagramPorts |> Option.defaultValue Set.empty

    /// Whether the index is what `table`'s sockets say it should be. Always
    /// true unless this file has a bug: `UnixSystem.checkInvariants` asks.
    let indexFresh (table : SocketTable) : bool =
        let rebuilt =
            (Map.empty, table.All)
            ||> Map.fold (fun index socketId socket ->
                match datagramPort socket with
                | Some port -> file socketId port index
                | None -> index
            )

        rebuilt = table.DatagramPorts
