namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel

/// What stands in the way of a port, on both flavours, held to one reference
/// written from the measured tables: `bind(2)`'s admission, the search for a
/// port to bind (`bind(2)` of port 0, `listen(2)` with no port), the search
/// for a connect's port, Linux's second look at a bound socket's `listen(2)`,
/// and Darwin's dropped SYN. Each is asked of walks of syscalls that leave
/// every kind of holder behind: idle and listening sockets, connected ones,
/// ends whose sockets have closed, ends done with their endpoints, and
/// connections waiting in an accept queue.
///
/// The reference never reads what the kernel holds. It keeps its own record
/// of what each call did, and judges each question by the measured rule
/// alone: the bind matrix (`TestSocketBinding`, `bind-held-endpoint.c`),
/// `docs/probes/ephemeral-search`, `docs/probes/connect-search-holders`,
/// `docs/probes/implicit-self-connect` rows H and Hr, and
/// `docs/probes/refused-connect-port`. Only where the allocator stands is
/// read from the kernel.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPortHolders =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 200

    /// A seed for a walk's own `System.Random`, drawn from the whole range; it
    /// has no meaningful shrink, so it is given no shrinker.
    let private walkSeed : Arbitrary<int> =
        Arb.fromGen (Gen.choose (0, System.Int32.MaxValue))

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private secondLoopback : Ipv4Address = Ipv4Address 0x7F000002u

    let private bindAddresses : Ipv4Address list =
        [ Ipv4Address.loopback ; Ipv4Address.any ; secondLoopback ]

    let private listenerPort (listener : int) : uint16 = 5000us + uint16 listener

    /// Where nothing is ever bound.
    let private closedPort : uint16 = 6000us

    /// Each fixed listener's backlog. A queue is kept short of it, whose
    /// capacity differs by flavour.
    let private backlog : int = 8

    let private flavourName (flavour : SimulatedUnixFlavour) : string =
        match flavour with
        | SimulatedUnixFlavour.Linux -> "Linux"
        | SimulatedUnixFlavour.Darwin -> "Darwin"

    // ------------------------------------------------------------------
    // The reference's own record of the walk
    // ------------------------------------------------------------------

    /// How a socket came by its port: by `bind(2)` (`locked` where it asked
    /// for the port itself), `listen(2)`, or `accept(2)`, which holds the
    /// listener's; or by connect's own implicit bind.
    [<RequireQualifiedAccess>]
    type private How =
        | BindMade of locked : bool
        | ConnectMade

    [<RequireQualifiedAccess>]
    type private State =
        /// No port, never had one.
        | Fresh
        /// Linux: its refused connect gave its port back, and it binds,
        /// listens and connects as a socket with no port, at `address`.
        | GaveBack of address : Ipv4Address
        /// Darwin: its connect was refused, and it holds nothing.
        | DarwinRefused
        | Bound of endpoint : Ipv4Endpoint * how : How
        | Listening of endpoint : Ipv4Endpoint
        | Connected of connection : int * client : bool

    type private WalkSocket =
        {
            Reuse : bool
            State : State
        }

    [<RequireQualifiedAccess>]
    type private EndAt =
        | Open of fd : int
        | Queued of listener : int
        /// Its socket has closed, carrying `SO_REUSEADDR` if `reuse`.
        | Closed of reuse : bool

    type private End =
        {
            Endpoint : Ipv4Endpoint
            How : How
            At : EndAt
            /// Whether the end has made its FIN, by `shutdown(2)` or its
            /// close. Nothing is ever in flight, so a FIN made has arrived.
            FinMade : bool
            /// Whether the peer's FIN had arrived when this end made its own.
            FinPassive : bool
        }

    type private Connection =
        {
            Client : End
            Server : End
        }

    type private Walk =
        {
            Flavour : SimulatedUnixFlavour
            System : UnixSystem<int, string>
            Sockets : Map<int, WalkSocket>
            /// Oldest first, by the order the connects made them.
            Connections : Map<int, Connection>
            NextConnection : int
            /// The fixed listeners' descriptors, and the `SO_REUSEADDR` each
            /// carries.
            Listeners : (int * bool) list
        }

    // ------------------------------------------------------------------
    // What the reference sees in a port's way
    // ------------------------------------------------------------------

    /// One thing the walk has left holding a port, a four-tuple, or both.
    type private Seen =
        {
            /// What it is, for coverage.
            Label : string
            Endpoint : Ipv4Endpoint
            HoldsPort : bool
            /// Whether `bind(2)`, `listen(2)` or `accept(2)` gave it the port.
            BindMade : bool
            Reuse : bool
            Listening : bool
            ConnectionEnd : bool
            /// Its own endpoint and its peer's, for a connection's end.
            Tuple : (Ipv4Endpoint * Ipv4Endpoint) option
        }

    /// Everything the walk has left holding something, but `self`.
    let private seen (walk : Walk) (self : int option) : Seen list =
        let sockets =
            walk.Sockets
            |> Map.toList
            |> List.choose (fun (fd, socket) ->
                if Some fd = self then
                    None
                else

                match socket.State with
                | State.Bound (endpoint, how) ->
                    Some
                        {
                            Label = "idle socket"
                            Endpoint = endpoint
                            HoldsPort = true
                            BindMade =
                                match how with
                                | How.BindMade _ -> true
                                | How.ConnectMade -> false
                            Reuse = socket.Reuse
                            Listening = false
                            ConnectionEnd = false
                            Tuple = None
                        }
                | State.Listening endpoint ->
                    Some
                        {
                            Label = "listener"
                            Endpoint = endpoint
                            HoldsPort = true
                            BindMade = true
                            Reuse = socket.Reuse
                            Listening = true
                            ConnectionEnd = false
                            Tuple = None
                        }
                | State.Fresh
                | State.GaveBack _
                | State.DarwinRefused
                | State.Connected _ -> None
            )

        let listeners =
            walk.Listeners
            |> List.mapi (fun i (_, reuse) ->
                {
                    Label = "listener"
                    Endpoint = loopback (listenerPort i)
                    HoldsPort = true
                    BindMade = true
                    Reuse = reuse
                    Listening = true
                    ConnectionEnd = false
                    Tuple = None
                }
            )

        let ends =
            walk.Connections
            |> Map.toList
            |> List.collect (fun (_, connection) ->
                [ connection.Client, connection.Server ; connection.Server, connection.Client ]
                |> List.map (fun (own, peer) ->
                    // `tcp-shutdown.c` section F: an end whose FIN, made after
                    // the peer's had arrived, has arrived is done with its
                    // endpoint, on Darwin at once and on Linux at once unless
                    // bind(2) chose its port, which it keeps until it closes.
                    let doneWith = own.FinMade && own.FinPassive

                    let bindMade, locked =
                        match own.How with
                        | How.BindMade locked -> true, locked
                        | How.ConnectMade -> false, false

                    let label, holds, reuse =
                        match own.At with
                        | EndAt.Open fd when Some fd = self -> "its own connection", false, false
                        | EndAt.Open fd ->
                            let keeps = walk.Flavour = SimulatedUnixFlavour.Linux && locked

                            (if doneWith then
                                 "connected socket done with its endpoint"
                             else
                                 "connected socket"),
                            not doneWith || keeps,
                            walk.Sockets.[fd].Reuse
                        | EndAt.Queued _ -> "queued end", false, false
                        | EndAt.Closed reuse ->
                            (if doneWith then
                                 "closed end done with its endpoint"
                             else
                                 "closed end"),
                            not doneWith,
                            reuse

                    {
                        Label = label
                        Endpoint = own.Endpoint
                        HoldsPort = holds
                        BindMade = bindMade
                        Reuse = reuse
                        Listening = false
                        ConnectionEnd = true
                        Tuple = Some (own.Endpoint, peer.Endpoint)
                    }
                )
            )

        sockets @ listeners @ ends

    let private overlap (a : Ipv4Endpoint) (b : Ipv4Endpoint) : bool =
        a.Address = Ipv4Address.any
        || b.Address = Ipv4Address.any
        || a.Address = b.Address

    /// The measured bind matrix: Linux refuses a port held at an overlapping
    /// address unless both carry `SO_REUSEADDR` and the holder is not
    /// listening; Darwin unless the candidate carries it and the addresses
    /// differ, or the holder is a connection's end.
    let private bindRefusers
        (flavour : SimulatedUnixFlavour)
        (holders : Seen list)
        (candidate : Ipv4Endpoint)
        (reuse : bool)
        : Seen list
        =
        holders
        |> List.filter (fun holder ->
            holder.HoldsPort
            && holder.Endpoint.Port = candidate.Port
            && overlap holder.Endpoint candidate
            && (
                match flavour with
                | SimulatedUnixFlavour.Linux -> not (holder.Reuse && reuse) || holder.Listening
                | SimulatedUnixFlavour.Darwin ->
                    not reuse
                    || (holder.Endpoint.Address = candidate.Address && not holder.ConnectionEnd)
            )
        )

    /// `docs/probes/ephemeral-search`: a search for a port to bind passes
    /// over a port held at an overlapping address, whatever anyone's flag.
    let private bindSearchRefusers (holders : Seen list) (candidate : Ipv4Endpoint) : Seen list =
        holders
        |> List.filter (fun holder ->
            holder.HoldsPort
            && holder.Endpoint.Port = candidate.Port
            && overlap holder.Endpoint candidate
        )

    /// `docs/probes/ephemeral-search` and `docs/probes/connect-search-holders`:
    /// a connect's search passes over a four-tuple in use, and over a port
    /// held at any address, on Linux only if `bind(2)`, `listen(2)` or
    /// `accept(2)` gave the holder its port, and on Darwin whatever did.
    let private connectSearchRefusers
        (flavour : SimulatedUnixFlavour)
        (holders : Seen list)
        (source : Ipv4Endpoint)
        (destination : Ipv4Endpoint)
        : Seen list
        =
        holders
        |> List.filter (fun holder ->
            let tupleTaken =
                match holder.Tuple with
                | Some (own, peer) -> (own = source && peer = destination) || (own = destination && peer = source)
                | None -> false

            let portTaken =
                holder.HoldsPort
                && holder.Endpoint.Port = source.Port
                && (
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> holder.BindMade
                    | SimulatedUnixFlavour.Darwin -> true
                )

            tupleTaken || portTaken
        )

    /// The ports of the range, from where the allocator stands, wrapping once.
    let private sweepOrder (machine : UnixMachineState) : uint16 list =
        let low, high = machine.EphemeralPortRange
        let width = int high - int low + 1

        let start =
            if machine.NextEphemeralPort < low || machine.NextEphemeralPort > high then
                low
            else
                machine.NextEphemeralPort

        [ 0 .. width - 1 ]
        |> List.map (fun i -> uint16 (int low + (int start - int low + i) % width))

    /// The first port of the sweep no holder stands in the way of, by
    /// `refusers`, counting under `question` what stood in the way of each port
    /// passed over.
    let private search
        (cover : string -> unit)
        (walk : Walk)
        (question : string)
        (refusers : uint16 -> Seen list)
        : uint16 option
        =
        let flavour = flavourName walk.Flavour

        let found =
            sweepOrder walk.System.Machine
            |> List.tryFind (fun port ->
                match refusers port with
                | [] -> true
                | inTheWay ->
                    for holder in inTheWay do
                        cover $"%s{flavour} %s{question}: %s{holder.Label} in the way"

                    false
            )

        match found with
        | Some _ -> cover $"%s{flavour} %s{question} found a port"
        | None -> cover $"%s{flavour} %s{question} found no port"

        found

    // ------------------------------------------------------------------
    // The kernel's side
    // ------------------------------------------------------------------

    let private socketOf (fd : int) (system : UnixSystem<int, string>) : SocketDescription =
        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) -> UnixMachineState.socket socketId system.Machine
        | other -> failwith $"fd %d{fd} is %A{other}, not a socket"

    /// Where the socket behind `fd` reports itself bound.
    let private boundAt (fd : int) (system : UnixSystem<int, string>) : Ipv4Endpoint option =
        (socketOf fd system).Ipv4Binding |> Option.map (fun binding -> binding.Endpoint)

    /// A call's answer, without the system it leaves.
    let private brief<'answer, 'refusal> (result : Result<'answer * UnixSystem<int, string>, 'refusal>) : string =
        match result with
        | Ok (answer, _) -> $"%A{answer}"
        | Error refusal -> $"refused: %A{refusal}"

    let private newSocket (reuse : bool) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        fd, (if reuse then ReuseAddress.set true fd system else system)

    let private systemOn (platform : SimulatedUnixPlatform) (high : uint16) (reuses : bool list) : Walk =
        let system =
            UnixSystem.initial platform
            |> UnixBootImage.withLocalIpv4Addresses
                [ Ipv4Address.loopback ; secondLoopback ]
                UnixSystem.defaultLocalRoutes
            |> UnixBootImage.tryWithEphemeralPortRange (40000us, high)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let listeners, system =
            ((([] : (int * bool) list), system), List.indexed reuses)
            ||> List.fold (fun (listeners, system) (i, reuse) ->
                let fd, system = newSocket reuse system

                let system =
                    match
                        CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (loopback (listenerPort i))) system
                    with
                    | Ok (BindAnswer.Bound _, system) -> system
                    | other -> failwith $"binding listener %d{i}: %A{other}"

                match UnixSocket.tryListen fd backlog system with
                | Ok (ListenAnswer.Listening _, system) -> listeners @ [ fd, reuse ], system
                | other -> failwith $"listener %d{i}: %A{other}"
            )

        {
            Flavour = SimulatedUnixPlatform.flavour platform
            System = system
            Sockets = Map.empty
            Connections = Map.empty
            NextConnection = 0
            Listeners = listeners
        }

    // ------------------------------------------------------------------
    // The walk
    // ------------------------------------------------------------------

    [<RequireQualifiedAccess>]
    type private Target =
        | Listener of listener : int
        | ClosedPort
        /// A socket bound and doing nothing, at this port on 127.0.0.1 or the
        /// wildcard, which nothing listens at.
        | Idle of port : uint16

    [<RequireQualifiedAccess>]
    type private Op =
        | New of reuse : bool
        | SetReuse of fd : int * reuse : bool
        | Bind of fd : int * address : Ipv4Address * port : uint16
        | BindZero of fd : int * address : Ipv4Address
        | Listen of fd : int
        | Connect of fd : int * target : Target
        | Accept of listener : int
        | ShutdownWrite of fd : int
        | Close of fd : int

    let private destinationOf (target : Target) : Ipv4Endpoint =
        match target with
        | Target.Listener listener -> loopback (listenerPort listener)
        | Target.ClosedPort -> loopback closedPort
        | Target.Idle port -> loopback port

    let private queueOf (listener : int) (walk : Walk) : int list =
        walk.Connections
        |> Map.toList
        |> List.choose (fun (id, connection) ->
            match connection.Server.At with
            | EndAt.Queued at when at = listener -> Some id
            | _ -> None
        )

    /// The source a socket already bound connects from.
    let private resolved (endpoint : Ipv4Endpoint) : Ipv4Endpoint =
        if endpoint.Address = Ipv4Address.any then
            loopback endpoint.Port
        else
            endpoint

    let private nextOp (rng : System.Random) (walk : Walk) : Op =
        let pick (list : 'a list) : 'a = list.[rng.Next list.Length]
        let low, high = walk.System.Machine.EphemeralPortRange
        let linux = walk.Flavour = SimulatedUnixFlavour.Linux

        // Bound idle sockets a connect may aim at: where nothing listens at an
        // overlapping address.
        let idleTargets =
            walk.Sockets
            |> Map.toList
            |> List.choose (fun (_, socket) ->
                match socket.State with
                | State.Bound (endpoint, _) when endpoint.Address <> secondLoopback -> Some endpoint.Port
                | _ -> None
            )
            |> List.distinct
            |> List.filter (fun port ->
                walk.Sockets
                |> Map.forall (fun _ socket ->
                    match socket.State with
                    | State.Listening endpoint -> not (endpoint.Port = port && overlap endpoint (loopback port))
                    | _ -> true
                )
            )

        let connects (fd : int) (source : Ipv4Endpoint option) : Op list =
            [
                for listener in 0 .. walk.Listeners.Length - 1 do
                    if List.length (queueOf listener walk) < backlog - 1 then
                        yield Target.Listener listener

                yield Target.ClosedPort

                for port in idleTargets do
                    yield Target.Idle port
            ]
            |> List.filter (fun target ->
                let destination = destinationOf target

                match source with
                | None -> true
                | Some source ->
                    // A source that is its own destination, or a four-tuple
                    // already in use, has no measured answer here.
                    source <> destination
                    && not (
                        seen walk (Some fd)
                        |> List.exists (fun holder -> holder.Tuple = Some (source, destination))
                    )
            )
            |> List.map (fun target -> Op.Connect (fd, target))

        let candidates =
            [
                yield Op.New false
                yield Op.New true

                for KeyValue (fd, socket) in walk.Sockets do
                    let unbound =
                        match socket.State with
                        | State.Fresh -> true
                        | State.GaveBack _ -> linux
                        | _ -> false

                    if unbound then
                        // Half the time at a port something already holds,
                        // so that binds meet holders often.
                        let held =
                            seen walk (Some fd)
                            |> List.filter (fun holder ->
                                holder.HoldsPort && holder.Endpoint.Port >= low && holder.Endpoint.Port <= high
                            )
                            |> List.map (fun holder -> holder.Endpoint.Port)

                        let port =
                            if not (List.isEmpty held) && rng.Next 2 = 0 then
                                pick held
                            else
                                uint16 (rng.Next (int low, int high + 1))

                        yield Op.Bind (fd, pick bindAddresses, port)
                        yield Op.BindZero (fd, pick bindAddresses)
                        yield Op.Listen fd
                        yield! connects fd None

                    match socket.State with
                    | State.Bound (endpoint, _) ->
                        yield Op.Listen fd
                        yield! connects fd (Some (resolved endpoint))
                    | State.Listening _ -> yield Op.Listen fd
                    | State.Connected (id, client) ->
                        let connection = walk.Connections.[id]
                        let own = if client then connection.Client else connection.Server

                        if not own.FinMade then
                            yield Op.ShutdownWrite fd
                    | State.Fresh
                    | State.GaveBack _
                    | State.DarwinRefused -> ()

                    match socket.State with
                    | State.Fresh
                    | State.Bound _
                    | State.Listening _ -> yield Op.SetReuse (fd, not socket.Reuse)
                    | State.GaveBack _ when linux -> yield Op.SetReuse (fd, not socket.Reuse)
                    | _ -> ()

                    yield Op.Close fd

                for listener in 0 .. walk.Listeners.Length - 1 do
                    if not (List.isEmpty (queueOf listener walk)) then
                        yield Op.Accept listener
            ]

        pick candidates

    /// One op, its answer held to the reference's; `cover` counts what stood
    /// in each port's way.
    let private step (cover : string -> unit) (op : Op) (walk : Walk) : Walk =
        let flavour = walk.Flavour
        let name = flavourName flavour
        let system = walk.System

        let fail (what : string) : 'a =
            let sockets =
                system.Machine.Sockets
                |> Map.toList
                |> List.map (fun (id, socket) -> id, socket.Phase, socket.Ipv4Binding, socket.ReuseAddress)

            failwith
                $"%s{name}, %A{op}: %s{what}\n  the walk held %A{walk.Sockets}\n  and %A{walk.Connections}\n  the kernel held %A{sockets}"

        let withSocket (fd : int) (socket : WalkSocket) (system : UnixSystem<int, string>) : Walk =
            { walk with
                System = system
                Sockets = Map.add fd socket walk.Sockets
            }

        let exhausted (what : string) : unit =
            match flavour with
            | SimulatedUnixFlavour.Linux -> ()
            | SimulatedUnixFlavour.Darwin -> cover $"Darwin %s{what}: refused at exhaustion"

        match op with
        | Op.New reuse ->
            let fd, system = newSocket reuse system

            withSocket
                fd
                {
                    Reuse = reuse
                    State = State.Fresh
                }
                system
        | Op.SetReuse (fd, reuse) ->
            withSocket
                fd
                { walk.Sockets.[fd] with
                    Reuse = reuse
                }
                (ReuseAddress.set reuse fd system)
        | Op.Bind (fd, address, port) ->
            let socket = walk.Sockets.[fd]
            let candidate = Ipv4Endpoint.ofParts address port
            let holders = seen walk (Some fd)
            let inTheWay = bindRefusers flavour holders candidate socket.Reuse

            for holder in inTheWay do
                cover $"%s{name} bind: %s{holder.Label} in the way"

            for holder in holders do
                if
                    holder.HoldsPort
                    && holder.Endpoint.Port = port
                    && overlap holder.Endpoint candidate
                    && not (List.contains holder inTheWay)
                then
                    cover $"%s{name} bind: admitted beside %s{holder.Label}"

            match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform candidate) system with
            | Ok (BindAnswer.Bound _, system) when List.isEmpty inTheWay ->
                withSocket
                    fd
                    { socket with
                        State = State.Bound (candidate, How.BindMade true)
                    }
                    system
            | Ok (BindAnswer.Failed UnixError.EADDRINUSE, system) when not (List.isEmpty inTheWay) ->
                withSocket fd socket system
            | other -> fail $"bind answered %s{brief other}; the reference has %A{inTheWay} in the way"
        | Op.BindZero (fd, address) ->
            let socket = walk.Sockets.[fd]
            let holders = seen walk (Some fd)

            let expected =
                search
                    cover
                    walk
                    "bind search"
                    (fun port -> bindSearchRefusers holders (Ipv4Endpoint.ofParts address port))

            match
                CopyIn.bind
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet system.Machine.UnixPlatform (Ipv4Endpoint.ofParts address 0us))
                    system,
                expected
            with
            | Ok (BindAnswer.Bound (SocketAddress.Inet bound), system), Some port when
                bound = Ipv4Endpoint.ofParts address port
                ->
                withSocket
                    fd
                    { socket with
                        State = State.Bound (bound, How.BindMade false)
                    }
                    system
            | Ok (BindAnswer.Failed UnixError.EADDRINUSE, system), None when flavour = SimulatedUnixFlavour.Linux ->
                withSocket fd socket system
            | Error (BindRefusal.EphemeralPortsExhausted _), None when flavour = SimulatedUnixFlavour.Darwin ->
                exhausted "bind search"
                walk
            | other, _ -> fail $"bind of port 0 answered %s{brief other}; the reference takes %A{expected}"
        | Op.Listen fd ->
            let socket = walk.Sockets.[fd]
            let holders = seen walk (Some fd)

            let searchAt (address : Ipv4Address) : Walk =
                let expected =
                    search
                        cover
                        walk
                        "listen search"
                        (fun port -> bindSearchRefusers holders (Ipv4Endpoint.ofParts address port))

                match UnixSocket.tryListen fd backlog system, expected with
                | Ok (ListenAnswer.Listening (SocketAddress.Inet bound), system), Some port when
                    bound = Ipv4Endpoint.ofParts address port
                    ->
                    withSocket
                        fd
                        { socket with
                            State = State.Listening bound
                        }
                        system
                | Ok (ListenAnswer.Failed UnixError.EADDRINUSE, system), None when flavour = SimulatedUnixFlavour.Linux ->
                    withSocket fd socket system
                | Error (ListenRefusal.EphemeralPortsExhausted _), None when flavour = SimulatedUnixFlavour.Darwin ->
                    exhausted "listen search"
                    walk
                | other, _ -> fail $"listen answered %s{brief other}; the reference takes %A{expected}"

            match socket.State with
            | State.Fresh -> searchAt Ipv4Address.any
            | State.GaveBack address -> searchAt address
            | State.Bound (endpoint, _) ->
                // Linux's listen asks bind(2)'s question again; Darwin's asks
                // nothing of a socket with a port.
                let inTheWay =
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> bindRefusers flavour holders endpoint socket.Reuse
                    | SimulatedUnixFlavour.Darwin -> []

                for holder in inTheWay do
                    cover $"%s{name} listen: %s{holder.Label} in the way"

                match UnixSocket.tryListen fd backlog system with
                | Ok (ListenAnswer.Listening _, system) when List.isEmpty inTheWay ->
                    withSocket
                        fd
                        { socket with
                            State = State.Listening endpoint
                        }
                        system
                | Ok (ListenAnswer.Failed UnixError.EADDRINUSE, system) when not (List.isEmpty inTheWay) ->
                    withSocket fd socket system
                | other -> fail $"listen answered %s{brief other}; the reference has %A{inTheWay} in the way"
            | State.Listening _ ->
                match UnixSocket.tryListen fd backlog system with
                | Ok (ListenAnswer.Listening _, system) -> withSocket fd socket system
                | other -> fail $"a listener's listen answered %s{brief other}"
            | other -> fail $"listen generated on a socket in %A{other}"
        | Op.Connect (fd, target) ->
            let socket = walk.Sockets.[fd]
            let holders = seen walk (Some fd)
            let destination = destinationOf target

            let listening =
                match target with
                | Target.Listener _ -> true
                | Target.ClosedPort
                | Target.Idle _ -> false

            // Darwin drops a SYN aimed where nothing listens and a socket is
            // bound idle at an overlapping address, before any port is chosen.
            let droppedBy =
                match flavour, listening with
                | SimulatedUnixFlavour.Darwin, false ->
                    holders
                    |> List.filter (fun holder ->
                        holder.HoldsPort
                        && not holder.Listening
                        && not holder.ConnectionEnd
                        && holder.Endpoint.Port = destination.Port
                        && overlap holder.Endpoint destination
                    )
                | _ -> []

            let answer =
                CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet system.Machine.UnixPlatform destination) system

            if not (List.isEmpty droppedBy) then
                for holder in droppedBy do
                    cover $"%s{name} SYN dropped by %s{holder.Label}"

                match answer with
                | Error (ConnectRefusal.DarwinSynDropped _) -> walk
                | other -> fail $"connect answered %s{brief other}; the reference drops the SYN"
            else

            // Where the connect goes from, and how it came by the port: `None`
            // for a search that found nothing.
            let source : (Ipv4Endpoint * How) option =
                let searchFrom (address : Ipv4Address) =
                    let address =
                        if address = Ipv4Address.any then
                            Ipv4Address.loopback
                        else
                            address

                    let expected =
                        search
                            cover
                            walk
                            "connect search"
                            (fun port ->
                                connectSearchRefusers flavour holders (Ipv4Endpoint.ofParts address port) destination
                            )

                    match expected with
                    | Some port ->
                        for holder in holders do
                            if holder.HoldsPort && holder.Endpoint.Port = port then
                                cover $"%s{name} connect search: shared %s{holder.Label}'s port"

                        Some (Ipv4Endpoint.ofParts address port, How.ConnectMade)
                    | None -> None

                match socket.State with
                | State.Fresh -> searchFrom Ipv4Address.any
                | State.GaveBack address -> searchFrom address
                | State.Bound (endpoint, how) -> Some (resolved endpoint, how)
                | other -> fail $"connect generated on a socket in %A{other}"

            match source with
            | None ->
                match answer with
                | Ok (SyscallAnswer.Failed UnixError.EADDRNOTAVAIL, system) when flavour = SimulatedUnixFlavour.Linux ->
                    withSocket fd socket system
                | Error (ConnectRefusal.EphemeralPortsExhausted _) when flavour = SimulatedUnixFlavour.Darwin ->
                    exhausted "connect search"
                    walk
                | other -> fail $"connect answered %s{brief other}; the reference finds no port"
            | Some (source, how) ->

            if listening then
                let listener =
                    match target with
                    | Target.Listener listener -> listener
                    | _ -> fail "a listening target that is not a listener"

                match answer with
                | Ok (SyscallAnswer.Completed 0L, system) when boundAt fd system = Some source ->
                    let id = walk.NextConnection

                    let connection =
                        {
                            Client =
                                {
                                    Endpoint = source
                                    How = how
                                    At = EndAt.Open fd
                                    FinMade = false
                                    FinPassive = false
                                }
                            Server =
                                {
                                    Endpoint = destination
                                    How = How.BindMade false
                                    At = EndAt.Queued listener
                                    FinMade = false
                                    FinPassive = false
                                }
                        }

                    { walk with
                        System = system
                        Sockets =
                            Map.add
                                fd
                                { socket with
                                    State = State.Connected (id, true)
                                }
                                walk.Sockets
                        Connections = Map.add id connection walk.Connections
                        NextConnection = id + 1
                    }
                | other -> fail $"connect answered %s{brief other}; the reference connects from %A{source}"
            else

            match answer with
            | Ok (SyscallAnswer.Failed UnixError.ECONNREFUSED, system) when
                (boundAt fd system |> Option.map (fun bound -> bound.Port)) = Some source.Port
                ->
                // `docs/probes/refused-connect-port`: Linux keeps a port
                // bind(2) chose, reverting the address to the one it bound,
                // and gives any other back, keeping the address bind(2) gave;
                // Darwin gives every port back, and the socket is done.
                let state =
                    match flavour, socket.State, how with
                    | SimulatedUnixFlavour.Darwin, _, _ -> State.DarwinRefused
                    | SimulatedUnixFlavour.Linux, State.Bound (endpoint, How.BindMade true), _ ->
                        State.Bound (endpoint, How.BindMade true)
                    | SimulatedUnixFlavour.Linux, State.Bound (endpoint, _), _ -> State.GaveBack endpoint.Address
                    | SimulatedUnixFlavour.Linux, State.GaveBack address, _ -> State.GaveBack address
                    | SimulatedUnixFlavour.Linux, _, _ -> State.GaveBack Ipv4Address.any

                withSocket
                    fd
                    { socket with
                        State = state
                    }
                    system
            | other -> fail $"connect answered %s{brief other}; the reference is refused from %A{source}"
        | Op.Accept listener ->
            let id = List.head (queueOf listener walk)
            let listenerFd, reuse = walk.Listeners.[listener]

            match UnixConnection.tryAccept 0 listenerFd UserBuffer.Mapped 16u system with
            | Ok (AcceptOutcome.Accepted (accepted, _, _), system) ->
                let connection = walk.Connections.[id]

                { walk with
                    System = system
                    Sockets =
                        Map.add
                            accepted
                            {
                                Reuse = reuse
                                State = State.Connected (id, false)
                            }
                            walk.Sockets
                    Connections =
                        Map.add
                            id
                            { connection with
                                Server =
                                    { connection.Server with
                                        At = EndAt.Open accepted
                                    }
                            }
                            walk.Connections
                }
            | other -> fail $"accept answered %s{brief other}"
        | Op.ShutdownWrite fd ->
            match walk.Sockets.[fd].State with
            | State.Connected (id, client) ->
                let connection = walk.Connections.[id]

                let finish (own : End) (peer : End) : End =
                    { own with
                        FinMade = true
                        FinPassive = peer.FinMade
                    }

                let connection =
                    if client then
                        { connection with
                            Client = finish connection.Client connection.Server
                        }
                    else
                        { connection with
                            Server = finish connection.Server connection.Client
                        }

                match UnixConnection.tryShutdown fd 1 system with
                | Ok (ShutdownAnswer.Shut, system) ->
                    { walk with
                        System = system
                        Connections = Map.add id connection walk.Connections
                    }
                | other -> fail $"shutdown answered %s{brief other}"
            | other -> fail $"shutdown generated on a socket in %A{other}"
        | Op.Close fd ->
            let socket = walk.Sockets.[fd]

            let connections =
                match socket.State with
                | State.Connected (id, client) ->
                    let connection = walk.Connections.[id]

                    let close (own : End) (peer : End) : End =
                        { own with
                            At = EndAt.Closed socket.Reuse
                            FinMade = true
                            FinPassive = if own.FinMade then own.FinPassive else peer.FinMade
                        }

                    let connection =
                        if client then
                            { connection with
                                Client = close connection.Client connection.Server
                            }
                        else
                            { connection with
                                Server = close connection.Server connection.Client
                            }

                    // A connection is forgotten once neither end has a socket
                    // or a place in a queue.
                    match connection.Client.At, connection.Server.At with
                    | EndAt.Closed _, EndAt.Closed _ -> Map.remove id walk.Connections
                    | _ -> Map.add id connection walk.Connections
                | _ -> walk.Connections

            match UnixDescriptor.tryClose fd system with
            | Ok (SyscallAnswer.Completed 0L, system) ->
                { walk with
                    System = system
                    Sockets = Map.remove fd walk.Sockets
                    Connections = connections
                }
            | other -> fail $"close answered %s{brief other}"

    /// `op`, checked, and the kernel's invariants after it.
    let private checkedStep (cover : string -> unit) (op : Op) (walk : Walk) : Walk =
        let walk = step cover op walk

        match UnixSystem.checkInvariants walk.System with
        | [] -> walk
        | defects -> failwith $"after %A{op}: %A{defects}"

    /// A new socket, and its descriptor.
    let private fresh (cover : string -> unit) (reuse : bool) (walk : Walk) : int * Walk =
        let after = checkedStep cover (Op.New reuse) walk

        let fd =
            after.Sockets
            |> Map.toSeq
            |> Seq.map fst
            |> Seq.find (fun fd -> not (walk.Sockets.ContainsKey fd))

        fd, after

    /// Each opening is a fixed start that reaches a holder a walk rarely
    /// leaves in place long enough to meet: two sockets bound at one port; two
    /// sockets carrying `SO_REUSEADDR` at one endpoint, one of which then
    /// listens, or gives the flag up, before the other listens; and a socket
    /// `bind(2)` gave its port, done with its connection, met by a bind.
    let private opening (cover : string -> unit) (rng : System.Random) (walk : Walk) : Walk =
        let pick (list : 'a list) : 'a = list.[rng.Next list.Length]
        let low, _ = walk.System.Machine.EphemeralPortRange

        let isBound (fd : int) (walk : Walk) : bool =
            match walk.Sockets.[fd].State with
            | State.Bound _ -> true
            | _ -> false

        match rng.Next 4 with
        | 0 -> walk
        | 1 ->
            let first, walk = fresh cover (rng.Next 2 = 0) walk
            let walk = checkedStep cover (Op.Bind (first, pick bindAddresses, low)) walk
            let second, walk = fresh cover (rng.Next 2 = 0) walk
            checkedStep cover (Op.Bind (second, pick bindAddresses, low)) walk
        | 2 ->
            let first, walk = fresh cover true walk
            let walk = checkedStep cover (Op.Bind (first, Ipv4Address.loopback, low)) walk
            let second, walk = fresh cover true walk
            let walk = checkedStep cover (Op.Bind (second, Ipv4Address.loopback, low)) walk

            let walk =
                if rng.Next 2 = 0 then
                    checkedStep cover (Op.Listen first) walk
                else
                    checkedStep cover (Op.SetReuse (first, false)) walk

            checkedStep cover (Op.Listen second) walk
        | _ ->
            let client, walk = fresh cover (rng.Next 2 = 0) walk
            let walk = checkedStep cover (Op.Bind (client, Ipv4Address.loopback, low)) walk

            if not (isBound client walk) then
                walk
            else

            let walk = checkedStep cover (Op.Connect (client, Target.Listener 0)) walk
            let before = walk
            let walk = checkedStep cover (Op.Accept 0) walk

            let server =
                walk.Sockets
                |> Map.toSeq
                |> Seq.map fst
                |> Seq.find (fun fd -> not (before.Sockets.ContainsKey fd))

            let walk = checkedStep cover (Op.ShutdownWrite server) walk
            let walk = checkedStep cover (Op.ShutdownWrite client) walk
            let other, walk = fresh cover (rng.Next 2 = 0) walk
            checkedStep cover (Op.Bind (other, pick bindAddresses, low)) walk

    /// Every port rule, on both flavours, agrees with the reference along a
    /// random walk; and the walks reach each kind of holder standing in each
    /// question's way.
    [<Test>]
    let ``every port rule agrees with the reference written from the measured tables`` () : unit =
        let property (cover : string -> unit) (seed : int) : bool =
            let rng = System.Random seed

            for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
                let initial =
                    systemOn platform (40000us + uint16 (1 + rng.Next 3)) [ rng.Next 2 = 0 ; rng.Next 2 = 0 ]
                    |> opening cover rng

                (initial, [ 1 .. 10 + rng.Next 40 ])
                ||> List.fold (fun walk _ -> checkedStep cover (nextOp rng walk) walk)
                |> ignore<Walk>

            true

        let coverage = CoverageSample.check propertyConfig walkSeed property

        let floors =
            [
                for flavour in [ "Linux" ; "Darwin" ] do
                    for question in [ "bind" ; "bind search" ; "listen search" ; "connect search" ] do
                        for label in [ "idle socket" ; "listener" ; "connected socket" ; "closed end" ] do
                            yield $"%s{flavour} %s{question}: %s{label} in the way"

                    // A four-tuple alone stands in a connect's way.
                    yield $"%s{flavour} connect search: queued end in the way"
                    yield $"%s{flavour} connect search: closed end done with its endpoint in the way"
                    yield $"%s{flavour} connect search: connected socket done with its endpoint in the way"

                    for search in [ "bind search" ; "listen search" ; "connect search" ] do
                        yield $"%s{flavour} %s{search} found no port"

                // Linux shares a port connect's own implicit bind took.
                yield "Linux connect search: shared connected socket's port"
                yield "Linux connect search: shared closed end's port"
                // Linux asks bind's question again at listen.
                yield "Linux listen: listener in the way"
                yield "Linux listen: idle socket in the way"
                // Linux keeps a port bind(2) chose until the socket closes.
                yield "Linux bind: connected socket done with its endpoint in the way"
                yield "Darwin SYN dropped by idle socket"
            ]

        let missing = floors |> List.filter (fun label -> coverage.Count label < 10)

        if not (List.isEmpty missing) then
            failwith $"the fixed sample reached these fewer than 10 times: %A{missing}"
