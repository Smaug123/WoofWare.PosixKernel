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
/// ends whose sockets have closed, ends done with their endpoints,
/// connections waiting in an accept queue, and ends in TIME_WAIT once both
/// their connection's sockets have closed, as the clock moves past the
/// delays and windows that decide them.
///
/// The reference never reads what the kernel holds. It keeps its own record
/// of what each call did, and judges each question by the measured rule
/// alone: the bind matrix (`TestSocketBinding`, `bind-held-endpoint.c`),
/// `docs/probes/ephemeral-search`, `docs/probes/connect-search-holders`,
/// `docs/probes/implicit-self-connect` rows H and Hr,
/// `docs/probes/refused-connect-port`, and `docs/probes/time-wait`. Only
/// where the allocator stands, and the clock, are read from the kernel.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPortHolders =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 400

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
            /// When both FINs had been made, and so had arrived.
            ExchangedAt : int64 option
        }

    /// An end in TIME_WAIT, its connection's sockets both closed.
    type private TimeWait =
        {
            Endpoint : Ipv4Endpoint
            Peer : Ipv4Endpoint
            How : How
            Reuse : bool
            EnteredAt : int64
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
            TimeWaits : TimeWait list
        }

    /// The kernel clock: when time passes is the client's to say, so the walk
    /// reads it.
    let private now (walk : Walk) : int64 =
        UnixSystem.nanosecondsSinceBoot walk.System

    /// `docs/probes/time-wait`, row W: Linux's TIME_WAIT held its port 60.2 s,
    /// and Darwin's 30.1 s at an msl of 15 s.
    let private window (flavour : SimulatedUnixFlavour) : int64 =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 60_000_000_000L
        | SimulatedUnixFlavour.Darwin -> 30_000_000_000L

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
            /// When it entered TIME_WAIT, for an end in TIME_WAIT.
            TimeWaitSince : int64 option
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
                            TimeWaitSince = None
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
                            TimeWaitSince = None
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
                    TimeWaitSince = None
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
                        TimeWaitSince = None
                    }
                )
            )

        let timeWaits =
            walk.TimeWaits
            |> List.map (fun timeWait ->
                {
                    Label = "time-wait end"
                    Endpoint = timeWait.Endpoint
                    HoldsPort = true
                    BindMade =
                        match timeWait.How with
                        | How.BindMade _ -> true
                        | How.ConnectMade -> false
                    Reuse = timeWait.Reuse
                    Listening = false
                    ConnectionEnd = true
                    Tuple = Some (timeWait.Endpoint, timeWait.Peer)
                    TimeWaitSince = Some timeWait.EnteredAt
                }
            )

        sockets @ listeners @ ends @ timeWaits

    /// Whether a question's answer is decided by what stands in its way.
    [<RequireQualifiedAccess>]
    type private Judged =
        | Clear
        /// Something stands in the way: what `labels` name.
        | InTheWay of labels : string list
        /// Only an end in TIME_WAIT past the window it was measured to last,
        /// or one about to be taken over at an unmeasured instant, would, as
        /// `labels` say.
        | Unknown of labels : string list

    /// What `refusers`, the holders a rule finds in the way as though each
    /// held its port, amount to once time is counted: an end in TIME_WAIT
    /// past its window may have gone.
    let private judged (walk : Walk) (refusers : Seen list) : Judged =
        let outlived (holder : Seen) : bool =
            match holder.TimeWaitSince with
            | Some since -> now walk - since >= window walk.Flavour
            | None -> false

        match refusers |> List.filter (outlived >> not), refusers with
        | _ :: _ as inTheWay, _ -> Judged.InTheWay (inTheWay |> List.map (fun holder -> holder.Label))
        | [], _ :: _ -> Judged.Unknown (refusers |> List.map (fun holder -> $"%s{holder.Label} outlived its window"))
        | [], [] -> Judged.Clear

    /// Every holder's judgement taken together: in the way if any is, else
    /// unknown if any is, else clear.
    let private together (verdicts : Judged list) : Judged =
        match
            verdicts
            |> List.collect (fun verdict ->
                match verdict with
                | Judged.InTheWay labels -> labels
                | _ -> []
            )
        with
        | _ :: _ as labels -> Judged.InTheWay labels
        | [] ->

        match
            verdicts
            |> List.collect (fun verdict ->
                match verdict with
                | Judged.Unknown labels -> labels
                | _ -> []
            )
        with
        | _ :: _ as labels -> Judged.Unknown labels
        | [] -> Judged.Clear

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
    /// `accept(2)` gave the holder its port, and on Darwin whatever did. An
    /// end in TIME_WAIT on the four-tuple stands in the way of the source's
    /// end alone, its peer's being ended by the connect; and Linux's search
    /// takes one over from 1.01 s after it entered TIME_WAIT, and not by 0.99
    /// s, unless it entered in the first second of uptime (`docs/probes/time-wait`,
    /// tw-reuse.c and tw-boot.c).
    let private connectSearchStanding
        (walk : Walk)
        (holders : Seen list)
        (source : Ipv4Endpoint)
        (destination : Ipv4Endpoint)
        : Judged
        =
        let portTaken (holder : Seen) : bool =
            holder.HoldsPort
            && holder.Endpoint.Port = source.Port
            && (
                match walk.Flavour with
                | SimulatedUnixFlavour.Linux -> holder.BindMade
                | SimulatedUnixFlavour.Darwin -> true
            )

        let refusers =
            holders
            |> List.filter (fun holder ->
                let tupleTaken =
                    match holder.Tuple, holder.TimeWaitSince with
                    | Some (own, peer), None ->
                        (own = source && peer = destination) || (own = destination && peer = source)
                    | Some (own, peer), Some _ -> own = source && peer = destination
                    | None, _ -> false

                portTaken holder || tupleTaken
            )

        // Linux's takeover of a TIME_WAIT four-tuple, where nothing else is in
        // the way.
        let takeover =
            refusers
            |> List.map (fun holder ->
                match walk.Flavour, holder.TimeWaitSince with
                | SimulatedUnixFlavour.Linux, Some since when not (portTaken holder) ->
                    let elapsed = now walk - since

                    if elapsed >= window walk.Flavour then
                        Judged.Unknown [ "time-wait end outlived its window" ]
                    elif since < 1_000_000_000L then
                        Judged.InTheWay [ "time-wait end" ]
                    elif elapsed <= 990_000_000L then
                        Judged.InTheWay [ "time-wait end" ]
                    elif elapsed >= 1_010_000_000L then
                        Judged.Clear
                    else
                        Judged.Unknown [ "time-wait end near the reuse delay" ]
                | _ -> judged walk [ holder ]
            )

        together takeover

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

    /// What a search finds.
    [<RequireQualifiedAccess>]
    type private Found =
        | Port of port : uint16
        | Exhausted
        /// The first port nothing is known to stand in the way of may be
        /// taken: the kernel refuses to say.
        | Unknown

    /// The first port of the sweep nothing stands in the way of, by
    /// `standingAt`, counting under `question` what stood in the way of each
    /// port passed over.
    let private search
        (cover : string -> unit)
        (walk : Walk)
        (question : string)
        (judgedAt : uint16 -> Judged)
        : Found
        =
        let flavour = flavourName walk.Flavour

        let rec sweep (ports : uint16 list) : Found =
            match ports with
            | [] -> Found.Exhausted
            | port :: rest ->
                match judgedAt port with
                | Judged.Clear -> Found.Port port
                | Judged.InTheWay labels ->
                    for label in labels do
                        cover $"%s{flavour} %s{question}: %s{label} in the way"

                    sweep rest
                | Judged.Unknown labels ->
                    for label in labels do
                        cover $"%s{flavour} %s{question}: %s{label}"

                    Found.Unknown

        let found = sweep (sweepOrder (Kernel.machine walk.System))

        match found with
        | Found.Port _ -> cover $"%s{flavour} %s{question} found a port"
        | Found.Exhausted -> cover $"%s{flavour} %s{question} found no port"
        | Found.Unknown -> ()

        found

    // ------------------------------------------------------------------
    // The kernel's side
    // ------------------------------------------------------------------

    let private socketOf (fd : int) (system : UnixSystem<int, string>) : SocketDescription =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) -> UnixMachineState.socket socketId (Kernel.machine system)
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

                match UnixSocket.tryListen (Callers.leader system) fd backlog system with
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
            TimeWaits = []
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
        /// Let this many milliseconds pass.
        | Advance of milliseconds : int64

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
        let low, high = UnixSystem.ephemeralPortRange walk.System
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
                        |> List.exists (fun holder ->
                            holder.TimeWaitSince.IsNone && holder.Tuple = Some (source, destination)
                        )
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

                // Time passes, across the delays and windows that decide an
                // end in TIME_WAIT: Linux's reuse delay of a second, and the
                // windows of 30 s (Darwin) and 60 s (Linux).
                for _ in 1..2 do
                    yield Op.Advance (pick [ 500L ; 1_000L ; 1_020L ; 2_000L ; 31_000L ; 61_000L ])
            ]

        pick candidates

    /// What a connect does about an end in TIME_WAIT on its four-tuple.
    [<RequireQualifiedAccess>]
    type private OverTimeWait =
        /// It goes ahead, leaving these ends in TIME_WAIT.
        | Proceeds of timeWaits : TimeWait list
        | AddressInUse
        /// The kernel refuses to say.
        | Refused

    /// `connection`, stamped with the walk's clock if both its FINs have now
    /// been made, and so have arrived, for the first time.
    let private exchanged (walk : Walk) (connection : Connection) : Connection =
        match connection.ExchangedAt with
        | None when connection.Client.FinMade && connection.Server.FinMade ->
            { connection with
                ExchangedAt = Some (now walk)
            }
        | _ -> connection

    /// One op, its answer held to the reference's; `cover` counts what stood
    /// in each port's way.
    let private step (cover : string -> unit) (op : Op) (walk : Walk) : Walk =
        let flavour = walk.Flavour
        let name = flavourName flavour
        let system = walk.System

        let fail (what : string) : 'a =
            let sockets =
                (Kernel.machine system).Sockets
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
            let refusers = bindRefusers flavour holders candidate socket.Reuse
            let verdict = judged walk refusers

            match verdict with
            | Judged.InTheWay labels ->
                for label in labels do
                    cover $"%s{name} bind: %s{label} in the way"
            | Judged.Unknown labels ->
                for label in labels do
                    cover $"%s{name} bind: %s{label}"
            | Judged.Clear -> ()

            for holder in holders do
                if
                    holder.HoldsPort
                    && holder.Endpoint.Port = port
                    && overlap holder.Endpoint candidate
                    && not (List.contains holder refusers)
                then
                    cover $"%s{name} bind: admitted beside %s{holder.Label}"

            match
                CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) candidate) system,
                verdict
            with
            | Ok (BindAnswer.Bound _, system), Judged.Clear ->
                withSocket
                    fd
                    { socket with
                        State = State.Bound (candidate, How.BindMade true)
                    }
                    system
            | Ok (BindAnswer.Failed UnixError.EADDRINUSE, system), Judged.InTheWay _ -> withSocket fd socket system
            | Error (BindRefusal.TimeWait _), Judged.Unknown _ -> walk
            | other, _ -> fail $"bind answered %s{brief other}; the reference has %A{verdict}"
        | Op.BindZero (fd, address) ->
            let socket = walk.Sockets.[fd]
            let holders = seen walk (Some fd)

            let expected =
                search
                    cover
                    walk
                    "bind search"
                    (fun port -> bindSearchRefusers holders (Ipv4Endpoint.ofParts address port) |> judged walk)

            match
                CopyIn.bind
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet (UnixSystem.platform system) (Ipv4Endpoint.ofParts address 0us))
                    system,
                expected
            with
            | Ok (BindAnswer.Bound (SocketAddress.Inet bound), system), Found.Port port when
                bound = Ipv4Endpoint.ofParts address port
                ->
                withSocket
                    fd
                    { socket with
                        State = State.Bound (bound, How.BindMade false)
                    }
                    system
            | Ok (BindAnswer.Failed UnixError.EADDRINUSE, system), Found.Exhausted when
                flavour = SimulatedUnixFlavour.Linux
                ->
                withSocket fd socket system
            | Error (BindRefusal.EphemeralPortsExhausted _), Found.Exhausted when flavour = SimulatedUnixFlavour.Darwin ->
                exhausted "bind search"
                walk
            | Error (BindRefusal.TimeWait _), Found.Unknown -> walk
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
                        (fun port -> bindSearchRefusers holders (Ipv4Endpoint.ofParts address port) |> judged walk)

                match UnixSocket.tryListen (Callers.leader system) fd backlog system, expected with
                | Ok (ListenAnswer.Listening (SocketAddress.Inet bound), system), Found.Port port when
                    bound = Ipv4Endpoint.ofParts address port
                    ->
                    withSocket
                        fd
                        { socket with
                            State = State.Listening bound
                        }
                        system
                | Ok (ListenAnswer.Failed UnixError.EADDRINUSE, system), Found.Exhausted when
                    flavour = SimulatedUnixFlavour.Linux
                    ->
                    withSocket fd socket system
                | Error (ListenRefusal.EphemeralPortsExhausted _), Found.Exhausted when
                    flavour = SimulatedUnixFlavour.Darwin
                    ->
                    exhausted "listen search"
                    walk
                | Error (ListenRefusal.TimeWait _), Found.Unknown -> walk
                | other, _ -> fail $"listen answered %s{brief other}; the reference takes %A{expected}"

            match socket.State with
            | State.Fresh -> searchAt Ipv4Address.any
            | State.GaveBack address -> searchAt address
            | State.Bound (endpoint, _) ->
                // Linux's listen asks bind(2)'s question again; Darwin's asks
                // nothing of a socket with a port.
                let verdict =
                    match flavour with
                    | SimulatedUnixFlavour.Linux -> bindRefusers flavour holders endpoint socket.Reuse |> judged walk
                    | SimulatedUnixFlavour.Darwin -> Judged.Clear

                match verdict with
                | Judged.InTheWay labels ->
                    for label in labels do
                        cover $"%s{name} listen: %s{label} in the way"
                | Judged.Unknown labels ->
                    for label in labels do
                        cover $"%s{name} listen: %s{label}"
                | Judged.Clear -> ()

                match UnixSocket.tryListen (Callers.leader system) fd backlog system, verdict with
                | Ok (ListenAnswer.Listening _, system), Judged.Clear ->
                    withSocket
                        fd
                        { socket with
                            State = State.Listening endpoint
                        }
                        system
                | Ok (ListenAnswer.Failed UnixError.EADDRINUSE, system), Judged.InTheWay _ ->
                    withSocket fd socket system
                | Error (ListenRefusal.TimeWait _), Judged.Unknown _ -> walk
                | other, _ -> fail $"listen answered %s{brief other}; the reference has %A{verdict}"
            | State.Listening _ ->
                match UnixSocket.tryListen (Callers.leader system) fd backlog system with
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
                CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) destination) system

            if not (List.isEmpty droppedBy) then
                for holder in droppedBy do
                    cover $"%s{name} SYN dropped by %s{holder.Label}"

                match answer with
                | Error (ConnectRefusal.DarwinSynDropped _) -> walk
                | other -> fail $"connect answered %s{brief other}; the reference drops the SYN"
            else

            // Where the connect goes from, and how it came by the port: by a
            // search, or by `bind(2)`.
            let searchFrom (address : Ipv4Address) : bool * Found * How =
                let address =
                    if address = Ipv4Address.any then
                        Ipv4Address.loopback
                    else
                        address

                let found =
                    search
                        cover
                        walk
                        "connect search"
                        (fun port -> connectSearchStanding walk holders (Ipv4Endpoint.ofParts address port) destination)

                match found with
                | Found.Port port ->
                    for holder in holders do
                        if holder.HoldsPort && holder.Endpoint.Port = port then
                            cover $"%s{name} connect search: shared %s{holder.Label}'s port"
                | Found.Exhausted
                | Found.Unknown -> ()

                true, found, How.ConnectMade

            let searched, found, how =
                match socket.State with
                | State.Fresh -> searchFrom Ipv4Address.any
                | State.GaveBack address -> searchFrom address
                | State.Bound (endpoint, how) -> false, Found.Port (resolved endpoint).Port, how
                | other -> fail $"connect generated on a socket in %A{other}"

            let sourceAddress =
                match socket.State with
                | State.Bound (endpoint, _) -> (resolved endpoint).Address
                | State.GaveBack address when address <> Ipv4Address.any -> address
                | _ -> Ipv4Address.loopback

            match found with
            | Found.Exhausted ->
                match answer with
                | Ok (SyscallAnswer.Failed UnixError.EADDRNOTAVAIL, system) when flavour = SimulatedUnixFlavour.Linux ->
                    withSocket fd socket system
                | Error (ConnectRefusal.EphemeralPortsExhausted _) when flavour = SimulatedUnixFlavour.Darwin ->
                    exhausted "connect search"
                    walk
                | other -> fail $"connect answered %s{brief other}; the reference finds no port"
            | Found.Unknown ->
                match answer with
                | Error (ConnectRefusal.TimeWait _) -> walk
                | other ->
                    fail
                        $"connect answered %s{brief other}; the reference's search meets an end in TIME_WAIT it cannot judge"
            | Found.Port port ->

            let source = Ipv4Endpoint.ofParts sourceAddress port

            // `docs/probes/time-wait`, tw-reuse.c: an end in TIME_WAIT at the
            // destination, towards the source, ends, and the connect goes
            // ahead (rows Q and Y); one at the source, towards the
            // destination, Linux's search has taken over by now, and a socket
            // bound there meets it: Linux takes it over unless it entered
            // TIME_WAIT in the first second of uptime, and Darwin answers
            // EADDRINUSE (rows E, V and Z), unless it outlived its window.
            let reverse, others =
                walk.TimeWaits
                |> List.partition (fun timeWait -> timeWait.Endpoint = destination && timeWait.Peer = source)

            if not (List.isEmpty reverse) then
                cover $"%s{name} connect: ended a time-wait end at the destination"

            let over =
                match
                    others
                    |> List.tryFind (fun timeWait -> timeWait.Endpoint = source && timeWait.Peer = destination)
                with
                | None -> OverTimeWait.Proceeds others
                | Some timeWait when searched ->
                    cover $"%s{name} connect search: took over a time-wait end's four-tuple"
                    OverTimeWait.Proceeds (List.filter ((<>) timeWait) others)
                | Some timeWait when now walk - timeWait.EnteredAt >= window flavour ->
                    cover $"%s{name} connect: time-wait end outlived its window"
                    OverTimeWait.Refused
                | Some timeWait ->
                    match flavour with
                    | SimulatedUnixFlavour.Darwin ->
                        cover "Darwin connect: EADDRINUSE over a time-wait end's four-tuple"
                        OverTimeWait.AddressInUse
                    | SimulatedUnixFlavour.Linux when timeWait.EnteredAt < 1_000_000_000L ->
                        cover "Linux connect: time-wait end from the first second"
                        OverTimeWait.Refused
                    | SimulatedUnixFlavour.Linux ->
                        cover "Linux connect: took over a time-wait end's four-tuple from a bound socket"
                        OverTimeWait.Proceeds (List.filter ((<>) timeWait) others)

            match over with
            | OverTimeWait.AddressInUse ->
                match answer with
                | Ok (SyscallAnswer.Failed UnixError.EADDRINUSE, system) when
                    (socketOf fd system).Ipv4Binding = (socketOf fd walk.System).Ipv4Binding
                    ->
                    withSocket fd socket system
                | other -> fail $"connect answered %s{brief other}; the reference answers EADDRINUSE"
            | OverTimeWait.Refused ->
                match answer with
                | Error (ConnectRefusal.TimeWait _) -> walk
                | other -> fail $"connect answered %s{brief other}; the reference refuses"
            | OverTimeWait.Proceeds timeWaits ->

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
                            ExchangedAt = None
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
                        TimeWaits = timeWaits
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

                { withSocket
                      fd
                      { socket with
                          State = state
                      }
                      system with
                    TimeWaits = timeWaits
                }
            | other -> fail $"connect answered %s{brief other}; the reference is refused from %A{source}"
        | Op.Accept listener ->
            let id = List.head (queueOf listener walk)
            let listenerFd, reuse = walk.Listeners.[listener]

            match
                UnixConnection.tryAccept (Callers.thread 0 system) listenerFd UserBuffer.Mapped (Some 16u) 0 system
            with
            | Ok (AcceptOutcome.Accepted (accepted, _), system) ->
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
                    |> exchanged walk

                match UnixConnection.tryShutdown (Callers.leader system) fd 1 system with
                | Ok (ShutdownAnswer.Shut, system) ->
                    { walk with
                        System = system
                        Connections = Map.add id connection walk.Connections
                    }
                | other -> fail $"shutdown answered %s{brief other}"
            | other -> fail $"shutdown generated on a socket in %A{other}"
        | Op.Close fd ->
            let socket = walk.Sockets.[fd]

            let connections, timeWaits =
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
                        |> exchanged walk

                    // A connection is forgotten once neither end has a socket
                    // or a place in a queue, and an end whose FIN was made
                    // first goes on in TIME_WAIT, from when both FINs had
                    // arrived (`docs/probes/time-wait`).
                    match connection.Client.At, connection.Server.At, connection.ExchangedAt with
                    | EndAt.Closed clientReuse, EndAt.Closed serverReuse, Some exchangedAt ->
                        let timeWaits =
                            [
                                connection.Client, connection.Server, clientReuse
                                connection.Server, connection.Client, serverReuse
                            ]
                            |> List.choose (fun (own, peer, reuse) ->
                                if own.FinPassive then
                                    None
                                else
                                    Some
                                        {
                                            Endpoint = own.Endpoint
                                            Peer = peer.Endpoint
                                            How = own.How
                                            Reuse = reuse
                                            EnteredAt = exchangedAt
                                        }
                            )

                        Map.remove id walk.Connections, walk.TimeWaits @ timeWaits
                    | EndAt.Closed _, EndAt.Closed _, None -> fail "both ends closed with the exchange of FINs not done"
                    | _ -> Map.add id connection walk.Connections, walk.TimeWaits
                | _ -> walk.Connections, walk.TimeWaits

            match UnixDescriptor.tryClose (Callers.leader system) fd system with
            | Ok (SyscallAnswer.Completed 0L, system) ->
                { walk with
                    System = system
                    Sockets = Map.remove fd walk.Sockets
                    Connections = connections
                    TimeWaits = timeWaits
                }
            | other -> fail $"close answered %s{brief other}"
        | Op.Advance milliseconds ->
            { walk with
                System = UnixSystem.advanceClock (milliseconds * 1_000_000L) system
            }

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
        let low, _ = UnixSystem.ephemeralPortRange walk.System

        let isBound (fd : int) (walk : Walk) : bool =
            match walk.Sockets.[fd].State with
            | State.Bound _ -> true
            | _ -> false

        // Half the walks start past the machine's first second of uptime, which
        // decides whether Linux ever takes a TIME_WAIT's four-tuple over.
        let walk =
            if rng.Next 2 = 0 then
                checkedStep cover (Op.Advance 2_000L) walk
            else
                walk

        match rng.Next 6 with
        | 0 -> walk
        | 4 ->
            // A client whose connection both sockets have closed, the client
            // first or the server, leaving one end in TIME_WAIT; and another
            // socket carrying SO_REUSEADDR bound at the client's port and
            // connecting to the same listener over it.
            let walk = checkedStep cover (Op.Advance 2_000L) walk
            let client, walk = fresh cover (rng.Next 4 > 0) walk
            let walk = checkedStep cover (Op.Connect (client, Target.Listener 0)) walk
            let before = walk
            let walk = checkedStep cover (Op.Accept 0) walk

            let server =
                walk.Sockets
                |> Map.toSeq
                |> Seq.map fst
                |> Seq.find (fun fd -> not (before.Sockets.ContainsKey fd))

            let port =
                match boundAt client walk.System with
                | Some bound -> bound.Port
                | None -> failwith "the opening's client is unbound"

            let first, second = if rng.Next 2 = 0 then client, server else server, client

            let walk =
                walk
                |> checkedStep cover (Op.Close first)
                |> checkedStep cover (Op.Close second)

            let walk = checkedStep cover (Op.Advance (pick [ 0L ; 500L ; 1_500L ])) walk
            let other, walk = fresh cover true walk
            let walk = checkedStep cover (Op.Bind (other, Ipv4Address.loopback, port)) walk

            match walk.Sockets.[other].State with
            | State.Bound _ -> checkedStep cover (Op.Connect (other, Target.Listener 0)) walk
            | _ -> walk
        | 5 ->
            // A client whose connection both sockets have closed, the client
            // first, and time passing to the reuse delay, past it, or past a
            // window; then, the allocator's cursor put back on the client's
            // port, a connect to the same listener.
            let client, walk = fresh cover (rng.Next 2 = 0) walk
            let walk = checkedStep cover (Op.Connect (client, Target.Listener 0)) walk
            let before = walk
            let walk = checkedStep cover (Op.Accept 0) walk

            let server =
                walk.Sockets
                |> Map.toSeq
                |> Seq.map fst
                |> Seq.find (fun fd -> not (before.Sockets.ContainsKey fd))

            let port =
                match boundAt client walk.System with
                | Some bound -> bound.Port
                | None -> failwith "the opening's client is unbound"

            let walk =
                walk
                |> checkedStep cover (Op.Close client)
                |> checkedStep cover (Op.Close server)

            let walk =
                checkedStep cover (Op.Advance (pick [ 1_000L ; 1_020L ; 31_000L ; 61_000L ])) walk

            let walk =
                { walk with
                    System =
                        Kernel.mapMachine
                            (fun machine ->
                                { machine with
                                    NextEphemeralPort = port
                                }
                            )
                            walk.System
                }

            let searching, walk = fresh cover (rng.Next 2 = 0) walk
            checkedStep cover (Op.Connect (searching, Target.Listener 0)) walk
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

                // An end in TIME_WAIT, its connection's sockets both closed.
                for flavour in [ "Linux" ; "Darwin" ] do
                    for question in [ "bind" ; "bind search" ; "listen search" ; "connect search" ] do
                        yield $"%s{flavour} %s{question}: time-wait end in the way"

                    yield $"%s{flavour} bind: time-wait end outlived its window"
                    yield $"%s{flavour} connect search: time-wait end outlived its window"
                    yield $"%s{flavour} connect: ended a time-wait end at the destination"

                yield "Linux connect search: took over a time-wait end's four-tuple"
                yield "Linux connect search: time-wait end near the reuse delay"
                yield "Linux connect: took over a time-wait end's four-tuple from a bound socket"
                yield "Darwin connect: EADDRINUSE over a time-wait end's four-tuple"
            ]

        let missing = floors |> List.filter (fun label -> coverage.Count label < 10)

        if not (List.isEmpty missing) then
            failwith $"the fixed sample reached these fewer than 10 times: %A{missing}"
