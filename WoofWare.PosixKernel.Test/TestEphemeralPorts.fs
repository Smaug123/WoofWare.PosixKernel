namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// The ephemeral port that `bind(2)` with port 0, `listen(2)` on an unbound
/// socket, and `connect(2)` on an unbound socket each choose, driven through
/// those syscalls on one system so that the three choices are held to one
/// rule.
///
/// The occupant these tests care about is a TCP connection whose client
/// closed: the connection survives in the accepted socket, and a real kernel
/// keeps the closed client's port in its bind table until the connection is
/// gone. `bind(0)` and `listen` must therefore not hand that port out, while
/// `connect` towards a *different* listener may, because a kernel selects a
/// connect-time port by four-tuple.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestEphemeralPorts =

    let private propertyConfig : Config = Config.QuickThrowOnFailure.WithMaxTest 200

    /// A seed for a walk's own `System.Random`, drawn from the whole range so
    /// that each run walks fresh sequences: FsCheck sizes an integer generator,
    /// so at the default end size `NonNegativeInt` yields only 0 to 100, and
    /// every run would walk some of the same 101 sequences. A seed has no meaningful shrink, since a smaller seed is a
    /// different walk rather than a simpler one, so it is given no shrinker.
    let private walkSeed : Arbitrary<int> =
        Arb.fromGen (Gen.choose (0, System.Int32.MaxValue))

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    let private inetFamily : int option =
        Some SimulatedUnixPlatform.internetAddressFamily

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private wildcard (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.any port

    /// A fresh system whose ephemeral range is `low..high`, so that the
    /// allocator wraps within a test.
    let private systemOn (platform : SimulatedUnixPlatform) (low : uint16, high : uint16) : UnixSystem<int, string> =
        let system : UnixBootImage<int, string> = UnixSystem.initial platform


        system
        |> UnixBootImage.tryWithEphemeralPortRange (low, high)
        |> Configured.expectOk EphemeralPortRangeRefusal.describe
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private newStream (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

    let private bindWithReuse
        (reuseAddress : bool)
        (fd : int)
        (endpoint : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : Result<BindAnswer, BindRefusal> * UnixSystem<int, string>
        =
        let system =
            if reuseAddress then
                ReuseAddress.set true fd system
            else
                system

        match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) endpoint) system with
        | Ok (answer, system) -> Ok answer, system
        | Error refusal -> Error refusal, system

    let private bindTo
        (fd : int)
        (endpoint : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : Result<BindAnswer, BindRefusal> * UnixSystem<int, string>
        =
        bindWithReuse false fd endpoint system

    /// `bind(2)` to the wildcard address and port 0, answering the port the
    /// kernel chose, or that it found none: an errno where the platform
    /// answers one, and the refusal where it does not.
    let private bindEphemeral
        (fd : int)
        (system : UnixSystem<int, string>)
        : Result<uint16, Choice<UnixError, BindRefusal>> * UnixSystem<int, string>
        =
        match bindTo fd (wildcard 0us) system with
        | Ok (BindAnswer.Bound (SocketAddress.Inet endpoint)), system -> Ok endpoint.Port, system
        | Ok (BindAnswer.Failed error), system -> Error (Choice1Of2 error), system
        | Ok answer, _ -> failwith $"bind(0.0.0.0:0) answered %A{answer}"
        | Error refusal, system -> Error (Choice2Of2 refusal), system

    /// What finding no ephemeral port answers on `platform`: Linux's
    /// EADDRINUSE, and Darwin's refusal.
    let private noPortForBind
        (platform : SimulatedUnixPlatform)
        (range : uint16 * uint16)
        : Choice<UnixError, BindRefusal>
        =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> Choice1Of2 UnixError.EADDRINUSE
        | SimulatedUnixFlavour.Darwin -> Choice2Of2 (BindRefusal.EphemeralPortsExhausted range)

    let private listenOn (fd : int) (system : UnixSystem<int, string>) : ListenAnswer * UnixSystem<int, string> =
        match UnixSocket.tryListen fd 8 system with
        | Ok (answer, system) -> answer, system
        | Error refusal -> failwith $"listen refused: %A{refusal}"

    /// A new socket bound to loopback at `port` and listening.
    let private listener (port : uint16) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, system = newStream system

        let system =
            match bindTo fd (loopback port) system with
            | Ok (BindAnswer.Bound _), system -> system
            | other, _ -> failwith $"binding the listener at port %d{port}: %A{other}"

        match listenOn fd system with
        | ListenAnswer.Listening _, system -> fd, system
        | ListenAnswer.Failed error, _ -> failwith $"listen at port %d{port} failed with %A{error}"

    let private connectTo
        (fd : int)
        (destination : Ipv4Endpoint)
        (system : UnixSystem<int, string>)
        : SyscallAnswer * UnixSystem<int, string>
        =
        match CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet (UnixSystem.platform system) destination) system with
        | Ok result -> result
        | Error refusal -> failwith $"connect refused: %s{ConnectRefusal.describe refusal}"

    let private acceptFrom (fd : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixConnection.tryAccept 0 fd UserBuffer.Mapped 16u system with
        | Ok (AcceptOutcome.Accepted (accepted, _, _), system) -> accepted, system
        | Ok (AcceptOutcome.Failed error, _) -> failwith $"accept failed with %A{error}"
        | Ok (AcceptOutcome.DroppedConnection error, _) -> failwith $"accept dropped the connection with %A{error}"
        | Ok (AcceptOutcome.WouldBlock _, _) -> failwith "accept parked"
        | Ok (AcceptOutcome.Restarts, _) -> failwith "accept restarted"
        | Error refusal -> failwith $"accept refused: %A{refusal}"

    let private closeFd (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | Ok (answer, _) -> failwith $"close answered %A{answer}"
        | Error refusal -> failwith $"close refused: %A{refusal}"

    /// The local port the socket behind `fd` holds.
    let private localPort (fd : int) (system : UnixSystem<int, string>) : uint16 =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) ->
            match (UnixMachineState.socket socketId system.Machine).Ipv4Binding with
            | Some binding -> binding.Endpoint.Port
            | None -> failwith $"fd %d{fd} is unbound"
        | other -> failwith $"fd %d{fd} is %A{other}, not a socket"

    let private noDefects (system : UnixSystem<int, string>) : unit =
        UnixSystem.checkInvariants system |> shouldEqual []

    /// A listener at 5000, a client that connected to it from the first
    /// ephemeral port and then closed, and the accepted socket still holding
    /// the connection. Answers the closed client's port and the system.
    let private closedClientAtFirstPort
        (platform : SimulatedUnixPlatform)
        (range : uint16 * uint16)
        : uint16 * UnixSystem<int, string>
        =
        let system = systemOn platform range
        let listenerFd, system = listener 5000us system
        let clientFd, system = newStream system

        let system =
            match connectTo clientFd (loopback 5000us) system with
            | SyscallAnswer.Completed _, system -> system
            | SyscallAnswer.Failed error, _ -> failwith $"the first connect failed with %A{error}"

        let clientPort = localPort clientFd system
        clientPort |> shouldEqual (fst range)

        let _accepted, system = acceptFrom listenerFd system
        let system = closeFd clientFd system

        // The connection outlives its client.
        system.Machine.Connections
        |> Map.exists (fun _ connection -> connection.ClientAddress = loopback clientPort)
        |> shouldEqual true

        noDefects system
        clientPort, system

    /// `closedClientAtFirstPort`, with the allocator's cursor put back on the
    /// closed client's port so that it is the first port considered.
    let private cursorOnClosedClient
        (platform : SimulatedUnixPlatform)
        (range : uint16 * uint16)
        : uint16 * UnixSystem<int, string>
        =
        let occupied, system = closedClientAtFirstPort platform range

        occupied,
        { system with
            Machine =
                { system.Machine with
                    NextEphemeralPort = occupied
                }
        }

    [<TestCaseSource(nameof platforms)>]
    let ``bind(0) skips a port a closed client's connection still occupies`` (platform : SimulatedUnixPlatform) : unit =
        let occupied, system = cursorOnClosedClient platform (40000us, 40001us)

        let fd1, system = newStream system
        let port1, system = bindEphemeral fd1 system
        port1 |> shouldEqual (Ok 40001us)
        noDefects system

        // The sweep passed the occupied port and found nothing else.
        let fd2, system = newStream system
        let port2, system = bindEphemeral fd2 system

        port2 |> shouldEqual (Error (noPortForBind platform (40000us, 40001us)))

        // ...and the socket that did get a port can connect to the listener,
        // which is what crashed when the occupied port was handed out.
        match connectTo fd1 (loopback 5000us) system with
        | SyscallAnswer.Completed _, system ->
            localPort fd1 system |> shouldNotEqual occupied
            noDefects system
        | SyscallAnswer.Failed error, _ -> failwith $"connect from the bound socket failed with %A{error}"

    [<TestCaseSource(nameof platforms)>]
    let ``listen on an unbound socket skips a port a closed client's connection still occupies``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let _, system = cursorOnClosedClient platform (40000us, 40001us)

        let fd, system = newStream system

        match listenOn fd system with
        | ListenAnswer.Listening (SocketAddress.Inet endpoint), system ->
            endpoint.Port |> shouldEqual 40001us
            noDefects system
        | answer, _ -> failwith $"listen answered %A{answer}"

    /// The client's port is the one the cursor has come back round to, so
    /// the connect-time choice is between reusing it and skipping it.
    let private cursorBackAtClosedClient (platform : SimulatedUnixPlatform) : uint16 * int * UnixSystem<int, string> =
        let occupied, system = closedClientAtFirstPort platform (40000us, 40001us)
        let listener1, system = listener 5001us system

        // Takes 40001, wrapping the cursor to 40000.
        let filler, system = newStream system

        let system =
            match connectTo filler (loopback 5001us) system with
            | SyscallAnswer.Completed _, system ->
                localPort filler system |> shouldEqual 40001us
                system
            | SyscallAnswer.Failed error, _ -> failwith $"the filler connect failed with %A{error}"

        let _, system = acceptFrom listener1 system
        let system = closeFd filler system
        system.Machine.NextEphemeralPort |> shouldEqual 40000us
        occupied, listener1, system

    [<TestCaseSource(nameof platforms)>]
    let ``connect reuses a closed client's port towards a different listener``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let occupied, _, system = cursorBackAtClosedClient platform

        // Towards the other listener the four-tuple is free, so the kernel's
        // connect-time selection reuses the port.
        let fd, system = newStream system

        match connectTo fd (loopback 5001us) system with
        | SyscallAnswer.Completed _, system ->
            localPort fd system |> shouldEqual occupied
            noDefects system
        | SyscallAnswer.Failed error, _ -> failwith $"connect to the second listener failed with %A{error}"

    [<TestCaseSource(nameof platforms)>]
    let ``connect skips a closed client's port towards the same listener`` (platform : SimulatedUnixPlatform) : unit =
        let occupied, _, system = cursorBackAtClosedClient platform

        // 40000 is taken towards 5000; 40001 is taken only towards 5001.
        let fd, system = newStream system

        match connectTo fd (loopback 5000us) system with
        | SyscallAnswer.Completed _, system ->
            localPort fd system |> shouldNotEqual occupied
            localPort fd system |> shouldEqual 40001us
            noDefects system
        | SyscallAnswer.Failed error, _ -> failwith $"connect to the first listener failed with %A{error}"

    /// A connection queued at a wildcard listener has a concrete server
    /// endpoint that no socket is bound at, and the listener owns it through
    /// its queue: it is not an orphan, so it takes nothing away from a bind
    /// the measured conflict rule admits beside the listener.
    [<Test>]
    let ``a queued connection's server endpoint belongs to the listener`` () : unit =
        // Darwin's measured rule: a specific reuse-address bind beside a
        // wildcard reuse-address listener on the same port is admitted, so
        // the only thing that could refuse the port is a misread of the queue.
        let system = systemOn SimulatedUnixPlatform.macOsArm64 (40000us, 40001us)

        let listenerFd, system = newStream system

        let system =
            match bindWithReuse true listenerFd (wildcard 0us) system with
            | Ok (BindAnswer.Bound (SocketAddress.Inet endpoint)), system ->
                endpoint.Port |> shouldEqual 40000us
                system
            | other, _ -> failwith $"binding the wildcard listener: %A{other}"

        let system =
            match listenOn listenerFd system with
            | ListenAnswer.Listening _, system -> system
            | ListenAnswer.Failed error, _ -> failwith $"listen failed with %A{error}"

        let clientFd, system = newStream system

        let system =
            match connectTo clientFd (loopback 40000us) system with
            | SyscallAnswer.Completed _, system -> system
            | SyscallAnswer.Failed error, _ -> failwith $"connect failed with %A{error}"

        localPort clientFd system |> shouldEqual 40001us

        // An explicit bind: a search for a port passes over every port held
        // at an overlapping address, whatever SO_REUSEADDR says.
        let bindBesideListener (system : UnixSystem<int, string>) : uint16 =
            let fd, system = newStream system

            match bindWithReuse true fd (loopback 40000us) system with
            | Ok (BindAnswer.Bound (SocketAddress.Inet endpoint)), _ -> endpoint.Port
            | other, _ -> failwith $"binding beside the listener: %A{other}"

        // Not yet accepted: the connection sits in the listener's queue.
        bindBesideListener system |> shouldEqual 40000us

        // Accepted: the accepted socket is bound at the server endpoint, and
        // the same answer follows from the measured established-socket row.
        let _, system = acceptFrom listenerFd system
        bindBesideListener system |> shouldEqual 40000us

    // ------------------------------------------------------------------
    // For all interleavings: the three choices never contradict each other
    // ------------------------------------------------------------------

    [<RequireQualifiedAccess>]
    type private Op =
        /// A new stream socket, into the next free slot.
        | New
        /// `bind(0.0.0.0:0)` on an unbound slot.
        | BindEphemeral of slot : int
        /// `listen` on a slot; the implicit bind if it is unbound.
        | Listen of slot : int
        /// `connect` from a slot towards one of the two fixed listeners.
        | Connect of slot : int * listener : int
        /// `connect` from a slot towards a port nothing is bound at, which
        /// the kernel refuses.
        | ConnectClosed of slot : int
        /// `accept` on a fixed listener, when its queue is non-empty.
        | Accept of listener : int
        /// `close` a slot.
        | Close of slot : int

    type private Run =
        {
            System : UnixSystem<int, string>
            /// Slot to fd, for sockets this run created and has not closed.
            Slots : Map<int, int>
            NextSlot : int
            /// The fds of the two fixed listeners, at 5000 and 5001.
            Listeners : int list
        }

    let private listenerPort (listener : int) : uint16 = 5000us + uint16 listener

    /// Where nothing is ever bound in a walk.
    let private closedPort : uint16 = 6000us

    /// Whether `slot`'s socket is in a state the op can lawfully be asked of:
    /// the generator is constructive, so an op that the model refuses
    /// outright (rather than answering an errno) is never generated.
    /// The slot's phase, and whether it holds a port: a refused connect may
    /// have given back the port it still reports.
    let private phaseOf (fd : int) (run : Run) : SocketPhase * bool =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors run.System) with
        | Some (OpenFileTarget.Socket socketId) ->
            let socket = UnixMachineState.socket socketId run.System.Machine

            socket.Phase,
            socket.Ipv4Binding
            |> Option.exists (fun binding -> PortHold.isHeld binding.PortHold)
        | other -> failwith $"slot fd %d{fd} is %A{other}"

    /// Whether `connect` from the unbound socket behind `fd` towards
    /// `destination` would find a port to take.
    let private implicitBindHasAPort (fd : int) (destination : Ipv4Endpoint) (run : Run) : bool =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors run.System) with
        | Some (OpenFileTarget.Socket socketId) ->
            let socket = UnixMachineState.socket socketId run.System.Machine

            let candidate (port : uint16) : Ipv4Binding =
                {
                    Endpoint = loopback port
                    LockedAddress = None
                    LockedPort = false
                    PortHold = PortHold.Reserved
                }

            UnixMachineState.allocateEphemeralPort
                (EphemeralPortUse.ConnectTo destination)
                socketId
                socket
                candidate
                run.System.Machine
            |> Option.isSome
        | other -> failwith $"slot fd %d{fd} is %A{other}"

    let private queueLength (listenerFd : int) (run : Run) : int =
        match phaseOf listenerFd run with
        | SocketPhase.Listening state, _ -> List.length state.Queue
        | phase, _ -> failwith $"listener is in phase %A{phase}"

    /// One op against the run. Every answer the kernel gives is accepted;
    /// what the property rejects is a throw, an invariant defect, or an
    /// ephemeral port handed to `bind`/`listen` that a surviving connection
    /// endpoint still occupies.
    let private execute (op : Op) (run : Run) : Run =
        match op with
        | Op.New ->
            let fd, system = newStream run.System

            { run with
                System = system
                Slots = Map.add run.NextSlot fd run.Slots
                NextSlot = run.NextSlot + 1
            }
        | Op.BindEphemeral slot ->
            let fd = run.Slots.[slot]

            match bindEphemeral fd run.System with
            | Ok _, system
            | Error (Choice1Of2 UnixError.EADDRINUSE), system
            | Error (Choice2Of2 (BindRefusal.EphemeralPortsExhausted _)), system ->
                { run with
                    System = system
                }
            | Error other, _ -> failwith $"bind answered %A{other}"
        | Op.Listen slot ->
            let fd = run.Slots.[slot]

            match UnixSocket.tryListen fd 8 run.System with
            | Ok (_, system) ->
                { run with
                    System = system
                }
            | Error (ListenRefusal.EphemeralPortsExhausted _) -> run
            | Error refusal -> failwith $"listen refused: %A{refusal}"
        | Op.Connect (slot, listener) ->
            let fd = run.Slots.[slot]
            let _, system = connectTo fd (loopback (listenerPort listener)) run.System

            { run with
                System = system
            }
        | Op.ConnectClosed slot ->
            let fd = run.Slots.[slot]

            match connectTo fd (loopback closedPort) run.System with
            | SyscallAnswer.Failed UnixError.ECONNREFUSED, system ->
                { run with
                    System = system
                }
            | answer, _ -> failwith $"connect to a closed port answered %A{answer}"
        | Op.Accept listener ->
            let _, system = acceptFrom run.Listeners.[listener] run.System

            { run with
                System = system
            }
        | Op.Close slot ->
            let fd = run.Slots.[slot]
            let system = closeFd fd run.System

            { run with
                System = system
                Slots = Map.remove slot run.Slots
            }

    /// The next op, chosen among those the model answers rather than refuses.
    let private nextOp (rng : System.Random) (run : Run) : Op =
        let slots = run.Slots |> Map.toList

        let candidates : Op list =
            [
                yield Op.New

                for slot, fd in slots do
                    match phaseOf fd run with
                    | SocketPhase.Idle, false ->
                        yield Op.BindEphemeral slot
                        yield Op.Listen slot
                    | SocketPhase.Idle, true -> yield Op.Listen slot
                    // EINVAL, on both flavours.
                    | SocketPhase.Refused _, _ -> yield Op.Listen slot
                    | _ -> ()

                    match phaseOf fd run with
                    | SocketPhase.Idle, bound ->
                        if bound || implicitBindHasAPort fd (loopback closedPort) run then
                            yield Op.ConnectClosed slot

                        for listener in 0..1 do
                            // A listener whose queue is full has no measured
                            // answer, so keep every queue short of it; and an
                            // unbound connect with no port left to take is a
                            // refusal `connectSocket` still states as a throw,
                            // which is not what this property is about.
                            if
                                queueLength run.Listeners.[listener] run < 8
                                && (bound || implicitBindHasAPort fd (loopback (listenerPort listener)) run)
                            then
                                yield Op.Connect (slot, listener)
                    | _ -> ()

                    // A listener created by `Listen` may hold a queue only
                    // through the fixed listeners, which are never closed,
                    // so any slot may close; and any established peer's
                    // close is answered, never refused.
                    yield Op.Close slot

                for listener in 0..1 do
                    if queueLength run.Listeners.[listener] run > 0 then
                        yield Op.Accept listener
            ]

        candidates.[rng.Next candidates.Length]

    /// Whether the socket behind `fd` reports a port its refused connect gave
    /// back.
    let private givenBack (fd : int) (run : Run) : bool =
        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors run.System) with
        | Some (OpenFileTarget.Socket socketId) ->
            (UnixMachineState.socket socketId run.System.Machine).Ipv4Binding
            |> Option.exists (fun binding -> not (PortHold.isHeld binding.PortHold))
        | other -> failwith $"slot fd %d{fd} is %A{other}"

    /// Whether `machine` and `without`, which lacks one of its sockets, agree
    /// about every port of the range: what a new stream socket's bind of it
    /// at loopback and at the wildcard conflicts with, and which port an
    /// allocation for it chooses, for a bind and for a connect to either
    /// fixed listener.
    let private invisibleTo (machine : UnixMachineState) (without : UnixMachineState) : bool =
        let probeId = SocketId 999999L

        let probe : SocketDescription =
            {
                Addressing = SocketAddressing.Inet None
                Kind = SocketKind.Stream
                Protocol = SocketProtocol.Tcp
                ReuseAddress = false
                Options = SocketOptions.initial
                Phase = SocketPhase.Idle
            }

        let low, high = machine.EphemeralPortRange

        let binding (address : Ipv4Address) (port : uint16) : Ipv4Binding =
            {
                Endpoint = Ipv4Endpoint.ofParts address port
                LockedAddress = None
                LockedPort = false
                PortHold = PortHold.Reserved
            }

        let conflictsAgree =
            [ low..high ]
            |> List.forall (fun port ->
                [ Ipv4Address.loopback ; Ipv4Address.any ]
                |> List.forall (fun address ->
                    UnixMachineState.bindingConflicts probeId probe (binding address port) machine = UnixMachineState.bindingConflicts
                        probeId
                        probe
                        (binding address port)
                        without
                )
            )

        let chosen (use' : EphemeralPortUse) (machine : UnixMachineState) : uint16 option =
            UnixMachineState.allocateEphemeralPort use' probeId probe (binding Ipv4Address.loopback) machine
            |> Option.map (fun (binding, _) -> binding.Endpoint.Port)

        let uses =
            [
                EphemeralPortUse.Reserve
                EphemeralPortUse.ConnectTo (loopback (listenerPort 0))
                EphemeralPortUse.ConnectTo (loopback (listenerPort 1))
            ]

        conflictsAgree
        && uses |> List.forall (fun use' -> chosen use' machine = chosen use' without)

    /// Every port `bind(0)` or an unbound `listen` handed out in this run,
    /// checked against the endpoints of every surviving connection whose
    /// socket has gone.
    let private orphanedEndpointPorts (system : UnixSystem<int, string>) : Set<uint16> =
        let boundEndpoints =
            system.Machine.Sockets
            |> Map.toSeq
            |> Seq.choose (fun (_, socket) ->
                socket.Ipv4Binding
                |> Option.filter (fun binding -> PortHold.isHeld binding.PortHold)
                |> Option.map (fun binding -> binding.Endpoint)
            )
            |> Set.ofSeq

        system.Machine.Connections
        |> Map.toSeq
        |> Seq.collect (fun (_, connection) -> [ connection.ClientAddress ; connection.ServerAddress ])
        |> Seq.filter (fun endpoint -> not (Set.contains endpoint boundEndpoints))
        |> Seq.map (fun endpoint -> endpoint.Port)
        |> Set.ofSeq

    [<TestCaseSource(nameof platforms)>]
    let ``no interleaving of the three choices crashes, and no reserved port is an orphaned connection's``
        (platform : SimulatedUnixPlatform)
        : unit
        =
        let property (cover : string -> unit) (seed : int) : bool =
            let rng = System.Random seed
            let system = systemOn platform (40000us, 40000us + uint16 (rng.Next 4))
            let listener0, system = listener (listenerPort 0) system
            let listener1, system = listener (listenerPort 1) system

            let initial =
                {
                    System = system
                    Slots = Map.empty
                    NextSlot = 0
                    Listeners = [ listener0 ; listener1 ]
                }

            let steps = 1 + rng.Next 24

            (initial, [ 1..steps ])
            ||> List.fold (fun run _ ->
                let op = nextOp rng run

                match op with
                | Op.ConnectClosed _ -> cover "a refused connect"
                | Op.BindEphemeral slot
                | Op.Listen slot
                | Op.Connect (slot, _)
                | Op.ConnectClosed slot when givenBack run.Slots.[slot] run ->
                    cover "a call on a socket whose refused connect gave its port back"
                | _ -> ()

                let run' = execute op run

                match UnixSystem.checkInvariants run'.System with
                | [] -> ()
                | defects -> failwith $"after %A{op}: %A{defects}"

                // Any bound socket's port that is also an orphaned
                // endpoint's must have been an explicit bind, which this
                // generator never makes: so any such overlap is a reserved
                // port that should have been skipped.
                let orphaned = orphanedEndpointPorts run'.System

                let reservedOverlap =
                    run'.System.Machine.Sockets
                    |> Map.toList
                    |> List.choose (fun (socketId, socket) ->
                        match socket.Ipv4Binding, socket.Phase with
                        | Some binding, (SocketPhase.Idle | SocketPhase.Listening _) when
                            PortHold.isHeld binding.PortHold
                            && binding.Endpoint.Port <> listenerPort 0
                            && binding.Endpoint.Port <> listenerPort 1
                            && Set.contains binding.Endpoint.Port orphaned
                            ->
                            Some (socketId, binding.Endpoint)
                        | _ -> None
                    )

                match reservedOverlap with
                | [] -> ()
                | overlap -> failwith $"after %A{op}: reserved ports on orphaned endpoints: %A{overlap}"

                // A port a refused connect gave back holds nothing: taking the
                // socket away changes no conflict a new socket's bind meets
                // and no port an allocation chooses.
                for KeyValue (socketId, socket) in run'.System.Machine.Sockets do
                    match socket.Ipv4Binding with
                    | Some binding when not (PortHold.isHeld binding.PortHold) ->
                        let machine = run'.System.Machine

                        let without =
                            { machine with
                                Sockets = Map.remove socketId machine.Sockets
                            }

                        if invisibleTo machine without |> not then
                            failwith
                                $"after %A{op}: socket %O{socketId}, whose port was given back, still holds something"
                    | _ -> ()

                run'
            )
            |> ignore<Run>

            true

        let coverage = CoverageSample.check propertyConfig walkSeed property

        coverage.Count "a refused connect" |> shouldBeGreaterThan 50

        coverage.Count "a call on a socket whose refused connect gave its port back"
        |> shouldBeGreaterThan 10

    /// Linux's search for a port to bind passes over a port another socket
    /// holds, both carrying `SO_REUSEADDR`, though an explicit bind of it
    /// would be admitted beside it (measured, `docs/probes/ephemeral-search`,
    /// row lr/Br): the search never relaxes the bind rule.
    [<Test>]
    let ``Linux bind(0) with SO_REUSEADDR does not share a port another reuse socket holds`` () : unit =
        let system = systemOn SimulatedUnixPlatform.linuxX64 (40000us, 40001us)
        let holder, system = newStream system

        let system =
            match bindWithReuse true holder (loopback 40000us) system with
            | Ok (BindAnswer.Bound _), system -> system
            | other, _ -> failwith $"binding the holder: %A{other}"

        // The control: an explicit bind beside it is admitted.
        let beside, system = newStream system

        match bindWithReuse true beside (loopback 40000us) system with
        | Ok (BindAnswer.Bound _), _ -> ()
        | other, _ -> failwith $"an explicit bind beside the holder: %A{other}"

        match bindWithReuse true beside (loopback 0us) system with
        | Ok (BindAnswer.Bound (SocketAddress.Inet endpoint)), system ->
            endpoint.Port |> shouldEqual 40001us
            noDefects system
        | other, _ -> failwith $"bind(127.0.0.1:0): %A{other}"

    // ------------------------------------------------------------------
    // Linux's search, against a reference written from the measured rule
    // ------------------------------------------------------------------

    /// What a walk socket holds, by how it came by its port, as the walk
    /// itself recorded it rather than as the kernel's state says.
    [<RequireQualifiedAccess>]
    type private Holding =
        /// No port: never bound, or given back by a refused connect. `address`
        /// is where the socket's next implicit bind binds.
        | Nothing of address : Ipv4Address
        /// A port `bind(2)` or `listen(2)` gave the socket (`locked` where
        /// `bind(2)` asked for it), or the listener's port an accepted socket
        /// holds.
        | BindMade of endpoint : Ipv4Endpoint * locked : bool
        /// A port connect's own implicit bind gave the socket, connected to
        /// `destination`.
        | ConnectMade of endpoint : Ipv4Endpoint * destination : Ipv4Endpoint

    type private Walk =
        {
            System : UnixSystem<int, string>
            /// Each walk socket's descriptor, and what it holds.
            Slots : Map<int, Holding>
            /// The fds of the two fixed listeners, at 5000 and 5001.
            Listeners : int list
        }

    /// Measured (`docs/probes/ephemeral-search`): Linux's search for a port to
    /// bind, for `bind(2)` of port 0 and an unbound `listen(2)`, passes over
    /// every port another socket holds at an address overlapping
    /// `candidate`'s, however it came by it and whatever either's
    /// `SO_REUSEADDR`.
    let private reserveFree (holdings : Holding list) (candidate : Ipv4Endpoint) : bool =
        holdings
        |> List.forall (fun holding ->
            match holding with
            | Holding.Nothing _ -> true
            | Holding.BindMade (held, _)
            | Holding.ConnectMade (held, _) ->
                not (held.Port = candidate.Port && Ipv4Endpoint.addressesOverlap held candidate)
        )

    /// Measured: Linux's search for a connect's port passes over every port a
    /// socket holds by `bind(2)` or `listen(2)`, at any address, and shares a
    /// port connect's own implicit bind gave another socket, unless that one
    /// is connected from the same source to the same destination.
    let private connectFree (holdings : Holding list) (source : Ipv4Endpoint) (destination : Ipv4Endpoint) : bool =
        holdings
        |> List.forall (fun holding ->
            match holding with
            | Holding.Nothing _ -> true
            | Holding.BindMade (held, _) -> held.Port <> source.Port
            | Holding.ConnectMade (held, connectedTo) -> not (held = source && connectedTo = destination)
        )

    /// The first port, from where the machine's allocator stands and wrapping
    /// round its range once, that `free` admits.
    let private firstFree (machine : UnixMachineState) (free : uint16 -> bool) : uint16 option =
        let low, high = machine.EphemeralPortRange
        let width = int high - int low + 1

        let start =
            if machine.NextEphemeralPort < low || machine.NextEphemeralPort > high then
                low
            else
                machine.NextEphemeralPort

        [ 0 .. width - 1 ]
        |> List.map (fun i -> uint16 (int low + (int start - int low + i) % width))
        |> List.tryFind free

    /// What every walk socket but `fd` holds.
    let private holdingsBut (fd : int) (walk : Walk) : Holding list =
        walk.Slots
        |> Map.toList
        |> List.filter (fun (other, _) -> other <> fd)
        |> List.map snd

    /// What `getsockname(2)` would report for the socket behind `fd`.
    let private nameOfFd (fd : int) (system : UnixSystem<int, string>) : Ipv4Endpoint =
        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) ->
            match (UnixMachineState.socket socketId system.Machine).Ipv4Binding with
            | Some binding -> binding.Endpoint
            | None -> wildcard 0us
        | other -> failwith $"fd %d{fd} is %A{other}"

    let private phaseOfFd (fd : int) (system : UnixSystem<int, string>) : SocketPhase =
        match FileDescriptorRegistry.tryFindTarget fd (UnixSystemState.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) -> (UnixMachineState.socket socketId system.Machine).Phase
        | other -> failwith $"fd %d{fd} is %A{other}"

    [<RequireQualifiedAccess>]
    type private SearchOp =
        | New of reuse : bool
        | BindExplicit of fd : int * address : Ipv4Address * port : uint16
        | BindZero of fd : int * address : Ipv4Address
        | Listen of fd : int
        /// `connect` to a fixed listener, or, for `None`, to a port nothing is
        /// bound at, which the kernel refuses.
        | Connect of fd : int * listener : int option
        | Accept of listener : int
        | Close of fd : int

    let private searchAddresses : Ipv4Address list =
        [ Ipv4Address.loopback ; Ipv4Address.any ; Ipv4Address 0x7F000002u ]

    let private nextSearchOp (rng : System.Random) (walk : Walk) : SearchOp =
        let pick (list : 'a list) : 'a = list.[rng.Next list.Length]
        let low, high = walk.System.Machine.EphemeralPortRange

        let queue (listener : int) : int =
            match phaseOfFd walk.Listeners.[listener] walk.System with
            | SocketPhase.Listening state -> List.length state.Queue
            | phase -> failwith $"a fixed listener is in %A{phase}"

        // A socket holding a port, which SO_REUSEADDR may have let it share,
        // connecting where a connection from that port already goes: how a
        // kernel refuses the duplicate four-tuple is unmeasured.
        let duplicates (fd : int) (destination : Ipv4Endpoint) : bool =
            match walk.Slots.[fd] with
            | Holding.Nothing _ -> false
            | Holding.BindMade (held, _)
            | Holding.ConnectMade (held, _) ->
                let source =
                    if held.Address = Ipv4Address.any then
                        loopback held.Port
                    else
                        held

                walk.System.Machine.Connections
                |> Map.exists (fun _ connection ->
                    connection.ClientAddress = source && connection.ServerAddress = destination
                )

        let connects (fd : int) : SearchOp list =
            [
                yield SearchOp.Connect (fd, None)

                for listener in 0..1 do
                    // A listener's queue at its capacity has no measured
                    // answer, so keep every queue short of it.
                    if queue listener < 8 && not (duplicates fd (loopback (listenerPort listener))) then
                        yield SearchOp.Connect (fd, Some listener)
            ]

        let candidates =
            [
                yield SearchOp.New false
                yield SearchOp.New true

                for KeyValue (fd, holding) in walk.Slots do
                    match phaseOfFd fd walk.System, holding with
                    | SocketPhase.Idle, Holding.Nothing _ ->
                        yield
                            SearchOp.BindExplicit (fd, pick searchAddresses, uint16 (rng.Next (int low, int high + 1)))

                        yield SearchOp.BindZero (fd, pick searchAddresses)
                        yield SearchOp.Listen fd
                        yield! connects fd
                        yield SearchOp.Close fd
                    | SocketPhase.Idle, _ ->
                        yield SearchOp.Listen fd
                        yield! connects fd
                        yield SearchOp.Close fd
                    // Only the fixed listeners are connected to, so a listener
                    // the walk made closes holding no connection; and the walk
                    // closes no connected socket, so no connection outlives its
                    // sockets.
                    | SocketPhase.Listening _, _ -> yield SearchOp.Close fd
                    | _ -> ()

                for listener in 0..1 do
                    if queue listener > 0 then
                        yield SearchOp.Accept listener
            ]

        pick candidates

    /// One op, checked against the reference wherever the kernel searches for
    /// a port; `cover` counts what the walk reached.
    let private stepSearch (cover : string -> unit) (op : SearchOp) (walk : Walk) : Walk =
        let system = walk.System
        let machine = system.Machine

        let holding (fd : int) : Holding = walk.Slots.[fd]

        let withHolding (fd : int) (h : Holding) (system : UnixSystem<int, string>) : Walk =
            { walk with
                System = system
                Slots = Map.add fd h walk.Slots
            }

        let unchanged (system : UnixSystem<int, string>) : Walk =
            { walk with
                System = system
            }

        /// Checks a search's outcome, `Some port` or `None`, against the
        /// reference's first free port.
        let checkSearch (what : string) (expected : uint16 option) (actual : uint16 option) : unit =
            if expected <> actual then
                let sockets =
                    machine.Sockets
                    |> Map.toList
                    |> List.map (fun (socketId, socket) -> socketId, socket.Phase, socket.Ipv4Binding)

                failwith
                    $"%A{op}: %s{what} took %A{actual}, where the reference takes %A{expected}; the walk held %A{walk.Slots}; the kernel held %A{sockets}"

            match actual with
            | None -> cover $"%s{what} found no port"
            | Some _ -> cover $"%s{what} found a port"

        match op with
        | SearchOp.New reuse ->
            let fd, system = newStream system
            let system = if reuse then ReuseAddress.set true fd system else system
            withHolding fd (Holding.Nothing Ipv4Address.any) system
        | SearchOp.BindExplicit (fd, address, port) ->
            match bindTo fd (Ipv4Endpoint.ofParts address port) system with
            | Ok (BindAnswer.Bound _), system ->
                withHolding fd (Holding.BindMade (Ipv4Endpoint.ofParts address port, true)) system
            | Ok (BindAnswer.Failed _), system -> unchanged system
            | Error refusal, _ -> failwith $"%A{op}: refused %A{refusal}"
        | SearchOp.BindZero (fd, address) ->
            let expected =
                firstFree machine (fun port -> reserveFree (holdingsBut fd walk) (Ipv4Endpoint.ofParts address port))

            match bindTo fd (Ipv4Endpoint.ofParts address 0us) system with
            | Ok (BindAnswer.Bound (SocketAddress.Inet bound)), system ->
                checkSearch "bind of port 0" expected (Some bound.Port)
                withHolding fd (Holding.BindMade (bound, false)) system
            | Ok (BindAnswer.Failed UnixError.EADDRINUSE), system ->
                checkSearch "bind of port 0" expected None
                unchanged system
            | other -> failwith $"%A{op}: %A{other}"
        | SearchOp.Listen fd ->
            match holding fd with
            | Holding.Nothing address ->
                let expected =
                    firstFree
                        machine
                        (fun port -> reserveFree (holdingsBut fd walk) (Ipv4Endpoint.ofParts address port))

                match listenOn fd system with
                | ListenAnswer.Listening (SocketAddress.Inet bound), system ->
                    checkSearch "listen" expected (Some bound.Port)
                    withHolding fd (Holding.BindMade (bound, false)) system
                | ListenAnswer.Failed UnixError.EADDRINUSE, system ->
                    checkSearch "listen" expected None
                    unchanged system
                | other -> failwith $"%A{op}: %A{other}"
            | held ->
                // No search: Linux screens the binding again, by the bind rule.
                match listenOn fd system with
                | ListenAnswer.Listening _, system -> withHolding fd held system
                | ListenAnswer.Failed _, system -> unchanged system
        | SearchOp.Connect (fd, listener) ->
            let destination =
                match listener with
                | Some listener -> loopback (listenerPort listener)
                | None -> loopback closedPort

            let expected =
                match holding fd with
                | Holding.Nothing address ->
                    let source =
                        if address = Ipv4Address.any then
                            Ipv4Address.loopback
                        else
                            address

                    let others = holdingsBut fd walk

                    let expected =
                        firstFree
                            machine
                            (fun port -> connectFree others (Ipv4Endpoint.ofParts source port) destination)

                    let shared =
                        others
                        |> List.exists (fun h ->
                            match h, expected with
                            | Holding.ConnectMade (held, _), Some port -> held.Port = port
                            | _ -> false
                        )

                    if shared then
                        cover "a connect shared a port another connect's implicit bind took"

                    Some expected
                | Holding.BindMade _
                | Holding.ConnectMade _ -> None

            let answer, system =
                match CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet machine.UnixPlatform destination) system with
                | Ok result -> result
                | Error refusal -> failwith $"%A{op}: refused %s{ConnectRefusal.describe refusal}"

            let after = nameOfFd fd system

            match expected, answer, listener with
            | Some expected, SyscallAnswer.Failed UnixError.EADDRNOTAVAIL, _ ->
                checkSearch "connect" expected None
                unchanged system
            | Some expected, SyscallAnswer.Failed UnixError.ECONNREFUSED, None ->
                checkSearch "connect" expected (Some after.Port)
                // The refusal gives an implicit bind's port straight back.
                withHolding fd (Holding.Nothing after.Address) system
            | Some expected, SyscallAnswer.Completed 0L, Some _ ->
                checkSearch "connect" expected (Some after.Port)
                withHolding fd (Holding.ConnectMade (after, destination)) system
            | None, SyscallAnswer.Failed UnixError.ECONNREFUSED, None ->
                match holding fd with
                | Holding.BindMade (_, true) -> withHolding fd (Holding.BindMade (after, true)) system
                | _ -> withHolding fd (Holding.Nothing after.Address) system
            | None, SyscallAnswer.Completed 0L, Some _ ->
                match holding fd with
                | Holding.BindMade (_, locked) -> withHolding fd (Holding.BindMade (after, locked)) system
                | other -> failwith $"%A{op}: a socket holding %A{other} connected"
            | _ -> failwith $"%A{op}: answered %A{answer}"
        | SearchOp.Accept listener ->
            let accepted, system = acceptFrom walk.Listeners.[listener] system
            withHolding accepted (Holding.BindMade (nameOfFd accepted system, false)) system
        | SearchOp.Close fd ->
            { walk with
                System = closeFd fd system
                Slots = Map.remove fd walk.Slots
            }

    /// Every port Linux's search hands out, for `bind(2)` of port 0, an
    /// unbound `listen(2)` and an unbound `connect(2)`, is the first, from
    /// where the allocator stands, that the measured rule leaves free, judged
    /// by how the walk itself saw each other socket come by its port; and a
    /// search that finds none is answered EADDRINUSE or EADDRNOTAVAIL exactly
    /// when the rule leaves none free.
    [<Test>]
    let ``Linux's search takes the first port the measured rule leaves free`` () : unit =
        let platform = SimulatedUnixPlatform.linuxX64

        let property (cover : string -> unit) (seed : int) : bool =
            let rng = System.Random seed

            // A range two ports wide or so, so that searches run out.
            let system = systemOn platform (40000us, 40000us + uint16 (rng.Next 3))
            let listener0, system = listener (listenerPort 0) system
            let listener1, system = listener (listenerPort 1) system

            let initial =
                {
                    System = system
                    Slots = Map.empty
                    Listeners = [ listener0 ; listener1 ]
                }

            (initial, [ 1 .. 1 + rng.Next 30 ])
            ||> List.fold (fun walk _ ->
                let op = nextSearchOp rng walk
                let walk = stepSearch cover op walk

                match UnixSystem.checkInvariants walk.System with
                | [] -> ()
                | defects -> failwith $"after %A{op}: %A{defects}"

                walk
            )
            |> ignore<Walk>

            true

        let coverage = CoverageSample.check propertyConfig walkSeed property

        for label in
            [
                "bind of port 0 found a port"
                "bind of port 0 found no port"
                "listen found a port"
                "listen found no port"
                "connect found a port"
                "connect found no port"
                "a connect shared a port another connect's implicit bind took"
            ] do
            if coverage.Count label < 10 then
                failwith $"the fixed sample reached %s{label} only %d{coverage.Count label} times"
