namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open NUnit.Framework
open WoofWare.PosixKernel

/// Waking a socket or a pipe costs time independent of how many
/// open file descriptions, epoll instances, kqueues and sleeping Darwin polls
/// the rest of the machine holds: finding the descriptions of what it woke,
/// the epoll instances registering them, and the kqueues and sleeping polls'
/// kqueues registering the socket, must not walk every one on the machine.
/// Measured by the bytes the call allocates, which unlike time do not move
/// with the host's load: a call beside four times the crowd may allocate a
/// little more, for the deeper maps it looks things up in, and one that
/// visits every description or poll allocates about four times as much.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestWakeSignalCost =

    let private platformOf (which : string) : SimulatedUnixPlatform =
        match which with
        | "linux" -> SimulatedUnixPlatform.linuxX64
        | "darwin" -> SimulatedUnixPlatform.macOsArm64
        | other -> failwith $"unknown platform %s{other}"

    let private resume (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        match UnixSignal.onReturnToUser caller system with
        | ProcessFate.Continues (ReturnToUserOutcome.Resumes None, system) -> system
        | other -> failwith $"expected no signal at the return to user mode: %A{other}"

    let private launch () : ProcessLaunch<int> =
        ProcessLaunch.create UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A new pipe of `caller`'s process: its read end, its write end, and the
    /// system.
    let private pipe (caller : Caller<int>) (system : UnixSystem<int, unit>) : int * int * UnixSystem<int, unit> =
        match UnixPipe.pipe2 caller 0 UserBuffer.Mapped system with
        | Pipe2Answer.Created (readFd, writeFd), system -> readFd, writeFd, resume caller system
        | answer, _ -> failwith $"expected pipe2 to make a pipe: %A{answer}"

    /// A new socket of `caller`'s process: `AF_INET` and `type`, on both
    /// flavours.
    let private socket
        (kind : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : int * UnixSystem<int, unit>
        =
        match UnixSocket.socket caller 2 kind 0 system with
        | DescriptorAnswer.Returned fd, system -> fd, resume caller system
        | DescriptorAnswer.Failed error, _ -> failwith $"expected socket to make a socket: %O{error}"

    /// `caller`'s process makes an epoll instance and registers `fd` in it.
    let private epollWatching
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let epfd, system =
            match UnixPoll.epollCreate1 caller 0 system with
            | DescriptorAnswer.Returned epfd, system -> epfd, resume caller system
            | DescriptorAnswer.Failed error, _ -> failwith $"expected epoll_create1 to make an instance: %O{error}"

        // `EPOLL_CTL_ADD`.
        match
            UnixPoll.epollCtl
                caller
                epfd
                1
                fd
                (EpollEventArgument.Readable (EpollEvents.In ||| EpollEvents.Out, 0UL))
                system
        with
        | EpollCtlAnswer.Changed, system -> resume caller system
        | answer, _ -> failwith $"expected epoll_ctl to register fd %d{fd}: %A{answer}"

    /// `caller`'s process makes a kqueue and registers `fd`'s read filter in it.
    let private kqueueWatching
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let kq, system =
            match UnixKqueue.kqueue caller system with
            | DescriptorAnswer.Returned kq, system -> kq, resume caller system
            | DescriptorAnswer.Failed error, _ -> failwith $"expected kqueue to make an instance: %O{error}"

        let change : Kevent =
            {
                Ident = uint64 fd
                Filter = KeventFilter.Read
                Flags = KeventFlags.Add
                FilterFlags = 0u
                Data = 0L
                UserData = 0UL
            }

        match
            UnixKqueue.kevent
                caller
                kq
                1
                [ change ]
                0
                UserBuffer.Mapped
                (TimespecArgument.Readable
                    {
                        Seconds = 0L
                        Nanoseconds = 0L
                    })
                system
        with
        | KeventOutcome.Failed error, _ -> failwith $"expected kevent to register fd %d{fd}: %O{error}"
        | KeventOutcome.WouldBlock _, _ -> failwith "expected kevent with no room for events not to wait"
        | _, system -> resume caller system

    /// `caller`'s thread goes to sleep in `poll` on `fd`.
    let private sleepsInPoll
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let entry : PollEntry =
            {
                Fd = fd
                // `POLLIN`.
                Events = 1s
            }

        match UnixPoll.poll caller [ entry ] -1 system with
        | PollOutcome.WouldBlock _, system -> system
        | outcome, _ -> failwith $"expected the poll to sleep: %A{outcome}"

    /// Each process of the crowd makes a TCP socket and watches it as its
    /// flavour can: in an epoll instance of its own on Linux; in a kqueue of
    /// its own on Darwin, and in a `poll` its thread sleeps in on a pipe,
    /// which the machine keeps a kqueue for.
    let private crowdMember (caller : Caller<int>) (system : UnixSystem<int, unit>) : UnixSystem<int, unit> =
        let fd, system = socket 1 caller system

        match SimulatedUnixPlatform.flavour (UnixSystem.platform system) with
        | SimulatedUnixFlavour.Linux -> epollWatching fd caller system
        | SimulatedUnixFlavour.Darwin ->
            let system = kqueueWatching fd caller system
            let readFd, _, system = pipe caller system
            sleepsInPoll readFd caller system

    /// A UDP socket of `caller`'s bound to the loopback address at a port
    /// bind(2) chooses, and that port.
    let private boundUdp
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : int * uint16 * UnixSystem<int, unit>
        =
        // `SOCK_DGRAM`.
        let fd, system = socket 2 caller system
        let platform = UnixSystem.platform system
        let address = CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us)

        let system =
            match CopyIn.bindAs caller fd UserBuffer.Mapped 16u address system with
            | Ok (BindAnswer.Bound _, system) -> resume caller system
            | other -> failwith $"expected bind to bind fd %d{fd}: %A{other}"

        let port =
            match FileDescriptorRegistry.tryFindTarget fd (Proc.fileDescriptors (Caller.processId caller) system) with
            | Some (OpenFileTarget.Socket socketId) ->
                match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
                | Some binding -> binding.Endpoint.Port
                | None -> failwith "the bound socket has no binding"
            | other -> failwith $"fd %d{fd} is %A{other}"

        fd, port, system

    /// `caller`'s UDP socket `fd` connected to the loopback `port`.
    let private connectUdp
        (caller : Caller<int>)
        (fd : int)
        (port : uint16)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        let platform = UnixSystem.platform system
        let address = CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port)

        match CopyIn.connectAs caller fd UserBuffer.Mapped 16u address system with
        | Ok (SyscallAnswer.Completed 0L, system) -> resume caller system
        | other -> failwith $"expected connect to connect fd %d{fd}: %A{other}"

    /// `caller`'s process watches the UDP socket `fd` as its flavour can: in
    /// an epoll instance on Linux, and not at all on Darwin, whose `kevent`
    /// this kernel refuses for a UDP socket.
    let private leaderWatching
        (fd : int)
        (caller : Caller<int>)
        (system : UnixSystem<int, unit>)
        : UnixSystem<int, unit>
        =
        match SimulatedUnixPlatform.flavour (UnixSystem.platform system) with
        | SimulatedUnixFlavour.Linux -> epollWatching fd caller system
        | SimulatedUnixFlavour.Darwin -> system

    /// What the leader does that wakes something.
    type private Waking =
        /// A UDP send to a connected peer, which wakes the sender and the
        /// peer.
        | UdpSend
        /// What a write that fills a pipe the client drains does when the
        /// client drains it, or a client's write into a pipe the process
        /// reads: find the descriptions of one end and signal the epoll
        /// instances registering them. Measured alone, since only the client
        /// makes these wakes.
        | PipeEndSignal

    /// A machine of `count` processes besides the leader's, each a member of
    /// the crowd (`crowdMember`); and the leader's caller and the descriptor
    /// it wakes through, made as `waking` needs: a UDP socket connected to a
    /// peer the leader watches (`leaderWatching`), or a pipe's write end,
    /// which this kernel lets no epoll instance or kqueue register.
    let private machine
        (platform : SimulatedUnixPlatform)
        (waking : Waking)
        (count : int)
        : UnixSystem<int, unit> * Caller<int> * int
        =
        let booted = UnixSystem.initial platform |> UnixBootImage.boot (launch ())
        let leader = Caller.make (Seq.exactlyOne (UnixSystem.processIds booted)) 0

        let fd, system =
            match waking with
            | Waking.UdpSend ->
                let sender, senderPort, system = boundUdp leader booted
                let receiver, receiverPort, system = boundUdp leader system

                let system =
                    connectUdp leader sender receiverPort system
                    |> connectUdp leader receiver senderPort
                    |> leaderWatching receiver leader

                sender, system
            | Waking.PipeEndSignal ->
                let _, writeFd, system = pipe leader booted
                writeFd, system

        let system =
            (system, [ 1..count ])
            ||> List.fold (fun system _ ->
                let pid, system = UnixSystem.launch (launch ()) system
                crowdMember (Caller.make pid 0) system
            )

        let _, system = UnixWait.wake system
        system, leader, fd

    let private payload : ImmutableArray<byte> =
        ImmutableArray.Create<byte> [| 1uy ; 2uy ; 3uy |]

    /// The fewest bytes of several that the leader's waking through `fd`
    /// allocates. A send is the library's own calls rather than
    /// `WriteOutcomes`, which compares the whole system with an oracle's.
    let private wakingBytes
        (waking : Waking)
        (caller : Caller<int>)
        (fd : int)
        (system : UnixSystem<int, unit>)
        : int64
        =
        let once () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()

            match waking with
            | Waking.UdpSend ->
                match
                    UnixReadWrite.trySend caller fd UserBuffer.Mapped (uint64 payload.Length) 0 system
                    |> CallProgress.resumeWith (UnixReadWrite.trySendWithBytes payload)
                with
                | Ok (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Completed 3L), _)) -> ()
                | other -> failwith $"expected the send to complete: %A{other}"
            | Waking.PipeEndSignal ->
                let pid = Caller.processId caller
                let machine = Kernel.machine system

                match FileDescriptorRegistry.tryFindTarget fd (Proc.fileDescriptors pid system) with
                | Some (OpenFileTarget.Pipe (pipeId, pipeEnd)) ->
                    OpenFileTable.signalEpollInstances
                        (UnixMachineState.descriptionsNamingPipeEnd pipeId pipeEnd machine)
                        (Some (EpollEvents.Out ||| EpollEvents.WrNorm))
                        machine.OpenFiles
                    |> ignore<OpenFileTable>
                | other -> failwith $"fd %d{fd} is %A{other}"

            GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    [<TestCase("linux", "udp")>]
    [<TestCase("linux", "pipe")>]
    [<TestCase("darwin", "udp")>]
    [<TestCase("darwin", "pipe")>]
    let ``a wake beside four times the watched sockets allocates about as much``
        (which : string, call : string)
        : unit
        =
        let platform = platformOf which

        let waking =
            match call with
            | "udp" -> Waking.UdpSend
            | "pipe" -> Waking.PipeEndSignal
            | other -> failwith $"unknown call %s{other}"

        let bytes (count : int) : int64 =
            let system, leader, fd = machine platform waking count
            wakingBytes waking leader fd system

        let fewer = bytes 100
        let more = bytes 400

        // Visiting every description, or every sleeping poll, allocates about
        // four times as much beside four times the crowd.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith
                $"%d{fewer} bytes the %s{call} beside a crowd of 100 processes, and %d{more} beside 400: %.2f{ratio} times as much"
