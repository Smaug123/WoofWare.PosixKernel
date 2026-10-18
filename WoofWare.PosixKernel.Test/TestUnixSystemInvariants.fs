namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `UnixSystem.checkInvariants`, for the rules nothing else exercises.
///
/// Five of these six were found by mutating each rule in turn and seeing which
/// mutants no suite killed, and three of those are the same gap twice over: the
/// `>=` against a counter is only ever tested with a strictly greater identity,
/// so the boundary the rule exists for is untested.
/// The sixth, `CurrentDirectoryIsNotADirectory`, arrived with the setter that
/// establishes the current directory. The seventh and eighth,
/// `UnmodelledBindingHeld` and `DatagramPeerOfAnotherFamily`, guard states no
/// syscall yet produces. `StatusNotOfFlavour` and `FlockHeldNotRecorded`
/// guard an open file description's status against its machine's flavour and
/// against its lock, and `DescriptorFlagsNotOfFlavour` a descriptor's flags
/// against the flavour.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestUnixSystemInvariants =

    let private context : string = "TestUnixSystemInvariants"

    let private epoch : UnixTimestamp = UnixTimestamp.ofMillisecondsSinceEpoch 0L

    /// A sound Linux system, before anything has happened to it. One flavour,
    /// because every rule below is about the tables rather than about the
    /// platform.
    let private system : UnixSystem<int, string> =
        let system : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        { system with
            Machine =
                { system.Machine with
                    LocalRoutes = []
                }
        }


    /// `system` launched with no descriptors at all, and so no pipes: the base
    /// for a row that replaces the whole descriptor table.
    let private unlaunched : UnixSystem<int, string> =
        let bare : UnixSystem<int, string> =
            UnixSystem.initial SimulatedUnixPlatform.linuxX64
            |> Launched.boot Map.empty 0 (CpuId 0)

        { bare with
            Machine =
                { bare.Machine with
                    LocalRoutes = []
                }
        }

    /// A sound system is the control every row below is a single edit away
    /// from: without it, a row that reported *some* defect would pass while
    /// naming the wrong one.
    [<Test>]
    let ``the starting system is sound`` () : unit =
        UnixSystem.checkInvariants system |> shouldEqual []

    // ------------------------------------------------------------------
    // The phase/kind rule, in the direction the other test does not take
    // ------------------------------------------------------------------

    /// The mismatch rule has two halves — a datagram socket in a stream phase,
    /// and a stream socket holding a datagram peer — written as two arms of one
    /// match. A test for either half alone leaves the other's arm free to say
    /// anything.
    [<TestCase(true)>]
    [<TestCase(false)>]
    let ``a stream socket holding a datagram peer is a defect`` (stream : bool) : unit =
        let kind = if stream then SocketKind.Stream else SocketKind.SeqPacket

        let phase =
            SocketPhase.DatagramPeer (SocketAddress.Inet (Ipv4Endpoint.ofParts Ipv4Address.loopback 80us))

        let forged =
            (Lone.withFileDescriptors
                (FileDescriptorRegistry.Unchecked.ofParts
                    SimulatedUnixFlavour.Linux
                    (Map.ofList [ 3, OpenFileDescriptionId 0L ])
                    (Map.ofList
                        [
                            OpenFileDescriptionId 0L,
                            {
                                Target = OpenFileTarget.Socket (SocketId 0L)
                                AccessMode = FileAccessMode.ReadWrite
                                NonBlocking = false
                                Flock = None
                                Status = OpenFileStatus.none SimulatedUnixFlavour.Linux
                            }
                        ])
                    (OpenFileDescriptionId 1L))
                { unlaunched with
                    Machine =
                        { unlaunched.Machine with
                            Sockets =
                                Map.ofList
                                    [
                                        SocketId 0L,
                                        {
                                            Addressing = SocketAddressing.Inet None
                                            Kind = kind
                                            Protocol = SocketProtocol.Tcp
                                            ReuseAddress = false
                                            Options = SocketOptions.initial
                                            Phase = phase
                                            Uid = UserId.root
                                        }
                                    ]
                            NextSocketId = SocketId 1L
                        }
                })

        UnixSystem.checkInvariants forged
        |> shouldEqual [ UnixSystemDefect.SocketPhaseKindMismatch (SocketId 0L, kind, phase) ]

    // ------------------------------------------------------------------
    // An open file description's status
    // ------------------------------------------------------------------

    /// A sound system of `platform` with the file `f` open for writing, and the
    /// description its descriptor names.
    let private withOpenFile
        (platform : SimulatedUnixPlatform)
        : UnixSystem<int, string> * int * OpenFileDescriptionId
        =
        let seed =
            Map.ofList
                [
                    DirectoryEntryName.parseOrFail context "f",
                    SeedEntry.File (ImmutableArray<byte>.Empty, PermissionBits.parseOrFail context 0o666, None)
                ]

        match UnixBootImage.tryWithFileSystem epoch Owners.linuxDefault seed (UnixSystem.initial platform) with
        | Error fault -> failwith $"could not build the system: %A{fault}"
        | Ok image ->
            let system =
                (Launched.bootWith (Launched.credentials Owners.root) UnixSystem.pipedStandardStreams 0 (CpuId 0)) image

            let fd, system =
                FcntlWorld.openWith (FcntlWorld.opening FileAccessMode.ReadWrite) "f" system

            match FileDescriptorRegistry.tryFindId fd (Lone.fileDescriptors system) with
            | Some id -> system, fd, id
            | None -> failwith $"fd %d{fd} names no description"

    /// `system` with the description `id`'s status replaced by `status`.
    let private withStatus
        (id : OpenFileDescriptionId)
        (status : OpenFileStatus)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        { system with
            Machine =
                { system.Machine with
                    OpenFiles = OpenFileTable.mapStatus id (fun _ -> status) system.Machine.OpenFiles
                }
        }

    [<Test>]
    let ``a description whose status is another flavour's is a defect`` () : unit =
        for platform, other in
            [
                SimulatedUnixPlatform.linuxX64, SimulatedUnixFlavour.Darwin
                SimulatedUnixPlatform.macOsArm64, SimulatedUnixFlavour.Linux
            ] do
            let system, _, id = withOpenFile platform
            let flavour = SimulatedUnixPlatform.flavour platform

            UnixSystem.checkInvariants system |> shouldEqual []

            let foreign = OpenFileStatus.none other

            system
            |> withStatus id foreign
            |> UnixSystem.checkInvariants
            |> shouldEqual [ UnixSystemDefect.StatusNotOfFlavour (id, foreign, flavour) ]

            // The control: the machine's own flavour's status, with every fact
            // it can hold set.
            let own =
                match flavour with
                | SimulatedUnixFlavour.Linux ->
                    OpenFileStatus.Linux (sync = LinuxSync.FullSync, openedDirectory = true, openedNoFollow = true)
                | SimulatedUnixFlavour.Darwin ->
                    OpenFileStatus.Darwin (synchronous = true, dataSynchronous = true, written = true, flocked = true)

            system |> withStatus id own |> UnixSystem.checkInvariants |> shouldEqual []

    [<Test>]
    let ``a descriptor whose flags are another flavour's is a defect`` () : unit =
        for platform, other in
            [
                SimulatedUnixPlatform.linuxX64, SimulatedUnixFlavour.Darwin
                SimulatedUnixPlatform.macOsArm64, SimulatedUnixFlavour.Linux
            ] do
            let system, fd, _ = withOpenFile platform
            let flavour = SimulatedUnixPlatform.flavour platform

            let withFlags (flags : DescriptorFlags) : UnixSystem<int, string> =
                Lone.withFileDescriptors (FileDescriptorRegistry.setFlags fd flags (Lone.fileDescriptors system)) system

            let foreign = DescriptorFlags.none other

            withFlags foreign
            |> UnixSystem.checkInvariants
            |> shouldEqual
                [
                    UnixSystemDefect.DescriptorFlagsNotOfFlavour (UnixSystem.defaultProcessId, fd, foreign, flavour)
                ]

            // The control: the machine's own flavour's flags, every one set.
            let own =
                match flavour with
                | SimulatedUnixFlavour.Linux -> DescriptorFlags.Linux (closeOnExec = true)
                | SimulatedUnixFlavour.Darwin -> DescriptorFlags.Darwin (closeOnExec = true, closeOnFork = true)

            withFlags own |> UnixSystem.checkInvariants |> shouldEqual []

    [<Test>]
    let ``a Darwin description holding a lock its status does not record is a defect`` () : unit =
        let lockExclusive = 2

        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            let system, fd, id = withOpenFile platform

            let locked =
                match UnixDescriptor.tryFlock (Callers.thread 0 system) fd lockExclusive system with
                | Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system) -> system
                | other -> failwith $"flock: %A{other}"

            UnixSystem.checkInvariants locked |> shouldEqual []

            let unrecorded =
                locked
                |> withStatus id (OpenFileStatus.none (SimulatedUnixPlatform.flavour platform))

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin ->
                UnixSystem.checkInvariants unrecorded
                |> shouldEqual [ UnixSystemDefect.FlockHeldNotRecorded id ]
            // Linux records no grant, so there is nothing to disagree with.
            | SimulatedUnixFlavour.Linux -> UnixSystem.checkInvariants unrecorded |> shouldEqual []

    // ------------------------------------------------------------------
    // The counters, at the boundary rather than past it
    // ------------------------------------------------------------------

    /// `NextConnectionId` equal to a live connection's identity, which is the
    /// state the rule exists for: the next connect mints that identity again
    /// and the two connections become one. A counter strictly *below* a live
    /// identity is caught by a strict comparison too.
    [<Test>]
    let ``NextConnectionId equal to a live connection is a defect`` () : unit =
        let connection = ConnectionId 2L

        let forged =
            (Lone.withFileDescriptors
                (FileDescriptorRegistry.Unchecked.ofParts
                    SimulatedUnixFlavour.Linux
                    (Map.ofList [ 3, OpenFileDescriptionId 0L ])
                    (Map.ofList
                        [
                            OpenFileDescriptionId 0L,
                            {
                                Target = OpenFileTarget.Socket (SocketId 0L)
                                AccessMode = FileAccessMode.ReadWrite
                                NonBlocking = false
                                Flock = None
                                Status = OpenFileStatus.none SimulatedUnixFlavour.Linux
                            }
                        ])
                    (OpenFileDescriptionId 1L))
                { unlaunched with
                    Machine =
                        { unlaunched.Machine with
                            Sockets =
                                Map.ofList
                                    [
                                        SocketId 0L,
                                        {
                                            Addressing = SocketAddressing.Inet None
                                            Kind = SocketKind.Stream
                                            Protocol = SocketProtocol.Tcp
                                            ReuseAddress = false
                                            Options = SocketOptions.initial
                                            Phase = SocketPhase.Established (connection, ConnectionEnd.Client)
                                            Uid = UserId.root
                                        }
                                    ]
                            NextSocketId = SocketId 1L
                            Connections =
                                Map.ofList
                                    [
                                        connection,
                                        {
                                            ClientAddress = Ipv4Endpoint.ofParts Ipv4Address.loopback 40000us
                                            FinsExchangedAt = None
                                            ServerAddress = Ipv4Endpoint.ofParts Ipv4Address.loopback 80us
                                            // No socket is the server end: it has closed.
                                            Transfer =
                                                TcpBufferSizing.newTransfer SocketDomain.Inet unlaunched.Machine
                                                |> TcpTransfer.close
                                                    ConnectionEnd.Server
                                                    false
                                                    PortHold.Reserved
                                                    UserId.root
                                                |> snd
                                        }
                                    ]
                            NextConnectionId = connection
                        }
                })

        UnixSystem.checkInvariants forged
        |> shouldEqual [ UnixSystemDefect.NextConnectionIdNotFresh (connection, connection) ]

    /// A registration stamped with the ordinal the counter is about to mint, so
    /// the next ADD repeats it. The ordinal's whole job is to order same-signal
    /// ties, which a repeat leaves unspecified. Same boundary as the connection
    /// counter above, and untested for the same reason.
    [<Test>]
    let ``a registration ordinal equal to the next to mint is a defect`` () : unit =
        let queueId = OpenFileDescriptionId 0L
        let ordinal = 7L

        let queueState =
            {
                Registrations =
                    Map.ofList
                        [
                            (3, OpenFileDescriptionId 1L),
                            {
                                Events =
                                    EpollEvents.In
                                    ||| EpollEvents.Err
                                    ||| EpollEvents.Hup
                                    ||| EpollEvents.EdgeTriggered
                                Data = 0UL
                                RegisteredAt = ordinal
                            }
                        ]
                Ready = []
            }

        let forged =
            (Lone.withFileDescriptors
                (FileDescriptorRegistry.Unchecked.ofParts
                    SimulatedUnixFlavour.Linux
                    (Map.ofList [ 4, queueId ])
                    (Map.ofList
                        [
                            queueId,
                            {
                                Target = OpenFileTarget.Epoll queueState
                                AccessMode = FileAccessMode.ReadWrite
                                NonBlocking = false
                                Flock = None
                                Status = OpenFileStatus.none SimulatedUnixFlavour.Linux
                            }
                        ])
                    (OpenFileDescriptionId 1L))
                { unlaunched with
                    Machine =
                        { unlaunched.Machine with
                            NextEventRegistrationOrdinal = ordinal
                        }
                })

        // The registration's target, description 1, is no description, which
        // the open file table's own rules report.
        UnixSystem.checkInvariants forged
        |> shouldEqual
            [
                UnixSystemDefect.EventRegistrationOrdinalNotFresh (ordinal, queueId, ordinal)
                UnixSystemDefect.OpenFiles (
                    FileDescriptorRegistryDefect.EpollRegistrationTargetDead (queueId, OpenFileDescriptionId 1L)
                )
            ]

    // ------------------------------------------------------------------
    // A current directory that is not a directory
    // ------------------------------------------------------------------

    /// A system standing in `/outer/inner`, from which both rows below are a
    /// single edit away.
    let private standing : UnixSystem<int, string> =
        let seed =
            Map.ofList
                [
                    DirectoryEntryName.parseOrFail context "outer",
                    SeedEntry.directory (
                        Map.ofList
                            [
                                DirectoryEntryName.parseOrFail context "inner", SeedEntry.directory FileSystemSeed.empty
                                DirectoryEntryName.parseOrFail context "file", SeedEntry.file ImmutableArray<byte>.Empty
                            ]
                    )
                ]

        match
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> UnixBootImage.tryWithFileSystem epoch Owners.linuxDefault seed
        with
        | Ok image ->
            (Launched.bootWith
                (ProcessLaunch.withCurrentDirectory (AbsoluteUnixPath.parseOrFail context "/outer/inner"))
                UnixSystem.pipedStandardStreams
                0
                (CpuId 0))
                image
        | Error fault -> failwith $"the fixture's own seed did not boot: %O{fault}."

    let private inodeOf (path : string) : InodeNumber =
        match
            PathWalk.resolveExisting
                (SimulatedUnixPlatform.pathLimits standing.Machine.UnixPlatform)
                Owners.root
                SymlinkProtection.Off
                (VirtualFileSystem.root standing.Machine.FileSystem)
                SymlinkPolicy.Follow
                (UnixPath.parseOrFail context path)
                standing.Machine.FileSystem
        with
        | Ok inode -> inode
        | Error error -> failwith $"could not resolve %s{path} in the test seed: %O{error}."

    [<Test>]
    let ``a current directory that is a regular file is a defect`` () : unit =
        let file = inodeOf "/outer/file"

        standing
        |> Lone.mapProc (fun proc ->
            { proc with
                CurrentDirectoryInode = file
            }
        )
        |> Lone.restand
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.CurrentDirectoryIsNotADirectory (UnixSystem.defaultProcessId, file)
            ]

    [<Test>]
    let ``a current directory the filesystem does not contain is a defect`` () : unit =
        // The same rule reached by the other input: an inode with no content at
        // all reads as "not a directory" rather than as its own defect, which is
        // what lets one rule cover both. A row asserting only the file case
        // would leave a checker that special-cased `Some` passing.
        let absent = VirtualFileSystem.nextInode standing.Machine.FileSystem

        standing
        |> Lone.mapProc (fun proc ->
            { proc with
                CurrentDirectoryInode = absent
            }
        )
        |> Lone.restand
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.CurrentDirectoryIsNotADirectory (UnixSystem.defaultProcessId, absent)
            ]

    // ------------------------------------------------------------------
    // Threads against the descriptor table
    // ------------------------------------------------------------------

    let private thread : int = 1

    /// `system` with one registered thread, parked as `parked` says.
    let private withThread
        (parked : ParkedSyscall option)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let registered = Threads.ensure thread system

        match parked with
        | None -> registered
        | Some parked -> Lone.Parking.park thread parked registered

    /// `system` with one registered thread, parked as `parked` says on a
    /// description the open file table may not hold, which no syscall parks on.
    let private withForgedThread (parked : ParkedSyscall) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        Threads.ensure thread system |> ForgedPark.onAbsent thread parked

    /// A description id nothing in `system` holds.
    let private absentDescription : OpenFileDescriptionId = OpenFileDescriptionId 999L

    /// `system` with the description stdin names, and every descriptor naming
    /// it, gone from the descriptor table but for the description itself.
    let private stdinUnnamed (system : UnixSystem<int, string>) : OpenFileDescriptionId * UnixSystem<int, string> =
        let stdin =
            FileDescriptorRegistry.tryFindId 0 (Lone.fileDescriptors system) |> Option.get

        // Held while the descriptor goes, so that the description survives
        // it, and let go of afterwards, so that nothing references it.
        let registry =
            match
                FileDescriptorRegistry.dropDescriptor
                    (Lone.proc system).ProcessId
                    0
                    (Lone.fileDescriptors system
                     |> FileDescriptorRegistry.mapOpenFiles (OpenFileTable.hold stdin))
            with
            | Ok (registry, None) -> FileDescriptorRegistry.mapOpenFiles (OpenFileTable.releaseHold stdin) registry
            | other -> failwith $"expected the description to survive, got %A{other}"

        stdin, Lone.withFileDescriptors registry system

    [<Test>]
    let ``a description nothing references is a defect, and one a parked call holds is not`` () : unit =
        let stdin, unnamed = stdinUnnamed system

        UnixSystem.checkInvariants unnamed
        |> shouldEqual [ UnixSystemDefect.UnreferencedDescription stdin ]

        // Held by a read asleep on it, as a read of the launched pipe's empty
        // read end would be.
        unnamed
        |> withThread (
            Some (
                ParkedSyscall.PipeRead
                    {
                        Reader = SleepTarget.Waiting (stdin, 0)
                        Buffer = UserBuffer.Mapped
                        Count = 1
                    }
            )
        )
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    [<Test>]
    let ``a thread parked on an flock of an absent description is a defect`` () : unit =
        system
        |> withForgedThread (
            ParkedSyscall.Flock
                {
                    Requester = absentDescription
                    Mode = FlockMode.Exclusive
                }
        )
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.ParkedOnAbsentDescription (Callers.ofDefault thread, absentDescription)
            ]

    [<Test>]
    let ``a thread parked in an epoll_wait on an absent description is a defect`` () : unit =
        system
        |> withForgedThread (
            ParkedSyscall.EpollWait
                {
                    Epoll = absentDescription
                    MaxEvents = 1
                    Buffer = UserBuffer.Mapped
                    Deadline = None
                }
        )
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.ParkedOnAbsentDescription (Callers.ofDefault thread, absentDescription)
            ]

    [<Test>]
    let ``a thread parked in an epoll_wait on a description that is not an epoll instance is a defect`` () : unit =
        // stdout, which every system holds and which is not an epoll instance.
        let stdoutDescription, target =
            match FileDescriptorRegistry.tryFindWithId 1 (Lone.fileDescriptors system) with
            | Some (id, description) -> id, description.Target
            | None -> failwith "the fixture has no stdout"

        system
        |> withThread (
            Some (
                ParkedSyscall.EpollWait
                    {
                        Epoll = stdoutDescription
                        MaxEvents = 1
                        Buffer = UserBuffer.Mapped
                        Deadline = None
                    }
            )
        )
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.ParkedEpollWaitOnNonEpoll (Callers.ofDefault thread, stdoutDescription, target)
            ]

    /// `system` with threads 1 and 2 parked on stdout's description, in that order.
    let private twoParked : UnixSystem<int, string> =
        let stdoutDescription =
            match FileDescriptorRegistry.tryFindWithId 1 (Lone.fileDescriptors system) with
            | Some (id, _) -> id
            | None -> failwith "the fixture has no stdout"

        let parked =
            ParkedSyscall.Flock
                {
                    Requester = stdoutDescription
                    Mode = FlockMode.Shared
                }

        system
        |> Threads.ensure 1
        |> Threads.ensure 2
        |> Lone.Parking.park 1 parked
        |> Lone.Parking.park 2 parked

    /// `system` with thread `name`'s park stamped `ordinal`, as only a record copy past
    /// `Parking.park` could.
    let private forgeOrdinal (name : int) (ordinal : ParkOrdinal) (system : UnixSystem<int, string>) =
        let thread = Lone.thread name system

        system
        |> ForgedThread.withState
            (Callers.thread name system)
            { thread with
                Parked =
                    thread.Parked
                    |> Option.map (fun park ->
                        { park with
                            Ordinal = ordinal
                        }
                    )
            }

    [<Test>]
    let ``parks minted by UnixWait are sound`` () : unit =
        UnixSystem.checkInvariants twoParked |> shouldEqual []

    [<Test>]
    let ``two parks stamped with one ordinal are a defect`` () : unit =
        let first = (Lone.parkOf 1 twoParked |> Option.get).Ordinal

        forgeOrdinal 2 first twoParked
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.DuplicateParkOrdinal first ]

    [<Test>]
    let ``a park stamped at or past the next ordinal is a defect`` () : unit =
        let next = twoParked.Machine.NextParkOrdinal

        forgeOrdinal 2 next twoParked
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.ParkOrdinalNotFresh (next, Callers.ofDefault 2, next) ]

    /// The control for the three rows above: a park onto a live object of the
    /// right kind is sound, so those rows are not passing because every park
    /// is reported.
    [<Test>]
    let ``a thread parked on a live epoll instance or file is sound`` () : unit =
        let queueFd, registry =
            FileDescriptorRegistry.createEpoll
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                (Lone.fileDescriptors system)

        let queueId =
            match FileDescriptorRegistry.tryFindWithId queueFd registry with
            | Some (id, _) -> id
            | None -> failwith "the epoll instance just created is not in the table"

        let stdoutDescription =
            match FileDescriptorRegistry.tryFindWithId 1 registry with
            | Some (id, _) -> id
            | None -> failwith "the fixture has no stdout"

        let queueSystem = Lone.withFileDescriptors registry system

        queueSystem
        |> withThread (
            Some (
                ParkedSyscall.EpollWait
                    {
                        Epoll = queueId
                        MaxEvents = 1
                        Buffer = UserBuffer.Mapped
                        Deadline = None
                    }
            )
        )
        |> UnixSystem.checkInvariants
        |> shouldEqual []

        queueSystem
        |> withThread (
            Some (
                ParkedSyscall.Flock
                    {
                        Requester = stdoutDescription
                        Mode = FlockMode.Shared
                    }
            )
        )
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    // ------------------------------------------------------------------
    // Sockets whose binding cannot have come from bind or listen
    // ------------------------------------------------------------------

    let private streamSocket (binding : Ipv4Binding option) (phase : SocketPhase) : SocketDescription =
        {
            Addressing = SocketAddressing.Inet binding
            Kind = SocketKind.Stream
            Protocol = SocketProtocol.Tcp
            ReuseAddress = false
            Options = SocketOptions.initial
            Phase = phase
            Uid = UserId.root
        }

    /// `system` holding one socket, open on a descriptor so that the socket
    /// table's own rules are satisfied.
    let private withSocket (socket : SocketDescription) : SocketId * UnixSystem<int, string> =
        let socketId = system.Machine.NextSocketId
        let (SocketId raw) = socketId

        let _, registry =
            FileDescriptorRegistry.createSocket
                (SimulatedUnixPlatform.flavour system.Machine.UnixPlatform)
                socketId
                (Lone.fileDescriptors system)

        socketId,
        { system with
            Machine =
                { system.Machine with
                    Sockets = Map.add socketId socket system.Machine.Sockets
                    NextSocketId = SocketId (raw + 1L)
                }
        }
        |> Lone.withFileDescriptors registry

    let private boundAt (port : uint16) : Ipv4Binding option =
        Some
            {
                Endpoint = Ipv4Endpoint.ofParts Ipv4Address.loopback port
                LockedAddress = None
                LockedPort = false
                PortHold = PortHold.Reserved
            }

    let private listening : SocketPhase =
        SocketPhase.Listening
            {
                Backlog = 8
                Queue = []
                Drained = false
            }

    [<Test>]
    let ``a listener without a binding is a defect`` () : unit =
        let socketId, faulty = withSocket (streamSocket None listening)

        UnixSystem.checkInvariants faulty
        |> shouldEqual [ UnixSystemDefect.ListenerWithoutBinding socketId ]

        // The control: a bound listener is sound.
        let _, sound = withSocket (streamSocket (boundAt 5000us) listening)
        UnixSystem.checkInvariants sound |> shouldEqual []

    /// A socket that can hold no address cannot have reached a phase only an
    /// addressed socket reaches.
    [<Test>]
    let ``an unaddressable socket with a latched refusal is a defect`` () : unit =
        let refused = SocketPhase.Refused RefusalError.Pending

        for addressing in [ SocketAddressing.Inet6V6Only None ; SocketAddressing.Unix None ] do
            let socketId, faulty =
                withSocket
                    { streamSocket None refused with
                        Addressing = addressing
                    }

            UnixSystem.checkInvariants faulty
            |> shouldEqual [ UnixSystemDefect.UnaddressableSocketInPhase (socketId, addressing, refused) ]

            // The control: idle, it is sound.
            let _, sound =
                withSocket
                    { streamSocket None SocketPhase.Idle with
                        Addressing = addressing
                    }

            UnixSystem.checkInvariants sound |> shouldEqual []

    let private ipv6Binding : Ipv6Binding =
        {
            Endpoint =
                {
                    Address = Ipv6Address.loopback
                    Port = 5000us
                    FlowInfo = 0u
                    ScopeId = 0u
                }
            LockedAddress = Some Ipv6Address.loopback
            LockedPort = true
            PortHold = PortHold.Reserved
        }

    let private socketName : UnixSocketName =
        match UnixByteString.ofString "/tmp/socket" with
        | Ok path -> UnixSocketName.ofPath path
        | Error defect -> failwith $"%s{context}: /tmp/socket is not a path: %A{defect}"

    /// No syscall binds a socket natively over IPv6 or names a Unix-domain
    /// socket yet, so a socket holding such a binding was assembled some other
    /// way.
    [<Test>]
    let ``a socket holding a binding no syscall makes is a defect`` () : unit =
        let unmodelled =
            [
                SocketAddressing.Inet6V6Only (Some ipv6Binding)
                SocketAddressing.Inet6DualMode (Some (DualModeBinding.Native ipv6Binding))
                SocketAddressing.Unix (Some socketName)
            ]

        for addressing in unmodelled do
            let socketId, faulty =
                withSocket
                    { streamSocket None SocketPhase.Idle with
                        Addressing = addressing
                    }

            UnixSystem.checkInvariants faulty
            |> shouldEqual [ UnixSystemDefect.UnmodelledBindingHeld (socketId, addressing) ]

        // The controls: each family unbound, and a dual-mode socket holding
        // its IPv4 transport, are sound.
        let sound =
            [
                SocketAddressing.Inet6V6Only None
                SocketAddressing.Inet6DualMode None
                SocketAddressing.Inet6DualMode (boundAt 5000us |> Option.map DualModeBinding.Mapped)
                SocketAddressing.Unix None
            ]

        for addressing in sound do
            let _, sound =
                withSocket
                    { streamSocket None SocketPhase.Idle with
                        Addressing = addressing
                    }

            UnixSystem.checkInvariants sound |> shouldEqual []

    /// `connect(2)` gives a datagram socket a peer in its own family only.
    [<Test>]
    let ``a datagram peer in another family is a defect`` () : unit =
        let datagramSocket (peer : SocketAddress) : SocketDescription =
            { streamSocket (boundAt 5000us) (SocketPhase.DatagramPeer peer) with
                Kind = SocketKind.Datagram
                Protocol = SocketProtocol.Udp
            }

        let foreignPeers =
            [
                SocketAddress.Inet6
                    {
                        Address = Ipv6Address.loopback
                        Port = 6000us
                        FlowInfo = 0u
                        ScopeId = 0u
                    }
                SocketAddress.Unix socketName
            ]

        for peer in foreignPeers do
            let socketId, faulty = withSocket (datagramSocket peer)

            UnixSystem.checkInvariants faulty
            |> shouldEqual
                [
                    UnixSystemDefect.DatagramPeerOfAnotherFamily (socketId, SocketDomain.Inet, peer)
                ]

        // The control: an IPv4 socket's IPv4 peer is sound.
        let _, sound =
            withSocket (datagramSocket (SocketAddress.Inet (Ipv4Endpoint.ofParts Ipv4Address.loopback 6000us)))

        UnixSystem.checkInvariants sound |> shouldEqual []

    /// `SocketPhase.Connecting` is reserved: nothing puts a socket in it yet, so
    /// a socket in it is a defect, which is what makes "nothing does" checked
    /// wherever a fuzzer checks invariants.
    [<Test>]
    let ``a connecting socket is a ReservedSocketPhase defect`` () : unit =
        let destination =
            SocketAddress.Inet (Ipv4Endpoint.ofParts Ipv4Address.loopback 6000us)

        let phase =
            SocketPhase.Connecting
                {
                    ConnectAttempt.Destination = destination
                }

        let socketId, faulty = withSocket (streamSocket (boundAt 5000us) phase)

        UnixSystem.checkInvariants faulty
        |> shouldEqual [ UnixSystemDefect.ReservedSocketPhase (socketId, phase) ]

    /// Only a refused TCP connect gives a port back, and under Linux only a
    /// port `bind(2)` did not choose: a socket that gave its port back is a
    /// refused stream socket, or one Linux's refusal left idle. (This system
    /// is Linux's.)
    [<Test>]
    let ``a port given back outside a refusal is a defect`` () : unit =
        let givenBack (lockedPort : bool) : Ipv4Binding option =
            Some
                {
                    Endpoint = Ipv4Endpoint.ofParts Ipv4Address.any 5000us
                    LockedAddress = Some Ipv4Address.any
                    LockedPort = lockedPort
                    PortHold = PortHold.GivenBack
                }

        let faulty =
            [
                streamSocket (givenBack false) listening
                // Linux keeps a port bind(2) chose.
                streamSocket (givenBack true) SocketPhase.Idle
                streamSocket (givenBack true) (SocketPhase.Refused RefusalError.Reported)
                { streamSocket (givenBack false) SocketPhase.Idle with
                    Kind = SocketKind.Datagram
                    Protocol = SocketProtocol.Udp
                }
            ]

        for socket in faulty do
            let socketId, faulty = withSocket socket

            UnixSystem.checkInvariants faulty
            |> shouldEqual [ UnixSystemDefect.PortGivenBackOutsideRefusal (socketId, socket.Phase) ]

        // The controls: what a Linux refusal leaves, delivered or latched.
        for phase in [ SocketPhase.Idle ; SocketPhase.Refused RefusalError.Pending ] do
            let _, sound = withSocket (streamSocket (givenBack false) phase)
            UnixSystem.checkInvariants sound |> shouldEqual []

    [<Test>]
    let ``a socket bound to port 0 is a defect`` () : unit =
        let socketId, faulty = withSocket (streamSocket (boundAt 0us) SocketPhase.Idle)

        UnixSystem.checkInvariants faulty
        |> shouldEqual [ UnixSystemDefect.BoundToPortZero socketId ]

        let _, sound = withSocket (streamSocket (boundAt 1us) SocketPhase.Idle)
        UnixSystem.checkInvariants sound |> shouldEqual []

    // ------------------------------------------------------------------
    // Signals against the thread table
    // ------------------------------------------------------------------

    let private withSignals
        (signals : SignalState<int, string>)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        system
        |> Lone.mapProc (fun proc ->
            { proc with
                Signals = signals
            }
        )

    [<Test>]
    let ``handler frames for a thread the table does not hold are a defect`` () : unit =
        // Thread 42 in a handler, in a state that is then given to a system
        // without it.
        let inHandler (inside : int) : SignalState<int, string> =
            SignalState.initial SignalNumbering.Linux Set.empty
            |> HandlerFrames.enter
                SignalNumbering.Linux
                "h"
                0
                (Set.ofList [ 0 ; inside ])
                inside
                (Set.singleton Signal.SIGINT)

        system
        |> withThread None
        |> withSignals (inHandler 42)
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.HandlerFramesWithoutThread (Callers.ofDefault 42)
                UnixSystemDefect.MaskWithoutThread (Callers.ofDefault 42)
            ]

        system
        |> withThread None
        |> withSignals (inHandler thread)
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    [<Test>]
    let ``a mask for a thread the table does not hold is a defect`` () : unit =
        let blocking (thread : int) : SignalState<int, string> =
            SignalState.initial SignalNumbering.Linux Set.empty
            |> SignalState.changeMask
                SignalNumbering.Linux
                SignalMaskChange.Block
                (SignalMask.ofSignals SignalNumbering.Linux (Set.singleton Signal.SIGINT))
                thread

        system
        |> withThread None
        |> withSignals (blocking 42)
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.MaskWithoutThread (Callers.ofDefault 42) ]

        system
        |> withThread None
        |> withSignals (blocking thread)
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    [<Test>]
    let ``a pending signal directed at a thread the table does not hold is a defect`` () : unit =
        let directedAt (target : int voption) : SignalState<int, string> =
            SignalState.initial SignalNumbering.Linux Set.empty
            |> SignalState.enqueue
                SignalNumbering.Linux
                {
                    Signal = Signal.SIGCHLD
                    Target = target
                }

        system
        |> withThread None
        |> withSignals (directedAt (ValueSome 43))
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.PendingSignalTargetWithoutThread (Callers.ofDefault 43, Signal.SIGCHLD)
            ]

        // Directed at a live thread, or at the process, whose leader takes
        // it: sound, the thread it is deliverable to owing a return to user
        // mode, as it would had the signal been sent.
        system
        |> withThread None
        |> withSignals (directedAt (ValueSome thread))
        |> ForgedThread.owing (Callers.thread thread system) OwedReturn.SignalDue
        |> UnixSystem.checkInvariants
        |> shouldEqual []

        system
        |> withThread None
        |> withSignals (directedAt ValueNone)
        |> ForgedThread.owing (Callers.leader system) OwedReturn.SignalDue
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    /// A thread in no syscall that a signal is deliverable to and that owes no
    /// return to user mode is a defect; a parked thread, one that owes the
    /// return, and one the signal is not deliverable to are not.
    [<Test>]
    let ``a thread a signal is deliverable to that owes no return is a defect`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            let numbering = SimulatedUnixPlatform.signalNumbering platform

            let booted =
                UnixSystem.initial<int, string> platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
                |> Threads.ensure thread

            let pendingOn (target : int voption) (blockedBy : int list) : UnixSystem<int, string> =
                let signals =
                    (SignalState.initial numbering Set.empty, blockedBy)
                    ||> List.fold (fun signals blocker ->
                        SignalState.changeMask
                            numbering
                            SignalMaskChange.Block
                            (SignalMask.ofSignals numbering (Set.singleton Signal.SIGUSR1))
                            blocker
                            signals
                    )
                    |> SignalState.enqueue
                        numbering
                        {
                            Signal = Signal.SIGUSR1
                            Target = target
                        }

                booted |> withSignals signals

            let undue (thread : int) : UnixSystemDefect<int> =
                UnixSystemDefect.SignalDeliverableWithoutOwedReturn (Callers.ofDefault thread, Signal.SIGUSR1)

            let owes (thread : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
                ForgedThread.owing (Callers.thread thread system) OwedReturn.SignalDue system

            let check (system : UnixSystem<int, string>) : UnixSystemDefect<int> list =
                UnixSystem.checkInvariants system

            // Its own signal, unblocked: a defect until it owes the return, and
            // none while it sleeps or blocks the signal.
            pendingOn (ValueSome thread) [] |> check |> shouldEqual [ undue thread ]
            pendingOn (ValueSome thread) [] |> owes thread |> check |> shouldEqual []

            let asleep =
                let pending = pendingOn (ValueSome thread) []

                pending
                |> withSignals (SignalState.suspend numbering thread SignalMask.empty (Lone.proc pending).Signals)
                |> Lone.Parking.park thread ParkedSyscall.SigSuspend

            asleep |> check |> shouldEqual []

            pendingOn (ValueSome thread) [ thread ] |> check |> shouldEqual []

            // The process's signal is the leader's to take, unless it blocks
            // it, when under Linux another thread that does not takes it.
            pendingOn ValueNone [] |> check |> shouldEqual [ undue 0 ]
            pendingOn ValueNone [] |> owes 0 |> check |> shouldEqual []

            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> pendingOn ValueNone [ 0 ] |> check |> shouldEqual [ undue thread ]
            | SimulatedUnixFlavour.Darwin -> pendingOn ValueNone [ 0 ] |> check |> shouldEqual []

            pendingOn ValueNone [ 0 ; thread ] |> check |> shouldEqual []

    [<Test>]
    let ``a mount the flavour cannot report is a defect`` () : unit =
        // Reachable only by assembling the record by hand: `UnixSystem.initial`
        // derives the type from the flavour, and
        // `UnixBootImage.withMount` refuses one the machine's
        // flavour cannot mount.
        let linux =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        { linux with
            Machine =
                { linux.Machine with
                    Mount = EmulatedMount.Apfs ApfsMount.defaults
                }
        }
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.FileSystemTypeNotReportable (SimulatedUnixFlavour.Linux, EmulatedFileSystemType.Apfs)
            ]

        // A hand-built machine whose pair does describe one system is sound.
        UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)
        |> fun darwin ->
            { darwin with
                Machine =
                    { darwin.Machine with
                        Mount = EmulatedMount.Nfs
                    }
            }
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    [<Test>]
    let ``a mounted filesystem the machine's device mount does not name is a defect`` () : unit =
        // Reachable only by assembling the record by hand: `UnixSystem.initial`
        // derives the device mount from the flavour, and mounts what it says.
        let linux =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let devRoot =
            VirtualFileSystem.mounts linux.Machine.FileSystem
            |> Map.toList
            |> List.exactlyOne
            |> fst

        UnixSystem.checkInvariants linux |> shouldEqual []

        { linux with
            Machine =
                { linux.Machine with
                    DeviceMount = DeviceFileSystemMount.Devfs
                }
        }
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.MountNotDeviceMount (devRoot, MountedFileSystem.Devtmpfs, MountedFileSystem.Devfs)
            ]

    // ------------------------------------------------------------------
    // Thread IDs. Every one of these is reachable only by a record copy past
    // `UnixSystem.initial`, `UnixThreadLifecycle.spawn` and the identity setters.

    let private spawned (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let booted =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        match UnixThreadLifecycle.trySpawn (Callers.thread 0 booted) 1 (CpuId 0) booted with
        | Ok (SpawnAnswer.Spawned _, system) -> system
        | Ok (SpawnAnswer.Failed error, _) -> failwith $"spawn failed: %O{error}"
        | Error refusal -> failwith $"spawn was refused: %s{SpawnRefusal.describe refusal}"

    [<Test>]
    let ``a leader that is not a thread is a defect`` () : unit =
        let system = spawned SimulatedUnixPlatform.linuxX64

        system
        |> Lone.withLeader 7
        |> UnixSystem.checkInvariants
        |> shouldEqual [ UnixSystemDefect.LeaderWithoutThread (Callers.ofDefault 7) ]

    [<Test>]
    let ``two threads with one thread ID are a defect`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            let system = spawned platform
            let leader = Lone.thread 0 system

            system
            |> ForgedThread.withState
                (Callers.thread 1 system)
                { Lone.thread 1 system with
                    OsThreadId = leader.OsThreadId
                }
            |> UnixSystem.checkInvariants
            |> shouldEqual
                [
                    UnixSystemDefect.DuplicateOsThreadId (leader.OsThreadId, List.map Callers.ofDefault [ 0 ; 1 ])
                    // Thread 1's own ID, which the allocator still records, is
                    // held by no thread now.
                    UnixSystemDefect.LiveThreadIdsMismatch (
                        Set.singleton (UnixThreadState.osThreadId (Lone.thread 1 system)),
                        Set.empty
                    )
                ]

    [<Test>]
    let ``on Linux a leader whose thread ID is not the process ID is a defect, and on Darwin it is not`` () : unit =
        let seventeen = ProcessId.parseOrFail "test" 17

        // The process, its ID 17 everywhere the kernel records it, but its
        // leader's thread ID.
        let moved (system : UnixSystem<int, string>) : UnixSystem<int, string> =
            let pid = Lone.pid system
            let slot = ProcessTable.find "test" (ProcessId.toInt32 pid) system.Processes

            { system with
                Machine =
                    { system.Machine with
                        ProcessIds =
                            system.Machine.ProcessIds
                            |> ProcessIdTable.remove pid
                            |> ProcessIdTable.add seventeen
                    }
                Processes =
                    ProcessTable.empty
                    |> ProcessTable.add
                        (ProcessId.toInt32 seventeen)
                        { slot with
                            Process =
                                { slot.Process with
                                    ProcessId = seventeen
                                }
                        }
            }

        let linux = spawned SimulatedUnixPlatform.linuxX64

        moved linux
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.LeaderThreadIdNotProcessId (
                    Caller.make seventeen 0,
                    UnixThreadState.osThreadId (Lone.thread 0 linux),
                    ProcessId.parseOrFail "test" 17
                )
            ]

        moved (spawned SimulatedUnixPlatform.macOsArm64)
        |> UnixSystem.checkInvariants
        |> shouldEqual []

    [<Test>]
    let ``a thread ID the counter could not have handed out is a defect`` () : unit =
        // Linux: a live tid no pid_max admits, by taking one from a Darwin
        // machine. A tid at or above the pid_max now in force is not one, because
        // the administrator may lower pid_max beneath live ids.
        let linux = spawned SimulatedUnixPlatform.linuxX64

        linux
        |> UnixSystem.writePidMaxSysctl 1000
        |> UnixSystem.checkInvariants
        |> shouldEqual []

        let withDarwinId (id : uint64) : OsThreadId * UnixSystem<int, string> =
            let foreign =
                (UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64
                 |> Launched.leaderThreadId id
                 |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0))
                |> Lone.thread 0
                |> UnixThreadState.osThreadId

            let replaced = UnixThreadState.osThreadId (Lone.thread 1 linux)

            foreign,
            { linux with
                Machine =
                    { linux.Machine with
                        // Recording the foreign ID as live in place of the one it
                        // replaces, so that what the counter could have minted is
                        // all that is wrong.
                        ThreadIds =
                            { linux.Machine.ThreadIds with
                                Live = linux.Machine.ThreadIds.Live |> Set.remove replaced |> Set.add foreign
                            }
                    }
            }
            |> ForgedThread.withState
                (Callers.thread 1 linux)
                { Lone.thread 1 linux with
                    OsThreadId = foreign
                }

        let _, below = withDarwinId 4194303UL
        UnixSystem.checkInvariants below |> shouldEqual []

        let foreign, at = withDarwinId 4194304UL

        UnixSystem.checkInvariants at
        |> shouldEqual
            [
                UnixSystemDefect.OsThreadIdNotMintable (Callers.ofDefault 1, foreign, at.Machine.ThreadIds)
            ]

        // Darwin: an id the counter has not reached, which it would hand out again.
        let darwin = spawned SimulatedUnixPlatform.macOsArm64

        let behind =
            (UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64
             |> Launched.leaderThreadId 4242UL
             |> (Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)))
                .Machine.ThreadIds
            |> fun behind ->
                { behind with
                    Live = darwin.Machine.ThreadIds.Live
                }

        { darwin with
            Machine =
                { darwin.Machine with
                    ThreadIds = behind
                }
        }
        |> UnixSystem.checkInvariants
        |> shouldEqual
            [
                UnixSystemDefect.OsThreadIdNotMintable (
                    Callers.ofDefault 1,
                    UnixThreadState.osThreadId (Lone.thread 1 darwin),
                    behind
                )
            ]

    [<Test>]
    let ``a thread ID counter of the other flavour is a defect`` () : unit =
        let linux =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.linuxX64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let darwin =
            UnixSystem.initial<int, string> SimulatedUnixPlatform.macOsArm64
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let swapped (system : UnixSystem<int, string>) (from : UnixSystem<int, string>) =
            { system with
                Machine =
                    { system.Machine with
                        ThreadIds = from.Machine.ThreadIds
                    }
            }
            |> UnixSystem.checkInvariants

        // Both leaders are 4242 and both counters are past it, so the flavour is all
        // that is wrong.
        swapped linux darwin
        |> shouldEqual
            [
                UnixSystemDefect.ThreadIdAllocatorNotOfFlavour (SimulatedUnixFlavour.Linux, darwin.Machine.ThreadIds)
            ]

        swapped darwin linux
        |> shouldEqual
            [
                UnixSystemDefect.ThreadIdAllocatorNotOfFlavour (SimulatedUnixFlavour.Darwin, linux.Machine.ThreadIds)
            ]
