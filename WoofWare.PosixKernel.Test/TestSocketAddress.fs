namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `SocketAddress` and `UnixSocketName`: what a name reads back as, and the
/// family of the address a `bind(2)` or `listen(2)` answers.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSocketAddress =

    let private byteGen : Gen<byte> = ArbMap.defaults |> ArbMap.generate<byte>

    /// A non-empty NUL-free byte string, often printable, sometimes not.
    let private pathGen : Gen<UnixByteString> =
        gen {
            let! length = Gen.choose (1, 110)

            let! bytes =
                Gen.arrayOfLength
                    length
                    (Gen.frequency
                        [
                            3, Gen.map byte (Gen.choose (0x20, 0x7E))
                            1, Gen.choose (1, 255) |> Gen.map byte
                        ])

            return
                match UnixByteString.ofBytes (ImmutableArray.Create<byte> bytes) with
                | Ok path -> path
                | Error defect -> failwith $"the generator made a byte string with a NUL: %A{defect}"
        }

    /// Any bytes, NULs included, and possibly none.
    let private abstractGen : Gen<byte[]> =
        gen {
            let! length = Gen.choose (0, 107)
            return! Gen.arrayOfLength length (Gen.frequency [ 2, byteGen ; 1, Gen.constant 0uy ])
        }

    [<Test>]
    let ``a path name's view reads back the path it was made from`` () : unit =
        let property (path : UnixByteString) : unit =
            match UnixSocketName.view (UnixSocketName.ofPath path) with
            | UnixSocketNameView.Path viewed -> viewed |> shouldEqual path
            | other -> failwith $"%A{path} was viewed as %A{other}"

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 500, Prop.forAll (Arb.fromGen pathGen) property)

    /// And the name owns its bytes: changing the array a caller built it
    /// from afterwards changes nothing.
    [<Test>]
    let ``an abstract name's view reads back the bytes it was made from`` () : unit =
        let property (bytes : byte[]) : unit =
            let name = UnixSocketName.ofAbstractName (ImmutableArray.Create<byte> bytes)

            match UnixSocketName.view name with
            | UnixSocketNameView.Abstract viewed ->
                Seq.toArray viewed |> shouldEqual bytes
                // The view's equality is the bytes', not the arrays'.
                UnixSocketName.view name
                |> shouldEqual (UnixSocketNameView.Abstract (ImmutableArray.Create<byte> (Array.copy bytes)))
            | other -> failwith $"%A{bytes} was viewed as %A{other}"

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 500, Prop.forAll (Arb.fromGen abstractGen) property)

    /// Two names are equal, and render alike, exactly when they are the same
    /// name: the private representation's equality is the bytes', and
    /// `toString` is injective.
    [<Test>]
    let ``names are equal, and render alike, exactly when they are the same name`` () : unit =
        let nameGen : Gen<UnixSocketName> =
            Gen.oneof
                [
                    Gen.map UnixSocketName.ofPath pathGen
                    Gen.map
                        (fun (bytes : byte[]) -> UnixSocketName.ofAbstractName (ImmutableArray.Create<byte> bytes))
                        abstractGen
                    // Short ones, so that two independent draws often coincide.
                    Gen.elements [ "a" ; "\\" ; "\\x00" ; "@" ]
                    |> Gen.map (fun text ->
                        match UnixByteString.ofString text with
                        | Ok path -> UnixSocketName.ofPath path
                        | Error _ -> failwith $"%s{text} is not a byte string"
                    )
                    Gen.elements [ [||] ; [| 0uy |] ; [| byte 'a' |] ; [| 0x5Cuy |] ; [| 0uy ; 0uy |] ]
                    |> Gen.map (fun (bytes : byte[]) ->
                        UnixSocketName.ofAbstractName (ImmutableArray.Create<byte> bytes)
                    )
                ]

        let same (a : UnixSocketName) (b : UnixSocketName) : bool =
            match UnixSocketName.view a, UnixSocketName.view b with
            | UnixSocketNameView.Path a, UnixSocketNameView.Path b -> a = b
            | UnixSocketNameView.Abstract a, UnixSocketNameView.Abstract b -> Seq.toArray a = Seq.toArray b
            | _ -> false

        let property (a : UnixSocketName, b : UnixSocketName) : unit =
            (a = b) |> shouldEqual (same a b)
            (hash a = hash b || not (same a b)) |> shouldEqual true
            (compare a b = 0) |> shouldEqual (same a b)

            (UnixSocketName.toString a = UnixSocketName.toString b)
            |> shouldEqual (same a b)

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 2000,
            Prop.forAll (Arb.fromGen (Gen.zip nameGen nameGen)) property
        )

    [<Test>]
    let ``an abstract name renders as its whole sun_path`` () : unit =
        ImmutableArray.Create<byte> [| byte 'a' ; 0uy ; 0x5Cuy ; 0xFFuy |]
        |> UnixSocketName.ofAbstractName
        |> SocketAddress.Unix
        |> SocketAddress.toString
        |> shouldEqual "\\x00a\\x00\\\\\\xff"

    // ------------------------------------------------------------------
    // The family of a bind's or a listen's answer
    // ------------------------------------------------------------------

    [<RequireQualifiedAccess>]
    type private Family =
        /// The socket's own: `AF_INET` on an IPv4 socket, `AF_INET6` on an
        /// IPv6 one, and `AF_INET` on a Unix-domain one, which is refused
        /// before its sockaddr is read.
        | Own
        | Inet
        | Inet6
        | Unspec

    [<RequireQualifiedAccess>]
    type private Op =
        /// `socket(2)` of `NewSocket.requests.[shape]`, then, on an IPv6
        /// socket, `IPV6_V6ONLY` set to `v6Only` if there is one.
        | NewSocket of shape : int * v6Only : int option
        /// `bind(2)` of `addresses.[address]` at `port`, in `family`, declared
        /// `length` long.
        | Bind of slot : int * family : Family * address : int * port : uint16 * length : uint32
        | Listen of slot : int
        /// `connect(2)` to `addresses.[address]` at `port`, in the socket's
        /// own family.
        | Connect of slot : int * address : int * port : uint16

    /// IPv4 addresses, each also bound v4-mapped from an IPv6 sockaddr: the
    /// wildcard, loopback, another local one, a foreign one and a multicast
    /// group. `None` is a native IPv6 address, `::1`.
    let private addresses : Ipv4Address option list =
        [
            Some Ipv4Address.any
            Some Ipv4Address.loopback
            Some Ipv4Address.loopback
            Some (Ipv4Address 0x7F000002u)
            Some (Ipv4Address 0x0A000001u)
            Some (Ipv4Address 0xE0000001u)
            None
        ]

    let private ports : uint16 list = [ 0us ; 5000us ; 5000us ; 5001us ]

    let private opGen : Gen<Op> =
        let slot = Gen.choose (0, 3)
        let address = Gen.choose (0, addresses.Length - 1)
        let port = Gen.elements ports

        Gen.frequency
            [
                3,
                Gen.map2
                    (fun shape v6Only -> Op.NewSocket (shape, v6Only))
                    (Gen.choose (0, NewSocket.requests.Length - 1))
                    (Gen.elements [ None ; Some 0 ; Some 1 ])
                5,
                gen {
                    let! slot = slot

                    let! family =
                        Gen.frequency
                            [
                                6, Gen.constant Family.Own
                                1, Gen.elements [ Family.Inet ; Family.Inet6 ; Family.Unspec ]
                            ]

                    let! address = address
                    let! port = port
                    let! length = Gen.elements [ 16u ; 24u ; 28u ; 28u ; 28u ; 128u ]
                    return Op.Bind (slot, family, address, port, length)
                }
                2, Gen.map Op.Listen slot
                2, Gen.map3 (fun s a p -> Op.Connect (s, a, p)) slot address port
            ]

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    /// The bytes a sockaddr argument holds for `address` at `port`, laid out
    /// for `family`: a `struct sockaddr_in6` for `AF_INET6` (v4-mapped for an
    /// IPv4 address), and a `struct sockaddr_in` otherwise.
    let private sockaddr
        (platform : SimulatedUnixPlatform)
        (familyNumber : int)
        (address : Ipv4Address option)
        (port : uint16)
        : byte[]
        =
        let inet6 = SimulatedUnixPlatform.internetV6AddressFamily platform

        match address with
        | Some v4 when familyNumber <> inet6 -> CopyIn.blob platform familyNumber (Ipv4Endpoint.ofParts v4 port)
        | Some (Ipv4Address v4) -> CopyIn.blob6 platform familyNumber (CopyIn.mappedAddress v4) port
        | None -> CopyIn.blob6 platform familyNumber (Ipv6Address.toBytes Ipv6Address.loopback) port

    /// What `getsockname(2)` would copy out for `address`, by the library's
    /// own encoders, which `TestSockaddrLayoutAgainstHost` checks against the
    /// host's.
    let private encoded (platform : SimulatedUnixPlatform) (address : SocketAddress) : byte[] =
        match address with
        | SocketAddress.Inet endpoint -> SimulatedUnixPlatform.encodeInternetSockaddr platform endpoint
        | SocketAddress.Inet6 endpoint -> SimulatedUnixPlatform.encodeInternetV6Sockaddr platform endpoint
        | SocketAddress.Unix name -> failwith $"no layout for the Unix-domain name %s{UnixSocketName.toString name}"

    /// How many answers the property checked, over every case: those from
    /// an IPv4 socket, those from an IPv6 one, and those of a listen.
    type private Seen =
        {
            mutable Inet : int
            mutable Inet6 : int
            mutable Listens : int
        }

    /// `UnixSystem.tryStep` of `call` by the process's leader in `system`.
    let private stepped
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : Result<SteppedCall<int, string>, SyscallRefusal<int>>
        =
        UnixSystem.tryStep (Callers.leader system) call system

    /// Fails the test: `call` answered `other`, which is not its own case.
    let private unexpected<'a> (call : Syscall<int, string>) (other : SteppedCall<int, string>) : 'a =
        failwith $"Syscall.%s{UnionCaseName.ofValue call} answered SteppedCall.%s{UnionCaseName.ofValue other}"

    /// Fails the test unless `answered`, what `UnixSystem.tryStep` answered
    /// for `setsockopt(fd, level, name, value, 4)` in `system`, is what the
    /// same call answers made a step at a time (admitting the copy, then
    /// `trySetsockoptBytes` of the bytes it admits): the same answer, leaving
    /// the same system, or the same refusal.
    let private requireSetAlike
        (fd : int)
        (level : int)
        (name : int)
        (value : ImmutableArray<byte>)
        (answered : Result<SteppedCall<int, string>, SyscallRefusal<int>>)
        (system : UnixSystem<int, string>)
        : unit
        =
        let supplied =
            match Lone.UnixSocket.tryAdmitSetSockOpt fd level name UserBuffer.Mapped 4u system with
            | Ok (SetSockOptAdmission.Transfer count) -> Some (ImmutableArray.Create (value, 0, count))
            | Ok SetSockOptAdmission.NoCopy
            | Ok (SetSockOptAdmission.Answered _)
            | Error _ -> None

        let throughSteps =
            Lone.UnixSocket.trySetsockoptBytes fd level name UserBuffer.Mapped 4u supplied system

        match answered, throughSteps with
        | Ok (SteppedCall.SetSockOpt (answer, after)), Ok (stepsAnswer, stepsAfter) when
            answer = stepsAnswer && after = stepsAfter
            ->
            ()
        | Error (SyscallRefusal.SetSockOpt refusal), Error stepsRefusal when refusal = stepsRefusal -> ()
        | _ ->
            failwith
                $"setsockopt(%d{fd}, %d{level}, %d{name}): UnixSystem.tryStep answered %A{Result.map UnionCaseName.ofValue answered}, and the call made a step at a time %A{Result.map fst throughSteps}, or left another system"

    /// Fails the test unless `answered`, what `UnixSystem.tryStep` answered
    /// for `bind(fd, blob, length)` in `system`, is what the same bind answers
    /// through the call's own functions, held to it made a step at a time
    /// (`CopyIn.bind`), as `requireSetAlike` holds a set.
    let private requireBoundAlike
        (fd : int)
        (blob : byte[])
        (length : uint32)
        (answered : Result<SteppedCall<int, string>, SyscallRefusal<int>>)
        (system : UnixSystem<int, string>)
        : unit
        =
        let throughSteps = CopyIn.bind fd UserBuffer.Mapped length blob system

        match answered, throughSteps with
        | Ok (SteppedCall.Bind (answer, after)), Ok (stepsAnswer, stepsAfter) when
            answer = stepsAnswer && after = stepsAfter
            ->
            ()
        | Error (SyscallRefusal.Bind refusal), Error stepsRefusal when refusal = stepsRefusal -> ()
        | _ ->
            failwith
                $"bind(%d{fd}): UnixSystem.tryStep answered %A{Result.map UnionCaseName.ofValue answered}, and the call's own functions %A{Result.map fst throughSteps}, or left another system"

    /// Fails the test unless `answered`, what `UnixSystem.tryStep` answered
    /// for `connect(fd, blob, length)` in `system`, is what the same connect
    /// answers through the call's own functions, held to it made a step at a
    /// time (`CopyIn.connect`, which fails the test if the call sleeps), as
    /// `requireSetAlike` holds a set.
    let private requireConnectedAlike
        (fd : int)
        (blob : byte[])
        (length : uint32)
        (answered : Result<SteppedCall<int, string>, SyscallRefusal<int>>)
        (system : UnixSystem<int, string>)
        : unit
        =
        let throughSteps = CopyIn.connect fd UserBuffer.Mapped length blob system

        match answered, throughSteps with
        | Ok (SteppedCall.Connect (SyscallOutcome.Answered answer, after)), Ok (stepsAnswer, stepsAfter) when
            answer = stepsAnswer && after = stepsAfter
            ->
            ()
        | Error (SyscallRefusal.Connect refusal), Error stepsRefusal when refusal = stepsRefusal -> ()
        | _ ->
            failwith
                $"connect(%d{fd}): UnixSystem.tryStep answered %A{Result.map UnionCaseName.ofValue answered}, and the call's own functions %A{Result.map fst throughSteps}, or left another system"

    /// The address `answered` for the socket on `fd` is in the socket's own
    /// family, and is what `getsockname(2)` copies out at once.
    let private checkAnswer
        (seen : Seen)
        (call : string)
        (fd : int)
        (answered : SocketAddress)
        (system : UnixSystem<int, string>)
        : unit
        =
        let platform = UnixSystem.platform system

        let socket =
            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) -> UnixMachineState.socket socketId (Kernel.machine system)
            | other -> failwith $"fd %d{fd} names %A{other}"

        match socket.Domain, answered with
        | SocketDomain.Inet, SocketAddress.Inet _ -> seen.Inet <- seen.Inet + 1
        | SocketDomain.Inet6, SocketAddress.Inet6 _ -> seen.Inet6 <- seen.Inet6 + 1
        | SocketDomain.Unix, SocketAddress.Unix _ -> ()
        | domain, _ ->
            failwith
                $"%s{call} on a %O{domain} socket answered %s{SocketAddress.toString answered}, which is not in the socket's own family"

        let getsockname = Syscall.GetSockName (fd, UserBuffer.Mapped, 128u)

        match stepped getsockname system with
        | Ok (SteppedCall.GetSockName (GetSockNameAnswer.Reported (copiedOut, _))) ->
            Seq.toArray copiedOut |> shouldEqual (encoded platform answered)
        | Ok (SteppedCall.GetSockName answer) -> failwith $"getsockname after %s{call} answered %A{answer}"
        | Ok other -> unexpected getsockname other
        | Error refusal -> failwith $"getsockname after %s{call} was refused: %s{SyscallRefusal.describe refusal}"

    [<Test>]
    let ``a bind or listen answers its address in the socket's own family, as getsockname reports it`` () : unit =
        let seen =
            {
                Inet = 0
                Inet6 = 0
                Listens = 0
            }

        let caseGen =
            Gen.zip (Gen.elements platforms) (Gen.choose (1, 14) |> Gen.bind (fun n -> Gen.listOfLength n opGen))

        let property (platform : SimulatedUnixPlatform, ops : Op list) : unit =
            let fdOf (slot : int) (fds : int list) : int option =
                if fds.IsEmpty then None else Some fds.[slot % fds.Length]

            let familyNumber (fd : int) (family : Family) (system : UnixSystem<int, string>) : int =
                match family with
                | Family.Inet -> SimulatedUnixPlatform.internetAddressFamily
                | Family.Inet6 -> SimulatedUnixPlatform.internetV6AddressFamily platform
                | Family.Unspec -> 0
                | Family.Own ->
                    match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
                    | Some (OpenFileTarget.Socket socketId) ->
                        match (UnixMachineState.socket socketId (Kernel.machine system)).Domain with
                        | SocketDomain.Inet6 -> SimulatedUnixPlatform.internetV6AddressFamily platform
                        | SocketDomain.Inet
                        | SocketDomain.Unix -> SimulatedUnixPlatform.internetAddressFamily
                    | other -> failwith $"fd %d{fd} names %A{other}"

            let step (fds : int list, system : UnixSystem<int, string>) (op : Op) =
                match op with
                | Op.NewSocket (shape, v6Only) ->
                    let domain, kind, protocol = NewSocket.requests.[shape]

                    let socket =
                        let domain, kind, protocol = NewSocket.arguments platform domain kind protocol
                        Syscall.Socket (domain, kind, protocol)

                    match stepped socket system with
                    | Ok (SteppedCall.Socket (Error _))
                    | Error _ -> fds, system
                    | Ok (SteppedCall.Socket (Ok (fd, system))) ->
                        let system =
                            match domain, v6Only with
                            | SocketDomain.Inet6, Some value ->
                                let level = SimulatedUnixPlatform.ipv6OptionLevel platform
                                let name = SimulatedUnixPlatform.ipv6OnlyOption platform

                                let bytes =
                                    ImmutableArray.CreateRange (SimulatedUnixPlatform.encodeCInt platform value)

                                let setsockopt =
                                    Syscall.SetSockOpt (fd, level, name, CopiedArgument.Readable bytes, 4u)

                                let answered = stepped setsockopt system
                                requireSetAlike fd level name bytes answered system

                                match answered with
                                | Ok (SteppedCall.SetSockOpt (_, system)) -> system
                                | Ok other -> unexpected setsockopt other
                                | Error _ -> system
                            | _ -> system

                        fds @ [ fd ], system
                    | Ok other -> unexpected socket other
                | Op.Bind (slot, family, address, port, length) ->
                    match fdOf slot fds with
                    | None -> fds, system
                    | Some fd ->
                        let blob =
                            sockaddr platform (familyNumber fd family system) addresses.[address] port

                        let bind =
                            Syscall.Bind (fd, CopiedArgument.Readable (ImmutableArray.Create<byte> blob), length)

                        let answered = stepped bind system
                        requireBoundAlike fd blob length answered system

                        match answered with
                        | Ok (SteppedCall.Bind (BindAnswer.Bound answered, system)) ->
                            checkAnswer seen "bind" fd answered system
                            fds, system
                        | Ok (SteppedCall.Bind (BindAnswer.Failed _, system)) -> fds, system
                        | Ok other -> unexpected bind other
                        | Error _ -> fds, system
                | Op.Listen slot ->
                    match fdOf slot fds with
                    | None -> fds, system
                    | Some fd ->
                        let listen = Syscall.Listen (fd, 4)

                        match stepped listen system with
                        | Ok (SteppedCall.Listen (ListenAnswer.Listening answered, system)) ->
                            seen.Listens <- seen.Listens + 1
                            checkAnswer seen "listen" fd answered system
                            fds, system
                        | Ok (SteppedCall.Listen (ListenAnswer.Failed _, system)) -> fds, system
                        | Ok other -> unexpected listen other
                        | Error _ -> fds, system
                | Op.Connect (slot, address, port) ->
                    match fdOf slot fds with
                    | None -> fds, system
                    | Some fd ->
                        let family = familyNumber fd Family.Own system

                        let length =
                            if family = SimulatedUnixPlatform.internetV6AddressFamily platform then
                                28u
                            else
                                16u

                        let blob = sockaddr platform family addresses.[address] port

                        let connect =
                            Syscall.Connect (fd, CopiedArgument.Readable (ImmutableArray.Create<byte> blob), length)

                        let answered = stepped connect system
                        requireConnectedAlike fd blob length answered system

                        match answered with
                        | Ok (SteppedCall.Connect (SyscallOutcome.Answered _, system)) -> fds, system
                        | Ok (SteppedCall.Connect (outcome, _)) ->
                            failwith $"expected a connect that returns, got %A{outcome}"
                        | Ok other -> unexpected connect other
                        | Error _ -> fds, system

            let system =
                UnixSystem.initial platform
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            List.fold step ([], system) ops |> ignore

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 1000, Prop.forAll (Arb.fromGen caseGen) property)

        // Each kind of answer was reached, so the property was not vacuous.
        seen.Inet |> shouldBeGreaterThan 0
        seen.Inet6 |> shouldBeGreaterThan 0
        seen.Listens |> shouldBeGreaterThan 0
