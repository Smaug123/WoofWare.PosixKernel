namespace WoofWare.PosixKernel.Test

open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel

/// What a socket's domain, its `IPV6_V6ONLY` and its local address allow of
/// one another, as a sequence of calls changes them: random sequences of
/// `socket`, `setsockopt` and `getsockopt` of `IPV6_V6ONLY`, `bind` and
/// `listen`, against a reference model written out here, with the system's
/// invariants checked after every call.
///
/// The reference model holds per socket only what decides these answers: its
/// domain and kind, its `IPV6_V6ONLY`, and whether it has an address.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSocketAddressing =

    [<RequireQualifiedAccess>]
    type Call =
        | Socket of domain : SocketDomain * kind : SocketKind
        | SetIpv6Only of socket : int * value : int
        | GetIpv6Only of socket : int
        | Bind of socket : int
        | Listen of socket : int

    /// What the reference model holds of one socket.
    type Expected =
        {
            Domain : SocketDomain
            Kind : SocketKind
            Ipv6Only : bool
            HasAddress : bool
        }

    /// A call's answer, reduced to what the reference model predicts.
    [<RequireQualifiedAccess>]
    type Answer =
        | Succeeded
        | Failed of UnixError
        | Read of value : int
        | Refused

    let private flavourColumn (platform : SimulatedUnixPlatform) (onLinux : 'a) (onDarwin : 'a) : 'a =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> onLinux
        | SimulatedUnixFlavour.Darwin -> onDarwin

    /// The answer to a set of `IPV6_V6ONLY` on `socket`, and the socket after
    /// it. Measured (`docs/probes/sockopt-options/`): an option for a socket it
    /// does not apply to is the flavour's errno, and an IPv6 socket with an
    /// address answers EINVAL.
    let private expectedSet (platform : SimulatedUnixPlatform) (value : int) (socket : Expected) : Answer * Expected =
        match socket.Domain with
        | SocketDomain.Inet6 when socket.HasAddress -> Answer.Failed UnixError.EINVAL, socket
        | SocketDomain.Inet6 ->
            Answer.Succeeded,
            { socket with
                Ipv6Only = value <> 0
            }
        | SocketDomain.Inet -> Answer.Failed (flavourColumn platform UnixError.ENOPROTOOPT UnixError.EINVAL), socket
        | SocketDomain.Unix -> Answer.Failed UnixError.EOPNOTSUPP, socket

    let private expectedGet (platform : SimulatedUnixPlatform) (socket : Expected) : Answer =
        match socket.Domain with
        | SocketDomain.Inet6 -> Answer.Read (if socket.Ipv6Only then 1 else 0)
        | SocketDomain.Inet -> Answer.Failed (flavourColumn platform UnixError.EOPNOTSUPP UnixError.EINVAL)
        | SocketDomain.Unix -> Answer.Failed UnixError.EOPNOTSUPP

    /// A bind to loopback and port 0, in the socket's own family: on an IPv6
    /// socket, `::ffff:127.0.0.1`. Measured (`docs/probes/dual-mode/`, B and
    /// F): an IPv6 socket with `IPV6_V6ONLY` on takes no v4-mapped address,
    /// and judges that before whether it is bound.
    let private expectedBind (platform : SimulatedUnixPlatform) (socket : Expected) : Answer * Expected =
        let bindable =
            socket.Domain = SocketDomain.Inet
            || (socket.Domain = SocketDomain.Inet6 && socket.Kind = SocketKind.Stream)

        if not bindable then
            Answer.Refused, socket
        elif socket.Domain = SocketDomain.Inet6 && socket.Ipv6Only then
            Answer.Failed (flavourColumn platform UnixError.EINVAL UnixError.EADDRNOTAVAIL), socket
        elif socket.HasAddress then
            Answer.Failed UnixError.EINVAL, socket
        else
            Answer.Succeeded,
            { socket with
                HasAddress = true
            }

    let private expectedListen (socket : Expected) : Answer * Expected =
        match socket.Domain with
        | SocketDomain.Inet ->
            Answer.Succeeded,
            { socket with
                HasAddress = true
            }
        | SocketDomain.Inet6
        | SocketDomain.Unix -> Answer.Refused, socket

    let private ipv6OnlyOption (platform : SimulatedUnixPlatform) : int * int =
        SimulatedUnixPlatform.ipv6OptionLevel platform, SimulatedUnixPlatform.ipv6OnlyOption platform

    /// `socket(2)` of `domain` and `kind`, with the default protocol.
    let private socketCall
        (platform : SimulatedUnixPlatform)
        (domain : SocketDomain)
        (kind : SocketKind)
        : Syscall<int, string>
        =
        let domain, kind, protocol =
            NewSocket.arguments platform domain kind SocketProtocol.Default

        Syscall.Socket (domain, kind, protocol)

    /// `setsockopt(2)` of `IPV6_V6ONLY` to `value` on `fd`.
    let private setCall (platform : SimulatedUnixPlatform) (fd : int) (value : int) : Syscall<int, string> =
        let level, name = ipv6OnlyOption platform
        Syscall.SetSockOpt (fd, level, name, CopiedArgument.Readable (OptionValue.ofInt value), 4u)

    /// `getsockopt(2)` of `IPV6_V6ONLY` on `fd`, into room for a C `int`.
    let private getCall (platform : SimulatedUnixPlatform) (fd : int) : Syscall<int, string> =
        let level, name = ipv6OnlyOption platform
        Syscall.GetSockOpt (fd, level, name, UserBuffer.Mapped, CopiedArgument.Readable 4u)

    /// `bind(2)` of `fd` to loopback and port 0, in `domain`'s own family.
    let private bindCall (platform : SimulatedUnixPlatform) (fd : int) (domain : SocketDomain) : Syscall<int, string> =
        let loopback = Ipv4Endpoint.ofParts Ipv4Address.loopback 0us

        let blob, length =
            match domain with
            | SocketDomain.Inet6 -> CopyIn.inet6Mapped platform loopback, 28u
            | SocketDomain.Inet
            | SocketDomain.Unix -> CopyIn.inet platform loopback, 16u

        Syscall.Bind (fd, CopiedArgument.Readable (CopyIn.prefix blob (int length)), length)

    /// `listen(2)` on `fd`.
    let private listenCall (fd : int) : Syscall<int, string> = Syscall.Listen (fd, 8)

    /// What `UnixSystem.tryStep` of `call` by the process's leader in `system`
    /// answered, reduced to what the reference model predicts, and the system
    /// after it.
    let private answerOf
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : Answer * UnixSystem<int, string>
        =
        match UnixSystem.tryStep (Callers.leader system) call system with
        | Error _ -> Answer.Refused, system
        | Ok (SteppedCall.SetSockOpt (SetSockOptAnswer.Set, after)) -> Answer.Succeeded, after
        | Ok (SteppedCall.SetSockOpt (SetSockOptAnswer.Failed error, after)) -> Answer.Failed error, after
        | Ok (SteppedCall.GetSockOpt (GetSockOptAnswer.Reported bytes, after)) when bytes.Length = 4 ->
            Answer.Read (SimulatedUnixPlatform.decodeCInt system.Machine.UnixPlatform bytes 0), after
        | Ok (SteppedCall.GetSockOpt (GetSockOptAnswer.Reported bytes, _)) ->
            failwith $"getsockopt reported %d{bytes.Length} bytes"
        | Ok (SteppedCall.GetSockOpt (GetSockOptAnswer.Failed (error, _), after)) -> Answer.Failed error, after
        | Ok (SteppedCall.Bind (BindAnswer.Bound _, after)) -> Answer.Succeeded, after
        | Ok (SteppedCall.Bind (BindAnswer.Failed error, after)) -> Answer.Failed error, after
        | Ok (SteppedCall.Listen (ListenAnswer.Listening _, after)) -> Answer.Succeeded, after
        | Ok (SteppedCall.Listen (ListenAnswer.Failed error, after)) -> Answer.Failed error, after
        | Ok other ->
            failwith $"Syscall.%s{UnionCaseName.ofValue call} answered SteppedCall.%s{UnionCaseName.ofValue other}"

    let private callGen : Gen<Call> =
        let index = Gen.choose (0, 3)

        Gen.oneof
            [
                Gen.zip
                    (Gen.elements [ SocketDomain.Inet ; SocketDomain.Inet6 ; SocketDomain.Unix ])
                    (Gen.elements [ SocketKind.Stream ; SocketKind.Datagram ])
                |> Gen.map Call.Socket
                Gen.zip index (Gen.elements [ 0 ; 1 ; 2 ; -1 ]) |> Gen.map Call.SetIpv6Only
                index |> Gen.map Call.GetIpv6Only
                index |> Gen.map Call.Bind
                index |> Gen.map Call.Listen
            ]

    let private platforms : SimulatedUnixPlatform list =
        [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ]

    [<Test>]
    let ``a socket's domain, IPV6_V6ONLY and address move together as the reference model says`` () : unit =
        let gen =
            Gen.zip
                (Gen.zip (Gen.elements platforms) (Gen.elements [ false ; true ]))
                (Gen.listOf callGen |> Gen.resize 24)

        let property ((platform : SimulatedUnixPlatform, ipv6OnlyByDefault : bool), calls : Call list) : unit =
            let system =
                UnixSystem.initial platform
                |> UnixBootImage.withIpv6OnlyByDefault ipv6OnlyByDefault
                |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

            let check (describe : string) (system : UnixSystem<int, string>) : unit =
                match UnixSystem.checkInvariants system with
                | [] -> ()
                | defects -> failwith $"%s{describe}: the system broke its invariants: %A{defects}"

            // The sockets made so far, oldest first: descriptor and model.
            let rec go
                (index : int)
                (calls : Call list)
                (sockets : (int * Expected) list)
                (system : UnixSystem<int, string>)
                : unit
                =
                match calls with
                | [] -> ()
                | call :: rest ->

                let describe =
                    $"%O{platform}, default %b{ipv6OnlyByDefault}, call %d{index} (%A{call})"

                let target (i : int) : (int * (int * Expected)) option =
                    if List.isEmpty sockets then
                        None
                    else
                        let i = i % List.length sockets
                        Some (i, List.item i sockets)

                let replace (i : int) (expected : Expected) =
                    sockets
                    |> List.mapi (fun j (fd, old) -> if i = j then fd, expected else fd, old)

                let compare (actual : Answer) (expected : Answer) =
                    if actual <> expected then
                        failwith $"%s{describe}: answered %A{actual}, where the model says %A{expected}"

                match call with
                | Call.Socket (domain, kind) ->
                    let fd, system =
                        let call = socketCall platform domain kind

                        match UnixSystem.tryStep (Callers.leader system) call system with
                        | Ok (SteppedCall.Socket (Ok created)) -> created
                        | Ok (SteppedCall.Socket (Error error)) -> failwith $"%s{describe}: socket answered %O{error}"
                        | Ok other ->
                            failwith $"%s{describe}: socket answered SteppedCall.%s{UnionCaseName.ofValue other}"
                        | Error refusal ->
                            failwith $"%s{describe}: socket was refused: %s{SyscallRefusal.describe refusal}"

                    check describe system

                    let expected =
                        {
                            Domain = domain
                            Kind = kind
                            Ipv6Only = domain = SocketDomain.Inet6 && ipv6OnlyByDefault
                            HasAddress = false
                        }

                    go (index + 1) rest (sockets @ [ fd, expected ]) system
                | Call.SetIpv6Only (i, value) ->
                    match target i with
                    | None -> go (index + 1) rest sockets system
                    | Some (i, (fd, socket)) ->
                        let actual, system = answerOf (setCall platform fd value) system
                        let expected, socket = expectedSet platform value socket
                        compare actual expected
                        check describe system
                        go (index + 1) rest (replace i socket) system
                | Call.GetIpv6Only i ->
                    match target i with
                    | None -> go (index + 1) rest sockets system
                    | Some (_, (fd, socket)) ->
                        let actual, system = answerOf (getCall platform fd) system
                        compare actual (expectedGet platform socket)
                        check describe system
                        go (index + 1) rest sockets system
                | Call.Bind i ->
                    match target i with
                    | None -> go (index + 1) rest sockets system
                    | Some (i, (fd, socket)) ->
                        let actual, system = answerOf (bindCall platform fd socket.Domain) system
                        let expected, socket = expectedBind platform socket
                        compare actual expected
                        check describe system
                        go (index + 1) rest (replace i socket) system
                | Call.Listen i ->
                    match target i with
                    | Some (i, (fd, socket)) when socket.Kind = SocketKind.Stream ->
                        let actual, system = answerOf (listenCall fd) system
                        let expected, socket = expectedListen socket
                        compare actual expected
                        check describe system
                        go (index + 1) rest (replace i socket) system
                    | Some _
                    | None -> go (index + 1) rest sockets system

            go 0 calls [] system

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 500, Prop.forAll (Arb.fromGen gen) property)
