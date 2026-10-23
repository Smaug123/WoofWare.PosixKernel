namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// What `setsockopt(IPV6_V6ONLY)` answers on a dual-mode IPv6 TCP socket whose
/// connect was refused, replayed from both flavours' outputs of
/// `docs/probes/v6only-after-refusal`.
///
/// Replayed: the rows whose socket came by its port through connect's own
/// bind (I), `bind(2)` of `[::ffff:127.0.0.1]:0` (Z) or of
/// `[::ffff:127.0.0.1]:<port>` (X), each refused blocking (b), non-blocking
/// (n) or with `SO_ERROR` read (s); and, where the set succeeded, the two
/// connects that follow it. Not replayed: the rows bound at `[::]`, which this
/// kernel does not bind a dual-mode socket to.
///
/// Linux takes the option on a socket whose refusal gave back a port no
/// `bind(2)` chose; a socket it then turns IPv6-only is one this kernel cannot
/// represent, so that set is refused.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestV6OnlyAfterRefusalMeasured =

    let private lines (flavour : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.v6only-after-refusal.%s{flavour}.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    let private loopback (port : uint16) : Ipv4Endpoint =
        Ipv4Endpoint.ofParts Ipv4Address.loopback port

    let private listenerPort : uint16 = 45201us

    let private errorName (error : UnixError) : string = $"%A{error}"

    let private answerName (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed _ -> "OK"
        | SyscallAnswer.Failed error -> errorName error

    /// A machine with an IPv4 listener at 127.0.0.1:`listenerPort`.
    let private systemOn (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        let system =
            UnixSystem.initial platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        let system =
            match CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (loopback listenerPort)) system with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"binding the listener: %A{other}"

        match UnixSocket.tryListen (Callers.leader system) fd 128 system with
        | Ok (ListenAnswer.Listening _, system) -> system
        | other -> failwith $"listening: %A{other}"

    /// `setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(int))`.
    let private setV6Only
        (fd : int)
        (value : int)
        (system : UnixSystem<int, string>)
        : Result<SetSockOptAnswer * UnixSystem<int, string>, SocketOptionRefusal>
        =
        let platform = UnixSystem.platform system
        let level = SimulatedUnixPlatform.ipv6OptionLevel platform
        let optionName = SimulatedUnixPlatform.ipv6OnlyOption platform

        match Lone.UnixSocket.tryAdmitSetSockOpt fd level optionName UserBuffer.Mapped 4u system with
        | Ok (SetSockOptAdmission.Transfer _) ->
            Lone.UnixSocket.trySetsockoptBytes
                fd
                level
                optionName
                UserBuffer.Mapped
                4u
                (Some (OptionValue.ofInt value))
                system
        | Ok (SetSockOptAdmission.Answered error) -> Ok (SetSockOptAnswer.Failed error, system)
        | Ok SetSockOptAdmission.NoCopy -> failwith "IPV6_V6ONLY is always copied"
        | Error refusal -> Error refusal

    let private getV6Only (fd : int) (system : UnixSystem<int, string>) : int =
        let platform = UnixSystem.platform system

        match
            Lone.UnixSocket.tryGetsockoptLength
                fd
                (SimulatedUnixPlatform.ipv6OptionLevel platform)
                (SimulatedUnixPlatform.ipv6OnlyOption platform)
                UserBuffer.Mapped
                UserBuffer.Mapped
                (Some 4u)
                system
        with
        | Ok (answer, _) -> OptionValue.readInt answer
        | Error refusal -> failwith $"IPV6_V6ONLY read refused: %s{SocketOptionRefusal.describe refusal}"

    let private takeError (fd : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let platform = UnixSystem.platform system

        match
            Lone.UnixSocket.tryGetsockoptLength
                fd
                (SimulatedUnixPlatform.socketOptionLevel platform)
                (SimulatedUnixPlatform.socketErrorOption platform)
                UserBuffer.Mapped
                UserBuffer.Mapped
                (Some 4u)
                system
        with
        | Ok (answer, system) ->
            let raw = OptionValue.readInt answer

            if raw = 0 then
                "OK", system
            else
                match UnixError.ofRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) raw with
                | Some error -> errorName error, system
                | None -> failwith $"SO_ERROR read errno %d{raw}"
        | Error refusal -> failwith $"SO_ERROR refused: %s{SocketOptionRefusal.describe refusal}"

    let private mapped (platform : SimulatedUnixPlatform) (endpoint : Ipv4Endpoint) : byte[] =
        CopyIn.inet6Mapped platform endpoint

    let private connect (fd : int) (destination : Ipv4Endpoint) (system : UnixSystem<int, string>) =
        match CopyIn.connect fd UserBuffer.Mapped 28u (mapped (UnixSystem.platform system) destination) system with
        | Ok result -> result
        | Error refusal -> failwith $"connect: refused %s{ConnectRefusal.describe refusal}"

    let private rowPattern : Regex =
        Regex
            @"^([IZWXY])([bns])([01]) bind=(\S+) connect=(\S+)(?: poll=\S+)?(?: SO_ERROR=(\S+))? getsockname=\S+ \| IPV6_V6ONLY=[01] -> (\S+), reads ([01]), getsockname=\S+(?: \| connect v4-mapped listener=(\S+) getsockname=\S+ \| again=(\S+) getsockname=\S+)?$"

    let private replay (flavour : string) (platform : SimulatedUnixPlatform) : int =
        let mutable replayed = 0

        for line in lines flavour do
            let m = rowPattern.Match line

            if m.Success && "IZX".Contains m.Groups.[1].Value then
                let group (i : int) : string = m.Groups.[i].Value

                let fail (what : string) =
                    failwith $"%s{what}\n  measured: %s{line}"

                let value = int (group 3)
                let system = systemOn platform

                let fd, system =
                    NewSocket.create SocketDomain.Inet6 SocketKind.Stream SocketProtocol.Tcp system

                let system =
                    match setV6Only fd 0 system with
                    | Ok (SetSockOptAnswer.Set, system) -> system
                    | other -> fail $"making the socket dual-mode answered %A{other}"

                let bound =
                    match group 1 with
                    | "I" -> None
                    | "Z" -> Some 0us
                    | _ -> Some 45301us

                let system =
                    match bound with
                    | None -> system
                    | Some port ->
                        match CopyIn.bind fd UserBuffer.Mapped 28u (mapped platform (loopback port)) system with
                        | Ok (BindAnswer.Bound _, system) -> system
                        | other -> fail $"bind answered %A{other}"

                let system =
                    if group 2 = "b" then
                        system
                    else
                        Lone.withFileDescriptors
                            (FileDescriptorRegistry.setNonBlocking fd true (Lone.fileDescriptors system))
                            system

                let answer, system = connect fd (loopback 1us) system

                if answerName answer <> group 5 then
                    fail $"connect answered %s{answerName answer}"

                let system =
                    if group 2 = "s" then
                        let taken, system = takeError fd system

                        if taken <> group 6 then
                            fail $"SO_ERROR read %s{taken}"

                        system
                    else
                        system

                // The probe makes the socket blocking again after its poll.
                let system =
                    Lone.withFileDescriptors
                        (FileDescriptorRegistry.setNonBlocking fd false (Lone.fileDescriptors system))
                        system

                match group 7, value, setV6Only fd value system with
                | "EINVAL", _, Ok (SetSockOptAnswer.Failed UnixError.EINVAL, system) ->
                    if getV6Only fd system <> int (group 8) then
                        fail "IPV6_V6ONLY reads back otherwise"
                | "OK", 1, Error (SocketOptionRefusal.Ipv6OnlyOnGivenBackPort _) -> ()
                | "OK", 0, Ok (SetSockOptAnswer.Set, system) ->
                    if getV6Only fd system <> 0 then
                        fail "IPV6_V6ONLY reads back otherwise"

                    let first, system = connect fd (loopback listenerPort) system

                    if answerName first <> group 9 then
                        fail $"the connect to the listener answered %s{answerName first}"

                    let second, _ = connect fd (loopback listenerPort) system

                    if answerName second <> group 10 then
                        fail $"the second connect to the listener answered %s{answerName second}"
                | _, _, other -> fail $"IPV6_V6ONLY=%d{value} answered %A{other}"

                replayed <- replayed + 1

        replayed

    [<Test>]
    let ``Linux takes IPV6_V6ONLY after a refusal gave back a port bind did not choose`` () : unit =
        replay "linux" SimulatedUnixPlatform.linuxX64 |> shouldEqual 18

    [<Test>]
    let ``Darwin refuses IPV6_V6ONLY after any refusal`` () : unit =
        replay "darwin" SimulatedUnixPlatform.macOsArm64 |> shouldEqual 18
