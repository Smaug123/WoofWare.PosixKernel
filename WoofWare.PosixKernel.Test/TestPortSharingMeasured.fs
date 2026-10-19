namespace WoofWare.PosixKernel.Test

open System
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Which binds two sockets of two processes may share a port through, by
/// `SO_REUSEADDR`, when the processes have one uid or two, and which ports a
/// datagram socket's search takes beside such a holder: both flavours' outputs
/// of `docs/probes/port-sharing`, replayed.
///
/// Every row the model can make is replayed: those whose sockets carry
/// `SO_REUSEADDR` or nothing (this kernel does not model `SO_REUSEPORT`, and
/// refuses to set it), other than the `sendto(2)` rows (it does not model
/// `sendto(2)`). Each replays on a machine whose ephemeral range is the row's
/// port, as the probe narrowed each searching socket's range to it, with the
/// holder made by one process of uid 1000 and the candidate by another, of
/// uid 1000 or 1001 as the row says.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestPortSharingMeasured =

    let private lines (flavour : string) : string list =
        let name = $"WoofWare.PosixKernel.Test.port-sharing.%s{flavour}.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"no embedded resource %s{name}"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split ('\n', StringSplitOptions.RemoveEmptyEntries)
        |> List.ofArray

    /// One row of the probe's output.
    type private Row =
        {
            Line : string
            Transport : SocketKind
            /// "i", "c", "L" or "none".
            Holder : string
            HolderFlags : string
            HolderAddress : string
            /// What the holder's getsockname reported, as the probe prints it.
            HeldAt : string
            CandidateFlags : string
            CandidateAddress : string
            DifferentUid : bool
            /// "bind", "search", "connect", "sendto" or "write".
            Operation : string
            Port : uint16
            Answer : string
            Name : string
        }

    let private rowPattern : Regex =
        Regex @"^(udp|tcp)/(\w+) H=(\S+)@(\S+) \((.*?)\) C=(\S+)@(\S+) (same|diff) (\w+) L=(\d+) -> (\S+) name=(\S+)$"

    let private rows (flavour : string) : Row list =
        lines flavour
        |> List.choose (fun line ->
            let m = rowPattern.Match line

            if m.Success then
                let group (i : int) : string = m.Groups.[i].Value

                Some
                    {
                        Line = line
                        Transport =
                            match group 1 with
                            | "udp" -> SocketKind.Datagram
                            | _ -> SocketKind.Stream
                        Holder = group 2
                        HolderFlags = group 3
                        HolderAddress = group 4
                        HeldAt =
                            match (group 5).Split " at " with
                            | [| _ ; at |] -> at
                            | _ -> "-"
                        CandidateFlags = group 6
                        CandidateAddress = group 7
                        DifferentUid = group 8 = "diff"
                        Operation = group 9
                        Port = UInt16.Parse (group 10)
                        Answer = group 11
                        Name = group 12
                    }
            elif
                line.StartsWith "Linux "
                || line.StartsWith "Darwin "
                || line.StartsWith "probe uid="
                || line.StartsWith "a process dropped to "
                || line.StartsWith "not root: "
            then
                None
            else
                failwith $"unparsed line: %s{line}"
        )

    /// Whether this kernel can make the row: neither socket carries
    /// `SO_REUSEPORT`, and the candidate's call is not `sendto(2)`.
    let private modelled (row : Row) : bool =
        not (row.HolderFlags.Contains 'p')
        && not (row.CandidateFlags.Contains 'p')
        && row.Operation <> "sendto"

    /// A dotted quad as the probe prints one.
    let private parseAddress (text : string) : Ipv4Address =
        match text.Split '.' |> Array.map Byte.Parse with
        | [| a ; b ; c ; d |] -> Ipv4Address ((uint32 a <<< 24) ||| (uint32 b <<< 16) ||| (uint32 c <<< 8) ||| uint32 d)
        | _ -> failwith $"not an IPv4 address: %s{text}"

    /// Where the probe's connects aim: a port nothing uses.
    let private unused : uint16 = 40000us

    let private credentials (uid : uint32) : Credentials =
        Credentials.ofIds
            (UserId.parseOrFail "TestPortSharingMeasured" uid)
            (GroupId.parseOrFail "TestPortSharingMeasured" uid)
            []

    let private describeRefusal (refusal : SyscallRefusal<int>) : string =
        $"refused (%s{SyscallRefusal.describe refusal})"

    /// `call` made by the leader of `pid`.
    let private step
        (pid : ProcessId)
        (call : Syscall<int, string>)
        (system : UnixSystem<int, string>)
        : Result<SteppedCall<int, string>, SyscallRefusal<int>>
        =
        UnixSystem.tryStep (Caller.make pid 0) call system

    let private sockaddr (platform : SimulatedUnixPlatform) (address : string) (port : uint16) =
        CopiedArgument.Readable (CopyIn.inetCopy platform (Ipv4Endpoint.ofParts (parseAddress address) port))

    /// A socket of `transport` made by `pid`, carrying `SO_REUSEADDR` if
    /// `flags` says so.
    let private socketOf
        (pid : ProcessId)
        (transport : SocketKind)
        (flags : string)
        (system : UnixSystem<int, string>)
        : int * UnixSystem<int, string>
        =
        let platform = UnixSystem.platform system

        let protocol =
            match transport with
            | SocketKind.Stream -> SocketProtocol.Tcp
            | _ -> SocketProtocol.Udp

        let domain, kind, protocol =
            NewSocket.arguments platform SocketDomain.Inet transport protocol

        let fd, system =
            match step pid (Syscall.Socket (domain, kind, protocol)) system with
            | Ok (SteppedCall.Socket (DescriptorAnswer.Returned fd, system)) -> fd, system
            | other -> failwith $"socket: %A{other}"

        if flags.Contains 'a' then
            let call =
                Syscall.SetSockOpt (
                    fd,
                    SimulatedUnixPlatform.socketOptionLevel platform,
                    SimulatedUnixPlatform.reuseAddressOption platform,
                    CopiedArgument.Readable (OptionValue.ofInt 1),
                    4u
                )

            match step pid call system with
            | Ok (SteppedCall.SetSockOpt (SetSockOptAnswer.Set, system)) -> fd, system
            | other -> failwith $"SO_REUSEADDR: %A{other}"
        else
            fd, system

    /// What getsockname reports for `fd` of `pid`, as the probe prints it.
    let private nameOf (pid : ProcessId) (fd : int) (system : UnixSystem<int, string>) : string =
        match step pid (Syscall.GetSockName (fd, UserBuffer.Mapped, 16u)) system with
        | Ok (SteppedCall.GetSockName (GetSockNameAnswer.Reported (bytes, _))) ->
            match (SimulatedUnixPlatform.decodeInternetSockaddr (UnixSystem.platform system) bytes).Endpoint with
            | Some endpoint -> Ipv4Endpoint.toString endpoint
            | None -> failwith $"fd %d{fd}: the reported name decodes to no endpoint"
        | other -> failwith $"getsockname on fd %d{fd}: %A{other}"

    /// The machine the row replays on, with the holder in place: the
    /// candidate's process, and the system.
    let private arrange (platform : SimulatedUnixPlatform) (row : Row) : ProcessId * UnixSystem<int, string> =
        let addresses =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> UnixSystem.defaultLocalIpv4Addresses @ [ parseAddress "127.0.0.2" ]
            | SimulatedUnixFlavour.Darwin -> UnixSystem.defaultLocalIpv4Addresses

        let system =
            UnixSystem.initial platform
            |> UnixBootImage.withLocalIpv4Addresses addresses UnixSystem.defaultLocalRoutes
            |> UnixBootImage.tryWithEphemeralPortRange (row.Port, row.Port)
            |> Configured.expectOk EphemeralPortRangeRefusal.describe
            |> Launched.bootWith (Launched.credentials (credentials 1000u)) UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let holderPid = Lone.pid system

        let launch =
            Launched.launch platform UnixSystem.pipedStandardStreams 0 (CpuId 0)
            |> Launched.credentials (credentials (if row.DifferentUid then 1001u else 1000u))

        let candidatePid, system =
            match Machines.tryLaunch launch system with
            | Ok launched -> launched
            | Error refusal -> failwith $"launch: %s{ProcessCreationRefusal.describe refusal}"

        let system =
            match row.Holder with
            | "none" -> system
            | holder ->
                let fd, system = socketOf holderPid row.Transport row.HolderFlags system

                let system =
                    match
                        step holderPid (Syscall.Bind (fd, sockaddr platform row.HolderAddress row.Port, 16u)) system
                    with
                    | Ok (SteppedCall.Bind (BindAnswer.Bound _, system)) -> system
                    | other -> failwith $"%s{row.Line}: the holder's bind answered %A{other}"

                let system =
                    match holder with
                    | "c" ->
                        match
                            step holderPid (Syscall.Connect (fd, sockaddr platform "127.0.0.1" unused, 16u)) system
                        with
                        | Ok (SteppedCall.Connect (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system)) ->
                            system
                        | other -> failwith $"%s{row.Line}: the holder's connect answered %A{other}"
                    | "L" ->
                        match step holderPid (Syscall.Listen (fd, 8)) system with
                        | Ok (SteppedCall.Listen (ListenAnswer.Listening _, system)) -> system
                        | other -> failwith $"%s{row.Line}: the holder's listen answered %A{other}"
                    | _ -> system

                let held = nameOf holderPid fd system

                if held <> row.HeldAt then
                    failwith $"%s{row.Line}: the model's holder is at %s{held}"

                system

        candidatePid, system

    /// What the candidate's call answers in the model, and the name its socket
    /// then reports, as the probe prints them.
    let private candidate (platform : SimulatedUnixPlatform) (row : Row) : string * string =
        let pid, system = arrange platform row
        let fd, system = socketOf pid row.Transport row.CandidateFlags system

        let answered (error : UnixError) : string = $"%A{error}"

        let answer, system =
            match row.Operation with
            | "bind"
            | "search" ->
                let port = if row.Operation = "bind" then row.Port else 0us

                match step pid (Syscall.Bind (fd, sockaddr platform row.CandidateAddress port, 16u)) system with
                | Ok (SteppedCall.Bind (BindAnswer.Bound _, system)) -> "OK", system
                | Ok (SteppedCall.Bind (BindAnswer.Failed error, system)) -> answered error, system
                | Ok other -> failwith $"%s{row.Line}: bind stepped to %A{other}"
                | Error refusal -> describeRefusal refusal, system
            | "connect" ->
                match step pid (Syscall.Connect (fd, sockaddr platform "127.0.0.1" unused, 16u)) system with
                | Ok (SteppedCall.Connect (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), system)) ->
                    "OK", system
                | Ok (SteppedCall.Connect (SyscallOutcome.Answered (SyscallAnswer.Failed error), system)) ->
                    answered error, system
                | Ok other -> failwith $"%s{row.Line}: connect stepped to %A{other}"
                | Error refusal -> describeRefusal refusal, system
            | "write" ->
                let buffer =
                    CopiedArgument.Readable (System.Collections.Immutable.ImmutableArray.Create<byte> [| 0x78uy |])

                match step pid (Syscall.Write (fd, buffer, 1UL)) system with
                | Ok (SteppedCall.Write (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Failed error), system),
                                         None)) -> answered error, system
                | Ok other -> failwith $"%s{row.Line}: write stepped to %A{other}"
                | Error refusal -> describeRefusal refusal, system
            | other -> failwith $"%s{row.Line}: unknown operation %s{other}"

        answer, nameOf pid fd system

    let private replay (platform : SimulatedUnixPlatform) (flavour : string) : int =
        let mismatches =
            rows flavour
            |> List.filter modelled
            |> List.choose (fun row ->
                let answer, name = candidate platform row

                if (answer, name) = (row.Answer, row.Name) then
                    None
                else
                    Some $"%s{row.Line}\n  model: %s{answer} name=%s{name}"
            )

        if not (List.isEmpty mismatches) then
            failwith (
                $"%d{List.length mismatches} rows differ from the model:\n"
                + String.concat "\n" mismatches
            )

        rows flavour |> List.filter modelled |> List.length

    [<Test>]
    let ``Linux shares a port between two processes exactly where it was measured to`` () : unit =
        // Two holder flags by two candidate flags (of four each); for each
        // uid pairing: UDP idle, 3 holder addresses by 3 candidate addresses,
        // 2 searches, connect and write; UDP connected, 1 by 3, 2, 2; TCP idle
        // and listening, 3 by 3 and 2 searches; and the 4 UDP and 2 TCP
        // control searches whose sockets carry no SO_REUSEPORT.
        let perFlags = (9 + 3 * 4) + (3 + 2 + 2) + 2 * (9 + 3 * 2)

        replay SimulatedUnixPlatform.linuxX64 "linux"
        |> shouldEqual (4 * 2 * perFlags + 2 * 6)

    [<Test>]
    let ``Darwin shares a port exactly where it was measured to`` () : unit =
        // Two holder flags by two candidate flags; UDP idle, 2 by 2; UDP
        // connected, 1 by 2; TCP idle and listening, 2 by 2.
        replay SimulatedUnixPlatform.macOsArm64 "darwin"
        |> shouldEqual (4 * (4 + 2 + 2 * 4))

    /// `SO_REUSEPORT`, in each flavour's numbering.
    let private reusePortOption (platform : SimulatedUnixPlatform) : int =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> 15
        | SimulatedUnixFlavour.Darwin -> 0x0200

    /// The probe's rows with `SO_REUSEPORT` on either side are not replayed,
    /// because this kernel refuses to set the option rather than set one it
    /// would then ignore.
    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``SO_REUSEPORT, which the unreplayed rows carry, is refused`` (flavour : string) : unit =
        let platform =
            match flavour with
            | "linux" -> SimulatedUnixPlatform.linuxX64
            | _ -> SimulatedUnixPlatform.macOsArm64

        let system =
            UnixSystem.initial platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let pid = Lone.pid system
        let fd, system = socketOf pid SocketKind.Datagram "-" system

        let call =
            Syscall.SetSockOpt (
                fd,
                SimulatedUnixPlatform.socketOptionLevel platform,
                reusePortOption platform,
                CopiedArgument.Readable (OptionValue.ofInt 1),
                4u
            )

        match step pid call system with
        | Error (SyscallRefusal.SetSockOpt (SocketOptionRefusal.UnmodelledOption _)) -> ()
        | other -> failwith $"setsockopt(SO_REUSEPORT) answered %A{other}"

        rows flavour |> List.exists (fun row -> not (modelled row)) |> shouldEqual true
