namespace WoofWare.PosixKernel.Test

open System
open System.Buffers.Binary
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `sendto(2)` and `recvfrom(2)` with their arguments and the socket's state
/// crossed, as `udp-sendto.c` (docs/plans/2026-10-18-udp-data-path, plan
/// section 2.15) made them on each kernel it ran on: every call it recorded is
/// made again in this kernel, through `UnixSystem.step`, from the same state,
/// and must answer and leave behind what it did there.
///
/// The probe's ports are its kernel's; a row prints only whether a socket holds
/// one, and the sender's own port as `pppp`, so the rows compare whatever
/// ports each kernel chose.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramSendToProbe =

    /// A kernel the probe ran on, as this library models it, and the embedded
    /// resource holding what the probe printed there.
    type private Recording =
        {
            Platform : SimulatedUnixPlatform
            Resource : string
        }

    let private recordings : Map<string, Recording> =
        let runner (major : uint32) (minor : uint32) (release : string) architecture (machine : string) =
            $"%s{release} %s{machine}",
            {
                Platform =
                    SimulatedUnixPlatform.createOrFail
                        "TestDatagramSendToProbe"
                        (SimulatedUnixKernel.Linux (
                            {
                                Major = major
                                Minor = minor
                                Patch = 0u
                            },
                            LinuxKernelBuild.SmallBuffer960
                        ))
                        architecture
                        SimulatedPageSize.FourKiB
                        release
                Resource = $"WoofWare.PosixKernel.Test.udpRunners.udp-sendto.linux-%s{release}-%s{machine}.txt"
            }

        [
            "darwin 27.0",
            {
                Platform = SimulatedUnixPlatform.macOsArm64
                Resource = "WoofWare.PosixKernel.Test.udpSendto.darwin.txt"
            }
            "6.18.5 container",
            {
                Platform = SimulatedUnixPlatform.linuxArm64
                Resource = "WoofWare.PosixKernel.Test.udpSendto.linux.txt"
            }
            runner 6u 17u "6.17.0-1022-azure" SimulatedUnixArchitecture.X64 "x86_64"
            runner 6u 17u "6.17.0-1022-azure" SimulatedUnixArchitecture.Arm64 "aarch64"
            runner 7u 0u "7.0.0-1017-azure" SimulatedUnixArchitecture.X64 "x86_64"
            runner 7u 0u "7.0.0-1017-azure" SimulatedUnixArchitecture.Arm64 "aarch64"
        ]
        |> Map.ofList

    let private recordingNames : string list = recordings |> Map.keys |> List.ofSeq

    /// One line of the probe: its section, the inputs before the colon, and
    /// what it saw after it.
    type private Row =
        {
            Section : string
            Inputs : Map<string, string>
            Seen : Map<string, string>
            Line : string
        }

    let private pairs (text : string) : Map<string, string> =
        Regex.Matches (text, @"([\w-]+)=(-1 \w+|\S+)")
        |> Seq.map (fun m -> m.Groups.[1].Value, m.Groups.[2].Value)
        |> Map.ofSeq

    let private rows (recording : Recording) : Row list =
        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream recording.Resource with
            | null -> failwith $"embedded resource %s{recording.Resource} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.map (fun line -> line.TrimEnd '\r')
        |> Array.filter (fun line -> line.StartsWith "Z")
        |> Array.map (fun line ->
            let section = line.Substring (0, 2)
            let colon = line.IndexOf ": "

            {
                Section = section
                Inputs = pairs (line.Substring (3, colon - 3))
                Seen = pairs (line.Substring (colon + 2))
                Line = line
            }
        )
        |> List.ofArray

    // ------------------------------------------------------------ calls

    type private World = UnixSystem<int, string>

    let private step (call : Syscall<int, string>) (system : World) : Result<SteppedCall<int, string>, string> =
        UnixSystem.tryStep (Callers.leader system) call system
        |> Result.mapError SyscallRefusal.describe

    let private stepped (call : Syscall<int, string>) (system : World) : SteppedCall<int, string> =
        match step call system with
        | Ok stepped -> stepped
        | Error refusal -> failwith $"%A{call} was refused: %s{refusal}"

    let private shown (answer : SyscallAnswer) : string =
        match answer with
        | SyscallAnswer.Completed value -> $"%d{value}"
        | SyscallAnswer.Failed error -> $"-1 %O{error}"

    let private writeShown (answer : WriteAnswer) : string =
        match answer with
        | WriteAnswer.Completed value -> $"%d{value}"
        | WriteAnswer.Failed error -> $"-1 %O{error}"

    let private boot (platform : SimulatedUnixPlatform) : World =
        UnixSystem.initial<int, string> platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    let private udp (system : World) : int * World =
        match stepped (Syscall.Socket (SimulatedUnixPlatform.internetAddressFamily, 2, 0)) system with
        | SteppedCall.Socket (DescriptorAnswer.Returned fd, system) -> fd, system
        | other -> failwith $"socket: %A{other}"

    let private sockaddr (system : World) (family : int) (endpoint : Ipv4Endpoint) : byte[] =
        CopyIn.blob (UnixSystem.platform system) family endpoint

    let private inet (system : World) (endpoint : Ipv4Endpoint) : byte[] =
        sockaddr system SimulatedUnixPlatform.internetAddressFamily endpoint

    let private bindTo (fd : int) (endpoint : Ipv4Endpoint) (system : World) : World =
        let address =
            CopiedArgument.Readable (ImmutableArray.Create<byte> (inet system endpoint))

        match stepped (Syscall.Bind (fd, address, 16u)) system with
        | SteppedCall.Bind (BindAnswer.Bound _, system) -> system
        | other -> failwith $"bind: %A{other}"

    /// The address `fd` reports for itself.
    let private name (fd : int) (system : World) : Ipv4Endpoint =
        match stepped (Syscall.GetSockName (fd, UserBuffer.Mapped, 16u)) system with
        | SteppedCall.GetSockName (GetSockNameAnswer.Reported (copied, _)) -> CopyOut.endpoint copied
        | other -> failwith $"getsockname: %A{other}"

    /// A UDP socket bound to `address`, and its port.
    let private boundAt (address : Ipv4Address) (system : World) : int * uint16 * World =
        let fd, system = udp system
        let system = bindTo fd (Ipv4Endpoint.ofParts address 0us) system
        fd, (name fd system).Port, system

    let private connectBytes (fd : int) (blob : byte[]) (system : World) : string * World =
        match
            stepped (Syscall.Connect (fd, CopiedArgument.Readable (ImmutableArray.Create<byte> blob), 16u)) system
        with
        | SteppedCall.Connect (SyscallOutcome.Answered answer, system) -> shown answer, system
        | other -> failwith $"connect: %A{other}"

    let private connectTo (fd : int) (port : uint16) (system : World) : World =
        match connectBytes fd (inet system (Ipv4Endpoint.ofParts Ipv4Address.loopback port)) system with
        | "0", system -> system
        | answer, _ -> failwith $"connect to %d{port}: %s{answer}"

    /// `connect(2)` of an `AF_UNSPEC` address, which dissolves a datagram
    /// socket's peer.
    let private dissolve (fd : int) (system : World) : string * World =
        connectBytes fd (sockaddr system 0 (Ipv4Endpoint.ofParts Ipv4Address.any 0us)) system

    let private payload (length : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Array.init length (fun _ -> byte 'd'))

    let private send (fd : int) (bytes : ImmutableArray<byte>) (system : World) : string * World =
        match stepped (Syscall.Send (fd, CopiedArgument.Readable bytes, uint64 bytes.Length, 0)) system with
        | SteppedCall.Send (ProcessFate.Continues (WriteOutcome.Returns answer, system)) -> writeShown answer, system
        | other -> failwith $"send: %A{other}"

    let private close (fd : int) (system : World) : World =
        match stepped (Syscall.Close fd) system with
        | SteppedCall.Close (SyscallAnswer.Completed _, system) -> system
        | other -> failwith $"close: %A{other}"

    let private soError (fd : int) (system : World) : int * World =
        let platform = UnixSystem.platform system

        let call =
            Syscall.GetSockOpt (
                fd,
                SimulatedUnixPlatform.socketOptionLevel platform,
                SimulatedUnixPlatform.socketErrorOption platform,
                UserBuffer.Mapped,
                CopiedArgument.Readable 4u
            )

        match stepped call system with
        | SteppedCall.GetSockOpt (answer, system) -> OptionValue.readInt answer, system
        | other -> failwith $"SO_ERROR: %A{other}"

    let private fionread (fd : int) (system : World) : int * World =
        match stepped (Syscall.BytesAvailable (fd, UserBuffer.Mapped)) system with
        | SteppedCall.BytesAvailable (BytesAvailableAnswer.Reported count, system) -> count, system
        | other -> failwith $"FIONREAD: %A{other}"

    /// Every datagram `fd` holds, taken, as the probe prints them: `0`, or
    /// their count and up to eight of their lengths.
    let private drain (fd : int) (system : World) : string * World =
        let dontWait =
            MessageFlag.number (SimulatedUnixPlatform.flavour (UnixSystem.platform system)) MessageFlag.DontWait
            |> Option.get

        let rec go (lengths : int list) (system : World) =
            match stepped (Syscall.Recv (fd, UserBuffer.Mapped, 70000UL, dontWait)) system with
            | SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Completed bytes), system) ->
                go (bytes.Length :: lengths) system
            | SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Failed _), system) -> List.rev lengths, system
            | other -> failwith $"recv: %A{other}"

        match go [] system with
        | [], system -> "0", system
        | lengths, system ->
            let shown = lengths |> List.truncate 8 |> List.map string |> String.concat ","
            $"%d{lengths.Length}:%s{shown}", system

    /// A port no socket holds: one a socket was bound to and closed, as the
    /// probe's `unheld_port` finds one.
    let private unheldPort (system : World) : uint16 * World =
        let fd, port, system = boundAt Ipv4Address.loopback system
        port, close fd system

    /// The socket's own address as the probe prints it, with a port it holds
    /// as `*`.
    let private self (fd : int) (system : World) : string =
        let endpoint = name fd system
        let (Ipv4Address address) = endpoint.Address

        let dotted =
            $"%d{address >>> 24}.%d{(address >>> 16) &&& 0xFFu}.%d{(address >>> 8) &&& 0xFFu}.%d{address &&& 0xFFu}"

        if endpoint.Port = 0us then
            $"%s{dotted}:0"
        else
            $"%s{dotted}:*"

    // ------------------------------------------------------------ Z1

    /// The destination argument `dest` names, towards the receiver at `rport`
    /// or the unheld port `uport`, and its declared length.
    let private destination
        (system : World)
        (dest : string)
        (rport : uint16)
        (uport : uint16)
        : CopiedArgument<ImmutableArray<byte>> * uint32
        =
        let platform = UnixSystem.platform system
        let inet = SimulatedUnixPlatform.internetAddressFamily
        let toReceiver = Ipv4Endpoint.ofParts Ipv4Address.loopback rport

        let held (family : int) (endpoint : Ipv4Endpoint) (length : uint32) =
            CopiedArgument.Readable (ImmutableArray.Create<byte> (sockaddr system family endpoint)), length

        match dest with
        | "null" -> CopiedArgument.Unmapped 0UL, 16u
        | "unmapped" -> CopiedArgument.Unmapped 1UL, 16u
        | "good" -> held inet toReceiver 16u
        | "len0" -> held inet toReceiver 0u
        | "len1" -> held inet toReceiver 1u
        | "len8" -> held inet toReceiver 8u
        | "len17" -> held inet toReceiver 17u
        | "len129" -> held inet toReceiver 129u
        | "len300" -> held inet toReceiver 300u
        | "inet6" -> held (SimulatedUnixPlatform.internetV6AddressFamily platform) toReceiver 16u
        | "family99" -> held 99 toReceiver 16u
        | "unspec" -> held 0 toReceiver 16u
        | "port0" -> held inet (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us) 16u
        | "any" -> held inet (Ipv4Endpoint.ofParts Ipv4Address.any rport) 16u
        | "broadcast" -> held inet (Ipv4Endpoint.ofParts (Ipv4Address 0xFFFFFFFFu) rport) 16u
        | "alias" -> held inet (Ipv4Endpoint.ofParts (Ipv4Address 0x7F000002u) rport) 16u
        | "unheld" -> held inet (Ipv4Endpoint.ofParts Ipv4Address.loopback uport) 16u
        | other -> failwith $"unknown destination %s{other}"

    /// A sender in `state`, beside a receiver at `rport`: connected to it, or
    /// erred by its own send to the unheld port `eport`.
    let private sender (state : string) (rport : uint16) (eport : uint16) (system : World) : int * World =
        match state with
        | "fresh" -> udp system
        | "wildcard" ->
            let fd, _, system = boundAt Ipv4Address.any system
            fd, system
        | "loopback" ->
            let fd, _, system = boundAt Ipv4Address.loopback system
            fd, system
        | "connected" ->
            let fd, system = udp system
            fd, connectTo fd rport system
        | "erred"
        | "erred-dissolved" ->
            let fd, system = udp system
            let system = connectTo fd eport system

            match send fd (payload 1) system with
            | "1", system ->
                if state = "erred" then
                    fd, system
                else
                    let _, system = dissolve fd system
                    fd, system
            | answer, _ -> failwith $"the erred sender's send answered %s{answer}"
        | other -> failwith $"unknown state %s{other}"

    /// What the model saw of a Z1 row, as the probe prints it, or `refused`.
    let private z1 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform
        let r, rport, system = boundAt Ipv4Address.loopback system
        let eport, system = unheldPort system
        let uport, system = unheldPort system
        let s, system = sender inputs.["state"] rport eport system
        let destination, declared = destination system inputs.["dest"] rport uport
        let count = int inputs.["count"]

        let buffer =
            match inputs.["buffer"] with
            | "mapped" -> CopiedArgument.Readable (payload count)
            | _ -> CopiedArgument.Unmapped 1UL

        let flags = if inputs.["flags"] = "oob" then 0x1 else 0

        match step (Syscall.SendTo (s, buffer, uint64 count, flags, destination, declared)) system with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns answer, system))) ->
            let after = self s system
            let received, system = drain r system
            let error, _ = soError s system

            Map.ofList
                [
                    "answer", writeShown answer
                    "self", after
                    "received", received
                    "error", string error
                ]
        | Ok other -> failwith $"sendto: %A{other}"

    // ------------------------------------------------------------ Z2

    let private hex (bytes : byte seq) : string =
        bytes |> Seq.map (fun b -> b.ToString "x2") |> String.concat ""

    /// What the model saw of a Z2 row, as the probe prints it, or `refused`:
    /// made by `recvfrom`, or, if `viaRecv`, by `recv`, which a row with a
    /// NULL source and length cell is.
    let private z2Through
        (viaRecv : bool)
        (platform : SimulatedUnixPlatform)
        (inputs : Map<string, string>)
        : Map<string, string>
        =
        let flavour = SimulatedUnixPlatform.flavour platform
        let system = boot platform
        let r, rport, system = boundAt Ipv4Address.loopback system
        let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) r true system
        let t, tport, system = boundAt Ipv4Address.loopback system

        let system =
            match inputs.["queue"] with
            | "abc" ->
                let system = connectTo t rport system
                snd (send t (ImmutableArray.Create<byte> "abc"B) system)
            | "zero" ->
                let system = connectTo t rport system
                snd (send t ImmutableArray.Empty system)
            | "erred" ->
                let port, system = unheldPort system
                let system = connectTo r port system
                snd (send r (payload 1) system)
            | _ -> system

        let count = int inputs.["count"]
        let mapped = inputs.["buffer"] = "mapped"

        let buffer =
            if mapped then
                UserBuffer.Mapped
            else
                UserBuffer.Unmapped 1UL

        let flags =
            let number flag =
                MessageFlag.number flavour flag |> Option.get

            match inputs.["flags"] with
            | "0" -> 0
            | "peek" -> number MessageFlag.Peek
            | "trunc" -> number MessageFlag.Truncate
            | _ -> number MessageFlag.Peek ||| number MessageFlag.Truncate

        // `opaque` and `addressless`, which the probe cannot make, are the
        // tests' own.
        let source =
            match inputs.["address"] with
            | "null" -> UserBuffer.Unmapped 0UL
            | "mapped" -> UserBuffer.Mapped
            | "addressless" -> UserBuffer.Addressless
            | _ -> UserBuffer.Unmapped 1UL

        let cell =
            match inputs.["cell"] with
            | "null" -> CopiedArgument.Unmapped 0UL
            | "unmapped" -> CopiedArgument.Unmapped 1UL
            | "ffffffff" -> CopiedArgument.Readable 0xFFFFFFFFu
            | "opaque" -> CopiedArgument.Opaque
            | "addressless" -> CopiedArgument.Addressless
            | value -> CopiedArgument.Readable (uint32 value)

        let made =
            if viaRecv then
                match step (Syscall.Recv (r, buffer, uint64 count, flags)) system with
                | Ok (SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Completed bytes), system)) ->
                    Ok (Ok (RecvFromAnswer.Received (bytes, int64 bytes.Length, PeerAddressCopy.NotRequested), system))
                | Ok (SteppedCall.Recv (ReadOutcome.Answered (ReadAnswer.Failed error), system)) ->
                    Ok (Ok (RecvFromAnswer.Failed error, system))
                | Ok other -> Ok (Error $"recv: %A{other}")
                | Error refusal -> Error refusal
            else
                match step (Syscall.RecvFrom (r, buffer, uint64 count, flags, source, cell)) system with
                | Ok (SteppedCall.RecvFrom (RecvFromOutcome.Answered answer, system)) -> Ok (Ok (answer, system))
                | Ok other -> Ok (Error $"recvfrom: %A{other}")
                | Error refusal -> Error refusal

        match made with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (Error unexpected) -> failwith unexpected
        | Ok (Ok (answer, system)) ->
            let data = Array.create 16 0xBBuy
            let address = Array.create 32 0xAAuy

            let cellAfter =
                match cell with
                | CopiedArgument.Readable value -> Some value
                | _ -> None

            let returned, written, cellAfter, answerShown =
                match answer with
                | RecvFromAnswer.Received (bytes, returned, copy) ->
                    let cellAfter =
                        match copy with
                        | PeerAddressCopy.Written (copiedOut, reported) ->
                            copiedOut.CopyTo address
                            Some (uint32 reported)
                        | PeerAddressCopy.NotRequested -> cellAfter

                    returned, bytes, cellAfter, $"%d{returned}"
                | RecvFromAnswer.Failed error -> -1L, ImmutableArray.Empty, cellAfter, $"-1 %O{error}"
                | RecvFromAnswer.FailedAfterReceiving (error, bytes, overwritten) ->
                    -1L, bytes, (overwritten |> Option.orElse cellAfter), $"-1 %O{error}"

            written.CopyTo data

            let dataShown =
                if mapped then
                    let shown = int (max 0L (min returned (int64 (min count 16))))
                    hex (data |> Array.truncate (shown + (if shown < 16 then 1 else 0)))
                else
                    "-"

            let addressShown =
                if inputs.["address"] = "mapped" then
                    let port = hex [| byte (tport >>> 8) ; byte tport |]
                    let text = hex (Array.truncate 20 address)

                    if text.Substring (4, 4) = port then
                        text.Substring (0, 4) + "pppp" + text.Substring 8
                    else
                        text
                else
                    "-"

            let error, system = soError r system
            let left, _ = drain r system

            Map.ofList
                [
                    "answer", answerShown
                    "data", dataShown
                    "addr", addressShown
                    "len", (cellAfter |> Option.map string |> Option.defaultValue "-")
                    "error", string error
                    "left", left
                ]

    let private z2 : SimulatedUnixPlatform -> Map<string, string> -> Map<string, string> =
        z2Through false

    // ------------------------------------------------------------ Z3, Z4

    /// What the model saw of a Z3 row (Darwin): whether a send that only
    /// takes the error another socket's sendto left marks the socket as
    /// having sent. The probe's `a-shows-error`, its own check that the error
    /// arrived, is not compared.
    let private z3 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform
        let a, system = udp system
        let system = ReuseAddress.set true a system
        let system = bindTo a (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us) system
        let shared = name a system
        let u, system = unheldPort system
        let system = connectTo a u system
        let variant = inputs.["variant"]
        let seen = ResizeArray<string * string> ()

        let system =
            if variant = "none" then
                system
            else
                let b, system = udp system
                let system = ReuseAddress.set true b system
                let system = bindTo b shared system

                let toUnheld =
                    CopiedArgument.Readable (
                        ImmutableArray.Create<byte> (inet system (Ipv4Endpoint.ofParts Ipv4Address.loopback u))
                    )

                match
                    stepped (Syscall.SendTo (b, CopiedArgument.Readable (payload 1), 1UL, 0, toUnheld, 16u)) system
                with
                | SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns answer, system)) ->
                    seen.Add ("b-sendto", writeShown answer)
                    let error, system = soError b system
                    seen.Add ("b-error", string error)
                    close b system
                | other -> failwith $"sendto: %A{other}"

        let system =
            match variant with
            | "send" ->
                let answer, system = send a (payload 1) system
                seen.Add ("a-send", answer)
                system
            | "so_error" ->
                let error, system = soError a system
                seen.Add ("a-error", string error)
                system
            | _ -> system

        let unspec, system = dissolve a system
        seen.Add ("unspec", unspec)
        let t, _, system = boundAt Ipv4Address.loopback system
        let system = connectTo t shared.Port system
        let _, system = send t (payload 10) system
        let available, system = fionread a system
        seen.Add ("fionread", string available)
        let error, system = soError a system
        seen.Add ("error", string error)
        let left, _ = drain a system
        seen.Add ("left", left)
        Map.ofSeq seen

    /// What the model saw of a Z5 row: a `recvfrom` with an unmapped length
    /// cell through a closed descriptor, a pipe, or an empty UDP socket.
    let private z5 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform

        let fd, system =
            match inputs.["fd"] with
            | "closed" -> 77, system
            | "pipe" -> 0, system
            | _ ->
                let fd, _, system = boundAt Ipv4Address.loopback system
                fd, system

        let source =
            if inputs.["address"] = "null" then
                UserBuffer.Unmapped 0UL
            else
                UserBuffer.Mapped

        let dontWait =
            MessageFlag.number (SimulatedUnixPlatform.flavour platform) MessageFlag.DontWait
            |> Option.get

        let call =
            Syscall.RecvFrom (fd, UserBuffer.Mapped, 4UL, dontWait, source, CopiedArgument.Unmapped 1UL)

        match step call system with
        | Ok (SteppedCall.RecvFrom (RecvFromOutcome.Answered (RecvFromAnswer.Failed error), _)) ->
            Map.ofList [ "answer", $"-1 %O{error}" ]
        | other -> failwith $"recvfrom: %A{other}"

    /// What the model saw of a Z4 row (Darwin): what a datagram of 10 bytes
    /// costs a socket after one sendto, or `refused`.
    let private z4 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform
        let r, rport, system = boundAt Ipv4Address.loopback system
        ignore<int> r
        let s, sport, system = boundAt Ipv4Address.loopback system
        let call = inputs.["call"]

        let answer =
            if call = "none" then
                Ok ("-", system)
            else
                let uport, system = unheldPort system
                let destination, declared = destination system inputs.["dest"] rport uport
                let count = if call = "large" then 9217 else 1

                let buffer =
                    if call = "fault" then
                        CopiedArgument.Unmapped 1UL
                    else
                        CopiedArgument.Readable (payload count)

                let flags = if call = "oob" then 0x1 else 0

                match step (Syscall.SendTo (s, buffer, uint64 count, flags, destination, declared)) system with
                | Error refusal -> Error refusal
                | Ok (SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns answer, system))) ->
                    Ok (writeShown answer, system)
                | Ok other -> failwith $"sendto: %A{other}"

        match answer with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (answer, system) ->
            let t, _, system = boundAt Ipv4Address.loopback system
            let system = connectTo t sport system
            let _, system = send t (payload 10) system
            let available, _ = fionread s system
            Map.ofList [ "answer", answer ; "fionread", string available ]

    // ------------------------------------------------------------ the tests

    /// Whether the model must refuse the row's call rather than answer it:
    /// `MSG_OOB`, which no send models, and a Darwin receive that would copy
    /// a datagram into an unmapped buffer (plan section 3.6).
    let private refuses (platform : SimulatedUnixPlatform) (row : Row) : bool =
        let darwin = SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Darwin

        match row.Section with
        | "Z1" -> row.Inputs.["flags"] = "oob"
        | "Z4" -> row.Inputs.["call"] = "oob"
        | "Z2" ->
            darwin
            && row.Inputs.["buffer"] = "unmapped"
            && row.Inputs.["count"] <> "0"
            && not (row.Inputs.["flags"].Contains "peek")
            && (row.Inputs.["queue"] = "abc")
            && row.Inputs.["cell"] <> "unmapped"
        | _ -> false

    let private replayThrough
        (observe : SimulatedUnixPlatform -> Map<string, string> -> Map<string, string>)
        (refuses : SimulatedUnixPlatform -> Row -> bool)
        (chosen : Row -> bool)
        (section : string)
        (name : string)
        : unit
        =
        let recording = recordings.[name]
        let platform = recording.Platform

        let rows =
            rows recording |> List.filter (fun row -> row.Section = section && chosen row)

        if rows.IsEmpty then
            failwith $"%s{name} recorded no %s{section} rows"

        let wrong =
            rows
            |> List.choose (fun row ->
                let seen = observe platform row.Inputs

                let expected =
                    if refuses platform row then
                        Map.ofList [ "refused", "" ]
                    else
                        row.Seen |> Map.remove "a-shows-error"

                if seen = expected then
                    None
                else
                    Some $"%s{row.Line}\n    model: %A{Map.toList seen}"
            )

        if not wrong.IsEmpty then
            let shown = wrong |> List.truncate 20 |> String.concat "\n"
            failwith $"%d{wrong.Length} of %d{rows.Length} rows differ on %s{name}:\n%s{shown}"

    let private replay (section : string) (name : string) : unit =
        let observe =
            match section with
            | "Z1" -> z1
            | "Z2" -> z2
            | "Z3" -> z3
            | "Z4" -> z4
            | _ -> z5

        replayThrough observe refuses (fun _ -> true) section name

    [<TestCaseSource(nameof recordingNames)>]
    let ``every sendto of udp-sendto.c answers as its kernel did`` (name : string) : unit = replay "Z1" name

    [<TestCaseSource(nameof recordingNames)>]
    let ``every recvfrom of udp-sendto.c answers as its kernel did`` (name : string) : unit = replay "Z2" name

    /// `recv(2)` is `recvfrom(2)` with a NULL source and length cell, as each
    /// kernel's own `recv` is, but for `MSG_TRUNC`, which it refuses.
    [<TestCaseSource(nameof recordingNames)>]
    let ``every recv of udp-sendto.c, a recvfrom with no source, answers as its kernel did`` (name : string) : unit =
        let refusesRecv (platform : SimulatedUnixPlatform) (row : Row) : bool =
            row.Inputs.["flags"].Contains "trunc" || refuses platform row

        replayThrough
            (z2Through true)
            refusesRecv
            (fun row -> row.Inputs.["address"] = "null" && row.Inputs.["cell"] = "null")
            "Z2"
            name

    /// The Z2 rows of `name` with a length cell holding 16, each made again
    /// with the cell `cell` instead, and what the model saw of each.
    let private withCell (cell : string) (name : string) : (Row * Map<string, string>) list =
        let recording = recordings.[name]

        rows recording
        |> List.filter (fun row -> row.Section = "Z2" && row.Inputs.["cell"] = "16")
        |> List.map (fun row -> row, z2 recording.Platform (Map.add "cell" cell row.Inputs))

    /// Whether the receive of a Z2 row took or peeked at a datagram, copying
    /// it to the buffer without a fault.
    let private receivedADatagram (row : Row) : bool =
        match row.Inputs.["queue"] with
        | "zero" -> true
        | "abc" -> not (row.Inputs.["buffer"] = "unmapped" && row.Inputs.["count"] <> "0")
        | _ -> false

    /// Whether the call of a Z2 row used what its length cell held: a
    /// datagram was received, for a source that is not NULL.
    let private usesTheCell (platform : SimulatedUnixPlatform) (row : Row) : bool =
        row.Inputs.["address"] <> "null"
        && receivedADatagram row
        && not (refuses platform row)

    /// A cell whose contents the client cannot produce is real storage, which
    /// each flavour reads without a fault, and what it holds matters only
    /// where the call uses it: anywhere else, the call answers as the cell
    /// holding 16 did, but for what it writes to the cell.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a recvfrom answers whatever an opaque length cell holds, unless it uses it`` (name : string) : unit =
        let platform = recordings.[name].Platform

        for row, seen in withCell "opaque" name do
            if refuses platform row || usesTheCell platform row then
                seen |> shouldEqual (Map.ofList [ "refused", "" ])
            else
                seen |> Map.remove "len" |> shouldEqual (row.Seen |> Map.remove "len")

    /// A cell that is no address may be NULL, or fault. Linux reads it only
    /// where it uses it, so it answers anywhere else as the cell holding 16
    /// did; Darwin reads it before anything else (Z5), so it refuses.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a recvfrom answers whatever a length cell that is no address is, unless it reads it`` (name : string) : unit =
        let platform = recordings.[name].Platform

        for row, seen in withCell "addressless" name do
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Darwin -> seen |> shouldEqual (Map.ofList [ "refused", "" ])
            | SimulatedUnixFlavour.Linux ->
                if refuses platform row || usesTheCell platform row then
                    seen |> shouldEqual (Map.ofList [ "refused", "" ])
                else
                    seen |> Map.remove "len" |> shouldEqual (row.Seen |> Map.remove "len")

    /// A source that is no address cannot be told from NULL, nor from a
    /// real buffer or one that faults, and which it is decides what a
    /// `recvfrom` writes. Wherever those answer differently the call is
    /// refused; where they agree it may still be, but where the receive
    /// itself failed, so that no source is written, it answers.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a recvfrom whose source is no address answers only where every source would agree`` (name : string) : unit =
        let recording = recordings.[name]
        let platform = recording.Platform
        let all = rows recording |> List.filter (fun row -> row.Section = "Z2")

        let find (row : Row) (address : string) : Row =
            all
            |> List.find (fun other -> other.Inputs = Map.add "address" address row.Inputs)

        for row in all |> List.filter (fun row -> row.Inputs.["address"] = "null") do
            if not (refuses platform row) then
                let seen = z2 platform (Map.add "address" "addressless" row.Inputs)

                let answers =
                    [ row ; find row "mapped" ; find row "unmapped" ]
                    |> List.map (fun row -> row.Seen |> Map.remove "addr")
                    |> List.distinct

                // With the source NULL, the answer is the receive's own.
                let receiveFailed = row.Seen.["answer"].StartsWith "-1"

                match answers with
                | [ only ] when receiveFailed -> seen |> shouldEqual (only |> Map.add "addr" "-")
                | [ only ] ->
                    if seen <> Map.ofList [ "refused", "" ] then
                        seen |> shouldEqual (only |> Map.add "addr" "-")
                | _ -> seen |> shouldEqual (Map.ofList [ "refused", "" ])

    /// A model of `recvfrom` with nothing to receive, and of `sendto`, on a
    /// descriptor that is not open: `EBADF`, whatever the call could not
    /// have read of its other arguments.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a closed descriptor is EBADF whatever the length cell or destination is`` (name : string) : unit =
        let system = boot recordings.[name].Platform

        // Darwin reads a cell that is not NULL first (Z5), and whether one
        // that is no address faults is not known.
        let cells =
            match SimulatedUnixPlatform.flavour recordings.[name].Platform with
            | SimulatedUnixFlavour.Linux -> [ CopiedArgument.Opaque ; CopiedArgument.Addressless ]
            | SimulatedUnixFlavour.Darwin -> [ CopiedArgument.Opaque ]

        for cell in cells do
            match step (Syscall.RecvFrom (77, UserBuffer.Mapped, 4UL, 0, UserBuffer.Mapped, cell)) system with
            | Ok (SteppedCall.RecvFrom (RecvFromOutcome.Answered (RecvFromAnswer.Failed UnixError.EBADF), _)) -> ()
            | other -> failwith $"recvfrom: %A{other}"

        for destination in [ CopiedArgument.Opaque ; CopiedArgument.Addressless ] do
            match step (Syscall.SendTo (77, CopiedArgument.Readable (payload 1), 1UL, 0, destination, 16u)) system with
            | Ok (SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns (WriteAnswer.Failed UnixError.EBADF),
                                                             _))) -> ()
            | other -> failwith $"sendto: %A{other}"

    /// A destination that is no address cannot be told from NULL, which makes
    /// the call a `send`: refused.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendto whose destination is no address is refused`` (name : string) : unit =
        let system = boot recordings.[name].Platform
        let s, system = udp system

        for length in [ 0u ; 16u ] do
            let call =
                Syscall.SendTo (s, CopiedArgument.Readable (payload 1), 1UL, 0, CopiedArgument.Addressless, length)

            match step call system with
            | Error _ -> ()
            | Ok other -> failwith $"sendto through an addressless destination: %A{other}"

    /// This kernel makes no IPv6 binding, and `sendto` with a destination and
    /// `recvfrom` read and write only a `struct sockaddr_in`.
    [<TestCaseSource(nameof recordingNames)>]
    let ``an IPv6 UDP socket's sendto with a destination, and its recvfrom, are refused`` (name : string) : unit =
        let platform = recordings.[name].Platform
        let system = boot platform

        let fd, system =
            match stepped (Syscall.Socket (SimulatedUnixPlatform.internetV6AddressFamily platform, 2, 0)) system with
            | SteppedCall.Socket (DescriptorAnswer.Returned fd, system) -> fd, system
            | other -> failwith $"socket: %A{other}"

        let toLoopback =
            CopiedArgument.Readable (
                ImmutableArray.Create<byte> (
                    CopyIn.inet6Mapped platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 5000us)
                )
            )

        match step (Syscall.SendTo (fd, CopiedArgument.Readable (payload 1), 1UL, 0, toLoopback, 28u)) system with
        | Error _ -> ()
        | Ok other -> failwith $"sendto: %A{other}"

        match
            step
                (Syscall.RecvFrom (fd, UserBuffer.Mapped, 4UL, 0, UserBuffer.Mapped, CopiedArgument.Readable 28u))
                system
        with
        | Error _ -> ()
        | Ok other -> failwith $"recvfrom: %A{other}"

    [<Test>]
    let ``a Darwin send that only takes a pending error marks the socket as having sent`` () : unit =
        replay "Z3" "darwin 27.0"

    /// The runners' recordings predate Z5.
    [<TestCase("darwin 27.0")>]
    [<TestCase("6.18.5 container")>]
    let ``a recvfrom reads a length cell before the descriptor on Darwin and after the receive on Linux``
        (name : string)
        : unit
        =
        replay "Z5" name

    [<Test>]
    let ``a Darwin sendto marks the socket as having sent unless copying its destination failed`` () : unit =
        replay "Z4" "darwin 27.0"
