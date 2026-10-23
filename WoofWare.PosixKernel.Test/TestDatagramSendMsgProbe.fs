namespace WoofWare.PosixKernel.Test

open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// `sendmsg(2)` with its arguments and the socket's state crossed, as
/// `udp-msg.c` (docs/plans/2026-10-18-udp-data-path, plan section 2.17) made
/// it on each kernel it ran on: every `sendmsg` it recorded is made again in
/// this kernel, through `UnixSystem.step`, from the same state, and must answer
/// and leave behind what it did there.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramSendMsgProbe =

    /// A kernel the probe ran on, as this library models it, and the embedded
    /// resource holding what the probe printed there.
    type private Recording =
        {
            Platform : SimulatedUnixPlatform
            Resource : string
        }

    let private recordings : Map<string, Recording> =
        [
            "darwin 27.0",
            {
                Platform = SimulatedUnixPlatform.macOsArm64
                Resource = "WoofWare.PosixKernel.Test.udpMsg.darwin.txt"
            }
            "6.18.5 container",
            {
                Platform = SimulatedUnixPlatform.linuxArm64
                Resource = "WoofWare.PosixKernel.Test.udpMsg.linux.txt"
            }
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
        |> Array.filter (fun line -> line.StartsWith "Y")
        |> Array.map (fun line ->
            let colon = line.IndexOf ": "

            {
                Section = line.Substring (0, 2)
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

    let private connectTo (fd : int) (port : uint16) (system : World) : World =
        let blob = inet system (Ipv4Endpoint.ofParts Ipv4Address.loopback port)

        match
            stepped (Syscall.Connect (fd, CopiedArgument.Readable (ImmutableArray.Create<byte> blob), 16u)) system
        with
        | SteppedCall.Connect (SyscallOutcome.Answered answer, system) when shown answer = "0" -> system
        | other -> failwith $"connect to %d{port}: %A{other}"

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

    let private sendmsg
        (fd : int)
        (message : CopiedArgument<SentMessage>)
        (flags : int)
        (system : World)
        : Result<string * World, string>
        =
        match step (Syscall.SendMsg (fd, message, flags)) system with
        | Error refusal -> Error refusal
        | Ok (SteppedCall.SendMsg (ProcessFate.Continues (WriteOutcome.Returns answer, system))) ->
            Ok (writeShown answer, system)
        | Ok other -> failwith $"sendmsg: %A{other}"

    // ------------------------------------------------------------ Y1, Y5

    /// A `size_t` with only its top bit set: negative as an `ssize_t`.
    let private negative : uint64 = 1UL <<< 63

    /// `SIZE_MAX >> 1`, which the probe's `huge` iovecs are.
    let private huge : uint64 = System.UInt64.MaxValue >>> 1

    /// The message of a Y1 row, from a sender beside the receiver at `rport`.
    let private message (system : World) (inputs : Map<string, string>) (rport : uint16) : CopiedArgument<SentMessage> =
        let flavour = SimulatedUnixPlatform.flavour (UnixSystem.platform system)

        let vector (bytes : ImmutableArray<byte>) (length : uint64) =
            {
                SentBase = CopiedArgument.Readable bytes
                SentLength = length
            }

        // The probe's two iovecs, of 2 and 1 bytes of its payload; what it
        // changes of them; and the rest of its array of 2000, NULL and empty.
        let first, second =
            match inputs.["iov"] with
            | "good" -> vector (payload 2) 2UL, vector (payload 1) 1UL
            | "base0" ->
                {
                    SentBase = CopiedArgument.Unmapped 1UL
                    SentLength = 2UL
                },
                vector (payload 1) 1UL
            | "base1" ->
                vector (payload 2) 2UL,
                {
                    SentBase = CopiedArgument.Unmapped 1UL
                    SentLength = 1UL
                }
            | "neg0" -> vector ImmutableArray.Empty negative, vector (payload 1) 1UL
            | "huge" -> vector ImmutableArray.Empty huge, vector ImmutableArray.Empty huge
            | "big" -> vector (payload 35000) 35000UL, vector (payload 35000) 35000UL
            | "empty" -> vector ImmutableArray.Empty 0UL, vector ImmutableArray.Empty 0UL
            | other -> failwith $"unknown iovecs %s{other}"

        let vectors =
            ImmutableArray.CreateRange (
                first
                :: second
                :: List.replicate
                    1998
                    {
                        SentBase = CopiedArgument.Unmapped 0UL
                        SentLength = 0UL
                    }
            )

        let count =
            match inputs.["iovlen"] with
            | "neg" ->
                match flavour with
                | SimulatedUnixFlavour.Linux -> System.UInt64.MaxValue
                | SimulatedUnixFlavour.Darwin -> 0xFFFFFFFFUL
            | count -> uint64 count

        let toReceiver = Ipv4Endpoint.ofParts Ipv4Address.loopback rport

        // The probe's name buffer is 512 bytes, the address at its start.
        let named (family : int) (endpoint : Ipv4Endpoint) (length : uint32) =
            let buffer = Array.zeroCreate<byte> 512
            (sockaddr system family endpoint).CopyTo (buffer, 0)
            CopiedArgument.Readable (ImmutableArray.Create<byte> buffer), length

        let inetFamily = SimulatedUnixPlatform.internetAddressFamily

        let name, nameLength =
            match inputs.["name"] with
            | "good" -> named inetFamily toReceiver 16u
            | "null" -> CopiedArgument.Unmapped 0UL, 0u
            | "nulllen16" -> CopiedArgument.Unmapped 0UL, 16u
            | "len0" -> named inetFamily toReceiver 0u
            | "len8" -> named inetFamily toReceiver 8u
            | "len129" -> named inetFamily toReceiver 129u
            | "unmapped" -> CopiedArgument.Unmapped 1UL, 16u
            | "family99" -> named 99 toReceiver 16u
            | "port0" -> named inetFamily (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us) 16u
            | other -> failwith $"unknown name %s{other}"

        let zeros =
            CopiedArgument.Readable (ImmutableArray.Create<byte> (Array.zeroCreate<byte> 64))

        let control, controlLength =
            match inputs.["control"] with
            | "none" -> CopiedArgument.Unmapped 0UL, 0UL
            | "nulllen16" -> CopiedArgument.Unmapped 0UL, 16UL
            | "unmapped16" -> CopiedArgument.Unmapped 1UL, 16UL
            | "zero8" -> zeros, 8UL
            | "zero16" -> zeros, 16UL
            | "big" -> zeros, 0x80000000UL
            | other -> failwith $"unknown control %s{other}"

        let sent =
            {
                SentName = name
                SentNameLength = nameLength
                SentVectors =
                    if inputs.["array"] = "unmapped" then
                        CopiedArgument.Unmapped 1UL
                    else
                        CopiedArgument.Readable vectors
                SentVectorCount = count
                SentControl = control
                SentControlLength = controlLength
            }

        match inputs.["header"] with
        | "unmapped" -> CopiedArgument.Unmapped 1UL
        // A read-only header is real storage, which `sendmsg` only reads.
        | _ -> CopiedArgument.Readable sent

    /// A sender in `state`, beside a receiver at `rport`: connected to it, or
    /// erred by its own send to a port nobody holds.
    let private sender (state : string) (rport : uint16) (system : World) : int * World =
        match state with
        | "fresh" -> udp system
        | "loopback" ->
            let fd, _, system = boundAt Ipv4Address.loopback system
            fd, system
        | "connected" ->
            let fd, system = udp system
            fd, connectTo fd rport system
        | "erred" ->
            let eport, system = unheldPort system
            let fd, system = udp system
            let system = connectTo fd eport system

            match send fd (payload 1) system with
            | "1", system -> fd, system
            | answer, _ -> failwith $"the erred sender's send answered %s{answer}"
        | other -> failwith $"unknown state %s{other}"

    let private flagsOf (inputs : Map<string, string>) : int =
        if inputs.["flags"] = "oob" then 0x1 else 0

    /// What the model saw of a Y1 row, as the probe prints it, or `refused`.
    let private y1 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform
        let r, rport, system = boundAt Ipv4Address.loopback system
        let s, system = sender inputs.["state"] rport system

        match sendmsg s (message system inputs rport) (flagsOf inputs) system with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (answer, system) ->
            let after = self s system
            let received, system = drain r system
            let error, _ = soError s system

            Map.ofList
                [
                    "answer", answer
                    "self", after
                    "received", received
                    "error", string error
                ]

    /// What the model saw of a Y5 row: what a datagram of 10 bytes costs the
    /// sender after its `sendmsg`, or `refused`.
    let private y5 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform
        let _, rport, system = boundAt Ipv4Address.loopback system
        let s, sport, system = boundAt Ipv4Address.loopback system

        match sendmsg s (message system inputs rport) (flagsOf inputs) system with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (answer, system) ->
            let t, _, system = boundAt Ipv4Address.loopback system
            let system = connectTo t sport system
            let _, system = send t (payload 10) system
            let available, _ = fionread s system
            Map.ofList [ "answer", answer ; "fionread", string available ]

    // ------------------------------------------------------------ Y4, Y6

    /// A header with one iovec, of `length` bytes from `bytes`, and a name of
    /// 16 bytes towards `port`.
    let private single
        (system : World)
        (port : uint16)
        (bytes : CopiedArgument<ImmutableArray<byte>>)
        (lengths : uint64 list)
        : SentMessage
        =
        {
            SentName =
                CopiedArgument.Readable (
                    ImmutableArray.Create<byte> (inet system (Ipv4Endpoint.ofParts Ipv4Address.loopback port))
                )
            SentNameLength = 16u
            SentVectors =
                lengths
                |> List.map (fun length ->
                    {
                        SentBase = bytes
                        SentLength = length
                    }
                )
                |> ImmutableArray.CreateRange
                |> CopiedArgument.Readable
            SentVectorCount = uint64 lengths.Length
            SentControl = CopiedArgument.Unmapped 0UL
            SentControlLength = 0UL
        }

    /// What the model saw of a Y4 `sendmsg` row.
    let private y4 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform

        let fd, system =
            match inputs.["fd"] with
            | "closed" -> 77, system
            | "pipe" ->
                match stepped (Syscall.Pipe2 (UserBuffer.Mapped, 0)) system with
                | SteppedCall.Pipe2 (Pipe2Answer.Created (readFd, _), system) -> readFd, system
                | other -> failwith $"pipe: %A{other}"
            | _ ->
                let fd, _, system = boundAt Ipv4Address.loopback system
                fd, system

        let port, system = unheldPort system
        let message = single system port (CopiedArgument.Readable (payload 16)) [ 16UL ]

        let message =
            match inputs.["fault"] with
            | "header" -> CopiedArgument.Unmapped 1UL
            | "array" ->
                CopiedArgument.Readable
                    { message with
                        SentVectors = CopiedArgument.Unmapped 1UL
                    }
            | "name" ->
                CopiedArgument.Readable
                    { message with
                        SentName = CopiedArgument.Unmapped 1UL
                    }
            | "iovlen1025" ->
                CopiedArgument.Readable
                    { message with
                        SentVectorCount = 1025UL
                    }
            | "neg0" -> CopiedArgument.Readable (single system port (CopiedArgument.Readable (payload 16)) [ negative ])
            | "namelenffffffff" ->
                CopiedArgument.Readable
                    { message with
                        SentNameLength = 0xFFFFFFFFu
                    }
            | other -> failwith $"unknown fault %s{other}"

        match sendmsg fd message 0 system with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (answer, _) -> Map.ofList [ "answer", answer ]

    /// What the model saw of a Y6 `sendmsg` row: one iovec of the row's
    /// total, or two of half of it each. Their bytes are left empty, since
    /// no call copies so many.
    let private y6 (platform : SimulatedUnixPlatform) (inputs : Map<string, string>) : Map<string, string> =
        let system = boot platform
        let _, rport, system = boundAt Ipv4Address.loopback system
        let s, _, system = boundAt Ipv4Address.loopback system
        let total = System.Convert.ToUInt64 (inputs.["total"], 16)

        let lengths =
            if inputs.["iovecs"] = "2" then
                [ total / 2UL ; total - total / 2UL ]
            else
                [ total ]

        let message =
            single system rport (CopiedArgument.Readable ImmutableArray.Empty) lengths

        match sendmsg s (CopiedArgument.Readable message) 0 system with
        | Error _ -> Map.ofList [ "refused", "" ]
        | Ok (answer, _) -> Map.ofList [ "answer", answer ]

    // ------------------------------------------------------------ the tests

    /// The arguments of a Y1 or Y5 row whose change of value fails the call
    /// before it reaches its control buffer (plan section 2.17).
    let private failsBeforeControl (platform : SimulatedUnixPlatform) (row : Row) : bool =
        let changed (dimension : string) (values : string list) =
            List.contains row.Inputs.[dimension] values

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            changed "name" [ "unmapped" ]
            || changed "iovlen" [ "1025" ; "neg" ]
            || changed "array" [ "unmapped" ]
            || changed "iov" [ "neg0" ; "huge" ]
        | SimulatedUnixFlavour.Darwin ->
            changed "name" [ "len0" ; "unmapped" ]
            || changed "iovlen" [ "0" ; "1025" ; "neg" ]
            || changed "array" [ "unmapped" ]
            || changed "iov" [ "neg0" ; "huge" ]

    /// Whether the model must refuse the row's call rather than answer it:
    /// `MSG_OOB`, which no send models, and control data, which `sendmsg`
    /// refuses where it reaches it.
    let private refuses (platform : SimulatedUnixPlatform) (row : Row) : bool =
        match row.Section with
        | "Y1"
        | "Y5" ->
            row.Inputs.["flags"] = "oob"
            || row.Inputs.["control"] <> "none" && not (failsBeforeControl platform row)
        | _ -> false

    let private replay
        (observe : SimulatedUnixPlatform -> Map<string, string> -> Map<string, string>)
        (section : string)
        (chosen : Row -> bool)
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
                        row.Seen

                if seen = expected then
                    None
                else
                    Some $"%s{row.Line}\n    model: %A{Map.toList seen}"
            )

        if not wrong.IsEmpty then
            let shown = wrong |> List.truncate 20 |> String.concat "\n"
            failwith $"%d{wrong.Length} of %d{rows.Length} rows differ on %s{name}:\n%s{shown}"

    let private isSendMsg (row : Row) : bool = row.Inputs.["call"] = "sendmsg"

    [<TestCaseSource(nameof recordingNames)>]
    let ``every sendmsg of udp-msg.c answers as its kernel did`` (name : string) : unit =
        replay y1 "Y1" (fun _ -> true) name

    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendmsg looks the descriptor up where its kernel did`` (name : string) : unit =
        replay y4 "Y4" isSendMsg name

    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendmsg marks a Darwin socket as having sent where its kernel did`` (name : string) : unit =
        replay y5 "Y5" (fun _ -> true) name

    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendmsg lets through the iovecs its kernel did`` (name : string) : unit = replay y6 "Y6" isSendMsg name

    // ------------------------------------------------------------ against sendto

    /// The destinations `udp-sendto.c` sends to (section Z1), but IPv6's,
    /// which a `sendmsg` names the same way.
    let private destinations : string list =
        [
            "null"
            "good"
            "len0"
            "len1"
            "len8"
            "len17"
            "len129"
            "len300"
            "unmapped"
            "family99"
            "unspec"
            "port0"
            "any"
            "broadcast"
            "alias"
            "unheld"
        ]

    /// The destination `dest` names, towards the receiver at `rport` or the
    /// unheld port `uport`, in a buffer of 512 bytes, and its declared length.
    let private destination
        (system : World)
        (dest : string)
        (rport : uint16)
        (uport : uint16)
        : CopiedArgument<ImmutableArray<byte>> * uint32
        =
        let inet = SimulatedUnixPlatform.internetAddressFamily
        let toReceiver = Ipv4Endpoint.ofParts Ipv4Address.loopback rport

        let held (family : int) (endpoint : Ipv4Endpoint) (length : uint32) =
            let buffer = Array.zeroCreate<byte> 512
            (sockaddr system family endpoint).CopyTo (buffer, 0)
            CopiedArgument.Readable (ImmutableArray.Create<byte> buffer), length

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
        | "family99" -> held 99 toReceiver 16u
        | "unspec" -> held 0 toReceiver 16u
        | "port0" -> held inet (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us) 16u
        | "any" -> held inet (Ipv4Endpoint.ofParts Ipv4Address.any rport) 16u
        | "broadcast" -> held inet (Ipv4Endpoint.ofParts (Ipv4Address 0xFFFFFFFFu) rport) 16u
        | "alias" -> held inet (Ipv4Endpoint.ofParts (Ipv4Address 0x7F000002u) rport) 16u
        | "unheld" -> held inet (Ipv4Endpoint.ofParts Ipv4Address.loopback uport) 16u
        | other -> failwith $"unknown destination %s{other}"

    /// What a send left behind, as the probes print it: its answer (or
    /// `refused`), the sender's own address, what the receiver holds, and
    /// the sender's `SO_ERROR`.
    let private after (s : int) (r : int) (answer : Result<string * World, string>) : string list =
        match answer with
        | Error _ -> [ "refused" ]
        | Ok (answer, system) ->
            let me = self s system
            let received, system = drain r system
            let error, _ = soError s system
            [ answer ; me ; received ; string error ]

    /// Where the two calls part, measured (plan section 2.17): Linux's
    /// `sendmsg` sends without a name of length 0, and cuts one above 128
    /// bytes to 128, where its `sendto` answers `EINVAL`.
    let private parts (flavour : SimulatedUnixFlavour) (dest : string) : bool =
        match flavour with
        | SimulatedUnixFlavour.Linux -> List.contains dest [ "len0" ; "len129" ; "len300" ]
        | SimulatedUnixFlavour.Darwin -> false

    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendmsg of one iovec answers as sendto of its bytes to its name`` (name : string) : unit =
        let platform = recordings.[name].Platform
        let flavour = SimulatedUnixPlatform.flavour platform
        let states = [ "fresh" ; "loopback" ; "connected" ; "erred" ]
        let counts = [ 0 ; 1 ; 9217 ; 65508 ; 70000 ]

        let property (state : string) (count : int) (mapped : bool) (dest : string) : unit =
            let system = boot platform
            let r, rport, system = boundAt Ipv4Address.loopback system
            let uport, system = unheldPort system
            let s, system = sender state rport system
            let named, declared = destination system dest rport uport

            let bytes =
                if mapped then
                    CopiedArgument.Readable (payload count)
                else
                    CopiedArgument.Unmapped 1UL

            let viaSendTo =
                match step (Syscall.SendTo (s, bytes, uint64 count, 0, named, declared)) system with
                | Error refusal -> Error refusal
                | Ok (SteppedCall.SendTo (ProcessFate.Continues (WriteOutcome.Returns answer, system))) ->
                    Ok (writeShown answer, system)
                | Ok other -> failwith $"sendto: %A{other}"

            let message =
                {
                    SentName = named
                    SentNameLength = declared
                    SentVectors =
                        CopiedArgument.Readable (
                            ImmutableArray.Create
                                {
                                    SentBase = bytes
                                    SentLength = uint64 count
                                }
                        )
                    SentVectorCount = 1UL
                    SentControl = CopiedArgument.Unmapped 0UL
                    SentControlLength = 0UL
                }

            let viaSendMsg = sendmsg s (CopiedArgument.Readable message) 0 system

            after s r viaSendMsg |> shouldEqual (after s r viaSendTo)

        let generator =
            gen {
                let! state = Gen.elements states
                let! count = Gen.elements counts
                let! mapped = Gen.elements [ true ; false ]

                let! dest =
                    destinations
                    |> List.filter (fun dest -> not (parts flavour dest))
                    |> Gen.elements

                return state, count, mapped, dest
            }

        Check.One (
            Config.QuickThrowOnFailure.WithMaxTest 300,
            Prop.forAll (Arb.fromGen generator) (fun (state, count, mapped, dest) -> property state count mapped dest)
        )

    /// The header, the name and the iovec array are the client's to classify,
    /// and none of them has an answer where its contents cannot be produced,
    /// or where it is no address and could be NULL.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendmsg refuses a header, name or iovec array it cannot read`` (name : string) : unit =
        let platform = recordings.[name].Platform
        let system = boot platform
        let _, rport, system = boundAt Ipv4Address.loopback system
        let s, _, system = boundAt Ipv4Address.loopback system
        let good = single system rport (CopiedArgument.Readable (payload 3)) [ 3UL ]

        for message in
            [
                CopiedArgument.Opaque
                CopiedArgument.Addressless
                CopiedArgument.Readable
                    { good with
                        SentName = CopiedArgument.Opaque
                    }
                CopiedArgument.Readable
                    { good with
                        SentName = CopiedArgument.Addressless
                    }
                CopiedArgument.Readable
                    { good with
                        SentVectors = CopiedArgument.Opaque
                    }
                CopiedArgument.Readable
                    { good with
                        SentVectors = CopiedArgument.Addressless
                    }
            ] do
            match sendmsg s message 0 system with
            | Error _ -> ()
            | Ok (answer, _) -> failwith $"%A{message} answered %s{answer}"

        match sendmsg s (CopiedArgument.Readable good) 0 system with
        | Ok ("3", _) -> ()
        | other -> failwith $"the good message: %A{other}"

    /// A Darwin header's `msg_iovlen` and `msg_controllen` are 32 bits wide,
    /// so a value wider is no header Darwin's memory could hold.
    [<Test>]
    let ``a Darwin sendmsg refuses a header field wider than the field`` () : unit =
        let system = boot SimulatedUnixPlatform.macOsArm64
        let _, rport, system = boundAt Ipv4Address.loopback system
        let s, _, system = boundAt Ipv4Address.loopback system
        let good = single system rport (CopiedArgument.Readable (payload 3)) [ 3UL ]

        let leader = Callers.leader system

        let paused =
            match UnixReadWrite.sendmsg leader s UserBuffer.Mapped 0 system with
            | CallProgress.NeedsCopyIn paused -> paused
            | other -> failwith $"sendmsg: %A{other}"

        let header = SentMessage.header good

        for wide in
            [
                { header with
                    MessageVectorCount = 0x100000001UL
                }
                { header with
                    MessageControlLength = 0x100000000UL
                }
            ] do
            Assert.Throws<System.ArgumentOutOfRangeException> (fun () ->
                UnixReadWrite.sendmsgWithHeader wide paused |> ignore<_>
            )
            |> ignore<System.ArgumentOutOfRangeException>

    /// How many bytes of a name `namelen` long a `sendmsg` copies: in the
    /// probe (Y7), the fewest readable bytes before an unmapped page that the
    /// call sent from; in this kernel, its `PausedSendMsgName.copyRange`.
    [<TestCaseSource(nameof recordingNames)>]
    let ``a sendmsg copies as much of a long name as its kernel did`` (name : string) : unit =
        let recording = recordings.[name]
        let y7 = rows recording |> List.filter (fun row -> row.Section = "Y7")

        if y7.IsEmpty then
            failwith $"%s{name} recorded no Y7 rows"

        let system = boot recording.Platform
        let _, rport, system = boundAt Ipv4Address.loopback system
        let s, _, system = boundAt Ipv4Address.loopback system
        let leader = Callers.leader system

        for namelen in y7 |> List.map (fun row -> uint32 row.Inputs.["namelen"]) |> List.distinct do
            let measured =
                y7
                |> List.filter (fun row -> uint32 row.Inputs.["namelen"] = namelen && row.Seen.["answer"] = "3")
                |> List.map (fun row -> int row.Inputs.["readable"])
                |> List.min

            let header =
                { SentMessage.header (single system rport (CopiedArgument.Readable (payload 3)) [ 3UL ]) with
                    MessageNameLength = namelen
                }

            let rec toName (progress : CallProgress<SendMsgCopy<int, string>, _>) : CopyRange =
                match progress with
                | CallProgress.NeedsCopyIn (SendMsgCopy.Name paused) -> PausedSendMsgName.copyRange paused
                | CallProgress.NeedsCopyIn (SendMsgCopy.Vectors paused) ->
                    UnixReadWrite.sendmsgWithVectors
                        (ImmutableArray.Create
                            {
                                VectorBase = UserBuffer.Mapped
                                VectorLength = 3UL
                            })
                        paused
                    |> toName
                | other -> failwith $"a sendmsg of a name %d{namelen} long: %A{other}"

            match UnixReadWrite.sendmsg leader s UserBuffer.Mapped 0 system with
            | CallProgress.NeedsCopyIn paused ->
                let range = UnixReadWrite.sendmsgWithHeader header paused |> toName

                range
                |> shouldEqual
                    {
                        FirstByte = 0
                        ByteCount = measured
                    }
            | other -> failwith $"sendmsg: %A{other}"
