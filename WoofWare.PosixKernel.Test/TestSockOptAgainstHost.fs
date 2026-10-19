namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Runtime.InteropServices
open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel

/// `setsockopt(2)` and `getsockopt(2)` of every option the model holds --
/// `SO_REUSEADDR`, `TCP_NODELAY`, `IPV6_V6ONLY`, `SO_LINGER` and Darwin's
/// `SO_LINGER_SEC` -- put to the kernel running the suite and to the model of
/// the same flavour, on the same random inputs.
///
/// Each host falsifies its own column live: macOS locally, Linux in CI. A Mac's
/// answers are recorded in `hostCorpus/setsockoptSequence.darwin.txt` and
/// `hostCorpus/getsockopt.darwin.txt`, which every host replays (see
/// `HostCorpus`), so CI holds the Darwin column too. The inputs
/// cover the descriptor kinds, value buffers and lengths the model
/// distinguishes -- a closed descriptor, a pipe, a fresh socket of every
/// domain and kind the flavour creates; real storage, a null pointer, and a
/// reserved `PROT_NONE` page; every length at the boundaries of `sizeof(int)`,
/// of `sizeof(struct linger)`, and of the signed and unsigned readings of a
/// `socklen_t`; and values at the edges of what each kernel stores. Only a
/// fresh socket's phases are reachable from here, which is why `TestSockOpt`
/// and `TestSocketOptions` carry the others as measured literals.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestSockOptAgainstHost =

    [<DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)>]
    extern int private hostSetSockOpt(int fd, int level, int optionName, nativeint value, uint32 optionLength)

    [<Literal>]
    let private PROT_NONE = 0

    let private mapPrivateAnonymous (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 0x02 ||| 0x20
        | SimulatedUnixFlavour.Darwin -> 0x02 ||| 0x1000

    /// A number no descriptor can have, so that it is closed on the host
    /// whatever the rest of the process holds. docs/probes/closed-descriptor
    /// measured that both flavours never allocate it, and that `setsockopt`
    /// and `getsockopt` answer it as they do a freed slot, on every option,
    /// buffer and length this fixture picks.
    [<Literal>]
    let private ClosedFd = Int32.MaxValue

    /// One reserved page nothing can be mapped over, whose address faults on
    /// every access. Never unmapped: it is a process-lifetime fixture.
    let private faultingPage : Lazy<uint64> =
        lazy
            match HostPlatform.flavour () with
            | None -> failwith "TestSockOptAgainstHost: no Unix host, so nothing to reserve"
            | Some flavour ->
                let page =
                    HostCalls.mmap (0n, 4096un, PROT_NONE, mapPrivateAnonymous flavour, -1, 0L)

                if page = -1n then
                    failwith $"TestSockOptAgainstHost: mmap failed with errno %d{Marshal.GetLastPInvokeError ()}"

                uint64 (int64 page)

    [<RequireQualifiedAccess>]
    type private Target =
        | Closed
        | Pipe
        | Socket of SocketDomain * SocketKind

    [<RequireQualifiedAccess>]
    type private Option =
        | ReuseAddress
        | NoDelay
        | Ipv6Only
        | Linger
        | LingerSeconds

    [<RequireQualifiedAccess>]
    type private Buffer =
        | Real
        | Null
        | Faulting

    let private numbered (platform : SimulatedUnixPlatform) (option : Option) : int * int =
        match option with
        | Option.ReuseAddress ->
            SimulatedUnixPlatform.socketOptionLevel platform, SimulatedUnixPlatform.reuseAddressOption platform
        | Option.NoDelay -> SimulatedUnixPlatform.tcpOptionLevel platform, SimulatedUnixPlatform.noDelayOption platform
        | Option.Ipv6Only ->
            SimulatedUnixPlatform.ipv6OptionLevel platform, SimulatedUnixPlatform.ipv6OnlyOption platform
        | Option.Linger -> SimulatedUnixPlatform.socketOptionLevel platform, SimulatedUnixPlatform.lingerOption platform
        | Option.LingerSeconds ->
            match SimulatedUnixPlatform.lingerSecondsOption platform with
            | Some name -> SimulatedUnixPlatform.socketOptionLevel platform, name
            | None -> failwith $"%O{platform} has no SO_LINGER_SEC"

    let private valueSize (option : Option) : int =
        match option with
        | Option.Linger
        | Option.LingerSeconds -> 8
        | Option.ReuseAddress
        | Option.NoDelay
        | Option.Ipv6Only -> 4

    let private options (platform : SimulatedUnixPlatform) : Option list =
        [
            yield Option.ReuseAddress
            yield Option.NoDelay
            yield Option.Ipv6Only
            yield Option.Linger
            if (SimulatedUnixPlatform.lingerSecondsOption platform).IsSome then
                yield Option.LingerSeconds
        ]

    let private targets (platform : SimulatedUnixPlatform) : Target list =
        [
            yield Target.Closed
            yield Target.Pipe
            for domain in [ SocketDomain.Inet ; SocketDomain.Inet6 ; SocketDomain.Unix ] do
                for kind in [ SocketKind.Stream ; SocketKind.Datagram ] do
                    yield Target.Socket (domain, kind)
            if SimulatedUnixPlatform.flavour platform = SimulatedUnixFlavour.Linux then
                yield Target.Socket (SocketDomain.Unix, SocketKind.SeqPacket)
        ]

    let private lengths : uint32 list =
        [
            0u
            1u
            2u
            3u
            4u
            5u
            7u
            8u
            9u
            16u
            0x7fff_ffffu
            0x8000_0000u
            0xffff_fffeu
            UInt32.MaxValue
        ]

    let private bufferGen : Gen<Buffer> =
        Gen.elements [ Buffer.Real ; Buffer.Null ; Buffer.Faulting ]

    let private lengthGen : Gen<uint32> =
        Gen.oneof [ Gen.elements lengths ; ArbMap.defaults |> ArbMap.generate<uint32> ]

    let private intGen : Gen<int> =
        Gen.oneof
            [
                Gen.elements
                    [
                        0
                        1
                        2
                        4
                        -1
                        0x100
                        5
                        327
                        328
                        32767
                        32768
                        65535
                        65536
                        21474836
                        21474837
                        42949673
                        Int32.MaxValue
                        Int32.MinValue
                    ]
                ArbMap.defaults |> ArbMap.generate<int>
            ]

    /// The bytes a caller's value buffer holds: two `int`s, of which an
    /// `int`-sized option reads the first.
    let private valueGen : Gen<byte[]> =
        Gen.map2
            (fun (a : int) (b : int) -> Array.append (BitConverter.GetBytes a) (BitConverter.GetBytes b))
            intGen
            intGen

    /// The address the model is given for a faulting buffer. The host's own is
    /// `faultingPage`, which differs between hosts; the model decides only by
    /// whether an address is below the user-address limit, as both are, so a
    /// recorded answer replays the same against either.
    [<Literal>]
    let private ModelFaultingAddress = 0x10000UL

    let private userBuffer (buffer : Buffer) : UserBuffer =
        match buffer with
        | Buffer.Real -> UserBuffer.Mapped
        | Buffer.Null -> UserBuffer.Unmapped 0UL
        | Buffer.Faulting -> UserBuffer.Unmapped ModelFaultingAddress

    let private fresh (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A host descriptor for `target`, for the duration of `action`.
    let private withHostTarget (platform : SimulatedUnixPlatform) (target : Target) (action : int -> 'a) : 'a =
        match target with
        | Target.Closed -> action ClosedFd
        | Target.Pipe ->
            let fds = Array.zeroCreate<int> 2

            if HostCalls.pipe fds <> 0 then
                failwith $"pipe failed with errno %d{Marshal.GetLastPInvokeError ()}"

            try
                action fds.[0]
            finally
                HostCalls.close fds.[0] |> ignore<int>
                HostCalls.close fds.[1] |> ignore<int>
        | Target.Socket (domain, kind) ->
            let rawDomain, rawKind, _ =
                NewSocket.arguments platform domain kind SocketProtocol.Default

            let fd = HostCalls.socket (rawDomain, rawKind, 0)

            if fd < 0 then
                failwith $"socket failed with errno %d{Marshal.GetLastPInvokeError ()}"

            try
                action fd
            finally
                HostCalls.close fd |> ignore<int>

    /// A model descriptor for `target` on a fresh system. The model's pipe is
    /// standard input, which it models as one.
    let private modelTarget (platform : SimulatedUnixPlatform) (target : Target) : int * UnixSystem<int, string> =
        let system = fresh platform

        match target with
        | Target.Closed -> ClosedFd, system
        | Target.Pipe -> 0, system
        | Target.Socket (domain, kind) -> NewSocket.create domain kind SocketProtocol.Default system

    /// Real storage holding `bytes`, or the host address `buffer` names, for
    /// the duration of `action`.
    let private withBuffer (buffer : Buffer) (bytes : byte[]) (action : nativeint -> 'a) : 'a =
        match buffer with
        | Buffer.Null -> action 0n
        | Buffer.Faulting -> action (nativeint (int64 faultingPage.Value))
        | Buffer.Real ->
            let storage = Marshal.AllocHGlobal bytes.Length

            try
                Marshal.Copy (bytes, 0, storage, bytes.Length)
                action storage
            finally
                Marshal.FreeHGlobal storage

    let private errnoOf (platform : SimulatedUnixPlatform) (error : UnixError) : int =
        UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) error

    let private hostSet (fd : int) (level : int) (name : int) (buffer : Buffer) (length : uint32) (value : byte[]) =
        withBuffer
            buffer
            value
            (fun address ->
                Marshal.SetLastPInvokeError 0

                if hostSetSockOpt (fd, level, name, address, length) = 0 then
                    0
                else
                    Marshal.GetLastPInvokeError ()
            )

    /// The model's set, as a client makes it: the admission, then the bytes the
    /// copy takes.
    let private modelSet
        (fd : int)
        (level : int)
        (name : int)
        (buffer : Buffer)
        (length : uint32)
        (value : byte[])
        (system : UnixSystem<int, string>)
        =
        let supplied =
            match Lone.UnixSocket.tryAdmitSetSockOpt fd level name (userBuffer buffer) length system with
            | Ok (SetSockOptAdmission.Transfer count) -> Some (ImmutableArray.Create (value, 0, count))
            | Ok SetSockOptAdmission.NoCopy
            | Ok (SetSockOptAdmission.Answered _)
            | Error _ -> None

        Lone.UnixSocket.trySetsockoptBytes fd level name (userBuffer buffer) length supplied system

    /// What a read through real buffers of the option's size answers, on the
    /// host: the errno, and the bytes and length on success.
    let private hostReadBack (fd : int) (level : int) (name : int) : int * byte[] =
        let storage = Marshal.AllocHGlobal 12

        try
            for i in 0..7 do
                Marshal.WriteByte (storage, i, 0x5auy)

            Marshal.WriteInt32 (storage, 8, 8)
            Marshal.SetLastPInvokeError 0

            if HostCalls.getSockOptPointer (fd, level, name, storage, storage + 8n) <> 0 then
                Marshal.GetLastPInvokeError (), [||]
            else
                let length = Marshal.ReadInt32 (storage, 8)
                let bytes = Array.zeroCreate<byte> length
                Marshal.Copy (storage, bytes, 0, length)
                0, bytes
        finally
            Marshal.FreeHGlobal storage

    let private modelReadBack (fd : int) (level : int) (name : int) (system : UnixSystem<int, string>) : int * byte[] =
        let platform = UnixSystem.platform system

        let read =
            match Lone.UnixSocket.tryAdmitGetSockOpt fd level name UserBuffer.Mapped UserBuffer.Mapped system with
            | Ok GetSockOptAdmission.ReadLength -> Some 8u
            | _ -> None

        match Lone.UnixSocket.tryGetsockoptLength fd level name UserBuffer.Mapped UserBuffer.Mapped read system with
        | Ok (GetSockOptAnswer.Reported copied, _) -> 0, Seq.toArray copied
        | Ok (GetSockOptAnswer.Failed (error, _), _) -> errnoOf platform error, [||]
        | Error refusal -> failwith $"reading the model back was refused: %s{SocketOptionRefusal.describe refusal}"

    let private onHost (test : SimulatedUnixPlatform -> unit) : unit =
        HostPlatform.onUnixHost (fun flavour ->
            if not BitConverter.IsLittleEndian then
                Assert.Ignore "the model's presets are little-endian machines"

            test (HostPlatform.platformOf flavour)
        )

    /// Whether the model's refusal is one it states for this input, rather than
    /// a disagreement: Linux's negative linger time, which this library will
    /// not answer.
    let private isStatedRefusal (refusal : SocketOptionRefusal) : bool =
        match refusal with
        | SocketOptionRefusal.NegativeLingerTime _ -> true
        | SocketOptionRefusal.UnmodelledOption _
        | SocketOptionRefusal.Buffer _
        | SocketOptionRefusal.LinuxReuseAddressInTimeWait _
        | SocketOptionRefusal.Ipv6OnlyOnGivenBackPort _ -> false

    // ------------------------------------------------------------ the corpus text

    let private writeTarget (target : Target) : string =
        let domain (domain : SocketDomain) : string =
            match domain with
            | SocketDomain.Inet -> "inet"
            | SocketDomain.Inet6 -> "inet6"
            | SocketDomain.Unix -> "unix"

        let kind (kind : SocketKind) : string =
            match kind with
            | SocketKind.Stream -> "stream"
            | SocketKind.Datagram -> "dgram"
            | SocketKind.SeqPacket -> "seqpacket"

        match target with
        | Target.Closed -> "closed"
        | Target.Pipe -> "pipe"
        | Target.Socket (d, k) -> $"%s{domain d}/%s{kind k}"

    let private parseTarget (text : string) : Target =
        let domain (text : string) : SocketDomain =
            match text with
            | "inet" -> SocketDomain.Inet
            | "inet6" -> SocketDomain.Inet6
            | "unix" -> SocketDomain.Unix
            | other -> failwith $"not a socket domain: %s{other}"

        let kind (text : string) : SocketKind =
            match text with
            | "stream" -> SocketKind.Stream
            | "dgram" -> SocketKind.Datagram
            | "seqpacket" -> SocketKind.SeqPacket
            | other -> failwith $"not a socket kind: %s{other}"

        match text.Split '/' with
        | [| "closed" |] -> Target.Closed
        | [| "pipe" |] -> Target.Pipe
        | [| d ; k |] -> Target.Socket (domain d, kind k)
        | _ -> failwith $"not a target: %s{text}"

    let private writeOption (option : Option) : string =
        match option with
        | Option.ReuseAddress -> "reuseaddr"
        | Option.NoDelay -> "nodelay"
        | Option.Ipv6Only -> "v6only"
        | Option.Linger -> "linger"
        | Option.LingerSeconds -> "lingersec"

    let private parseOption (text : string) : Option =
        match text with
        | "reuseaddr" -> Option.ReuseAddress
        | "nodelay" -> Option.NoDelay
        | "v6only" -> Option.Ipv6Only
        | "linger" -> Option.Linger
        | "lingersec" -> Option.LingerSeconds
        | other -> failwith $"not an option: %s{other}"

    let private writeBuffer (buffer : Buffer) : string =
        match buffer with
        | Buffer.Real -> "real"
        | Buffer.Null -> "null"
        | Buffer.Faulting -> "fault"

    let private parseBuffer (text : string) : Buffer =
        match text with
        | "real" -> Buffer.Real
        | "null" -> Buffer.Null
        | "fault" -> Buffer.Faulting
        | other -> failwith $"not a buffer: %s{other}"

    /// Bytes as lowercase hex, `-` for none.
    let private writeBytes (bytes : byte[]) : string =
        if bytes.Length = 0 then
            "-"
        else
            Convert.ToHexString(bytes).ToLowerInvariant ()

    let private parseBytes (text : string) : byte[] =
        if text = "-" then [||] else Convert.FromHexString text

    let private writeOptional (write : 'a -> string) (value : 'a option) : string =
        match value with
        | None -> "~"
        | Some value -> write value

    let private parseOptional (parse : string -> 'a) (text : string) : 'a option =
        if text = "~" then None else Some (parse text)

    // ------------------------------------------------------------ setsockopt sequences

    /// One `setsockopt` call of a sequence: the value buffer, the declared
    /// length, and the bytes the buffer holds.
    type private SetStep =
        {
            Buffer : Buffer
            Length : uint32
            Value : byte[]
        }

    type private SetSequence =
        {
            Target : Target
            Option : Option
            Steps : SetStep list
        }

    /// What the kernel answered to one step: the set's errno, then a read back
    /// through real buffers: its errno, and the bytes it reported.
    type private SetAnswer =
        {
            SetErrno : int
            ReadErrno : int
            Read : byte[]
        }

    let private setSequences : HostComparison<SetSequence, SetAnswer list> =
        {
            Name = "setsockoptSequence"
            Inputs =
                fun platform ->
                    let step =
                        Gen.map3
                            (fun buffer length value ->
                                {
                                    Buffer = buffer
                                    Length = length
                                    Value = value
                                }
                            )
                            bufferGen
                            lengthGen
                            valueGen

                    Gen.map3
                        (fun target option steps ->
                            {
                                Target = target
                                Option = option
                                Steps = steps
                            }
                        )
                        (Gen.elements (targets platform))
                        (Gen.elements (options platform))
                        (Gen.listOf step |> Gen.resize 4)
            Count = 2000
            WriteInput =
                fun sequence ->
                    [
                        yield writeTarget sequence.Target
                        yield writeOption sequence.Option
                        for step in sequence.Steps do
                            yield $"%s{writeBuffer step.Buffer},%d{step.Length},%s{writeBytes step.Value}"
                    ]
                    |> String.concat " "
            ParseInput =
                fun text ->
                    match text.Split ' ' |> Array.toList with
                    | target :: option :: steps ->
                        {
                            Target = parseTarget target
                            Option = parseOption option
                            Steps =
                                steps
                                |> List.map (fun step ->
                                    match step.Split ',' with
                                    | [| buffer ; length ; value |] ->
                                        {
                                            Buffer = parseBuffer buffer
                                            Length = UInt32.Parse length
                                            Value = parseBytes value
                                        }
                                    | _ -> failwith $"not a setsockopt step: %s{step}"
                                )
                        }
                    | _ -> failwith $"not a setsockopt sequence: %s{text}"
            WriteAnswer =
                fun answers ->
                    answers
                    |> List.map (fun answer -> $"%d{answer.SetErrno},%d{answer.ReadErrno},%s{writeBytes answer.Read}")
                    |> String.concat " "
            ParseAnswer =
                fun text ->
                    if text = "" then
                        []
                    else
                        text.Split ' '
                        |> Array.toList
                        |> List.map (fun answer ->
                            match answer.Split ',' with
                            | [| set ; read ; bytes |] ->
                                {
                                    SetErrno = int set
                                    ReadErrno = int read
                                    Read = parseBytes bytes
                                }
                            | _ -> failwith $"not a setsockopt answer: %s{answer}"
                        )
            Host =
                fun platform sequence ->
                    let level, name = numbered platform sequence.Option

                    withHostTarget
                        platform
                        sequence.Target
                        (fun fd ->
                            sequence.Steps
                            |> List.map (fun step ->
                                let setErrno = hostSet fd level name step.Buffer step.Length step.Value
                                let readErrno, read = hostReadBack fd level name

                                {
                                    SetErrno = setErrno
                                    ReadErrno = readErrno
                                    Read = read
                                }
                            )
                        )
            Disagreement =
                fun platform sequence answers ->
                    let level, name = numbered platform sequence.Option
                    let modelFd, system = modelTarget platform sequence.Target

                    let rec go
                        (index : int)
                        (pairs : (SetStep * SetAnswer) list)
                        (system : UnixSystem<int, string>)
                        : string option
                        =
                        match pairs with
                        | [] -> None
                        | (step, answer) :: rest ->

                        let describe =
                            $"%A{sequence.Target} %A{sequence.Option}, step %d{index} of %A{sequence.Steps}: %A{step.Buffer} length %d{step.Length} value %A{step.Value}"

                        match modelSet modelFd level name step.Buffer step.Length step.Value system with
                        | Error refusal when isStatedRefusal refusal -> None
                        | Error refusal ->
                            Some
                                $"%s{describe}: the model refused (%s{SocketOptionRefusal.describe refusal}) where this kernel answered errno %d{answer.SetErrno}"
                        | Ok (set, system) ->

                        let modelErrno =
                            match set with
                            | SetSockOptAnswer.Set -> 0
                            | SetSockOptAnswer.Failed error -> errnoOf platform error

                        if modelErrno <> answer.SetErrno then
                            Some $"%s{describe}: the model answered %d{modelErrno}, this kernel %d{answer.SetErrno}"
                        else

                        let modelRead = modelReadBack modelFd level name system
                        let hostRead = answer.ReadErrno, answer.Read

                        if modelRead <> hostRead then
                            Some $"%s{describe}: the model reads back %A{modelRead}, this kernel %A{hostRead}"
                        else
                            go (index + 1) rest system

                    if answers.Length <> sequence.Steps.Length then
                        Some $"%d{sequence.Steps.Length} steps, but %d{answers.Length} answers"
                    else
                        go 0 (List.zip sequence.Steps answers) system
        }

    [<Test>]
    let ``a sequence of setsockopt calls answers and reads back as this kernel does`` () : unit =
        onHost (HostCorpus.live setSequences)

    [<Test>]
    let ``a sequence of setsockopt calls answers and reads back as Darwin's kernel did`` () : unit =
        HostCorpus.replay setSequences SimulatedUnixPlatform.macOsArm64

    // ------------------------------------------------------------ getsockopt

    /// One `getsockopt` call: where its value and length go, the length it
    /// declares, and the value, if any, set through real storage beforehand,
    /// so that the read has something other than the default to report.
    type private GetCall =
        {
            Target : Target
            Option : Option
            ValueBuffer : Buffer
            LengthBuffer : Buffer
            DeclaredLength : uint32
            Prior : byte[] option
        }

    /// What the kernel answered: the prior set's errno, if there was one; the
    /// read's errno; and, where each buffer was real storage, the sixteen bytes
    /// the value buffer then held and the length it reported.
    type private GetAnswer =
        {
            PriorErrno : int option
            Errno : int
            Value : byte[] option
            Length : uint32 option
        }

    /// What a value buffer holds before the call.
    [<Literal>]
    let private Sentinel = 0x5auy

    let private getCalls : HostComparison<GetCall, GetAnswer> =
        {
            Name = "getsockopt"
            Inputs =
                fun platform ->
                    Gen.zip
                        (Gen.zip (Gen.elements (targets platform)) (Gen.elements (options platform)))
                        (Gen.zip (Gen.zip bufferGen bufferGen) (Gen.zip lengthGen (Gen.optionOf valueGen)))
                    |> Gen.map (fun ((target, option), ((valueBuffer, lengthBuffer), (declaredLength, prior))) ->
                        {
                            Target = target
                            Option = option
                            ValueBuffer = valueBuffer
                            LengthBuffer = lengthBuffer
                            DeclaredLength = declaredLength
                            Prior = prior
                        }
                    )
            Count = 2000
            WriteInput =
                fun call ->
                    [
                        writeTarget call.Target
                        writeOption call.Option
                        writeBuffer call.ValueBuffer
                        writeBuffer call.LengthBuffer
                        string<uint32> call.DeclaredLength
                        writeOptional writeBytes call.Prior
                    ]
                    |> String.concat " "
            ParseInput =
                fun text ->
                    match text.Split ' ' with
                    | [| target ; option ; valueBuffer ; lengthBuffer ; declaredLength ; prior |] ->
                        {
                            Target = parseTarget target
                            Option = parseOption option
                            ValueBuffer = parseBuffer valueBuffer
                            LengthBuffer = parseBuffer lengthBuffer
                            DeclaredLength = UInt32.Parse declaredLength
                            Prior = parseOptional parseBytes prior
                        }
                    | _ -> failwith $"not a getsockopt call: %s{text}"
            WriteAnswer =
                fun answer ->
                    [
                        writeOptional string<int> answer.PriorErrno
                        string<int> answer.Errno
                        writeOptional writeBytes answer.Value
                        writeOptional string<uint32> answer.Length
                    ]
                    |> String.concat " "
            ParseAnswer =
                fun text ->
                    match text.Split ' ' with
                    | [| priorErrno ; errno ; value ; length |] ->
                        {
                            PriorErrno = parseOptional int priorErrno
                            Errno = int errno
                            Value = parseOptional parseBytes value
                            Length = parseOptional UInt32.Parse length
                        }
                    | _ -> failwith $"not a getsockopt answer: %s{text}"
            Host =
                fun platform call ->
                    let level, name = numbered platform call.Option

                    withHostTarget
                        platform
                        call.Target
                        (fun fd ->
                            let priorErrno =
                                call.Prior
                                |> Option.map (fun value ->
                                    hostSet fd level name Buffer.Real (uint32 (valueSize call.Option)) value
                                )

                            withBuffer
                                call.ValueBuffer
                                (Array.create 16 Sentinel)
                                (fun valueAddress ->
                                    withBuffer
                                        call.LengthBuffer
                                        (BitConverter.GetBytes call.DeclaredLength)
                                        (fun lengthAddress ->
                                            Marshal.SetLastPInvokeError 0

                                            let errno =
                                                if
                                                    HostCalls.getSockOptPointer (
                                                        fd,
                                                        level,
                                                        name,
                                                        valueAddress,
                                                        lengthAddress
                                                    ) = 0
                                                then
                                                    0
                                                else
                                                    Marshal.GetLastPInvokeError ()

                                            let value =
                                                match call.ValueBuffer with
                                                | Buffer.Real ->
                                                    let bytes = Array.zeroCreate<byte> 16
                                                    Marshal.Copy (valueAddress, bytes, 0, 16)
                                                    Some bytes
                                                | Buffer.Null
                                                | Buffer.Faulting -> None

                                            let length =
                                                match call.LengthBuffer with
                                                | Buffer.Real -> Some (uint32 (Marshal.ReadInt32 lengthAddress))
                                                | Buffer.Null
                                                | Buffer.Faulting -> None

                                            {
                                                PriorErrno = priorErrno
                                                Errno = errno
                                                Value = value
                                                Length = length
                                            }
                                        )
                                )
                        )
            Disagreement =
                fun platform call answer ->
                    let level, name = numbered platform call.Option
                    let modelFd, system = modelTarget platform call.Target

                    let describe =
                        $"%A{call.Target} %A{call.Option} prior %A{call.Prior} value %A{call.ValueBuffer} length %A{call.LengthBuffer} = %d{call.DeclaredLength}"

                    // The model judges the read only where it, too, took the
                    // prior value; where it took it and the kernel did not, the
                    // two already disagree.
                    let prior : Result<UnixSystem<int, string> option, string> =
                        match call.Prior with
                        | None -> Ok (Some system)
                        | Some value ->
                            let size = uint32 (valueSize call.Option)

                            match modelSet modelFd level name Buffer.Real size value system with
                            | Ok (SetSockOptAnswer.Set, system) ->
                                if answer.PriorErrno <> Some 0 then
                                    Error
                                        $"%s{describe}: the model took the prior value, this kernel answered %A{answer.PriorErrno}"
                                else
                                    Ok (Some system)
                            | Ok (SetSockOptAnswer.Failed _, _)
                            | Error _ -> Ok None

                    match prior with
                    | Error disagreement -> Some disagreement
                    | Ok None -> None
                    | Ok (Some system) ->

                    let modelLength = userBuffer call.LengthBuffer

                    let read =
                        match
                            Lone.UnixSocket.tryAdmitGetSockOpt
                                modelFd
                                level
                                name
                                (userBuffer call.ValueBuffer)
                                modelLength
                                system
                        with
                        | Ok GetSockOptAdmission.ReadLength -> Some call.DeclaredLength
                        | _ -> None

                    let untouched (buffer : Buffer) (contents : 'a) : 'a option =
                        match buffer with
                        | Buffer.Real -> Some contents
                        | Buffer.Null
                        | Buffer.Faulting -> None

                    let model =
                        match
                            Lone.UnixSocket.tryGetsockoptLength
                                modelFd
                                level
                                name
                                (userBuffer call.ValueBuffer)
                                modelLength
                                read
                                system
                        with
                        | Error refusal ->
                            Error
                                $"%s{describe}: the model refused (%s{SocketOptionRefusal.describe refusal}) where this kernel answered errno %d{answer.Errno}"
                        | Ok (GetSockOptAnswer.Failed (error, overwritten), _) ->
                            Ok (
                                errnoOf platform error,
                                untouched call.ValueBuffer (Array.create 16 Sentinel),
                                untouched call.LengthBuffer (Option.defaultValue call.DeclaredLength overwritten)
                            )
                        | Ok (GetSockOptAnswer.Reported copied, _) ->
                            let bytes = Array.create 16 Sentinel
                            copied.CopyTo bytes
                            Ok (0, untouched call.ValueBuffer bytes, untouched call.LengthBuffer (uint32 copied.Length))

                    let host = answer.Errno, answer.Value, answer.Length

                    match model with
                    | Error disagreement -> Some disagreement
                    | Ok model when model <> host ->
                        Some $"%s{describe}: the model predicts %A{model}, this kernel did %A{host}"
                    | Ok _ -> None
        }

    [<Test>]
    let ``getsockopt answers as this kernel does`` () : unit = onHost (HostCorpus.live getCalls)

    [<Test>]
    let ``getsockopt answers as Darwin's kernel did`` () : unit =
        HostCorpus.replay getCalls SimulatedUnixPlatform.macOsArm64

    [<Test>]
    let ``every generated call reads back as itself`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            HostCorpus.inputsRoundTrip setSequences platform
            HostCorpus.inputsRoundTrip getCalls platform
