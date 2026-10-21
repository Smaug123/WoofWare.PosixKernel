namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Runtime.InteropServices
open System.Threading
open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel

/// Random sequences of UDP sends and receives between connected senders and
/// unconnected receivers on loopback, made on the host the suite runs on and
/// in the kernel, which must answer each call as the host did. Linux's column
/// is checked live on CI, and Darwin's live on a Mac and, on every host, from
/// the answers a Mac recorded.
///
/// Two receivers are bound to 127.0.0.1 and left unconnected, the first
/// through a blocking description (so that Linux's poll of it refills its
/// reader queue) and the second through a non-blocking one; three senders
/// are bound and each connected to a receiver. Every datagram so has exactly
/// one socket to reach, which keeps the calls clear of ties, which the kernel
/// refuses, and of the ICMP error, which `TestDatagramErrorAgainstHost`
/// compares.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramTransferAgainstHost =

    [<RequireQualifiedAccess>]
    type private Op =
        /// Sender `sender` (0 to 2) sends `length` bytes, by `write(2)` if
        /// `viaWrite` and by `send(2)` otherwise, from a buffer mapped or not.
        | Send of sender : int * length : int * viaWrite : bool * mapped : bool
        /// Sender `sender` sends `count` datagrams of `length` bytes.
        | Flood of sender : int * length : int * count : int
        /// Unconnected receiver `receiver` (0 or 1) sends, which answers
        /// `EDESTADDRREQ`.
        | SendUnconnected of receiver : int * length : int * viaWrite : bool
        /// A receive of `count` bytes on socket `socket` (0 to 4): by `read(2)`
        /// if `viaRead`, and otherwise by `recv(2)` with `MSG_DONTWAIT`, and
        /// `MSG_PEEK` if `peek`; into a buffer mapped or not.
        | Receive of socket : int * count : int * peek : bool * viaRead : bool * mapped : bool
        | Fionread of socket : int
        /// Linux `poll(2)` of every event.
        | Poll of socket : int

    /// One call's answer: the return value and errno, and a digest of the
    /// bytes a receive gave into a mapped buffer (`received`).
    type private Seen =
        {
            Returned : int64
            Errno : int
            Received : string
        }

    /// `bytes` as their length and the start of their SHA-256, or `-` for
    /// none: a datagram can be 9216 bytes, too many to record whole.
    let private received (bytes : byte[]) : string =
        if bytes.Length = 0 then
            "-"
        else
            let hash = System.Security.Cryptography.SHA256.HashData bytes
            $"%d{bytes.Length}~%s{Convert.ToHexString(hash, 0, 12).ToLowerInvariant ()}"

    /// Socket 2, 3 and 4's receivers.
    let private targets : int list = [ 0 ; 1 ; 0 ]

    let private payload (salt : int) (length : int) : byte[] =
        Array.init length (fun i -> byte (i * 7 + salt * 13))

    let private dontWait (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 0x40
        | SimulatedUnixFlavour.Darwin -> 0x80

    [<Literal>]
    let private MSG_PEEK = 0x2

    // ------------------------------------------------------------ the host

    let private check (what : string) (result : int) : unit =
        if result < 0 then
            failwith $"%s{what} failed with errno %d{Marshal.GetLastPInvokeError ()}"

    let private hostName (fd : int) : byte[] * uint32 =
        let name = Array.zeroCreate<byte> 16
        let mutable length = 16u
        check "getsockname" (HostCalls.getSockName (fd, name, &length))
        name, length

    /// Five sockets, as the fixture describes them.
    let private hostSockets (platform : SimulatedUnixPlatform) : int list =
        let address =
            SimulatedUnixPlatform.encodeInternetSockaddr platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us)

        let socket () =
            // AF_INET is 2, and SOCK_DGRAM 2, on both.
            let fd = HostCalls.socket (SimulatedUnixPlatform.internetAddressFamily, 2, 0)

            check "socket" fd
            check "bind" (HostCalls.bind (fd, address, uint32 address.Length))
            fd

        let sockets = List.init 5 (fun _ -> socket ())

        for sender, receiver in List.zip [ 2 ; 3 ; 4 ] targets do
            let name, length = hostName sockets.[receiver]
            check "connect" (HostCalls.connect (sockets.[sender], name, length))

        for fd in sockets.Tail do
            if HostCalls.setNonBlocking (nativeint fd, 1) <> 0 then
                failwith $"could not make fd %d{fd} non-blocking"

        sockets

    let private call (f : unit -> nativeint) : int64 * int =
        Marshal.SetLastPInvokeError 0
        let result = int64 (f ())
        result, (if result < 0L then Marshal.GetLastPInvokeError () else 0)

    /// A fingerprint of what `fd`'s receive buffer holds that moves with every
    /// datagram it takes or drops: Linux's charge and drop count, read through
    /// `SO_MEMINFO`; Darwin's `FIONREAD`, which counts every datagram's
    /// bytes and address.
    let private hostFingerprint (flavour : SimulatedUnixFlavour) (fd : int) : int64 =
        match flavour with
        | SimulatedUnixFlavour.Linux ->
            let memory = Array.zeroCreate<byte> 36
            let mutable length = 36u
            check "SO_MEMINFO" (HostCalls.getSockOptBytes (fd, 1, 55, memory, &length))

            int64 (BitConverter.ToUInt32 (memory, 0))
            ||| (int64 (BitConverter.ToUInt32 (memory, 32)) <<< 32)
        | SimulatedUnixFlavour.Darwin ->
            let mutable available = 0
            check "FIONREAD" (HostCalls.bytesAvailable (nativeint fd, &available))
            int64 available

    /// Send by `send`, then wait for the datagram to reach `receiver`'s
    /// buffer or be dropped there: Darwin's loopback delivers on another
    /// thread, and Linux's under a burst. On Linux the drop count says when a
    /// datagram is dropped; on Darwin a datagram that has not arrived in 30
    /// ms has been.
    let private hostSendAndSettle
        (flavour : SimulatedUnixFlavour)
        (receiver : int)
        (send : unit -> nativeint)
        : int64 * int
        =
        let before = hostFingerprint flavour receiver
        let answer = call send

        if fst answer >= 0L then
            let deadline = DateTime.UtcNow.AddMilliseconds 30.0

            while hostFingerprint flavour receiver = before && DateTime.UtcNow < deadline do
                Thread.Sleep 1

        answer

    let private hostApply (flavour : SimulatedUnixFlavour) (sockets : int list) (salt : int) (op : Op) : Seen list =
        let answered (returned : int64, errno : int) =
            {
                Returned = returned
                Errno = errno
                Received = "-"
            }

        match op with
        | Op.Send (sender, length, viaWrite, mapped) ->
            let fd = sockets.[sender + 2]
            let receiver = sockets.[targets.[sender]]
            let bytes = payload salt length

            let send () =
                match viaWrite, mapped with
                | true, true -> HostCalls.write (fd, bytes, unativeint length)
                | true, false -> HostCalls.writePointer (fd, 1n, unativeint length)
                | false, true -> HostCalls.send (fd, bytes, unativeint length, 0)
                | false, false -> HostCalls.sendPointer (fd, 1n, unativeint length, 0)

            [ answered (hostSendAndSettle flavour receiver send) ]
        | Op.Flood (sender, length, count) ->
            let fd = sockets.[sender + 2]
            let receiver = sockets.[targets.[sender]]
            let bytes = payload salt length

            List.init
                count
                (fun _ ->
                    answered (
                        hostSendAndSettle flavour receiver (fun () -> HostCalls.send (fd, bytes, unativeint length, 0))
                    )
                )
        | Op.SendUnconnected (receiver, length, viaWrite) ->
            let fd = sockets.[receiver]
            let bytes = payload salt length

            [
                answered (
                    call (fun () ->
                        if viaWrite then
                            HostCalls.write (fd, bytes, unativeint length)
                        else
                            HostCalls.send (fd, bytes, unativeint length, 0)
                    )
                )
            ]
        | Op.Receive (socket, count, peek, viaRead, mapped) ->
            let fd = sockets.[socket]
            let buffer = Array.zeroCreate<byte> (max count 1)
            let flags = dontWait flavour ||| (if peek then MSG_PEEK else 0)

            let returned, errno =
                call (fun () ->
                    match viaRead, mapped with
                    | true, true -> HostCalls.read (fd, buffer, unativeint count)
                    | true, false -> HostCalls.readPointer (fd, 1n, unativeint count)
                    | false, true -> HostCalls.recv (fd, buffer, unativeint count, flags)
                    | false, false -> HostCalls.recvPointer (fd, 1n, unativeint count, flags)
                )

            [
                {
                    Returned = returned
                    Errno = errno
                    Received =
                        if returned > 0L && mapped then
                            received buffer.[0 .. int returned - 1]
                        else
                            "-"
                }
            ]
        | Op.Fionread socket ->
            let mutable available = 0

            let returned, errno =
                call (fun () -> nativeint (HostCalls.bytesAvailable (nativeint sockets.[socket], &available)))

            [ answered ((if returned < 0L then returned else int64 available), errno) ]
        | Op.Poll socket ->
            // IN PRI OUT RDNORM RDBAND WRNORM WRBAND RDHUP
            let entry = [| int64 (uint32 sockets.[socket]) ||| (0x23c7L <<< 32) |]
            check "poll" (HostCalls.pollPacked (entry, 1un, 0))
            [ answered (int64 (uint16 (entry.[0] >>> 48)), 0) ]

    // ------------------------------------------------------------ the kernel

    /// The receive buffer a fresh UDP socket on this host starts with, which
    /// the host's administrator configures: `getsockopt(SO_RCVBUF)`.
    let private hostReceiveBuffer (flavour : SimulatedUnixFlavour) (fd : int) : int =
        // SOL_SOCKET and SO_RCVBUF: 1 and 8 on Linux, 0xffff and 0x1002 on Darwin.
        let level, option =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 1, 8
            | SimulatedUnixFlavour.Darwin -> 0xffff, 0x1002

        let mutable value = 0
        let mutable length = 4u
        check "SO_RCVBUF" (HostCalls.getSockOptInt (fd, level, option, &value, &length))
        value

    /// Five sockets, as the fixture describes them, on a machine whose UDP
    /// receive buffer is `receiveBuffer`.
    let private kernelSockets
        (platform : SimulatedUnixPlatform)
        (receiveBuffer : int)
        : int list * UnixSystem<int, string>
        =
        let mutable system =
            UnixSystem.initial<int, string> platform
            |> UnixBootImage.withUdpReceiveSpace (Some receiveBuffer)
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let address = CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us)

        let sockets =
            List.init
                5
                (fun _ ->
                    let fd, after =
                        NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

                    system <-
                        match CopyIn.bind fd UserBuffer.Mapped 16u address after with
                        | Ok (BindAnswer.Bound _, after) -> after
                        | other -> failwith $"bind: %A{other}"

                    fd
                )

        let portOf (fd : int) : uint16 =
            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
                | Some binding -> binding.Endpoint.Port
                | None -> failwith "a bound socket has no binding"
            | other -> failwith $"%A{other}"

        for sender, receiver in List.zip [ 2 ; 3 ; 4 ] targets do
            let destination =
                CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback (portOf sockets.[receiver]))

            system <-
                match CopyIn.connect sockets.[sender] UserBuffer.Mapped 16u destination system with
                | Ok (SyscallAnswer.Completed 0L, after) -> after
                | other -> failwith $"connect: %A{other}"

        for fd in sockets.Tail do
            system <- UnixDescriptor.setNonBlocking (Callers.leader system) fd true system |> snd

        sockets, system

    let private kernelApply
        (platform : SimulatedUnixPlatform)
        (sockets : int list)
        (salt : int)
        (op : Op)
        (system : UnixSystem<int, string>)
        : Seen list * UnixSystem<int, string>
        =
        let errno (error : UnixError) : int =
            UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) error

        let ofWrite (answer : WriteAnswer) : Seen =
            match answer with
            | WriteAnswer.Completed written ->
                {
                    Returned = written
                    Errno = 0
                    Received = "-"
                }
            | WriteAnswer.Failed error ->
                {
                    Returned = -1L
                    Errno = errno error
                    Received = "-"
                }

        let ofRead (mapped : bool) (answer : ReadAnswer) : Seen =
            match answer with
            | ReadAnswer.Completed bytes ->
                {
                    Returned = int64 bytes.Length
                    Errno = 0
                    Received = if mapped then received (Seq.toArray bytes) else "-"
                }
            | ReadAnswer.Failed error ->
                {
                    Returned = -1L
                    Errno = errno error
                    Received = "-"
                }
            | ReadAnswer.Drawn _ -> failwith "a socket draws no entropy"

        let sendOne (fd : int) (length : int) (viaWrite : bool) (mapped : bool) (system : UnixSystem<int, string>) =
            let bytes = ImmutableArray.Create<byte> (payload salt length)

            let buffer =
                if mapped then
                    UserBuffer.Mapped
                else
                    UserBuffer.Unmapped 1UL

            if viaWrite then
                match WriteOutcomes.admitThenWrite 0 fd buffer bytes system with
                | Ok (WriteStep.Returns (answer, system)) -> ofWrite answer, system
                | other -> failwith $"write: %A{other}"
            else
                match WriteOutcomes.admitThenSend 0 fd buffer bytes 0 system with
                | Ok (WriteStep.Returns (answer, system)) -> ofWrite answer, system
                | other -> failwith $"send: %A{other}"

        match op with
        | Op.Send (sender, length, viaWrite, mapped) ->
            let seen, system = sendOne sockets.[sender + 2] length viaWrite mapped system
            [ seen ], system
        | Op.Flood (sender, length, count) ->
            List.mapFold (fun system _ -> sendOne sockets.[sender + 2] length false true system) system [ 1..count ]
        | Op.SendUnconnected (receiver, length, viaWrite) ->
            let seen, system = sendOne sockets.[receiver] length viaWrite true system
            [ seen ], system
        | Op.Receive (socket, count, peek, viaRead, mapped) ->
            let fd = sockets.[socket]

            let buffer =
                if mapped then
                    UserBuffer.Mapped
                else
                    UserBuffer.Unmapped 1UL

            if viaRead then
                match ReadOutcomes.read fd buffer (uint64 count) system with
                | Ok (answer, system) -> [ ofRead mapped answer ], system
                | other -> failwith $"read: %A{other}"
            else
                let flags =
                    dontWait (SimulatedUnixPlatform.flavour platform)
                    ||| (if peek then MSG_PEEK else 0)

                match UnixReadWrite.tryRecv (Callers.leader system) fd buffer (uint64 count) flags system with
                | Ok (ReadOutcome.Answered answer, system) -> [ ofRead mapped answer ], system
                | other -> failwith $"recv: %A{other}"
        | Op.Fionread socket ->
            match
                UnixDescriptor.tryBytesAvailable (Callers.leader system) sockets.[socket] UserBuffer.Mapped system
            with
            | Ok (BytesAvailableAnswer.Reported count, system) ->
                [
                    {
                        Returned = int64 count
                        Errno = 0
                        Received = "-"
                    }
                ],
                system
            | other -> failwith $"FIONREAD: %A{other}"
        | Op.Poll socket ->
            let entry : PollEntry =
                {
                    Fd = sockets.[socket]
                    Events = 0x23c7s
                }

            match UnixPoll.tryPoll (Callers.leader system) [ entry ] 0 system with
            | Ok (PollOutcome.Answered ([ revents ], _), system) ->
                [
                    {
                        Returned = int64 (uint16 revents)
                        Errno = 0
                        Received = "-"
                    }
                ],
                system
            | other -> failwith $"poll: %A{other}"

    // ------------------------------------------------------------ the property

    let private opGen (flavour : SimulatedUnixFlavour) : Gen<Op> =
        let largest =
            match flavour with
            | SimulatedUnixFlavour.Linux -> 65507
            | SimulatedUnixFlavour.Darwin -> 9216

        let length =
            Gen.frequency
                [
                    5, Gen.choose (0, 300)
                    2, Gen.choose (0, 3000)
                    1, Gen.elements [ 0 ; 197 ; 198 ; 256 ; 257 ; 288 ; 289 ; 2048 ; 4096 ; largest ; largest + 1 ]
                ]

        let bool = Gen.elements [ false ; true ]

        let receive =
            gen {
                let! socket = Gen.choose (0, 4)
                let! count = Gen.frequency [ 1, Gen.constant 0 ; 4, Gen.choose (1, 400) ; 1, Gen.constant 70000 ]
                let! peek = bool
                // `read(2)` only through a non-blocking description.
                let! viaRead = if socket = 0 then Gen.constant false else bool
                // Darwin's receive into an unmapped buffer is refused; a peek
                // is not.
                let! mapped =
                    match flavour, peek && not viaRead with
                    | SimulatedUnixFlavour.Darwin, false -> Gen.constant true
                    | _ -> Gen.frequency [ 5, Gen.constant true ; 1, Gen.constant false ]

                return Op.Receive (socket, count, peek && not viaRead, viaRead, mapped)
            }

        Gen.frequency
            [
                yield
                    8,
                    Gen.map4
                        (fun sender length viaWrite mapped -> Op.Send (sender, length, viaWrite, mapped))
                        (Gen.choose (0, 2))
                        length
                        bool
                        (Gen.frequency [ 6, Gen.constant true ; 1, Gen.constant false ])
                yield
                    1,
                    Gen.map3
                        (fun sender length count -> Op.Flood (sender, length, count))
                        (Gen.choose (0, 2))
                        (Gen.elements [ 1 ; 100 ; 1000 ; 4096 ; largest ])
                        (Gen.choose (1, 120))
                yield
                    1,
                    Gen.map3
                        (fun receiver length viaWrite -> Op.SendUnconnected (receiver, length, viaWrite))
                        (Gen.choose (0, 1))
                        length
                        bool
                yield 8, receive
                yield 2, Gen.map Op.Fionread (Gen.choose (0, 4))
                if flavour = SimulatedUnixFlavour.Linux then
                    yield 2, Gen.map Op.Poll (Gen.choose (0, 4))
            ]

    // ------------------------------------------------------------ the corpus

    let private bit (value : bool) : string = if value then "1" else "0"

    let private writeOp (op : Op) : string =
        match op with
        | Op.Send (sender, length, viaWrite, mapped) -> $"s:%d{sender}:%d{length}:%s{bit viaWrite}:%s{bit mapped}"
        | Op.Flood (sender, length, count) -> $"f:%d{sender}:%d{length}:%d{count}"
        | Op.SendUnconnected (receiver, length, viaWrite) -> $"u:%d{receiver}:%d{length}:%s{bit viaWrite}"
        | Op.Receive (socket, count, peek, viaRead, mapped) ->
            $"r:%d{socket}:%d{count}:%s{bit peek}:%s{bit viaRead}:%s{bit mapped}"
        | Op.Fionread socket -> $"i:%d{socket}"
        | Op.Poll socket -> $"p:%d{socket}"

    let private parseOp (text : string) : Op =
        let flag (field : string) : bool =
            match field with
            | "0" -> false
            | "1" -> true
            | _ -> failwith $"not a flag in a UDP op: %s{text}"

        match text.Split ':' with
        | [| "s" ; sender ; length ; viaWrite ; mapped |] ->
            Op.Send (int sender, int length, flag viaWrite, flag mapped)
        | [| "f" ; sender ; length ; count |] -> Op.Flood (int sender, int length, int count)
        | [| "u" ; receiver ; length ; viaWrite |] -> Op.SendUnconnected (int receiver, int length, flag viaWrite)
        | [| "r" ; socket ; count ; peek ; viaRead ; mapped |] ->
            Op.Receive (int socket, int count, flag peek, flag viaRead, flag mapped)
        | [| "i" ; socket |] -> Op.Fionread (int socket)
        | [| "p" ; socket |] -> Op.Poll (int socket)
        | _ -> failwith $"not a UDP op: %s{text}"

    let private writeSeen (seen : Seen) : string =
        $"%d{seen.Returned}:%d{seen.Errno}:%s{seen.Received}"

    let private parseSeen (text : string) : Seen =
        match text.Split ':' with
        | [| returned ; errno ; received |] ->
            {
                Returned = int64 returned
                Errno = int errno
                Received = received
            }
        | _ -> failwith $"not a UDP answer: %s{text}"

    /// `items` written by `write` and separated by `separator`, or `-` for
    /// none, which no item's writing is.
    let private joined (separator : string) (write : 'a -> string) (items : 'a list) : string =
        match items with
        | [] -> "-"
        | _ -> items |> List.map write |> String.concat separator

    let private writeSeens : Seen list -> string = joined "," writeSeen

    let private writeOps : Op list -> string = joined " " writeOp

    let private split (separator : char) (parse : string -> 'a) (text : string) : 'a list =
        match text with
        | "-" -> []
        | _ -> text.Split separator |> Array.toList |> List.map parse

    /// What a host answered to a sequence: the receive buffer its UDP sockets
    /// started with, and one `Seen` for each call each op made.
    type private HostRun =
        {
            ReceiveBuffer : int
            Calls : Seen list list
        }

    let private writeRun (run : HostRun) : string =
        let calls = joined " " writeSeens run.Calls
        $"%d{run.ReceiveBuffer};%s{calls}"

    let private parseRun (text : string) : HostRun =
        match text.Split (';', 2) with
        | [| buffer ; calls |] ->
            {
                ReceiveBuffer = int buffer
                Calls = split ' ' (split ',' parseSeen) calls
            }
        | _ -> failwith $"not a UDP run: %s{text}"

    /// Sequences of up to 40 ops over the fixture's five sockets, made on the
    /// host and in the kernel and compared answer by answer, the kernel booted
    /// with the host's receive buffer. A Mac's answers are recorded in
    /// `hostCorpus/udpTransfer.darwin.txt`, which every host replays, so CI,
    /// which runs on Linux, holds the Darwin column too.
    let private transfers : HostComparison<Op list, HostRun> =
        {
            Name = "udpTransfer"
            Inputs =
                fun platform ->
                    Gen.listOf (opGen (SimulatedUnixPlatform.flavour platform))
                    |> Gen.map (List.truncate 40)
            Count = 40
            WriteInput = writeOps
            ParseInput = split ' ' parseOp
            WriteAnswer = writeRun
            ParseAnswer = parseRun
            Host =
                fun platform ops ->
                    let flavour = SimulatedUnixPlatform.flavour platform
                    let host = hostSockets platform

                    try
                        {
                            ReceiveBuffer = hostReceiveBuffer flavour host.Head
                            Calls = ops |> List.mapi (fun index op -> hostApply flavour host index op)
                        }
                    finally
                        for fd in host do
                            HostCalls.close fd |> ignore<int>
            Disagreement =
                fun platform ops run ->
                    let kernel, system = kernelSockets platform run.ReceiveBuffer
                    let answers = run.Calls

                    let rec go
                        (system : UnixSystem<int, string>)
                        (calls : (int * Op * Seen list) list)
                        : string option
                        =
                        match calls with
                        | [] -> None
                        | (index, op, expected) :: rest ->
                            let seen, system = kernelApply platform kernel index op system

                            if seen <> expected then
                                Some
                                    $"op %d{index} (%s{writeOp op}): the model answered %s{writeSeens seen}, the kernel %s{writeSeens expected}"
                            else
                                match UnixSystem.checkInvariants system with
                                | [] -> go system rest
                                | violations -> Some $"op %d{index} (%s{writeOp op}) broke invariants: %A{violations}"

                    if answers.Length <> ops.Length then
                        Some $"%d{ops.Length} ops, but %d{answers.Length} answers"
                    else
                        go system (List.mapi2 (fun index op answer -> index, op, answer) ops answers)
                    |> Option.map (fun disagreement -> $"in [%s{writeOps ops}], %s{disagreement}")
        }

    [<Test>]
    let ``the kernel answers random UDP transfers as this host does`` () : unit =
        HostPlatform.onUnixHostKernel (HostCorpus.live transfers)

    [<Test>]
    let ``the kernel answers random UDP transfers as Darwin did`` () : unit =
        HostCorpus.replay transfers SimulatedUnixPlatform.macOsArm64

    [<Test>]
    let ``every random UDP transfer reads back as itself`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            HostCorpus.inputsRoundTrip transfers platform
