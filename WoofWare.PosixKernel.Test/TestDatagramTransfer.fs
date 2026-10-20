namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Moving datagrams between connected and unconnected UDP sockets through
/// `write(2)`, `send(2)`, `read(2)` and `recv(2)`, and what `FIONREAD` and
/// Linux's `poll(2)` report: the rows of `udp-transfer.c`
/// (docs/plans/2026-10-18-udp-data-path) that need no `sendto` and no ICMP
/// error, replayed on both flavours against the output each was measured to
/// give.
///
/// The probe's senders are unconnected and use `sendto`; here each is a
/// socket connected to the receiver, which delivers the same datagram.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramTransfer =

    let private shouldStartWith (prefix : string) (text : string) : unit =
        if not (text.StartsWith prefix) then
            failwith $"expected %s{text} to start with %s{prefix}"

    let private shouldEndWith (suffix : string) (text : string) : unit =
        if not (text.EndsWith suffix) then
            failwith $"expected %s{text} to end with %s{suffix}"

    let private platformOf (which : string) : SimulatedUnixPlatform =
        match which with
        | "linux" -> SimulatedUnixPlatform.linuxX64
        | _ -> SimulatedUnixPlatform.macOsArm64

    let private probe (platform : SimulatedUnixPlatform) : string list =
        let name =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.udpTransfer.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.udpTransfer.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.toList
        |> List.map (fun line -> line.TrimEnd '\r')

    /// The part of the probe's line starting `prefix` after `prefix`.
    let private row (platform : SimulatedUnixPlatform) (prefix : string) : string =
        match probe platform |> List.filter (fun line -> line.StartsWith prefix) with
        | [ line ] -> line.Substring prefix.Length
        | lines -> failwith $"expected one probe line starting %s{prefix}, found %d{lines.Length}"

    let private dontWait (platform : SimulatedUnixPlatform) : int =
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux -> 0x40
        | SimulatedUnixFlavour.Darwin -> 0x80

    [<Literal>]
    let private MSG_PEEK = 0x2

    let private payload (length : int) : ImmutableArray<byte> =
        ImmutableArray.CreateRange (Array.init length (fun i -> byte ('a' + char (i % 26))))

    /// A booted system of `platform`.
    let private systemOf (platform : SimulatedUnixPlatform) : UnixSystem<int, string> =
        UnixSystem.initial<int, string> platform
        |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

    /// A UDP socket bound to `address` at port 0, and its port.
    let private boundAt
        (address : Ipv4Address)
        (system : UnixSystem<int, string>)
        : int * uint16 * UnixSystem<int, string>
        =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let platform = UnixSystem.platform system

        let system =
            match
                CopyIn.bind fd UserBuffer.Mapped 16u (CopyIn.inet platform (Ipv4Endpoint.ofParts address 0us)) system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let socketId =
            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) -> socketId
            | other -> failwith $"fd %d{fd} is %A{other}"

        let port =
            match (Kernel.machine system).Sockets.[socketId].Ipv4Binding with
            | Some binding -> binding.Endpoint.Port
            | None -> failwith "the bound socket has no binding"

        fd, port, system

    let private bound (system : UnixSystem<int, string>) : int * uint16 * UnixSystem<int, string> =
        boundAt Ipv4Address.loopback system

    let private connectTo
        (fd : int)
        (address : Ipv4Address)
        (port : uint16)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        let platform = UnixSystem.platform system

        match
            CopyIn.connect fd UserBuffer.Mapped 16u (CopyIn.inet platform (Ipv4Endpoint.ofParts address port)) system
        with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"connect: %A{other}"

    /// A socket connected to the loopback `port`.
    let private senderTo (port : uint16) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let fd, _, system = bound system
        fd, connectTo fd Ipv4Address.loopback port system

    /// What a call returned, as the probe prints it: the count, or `-1` and
    /// the errno's name.
    let private shown (answer : Result<int64, UnixError>) : string =
        match answer with
        | Ok count -> $"%d{count}"
        | Error error -> $"-1 %O{error}"

    let private writeOf (answer : WriteAnswer) : Result<int64, UnixError> =
        match answer with
        | WriteAnswer.Completed written -> Ok written
        | WriteAnswer.Failed error -> Error error

    let private send
        (fd : int)
        (buffer : UserBuffer)
        (length : int)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        match WriteOutcomes.admitThenSend 0 fd buffer (payload length) 0 system with
        | Ok (WriteStep.Returns (answer, system)) -> shown (writeOf answer), system
        | other -> failwith $"send of %d{length}: %A{other}"

    let private write
        (fd : int)
        (buffer : UserBuffer)
        (length : int)
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        match WriteOutcomes.admitThenWrite 0 fd buffer (payload length) system with
        | Ok (WriteStep.Returns (answer, system)) -> shown (writeOf answer), system
        | other -> failwith $"write of %d{length}: %A{other}"

    let private readShown (answer : ReadAnswer) : string =
        match answer with
        | ReadAnswer.Completed bytes -> $"%d{bytes.Length}"
        | ReadAnswer.Failed error -> $"-1 %O{error}"
        | ReadAnswer.Drawn _ -> failwith "a socket draws no entropy"

    /// A non-blocking `recv(2)` of `count` with `flags`: what it answered,
    /// the bytes, and the system after.
    let private recv
        (fd : int)
        (buffer : UserBuffer)
        (count : int)
        (flags : int)
        (system : UnixSystem<int, string>)
        : string * ImmutableArray<byte> * UnixSystem<int, string>
        =
        let flags = flags ||| dontWait (UnixSystem.platform system)

        match UnixReadWrite.tryRecv (Callers.leader system) fd buffer (uint64 count) flags system with
        | Ok (ReadOutcome.Answered answer, system) ->
            let bytes =
                match answer with
                | ReadAnswer.Completed bytes -> bytes
                | _ -> ImmutableArray.Empty

            readShown answer, bytes, system
        | other -> failwith $"recv of %d{count}: %A{other}"

    let private recvShown fd buffer count flags system =
        let shown, _, system = recv fd buffer count flags system
        shown, system

    /// A read of `count` through a description made non-blocking for it.
    let private read (fd : int) (count : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) fd true system

        let answer, system =
            match ReadOutcomes.read fd UserBuffer.Mapped (uint64 count) system with
            | Ok (answer, system) -> readShown answer, system
            | other -> failwith $"read of %d{count}: %A{other}"

        let _, system =
            UnixDescriptor.setNonBlocking (Callers.leader system) fd false system

        answer, system

    /// What the probe's `drain` prints: every datagram's length, or "none".
    let private drain (fd : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        let rec go (taken : string list) (system : UnixSystem<int, string>) =
            match recvShown fd UserBuffer.Mapped 70000 0 system with
            | "-1 EAGAIN", system -> List.rev taken, system
            | shown, system -> go (shown :: taken) system

        match go [] system with
        | [], system -> "none", system
        | taken, system -> String.concat "," taken, system

    let private fionread (fd : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixDescriptor.tryBytesAvailable (Callers.leader system) fd UserBuffer.Mapped system with
        | Ok (BytesAvailableAnswer.Reported count, system) -> count, system
        | other -> failwith $"FIONREAD: %A{other}"

    /// Linux `poll(2)` of every event, as the probe asks, printed as it
    /// prints it.
    let private revents (fd : int) (system : UnixSystem<int, string>) : string * UnixSystem<int, string> =
        // IN PRI OUT RDNORM RDBAND WRNORM WRBAND RDHUP
        let entry : PollEntry =
            {
                Fd = fd
                Events = 0x23c7s
            }

        match UnixPoll.tryPoll (Callers.leader system) [ entry ] 0 system with
        | Ok (PollOutcome.Answered ([ revents ], count), system) ->
            $"poll=%d{count} revents=0x%x{uint16 revents}", system
        | other -> failwith $"poll: %A{other}"

    // ------------------------------------------------------------ B to E

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``datagrams keep their boundaries, as B1 and B2 measured`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system
        let _, system = send s UserBuffer.Mapped 10 system
        let _, system = send s UserBuffer.Mapped 20 system
        let _, system = send s UserBuffer.Mapped 30 system
        let a, system = recvShown r UserBuffer.Mapped 100 0 system
        let b, system = recvShown r UserBuffer.Mapped 100 0 system
        let c, system = recvShown r UserBuffer.Mapped 100 0 system
        let d, system = recvShown r UserBuffer.Mapped 100 0 system

        $"%s{a} %s{b} %s{c} %s{d}"
        |> shouldEqual (row platform "B1 datagrams of 10, 20, 30; four recvs of 100: ")

        let _, system = send s UserBuffer.Mapped 3 system
        let e, system = read r 100 system
        let f, _ = read r 100 system

        $"%s{e}, then %s{f}"
        |> shouldEqual (row platform "B2 read(2) of an unconnected socket holding one datagram of 3: ")

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``short and empty receives answer as C1 to C9 measured`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system

        // C1: a short receive discards the rest of the datagram.
        let _, system = send s UserBuffer.Mapped 100 system
        let _, system = send s UserBuffer.Mapped 4 system
        let a, bytes, system = recv r UserBuffer.Mapped 10 0 system
        let b, system = recvShown r UserBuffer.Mapped 200 0 system
        let first = Text.Encoding.ASCII.GetString (bytes.AsSpan(0, 3).ToArray ())

        $"%s{a} (first bytes %s{first}), then %s{b} (the next datagram if 4)"
        |> shouldEqual (row platform "C1 a datagram of 100 then one of 4; recv of 10, then of 200: ")

        // C3: a zero-length recv of a datagram.
        let _, system = send s UserBuffer.Mapped 100 system
        let a, system = recvShown r UserBuffer.Mapped 0 0 system
        let held, system = drain r system

        $"%s{a}; then the queue holds %s{held}"
        |> shouldEqual (row platform "C3 recv of 0 with a datagram of 100 queued: ")

        // C5: a zero-length read of a datagram.
        let _, system = send s UserBuffer.Mapped 100 system
        let a, system = read r 0 system
        let held, system = drain r system

        $"%s{a}; then %s{held}"
        |> shouldEqual (row platform "C5 read(2) of 0 with a datagram of 100 queued: ")

        // C6 and C7: a zero-length recv of nothing.
        let a, system = recvShown r UserBuffer.Mapped 0 0 system
        a |> shouldEqual (row platform "C6 recv of 0 MSG_DONTWAIT on an empty queue: ")
        let a, system = recvShown r (UserBuffer.Unmapped 0UL) 0 0 system
        a |> shouldEqual (row platform "C7 recv of 0 into NULL on an empty queue: ")

        // C9: a zero-length recv into an unmapped buffer.
        let _, system = send s UserBuffer.Mapped 100 system
        let a, system = recvShown r (UserBuffer.Unmapped 1UL) 0 0 system
        let held, system = drain r system

        $"%s{a}; then %s{held}"
        |> shouldEqual (row platform "C9 recv of 0 into an unmapped buffer, datagram of 100 queued: ")

        // C8: Linux takes the datagram and answers EFAULT; Darwin strips it,
        // which is refused.
        let _, system = send s UserBuffer.Mapped 100 system

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            let a, system = recvShown r (UserBuffer.Unmapped 1UL) 10 0 system
            let held, _ = drain r system

            $"%s{a}; then %s{held}"
            |> shouldEqual (row platform "C8 recv of 10 into an unmapped buffer, datagram of 100 queued: ")
        | SimulatedUnixFlavour.Darwin ->
            let flags = dontWait platform

            match UnixReadWrite.tryRecv (Callers.leader system) r (UserBuffer.Unmapped 1UL) 10UL flags system with
            | Error (ReceiveRefusal.DatagramFault _) -> ()
            | other -> failwith $"expected Darwin's faulting recv to be refused, got %A{other}"

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``peeks and empty datagrams answer as D1, D2, E1 and E2 measured`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system

        let _, system = send s UserBuffer.Mapped 20 system
        let _, system = send s UserBuffer.Mapped 3 system
        let a, system = recvShown r UserBuffer.Mapped 10 MSG_PEEK system
        let b, system = recvShown r UserBuffer.Mapped 100 MSG_PEEK system
        let held, system = drain r system
        // The probe's third peek is with MSG_TRUNC, which a recv refuses here.
        let measured =
            row platform "D1 peeks of 10, 100, and 10 with MSG_TRUNC, datagrams of 20 and 3: "

        let m = Regex.Match (measured, @"^(\S+) (\S+) \S+; then the queue holds (.*)$")

        $"%s{a} %s{b} %s{held}"
        |> shouldEqual $"%s{m.Groups.[1].Value} %s{m.Groups.[2].Value} %s{m.Groups.[3].Value}"

        let a, system = recvShown r UserBuffer.Mapped 10 MSG_PEEK system
        a |> shouldEqual (row platform "D2 peek of an empty queue: ")

        // E: a fresh receiver, as the probe's, which on Darwin charges its
        // first datagram less.
        let r, port, system = bound system
        let s, system = senderTo port system
        let count, system = fionread r system

        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            let level, system = revents r system
            $"%s{level} FIONREAD=%d{count}" |> shouldEqual (row platform "E0 empty queue: ")
            let a, system = send s UserBuffer.Mapped 0 system
            let level, system = revents r system
            let count, system = fionread r system

            $"%s{a}; then %s{level} FIONREAD=%d{count}"
            |> shouldEqual (row platform "E1 sendto of 0: ")

            let b, system = recvShown r UserBuffer.Mapped 100 0 system
            let c, system = recvShown r UserBuffer.Mapped 100 0 system
            let level, _ = revents r system

            $"%s{b} %s{c}; then %s{level}"
            |> shouldEqual (row platform "E2 recv of 100, twice: ")
        | SimulatedUnixFlavour.Darwin ->
            // Darwin's poll of a datagram socket is not modelled yet.
            count |> shouldEqual 0
            let a, system = send s UserBuffer.Mapped 0 system
            let count, system = fionread r system
            let measured = row platform "E1 sendto of 0: "
            measured |> shouldStartWith $"%s{a}; then "
            measured |> shouldEndWith $"FIONREAD=%d{count}"
            let b, system = recvShown r UserBuffer.Mapped 100 0 system
            let c, _ = recvShown r UserBuffer.Mapped 100 0 system
            row platform "E2 recv of 100, twice: " |> shouldStartWith $"%s{b} %s{c}; then "

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``FIONREAD reports what F1 to F6 measured`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system

        let _, system = send s UserBuffer.Mapped 10 system
        let _, system = send s UserBuffer.Mapped 20 system
        let _, system = send s UserBuffer.Mapped 30 system
        let f1, system = fionread r system

        row platform "F1 datagrams of 10, 20, 30: "
        |> shouldStartWith $"FIONREAD=%d{f1}"

        let _, system = recvShown r UserBuffer.Mapped 100 0 system
        let f2, system = fionread r system
        row platform "F2 after one recv: " |> shouldStartWith $"FIONREAD=%d{f2}"
        let _, system = drain r system
        let _, system = send s UserBuffer.Mapped 0 system
        let _, system = send s UserBuffer.Mapped 10 system
        let f3, _ = fionread r system
        row platform "F3 datagrams of 0, 10: " |> shouldStartWith $"FIONREAD=%d{f3}"

        // F6: a fresh receiver, its first datagram from one sender, the next
        // from another.
        let r3, port3, system = bound system
        let s3, system = senderTo port3 system
        let s4, system = senderTo port3 system
        let mutable system = system
        let mutable shownRow = []

        for name, sender in [ "s3", s3 ; "s4", s4 ; "s3", s3 ; "s3", s3 ] do
            let _, after = send sender UserBuffer.Mapped 10 system
            let count, after = fionread r3 after
            system <- after
            shownRow <- shownRow @ [ $"%s{name}+10=%d{count}" ]

        String.concat " " shownRow |> shouldEqual (row platform "F6 two senders: ")

    // ------------------------------------------------------------ G

    [<Test>]
    let ``a Linux UDP socket's poll level is what G1 to G4 measured`` () : unit =
        let platform = platformOf "linux"
        let system = systemOf platform

        let fresh, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let level, system = revents fresh system
        level |> shouldEqual (row platform "G1 fresh unbound: ")
        let r, port, system = bound system
        let level, system = revents r system
        level |> shouldEqual (row platform "G2 bound, empty: ")
        let s, system = senderTo port system
        let _, system = send s UserBuffer.Mapped 10 system
        let level, system = revents r system
        level |> shouldEqual (row platform "G3 bound, one datagram queued: ")
        let level, _ = revents s system
        level |> shouldEqual (row platform "G4 connected to a bound socket, empty: ")

    // ------------------------------------------------------------ H

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a connected send takes the sizes H1 and H3 measured`` (which : string) : unit =
        let platform = platformOf which

        for size in
            [
                0
                1
                1472
                8192
                9216
                9217
                16384
                65507
                65508
                65527
                65535
                65536
                69999
            ] do
            let system = systemOf platform
            let r, port, system = bound system
            let s, system = senderTo port system
            let a, system = send s UserBuffer.Mapped size system
            let held, _ = drain r system

            $"%s{a}; the receiver holds %s{held}"
            |> shouldEqual (row platform $"H1 send (connected) of %d{size}: ")

        for call, size in
            [
                for call in [ "send" ; "write" ] do
                    for size in [ 5 ; 9217 ; 65508 ; 70000 ] -> call, size
            ] do
            let system = systemOf platform
            let r, port, system = bound system
            let s, system = senderTo port system

            let a, system =
                match call with
                | "send" -> send s (UserBuffer.Unmapped 1UL) size system
                | _ -> write s (UserBuffer.Unmapped 1UL) size system

            let held, _ = drain r system

            $"%s{a}; the receiver holds %s{held}"
            |> shouldEqual (row platform $"H3 a connected %s{call} of %d{size} from an unmapped buffer: ")

    // ------------------------------------------------------------ K, M, W

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a connected socket's write, send and read answer as K1 to K3, M2 and W9 measured`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let r, port, system = bound system
        let c, system = senderTo port system
        let a, system = write c UserBuffer.Mapped 1 system
        let b, system = send c UserBuffer.Mapped 1 system
        let measured = row platform "K1 connected to r: "
        measured |> shouldStartWith $"write=%s{a} send=%s{b} "

        // K2: the receiver sends back.
        let rc, system =
            let socketId =
                match FileDescriptorRegistry.tryFindTarget c (Lone.fileDescriptors system) with
                | Some (OpenFileTarget.Socket socketId) -> socketId
                | other -> failwith $"%A{other}"

            match (Kernel.machine system).Sockets.[socketId].Ipv4Binding with
            | Some binding -> binding.Endpoint.Port, system
            | None -> failwith "no binding"

        // `r` connects to `c` to send back, since `c` takes datagrams only
        // from its peer.
        let system = connectTo r Ipv4Address.loopback rc system
        let _, system = send r UserBuffer.Mapped 4 system
        let x, system = read c 64 system
        let y, system = read c 64 system
        $"read=%s{x} then read=%s{y}" |> shouldEqual (row platform "K2 r sends to c: ")

        // K3: an empty datagram.
        let _, system = drain r system
        let a, system = write c UserBuffer.Mapped 0 system
        let held, system = drain r system

        $"%s{a}; r receives %s{held}"
        |> shouldEqual (row platform "K3 write of 0 on a connected socket: ")

        // M2: a socket connected to itself.
        let m, mport, system = bound system
        let system = connectTo m Ipv4Address.loopback mport system
        let a, system = send m UserBuffer.Mapped 5 system
        let got, bytes, system = recv m UserBuffer.Mapped 64 0 system
        got |> shouldEqual "5"

        $"%s{a}; it receives self2"
        |> shouldEqual (row platform "M2 connected to itself, send: ")

        bytes.Length |> shouldEqual 5

        // W9: send on an unconnected socket.
        let u, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let a, _ = send u UserBuffer.Mapped 1 system
        a |> shouldEqual (row platform "W9 send on an unconnected socket: ")

    // ------------------------------------------------------------ delivery

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``127.0.0.2 reaches a wildcard socket on Linux and no one on Darwin, as L15 measured`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let r, port, system = boundAt Ipv4Address.any system
        let c, _, system = boundAt Ipv4Address.any system
        let system = connectTo c (Ipv4Address 0x7F000002u) port system
        let a, system = send c UserBuffer.Mapped 1 system
        let held, _ = drain r system

        let measured =
            row platform "L15 connected to 127.0.0.2 at a port a 0.0.0.0-bound socket holds "

        measured |> shouldStartWith "(connect 0, from 127.0.0.1:"
        measured |> shouldEndWith $"send %s{a}; SO_ERROR 0; the receiver holds %s{held}"

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a datagram to a port nobody holds is refused until the ICMP error is modelled`` (which : string) : unit =
        let platform = platformOf which
        let system = systemOf platform
        let gone, port, system = bound system

        let system =
            match UnixDescriptor.tryClose (Callers.leader system) gone system with
            | Ok (SyscallAnswer.Completed 0L, system) -> system
            | other -> failwith $"close: %A{other}"

        let c, system = senderTo port system

        match
            UnixReadWrite.trySend (Callers.leader system) c UserBuffer.Mapped 1UL 0 system
            |> CallProgress.resumeWith (fun paused -> UnixReadWrite.trySendWithBytes (payload 1) paused)
        with
        | Error (SendRefusal.Delivery (DeliveryRefusal.Unreachable _)) -> ()
        | other -> failwith $"expected the send to be refused, got %A{other}"

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a specific address beats the wildcard, and a connected socket an unconnected one, as Q3 and Q5 measured``
        (which : string)
        : unit
        =
        let platform = platformOf which
        let reuse (fd : int) (system : UnixSystem<int, string>) = ReuseAddress.set true fd system

        // Q3: one socket on 0.0.0.0:p and one on 127.0.0.1:p, bound in each
        // order; a datagram to 127.0.0.1:p.
        for wildcardFirst in [ true ; false ] do
            let system = systemOf platform

            let first, system =
                NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

            let second, system =
                NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

            let system = system |> reuse first |> reuse second

            let firstAddress, secondAddress =
                if wildcardFirst then
                    Ipv4Address.any, Ipv4Address.loopback
                else
                    Ipv4Address.loopback, Ipv4Address.any

            let system =
                match
                    CopyIn.bind
                        first
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet platform (Ipv4Endpoint.ofParts firstAddress 0us))
                        system
                with
                | Ok (BindAnswer.Bound _, system) -> system
                | other -> failwith $"bind: %A{other}"

            let port =
                match FileDescriptorRegistry.tryFindTarget first (Lone.fileDescriptors system) with
                | Some (OpenFileTarget.Socket socketId) ->
                    (Kernel.machine system).Sockets.[socketId].Ipv4Binding.Value.Endpoint.Port
                | other -> failwith $"%A{other}"

            let system =
                match
                    CopyIn.bind
                        second
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet platform (Ipv4Endpoint.ofParts secondAddress port))
                        system
                with
                | Ok (BindAnswer.Bound _, system) -> system
                | other -> failwith $"bind: %A{other}"

            let s, system = senderTo port system
            let mutable system = system

            for _ in 1..4 do
                system <- send s UserBuffer.Mapped 1 system |> snd

            let wildcard, specific = if wildcardFirst then first, second else second, first
            let toWildcard, system = drain wildcard system
            let toSpecific, _ = drain specific system

            let count (held : string) =
                if held = "none" then 0 else held.Split(',').Length

            let order = if wildcardFirst then "0.0.0.0" else "127.0.0.1"

            row
                platform
                $"Q3 %s{order} bound first, the other second (0), SO_REUSEADDR on both; 4 datagrams to 127.0.0.1: "
            |> shouldEqual $"0.0.0.0 got %d{count toWildcard}, 127.0.0.1 got %d{count toSpecific}"

        // Q5: a, connected to s, holds 127.0.0.1:p; b binds it after, with
        // SO_REUSEADDR on both; s and t, each connected to p, send four each.
        let system = systemOf platform

        let a, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let b, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let system = system |> reuse a |> reuse b

        let system =
            match
                CopyIn.bind
                    a
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let portOf (fd : int) (system : UnixSystem<int, string>) : uint16 =
            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                (Kernel.machine system).Sockets.[socketId].Ipv4Binding.Value.Endpoint.Port
            | other -> failwith $"%A{other}"

        let p = portOf a system
        let s, sport, system = bound system
        let system = connectTo s Ipv4Address.loopback p system
        let system = connectTo a Ipv4Address.loopback sport system

        let system =
            match
                CopyIn.bind
                    b
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback p))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let t, system = senderTo p system
        let mutable system = system

        for _ in 1..4 do
            system <- send s UserBuffer.Mapped 1 system |> snd
            system <- send t UserBuffer.Mapped 1 system |> snd

        let toA, system = drain a system
        let toB, _ = drain b system

        let count (held : string) =
            if held = "none" then 0 else held.Split(',').Length

        let measured =
            row platform "Q5 a (connected to s) holds the port; b binds it after (0); s and t each send 4: "

        let m = Regex.Match (measured, @"^a got (.*); b got (.*)$")

        let countOf (text : string) =
            if text = "none" || text = "" then
                0
            else
                text.Split('|').Length

        (count toA, count toB)
        |> shouldEqual (countOf m.Groups.[1].Value, countOf m.Groups.[2].Value)

    // ------------------------------------------------------------ Linux's epoll edges

    let private epollOn (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        match UnixPoll.tryEpollCreate1 (Callers.leader system) 0 system with
        | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
        | other -> failwith $"epoll_create1: %A{other}"

    let private watch
        (epoll : int)
        (fd : int)
        (events : uint32)
        (system : UnixSystem<int, string>)
        : UnixSystem<int, string>
        =
        match
            UnixPoll.tryEpollCtl
                (Callers.leader system)
                epoll
                1
                fd
                (EpollEventArgument.Readable (events, uint64 fd))
                system
        with
        | Ok (EpollCtlAnswer.Changed, system) -> system
        | other -> failwith $"epoll_ctl: %A{other}"

    /// `epoll_wait` with timeout 0, as the probe's `epoll_now` prints it:
    /// the count, and the first event's mask.
    let private epollNow
        (epoll : int)
        (maxEvents : int)
        (system : UnixSystem<int, string>)
        : (uint64 * uint32) list * UnixSystem<int, string>
        =
        match UnixPoll.tryEpollWait (Callers.leader system) epoll maxEvents UserBuffer.Mapped 0 system with
        | Ok (EpollWaitOutcome.Answered events, system) -> events, system
        | other -> failwith $"epoll_wait: %A{other}"

    let private shownEvents (events : (uint64 * uint32) list) : string =
        match events with
        | [] -> "0"
        | (_, mask) :: _ -> $"%d{events.Length}:0x%x{mask}"

    [<Test>]
    let ``Linux's edge-triggered epoll sees what G5, G6, G8 and G9 measured`` () : unit =
        let platform = platformOf "linux"
        let edge = EpollEvents.EdgeTriggered

        // G5: a receiver watched for IN|OUT|ET.
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system
        let epoll, system = epollOn system
        let system = watch epoll r (EpollEvents.In ||| EpollEvents.Out ||| edge) system
        let w0, system = epollNow epoll 4 system
        let w1, system = epollNow epoll 4 system
        let _, system = send s UserBuffer.Mapped 10 system
        let w2, system = epollNow epoll 4 system
        let w3, system = epollNow epoll 4 system
        let _, system = send s UserBuffer.Mapped 20 system
        let w4, system = epollNow epoll 4 system
        let _, system = recvShown r UserBuffer.Mapped 100 0 system
        let w5, system = epollNow epoll 4 system
        let _, system = recvShown r UserBuffer.Mapped 100 0 system
        let w6, _ = epollNow epoll 4 system

        $"registered %s{shownEvents w0}, again %s{shownEvents w1}; a datagram %s{shownEvents w2}, again %s{shownEvents w3}; a second %s{shownEvents w4}; one taken %s{shownEvents w5}; both taken %s{shownEvents w6}"
        |> shouldEqual (row platform "G5 epoll IN|OUT|ET on a bound receiver: ")

        // G6: a sender watched for OUT|ET.
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system
        let epoll, system = epollOn system
        let system = watch epoll s (EpollEvents.Out ||| edge) system
        let w0, system = epollNow epoll 4 system
        let _, system = send s UserBuffer.Mapped 10 system
        let w1, system = epollNow epoll 4 system
        let _, system = recvShown r UserBuffer.Mapped 100 0 system
        let w2, _ = epollNow epoll 4 system

        $"registered %s{shownEvents w0}; after its send %s{shownEvents w1}; after the receiver takes it %s{shownEvents w2}"
        |> shouldEqual (row platform "G6 epoll OUT|ET on a sender: ")

        // G8: one instance watching a sender and its receiver.
        let system = systemOf platform
        let r, port, system = bound system
        let s, system = senderTo port system
        let epoll, system = epollOn system
        let system = watch epoll s (EpollEvents.Out ||| edge) system
        let system = watch epoll r (EpollEvents.In ||| edge) system
        let _, system = epollNow epoll 4 system
        let _, system = send s UserBuffer.Mapped 10 system

        let name (events : (uint64 * uint32) list) : string =
            match events with
            | [] -> "none"
            | (data, _) :: _ when data = uint64 s -> "sender"
            | (data, _) :: _ when data = uint64 r -> "receiver"
            | _ -> "?"

        let first, system = epollNow epoll 1 system
        let second, _ = epollNow epoll 1 system

        $"first %s{name first}, then %s{name second}"
        |> shouldEqual (row platform "G8 one epoll, sender OUT|ET and receiver IN|ET, after a send, maxevents 1: ")

        // G9: a connected sender's calls that fail, or send nothing.
        for what, call in
            [
                "write from an unmapped buffer (EFAULT)", (fun s system -> write s (UserBuffer.Unmapped 1UL) 1 system)
                "send of 65508 bytes (EMSGSIZE)", (fun s system -> send s UserBuffer.Mapped 65508 system)
                "write of 0 bytes (sent)", (fun s system -> write s UserBuffer.Mapped 0 system)
                "send from an unmapped buffer (EFAULT)", (fun s system -> send s (UserBuffer.Unmapped 1UL) 1 system)
            ] do
            let system = systemOf platform
            let _, port, system = bound system
            let s, system = senderTo port system
            let epoll, system = epollOn system
            let system = watch epoll s (EpollEvents.Out ||| edge) system
            let w0, system = epollNow epoll 4 system
            let a, system = call s system
            let w1, _ = epollNow epoll 4 system

            let line =
                $"G9 epoll OUT|ET on a connected sender: registered %s{shownEvents w0}; a %s{what}: %s{a}, then %s{shownEvents w1}"

            if not (List.contains line (probe platform)) then
                failwith $"the probe has no line %s{line}"

    [<Test>]
    let ``a Linux socket connected to port 0 refuses a datagram from its peer's address`` () : unit =
        let platform = platformOf "linux"
        let system = systemOf platform
        // A connected to 127.0.0.1:0, and B, beside it on the wildcard at the
        // same port, which would otherwise take the datagram.
        let a, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let b, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let system = system |> ReuseAddress.set true a |> ReuseAddress.set true b

        let system =
            match
                CopyIn.bind
                    a
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let port =
            match FileDescriptorRegistry.tryFindTarget a (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                (Kernel.machine system).Sockets.[socketId].Ipv4Binding.Value.Endpoint.Port
            | other -> failwith $"%A{other}"

        let system = connectTo a Ipv4Address.loopback 0us system

        let system =
            match
                CopyIn.bind
                    b
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.any port))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let s, system = senderTo port system

        match
            UnixReadWrite.trySend (Callers.leader system) s UserBuffer.Mapped 1UL 0 system
            |> CallProgress.resumeWith (fun paused -> UnixReadWrite.trySendWithBytes (payload 1) paused)
        with
        | Error (SendRefusal.Delivery (DeliveryRefusal.ZeroPortPeer _)) -> ()
        | other -> failwith $"expected the send to be refused, got %A{other}"
