namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.IO
open System.Reflection
open System.Text.RegularExpressions
open FsCheck
open FsCheck.FSharp
open FsUnitTyped
open NUnit.Framework
open WoofWare.PosixKernel

/// Moving datagrams between connected and unconnected UDP sockets through
/// `write(2)`, `send(2)`, `read(2)` and `recv(2)`, what `FIONREAD` and
/// Linux's `poll(2)` report, and the ICMP error a datagram no socket takes
/// raises: the rows of `udp-transfer.c` and `udp-error.c`
/// (docs/plans/2026-10-18-udp-data-path) that need no `sendto`, replayed on
/// both flavours against the output each was measured to give.
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
            match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
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

            match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
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
                    (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding.Value.Endpoint.Port
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
                (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding.Value.Endpoint.Port
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
                (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding.Value.Endpoint.Port
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

    // ------------------------------------------------------------ the ICMP error: L, X and Y

    /// The lines `udp-error.c` printed on `platform`.
    let private errorProbe (platform : SimulatedUnixPlatform) : string list =
        let name =
            match SimulatedUnixPlatform.flavour platform with
            | SimulatedUnixFlavour.Linux -> "WoofWare.PosixKernel.Test.udpError.linux.txt"
            | SimulatedUnixFlavour.Darwin -> "WoofWare.PosixKernel.Test.udpError.darwin.txt"

        use stream =
            match Assembly.GetExecutingAssembly().GetManifestResourceStream name with
            | null -> failwith $"embedded resource %s{name} not found"
            | stream -> stream

        use reader = new StreamReader (stream)

        reader.ReadToEnd().Split '\n'
        |> Array.toList
        |> List.map (fun line -> line.TrimEnd '\r')

    /// `text` with every port number in it replaced, since each run of the
    /// probe, and of the kernel, picks its own.
    let private portless (text : string) : string = Regex.Replace (text, @":\d+", ":N")

    /// Fails unless the probe printed `line` on `platform`, ports aside.
    let private measuredLine (lines : string list) (line : string) : unit =
        if not (lines |> List.map portless |> List.contains (portless line)) then
            failwith $"the probe has no line %s{line}"

    let private close (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"close: %A{other}"

    /// A port no socket holds: one a socket was bound to and closed, as the
    /// probe's `unheld_port` finds one.
    let private unheldPort (system : UnixSystem<int, string>) : uint16 * UnixSystem<int, string> =
        let fd, port, system = bound system
        port, close fd system

    /// `SO_ERROR` read through an `int`: the raw errno, or 0.
    let private soError (fd : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
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
        | Ok (answer, system) -> OptionValue.readInt answer, system
        | Error refusal -> failwith $"SO_ERROR refused: %s{SocketOptionRefusal.describe refusal}"

    /// A connect through a buffer holding `blob`, declared `length` bytes
    /// long, as the probe prints its answer.
    let private connectShown
        (fd : int)
        (buffer : UserBuffer)
        (length : uint32)
        (blob : byte[])
        (system : UnixSystem<int, string>)
        : string * UnixSystem<int, string>
        =
        match CopyIn.connect fd buffer length blob system with
        | Ok (SyscallAnswer.Completed answer, system) -> $"%d{answer}", system
        | Ok (SyscallAnswer.Failed error, system) -> $"-1 %O{error}", system
        | Error refusal -> failwith $"connect refused: %s{ConnectRefusal.describe refusal}"

    let private endpointText (endpoint : Ipv4Endpoint) : string =
        let (Ipv4Address address) = endpoint.Address
        $"%d{address >>> 24}.%d{(address >>> 16) &&& 0xFFu}.%d{(address >>> 8) &&& 0xFFu}.%d{address &&& 0xFFu}:%d{endpoint.Port}"

    /// `getpeername` or `getsockname`, as `udp-error.c` prints it.
    let private nameShown
        (label : string)
        (call : Caller<int> -> int -> UserBuffer -> uint32 -> UnixSystem<int, string> -> Result<GetSockNameAnswer, _>)
        (fd : int)
        (system : UnixSystem<int, string>)
        : string
        =
        match call (Callers.leader system) fd UserBuffer.Mapped 16u system with
        | Ok (GetSockNameAnswer.Reported (bytes, _)) -> $"%s{label} %s{endpointText (CopyOut.endpoint bytes)}"
        | Ok (GetSockNameAnswer.Failed (error, _)) -> $"get%s{label}name %O{error}"
        | Error _ -> failwith $"get%s{label}name refused"

    let private peerShown (fd : int) (system : UnixSystem<int, string>) : string =
        nameShown "peer" UnixSocket.tryGetpeername fd system

    let private selfShown (fd : int) (system : UnixSystem<int, string>) : string =
        nameShown "self" UnixSocket.tryGetsockname fd system

    /// A socket bound to 127.0.0.1, connected to a port nobody holds, that
    /// has sent a byte there, and so has ECONNREFUSED pending: the probe's
    /// `pending`. Also the port.
    let private pending (system : UnixSystem<int, string>) : int * uint16 * UnixSystem<int, string> =
        let port, system = unheldPort system
        let c, system = senderTo port system
        let sent, system = send c UserBuffer.Mapped 1 system

        if sent <> "1" then
            failwith $"the send that raises the error answered %s{sent}"

        c, port, system

    /// A blob holding `family` and 127.0.0.1:`port`.
    let private family (platform : SimulatedUnixPlatform) (family : int) (port : uint16) : byte[] =
        CopyIn.blob platform family (Ipv4Endpoint.ofParts Ipv4Address.loopback port)

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``each connect answers a pending ICMP error as Y1 measured`` (which : string) : unit =
        let platform = platformOf which
        let lines = errorProbe platform
        let inet = SimulatedUnixPlatform.internetAddressFamily

        let row
            (label : string)
            (connect : int -> uint16 -> UnixSystem<int, string> -> string * UnixSystem<int, string>)
            =
            let system = systemOf platform
            let c, port, system = pending system
            let answer, system = connect c port system
            let error, system = soError c system

            measuredLine
                lines
                $"Y1 %s{label}: %s{answer}; then SO_ERROR=%d{error}; %s{peerShown c system}; %s{selfShown c system}"

        row
            "connect elsewhere"
            (fun c _ system ->
                let other, system = unheldPort system
                connectShown c UserBuffer.Mapped 16u (family platform inet other) system
            )

        row
            "connect to the same peer"
            (fun c port system -> connectShown c UserBuffer.Mapped 16u (family platform inet port) system)

        row
            "connect AF_UNSPEC, length 16"
            (fun c _ system -> connectShown c UserBuffer.Mapped 16u (family platform 0 0us) system)

        row
            "connect to 127.0.0.1:0"
            (fun c _ system -> connectShown c UserBuffer.Mapped 16u (family platform inet 0us) system)

        row
            "connect with family 200"
            (fun c _ system -> connectShown c UserBuffer.Mapped 16u (family platform 200 9us) system)

        row
            "connect with length 8"
            (fun c _ system -> connectShown c UserBuffer.Mapped 8u (family platform inet 9us) system)

        row
            "connect from an unmapped address"
            (fun c _ system -> connectShown c (UserBuffer.Unmapped 1UL) 16u (family platform inet 9us) system)

        // Darwin's connects the socket to the broadcast address, which this
        // kernel refuses to record as a peer.
        match SimulatedUnixPlatform.flavour platform with
        | SimulatedUnixFlavour.Linux ->
            row
                "connect to 255.255.255.255:9"
                (fun c _ system ->
                    connectShown
                        c
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.broadcast 9us))
                        system
                )
        | SimulatedUnixFlavour.Darwin -> ()

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``sends, receives and the calls that report on a socket answer a pending ICMP error as Y2 to Y6 measured``
        (which : string)
        : unit
        =
        let platform = platformOf which
        let lines = errorProbe platform

        let afterwards
            (line : string -> int -> string)
            (call : int -> UnixSystem<int, string> -> string * UnixSystem<int, string>)
            =
            let system = systemOf platform
            let c, _, system = pending system
            let answer, system = call c system
            let error, _ = soError c system
            measuredLine lines (line answer error)

        // Y2 and Y3.
        for size in [ 9217 ; 65507 ; 65508 ; 65536 ] do
            afterwards
                (fun a e -> $"Y2 write of %d{size}: %s{a}; then SO_ERROR=%d{e}")
                (fun c -> write c UserBuffer.Mapped size)

            afterwards
                (fun a e -> $"Y2 send of %d{size}: %s{a}; then SO_ERROR=%d{e}")
                (fun c -> send c UserBuffer.Mapped size)

        afterwards
            (fun a e -> $"Y3 write of 1 from an unmapped buffer: %s{a}; then SO_ERROR=%d{e}")
            (fun c -> write c (UserBuffer.Unmapped 1UL) 1)

        afterwards
            (fun a e -> $"Y3 send of 1 from an unmapped buffer: %s{a}; then SO_ERROR=%d{e}")
            (fun c -> send c (UserBuffer.Unmapped 1UL) 1)

        // Y4.
        afterwards
            (fun a e -> $"Y4 read of 1 into an unmapped buffer: %s{a}; then SO_ERROR=%d{e}")
            (fun c system ->
                let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) c true system

                match ReadOutcomes.read c (UserBuffer.Unmapped 1UL) 1UL system with
                | Ok (answer, system) -> readShown answer, system
                | other -> failwith $"read: %A{other}"
            )

        afterwards
            (fun a e -> $"Y4 recv of 1 into an unmapped buffer: %s{a}; then SO_ERROR=%d{e}")
            (fun c -> recvShown c (UserBuffer.Unmapped 1UL) 1 0)

        // Y5.
        afterwards
            (fun a e -> $"Y5 FIONREAD: 0, value %s{a}; then SO_ERROR=%d{e}")
            (fun c system ->
                let count, system = fionread c system
                $"%d{count}", system
            )

        afterwards
            (fun a e -> $"Y5 getsockname and getpeername: %s{a}; then SO_ERROR=%d{e}")
            (fun c system -> $"%s{selfShown c system}; %s{peerShown c system}", system)

        afterwards
            (fun a e -> $"Y5 bind again: %s{a}; then SO_ERROR=%d{e}")
            (fun c system ->
                match
                    CopyIn.bind
                        c
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us))
                        system
                with
                | Ok (BindAnswer.Failed error, system) -> $"-1 %O{error}", system
                | other -> failwith $"bind: %A{other}"
            )

        let soErrorThrough
            (value : UserBuffer)
            (declared : uint32 option)
            (c : int)
            (system : UnixSystem<int, string>)
            : GetSockOptAnswer * UnixSystem<int, string>
            =
            match
                Lone.UnixSocket.tryGetsockoptLength
                    c
                    (SimulatedUnixPlatform.socketOptionLevel platform)
                    (SimulatedUnixPlatform.socketErrorOption platform)
                    value
                    UserBuffer.Mapped
                    declared
                    system
            with
            | Ok (answer, system) -> answer, system
            | Error refusal -> failwith $"SO_ERROR refused: %s{SocketOptionRefusal.describe refusal}"

        afterwards
            (fun a e -> $"Y5 SO_ERROR into a null value buffer: %s{a}; then SO_ERROR=%d{e}")
            (fun c system ->
                // Darwin reads no length through a null value buffer.
                let declared =
                    match SimulatedUnixPlatform.flavour platform with
                    | SimulatedUnixFlavour.Linux -> Some 4u
                    | SimulatedUnixFlavour.Darwin -> None

                match soErrorThrough (UserBuffer.Unmapped 0UL) declared c system with
                | GetSockOptAnswer.Reported _, system -> "0", system
                | GetSockOptAnswer.Failed (error, _), system -> $"-1 %O{error}", system
            )

        afterwards
            (fun a e -> $"Y5 SO_ERROR with length 0: %s{a}; then SO_ERROR=%d{e}")
            (fun c system ->
                match soErrorThrough UserBuffer.Mapped (Some 0u) c system with
                | GetSockOptAnswer.Reported copied, system when copied.IsEmpty -> "0, length 0, value -1", system
                | other, _ -> failwith $"SO_ERROR with length 0: %A{other}"
            )

        // Y6.
        let system = systemOf platform
        let c, _, system = pending system
        let a, system = send c UserBuffer.Mapped 1 system
        let first, system = soError c system
        let second, _ = soError c system
        measuredLine lines $"Y6 a send with the error pending: %s{a}; then SO_ERROR=%d{first}, then SO_ERROR=%d{second}"

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a socket an AF_UNSPEC connect disconnected keeps its pending ICMP error, as Y7 measured``
        (which : string)
        : unit
        =
        let platform = platformOf which
        let lines = errorProbe platform

        let calls : (string * (int -> UnixSystem<int, string> -> string * UnixSystem<int, string>)) list =
            [
                "write of 1", (fun c -> write c UserBuffer.Mapped 1)
                "write of 0", (fun c -> write c UserBuffer.Mapped 0)
                "send of 1", (fun c -> send c UserBuffer.Mapped 1)
                "read of 1", (fun c -> read c 1)
                "read of 0", (fun c -> read c 0)
                "recv of 1", (fun c -> recvShown c UserBuffer.Mapped 1 0)
                "recv of 0", (fun c -> recvShown c UserBuffer.Mapped 0 0)
                "connect elsewhere",
                (fun c system ->
                    let other, system = unheldPort system

                    connectShown
                        c
                        UserBuffer.Mapped
                        16u
                        (family platform SimulatedUnixPlatform.internetAddressFamily other)
                        system
                )
                "SO_ERROR",
                (fun c system ->
                    let error, system = soError c system
                    $"%d{error}", system
                )
            ]

        for label, call in calls do
            let system = systemOf platform
            let c, _, system = pending system
            let _, system = connectShown c UserBuffer.Mapped 16u (family platform 0 0us) system
            let answer, system = call c system
            let error, system = soError c system

            measuredLine
                lines
                $"Y7 disconnected by AF_UNSPEC, then %s{label}: %s{answer}; then SO_ERROR=%d{error}; %s{peerShown c system}"

    [<Test>]
    let ``Linux's edge-triggered epoll sees a pending ICMP error as G7 and Y8 measured`` () : unit =
        let platform = platformOf "linux"
        let lines = errorProbe platform
        let edge = EpollEvents.EdgeTriggered

        let calls : (string * (int -> UnixSystem<int, string> -> string * UnixSystem<int, string>)) list =
            [
                "write of 1", (fun c -> write c UserBuffer.Mapped 1)
                "recv of 1", (fun c -> recvShown c UserBuffer.Mapped 1 0)
                "SO_ERROR",
                (fun c system ->
                    let error, system = soError c system
                    $"%d{error}", system
                )
                "connect elsewhere",
                (fun c system ->
                    let other, system = unheldPort system

                    connectShown
                        c
                        UserBuffer.Mapped
                        16u
                        (family platform SimulatedUnixPlatform.internetAddressFamily other)
                        system
                )
            ]

        // The probe prints a mask of 0 when nothing is reported.
        let shownOrZero (events : (uint64 * uint32) list) : string =
            match events with
            | [] -> "0:0x0"
            | _ -> shownEvents events

        for label, call in calls do
            let system = systemOf platform
            let c, _, system = pending system
            let epoll, system = epollOn system
            let system = watch epoll c (EpollEvents.In ||| EpollEvents.Out ||| edge) system
            let w1, system = epollNow epoll 1 system
            let w2, system = epollNow epoll 1 system
            let answer, system = call c system
            let w3, _ = epollNow epoll 1 system

            measuredLine
                lines
                $"Y8 epoll IN|OUT|ET registered with the error pending: %s{shownEvents w1}, again %s{shownEvents w2}; %s{label}: %s{answer}; then %s{shownOrZero w3}"

        let system = systemOf platform
        let port, system = unheldPort system
        let c, system = senderTo port system
        let epoll, system = epollOn system
        let system = watch epoll c (EpollEvents.In ||| EpollEvents.Out ||| edge) system
        let w1, system = epollNow epoll 1 system
        let a, system = send c UserBuffer.Mapped 1 system
        let w2, system = epollNow epoll 1 system
        let w3, _ = epollNow epoll 1 system

        measuredLine
            lines
            $"Y8 epoll IN|OUT|ET on a socket connected to an unheld port: registered %s{shownEvents w1}; a send %s{a}; then %s{shownEvents w2}; again %s{shownEvents w3}"

        // G7: a registration for IN|ET alone is told of the error.
        let system = systemOf platform
        let port, system = unheldPort system
        let c, system = senderTo port system
        let epoll, system = epollOn system
        let system = watch epoll c (EpollEvents.In ||| edge) system
        let w1, system = epollNow epoll 4 system
        let _, system = send c UserBuffer.Mapped 1 system
        let w2, system = epollNow epoll 4 system
        let w3, _ = epollNow epoll 4 system

        $"registered %s{shownEvents w1}; after a send %s{shownEvents w2}; again %s{shownEvents w3}"
        |> shouldEqual (row platform "G7 epoll IN|ET on a socket connected to an unheld port: ")

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``a connected socket's datagram that no socket takes leaves ECONNREFUSED pending, as L measured``
        (which : string)
        : unit
        =
        let platform = platformOf which
        let flavour = SimulatedUnixPlatform.flavour platform

        // L1 and L2: Linux sets the error before the send returns, and
        // Darwin a moment later, so only Linux's rows say what the kernel,
        // which sets it at once on both, answers. Darwin's sometimes do too:
        // section 2.8 of the plan.
        if flavour = SimulatedUnixFlavour.Linux then
            let system = systemOf platform
            let port, system = unheldPort system
            let c, system = senderTo port system
            let a, system = send c UserBuffer.Mapped 1 system
            let p0, system = revents c system
            let p1, system = revents c system
            let b, system = recvShown c UserBuffer.Mapped 64 0 system
            let p2, system = revents c system
            let d, system = recvShown c UserBuffer.Mapped 64 0 system
            let e, _ = soError c system

            $"send=%s{a}; at once %s{p0}; later %s{p1}; recv=%s{b} then %s{p2}; recv=%s{d}; SO_ERROR=%d{e}"
            |> shouldEqual (row platform "L1 connected to an unheld port: ")

            let system = systemOf platform
            let port, system = unheldPort system
            let c, system = senderTo port system
            let a, system = send c UserBuffer.Mapped 1 system
            let b, system = send c UserBuffer.Mapped 1 system
            let d, system = send c UserBuffer.Mapped 1 system
            let e, system = send c UserBuffer.Mapped 1 system
            let first, system = soError c system
            let second, _ = soError c system

            $"%s{a}, at once %s{b}, later %s{d}, %s{e}; SO_ERROR=%d{first} then %d{second}"
            |> shouldEqual (row platform "L2 connected to an unheld port, sends: ")

        // L3.
        let system = systemOf platform
        let c, _, system = pending system
        let e1, system = soError c system
        let e2, system = soError c system
        let b, _ = recvShown c UserBuffer.Mapped 64 0 system

        $"SO_ERROR=%d{e1} then %d{e2}; recv=%s{b}"
        |> shouldEqual (row platform "L3 connected to an unheld port, after a send: ")

        // L5: the error, then a datagram from the peer, which has bound the
        // port since.
        let system = systemOf platform
        let c, x, system = pending system

        let q, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let system =
            match
                CopyIn.bind
                    q
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback x))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let cPort =
            match FileDescriptorRegistry.tryFindTarget c (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding.Value.Endpoint.Port
            | other -> failwith $"%A{other}"

        let system = connectTo q Ipv4Address.loopback cPort system
        let _, system = send q UserBuffer.Mapped 4 system
        let fion, system = fionread c system

        let rec drainText (taken : string list) (system : UnixSystem<int, string>) =
            match recv c UserBuffer.Mapped 256 0 system with
            | "-1 EAGAIN", _, system -> List.rev taken, system
            | "-1 ECONNREFUSED", _, system -> drainText ("ECONNREFUSED" :: taken) system
            | _, bytes, system -> drainText (Text.Encoding.ASCII.GetString (bytes.AsSpan().ToArray ()) :: taken) system

        let level, system =
            match flavour with
            | SimulatedUnixFlavour.Linux -> revents c system
            // Darwin's poll of a UDP socket is refused (issue #12); the row's
            // own level stands in.
            | SimulatedUnixFlavour.Darwin -> "poll=1 revents=0x145", system

        let got, system = drainText [] system
        let after, _ = soError c system

        // The peer's data is "abcd" here, "data" in the probe.
        let got =
            got
            |> List.map (fun text -> if text = "abcd" then "data" else text)
            |> String.concat "|"

        $"FIONREAD=%d{fion}; %s{level}; c receives %s{got}; SO_ERROR=%d{after}"
        |> shouldEqual (row platform "L5 an error pending, then the peer binds (0) and sends 'data': ")

        // L6.
        let system = systemOf platform
        let port, system = unheldPort system
        let c, system = senderTo port system
        let _, system = write c UserBuffer.Mapped 1 system
        let a, system = write c UserBuffer.Mapped 1 system
        let b, _ = read c 64 system

        $"%s{a}; read after the second write's error=%s{b}"
        |> shouldEqual (row platform "L6 write then write: ")

        // L7.
        let system = systemOf platform
        let c, _, system = pending system
        let _, rPort, system = bound system

        let cc, system =
            connectShown
                c
                UserBuffer.Mapped
                16u
                (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback rPort))
                system

        let error, system = soError c system

        let peerPort =
            match UnixSocket.tryGetpeername (Callers.leader system) c UserBuffer.Mapped 16u system with
            | Ok (GetSockNameAnswer.Reported (bytes, _)) -> (CopyOut.endpoint bytes).Port
            | other -> failwith $"getpeername: %A{other}"

        let measured = row platform "L7 an error pending, then connect elsewhere "

        let m =
            Regex.Match (measured, @"^\(to port (\d+)\): (.*); SO_ERROR=(\d+); getpeername (-?\d+) port (\d+)$")

        m.Success |> shouldEqual true
        m.Groups.[1].Value |> shouldEqual m.Groups.[5].Value
        m.Groups.[4].Value |> shouldEqual "0"

        (cc, error, peerPort = rPort)
        |> shouldEqual (m.Groups.[2].Value, int m.Groups.[3].Value, true)

        // L8.
        let system = systemOf platform
        let c, _, system = pending system
        let a, system = recvShown c UserBuffer.Mapped 0 0 system
        let e, _ = soError c system

        $"%s{a}; SO_ERROR=%d{e}"
        |> shouldEqual (row platform "L8 an error pending, recv of 0: ")

        // L10.
        let system = systemOf platform
        let port, system = unheldPort system
        let c, _, system = boundAt Ipv4Address.any system
        let system = connectTo c Ipv4Address.loopback port system
        let _, system = send c UserBuffer.Mapped 1 system
        let e, _ = soError c system

        $"SO_ERROR=%d{e}"
        |> shouldEqual (row platform "L10 bound 0.0.0.0, connected to an unheld port, after a send: ")

        // L11: a port only a TCP listener holds.
        let system = systemOf platform

        let listener, system =
            NewSocket.create SocketDomain.Inet SocketKind.Stream SocketProtocol.Tcp system

        let system =
            match
                CopyIn.bind
                    listener
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let system =
            match UnixSocket.tryListen (Callers.leader system) listener 16 system with
            | Ok (_, system) -> system
            | other -> failwith $"listen: %A{other}"

        let tcpPort =
            match FileDescriptorRegistry.tryFindTarget listener (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding.Value.Endpoint.Port
            | other -> failwith $"%A{other}"

        let c, system = senderTo tcpPort system
        let _, system = send c UserBuffer.Mapped 1 system
        let e, _ = soError c system

        $"SO_ERROR=%d{e}"
        |> shouldEqual (row platform "L11 connected to a port only a TCP listener holds, after a send: ")

        // L12.
        let system = systemOf platform
        let x, xPort, system = bound system
        let _, otherPort, system = bound system
        let system = connectTo x Ipv4Address.loopback otherPort system
        let c, system = senderTo xPort system
        let _, system = send c UserBuffer.Mapped 1 system
        let e, system = soError c system
        let held, _ = drain x system

        $"SO_ERROR=%d{e}; that socket holds %s{held}"
        |> shouldEqual (row platform "L12 connected to a port whose only socket is connected elsewhere, after a send: ")

        // L13.
        let system = systemOf platform
        let _, xPort, system = bound system
        let c, system = senderTo xPort system
        let mutable system = system
        let mutable sent = 0

        for _ in 1..400 do
            let answer, after = send c UserBuffer.Mapped 9000 system
            system <- after

            if answer = "9000" then
                sent <- sent + 1

        let e, _ = soError c system

        $"%d{sent} sends: SO_ERROR=%d{e}"
        |> shouldEqual (row platform "L13 connected, the receiver's queue overfilled with ")

        // L14.
        for name, call in
            [
                "read of 0", (fun c -> read c 0)
                "read of 0 into NULL",
                (fun c system ->
                    let _, system = UnixDescriptor.setNonBlocking (Callers.leader system) c true system

                    match ReadOutcomes.read c (UserBuffer.Unmapped 0UL) 0UL system with
                    | Ok (answer, system) -> readShown answer, system
                    | other -> failwith $"read: %A{other}"
                )
                "write of 0", (fun c -> write c UserBuffer.Mapped 0)
                "send of 0", (fun c -> send c UserBuffer.Mapped 0)
            ] do
            let system = systemOf platform
            let c, _, system = pending system
            let a, system = call c system
            let e, _ = soError c system

            $"%s{a}; then SO_ERROR=%d{e}"
            |> shouldEqual (row platform $"L14 an error pending, %s{name}: ")

        // L15: 127.0.0.2, at a port nobody holds.
        let system = systemOf platform
        let port, system = unheldPort system
        let c, _, system = boundAt Ipv4Address.any system

        let cc, system =
            connectShown
                c
                UserBuffer.Mapped
                16u
                (CopyIn.inet platform (Ipv4Endpoint.ofParts (Ipv4Address 0x7F000002u) port))
                system

        let a, system = send c UserBuffer.Mapped 1 system
        let e, system = soError c system
        let from = (selfShown c system).Substring "self ".Length

        $"(connect %s{cc}, from %s{from}): send %s{a}; SO_ERROR %d{e}; the receiver holds -"
        |> portless
        |> shouldEqual (portless (row platform "L15 connected to 127.0.0.2 at a port nobody holds "))

    [<Test>]
    let ``a datagram to no one from a socket sharing its endpoint with another connected to the same peer is refused on Linux``
        ()
        : unit
        =
        // L16's second row: A and B share 127.0.0.1:L through SO_REUSEADDR,
        // both connected to P, which nobody holds, and B sends. Linux gives
        // the error to B, the socket bound last, which this kernel does not
        // record; Darwin refuses B's connect, as this kernel does.
        let platform = platformOf "linux"
        let system = systemOf platform

        let a, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let b, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let system = system |> ReuseAddress.set true a |> ReuseAddress.set true b

        let bindAt (fd : int) (port : uint16) (system : UnixSystem<int, string>) =
            match
                CopyIn.bind
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port))
                    system
            with
            | Ok (BindAnswer.Bound address, system) -> address, system
            | other -> failwith $"bind: %A{other}"

        let p, system = unheldPort system

        let l, system =
            match bindAt a 0us system with
            | SocketAddress.Inet endpoint, system -> endpoint.Port, system
            | other, _ -> failwith $"%A{other}"

        let system = connectTo a Ipv4Address.loopback p system
        let _, system = bindAt b l system
        let system = connectTo b Ipv4Address.loopback p system

        match
            UnixReadWrite.trySend (Callers.leader system) b UserBuffer.Mapped 1UL 0 system
            |> CallProgress.resumeWith (fun paused -> UnixReadWrite.trySendWithBytes (payload 1) paused)
        with
        | Error (SendRefusal.Delivery (DeliveryRefusal.ErrorTie _)) -> ()
        | other -> failwith $"expected the send to be refused, got %A{other}"

    /// `ms` milliseconds, in the kernel clock's nanoseconds.
    let private after (ms : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        UnixSystem.advanceClock (int64 ms * 1_000_000L) system

    /// 1 if `fd` has an error pending, which `SO_ERROR` takes, as X8 prints it.
    let private raised (fd : int) (system : UnixSystem<int, string>) : int * UnixSystem<int, string> =
        let error, system = soError fd system
        (if error <> 0 then 1 else 0), system

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``which datagrams to no one raise the error, as X1 to X8 measured`` (which : string) : unit =
        let platform = platformOf which

        // X1: two sends `gap` ms apart, the first's error taken 10 ms after
        // it, five times, 300 ms apart.
        for gap in [ 15 ; 50 ; 85 ; 95 ; 98 ; 100 ; 102 ; 110 ; 150 ; 500 ] do
            let mutable system = systemOf platform
            let mutable firsts = 0
            let mutable seconds = 0

            for _ in 1..5 do
                let s = after 300 system
                let port, s = unheldPort s
                let c, s = senderTo port s
                let _, s = send c UserBuffer.Mapped 1 s
                let first, s = raised c (after 10 s)
                let _, s = send c UserBuffer.Mapped 1 (after (gap - 10) s)
                let second, s = raised c (after 30 s)
                firsts <- firsts + first
                seconds <- seconds + second
                system <- close c s

            $"the first raised one in %d{firsts} of 5, the second in %d{seconds} of 5"
            |> shouldEqual (row platform $"X1 a send raising an error, taken, and another %d{gap} ms after the first: ")

        // X4: sends every 40 ms, each error read 15 ms after.
        let system = systemOf platform
        let port, system = unheldPort system
        let c, system = senderTo port system

        let errors, _ =
            ((system, []), [ 1..12 ])
            ||> List.fold (fun (system, errors) _ ->
                let _, system = send c UserBuffer.Mapped 1 system
                let error, system = soError c (after 15 system)
                after 25 system, error :: errors
            )
            |> fun (system, errors) -> List.rev errors, system

        errors
        |> List.map (sprintf " %d")
        |> String.concat ""
        |> shouldEqual (row platform "X4 sends every 40 ms, SO_ERROR 15 ms after each:")

        // X5 and X2: two sockets, sending 5 ms apart, to one unheld port or
        // to one each.
        for label, shared in
            [
                "X5 two sockets connected to one unheld port, sending 5 ms apart: ", true
                "X2 two sockets, each connected to its own unheld port, sending 5 ms apart: ", false
            ] do
            let system = systemOf platform
            let p, system = unheldPort system
            let q, system = if shared then p, system else unheldPort system
            let c, system = senderTo p system
            let d, system = senderTo q system
            let _, system = send c UserBuffer.Mapped 1 system
            let _, system = send d UserBuffer.Mapped 1 (after 5 system)
            let ec, system = soError c (after 50 system)
            let ed, _ = soError d system

            $"SO_ERROR %d{ec} and %d{ed}" |> shouldEqual (row platform label)

        // X6: socket c, bound to L and connected to P, sends and has its
        // error taken 10 ms later; then the row's change, and its second
        // send 20 ms after the first.
        let rows
            : (string * (int -> uint16 -> uint16 -> uint16 -> UnixSystem<int, string> -> int * UnixSystem<int, string>)) list =
            [
                "c sends again (control)", (fun c _ _ _ system -> c, system)
                "c reconnects to another unheld port Q and sends",
                (fun c _ _ q system -> c, connectTo c Ipv4Address.loopback q system)
                "c reconnects to Q, then back to P, and sends",
                (fun c _ p q system ->
                    c,
                    system
                    |> connectTo c Ipv4Address.loopback q
                    |> connectTo c Ipv4Address.loopback p
                )
                "c closes; a new socket bound to L connects to P and sends",
                (fun c l p _ system ->
                    let system = close c system

                    let s, system =
                        NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

                    let system = ReuseAddress.set true s system

                    let system =
                        match
                            CopyIn.bind
                                s
                                UserBuffer.Mapped
                                16u
                                (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback l))
                                system
                        with
                        | Ok (BindAnswer.Bound _, system) -> system
                        | other -> failwith $"bind: %A{other}"

                    s, connectTo s Ipv4Address.loopback p system
                )
                "a new socket bound elsewhere connects to P and sends", (fun _ _ p _ system -> senderTo p system)
                "c disconnects (AF_UNSPEC), rebinds to L, reconnects to P and sends",
                (fun c l p _ system ->
                    let _, system = connectShown c UserBuffer.Mapped 16u (family platform 0 0us) system

                    // Darwin's disconnect leaves c bound, so its bind
                    // answers EINVAL; Linux's leaves it half-bound, and it
                    // binds.
                    let system =
                        match
                            CopyIn.bind
                                c
                                UserBuffer.Mapped
                                16u
                                (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback l))
                                system
                        with
                        | Ok (_, system) -> system
                        | Error refusal -> failwith $"bind refused: %A{refusal}"

                    c, connectTo c Ipv4Address.loopback p system
                )
            ]

        for label, change in rows do
            let system = systemOf platform
            let c, l, system = bound system
            let p, system = unheldPort system
            let q, system = unheldPort system
            let system = connectTo c Ipv4Address.loopback p system
            let _, system = send c UserBuffer.Mapped 1 system
            let first, system = soError c (after 10 system)
            let s2, system = change c l p q system
            let a2, system = send s2 UserBuffer.Mapped 1 (after 10 system)
            let second, system = soError s2 (after 30 system)
            let socket = (selfShown s2 system).Substring "self ".Length

            $"the first raised %d{first}; the second send %s{a2}, then SO_ERROR %d{second}; the socket is %s{socket}"
            |> portless
            |> shouldEqual (portless (row platform $"X6 %s{label}: "))

        // X8: up to three sockets, each connected to its own one of P, Q and
        // R, nobody holding any; each step a send, and the sender's error
        // read 8 ms later.
        for name, destinations, steps in
            [
                "A>P A>P A>P", [ 0 ], [ 0 ; 0 ; 0 ]
                "A>P B>P A>P", [ 0 ; 0 ], [ 0 ; 1 ; 0 ]
                "A>P B>Q A>P", [ 0 ; 1 ], [ 0 ; 1 ; 0 ]
                "A>P A>P B>P A>P", [ 0 ; 0 ], [ 0 ; 0 ; 1 ; 0 ]
                "A>P B>Q C>R A>P", [ 0 ; 1 ; 2 ], [ 0 ; 1 ; 2 ; 0 ]
                "A>P B>Q A>P B>Q", [ 0 ; 1 ], [ 0 ; 1 ; 0 ; 1 ]
            ] do
            let system = systemOf platform

            let ports, system =
                ((system, []), [ 1..3 ])
                ||> List.fold (fun (system, ports) _ ->
                    let port, system = unheldPort system
                    system, port :: ports
                )
                |> fun (system, ports) -> List.rev ports, system

            let sockets, system =
                ((system, []), destinations)
                ||> List.fold (fun (system, sockets) destination ->
                    let fd, system = senderTo ports.[destination] system
                    system, fd :: sockets
                )
                |> fun (system, sockets) -> List.rev sockets, system

            let shown, _ =
                ((system, []), steps)
                ||> List.fold (fun (system, shown) who ->
                    let _, system = send sockets.[who] UserBuffer.Mapped 1 system
                    let flag, system = raised sockets.[who] (after 8 system)
                    system, $" %c{char (int 'A' + who)}%d{flag}" :: shown
                )
                |> fun (system, shown) -> String.concat "" (List.rev shown), system

            shown |> shouldEqual (row platform $"X8 %s{name}:")

        // X3: 80 sockets, each connected to its own unheld port, sending at
        // once.
        let system = systemOf platform

        let system, sockets =
            ((system, []), [ 1..80 ])
            ||> List.fold (fun (system, sockets) _ ->
                let port, system = unheldPort system
                let fd, system = senderTo port system
                system, fd :: sockets
            )

        let system =
            (system, sockets)
            ||> List.fold (fun system fd -> send fd UserBuffer.Mapped 1 system |> snd)

        let errors, _ =
            ((0, after 100 system), sockets)
            ||> List.fold (fun (errors, system) fd ->
                let flag, system = raised fd system
                errors + flag, system
            )

        $"%d{errors} errors"
        |> shouldEqual (row platform "X3 80 sockets, each connected to an unheld port, sending at once: ")

    [<Test>]
    let ``Darwin answers a datagram to no one unless the last it answered had its four-tuple and came within the window``
        ()
        : unit
        =
        // A reference that keeps every datagram the machine answered: one is
        // answered unless the latest answered before it is on its four-tuple
        // and less than 100 ms before it.
        let window = 100_000_000L

        let reference (history : ((Ipv4Endpoint * Ipv4Endpoint) * int64) list) : bool list =
            ((([] : ((Ipv4Endpoint * Ipv4Endpoint) * int64) list), []), history)
            ||> List.fold (fun (answered, verdicts) (tuple, at) ->
                let suppressed =
                    match answered with
                    | (last, lastAt) :: _ -> last = tuple && at - lastAt < window
                    | [] -> false

                if suppressed then
                    answered, false :: verdicts
                else
                    (tuple, at) :: answered, true :: verdicts
            )
            |> snd
            |> List.rev

        let endpoint (port : int) =
            Ipv4Endpoint.ofParts Ipv4Address.loopback (uint16 (40000 + port))

        // Each step: a source and destination among three each, and how
        // long after the last step it comes, in ms, often near 100.
        let step =
            Gen.zip3 (Gen.choose (0, 2)) (Gen.choose (0, 2)) (Gen.oneof [ Gen.choose (0, 250) ; Gen.choose (95, 105) ])

        let property (steps : (int * int * int) list) : bool =
            let history =
                (0L, steps)
                ||> List.mapFold (fun now (source, destination, gap) ->
                    let now = now + int64 gap * 1_000_000L
                    ((endpoint source, endpoint (3 + destination)), now), now
                )
                |> fst

            let model =
                (PortUnreachableReplies.defaultFor SimulatedUnixFlavour.Darwin, history)
                ||> List.mapFold (fun replies ((source, destination), at) ->
                    PortUnreachableReplies.answer at source destination replies
                )
                |> fst

            model = reference history

        Check.One (Config.QuickThrowOnFailure.WithMaxTest 500, Prop.forAll (Arb.fromGen (Gen.listOf step)) property)
