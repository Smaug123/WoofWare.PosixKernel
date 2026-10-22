namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open System.Diagnostics
open System.Runtime.InteropServices
open System.Threading
open FsCheck
open FsCheck.FSharp
open NUnit.Framework
open WoofWare.PosixKernel

/// Random sequences of connects, sends, receives and `SO_ERROR` reads on UDP
/// sockets connected to ports nobody holds, made on the host the suite runs on
/// and in the kernel, which must answer each call as the host did: which
/// datagrams raise the ICMP error, and what each call does with it pending.
/// Linux's column is checked live on CI, and Darwin's live on a Mac and, on
/// every host, from the answers a Mac recorded.
///
/// Three senders, each bound to 127.0.0.1 at a port of its own choosing
/// (bound explicitly, so that a Linux `AF_UNSPEC` connect keeps it), start
/// connected to three ports nobody holds; a fourth socket holds a port a
/// sender can connect to instead, and never reads. A pause is 120 ms, past
/// Darwin's 100 ms window; between pauses at most four sends are made, which
/// the host makes well inside it.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramErrorAgainstHost =

    [<RequireQualifiedAccess>]
    type private Op =
        /// Sender `socket` (0 to 2) connects to `target`: one of the three
        /// ports nobody holds (0 to 2), or the held one (3).
        | Connect of socket : int * target : int
        /// Sender `socket` connects to `AF_UNSPEC`, which disconnects it.
        | Disconnect of socket : int
        /// Sender `socket` sends `length` bytes, by `write(2)` if `viaWrite`
        /// and by `send(2)` otherwise.
        | Send of socket : int * length : int * viaWrite : bool
        /// A non-blocking receive of `count` bytes on sender `socket`, by
        /// `read(2)` if `viaRead` and `recv(2)` otherwise.
        | Receive of socket : int * count : int * viaRead : bool
        /// `getsockopt(SO_ERROR)` on sender `socket`.
        | SoError of socket : int
        /// Linux `poll(2)` of every event on sender `socket`.
        | Poll of socket : int
        /// 120 ms pass.
        | Pause

    /// One call's answer: the return value and errno.
    type private Seen =
        {
            Returned : int64
            Errno : int
        }

    [<Literal>]
    let private pauseMilliseconds = 120

    let private dontWait (flavour : SimulatedUnixFlavour) : int =
        match flavour with
        | SimulatedUnixFlavour.Linux -> 0x40
        | SimulatedUnixFlavour.Darwin -> 0x80

    let private payload (length : int) : byte[] = Array.init length byte

    // ------------------------------------------------------------ the host

    let private check (what : string) (result : int) : unit =
        if result < 0 then
            failwith $"%s{what} failed with errno %d{Marshal.GetLastPInvokeError ()}"

    let private call (f : unit -> nativeint) : Seen =
        Marshal.SetLastPInvokeError 0
        let result = int64 (f ())

        {
            Returned = result
            Errno = if result < 0L then Marshal.GetLastPInvokeError () else 0
        }

    let private hostPort (fd : int) : uint16 =
        let name = Array.zeroCreate<byte> 16
        let mutable length = 16u
        check "getsockname" (HostCalls.getSockName (fd, name, &length))
        uint16 name.[2] <<< 8 ||| uint16 name.[3]

    let private hostSocket () : int =
        // AF_INET is 2, and SOCK_DGRAM 2, on both.
        let fd = HostCalls.socket (SimulatedUnixPlatform.internetAddressFamily, 2, 0)
        check "socket" fd
        fd

    let private hostBind (platform : SimulatedUnixPlatform) (fd : int) (port : uint16) : unit =
        let address =
            SimulatedUnixPlatform.encodeInternetSockaddr platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port)

        check "bind" (HostCalls.bind (fd, address, uint32 address.Length))

    /// A port the kernel picked for a socket that has since closed.
    let private hostFreePort (platform : SimulatedUnixPlatform) : uint16 =
        let fd = hostSocket ()
        hostBind platform fd 0us
        let port = hostPort fd
        check "close" (HostCalls.close fd)
        port

    /// The fixture's sockets: the three senders, then the holder; and the
    /// four ports a sender connects to.
    let private hostSockets (platform : SimulatedUnixPlatform) : int list * uint16 list =
        let senders =
            List.init
                3
                (fun _ ->
                    let port = hostFreePort platform
                    let fd = hostSocket ()
                    hostBind platform fd port

                    if HostCalls.setNonBlocking (nativeint fd, 1) <> 0 then
                        failwith $"could not make fd %d{fd} non-blocking"

                    fd
                )

        let holder = hostSocket ()
        hostBind platform holder 0us
        let unheld = List.init 3 (fun _ -> hostFreePort platform)
        let targets = unheld @ [ hostPort holder ]

        for sender, target in List.zip senders unheld do
            let destination =
                SimulatedUnixPlatform.encodeInternetSockaddr platform (Ipv4Endpoint.ofParts Ipv4Address.loopback target)

            check "connect" (HostCalls.connect (sender, destination, uint32 destination.Length))

        senders @ [ holder ], targets

    /// Whether `fd` reports POLLIN, which on Darwin a pending error makes it
    /// do: a sender never holds a datagram here.
    let private hostReadable (fd : int) : bool =
        let entry = [| int64 (uint32 fd) ||| (0x1L <<< 32) |]
        check "poll" (HostCalls.pollPacked (entry, 1un, 0))
        (entry.[0] >>> 48) &&& 0x1L <> 0L

    let private hostApply
        (platform : SimulatedUnixPlatform)
        (sockets : int list)
        (targets : uint16 list)
        (op : Op)
        : Seen
        =
        let flavour = SimulatedUnixPlatform.flavour platform

        match op with
        | Op.Connect (socket, target) ->
            let destination =
                SimulatedUnixPlatform.encodeInternetSockaddr
                    platform
                    (Ipv4Endpoint.ofParts Ipv4Address.loopback targets.[target])

            call (fun () -> nativeint (HostCalls.connect (sockets.[socket], destination, uint32 destination.Length)))
        | Op.Disconnect socket ->
            let unspec = CopyIn.blob platform 0 (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us)
            call (fun () -> nativeint (HostCalls.connect (sockets.[socket], unspec, 16u)))
        | Op.Send (socket, length, viaWrite) ->
            let fd = sockets.[socket]
            let bytes = payload length

            let seen =
                call (fun () ->
                    if viaWrite then
                        HostCalls.write (fd, bytes, unativeint length)
                    else
                        HostCalls.send (fd, bytes, unativeint length, 0)
                )

            // Darwin's error arrives a moment after the send returns: wait for
            // it, or for long enough that it is not coming.
            if flavour = SimulatedUnixFlavour.Darwin && seen.Returned >= 0L then
                let clock = Stopwatch.StartNew ()

                while not (hostReadable fd) && clock.ElapsedMilliseconds < 15L do
                    Thread.Sleep 1

            seen
        | Op.Receive (socket, count, viaRead) ->
            let fd = sockets.[socket]
            let buffer = Array.zeroCreate<byte> (max count 1)

            call (fun () ->
                if viaRead then
                    HostCalls.read (fd, buffer, unativeint count)
                else
                    HostCalls.recv (fd, buffer, unativeint count, dontWait flavour)
            )
        | Op.SoError socket ->
            // SOL_SOCKET and SO_ERROR: 1 and 4 on Linux, 0xffff and 0x1007 on
            // Darwin.
            let level, option =
                match flavour with
                | SimulatedUnixFlavour.Linux -> 1, 4
                | SimulatedUnixFlavour.Darwin -> 0xffff, 0x1007

            let mutable value = 0
            let mutable length = 4u
            check "SO_ERROR" (HostCalls.getSockOptInt (sockets.[socket], level, option, &value, &length))

            {
                Returned = int64 value
                Errno = 0
            }
        | Op.Poll socket ->
            // IN PRI OUT RDNORM RDBAND WRNORM WRBAND RDHUP
            let entry = [| int64 (uint32 sockets.[socket]) ||| (0x23c7L <<< 32) |]
            check "poll" (HostCalls.pollPacked (entry, 1un, 0))

            {
                Returned = int64 (uint16 (entry.[0] >>> 48))
                Errno = 0
            }
        | Op.Pause ->
            // Linux answers every datagram, however close together (X1), so
            // only Darwin's host need wait.
            if flavour = SimulatedUnixFlavour.Darwin then
                Thread.Sleep pauseMilliseconds

            {
                Returned = 0L
                Errno = 0
            }

    // ------------------------------------------------------------ the kernel

    let private kernelPort (fd : int) (system : UnixSystem<int, string>) : uint16 =
        match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
        | Some (OpenFileTarget.Socket socketId) ->
            match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
            | Some binding -> binding.Endpoint.Port
            | None -> failwith "a bound socket has no binding"
        | other -> failwith $"%A{other}"

    let private kernelBind (port : uint16) (fd : int) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let address =
            CopyIn.inet (UnixSystem.platform system) (Ipv4Endpoint.ofParts Ipv4Address.loopback port)

        match CopyIn.bind fd UserBuffer.Mapped 16u address system with
        | Ok (BindAnswer.Bound _, system) -> system
        | other -> failwith $"bind: %A{other}"

    let private kernelFreePort (system : UnixSystem<int, string>) : uint16 * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let system = kernelBind 0us fd system
        let port = kernelPort fd system

        match UnixDescriptor.tryClose (Callers.leader system) fd system with
        | Ok (SyscallAnswer.Completed 0L, system) -> port, system
        | other -> failwith $"close: %A{other}"

    /// The fixture's sockets and ports, as `hostSockets` makes them.
    let private kernelSockets (platform : SimulatedUnixPlatform) : int list * uint16 list * UnixSystem<int, string> =
        let mutable system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let senders =
            List.init
                3
                (fun _ ->
                    let port, after = kernelFreePort system

                    let fd, after =
                        NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp after

                    system <-
                        kernelBind port fd after
                        |> UnixDescriptor.setNonBlocking (Callers.leader after) fd true
                        |> snd

                    fd
                )

        let holder, after =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        system <- kernelBind 0us holder after

        let unheld =
            List.init
                3
                (fun _ ->
                    let port, after = kernelFreePort system
                    system <- after
                    port
                )

        let targets = unheld @ [ kernelPort holder system ]

        for sender, target in List.zip senders unheld do
            system <-
                match
                    CopyIn.connect
                        sender
                        UserBuffer.Mapped
                        16u
                        (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback target))
                        system
                with
                | Ok (SyscallAnswer.Completed 0L, after) -> after
                | other -> failwith $"connect: %A{other}"

        senders @ [ holder ], targets, system

    let private kernelApply
        (platform : SimulatedUnixPlatform)
        (sockets : int list)
        (targets : uint16 list)
        (op : Op)
        (system : UnixSystem<int, string>)
        : Seen * UnixSystem<int, string>
        =
        let errno (error : UnixError) : int =
            UnixError.toRawErrnoUnder (SimulatedUnixPlatform.rawErrnoNumbering platform) error

        let ofAnswer (answer : SyscallAnswer) : Seen =
            match answer with
            | SyscallAnswer.Completed value ->
                {
                    Returned = value
                    Errno = 0
                }
            | SyscallAnswer.Failed error ->
                {
                    Returned = -1L
                    Errno = errno error
                }

        let connect (fd : int) (blob : byte[]) (system : UnixSystem<int, string>) =
            match CopyIn.connect fd UserBuffer.Mapped 16u blob system with
            | Ok (answer, system) -> ofAnswer answer, system
            | Error refusal -> failwith $"connect refused: %s{ConnectRefusal.describe refusal}"

        match op with
        | Op.Connect (socket, target) ->
            connect
                sockets.[socket]
                (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback targets.[target]))
                system
        | Op.Disconnect socket ->
            connect sockets.[socket] (CopyIn.blob platform 0 (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us)) system
        | Op.Send (socket, length, viaWrite) ->
            let bytes = ImmutableArray.Create<byte> (payload length)

            let step =
                if viaWrite then
                    WriteOutcomes.admitThenWrite 0 sockets.[socket] UserBuffer.Mapped bytes system
                    |> Result.mapError (sprintf "%A")
                else
                    WriteOutcomes.admitThenSend 0 sockets.[socket] UserBuffer.Mapped bytes 0 system
                    |> Result.mapError (sprintf "%A")

            match step with
            | Ok (WriteStep.Returns (WriteAnswer.Completed written, system)) ->
                {
                    Returned = written
                    Errno = 0
                },
                system
            | Ok (WriteStep.Returns (WriteAnswer.Failed error, system)) ->
                {
                    Returned = -1L
                    Errno = errno error
                },
                system
            | other -> failwith $"send: %A{other}"
        | Op.Receive (socket, count, viaRead) ->
            let answer =
                if viaRead then
                    ReadOutcomes.read sockets.[socket] UserBuffer.Mapped (uint64 count) system
                    |> Result.map (fun (answer, system) -> answer, system)
                    |> Result.mapError (sprintf "%A")
                else
                    match
                        UnixReadWrite.tryRecv
                            (Callers.leader system)
                            sockets.[socket]
                            UserBuffer.Mapped
                            (uint64 count)
                            (dontWait (SimulatedUnixPlatform.flavour platform))
                            system
                    with
                    | Ok (ReadOutcome.Answered answer, system) -> Ok (answer, system)
                    | other -> Error $"%A{other}"

            match answer with
            | Ok (ReadAnswer.Completed bytes, system) ->
                {
                    Returned = int64 bytes.Length
                    Errno = 0
                },
                system
            | Ok (ReadAnswer.Failed error, system) ->
                {
                    Returned = -1L
                    Errno = errno error
                },
                system
            | other -> failwith $"receive: %A{other}"
        | Op.SoError socket ->
            match
                Lone.UnixSocket.tryGetsockoptLength
                    sockets.[socket]
                    (SimulatedUnixPlatform.socketOptionLevel platform)
                    (SimulatedUnixPlatform.socketErrorOption platform)
                    UserBuffer.Mapped
                    UserBuffer.Mapped
                    (Some 4u)
                    system
            with
            | Ok (answer, system) ->
                {
                    Returned = int64 (OptionValue.readInt answer)
                    Errno = 0
                },
                system
            | Error refusal -> failwith $"SO_ERROR refused: %s{SocketOptionRefusal.describe refusal}"
        | Op.Poll socket ->
            let entry : PollEntry =
                {
                    Fd = sockets.[socket]
                    Events = 0x23c7s
                }

            match UnixPoll.tryPoll (Callers.leader system) [ entry ] 0 system with
            | Ok (PollOutcome.Answered ([ revents ], _), system) ->
                {
                    Returned = int64 (uint16 revents)
                    Errno = 0
                },
                system
            | other -> failwith $"poll: %A{other}"
        | Op.Pause ->
            {
                Returned = 0L
                Errno = 0
            },
            UnixSystem.advanceClock (int64 pauseMilliseconds * 1_000_000L) system

    // ------------------------------------------------------------ the property

    let private isSend (op : Op) : bool =
        match op with
        | Op.Send _ -> true
        | _ -> false

    /// One to eight calls, at most four of them sends, then a pause.
    let private segment (flavour : SimulatedUnixFlavour) : Gen<Op list> =
        let socket = Gen.choose (0, 2)
        let bool = Gen.elements [ false ; true ]

        let op =
            Gen.frequency
                [
                    yield 3, Gen.map2 (fun socket target -> Op.Connect (socket, target)) socket (Gen.choose (0, 3))
                    yield 1, Gen.map Op.Disconnect socket
                    yield
                        6,
                        Gen.map3
                            (fun socket length viaWrite -> Op.Send (socket, length, viaWrite))
                            socket
                            (Gen.elements [ 0 ; 1 ; 5 ])
                            bool
                    yield
                        3,
                        Gen.map3
                            (fun socket count viaRead -> Op.Receive (socket, count, viaRead))
                            socket
                            (Gen.elements [ 0 ; 1 ; 8 ])
                            bool
                    yield 3, Gen.map Op.SoError socket
                    if flavour = SimulatedUnixFlavour.Linux then
                        yield 2, Gen.map Op.Poll socket
                ]

        Gen.nonEmptyListOf op
        |> Gen.map (fun ops ->
            let kept =
                (([], 0), List.truncate 8 ops)
                ||> List.fold (fun (kept, sends) op ->
                    match op with
                    | Op.Send _ when sends = 4 -> kept, sends
                    | Op.Send _ -> op :: kept, sends + 1
                    | _ -> op :: kept, sends
                )
                |> fst
                |> List.rev

            kept @ [ Op.Pause ]
        )

    // ------------------------------------------------------------ the corpus

    let private bit (value : bool) : string = if value then "1" else "0"

    let private writeOp (op : Op) : string =
        match op with
        | Op.Connect (socket, target) -> $"c:%d{socket}:%d{target}"
        | Op.Disconnect socket -> $"d:%d{socket}"
        | Op.Send (socket, length, viaWrite) -> $"s:%d{socket}:%d{length}:%s{bit viaWrite}"
        | Op.Receive (socket, count, viaRead) -> $"r:%d{socket}:%d{count}:%s{bit viaRead}"
        | Op.SoError socket -> $"e:%d{socket}"
        | Op.Poll socket -> $"p:%d{socket}"
        | Op.Pause -> "z"

    let private parseOp (text : string) : Op =
        let flag (field : string) : bool =
            match field with
            | "0" -> false
            | "1" -> true
            | _ -> failwith $"not a flag in a UDP error op: %s{text}"

        match text.Split ':' with
        | [| "c" ; socket ; target |] -> Op.Connect (int socket, int target)
        | [| "d" ; socket |] -> Op.Disconnect (int socket)
        | [| "s" ; socket ; length ; viaWrite |] -> Op.Send (int socket, int length, flag viaWrite)
        | [| "r" ; socket ; count ; viaRead |] -> Op.Receive (int socket, int count, flag viaRead)
        | [| "e" ; socket |] -> Op.SoError (int socket)
        | [| "p" ; socket |] -> Op.Poll (int socket)
        | [| "z" |] -> Op.Pause
        | _ -> failwith $"not a UDP error op: %s{text}"

    let private writeSeen (seen : Seen) : string = $"%d{seen.Returned}:%d{seen.Errno}"

    let private parseSeen (text : string) : Seen =
        match text.Split ':' with
        | [| returned ; errno |] ->
            {
                Returned = int64 returned
                Errno = int errno
            }
        | _ -> failwith $"not a UDP error answer: %s{text}"

    /// `items` written by `write` and separated by spaces, or `-` for none.
    let private joined (write : 'a -> string) (items : 'a list) : string =
        match items with
        | [] -> "-"
        | _ -> items |> List.map write |> String.concat " "

    let private split (parse : string -> 'a) (text : string) : 'a list =
        match text with
        | "-" -> []
        | _ -> text.Split ' ' |> Array.toList |> List.map parse

    /// Sequences of up to 40 calls, made on the host and in the kernel and
    /// compared answer by answer. A Mac's answers are recorded in
    /// `hostCorpus/udpError.darwin.txt`, which every host replays.
    let private errors : HostComparison<Op list, Seen list> =
        {
            Name = "udpError"
            Inputs =
                fun platform ->
                    Gen.listOf (segment (SimulatedUnixPlatform.flavour platform))
                    |> Gen.map (List.concat >> List.truncate 40)
            Count = 30
            WriteInput = joined writeOp
            ParseInput = split parseOp
            WriteAnswer = joined writeSeen
            ParseAnswer = split parseSeen
            Host =
                fun platform ops ->
                    let sockets, targets = hostSockets platform

                    try
                        ops |> List.map (hostApply platform sockets targets)
                    finally
                        for fd in sockets do
                            HostCalls.close fd |> ignore<int>
            Disagreement =
                fun platform ops answers ->
                    let sockets, targets, system = kernelSockets platform

                    let rec go (system : UnixSystem<int, string>) (calls : (int * Op * Seen) list) : string option =
                        match calls with
                        | [] -> None
                        | (index, op, expected) :: rest ->
                            let seen, system = kernelApply platform sockets targets op system

                            if seen <> expected then
                                Some
                                    $"op %d{index} (%s{writeOp op}): the model answered %s{writeSeen seen}, the kernel %s{writeSeen expected}"
                            else
                                match UnixSystem.checkInvariants system with
                                | [] -> go system rest
                                | violations -> Some $"op %d{index} (%s{writeOp op}) broke invariants: %A{violations}"

                    if answers.Length <> ops.Length then
                        Some $"%d{ops.Length} ops, but %d{answers.Length} answers"
                    else
                        go system (List.mapi2 (fun index op answer -> index, op, answer) ops answers)
                    |> Option.map (fun disagreement -> $"in [%s{joined writeOp ops}], %s{disagreement}")
        }

    [<Test>]
    let ``the kernel answers random sends to ports nobody holds as this host does`` () : unit =
        HostPlatform.onUnixHostKernel (HostCorpus.live errors)

    [<Test>]
    let ``the kernel answers random sends to ports nobody holds as Darwin did`` () : unit =
        HostCorpus.replay errors SimulatedUnixPlatform.macOsArm64

    [<Test>]
    let ``every random sequence of sends to ports nobody holds reads back as itself`` () : unit =
        for platform in [ SimulatedUnixPlatform.linuxX64 ; SimulatedUnixPlatform.macOsArm64 ] do
            HostCorpus.inputsRoundTrip errors platform
