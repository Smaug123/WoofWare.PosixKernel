namespace WoofWare.PosixKernel.Test

open System
open System.Collections.Immutable
open NUnit.Framework
open WoofWare.PosixKernel

/// Finding the socket a datagram reaches (`DatagramDelivery.receiverOf`)
/// reads only the UDP sockets bound at its destination port, so it costs the
/// same however many sockets are bound elsewhere on the machine. Measured by
/// the bytes it allocates, which unlike time do not move with the host's
/// load.
[<TestFixture>]
[<Parallelizable(ParallelScope.All)>]
module TestDatagramDeliveryCost =

    let private platformOf (which : string) : SimulatedUnixPlatform =
        match which with
        | "linux" -> SimulatedUnixPlatform.linuxX64
        | "darwin" -> SimulatedUnixPlatform.macOsArm64
        | other -> failwith $"unknown platform %s{other}"

    /// A UDP socket bound to the loopback address at a port bind(2) chooses,
    /// and that port.
    let private bound (system : UnixSystem<int, string>) : int * uint16 * UnixSystem<int, string> =
        let fd, system =
            NewSocket.create SocketDomain.Inet SocketKind.Datagram SocketProtocol.Udp system

        let platform = UnixSystem.platform system

        let system =
            match
                CopyIn.bind
                    fd
                    UserBuffer.Mapped
                    16u
                    (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback 0us))
                    system
            with
            | Ok (BindAnswer.Bound _, system) -> system
            | other -> failwith $"bind: %A{other}"

        let port =
            match FileDescriptorRegistry.tryFindTarget fd (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) ->
                match (UnixMachineState.socket socketId (Kernel.machine system)).Ipv4Binding with
                | Some binding -> binding.Endpoint.Port
                | None -> failwith "the bound socket has no binding"
            | other -> failwith $"fd %d{fd} is %A{other}"

        fd, port, system

    let private connectTo (fd : int) (port : uint16) (system : UnixSystem<int, string>) : UnixSystem<int, string> =
        let platform = UnixSystem.platform system

        match
            CopyIn.connect
                fd
                UserBuffer.Mapped
                16u
                (CopyIn.inet platform (Ipv4Endpoint.ofParts Ipv4Address.loopback port))
                system
        with
        | Ok (SyscallAnswer.Completed 0L, system) -> system
        | other -> failwith $"connect: %A{other}"

    /// A system of `platform` with `others` UDP sockets bound at ports of
    /// their own, and a pair connected to each other; and the descriptor of
    /// one of the pair.
    let private crowded (platform : SimulatedUnixPlatform) (others : int) : int * UnixSystem<int, string> =
        let system =
            UnixSystem.initial<int, string> platform
            |> Launched.boot UnixSystem.pipedStandardStreams 0 (CpuId 0)

        let system =
            (system, [ 1..others ])
            ||> List.fold (fun system _ ->
                let _, _, system = bound system
                system
            )

        let sender, senderPort, system = bound system
        let receiver, receiverPort, system = bound system
        let system = connectTo sender receiverPort system |> connectTo receiver senderPort
        sender, system

    /// The fewest bytes of several that finding the receiver of a datagram
    /// from `sender` to its peer allocates.
    let private receiverBytes (sender : int) (system : UnixSystem<int, string>) : int64 =
        let machine = Kernel.machine system

        let socket =
            match FileDescriptorRegistry.tryFindTarget sender (Lone.fileDescriptors system) with
            | Some (OpenFileTarget.Socket socketId) -> UnixMachineState.socket socketId machine
            | other -> failwith $"fd %d{sender} is %A{other}"

        let from, peer =
            match socket.Ipv4Binding, socket.Phase with
            | Some binding, SocketPhase.DatagramPeer (SocketAddress.Inet peer) ->
                DatagramDelivery.source binding.Endpoint, peer
            | binding, phase -> failwith $"the sender is bound at %A{binding} and in %A{phase}"

        let once () : int64 =
            let before = GC.GetAllocatedBytesForCurrentThread ()

            match DatagramDelivery.receiverOf machine from peer with
            | Ok (Some _) -> ()
            | other -> failwith $"expected the peer to receive the datagram: %A{other}"

            GC.GetAllocatedBytesForCurrentThread () - before

        once () |> ignore
        List.init 5 (fun _ -> once ()) |> List.min

    [<TestCase "linux">]
    [<TestCase "darwin">]
    let ``finding a datagram's receiver beside four times the bound UDP sockets allocates about as much``
        (which : string)
        : unit
        =
        let platform = platformOf which
        // 200 sockets beside the standard streams stay under the 256
        // descriptors a Darwin process may have.
        let fewer = crowded platform 50 ||> receiverBytes
        let more = crowded platform 200 ||> receiverBytes

        // Asking every socket on the machine allocates about four times as
        // much beside four times the sockets.
        let ratio = float more / float fewer

        if ratio > 1.5 then
            failwith
                $"%d{fewer} bytes finding the receiver beside 50 bound UDP sockets, and %d{more} beside 200: %.2f{ratio} times as much"
