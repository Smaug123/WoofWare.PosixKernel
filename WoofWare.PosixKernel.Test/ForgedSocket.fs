namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// Forging a socket into a machine as `socket(2)` would have made it, for a
/// test that builds its sockets by hand: a UDP socket comes with its receive
/// side, which `UnixSystem.checkInvariants` requires and every UDP call reads.
[<RequireQualifiedAccess>]
module internal ForgedSocket =

    /// `machine`'s receive sides, with a fresh one for `socket` under
    /// `socketId` if it is a UDP socket.
    let receivers
        (socketId : SocketId)
        (socket : SocketDescription)
        (machine : UnixMachineState)
        : Map<SocketId, DatagramReceiver>
        =
        if UnixMachineState.receivesDatagrams socket then
            Map.add
                socketId
                (DatagramReceiver.create
                    (SimulatedUnixPlatform.datagramReceiveRules machine.UnixPlatform)
                    machine.UdpReceiveSpace)
                machine.DatagramReceivers
        else
            machine.DatagramReceivers
