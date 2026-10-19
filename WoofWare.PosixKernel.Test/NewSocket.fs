namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `socket(2)` for a test that wants a socket of a known shape and has no
/// interest in how the request was numbered.
[<RequireQualifiedAccess>]
module NewSocket =

    /// The numbers `UnixSocket.socket` takes for this shape, in `platform`'s
    /// own numbering.
    let arguments
        (platform : SimulatedUnixPlatform)
        (domain : SocketDomain)
        (kind : SocketKind)
        (protocol : SocketProtocol)
        : int * int * int
        =
        let domain =
            match domain with
            | SocketDomain.Unix -> 1
            | SocketDomain.Inet -> SimulatedUnixPlatform.internetAddressFamily
            | SocketDomain.Inet6 -> SimulatedUnixPlatform.internetV6AddressFamily platform

        let kind =
            match kind with
            | SocketKind.Stream -> 1
            | SocketKind.Datagram -> 2
            | SocketKind.SeqPacket -> 5

        let protocol =
            match protocol with
            | SocketProtocol.Default -> 0
            | SocketProtocol.Tcp -> 6
            | SocketProtocol.Udp -> 17

        domain, kind, protocol

    /// Create a blocking socket of this shape, made by `caller`, failing the
    /// test if the kernel does not.
    let createAs<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (domain : SocketDomain)
        (kind : SocketKind)
        (protocol : SocketProtocol)
        (system : UnixSystem<'Thread, 'Handler>)
        : int * UnixSystem<'Thread, 'Handler>
        =
        let rawDomain, rawKind, rawProtocol =
            arguments (UnixSystem.platform system) domain kind protocol

        match UnixSocket.trySocket caller rawDomain rawKind rawProtocol system with
        | Ok (DescriptorAnswer.Returned fd, system) -> fd, system
        | Ok (DescriptorAnswer.Failed error, _) ->
            failwith $"NewSocket.create: socket(%d{rawDomain}, %d{rawKind}, %d{rawProtocol}) answered %O{error}"
        | Error refusal ->
            failwith
                $"NewSocket.create: socket(%d{rawDomain}, %d{rawKind}, %d{rawProtocol}) was refused: %s{SocketRefusal.describe refusal}"

    /// `createAs` the leader of the only process on the machine.
    let create<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (domain : SocketDomain)
        (kind : SocketKind)
        (protocol : SocketProtocol)
        (system : UnixSystem<'Thread, 'Handler>)
        : int * UnixSystem<'Thread, 'Handler>
        =
        createAs (Callers.leader system) domain kind protocol system

    /// Every shape `create` can ask for: each domain, kind and protocol. A
    /// socket this kernel makes is described by exactly these three, so the
    /// ones it makes for some request here are all the sockets it makes.
    let requests : (SocketDomain * SocketKind * SocketProtocol) list =
        [
            for domain in [ SocketDomain.Unix ; SocketDomain.Inet ; SocketDomain.Inet6 ] do
                for kind in [ SocketKind.Stream ; SocketKind.Datagram ; SocketKind.SeqPacket ] do
                    for protocol in [ SocketProtocol.Default ; SocketProtocol.Tcp ; SocketProtocol.Udp ] do
                        domain, kind, protocol
        ]

    /// `socket(2)` for this shape, or `None` when the kernel answers an errno
    /// or refuses.
    let tryCreate<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (domain : SocketDomain)
        (kind : SocketKind)
        (protocol : SocketProtocol)
        (system : UnixSystem<'Thread, 'Handler>)
        : (int * UnixSystem<'Thread, 'Handler>) option
        =
        let rawDomain, rawKind, rawProtocol =
            arguments (UnixSystem.platform system) domain kind protocol

        match UnixSocket.trySocket (Callers.leader system) rawDomain rawKind rawProtocol system with
        | Ok (DescriptorAnswer.Returned fd, system) -> Some (fd, system)
        | Ok (DescriptorAnswer.Failed _, _)
        | Error _ -> None
