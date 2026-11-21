namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `getsockname(2)` and `getpeername(2)` as a client makes them, through the
/// library's public protocol: the call, and if it stops at the read of the
/// length cell, the call given what the cell holds.
[<RequireQualifiedAccess>]
module internal SockNameCalls =

    /// Fails the test unless the length cell at `length` is one a client can
    /// read, as it must be wherever a call stops for the client to read it.
    let private readable (call : string) (length : UserBuffer) : unit =
        match length with
        | UserBuffer.Mapped -> ()
        | UserBuffer.Unmapped _
        | UserBuffer.Opaque
        | UserBuffer.Addressless ->
            failwith $"%s{call} stopped for the client to read a length cell at %A{length}, which no client can read"

    /// `getsockname(2)` as `caller` makes it, into the address buffer
    /// `destination`, through the length cell at `length`, which holds `cell`
    /// wherever the kernel reads it.
    let getsockname<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (length : UserBuffer)
        (cell : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetSockNameAnswer, GetSockNameRefusal>
        =
        UnixSocket.tryGetsockname caller fd destination length system
        |> CallProgress.resumeWith (fun paused ->
            readable "getsockname" length
            UnixSocket.tryGetsocknameWithLength cell paused
        )

    /// `getpeername(2)` as `caller` makes it, as `getsockname` is.
    let getpeername<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (fd : int)
        (destination : UserBuffer)
        (length : UserBuffer)
        (cell : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetSockNameAnswer, GetSockNameRefusal>
        =
        UnixSocket.tryGetpeername caller fd destination length system
        |> CallProgress.resumeWith (fun paused ->
            readable "getpeername" length
            UnixSocket.tryGetpeernameWithLength cell paused
        )
