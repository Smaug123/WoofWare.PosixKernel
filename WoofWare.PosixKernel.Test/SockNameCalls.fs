namespace WoofWare.PosixKernel.Test

open WoofWare.PosixKernel

/// `getsockname(2)` and `getpeername(2)` as a client makes them, through the
/// library's public protocol: the call, and if it stops at the read of the
/// length cell, the call given what the cell holds. Each is held to the
/// internal steps it is made of: the admission, then the call given the cell's
/// contents wherever the admission says the kernel reads them.
[<RequireQualifiedAccess>]
module internal SockNameCalls =

    /// `actual`, having failed unless it is what the oracle `expected` says.
    let private agreeing
        (call : string)
        (expected : Result<GetSockNameAnswer, GetSockNameRefusal>)
        (actual : Result<GetSockNameAnswer, GetSockNameRefusal>)
        : Result<GetSockNameAnswer, GetSockNameRefusal>
        =
        if actual <> expected then
            failwith $"%s{call} through the paused call answered %A{actual}, and made a step at a time, %A{expected}"

        actual

    /// What the admission `admitted` says the kernel reads of a length cell
    /// holding `cell`: all of it where the kernel reads the cell, and nothing
    /// otherwise.
    let private read (admitted : Result<SockNameAdmission, GetSockNameRefusal>) (cell : uint32) : uint32 option =
        match admitted with
        | Ok (SockNameAdmission.ReadLength _) -> Some cell
        | Ok (SockNameAdmission.Answered _)
        | Error _ -> None

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
        let view = Proc.view (Caller.processId caller) system

        let expected =
            UnixSocket.tryGetsocknameLength
                fd
                destination
                length
                (read (UnixSocket.tryAdmitGetSockName fd length view) cell)
                view

        let actual =
            UnixSocket.tryGetsockname caller fd destination length system
            |> CallProgress.resumeWith (fun paused ->
                readable "getsockname" length
                UnixSocket.tryGetsocknameWithLength cell paused
            )

        agreeing "getsockname" expected actual

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
        let view = Proc.view (Caller.processId caller) system

        let expected =
            UnixSocket.tryGetpeernameLength
                fd
                destination
                length
                (read (UnixSocket.tryAdmitGetPeerName fd length view) cell)
                view

        let actual =
            UnixSocket.tryGetpeername caller fd destination length system
            |> CallProgress.resumeWith (fun paused ->
                readable "getpeername" length
                UnixSocket.tryGetpeernameWithLength cell paused
            )

        agreeing "getpeername" expected actual
