namespace WoofWare.PosixKernel

/// Which call reads from a TCP connection.
[<RequireQualifiedAccess>]
type TcpReceiveCall =
    /// `read(2)`.
    | Read
    /// `recv(2)` without `MSG_PEEK`.
    | Receive
    /// `recv(2)` with `MSG_PEEK`: the bytes stay queued.
    | Peek
