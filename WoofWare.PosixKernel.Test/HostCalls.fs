namespace WoofWare.PosixKernel.Test

open System.Runtime.InteropServices

/// Calls into the kernel running the suite, for the tests that measure it, each
/// declared once. A test that needs a call declared another way (another
/// signature, or `errno` where this one does not capture it) declares its own.
[<RequireQualifiedAccess>]
module internal HostCalls =

    /// `uname(2)` into `buffer`, which must hold this host's `struct utsname`.
    [<DllImport("libc", EntryPoint = "uname", SetLastError = true)>]
    extern int uname(byte[] buffer)

    /// `socket(2)`.
    [<DllImport("libc", EntryPoint = "socket", SetLastError = true)>]
    extern int socket(int domain, int kind, int protocol)

    /// `pipe(2)`, into `fds`, which must hold two.
    [<DllImport("libc", EntryPoint = "pipe", SetLastError = true)>]
    extern int pipe(int[] fds)

    /// `read(2)` of at most `count` bytes into `buffer`.
    [<DllImport("libc", EntryPoint = "read", SetLastError = true)>]
    extern nativeint read(int fd, byte[] buffer, unativeint count)

    /// `write(2)` of `buffer`'s first `count` bytes.
    [<DllImport("libc", EntryPoint = "write", SetLastError = true)>]
    extern nativeint write(int fd, byte[] buffer, unativeint count)

    /// `close(2)`, without capturing `errno`.
    [<DllImport("libc", EntryPoint = "close")>]
    extern int close(int fd)

    // `fcntl(2)` and `ioctl(2)` are variadic, which a P/Invoke cannot call
    // portably (Apple's arm64 ABI passes variadic arguments on the stack), so
    // these two go through .NET's own fixed-arity wrappers of them in its
    // `System.Native` library.

    /// Sets `O_NONBLOCK` on `fd`'s description where `isNonBlocking` is 1, and
    /// clears it where 0, answering 0 or -1, without capturing `errno`.
    [<DllImport("libSystem.Native", EntryPoint = "SystemNative_FcntlSetIsNonBlocking")>]
    extern int setNonBlocking(nativeint fd, int isNonBlocking)

    /// `ioctl(FIONREAD)`: how many bytes a read of `fd` could take, into
    /// `available`, answering 0 or -1, without capturing `errno`.
    [<DllImport("libSystem.Native", EntryPoint = "SystemNative_GetBytesAvailable")>]
    extern int bytesAvailable(nativeint fd, int& available)
