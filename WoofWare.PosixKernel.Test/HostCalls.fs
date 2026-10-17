namespace WoofWare.PosixKernel.Test

open System.Runtime.InteropServices

/// Calls into the kernel running the suite, for the tests that measure it, each
/// declared once. A test that needs a call declared another way (another
/// signature, or `errno` where this one does not capture it) declares its own.
///
/// A `DllImport` binds on its first call, so a declaration of a call this host
/// lacks (epoll and inotify on Darwin, kqueue on Linux) costs nothing until a
/// test makes it.
[<RequireQualifiedAccess>]
module internal HostCalls =

    /// `uname(2)` into `buffer`, which must hold this host's `struct utsname`.
    [<DllImport("libc", EntryPoint = "uname", SetLastError = true)>]
    extern int uname(byte[] buffer)

    /// `geteuid(2)`.
    [<DllImport("libc", EntryPoint = "geteuid")>]
    extern uint32 getEUid()

    /// `getegid(2)`.
    [<DllImport("libc", EntryPoint = "getegid")>]
    extern uint32 getEGid()

    /// `close(2)`.
    [<DllImport("libc", EntryPoint = "close", SetLastError = true)>]
    extern int close(int fd)

    /// `dup(2)`.
    [<DllImport("libc", EntryPoint = "dup", SetLastError = true)>]
    extern int dup(int fd)

    /// `fcntl(2)`, with its third argument passed as a fixed one. `fcntl` is
    /// variadic, and Apple's arm64 ABI passes a variadic argument on the stack,
    /// where this one is not: there, only a command that ignores its argument
    /// (`F_GETFL`, `F_GETFD`) answers as it would from C.
    [<DllImport("libc", EntryPoint = "fcntl", SetLastError = true)>]
    extern int fcntl(int fd, int command, int argument)

    /// `lseek(2)`.
    [<DllImport("libc", EntryPoint = "lseek", SetLastError = true)>]
    extern int64 lseek(int fd, int64 offset, int whence)

    /// `ftruncate(2)`.
    [<DllImport("libc", EntryPoint = "ftruncate", SetLastError = true)>]
    extern int ftruncate(int fd, int64 length)

    /// `fstat(2)` into `buffer`, which must hold this host's `struct stat`.
    [<DllImport("libc", EntryPoint = "fstat", SetLastError = true)>]
    extern int fstat(int fd, byte[] buffer)

    /// `pipe(2)`, into `fds`, which must hold two.
    [<DllImport("libc", EntryPoint = "pipe", SetLastError = true)>]
    extern int pipe(int[] fds)

    /// `read(2)` of at most `count` bytes into `buffer`.
    [<DllImport("libc", EntryPoint = "read", SetLastError = true)>]
    extern nativeint read(int fd, byte[] buffer, unativeint count)

    /// `read(2)` of at most `count` bytes to the address `buffer`, which may be
    /// one the process has not mapped.
    [<DllImport("libc", EntryPoint = "read", SetLastError = true)>]
    extern nativeint readPointer(int fd, nativeint buffer, unativeint count)

    /// `write(2)` of `buffer`'s first `count` bytes.
    [<DllImport("libc", EntryPoint = "write", SetLastError = true)>]
    extern nativeint write(int fd, byte[] buffer, unativeint count)

    /// `write(2)` of `count` bytes from the address `buffer`, which may be one
    /// the process has not mapped.
    [<DllImport("libc", EntryPoint = "write", SetLastError = true)>]
    extern nativeint writePointer(int fd, nativeint buffer, unativeint count)

    /// `open(2)` of the path `path` names. `mode` is variadic in C, and Apple's
    /// arm64 ABI passes a variadic argument on the stack, where this one is
    /// not: there, the mode of a file this creates is not `mode`. `path` and
    /// `flags` are fixed arguments, so whether the call creates, opens or fails
    /// is the host's own answer.
    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int openFile(string path, int flags, int mode)

    /// `open` of the NUL-terminated path in `path`, as `openFile` is of a
    /// string.
    [<DllImport("libc", EntryPoint = "open", SetLastError = true)>]
    extern int openFileBytes(byte[] path, int flags, int mode)

    /// `mkdir(2)`.
    [<DllImport("libc", EntryPoint = "mkdir", SetLastError = true)>]
    extern int mkdir(string path, uint32 mode)

    /// `mkdir(2)` of the NUL-terminated path in `path`.
    [<DllImport("libc", EntryPoint = "mkdir", SetLastError = true)>]
    extern int mkdirBytes(byte[] path, uint32 mode)

    /// `rename(2)`.
    [<DllImport("libc", EntryPoint = "rename", SetLastError = true)>]
    extern int rename(string source, string destination)

    /// `rename(2)` of the NUL-terminated paths in `source` and `destination`.
    [<DllImport("libc", EntryPoint = "rename", SetLastError = true)>]
    extern int renameBytes(byte[] source, byte[] destination)

    /// `rmdir(2)`.
    [<DllImport("libc", EntryPoint = "rmdir", SetLastError = true)>]
    extern int rmdir(string path)

    /// `rmdir(2)` of the NUL-terminated path in `path`.
    [<DllImport("libc", EntryPoint = "rmdir", SetLastError = true)>]
    extern int rmdirBytes(byte[] path)

    /// `unlink(2)`.
    [<DllImport("libc", EntryPoint = "unlink", SetLastError = true)>]
    extern int unlink(string path)

    /// `unlink(2)` of the NUL-terminated path in `path`.
    [<DllImport("libc", EntryPoint = "unlink", SetLastError = true)>]
    extern int unlinkBytes(byte[] path)

    /// `mmap(2)`.
    [<DllImport("libc", EntryPoint = "mmap", SetLastError = true)>]
    extern nativeint mmap(nativeint address, unativeint length, int protection, int flags, int fd, int64 offset)

    /// `socket(2)`.
    [<DllImport("libc", EntryPoint = "socket", SetLastError = true)>]
    extern int socket(int domain, int kind, int protocol)

    /// `bind(2)` to the sockaddr in `address`'s first `length` bytes.
    [<DllImport("libc", EntryPoint = "bind", SetLastError = true)>]
    extern int bind(int fd, byte[] address, uint32 length)

    /// `listen(2)`.
    [<DllImport("libc", EntryPoint = "listen", SetLastError = true)>]
    extern int listen(int fd, int backlog)

    /// `connect(2)` to the sockaddr in `address`'s first `length` bytes.
    [<DllImport("libc", EntryPoint = "connect", SetLastError = true)>]
    extern int connect(int fd, byte[] address, uint32 length)

    /// `accept(2)`, writing the peer's address to `address` and its length
    /// to `length`, either of which may be 0 for none.
    [<DllImport("libc", EntryPoint = "accept", SetLastError = true)>]
    extern int accept(int fd, nativeint address, nativeint length)

    /// `getsockname(2)` into `address`, whose length `length` gives on the
    /// way in and the kernel sets on the way out.
    [<DllImport("libc", EntryPoint = "getsockname", SetLastError = true)>]
    extern int getSockName(int fd, byte[] address, uint32& length)

    /// `setsockopt(2)` of `value`'s first `length` bytes.
    [<DllImport("libc", EntryPoint = "setsockopt", SetLastError = true)>]
    extern int setSockOpt(int fd, int level, int optionName, byte[] value, uint32 length)

    /// `getsockopt(2)` of an option that is an `int`.
    [<DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)>]
    extern int getSockOptInt(int fd, int level, int optionName, int& value, uint32& length)

    /// `getsockopt(2)` into `value`, whose length `length` gives on the way in
    /// and the kernel sets on the way out.
    [<DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)>]
    extern int getSockOptBytes(int fd, int level, int optionName, byte[] value, uint32& length)

    /// `getsockopt(2)` with the value and the length cell at raw addresses,
    /// either of which may be one the process has not mapped.
    [<DllImport("libc", EntryPoint = "getsockopt", SetLastError = true)>]
    extern int getSockOptPointer(int fd, int level, int optionName, nativeint value, nativeint length)

    /// One `struct pollfd`, as `poll` takes it.
    [<Struct ; StructLayout(LayoutKind.Sequential)>]
    type PollFd =
        val mutable Fd : int
        val mutable Events : int16
        val mutable Revents : int16

    /// `poll(2)` of `fds`' first `count` entries.
    [<DllImport("libc", EntryPoint = "poll", SetLastError = true)>]
    extern int poll([<In ; Out>] PollFd[] fds, unativeint count, int timeout)

    /// `poll(2)` of `fds`' first `count` entries, each a `struct pollfd` read
    /// as a little-endian word: the descriptor in bits 0 to 31, the events
    /// asked for in bits 32 to 47, and those reported in bits 48 to 63.
    [<DllImport("libc", EntryPoint = "poll", SetLastError = true)>]
    extern int pollPacked(int64[] fds, unativeint count, int timeoutMs)

    /// `epoll_create1(2)`, Linux's.
    [<DllImport("libc", EntryPoint = "epoll_create1", SetLastError = true)>]
    extern int epollCreate1(int flags)

    /// `epoll_ctl(2)`, Linux's, with `event` this host's `struct epoll_event`.
    [<DllImport("libc", EntryPoint = "epoll_ctl", SetLastError = true)>]
    extern int epollCtl(int epfd, int op, int fd, byte[] event)

    /// `kqueue(2)`, Darwin's.
    [<DllImport("libc", EntryPoint = "kqueue", SetLastError = true)>]
    extern int kqueue()

    /// `inotify_init1(2)`, Linux's.
    [<DllImport("libc", EntryPoint = "inotify_init1", SetLastError = true)>]
    extern int inotifyInit1(int flags)

    /// `inotify_add_watch(2)`, Linux's, of the NUL-terminated path in `path`.
    [<DllImport("libc", EntryPoint = "inotify_add_watch", SetLastError = true)>]
    extern int inotifyAddWatch(int fd, byte[] path, uint32 mask)

    /// `inotify_rm_watch(2)`, Linux's.
    [<DllImport("libc", EntryPoint = "inotify_rm_watch", SetLastError = true)>]
    extern int inotifyRmWatch(int fd, int wd)

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
