namespace WoofWare.PosixKernel

/// <summary>
/// Describes which platform's errno convention the kernel is using.
/// </summary>
///
/// <remarks>
/// This exists because <c>&lt;errno.h&gt;</c> can be different on different platforms.
/// </remarks>
/// <remarks>
/// Interpreted by <c>SimulatedUnixPlatform.rawErrnoNumbering</c>.
/// </remarks>
[<RequireQualifiedAccess>]
type RawErrnoNumbering =
    /// <summary>
    /// <c>&lt;errno.h&gt;</c> is derived from Linux.
    /// </summary>
    | Linux
    /// <summary>
    /// <c>&lt;errno.h&gt;</c> is derived from Darwin.
    /// </summary>
    | Darwin

/// <summary>
/// How portable a given raw <c>&lt;errno.h&gt;</c> number is, across the modelled Unixes.
/// </summary>
///
/// <remarks>
/// Raw errno numbers are assigned per-platform, and Linux and Darwin agree
/// only on the range they both inherited from V7 Unix.
/// For example, the values 1-34 name the same error on both (except 11, which is <c>EAGAIN</c> on Linux and <c>EDEADLK</c> on Darwin),
/// but everything from 35 up was numbered independently (so e.g. 39 is <c>ENOTEMPTY</c> on Linux and <c>EDESTADDRREQ</c> on Darwin).
/// </remarks>
[<RequireQualifiedAccess>]
type RawErrnoPortability =
    /// <summary>
    /// This error has the same raw number on every Unix we model, so the
    /// emulated kernel can report it without first deciding which platform it is
    /// impersonating.
    /// </summary>
    | Portable of value : int
    /// <summary>
    /// This error's raw number is not consistent among the modelled Unixes,
    /// so it can't be interpreted as an int without knowing what platform is being
    /// simulated.
    /// </summary>
    /// <example>
    /// E.g. <c>ELOOP</c>: raw 40 is <c>ELOOP</c> on Linux but <c>EMSGSIZE</c> on Darwin, and
    /// raw 62 is <c>ELOOP</c> on Darwin but <c>ETIME</c> on Linux.
    /// </example>
    | PlatformDependent of linux : int * darwin : int
    /// <summary>This error exists only on Linux.</summary>
    /// <remarks>
    /// That is, Darwin's <c>&lt;errno.h&gt;</c> has no name for this error,
    /// so this number is either a different error on Darwin or completely unassigned.
    /// </remarks>
    /// <example>
    /// <c>ENOKEY</c>: Linux has <c>keyctl(2)</c> but Darwin does not, so Darwin doesn't have that error.
    /// </example>
    | LinuxOnly of linux : int
    /// <summary>This error exists only on Darwin.</summary>
    /// <remarks>
    /// That is, Linux's <c>&lt;errno.h&gt;</c> has no name for this error,
    /// so this number is either a different error on Linux or completely unassigned.
    /// </remarks>
    /// <example>
    /// <c>EAUTH</c> is a BSD-flavoured errno which Linux doesn't have but Darwin does.
    /// </example>
    | DarwinOnly of darwin : int

/// <summary>
/// The conventional errors a syscall can report.
/// </summary>
/// <remarks>
/// A process sees these errors as integers, which on a real host would come from <c>&lt;errno.h&gt;</c>.
/// However, those ints are not portable across the simulated platforms, so we also provide this separate
/// semantic layer.
/// Call <c>UnixError.toRawErrnoUnder</c> to get an integer out directly for a given platform, or
/// <c>UnixError.rawNumbering</c> if you don't yet know the platform.
///
/// There is a case for every error which appears in either of our flavours' <c>&lt;errno.h&gt;</c>, including
/// those only one of them has (such as Linux's <c>ENOKEY</c> or Darwin's <c>EAUTH</c>).
///
/// A second spelling of the same error, like <c>EWOULDBLOCK</c> for <c>EAGAIN</c>, has no case of its own.
/// </remarks>
[<RequireQualifiedAccess>]
type UnixError =
    /// <summary>
    /// Operation not permitted.
    /// </summary>
    | EPERM
    /// <summary>
    /// No such file or directory.
    /// </summary>
    | ENOENT
    /// <summary>
    /// No such process.
    /// </summary>
    | ESRCH
    /// <summary>
    /// Interrupted function.
    /// </summary>
    | EINTR
    /// <summary>
    /// I/O error.
    /// </summary>
    | EIO
    /// <summary>
    /// No such device or address.
    /// </summary>
    | ENXIO
    /// <summary>
    /// Argument list too long.
    /// </summary>
    | E2BIG
    /// <summary>
    /// Executable file format error.
    /// </summary>
    | ENOEXEC
    /// <summary>Bad file descriptor.</summary>
    /// <example>
    /// Returned by <c>dup</c>, <c>close</c>, <c>read</c>, <c>write</c>, etc. when the supplied
    /// file descriptor is not currently open.
    /// </example>
    | EBADF
    /// <summary>
    /// No child processes.
    /// </summary>
    | ECHILD
    /// <summary>
    /// Not enough space.
    /// </summary>
    | ENOMEM
    /// <summary>
    /// Permission denied.
    /// </summary>
    | EACCES
    /// <summary>
    /// Bad address.
    /// </summary>
    /// <example>
    /// Returned by <c>read(2)</c> / <c>write(2)</c> and friends when the buffer
    /// pointer is outside the process's accessible address space - most
    /// notably when the caller passes <c>NULL</c> (or any other
    /// non-dereferenceable bit pattern) with a non-zero <c>bufferSize</c>.
    /// The kernel performs no I/O for such a call.
    /// </example>
    | EFAULT
    /// <summary>
    /// Device or resource busy.
    /// </summary>
    | EBUSY
    /// <summary>
    /// File exists.
    /// </summary>
    | EEXIST
    /// <summary>
    /// Cross-device link.
    /// </summary>
    | EXDEV
    /// <summary>
    /// No such device.
    /// </summary>
    | ENODEV
    /// <summary>
    /// Not a directory or a symbolic link to a directory.
    /// </summary>
    | ENOTDIR
    /// <summary>
    /// Is a directory.
    /// </summary>
    | EISDIR
    /// <summary>
    /// Invalid argument.
    /// </summary>
    | EINVAL
    /// <summary>
    /// Too many files open in system.
    /// </summary>
    | ENFILE
    /// <summary>
    /// File descriptor value too large.
    /// </summary>
    | EMFILE
    /// <summary>Inappropriate I/O control operation.</summary>
    /// <example>
    /// Returned by <c>isatty(3)</c> when the supplied file descriptor is open but does not
    /// refer to a terminal.
    /// </example>
    | ENOTTY
    /// <summary>
    /// Text file busy.
    /// </summary>
    | ETXTBSY
    /// <summary>
    /// File too large.
    /// </summary>
    | EFBIG
    /// <summary>
    /// No space left on device.
    /// </summary>
    | ENOSPC
    /// <summary>
    /// Invalid seek.
    /// </summary>
    | ESPIPE
    /// <summary>
    /// Read-only file system.
    /// </summary>
    | EROFS
    /// <summary>
    /// Too many links.
    /// </summary>
    | EMLINK
    /// <summary>
    /// Broken pipe.
    /// </summary>
    | EPIPE
    /// <summary>
    /// Mathematics argument out of domain of function.
    /// </summary>
    | EDOM
    /// <summary>
    /// Result too large.
    /// </summary>
    | ERANGE
    /// <summary>
    /// Too many levels of symbolic links.
    /// </summary>
    /// <example>
    /// Reported when resolving a path would exceed the modelled Unix's limit
    /// on symlink traversals.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 40; Darwin numbers it 62.
    /// </remarks>
    | ELOOP
    /// <summary>
    /// Filename too long.
    /// </summary>
    /// <example>
    /// Reported for a pathname argument longer than the platform's <c>PATH_MAX</c>,
    /// and for any single component longer than its <c>NAME_MAX</c>. Both those limits,
    /// and the unit components are measured in, come from <c>PathLimits</c> and are
    /// filesystem-dependent.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 36; Darwin numbers it 63.
    /// </remarks>
    | ENAMETOOLONG
    /// <summary>
    /// Directory not empty.
    /// </summary>
    ///
    /// <example>
    /// Reported by <c>rmdir(2)</c> for a directory that still holds an entry,
    /// or for a path whose final component was ".." (see <c>RmDirRules</c>).
    /// </example>
    ///
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 39; Darwin numbers it 66.
    /// </remarks>
    | ENOTEMPTY
    /// <summary>
    /// Resource temporarily unavailable.
    /// </summary>
    /// <remarks>
    /// <c>EWOULDBLOCK</c> is the same value, on all platforms we model, so we
    /// don't supply a separate case for that.
    ///
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 11; Darwin numbers it 35.
    /// </remarks>
    | EAGAIN
    /// <summary>
    /// Value too large to be stored in data type.
    /// </summary>
    /// <example>
    /// <c>lseek</c> returns this on Darwin when the computed file offset does not
    /// fit in a signed 64-bit <c>off_t</c>. Linux returns <c>EINVAL</c> for the same
    /// input.
    /// (An offset which lands below zero is <c>EINVAL</c> on both.)
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 75; Darwin numbers it 84.
    /// </remarks>
    | EOVERFLOW
    /// <summary>
    /// Illegal byte sequence.
    /// </summary>
    /// <example>
    /// Darwin answers this instead of binding a filename that APFS will not hold: e.g. a creating <c>open</c>,
    /// <c>mkdir</c> or <c>rename</c> whose final name is not valid UTF-8. (Linux successfully binds such a name.)
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 84; Darwin numbers it 92.
    /// </remarks>
    | EILSEQ
    /// <summary>
    /// Address family not supported.
    /// </summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 97; Darwin numbers it 47.
    /// </remarks>
    | EAFNOSUPPORT
    /// <summary>
    /// Protocol wrong type for socket.
    /// </summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 91; Darwin numbers it 41.
    /// </remarks>
    | EPROTOTYPE
    /// <summary>
    /// Protocol not supported.
    /// </summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 93; Darwin numbers it 43.
    /// </remarks>
    | EPROTONOSUPPORT
    /// <summary>
    /// Socket type not supported.
    /// </summary>
    /// <example>
    /// Reported by Linux's <c>socket(2)</c> for a type the address family has no protocol for, such as
    /// <c>SOCK_RDM</c> under <c>AF_INET</c>.
    /// (Darwin answers <c>EPROTONOSUPPORT</c> or <c>EPROTOTYPE</c> there instead.)
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 94; Darwin numbers it 44.
    /// </remarks>
    | ESOCKTNOSUPPORT
    /// <summary>
    /// Address already in use.
    /// </summary>
    /// <example>
    /// Reported by <c>bind(2)</c> when another socket already holds a conflicting
    /// local address. (Whether two sockets "conflict" depends on both sockets' <c>SO_REUSEADDR</c>,
    /// on whether they're listening, and on the Unix flavour.)
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 98; Darwin numbers it 48.
    /// </remarks>
    | EADDRINUSE
    /// <summary>
    /// Cannot assign requested address.
    /// </summary>
    /// <example>
    /// Reported by <c>bind(2)</c> for an address this machine does not hold.
    ///
    /// What counts as "held" differs per Unix flavour, as follows:
    /// the machine is configured with two lists of addresses, <c>LocalIpv4Addresses</c> (which configures interfaces),
    /// and <c>LocalRoutes</c> (the routing table).
    /// Darwin reads only <c>LocalIpv4Addresses</c> when binding, while Linux will additionally
    /// bind any address inside a prefix in <c>LocalRoutes</c>.
    ///
    /// So with the defaults - holding <c>127.0.0.1</c>, routing <c>127.0.0.0/8</c> -
    /// <c>127.0.0.9</c> binds on Linux but is <c>EADDRNOTAVAIL</c> on Darwin.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 99; Darwin numbers it 49.
    /// </remarks>
    | EADDRNOTAVAIL
    /// <summary>
    /// Operation not supported on socket.
    /// </summary>
    /// <example>
    /// Reported by <c>listen(2)</c> on a socket whose type does not accept
    /// connections, such as a datagram socket.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// </remarks>
    | EOPNOTSUPP
    /// <summary>
    /// Socket operation on non-socket.
    /// </summary>
    /// <example>
    /// For example, <c>accept(2)</c>, <c>bind(2)</c>, <c>listen(2)</c>, and <c>getsockname(2)</c>
    /// when their input isn't a socket but instead is any of
    /// a regular file, an event queue, or either end of a pipe.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 88; Darwin numbers it 38.
    /// </remarks>
    | ENOTSOCK
    /// <summary>
    /// Socket is connected.
    /// </summary>
    /// <example>
    /// Reported by <c>connect(2)</c> when a connect is issued on:
    ///
    /// <list type="bullet">
    /// <item>a socket that is already connected</item>
    /// <item>a socket that is listening (on Linux)</item>
    /// <item>a socket which has already completed an asynchronous connect (on Darwin).</item>
    /// </list>
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 106; Darwin numbers it 56.
    /// </remarks>
    | EISCONN
    /// <summary>
    /// Operation now in progress.
    /// </summary>
    /// <example>
    /// Reported by <c>connect(2)</c> when a connect is issued on a non-blocking socket.
    /// (This is true regardless of whether the destination is already listening or has refused the connection,
    /// and is true on loopback too, on all modelled platforms.)
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 115; Darwin numbers it 36.
    /// </remarks>
    | EINPROGRESS
    /// <summary>
    /// Connection refused.
    /// </summary>
    /// <example>
    /// Reported by <c>connect(2)</c> on Linux when another idle stream socket is already bound to
    /// the destination port but is not listening. (Not on Darwin, though; there, the SYN is dropped
    /// and the connect pends towards <c>ETIMEDOUT</c> instead.)
    /// Delivered inline if the connect was blocking, or on the first retry if the connect was non-blocking.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 111; Darwin numbers it 61.
    /// </remarks>
    | ECONNREFUSED
    /// <summary>
    /// Not supported.
    /// </summary>
    /// <example>
    /// On Darwin, <c>flock</c> on a socket, a pipe, or a kqueue returns this error.
    /// </example>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 95; Darwin numbers it 45.
    /// </remarks>
    | ENOTSUP
    /// <summary>The socket is not connected.</summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 107; Darwin numbers it 57.
    /// </remarks>
    | ENOTCONN
    /// <summary>Connection timed out.</summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 110; Darwin numbers it 60.
    /// </remarks>
    | ETIMEDOUT
    /// <summary>Connection reset by peer.</summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 104; Darwin numbers it 54.
    /// </remarks>
    | ECONNRESET
    /// <summary>Message too long.</summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 90; Darwin numbers it 40.
    /// </remarks>
    | EMSGSIZE
    /// <summary>Function not implemented.</summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 38; Darwin numbers it 78.
    /// </remarks>
    | ENOSYS
    /// <summary>Resource deadlock would occur.</summary>
    /// <remarks>
    /// On Linux, <c>EDEADLOCK</c> is another name for this.
    ///
    /// This is the only errno in the range 1-34 which differs between Linux and Darwin
    /// (it was transposed with <c>EAGAIN</c>).
    ///
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 35; Darwin numbers it 11.
    /// </remarks>
    | EDEADLK
    /// <summary>No locks available.</summary>
    /// <remarks>
    /// This is one of the many errnos with an integer value that's not portable.
    /// Linux numbers it 37; Darwin numbers it 77.
    /// </remarks>
    | ENOLCK
    /// <summary>
    /// Block device required.
    /// </summary>
    | ENOTBLK
    /// <summary>
    /// No message of desired type.
    /// </summary>
    | ENOMSG
    /// <summary>
    /// Identifier removed.
    /// </summary>
    | EIDRM
    /// <summary>
    /// Device not a stream.
    /// </summary>
    | ENOSTR
    /// <summary>
    /// No data available.
    /// </summary>
    | ENODATA
    /// <summary>
    /// Timer expired.
    /// </summary>
    | ETIME
    /// <summary>
    /// Out of streams resources.
    /// </summary>
    | ENOSR
    /// <summary>
    /// Object is remote.
    /// </summary>
    | EREMOTE
    /// <summary>
    /// Link has been severed.
    /// </summary>
    | ENOLINK
    /// <summary>
    /// Protocol error.
    /// </summary>
    | EPROTO
    /// <summary>
    /// Multihop attempted.
    /// </summary>
    | EMULTIHOP
    /// <summary>
    /// Bad message.
    /// </summary>
    | EBADMSG
    /// <summary>
    /// Too many users.
    /// </summary>
    | EUSERS
    /// <summary>
    /// Destination address required.
    /// </summary>
    | EDESTADDRREQ
    /// <summary>
    /// Protocol not available.
    /// </summary>
    | ENOPROTOOPT
    /// <summary>
    /// Protocol family not supported.
    /// </summary>
    | EPFNOSUPPORT
    /// <summary>
    /// Network is down.
    /// </summary>
    | ENETDOWN
    /// <summary>
    /// Network is unreachable.
    /// </summary>
    | ENETUNREACH
    /// <summary>
    /// Network dropped connection on reset.
    /// </summary>
    | ENETRESET
    /// <summary>
    /// Software caused connection abort.
    /// </summary>
    | ECONNABORTED
    /// <summary>
    /// No buffer space available.
    /// </summary>
    | ENOBUFS
    /// <summary>
    /// Cannot send after transport endpoint shutdown.
    /// </summary>
    | ESHUTDOWN
    /// <summary>
    /// Too many references: cannot splice.
    /// </summary>
    | ETOOMANYREFS
    /// <summary>
    /// Host is down.
    /// </summary>
    | EHOSTDOWN
    /// <summary>
    /// No route to host.
    /// </summary>
    | EHOSTUNREACH
    /// <summary>
    /// Operation already in progress.
    /// </summary>
    | EALREADY
    /// <summary>
    /// Stale file handle.
    /// </summary>
    | ESTALE
    /// <summary>
    /// Disk quota exceeded.
    /// </summary>
    | EDQUOT
    /// <summary>
    /// Operation canceled.
    /// </summary>
    | ECANCELED
    /// <summary>
    /// Owner died.
    /// </summary>
    | EOWNERDEAD
    /// <summary>
    /// State not recoverable.
    /// </summary>
    | ENOTRECOVERABLE
    /// <summary>
    /// Channel number out of range.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ECHRNG
    /// <summary>
    /// Level 2 not synchronized.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EL2NSYNC
    /// <summary>
    /// Level 3 halted.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EL3HLT
    /// <summary>
    /// Level 3 reset.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EL3RST
    /// <summary>
    /// Link number out of range.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ELNRNG
    /// <summary>
    /// Protocol driver not attached.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EUNATCH
    /// <summary>
    /// No CSI structure available.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOCSI
    /// <summary>
    /// Level 2 halted.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EL2HLT
    /// <summary>
    /// Invalid exchange.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EBADE
    /// <summary>
    /// Invalid request descriptor.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EBADR
    /// <summary>
    /// Exchange full.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EXFULL
    /// <summary>
    /// No anode.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOANO
    /// <summary>
    /// Invalid request code.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EBADRQC
    /// <summary>
    /// Invalid slot.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EBADSLT
    /// <summary>
    /// Bad font file format.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EBFONT
    /// <summary>
    /// Machine is not on the network.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENONET
    /// <summary>
    /// Package not installed.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOPKG
    /// <summary>
    /// Advertise error.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EADV
    /// <summary>
    /// Srmount error.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ESRMNT
    /// <summary>
    /// Communication error on send.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ECOMM
    /// <summary>
    /// RFS specific error.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EDOTDOT
    /// <summary>
    /// Name not unique on network.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOTUNIQ
    /// <summary>
    /// File descriptor in bad state.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EBADFD
    /// <summary>
    /// Remote address changed.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EREMCHG
    /// <summary>
    /// Can not access a needed shared library.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ELIBACC
    /// <summary>
    /// Accessing a corrupted shared library.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ELIBBAD
    /// <summary>
    /// .lib section in a.out corrupted.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ELIBSCN
    /// <summary>
    /// Attempting to link in too many shared libraries.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ELIBMAX
    /// <summary>
    /// Cannot exec a shared library directly.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ELIBEXEC
    /// <summary>
    /// Interrupted system call should be restarted.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ERESTART
    /// <summary>
    /// Streams pipe error.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ESTRPIPE
    /// <summary>
    /// Structure needs cleaning.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EUCLEAN
    /// <summary>
    /// Not a XENIX named type file.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOTNAM
    /// <summary>
    /// No XENIX semaphores available.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENAVAIL
    /// <summary>
    /// Is a named type file.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EISNAM
    /// <summary>
    /// Remote I/O error.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EREMOTEIO
    /// <summary>
    /// No medium found.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOMEDIUM
    /// <summary>
    /// Wrong medium type.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EMEDIUMTYPE
    /// <summary>
    /// Required key not available.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ENOKEY
    /// <summary>
    /// Key has expired.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EKEYEXPIRED
    /// <summary>
    /// Key has been revoked.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EKEYREVOKED
    /// <summary>
    /// Key was rejected by service.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EKEYREJECTED
    /// <summary>
    /// Operation not possible due to RF-kill.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | ERFKILL
    /// <summary>
    /// Memory page has hardware error.
    /// </summary>
    /// <remarks>
    /// This is Linux-only.
    /// </remarks>
    | EHWPOISON
    /// Too many processes. Darwin only.
    | EPROCLIM
    /// RPC struct is bad. Darwin only.
    | EBADRPC
    /// RPC version wrong. Darwin only.
    | ERPCMISMATCH
    /// RPC prog. not avail. Darwin only.
    | EPROGUNAVAIL
    /// Program version wrong. Darwin only.
    | EPROGMISMATCH
    /// Bad procedure for program. Darwin only.
    | EPROCUNAVAIL
    /// Inappropriate file type or format. Darwin only.
    | EFTYPE
    /// Authentication error. Darwin only.
    | EAUTH
    /// Need authenticator. Darwin only.
    | ENEEDAUTH
    /// Device power is off. Darwin only.
    | EPWROFF
    /// Device error. Darwin only.
    | EDEVERR
    /// Bad executable (or shared library). Darwin only.
    | EBADEXEC
    /// Bad CPU type in executable. Darwin only.
    | EBADARCH
    /// Shared library version mismatch. Darwin only.
    | ESHLIBVERS
    /// Malformed Mach-o file. Darwin only.
    | EBADMACHO
    /// Attribute not found. Darwin only.
    | ENOATTR
    /// Policy not found. Darwin only.
    | ENOPOLICY
    /// Interface output queue is full. Darwin only.
    | EQFULL
    /// Capabilities insufficient. Darwin only.
    | ENOTCAPABLE

    /// <summary>The error's name as <c>&lt;errno.h&gt;</c> spells it.</summary>
    /// <example><c>"EACCES"</c></example>
    override this.ToString () : string =
        // F#'s generated ToString reflects over every case on each call, so we do this manually.
        match this with
        | UnixError.EPERM -> "EPERM"
        | UnixError.ENOENT -> "ENOENT"
        | UnixError.ESRCH -> "ESRCH"
        | UnixError.EINTR -> "EINTR"
        | UnixError.EIO -> "EIO"
        | UnixError.ENXIO -> "ENXIO"
        | UnixError.E2BIG -> "E2BIG"
        | UnixError.ENOEXEC -> "ENOEXEC"
        | UnixError.EBADF -> "EBADF"
        | UnixError.ECHILD -> "ECHILD"
        | UnixError.ENOMEM -> "ENOMEM"
        | UnixError.EACCES -> "EACCES"
        | UnixError.EFAULT -> "EFAULT"
        | UnixError.EBUSY -> "EBUSY"
        | UnixError.EEXIST -> "EEXIST"
        | UnixError.EXDEV -> "EXDEV"
        | UnixError.ENODEV -> "ENODEV"
        | UnixError.ENOTDIR -> "ENOTDIR"
        | UnixError.EISDIR -> "EISDIR"
        | UnixError.EINVAL -> "EINVAL"
        | UnixError.ENFILE -> "ENFILE"
        | UnixError.EMFILE -> "EMFILE"
        | UnixError.ENOTTY -> "ENOTTY"
        | UnixError.ETXTBSY -> "ETXTBSY"
        | UnixError.EFBIG -> "EFBIG"
        | UnixError.ENOSPC -> "ENOSPC"
        | UnixError.ESPIPE -> "ESPIPE"
        | UnixError.EROFS -> "EROFS"
        | UnixError.EMLINK -> "EMLINK"
        | UnixError.EPIPE -> "EPIPE"
        | UnixError.EDOM -> "EDOM"
        | UnixError.ERANGE -> "ERANGE"
        | UnixError.ELOOP -> "ELOOP"
        | UnixError.ENAMETOOLONG -> "ENAMETOOLONG"
        | UnixError.ENOTEMPTY -> "ENOTEMPTY"
        | UnixError.EAGAIN -> "EAGAIN"
        | UnixError.EOVERFLOW -> "EOVERFLOW"
        | UnixError.EILSEQ -> "EILSEQ"
        | UnixError.EAFNOSUPPORT -> "EAFNOSUPPORT"
        | UnixError.EPROTOTYPE -> "EPROTOTYPE"
        | UnixError.EPROTONOSUPPORT -> "EPROTONOSUPPORT"
        | UnixError.ESOCKTNOSUPPORT -> "ESOCKTNOSUPPORT"
        | UnixError.EADDRINUSE -> "EADDRINUSE"
        | UnixError.EADDRNOTAVAIL -> "EADDRNOTAVAIL"
        | UnixError.EOPNOTSUPP -> "EOPNOTSUPP"
        | UnixError.ENOTSOCK -> "ENOTSOCK"
        | UnixError.EISCONN -> "EISCONN"
        | UnixError.EINPROGRESS -> "EINPROGRESS"
        | UnixError.ECONNREFUSED -> "ECONNREFUSED"
        | UnixError.ENOTSUP -> "ENOTSUP"
        | UnixError.ENOTCONN -> "ENOTCONN"
        | UnixError.ETIMEDOUT -> "ETIMEDOUT"
        | UnixError.ECONNRESET -> "ECONNRESET"
        | UnixError.EMSGSIZE -> "EMSGSIZE"
        | UnixError.ENOSYS -> "ENOSYS"
        | UnixError.EDEADLK -> "EDEADLK"
        | UnixError.ENOLCK -> "ENOLCK"
        | UnixError.ENOTBLK -> "ENOTBLK"
        | UnixError.ENOMSG -> "ENOMSG"
        | UnixError.EIDRM -> "EIDRM"
        | UnixError.ENOSTR -> "ENOSTR"
        | UnixError.ENODATA -> "ENODATA"
        | UnixError.ETIME -> "ETIME"
        | UnixError.ENOSR -> "ENOSR"
        | UnixError.EREMOTE -> "EREMOTE"
        | UnixError.ENOLINK -> "ENOLINK"
        | UnixError.EPROTO -> "EPROTO"
        | UnixError.EMULTIHOP -> "EMULTIHOP"
        | UnixError.EBADMSG -> "EBADMSG"
        | UnixError.EUSERS -> "EUSERS"
        | UnixError.EDESTADDRREQ -> "EDESTADDRREQ"
        | UnixError.ENOPROTOOPT -> "ENOPROTOOPT"
        | UnixError.EPFNOSUPPORT -> "EPFNOSUPPORT"
        | UnixError.ENETDOWN -> "ENETDOWN"
        | UnixError.ENETUNREACH -> "ENETUNREACH"
        | UnixError.ENETRESET -> "ENETRESET"
        | UnixError.ECONNABORTED -> "ECONNABORTED"
        | UnixError.ENOBUFS -> "ENOBUFS"
        | UnixError.ESHUTDOWN -> "ESHUTDOWN"
        | UnixError.ETOOMANYREFS -> "ETOOMANYREFS"
        | UnixError.EHOSTDOWN -> "EHOSTDOWN"
        | UnixError.EHOSTUNREACH -> "EHOSTUNREACH"
        | UnixError.EALREADY -> "EALREADY"
        | UnixError.ESTALE -> "ESTALE"
        | UnixError.EDQUOT -> "EDQUOT"
        | UnixError.ECANCELED -> "ECANCELED"
        | UnixError.EOWNERDEAD -> "EOWNERDEAD"
        | UnixError.ENOTRECOVERABLE -> "ENOTRECOVERABLE"
        | UnixError.ECHRNG -> "ECHRNG"
        | UnixError.EL2NSYNC -> "EL2NSYNC"
        | UnixError.EL3HLT -> "EL3HLT"
        | UnixError.EL3RST -> "EL3RST"
        | UnixError.ELNRNG -> "ELNRNG"
        | UnixError.EUNATCH -> "EUNATCH"
        | UnixError.ENOCSI -> "ENOCSI"
        | UnixError.EL2HLT -> "EL2HLT"
        | UnixError.EBADE -> "EBADE"
        | UnixError.EBADR -> "EBADR"
        | UnixError.EXFULL -> "EXFULL"
        | UnixError.ENOANO -> "ENOANO"
        | UnixError.EBADRQC -> "EBADRQC"
        | UnixError.EBADSLT -> "EBADSLT"
        | UnixError.EBFONT -> "EBFONT"
        | UnixError.ENONET -> "ENONET"
        | UnixError.ENOPKG -> "ENOPKG"
        | UnixError.EADV -> "EADV"
        | UnixError.ESRMNT -> "ESRMNT"
        | UnixError.ECOMM -> "ECOMM"
        | UnixError.EDOTDOT -> "EDOTDOT"
        | UnixError.ENOTUNIQ -> "ENOTUNIQ"
        | UnixError.EBADFD -> "EBADFD"
        | UnixError.EREMCHG -> "EREMCHG"
        | UnixError.ELIBACC -> "ELIBACC"
        | UnixError.ELIBBAD -> "ELIBBAD"
        | UnixError.ELIBSCN -> "ELIBSCN"
        | UnixError.ELIBMAX -> "ELIBMAX"
        | UnixError.ELIBEXEC -> "ELIBEXEC"
        | UnixError.ERESTART -> "ERESTART"
        | UnixError.ESTRPIPE -> "ESTRPIPE"
        | UnixError.EUCLEAN -> "EUCLEAN"
        | UnixError.ENOTNAM -> "ENOTNAM"
        | UnixError.ENAVAIL -> "ENAVAIL"
        | UnixError.EISNAM -> "EISNAM"
        | UnixError.EREMOTEIO -> "EREMOTEIO"
        | UnixError.ENOMEDIUM -> "ENOMEDIUM"
        | UnixError.EMEDIUMTYPE -> "EMEDIUMTYPE"
        | UnixError.ENOKEY -> "ENOKEY"
        | UnixError.EKEYEXPIRED -> "EKEYEXPIRED"
        | UnixError.EKEYREVOKED -> "EKEYREVOKED"
        | UnixError.EKEYREJECTED -> "EKEYREJECTED"
        | UnixError.ERFKILL -> "ERFKILL"
        | UnixError.EHWPOISON -> "EHWPOISON"
        | UnixError.EPROCLIM -> "EPROCLIM"
        | UnixError.EBADRPC -> "EBADRPC"
        | UnixError.ERPCMISMATCH -> "ERPCMISMATCH"
        | UnixError.EPROGUNAVAIL -> "EPROGUNAVAIL"
        | UnixError.EPROGMISMATCH -> "EPROGMISMATCH"
        | UnixError.EPROCUNAVAIL -> "EPROCUNAVAIL"
        | UnixError.EFTYPE -> "EFTYPE"
        | UnixError.EAUTH -> "EAUTH"
        | UnixError.ENEEDAUTH -> "ENEEDAUTH"
        | UnixError.EPWROFF -> "EPWROFF"
        | UnixError.EDEVERR -> "EDEVERR"
        | UnixError.EBADEXEC -> "EBADEXEC"
        | UnixError.EBADARCH -> "EBADARCH"
        | UnixError.ESHLIBVERS -> "ESHLIBVERS"
        | UnixError.EBADMACHO -> "EBADMACHO"
        | UnixError.ENOATTR -> "ENOATTR"
        | UnixError.ENOPOLICY -> "ENOPOLICY"
        | UnixError.EQFULL -> "EQFULL"
        | UnixError.ENOTCAPABLE -> "ENOTCAPABLE"

[<RequireQualifiedAccess>]
module UnixError =
    /// <summary>
    /// Every case of `UnixError`, exposed for property testing.
    /// </summary>
    let all : UnixError list =
        // TODO: write a Myriad source generator for this, it's ridiculous
        [
            UnixError.EPERM
            UnixError.ENOENT
            UnixError.ESRCH
            UnixError.EINTR
            UnixError.EIO
            UnixError.ENXIO
            UnixError.E2BIG
            UnixError.ENOEXEC
            UnixError.EBADF
            UnixError.ECHILD
            UnixError.ENOMEM
            UnixError.EACCES
            UnixError.EFAULT
            UnixError.EBUSY
            UnixError.EEXIST
            UnixError.EXDEV
            UnixError.ENODEV
            UnixError.ENOTDIR
            UnixError.EISDIR
            UnixError.EINVAL
            UnixError.ENFILE
            UnixError.EMFILE
            UnixError.ENOTTY
            UnixError.ETXTBSY
            UnixError.EFBIG
            UnixError.ENOSPC
            UnixError.ESPIPE
            UnixError.EROFS
            UnixError.EMLINK
            UnixError.EPIPE
            UnixError.EDOM
            UnixError.ERANGE
            UnixError.ELOOP
            UnixError.ENAMETOOLONG
            UnixError.ENOTEMPTY
            UnixError.EAGAIN
            UnixError.EOVERFLOW
            UnixError.EILSEQ
            UnixError.EAFNOSUPPORT
            UnixError.EPROTOTYPE
            UnixError.EPROTONOSUPPORT
            UnixError.EADDRINUSE
            UnixError.EADDRNOTAVAIL
            UnixError.EOPNOTSUPP
            UnixError.ENOTSOCK
            UnixError.EISCONN
            UnixError.EINPROGRESS
            UnixError.ECONNREFUSED
            UnixError.ENOTSUP
            UnixError.ENOTCONN
            UnixError.ETIMEDOUT
            UnixError.ECONNRESET
            UnixError.EMSGSIZE
            UnixError.ENOSYS
            UnixError.EDEADLK
            UnixError.ENOLCK
            UnixError.ENOTBLK
            UnixError.ENOMSG
            UnixError.EIDRM
            UnixError.ENOSTR
            UnixError.ENODATA
            UnixError.ETIME
            UnixError.ENOSR
            UnixError.EREMOTE
            UnixError.ENOLINK
            UnixError.EPROTO
            UnixError.EMULTIHOP
            UnixError.EBADMSG
            UnixError.EUSERS
            UnixError.EDESTADDRREQ
            UnixError.ENOPROTOOPT
            UnixError.ESOCKTNOSUPPORT
            UnixError.EPFNOSUPPORT
            UnixError.ENETDOWN
            UnixError.ENETUNREACH
            UnixError.ENETRESET
            UnixError.ECONNABORTED
            UnixError.ENOBUFS
            UnixError.ESHUTDOWN
            UnixError.ETOOMANYREFS
            UnixError.EHOSTDOWN
            UnixError.EHOSTUNREACH
            UnixError.EALREADY
            UnixError.ESTALE
            UnixError.EDQUOT
            UnixError.ECANCELED
            UnixError.EOWNERDEAD
            UnixError.ENOTRECOVERABLE
            UnixError.ECHRNG
            UnixError.EL2NSYNC
            UnixError.EL3HLT
            UnixError.EL3RST
            UnixError.ELNRNG
            UnixError.EUNATCH
            UnixError.ENOCSI
            UnixError.EL2HLT
            UnixError.EBADE
            UnixError.EBADR
            UnixError.EXFULL
            UnixError.ENOANO
            UnixError.EBADRQC
            UnixError.EBADSLT
            UnixError.EBFONT
            UnixError.ENONET
            UnixError.ENOPKG
            UnixError.EADV
            UnixError.ESRMNT
            UnixError.ECOMM
            UnixError.EDOTDOT
            UnixError.ENOTUNIQ
            UnixError.EBADFD
            UnixError.EREMCHG
            UnixError.ELIBACC
            UnixError.ELIBBAD
            UnixError.ELIBSCN
            UnixError.ELIBMAX
            UnixError.ELIBEXEC
            UnixError.ERESTART
            UnixError.ESTRPIPE
            UnixError.EUCLEAN
            UnixError.ENOTNAM
            UnixError.ENAVAIL
            UnixError.EISNAM
            UnixError.EREMOTEIO
            UnixError.ENOMEDIUM
            UnixError.EMEDIUMTYPE
            UnixError.ENOKEY
            UnixError.EKEYEXPIRED
            UnixError.EKEYREVOKED
            UnixError.EKEYREJECTED
            UnixError.ERFKILL
            UnixError.EHWPOISON
            UnixError.EPROCLIM
            UnixError.EBADRPC
            UnixError.ERPCMISMATCH
            UnixError.EPROGUNAVAIL
            UnixError.EPROGMISMATCH
            UnixError.EPROCUNAVAIL
            UnixError.EFTYPE
            UnixError.EAUTH
            UnixError.ENEEDAUTH
            UnixError.EPWROFF
            UnixError.EDEVERR
            UnixError.EBADEXEC
            UnixError.EBADARCH
            UnixError.ESHLIBVERS
            UnixError.EBADMACHO
            UnixError.ENOATTR
            UnixError.ENOPOLICY
            UnixError.EQFULL
            UnixError.ENOTCAPABLE
        ]

    let private portable (raw : int) : RawErrnoPortability = RawErrnoPortability.Portable raw

    let private platformDependent (linux : int) (darwin : int) : RawErrnoPortability =
        RawErrnoPortability.PlatformDependent (linux, darwin)

    let private linuxOnly (linux : int) : RawErrnoPortability = RawErrnoPortability.LinuxOnly linux

    let private darwinOnly (darwin : int) : RawErrnoPortability = RawErrnoPortability.DarwinOnly darwin

    /// <summary>
    /// Describe the errno corresponding to a <c>UnixError</c>, in a way that is agnostic about the flavour of
    /// simulated platform.
    /// </summary>
    /// <remarks>
    /// Use <c>toRawErrnoUnder</c> to get an actual integer.
    /// </remarks>
    let rawNumbering (error : UnixError) : RawErrnoPortability =
        // Transcribed from Linux's asm-generic/errno-base.h and asm-generic/errno.h
        // (the same on x86-64 and aarch64) and Darwin's sys/errno.h (the macOS
        // 26.4 SDK). `TestUnixError` holds this to a checked-in transcription of
        // both, and checks that against the host's own header and strerror;
        // docs/plans/2026-08-23-posix-kernel-extraction/errno-table.sh is the
        // probe that produced it.
        match error with
        | UnixError.EPERM -> portable 1
        | UnixError.ENOENT -> portable 2
        | UnixError.ESRCH -> portable 3
        | UnixError.EINTR -> portable 4
        | UnixError.EIO -> portable 5
        | UnixError.ENXIO -> portable 6
        | UnixError.E2BIG -> portable 7
        | UnixError.ENOEXEC -> portable 8
        | UnixError.EBADF -> portable 9
        | UnixError.ECHILD -> portable 10
        | UnixError.ENOMEM -> portable 12
        | UnixError.EACCES -> portable 13
        | UnixError.EFAULT -> portable 14
        | UnixError.EBUSY -> portable 16
        | UnixError.EEXIST -> portable 17
        | UnixError.EXDEV -> portable 18
        | UnixError.ENODEV -> portable 19
        | UnixError.ENOTDIR -> portable 20
        | UnixError.EISDIR -> portable 21
        | UnixError.EINVAL -> portable 22
        | UnixError.ENFILE -> portable 23
        | UnixError.EMFILE -> portable 24
        | UnixError.ENOTTY -> portable 25
        | UnixError.ETXTBSY -> portable 26
        | UnixError.EFBIG -> portable 27
        | UnixError.ENOSPC -> portable 28
        | UnixError.ESPIPE -> portable 29
        | UnixError.EROFS -> portable 30
        | UnixError.EMLINK -> portable 31
        | UnixError.EPIPE -> portable 32
        | UnixError.EDOM -> portable 33
        | UnixError.ERANGE -> portable 34
        // Raw 40 is EMSGSIZE on Darwin, and raw 62 is ETIME on Linux.
        | UnixError.ELOOP -> platformDependent 40 62
        // Likewise: raw 36 is EINPROGRESS on Darwin, and raw 63 is ENOSR on
        // Linux.
        | UnixError.ENAMETOOLONG -> platformDependent 36 63
        // Raw 39 is ENOTEMPTY on Linux and EDESTADDRREQ on
        // Darwin; raw 66 is ENOTEMPTY on Darwin and EREMOTE on Linux.
        | UnixError.ENOTEMPTY -> platformDependent 39 66
        // The V7 transposition itself: raw 11 is EAGAIN on Linux but EDEADLK on
        // Darwin, and raw 35 is EAGAIN on Darwin but EDEADLK on Linux.
        | UnixError.EAGAIN -> platformDependent 11 35
        // Raw 75 is EOVERFLOW on Linux and EPROGMISMATCH on
        // Darwin; raw 84 is EOVERFLOW on Darwin and EILSEQ on Linux.
        | UnixError.EOVERFLOW -> platformDependent 75 84
        // Raw 92 is EILSEQ on Darwin and ENOPROTOOPT on Linux.
        | UnixError.EILSEQ -> platformDependent 84 92
        // Raw 97 is EAFNOSUPPORT on Linux and ENOLINK on
        // Darwin; raw 47 is EAFNOSUPPORT on Darwin and EL3RST on Linux.
        | UnixError.EAFNOSUPPORT -> platformDependent 97 47
        // Raw 91 is EPROTOTYPE on Linux and ENOMSG on Darwin, while
        // raw 41 is EPROTOTYPE on Darwin and unnamed on Linux.
        | UnixError.EPROTOTYPE -> platformDependent 91 41
        // Raw 93 is EPROTONOSUPPORT on Linux and ENOATTR on Darwin,
        // while raw 43 is EPROTONOSUPPORT on Darwin and EIDRM on Linux.
        | UnixError.EPROTONOSUPPORT -> platformDependent 93 43
        | UnixError.EADDRINUSE -> platformDependent 98 48
        | UnixError.EADDRNOTAVAIL -> platformDependent 99 49
        | UnixError.EOPNOTSUPP -> platformDependent 95 102
        // Raw 88 is ENOTSOCK on Linux and EBADMACHO on
        // Darwin, while raw 38 is ENOTSOCK on Darwin and ENOSYS on Linux.
        | UnixError.ENOTSOCK -> platformDependent 88 38
        | UnixError.EISCONN -> platformDependent 106 56
        | UnixError.EINPROGRESS -> platformDependent 115 36
        | UnixError.ECONNREFUSED -> platformDependent 111 61
        // Linux has one number for ENOTSUP and EOPNOTSUPP, which decodes as
        // EOPNOTSUPP (see `decodesUnder`). Darwin keeps them apart: 45
        // against 102.
        | UnixError.ENOTSUP -> platformDependent 95 45
        | UnixError.ENOTCONN -> platformDependent 107 57
        | UnixError.ETIMEDOUT -> platformDependent 110 60
        | UnixError.ECONNRESET -> platformDependent 104 54
        // Raw 40 is EMSGSIZE on Darwin and ELOOP on Linux.
        | UnixError.EMSGSIZE -> platformDependent 90 40
        // Raw 38 is ENOSYS on Linux and ENOTSOCK on Darwin.
        | UnixError.ENOSYS -> platformDependent 38 78
        // The other half of the V7 transposition: raw 35 is EDEADLK on Linux
        // and EAGAIN on Darwin, and raw 11 the reverse.
        | UnixError.EDEADLK -> platformDependent 35 11
        | UnixError.ENOLCK -> platformDependent 37 77
        | UnixError.ENOTBLK -> portable 15
        | UnixError.ENOMSG -> platformDependent 42 91
        | UnixError.EIDRM -> platformDependent 43 90
        | UnixError.ENOSTR -> platformDependent 60 99
        | UnixError.ENODATA -> platformDependent 61 96
        | UnixError.ETIME -> platformDependent 62 101
        | UnixError.ENOSR -> platformDependent 63 98
        | UnixError.EREMOTE -> platformDependent 66 71
        | UnixError.ENOLINK -> platformDependent 67 97
        | UnixError.EPROTO -> platformDependent 71 100
        | UnixError.EMULTIHOP -> platformDependent 72 95
        | UnixError.EBADMSG -> platformDependent 74 94
        | UnixError.EUSERS -> platformDependent 87 68
        | UnixError.EDESTADDRREQ -> platformDependent 89 39
        | UnixError.ENOPROTOOPT -> platformDependent 92 42
        | UnixError.ESOCKTNOSUPPORT -> platformDependent 94 44
        | UnixError.EPFNOSUPPORT -> platformDependent 96 46
        | UnixError.ENETDOWN -> platformDependent 100 50
        | UnixError.ENETUNREACH -> platformDependent 101 51
        | UnixError.ENETRESET -> platformDependent 102 52
        | UnixError.ECONNABORTED -> platformDependent 103 53
        | UnixError.ENOBUFS -> platformDependent 105 55
        | UnixError.ESHUTDOWN -> platformDependent 108 58
        | UnixError.ETOOMANYREFS -> platformDependent 109 59
        | UnixError.EHOSTDOWN -> platformDependent 112 64
        | UnixError.EHOSTUNREACH -> platformDependent 113 65
        | UnixError.EALREADY -> platformDependent 114 37
        | UnixError.ESTALE -> platformDependent 116 70
        | UnixError.EDQUOT -> platformDependent 122 69
        | UnixError.ECANCELED -> platformDependent 125 89
        | UnixError.EOWNERDEAD -> platformDependent 130 105
        | UnixError.ENOTRECOVERABLE -> platformDependent 131 104
        | UnixError.ECHRNG -> linuxOnly 44
        | UnixError.EL2NSYNC -> linuxOnly 45
        | UnixError.EL3HLT -> linuxOnly 46
        | UnixError.EL3RST -> linuxOnly 47
        | UnixError.ELNRNG -> linuxOnly 48
        | UnixError.EUNATCH -> linuxOnly 49
        | UnixError.ENOCSI -> linuxOnly 50
        | UnixError.EL2HLT -> linuxOnly 51
        | UnixError.EBADE -> linuxOnly 52
        | UnixError.EBADR -> linuxOnly 53
        | UnixError.EXFULL -> linuxOnly 54
        | UnixError.ENOANO -> linuxOnly 55
        | UnixError.EBADRQC -> linuxOnly 56
        | UnixError.EBADSLT -> linuxOnly 57
        | UnixError.EBFONT -> linuxOnly 59
        | UnixError.ENONET -> linuxOnly 64
        | UnixError.ENOPKG -> linuxOnly 65
        | UnixError.EADV -> linuxOnly 68
        | UnixError.ESRMNT -> linuxOnly 69
        | UnixError.ECOMM -> linuxOnly 70
        | UnixError.EDOTDOT -> linuxOnly 73
        | UnixError.ENOTUNIQ -> linuxOnly 76
        | UnixError.EBADFD -> linuxOnly 77
        | UnixError.EREMCHG -> linuxOnly 78
        | UnixError.ELIBACC -> linuxOnly 79
        | UnixError.ELIBBAD -> linuxOnly 80
        | UnixError.ELIBSCN -> linuxOnly 81
        | UnixError.ELIBMAX -> linuxOnly 82
        | UnixError.ELIBEXEC -> linuxOnly 83
        | UnixError.ERESTART -> linuxOnly 85
        | UnixError.ESTRPIPE -> linuxOnly 86
        | UnixError.EUCLEAN -> linuxOnly 117
        | UnixError.ENOTNAM -> linuxOnly 118
        | UnixError.ENAVAIL -> linuxOnly 119
        | UnixError.EISNAM -> linuxOnly 120
        | UnixError.EREMOTEIO -> linuxOnly 121
        | UnixError.ENOMEDIUM -> linuxOnly 123
        | UnixError.EMEDIUMTYPE -> linuxOnly 124
        | UnixError.ENOKEY -> linuxOnly 126
        | UnixError.EKEYEXPIRED -> linuxOnly 127
        | UnixError.EKEYREVOKED -> linuxOnly 128
        | UnixError.EKEYREJECTED -> linuxOnly 129
        | UnixError.ERFKILL -> linuxOnly 132
        | UnixError.EHWPOISON -> linuxOnly 133
        | UnixError.EPROCLIM -> darwinOnly 67
        | UnixError.EBADRPC -> darwinOnly 72
        | UnixError.ERPCMISMATCH -> darwinOnly 73
        | UnixError.EPROGUNAVAIL -> darwinOnly 74
        | UnixError.EPROGMISMATCH -> darwinOnly 75
        | UnixError.EPROCUNAVAIL -> darwinOnly 76
        | UnixError.EFTYPE -> darwinOnly 79
        | UnixError.EAUTH -> darwinOnly 80
        | UnixError.ENEEDAUTH -> darwinOnly 81
        | UnixError.EPWROFF -> darwinOnly 82
        | UnixError.EDEVERR -> darwinOnly 83
        | UnixError.EBADEXEC -> darwinOnly 85
        | UnixError.EBADARCH -> darwinOnly 86
        | UnixError.ESHLIBVERS -> darwinOnly 87
        | UnixError.EBADMACHO -> darwinOnly 88
        | UnixError.ENOATTR -> darwinOnly 93
        | UnixError.ENOPOLICY -> darwinOnly 103
        | UnixError.EQFULL -> darwinOnly 106
        | UnixError.ENOTCAPABLE -> darwinOnly 107

    /// <summary>
    /// The raw <c>&lt;errno.h&gt;</c> number for this error on the chosen platform.
    /// </summary>
    /// <returns><c>None</c> if the given platform has no such error.</returns>
    /// <example>
    /// <c>ENOKEY</c> doesn't exist on Darwin, so you get <c>None</c> there.
    /// </example>
    let tryToRawErrnoUnder (reporting : RawErrnoNumbering) (error : UnixError) : int option =
        match rawNumbering error, reporting with
        | RawErrnoPortability.Portable value, _ -> Some value
        | RawErrnoPortability.PlatformDependent (linux, _), RawErrnoNumbering.Linux -> Some linux
        | RawErrnoPortability.PlatformDependent (_, darwin), RawErrnoNumbering.Darwin -> Some darwin
        | RawErrnoPortability.LinuxOnly linux, RawErrnoNumbering.Linux -> Some linux
        | RawErrnoPortability.DarwinOnly darwin, RawErrnoNumbering.Darwin -> Some darwin
        | RawErrnoPortability.LinuxOnly _, RawErrnoNumbering.Darwin
        | RawErrnoPortability.DarwinOnly _, RawErrnoNumbering.Linux -> None

    /// <summary>
    /// The raw <c>&lt;errno.h&gt;</c> integer for this error on the chosen platform.
    /// </summary>
    /// <remarks>
    /// Throws for an error the chosen platform does not have, such as <c>ENOKEY</c> under Darwin.
    /// Use <c>tryToRawErrnoUnder</c> to get <c>None</c> instead.
    /// </remarks>
    /// <exception cref="T:System.ArgumentException">The chosen platform does not have <c>error</c>.</exception>
    let toRawErrnoUnder (reporting : RawErrnoNumbering) (error : UnixError) : int =
        match tryToRawErrnoUnder reporting error with
        | Some raw -> raw
        | None ->
            raise (
                Refusal.exceptionOf
                    "UnixError.toRawErrnoUnder"
                    (RefusalKind.Contradictory "error")
                    $"%O{error} does not exist under the %O{reporting} numbering (its numbering is %A{rawNumbering error}), so no number is right for it there. Whatever produced it for a %O{reporting} process has answered with another flavour's error."
            )

    /// <summary>
    /// Whether the integer is an errno which is portable across all WoofWare.PosixKernel's modelled Unixes.
    /// </summary>
    /// <example>
    /// The number 5 is <c>EIO</c> on all modelled platforms, so is portable.
    ///
    /// The number 11 is <c>EAGAIN</c> on Linux but <c>EDEADLK</c> on Darwin, so is not portable.
    /// </example>
    /// <remarks>
    /// These are exactly the numbers <c>ofRawErrnoPortable</c> converts.
    /// </remarks>
    let isPortableRawErrno (raw : int) : bool = raw >= 1 && raw <= 34 && raw <> 11

    /// <summary>
    /// A fast-path to detect whether the integer is known not to be a valid errno on any modelled Unix.
    /// </summary>
    /// <example>
    /// POSIX specifies that errnos are positive, so any negative int is unambiguously a nonstandard raw errno.
    /// </example>
    let isUnambiguouslyNonStandardRawErrno (raw : int) : bool = raw < 0

    /// <summary>
    /// Convert a portable raw integer errno to a structured error.
    /// </summary>
    /// <remarks>
    /// This returns <c>None</c> for non-portable errnos, and for numbers which aren't named under any
    /// modelled Unix.
    ///
    /// Use <c>ofRawErrnoUnder</c> to convert an errno if you already know the platform you're simulating.
    /// </remarks>
    let ofRawErrnoPortable (raw : int) : UnixError option =
        all
        |> List.tryFind (fun error ->
            match rawNumbering error with
            | RawErrnoPortability.Portable value -> value = raw
            | RawErrnoPortability.PlatformDependent _
            | RawErrnoPortability.LinuxOnly _
            | RawErrnoPortability.DarwinOnly _ -> false
        )

    /// <summary>
    /// Whether this error decodes on the platform.
    /// </summary>
    /// <param name="reporting">The flavour of platform we're decoding the error for.</param>
    /// <param name="error">An error which may or may not be valid for this platform.</param>
    /// <example>
    /// Linux gives ENOTSUP and EOPNOTSUPP one number, 95, and the kernel's own
    /// name for it is EOPNOTSUPP: its headers don't define ENOTSUP, and glibc's
    /// <c>&lt;errno.h&gt;</c> adds as a synonym. So under Linux the number decodes as
    /// EOPNOTSUPP, and ENOTSUP is only ever encoded.
    ///
    /// So this function returns <c>false</c> for ENOTSUP.
    /// </example>
    let private decodesUnder (reporting : RawErrnoNumbering) (error : UnixError) : bool =
        match reporting, error with
        | RawErrnoNumbering.Linux, UnixError.ENOTSUP -> false
        | _, _ -> true

    let private decodeTable (reporting : RawErrnoNumbering) : Map<int, UnixError> =
        all
        |> List.filter (decodesUnder reporting)
        |> List.fold
            (fun (table : Map<int, UnixError>) error ->
                match tryToRawErrnoUnder reporting error with
                | None -> table
                | Some raw ->
                    match Map.tryFind raw table with
                    | Some other ->
                        failwith
                            $"UnixError: %O{other} and %O{error} are both %d{raw} under the %O{reporting} numbering, and neither is declared the other's alias. The table is mis-transcribed."
                    | None -> Map.add raw error table
            )
            Map.empty

    let private linuxDecode : Map<int, UnixError> = decodeTable RawErrnoNumbering.Linux

    let private darwinDecode : Map<int, UnixError> =
        decodeTable RawErrnoNumbering.Darwin

    /// <summary>
    /// Convert a raw integer errno to a structured error on the specified platform.
    /// </summary>
    /// <remarks>
    /// Unlike <c>ofRawErrnoPortable</c>, this returns values for platform-dependent entries too.
    /// It returns <c>None</c> exactly for a number that platform's <c>&lt;errno.h&gt;</c> names no error for.
    /// Where a platform gives two errors one number, one of them is answered:
    /// Linux's 95 is <c>EOPNOTSUPP</c>, never <c>ENOTSUP</c>.
    /// </remarks>
    let ofRawErrnoUnder (reporting : RawErrnoNumbering) (raw : int) : UnixError option =
        match reporting with
        | RawErrnoNumbering.Linux -> Map.tryFind raw linuxDecode
        | RawErrnoNumbering.Darwin -> Map.tryFind raw darwinDecode
