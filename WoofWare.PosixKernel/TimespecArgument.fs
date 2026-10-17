namespace WoofWare.PosixKernel

/// A `const struct timespec *` argument, as the kernel's copy-in finds it.
///
/// The caller classifies it, because only the caller knows what its memory
/// holds. The kernel validates the fields: a `Readable` timespec may hold any
/// pair of numbers.
[<RequireQualifiedAccess>]
type TimespecArgument =
    /// A null pointer.
    | Null
    /// The pointer names a readable `struct timespec` holding these.
    | Readable of seconds : int64 * nanoseconds : int64
    /// The pointer is not null, and names no readable `struct timespec`.
    | Unreadable
