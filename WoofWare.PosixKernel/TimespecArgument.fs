namespace WoofWare.PosixKernel

/// A `struct timespec` as the caller's memory held it: `tv_sec` and
/// `tv_nsec`, both raw, before this kernel decides what they say.
[<Struct>]
type TimespecFields =
    {
        /// `tv_sec`.
        Seconds : int64
        /// `tv_nsec`, which may be any value the caller stored: a call that
        /// gives some values a meaning of their own, as `utimensat(2)` does
        /// `UTIME_NOW` and `UTIME_OMIT`, says so.
        Nanoseconds : int64
    }

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
    | Readable of fields : TimespecFields
    /// The pointer is not null, and names no readable `struct timespec`.
    | Unreadable
