namespace WoofWare.PosixKernel

/// A `struct timespec` as the client read it from the process's memory:
/// `tv_sec` and `tv_nsec`, both raw, before this kernel decides what they
/// mean.
[<Struct>]
type TimespecFields =
    {
        /// `tv_sec`.
        Seconds : int64
        /// `tv_nsec`, which may be any value the process stored. A call that
        /// gives some values a meaning of their own, as `utimensat(2)` does
        /// `UTIME_NOW` and `UTIME_OMIT`, says so.
        Nanoseconds : int64
    }

/// A `const struct timespec *` argument, as the kernel's copy-in finds it.
///
/// The client classifies the pointer and reads the fields, because only the
/// client holds the process's memory (see "What every client does" in the
/// README). The kernel validates the fields: a `Readable` timespec may hold
/// any pair of numbers.
[<RequireQualifiedAccess>]
type TimespecArgument =
    /// A null pointer.
    | Null
    /// The pointer names a readable `struct timespec` holding these.
    | Readable of fields : TimespecFields
    /// The pointer is not null, and names no readable `struct timespec`.
    | Unreadable
