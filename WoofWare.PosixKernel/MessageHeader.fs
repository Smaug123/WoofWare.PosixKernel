namespace WoofWare.PosixKernel

/// A `struct msghdr`, as the caller's memory held it when `sendmsg(2)` or
/// `recvmsg(2)` read it: each pointer as the client classifies the storage it
/// names, and each count as the raw bits of the field, in the flavour's own
/// width.
///
/// The client decodes the structure by its platform's layout, which this
/// kernel does not check: a field read from the wrong offset is a field this
/// kernel takes at its word. `msg_flags` is not here, since neither call reads
/// it.
type MessageHeader =
    {
        /// `msg_name`. A NULL one is `UserBuffer.Unmapped 0UL`.
        MessageName : UserBuffer
        /// `msg_namelen`, a `socklen_t`.
        MessageNameLength : uint32
        /// `msg_iov`, the iovec array.
        MessageVectors : UserBuffer
        /// `msg_iovlen`: Linux's `size_t`, or Darwin's `int`, its 32 bits as an
        /// unsigned number (so -1 is 0xFFFFFFFF).
        MessageVectorCount : uint64
        /// `msg_control`. A NULL one is `UserBuffer.Unmapped 0UL`.
        MessageControl : UserBuffer
        /// `msg_controllen`: Linux's `size_t`, or Darwin's `socklen_t`.
        MessageControlLength : uint64
    }

/// A `struct iovec` of the array a `MessageHeader` names, as the caller's
/// memory held it.
type IoVector =
    {
        /// `iov_base`, as the client classifies the storage it names.
        VectorBase : UserBuffer
        /// `iov_len`, a `size_t`.
        VectorLength : uint64
    }
