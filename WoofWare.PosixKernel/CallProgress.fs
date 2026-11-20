namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// How far a syscall got: either it is over, or it has stopped at the point
/// where the kernel copies from the process's memory.
///
/// This library never reads the process's memory, so the client reads it and
/// hands over what it found. A call stops at the copy because what happens
/// before the copy is observable: a Linux `write` to a bad descriptor answers
/// `EBADF` whatever the buffer holds. Every answer that the call gives without reading that
/// memory therefore comes first, as `Answered`, and the client reads the
/// memory only where a real kernel would. A client that holds every argument
/// already can make the call through `UnixSystem.step` instead, which never
/// stops (see "Calls that copy in from the caller's memory" in the README).
///
/// Each paused type says what to copy: one that copies bytes has a
/// `copyRange` (or `copyRanges`) in its own module. The function that resumes
/// it is in the call's family module, such as `UnixReadWrite.writeWithBytes`
/// for a `PausedWrite`. The resumption answers `'Answer`, the type that
/// `Answered` carries; where the call copies again after that, it answers
/// another `CallProgress` with the same `'Answer`. The one exception is
/// `UnixReadWrite.writeWithBytes`, which also answers the bytes that the write
/// delivered to a client that drains a pipe (`Delivery`).
///
/// The paused value holds the whole system as it stood at the copy, so the
/// client resumes it before it does anything else to the system (see "What
/// every client does" in the README). Resuming the same paused value twice
/// gives two independent answers from the same system.
///
/// A resumption that copies a range of bytes (one whose paused type has a
/// `copyRange`) takes exactly those bytes and nothing else. It has no way to
/// say that the copy faulted, or that only some of the bytes could be read: a
/// buffer that faults is described before the call, as
/// `UserBuffer.Unmapped`, and this library cannot express a buffer that is
/// readable only in part. A resumption that takes a pathname is different: it
/// takes a `PathArgumentBytes`, so the client reports an unreadable pathname
/// (`PathArgumentBytes.Unreadable`) when it is asked for it.
[<RequireQualifiedAccess>]
type CallProgress<'Paused, 'Answer> =
    /// The call is over, without reading (any more of) the process's memory.
    | Answered of answer : 'Answer
    /// The call has stopped where the kernel copies from the process's memory.
    /// `paused` holds the system and everything the call has decided so far,
    /// so nothing else can happen to the system in between.
    | NeedsCopyIn of paused : 'Paused

[<RequireQualifiedAccess>]
module internal CallProgress =
    /// The answer of a call made with what it copies in already to hand: the
    /// answer `progress` holds if it ended before its copy, and otherwise what
    /// `resume` answers for the paused call.
    let resumeWith<'Paused, 'Answer, 'Refusal>
        (resume : 'Paused -> Result<'Answer, 'Refusal>)
        (progress : Result<CallProgress<'Paused, 'Answer>, 'Refusal>)
        : Result<'Answer, 'Refusal>
        =
        match progress with
        | Error refusal -> Error refusal
        | Ok (CallProgress.Answered answer) -> Ok answer
        | Ok (CallProgress.NeedsCopyIn paused) -> resume paused

    /// `progress` with its answer made `f` of what it was, if the call is over;
    /// a paused call is left as it is.
    let mapAnswered<'Paused, 'Answer, 'Mapped>
        (f : 'Answer -> 'Mapped)
        (progress : CallProgress<'Paused, 'Answer>)
        : CallProgress<'Paused, 'Mapped>
        =
        match progress with
        | CallProgress.Answered answer -> CallProgress.Answered (f answer)
        | CallProgress.NeedsCopyIn paused -> CallProgress.NeedsCopyIn paused

    /// Throws `ArgumentNullException`, naming the parameter `paused`, if
    /// `paused` is null, as only `Unchecked.defaultof` or C# `default` can make
    /// a paused call: `resume` names the function the client called with it,
    /// and `origin` the functions that answer one.
    let requirePaused<'Paused when 'Paused : not struct> (resume : string) (origin : string) (paused : 'Paused) : unit =
        match box paused with
        | null ->
            raise (
                Refusal.exceptionOf
                    resume
                    (RefusalKind.Null "paused")
                    $"this paused call is null, which it can only be if it came from `Unchecked.defaultof` or C# `default`; obtain one from %s{origin} instead."
            )
        | _ -> ()

/// The bytes that a paused call copies next from a buffer which the process
/// passed: `ByteCount` bytes, starting `FirstByte` bytes after the pointer the
/// process passed.
type CopyRange =
    {
        /// How many bytes into the buffer the copy starts, counted from the
        /// pointer the process passed. Zero unless part of the buffer was
        /// copied before, as by a write that slept partway.
        FirstByte : int
        /// How many bytes the call copies. The client supplies exactly this
        /// many; the resuming function throws `InvalidOperationException` for
        /// any other number.
        ByteCount : int
    }

[<RequireQualifiedAccess>]
module internal CopyRange =
    /// The first `byteCount` bytes of the caller's buffer.
    let fromStart (byteCount : int) : CopyRange =
        {
            FirstByte = 0
            ByteCount = byteCount
        }

    /// Fails loudly unless `bytes` is exactly the `range` a call copies:
    /// `caller` names the function the client called with them.
    let require (caller : string) (range : CopyRange) (bytes : ImmutableArray<byte>) : unit =
        if bytes.IsDefault then
            invalidOp
                $"%s{caller}: bytes is the default ImmutableArray, whose underlying array is null. That is not an empty copy; pass ImmutableArray<byte>.Empty."

        if bytes.Length <> range.ByteCount then
            invalidOp
                $"%s{caller}: the call copies %d{range.ByteCount} bytes, starting %d{range.FirstByte} bytes into the caller's buffer, but %d{bytes.Length} were supplied. Supply exactly the bytes the paused call's copyRange names: a byte the kernel could not read and a byte holding zero have different answers, so neither too few nor too many can be answered for (this is a bug in the caller)."
