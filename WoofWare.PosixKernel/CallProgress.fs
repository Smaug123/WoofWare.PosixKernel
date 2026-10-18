namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// How far a syscall got: it is over, or it has stopped at the point where the
/// kernel copies from the caller's memory.
///
/// A call stops there because the client may not be able to produce the bytes
/// without failing: a foreign-function layer whose memory is not a flat array
/// has to resolve the pointer, and resolving it can be a mistake in itself.
/// Every answer the call gives *without* reading that memory comes first, so
/// that the client reads it only where a real kernel would.
///
/// Resuming a `'Paused` with what it asks for answers `'Answer`, the same type
/// `Answered` carries, or, where the call copies again after that, another
/// `CallProgress` with the same `'Answer`. Each paused type says what to copy:
/// one that copies bytes has a `copyRange`, and its module the function that
/// resumes it.
[<RequireQualifiedAccess>]
type CallProgress<'Paused, 'Answer> =
    /// The call is over, without reading (any more of) the caller's memory.
    | Answered of answer : 'Answer
    /// The call has stopped where the kernel copies from the caller's memory.
    /// `paused` holds the system and everything the call has decided so far,
    /// so nothing else can be made to happen in between.
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

/// The bytes of a buffer the caller passed that a paused call copies next:
/// `ByteCount` bytes, starting `FirstByte` bytes into the buffer.
type CopyRange =
    {
        /// How far into the caller's buffer the bytes start. Zero unless part of
        /// the buffer was copied before, as by a write that slept partway.
        FirstByte : int
        /// How many bytes the call copies: exactly this many must be supplied.
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
