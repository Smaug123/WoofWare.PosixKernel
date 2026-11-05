namespace WoofWare.PosixKernel

open System.Collections.Immutable

/// What `gethostname(3)` places in the caller's buffer and returns.
///
/// Neither flavour's C library answers a buffer too short for the name the
/// same way, and neither is POSIX's "truncated, and unspecified whether
/// terminated" in full: see `UnixHostName.getHostName`.
[<RequireQualifiedAccess ; NoComparison>]
type GetHostNameAnswer =
    /// Place `placed` at the start of the caller's buffer; the call returns 0.
    ///
    /// `placed` is never longer than the capacity, and the bytes past it are
    /// untouched. It is empty only for Darwin's null destination at a
    /// capacity of `MAXHOSTNAMELEN + 1` or more, which `sysctl(3)` takes as a
    /// request for the name's length alone.
    | Returned of placed : ImmutableArray<byte>
    /// Place `placed` at the start of the caller's buffer; the call returns -1
    /// and the caller stores `error` wherever its libc keeps errno.
    ///
    /// `placed` is empty except on Linux's ENAMETOOLONG, which glibc reports
    /// after copying as much of the name as fits, with no terminator.
    | Failed of placed : ImmutableArray<byte> * error : UnixError

/// Why this kernel will not answer a `gethostname`.
[<RequireQualifiedAccess>]
type internal GetHostNameRefusal =
    /// The destination has no answer at the copy.
    | Buffer of BufferRefusal
    /// The destination names no storage the caller can write, on a route
    /// where the C library stores into it from user space. That is a fatal
    /// signal rather than an errno, and this kernel has no way to deliver one.
    | FatalToTheProcess
    /// Darwin, at a capacity of zero: its C library terminates the buffer at
    /// index `capacity - 1`, which is the byte before the buffer.
    | StoresBeforeTheBuffer

[<RequireQualifiedAccess>]
module internal GetHostNameRefusal =
    /// What this kernel knows about why it cannot answer a `gethostname`. The
    /// client supplies its own half: which entry point, and what the
    /// destination actually was.
    let describe (refusal : GetHostNameRefusal) : string =
        match refusal with
        | GetHostNameRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | GetHostNameRefusal.FatalToTheProcess ->
            "the destination names no storage this caller can write, and this flavour's gethostname(3) copies the name into it from user space at this capacity, so the real call dies on a signal (measured: SIGSEGV on Linux, SIGSEGV or SIGBUS on Darwin, docs/probes/gethostname). A dead process is not an errno."
        | GetHostNameRefusal.StoresBeforeTheBuffer ->
            "Darwin's gethostname(3) terminates the buffer at index capacity - 1, so at a capacity of zero it stores a NUL in the byte before the buffer and returns 0 (measured, docs/probes/gethostname). This library cannot say what that byte belonged to."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : GetHostNameRefusal) : RefusalKind =
        match refusal with
        | GetHostNameRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | GetHostNameRefusal.FatalToTheProcess -> RefusalKind.Unmodelled
        | GetHostNameRefusal.StoresBeforeTheBuffer -> RefusalKind.Unmodelled

/// `gethostname(3)`: the machine's name, as `UnixBootImage.withHostName` set it.
[<RequireQualifiedAccess>]
module UnixHostName =

    /// Darwin's `MAXHOSTNAMELEN`, from `<sys/param.h>`: the size of the
    /// kernel's `kern.hostname` buffer, terminator included.
    [<Literal>]
    let private darwinMaxHostNameLength : uint64 = 256UL

    /// `tryGetHostName` once `Entry` has admitted its caller.
    let private tryGetHostNameIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (destination : UserBuffer)
        (capacity : uint64)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<GetHostNameAnswer, GetHostNameRefusal>
        =
        let name = UnixByteString.toBytes system.Machine.HostName
        let terminated = name.Add 0uy

        /// The C library is about to store `placed` into the destination
        /// itself, from user space.
        let storeFromUserSpace (onStored : GetHostNameAnswer) : Result<GetHostNameAnswer, GetHostNameRefusal> =
            match destination with
            | UserBuffer.Mapped -> Ok onStored
            | UserBuffer.Unmapped _ -> Error GetHostNameRefusal.FatalToTheProcess
            | UserBuffer.Opaque -> Error (GetHostNameRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
            | UserBuffer.Addressless -> Error (GetHostNameRefusal.Buffer BufferRefusal.AddresslessAtTransfer)

        // Every row below is measured on both flavours by
        // docs/probes/gethostname, which `TestGetHostName` replays.
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux ->
            // glibc's gethostname reads `uname(2)` into a struct of its own,
            // then copies the name and its terminator, as much as fits, with
            // `memcpy`; and fails if that was not all of it.
            if capacity = 0UL then
                // Copies nothing, so no destination is consulted: measured
                // ENAMETOOLONG through a null pointer and an unwritable page.
                Ok (GetHostNameAnswer.Failed (ImmutableArray.Empty, UnixError.ENAMETOOLONG))
            elif capacity < uint64 terminated.Length then
                let placed = terminated.Slice (0, int capacity)
                storeFromUserSpace (GetHostNameAnswer.Failed (placed, UnixError.ENAMETOOLONG))
            else
                storeFromUserSpace (GetHostNameAnswer.Returned terminated)
        | SimulatedUnixFlavour.Darwin ->
            // Darwin's Libc reads `kern.hostname` straight into the caller's
            // buffer when it holds `MAXHOSTNAMELEN + 1` bytes or more, and
            // otherwise into a buffer of its own, which it `strncpy`s across
            // and then terminates at `capacity - 1`.
            if capacity = 0UL then
                Error GetHostNameRefusal.StoresBeforeTheBuffer
            elif capacity > darwinMaxHostNameLength then
                // The kernel's own copy-out, which faults as EFAULT; except that
                // `sysctl` takes a null destination as asking only for the
                // length, and copies nothing.
                match destination with
                | UserBuffer.Unmapped 0UL -> Ok (GetHostNameAnswer.Returned ImmutableArray.Empty)
                | UserBuffer.Unmapped _ -> Ok (GetHostNameAnswer.Failed (ImmutableArray.Empty, UnixError.EFAULT))
                | UserBuffer.Mapped -> Ok (GetHostNameAnswer.Returned terminated)
                | UserBuffer.Opaque -> Error (GetHostNameRefusal.Buffer BufferRefusal.OpaqueAtTransfer)
                | UserBuffer.Addressless -> Error (GetHostNameRefusal.Buffer BufferRefusal.AddresslessAtTransfer)
            else
                // `strncpy` writes all `capacity` bytes: the name as far as it
                // fits short of the last byte, then NULs to the end.
                let kept = min name.Length (int capacity - 1)
                let placed = ImmutableArray.CreateBuilder<byte> (int capacity)
                placed.AddRange (name.Slice (0, kept))
                placed.Count <- int capacity
                storeFromUserSpace (GetHostNameAnswer.Returned (placed.MoveToImmutable ()))

    /// `getHostName`, with a refusal answered as the `Error` rather than raised.
    let internal tryGetHostName<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (destination : UserBuffer)
        (capacity : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetHostNameAnswer, GetHostNameRefusal>
        =
        Entry.call
            "UnixHostName.getHostName"
            CallerRequirement.Running
            caller
            Shape.answer
            (tryGetHostNameIn destination capacity)
            system

    /// <summary>
    /// <c>gethostname(3)</c>: copy the machine's name into the caller's buffer
    /// of <c>capacity</c> bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This has no side-effects on the kernel.
    /// </para>
    /// <para>
    /// A buffer with room for the name and its terminator gets exactly those
    /// bytes on both flavours. A shorter one is where they part. On Linux the
    /// call places as much of the name as fits, unterminated, and fails with
    /// ENAMETOOLONG. On Darwin it succeeds, placing the name truncated to
    /// <c>capacity - 1</c> bytes and padding with NULs to fill the buffer;
    /// Darwin pads any capacity up to <c>MAXHOSTNAMELEN</c> (256) that way.
    /// </para>
    /// </remarks>
    /// <param name="caller">The thread making the call.</param>
    /// <param name="destination">Where the call writes the name.</param>
    /// <param name="capacity">The caller's buffer size, as the <c>size_t</c> it is.</param>
    /// <param name="system">The kernel the name is read from.</param>
    /// <exception cref="T:WoofWare.PosixKernel.UnmodelledException">The destination cannot be written at a capacity where the C library stores into it itself, which kills the real process; or Darwin's capacity is zero, where it stores before the buffer; or the destination is <c>Opaque</c> or <c>Addressless</c> where bytes would be placed.</exception>
    let getHostName<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (destination : UserBuffer)
        (capacity : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : GetHostNameAnswer
        =
        tryGetHostName caller destination capacity system
        |> Refusal.orRaise "UnixHostName.getHostName" GetHostNameRefusal.kind GetHostNameRefusal.describe
