namespace WoofWare.PosixKernel

/// The bits `getrandom(2)` accepts in its `flags` argument, as Linux's
/// `<sys/random.h>` numbers them.
///
/// None of them changes what this kernel answers: its pool is initialised from
/// boot, so there is never a wait for `GRND_NONBLOCK` to decline, and every
/// source the other two select is that one pool.
[<RequireQualifiedAccess>]
module GetRandomFlags =
    /// `GRND_NONBLOCK`.
    [<Literal>]
    let NonBlock : uint32 = 1u

    /// `GRND_RANDOM`.
    [<Literal>]
    let Random : uint32 = 2u

    /// `GRND_INSECURE`.
    [<Literal>]
    let Insecure : uint32 = 4u

/// What `getrandom(2)` did, for a request this kernel could answer.
[<RequireQualifiedAccess>]
type GetRandomAnswer =
    /// The client fetches the bytes from the draw, all at once or a range at a
    /// time, and stores them at the start of the process's buffer; the
    /// process's call returns `EntropyDraw.count draw`. That can be fewer than
    /// the process asked for: see `UnixEntropy.getRandomMaxTransfer`. The
    /// system that comes back with this answer has already moved its pool past
    /// them.
    ///
    /// A count of zero means that the call moved nothing and did not touch the
    /// buffer at all.
    | Completed of draw : EntropyDraw
    /// The process's call returns -1, and the client sets the calling thread's errno
    /// to `error`. Nothing was drawn from the pool.
    | Failed of error : UnixError

/// Why this kernel will not answer a `getrandom`.
[<RequireQualifiedAccess>]
type internal GetRandomRefusal =
    /// The buffer has no answer at the step the call reached.
    | Buffer of BufferRefusal
    /// The simulated kernel has no `getrandom` system call.
    | NoSuchSyscall of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal GetRandomRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which entry point, and what it passed.
    let describe (refusal : GetRandomRefusal) : string =
        match refusal with
        | GetRandomRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | GetRandomRefusal.NoSuchSyscall flavour ->
            $"the simulated kernel is %O{flavour}, which has no getrandom system call; getentropy(2) is how a process asks it for random bytes."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : GetRandomRefusal) : RefusalKind =
        match refusal with
        | GetRandomRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | GetRandomRefusal.NoSuchSyscall _ -> RefusalKind.NotOnPlatform

/// What `getentropy(2)` did, for a request this kernel could answer.
[<RequireQualifiedAccess>]
type GetEntropyAnswer =
    /// The client fetches the bytes from the draw, which holds exactly as many
    /// as the process asked for, and stores them at the start of the process's
    /// buffer; the process's call returns 0. The system that comes back with
    /// this answer has already moved its pool past them.
    ///
    /// A count of zero means that the process asked for nothing, and the call
    /// did not touch the buffer at all.
    | Completed of draw : EntropyDraw
    /// The process's call returns -1, and the client sets the calling thread's errno
    /// to `error`. Nothing was drawn from the pool.
    | Failed of error : UnixError

/// Why this kernel will not answer a `getentropy`.
[<RequireQualifiedAccess>]
type internal GetEntropyRefusal =
    /// The buffer has no answer at the step the call reached.
    | Buffer of BufferRefusal
    /// The simulated kernel has no `getentropy` system call.
    | NoSuchSyscall of flavour : SimulatedUnixFlavour

[<RequireQualifiedAccess>]
module internal GetEntropyRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which entry point, and what it passed.
    let describe (refusal : GetEntropyRefusal) : string =
        match refusal with
        | GetEntropyRefusal.Buffer refusal -> BufferRefusal.describe refusal
        | GetEntropyRefusal.NoSuchSyscall flavour ->
            $"the simulated kernel is %O{flavour}, which has no getentropy system call; getrandom(2) is how a process asks it for random bytes."

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : GetEntropyRefusal) : RefusalKind =
        match refusal with
        | GetEntropyRefusal.Buffer refusal -> BufferRefusal.kind refusal
        | GetEntropyRefusal.NoSuchSyscall _ -> RefusalKind.NotOnPlatform

/// The syscalls that hand out bytes from the kernel's entropy pool.
[<RequireQualifiedAccess>]
module UnixEntropy =

    /// The most bytes one `getrandom` moves on `platform`, however many were
    /// asked for: the same limit as one `read(2)`, which on Linux, the one
    /// flavour with a `getrandom`, is `MAX_RW_COUNT` (`INT_MAX` rounded down to
    /// a whole page). A larger request is not an error; it returns this many.
    let getRandomMaxTransfer (platform : SimulatedUnixPlatform) : uint64 =
        // Measured with 4 KiB pages, the only size a Linux platform admits:
        // 0x7FFFF000 on 6.18.5 aarch64 for requests of INT_MAX, 2^31,
        // 2^31 + 4096, 2^40 and SIZE_MAX alike, and the whole request for every
        // size measured up to 256 MiB; and 0x7FFFF000 on 6.12 x86-64 for INT_MAX,
        // 2^31 and SIZE_MAX. `TestEntropyAgainstHost` measures it again on a
        // Linux host.
        uint64 (TransferCountLimit.maxTransfer (SimulatedUnixPlatform.transferCountLimit platform))

    /// The most bytes one `getentropy` will be asked for. A longer request is
    /// EINVAL, and moves nothing.
    [<Literal>]
    let getEntropyMaxLength : uint64 = 256UL

    /// Where a call that has decided how many bytes to move gets them: the
    /// buffer screen, the zero-length shortcut, and the one point at which the
    /// buffer must be able to hold bytes. `Error` is a refusal; `Ok (Error _)`
    /// is an errno.
    let private transfer<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (buffer : UserBuffer)
        (length : int)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<Result<EntropyDraw * ProcessView<'Thread, 'Handler>, UnixError>, BufferRefusal>
        =
        match
            UserBufferCheck.faultsBeforeOperationFor
                (UnixMachineState.userBufferCheck system.Machine)
                buffer
                (uint64 length)
        with
        | Error refusal -> Error refusal
        | Ok true -> Ok (Error UnixError.EFAULT)
        | Ok false ->

        if length = 0 then
            // Nothing moves, so the buffer is not consulted: measured on both,
            // a zero-length call through a null pointer returns success. On
            // Darwin, which screens nothing, so does one through the last
            // address there is.
            Ok (Ok (fst (EntropyPool.take 0 system.Machine.EntropyPool), system))
        else

        match buffer with
        | UserBuffer.Unmapped _ ->
            // A real kernel draws before it copies out, so its pool has moved on
            // by the time the copy faults. No process can tell where a real
            // kernel's pool is, so this one stays put, which keeps a faulting
            // call from changing the system at all.
            Ok (Error UnixError.EFAULT)
        | UserBuffer.Opaque -> Error BufferRefusal.OpaqueAtTransfer
        | UserBuffer.Addressless -> Error BufferRefusal.AddresslessAtTransfer
        | UserBuffer.Mapped ->

        // The whole length. Linux's getrandom stops at the first page boundary
        // past which a signal is pending, but no signal is deliverable to a
        // thread here as its call begins, which owes its return to user mode
        // first: moving every byte is the outcome in which a signal arrives
        // after the last check.
        let draw, pool = EntropyPool.take length system.Machine.EntropyPool

        Ok (
            Ok (
                draw,
                { system with
                    Machine =
                        { system.Machine with
                            EntropyPool = pool
                        }
                }
            )
        )

    /// `tryGetRandom` once `Entry` has admitted its caller.
    let private tryGetRandomIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (buffer : UserBuffer)
        (count : uint64)
        (flags : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<GetRandomAnswer * ProcessView<'Thread, 'Handler>, GetRandomRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin as flavour -> Error (GetRandomRefusal.NoSuchSyscall flavour)
        | SimulatedUnixFlavour.Linux ->

        let known =
            GetRandomFlags.NonBlock ||| GetRandomFlags.Random ||| GetRandomFlags.Insecure

        let exclusive = GetRandomFlags.Random ||| GetRandomFlags.Insecure

        // Both checks precede everything else: measured, a malformed `flags`
        // is EINVAL through a null pointer, through the last address there is,
        // and at a count of zero.
        if flags &&& ~~~known <> 0u || flags &&& exclusive = exclusive then
            Ok (GetRandomAnswer.Failed UnixError.EINVAL, system)
        else

        // Clamped before the buffer is screened, so it is the clamped range the
        // screen sees: measured, a request of SIZE_MAX into storage that holds
        // the clamped count succeeds rather than faulting.
        let length = int (min count (getRandomMaxTransfer system.Machine.UnixPlatform))

        match transfer buffer length system with
        | Error refusal -> Error (GetRandomRefusal.Buffer refusal)
        | Ok (Error error) -> Ok (GetRandomAnswer.Failed error, system)
        | Ok (Ok (draw, system)) -> Ok (GetRandomAnswer.Completed draw, system)

    /// `getRandom`, with a refusal answered as the `Error` rather than raised.
    let internal tryGetRandom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (buffer : UserBuffer)
        (count : uint64)
        (flags : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetRandomAnswer * UnixSystem<'Thread, 'Handler>, GetRandomRefusal>
        =
        Entry.call
            "UnixEntropy.getRandom"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryGetRandomIn buffer count flags)
            system

    /// <summary>
    /// `getrandom(2)`: draw up to `count` bytes from the entropy pool. The
    /// answer carries the draw, and the client stores its bytes in the
    /// process's buffer.
    ///
    /// `flags` is the raw argument, any combination of `GetRandomFlags`. It is
    /// EINVAL if it has any other bit set, or both `GetRandomFlags.Random` and
    /// `GetRandomFlags.Insecure`, whatever the buffer and the count.
    ///
    /// Never blocks. Linux-only: under any other flavour it throws
    /// `PlatformNotSupportedException`.
    ///
    /// `caller` is the thread making the call, which must be one of the process's,
    /// and not asleep in another call.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">The simulated kernel has no `getrandom` system call.</exception>
    let getRandom<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (buffer : UserBuffer)
        (count : uint64)
        (flags : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : GetRandomAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryGetRandom caller buffer count flags system
        |> Refusal.orRaise "UnixEntropy.getRandom" GetRandomRefusal.kind GetRandomRefusal.describe

    /// `tryGetEntropy` once `Entry` has admitted its caller.
    let private tryGetEntropyIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (buffer : UserBuffer)
        (length : uint64)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<GetEntropyAnswer * ProcessView<'Thread, 'Handler>, GetEntropyRefusal>
        =
        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Linux as flavour -> Error (GetEntropyRefusal.NoSuchSyscall flavour)
        | SimulatedUnixFlavour.Darwin ->

        // Ahead of the buffer: measured, 257 bytes is EINVAL through a null
        // pointer and through the last address there is, where 256 is EFAULT.
        if length > getEntropyMaxLength then
            Ok (GetEntropyAnswer.Failed UnixError.EINVAL, system)
        else

        match transfer buffer (int length) system with
        | Error refusal -> Error (GetEntropyRefusal.Buffer refusal)
        | Ok (Error error) -> Ok (GetEntropyAnswer.Failed error, system)
        | Ok (Ok (draw, system)) -> Ok (GetEntropyAnswer.Completed draw, system)

    /// `getEntropy`, with a refusal answered as the `Error` rather than raised.
    let internal tryGetEntropy<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (buffer : UserBuffer)
        (length : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<GetEntropyAnswer * UnixSystem<'Thread, 'Handler>, GetEntropyRefusal>
        =
        Entry.call
            "UnixEntropy.getEntropy"
            CallerRequirement.Running
            caller
            (Shape.result Shape.withSystem)
            (tryGetEntropyIn buffer length)
            system

    /// <summary>
    /// `getentropy(2)`: draw `length` bytes from the entropy pool. The answer
    /// carries the draw, and the client stores its bytes in the process's
    /// buffer.
    ///
    /// A `length` above `getEntropyMaxLength` is EINVAL, whatever the buffer.
    ///
    /// Darwin-only: under any other flavour it throws
    /// `PlatformNotSupportedException`.
    /// </summary>
    /// <exception cref="T:System.PlatformNotSupportedException">The simulated kernel has no `getentropy` system call.</exception>
    let getEntropy<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (buffer : UserBuffer)
        (length : uint64)
        (system : UnixSystem<'Thread, 'Handler>)
        : GetEntropyAnswer * UnixSystem<'Thread, 'Handler>
        =
        tryGetEntropy caller buffer length system
        |> Refusal.orRaise "UnixEntropy.getEntropy" GetEntropyRefusal.kind GetEntropyRefusal.describe
