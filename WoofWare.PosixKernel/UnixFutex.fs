namespace WoofWare.PosixKernel

/// Why this kernel will not answer a `futex(2)`, or finish a futex wait.
[<RequireQualifiedAccess>]
type internal FutexRefusal =
    /// This kernel is not Linux-flavoured, and only Linux has `futex(2)`.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// `op` names a command Linux decodes but this kernel does not model:
    /// one without `FUTEX_PRIVATE_FLAG`, or one other than a wait, a wake, a
    /// bitset wait and a bitset wake.
    | UnmodelledOperation of op : int
    /// The word a wait compares is real memory whose contents the caller
    /// cannot produce (`UserBuffer.Opaque`).
    | OpaqueWord
    /// The word a wait compares is described as `word`, which is not the
    /// memory at `address`: an `Unmapped` buffer at another address, or an
    /// `Addressless` one.
    | WordElsewhere of address : uint64 * word : UserBuffer
    /// A wait's deadline on the realtime clock lies more than `Int64.MaxValue`
    /// nanoseconds before the machine booted at `bootTime`, so it has no
    /// instant in nanoseconds since boot. Unmodelled: Linux keeps the realtime
    /// clock as a signed 64-bit count of nanoseconds, which no reading so far
    /// past boot fits.
    | RealtimeDeadlineBeforeBoot of bootTime : UnixTimestamp
    /// How a signal ends the wait.
    | Interruption of SyscallInterruptionRefusal

[<RequireQualifiedAccess>]
module internal FutexRefusal =
    /// What this kernel knows about why it cannot answer. The client supplies
    /// its own half: which call was made, and by which thread.
    let describe (refusal : FutexRefusal) : string =
        match refusal with
        | FutexRefusal.UnmodelledFlavour flavour ->
            $"this kernel is %O{flavour}-flavoured, and futex(2) exists on Linux only."
        | FutexRefusal.UnmodelledOperation op ->
            $"futex(2) operation %d{op} is a command this kernel does not model: it models FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAIT_BITSET and FUTEX_WAKE_BITSET, each only with FUTEX_PRIVATE_FLAG."
        | FutexRefusal.OpaqueWord ->
            "the futex wait's word is memory whose contents the caller cannot produce, so the wait cannot compare it with the value it expects."
        | FutexRefusal.WordElsewhere (address, word) ->
            $"the futex wait is at address 0x%x{address}, but its word was described as %A{word}, which is not the memory at that address."
        | FutexRefusal.RealtimeDeadlineBeforeBoot bootTime ->
            $"the futex wait's deadline on the realtime clock is more than 2^63 nanoseconds before the machine booted (at %O{bootTime}), so it has no instant since boot; Linux keeps the realtime clock as a signed 64-bit count of nanoseconds, which no reading so late fits."
        | FutexRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FutexRefusal) : RefusalKind =
        match refusal with
        | FutexRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | FutexRefusal.UnmodelledOperation _ -> RefusalKind.Unmodelled
        | FutexRefusal.OpaqueWord -> RefusalKind.Unmodelled
        | FutexRefusal.WordElsewhere _ -> RefusalKind.Contradictory "word"
        | FutexRefusal.RealtimeDeadlineBeforeBoot _ -> RefusalKind.Unmodelled
        | FutexRefusal.Interruption refusal -> SyscallInterruptionRefusal.kind refusal

/// What clock a futex wait's timeout is measured on, and how.
[<RequireQualifiedAccess>]
type internal FutexTimeoutClock =
    /// A length of time from the call, on the monotonic clock
    /// (`FUTEX_WAIT_PRIVATE`).
    | Relative
    /// An instant on the monotonic clock (`FUTEX_WAIT_BITSET_PRIVATE`).
    | Monotonic
    /// An instant on the realtime clock (`FUTEX_WAIT_BITSET_PRIVATE` with
    /// `FUTEX_CLOCK_REALTIME`).
    | Realtime

/// A futex wait stopped where the kernel reads the word at its address:
/// `UnixFutex.futex` answers it, and `UnixFutex.futexWithWord` takes what the
/// word held and finishes the call.
[<NoEquality ; NoComparison>]
type PausedFutexWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            Thread : 'Thread
            Address : uint64
            Expected : uint32
            Bitset : uint32
            /// The timeout as the call gave it, already screened: seconds and
            /// nanoseconds, or `None` for none.
            Timeout : (int64 * int64) option
            Clock : FutexTimeoutClock
            /// The system the call was made in: everything a wait does before
            /// reading the word is a question.
            System : ProcessView<'Thread, 'Handler>
        }

/// Linux's `futex(2)`, for the operations this kernel models:
/// `FUTEX_WAIT_PRIVATE`, `FUTEX_WAKE_PRIVATE`, `FUTEX_WAIT_BITSET_PRIVATE` (on
/// either clock) and `FUTEX_WAKE_BITSET_PRIVATE`.
///
/// A process's waiters on one address form one queue, in the order they
/// parked. The kernel holds no word: the word is the caller's memory, which a
/// wait reads through `futexWithWord`.
[<RequireQualifiedAccess>]
module UnixFutex =

    /// `FUTEX_WAIT` with `FUTEX_PRIVATE_FLAG`: `<linux/futex.h>`'s
    /// `FUTEX_WAIT_PRIVATE`.
    [<Literal>]
    let FutexWaitPrivate : int = 128

    /// `FUTEX_WAKE` with `FUTEX_PRIVATE_FLAG`: `<linux/futex.h>`'s
    /// `FUTEX_WAKE_PRIVATE`.
    [<Literal>]
    let FutexWakePrivate : int = 129

    /// `FUTEX_WAIT_BITSET` with `FUTEX_PRIVATE_FLAG`: `<linux/futex.h>`'s
    /// `FUTEX_WAIT_BITSET_PRIVATE`.
    [<Literal>]
    let FutexWaitBitsetPrivate : int = 137

    /// `FUTEX_WAKE_BITSET` with `FUTEX_PRIVATE_FLAG`: `<linux/futex.h>`'s
    /// `FUTEX_WAKE_BITSET_PRIVATE`.
    [<Literal>]
    let FutexWakeBitsetPrivate : int = 138

    /// `<linux/futex.h>`'s `FUTEX_CLOCK_REALTIME`: with
    /// `FUTEX_WAIT_BITSET_PRIVATE`, the wait's deadline is an instant on the
    /// realtime clock rather than the monotonic one.
    [<Literal>]
    let FutexClockRealtime : int = 256

    /// `<linux/futex.h>`'s `FUTEX_BITSET_MATCH_ANY`: the bitset a plain wait
    /// waits with and a plain wake wakes with.
    [<Literal>]
    let FutexBitsetMatchAny : uint32 = 0xFFFFFFFFu

    let private futexPrivateFlag : int = 128

    // `<linux/futex.h>`'s commands: what `op` holds once its two flags are
    // masked off.
    let private futexWait : int = 0
    let private futexWake : int = 1
    let private futexWaitBitset : int = 9
    let private futexWakeBitset : int = 10
    let private futexWaitRequeuePi : int = 11
    let private futexLockPi2 : int = 13

    /// The commands Linux decodes, every one of which this kernel either
    /// models or refuses: `FUTEX_FD` (2) is not among them, since Linux no
    /// longer decodes it (measured: `ENOSYS`).
    let private decodedCommands : Set<int> =
        set [ 0 ; 1 ; 3 ; 4 ; 5 ; 6 ; 7 ; 8 ; 9 ; 10 ; 11 ; 12 ; 13 ]

    /// The commands whose fourth argument is a timeout, which Linux screens
    /// before it decodes the rest of the call: `FUTEX_WAIT`, `FUTEX_LOCK_PI`,
    /// `FUTEX_WAIT_BITSET`, `FUTEX_WAIT_REQUEUE_PI` and `FUTEX_LOCK_PI2`.
    let private commandsTakingTimeout : Set<int> = set [ 0 ; 6 ; 9 ; 11 ; 13 ]

    let private nanosecondsPerSecond : int64 = 1_000_000_000L

    /// Linux's `KTIME_SEC_MAX`: from this many seconds up, a timespec
    /// saturates to the last instant the kernel's clock can represent.
    let private ktimeSecondsMax : int64 = System.Int64.MaxValue / nanosecondsPerSecond

    /// The seconds and nanoseconds `timeout` holds, or `None` for a null
    /// pointer; or the error the timeout answers.
    let private screenTimeout (timeout : TimespecArgument) : Result<(int64 * int64) option, UnixError> =
        match timeout with
        | TimespecArgument.Null -> Ok None
        | TimespecArgument.Unreadable -> Error UnixError.EFAULT
        | TimespecArgument.Readable {
                                        Seconds = seconds
                                        Nanoseconds = nanoseconds
                                    } ->
            if seconds < 0L || nanoseconds < 0L || nanoseconds >= nanosecondsPerSecond then
                Error UnixError.EINVAL
            else
                Ok (Some (seconds, nanoseconds))

    /// When a wait whose screened timeout is `timeout`, measured as `clock`
    /// says, made at `system`'s present, times out.
    let private timeoutOf<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (clock : FutexTimeoutClock)
        (timeout : (int64 * int64) option)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<FutexTimeout, FutexRefusal>
        =
        match timeout with
        | None -> Ok FutexTimeout.Untimed
        | Some (seconds, _) when seconds >= ktimeSecondsMax ->
            // Linux turns the timespec into nanoseconds, saturating from
            // `KTIME_SEC_MAX` seconds up (`timespec64_to_ktime`; the rule's
            // shape from source). Measured (`docs/probes/huge-timeout` and
            // `docs/probes/futex-bitset`, the "huge" rows, on both sides of the
            // saturation): every such wait, relative or absolute on either
            // clock, slept until a wake ended it, and a signal under
            // `SA_RESTART` ended it with `EINTR`, as it ends a timed wait. By
            // source Linux arms a timer near `KTIME_SEC_MAX` seconds after
            // boot, which no measurement can tell from never, so a saturated
            // wait has no deadline here.
            Ok FutexTimeout.Unbounded
        | Some (seconds, nanoseconds) ->

        let length = seconds * nanosecondsPerSecond + nanoseconds

        match clock with
        | FutexTimeoutClock.Relative ->
            // A relative timeout is added to the time now, saturating where
            // the sum overflows (`ktime_add_safe`; measured, the "huge" rows of
            // `docs/probes/huge-timeout`).
            let now = system.Scheduling.NanosecondsSinceBoot

            if now > System.Int64.MaxValue - length then
                Ok FutexTimeout.Unbounded
            else
                Ok (FutexTimeout.Until (now + length))
        | FutexTimeoutClock.Monotonic -> Ok (FutexTimeout.At length)
        | FutexTimeoutClock.Realtime ->
            // This kernel's realtime clock reads `BootTime` plus the uptime and
            // never steps, so an instant on it is that instant less
            // `BootTime`, in nanoseconds since boot, for as long as the wait
            // lasts. `BootTime` can lie far enough past the epoch that the
            // difference does not fit.
            let bootTime = system.Machine.BootTime

            let sinceBoot =
                System.Int128.op_Implicit length
                - System.Int128.op_Implicit (UnixTimestamp.seconds bootTime)
                  * System.Int128.op_Implicit nanosecondsPerSecond
                - System.Int128.op_Implicit (int64 (UnixTimestamp.nanoseconds bootTime))

            if sinceBoot < System.Int128.op_Implicit System.Int64.MinValue then
                Error (FutexRefusal.RealtimeDeadlineBeforeBoot bootTime)
            else
                Ok (FutexTimeout.At (System.Int128.op_Explicit sinceBoot : int64))

    /// `tryFutex` once `Entry` has admitted its caller.
    let private tryFutexIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (address : uint64)
        (op : int)
        (value : int)
        (word : UserBuffer)
        (timeout : TimespecArgument)
        (val3 : uint32)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedFutexWait<'Thread, 'Handler>, SyscallOutcome * ProcessView<'Thread, 'Handler>>,
              FutexRefusal
           >
        =
        let failed (error : UnixError) =
            Ok (CallProgress.Answered (SyscallOutcome.Answered (SyscallAnswer.Failed error), system))

        match SimulatedUnixPlatform.flavour system.Machine.UnixPlatform with
        | SimulatedUnixFlavour.Darwin -> Error (FutexRefusal.UnmodelledFlavour SimulatedUnixFlavour.Darwin)
        | SimulatedUnixFlavour.Linux ->

        let command = op &&& ~~~(futexPrivateFlag ||| FutexClockRealtime)
        let isPrivate = op &&& futexPrivateFlag <> 0
        let onRealtimeClock = op &&& FutexClockRealtime <> 0

        // Measured on Linux 6.18.5 (`docs/probes/futex-bitset`, the "decode"
        // rows): a command that takes a timeout screens it first; then
        // `FUTEX_CLOCK_REALTIME` on any command but `FUTEX_WAIT_BITSET`,
        // `FUTEX_WAIT_REQUEUE_PI` and `FUTEX_LOCK_PI2` answers `ENOSYS`; then a
        // command Linux does not decode answers `ENOSYS`, reading no timeout.
        let screened =
            if commandsTakingTimeout.Contains command then
                screenTimeout timeout
            else
                Ok None

        match screened with
        | Error error -> failed error
        | Ok screenedTimeout ->

        if
            onRealtimeClock
            && command <> futexWaitBitset
            && command <> futexWaitRequeuePi
            && command <> futexLockPi2
        then
            failed UnixError.ENOSYS
        elif not (decodedCommands.Contains command) then
            failed UnixError.ENOSYS
        elif not isPrivate then
            Error (FutexRefusal.UnmodelledOperation op)
        else

        // Measured on Linux 6.18.5 (`docs/probes/futex`, the "wait-screen",
        // "wake-screen" and "range" rows, and `docs/probes/futex-bitset`, the
        // "wait-screen" and "wake-screen" rows): a wait copies and screens its
        // timeout, then its bitset, then its address's alignment, then whether
        // the word lies in user space, then reads the word; a private wake
        // screens its bitset, then the alignment and the range, and reads no
        // memory. A plain wait or wake has the bitset `FUTEX_BITSET_MATCH_ANY`.
        let aligned = address % 4UL = 0UL

        let outsideUserSpace =
            UserBufferCheck.faultsBeforeOperation (UnixMachineState.userBufferCheck system.Machine) address 4UL

        let wait (bitset : uint32) (clock : FutexTimeoutClock) =
            if bitset = 0u then
                failed UnixError.EINVAL
            elif not aligned then
                failed UnixError.EINVAL
            elif outsideUserSpace then
                failed UnixError.EFAULT
            else

            match word with
            | UserBuffer.Unmapped at when at = address -> failed UnixError.EFAULT
            | UserBuffer.Unmapped _
            | UserBuffer.Addressless -> Error (FutexRefusal.WordElsewhere (address, word))
            | UserBuffer.Opaque -> Error FutexRefusal.OpaqueWord
            | UserBuffer.Mapped ->
                {
                    Thread = thread
                    Address = address
                    Expected = uint32 value
                    Bitset = bitset
                    Timeout = screenedTimeout
                    Clock = clock
                    System = system
                }
                |> CallProgress.NeedsCopyIn
                |> Ok

        let wake (bitset : uint32) =
            if bitset = 0u then
                failed UnixError.EINVAL
            elif not aligned then
                failed UnixError.EINVAL
            elif outsideUserSpace then
                failed UnixError.EFAULT
            else

            // Measured (the "count" rows of `docs/probes/futex`, the "order"
            // rows of `docs/probes/futex-bitset`): a wake of 0 or fewer wakes
            // one.
            let count = max value 1

            // Every waiter on the address that no wake has taken yet, asleep
            // or woken by something else and not yet finished, whose bitset
            // shares a bit with the wake's, in the order they parked: a waiter
            // a signal or its timeout has woken keeps its place until it runs
            // (measured, the "race" rows), and a waiter whose bitset does not
            // match is passed over (the "match" and "order" rows).
            let taken =
                UnixThreadTable.byName system.Threads
                |> Map.toList
                |> List.choose (fun (waiter, state) ->
                    match UnixThreadState.park state with
                    | Some ({
                                Syscall = ParkedSyscall.Futex wait
                            } as park) when
                        wait.FutexAddress = address
                        && not wait.TakenByWake
                        && wait.FutexBitset &&& bitset <> 0u
                        ->
                        Some (park.Ordinal, waiter, park, wait)
                    | _ -> None
                )
                |> List.sortBy (fun (ordinal, _, _, _) -> ordinal)
                |> List.truncate count

            let woken =
                (system, taken)
                ||> List.fold (fun system (_, waiter, park, wait) ->
                    UnixParkState.setPark
                        waiter
                        { park with
                            Syscall =
                                ParkedSyscall.Futex
                                    { wait with
                                        TakenByWake = true
                                    }
                        }
                        system
                )

            Ok (
                CallProgress.Answered (
                    SyscallOutcome.Answered (SyscallAnswer.Completed (int64 (List.length taken))),
                    woken
                )
            )

        if command = futexWait then
            wait FutexBitsetMatchAny FutexTimeoutClock.Relative
        elif command = futexWaitBitset then
            wait
                val3
                (if onRealtimeClock then
                     FutexTimeoutClock.Realtime
                 else
                     FutexTimeoutClock.Monotonic)
        elif command = futexWake then
            wake FutexBitsetMatchAny
        elif command = futexWakeBitset then
            wake val3
        else
            Error (FutexRefusal.UnmodelledOperation op)

    /// `futex`, with a refusal answered as the `Error` rather than raised.
    let internal tryFutex<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (address : uint64)
        (op : int)
        (value : int)
        (word : UserBuffer)
        (timeout : TimespecArgument)
        (val3 : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<
              CallProgress<PausedFutexWait<'Thread, 'Handler>, SyscallOutcome * UnixSystem<'Thread, 'Handler>>,
              FutexRefusal
           >
        =
        Entry.call
            "UnixFutex.futex"
            CallerRequirement.Running
            caller
            (Shape.result (Shape.progress Shape.withSystem))
            (tryFutexIn (Caller.thread caller) address op value word timeout val3)
            system

    /// Linux's `futex(2)`, made by `caller` on the 32-bit word at `address`.
    ///
    /// `op` is the raw operation word: a command and the flags
    /// `FUTEX_PRIVATE_FLAG` (128) and `FUTEX_CLOCK_REALTIME` (256). The four
    /// modelled operations are `FUTEX_WAIT_PRIVATE` (128),
    /// `FUTEX_WAKE_PRIVATE` (129), `FUTEX_WAIT_BITSET_PRIVATE` (137, or 393 on
    /// the realtime clock) and `FUTEX_WAKE_BITSET_PRIVATE` (138). `val3` is the
    /// syscall's sixth argument, the bitset of a bitset wait or wake; the
    /// other operations do not read it.
    ///
    /// A wait waits while the word at `address` holds `value`. Its `timeout`,
    /// or `TimespecArgument.Null` for none, is a length of time on the
    /// monotonic clock for `FUTEX_WAIT_PRIVATE`, and an instant for
    /// `FUTEX_WAIT_BITSET_PRIVATE`, on the monotonic clock or, with
    /// `FUTEX_CLOCK_REALTIME`, on the realtime clock. A timeout of
    /// `KTIME_SEC_MAX` (9223372036) seconds or more, or a relative one that
    /// ends past the last instant the clock can represent, never expires
    /// (`FutexTimeout.Unbounded`), but is still a timeout to a signal. A
    /// bitset wait waits with the bitset `val3`, and a plain one with
    /// `FUTEX_BITSET_MATCH_ANY`. `word` is the caller's memory at `address`.
    /// Once the timeout, the bitset and the address have passed their screens
    /// (`EFAULT` for an unreadable timeout, `EINVAL` for a malformed one, then
    /// `EINVAL` for a bitset of 0, then `EINVAL` for an address that is not a
    /// multiple of 4, then `EFAULT` for a word outside user space or a `word`
    /// that is `Unmapped`), the call stops where the kernel reads the word,
    /// and `futexWithWord` takes what it holds. The caller must read the word
    /// as it makes that call, with no store by any thread in between, since
    /// the kernel's read and its decision to sleep are one step.
    ///
    /// A wake takes up to `value` of the process's waiters on `address` off
    /// its queue, in the order they began to wait, passing over any whose
    /// bitset shares no bit with its own (`val3` for a bitset wake,
    /// `FUTEX_BITSET_MATCH_ANY` for a plain one), and answers how many it
    /// took. A `value` of 0 or less takes one. It reads no memory, so `word`
    /// and `timeout` are not looked at; it answers `EINVAL` for a bitset of 0,
    /// then `EINVAL` for a misaligned address, then `EFAULT` for one outside
    /// user space, and an address no memory backs otherwise answers 0. A taken
    /// waiter's wait answers 0 when it is finished (`UnixWait.finish`), whatever
    /// else has woken it.
    ///
    /// Any other `op` Linux answers as Linux does where it does not decode it:
    /// after screening the timeout of a command that takes one, `ENOSYS` for
    /// `FUTEX_CLOCK_REALTIME` on a command that does not take it, and `ENOSYS`
    /// for a command Linux does not have.
    ///
    /// Throws `PlatformNotSupportedException` under the Darwin flavour, which
    /// has no `futex(2)`; `UnmodelledException` for any other command Linux
    /// has (requeueing, `FUTEX_WAKE_OP`, the priority-inheritance commands),
    /// for any command without `FUTEX_PRIVATE_FLAG`, and for a wait whose
    /// `word` is `Opaque`; and `ArgumentException` for a wait whose `word` is
    /// `Addressless` or `Unmapped` at an address other than `address`.
    let futex<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (address : uint64)
        (op : int)
        (value : int)
        (word : UserBuffer)
        (timeout : TimespecArgument)
        (val3 : uint32)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedFutexWait<'Thread, 'Handler>, SyscallOutcome * UnixSystem<'Thread, 'Handler>>
        =
        tryFutex caller address op value word timeout val3 system
        |> Refusal.orRaise "UnixFutex.futex" FutexRefusal.kind FutexRefusal.describe

    /// `tryFutexWithWord` before `Entry` makes a kernel of its view.
    let private tryFutexWithWordIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (word : uint32)
        (paused : PausedFutexWait<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, FutexRefusal>
        =
        CallProgress.requirePaused "UnixFutex.futexWithWord" "UnixFutex.futex" paused

        let system = paused.System

        if word <> paused.Expected then
            Ok (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.EAGAIN), system)
        else

        match timeoutOf paused.Clock paused.Timeout system with
        | Error refusal -> Error refusal
        | Ok timeout ->

        let parked =
            ParkedSyscall.Futex
                {
                    FutexAddress = paused.Address
                    FutexTimeout = timeout
                    FutexBitset = paused.Bitset
                    TakenByWake = false
                }

        // A wait whose deadline has already come still sleeps before it
        // answers `ETIMEDOUT` (measured, the "switches" rows of
        // `docs/probes/futex` and `docs/probes/futex-bitset`: a voluntary
        // context switch for nearly every one of 1000 waits with a zero
        // relative timeout, or an absolute one already passed, on either
        // clock), so it parks with its condition already holding, which
        // `parkWaiting` would report as a bug.
        let asleep =
            match FutexTimeout.deadline timeout with
            | Some deadline when deadline <= system.Scheduling.NanosecondsSinceBoot ->
                Parking.park paused.Thread parked system
            | Some _
            | None -> Parking.parkWaiting paused.Thread parked system

        Ok (SyscallOutcome.WouldBlock (WakeCondition.ofPark parked), asleep)

    /// `futexWithWord`, with a refusal answered as the `Error` rather than
    /// raised.
    let internal tryFutexWithWord<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (word : uint32)
        (paused : PausedFutexWait<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, FutexRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryFutexWithWordIn word paused)

    /// The rest of the futex wait `paused` stopped: `word` is what the word at
    /// its address holds, read as this is called. See `futex`.
    ///
    /// A word other than the value the wait expects answers `EAGAIN`.
    /// Otherwise the calling thread parks, answering
    /// `SyscallOutcome.WouldBlock`, and `finishFutexWait` (or `UnixWait.finish`)
    /// finishes the call once `UnixWait.wake` has woken it.
    ///
    /// Throws `UnmodelledException` for a wait whose deadline on the realtime
    /// clock lies more than `Int64.MaxValue` nanoseconds before the machine
    /// booted, which only a machine booted after the year 2262 can make.
    let futexWithWord<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (word : uint32)
        (paused : PausedFutexWait<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFutexWithWord word paused
        |> Refusal.orRaise "UnixFutex.futexWithWord" FutexRefusal.kind FutexRefusal.describe

    /// `tryFinishFutexWait` once `Entry` has admitted its caller.
    let internal tryFinishFutexWaitIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (system : ProcessView<'Thread, 'Handler>)
        : Result<SyscallOutcome * ProcessView<'Thread, 'Handler>, FutexRefusal>
        =
        let wait =
            UnixThreadTable.expectParked
                "UnixFutex.finishFutexWait"
                (fun parked ->
                    match parked with
                    | ParkedSyscall.Futex wait -> Some wait
                    | _ -> None
                )
                thread
                system.Threads

        // Measured on Linux 6.18.5 (`docs/probes/futex` and
        // `docs/probes/futex-bitset`, the "race" rows), the waiter held off its
        // CPU until all had happened: a wait a wake took answers 0 though a
        // signal or its timeout came first, and the signal's handler runs as
        // it returns; and a timeout beats a signal.
        if wait.TakenByWake then
            Ok (SyscallOutcome.Answered (SyscallAnswer.Completed 0L), UnixParkState.unpark thread system)
        elif WakeCondition.deadlinePassed (FutexTimeout.deadline wait.FutexTimeout) system then
            Ok (SyscallOutcome.Answered (SyscallAnswer.Failed UnixError.ETIMEDOUT), UnixParkState.unpark thread system)
        else

        match SyscallInterruption.ofPark thread system with
        | Error refusal -> Error (FutexRefusal.Interruption refusal)
        | Ok (Some interruption) ->
            Ok (
                SyscallOutcome.Interrupted,
                OwedReturns.interrupt thread interruption (UnixParkState.unpark thread system)
            )
        | Ok None ->
            // A wait wakes for a wake that took it, its deadline, or a signal,
            // and only the signal can have gone by now; `ofPark` never sends a
            // futex wait a signal woke back to sleep, since its restart reads
            // the word again.
            failwith
                $"UnixFutex.finishFutexWait: thread %O{thread} was woken from its futex wait (%A{UnixThreadTable.parkOf thread system.Threads}), but no wake has taken it, its deadline has not passed, and no signal interrupts it (this is a bug in this library)."

    /// `finishFutexWait`, with a refusal answered as the `Error` rather than
    /// raised.
    let internal tryFinishFutexWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, FutexRefusal>
        =
        Entry.call
            "UnixFutex.finishFutexWait"
            CallerRequirement.Woken
            caller
            (Shape.result Shape.withSystem)
            (tryFinishFutexWaitIn (Caller.thread caller))
            system

    /// Finish the futex wait (`FUTEX_WAIT_PRIVATE` or
    /// `FUTEX_WAIT_BITSET_PRIVATE`) `caller` parked in, once `UnixWait.wake`
    /// has woken it.
    ///
    /// Answers 0 if a wake took the waiter, whatever else woke it; then
    /// `ETIMEDOUT` if its deadline has passed; and otherwise the call is
    /// interrupted by a signal (`SyscallOutcome.Interrupted`), and the thread's
    /// return to user mode (`UnixSignal.onReturnToUser`) says whether it fails
    /// with `EINTR` or restarts. A wait with no timeout restarts under a
    /// handler installed with `SA_RESTART`; one with a timeout, even one that
    /// never expires, never does. A restarted wait reads its word again, so the
    /// caller makes the call again with the arguments it first made it with.
    /// Where the thread would by now take no signal as it returned to user
    /// mode, the wait restarts too, and a bitset wait keeps the instant its
    /// call named, as the call made again does.
    ///
    /// Throws `UnmodelledException` for a `FUTEX_WAIT_PRIVATE` with a deadline
    /// (`FutexTimeout.Until`) that a signal woke, where by now the thread would
    /// take no signal as it returned to user mode: Linux restarts such a wait
    /// with its first deadline, which a call made again with its relative
    /// timeout does not have. A wait whose timeout never expires restarts then,
    /// as one with no timeout does.
    let finishFutexWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFinishFutexWait caller system
        |> Refusal.orRaise "UnixFutex.finishFutexWait" FutexRefusal.kind FutexRefusal.describe
