namespace WoofWare.PosixKernel

/// Why this kernel will not answer a `futex(2)`, or finish a futex wait.
[<RequireQualifiedAccess>]
type internal FutexRefusal =
    /// This kernel is not Linux-flavoured, and only Linux has `futex(2)`.
    | UnmodelledFlavour of flavour : SimulatedUnixFlavour
    /// `op` is neither `FUTEX_WAIT_PRIVATE` nor `FUTEX_WAKE_PRIVATE`, the only
    /// operations this kernel models.
    | UnmodelledOperation of op : int
    /// The word a wait compares is real memory whose contents the caller
    /// cannot produce (`UserBuffer.Opaque`).
    | OpaqueWord
    /// The word a wait compares is described as `word`, which is not the
    /// memory at `address`: an `Unmapped` buffer at another address, or an
    /// `Addressless` one.
    | WordElsewhere of address : uint64 * word : UserBuffer
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
            $"futex(2) operation %d{op} is not FUTEX_WAIT_PRIVATE (128) or FUTEX_WAKE_PRIVATE (129), the only operations this kernel models."
        | FutexRefusal.OpaqueWord ->
            "the futex wait's word is memory whose contents the caller cannot produce, so the wait cannot compare it with the value it expects."
        | FutexRefusal.WordElsewhere (address, word) ->
            $"the futex wait is at address 0x%x{address}, but its word was described as %A{word}, which is not the memory at that address."
        | FutexRefusal.Interruption refusal -> SyscallInterruptionRefusal.describe refusal

    /// Which exception a public entry point raises this refusal as.
    let kind (refusal : FutexRefusal) : RefusalKind =
        match refusal with
        | FutexRefusal.UnmodelledFlavour _ -> RefusalKind.NotOnPlatform
        | FutexRefusal.UnmodelledOperation _ -> RefusalKind.Unmodelled
        | FutexRefusal.OpaqueWord -> RefusalKind.Unmodelled
        | FutexRefusal.WordElsewhere _ -> RefusalKind.Contradictory "word"
        | FutexRefusal.Interruption refusal -> SyscallInterruptionRefusal.kind refusal

/// A `FUTEX_WAIT_PRIVATE` stopped where the kernel reads the word at its
/// address: `UnixFutex.futex` answers it, and `UnixFutex.futexWithWord` takes
/// what the word held and finishes the call.
[<NoEquality ; NoComparison>]
type PausedFutexWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    private
        {
            Thread : 'Thread
            Address : uint64
            Expected : uint32
            Timeout : FutexTimeout
            /// The system the call was made in: everything a wait does before
            /// reading the word is a question.
            System : ProcessView<'Thread, 'Handler>
        }

/// Linux's `futex(2)`, for the two operations this kernel models:
/// `FUTEX_WAIT_PRIVATE` and `FUTEX_WAKE_PRIVATE`.
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

    let private nanosecondsPerSecond : int64 = 1_000_000_000L

    /// When a wait made at `now` with the relative timeout `timeout` times
    /// out; or the error the timeout answers.
    let private timeoutOf (now : int64) (timeout : TimespecArgument) : Result<FutexTimeout, UnixError> =
        match timeout with
        | TimespecArgument.Null -> Ok FutexTimeout.Untimed
        | TimespecArgument.Unreadable -> Error UnixError.EFAULT
        | TimespecArgument.Readable (seconds, nanoseconds) ->
            if seconds < 0L || nanoseconds < 0L || nanoseconds >= nanosecondsPerSecond then
                Error UnixError.EINVAL
            else
                // Linux turns the timespec into nanoseconds, saturating from
                // `KTIME_SEC_MAX` seconds up, and adds the time now, saturating
                // again where the sum overflows (`timespec64_to_ktime`,
                // `ktime_add_safe`; the rule's shape from source). Measured
                // (`docs/probes/huge-timeout`, on both sides of each
                // saturation): every such wait slept until a wake ended it, and
                // a signal under `SA_RESTART` ended it with `EINTR`, as it ends
                // a timed wait. By source Linux arms a timer near
                // `KTIME_SEC_MAX` seconds after boot, which no measurement can
                // tell from never, so a saturated wait has no deadline here.
                let ktimeSecondsMax = System.Int64.MaxValue / nanosecondsPerSecond

                if seconds >= ktimeSecondsMax then
                    Ok FutexTimeout.Unbounded
                else
                    let length = seconds * nanosecondsPerSecond + nanoseconds

                    if now > System.Int64.MaxValue - length then
                        Ok FutexTimeout.Unbounded
                    else
                        Ok (FutexTimeout.Until (now + length))

    /// `tryFutex` once `Entry` has admitted its caller.
    let private tryFutexIn<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (thread : 'Thread)
        (address : uint64)
        (op : int)
        (value : int)
        (word : UserBuffer)
        (timeout : TimespecArgument)
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

        // Measured on Linux 6.18.5 (`docs/probes/futex`, the "wait-screen",
        // "wake-screen" and "range" rows): a wait copies and screens its
        // timeout, then its address's alignment, then whether the word lies
        // in user space, then reads the word; a private wake screens the
        // alignment and the range, and reads no memory.
        let aligned = address % 4UL = 0UL

        let outsideUserSpace =
            UserBufferCheck.faultsBeforeOperation (UnixMachineState.userBufferCheck system.Machine) address 4UL

        if op = FutexWaitPrivate then
            match timeoutOf system.Scheduling.NanosecondsSinceBoot timeout with
            | Error error -> failed error
            | Ok timeout ->

            if not aligned then
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
                    Timeout = timeout
                    System = system
                }
                |> CallProgress.NeedsCopyIn
                |> Ok
        elif op = FutexWakePrivate then
            if not aligned then
                failed UnixError.EINVAL
            elif outsideUserSpace then
                failed UnixError.EFAULT
            else

            // Measured (the "count" rows): a wake of 0 or fewer wakes one.
            let count = max value 1

            // Every waiter on the address that no wake has taken yet, asleep
            // or woken by something else and not yet finished, in the order
            // they parked: a waiter a signal or its timeout has woken keeps its
            // place until it runs (measured, the "race" rows).
            let taken =
                system.Threads
                |> Map.toList
                |> List.choose (fun (waiter, state) ->
                    match UnixThreadState.park state with
                    | Some ({
                                Syscall = ParkedSyscall.Futex wait
                            } as park) when wait.FutexAddress = address && not wait.TakenByWake ->
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
            (tryFutexIn (Caller.thread caller) address op value word timeout)
            system

    /// Linux's `futex(2)`, made by `caller` on the 32-bit word at `address`,
    /// for `FUTEX_WAIT_PRIVATE` (`op` 128) and `FUTEX_WAKE_PRIVATE` (129).
    ///
    /// `FUTEX_WAIT_PRIVATE` waits while the word at `address` holds `value`,
    /// for at most `timeout`, a relative time on the monotonic clock, or for
    /// ever if it is `TimespecArgument.Null`. A timeout of `KTIME_SEC_MAX`
    /// (9223372036) seconds or more, or one that ends past the last instant
    /// the clock can represent, never expires (`FutexTimeout.Unbounded`), but
    /// is still a timeout to a signal. `word` is the caller's memory at
    /// `address`. Once the timeout and the address have passed their screens
    /// (`EFAULT` for an unreadable timeout, `EINVAL` for a malformed one, then
    /// `EINVAL` for an address that is not a multiple of 4, then `EFAULT` for
    /// a word outside user space or a `word` that is `Unmapped`), the call
    /// stops where the kernel reads the
    /// word, and `futexWithWord` takes what it holds. The caller must read the
    /// word as it makes that call, with no store by any thread in between,
    /// since the kernel's read and its decision to sleep are one step.
    ///
    /// `FUTEX_WAKE_PRIVATE` takes up to `value` of the process's waiters on
    /// `address` off its queue, in the order they began to wait, and answers
    /// how many it took. A `value` of 0 or less takes one. It reads no memory,
    /// so `word` and `timeout` are not looked at, and an address no memory
    /// backs answers 0 unless it lies outside user space (`EFAULT`), as a
    /// misaligned one answers `EINVAL`. A taken waiter's wait answers 0 when it is finished
    /// (`UnixWait.finish`), whatever else has woken it.
    ///
    /// Throws `PlatformNotSupportedException` under the Darwin flavour, which
    /// has no `futex(2)`; `UnmodelledException` for any other `op`, and for a
    /// wait whose `word` is `Opaque`; and `ArgumentException` for a wait whose
    /// `word` is `Addressless` or `Unmapped` at an address other than
    /// `address`.
    let futex<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (address : uint64)
        (op : int)
        (value : int)
        (word : UserBuffer)
        (timeout : TimespecArgument)
        (system : UnixSystem<'Thread, 'Handler>)
        : CallProgress<PausedFutexWait<'Thread, 'Handler>, SyscallOutcome * UnixSystem<'Thread, 'Handler>>
        =
        tryFutex caller address op value word timeout system
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

        let parked =
            ParkedSyscall.Futex
                {
                    FutexAddress = paused.Address
                    FutexTimeout = paused.Timeout
                    TakenByWake = false
                }

        // A wait whose deadline has already come still sleeps before it
        // answers `ETIMEDOUT` (measured, the "switches" rows: a voluntary
        // context switch for every one of 1000 waits with a zero timeout), so
        // it parks with its condition already holding, which `parkWaiting`
        // would report as a bug.
        let asleep =
            match paused.Timeout with
            | FutexTimeout.Until deadline when deadline <= system.Scheduling.NanosecondsSinceBoot ->
                Parking.park paused.Thread parked system
            | FutexTimeout.Until _
            | FutexTimeout.Untimed
            | FutexTimeout.Unbounded -> Parking.parkWaiting paused.Thread parked system

        Ok (SyscallOutcome.WouldBlock (WakeCondition.ofPark parked), asleep)

    /// `futexWithWord`, with a refusal answered as the `Error` rather than
    /// raised.
    let internal tryFutexWithWord<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (word : uint32)
        (paused : PausedFutexWait<'Thread, 'Handler>)
        : Result<SyscallOutcome * UnixSystem<'Thread, 'Handler>, FutexRefusal>
        =
        Entry.resume (Shape.result Shape.withSystem) (tryFutexWithWordIn word paused)

    /// The rest of the `FUTEX_WAIT_PRIVATE` `paused` stopped: `word` is what
    /// the word at its address holds, read as this is called. See `futex`.
    ///
    /// A word other than the value the wait expects answers `EAGAIN`.
    /// Otherwise the calling thread parks, answering
    /// `SyscallOutcome.WouldBlock`, and `finishFutexWait` (or `UnixWait.finish`)
    /// finishes the call once `UnixWait.wake` has woken it.
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

        // Measured on Linux 6.18.5 (`docs/probes/futex`, the "race" rows), the
        // waiter held off its CPU until all had happened: a wait a wake took
        // answers 0 though a signal or its timeout came first, and the
        // signal's handler runs as it returns; and a timeout beats a signal.
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

    /// Finish the `FUTEX_WAIT_PRIVATE` `caller` parked in, once `UnixWait.wake`
    /// has woken it.
    ///
    /// Answers 0 if a `FUTEX_WAKE_PRIVATE` took the waiter, whatever else woke
    /// it; then `ETIMEDOUT` if its deadline has passed; and otherwise the call
    /// is interrupted by a signal (`SyscallOutcome.Interrupted`), and the
    /// thread's return to user mode (`UnixSignal.onReturnToUser`) says whether
    /// it fails with `EINTR` or restarts. A wait with no timeout restarts under
    /// a handler installed with `SA_RESTART`; one with a timeout, even one that
    /// never expires, never does. A
    /// restarted wait reads its word again, so the caller makes the call again
    /// with the arguments it first made it with.
    ///
    /// Throws `UnmodelledException` for a wait with a deadline that a signal
    /// woke, where by now the thread would take no signal as it returned to
    /// user mode: Linux restarts such a wait with its first deadline, which a
    /// call made again does not have. A wait whose timeout never expires
    /// restarts then, as one with no timeout does.
    let finishFutexWait<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality>
        (caller : Caller<'Thread>)
        (system : UnixSystem<'Thread, 'Handler>)
        : SyscallOutcome * UnixSystem<'Thread, 'Handler>
        =
        tryFinishFutexWait caller system
        |> Refusal.orRaise "UnixFutex.finishFutexWait" FutexRefusal.kind FutexRefusal.describe
