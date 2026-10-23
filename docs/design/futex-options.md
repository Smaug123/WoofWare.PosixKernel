# `futex`: options

*Design note, 2026-10-17, at `origin/main` `267eef6`. Design item D5 of `reserved-union-cases.md`, which left open whether blocks inside the process move into the kernel at all. Patrick decided on 2026-10-17 that Linux's `futex` belongs in the kernel ("long-term correct"), with a minimal private wait and wake subset, provided it is sound and every call outside it refuses loudly. The design below was reviewed by a second model (Fable) before the probe was written; its findings are folded in. The probe is `docs/probes/futex/futex.c`, with its output on Linux 6.18.5 (aarch64, glibc 2.41, root in Apple's `container --cap-add ALL`, 5 CPUs) beside it, run three times with the same rows each time (timings aside). Every row below was measured unless it says "source".*

## 0. Summary

- **What a client needs.** .NET 11's CoreLib on Linux, and only on Linux, blocks its low-level lock and its thread pool's semaphore on raw futexes (`LowLevelThreadBlocker`, under `LowLevelLock` and `LowLevelLifoSemaphore`; so the wait subsystem's global lock too). It makes exactly three calls (`src/native/libs/System.Native/pal_threading.c:163-190` in dotnet/runtime): `FUTEX_WAIT_PRIVATE` with no timeout, `FUTEX_WAIT_PRIVATE` with a relative `CLOCK_MONOTONIC` timeout, and `FUTEX_WAKE_PRIVATE` of 1. On Darwin it still uses a mutex and condition variable, which stay the client's.
- **Recommendation.** One new syscall, `futex`, under Linux only, taking the raw `op` word and decoding it in the kernel. It models `FUTEX_WAIT_PRIVATE` and `FUTEX_WAKE_PRIVATE` and refuses every other operation. A wait parks as `ParkedSyscall.Futex`. A wake marks the waiters it takes *on their own parks*, and a new primitive, `WakePrimitive.FutexWakeTaken`, holds for a marked park, so `UnixWait.wake` stays the one way a thread wakes (§4.2, option A).
- **Measured rules the model must hold** (§1, §2): the screen order; FIFO waking; a wake of `n ≤ 0` wakes one; a taken waiter answers 0 whatever else woke it; a timeout beats a signal; a restarted wait reads the word again; a private key is per address space.
- **One rule the kernel cannot follow alone** (§4.4): a restarted wait reads the word again, and the word is the client's. So a restart is handed to the client, which makes the call again; where that cannot keep the call's deadline, the kernel refuses.
- **PRs** (§7): F1, this note and the probe; F2, the library; F3, the client.
- **Questions for Patrick** (§8): whether a zero timeout parks; whether a wait whose signal has gone by its finish is refused when timed; the call's shape.

## 1. What was measured

`W` is a thread in `FUTEX_WAIT_PRIVATE`; "the word" is the 32-bit word at its address. Sections are the probe's.

| row | Linux 6.18.5 |
| --- | --- |
| **wait-screen**: which error wins | an unreadable timespec (`EFAULT`), then a bad timespec (`tv_nsec` ∉ [0, 1e9) or `tv_sec` < 0: `EINVAL`), then a misaligned address (`EINVAL`), then an address outside user space (`EFAULT`, the "range" rows), then an unreadable word (`EFAULT`, the null address included), then a word that differs from `val` (`EAGAIN`). So a misaligned address with an unmapped timespec is `EFAULT`; an unmapped word with a bad timespec is `EINVAL`; a mismatch with a zero timeout is `EAGAIN` |
| a matching word and a 10 ms timeout | `ETIMEDOUT` at 10 ms |
| a matching word and a zero (or 1 ns) timeout | `ETIMEDOUT`, **after sleeping**: 1000 voluntary context switches in 1000 calls (999 or 1000 for 1 ns, across runs), about 70 µs each (the default 50 µs timer slack). A mismatch with a zero timeout: `EAGAIN`, no switch |
| a timeout too large for the clock (`tv_sec` 9223372035, 9223372036, `INT64_MAX`) | no error: the wait sleeps until a wake ends it (saturated, as `nanosleep`'s deadline is in `nanosleep-options.md`) |
| **compare** | of 32-bit words: a word of `0xFFFFFFFF` matches `val` -1, and `0x80000000` matches `INT_MIN` |
| **wake-screen** | a misaligned address: `EINVAL`. An unmapped address, the null address, and an address with no waiters: 0. A private wake reads no memory |
| **range**: addresses no mapping backs, on this kernel's 48-bit user address space | a wake at 2^48 − 8 or 2^48 − 4 answers 0; at 2^48, 2^48 + 4, 2^63 or 2^64 − 4, `EFAULT`, as a wait at each answers `EFAULT`. So the four bytes at the address must lie in user space, even for a wake. A misaligned address past the limit is `EINVAL`, and a bad timespec with one is `EINVAL`: alignment and the timespec are screened first |
| **count**: `FUTEX_WAKE n` with 0, 1 and 3 waiters | returns how many it woke. `n` of 1, 2, `INT_MAX` wake that many (or all there are). **`n` of 0, -1, -2 and `INT_MIN` each wake one**, when there is one |
| **order**: A, B, C parked in that order (each asleep in `__futex_wait` before the next starts), `wake 1` ×3 | A, B, C, in 10 trials of 10 |
| the same, each waiter waiting again once woken, `wake 1` ×6 | A, B, C, A, B, C in 10 of 10: a waiter that waits again goes to the back |
| `wake 2` then `wake 1` | A and B, then C, in 5 of 5 |
| **signal**: a handler; `pthread_kill` 100 ms into W's wait; `wake 1` at 300 ms | untimed, flags 0: `EINTR` at 100 ms. **Untimed, `SA_RESTART`: restarted**, and the wake at 300 ms ends it with 0. **Timed (2 s), with or without `SA_RESTART`: `EINTR`** |
| the same, the handler storing 1 to the word | untimed, flags 0: `EINTR`. **Untimed, `SA_RESTART`: `EAGAIN`** at 100 ms: the restarted wait read the word again. Timed, `SA_RESTART`: `EINTR` |
| `SIG_IGN`; `SIGURG` at its default (ignore); the signal blocked by W | none ends the wait: each ends at the wake, with 0 |
| **stop**: W's process stopped 100 ms in and continued at 200 ms, no handler | untimed: restarted, and ended by the wake at 600 ms with 0. **With 1 stored to the word during the stop: `EAGAIN` at 200 ms**, timed or not. **With a 300 ms timeout: `ETIMEDOUT` at 300 ms**: the restart kept the call's deadline |
| **race**: on one CPU, a sender at `SCHED_FIFO` 50 and W at 10, so nothing W does happens until the sender sleeps. `ran-early=0` in every trial (the control) | |
| a signal (handler), then `wake 1`, before W runs | the wake returns 1, W returns **0**, and the handler runs: untimed with flags 0, untimed with `SA_RESTART`, and timed; 5 of 5 each |
| W's 10 ms timeout expires, then `wake 1`, before W runs | the wake returns 1, W returns **0**; 5 of 5 |
| W's 10 ms timeout expires, then a signal, before W runs | W returns **`ETIMEDOUT`**, and the handler runs; flags 0 and `SA_RESTART`, 5 of 5 each |
| A then B parked; A signalled (or A's timeout expired); `wake 1`; all before either runs | the wake takes **A**: A returns 0 and B sleeps on; 5 of 5 each. A waiter something else has woken, but which has not yet run, keeps its place |
| A then B parked; `wake 1`; `wake 1` | 1 and 1: the second wake takes B. A waiter is taken off the queue by the wake itself, before it runs |
| **xproc**: a child waits privately on a `MAP_SHARED` word; its parent wakes the word 100 ms in | a private wake and a shared wake each return 0, and the child times out at 300 ms. Control: a shared wait is woken by a shared wake (1, at 100 ms). A private key is the address space's |

From Linux 6.18's source (`kernel/futex/waitwake.c`), not measured, for the rule's shape: `futex_wait` sleeps, then asks `futex_unqueue`; if a wake has already taken it off the queue it returns 0, whatever else is pending; then `ETIMEDOUT` if its timer fired; then, with a signal pending, `-ERESTARTSYS` untimed or `-ERESTART_RESTARTBLOCK` timed (the restart block holds the absolute deadline). A restart runs the whole wait again, word read and all. The race and stop rows measure each of those outcomes.

## 2. What the measurements mean for the model

1. **One queue per (process, address).** A private key is the address space's (xproc), so a process's waiters on an address form one queue, and no other process can reach it. The kernel holds no word: the word is user memory, which is the client's.
2. **The queue is the futex parks on the key, in park order.** FIFO (order), and a waiter that waits again parks afresh at the back, which is what `Parking.park` already does with a fresh `ParkOrdinal`.
3. **A wake takes its waiters at once, and taking decides the answer.** A waiter taken by a wake returns 0 whether a signal or its timeout has also woken it; a waiter woken by anything else, but not yet run, keeps its place (race). So a wake chooses among every futex park on the key not yet taken, asleep or woken, from the front.
4. **`n ≤ 0` is `n = 1`.** Measured, so the model answers it rather than refusing it.
5. **The wait's answers, in order:** taken → 0; deadline passed → `ETIMEDOUT` (it beats a signal); a deliverable handler → `EINTR` if timed, `EINTR` or restart by `SA_RESTART` if untimed (`SignalRestartRule.RestartsUnderSaRestart`). Signals that are ignored or blocked never end it, which is `WakePrimitive.SignalDeliverable` exactly.
6. **A restart reads the word again**, with or without a handler, and a timed restart keeps its deadline (stop rows). The kernel cannot read the word, so only the client can make a restart (§4.4).
7. **A zero timeout sleeps.** Linux switches away and back before answering `ETIMEDOUT`, as a zero `nanosleep` does; a wake made in between would be taken (§8, Q1).
8. **A huge timeout saturates**, as `nanosleep`'s does: the deadline is `min(now + timeout, Int64.MaxValue)` nanoseconds since boot.

## 3. What the existing kernel decides for us

- **The park names its own deadline.** `WakeCondition.ofPark` is public and reads only the park (`nanosleep-options.md` §3.1), and `SyscallInterruption.ruleOf` must tell a timed wait from an untimed one, which it is given only the park to do. So `ParkedFutex` carries `FutexDeadline : int64 option`.
- **A park can be rewritten in place.** `UnixThreadTable.withPark` accepts a write that keeps the park's ordinal and state: a Darwin close rewrites the call it ends to `SleepTarget.EndedByClose`, and `WakePrimitive.EndedByClose` holds by reading the waiter's own park. A wake can mark its waiters the same way.
- **Only `UnixWait.wake` wakes.** `withPark` refuses any state change except through `markWoken`, and `wake`'s answer is how a client learns a thread woke.
- **A taken waiter's signal is not lost.** Finishing a park runs `OwedReturns.markIfDue`, so a signal that also woke the waiter is taken as the thread returns to user mode, with no interruption: "returns 0, and the handler runs".
- **The wake memo needs nothing.** A rewritten park is a new thread table, which `WakeMemo.readsSame` compares by reference.
- **No exclusive queue.** `ExclusiveWaitQueue` exists because a sweep sees only states and must pick one waiter per event. A wake that names its waiters has already picked.

## 4. Decisions, with options

### 4.1 Kernel or client — decided

The README's "Blocks inside the process" made futexes the client's "for now", with the kernel as the long-term plan. Patrick decided on 2026-10-17 to model them in the kernel. A client then has every blocked thread parked where the kernel can see it, so signals, deadlines and runnability come from one place. The alternative was for the client to keep its own futex queues, as PawPrint keeps its `LowLevelMonitor`; it needed no kernel work, and kept the client deciding how a signal or a deadline ends its own blocks.

### 4.2 How a wake reaches the waiter

- **A (recommended): the wake marks the park.** `ParkedFutex` carries `TakenByWake : bool` (or a two-case union). `futex(FUTEX_WAKE)` rewrites each chosen park in place with `TakenByWake = true`; `FutexWakeTaken` holds for a taken park; `UnixWait.wake` then wakes it as any other; the finishing call answers 0. A mark cannot exist without its park, needs no invariant of its own, and goes when the park goes (a process ending unparks every thread). A client can see it through `UnixThreadState.parkedIn`.
- **B: a per-process `Set<'Thread>` of taken waiters.** Passes the skill's "an absent key has a truthful reading" test, but makes "taken and not parked in a futex" representable, so `checkInvariants` needs a rule tying the two, and process end must clear it.
- **C: the wake sets `ParkState.Woken` directly.** Simplest to write, but a second way to wake a thread, which `withPark` forbids, and the client would never see these wakes in `UnixWait.wake`'s answer.

A is the repository's existing pattern and the only one with no state that can disagree with another.

### 4.3 The call's shape

- **A (recommended): the raw call.** `Syscall.Futex of address : uint64 * op : int * value : int * word : CopiedArgument<uint32> * timeout : TimespecArgument`, decoded in a new `UnixFutex`. As `fcntl` and `epoll_ctl` take the raw command, the kernel then owns the decoding and every refusal, and states POSIX values rather than a client's parse of them.
- **B: a parsed call** (`FutexCall = Wait of … | Wake of …`). Smaller, but the refusal of every other operation moves into the client.

`word` is what the client read at `address` as it made the call, in the same step, with no store by any thread in between; the kernel consults it only once the address has passed its screens, so a wake (which reads no memory) and a misaligned wait never need it. The `TimespecArgument` is raw (`Null | Readable of seconds * nanoseconds | Unreadable`), as `nanosleep-options.md` proposes and `KeventTimeout` already is, so that the kernel applies the measured screen order. `op` is refused unless it is exactly `FUTEX_WAIT_PRIVATE` (128) or `FUTEX_WAKE_PRIVATE` (129).

### 4.4 A restart reads the word again

When a signal interrupts a wait and the wait restarts, Linux runs it again from the top and reads the word again (signal and stop rows: `EAGAIN` when the word changed). The kernel's existing in-kernel re-park (`SyscallInterruption.ofPark` answering `Ok None` for `Ends Restarts`) would put the waiter back to sleep without that read, and later answer 0 where Linux answered `EAGAIN`: an answer no Linux run gives, if the word changed after the signal arrived. So:

- **With a handler** (untimed, `SA_RESTART`): the existing path is already right. The call answers `Interrupted`, the return to user mode settles `InterruptedCall.Restarts`, and the client makes the call again from the top, reading the word again.
- **Without a handler by the time the call finishes** (the signal that woke it has been discarded or blocked), untimed: the call answers `Interrupted` with `AtInterruption = Some Restarts` rather than re-parking, so the client makes it again. Exact.
- **The same, timed:** Linux restarts with the *original* deadline (stop row: `ETIMEDOUT` at 300 ms, not 400). The client can only remake the call with a relative timeout, which `InterruptedCall.Restarts` would make from the call's first arguments: a later deadline. **Option A (recommended): refuse** (`SyscallInterruptionRefusal`, a new case), loudly. It is reachable only when a handler was deliverable as the waiter woke and is gone by its finish. **Option B:** a public `InterruptedCall` case meaning "restart with this much of your timeout left", which the client honours. More complete, but a public case for one rare path. **Option C:** re-park in the kernel. Rejected: unsound, as above.

### 4.5 A zero timeout

See §8, Q1. Linux sleeps before answering (§1), as it does for a zero `nanosleep`, and the decision there (`nanosleep-options.md`, Q3) was that a zero-length Linux sleep parks. But `Parking.parkWaiting`'s Debug assertion fails for a park whose condition already holds, so either the futex arm parks with `Parking.park` and says why, or it answers `ETIMEDOUT` at once. Parking is truthful: a wake made before the thread runs is taken, and the thread answers 0. Answering at once is the schedule in which the timer fired before any other thread ran, and is a real answer too.

## 5. The proposed shape

```fsharp
// UnixThread.fs, appended to ParkedSyscall
| Futex of ParkedFutex

type ParkedFutex =
    {
        /// The address the waiter waits on; with the waiter's process, the queue's key.
        FutexAddress : uint64
        /// Nanoseconds since boot at which the wait times out, if it has a timeout.
        FutexDeadline : int64 option
        /// Whether a `FUTEX_WAKE` has taken this waiter off its queue.
        TakenByWake : bool
    }

// WakePrimitive.fs, appended
/// A `FUTEX_WAKE` has taken the waiting thread off the queue of the futex it
/// waits on. Names no kernel object, as `SignalDeliverable` names none.
| FutexWakeTaken

// Syscall.fs, appended to Syscall and SteppedCall
| Futex of address : uint64 * op : int * value : int * word : CopiedArgument<uint32> * timeout : TimespecArgument
| Futex of outcome : SyscallOutcome * system : UnixSystem<'Thread, 'Handler>   // as FLock's: an answer, or WouldBlock
```

- **Field labels:** none is a label another public record has (`Address` is `Ipv4Endpoint`'s and `Ipv6Endpoint`'s, `Deadline` several parks'), which `TestSurface`'s record-label check requires: F# resolves a shared label to the record declared last, so a reused one could change what a client's code means.
- **Condition:** `AnyOf [FutexWakeTaken; SignalDeliverable]`, plus `DeadlinePassed d` for a timed wait.
- **Finishing call** (`UnixFutex.tryFinishFutexIn`, reached by `UnixWait.finish`): taken → 0; deadline passed → `ETIMEDOUT`; a signal → as `SyscallInterruption` says, with `ruleOf` answering `RestartsUnderSaRestart` untimed and `FailsWithEintr` timed, and `withoutHandler` answering as §4.4; otherwise sleep again (a spurious wake, which `futex_wait` also answers by sleeping again).
- **Wake:** among the caller's process's futex parks on `address` that are not taken, in park order, rewrite the first `max(n, 1)` as taken; answer the count.
- **Darwin:** the call does not exist, so `PlatformNotSupportedException`, as epoll's are.
- **Refused** (`UnmodelledException`): every `op` but the two; a word the client cannot produce (`CopiedArgument.Opaque` or `Addressless`) where it would be compared. Nothing a refusal leaves behind can mislead the modelled calls, since a refused call changes no state.

## 6. Blast radius

The `ParkedSyscall` matches `nanosleep-options.md` §6 lists, plus `UnixThreadTable.withPark`'s `kind`, `WakeCondition.ofPark` and `holds`, `Parking.exclusiveQueueOf` (`None`), `UnixWait.finish`, `FinishedCall` and `ViewFinishedCall`, `FinishRefusal`, `SyscallInterruption.ruleOf` and `withoutHandler`, and `UnixSystem.step` and `checkInvariants`. `SurfaceBaseline.txt` is regenerated, with every case appended at its union's end. The README's park and syscall tables, and "Blocks inside the process", which becomes: Linux's `futex` is the kernel's; Darwin's `__psynch_*` and `__ulock_*`, and the C library's mutexes and condition variables built on them, are the client's. PawPrint's `GuestLocation.fs` matches `ParkedSyscall` case by case.

## 7. PRs

1. **F1:** this note and the probe, with its output.
2. **F2: the library.** `UnixFutex.fs` and the arms of §6.
   - `TestFutex`: every row of §1 the model answers, transcribed and citing the probe; the race rows as states (a park woken by a signal or a deadline, then a wake, then the finish).
   - A property test against a reference model: per (process, address) a FIFO list of waiters, each with a taken flag, its deadline and whether it has been woken; a wake takes the first `max(n, 1)` untaken entries whatever their woken state; a finish answers taken, then timed out, then the signal rule. Over generated sequences of waits, wakes, signals, mask changes, clock advances and finishes, across threads and two processes, the kernel and the model give the same answers.
   - Mutation checks: wake from the back; let a signal beat a taken mark; let a signal beat an expired deadline; key the queue on the address alone; re-park on a restart.
   - The README and the skill's "Where does this fact live?" (which lists `futex` as the client's).
3. **F3: the client.** PawPrint routes `SystemNative_LowLevelFutex_*` through `UnixSystem.step`, once a package with F2 is published.

## 8. Questions for Patrick

1. **Should a zero (or 1 ns, or already-passed) timeout park,** as measured and as was decided for `nanosleep`, or answer `ETIMEDOUT` at once? I recommend parking, through `Parking.park` with a comment where `parkWaiting`'s assertion would otherwise fire.
2. **A timed wait whose waking signal has gone by its finish:** refuse (§4.4 A, recommended), or add a public "restart with what is left of the timeout" case (B)?
3. **The call's shape:** the raw call (§4.3 A, recommended), or a parsed one (B)?

## Decision (Patrick, 2026-10-17)

- **Q1:** a zero (or 1 ns, or already-passed) timeout parks, as measured and as for `nanosleep`; the futex arm parks through `Parking.park`, saying why where `parkWaiting`'s assertion would fail.
- **Q2:** refuse a timed wait whose waking signal has gone by its finish (§4.4 A).
- **Q3:** the raw call, as `fcntl` takes its command (§4.3 A).
