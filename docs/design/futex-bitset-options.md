# `futex` bitset waits and wakes: options

*Design note, 2026-10-18, at `origin/main` `dafb8c5`. Follows `futex-options.md`, which modelled `FUTEX_WAIT_PRIVATE` and `FUTEX_WAKE_PRIVATE` and refused every other operation. glibc's `pthread_cond_wait`, `sem_wait` and timed locks wait with `FUTEX_WAIT_BITSET_PRIVATE` (op 137, or 393 with `FUTEX_CLOCK_REALTIME`), so a replay of any glibc program is refused at its first condition variable: `docs/design/devices-raw/out/linux-dotnet-device-usage.strace` has 13 such waits. Patrick ruled out, on 2026-10-18, any operation that has the kernel read or write the caller's memory beyond the word a wait compares (`FUTEX_WAKE_OP`, the PI operations, robust lists, `clear_child_tid`). The probe is `docs/probes/futex-bitset/futex-bitset.c`, with its output on Linux 6.18.5 (aarch64, glibc 2.41, root in Apple's `container --cap-add ALL`, 5 CPUs) beside it, run three times with the same rows each time (timings aside). Every row below was measured unless it says "source".*

## 0. Summary

- **Scope.** `FUTEX_WAIT_BITSET` and `FUTEX_WAKE_BITSET`, private, with `FUTEX_CLOCK_REALTIME` on the wait; and Linux's own answer (`ENOSYS`) to every `op` it does not decode. Non-private operations, requeue, `FUTEX_WAKE_OP` and the PI operations stay refused.
- **What a bitset adds.** A 32-bit mask on each waiter and each wake; a wake takes, in queue order, the first `max(n, 1)` waiters whose mask shares a bit with its own. A plain wait or wake has the mask `FUTEX_BITSET_MATCH_ANY`. A mask of 0 is `EINVAL`.
- **What an absolute timeout adds.** The deadline is an instant on `CLOCK_MONOTONIC`, or on `CLOCK_REALTIME` with the flag. A restart keeps it, so the client making the call again with its first arguments restarts it exactly, and the refusal `futex-options.md` §4.4 chose for a timed relative wait is not needed for these waits.
- **The call's shape** (§3.1): one more argument, the raw `val3`.
- **One question for Patrick** (§4): how the park records an absolute deadline.

## 1. What was measured

| row | Linux 6.18.5 |
| --- | --- |
| **decode**: how `op` is read | `cmd = op & ~(FUTEX_PRIVATE_FLAG \| FUTEX_CLOCK_REALTIME)`. For a command that takes a timeout (`WAIT` 0, `LOCK_PI` 6, `WAIT_BITSET` 9, `WAIT_REQUEUE_PI` 11, `LOCK_PI2` 13), the timeout is screened first, as for `FUTEX_WAIT_PRIVATE` (`EFAULT` unreadable, then `EINVAL` malformed). Then `FUTEX_CLOCK_REALTIME` on any command but 9, 11 and 13 is `ENOSYS` (measured on 0, 1, 3, 4, 5, 6, 7, 8, 10, 12). Then an unknown command is `ENOSYS`, with no timeout read: 2 (`FUTEX_FD`), 14, 15, 127, 512, and any `op` with a bit set outside the command's low bits and the two flags (649, 1153, -1, `INT_MIN`, `0x80000089`) |
| **wait-screen**, 137 and 393, against 9 address kinds × 7 timeouts × mask any or 0 (274 rows with the wake-screen, all matching this rule) | an unreadable timespec (`EFAULT`), then a malformed one (`EINVAL`), then **a mask of 0 (`EINVAL`)**, then a misaligned address (`EINVAL`), then an address outside user space or an unreadable word (`EFAULT`), then a word other than `val` (`EAGAIN`). A matching word with a deadline 10 ms off: `ETIMEDOUT` at 10 ms, on either clock. A mask of 0 with an address outside user space is `EINVAL` |
| **wake-screen**, 138 | **a mask of 0 is `EINVAL`, before the address is screened** (even past the user address limit); then a misaligned address `EINVAL`; then outside user space `EFAULT`; an unmapped or null address with no waiters 0. A wake reads no memory |
| **switches**: 1000 waits whose absolute deadline has passed ({0, 0}, or the clock's reading as the call is made), either clock | `ETIMEDOUT` every time, **after a voluntary context switch every time** (999 or 1000 across runs). About 4 µs each for {0, 0}, about 77 µs for "now" (the timer slack), as for a relative zero (the control). A mismatch: `EAGAIN`, no switch |
| **huge**: an absolute `tv_sec` of 9223372035, 9223372036 or `INT64_MAX`, either clock | no error; the wait sleeps until a wake 100 ms in ends it (0). 9223372035 s is a finite instant some 292 years after boot or the epoch; from 9223372036 (`KTIME_SEC_MAX`) Linux saturates (source) |
| **match**: one waiter of mask m, `FUTEX_WAKE_BITSET` 1 of mask k, m and k each of 1, 2, 3 or 4, `0x80000000`, any | taken exactly when `m & k ≠ 0`; the wake answers 1 or 0. A `FUTEX_WAIT_PRIVATE` waiter is taken by a bitset wake of mask 1 and of `0x80000000`; a bitset waiter of mask 1, or a realtime one of mask 2, by `FUTEX_WAKE_PRIVATE` |
| **order**: A (mask 1), B (2), C (1), D (any) parked in that order | wake mask 1, n 1, three times: A, then C, then D; then mask 2: B (5 of 5). Mask 1 with n 0, -1 or `INT_MIN`: A alone; mask 2, n 0: B; mask 4, n 0 or `INT_MAX`: D alone; mask 1, n `INT_MAX`: A, C, D (3). Mask 3, n 2, twice: A B, then C D. Mask any, n 2, then mask 1, n 1: A B, then C |
| **signal**: a handler; signal at 100 ms; `FUTEX_WAKE_PRIVATE` 1 at 300 ms; both clocks | untimed: `EINTR` with flags 0, restarted under `SA_RESTART` (ended by the wake with 0), and `EAGAIN` under `SA_RESTART` if the handler stored to the word. With a deadline 2 s off: `EINTR`, with or without `SA_RESTART`, stored to or not |
| **stop**: stopped at 100 ms, continued at 200 ms, no handler; wake at 600 ms; both clocks | untimed: restarted, ended by the wake (0); with 1 stored during the stop, `EAGAIN` at 200 ms. **A deadline 300 ms in: `ETIMEDOUT` at 300 ms**, the deadline the call named; with a store, `EAGAIN` at 200 ms |
| **race** (on one CPU, the sender at `SCHED_FIFO` 50 and the waiter at 10; `ran-early` 0 in every trial), both clocks, `SA_RESTART` | a signal then a wake, before the waiter runs: 0, and the handler runs. The deadline passes, then a wake: 0. The deadline passes, then a signal: `ETIMEDOUT`, and the handler runs. 3 of 3 each |

From Linux 6.18's source (`kernel/futex/syscalls.c`, `waitwake.c`), for the rule's shape only: `FUTEX_WAIT` is `futex_wait` with the mask `FUTEX_BITSET_MATCH_ANY` and its relative timeout turned into an absolute monotonic one at entry, so a bitset wait and a plain one share every rule `futex-options.md` §1 measured: the queue, the race, the restart reading the word again. `FUTEX_WAKE` is `futex_wake` with `FUTEX_BITSET_MATCH_ANY`.

## 2. What the measurements mean for the model

1. **A mask on each waiter.** `ParkedFutex` gains the waiter's mask, `0xFFFFFFFF` for a `FUTEX_WAIT_PRIVATE`. A wake takes among the process's untaken futex parks on its address those whose mask meets its own, in park order, the first `max(n, 1)` (order rows). A plain wake has the mask `0xFFFFFFFF`.
2. **A mask of 0 is screened** after the timeout and before the address, on a wait; first of all on a wake.
3. **The absolute deadline is the instant named.** On `CLOCK_MONOTONIC` that is nanoseconds since boot as the kernel counts them (`UnixSchedulingState.NanosecondsSinceBoot`, which `clock_gettime(CLOCK_MONOTONIC)` reads). On `CLOCK_REALTIME` it is the realtime instant less `UnixMachineState.BootTime`, which is exact because the modelled realtime clock never steps (`UnixMachine.fs`, `BootTime`). `BootTime` is never before the epoch, so the subtraction cannot overflow; a realtime instant before boot has passed.
4. **Saturation.** `tv_sec ≥ KTIME_SEC_MAX` never times out (`FutexTimeout.Unbounded`), as for a relative wait; any smaller absolute deadline is an instant, however far off.
5. **A deadline that has passed still sleeps** before answering `ETIMEDOUT` (switches rows), as a relative zero does: the wait parks through `Parking.park`, as `futex-options.md` Q1 decided.
6. **A signal**: untimed, `SignalRestartRule.RestartsUnderSaRestart`; timed, `FailsWithEintr` (signal rows). Exactly the relative wait's rule.
7. **A restart with no handler keeps the named deadline** (stop rows). The client making the call again with its first arguments names the same instant, so the call answers `Interrupted` with `Restarts`, exactly; no refusal.
8. **`ENOSYS` is Linux's answer, not a gap in the model.** An `op` Linux does not decode, or `FUTEX_CLOCK_REALTIME` on a command that does not take it, answers `ENOSYS` (after the timeout screen where the command takes a timeout). A known command this kernel does not model is still refused, as is any operation without `FUTEX_PRIVATE_FLAG`.

## 3. Decided by the existing design

### 3.1 The call's shape

`futex-options.md` Q3 chose the raw call. The bitset is the syscall's sixth argument, `u32 val3`, so `UnixFutex.futex` and `Syscall.Futex` gain `val3 : uint32` after `timeout`. The fifth, `uaddr2`, is read by no modelled operation and stays out; a refused operation that reads it is refused before it would be. A `FUTEX_WAIT_PRIVATE` or `FUTEX_WAKE_PRIVATE` does not read `val3`.

### 3.2 Unchanged

The word (`UserBuffer`, then `futexWithWord`), `WakePrimitive.FutexWakeTaken`, the finishing call's order (taken, then deadline, then signal), and the race rules carry over, the source saying the code is the same and the race rows agreeing.

## 4. The question: how the park records an absolute deadline

The park must say, without reading the machine (`WakeCondition.ofPark` reads only the park), when the wait times out and whether the call made again restarts it exactly. `FutexTimeout` is public.

- **A (recommended): one more `FutexTimeout` case, `At of nanosecondsSinceBoot : int64`**, appended. A realtime deadline is converted as the call is made. `Until` keeps meaning "a relative timeout, made absolute", whose restart is refused when no handler runs; `At` means "the instant the call named", whose restart is the call made again. Smallest change. If the realtime clock ever steps (`clock_settime`), a realtime wait must move with it, and `At` will not say which waits are realtime: that change would add a case then.
- **B: keep the clock.** `AtMonotonic of nanosecondsSinceBoot : int64` and `AtRealtime of realtime : UnixTimestamp * nanosecondsSinceBoot : int64`, the second carrying both the named instant and its conversion. A future `clock_settime` can find and move every realtime wait. But nothing in the model steps the realtime clock, nothing reads the extra field, and the two halves of `AtRealtime` must be kept in agreement by an invariant.
- **C: a flag beside the timeout** (`ParkedFutex.DeadlineNamed : bool`). Keeps `FutexTimeout` as it is, but makes "untimed and named" representable.

A is the smallest that is exact today; B is what a stepping realtime clock would need, and 1.0 is close, after which adding B's case would be a major version.

## 5. Tests

- `TestFutex`: the decode, screen, match and order rows transcribed, citing the probe; the signal, stop and race rows as states, for both clocks.
- The reference-model property test gains masks: a wake takes the first `max(n, 1)` untaken waiters on the key whose mask meets its own; and absolute deadlines on both clocks.
- Mutation checks: ignore the mask; screen the mask after the address; let a wake of mask 0 answer 0; convert a realtime deadline without `BootTime`; refuse a timed absolute restart; answer an unknown `op` by refusing.

## Decision (Patrick, 2026-10-18)

- **§4:** A. `FutexTimeout` gains `At of nanosecondsSinceBoot : int64`, appended; a realtime deadline is converted as the call is made.
