# `nanosleep` and `clock_nanosleep`: options

*Design note, 2026-10-11, at `origin/main` `7d700bb6`. Design item D2 of `reserved-union-cases.md`, and the `nanosleep` row of `signal-masks-and-sleep-scoping.md` §3. Patrick asked on 2026-10-11 for `nanosleep` to be designed now, so that its park can be reserved before 1.0 with the right fields. The probe is on branch `pk-nanosleep-probe` (commit `2d91f384`, no PR): `docs/plans/2026-08-23-posix-kernel-extraction/nanosleep-edges.c`, with its output on Darwin 27.0.0 (arm64, uid 501) and Linux 6.18.5 (aarch64, glibc 2.41, root in Apple's `container` with `CAP_SYS_TIME`). Every row below was measured unless it says "source".*

## 0. Summary

- **Recommendation: option B.** Add `ParkedSyscall.Sleep of ParkedSleep`, a public record carrying the deadline and what an interruption reports. No new `WakePrimitive`: `DeadlinePassed` and `SignalDeliverable` cover it.
- **Reserve now (PR R4, release work):**

  ```fsharp
  [<RequireQualifiedAccess>]
  type SleepRemainder =
      | Unreported
      | Reported of until : int64 * destination : UserBuffer

  type ParkedSleep =
      {
          Deadline : int64
          Remainder : SleepRemainder
      }

  // appended to ParkedSyscall, after SigSuspend:
      | Sleep of ParkedSleep
  ```

- **Then (PR N1, post-release unless Patrick says otherwise):** a new module `UnixSleep` with `nanosleep`, `clockNanosleep`, `clockNanosleepSyscall` and `finishSleep`. Optionally (PR N2) a raw-libc arm in PawPrint. No BCL path reaches either call.
- **Option A, which D2 asked about (no fields, state kept beside the park as `sigsuspend` keeps its mask), is rejected.** `WakeCondition.ofPark` is public and reads only the park. A fieldless park cannot give it the deadline, so `ofPark` would either lie or have to take the system. And unlike `sigsuspend`'s saved mask, nothing a sleep holds outlives its park.
- **A measurement that lowers the risk of B (§3.3).** A client that was not recompiled keeps working when a record gains a field, as long as it only reads the record. Only code that *builds* the record breaks, with `MissingMethodException`. So a field forgotten now costs construction sites (tests, and nothing else) rather than every reader.
- **Questions for Patrick (§7):** will the realtime clock ever be stepped; is a timer slack of 0 the right Linux answer; should a zero-length Linux sleep park; record payload (B) or opaque payload (C).

## 1. What was measured

| row | Linux 6.18.5 | Darwin 27.0 |
| --- | --- | --- |
| `tv_nsec` ∉ [0, 1e9), or `tv_sec` < 0 | EINVAL at once; `rem` untouched, even an unmapped one | the same |
| request null | EFAULT | EINVAL (the C library checks) |
| request unmapped | EFAULT | the process dies of SIGSEGV (the C library reads it) |
| a sleep that runs its course | 0; `rem` never written; an unmapped `rem` not noticed | the same |
| a caught signal, 100 ms into 2 s | EINTR | EINTR |
| the same, `SA_RESTART` | EINTR (never restarted) | EINTR (never restarted) |
| `rem` after EINTR | deadline − now **+ the task's timer slack**: excess 55–63 µs at the default 50 µs, 5–17 µs at 1 ns, 1.006–1.011 ms at 1 ms (`prctl(PR_SET_TIMERSLACK)`) | deadline − now, to within 1–3 µs, with nanosecond digits |
| `rem` null, interrupted | EINTR | EINTR |
| `rem` unmapped, interrupted | **EFAULT** (the sleep was interrupted, and the copy failed) | the process dies of SIGSEGV (the C library writes it) |
| `rem` the same pointer as the request | as any other `rem` | the same |
| huge request (2^32+10 s, 2^33+10 s, 9223372035 s … `INT64_MAX`) | the deadline **saturates at KTIME_MAX** (2^63−1 ns since boot): every request past it leaves `rem` = KTIME_MAX − uptime | the sleep never ends early (not at 2^32 s, nor where `tv_sec` × 1e9 passes 2^64). But `rem` is computed **modulo 2^32 s**: 2^32+10 s leaves 9.9 s, and 2^32+1 s interrupted after 3 s leaves **0**, with EINTR |
| which clock Darwin's `rem` counts from | — | the uptime: 2^32−1e9 s leaves 3294967295.9 s, which would have wrapped if counted from the epoch |
| zero-length or 1 ns `nanosleep`, ×1000 | **blocks every time**: 1000 voluntary switches, about 70 µs each (the 50 µs slack) | zero: returns with **no switch**; 1 ns: one involuntary switch each |
| absolute `clock_nanosleep` in the past, ×1000 | blocks every time: 1000 voluntary switches, 3–5 µs each | — |
| an ignored signal, one at a default that ignores (URG), a blocked one | none ends the sleep | the same |
| stopped 100 ms in, continued 500 ms later, no handler for CONT | 0 at the original deadline (2 s), or at the continue if later. **`rem` written anyway**, as at the stop | 0 at the original deadline; `rem` not written |
| the same, with a handler for CONT | EINTR, `rem` as at the stop. Still EINTR when the deadline passed during the stop | EINTR, `rem` as at the continue. **0** when the deadline passed during the stop |
| `clock_nanosleep` clocks | sleeps on REALTIME (0), MONOTONIC (1), PROCESS_CPUTIME (2, on CPU time), BOOTTIME (7), TAI (11). THREAD_CPUTIME (3): EINVAL from glibc, **EOPNOTSUPP** from the system call. MONOTONIC_RAW and both COARSE (4–6): EOPNOTSUPP. The ALARM clocks (8, 9): EPERM without `CAP_WAKE_ALARM`. Every other id from −2 to 24, aux 16–23 included: EINVAL | **no such function**: the macOS 27 SDK's `<time.h>` declares `clock_getres`, `clock_gettime` and `clock_settime` only |
| its return convention | glibc returns the error number and leaves `errno` alone; the system call returns −1 and sets `errno` | — |
| its screens, in order | the clock (EINVAL), whether it can sleep (EOPNOTSUPP), reading the request (EFAULT), the request (EINVAL) | — |
| its flags | only bit 0 (`TIMER_ABSTIME`) is read: 2, −2 and 256 sleep relative; 3 and −1 absolute | — |
| `TIMER_ABSTIME` | ends on time on MONOTONIC, REALTIME, BOOTTIME and TAI; a deadline in the past returns 0 at once; a signal gives EINTR with or without `SA_RESTART`, and **`rem` is never written** | — |
| relative `clock_nanosleep`, interrupted | EINTR with `rem`, as `nanosleep` | — |
| realtime clock stepped 100 ms in | an absolute REALTIME sleep follows the step: +10 s past its deadline ends it at once (101 ms); −1 s turns 500 ms into 1503 ms. A relative REALTIME `clock_nanosleep`, a `nanosleep`, and an absolute MONOTONIC sleep each run 1000 ms whatever the step | — |

Read from Linux 6.18 source (`kernel/time/hrtimer.c`, `posix-timers.c`), not measured, because only a race reaches them:
- `do_nanosleep` returns 0 if the timer fired, whatever signal is pending. So on Linux the deadline wins when both hold.
- With `rem` non-null it also returns 0 if the time left is ≤ 0.
- `clock_nanosleep` sets `rmtp` to NULL under `TIMER_ABSTIME`, which is why `rem` is never written there.

On Darwin, when the deadline and a signal both reach the sleeper, the stop row shows the deadline winning when it came first. That is the "whichever reached the sleeper first" rule that `SyscallInterruption.beforeCompleting` already refuses for `accept` and `flock`.

## 2. What the measurements mean for the model

1. **A sleep's whole state is one instant and one report rule.** The deadline is fixed when the call is made. Every relative sleep runs on the monotonic clock (the step rows), and this machine's realtime clock is never stepped (`UnixMachineState.BootTime`'s docstring). So every sleep this kernel answers has a deadline in nanoseconds since boot, which is what `WakePrimitive.DeadlinePassed` takes. An absolute REALTIME deadline converts exactly, by subtracting `BootTime`.
2. **Saturate, do not refuse.** Linux saturates a deadline past KTIME_MAX at KTIME_MAX, which is `Int64.MaxValue` ns since boot, the same bound `advanceClock` has. Darwin's sleep never ends early for any huge request either. So `Deadline = min(now + request, Int64.MaxValue)` is a measured answer on both. (The poll family refuses the same overflow as `DeadlineBeyondClock`, unmeasured. This probe does not measure `poll`, so that refusal stands.)
3. **`rem` is "time from now to some instant, or 0".** On Linux the instant is the timer's latest expiry: the deadline plus the task's slack. On Darwin it is the C library's own completion time, which is the deadline unless `tv_sec` reaches 2^32 s less the uptime, where its 32-bit arithmetic wraps. The two flavours share one shape: an instant, `until`, fixed at the call, and `rem = max(0, until − now)`.
4. **Whether `rem` is reported at all is fixed at the call.** Null `rem`, and any `TIMER_ABSTIME` sleep, report nothing. A Linux `rem` the kernel cannot write turns EINTR into EFAULT. A Darwin `rem` is written by the C library, so a fault there is the client's, as `UserBuffer`'s docstring says of a foreign-function layer that dereferences a pointer on its own account.
5. **Signals.** EINTR under `SA_RESTART` on both, so `SyscallInterruption.ruleOf` answers `FailsWithEintr`. Ignored and blocked signals do not wake, which is exactly `SignalDeliverable`. A deadline beside a deliverable handler: Linux answers 0, and Darwin is refused as `SignalBesideCompletion`, both through the existing `beforeCompleting`.
6. **Stops stay refused.** The library holds no stopped state (decided 2026-10-09). The stop rows diverge sharply (Linux writes `rem` and then returns 0; Darwin computes `rem` at the continue), so a refusal is the honest answer. `framesOnReturn` already refuses a default stop as `DefaultAction`.
7. **A zero-length sleep.** Linux blocks even for zero, or for an absolute deadline in the past. Darwin returns at once for zero. The model can say this exactly: under Linux the call parks with a deadline that has already passed, and `UnixWait.wakes` wakes it on the next ask; under Darwin a zero request answers 0 without parking. Parking hands the client a point to switch tasks, as Linux does. It changes nothing else.
8. **`clock_nanosleep` is Linux's alone**, and needs two levels as `sigaction`/`sigactionSyscall` have: glibc answers EINVAL for THREAD_CPUTIME, and the system call answers EOPNOTSUPP.

## 3. What the existing kernel decides for us

### 3.1 The park must name its own deadline

`WakeCondition.ofPark : ParkedSyscall -> WakeCondition` is public and reads only the park. Its docstring makes this a design rule: "Deriving rather than storing the condition beside the record is what stops the two disagreeing". `UnixWait.deadlines`, `UnixWait.satisfied` and `UnixWait.wakes` all go through it. Every park that waits on time carries its deadline in its record: `ParkedPoll`, `ParkedEpollWait`, `ParkedKevent`, `ParkedKqueuePoll`.

`SigSuspend` has no fields because its condition needs none. `SignalDeliverable` reads the task's live mask through `SyscallInterruption.wakes`. Its saved mask lives in `SignalState` because it **outlives the park**: the finishing call unparks the task before `onReturnToUser` pushes the frame that saves the mask. Nothing a sleep holds outlives its park. Once `finishSleep` has answered, the deadline and `rem`'s instant are spent. Linux's `restart_block` would outlive it, but only across a stop, which is refused.

### 3.2 No new wake primitive

`AnyOf [DeadlinePassed deadline; SignalDeliverable]` is the whole condition. `poll` with no entries and a timeout already parks on exactly that. `UnixWait.deadlines` then reports the sleep's deadline to a client about to jump its clock, with no change.

### 3.3 Adding a record field later: measured

I measured what a record field added in a later version does to a client that was not recompiled. Set-up: library v1 with `type ParkedSleep = { Deadline : int64 }` inside a union case; a client built against v1; then v2, with a second field `Until`, dropped in. SDK: the devshell's `net10.0`. Files are in this session's scratchpad (`recbin/`).

| client code | v1 | v2 dropped in |
| --- | --- | --- |
| `match p with Parked.Sleep { Deadline = d } -> …` | works | works |
| `match p with Parked.Sleep s -> s.Deadline` | works | works |
| `Parked.Sleep { Deadline = 7L }` (the client builds one) | works | `MissingMethodException: ParkedSleep..ctor(Int64)` |
| reading a park built by a small library function, which F# inlined into the client | works | `MissingMethodException`, in the reader |

So a field added to a park record breaks only code that builds parks. No client should build one, except tests through `InternalsVisibleTo`. The last row is a caveat: F# inlines small library functions across assemblies, constructor and all. The library's functions that park are large, so this does not arise today, but a one-line helper that builds a park could make it arise.

This changes the risk in the policy. Choosing the *case's* payload wrongly breaks every reader. Choosing a *record's* fields wrongly breaks only builders.

## 4. Options

### Option A: `ParkedSyscall.Sleep` with no fields, state beside the park

- **Shape.** `| Sleep` with no payload. An internal `Sleeps : Map<'Task, SleepState>` on the process (or the task), holding `{ Deadline; Remainder }`. `checkInvariants` gains `SleepWithoutState` and `SleepStateWithoutPark`, as `SigsuspendWithoutMaskToRestore` exists today.
- **Entry points.** As in B (§5), with the state written beside the park.
- **Condition.** `ofPark` cannot see the map. Either it answers `SignalDeliverable` alone for `Sleep`, which is false, and `UnixWait` special-cases sleeps around it. Or `ofPark` becomes `'Task -> UnixSystem<'Task, 'Handler> -> ParkedSyscall -> WakeCondition`, a public signature change, and so does `WakeCondition.deadlines`' only way in.
- **Signal, `TIMER_ABSTIME`.** As B.
- **Clients see** `ParkedSyscall.Sleep` and nothing else. PawPrint's `GuestLocation` would need a public accessor to say "until when".
- **Blast radius.** The `ParkedSyscall` matches (§6), plus `ofPark`'s callers, the invariants, and `forgetTask`-style clean-up on exit, which the map makes necessary and the park makes free.
- **Reservation.** `| Sleep`, no fields. It could be reserved without any of this design.
- **Verdict.** Rejected. It breaks the rule that the condition comes from the park, creates a second record of the same thing, and gains only the freedom to reshape state that B's record already has for readers (§3.3).

### Option B (recommended): `ParkedSyscall.Sleep of ParkedSleep`, a public record

- **Shape.** As in §0. `Deadline` is the instant, in nanoseconds since boot, at which the call returns 0, saturated at `Int64.MaxValue`. `Remainder` is `Unreported` for a null `rem` or any `TIMER_ABSTIME` sleep. Otherwise it is `Reported (until, destination)`: an interrupted call reports `max(0, until − now)` and, under Linux, fails with EFAULT if `destination` is `Unmapped`. Under Linux `until` is `Deadline` (with a slack of 0, Q2). Under Darwin it is the C library's 32-bit completion time, which differs from `Deadline` only for requests of nearly 2^32 s or more. Under Darwin `destination` is not consulted: the C library writes `rem`, and a fault there is the client's.
- **Why these fields and no others.** Each is fixed when the call is made, and each is read by the finishing call. Nothing else is: the clock id, the flags and the request are spent once `Deadline` and `until` are computed. `until` earns its place on measurement (Darwin's wrap). It also holds Linux's slack, if the slack is ever modelled (Q2). `destination` is a `UserBuffer` captured at the call, as `ParkedEpollWait.Buffer` is. That is the same approximation: Linux checks `rem` when it copies out, at the end of the sleep.
- **Entry points** (new module `UnixSleep`, compiled after `UnixWait`; `UnixClock.fs` is compiled before `SyscallInterruption.fs` and `WakeCondition.fs`, so it cannot hold them):
  - `nanosleep task (request : TimespecArgument) (remainder : UserBuffer option) system : Result<SleepOutcome * UnixSystem<_,_>, SleepRefusal>`, on both flavours. `TimespecArgument` is `Null | Readable of seconds : int64 * nanoseconds : int64 | Unreadable`, as `KeventTimeout` is for `kevent`. Darwin's entry point is its C library's `nanosleep` over `__semwait_signal`, at the POSIX surface where `pthreadKill` and `getentropy` already sit.
  - `clockNanosleep task (clockId : int) (flags : int) request remainder system`, glibc's, and `clockNanosleepSyscall`, the system call's. Linux only; each fails loudly under Darwin, as `rtSigsuspend` does.
  - `finishSleep task system`.
  - `SleepOutcome = Failed of UnixError | Slept | Interrupted of remainingNanoseconds : int64 | WouldBlock of WakeCondition`. `Interrupted` means "EINTR, and write this to `rem`". `Failed EINTR` is EINTR with nothing to write. The client renders either as `nanosleep`'s −1/`errno` or `clock_nanosleep`'s returned error.
  - `SleepRefusal`: a clock this kernel does not model (`CpuTime`, `EncodedClock`, `MachineDependent`, reusing `ClockGettimeRefusal`'s cases or wrapping it); `Interruption of SyscallInterruptionRefusal`; `Buffer of BufferRefusal`; and a Darwin uptime past 2^32 s, where its C library's 32-bit seconds would wrap the start time too. Each is reachable only with input no measured row covers.
- **The park and its finish.** A request that fails a screen answers at once and changes nothing. A Darwin zero request answers `Slept`. Every other request parks: `UnixWait.park task (ParkedSyscall.Sleep { … })`, answering `WouldBlock (WakeCondition.ofPark …)`. `finishSleep` then answers, in this order:
  1. The deadline has passed: `beforeCompleting` (Linux always proceeds; Darwin refuses when a handler is also deliverable), then `Slept`.
  2. `SyscallInterruption.ofPark` says a handler interrupts (`FailsWithEintr`, so always `Eintr`): `Interrupted (max 0 (until − now))`, or under Linux `Failed EFAULT` for an `Unmapped` destination, or `Failed EINTR` when `Unreported`.
  3. Otherwise it parks again, as `finishSigsuspend` does.
- **`TIMER_ABSTIME`.** Only the deadline differs: the request itself on MONOTONIC and BOOTTIME, the request less `BootTime` on REALTIME (in the past if negative), with `Unreported` always. TAI, the ALARM clocks and the auxiliary clocks are refused as `MachineDependent`, matching `clockGettime`. PROCESS_CPUTIME and negative ids are refused as CPU time. THREAD_CPUTIME, 3 to 6 and the rest answer their measured errors.
- **What clients see.** One more park, with a finishing function, a row in the README's park table, and a deadline in `UnixWait.deadlines`. PawPrint's `GuestLocation` can print "in nanosleep, until t".
- **Blast radius.** §6. The new code is about 300 lines in one new file. The reservation PR alone is about 18 library match arms.
- **Reservation.** The three declarations in §0.

### Option C: as B, with the record's representation hidden

- **Shape.** `type ParkedSleep = internal { … }` with public readers `ParkedSleep.deadline` and `ParkedSleep.remainder`, as `UnixTaskState` and `SignalMask` hide theirs.
- **Gain.** Fields can then be added, removed or retyped in any minor version, construction included. That covers a realtime step tag (Q1) or a slack field (Q2) without the §3.3 caveat.
- **Cost.** It is the only park a client cannot pattern-match. Tests and PawPrint use accessors, and the record's docstrings move onto the accessors.
- **Reservation.** `| Sleep of ParkedSleep`, with an opaque `ParkedSleep` and its readers.

### Option D: no new case; reuse the `poll` park

- **Shape.** A sleep parks as `ParkedSyscall.Poll { Entries = []; Deadline = Some d }`, which already waits on exactly `DeadlinePassed` and `SignalDeliverable`.
- **What breaks.** `ParkedPoll` has nowhere to put `rem`, so adding it is a shape change to an existing record. That is the same kind of change as B's, made to a record two calls then share. Darwin's `poll` parks as `KqueuePoll`, so a Darwin sleep would park in a Linux-shaped record. `finishPoll` would have to tell a sleep from a poll to answer `rem`. And `GuestLocation` would report every sleeping thread as "in poll".
- **Reservation.** None.
- **Verdict.** Rejected: two syscalls behind one record, which is what the scoping note's option (B) was rejected for.

(A fifth option is to leave `nanosleep` to the client, as PawPrint's `Thread.Sleep` is today. It would need a public "would a signal interrupt this task" query, and Linux's EFAULT-for-`rem` rule would become the client's. The scoping note decided that a sleep in the kernel is the kernel's. I did not develop it further.)

## 5. Recommendation

**Option B**, for these reasons:
- the condition comes from the park, like every other timed park;
- every field is fixed at the call and read at the finish, and each one is measured;
- a field added later breaks only code that builds parks (§3.3).

If Patrick answers yes to Q1 (realtime steps are coming), I would still take B, adding the third field now: `Follows : SleepClock`, which says the deadline follows the realtime clock, so that a future step can move it, as Linux's `clock_was_set` moves its timers. Choose C instead only if a field in a park must be free to change whatever it costs a builder.

What the reserved case must say while unreachable:
- its docstring says that nothing parks in it yet, and that `nanosleep` and `clock_nanosleep` will;
- `ParkedSyscall.descriptions` answers `[]`;
- `WakeCondition.ofPark` answers `AnyOf [DeadlinePassed d; SignalDeliverable]`;
- `SyscallInterruption.ruleOf` answers `FailsWithEintr`;
- `UnixWait`'s exclusive-queue sweep answers `None`.

These answers are already right. Only the finishing function is missing, and that is not a match arm. The descriptor and read-write paths that refuse a call while a task is parked treat `Sleep` as they treat `SigSuspend`.

## 6. Blast radius

`ParkedSyscall` has exhaustive matches in the library:

| file | arms |
| --- | --- |
| `UnixTask.fs` | `descriptions`, and the check in `UnixTaskTable.withPark` that a re-park is of the same syscall |
| `WakeCondition.fs` | `ofPark` |
| `SyscallInterruption.fs` | `ruleOf` |
| `UnixWait.fs` | the `finishing` sweep |
| `UnixSystem.fs` | `checkInvariants` (described parks, the `MaskToRestore` rows) |
| `UnixDescriptor.fs` | 7 arms: `flockAcquire`, and six in `close` |
| `UnixReadWrite.fs` | 1 arm (`waitingWriter`) |

PawPrint has `GuestLocation.fs`, four arms in `NativeSystemNative.fs`, `NativeLibcSignalMask.fs`, and `DebuggerServer.fs`. The tests have `TestCallHolds`, `TestMultiProcessFuzz`, `TestSyscallPark`, `TestFlockPark` and `TestSocketEventsWait`. Every site that names `ParkedSyscall.SigSuspend` today needs the same treatment. `rg -l "ParkedSyscall\.SigSuspend"` lists 19 files.

## 7. PR breakdown

1. **R4: reserve `ParkedSyscall.Sleep` (release work, independent of everything else).**
   - Add `SleepRemainder`, `ParkedSleep` and the case, appended after `SigSuspend`, in `UnixTask.fs`.
   - Add the arms of §5, and the PawPrint and test arms. Wherever a park is described in prose, `Sleep` says "nanosleep".
   - Add a README park-table row: "reserved; no call parks here yet".
   - Add an unreachability property, as `reserved-union-cases.md` §1.2 has one: over the multi-process fuzzer's random syscall sequences, no task is ever parked in `Sleep`.
   - Mutation check: temporarily park a `poll` with no entries as `Sleep`, and watch the property fail.
   - Size: small. About 18 library arms and 8 PawPrint arms, with docstrings.
2. **N1: `UnixSleep` (post-release, by the 2026-10-07 decision, unless Patrick moves it).**
   - The entry points, `finishSleep`, `SleepOutcome`, `SleepRefusal` and `TimespecArgument` of §4 B.
   - `TestNanosleep.fs` transcribes every row of §1 that the model answers, citing the probe.
   - A property test against a reference model: for random requests, advances and signal times, the answer matches `rem = max(0, until − now)`, the saturation, Darwin's 32-bit completion, and the screen order. A mutation check on each rule.
   - README rows: the syscall table, the park table, and "What the kernel leaves to the client" (Darwin's C library reads the request and writes `rem`).
   - Size: medium. About 300 lines of library and 400 of tests.
3. **N2 (optional): PawPrint's raw-libc arms.** `nanosleep` and `clock_nanosleep` in `NativeLibc`, with a `sourcesImpure` guest under both flavours that sleeps and is interrupted by `pthread_kill`. No BCL path reaches either call (scoping note §3(a)), so this only shows the wiring.

## 8. Questions for Patrick

1. **Will the kernel ever step the realtime clock** (`clock_settime`, `settimeofday`, `adjtime`)? Today it never does, so an absolute REALTIME deadline converts exactly to time since boot. If a step may come, B should carry `Follows : SleepClock` now. Linux moves such a sleep's deadline with the step (measured), and the park must say which sleeps to move.
2. **Timer slack.** Linux's `rem` includes the task's slack: 50 µs by default, 0 under a real-time policy. I propose a slack of 0, which is a real Linux answer (a real-time task's), so that `until = Deadline` under Linux. Modelling the default would also make a Linux zero-length sleep take up to 50 µs of virtual time. `until` leaves room for it either way.
3. **Should a zero-length or past Linux sleep park** (truthful: measured to block, so the client's scheduler may switch tasks there), or answer at once as Darwin's does? I recommend parking.
4. **Record payload (B) or opaque payload (C)?** B matches the ten sibling parks and keeps readers safe (§3.3). C makes any later change free, at the cost of accessors. I recommend B.

## Decision (orchestrator, 2026-10-11)

- **Option B**, a public record `ParkedSleep`, reserved now as R4 with the fields above. Not C: the measurement in this document shows a client that only reads a record keeps working when the record gains a field, and no client builds a `ParkedSleep`, so hiding the representation buys nothing.
- **Q1 (stepping the realtime clock):** not answered now, and no `Follows` field yet. If the realtime clock ever becomes settable, the field is added then; under the measurement above that breaks no client, since only the library builds the record.
- **Q2 (timer slack):** for N1, not for the reservation. Preference: the measured Linux default (50 µs) is data in the Linux profile, as other measured facts are, rather than 0, so `rem` matches the measurement; Darwin has none.
- **Q3:** a zero-length Linux sleep parks, as measured; Darwin's returns at once.
- R4 is release work; N1 and N2 are not.
