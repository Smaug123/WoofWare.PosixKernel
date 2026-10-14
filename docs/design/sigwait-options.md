# `sigwait`, `sigwaitinfo` and `sigtimedwait`: options

*Design note, 2026-10-13, at `origin/main` `55e2622d`. Design item D4 of `reserved-union-cases.md`, and probe M6 of `signal-masks-and-sleep-scoping.md`. Patrick asked for the park to be reserved before 1.0. The probe is `docs/probes/sigwait/sigwait.c` on branch `pk-reserve-sigwait-park`, with its output on Darwin 27.0.0 (arm64, uid 501) and Linux 6.18.5 (aarch64, glibc 2.41, root in Apple's `container` with `--cap-add ALL`, for `SCHED_FIFO`). Every row below was measured unless it says "source".*

## 0. Summary

- **Recommendation: option A.** Append `ParkedSyscall.SignalWait of ParkedSignalWait`, a public record of three fields, and `WakePrimitive.AwaitedSignalPending of awaited : SignalMask`.

  ```fsharp
  type ParkedSignalWait =
      {
          Awaited : SignalMask              // the set the call takes from
          Deadline : int64 option           // Linux rt_sigtimedwait's timeout, as an instant
          Destination : UserBuffer option   // Linux `info`, Darwin `sig`; None when null
      }

  // appended to ParkedSyscall, after InotifyRead:
      | SignalWait of ParkedSignalWait
  // appended to WakePrimitive, after InotifyRecordQueued:
      | AwaitedSignalPending of awaited : SignalMask
  ```

- **M6's answers.** The set need not be blocked: an unblocked awaited signal with a handler is taken by the call on both flavours, and its handler never runs. When an awaited signal and a deliverable handler's signal are both pending as the waiter runs, both flavours return the awaited one, and the handler runs on the way out. The flavours part on what a handler's signal does to the wait: Linux's call ends with `EINTR` (even under `SA_RESTART`), Darwin's sleeps on, and the handler runs only once the call returns.
- **The deadline needs nothing beyond `DeadlinePassed`.** Linux fixes it at the call and never writes the timeout back. A zero timeout answers `EAGAIN` without blocking. The park carries the instant, as `ParkedEpollWait` does, so that `WakeCondition.ofPark` can derive the condition from the park.
- **Nothing for Patrick.** The fields are each measured, the case is "likely" in the audit and Patrick has asked for it, and no measurement contradicts the audit's premise.

## 1. What was measured

`set` is the set passed to the call. "Libc" is `sigwait(3)` on both flavours. "Raw" is `rt_sigtimedwait(2)` on Linux and `__sigwait` (syscall 330) on Darwin. A signal "arrives during" the wait when another thread sends it 100 ms in.

| row | Linux 6.18.5 | Darwin 27.0 |
| --- | --- | --- |
| which calls exist | glibc's `sigwait`, `sigwaitinfo` and `sigtimedwait`, all over the one system call `rt_sigtimedwait(set, info, timeout, sigsetsize)` | `sigwait` alone (the macOS 27 SDK's `<signal.h>`), over `__sigwait(set, sig)` |
| two awaited signals pending at entry, both blocked | the lower-numbered first (USR1 before USR2), each consumed | the same |
| a blocked awaited signal arrives during, to the thread or the process | taken, at once | the same |
| receiver: the main thread blocks USR1 and sleeps, a second thread waits for it; `kill` to the process | the waiter takes it | the same |
| receiver: the main thread has a handler for USR1 and does not block it; `kill` to the process | the main thread's handler runs; the waiter sleeps on | the same |
| an **unblocked** awaited signal with a handler arrives during | **taken by the call; the handler never runs** | the same |
| an unblocked awaited signal at a default that terminates (USR1) arrives during | **the process dies** of it | **taken by the call**; the process lives |
| an unblocked awaited signal that is ignored (`SIG_IGN`, or URG at its default) arrives during | discarded; the call sleeps on | the same |
| a **blocked** awaited signal that is ignored (`SIG_IGN`, or URG at its default), sent before the call or during it | **kept pending, and taken** | **discarded**; the call sleeps on |
| a handler's signal outside the set, unblocked, arrives during (flags 0 and `SA_RESTART`) | raw: **`EINTR`** at once, either way; the handler runs on return. glibc's `sigwait` loops on `EINTR` and goes on waiting | raw and libc: **the call sleeps on**; the handler runs only when the call returns, at the awaited signal's arrival |
| both an awaited signal (blocked) and a handler's signal outside the set arrive while the waiter cannot run, in either order (Linux: one CPU, `SCHED_FIFO`, sender at the higher priority; Darwin: the parent stops the waiter, sends both, continues it) | the call **returns the awaited signal**, and the handler runs on the way out | the same |
| the same, made by stopping the waiter (Linux) | raw: the stop ends the call with `EINTR`; the handler runs, and the awaited signal stays pending. glibc's `sigwait` loops and takes it | — (as above: a stop does not end the call) |
| the waiter's blocked mask while it waits ({USR1, USR2} blocked, set {USR1}) | `/proc`'s `SigBlk` shows USR1 **removed** during the wait, and restored after | not observable |
| destination null, signal pending at entry or arriving during | the signal is answered (raw returns its number) and nothing is written | `__sigwait` returns 0 and writes nothing |
| destination unmapped, signal pending at entry or arriving during | **`EFAULT`, and the signal is consumed** | the same |
| what is written | a `siginfo_t` to `info`; a signal from `raise` reads `si_code` −6 (`SI_TKILL`) and `si_pid` the caller | an `int` to `sig` |
| an empty set | sleeps (raw with a 100 ms timeout: `EAGAIN`; libc: until killed) | **`EINVAL`** |
| a set of KILL and STOP alone | as an empty set: both silently dropped | **`EINVAL`** |
| timeout 100 ms, nothing arrives | `EAGAIN` after 100 ms; one voluntary switch | — |
| timeout zero, nothing pending | `EAGAIN` at once, **no switch** | — |
| timeout with `tv_nsec` = 1e9 or `tv_sec` < 0 | `EINVAL`, even with an awaited signal pending, which stays pending | — |
| `sigsetsize` 4 | `EINVAL`, even with a signal pending, which stays pending | — |
| `set` or `timeout` unmapped | `EFAULT` | — |
| a handler's signal under `SA_RESTART` during a 500 ms timed wait | `EINTR` at 100 ms; the timeout is never written back | — |
| glibc's `sigtimedwait` | returns −1 and sets `errno` | — |

Read from Linux 6.18 source (`kernel/signal.c`), consistent with the rows above: `do_sigtimedwait` dequeues an awaited signal before sleeping; while it sleeps it copies the mask to `real_blocked` and removes the set from `blocked` (the `SigBlk` row); generation does not discard an ignored signal that is in `real_blocked` (the blocked-and-ignored row) and does not kill the group for a fatal one in `real_blocked` (so an unblocked one kills, as measured); after waking it dequeues again, so an awaited signal wins over the interruption (the rank row); `rt_sigtimedwait` copies `info` out after dequeuing, so a fault there loses the signal (the destination row).

Not measured, because neither shape nor reservation depends on them: Darwin's answer for a set with bit 31, or for a set mixing a signal with KILL; Linux's saturation of a huge timeout; real-time signal queueing.

## 2. What the measurements mean for the model

1. **The call's state is the set, an optional instant, and an optional destination, all fixed at the call.** Nothing is written back to the timeout. The destination is where the taken signal is reported: a `siginfo_t` on Linux, an `int` on Darwin, and on both a null pointer is tested for and skipped, so a null is not an address (`UserBuffer` has deliberately no null case) and the field is an `option`. Which layout is written is the flavour's.
2. **The destination is classified at the call**, as `ParkedEpollWait.Buffer` is. Both kernels look at it only after taking the signal, which is the same approximation the epoll park makes.
3. **No mask is saved.** Linux removes the set from the blocked mask while the task sleeps and restores it afterwards, but nothing about that outlives the park. The model can leave the task's mask alone and have generation read the park instead: a task parked in a signal wait treats its awaited set as Linux's `real_blocked` does. Unlike `sigsuspend`, there is no mask to restore, so no `SignalState.MasksToRestore` entry.
4. **What a handler's signal does differs, and the park need not say so.** On Linux the condition is the usual `AnyOf [AwaitedSignalPending; DeadlinePassed?; SignalDeliverable]`, and `SyscallInterruption.ruleOf` answers `FailsWithEintr`. On Darwin no signal outside the set ends the call. `WakeCondition.ofPark` is flavour-free and ORs `SignalDeliverable` into every park, so on Darwin that primitive's *evaluation* must answer false for a task in a signal wait: Darwin holds the signal pending on that thread until the call returns, so "were it to return to user mode now it would run that handler" is not true of it. That is a rule inside `SyscallInterruption.wakes`, which already reads the task's park for `sigsuspend`, and it changes no type.
5. **An awaited signal wins over the interruption, on both.** So the finishing call asks `AwaitedSignalPending` first, and the handlers run at `onReturnToUser` as they already do. No field records the order.
6. **Generation differs at its edges**, and those are rules over state, not fields: Linux kills the process for an unblocked awaited signal whose default terminates, keeps a blocked-and-ignored awaited signal, and discards an unblocked ignored one. Darwin takes the first, discards the second, and discards the third.
7. **The set's screens are the flavour's.** Darwin refuses an empty set (and one of KILL and STOP alone) with `EINVAL`; Linux drops KILL and STOP and sleeps on an empty set. Either way the park's `Awaited` is a `SignalMask`, the type every other signal set in this library has, because Darwin's `sigset_t` keeps bit 31, which names no signal.

## 3. What the existing kernel decides for us

- `WakeCondition.ofPark` is public and reads only the park (`nanosleep-options.md` §3.1), so the park must carry its deadline and its set.
- A record field added later breaks only code that builds the record (`nanosleep-options.md` §3.3, measured). Only the library builds parks.
- `SignalDeliverable` already depends on the task's park for `sigsuspend` (its temporary mask), so a Darwin carve-out there is in keeping.

## 4. Options

### Option A (recommended): a public record, and a primitive that carries the set

- **Shape.** As in §0. `Awaited` is the set the call takes from. `Deadline` is `Some` instant in nanoseconds since boot for a Linux call with a non-zero timeout, and `None` otherwise (Darwin has no timed call). `Destination` is `None` for a null `info` or `sig`.
- **Primitive.** `AwaitedSignalPending of awaited : SignalMask`: a signal in `awaited` is pending to the waiting task. It carries the set as `FifoPartnerOpened` carries its count, so the condition says what it waits for without the park.
- **Why these fields.** Each is fixed at the call and read by the finish: the set to take from, the instant at which to answer `EAGAIN`, and where to report. The call's name (`sigwait` against `sigtimedwait`) is not a field: each flavour has one system call, and glibc's `EINTR` loop in `sigwait` is the client's.
- **Reservation.** The two cases and the record.

### Option B: the record's representation hidden

- `type ParkedSignalWait = internal { … }` with public readers, as `SignalMask` hides its own.
- Gains: any later change to the fields is free, construction included.
- Costs: the only park a client cannot pattern-match, and the measurement in `nanosleep-options.md` §3.3 already makes a later field free for readers. The orchestrator rejected the same option for `ParkedSleep` on that ground.

### Option C: no fields, state beside the park

- `| SignalWait` alone, with the set, deadline and destination in a per-task map in `SignalState`, as `sigsuspend`'s saved mask is.
- Rejected for the reason `nanosleep-options.md` rejected its option A: `WakeCondition.ofPark` reads only the park and could not name the deadline or the set. And nothing here outlives the park, which was `sigsuspend`'s only reason.

### Option D: reuse `sigsuspend`'s park and `SignalDeliverable`

- Linux does literally unblock the set while it sleeps, so a signal wait looks like a `sigsuspend` with a temporary mask of `blocked \ set`.
- Rejected: `SignalDeliverable` holds only for a signal with a handler, but the awaited signals are usually at their default action (a daemon's signal thread waits for INT and TERM) or blocked and ignored, and must be taken, not delivered; the finish answers a signal number, not `EINTR`; and Darwin's call is not interrupted at all.

For the primitive alone there is a second choice: a payload-free `AwaitedSignalPending`, evaluated by reading the set from the task's park. It would save nothing (the condition is derived from the park either way) and would make the condition the only one in this library that does not say what it waits for. Rejected.

## 5. What the reserved cases do while unreachable

- `ParkedSyscall.descriptions` answers `[]`: the call holds no open file description.
- `WakeCondition.ofPark` answers `AwaitedSignalPending awaited`, then `DeadlinePassed d` if there is a deadline, then `SignalDeliverable`.
- `WakeCondition.deadlines` finds the deadline through the condition, so `UnixWait.deadlines` reports it.
- `SyscallInterruption.ruleOf` answers `FailsWithEintr` under Linux (measured, with and without `SA_RESTART`). Under Darwin a handler does not end the call, so no rule applies; it answers `FailsWithEintr` there too, and the docstring says that the Darwin answer is not consulted once the wait is modelled.
- Evaluating `AwaitedSignalPending` fails loudly, as `FifoPartnerOpened`'s does: no call parks on it yet.
- The exclusive-queue sweep answers no queue; every `close` arm leaves the call alone, as for `SigSuspend`.
- `UnixSystem.checkInvariants` reports a task parked in it as `UnixSystemDefect.ReservedPark`.
- PawPrint's `GuestLocation` and debugger server report the set and the deadline.

## 6. PR breakdown

1. **R-D4 (this one):** the probe and its outputs; the record and both cases; the arms of §5; `TestSignalWaitPark`; a README sentence beside the other reserved parks. Mutation check: park `sigsuspend` as a `SignalWait` and watch the fuzzer fail.
2. **Later (post-release, per the 2026-10-07 decision):** `UnixSignal.sigwait` (Darwin's `__sigwait`), `rtSigtimedwait` (Linux), `finishSignalWait`, the generation rules of §2.6, Darwin's carve-out in `SignalDeliverable`, and the refusals for what §1 leaves unmeasured.

## Decision (orchestrator's delegate, 2026-10-13)

**Option A.** Each field is fixed at the call, read by the finish, and measured on both flavours; a field found missing later costs only builders, and only the library builds parks. The primitive carries its set. `sigtimedwait`'s deadline needs nothing beyond `DeadlinePassed`; the park carries the instant so that `ofPark` can name it. Darwin's uninterruptible wait is a rule in `SignalDeliverable`'s evaluation, left to the implementing PR, and changes no type.
