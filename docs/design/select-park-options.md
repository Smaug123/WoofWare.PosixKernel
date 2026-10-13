# A park for `select(2)`: options

*Design note, 2026-10-13, at `origin/main` `55e2622d`. Design item D3 of `reserved-union-cases.md` §2.2, and the `select`/`pselect` rows of `signal-masks-and-sleep-scoping.md` §3. The probe is `docs/probes/select-park/select-park.c` on branch `pk-reserve-select-park`, with its output on Darwin 27.0.0 (xnu-13432.1.9, arm64, uid 501) and Linux 6.18.5 (aarch64, glibc 2.41, Apple's `container`). Linux source is 6.18.7 (`fs/select.c`, `fs/eventpoll.c`); XNU source is `apple-oss-distributions/xnu` `main` at `f6217f89` (`bsd/kern/sys_generic.c`, `kern_descrip.c`). Every row below says whether it was measured or read.*

## 0. Summary

- **Reserve `ParkedSyscall.Select of ParkedSelect`, appended, with `ParkedSelect` opaque** (option A). Its representation is internal and holds only the deadline today; it has no public accessor, since `WakeCondition.ofPark` and `UnixWait.deadlines` already give a client the deadline.
- **No `WakePrimitive` is reserved.** Linux's `select` waits for exactly what `DescriptorReady` says. Darwin's sweep is unmeasured, and either a Darwin reading of `DescriptorReady` or a waiter-relative primitive would serve it. Neither is certain.
- **The remaining-timeout write-back needs nothing in the park.** Linux writes it on every return, but a write it cannot make changes nothing the call answers. So the finishing call will answer the remaining time, and the client copies it. Linux's C library writes it for `select` and never for `pselect` or `ppoll`; Darwin never writes it.
- **`pselect`, `ppoll` and `epoll_pwait` need no case.** They park as `Select`, `Poll` and `EpollWait`. Their temporary mask is `SignalState.MasksToRestore`, as `sigsuspend`'s is, with one rule added: any answer other than `EINTR` restores the mask in the call itself. `UnixSystemDefect.MaskToRestoreOutsideSigsuspend` then has to admit those three parks. Its representation is internal, so changing it does not break a client.

## 1. What was measured

| row | Linux 6.18.5 | Darwin 27.0 |
| --- | --- | --- |
| A1: `select` runs its 300 ms course | 0; timeout written back as 0 | 0; timeout untouched |
| A2: a byte arrives 100 ms into 2 s | 1; timeout written back as 1.89 s | 1; untouched |
| A3: a caught signal 100 ms into 2 s, with and without `SA_RESTART` | `EINTR` both ways; written back as 1.89 s | `EINTR` both ways; untouched |
| A4: zero timeout | not written (it is 0 anyway) | untouched |
| A5: libc `select`, timeout in read-only memory | **the process dies of SIGSEGV**, for a byte and for a signal: glibc on aarch64 has no `select` system call, so it calls `pselect6` and writes the `timeval` back itself | 1, or `EINTR`, as normal |
| A5: raw `pselect6`, timeout in read-only memory | 1, or `EINTR`, as if the write-back had worked | — |
| A6: a descriptor past the table (200) with `nfds` 201 | ignored: `nfds` is clipped to the table's size | ignored, the same |
| B: `tv_usec` = 1 000 000, 1 500 000 | accepted and normalised: sleeps 1.0 s and 1.5 s | `EINVAL` |
| B: `tv_usec` = −1, `tv_sec` = −1 | `EINVAL` | `EINVAL` |
| C1: libc `pselect`, a byte at 100 ms into 2 s | 1; timeout untouched | 1; untouched |
| C2: raw `pselect6`, the same | 1; written back as 1.89 s | no such call |
| C3: libc `ppoll` / raw `ppoll`, the same | untouched / written back | no such call |
| D1: `SIGUSR1` blocked and pending; `pselect` (and `ppoll`) with a temporary mask that lets it through and blocks `SIGUSR2` | `EINTR` at once; the handler runs with both blocked; afterwards `SIGUSR1` is blocked again and not pending | the same (no `ppoll`) |
| D2: the same, and the pipe is ready | 1; **no handler runs**; afterwards `SIGUSR1` is blocked and still pending; unblocking it runs the handler | the same |
| D3: `SIGUSR1` blocked by the temporary mask arrives at 100 ms of a 400 ms wait | 0 at 400 ms; the handler runs on the way out, under the restored mask | the same |
| E1: another thread closes the selected pipe read end 100 ms into 1 s (with or without a `dup` keeping the pipe open) | the call sleeps on, and returns **1 at 1 s with the descriptor set** | **`EBADF` at the close** |
| E2: as E1 with a `dup`, and a byte at 200 ms | 1 at 200 ms | `EBADF` at 100 ms |
| F1: one socket, readable and writable, in both sets | 2 | 2 |
| F2: the ready descriptor at `nfds` | not looked at | not looked at |
| F3: `nfds` = `FD_SETSIZE` with empty sets; `nfds` = −1 | 0; `EINVAL` | 0; `EINVAL` |

What the source says about these rows:
- **Linux.** `select_poll_one` (`fs/select.c:466`) answers `EPOLLNVAL` for a descriptor that is no longer open. `POLLIN_SET`, `POLLOUT_SET` and `POLLEX_SET` (`:459`) all contain `EPOLLNVAL`, so a closed descriptor is reported in every set it was in, at the next scan. Nothing wakes the call at the close: it holds the file through its wait-queue entry (`__pollwait` takes a reference), as `poll` does. That is E1 and E2.
- **Linux write-back.** `poll_select_finish` (`:295`) writes the remaining time on every return once the timeout was read, unless the timeout was zero or the personality has `STICKY_TIMEOUTS`. A failed copy is silent: "we don't want the Linux-specific update to the timeval to cause a fault after the select has completed successfully". It only turns `-ERESTARTNOHAND` into `EINTR`, since the call cannot restart without the updated timeout. `-ERESTARTNOHAND` restarts only when no handler ran, which means after a stop, and stops are refused today.
- **Linux mask.** `do_pselect` and `ppoll` call `set_user_sigmask`, and `poll_select_finish` calls `restore_saved_sigmask_unless(ret == -ERESTARTNOHAND)`. `do_epoll_pwait` (`fs/eventpoll.c:2489`) does the same with `-EINTR`. Neither `epoll_pwait` nor `epoll_pwait2` writes its timeout back.
- **Darwin.** `select_nocancel` and `pselect_nocancel` read the timeout and never write it (`sys_generic.c:1133`, `:1175`). `itimerfix` refuses `tv_usec` ≥ 10^6. `selcount` (`:1939`) takes an I/O reference on each selected descriptor's fileproc. A `close` of one drains those (`fileproc_drain`, `kern_descrip.c:1621`), waking the select with `THREAD_INTERRUPTED`. The rescan then fails in `selscan` with `EBADF` (`:1641`). That is E1. `selprocess` turns `ERESTART` into `EINTR` ("select is not restarted after signals"). `pselect_nocancel` and `selprocess` restore the old mask unless the answer is `EINTR` (`:1221`, `:1487`).

## 2. What the measurements mean for the park

1. **`select` needs a park of its own on Darwin whatever Linux does.** Darwin's `poll` is kqueue-based (`ParkedKqueuePoll`); its `select` is `selscan` over `fo_select`, with no kqueue. A close of a selected descriptor ends Darwin's call with `EBADF` (E1), which neither poll park can say. Linux's `select` keeps sleeping and reports the closed descriptor in every set (E1, E2).
2. **What the park holds is not settled.**
   - Darwin holds a reference per selected *descriptor*, and its close ends the call. So a Darwin park must know which descriptor numbers it was entered through, as `SleepTarget.Waiting` does, and must be able to record that a close ended it.
   - Linux holds the *file* behind each descriptor, and its close does nothing to the call.
   - Darwin's readiness for each of the three sets (`soo_select`, `pipe_select`, `vn_select`) is unmeasured. The 51-state sweep of `darwin-poll-options.md` §3 has not been run for `select`.
   - Whether the result sets are copied out per set, or as a single answer, is the finishing call's design.

   Any record written now would be changed when `select` lands, and changing a public record's fields breaks a reader as much as adding a case does. Adding one does not: `nanosleep-options.md` §3.3 measured that a client that only reads a record survives a new field. But removing or retyping a field breaks it, and both are likely here.
3. **The remaining-timeout write-back is not park state.** The remaining time is the deadline minus now, clipped at 0, truncated to microseconds for `select` (A2, A3; `poll_select_finish`). A copy the kernel cannot make changes nothing it answers (A5, raw), apart from the restart that the refused stop would need. So the park needs no destination. The finishing call answers the time; the client writes it, or does not. Which call writes it is a fact about the entry point, not the park:
   - Linux `select`: written. On aarch64 it is glibc that writes it (A5, libc), which is the client's business.
   - Linux `pselect6` and `ppoll`: written by the system call, never by glibc (C1–C3). This gives two levels, as `sigaction` and `sigactionSyscall` have.
   - Darwin: never written.
4. **The temporary mask behaves as `sigsuspend`'s, on both flavours, with one difference** (D1–D3).
   - While the task sleeps, its mask is the temporary one.
   - An `EINTR` answer leaves the mask to restore until the task returns to user mode. The handler frame saves the original mask (D1), as for `sigsuspend`.
   - **Any other answer restores the mask in the call itself.** A signal that only the temporary mask let through then stays pending (D2), and one it blocked is delivered on the way out (D3).
   
   So the state is `SignalState.MasksToRestore`, already present, and the park needs no field to say whether a mask was installed. A mask to restore exists exactly when the call installed one.
5. **Restart rule.** `EINTR` with or without `SA_RESTART` on both flavours (A3), so `SyscallInterruption.ruleOf` answers `FailsWithEintr`, as for `poll`.

## 3. Options

### Option A (chosen): a case of its own, with an opaque payload

```fsharp
/// One task's in-flight `select(2)` or `pselect(2)`. Its representation is
/// internal, so a later version can change what it holds.
type ParkedSelect =
    internal
        {
            Deadline : int64 option
        }

// appended to ParkedSyscall, after InotifyRead:
    | Select of ParkedSelect
```

- **What every reader answers for it, while it is reserved:**
  - `ofPark`: the deadline, if any, or a signal. `descriptions`: `[]`.
  - `ruleOf`: `FailsWithEintr` on both flavours (measured, A3).
  - The exclusive-queue sweep: none.
  - `close` and `flock`: as for `SigSuspend`.
  - The finishing paths: refuse it, as they refuse any other park.
  - `checkInvariants`: `ReservedPark`.
- **Later:** the internal record gains the entries, Linux's held descriptions, Darwin's entered-through descriptors and an "ended by a close" state. None of that is public, so none of it breaks a client. A public reader that turns out to be needed is a new function, which is additive.
- **Cost:** it is the only park a client cannot pattern-match into. Today PawPrint and the tests would have nothing to read in it except through `ofPark`, and they need nothing else.

### Option B: the `Poll` park with a tag

`ParkedPoll` gains `Call : PollCall` (`Poll | Select of …`), and no case is added.
- It covers Linux alone. Darwin's `select` is neither `Poll` (Linux-flavoured) nor `KqueuePoll`, and its close rule (E1) fits neither. So Darwin still needs a case.
- It puts two syscalls behind one record, so `finishPoll` would have to tell them apart. `nanosleep-options.md` option D was rejected for exactly that.
- The tag's payload has the same uncertainty as A's fields, so the field would be retyped later. That breaks readers of `ParkedPoll`, which today PawPrint pattern-matches.

Rejected.

### Option C: a case of its own, with a public record

The same shape as `ParkedSleep`, with fields such as `Entries : (fd * which sets * description) list`, `Deadline` and `Destinations`.
- §2.2 lists what is unsettled. The Darwin entry has to say which descriptor it came through and whether a close ended it, which the Linux entry does not. The per-set result destinations are the finishing call's design.
- A field added later breaks only builders (§3.3 of the nanosleep note). A field retyped or removed breaks readers. Both are likely here.

Rejected, in favour of A's opaque payload, which `reserved-union-cases.md` asks for when fields are not certain.

### Option D: no park; the client turns `select` into `poll`

This is what .NET does on Linux (`SelectViaPoll`).
- It loses Darwin's close rule (E1).
- It loses Linux's report of a closed descriptor in every set, where `poll` reports it once, as `POLLNVAL`.
- It loses the remaining-timeout answer.
- A trace replayer replays `select` as `select`.
- `signal-masks-and-sleep-scoping.md` §3(c) put `select` in the kernel.

Rejected.

## 4. What changes for `pselect`, `ppoll` and `epoll_pwait`

- **No case.** They park as `Select`, `Poll` and `EpollWait`.
- **The mask is installed where `sigsuspend` installs it.** Each entry point stores the task's current mask in `MasksToRestore` and installs the temporary one.
- **The finishing call reads the stored mask as the tag.** When it answers anything other than `EINTR`, it restores the mask and drops the entry (§2.4). When it answers `EINTR`, it leaves the entry for `onReturnToUser`, as `finishSigsuspend` does. So no park record needs a field for the mask.
- **Linux `ppoll`'s remaining time.** The raw system call writes it back (C3), and `poll` does not. So `ppoll` gets a finishing function of its own, which answers the time. That function is new, so it is additive, and `ParkedPoll` is untouched.
- **`UnixSystemDefect`.** Its representation is internal, so these changes are free:
  - `MaskToRestoreOutsideSigsuspend` becomes "a task parked in a call that installs no temporary mask has a mask to restore". Those calls are every park except `SigSuspend`, `Select`, `Poll` (Linux `ppoll`) and `EpollWait` (`epoll_pwait`, `epoll_pwait2`). `KqueuePoll` and `Kevent` stay outside, since XNU has no `ppoll` and its `kevent` takes no mask.
  - `SigsuspendWithoutMaskToRestore` stays as it is. A `Poll` park without a mask is a plain `poll`, which is not a defect. That half of the check cannot extend to the three, because no park says which call made it, and option A keeps it that way.
  - Nothing in the reservation PR changes either defect, since nothing can park in `Select` yet.

## 5. Reservation PR

- `UnixTask.fs`: `ParkedSelect` (internal representation), and `ParkedSyscall.Select`, appended after `InotifyRead`.
- Library arms:
  - `descriptions`;
  - `withPark`'s `kind`;
  - `ofPark` (deadline or signal);
  - `ruleOf` (`FailsWithEintr`, citing A3);
  - the `UnixWait` exclusive-queue sweep;
  - `UnixDescriptor`'s `flock` and `close` arms, and `UnixReadWrite`'s `waitingWriter`, as for `Sleep`;
  - `checkInvariants`' `ReservedPark` row;
  - `deadlines`, which is unchanged since it reads the condition.
- PawPrint arms:
  - `GuestLocation` reports "in select or pselect".
  - `DebuggerServer` reports `blockedInSelect`.
  - The four arms in `NativeSystemNative` refuse it, as they refuse `Sleep`.
- Tests:
  - `TestSelectPark`: the readers' answers over random deadlines, and `ReservedPark` with the deadline in `UnixWait.deadlines`.
  - The arms in `TestCallHolds`, `TestSyscallInterruption`, `TestMultiProcessFuzz`, `TestSyscallPark`, `TestFlockPark` and `TestSocketEventsWait`.
  - Mutation check: park an empty Linux `poll` as `Select` in the multi-process fuzzer, and watch `ReservedPark` fire.
- README: the reserved-case list and the park paragraph.

## Decision (orchestrator's delegate, 2026-10-13)

- **Option A.** Reserve `ParkedSyscall.Select of ParkedSelect`, with `ParkedSelect`'s representation internal (deadline only) and no public accessor.
  - The case is certain (#1726).
  - The fields are not. Darwin's close ends the call (E1), and its per-set readiness is unmeasured. The entries would need different contents per flavour.
  - Opacity makes all of that free to settle later.
- **No `WakePrimitive` reserved.** Linux needs none, since `DescriptorReady` with `POLLIN_SET`/`POLLOUT_SET`/`POLLEX_SET` is exactly its wait. Whether Darwin needs one depends on the unmeasured sweep.
- **Write-back:** answered by the finishing call as a time for the client to copy, never stored in the park. There are two levels on Linux, the C library's (`select` writes it back; `pselect` and `ppoll` never do) and the system call's (all three write it back). Darwin never writes it back.
- **`pselect`/`ppoll`/`epoll_pwait`:** no case. They use the temporary-mask mechanism of `sigsuspend`, plus a restore in the call on any non-`EINTR` answer, measured on both flavours. The defect changes as §4 says when they land.
