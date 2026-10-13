# Signal masks and sleeping on time: scoping

*Scoping note, 2026-10-07, main at `868f97b6`. Read-only investigation for two "Feature work" items on #1726. Runtime source is the devshell pin (`$DOTNET_RUNTIME_SRC` = `/nix/store/5hhx05xahzb50g696pwcjryjz4hkvk0y-runtime-4271d88`, written `$RT` below). Managed IL was read with `WoofWare.PawPrint.IlDump` against the pinned linux-x64 pack (`dotnet-linux-x64-framework-10.0.12`).*

## 0. Summary

| family | .NET reaches it? | PawPrint today | verdict | PRs |
| --- | --- | --- | --- | --- |
| `sigprocmask`/`pthread_sigmask`, `sigpending` | **No managed path.** Only native CoreCLR internals and the shim's fork window | Masks exist only as handler frames; a raw P/Invoke is `failUnimplemented` | **Needed for release** (fork/exec, the U3 throw, the second client) | 1 |
| `sigsuspend` (with `pause`) | No | Not modelled | **Needed for release** (small once masks exist; its temporary mask is the mechanism `pselect`/`ppoll` reuse) | 1 |
| delivery to a non-leader task | Not with empty masks | Refused (`LeaderBlocks`) | Release-optional. Already measured | 1 |
| `sigwait` / `sigtimedwait` / `sigwaitinfo` | No (the shim uses a self-pipe) | Not modelled | Post-release unless the replay corpus needs it | 1 |
| `sigaltstack` | Native PAL only | Not modelled | **Out of scope: the client's** (user memory and the stack pointer) | 0 (1 if a record-only form is wanted) |
| `nanosleep`/`clock_nanosleep`/`usleep` | Native runtime internals only. `Thread.Sleep` is a futex wait | `Thread.Sleep` is PawPrint's own `BlockedOnSleep` | **Needed for release** (second client); kernel scope; trivial on the existing machinery | 1 |
| `select` with a timeout | **Yes**: `Socket.Select` under the **Darwin** CoreLib flavour only | `SystemNative_Select` is `failUnimplemented` | Release-optional. Linux is cheap; Darwin needs a sweep | 1–2 |
| `pselect`/`ppoll`/`epoll_pwait` | No | Not modelled | After masks | 1 |
| `poll`/`epoll_wait`/`kevent` with a timeout | Yes (`Socket.Poll`, Console, FileSystemWatcher, the socket engine) | **Already modelled** with `DeadlinePassed` | done | 0 |
| `alarm`/`setitimer(ITIMER_REAL)` | No | Not modelled | Post-release, **but its API shape (time passing can generate a signal) should be decided before the API baseline** | 2 (options + impl) |
| `ITIMER_VIRTUAL`/`ITIMER_PROF`, CPU-clock `timer_create` | No | Not modelled | Blocked on CPU-time accounting (deferred on #1726) | — |
| `timerfd` (Linux) | No | Not modelled | Post-release | 2 |
| `EVFILT_TIMER` (Darwin) | No (the shim's kqueue never registers one) | Not modelled | Post-release | 1 |

**Release total: 3 PRs** (masks, `sigsuspend`/`pause`, `nanosleep`). Plus 1–2 optional (`select`, the receiver rules). **Everything else: about 7 PRs, post-release.**

The single reason anything here is "needed for release" is that nothing in .NET reaches it except through native code PawPrint replaces. The reasons are (i) the multi-process work, which has to say what a child's mask is, (ii) one audit throw that exists only because masks are missing, and (iii) the second-client exit criterion. If Patrick does not count the trace replayer as setting the bar for release, then only (i) and (ii) remain, and they need the mask PR alone (see §5, Q1).

## 1. What the kernel has today

### Signals
- A task's mask is **derived from its handler frames**: the innermost frame's `Mask`, or empty without one. `SignalState.fs:136-138` ("nothing else sets one, because this library models no `sigprocmask(2)`"); `maskOf` at `SignalState.fs:421`. The emulated-posix-kernel skill §2 says the same: "a test that needs a task to block signals puts it in a handler".
- `HandlerFrame.Mask` (`SignalState.fs:95-98`) holds the mask *while the handler runs*. `sigreturn` restores the mask by popping the frame (`SignalState.fs:1020-1022`). That is correct only because nothing can change the mask inside a handler.
- Receiver: a process-directed signal goes to the leader. If the leader blocks it and another task doesn't, the call is refused with `SignalReceiverRefusal.LeaderBlocks` (`SignalState.fs:209`, `receiverFor` at `:624-661`). The measured rules for that case are cited at `:645-652`: Darwin picks the first-created non-blocking thread, Linux uses the `curr_target` cursor.
- `UnixTaskLifecycle.spawn` **throws** if the parent is inside a handler (`UnixTaskLifecycle.fs:169-176`). A new thread inherits its creator's mask, measured by `thread-spawn-mask.c`, and a frame-derived mask can't be given to a task with no frames. This is audit row **U3** (`failwith-audit-2026-10-07.md:117`). It is reachable with legal input and needs either a `SpawnRefusal` or a real mask.
- Several facts are already measured, so the mask work needs few new probes:
  - `Signal.fs:387-406`: SIGKILL/SIGSTOP are silently dropped from a mask, and glibc screens 32/33.
  - `Signal.fs:506`: an ignored signal stays pending while blocked on Linux. On Darwin it is discarded.
  - `pickRank`: the per-flavour order in which pending signals are taken.
  - `pawprint-signals-research/measurements.md` §5: "after the handler returns the mask is exactly the one at delivery, whatever the handler did to it".
  - §5 also gives the EINTR table: `nanosleep`, `select`, `poll`, `pause` and `sigsuspend` answer EINTR even under `SA_RESTART`, on both flavours.
  - §6: the receiver rules.

### Waiting
Most of `waiting-options.md`'s design B is now in place:
- `WakePrimitive.DeadlinePassed of nanosecondsSinceBoot` (`WakeCondition.fs:124`) and `SignalDeliverable` (`:133`).
- `WakeCondition.deadlines` (`:384`), and `ofPark` (`:417`), which ORs `SignalDeliverable` into every park (`:504`).
- `UnixWait.wakes` (`UnixWait.fs:75`) and `UnixWait.deadlines` (`:284`).
- `poll`, `epoll_wait` and `kevent` carry an optional `Deadline`.
- `poll` with no entries and a timeout already parks on the deadline and a signal alone (`WakeCondition.fs:411`). That is a `nanosleep` in all but name.

PawPrint merges the kernel's deadlines into its idle jump: `Program.fs:409` `syscallDeadlines`, `:422` `pendingDeadlines`.

Time passing is `UnixSystem.advanceClock` (`UnixSystem.fs:594`, `UnixMachine.fs:277`). It returns a bare machine, so **nothing can happen because time passed** except that a pulled `DeadlinePassed` becomes true. That matters for §3.3.

## 2. Signal masks

### (a) Does .NET reach it?

**No `SystemNative_*` export exposes a mask, and no managed API reaches one.** This was confirmed by grepping `$RT/src/native/libs`, `$RT/src/coreclr` and the CoreLib tree. It agrees with `docs/plans/2026-09-16-signal-state-kernel-model.md` Decision 3 ("the BCL exposes no managed path to `pthread_sigmask` at all").

Every mask call in the pinned source:

| call site | what | reached under PawPrint? |
| --- | --- | --- |
| `$RT/src/native/libs/System.Native/pal_process.c:314-315, 395, 433` (`SystemNative_ForkAndExecProcess`) | `sigfillset` + `pthread_sigmask(SIG_SETMASK)` around `fork`/`vfork`. The child resets caught handlers to `SIG_DFL`, restores the old mask, then `execve`. The parent restores the old mask | **Yes, once the multi-process work implements `ForkAndExecProcess`** (today it is `failUnimplemented`; the export is imported only by `System.Diagnostics.Process.dll`) |
| `$RT/src/coreclr/pal/src/exception/signal.cpp:516-539` (`Unmask/MaskActivationSignal`), `:1121` (unmask a hardware-fault signal before throwing out of the handler), `init/sxs.cpp:95` | CoreCLR's GC-suspension activation signal and hardware exceptions | No: PawPrint *is* the runtime, and suspends threads itself |
| `$RT/src/coreclr/pal/src/thread/process.cpp:848` | PAL `CreateProcess` child clears its mask | No (native PAL) |
| `$RT/src/coreclr/pal/src/thread/thread.cpp:2317-2394` | `sigaltstack` per PAL thread, for stack-overflow handling | No (native PAL) |

`PosixSignalRegistration` / `Console.CancelKeyPress`: `pal_signal.c`'s handler writes the signal number into a self-pipe (`:240`), and a dedicated `SignalHandlerLoop` pthread reads it (`:308-331`, created at `:538`). **It uses no mask and no `sigwait`.** The handler thread inherits its creator's (empty) mask. Because no thread blocks anything, a process-directed signal goes to the main thread (measured 192/192 per flavour). PawPrint reproduces this: `SignalDispatch.fs:44-52` delivers to the leader only, and the dispatcher thread never receives a signal.

### (b) What PawPrint does today
- A raw `[DllImport("libc")] pthread_sigmask`/`sigprocmask`/`sigpending`/`sigsuspend`/`sigaltstack` falls to `NativeCall.failUnimplemented` (`NativeCall.fs:895`). `NativeLibc` implements only `kill`, `raise` and `gettid` (`NativeLibc.fs:368-385`).
- `SystemNative_ForkAndExecProcess` is `failUnimplemented`.
- No refusal or `failwith` names masks, except the U3 throw in `spawn`.

### (c)/(d) Does a correct model of .NET need per-thread masks?

**For what .NET can reach today, no.** In real .NET every thread's mask is empty, except:
1. inside a handler, which is already modelled as frames;
2. the forking thread during `ForkAndExecProcess`'s window, which PawPrint will run as one atomic native call;
3. CoreCLR's own alternate-stack activation masking, which PawPrint doesn't run.

The window in item 2 has one lost schedule. A signal arriving while the forking thread is the leader and has everything blocked goes, on real .NET, to another thread. That thread runs the same shim handler, which writes the same byte into the pipe. The difference is only which thread's syscall sees EINTR. I consider this acceptable and not worth modelling.

**What breaks today, or will break soon:**
- **U3**: `spawn` from inside a handler throws. A real mask (spawn copies the parent's *current* mask) deletes the throw rather than typing it.
- **fork/exec from inside a handler** has the same shape. On a real kernel the child of `fork` gets the forking thread's mask, and `execve` keeps the mask and the pending set while resetting caught dispositions. If the forking thread is in a handler, the child's mask is that frame's mask, and the child has no frames. The kernel cannot represent this without a base mask. **The multi-process session should refuse fork and exec from inside a handler until masks land**, exactly as `spawn` does. (A question for that session, not for Patrick.)
- **A process that boots with signals blocked.** A mask is inherited across `execve`, for example from a parent that forked while blocking. `KernelConfig` already has inherited *ignores* (signals research §7); an inherited mask has no home. Minor.
- With an explicit mask, the `LeaderBlocks` refusal becomes reachable with no handler involved. For .NET it is still unreachable.

### (e) A second client
The trace replayer named on #1726 needs this almost immediately:
- **Linux.** glibc's `pthread_create` brackets `clone3` with `rt_sigprocmask(SIG_BLOCK, ~0)` and `rt_sigprocmask(SIG_SETMASK, old)`. `posix_spawn`, `system()` and `abort()` call it too.
- **Darwin.** Libc's `pthread_create` and `posix_spawn` do the same through `__pthread_sigmask`.
- **Every multithreaded program's trace contains it, `dotnet` itself included.** A replayer without masks would refuse essentially every real trace.
- `sigsuspend` and `pause` are the classic race-free wait in C. `sigwait` is the standard "signal thread" pattern in daemons.

### Verdict
- **`sigprocmask`/`pthread_sigmask` + `sigpending`: needed for release.** One PR.
- **`sigsuspend` (with `pause`): needed for release.** One PR, after the first.
- **Receiver beyond the leader: release-optional.** One PR. Every row is already measured.
- **`sigwait*`: post-release**, unless a replay corpus shows it often.
- **`sigaltstack`: out of scope.** It describes user memory, and `SS_ONSTACK`/`EPERM` are decided by the *user stack pointer* (Linux `on_sig_stack(sp)`). Both are the client's facts, as `mmap` is. If the replayer wants it answered, a record-only form taking the client's stack pointer as an argument is one small PR. Patrick to confirm (Q3).

### Where it fits
**State.** Option (a) of 2026-09-16 Decision 3 still stands: `Blocked : Set<Signal>` on `UnixTaskState`, required by `UnixTaskTable.register`, so every creation site has to say whose mask the task inherits. Its consequences:
- `HandlerFrame.Mask` splits in two.
  - The frame stores the **saved** mask, which is the mask at delivery and what `sigreturn` restores.
  - The task's current mask lives on the task. Delivery sets it to `saved ∪ sa_mask ∪ {sig}`.
  - This is what the measured "restored exactly, whatever the handler did" row requires.
- `maskOf` reads the task.
- The skill's §2 note ("a mask exists only while a handler runs") and the `SignalState` type docstring change with it.
- The alternative is to keep masks in `SignalState` as a `Map<'Task, Set<Signal>>` holding only non-empty masks (absent means empty). This is the "map form" from skill §2, and it keeps the change inside `SignalState`/`UnixProcess`, away from `UnixTask.fs`. The cost is that inheritance becomes something a caller must remember to do, which Decision 3 rejected for that reason. **I recommend (a)**, unless the multi-process refactor moves tasks under processes in a way that makes `SignalState` the natural owner. Decide after seeing that shape.

**Syscalls** (`UnixSignal`):
- `sigprocmask how set` gives `Ok old` or `Failed EINVAL`. A changed mask can make a pending signal deliverable, and the client learns that from the next `onReturnToUser`, as now.
- `sigpending task`.
- `sigsuspend task mask` parks a task with a **temporary mask**. The park record stores the saved mask, the condition is `SignalDeliverable` alone, and the finish always answers EINTR. The delivered frame's *saved* mask must be the pre-call mask, not the temporary one; probe M3 checks this.
- `pause` is `sigsuspend` with the current mask.
- **New `ParkedSyscall` cases: `SigSuspend`, `Pause`. No new `WakePrimitive`.** `SyscallInterruption.wakes` already asks `onReturnToUser`, which reads the mask.

**Raw `sigset_t`.** Linux's `rt_sigprocmask` takes a `sigsetsize` (8, else EINVAL) and a 64-bit word. Darwin's `sigset_t` is 32 bits and has no real-time signals. By the 2026-10-03 decision that the kernel decodes `struct sockaddr` itself, a per-flavour `SignalSet` decoder belongs in the kernel too. That needs Patrick's confirmation (Q4).

**Receiver PR.** This replaces `LeaderBlocks` with the measured rules: Darwin's first-created non-blocking thread, and Linux's `curr_target` cursor. The cursor is new per-process state, and `analyse_receiver.py` is already a reference model to property-test against. It also has to settle the Darwin rows behind `PendingForProcessAndLeader`, since Darwin assigns a process-directed signal to a thread at generation.

**PawPrint side.** No BCL caller exists. The only end-to-end observer is a raw-libc `pthread_sigmask` arm in `NativeLibc`, modelled on `kill` (`sourcesImpure`, both flavours). With a non-empty mask on the leader, `SignalDispatch`'s "only the leader is asked" (`SignalDispatch.fs:50`) becomes a refusal path that needs to stay loud.

**Second client: `siglongjmp`.** A C program commonly leaves a handler by `siglongjmp` and never calls `sigreturn`. The frame stack then needs an "abandon frames down to here" operation, and `siglongjmp`'s mask restore is just `sigprocmask`. This is not needed for .NET: PawPrint's PAL fault path already pops what it pushes. Note it for the replayer.

### Measurements needed
Most rows are already measured (listed in §1). New rows:

| probe | what | why |
| --- | --- | --- |
| **M1** `sigprocmask-ops.c` | each `how` (BLOCK, UNBLOCK, SETMASK, and an invalid value), a NULL `set` (query), whether `oldset` is written on an error, the raw `rt_sigprocmask` with `sigsetsize` ≠ 8 (Linux), and `sigprocmask` against `pthread_sigmask` in a multithreaded process (Darwin's `sigprocmask` is per-thread, as on Linux? measure). Also: unblocking two pending signals delivers both frames at the return from `sigprocmask` itself, in `pickRank` order | the syscall's own answers |
| **M2** `sigpending-scope.c` | `sigpending` on threads A and B after a process-directed signal that both block. Is it Linux's `(own ∪ shared) ∩ blocked`? Is it Darwin's assigned-thread-only? Also an ignored-and-blocked signal (Linux keeps it pending), and a pending *unblocked* signal inside a handler | divergence, and the Darwin row behind `PendingForProcessAndLeader` |
| **M3** `sigsuspend-mask.c` | the mask during the wait; the mask inside the handler (`temp ∪ sa_mask ∪ sig`?); the mask after return (the original); a temporary mask that unblocks an already-pending signal (immediate handler + EINTR); an ignored signal (keeps sleeping); a default-terminate signal; SIGKILL/SIGSTOP in the temporary mask. The same for `pause` | the saved-mask rule |
| **M4** (with the multi-process work) | the fork child's mask is the forking thread's; the child's pending set is empty; `execve` keeps the mask and pending set and resets caught dispositions; a pending caught signal whose disposition becomes default at `execve` | inheritance |
| **M6** (post-release) `sigwait.c` | which pending signals `sigwait` takes (must they be blocked?); priority against a deliverable handler; `sigtimedwait` timeout and EAGAIN (Linux only: Darwin has `sigwait` alone) | `sigwait*` |

## 3. Sleeping on time

### (a) Does .NET reach it? (b) What does PawPrint do?

| path | real .NET | PawPrint |
| --- | --- | --- |
| `Thread.Sleep` | QCall `ThreadNative_Sleep`, then PAL `InternalSleepEx` (`$RT/src/coreclr/pal/src/synchmgr/wait.cpp:824-854`), then `BlockThread`, a condition-variable timed wait. **A futex, not `nanosleep`** | `NativeThreading.fs:629-693`: `Scheduler.blockOnSleep` with a deadline on `VirtualClockTicks`. The client's own block |
| `Task.Delay`, `System.Threading.Timer`, the threadpool's wait thread, `WaitHandle.WaitOne(t)`, `Monitor.Wait(t)` | the timer thread and wait handles, all PAL timed waits or `LowLevelMonitor_TimedWait` (`pthread_cond_timedwait`) | `NativeLowLevelMonitor.fs:100-160`, `NativeWaitHandle`, `NativeMonitor`: the client's deadlines |
| `nanosleep` in the runtime | `$RT/src/native/minipal/time.c:151` (`minipal_microdelay`, called only from `vm/threadsuspend.cpp:3361-3366`), `gc/unix/gcenv.unix.cpp:553`, `pal/src/misc/time.cpp:182` (`PAL_nanosleep`: eventpipe, PAL pipe-open retry), `pal/src/synchobj/mutex.cpp:797` | Never: all native CoreCLR internals |
| `Socket.Poll(µs)`, `ConsolePal.Write` on EAGAIN (`poll` −1), FileSystemWatcher (`poll` with a timeout), socket engine (`epoll_wait`/`kevent`) | `SystemNative_Poll` and `SystemNative_WaitForSocketEvents` | **kernel**: `UnixPoll` parks with `DeadlinePassed`. Done |
| `Socket.Select` | `SocketPal.Select` takes `SelectViaSelect` (`SystemNative_Select`, a real `select(2)` only under `_DARWIN_UNLIMITED_SELECT`, `$RT/.../pal_networking.c:2990-3053`) iff `SelectOverPollIsBroken`. The cctor sets that from `OperatingSystem.IsMacOS/IsIOS/IsTvOS/IsMacCatalyst`, which **compile to constants per CoreLib flavour** (Linux CoreLib's `IsMacOS` is `ldc.i4.0; ret`). Otherwise it uses `SelectViaPoll` | Linux flavour: `SystemNative_Poll`, modelled. **Darwin flavour (a macOS dev box): `SystemNative_Select` is `failUnimplemented`** |
| `alarm`, `setitimer`, `timerfd_*`, `EVFILT_TIMER`, `pselect`, `ppoll`, `usleep`, `clock_nanosleep` | no hits anywhere in `$RT/src/native/libs` or `$RT/src/coreclr/pal/src` (beyond the `nanosleep`s above) | unreachable |

### (c) Kernel scope?
- **`nanosleep`/`clock_nanosleep`: kernel.** The task blocks in the kernel on a clock, which is exactly a park whose condition is `AnyOf [DeadlinePassed d; SignalDeliverable]`. This is not the client's futex. "The client decides, the kernel records" is unaffected: the kernel says when the deadline has passed (pulled), and the client chooses when to run the woken task. `Thread.Sleep` stays the client's, by the 2026-09-26 decision ("Out of scope: PawPrint's CoreCLR-level waits"), and because it really is a futex.
- **`select`/`pselect`/`ppoll`: kernel**, as `poll` is.
- **`alarm`/`setitimer`/`timer_create`: kernel**, because the kernel owns both the clock and signal generation. **But they need something the design doesn't have yet: time passing that *generates* something.** Today `advanceClock` returns only a machine (§1), and a timer expiry is a signal *generation*, which can terminate the process at generation (`SignalState.generate`). It also has to bound the client's idle jump: with every task asleep, the next expiry is a deadline even though no park names it.
- **`timerfd`, `EVFILT_TIMER`: kernel.** Readiness becomes a function of the clock. `WakeCondition.deadlines` (`WakeCondition.fs:384`) reads only the condition, but the deadline of a wait on a timerfd depends on the timer's *current* setting, which another task can re-arm during the wait. So the public `WakeCondition.deadlines` would need the system.
- **`ITIMER_VIRTUAL`/`ITIMER_PROF`** need per-task CPU time ("Task T used d of CPU time", #1726, unbuilt). Deferred with the CPU-time clocks.

### (e) A second client
- `nanosleep`/`clock_nanosleep` appear in any trace that sleeps (`sleep 1`, `usleep`, every retry loop). Go and Rust runtimes use them too.
- Darwin has no `clock_nanosleep`. Its libc `nanosleep` is the `__semwait_signal` syscall, so a dtruss trace shows that call, and the replayer has to map it onto `nanosleep`. The kernel already models at the POSIX surface (`pthread_kill`, `getentropy`), so this fits.
- `select` is common in older code; `alarm` in shell tools (`timeout(1)`) and test harnesses (every probe in this repo calls `alarm()`). `timerfd` is used by systemd's sd-event; `EVFILT_TIMER` by libdispatch, so any GCD timer on Darwin.

### Verdict
- **`nanosleep` + `clock_nanosleep`: needed for release** (second client). One PR, small.
- **`select`: release-optional.**
  - Linux `select` uses the same `f_op->poll` as `poll`, through `POLLIN_SET`/`POLLOUT_SET`/`POLLEX_SET`, so it's a thin layer over `LinuxReadiness`.
  - Darwin `select` is **not** kqueue-based, unlike Darwin `poll` (`darwin-poll-options.md`). It goes `select_internal`, then `selscan`, then `fo_select`, so it needs its own readiness sweep.
  - Its only PawPrint consumer is Darwin-flavour `Socket.Select`, and CI and production are Linux. 1 PR Linux, plus 1 PR Darwin.
- **`pselect`/`ppoll`/`epoll_pwait`: after masks.** They reuse `sigsuspend`'s temporary-mask park. One PR.
- **`alarm`/`setitimer(ITIMER_REAL)`/`getitimer`: post-release.** But their **API consequence is a breaking change to `advanceClock`**: it would return something like `Continues of system | ProcessEnded of …`, and the idle-jump query would grow timer expiries. Decide before #1766's API baseline whether it is in 1.0 (Q5). Options doc + 1 PR.
- **`timerfd`, `EVFILT_TIMER`: post-release.** 2 PRs and 1 PR. `timerfd` also changes `WakeCondition.deadlines`' signature.

### Where `nanosleep` fits
Two genuinely different options:
- **(A) A new `ParkedSyscall.Sleep { Clock; Deadline; Relative }`**, condition `AnyOf [DeadlinePassed; SignalDeliverable]`.
  - `UnixClock.nanosleep`/`clockNanosleep` validate the timespec (EINVAL rows) and answer at once for a zero or past deadline. Otherwise they park.
  - `finishSleep` answers 0 on the deadline. On a signal it answers EINTR, with `rem = deadline - now` when relative, never restarting, as measured.
  - Absolute `CLOCK_REALTIME` converts exactly to since-boot, because this kernel has no `settimeofday`; that becomes a refusal or a re-evaluation the day one exists.
  - Touches `UnixTask.fs`, `WakeCondition.fs`, and the exhaustive `ParkedSyscall` matches in `Readiness.fs` (being refactored), `UnixSystem.fs`, `UnixDescriptor.fs` and `SyscallInterruption.fs`.
- **(B) Express it as the existing `poll` park with no entries.** No new case, so no conflict with the refactor. But `rem`, the clock choice and `TIMER_ABSTIME` would ride on `poll`'s record, and the finishing call would have to know which syscall it is finishing. That puts two syscalls behind one record.

**Recommend (A).** The match sites are mechanical, and the record stays honest.

### Measurements needed
| probe | what |
| --- | --- |
| **S1** `nanosleep-edges.c` | `tv_nsec` ≥ 1e9 or negative, and negative `tv_sec` (EINVAL?); zero (immediate, no park?); `rem` after EINTR (both flavours); a huge `tv_sec` (overflow behaviour); a stop/continue without a handler (Linux `restart_syscall`: does the sleep resume transparently?) |
| **S2** `clock-nanosleep.c` (Linux) | accepted clock ids (REALTIME, MONOTONIC, BOOTTIME, TAI, the CPU clocks giving ENOTSUP/EINVAL, an invalid one); a past `TIMER_ABSTIME` deadline; that errors are *returned*, not set in `errno`; `rem` untouched for absolute sleeps |
| **S3** `select-edges.c` | `nfds` bounds (0, > `FD_SETSIZE`, > `RLIMIT_NOFILE`); a closed fd in a set (EBADF); Linux rewriting `timeout` to the remaining time, against Darwin not doing so; then a Darwin readiness sweep over the 51 states of `darwin-poll-options.md` §3, read/write/except sets |
| **S4** `itimer.c` (post-release) | `alarm`'s returned seconds (rounding); `alarm(0)`; ITIMER_REAL period and overrun coalescing after a long stall; fork clears and exec keeps |
| **S5** `timerfd.c`, **S6** `evfilt-timer.c` (post-release) | expiration counts, flags, readiness under poll/epoll/kqueue, and the `flock` identity of a timerfd (skill §4: measure, don't assume `anon_inodefs` sharing) |

## 4. Conflict with the multi-process refactor

That session is changing `UnixSystemState`, `UnixProcess`, `FileDescriptorRegistry`, `UnixMachine`, `Readiness` and `ObjectLifetime`.
- **Masks.**
  - `SignalState` (frames, pending) lives on `UnixProcessState.Signals` (`UnixProcess.fs:116`), and a per-task mask goes on `UnixTaskState` (`UnixTask.fs`), whose ownership the refactor may move under a process.
  - `fork`/`exec` must copy and keep the mask (M4).
  - **Sequence the mask PR after the refactor's process split.** Meanwhile, the refactor should refuse fork and exec from inside a handler, the way `spawn` does. Whichever lands second carries the inheritance line, and a required `register` argument makes the compiler flag it.
- **`nanosleep`.** It adds a `ParkedSyscall` case, which touches the exhaustive match in `Readiness.fs` (`Readiness.fs` matches `ParkedSyscall.Poll`/`KqueuePoll`). The rest is in files the refactor isn't changing. Low conflict. It can go now, or right after the refactor's `Readiness` change.
- **Interval timers** are per-process state (`UnixProcess`); fork clears them and exec keeps them. **`timerfd`** is a new descriptor kind (`FileDescriptorRegistry`, `ObjectLifetime`, `Readiness`). **Both must wait** for the refactor.

## 5. Questions for Patrick
1. **Does the second client set the bar for release?**
   - If yes: masks, `sigsuspend`/`pause` and `nanosleep` are release work (3 PRs).
   - If no: .NET reaches none of them, so only the mask PR is needed, for fork/exec inheritance and the U3 throw. Everything else waits for a client that asks.
2. **The receiver PR:** make it release work, or keep the sound `LeaderBlocks` refusal?
3. **Is `sigaltstack` the client's**, like `mmap`, given that its answers depend on the user stack pointer? I recommend yes.
4. **Raw `sigset_t`:** does the kernel decode it per flavour, the way the 2026-10-03 decision has it decode `struct sockaddr`? Or does it take `Set<Signal>` and leave the bytes to the client?
5. **Interval timers and 1.0:** decide before the API baseline (#1766) whether `advanceClock` will ever generate signals. If yes, its result type should change before 1.0, even if `alarm` is built later.

## Decision (orchestrator, 2026-10-08, on Fable's advice; main at `8dd86f9c`)

Patrick settled Q1, Q2 and Q5 on 2026-10-07 (see #1726): the second client doesn't set the release bar, `LeaderBlocks` stays, `advanceClock` stays state→state. Q3: `sigaltstack` is the client's, decided by the orchestrator on 2026-10-09 (Patrick had no preference). So release work here is the mask PR and the `sigsuspend`/`pause` PR.

**Q4: a signal set crosses as `Set<Signal>` (option A), with a codec the kernel publishes.**
- The sockaddr decision's premises don't hold for `sigset_t`. A sockaddr's copy extent depends on the syscall and its state, and its errno ladder interleaves with decoding. A `sigset_t` is a fixed-width bitmap, Linux 8 bytes and Darwin 4. Bit `n-1` is signo `n`, which `Signal.ofRawSignoUnder` already decodes.
- `sigaction`'s `SignalCatch.Mask` is already a `Set<Signal>`. Option B would make every set-taking call a bytes API while `sa_mask` stays typed.
- strace prints sets already decoded, so a replayer holds names, not bytes.

The codec is `SignalSet.ofWord numbering : uint64 -> Result<Set<Signal>, unnamed bits>` with a total `toWord`, round-trip property-tested. On Darwin, a bit that names no signal (bit 31) is refused until M1 measures what xnu does with it.

The API has two levels, following `sigaction`/`sigactionSyscall`:
- libc level, `sigprocmask`/`pthread_sigmask`, which drops 32/33 on Linux as glibc does;
- raw `rt_sigprocmask`, which takes `sigsetsize` and gives EINVAL unless it is 8, screened first.

`how` is passed raw and decoded per flavour, as `signo` is: Linux numbers it 0/1/2, Darwin 1/2/3. An unknown value gives EINVAL.

**Q2: masks live in `SignalState`, as option (b), overturning the note's (a).**
- Multi-process stage 3 made task creation the library's own business. `UnixTaskTable.add` is internal, with two call sites: `ProcessLaunch.launchOnto` and `UnixTaskLifecycle.spawn`. Decision 3 objected to (b) because "inheritance is a discipline a client must remember"; that discipline no longer exists.
- Masks are written by delivery, `sigreturn` and `sigsuspend` inside `SignalState`, and read by `receiverFor`. Frames already live there under the same trade-off, `HandlerFramesWithoutTask`.
- The design: `Blocked : Map<'Task, Set<Signal>>`, holding non-empty masks only, plus a saved mask for `sigsuspend`, both in `SignalState`.
  - `maskOf` keeps its signature.
  - `forgetTask` clears both maps.
  - `checkInvariants` gains `MaskWithoutTask`.
  - `spawn` inherits its creator's current mask, which deletes `SpawnRefusal.InheritedHandlerMask`.
- A mask inherited across exec needs no `ProcessLaunch` field. The host calls `sigprocmask(SIG_SETMASK)` on the leader before its first instruction, as inherited ignores are installed by `sigaction` today.

**`sigsuspend` (second PR).**
- The saved mask is per-task signal state, not park payload. The frame that delivery pushes must save the pre-call mask, while the deliverability check and `maskDuring` use the temporary one. That is Linux's `saved_sigmask` with `TIF_RESTORE_SIGMASK`.
- "Always EINTR" is wrong when no handler ran: a default stop followed by continue restarts transparently. Keep today's `DefaultAction` refusal for that case, and add an M3 row for stop then SIGCONT during `sigsuspend`/`pause`.
- M1 adds a row: raw `rt_sigprocmask` blocking signal 33, then reading `oldset` through glibc's wrapper. glibc screens `set` but not `oset`.

## Amendment (orchestrator, 2026-10-08, after M1/M2: probes on branch `pk-sigprocmask`)

Measured on Darwin 27.0 and Linux 6.18.5, with these consequences:
1. **On Darwin, `sigprocmask` (both libc and `SYS_sigprocmask`) applies to every thread in the process; `pthread_sigmask` affects only the caller.** On Linux, every route is per-thread. So there are two entry points:
   - `pthreadSigmask` is per-task.
   - `sigprocmask` on Darwin changes every task and answers the caller's old mask.
   
   No "who else changed" answer is needed: other tasks learn through `UnixWait.wakes` and `onReturnToUser`, as they do after `kill`.
2. **Darwin keeps bit 31 (signo 32, which names no signal), and its `sigfillset` sets it.** A full mask reads back as `0xfffefeff`. The Q4 decision therefore changes from `Set<Signal>` to an opaque `SignalMask`, built from a word or from a set of signals, which carries the bits that name no signal.
   - The codec refuses only bits the flavour's `sigset_t` cannot hold.
   - SIGKILL/SIGSTOP are screened when a mask is stored, in `SignalState`.
   - `SignalCatch.Mask` becomes a `SignalMask` too, storing whatever Darwin's `sa_mask` is measured to keep. That change gets a PR of its own (`pk-signal-mask-type`), and `pk-sigprocmask` stacks on it.
   - Refusing bit 31 instead would have refused Darwin libc's own full-mask idiom, which `pthread_create` uses.
3. **A blocked SIGCONT at its default stays pending** (`sigpending` shows it on both flavours). The model consumed it at `onReturnToUser`. The fix: the continue happens at generation, and the pending entry is gated by the mask like any other signal.

Confirmed as the doc assumed:
- `how` numbering, and EINVAL only with a non-null `set`; `old` is never written on failure.
- Raw `sigsetsize` ≠ 8 gives EINVAL, screened first.
- glibc drops 32/33 from `set` but not from `oset`.
- `sigpending` is Linux's `(own ∪ shared) ∩ blocked`. On Darwin it is the leader-only shape the model already has.
- An ignored-and-blocked signal is kept on Linux and discarded on Darwin, except CONT.
- Unblocking several pending signals runs every handler before the call returns.
