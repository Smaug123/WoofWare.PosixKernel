# Plan: `kill(2)` between processes

Status: proposed 2026-10-18, for Patrick to choose among the options. Nothing here is implemented.

It builds on PR #105 (`kill-targets-measured`).
That PR measured `kill(2)` against every kind of target (`docs/probes/kill-targets`), and is being changed so that the model answers `ESRCH` for a pid that names nothing and keeps refusing pid 1.
This plan assumes that change has landed, and does not repeat it.

## 0. In brief

Today `UnixSignal.kill` answers only a signal to the caller's own process, and refuses every other positive pid (`KillRefusal.OtherProcess`).
This plan makes it answer a signal to another process the system holds, wherever the answer is measured.

Six things have to change, and each has a decision for Patrick in §3:

1. **When a fatal signal ends its target.** A self-kill ends the process inside the `kill` call. A kill from outside does not: the target's threads exit as each next runs, and `kill` can return first. (Decision T.)
2. **The answer.** If the target can end inside the call, `kill` must say so, and `ProcessFate.ProcessEnded` means the caller ended. (Decision A, which T decides.)
3. **The rule that a call changes only its own process.** A kill must write the target's signal state and mark the target's threads as owing a return. (Decision B.)
4. **Sessions.** On Linux, `SIGCONT` is allowed within a session even where the uid rule refuses everything else, and the model has no sessions. (Decision C.)
5. **Where the signal lands, and who takes it.** (Decision D.)
6. **Stops.** A stop of another process leaves a stopped process that the caller can go on talking to, and the model holds no stopped state. (Decision E.)

Recommended, in short:
- a fatal signal from outside marks its target as exiting where the flavour commits the death at generation (Linux, and `SIGKILL` on Darwin, if the probes agree); every thread of the target then owes a return to user mode, and the target ends at the first of those returns the client makes (T2a). A Darwin `SIGTERM` stays pending on its receiver instead, whose return applies whatever disposition holds then;
- so `kill`'s answer type does not change, since the target's end is reported where a process's end already is: by the return to user mode that ends it (A0);
- kill's body running over the whole kernel through one new entry point, with every other call machine-checked to leave other processes alone (B2);
- `SIGCONT` refused where only a session could permit it (C1);
- the signal generated into the target exactly as a self-kill generates it, with the target's sleeping threads woken by the existing pull sweep (D1);
- a stop of another process refused (E1).

The work is four stages after a probe stage (§5), or five under T1.
Signal 0 comes first, because it needs permission and existence checks but changes nothing.
Then come signals that leave the target running, then signals that end it.

## 1. What a real kernel does

Patrick asked for kernel semantics to be explained concretely, so this section says what both kernels do before any design.

### Linux

`kill(pid, sig)` with `pid > 0` does this (`kernel/signal.c`, `kill_proc_info` → `kill_pid_info` → `group_send_sig_info`):

1. It looks `pid` up among *task* IDs, so a thread ID finds that thread. If nothing is found, it answers `ESRCH` before it looks at `sig` (#105: `kill(reaped, 999)` is `ESRCH`).
2. It checks that `sig` is 0..64, and otherwise answers `EINVAL`.
3. It checks permission (`check_kill_permission`). A thread of the target's own process always may. Otherwise it is allowed iff one of these holds:
   - the sender's real or effective uid equals the target's real or saved uid (`kill_ok_by_cred`);
   - the sender has `CAP_KILL`;
   - the signal is `SIGCONT` and both are in the same session.

   Signal 0 is checked too, which is how `kill(pid, 0)` tests for permission.
4. If `sig` is 0, it stops there and answers 0.
5. It *generates* the signal: it puts it in the target process's shared pending set, or discards it at once if it is ignored. It then picks a thread to wake (`complete_signal`). It prefers the thread the pid named, which for a pid is the leader, if that thread "wants" the signal: the thread does not block it, and is either running or has no signal pending yet. Otherwise it walks the other threads from a cursor (`signal->curr_target`).
6. A fatal default (`SIGKILL`, or `SIGTERM` with no handler) is decided at generation, if some thread could take it: the process is marked as exiting (`SIGNAL_GROUP_EXIT`), and every thread of it is sent `SIGKILL` and woken, whatever it blocks. But each thread exits in its own context, as it next runs (`do_exit`), and the descriptors are closed only as the last thread drops the shared table (`exit_files`). So `kill` can return while the target still holds every descriptor. A stop default (`SIGSTOP`, or `SIGTSTP` with no handler) takes effect when a thread next returns to user mode. `SIGTSTP`, `SIGTTIN` and `SIGTTOU` do nothing in an orphaned process group; `SIGSTOP` always stops.

The sender carries on. Nothing about the target flows back to it, except the errno.

### Darwin

XNU's `kill` (`bsd/kern/kern_sig.c`) checks the number first, so a bad number is `EINVAL` even for a pid that names nothing (#105).
It then finds the process (`ESRCH`) and checks permission (`cansignal`).
`cansignal` has the same shape as Linux's rule, with root (`kauth_cred_issuser`) for `CAP_KILL`, and the same session exception for `SIGCONT`.
Then it generates the signal, picking the receiving thread at once: the first-created thread that does not block it.
A fatal signal is acted on by the target's own threads, as on Linux. Codex, reviewing this plan, observed on Darwin 27 that a non-blocking read of a pipe whose only writer was the target answered `EAGAIN` straight after `kill(target, SIGKILL)` in 100 runs of 100, and end of file only after `waitpid`. That observation is not committed; P1 measures it on both flavours.

That is the shape from source. The policy is to answer only what has been measured; §2 says which parts are.

### A worked example

Process A (pid 4242, uid 1000) sends `SIGUSR1` to process B (pid 4243, uid 1000).
B has a handler for `SIGUSR1` installed with `SA_RESTART`, and its leader is asleep in `accept`.

1. B exists, `SIGUSR1` is a signal, and A's real uid equals B's real uid, so the call is allowed.
2. `SIGUSR1` goes into B's process-wide pending set. B's leader does not block it, so the leader is chosen and woken.
3. A's `kill` returns 0. A runs on.
4. B's leader leaves `accept`, returns to user mode, runs the handler, and restarts the `accept`.

In the model, steps 2 and 4 already exist for a `kill(getpid(), SIGUSR1)` made by one of B's own threads.
The only new parts are step 1, and doing step 2 to a process other than the caller's.

If the signal were `SIGTERM` and B had no handler, step 2 would mark B as exiting and wake every thread of it, and A's `kill` would return 0.
B would end only as its threads ran: its descriptors would close when the last of them exited.
Between the two, A can still see B holding everything it held.
When the model says B ends, and how a client learns of it, are Decisions T and A.

## 2. The facts, and which are measured

"Measured" means a committed probe output on that flavour.
#105's outputs are `docs/probes/kill-targets/measured-linux-6.18.5-aarch64-uid{0,1000}.txt` and `measured-darwin-27.0-uid501.txt`.

| # | Fact | Linux | Darwin |
| --- | --- | --- | --- |
| F1 | A pid naming nothing is `ESRCH`; the check order | measured: ESRCH, then EINVAL, then EPERM | measured: EINVAL first |
| F2 | The uid rule between non-root users | measured: all 64 combinations of (real, effective, saved) from {1000, 1001}. Allowed iff the sender's real or effective uid equals the target's real or saved uid | **unmeasured**: this Mac cannot change uid. Only measured: a uid-501 process signals another uid-501 process through `kill(0)` and `kill(-pgid)` (group rows), and gets EPERM from pid 1 |
| F3 | Root as sender or target | measured only for (0, 0, 0) → (1000, 1000, 1000) allowed, and (1000, 1000, 1000) → (0, 0, 0) EPERM, signal 0 included | unmeasured |
| F4 | A sender holding uid 0 in some but not all of its three uids | **unmeasured** | unmeasured |
| F5 | Signal 0 is checked for permission | measured (the `cred` rows with `sig=0`) | measured (pid 1 is EPERM for signal 0) |
| F6 | The `SIGCONT` session exception | measured: same session 0, another session EPERM, where signal 0 is EPERM | **unmeasured**: it needs a target of another uid |
| F7 | `kill` of another thread's ID | measured: that thread takes the signal | not applicable: thread IDs are not pids |
| F8 | Which thread of the target takes a process-directed signal | measured only with the sender inside the target process (`signalReceiver/linux.txt`, 192 rows): the leader whenever it does not block it. #102 measured that an asleep leader with a signal already pending is passed over | measured only with the sender inside: the leader whenever it does not block it, else the first-created thread that does not |
| F9 | A target that blocks the signal | measured for a sender inside (`non-leader-unblock`, `sigcont-generation`) | the same |
| F10 | A target with threads asleep in calls | measured for a sender inside (the interruption rows in the divergence index) | the same |
| F11 | `SIGKILL`, `SIGTERM` and core-dumping defaults ending another process; the status its parent reads | the end is measured only for self-sent signals (`core-class.c`, `process-termination`) | the same |
| F12 | `SIGSTOP` and `SIGTSTP` to another process | unmeasured (and not needed if E1 is chosen) | unmeasured |
| F13 | `SIGCONT` to a running target | measured for a sender inside (`sigcont-generation.c`) | the same |
| F14 | A zombie target (ended, not yet reaped) | **unmeasured** | **unmeasured** |
| F15 | `kill(0)`, `kill(-pgid)`, `kill(-1)` | measured (the `group` and `all` rows), and needs process groups | measured (the `group` rows) |
| F16 | `RLIMIT_SIGPENDING` counts real-time signals per real user of the receiver, across processes | measured (#107) | not applicable: Darwin has no real-time signals |
| F17 | Job-control stops do nothing in an orphaned process group | unmeasured. `non-leader-unblock.c` calls `setpgid` to avoid exactly this, and says so in a comment | unmeasured |
| F18 | Whether a fatal signal from outside has ended its target, and closed its descriptors, by the time `kill` returns; and what the target answers in between (`kill(target, 0)`, a second signal) | **unmeasured** | **unmeasured**, but observed once by the reviewer (not committed): still open after `SIGKILL`, 100 of 100 |
| F19 | Whether a fatal default from outside can still be averted by a disposition the target installs after `kill` returns | **unmeasured** (by source, no: committed at generation) | **unmeasured**, but observed once by the reviewer (not committed): `SIGTERM` averted by a later `SIG_IGN` in 86 of 100 |

### Why a sender outside the target must be measured again

F8 to F13 are measured, but every measurement sent the signal from a thread of the target process.
By the source, the sender does not enter Linux's `complete_signal` or XNU's `get_signalthread`, so a sender outside should change nothing.
The policy says to measure that rather than read it, and it matters here for a second reason: the oracle recommended in §5 assumes it.
That oracle is "a kill from outside does to the target exactly what a kill from inside does".

### Probes still to write

All of them run on Linux in the container, as root and as uid 1000 through `setpriv`, and on this Mac as uid 501.
Each row runs in a fresh forked child that is in a process group of its own, under a parent in the same session (as `non-leader-unblock.c` does), so that no row is in an orphaned process group.

**P1, `docs/probes/kill-across`: a sender in another process.** The target is a forked child with four threads. The sender is its parent, or a sibling.
- *Receiver* (F8, F9): `SIGUSR1` caught, under every mask set short of all four threads, with threads asleep in `poll` or spinning. Which thread ran the handler? Also #102's shape: the leader asleep with a signal already pending, then a second signal from outside.
- *Interruption* (F10): the target's leader asleep in `accept`, `read` of a pipe, `poll` with and without a timeout, `sigsuspend`, `pause`, and on Linux a futex wait. Each is ended by a caught `SIGUSR1` from outside, with and without `SA_RESTART`. Does the call fail with EINTR or restart? A subset of the existing in-process rows is enough to confirm that they agree.
- *Ignored and continue* (F13): `SIGUSR1` under `SIG_IGN`, `SIGWINCH` at its default, and `SIGCONT` at its default and caught, each to a target whose leader blocks it or does not. Is it pending afterwards (`sigpending`), and does a handler installed later run?
- *Defaults that end* (F11): `SIGTERM`, `SIGKILL`, and `SIGQUIT` with `RLIMIT_CORE` 0 and infinite, to a target whose threads are asleep, spinning, or blocking the signal. The `waitpid` status. Whether a target that blocks `SIGTERM` in every thread survives with it pending. The order in which the target's descriptors are closed, as seen from the sender's end of a socket pair.
- *The time between* (F18), observed before any `waitpid`, straight after `kill` returns and again after `sched_yield` and after a short sleep: a non-blocking read of the sender's end of a loopback TCP connection whose other end the target holds and has written nothing to (`EAGAIN` while the target holds it, end of file once its end has closed), which is the cross-process resource the model can build (a pipe cannot reach another process in the model); a non-blocking read of a pipe whose only writer is the target, for comparison with the reviewer's Darwin observation; `kill(target, 0)`; and a second `kill(target, SIGUSR1)`. On Linux, also with the sender and the target pinned to one CPU and the sender under `SCHED_FIFO`, so that the target cannot preempt it, with each target thread's `/proc/<tid>/schedstat` read before and after to confirm the target did not run in between (as root only, for `SCHED_FIFO`; a non-leader thread whose entry has gone has run its exit); and pinned to two CPUs, where it can (Darwin has neither an affinity call nor a way to read a thread's run time from outside, so its rows show only what some schedule allows). This decides Decision T: one schedule in which the target still holds its descriptors after `kill` has returned rules out ending the target inside the call, and end of file seen straight after `kill` rules out nothing, because the target may have run first. A probe cannot see the target's threads exit one by one, so it can only bound the window, not say which thread's exit closed the descriptors.
- *Commitment* (F19): when a fatal default from outside becomes irrevocable. The target's leader does not block the signal and is asleep in `poll`; a worker blocks it. After the sender's `kill` returns, the worker installs `SIG_IGN`, or a handler, for the signal (the sender tells it to through a pipe it watches). Does the target survive, and does the handler run? For `SIGTERM` and `SIGQUIT` at their defaults, and for `SIGKILL` (where the worker's `sigaction` fails, so only survival is asked), with controls that change nothing, on both flavours. Then the same with every thread blocking `SIGTERM` until the worker unblocks it after installing the disposition.
- *Stops* (F12), measured though not modelled under E1: `SIGSTOP` and `SIGTSTP` to a target, then `SIGCONT`. `waitpid` with `WUNTRACED | WCONTINUED`. What became of a target thread asleep in `read`.

**P2: Linux senders holding uid 0 partly** (F3, F4). Senders (0, 1000, 1000), (1000, 0, 1000), (1000, 1000, 0), (0, 0, 1000), (0, 1000, 0) and (1000, 0, 0); targets (1001, 1001, 1001), (0, 0, 0), (1001, 0, 1001) and (0, 1001, 1001); signals 0 and `SIGUSR1`. This can be a section of P1. It decides whether "the sender's effective uid is 0" is the privilege test (`CAP_KILL` follows the effective uid), as it already is for `setresuid`.

**P3: Darwin rows that need no root** (F2, F3).
- A uid-501 process to another uid-501 process, by its pid, for signals 0, `SIGUSR1`, `SIGTERM` and `SIGKILL`.
- uid 501 to a root-owned process other than pid 1 (any root daemon's pid), for signals 0, `SIGUSR1` and `SIGCONT`.
- If a set-user-ID-root program can be left waiting (real uid 501, effective 0), uid 501 to it. FreeBSD restricts signals to set-ID processes, and whether Darwin does is unknown.

**P4: zombie targets** (F14). `kill` of a child that has exited and has not been waited for, with signal 0 and `SIGTERM`, on both flavours. The model answers `ESRCH` for an ended process, as for a reaped one, because it reaps at once (README, "Starting and ending processes"). This probe is for the day `wait` keeps zombies, and blocks nothing here.

**P5: orphaned process groups** (F17). `kill(getpid(), SIGTSTP)` and `kill(getpid(), SIGSTOP)` from a process in an orphaned process group, on both flavours. This blocks nothing here, but see §6: the model's existing self-stop answer may depend on it.

## 3. Decisions

Each decision has at least two options, with their blast radius, how reversible each is, what information each keeps for a client, and how each composes with `ProcessFate`, `Entry`/`Shape`, the wake memo, `checkInvariants`, the step oracle (`TestStepOracle`) and the multi-process fuzzer (`TestMultiProcessFuzz`).

### Decision T: when a fatal signal from outside ends its target

Today a signal whose default terminates the process ends it inside the call that generates it, wherever some thread could take it (chosen 2026-09-22, after Linux's `complete_signal`). For a self-kill, nothing outside the process can run in between, so the shortcut is invisible to the caller.
From outside it is visible. The sender carries on after `kill` returns, and it can read a connection or pipe whose other end the target still holds before the target's threads have run (§1, F18).

**T1. End the target inside the `kill`**, as a self-kill does: its threads go and its descriptors are closed before `kill` answers.
- Blast radius: the smallest in the library. But it needs Decision A to report another process's end in kill's answer.
- Against: it answers what the reviewer's Darwin observation contradicts. A sender's non-blocking read of a pipe the target was the only writer of, or of a connection whose other end the target holds, answers end of file at once, where Darwin answered `EAGAIN` until the target had been reaped. Unless P1 shows that one flavour does close everything before `kill` returns, T1 invents an answer.

**T2. The target ends through its own threads.**
The generation marks the target as exiting, with how it will end (`Signaled (signal, coreDumped)`), as Linux's `SIGNAL_GROUP_EXIT` does.
Every thread of the target then owes a return to user mode, whatever it blocks. A sleeping one wakes on the next `UnixWait.wake`, and its call answers `Interrupted`.
`kill` answers that the caller runs on. Until the client returns one of the target's threads to user mode, the target holds every descriptor it held, and `kill(target, 0)` finds it.
- **T2a.** The first return to user mode the client makes for a thread of the exiting target ends the whole process there, through the existing path: `onReturnToUser` answers `ProcessFate.ProcessEnded`, closing the descriptors as `exitGroup` closes them. One step ends the process, as every end in the model does today.
- **T2b.** Each thread's return is that thread's exit, and the last one ends the process and closes its descriptors, as Linux's `exit_files` does. This is closer to the kernel, but it brings a state the model refuses today: a leader that has gone while other threads live. And no probe can tell T2b from T2a (P1 can bound the window, not see the order in which threads exit).
- What T2 needs that does not exist: an internal "exiting" mark on the process. `checkInvariants` checks that every thread of an exiting process either owes a return or is parked. A parked thread may still be asleep: the kill cannot mark it owing (`UnixThreadTable.owe` refuses a parked thread), and it is woken only by the next `UnixWait.wake` sweep, as every signal's sleeper is. `WakePrimitive.SignalDeliverable` holds for a thread of an exiting process. At the return, the exit comes first, ahead of the refusals that an interrupted call's return makes today (`DefaultAction`, `MixedRestartFlags`). Also a reader, such as `UnixSystem.exiting pid`, if a client needs to know before it returns a thread. P1's "time between" rows decide whether a second signal to an exiting target is discarded, and what `kill(target, 0)` answers.
- Composes with the client's existing loop: a client already returns every thread that owes a return before running it, so the target's end arrives where a process's end from a signal already does.
- The scheduling decision stands: the kernel does not choose when the target's threads run; the client does.
- **When death is committed is per flavour, and per signal.** The exiting mark makes the death irrevocable at generation, which is Linux's shape: `complete_signal`'s fatal path sets `SIGNAL_GROUP_EXIT` and sends every thread `SIGKILL`, so a disposition changed afterwards cannot save the target. Darwin's shape differs. Codex, reviewing this plan, observed on Darwin 27 (uncommitted) a target whose leader did not block `SIGTERM` and whose worker did. The worker installed `SIG_IGN` only after the sender's `kill` had returned, and the target survived in 86 runs of 100, where unchanged controls died in 100 of 100. So on Darwin a catchable fatal default from outside is not committed at generation: it is pending on its receiver, and its default is applied at the receiver's return to user mode, under the disposition then. The model already has that path for a process's own signals that become deliverable later (README, "The return to user mode"). So T2 takes the exiting mark only where the probe shows death committed at generation: on Linux for every fatal default, if P1 agrees, and on Darwin for `SIGKILL`, which no disposition can change, if P1 agrees. A Darwin `SIGTERM`, or any other catchable fatal default, is left pending on its receiver, which owes a return, and the existing return path applies the default, or the handler or ignore installed since. Where P1 does not settle a flavour's commitment point for a signal, that signal from outside is refused (T3) on that flavour.

**T3. Refuse a fatal signal to another process**, and answer only signals that leave the target running.
- Blast radius: none. It is reversible, and it leaves `SIGKILL` and `SIGTERM` between processes unanswered, which are among the commonest kills there are.

**Recommendation: T2a.** End of file seen straight after `kill` proves nothing, because the target may simply have run first, on another CPU or by preempting the sender. One schedule in which the target still holds its descriptors after `kill` has returned is enough to rule T1 out. Darwin already has one such observation, uncommitted. On Linux, pinning both to one CPU is not enough, because the target can still preempt the sender between `kill` and the read. So P1 also runs the sender under `SCHED_FIFO` on that CPU, which an ordinary target cannot preempt, and checks the target's threads' `/proc/<tid>/schedstat` run times before and after, to confirm that the target did not run in between.
A flavour on which every run, so controlled, still reads end of file straight after `kill` would mean its descriptors are closed inside the call: T1 for that flavour, the flavours diverging, and Decision A coming back, which is why A1 and A2 are kept below.
Results that never show the target holding its descriptors, but where the target's not running cannot be confirmed, are inconclusive. That flavour then takes T3, refusing fatal kills from outside, until a probe settles it.
Self-kill keeps ending at generation. Whether it should follow T2 too, for a multithreaded process whose other threads an outside process could watch, is a follow-up question, not part of this plan.

### Decision A: how a kill says it ended or stopped another process

The caller of a `kill` to another positive pid never ends or stops itself.
So the caller's `ProcessFate` is always `Continues`, and the news, if any, is about the target.

**A0. No news in the answer.** Under T2 (or T3) and E1, no kill to another process ends or stops its target inside the call. A stop modelled later (E3) takes effect at the target's return to user mode too, as `ReturnToUserOutcome.ProcessStopped` already reports for a process's own threads. So `kill`'s type is unchanged, and a kill to another process answers `Ok (ProcessFate.Continues (KillOutcome.ProcessRuns, system))`, where `ProcessRuns` is documented as "the calling process runs on".
- Blast radius: none in the public API. Only the docstrings and the README change.
- What a client gets: the target's end is reported once, by the return that ends it, through the channel every other signal death already uses.
- Against: a client sees nothing in the answer that tells it the target is exiting. It finds out from `owesReturn` of the target's threads, or from the T2 reader.

The options below are for T1, where the target can end inside the call.

**A1. New cases on `KillOutcome`.**

```fsharp
type KillOutcome =
    | ProcessRuns                        // the caller's process runs on
    | ProcessStopped of signal : Signal  // the caller's process stopped
    | OtherProcessRuns of target : ProcessId
    | OtherProcessEnded of ended : EndedProcess
    | OtherProcessStopped of target : ProcessId * signal : Signal  // reserved under E1
```

`kill`'s type is unchanged: `Result<ProcessFate<KillOutcome>, UnixError>`. A kill that ends B answers `Ok (ProcessFate.Continues (KillOutcome.OtherProcessEnded ended, system))`, and `system` no longer holds B.
- Blast radius: smallest. One union gains cases at its end, and every match on `KillOutcome` (about 60 test sites, and every client) gains arms.
- What a client can no longer rely on: `pthreadKill` shares `KillOutcome` and can never produce the new cases. That is an illegal state the types allow. `ProcessFate.ProcessEnded` and `OtherProcessEnded` are two ways to say "the target ended", told apart by whether the target was the caller.
- Reversible before 1.0. After 1.0, splitting `pthreadKill` off would be a major version.

**A2. A kill-specific answer that names its target.**

```fsharp
/// What a signal did to a process other than the caller's.
type OtherProcessSignalled =
    | Runs of target : ProcessId     // nothing sent, or pending, coalesced or discarded
    | Ended of ended : EndedProcess  // it ended; the system no longer holds it
    | Stopped of target : ProcessId * signal : Signal  // reserved under E1

type KillAnswer<'Thread, 'Handler> =
    | Own of fate : ProcessFate<KillOutcome, 'Thread, 'Handler>  // pid named the caller's process
    | Other of signalled : OtherProcessSignalled * system : UnixSystem<'Thread, 'Handler>

UnixSignal.kill : Caller -> pid:int -> signo:int -> UnixSystem -> Result<KillAnswer, UnixError>
```

`KillOutcome` and `pthreadKill` are unchanged. `SteppedCall.Kill` holds a `KillAnswer`.
- Blast radius: every match on `kill`'s answer changes shape (the same 60 sites, and the README's examples), but `pthreadKill`'s do not.
- What a client gets: each answer can mean only one thing. `Other (Ended _)` cannot be about the caller, and `pthreadKill` cannot say anything about another process.
- Process groups: a later `kill(0)` or `kill(-pgid)` reaches several processes, possibly including the caller. That would be a third case, `Group`, whose shape is not knowable until groups are designed and measured. Before 1.0 a new case is free; after 1.0 it is a major version. It could be reserved now, but I recommend not reserving it, because its payload is unknown.
- Reversible before 1.0.

**A3. The ended process recorded on the system, for the client to collect.**

A log on the machine, as `UnixSystem.delivered` (a `DeliveryLog`) is for launched pipes: `UnixSystem.endedProcesses : EndLog`, with `EndLog.since`.
Every end of every process appends to it. A kill that ends B answers `Continues (ProcessRuns, system)`, and B's end is in `system`'s log.
- Blast radius: no answer type changes.
- What a client gets: one channel for every way a process ends, now and later, such as a group kill or an end caused by another process's exit.
- Against:
  - The caller's own end would then be reported twice, by `ProcessFate.ProcessEnded` and by the log.
  - A client that forgets to read the log carries on with threads that no longer exist, and only finds out when a call about them throws.
  - Once `wait` keeps zombies, the log and the zombie table are two records of the same ends.
  - The log grows without bound, and is part of the system's value, so two runs that differ only in which processes ended are unequal.

**A4. Zombies now.** An ended process stays in the table, holding its pid, until something reaps it: the client through `UnixSystem.reap`, or a future `wait`.
This is how the kernels work, and what `wait` needs.
But it reverses the one-kernel plan's decision that "an ended process is removed at once" for every call that ends a process, not just kill.
It changes pid reuse (a zombie holds its pid), every test that counts `processIds` after an end, and the README's whole account of the end of a process.
It belongs with `fork` and `wait`. I list it so that A1 to A3 can be judged against it.

How each composes:
- `ProcessFate`: A1 and A2 leave it meaning "the caller's fate". A3 makes it one of two reports.
- `Entry`/`Shape`: under B2 (below), kill's body makes the answer itself, and any of A1 to A3 works. Under B1, A2's `Other` is shaped as `Shape.withSystem` and `Own` as `Shape.fate`, through `Shape.union`.
- The step oracle: `Syscall.Kill` is unchanged, and `SteppedCall.Kill` holds whatever `kill` answers.
- A future `wait`: under A1 and A2, the `EndedProcess` in the answer is a notification, as `exitGroup`'s already is. When `wait` keeps zombies, an end also leaves one, and the answer's shape does not change.

**Recommendation: A0, which follows from T2a.** If T1 is taken for either flavour, then A2: it is the only option in which every answer means exactly one thing, and "hard to misuse" outranks a smaller diff.

### Decision B: the rule that a call changes only its own process, and where kill's write happens

Today the README says, under "Several processes": "Every call names its caller's process, and is made in that process: it can read and change that process's own state and the machine, and no other process's own state, and the system it answers holds every other process as it was."
That is enforced only by a test: `TestMultiProcessFuzz.othersUnmoved`, which checks after every step of the fuzzer that each process but the stepping one is as it was.
A call's body works on a `ProcessView`, which holds the other processes (`Others`) and could write them. Today no body does: `Others` is read or written only in `UnixSystemState.fs`.

**B1. A helper that moves a body's focus to the target.**
Inside `tryKillIn`, a helper `ProcessView.across target f view` does four things: it puts the caller's view back into a kernel, focuses the target, runs `f` (`ProcessSignal.generate`) on the target's view, and refocuses the caller.
`Entry` is unchanged, and the rule stays a convention that only the fuzzer enforces.
- Blast radius: the smallest; one helper.
- Against: any body can call the helper, so a reader of an `Entry.call` site can no longer tell whether the call may touch another process.

**B2. Kill's body runs over the whole kernel, and every other call is checked to leave other processes alone.**
- A new `Entry.callKernel operation requirement caller body system` admits the caller as `Entry.call` does, then hands `body` the whole `UnixSystem`, with no view. The body focuses the caller to read its credentials and numbering, and the target to generate into it. It puts each back, using `ProcessView.unfocusWithout` for a target that ended (under T1 only).
- Every way a per-process body's answer goes back into the kernel gains a check that the body left the other processes as it was handed them: each view in the answer has `Others` as the very map the body was handed (`obj.ReferenceEquals`). Otherwise it fails loudly, as a library bug. There are three such ways:
  - `Unfocus.Back` in `Entry.call`, for a process that carries on;
  - `Unfocus.Without` in `Entry.call`, for a process that ended (`exitGroup`, a fatal self-kill or `pthreadKill`, a write's `SIGPIPE`, a return to user mode);
  - `Entry.resume`, for a call resumed after a copy-in pause (`writeWithBytes` and the rest).

  A copy-in pause needs two more things, because `Shape.progress` passes a paused value through without unfocusing it. A body could change `Others` before it pauses, and the paused view would then carry the change into the resumption, where comparing against the paused view would accept it. So each paused value keeps the `Others` that `Entry.call` admitted, beside the view it paused in. `Shape.progress` checks the paused view against it at the pause, through an accessor for the paused value's view. `Entry.resume` checks each answer view against the admitted map, not against the paused view's.

  The check is always on. It costs one reference comparison per view, and allocates nothing, so it does not disturb `UnixScheduling.dispatch`, which bypasses `Entry.call` anyway.
- A future cross-process signal that does not come from `kill` goes through `callKernel` too, such as a parent's `SIGCHLD`, or `SIGIO` to an `F_SETOWN` owner. The exception stays visible at the entry point.
- Blast radius: one new entry point and one assertion. `tryKill` moves from `Entry.call` to `Entry.callKernel`, and no other call changes.
- The wake memo: `callKernel` must hand back the very kernel it was given when nothing changed, as `unfocusFrom` does. Otherwise a kill of signal 0, or of a discarded signal, would invalidate the memo for nothing. A kill that does change the target changes `Processes`, which the memo compares by reference, so the next `wake` sweeps, as it must.

**B3. The body returns a description, and `Entry` carries it out.**
Kill's body reads `Others` to check existence and permission, and answers a description such as `SignalAnother (target, entry)`. After putting the caller's view back, `Entry` interprets it by generating `entry` in `target`.
This follows the gospel's "compute a description, then do it".
- Against: the generation can refuse (`SignalReceiverRefusal`, or, under T1, `ProcessEndRefusal` for a target whose end is refused), and under T1 whether the target ended decides the answer. So the interpreter has to be able to turn an `Ok` into an `Error`, and to choose the answer's case. `Shape` maps views to kernels without changing the answer's structure, so it would need an effectful, fallible primitive, which is more machinery than kill alone justifies.

**Recommendation: B2.** It turns the README's rule into one the machine checks for every call but one, and that one says so at its entry point.

**The rule, restated** (README, "Several processes"):

> Every call names its caller's process, and is made in that process: it can read and change that process's own state and the machine, and no other process's own state, except through a signal it sends.
> A `kill` to another process can change that process's signal state, mark its threads as owing a return to user mode, and mark it as exiting, so that it ends at the first of those returns.
> The system it answers holds every process but those two as it was.

(Under T1, the second sentence ends "and end it, removing it from the system" instead.)

**Tests that change:**
- `TestMultiProcessFuzz`: `othersUnmoved` lets a kill step also change its target. The target's slot may differ only in `Process.Signals`, its threads' `Owes`, and (T2) its exiting mark. A new `Op.KillOther` (stage 3 onwards) sends signal 0, `SIGUSR1` with or without a handler installed in the target, a fatal default, `SIGKILL`, and a signal the target blocks. Under T2, the fuzzer's next return of any of the target's threads ends the target, and the fuzzer drops the target's asleep and woken threads, as it does for `exitGroup`.
- `TestProcessView`: a test for each of the three ways back into the kernel (`Back`, `Without`, `Entry.resume`), and one for a body that writes `Others` before it pauses for a copy-in, each failing loudly and each mutation-checked.
- `TestKillTargetsMeasured`: the `cred` rows, which today must be refused, become answers: `answer` and `handled` must match.
- `TestStepOracle` and `Stepped.fs`: kill to another pid joins the generator.
- `TestUnixSystemInvariants`: `checkInvariants` after cross-process kills. Owed returns and pending signals are per process, and are checked already. T2 adds one defect: a thread of an exiting process that neither owes a return nor is parked.
- `TestReadme`, for "Signals", "Several processes" and the examples; `TestSurface`, for any new reader (T2) or for A2's types (T1).

### Decision C: sessions

The session exception decides only one case: `SIGCONT` where the uid rule refuses.

**C1. Refuse that case.** Where the uid rule allows a signal, the session does not matter, and the call is answered. Where it refuses and the signal is `SIGCONT`, the call is refused, because the answer depends on sessions, which the model does not have. Every other signal the rule refuses is `EPERM`.
- Blast radius: one refusal case. Reversible, by turning the refusal into an answer later.
- What a client loses: `SIGCONT` between users. A client is unlikely to need that before job control.

**C2. A session ID as launch configuration.** `ProcessLaunch.withSession : SessionId`, read only by kill's permission check.
- Against: no default is truthful. Processes a shell starts share its session; a daemon has its own. So the setting would either be required, which changes every launch, or refused when absent and needed, which is C1 with a knob.
- Against: sessions without `setsid` and `getsid` is half a feature, and sessions without process groups cannot express a job.

**C3. Sessions and process groups together.** Session and process-group IDs, `setsid`, `setpgid`, `getsid` and `getpgid`, `kill(0)` and `kill(-pgid)`, and the orphaned-group rule for stops (F17). This is a feature of its own, with its own probes and plan. It is what C2 grows into.

**Recommendation: C1 now, and C3 as its own feature later.**

### Decision D: where the signal lands, and how the target's threads come to owe a return

**D1. Generate into the target as a self-kill does.**
`ProcessSignal.effect` already does everything for one process: it applies `SignalState.generate`'s rules, refusals and measured divergences, and marks the receiver as owing a return (`OwedReturns.markIfDue`). Kill runs it on the target's view, with `Target = ValueNone`.
- What follows from that, with no new code:
  - A sleeping thread of the target wakes on the next `UnixWait.wake`, because `WakePrimitive.SignalDeliverable` is asked of the thread's own process, and every process's sleepers are swept.
  - A running thread of the target owes a return. A client already asks `UnixSignal.owesReturn` of every thread before running it (README, "The return to user mode"), and that text is widened from "another thread" to "another thread, of any process".
- The receiver refusals carry over unchanged, now about the target: the leader blocks it (`LeaderBlocks`); the leader is asleep with a signal already pending (#102's `LeaderAlreadySignalled`); `DefaultBehindHandlers`; and Darwin's `PendingForProcessAndLeader`.
- This option is conditional on P1 agreeing with F8 to F10, measured from outside. If P1 shows a difference, kill from outside needs its own receiver rule, and this decision comes back.

**D2. D1, and the answer also lists the target's threads that now owe a return.**
- What a client gets: it learns which threads to return to user mode without asking. But `owesReturn` already says so, and a list in the answer would be a second record of the same fact, which can go stale.
- Not recommended.

**D3. A queue of signals in flight on the machine, applied when the target next enters the kernel.**
This would keep "a call changes only its own process" literally true.
- Against: it is not what either kernel does. Generation is immediate: a discard is decided by the target's masks at generation, and `SIGKILL` ends the target before `kill` returns. The sender's answer would therefore depend on a state that does not exist yet.
- Rejected; listed only because it is the option that keeps the rule unchanged.

**The receiver rule itself.** E1′: keep the leader-first rule, and its refusals, for signals from outside, if P1 confirms it. E2′: model Linux's `curr_target` cursor and Darwin's first-unblocked thread, which would answer what is refused today. E2′ is a change to self-kill too, and belongs in its own plan.

**Recommendation: D1, with E1′.**

### Decision E: stops

**E1. Refuse a stop of another process.** A signal whose effect on the target is to stop it is refused (`KillRefusal.OtherProcessStops`): `SIGSTOP`, or a job-control stop at its default. (Under A2, its `Stopped` case stays reserved.)
- Reversible. Information: none lost that the model could truthfully give.

**E2. Report the stop and hold no state**, as the model already does for a self-stop (`KillOutcome.ProcessStopped`, "a client should refuse a stop rather than carry on").
- Against: a self-stop leaves no thread of the caller running, so nothing more happens until the client acts. A stop of another process leaves the caller running, and the caller's next call may be `kill(target, SIGCONT)`. The model would answer that as a `SIGCONT` to a running process (discarded at its default), which is wrong. So E2 hands the client a state the library then mis-answers.

**E3. Model stopped processes.** A stopped flag on the process: its threads make no calls; `SIGCONT` resumes it at generation, whatever the masks; `SIGKILL` still ends it; other signals stay pending; a sleeping call may restart. Later, `waitpid(WUNTRACED)`.
- That is job control, which needs P1's stop rows and more. It belongs with C3.

**Recommendation: E1.**

### Decision F: Darwin's permission rule

**F1. Answer only the measured shapes.** Answer when sender and target hold the same three uids (P3 measures a direct `kill` to confirm the group rows). Answer `EPERM` from a non-root sender to a target whose three uids are all 0 (pid 1 measured; P3 adds another root process). Refuse the rest.

**F2. Take XNU's `cansignal` from source.** This is against the policy (AGENTS.md: "use source only to learn a rule's shape").

**Recommendation: F1.** The Darwin column of cross-user kills stays refused until a Mac with root can measure it.

### Decision G: Linux senders holding uid 0 partly

**G1. Refuse until P2.** A sender with uid 0 in some but not all of its real, effective and saved uids is refused.

**G2. Take "effective uid 0" as `CAP_KILL`**, as `setresuid`'s rule already does for privilege.

P2 is cheap, so: **G1 in the stage that lands before P2, and replaced by whatever P2 shows.** If P2 is merged first, G1 never ships.

### What stays refused

- **Process groups and every process**: a pid of 0 or below (`KillRefusal.ProcessGroup`).
- **Pid 1** (#105's change). The model's own pid-1 process too, if a client launched one with `withProcessId 1`: an init process ignores signals at their default, which is not modelled (`InitProcess`, now for the target as well as the caller).
- **A Linux thread ID of a non-leader thread**, in any process. The kernel prefers that thread, and the model delivers process-directed signals to the leader first.
- **A stop of another process** (E1).
- **`SIGCONT` that only a session could permit** (C1).
- **Credentials outside the measured shapes**: a Linux sender with uid 0 in some but not all of its uids (G1); and on Darwin, any pair but the measured ones (F1).
- **The target's own receiver refusals** (D1), which carry the target's pid in their message.
- **`ProcessEndRefusal`** for a target whose end closes a descriptor whose close is refused, such as a lingering socket. Under T2a this is refused where the end happens, at the return to user mode of the target's thread, as it already is for a process's own signal death. Under T1 it would be the `kill`'s refusal.
- **Real-time signals past `RLIMIT_SIGPENDING`**, if #107's decision is a refusal. Whatever it decides, its count is per real user of the receiver, across processes, and a kill from outside must go through it.

### Not affected

- `pthreadKill` stays within the caller's process: `pthread_kill(3)` cannot name another process's thread.
- `SIGPIPE` stays the writer's own.
- No `SIGCHLD` is sent when a process ends, because a launched process has no parent on the machine. When `ProcessLaunch` can name one, an end generates `SIGCHLD` there, through B2's `callKernel`.
- The model keeps process-wide credentials (#100 and #103 are deciding whether to). If credentials become per thread, Linux checks the sending thread's against the target leader's (`kill_ok_by_cred` takes the task the pid names). The permission check then reads those two, which is a one-line change here.

## 4. API sketch

Under the recommendations (T2a, A0), no public type changes.
`UnixSignal.kill` keeps its type, `Result<ProcessFate<KillOutcome>, UnixError>`. `KillOutcome.ProcessRuns` is documented as "the calling process runs on", and its docstring and the README say what a kill to another process does to the target.
The one public addition, if a client needs it before it returns a thread, is a reader:

```fsharp
module UnixSystem =
    /// How the process `pid` will end, if a fatal signal from another process has marked it as exiting:
    /// it ends at the next return to user mode of any of its threads.
    val exiting : pid : ProcessId -> UnixSystem<'Thread, 'Handler> -> ProcessTermination option
```

Under T1, the public answer would instead be A2's:

```fsharp
type OtherProcessSignalled =
    | Runs of target : ProcessId
    | Ended of ended : EndedProcess
    | Stopped of target : ProcessId * signal : Signal   // reserved: refused until stops are modelled

type KillAnswer<'Thread, 'Handler when 'Thread : comparison and 'Handler : equality> =
    | Own of fate : ProcessFate<KillOutcome, 'Thread, 'Handler>
    | Other of signalled : OtherProcessSignalled * system : UnixSystem<'Thread, 'Handler>

module UnixSignal =
    val kill : Caller<'Thread> -> pid : int32 -> signo : int32 -> UnixSystem<'Thread, 'Handler>
               -> Result<KillAnswer<'Thread, 'Handler>, UnixError>

// SteppedCall.Kill of Result<KillAnswer<'Thread, 'Handler>, UnixError>
```

Internal, whichever is chosen: `Entry.callKernel`; the assertion on the three ways back into the kernel; under T2, the exiting mark on `UnixProcessState`; `KillPermission.allowedUnder : SimulatedUnixFlavour -> sender : Credentials -> target : Credentials -> signal : Signal option -> Result<bool, KillPermissionRefusal>`, a pure rule beside the other `*Rules.fs` files, with the measured rows as its tests; and `KillRefusal` gains `OtherProcessStops`, `SessionUnknown` and `Permission of KillPermissionRefusal`, while `OtherProcess` goes.

## 5. Stages

Implement this plan with each stage on its own branch, stacked as necessary on previous branches, so that a reviewer can review each branch in isolation.

### Stage 0: the probes

**Dependencies:** none (beside #105).

**Implements:** §2's P1, P2 and P3 (P4 and P5 may follow separately; nothing here waits for them).

**Correctness oracle:**
- each output is committed with its kernel version and uid, and has been re-run once with no row changing;
- `TestKillAcrossMeasured` replays every row against today's model, which must refuse each one (as `TestKillTargetsMeasured` does for #105's rows);
- a row in the skill's `reference/flavour-divergence.md`.

If P1 contradicts F8 to F10 from outside, stop and bring Decision D back before stage 4.
If P1's "time between" rows show either flavour closing the target's descriptors before `kill` returns even where the target is confirmed not to have run in between, stop and bring Decisions T and A back before stage 2. If they are inconclusive for a flavour (no run shows the target still holding its descriptors, and none confirms that it did not run), that flavour refuses fatal kills from outside (T3) in stage 5.
The replay of those rows holds the model only to what every schedule allows: the target still holding its descriptors straight after `kill`, where some run showed that. End of file seen straight after `kill` is a schedule in which the target ran first, which the model reaches by the client returning a target thread before the sender reads.

### Stage 1: other processes, machine-checked

**Dependencies:** none.

**Implements:** B2's assertion on all three ways back into the kernel (`Unfocus.Back`, `Unfocus.Without`, `Entry.resume`) and at a copy-in pause, with the admitted `Others` kept in each paused value; no behaviour change.

**Correctness oracle:**
- the whole suite is green, which shows no body writes `Others` today;
- four new tests, one for each way back and one for a body that rebuilds `Others` before a copy-in pause, each expecting the loud failure. Mutation check: remove each assertion in turn (the pause's included) and watch its test go red;
- `TestMultiProcessFuzz` and `TestProcessView` stay green unchanged.

### Stage 2 (under T1 only): kill's answer names its target

**Dependencies:** none. Under T2a this stage does not exist.

**Implements:** A2's public types. `kill` answers `KillAnswer.Own` for the caller's pid, and refuses or answers `ESRCH` for every other pid exactly as before, so nothing produces `Other` yet.

**Correctness oracle:**
- the suite is green with every match on kill's answer rewritten mechanically;
- `TestSurface`'s baseline is regenerated, with the diff limited to the new types and `kill`'s and `SteppedCall.Kill`'s signatures;
- `TestReadme` passes with the examples updated;
- `TestStepOracle` holds `step` to `kill` for the new answer.

### Stage 3: signal 0 to another process

**Dependencies:** stage 1 (and stage 2 under T1); stage 0's P3 rows for Darwin; P2 for Linux, or G1 in its place.

**Implements:** `Entry.callKernel`; `KillPermission`; checks in each flavour's order (Linux ESRCH, EINVAL, EPERM; Darwin EINVAL, ESRCH, EPERM); the answer `Continues (ProcessRuns, system)` (under T1, `KillAnswer.Other (Runs target, system)`), where `system` is the very kernel given; the refusals for credentials outside the measured shapes. Every nonzero signal to another process is still refused.

**Correctness oracle:**
- every `sig=0` row of #105's `cred` section and of P2 and P3 is replayed as an answer;
- a property: over generated sender and target credentials, pids and signal numbers, the errno equals a naive reference written from the measured rows (the check order as a list of guards), and a refusal occurs exactly where the reference has no row;
- a property: the answered system is reference-equal to the one given, so a `wake` straight after answers from its memo;
- `TestMultiProcessFuzz` gains `KillOther` with signal 0.

Mutation checks: swap EINVAL and EPERM in Linux's order; drop the saved uid from the rule; answer instead of refusing a Darwin cross-user pair.

### Stage 4: signals that leave the target running

**Dependencies:** stage 3; stage 0's P1; #102, if it has merged by then (its refusal then applies to targets too).

**Implements:** D1 and E1′. The target's view is generated into; its receiver owes a return; caught, ignored, blocked and discarded signals; `SIGCONT` where the uid rule allows it, and C1's refusal where it does not; E1's refusal of a stop. README "Signals" and "Several processes" restated as in Decision B.

**Correctness oracle:**
- P1's receiver, interruption, ignored and continue rows are replayed: which thread runs the handler, whether a sleeping call ends with EINTR or restarts, and what `sigpending` reports;
- every `sig=USR1` row of #105's `cred` section is replayed: `handled=1` means the target's leader owes a return and its return pushes the handler's frame;
- the `cont` rows are replayed: both are refused under C1, since the uid rule refuses them;
- a differential property, "a kill from outside equals a kill from inside": for a generated target with at least one running thread T, any dispositions, masks and parks, and a signal that leaves it running, B's slot after `kill(B)` from A equals B's slot after `kill(getpid())` made by T, and A's slot is unchanged. P1 is what makes this property a statement about real kernels rather than about the code;
- `TestMultiProcessFuzz`: `KillOther` with caught, ignored and blocked signals, and the restricted `othersUnmoved`;
- `checkInvariants` holds after every step of both.

### Stage 5: signals that end the target

**Dependencies:** stage 4; Decision T settled by P1's "time between" rows.

**Implements, under T2a:** a fatal default from outside (`SIGTERM`, `SIGKILL`, a core-dumping default under the target's `CoreDumps`), where some thread of the target could take it and P1's commitment rows show death committed at generation for that signal and flavour, marks the target as exiting with its `Signaled` termination. Where they show it is not (Darwin's `SIGTERM`, by the reviewer's observation), the signal is left pending on its receiver as stage 4 leaves any other, and the return path applies whatever disposition holds then; where they settle nothing, the signal is refused on that flavour. For a target marked as exiting, and only for one: every thread of it owes a return to user mode, whatever it blocks, and a sleeping one wakes and is interrupted; the first return the client makes for any of them ends the process there (`ProcessFate.ProcessEnded`), its descriptors closed as `exitGroup` closes them, and refused where that would be. The rest of what an exiting target answers until then (a second signal, `kill(target, 0)`) is as P1 measured. Plus `UnixSystem.exiting`, if Patrick wants the reader.

**Correctness oracle:**
- P1's ending rows are replayed: the status, the core flag, and that a target blocking `SIGTERM` in every thread survives with it pending;
- P1's "time between" rows are replayed: straight after the `kill`, the sender's non-blocking read of its end of a loopback TCP connection to the target answers as P1 measured (`EAGAIN` while the target holds its end), and end of file once the client has returned one of the target's threads;
- a property, for a target marked as exiting: the system after a fatal kill of B, then the return of any thread of B, equals the system after B's own `exitGroup`-shaped end with that `Signaled` termination (`UnixThreadLifecycle.tryEndProcess`). So the close order and the peers' resets are the measured ones the end tests already hold;
- a property, for a target marked as exiting: between the kill and that return, every thread of B owes a return or is parked (the new `checkInvariants` rule); the first `UnixWait.wake` after the kill wakes every parked thread of B, whose finished calls answer `Interrupted`; and no call by a thread of B can be made;
- the cross-process wake tests in `TestCrossProcess` gain a case: a client in A asleep on a socket whose peer B is killed wakes with a reset or end of file once B's end has happened;
- a property, for a fatal default left pending (not committed): only its receiver owes a return for it, the target's other threads go on making calls, a disposition one of them installs before the receiver's return is the one that return applies, and stage 4's differential property (a kill from outside equals one from inside) holds for it;
- `TestMultiProcessFuzz`: fatal `KillOther` and `SIGKILL`; a target marked as exiting ends at the fuzzer's next return of one of its threads, and its asleep and woken sets are pruned;
- P1's commitment rows are replayed: on a flavour and signal whose death is committed, a disposition installed after the kill changes nothing; on one whose death is not, the target survives a `SIG_IGN` installed before its receiver's return.

Mutation checks: end the target inside the `kill` (the "time between" replay goes red); mark a Darwin `SIGTERM` target as exiting (the commitment replay goes red); leave a thread that blocks `SIGTERM` owing nothing (the invariant goes red); end the caller instead of the target.

**Under T1 instead:** the target ends inside the `kill`, which answers `KillAnswer.Other (Ended ended, system)`, and the target's `ProcessEndRefusal` is the kill's refusal. The first property becomes "the system after a fatal kill of B equals B's `exitGroup`-shaped end".

### Later, each its own plan

- Sessions and process groups (C3), with `kill(0)`, `kill(-pgid)` and `kill(-1)`, the orphaned-group rule (P5), and the `SIGCONT` exception.
- Stopped processes (E3), which needs C3 and P1's stop rows.
- Linux thread-ID targets, once the receiver rule can prefer a named thread (E2′).
- Zombies, `wait` and `SIGCHLD` (A4, P4), with `fork`.

## 6. Found on the way, for Patrick

- **The self-stop answer assumes a process group that is not orphaned.** The model stops the process for `SIGTSTP` at its default sent to itself (`KillOutcome.ProcessStopped`). `non-leader-unblock.c` calls `setpgid` precisely so that its row is not in an orphaned process group, where, its comment says, the kernel discards `SIGTSTP` instead (F17). The model has no process groups, and the README does not state the assumption. P5 would measure it. Until then, the README's "Signals" section could say that a stop's answer assumes a process group that is not orphaned.
- **Darwin's half of cross-user kill cannot be measured on this Mac**, which has no root. Under F1 the Darwin column stays refused for any pair whose credentials differ, beyond the root-target row P3 can measure.
- **Darwin's self-kill may end the process too early.** The model applies a fatal default at generation, on both flavours (the 2026-09-22 choice, after Linux). The reviewer's Darwin observation behind F19 suggests that XNU commits a catchable fatal default only as its receiver returns to user mode. If so, a non-leader thread's `kill(getpid(), SIGTERM)`, followed by another thread installing `SIG_IGN` before the leader returns, survives on Darwin where the model ends the process. P1's commitment section measures the outside case; one in-process row beside it would settle the self-kill case too.
