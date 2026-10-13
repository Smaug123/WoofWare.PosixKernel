# The process and thread lifecycle in WoofWare.PosixKernel

*Options document, 2026-09-26. Part of the "PosixKernel knows nothing of the CLR" workstream. Code references are at `origin/main` `d1d34c9d`. Probes and raw output are in [`lifecycle-raw/`](lifecycle-raw/) beside this file (copies of the scratchpad's `lifecycle/`). It builds on the signals redesign ([`options.md`](../pawprint-signals-research/options.md), design B, §7) and answers its open Q5.*

## 1. What there is today

### The library

| piece | where | whose fact? |
| --- | --- | --- |
| No `exit`, `_exit`, `exit_group` or thread exit. No terminated state. | — | missing |
| `UnixSignal.kill` returns `SignalGeneration.ProcessTerminated` **together with the still-live system**, so later calls are answered as if nothing happened | `UnixSignal.fs:60-78`, `SignalState.fs:73-82`, `:457-494` | kernel-shaped verdict, not state |
| `UnixTaskTable.register` adds a task. Nothing removes one. It checks only that the *name* is new, so two tasks can carry the same `OsThreadId` | `UnixTask.fs:174-192` | half a lifecycle |
| `UnixTaskState`'s docstring says the client keeps "the set of tasks equal to its set of live threads", and that `OsThreadId` is "never reused". Neither is enforced, and the first is false in PawPrint (below) | `UnixTask.fs:105-132` | prose drift |
| `OsThreadId of uint32` | `UnixTask.fs:27-28` | **shim**: the width of `SystemNative_TryGetUInt32OSThreadId`. Linux's tid is a positive `pid_t`, Darwin's `pthread_threadid_np` is a `uint64_t` |
| The signal receiver comes from a `liveThreads` array **the caller passes on every call** | `UnixSignal.fs:32-37`, `SignalState.fs:426-448` | a second source of truth beside `Tasks` |
| `UnixSystem.initial` builds a process with **no tasks** (`Tasks = Map.empty`) | `UnixSystem.fs:790`, `:845` | a state no kernel has |
| `ProcessId` fixed for the run (default 4242); no ppid, pgid or sid; no `fork`, `exec` or `wait` | `UnixProcess.fs:146`, `UnixSystem.fs:754-760` | single process, stated honestly |
| `Environment` is the exec-time `envp` (#1513) | `UnixProcess.fs:51` | kernel |
| `ProcessPath : AbsoluteUnixPath option` | `UnixProcess.fs:96`, `UnixSystem.fs:684` | **shim**: `minipal_getexepath`'s *answer*, a `realpath` over two kernel facts (§2 row 9). Not resolved against the filesystem |
| `ProcessorCount` | `UnixMachine.fs:101` | CoreCLR's detection result (see §6) |

### PawPrint's use of it

| site | what it does |
| --- | --- |
| `IlMachineThreadState.addThread` (`:376`), `allocateUnstartedThread` (`:403`), `allocateParkedThread` (`:454`) | every `ThreadId` PawPrint allocates is registered as a task: the entry thread, every guest `Thread` **at construction** (before `Start`, so before any OS thread would exist), and the signal dispatcher |
| `EmulatedKernel.osThreadId` (`EmulatedKernel.fs:1504`) | mints `pid + ThreadId`. This is where "the leader's tid is the pid" lives; `Program.fs:1320-1324` asserts the entry thread is `ThreadId 0` so that it holds |
| `EmulatedKernel.cpuForRotation` (`:1448`) | the task's CPU, from `effectiveProcessorCount` (`:1355`), which reads CoreCLR's `PROCESSOR_COUNT` knob |
| `Scheduler.onThreadTerminated` (`Scheduler.fs:667`) | marks a thread `Terminated`; **tells the kernel nothing**. `EmulatedKernel.fs:1654-1659` says "Nothing removes a thread today", and `checkTaskInvariants` compares the task set with *every* thread PawPrint ever allocated |
| `ThreadStatus.canReceiveSignal` (`ThreadState.fs:344`), used by `NativeLibc.kill` (`NativeLibc.fs:98-106`) and `SignalDispatch.liveExcludingDispatcher` (`SignalDispatch.fs:58`) | PawPrint's answer to "which tasks are alive": excludes `NotStarted`, `Terminated`, and the dispatcher |
| `IlMachineState.LatchedExitCode : int` (`IlMachineStateModel.fs:195-208`) | CoreCLR's latch, written by `Main`'s return, `Environment.ExitCode` and `Environment._Exit` (`NativeEnvironment.fs:98`, `:118`) |
| `RunOutcome` (`IlMachineStateModel.fs:767`) → App (`App/Program.fs:226-318`) | `NormalExit`/`ProcessExit` return `LatchedExitCode` whole; `SignalTerminated` returns `128 + signo` under the simulated numbering; `Aborted` and an unhandled exception return 134 from a host OS read. The kernel never learns the process died |
| `SystemNative_TryGetUInt32OSThreadId` / `GetUInt64OSThreadId` (`NativeSystemNative.fs:2065-2124`) | zero-extend the 32-bit id. The comment still says the id is "stored in `ThreadState.OsThreadId`" and "not a function of `ThreadId`"; both are stale |
| `GuestConfig.Argv` / `AssemblyPath` (`HostConfig.fs:27-56`) | `Main`'s arguments and CoreCLR's argv[0], i.e. hostfxr's view. The kernel's argv would be the muxer's (`dotnet app.dll …`); no guest reads it |

## 2. Measured facts

Linux 6.18.5 aarch64 (Apple `container` VM, `gcc:14`, root). Darwin 27.0.0 arm64 (macOS 27.0, uid 501). **Neither is x86-64.** Every probe has an `alarm()` and bounded loops.

| # | fact | Linux | Darwin | raw |
| --- | --- | --- | --- | --- |
| 1 | leader's id vs the pid | **equal** (pid 8, tid 8) | **unrelated** (pid 58948, id 2897490) | [tids](lifecycle-raw/out/tids.linux.txt) / [tids](lifecycle-raw/out/tids.darwin.txt) |
| 2 | how ids are minted | pid+1, pid+2… in creation order. **pids and tids share one counter**: a `fork` between two threads consumed the id between them | one **system-wide** 64-bit counter shared with every process: consecutive when quiet; a forked child's thread consumed one, and 2–7 ids went to other processes between the leader and its first thread | same |
| 3 | width | `pid_t`, ≤ `pid_max` (4194304 in the VM) | `uint64_t`; high word 0 at this uptime | same |
| 4 | reuse after exit | none in 20000 create/join rounds; at `pid_max`=1000 it **wraps to 300** (`RESERVED_PIDS`) and reuses, skipping live ids (3 wraps in 3000 rounds) | none, never backwards, in 20000 rounds | [pid_max 1000](lifecycle-raw/out/tids-pidmax1000.linux.txt) |
| 5 | main thread `pthread_exit`s while a worker lives | process lives. Leader is a **zombie task**: `/proc/self/task/<pid>` is `Z`, `/proc/self/status` says `Z`, `Threads: 2` | process lives. Leader **vanishes**: thread count 1 | [mainexit](lifecycle-raw/out/mainexit.linux.txt) / [mainexit](lifecycle-raw/out/mainexit.darwin.txt) |
| 6 | …then, from the worker | `getpid` unchanged; `kill(pid,0)` = 0; a process-directed signal goes to the worker | same | same |
| 7 | the last thread ends | `pthread_exit`/return → status 0 (libc calls `exit(0)`). Raw `SYS_exit`: **the last thread's code decides** (leader 3 then worker 5 → 5; worker 0 → 0) | `pthread_exit`/return → 0. Raw thread exit not measured | same |
| 8 | `exit`, `_exit`, `exit_group` from a worker, main blocked in `read` | process ends at once with that status; `atexit` runs only for `exit`, on the calling thread | same (no `exit_group`; `_exit` is process exit) | same |
| 8a | other threads during `exit()` | **keep running** while `atexit` handlers run (a ticker advanced 196 of 300 ms). Only the final syscall is atomic | same (190) | same |
| 8b | a blocked syscall on another thread at process death | a 1 MiB pipe `write` keeps its **partial** effect (336–360 KiB delivered) | same (348–356 KiB) | [exitinflight](lifecycle-raw/out/exitinflight.linux.txt) / [exitinflight](lifecycle-raw/out/exitinflight.darwin.txt) |
| 9 | wait status, `exit(n)` / `_exit(n)` | raw `(n & 0xff) << 8`; `waitid` `si_status` = `n & 0xff` | raw `(n & 0xff) << 8`; **`waitid` `si_status` = `n & 0xffffff`**: `exit(256)` → 256, `exit(-1)` → 16777215 | [waitstatus](lifecycle-raw/out/waitstatus.linux.txt) / [waitstatus](lifecycle-raw/out/waitstatus.darwin.txt) |
| 10 | wait status, death by signal | raw `signo` (\| `0x80` if a core was written); `CLD_KILLED`/`CLD_DUMPED`; core only under `RLIMIT_CORE` > 0 | same encoding; no core was written in this environment even with `RLIMIT_CORE` unlimited | same |
| 10a | default-ignore and stop | ignored: 17 18 23 28. `SIGSTOP` → raw `0x137f` | ignored: 16 19 20 23 28 29. `SIGSTOP` → `0x117f` | same |
| 10b | `SIGTSTP`/`SIGTTIN`/`SIGTTOU` | **discarded**: both harnesses' process groups were orphaned, so the job-control rule applied. Their stop is unmeasured | same | same |
| 11 | own executable path | `readlink(/proc/self/exe)` follows the **inode**: renamed → new path; unlinked → `"<path> (deleted)"`, and `realpath` → ENOENT; `open` still works (`st_nlink` 0). `AT_EXECFN` is the exec **string** (`./exe-copy`), never updated | `proc_pidpath` follows the inode: renamed → new path; unlinked → ENOENT. `_NSGetExecutablePath` is the exec string, never updated | [exepath](lifecycle-raw/out/exepath.linux.txt) / [exepath](lifecycle-raw/out/exepath.darwin.txt) |
| 11a | `minipal_getexepath` after unlink **plus a new, unrelated file at the original name** | answers the new file's path (`realpath(/proc/self/exe)` fails, the `AT_EXECFN` fallback succeeds) | answers the new file's path (`realpath(_NSGetExecutablePath)`) | same |
| 12 | family | an orphan's `getppid` becomes 1 (no subreaper in either harness) | same | [ids](lifecycle-raw/out/ids.linux.txt) / [ids](lifecycle-raw/out/ids.darwin.txt) |
| 13 | `waitpid`/`waitid` with no children | ECHILD (10), with and without `WNOHANG` | same | [nochild](lifecycle-raw/out/nochild.linux.txt) / [nochild](lifecycle-raw/out/nochild.darwin.txt) |
| — | what a syscall on one thread can observe *during* another's `exit_group` | **unmeasured** beyond row 8b | | |

Three consequences:

- **The status a kernel keeps is per flavour.** `waitpid` hides the difference (8 bits on both). `waitid` shows it (8 against 24 bits). CoreCLR hands `exit()` the whole `LatchedExitCode` (`PROCEndProcess` only logs that "exit() only supports the lower 8-bits"), so a Darwin parent using `waitid` sees `Main`'s `return 256` as 256.
- **`minipal_getexepath` is a function of two kernel facts.** One is the executable's inode, which the kernel tracks through renames. The other is the exec-time string, which it does not. `ProcessPath` stores the composition, not either fact. Row 11a shows the composition naming a file that is not the running image.
- **CoreCLR never makes the main thread exit alone.** `RunMain` waits for foreground threads (PawPrint's `WaitingForForegroundThreads`), then the host calls `exit(code)`, which is `exit_group` while background threads live. So signals design B's refusal ("the main thread exits while others live") is never reached by a .NET guest, only by a raw `pthread_exit` P/Invoke.

## 3. Shared across all designs: the answer to Q5

**The task tells the library, by making the thread-exit syscall.** A kernel learns that a thread ended because the thread calls `exit(2)` (glibc's `start_thread` ends in `SYS_exit`). The library gets exactly that call, not a liveness list and not a callback:

```fsharp
/// SYS_exit: the calling task ends. Not the process, unless it is the last task.
val UnixTask.exitThread : task:'Task -> status:int32 -> UnixSystem<'T,'H> -> Result<TaskOutcome<'T,'H>, ThreadExitRefusal<'T>>
/// exit_group: every task ends at once, parks included.
val UnixTask.exitGroup  : task:'Task -> status:int32 -> UnixSystem<'T,'H> -> EndedProcess<'T,'H>
/// clone(CLONE_THREAD) by `parent`: the library mints the tid.
val UnixTask.spawn      : parent:'Task -> child:'Task -> cpu:CpuId -> UnixSystem<'T,'H> -> OsThreadId * UnixSystem<'T,'H>

type TaskOutcome<'T,'H> = Continues of UnixSystem<'T,'H> | ProcessEnded of EndedProcess<'T,'H>
type ProcessTermination = Exited of ExitStatus | Signaled of Signal * coreDumped : bool
```

- **`ExitStatus`** is what the flavour keeps of the argument: `n & 0xff` on Linux, `n & 0xffffff` on Darwin (row 9). `waitpidStatus` and `waitidStatus` are views of it, pinned by row 9's literals.
- **What exit removes.** `exitThread` removes the task and every per-task entry: its `Blocked` mask, its thread-directed pending signals (Linux discards them at thread exit; from source, unmeasured), and its park. It refuses a task that is still parked, because a blocked task makes no syscall.
- **How the receiver rules fall out.** Receivers are a subset of `Tasks`, by construction. The `liveThreads` parameter disappears from `kill`, `generate` and `nextDelivery`, and `canReceiveSignal` is deleted from PawPrint. Under signals B the receiver is the leader, and the leader is live for as long as the process is, because leader-first exit is refused.
- **What PawPrint calls.**
  - `exitThread` from `Scheduler.onThreadTerminated`, for every thread except the entry thread.
  - `spawn` from `startUnstartedThread` and `allocateParkedThread`.
  - `exitGroup` wherever a `RunOutcome` ends the run.

## 4. Designs

### A. One process that can die

- **State.**
  - `UnixSystem` gains `Leader : 'Task`, which must be in `Tasks`. `initial` takes the leader, so a live process always has at least one task.
  - `UnixMachineState` gains a flavour-shaped id allocator:
    - Linux: `{ Next : int32; PidMax : int32 }`. The leader's tid is the pid, then pid+1 onward, wrapping to 300 and skipping live ids (rows 1, 2, 4).
    - Darwin: `{ NextUniqueId : uint64 }`, a configured start (rows 1–4).
  - `OsThreadId` becomes a private struct over `uint64` that only the allocator mints. Its views are `toPidT` (Linux; asserts) and `toUInt64`. The 32-bit projection and the `0 → (uint32)-1` sentinel move to a PawPrint PAL adapter.
  - `withProcessId` is fused with the leader's tid on Linux. It refuses once a second task exists.
- **Termination is a type, not a flag.**
  - `exitGroup`, the last task's `exitThread` (Linux, row 7) and a fatal `kill`/`generate` all return `ProcessEnded of EndedProcess`, which holds `{ Termination; Machine; FinalProcess }`. It is not a `UnixSystem` and has no `Tasks`, so no syscall function can be applied to it.
  - `SignalGeneration.ProcessTerminated` is deleted; `ProcessStopped` stays and PawPrint still refuses it.
  - Two alternatives were weighed:
    - a `Running | Terminated` field with a guard at every public entry. This is discipline: about 140 public functions, and a new syscall can forget its guard.
    - naming the calling task at every entry, so that a dead process, having no tasks, refuses by lookup. That is enforced by structure, but costs a signature change on every function.
  - The type split gets the compile-time guarantee for one new return type, and it is the shape that becomes design B's zombie entry.
- **Refused, with typed refusals.**
  - `exitThread` of the leader while other tasks live (signals B; rows 5–6 say what a kernel would do);
  - the last task's `exitThread` on Darwin (unmeasured);
  - `exitThread` of a parked task;
  - `fork`, `vfork`, a non-thread `clone`, `execve`, the `wait` family, and `getppid`/`getpgrp`/`getsid`;
  - a stopped process (as today).
- **Tests.**
  - A state-machine property test of `spawn`/`exitThread`/`exitGroup`/`kill` against a naive reference model (a list of live tids and a counter). Invariants:
    - tids are unique among live tasks;
    - the Linux leader's tid is the pid;
    - no tid is reused before a wrap, and after a wrap allocation restarts at 300 and skips live ids;
    - no per-task entry outlives its task;
    - a process has ended exactly when an `EndedProcess` was returned.
  - Row 9 and 10 literals for both flavours.
  - A host-tier test: `Process.Start("/bin/sh", "-c 'exit n'")` and `kill -s SIG $$` over the row 9 and 10 sweeps, comparing .NET's `ExitCode` with the rendering of `ProcessTermination`.
  - In PawPrint, the oracle the extraction plan could not write: "tasks = threads with an OS thread", mutation-tested by deleting the `exitThread` call.
- **Blast radius.**
  - Library: `UnixTask.fs`, `UnixSignal.fs`, `SignalState.fs` (the `liveThreads` removal), `UnixSystem.initial` (97 call sites, 77 of them in library tests), and the `register` call sites.
  - PawPrint: the three thread-allocation sites, `onThreadTerminated`, `EmulatedKernel.osThreadId` (deleted), `NativeLibc.kill`, `SignalDispatch`, the five terminating `ExecutionResult` producers, and the App.
- **Upgrade.** Additive to B. `EndedProcess` becomes the zombie entry's payload, and the allocator is already machine state.

### B. A process table, single-process in practice

- **State.**
  - `UnixSystem = { Machine; Self : ProcessId; Processes : Map<ProcessId, ProcessEntry> }`, where `ProcessEntry = Live of { Process; Tasks; Leader; Parent } | Zombie of { Termination; Parent }`.
  - The parent is a configured pid outside the table: the host is the parent.
  - The Linux allocator hands out pids and tids from its one counter (row 2).
- **Answered, beyond A.**
  - `getppid` from configuration;
  - `waitpid`/`waitid` → ECHILD (row 13);
  - the client, as parent, reaps the zombie.
- **Refused.** `fork`, `exec`, a signal to another pid (the table is not the whole machine, so ESRCH would be a guess), and process groups beyond reading them.
- **Tests.** A's, plus table invariants: one live entry; a zombie has no tasks; reaping happens exactly once.
- **Blast radius.** A's, plus projecting "the calling process" everywhere. That is about 80 `.Process.` reads and 25 record updates in the library, 96 updates in its tests, and every `EmulatedKernel` adapter.
- **What a guest gains.** `getppid` and ECHILD, neither of which CoreLib calls without children.
- **Upgrade.** Additive to C: `fork` adds a `Live` entry.

### C. Full `fork`/`exec`/`wait`/process groups

- **State.** B's, plus pgid and sid per process, reparenting to init (row 12), and `SIGCHLD` to the parent.
- **`fork`.** It copies the fd table and shares the descriptions (`FileDescriptorRegistry` already splits the two). It copies the dispositions and the caller's mask, clears pending signals, and keeps only the calling thread.
- **`exec`.** It installs a new image record (`{ Argv; Envp; ExecFileName; Executable : inode }`, row 11), closes `CLOEXEC` descriptors, and resets caught signals to their defaults. It also destroys the other threads; from source reading, a non-leader exec'er takes the leader's tid on Linux (unmeasured).
- **Refused.** Only what is unmeasured: the job-control stop rules (row 10b), terminals, and ptrace.
- **Tests.** A host-differential fuzzer over trees of `fork`/`exit`/`wait` (C harness, deterministic because each step waits), with the invariants above plus "every live process's parent is live, or is init".
- **Blast radius.** It needs a second interpreted process sharing one kernel and one scheduler. .NET's `Process.Start` is `SystemNative_ForkAndExecProcess` (vfork, then exec), so the child is a *new program* that PawPrint must be able to run. That is a PawPrint-wide redesign, not a kernel change.

## 5. Recommendation: A, with termination as a type, and the calling task naming itself at `exit` and `spawn`

A models everything a .NET guest can reach: threads that start and end, a process that ends, and ids with each flavour's shape. It also answers Q5 in the kernel's own terms, as a syscall the ending task makes. B's only guest-visible additions are `getppid` and ECHILD, which no CoreLib path reaches, and B costs a projection refactor across the library. C needs PawPrint to run two processes.

**Keeping guests bit-identical.** Each stage states what it changes. Only stages 3 and 4 below change a guest-visible value, and each does so in its own PR.

- **Thread ids.**
  - Stage 3 on Linux: the library mints the same numbers as `pid + ThreadId` as long as registration order is unchanged. A property test runs both over random allocation sequences without wraps.
  - Stage 3 on Darwin: the numbers change unless the counter's default start is the pid (question 2).
  - Stage 4: registering at `Start` rather than at construction renumbers only threads started out of construction order. No differential oracle pins a tid value, because real .NET's own runtime threads consume ids.
- **CPU placement** does not move. PawPrint keeps choosing the rotation slot at construction and passes the `CpuId` to `spawn`, so `sched_getcpu`, and with it every sharded pool, is unchanged.
- **Exit codes.** `LatchedExitCode` stays PawPrint's: it is CoreCLR's latch, and CoreCLR passes it to `exit()`. The App keeps returning exactly what it returns today, and its host kernel does the same truncation a real one would. Each terminating `RunOutcome` gains the kernel's `ProcessTermination`:

  | outcome | `ProcessTermination` |
  | --- | --- |
  | `NormalExit`, `ProcessExit` | `exitGroup LatchedExitCode` |
  | `SignalTerminated` | from `kill` |
  | `Aborted`, unhandled exception | `Signaled(SIGABRT)`: CoreCLR's `PROCAbort` ends in `abort()` |

  The App asserts that its code, rendered the way a shell renders a status, equals the termination's rendering.
- **Signal receivers.** Receivers are unchanged while `ThreadId 0` is the leader and always live. The lowest-ordered live task and `canReceiveSignal`'s answer then coincide.

### Stages, one PR each

1. **Tasks that leave.** `UnixTask.exitThread` (refusals: leader first, parked, Darwin's last task), removing per-task entries. `Scheduler.onThreadTerminated` calls it. `checkTaskInvariants` compares against threads that are not `Terminated`; `NotStarted` threads stay registered until stage 4, and this is documented. New tests: the task-set oracle, mutation-tested, and a property test that no per-task entry outlives its task. No guest-visible change.
2. **Termination as state.** `ProcessTermination`, `ExitStatus` per flavour, `EndedProcess`, `exitGroup`, and fatal `kill`/`generate` returning `ProcessEnded`. PawPrint's five terminators go through the kernel; each `RunOutcome` carries the termination; the App gets its consistency assertion. Tests: row 9 and 10 literals, the host-tier `sh` sweep, and a property test that the `waitpid` view is `retained & 0xff` on both flavours. Coordinate `coreDumped` with signals stage 3, which makes `RLIMIT_CORE` configuration. No guest-visible change.
3. **The library mints ids.** Add the allocator and `OsThreadId` over `uint64` (with the PAL projection in PawPrint), `initial` taking the leader, and `spawn` replacing `register`. Delete `EmulatedKernel.osThreadId` and its stale comments in `NativeSystemNative.fs`. Tests: the reference-model property test, rows 1–4 as literals (Linux wrap at a small `pid_max`), and old ≡ new numbering on Linux. Darwin's numbering changes here or not, per question 2. Merge with signals stage 4, which also adds `Leader`.
4. **A task is born at `Start`.** `allocateUnstartedThread` stops registering; `startUnstartedThread` calls `spawn`. Delete `canReceiveSignal` and the `liveThreads` parameters. Tests: the task-set oracle tightens to "threads with an OS thread", plus a guest that constructs two threads and starts them in reverse order (`sourcesImpure`, raw `gettid` on Linux). This deliberately renumbers tids.
5. **The executable image** (only when `exec` lands or question 3 says so). Split `ProcessPath` into the exe inode and the exec-time string, and move `minipal_getexepath`'s `realpath` composition to PawPrint, where row 11a then falls out.

New library docstrings are flat `///`, for Patrick to rewrite (`WoofWare.PosixKernel/AGENTS.md`).

## 6. Noted for a separate document: `ProcessorCount`

It touches the lifecycle once. `cpuForRotation` places each new task by `effectiveProcessorCount`, which honours CoreCLR's `PROCESSOR_COUNT` knob (`EmulatedKernel.fs:1341-1364`). So a CoreCLR configuration variable decides which CPU the *kernel* runs a thread on, whereas a real kernel places by affinity within the online CPUs. `spawn` should check that the `CpuId` names an online CPU; the placement policy stays the client's. The rest (configured CPUs, online CPUs, affinity, cgroup quota) belongs to its own document.

## 7. Questions that need Patrick

1. **Scope.** Is a guest's `Process.Start` (fork/exec) in scope for the foreseeable future? That alone separates A from B and C.
2. **Darwin thread ids.** Stage 3 can default Darwin's counter to the pid, which keeps today's numbers and is a legal state but not a typical one (row 1). Or it can start somewhere unrelated to the pid, which is truer but renumbers every Darwin-flavour guest's `pthread_threadid_np`. Is a one-off renumbering of a value no oracle pins acceptable?
3. **The executable image.** Should PawPrint seed the launched image into the emulated filesystem, so that the executable's path derives from an inode (rows 11 and 11a)? Or does `ProcessPath` stay configured data, and so stay a CoreCLR-shaped fact?

## 8. Decisions that are the orchestrator's

- Refusing a dead process by type (`EndedProcess`) rather than by a status guard or a calling task on every function (§4 A).
- Whether `RunOutcome` carries `ProcessTermination`, or `EmulatedKernel` holds it as an option.
- The Linux `pid_max` default: 4194304, as measured in the VM, as a `KernelConfig` knob. Because reuse happens only after a wrap, the stale-`Lock`-owner hazard in `UnixTask.fs:127-132` needs about 4M thread creations by default. A client that wants to exercise it lowers `pid_max`.
- Stage order: 1 and 2 are independent; 3 waits for signals stage 4 or merges with it.
- Whether the App's 134 should use the simulated platform's `SIGABRT` rather than a host OS read. It is 6 on both flavours, so this is only consistency.

## Decision (orchestrator, 2026-09-26)
- **Design A,** built so that B is purely additive, with the five-stage plan. Stage 1 (tasks that leave) starts once the wake-condition algebra (#1580) merges, because both change `UnixTask.fs`.
- **Q2, Darwin thread ids:** a configurable counter start, defaulting to the pid. That keeps today's numbers and is legal.
- **Q3, the executable image:** not now. `ProcessPath` stays configured data until `exec` is modelled.
- **Q1, whether a guest's `Process.Start` is in scope:** Patrick (2026-09-26): not for now. A stands, and B stays additive.

## Decision, stage 1 (orchestrator, 2026-09-26)

Stage 1 cannot refuse "the leader exits first", because the library has no leader until stage 3 adds `UnixSystem.Leader`. Options were (a) the client names the leader to `exitThread` until stage 3, (b) add leader state now (`initial` taking it, or a first-registration `Leader : 'Task voption`), (c) move the refusal to stage 3.

**Chosen: (c).** Through the library's API today a leader leaving first cannot be told from a worker leaving (rows 5–6: `getpid` unchanged, a process-directed signal reaches a survivor; Linux's zombie leader is visible only through `/proc` and the thread count, which are not modelled), and the refusal exists to protect signals B's leader-receives rule, which arrives with `Leader`. (a) adds a parameter only to delete it and cannot check its argument; (b) pulls stage 3 forward into code #1598 and signals stage 4 are changing. **Stage 3 must add the leader-first refusal**; stage 1's `exitThread` docstring says so.

Also settled for stage 1: the last task's exit is refused on both flavours (Linux until stage 2 makes the process's end state; Darwin as unmeasured), as distinct typed cases; `exitThread` takes no status until stage 2; a thread's own pending signals are discarded at exit, measured on both flavours by `thread-exit-pending.c`.

## Decision, stages 3 and signals 4 (orchestrator, 2026-09-27)

The plan pairs lifecycle stage 3 with signals stage 4 because both add `Leader`. They land as two PRs in sequence rather than one: lifecycle stage 3 first (`Leader`, the id allocator with Darwin's counter defaulting to the pid, `initial` taking the leader, `spawn` replacing `register`, and the leader-exits-first refusal deferred from stage 1), then signals stage 4 on top (the per-flavour pick order and the leader-first receiver). Signals Q5 ("who tells the library a task has exited") is answered by stage 1's `exitThread`.
