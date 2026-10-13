# CPU placement in WoofWare.PosixKernel: options

Issue #1726, under "Scheduling: the client decides, and the kernel records". Patrick decided on 2026-10-09 that this is release work: the kernel records "task T is now running on CPU c", answers `sched_getcpu` from that record, and `checkInvariants` checks `c < ProcessorCount` (audit #10). CPU-time accounting and moving the scheduling policy out of PawPrint are post-release.

Read against `origin/main` 8b20be5e, with #1809 (`UnixTaskState.cpu` replaces `UnixTaskTable.cpuOf`) and #1791 (the multi-program driver) open.

## Summary

- **Recommendation: option A.** The client reports each dispatch with `UnixScheduling.dispatch task cpu`.
- **What the kernel keeps:** the same two things Linux keeps. Each task has a CPU (Linux's `task_cpu`: the CPU it last ran on, or the one its creator named). Each CPU has at most one occupant (Linux's `rq->curr`).
- **`getcpu`** answers only for a task that occupies a CPU.
- **Placement is not kept:** "which CPU a thread belongs on" is the client's policy, and the kernel stops calling it "pinned".
- **A PawPrint change comes first.** PawPrint places threads by `DOTNET_PROCESSOR_COUNT`, so it can name a CPU the machine does not have. No real kernel does that, and CoreLib does not need it.
- **One question for Patrick** is at the end of section 4. It has a default.

## Where things stand

- **The kernel.** `UnixTaskState.Cpu : CpuId` is set when a task is created: `UnixTaskLifecycle.spawn parent child cpu`, and `ProcessLaunch.create … leaderCpu` for a leader. Nothing changes it afterwards, and nothing checks its range. Its docstring says "pinned to" and "currently executing on" coincide under a client that never migrates a task.
- **How PawPrint places threads.** `EmulatedKernel.cpuForRotation` is round-robin over `effectiveProcessorCount`, which honours `DOTNET_PROCESSOR_COUNT`. The cursor is `IlMachineState.NextCpuRotation`, and constructing a `Thread` takes a slot. The signal dispatcher is put on CPU 0.
- **How PawPrint answers `SystemNative_SchedGetCpu`.** On Linux it answers the task's `Cpu`. On Darwin it answers -1 (#1682).
- **#1791** gives each program its own cursor, so every program's leader is on CPU 0. There is one global interleaving and one clock.
- **Audit #10's gap is asserted by a test.** `TestCpuPlacement."the environment knob moves placement, not just the reported count"` requires `DOTNET_PROCESSOR_COUNT=8` on a one-CPU machine to place threads on CPUs 0–7.

## 1. What a real kernel exposes

| Fact | Linux | Darwin | Does a .NET guest under PawPrint reach it? |
| --- | --- | --- | --- |
| The CPU of the running thread | `getcpu(2)`. glibc's `sched_getcpu` reads rseq's `cpu_id` instead, with no syscall | No `sched_getcpu` and no `getcpu`. `pthread_cpu_number_np` reads a value the kernel sets | **Yes, on Linux.** `SystemNative_SchedGetCpu` → `Thread.GetCurrentProcessorId` → `SharedArrayPool`, `TimerQueue.Instances`, `PoolingAsyncValueTaskMethodBuilder`. On Darwin the shim is built without `HAVE_SCHED_GETCPU`, so it answers -1 without asking, and CoreLib falls back to the managed thread ID (`ProcessorIdCache.cs`) |
| rseq `cpu_id` | Written by the kernel on return to user mode | — | Only as glibc's route to the same value |
| `/proc/<pid>/task/<tid>/stat` field 39 | `task_cpu`, which a sleeping task has too | — | No. .NET's `ParsedStat` leaves `processor` commented out, and the library has no procfs |
| Affinity | `sched_{get,set}affinity`, `pthread_setaffinity_np` | None on Apple silicon: `THREAD_AFFINITY_POLICY` answers `KERN_NOT_SUPPORTED` | Only through `Process.ProcessorAffinity` (System.Diagnostics.Process.dll, `SystemNative_Sched{Get,Set}Affinity`). PawPrint implements neither, and Darwin throws `PlatformNotSupportedException` (Process.BSD.cs) |
| Processor count | Affinity count, cgroup quota, the `PROCESSOR_COUNT` knob | `hw.ncpu` and similar | `Environment.ProcessorCount` is an FCall, which PawPrint answers from configuration (`effectiveProcessorCount`); no kernel call |
| NUMA node | `getcpu`'s second result | — | No: the shim asks for no node |
| GC heap balancing | `sched_getcpu` in `gcenv.unix.cpp` | — | No: that is native code |
| CPU time | `getrusage`, CPU-time clocks | `getrusage` | `SystemNative_GetCpuUtilization`; post-release |

Found by searching `$DOTNET_RUNTIME_SRC` (v10.0.12) and the managed linux-x64 10.0.12 framework for the entry points. Only `System.Private.CoreLib.dll` names `SystemNative_SchedGetCpu`, and only `System.Diagnostics.Process.dll` names the two affinity entry points.

### Measured

The probe is `cpu-placement.c`. It and its outputs are uncommitted, in the scratch worktree `.claude/worktrees/cpu-placement-probe` (detached at `origin/main`), under `docs/plans/2026-08-23-posix-kernel-extraction/`:
- `cpu-placement.darwin-27.0-uid501.txt` (this Mac: 18 CPUs, 6 performance and 12 efficiency);
- `cpu-placement.linux-6.18.5-aarch64-cpus4.txt` (5 CPUs);
- `cpu-placement.linux-6.18.5-aarch64-cpus1.txt` (2 CPUs).

`container run --cpus n` gives the VM n+1 CPUs (1→2, 2→3, 4→5), and the default is 5.

1. **On Linux the routes are one fact while a thread runs.** glibc 2.41 registers rseq (`__rseq_size` 28). Read back to back, `sched_getcpu`, the raw `getcpu` syscall and rseq's `cpu_id` agreed on 20,000 of 20,000 reads, and field 39 agreed on 1,000 of 1,000, at both CPU counts. `getcpu`'s node was always 0.
2. **A thread's CPU changes across a block, on both kernels.**

   | Across 2000 rounds | Darwin, idle | Darwin, loaded | Linux, 2 and 5 CPUs |
   | --- | --- | --- | --- |
   | pipe wakes on another CPU | 145–542 | 306 | 0–4 |
   | 100 µs sleeps waking on another CPU | 204–775 | 1127 | 0–1 |
   | 100 µs spin samples on another CPU | 45–169 | 46 | 0–1 |

   "Loaded" adds one busy thread per CPU. The Darwin idle ranges cover two runs.
3. **Linux keeps a blocked task's last CPU.** While a thread was blocked in `read(2)`, field 39 was the CPU it blocked on. That held even after `pthread_setaffinity_np` excluded that CPU. The thread ran on the newly allowed CPU only after it woke. This was the same at 2 and 5 CPUs.
4. **Setting affinity moves a running caller before the call returns.** After `sched_setaffinity` to the single CPU k, `sched_getcpu` and field 39 were k for every k.
5. **Linux affinity errors.**
   - An empty mask is EINVAL. So is a mask holding only CPU 1023.
   - The mask {0, 1023} is accepted, and reads back as {0}.
   - A raw `sched_getaffinity` into 1 byte is EINVAL. Into 8 bytes it answers 8.
   - An unknown pid is ESRCH.
6. **Darwin.** `dlsym` finds neither `sched_getcpu` nor `getcpu`. `pthread_cpu_number_np` succeeds, and over 100,000 reads it answered every CPU from 0 to 17. `THREAD_AFFINITY_POLICY` answers 46 (`KERN_NOT_SUPPORTED`).

What follows from these:
- **The kernel models one value per running task.** `getcpu` (Linux) and the value behind `pthread_cpu_number_np` (Darwin) both report it.
- **"Last CPU" is only observable for a task that is not running,** and only through procfs, which nothing reaches. A task calling `getcpu` is running by definition.
- **Real tasks move, and they move at a dispatch.** A CPU fixed at creation is one client's policy, not a rule of the kernel.
- **A real kernel never reports a CPU the machine lacks,** whatever `DOTNET_PROCESSOR_COUNT` says. CoreLib reduces every processor ID modulo its own count (`SharedArrayPool.cs:344`, `Timer.cs:514`, `PoolingAsyncValueTaskMethodBuilderT.cs:359`), so no shard index needs the two counts to agree.

## 2. The state

**Per task, per CPU, or both?** Both, as Linux has:
- **Per task, `Cpu : CpuId`.** This is the existing field, with its meaning stated truthfully: the CPU the task last ran on, or, before its first dispatch, the one its creator named. Only `dispatch` changes it. A task always has one, so it stays a field rather than a map (skill §2).
- **Per machine, `Occupants : Map<CpuId, OsThreadId>`.** This is the task running on each busy CPU.
  - Keying the map by CPU makes "two tasks running on one CPU" unrepresentable.
  - It is on the machine because a multi-process machine's processes share its CPUs.
  - It names the occupant by `OsThreadId` because `UnixMachineState` is not generic in `'Task`, task names are per process (`ProcessSlot.Tasks`), and the machine's `ThreadIdAllocator` already gives every live task a unique thread ID.
  - An idle CPU is absent from the map. Idle is a truthful reading of an absent key, so the map form is right, and an idle CPU is never stored.
- **Whether a task is running is derived, never stored:** T is running exactly when `Occupants[T.Cpu] = T.OsThreadId`. No flag exists to disagree with the map.

**The alternative I rejected: occupants only.** It would drop the per-task field, and with it the `cpu` parameters of `spawn` and `ProcessLaunch.create`. That is smaller, and it is the closest call in this document. I kept the per-task field for three reasons:
- It is the one fact a real kernel keeps about a task that is not running (measurement 3).
- Procfs, or affinity on a sleeping task, would need it back, along with a creation CPU on `spawn`, which would be a breaking change after 1.0.
- Without it, PawPrint would have to hold each thread's CPU itself.

The crux: if the only reader of a non-running task's CPU will ever be the client, occupants-only is better.

**Can two tasks be running on one CPU at once?** No: it cannot be represented. Many tasks may share a `Cpu`, as many share a Linux run queue.
- On a multi-process machine, dispatching process B's task to CPU 0 displaces process A's task. Only the machine's map changes; A's slot is untouched.
- A's task keeps `Cpu = 0`, which is what Linux's `task_cpu` says of a preempted task.

**What does "not running" mean for `sched_getcpu`?** The question never arises, because a task calling `getcpu` is running. If the kernel does not have the caller on a CPU, the client's bookkeeping is wrong, and `getcpu` throws, just as a syscall from a parked task throws today. The last CPU stays readable through `UnixTaskState.cpu` (#1809), which is what field 39 would report.

**How does a parked task interact with this?**
- **A park takes the task off its CPU.** `UnixSystemState.setPark`, the one place a park is written, removes the task from `Occupants`.
- **A parked task may be dispatched.** That is how a woken task gets back on a CPU to finish its call.
  - Wakes are pulled. `UnixWait.wakes` takes the client's set of tasks it considers asleep, and the kernel holds no "woken" bit.
  - A woken waiter can also find its condition gone by the time it runs (two readers woken for one byte), and then it parks again.
  - So "dispatching a task that is still asleep" is an error in the client's records, like a wrong `asleep` set. Kernel state cannot detect it.
  - If `futex` and `__psynch` move blocking into the kernel (#1726's long-term item), a pushed wake would make it detectable.
- **A task ending takes it off its CPU.** `exitThread`, `exitGroup` and `SimulatedMachine.endProcess` all remove the task from `Occupants`.

## 3. API shapes

- **A, dispatch.** `UnixScheduling.dispatch task cpu` means "task now runs on cpu". It sets the task's `Cpu` and the CPU's occupant, displacing whoever was there. If the task was running elsewhere, that CPU becomes idle. `UnixScheduling.getcpu task` answers the occupied CPU, and `UnixScheduling.runningOn task` answers `CpuId option`.
- **B, nothing held.** The client passes the CPU to `getcpu task cpu`, and the kernel checks its range and echoes it. The `Cpu` field and the creation parameters go.
- **C, placement plus `migrate`.** This is today's model, with `migrate task cpu` added. The client calls it only when a task moves, and `getcpu` answers the task's `Cpu`.
- **D, the CPU at every kernel entry.** Every syscall takes the calling task and its CPU, and the kernel records the CPU it saw last. This is the only point at which a kernel ever observes a task.

Without occupants, A and C are the same function under two contracts. Calling `dispatch` on every run or `migrate` on every move leaves identical state, because re-dispatching a task to the CPU it is on changes nothing. So what A adds is the record of who occupies each CPU, and the check that uses it in `getcpu`. Without that check, "call `dispatch` each time you run a task" is a rule the kernel cannot enforce.

| | A, dispatch | B, nothing held | C, placement + `migrate` | D, CPU at every entry |
| --- | --- | --- | --- | --- |
| Cost to a client that never migrates (PawPrint) | One call when it runs a task. A no-op when nothing changed, and it then returns the same object, so calling it every step allocates nothing | Holds placement itself, and passes it to `getcpu` | Nothing | One more argument on every syscall |
| A PCT harness steering from outside | Each decision is one `dispatch`. It can model N parallel CPUs, time slicing and migration, and the kernel checks each report | Passes c to every `getcpu`. Nothing is checked across calls: it can say T and U are both on CPU 0 | Calls `migrate` when it moves a task. It cannot say which of the tasks sharing a CPU runs | Names c at every call. Checked per call only |
| Multi-process machines | Occupants live on the machine, keyed by thread ID. A dispatch in one process's view displaces another's task without touching that process's slot | Nothing to compose | Per task, so it composes, but there is nothing machine-wide to check | As C |
| CPU time, later | A dispatch starts a run interval; displacement, a park or an exit ends it. It also supports a client-reported "T used d", which becomes checkable: T must occupy a CPU, and d is bounded by the time since its dispatch. Context-switch counts (`ru_nvcsw`) and rseq's "preempted or migrated since" also come from dispatches | No record, so a reported d cannot be checked | Records only migrations, so a second event would be needed that overlaps `migrate`. Retiring `migrate` after 1.0 would break clients | The time between two syscalls is not a run interval |
| 1.0 API (#1766) | Adds a `UnixScheduling` module (`dispatch`, `getcpu`, `runningOn`), `GetCpuAnswer`, `GetCpuRefusal`, four `UnixSystemDefect` cases and one `LaunchRefusal` case. No existing signature changes | Removes `UnixTaskState.cpu` and the `cpu` parameters of `spawn` and `ProcessLaunch.create` | Adds `migrate` and `getcpu` | Every syscall entry point's signature changes, and most tests with it |
| Invariants `checkInvariants` can check | Each task's `Cpu` is in range. Each occupied CPU is in range. Each occupant is a live task (machine-wide in `SimulatedMachine.checkInvariants`; its own process's tasks in a view). Each occupant's `Cpu` is the CPU it occupies. Two tasks on one CPU cannot be represented | None | Each task's `Cpu` is in range | As C |
| Refusals and throws | `dispatch`, or a `spawn`, naming a CPU outside `[0, ProcessorCount)`: throw. `getcpu` from a task that is unknown, parked or not running: throw. `getcpu` under Darwin: typed. A launch whose leader CPU the machine lacks: typed `LaunchRefusal`. A parked task being dispatched is not refused (section 2) | `getcpu` with a CPU out of range | `migrate` with a CPU out of range | Per syscall |

**Throw or typed refusal?** This follows the rule decided on 2026-10-09 for `UnixWait.wakes`. The client can read `UnixSystem.processorCount` and its own tasks. So a CPU the machine lacks, or a `getcpu` from a task it never put on a CPU, means its own bookkeeping disagrees with the kernel, and that is a client bug. A `Result` would make every caller handle an error that only a buggy client produces.

A launch is configuration, so it gets a typed refusal under the boot-setter policy. The value is contradictory: the launch names a CPU the machine lacks. That is the same shape as `LaunchRefusal.NotOfPlatform`.

Darwin has no `getcpu`, so `getcpu` there is refused, as `epoll_create1` is (`UnmodelledFlavour`). The value behind `pthread_cpu_number_np` is the same record. A Darwin client that needs it can have a reader added later without breaking anything.

`getcpu` answers `{ Cpu; Node = 0 }`. The model has one NUMA node, which matches what was measured. A node count in the boot image could be added later, defaulting to 1, without breaking anything.

## 4. Recommendation

**Choose A, with both kinds of state from section 2.**
- **It is the record Patrick asked for:** "task T is *now running* on CPU c".
- **It is what the issue already assumes:** "the client then reports that choice to the kernel as a dispatch".
- **It is Linux's own state.** The measured behaviours (a blocked task keeps its CPU; it moves at a wake; setting affinity moves a running caller before return) are about exactly these two records.
- **It costs PawPrint one call per step,** with no allocation when nothing changed.
- **Every post-release item has a place:**
  - CPU time starts and ends at dispatch, displacement, park and exit;
  - affinity becomes a per-task mask that `dispatch` checks, and a `sched_setaffinity` that excludes a running caller's CPU takes the caller off it, so the client must dispatch it somewhere allowed before it returns (measurement 4);
  - rseq is written at dispatch;
  - procfs reads `Cpu`.

**The alternatives:**
- **B** discards the record that Patrick decided the kernel should keep.
- **C** is the cheapest today. But its contract is unenforceable, and it needs a second, overlapping event as soon as CPU time arrives.
- **D**'s blast radius is the whole syscall surface.

**Decided here, with the crux in case Patrick disagrees:**
- **PawPrint places threads over the machine's CPUs, not over `DOTNET_PROCESSOR_COUNT`.** This reverses the choice #742 made, and audit #10's "no change for now". It must happen before the kernel checks the range, or a run with the knob above the machine's count would throw. The evidence:
  - real Linux never reports a CPU the machine lacks;
  - CoreLib reduces every processor ID modulo its own count.

  The cost is that a recorded trace which set the knob above `ProcessorCount` and read `GetCurrentProcessorId` changes.
- **`getcpu` requires its caller to occupy a CPU.** That turns "dispatch when you run a task" from a rule a client must remember into one the kernel checks at the only call that reads placement.

**The question for Patrick:** should every syscall, not only `getcpu`, require its caller to occupy a CPU?
- **My default is no.** Nothing but `getcpu` reads placement before release. The rule would extend the forty or so per-syscall "caller is parked" checks, and every test that makes a syscall from a spawned task would need a dispatch first.
- **Why it has to be decided now:** adding the rule after 1.0 would break clients. So this is effectively the last time it can be added. If the answer is "not before 1.0", then the answer is never.

## 5. Implementation plan

Each PR is green alone.

1. **PawPrint: place threads over the machine's CPUs.**
   - **Code:** `cpuForRotation` takes the count from `UnixSystem.processorCount`. Its docstring, and the one on `NativeSystemNative`'s `SchedGetCpu`, change from "a processor the guest also counts" to "a processor the machine has".
   - **Unit test:** `TestCpuPlacement`'s knob property inverts: placement depends on `ProcessorCount` alone, whatever the knob says.
   - **Guest test (`sourcesImpure`):** with `ProcessorCount = 2` and `DOTNET_PROCESSOR_COUNT=8`, `Environment.ProcessorCount` is 8, every thread's `GetCurrentProcessorId` is in {0, 1}, and `ArrayPool<byte>.Shared` round-trips.
   - **Guest test, the other way:** with a count of 8 and the knob at 2, IDs up to 7 appear. No oracle, because the host's CPU count would decide the answer.
2. **Kernel: the range (closes audit #10).**
   - **Code:**
     - `spawn` throws on a CPU outside `[0, ProcessorCount)`.
     - `UnixBootImage.boot` and `SimulatedMachine.launch` refuse with `LaunchRefusal.LeaderCpuBeyondMachine`.
     - Add `UnixSystemDefect.CpuBeyondMachine`.
     - Rewrite `UnixTaskState.Cpu`'s docstring.
   - **Tests:**
     - Properties over every count and CPU: `spawn` throws, and `boot` and `launch` refuse, exactly when the CPU is out of range.
     - The existing fuzzers that call `checkInvariants` pick up the new clause.
     - Mutation-test by deleting each check.
3. **Kernel: occupants, `dispatch`, `getcpu`.**
   - **Code:**
     - Add `UnixMachineState.Occupants`.
     - Add a new family file, `UnixScheduling.fs`, with `dispatch`, `getcpu` and `runningOn`.
     - Take tasks off their CPU in `setPark`, `exitThread`, `exitGroup` and `SimulatedMachine.endProcess`.
     - Add three more `UnixSystemDefect` cases and their clauses.
     - Update the README's section on what the kernel leaves to the client (#1808): the placement policy is the client's, and `dispatch` is its report.
   - **The test, a reference model:** a history-scanning oracle, deliberately unlike the kernel's state update. T runs on c exactly when the most recent event mentioning T or c is "dispatch T to c", and T's CPU is that of its latest dispatch, or else its creation CPU.
   - **The generator:** sequences on a `SimulatedMachine` of 1–4 CPUs, 1–3 processes and up to 6 tasks, over these operations:
     - spawn;
     - dispatch, about 10% of them out of range;
     - park, by a blocking `read` on an empty pipe;
     - wake and finish;
     - `exitThread`;
     - `endProcess`;
     - `getcpu`.
   - **After every step, check that:**
     - `getcpu` answers or throws for every live task exactly as the oracle says;
     - `runningOn` agrees with the oracle;
     - `checkInvariants` is empty;
     - re-dispatching a running task to its CPU returns a reference-equal system.
   - **Distribution floors**, as `TestSignalState` has, each with a stated margin:
     - a displaced task calling `getcpu`;
     - a woken task dispatched while still parked;
     - a displacement across processes;
     - an out-of-range dispatch.
   - **Mutations that must fail the suite:**
     - no displacement;
     - a park that leaves the CPU occupied;
     - an exit or `endProcess` that leaves its CPU occupied;
     - no range check;
     - `getcpu` answering `Cpu` without checking that the task occupies it.
   - **Also:** `getcpu` under Darwin is refused.
4. **PawPrint: report dispatches, and answer through `getcpu`.**
   - **Code:**
     - Before stepping a thread, `BoundedRun` and `MultiProgram` call `dispatch` with that thread's `UnixTaskState.cpu`. The signal dispatcher is included.
     - On Linux, `SystemNative_SchedGetCpu` answers through `UnixScheduling.getcpu`.
   - **Measure** tick time and bytes per tick over the Guest suite against `main`, as #1791 did. If the call costs measurably, dispatch only on a switch or after a park, and let `getcpu`'s throw catch any dispatch that gets missed.
   - **Guest tests:**
     - A thread blocks on a pipe read, is woken, then reads `GetCurrentProcessorId`. This checks that a thread is dispatched again after a park.
     - Two programs on a one-CPU machine each read their processor. This checks displacement across processes.
     - `SchedGetCpuPlacement.cs` passes unchanged.

**After release, each item attaches to A without breaking anything:**
- `vacate`, for blocks the client keeps itself (so that CPU time stops for a thread in `Monitor.Wait`);
- CPU time, recorded at dispatch;
- the affinity syscalls, with the per-task mask that `dispatch` checks;
- rseq;
- a NUMA node count.

## Decision (orchestrator, 2026-10-09)

**Option A, as recommended.** Patrick decided on 2026-10-09 that CPU placement is release work. The open question was whether every syscall should require its caller to be on a CPU.

**Answer: no. Only `getcpu` requires it.**
- A client that never reads placement should not have to report it. A trace replayer has no CPU column, so a universal rule would make it dispatch to an arbitrary CPU before every call, which the check could not verify as true.
- The record is enforced where it is read. `getcpu` throws for a task that is not on a CPU, so a client that does read placement cannot get a stale answer.
- When CPU-time accounting arrives, its clocks and `getrusage` can refuse for a task that has never been dispatched. That keeps the check where the fact is read, and needs no universal rule now.

**PR 1 reverses #742's placement over `DOTNET_PROCESSOR_COUNT`, deliberately.**
- No real kernel reports a CPU it does not have, and CoreLib reduces every processor ID modulo its own count. So nothing a guest can observe needs IDs at or above the machine's count.
- The cost is that a recorded trace which set the knob above the machine's count and read `GetCurrentProcessorId` will change. That cost was accepted.
