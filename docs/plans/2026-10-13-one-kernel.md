# Plan: one kernel, where every call names its caller

Status: proposed 2026-10-13, after a whole-repository review. Directions approved by Patrick: one kernel state with a (process, thread) caller on every call; kernel-side wake state and the return-to-user change folded in; "derive flavour facts"; a total `Syscall` union as labels; reserved union cases kept; everything breaking lands before 1.0.

Each stage is its own branch, stacked where necessary, so that each can be reviewed alone.

## 0. In brief

1. **C — a caller on every call.** Every public `X` and internal `tryX` gains a `Caller` while the state is still today's per-process view. Each goes through one internal entry combinator, which validates the caller.
2. **F — the flip.** The public `UnixSystem` becomes the whole kernel. Only the entry combinator changes: it now focuses the caller's process atomically, so no view can go stale, and the staleness machinery is deleted in the same PR. The function bodies stay view-shaped, behind an internal lens.
3. **W — wake state and the return to user mode move into the kernel.**
4. **D and S.** D derives the cross-process summaries the machine now duplicates. S makes `Syscall` total.

Tests reach the caller by a mechanical rewrite, and reach the kernel through a few test helpers that are centralised first (T1, T2), so the flip edits almost no test call sites.

## 1. Target API

### The kernel

`UnixSystem<'Thread, 'Handler>` keeps its name and becomes the whole kernel; `SimulatedMachine` is deleted.

```
UnixSystem  = { Machine; Scheduling; Processes : Map<ProcessId, ProcessSlot>; Sweep }   // internal
ProcessSlot = { Process; Threads; Leader }                                            // today's
```

`Sweep` is the wake memo, kept inside the kernel and ignored by equality.

Keeping the name means 1,619 test type annotations and 326 boot sites stay valid, the README already calls the whole kernel "a `UnixSystem`", and every signature changes anyway, so the compiler finds every client use. The alternative, `UnixKernel`, is louder at the cost of a mechanical rename.

### The caller

`Caller<'Thread>` is an opaque struct over `ProcessId * 'Thread`: `Caller.make pid thread`, `Caller.processId`, `Caller.thread`, with structural equality and comparison. Opaque rather than a public record, because a record labelled `Process` and `Thread` would capture F# label resolution for the internal `ProcessSlot.Process`. Threads stay named per process, so two processes may both have a thread 0.

### Representative signatures (the kernel argument left out)

| | Before | After |
|---|---|---|
| dup | `UnixDescriptor.dup (fd)` → `SyscallAnswer * UnixSystem` | `dup (caller) (fd)`, same answer |
| read | `UnixReadWrite.read (thread) (fd) (buffer) (count)` → `ReadOutcome * UnixSystem` | `read (caller) …`; `ReadOutcome.Restarts` becomes `Interrupted` (W4) |
| finishRead | `finishRead (thread)` | `finishRead (caller)`, requiring a `Woken` park; also `UnixWait.finish (caller)` → `FinishedCall` (W3) |
| write | `write (thread) …` → `CallProgress<PausedWrite, ProcessFate<WriteOutcome>>` | `write (caller) …`, same answer |
| writeWithBytes | `(bytes) (paused)` | unchanged: the paused value holds the caller and the focus continuation |
| kill | `kill (pid) (signo)` | `kill (caller) (pid) (signo)`; another pid stays refused for now |
| pthreadKill, spawn | `pthreadKill (target)`, `spawn (parent) (child) (cpu)` | `pthreadKill (caller) (target)`, `spawn (caller) (child) (cpu)` |
| exitGroup | `exitGroup (thread) (status)` → `EndedProcess` | `exitGroup (caller) (status)` → `EndedProcess * UnixSystem` |
| `ProcessFate.ProcessEnded` | `of EndedProcess` | `of EndedProcess * UnixSystem`: the kernel without the process |
| launch | `SimulatedMachine.launch (launch)` | `UnixSystem.launch (launch)` → `ProcessId * UnixSystem`; `UnixBootImage.boot` answers the kernel |
| wakes | `UnixWait.wakes (asleep)`, `SimulatedMachine.wakes`, `wakesRemembering memo asleep` | `UnixWait.wake` → `(Caller * Set<WakePrimitive>) list * UnixSystem`; `UnixWait.deadlines` takes no set; `UnixWait.satisfied (caller)` |
| checkInvariants | `UnixSystem.checkInvariants`, `checkViewInvariants`, `SimulatedMachine.checkInvariants`, `FileDescriptorRegistry.checkInvariants` | one `UnixSystem.checkInvariants`; `VirtualFileSystem.checkInvariants` stays separate |
| per-process queries | `UnixSystem.threads`, `credentials`, `signals`, … | take `(pid)`; syscall-like ones (`getpid`, `umask`) take the caller; `UnixSystem.processIds` is new |
| step | `UnixSystem.step (thread) (call)`, `SimulatedMachine.step pid thread call` | `UnixSystem.step (caller) (call)` |
| onReturnToUser | `(thread)` | `(caller)`; after an `Interrupted` call, it also says EINTR or restart |

### An ended process is removed at once

The call that ends it closes its descriptors in each flavour's measured order (today's `SimulatedMachine.tryEndProcess`, made internal) and answers `EndedProcess * UnixSystem`, where `EndedProcess` is just `{ ProcessId; Termination }`. That deletes `EndedIn`, `FinalProcess`, the machine copies inside `EndedProcess`, `endProcess`, and the `endLoneProcess` an in-flight branch adds. Exit-time refusals (an `SO_LINGER` close, the Darwin timer cases) then surface from the ending call itself, which is honest because a throw leaves nothing behind. Removal at once is what a parent outside the kernel that reaps at once would see; zombies arrive with `fork` and `wait`, in the same answer shape.

### What becomes of each piece

- `UnixSystem` becomes the kernel; today's record becomes the internal lens `ProcessView = { Machine; Scheduling; ProcessId; Process; Threads; Leader; Others }`.
- Deleted at F1: `SimulatedMachine` with `focus`, `unfocus`, `inView`, `holdsProcessOf`, `ofSystem`, `assertCurrent`, `SimulatedMachineDefect`; `FocusOrigin`.
- Deleted at D1: `DescriptorCensus`, `machineDefects`' `complete` flag, `UnixSystemState.census`, the census argument in ProcessLaunch.
- Derived (D2–D4): `ProcessIdTable.Live` (the kernel's keys are the truth), `ThreadIdAllocator.Live` (`allocate` takes the live set), `CurrentDirectories`, and the duplicate `UnixProcessState.ProcessId` (removing `SlotUnderAnotherProcessId`, `DuplicateProcessId`).
- Kept as indexes, each with one invariant: each description's descriptor and hold counts (the kernel's `f_count`, read on hot paths, and public); `KqueueState.Owner` (a real fact: whose table the registrations' fd numbers are read in); `PollQueues`.
- The invariant split collapses into one function with per-process clauses; a defect about a thread carries its `Caller`.

### Wake state and the return to user mode

- `ThreadPark` gains `State : Asleep | Woken of Set<WakePrimitive>`; `wake` writes `Woken`. The exclusive-queue rule in `wakesAmong` reads `Woken` parks instead of "parked but not in `asleep`".
- `UnixWait.finish caller` answers a union with one case per park kind, reserved parks included, so finishing them later adds no case after 1.0. The per-family finishers stay public, for their precise answer types.
- An interrupted call answers `Interrupted`. The thread then owes a return to user mode (the mark records the call's restart rule); `onReturnToUser` decides EINTR or restart and clears the mark, and any other call by that thread throws `InvalidOperationException` until then. The refusals `MixedRestartFlags` and `DefaultAction` move from `SyscallInterruption.ofPark` to `onReturnToUser`.

## 2. How the library gets there

**C0: entry combinators.** A few internal combinators in UnixSystemState.fs, one per answer shape (answer alone; answer and system; a `Result` of those; a `ProcessFate`; a `CallProgress` whose paused value holds the system). Each takes a requirement (`Running`, `Woken`, `Returning`, `Exists`), the caller, and a body over the view. During C each validates the caller (its process is the view's, the thread exists and meets the requirement) and runs the body on the view. Each family's C PR splits every function into `tryX caller … = Entry.x req caller (tryXIn …)`, keeping the body unchanged as `tryXIn` and passing `Caller.thread caller` where the body took a thread.

**R1: rename only.** `type internal ProcessView<'T, 'H> = UnixSystem<'T, 'H>`, and re-annotate the internal bodies. Reviewed as a rename-only diff.

**F1: the flip.** `ProcessView` becomes a real record and `UnixSystem` the kernel; only the combinators change, to focus, run the body, and unfocus; paused values capture the unfocus continuation. Two details the wake memo depends on: `unfocus` returns the same kernel value when the view's parts are physically unchanged, or every read-only call would invalidate the memo, which compares by reference; and `UnixScheduling.dispatch`, called once per instruction, bypasses the lens and works on `Scheduling` without allocating.

After F1, bodies get the `Others` part of the zipper, so D can derive summaries from other processes, and W and S are ordinary work on a stable shape.

## 3. Tests

Tests use internals heavily: 2,221 internal `try*` calls, 449 uses of `UnixSystemState.fileDescriptors`/`withFileDescriptors`, 384 reads of `.Process`, 166 of `.Threads`, 86 of `.Leader`, 109 `Process =` record updates, 147 `SimulatedMachine.*` calls.

- **T1.** A test-only `Lone` module takes all of the single-process accesses (`Lone.proc`, `mapProc`, `threads`, `leader`, `fileDescriptors`, `withFileDescriptors`, `view`). Before F1 they are the identity on the view; at F1 they focus the kernel's only process, failing loudly if there are several. It also absorbs `Launched.restand`, `ForgedPark` and `EndedMachine`.
- **T2.** `Machines.fs` absorbs every `SimulatedMachine` use outside `TestSimulatedMachine`; at F1, `Machines.inProcess pid f k` becomes `f k` after checking that `pid` exists.
- **Callers.** A test module with `Callers.leader`, `Callers.thread n`, and `Caller.make pid n`. Each C PR rewrites its family's call sites mechanically, with a Python `str.replace` script (AGENTS.md: perl's `$` corrupts F# interpolated strings). A test that parks thread 0 and then makes a callerless call must pick an unparked caller: a real test bug the new validation exposes.
- **Green at every stage.** Each PR runs the full suite and the `LargeMemory` filter on its own; updates its README rows and examples (TestReadme runs them); regenerates SurfaceBaseline.txt with the `TestSurface&Name~Update` filter; and regenerates deliberately where a union case is renamed or changes payload (`Restarts`→`Interrupted`, `ProcessEnded`). Every merge to main publishes, so F1's transitional shapes reach nuget; acceptable before 1.0.

## 4. Stages

Sizes count changed lines, test churn included: S under 600, M 600–2k, L over 2k.

| PR | Does, and deletes | Depends on | Oracle | Size |
|---|---|---|---|---|
| in flight | the review's fix and dedup branches | — | their own tests | — |
| P2 | a paused write carries the admission's decision; the step after copy-in applies it | copy-in plumbing | write/send tests unchanged | S |
| P3 | derive flavour facts: delete `SignalState.Numbering` and other stored platform copies; `OpenFileStatus` a per-flavour union with one writer module | in flight | suite; status union tests per flavour | M |
| T1 | `Lone` helpers (test-only) | none | suite; grep finds `.Process`/`.Threads`/`.Leader`/`UnixSystemState.*` only in `Lone` | L, mechanical |
| T2 | `Machines` absorbs `SimulatedMachine` (test-only) | none | suite; grep | M |
| C0 | `Caller`, entry combinators, `Callers`, README "Making a call" | in flight, P3 | caller-validation tests (absent process, absent thread, parked thread, wrong process), mutation-tested | S |
| C1 | Descriptor, Pipe | C0 | suite; README rows | L |
| C2 | PathResolution, Credentials, Clock, Entropy | C0 | same | L |
| C3 | Namespace, Inotify | C0 | same | M |
| C4 | ReadWrite, finishers included | C0, P2 | same | M |
| C5 | Socket, Connection | C0 | same | M |
| C6 | Poll, Kqueue | C0 | same | M |
| C7 | Signal, ThreadLifecycle, Scheduling, `UnixWait.satisfied`, per-process queries, `step` | C0 | same | L |
| R1 | `ProcessView` abbreviation | C1–C7 | build, suite, rename-only diff | L, trivial |
| F1 | the flip; deletes `FocusOrigin`, `SimulatedMachine` and its staleness API, `SimulatedMachineDefect`, the public view-invariant split | R1, T1, T2 | suite; property: a fuzzed multi-process sequence answers as today's focus/unfocus replay on the TestMultiProcessFuzz corpus; README "Several processes" | L |
| F2 | a process ends in its own call (`ProcessEnded of EndedProcess * UnixSystem`) | F1 | exit close-order tests through `exitGroup`; README | M |
| W1 | `ThreadPark.State`, `UnixWait.wake`; deletes the `asleep` arguments | F1 | wake-order tests; property: `wake` ≡ old `wakes` with `asleep` = the `Asleep` parks | M–L |
| W2 | the memo moves into the kernel; deletes `WakeSweepMemo`, `wakesRemembering` | W1 | Debug cross-check; TestWakeSweepMemo properties | S |
| W3 | `UnixWait.finish` | W1 | each family's finisher ≡ `finish` | M |
| W4 | `Interrupted`, decided at `onReturnToUser`; the owes-return mark | C7, best after F1 | TestSyscallInterruption, sigsuspend tables, signal fuzz corpus unchanged | L |
| D1 | delete `DescriptorCensus` | F1 | TestFileDescriptorRegistry; mutate a count | S |
| D2–D4 | derive live process IDs, live thread IDs, current directories | F1 | TestThreadIds, TestStartingDirectory, TestInodeLifetime | S each |
| S1–S3 | a total `Syscall`, with `step`'s answer union; reserve exactly the calls the reserved parks imply (`nanosleep`, `select`, `sigwait`, the datagram calls) | C7, F2, W3, W4 | `step c call ≡ direct call`, a property per case | M each |

Order: merge the in-flight branches; T1 and T2 alongside them; then P2 and P3; then C0; C1–C7 stacked, or in at most two lanes whose test files don't overlap; R1 in a quiet window just before F1; after F1, three lanes (F2; W1→W2→W3; D1), with W4 beside them; S last. Everything but D2–D4 lands before 1.0. About 25 PRs.

## 5. Choices made in this plan

1. A caller is `(ProcessId, 'Thread)`, with thread names per process. Machine-unique names would make the caller just `'Thread`, but `launch` and `fork` can't put the pid in a name the client chose before the kernel chose the pid; `OsThreadId` is reused after a Linux wrap.
2. The caller is validated on every call, by the combinator: the process and thread exist, and the thread is not parked and owes no return. Finishers require `Woken`; `onReturnToUser` accepts `Returning`; `dispatch` accepts any existing thread.
3. When a thread owes a return to user mode. The planning agent proposed "only after `Interrupted`", since marking after every call would force every test to call `onReturnToUser` between calls. The review's amendment: also mark it after any call that leaves a signal the thread would take at the return (a deliverable pending signal), since that is exactly the case where skipping the return silently loses a handler, and a test with no signals is unaffected.
4. An interrupted call whose signal is no longer deliverable at the return (another thread changed the disposition in between): Linux restarts the call, by its source. Refuse until a probe measures it.
5. The per-family finishers stay public beside `UnixWait.finish`.
6. An ended process is removed at once (§1).
7. `Syscall` reserves exactly the calls the reserved parks imply.

## 6. Relation to earlier decisions (docs/design, PR #24)

- **`waiting-options` chose B (an algebra of wake conditions, pulled) over C (kernel-owned wait queues, pushed).** W1 keeps B. Nothing that makes a condition true wakes anyone; `UnixWait.wake` is today's sweep over today's conditions, and the only change is where the "woken, not yet finished" bit lives: in the park, rather than inferred from "parked but missing from the client's `asleep` set". So C's objection ("one forgetful producer is a silent deadlock") does not apply; today the forgetful party that causes a silent deadlock is the client, whose set must name every parked thread. C's other objection ("waiter state that duplicates the client's thread statuses") is answered the other way round: today the client's `asleep` set duplicates the kernel's park records, and after W1 a client reads a kernel-parked thread's status from the kernel instead of keeping its own copy. The exclusive-wake under-approximation recorded in "Decision, stage 3" is unchanged.
- **`lifecycle-options` design B** ("a process table, single-process in practice": `UnixSystem = { Machine; Self; Processes : Map<ProcessId, ProcessEntry> }`) is close to this plan's target, without `Self`, since the caller names the process, and with an ended process removed at once rather than kept as a zombie, which that note's `EndedProcess`-as-zombie-payload upgrade path still allows. Leader-first thread exit stays refused, as there, for the leader-receives receiver rule; the measured Linux zombie-leader and Darwin vanishing-leader rows (mainexit) are what a later change would model.
- **The scheduling decision (audit-2026-10-02, revised 2026-10-03)** stands: the kernel never chooses who runs. `wake` marks parks woken; when a woken thread runs is still the client's choice.
- **audit-2026-10-02 rejected "`step` not covering read" and "the admit/write split" as defects.** Both are superseded by the 2026-10-13 decisions: `Syscall` becomes total, as labels `step` interprets; and the admission/apply split stays, but the apply step takes the admission's decision from the paused value instead of re-deriving it (P2).

## 7. What the shape makes possible (out of scope)

`kill` of another process (generation in the target's lens, `ESRCH`/`EINVAL` in the order `kill-arguments.c` measured); `getppid`, once a launch can name a parent; `fork` (copy the table, bump the counts, the client names the child's thread); `wait`, `SCM_RIGHTS`, and a pipe shared between launched processes.

## 8. Things the view model leans on

The wake memo's reference-equality reads (§2); `UnixSchedulingState` held apart from the machine, so a dispatch doesn't change the machine's identity; `FocusOrigin`'s custom equality being part of `UnixSystem`'s (deleting it makes more systems compare equal, harmlessly); tests reaching internals through `try*` functions (why C splits `tryX` from `tryXIn`); `UnixSystemDefect<'Thread>` naming a thread without its process; the docstrings of `PollQueue` and `KillRefusal.OtherProcess`, which explain themselves by the view; a paused call holding the whole kernel, so no other process runs during a copy-in, as is already true in effect.

Performance: each call pays one map find and one map add for the focus; `dispatch`, the once-per-instruction path, bypasses the lens.
