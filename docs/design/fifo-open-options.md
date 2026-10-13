# Opening a FIFO in WoofWare.PosixKernel: the public shape before 1.0

*Options document, 2026-10-11. Design item D1 of `reserved-union-cases.md`. Code references are at `origin/main` `7d700bb6`. The probe and its outputs are committed on branch `pk-fifo-open-probe` (`docs/probes/fifo-open/`: `fifo-open.c`, with `measured-darwin-27.0-uid501.txt`, `measured-linux-6.18.5-aarch64-root.txt` and `measured-linux-6.18.5-aarch64-uid1000.txt` beside it). Row names below (A1, C3, …) are the probe's sections. No library or PawPrint code has changed.*

**Decided already (Patrick, 2026-10-10).** FIFOs will be modelled. `openat` and `openPath` change shape before 1.0, so that a FIFO open can sleep. `InodeContent.Fifo` and `DirectoryEntryKind.Fifo` are reserved as the socket cases were in #1849. The behaviour is not release work; the shape is.

## 0. Summary

- **Both flavours agree on everything a blocking open needs.** An open of one end sleeps until the other end is opened. While it sleeps, it counts as an open end. A partner that opens and closes before the sleeper runs still completes the open. A signal ends it with EINTR and releases its end. The descriptor number is taken before the sleep.
- **They differ in six places.**
  - `SA_RESTART` restarts the open on Linux only; Darwin answers EINTR.
  - `SIGSTOP` ends the sleep on Linux only.
  - Poll of either end differs.
  - `FIONREAD` differs on the write side.
  - `dup2` onto the reserved number is EBUSY on Linux and waits on Darwin.
  - A Darwin FIFO's buffer is 8192 bytes, not a Darwin pipe's 65536. So a Darwin FIFO is not a Darwin pipe.
- **Recommendation.**
  - `openat` and `openPath` take the task and answer `SyscallOutcome` (option A).
  - A FIFO's description is a new `OpenFileTarget.Fifo of inode * attachment`, with an opaque attachment (option R2). It is not the existing `Pipe` case.
  - Reserve three more cases now: that one, `ParkedSyscall.FifoOpen of ParkedFifoOpen`, and `WakePrimitive.FifoPartnerOpened of opener * opens`.
- **Release work is four PRs:** the inode cases, the shape change, the description case, and the park with its primitive. The behaviour is four more, after 1.0 if need be.

## 1. What there is today

### 1.1 The shape of `open`

| function | signature (after `system`) | answers |
| --- | --- | --- |
| `UnixNamespace.openPath` | `(flags : int) (path : PathArgumentBytes) (mode : int)` | `Result<SyscallAnswer * UnixSystem, OpenRefusal>` |
| `UnixNamespace.openat` | `(dirfd : int) (path) (flags : int) (mode : int)` | the same |

- Neither takes a task, so neither can park one. `openPath` is `openat` from `AT_FDCWD` (`UnixNamespace.fs:1210`, `:1230`).
- `O_NONBLOCK` is refused at open (`UnmodelledOpenFlag.NonBlocking`, `UnixNamespace.fs:648`, `:665`). So a non-blocking FIFO open is not modelled either. That is behaviour, not shape.
- The blocking calls that exist take the task first and answer an outcome: `read` (`ReadOutcome`), `accept` (`AcceptOutcome`), `flock` (`SyscallOutcome`). A woken call is finished by its own function: `finishRead`, `finishAccept`, `flockAcquire`.

### 1.2 Who calls `open`

- **PawPrint**, three call sites:
  - `SystemNative_Open` (`NativeSystemNative.fs:3244`);
  - `SystemNative_OpenDir`'s open (`:3494`);
  - minipal's `/dev/urandom` (`MinipalRandom.fs:137`). Its caller has the thread (`MinipalRandom.fs:167`), but `urandomDescriptor` does not take it yet.
- **The README:** the example at `README.md:200`, and the two table rows at `:340` and `:341`.
- **Tests:** 30 direct calls (`UnixNamespace.openPath`/`openat`), plus helpers. 155 references in all, across both test projects.

### 1.3 How a pipe is described

- `OpenFileTarget.Pipe of pipe : PipeId * pipeEnd : PipeEnd` (`FileDescriptorRegistry.fs:759`). `PipeEnd` is `Read | Write`.
- The pipe itself is in the machine's pipe table: `PipeState`, which holds `Buffer`, `Origin` and `Reads`. `PipeOrigin` is `Made of PipeStatus | Launched of …`.
- Whether an end is open is derived. It is open while some open file description names it, including a description that only a park holds.
- `PipeState.Reads` exists for one reason. Darwin wakes a sleeping writer at every read, so a write's park snapshots the count, and `WakePrimitive.PipeReadWhileNonBlocking of writer * reads` compares against it. A FIFO open needs the same kind of snapshot (§4, M3).

### 1.4 How many matches a new case touches

| case | mentions in the library | in PawPrint |
| --- | --- | --- |
| an `OpenFileTarget` case (`Kqueue` as the measure) | 92, in 15 files | 1 (`SignalDispatch.fs:524`) |
| a `ParkedSyscall` case (`SigSuspend`) | 23, in 8 files | 6 (`GuestLocation.fs` and the re-entry dispatch in `NativeSystemNative.fs`, which lists every case) |
| a `WakePrimitive` case (`EndedByClose`) | 7, in 2 files | 0 |
| a `PipeEnd` case | 59 in all | some |
| an `InodeContent` case (`Socket`, after #1849) | 62, in 15 files | 0 |

The registry's representation is private (`FileDescriptorRegistry.fs:1121`). So a reserved descriptor slot (§4, M5) changes no public type.

## 2. Measured facts

**Envelope.**
- **Darwin:** 27.0.0 arm64 (macOS 27.0.1), uid 501, APFS.
- **Linux:** 6.18.5 aarch64 under Apple's `container` (debian:trixie, glibc 2.41), ext4, five CPUs. Run as root (with `CAP_SYS_NICE`, for the forced schedule) and as uid 1000.
- Sections A–G ran five times on Darwin, four times as Linux root and three times as uid 1000. H and I ran twice on each. The answers were identical each time, bar the order of two threads' lines in B5.
- `fs.protected_fifos` was 0. No x86-64 kernel was used; nothing here depends on the architecture.

**Method notes.**
- An "opener" is a thread blocked in `open`. It gets 100 ms to fall asleep.
- A2, A9, B2 and B8 do not force the order: the sleeper may run before the partner's close. So "returned OK" there says nothing about whether a partner must still be present. Two rows do force it:
  - Linux A3/B3: both threads on CPU 0, main under `SCHED_FIFO`. The probe checks that the opener had not returned by the close.
  - Darwin A4/B4: the sleeper is a stopped child process. A8/B7 are the control: stopping and continuing alone wakes nothing.
- D5 is the control for `SA_RESTART`: the same handler restarts a blocking pipe read on both flavours.

| # | what | Linux | Darwin |
| --- | --- | --- | --- |
| A1, B1 | blocking `O_RDONLY` with no writer; blocking `O_WRONLY` with no reader | sleeps | sleeps |
| A2 | `O_WRONLY\|O_NONBLOCK` while a reader sleeps in open | OK: the sleeper counts as a reader | OK, the same |
| A1, A5, B5 | what wakes it | any partner open. Every sleeper wakes (two of two) | the same |
| A6, B6 | `O_RDWR` open by another | wakes a sleeper of either kind | the same |
| A7 | another reader's open | does not wake a sleeping reader | the same |
| A3, B3 / A4, B4 | a partner opens and closes before the sleeper runs | the open succeeds (forced by `SCHED_FIFO`) | the open succeeds (sleeper stopped across it) |
| B2, B3 | a writer woken that way then writes | EPIPE | EPIPE |
| A4, B4 | `SIGSTOP` on the sleeper | ends the wait. The call stops counting: the partner's `O_WRONLY\|O_NONBLOCK` is ENXIO. `SIGCONT` restarts it, asleep | the sleeper still counts, and completes on `SIGCONT` |
| C1 | `O_RDONLY\|O_NONBLOCK`, no writer | OK. `read` 0. `EAGAIN` once a writer is open and nothing is held | the same |
| C2, G8 | `O_WRONLY\|O_NONBLOCK`, no reader (with `O_CREAT` too) | ENXIO | ENXIO |
| C4, C5 | `O_RDWR`, with or without `O_NONBLOCK`, nobody else | never sleeps. Reads back its own write | the same |
| C6 | access mode 3 | EINVAL | EINVAL |
| D1, D3 | signal with a handler, no `SA_RESTART` | EINTR. The end is released: ENXIO for a later `O_WRONLY\|O_NONBLOCK`, and a later `O_RDONLY` sleeps | the same |
| D2, D4 | the same with `SA_RESTART` | restarts: sleeps on, and completes when a partner opens | **EINTR** |
| C1 | poll of a non-blocking read end: no writer yet / a writer open, nothing held / that writer closed | nothing / nothing / `POLLHUP` | `POLLOUT` / `POLLOUT` / `POLLOUT` |
| C3 | poll of a write end whose reader closed; a write | `POLLOUT\|POLLERR`; EPIPE | `POLLOUT`; EPIPE |
| E1–E3 | `stat` of the path; `fstat` of each end and of `O_RDWR` | `S_IFIFO`, the path's permissions, inode and device. `st_size` 0 whatever is held. `nlink` 1, `rdev` 0, `blksize` 4096, `blocks` 0 | the same |
| E2 | a write; a read | the write moves the inode's `mtime` and `ctime` (`stat` of the path sees it). The read moves `atime` | the same |
| E2, E3 | `FIONREAD`, 3 bytes held | 3 on the read end, the write end and `O_RDWR` | 3 on the read end. **0** on the write end and on `O_RDWR` |
| E4, E5 | `lseek`, `pread`; `fchmod` through a descriptor | ESPIPE, ESPIPE; changes the inode | the same |
| F1, F2 | the bytes when every end closes; while one stays open | gone; kept | the same |
| H1–H3 | non-blocking writes of 1, 4096, 1000 bytes until EAGAIN | 65536, 65536, 64000: exactly a Linux pipe | **8192, 8192, 8000**, where a Darwin pipe takes 65536. After the 1000-byte fill the write end polls writable |
| I1 | the descriptor a sleeping open will return | taken before the sleep: another open gets the next number | the same |
| I2, I3 | `fcntl`, `close` of that number meanwhile | EBADF, EBADF | EBADF, EBADF |
| I4–I6 | `dup2` onto that number meanwhile | EBUSY. The open then installs it | **waits** until the open installs it, then replaces it. (From the main thread this hung uninterruptibly; `SIGALRM` did not end it) |
| G1–G4 | `mkfifo`, `mknod(S_IFIFO)`, umask 022 | agree; keep all twelve bits (07777 makes 07755), as root and as uid 1000 | the same, uid 501 |
| G5–G12 | `mkfifo` of an existing name; `O_CREAT\|O_EXCL`; `O_CREAT`; `O_TRUNC`; `O_DIRECTORY`; `mkfifoat`, `openat` | EEXIST; EEXIST; opens it; accepted; ENOTDIR; work | the same |

### 2.1 Read from source, not measured

From Linux 6.18.7 `fs/pipe.c` (`/nix/store/yq0jp3zg…-linux-6.18.7.tar.xz`):
- `fifo_open` (`:1121`) bumps `readers` and `r_counter` (or the writer pair) **before** it sleeps. That is why a sleeper counts (A2). The error paths `err_rd` and `err_wr` undo the count (D1, D3).
- `wait_for_partner` (`:1099`) loops until the partner's *counter* changes. It returns `-ERESTARTSYS` if a signal is pending and the counter has not changed. So `SA_RESTART` re-issues the whole open, path walk included.
- An `O_RDONLY|O_NONBLOCK` open with no writer stores `filp->f_pipe = pipe->w_counter`. `pipe_poll` (`:691`) reports `EPOLLHUP` only when `f_pipe != w_counter`. That is C1's suppression, and it is **state of the description**, not of the pipe.
- The `pipe_inode_info` is made at the first open and freed at the last close. So the counters restart with each new pipe, and F1's bytes go.

From Darwin, nothing was read. The 8192-byte capacity, the `POLLOUT` on a read end and `FIONREAD`'s 0 on the write side all fit a FIFO built from a connected `AF_UNIX` stream socket pair, as BSD's fifofs is. That is an inference from the measurements, not a reading of XNU.

## 3. What is not measured

- **Darwin as root.** As in the other documents.
- **`protected_fifos` = 1 or 2.** `flavour-divergence.md` already states it "row for row" with `protected_regular`, from source.
- **An opener that is woken and signalled at once.** Linux gives the success if the counter changed (`wait_for_partner` checks the counter after the signal). Darwin is unmeasured. The model would refuse that tie on Darwin, as `SyscallInterruption.SignalBesideCompletion` does elsewhere.
- **Darwin's buffer rules beyond the capacity:** `PIPE_BUF`, short writes, the poll threshold. They belong with the `AF_UNIX` stream socket model, which is release work in `socket-address-api-options.md`.
- **Wake order among several sleepers.** Both woke all (A5, B5). A model that wakes every sleeper needs no order.
- **`flock` on a FIFO.** `reserved-union-cases.md` §2.3 says it contends per inode. Not re-measured.

## 4. What the measurements mean for the model

- **M1. An open must be able to park.** A1 and B1 hold on both flavours. Patrick's decision stands, and there is a second reason for it: Darwin's `O_EXLOCK` and `O_SHLOCK` (both `UnmodelledOpenFlag` today) make an open sleep on a lock, by `open(2)`'s manual page; this probe did not measure that. So a FIFO is probably not the only blocking open.
- **M2. The sleeping open holds its description.** A sleeper counts as an open end of its kind (A2, both), and stops counting when a signal ends it (D1, D3, both). In this library an end is open while some description names it (§1.3), and a park holds the descriptions it names. So making the description before the sleep, and letting the park hold it, gives both rows with no new mechanism. Releasing it on EINTR gives D1 and D3.
- **M3. The wake is "a partner has opened since the park", not "a partner is present".** This holds on both flavours (A3, B3 forced on Linux; A4, B4 on Darwin). So the primitive needs a snapshot of a per-FIFO count of partner opens, as `PipeReadWhileNonBlocking` carries `reads`. The count restarts with each new channel, but a sleeper keeps its channel alive, so the snapshot stays meaningful.
- **M4. The finishing call differs by flavour only on signals.**
  - Linux: a changed count beats a pending signal. Otherwise a signal ends the call: `Restarts` under `SA_RESTART`, EINTR without.
  - Darwin: EINTR even under `SA_RESTART` (D2, D4).
  - Both flavours' `SystemNative_Open` loops on EINTR, so a CoreLib caller sees no difference. A raw P/Invoke does.
- **M5. The descriptor number is reserved during the sleep (I1–I6, both).** The registry needs a reserved slot. It reads as unopened to `fcntl` and `close`. Linux's `dup2` onto it is EBUSY. Darwin's `dup2` waits, which the model should refuse rather than park (a new `Dup2Refusal` case). The registry is private, so no public type changes. But the park must name the number.
- **M6. A FIFO's description is not an anonymous pipe's description.** Five rows separate them:
  - its identity and `fstat` are the inode's (E1–E3);
  - its timestamps are the inode's (E2);
  - it can be `O_RDWR` (C4);
  - on Linux it carries the poll snapshot `f_pipe` (C1, §2.1);
  - on Darwin its buffer is not a pipe's at all (H1–H3).
  
  The read and write rules are a pipe's on Linux (H1–H3), so code can be shared there.
- **M7. The FIFO's channel lives only while some end is open (F1, F2).** That confirms Q2 of the audit: the channel is not `InodeContent`. `InodeContent.Fifo of permissions : PermissionBits` holds the twelve bits (G2, G4), and `chmod` applies (E5). The channel belongs in an internal table from inode to channel, the same choice the socket design made (option B, decided).

## 5. The shape of `openat` and `openPath`

### Option A: they take the task and answer `SyscallOutcome` (recommended)

```fsharp
openPath (task : 'Task) (flags : int) (path : PathArgumentBytes) (mode : int) system
    : Result<SyscallOutcome * UnixSystem<'Task, 'Handler>, OpenRefusal>
openat (task : 'Task) (dirfd : int) (path : PathArgumentBytes) (flags : int) (mode : int) system
    : Result<SyscallOutcome * UnixSystem<'Task, 'Handler>, OpenRefusal>
// later, additive, with the behaviour:
finishOpen (task : 'Task) system : Result<SyscallOutcome * UnixSystem<'Task, 'Handler>, OpenRefusal>
```

- **Until FIFOs land** the answer is always `Answered`. The task is checked as `read` checks it: a parked task issuing an open is a client bug, and fails loudly.
- **Why `SyscallOutcome`, not a new `OpenOutcome`.** Open's answer is a descriptor, which `SyscallAnswer` already carries. `flock` is the precedent. A dedicated union, as `read` and `accept` have, would add room for a richer answer that nobody has asked for. That would be a second type to keep in step with this one.
- **Blast radius.**
  - PawPrint: three call sites, plus threading `thread` into `urandomDescriptor`. Each site gains a `WouldBlock` arm. Until the behaviour lands, that arm fails loudly, naming the missing behaviour.
  - The README: an example and two rows.
  - About 30 direct test calls, plus the helpers. All mechanical.
- **Reversibility.** Breaking now, free later. `finishOpen`, the park and the primitive are all additive afterwards (with the reservations of §7).
- **Information kept.** Everything. A client sees every open that would sleep.

### Option B: keep the shape; refuse a blocking FIFO open for ever; add a second entry point later

- `openat` and `openPath` stay. A FIFO open that would sleep answers a new `OpenRefusal.BlockingFifoOpen`. A later minor version adds `openatAs task …`, answering `SyscallOutcome`.
- **Blast radius now:** none.
- **What it costs:**
  - Two functions for one syscall. The old one stays a trap. This is the half-migrated state that the gospel says to finish.
  - Whether an open sleeps depends on the schedule (A2: has the partner opened yet?). So the old function's refusal would come and go between runs of the same program. Under PawPrint a refusal aborts the run. A schedule-dependent abort is the kind of flakiness this project exists to remove.
  - It does nothing for Darwin's `O_EXLOCK` (M1).
- **Reversibility:** high. Nothing breaks.
- **Information kept:** less. The refusal discards the fact that the call would sleep, and on what.

### Option C: the client holds the pending open (listed to reject)

- `openat` answers `Opened fd | Failed errno | Pending of PendingOpen`. `PendingOpen` is an opaque token naming the reserved descriptor and the description. The kernel records no park. The client asks `PendingOpen.ready system`, and calls `completeOpen` when it holds.
- **Structurally different:** the wait lives outside the task table, like the in-process blocks the README leaves to clients (`futex`, `__psynch`).
- **Why reject it.** Every other sleeping call is a park:
  - `UnixWait.wakes` decides wakes over parks;
  - `SignalDeliverable`, `SyscallInterruption` and the restart rules run over parks;
  - PawPrint's deadlock report reads parks.

  A pending open would be invisible to all of these. The client would have to reimplement M4's signal rules, which differ by flavour.

## 6. How a FIFO's open file description is represented

### Option R1: reuse `OpenFileTarget.Pipe`, with `PipeOrigin.Fifo of inode` and `PipeEnd.Both`

- The FIFO's channel is a `PipeState` in the pipe table, with `Origin = PipeOrigin.Fifo inode`. A description is `Pipe (pipeId, end)`.
- **`O_RDWR`** needs a third end, `PipeEnd.Both`. Every match on `PipeEnd` (59 mentions) gains an arm that an anonymous pipe never reaches.
- **Linux's poll snapshot (C1)** belongs to the description. `Pipe of PipeId * PipeEnd` has no room for it, and a field added to that case later breaks clients. So it would go in a side table keyed by description.
- **Darwin (H1–H3).** `PipeState.Buffer` is a `PipeBuffer`, and Darwin's `PipeBuffer` follows Darwin *pipe* rules (512 bytes, growing to 65536). A Darwin FIFO would need a second buffer kind inside `PipeState`. Otherwise it gets the wrong capacity.
- **Gains:** every pipe path (read, write, poll, epoll, the blocking transfers) works unchanged for a Linux FIFO.
- **Blast radius:** `PipeOrigin` +1 case (35 mentions), `PipeEnd` +1 case (59 mentions), and a new buffer kind.
- **Reversibility:** poor. `PipeEnd.Both` is public, and so would be the claim that a FIFO is a pipe.

### Option R2: a new `OpenFileTarget.Fifo of inode : InodeNumber * attachment : FifoAttachment` (recommended)

- `inode` is public and certain: it is the identity, `fstat`'s source, `fchmod`'s target and the `flock` key (E1–E5).
- `FifoAttachment` has a **private representation**, with readers where a client needs one. On Linux it would hold the `PipeId` of the channel and C1's snapshot. On Darwin it would hold whatever the `AF_UNIX` stream model offers. Its contents can change in any minor version.
- **`O_RDWR`.** The ends come from `OpenFileDescription.AccessMode`, which every description already has. No `PipeEnd` is needed, and `PipeEnd` stays `Read | Write`: "which end of an anonymous pipe".
- **Linux sharing.** The Linux arms of read, write and poll call the existing pipe functions on the attachment's `PipeId`, for whichever ends the access mode grants. "Is a reader open" must then count `Fifo` descriptions with read access as well as `Pipe (_, Read)`. That is one function, `ObjectLifetime`'s or `PipeState`'s.
- **Blast radius:** one `OpenFileTarget` case (about 90 mentions in 15 library files, 1 in PawPrint). Most join an or-pattern with `Pipe` or `File`. The rest throw while the case is reserved.
- **Reversibility:** good. The opaque attachment is the part most likely to be wrong, and it can change freely.
- **Information kept:** more than R1. The kind of object is in the type, and nothing claims that a Darwin FIFO is a pipe.

### Recommendation for §6: R2

M6 decides it. The description differs from a pipe's in five ways, and on Darwin the buffer differs too. R1 would put all of that into a case that anonymous pipes share.

## 7. The park, the primitive, and what can be reserved now

**The park.** `ParkedSyscall.FifoOpen of ParkedFifoOpen`, where:

```fsharp
type ParkedFifoOpen =
    {
        /// The open file description the call made, and holds while it sleeps,
        /// so that it counts as an open end of its kind (A2, D1).
        Opener : OpenFileDescriptionId
        /// The descriptor number reserved for it, which the finishing call installs (I1-I6).
        Descriptor : int
        /// How many partner opens the FIFO had seen when the call slept (M3).
        PartnerOpens : int64
    }
```

- The record is the payload, not tuple fields. A receiving client is unaffected if a field is *added* later, because F# reads record fields through properties. Only removing or retyping a field breaks it. Clients never build parks.
- `ParkedSyscall.descriptions` returns `[ Opener ]`.
- `Restarts` needs no field: the client re-issues the call with its own arguments, as for every other call.

**The primitive.** `WakePrimitive.FifoPartnerOpened of opener : OpenFileDescriptionId * opens : int64`:
- It holds once the FIFO that `opener` names has seen more partner opens than `opens`.
- The partner's kind comes from the opener's access mode. `O_RDWR` never sleeps (C4), so it needs no rule.
- The fields follow `PipeReadWhileNonBlocking` exactly: the description the call holds, and a count. Tuple fields cannot grow, so they must be right now. I think they are, given M2 and M3.

**What to reserve, and how certain each is:**

| type | case | case certain? | fields certain? | unreachable because |
| --- | --- | --- | --- | --- |
| `InodeContent` | `Fifo of permissions : PermissionBits` | yes (audit §2.1) | yes: twelve bits (G2, G4), `chmod` applies (E5); the channel stays out (M7) | `mknodat(S_IFIFO)` answers `MkNodRefusal.Fifo` |
| `DirectoryEntryKind` | `Fifo` | yes | no fields; `DT_FIFO` is 1 on both | no inode holds the content |
| `OpenFileTarget` | `Fifo of inode : InodeNumber * attachment : FifoAttachment` | yes, under R2 | `inode` yes. `FifoAttachment` is opaque, so it may change | no FIFO inode exists to open |
| `ParkedSyscall` | `FifoOpen of ParkedFifoOpen` | yes (M1) | the record can grow. `Opener` rests on M2, `Descriptor` on I1, `PartnerOpens` on M3 | `openat` never parks |
| `WakePrimitive` | `FifoPartnerOpened of opener : OpenFileDescriptionId * opens : int64` | yes | yes, given M2 and M3 | nothing parks in a FIFO open |
| `PipeOrigin`, `PipeEnd` | none | — | — | unchanged under R2 |

**Showing they are unreachable.**
- #1849 added `VirtualFileSystemDefect.ReservedContent`, so `checkInvariants` reports any inode holding reserved content. It will report `InodeContent.Fifo` with no change.
- The description, the park and the primitive need the same: a `FileDescriptorRegistryDefect.ReservedTarget` and a `UnixSystemDefect.ReservedPark`, each named for *any* reserved case, as `ReservedContent` is. That way they need not be removed when FIFOs land.
- The fuzzers that already run `checkInvariants` then check the claim.
- **A mutation check:** let `mknodat(S_IFIFO)` succeed, and the inode defect fires.

**Not reserved.**
- `OpenRefusal` cases (refusals grow freely).
- A `Dup2Refusal` case for Darwin's waiting `dup2` (likewise).
- `Syscall` cases for `open` and `openat` (clients only build `Syscall`).
- A park for Darwin's `O_EXLOCK` open. It is likely, but its fields (the lock mode, and `FlockGrantable`'s requester) wait for that design. It is a separate case, not a second use of `FifoOpen`.

## 8. Recommendation

- **A** for the shape. Patrick prefers it. It also wins on the merits: B's refusal depends on the schedule, and C hides the wait from everything that reads parks.
- **R2** for the description.
- Reserve the five cases of §7.
- Keep `SyscallOutcome` as the answer type.

## 9. PR breakdown

Each PR is one feature. P1–P4 are release work. Each adds cases or changes a signature, and none adds behaviour, so the existing suite is the oracle, plus the defects of §7. Run the Guest fixtures for P1 and P2, since PawPrint changes.

**Release work.**
1. **P1: reserve the FIFO inode cases** (audit R2, a copy of #1849).
   - `InodeContent.Fifo of permissions : PermissionBits` and `DirectoryEntryKind.Fifo`.
   - `fileTypeBits` gives `0o010000`.
   - PawPrint's `DirectoryEntryPal.nodeType` gains `DT_FIFO` (1), checked against the pinned `Interop.ReadDir.cs`.
   - `ReservedContent` already covers it. The PR counts its new throws.
   - Small to medium.
2. **P2: the shape change.**
   - `openPath` and `openat` take the task first and answer `SyscallOutcome`. They never park yet.
   - PawPrint's three sites, with `thread` threaded into `urandomDescriptor`.
   - The README example and rows.
   - The test call sites.
   - Independent of P1. Medium, mechanical.
3. **P3: reserve `OpenFileTarget.Fifo`**, with the opaque `FifoAttachment` (empty for now) and `FileDescriptorRegistryDefect.ReservedTarget`.
   - About 90 arms. Most join an or-pattern. The `read`, `write`, `lseek`, `poll` and `fstat` arms throw, naming the case.
   - PawPrint's `SignalDispatch.fs:524` gains a line.
   - Medium.
4. **P4: reserve `ParkedSyscall.FifoOpen` and `WakePrimitive.FifoPartnerOpened`**, with `ParkedFifoOpen` and `UnixSystemDefect.ReservedPark`.
   - `ParkedSyscall.descriptions` and `WakeCondition.ofPark` get real arms; they are total and cheap.
   - PawPrint's six `ParkedSyscall` matches each gain a failing arm.
   - Small to medium. Could merge with P3 if review prefers one "FIFO open types" PR.

**Behaviour, not release work** (in order; each one feature):
5. **`O_NONBLOCK` at open**, for every kind open can name today. The description's `NonBlocking` is already modelled for `fcntl`. Retire the `UnmodelledOpenFlag.NonBlocking` refusal, but keep the case.
6. **Making FIFO inodes:** `mknodat(S_IFIFO)`, `mkfifo` and `mkfifoat` on both flavours (G1–G12). Also `stat`, `readdir`, `chmod`, `rename` and `unlink` of them. Opening one stays refused, by a new `OpenRefusal` case. PawPrint dispatches `SystemNative_MkFifo`.
7. **Linux FIFO opens and transfers**, over the pipe machinery:
   - the non-blocking rules and `O_RDWR`;
   - the park, `finishOpen` and the reserved descriptor (with `dup2` EBUSY);
   - C1's poll snapshot;
   - the inode's timestamps, `fstat` and `FIONREAD`.

   Every row of the probe is a literal in the test. Host-equality tier for `fstat` and capacity.
8. **Darwin FIFOs**, after the `AF_UNIX` stream socket model:
   - the 8192-byte channel;
   - the poll and `FIONREAD` rows;
   - EINTR under `SA_RESTART`;
   - the waiting `dup2` refused.

   Until then, P6's refusal stands on Darwin.

## 10. Questions for Patrick

1. **R2 over R1?** It is a new `OpenFileTarget` case with an opaque attachment, so a Darwin FIFO is never a pipe.
2. **M2:** may the sleeping open make its description before it sleeps, and hold it in the park? That is what makes `ParkedFifoOpen.Opener` and the primitive's first field certain. The alternative is to count ends from parks as well as descriptions. That makes every "is an end open" question read the task table.
3. **Reserve the park and the primitive now (P4), or leave them to the minor-version policy?** Their fields look certain to me, and PawPrint covers `ParkedSyscall` case by case in six places. But the behaviour is post-1.0, and I may be wrong about the snapshot.
4. **`SyscallOutcome`, or a dedicated `OpenOutcome`** as `read` and `accept` have? I recommend the former.
5. **Darwin FIFOs:** model them on the `AF_UNIX` stream socket work (P8), or refuse a Darwin FIFO open through 1.x? Under R2 neither choice changes a public type.

## Decision (orchestrator, 2026-10-11)

- **Shape A and description R2.** Patrick decided the shape changes before 1.0. R2 over R1 because the measurements say a FIFO is not a pipe on either flavour: Darwin's holds 8192 bytes where its pipe holds 65536, and Linux's poll state (no `POLLHUP` until a writer has opened) belongs to the description.
- **Q2: yes.** The sleeping open creates its description before it sleeps and the park holds it. That is what was measured: while it sleeps, the opener counts as an open end and its descriptor number is taken.
- **Q3: reserve the park and the primitive now** (P4). Their fields follow from Q2 and from the measured wait for a count change, so they are as certain as the cases.
- **Q4: `SyscallOutcome`.** `openat` and `openPath` answer a `SyscallAnswer` today, and `SyscallOutcome`'s `Restarts` is what Linux does under `SA_RESTART`.
- **Q5:** a Darwin FIFO open stays refused until the `AF_UNIX` stream work models what Darwin builds it on. A refusal that later becomes an answer is the ordinary path under the union policy.
- Order: P2 (the shape change) first, as the largest; P1, P3 and P4 after, one at a time, beside R3 and R4.
