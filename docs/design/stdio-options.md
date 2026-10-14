# Pipes and the standard streams in WoofWare.PosixKernel

*Options document, 2026-09-26. Part of the "PosixKernel knows nothing of the CLR" workstream. Code references are at `origin/main` `ff8c21c3`, which includes #1578 (`epoll_ctl`). Probes, raw output and the model checker are in [`stdio-raw/`](stdio-raw/) beside this file (copies of the scratchpad's `stdio/`). It builds on the waiting redesign ([`waiting-options.md`](waiting-options.md), design B) and the signals redesign ([`options.md`](../pawprint-signals-research/options.md), design B and its §7 decisions).*

## 1. What there is today

Every claim in the re-audit holds. Details follow.

### The library

| piece | where | whose fact? |
| --- | --- | --- |
| `FileDescriptorRole = StandardInput \| StandardOutput \| StandardError` | `FileDescriptorRegistry.fs:10` | **the harness's**: a role is how the launcher wired fds 0–2. It is not a kernel object. |
| `OpenFileObject.StandardStream of role` and `OpenFileTarget.StandardStream of role` | `FileDescriptorRegistry.fs:249`, `:463` | a pipe end whose pipe does not exist. The prose says "modelled as a pipe" in about a dozen places, but no pipe state backs it. |
| `FileDescriptorRegistry.initial` hard-codes three distinct descriptions (`O_RDONLY` / `O_WRONLY` / `O_WRONLY`), with ids 0–2, and `NextId = 3` | `FileDescriptorRegistry.fs:751` | **the harness's launch shape**. The docstring says so and rejects the tty shape. No other shape can be expressed. |
| stdin: `ReadTarget.Stdin` answers end of file at once, without touching the buffer | `UnixReadWrite.fs:264`, `:345` | the pipe's writer is closed and the pipe holds no bytes. The client cannot change either. |
| stdout/stderr: `write` appends `{Role; Bytes}` to `UnixProcessState.OutputLog`, and is "never short and never `EINTR`" | `UnixReadWrite.fs:595`, `:677`, `:711`; `UnixProcess.fs:39` | **the harness's**: a reader with infinite capacity that never goes away. It never returns EAGAIN or EPIPE. |
| `OutputLogEntry.bytesFor`, documented as "used by tests" | `FileDescriptorRegistry.fs:1826`, `:1839` | test and client convenience living in the kernel |
| `fstat` refused (`FStatRefusal.StandardStream`) | `UnixPathResolution.fs:104`, `:438` | limit of the model: there is no pipe to report on |
| setting `O_NONBLOCK` refused (`SetNonBlockingRefusal.UnmodelledOnStandardStream`); clearing it answered | `UnixSocket.fs:221`, `:529`; defect `FileDescriptorRegistry.fs:1312` | see §3.1: this refusal is stricter than it needs to be |
| `lseek` ESPIPE, `posix_fadvise` ESPIPE, `ftruncate` EINVAL, `pread`/`pwrite` ESPIPE-or-EBADF ties, Darwin `flock` refused, `fstatfs` pipefs magic (Linux) or EINVAL (Darwin) | `UnixDescriptor.fs:368`, `:687`, `:620`, `:63`/`:798`; `UnixReadWrite.fs` pread/pwrite arms; `EmulatedFileSystemType.fs:221` | **kernel** facts about pipes, each already measured. They are correct once a pipe exists. |
| readiness: stdin is `HUP`, stdout/stderr are `OUT\|WRNORM`, as constants | `UnixPoll.fs:91-102` (`LinuxReadiness.ofDescription`, shared by `poll` and epoll since #1578) | constants of the launch shape. Nothing produces a change, because nothing can change. |
| epoll registration of a stream is allowed | `UnixPoll.fs` (the #1578 ladder) | kernel |
| no pipe object, no `pipe(2)`/`pipe2`, no `FIONREAD`, no `F_GETPIPE_SZ` | — | missing |
| no byte buffer anywhere: sockets carry no data either | `FileDescriptorRegistry.fs` `SocketPhase` | a pipe would be the first object with bytes in flight |

### PawPrint's use of it

| site | what it does |
| --- | --- |
| `SystemNative_Write` (`NativeSystemNative.fs:5626`) | after the kernel appends to `OutputLog`, it emits `StepEffect.WroteToFd (role, bytes)` (`IlMachineStateModel.fs:555`) when the fd's target is a `StandardStream` |
| `PawPrint.App` (`App/Program.fs:170-230`, `:322`) | streams each `WroteToFd` to the host's stdout or stderr and flushes it. `drainRemaining` covers writes made before the stepping loop starts. A `StandardInput` entry is a `failwith`. |
| `DebuggerServer.fs:698`, `EmulatedKernel.fs:738` | read `OutputLog` |
| tests | 30 `OutputLog`/`bytesFor` sites in `WoofWare.PawPrint.Test` (11 in `TestImpureCases`, 4 in `TestStepEffectStreaming`), 4 in the library's tests |
| `SystemNative_IsATty` (`NativeSystemNative.fs:5497`) | answers 0, with ENOTTY for a live fd and EBADF otherwise. **The logic is the kernel's** (what `isatty(3)` says about an object), but it lives in PawPrint. |
| `SystemNative_InitializeTerminalAndSignalHandling` (`:5724`) | does not ask the kernel `tcgetattr(0)`. The real shim does, and that call is how it decides it has no tty. |
| `SystemNative_FStat` refusal text (`:948`) | says the BCL reaches `FStat` on a stream only through a hand-rolled P/Invoke. True for 0–2. But `PipeStream.ValidateHandleIsPipe` fstats **any** pipe handle and demands `S_IFIFO`, so in-process pipes will need `fstat`. |
| `RealRuntime` (`RealRuntime.fs:230`, `:266`) | the oracle's launch shape: three redirected pipes, with stdin's writer closed at once. That is exactly what `initial` models, and what lets `sourcesPure/FileStreamHandleSeeded.cs` assert stdin EOF differentially. |

### What the BCL does with the streams (read at the pinned runtime)

- **Writing.** `Console.Out` is `StreamWriter(bufferSize 256, AutoFlush = true)` over `UnixConsoleStream`. So each `WriteLine` is one `Write`.
- **The write loop.** `ConsolePal.Unix.Write` loops over short writes, **swallows EPIPE** ("pretend we were successful"), and answers EAGAIN with `poll(POLLOUT, -1)` before retrying.
- **Why bit-identity needs whole writes.** Each extra round of that loop runs more guest instructions, which changes the schedule. So every stdout write must complete in full, in one call, for guest behaviour to stay bit-identical.
- **Reading.** A redirected `Console.In` is `StreamReader` over `ConsolePal.Read`, which calls `SystemNative_Read` and throws on any error, EAGAIN included.
- **Terminal setup.** `EnsureConsoleInitialized` calls `IsATty` on 0 and 1. If either is a tty, it reads the terminfo database, `SetKeypadXmit`, `tcgetattr` and friends. So a tty launch shape is a large BCL surface.
- **`System.IO.Pipes` on Unix** creates pipes with `SystemNative_Pipe(O_CLOEXEC)`. It validates handles with `fstat` (`S_IFIFO` or `S_IFSOCK`) and reads `F_GETPIPE_SZ` for `InBufferSize`. It moves data by wrapping the fd in a `Socket`, whose `Receive` and `Send` fall back to `read`/`write` on a non-socket.
- **CoreCLR's own pipes.** It makes some: the signal shim's self-pipe (`pal_signal.c:40`; signals Q3) and a transient pipe per thread created suspended (`pal/src/thread/threadsusp.cpp:71`). PawPrint models neither.

## 2. Measured facts

**Machines.** Linux 6.18.5 aarch64 (Apple `container` VM, `gcc:14`, root; **not x86-64**, 4 KiB pages). Darwin 27.0.0 arm64 (uid 501). Every probe has `alarm()` and bounded loops. Where a result was checked by a model rather than read off, the row says so.

**How the buffer rows were checked.** `trace.c` runs 200 seeds × 300 random non-blocking reads and writes per flavour, twice: once at a normal fill level and once biased towards full. It records every result, `FIONREAD`, the `poll` of both ends and `st_size`. `model.py` then replays the 240,000 rows against candidate models.

| # | fact | Linux | Darwin | raw |
| --- | --- | --- | --- | --- |
| 1 | `PIPE_BUF` (`fpathconf`) | 4096 | **512** | [capacity](stdio-raw/out/capacity.linux.txt) / [capacity](stdio-raw/out/capacity.darwin.txt) |
| 2 | capacity | 64 KiB, but **as 16 page slots, not as bytes**: filling with 3-byte writes stops at 65520, 100-byte at 64000, 513-byte at 57456, and 4097-byte at **45066** | 64 KiB of bytes (3-byte writes stop at 65535) | same |
| 3 | the buffer rule, checked on 120,000 rows per flavour | **exact**: a write merges its `n mod 4096` remainder into the last slot if it fits, then takes whole new slots. A read frees a slot only when the slot is empty. POLLOUT means a free slot, not free bytes. A byte-counting model diverged on every seed. | **exact**: the buffer **grows** (512…16 KiB, then 64 KiB) when a write does not fit, and never shrinks. Writes behave like a 64 KiB byte ring, but **POLLOUT means `max(16384, size) − count ≥ 512`**. So a pipe that holds 16000 bytes and has never held more than 16 KiB is not writable-ready, and one more write *adds* POLLOUT. A fixed-64 KiB model diverged on 7 and 11 seeds. | [trace](stdio-raw/out/trace.linux.txt), [full](stdio-raw/out/trace-full.linux.txt) / [trace](stdio-raw/out/trace.darwin.txt), [full](stdio-raw/out/trace-full.darwin.txt); [model.py](stdio-raw/model.py) |
| 4 | `PIPE_BUF` atomicity and short writes (non-blocking) | a write of at most 4096 bytes is all-or-nothing (EAGAIN). A larger one takes whatever slots are free: a short write, or EAGAIN if none. A non-blocking 1 MiB write into an empty pipe returns 65536. | at most 512 bytes is all-or-nothing. A larger one takes `min(n, free)`. 1 MiB returns 65536. | rows 2–3 |
| 5 | `F_SETPIPE_SZ` / `F_GETPIPE_SZ` | rounds up to a power-of-two number of pages, minimum 4096. `-1` gives EINVAL. Above `pipe-max-size` (1048576) the answer is **EPERM even for container root**, so `CAP_SYS_RESOURCE` is unmeasured. Shrinking below the bytes held gives EBUSY. It works through either end. | no such fcntl | [capacity](stdio-raw/out/capacity.linux.txt) |
| 6 | empty pipe, writer open | blocking read waits and returns the 3 bytes that arrive (202 ms). Non-blocking read: EAGAIN. | same (205 ms), EAGAIN (35) | [states](stdio-raw/out/states.linux.txt) / [states](stdio-raw/out/states.darwin.txt) |
| 7 | writer closed | EOF (0), after any data. Reads of 2 over 3 bytes return 2, 1, 0. A blocked reader wakes with 0 when the writer closes. | same | states, [sigpipe](stdio-raw/out/sigpipe.linux.txt) |
| 8 | partial reads, and zero-length reads | a read returns what is there, up to the count, and does not wait to fill the buffer. Writes of 5, 5 and 5 bytes read back as one 15-byte read: no message boundaries. `read(fd, buf, 0)` returns 0 even when the pipe is empty and a writer is open. `read(NULL, 10)` on an empty pipe gives EAGAIN, not EFAULT. A bad pointer with data held gives EFAULT, and the data stays. | same | states |
| 9 | signal during a blocked read | EINTR without `SA_RESTART`; restarted with it | same | states |
| 10 | write with the reader closed | **EPIPE and SIGPIPE**. The signal is delivered before `write` returns. EPIPE wins over EAGAIN (full, non-blocking) and over EFAULT (bad pointer). | same | [sigpipe](stdio-raw/out/sigpipe.linux.txt) / [sigpipe](stdio-raw/out/sigpipe.darwin.txt) |
| 10a | a **zero-length** write with the reader closed | **returns 0, and no signal** | **EPIPE and SIGPIPE** | same |
| 10b | **who receives SIGPIPE** when a worker thread writes | the **writing thread** (thread-directed) | the **main thread** (process-directed) | same |
| 10c | the reader leaves during a blocking 200000-byte write | returns the **partial count** (65536) and sends SIGPIPE | returns **−1 EPIPE**, and the partial count is lost | same |
| 10d | SIGPIPE ignored | EPIPE only | EPIPE only | same |
| 10e | SIGPIPE ignored *and* blocked | the signal stays pending | discarded (matches `blockedIgnoredSignalStaysPendingUnder`) | same |
| 10f | per-descriptor opt-out | none for pipes | `F_SETNOSIGPIPE`: EPIPE and no signal, even under `SIG_DFL` | same |
| 11 | `fstat` of a pipe | `S_IFIFO\|0600`, nlink 1, the creator's uid/gid, size **0 always**, blksize 4096, blocks 0, dev `0xc` (pipefs; this boot's), **one ino shared by both ends**, handed out sequentially per pipe (2084, 2085). Timestamps stay at creation: a write and a read moved none. | `S_IFIFO\|0660`, nlink 0, uid/gid, **size = unread bytes on both ends**, blksize 16384, blocks 0→1 with data, dev 0, **a different random 64-bit ino per end**. A write moves mtime and ctime on both ends; a read moves atime on the read end only. | states |
| 12 | `FIONREAD` | the bytes held, on **both** ends | the bytes held on the read end; 0 on the write end | states, traces |
| 13 | `poll` levels, both ends open | read end: `IN\|RDNORM` iff non-empty. Write end: `OUT\|WRNORM` iff a slot is free. | read end: `IN\|PRI\|RDNORM\|RDBAND` (0xc3) iff non-empty. Write end: `OUT\|WRBAND` (0x104) per row 3. | states, traces |
| 13a | …with the other end closed | read end: `HUP`, plus `IN\|RDNORM` if data remains. Write end: `ERR` (even for `events = 0`), plus `OUT\|WRNORM` if a slot is free. | **both ends: `IN\|PRI\|RDNORM\|RDBAND\|HUP` (0xd3)**, and the write end loses OUT | states |
| 14 | `isatty`, `tcgetattr`, `TIOCGWINSZ` on either end | ENOTTY (25) | ENOTTY (25) | states |
| 15 | `lseek` on either end | ESPIPE for whence 0–4. **An invalid whence (99) gives EINVAL**: the whence is checked first. | ESPIPE for every whence, 99 included | states |
| 16 | `pipe`/`pipe2` | fds are the lowest free. `pipe2` accepts `O_CLOEXEC`, `O_NONBLOCK` and `O_DIRECT` (packet mode). `O_NOTIFICATION_PIPE` gives ENOPKG in this kernel's build. Any other flag: EINVAL. A bad pointer gives EFAULT. | **`pipe2` exists in Darwin 27's libc**, with `O_CLOEXEC` and `O_NONBLOCK`; any other flag gives EINVAL. **`pipe(bad ptr)` segfaults in libc**, because libc stores the fds itself. | states, [pipe2probe](stdio-raw/out/pipe2probe.darwin.txt) |
| 17 | `flock` on a pipe | the pipe is the contention key: `LOCK_EX` on the read end blocks it on the write end; another pipe is free | ENOTSUP (45) on every pipe | [flockpipe](stdio-raw/out/flockpipe.linux.txt) / [flockpipe](stdio-raw/out/flockpipe.darwin.txt) |
| 18 | launch shapes seen from the child (`shapes.sh`) | see below | see below | [launch](stdio-raw/out/launch.linux.txt) / [launch](stdio-raw/out/launch.darwin.txt) |

**Row 18, launch shapes.** Both flavours agree except for the poll levels.

- **Redirected pipes** (the harness and `RealRuntime` shape): three distinct descriptions, accmode 0/1/1, `S_IFIFO`, `lseek` ESPIPE. A non-blocking read of the empty stdin gives **0**, not EAGAIN, because its writer is gone. `write(0, _, 0)` gives EBADF.
- **stdin at `/dev/null`**: `S_IFCHR`, `lseek` **succeeds**, so `FileStream(fd 0).CanSeek` would flip. Linux polls it as `IN|OUT`; **Darwin's `poll` answers POLLNVAL for `/dev/null`**. `tcgetattr` is ENOTTY on Linux and ENODEV on Darwin.
- **stdin a regular file**: seekable, and reads the file.
- **stdin closed**: fd 0 is absent, and the first `open` gets fd 0.
- **`2>&1`**: fds 1 and 2 share a description.
- **A terminal**: one shared `O_RDWR` description on 0–2, `isatty` 1, and a non-blocking read gives EAGAIN.

**Consequences worth stating:**

- **Linux needs the slot structure.** It shows through capacity, short writes and POLLOUT; a byte count cannot reproduce it. **Darwin needs a size field**, and it shows through POLLOUT alone. Both rules are small, and the checker holds both exactly.
- **SIGPIPE goes through the signals library, per flavour.** Linux sends it to the writing thread. Signals design B refuses a thread-directed signal to a non-main thread, but PawPrint's startup dispositions ignore SIGPIPE (signals §7). An ignored, unblocked signal is discarded at generation, so no delivery is ever needed. A guest that installs a SIGPIPE handler and writes from a worker thread is the one case that meets design B's refusal.
- **The launch shape is visible through the BCL**, not only through raw syscalls: `CanSeek` differs between a pipe and `/dev/null`, and `IsATty` decides whether terminfo is read. A tty is a large surface.

## 3. What every design shares

### 3.1 A fix available now, whichever design is chosen

The `O_NONBLOCK` refusal on streams (`UnixSocket.fs:529`) guards against a stored flag that no transfer honours. But in today's launch shape **no stream transfer can block**:

- stdin's writer is closed, so a read returns 0 with or without the flag (row 18, measured);
- the output reader never lets its pipe fill.

So honouring the flag is vacuous, and storing it is honest. `F_GETFL` then reads it back, as it would for real. This lifts a refusal a guest can reach through `fcntl` with no model change, and it removes the defect at `FileDescriptorRegistry.fs:1312`.

### 3.2 The far ends belong to the client

The other end of each standard stream is held by whoever launched the process. For PawPrint, that is PawPrint. No design makes the client a process in the kernel. It is an *external holder* of a pipe end, with a behaviour given as data:

- **For a read end the client holds:**
  - `Drained`: a reader that takes every byte the moment it is written. The pipe never holds bytes, so writes are never short, never EAGAIN, and POLLOUT always holds. **This is today's `OutputLog` semantics, exactly.**
  - `Gone`: the reader has closed. Writes get EPIPE.
- **For a write end the client holds:**
  - `Supplied of bytes`: equivalent to the launcher making one blocking `write(all)` and then `close()`. Today's stdin is `Supplied empty`.
  - `Fed`: the client calls `feed` and `closeInput` itself, and readers park in between.

A bounded, client-paced reader (`Paced`) is possible, but it adds an axis of schedule exploration. That is question 1 in §6.

### 3.3 Keeping guest behaviour bit-identical

- **Default launch configuration.** It is today's: `Supplied empty` on fd 0, `Drained` on fds 1 and 2, three distinct descriptions with the same access modes.
- **Answers already given do not change.** Every answer today's model gives is one this configuration gives too: EOF, whole writes, `HUP`/`OUT|WRNORM`, ESPIPE, and the rest.
- **What does change is refusals becoming answers.** `fstat`, `O_NONBLOCK`, `FIONREAD` and `tcgetattr` go from refused to answered, and no passing guest currently reaches any of them.
- **No startup pipes.** Nothing opens a pipe at startup unless signals Q3 is answered that way, so fd numbering is unchanged.
- **The log stays identical.** The ordered log of bytes delivered to `Drained` readers equals today's `OutputLog` entry for entry, when each endpoint is labelled with its role. That is a property test in every design.

## 4. Designs

### A. A pipe object, `pipe2`, and a launch table (recommended)

**State.**

```fsharp
type PipeId                                         // like SocketId: identity, never guest-visible
type PipeEnd = Read | Write
type PipeBuffer =                                    // each flavour's measured rule (row 3)
    | LinuxSlots of slots : Slot list * maxSlots : int          // Slot = { Bytes; Offset }
    | DarwinGrowing of bytes : ByteQueue * size : int
type ExternalReader = Drained of EndpointId | Gone
type ExternalWriter = Supplied of EndpointId * remaining : ImmutableArray<byte> | Fed of EndpointId | Closed
type PipeState = {
    Buffer : PipeBuffer
    ExternalReader : ExternalReader option
    ExternalWriter : ExternalWriter option
    CreatedBy : UserId * GroupId; CreatedAt : Timestamp; ... }   // for fstat
// UnixMachineState.Pipes : Map<PipeId, PipeState>
// OpenFileTarget.Pipe of PipeId * PipeEnd;  OpenFileObject.Pipe of PipeId   (row 17: one key for both ends)
```

**What each end's holders are.** They are *derived* from the descriptor table plus the external holder, never counted separately, as sockets already are. "Writer closed" means that no description names the write end and there is no open external writer.

**The launch table** is `Map<int, LaunchDescriptor>` passed to `UnixSystem.initial`. `LaunchDescriptor` is one of:

- `PipeFromClient of ExternalWriter`, or `PipeToClient of ExternalReader`;
- `SameDescriptionAs of fd`, for `2>&1`;
- `Absent`, for a closed stdin, so that the first `open` gets fd 0.

A file, `/dev/null` and a terminal are refused as launch descriptors (see C).

**The delivered log.** `UnixProcessState.OutputLog` becomes `UnixMachineState.Delivered : (EndpointId * bytes) list`, in delivery order. It is the bytes the outside world received.

- `EndpointId` is the client's own label: PawPrint maps it to `FileDescriptorRole`, which moves to PawPrint.
- `bytesFor` moves to PawPrint.
- `WroteToFd` is emitted when a write *delivered* to an endpoint. It is keyed by the write's endpoint, not by the fd's target kind.

**API.**

- `pipe2 flags`. Linux: `O_CLOEXEC`, `O_NONBLOCK`, and `O_DIRECT` refused (packet mode is unmeasured). Darwin: `O_CLOEXEC` and `O_NONBLOCK`. Other flags: EINVAL.
  - `O_CLOEXEC` needs a per-descriptor flag that does not exist yet. Add it, or refuse the flag until `F_GETFD` is modelled.
  - Darwin `pipe(bad)` faults in the client's libc, so the client refuses it before the kernel sees it.
- `read` and `write` on either end, with rows 2–10 as data.
- `close`, which reaps a pipe when neither end has a holder.
- `fstat`, `FIONREAD`, and Linux `F_GETPIPE_SZ`/`F_SETPIPE_SZ`. `pipe-max-size` is a sysctl, so it goes in `KernelConfig`.
- `isatty` and `tcgetattr`, which answer ENOTTY for every object the kernel models and EBADF for no object. These move out of PawPrint.
- For the client: `feed endpoint bytes`, `closeInput endpoint`, and `Delivered`.

**Blocking.** A blocking read of an empty pipe returns `WouldBlock (DescriptorReady (description, IN))`, the primitive the waiting design already plans for `poll`.

- **A blocking write of more than fits:**
  - **Linux** keeps a partial effect (row 10c), so the park record carries the bytes still to write and the count done. The write finishes with the count, or EPIPE if nothing was written.
  - **Darwin** has the same park record, but a reader leaving answers EPIPE whatever was written.
- **An interrupting signal** answers EINTR or restarts (row 9), which is signals stage 6 in the algebra (`SignalDeliverable`).
- `Drained` and `Supplied` never make the guest park.

**Refused, each with a typed refusal:**

- Packet mode (`O_DIRECT`);
- `F_SETPIPE_SZ` above the limit when privileged (`CAP_SYS_RESOURCE` is unmeasured);
- EPIPE while no disposition table exists: until signals stage 3 there is nothing to say whether SIGPIPE kills, so a write to a pipe with no reader is refused;
- a SIGPIPE handler delivered to a Linux worker thread, which is design B's own refusal;
- the `fstat` fields that are this machine's rather than the kernel's (question 3);
- a Darwin `poll`, as today.

**Tests and oracles.**

- **Reference models.** Port `model.py`'s two classes as naive F# references. Property: the implementation equals the reference over random operation sequences, including closes and `F_SETPIPE_SZ`.
- **Corpus.** Check in the 240,000 recorded kernel rows and replay them. That covers each flavour's column wherever the suite runs.
- **Live host differential.** `trace.c`'s operations through P/Invoke `pipe`/`read`/`write`/`poll`/`ioctl`, in `WoofWare.PosixKernel.Test` behind a host check. That is Linux in CI and Darwin locally, as `TestVirtualFileSystemAgainstHost` does.
- **Invariants in `checkInvariants`:**
  - no pipe without a holder;
  - FIFO byte order (the traces also check this);
  - Linux slots ≤ max and every slot's bytes ≤ 4096;
  - a Darwin size in the block table;
  - a `Drained` pipe always empty.
- **The §3.3 log-equality property.**
- **Guest tests:**
  - `sourcesPure` for `Console.ReadLine` over supplied stdin, with `RealRuntime` writing the same bytes before closing;
  - `sourcesImpure` for raw `pipe2`, `fstat` `S_IFIFO`, and blocking between two guest threads.

**Blast radius.** In the library, 64 `StandardStream` mentions become `Pipe` arms:

- files: `FileDescriptorRegistry`, `UnixReadWrite`, `UnixPoll`, `UnixDescriptor`, `UnixSocket`, `UnixPathResolution`, `EmulatedFileSystemType`, `UnixConnection`, `UnixSystem`;
- the `OutputLog` field and `initial` change shape;
- 14 plus 4 mentions in the library's tests.

In PawPrint:

- the write handler's effect, `IsATty`, the `FStat` message, `EmulatedKernel.OutputLog`, the App and the `DebuggerServer`;
- 30 test sites, which are mechanical if PawPrint keeps a `bytesFor role` view;
- `TestFileSystemTypePal` and `TestPollEventsPal`.

It is roughly the size of the socket table's introduction.

**Moving on to C is additive.** A device or FIFO inode is a new `OpenFileTarget` case, and a new `LaunchDescriptor` case where the launch table refused one.

### B. Keep `StandardStream`, give it pipe semantics per role

**State.**

- `OpenFileTarget.StandardStream of role` stays.
- `UnixProcessState` gains `StandardInput : { Remaining : bytes; WriterOpen : bool }` and `OutputReaderGone : Set<role>`.
- `OutputLog` stays.

**Answers.**

- stdin reads take from `Remaining`, then give EOF, or park or EAGAIN while `WriterOpen`.
- Output writes go to the log whole, or give EPIPE for a gone role.
- `fstat` synthesises each flavour's pipe fields from these, so Darwin's `st_size` is `Remaining`'s length.
- Readiness is computed from the same fields.

**Refused.** `pipe`/`pipe2` and every in-process pipe (`System.IO.Pipes`, the signal self-pipe), and every launch shape but three distinct pipes.

**Tests.** The same guests as A for stdin and EPIPE. No capacity or slot rules exist, so no traces are needed and there is no reference model worth the name.

**Blast radius.** Small: the stdin arm, the write arm, `fstat`, readiness and `initial`'s parameters. PawPrint barely changes.

**Moving on to A is not additive.** A removes every `StandardStream` arm B touched, so B's arms are rewritten. Only B's rule *functions* survive, and only if they are written over a pipe-shaped record. So B is cheap now and paid for twice later. It also keeps harness vocabulary (roles) in the kernel, which is the thing this workstream set out to remove.

### C. A generic stream model: pipes, FIFOs and character devices

**State.** It is A's pipe table, plus two things.

- **Device inodes in the VFS**: `InodeContent.CharDevice of DeviceKind` (`Null | Zero | URandom`, and later `Tty`), each with its measured `st_rdev` and poll levels. Note that Darwin's `poll` on `/dev/null` is POLLNVAL.
- **FIFO inodes (`mkfifo`)**, whose `open` attaches to a pipe object. That brings FIFO open rules: a blocking open waits for the other side; a non-blocking write-open with no reader gives ENXIO. These are unmeasured.

The launch table then names paths as well as pipe ends: stdin `/dev/null`, a file opened `O_RDONLY`, or `O_APPEND` output.

**What it also unlocks.** `SystemNative_GetCryptographicallySecureRandomBytes` on Linux could `open` and `read` `/dev/urandom` through a real device instead of bypassing descriptors, as `NativeSystemNative` does today. That would move fd numbering to match the shim.

**Refused.** A terminal: termios and job control are a design of their own, and the BCL's terminfo path comes with it.

**Tests.** A's, plus FIFO-open sweeps and per-device rows on both flavours.

**Blast radius.** A's, plus the VFS, `open`, path resolution into devices, and `fstat`/`poll` for devices. Roughly twice A, with no current consumer for the extra half.

**Moving on further.** Nothing is left beyond it except the tty.

*Considered and rejected: the client answers external I/O.* Here a write to a client-held end returns an effect description (`WouldDeliver bytes`) and the client decides the result. It is dependency rejection taken to its limit, but it hands the client the pipe rules (capacity, `PIPE_BUF`, EPIPE ordering), and the library could then no longer property-test them. A's `Fed` and `Drained` policies are that idea restricted to the part that belongs to the client.

## 5. Recommendation: A, staged; C only when a consumer appears

A is the only design where "the standard streams" stop being a kernel concept and become what they are: three descriptors onto pipes whose far ends the client holds. It gives in-process pipes, and with them `System.IO.Pipes`, signals Q3's self-pipe, and two-thread blocking tests for the waiting design, from the same object. Its buffer rules are already measured and have exact reference models. B is cheaper, but it is not a step towards A. C's devices and FIFOs add to A with no rework, so they can wait for a guest that needs `/dev/null` or `mkfifo`.

**Stages, each one PR with its own tests:**

0. **Store `O_NONBLOCK` on the streams** (§3.1). Lift `UnmodelledOnStandardStream` and the registry defect. Test with a `sourcesImpure` guest: `fcntl` sets the flag, reads it back, and a non-blocking read of stdin returns 0, as row 18 measured. Independent of the rest.
1. **`PipeBuffer`, alone.** The two flavour rules as a pure module; the F# reference models; replay of the checked-in corpus; properties. No syscall yet.
2. **`pipe2` and non-blocking pipe I/O.**
   - The pipe table, `OpenFileTarget.Pipe`, `read`, `write`, `close`/reap, readiness, `fstat`, `FIONREAD`, `lseek`, `flock`, `fstatfs`, and `isatty`/`tcgetattr` in the library.
   - A blocking transfer that would wait is refused (`WouldPark`, as `poll` does now).
   - EPIPE is refused until stage 5.
   - The live host differential fuzzer lands here.
   - PawPrint: `SystemNative_Pipe`, and `SystemNative_IsATty` routed to the library.
3. **The standard streams become pipe ends.**
   - The launch table goes in `initial`, with `Drained`/`Supplied` external holders; `Delivered` replaces `OutputLog`; `FileDescriptorRole` and `bytesFor` move to PawPrint.
   - Delete `StandardStream` everywhere, then run the whole Guest suite.
   - The §3.3 log-equality property, plus `TestStepEffectStreaming`, pin bit-identity.
   - `InitializeTerminalAndSignalHandling` asks the library for `tcgetattr(0)`.
   - A pure move of vocabulary: rename-only checks where they apply, and `check-docstring-attachment.py`.
4. **Supplied stdin.** `HostConfig` carries stdin bytes, and `RealRuntime` gets a way to write the same bytes before closing. Add `sourcesPure` guests for `Console.ReadLine`, `Console.In.ReadToEnd` and `FileStream(fd 0)`.
5. **EPIPE and SIGPIPE.**
   - Waits for signals stage 3 (the disposition table, with PawPrint's startup `SIG_IGN`). SIGPIPE is generated per flavour (row 10b), and the zero-length and partial rows (10a, 10c) are answered.
   - The `Gone` launch option.
   - A guest that writes to a gone stdout sees `Console.Out` swallow it, as real .NET does. That is differential if `RealRuntime` can close the child's stdout reader.
6. **Blocking pipe transfers.** Waits for waiting stage 2 (`DescriptorReady`): parks, the partial-write park record, `Fed` stdin. Test with a two-thread guest over `pipe2`, and with `AnonymousPipeServerStream` once the socket-from-handle path is answered.
7. **Optional.** Linux `F_GETPIPE_SZ`/`F_SETPIPE_SZ` (`PipeStream.InBufferSize`), Darwin `F_SETNOSIGPIPE`, `O_DIRECT` packet mode. Each only when a guest reaches it.

## 6. Questions

### For Patrick (policy or scope)

1. **Should an external reader ever push back?** `Drained` keeps today's never-short writes. A `Paced` reader, which the client drains on its own schedule, would let the scheduler explore short writes and EAGAIN on stdout: new schedules, found by PCT, for guests that print a lot. Is that in scope, or is stdout always a sink?
2. **Which launch shapes are worth configuring?** Pipes (all in A) cover the harness and the oracle. `/dev/null` and file stdin (C) are guest-visible through `CanSeek` and `poll`. A terminal is a large BCL surface: terminfo, termios, keypad transmit. Pipes only for now, with the tty refused for the foreseeable future?
3. **`fstat` fields with no deterministic truth.** Linux's pipefs `st_dev` is this boot's, and its `st_ino` is a machine-wide counter. Darwin's `st_ino` is a hashed kernel address, different per end. Should these be deterministic inventions documented as such (as pid 4242 is), or should `fstat` keep refusing those fields? The only managed consumer, `PipeStream.ValidateHandleIsPipe`, reads `S_IFMT` alone, but the PAL's `FileStatus` cannot leave a field unset.
4. **Signals Q3, revisited.** With `pipe2` in the library, the shim's self-pipe can be a real emulated pipe, taking two fds as the real shim does. Real CoreCLR also opens a transient pipe per suspended-created thread, so fd-number parity with real .NET is out of reach either way (see `OpenFdNumbering.cs`'s comment). Model the self-pipe, or keep it PawPrint-internal?

### For the orchestrator (decidable from the evidence)

- A slot model on Linux and a size-carrying model on Darwin: required by rows 2–3; a byte count is falsified.
- `OpenFileObject.Pipe of PipeId`, shared by both ends: row 17.
- Holders derived from the descriptor table rather than counted: matches sockets, and a count could drift.
- Whether `O_CLOEXEC` in `pipe2` waits for a per-descriptor flag or is refused: no guest distinguishes them until `exec` exists.
- Naming: `Delivered` and `EndpointId`, or something else.

## Decision (orchestrator, 2026-09-26)
- **Design A**, with the staged plan.
- **Q1, a `Paced` reader:** not now. Stdout stays a sink (`Drained`); `Paced` can be added later as another case.
- **Q2:** pipes only as launch shapes for now. `/dev/null`, file stdin and a tty stay refused.
- **Q3:** a pipe's inode numbers are minted by the model, as every other inode's are; Linux shares one number between the ends, Darwin gives each end its own. `st_dev` for pipes is machine configuration with a deterministic default, as the pid is. Timestamps follow each flavour's measured rule on the model's clock.
- **Q4 (signals Q3):** decided by Patrick, 2026-09-27: the self-pipe is a real emulated pipe, through `pipe2`; signals stage 5 implements it.
- **Order:** stage 1 (the buffer rules as a pure module) starts now. Stage 0 (storing `O_NONBLOCK` on the streams) follows, as a small separate PR.
