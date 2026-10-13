---
name: emulated-posix-kernel
description: Deciding how the emulated kernel should answer a syscall — whether a fact belongs to the platform, to boot or process configuration, or to the client; whose encoding a value is stated in; where per-thread state lives; which test tier can observe the answer. Use when adding or changing anything in WoofWare.PosixKernel (the Unix* syscall files — UnixSocket.fs, UnixConnection.fs, UnixPoll.fs, UnixKqueue.fs, UnixInotify.fs, UnixDescriptor.fs, UnixPathResolution.fs, UnixReadWrite.fs, UnixNamespace.fs, UnixPipe.fs, UnixSignal.fs, UnixClock.fs, UnixEntropy.fs, UnixCredentials.fs, UnixThreadLifecycle.fs, UnixWait.fs, UnixSystem.fs, UnixBootImage.fs — as well as the platform profile and the per-syscall divergence rules it selects between — SimulatedUnixPlatform.fs, SimulatedUnixFlavour.fs, StartingPointRules.fs, CreatingOpenRules.fs, MkDirRules.fs, MkNodRules.fs, RemovalRules.fs, RenameRules.fs, AccessRules.fs, StatRules.fs, AttributeChangeRules.fs, TimestampChangeRules.fs, OwnerChangeRules.fs, ProtectedFiles.fs, Sockaddr.fs, UserBuffer.fs, EmulatedFileSystemType.fs — and ProcessLaunch.fs, VirtualFileSystem.fs, PathWalk.fs, FileDescriptorRegistry.fs, Signal.fs, SignalState.fs). Carries measured Linux/Darwin divergence tables — consult them rather than re-measuring.
---

# Deciding what the emulated kernel says

The library models a Unix kernel as *data*, never as a host read: a replay must
not depend on the machine that produced it. That constraint decides most of what
follows.

## 1. Where does this fact live?

First ask whether it is the kernel's at all. `WoofWare.PosixKernel/README.md`,
"What the kernel leaves to the client", lists what the library deliberately does
not do — user memory and `mmap`, blocks inside the process (`futex`,
`__psynch`), choosing which thread runs, when time passes, running a signal
handler, `sigaltstack`, process creation — with why each is the client's and how
the two meet. Change that section when you move the line.

If it is the kernel's, it has two possible homes, and picking the wrong one is
the most common mistake in this area because they look alike from the call site.
The table's third row looks like them too, and is not the kernel's at all.

| home | the fact is… | examples |
| --- | --- | --- |
| `SimulatedUnixPlatform` | true of *this kernel's source*, the same on every machine running it | the architecture and page size the image was built for, `sa_family_t` width, `AF_INET6`'s number, `sizeof(struct sockaddr_storage)`, `reportsBirthTime`, `setIdBitsOnTruncation`, `creatingOpenRules` |
| configuration: `UnixBootImage` for the machine, `ProcessLaunch` for a process | true of *this machine or mount or process*, and a different admin could change it | `withMount`, `withUserAddressLimit`, `withProcessorCount`, `withBootTime`, `withProtectedFiles` on the boot image; `withCredentials`, `withUmask` on a launch |
| the client | an artefact of how the client runs the process, which no real kernel has | a limit that comes from how the client represents memory; which code path the process's own C library or runtime takes on each platform |

The test that separates the first two: **could two machines running the same
kernel image disagree?** A sysctl, a mount option, a uid — yes, so it is
configuration. `sizeof(struct sockaddr_un)` — no, so it is the platform.

Two entries currently in `SimulatedUnixPlatform` do not pass that test, and are
there as deliberate approximations rather than as precedent. `pathLimits` holds a
`NAME_MAX` that varies per mount on Linux, and `bindableEntryNames` holds which
names APFS will bind, because the library models exactly one filesystem a name
can be created in per flavour (the device filesystem at `/dev` is closed: no name
is created in it). Each has a named trigger for becoming configuration, stated
beside it: a second filesystem. Do not cite either as a reason to put a
machine-dependent fact in the platform.

A symbolic link's mode is a worked example of the line between the two: the
*rule* (`symlinkCreationPermissions`: Linux 0777, Darwin `0777 & ~umask`) is the
platform's, the *umask* it is applied to is the creating process's, and the
result is stored on the inode. A seeded link was created by some other process,
so it gets the rule applied to `SeedEntry.symlinkCreatorsUmask` (022), not to
this run's configured umask.
The filesystem type `fstatfs(2)` reports is another: the value is a *mount*
fact, so it is configuration (`UnixBootImage.withMount`), even though the flavour
constrains which types are possible (`EmulatedFileSystemType.isReportableUnder`:
`Tmpfs` is Linux-only, `Apfs` Darwin-only).

Two rules for adding a configuration knob:

- **The platform is a constructor argument, never a setter's.**
  `UnixSystem.initial` takes it, and nothing changes it afterwards, so a setter
  that reads the platform for a flavour-derived default (`withSoMaxConn`,
  `withMount`, the limits `withFileSystem` admits a seed's names under) is not
  order-dependent: there is no platform setter to run after it. When one knob's
  answer is not well-formed without another's, resolve it where both are final:
  a current directory is an inode of *this* filesystem, and a new filesystem
  invalidates every inode number the previous one handed out, so `ProcessLaunch`
  holds the directory as a path and the launch resolves it against the machine
  it starts on.
- **How a process starts is a `ProcessLaunch`, not a boot-image setter.** The
  first process (`UnixBootImage.boot`) and every later one
  (`SimulatedMachine.launch`) start from one, so a per-process knob goes on
  `ProcessLaunch` and a machine knob on `UnixBootImage`. The kernel chooses a
  later process's ID; only the first one's is configuration.

## 2. Per-thread state: field or map?

The criterion is **whether an absent key has a truthful reading**:

- **Field on `UnixThreadState`** when it does not — `Cpu`, `OsThreadId`. There is
  no honest default processor index or thread ID, and an arbitrary one aliases
  two threads. As a field, the compiler asks every future thread-creation site which
  value it wants.
- **`Map<'Thread, _>` on the kernel** when it does — `SignalState`'s handler
  frames (no frame, so an empty mask).

CPU placement has both, as Linux does. A thread's processor (`UnixThreadState.Cpu`,
the one it last ran on) is a field, because every thread has one. Which thread each
processor is running (`UnixSchedulingState.Occupants`) is a `Map<CpuId, OsThreadId>`
on the *machine*, because an idle processor is a truthful reading of an absent
key, and because a machine's processes share its processors. Keying it by
processor makes two threads on one processor unrepresentable, and "is T running" is
derived from it (`UnixScheduling.runningOn`), never stored beside it. Every way a
thread stops running (a dispatch elsewhere, a park in `UnixWait.park`, an exit, a
process ending) must take it out of the map; `TestUnixScheduling` holds that to a
reference that reads it off the event history.

The map form carries an obligation that is easy to miss: **remove the entry when
the value returns to the default.** A client may compare two states for equality
to decide whether a step changed anything, so a stored default is a state that
looks different while behaving identically. No process can observe it; it
corrodes determinism. `SignalState.sigreturn` drops a thread's last frame rather
than storing an empty stack, and `TestSignalState.fs` property-tests that against
a store-everything oracle: reads must agree, **and** no default may ever be
stored.

`SignalState.Blocked` is such a map: a thread absent from it blocks nothing, and
an empty mask is never stored. `sigprocmask(2)` and delivery set a thread's mask,
`sigreturn` restores the mask its frame saved, a new thread copies its creator's,
and a thread's exit drops it. A test that needs a thread to block signals calls
`UnixSignal.pthreadSigmask`; putting it in a handler (`HandlerFrames` in
`WoofWare.PosixKernel.Test`) still works, and is what a test of frames wants. A
mask is a `SignalMask`, not a set of signals, because Darwin keeps bit 31, which
names none.

`SignalState.MasksToRestore` is the other per-thread map: the mask a
`sigsuspend(2)` replaced, held from the call until the thread returns to user
mode. There an absent key means "not in the call", so an empty mask *is*
stored, as the mask to restore. It lives in the signal state rather than the
park because it outlives the park: the finishing call unparks before
`UnixSignal.onReturnToUser` pushes the frame that saves it.

## 3. Whose encoding is this?

The library is meant to be usable by a client that has never heard of .NET, so
**it states POSIX values and no client's encoding of them**: a raw `<errno.h>`
number in each flavour's own numbering, epoll's own readiness conditions, a
signo, an `open(2)` flag word, the set of sockets it will create. A conversion
between one of those and a client's encoding goes on the client's side, in the
client's repository. (PawPrint, the first client, keeps each of its
conversions — .NET's errno numbering, its socket-event bits, its signal enum —
as an adapter of its own, and the library never sees them.)

`scripts/check-client-references.py`, the `client-references` flake check,
fails on a library line that names a client or a client's symbols. Two things it
cannot see are how an encoding comes back:

- **Prose that describes a POSIX-named declaration in a client's terms.** The
  shapes to look for: a declaration's fields documented as a client's bits, a
  POSIX value documented with a client's number beside it, a case documented as
  carrying a client's enum value. Each reads as clean to every check. **Read the
  prose when you add, move or retire something**; nothing else will.
- **A bare numeric table under an innocent name.** If the numbers are a
  client's rather than a kernel's, the name will not say so.

## 4. Is this an identity, or a contention key?

`OpenFileObject` is the `flock` contention key, *not* a general-purpose identity.
Code that needs to tell two descriptions apart wants `OpenFileDescriptionId`.

Before keying it on anything per-description, ask what the *kernel* contends on
and **measure that descriptor kind**; do not generalise from a neighbouring one.
Measured, epoll descriptors, inotify descriptors and an `eventfd` share a single
`anon_inodefs` inode, so two epoll ports contend under `flock`, as do an epoll
port and an inotify instance, and `OpenFileObject.AnonymousInode` is
payload-free. That is a fact about those creators, not about anonymous inodes as
a class: Linux hands a distinct inode to files created through
`anon_inode_getfile_secure` and `anon_inode_create_getfile`, so a future
descriptor kind on `anon_inodefs` may well need its own identity. Sockets are on
`sockfs` with an inode each, and do not contend.

Giving each epoll port its own identity would grant two exclusive locks where
Linux grants one — visible to a process, and invisible to any test that only
locks one port.

## 5. Refuse rather than invent

When the platforms disagree and the library has not modelled the distinguishing
state, refusing with a reason that names the missing input beats returning a
plausible constant: a constant becomes a lie the moment the state it depends on
lands. This is why `UnixPathResolution.fstat` refuses a socket — the kernel holds
no inode for one, and `st_mode`, `st_nlink`, `st_blksize` and the identity fields
all differ between the flavours — while `fstatfs` answers, every field having
been measured on both (`TestFileSystemType`).

"Refuse" means a typed value, internal to the library: an internal function
`tryX` answers `Result<_, XRefusal>`, where `XRefusal` is an internal union whose
cases state facts and name no knob, with a `describe` and a `kind`. Only the
public entry point `X` throws, through `Refusal.orRaise`, and `XRefusal.kind`
says as what: `UnmodelledException` where the model does not cover the call
(unmeasured or unmodelled), and the BCL's own exception where no client following
the documentation could have made it (`ArgumentException` or
`ArgumentOutOfRangeException` for a contradictory boot setting,
`InvalidOperationException` for misuse, `PlatformNotSupportedException` for a
call the flavour lacks). A new refusal is a new internal case and an arm of its
`kind`; nothing public changes, so it is a minor version. That holds for boot
configuration too: a setter in `UnixBootImage` or `ProcessLaunch` that rejects a
well-formed value (`withBootTime`, `withMount`, `withTcpSendSpace`,
`withProcessId`, `withCredentials`, …) has a `tryWith…` returning its own
refusal, each case's docstring saying whether the value is unmeasured,
unmodelled or contradictory. A client without friend access sees only the
exception, so it is the client that names its own configuration field when it
reports one. Only a forged value (`Unchecked.defaultof`) still fails with
`failwith`, and a setter keeps a `context` parameter only to name the knob in
that throw.

## 6. Establish the fact by measuring, not by reading source

For any kernel-behaviour constant, write the measure-the-host test *first* and
let it name the value. Use source only to learn the rule's **shape** — is this a
pointer test or a range test? — which is far more stable across versions than the
constant.

`SimulatedUnixPlatform.linuxX64` names a release string, and that is what a
process reads from `uname`; it is **not** evidence about the kernel a test runs
on. Reading `access_ok` at the preset's version gave a sign-bit split where CI
measured `TASK_SIZE_MAX`, because x86 changed the rule between 6.9 and 6.12.

No fact follows from the release string. A fact that changed between Linux
versions follows the platform's `LinuxKernelVersion` (`SimulatedUnixKernel.Linux`),
which each preset states for itself (`linuxX64` 6.17.0, `linuxArm64` 6.18.5):
`getSockNameFaultLength` is the first, after Linux 6.18 moved the length's store
ahead of the copy, which CI's 6.17 caught where 6.18.5 had been measured. A
host-equality test of such a fact models the host's *own* version
(`HostPlatform.onUnixHostKernel`), so it holds on whichever kernel runs it, and
its rows should come from kernels on both sides of the change.

See `reference/probing.md` for the probe technique, including the two ways a
set-ID measurement reads as "unsupported" when it is not.

## 7. Which test tier can see it?

Summarised here; `reference/testing.md` has the detail.

- **Unit and property tests** — the measured rows as literals for both flavours,
  including the rows no host can reach (the other flavour, the real root, uid 0),
  and the rule held to a naive reference over generated inputs. They state the
  rule as the author understood it, so they cannot catch a misreading of the
  kernel.
- **Host-equality tests** (`*AgainstHost`) — for a fact measurable on the
  machine running the test. Assert *equality* against the host and make the
  failure message report the measured value, so one CI run corrects a wrong
  constant rather than merely rejecting it. macOS locally and Linux in CI each
  falsify one column, so divergent rows belong here too.
- **Replays of committed probe outputs** (`*Measured`, and the corpus files
  other tests embed) — both flavours' real answers, checked on every machine,
  frozen at the kernel version and date the probe ran.
- **The fuzzers** (`TestSocketFuzz`, `TestSignalFuzz`) — generated syscall
  sequences on a real kernel and on the model, with a committed corpus that
  replays everywhere and a live mode that needs a real kernel of the flavour.

## Reference

- `reference/flavour-divergence.md` — an index from each measured Linux/Darwin
  fact to the test that owns its rows, the envelope those measurements were taken
  in, and the few facts no test states. **Read the test, do not re-measure.**
- `reference/descriptor-kinds.md` — the same for descriptor kinds, plus three
  places where reading the kernel source gives the wrong answer.
- `reference/testing.md` — choosing a tier, and the traps in each.
- `reference/probing.md` — running a probe on both platforms, and the two
  environment facts that make a probe lie.
