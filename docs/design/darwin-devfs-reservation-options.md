# Darwin's devfs before 1.0: which shapes to reserve

*Design note, 2026-10-13, at `origin/main` `628a80d7`. Design item D7 of `reserved-union-cases.md`. Darwin's `/dev` stays refused for 1.0 (`darwin-devfs-options.md`, which recommends option A, staged D0–D3); this note settles only what must change shape before 1.0 so that those stages, when they land, add rather than break. The facts are `darwin-devfs-options.md` §2's, from `darwin-devfs.c` on branch `pk-darwin-devfs-probe` (commit `e05a88b8`), which this PR brings onto `main`. No new measurement was needed.*

## 0. Summary

The audit lists four candidate changes. Read against the public surface (the API baseline, `SurfaceBaseline.txt`), two of them are not needed as public shapes at all, and two shapes it does not list are:

| candidate | verdict |
| --- | --- |
| `DeviceFileSystemMount.Devfs` gains `of DevfsMount` (D0) | **Not needed as a public shape.** The type reaches a client only through its own module and `FileSystemStatistics.ofDeviceMount`; no setter takes it and PawPrint uses neither. Make `DeviceFileSystemMount`, `DevtmpfsMount` and those functions **internal**, so that the Darwin payload, and whether any of it is configuration, is free to settle in D0 |
| a Darwin device description has a position (D1) | **Needed.** `OpenFileTarget.CharacterDevice` is a public case a client matches (PawPrint's `SignalDispatch`), so a field added later breaks it. Add a third field now, an **opaque** `CharacterDeviceState`, as `OpenFileTarget.Fifo` carries `FifoAttachment` |
| `EmulatedFileSystemType.Devfs` (`fileSystemTypeOf` must answer for a devfs inode) | **Not needed.** `fileSystemTypeOf` is internal, and what a client sees of a filesystem's type comes through `FileSystemStatistics` and `FileSystemTypeFields`, which carry Darwin's `f_type` (19) and `f_fstypename` (`devfs`) as raw values. The internal function can answer an internal type. A public `Devfs` case would make `EmulatedMount.defaultOf` partial, since devfs cannot be the root mount |
| `CharacterDevice.Tty` | **Reserve**, as `Zero` and `Random` were (#1853): a field-less case of a union clients match in full. Its facts are measured on both flavours |
| *(not in the audit)* `CharacterDevice.unrecognisedIoctl : CharacterDevice -> UnixError` | **Make internal.** D1 needs a flavour here (Darwin answers `ENODEV` where Linux answers `ENOTTY` or `EINVAL`), which would change a public signature |
| *(not in the audit)* `CharacterDevice.specialFileDevice : SimulatedUnixFlavour -> CharacterDevice -> int64` | **Make internal.** If random's major is configuration (Q1 below), Darwin's `st_rdev` for `random` and `urandom` needs the mount as well as the flavour |

So the PR is: the probe; `CharacterDevice.Tty`; a third field on `OpenFileTarget.CharacterDevice`; and five public names made internal. Nothing about Darwin's devfs becomes reachable.

## 1. What the public surface exposes today

From `SurfaceBaseline.txt` at `628a80d7`:
- `DeviceFileSystemMount` (2 cases) appears in `DeviceFileSystemMount.defaultFor`, `DeviceFileSystemMount.isMountableUnder` and `FileSystemStatistics.ofDeviceMount`, and nowhere else. `DevtmpfsMount` appears only inside it and in `DevtmpfsMount.defaults`. No `UnixBootImage` or `ProcessLaunch` setter takes either, so a client cannot configure the device filesystem at all; `UnixSystem.mountDeviceFileSystem` mounts `defaultFor flavour`.
- `rg` over `WoofWare.PawPrint*` finds none of them used. The library's own test project uses `DevtmpfsMount.defaults` once, through `InternalsVisibleTo`.
- `OpenFileTarget.CharacterDevice of inode * device` is received by clients: PawPrint matches `OpenFileTarget` case by case (`SignalDispatch.fs`), and the audit's §1.1 measurement shows an unrecompiled client meets a changed case as `InvalidCastException`.
- `CharacterDevice`'s module exposes `all`, `name`, `permissions`, `specialFileDevice` and `unrecognisedIoctl`. Outside the library only its tests call them.
- `EmulatedFileSystemType` reaches clients through `EmulatedMount.fileSystemType`, `EmulatedMount.defaultOf`, `EmulatedFileSystemType.fieldsFor`/`isReportableUnder`/`defaultFor` and `TimestampChangeRules.rangeOf`. PawPrint matches it in `NativeSystemNative.fs`. `UnixMachineState.fileSystemTypeOf` is internal.
- `FileSystemStatistics.Darwin`'s fields (type number, type name, block and I/O sizes, capacity, `f_fsid`, owner, flags, sub-type, mounted-on and mounted-from) already hold everything devfs's `statfs` reports (`darwin-devfs-options.md` §2.1: 19, `devfs`, 512, 512, capacity refused, `{st_dev, 19}`, 0, `0x4101000`, 0, `/dev`, `devfs`).

## 2. The mount (D0)

### Options

- **M1 (chosen): make `DeviceFileSystemMount`, `DevtmpfsMount` and their functions internal**, with `FileSystemStatistics.ofDeviceMount`. Nothing a client can see changes when D0 gives `Devfs` a payload. Making them public again, the day a client may configure the device filesystem, is additive.
- **M2: give `Devfs` its payload now**, `Devfs of DevfsMount` with `DeviceId` and `Flags` (both measured: `st_dev` moves per boot; `f_flags` `0x4101000`), and perhaps the random major (Q1). Every field would be fixed before D0 has been written, for a type no client can do anything with.
- **M3: an opaque `DevfsMount`**, public, with no readers. A hedge with nothing to hedge: no client builds or reads it.

M1 keeps every option open and costs nothing a client uses. M2 and M3 both commit to a public type whose only purpose would be to be read by a client that has no reason to.

### Q1: is random's major (17) configuration?

**Configuration, with 17 as the measured default** (`darwin-devfs-options.md` §5's recommendation, taken). `randomdev.c` registers with `cdevsw_add(-1)`, so the kernel picks the first free slot from 13 at boot, and which slots are free depends on what registered first. By the skill's test, two machines running the same kernel image could disagree, so it is a fact of the machine, not of the platform. Null (3,2), zero (3,3) and tty (2,0) are static slots in `bsd/dev/arm64/conf.c`, so they are platform facts.

Under M1 this decides only where the number will live: in the internal `DevfsMount`, read when `stat` encodes `st_rdev`. That is why `specialFileDevice` cannot stay public with its present signature (§4).

## 3. The description's position (D1)

Measured on Darwin 27.0 (`darwin-devfs-options.md` §2.3): `read` and `write` on `/dev/null`, `zero`, `random` and `urandom` advance a position; `lseek` keeps it; `SEEK_SET` and `SEEK_END` accept any offset, negative included; `SEEK_CUR` past `INT64_MAX` is `EOVERFLOW`. Linux keeps none: `lseek` answers 0 for every whence and offset. So a Darwin device's description carries a signed 64-bit position and a Linux one carries nothing.

### Options

- **P1: a public field typed by a union**, `CharacterDevice of inode * device * position : DevicePosition`, with `DevicePosition = Positionless | At of int64`. Exact for what is measured, and readable by a client.
- **P2 (chosen): an opaque third field**, `CharacterDevice of inode * device * state : CharacterDeviceState`, whose representation is internal, holding today the one value a Linux description has. D1 adds Darwin's position as an internal case, and any further per-description state Darwin's drivers turn out to keep, without touching the case.
- **P3: a position on every device description**, `int64`, which Linux simply never moves from 0. Shorter, but it makes "a Linux description at position 5" representable, and a field whose meaning depends on the flavour is what the invariants would then have to police.
- **P4: keep the position off the target**, in a side table keyed by description. Rejected: the target is where every other kind keeps its own per-description state (`File`'s offset, `Directory`'s position), and a side table must be kept in step with every description's creation, `dup` and release.

P2 over P1 because only the position is measured, not the whole of what a Darwin device's description keeps: D1 is the stage that will find out (`/dev/tty` with a controlling terminal, for instance, is unmeasured past `fstat`). A client has no use for a device's position — `lseek` answers it — so hiding it loses nothing a client needs. It follows `FifoAttachment`'s precedent exactly: a reserved kind of state, one internal case, no readers.

## 4. The device functions

`CharacterDevice.unrecognisedIoctl` answers Linux's `ENOTTY` (null) and `EINVAL` (urandom). Darwin answers `ENODEV` for both (`darwin-devfs-options.md` §2.3), so D1 must give it a flavour. `CharacterDevice.specialFileDevice flavour device` cannot answer Darwin's random or urandom from the flavour alone once the major is configuration (§2). Both would change signature; neither is used outside the library and its tests. **Make both internal.** `name` and `permissions` stay public: they are the same on both flavours for every device planned (`tty` is 020666 on both), and `all` stays as it is (a per-flavour `devicesFor`, if Darwin's set ever differs, is a new function).

## 5. The filesystem type

### Options

- **T1: `EmulatedFileSystemType.Devfs`**, which `fileSystemTypeOf` answers for a devfs inode, as it answers `Tmpfs` for a devtmpfs inode (a devtmpfs is a tmpfs, and reports tmpfs's magic). `fieldsFor Darwin Devfs` would answer `(19, "devfs")`.
- **T2 (chosen): leave `EmulatedFileSystemType` alone**, and have the internal `fileSystemTypeOf` answer an internal type that can say "the device filesystem" when D0 lands (for example `Root of EmulatedFileSystemType | Device of DeviceFileSystemMount`).

T1 makes `EmulatedFileSystemType` mean two things: the type a client chooses for the root mount, which is what its docstring says it is, and a type no client can choose. `EmulatedMount.defaultOf : EmulatedFileSystemType -> EmulatedMount` is public and total today; with `Devfs` it would have to throw for a type no `EmulatedMount` has. `isReportableUnder Darwin Devfs` would be true, but `withMount` could never be handed it. And nothing public needs the case: a client learns a descriptor's filesystem through `FileSystemStatistics`, whose Darwin fields carry the raw type number and name, which is how PawPrint's `FileSystemTypePal` answers `SystemNative_GetFileSystemType` (it would need a `devfs` row, which is PawPrint's to add with D0). T2 costs nothing now and keeps the public type honest. The audit's premise holds — `fileSystemTypeOf` throws for a devfs inode at `UnixMachine.fs:390` — but the fix is internal.

`TimestampChangeRules.rangeOf` takes an `EmulatedFileSystemType`. A devfs node's timestamp range (microseconds, `darwin-devfs-options.md` §2.2) will be an internal rule beside it; the public function keeps answering for root mounts.

## 6. `CharacterDevice.Tty`

- **Certainty of the case.** Likely, in the audit's terms: `/dev/tty` is D2 of `darwin-devfs-options.md`, and Patrick asked for it reserved. `CharacterDevice` has field-less cases that clients cover in full, the shape §1.1 of the audit shows fails silently without a reserved case.
- **Fields.** None. The facts it will select are measured: name `tty`; mode 020666 on Darwin 27.0 and Linux 6.18.5; `st_rdev` 2,0 on Darwin (a static slot) and 5,0 on Linux (raw `0x500`).
- **Q4 (may the library state that no process has a controlling terminal?)** decides D2's behaviour (`open` answers `ENXIO`, as measured without one), not the shape. The reservation does not depend on it. When D2 comes, the premise belongs in the `open` arm's docstring; a later controlling-terminal model would add state to the process, which is additive.
- **While reserved**, as `Zero` and `Random`: not in `CharacterDevice.all`, so no node names it; `name`, `permissions` and (Linux) `specialFileDevice` answer the measured facts; the drivers and `unrecognisedIoctl` throw, naming it; `VirtualFileSystem.checkInvariants` reports a node of it as `ReservedContent`, which the existing reflection-driven test covers.

## 7. Other open questions of `darwin-devfs-options.md` §5, as far as shapes go

- **Q2 (D0 without D1):** a scheduling question, not a shape. Nothing here depends on it.
- **Q3 (`NAME_MAX` per filesystem):** no public shape. The check is the internal path walk's (`PathWalk.fs`), and `SimulatedUnixPlatform.pathLimits` can go on answering the root filesystem's limits; a per-mount limit, if it is ever exposed, is a new function. So D0 may either refuse an over-long name inside devfs (an internal refusal case) or answer Darwin's `ENOENT` from a per-filesystem limit, without a break.
- **Q5 (Darwin root):** behaviour only; root's devfs namespace operations stay refused.

## 8. What else D0–D3 will need, checked

Each later stage's answers fit types that already exist: `stat`'s record (birth time 0, microsecond stamps), `FileSystemStatistics.Darwin` (§1), `lseek`'s and `ioctl`'s `SyscallAnswer`, `poll`'s raw `revents` (`POLLNVAL`) and `kevent`'s per-event errors (`EV_ERROR` with `EINVAL`). The namespace verdicts (`EPERM` throughout) are errnos. The refusals they retire or add are internal. `/dev/fd` and the standard-stream links stay refused (`darwin-devfs-options.md` §4), so their shape is not reserved.

## Decision (orchestrator's delegate, 2026-10-13)

- **The mount (D0): M1.** `DeviceFileSystemMount`, `DevtmpfsMount`, their modules and `FileSystemStatistics.ofDeviceMount` become internal. Q1: random's major is configuration with 17 as its default, to live in the internal `DevfsMount`.
- **The position (D1): P2.** `OpenFileTarget.CharacterDevice` gains a third field, the opaque `CharacterDeviceState`, with one internal case for the position-free description every device has today.
- **The filesystem type: T2.** No `EmulatedFileSystemType.Devfs`; the internal `fileSystemTypeOf` will answer an internal type when D0 lands.
- **`CharacterDevice.Tty`: reserved**, field-less, appended after `Random`, with its measured name, mode and Linux `st_rdev`. Q4 is left to D2.
- **`CharacterDevice.unrecognisedIoctl` and `specialFileDevice`** become internal: the audit did not list them, but D1 and Q1 would each change one's signature.
