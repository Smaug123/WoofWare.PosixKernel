# Darwin's devfs in WoofWare.PosixKernel

*Options document, 2026-10-07. Code references are at `origin/main` `5f1238f3`. New measurements are from `docs/plans/2026-08-23-posix-kernel-extraction/darwin-devfs.c`, committed with their outputs on the local branch `pk-darwin-devfs-probe` (commit `e05a88b8`, not pushed). Older measurements are from `devices.c` and `mountpoint.c` beside it, and are summarised in `devices-options.md` §2; this document does not repeat what that one says about the four memory devices except where a second boot or a new row changes it.*

## 0. Summary

- **Nothing in .NET opens a `/dev` path on Darwin.** A Darwin-flavour guest reaches `/dev` only through its own code: `File.Exists("/dev/null")`, a `FileStream` over `/dev/null` or `/dev/urandom`, `/dev/stdin` in a command-line tool. No current PawPrint test does that (§1).
- **Darwin's devfs is very regular where a client is likely to look**, and differs from Linux's devtmpfs in ways the model already has the shape for (§2):
  - its nodes' identity (`st_rdev`, inode numbers) was the same across two boots;
  - only `st_dev` (and so `f_fsid`) and the capacity counts move between boots;
  - every namespace change by uid 501 is EPERM, where Linux's is EACCES.
- **`/dev/fd/N` is dup-like on Darwin and reopen-like on Linux.** Linux's `/dev/fd` is a symlink into procfs. Neither is needed by a known client, so both stay refused (§2.5).
- **A Darwin devfs lookup of an over-long name is ENOENT, not ENAMETOOLONG.** This is the "second filesystem" trigger that `SimulatedUnixPlatform.pathLimits` names for making `NAME_MAX` per mount (§2.6).
- **Recommendation: option A.** Generalise the existing device filesystem into a per-flavour table, in stages (§4):
  1. D0: Darwin devfs at the stat and namespace level, with `open` of a Darwin node still refused. This stage avoids the files the multi-process refactor is changing, except for `UnixMachine.fs`.
  2. D1: the drivers for `null` and `urandom`. This needs a position on the device's open file description, so it should wait until that refactor has landed.
  3. `/dev/tty`, then `/dev/zero` and `/dev/random`, each when a consumer appears.
  4. `/dev/fd` and the standard-stream links stay refused.

## 1. What a Darwin client needs from `/dev`

### 1.1 The runtime and the BCL: nothing

- **Managed code.** I scanned every assembly in the 10.0.12 macOS shared framework (`Microsoft.NETCore.App`, as the devshell installs it) for UTF-16 string literals containing `dev/`, and found none. The same scan of the pinned linux-x64 pack (`$DOTNET_LINUX_FRAMEWORK_DIR`) also found none.
  - `System.Console` names only terminfo directories (`/etc/terminfo`, `/usr/share/terminfo`, and so on), never `/dev/tty`.
  - CoreLib's `RandomAccess.Unix.cs` mentions `/dev/tty` only in a comment.
- **Native code.** The only `/dev` string in the macOS dylibs is `/dev/zero`, in `libcoreclr`, `libclrjit` and `libmscordaccore`. That is the PAL's name for an anonymous file mapping (`map.cpp:399`), which mmaps with `MAP_ANON` and never opens the path. PawPrint does not run that code anyway. `libSystem.Native.dylib` names no `/dev` path.
- **Random bytes.** On Darwin, minipal calls `CCRandomGenerateBytes` (`random.c`, `#elif defined(__APPLE__)`), and PawPrint's libSystem generator is seeded through `getentropy` (`devices-options.md` §6.2, merged as #1706). Nothing opens `/dev/urandom`.
- **PawPrint.** `WoofWare.PawPrint/Native/` reaches `/dev` only from `MinipalRandom.fs` (Linux), plus refusal messages in `NativeSystemNative.fs` and `EmulatedKernel.fs`.
  - The guest sources (`WoofWare.PawPrint.Test/sources*`) name `/dev` only in Linux guests: `MinipalUrandomDescriptorLinux`, `MinipalPartialReadLinux` and `CopyFileFromUrandomLinux`.
  - `GetFileSystemTypeDarwin.cs` mentions devfs only to explain why it is not differential.

So **no current consumer** sends a syscall to Darwin's `/dev`. The need is prospective: a guest written against Darwin that uses a device itself.

### 1.2 What such a guest sends

CoreLib's managed I/O is the same code on both flavours. The Linux `strace` in `devices-options.md` §2.9 is therefore what a Darwin guest sends for the same calls, with Darwin's answers:

| guest code | syscalls on the device |
|---|---|
| `File.Exists("/dev/null")`, `new FileInfo(p).Length`, `File.GetAttributes` | `lstat`, then `stat` |
| `File.OpenRead("/dev/urandom")` + `Read` | `open(O_RDONLY\|O_CLOEXEC)`, `fstat`, `flock(LOCK_SH\|LOCK_NB)`, `lseek(0, SEEK_CUR)`, `pread`/`read`, `close` |
| `File.WriteAllText("/dev/null", …)`, `new FileStream(…, FileMode.Create)` | `open(O_WRONLY\|O_CREAT\|O_CLOEXEC [\|O_TRUNC])`, `fstat`, **`fstatfs`** (CoreLib asks the filesystem type before it takes the shared lock), `flock`, `ftruncate`, `lseek`, `pwrite` |
| `Console.OpenStandardInput()` | `dup(0)`, never `/dev/stdin` |
| `File.ReadAllText("/dev/stdin")` in a guest's own code | `open("/dev/stdin")`: a dup of fd 0 on Darwin (§2.5), then `fstat` (a FIFO, so not seekable), then `read` |
| `Directory.EnumerateFileSystemEntries("/", …, AllDirectories)` | `open("/dev", O_DIRECTORY)` and `getdirentries` |

So, in order of likelihood:
1. `stat`/`lstat` of `/dev/null` and `/dev/urandom`;
2. `open`, `fstat`, `fstatfs`, `flock`, `lseek`, `read`/`pread`, `write`/`pwrite`, `ftruncate` and `close` on them;
3. a walk into `/dev` that lists it, which stays refused on both flavours (§3);
4. far behind, `/dev/stdin`-style links and `/dev/tty`.

### 1.3 What the model does today

`DeviceFileSystemMount.Devfs` exists, and `UnixSystem.mountDeviceFileSystem` mounts it on Darwin as an empty mode-0555 root (`UnixSystem.fs:491-518`). After that, every way in is refused or rules it out:

| site | what it does on Darwin |
|---|---|
| `PathWalk.unmodelledMountRefusal` (`PathWalk.fs:296`), reached from `walkFrom` (`:523`) and `completeResolution` (`:774`) | any walk that reaches `/dev`'s mounted root is refused with `PathRefusal.UnmodelledFileSystem (root, Devfs)`. This covers `stat("/dev")`, `chdir("/dev")`, `open("/dev/null")`, and `rename`/`unlink`/`rmdir` of `/dev` |
| `PathWalk.absentNameRefusal` (`:274`) | `UnmodelledDeviceName`, for both device filesystems. On Darwin this is unreachable, because the walk is refused at the root first |
| `UnixPathResolution.statOf` `deviceId` (`:667`) | `failwith` "no path or descriptor can reach it". This is audit U6 (`failwith-audit-2026-10-07.md`): `stat("/dev")` refuses, the refusal hands the client inode 3, and the public `statOf (InodeNumber 3)` then throws |
| `StatRefusal`/`FStatRefusal.DeviceFileSystemRoot` (`:96`, `:152`) | refuses `st_size` and `st_nlink` of a device filesystem's root, on both flavours |
| `UnixMachineState.fileSystemTypeOf` (`UnixMachine.fs:312`) | `failwith` for an inode on devfs |
| `FileSystemStatistics.ofDeviceMount` (`FileSystemStatistics.fs:358`) | `failwith` for devfs |
| `CharacterDevice.specialFileDevice` and `unrecognisedIoctl` (`DeviceFileSystem.fs`) | `failwith` on Darwin ("Linux only: this kernel holds no device on Darwin") |
| `UnixSystem.checkInvariants` `foreignObjects` (`UnixSystem.fs:1012`) | `DescriptionNotOfFlavour` for an `OpenFileTarget.CharacterDevice` on Darwin |
| `ReadDirectoryRefusal`/`RemovalRefusal`/`RenameRefusal.DeviceFileSystem` (`UnixNamespace.fs:237`, `:308`; `RemovalRules.fs:32`) | refuse listing a device filesystem and changing a name in it, on both flavours |
| `RemovalRules` Darwin `unlink`/`rmdir` docstrings (`:319`, `:601`) | rely on "this library mounts no filesystem a Darwin path can reach", to equate "the root of a mount" with "the root" |
| `LinkRules` (`:161`) | EXDEV across mounts, which is Linux's answer. Darwin's is EPERM |
| the device drivers in `UnixReadWrite.fs` (`readDevice`, `deviceWriteWithoutBytes`), `UnixDescriptor.fs` (`lseek` at `:713`, FIONREAD at `:1439`), `Readiness.fs:86`, `UnixPoll.fs:477` | encode Linux's rows only: no position, no timestamps, urandom accepts writes, `POLLIN\|POLLOUT` |

## 2. Measurements

**Envelope.**
- **Darwin:** 27.0.0, xnu-13432.1.9 arm64, natively, as uid 501. This is the boot of 2026-10-07 (`kern.boottime` 1791357518). `devices.c` measured the boot of 2026-10-02, so wherever both probes read a field, this run is a second boot.
- **No controlling terminal.** The probe makes one in a child for the `tty` rows.
- **Standard streams.** The probe replaces fds 0, 1 and 2 with three pipes (stdin's writer closed), which is how PawPrint's harness launches a guest.
- **Linux comparison:** 6.18.5 aarch64 under Apple's `container` 1.4.1 (`gcc:14`), as root and as uid 1000, with `/dev` a devtmpfs.

### 2.1 Identity: what a reboot moves

| field | boot of 10-02 | boot of 10-07 | so |
|---|---|---|---|
| `st_dev` of `/dev` and every node | `0xc954548f` | `0x52597f09` | **per boot**: configuration, like devtmpfs's `DeviceId` |
| `f_fsid` | `c954548f:00000013` | `52597f09:00000013` | `{ st_dev, f_type }`: a rule, the same one APFS follows |
| `f_type` / `f_fstypename` / `f_fssubtype` | 19 / `devfs` / 0 | same | platform |
| `f_bsize` / `f_iosize` | 512 / 512 | same | platform |
| `f_flags` | `0x4101000` | same | `MNT_LOCAL\|MNT_DONTBROWSE\|MNT_MULTILABEL` ("local, nobrowse"). Configuration with this default, like devtmpfs's `Flags` |
| `f_blocks` / `f_files`; `bfree`, `bavail`, `ffree` | 414 / 716; all 0 | 403 / 698; all 0 | the counts follow the machine's node set: refused, as Linux's are (`CapacityRefusal.DeviceFileSystem`) |
| `/dev` `st_ino` / mode / `st_nlink` | 335 / 040555 / 4 | same | the size is 4922, then 4787: it follows the node set, so it is refused, as Linux's is (`StatRefusal.DeviceFileSystemRoot`) |
| inode numbers: console, tty, null, zero, fd, stdin/out/err, random, urandom | 336, 337, 338, 339, 343, 344–346, 613, 614 | same | devfs's own creation-order counter. The order depends on what registered nodes first (random's 613 sits after about 270 pty and disk nodes), so these are not facts a client can rely on |
| `st_rdev` null / zero | 3,2 / 3,3 | same | **platform**: cdevsw slot 3 (`mm`) is static in `bsd/dev/arm64/conf.c` |
| `st_rdev` tty | — | 2,0 | **platform**: static slot 2 (`ctty`) |
| `st_rdev` random / urandom | 17,0 / 17,1 | same | **assigned at boot**: `randomdev.c` registers with `cdevsw_add(RANDOM_MAJOR = -1)`, "let the kernel pick the device number", from the free range 13–63. Two boots agree. Whether another Mac model agrees depends on what registers before it, which I have not measured |
| `st_rdev` ptmx / pts slave | — | 15,2 / 16,2 | also assigned at boot |
| encoding | `major << 24 \| minor` | same | platform |

### 2.2 Per node: `stat` (uid 501, no controlling terminal)

All nodes are on devfs (`st_dev` as above). `st_flags` is 0, `st_gen` is 0, and birth time is **0** for every devfs node, including `/dev` itself. Timestamps are in microseconds.

| node | `lstat` | `stat` (following) | `st_blksize` | owner | timestamps |
|---|---|---|---|---|---|
| `/dev` | dir 040555, nlink 4 | = lstat | 512 | 0:0 | mtime/ctime at boot. **atime moves on `readdir`, not on a lookup**, and a failed create moves nothing (`TIMES` rows) |
| `/dev/null` | chr 020666, nlink 1, size 0, rdev 3,2 | = lstat | 65536 | 0:0 | moved by every read (atime) and write (mtime, ctime), by any process (`devices-options.md` §2.6). `utimes(NULL)` as uid 501 succeeds |
| `/dev/zero`, `/dev/random`, `/dev/urandom` | chr 020666, rdev as §2.1 | = lstat | 65536 | 0:0 | as null. `/dev/zero`, untouched since boot, read the boot instant for all three |
| `/dev/tty` | chr **020666**, rdev 2,0 | = lstat | 65536 | 0:0 | moved by other processes' terminal I/O |
| `/dev/console` | chr 020622, rdev 0,0 | = lstat | 65536 | **501:20** (the console user) | — |
| `/dev/stdin`, `stdout`, `stderr` | **symlink 0120555** to `fd/0`, `fd/1`, `fd/2`; size 0 (not 4); nlink 1 | the object fd 0, 1 or 2 names, as `/dev/fd/N` reports it (§2.5) | 512 | 0:0 | boot, never moved, including by a read through them |
| `/dev/fd` | dir 040555, nlink 1, size 0 | = lstat | 512 | 0:0 | boot |
| `/dev/fd/N` | see §2.5 | = lstat (not a symlink) | — | — | — |
| `/dev/full`, `/dev/shm`, `/dev/pts` | ENOENT | | | | (all three exist on Linux) |

`readlink` of `/dev/stdin` gives `fd/0`. `readlink` of `/dev/fd`, `/dev/fd/0`, `/dev/fd/10` and `/dev/null` is EINVAL.

`access` follows the mode bits:
- `/dev`: R and X yes, W EACCES.
- null, tty: R and W yes, X EACCES.
- `/dev/stdin`: R only, because the masked mode (§2.5) applies.
- `/dev/fd/99` (not open): EBADF.

**`statfs`** of `/dev`, of any node, of `/dev/fd` and **of every `/dev/fd/N`** answers devfs, even when N names an APFS file or a pipe. `fstatfs` on the descriptor that `open("/dev/fd/10")` returns answers APFS, because that descriptor is a dup.

### 2.3 Per node: `open` and operations

**`/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`.** `devices-options.md` §2.5–§2.7 is unchanged. The rows that differ from Linux, and so need a Darwin column in the drivers:

| | Darwin | Linux (modelled) |
|---|---|---|
| `lseek` | **keeps a position**. `read` and `write` advance it. `SEEK_SET`/`SEEK_END` accept any offset, negative included. `SEEK_CUR` past `INT64_MAX` is EOVERFLOW. Whence 3 and 4 are ENODEV | 0 for everything |
| timestamps | read stamps atime; write (even a failed or zero-length one) stamps mtime and ctime | never |
| `write` to urandom | **EPERM**, before anything else (`randomdev.c`: "`if (minor(dev) != RANDOM_MINOR) return EPERM`") | the count |
| `ftruncate` through a read-write descriptor | 0 | EINVAL |
| `fsync` | 0 | EINVAL |
| `ioctl(FIONREAD)`, `tcgetattr` | **ENODEV** | ENOTTY (null) / EINVAL (urandom) |
| `poll` | `POLLNVAL` | `IN\|OUT\|RDNORM\|WRNORM` |
| `kevent` `EVFILT_READ`/`EVFILT_WRITE` | `EV_ERROR`, data EINVAL | — |
| `pread` at offset −1 | succeeds | EINVAL |
| `pwrite` at offset `INT64_MAX` | EFBIG | EINVAL |
| a partly mapped read buffer | EFAULT | a short count |
| `open` `O_CREAT\|O_EXCL` / `O_DIRECTORY` / `O_NOFOLLOW` / `O_TRUNC` | EEXIST / ENOTDIR / opens / opens, nothing truncated | same |
| `fstatfs` | devfs | tmpfs magic |

**`/dev/tty`.**

| | no controlling terminal | with a pty as controlling terminal |
|---|---|---|
| `open` (every access mode, `O_NONBLOCK`, `O_NOFOLLOW`, `O_TRUNC`, `O_CREAT`) | **ENXIO**, Darwin and Linux alike | opens |
| `open` `O_CREAT\|O_EXCL` / `O_DIRECTORY` | EEXIST / ENOTDIR (checked before the driver) | — |
| `fstat` of the opened descriptor | — | **the `/dev/tty` node itself** (2,0, ino 337), not the pty slave. Linux: 5,0, also the node |
| `isatty` / `FIONREAD` / `lseek` / `write` / non-blocking `read` | — | 1 / 0 / ESPIPE / the count / EAGAIN |
| `fstatfs` | — | devfs |

**`/dev/stdin`, `/dev/stdout`, `/dev/stderr`** behave as `/dev/fd/0`, `/dev/fd/1` and `/dev/fd/2` (§2.5), except:
- `O_NOFOLLOW` is ELOOP (Linux: the same);
- the link itself is never stamped.

With fds 0, 1 and 2 as pipes:
- `/dev/stdin` opens only for reading, and `/dev/stdout` and `/dev/stderr` only for writing (EACCES otherwise);
- `read` gives 0 (the writer is closed), `lseek` gives ESPIPE, `FIONREAD` gives 0, `tcgetattr` gives ENOTTY.

With fd 0 closed, `stat("/dev/stdin")` and `open("/dev/stdin")` are **EBADF** (Linux: ENOENT), while `lstat` still succeeds.

**`/dev/fd` (the directory):**
- `open(O_RDONLY)` and `O_DIRECTORY` succeed; `O_WRONLY` and `O_RDWR` are EISDIR;
- `read` is ENOTSUP;
- `fchdir` into it works, and `getcwd` gives `/dev/fd`;
- `openat(that, "10")` is again a dup.

### 2.4 Directory operations in `/dev` (uid 501)

| operation | Darwin | Linux uid 1000 |
|---|---|---|
| create a name: `open(O_CREAT)`, `mkdir`, `mkfifo`, `symlink`, `link(/dev/null, /dev/x)`, `mknod` | **EPERM** | EACCES |
| `unlink` of `null`, `stdin` (a link) or `fd` (a directory) | **EPERM** | EACCES |
| `rmdir` of `fd` / `null` / an absent name | EPERM / ENOTDIR / ENOENT | EACCES / EACCES / ENOENT |
| `rename` within `/dev` (`null` → new name, `null` → `zero`) | **EPERM** | EACCES |
| `rename` of an absent name in `/dev` | ENOENT | ENOENT |
| `rename` between `/dev` and the root filesystem | EXDEV after an ENOENT check of the source (`devices-options.md` §2.3) | EXDEV whatever the source |
| `chmod` of `/dev`, `null`, `tty`, `fd` | EPERM | EPERM |
| `chown(-1, -1)` of `null` or `/dev` / `chown` to oneself | 0 / EPERM | same |
| `utimes(NULL)` of `null` / `tty` / `/dev` | 0 / 0 / EACCES (needs write permission) | same |
| `utimes` with explicit times, of `null` | EPERM | EPERM |
| `truncate("/dev/null", 0)` | EINVAL | EINVAL |
| a 32-byte name with `O_CREAT` | EPERM | EACCES |
| `rmdir("/dev")`, `unlink("/dev")`, `rename("/dev", …)`, `rmdir("/dev/.")` | EBUSY, EBUSY, EXDEV, EBUSY (`devices-options.md` §2.3) | EACCES (no write permission on `/`) |

Every Darwin namespace change in `/dev` by an unprivileged process is **EPERM**, and so is every Darwin node's `chmod`. This is devfs refusing the operation, not a permission check: `/dev` is 0555, so the permission check would have answered EACCES, which is Linux's answer. **Root on Darwin is unmeasured** (no root here), so a Darwin devfs model must refuse root's namespace operations.

**`readdir("/dev")`**:
- 349 entries this boot (358 before). `.` and `..` both carry `/dev`'s own inode.
- After those, the order is creation order: `console`, `tty`, `null`, `zero`, `klog`, `oslog`, `oslog_stream`, `fd` (`DT_UNKNOWN`), `stdin`, `stdout`, `stderr` (`DT_LNK`), then about 270 pty and disk nodes, `ptmx`, …, `random`, `urandom`, `dtracehelper`, …
- By `d_type`: 320 character devices, 22 block devices, 3 directories, 3 links, 1 unknown.
- The listing is machine-dependent, so it stays refused, as Linux's is.
- `readdir("/")` reports `dev` with the covered directory's inode (1152921500312607380), not 335.

### 2.5 `/dev/fd/N` and the standard-stream links

**Darwin's `/dev/fd/N` is a dup of N.** Linux's `/dev/fd` is a symlink to `/proc/self/fd`, whose entries are magic links that **reopen** the object.

| | Darwin | Linux (uid 1000) |
|---|---|---|
| the object `/dev/fd` | a devfs directory, 0555 | a symlink to `/proc/self/fd`, on procfs |
| `lstat("/dev/fd/10")` | the same as `stat`: no link | a symlink (mode `0120700`, on procfs) |
| `stat("/dev/fd/N")` | **the underlying object's inode, size, times, nlink and owner, but devfs's `st_dev`, `st_blksize` 512 for a pipe or socket, and the permission bits masked by N's access mode** (`fdesc_attr`: read bits cleared without `FREAD`, write bits cleared without `FWRITE`). A file `0644`: 0644 through `O_RDWR`, 0444 through `O_RDONLY`, 0200 through `O_WRONLY`. So `stat("/dev/fd/N")` ≠ `fstat(N)` | exactly the underlying object (it follows the link) |
| `open("/dev/fd/10")` where 10 is a file at offset 3 | **the same open file description**: offset 3, a `read` through it moves fd 10's offset, and `flock(EX)` through it succeeds while fd 10 holds `EX` | a new description: offset 0, `flock` contends (EAGAIN) |
| the access mode asked for | must be a subset of N's, or **EACCES** (an `O_RDONLY` fd cannot be reopened for writing). **The result has N's flags, not the request's**: `O_WRONLY\|O_APPEND` asked of an `O_RDWR` fd gives `O_RDWR` without append, and `O_NONBLOCK` asked is not applied | any access mode the inode's permissions allow. The flags are the request's |
| `O_CLOEXEC` | applied to the new descriptor | applied |
| `O_TRUNC` | **ignored**: the file keeps its size | truncates the file |
| `O_CREAT` / `O_CREAT\|O_EXCL` | opens / EEXIST | same |
| `O_DIRECTORY` | **ENOTDIR, even when N is a directory** | opens a directory |
| `O_NOFOLLOW` | opens | ELOOP |
| N not open | **EBADF** (`stat`, `open`, `access`) | ENOENT |
| N a socket | opens (a dup) | **ENXIO** |
| N a pipe end | a dup of that end only | a reopen of the pipe, for either direction |
| the name | leading zeros accepted (`010` is 10). **`4294967306` is 10**: the number wraps at 2^32. `+10`, `1a`, `-1` and a 20-digit name are ENOENT | `010` is ENOENT |
| `N/`, `N/.`, `N/x` | ENOTDIR, ENOENT, ENOENT, **even when N is a directory** | follows N: `11/.` and `11/file` resolve |
| `chdir("/dev/fd/11")` with 11 a directory | ENOTDIR | changes into the directory |
| `chmod`, `chown`, `utimes` of `/dev/fd/10` | **reach the file**: its mode and mtime change | the same (the link is followed) |
| `truncate("/dev/fd/10", 4)` | **0, and nothing is truncated** | truncates |
| `truncate` through an `O_RDONLY` fd's entry | EACCES (the masked mode) | 0 |
| `unlink` / `rmdir` / `rename` of `/dev/fd/10` | EPERM / ENOTDIR / EXDEV | EPERM / ENOTDIR / EXDEV |
| creating `/dev/fd/x` or `/dev/fd/77` | ENOENT, EBADF | ENOENT, ENOENT |
| `readdir("/dev/fd")` | exactly the open descriptors, in ascending order, the listing's own included. `d_type` `DT_UNKNOWN`, `d_ino` = N + 4. No `.` or `..` | `.`, `..`, then each fd as `DT_LNK` |
| a symlink elsewhere to `/dev/fd/10` | opens as a dup too (offset 3) | a reopen |
| `getcwd` after `chdir("/dev/fd")` | `/dev/fd` | `/proc/<pid>/fd` |

### 2.6 The path walk at and inside `/dev`

These Darwin rows are the same as Linux's, and are already the model's behaviour for Linux:
- `/dev/`, `/dev/.`, `//dev`, `/./dev`, `/dev/../dev`, `/dev//null`, `/dev/./null` and `/dev/../dev/null` resolve as expected;
- `/dev/..` is `/` on the root filesystem;
- `/dev/null/`, `/dev/null/.`, `/dev/null/..` and `/dev/null/x` are ENOTDIR;
- `/dev/nonexistent` and `/dev/nonexistent/` are ENOENT;
- `chdir("/dev")` then `chdir("..")` gives `/`.

Darwin also has:
- `/dev/fd/..` is `/dev`;
- `/dev/stdin/` is ENOTDIR, and `/dev/stdin/.` is ENOENT.

**Name length is per filesystem:**

| path | Darwin | Linux |
|---|---|---|
| `/dev/<255 bytes>` | ENOENT | ENOENT |
| `/dev/<256 bytes>`, `/dev/<1000 bytes>`, `/dev/<256 bytes>/x` | **ENOENT** | ENAMETOOLONG |
| `/tmp/<256 bytes>` (APFS) | ENAMETOOLONG | ENAMETOOLONG |
| `pathconf("/dev", _PC_NAME_MAX)` | 31 | 255 |

XNU leaves the length check to the filesystem. APFS checks, and devfs's lookup simply finds nothing. The model's walk checks a non-final component against the flavour-wide `PathLimits` *before* the lookup (`PathWalk.fs:511`; the final component at `:759`). So a Darwin devfs model needs either a per-filesystem limit, or a refusal for an over-long name inside devfs.

## 3. Options

These things are shared by every option. `/dev` is mounted at boot over a covered directory, in the existing one-graph-with-mounts design. A lookup of a name the model does not hold stays a typed refusal (`UnmodelledDeviceName`), because a real devfs holds about 350 nodes and ENOENT would be false. Listing `/dev` stays refused.

### A. Generalise the device filesystem into a per-flavour table (recommended)

- **State.**
  - `DeviceFileSystemMount.Devfs of DevfsMount`, with the configuration a boot decides: `DeviceId` (`st_dev`, from which `f_fsid` is derived by APFS's rule) and `Flags`. The defaults are this boot's.
  - `CharacterDevice` stays the driver's identity. Its per-flavour facts become one table: name, permissions, owner and `st_rdev` per `(flavour, device)`. `CharacterDevice.all` becomes `devicesFor flavour`.
- **The filesystem's own rules**, as functions of `DeviceFileSystemMount`, beside the existing ones:
  - `statfs` (type 19, 512/512, capacity refused);
  - birth time 0 and microsecond stamps;
  - the namespace verdicts: creation, `unlink`, `rename` within, `chmod` → EPERM; root refused; EXDEV after the source check; `link` → EPERM; the mount-point rows;
  - the name-length rule from §2.6.
- **The drivers' Darwin column** goes into the existing matches on `CharacterDevice`, as `(flavour, device)` arms:
  - a position, kept on the description;
  - read/write stamping;
  - urandom's EPERM;
  - ENODEV ioctls;
  - `POLLNVAL`;
  - `kevent` EINVAL.
- **Inode, `st_dev` and `st_rdev` numbering.**
  - Inodes come from the graph's one counter, as devtmpfs's do. Darwin's real numbers (335, 338, …) depend on the order drivers registered, so no client can rely on them, and any unique numbering is one a boot could give.
  - `st_dev` is configuration.
  - `st_rdev` comes from the table. Null, zero and tty are platform facts (static cdevsw slots). random/urandom 17 is either a platform fact or configuration with a measured default (open question 1).
- **Blast radius.**
  - D0 below touches `DeviceFileSystem.fs`, `VirtualFileSystem.fs` (`mountAtRoot` and the birth rule), `PathWalk.fs`, `UnixPathResolution.fs`, `FileSystemStatistics.fs`, `UnixNamespace.fs`, `RemovalRules.fs`, `RenameRules.fs`/`LinkRules.fs`, `UnixSystem.fs` (`mountDeviceFileSystem`, invariants) and `UnixMachine.fs` (`fileSystemTypeOf`, one arm).
  - D1 touches `FileDescriptorRegistry.fs` (the position), `UnixReadWrite.fs`, `UnixDescriptor.fs`, `Readiness.fs`, `UnixPoll.fs` and `UnixKqueue.fs`.
- **Sharing with Linux:** maximal. The mount crossing, the refusal of unknown names, `OpenFileTarget.CharacterDevice`, `openCharacterDevice` and every descriptor-kind match are reused unchanged.
- **Reversibility:** high. Each Darwin arm is additive. Removing Darwin again means restoring the refusal at the mounted root.
- **Risk.** It invites "the Linux row, with a Darwin tweak" mistakes. Every Darwin arm needs its own measured row. The existing `TestDeviceDescriptorsAgainstHost` host-equality tier would catch these on a macOS dev box, once it runs under Darwin.

### B. A separate Darwin devfs, with its own node and descriptor kinds

- **State.**
  - `InodeContent.DevfsNode of DevfsNode`, where `DevfsNode` is a node holding a Darwin driver, a stdio link, or the `fd` directory.
  - `OpenFileTarget.DevfsDevice of inode * driver * position`.
  - Optionally, a synthetic `/dev/fd` computed from the descriptor table at lookup time rather than stored as inodes.
- **Numbering:** the same as A, but the Darwin driver identity is its own DU (`DarwinDevice = Null | Zero | Random | URandom | Tty`), with `st_rdev` on it.
- **Blast radius:** the largest.
  - A new `OpenFileTarget` case is a new arm in every exhaustive match over descriptor kinds: 74 mentions of `OpenFileTarget.CharacterDevice` today, across `FileDescriptorRegistry`, `Readiness`, `ObjectLifetime`, `UnixProcess`, `UnixSocket`, `UnixConnection`, `UnixPoll`, `WakeCondition` and `UnixSystem`. Several of those files belong to the concurrent refactor.
  - A new `InodeContent` case touches about as many again: `InodeContent.CharacterDevice` has 51 mentions.
- **Sharing with Linux:** little. Two ways to say "character device" invite drift. For example, `StartingPointRules`' "ENOTDIR for a device" would have to be written twice.
- **Reversibility:** good. The Darwin code is isolated, and can be deleted as a unit.
- **What it buys:** it separates Darwin's position-keeping description from Linux's position-free one by type. A can buy the same with a `DevicePosition` field that is `None` on Linux and a value on Darwin, checked by the invariants.

### C. A minimal Darwin `/dev`: nodes at the stat level, and everything else refused

- **State.**
  - `DeviceFileSystemMount.Devfs of DevfsMount`, and Darwin entries for `null` and `urandom` (perhaps `tty`) in the node table, for lookup, `stat`, `lstat`, `access`, `statfs` and the namespace verdicts.
  - `open` of any Darwin node is a typed refusal (`OpenRefusal.UnmodelledDarwinDriver`). So `OpenFileTarget.CharacterDevice` never exists on Darwin, and the foreign-objects invariant stays as it is.
- **Answers:** `File.Exists`, `FileInfo`, `File.GetAttributes`, `Directory.Exists("/dev")` and `stat("/dev/null")` answer. Any `FileStream` over a device refuses.
- **Blast radius:** small. It touches no descriptor file except the `open` refusal in `UnixNamespace.openParsed`.
- **Sharing with Linux:** the same as A's D0. **C is exactly A's first stage, stopped there**, so choosing it closes no door.
- **Its cost:** a Darwin guest's most likely device use, `FileStream` over `/dev/null`, still refuses.

## 4. Recommendation and staged plan

**A, staged so that its first stage is C.** C alone is the right stopping point until a Darwin guest opens a device. Nothing does today (§1.1), and D1 is the stage that collides with the multi-process refactor.

| PR | content | touches the refactor's files? |
|---|---|---|
| **D0** Darwin devfs, stat level | `DevfsMount` (`DeviceId`, `Flags`) with this boot's defaults; Darwin nodes `null` and `urandom` (mode, owner, `st_rdev` 3,2 and 17,1, birth 0); the walk no longer refuses at devfs's root; `stat`/`lstat`/`fstatat`/`access` of `/dev` (size and nlink still refused) and of the nodes; `statfs` (type 19, geometry, `f_fsid` rule, capacity refused); `fileSystemTypeOf` and `ofDeviceMount` answer, which retires audit U6 and two `failwith`s; namespace verdicts (§2.4: EPERM for creation, removal, rename within and `chmod` of a node; `chown(-1,-1)` 0; `utimes(NULL)` 0 with a µs stamp; explicit `utimes` EPERM; root refused; `link` EPERM; EXDEV after the ENOENT source check); the mount-point rows (`rmdir`/`unlink` EBUSY, `rename` EXDEV), with `RemovalRules`' "no Darwin mount" docstrings corrected; the over-long-name rule (§2.6), as a refusal unless open question 3 says otherwise; `open` of a Darwin node refused, typed. Tests: `TestDeviceFileSystem`'s rows gain a Darwin column, and `TestDeviceFileSystemAgainstHost` runs on a macOS host (mode, nlink, rdev for null/zero/tty, `f_type`, EPERM rows) | `UnixMachine.fs` only: one arm of `fileSystemTypeOf`. Low |
| **D1** Darwin drivers for null and urandom | a position on `OpenFileTarget.CharacterDevice` (Darwin only; the invariants require none on Linux); the rows of §2.3: read/write/lseek/pread/pwrite, timestamp stamping, urandom EPERM, `ftruncate`/`fsync` 0, FIONREAD/tcgetattr ENODEV, `POLLNVAL`, `kevent` EINVAL, `flock` contention, `fstatfs` devfs; the invariant `DescriptionNotOfFlavour` relaxed for devices; `CharacterDevice.unrecognisedIoctl` gets a flavour. Tests: `TestDeviceDescriptorsAgainstHost` runs on macOS too | **Yes**: `FileDescriptorRegistry.fs`, `Readiness.fs`, `ObjectLifetime.fs` (one match each), plus `UnixReadWrite`/`UnixDescriptor`/`UnixPoll`/`UnixKqueue`. **Land after the multi-process refactor** |
| **D2** `/dev/tty`, both flavours (optional) | the node (Darwin 2,0, Linux 5,0, mode 0666), and `open` → ENXIO, since the model has no terminals and so no process has a controlling terminal. `O_CREAT\|O_EXCL`/`O_DIRECTORY` answered ahead of the driver. A docstring states the no-ctty premise | no |
| **D3** `/dev/zero`, `/dev/random` (on a consumer) | DU cases. All rows are measured on both flavours | as D1 |

**What stays refused**, typed:
- listing `/dev`;
- every name the table does not hold;
- root's namespace operations on Darwin devfs;
- `/dev/fd`, `/dev/fd/N`, `/dev/stdin`, `/dev/stdout` and `/dev/stderr`, on both flavours.

The reasons for the last group:
- **Darwin:** a dup-like `open` whose flags come from N's description, a `stat` that masks modes and substitutes `st_dev`, `O_TRUNC` ignored, `O_DIRECTORY` always ENOTDIR, a name that wraps at 2^32. That is a seventh syscall surface, measured here but with no consumer.
- **Linux:** the same paths go through procfs, which the model does not have.
- When a consumer appears, the Darwin form is cheap to state: a synthetic directory over the descriptor table, whose `open` is `dup` plus an access-mode subset check. The rows in §2.5 are the specification.

### Conflict risk with the multi-process refactor

That session is changing `UnixSystemState`, `UnixProcess`, `FileDescriptorRegistry`, `UnixMachine`, `Readiness` and `ObjectLifetime`.
- **D0** touches only `UnixMachine.fs`, in one `match` arm of `fileSystemTypeOf`, and the `foreignObjects` invariant in `UnixSystem.fs`, which reads `system.Process.FileDescriptors`. The refactor will move that access path if processes become a map. Rebasing D0 over it is mechanical.
- **D1** puts a position on `OpenFileTarget.CharacterDevice`, which is declared in `FileDescriptorRegistry.fs` and matched in `Readiness.fs` and `ObjectLifetime.fs`. It should be stacked after the refactor. The memory note "a rebase over a new DU case hides in wildcards" applies: check every match on the target after the rebase.
- **`/dev/fd` would depend on the refactor's outcome.** A dup-like open needs "this process's descriptor table", and that is exactly what the refactor is changing. That is one more reason to leave `/dev/fd` refused for now.

## 5. Open questions

1. **random/urandom's `st_rdev` major (17)**: platform fact or configuration? It is assigned at boot (`cdevsw_add(-1)`), and two boots on this Mac agree. Whether another Mac model agrees depends on which drivers registered before `random_init`. I recommend configuration in `DevfsMount`, with 17 as the measured default, by the skill's test ("could two machines running the same kernel image disagree?" — plausibly yes). Null, zero and tty are static slots, so they are platform facts.
2. **D0 without D1:** is a Darwin `/dev/null` that a guest can `stat` but not `open` useful enough to land on its own? Or should D0 wait and land with D1 after the refactor?
3. **Name length:** answer Darwin's ENOENT for an over-long name inside devfs, by making `NAME_MAX` a per-filesystem fact (the trigger `SimulatedUnixPlatform.pathLimits` names)? Or refuse that one case? I lean towards refusing it in D0 and making the limit per-filesystem as a separate change, since APFS and tmpfs would move with it.
4. **`/dev/tty` (D2):** is "the model has no terminals, so no process has a controlling terminal" a premise you are content for the library to state, on both flavours?
5. **Darwin root:** every devfs row here is uid 501, and root needs a password on this machine. Root's namespace operations in `/dev` stay refused unless you can measure them.

## Appendix: the probe's raw outputs

All on branch `pk-darwin-devfs-probe`, in `docs/plans/2026-08-23-posix-kernel-extraction/`:
- `darwin-devfs.c`: sections `stat statfs walk fdsem open ns list tty times`;
- `darwin-devfs.darwin-27.0-uid501.txt`: every section, `times` included;
- `darwin-devfs.linux-6.18.5-aarch64-uid1000.txt`;
- `darwin-devfs.linux-6.18.5-aarch64-root.txt`: with `times`; the rows that would change an existing node print "skipped (root)".
