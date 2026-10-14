# Device nodes in WoofWare.PosixKernel, and `/dev/urandom` for the Linux random entry points

*Options document, 2026-10-02. Part of the "PosixKernel knows nothing of the CLR" workstream. Code references are at `origin/main` `d4ea564a`. Probes, raw outputs and scripts are in [`devices-raw/`](devices-raw/) beside this file (called `$R` below); Phase 2 commits the probe sources beside the others in `docs/plans/2026-08-23-posix-kernel-extraction/`.*

## 1. What there is today

- **No device nodes.** `InodeContent` is `RegularFile | Directory | Symlink` (`Inode.fs:146`). There is one `VirtualFileSystem` with one `deviceId` (`0x1000001`, `VirtualFileSystem.fs:420`), which every inode reports as `st_dev` and Darwin's `f_fsid` repeats. `FileStatus.SpecialFileDevice` (`st_rdev`) is always 0. There is no `mknod`, no `link`, and no mount table: `EmulatedMount` is "the one filesystem a machine has mounted".
- **PawPrint's default machine has no `/dev` at all.** `KernelConfig.Default.FileSystem = FileSystemSeed.empty`, and 67 PawPrint test sites supply a seed of their own.
- **Entropy.** The brief's background is out of date. Since #1687, PawPrint no longer touches `EntropyPool` (`rg EntropyPool WoofWare.PawPrint` finds nothing).
  - `MinipalRandom.secureRandomBytes` serves `SystemNative_GetCryptographicallySecureRandomBytes` and the dynamic-module MVID. It calls `getrandom(GRND_INSECURE)` on Linux and `getentropy` in 256-byte chunks on Darwin.
  - `SystemNative_GetNonCryptographicallySecureRandomBytes` draws from PawPrint's own splitmix stream, `EmulatedKernel.NonCryptoRandomState`, on both flavours.
  - The known gap, from #1687's `minipal-random-descriptors.cs`: on real Linux .NET, System.Native opens `/dev/urandom` on the first call to either entry point, and the guest's next `open` lands one higher (22 → 23). PawPrint does not do this.
- **`time(NULL)` has no kernel answer.** `UnixClock` refuses Linux `CLOCK_REALTIME_COARSE` (id 5) as `Coarse`. It answers `CLOCK_MONOTONIC_COARSE` by an argument that applies equally to id 5: this machine's clock moves only when advanced, so its last update is the current reading. glibc's `time()` reads exactly that clock (§2.10).

## 2. Measured facts

**Envelope.**
- **Darwin:** 27.0.0 (xnu-13432.1.9) arm64, natively, as uid 501. Root is not available (`sudo -n` needs a password), so no Darwin row was measured as root.
- **Linux:** 6.18.5 aarch64 under Apple's `container` 1.4.1, image `gcc:14` (glibc 2.41), as root and as uid 1000 (`setpriv --reuid=1000 --regid=1000 --clear-groups`). That VM's `/dev` is a real **devtmpfs** (`none /dev devtmpfs rw,nosuid,relatime,size=568448k,nr_inodes=142112,mode=755`), not a container tmpfs.
- **.NET:** `mcr.microsoft.com/dotnet/sdk:10.0` (Ubuntu 24.04, runtime 10.0.11) under `strace`; `mcr.microsoft.com/dotnet/runtime:10.0` (10.0.12) arm64 and amd64 for `objdump -T`.
- **x86-64:** only under Rosetta (`--arch amd64`), which runs on the aarch64 kernel. It was used only for glibc-level facts (`lrand48`, symbol versions), never for a kernel answer.

Probes: `devices.c` (sections `stat statfs ns list ops times`), `devfs-times.c`, `bigread.c`, `mountpoint.c`, `mknod-node.c`, `mknod-node-tmpfs.c`, `timesrc.c`, `lrand48.c`, `darwin-rng-interpose.c`, `darwin-rng-reseed.c`, `darwin-rng-reseed-interval.c`, `dotnet-device-usage.cs`, and #1687's `minipal-random-descriptors.cs`. Outputs are in `$R/out/`.

### 2.1 `stat` of the four devices (`out/*-devices.txt`, `STAT`)

| field | Linux (devtmpfs) | Darwin (devfs) |
|---|---|---|
| `st_dev` | `0,6`: devtmpfs's anonymous device, the same for `/dev` and every node. Machine-dependent. | `0xc954548f` as a signed 32-bit `dev_t` (prints as major 201, minor 5526671). The same for `/dev` and every node, and equal to `f_fsid.val[0]`. Boot-dependent. |
| `st_rdev` | null `1,3`, zero `1,5`, random `1,8`, urandom `1,9` (raw 259/261/264/265, glibc's `makedev`) | null `3,2`, zero `3,3`, random `17,0`, urandom `17,1` (raw `major<<24 \| minor`). Only one boot was measured, so whether these majors are fixed by the kernel build or assigned at boot is **not known**. |
| `st_mode` | `020666` for all four | `020666` for all four |
| `st_nlink` | 1 | 1 |
| owner | 0:0 | 0:0 (root:wheel) |
| `st_size` / `st_blocks` | 0 / 0 | 0 / 0 |
| `st_blksize` | 4096 | 65536 |
| `st_ino` | 2, 3, 5, 6 (creation order at boot) | 338, 339, 613, 614 |
| timestamps | all equal to when devtmpfs made the node at boot: here 0, because the VM had no clock yet. **Never moved by `read` or `write`** (§2.6). | `atime`, `mtime` and `ctime` as last touched; **birth time 0**; microsecond granularity (`…443076000`). Moved by every `read` and `write` (§2.6). |
| `st_flags` | — | 0 |

`fstat` through a descriptor agrees with `stat` for every field.

### 2.2 `statfs("/dev")` (`STATFS`)

| | Linux devtmpfs | Darwin devfs |
|---|---|---|
| type | **`0x01021994`, `TMPFS_MAGIC`**: devtmpfs is shmem and reports tmpfs's magic | `f_type` 19, `f_fstypename` `devfs`, `f_fssubtype` 0 |
| geometry | `bsize` = `frsize` = 4096, `namelen` 255 | `bsize` 512, `iosize` 512 |
| capacity | `blocks` = `files` = 142112 (from `size=` and `nr_inodes=`), `bfree` = `blocks`, `ffree` = `files` less the nodes in use (141974). Machine-dependent. | `blocks` 414, `files` 716, `bfree` = `bavail` = `ffree` = 0. Grows with the node count. Machine-dependent. |
| `f_fsid` | `544366de:ad9235de` (random per mount) | `c954548f:00000013`: `st_dev`, then the type number |
| flags | `0x1022` (`ST_VALID\|ST_NOSUID\|ST_RELATIME`) | `0x4101000`, owner 0, mounted on `/dev` from `devfs` |

`fstatfs` on an open device answers the same as `statfs("/dev")`.

### 2.3 The namespace at `/dev`'s boundary (`NS`, `out/*-mountpoint.txt`)

| operation | Linux uid 1000 | Linux root | Darwin uid 501 |
|---|---|---|---|
| `rename(/tmp/f, /dev/x)` or `rename(/tmp/dir, /dev/x)` | EXDEV | EXDEV | EXDEV |
| `rename(/dev/null, /tmp/new)`, or onto an existing `/tmp` file | EXDEV | EXDEV | EXDEV |
| `rename(/tmp/f, /dev/null)` | EXDEV | EXDEV | EXDEV |
| `rename(/dev/nonexistent, /tmp/new)` | **EXDEV** | **EXDEV** | **ENOENT** |
| `rename(/tmp/nonexistent, /dev/new)` | **EXDEV** | **EXDEV** | **ENOENT** |
| `link(/tmp/f, /dev/x)` and `link(/dev/null, /tmp/new)` | EXDEV | EXDEV | **EPERM** |
| `open(/dev/x, O_CREAT\|O_EXCL)`, `mkdir`, `symlink` | EACCES | **succeeds**: devtmpfs is writable shmem, and the new file reports `st_dev 0,6` | **EPERM** (not EACCES) |
| `mknod(/dev/x, S_IFCHR 1,3)` | EACCES | succeeds | EPERM |
| `unlink(/dev/nonexistent)` | ENOENT | ENOENT | ENOENT |
| `chmod(/dev/null, 0666)` | EPERM (not owner) | succeeds | EPERM |
| `rmdir(/dev)` | EACCES | EBUSY | **EBUSY** |
| `rename(/dev, /devx)` | EACCES | EBUSY | **EXDEV** |
| `unlink(/dev)` | EACCES | EISDIR | **EBUSY** |
| `chmod(/dev, same mode)` | EPERM | succeeds | EPERM |
| `rmdir(/dev/.)` | EINVAL | EINVAL | **EBUSY** |
| `open(/dev/null, O_CREAT\|O_EXCL)` / `O_DIRECTORY` / `open(/dev/null/x)` | EEXIST / ENOTDIR / ENOTDIR | same | same |
| `access(/dev/urandom, R_OK\|W_OK)` / `X_OK` | 0 / EACCES | same | same |

**`/dev` is a mount point on both.**
- `readdir("/")` reports `dev` with the **covered** directory's inode: 14 on Linux and 1152921500312607380 on Darwin. `stat("/dev")` reports the mounted root's: 1 and 335.
- `getdents` of `/dev` reports `..` with `/dev`'s own inode on both, but `stat("/dev/..")` is `/`.
- `chdir("/dev")`, then `chdir("..")`, reaches `/`.

### 2.4 Listing `/dev` (`LIST`)

- Linux devtmpfs: 137 entries.
  - `.` and `..` first, then **newest first**: `urandom` (ino 6), `random` (5), `zero` (3), `null` (2). This is the tmpfs order the directories document measured.
  - Device nodes have `d_type` `DT_CHR` (2); `fd` and `stdin` are symlinks.
- Darwin devfs: 358 entries.
  - `.` and `..` first (both with `/dev`'s own inode), then **creation order**.
  - `fd` has `d_type` `DT_UNKNOWN`.
- Both listings are the machine's: which drivers registered nodes, and in what order.

### 2.5 Each device's operations (`== /dev/...` blocks)

Each row holds for all four devices unless it says otherwise. Linux rows are the same as root and as uid 1000.

| operation | Linux | Darwin |
|---|---|---|
| `open`: `O_RDONLY`, `O_WRONLY`, `O_RDWR`, `\|O_TRUNC` (even read-only), `\|O_APPEND`, `\|O_CREAT` on the existing node, `\|O_NOFOLLOW` | all succeed. `O_TRUNC` does nothing. | all succeed |
| `read` null | 0, buffer untouched, even through NULL or an unmapped address | same |
| `read` zero | zeros. NULL is EFAULT. A partly mapped buffer gives a short count (96 of 100 bytes). | zeros. NULL is EFAULT. **A partly mapped buffer is EFAULT.** |
| `read` random, urandom | the full count. NULL is EFAULT. A partly mapped buffer gives a short count (88 of 100: the arm64 copy granularity). | the full count. NULL and a partly mapped buffer are EFAULT. |
| `write` null, zero | the count, **buffer never read**: NULL with count 1 returns 1 | same |
| `write` random, urandom | the count, **at any uid**. The buffer is copied: NULL is EFAULT, and a partly mapped buffer gives a short count. | **urandom: EPERM for every write**, count 0 and NULL included. **random: accepted at uid 501**, and the buffer is copied (NULL is EFAULT). |
| `read` through an `O_WRONLY` descriptor, or `write` through `O_RDONLY` | EBADF | EBADF |
| `lseek` | **returns 0 for every whence 0–4 and every offset** (−1, 0, 1, 100, `INT64_MAX`). Neither `read` nor `write` moves the position. | `SEEK_SET`/`SEEK_END` accept any offset, **negative included** (−1 is returned as the new position). `SEEK_CUR` past `INT64_MAX` is EOVERFLOW. Whence 3 and 4 are **ENODEV**. **`read` and `write` advance the position** by what moved (zero, random and urandom: 100 after reading 100; null: 50 after writing 50). |
| `pread` | offset < 0 or `INT64_MAX` is EINVAL. Otherwise the offset is ignored. | offset −1 succeeds (16 bytes); `INT64_MAX` returns 0 |
| `pwrite` | offset < 0 or `INT64_MAX` is EINVAL | offset −1 is EINVAL and `INT64_MAX` is EFBIG, urandom included; at a valid offset urandom is EPERM |
| `ftruncate` | EINVAL, whatever the length and access mode | **0 through a read-write descriptor**, for length 0 or 10; −1 is EINVAL; read-only is EINVAL |
| `truncate(path, 0)` | EINVAL | EINVAL |
| `O_NONBLOCK` (by `open` or `F_SETFL`) | no effect | no effect |
| `poll`, all seven bits asked | **null, zero, urandom: `0x145`** (`POLLIN\|POLLOUT\|POLLRDNORM\|POLLWRNORM`), whatever the access mode. **random: `0x41`** (`POLLIN\|POLLRDNORM` only). | **`POLLNVAL` (`0x20`) for all four** |
| `epoll_ctl(ADD)` | **null, zero, urandom: EPERM** (no poll operation). **random: succeeds** and reports `EPOLLIN`. `MOD` with `EPOLLET` likewise. | — |
| `kevent(EV_ADD)` | — | `EVFILT_READ` and `EVFILT_WRITE` each fail as `EV_ERROR` with data 22 (EINVAL) |
| `flock` on two descriptions | `LOCK_EX` then `LOCK_EX\|LOCK_NB` is EAGAIN: they contend on the node | same |
| `fsync`, `fdatasync` | EINVAL | `fsync` 0 |
| `ioctl(FIONREAD)` | null, zero: ENOTTY. random, urandom: EINVAL. | ENODEV |
| `posix_fadvise` | 0 for valid advice; EINVAL for 99 | — |
| `isatty` | 0 | 0 |
| `close`, then `open` | the number is reused | the number is reused |

### 2.6 Timestamps (`out/*-times.txt`, `out/darwin-devfs-times.txt`)

- **Linux:** no `read` or `write` moves any timestamp, on any of the four devices, as root or uid 1000.
- **Darwin devfs:**
  - **Every `read` sets `atime` to the time of the read**, to the microsecond. That includes a zero-length read, and a read of `/dev/null` that returns 0. The new time is stamped at the read, not at the next `stat`: a `stat` 1.5 s later shows the read's time.
  - **Every `write` sets `mtime` and `ctime`**, including a zero-length one and **a `write` to urandom that fails EPERM**.
  - `open` and `close` move nothing.
  - Each of five reads 20 ms apart moved `atime`, so the updates are not lazy.
  - Other processes write `/dev/null` constantly, so its real `mtime` is never the boot time.

### 2.7 Read sizes and short reads (`out/*-bigread.txt`)

| | Linux | Darwin |
|---|---|---|
| counts `0x7FFFF000`, `0x7FFFF001`, `0x7FFFFFFF`, `2^31`, `2^32`, into storage that holds them | **all return `0x7FFFF000`** (`MAX_RW_COUNT`), on zero, random and urandom | up to `0x7FFFFFFF` **in full**; `2^31` and above are **EINVAL** |
| counts `SSIZE_MAX` and `SIZE_MAX` with a 5 GiB buffer | **EFAULT**: the buffer screen uses the count asked for, not the clamped one. **This differs from `getrandom`**, which clamps first and succeeds for `SIZE_MAX` (`UnixEntropy.getRandom`). | EINVAL |
| `SIGALRM` every ~50 µs (handler without `SA_RESTART`); reads of 16 MiB and 1 MiB (300 each) and 4097 bytes (20000) | **short whenever a signal arrives mid-read**, always a multiple of 4096 and at least 4096 (for 4097 bytes, always 4096). **Never EINTR** (0 of about 61,800 reads). | **never short and never EINTR** (0 of about 61,800 reads, about 10,600 signals) |

These are the platform's existing `TransferCountLimit` (`Shortened 0x7FFFF000` on Linux, `Refused INT_MAX` on Darwin) and `UserBufferCheck`. Devices need no new limit.

### 2.8 A node on another filesystem (Linux, root; `out/linux-mknod-node*.txt`)

`mknod` made `1,9` nodes on a fresh tmpfs (`size=0,nr_inodes=0`) and on ext4, and they were compared with devtmpfs's urandom.
- **What the holding filesystem decides:** `st_dev`, `st_ino`, the mode (here `umask`ed to 0644), the timestamps, and `fstatfs`.
- **What the driver decides:** read, write, lseek (0), poll (`POLLIN|POLLOUT`), `epoll` (EPERM) and `ftruncate` (EINVAL), identically on all three.
- No `read` or `write` moved a timestamp on any of the three filesystems.
- A node on `/dev/shm`, which is mounted `nodev`, cannot be opened (EACCES).

### 2.9 What CoreLib does to a device (`dotnet-device-usage.cs`, `out/linux-dotnet-device-usage.strace`)

The likely guest uses, under `strace` on .NET 10 Linux:

| guest code | syscalls on the device |
|---|---|
| `File.Exists("/dev/null")`, `new FileInfo("/dev/urandom").Length` | `newfstatat(AT_SYMLINK_NOFOLLOW)` |
| `File.OpenRead("/dev/urandom")`, then `Read` ×2, then `Position` | `openat(O_RDONLY\|O_CLOEXEC)`, `fstat`, `flock(LOCK_SH\|LOCK_NB)`, `lseek(0, SEEK_CUR)` (CanSeek: 0, so **CoreLib treats the device as seekable**), `pread64(4096, offset 0)`, `flock(LOCK_UN)` |
| `File.WriteAllText("/dev/null", …)` | `openat(O_WRONLY\|O_CREAT\|O_CLOEXEC, 0666)`, **`fstatfs`** (CoreLib asks the filesystem type before taking a shared lock for writing, `SafeFileHandle.CanLockTheFile`), `flock`, `ftruncate(0)` = EINVAL (which CoreLib ignores for special files), `lseek`, `pwrite64(offset 0)` |
| `File.AppendAllText`, `File.ReadAllBytes`, `new FileStream(..., FileAccess.Write)` + `Flush(true)` | the same set, plus `fstat`, and `pread64(512, 0)` returning 0 |

So `stat`, `open`, `fstat`, **`fstatfs`**, `flock`, `lseek`, `pread`, `pwrite` and `ftruncate` on a device are all in CoreLib's ordinary paths. **`fstatfs` matters to the choice in §3:** CoreLib reads only the type (Linux `f_type`, Darwin `f_fstypename`), but a write-open of `/dev/null` cannot get past it.

### 2.10 How the random entry points really get bytes

- **Linux build floor** (`out/linux-dotnet-glibc-floor.txt`).
  - `objdump -T` of the shipped 10.0.12 `libSystem.Native.so` finds no symbol version above `GLIBC_2.17` on arm64, or above `GLIBC_2.16` on x64. `libcoreclr.so` needs nothing above `GLIBC_2.27`.
  - `arc4random_buf` arrived in glibc 2.36, and neither library imports it. Both import `open64`, `read`, `time`, `srand48` and `lrand48`.
  - So `HAVE_ARC4RANDOM_BUF` was false in the build, and minipal takes the `/dev/urandom` + `lrand48` path. That agrees with #1687's `grep` of the same libraries.
- **Linux, at run time** (`out/linux-dotnet-urandom-strace.txt`).
  - **CoreCLR's own copy of minipal** opens `/dev/urandom` (fd 9) before `libSystem.Native.so` is loaded, and reads 16 bytes from it during startup.
  - **System.Native's copy** opens its own (fd 22) on the first call to either entry point. It then reads 16 bytes for `Guid.NewGuid` and 32 for `Random.Shared`'s seed. The non-secure path reads `/dev/urandom` too.
  - Both copies keep their descriptor for the life of the process.
- **`time(NULL)` is the coarse realtime clock** (`out/linux-timesrc.txt`).
  - On aarch64, across 493 million readings that did not straddle a second boundary, `time()` agreed with `CLOCK_REALTIME_COARSE` every time. 1.79 million of those disagreed with `CLOCK_REALTIME`.
  - Under Rosetta it agreed with `CLOCK_REALTIME` instead. That is Rosetta's emulation of the x86-64 vDSO, not evidence about an x86-64 kernel.
- **glibc's `srand48`/`lrand48`** (`out/linux-lrand48.txt`).
  - The algorithm is `X ← (0x5DEECE66D·X + 0xB) mod 2^48`, output `X >> 17`, with `srand48(s)` setting `X = (s mod 2^32) << 16 | 0x330E`.
  - A 12-line Python reference reproduces glibc 2.41's first four outputs for 8 seeds, on aarch64 and x86-64 alike. The seeds include 0, 2^32 and −1, which show the truncation to 32 bits.
- **Darwin libSystem** (`out/darwin-rng-interpose.txt`, `out/darwin-rng-reseed-*.txt`). Measured by interposing `getentropy` and `open` with `DYLD_INSERT_LIBRARIES`, plus a backtrace.
  - **One process-wide generator**: corecrypto's `ccrng_process`. `libSystem_initializer` seeds it **before `main`** with **one `getentropy(32)`**: `__malloc_init` → `arc4random_uniform` → `arc4_init` → `ccrng_prng` → `ccrng_process_init` → `ccrng_getentropy_generate`.
  - `CCRandomGenerateBytes` and `arc4random_buf` then made **no** `getentropy` call and no `open`, across sizes 1 B–1 MiB and 200,000 × 4 KiB each, all within 5 s of the startup seed.
  - `CCRandomGenerateBytes` never seeded a generator of its own, so it draws from the same one.
  - **A draw made 5 s or more after the last reseed first reseeds, with one more `getentropy(32)`** (`out/darwin-rng-reseed-interval-{cc,arc4}.txt`).
    - Bracketed between 4.9 s (no call) and 5.1 s (one call), the same for both entry points.
    - The clock runs from the last *reseed*, not the last draw: with a draw every second, the draw at 5 s reseeds.
    - Every gap from 5.1 s to 70 s gave exactly one call of 32 bytes, and a draw with no gap gave none.
  - Neither entry point takes a descriptor (#1687).

## 3. Where device nodes live

Two questions are independent of where the nodes live, and every option shares their answers:
- **The node is an inode kind.** §2.8 shows that a node's driver behaviour does not depend on the filesystem holding it, while its `stat` identity, timestamps and `fstatfs` come from that filesystem. So a character-device inode kind, with a driver chosen by its device, is needed in every option.
- **Which machine `/dev` belongs to.** The question below is what holds the nodes, and so what `st_dev`, `fstatfs`, rename/link and the mount-point rules report.

### A. A character-device inode kind on the one filesystem, seeded by the client
- **State.**
  - `InodeContent.CharacterDevice of device : CharacterDevice * permissions : PermissionBits`, and `SeedEntry.CharacterDevice` beside it.
  - PawPrint's `KernelConfig.toKernel` merges a `/dev` holding the configured nodes into whatever seed the host supplies, root-owned, mode 0755 for the directory and 0666 for the nodes.
  - This is the analogue of an initramfs image that carries static `/dev` nodes.
- **The machine it describes** is Linux with the configured root mount and no devtmpfs: an initramfs before `devtmpfs` is mounted, or a chroot with `mknod`'d nodes. **Every Linux answer is true for that machine.**
  - `/dev/null` reports `/`'s `st_dev`, and `fstatfs` reports the root mount. On the default tmpfs root that is `TMPFS_MAGIC`, which devtmpfs also reports, so CoreLib's `FileStream` takes the same path as on a real host.
  - `rename(/tmp/f, /dev/f)` succeeds where a real host says EXDEV, because on that machine `/dev` is not a mount.
  - Non-root creation in `/dev` is EACCES from the directory's mode. Root creation succeeds.
  - A name not seeded in `/dev` is ENOENT, which is true for a static `/dev`.
- **It is not the machine .NET runs on.** Every real host and container has a separate filesystem at `/dev`, so `st_dev`, EXDEV and the `statfs` counts differ from what a recorded production run would show.
- **Darwin: cannot be made true.**
  - Darwin always mounts devfs at `/dev`.
  - A node on APFS needs root to make, so its behaviour (timestamps, `fstatfs`) cannot be measured here.
  - devfs's own rules (§2.3, §2.6) belong to a filesystem this option does not have.
  - So Darwin device nodes would be refused in the seed. Darwin's random path does not need them (§2.10).
- **Cost.**
  - One inode kind (compiler-guided: about 300 mentions of `InodeContent`'s cases, mostly in `VirtualFileSystem.fs`, `UnixNamespace.fs` and tests), a seed case, and a device arm in each descriptor operation.
  - PathWalk and identity are untouched.
- **Reversibility.** The inode kind and the driver table carry over to C unchanged. Moving later changes the machine, and with it every pinned `st_dev` and EXDEV answer.

### B. A mount table of separate filesystems
- **State.**
  - `UnixMachineState` holds several `VirtualFileSystem`s and a table `(mount, covered directory) → mounted filesystem`.
  - Every inode identity becomes `(MountId, InodeNumber)`: `OpenFileTarget.File` and `Directory`, `flock` objects, pinned inodes, the current directory, and the rename, clone and copy rules.
  - The kernel mounts devtmpfs (Linux) or devfs (Darwin) at `/dev` at boot.
- **Answers.** True wherever it answers: `st_dev` and `statfs` per mount, EXDEV, the mount-point rules, the covered `d_ino`.
  - Per-filesystem inode numbering would let two filesystems both have an inode 2, as real ones do. That is *allowed* rather than *required*: any unique numbering is one some boot could produce.
- **Cost.** The largest: every `InodeNumber` consumer in the library, plus PawPrint's. It also buys things no consumer needs: bind mounts, and one filesystem mounted twice.

### C. One inode graph, tagged by filesystem, with a mount table over it (recommended)
- **State.**
  - One `Map<InodeNumber, Inode>` and one inode counter, as now, so `InodeNumber` stays the identity everywhere.
  - Each inode records the **filesystem it is on**: a superblock id. A superblock table holds each one's type and the configuration `st_dev` and `statfs` read: the root's existing `EmulatedMount`, plus a devtmpfs (Linux) or devfs (Darwin).
  - A mount table maps a **covered directory** in the root filesystem to the **mounted root** of another.
  - The kernel creates `/dev` at boot: an empty covered directory in the root and the device filesystem over it. A seed that already has a non-empty `dev` is refused at boot. `KernelConfig` chooses the device filesystem's configuration, or none.
- **What changes.**
  - The walk crosses a covered directory into the mounted root, and `..` from a mounted root goes to the covered directory's parent (§2.3).
  - `getcwd` names a mounted directory through its covered directory.
  - `stat` reads `st_dev` from the inode's superblock, and `statfs`/`fstatfs` read the superblock's statistics.
  - Rename and link answer EXDEV when the superblocks differ, in each flavour's check order. Linux decides EXDEV before the last component exists; Darwin decides ENOENT first, and answers `link` with EPERM.
  - `rmdir`, `unlink` and `rename` of a mount point follow §2.3. Linux: EACCES for a caller without write permission on `/`, otherwise EBUSY (EISDIR for `unlink`). Darwin: EBUSY, or EXDEV for `rename`.
  - `getdents` reports a covered directory's inode in its parent's listing, and a mounted root's own inode for its `..`.
  - The invariants learn that a mounted root is reachable through its covered directory.
- **The device filesystem is closed.** Its nodes are the configured devices, and the kernel answers only for them:
  - **A lookup of any other name in `/dev` is a typed refusal** (`UnmodelledDeviceName`), not ENOENT. A real devtmpfs or devfs always has hundreds of nodes (§2.4), so ENOENT for `/dev/tty` would be false.
  - Creation in `/dev` is refused for the same reason: whether the name exists is unknown. So is listing `/dev`.
  - Root operations on Darwin devfs are refused, being unmeasured.
  - Linux devtmpfs is answered as tmpfs where tmpfs rules apply: directory size and link count.
- **Answers.** True wherever it answers, on both flavours, for the machine .NET actually runs on.
- **Cost.** Between A and B.
  - Shared by both flavours: PathWalk's two crossing points, `getcwd`, the invariants, and a superblock lookup in `stat` and `statfs`.
  - The namespace rules are about a dozen rows, already measured.
  - Identity, and every descriptor kind's code, is untouched.
- **Reversibility.** C becomes B by splitting the graph along the tags, should a second root-like filesystem ever be wanted. The device inode kind and the driver table are the same in A, B and C.

### What each gets wrong, observation by observation

| observation | likely in a guest? | A | B | C |
|---|---|---|---|---|
| `stat` mode, `st_rdev`, `st_nlink`, owner, size of a device | **yes**: `File.Exists`, `FileInfo`, every `FileStream` open `fstat`s | true | true | true |
| `stat` `st_dev` / `st_ino` of a device | rare (same-file checks) | true for a static-`/dev` machine; differs from a real host | true (configured) | true (configured) |
| device timestamps | rare | Linux: true (boot instant, never moved). Darwin: refused. | true (Darwin devfs moves them, §2.6) | true |
| `fstatfs` of an open device | **yes**: every write-open by CoreLib | true for its machine (the root's type) | true | true: type, geometry, `f_fsid` (configured) and flags are answered; the capacity counts are refused on both flavours (per-field `CapacityRefusal`), since they count the machine's real node set |
| `statfs("/dev")` | rare (`DriveInfo`) | true for its machine | true | true, as above |
| `rename`/`link` across `/dev` | rare (`File.Move` to or from `/dev`) | true for its machine (no EXDEV) | true | true |
| creating a regular file in `/dev` | rare | true for its machine | true | refused (unknown names); answered for root on Linux only if devtmpfs is modelled as a full tmpfs |
| `getdents` of `/dev` | rare | true for its machine (only the seeded nodes, in the model's order) | true only with the full node set, so refused | refused |
| `rmdir`/`rename` of `/dev` itself | very rare | true for its machine (a plain directory) | true | true |
| `readdir("/")`'s `d_ino` for `dev` | very rare (CoreLib reads only name and type) | true for its machine | true | true |

## 4. Which devices, and how a device's behaviour is represented

**Representation: a closed DU of drivers, chosen at `open` from the node.**
- `CharacterDevice = Null | URandom` (with `Zero` and `Random` added when wanted).
- The node holds the `CharacterDevice` directly rather than a `(major, minor)` pair. The library has no `mknod`, so every node it holds is one it made, and no unknown number can reach `open`. If `mknod` arrives, the node switches to holding a number, and what `open` answers for a number with no driver would need measuring.
- `st_rdev` comes from a per-flavour table:
  - Linux's numbers, 1:3, 1:5, 1:8 and 1:9, are the mem driver's entries in Linux's documented device registry (and measured here), so they are platform facts.
  - Darwin's numbers (3:2, 3:3, 17:0, 17:1) were measured on one boot only, so they are configuration with measured defaults until a second boot or xnu's source shows which are fixed. They matter only once Darwin devfs exists.
- Each operation is a function matching on `(flavour, device)` and returning data, in the interpreter style the library already uses. Examples: a read's payload is `Nothing | Zeros of count | Entropy of EntropyDraw`, and readiness is the measured bits or EPERM.
- The open file description gets `OpenFileTarget.Device of inode * device * position : int64`.
  - Darwin keeps a position that reads and writes advance and `lseek` sets, negative included.
  - Linux's position is always 0.
  - A separate case, not `File`, so that a regular file's offset and a device's position cannot be confused.
- `ReadAnswer.Completed of ImmutableArray<byte>` needs a lazy payload for devices: a single read may move `0x7FFFF000` bytes, as `getrandom`'s `EntropyDraw` already avoids materialising.

**Which devices earn their place:**
- **`/dev/urandom`: yes.** It is the reason for this work.
- **`/dev/null`: yes (recommended).**
  - It is the most commonly opened device in real programs.
  - CoreLib's `FileStream` path over it uses `fstatfs`, `flock`, `ftruncate`, `lseek` and `pwrite` (§2.9), so it tests the descriptor rows on a second driver as soon as they exist.
  - Its rows are the simplest: reads return 0, writes return the count, neither touches the buffer, and Linux `lseek` returns 0.
  - Under A, leaving it out describes a static `/dev` without `null`: true but odd. Under C, a guest touching it would hit the typed refusal.
- **`/dev/zero`: not yet.** No known consumer. Its rows are measured and recorded here, so adding it later is a DU case.
- **`/dev/random`: not yet.**
  - It is *not* free on top of urandom: on Linux 6.18 it differs in `poll` (`POLLIN|POLLRDNORM` only, no `POLLOUT`) and in `epoll` (allowed, where urandom is EPERM), and on Darwin in `write` (accepted at uid 501, where urandom is EPERM).
  - Reads are the same as urandom on both, as the brief expected for Linux 5.6 and later. Measured: identical sizes, caps and short reads, and no blocking, since the pool is initialised.
  - No known consumer.

## 5. Reads from `/dev/urandom`

- **Largest single read.**
  - Linux: `min(count, 0x7FFFF000)`, after screening the buffer over the count asked for.
  - Darwin: the whole count up to `INT_MAX`, and EINVAL above it.
  - Both are the platform's existing `TransferCountLimit` and `UserBufferCheck`. The urandom-specific part is that **`getrandom` screens the clamped count and `read` the unclamped one** (§2.7).
- **Short reads.**
  - Darwin never returns one.
  - Linux returns one only when a signal arrives mid-read: at least 4096 bytes, in multiples of 4096, and never EINTR.
  - A read in this library is one step, so no signal can arrive during it, and a whole read is the true answer for an interleaving in which none did.
  - If a client lets a task enter `read` while a signal is already deliverable to it, Linux's source says it stops after the first page. That is unmeasured, since it cannot be arranged from user space without a race, so **a Linux device read of more than 4096 bytes with a deliverable signal pending is refused** (typed).
  - A partly mapped buffer (short on Linux at the architecture's copy granularity, EFAULT on Darwin) cannot be described by `UserBuffer` today, and stays out of scope.
- **Which stream.** The same `EntropyPool` that `getrandom` and `getentropy` draw from: a read of `n` bytes is `EntropyPool.take n`, exactly as `getrandom` of `n`. One machine, one entropy source. `/dev/random` would draw from it too.
- **Writes.**
  - Linux: random and urandom accept a write from any uid. They copy the buffer (EFAULT on NULL) and return the count. A real kernel mixes the bytes into its input pool, which reaches output only at the next reseed, and no process can tell, so the model **leaves `EntropyPool` unchanged**.
  - Darwin: a write to urandom is EPERM before anything else, and a write to random is accepted. Both stamp devfs's `mtime` and `ctime`, which needs C.

## 6. The PawPrint side (a separate PR)

### 6.1 Linux: be minipal
`EmulatedKernel` gains userspace state for **System.Native's** copy of minipal, beside `PosixSignalShim` and `CopyFileRangeSupport`:
```fsharp
type MinipalUrandom =
    | Unopened               // rand_des == -1, sMissingDevURandom == false
    | Open of fd : int       // the descriptor minipal keeps for the process's life
    | Missing                // open answered ENOENT: latched, every call returns -1
// and Lrand48 : uint64 option   // srand48 has not run / the 48-bit X
```
- **Secure bytes.**
  - On the first call, `openat("/dev/urandom", O_RDONLY|O_CLOEXEC)` through the kernel, retrying on EINTR as minipal does.
  - ENOENT latches `Missing`. Any other error leaves `Unopened` and returns −1, and the next call tries again.
  - Then `read` until the request is full: EINTR continues, any other error returns −1, and a short read loops.
  - **A read returning 0 is refused**: real minipal would spin forever. A guest can cause that by `dup2`ing `/dev/null` over the descriptor. A read that would sleep (a pipe `dup2`'d there) is refused too.
  - The bytes come from the kernel's `read`, not from a direct draw.
- **Non-secure bytes.**
  - The secure path runs first, and its result is ignored as minipal ignores it. On failure, the guest's buffer keeps its old contents, which PawPrint must then read back.
  - On the first call only, `srand48(time(NULL))`. `time` is `clock_gettime(CLOCK_REALTIME_COARSE)` through the kernel (§2.10), so the library must answer id 5 (§7, L0).
  - Then XOR `lrand48()` over the buffer: a fresh output at every fourth byte, low byte first, shifted right 8 for each following byte.
  - The `lrand48` state is PawPrint's, reproducing glibc exactly (§2.10).
  - `NonCryptoRandomState` is deleted. `NonCryptoRandom` stays: the scheduler uses it.
- **The held descriptor is guest-visible**, as on real Linux.
  - It takes a number, so the next `open` lands one higher.
  - `fstat` and `fcntl` on that number answer for `/dev/urandom`.
  - A guest's `close` of that number makes later secure draws fail. `Guid.NewGuid` then throws, as on real .NET.
  - `/proc/self/fd` is not modelled.
  - PawPrint stores only the number, as minipal's static does; the description lives in the kernel's table like any other.
- **The MVID.** CoreCLR's minipal is a second copy with its own descriptor, opened and read (16 bytes) before `Main` (§2.10). Options:
  - **M1 (recommended):** keep `getrandom(GRND_INSECURE)` for the MVID, with no descriptor. CoreCLR's startup descriptors (about 19 of them on real .NET, since the guest's first `open` is 22) are a divergence PawPrint already has and does not otherwise model. M1 draws the same bytes from the same pool that a read of CoreCLR's descriptor would.
  - **M2:** model CoreCLR's copy as a descriptor opened, and read for 16 bytes, at process start. This shifts every guest descriptor number and every pool draw by a constant, and models one of those 19 descriptors but not the others.
  - **M3:** share System.Native's descriptor. This is wrong: real .NET has two.

### 6.2 Darwin: one libSystem generator, seeded through `getentropy`
- **D2 (recommended).**
  - At process start, before `Main`, as `libSystem_initializer` does, PawPrint calls `getentropy(32)` through the kernel and seeds one userspace generator it owns.
  - `CCRandomGenerateBytes`, `arc4random_buf` and the MVID all draw from that generator: on Darwin, CoreCLR's minipal calls `CCRandomGenerateBytes` too.
  - **Reseeding follows the measured rule** (§2.10): a draw 5 s or more after the last reseed first calls `getentropy(32)` and reseeds. D2 measures the 5 s on the kernel's monotonic clock. The boundary itself is known only to within ±0.1 s, which no guest can resolve on a real machine either.
  - The generator algorithm is PawPrint's choice: corecrypto's DRBG output cannot be reproduced and need not be. Splitmix64 keyed by the 32 bytes is enough.
  - No descriptor is involved.
- **D1:** keep today's approach: `getentropy` passthrough for secure bytes, and a constant-seeded splitmix stream for non-secure ones. It never bypasses the kernel, but it has two streams where libSystem has one, and the non-secure stream never takes kernel entropy.
- Darwin's flow needs nothing from §3: no device is opened.

### 6.3 Guest-visible bytes
The default configuration is `linuxX64`, `WallClockEpochMs = 0`. For `EntropyStreamsDefault.cs`:

| row | changes? | why |
|---|---|---|
| `Guid.NewGuid()` | **no** | It is still the pool's first 16 bytes. Checked: the pinned `new Random()` values equal a fresh `NonCryptoRandom` stream's first 32 bytes (Python reproduction), so no non-secure draw happens before `Main`. A urandom read of 16 takes `EntropyPool.take 16`, like the `getrandom` it replaces. |
| `new Random()`, `Next()` ×2 | **yes** | The seed becomes pool bytes 16–47 XOR `lrand48` after `srand48(0)`, instead of PawPrint's separate splitmix stream. |
| secure 24 bytes | **yes** | The pool has moved 32 more bytes, for `Random`'s seed. |
| non-secure 24 bytes | **yes** | Pool bytes XOR the next six `lrand48` outputs. |
| second `Guid.NewGuid()` | **yes** | The pool has moved. |

Other effects to expect:
- Every Linux guest that touches either entry point now holds one more descriptor from its first call onwards. A fixture that predicts descriptor numbers (such as `EnumerateClosedFdSeeded.cs`) may move; the Guest suite will say which.
- On Darwin (D2), every random byte changes. Nothing pins Darwin bytes today except `TestMinipalRandom`'s Darwin chunking, which goes.
- `DynamicModuleVersionIdEntropy.cs` is unchanged under M1.
- This reverses #1512's choice to keep `new Random()` from shifting later GUIDs. That choice did not match either real platform: Linux's non-secure path reads urandom, and Darwin's two entry points share one generator.

## 7. PR split and order

| PR | content | depends on |
|---|---|---|
| **L0** (library, small) | Answer Linux `CLOCK_REALTIME_COARSE` (id 5) as the realtime clock, by `MONOTONIC_COARSE`'s argument. PawPrint's `time()` needs it. | — |
| **L1** (library) | **C only:** superblocks, the mount table, the walk crossing, the mount-point and EXDEV rules, per-superblock `st_dev`/`statfs`, and a device filesystem at `/dev` booted from `KernelConfig` with **stat-level answers only**: lookups, `stat`, `statfs`, the namespace rules and the refusals. `open` of a device is refused. Linux first; Darwin devfs either here or as **L1b**. | — |
| **L2** (library) | The `CharacterDevice` DU (`URandom`, `Null`), `OpenFileTarget.Device`, and each operation's measured rows: `open`, `read` (lazy payload, pool draws), `write`, `lseek`, `pread`/`pwrite`, `fstat`, `fstatfs`, `ftruncate`, `flock`, `poll`/`epoll` readiness, `O_NONBLOCK`, `FIONREAD`, `fadvise` and `close`. **Under A, L1 and L2 merge**: the inode kind, `SeedEntry.CharacterDevice` and these rows, for Linux only. | L1 (C) |
| **P1** (PawPrint) | §6: `MinipalUrandom` and `lrand48` on Linux, the libSystem generator on Darwin, the MVID under M1, the `/dev` configuration in `KernelConfig`, and re-pinning `EntropyStreamsDefault`. | L0, L2 |
| **L1b** (library, optional) | Darwin devfs as a superblock type: §2.3's EPERM rules, µs and birth-0 timestamps, and the read/write stamping of §2.6. Not needed by P1, because Darwin's random path opens nothing. | L1 |

L2 should not be split further: its rows are one table per device, and splitting by syscall would leave a device you can `open` but not `close`. L1 is the one to split if it grows: the walk crossing and `getcwd` alone, then the namespace rules.

## 8. Recommendation, and what is yours to decide

- **Where nodes live: C.**
  - It is the only option that is true on both flavours *for the machine .NET runs on*.
  - It is the only one under which Darwin devices can exist at all.
  - It costs less than B, because identity stays `InodeNumber`.
  - A is the cheap alternative, and every Linux answer it gives is true. But it describes an initramfs-style machine, and it describes nothing on Darwin. If you prefer A, L1 disappears, and L2 carries the inode kind and the seed instead.
- **Devices:** urandom and null now; zero and random later, their rows being recorded here.
- **PawPrint:** §6.1 on Linux; D2 on Darwin; M1 for the MVID.
- **Order:** L0 → L1 → L2 → P1, with L1b whenever Darwin devices are wanted.
- **Yours to decide:**
  1. A or C (or B).
  2. Whether null goes in now.
  3. M1 or M2 for CoreCLR's own descriptor.
  4. D1 or D2 for Darwin, and whether D2 reproduces the 5 s reseed (my recommendation) or reseeds only at start.
  5. Whether unknown names in `/dev` should be refused under C, rather than answered ENOENT under a "container-built `/dev`" configuration. The OCI default device set includes `tty`, `console`, `ptmx` and `full`, so a four-node container `/dev` is not OCI-conformant either.

## Decision (orchestrator, 2026-10-02)
1. **Option C:** one inode graph tagged by superblock, with a mount table, and the kernel mounts `/dev` at boot.
   - It is the only option whose answers are true for the machine .NET actually runs on, on both flavours.
   - Inode identity stays `InodeNumber`, which keeps its cost well below B's.
   - A is rejected: it describes a machine nobody runs (a static `/dev` with no devtmpfs), and it can't express Darwin at all.
   - B is rejected: it re-keys every inode identity to buy bind mounts and double mounts, which nothing needs.
2. **Devices:** `/dev/null` goes in now, beside urandom. `/dev/zero` and `/dev/random` wait for a consumer; their rows are already recorded.
3. **MVID: M1.** Keep `getrandom`.
4. **Darwin: D2.** One generator owned by PawPrint, seeded through `getentropy(32)` at start.
   - Reproduce the reseed only if Apple's published Libc or libplatform source pins its threshold exactly (for example, a named constant).
   - Otherwise seed once, and record the divergence in the generator's docstring.
   - This state belongs to the client's userspace, so it is not a kernel-correctness question.
5. **Unknown names in `/dev`:** a typed refusal, as recommended. There is no "container-built `/dev`" configuration, because nothing needs one yet.
   - A test seed that already has a non-empty `dev` is migrated, not grandfathered.
6. **PR order:**
   - **L0**, `CLOCK_REALTIME_COARSE`, off main. The coarse clock's tick is a platform fact: measure `clock_getres`, and state it as configuration if it depends on the kernel's build.
   - **L1**, mounts and `/dev` at the stat level, off main.
   - **L2**, the drivers, stacked on L1.
   - **P1**, the PawPrint side, stacked on L0 and L2.
   - **L1b**, Darwin devfs, comes later. Until then a Darwin-flavoured kernel has no device filesystem, and `/dev` lookups are refused, typed.
