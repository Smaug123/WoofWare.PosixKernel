# The `*at` calls, `link`, `symlink` and `mknod` in WoofWare.PosixKernel (audit #19)

*Options document, 2026-10-04. Part of the "PosixKernel knows nothing of the CLR" workstream. Code references are at `origin/main` `481fbde2`. The probes and their outputs are committed on branch `kernel-at-calls` (`45e1a40c`, `1a2826ad`) in `docs/plans/2026-08-23-posix-kernel-extraction/` as `at-dirfd.c` and `link-symlink.c`, each with one output per envelope beside it (called `$P` below).*

Audit #19 says these are absent: the `*at` calls (only `faccessat` exists), `link`/`linkat`, `symlink`/`symlinkat`, and `mknod`/`mknodat`.

## 1. What there is today

### 1.1 Path syscalls and how they start a walk

| family | plain forms in the library | `*at` forms |
|---|---|---|
| lookup | `stat`/`lstat` (`UnixPathResolution.stat`), `readlink` (`UnixNamespace.readlink`), `statfs`, `access` | `faccessat` only |
| open | `UnixNamespace.openPath` (open, `O_CREAT`, opendir's open) | none |
| namespace | `mkdir`, `unlink`, `rmdir`, `rename` (two phases), `clonefile` (Darwin, two phases) | none |
| attributes | `chmod`, `chown`, `lchown`; `fchmod`, `fchown`, `futimens` by descriptor | none |
| cwd | `chdir`, `getcwd` | no `fchdir` |
| absent | `link`, `symlink`, `mknod`, `mkfifo`, `utimensat` | all |

Every pathname crosses as `PathArgumentBytes` and is copied in by `UnixPathResolution.copyIn` (`UnixPathResolution.fs:386`), giving a `UnixPath`; an empty path parses, and the walk answers its ENOENT.

**Every walk starts in one of two internal functions**, `UnixPathResolution.resolvePathFull` (`:409`) and `resolvePathParent` (`:452`). They are the only readers of `system.Process.CurrentDirectoryInode` for a walk, and everything above them (about fifteen call sites in `UnixPathResolution.fs` and `UnixNamespace.fs`) inherits the cwd from them.

**`PathWalk` already takes an arbitrary start.** `PathWalk.resolveParent` and `resolveFull` (`PathWalk.fs:893`, `:950`) take `startDirectory : InodeNumber`. Their rules are:
- an empty path is ENOENT before the start is looked at;
- a rooted path ignores the start;
- a start the graph does not hold is ENOENT;
- a start that is not a directory is ENOTDIR;
- the start's search bit is checked when the first component is consumed, against its *current* mode.

`PathWalk` cannot see descriptors, so EBADF and the pipe or socket answers cannot come from it. A pipe's `InodeNumber` is not in the graph, and would read as ENOENT there.

**`faccessat` decodes its own `dirfd`.**
- The type is `AtDirectory = CurrentDirectory | Descriptor of fd` (`AccessRules.fs:50`).
- The raw value is decoded by `AccessRules.atDirectory` (`:157`): Linux's `AT_FDCWD` is -100 and Darwin's is -2. Each flavour's number is simply an unheld descriptor under the other.
- The start is decoded by hand in `accessWithPath` (`UnixPathResolution.fs:1626`, the `start` match at `:1664`):
  - a rooted path ignores `dirfd`;
  - an empty path follows `AccessEmptyPath`, which has three cases: Linux without `AT_EMPTY_PATH`, Linux with it, and Darwin;
  - a descriptor that is absent is EBADF; a `Directory` gives its inode; a `File` or `CharacterDevice` is ENOTDIR;
  - Pipe, Socket, Epoll and Kqueue are refused (`AccessRefusal.UnmodelledDescriptor`, "has not been measured"). §2.1 now measures them.

### 1.2 What a directory descriptor holds

- `OpenFileTarget.Directory of inode * position` (`FileDescriptorRegistry.fs:582`) holds the **inode number**, not a path.
- Every `File`, `Directory` and `CharacterDevice` description pins its inode, and so does the cwd (`UnixProcess.fs:245-257`).
- So a `dirfd` survives a rename of its directory, because identity is the inode.
- It also survives the directory's `rmdir`. The orphan stays in the graph with its `Parent`, so ".." works from it, which is already measured for the cwd (`ObjectLifetime.fs:46`). `VirtualFileSystem.isOrphanedDirectory` (`:1349`) is what the creating verdicts (`MkDirRules`, `CreatingOpenRules`, `RenameRules`) consult for the ENOENT that a creation inside an orphan gets.
- That is enough to resolve relative to a `dirfd` in every state §2.1 measures. Nothing in the descriptor needs to change.

### 1.3 Hard links and symbolic links in the graph

**Hard links are already supported by the graph.**
- `VirtualFileSystem.hardLink` (`:1147`) binds an existing inode under a second name. It refuses a directory with EPERM and asserts the root filesystem. It moves the target's `ctime` and, through `bind`, the directory's `mtime` and `ctime`.
- `BindingCounts` keeps every inode's name count. `bindingCount` (`:1313`) *is* `st_nlink` for a file or symbolic link, already measured (`TestLinkCount`, `TestBindingCount`), and the reported count is capped by `SimulatedUnixPlatform.linkCountCeiling`.
- Only tests and seeds call `hardLink`; no syscall does.

**Symbolic links exist only by seeding.**
- `VirtualFileSystem.createSymlink` (`:1125`) has no permissions parameter.
- A link's mode is `InodePermissions.PlatformSymlinkDefault` (`Inode.fs:303`), resolved by `SimulatedUnixPlatform.symlinkPermissions` (`:533`): 0777 on Linux, and on Darwin a fixed 0755, the `umask 022` answer.
- Its docstring names `symlink(2)` as the trigger for making the mode depend on the creating process's umask. The emulated-posix-kernel skill names that trigger too.
- `FileSystemSeed.Symlink` carries a target and an optional owner, with no mode (`FileSystemSeed.fs:39`).
- `SymlinkTarget` cannot be empty (`SymlinkTargetError.Empty`), and its docstring already notes that Darwin accepts an empty target.

**Device nodes** are `CharacterDevice.Null` and `URandom` on Linux's devtmpfs at `/dev`. The device filesystem is closed: the model refuses any other name in it.

### 1.4 Who would call these

PawPrint dispatches none of the shim entry points that would use them. In the pinned runtime (`pal_io.c`, `pal_time.c`):

| shim | calls | CoreLib caller |
|---|---|---|
| `SystemNative_Link` | `link(2)` | `FileSystem.Unix.cs:77` `LinkOrCopyFile`, which `File.Move` without overwrite reaches whenever the destination exists or the `rename` failed, and which `File.Replace` with a backup reaches |
| `SystemNative_SymLink` | `symlink(2)` | `File`/`Directory.CreateSymbolicLink` (`FileSystem.Unix.cs:666`) |
| `SystemNative_MkNod`, `SystemNative_MkFifo` | `mknod(2)`, `mkfifo(3)` | `System.Formats.Tar` extraction |
| `SystemNative_UTimensat` | `utimensat(AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW)` | `FileStatus.Unix.cs:420` (`File.SetLastWriteTime` and friends) |

**No shim entry point passes a real directory descriptor.** Every `*at` call it makes passes `AT_FDCWD`. So `dirfd` generality is for the library's other clients, and for a process that P/Invokes libc directly. PawPrint needs only the plain forms, and the guest-observable behaviour PawPrint gains from this work is `link`, `symlink` and later `mknod`.

### 1.5 A hazard already on main

`UnixSystemDefect<'Task>` (`UnixSystem.fs:118`) has **exactly 64 cases** at `481fbde2`. The tests match it with two outcomes in three places:
- `TestPipe.fs:1408`
- `TestDirectoryDescription.fs:728`
- `TestDirectoryDescription.fs:742`

That is the dotnet/runtime#131716 shape on x64 .NET 10.0.0–10.0.11. I have not checked whether CI's runtime is in that range. Any design below that adds a defect case moves it to 65.

`Syscall` has 30 cases and `SyscallRefusal` 22. None of the options brings either near 64.

## 2. Measured facts

**Envelope.**
- **Darwin:** 27.0.0 arm64, natively, as uid 501. There is no root, so no Darwin row is a root row.
- **Linux:** 6.18.5 aarch64 under Apple's `container` (image `gcc:14`, glibc), as root and as uid 1000 (`setpriv`). Probe directories were on ext4 `/tmp`.
- **Linux sysctls:** `fs.protected_hardlinks` was 0 by default. One extra run set it to 1 (`--cap-add ALL`, with `/proc/sys` remounted).
- **x86-64:** none of these facts is architecture-dependent, and no x86-64 kernel was used.

All calls go through libc, as the shim's do. glibc 2.41 passes every argument here straight through. On Linux, `link`, `symlink`, `mkdir` and the rest are the `*at` syscalls with `AT_FDCWD`, because aarch64 has no plain ones.

**Sweep.**
- `at-dirfd.c` crosses 19 calls with 13 directory arguments and 9 pathnames: 2223 cells per envelope, each run in a forked child with a fresh fixture.
  - Calls: `openat` plain and `O_CREAT`; `fstatat` with and without `NOFOLLOW`; `mkdirat`; `unlinkat` with 0 and `AT_REMOVEDIR`; `readlinkat`; `fchmodat`; `fchownat`; `faccessat`; `symlinkat`; `linkat` on its old side and its new side; `renameat` on each side; `mkfifoat`; `mknodat(S_IFREG)`; `utimensat`.
  - Directory arguments: own `AT_FDCWD`, the other flavour's, -1, a closed number, a directory, a file, a pipe, a socket, a removed directory, a renamed directory, a directory made mode 0 after opening, `/dev/null`, and an epoll instance or kqueue.
  - Pathnames: `f`, `nx`, `""`, NULL, a `PROT_NONE` page, `PATH_MAX` bytes with no NUL, an absolute path, `.`, `..`.
- `at-dirfd.c` also has three more sections:
  - `ORDER2`: `linkat` and `renameat` with five states per side;
  - `FLAGS`: each of seven flag-taking calls under every single flag bit, 0 to 31;
  - `FLAGORDER`: a rejected bit against a NULL path, a bad `dirfd` and the empty path.
- `link-symlink.c` measures:
  - 11 source kinds × `link`/`linkat(0)`/`linkat(FOLLOW)`;
  - 14 destination kinds;
  - 6 crossings of `/dev`;
  - 8 permission rows;
  - 17 `symlink` rows;
  - an empty target followed 7 ways;
  - 5 umasks;
  - the group rule;
  - 10 `mknod` types.

### 2.1 The starting-directory rule: one rule per flavour, shared by every call

Order, Linux:
1. The flag word, if the call has one: EINVAL.
2. The path's copy-in: EFAULT, ENAMETOOLONG.
3. **The empty path: ENOENT, before `dirfd` is looked at.**
4. A rooted path: `dirfd` is never looked at, whatever it is.
5. `dirfd`:
   - no such descriptor is EBADF, including the other flavour's `AT_FDCWD`;
   - any open descriptor that is not a directory is **ENOTDIR**: a file, `/dev/null`, a pipe, a socket or an epoll instance alike.
6. The walk starts at the descriptor's inode as it is *now*.

Order, Darwin:
1. The flag word, for every call except `utimensat`.
2. The copy-in.
3. A rooted path ignores `dirfd`.
4. `dirfd`, **even for the empty path**:
   - EBADF;
   - **ENOTDIR for a vnode that is not a directory** (a file, `/dev/null`);
   - **ENOTSUP for a descriptor that is not a vnode** (a pipe, a socket, a kqueue).
5. Then the empty path is ENOENT.
6. Then the walk.

Both flavours agree on what happens once the walk starts at the descriptor's directory:

| starting directory | `f` | `nx` | `.` / `..` | creating `nx` |
|---|---|---|---|---|
| a directory | found | ENOENT | found | created |
| renamed after it was opened | found (the walk follows the inode) | ENOENT | found | created |
| removed (`rmdir`) after it was opened | ENOENT | ENOENT | found; ".." is the old parent | **ENOENT** |
| chmod 0 after it was opened, non-root | EACCES | EACCES | EACCES | EACCES |
| chmod 0 after it was opened, Linux root | found | ENOENT | found | created |

The table is the same for all 18 calls (19 less `mknodat`, below). This is exactly how the cwd behaves today: the search bit is checked at walk time against the current mode, and an orphan is treated as the cwd's orphan is.

**A `dirfd` never changes a call's own rules.**
- With `.` or `..` from a directory descriptor, the divergences are the ones each call already has from the cwd:
  - `open(O_CREAT)` of `.`: Linux EISDIR, Darwin success;
  - `unlink(".")`: Linux EISDIR, Darwin EPERM;
  - `rename` of `.`: Linux EBUSY, Darwin EINVAL;
  - `rmdir("..")`: Linux ENOTEMPTY, Darwin EINVAL.
- They are identical whether the starting point is the cwd, a directory, a renamed directory or a removed directory.

**The exceptions to the shared rule** (`$P/at-dirfd.*.txt`):
- **Linux `readlinkat` with an empty path consults `dirfd`.** It is EBADF for a bad descriptor and ENOENT for anything else measured, since none is a symbolic link opened `O_PATH`. Every other Linux call answers the empty path ENOENT first.
- **Linux `utimensat` with a NULL path acts on `dirfd` itself.** It is EBADF for a bad descriptor and succeeds on any open one the caller may stamp, even a pipe (uid 1000 got EACCES on an epoll instance it does not own), while `AT_FDCWD` with NULL is EFAULT. Darwin answers EFAULT. glibc passes NULL through to the kernel.
- **Darwin `mknodat` is EPERM before anything else** for a non-root caller and a non-FIFO type, NULL path included (§2.8).
- **Darwin `utimensat` rejects no flag bit at all.** On Linux it rejects everything except `AT_SYMLINK_NOFOLLOW` (0x100) and `AT_EMPTY_PATH` (0x1000).

### 2.2 Two-path calls (`ORDER2`)

| | Linux `linkat` | Darwin `linkat` | Linux `renameat` | Darwin `renameat` |
|---|---|---|---|---|
| order | old copy-in, old `dirfd`, old walk *including its final lookup*, then new copy-in, new `dirfd`, new walk | the same | old copy-in, old `dirfd`, old parent walk, new copy-in, new `dirfd`, new parent walk, old final, new final | as `linkat` |
| absent old + NULL new | ENOENT | ENOENT | **EFAULT** | ENOENT |
| absent old + bad new `dirfd` | ENOENT | ENOENT | **EBADF** | ENOENT |

Linux's `renameat` row is the interleaving `PausedResolution` already models for `rename`. Each side's `dirfd` is decoded at the point that side's walk starts.

### 2.3 `AT_*` numbering and which bits each call accepts (`CONST`, `FLAGS`)

| | Linux | Darwin |
|---|---|---|
| `AT_FDCWD` | -100 | -2 |
| `AT_SYMLINK_NOFOLLOW` | 0x100 | 0x20 |
| `AT_SYMLINK_FOLLOW` | 0x400 | 0x40 |
| `AT_REMOVEDIR` | 0x200 | 0x80 |
| `AT_EACCESS` | 0x200 (the same number as `AT_REMOVEDIR`) | 0x10 |
| `AT_EMPTY_PATH` | 0x1000 | none (`fstatat` and `faccessat` reject 0x1000) |
| others | `AT_NO_AUTOMOUNT` 0x800, `AT_STATX_SYNC_TYPE` 0x6000 | `AT_REALDEV` 0x200, `AT_FDONLY` 0x400, `AT_SYMLINK_NOFOLLOW_ANY` 0x800, plus 0x2000 and 0x8000, named by #1662's `access-rules.c` as `AT_RESOLVE_BENEATH` and `AT_UNIQUE` |

Accepted bits per call (every other bit is EINVAL, screened before the copy-in and before `dirfd` on both flavours, except Darwin's `utimensat`):

| call | Linux accepts | Darwin accepts |
|---|---|---|
| `fstatat` | 0x100, 0x800, 0x1000, 0x2000, 0x4000 | 0x20, 0x200, 0x400 (then EBADF), 0x800, 0x2000, 0x8000 |
| `unlinkat` | 0x200 | 0x80, 0x100, 0x800, 0x1000, 0x2000, 0x4000, 0x8000 (0x80 and 0x100 both answered ENOTDIR on a file) |
| `fchmodat` | 0x100, 0x1000 (glibc → `fchmodat2`) | 0x20, 0x800, 0x2000, 0x8000 |
| `fchownat` | 0x100, 0x1000 | 0x20, 0x800, 0x2000, 0x8000 |
| `linkat` | 0x400, 0x1000 | 0x40, 0x800, 0x2000, 0x8000 |
| `utimensat` | 0x100, 0x1000 | every bit |
| `faccessat` | 0x100, 0x200, 0x1000 (agrees with #1662) | 0x10, 0x20, 0x800, 0x2000, 0x8000 (agrees) |

### 2.4 `link` and `linkat` (`$P/link-symlink.*`, `LINKSRC`, `LINKDST`, `LINKDEV`, `LINKPERM`)

**Plain `link` is `linkat(AT_FDCWD, …, AT_FDCWD, …, F)`, where F differs by flavour.**
- On Linux, F is 0: the link is not followed.
- **On Darwin, F is `AT_SYMLINK_FOLLOW`: plain `link` follows a symbolic link source.**
- Every `link` row equals the `linkat` row with that flag, on each flavour.

Sources:

| source | Linux `link` | Darwin `link` | `linkat(0)`, both | `linkat(FOLLOW)`, both |
|---|---|---|---|---|
| `f` | ok | ok | ok | ok |
| `lf -> f` | the link itself | `f` | the link itself | `f` |
| `ld -> d` | the link itself | EPERM | the link itself | EPERM |
| `dang -> nx` | the link itself | ENOENT | the link itself | ENOENT |
| `cyc -> cyc` | the link itself | ELOOP | the link itself | ELOOP |
| `d`, `d/`, `ld/` | EPERM | EPERM | EPERM | EPERM |
| `f/`, `lf/` | ENOTDIR | ENOTDIR | ENOTDIR | ENOTDIR |
| `nx` | ENOENT | ENOENT | ENOENT | ENOENT |

On success, on both flavours:
- the new name has the linked inode, whose `st_nlink` becomes 2 and whose `ctime` moves;
- the directory's `mtime` moves;
- when a link is followed, it is the target's `ctime` that moves, not the link's.

Destinations:

| destination | Linux | Darwin |
|---|---|---|
| `n`, `d/n`, `ld/n` | ok | ok |
| `g`, `dl` (dangling), `e`, `lf`, `e/`, `.` | EEXIST | EEXIST |
| `n/`, `nxdir/n` | ENOENT | ENOENT |
| `g/n` | ENOTDIR | ENOTDIR |
| `g/` (an existing file) | **EEXIST** | **ENOTDIR** |
| `dl/` (an existing dangling link) | **EEXIST** | **ENOENT** |

These trailing-separator rows are the same shape as `symlink`'s (§2.5). They are **not** `mkdir`'s Darwin rule: Darwin `mkdir("dang/")` creates the target, while `link` and `symlink` create nothing.

Crossing `/dev`:
- **Linux:**
  - `link("/dev/null", "n")` is EXDEV.
  - `link("f", "/dev/n")` is EXDEV, as uid 1000 too, so EXDEV comes before the EACCES that `/dev`'s mode 0755 would give.
  - `link("nx", "/dev/n")` is ENOENT.
  - `link("f", "/dev/null")` is **EEXIST, before EXDEV**.
  - Inside `/dev`, root succeeds and uid 1000 gets EACCES.
- **Darwin** (devfs, which the model refuses to walk into anyway): EPERM, with ENOENT for an absent source.

Permission, non-root:

| row | result |
|---|---|
| destination directory 0555 | EACCES, both flavours |
| source directory 0600 (unsearchable), source present or absent | EACCES |
| absent source with an unwritable destination directory | ENOENT: the source comes first |
| existing destination in an unwritable directory | **EEXIST before EACCES** |
| Linux, another user's file, `protected_hardlinks=0` | succeeds |
| Linux, another user's file, `protected_hardlinks=1` | 0600 and 0644 are **EPERM**; 0666, which the caller may read and write, succeeds |

Darwin has no such sysctl. Its other-user row was not measured, because there is no second user to own the file.

### 2.5 `symlink` and `symlinkat` (`SYMLINK`, `SYMEMPTY`, `SYMMODE`, `SYMGROUP`)

| row | Linux | Darwin |
|---|---|---|
| `t -> n`, `t -> ld/n` | ok | ok |
| empty target | **ENOENT** | **ok**: `st_size` 0, `lstat` ok, and every follow ENOENT (`stat`, `stat("n/")`, `stat("n/x")`, `open`, `open(O_CREAT)` creates nothing, `mkdir("n/")`, `chdir`) |
| target of `PATH_MAX`-1 bytes | ok (4095) | ok (1023) |
| target of `PATH_MAX` bytes | ENAMETOOLONG | ENAMETOOLONG |
| name exists: `f`, `dl` (dangling), `lf`, `d`, `d/`, `.` | EEXIST | EEXIST |
| `n/`, `nxdir/n`, empty name | ENOENT | ENOENT |
| `f/n` | ENOTDIR | ENOTDIR |
| `f/` | **EEXIST** | **ENOTDIR** |
| `dl/` | **EEXIST** | **ENOENT**, creating nothing |
| mode | **0777 under every umask** | **0777 & ~umask** (umask 0, 022, 077, 0777 and 0700 gave 0777, 0755, 0700, 0 and 077) |
| group | the effective group, or the directory's if it is set-group-ID | the directory's, always |

The group rule matches what a regular file in the same directory got in every row, so it is the existing `NewInodeGroupRule`.

### 2.6 What the empty path, `.` and `..` mean through a `dirfd`

These rows are covered by §2.1. Linux's `AT_EMPTY_PATH` semantics were not exercised; only the flag's acceptance was (§3).

### 2.7 `protected_hardlinks`

`fs.protected_hardlinks` is 0 in the container, which is the kernel's default; systemd distributions set 1. With 1, a non-owner may link only a regular file it may both read and write (the 0666 row). Rows with set-ID bits were not measured.

### 2.8 `mknod` and `mkfifo` (`MKNOD`)

| type | Linux root | Linux uid 1000 | Darwin uid 501 |
|---|---|---|---|
| `S_IFREG`, type 0 | regular file | regular file | **EPERM** |
| `S_IFIFO`, `mkfifo` | FIFO | FIFO | FIFO |
| `S_IFSOCK` | socket inode | socket inode | EPERM |
| `S_IFCHR`, `S_IFBLK` | device node (`makedev(1,3)`, raw 259) | EPERM, but EEXIST onto an existing name | EPERM |
| `S_IFDIR` | EPERM | EPERM | EPERM |
| `S_IFLNK`, `S_IFMT` | EINVAL | EINVAL | EPERM |

Darwin's EPERM comes before the path is even copied in. Linux screens the type first (EINVAL, or EPERM for a directory), then the name (EEXIST), then the privilege.

## 3. What is not measured

- **`O_PATH` (Linux) and `O_SEARCH` (Darwin) descriptors as `dirfd`.** An `O_SEARCH` directory grants search however it is later chmodded. Neither open flag is modelled, so both stay refused at `open`.
- **Linux `AT_EMPTY_PATH` semantics, call by call.**
  - Unmeasured: `fstatat` on the descriptor, `fchownat`, `fchmodat2`, `utimensat`, and `linkat` (which needs `CAP_DAC_READ_SEARCH`, or, since 6.10, the descriptor's opener's credentials).
  - Only which bits each call accepts is measured.
- **`fchmodat(…, AT_SYMLINK_NOFOLLOW)` on a symbolic link.** On Linux, `fchmodat2` probably answers EOPNOTSUPP. On Darwin it is `lchmod`, which changes the link's own mode, and that matters once links carry a mode (§6).
- **The full check order of `link`.** Partly measured: EEXIST comes before EACCES, the source's ENOENT before the destination's EACCES, and EEXIST before EXDEV, which comes before EACCES. Not measured:
  - `protected_hardlinks` EPERM against EACCES and against EEXIST;
  - a directory source's EPERM against the destination's EEXIST and EACCES;
  - the sticky directory.

  The `RenameRules` precedent says to measure the whole order in the PR that models `link`.
- **EMLINK.** Unmeasured:
  - whether APFS refuses the 65536th link of a file (`st_nlink` reporting is capped at 65535, which is measured);
  - whether tmpfs ever refuses.

  The model must refuse at Darwin's ceiling rather than guess.
- **Darwin root, everywhere.**
- **`renameat2` / `renameatx_np` flags**, `openat2`, `RESOLVE_*`, and `AT_SYMLINK_NOFOLLOW_ANY`. Darwin accepts the last on every call, and the model should refuse it as `faccessat` already does.
- **Darwin's other accepted `unlinkat` bits** (0x100, 0x1000, 0x4000). The model refuses them.
- **The `utimensat` time arguments.** Only NULL times were sent.
- **`symlink` timestamps and `ctime` details** beyond "the directory's `mtime` moves". The existing `bind` behaviour is presumably right, but no row says so.
- **x86-64 kernels.** These facts have no architecture dependence I can see.

## 4. The core question: where does a path resolution get its starting directory?

Inputs common to every option:
- the per-flavour start rule of §2.1;
- the empty-path rule, whose cases are "before the descriptor" (Linux), "after the descriptor" (Darwin) and "names the starting point" (Linux `AT_EMPTY_PATH` and Linux `readlinkat`);
- the non-directory descriptor answer: Linux ENOTDIR for every kind; Darwin ENOTDIR for a vnode and ENOTSUP otherwise;
- the decoding of a raw `dirfd` (`AT_FDCWD` per flavour).

Under the raw-versus-parsed rule these cross **raw**, because the library can classify a `dirfd` and owns its consequences. `FAccessAt of dirfd : int` already does this.

### Option A: every path syscall is its `*at` form, and the plain forms are sugar

**What changes.**
- `resolvePathFull` and `resolvePathParent` take the call's `AtDirectory` (and its empty-path rule) as a **required** argument. The compiler then finds every caller, and no walk can start from an implicit cwd any more.
- One internal `startOf` decodes it after the copy-in, in the measured order: rooted, then empty, then descriptor kind, then inode. It produces `Root | From of InodeNumber | NamedObject of InodeNumber`, or an errno.
- The per-flavour facts become data on `SimulatedUnixPlatform`, beside `creatingOpenRules`.
- `AtDirectory` and the `AT_*` numbering move out of `AccessRules` into a module of their own, in the style of `OpenFlagNumbering`.
- `faccessat`'s hand-written decode is deleted in favour of `startOf`. `AccessRefusal.UnmodelledDescriptor` is deleted, because it is now measured: **this removes a published case**.

**Public surface.**
- Each syscall gains its `*at` function as the primary definition: `openat`, `fstatat`, `readlinkat`, `mkdirat`, `unlinkat` (whose `AT_REMOVEDIR` selects the `rmdir` rules), `renameat`, `fchmodat`, `fchownat`, `linkat`, `symlinkat`, `mknodat`, `utimensat`.
- The plain names stay as one-line sugar with `AtDirectory.CurrentDirectory`, because PawPrint's shim calls those.
- `link`'s sugar takes its follow flag from a per-flavour fact, `SimulatedUnixPlatform.linkFollowsSymlink` (§2.4).
- In the `Syscall` DU, the plain cases (`MkDir`, `Unlink`, `RmDir`, `ChMod`, `ChOwn`, `LChOwn`, `Access`) become `*At` cases with a raw `dirfd`, as `FAccessAt` is. That is the kernel's own table: Linux on aarch64 has no plain `mkdir` at all.
  - This **changes published cases**.
  - The blast radius is the library and its tests (about 40 sites, 31 of them in tests). PawPrint does not use `Syscall`.

**Errors.** The order lives in one place, so it cannot differ between `stat` and `fstatat`. The two-path calls call `startOf` once per side, at the moment that side's walk begins. That is all §2.2 needs, and the Linux rename interleaving keeps its existing `PausedResolution` shape.

**Blast radius.** About 15 internal call sites change mechanically, to pass `CurrentDirectory`. Existing behaviour is bit-identical by construction, which a property test can hold: for random trees and paths, `X path ≡ Xat AtDirectory.CurrentDirectory path`.

**Reversibility.** High. Removing the argument again is mechanical, and the published `Syscall` change is the only one-way door.

**Information preserved.** All of it. A refusal or diagnostic can name which `dirfd` started the walk.

### Option B: keep the plain forms primary and add `*at` variants beside them

**What changes.**
- `resolvePathFull` keeps reading the cwd.
- A parallel `resolvePathFullFrom start` is added, and each new `*at` function does its own descriptor decode, then calls it. This is `faccessat`'s current shape, generalised.

**Errors.** The start rule is written once per `*at` function, or in a shared helper that the plain forms do not use. The plain and `*at` forms of each call are then two code paths for one kernel rule, kept in agreement only by tests.

**Blast radius.** Smallest today: no existing call path is touched. The `Syscall` DU grows instead (`MkDirAt` beside `MkDir`, and so on), so the DU has two ways of saying one syscall.

**Reversibility.** Easy to add, and expensive to remove later, because the deduplication is option A done afterwards.

**Information preserved.** The same as A.

**Against it.** This is the half-migration the principles warn about: two representations of "where a walk starts" coexist for good.

### Option C: anchor the path itself; the start becomes part of the path value

**What changes.**
- Copy-in plus decode produces an `AnchoredPath = { Start : PathStart ; Path : UnixPath }`.
- Resolution, and every rules module that takes a path, takes `AnchoredPath`, so a `UnixPath` alone can no longer be walked.
- `PathWalk.resolveParent` takes the anchor instead of `startDirectory : InodeNumber`.

**Against A.**
- In A the start is a second argument that travels beside the path. In C it is fused with the path, so a function that receives a path can never be handed the wrong start.
- The cost is that every rules module and `PausedResolution` changes type.
- A symbolic link's spliced target, which is re-anchored mid-walk, needs a separate un-anchored path type, which `UnixPath` already is.

**Errors.** As A. The anchoring happens per side, at that side's copy-in, which §2.2 permits on both flavours.

**Blast radius.** Larger than A. Every function that takes a `UnixPath` for walking, the rules modules, and their tests, perhaps 40 sites. It is mostly mechanical, and the compiler checks it.

**Reversibility.** Moderate.

**Information preserved.** The most: the anchor travels with the path into every verdict.

**Judgement.** C is A with the invariant pushed into a type. What it guards against is "walked with the wrong start", and A's required argument already makes that a compile error at every call site. Within the walk, the start is consumed at once. So the extra type buys little.

### Option D (listed to reject): run the plain call with the cwd temporarily replaced by the descriptor's directory

**What it does.** `fstatat(fd, p)` would set `CurrentDirectoryInode` to `fd`'s inode, call `stat p`, and restore the cwd. No existing code would change.

**Why not.**
- **It gets the order wrong.** The descriptor would be decoded before the copy-in (§2.1 needs it after), and for rooted paths, which never consult `dirfd`.
- Getting the order right means copying in inside the wrapper and calling a post-copy-in entry point. That entry point is A's internal function anyway.
- It also mixes a transient state change into what should be a pure computation of a start, which defeats local reasoning.

### Recommendation for §4: A

A puts the measured rule in one function, makes the cwd one case of the starting point, and turns "every plain call is its `*at` form with `AT_FDCWD`" from a property tested in two places into a fact of construction.

Its one one-way door is the `Syscall` DU, and I would take it, for the orthogonality argument. If Patrick prefers not to change published `Syscall` cases yet, A still works with the DU left as it is and `*At` cases added later. That would be A internally and B only at the DU, which is reversible.

## 5. Hard links in the graph

The graph's representation needs no change: `hardLink`, `BindingCounts` and the `st_nlink` reporting already exist and are tested. The decisions are about the rules around them.

### Option H1: a `LinkRules` verdict module, in the style of `RenameRules` and `RemovalRules`

A per-flavour verdict over the two resolutions decides:
- whether the source's final link is followed: the flag, and plain `link`'s per-flavour default;
- the source must exist (ENOENT);
- a directory source is EPERM, including `ld/`;
- the destination's trailing-separator rule (§2.4: Linux EEXIST on `g/` and `dl/`, Darwin ENOTDIR and ENOENT);
- EEXIST;
- an orphaned destination parent is ENOENT;
- EXDEV across mounts (Linux, after EEXIST) and the closed device filesystem;
- the destination directory's write and search permission (EACCES);
- Linux's `protected_hardlinks`.

`VirtualFileSystem.hardLink` does the binding. EMLINK is refused at `linkCountCeiling` until it is measured.

### Option H2: express `link` as `rename`'s destination half without the unbind

This would reuse `RenameRules`' destination checks. It fails at the first row: `rename` *replaces* an existing destination, and `link` answers EEXIST. The trailing-separator rows also differ from `rename`'s, and so does the follow rule. Sharing would mean a flag on every `RenameRules` branch.

### Recommendation: H1

H1 also needs one new **machine configuration** fact: `ProtectedFiles` gains `Hardlinks` (Linux 0 or 1, kernel default 0; Darwin `off` only).
- It belongs in `KernelConfig`, as `protected_symlinks` is, because two machines running the same kernel disagree on it.
- Adding it in its own PR first keeps `link`'s PR to one feature.

## 6. Creating symbolic links in the graph

### 6.1 A link's mode

**Option S1: every symbolic link inode stores its permission bits.**
- `InodeContent.Symlink of target * permissions`.
- A Linux link's bits are always 0777, which `checkInvariants` holds as a new `VirtualFileSystemDefect`. The 64-case hazard is on `UnixSystemDefect`, not here: that DU has 17 cases.
- A Darwin link stores `0777 & ~umask` at creation.
- A seed's link takes `symlinkPermissions` at seeding time, so every existing run is bit-identical.
- Removes:
  - `InodePermissions.PlatformSymlinkDefault`;
  - `SimulatedUnixPlatform.symlinkPermissions`, which is reduced to a seed-time default or deleted.

  **Both removals change the published API.**
- Prepares for Darwin's `lchmod` and `fchmodat(NOFOLLOW)`, which change exactly this field.

**Option S2: keep `PlatformSymlinkDefault` for seeded links and add a stored case for created ones.**
- No published removal.
- But there are then two representations of one fact: a seeded Darwin link would read the platform's 0755 while a created one reads its own bits. Every reader keeps matching on both.
- The skill already describes the platform default as "a deliberate approximation, with a named trigger". S2 would keep the approximation alive after its trigger has fired.

**Recommendation: S1**, as its own refactoring PR before `symlink`.

### 6.2 The empty target (Darwin only)

**Option E1: represent it.**
- `SymlinkTarget` admits empty under Darwin.
- The walk answers ENOENT on traversing it, which is measured for seven kinds of follow.
- `readlink` answers 0 bytes, and `lstat` size 0.
- `SymlinkTargetError.Empty` becomes a per-flavour verdict rather than a type-level refusal.

**Option E2: refuse it.**
- `symlink("", …)` under Darwin answers a typed refusal (`SymlinkRefusal.EmptyTarget`).
- Linux answers the measured ENOENT.
- `SymlinkTarget` stays non-empty.

**Recommendation: E2 first.** No known client makes an empty link. The refusal names the measured behaviour, and E1 can follow if a client ever needs it, without touching anything E2 built.

## 7. `mknod`

A FIFO, a socket inode and a character device other than the two existing ones are each new inode kinds:
- a FIFO needs a named pipe backed by `PipeBuffer`, with open-blocking semantics;
- a socket inode needs a binding to an `AF_UNIX` socket.

Neither is small. Recommended scope for the `mknod` PR:
- Linux `S_IFREG`/type 0 creating a regular file, exactly as `open(O_CREAT|O_EXCL)` would;
- the measured type screen and the EPERM rows;
- Darwin's EPERM, which precedes the copy-in;
- typed refusals for `S_IFIFO`, `S_IFSOCK` and root's device nodes.

`mkfifo` is refused outright until FIFOs exist. FIFOs are a separate feature, and they are larger than everything else in this document.

## 8. Linux against Darwin, in one place

| fact | Linux | Darwin |
|---|---|---|
| `AT_FDCWD` | -100 | -2 |
| empty path against `dirfd` | ENOENT first (except `readlinkat`, and `AT_EMPTY_PATH` calls) | `dirfd` first |
| `dirfd` naming a pipe, socket or event queue | ENOTDIR | ENOTSUP |
| `dirfd` naming a file or device | ENOTDIR | ENOTDIR |
| `renameat` with an absent old path and a bad new argument | the new side's EFAULT/EBADF | the old side's ENOENT |
| plain `link` follows a symbolic link source | no | yes |
| `link`/`symlink` onto `g/` (a file) | EEXIST | ENOTDIR |
| `link`/`symlink` onto `dl/` (a dangling link) | EEXIST | ENOENT, creating nothing |
| `symlink` with an empty target | ENOENT | creates an unfollowable link |
| new symbolic link's mode | 0777 | 0777 & ~umask |
| new symbolic link's group | the effective group, or the set-group-ID directory's | the directory's |
| `protected_hardlinks` | configuration, 0 or 1 | none |
| unprivileged `mknod(S_IFREG)` | creates a file | EPERM before copy-in |
| `utimensat` flag screen | rejects all but 0x100 and 0x1000 | rejects nothing |

## 9. PR breakdown, one feature each, smallest first

0. **Probes** (this branch, `kernel-at-calls`, two commits). Also: transcribe §2's rows into the flavour-divergence index when the first modelling PR lands.
1. **The starting directory** (A's core).
   - Add `AtDirectory` and the `AT_*` numbering module, and `startOf` with the per-flavour rules.
   - Give `resolvePathFull`/`resolvePathParent` the required argument, and every existing caller `CurrentDirectory`.
   - Move `faccessat` onto `startOf`, answering ENOTDIR or ENOTSUP where it refused before. This is **the only behaviour change**, and it is guest-visible only through a raw `faccessat` on a pipe, which PawPrint does not dispatch.
   - Remove `AccessRefusal.UnmodelledDescriptor`.
   - Tests:
     - `at-dirfd`'s `faccessat` rows replayed per flavour;
     - a property that every existing plain call equals its `CurrentDirectory` form over generated trees;
     - mutation-tests of the rule's arms (empty-before or after the descriptor, the descriptor kinds, rooted paths skipping the descriptor).
2. **`fstatat`.** The first new `*at` syscall, read-only, with its flag screen (`AT_SYMLINK_NOFOLLOW`; Linux's `AT_EMPTY_PATH` refused until measured).
3. **`readlinkat`**, including Linux's empty-path quirk.
4. **`openat`**, then **`mkdirat`**, **`unlinkat`** (`AT_REMOVEDIR` dispatching to the `rmdir` rules), **`renameat`** (two `dirfd`s; §2.2), and **`fchmodat`/`fchownat`**, one PR each. The `Syscall` DU's plain cases become `*At` cases in the PR that adds each one.
5. **Stored symbolic-link modes** (S1). A refactoring PR, bit-identical for every existing run.
6. **`symlinkat`/`symlink`**, with E2's refusal, the trailing-separator rows, the mode under the umask and the group rule. Plus PawPrint's `SystemNative_SymLink`, and an `sourcesImpure` wiring guest under both flavours with the umask away from 022.
7. **`ProtectedFiles.Hardlinks`**: configuration only, with its Linux rows and Darwin's `off`-only check.
8. **`linkat`/`link`** (H1, `LinkRules`).
   - Before writing the verdict, measure the full check order (§3).
   - Plain `link` follows on Darwin.
   - EMLINK is refused at the ceiling.
   - Plus PawPrint's `SystemNative_Link`. `File.Move` onto an existing destination is the guest test, together with a pure differential case where the flavours agree.
9. **`utimensat`**, then PawPrint's `SystemNative_UTimensat`. Not in the audit item, but it is the shim's one `*at` entry point.
10. **`mknodat`/`mknod`**, with the scope of §7, plus PawPrint's `SystemNative_MkNod`, refusing what §7 refuses. FIFOs are a separate project.

PRs 5 to 8 do not depend on 2 to 4, so they could come straight after 1 if Patrick wants the guest-visible features (`File.CreateSymbolicLink`, `File.Move` onto an existing file) sooner.

## 10. Recommendation

- **§4: option A.** One required starting-directory argument through the two internal resolution entry points, one per-flavour `startOf`, `*at` forms primary and plain forms as sugar, and the `Syscall` DU moved to the `*at` cases as each one lands.
- **§5: H1**, a `LinkRules` verdict over the existing `hardLink`, with `protected_hardlinks` added as configuration first.
- **§6: S1**, storing each link's mode, then **E2**, refusing Darwin's empty target.
- **§7:** a narrow `mknod`, with FIFOs left for later.

Decisions for Patrick:
1. Whether to change the published `Syscall` cases now (A in full) or only internally (A, with B at the DU).
2. Whether to accept S1's removal of `PlatformSymlinkDefault` and `symlinkPermissions` from the published API.
3. The order of PRs 2–4 against 5–8.
4. Whether the 64-case `UnixSystemDefect` on main (§1.5) needs looking at first.

## Decisions (orchestrator, 2026-10-04)
- **Starting directory: option A.** The two resolution functions take a required `AtDirectory`, decoded once per flavour; the `*at` forms are primary and the plain forms sugar. B keeps two code paths for one rule; C adds a type for little gain; D gets the error order wrong.
- **Published `Syscall` cases move to their `*At` forms now**, each in the PR that models that call. The package has never been published, and keeping plain cases beside `*At` ones would be two versions of the truth.
- **Hard links: H1** (`LinkRules` over the existing `hardLink`, `ProtectedFiles.Hardlinks` first as configuration).
- **Symbolic links: S1.** Store the mode on each link inode and remove `PlatformSymlinkDefault` and `symlinkPermissions`, for the same reason as above. The empty target is a typed refusal (E2) until a client needs it.
- **`mknod`:** the narrow scope (regular files and the measured screens; FIFOs, sockets and devices refused).
- **Order:** 1 (core), then the client-visible 4–7 (stored modes, `symlink`, `ProtectedFiles.Hardlinks`, `link`), then 2–3, 8, 9.
- The 64-case `UnixSystemDefect` matches the survey flagged (`TestPipe.fs`, `TestDirectoryDescription.fs`) do not trigger dotnet/runtime#131716: the IL scan of the Release build found only `TestPollTimeout`'s filter, now rewritten, and main's x64 CI is green. #1734 takes the union to 65, and the devshell is moving to runtime 10.0.12.

## Update (2026-10-10)

#1835 measured the Darwin link-mode case that §3 lists as unmeasured (probe `lchmod-rules.c`) and models `fchmodat(AT_SYMLINK_NOFOLLOW)` on Darwin. Darwin's libc `lchmod` is `setattrlist`, not `fchmodat`, and is not modelled.
