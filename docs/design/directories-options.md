# Directory enumeration in WoofWare.PosixKernel: `DIR*` out, `getdents` in

*Options document, 2026-09-26. Part of the "PosixKernel knows nothing of the CLR" workstream. Code references are at `origin/main` `d1d34c9d`. Probes, raw outputs and analysis scripts are in `/private/tmp/claude-501/-Users-patrick-Documents-GitHub-WoofWare-PawPrint/8343d887-fd13-443f-a0e2-dd127c2cbf72/scratchpad/directories/` (called `$P` below).*

## 1. What there is today

The library models glibc's `DIR`, not the kernel.

- **The stream is process state, not description state.**
  - `UnixProcessState.DirectoryStreams : Map<DirectoryStreamId, DirectoryStream>` and `NextDirectoryStreamId` (`UnixProcess.fs:115-117`).
  - `DirectoryStream = { Fd; Inode; Cursor }` (`VirtualFileSystem.fs:264-275`). Its docstring (`:258-263`) admits that "a `dup` of the descriptor would not share the cursor".
  - The descriptor `opendir` opens is an ordinary `OpenFileTarget.File (inode, 0)` whose offset never moves (`UnixNamespace.fs:519-521`). So `lseek(fd, 0, SEEK_SET)` does not rewind, and `SEEK_CUR` always answers 0. `docs/divergences.md` ("A directory stream's descriptor keeps an offset of zero") records that as a choice.
  - `heldInodes` pins every stream's inode (`UnixProcess.fs:305-335`), for a guest that closes the stream's descriptor behind libc's back. That is a hold a real kernel does not have: it exists only because the library owns libc's state.
- **The API is the shim's.**
  - `opendir` returns `OpenDirAnswer.Opened of DirectoryStreamId`, a `DIR*` by another name (`UnixNamespace.fs:100-111`, `:499-541`).
  - `readdir` returns `ReadDirAnswer.Entry of name * kind` (`:114-124`, `:549-587`). That is exactly `pal_io.h`'s `DirectoryEntry {Name, NameLength, InodeType}` minus the length: no `d_ino`, and no `d_off`.
  - There is no `closedir`, and no `getdents` or `getdirentries`.
- **Library invariants for libc state.** `UnixSystemDefect.DanglingDirectoryStreamInode`, `DirectoryStreamIsNotADirectory` and `NextDirectoryStreamIdNotFresh` (`UnixSystem.fs:89-94`, `:366-383`), and the "stranded streams" guard in `withFileSystemAndCurrentDirectory` (`:941-946`).
- **The walk.** `VirtualFileSystem.nextDirectoryEntry` (`VirtualFileSystem.fs:1248-1294`) and `DirectoryCursor = Start | After name | ReturnedDotDot | ReturnedDot` (`:228-240`).
  - The order is names in unsigned byte order, then `..`, then `.`. This is a deliberate "least convenient" choice (`docs/divergences.md`, "Directory enumeration order is the model's own").
  - A mutation is seen by name: `readdir` yields the least live name above the cursor.
  - An `rmdir`'d directory is at end-of-stream at once.
- **How PawPrint uses it** (`NativeSystemNative.fs`):
  - `SystemNative_OpenDir` (`:2672`) calls `UnixNamespace.opendir`, allocates a native block to be the `DIR*` and the `d_name` buffer, and binds them with `EmulatedKernel.withDirectoryStreamBlock`.
  - `SystemNative_ReadDir` (`:2775`) calls `UnixNamespace.readdir` once per guest call, with no buffering. It encodes `DT_*` itself, and `NameLength` via `DirectoryEntryPal`.
  - `SystemNative_CloseDir` (`:2891-2932`) assembles `closedir` by hand: `EmulatedKernel.withoutDirectoryStream` edits `kernel.Process with DirectoryStreams = Map.remove …` directly (`EmulatedKernel.fs:1604-1612`), then it frees the block, calls `UnixDescriptor.close stream.Fd`, and calls `forgetIfUnheld`.
  - `EmulatedKernel.DirectoryStreamBlocks : Map<NativeMemoryBlockId, DirectoryStreamId>` (`EmulatedKernel.fs:731`) has invariants in both directions plus injectivity (`:1717-1745`).
- **What reaches the shim.** CoreLib reaches directories only through `OpenDir`/`ReadDir`/`CloseDir`, and `FileSystemEntry` reads only `Name`, `NameLength` and `InodeType` (falling back to `stat` on `DT_UNKNOWN`). Nothing in CoreLib calls `dirfd`, `telldir`, `seekdir` or `lseek` on a directory. So `d_ino`, `d_off` and the descriptor's position are observable only by a guest that guesses the descriptor number (`sourcesImpure/EnumerateClosedFdSeeded.cs` does exactly that).
- **Stale prose.** `DirectoryEntryPal.fs:25` names `SystemNative_ReadDirR`, which .NET 10's shim no longer has.

## 2. Measured facts

**Envelope.**
- Linux 6.18.5 aarch64 (Apple `container`, image `gcc:14`, glibc 2.41), on `/dev/shm`, which is tmpfs (magic `0x01021994`). The container's `/` (ext4 without `dir_index`) was measured only as a contrast.
- Darwin 27.0.0 (macOS 27.0, arm64) on APFS (a case-insensitive volume; `/private/tmp`).
- The syscalls were called directly: `syscall(SYS_getdents64)` on Linux and `__getdirentries64` on Darwin. Records were parsed from raw bytes at explicit offsets.
- `linux_dirent64` is architecture-independent, so an aarch64 kernel suffices for its layout. No x86-64 kernel was used.

| # | fact | Linux / tmpfs | Darwin / APFS | raw |
|---|---|---|---|---|
| 1 | record layout | `d_ino` u64 @0, `d_off` s64 @8, `d_reclen` u16 @16, `d_type` u8 @18, name @19, NUL, zero padding. `reclen = align8(20 + namlen)` | `d_ino` u64 @0, `d_seekoff` u64 @8, `d_reclen` u16 @16, `d_namlen` u16 @18, `d_type` u8 @20, name @21, NUL, zero padding. `reclen = (namlen + 32) & ~7`. **`d_seekoff` is 0 in every record** | `layout-*.txt` `LAYOUT rec` |
| 2 | padding bytes after the NUL | zero in every record | zero in every record | `pad_nonzero=0` |
| 3 | `d_ino` | equals `lstat`'s `st_ino` for every name, for `.`, and for `..` (the parent's). A hard link reports its target's inode | same | `LAYOUT ino_check` |
| 4 | `d_type` | dir 4, reg 8, lnk 10, fifo 1, sock 12; dots 4. **Never `DT_UNKNOWN`** | identical | `LAYOUT rec` |
| 5 | smallest buffer | EINVAL whenever the first record of *this* call does not fit (0..23 bytes for a 24-byte dot; 24..279 bytes for a 280-byte name after the dots) | **EINVAL below 64 bytes whatever the entry.** At 64 or more, when the next record does not fit, it answers **0, a false end-of-file**, and consumes nothing: a larger buffer then returns the entry | `BUFSWEEP*`, `TOOSMALL` in `mutate-*-1.txt` |
| 6 | trailing flags word | none | when the buffer is 1024 bytes or more, the **last 4 bytes are a flags word**, with bit 0 set at end-of-directory; below 1024 they are ordinary record space. `basep` receives the position *before* the call | `darwin-eofflag.txt` |
| 7 | the cursor is on the open file description | a `dup` continues where the original stopped, and draining one drains both; a second `open` starts afresh | same | `CURSOR dup_*` |
| 8 | `lseek(fd, 0, SEEK_SET)` | rewinds | rewinds | `CURSOR rewind` |
| 9 | position values | `.` is 0; `..`'s `d_off` is 1; each name's offset comes from a **per-directory counter from 3 at link time**; end-of-directory is **`0x7FFFFFFF`**. Seeking to any `d_off` resumes exactly (all 20 rows). `SEEK_SET v` accepts any v ≥ 0 | `SEEK_CUR` reports `(k << 32) \| n`, where n is the entries returned so far on this description and **k is a per-directory counter that every call stopping mid-directory increments, across opens** (12 consecutive opens, two directories interleaved); end-of-directory is **`0x7FFFFFFF`**. For `SEEK_SET v` with a high word of 0, v ≥ 2 skips v entries (v = 1 also skips both dots); v = 2^62 makes the next call EAGAIN | `CURSOR cookie`, `CURSOR arbitrary`, `COOKIE` |
| 10 | `SEEK_END` / `SEEK_DATA` / `SEEK_HOLE` on a directory | EINVAL / EINVAL / EINVAL | `st_size` (640 for 18 names, agreeing with #1523) / ENXIO / ENXIO | `CURSOR whence` |
| 11 | error answers | bad fd EBADF; regular file ENOTDIR, even with count 0; pipe ENOTDIR; `O_PATH` descriptor EBADF; NULL or wild buffer EFAULT | bad fd EBADF; regular file **EINVAL**; pipe **ENOTSUP (45)**; NULL buffer EFAULT | `ERRORS` |
| 12 | a directory removed by `rmdir` | **ENOENT**: before the first read, after a partial read, and after a rewind | **0 (end-of-file)** in all three cases | `ERRORS removed_*` |
| 13 | `.` and `..` | always first, at positions 0 and 1 | always first | `ORDER`, `apfs-unicode.txt` |
| 14 | **order among the names** | **newest link first.** Reverse creation order in 320/320 trials; a rename (to a fresh name, or over an existing one) moves the entry to the front; a recreated name goes to the front. The order is **not** a function of the name set (20/320 agreed across two creation orders, by chance) | **a function of the names alone** (320/320 trials agree across two creation orders): ascending `(~crc32c(UTF-32LE(casefold(NFD(name))))) & 0x3FFFFF`, **ties broken by name bytes** (20/20 searched hash collisions; the length field in APFS's key is not used). Reproduced for 1055/1055 listings, and for Latin-1, Greek, Cyrillic, combining, CJK, emoji and special-fold names (ß, ẞ, İ, ı, ς, ﬁ, ǅ, K) with Python's `casefold` and NFD | `analyse_order.py`, `apfs_hash.py`, `apfs_unicode.py`, `apfs-collisions.txt` |
| 15 | **mutation mid-scan, one record per call** (9 operations, including create, unlink ahead or behind, rename ahead or behind, rename over, delete-last-and-create, and mkdir; 1280 cases per flavour over 8 seeds) | **deterministic, 1280/1280**, with this model: the list is in newest-link order; a plain rename takes a fresh offset, and a rename-over inherits the target's; the position names the *next* entry's offset; a resume starts at the entry with the greatest offset ≤ the position and walks list order; with none, it **restarts from the newest entry**. That re-yields names already returned in **79/1280** cases (unlinking the next entry when it is last; a rename onto or of the next entry) | **deterministic, 1280/1280**: the continuation is the live names whose key is > the last-returned key, in key order; **once a call has returned the last entry, end-of-file is sticky**, and a name created afterwards is never seen | `tmpfs_model.py`, `analyse_mutate2.py`, `mutate-*.txt` |
| 16 | deleting each name as it is returned | 3000 names, buffers of 24, 256, 4096 and 65536 bytes, 3 repetitions each: nothing skipped, directory empty | same, with buffers of 64, 256, 4096 and 65536 bytes | `DRAIN` |
| 17 | libc over the syscall | glibc 2.41: `opendir` is `openat(O_RDONLY\|O_NONBLOCK\|O_CLOEXEC\|O_DIRECTORY)`; reads use a **32 KiB** buffer; `telldir` is the `d_off` cookie and `seekdir` round-trips; `readdir` on an `rmdir`'d directory is NULL with errno 0 (glibc turns ENOENT into end-of-file) | libc: `FD_CLOEXEC` set, `F_GETFL` 0; reads use an **8 KiB** buffer (interposed) and stop on the flags word without a final 0-returning call; `telldir` is a small libc-side index (1, 2, 3, …) and `seekdir` round-trips | `glibc-readdir-strace.txt`, `darwin-readdir-interpose.txt`, `LIBC` |

**Three findings contradict current prose, and should be corrected whatever is chosen:**
- **Mutation mid-scan is a kernel fact at the syscall level.** `docs/divergences.md` and the skill's divergence table say both kernels' answers are "buffering artefacts". That is true only through libc. At the syscall level both modelled filesystems have an exact, reproducible rule (row 15).
- **"No real order can be reproduced" is false for tmpfs and APFS.** tmpfs orders by link history and APFS by a hash of the name (row 14). The disagreeing CI machines were ext4, whose htree order is not modelled here.
- **`DirectoryCursor`'s docstring says a real filesystem hands out "a stable per-entry cookie rather than an index".** APFS's position *is* an index in its low word (row 9), resumed by key through a per-directory cache. tmpfs re-yields entries after some mutations. Both drain cleanly under delete-as-returned (row 16), which is the claim the docstring needs.

## 3. Designs

Two decisions are independent: **where the stream lives, and what the kernel primitive is** (A, B, C), and **what order and mutation semantics the directory index has** (O1, O2). The recommendation combines A with O1.

### A. `getdents` on the open file description; `DIR*` belongs to the client
- **State.**
  - A new `OpenFileTarget.Directory of inode * position : DirectoryPosition`, separate from `File`, so that a regular file's description can never hold a directory cursor.
  - `DirectoryPosition = Start | After of DirectoryEntryName | ReturnedDotDot | ReturnedDot | Unenumerable of int64`. This is today's `DirectoryCursor` moved onto the description, plus one case for a position the model can report but not enumerate from.
  - Deleted: `DirectoryStreams`, `NextDirectoryStreamId`, `DirectoryStream`, `DirectoryStreamId`, `OpenDirAnswer`, `ReadDirAnswer`, the three `UnixSystemDefect` cases, the stream clause of `heldInodes`, and the stranded-stream guard. These are removals from the published API.
- **API.**
  - `opendir(3)` is `open(O_RDONLY|O_DIRECTORY|O_CLOEXEC)` (row 17). So the library gains an `O_DIRECTORY` field on `OpenFlags` for the existing `UnixNamespace.openPath`, rather than a separate entry point. `OpenDirRules`' measured rows must then come out of `openPath` with that flag (stage 2 checks this). `openPath` on a directory, with or without the flag, yields a `Directory` description, because a plain `open(dir, O_RDONLY)` can be read with `getdents` on both kernels.
  - `readDirectoryEntry fd` is the parsed step: `{ Inode; Name; Kind }`, end-of-directory, or an errno per flavour (EBADF; ENOTDIR on Linux or EINVAL on Darwin for a non-directory; ENOENT on Linux or end-of-directory on Darwin for a removed directory).
  - `lseek` on a directory: `SEEK_SET 0` rewinds, and `SEEK_CUR` at `Start` answers 0. `SEEK_END` keeps #1523's answer and leaves the position `Unenumerable`, so a later read is refused rather than guessed. `SEEK_SET` to any nonzero value, and `SEEK_CUR` mid-scan, are typed refusals (`LSeekRefusal.DirectoryPosition`): neither kernel's value is one this model can mint (row 9).
  - Later, and additive: raw `getdents fd buffer capacity`, which packs records into each flavour's ABI (rows 1, 2, 5 and 6). It needs a `d_off` decision, and O2 supplies one.
- **Refused.** Seeking a directory anywhere but 0; reading from `Unenumerable`; and NFS, whose `d_type` and order are the server's and unmeasured (refused as `directorySize` already is).
- **Property tests and oracles.**
  - Model laws against a naive oracle over the `Map`:
    - a full scan with no mutation is a permutation of the bound names plus the dots;
    - after any mutation, the next entry is the least live name above the cursor;
    - reading alternately through a `dup` pair yields the same sequence as reading through one descriptor;
    - rewind-then-scan equals a fresh open's scan;
    - delete-as-returned drains;
    - an `rmdir`'d directory answers its flavour's row-12 value at every position;
    - `d_ino` equals `stat`'s answer.
  - Host oracles on `/dev/shm` and the temporary directory, as `TestDirectorySize` does: dup sharing, rewind, `d_ino` and `d_type` per kind, the removed-directory answer, and the error rows, compared as sets.
- **Blast radius.**
  - Library: 70 references to `OpenFileTarget.File` across the repository (the compiler finds each match that needs a new arm), `UnixNamespace`, `UnixProcess`, `UnixSystem`, `VirtualFileSystem`, and about 7 test files (`TestDirectoryEnumeration` is the main one).
  - PawPrint:
    - `DirectoryStreamBlocks` becomes `Map<NativeMemoryBlockId, int>`, mapping each block to its fd.
    - `CloseDir` becomes "free the block, `close` the fd".
    - The injectivity invariant goes, because a guest can legitimately make two `DIR*`s name one fd number by closing and reopening.
    - `TestDirectoryStreamId`.
- **Reversibility.** Moving to B or O2, or adding raw `getdents`, is purely additive.
- **Bit-identity.** PawPrint's `ReadDir` makes one `readDirectoryEntry` call per guest call and converts ENOENT to end-of-stream as glibc does. The order, the cursor semantics and the dots-last choice are therefore unchanged. Only undefined-behaviour paths change, and each moves *toward* real libc:
  - `readdir` after the guest closed the stream's fd answers EBADF instead of continuing;
  - if that fd number is reused, `readdir` reads whatever it now names;
  - a guest-guessed `lseek` on the fd is refused mid-scan instead of answering 0.
  - `EnumerateClosedFdSeeded.cs` does not read after its close, so its observations are unchanged; its terminal-state check also holds, since `rmdir` now reaps at once.

### B. As A, plus a pure libc layer in the library
- **State.** Nothing in the kernel beyond A. The library adds `DirStream`, an immutable *value* the client holds (fd, buffered records, and a `LibcDirectoryPolicy`: buffer bytes, glibc's ENOENT-to-end-of-file, Darwin's flags word). `readdir : DirStream -> UnixSystem -> entry option * DirStream * UnixSystem`, and `closedir`.
- **What it buys.** A second client gets a faithful `readdir` for free, with glibc's 32 KiB and Darwin's 8 KiB behaviour selectable. PawPrint picks a one-record policy and stays bit-identical.
- **Refused.** The same as A.
- **Oracles.** Those of A, plus laws for each policy. With the directory unchanged, every policy yields the same sequence. A buffered policy is a snapshot per refill, and a differential test against the host's real libc can compare sequences under mutation once O2 exists.
- **Cost.** It models libc in a kernel package. Libc flavours are not kernel flavours (musl and glibc share Linux), so the policy axis grows independently of `SimulatedUnixFlavour`. It is speculative until a second client exists.
- **Blast radius.** A's, plus one module.
- **Reversibility.** Removing it later is a deletion.

### C. A snapshot per open file description
- **State.** `OpenFileTarget.Directory of inode * snapshot : DirectoryRecord array * index : int`. The snapshot is taken at `open` and at `SEEK_SET 0`.
- **API.** As A, but a position is just an index. So `d_off = index + 1`, `SEEK_CUR` answers the index, and seeking to any value is exact (past the end is end-of-file).
- **Refused.** Nothing about seeking. The removed-directory answer still follows row 12.
- **Oracles.** The simplest laws: a scan is a permutation of the directory as it was at open; seeking to `d_off[i]` yields record i+1 for every i; mutation is invisible. Every one of these laws *contradicts* row 15 on both kernels, so no host oracle can ever hold under mutation.
- **Blast radius.** A's, plus a record array per description. The name-cursor walk and its tests are deleted.
- **Reversibility.** Moving from C to A or O2 is a reshape of the description's state, not an addition.
- **Bit-identity.** **Not bit-identical.** The `divergences.md` example (create `d/c` mid-scan) stops yielding `d/c`. `divergences.md` rejected this as the "most forgiving" model, one that hides every mutation-during-scan bug in a guest.

### The index: O1 or O2
- **O1, the model's own order (today's).**
  - Byte order, then `..`, then `.`; a live cursor by name. No VFS change.
  - Deliberately matches no kernel. It is honest in the way `EmulatedFileSystemType` is: this is an in-memory graph, not a real filesystem.
- **O2, a faithful index per filesystem.**
  - **tmpfs:** `DirectoryContent` gains a per-directory link counter and per-binding offsets, together with list order. `rename` relinks, taking a fresh offset for a plain rename and the target's offset for a rename-over. The resume rule is row 15's, duplicates included.
  - **APFS:** order by `(hash22, name bytes)`, a key cursor, and sticky end-of-file.
  - It admits the strongest oracle available: the probe in `$P/mutate.c` becomes a host-differential test on **sequences** under random mutation scripts. It also supplies honest `d_off` values for raw `getdents` on tmpfs; on APFS it would mint `(k << 32) | n` from a per-directory counter.
  - **Costs:**
    - The tmpfs rule is one kernel version's. Only 6.18.5 was measured. My recollection, not checked here, is that libfs's directory-offset code has been reworked more than once in recent releases.
    - The APFS hash needs NFD and case-fold tables that match Apple's. The library cannot call `String.Normalize`, since that depends on the host's ICU (and on invariant globalisation), so it must ship tables or refuse non-ASCII names on Darwin.
    - It is guest-visible: the dots move first, and the order changes on both flavours.
  - It is additive behind a per-filesystem selector if A's `readDirectoryEntry` delegates to the index.

## 4. Recommendation: A with O1, staged

A removes libc from the kernel, puts the cursor where both kernels keep it (rows 7 and 8), and keeps every CoreLib-reachable behaviour bit-identical. It refuses exactly the two things the model cannot state: arbitrary directory seeks, and a mid-scan position value. B is speculative with one client. C is simpler but contradicts both kernels and changes guest behaviour. O2 is well supported by measurement (row 15 reproduced exactly) and is additive later; whether to take it is policy (§5).

**Stages, one PR each:**
1. **Facts and prose.**
   - Commit `layout.c`, `mutate.c` and `eofflag.c` beside the existing probes in `docs/plans/2026-08-23-posix-kernel-extraction/`.
   - Add host-measuring tests for rows 3, 4, 7, 8, 11 and 12 (a raw `getdents64`/`__getdirentries64` P/Invoke from the library's test project, skipped off tmpfs and APFS), with each failure message reporting the measured value.
   - Correct the three pieces of prose in §2, the `DirectoryEntryPal` stale name, and the skill's divergence rows.
   - No behaviour change.
2. **The directory description, in the library.**
   - `OpenFileTarget.Directory`, `DirectoryPosition`, `O_DIRECTORY` on `OpenFlags`, `readDirectoryEntry` and the directory arm of `lseek`, with property tests first (A's laws) and the removed-directory rows per flavour.
   - Re-implement the existing `opendir` and `readdir` over the new primitives, so that PawPrint and the Guest suite are untouched. That run is the bit-identity oracle.
   - Mutation-test the rewind, dup and removed-directory guards.
3. **PawPrint switches, and the library deletes.**
   - `OpenDir`, `ReadDir` and `CloseDir` go over fds (glibc's ENOENT-to-end-of-file in the `ReadDir` handler), and `DirectoryStreamBlocks` becomes a map from block to fd.
   - Delete `DirectoryStreams` and everything listed under A (published-API removals: flag them). Rewrite `divergences.md`'s "keeps an offset of zero" section.
   - Run the default and Guest suites.
4. **Raw `getdents`** (optional, when a client needs bytes). The per-flavour packing of rows 1, 2, 5 and 6, plus a `d_off` policy: refused under O1, or real under O2.
5. **O2** (optional, policy): tmpfs first, since its model needs no Unicode tables.

## 5. Open questions

**For Patrick (policy or scope):**
1. **Order.** Keep the model's own order (O1: byte order, dots last), or adopt the measured per-filesystem orders now that both are reproducible (O2)? O2 is guest-visible, and it gives up the deliberate "dots last" adversarial choice for fidelity.
2. **Mutation visibility through PawPrint's libc.** Keep today's live-per-entry behaviour (no libc buffer), or give PawPrint glibc's and Darwin's real buffering (32 KiB and 8 KiB)? Real buffering makes a small directory a snapshot after its first `readdir`, which is what a real guest sees, and is guest-visible.
3. **APFS names under O2.** Ship NFD and case-fold tables (and accept Unicode-version drift from Apple), or refuse non-ASCII names in Darwin's order model?
4. **Scope.** Should the library ever carry a libc layer (B), or does libc always stay with its client?

**Mine to decide during implementation:**
- A separate `OpenFileTarget.Directory` case rather than a cursor on `File`. I recommend the separate case, so that a regular file's description can never hold a directory cursor.
- Refusing mid-scan `SEEK_CUR` versus reporting an ordinal. I recommend refusing, since neither kernel's value is mintable under O1.
- The exact check order of the error rows. Stage 1 sweeps it.

## Decision (orchestrator, 2026-09-26)
**A with O1** is chosen.
- **Stages 1 and 2 are one PR:** the probes, host tests and prose fixes, plus the library primitives, with the existing `opendir`/`readdir` rebuilt over them so that the Guest suite proves they are bit-identical.
- **Stage 3 is its own PR:** PawPrint switches over, and the stream table is deleted.

The open questions:
- **Q1, O2:** deferred, not rejected. tmpfs's measured order (newest link first) is a candidate for a later stage, because tmpfs is PawPrint's default filesystem. APFS's order waits for a consumer, since it needs NFD and case-fold tables.
- **Q2:** keep live, one-entry-at-a-time `readdir` in PawPrint.
- **Q3:** moot until O2 is taken up for APFS.
- **Q4:** no library libc layer (B); it is speculative with one client.
