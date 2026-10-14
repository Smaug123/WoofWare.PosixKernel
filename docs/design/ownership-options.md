# Ownership and credentials in WoofWare.PosixKernel

*Options document, 2026-09-26. Part of the "PosixKernel knows nothing of the CLR" workstream. Code cited at `origin/main` d1d34c9d. Issue #1273.*

## 1. What there is today

**No inode has an owner.**
- `Inode` is `{ Content; Times }` (`Inode.fs:186-190`), and `SeedEntry` has no owner field (`FileSystemSeed.fs:25-31`).
- `statOf` reports the *calling process's* uid and gid as every inode's (`UnixPathResolution.fs:377-381`, and the docstrings at 21-36 cite #1273).
- The seeded root directory is 0755 (`VirtualFileSystem.fs:300-319`). Because the caller "owns" it, uid 1000 can create entries in `/`. A seeded 0644 `/etc/passwd` is writable by uid 1000 too.
- The justification at `UnixProcess.fs:121-123`, "a per-inode field could never make two inodes differ", overlooks the seed. The seed is exactly where two inodes differ.

**Credentials are one effective uid and gid.**
- These are `UnixProcessState.UserId` and `GroupId` (`UnixProcess.fs:118-127`).
- There are no real or saved ids and no supplementary groups.
- `Syscall.GetEffectiveUserId` is the only id call (`UnixSystem.fs:12`, `UnixDescriptor.fs:298-306`).
- `callerPrivilege` is `UserId = 0` (`UnixProcess.fs:232-239`). `UnixSocket.fs:664-670` re-derives root as `UserId <> 0u` instead of calling it, so privilege has two definitions.

**umask** is fixed configuration (`UnixProcess.fs:128-141`: "this library models no `umask(2)`"). There are also no `chown`, `chmod`/`fchmod` or `access`/`faccessat` calls.

**Rules that silently assume the caller owns everything.** Each is exact today only because of that assumption.

| rule | where | what changes once owners exist |
| --- | --- | --- |
| `PermissionBits.deniedTo`: owner triple only | `PermissionBits.fs:177-193`, used by `open` (`UnixNamespace.fs:338-360`), the walk's search check (`PathWalk.fs:359-374`), `chdir` (`UnixPathResolution.fs:638`), the parent-write checks of `open(O_CREAT)` and `mkdir` (`CreatingOpenRules.fs:162`, `MkDirRules.fs:148`), `opendir` (`RemovalRules.fs:358`), and `unlink`, `rmdir` and `rename` (`RemovalRules.fs:95`, `RenameRules.fs:127`) | the permission class (owner, then group, then other) must be chosen |
| sticky bit "can never refuse" | `RemovalRules.fs:64-68`, `RenameRules.fs:111-113` | EPERM when the caller owns neither the entry nor the directory (measured, §2) |
| `SetGroupIdOnWrite.StripWhenGroupExecutable` (Linux) | `PermissionBits.fs:64-90, 316-350`; `UnixReadWrite.fs:732-734, 975-976` | **wrong for a writer outside the file's group.** Linux strips `S_ISGID` from `02666` too (measured) |
| `afterTruncation`, Linux `Strip` | `PermissionBits.fs:366-394` | the same membership dependence |
| `MkDirRules.InheritsSetGroupIdFromParent` | `MkDirRules.fs:30-44` | the bit is right, but the new directory's *gid* is not modelled |
| `CreatingOpenRules.createdPermissions` | `CreatingOpenRules.fs:170-177` | Linux strips a requested `S_ISGID` in a set-group-ID directory whose group the caller is not in. `flavour-divergence.md` calls this "unmeasured"; it is now measured |
| `st_uid`/`st_gid` | `UnixPathResolution.fs:377-381` | read from the inode |

`CallerPrivilege` itself (`PermissionBits.fs:10-20`) is POSIX-shaped and fine: nothing here is shim- or CoreCLR-shaped.

**How PawPrint uses it.**
- `KernelConfig.UserId`/`GroupId` are optional, defaulting to the flavour's first user. `Umask` is fixed (`EmulatedKernel.fs:1885-1896`).
- **`toKernel` realises the seed *before* it applies the ids** (`EmulatedKernel.fs:1987-2002`). That ordering is harmless today and is a trap for any design where a seed defaults its owner to "the process".
- `SystemNative_Stat` writes the kernel's `UserId`/`GroupId` (`NativeSystemNative.fs:900-901`).
- `SystemNative_GetEUid` is implemented. `GetEGid` and `GetGroups` are deliberately *not* (`NativeSystemNative.fs:2444-2476`).
  - The reason: CoreLib's only route to them is `FileStatus.IsModeReadOnlyCore`, behind `_fileCache.Uid == GetEUid()` (`FileStatus.Unix.cs:106`). That guard is always true while the process owns everything.
  - `sourcesImpure/EffectiveUserIdConfigured.cs` pins this premise and will fail when it ends.
- `SystemNative_ChMod`, `FChMod` and `Access` are unimplemented. `File.SetUnixFileMode`, `File.Copy` (its `fchmod`) and `File.SetAttributes` stop there.
- The differential oracle materialises a seed as the test user, and already refuses special mode bits (`RealRuntime.fs:418`). It can't materialise foreign owners either.

## 2. Measured facts

**Where and how measured.**
- **Linux:** 6.18.5 **aarch64**, in Apple `container` (gcc:14), as root with every capability, forking children with chosen `setgroups`/`setresgid`/`setresuid`. It was run on the ext4 rootfs and on tmpfs (`/dev/shm`); the two agree on every row except the one flagged below.
- **Darwin:** 27.0 / APFS at uid 501, which is in groups 20, 12, 61, 100 and 701. **No root on Darwin** (sudo needs a password), so every Darwin root row is unmeasured.
- **Sweeps:** each sweep compares every one of the 512 permission modes against a stated rule and prints the mismatch count.

Raw output is in `ownership-raw/` beside this file (copies of the scratchpad's `ownership/`):
- the probe [`ownership-probe.c`](ownership-raw/ownership-probe.c);
- its output: [`linux-6.18.5-aarch64-ext4.tsv`](ownership-raw/linux-6.18.5-aarch64-ext4.tsv), [`linux-6.18.5-aarch64-tmpfs.tsv`](ownership-raw/linux-6.18.5-aarch64-tmpfs.tsv), [`darwin-27.0-uid501.tsv`](ownership-raw/darwin-27.0-uid501.tsv);
- follow-ups: [`linux-followup.txt`](ownership-raw/linux-followup.txt) (a non-owner's no-op `chown`, the `grpid` mount) and [`linux-groups-order.txt`](ownership-raw/linux-groups-order.txt).

| fact | Linux | Darwin |
| --- | --- | --- |
| **Which triple applies** | First match among owner, group (egid *or* supplementary), other; only that triple's bits are consulted. **0 mismatches** over 512 modes × {owner, primary group, supplementary group, other, root} × {file, dir}. The probe tested `open` R/W, `access` R/W/X, search, `opendir`, and create-in-dir | Owner class: 0 mismatches over 512 × {file, dir}. Group class (spot rows): the root:staff 0774 dir is searchable, so group wins over other; the steam:staff 0700 dir is EACCES, so group denies though the caller is not the owner. Other: root:wheel 0750 and 0600 are EACCES |
| owner denied though group or other allows | denied (0070 and 0007 to the owner are EACCES) | denied (same) |
| **root** | Read and write bypassed; a directory is always searchable; `access(X_OK)` on a regular file is ok iff *any* execute bit is set | unmeasured |
| a `noexec` mount | `access(X_OK)` is EACCES for every regular file, even as root (tmpfs `/dev/shm`). A mount option, not a tmpfs fact | — |
| **`access`** | Uses the **real** uid and gid; `faccessat(AT_EACCESS)` uses the effective ones. Measured both ways for uid and gid. Real root plus effective 1000 makes `access` ok and `open` EACCES | unmeasurable (it needs `setuid`) |
| new inode's **uid** | The effective uid (measured with real 1000, effective 1001) | the caller's |
| new inode's **gid** | The egid; **the parent's gid if the parent is set-group-ID**, or on a `grpid` mount (measured, ext4) | **always the parent's gid**, even `wheel`, of which the caller is not a member |
| new *directory* in a set-group-ID parent | Parent's gid, and `S_ISGID` is set whatever the mode; `grpid` alone does not set it | parent's gid, and no `S_ISGID` |
| **set-group-ID stripped at creation** | `open(O_CREAT)` and `mkfifo` with `02775` in a set-group-ID parent whose group the caller is not in → `0775`. `02765` (no `g+x`) is kept. Root keeps it | `open` and `mkdir` can't set it at all (mask 0777). `mkfifo(02775)` in a non-member-group parent is **EPERM, and nothing is created** |
| **`chown`: who may** | A non-owner giving any id: EPERM. The owner may give an owner id only if it is its own; a group only if it is the egid or a supplementary group; otherwise EPERM. Root may do anything | same, for the owner (a non-member group or another uid: EPERM) |
| `chown(-1, -1)` by a non-owner | ok on a directory or on a file with no set-ID bits; **EPERM on a file with any set-ID bit**, even `02644` | ok (`/etc/hosts`, 0644) |
| **`chown` clears set-ID bits** | Regular files only: every successful `chown`, **including `(-1, -1)` and including root**, clears `S_ISUID`, and clears `S_ISGID` iff `g+x` (`06745` → `02745`). Directories are untouched | Non-root: any `chown` naming an id, even the unchanged one, clears **both** bits whatever `g+x` is, **on directories too**. `(-1, -1)` clears nothing. Root: unmeasured |
| **`chmod`** | A non-owner gets EPERM. The owner outside the file's group has `S_ISGID` **silently dropped** (success, files and dirs). The sticky bit on a regular file is kept. Root keeps everything | same, all three rows (`EFTYPE` was not observed) |
| writing or truncating a set-group-ID file | Non-root: `S_ISUID` is stripped. `S_ISGID` is stripped if `g+x` **or the writer is not in the file's group**, owner or not. `02666` survives only a writer in its group. Root keeps both | non-root strips both whatever the group (existing table; measured as owner only) |
| **sticky directories** | EPERM for unlink, rename-from, rename-onto (replacing someone else's entry), and rmdir, unless the caller owns the entry or the directory. Root bypasses it. A source's sticky EPERM beats a destination's EACCES in `rename` | unmeasured (it needs a second user) |
| **umask storage** | `umask(07777)` reads back `0777` | reads back **`07777`** (from 0xffffffff too) |
| umask applied | `open`: `mode & 07777 & ~umask`. `mkdir`: `mode & 01777 & ~umask`. **`mkfifo`: `mode & 07777 & ~umask`** (set-ID bits kept). 0 mismatches over 513 umasks × 6 modes | `open`/`mkdir`: `mode & 0777 & ~umask`. **`mkfifo`: `mode & ~umask` over all twelve bits**, so the umask's high bits *do* matter here, contrary to `PermissionBits.fromCreationMode`'s remark |
| inherited umask | `022` (and the VM's init has `0022`) | `022` |
| **`getgroups`** | The supplementary set, **sorted ascending with duplicates kept**. The egid is *not* implicitly included. `NGROUPS_MAX` is 65536 | the login list with the egid first (`20,12,61,100,701`), not sorted. `NGROUPS_MAX` is 16 |
| `getgroups(n)` with n too small | EINVAL | EINVAL |
| `protected_symlinks=1` (sysctl) | Following a link in a world-writable sticky directory is EACCES unless the link is the follower's or the directory owner's | none |
| `protected_regular=1` / `2` | `O_CREAT` on someone else's existing file in a world-writable (1) or group-writable too (2) sticky directory is EACCES; without `O_CREAT`, ok. Defaults in the VM: all 0. **Distributions set these**, so the value is configuration | none |
| a sandbox refusal | — | TCC answered EPERM for `opendir` on `/private/var/db/searchparty`. This is not a POSIX permission, and is not modelled |

## 3. Decisions every design shares

**Seed ownership: three options, and the recommendation.**

**(i) Mandatory owner on every `SeedEntry`.**
- Explicit, but it churns 206 construction sites.
- Every test must then state an owner that its host oracle cannot honour anyway.

**(ii) An optional owner per entry, realised against an explicit default owner** (recommended).
- The default is an argument to `VirtualFileSystem.ofFileSystemSeed` and `UnixSystem.withFileSystemAndCurrentDirectory`, and it also decides who owns the root directory.
- PawPrint passes the configured credentials, and `toKernel` must resolve them *before* realising the seed.

**(iii) Implicitly "the process's credentials at realisation".** Rejected, for two reasons:
- given `toKernel`'s order, a `UserId = Some 0u` configuration would own every inode by 1000 or 501;
- `EffectiveUserIdConfigured`'s root registration would catch it, but the design invites the bug.

**`UserId` and `GroupId` become newtypes** (`[<Struct>] UserId of uint32`) wherever they appear in the library, so that a gid can't be passed where a uid is wanted. Several of the rules below compare the two kinds side by side.

**Real, effective and saved ids stay one value each for now.**
- With no `set*id`, `exec` or `fork`, no call can make them differ.
- That makes `access` equal to `faccessat(AT_EACCESS)` exactly, and the docstring says why.
- Widening this to real/effective/saved is additive once `setuid` exists.
- Capabilities stay out: `Privileged` is uid 0, as today.

## 4. Designs

### A. A symbolic owner: `ProcessOwned | Owned of InodeOwner`
**State and API.**
- Inodes the process creates, and seed entries without an owner, are `ProcessOwned`. Only a seed can make an inode `Owned`.
- `st_uid` of a `ProcessOwned` inode is read from the process, as today.
- Credentials gain supplementary groups only.
- Rules take the caller's relation to each inode.

**Refused.**
- `chown` entirely: there is no concrete owner to change from `ProcessOwned`.
- `chmod` and `access` work.

**Tests.**
- A property: "an all-`ProcessOwned` system answers exactly as today". That is cheap bit-identity.
- Exhaustive rule tables, as in C.

**Blast radius.** The smallest: existing seeds and tests are unchanged.

**Reversibility.** Poor.
- `ProcessOwned` means "whoever the process is *now*", so a later change of the ids silently re-owns files. That is wrong today already, via `withUserAndGroupId` after seeding.
- Under `fork` or `setuid` it would be ambiguous.
- Moving to concrete owners means choosing *when* each inode's owner was fixed, which the recorded state no longer knows.

**Bit-identity:** trivially preserved.

### B. A concrete owner on every inode; the rules interpret credentials
**State.**
- `Inode = { Content; Times; Owner : InodeOwner }`, with `InodeOwner = { User : UserId; Group : GroupId }`, total and mandatory inside the VFS.
- `UnixProcessState.Credentials = { User; Group; Groups : GroupId list }` replaces `UserId`/`GroupId`. The list is in `getgroups` order: sorted on Linux, as given on Darwin. It is validated against the flavour's `NGROUPS_MAX`.

**API.**
- Each rule takes `Credentials` and the `InodeOwner`s it cares about, as Linux's `inode_permission(cred, inode)` does.
- New `Syscall` cases: `Chown`/`FChown`/`LChown`, `ChMod`/`FChMod`, `UMask`, `Access` (with an `EffectiveIds` flag), `GetEffectiveGroupId` and `GetGroups`.
- New flavour tables in `SimulatedUnixPlatform`, from §2:
  - `newInodeGroup`: Linux `CreatorsUnlessParentSetGroupId`, Darwin `Parents`;
  - `chownRules`;
  - `umaskStoredBits`: 0777 or 07777;
  - Linux's creation-time `S_ISGID` strip;
  - a corrected write/truncate rule, whose Linux case becomes "strip `S_ISGID` if `g+x` or the writer is outside the group".
- The Linux-only mount and sysctl knobs (`grpid`, `protected_symlinks`, `protected_regular`) go in `KernelConfig`-style configuration, refused on Darwin.

**Refused, until measured.**
- On Darwin, any rule whose root row or second-user row is unmeasured:
  - `chown` by root;
  - the sticky EPERM;
  - `access(X_OK)` as root.
- The refusal names the missing measurement.

**Tests.** Rules take unbounded ids, so they need property tests over generated credentials and owners, compared against a reference implementation. Rows written as literals come from the §2 output.

**Blast radius.**
- About 10 `deniedTo` call sites and every rule signature that takes `CallerPrivilege`: `PathWalk`, `CreatingOpenRules`, `MkDirRules`, `RemovalRules`, `RenameRules` and `PermissionBits`.
- `VirtualFileSystem`'s create functions take an owner.
- There are about 270 mentions of `CallerPrivilege` in about 14 test files.

**Reversibility.** Additive to full `set*id` credentials and to capabilities.

### C. As B, but the rules take a derived `Standing` (recommended)
**State:** identical to B.

**The difference is where ids are interpreted: in exactly one function.**
- `Standing = { Privilege : CallerPrivilege; Owns : bool; InGroup : bool }`.
- `Standing.toward : Credentials -> InodeOwner -> Standing` answers how the caller stands towards *one* inode.
- `deniedTo : Standing -> AccessRequest -> PermissionBits -> bool` picks the triple by first match.
- `AccessRequest` gains `Execute` for `access(X_OK)`. Root needs some execute bit.
- Each rule takes the standings it needs, which is the existing `CallerPrivilege` argument widened:
  - the sticky check takes the directory's and the entry's standings;
  - Linux's write-strip reads `InGroup`;
  - the creation strip reads the parent's `InGroup`.
- Only the calls that are *about* ids take `Credentials`: `chown`, new-inode ownership, `getgroups` and `access`'s choice of ids.

**Refused:** as in B.

**Tests.**
- Every rule's input space is finite (2 × 2 × 2 standings × 4096 modes × request), so the §2 tables can be asserted **exhaustively** rather than sampled.
- The measured TSVs can be checked in as data, as `socketMatrix/*.tsv` is, and for the same reason: no single machine can measure both privilege columns.
- `Standing.toward` gets one small property test against a naive membership oracle.
- Model-based tests:
  - random multi-credential traces of `open`, `mkdir`, `chmod`, `chown`, `unlink` and `rename` against a reference model;
  - the invariant "every inode has an owner";
  - **the bit-identity property:** a system whose every inode is owned by its credentials answers every existing call exactly as `Standing = { Owns = true; InGroup = true }` does, which is today's answer.

**Blast radius.**
- The same files as B.
- The test churn is mechanical: `CallerPrivilege.Unprivileged` becomes `Standing.ownerOf CallerPrivilege.Unprivileged`.
- `PathWalk.PausedResolution` carries `Credentials` in place of `Privilege`, and computes a standing per directory it searches.

**Reversibility.**
- B ↔ C is a refactor of signatures over the same state.
- Real/saved ids change only `Standing.toward` and `access`.
- Capabilities widen `Privilege` inside `Standing`, which is additive per rule.

*Rejected encoding (for B or C): owners in a side table,* `Map<InodeNumber, InodeOwner>`, where an absent key means the filesystem's default owner.
- It saves touching `Inode`.
- But it carries the remove-on-default obligation of §2 in the skill, and a `chown` back to the default must delete the entry.
- It buys nothing that the optional *seed* field in §3 (ii) does not already buy.

### Keeping PawPrint's guests bit-identical (B or C)
- Seeds without an owner are realised as the configured `(uid, gid)`. That default is resolved before realisation, and it also decides who owns the root directory. So every inode is owned by the process, exactly as `stat` reports today.
- New inodes get `Credentials.User`. For the group:
  - Darwin's rule gives the parent's gid, which is the process's under the default.
  - Linux's rule gives the egid, or the parent's gid under set-group-ID, which again is the process's.
- Every `Standing` is therefore `{ Owns = true; InGroup = true }`:
  - `deniedTo` reads the owner triple;
  - sticky never refuses;
  - Linux's write-strip keeps `02666`.
- That is today's behaviour, row for row.
- New syscalls change nothing that already answers.
- `GetEGid`/`GetGroups` stay unimplemented until a seed can state a foreign owner. They are then implemented in that same PR, because the group branch of `IsModeReadOnlyCore` becomes reachable exactly then.
- `RealRuntime` refuses a seed with an explicit owner, just as it refuses special bits, so such cases go to `sourcesImpure`.

## 5. Recommendation: C, with seed option (ii)

C keeps the model's rules as small finite tables that can be tested exhaustively. That is the property that made the existing flavour rules trustworthy.

It interprets ids in one function, so "who is in which group" cannot drift between call sites. The `UnixSocket.fs:670` duplicate of "who is root" goes too.

A is cheaper, but it encodes "whoever the process is now" into filesystem state, and fails the first time the ids move.

**Stages** (one PR each, each with its own tests):
1. **Credentials.**
   - `UserId`/`GroupId` newtypes, and `Credentials { User; Group; Groups }` with `NGROUPS_MAX` validation and Linux's sort.
   - `getegid` and `getgroups` as library calls (EINVAL for a short buffer; order per flavour).
   - `UnixSocket` uses `callerPrivilege`.
   - `KernelConfig.SupplementaryGroups : uint32 list option`.
   - PawPrint's behaviour is unchanged. `GetEGid`/`GetGroups` stay unimplemented.
2. **`Inode.Owner`, populated but never foreign.**
   - The VFS create functions and seed realisation take an owner, and `stat` reads it.
   - `toKernel` resolves the ids before the seed.
   - The new-inode group rule per flavour, with a unit test on a hand-built VFS whose parents are foreign.
   - A property test: under the current API, every inode's owner equals the credentials.
3. **`Standing` and the class-selecting rules.**
   - `deniedTo`, sticky EPERM (with Linux's source-before-destination order), and Linux's membership-dependent write and truncate strip.
   - Linux's creation `S_ISGID` strip.
   - The §2 tables as literal rows, run exhaustively against hand-built foreign-owned filesystems.
   - Darwin's unmeasured rows are refused. Bit-identity property.
   - Correct the docstrings which §1 lists as resting on the old premise.
4. **Foreign owners in seeds.**
   - An optional `owner` on `SeedEntry`.
   - PawPrint: implement `GetEGid`/`GetGroups`, since the `IsModeReadOnlyCore` group path is now reachable. Update the `EffectiveUserIdConfigured` premise. `RealRuntime` refuses owned seeds.
   - A `sourcesImpure` guest: uid 1000 against a root-owned `/etc/passwd` and `/`, EACCES on write and create; `File.GetAttributes(...).ReadOnly` through the group path.
5. **`chmod`/`fchmod`** (the rules are measured on both flavours), plus PawPrint's `SystemNative_ChMod`/`FChMod`. This unlocks `File.SetUnixFileMode` and `File.Copy`.
6. **`umask(2)`**, with the flavour's stored width. `mkfifo` comes when it is needed, carrying Darwin's twelve-bit umask and its EPERM.
7. **`access`/`faccessat`**, with the root `X_OK` rule, plus `SystemNative_Access`.
8. **`chown`/`fchown`/`lchown`** with both measured bit-clearing tables. Darwin's root row is refused until measured.
9. **Linux `protected_symlinks`/`protected_regular`** as configuration. Only needed once a guest can create a symlink or a seed can hold another user's file in a sticky directory.

## 6. Open questions

**For Patrick (policy or scope):**
1. **The default tree for new PawPrint tests.** "Everything owned by the configured user" is recommended, because it is bit-identical and what the oracle can materialise. A realistic root-owned system with a user-owned home would change what guests see.
2. **The default supplementary groups.**
   - `[gid]`, which is what `initgroups` gives a user with no extra groups, versus a distribution-like list: Ubuntu's `adm,cdrom,sudo,…`, or macOS's measured `20,12,61,79,80,…`.
   - It is guest-visible through `getgroups`, and so through CoreLib's read-only check.
3. **Which Linux?** The kernel defaults `protected_*=0`, which is what the VM had. Ubuntu, and so probably CI, sets them through `sysctl.d`. Model "a kernel" or "the distribution CI runs"? Measure the runner first.
4. **Darwin root rows need `sudo`.** They are `chown` by root, root `X_OK`, and the sticky rows (these need a second user). Running `ownership-probe.c` once as root, with a second account, would replace four refusals with rows. Otherwise they stay refused.
5. **Scope of `set*id`/`exec`/`fork`,** which is what would make real, effective and saved ids differ. Is any client expected to need it? If not, the single-id credentials are final rather than interim.

**I can decide these:**
- B versus C;
- the field shape of `SeedEntry`'s optional owner;
- the stage order;
- naming;
- how `RealRuntime` refuses owned seeds;
- whether `mkfifo` is in scope;
- not modelling Darwin's directory-service group resolution or TCC refusals;
- treating `noexec` and `grpid` as mount options. The model has one filesystem, so these are `KernelConfig` fields when they are needed, not now.

## Decision (orchestrator, 2026-09-26)
- **Design C** is chosen, with the 9-stage plan. Stage 1 (credentials) starts now. It includes making `UnixSocket.fs:670`'s direct `UserId <> 0` test use the single privilege definition.
- **Open questions:**
  - Default supplementary groups: empty, and configurable.
  - Linux `protected_symlinks`/`protected_regular`/`protected_fifos`: machine configuration, defaulting to the kernel's own default of 0.
  - `set*id`, `exec` and `fork`: out of scope here. They belong to the process-lifecycle design.
  - The default tree for tests: unowned seed entries are owned by the configured user and group.
  - Darwin's root rows stay refused until someone runs the probe once under sudo. Only that last point needs Patrick.
