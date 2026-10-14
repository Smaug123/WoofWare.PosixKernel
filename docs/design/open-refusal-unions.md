# Open refusal unions

*Design note with measurements, 2026-10-11. Library facts are read at `origin/main` `9125cac8`, built in a scratch worktree. Nothing in the repository has changed. The scratch projects are in the session scratchpad, `openrefusal/` (a library `lib`, clients `client` and `clientall`, a friend assembly `libtest`, and `a1var/`), with the scripts `run.sh` to `run4.sh` that drive them.*

**Background.** PR #1870 (branch `pk-strict-semver-unions`) makes a new case in any public union a major version from 1.0. The reason is measured (`reserved-union-cases.md` §1.1): an F# client compiled against an older union dispatches on tags, so a new case silently runs an existing arm or throws `InvalidCastException`. A wildcard after a complete match is FS0026 and is compiled away.

Refusals grow all the time, though. Every newly measured Linux/Darwin divergence adds a refusal case. Patrick has agreed in principle that refusal unions should be *open*: a client cannot match them exhaustively, so a new refusal is a minor version. This note measures the proposed mechanism, sets out the alternatives, decides which unions are open, and plans the PRs.

**Result in brief.**
- **The proposed spelling does not compile.** If the union's cases are `internal` and its module has a pattern of the same name, a client's `| BindRefusal.UnmodelledMulticast (s, a) ->` is error FS1093: "The union cases or fields of the type 'BindRefusal' are not accessible from this code location". The hidden case shadows the pattern under every spelling I tried (§1.1).
- **The mechanism works with a different spelling.** Put the patterns in a nested module, so a client writes `| BindRefusal.Reason.UnmodelledMulticast (s, a) ->`. Then everything the brief asked for holds, in Debug and Release: no diagnostic with a wildcard, FS0025 without one, new cases reach the wildcard, and inserted cases do too (§1).
- **Scope, decided by what each type is rather than its name:** 107 unions become open with patterns (88 syscall and runtime refusals, 17 boot and launch refusals, and the two boot faults `CurrentDirectoryFault` and `FileSystemSeedFault`). That is 386 patterns. The 4 invariant-defect unions become open with no patterns. 16 stay closed: parse errors, flavour rules, a socket state, and `BufferRefusal` (§3).
- **PawPrint:** every one of its 135 match rules that names a refusal case ends the run. 75 of its lines have the plain form `| Error (XRefusal.Case …)`. None recovers. It builds a refusal value in 3 places and its tests in 2 more. 41 of its matches are exhaustive today, and 40 of them need a wildcard (§4).

## 1. Measurements

Set-up: the devshell's SDK 10.0.401, with F# at its default language version (F# 10). The library targets `net8.0`, the clients target `net10.0`, and `TreatWarningsAsErrors` is on with the repository's `WarnOn`. "v1 → v2" means: build the client against v1, then drop v2's `Lib.dll` in beside it without rebuilding.

I tried three designs.

- **A1, the proposal.** `type R = internal | Copy of Inner | Ports`, with `(|Copy|_|)` and `(|Ports|_|)` in `module R`.
- **A2, nested module.** `type S = internal | …`, with the patterns in `module S = module Case = …`. Clients write `S.Case.Copy`.
- **A3, opaque wrapper.** An internal union `TCase`, and a public `type T = internal { Case : TCase }` with no cases. The patterns go in `module T`, so clients write `T.Copy`.

Each union has a nested refusal (`Inner`, standing for `SockaddrCopyRefusal` inside `BindRefusal.Copy`), a case with two fields and a case with none. A generic `G<'Task>` stands for `CloseRefusal<'Task>`.

### 1.1 Does a client compile qualified patterns?

| question | result |
| --- | --- |
| A1: client writes `\| R.Copy x -> … \| _ -> …` | **No.** FS1093 on every arm. The same holds for an unqualified pattern (type without `RequireQualifiedAccess`), for the fully qualified `Lib.U.UCopy`, and for `private` representation instead of `internal` (`a1var/`). The client's name lookup finds the hidden case before the pattern, then reports it inaccessible |
| A2 and A3: client writes `\| S.Case.Copy (Inner.Case.X n) -> … \| S.Case.Multicast (s, a) -> … \| _ -> …` | **Yes, with no diagnostic.** No FS0025, no FS0026, nothing else. A `when` guard on a pattern works too |
| A2 and A3: client names every pattern and has no wildcard | **FS0025** "Incomplete pattern matches", for both. That is what we want: the match can never be complete |
| `[<RequireQualifiedAccess>]` on the type, the module and the nested module | No interaction. A2 needs it on the nested module, or a client could `open` it |
| generic union, `G.Case.Parked (task, fd)` | **Yes** |

### 1.2 New cases, client not rebuilt

| change | client built against v1, Debug | the same, Release |
| --- | --- | --- |
| v2 appends `NewCase of int` and `NewBare`, plus a pattern for `NewCase` | both new cases reach the wildcard; old cases reach their arms | the same |
| v3 also inserts `Front of string` before every existing case, so every tag moves | `Front` reaches the wildcard; old cases still reach their arms | the same |

A3 behaves identically. The v3 run also shows that the Release client does not inline the library's tag tests: every tag moved, and every old arm still matched. A client rebuilt against v2 or v3 compiles unchanged, with no diagnostic.

### 1.3 Equality, printing and friends

| question | result |
| --- | --- |
| client uses `=`, `compare`, `hash`, `Set.ofList` | all work, with the expected answers |
| `%A`, `%O` and `ToString ()` | print the internal case names and fields: `Multicast (3, "224.0.0.1")`, `Copy (X 5)`, `Ports`. A3 prints `{ Case = Multicast (3, "224.0.0.1") }` |
| reflection | `FSharpType.IsUnion t` is false; with `BindingFlags.NonPublic` it is true |
| friend assembly (`InternalsVisibleTo`) builds cases, reads `.IsCopy`, and uses named-field patterns such as `S.Multicast (socket = s)` | **Yes.** A complete match with no wildcard draws no FS0025, so `S.Copy` names the case there. This holds for A1 too |
| library code after the module, and inside it | `S.Copy` names the case; complete matches draw no FS0025 |
| `internal` as a representation modifier | accepted. The repository already uses it (`FifoAttachment`, `ThreadIdAllocator`) |
| bool-returning patterns for fieldless cases | need F# 9. The library at `LangVersion` 8.0 fails with FS3350, and so does an F# 8.0 **client** using bool-returning patterns from a library built with F# 10. `option`-returning patterns compiled in the same F# 8 client. Since the library targets `net8.0` for older consumers, fieldless reasons should return `unit option` |

### 1.4 What ApiSurface prints

ApiSurface 5.0.10, the version on `pk-api-surface` (PR #1766), run over the scratch library:
- A union with hidden representation prints only its type line and interfaces: `Lib.S inherit obj, implements Lib.S System.IEquatable, …`. There is no "union type with N cases", no `Tags` class, and no `IsX`, `NewX` or `Tag`. The baseline on `pk-api-surface` already shows this for `SignalMask`.
- The patterns appear as static methods: `Lib.SModule+Case.|Copy|_| [static method]: Lib.S -> Lib.Inner option`.

So the hidden cases are not printed, and `UnionCaseOrder.parse` never sees a hidden union. §6 says what that means for the order test.

## 2. Mechanisms

The brief asks for at least two structurally different mechanisms. Here are four. A and B are real candidates.

### A. Hidden representation, one partial pattern per case

Each open union gets `internal` representation. Its module gains a nested module of patterns, one per case:

```fsharp
[<RequireQualifiedAccess>]
module BindRefusal =
    /// Partial patterns, one per reason this kernel refuses a `bind`. …
    [<RequireQualifiedAccess>]
    module Reason =
        /// The screens every sockaddr-taking call shares had no answer.
        let (|Copy|_|) (refusal : BindRefusal) : SockaddrCopyRefusal option =
            match refusal with
            | BindRefusal.Copy inner -> Some inner
            | _ -> None
        …

    let describe (refusal : BindRefusal) : string = …
```

A client writes `| Error (BindRefusal.Reason.UnmodelledMulticast (socket, address)) -> …` and ends with a wildcard.

- **A2 (recommended):** the nested module as above. The library and its tests change only by `internal` and the new patterns. The 1,041 references in the library and the 720 in `WoofWare.PosixKernel.Test` stay as they are, because a friend assembly still sees the cases (§1.3). PawPrint's spelling gains `.Reason`.
- **A2', a sibling module:** the same patterns in a separate top-level module, `BindRefusalReason.UnmodelledMulticast`. It is one word shorter at each call site, but it adds a second public name per union. It cannot be the same module under another file, because F# rejects a module defined twice.
- **A3, an opaque wrapper:** today's spelling survives unchanged, `| Error (BindRefusal.UnmodelledMulticast (s, a))`, since the public type has no cases to shadow the pattern. The price is the library. Every construction becomes `BindRefusal.ofCase (BindRefusalCase.X …)`, and every match becomes `match r.Case with BindRefusalCase.X`: about 1,760 references across the library and its tests. `%A` also prints a record around the case. I recommend against it. Its one gain is that PawPrint's 186 pattern lines would not change.

What A gives:
- A new reason adds a case and a pattern. An old client never calls the new pattern, so its wildcard catches the case (§1.2).
- The library can change a case's fields freely as long as the pattern's payload does not change. It can, for example, hold a field it does not expose.
- A reason the library stops producing keeps its pattern, which then never matches. Deleting the pattern is a breaking change.
- Payloads are positional tuples, so field names are lost. Each pattern's docstring must name its tuple in order. PawPrint matches positionally everywhere already: no named-field pattern on a kernel type appears outside the library and its tests.
- Clients cannot build refusal values. That affects PawPrint in 3 places and its tests in 2 (§4).
- C# clients get `describe` only: a compiled name such as `|Copy|_|` is not a C# identifier. This is inferred from the names, not measured.

### B. A public union with one reserved catch-all case

Keep the cases public, and add one last case to each union: `| Unclassified of UnclassifiedRefusal`. `UnclassifiedRefusal` is an opaque type with `describe`. A refusal added in a minor version arrives as `Unclassified`. At the next major version it is promoted to a case of its own.

- An old client meets a new refusal in its `Unclassified` arm. That case has a tag the client was built with, so nothing is misrouted. This follows from the public union not changing, so I did not measure it.
- Exhaustive matching stays legal and meaningful. PawPrint keeps its FS0025 prompts for every published reason.
- But each new reason has two representations over its life: opaque until the next major, then a case. A client that cares about it cannot match it until the promotion, and the promotion breaks clients who matched `Unclassified` to catch it. The library builds new refusals in two styles. Each union carries a second, internal union, or all of them share one.
- It contradicts the premise. Patrick's reason for openness is that a client should not match a refusal's reason exhaustively, and B is built to keep that possible.

### C. Hidden representation, `describe` only

As A, but with no patterns. This is the smallest change to the library, and the README promise becomes simply "a refusal is a string for a human".
- It removes the remedies PawPrint gives. PawPrint has 135 match rules on refusal cases. Each adds what a .NET guest did to get there, or which configuration knob lifts the refusal ("Configure a user other than root (KernelConfig.UserId)…"). C leaves PawPrint with string matching on `describe`, which would be worse than either A or B.
- **It is the right shape for the invariant defects** (§3.3). No client matches them, and their cases should be free to come and go.

### D. A `kind` query

`BindRefusal.kind : BindRefusal -> BindRefusalKind` would need a public fieldless union, `BindRefusalKind`. That union gains a case with each new refusal. It is the worst shape of all in §1.1: fieldless, so an old client silently runs the first arm. Making `kind` a string avoids that and is stringly typed. Rejected.

### Recommendation

**A2 for refusals and boot faults, C for the invariant defects, and closed for the rest.** A2 gives clients what B gives them, minus the exhaustive match the policy says they should not write. It costs the library almost nothing, because the friend assembly keeps every existing case reference. B is the only real alternative. I would choose it only if Patrick wants PawPrint's compile-time prompt for new reasons more than he wants refusal reasons to be non-exhaustive by construction.

## 3. Which unions are open

Classified by reading every case's docstring and every client use, not by name. Many names are misleading: `DirectorySourceRefusal` is a flavour rule, `RefusalError` is a socket state, and `UnixByteStringDefect` is a parse error. Counts come from reflection over `origin/main`. There are 127 public unions whose names end in `Refusal`, `Defect`, `Error` or `Fault`: 109 refusals, 6 defects, and 12 errors and faults (`UnixError` is on the closed list and not counted). The audit counted 108 refusals at an earlier commit; `ShutdownRefusal` is new since.

| verdict | unions | cases | patterns |
| --- | --- | --- | --- |
| open, patterns: syscall and runtime refusals | 88 | 347 | 347 |
| open, patterns: boot and launch refusals | 17 | 32 | 32 |
| open, patterns: boot faults | 2 | 7 | 7 |
| open, no patterns: invariant defects | 4 | 140 | 0 |
| closed: refusal-named | 4 | 8 | — |
| closed: defect-named parse errors | 2 | 3 | — |
| closed: errors and faults | 10 | 40 | — |
| **total** | **127** | | **386** |

### 3.1 "The model doesn't know": open, with patterns (88)

Every case says what is unmeasured, unmodelled, or not represented. They are returned by syscalls and by the machine's runtime calls (`SimulatedMachine.launch`, `endProcess`, `ProcessTermination`'s wait status). Some cases inside these unions are of other kinds, but none makes its union closed:
- **20 unions carry `Buffer of BufferRefusal`**, the client's own buffer that the model cannot represent. The wrapper case is open like its union. `BufferRefusal` itself is closed (§3.4).
- **15 cases say the flavour lacks the call**: `NoSuchCall`, `NoSuchSyscall`, `NotProvided` and `UnmodelledFlavour`. A client could have checked the platform first. These stay as reasons; a client that wants to turn one into `ENOSYS` matches its pattern.
- **9 unions carry `DescriptorLimit of DescriptorLimitRefusal`**. That payload is a record, which stays as it is.
- A few cases describe a client bug rather than a gap in the model, such as `ThreadExitRefusal.Parked`. They are rare and change nothing.

The 88: AcceptRefusal, AccessRefusal, BindRefusal, BytesAvailableRefusal, CapacityRefusal, ChModRefusal, ChOwnRefusal, ClockGettimeRefusal, CloneFileRefusal, CloseRefusal, ConnectRefusal, CopyFileRangeRefusal, DescriptionReleaseRefusal, Dup2Refusal, Dup3Refusal, EndedWriteSignalRefusal, EpollCreateRefusal, EpollCtlRefusal, EpollWaitRefusal, ExecutionRefusal, FChModAtRefusal, FChModRefusal, FChOwnAtRefusal, FChOwnRefusal, FLockRefusal, FStatAtRefusal, FStatRefusal, FcntlRefusal, FileCloneRefusal, FileSystemIdRefusal, GeometryRefusal, GetCpuRefusal, GetCwdRefusal, GetEntropyRefusal, GetGroupsRefusal, GetIdsRefusal, GetRandomRefusal, GetSockNameRefusal, KeventRefusal, KillRefusal, KqueueRefusal, LSeekRefusal, LinkReadRefusal, LinkRefusal, ListenRefusal, MkNodRefusal, ModeChangeRefusal, MountFieldsRefusal, OpenRefusal, OwnerChangeRefusal, PReadRefusal, PWriteRefusal, PathRefusal, Pipe2Refusal, PollRefusal, PosixFadviseRefusal, ProcessCreationRefusal, ProcessEndRefusal, ReadDirectoryRefusal, ReadLinkRefusal, ReadRefusal, ReceiveRefusal, RemovalRefusal, RenameRefusal, SendRefusal, SetGroupsRefusal, SetIdChangeRefusal, SetIdsRefusal, ShutdownRefusal, SignalReceiverRefusal, SigprocmaskRefusal, SigsuspendRefusal, SockaddrCopyRefusal, SocketOptionRefusal, SocketRefusal, SpawnRefusal, StatRefusal, StickyRefusal, SymlinkRefusal, SyscallInterruptionRefusal, SyscallRefusal, ThreadExitRefusal, ThreadKillRefusal, TruncationRefusal, UTimensAtRefusal, UnlinkAtRefusal, WaitStatusRefusal, WriteRefusal.

`SyscallRefusal` (24 cases) gains a case with each new `Syscall` case, which is itself a reason to make it open. Its cases wrap each call's own refusal, so a pattern hands back an open refusal.

### 3.2 Boot and launch configuration: open, with patterns (17 + 2)

These are BootTimeRefusal, CredentialsRefusal, UmaskRefusal, LaunchRefusal, LaunchTableRefusal, UserAddressLimitRefusal, ProcessorCountRefusal, EphemeralPortRangeRefusal, MountRefusal, ProtectedFilesRefusal, PipeDeviceRefusal, SoMaxConnRefusal, TcpSendSpaceRefusal, ProcessIdRefusal, LeaderThreadIdRefusal, TcpReceiveSpaceRefusal and TcpSendSpaceMaxRefusal, plus the faults CurrentDirectoryFault and FileSystemSeedFault.

They refuse the client's own input, so one could argue that they are fixed validation rules and should be closed. The evidence says otherwise:
- **The cases come from measurement too.** Each docstring tags its case "Contradictory", "Unmeasured" or "Unmodelled". Ten of the 17 unions mix those tags. `TcpSendSpaceRefusal.BelowLoopbackSendPipe` ("this library does not model routes") and the `NotReadOn` cases came from new measurements, exactly as syscall refusals do.
- **The line between "no machine could have this" and "nobody has measured this" moves.** `boot-setter-refusals.md` gives that as the reason all setters refuse uniformly: "six setters say 'not measured', not three".
- **The one client handles them as refusals.** PawPrint matches 11 of the 17 exhaustively, and both faults. Every arm fails with the knob's name and a remedy. A wildcard with `describe` is the right fallback for a reason it has not seen.

`CurrentDirectoryFault` and `FileSystemSeedFault` are refusals of the same setters, despite their names. `CurrentDirectoryFault.Path` already wraps the open `PathRefusal`.

### 3.3 Invariant defects: open, no patterns (4)

UnixSystemDefect (99 cases), VirtualFileSystemDefect (18), FileDescriptorRegistryDefect (17) and SimulatedMachineDefect (6). A defect is a bug report about the library. No client branches on which invariant broke: PawPrint matches none of these cases, and only the library's own tests do, through the friend assembly.

These cases are also *removed* when an invariant becomes a fact of the types (`reserved-union-cases.md` §2.5). With patterns, removing a case would mean keeping its pattern for ever. So there are none: `internal` representation and `describe`. Adding and removing a defect are then both free. This also answers that audit's Q4. The reserved-case defects (`ReservedContent`, `ReservedTarget`, `ReservedPark`) can go when their behaviour lands, instead of staying unreachable.

### 3.4 Closed (16)

| union (cases) | what it is | why closed |
| --- | --- | --- |
| BufferRefusal (3) | the client's own buffer (`UserBuffer.Opaque`, `Addressless`) meeting a screen or a transfer | Its own docstring calls it a gap in representation, not in measurement. Its cases are the client's buffer kinds crossed with the two places a kernel touches a buffer. It changes only when `UserBuffer` changes shape, which is a major version anyway. PawPrint *builds* it (`NativeSystemNative.fs:105–106`) to share its message. The 20 `Buffer of BufferRefusal` cases stay open with their unions |
| Ipv4PrefixRefusal (2) | `Ipv4Prefix.create`'s error | Both cases are contradictions over a fixed domain: a length outside [0, 32], or host bits set. A parse error |
| SignalMaskRefusal (1) | `SignalMask.ofWord`'s error | A word wider than the flavour's `sigset_t`. A parse error |
| DirectorySourceRefusal (2) | when a flavour's `link(2)` refuses a directory source: `BeforeDestination` (Darwin) or `Last` (Linux) | A flavour rule, like `EmptyPathRule`. Not a refusal |
| UnixByteStringDefect (1), UnixPathTextDefect (2) | the errors of `UnixByteString.ofBytes` and of the text parsers | Parse errors of a fixed format. PawPrint reads `ContainsNul offset` |
| AbsoluteUnixPathError (7), FileNameError (4), UnixPathError (2), SymlinkTargetError (2), SimulatedUnixReleaseError (3) | parse errors | A fixed input format |
| SimulatedUnixPlatformError (2) | `SimulatedUnixPlatform.create`'s error | A parse error. Its `UnmeasuredKernel` case is a model gap, but measuring a kernel removes refusals rather than adding a case |
| EpollCtlError (9) | Linux's `epoll_ctl` failures, in the order Linux decides them | A measured, fixed answer vocabulary, as `UnixError` is |
| BindFault (7) | `bind(2)`'s checks, ordered per flavour by `bindFaultOrder` | Flavour rule data |
| GetCwdDestinationFault (2) | how a flavour's `getcwd` treats an unwritable destination | A flavour rule |
| RefusalError (2) | whether a refused connection's `ECONNREFUSED` is `Pending` or `Reported` | Socket state. Not an error |

`DescriptorLimitRefusal` is a record, so it is out of scope.

## 4. PawPrint today, and what changes

### 4.1 Every arm that matches a refusal case ends the run

I read every match rule in `WoofWare.PawPrint/` that names a case of a kernel refusal, defect, error or fault:
- **135 rules name a refusal case.** They are in NativeSystemNative.fs (116), EmulatedKernel.fs (18) and MinipalRandom.fs (1). (My scan also caught a comment in SignalDispatch.fs, which is not a rule.) **75 lines** have the plain form `| Error (XRefusal.Case …)`: 53 in NativeSystemNative, 21 in EmulatedKernel and 1 in MinipalRandom. Some rules span several such lines, joined by or-patterns. The brief's count of 73 was probably taken another way, or before `ShutdownRefusal`; it does not change the finding. The other rules are inside helpers that compute a remedy string per case: `closeRefusalMessage`, `fstatRefusalMessage`, `describeUnlinkAtRefusal`, the `refused`, `refuse` and `reachedBy` matches, and the advice for `FChModAt` and `Access`.
- **Every one of them fails.** It either calls `failwith` directly, or builds a string that reaches `failwith` through one of: `closeRefusalMessage` (called at :3714, :4643 and :6718, each `failwith`); `fstatRefusalMessage` (:3919); `describeUnlinkAtRefusal` and the `FChModAt` advice, through `Result.mapError` into `pathSyscall`, whose `Error` arm is `failwith` (:1291); or the `refused`, `refusedFinishing` and `refusedSending` helpers, each typed `'a` and ending in `failwith`. Some arms fail because the refusal "is an interpreter bug": an internet domain refused as unmodelled, `PosixFadviseRefusal.NotProvided`, or `UnixByteStringDefect.ContainsNul`. No arm matching a specific case recovers.
- **8 rules name a non-refusal case:** `CurrentDirectoryFault` (4), `FileSystemSeedFault` (3) and `UnixByteStringDefect` (1). All fail.
- There are about a dozen wildcard arms, `| Error _ -> …`, that do not fail. Each sits on a lookahead call (`admitSockaddrCopy`, the `setsockopt` and `getsockopt` admissions) whose refusal the next call raises again, or on a `Result` that is not a refusal. They name no case, so openness does not affect them.

### 4.2 Payloads PawPrint reads

The patterns must hand these back:
- nested refusals: `BindRefusal.Copy`, `ConnectRefusal.Copy`, `UnlinkAtRefusal.Removal`, `RemovalRefusal.Sticky`, `RenameRefusal.Sticky`, `CloseRefusal.Release`, `FChModAtRefusal.ChMod`, `ReadLinkRefusal.Path` and `CurrentDirectoryFault.Path`;
- `BufferRefusal`, from every `X.Buffer`;
- the `DescriptorLimitRefusal` record;
- `SocketDomain` from `UnmodelledDomain (_, domain)`, matched further, as in `ListenRefusal.UnmodelledDomain (_, SocketDomain.Unix)`;
- `MountRefusal.NotReportableUnder (_, flavour)`, and `TcpSendSpaceRefusal.AboveSocketBufferMax (_, max)` and `BelowLoopbackSendPipe (_, sendPipe)`;
- `LaunchRefusal.CurrentDirectory (directory, fault)`, and all of `FileSystemSeedFault`'s and `CurrentDirectoryFault`'s fields.

Nested patterns over tuples work (§1.1), so `BindRefusal.Reason.Copy (SockaddrCopyRefusal.Reason.UnmodelledDomain (_, SocketDomain.Unix))` is fine.

### 4.3 What changes in PawPrint under A2

- **Every pattern on an open union gains `.Reason`:** `| Error (OpenRefusal.DescriptorLimit refusal)` becomes `| Error (OpenRefusal.Reason.DescriptorLimit refusal)`. **The spelling cannot stay unchanged under A2**: §1.1 measured that the bare name resolves to the hidden case and fails with FS1093. Only A3 keeps it. That touches about 186 pattern lines, mechanically.
- **41 matches are exhaustive today, and 40 of them gain a wildcard.** In EmulatedKernel.fs: LaunchRefusal, CurrentDirectoryFault, FileSystemSeedFault, BootTimeRefusal, CredentialsRefusal, ProcessorCountRefusal, UserAddressLimitRefusal, MountRefusal, EphemeralPortRangeRefusal, SoMaxConnRefusal, TcpSendSpaceRefusal, TcpSendSpaceMaxRefusal and ProtectedFilesRefusal. In NativeSystemNative.fs: UnlinkAt, Close, FStat, GetCwd, GetGroups, FChModAt, Access, FChMod, PosixFadvise, FLock, PRead, PWrite, Read, LSeek, ReadLink, Bind, Listen, Accept, SockaddrCopy, GetSockName, Shutdown, Receive, Write (twice), Send, EpollWait and Poll. The 41st, over `UnixByteStringDefect` (NativeSystemNative.fs:1261), stays exhaustive because that union is closed. Each new wildcard fails with `describe` and the same context as its siblings. A match that also covers a nested open refusal case by case, as `closeRefusalMessage` covers `DescriptionReleaseRefusal`, needs a wildcard at that level too.
- **PawPrint loses a prompt.** These matches were written exhaustively on purpose: when the library adds a reason, FS0025 makes PawPrint write a remedy for it. Under A2 the new reason lands in the wildcard silently, with a generic message. B keeps the prompt. Under A2 a PawPrint test could keep it instead, by reflecting over the hidden cases (`BindingFlags.NonPublic`) and comparing them with a list of reasons PawPrint gives remedies for. That is Q4.
- **Three constructions:**
  - `NativeSystemNative.fs:5076`, `refuse (BindRefusal.Copy refusal)`. Give the sockaddr screen its own handler, as connect's `refuse` already is at :5477.
  - :105 and :106 build `BufferRefusal`, which stays closed, so nothing changes there.
- **Two in PawPrint's tests:** `TestUserBufferCheck.fs:177` and `:220` build `UserAddressLimitRefusal` cases to compare with `shouldEqual`. Rewrite them as pattern matches, or move the tests to `WoofWare.PosixKernel.Test`, whose friend access lets them build cases.
- `%A{refusal}` in failure messages keeps printing the case name (§1.3).

## 5. `describe`, equality and printing

- **`describe`** is unchanged. It is a total match over the internal cases inside the library, and the wildcard is where a client calls it. The test `every refusal a public function answers has a describe` stays as it is.
- **Equality, comparison and hashing** stay structural and available to clients (§1.3). Clients cannot construct a refusal, so they can only compare refusals they were given.
- **Printing:** `%A`, `%O` and `ToString` still print case names and fields, so logs read as they do today. A reader may see a case name that is not matchable; the pattern of that name is.
- **Docstrings.** A client sees only the patterns, so each pattern carries the client's prose: what the reason means, and its payload tuple in order. The internal case keeps a one-line pointer to its pattern. That is a move of prose, so `scripts/check-docstring-attachment.py` may report it. Read the report and add the `Docstring-attachment: reviewed` trailer (Q6).

## 6. The API baseline and its order test (PR #1766)

- **Converting a union changes the baseline**: its case members, `Tags` and `NewX` go, and its patterns appear. Each conversion PR regenerates the baseline with `Update API surface`. This is allowed before 1.0.
- **`Every public union keeps its committed cases at their tags`** reports `NoLongerAUnion` once for each converted union, because `parse` sees no "union type with N cases" line. The failure message already gives the remedy before 1.0 (regenerate). After 1.0 the same report is correct: hiding a union's cases is breaking. The test needs no change. A hidden union is invisible to it, and should be, because its tags are not public.
- **New guards**, in the pilot PR, so the later batches are covered as they land:
  1. **Every hidden case has exactly one pattern, and every pattern matches exactly its case.** For each union with hidden representation whose module has a `Reason` module, and each case (`FSharpType.GetUnionCases (t, BindingFlags.NonPublic)`):
     - build the case with generated fields, distinct where the types allow, so that a swapped tuple is caught;
     - assert that exactly one pattern answers, that it is the case's own, and that its payload equals the fields in declaration order.

     Mutation checks: delete a pattern; swap a two-field payload (`EphemeralPortsExhausted of uint16 * uint16` is the natural target); make a pattern answer for two cases. Each must fail the test.
  2. **A ratchet over the classification.** A test lists the closed unions (§3.4) and the unions not yet converted. It fails if a type named `*Refusal`, `*Defect` or a boot fault has public cases without being on either list. The second list shrinks with each batch and is empty at the end, as `pal-residue-allowlist.txt` became.
  3. **`LibraryNames.namesInSource`** learns that a method named `|X|_|` has the source name `X`. Then the README's `BindRefusal.Reason.UnmodelledMulticast` resolves. Code spans such as `MkNodRefusal.Fifo` in the README become `MkNodRefusal.Reason.Fifo`.

## 7. Writing the patterns: by hand, or a generator

386 patterns at about six lines each, docstring included, is about 2,300 lines over six or so PRs.

- **A checked-in generator** with a CI check that its output matches the committed code would be a second source of truth, with its own maintenance and failure modes. The repository dislikes that, and the patterns are too simple to need it. They also cannot live in one generated file: a pattern module must sit inside its union's module, and F# will not reopen a module from another file.
- **Recommended: a throwaway script for each batch, and the guard test as the oracle for ever after.** The script reads the union's cases and docstrings and writes the `Reason` module into the source. Its output is reviewed as ordinary code in the PR diff, and the commit message names it. When a later PR adds a reason, it writes the pattern by hand. Guard 1 fails if the pattern is missing or wrong. That is the machine checking the invariant rather than a generator re-deriving it.

## 8. What changes in the README

On top of #1870's "Unions that gain cases". In the paragraph that says adding a case is breaking, "any public union" becomes "any union whose cases are public". Then add:

> ### Refusals are open
>
> A refusal is this library saying it will not answer. Nobody has measured what the kernel does, or the model does not hold what the answer needs. The library cannot promise that its model of a real kernel is complete, and each newly measured difference between Linux and Darwin brings a new reason to refuse. So a refusal is a feature request, not an outcome a client handles in normal operation, and matching every reason a refusal can have is not something a client should do.
>
> The refusal types are therefore open. Their cases are not public, so a client can neither build one nor match it exhaustively. Each refusal type's module has a `Reason` module with one pattern per reason, which a client uses where it has something to add, and every such match ends with a wildcard:
>
> ```
> match UnixSocket.bind fd address length system with
> | Error (BindRefusal.Reason.UnmodelledMulticast (socket, address)) -> …
> | Error refusal -> failwith (BindRefusal.describe refusal)
> | Ok (answer, system) -> …
> ```
>
> A minor version may add a reason. A client built against an older version meets it in its wildcard, which is where `describe` belongs. Removing a reason's pattern, or changing what it gives back, is a breaking change. A reason the library no longer produces keeps a pattern that never matches.
>
> The refusals of the boot and launch setters are open in the same way, including `CurrentDirectoryFault` and `FileSystemSeedFault`. The defects that the `checkInvariants` functions report are open too, and have no patterns: a defect is a bug in this library, and the thing to do with one is report it with `describe`.
>
> These keep public cases: `BufferRefusal`, which describes the client's own buffer; the errors of the parsers that build a value; and the flavour rules and states whose names happen to end in `Refusal`, `Error` or `Fault`.

The example is not tagged `fsharp`, because TestReadme runs every `fsharp` block. Either make it a runnable example with a `// Prints:` trailer, or leave it untagged. Also update the "Answers and refusals" paragraph on `describe`, the case names in code spans, and the `.fsproj` `Description` (#1870's text says any new case is a major version).

## 9. PR breakdown

Each PR is one feature. It runs the PosixKernel suite and the default PawPrint suite. It also runs the Guest fixtures, because PawPrint's handlers change. It regenerates the API baseline. The pilot waits for #1766 (the baseline) and #1870 (the strict policy).

1. **The mechanism, with `BindRefusal` as the pilot.** `BindRefusal` has a nested open refusal, a payload of two equal types, and PawPrint builds it once, so it exercises every part. The PR contains:
   - `internal` representation and `BindRefusal.Reason`, with fieldless reasons as `unit option`;
   - guards 1–3 of §6, with their mutation checks recorded in the commit message;
   - the README section of §8;
   - PawPrint's bind handler: `.Reason`, a wildcard, and the construction at :5076.

   `SockaddrCopyRefusal` stays public in this PR, which shows that open and closed unions mix in one pattern. Small.
2. **Invariant defects, describe-only.** The four unions become `internal`; there are no patterns and no PawPrint change. Independent of 1 except for the ratchet; it can land first if the ratchet goes with it.
3. **Sockets.** UnixSocket.fs and UnixConnection.fs: SockaddrCopy, Listen, GetSockName, SocketOption, Socket, Accept, Shutdown and Connect.
4. **Reading and writing.** UnixReadWrite.fs: Read, PRead, Write, PWrite, Receive, Send and CopyFileRange.
5. **Descriptors and lifetimes.** UnixDescriptor.fs and ObjectLifetime.fs: LSeek, FLock, PosixFadvise, Truncation, EndedWriteSignal, Close, Fcntl, Dup2, Dup3, BytesAvailable, GetGroups, FileClone and DescriptionRelease.
6. **Paths and the namespace.** PathWalk.fs, UnixNamespace.fs, UnixPathResolution.fs, and the rules files' refusals: Path, Removal, UnlinkAt, Sticky, Access, MkNod, Owner change, SetIdChange, Execution, LinkRead, ModeChange, and the stat and chmod/chown families.
7. **Events, signals, time, identity and processes.** UnixPoll.fs, UnixKqueue.fs, UnixSignal.fs, SignalState.fs, SyscallInterruption.fs, UnixClock.fs, UnixEntropy.fs, UnixCredentials.fs, UnixScheduling.fs, UnixTaskLifecycle.fs, FileSystemStatistics.fs, ProcessTermination.fs, SimulatedMachine.fs, and `SyscallRefusal`.
8. **Boot and launch.** UnixBootImage.fs, ProcessLaunch.fs, `CurrentDirectoryFault` and `FileSystemSeedFault`. EmulatedKernel's 13 exhaustive matches gain wildcards. This one moves PawPrint.Test's two constructions.

PRs 3–8 are mechanical: the throwaway script, then PawPrint's call sites, then the baseline and the ratchet list. Each is medium-sized: 30–80 patterns, and 20–40 PawPrint lines. Once the ratchet list is empty, the ratchet test loses its countdown list.

Optional, and separate: renames of the closed unions whose names mislead (Q3).

## 10. Questions for Patrick

1. **Spelling.** The same-name patterns you proposed do not compile (§1.1). Which instead? `BindRefusal.Reason.UnmodelledMulticast` (A2, recommended), `BindRefusalReason.UnmodelledMulticast` (A2'), or today's spelling with an opaque wrapper (A3), at the cost of rewriting about 1,760 library and test references? And is "Reason" the right word for the nested module?
2. **`BufferRefusal` closed?** It describes the client's own buffer, changes only with `UserBuffer`, and PawPrint builds it. The 20 `Buffer of BufferRefusal` cases stay open with their unions.
3. **Misleading names on closed types.** `DirectorySourceRefusal` is a flavour rule, `RefusalError` a socket state, and `GetCwdDestinationFault` a flavour rule. `UnixByteStringDefect` and `UnixPathTextDefect` are parse errors, as are `Ipv4PrefixRefusal` and `SignalMaskRefusal`. Rename them before 1.0, so that the name tells a client which kind of type it is?
4. **PawPrint's prompt for new reasons.** 41 exhaustive matches lose FS0025 when a reason is added. Should they accept the wildcard's generic message, or should a PawPrint test reflect over the hidden cases to keep the prompt? Making PawPrint a friend assembly would also keep it, but then PawPrint stops being an honest client of the public API. I recommend against that.
5. **Defects with no patterns** (C), so that adding and removing an invariant are both free?
6. **Docstrings:** move the client-facing prose from each internal case to its pattern, leaving a pointer on the case? Or keep it on the case and give the pattern one line?
7. **B instead of A?** Only if PawPrint's compile-time prompt matters more to you than refusals being non-exhaustive by construction.

## Decision (orchestrator, 2026-10-11)

- **Spelling: the nested `Reason` module**, e.g. `| BindRefusal.Reason.UnmodelledMulticast (socket, address) -> ... | _ -> ...`. It leaves the ~1,760 references in the library and tests untouched, and reads as what it is: the reason for the refusal. The opaque wrapper would keep today's client spelling but rewrite every library reference; a sibling module reads worse. Patrick may still rename `Reason` in PR 1's review.
- **Field-less cases' patterns return `unit option`**, since `bool`-returning partial patterns fail for F# 8 clients (FS3350).
- **`BufferRefusal` stays closed**, as classified: it is a fixed classification of a client pointer, not a gap in the model.
- **Rename closed types whose names mislead**, so that the suffix `Refusal` always means an open union of things the model cannot yet answer. Do it before 1.0, in its own PR after the batches; each rename keeps its docstring.
- **No reflection test in PawPrint** to prompt on new reasons. PawPrint's wildcard fails with the refusal's `describe`, which already says what was refused. PawPrint names a case only to add how a .NET caller could reach it, and that can be added when a new reason is first met.
- **Defects: `describe` only**, no patterns. A client prints a defect; it never branches on one.
- **Docstrings move to the patterns**, which are what a client sees. The internal cases keep at most a one-line pointer.
- Order: PR 1 (mechanism, `BindRefusal` pilot, guard tests, README section), then PR 2 (defects), then the mechanical batches one at a time, then the renames.

## Superseded (2026-10-12): refusals become one thrown exception

Patrick's objection: an open union only helps a function that already returns one. A function that has no refusal channel today needs a major version to gain one, so the open-union design still asks us to predict every place that might refuse. The only client also turns every refusal into `failwith` (§4.1). Decision: a single not-modelled exception, converted in one PR. #1873 and #1874 had merged, and #1875, #1876, #1878, #1879 and #1880 were closed unbuilt.

Options considered: (A) give every function that might refuse a refusal channel now; (B) one exception type for "not modelled"; (C) one opaque `Refusal` type returned everywhere. B chosen.

Orchestrator's decisions within B:
- **Where the throw happens.** Considered: (i) throw where the refusal arises, so every internal function throws and tests read an internal payload off the exception; (ii) keep the refusal unions as **internal** values, with internal `Result`-returning functions, and throw only in the public entry points. Chose (ii). The functional core keeps its typed values, nested refusals keep composing as they do now, and the library's tests keep matching cases through the friend assembly. Only the boundary changes. The cost is a thin public wrapper per entry point.
- **Public surface.** `UnmodelledException`, sealed, deriving from `System.Exception`, with an internal constructor and a message built from the refusal's `describe`. It has no public reason structure and no `Reason` patterns; those can be added later in a minor version if a client needs them, and removing them later would be a major version. `describe` becomes internal.
- **Not every refusal is "not modelled".** A refusal that a correct client cannot reach throws the BCL exception .NET uses for that: `ArgumentException`/`ArgumentOutOfRangeException` for a contradictory input (boot settings tagged "Contradictory"), `InvalidOperationException` for misuse such as `ThreadExitRefusal.Parked`, and `PlatformNotSupportedException` for a call the flavour lacks (`NoSuchCall`, `NotProvided`, `UnmodelledFlavour`). These are documented on the function. The test for which kind: could a correct client, following the documentation, reach this case? If so, it is `UnmodelledException`.
- **The policy** in the README: any call may throw `UnmodelledException`, and a minor version may add or remove the places that do. A throw leaves no state behind, because the state the caller passed in is immutable, so a client may catch the exception and carry on with that state.
- Closed value types that are not refusals (§3.4: parse errors, flavour rules, `RefusalError`, `BindFault`, `EpollCtlError`) stay public values. Invariant defects (§3.3, #1877) are unaffected.
