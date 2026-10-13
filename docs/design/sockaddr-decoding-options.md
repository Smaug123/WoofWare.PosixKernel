# Decoding `struct sockaddr` in WoofWare.PosixKernel

*Options document, 2026-10-03. Part of the "PosixKernel knows nothing of the CLR" workstream (audit item #14). Code references are at branch `kernel-sockaddr-decoding`, off `origin/main` `2a63dfc5`. The new probe is committed there as `c25ba78a`: `docs/plans/2026-08-23-posix-kernel-extraction/sockaddr-decoding.c`, with its outputs `sockaddr-decoding.darwin-27.0-uid501.txt` and `sockaddr-decoding.linux-6.18.5-aarch64-root.txt` beside it. No library or PawPrint code has changed.*

**The decision already taken (Patrick, 2026-10-03):** the kernel decodes a `struct sockaddr` itself. `bind`, `connect` and every later call that takes an address in will take the caller's bytes and declared length, as path calls take `PathArgumentBytes`, and the kernel answers every error about those bytes.

**What this document decides:** the shape of that API, what the decoder must answer, and how to split the work into PRs.

**Recommendation in one line:** keep the two-call admission that `bind` and `connect` already have, and change only what crosses on the second call: the client passes the exact bytes the admission names, not a family and an endpoint (option A, §5). Copy-out (`getsockname`, `accept`) is a separate, later PR (§7).

## 1. What there is today

### The library's entry points that take or return an address

| entry point | direction | address parameters today |
| --- | --- | --- |
| `UnixSocket.admitSockaddrCopy` (`UnixSocket.fs:488`) | in, first call | `SockaddrCopySyscall` (`Bind`/`Connect`), `fd`, `destination : UserBuffer`, `declaredLength : uint32`. Returns `SockaddrCopyAdmission`: `Answered of UnixError` or `Transfer of length * fields : SockaddrCopyFields` |
| `UnixSocket.bind` (`UnixSocket.fs:1037`) | in | `destination : UserBuffer`, `declaredLength : uint32`, **`family : int option`, `endpoint : InternetEndpoint option`** |
| `UnixConnection.connect` (`UnixConnection.fs:1064`) | in | the same four |
| `UnixConnection.connectSocket` (`UnixConnection.fs:240`) | in | `socketId`, `nonBlocking`, `declaredLength`, `family`, `destination` (the ladder without the descriptor screens; public, called from tests) |
| `SockaddrCopyFields` with `checkSupplied` (`UnixSocket.fs:12-46`) | in | tells the client which fields to read (`Nothing`, `Family`, `FamilyAndEndpoint`), and fails if it reads a different set |
| `UnixSocket.getsockname` (`UnixSocket.fs:1372`) | out | `destination`, `declaredLength`. Answers `Reported of InternetEndpoint * reportedLength`, or `Failed of error * lengthOverwritten` |
| `UnixConnection.accept` / `finishAccept` (`UnixConnection.fs:1389`, `:1597`) | out | `destination`, `declaredLength`. Answers `AcceptOutcome.Accepted of fd * peer : InternetEndpoint * reportedLength` |
| `UnixConnection.acceptConnection` | out | answers the `TcpConnection`, whose `ClientAddress` is an endpoint |
| `SimulatedUnixPlatform.encodeInternetSockaddr` (`SimulatedUnixPlatform.fs:1197`) | out | `InternetEndpoint -> byte[]`, the full 16 bytes as the kernel copies them out, `sa_len` included on Darwin |

The library has no `getpeername`, `sendto`, `recvfrom`, `sendmsg` or `recvmsg`, and PawPrint has no shim handler that would call one.

The layout facts are already in the library. `Sockaddr.fs` holds `SockaddrField`, `InternetSockaddr`, `InternetV6Sockaddr` and `SockaddrFamilyField`. `SimulatedUnixPlatform` holds the family field per flavour, `AF_INET` and `AF_INET6`, the sizes, and `bindAddressLength` with its `BindLengthVerdict`. Every *rule* about the address is in the library too: the length verdict, `bindFaultOrder`, `AF_UNSPEC`'s handling, and the connect ladder. **What the client still does is the read itself:** it takes three fields out of the bytes, in their ABI byte orders.

### Where PawPrint decodes or encodes for the kernel

All of it is in `WoofWare.PawPrint/Native/NativeSystemNative.fs`:

- **`SystemNative_Bind` (`:4697`) and `SystemNative_Connect` (`:5224`).** Each calls `admitSockaddrCopy`, resolves the pointer, and runs `requireBufferRoom` over the admitted length. It then reads `sa_family` with `readSockaddrFamily` (`:890`: one byte at offset 1, or a little-endian `uint16` at 0), `sin_port` (big-endian) and `sin_addr` (big-endian). It builds the `InternetEndpoint` and calls `bind` or `connect`. These are the only places where the client decodes on the kernel's behalf.
- **`SystemNative_Accept` (`:4957`, finishing at `:5096` and `:5165`) and `SystemNative_GetSockName` (`:5385`).** Each calls `encodeInternetSockaddr`, then writes `min declaredLength reportedLength` bytes of it. The encoding is already the library's. The truncation rule is a kernel fact that the client applies.
- **`EmulatedKernel.connectSocket` (`EmulatedKernel.fs:1515`).** It wraps `UnixConnection.connectSocket`, with decoded family and destination. **It has no callers.** Its docstring still says "six fixtures call it"; #1717 moved those fixtures onto syscalls. It is dead code.

### Byte orders, and where each convention belongs after the move

The kernel ABI is fixed:

- `sa_family` is in the machine's byte order: two bytes at offset 0 on Linux, one byte at offset 1 on Darwin.
- `sin_port`, `sin6_port` and `sin_addr` are in network order.
- `sin6_scope_id` is in the machine's byte order.

The `SockaddrField` docstring says callers disagree. That disagreement belongs to the **shim's** pure accessors, not to the kernel. The accessors are `SystemNative_{Get,Set}{AddressFamily,Port,IPv4Address,IPv6Address}` (`:1779`-`:2350`):

- `GetPort` and `SetPort` swap the port to and from host order (`ntohs`/`htons`).
- `GetIPv4Address` and `SetIPv4Address` copy the address word verbatim.
- `GetIPv6Address` copies the scope id in host order.
- `GetAddressFamily` converts the platform's `AF_*` to PAL numbering (`SocketArgumentsPal`).

After the move:

- **The kernel decodes in ABI order, privately.** `bind` and `connect` are its only consumers. No client ever needs an order-normalising accessor from the library, so the `SockaddrField` docstring's argument for carrying no order still holds.
- **The machine order of `sa_family` becomes the library's fact.** PawPrint's `readSockaddrFamily` justifies little-endian with "both architectures PawPrint models are little-endian". In the library, that should be a match over `SimulatedUnixArchitecture`, so that adding a big-endian architecture fails to compile there.
- **The shim's conventions stay in PawPrint.** That covers the eight accessors, `SocketArgumentsPal`'s family numbering, and the shim's own screens (a null pointer, a negative length, and `IsInBounds`). They go on reading the layout facts in `Sockaddr.fs`. Those facts are POSIX ABI, not PAL, so they stay public in the library. `readSockaddrFamily` and `writeSockaddrFamily` stay in PawPrint for the accessors.

## 2. What is measured

### Before this work

- **`socket-address-length.c`** (2026-10-02). This sweeps the 32-bit length word for `bind`, `connect`, `accept`, `accept4`, `getsockname` and `getpeername`, and measures the check order:
  - EBADF comes first everywhere.
  - ENOTSOCK comes next, except that Linux's `connect` judges the length and the copy before it: EINVAL outside [0, 128], and EFAULT for an unmapped buffer.
  - Darwin answers ENAMETOOLONG above 255.
  - Copy-out never errs on Darwin. On Linux, a negative length is EINVAL.
  - **This answers the brief's question about whether EBADF and ENOTSOCK come before EFAULT and EINVAL. It is already in the model (`admitSockaddrCopy`) and needs no new measurement.**
- **`docs/plans/2026-08-20-socket-bind-listen.md`:**
  - `bindFaultOrder`, measured pairwise: Linux checks the length before the family, and Darwin the family before the length.
  - The two `AF_UNSPEC` bind rules.
  - On Darwin, `sa_len` at 0, 8, 24 or 32 is ignored.
- **`docs/plans/2026-08-21-socket-connect.md`:**
  - One wrong family (AF_APPLETALK) on stream and on datagram.
  - `AF_UNSPEC` at length 16 with an **all-zero** blob.
- **`sockaddr-layout.c`** gives the field offsets. `TestSockaddrLayoutAgainstHost` checks the encoder against `IPEndPoint.Serialize()` on the host.

### New (`sockaddr-decoding.c`, committed in `c25ba78a`)

**Scope.**
- Machines: Darwin 27.0.0 arm64 (uid 501) and Linux 6.18.5 aarch64 (Apple `container`, debian:trixie, root).
- Sections F, L, Z and X ran three times on each machine. D and T ran twice on Darwin and three times on Linux. All runs agreed apart from port numbers and the T rows skipped when a port byte was `0xAA`.
- Calls: `bind` and `connect`, each on stream and on datagram.
- Family values: on Darwin, 0..255 (all of them). On Linux, 0..65535 at length 16, and elsewhere 0..300 plus eight words with a high byte set (`0x0200`, `0x0202`, `0x0302`, `0x0a02`, `0x8002`, `0xff02`, `0xfffe`, `0xffff`).
- Lengths: 0, 1, 2, 8, 15, 16, 17, 28 and 128.
- Darwin `sa_len`: 0..255 at lengths 15, 16 and 17.
- `sin_zero`: all zero, all `0xFF`, and each of its eight bytes alone set to 1.
- Trailing bytes: lengths 17..128 with the bytes after the first 16 set to `0xFF`.
- Copy-out: declared lengths 0..20 for `getsockname`, `getpeername` and `accept`.

**What the decoder must reproduce**, at the swept lengths (the probe's summary has more detail):

| fact | Linux | Darwin |
| --- | --- | --- |
| width of the family field | two bytes, machine order: `0x0202` is not `AF_INET` | one byte at offset 1 |
| `sa_len` | not present | **ignored**: all 256 values behave as the length argument says |
| `sin_zero` | ignored | ignored |
| bytes after the first 16 | ignored, up to 128 | not reachable: any length but 16 is EINVAL |
| length 0 or 1 | EINVAL, every call | EINVAL, every call (nothing is copied) |
| `bind`, length 2..15 | EINVAL for every family | EAFNOSUPPORT for every family except `AF_UNSPEC` and `AF_INET`, which get EINVAL |
| `bind`, length ≥ 16 | `AF_INET` binds; `AF_UNSPEC` binds only an all-zero address (earlier measurement; 127.0.0.1 is EAFNOSUPPORT here); every other family is EAFNOSUPPORT | stream: as for 2..15, except that exactly 16 binds. Datagram: also accepts **`AF_INET6`'s number (30)** and reads the blob as a `sockaddr_in` |
| stream `connect`, length 2..15 | `AF_UNSPEC`: a no-op on an idle socket. Every other family: EINVAL | **family before length**: EAFNOSUPPORT for every family except 0 and 2, which get EINVAL |
| stream `connect`, `AF_UNSPEC` at 16 | a no-op | **read as `AF_INET`**: 127.0.0.1 on a closed port is ECONNREFUSED |
| datagram `connect` | `AF_UNSPEC` succeeds at every swept length from 2. Below 16, every other family is EINVAL | **length before family**: EINVAL at every length but 16, then EAFNOSUPPORT for every family but `AF_INET` |
| copy-out | the first `min(declared, 16)` bytes of the full address; the cell gets 16 at every declared length | the same |

**Three Darwin rows where today's model is wrong.** All three are reachable today by a raw-P/Invoke guest. None is reachable through managed `Socket`.

1. **A stream `connect` checks the family before the length.** At every swept length from 2 to 128 except 16, a family other than 0 or 2 gets EAFNOSUPPORT. The model checks `lengthVerdict` first (`UnixConnection.fs:855`) and answers EINVAL.
2. **A stream `connect` with `AF_UNSPEC` is an `AF_INET` connect.** The model answers EADDRNOTAVAIL at length 16 whatever the address. The earlier measurement used an all-zero blob, and port 0 happens to give EADDRNOTAVAIL. At any other length the model refuses (`UnspecDeclaredLength`), where Darwin answers EINVAL.
3. **A datagram `bind` accepts the family number 30.** It binds 127.0.0.1 or 0.0.0.0, and 8.8.8.8 gets EADDRNOTAVAIL. The model answers EAFNOSUPPORT, because `familyFault` is true for every family other than 0 and 2.

**Refusals the new data lets the model lift:**
- Linux datagram `connect` with `AF_UNSPEC` below length 16 succeeds at 2, 8 and 15 on an idle socket.
- Darwin `AF_UNSPEC` at a length other than 16 is EINVAL, on stream and datagram.

### Still unmeasured, and why that is acceptable now

- **The fields of `sockaddr_in6`: v4-mapped addresses, `sin6_scope_id` and `sin6_flowinfo`.** These matter only once an `AF_INET6` socket gets an address. Today every IPv6 socket is refused (`SockaddrCopyRefusal.UnmodelledDomain`) before anything is decoded. On Linux `connect`, the refusal comes after the copy's own errors, which are measured. So no decoder could have a consumer for these fields yet. They belong to the IPv6 socket feature.
- **`sockaddr_un`.** It is the same story with the Unix-domain sockets feature: a path, Darwin's `sun_len`, and Linux's abstract namespace.
- **A copy that faults partway, where the first page is mapped and the next is not.** PawPrint's memory has no partial mapping, and `UserBuffer` cannot express one. The answer stays where it is today: `requireBufferRoom` refuses a copy that reaches past the guest's storage.

## 3. Constraints on the design

1. **The kernel decides whether, and how much, it copies. That decision depends on the flavour and the syscall.**
   - Darwin copies nothing below 2.
   - Linux rejects lengths above 128 before it copies.
   - Linux's `connect` copies before it checks that the descriptor is a socket.
   - EBADF and ENOTSOCK otherwise come first.

   A client that must produce the bytes *before* the kernel has said whether it reads them will either read bytes no kernel reads or need the kernel's rule. This is exactly why stage 9l chose two calls. The plan (`2026-08-23-posix-kernel-extraction.md`, at "Two calls rather than one") rejected "the library takes the sockaddr bytes" in its single-call form: "It would trade a correct answer for a crash on inputs a real kernel never reads."
2. **The errors about the address are not a parse step.** Where a short length or a foreign family lands depends on the syscall, the socket kind and the flavour:
   - Linux `bind`: length, then family.
   - Darwin `bind` and stream `connect`: family, then length.
   - Darwin datagram `connect`: length, then family.
   - Linux stream `connect`: `AF_UNSPEC` first, then the socket's state, then length, then family.

   So no `parse : bytes -> Result<Address, errno>` can be called before the syscall. Decoding must produce *what was read*, and the syscall's ladder decides which fault wins. The ladders already do this, given `family : int option` and `endpoint : InternetEndpoint option`.
3. **PawPrint's guest-visible behaviour must not change.** Today the client reads exactly the bytes the admission names, so a change that keeps that set of bytes can be checked bit for bit against the old decoder.

## 4. The options

### Option A: the same two calls, with bytes instead of fields on the second

```fsharp
type SockaddrCopyAdmission =
    | Answered of error : UnixError
    /// The copy is reached: read exactly `length` bytes from the start of the
    /// caller's buffer (possibly zero) and pass them to the syscall.
    | Transfer of length : int

UnixSocket.bind :
    fd:int -> destination:UserBuffer -> declaredLength:uint32
    -> copied:ImmutableArray<byte> -> UnixSystem<_,_> -> Result<BindAnswer * UnixSystem<_,_>, BindRefusal>
UnixConnection.connect : (the same)
UnixConnection.connectSocket :
    SocketId -> nonBlocking:bool -> declaredLength:uint32 -> copied:ImmutableArray<byte> -> ...
```

**How it works.**
- `bind` and `connect` run the admission again, as they do today.
- They assert that `copied.Length` equals the admitted length, or 0 when the answer is `Answered`. A mismatch is a `failwith` naming the caller's bug, which replaces `SockaddrCopyFields.checkSupplied`.
- A private `decodeInternet : SimulatedUnixPlatform -> ImmutableArray<byte> -> SockaddrContents` produces the `family : int option` and `endpoint : InternetEndpoint option` that the ladders already take. The family is present from length 2, the endpoint from length 8, and everything past byte 8 is ignored, as measured.
- The ladders do not change.
- `SockaddrCopyFields` and `checkSupplied` go.

**PawPrint.** The bind and connect handlers lose their three field reads. They read `length` bytes with one `readBytesThrough` after `requireBufferRoom`, which already runs over that same length. `EmulatedKernel.connectSocket` is deleted.

**Blast radius.** Two handlers, plus the call sites of every function whose signature changes:
- `UnixSocket.bind`: 25 test call sites in 12 files.
- `UnixConnection.connect`: 18 sites in 10 files.
- `connectSocket`: 9 sites in 5 files.
- `admitSockaddrCopy` and `SockaddrCopyFields` in `TestConnect` and `TestSocketAddressLength`: about 30 sites.

All of these are mechanical. `(Some family) (Some endpoint)` becomes a call to a test helper that encodes a blob.

**Public API removals (the package is published):** `SockaddrCopyFields`, `SockaddrCopyFields.checkSupplied`, and the `fields` field of `SockaddrCopyAdmission.Transfer`. The signatures of `bind`, `connect` and `connectSocket` change.

**Error order.** It does not change. The admission still answers everything that comes before the copy, and the ladders still answer everything after it.

**Information.** The kernel sees every byte it copies. The client keeps the knowledge it alone has: which pointers name storage (`UserBuffer`), and whether the storage reaches the admitted length.

**Reversibility.** Good. Moving later to option C below is mechanical: C's single call is A's admission followed by A's syscall, inside the library. Going from C back to A would reintroduce a protocol that clients had stopped following.

**Verification.**
- An exact property test. The old PawPrint decoder, transcribed into the test, is the oracle: for every flavour, socket state, length in [0, 300] and random blob, `bind` and `connect` on bytes must equal `bind` and `connect` on the old decode.
- Properties from the probe: changing `sa_len`, `sin_zero` or any byte at offset 16 or later changes no answer. Writing the family as a two-byte word with a nonzero high byte is never `AF_INET` on Linux.
- Optionally a host-equality fixture, in the style of `TestSockOptAgainstHost`, that puts random blobs to the host kernel and to the model.
- The Guest suite, unchanged, as the end-to-end check.

**Risk.** The client now reads all `length` bytes (up to 128), where today it reads at most offsets 0..7. `requireBufferRoom` already passes that range, refusing `Escapes` and admitting `Undecided`. An `Undecided` range whose later bytes `readBytesThrough` cannot produce would turn today's answer into a host failure. Reading every byte the real kernel copies is the more faithful behaviour. This needs one check during implementation: whether any guest reaches `bind` or `connect` with storage that is `Undecided`.

### Option B: a public decoder, and syscalls that take its result

```fsharp
/// What the copy-in contained. Built only by `Sockaddr.copyIn`.
type CopiedSockaddr = private { Platform : SimulatedUnixPlatform; Length : int; Family : int option; Endpoint : InternetEndpoint option }
module Sockaddr =
    val copyIn : SimulatedUnixPlatform -> admitted:int -> ImmutableArray<byte> -> CopiedSockaddr
UnixSocket.bind : fd -> UserBuffer -> uint32 -> CopiedSockaddr -> ...
```

**How it works.**
- The client still makes the admission call.
- It then calls `Sockaddr.copyIn` on the bytes and passes the opaque result to the syscall.
- Per constraint 2, `copyIn` cannot return an errno. It reports what was read, so the "proof" proves only that the library did the decoding.

**PawPrint.** The same as A, plus one call.

**Blast radius.** A's, plus a new public type and function. The syscalls must check that the proof's platform and length match the system and the declared length they are given. These are two more runtime assertions, because the proof does not tie itself to them.

**Error order.** The same as A.

**Information.** The same as A. The client also holds a decoded address, which helps only a client that wants one for its own purposes. PawPrint does not: its refusal messages already get the endpoint from the kernel's refusal cases.

**Reversibility.** Worse than A. It commits the published package to a type and a function that no client needs, and removing them later is a breaking change.

**Why it is not recommended.** B adds a public step between two calls that A already sequences, and the step can validate nothing. If a client ever needs a decoder, A can expose `decodeInternet` as a plain pure helper without making the syscalls depend on it.

### Option C: one call, taking a description of the caller's buffer

```fsharp
/// The caller's address argument, read eagerly: as many bytes from its start as
/// the caller could produce, up to min(declared, Sockaddr.longestCopy), and why it stopped.
type SockaddrArgument = { Prefix : ImmutableArray<byte>; Stop : SockaddrArgumentStop }
and SockaddrArgumentStop =
    | DeclaredLength                    // Prefix is the whole min(declared, longestCopy)
    | Unmapped of address : uint64      // the next byte faults: EFAULT if the kernel copies it
    | Opaque | Addressless              // refused if the kernel copies past Prefix
    | StorageEnds                       // the caller's object ends here; a real kernel reads on
UnixSocket.bind : fd -> declaredLength:uint32 -> SockaddrArgument -> ...
```

**How it works.**
- No admission call.
- The kernel decides how much it copies. If that fits in `Prefix`, it decodes. Otherwise it answers from `Stop`.
- `Sockaddr.longestCopy = 255` is the one flavour-free bound the client needs, so that it never reads two gigabytes.
- This is the `PathArgumentBytes` shape, generalised to a copy bounded by a length rather than by a NUL.

**PawPrint.** It reads eagerly up to `min(declared, 255)` bytes before any screen runs, and stops at the end of the storage instead of refusing there. When the storage's extent is `Undecided`, it must either read and risk a host failure, or stop and call that `StorageEnds`. The first changes behaviour on inputs a real kernel answers without reading: EBADF, ENOTSOCK, Linux above 128, Darwin below 2. The second turns today's successful reads into refusals.

**Blast radius.** The largest:
- `admitSockaddrCopy`, `SockaddrCopyAdmission`, `SockaddrCopySyscall` and `SockaddrCopyRefusal.Buffer`'s current role all leave the public API.
- Every test that drives the admission is rewritten, not edited mechanically.
- Both PawPrint handlers are restructured.
- A fourth description of a buffer joins `UserBuffer`, `PathArgumentBytes` and the write admission.

**Error order.** It lives entirely in the kernel, which is the cleanest place for it. But the client's eager read happens before EBADF, so a client that *refuses* while reading pre-empts the kernel's answer.

**Information.** The most of the three. The kernel sees how far the caller's memory goes, as well as the bytes.

**Reversibility.** Poor, for the reason given under A.

**Why it is not recommended now.** It reopens the hazard stage 9l closed, reading before the kernel has said it reads, in exchange for one fewer call. That would be worth it if the two-call protocol were error-prone. A's length assertion makes misuse loud, and `admitWrite`/`write` and `admitSetSockOpt`/`setsockopt` have used this protocol without trouble.

### Variant not pursued: a typed admission token

The admission could return an opaque `SockaddrCopy` (fd, syscall, length) that `bind` takes along with the bytes. But `bind` is handed a system that may differ from the one the admission saw, so it must run the admission again anyway. The token would add a type without removing that check.

## 5. Recommendation

**Option A.** It is the smallest change that gives the decision its point: no client reads a field of a sockaddr for the kernel. It keeps the one property that made the current design safe, which is that the client reads only what the kernel copies. It follows the library's existing pattern for copy-ins bounded by a length. And it has an exact oracle, so "bit-identical" is something a test checks rather than something the PR claims.

`setsockopt` has the same shape today: `admitSetSockOpt` returns `Transfer of length`, and then the client decodes the `int` (`supplied : int option`). By the same decision it should take the bytes too. That is a separate PR, noted in §8.

## 6. Error order after the change

Nothing moves. For the record, these are the steps the inbound path takes, each measured:

1. The descriptor is looked up: EBADF.
2. Linux `connect` only: the length (EINVAL outside [0, 128]) and the copy (EFAULT).
3. ENOTSOCK.
4. The socket's domain. IPv6 and Unix-domain sockets are refused.
5. The copy helper's own bounds. Linux: EINVAL outside [0, 128]. Darwin: EINVAL below 2 without copying, ENAMETOOLONG above 255.
6. The copy itself: EFAULT for an unmapped buffer. The client refuses an opaque or addressless buffer, or one whose storage ends early.
7. The protocol's ladder:
   - `bind`: `bindFaultOrder`.
   - stream `connect`: the state arms, then length and family in the flavour's order.
   - datagram `connect`: length, then family.

The three Darwin rows in §2 change step 7 only, and only for those rows.

## 7. Copy-out: this change or a follow-up?

**A follow-up PR.** The reasons:

- **No client decoding happens in this direction.** The bytes already come from the library's `encodeInternetSockaddr`. The client's only kernel knowledge here is the truncation, `min declaredLength reportedLength`. That is a kernel rule, measured identical across all three calls and both flavours (T section), but it is one line.
- **The type change is in a busy area.** `AcceptOutcome.Accepted` is built in `handOver` and matched in `TestAccept`, `TestBlockingAccept`, `TestSocketAddressLength`, `KeventWorld` and two PawPrint handlers. Mixing that into the inbound PR would double its diff for an unrelated reason.
- **It has its own oracle.** The truncated copy must be the first `min(declared, 16)` bytes of `encodeInternetSockaddr`, with the cell set to 16. That is a property over the encoder and needs no reference decoder.

**Shape.**
- `GetSockNameAnswer.Reported of copiedOut : ImmutableArray<byte> * reportedLength : int` and `AcceptOutcome.Accepted of fd * copiedOut * reportedLength`, where `copiedOut` is exactly what the kernel writes.
- Callers that want the endpoint read it from the socket state (`TcpConnection.ClientAddress`, the binding), where it already lives.
- `encodeInternetSockaddr` can then become private, unless a client wants it as a helper.

**The failure paths do not change.** Linux's `lengthOverwritten` stays as it is. `AcceptRefusal.UnmeasuredCopyOutFault` stays as it is.

## 8. PRs, one feature each

1. **Inbound decoding, option A** (this workstream's PR):
   - `bind`, `connect` and `connectSocket` take `copied : ImmutableArray<byte>`.
   - `SockaddrCopyAdmission.Transfer` loses `fields`.
   - `SockaddrCopyFields` and `checkSupplied` go.
   - The machine order of `sa_family` becomes a match over the architecture.
   - PawPrint passes bytes, and `EmulatedKernel.connectSocket` is deleted.
   - The probe's new rows that agree with the model go into the tests and the flavour-divergence table.
   - No behaviour change. The tests are the reference-decoder property and the `sa_len`, `sin_zero` and trailing-bytes properties.
2. **Darwin's connect ladder from the sweep:** the family check before the length on a stream connect, and `AF_UNSPEC` as `AF_INET` on a stream connect. This lifts `UnspecDeclaredLength` for Darwin stream sockets: EINVAL off 16 when idle. The non-idle phases keep their measured arms.
3. **`AF_UNSPEC` lengths on datagram `connect`:** Linux succeeds at 2..15, and Darwin is EINVAL off 16. This lifts the remaining `UnspecDeclaredLength` cases. It could be folded into PR 2 if you prefer a single "connect family/length" PR.
4. **Darwin's datagram `bind` takes `AF_INET6`'s number.** It is bound as `AF_INET`, and every measured row (D section) becomes a test.
5. **Copy-out bytes** (§7).
6. Later, with their own features:
   - `setsockopt`'s value as bytes, on the same principle.
   - `sockaddr_in6` and `sockaddr_un` decoding, with IPv6 and Unix-domain sockets.
   - `getpeername`, `sendto` and `recvfrom` as they arrive. Each takes or returns bytes from the start.

PRs 2–4 do not depend on PR 1. Today's client passes the endpoint whenever the length reaches it, whatever the family. They could land in either order. I would land PR 1 first, so that its "no behaviour change" property is checked against a stable model, and then make each fix as a visible change of expected rows.

## 9. For Patrick

- **The three Darwin model errors (§2)** are measured, reproducible, and independent of the API decision. Do you want them fixed in this series (PRs 2–4) or tracked separately?
- **`EmulatedKernel.connectSocket` is dead.** PR 1 deletes it either way.
- **The plan's "Two calls rather than one" paragraph** (stage 9l) rejected single-call bytes for the reason in constraint 1. Option A is the combination that paragraph did not list: two calls, with bytes on the second. Once PR 1 lands, the plan and audit item #14 should say so.

## Decision (orchestrator, 2026-10-03)
**Option A.** The kernel admits a length, and the client hands back exactly that many bytes, which the kernel decodes. Reading the whole admitted length is not a risk but the measured kernel behaviour: Linux's `move_addr_to_kernel` and Darwin's `getsockaddr` both copy all `addrlen` bytes (up to `sockaddr_storage`), so a fault anywhere in them is EFAULT. Where PawPrint cannot decide a storage extent, it refuses rather than guess. B adds published API that checks nothing; C reintroduces the read-before-admission hazard stage 9l rejected.

The three Darwin model errors and the two refusals the data lifts are fixed in this series, after PR 1, as PRs 2–4 (2 and 3 folded together), each against the committed probe. Copy-out is PR 5. `EmulatedKernel.connectSocket` (dead) is deleted in PR 1, since its callee's signature changes there.
