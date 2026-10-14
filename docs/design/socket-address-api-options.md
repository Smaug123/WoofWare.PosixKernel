# Socket addresses in WoofWare.PosixKernel's public API: IPv6 and Unix-domain

*Options document, 2026-10-10. Part of the 1.0 release work (issue #1726, "IPv6 and Unix-domain sockets"). Code references are at `origin/main` `f01491b6`, in worktree `.claude/worktrees/pk-socket-address-api` (branch `pk-socket-address-api`, no commits). The public surface was enumerated by reflection over the built `WoofWare.PosixKernel.dll` (scratch scripts in the session's scratchpad, not committed). No library or PawPrint code has changed.*

**The decisions already taken (Patrick, 2026-10-10):**
- The *public API* for IPv6 and Unix-domain sockets is release work. The *behaviour* is not. Before 1.0, the public types must be able to express an IPv6 endpoint and a Unix-domain name, so that implementing either later is additive. The operations themselves may stay refused, with typed refusals.
- Answer and refusal unions may gain cases in a minor version. Clients fall back to `describe`. Changing the *shape* of an existing type is breaking.

**What this document decides:** which public types change before 1.0, into what, and in which PRs.

**Recommendation in one line:** option B. The socket's family case carries that family's own binding type, so an `AF_INET` socket cannot hold a path. One closed `SocketAddress` union appears only where a single signature must answer for every family. The IP leaf types mirror `sockaddr_in`/`sockaddr_in6` field for field, and the Unix-domain name is opaque, because what Darwin stores for it is unmeasured (§5).

## 1. Inventory

### Method

- Reflection over every exported type of the built library: each public method, property and union-case constructor whose signature mentions `InternetEndpoint`, `Ipv4Prefix`, `Ipv4PrefixRefusal`, `UInt32`, `SocketDomain`, `SocketAddressing` or `SocketBinding`. Then the `uint32` hits were read by hand, to keep the ones that are addresses.
- A second pass for the public functions that hand socket state to a client. There is one, `UnixSystem.socket : SocketId -> UnixSystem -> SocketDescription option` (`UnixSystem.fs:953`). So `SocketDescription`, `SocketAddressing`, `SocketBinding` and `SocketPhase` are client-readable state, not internals. `SocketPhase` is also a payload of six public refusal cases. `InodeContent` is client-readable through `VirtualFileSystem.tryGetContent`.
- Many address types are already internal and are therefore free to change: `TcpConnection` (`ClientAddress`/`ServerAddress`), `EphemeralPortUse.ConnectTo`, `Ipv6Destination` (with `V4Mapped`), `CopiedInternetSockaddr`, `CopiedInternetV6Sockaddr`, `ConnectAddress`, the decoders `decodeInternetSockaddr`/`decodeInternetV6Sockaddr`, and the machine's `LocalAddresses`/`LocalRoutes` fields. The brief listed several of these. They need no pre-1.0 decision.

### (a) Shape changes: breaking, so they must happen before 1.0

| # | public item | file:line | why it cannot carry IPv6 or a Unix-domain name |
| --- | --- | --- | --- |
| 1 | `InternetEndpoint` record | `InternetEndpoint.fs:14` | `Address : uint32`, a public field. |
| 2 | `InternetEndpoint` module: `WildcardAddress`, `LoopbackAddress`, `ofParts`, `isWildcard`, `addressesOverlap`, `toString` | `InternetEndpoint.fs:73, 79, 81, 87, 97, 110` | IPv4 arithmetic on `uint32`. They survive as the IPv4 type's module, but under a new type. |
| 3 | `SocketBinding`: `Endpoint`, `LockedAddress : uint32 option`, `LockedPort` | `FileDescriptorRegistry.fs:132, 137, 144, 152` | IPv4 endpoint and IPv4 address. A Unix-domain socket has neither a locked address nor a port. |
| 4 | `SocketPhase.DatagramPeer of peer : InternetEndpoint` | `FileDescriptorRegistry.fs:317` | An IPv6 or Unix-domain datagram peer has nowhere to go. |
| 5 | `SocketAddressing.Inet6DualMode of binding : SocketBinding option` | `FileDescriptorRegistry.fs:361` | Holds only an IPv4 (v4-mapped) binding. A dual-mode socket bound to `::` or `::1` needs a native IPv6 one. |
| 6 | `SocketAddressing.Inet6V6Only` (nullary) | `FileDescriptorRegistry.fs:364` | "Never bound". Carries no binding at all. |
| 7 | `SocketAddressing.Unix` (nullary) | `FileDescriptorRegistry.fs:366` | "Never bound". Carries no name at all. |
| 8 | `SocketAddressing.binding`, `.initial`, `.replaceBinding`; `SocketDescription.Binding` | `FileDescriptorRegistry.fs:379, 389, 401, 450` | Typed in `SocketBinding`. `replaceBinding` throws for cases 6 and 7. |
| 9 | `BindAnswer.Bound of endpoint : InternetEndpoint` | `UnixSocket.fs:99` | An IPv6 or Unix-domain bind has no answer to give. |
| 10 | `ListenAnswer.Listening of endpoint : InternetEndpoint` | `UnixSocket.fs:152` | The same. |
| 11 | `BindRefusal.UnmodelledIpv6Address of socket * address : ImmutableArray<byte>` | `UnixSocket.fs:130` | The type exists, but as a raw byte array: the 16-byte length is a runtime fact, not a type fact. |
| 12 | `BindRefusal.UnmodelledMulticast of socket * address : uint32` | `UnixSocket.fs:116` | A primitive address. IPv4-only is fine here (IPv6 multicast can be a new case), but the payload changes if an IPv4 address type is introduced. |
| 13–20 | `ConnectRefusal.SourceForNonLoopbackDestination`, `DestinationNotLocal`, `AcceptQueueFull`, `SelfTuple`, `DuplicateFourTuple`, `SimultaneousOpen`, `DarwinSynDropped`, `DatagramGroupDestination`, each carrying `InternetEndpoint` | `UnixConnection.fs:156, 162, 165, 168, 173, 181, 184, 191` | Every one of them can arise for IPv6. `AcceptQueueFull` can arise for a Unix-domain listener too, which has a backlog. |
| 21 | `ConnectRefusal.Ipv6Destination of socket * address : ImmutableArray<byte> * port : uint16` | `UnixConnection.fs:195` | Raw bytes, no flow label or scope id. |
| 22 | `SimulatedUnixPlatform.encodeInternetSockaddr : platform -> InternetEndpoint -> byte[]` | `SimulatedUnixPlatform.fs:1670` | IPv4 by nature, which is fine. But if `InternetEndpoint` ever holds IPv6 (option C), this becomes partial. |
| 23 | `SimulatedUnixPlatform.presentedIpv6Address : platform -> bool -> uint32 -> byte[]` | `SimulatedUnixPlatform.fs:1787` | Primitive in, primitive out. |
| 24 | `SimulatedUnixPlatform.encodeInternetV6Sockaddr : platform -> byte[] -> uint16 -> byte[]` | `SimulatedUnixPlatform.fs:1806` | No `sin6_flowinfo` or `sin6_scope_id` parameter, so it cannot encode a scoped address. It checks the address length at run time. |
| 25 | `UnixBootImage.withLocalAddresses : uint32 list -> Ipv4Prefix list -> ...` | `UnixBootImage.fs:649` | IPv4 by design. Only the `uint32` is a shape question, and the name: "local addresses" becomes ambiguous once IPv6 ones exist. |
| 26 | `UnixSystem.defaultLocalAddresses : uint32 list` (and `defaultLocalRoutes`) | `UnixSystem.fs:2831, 2836` | The same. |
| 27 | `Ipv4Prefix.create`/`network`/`contains`, `Ipv4PrefixRefusal.HostBitsSet` | `InternetEndpoint.fs:150, 161, 178, 64` | IPv4 by design. Only the `uint32` changes, and only if an IPv4 address type is introduced. |

`UnixSystemDefect.UnaddressableSocketInPhase` (`UnixSystem.fs:474`) carries a `SocketAddressing`. It needs no edit of its own, but it follows items 5–7.

Prose also assumes IPv4. `GetSockNameAnswer.Reported` (`UnixSocket.fs:204`) and `AcceptOutcome.Accepted` (`UnixConnection.fs:29`) say "this platform's `struct sockaddr_in`", although the payload is bytes and is already `sockaddr_in6` for a dual-mode socket. That is a docstring fix.

### (b) Places where a new case or a new function suffices: additive

- **Copy-in and copy-out are already bytes.** `bind`/`connect` take `copied : ImmutableArray<byte>`. `getsockname`, `getpeername` and `accept` answer `copiedOut : ImmutableArray<byte>` with a `reportedLength : int`. The lengths a Unix-domain socket reports (2, up to 110 or 111 on Linux, 106 on Darwin) fit as they are. This is the largest reason the change is small.
- **`SocketDomain`** (`FileDescriptorRegistry.fs:92`) already has `Inet | Inet6 | Unix`.
- **Layout facts** (`Sockaddr.fs`): a `UnixSockaddr` module beside `InternetSockaddr`/`InternetV6Sockaddr`, and `SimulatedUnixPlatform.unixSocketAddressSize`, `localAddressFamily` and the `sockaddr_un` codecs. All new functions.
- **Refusals for what stays unmodelled.** Every one needed before 1.0 exists already: `SockaddrCopyRefusal.UnmodelledDomain` (a Unix-domain `bind`/`connect`, refused before decoding), `UnmodelledInet6Kind`, `DarwinShortInet6Sockaddr`, `BindRefusal.UnmodelledIpv6Address`, `ConnectRefusal.Ipv6Destination`, `ListenRefusal.Ipv6Listener`/`UnmodelledDomain`, `AcceptRefusal.UnmodelledDomain`, `GetSockNameRefusal.UnmodelledDomain`/`UnmodelledInet6Kind`, `WriteRefusal.Inet6Binding`. When behaviour lands, some of these stop being returned, and new ones (for example a refusal that carries a decoded Unix-domain name) are new cases.
- **New syscalls:** `socketpair`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`. Each is a new function, taking and answering bytes.
- **IPv6 local addresses:** a new boot setter and a new default (`::1`). Linux's IPv6 `bind` checks assigned addresses rather than local routes (read from source, not measured), so `Ipv4Prefix` has no IPv6 counterpart to commit to now.
- **`InodeContent` needs a socket-file case** (`Inode.fs:167`) for a pathname socket's `S_IFSOCK` inode. That is a case added to a *state* union that clients read. Whether that is additive is a policy question (§7).

**Count:** 27 rows of shape changes (rows 13–20 are one row per `ConnectRefusal` case; rows 2, 3, 8, 26 and 27 group several members of one type), plus one dependent case (`UnaddressableSocketInPhase`) and two docstrings. Seven additive groups.

## 2. What the real kernels expose

"Measured" means a committed probe in this repository. "Source" means Linux 6.18.7 (`/nix/store/...-linux-6.18.7.tar.xz`, extracted to the scratchpad) or the macOS SDK headers on this machine. No XNU source is available locally, and there was no network, so every Darwin fact below beyond the headers is **unmeasured**.

### IPv6 (`struct sockaddr_in6`)

| fact | value | provenance |
| --- | --- | --- |
| size; `sin6_port` at 2; `sin6_flowinfo` at 4; `sin6_addr` at 8 (16 bytes); `sin6_scope_id` at 24 | 28; the same on both | measured (`sockaddr-layout.c`) |
| `AF_INET6` | 10 on Linux, 30 on Darwin | measured |
| flow info and scope id on a v4-mapped `connect` | ignored; `getpeername` reports both as 0, on both | measured (`docs/probes/dual-mode`, rows A11 and A12) |
| Linux `getsockname`/`getpeername` | `sin6_flowinfo` is 0, except that `getpeername` reports the socket's flow label when `IPV6_FLOWINFO_SEND` is set. `sin6_scope_id` is `ipv6_iface_scope_id(addr, sk_bound_dev_if)`: non-zero for a scoped (link-local) address on a socket bound to a device | source (`net/ipv6/af_inet6.c`, `inet6_getname`) |
| Linux UDP `recvfrom` | `sin6_flowinfo` is 0; `sin6_scope_id` is the arriving interface for a scoped source, 0 for a v4-mapped one | source (`net/ipv6/udp.c:544-552`) |
| Linux `connect` with a scope id | sets the socket's bound device | source (`net/ipv6/datagram.c:223-228`) |
| Darwin presentation of a failed dual-mode connection | `::a.b.c.d` rather than `::ffff:a.b.c.d` | measured (dual-mode A, E, G, R), already modelled (`presentedIpv6Address`) |

**What an endpoint must carry to round-trip:** all four fields of `sockaddr_in6` other than the family and Darwin's `sin6_len`. The address and port are obvious. The scope id is reported by all four calls for a scoped address. The flow info is reported by Linux's `getpeername`. A loopback-only model never makes either non-zero, but a type without them could not hold what a later model reports.

### Unix-domain (`struct sockaddr_un`)

| fact | Linux | Darwin | provenance |
| --- | --- | --- | --- |
| `sun_path` size; `sizeof(struct sockaddr_un)` | 108; 110 | 104 (after a one-byte `sun_len` and a one-byte `sun_family`); 106 | sizes measured (`SocketShimPal.SocketAddressSizes`); paths from `linux/un.h` (7.0 headers) and Darwin `sys/un.h`, `unix(4)` |
| `AF_UNIX` | 1 | 1 | headers (not yet stated in the library) |
| pathname socket | `sun_path` up to the first NUL. The stored length is `strlen + 3`: bytes after the NUL are dropped. A 108-byte path with no NUL is accepted, and `getsockname` then reports **111**, more than `sizeof(struct sockaddr_un)` | stored as given, or re-terminated: **unmeasured** | Linux source (`unix_mkname_bsd`, `af_unix.c:345`) |
| abstract socket | `sun_path[0] == 0`. The name is every byte after it up to the declared length. **NULs inside are significant, and so are trailing ones.** Not in the filesystem | does not exist | Linux source (`unix_create_addr`, `af_unix.c:306`) |
| unnamed socket (never bound, or from `socketpair`) | `getsockname`/`getpeername` report 2 bytes: the family alone | **unmeasured** | Linux source (`unix_getname`, `af_unix.c:1909`) |
| autobind | `bind` with length exactly 2, and `connect`/`sendmsg` on an unbound socket with `SO_PASSCRED` or `SO_PASSPIDFD`. The name is abstract: a NUL then five lower-case hex digits, length 8. The start is `get_random_u32()`, and ENOSPC once all 2^20 are taken | none known | Linux source (`unix_autobind`, `af_unix.c:1305`) |
| `bind` validation | length ≤ 2 (other than the autobind case) or > 110 is EINVAL; a family other than `AF_UNIX` is **EINVAL**, not EAFNOSUPPORT | **unmeasured** | Linux source (`unix_validate_addr`) |
| `listen` on an unbound socket | EINVAL: no implicit bind | **unmeasured** | Linux source (`unix_listen`) |
| `getpeername` on an unconnected Unix-domain socket | ENOTCONN | ENOTCONN | measured (`docs/probes/getpeername`) |
| copy-out length byte | none | the kernel writes `sun_len` | header; measured only for `sockaddr_in`/`sockaddr_in6` |

**What a name type must carry to round-trip:**
- A **pathname**: the bytes as the caller gave them, before any resolution. A relative path stays relative, because `getsockname` reports it so. It is NUL-free, so it is a `UnixByteString`. At most 108 bytes on Linux and 104 on Darwin.
- An **abstract name** (Linux only): up to 107 bytes, NULs included. It is **not** a `UnixByteString`, which forbids NUL. It needs a byte type of its own.
- **Unnamed** is the absence of a name. In state it is `None`. A copy-out reports it as bytes. A name type does not need an "unnamed" case. Leaving it out keeps "bound to no name" unrepresentable.
- **Darwin's stored form is the open question.** If Darwin keeps the whole `sockaddr_un` that `bind` was given (bytes after the NUL included, with `sun_len` set to the declared length), then a path alone does not round-trip on Darwin. One probe settles it (§6). Until then, the safe choice is a type whose representation can change without breaking clients.
- `socketpair` makes two unnamed sockets. `accept` on a Unix-domain listener reports the connecting socket's name, which is usually unnamed. Both are bytes at the copy-out, so neither needs a typed form.

## 3. Constraints on the design

1. **Nothing a client passes in is a decoded address.** Inputs are bytes (`bind`, `connect`) or boot configuration (`withLocalAddresses`). So the types' job is to describe what the kernel *hands out*: answers, refusals and state. Illegal values are produced only by a library bug, which `checkInvariants` and property tests catch. Inside the library, though, a type that admits a wrong family forces partial matches at every read.
2. **The library already reads bindings in about 40 places** (`binding.Endpoint`, `.Endpoint.`: 41 lines in the library, 52 in its tests). `InternetEndpoint` appears on 81 library lines in 10 files and 225 test lines in 44 files. `SocketPhase` appears on 236 library lines and 314 test lines.
3. **PawPrint barely sees any of this.** Its library matches `BindAnswer.Bound _`, `ListenAnswer.Listening _`, `BindRefusal.UnmodelledMulticast _` and `UnmodelledIpv6Address _` with wildcards (`NativeSystemNative.fs:5009, 5010, 5094, 5136`), and its `KernelConfig` carries `LocalAddresses : uint32 list` and `LocalRoutes : Ipv4Prefix list` (`EmulatedKernel.fs:2089-2093`, `2165-2166`, `2291-2293`, `2644`, `2765`). It never calls `UnixSystem.socket`. Its `SocketDomain` matches are unaffected by every option.
4. **A public record freezes its fields.** Adding a field to a public record breaks every client that constructs one. Hiding the representation (`private`) is the only way to leave room.

## 4. The options

The leaf types are shared by A and B, and C uses some of them:

```fsharp
/// Host order. Every 32-bit value is an address, so the case is public.
[<Struct>]
type Ipv4Address = Ipv4Address of uint32

/// 128 bits. Two words rather than an ImmutableArray: equality, ordering and the
/// length are then the type's, not a runtime check.
[<Struct>]
type Ipv6Address = private Ipv6Address of high : uint64 * low : uint64
// Ipv6Address.ofBytes : ReadOnlySpan<byte> -> Ipv6Address option, toBytes, tryV4Mapped, v4Mapped, loopback, any

/// Every field of `struct sockaddr_in` but the family and `sin_zero`.
type Ipv4Endpoint = { Address : Ipv4Address ; Port : uint16 }

/// Every field of `struct sockaddr_in6` but the family and `sin6_len`.
type Ipv6Endpoint = { Address : Ipv6Address ; Port : uint16 ; FlowInfo : uint32 ; ScopeId : uint32 }

/// A Unix-domain socket's name. Opaque: what Darwin stores is unmeasured.
type UnixSocketName = private | Path of UnixByteString | Abstract of ImmutableArray<byte>
// UnixSocketName.view : UnixSocketName -> UnixSocketNameView   (a public Path | Abstract union)
// UnixSocketName.toString, for describe
```

`Ipv4Endpoint` and `Ipv6Endpoint` mirror the ABI structs, which will not change, so they can be public records. `UnixSocketName` cannot yet be pinned that way, so it is opaque. Its constructors are internal (no client builds one: nothing public takes one), and `view` gives clients a closed, public reading.

### Option A: one address union everywhere

```fsharp
[<RequireQualifiedAccess>]
type SocketAddress =
    | Inet of Ipv4Endpoint
    | Inet6 of Ipv6Endpoint
    | Unix of UnixSocketName

type SocketBinding =
    {
        Address : SocketAddress
        /// None on a Unix-domain socket, which has no SOCK_BINDADDR_LOCK.
        LockedAddress : SocketAddress option
        LockedPort : bool
    }

[<RequireQualifiedAccess>]
type SocketAddressing =
    | Inet of binding : SocketBinding option
    | Inet6 of v6Only : bool * binding : SocketBinding option
    | Unix of binding : SocketBinding option

SocketPhase.DatagramPeer of peer : SocketAddress
BindAnswer.Bound of address : SocketAddress
ListenAnswer.Listening of address : SocketAddress
ConnectRefusal.DestinationNotLocal of destination : SocketAddress * kind : SocketKind   // and the other seven
```

- **v4-mapped dual mode.** The binding of a dual-mode socket is either `SocketAddress.Inet` (the transport) or `SocketAddress.Inet6` holding `::ffff:a.b.c.d` (the presentation). A admits both, so an invariant must pick one. I would store the transport form, as today, and present at copy-out, because Darwin's presentation depends on the connection's state anyway.
- **Refusals.** None added. Items 11 and 21 take `Ipv6Address`/`Ipv6Endpoint`. Item 12 takes `Ipv4Address`.
- **Illegal states.** Not excluded: an `AF_INET` socket bound to a path, a Unix-domain binding with a locked port, a `V6Only` socket holding an IPv4 binding. Each is a `checkInvariants` rule, and every IPv4 read in the library becomes `match binding.Address with SocketAddress.Inet e -> ... | _ -> failwith`. That is about 40 new partial matches, each a new throw site, in a library whose throw sites were just audited.
- **Blast radius.** Library: every line in constraint 2, plus the codecs. Tests: about 300 lines, mostly mechanical. PawPrint: only `KernelConfig` (about 10 lines).
- **`Ipv4Prefix` and local addresses.** Retyped to `Ipv4Address`. IPv6 configuration is a later setter.
- **Reversibility.** Good towards B: B's types are A's with the family moved up a level.
- **Information.** The same as B, but the family agreement lives in invariants rather than in the types.

### Option B: the socket's family carries its own binding type

The leaf types above, plus:

```fsharp
/// An IP socket's local address, as bind or an implicit bind gave it. Generic in
/// the family's endpoint and address, so one definition serves both and an
/// IPv4 binding cannot hold an IPv6 address.
type InetBinding<'Endpoint, 'Address> =
    { Endpoint : 'Endpoint ; LockedAddress : 'Address option ; LockedPort : bool }

type Ipv4Binding = InetBinding<Ipv4Endpoint, Ipv4Address>
type Ipv6Binding = InetBinding<Ipv6Endpoint, Ipv6Address>

/// A dual-mode socket's binding: an IPv4 one reached through v4-mapped
/// addresses, or a native IPv6 one.
[<RequireQualifiedAccess>]
type DualModeBinding =
    | Mapped of Ipv4Binding
    | Native of Ipv6Binding

[<RequireQualifiedAccess>]
type SocketAddressing =
    | Inet of binding : Ipv4Binding option
    | Inet6DualMode of binding : DualModeBinding option
    | Inet6V6Only of binding : Ipv6Binding option
    | Unix of name : UnixSocketName option

/// Where one signature must answer for every family.
[<RequireQualifiedAccess>]
type SocketAddress =
    | Inet of Ipv4Endpoint
    | Inet6 of Ipv6Endpoint
    | Unix of UnixSocketName

SocketPhase.DatagramPeer of peer : SocketAddress
BindAnswer.Bound of address : SocketAddress
ListenAnswer.Listening of address : SocketAddress
ConnectRefusal.<the eight> of ... SocketAddress ...
```

- **v4-mapped dual mode.** `DualModeBinding.Mapped` holds the IPv4 transport, exactly as today's `Inet6DualMode of SocketBinding option` does. `Inet6V6Only` cannot hold `Mapped`: the type says what the docstring says today. `IPV6_V6ONLY` changes only while unbound (measured: EINVAL once bound), so moving between the two cases never carries a binding. An answer reports an address in the socket's own family, as `getsockname` would at that moment: a dual-mode `bind` answers `SocketAddress.Inet6` with `::ffff:a.b.c.d`. Today it answers the IPv4 endpoint (`UnixSocket.fs:1089`), so this is a visible change to that answer, made deliberately in PR 3.
- **The phase stays family-agnostic.** Making `SocketPhase` generic in its peer type and moving it into each family's case would exclude a wrong-family peer by type too. But it touches 236 library lines and 314 test lines, and six refusal cases carry a `SocketPhase`. So `DatagramPeer` takes the `SocketAddress` union, and one `checkInvariants` rule checks that the peer's family is the socket's. That is the one place in B where family agreement is checked at run time.
- **A Unix-domain socket's state is just its name.** The inode a pathname socket creates belongs in an internal inode-to-socket table, as Linux keeps one (`unix_find_socket_byinode`). It is not on the public record, which keeps the public shape small.
- **Refusals.** As for A: none added; items 11, 12 and 21 retyped. The eight `ConnectRefusal` cases take `SocketAddress`. A narrower "IP endpoint" union would exclude a Unix-domain name from `SynDropped`, but it adds a fourth public union, and `AcceptQueueFull` needs the Unix-domain case anyway.
- **Illegal states.** Excluded by type: a wrong-family binding; a locked port on a Unix-domain socket; a v4-mapped binding on a `V6Only` socket; "bound to no name". Left to invariants: the datagram peer's family; an abstract name under Darwin; a binding's `FlowInfo` other than 0.
- **Blast radius.** Library: the IPv4 paths read `Ipv4Binding` straight from the case, so they gain no partial matches. Most edits are the rename `SocketBinding` to `Ipv4Binding` and `.Address` reads becoming `Ipv4Address` values. Tests: about 300 lines, mostly mechanical: 98 `InternetEndpoint.ofParts` calls and about 100 record constructions. PawPrint: only `KernelConfig`, about 10 lines.
- **`Ipv4Prefix` and local addresses.** As for A.
- **Reversibility.** Moving back to A is mechanical, since A's types are B's flattened. Generalising the phase later stays possible, at the price above.
- **Information.** The most of the three.

### Option C: keep `InternetEndpoint`, make it opaque, decide IPv6 later

```fsharp
type InternetEndpoint = private | V4 of address : uint32 * port : uint16   // later: | V6 of ...
// InternetEndpoint.ofIpv4 (today's ofParts), port, tryIpv4Address : InternetEndpoint -> uint32 option, toString

type UnixSocketName = private ...   // as above

[<RequireQualifiedAccess>]
type SocketAddressing =
    | Inet of binding : SocketBinding option
    | Inet6DualMode of binding : SocketBinding option
    | Inet6V6Only of binding : SocketBinding option      // shape change now
    | Unix of name : UnixSocketName option               // shape change now
```

- **How IPv6 arrives.** A private `V6` case, with `ofIpv6` and `tryIpv6Address` beside it. Clients never matched the representation, so nothing breaks.
- **How Unix-domain arrives.** `BindAnswer` gains `BoundName of UnixSocketName` and `ListenAnswer` `ListeningName`, which the policy allows. `SocketPhase` gains `UnixDatagramPeer`, which is a *state* union gaining a case: allowed only if the policy extends to state (§7).
- **v4-mapped dual mode.** Unchanged: the binding holds the IPv4 transport.
- **Refusals.** As for A and B, but items 11 and 21 keep raw bytes unless a 128-bit type is introduced anyway.
- **What it costs.** Every IPv4-only function typed in `InternetEndpoint` becomes partial once `V6` exists: `encodeInternetSockaddr`, `addressesOverlap` and `isWildcard` all would. So they must be retyped now to take IPv4 parts, or they throw later. `tryIpv4Address` answers an option that is always `Some` today, so a client cannot tell from the type which families an endpoint may hold. Inside the library, the eventual IPv6 PR still rewrites every internal reader. C does not avoid that work. It moves it to after 1.0, with no type help at the boundary.
- **Illegal states.** Fewest excluded: any family in any socket.
- **Blast radius now.** The smallest. `.Address`/`.Port` field reads become accessor calls (41 library lines), record constructions become `ofIpv4` (about 100 test lines), and `SocketAddressing` gains two payloads.
- **Reversibility.** The best, since hiding can be undone without breaking. But it defers the IPv6 representation decision past the point where a mistake is cheap to fix.

### Considered and rejected: addresses only as `sockaddr` bytes

Answers, refusals and state could carry the platform's encoded `sockaddr` (`ImmutableArray<byte>`), as copy-in and copy-out already do. Any family fits, so no type would ever change. But it is stringly typed state: every client that wants a port parses bytes, and `describe` decodes its own payloads. The syscalls take bytes because the kernel's copy rules depend on the bytes (`sockaddr-decoding-options.md`, constraint 1). No such reason applies to state or to refusals.

### A lever that composes with any option: shrink the public state

PawPrint never calls `UnixSystem.socket`. If `SocketDescription` became opaque, with accessor functions, and `SocketAddressing`/`SocketBinding` became internal, rows 3, 5–8 would leave the API altogether. `SocketPhase` would stay public through its six refusal payloads, so row 4 would remain. I do not recommend it now. Reading socket state is what a test harness or a second client wants, the orphan and reachability checks in `TestPublicSurface` would need the refusal payloads reworked, and B's types are the ones such accessors would return anyway. It is listed so that the choice is explicit.

## 5. Recommendation

**Option B**, with the leaf types above.

- **It puts family agreement in the types where the library reads it most.** About 40 library sites read a binding. Under B they get an `Ipv4Binding` from the case they already match on. Under A each needs a partial match and a throw. B checks family agreement at run time in one place, the datagram peer, and says so.
- **Every shape that must change, changes now, once.** `SocketAddressing`'s nullary cases gain payloads, the IPv6 payloads become a 128-bit type, and the answers take `SocketAddress`. After 1.0, IPv6 and Unix-domain behaviour add cases, functions and invariants, but change no shape.
- **The IP types mirror the ABI, and only the unmeasured one is opaque.** `sockaddr_in` and `sockaddr_in6` are fixed, so public records over them cost nothing in future flexibility and give clients pattern matching. What Darwin stores for a Unix-domain name is unknown, so `UnixSocketName` hides its representation and exposes a closed `view`.
- **The PawPrint cost is about ten lines**, all in `KernelConfig`, all in one PR.
- **C is the cheapest now and the most expensive later.** It keeps a single type for two families' addresses, which every reader must then take apart through options. It also leaves the 128-bit representation undecided.

Two smaller choices inside B:
- **Rename the IPv4 setter** to `withLocalIpv4Addresses` (and `defaultLocalIpv4Addresses`, `KernelConfig.LocalIpv4Addresses`), taking `Ipv4Address list`. Once IPv6 addresses are configurable, "local addresses" no longer names one family. It costs one PawPrint call site and is free now.
- **`encodeInternetV6Sockaddr` takes an `Ipv6Endpoint`** and writes its flow info and scope id. Today's callers pass zero for both, so their output is unchanged.

## 6. PRs, one feature each

All four are pure API changes: no answer changes except the one named in PR 3. The oracle for each is the existing suite, unchanged in meaning, plus the Guest fixtures, since PawPrint's `KernelConfig` changes in PR 1.

1. **IPv4 address types** (*medium*: library about 150 lines over 10 files, tests about 350 lines over 45 files, PawPrint about 15 lines).
   - `Ipv4Address`; `Ipv4Endpoint` replaces `InternetEndpoint`, and its module moves with it.
   - `LockedAddress`, `UnmodelledMulticast`, `Ipv4Prefix`, `Ipv4PrefixRefusal.HostBitsSet`, `presentedIpv6Address`'s argument, and the local-address setter, default and `KernelConfig` fields take `Ipv4Address`. The setter is renamed.
   - Purely mechanical. `TestPublicSurface` and the API listing confirm that nothing else moved.
2. **IPv6 address types** (*small*: library about 80 lines, tests about 60).
   - `Ipv6Address` and `Ipv6Endpoint`.
   - `BindRefusal.UnmodelledIpv6Address`, `ConnectRefusal.Ipv6Destination`, the internal `Ipv6Destination.Native`, `presentedIpv6Address`'s result and `encodeInternetV6Sockaddr` take them.
   - Property tests: `ofBytes`/`toBytes` round-trip; `tryV4Mapped` against the byte-level check the decoder uses today; `encodeInternetV6Sockaddr` against `IPEndPoint.Serialize()` on the host, with random flow info and scope ids (`TestSockaddrLayoutAgainstHost` already does this for zeros).
3. **`UnixSocketName` and the `SocketAddress` union at the boundary** (*medium*: library about 120 lines, tests about 200 lines over 35 files).
   - `BindAnswer.Bound`, `ListenAnswer.Listening`, `SocketPhase.DatagramPeer` and the eight `ConnectRefusal` cases take `SocketAddress`. `describe` uses `SocketAddress.toString`.
   - The docstrings that say `struct sockaddr_in` for a copy-out become family-neutral.
   - **The one visible change:** a dual-mode `bind` and `listen` answer the v4-mapped `SocketAddress.Inet6`, as `getsockname` would report it, instead of the IPv4 transport endpoint. If you would rather keep today's answer, PR 3 keeps it and the docstring says it is the transport form.
   - `UnixSocketName` has no producer yet. A property test covers its internal constructors and `view` on random paths and abstract names.
4. **Family-indexed `SocketAddressing`** (*medium*: library about 150 lines, tests about 150).
   - `InetBinding<_, _>`, `Ipv4Binding`, `Ipv6Binding`, `DualModeBinding`. `Inet6V6Only` and `Unix` gain their option payloads, always `None` until behaviour lands.
   - `replaceBinding` becomes internal: no client can change state, and its throwing arms become unrepresentable.
   - A `checkInvariants` rule for the datagram peer's family, and a mutation test showing the rule fires.
5. *(Only if state unions may not gain cases after 1.0.)* **`InodeContent.Socket`**, unreachable until pathname sockets exist (*small*).

PRs 1 and 2 are independent. PR 3 needs both. PR 4 needs PR 1 and is easiest after PR 3.

**Before Unix-domain behaviour, not before 1.0:** one probe, run on both flavours, measuring:
- `getsockname` after a `bind` whose `sun_path` has bytes after the NUL, and with `sun_len` disagreeing with the length;
- an unnamed socket's `getsockname`/`getpeername`;
- both ends of a `socketpair`;
- `accept`'s peer for an unnamed client;
- `bind`'s length and family errors;
- `listen` on an unbound socket.

Those rows decide `UnixSocketName`'s internal representation, which the opaque type lets change freely.

## 7. For Patrick

- **May *state* unions gain cases in a minor version too?** The policy names answer and refusal unions. `SocketPhase`, `SocketAddressing` and `InodeContent` are state that clients read through `UnixSystem.socket` and `VirtualFileSystem.tryGetContent`. Option B needs this only for `InodeContent.Socket` (else PR 5). Option C needs it for `SocketPhase` as well.
- **A dual-mode bind's answer** (PR 3): report the v4-mapped IPv6 address, as `getsockname` would, or keep today's IPv4 transport endpoint?

## Decision (orchestrator, 2026-10-10)

- **Option B**, with the leaf types and the two smaller choices in §5.
- **§7 question 1 is settled by Patrick's compatibility policy (#1845):** every union may gain cases in a minor version except a closed list (`SyscallAnswer`, `UnixError`, `Signal`, the flavour and numbering unions, `ProcessTermination`). State unions are not on it, so PR 5 is not needed; `InodeContent.Socket` arrives with pathname sockets.
- **§7 question 2: a dual-mode `bind` or `listen` answers the v4-mapped `SocketAddress.Inet6`**, as `getsockname` would. Then an answer's address is always in the socket's own family, which a test can state as a property, and a client never sees an IPv4 address from an `AF_INET6` socket. The IPv4 transport stays in the state (`DualModeBinding.Mapped`), where it is typed as such.
- PRs 1 and 2 start in parallel; PR 3 after both; PR 4 after PR 3.
- **Amended (Patrick, 2026-10-10): reserve a case up front when it is quite certain to appear**, unreachable until its behaviour lands, so its arrival is not a source incompatibility. So PR 5 (`InodeContent.Socket`) is reinstated, with `DirectoryEntryKind.Socket` beside it if that union lacks one; its fields must be ones we are sure of.
