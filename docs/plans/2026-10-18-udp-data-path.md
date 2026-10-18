# Moving datagrams over UDP

## Goal

A UDP socket can be created, bound and connected, but it carries no data.
`sendto`, `recvfrom`, `sendmsg` and `recvmsg` are reserved `Syscall` cases
with nothing behind them. `read`, `write`, `send` and `recv` refuse a connected
UDP socket (`UnmodelledSocketPhase`), and a blocking `read` of an unconnected
one is refused as `DatagramSleep`. This plan covers moving datagrams between
IPv4 UDP sockets on one simulated machine, over loopback:

- where a datagram waits, and how many wait;
- which socket a datagram is delivered to;
- what each sending and receiving call answers on each flavour;
- readiness and wakes;
- the error a connected socket gets when its datagram reaches no one;
- the blocking receive, which `ParkedSyscall.DatagramReceive` reserves.

This document is the design and measurement phase only. Nothing here changes
the kernel.

**Out of scope.**

- IPv6 UDP: the kernel makes no IPv6 binding yet (README, "Only IPv4 bindings
  are made yet").
- Unix-domain datagrams, and so `ParkedSyscall.DatagramSend`: a UDP send never
  sleeps (`docs/probes/datagram-park`, row S1).
- Broadcast, multicast, and every destination off the machine: `connect` already
  refuses them, and `sendto` will refuse them the same way.
- `shutdown` of a datagram socket, which is already refused
  (`ShutdownRefusal.ConnectedDatagram`).
- Socket options for buffer sizes (`SO_RCVBUF`, `SO_SNDBUF`), `SO_REUSEPORT`,
  `SO_BROADCAST`, `SO_RCVTIMEO` and `IP_RECVERR`, none of which is settable
  today.

## 1. What exists

- **The socket.** `SocketDescription` (`FileDescriptorRegistry.fs`) holds the
  binding in `Addressing` and the default peer in
  `SocketPhase.DatagramPeer of SocketAddress`. That phase's docstring says it
  "filters nothing yet — no receive path exists". A datagram socket is only
  ever `Idle` or `DatagramPeer` (`checkInvariants`). Nothing holds a datagram,
  or a pending error, for a datagram socket.
- **Binding and connecting.** These are measured and modelled: autobind,
  `AF_UNSPEC` dissolution (`docs/probes/udp-connect`), the destination ladder
  (wildcard, port 0, broadcast, non-local), and port sharing under
  `SO_REUSEADDR` across processes and uids (`PortHolderRules`). A connect to a
  port nobody holds succeeds, as it should. A datagram connect is a peer
  filter, not a handshake.
- **No index.** Nothing maps a port to the sockets bound there.
  `UnixMachineState.portHolders` scans every socket.
- **Readiness.** On Linux, `socketReadinessLevel` answers OUT alone for a
  datagram socket (`poll` 0x304), and never IN. On Darwin, `poll` and `kevent`
  refuse every datagram socket (`DarwinReadiness.modelsSocket`, issue #12).
- **Calls.** `UnconnectedSocketRules` answers `read` and `write` on a socket
  with no peer. A datagram `read` answers 0 for a count of 0, `EAGAIN` when
  non-blocking, and otherwise refuses as `DatagramSleep`. A datagram `write`
  answers `EDESTADDRREQ` (and on Linux, `EMSGSIZE` above 65535 bytes, binding
  first). `recv` and `send` refuse every socket that has no TCP connection.
  `FIONREAD` refuses one too, and `SO_ERROR` answers 0.
- **Flags.** `ReceiveFlags` accepts `MSG_PEEK`, `MSG_DONTWAIT` and
  `MSG_NOSIGNAL`, and `SendFlags` accepts `MSG_DONTWAIT` and `MSG_NOSIGNAL`.
  Every other flag is refused, `MSG_TRUNC` included.
- **The reserved parts.**
  - `Syscall.SendTo`, `RecvFrom`, `SendMsg` and `RecvMsg` carry opaque argument
    types, and `step` refuses them as `SyscallRefusal.Reserved`.
  - `ParkedDatagramReceive` holds only the description.
  - `FinishedDatagramReceive` has an empty representation.
  - No `WakePrimitive` is reserved for a datagram (`datagram-park-options.md`,
    decision).

## 2. Measured facts

**Probes**, beside this plan in `2026-10-18-udp-data-path/`, each with its
output:

- `udp-transfer.c`: every call's answers, sections A to W. Run on Darwin 27.0.0
  (macOS 27.0.1, arm64, uid 501), and on Linux 6.18.5 (aarch64, glibc 2.41, as
  root in Apple's `container`, sysctls at their defaults).
- `udp-capacity.c`: how many datagrams of each size an unread receiver holds.
  Both flavours.
- `udp-truesize.c`: what Linux charges a receiver per datagram, read through
  `SO_MEMINFO`, and when the charge is given back. Linux only.

Each probe was run more than once. Every row repeated, except the two that are
races by nature: which of several sleeping receivers took a datagram (S1), and
whether Darwin's asynchronous ICMP error had arrived "at once" (L1).

No x86-64 kernel was measured by hand. A host-equality test (section 5) checks
Linux's column on CI's x86-64 and Darwin's locally.

Below, L is Linux and D is Darwin.

### 2.1 Delivery is immediate on Linux and asynchronous on Darwin (A)

- **Linux.** A `MSG_DONTWAIT` receive straight after `sendto` found the
  datagram in 1000 trials of 1000.
- **Darwin.** It found it in 21 and in 1 of 1000 (two runs). The loopback
  interface delivers on another thread, as the TCP plan found for Darwin's send
  queue.
- **Linux under a burst.** Linux is asynchronous too: delivery moves from the
  sender's softirq to `ksoftirqd`, and a reader racing the burst sees fewer
  datagrams than will arrive. `udp-truesize.c` had to wait for each delivery for
  this reason.

The source address a receiver sees is 127.0.0.1 and the sender's port, on both.
That holds whether the sender was unbound (`sendto` gives it an ephemeral port
first) or bound to 0.0.0.0 or 127.0.0.1.

### 2.2 Datagrams, truncation, peeking and empty receives (B–E)

| row | L | D |
|---|---|---|
| datagrams of 10, 20, 30; four receives of 100 | 10, 20, 30, `EAGAIN` | same |
| 100 queued, `recv` of 10 | 10; the other 90 bytes are discarded | same |
| 100 queued, `recv` of 10 with `MSG_TRUNC` | **100** (the datagram's length) | **10** (the flag is ignored) |
| 100 queued, `recv` of 0 | 0, and the datagram is taken | same |
| 100 queued, `read` of 0 | **0, and the datagram stays** | 0, and it is taken |
| empty, non-blocking `recv` of 0 | **`EAGAIN`** | **0** |
| 100 queued, `recv` into an unmapped buffer | `EFAULT`, and **the datagram is lost** | `EFAULT`, and **it stays** |
| 100 queued, `recv` of 0 into an unmapped buffer | 0, and it is taken | same |
| 20 and 3 queued, peeks of 10, 100, and 10 with `MSG_TRUNC` | 10, 20, **20**; both stay | 10, 20, **10**; both stay |
| `sendto` of 0 bytes | 0; the receiver holds one empty datagram, which a `recv` takes and answers 0 | same |
| `sendto` of 0 bytes from NULL or an unmapped buffer | 0, and the datagram is sent | same |
| `sendto` of 5 bytes from an unmapped buffer | `EFAULT`, nothing sent; **Linux has bound the sender** | `EFAULT`, nothing sent; Darwin has bound it too |
| `read` of an unconnected socket holding a datagram | the datagram | same |

### 2.3 How large a datagram may be (H)

| | L | D |
|---|---|---|
| a fresh socket's `SO_SNDBUF` and `SO_RCVBUF` | 212992 and 212992 (`net.core.wmem_default`, `rmem_default`) | 9216 and 786896 (`net.inet.udp.maxdgram`, `recvspace`) |
| the largest datagram `sendto` or `send` takes | 65507, which is 65535 less the IP and UDP headers; `EMSGSIZE` above | **9216**; `EMSGSIZE` above |
| with `SO_SNDBUF` at 2048 | 65507 still taken | `EMSGSIZE` above 2048: the send buffer is Darwin's limit |

`EMSGSIZE` sends nothing, on both flavours.

### 2.4 How many datagrams a receiver holds (I, `udp-capacity.c`, `udp-truesize.c`)

Datagrams beyond a receiver's capacity are **dropped silently**: the sender's
call succeeds, and no error appears anywhere (L13). Both flavours are
deterministic here. Every count repeated exactly, paced or not, and fresh or
not, except for Darwin's first-datagram rule below.

**Linux** charges each queued datagram a fixed *truesize* by its length, read
directly through `SO_MEMINFO`:

| length | charge |
|---|---|
| 0–197 | 832 |
| 198–645 | 1280 |
| 646–1669 | 2304 |
| 1670–3717 | 4352 |
| 3718–7813 | 8448 |
| 7814–16004 | 16640 |
| 16005–65507 | length + 832 (sampled at 512 sizes, no exception) |

- **Admission.** A datagram is admitted exactly when the charge already held
  plus its own is at most `SO_RCVBUF` (212992). That held for every admission in
  nine single-size fills and in five mixed-size trials of 600 sends. Charges
  add exactly. So an unread receiver holds 256 datagrams of 0–197 bytes, 166 of
  198–645, 92 of 646–1669, and 3 of 65507.
- **Release.** Taking a datagram does not give its charge back at once. The
  charge of the datagrams taken accumulates, and is given back together once it
  reaches a quarter of `SO_RCVBUF` (53248), or once the reader's queue is empty.
  After 92 datagrams of 1000 bytes, the charge stood at 211968 through 23 takes
  and fell by 24 × 2304 at the 24th. A full receiver with 22 datagrams taken
  admitted nothing more; with 29 taken, 24 more.

  This is `udp_rmem_release`'s forward deficit. Linux's source has the shape:
  a receive moves the whole arrival queue into a reader queue when the reader
  queue is empty, and "the reader's queue is empty" means that reader queue.

**Darwin** counts in `sb_cc`, the same number `FIONREAD` reports (2.5).

- **Charge.** A datagram costs its length plus 32 bytes (a 16-byte address
  record and 16 more). The **first datagram a socket ever receives** costs
  its length plus 16 instead.
- **Admission.** A datagram is admitted exactly when `sb_cc` plus its cost is at
  most 786896.
- **Measurements.** The fresh and primed counts at 1138, 1139 and 1140 bytes
  are 672/672, 672/671 and 671/671. Those are
  floor((786896 + 16) / (length + 32)) for a fresh socket, and
  floor(786896 / (length + 32)) for one whose first datagram was taken.
  `FIONREAD` follows the same arithmetic step by step (F5, F6).
- **Release** is immediate (F5).
- **A second budget.** Darwin also counts mbufs, its kernel memory buffers, and
  that budget binds for small datagrams. A receiver holds at most 4099
  datagrams of 1–159 bytes, 3075 empty ones (3074 once primed), and 1757 of
  257 bytes up to at least 404. These fit a budget of 4 × 786896, at 768 per
  datagram of 1–256 bytes, 1024 per empty one and 1792 per larger one, with a
  datagram admitted while the budget is not exhausted.

  Above 415 bytes the byte budget always binds first. The byte formula held at
  every one of 150 sizes sampled from 160 to 9216, except at 282, 343 and 404,
  where the cap of 1757 binds. So at the default `recvspace`, the mbuf budget
  decides only for datagrams of 0–159 and 257–415 bytes. The per-datagram mbuf
  charges are inferred from three caps, not read from the kernel: Darwin has no
  `SO_MEMINFO`.

### 2.5 `FIONREAD` (F)

| queue | L | D |
|---|---|---|
| empty | 0 | 0 |
| 10, 20, 30 | **10** (the first datagram's length) | **140** (`sb_cc`: 60 bytes, plus 32 for each datagram, less 16 for the socket's first) |
| after taking the 10 | 20 | 114 |
| 0, then 10 | 0 | 74 |

Darwin's `SO_NREAD` answers the first datagram's length, as Linux's `FIONREAD`
does. It is not modelled, since `getsockopt` refuses it.

### 2.6 Readiness (G, L)

**Linux.**

| state | `poll` revents |
|---|---|
| unbound, bound, or connected, nothing queued | OUT\|WRNORM\|WRBAND (0x304), today's level |
| a datagram queued | IN\|RDNORM\|OUT\|WRNORM\|WRBAND (0x345) |
| an ICMP error pending (2.8) | OUT\|ERR\|WRNORM\|WRBAND (0x30c): **ERR, and no IN** |

Under `EPOLLET`:

- every arrival is an edge, even with datagrams already queued, and it reports
  IN|OUT (0x5);
- a take is not an edge;
- **a sender's own `sendto` gives it an OUT edge** (G6), which a TCP writer
  never gets;
- an ICMP error gives an ERR edge (0x8), even to a registration for IN alone.

**Darwin**, kqueue (G5–G7):

- `EVFILT_WRITE` is always ready, with data 9216, the send buffer.
- `EVFILT_READ` is ready while a datagram is queued, with **data the payload
  bytes queued** (10, then 30 with two queued, then 20). That is not `sb_cc`.
- Under `EV_CLEAR`, every arrival activates READ, and a take activates nothing.
  A sender's own send activates no WRITE.
- An ICMP error makes READ ready with data 0, and **no `EV_EOF`**.
- `poll`, derived from the filters, answers 0x104 empty, 0x145 with a datagram,
  and **0x145 with an error pending: IN, not ERR**.

### 2.7 Which socket a datagram reaches (J, Q, M)

- **A connected socket takes only datagrams from its peer.** Datagrams from
  anyone else are dropped, but a datagram queued before the `connect` stays
  (J1). The peer's address is compared as the datagram's source shows it, so a
  peer bound to 0.0.0.0 sending from 127.0.0.1 matches a connect to 127.0.0.1
  (J3).
- **A socket sending to itself** receives its datagram, connected to itself or
  not (M).
- **Several sockets on one port**, each the best match, on both flavours:
  - a socket bound to 127.0.0.1 beats one bound to 0.0.0.0, whichever was
    bound first (Q3);
  - a socket connected to the datagram's source beats an unconnected one (Q5).
    Linux shows the same when both bound before the connect (Q4), and Darwin
    refuses that second bind.
- **Ties.**
  - **Linux**, two unconnected sockets on 127.0.0.1:p with `SO_REUSEADDR`: the
    socket bound last takes every datagram (Q1, Q2). With `SO_REUSEPORT`, the
    choice hashes the source, so eight senders split 6 to 2.
  - **Darwin** refuses that second bind (`EADDRINUSE`). With `SO_REUSEPORT`,
    the socket bound last takes all.

  `SO_REUSEPORT` is not modelled.

### 2.8 A datagram that reaches no one: the ICMP error (L)

A datagram sent over loopback to a port no UDP socket would accept is answered
with ICMP "port unreachable".

- **Which ports count as unheld.** A port held only by a TCP socket (L11), and
  a port whose only socket is connected elsewhere (L12), both count.
- **Which sockets learn of it.** A **connected** sender then has
  `ECONNREFUSED` pending, on both flavours, and an unconnected one never learns
  of it (L4). Linux's `IP_RECVERR` would change that, and it is not settable.
- **A full receiver** raises nothing (L13).
- **When the error arrives.** Linux sets it before `sendto` returns. Darwin sets
  it a moment later: one run's "at once" `poll` saw it, and the other's did not.

How the pending error is reported and taken:

| call | L | D |
|---|---|---|
| `recv`, `read` (any count, 0 included) | `ECONNREFUSED`, taken | same |
| `send`, `write` | `ECONNREFUSED`, taken, nothing sent | same |
| `SO_ERROR` | 111, taken | 61, taken |
| `connect` elsewhere | succeeds; **the error stays pending** | **`ECONNREFUSED`, taken, and the socket is connected anyway** (`getpeername` names the new peer) |
| a datagram arrives while the error is pending | **the error first**, then the datagram | **the datagram first**, then the error |
| a blocking `recv` asleep when the error arrives | wakes with `ECONNREFUSED` | same |

`FIONREAD` with both pending is 4 on Linux and 36 on Darwin: the datagram,
whatever the error.

### 2.9 Sending on a connected socket (K)

- `write`, `send` and `sendto` with no address reach the peer, on both.
- **`sendto` with an address, on a connected socket**:
  - **Linux** sends to that address, whatever the peer;
  - **Darwin** answers **`EISCONN`**, even for the peer's own address.
- `write` of 0 sends an empty datagram, on both.
- `send` on an unconnected socket is `EDESTADDRREQ`, as `write` is.

### 2.10 `sendto`'s destination (N)

Each row is a fresh, unbound sender, sending to a receiver bound to 0.0.0.0.
"Binds" means `getsockname` shows an ephemeral port afterwards.

| destination | L | D |
|---|---|---|
| NULL, length 0 or 16 | `EDESTADDRREQ`, binds | `EDESTADDRREQ` |
| a good address, length 0, 8 or 15 | `EINVAL`, binds | `EINVAL` |
| length 17 or 128 | **sent** | **`EINVAL`**: Darwin takes 16 alone |
| length 129 or 200 | `EINVAL`, no bind (above `sockaddr_storage`, refused before the copy) | `EINVAL` |
| unmapped, length 16 | `EFAULT`, no bind | `EFAULT` |
| `AF_UNSPEC` | **sent, as `AF_INET`** | **sent** |
| `AF_INET6` or family 99, length 16 | `EAFNOSUPPORT`, binds | `EAFNOSUPPORT` |
| `AF_INET6` `::1`, length 28 | `EAFNOSUPPORT`, binds | `EINVAL` |
| 127.0.0.1, port 0 | `EINVAL`, binds | `EADDRNOTAVAIL` |
| 0.0.0.0 | **sent, and delivered** (as to 127.0.0.1) | **`EHOSTUNREACH`, binds** |
| 255.255.255.255 | `EACCES`, binds | `EHOSTUNREACH`, binds |
| 127.0.0.2 | sent, and delivered to a 0.0.0.0 receiver but not a 127.0.0.1 one; the source is 127.0.0.1 | sent, and **delivered to no one** |
| `sin_zero` non-zero; Darwin `sin_len` 0, 8 or 255 | sent | sent |
| a pipe; a closed descriptor | `ENOTSOCK`; `EBADF` (also with an unmapped buffer or address) | same |

**Order.** Linux autobinds first and keeps the binding whatever then fails,
except a destination it could not copy in. That matches `connect`'s
`failPrepared` and `write`'s `writeBindsFirst`. Darwin binds on success, on
`EHOSTUNREACH`, and when the data buffer faults (E6), but not on any other
failure of the destination.

### 2.11 `recvfrom`'s source (O)

With a datagram queued from 127.0.0.1:p, the address length cell is in and out.

| source argument | L | D |
|---|---|---|
| address length 0 | 3; nothing written; **length out 16** | 3; nothing written; **length out 0** |
| length 1–15 | that many bytes of the address, length out 16 | same (Darwin's bytes start with `sin_len` 16) |
| length 16 or more | 16 bytes, length out 16 | same |
| NULL address, length 16 | 3; length out 16 | same |
| an address, NULL length | **`EFAULT`, and the datagram is lost** | **3**, nothing written |
| length 0xFFFFFFFF | **`EINVAL`, and the datagram is lost** | 3, length out 16 |
| unmapped address, length 16 | **`EFAULT`, and the datagram is lost** | **3**: the fault is ignored |
| unmapped length cell | `EFAULT`, and the datagram is lost | `EFAULT`, and **the datagram stays** |
| nothing queued, length 99 | `EAGAIN`; the cell is untouched | same |
| a connected receiver | the source is reported | same |

### 2.12 `recvmsg` and `sendmsg` (P)

| row | L | D |
|---|---|---|
| iovecs of 4 and 4, a datagram of 6 | 6, scattered `ABCD`/`EF`; `msg_namelen` 16; `msg_controllen` 0; `msg_flags` 0 | same |
| a datagram of 100 into 10 | 10; `msg_flags` `MSG_TRUNC` | same |
| into 10, with `MSG_TRUNC` | **100**, `MSG_TRUNC` | 10, `MSG_TRUNC` |
| `MSG_DONTWAIT` or `MSG_PEEK` given | `msg_flags` 0 | **`msg_flags` echoes them** (0x80, 0x2) |
| `EAGAIN` | `msg_flags` untouched | same |
| no iovecs, a datagram of 100 | **0, `MSG_TRUNC`, taken** | **`EMSGSIZE`, it stays** |
| `msg_name` NULL, `msg_namelen` 16 | `msg_namelen` out 16 | same |
| `sendmsg` gathering `ab`, ``, `cde` | 5, one datagram `abcde` | same |
| `sendmsg` with no name, unconnected | `EDESTADDRREQ` | same |
| `sendmsg` with no iovecs | **0, an empty datagram sent** | **`EMSGSIZE`** |
| `sendmsg` with 16 zero bytes of control | **`EINVAL`** (a `cmsg_len` of 0) | sent |

### 2.13 Sleeping receivers (S, and `datagram-park`)

- **One datagram wakes one sleeper.** Three threads asleep in `recv` on one
  socket: one datagram returned one of them, and a second returned another. The
  third slept on until a signal, on both flavours. Linux wakes one waiter, and
  Darwin wakes all of them, but the losers sleep again, so the answers are the
  same.
- From `datagram-park` (R1–R6):
  - every receiving call sleeps;
  - a caught signal is `EINTR`, or a restart under `SA_RESTART`;
  - a close of the descriptor leaves a Linux receiver asleep, holding the
    socket, and ends a Darwin one with `EBADF`;
  - Linux's `SHUT_RD` ends it with 0;
  - `SO_RCVTIMEO` is `EAGAIN`.
- An ICMP error wakes a sleeper (L9).

### 2.14 Flags (W)

| flag | L | D |
|---|---|---|
| `sendto` with `MSG_OOB` | `EOPNOTSUPP` | same |
| `recv` with `MSG_OOB`, a datagram queued | **the datagram** (ignored) | **`EOPNOTSUPP`**, it stays |
| `recv` with `MSG_WAITALL` | ignored: answers the datagram | same |
| `MSG_NOSIGNAL`, `MSG_DONTROUTE`, an unknown bit (0x40000000) | ignored | same |
| `MSG_DONTWAIT` on a blocking socket | `EAGAIN` when empty | same |

## 3. Design options

### 3.1 Where the datagrams wait

A datagram is queued at a socket, and lives exactly as long as the socket does.
There is no connection to outlive either end, so the TCP plan's reason for
holding bytes off the socket does not apply.

- **(A) A machine map, `UnixMachineState.DatagramReceivers :
  Map<SocketId, DatagramReceiver>`**, beside `Connections` and `Pipes`.
  - An entry exists for a UDP socket from its creation, and goes with it in
    `ObjectLifetime.releaseDestroyed`.
  - `DatagramReceiver` holds the queue, its charge, the pending error, and the
    per-flavour state below. Its representation is private to its own file,
    as `CommittedFileSystem`'s is.
  - `checkInvariants` gains "every UDP socket has a receiver, and every
    receiver has a UDP socket".
  - Nothing public changes.
- **(B) A field on `SocketDescription`.** That record is public, so this is an
  API change. It would also give every TCP and Unix-domain socket an empty
  queue that nothing may fill: an illegal state the types allow.
- **(C) Split the datagram phases**: `SocketPhase.Idle` is shared with stream
  sockets, so this means `DatagramIdle of DatagramReceiver` and
  `DatagramPeer of SocketAddress * DatagramReceiver`. This makes "only a
  datagram socket has a queue" structural. But `SocketPhase` is public, and
  every match on `Idle` or `DatagramPeer` changes, in the library and in
  clients.

**Recommend (A).** It mirrors how `Connections` and `Pipes` already hold
transfer state, the illegal state costs one invariant rather than a public
type, and it is the most reversible choice. A move to (C) later is a refactor
behind accessors.

### 3.2 How many datagrams wait

Section 2.4 shows both flavours' capacity is a deterministic function of the
sizes and of the takes, with a rule small enough to state.

- **(A) Reproduce each flavour's accounting.**
  - **Linux**: the truesize table, admission at "held + own ≤ 212992", and the
    forward-deficit release, with its reader queue and arrival queue.
  - **Darwin**: the byte budget, with its first-datagram discount, released
    at once, and the mbuf budget.

  `FIONREAD` then falls out on Darwin (it is the byte budget). A randomised
  test of interleaved sends and takes against the host checks the rule, on
  Linux in CI and Darwin locally.

  For Darwin's mbuf budget, whose charges are inferred rather than read, there
  are two choices:
  - **(A1)** model it with the inferred charges, and let the randomised host
    test confirm or refute them on mixed sizes;
  - **(A2)** refuse (`UnmodelledException`) an arrival at a Darwin queue
    already holding 1757 datagrams, the smallest cap measured. Below that
    count the mbuf budget cannot bind, if no datagram costs more than the
    largest inferred charge.

  **Recommend (A2)** for U1: it is exact wherever it answers, and a program
  must queue 1757 unread datagrams to reach it. (A1) can follow once the host
  test has a mixed-size Darwin corpus to hold it to.
- **(B) Count payload bytes against `SO_RCVBUF`.** This is simple, but an
  unread Linux receiver would then hold 2129 datagrams of 100 bytes where the
  kernel holds 256. A program that floods an unread socket would see every
  datagram arrive.
- **(C) No capacity.** No drops at all. This violates "bound uncertainty", and
  a dropped datagram is precisely what UDP programs are written to survive.

**Recommend (A).** Both rules are a handful of integers and one comparison,
the probes give exact expected answers, and the host test makes a wrong
reconstruction fail loudly.

**The sysctls are configuration.** Linux's `net.core.rmem_default` (212992) and
Darwin's `net.inet.udp.recvspace` (786896) and `net.inet.udp.maxdgram` (9216)
are values an administrator sets. So, by the `emulated-posix-kernel` skill's
rule, they are boot configuration with these defaults, as `TcpSendSpace` is.
The truesize table and the 832, 32 and 16 are the kernel's own, and so are
platform facts. **Recommend** adding the three as machine settings now, with
setters only once a client needs to change one. A setter is additive.

### 3.3 Which socket receives

Delivery picks, among the UDP sockets bound to the destination's port:

- those whose address is the destination or the wildcard;
- those either unconnected, or connected to exactly the datagram's source.

It then ranks them: a connected socket over an unconnected one, and a specific
address over the wildcard. These are measured rules: 2.7, Q3 and Q5.

- **Ties.** Two candidates can still tie: Linux's two `SO_REUSEADDR` sockets,
  or Darwin's sharing permitted beside a connected holder.
  - **(a) Refuse** (`UnmodelledException`) when the best rank holds more than
    one socket.
  - **(b) Model Linux's "bound last wins"**, which needs the kernel to record
    the order of bindings, and whose rule under rebinding (`AF_UNSPEC`
    dissolution, a re-`connect` that moves the local address) is unmeasured.

  **Recommend (a)** now. (b) can follow as its own measured change.
- **Cost.** Finding candidates by scanning every socket makes each `sendto`
  O(sockets). That breaks the per-call cost work (#124, #130, #132).
  - **(a) Scan first, index next.** Deliver by a scan in the first stage, then
    add a port index in a separate PR. That PR follows #124's pattern: an index
    inside a private representation, an oracle property test (index ≡ scan),
    and an allocation-ratio cost test.
  - **(b) Build the index in the first stage.**

  **Recommend (a)**, so that the stage that changes behaviour is reviewable on
  its own.

### 3.4 When a datagram is delivered

Darwin delivers asynchronously on loopback, and so does Linux under a burst
(2.1). **The model delivers before `sendto` returns.** That is one of each
kernel's possible schedules: the common one on Linux, and one seen on Darwin
(21 of 1000). So every answer the model gives is one the kernel can give.

The ICMP error is likewise set before `sendto` returns, on both, which Darwin
also showed (L1, first run). What the model never shows is the window in which
a Darwin datagram, or error, is in flight. No program can depend on the width
of that window.

### 3.5 The pending error

- **One slot per receiver**, `ECONNREFUSED option`, set when a connected
  socket's datagram finds no receiver at all.
- **No error** when a candidate exists but its queue is full (L13), and none
  for an unconnected sender (L4).
- Every reader of the slot takes it, as the 2.8 table says: one function per
  flavour, tested against the table. It decides which comes first, the error
  or a queued datagram, and whether `connect` takes the error.
- **The slot is per flavour by type**, not a field Darwin ignores. Linux's
  `connect` leaves the error pending and Darwin's takes it, so the same slot
  has different lifecycles, which a function per flavour expresses.

### 3.6 How the calls are expressed

**`read`, `write`, `send` and `recv`** on a datagram socket move to the
datagram receiver. `UnconnectedSocketRules` keeps its rules for a socket that
holds nothing. Its "datagram, blocking, sleeps" becomes the park (3.8).

**`sendto` and `recvfrom`** need real argument types. NULL is not the same as
an unmapped address here: `sendto` with a NULL destination is `EDESTADDRREQ`,
not `EFAULT`. And each of `recvfrom`'s two source pointers is separately NULL or
not (2.11). A sketch:

```fsharp
/// sendto(2)'s destination argument.
type SendDestination =
    /// A NULL `dest_addr`.
    | Absent
    /// A `dest_addr` and `addrlen`. The address is what the caller's memory held.
    | Present of address : CopiedArgument<ImmutableArray<byte>> * declaredLength : uint32

type SendToArguments =
    internal
        {
            Fd : int
            Buffer : CopiedArgument<ImmutableArray<byte>>
            Count : uint64
            Flags : int
            Destination : SendDestination
        }

type RecvFromArguments =
    internal
        {
            Fd : int
            Buffer : UserBuffer
            Count : uint64
            Flags : int
            /// `src_addr`: None for NULL.
            Source : UserBuffer option
            /// `addrlen`, which the call reads and then writes: None for NULL.
            SourceLength : CopiedArgument<uint32> option
        }
```

- **Construction.** The records keep internal representations, with a public
  `create` for each, so a field can be added later without breaking a client.
- **The answers.** `recvfrom` answers the bytes received, the length the call
  returns (which `MSG_TRUNC` makes the datagram's length on Linux), and what
  it writes to the source and its length cell. Writes go through the
  `copyOutInternetSockaddr` path that `accept` and `getsockname` use.

**`sendmsg` and `recvmsg`** carry a `msghdr`, an iovec array and a control
buffer. Each is a separate copy-in that can fault on its own, and the flags
come back out. Their argument shape, and what the kernel does with control
messages, are a design note of their own before their stage (section 4, stage
U5). Section 2.12 is its measured input.

**Flags.** Accept what section 2.14 measured, by flavour: `MSG_TRUNC` on a
receive, and Linux's ignored `MSG_OOB` on a receive. Keep refusing every
unmeasured bit, as today, rather than ignoring it as both kernels do.

### 3.7 Readiness and wakes

**Linux.**

- `socketReadinessLevel` gains IN while the queue is non-empty, and ERR while
  the error is pending. In the error state it drops IN, as 2.6 measured.
- `SocketWake.DataArrived` already exists. A delivery raises it on the
  receiver for each datagram.
- A new `SocketWake.DatagramSent` raises an OUT edge on the sender after each
  send (G6).
- A new `SocketWake.ErrorRaised` raises ERR on the sender when the ICMP error
  is set (G7).

**Darwin.** `poll` and `kevent` on a datagram socket stay refused until their
own stage (U6), which answers issue #12 for UDP. That stage's facts are in
2.6: READ with data the payload bytes queued, WRITE always ready with data
9216, activation on each arrival, an error making READ ready with data 0, and
Darwin's datagram `connect` activating WRITE. That last is the reason
`modelsSocket` gives today.

### 3.8 The blocking receive

`ParkedDatagramReceive` gains what the finish needs: which call it was (`read`,
`recv`, `recvfrom` or `recvmsg`), the count, the flags, and where `recvfrom`'s
or `recvmsg`'s source goes. It also gains, for Darwin, that a close has ended
it (R3), as `SleepTarget.EndedByClose` is for a TCP read.

- **(a) One primitive, `WakePrimitive.DatagramReceivable of reader`**: the
  queue is non-empty, or an error is pending. Several sleepers may all be
  satisfied by one datagram. The client runs one, it takes the datagram, and
  the others find nothing on their finish and park again. That is Darwin's
  mechanism outright, and Linux's answers. The kernel's finishing functions
  already re-park a TCP reader that was beaten to the bytes.
- **(b) An exclusive primitive** that wakes exactly one sleeper per datagram,
  as Linux does. The answers would be the same, at the cost of a wake queue
  that the per-call cost work deliberately did not build.

**Recommend (a).** S1 shows the two are indistinguishable to a program.

## 4. Staging

Each stage is a PR, green on its own, with the README changed alongside the API
it touches.

- **U0. This plan and its probes.**
- **U1. The receiver, and connected transfer through existing calls.**
  - `DatagramReceiver` (3.1) with both flavours' accounting (3.2), as pure
    functions, property-tested against a naive reference and against the
    probe outputs embedded as resources.
  - Then the calls: `write` and `send` to a peer; `read` and `recv` of a queued
    datagram, or `EAGAIN` when non-blocking (a blocking one with nothing queued
    stays refused); `MSG_TRUNC`; `FIONREAD`; the ICMP error and `SO_ERROR`
    (3.5); Linux readiness and wakes (3.7); delivery by scan (3.3).
  - `TestDatagramTransferAgainstHost` replays sections B to L against the host,
    and a randomised sequence of sends and takes checks the capacity rules.
- **U2. The port index** (3.3). No behaviour change.
- **U3. `sendto` and `recvfrom`** (3.6): the argument and answer types, the
  destination ladder of 2.10 (sharing `connect`'s decoding and autobind), and
  the source writes of 2.11.
- **U4. The blocking receive** (3.8): the park's fields, the primitive, the
  finish, and close per flavour. `ReadRefusal.DatagramSleep` goes.
- **U5. `sendmsg` and `recvmsg`**: their design note, then the calls (2.12).
- **U6. Darwin `poll` and `kevent` on UDP sockets** (2.6), for issue #12.

U3 and U4 are independent of each other once U1 lands. A client that needs
blocking receives first can have U4 before U3.

## 5. What the model deliberately does not reproduce

- **Delivery latency** (3.4): datagrams and errors arrive before `sendto`
  returns.
- **Ties at delivery** (3.3) and **`SO_REUSEPORT`**: refused.
- **Buffer-size options**: `SO_RCVBUF` and `SO_SNDBUF` are refused, so
  capacities are the configured defaults.
- **Unknown flags**: refused, where both kernels ignore them.
- **Darwin's mbuf budget** (3.2, A2): an arrival at a queue holding 1757
  datagrams is refused.

## Decisions

To be taken with Patrick before U1: 3.1, 3.2 (and the sysctls), 3.3 (ties and
cost), 3.8, and the stage order.
