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
- `udp-release.c`: which calls refill a Linux receiver's reader queue, seen
  through when the charge comes back. Linux only.
- `udp-mbufs.c`: what Darwin charges a receiver per datagram in bytes and in
  mbuf memory, read from `net.inet.udp.pcblist_n`, what a socket's history
  does to the charge, and whether the two-budget rule predicts every arrival.
  Darwin only.

Each probe was run more than once. Every row repeated, except the two that are
races by nature: which of several sleeping receivers took a datagram (S1), and
whether Darwin's asynchronous ICMP error had arrived "at once" (L1).

No x86-64 kernel was measured by hand. A host-equality test (section 5) checks
Linux's column on CI's x86-64 and Darwin's locally.

Below, L is Linux and D is Darwin.

### 2.1 Delivery is immediate on Linux and asynchronous on Darwin (A)

- **Linux.** A `MSG_DONTWAIT` receive straight after `sendto` found the
  datagram in 1000 trials of 1000.
- **Darwin.** It found it in between 1 and 121 of 1000, over five runs. The loopback
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
| 100 queued, `recv` into an unmapped buffer (C8, C10) | `EFAULT`, and **the datagram is lost** | `EFAULT`; **the payload stays, stripped of its source address and control record** (`FIONREAD` 116 → 100), and the `recvfrom` that takes it reports no source (`addrlen` 0, nothing written) |
| 100 queued, `recv(MSG_PEEK)` into an unmapped buffer (C10) | `EFAULT`, and it stays whole | same |
| 100 queued, `recv` of 0 into an unmapped buffer | 0, and it is taken | same |
| 20 and 3 queued, peeks of 10, 100, and 10 with `MSG_TRUNC` | 10, 20, **20**; both stay | 10, 20, **10**; both stay |
| `sendto` of 0 bytes | 0; the receiver holds one empty datagram, which a `recv` takes and answers 0 | same |
| `sendto` of 0 bytes from NULL or an unmapped buffer | 0, and the datagram is sent | same |
| a connected `send` or `write` from an unmapped buffer (H3) | `EFAULT` at 5 and 9217 bytes, `EMSGSIZE` at 65508 and above: the size is judged first | `EFAULT` at 5 bytes, `EMSGSIZE` at 9217 and above |
| a fresh sender's `sendto` of 5 bytes from an unmapped buffer | `EFAULT`, nothing sent; **the sender is bound** | `EFAULT`, nothing sent; **the sender is not bound** |
| `read` of an unconnected socket holding a datagram | the datagram | same |

### 2.3 How large a datagram may be (H)

| | L | D |
|---|---|---|
| a fresh socket's `SO_SNDBUF` and `SO_RCVBUF` | 212992 and 212992 (`net.core.wmem_default`, `rmem_default`) | 9216 and 786896 (`net.inet.udp.maxdgram`, `recvspace`) |
| the largest datagram `sendto` or `send` takes | 65507, which is 65535 less the IP and UDP headers; `EMSGSIZE` above | **9216**; `EMSGSIZE` above |
| with `SO_SNDBUF` at 2048 | 65507 still taken | `EMSGSIZE` above 2048: the send buffer is Darwin's limit |

`EMSGSIZE` sends nothing, on both flavours.

### 2.4 How many datagrams a receiver holds (I, `udp-capacity.c`, `udp-truesize.c`, `udp-release.c`, `udp-mbufs.c`)

Datagrams beyond a receiver's capacity are **dropped silently**: the sender's
call succeeds, and no error appears anywhere (L13). Both flavours are
deterministic here. Each kernel's own account of a socket's buffer was read
directly: Linux's through `SO_MEMINFO`, and Darwin's through the
`net.inet.udp.pcblist_n` sysctl, which `netstat` reads. Every rule below
predicted every admission in its probe.

**Linux** charges each queued datagram a fixed *truesize* by its length:

| length | charge |
|---|---|
| 0–197 | 832 |
| 198–645 | 1280 |
| 646–1669 | 2304 |
| 1670–3717 | 4352 |
| 3718–7813 | 8448 |
| 7814–16004 | 16640 |
| 16005–65507 | length + 832 (sampled at 512 sizes, no exception) |

The table is of slab sizes, measured on aarch64. x86-64's may differ, and
CI's host test (section 4, U1) is what will show it.

- **Admission.** A datagram is admitted exactly when the charge already held
  plus its own is at most `SO_RCVBUF` (212992). That held for every admission in
  nine single-size fills and in five mixed-size trials of 600 sends. Charges
  add exactly. So an unread receiver holds 256 datagrams of 0–197 bytes, 166 of
  198–645, 92 of 646–1669, and 3 of 65507.
- **Release.** Taking a datagram does not give its charge back at once. The
  charge of the datagrams taken accumulates, and is given back together once it
  reaches a quarter of `SO_RCVBUF` (53248), or once the reader queue is empty.
  After 92 datagrams of 1000 bytes, the charge stood at 211968 through 23 takes
  and fell by 24 × 2304 at the 24th. A full receiver with 22 datagrams taken
  admitted nothing more; with 29 taken, 24 more.

  This is `udp_rmem_release`'s forward deficit. Linux keeps two queues: the
  arrivals, and a reader queue that a receive refills with every arrival at
  once, when it finds the reader queue empty. "Empty" means the reader queue.
- **Which calls refill the reader queue** (`udp-release.c`). Each was made with
  ten datagrams arrived, before ten more:
  - **refill**: `recv(MSG_PEEK)`, `FIONREAD`, and `poll`, `epoll_ctl(ADD)` or
    `epoll_wait` of a **blocking** socket;
  - **do not refill**: the same `poll` and `epoll_wait` of a non-blocking
    socket, and `FIONREAD` when the reader queue holds something.

  This is `first_packet_length`, which `FIONREAD` calls, and which `udp_poll`
  calls only for a description without `O_NONBLOCK`. So on Linux, a `poll` of a
  blocking UDP socket changes when its charge comes back.

**Darwin** keeps two budgets, both in bytes:

- **`sb_cc`**, which `FIONREAD` reports (2.5):
  - **the charge** is a datagram's length plus 32 (its 16-byte source address
    and a 16-byte control record);
  - **the cheaper charge** is length + 16, without the control record. It goes
    to a datagram arriving at a socket that has never sent or received a
    datagram and is not connected (`udp-mbufs.c` section 2):
    - a socket that has received, or is connected, pays 32;
    - so does one that has made any send call that reached it, whatever the
      call answered: a datagram sent, or `EDESTADDRREQ`, `EMSGSIZE`, `EFAULT`,
      `EINVAL`, `EAFNOSUPPORT` or `EHOSTUNREACH`;
    - `connect` followed by `AF_UNSPEC`, with nothing sent, restores the 16;
    - a failed `connect`, a send to a closed descriptor, `getsockname`,
      `SO_REUSEADDR`, `poll`, `FIONREAD` and an empty `recv` change nothing.
- **`sb_mbcnt`**, the mbuf memory the datagram occupies. It is measured at every
  size from 0 to 9216, with the cheaper charge and without:

  | length | with the 16-byte control record | without |
  |---|---|---|
  | 0 | 2048 | 1536 |
  | 1–256 | 1536 | 1024 |
  | 257–288 | 3584 | 1536 |
  | 289–2016 | 3584 | 3584 |
  | 2017–2048 | 5632 | 3584 |
  | 2049–4064 | 5632 | 5632 |
  | 4065–4096 | 10240 | 5632 |
  | 4097–8160 | 10240 | 10240 |
  | 8161–8192 | 14848 | 10240 |
  | 8193–9216 | 14848 | 14848 |

- **Admission.** A datagram is admitted exactly when `sb_cc` plus its byte
  charge is at most `sb_hiwat` (786896, `net.inet.udp.recvspace`), *and*
  `sb_mbcnt` plus the same byte charge is at most `sb_mbmax`. The budget is
  6295168 = 8 × 786896, under `kern.ipc.maxsockbuf`'s 8388608.
  - Section 3 of `udp-mbufs.c` checked this against every arrival and drop in
    eight random mixtures of sizes and takes, about 6,000 datagrams, with no
    exception.
  - It also explains every count of `udp-capacity.c`: 4099 datagrams of 1–159
    bytes, 3075 empty ones (3074 once primed), and 1757 of 257–415 bytes, where
    the mbuf budget decides, and floor(786896 / (length + 32)) elsewhere.
  - It explains the reviewer's mixture too: five datagrams of 9216 bytes, then
    1737 of 257, keep 1741.
- **Release** of both budgets is immediate (F5).

### 2.5 `FIONREAD` (F)

| queue | L | D |
|---|---|---|
| empty | 0 | 0 |
| 10, 20, 30 | **10** (the first datagram's length) | **140** (`sb_cc`: 60 bytes, plus 32 for each datagram, less 16 for the first, which arrived at a fresh socket) |
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
| an ICMP error pending (2.8), nothing queued | OUT\|ERR\|WRNORM\|WRBAND (0x30c) |
| an ICMP error pending and a datagram queued | IN\|RDNORM\|OUT\|ERR\|WRNORM\|WRBAND (0x34d): IN and ERR are independent |

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
  and **0x145 with an error pending, with or without a datagram: IN, never
  ERR**.

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
    choice hashes the source with a secret chosen at boot, so eight senders
    split 6 to 2, 5 to 3 and 2 to 6 in three runs.
  - **Darwin** refuses that second bind (`EADDRINUSE`). With `SO_REUSEPORT`,
    the socket bound last takes all.

  `SO_REUSEPORT` is not modelled.

### 2.8 A datagram that reaches no one: the ICMP error (L)

A datagram sent over loopback to a port no UDP socket would accept is answered
with ICMP "port unreachable".

- **Which ports count as unheld.** A port held only by a TCP socket (L11), and
  a port whose only socket is connected elsewhere (L12), both count.
- **Which socket learns of it** (L4, L16): the socket a reply from the
  destination to the datagram's source would reach, by the rules of 3.3, and
  only if that socket is connected. Usually that is the connected sender
  itself, and an unconnected sender never learns of it. But with A connected
  to the unheld port and B sharing A's local endpoint unconnected, B's
  `sendto` leaves the error pending at A, on both flavours; with A connected
  elsewhere, at no one. Linux's `IP_RECVERR` would change that, and it is not
  settable.
- **A full receiver** raises nothing (L13).
- **When the error arrives.** Linux sets it before `sendto` returns. Darwin sets
  it a moment later: one run's "at once" `poll` saw it, and the other's did not,
  and likewise whether L2's second send, made at once, met it.
- **How often** (X). **Linux** raises an error for every such datagram: sends
  15 ms apart, sends every 40 ms, and 80 sockets sending at once each got one.
  **Darwin** keeps one record, for the whole machine, of the last datagram it
  answered with the error. It answers a datagram unless that datagram is on
  the record's four-tuple (local address and port, remote address and port)
  and less than 100 ms have passed since.
  - The boundary is at 100 ms, to within Darwin's delivery jitter. A second
    send 100 ms or more after the first always raised an error (5 of 5, in
    every run). One 95 or 98 ms after raised one at most once in 5, and one
    85 ms or less after, never.
  - A send the window suppresses does not extend it. Sends every 40 ms raised
    errors at 0, 120, 240 and 360 ms.
  - **It is one record, not one per four-tuple** (X8). With sockets A, B and C
    connected to unheld ports P, Q and R, `A>P A>P B>P A>P` raises, suppresses,
    raises, raises. B's datagram replaced the record, so A's third is answered
    within the window. `A>P B>Q A>P B>Q` raises all four, and `A>P A>P A>P`
    only the first.
  - **It is of the four-tuple, not the socket** (X6):
    - a socket that reconnects to another unheld port gets an error at once;
    - one that reconnects back to the first within the window gets none;
    - a new socket bound to the same local endpoint and connected to the same
      peer gets none, though the first socket has closed;
    - one bound elsewhere gets one (X5: two sockets at one port, both errors).
  - **It counts a datagram whose error no one is told of** (X7). An unconnected
    `sendto` an unheld port, which reports nothing, keeps a connect to that
    port and a send 20 ms later from raising an error.

How the pending error is reported and taken:

| call | L | D |
|---|---|---|
| `recv`, of any count, 0 included; `read` of more than 0 | `ECONNREFUSED`, taken | same |
| `read` of 0, into a buffer or NULL (L14) | **0, and the error stays pending** (Linux's zero-length read answers 0 in every state) | **`ECONNREFUSED`, taken** |
| `send`, `write`, of any count, 0 included | `ECONNREFUSED`, taken, nothing sent | same |
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
| 127.0.0.2 | sent, and delivered to a 0.0.0.0 receiver but not a 127.0.0.1 one; the source is 127.0.0.1 | sent, and **delivered to no one**; a connected sender gets no error either (L15) |
| `sin_zero` non-zero; Darwin `sin_len` 0, 8 or 255 | sent | sent |
| a pipe; a closed descriptor | `ENOTSOCK`; `EBADF` (also with an unmapped buffer or address) | same |

**Order.** Linux autobinds first and keeps the binding whatever then fails,
except a destination it could not copy in. That matches `connect`'s
`failPrepared` and `write`'s `writeBindsFirst`, and Linux binds when the data
buffer faults too (E6). Darwin binds only on success and on `EHOSTUNREACH`.

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

- **One datagram completes one taker.** Three threads asleep in `recv` on one
  socket: one datagram returned one of them, and a second returned another. The
  third slept on until a signal, on both flavours.
- **Peekers show who is woken** (S3 to S5). Linux wakes only the sleeper that
  parked first, and Darwin wakes all: three peekers, one datagram, one returned
  on Linux and all three on Darwin. Section 3.8 has the rest.
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

- **(A) Reproduce each flavour's accounting**, as section 2.4 read it from
  each kernel.
  - **Linux**: the truesize table, admission at "held + own ≤ 212992", and the
    forward-deficit release, with its reader queue and arrival queue, and the
    calls that refill the reader queue.
  - **Darwin**: the byte budget and the mbuf budget, each charge with its
    cheaper form for a socket that has neither sent, received, nor connected,
    both released at once.

  `FIONREAD` then falls out on Darwin, since it is the byte budget. A
  randomised test of interleaved sends and takes against the host checks both
  rules, on Linux in CI and on Darwin locally.

  An earlier draft refused an arrival at a Darwin queue holding 1757
  datagrams, because Darwin's mbuf charges were then inferred from three caps
  rather than read. Review showed that refusal was unsafe: datagrams of mixed
  sizes are dropped below it. The charges are now read for every size, and
  the rule predicted every arrival in mixed trials, so the refusal is gone.
- **(B) Count payload bytes against `SO_RCVBUF`.** This is simple, but an
  unread Linux receiver would then hold 2129 datagrams of 100 bytes where the
  kernel holds 256. A program that floods an unread socket would see every
  datagram arrive.
- **(C) No capacity.** No drops at all. This violates "bound uncertainty", and
  a dropped datagram is precisely what UDP programs are written to survive.

**Recommend (A).** Each rule is a table and one or two comparisons, the probes
give exact expected answers, and the host test makes a wrong reconstruction
fail loudly.

**The sysctls are configuration.** Linux's `net.core.rmem_default` (212992) and
Darwin's `net.inet.udp.recvspace` (786896) and `net.inet.udp.maxdgram` (9216)
are values an administrator sets. So, by the `emulated-posix-kernel` skill's
rule, they are boot configuration with these defaults, as `TcpSendSpace` is.
The truesize table, Darwin's mbuf table, and its 32, 16 and factor of 8 are
the kernel's own, and so are platform facts. **Recommend** adding the three as machine settings now, with
setters only once a client needs to change one. A setter is additive.

### 3.3 Which socket receives

First, **whether the machine takes the destination address as its own**, by
flavour (2.10, N and L15):

- **Linux** takes every address on a local route, so a datagram to 127.0.0.2
  is delivered to a socket bound to the wildcard, though not to one bound to
  127.0.0.1. With no socket to take it, it is answered with the ICMP error.
- **Darwin** takes only the addresses it holds (`LocalIpv4Addresses`). A
  datagram to 127.0.0.2, which `connect` and `sendto` accept, reaches no one
  and raises no error, whether or not a wildcard socket holds its port.

Then delivery picks, among the UDP sockets bound to the destination's port:

- those whose address is the destination or the wildcard;
- those either unconnected, or connected to exactly the datagram's source.

It ranks them: a connected socket over an unconnected one, and a specific
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
(up to 121 of 1000). So every answer the model gives is one the kernel can
give.

The ICMP error is likewise set before `sendto` returns, on both, which Darwin
also showed (L1, first run). What the model never shows is the window in which
a Darwin datagram, or error, is in flight. No program can depend on the width
of that window.

### 3.5 The pending error

- **One slot per receiver**, `ECONNREFUSED option`, set when a datagram finds
  no receiver at all, at the socket a reply from its destination would reach
  if that socket is connected (2.8, L16). Where that is a tie (L16, Linux's
  two sockets connected to one peer), the send is refused.
- **No error** when a candidate exists but its queue is full (L13), and none
  where the reply lookup finds no socket, or an unconnected one (L4). So an
  unconnected sender never learns of its own datagram's error, though a
  connected socket sharing its endpoint may (L16).
- **Darwin's 100 ms window** (2.8, X) is one machine-wide record: the
  four-tuple and kernel-clock time of the last datagram answered with the
  error. It is not in any receiver, since it outlives its socket and counts
  unconnected senders.
  - A datagram to no one is answered unless it is on the record's four-tuple
    and the clock has moved less than 100 ms past the record. An answer
    replaces the record; a suppressed datagram leaves it alone.
  - A connected sender whose datagram is answered has the error pending.
  - The clock moves only when the client says, so the answer is a function of
    the history.
- Every reader of the slot takes it, as the 2.8 table says: one function per
  flavour, tested against the table. It decides which comes first, the error
  or a queued datagram, and whether `connect` takes the error.
- **The slot is per flavour by type**, not a field Darwin ignores. Linux's
  `connect` leaves the error pending and Darwin's takes it, so the same slot
  has different lifecycles, which a function per flavour expresses.

### 3.6 How the calls are expressed

**`read`, `write`, `send` and `recv`** on a datagram socket move to the
datagram receiver. Linux's zero-length `read`, which answers 0 in every state,
stays ahead of all of it: it neither takes a datagram nor the error (2.2,
2.8). `UnconnectedSocketRules` keeps its rules for a socket that
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

**A faulting receive.** Linux's takes the datagram and answers `EFAULT` (2.2).
Darwin's strips the datagram it leaves (2.2, C10), and what that does to the
mbuf budget is unmeasured. So a Darwin receive into an unmapped buffer, with
bytes to copy, is refused (`UnmodelledException`), as a faulting TCP receive
is today. A peek that faults answers `EFAULT` on both, and changes nothing.

**Flags.** Accept what section 2.14 measured, by flavour: `MSG_TRUNC` on a
receive, and Linux's ignored `MSG_OOB` on a receive. Keep refusing every
unmeasured bit, as today, rather than ignoring it as both kernels do.

### 3.7 Readiness and wakes

**Linux.**

- `socketReadinessLevel` gains IN while the queue is non-empty, and ERR while
  the error is pending, independently (2.6).
- A `poll`, `epoll_ctl(ADD)` or `epoll_wait` of a blocking socket refills its
  reader queue (2.4). So for a UDP socket, Linux's poll changes the receiver,
  as `LinuxReadiness.polled` already lets a poll change a TCP socket's send
  state.
- `SocketWake.DataArrived` already exists. A delivery raises it on the
  receiver for each datagram.
- A new `SocketWake.DatagramSent` raises an OUT edge on the sender after each
  send (G6).
- A new `SocketWake.ErrorRaised` raises ERR when the ICMP error is set (G7),
  on the socket the reply lookup chose and that holds the error, which need
  not be the sender (L16).

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

Who a datagram wakes differs by flavour, and peeking sleepers show it (S3 to
S5). **Linux** wakes exactly one sleeper per arriving datagram, the one that
parked first, whatever it then does: of three peekers, one returned. Of a
peeker parked before a taker, the peeker returned and the taker slept on, and
of the two the other way round, the taker. **Darwin** wakes every sleeper: all
three peekers returned, and so did a peeker parked before a taker.

- **(a) One primitive, `WakePrimitive.DatagramReceivable of reader`**,
  satisfied by a non-empty queue or a pending error, on both flavours.
  Several sleepers are satisfied by one datagram; the client runs one, and the
  others either find what it left (peekers) or park again. That is Darwin's
  rule outright. On Linux it is right for takers only: it would complete all
  three peekers of S3 where Linux completes one.
- **(b) Per flavour.** On Darwin, (a). On Linux, an arrival wakes the
  earliest-parked sleeper on the socket that is not already woken, by park
  ordinal (`ThreadPark.Ordinal`), and marks it woken in the kernel's wake
  state, as the W stages built. No wake queue is needed: the ordinal orders
  the parks, and a sweep finds the earliest. Whom a pending error wakes, with
  several asleep, is unmeasured (L9 has one sleeper), so U4 measures it
  first.

**Recommend (b).** (a) is observably wrong for Linux peekers, and (b) costs
one ordinal comparison over the socket's sleepers per arrival.

## 4. Staging

Each stage is a PR, green on its own, with the README changed alongside the API
it touches.

- **U0. This plan and its probes.**
- **U1. The receiver, and connected transfer through existing calls**, in
  three PRs:
  - **U1a.** `DatagramReceiver` (3.1) with both flavours' accounting (3.2), as
    pure functions, property-tested against a naive reference and replayed
    against the probe outputs embedded as resources. The machine map, made
    with a UDP socket and released with it, and its invariant. No call's
    answer changes.
  - **U1b.** The calls: `write` and `send` to a peer; `read` and `recv` of a
    queued datagram, or `EAGAIN` when non-blocking (a blocking one with nothing
    queued stays refused); `FIONREAD`; Linux readiness and wakes (3.7),
    including a blocking poll's refill; delivery by scan (3.3).
    - `MSG_TRUNC` moves to U3. Linux's makes `recv` return more than it
      copies, which `ReadAnswer` cannot say, and `recvfrom` gets an answer
      type of its own.
    - `FIONREAD` (`UnixDescriptor.bytesAvailable`, `SteppedCall.BytesAvailable`)
      now comes back with the system, since Linux's refills the reader queue.
    - A socket a Linux connect to port 0 left connected is refused as a
      receiver candidate: Linux takes a peer port of 0 as matching any source
      port, and its rank is unmeasured.
    `TestDatagramTransferAgainstHost` replays sections B to K against the
    host, and a randomised sequence of sends and takes checks the capacity
    rules there.
  - **U1c.** The ICMP error (3.5): the pending error, `SO_ERROR`, Darwin's
    four-tuple window, and what `connect` does with a pending error. Section L
    and X join the host test.
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
- **A Darwin receive into an unmapped buffer** (3.6), which strips the
  datagram it leaves: refused.

## Decisions

Patrick, 2026-10-18:

- **3.1**: (A), a machine map of datagram receivers.
- **3.2**: (A), each flavour's accounting reproduced, with (A2): an arrival at
  a Darwin queue holding 1757 datagrams is refused. **Superseded, for Patrick
  to confirm**: review found (A2) unsafe for mixed sizes, and Darwin's mbuf
  charges are now measured, so (A) models both of Darwin's budgets exactly,
  and nothing is refused (3.2).
- **3.3**: ties are refused; U1 delivers by a scan, and U2 adds the port index.
- **Staging**: as section 4, U1 to U6 in order.

Not put to Patrick, so the recommendation stands until he says otherwise:
3.8's (b), Linux's earliest-parked wake (the draft recommended (a), which S3
showed wrong for Linux); and 3.2's sysctls as
machine settings without setters.
