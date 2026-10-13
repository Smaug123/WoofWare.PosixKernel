# Parks for a datagram transfer that sleeps: options

*Design note, 2026-10-13, at `origin/main` `55e2622d`. Design item D9 of `reserved-union-cases.md` §2.2. The probe is `docs/probes/datagram-park/datagram-park.c` on branch `pk-reserve-datagram-receive-park`, with its output on Darwin 27.0.0 (xnu-13432.1.9, arm64, uid 501) and Linux 6.18.5 (aarch64, glibc 2.41, root in Apple's `container`, `net.unix.max_dgram_qlen` 10). Linux source is 6.18.7 (`net/core/datagram.c`, `net/unix/af_unix.c`). XNU source is `apple-oss-distributions/xnu` `main` `f6217f89` (`bsd/kern/uipc_usrreq.c`, `uipc_socket.c`).*

## 0. Summary

- **Reserve `ParkedSyscall.DatagramReceive of ParkedDatagramReceive`**, with an opaque payload. A blocking receive on a datagram socket with nothing queued sleeps on both flavours, through `read`, `recv`, `recvfrom` and `recvmsg` alike. Today it is the internal refusal `ReadRefusal.DatagramSleep`, raised as `UnmodelledException`. One case covers all four calls.
- **Also reserve `ParkedSyscall.DatagramSend of ParkedDatagramSend`**, with an opaque payload. Measured: a blocking Unix-domain datagram send **sleeps on Linux** when the receiver's queue or the sender's buffer is full. A UDP send never sleeps on either flavour, and a Darwin Unix-domain send fails with `ENOBUFS` instead. Unix-domain sockets are on #1726, and Patrick put their API in 1.0 (2026-10-10).
- **Both payloads are opaque.** Their representation is internal and holds only the open file description the call was made through. Nothing designs the datagram data path yet. The tcp byte-transfer plan, `docs/plans/2026-10-07-tcp-byte-transfer.md`, covers connected TCP alone. So the call vocabulary, the source-address and control-message destinations and `MSG_TRUNC` are all unsettled.
- **No `WakePrimitive` is reserved.** On Linux a datagram wakes one sleeping receiver, while an error or a shutdown wakes them all. That may become one primitive or two, as a pipe's read has two. The send side waits on two different queues. Neither design is settled.

## 1. What was measured

| row | Linux 6.18.5 | Darwin 27.0 |
| --- | --- | --- |
| R1: an unconnected, bound UDP socket; `read`, `recv`, `recvfrom`, `recvmsg`; a datagram at 100 ms | each sleeps, and returns 5 at 100 ms | the same |
| R2: UDP and Unix-domain socketpair `recv`; a caught signal at 100 ms; a datagram at 300 ms | `EINTR` without `SA_RESTART`. With it, **restarts** and returns 5 at 300 ms | the same |
| R3: UDP `recv`; another thread closes the only descriptor at 100 ms; a datagram at 300 ms | **sleeps on** and returns the datagram at 300 ms: the call keeps the socket | **`EBADF` at the close** |
| R4: UDP `recv`; `shutdown(SHUT_RD)` at 100 ms | **0 at 100 ms** | sleeps on (a signal at 600 ms ends it) |
| R5: Unix-domain socketpair `recv`; the peer closes at 100 ms | sleeps on | sleeps on |
| R6: `SO_RCVTIMEO` 200 ms | `EAGAIN` at 200 ms | `EAGAIN` at 200 ms |
| S1: UDP `sendto` a bound socket nobody reads, for 1 s | never sleeps (200 000 sent in 0.1 s; the rest dropped) | never sleeps (183 298 sent in 1 s) |
| S2: Unix-domain socketpair `send`, the peer reading nothing | **sleeps** after 278 datagrams of 100 bytes (send buffer) | `ENOBUFS` after 32 |
| S3: unconnected Unix-domain `sendto` a bound socket nobody reads | **sleeps** after 11 (the receive queue is past `max_dgram_qlen` 10) | `ENOBUFS` after 32 |
| S4: S2 and S3 asleep; a caught signal at 100 ms; the receiver drains at 300 ms | `EINTR` without `SA_RESTART`. With it, **restarts** and sends at 300 ms | never sleeps: `ENOBUFS` at once |

From the source:
- **Linux receive.** `__skb_wait_for_more_packets` (`net/core/datagram.c:89`) waits with `prepare_to_wait_exclusive` on the socket's queue, so a datagram wakes one sleeper. It ends early for a pending socket error, and for `RCV_SHUTDOWN`, which answers 0 (R4). Its signal answer is `sock_intr_errno`: `-ERESTARTSYS` with no timeout, so it restarts under `SA_RESTART` (R2), and `EINTR` under `SO_RCVTIMEO`.
- **Linux send.** `unix_dgram_sendmsg` (`net/unix/af_unix.c:2097`) waits in `unix_wait_for_peer` (`:1624`, exclusive on the receiver's `peer_wait`) while the receiver's queue is longer than its backlog, unless the receiver is connected back to the sender (`:2269`). Otherwise it waits for half the send buffer to be free, in `sock_alloc_send_pskb` (S2). That is why S4 drains the whole queue: one datagram read does not wake it.
- **Darwin.** `uipc_send` for `SOCK_DGRAM` drops the message and fails when the receiver has no room ("we will lose messages for the SOCK_DGRAM case when the receiver's queue overflows", `uipc_usrreq.c:566`), so it never sleeps (S2–S4). `soreceive` sleeps in `sbwait`, and a close drains it with `EBADF`, as Darwin's close ends a blocking connected read (R3; `SleepTarget.EndedByClose`).

## 2. What the measurements mean

1. **The receive park is certain, and one case serves every receiving call** (R1). Today it is a refusal (`ReadRefusal.DatagramSleep`, reached through `read`). A datagram socket can be created, bound and connected, so a datagram transfer is a feature the model already implies. Once datagrams move, the refusal becomes a sleep (`reserved-union-cases.md` §2.2, D9: "certain with the socket data path").
2. **A send can sleep, but only a Linux Unix-domain datagram send** (S1–S4). The feature is Unix-domain socket behaviour. #1726 plans it post-release, and Patrick put its *API* in 1.0. A park is API. A UDP send never parks, so its absence would not be noticed until Unix-domain datagrams land, and then adding a case would break clients. It meets the audit's bar for "certain" (the roadmap plans the behaviour), so I reserve it. Removing it before 1.0, if Patrick disagrees, costs nothing.
3. **Neither park's fields are settled.**
   - The receive must say which call it is and where the source address goes: `recvfrom`'s `sockaddr` and length cell, and `recvmsg`'s `msghdr`, control buffer and flags out. It must also say whether `MSG_TRUNC` or `MSG_PEEK` apply.
   - On Darwin a close ends it (R3). Linux's close leaves it asleep, holding the socket.
   - The send must hold the datagram's destination, for `sendto` to a bound path, and which of Linux's two waits it is in.
   - None of that is designed. `ParkedConnectionRead`'s `Count` and `Call : TcpReceiveCall` are stream-shaped.

   So the payloads are opaque, as `reserved-union-cases.md` asks, and as `FifoAttachment` and `ParkedSelect` are.
4. **The restart rule is measured.** A receive restarts under `SA_RESTART` on both flavours (R2), and so does a Linux send (S4). A Darwin send never parks, and by `ruleOf`'s convention it is answered as the flavour that makes it.
5. **What the park holds is measured for Linux.** The call keeps the socket's description alive across a close (R3), so `ParkedSyscall.descriptions` answers it. Darwin's close ending the call will need an "ended" state, as `SleepTarget.EndedByClose` is for a connected read. The internal representation can gain it later.

## 3. Options

### Option A (chosen): two cases of their own, opaque payloads, no primitive

```fsharp
type ParkedDatagramReceive = internal { Socket : OpenFileDescriptionId }
type ParkedDatagramSend = internal { Socket : OpenFileDescriptionId }

// appended to ParkedSyscall:
    | DatagramReceive of ParkedDatagramReceive
    | DatagramSend of ParkedDatagramSend
```

- `descriptions` answers `[ Socket ]`.
- `ofPark` answers a signal alone, since no primitive exists for it to wait on yet. It is unreachable.
- `ruleOf` answers `RestartsUnderSaRestart` (R2, S4).
- `close`, `flock` and the exclusive-queue sweep treat these cases as they treat `Sleep`.
- `checkInvariants` reports a task parked in either as `ReservedPark`.
- Cost: two more arms in each match over parks, and two parks a client cannot pattern-match into.

### Option B: reuse `ConnectionRead` and `ConnectionWrite`

Widen their docstrings to datagram sockets, and add no case.
- `ParkedConnectionRead.Call : TcpReceiveCall` (`Read | Receive | Peek`) cannot name `recvfrom` or `recvmsg`. Its `Count` is a stream's "most bytes the call takes", where a datagram receive takes one datagram whole or truncated. So the public record's fields would be retyped. That breaks every reader, PawPrint's `GuestLocation` and `DebuggerServer` among them.
- It puts two transfer models behind one record.
- `ConnectionReadable`'s documented rule is that every reader wakes. That is not Linux's rule for a datagram.

Rejected.

### Option C: two cases with public records

For example `{ Socket : SleepTarget<SocketId>; Buffer; Count; Call : DatagramReceiveCall; Source : UserBuffer option }`.
- Fields could later be added without breaking readers (`nanosleep-options.md` §3.3).
- But the call vocabulary, and the shape of `recvmsg`'s destinations, would probably be *retyped*, which does break readers. They depend on a data-path design that does not exist.

Rejected, in favour of A's opacity.

### Option D: the receive alone

Reserve the receive and leave the send to the minor-version policy.
- This is defensible if Unix-domain datagram behaviour is not counted as certain.
- But S2–S4 show the sleep is real on Linux, and the feature is on the roadmap.
- A later case would break every client that matches `ParkedSyscall` in full, which PawPrint does in four places.

Rejected, but it is the fallback if Patrick does not count Unix-domain datagrams as certain.

## 4. Reservation PR

- `UnixTask.fs`: the two payload types (internal representation), and the cases, appended after `ParkedSyscall.Select` if D3 lands first, or after `InotifyRead` otherwise.
- Library arms, as for `Sleep`:
  - `descriptions`;
  - `withPark`'s `kind`;
  - `ofPark`;
  - `ruleOf`, citing R2 and S4;
  - the exclusive-queue sweep;
  - `UnixDescriptor`'s `flock` and `close` arms;
  - `UnixReadWrite`'s `waitingWriter`;
  - `WakeCondition`'s ended-by-close check;
  - `checkInvariants`' `ReservedPark` row.
- PawPrint arms: `GuestLocation`, `DebuggerServer`, and the four in `NativeSystemNative`.
- Tests:
  - `TestDatagramPark`: the readers' answers over random descriptions, and `ReservedPark`.
  - The test arms.
  - Mutation checks: park a blocking datagram read as `DatagramReceive` instead of refusing it, and watch a property fail. Drop the `ReservedPark` rule, and watch the unit test fail.
- README: the reserved-case list and the park paragraph. `ReadRefusal.DatagramSleep` stays: it is internal, and the read still refuses.

## Decision (orchestrator's delegate, 2026-10-13)

- **Option A.** Reserve `ParkedSyscall.DatagramReceive` and `ParkedSyscall.DatagramSend`, each with a payload whose representation is internal, holding the description the call was made through and holds.
  - The receive covers `read`, `recv`, `recvfrom` and `recvmsg` on any datagram socket, UDP or Unix-domain, connected or not (R1, R2).
  - The send covers a Linux Unix-domain datagram send (S2–S4). A UDP send never parks (S1), and a Darwin Unix-domain send fails with `ENOBUFS`.
- **No primitive.** Whether Linux's wake-one datagram arrival and wake-all error or shutdown are one primitive or two belongs to the data-path design, as does the send's pair of waits.
- **For Patrick:** reserving `DatagramSend` rests on counting Unix-domain datagram behaviour as certain. If he does not, drop it before 1.0 (option D), which is free until then.
