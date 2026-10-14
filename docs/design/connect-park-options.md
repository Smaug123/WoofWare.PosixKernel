# A `connect` that sleeps: options

*Design note, 2026-10-13, at `origin/main` `628a80d7`. Design item D8 of `reserved-union-cases.md` §2.2. Patrick chose the shape (option B below) on 2026-10-13, after the audit: `UnixConnection.connect` takes the calling task and answers `SyscallOutcome` now, as #1855 did for `openat`, rather than refusing a blocking connect to a full listener until 2.0. This note records the facts behind that decision, and settles what the reservation holds. The probe is `docs/probes/connect-park/` on branch `pk-reserve-connect-park`: `connect-park.c` and `fill.c`, with their output on Darwin 27.0.0 (xnu-13432.1.9, arm64, uid 501) and Linux 6.18.5 (aarch64, glibc 2.41, root in Apple's `container`, `tcp_syn_retries` 6, `tcp_abort_on_overflow` 0, `tcp_syncookies` 1). Linux source is 6.18.7, XNU `apple-oss-distributions/xnu` `main` `f6217f89`.*

## 0. Summary

- **Shape (decided):** `connect task fd destination declaredLength copied system : SyscallOutcome * UnixSystem<_, _>`. `ConnectOutcome` goes: its two cases are `SyscallOutcome.Answered (SyscallAnswer.Completed 0L)` and `Answered (SyscallAnswer.Failed e)`. Every connect still answers at once.
- **Reserve `ParkedSyscall.Connect of ParkedConnect`**, with an opaque payload holding the connecting socket's description. **Reserve `WakePrimitive.AcceptQueueHasRoom of listener : SocketId`.**
- **The TCP retry reuses `DeadlinePassed`.** Measured on Linux, a blocking TCP connect to a full listener completes at its next SYN retransmit (1 s in), not when room appears (200 ms in).
- **No `InProgress` answer is needed.** The model already answers a non-blocking connect `Failed EINPROGRESS` and latches the result on the socket's phase.
- **What the shape still lacks, and why I do not reserve it:** a *connecting* `SocketPhase`.
  - A non-blocking Linux TCP connect to a full listener, and a blocking one that a signal interrupts, both leave the socket in `SYN_SENT`. It then completes on its own at a later retransmit.
  - That is readiness changing because time passed. The model cannot express that today, and it is the same open question as timerfd (D10).
  - So I do not count the case as certain. Both paths stay refused.

## 1. What was measured

The listener's queue is filled with one connection first: Linux `listen(fd, 0)` admits one, as the model says. Then a second connect is made.

| row | Linux 6.18.5 | Darwin 27.0 |
| --- | --- | --- |
| T1: TCP, blocking; the filler accepted at 200 ms | **sleeps**; completes at **1011 ms**, the first SYN retransmit | **never sleeps**: completes at once, or `ECONNRESET` at once (3 runs: 1 of 3 reset) |
| T2: TCP, non-blocking, the same | `EINPROGRESS`; writable at 1022 ms, `SO_ERROR` 0 | `EINPROGRESS`; writable at once, `SO_ERROR` 0 or `ECONNRESET` |
| T3: TCP, blocking; a caught signal at 100 ms; accept at 300 ms | without `SA_RESTART`: `EINTR` at 100 ms, and a second `connect` sleeps on and completes at the retransmit. With it: **restarts**, completes at 1024 ms | completes at once |
| T4: TCP, blocking; the listener closed at 200 ms | `ECONNREFUSED` at 1023 ms (the retransmit meets a reset) | completes at once, or `ECONNRESET` |
| `fill.c`: TCP `listen(1)`, `listen(2)`, eight blocking connects, nothing accepting | (not run) | **no connect sleeps**. Past the queue, each completes or answers `ECONNRESET` (`listen(1)`: #3 and #7 reset; `listen(2)`: #6 and #7 reset) |
| U1: Unix-domain stream, blocking; the filler accepted at 200 ms | **sleeps**; completes at **203 ms** | `ECONNREFUSED` at once |
| U2: the same, non-blocking | `EAGAIN` | `ECONNREFUSED` |
| U3: blocking; a caught signal at 100 ms; accept at 300 ms | without `SA_RESTART`: `EINTR`, and a second connect sleeps until the accept. With it: **restarts**, completes at 304 ms | `ECONNREFUSED` at once |
| U4: blocking; the listener closed at 200 ms | **`ECONNREFUSED` at 205 ms** | `ECONNREFUSED` at once |

From the source:
- **Linux TCP.** `tcp_conn_request` drops a SYN while `sk_acceptq_is_full`. So the client sits in `SYN_SENT` and retransmits on its timer: 1 s initially (`TCP_TIMEOUT_INIT`), doubling, and `ETIMEDOUT` after `tcp_syn_retries`. A blocking `inet_stream_connect` sleeps in `inet_wait_for_connect` until the state leaves `SYN_SENT`. That is T1: room at 200 ms is not seen until the retransmit at 1 s.
- **Linux Unix-domain.** `unix_stream_connect` (`net/unix/af_unix.c:1720`) answers `EAGAIN` without a timeout. Otherwise it waits in `unix_wait_for_peer` (`:1624`), exclusively on the listener's `peer_wait`, until the queue has room, or the listener is dead or shut down. It then restarts the lookup, which answers `ECONNREFUSED` for a dead listener (U4). Its signal answer is `sock_intr_errno`: `-ERESTARTSYS`, so it restarts under `SA_RESTART` (U3).
- **Darwin TCP.** When the queue overflows, `tcp_input` evicts an embryonic or queued connection (`tcp_dropdropablreq`) or resets the new one. Which one it picks is not a function of anything this model holds. So `ConnectRefusal.AcceptQueueFull` stays the answer under Darwin.
- **Darwin Unix-domain.** `unp_connect` answers `ECONNREFUSED` when `sonewconn` cannot queue (U1–U4). It never sleeps, so it needs no park once Unix-domain connects are modelled.

## 2. What the measurements mean for the reservation

1. **Two calls sleep, both on Linux alone.**
   - **TCP** sleeps on a timer: its condition is `AnyOf [DeadlinePassed retransmit; SignalDeliverable]`. At each retransmit the finishing call checks for room, and then either completes or parks again with the next deadline.
   - **Unix-domain** sleeps on the listener: `AnyOf [AcceptQueueHasRoom listener; SignalDeliverable]`.

   One park serves both, because only the call knows which it is. The TCP retry needs no new primitive.
2. **The primitive names the listener by `SocketId`.** The connecting call holds the listener's *socket* (`unix_find_other` takes a reference), not a description of it, so no `OpenFileDescriptionId` names it. `SocketId` is the machine's identity for a socket, as `SleepTarget.EndedByClose` and kqueue registrations use it. The primitive must also hold once the listener is gone or shut down, since that wakes the sleeper to be refused (U4). That is a rule about its evaluation, not about its field.
3. **The park's payload is not settled.**
   - TCP must hold the retransmit schedule: the attempt, the next deadline, and the destination.
   - Unix-domain must hold the listener, and the name it looked up, since the call restarts the lookup.

   So the payload is opaque, holding for now only the connecting socket's description. The call holds that description for its duration, by `fdget` on Linux, as every syscall does with the descriptor it names.
4. **Restart rule:** `RestartsUnderSaRestart` on Linux, for TCP (T3) and Unix-domain (U3). A Darwin connect to a full listener never sleeps, so by `ruleOf`'s convention it is answered as Linux's.
5. **`EINPROGRESS` is already answered.** It is `SyscallAnswer.Failed EINPROGRESS`, with the completion latched on the phase (`UnixConnection.fs`, "the syscall itself still answers EINPROGRESS"). A non-blocking connect to a full Linux TCP listener needs more than an answer, though. The socket stays in `SYN_SENT` and completes at a retransmit that nothing waits on: readiness changing with the clock. The same holds after an interrupted blocking connect (T3: the second connect finds the connection still in progress). Modelling either needs a connecting `SocketPhase` *and* time-driven readiness. The second is D10's open question, so neither is certain, and neither is reserved. Until then the implementation refuses both. The non-blocking one is `AcceptQueueFull` as today. The interrupted one is refused when the signal arrives without `SA_RESTART`, through `SyscallInterruption`'s existing refusal.

## 3. Options

### Option A: keep `connect`'s shape, and refuse for ever

`ConnectRefusal.AcceptQueueFull` stays. Patrick rejected this. Whether a connect meets a full queue depends on the schedule, so the refusal would appear in some runs of a program and not others, the reason #1855 gave for `openat`.

### Option B (Patrick's choice): `connect` takes the task and answers `SyscallOutcome`; reserve the park and the primitive

- `UnixConnection.connect task fd destination declaredLength copied system : SyscallOutcome * UnixSystem<_, _>`, with `tryConnect` the same internally. `ConnectOutcome` is deleted, since nothing would answer it.
- The task is checked as `openat` checks it since #1855: a parked task, or a name that is not a task, fails loudly.
- `ParkedSyscall.Connect of ParkedConnect` (internal representation `{ Socket : OpenFileDescriptionId }`):
  - `descriptions` answers `[ Socket ]`;
  - `ofPark` answers a signal alone while it is reserved;
  - `ruleOf` answers `RestartsUnderSaRestart`;
  - the exclusive-queue sweep answers none;
  - the arms for `close` and `flock` treat it as they treat `Sleep`;
  - `checkInvariants` reports a task parked in it as `ReservedPark`.
- `WakePrimitive.AcceptQueueHasRoom of listener : SocketId`. It is contained in no condition yet. `satisfied` fails loudly for it, as for `FifoPartnerOpened`. `UnixWait`'s exclusive-queue sweep answers none for it today. Linux's `peer_wait` is exclusive, which the implementation will model.
- PawPrint: `SystemNative_Connect` passes the guest thread and fails loudly on `WouldBlock` and `Restarts`.
- Tests: every connect call site asserts `Answered`, as #1855's open tests do, through a `ConnectOutcomes` helper. There is a test that a parked task or a stranger fails loudly, and the reserved-park and primitive tests.

### Option C: as B, with a `ConnectOutcome.WouldBlock` case instead of `SyscallOutcome`

This keeps the connect-specific union and adds the case. But `SyscallOutcome` already says "answered, or sleeps on this condition, or restarts". `flock`, `openat` and the generic `step` use it, and a client's driver loop is written once against it. A per-call union duplicates it. Rejected.

## 4. What the reserved shape covers and lacks

| case | covered by the reservation | lacking |
| --- | --- | --- |
| Linux TCP, blocking, full queue | yes: park, `DeadlinePassed` at each retransmit, finish re-checks | the retransmit schedule (internal payload); a connecting phase if a signal interrupts it without `SA_RESTART` (refused meanwhile) |
| Linux TCP, non-blocking, full queue | `EINPROGRESS` is answerable today | a connecting phase that completes with the clock (D10's question); stays `AcceptQueueFull` |
| Linux Unix-domain stream, blocking | yes: park, `AcceptQueueHasRoom`, `ECONNREFUSED` once the listener goes | Unix-domain connects themselves (post-release; refused today as an unmodelled domain) |
| Linux Unix-domain stream, non-blocking | `EAGAIN`, an ordinary answer | — |
| Darwin TCP | nothing sleeps | the eviction or reset is not decidable from model state; stays `AcceptQueueFull` |
| Darwin Unix-domain | nothing sleeps: `ECONNREFUSED` | — |

## Decision (Patrick, 2026-10-13; details by the orchestrator's delegate)

- **Option B**, as Patrick chose. `ParkedSyscall.Connect` has an opaque payload. `WakePrimitive.AcceptQueueHasRoom of listener : SocketId` is reserved. `ConnectOutcome` is deleted.
- **The TCP retry is `DeadlinePassed`.** No primitive for it.
- **No `InProgress` case.** `EINPROGRESS` is already a `Failed` answer.
- **No connecting `SocketPhase`** reserved, since it waits on time-driven readiness (D10). Recorded here for Patrick, since it is the one certain-looking gap the shape leaves: a Linux TCP connect interrupted, or made non-blocking, against a full listener.

## Amendment (orchestrator's delegate, 2026-10-13): combining with #1904's pause for the copy-in

#1904 merged first. It made `connect` stop where the kernel copies the caller's `struct sockaddr` in, as the plan `docs/plans/2026-10-13-copy-in-pauses-and-process-fate.md` describes:
- `connect fd address declaredLength system` answers `CallProgress<PausedConnect, ConnectOutcome * UnixSystem>`;
- `connectWithAddress copied paused` finishes it;
- `PausedConnect` is opaque, and holds the system the call was made in.

Both changes are to `connect`'s shape, so they combine as follows.

- **The task is passed to the first call only.** It is `connect task fd address declaredLength system`. The paused value holds the task, as it already holds the system, so `connectWithAddress copied paused` takes no task. A resume therefore cannot name a different task from the one that made the call.
- **The parked-task check runs in the first call, before anything else.** The paused value holds the system as it was then, so the task is still unparked when the call resumes. No second check is needed.
- **Both ends answer `SyscallOutcome * UnixSystem`.** These are:
  - `CallProgress.Answered` from `connect`, for a call answered before the copy;
  - the result of `connectWithAddress`.

  This keeps #1904's law that `Answered` carries the same type a resume answers. The one connect that will sleep (to a full listener) is decided after the copy, so it is `connectWithAddress` that will answer `WouldBlock`. That is why the paused value must carry the task.
- **`ConnectOutcome` is deleted**, as before.
- **The internal step `tryConnectBytes` still answers `SyscallAnswer * UnixSystem`.** A private `finishConnect task …` lifts it to the outcome, and is where the park will be made. The step is internal, so how it reaches the park can change freely.
- **Tests.** #1904's helper approach is kept: `CopyIn.connectAs task` makes the call through the public pause-and-resume path. It fails unless that agrees with the internal steps (admitting the copy, then `tryConnectBytes`), and fails if the call sleeps. `CopyIn.connect` is `connectAs` the leader. The tests that probe the internal step directly keep calling `tryConnectBytes`.
