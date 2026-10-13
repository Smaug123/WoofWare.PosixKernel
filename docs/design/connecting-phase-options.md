# A connect in progress: `SocketPhase.Connecting`

*Design note, 2026-10-13. A follow-on to D8 (`connect-park-options.md`, which names this gap in its §2.5 and §4), approved by Patrick on 2026-10-13. Written on top of #1906, which has since merged; the PR is #1913. The facts are those that note measured (`docs/probes/connect-park/`, rows T2 and T3).*

## The gap

On Linux, a TCP connect to a listener whose accept queue is full leaves the socket in `SYN_SENT`, and it completes at a later SYN retransmit. Two calls leave it there and return:
- a non-blocking connect, which answers `EINPROGRESS` and becomes writable at the retransmit (T2, 1022 ms);
- a blocking connect interrupted by a signal without `SA_RESTART`, which answers `EINTR`. A second connect then sleeps on and completes at the retransmit (T3).

Today a socket's phase can be only `Idle`, `Listening`, `EstablishedPendingReport`, `Established`, `Refused` or `DatagramPeer`. None of these says "a connect is in flight", so both calls are refused (`ConnectRefusal.AcceptQueueFull`, and `SyscallInterruption`'s refusal). `SocketPhase` is public and complete-matched by clients, so the phase must be reserved before 1.0.

## Options

- **A (chosen): `SocketPhase.Connecting of ConnectAttempt`, with `ConnectAttempt` opaque.**
  - Its representation is internal. Today it holds the destination `SocketAddress`, which a `SYN_SENT` socket certainly has.
  - What else it will hold is unsettled: the retransmit schedule (the attempt, the next deadline), whether the error is pending, and what readiness and `SO_ERROR` report meanwhile. All of that can change later without breaking a client.
- **B: a public record**, for example `{ Destination; NextRetransmit : int64; Attempt : int }`.
  - The schedule's fields are unmeasured beyond the first retransmit at 1 s.
  - Retyping a field later breaks readers.
  - Rejected.
- **C: no phase; keep the socket `Idle` and hold the attempt in an internal table beside it.**
  - Then `Idle` would lie about a socket whose `connect` answers `EALREADY`, and whose `getsockopt(SO_ERROR)` can later report a refusal.
  - Every reader of the phase would have to consult the table too.
  - Rejected, by the architecture guideline that a classifier must stay truthful.

## Time-driven completion is free later

A `Connecting` socket completes when its retransmit deadline passes, which is readiness that changes as the clock advances. #1895 made `WakeCondition.deadlines` internal; clients read `UnixWait.deadlines`, which takes the system. So a deadline derived from a socket's state can join the client's idle jump later without any public change: `UnixWait.deadlines` can read the `Connecting` sockets' next retransmits. That is also what timerfd (D10) needs.

## While reserved

- Nothing puts a socket in `Connecting`.
- `UnixSystem.checkInvariants` reports a socket in it as a new internal defect, `UnixSystemDefect.ReservedSocketPhase`, appended in the style of `ReservedPark`. That makes "unreachable" checked wherever a fuzzer checks invariants. Removing the defect when the phase lands is free, since the defect union is internal.
- The arms that would have to answer for a connecting socket throw, naming the reserved case. These are readiness, `connect` itself, `accept`, `listen`, `getpeername`, transfers and `SO_ERROR`. An arm where a connecting socket behaves exactly as an idle one, such as closing it, treats it so. The PR counts both kinds.

## Decision (orchestrator's delegate, 2026-10-13)

Option A: reserve `SocketPhase.Connecting of ConnectAttempt`, appended, with `ConnectAttempt`'s representation internal and holding only the destination. No public accessor is added.
