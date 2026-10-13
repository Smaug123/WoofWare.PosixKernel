# Waiting in WoofWare.PosixKernel: deadlines, and the calls that sleep

*Options document, 2026-09-26. Part of the "PosixKernel knows nothing of the CLR" workstream.*

## 1. What there is today

- **Two kinds of park, both without time.**
  - `ParkedSyscall = SocketWait | Flock`, and `WakeCondition = FlockGrantable | SocketEventDeliverable`.
  - `SyscallOutcome.WouldBlock of WakeCondition` is how a call says "the caller sleeps".
  - Neither park has a deadline, and `WakeCondition`'s own docstring promises one ("advance the virtual clock to the nearest deadline") that no case carries.
- **flock is library-shaped; the epoll wait is not.**
  - `flock` returns `WouldBlock`, records the park, and finishes through `flockAcquire`.
  - The epoll wait is assembled by PawPrint (`NativeSystemNative.fs`, `SystemNative_WaitForSocketEvents`): `admitSocketWait`, then `drain`, then building `ParkedSyscall.SocketWait` itself, then `withParked`, then re-entry through `parkedFor`, then clearing the park.
  - Its only timeout is the shim's `-1`.
- **Every other sleeping call is refused.**
  - `poll` with any nonzero timeout gives `PollRefusal.WouldPark`.
  - A blocking `accept` gives `AcceptRefusal.WouldPark`.
  - There is no `nanosleep`, `select` or futex.
- **Time.**
  - The kernel owns `NanosecondsSinceBoot`. PawPrint advances it as it retires instructions.
  - When nothing is runnable, PawPrint jumps it to the nearest deadline (`Program.advanceUntilRunnableOrQuiescent`), and `ClockJitter.EagerDeadlines` may jump ahead of a deadline or overshoot it.
  - The deadlines it considers are all PawPrint's own: CoreCLR-level thread states (monitor and sync-block waits, wait handles, `Join`, `Sleep`) carrying a deadline in 100 ns ticks. No kernel park can contribute one.
- **Wakeups are pulled, not pushed.**
  - Every tick, PawPrint asks `WakeCondition.isSatisfied` of every parked task (`fireSyscallWakes`). That is deliberate: a producer can't forget to wake anyone.
  - Several threads parked on one epoll instance are refused, because Linux wakes exactly one of them by park order, which nothing records.

## 2. What a kernel does
To be measured on both flavours before stage 2; these rows are from source reading and man pages.

- **Units.** `poll`, `epoll_wait` and `select` take a *relative* timeout, which Linux turns into a `CLOCK_MONOTONIC` deadline. `epoll_pwait2` and `ppoll` take a `timespec`.
- **Expiry.** An expired wait returns 0. A signal interrupts it with EINTR, which is stage 6 of the signals plan.
- **Negative timeouts.** Measured 2026-09-26 (`poll-timeout.c`): every negative timeout (−1, −2, −3, −1000, `INT_MIN`) is infinite on Linux 6.18.5 *and* on Darwin 27.0.0; Darwin 27 does **not** answer EINVAL below −1, which this row used to claim from older man pages.
- **Blocking `accept`.** It waits for the accept queue to become non-empty. `SO_RCVTIMEO` bounds it, giving EAGAIN.
- **Slack.** A real timeout fires *at or after* its deadline; timer slack defaults to 50 µs for normal tasks. In a simulator, "exactly at the deadline" is one legal outcome and "after it" is a scheduling choice. That choice belongs to the client's scheduler, which already models overshoot.

## 3. Options

### A. A deadline field on each park record
- **Shape.**
  - Every `ParkedSyscall` case gains `Deadline : int64 voption`, in monotonic nanoseconds.
  - `WakeCondition` stays event-only.
  - A new `check park system` answers `Ready | TimedOut | NotYet`.
  - `UnixTaskTable.nextDeadline` feeds the client's idle jump.
- **Cost.** Small. Each parking syscall adds a field and a finishing arm.
- **Weakness.** `poll` waits on *any of several* descriptors, *or* a deadline. A later signal interruption adds "or a signal is deliverable". A waits on one thing plus time, so each of those grows its own case and its own ad-hoc disjunction. The operation set stops being enumerable.

### B. A small algebra of wake conditions (recommended)
- **Primitives:**
  - `FlockGrantable`;
  - `EpollReady of instance`;
  - `DescriptorReady of description * events`, for `poll`;
  - `AcceptQueueNonEmpty of listener`;
  - `DeadlinePassed of ns`;
  - later, `SignalDeliverable of task`.
- **One combinator:** `AnyOf of WakeCondition list`, which must be non-empty.
- **Evaluation.** `isSatisfied` becomes `satisfied : WakeCondition -> UnixSystem -> Primitive list`. The finishing call learns *which* primitive fired: an event, a timeout, or later a signal.
- **Deadlines as data.** `deadlines : WakeCondition -> int64 list` is what the client's idle jump and `ClockJitter` read. With this, the docstring's promise is finally true.
- **Records unchanged in role.** `ParkedSyscall` still carries the per-syscall state the finishing call needs (`maxevents`, `poll`'s descriptor list), and `WakeCondition.ofPark` still derives the condition from the record. The two can't disagree, as today.
- **Laws, which property tests can state against an oracle.** `AnyOf` is associative and idempotent, and an `AnyOf` of one element equals that element. `satisfied (AnyOf cs) = concat (map satisfied cs)`. `DeadlinePassed t` holds iff the clock is at or past `t`.
- **What it unlocks.** `poll` with a timeout, `epoll_wait` with a timeout, blocking `accept` and `nanosleep` all become a condition plus a finish. Signal interruption (signals stage 6) is one new primitive, not a change to every park.
- **Cost.** A reshape of `WakeCondition` and `fireSyscallWakes`. It is additive for the existing two parks: each is an `AnyOf` of one.

### C. The kernel owns wait queues and pushes wakeups
- **Shape.** The library keeps wait queues and a timer queue, and returns explicit wake lists. `advanceClock` returns the tasks whose timers expired, and each syscall that makes a condition true returns whom it woke.
- **Strength.** It matches a real kernel's structure, and the queue order makes epoll's exclusive one-waiter wakeup modelable.
- **Cost.** A push model, which is exactly what `fireSyscallWakes`' design rejects, because one forgetful producer is a silent deadlock. The library would also hold waiter state that duplicates the client's thread statuses. It has the largest blast radius, and is the hardest to undo.

## 4. Decision: B, plus park order

B is chosen. Its operation set is enumerable and its laws are testable. It keeps the pull model, and every sleeping call and the signal interruption become instances of it rather than new mechanisms.

**Park order,** so that epoll's exclusive wakeup can be modelled later without C:
- each park records a monotonically increasing sequence number, which is kernel state;
- a library function over the task table then answers "which waiters does this satisfied condition wake": all of them for `flock`, and for an epoll instance the **last-parked** (LIFO), measured 2026-09-26 by `epoll-wait.c` on Linux 6.18.5 (60/60 trials over all six park orders; a waiter that waits again is woken first). The plan's original "earliest-parked" was an assumption, and wrong;
- so the kernel decides who wakes, and the client still pulls.

**Deadlines** are in the kernel's own monotonic nanoseconds (`NanosecondsSinceBoot`). PawPrint converts them to its ticks with `ClockPal` when it merges them with its own CoreCLR-level deadlines. Firing *exactly* at the deadline is the library's answer; overshoot is the client's jitter, as today.

**Out of scope:** PawPrint's CoreCLR-level waits (monitor, `Sleep`, wait handles). These are the runtime's own synchronisation, above the kernel. Re-expressing them as futex and `nanosleep` is a separate unification, and nothing here depends on it.

## 5. Stages (one PR each)
1. **The algebra.** `WakeCondition` primitives, `AnyOf`, `DeadlinePassed`, `satisfied`, `deadlines`, and the park sequence number. The two existing parks become one-element `AnyOf`s. PawPrint's sweep reads `satisfied`, and its idle jump merges the kernel's deadlines, of which there are none yet, so behaviour is unchanged. Property tests of the laws.
2. **`poll` with a timeout,** after measuring timeout, expiry and negative-value semantics on both flavours. `PollRefusal.WouldPark` is lifted. The BCL's `Socket.Poll(microseconds)` reaches this through `SystemNative_Poll`, so it can be tested end to end with a guest.
3. **`epoll_create1` and `epoll_wait` as library entry points,** with a timeout. The library takes over the admit, drain, park and finish that PawPrint assembles. PawPrint's shim wait passes -1. Park order makes the one-waiter rule modelable; model it or keep refusing, as measurement decides. This is the start of the epoll/kqueue redesign, and it follows the `epoll_ctl` bits PR.
4. **Blocking `accept`** (`AcceptQueueNonEmpty`), with `SO_RCVTIMEO` refused until modelled.
5. **`nanosleep`/`clock_nanosleep`,** only once a client needs them.
6. **Signals stage 6:** `SignalDeliverable` joins the algebra, and a parked call's finish answers EINTR or restarts, per the measured table.

## Decision, stage 3 (orchestrator, 2026-09-27)

Exclusive epoll wakeup is modelled as measured: an event wakes the last-parked asleep waiter on its port, and nobody else on that port while a woken waiter has yet to finish. Because the pull design sees states rather than wakeup signals, this under-approximates: when a second signal arrives while the first woken waiter is still pending, a real kernel wakes a second waiter, and the model answers only the schedule in which the first waiter runs first. Every answer is one a real kernel gives (F3 matched in 50/50), so it is sound but not complete. Accepted over keeping the refusal; counting signals per port would be the push model this design rejected.

## Decision, kqueue registration (orchestrator, 2026-10-02)
#1685 made `kqueue()` and the wait half of `kevent()` library entry points, with registration refused. For registration: **A**. Store registrations in `KqueueState`, keyed by (ident, filter), with EV_CLEAR only (other flags refused), udata, and an activation queue. EVFILT_READ/WRITE readiness comes from the existing socket level, activated at the producer points epoll already hooks; a registration is removed when its descriptor closes. Rejected: B, sharing epoll's interest table (per-filter keys, a replacing re-ADD and removal on close all differ); C, a general filter algebra (speculative). Needs Darwin measurements first: per-producer activation, EV_EOF and `data`, EV_RECEIPT with a full eventlist, delivery order, re-ADD, and file targets.

## Amendment, kqueue registration (orchestrator, 2026-10-02)
The implementation (branch kernel-kevent-register) supports registrations without EV_CLEAR (level-triggered) as well, because they were measured; "EV_CLEAR only" above is superseded. Readiness for kqueue is Darwin's own `DarwinReadiness`, a function of the socket phase, because Linux's `ReadinessLevel` gets the idle, refused and FIN rows wrong for Darwin. An EVFILT_WRITE event's `data` (the send buffer's free space) is a typed unknown, `SendBufferSpace`. Decision on the bytes the shim leaves unconverted in a single WRITE event: **D**, keep the caller's old bytes and document it, until PawPrint can mark bytes indeterminate (option A, which overlaps the poison-values work). B (send space as configuration) would go wrong once a send path and autotuning exist; C (refuse) would break managed async connect.

## Amendment 2, the WRITE event's `data` (orchestrator, 2026-10-02, after a Codex P2 on #1694 that Patrick forwarded)
Decision D, which kept the caller's old bytes, is **withdrawn**.
- **Why.** It is neither a refusal nor the truth. A guest reading offset 16 sees stale bytes where real .NET sees a positive send-buffer space, which is what the kernel skill's §5 ("refuse rather than invent") forbids.
- **Why "unknown" was wrong.** D rested on the free space being unknowable, but in every state this kernel can reach, it is determined:
  - there is no send path, so nothing is ever queued;
  - `SO_SNDBUF` is refused by both `setsockopt` and `getsockopt`, so the high-water mark is always its initial value.
- **New decision, E.** Model the free space exactly: the initial send buffer's size, as measured, for an established TCP socket over IPv4 and IPv6 on both its client and accepted ends, plus the measured 2048 for a refused connect.
  - The initial size is a machine fact: Darwin's `net.inet.tcp.sendspace`. It becomes configuration with a measured default, unless measurement shows a loopback-specific rule.
  - **First:** explain the refused 2048 from XNU's source, or at least show it doesn't vary with the configured size. If it can't be pinned, a refused socket's WRITE `data` stays a typed unknown, and the PawPrint adapter **refuses** to convert it (`failwith` naming the condition). Managed connect reads the event's flags, not this data, but a stale value must never be served.
- **Structure.** The library computes the space from the socket's send-buffer state, so the PR that adds a send path or `SO_SNDBUF` has to replace a single function.
- **What this supersedes.** B was rejected earlier because "autotuning will make it wrong once a send path exists". That remains true, but autotuning is the send path's problem, and it should refuse there, not here.
- **A remains the long-term answer** for anything genuinely unknown, once the poison-values work (#1577) lands.
- **Outcome (commits 250ea354 and cb20118b on #1694).** The rule turned out to be specific to loopback. During the handshake, `sb_hiwat` becomes `max(route sendpipe, sendspace)`, rounded up to whole segments of lo0's MTU less the headers (16332 over IPv4, 16312 over IPv6), and capped at `kern.ipc.maxsockbuf`. Measured values: 146988 over IPv4 and 146808 over IPv6, at both ends.
  - **Configuration.** The send space is `UnixMachineState.TcpSendSpace`, with a default of 131072 on Darwin.
  - **Refused setter values.** `withTcpSendSpace` refuses three kinds of value:
    - Darwin values below 49152, because the route to 127.0.0.1 has a sendpipe of 3 × LOMTU and this kernel models no routes;
    - values above `maxsockbuf`, which Darwin itself refuses with ERANGE;
    - any configured Linux value, since nothing reads it.
  - **A refused connect reports 2048** because of `tcp_attach`'s `sb_preconn_hiwat`, which only a completed connect clears; the value is `min(size, 2048)`. It does not depend on the configured send space.
  - **What changed in the types.** `KqueueEventData` and `SendBufferSpace` are deleted. PawPrint now writes every byte of the kevent image.
