# What a kqueue registration may name, before 1.0

*Row D6 of `reserved-union-cases.md` §2.2, for #1726. 2026-10-13, at `origin/main` `55e2622d`, in worktree `.claude/worktrees/pk-reserve-kqueue-attachments`. The probe is committed as `docs/probes/kqueue-attachments/`.*

## The question

Today a client sees every kqueue registration in full:

- `KqueueState` (inside the public case `OpenFileTarget.Kqueue`) is a public record, with a public constructor, whose `Registrations : Map<int * KqueueFilter, KqueueRegistration>` and `Active : (int * KqueueFilter) list` are keyed by a descriptor number.
- `KqueueRegistration` is a public record: `Clear`, `Receipt`, `UserData`, `RegisteredAt`, and `Socket : SocketId`.
- `PollQueue` (the kqueue a sleeping Darwin `poll` makes, which `UnixSystem.pollQueue` hands out) is a public record, keyed the same way, of public `PollRegistration`s: `Entry`, `OutOfBand`, `RegisteredAt`, `Socket : SocketId option`.
- `KqueueFilter` has two cases, `Read` and `Write`.

`kevent` on pipes is certain (#1726, "kevent registration for pipes"), and `EVFILT_TIMER` is likely. Each would change a public shape: a pipe registration has no `SocketId`, and a timer has no descriptor. What should the public shape be now, so that each lands as an addition?

## Facts

Measured on Darwin 27.0.0 arm64 (`docs/probes/kqueue-attachments/kevent-ident.c`, output beside it):

- **T1.** `EV_ADD` of `EVFILT_TIMER` succeeds for an ident above 32 bits (`0x100000001`) and for `UINTPTR_MAX`. The same ident under `EVFILT_READ` is `EINVAL`, as the existing `kevent-register.c` X2 rows say. A timer's ident names no descriptor.
- **T2.** One kqueue holds a timer and an `EVFILT_READ` under the same ident, a pipe's read descriptor. Closing that descriptor removes the read filter (a later `EV_DELETE` is `ENOENT`) and leaves the timer (its `EV_DELETE` succeeds). So the key is `(ident, filter)` for every filter, but "closing a descriptor removes its registrations" holds only for descriptor filters.
- **T3.** A timer added without `EV_CLEAR` reports with `EV_CLEAR` set, and `data` counts the expirations since the last report. `<sys/event.h>` says the same: "All timeouts are implicitly EV_CLEAR events". So a public `Clear : bool` documented as "whether the registration was first added with `EV_CLEAR`" would be false of a timer.
- **T4.** Each end of a pipe takes both `EVFILT_READ` and `EVFILT_WRITE`. So a pipe registration names a pipe and an end, under either filter, and which `struct pipe` XNU hangs the knote on for each pairing is not measured.

From `<sys/event.h>` in the macOS 27 SDK: `struct kevent64_s` has `ident : uint64_t`; `EVFILT_TIMER` is `-7`; a timer's `fflags` choose the unit (`NOTE_SECONDS`, `NOTE_USECONDS`, `NOTE_NSECONDS`, milliseconds by default), absolute time (`NOTE_ABSOLUTE`, implicitly one-shot), and coalescing (`NOTE_LEEWAY` with `ext[1]`, `NOTE_CRITICAL`, `NOTE_BACKGROUND`, `NOTE_MACH_CONTINUOUS_TIME`).

Who reads the tables today:

- **PawPrint** reads no field of `KqueueState` and no `KqueueRegistration`; it matches `OpenFileTarget.Kqueue _` only. From a `PollQueue` it reads, for diagnostics only (`GuestLocation.fs`, `DebuggerServer.fs`): the `(fd, filter)` keys, each registration's `Entry`, and whether a key is in `Active`. It matches `KqueueFilter` exhaustively (`DebuggerServer.fs`).
- **The README** names `PollQueue` and says that a kqueue records its owner and each registration the socket it is attached to. It names no field.
- **The library's own tests** read every field. They have `InternalsVisibleTo`.

## What is certain about a timer

The filter: `EVFILT_TIMER` exists on every Darwin, and a `KqueueFilter` case has no fields, so `KqueueFilter.Timer` is as certain as the feature. The rest is not. That covers the interval, the unit, absolute or relative, and leeway. It also covers whether a periodic timer's expiry count belongs in the registration or in its activation, and where the deadline lives so that `UnixWait.deadlines` can see it (D10 made `WakeCondition.deadlines` internal for this). No public type should hold any of these yet.

## Options

**(a) A public attachment union and a 64-bit key.** `KqueueAttachment = Socket of SocketId | Pipe of PipeId`, with `KqueueRegistration.Attachment : KqueueAttachment`, `PollRegistration.Attachment : KqueueAttachment option`, keys `uint64 * KqueueFilter`, and `KqueueFilter.Timer`.
- This is the smallest change, and a client can still read everything it reads today.
- But a timer attaches to no object, so `Attachment` must become an option or gain a `Timer` case. That case's fields are the uncertain list above. The `Pipe` case's fields are uncertain too: T4 says it needs the end as well as the pipe, and whether it attaches to the pipe or its end is unmeasured.
- The records stay public with public constructors. So each `EV_*` flag modelled later is a new field, and so a breaking change: `EV_ONESHOT`, `EV_DISPATCH` and `EV_DISABLE` are all refused today. T3 already shows that `Clear` would read wrongly for a timer.
- Every later attachment kind is a new case of a union clients receive. That is permitted, but §1.1 of the audit shows it is silently mis-dispatched by a client that isn't recompiled.

**(b) Opaque tables, with queries.** `KqueueState` and `PollQueue` keep their public names, but their representations become `internal`, as `FifoAttachment`'s is. `KqueueRegistration` and `PollRegistration` become internal types. `PollQueue` gains three public queries for what PawPrint reads: `registered`, `entry` and `activated`. `KqueueFilter.Timer` is reserved.
- An attachment kind, a 64-bit ident, a flag or a timer's parameters can then be added in any minor version. Each one is internal.
- A query is a new function, so adding one later is additive.
- The cost is that clients can no longer read a kqueue's registrations or forge a `KqueueState`. No client reads them, and forging one was never sound: `TestPublicSurface` already holds that a client holds only what the library hands it.
- The PR is medium-sized, but mechanical. The library and its tests keep their field access through `InternalsVisibleTo`.

**(c) Public records with an opaque attachment.** Keep both records public, but replace `Socket` with an opaque `KqueueAttachment` and widen the key to `uint64`.
- This fixes the attachment, but keeps (a)'s other two problems: a later flag is a new public field, and `Clear` misreads a timer.
- It is (a) with one field hidden, and the brief asks for at least two structurally different options, which (a) and (b) are. So (c) is only a variant.

## Decision (orchestrator's delegate)

**(b).** The brief asks for the shape that keeps *future* attachment kinds additive. Only (b) does that for kinds, flags and timer parameters all at once. Under (a), each of those is a field or case decided now on unmeasured facts, which the policy rules out. Pipes and timers stay refused, as they are today:
- `kevent` on a pipe answers `KeventRefusal.UnmodelledTarget`;
- `EVFILT_TIMER` answers `KeventRefusal.UnmodelledFilter`;
- so `KqueueFilter.Timer` is unreachable.

What is public after this PR:

| type | public | internal |
| --- | --- | --- |
| `KqueueFilter` | `Read`, `Write`, `Timer` (appended) | |
| `KqueueState` | the type, its equality and comparison | every field |
| `PollQueue` | the type; `PollQueue.registered`, `PollQueue.entry`, `PollQueue.activated` | every field |
| `KqueueRegistration`, `PollRegistration` | | the whole type |

The internal key stays `int * KqueueFilter` until the timer PR. It is internal, so widening it then is not a shape change. The internal `Socket` fields likewise become an attachment union in the pipe PR.

How `Timer` is kept unreachable, after §1.2 of the audit:
- Each complete match on `KqueueFilter` gets an arm. A readiness arm, such as a socket's or a pipe's filter readiness, fails loudly and names the reserved case. `filterNumber` answers `-7`, which is `<sys/event.h>`'s value.
- A property drives random changelists through `kevent`, with every `EVFILT_*` number in the header, idents both inside and beyond 32 bits, and every supported flag. Separately it drives random Darwin polls that sleep. It checks that no kqueue and no poll queue ever registers or activates `Timer`.
- The mutation check: decode `-7` as `Timer` in `kevent`, and the property fails.
