# Darwin `poll(2)` in WoofWare.PosixKernel

*Options document, 2026-10-02. Part of the "PosixKernel knows nothing of the CLR" workstream. Code references are at branch `kernel-darwin-poll` `e5f294cb`, which is stacked on `kernel-kevent-register` (#1694) and `kernel-kqueue` (#1685). Probes are in that worktree's `docs/plans/2026-08-23-posix-kernel-extraction/`, uncommitted: `poll-darwin.c` (Darwin only, the full sweep) with its output `poll-darwin.darwin-27.0-uid501.txt`, and `poll-entry-interplay.c` (the rows where Darwin and Linux part ways, run on both) with `poll-entry-interplay.{darwin-27.0,linux-6.18.5-aarch64}.txt`. XNU source was read at `apple-oss-distributions/xnu` `main` (`bsd/kern/sys_generic.c`, `kern_event.c`, `uipc_socket.c`, `bsd/vfs/vfs_vnops.c`); every fact below that matters was then measured on this Mac (Darwin 27.0.0, xnu-13432.1.9, uid 501).*

## 1. What there is today

- **The library.**
  - `UnixPoll.poll` answers Linux only. Each entry is `LinuxReadiness.ofDescription` masked by `events | ERR | HUP`. A poll with nothing ready parks on one `WakePrimitive.DescriptorReady` per entry (plus the deadline and `SignalDeliverable`), and `close` refuses to close a descriptor a parked poll watches.
  - Under Darwin every poll is `PollRefusal.UnmodelledFlavour`.
  - #1685 and #1694 built Darwin's kqueue:
    - `KqueueState`: registrations keyed by (descriptor number, filter), an `Active` queue, and `Drained`.
    - `KqueueQueue.activate`, called by `SocketWake.signal` from each socket producer.
    - `KqueueQueue.drain`: walk the queue in order, drop the stale entries, take `EV_CLEAR` ones off and requeue the rest.
    - `DarwinReadiness.ofSocket`, for IPv4 and IPv6 stream sockets only.
    - What `kevent` refuses: `EV_ONESHOT`, every target that is not a socket, and every other socket kind.
- **PawPrint.** The `SystemNative_Poll` handler is flavour-agnostic. It screens a null buffer and `milliseconds < -1` itself, as the shim does, so the kernel only ever sees `-1` as a negative timeout. `PollEventsPal`'s six bits are numbered alike on both flavours. Darwin's poll needs no production change in PawPrint.
- **The BCL's callers of `SystemNative_Poll`:**
  - `SocketPal.TryCompleteConnect` and `HasNonBlockingConnectCompleted`: `POLLOUT`, timeout 0.
  - `Socket.Poll`: `IN`, `OUT` or `PRI`, with any timeout.
  - `ConsolePal.Unix.Write` after EAGAIN: `POLLOUT` on stdout or stderr, timeout -1.
  - `Process.Multiplexing.Unix`.
  - On macOS, `Socket.Select` goes to `SystemNative_Select`, not to poll.
- **The acceptance guest cannot pass on poll alone.**
  - `SocketAsyncSendReceiveDarwin.cs` does send and receive after its connect. PawPrint has no `SystemNative_Send` or `SystemNative_Receive` handler, and the kernel has no receive path (`DarwinReadiness`: "no byte is ever waiting to be read").
  - Darwin poll moves it from `SystemNative_Poll` to the next stop. §8 proposes guests that can pass.

## 2. How XNU builds `poll`

`poll_nocancel` makes a **private kqueue for the call**, with no descriptor. It never sees the process's own kqueues.

**Registration.** For each entry, in order:
- A negative fd is skipped, with `revents = 0`.
- Otherwise it registers `EV_ADD|EV_ONESHOT|EV_POLL`, `ident = fd`, `udata = entry index`, one filter per group of requested bits, in this order:
  - `EVFILT_READ` for any of `IN|RDNORM|PRI|RDBAND|HUP`, with `EV_OOBAND` added for `PRI|RDBAND`;
  - `EVFILT_WRITE` for any of `OUT|WRBAND` (`WRNORM` = `OUT`);
  - `EVFILT_VNODE` for any of `EXTEND|ATTRIB|NLINK|WRITE`, with the matching `NOTE_*` fflags.
- It stops at the first group whose registration fails, and that entry's `revents = POLLNVAL`. A filter registered before the failure stays registered.
- `ERR`, `NVAL` and `0x2000..0x8000` register nothing. So a request of only those, or of 0, never registers, and reports nothing even for a closed fd.
- Registering a (fd, filter) pair already registered by an earlier entry is a re-`EV_ADD` of the same knote, and it **replaces `udata`**.

**Scan.**
- If every non-negative entry failed (`nfds && rfds == nfds`), there is no scan.
- If any failed, the scan is immediate (`KEVENT_FLAG_IMMEDIATE`).
- Otherwise:
  - a timeout of `-1` waits forever;
  - any other timeout sets a deadline of `clock_interval_to_deadline(timeout, NSEC_PER_MSEC)`, whose interval is a **`uint32_t`**.
- `kqueue_scan` processes every active knote in queue (activation) order, through `poll_callback`. It returns once the output count is non-zero, and otherwise sleeps again with the same deadline.
- A knote that reports is dropped (`EV_ONESHOT`), whether or not it added anything. A stale knote is deactivated, but stays registered.

**`poll_callback`.** For each event:
- `EV_EOF` sets `HUP`, and `EV_ERROR` sets `ERR`.
- READ adds `events & (IN|RDNORM|PRI|RDBAND)` if `HUP` is now set. Otherwise it adds `events & (IN|RDNORM)`, plus `PRI|RDBAND` if the event carries `EV_OOBAND`.
- WRITE adds `events & (OUT|WRBAND)` **only if `HUP` is not already set**.
- VNODE adds the `NOTE_*` bits that fired.
- The count goes up when an entry's `revents` goes from 0 to non-zero.

**The ending.** `ERESTART` becomes `EINTR` (poll never restarts). `revents` are copied out for every entry, so a read-only buffer is `EFAULT`.

**The argument screen.** `nfds > OPEN_MAX (10240) || (nfds > RLIMIT_NOFILE && (not root || nfds > FD_SETSIZE))` is `EINVAL`, ahead of the copy-in.

## 3. Measured on Darwin 27.0.0

Two runs agreed except for timings and send-buffer sizes. The `poll-darwin.c` row names are given in brackets.

| fact | measured |
| --- | --- |
| **Every single-entry answer is §2 applied to the filters' own reports** | All 65536 masks, timeout 0, over 51 states: TCP over IPv4 and IPv6 (unbound, bound, listener empty and queued, connected, accepted, each half shut down, peer closed, data waiting, reset, refused before and after `SO_ERROR`); UDP fresh and connected; AF_UNIX stream and datagram; every pipe-end state including full; regular files at every access mode and offset; a directory; `/dev/null`; a kqueue empty and with an event; a closed fd; `-1`. **0 mismatches**, with no mask failing and `rv == (revents != 0)` every time. The prediction is §2 applied to what one `kevent(EV_ADD\|EV_ONESHOT)` per filter reported, plus two things user-space `kevent` cannot show (both from source, both confirmed by the sweep): (a) `EV_POLL` makes a regular file's READ always ready (`vnode_readable_data_count`); (b) `EV_OOBAND` stays in the event flags of every READ but a socket's (`filt_sockattach` clears it), so a ready pipe, file or kqueue READ answers `PRI\|RDBAND` when asked. [S] |
| **Representative answers** (modelled socket states) | idle or bound or empty listener: 0 to everything but a vnode bit, which is NVAL. Queued listener: `IN`, `RDNORM`. Connected: `OUT`, `WRBAND`. Peer closed: `IN→IN\|HUP`, `OUT→OUT`, `HUP→HUP`, `IN\|OUT→IN\|HUP`. Refused (before or after `SO_ERROR`): `IN→IN\|HUP`, `OUT→HUP`, `IN\|OUT→IN\|HUP`. [S] |
| **Other targets** | Pipe read end holding data: `IN`, `PRI` (from b. above). Empty with the writer gone: `IN\|HUP`, `OUT→HUP` (a WRITE registers on a read end and reports `EV_EOF`). Write end with room: `OUT`; full: 0; reader gone: `OUT→HUP`, `IN→IN\|HUP`. Regular file: everything readable and writable at any offset, vnode bits register and report nothing. Directory and `/dev/null`: any read or write bit is NVAL, and vnode bits alone report 0. Kqueue: `OUT` is NVAL, and `IN` is ready while an event is pending. Closed: NVAL for any registering bit, 0 for 0. [S] |
| **One descriptor in several entries** | **Darwin**: a (fd, filter) pair reports to the *last* entry naming it. Two `IN` entries on a queued listener give `[0, IN]`, rv 1; two `OUT` give `[0, OUT]`; the peer-closed `[IN\|OUT, IN]` gives `[OUT, IN\|HUP]`. Its dup is a different ident and reports separately. **Linux** reports each entry from its own level: `[IN, IN]`, `[OUT, OUT]`, `[IN\|OUT, IN]`. [M1, M12, M13–M16; interplay] |
| **A failing entry beside a ready filter** | A queued listener with `IN\|EXTEND` reports `IN\|NVAL` when another entry exists (whether ready, idle or `-1`), and `NVAL` alone when it is the only one. The count stays 1. [M3–M5, M9, M10] |
| **The count** | Always the number of entries with non-zero `revents`. Never double-counted. [S, M] |
| **What wakes a sleeping poll** | A queued connection (listener `IN`), the peer's close (`IN→IN\|HUP`, and `HUP` alone → `HUP`), and a pipe write. Each returned within ~5 ms of its event. [W1, W4, W5, W8] |
| **A wake that adds nothing is consumed** | `HUP` alone on an empty listener, then a connection: 0 at the 300 ms timeout. So does `HUP\|OUT`, and `HUP` on an already-queued listener followed by a second connection. **At registration too**: `HUP` alone on a pipe holding data, then the writer closes: 0 at the timeout, where the same poll of an empty pipe answers `HUP` at the close. **Linux** answers that pipe row `HUP` at the close. [W2, W3, W10, W7; interplay] |
| **Activation order decides the answer** | A poll of `IN\|OUT` on an idle socket, with the poller made a background thread and every CPU busy while a connect completes and the peer closes, answered **`IN\|OUT\|HUP` 37/40 and 33/40**, and `OUT` the rest. A poll made in that final state answers `IN\|HUP`; no single state answers `IN\|OUT\|HUP`. Without the close: `OUT` 20/20. SIGSTOP does not hold a sleeper off: the woken poll finishes in the kernel and stops on its way out [W6]. [W11; interplay] |
| **Close under a sleeping poll** | Already measured (`poll-timeout.c` E1–E4): Darwin drops the entry and waits to the timeout, answering 0, even when the number is reused by a socket that becomes ready. That is §2 exactly, since a close removes the knotes made through the descriptor. |
| **Timeouts and EINTR** | Already measured (`poll-timeout.c`, `signal-interrupt-requeue.c`). On both kernels: a positive timeout fires at or after its deadline and never before; 0 is immediate; `-1`, `-2`, `-1000` and `INT_MIN` all slept past 250 ms. A caught signal is `EINTR` with `SA_RESTART` or without. Darwin answers whichever reached the sleeper first. **Not measurable**: by source, a negative timeout other than `-1` is a finite deadline of `(uint32)timeout` ms (`-2` ≈ 49.7 days, `INT_MIN` ≈ 24.9 days), not infinite. |
| **`nfds`** | `EINVAL` above 10240 (`OPEN_MAX`) even with `RLIMIT_NOFILE` = 1048576, and above `RLIMIT_NOFILE` (64, 2048) for uid 501, in both cases ahead of a NULL buffer's `EFAULT`. Otherwise a NULL buffer is `EFAULT`, except for `nfds` 0, which never touches it. Linux has no `OPEN_MAX` cap. Root's `FD_SETSIZE` allowance is from source only. [N] |
| **Copy-out** | A buffer that can be read but not written is `EFAULT`, even for a lone `-1` entry and after the wait. [N] |

## 4. Options

### A. Poll as XNU builds it: a private kqueue per call, in the park record (recommended)

**Shape.** `poll` under Darwin does what `poll_nocancel` does, using the machinery #1694 built:

- **Registration.** For each entry, register the filters of §2 into a fresh `KqueueState` that belongs to the call, with the same re-ADD rule `kevent` already has (keep the flags, replace `udata`, activate if ready without moving it). `KqueueRegistration` gains:
  - `OneShot` (drop on report);
  - `OutOfBand` (`EV_OOBAND` as given; a socket's filter ignores it);
  - `ForPoll` (`EV_POLL`, which only a regular file's READ reads).
- **Scan.** Drain with no count limit, dropping one-shots, and fold the reports through a pure `pollCallback`, in queue order.
- **Park.** With nothing to report, park on `ParkedSyscall.Poll` in a Darwin form that holds that private `KqueueState`, its entries and its deadline.
  - Producers reach it: `KqueueQueue.activate` folds over parked polls' private kqueues as well as over the kqueues in the descriptor table.
  - `close` removes the registrations made through the closed descriptor from them too, which is the measured "drops the entry" (§3).
- **Wake.**
  - A new `WakePrimitive.PollReportable` holds when draining the task's own private kqueue would add anything to `revents`. Like `SignalDeliverable`, it names no object, because the object is the waiter's own.
  - `finishPoll` drains and answers, or re-parks with the consumption applied.

**Laws it can be tested against.** A reference implementation of `poll_nocancel` and `poll_callback` is short (the probe's `predict` is 40 lines). As an FsCheck property, the library's answer must equal the reference applied to an oracle of filter reports, for random entry lists (duplicates, dups, `-1`, closed, failing groups) and random event sequences.

**Single source of truth.** "Is this socket readable" is `DarwinReadiness` for both `kevent` and `poll`. Extending it to a new target serves both.

**Unmodelled targets.**
- A registration that *fails* is answered whatever the target, since the failure is the answer (NVAL). That covers vnode bits on sockets, pipes and kqueues; read or write bits on directories; WRITE on a kqueue; and a closed fd.
- A registration that *succeeds* on a target whose readiness is not modelled is refused, typed: datagram and AF_UNIX sockets (as `kevent` refuses them), and READ on a kqueue (a nested kqueue).
- A registration whose readiness is modelled but whose *activations* are not answers the call when it does not park, and refuses the park. That covers pipes until their producers are measured, and VNODE on files and directories, whose `NOTE_*` events nothing models.

**Blast radius.**
- The largest of the three options: three new registration fields, one-shot handling in `drain`, `activate` and `close` reaching parked polls, a park form and a wake primitive.
- Every piece is something a real kqueue also has. `EV_ONESHOT` becomes something `kevent` could accept later with no new machinery.
- Linux's poll is untouched.

**Reversibility.** It is all internal to the library. The published API grows by the new `WakePrimitive` and `ParkedSyscall` shapes, and a new `PollRefusal` case or two.

**Information preserved.** Everything the real kernel keeps: which knote belongs to which entry, the order of activation, and what has been consumed. That is why W11 and W7 come out right.

**Sub-choice: where the private kqueue lives.**
- **A1, the park record** (recommended). It exists only while the call sleeps. At timeout 0 it never touches the system at all.
- **A2, an fd-less open file description in the registry.** `activate` and `close` would reach it with no change. The cost is the registry's invariant that every description is named by a descriptor, the description's teardown at finish, and a new kind of object that only one syscall makes. A2 saves two folds and costs an invariant, so A1 is the better trade.

### B. A separate Darwin poll table, keyed by target kind, state and requested bits

**Shape.** A table, or a closed-form rule per state, giving `revents` for each (target state, `events`), measured row by row as Linux's `LinuxReadiness` was. It has its own wake primitive: "the table now answers something".

**Single source of truth.** No. "Is this socket readable" would live in `DarwinReadiness` for `kevent` and in this table for `poll`, and every new state would need measuring twice. The sweep shows that the table is §2 applied to the filter reports, so the duplicate is derivable, but nothing would keep the two in step.

**Unmodelled targets.** One refusal per missing row.

**What it gets wrong.** Everything that is not a function of one entry's state:
- duplicates (M1, M13), which need a "last entry wins" special case;
- NVAL beside a ready filter (M3);
- consumption at registration (W7);
- activation order (W11).

Each needs either a typed refusal or a special case. The W11 answer (`IN|OUT|HUP`) is not in any row at all.

**Blast radius.** Small: one new module. **Reversibility:** easy to throw away, but it leaves a second copy of the readiness facts to unpick.

### C. XNU's translation, stateless: `poll_callback` over `DarwinReadiness`, evaluated afresh

**Shape.** A pure `DarwinPoll.revents`:
- registration errors give NVAL;
- the (fd, filter) pairs are assigned to the last entry naming them;
- the filter reports are read *now* from `DarwinReadiness`;
- the result is folded in registration order through `poll_callback`.

The park is one primitive per entry, "this entry's translation is non-zero now". No private kqueue state is kept.

**Single source of truth.** Yes, `DarwinReadiness`, as in A.

**Exactness.** Exact for every call that does not park: this is what the sweep and M rows check. For a sleeping poll it is **unsound**, not merely incomplete:
- **Order.** After W11's two events it answers `IN|HUP`. Real Darwin answers `OUT` (the poller ran between) or `IN|OUT|HUP` (it did not), and never `IN|HUP`.
- **Consumption.** It cannot see that a READ reported at registration was consumed (W7). It would wake a `HUP`-only poll of a pipe holding data when the writer closes, where Darwin sleeps on.

Making it sound means refusing every finish at which an entry has two filters that became ready during the sleep, and every park with a READ already reported. Both refusals depend on facts (no receive path today, pipes not parked) that a later PR can silently invalidate.

**Unmodelled targets.** As A.

**Blast radius.** Medium-small: a module plus a park form. **Reversibility:** moving to A later replaces the park and the finish.

### Comparison

| | A | B | C |
| --- | --- | --- | --- |
| one source of truth for readiness | yes (`DarwinReadiness`) | no | yes |
| timeout-0 answers (the BCL's connect path) | exact | exact if every row is measured | exact |
| duplicates, NVAL beside ready | fall out | special cases | special case |
| sleeping poll: order (W11), consumption (W7) | exact, by keeping the kernel's state | wrong, or refused | wrong, or refused by guards a later PR can invalidate |
| close under a sleeper (Darwin's measured "drop the entry") | falls out of the existing close rule | needs its own rule | needs its own rule |
| new targets later | extend `DarwinReadiness` once, and `kevent` gains them too | new table rows | extend `DarwinReadiness` |
| size | largest | smallest | middle |

**Recommendation: A1.** It is the only option whose sleeping answers are sound without guards. Its pieces are the kqueue's own, and it leaves `kevent` one step from `EV_ONESHOT` and from every target poll adds to `DarwinReadiness`.

## 5. Scope (under A)

| target | timeout 0 / ready at once | park |
| --- | --- | --- |
| IPv4/IPv6 TCP in every phase the kernel models (idle, listening, established, peer FIN, refused with the error pending or taken) | answer | answer: every producer is already measured and wired through `SocketWake.signal` |
| any socket with only vnode bits asked, or with a vnode bit after its registering groups | NVAL (or `IN\|NVAL` per §3) | answer: the failure is immediate |
| UDP and AF_UNIX sockets | refuse (`UnmodelledSocket`) when a read or write filter would register | refuse |
| pipe ends | answer: READ is `PipeBuffer.readable` or `EV_EOF` with no writer; WRITE is the measured `max(16384, size) − held ≥ 512` or `EV_EOF` with no reader (both ends take both filters) | refuse (`UnmodelledWake`) until pipe activations are measured, for `kevent` and poll at once |
| regular file | answer: READ and WRITE always ready under `EV_POLL`; vnode bits register and report nothing | VNODE-only would park: refuse |
| directory | read or write bits NVAL; vnode bits register | vnode-only: refuse |
| kqueue | `OUT`/`WRBAND`/vnode bits NVAL; READ refused (nested kqueue) | refuse |
| epoll | cannot exist under Darwin (`failwith`, as elsewhere) | — |
| closed fd | NVAL for any registering bit, 0 for a request of 0 | — |
| negative fd | 0, not counted | — |
| request of 0, or of only `ERR`/`NVAL`/`0x2000..0x8000` | 0, registers nothing, waits on nothing | a poll of only such entries sleeps to its deadline or a signal, as `nfds = 0` does |

The sweep bounds are the 51 states and 65536 masks of §3. The rows not swept are listed in §9.

## 6. The rest of the call

- **Timeout.**
  - `-1` is infinite and `0` is immediate. A positive timeout is a deadline, as on Linux (`relativeDeadline` serves both).
  - **Any other negative timeout: refuse** (`PollRefusal.UnmeasuredNegativeTimeout`). By source it is a finite deadline of `(uint32)timeout` ms. Measurement cannot tell that from infinite, and a simulator's idle clock jump would reach it at once. PawPrint never sends one, since the shim screens `< -1`.
- **Deadline beside output at a finish:** refuse, as `kevent` does (`EventsBesideDeadline`). XNU returns 0 on `THREAD_TIMED_OUT` without scanning, so Darwin answers whichever reached the sleeper first.
- **EINTR:** as `kevent`'s finish: `EINTR` with `SA_RESTART` or without. A signal beside an answer is `SyscallInterruptionRefusal` through `beforeCompleting`, which is already Darwin's rule.
- **The count:** the entries with non-zero `revents` (unchanged from Linux).
- **A request of 0:** reports nothing and waits on nothing, even for a closed fd. It does not count.
- **`nfds`:** the library takes a list, not `nfds`, and PawPrint models `RLIMIT_NOFILE` as infinite (the handler documents why). But the `OPEN_MAX` cap is a Darwin fact independent of any limit. **Recommend answering `EINVAL` for more than 10240 entries under Darwin**, as the first check (measured ahead of `EFAULT`). Linux stays uncapped.
- **`EFAULT` on copy-in or copy-out** stays the client's: PawPrint's buffer is managed memory, and the shim screens NULL.
- **Close under a sleeper:** answered under Darwin, by removing the registrations made through the fd from the parked poll (§3). Linux keeps its refusal.

## 7. Wake-ups

- **Linux** parks on `DescriptorReady` per entry, which reads `LinuxReadiness` afresh. That is right for Linux, where a woken poll re-polls each file's level.
- **Darwin** must not reuse it: W7 and W11 show the answer depends on what the private kqueue has activated and consumed, not on levels.
- **The producer side is already there.** `SocketWake.signal` calls `KqueueQueue.activate`, with each producer's filters in measured order (WRITE before READ for a resolved connect). Under A1, `activate` also appends to the `Active` queue of each parked poll's private kqueue that registers that socket and filter, if the filter is ready. That is the same rule real kqueues get.
- **The consumer side stays pulled.** `WakePrimitive.PollReportable` holds when a drain of the waiter's private queue would add something to `revents`. The client's sweep asks it every tick, as it asks every other primitive.
- **Deferred consumption.** A real kernel wakes the poller for an activation that adds nothing (W2) and consumes it. The pull model leaves it queued until the finish. That answers the schedule in which the poller had not yet run, which is a schedule a real kernel can produce: sound, not complete, as epoll's stage-3 decision already accepted. Consumption *at registration* (W7) is not deferred, because the initial call drains as `kqueue_scan` does.
- **Wake order between waiters** does not arise: each poll's private kqueue has exactly one waiter.

## 8. PR split

**Recommendation: one PR on this branch, in two commits.**
1. **The library.** Darwin poll as A1, with:
   - the FsCheck property against a reference `poll_nocancel`;
   - the swept states as literals, from the probe's answers;
   - the M and W rows as literals;
   - the measured rows in the flavour-divergence table and beside the code.
2. **The guests,** differential on a Darwin host:
   - `SocketPollDarwin.cs`, a direct `SystemNative_Poll` P/Invoke, as `SocketPollLinux.cs` is: listener queued and empty, connected, peer closed, refused, NVAL beside ready, duplicates, a request of 0, a closed fd;
   - `SocketAsyncConnectDarwin.cs`: managed `ConnectAsync` and `AcceptAsync` with no data, which is what poll actually unblocks in `SocketAsyncSendReceiveDarwin.cs`.

   That guest stays parked, with its comment updated to the next stop (send and receive). `Socket.Poll` with a positive timeout belongs in the first guest too, so that a sleeping poll is exercised through PawPrint.

**Why not two PRs.** PawPrint needs no production change, so the second PR would be test-only, and stacking it on a three-deep stack costs more review overhead than it saves. If the library diff turns out much larger than expected, split there.

## 9. Not measured, and the questions for you

**Not swept.**
- A second filter registered by a *later* entry with different `EV_OOBAND` from the first (re-ADD's flags rule for `EV_OOBAND` on a non-socket). Only reachable by asking a pipe, file or kqueue for `IN` in one entry and `PRI` in a later one. Refuse it in phase 2 unless a quick probe settles it.
- Root's `FD_SETSIZE` allowance.
- Pipe activations (which reads and writes activate which filter). Hence the pipe park refusal.

**Decisions for you.**
1. **A1** (recommended), A2, B or C?
2. Scope as in §5: in particular, answer pipes, files, directories and kqueue-`OUT` when the call does not park, but refuse parking on them.
3. Refuse negative timeouts other than `-1` under Darwin (recommended), or model the source's `uint32` deadline?
4. Answer `EINVAL` above 10240 entries under Darwin (recommended), or leave `nfds` to the client as on Linux?
5. One PR (recommended) or two, and the acceptance guests of §8 in place of un-parking `SocketAsyncSendReceiveDarwin.cs`, which needs socket data transfer first.

## Decision (orchestrator, 2026-10-02)
1. **Structure: A1.** Each call gets a private kqueue, kept in the park record. A1 is the only option that keeps `DarwinReadiness` as the single source of truth and gets the activation-order, consumption and duplicate-entry rows right by construction.
   - A2 is rejected: it breaks the invariant that every description is named by a descriptor.
   - B is rejected: it duplicates the readiness facts.
   - C is rejected: it is unsound for a sleeping poll unless it carries guards that a later change can quietly invalidate.
2. **Scope.** Take the recommended scope with one change: **measure which pipe operations activate which filter now**, then let a poll park on pipes if those measurements are clean. Pipes are the commonest non-socket target, and "model Darwin poll" should cover a sleeping wait on one.
   - If the measurements are not clean (for example, they are nondeterministic in a way the model can't state), keep the typed refusal and record why.
   - Parking on regular files, directories and kqueues stays refused, as recommended.
   - UDP and Unix-domain sockets, and nested kqueue `IN`, stay refused.
3. **Negative timeouts** other than -1 are refused under Darwin, typed, because the 49.7-day deadline cannot be measured.
4. **`nfds`.** Answer the measured EINVAL above 10240. Also measure the band where `FD_SETSIZE < nfds <= 10240` and `nfds` is above `RLIMIT_NOFILE`'s soft limit, which the source suggests is EINVAL for a non-root process.
   - Model it if the kernel has `RLIMIT_NOFILE`.
   - Otherwise refuse that band, typed.
   - A root process inside that band is refused, because it is unmeasured.
5. **PRs.** One PR on this branch, with a library commit and a guest commit. The acceptance guests are `SocketPollDarwin.cs` and `SocketAsyncConnectDarwin.cs`. `SocketAsyncSendReceiveDarwin.cs` is re-parked, with its comment naming the real blocker: socket send and receive.
