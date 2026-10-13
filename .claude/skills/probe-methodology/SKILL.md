---
name: probe-methodology
description: How to measure ground truth with a probe without measuring the wrong thing. Use before writing any claim that a probe or measurement establishes — what a kernel answers, the order it checks in, that a branch "runs once", or that a branch is unreachable.
---

# Probing before implementing

A "probe" is a measurement used to establish ground truth before writing a fix,
a row or a comment about behaviour: a C program run on each platform (committed
under `docs/probes/` or beside a plan, with its output), or a temporary
`failwith` or counter in the library. Three ways a probe can look successful
while measuring the wrong thing. For the platform-specific traps — set-ID bits,
`uname`, Rosetta — see the `emulated-posix-kernel` skill's
`reference/probing.md`.

## Re-entrant calls look like straight-line code

A syscall that sleeps or pauses is not one pass through one function. A call
interrupted by a signal handler under `SA_RESTART` is issued again by the client
from the top (`ReadOutcome.Restarts`); a call that stops to copy bytes in
(`CallProgress.NeedsCopyIn`) finishes in its resume function; a parked call is
completed by its family's finishing function once `UnixWait` says it is woken.
So a branch that reads like a once-per-call early return can run twice for what
the process sees as one call, and code after a park runs against a state that
other threads have changed in between. None of this is visible at the point you
read the code.

**How to apply:** before writing any claim about ordering, "runs once", or that a
branch is unreachable, temporarily instrument the suspicious arm and run the test
you think exercises it. An unconditional `failwith "PROBE: <arm> really happens
here"` only proves the arm is reached on *some* visit — it aborts before any
later restart or resumption can occur, so it can't distinguish "runs once" from
"reruns on resumption". To settle ordering or repeat-visit questions, increment a
counter (or `printfn`) on each entry and `failwith` only once the counter shows a
second visit, or trace and inspect the log after a normal run. Thirty seconds
either way, and it settles both whether the path is live and whether the claim is
true.

## A newer measurement doesn't supersede an older one about the same mechanism

When a new measurement changes your conclusion, the natural move is to rewrite
the model around the new result. But an earlier row that disagrees with the new
model is not thereby wrong; more often both are true, and the rule picks between
them by some state neither probe varied. A probe that finds a signal sent to the
process handled on the main thread, and a later one that finds it on a worker,
are not one right and one wrong: the rule is "the main thread whenever it does
not block the signal".

**How to apply:** when a new measurement changes your conclusion, re-read every
earlier row and check the new model predicts each one — write the rows into a
table so the check is forced. When a conclusion has two candidate poles, suspect
the real answer is a rule that picks between them by state, and design the probe
to hit each side deliberately.

## A probe can address the wrong entity, or never read it

A probe has two failure modes that look identical to success. It can address the
wrong entity: the descriptor, index or slot it computes is not the one it names
(`fds[0]` of a pipe is the read end, so a probe that "closes the writer" by
closing `fds[0]` measures the opposite case). Or it can address the right entity
but never cause it to be read: a probe that sets a socket option and then never
makes the call the option governs records every value as accepted, whether or
not the kernel honours it. Both yield clean, plausible numbers, and neither is
caught by a control that only checks "the untouched case still works" — that
control passes in both wrong versions.

**How to apply:**
1. Print the fixture itself, not just the result — which descriptor is which, the
   bytes of the buffer passed, the mode actually set — so a mismatch shows
   immediately.
2. Confirm the perturbation actually reaches the code under test: at least one
   perturbation must *change the answer*. If every variation gives the same
   result, the target is dead.
3. Name the index/entity explicitly rather than by position (`Count - 1` is a
   guess about layout).

A probe is a test, and an unfalsifiable one is worth nothing.
