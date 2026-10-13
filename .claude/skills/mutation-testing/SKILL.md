---
name: mutation-testing
description: How to confirm a test or guard catches the failure it names rather than being vacuously green, by deliberately breaking the implementation and watching the test go red. Use before claiming a new test covers a failure mode, and when a fix adds a guard across several symmetric arms.
---

# Mutation testing in this codebase

Mutation testing — deliberately breaking an implementation to confirm a test catches it — is how you validate that a new test or guard catches the failure it names rather than being vacuously green. This describes the traps that make coverage vacuous, and the operational pitfalls of doing it.

## Why mutate

A green suite proves nothing about a *specific* test unless you've watched it turn red for the reason you expect. Three recurring traps produce vacuous coverage:

- **An earlier check answers first.** A syscall makes its checks in an order, and a test whose input trips an earlier one never reaches the rule it names. A test of `lseek`'s whence screen made on a descriptor that is not open is answered EBADF whatever the screen does, and stays green with the screen deleted. Make every check before the one under test pass, then mutate the one under test.
- **Lossless destinations.** If the layer a value passes through next cannot tell two values apart, no test above that layer can either: a mutant that changes the value survives every test that observes it only through that layer, and only the unit test of the layer that produced it dies. A mutation table tells you *which layer* a test actually covers; don't claim end-to-end coverage of a property that round-trips losslessly through the next layer.
- **A host test sees one column.** A `*AgainstHost` test compares the model with the kernel running it, so a mutant that changes only the other flavour's answer survives it. On macOS, a Linux-only rule is killed only by the literal rows, a replay of a committed probe output, or CI's Linux run.

**How to apply:** before claiming a new test covers a failure mode, break the implementation and watch it fail — once per mode the test's docstring claims — and check that it fails *for the reason you expect* (the message names the row and the value you broke), not merely that something failed. For a fix that adds a guard across N symmetric arms, mutate each arm separately; a surviving mutant means either a missing test or an unjustified line. A helper that survives mutation to the identity, and that analysis shows no input can observe, should be deleted rather than given an invented test. Record confirmed mutations in the PR body as a table — it tells a reviewer exactly which failures the test catches.

## Operational hazards: the harness owns the tree

A mutation run — background or scripted — holds exclusive access to the working tree, the same as `codex review`: nothing else should touch the worktree until it finishes. Several ways to lose an edit or leave a mutant live:

- **Never `git checkout` to restore a mutated file.** It reverts to HEAD, discarding the *entire* uncommitted diff, not just the mutation — this can destroy a finished implementation. Instead, `cp` every file you plan to mutate to a scratchpad before the first mutation, mutate with a script that asserts `s.count(old) == 1`, and restore with `cp` back.
- **A killed harness leaves a mutant live.** Editing a file mid-run, or stopping a run early, means the harness's unconditional restore-on-finish never happens — a killed process never reaches its `finally`. After stopping one early, `grep` for every mutant anchor before doing anything else; the `.bak` files that exist tell you which mutation it had reached.
- **An inline background command inherits `errexit`.** The first killed mutant (a non-zero `dotnet test` — the very outcome you're hoping for) aborts the loop between "apply" and "restore" and leaves that mutant live. Put the battery in a script file with `set +e`, not pasted inline: a loop that runs fifteen mutations cleanly as a script can die on the first when pasted inline.
- **Restoring from a backup preserves the old mtime.** `shutil.copy2` + `shutil.move` puts back the *original* mtime, older than the DLL built from the mutant — incremental MSBuild then considers the output up to date and silently replays the mutant on the next `dotnet test`, even without `--no-build`. `touch` the file after restoring (or `os.utime(path, None)` in the harness's `finally`).
- **A stale `.bak` reverts real edits.** A script that does `[ -f "$BAK" ] || cp "$SRC" "$BAK"` then `cp "$BAK" "$SRC"` will, on a second battery, copy a *stale* backup over source that's since been legitimately fixed. The perl then matches nothing, prints `MUTATION-DID-NOT-APPLY`, and restores the stale file again — silently discarding the fix. Always refresh the backup from the working tree, and refuse to run when the target differs from HEAD:
  ```bash
  if ! git diff --quiet HEAD -- "$REL"; then
    echo "REFUSING: $REL differs from HEAD; commit or revert first."; exit 4
  fi
  cp "$SRC" "$BAK"
  ```
  (`git diff --quiet` alone compares only the worktree against the index, so it misses staged-but-uncommitted changes — always diff against `HEAD`.)
  Commit before each battery. Treat `MUTATION-DID-NOT-APPLY` as "check the file right now", never as "nothing happened".
- **`--no-build` runs whatever binary is already there.** Reverting a temporary source edit (a probe, a mutation) doesn't take effect until the next build — `git status` describes the source tree, but `--no-build` depends on `bin/`, and those two disagree for exactly as long as it takes to rebuild. When a suite fails on precisely the test you were just poking, suspect the stale binary before suspecting the diff: rebuild and re-run that one test before investigating further.

Prefer running a mutation battery when you have no pending edits at all.
