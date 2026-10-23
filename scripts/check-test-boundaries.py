#!/usr/bin/env python3
"""Fail if a test file reaches past the helpers that hide a kernel internal.

`InternalsVisibleTo` shows every internal of the library to the test project,
so F#'s visibility cannot stop a test holding an internal representation, and a
test that holds one must change whenever the representation does, though
nothing it asserts has. So the tests reach each such internal through a few
helper modules, and this check holds them to that: each rule names an
internal, by a pattern its every use matches, and the files allowed to name it. A rule's allowlist is the helpers that hide the
internal and the tests of the internal itself, each with the reason it needs
the representation; every other file asks the helpers.

Every `.fs` line is scanned -- code, docstrings, comments and string literals
alike -- since a comment naming an internal function documents a coupling as
surely as a call makes one, and a reflection test that names the module by a
string breaks when the module is renamed.

An allowlist entry that names a file which no longer matches its rule, or which
is not there, is reported too, so that the allowlist shrinks as its files stop
needing the representation, rather than going on exempting them.

To hide another internal, add a `Rule`: its name, its pattern, what a test
should do instead, and its allowlist.

What it does not see, accepted deliberately:

  * A use that matches no pattern: a value of an internal type that a test
    gets from a helper and passes on without naming its type or module. A rule
    names the helpers that hand the representation out as well (`threadTable`,
    `mapThreadTable`), so that each is caught where it is used.
  * The type a field is read from. The patterns for the `UnixSystem` record's
    fields see a name, `.Machine` on a value or `Machine =` where a record
    label stands, so a test's own record with a field of the same name is
    reported as though it were the system's (rename the field), and a field
    read through a value whose every name starts in upper case is not seen.
  * What a test does with the machine or scheduling `Kernel` hands it: the
    machine's own fields are the next layer down, behind no rule here.
  * Build output under `obj/` or `bin/`, and non-`.fs` files.

Usage:  check-test-boundaries.py <test-project-dir>
"""

import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    instead: str
    # File, relative to the test project, to the reason it may name the internal.
    allowed: dict


RULES = [
    Rule(
        name="thread table",
        # `UnixThreadTable` and `ThreadTable`, and `Proc.threadTable`,
        # `Lone.threadTable` and `Proc.mapThreadTable`, which hand one out.
        pattern=re.compile(r"[Tt]hreadTable"),
        instead=(
            "ask about one thread through `Proc` or `Lone` (`thread`, `parkOf`, "
            "`parkedIn`, `owedBy`, `threadMap`), and forge a thread's state through "
            "`ForgedThread`; if no helper there answers, add one"
        ),
        allowed={
            "Proc.fs": "defines the per-thread queries every test asks, and the accessors that hand the table to the files below",
            "Lone.fs": "defines `Proc`'s per-thread queries for a system holding one process",
            "ForgedThread.fs": "forges a thread's state by writing the table, for every test that forges one",
            "TestUnixThreadTable.fs": "tests the table's own functions, and what its module makes public",
            "TestSleeperIndex.fs": "tests that the table's names of its parked threads are the ones a scan of every thread finds, which only the table holds",
            "TestWakeMemo.fs": "the sweep memo holds each process's table by identity (`WakeMemo`), so its tests build a table equal to another but distinct, and a process holding no threads",
            "TestProcessView.fs": "tests that putting a view back compares each of its parts by identity, so it rebuilds the view's table as an equal but distinct one",
            "TestBootImage.fs": "names the module by reflection, to hold its `unpark` private; it holds no table",
        },
    ),
    Rule(
        name="system's machine and scheduling fields",
        # `.Machine` and `.Scheduling` read from a value (a name starting in
        # lower case, or a parenthesised expression, whose read Fantomas may
        # put at the start of the next line), and the record labels
        # that write them. A field of a type (`UnixSystem.Machine` in prose)
        # is named too; a name merely containing the word (`UnixMachineState`,
        # `UnixSchedulingState`, `machine.UnixPlatform`) is not.
        pattern=re.compile(
            r"(?:(?:\b[a-z_][\w']*(?:\.[A-Za-z_][\w']*)*|\)|\bUnixSystem)|^\s*)\.(?:Machine|Scheduling)\b"
            r"|(?:^\s*|[{;]\s*|\bwith\s+)(?:Machine|Scheduling)\s*="
        ),
        instead=(
            "ask the public `UnixSystem` query where a client could see the fact (`platform`, `fileSystem`, "
            "`openFiles`, `realtime`, `nanosecondsSinceBoot`, `advanceClock`, ...), and otherwise read and "
            "write the machine and the scheduling through `Kernel` (`machine`, `mapMachine`, `scheduling`, "
            "`mapScheduling`); if no helper there answers, add one"
        ),
        allowed={
            "Kernel.fs": "defines the reads and writes of the machine and the scheduling every other test makes",
            "TestProcessView.fs": "tests that putting a view back compares each of its parts by identity, so it rebuilds the view's machine and scheduling as equal but distinct ones",
        },
    ),
    Rule(
        name="process table",
        # The table, its slots, and the system's and a view's fields holding one.
        pattern=re.compile(
            r"\bProcessTable\b|\bProcessSlot\b"
            r"|(?:(?:\b[a-z_][\w']*(?:\.[A-Za-z_][\w']*)*|\)|\bUnixSystem)|^\s*)\.(?:Processes|Others)\b"
            r"|(?:^\s*|[{;]\s*|\bwith\s+)(?:Processes|Others)\s*="
        ),
        instead=(
            "read and write one process through `Proc` or `Lone` (`state`, `mapState`, `leader`, `withLeader`, "
            "`view`, ...), and ask which processes there are through `UnixSystem.processIds`; if no helper "
            "there answers, add one"
        ),
        allowed={
            "Proc.fs": "defines the reads and writes of one process every test makes, which find its slot in the table",
            "TestSleeperIndex.fs": "tests that the table's keys of its processes with a parked thread are those a scan of every slot finds, which only the table holds",
            "TestWakeMemo.fs": "the sweep memo holds the table by identity (`WakeMemo`), so its tests build a table equal to another but distinct",
            "TestProcessView.fs": "tests that focusing a view takes its process out of the table and putting it back puts the same slots back, by identity",
            "TestMultiProcessFuzz.fs": "its wake properties hold a sweep to leave the table the very value it was given, and the memo's `covers` and `readsSame` take the table; and each step to leave every other process's slot, its thread table's index of parked threads among it, as it was",
            "TestUnixWait.fs": "tests that a sweep that wakes nobody leaves the table the very value it was given",
            "TestBootImage.fs": "names the slot's type by reflection, to hold that a client can build none; it holds no table",
        },
    ),
    Rule(
        name="wake memo",
        pattern=re.compile(
            r"(?:(?:\b[a-z_][\w']*(?:\.[A-Za-z_][\w']*)*|\)|\bUnixSystem)|^\s*)\.Sweep\b"
            r"|(?:^\s*|[{;]\s*|\bwith\s+)Sweep\s*="
        ),
        instead="leave the memo to `UnixWait.wake`, whose answers no memo may change",
        allowed={
            "TestWakeMemo.fs": "tests the memo itself: what it remembers, and that equality ignores it",
            "TestMultiProcessFuzz.fs": "holds every answer the memo gives to the sweep it stands in for, along random interleavings, and that equality ignores it",
        },
    ),
    Rule(
        name="process view's module",
        pattern=re.compile(r"\bProcessView\."),
        instead=(
            "focus a process through `Proc.view` or `Lone.view`, and put a view back through `unview` or "
            "`unfocus` there"
        ),
        allowed={
            "Proc.fs": "defines the focusing and putting back every other test does",
            "TestProcessView.fs": "tests the module itself: that putting back a view unchanged from the one focused answers the very system focused",
        },
    ),
    Rule(
        name="UnixSystemState module",
        pattern=re.compile(r"\bUnixSystemState\b"),
        instead=(
            "read and write a process's descriptor table through `Proc` or `Lone` (`fileDescriptors`, "
            "`withFileDescriptors`), and the signal numbering through `Kernel.signalNumbering`"
        ),
        allowed={
            "Proc.fs": "defines the reads and writes of a process's descriptor table every other test makes",
        },
    ),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    tests = Path(sys.argv[1])
    sources = sorted(
        path
        for path in tests.rglob("*.fs")
        if not {"obj", "bin"} & set(path.relative_to(tests).parts[:-1])
    )

    # A mistyped directory would otherwise pass vacuously.
    if not sources:
        print(f"Test boundaries: no .fs files under {tests}", file=sys.stderr)
        return 2

    lines = {source.relative_to(tests).as_posix(): source.read_text().splitlines() for source in sources}

    failed = False
    for rule in RULES:
        hits = []
        matched = set()
        for name, text in lines.items():
            for number, line in enumerate(text, start=1):
                for match in rule.pattern.finditer(line):
                    matched.add(name)
                    if name not in rule.allowed:
                        hits.append(f"{name}:{number}: {match.group(0).strip()}: {line.strip()}")

        stale = [
            f"{name}: {'is not there' if name not in lines else 'names nothing the rule matches'}"
            for name in sorted(rule.allowed)
            if name not in matched
        ]

        if hits:
            failed = True
            print(
                f"Test boundaries: {len(hits)} uses of the {rule.name} outside its helpers; {rule.instead}.",
                file=sys.stderr,
            )
            for hit in hits:
                print(f"  {hit}", file=sys.stderr)

        if stale:
            failed = True
            print(
                f"Test boundaries: {len(stale)} entries of the {rule.name}'s allowlist exempt no use of it; take them off.",
                file=sys.stderr,
            )
            for entry in stale:
                print(f"  {entry}", file=sys.stderr)

    if failed:
        return 1

    print(f"Test boundaries: none crossed in {len(sources)} files.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
