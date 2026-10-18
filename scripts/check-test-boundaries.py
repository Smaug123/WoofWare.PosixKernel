#!/usr/bin/env python3
"""Fail if a test file reaches past the helpers that hide a kernel internal.

`InternalsVisibleTo` shows every internal of the library to the test project,
so F#'s visibility cannot stop a test holding an internal representation, and a
test that holds one must change whenever the representation does, though
nothing it asserts has. So the tests reach each such internal through a few
helper modules, and this check holds them to that: each rule names an internal, by a pattern its every use matches, and the
files allowed to name it. A rule's allowlist is the helpers that hide the
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
                        hits.append(f"{name}:{number}: {match.group(0)}: {line.strip()}")

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
