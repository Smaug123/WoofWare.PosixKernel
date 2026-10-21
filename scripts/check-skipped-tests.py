#!/usr/bin/env python3
"""Fail if a CI test run skipped a test that the allowlist does not expect skipped.

A skipped NUnit test (`Assert.Ignore`, `[<Explicit>]`, a fixture whose setup
skipped) leaves `dotnet test` exiting 0, so a test that newly skips -- a host
comparison whose guard stopped matching CI's kernel, a tool that went missing
from the devshell -- stops checking anything without anyone seeing it. This
reads the TRX files every test step wrote and holds the tests none of them ran
to an allowlist, each entry naming the test, the exact message it skips with,
and why CI cannot run it.

A test counts as run if any TRX file records it passing or failing, so that a
test one step skips and a later step runs (the `LargeMemory` fixtures, which
the default step leaves out) is not a skip. Any other outcome (`NotExecuted`,
`Inconclusive`, ...) in every file that records it counts as a skip.

It reports, and exits 1 on:

  * a skipped test the allowlist does not name;
  * an allowlisted test that skipped with a different message, since a new
    reason to skip is a new skip;
  * an allowlisted test that ran, or that no TRX file records, so that the
    allowlist shrinks when a test starts running, is renamed or is deleted,
    rather than going on excusing it.

It exits 2 on a usage error: no TRX files, a TRX file recording no results, or
an allowlist that is not a JSON list of entries with exactly the fields
`fixture`, `test`, `message` and `why`, or that names one test twice.

`fixture` is the test's class as the TRX file records it (an F# module's full
name), `test` its name with any `TestCase` arguments, and `message` the skip
message, `""` where there is none (an `[<Explicit>]` test).

Usage:  check-skipped-tests.py <allowlist.json> <results.trx>...
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = "{http://microsoft.com/schemas/VisualStudio/TeamTest/2010}"
RAN = {"Passed", "Failed"}
FIELDS = {"fixture", "test", "message", "why"}


class UsageError(Exception):
    pass


def read_results(paths):
    """Each test's identity to (whether any file ran it, its skip messages)."""
    tests = {}
    for path in paths:
        root = ET.parse(path).getroot()
        definitions = {}
        for unit in root.iter(NS + "UnitTest"):
            method = unit.find(NS + "TestMethod")
            if method is None:
                raise UsageError(f"{path}: test {unit.get('id')} has no TestMethod")
            definitions[unit.get("id")] = (method.get("className"), unit.get("name"))
        results = list(root.iter(NS + "UnitTestResult"))
        if not results:
            raise UsageError(f"{path}: records no test results")
        for result in results:
            key = definitions.get(result.get("testId"))
            if key is None:
                raise UsageError(f"{path}: result for undefined test {result.get('testId')}")
            ran, messages = tests.setdefault(key, (False, set()))
            if result.get("outcome") in RAN:
                ran = True
            else:
                messages.add(result.findtext(f"{NS}Output/{NS}ErrorInfo/{NS}Message") or "")
            tests[key] = (ran, messages)
    return tests


def read_allowlist(path):
    try:
        entries = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise UsageError(f"{path}: {e}")
    if not isinstance(entries, list):
        raise UsageError(f"{path}: not a JSON list")
    allowed = {}
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != FIELDS:
            raise UsageError(f"{path}: entry {i} does not have exactly the fields {sorted(FIELDS)}")
        if not all(isinstance(entry[field], str) for field in FIELDS):
            raise UsageError(f"{path}: entry {i} has a field that is not a string")
        if not entry["why"].strip():
            raise UsageError(f"{path}: entry {i} does not say why CI skips it")
        key = (entry["fixture"], entry["test"])
        if key in allowed:
            raise UsageError(f"{path}: entry {i} names {key[0]} :: {key[1]} a second time")
        allowed[key] = entry["message"]
    return allowed


def check(allowlist_path, trx_paths):
    """The reports, one line each; empty when the run skipped what was expected."""
    tests = read_results(trx_paths)
    allowed = read_allowlist(allowlist_path)
    reports = []
    for (fixture, test), (ran, messages) in sorted(tests.items()):
        name = f"{fixture} :: {test}"
        if (fixture, test) in allowed:
            expected = allowed[(fixture, test)]
            if ran:
                reports.append(f"ran, but is allowlisted as skipping: {name}")
            elif messages != {expected}:
                got = " / ".join(repr(m) for m in sorted(messages))
                reports.append(f"skipped with {got}, allowlisted as {expected!r}: {name}")
        elif not ran:
            got = " / ".join(repr(m) for m in sorted(messages))
            reports.append(f"skipped, not allowlisted ({got}): {name}")
    for fixture, test in sorted(set(allowed) - set(tests)):
        reports.append(f"allowlisted, but no TRX file records it: {fixture} :: {test}")
    skipped = sum(1 for ran, _ in tests.values() if not ran)
    return reports, len(tests), skipped


def main(argv):
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    allowlist_path, trx_paths = argv[1], argv[2:]
    try:
        reports, total, skipped = check(allowlist_path, trx_paths)
    except (UsageError, ET.ParseError, OSError) as e:
        print(f"check-skipped-tests: {e}", file=sys.stderr)
        return 2
    if reports:
        print(f"check-skipped-tests: {len(reports)} unexpected in {total} tests:")
        for report in reports:
            print(f"  {report}")
        print(
            f"A test CI cannot run belongs in {allowlist_path} with its exact skip message "
            "and why; a test that should run must not skip."
        )
        return 1
    print(f"check-skipped-tests: {skipped} of {total} tests skipped, each as {allowlist_path} expects")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
