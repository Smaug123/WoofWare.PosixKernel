#!/usr/bin/env bash
# Executable contract for check-skipped-tests.py.
#
# Writes two throwaway TRX files, shaped as `dotnet test --logger trx` writes
# them, and an allowlist, and asserts the report names exactly the unexpected
# skips: a skip the allowlist lacks, a skip whose message changed, an
# allowlisted test that ran, and one no file records. The silent shapes are as
# much the point: an allowlisted skip, a test one file skips and another runs
# (in either order), a failure (which the test step itself reports) and a
# `TestCase` row whose sibling row is allowlisted. The exit status is asserted
# too, since that is what CI branches on.
set -euo pipefail

# The checker is normally its sibling; the flake check passes it in from the
# store, where the two have no directory in common.
checker="${1:-$(cd "$(dirname "$0")" && pwd)/check-skipped-tests.py}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# trx <file> then rows of "id|class|name|outcome|message", message "-" for none.
trx() {
  local file="$1"
  shift
  {
    echo '<?xml version="1.0" encoding="utf-8"?>'
    echo '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010">'
    echo '<Results>'
    local row id class name outcome message
    for row in "$@"; do
      IFS='|' read -r id class name outcome message <<<"$row"
      echo "<UnitTestResult testId=\"$id\" testName=\"$name\" outcome=\"$outcome\">"
      if [ "$message" != "-" ]; then
        echo "<Output><ErrorInfo><Message>$message</Message></ErrorInfo></Output>"
      fi
      echo '</UnitTestResult>'
    done
    echo '</Results>'
    echo '<TestDefinitions>'
    for row in "$@"; do
      IFS='|' read -r id class name outcome message <<<"$row"
      echo "<UnitTest name=\"$name\" id=\"$id\"><TestMethod className=\"$class\" name=\"$name\" /></UnitTest>"
    done
    echo '</TestDefinitions>'
    echo '</TestRun>'
  } > "$file"
}

trx "$tmp/default.trx" \
  "1|N.TestA|passes|Passed|-" \
  "2|N.TestA|fails|Failed|boom" \
  "3|N.TestA|darwin only|NotExecuted|not a Darwin host" \
  "4|N.TestA|explicit|NotExecuted|-" \
  "5|N.TestA|large|NotExecuted|OneTimeSetUp: " \
  "6|N.TestB|new skip|NotExecuted|no compiler" \
  "7|N.TestB|reason changed|NotExecuted|a new reason" \
  "8|N.TestB|now runs|Passed|-" \
  "9|N.TestB|inconclusive|Inconclusive|cannot tell" \
  "10|N.TestC|row(&quot;linux&quot;)|Passed|-" \
  "11|N.TestC|row(&quot;darwin&quot;)|NotExecuted|Darwin only"
# The large step records "passes" too, as a step that filters a test out may:
# a test some file ran is run, whichever file comes last.
trx "$tmp/large.trx" \
  "12|N.TestA|large|Passed|-" \
  "1|N.TestA|passes|NotExecuted|filtered out"

cat > "$tmp/allow.json" <<'EOF'
[
  {"fixture": "N.TestA", "test": "darwin only", "message": "not a Darwin host", "why": "Linux CI"},
  {"fixture": "N.TestA", "test": "explicit", "message": "", "why": "Explicit"},
  {"fixture": "N.TestB", "test": "reason changed", "message": "the old reason", "why": "Linux CI"},
  {"fixture": "N.TestB", "test": "now runs", "message": "not a Darwin host", "why": "Linux CI"},
  {"fixture": "N.TestB", "test": "deleted", "message": "gone", "why": "Linux CI"},
  {"fixture": "N.TestC", "test": "row(\"darwin\")", "message": "Darwin only", "why": "Linux CI"}
]
EOF

set +e
out="$(python3 "$checker" "$tmp/allow.json" "$tmp/default.trx" "$tmp/large.trx" 2>&1)"
status=$?
set -e

expected_hits=(
  "skipped, not allowlisted ('no compiler'): N.TestB :: new skip"
  "skipped with 'a new reason', allowlisted as 'the old reason': N.TestB :: reason changed"
  "ran, but is allowlisted as skipping: N.TestB :: now runs"
  "skipped, not allowlisted ('cannot tell'): N.TestB :: inconclusive"
  "allowlisted, but no TRX file records it: N.TestB :: deleted"
)

fail=0
if [ "$status" -ne 1 ]; then
  echo "FAIL: expected exit 1 on unexpected skips, got $status" >&2
  fail=1
fi
for hit in "${expected_hits[@]}"; do
  if ! grep -qxF "  $hit" <<<"$out"; then
    echo "FAIL: not reported: $hit" >&2
    fail=1
  fi
done
reported="$(grep -c '^  ' <<<"$out" || true)"
if [ "$reported" -ne "${#expected_hits[@]}" ]; then
  echo "FAIL: expected ${#expected_hits[@]} reports, got $reported" >&2
  fail=1
fi
# The report says where an expected skip belongs.
if ! grep -qF "$tmp/allow.json" <<<"$out"; then
  echo "FAIL: the report does not name the allowlist" >&2
  fail=1
fi

# The default file alone: the large fixture is now skipped everywhere.
set +e
alone="$(python3 "$checker" "$tmp/allow.json" "$tmp/default.trx" 2>&1)"
set -e
if ! grep -qxF "  skipped, not allowlisted ('OneTimeSetUp: '): N.TestA :: large" <<<"$alone"; then
  echo "FAIL: a test only a missing step runs was not reported" >&2
  fail=1
fi

# A run that skipped exactly what the allowlist expects passes, and says so.
cat > "$tmp/clean.json" <<'EOF'
[
  {"fixture": "N.TestA", "test": "darwin only", "message": "not a Darwin host", "why": "Linux CI"},
  {"fixture": "N.TestA", "test": "explicit", "message": "", "why": "Explicit"}
]
EOF
trx "$tmp/clean.trx" \
  "1|N.TestA|passes|Passed|-" \
  "3|N.TestA|darwin only|NotExecuted|not a Darwin host" \
  "4|N.TestA|explicit|NotExecuted|-"
if ! python3 "$checker" "$tmp/clean.json" "$tmp/clean.trx" | grep -qF '2 of 3 tests skipped'; then
  echo "FAIL: a run skipping only what was expected was not reported clean" >&2
  fail=1
fi

# Usage errors exit 2, not 0 or 1.
usage() {
  local what="$1"
  shift
  set +e
  python3 "$checker" "$@" >/dev/null 2>&1
  local got=$?
  set -e
  if [ "$got" -ne 2 ]; then
    echo "FAIL: expected exit 2 for $what, got $got" >&2
    fail=1
  fi
}
printf '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"/>\n' > "$tmp/empty.trx"
echo '{}' > "$tmp/object.json"
echo '[{"fixture": "N.TestA", "test": "explicit", "message": ""}]' > "$tmp/nowhy.json"
echo '[{"fixture": "N.TestA", "test": "explicit", "message": "", "why": " "}]' > "$tmp/blankwhy.json"
printf '[%s,%s]\n' \
  '{"fixture": "N.TestA", "test": "explicit", "message": "", "why": "x"}' \
  '{"fixture": "N.TestA", "test": "explicit", "message": "", "why": "y"}' > "$tmp/twice.json"
usage "no TRX files" "$tmp/clean.json"
usage "no arguments"
usage "a TRX file with no results" "$tmp/clean.json" "$tmp/empty.trx"
usage "a missing TRX file" "$tmp/clean.json" "$tmp/absent.trx"
usage "an allowlist that is not a list" "$tmp/object.json" "$tmp/clean.trx"
usage "an entry without a why" "$tmp/nowhy.json" "$tmp/clean.trx"
usage "an entry with a blank why" "$tmp/blankwhy.json" "$tmp/clean.trx"
usage "a test named twice" "$tmp/twice.json" "$tmp/clean.trx"

if [ "$fail" -ne 0 ]; then
  echo "--- checker output ---" >&2
  echo "$out" >&2
  exit 1
fi
echo "skipped-tests contract: ${#expected_hits[@]} reports made, silent shapes silent"
