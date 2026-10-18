#!/usr/bin/env bash
# Executable contract for check-test-boundaries.py.
#
# Builds a throwaway test directory holding every shape the check has an
# opinion about, and asserts the report names exactly the lines that name the
# thread table outside its allowlist, in code, type annotations, docstrings,
# comments and strings alike, and exactly the allowlist entries that exempt
# nothing. The silent shapes are as much the point: a check that fires on
# `UnixThreadState`, on `Lone.threadMap` or on the words "thread table" is a
# check nobody keeps. The exit status is asserted too, since that is what the
# flake check branches on.
set -euo pipefail

# The checker is normally its sibling; the flake check passes it in from the
# store, where the two have no directory in common.
checker="${1:-$(cd "$(dirname "$0")" && pwd)/check-test-boundaries.py}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Every file on the thread table's allowlist, each naming the table, but for
# TestBootImage.fs, which names nothing, and TestWakeMemo.fs, which is absent:
# both entries exempt nothing, and are reported.
allowed=(Proc.fs Lone.fs ForgedThread.fs TestUnixThreadTable.fs TestSleeperIndex.fs TestProcessView.fs)

mkdir -p "$tmp/tests/Nested"
for file in "${allowed[@]}"; do
  printf 'module M\nlet t : ThreadTable<int> = UnixThreadTable.empty\nlet u = Proc.threadTable pid system\n' > "$tmp/tests/$file"
done
printf 'module M\n/// Holds by reflection that parking is not public.\nlet n = 1\n' > "$tmp/tests/TestBootImage.fs"

cat > "$tmp/tests/TestA.fs" <<'EOF'
module TestA
let parked = UnixThreadTable.parkedFor 1 (Lone.threadTable system)
let annotated (threads : ThreadTable<int>) = threads
/// Reads `UnixThreadTable.get` of the thread.
let docstring = 1
// The table refuses this (`UnixThreadTable.withPark`).
let comment = 2
let reflected = assembly.GetType ("WoofWare.PosixKernel.UnixThreadTable", true)
let forged = Proc.mapThreadTable pid id system
let ``UnixThreadTable asks nothing`` () = ()
let silentState = UnixThreadState.park (Lone.thread 1 system)
let silentMap = Lone.threadMap system |> Map.keys
/// The process's thread table, and its Threads, ThreadIds and threads.
let silentWords = Proc.parkedIn caller system
EOF

cat > "$tmp/tests/Nested/TestB.fs" <<'EOF'
module TestB
let owed = UnixThreadTable.owedBy 0 table
EOF

cat > "$tmp/tests/README.md" <<'EOF'
`UnixThreadTable.parkedFor` is not read here.
EOF

cat > "$tmp/tests/Tests.fsproj" <<'EOF'
<Compile Include="TestUnixThreadTable.fs" />
EOF

mkdir -p "$tmp/tests/obj/Debug" "$tmp/tests/bin"
printf 'let t = UnixThreadTable.empty\n' > "$tmp/tests/obj/Debug/Generated.fs"
printf 'let t = UnixThreadTable.empty\n' > "$tmp/tests/bin/Built.fs"

set +e
out="$(python3 "$checker" "$tmp/tests" 2>&1)"
status=$?
set -e

expected_hits=(
  "TestA.fs:2: ThreadTable:"
  "TestA.fs:2: threadTable:"
  "TestA.fs:3: ThreadTable:"
  "TestA.fs:4: ThreadTable:"
  "TestA.fs:6: ThreadTable:"
  "TestA.fs:8: ThreadTable:"
  "TestA.fs:9: ThreadTable:"
  "TestA.fs:10: ThreadTable:"
  "Nested/TestB.fs:2: ThreadTable:"
  "TestBootImage.fs: names nothing the rule matches"
  "TestWakeMemo.fs: is not there"
)

fail=0
if [ "$status" -ne 1 ]; then
  echo "FAIL: expected exit 1 on a test directory crossing a boundary, got $status" >&2
  fail=1
fi
for hit in "${expected_hits[@]}"; do
  if ! grep -qF "  $hit" <<<"$out"; then
    echo "FAIL: not reported: $hit" >&2
    fail=1
  fi
done
reported="$(grep -c '^  ' <<<"$out" || true)"
if [ "$reported" -ne "${#expected_hits[@]}" ]; then
  echo "FAIL: expected ${#expected_hits[@]} reports, got $reported" >&2
  fail=1
fi

# The allowlisted files name the table freely; the per-thread queries, the
# public thread state and the plain words beside them are silent.
for file in "${allowed[@]}"; do
  if grep -qF "  $file:" <<<"$out"; then
    echo "FAIL: allowlisted $file was reported" >&2
    fail=1
  fi
done
if grep -qE 'TestA\.fs:(1|5|7|11|12|13|14): ' <<<"$out"; then
  echo "FAIL: a silent line was reported" >&2
  fail=1
fi
if grep -qE 'README|fsproj' <<<"$out"; then
  echo "FAIL: a non-.fs file was scanned" >&2
  fail=1
fi
if grep -qE 'Generated|Built' <<<"$out"; then
  echo "FAIL: build output under obj/ or bin/ was scanned" >&2
  fail=1
fi
# The report says what to do instead.
if ! grep -qF 'ForgedThread' <<<"$out"; then
  echo "FAIL: the report does not say where to add a helper" >&2
  fail=1
fi

# A clean directory, its allowlist all needed, passes, and says how much it read.
mkdir -p "$tmp/clean"
for file in "${allowed[@]}" TestWakeMemo.fs TestBootImage.fs; do
  printf 'module M\nlet t = UnixThreadTable.empty\n' > "$tmp/clean/$file"
done
printf 'module C\nlet c = Lone.parkOf 1 system\n' > "$tmp/clean/C.fs"
if ! python3 "$checker" "$tmp/clean" | grep -q 'none crossed in 9 files'; then
  echo "FAIL: a clean directory was not reported clean" >&2
  fail=1
fi

# A directory with no sources is a usage error, not a pass.
mkdir -p "$tmp/empty"
set +e
python3 "$checker" "$tmp/empty" >/dev/null 2>&1
empty_status=$?
set -e
if [ "$empty_status" -ne 2 ]; then
  echo "FAIL: expected exit 2 on a directory with no .fs files, got $empty_status" >&2
  fail=1
fi

# So is a call without the directory.
set +e
python3 "$checker" >/dev/null 2>&1
usage_status=$?
set -e
if [ "$usage_status" -ne 2 ]; then
  echo "FAIL: expected exit 2 when called without a directory, got $usage_status" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "--- checker output ---" >&2
  echo "$out" >&2
  exit 1
fi
echo "test-boundaries contract: ${#expected_hits[@]} reports made, silent shapes silent"
