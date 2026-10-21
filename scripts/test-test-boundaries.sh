#!/usr/bin/env bash
# Executable contract for check-test-boundaries.py.
#
# Builds a throwaway test directory holding every shape the check has an
# opinion about, and asserts the report names exactly the lines that name an
# internal outside its rule's allowlist, in code, type annotations, docstrings,
# comments and strings alike, and exactly the allowlist entries that exempt
# nothing. The silent shapes are as much the point: a check that fires on
# `UnixThreadState`, on `Lone.threadMap`, on `UnixMachineState`, on a union
# case named `Processes` or on the words "thread table" is a check nobody
# keeps. The exit status is asserted too, since that is what the flake check
# branches on.
set -euo pipefail

# The checker is normally its sibling; the flake check passes it in from the
# store, where the two have no directory in common.
checker="${1:-$(cd "$(dirname "$0")" && pwd)/check-test-boundaries.py}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# One use of each rule's internal, for the allowlisted files to hold.
thread_use='let u = Proc.threadTable pid system'
machine_use='let m = system.Machine'
table_use='let t = ProcessTable.empty'
memo_use='let s = system.Sweep'
view_use='let v = ProcessView.unfocus view'
state_use='let r = UnixSystemState.fileDescriptors view'

# `allowed <directory> <file> <use>...` writes <file> holding each use: one
# for each rule that allows the file, as the checker's allowlists do.
allowed() {
  local directory="$1" file="$2"
  shift 2
  { printf 'module M\n'; printf '%s\n' "$@"; } > "$directory/$file"
}

# Every allowlisted file, each using every internal its rules allow it, but
# for three stale entries, which are reported: TestBootImage.fs names no
# thread table, TestUnixWait.fs names no process table, and
# TestUnixThreadTable.fs is absent.
mkdir -p "$tmp/tests/Nested"
allowed "$tmp/tests" Proc.fs "$thread_use" "$table_use" "$view_use" "$state_use"
allowed "$tmp/tests" Lone.fs "$thread_use"
allowed "$tmp/tests" ForgedThread.fs "$thread_use"
allowed "$tmp/tests" TestSleeperIndex.fs "$thread_use" "$table_use"
allowed "$tmp/tests" TestWakeMemo.fs "$thread_use" "$table_use" "$memo_use"
allowed "$tmp/tests" TestProcessView.fs "$thread_use" "$machine_use" "$table_use" "$view_use"
allowed "$tmp/tests" Kernel.fs "$machine_use"
allowed "$tmp/tests" TestMultiProcessFuzz.fs "$table_use" "$memo_use"
allowed "$tmp/tests" TestBootImage.fs 'let records = [ typeof<ProcessSlot<int, string>> ]'
allowed "$tmp/tests" TestUnixWait.fs 'let woken, after = UnixWait.wake parked'
exempt=(Proc.fs Lone.fs ForgedThread.fs TestSleeperIndex.fs TestWakeMemo.fs TestProcessView.fs Kernel.fs TestMultiProcessFuzz.fs TestBootImage.fs TestUnixWait.fs)

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

cat > "$tmp/tests/TestC.fs" <<'EOF'
module TestC
let platform = system.Machine.UnixPlatform
let rebuilt = { system with Machine = machine }
    Scheduling =
let uptime = row.System.Scheduling.NanosecondsSinceBoot
let booted = (Launched.boot image).Machine
/// Reads `UnixSystem.Machine` of the system.
let both = { system with Count = 1; Scheduling = scheduling }
let slot = ProcessTable.find "test" key table
let typed : ProcessSlot<int, string> = slot
let others = focused.Others
let processes = system.Processes
    Processes = table
let remembered = machine.Sweep.Remembered
    Sweep = WakeMemo.none
let back = ProcessView.unfocus view
let registry = UnixSystemState.fileDescriptors view
// `Lone.UnixSystemState.signalNumbering` reads the platform.
let silentQuery = UnixSystem.platform system
let silentMachine = (Kernel.machine system).Sockets
let silentClock = UnixSchedulingState.advanceClock 1L (Kernel.scheduling system)
let silentType : UnixMachineState = machine
let silentMap = Kernel.mapMachine (fun machine -> { machine with Sockets = sockets }) system
let silentCase = Crowd.Processes
let silentLabels = { Platform = platform; ProcessCount = 2; MachineCount = 1 }
type private Sweep = | Op of int
let silentSweep (op : Op) : Sweep = Op.Sweep
let silentView : ProcessView<int, string> = Proc.view pid system
let silentIds = UnixSystem.processIds system
let silentDefect = UnixSystemDefect.LiveProcessIdsMismatch
let silentNumbering = Kernel.signalNumbering system
/// The machine's scheduling, the process table, the wake memo and a process's view.
let silentField = machine.UnixPlatform
EOF

# A read Fantomas puts at the start of the line after its receiver.
cat > "$tmp/tests/TestD.fs" <<'EOF'
module TestD
let booted =
    (image |> boot)
        .Machine.SoMaxConn
let processes =
    (system)
        .Processes
let remembered =
    (system)
        .Sweep
let silentPiped =
    (image |> boot |> Kernel.machine)
        .UnixPlatform
EOF

cat > "$tmp/tests/Nested/TestB.fs" <<'EOF'
module TestB
let owed = UnixThreadTable.owedBy 0 table
EOF

cat > "$tmp/tests/README.md" <<'EOF'
`UnixThreadTable.parkedFor` is not read here, nor `system.Machine`.
EOF

cat > "$tmp/tests/Tests.fsproj" <<'EOF'
<Compile Include="TestUnixThreadTable.fs" />
EOF

mkdir -p "$tmp/tests/obj/Debug" "$tmp/tests/bin"
printf 'let t = UnixThreadTable.empty\nlet m = system.Machine\n' > "$tmp/tests/obj/Debug/Generated.fs"
printf 'let t = UnixThreadTable.empty\nlet m = system.Machine\n' > "$tmp/tests/bin/Built.fs"

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
  "TestC.fs:2: system.Machine:"
  "TestC.fs:3: with Machine =:"
  "TestC.fs:4: Scheduling =:"
  "TestC.fs:5: row.System.Scheduling:"
  "TestC.fs:6: ).Machine:"
  "TestC.fs:7: UnixSystem.Machine:"
  "TestC.fs:8: ; Scheduling =:"
  "TestC.fs:9: ProcessTable:"
  "TestC.fs:10: ProcessSlot:"
  "TestC.fs:11: focused.Others:"
  "TestC.fs:12: system.Processes:"
  "TestC.fs:13: Processes =:"
  "TestC.fs:14: machine.Sweep:"
  "TestC.fs:15: Sweep =:"
  "TestC.fs:16: ProcessView.:"
  "TestC.fs:17: UnixSystemState:"
  "TestC.fs:18: UnixSystemState:"
  "TestD.fs:4: .Machine:"
  "TestD.fs:7: .Processes:"
  "TestD.fs:10: .Sweep:"
  "TestBootImage.fs: names nothing the rule matches"
  "TestUnixWait.fs: names nothing the rule matches"
  "TestUnixThreadTable.fs: is not there"
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

# The allowlisted files use their internals freely; the per-thread queries, the
# public queries, `Kernel`'s helpers, the machine's own fields, names that
# merely contain a field's name, and the plain words beside them are silent.
for file in "${exempt[@]}"; do
  if grep -qE "^  $file:[0-9]" <<<"$out"; then
    echo "FAIL: allowlisted $file was reported" >&2
    fail=1
  fi
done
if grep -qE 'TestA\.fs:(1|5|7|11|12|13|14): ' <<<"$out"; then
  echo "FAIL: a silent line of TestA.fs was reported" >&2
  fail=1
fi
if grep -qE 'TestC\.fs:(1|19|2[0-9]|3[0-4]): ' <<<"$out"; then
  echo "FAIL: a silent line of TestC.fs was reported" >&2
  fail=1
fi
if grep -qE 'TestD\.fs:(1|2|3|5|6|8|9|11|12|13): ' <<<"$out"; then
  echo "FAIL: a silent line of TestD.fs was reported" >&2
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
for helper in ForgedThread mapMachine UnixSystem.processIds Proc.view Kernel.signalNumbering; do
  if ! grep -qF "$helper" <<<"$out"; then
    echo "FAIL: the report does not name $helper" >&2
    fail=1
  fi
done

# A clean directory, its allowlists all needed, passes, and says how much it read.
mkdir -p "$tmp/clean"
allowed "$tmp/clean" Proc.fs "$thread_use" "$table_use" "$view_use" "$state_use"
allowed "$tmp/clean" Lone.fs "$thread_use"
allowed "$tmp/clean" ForgedThread.fs "$thread_use"
allowed "$tmp/clean" TestUnixThreadTable.fs "$thread_use"
allowed "$tmp/clean" TestSleeperIndex.fs "$thread_use" "$table_use"
allowed "$tmp/clean" TestWakeMemo.fs "$thread_use" "$table_use" "$memo_use"
allowed "$tmp/clean" TestProcessView.fs "$thread_use" "$machine_use" "$table_use" "$view_use"
allowed "$tmp/clean" TestBootImage.fs "$thread_use" "$table_use"
allowed "$tmp/clean" Kernel.fs "$machine_use"
allowed "$tmp/clean" TestMultiProcessFuzz.fs "$table_use" "$memo_use"
allowed "$tmp/clean" TestUnixWait.fs "$table_use"
printf 'module C\nlet c = Lone.parkOf 1 system\nlet p = UnixSystem.platform system\n' > "$tmp/clean/C.fs"
if ! python3 "$checker" "$tmp/clean" | grep -q 'none crossed in 12 files'; then
  echo "FAIL: a clean directory was not reported clean" >&2
  python3 "$checker" "$tmp/clean" >&2 || true
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
