#!/bin/sh
# Runs every Darwin probe that needs root, and records what each printed
# beside the probe that printed it.
#
#   sudo sh docs/probes/darwin-root/run.sh
#
# What it does, in order:
#   1. Compiles the probes as the user who ran sudo (never as root), with the
#      system compiler, into a fresh temporary directory, and copies the
#      binaries into a second one only root can write.
#   2. Makes one fresh directory under /private/tmp (mode 0711, so the probes'
#      children can reach their files by name), in which every file probe
#      works. Nothing outside it is created, changed or removed, except the
#      output files below.
#   3. Runs, one after another:
#        root-files.c, credentials.c, bind-uids.c, port-range.c (this directory)
#        ../faulting-file-write/faulting-file-write.c
#        ../poll-entry-count/poll-entry-count.c
#        ../privileged-port/privileged-port.c
#        ../../plans/2026-08-23-posix-kernel-extraction/setresid.c
#      Each probe's other users are forked children that take uid 501, 502
#      (factotum) or 504 (work) with setuid(2) and are waited for; each has an
#      alarm(2) that ends it if it hangs. No account is created or changed.
#   4. port-range changes net.inet.ip.portrange.{first,last,hifirst,hilast,
#      lowfirst,lowlast} for a few milliseconds at a time, and puts each back
#      at once. This script also records all six before anything runs, and on
#      exit (however it exits, unless it is SIGKILLed) writes back any that
#      differ and reads each back to check.
#   5. Removes both temporary directories, and gives the output files to the
#      user who ran sudo.
#
# A probe's output is written beside its final name as <name>.running and
# moved into place only when the probe exits 0. A probe that does not build,
# exits non-zero or is interrupted leaves no file under its final name (an
# earlier one is removed, so it cannot pass for this run's); what it did print
# is kept as <name>.FAILED.txt. The script then exits non-zero and lists the
# probes that failed. It also exits non-zero if a sysctl could not be put
# back, and says loudly which, and to what.
#
# Run without root, it does the same with the probes' own SKIP rows for what
# needs root, and writes its outputs to a temporary directory (which it names)
# instead of into the repository.
#
# Outputs, when run as root (DARWIN is the kernel's release, e.g. 27.0):
#   docs/probes/darwin-root/{root-files,credentials,bind-uids,port-range}.darwin-DARWIN-root.txt
#   docs/probes/darwin-root/run.darwin-DARWIN-root.log
#   docs/probes/faulting-file-write/darwin-<uname -r>-arm64-apfs-root.txt
#   docs/probes/poll-entry-count/measured-darwin-DARWIN-uid0.txt
#   docs/probes/privileged-port/measured-darwin-DARWIN-root.txt
#   docs/plans/2026-08-23-posix-kernel-extraction/setresid.darwin-DARWIN-root.txt

set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

if [ "$(uname -s)" != Darwin ]; then
    echo "run.sh: these probes are Darwin's" >&2
    exit 2
fi

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
RELEASE=$(uname -r)
DARWIN=$(echo "$RELEASE" | cut -d. -f1-2)
ARCH=$(uname -m)

if [ "$(id -u)" = 0 ]; then
    AS_ROOT=1
    BUILDER=${SUDO_USER:-}
    OWNER_UID=${SUDO_UID:-0}
    OWNER_GID=${SUDO_GID:-0}
else
    AS_ROOT=0
    BUILDER=
fi

LOG=
say() {
    echo "$*"
    if [ -n "$LOG" ]; then echo "$*" >> "$LOG"; fi
}
warn() {
    echo "$*" >&2
    if [ -n "$LOG" ]; then echo "$*" >> "$LOG"; fi
}

SYSCTLS="net.inet.ip.portrange.first net.inet.ip.portrange.last net.inet.ip.portrange.hifirst net.inet.ip.portrange.hilast net.inet.ip.portrange.lowfirst net.inet.ip.portrange.lowlast"
ORIGINAL=
for s in $SYSCTLS; do
    v=$(sysctl -n "$s") || { echo "run.sh: cannot read $s" >&2; exit 2; }
    ORIGINAL="$ORIGINAL $s=$v"
done

# Put back every sysctl that differs from what it was before the run, and
# check each by reading it back. Sets RESTORE_FAILED=1 for any that is not
# now what it was.
RESTORE_FAILED=0
restore_sysctls() {
    for pair in $ORIGINAL; do
        name=${pair%%=*}
        want=${pair#*=}
        now=$(sysctl -n "$name" 2>/dev/null)
        [ "$now" = "$want" ] && continue
        sysctl -w "$pair" > /dev/null 2>&1
        rc=$?
        back=$(sysctl -n "$name" 2>/dev/null)
        if [ "$rc" = 0 ] && [ "$back" = "$want" ]; then
            say "# restored $pair (it was $now)"
        else
            RESTORE_FAILED=1
            warn "!!!!!!!! $name is ${back:-unreadable}, but it was $want before this run, and writing it back failed (sysctl -w exit $rc)."
            warn "!!!!!!!! Put it back by hand: sudo sysctl -w $pair"
        fi
    done
}

BUILD=
BIN=
WORK=
PROBES=
FINALS=
RAN=
FAILED=
CURRENT_NAME=
CURRENT_OUT=
CURRENT_TMP=

failed_name() {
    echo "${1%.txt}.FAILED.txt"
}

# The probe `$1` failed (`$4` says how): nothing stays under its final name
# `$2`, and what it printed into `$3` (empty if it never ran), if anything,
# is kept as the FAILED file.
probe_failed() {
    rm -f "$2"
    f=$(failed_name "$2")
    if [ -n "$3" ] && [ -s "$3" ]; then
        mv "$3" "$f"
        say "# FAILED $1 ($4): removed $2; what it printed is in $f"
    else
        [ -n "$3" ] && rm -f "$3"
        rm -f "$f"
        say "# FAILED $1 ($4): removed $2; it printed nothing"
    fi
    FAILED="$FAILED $1"
}

on_exit() {
    status=$?
    trap - EXIT INT TERM HUP
    if [ -n "$CURRENT_TMP" ]; then
        probe_failed "$CURRENT_NAME" "$CURRENT_OUT" "$CURRENT_TMP" "interrupted"
        CURRENT_TMP=
    fi
    for p in $PROBES; do
        case " $RAN " in
            *" $p "*) ;;
            *) say "# NOT RUN $p: the script stopped first"; FAILED="$FAILED $p" ;;
        esac
    done
    restore_sysctls
    if [ "$AS_ROOT" = 1 ]; then
        for f in $LOG $FINALS; do
            [ -e "$f" ] && chown "$OWNER_UID:$OWNER_GID" "$f"
            g=$(failed_name "$f")
            [ -e "$g" ] && chown "$OWNER_UID:$OWNER_GID" "$g"
        done
    fi
    case "$WORK" in
        /private/tmp/darwin-root.*) rm -rf "$WORK" ;;
    esac
    case "$BIN" in
        /private/tmp/darwin-root-bin.*) rm -rf "$BIN" ;;
    esac
    case "$BUILD" in
        /private/tmp/darwin-root-build.*) rm -rf "$BUILD" ;;
    esac
    for d in "$WORK" "$BIN" "$BUILD"; do
        [ -n "$d" ] && [ -e "$d" ] && warn "# WARNING: could not remove $d"
    done
    if [ "$RESTORE_FAILED" = 1 ]; then
        warn "!!!!!!!! At least one sysctl was not put back: see the lines above."
        [ "$status" = 0 ] && status=3
    fi
    if [ -n "$FAILED" ] && [ "$status" = 0 ]; then status=1; fi
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

if [ "$AS_ROOT" = 1 ]; then
    OUT_ROOT="$REPO/docs/probes/darwin-root"
    OUT_FW="$REPO/docs/probes/faulting-file-write"
    OUT_POLL="$REPO/docs/probes/poll-entry-count"
    OUT_PP="$REPO/docs/probes/privileged-port"
    OUT_SR="$REPO/docs/plans/2026-08-23-posix-kernel-extraction"
    SUFFIX=root
    POLL_OUT="$OUT_POLL/measured-darwin-$DARWIN-uid0.txt"
else
    OUT=$(mktemp -d /private/tmp/darwin-root-out.XXXXXX)
    OUT_ROOT=$OUT/darwin-root
    OUT_FW=$OUT/faulting-file-write
    OUT_POLL=$OUT/poll-entry-count
    OUT_PP=$OUT/privileged-port
    OUT_SR=$OUT/setresid
    mkdir -p "$OUT_ROOT" "$OUT_FW" "$OUT_POLL" "$OUT_PP" "$OUT_SR"
    SUFFIX=uid$(id -u)
    POLL_OUT="$OUT_POLL/measured-darwin-$DARWIN-$SUFFIX.txt"
fi
LOG="$OUT_ROOT/run.darwin-$DARWIN-$SUFFIX.log"
: > "$LOG"

# Every probe this run makes, and its final output. Each output, and any
# FAILED or .running file beside it from an earlier run, is removed before
# anything runs, so whatever is under a final name afterwards is this run's.
PROBES="root-files credentials bind-uids port-range faulting-file-write poll-entry-count privileged-port setresid"
FINALS="$OUT_ROOT/root-files.darwin-$DARWIN-$SUFFIX.txt $OUT_ROOT/credentials.darwin-$DARWIN-$SUFFIX.txt $OUT_ROOT/bind-uids.darwin-$DARWIN-$SUFFIX.txt $OUT_ROOT/port-range.darwin-$DARWIN-$SUFFIX.txt $OUT_FW/darwin-$RELEASE-$ARCH-apfs-$SUFFIX.txt $POLL_OUT $OUT_PP/measured-darwin-$DARWIN-$SUFFIX.txt $OUT_SR/setresid.darwin-$DARWIN-$SUFFIX.txt"
for f in $FINALS; do
    rm -f "$f" "$(failed_name "$f")" "$f.running"
done
RAN=

say "# run.sh: $(uname -s) $RELEASE $ARCH, macOS $(sw_vers -productVersion), as uid $(id -u), started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "# sysctls before:$ORIGINAL"
for acct in factotum:502 work:504; do
    name=${acct%%:*}
    want=${acct#*:}
    got=$(id -u "$name" 2>/dev/null || echo none)
    [ "$got" = "$want" ] || say "# WARNING: account $name has uid $got, not $want; the probes use uid $want by number"
done

# 1. Compile, as the user who ran sudo.
if [ -n "$BUILDER" ]; then
    BUILD=$(sudo -u "$BUILDER" mktemp -d /private/tmp/darwin-root-build.XXXXXX)
else
    BUILD=$(mktemp -d /private/tmp/darwin-root-build.XXXXXX)
fi
compile() {
    name=$1
    src=$2
    flags=$3
    if [ -n "$BUILDER" ]; then
        sudo -u "$BUILDER" -H /usr/bin/cc $flags -o "$BUILD/$name" "$src" >> "$LOG" 2>&1
    else
        /usr/bin/cc $flags -o "$BUILD/$name" "$src" >> "$LOG" 2>&1
    fi
    if [ $? = 0 ]; then
        say "# built $name"
    else
        rm -f "$BUILD/$name"
        say "# FAILED to build $name from $src"
    fi
}
compile root-files "$HERE/root-files.c" "-Wall -Werror -O1"
compile credentials "$HERE/credentials.c" "-Wall -Werror -O1"
compile bind-uids "$HERE/bind-uids.c" "-Wall -Werror -O1"
compile port-range "$HERE/port-range.c" "-Wall -Werror -O1"
compile faulting-file-write "$REPO/docs/probes/faulting-file-write/faulting-file-write.c" "-Wall -O1"
compile poll-entry-count "$REPO/docs/probes/poll-entry-count/poll-entry-count.c" "-Wall -O1"
compile privileged-port "$REPO/docs/probes/privileged-port/privileged-port.c" "-Wall -O1"
compile setresid "$REPO/docs/plans/2026-08-23-posix-kernel-extraction/setresid.c" "-Wall -O1"

# The binaries root runs live where only root can change them.
BIN=$(mktemp -d /private/tmp/darwin-root-bin.XXXXXX)
chmod 0700 "$BIN"
for f in "$BUILD"/*; do
    [ -f "$f" ] && cp "$f" "$BIN/"
done

# 2. The one directory the file probes work in.
WORK=$(mktemp -d /private/tmp/darwin-root.XXXXXX)
chmod 0711 "$WORK"

# 3. Run each probe: `run <probe> <final output> [args...]`.
run() {
    name=$1
    out=$2
    shift 2
    RAN="$RAN $name"
    if [ ! -x "$BIN/$name" ]; then
        probe_failed "$name" "$out" "" "it did not build"
        return
    fi
    tmp="$out.running"
    rm -f "$tmp"
    CURRENT_NAME=$name
    CURRENT_OUT=$out
    CURRENT_TMP=$tmp
    start=$(date +%s)
    "$BIN/$name" "$@" > "$tmp" 2>> "$LOG"
    rc=$?
    CURRENT_TMP=
    if [ "$rc" = 0 ]; then
        mv "$tmp" "$out"
        say "# ran $name -> $out: exit 0, $(( $(date +%s) - start )) s"
    else
        probe_failed "$name" "$out" "$tmp" "exit $rc after $(( $(date +%s) - start )) s"
    fi
}
mkdir -m 0711 "$WORK/rf" "$WORK/cr" "$WORK/fw"
run root-files "$OUT_ROOT/root-files.darwin-$DARWIN-$SUFFIX.txt" "$WORK/rf"
run credentials "$OUT_ROOT/credentials.darwin-$DARWIN-$SUFFIX.txt" "$WORK/cr"
run bind-uids "$OUT_ROOT/bind-uids.darwin-$DARWIN-$SUFFIX.txt"
run port-range "$OUT_ROOT/port-range.darwin-$DARWIN-$SUFFIX.txt"
run faulting-file-write "$OUT_FW/darwin-$RELEASE-$ARCH-apfs-$SUFFIX.txt" "$WORK/fw"
run poll-entry-count "$POLL_OUT"
run privileged-port "$OUT_PP/measured-darwin-$DARWIN-$SUFFIX.txt"
# setresid makes its files (on Linux; Darwin's rows make none) in $TMPDIR,
# which must be writable by everyone, as /tmp is.
mkdir -m 0700 "$WORK/sr" && chmod 01777 "$WORK/sr"
TMPDIR="$WORK/sr"
export TMPDIR
run setresid "$OUT_SR/setresid.darwin-$DARWIN-$SUFFIX.txt"
unset TMPDIR

# 4: put the sysctls back (on_exit checks again) and say what they are.
restore_sysctls
AFTER=
for s in $SYSCTLS; do
    AFTER="$AFTER $s=$(sysctl -n "$s")"
done
say "# sysctls after:$AFTER"
[ "$AFTER" = "$ORIGINAL" ] || warn "!!!!!!!! WARNING: the sysctls differ from before the run"
say "# finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ "$AS_ROOT" = 1 ]; then
    echo "Outputs are in the repository; the log is $LOG"
else
    echo "Not root: outputs are in $OUT"
fi
if [ -n "$FAILED" ]; then
    warn "FAILED probes:$FAILED (see the log, $LOG)"
    exit 1
fi
exit 0
