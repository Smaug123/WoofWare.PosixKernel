#!/bin/sh
# Usage: shapes.sh LAUNCH-BINARY — runs launch.c's probe under each launch shape.
# The probe reports on fd 3, which is this script's stdout.
L=$1
T=$(mktemp -d)
printf 'abc' > "$T/file"
mkfifo "$T/errfifo"
run() { echo "### $1"; sh -c "$2" 3>&1; }
run "harness-like: stdin pipe (writer gone), stdout pipe, stderr a *named* FIFO (sh has no anonymous third pipe)" \
    "cat $T/errfifo >/dev/null & : | $L 2>$T/errfifo | cat; wait"
run "stdin pipe holding 'abc', writer gone" "printf abc | $L 2>/dev/null | cat"
run "stdin /dev/null, 2>&1 into one pipe" "$L </dev/null 2>&1 | cat"
run "stdin a regular file" "$L <$T/file >/dev/null 2>&1"
run "stdin closed" "$L <&- >/dev/null 2>&1"
run "stdout a regular file (O_TRUNC), stderr appended to one" "$L </dev/null >$T/out 2>>$T/err"
run "all three a fresh terminal (forkpty)" "$L pty"
rm -rf "$T"
