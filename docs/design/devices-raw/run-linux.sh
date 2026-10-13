#!/bin/sh
# Usage: run-linux.sh probe [shell-command-suffix] — compiles /probe/<probe>.c in
# gcc:14 under Apple's `container` CLI (Linux 6.18.5 aarch64 VM, root) and runs
# the shell snippet given (default: the probe with no arguments).
set -e
L=$(cd "$(dirname "$0")" && pwd)
P=$1; shift
RUN=${1:-/tmp/p}
container run --rm -v "$L":/probe gcc:14 sh -c "echo \"# kernel: \$(uname -srm)\" && gcc -Wall -O0 -pthread -o /tmp/p /probe/$P.c -lutil && cd /tmp && $RUN" 2>&1 | grep -v '^\[[0-9]/[0-9]\]'
