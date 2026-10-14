#!/bin/sh
# Usage: run-linux.sh probe [args...] — compiles /probe/<probe>.c in gcc:14 under
# Apple's `container` CLI (Linux 6.18.5 aarch64 VM) and runs it as root.
set -e
L=$(cd "$(dirname "$0")" && pwd)
P=$1; shift
container run --rm -v "$L":/probe gcc:14 sh -c "echo \"# kernel: \$(uname -srm)\" && gcc -Wall -O0 -pthread -o /tmp/p /probe/$P.c && cd /tmp && /tmp/p $*" 2>&1 | grep -v '^\[[0-9]/[0-9]\]'
