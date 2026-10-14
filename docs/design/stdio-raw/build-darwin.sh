#!/bin/sh
# Usage: build-darwin.sh probe — compiles with the repository devshell's clang
# (the system cc refuses to run until the Xcode licence is accepted).
set -e
L=$(cd "$(dirname "$0")" && pwd)
cd /Users/patrick/Documents/GitHub/WoofWare.PawPrint
nix develop -c cc -Wall -Wno-deprecated-declarations -O0 -pthread -o "$L/bin/$1" "$L/$1.c" 2>&1 | grep -v '^warning: Git tree' || true
test -x "$L/bin/$1"
