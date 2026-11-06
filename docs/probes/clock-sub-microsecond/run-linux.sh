#!/bin/sh
set -e
gcc -Wall -O1 -pthread -o /tmp/p /probe/clock-sub-microsecond.c
echo "# $(uname -sr) $(uname -m), $(ldd --version | head -1)"
/tmp/p
/tmp/p -b 20 1 6
