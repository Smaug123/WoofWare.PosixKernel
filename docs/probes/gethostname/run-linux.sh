#!/bin/sh
set -e
gcc -Wall -O1 -o /tmp/p /probe/gethostname.c
echo "# $(uname -sr) $(uname -m), $(ldd --version | head -1); root in its own UTS namespace"
/tmp/p 0 1 9 63 64 65 255 256
