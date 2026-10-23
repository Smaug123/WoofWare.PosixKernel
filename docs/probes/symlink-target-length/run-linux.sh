#!/bin/sh
set -e
gcc -Wall -O1 -o /tmp/p /probe/target-length.c
echo "# $(uname -sr) $(uname -m), $(ldd --version | head -1); root, then uid 1000 via setpriv"
mkdir -p /mnt/tmpfs
mount -t tmpfs none /mnt/tmpfs
grep -E " (/|/tmp|/dev/shm|/mnt/tmpfs) " /proc/mounts | sed 's/^/# mount: /'
/tmp/p /dev/shm /mnt/tmpfs /tmp
d=$(mktemp -d)
chown 1000:1000 "$d"
chmod 1777 /mnt/tmpfs
setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/p "$d" /mnt/tmpfs
