#!/bin/sh
# Runs stat-fault.c against a fresh tmpfs, as its header describes:
#   container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
# The probe drops to an unprivileged user itself; mounting the tmpfs is what
# needs CAP_SYS_ADMIN.
set -e
gcc -Wall -O1 -o /tmp/stat-fault /probe/stat-fault.c
mkdir -p /mnt/stat-fault
mount -t tmpfs -o mode=1777 tmpfs /mnt/stat-fault
: | /tmp/stat-fault /mnt/stat-fault
