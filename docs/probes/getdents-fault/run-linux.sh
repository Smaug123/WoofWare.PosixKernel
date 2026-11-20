#!/bin/sh
# Runs getdents-fault.c against a fresh tmpfs mounted strictatime, so that
# any read of a directory moves its access time:
#   container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
# The probe drops to an unprivileged user itself; mounting the tmpfs is what
# needs CAP_SYS_ADMIN.
set -e
gcc -Wall -O1 -o /tmp/getdents-fault /probe/getdents-fault.c
mkdir -p /mnt/getdents-fault
mount -t tmpfs -o strictatime,mode=1777 tmpfs /mnt/getdents-fault
/tmp/getdents-fault /mnt/getdents-fault
