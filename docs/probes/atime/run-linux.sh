#!/bin/sh
# Run atime.c on Linux: tmpfs and ext4, each under its default options and
# under strictatime, noatime, nodiratime and lazytime; then the 24-hour rows,
# which step the clock, on a default tmpfs and a default ext4.
#
# From this directory, on a Mac with Apple's `container` CLI:
#   container run --rm -v "$PWD":/probe gcc:14 gcc -static -Wall -O1 -o /probe/atime-linux /probe/atime.c
#   container run --rm --cap-add ALL -v "$PWD":/probe debian:bookworm sh /probe/run-linux.sh matrix > measured-linux-6.18.5-aarch64.txt
#   container run --rm --cap-add ALL -v "$PWD":/probe debian:bookworm sh /probe/run-linux.sh clock > measured-linux-6.18.5-aarch64-clock.txt
#   rm atime-linux
# (gcc:14 has no mkfs.ext4 and debian:bookworm no compiler, so the probe is
# built statically in one and run in the other.) Each `container run` boots a
# VM of its own, so the clock the `clock` run steps is that VM's alone.
#
# The matrix rows run as uid 1000, which owns each probe directory; mounting,
# and the clock rows, need root.

set -e
P=/probe/atime-linux
echo "# $(uname -sr) $(uname -m)"

mount_tmpfs() { # <dir> <options>
  mkdir -p "$1"
  if [ -n "$2" ]; then mount -t tmpfs -o "$2" tmpfs "$1"; else mount -t tmpfs tmpfs "$1"; fi
}

mount_ext4() { # <dir> <options>
  mkdir -p "$1"
  if [ -n "$2" ]; then mount -o "loop,$2" /tmp/ext4.img "$1"; else mount -o loop /tmp/ext4.img "$1"; fi
}

run() { # <kind> <label> <options> <mode>
  m=/m/$2
  "mount_$1" "$m" "$3"
  grep " $m " /proc/mounts | sed 's/^/# mount: /'
  mkdir -p "$m/p"
  chown 1000:1000 "$m/p"
  if [ "$4" = clock ]; then
    "$P" "$m/p" "$2" clock
  else
    setpriv --reuid=1000 --regid=1000 --clear-groups "$P" "$m/p" "$2"
  fi
  umount "$m"
}

mkfs.ext4 -q -F /tmp/ext4.img 64M >&2

case "$1" in
matrix)
  for o in default strictatime noatime nodiratime lazytime; do
    opts=$o
    [ "$o" = default ] && opts=
    run tmpfs "tmpfs-$o" "$opts" matrix
    run ext4 "ext4-$o" "$opts" matrix
  done
  ;;
clock)
  run tmpfs tmpfs-default "" clock
  run ext4 ext4-default "" clock
  ;;
*)
  echo "usage: run-linux.sh matrix|clock" >&2
  exit 2
  ;;
esac
