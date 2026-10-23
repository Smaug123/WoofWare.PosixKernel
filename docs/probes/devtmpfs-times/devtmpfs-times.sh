#!/bin/sh
# The timestamps a Linux devtmpfs reports for /dev and for the nodes this
# library makes in it (null, urandom), against the machine's boot time, and
# whether reading, writing, opening or closing a node moves them.
#
# Run as root in a fresh VM, so that the kernel's own dmesg lines say when
# devtmpfs made its nodes and when the realtime clock was first set:
#   container run --rm --cap-add ALL -v "$PWD":/probe debian:trixie /bin/sh /probe/devtmpfs-times.sh
# Each `container run` boots its own VM, so each run is a separate boot.
#
# A time is seconds.nanoseconds since the epoch, as stat(1) prints it (birth
# through statx). `btime` is /proc/stat's: the realtime clock less the time
# since boot, so it is when the kernel started on the clock as it now stands.

echo "# $(uname -sr) $(uname -m)"
echo "# $(grep btime /proc/stat)"
echo "# uptime at start: $(cut -d' ' -f1 /proc/uptime)"
grep -E " /dev " /proc/mounts | sed 's/^/# mount: /'
stat -f -c '# statfs /dev: f_type=0x%t' /dev
# When devtmpfs was set up and mounted, and when the realtime clock was first
# set (from the RTC, by rtc_hctosys), in seconds since boot.
dmesg | grep -E "devtmpfs|setting system clock|persistent clock" | sed 's/^/# dmesg: /'

show() {
  for p in /dev /dev/null /dev/urandom; do
    stat -c "$1 $p ino=%i atime=%.9X mtime=%.9Y ctime=%.9Z birth=%.9W" "$p"
  done
}

show STAT
sleep 1.1
head -c 16 /dev/null > /dev/null
head -c 16 /dev/urandom > /dev/null
show AFTER-READ
sleep 1.1
echo hi > /dev/null
echo hi > /dev/urandom
show AFTER-WRITE
sleep 1.1
setpriv --reuid=1000 --regid=1000 --clear-groups sh -c 'head -c 16 /dev/urandom > /dev/null; echo hi > /dev/null; echo hi > /dev/urandom'
show AFTER-UID1000-READ-WRITE
echo "# realtime at end: $(date +%s.%N)"
