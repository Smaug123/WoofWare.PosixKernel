#!/bin/sh
# What getdents64 reports for `.` and `..` in a devtmpfs, and when a listing
# moves a devtmpfs directory's access time, which its `relatime` mount option
# decides.
#
# Run as root in a fresh VM, with the capability to set the clock (the probe
# moves the VM's clock forward a day, and the VM is thrown away afterwards):
#   container run --rm --cap-add ALL -v "$PWD":/probe gcc:14 /bin/sh /probe/devtmpfs-listing.sh
set -e
echo "# $(uname -sr) $(uname -m)"
grep -E " /dev " /proc/mounts | sed 's/^/# mount: /'
gcc -Wall -O0 -o /tmp/dents /probe/dents.c

# `.` and `..` of the devtmpfs root, of a directory inside it, and of the root
# filesystem's root, beside each directory's own st_ino.
mkdir /dev/listing-probe
/tmp/dents / /dev /dev/listing-probe | grep -E '^DIR|^DENT [^ ]+ [0-9]+ [0-9]+ (\.|\.\.|dev|listing-probe)$'

d=/dev/atime-probe
show() { stat -c "$1 atime=%.9X mtime=%.9Y ctime=%.9Z" "$d"; }
# The realtime clock just before each listing, which is the `now` a listing
# that moves the atime moves it to (to the kernel's coarse clock).
list() { echo "LIST-AT $(date +%s.%N)"; ls -f "$d" > /dev/null; }
mkdir "$d"
show MADE
sleep 1.1
list
show LISTED-ATIME-EQUAL-MTIME
sleep 1.1
list
show LISTED-ATIME-AFTER-MTIME
sleep 1.1
chmod 700 "$d"
show CHMOD
sleep 1.1
list
show LISTED-AFTER-CHMOD
a=$(stat -c %X "$d")
date -s "@$((a + 86399))" > /dev/null
list
show LISTED-86399S-LATER
date -s "@$((a + 86400))" > /dev/null
list
show LISTED-86400S-LATER
sleep 1.1
mknod "$d/n" c 1 3
show MKNOD
sleep 1.1
list
show LISTED-AFTER-MKNOD
