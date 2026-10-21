#!/bin/sh
# Every entry a Linux devtmpfs at /dev holds, as stat(1) reports it, and the
# order getdents64 lists each of its directories in.
#
# Run as root in a fresh VM:
#   container run --rm -v "$PWD":/probe debian:trixie /bin/sh /probe/devtmpfs-contents.sh
#
# `find -xdev` does not descend into the filesystems mounted on /dev, but does
# report their mount points, whose stat is the mounted filesystem's root; the
# MOUNT lines say which they are. An entry's times tell who made it: devtmpfs
# makes its nodes before the realtime clock is first set, so theirs are a few
# milliseconds past the epoch, while an entry userspace made afterwards has the
# clock's time then.
#
# ENTRY fields, tab-separated: path, file type, mode in octal, uid:gid, inode,
# st_nlink, st_size, the major:minor a device node holds (0:0 for anything
# else), atime, mtime, ctime, birth (seconds.nanoseconds), and for a symbolic
# link its target.

echo "# $(uname -sr) $(uname -m)"
echo "# $(grep btime /proc/stat)"
awk '$5 ~ /^\/dev(\/|$)/ { print "MOUNT\t" $5 "\t" $(NF-2) }' /proc/self/mountinfo

find /dev -xdev | sort | while read -r p; do
  printf 'ENTRY\t%s\n' "$(stat -c '%n	%F	%a	%u:%g	%i	%h	%s	%Hr:%Lr	%.9X	%.9Y	%.9Z	%.9W' "$p")	$(readlink "$p")"
done

# The order getdents64 lists each directory in: `ls -f` neither sorts nor
# hides anything.
find /dev -xdev -type d | sort | while read -r d; do
  printf 'LISTING\t%s\t%s\n' "$d" "$(ls -f "$d" | tr '\n' ' ')"
done
