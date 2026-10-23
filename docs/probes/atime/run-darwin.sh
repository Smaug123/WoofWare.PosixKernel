#!/bin/sh
# Run atime.c on Darwin, as an ordinary user: in a directory on the volume
# holding /private/tmp (a Mac's data volume, mounted with its default options),
# and on a fresh APFS disk image attached with its default options, with
# noatime and with strictatime.
#
# From this directory:
#   sh run-darwin.sh
# which writes measured-darwin-27.0-apfs-*.txt beside it.

set -e
# launchd's default soft limit, so that a leaked descriptor shows.
ulimit -n 256
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d /private/tmp/atime.XXXXXX)
cc -Wall -O1 -Wno-deprecated-declarations -o "$work/atime" "$here/atime.c"

header() { # <mount point>
  echo "# $(uname -sr) $(uname -m), uid $(id -u)"
  mount | awk -v m="$1" '$3 == m' | sed 's/^/# mount: /'
}

# The data volume: /private/tmp is on it, mounted at /System/Volumes/Data.
mkdir "$work/data"
{
  header /System/Volumes/Data
  "$work/atime" "$work/data" apfs-data
} > "$here/measured-darwin-27.0-apfs-data.txt"

hdiutil create -quiet -size 64m -fs APFS -volname atimeprobe "$work/img.dmg"
for opts in default noatime strictatime; do
  mnt="$work/mnt-$opts"
  if [ "$opts" = default ]; then
    diskutil image attach --nobrowse --mountPoint "$mnt" "$work/img.dmg" > /dev/null
  else
    diskutil image attach --nobrowse --mountPoint "$mnt" --mountOptions "$opts" "$work/img.dmg" > /dev/null
  fi
  mkdir -p "$mnt/p"
  {
    header "$mnt"
    "$work/atime" "$mnt/p" "apfs-image-$opts"
  } > "$here/measured-darwin-27.0-apfs-image-$opts.txt"
  dev=$(mount | awk -v m="$mnt" '$3 == m {print $1}')
  diskutil eject "$dev" > /dev/null
  hdiutil detach -quiet "$(echo "$dev" | sed -E 's#(/dev/disk[0-9]+).*#\1#')" 2> /dev/null || true
done
rm -rf "$work"
