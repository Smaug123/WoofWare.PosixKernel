set -u
cd /tmp && mkdir -p fu && cd fu
for m in 0644 2644 2654 4644; do
  rm -f f; touch f; chown 1000:1000 f; chmod $m f
  r=$(setpriv --reuid 1001 --regid 1001 --init-groups 2>/dev/null true; echo)
  out=$(setpriv --reuid=1001 --regid=1001 --clear-groups perl -e 'print chown(-1,-1,"f") ? "ok" : "fail:$!"' 2>&1)
  echo "NONOWNER-CHOWN-NOOP	file mode $m	$out	after $(stat -c 'uid=%u gid=%g mode=%a' f)"
done
echo "--- grpid"
command -v mkfs.ext4 || echo "no mkfs.ext4"
dd if=/dev/zero of=/tmp/img bs=1M count=16 status=none && mkfs.ext4 -q /tmp/img 2>&1 && mkdir -p /mnt/g && mount -o loop,grpid /tmp/img /mnt/g 2>&1 && mount | grep /mnt/g
if mountpoint -q /mnt/g; then
  mkdir /mnt/g/p; chown 0:2000 /mnt/g/p; chmod 0777 /mnt/g/p
  setpriv --reuid=1000 --regid=1000 --groups=1000 sh -c 'umask 0; touch /mnt/g/p/f; mkdir /mnt/g/p/d; mkdir /mnt/g/p/d2; true'
  stat -c 'GRPID	%n	uid=%u gid=%g mode=%a' /mnt/g/p /mnt/g/p/f /mnt/g/p/d
fi
