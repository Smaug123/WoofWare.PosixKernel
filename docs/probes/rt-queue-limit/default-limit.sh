#!/bin/sh
# RLIMIT_SIGPENDING's default against the memory of the Linux VM that Apple's
# `container` boots: the limit a fresh process reads in SigQ, beside MemTotal
# and threads-max. Run on the host; its output is
# measured-default-limit-linux-6.18.5-aarch64.txt.
for m in 512M 1G 2G 4G 8G; do
  container run --rm -m $m gcc:14 sh -c "echo \"memory=$m \$(grep MemTotal /proc/meminfo | tr -s ' ') \$(grep SigQ /proc/self/status | tr -s '\t' ' ') threads-max=\$(cat /proc/sys/kernel/threads-max) \$(uname -r)\"" 2>&1 | grep -v '^\[[0-9]/6\]'
done
