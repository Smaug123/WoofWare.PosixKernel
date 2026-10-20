#!/usr/bin/env python3
"""rename(2) whose destination is the source's parent or an ancestor of it.

Linux's do_renameat2 refuses that with ENOTEMPTY right after the EINVAL
subtree check and before vfs_rename, so it beats the type rule and every
EACCES; Darwin has no such arm and answers whatever its ordinary ordering
gives. Measured outputs sit beside this file.

The rows with a trailing separator ask where the trap sits against the
ENOTDIR a trailing separator over a non-directory earns. Linux moved it:
up to 6.18 the trap is checked after that ENOTDIR, and from 6.19 (where
__start_renaming checks it while taking the locks) before.

    python3 ancestor-trap.py /tmp/scratch
    container run --rm -v "$PWD:/probe" --user 1000:1000 python:3-slim \
        python3 /probe/ancestor-trap.py /tmp/scratch     # ext4, unprivileged
    container run --rm -v "$PWD:/probe" python:3-slim \
        python3 /probe/ancestor-trap.py /tmp/scratch     # ext4, uid 0
"""
import os, errno, sys, shutil, stat
base = sys.argv[1]
def fresh():
    shutil.rmtree(base, ignore_errors=True); os.makedirs(base)
def attempt(name, src, dst, setup):
    fresh(); setup()
    try:
        os.rename(os.path.join(base, src), os.path.join(base, dst)); print(f"{name:34}: OK")
    except OSError as e:
        print(f"{name:34}: {errno.errorcode[e.errno]}")
    for d in ["a/b", "a"]:
        try: os.chmod(os.path.join(base, d), 0o755)
        except Exception: pass
print(os.uname().sysname, os.uname().release, "uid", os.getuid())
def s1():
    os.makedirs(base+"/a"); open(base+"/a/f","w").close()
attempt("rename(a/f, a) f file", "a/f", "a", s1)
def s2():
    os.makedirs(base+"/a/sub"); os.chmod(base+"/a", 0o555)
attempt("rename(a/sub, a) a 0555", "a/sub", "a", s2)
def s3():
    os.makedirs(base+"/a/b/c"); os.chmod(base+"/a/b", 0o555)
attempt("rename(a/b/c, a) a/b 0555", "a/b/c", "a", s3)
def s4():
    os.makedirs(base+"/a/sub")
attempt("rename(a/sub, a) a 0755", "a/sub", "a", s4)
def s5():
    os.makedirs(base+"/a/b/c")
attempt("rename(a/b/c, a/b) parent", "a/b/c", "a/b", s5)
def s6():
    os.makedirs(base+"/a/b/c"); os.chmod(base+"/a/b", 0o555)
attempt("rename(a/b/c, a/b) parent 0555", "a/b/c", "a/b", s6)
def s7():
    os.makedirs(base+"/a"); os.symlink("x", base+"/a/l")
attempt("rename(a/l, a) l symlink", "a/l", "a", s7)
def s8():
    os.makedirs(base+"/a/b"); open(base+"/a/b/f","w").close(); os.chmod(base+"/a/b", 0o555)
attempt("rename(a/b/f, a) a/b 0555, f file", "a/b/f", "a", s8)
def s9():
    os.makedirs(base+"/a"); open(base+"/a/f","w").close()
attempt("rename(a/f/, a) f file", "a/f/", "a", s9)
attempt("rename(a/f, a/) f file", "a/f", "a/", s9)
attempt("rename(a/f/, a/) f file", "a/f/", "a/", s9)
attempt("rename(a/l/, a) l symlink", "a/l/", "a", s7)
def s10():
    os.makedirs(base+"/a/b"); open(base+"/a/b/f","w").close()
attempt("rename(a/b/f, a/) f file", "a/b/f", "a/", s10)
def s11():
    os.makedirs(base+"/a/b"); open(base+"/a/b/f","w").close(); os.chmod(base+"/a/b", 0o555)
attempt("rename(a/b/f/, a) a/b 0555", "a/b/f/", "a", s11)
# Controls. A directory source takes no ENOTDIR from a separator, so the trap
# answers on every Linux; and a separator with no trap in the way is ENOTDIR on
# every Linux, so the rows above are not a separator check that went missing.
attempt("rename(a/sub/, a/) sub dir", "a/sub/", "a/", s4)
def s12():
    os.makedirs(base+"/a"); os.makedirs(base+"/z"); open(base+"/a/f","w").close()
attempt("rename(a/f, z/) not an ancestor", "a/f", "z/", s12)
