// The longest target symlink(2) and symlinkat(2) will store, on each
// filesystem named on the command line, and what lstat(2) and readlink(2)
// report of a link holding it.
//
// Each argument is a writable directory; the probe makes and removes the link
// "l" in it. Every row is a target of that many 'a' bytes. A row is
//   <call> len=<n>: <ok|errno> [readlink=<bytes> st_size=<bytes>]
// so a refusal names its errno and a link that was made says how long the
// kernel reports its target to be.
//
// Linux:  container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
//         (tmpfs, both /dev/shm and a fresh mount, and the container's ext4,
//         as root and as uid 1000)
// Darwin: nix develop -c clang -Wall -o target-length target-length.c && ./target-length <apfs dir> <hfs dir>
//         (the HFS+ directory is a disk image uid 501 made and attached:
//         hdiutil create -size 20m -fs HFS+ -volname symlenhfs hfs.dmg &&
//         hdiutil attach -nobrowse -mountpoint <hfs dir> hfs.dmg)
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/vfs.h>
#else
#include <sys/mount.h>
#include <sys/param.h>
#endif

static const char *en(int e) {
    switch (e) {
    case 0: return "ok";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case EACCES: return "EACCES";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case ENOSPC: return "ENOSPC";
    default: return strerror(e);
    }
}

static char target[8200];
static char buf[8200];

static void row(const char *dir, int dirfd, int at, size_t len) {
    memset(target, 'a', len);
    target[len] = 0;
    char link[PATH_MAX];
    snprintf(link, sizeof link, "%s/l", dir);
    unlink(link);
    errno = 0;
    int r = at ? symlinkat(target, dirfd, "l") : symlink(target, link);
    int e = r == 0 ? 0 : errno;
    printf("%-9s len=%zu: %s", at ? "symlinkat" : "symlink", len, en(e));
    if (r == 0) {
        ssize_t got = readlink(link, buf, sizeof buf);
        struct stat s;
        int sr = lstat(link, &s);
        int same = got >= 0 && (size_t)got == len && memcmp(buf, target, len) == 0;
        printf(" readlink=%zd%s st_size=%lld", got, same ? "(same bytes)" : "(DIFFERENT BYTES)",
               sr == 0 ? (long long)s.st_size : -1LL);
        unlink(link);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    printf("PATH_MAX=%d euid=%d\n", PATH_MAX, (int)geteuid());
    for (int i = 1; i < argc; i++) {
        const char *dir = argv[i];
        struct statfs fs;
        if (statfs(dir, &fs) != 0) {
            printf("%s: statfs %s\n", dir, strerror(errno));
            continue;
        }
#ifdef __linux__
        printf("dir=%s f_type=0x%lx\n", dir, (unsigned long)fs.f_type);
#else
        printf("dir=%s f_fstypename=%s\n", dir, fs.f_fstypename);
#endif
        int dirfd = open(dir, O_RDONLY | O_DIRECTORY);
        size_t lens[] = {1, 1022, 1023, 1024, 1025, 4094, 4095, 4096, 4097, 8000};
        for (int at = 0; at < 2; at++)
            for (size_t j = 0; j < sizeof lens / sizeof lens[0]; j++)
                row(dir, dirfd, at, lens[j]);
        close(dirfd);
    }
    return 0;
}
