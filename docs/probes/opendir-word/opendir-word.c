// Measures what open(2) answers for the flag word each C library's
// opendir(3) passes, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC, which
// open-flags.c (docs/plans/2026-08-23-posix-kernel-extraction/) swept only
// one and two bits at a time. And, for comparison, what opendir(3) itself
// leaves on the descriptor it opened.
//
// The kernel's own entry point is called, not the C library's: openat(2)
// through syscall(2) on Linux, so glibc adds nothing to the word, and libc's
// open(2) on Darwin, which passes the word to the kernel unchanged.
//
// Each OPEN line is a path in the scratch directory (d a directory, f a
// regular file, l a symbolic link to d, nx nothing) and either the errno name
// or "ok" with the new descriptor's F_GETFL and F_GETFD words.
//
// Linux aarch64:
//   container run --rm -v "$PWD":/probe gcc:14 sh -c
//     'gcc -Wall -O0 -o /tmp/p /probe/opendir-word.c && /tmp/p "$(mktemp -d)"'
// Darwin:
//   cc -Wall -O0 -o opendir-word opendir-word.c
//   ./opendir-word "$(mktemp -d /private/tmp/opendir-word.XXXXXX)"
//
// Measured 2026-10-18 on Linux 6.18.5 aarch64 (root) and Darwin 27.0 arm64
// (uid 501); the output of each is beside this file.
// WoofWare.PosixKernel.Test/TestOpenFlagWord.fs holds the library to it.
//
// What they say: the word opens a directory on both, keeping O_NONBLOCK in
// F_GETFL and setting FD_CLOEXEC, and is ENOTDIR for a file. glibc's
// opendir leaves O_NONBLOCK on the descriptor; Darwin's does not.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static int raw_open(const char *path, int flags) {
#ifdef __linux__
    return (int)syscall(SYS_openat, AT_FDCWD, path, flags, 0);
#else
    return open(path, flags, 0);
#endif
}

static const char *en(int e) {
    switch (e) {
    case ENOENT: return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case EINVAL: return "EINVAL";
    case EACCES: return "EACCES";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <empty-scratch-dir>\n", argv[0]);
        return 2;
    }
    if (chdir(argv[1]) != 0) { perror("chdir"); return 2; }
    if (mkdir("d", 0755) != 0) { perror("mkdir d"); return 2; }
    int seed = open("f", O_CREAT | O_WRONLY, 0644);
    if (seed < 0) { perror("create f"); return 2; }
    close(seed);
    if (symlink("d", "l") != 0) { perror("symlink l"); return 2; }

    struct utsname u;
    uname(&u);
    printf("KERNEL\t%s %s %s\tuid=%d\n", u.sysname, u.release, u.machine, (int)geteuid());

    int word = O_RDONLY | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC;
    printf("WORD\t0x%x\n", (unsigned)word);

    const char *paths[] = {"d", "f", "l", "nx"};
    for (size_t i = 0; i < sizeof paths / sizeof *paths; i++) {
        errno = 0;
        int fd = raw_open(paths[i], word);
        if (fd < 0) {
            printf("OPEN\t%s\t%s\n", paths[i], en(errno));
            continue;
        }
        printf("OPEN\t%s\tok/0x%x/0x%x\n", paths[i], (unsigned)fcntl(fd, F_GETFL), (unsigned)fcntl(fd, F_GETFD));
        close(fd);
    }

    DIR *dir = opendir("d");
    if (dir == NULL) {
        printf("OPENDIR\td\t%s\n", en(errno));
    } else {
        printf("OPENDIR\td\tok/0x%x/0x%x\n", (unsigned)fcntl(dirfd(dir), F_GETFL), (unsigned)fcntl(dirfd(dir), F_GETFD));
        closedir(dir);
    }
    printf("DONE\n");
    return 0;
}
