// Where the EFAULT for an unwritable output struct falls among the other
// answers of stat(2), lstat(2), fstat(2), fstatat(2), statfs(2) and
// fstatfs(2): each call is made in a state that gives some answer through a
// writable struct, then again through NULL, through a PROT_NONE page, and
// through the last page of the 64-bit address space, which is out of range
// for every user address check.
//
// A row is
//   <call> <case> dest=<kind>: r=<r> errno=<e>
// The `straddle` rows put the struct 8 bytes before a PROT_NONE page and
// report how many of those 8 bytes (pre-filled with 0xAA) the call changed.
//
// On Linux every call is the raw syscall (`newfstatat` for stat and lstat,
// since aarch64 has no `stat` syscall, and `fstat`, `statfs`, `fstatfs`), so
// that glibc's own screening (such as its EBADF for a negative fd) is not
// measured. On Darwin each is the C library's function, which is the trap.
//
// The probe runs as an unprivileged user (it drops to 65534 if started as
// root), in the directory named by its argument, which it fills itself, with
// a pipe as its standard input: the `inherited-pipe` rows are `fstat` of a
// pipe the process did not make.
//
// Outputs beside this file, measured 2026-11-20:
//
// * measured-linux-6.18.5-aarch64-uid65534.txt: Apple's `container`, gcc:14
//   image, on a fresh tmpfs:
//     container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
// * measured-darwin-27.2-uid501.txt: natively, on the APFS data volume:
//     cc -Wall -o /tmp/stat-fault stat-fault.c && : | /tmp/stat-fault "$(mktemp -d)"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <sys/socket.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#else
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/param.h>
#endif

static const char *en(int e) {
    switch (e) {
    case 0: return "0";
    case EFAULT: return "EFAULT";
    case ENOENT: return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case EACCES: return "EACCES";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case ELOOP: return "ELOOP";
    case EBADF: return "EBADF";
    case EINVAL: return "EINVAL";
    case ENOTSUP: return "ENOTSUP";
    default: return strerror(e);
    }
}

#ifdef __linux__
typedef struct stat stat_t;
typedef struct statfs statfs_t;
static long k_stat(const char *p, void *b) { return syscall(SYS_newfstatat, AT_FDCWD, p, b, 0); }
static long k_lstat(const char *p, void *b) { return syscall(SYS_newfstatat, AT_FDCWD, p, b, AT_SYMLINK_NOFOLLOW); }
static long k_fstat(int fd, void *b) { return syscall(SYS_fstat, fd, b); }
static long k_fstatat(int d, const char *p, void *b, int f) { return syscall(SYS_newfstatat, d, p, b, f); }
static long k_statfs(const char *p, void *b) { return syscall(SYS_statfs, p, b); }
static long k_fstatfs(int fd, void *b) { return syscall(SYS_fstatfs, fd, b); }
#define BADFLAG 0x1
#else
typedef struct stat stat_t;
typedef struct statfs statfs_t;
static long k_stat(const char *p, void *b) { return stat(p, b); }
static long k_lstat(const char *p, void *b) { return lstat(p, b); }
static long k_fstat(int fd, void *b) { return fstat(fd, b); }
static long k_fstatat(int d, const char *p, void *b, int f) { return fstatat(d, p, b, f); }
static long k_statfs(const char *p, void *b) { return statfs(p, b); }
static long k_fstatfs(int fd, void *b) { return fstatfs(fd, b); }
#define BADFLAG 0x1
#endif

// Fixture setup that fails stops the probe, naming what failed, rather than
// letting a row measure something other than what it names.
#define SETUP(expr)                                                         \
    do {                                                                    \
        if ((long)(expr) < 0) {                                             \
            fprintf(stderr, "setup failed: %s: %s\n", #expr, strerror(errno)); \
            exit(1);                                                        \
        }                                                                   \
    } while (0)

static void *protNone;
static unsigned char *straddle; // 8 bytes before a PROT_NONE page
#define HIGH ((void *)(uintptr_t)0xfffffffffffff000ULL)

static union {
    stat_t s;
    statfs_t f;
    unsigned char raw[8192];
} good;

static const char *dname[] = {"ok", "null", "prot_none", "high"};

static void *dest(int d) {
    switch (d) {
    case 0: return &good;
    case 1: return NULL;
    case 2: return protNone;
    default: return HIGH;
    }
}

#define ROWS(call, label, expr)                                                      \
    do {                                                                             \
        for (int d_ = 0; d_ < 4; d_++) {                                             \
            void *b = dest(d_);                                                      \
            errno = 0;                                                               \
            long r_ = (expr);                                                        \
            int e_ = r_ == 0 ? 0 : errno;                                            \
            printf("%-8s %-22s dest=%-8s: r=%ld errno=%s\n", call, label, dname[d_], \
                   r_, en(e_));                                                      \
        }                                                                            \
        {                                                                            \
            memset(straddle, 0xAA, 8);                                               \
            void *b = straddle;                                                      \
            errno = 0;                                                               \
            long r_ = (expr);                                                        \
            int e_ = r_ == 0 ? 0 : errno;                                            \
            int changed_ = 0;                                                        \
            for (int i_ = 0; i_ < 8; i_++)                                           \
                if (straddle[i_] != 0xAA) changed_++;                                \
            printf("%-8s %-22s dest=%-8s: r=%ld errno=%s changed=%d/8\n", call,      \
                   label, "straddle", r_, en(e_), changed_);                         \
        }                                                                            \
    } while (0)

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <empty directory>\n", argv[0]);
        return 2;
    }
    struct utsname u;
    uname(&u);
    if (chdir(argv[1]) != 0) {
        perror("chdir");
        return 1;
    }
    if (getuid() == 0) {
        if (setgid(65534) != 0 || setuid(65534) != 0) {
            perror("drop privileges");
            return 1;
        }
    }
    printf("# %s %s %s, uid %d\n", u.sysname, u.release, u.machine, (int)getuid());

    long page = sysconf(_SC_PAGESIZE);
    // PROT_NONE rather than unmapped, so that no later allocation can take
    // the address over.
    protNone = mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    unsigned char *two = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (protNone == MAP_FAILED || two == MAP_FAILED) {
        fprintf(stderr, "setup failed: mmap: %s\n", strerror(errno));
        return 1;
    }
    SETUP(mprotect(two + page, (size_t)page, PROT_NONE));
    straddle = two + page - 8;
    printf("# fixture: prot_none=%p straddle=%p (page %ld)\n", protNone, (void *)straddle, page);

    int fd = open("f", O_CREAT | O_EXCL | O_RDWR, 0644);
    SETUP(fd);
    if (write(fd, "hello", 5) != 5) {
        fprintf(stderr, "setup failed: write f\n");
        return 1;
    }
    SETUP(mkdir("d", 0755));
    SETUP(mkdir("d0", 0755));
    int x = open("d0/x", O_CREAT | O_EXCL | O_RDWR, 0644);
    SETUP(x);
    close(x);
    SETUP(chmod("d0", 0));
    SETUP(symlink("f", "l"));
    SETUP(symlink("loop", "loop"));
    char longname[301];
    memset(longname, 'n', 300);
    longname[300] = 0;
    int dfd = open("d", O_RDONLY);
    SETUP(dfd);
    int pipefd[2];
    SETUP(pipe(pipefd));
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    SETUP(sock);
#ifdef __linux__
    int queue = epoll_create1(0);
#else
    int queue = kqueue();
#endif
    SETUP(queue);
    // The probe is run with a pipe as its standard input, which it did not
    // make itself.
    struct stat in;
    SETUP(fstat(0, &in));
    if (!S_ISFIFO(in.st_mode)) {
        fprintf(stderr, "setup failed: standard input is not a pipe\n");
        return 1;
    }
    // A descriptor this process held and closed, so that none it inherited
    // can stand in for it.
    int closed = dup(fd);
    SETUP(closed);
    SETUP(close(closed));
    printf("# fixture: closed descriptor %d\n", closed);

    ROWS("stat", "file", k_stat("f", b));
    ROWS("stat", "symlink-to-file", k_stat("l", b));
    ROWS("stat", "missing", k_stat("missing", b));
    ROWS("stat", "empty", k_stat("", b));
    ROWS("stat", "file-as-directory", k_stat("f/x", b));
    ROWS("stat", "unsearchable", k_stat("d0/x", b));
    ROWS("stat", "long-name", k_stat(longname, b));
    ROWS("stat", "loop", k_stat("loop", b));
    ROWS("stat", "unreadable-path", k_stat((const char *)protNone, b));

    ROWS("lstat", "symlink", k_lstat("l", b));
    ROWS("lstat", "missing", k_lstat("missing", b));
    ROWS("lstat", "unsearchable", k_lstat("d0/x", b));

    ROWS("fstat", "file", k_fstat(fd, b));
    ROWS("fstat", "directory", k_fstat(dfd, b));
    ROWS("fstat", "pipe-read-end", k_fstat(pipefd[0], b));
    ROWS("fstat", "inherited-pipe", k_fstat(0, b));
    ROWS("fstat", "socket", k_fstat(sock, b));
    ROWS("fstat", "event-queue", k_fstat(queue, b));
    ROWS("fstat", "negative-fd", k_fstat(-1, b));
    ROWS("fstat", "closed-fd", k_fstat(closed, b));

    ROWS("fstatat", "cwd-file", k_fstatat(AT_FDCWD, "f", b, 0));
    ROWS("fstatat", "dirfd-missing", k_fstatat(dfd, "missing", b, 0));
    ROWS("fstatat", "closed-dirfd", k_fstatat(closed, "f", b, 0));
    ROWS("fstatat", "file-as-dirfd", k_fstatat(fd, "x", b, 0));
    ROWS("fstatat", "pipe-as-dirfd", k_fstatat(pipefd[0], "x", b, 0));
    ROWS("fstatat", "bad-flag", k_fstatat(AT_FDCWD, "f", b, BADFLAG));
    ROWS("fstatat", "bad-flag-missing", k_fstatat(AT_FDCWD, "missing", b, BADFLAG));
    ROWS("fstatat", "nofollow-loop", k_fstatat(AT_FDCWD, "loop", b, AT_SYMLINK_NOFOLLOW));
    ROWS("fstatat", "unsearchable", k_fstatat(AT_FDCWD, "d0/x", b, 0));
#ifdef __linux__
    ROWS("fstatat", "empty-path-file", k_fstatat(fd, "", b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-closed", k_fstatat(closed, "", b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-pipe", k_fstatat(pipefd[0], "", b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-socket", k_fstatat(sock, "", b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-null-path", k_fstatat(fd, NULL, b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-unreadable-path", k_fstatat(fd, (const char *)protNone, b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-closed-null-path", k_fstatat(closed, NULL, b, AT_EMPTY_PATH));
    ROWS("fstatat", "empty-path-closed-unreadable-path",
         k_fstatat(closed, (const char *)protNone, b, AT_EMPTY_PATH));
#endif

    ROWS("statfs", "file", k_statfs("f", b));
    ROWS("statfs", "missing", k_statfs("missing", b));
    ROWS("statfs", "file-as-directory", k_statfs("f/x", b));
    ROWS("statfs", "unsearchable", k_statfs("d0/x", b));
    ROWS("statfs", "loop", k_statfs("loop", b));

    ROWS("fstatfs", "file", k_fstatfs(fd, b));
    ROWS("fstatfs", "directory", k_fstatfs(dfd, b));
    ROWS("fstatfs", "pipe-read-end", k_fstatfs(pipefd[0], b));
    ROWS("fstatfs", "negative-fd", k_fstatfs(-1, b));
    ROWS("fstatfs", "closed-fd", k_fstatfs(closed, b));

    chmod("d0", 0755);
    return 0;
}
