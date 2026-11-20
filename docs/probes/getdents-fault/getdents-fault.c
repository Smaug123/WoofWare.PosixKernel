// What a directory read answers through a buffer it cannot write, where that
// EFAULT falls among the call's other answers, and where it leaves the
// description's position: Linux's getdents64(2) and Darwin's
// getdirentries64, the trap under readdir(3) on each.
//
// Each faulting buffer is NULL, a PROT_NONE page, or the last page of the
// 64-bit address space (out of range for every user address check), beside a
// writable buffer as the control. A row is
//   <case> dest=<kind>: r=<r> errno=<e> pos=<before>-><after> then=<n>:<names>
// where `pos` is lseek(fd, 0, SEEK_CUR) before and after the call, and `then`
// is what reading the rest of the directory through a writable buffer
// returns afterwards: how many entries, and their names in order.
//
// The `partial-<k>` rows give a buffer of 4096 bytes whose first k bytes are
// writable and the rest a PROT_NONE page, with k chosen from the record
// lengths of the directory's first two entries (R1, R2) as a control read
// reports them, so that the first record fits and a later one faults.
//
// The `atime` rows set the directory's access time to 1000 s with its
// modification time now, make one read through the buffer, and report
// whether the access time moved.
//
// The probe runs as an unprivileged user (it drops to 65534 if started as
// root), in the directory named by its argument, which it fills itself.
//
// Outputs beside this file, measured 2026-11-20:
//
// * measured-linux-6.18.5-aarch64-uid65534.txt: Apple's `container`, gcc:14
//   image, on a fresh tmpfs mounted strictatime:
//     container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
// * measured-darwin-27.2-uid501.txt: natively, on the APFS data volume (which
//   moves an access time that is before the modification time), with the
//   devfs rows on /dev:
//     cc -Wall -o /tmp/getdents-fault getdents-fault.c && /tmp/getdents-fault "$(mktemp -d)"
//
// No test replays these yet: the library's readDirectoryEntry takes no
// buffer, and Darwin's partial rows are not something a per-record call can
// answer.
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
#ifdef __linux__
#include <sys/syscall.h>
// struct linux_dirent64: d_ino, d_off, d_reclen at 16, d_type, d_name at 19.
#define NAME_OFFSET 19
static long gd(int fd, void *buf, size_t n) { return syscall(SYS_getdents64, fd, buf, n); }
#else
// struct direntry: d_ino, d_seekoff, d_reclen at 16, d_namlen, d_type,
// d_name at 21.
#define NAME_OFFSET 21
extern ssize_t __getdirentries64(int, void *, size_t, off_t *);
static long gd(int fd, void *buf, size_t n) {
    off_t base = 0;
    return __getdirentries64(fd, buf, n, &base);
}
#endif

static const char *en(int e) {
    switch (e) {
    case 0: return "0";
    case EFAULT: return "EFAULT";
    case ENOENT: return "ENOENT";
    case ENOTDIR: return "ENOTDIR";
    case EBADF: return "EBADF";
    case EINVAL: return "EINVAL";
    case ENOTSUP: return "ENOTSUP";
    default: return strerror(e);
    }
}

static unsigned short reclen(const unsigned char *p) {
    unsigned short r;
    memcpy(&r, p + 16, sizeof r);
    return r;
}

// Appends the names of the records in buf[0..n) to out; returns how many.
static int names(const unsigned char *buf, long n, char *out, size_t cap) {
    int count = 0;
    for (long at = 0; at < n; at += reclen(buf + at)) {
        if (reclen(buf + at) == 0) break;
        size_t used = strlen(out);
        snprintf(out + used, cap - used, "%s%s", *out ? "," : "", (const char *)buf + at + NAME_OFFSET);
        count++;
    }
    return count;
}

static unsigned char big[65536];

// Reads the rest of the directory through a writable buffer.
static void rest(int fd, char *out, size_t cap, int *count) {
    *out = 0;
    *count = 0;
    for (;;) {
        long r = gd(fd, big, sizeof big);
        if (r < 0) {
            snprintf(out + strlen(out), cap - strlen(out), "%s<%s>", *out ? "," : "", en(errno));
            return;
        }
        if (r == 0) return;
        *count += names(big, r, out, cap);
    }
}

static void *protNone;
static unsigned char *edge; // the first byte of a PROT_NONE page after a writable one
#define HIGH ((void *)(uintptr_t)0xfffffffffffff000ULL)
static const char *dname[] = {"ok", "null", "prot_none", "high"};

static void *dest(int d) {
    switch (d) {
    case 0: return big;
    case 1: return NULL;
    case 2: return protNone;
    default: return HIGH;
    }
}

static void row(const char *label, const char *dn, int fd, void *buf, size_t count, int then) {
    off_t before = lseek(fd, 0, SEEK_CUR);
    errno = 0;
    long r = gd(fd, buf, count);
    int e = r < 0 ? errno : 0;
    off_t after = lseek(fd, 0, SEEK_CUR);
    printf("%-14s dest=%-9s: r=%ld errno=%s pos=%lld->%lld", label, dn, r, en(e), (long long)before,
           (long long)after);
    if (then) {
        char out[4096];
        int n;
        rest(fd, out, sizeof out, &n);
        printf(" then=%d:%s", n, out);
    }
    printf("\n");
}

static int fresh(void) { return open("dir", O_RDONLY | O_DIRECTORY); }

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
    protNone = mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    unsigned char *two = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    mprotect(two + page, (size_t)page, PROT_NONE);
    edge = two + page;

    mkdir("dir", 0755);
    const char *files[] = {"a", "b", "c", "d", "e"};
    for (int i = 0; i < 5; i++) {
        char p[16];
        snprintf(p, sizeof p, "dir/%s", files[i]);
        close(open(p, O_CREAT | O_RDWR, 0644));
    }
    int file = open("f", O_CREAT | O_RDWR, 0644);

    // The control: the whole directory through one writable buffer.
    int fd = fresh();
    long all = gd(fd, big, sizeof big);
    char listing[4096] = "";
    int total = names(big, all, listing, sizeof listing);
    unsigned short r1 = reclen(big), r2 = reclen(big + r1), r3 = reclen(big + r1 + r2);
    printf("# control offsets (d_off / d_seekoff):");
    for (long at = 0; at < all; at += reclen(big + at)) {
        long long off;
        memcpy(&off, big + at + 8, sizeof off);
        printf(" %s=%lld", (const char *)big + at + NAME_OFFSET, off);
    }
    printf("\n");
    // The smallest count this directory read accepts at the start.
    for (size_t c = 1; c <= 4096; c++) {
        int probeFd = fresh();
        long r = gd(probeFd, big, c);
        close(probeFd);
        if (r > 0) {
            printf("# smallest count accepted: %zu (r=%ld)\n", c, r);
            break;
        }
    }
    printf("# fixture: prot_none=%p edge=%p (page %ld); control r=%ld: %d entries %s; R1=%u R2=%u\n", protNone,
           (void *)edge, page, all, total, listing, r1, r2);
    close(fd);

    for (int d = 0; d < 4; d++) row("closed-fd", dname[d], 999, dest(d), 4096, 0);
    for (int d = 0; d < 4; d++) row("regular-file", dname[d], file, dest(d), 4096, 0);
    for (int d = 0; d < 4; d++) {
        fd = fresh();
        row("count-1", dname[d], fd, dest(d), 1, 1);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        fd = fresh();
        row("start", dname[d], fd, dest(d), 4096, 1);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        fd = fresh();
        long first = gd(fd, big, r1);
        char one[256] = "";
        names(big, first, one, sizeof one);
        char label[32];
        snprintf(label, sizeof label, "after-first");
        printf("# after-first: first read of %u bytes r=%ld %s\n", r1, first, one);
        row(label, dname[d], fd, dest(d), 4096, 1);
        close(fd);
    }
    unsigned ks[] = {r1, r1 + 8u, (unsigned)r1 + r2, (unsigned)r1 + r2 + r3};
    const char *kn[] = {"partial-R1", "partial-R1+8", "partial-R1+R2", "partial-R1+R2+R3"};
    for (int i = 0; i < 4; i++) {
        fd = fresh();
        memset(edge - ks[i], 0xAA, ks[i]);
        row(kn[i], "edge", fd, edge - ks[i], 4096, 0);
        // What the writable bytes now hold, as records.
        char got[1024] = "";
        int n = names(edge - ks[i], ks[i] >= r1 ? r1 : 0, got, sizeof got);
        printf("# %s: first writable record now %d:%s\n", kn[i], n, got);
        char out[4096];
        rest(fd, out, sizeof out, &n);
        printf("# %s: then=%d:%s\n", kn[i], n, out);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        fd = fresh();
        char out[4096];
        int n;
        rest(fd, out, sizeof out, &n);
        row("end", dname[d], fd, dest(d), 4096, 1);
        close(fd);
    }
    {
        // At the end, through a buffer whose first R1 bytes are writable.
        fd = fresh();
        char out[4096];
        int n;
        rest(fd, out, sizeof out, &n);
        row("end-partial", "edge", fd, edge - r1, 4096, 0);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        mkdir("gone", 0755);
        fd = open("gone", O_RDONLY | O_DIRECTORY);
        rmdir("gone");
        row("removed", dname[d], fd, dest(d), 4096, 1);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        struct timespec ts[2] = {{1000, 0}, {0, UTIME_NOW}};
        utimensat(AT_FDCWD, "dir", ts, 0);
        fd = fresh();
        errno = 0;
        long r = gd(fd, dest(d), 4096);
        int e = r < 0 ? errno : 0;
        struct stat st;
        stat("dir", &st);
#ifdef __linux__
        long long at = (long long)st.st_atim.tv_sec;
#else
        long long at = (long long)st.st_atimespec.tv_sec;
#endif
        printf("%-14s dest=%-9s: r=%ld errno=%s atime=%s\n", "atime", dname[d], r, en(e),
               at == 1000 ? "kept" : "moved");
        close(fd);
    }
#ifndef __linux__
    // Darwin's devfs, the other filesystem a Darwin directory is on.
    for (int d = 0; d < 4; d++) {
        fd = open("/dev", O_RDONLY | O_DIRECTORY);
        row("devfs-start", dname[d], fd, dest(d), 4096, 0);
        char out[65536];
        int n;
        rest(fd, out, sizeof out, &n);
        printf("# devfs-start: then %d entries\n", n);
        close(fd);
    }
    {
        fd = open("/dev", O_RDONLY | O_DIRECTORY);
        long first = gd(fd, big, sizeof big);
        printf("# devfs control r=%ld; R1=%u\n", first, reclen(big));
        unsigned dr1 = reclen(big);
        close(fd);
        fd = open("/dev", O_RDONLY | O_DIRECTORY);
        row("devfs-partial", "edge", fd, edge - dr1, 4096, 0);
        char out[65536];
        int n;
        rest(fd, out, sizeof out, &n);
        printf("# devfs-partial: then %d entries\n", n);
        close(fd);
        fd = open("/dev", O_RDONLY | O_DIRECTORY);
        rest(fd, out, sizeof out, &n);
        for (int d = 0; d < 4; d++) row("devfs-end", dname[d], fd, dest(d), 4096, 0);
        close(fd);
    }
#endif
    return 0;
}
