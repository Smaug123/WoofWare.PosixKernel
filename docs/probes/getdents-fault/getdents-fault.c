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
// The `end-null-<count>`, `start-null-512`, `end-prefix`, `start-prefix` and
// `start-tail` rows vary the count and which end of the buffer is writable,
// which is where Darwin's getdirentries64 stores a four-byte status word in a
// buffer of 1024 bytes or more. The `resumed-null-<count>` rows fault on a
// description a writable read has already taken two records from. The
// `first-<k>` rows make only the first k bytes writable, around where the
// first record's name, NUL and padding end, and report how many of them the
// call wrote.
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
// `TestDirectoryDestination` replays the rows the library models. Darwin's
// rows that fault after storing a record (`partial-*`, `devfs-partial`) are
// refused rather than modelled.
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
// Stops at the first record that does not lie wholly within n bytes or whose
// name has no NUL inside it, so that a buffer the kernel never wrote is read
// as holding no record.
static int names(const unsigned char *buf, long n, char *out, size_t cap) {
    int count = 0;
    for (long at = 0; at + NAME_OFFSET < n; at += reclen(buf + at)) {
        unsigned short r = reclen(buf + at);
        if (r <= NAME_OFFSET || at + r > n) break;
        const unsigned char *name = buf + at + NAME_OFFSET;
        if (memchr(name, 0, (size_t)(r - NAME_OFFSET)) == NULL) break;
        size_t used = strlen(out);
        snprintf(out + used, cap - used, "%s%s", *out ? "," : "", (const char *)name);
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

// Fixture setup that fails stops the probe, naming what failed, rather than
// letting a row measure something other than what it names.
static void setup(long result, const char *what) {
    if (result < 0) {
        fprintf(stderr, "setup failed: %s: %s\n", what, strerror(errno));
        exit(1);
    }
}

// Sets dir's access time to 1000 s and its modification time to now, and
// checks that the access time took.
static void oldAtime(void) {
    struct timespec ts[2] = {{1000, 0}, {0, UTIME_NOW}};
    setup(utimensat(AT_FDCWD, "dir", ts, 0), "utimensat dir");
    struct stat st;
    setup(stat("dir", &st), "stat dir");
#ifdef __linux__
    long long at = (long long)st.st_atim.tv_sec;
#else
    long long at = (long long)st.st_atimespec.tv_sec;
#endif
    if (at != 1000) setup(-1, "dir's access time did not take");
}

// Whether dir's access time is still the 1000 s oldAtime set.
static const char *atimeOf(const char *path) {
    struct stat st;
    setup(stat(path, &st), "stat");
#ifdef __linux__
    long long at = (long long)st.st_atim.tv_sec;
#else
    long long at = (long long)st.st_atimespec.tv_sec;
#endif
    return at == 1000 ? "kept" : "moved";
}

static int openDev(void) {
    int fd = open("/dev", O_RDONLY | O_DIRECTORY);
    setup(fd, "open /dev");
    return fd;
}

// A directory made, opened and removed, its descriptor still open.
static int removed(void) {
    setup(mkdir("gone", 0755), "mkdir gone");
    int fd = open("gone", O_RDONLY | O_DIRECTORY);
    setup(fd, "open gone");
    setup(rmdir("gone"), "rmdir gone");
    return fd;
}

static int fresh(void) {
    int fd = open("dir", O_RDONLY | O_DIRECTORY);
    setup(fd, "open dir");
    return fd;
}

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
    if (protNone == MAP_FAILED || two == MAP_FAILED) setup(-1, "mmap");
    setup(mprotect(two + page, (size_t)page, PROT_NONE), "mprotect");
    edge = two + page;

    setup(mkdir("dir", 0755), "mkdir dir");
    const char *files[] = {"a", "b", "c", "d", "e"};
    for (int i = 0; i < 5; i++) {
        char p[16];
        snprintf(p, sizeof p, "dir/%s", files[i]);
        int made = open(p, O_CREAT | O_EXCL | O_RDWR, 0644);
        setup(made, p);
        close(made);
    }
    int file = open("f", O_CREAT | O_EXCL | O_RDWR, 0644);
    setup(file, "open f");

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

    // A descriptor this process held and closed, so that none it inherited
    // can stand in for it.
    int closed = dup(file);
    setup(closed, "dup");
    setup(close(closed), "close");
    for (int d = 0; d < 4; d++) row("closed-fd", dname[d], closed, dest(d), 4096, 0);
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
        size_t firstCount = r1 < 64 ? 64 : r1;
        long first = gd(fd, big, firstCount);
        if (first <= 0) setup(-1, "after-first's first read");
        char one[256] = "";
        names(big, first, one, sizeof one);
        char label[32];
        snprintf(label, sizeof label, "after-first");
        printf("# after-first: first read of %zu bytes r=%ld %s\n", firstCount, first, one);
        row(label, dname[d], fd, dest(d), 4096, 1);
        close(fd);
    }
    unsigned ks[] = {r1, r1 + 8u, (unsigned)r1 + r2, (unsigned)r1 + r2 + r3};
    const char *kn[] = {"partial-R1", "partial-R1+8", "partial-R1+R2", "partial-R1+R2+R3"};
    for (int i = 0; i < 4; i++) {
        fd = fresh();
        memset(edge - ks[i], 0xAA, ks[i]);
        row(kn[i], "edge", fd, edge - ks[i], 4096, 1);
        // What the writable bytes now hold, as records.
        char got[1024] = "";
        int n = names(edge - ks[i], ks[i] >= r1 ? r1 : 0, got, sizeof got);
        printf("# %s: first writable record now %d:%s\n", kn[i], n, got);
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
        // And through ones whose last 24 bytes, or last byte, are not.
        row("end-mostly", "edge", fd, edge - (4096 - 24), 4096, 0);
        row("end-last-byte", "edge", fd, edge - 4095, 4096, 0);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        fd = removed();
        row("removed", dname[d], fd, dest(d), 4096, 1);
        close(fd);
    }
    {
        // Twice through NULL: the second call starts where the first left.
        fd = removed();
        row("removed-first", "null", fd, NULL, 4096, 0);
        row("removed-again", "null", fd, NULL, 4096, 1);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        fd = fresh();
        oldAtime();
        errno = 0;
        long r = gd(fd, dest(d), 4096);
        int e = r < 0 ? errno : 0;
        printf("%-14s dest=%-9s: r=%ld errno=%s atime=%s\n", "atime", dname[d], r, en(e), atimeOf("dir"));
        close(fd);
    }
    // A buffer laid out across a PROT_NONE page and a writable one after it,
    // so that its first bytes are the ones it cannot write.
    unsigned char *pair = mmap(NULL, 2 * (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pair == MAP_FAILED) setup(-1, "mmap pair");
    setup(mprotect(pair, (size_t)page, PROT_NONE), "mprotect pair");
    unsigned char *after = pair + page;

    // At the end of the directory: NULL through small counts, and a buffer
    // whose first 4092 bytes cannot be written and whose last 4 can.
    {
        size_t counts[] = {512, 1023, 1024, 4096};
        for (int i = 0; i < 4; i++) {
            fd = fresh();
            char out[4096];
            int n;
            rest(fd, out, sizeof out, &n);
            char label[32];
            snprintf(label, sizeof label, "end-null-%zu", counts[i]);
            row(label, "null", fd, NULL, counts[i], 0);
            close(fd);
        }
        fd = fresh();
        char out[4096];
        int n;
        rest(fd, out, sizeof out, &n);
        row("end-prefix", "edge", fd, after - 4092, 4096, 0);
        close(fd);
    }
    // At the start: NULL through a small count, and a buffer writable but
    // for its last 4 bytes, or its first 4092.
    {
        fd = fresh();
        row("start-null-512", "null", fd, NULL, 512, 1);
        close(fd);
        fd = fresh();
        row("start-tail", "edge", fd, edge - 4092, 4096, 1);
        close(fd);
        fd = fresh();
        row("start-prefix", "edge", fd, after - 4092, 4096, 1);
        close(fd);
    }
    // Resumed: a writable read of the first two records, then one through
    // NULL, with the directory's access time set before its modification
    // time between them.
    {
        size_t counts[] = {512, 4096};
        for (int i = 0; i < 2; i++) {
            fd = fresh();
            long first = gd(fd, big, (size_t)r1 + r2);
            if (first != (long)r1 + r2) setup(-1, "resumed's first read");
            char got[256] = "";
            names(big, first, got, sizeof got);
            oldAtime();
            char label[32];
            snprintf(label, sizeof label, "resumed-null-%zu", counts[i]);
            printf("# %s: first read of %u bytes r=%ld %s\n", label, r1 + r2, first, got);
            off_t before = lseek(fd, 0, SEEK_CUR);
            errno = 0;
            long r = gd(fd, NULL, counts[i]);
            int e = r < 0 ? errno : 0;
            off_t afterPos = lseek(fd, 0, SEEK_CUR);
            // The access time, before reading on moves it.
            const char *moved = atimeOf("dir");
            char out[4096];
            int n;
            rest(fd, out, sizeof out, &n);
            printf("%-14s dest=%-9s: r=%ld errno=%s pos=%lld->%lld then=%d:%s\n", label, "null", r, en(e),
                   (long long)before, (long long)afterPos, n, out);
            printf("# %s: atime=%s\n", label, moved);
            close(fd);
        }
    }
    // The first record's own bytes: a buffer whose first k bytes are
    // writable, for k around where the record's name and NUL end and where
    // its padding ends, reporting how many of those k bytes (pre-filled with
    // 0xAA) the call changed.
    {
        unsigned extent = NAME_OFFSET + 2; // "." and its NUL
        unsigned ks[] = {16, extent - 1, extent, (unsigned)r1 - 1};
        for (int i = 0; i < 4; i++) {
            // Two runs, under fills 0xAA and 0x55: a byte the call wrote
            // differs from at least one fill, whatever it holds.
            unsigned char *buf = edge - ks[i];
            unsigned char seen[2][64];
            char label[32];
            snprintf(label, sizeof label, "first-%u", ks[i]);
            const unsigned char fills[2] = {0xAA, 0x55};
            for (int run = 0; run < 2; run++) {
                fd = fresh();
                memset(buf, fills[run], ks[i]);
                if (run == 0)
                    row(label, "edge", fd, buf, 4096, 1);
                else
                    gd(fd, buf, 4096);
                memcpy(seen[run], buf, ks[i]);
                close(fd);
            }
            int changed = 0;
            for (unsigned j = 0; j < ks[i]; j++)
                if (seen[0][j] != 0xAA || seen[1][j] != 0x55) changed++;
            printf("# %s: changed %d of %u writable bytes\n", label, changed, ks[i]);
        }
    }

    // A directory of 40 three-letter names, more than a 1024-byte buffer
    // holds on Darwin: through a writable buffer, and through one whose last
    // four bytes cannot be written.
    {
        setup(mkdir("big", 0755), "mkdir big");
        for (int i = 0; i < 40; i++) {
            char p[16];
            snprintf(p, sizeof p, "big/n%02d", i);
            int made = open(p, O_CREAT | O_EXCL | O_RDWR, 0644);
            setup(made, p);
            close(made);
        }
        fd = open("big", O_RDONLY | O_DIRECTORY);
        setup(fd, "open big");
        row("big-1024", "ok", fd, big, 1024, 1);
        close(fd);
        fd = open("big", O_RDONLY | O_DIRECTORY);
        setup(fd, "open big");
        row("big-tail-1024", "edge", fd, edge - 1020, 1024, 1);
        close(fd);
    }

    // A fault on the third record through a 512-byte buffer, which carries
    // no Darwin status word.
    {
        fd = fresh();
        memset(edge - (r1 + r2), 0xAA, r1 + r2);
        row("partial-R1+R2-512", "edge", fd, edge - (r1 + r2), 512, 1);
        close(fd);
    }
    // A removed directory through NULL and a 32-byte count.
    {
        fd = removed();
        row("removed-32", "null", fd, NULL, 32, 1);
        close(fd);
    }

    // A removed directory's access time, through a writable buffer and
    // through NULL, read through the descriptor still open on it; through
    // NULL, twice, with the times reset between.
    for (int d = 0; d < 2; d++) {
        setup(mkdir("gone", 0755), "mkdir gone");
        struct timespec ts[2] = {{1000, 0}, {0, UTIME_NOW}};
        setup(utimensat(AT_FDCWD, "gone", ts, 0), "utimensat gone");
        fd = open("gone", O_RDONLY | O_DIRECTORY);
        setup(fd, "open gone");
        setup(rmdir("gone"), "rmdir gone");
        for (int call = 0; call < (d == 0 ? 1 : 2); call++) {
            if (call > 0) setup(futimens(fd, ts), "futimens gone");
            struct stat st;
            setup(fstat(fd, &st), "fstat gone");
#ifdef __linux__
            long long baseline = (long long)st.st_atim.tv_sec;
#else
            long long baseline = (long long)st.st_atimespec.tv_sec;
#endif
            if (baseline != 1000) setup(-1, "gone's access time did not take");
            errno = 0;
            long r = gd(fd, dest(d), 4096);
            int e = r < 0 ? errno : 0;
            setup(fstat(fd, &st), "fstat gone");
#ifdef __linux__
            long long at = (long long)st.st_atim.tv_sec;
#else
            long long at = (long long)st.st_atimespec.tv_sec;
#endif
            printf("%-14s dest=%-9s: r=%ld errno=%s atime=%s\n", call == 0 ? "removed-atime" : "removed-atime-again",
                   dname[d], r, en(e), at == 1000 ? "kept" : "moved");
        }
        close(fd);
    }

#ifndef __linux__
    // Darwin's devfs, the other filesystem a Darwin directory is on.
    // Resumed: a writable read of one record, then one through NULL, the
    // access time watched across it, and what a writable read takes next.
    {
        fd = openDev();
        long first = gd(fd, big, 32);
        if (first != 32) setup(-1, "devfs-resumed's first read");
        char one[64] = "";
        names(big, first, one, sizeof one);
        struct stat before, after;
        setup(stat("/dev", &before), "stat /dev");
        usleep(10000);
        off_t from = lseek(fd, 0, SEEK_CUR);
        errno = 0;
        long r = gd(fd, NULL, 4096);
        int e = r < 0 ? errno : 0;
        off_t to = lseek(fd, 0, SEEK_CUR);
        setup(stat("/dev", &after), "stat /dev");
        int moved = before.st_atimespec.tv_sec != after.st_atimespec.tv_sec
            || before.st_atimespec.tv_nsec != after.st_atimespec.tv_nsec;
        long next = gd(fd, big, 32);
        char two[64] = "";
        names(big, next, two, sizeof two);
        printf("%-14s dest=%-9s: r=%ld errno=%s pos=%lld->%lld atime=%s\n", "devfs-resumed", "null", r, en(e),
               (long long)from, (long long)to, moved ? "moved" : "kept");
        printf("# devfs-resumed: first read %s, next read %s\n", one, two);
        close(fd);
    }
    // Small counts on a fresh description, and a 96-byte count through a
    // writable buffer.
    for (int i = 0; i < 2; i++) {
        fd = openDev();
        row("devfs-32", i == 0 ? "ok" : "null", fd, i == 0 ? big : NULL, 32, 0);
        close(fd);
    }
    {
        fd = openDev();
        row("devfs-96", "ok", fd, big, 96, 0);
        close(fd);
    }
    for (int d = 0; d < 4; d++) {
        fd = openDev();
        row("devfs-start", dname[d], fd, dest(d), 4096, 0);
        char out[65536];
        int n;
        rest(fd, out, sizeof out, &n);
        printf("# devfs-start: then %d entries\n", n);
        close(fd);
    }
    {
        fd = openDev();
        long first = gd(fd, big, sizeof big);
        printf("# devfs control r=%ld; R1=%u\n", first, reclen(big));
        unsigned dr1 = reclen(big);
        close(fd);
        fd = openDev();
        row("devfs-partial", "edge", fd, edge - dr1, 4096, 0);
        char out[65536];
        int n;
        rest(fd, out, sizeof out, &n);
        printf("# devfs-partial: then %d entries\n", n);
        close(fd);
        fd = openDev();
        rest(fd, out, sizeof out, &n);
        for (int d = 0; d < 4; d++) row("devfs-end", dname[d], fd, dest(d), 4096, 0);
        close(fd);
    }
    // Whether a read of /dev moves its access time, which devfs keeps to the
    // microsecond and moves on every listing call: at the start, and at the
    // end after a writable read has reached it. Each row waits 10 ms first,
    // so that a move is visible.
    for (int d = 0; d < 4; d++) {
        for (int atEnd = 0; atEnd < 2; atEnd++) {
            fd = openDev();
            if (atEnd) {
                char out[65536];
                int n;
                rest(fd, out, sizeof out, &n);
            }
            struct stat before, after;
            setup(stat("/dev", &before), "stat /dev");
            usleep(10000);
            errno = 0;
            long r = gd(fd, dest(d), 4096);
            int e = r < 0 ? errno : 0;
            setup(stat("/dev", &after), "stat /dev");
            int moved = before.st_atimespec.tv_sec != after.st_atimespec.tv_sec
                || before.st_atimespec.tv_nsec != after.st_atimespec.tv_nsec;
            printf("%-14s dest=%-9s: r=%ld errno=%s atime=%s\n", atEnd ? "devfs-atime-end" : "devfs-atime",
                   dname[d], r, en(e), moved ? "moved" : "kept");
            close(fd);
        }
    }
#endif
    return 0;
}
