// copy_file_range(2) whose offset plus length passes 2^64 - 1: which offsets
// and lengths are EOVERFLOW, and where that check falls among the others.
//
// Linux only; output beside this file.
//
//     container run --rm -v "$PWD":/p gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/c /p/copy-file-range-overflow.c && uname -r && setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/c /dev/shm/cfo /tmp/cfo'
//
// The first directory must be on tmpfs (the filesystem the model answers for);
// the second must be on a different filesystem (the container's /tmp is
// ext4), for the EXDEV row. Run as root instead, every row but the euid line
// was the same.
//
// GRID rows: a 5-byte source and an empty destination, two descriptions on
// two files of the first directory, at every pair of offsets from OFFSETS and
// every length from LENGTHS together with the three lengths around each
// offset's largest non-wrapping one (2^64 - 1 - offset, then one less and one
// more). `form=desc` passes NULL offset pointers, the descriptions standing
// at the offsets; `form=ptr` passes pointers holding the offsets, the
// descriptions standing at 0. Each row prints the answer, then where each
// description stands afterwards, and for `form=ptr` what the pointers hold.
//
// ORDER rows: the wrap beside each other check copy_file_range makes, each
// once with a length that wraps and once with one that does not, so that the
// row shows both answers.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <unistd.h>

// Shorter than PATH_MAX, so that a name joined to either always fits.
static char tmpfs[256], other[256];

static void die(const char *what) {
    perror(what);
    exit(2);
}

static const char *en(int e) {
    static char buf[32];
    switch (e) {
    case EBADF: return "EBADF";
    case EINVAL: return "EINVAL";
    case EISDIR: return "EISDIR";
    case EXDEV: return "EXDEV";
    case EOVERFLOW: return "EOVERFLOW";
    case EFBIG: return "EFBIG";
    case EFAULT: return "EFAULT";
    case EPERM: return "EPERM";
    case ETXTBSY: return "ETXTBSY";
    }
    snprintf(buf, sizeof buf, "errno%d", e);
    return buf;
}

static void answer(char *out, size_t size, long r, int e) {
    if (r < 0)
        snprintf(out, size, "%s", en(e));
    else
        snprintf(out, size, "%ld", r);
}

// A fresh file `name` in `dir` holding `content`.
static void mkfile(const char *dir, const char *name, const char *content) {
    char pth[PATH_MAX];
    snprintf(pth, sizeof pth, "%s/%s", dir, name);
    unlink(pth);
    int fd = open(pth, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) die(pth);
    if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) die("write");
    close(fd);
}

static int openin(const char *dir, const char *name, int flags) {
    char pth[PATH_MAX];
    snprintf(pth, sizeof pth, "%s/%s", dir, name);
    int fd = open(pth, flags);
    if (fd < 0) die(pth);
    return fd;
}

static void seek(int fd, int64_t to) {
    if (lseek(fd, to, SEEK_SET) != to) die("lseek");
}

static int64_t pos(int fd) {
    return (int64_t)lseek(fd, 0, SEEK_CUR);
}

static long cfr(int in, loff_t *offIn, int out, loff_t *offOut, size_t len, unsigned flags) {
    return syscall(__NR_copy_file_range, in, offIn, out, offOut, len, flags);
}

static const int64_t OFFSETS[] = {
    0, 1, 4, 5, 6, (int64_t)1 << 62, INT64_MAX - 2, INT64_MAX - 1, INT64_MAX,
};
#define NOFFSETS (sizeof OFFSETS / sizeof OFFSETS[0])

static const uint64_t LENGTHS[] = {
    0,
    1,
    5,
    (uint64_t)INT64_MAX - 1,
    (uint64_t)INT64_MAX,
    (uint64_t)INT64_MAX + 1,
    (uint64_t)INT64_MAX + 2,
    (uint64_t)INT64_MAX + 3,
    UINT64_MAX - 6,
    UINT64_MAX - 5,
    UINT64_MAX - 4,
    UINT64_MAX - 3,
    UINT64_MAX - 2,
    UINT64_MAX - 1,
    UINT64_MAX,
};
#define NLENGTHS (sizeof LENGTHS / sizeof LENGTHS[0])

static int cmpu64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

// The lengths a grid row at offsets (in, out) tries: LENGTHS, and each
// offset's largest non-wrapping length with its neighbours, sorted and unique.
static size_t lengthsFor(int64_t in, int64_t out, uint64_t *into) {
    size_t n = 0;
    for (size_t k = 0; k < NLENGTHS; k++) into[n++] = LENGTHS[k];
    int64_t offs[2] = { in, out };
    for (int s = 0; s < 2; s++) {
        uint64_t largest = UINT64_MAX - (uint64_t)offs[s];
        into[n++] = largest - 1;
        into[n++] = largest;
        if (largest != UINT64_MAX) into[n++] = largest + 1;
    }
    qsort(into, n, sizeof into[0], cmpu64);
    size_t m = 0;
    for (size_t k = 0; k < n; k++)
        if (m == 0 || into[m - 1] != into[k]) into[m++] = into[k];
    return m;
}

static void grid(void) {
    printf("GRID: a 5-byte source, an empty destination, on %s\n", tmpfs);
    uint64_t lens[NLENGTHS + 6];
    for (int form = 0; form < 2; form++) {
        for (size_t i = 0; i < NOFFSETS; i++) {
            for (size_t o = 0; o < NOFFSETS; o++) {
                size_t nlens = lengthsFor(OFFSETS[i], OFFSETS[o], lens);
                for (size_t l = 0; l < nlens; l++) {
                    mkfile(tmpfs, "src", "hello");
                    mkfile(tmpfs, "dst", "");
                    int in = openin(tmpfs, "src", O_RDONLY);
                    int out = openin(tmpfs, "dst", O_WRONLY);
                    loff_t offIn = OFFSETS[i], offOut = OFFSETS[o];
                    long r;
                    errno = 0;
                    if (form == 0) {
                        seek(in, OFFSETS[i]);
                        seek(out, OFFSETS[o]);
                        r = cfr(in, NULL, out, NULL, lens[l], 0);
                    } else {
                        r = cfr(in, &offIn, out, &offOut, lens[l], 0);
                    }
                    int e = errno;
                    char a[32];
                    answer(a, sizeof a, r, e);
                    printf("GRID form=%s in=%lld out=%lld len=%llu -> %s inpos=%lld outpos=%lld", form == 0 ? "desc" : "ptr",
                           (long long)OFFSETS[i], (long long)OFFSETS[o], (unsigned long long)lens[l], a, (long long)pos(in),
                           (long long)pos(out));
                    if (form == 1) printf(" offin=%lld offout=%lld", (long long)offIn, (long long)offOut);
                    printf("\n");
                    close(in);
                    close(out);
                }
            }
        }
    }
    char pth[PATH_MAX];
    snprintf(pth, sizeof pth, "%s/src", tmpfs);
    unlink(pth);
    snprintf(pth, sizeof pth, "%s/dst", tmpfs);
    unlink(pth);
}

// One ORDER row: `label`, then the answer for each of the lengths `wrapping`
// and `fits`, each made against freshly made descriptors by `make`, which
// sets *in and *out (and their offsets) and says which to close afterwards.
typedef void (*maker)(int *in, int *out);

static void row(const char *label, maker make, uint64_t wrapping, uint64_t fits) {
    char a[2][32];
    uint64_t lens[2] = { wrapping, fits };
    int64_t inpos = -1, outpos = -1;
    for (int k = 0; k < 2; k++) {
        int in, out;
        make(&in, &out);
        errno = 0;
        long r = cfr(in, NULL, out, NULL, lens[k], 0);
        answer(a[k], sizeof a[k], r, errno);
        if (k == 0) {
            inpos = pos(in);
            outpos = pos(out);
        }
        if (in >= 0 && in != 700) close(in);
        if (out >= 0 && out != 700 && out != in) close(out);
    }
    printf("ORDER %s: len=%llu -> %s inpos=%lld outpos=%lld | len=%llu -> %s\n", label, (unsigned long long)wrapping, a[0],
           (long long)inpos, (long long)outpos, (unsigned long long)fits, a[1]);
}

static void rowFlags(const char *label, maker make, uint64_t wrapping, uint64_t fits, unsigned flags) {
    char a[2][32];
    uint64_t lens[2] = { wrapping, fits };
    for (int k = 0; k < 2; k++) {
        int in, out;
        make(&in, &out);
        errno = 0;
        long r = cfr(in, NULL, out, NULL, lens[k], flags);
        answer(a[k], sizeof a[k], r, errno);
        close(in);
        close(out);
    }
    printf("ORDER %s: len=%llu -> %s | len=%llu -> %s\n", label, (unsigned long long)wrapping, a[0], (unsigned long long)fits,
           a[1]);
}

static int closedFd(void) {
    // A number nothing else is given.
    close(700);
    return 700;
}

static void fresh(void) {
    mkfile(tmpfs, "src", "hello");
    mkfile(tmpfs, "dst", "");
}

// The source at 1, so that SIZE_MAX wraps on the source's side.
static void mkClosedIn(int *in, int *out) {
    fresh();
    *in = closedFd();
    *out = openin(tmpfs, "dst", O_WRONLY);
    seek(*out, 1);
}
static void mkClosedOut(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = closedFd();
}
static void mkGood(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = openin(tmpfs, "dst", O_WRONLY);
}
static void mkDirIn(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, ".", O_RDONLY);
    *out = openin(tmpfs, "dst", O_WRONLY);
    seek(*out, 1);
}
static void mkDirOut(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = openin(tmpfs, ".", O_RDONLY);
}
static void mkPipeIn(int *in, int *out) {
    int fds[2];
    fresh();
    if (pipe(fds) != 0) die("pipe");
    if (write(fds[1], "hello", 5) != 5) die("pipe write");
    close(fds[1]);
    *in = fds[0];
    *out = openin(tmpfs, "dst", O_WRONLY);
    seek(*out, 1);
}
static void mkSocketOut(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = socket(AF_INET, SOCK_STREAM, 0);
    if (*out < 0) die("socket");
}
static void mkWriteOnlyIn(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_WRONLY);
    seek(*in, 1);
    *out = openin(tmpfs, "dst", O_WRONLY);
}
static void mkReadOnlyOut(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = openin(tmpfs, "dst", O_RDONLY);
}
static void mkCrossFs(int *in, int *out) {
    fresh();
    mkfile(other, "dst", "");
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = openin(other, "dst", O_WRONLY);
}
// One description, at 1, as both: [1, 5) against [1, 5) after shortening.
static void mkSameDescription(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDWR);
    seek(*in, 1);
    *out = *in;
}
// Two descriptions of one file, the source at 1 and the destination at 2.
static void mkSameFile(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = openin(tmpfs, "src", O_WRONLY);
    seek(*out, 2);
}
// A destination at INT64_MAX: SIZE_MAX wraps, SSIZE_MAX + 1 reaches exactly
// 2^64 - 1 and does not.
static void mkDestinationAtMax(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    *out = openin(tmpfs, "dst", O_WRONLY);
    seek(*out, INT64_MAX);
}
// The source at its end: 5 + (2^64 - 5) wraps, 5 + (2^64 - 6) does not.
static void mkSourceAtEnd(int *in, int *out) {
    fresh();
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 5);
    *out = openin(tmpfs, "dst", O_WRONLY);
}
// An empty source, at 1.
static void mkEmptySource(int *in, int *out) {
    mkfile(tmpfs, "src", "");
    mkfile(tmpfs, "dst", "");
    *in = openin(tmpfs, "src", O_RDONLY);
    seek(*in, 1);
    *out = openin(tmpfs, "dst", O_WRONLY);
}

static void order(void) {
    printf("ORDER: on %s, the other filesystem %s; the first length wraps, the second does not\n", tmpfs, other);
    row("closed-in", mkClosedIn, UINT64_MAX, 5);
    row("closed-out", mkClosedOut, UINT64_MAX, 5);
    rowFlags("flags1", mkGood, UINT64_MAX, 5, 1);
    row("dir-in", mkDirIn, UINT64_MAX, 5);
    row("dir-out", mkDirOut, UINT64_MAX, 5);
    row("pipe-in", mkPipeIn, UINT64_MAX, 5);
    row("socket-out", mkSocketOut, UINT64_MAX, 5);
    row("write-only-in", mkWriteOnlyIn, UINT64_MAX, 5);
    row("read-only-out", mkReadOnlyOut, UINT64_MAX, 5);
    row("cross-filesystem", mkCrossFs, UINT64_MAX, 5);
    row("same-description", mkSameDescription, UINT64_MAX, 5);
    row("same-file", mkSameFile, UINT64_MAX, 5);
    row("destination-at-max", mkDestinationAtMax, UINT64_MAX, (uint64_t)INT64_MAX + 1);
    row("source-at-end", mkSourceAtEnd, UINT64_MAX - 4, UINT64_MAX - 5);
    row("empty-source", mkEmptySource, UINT64_MAX, UINT64_MAX - 1);
}

int main(int argc, char **argv) {
    alarm(600);
    if (argc != 3) {
        fprintf(stderr, "usage: %s <tmpfs directory to create> <directory to create on another filesystem>\n", argv[0]);
        return 2;
    }
    snprintf(tmpfs, sizeof tmpfs, "%s", argv[1]);
    snprintf(other, sizeof other, "%s", argv[2]);
    mkdir(tmpfs, 0777);
    mkdir(other, 0777);
    struct stat a, b;
    if (stat(tmpfs, &a) != 0 || stat(other, &b) != 0) die("stat");
    if (a.st_dev == b.st_dev) {
        fprintf(stderr, "%s and %s are on one filesystem\n", tmpfs, other);
        return 2;
    }
    struct statfs fa, fb;
    if (statfs(tmpfs, &fa) != 0 || statfs(other, &fb) != 0) die("statfs");
    if (fa.f_type != 0x01021994) {
        fprintf(stderr, "%s is not on tmpfs (f_type %lx)\n", tmpfs, (long)fa.f_type);
        return 2;
    }
    printf("euid %u, %s f_type %lx, %s f_type %lx\n", geteuid(), tmpfs, (long)fa.f_type, other, (long)fb.f_type);
    grid();
    order();
    return 0;
}
