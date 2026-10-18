// Measures st_blksize and st_blocks where stat-fields.c
// (docs/plans/2026-08-23-posix-kernel-extraction/) left them open: a pipe's as
// its buffer grows and as its ends close, a regular file's once it has a
// hole, before and after fsync(2) and after the kernel has had time to write
// the file back on its own, and a regular file's after a pwrite(2) whose
// buffer faults. Also a symbolic link's around the length where
// its blocks change, a directory of many names, a dense file of 16 MiB, and
// (Darwin) a clonefile(2) copy.
//
// Usage: stat-blocks <scratch-dir> <wait-seconds>
//   <scratch-dir>   an empty directory on the filesystem under test
//   <wait-seconds>  how long to leave the hole files open, unsynced, before
//                   reading them again
//
// Linux (tmpfs):
//   container run --rm -v "$PWD":/probe gcc:14 sh -c
//     'gcc -Wall -O0 -o /tmp/p /probe/stat-blocks.c && /tmp/p "$(mktemp -d -p /dev/shm)" 45'
// Darwin (APFS):
//   cc -Wall -O0 -o stat-blocks stat-blocks.c
//   ./stat-blocks "$(mktemp -d /private/tmp/stat-blocks.XXXXXX)" 45
//
// Each line names the object, then the fields fstat(2) or lstat(2) reported.
// Every pipe write is non-blocking and its count is printed, so a short write
// cannot pass for a full one.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/clonefile.h>
#endif

static char bytes[1 << 24];

static void report(const char *label, int result, const struct stat *st) {
    if (result != 0) {
        printf("%s\terr=%s\n", label, strerror(errno));
        return;
    }
    printf("%s\tsize=%lld\tblksize=%lld\tblocks=%lld\n", label, (long long)st->st_size, (long long)st->st_blksize,
           (long long)st->st_blocks);
}

static void fd_row(const char *label, int fd) {
    struct stat st;
    int result = fstat(fd, &st);
    report(label, result, &st);
}

static void path_row(const char *label, const char *path) {
    struct stat st;
    int result = lstat(path, &st);
    report(label, result, &st);
}

static void in(char *out, size_t size, const char *dir, const char *name) { snprintf(out, size, "%s/%s", dir, name); }

static int fresh(const char *dir, const char *name) {
    char path[1024];
    in(path, sizeof path, dir, name);
    unlink(path);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror(path);
        exit(1);
    }
    return fd;
}

static int nonblocking_pipe(int p[2]) {
    if (pipe(p) != 0) {
        perror("pipe");
        exit(1);
    }
    return fcntl(p[1], F_SETFL, O_NONBLOCK);
}

static void put(int fd, size_t count) { printf("WROTE\trequested=%zu\twrote=%zd\n", count, write(fd, bytes, count)); }

static void pipes(void) {
    int p[2];

    nonblocking_pipe(p);
    fd_row("PIPE\tread_end_empty", p[0]);
    fd_row("PIPE\twrite_end_empty", p[1]);
    put(p[1], 100);
    fd_row("PIPE\tread_end_holding_100", p[0]);
    fd_row("PIPE\twrite_end_holding_100", p[1]);
    put(p[1], 20000);
    fd_row("PIPE\tread_end_holding_20100", p[0]);
    fd_row("PIPE\twrite_end_holding_20100", p[1]);
    char drain[70000];
    printf("READ\tread=%zd\n", read(p[0], drain, sizeof drain));
    fd_row("PIPE\tread_end_drained", p[0]);
    close(p[1]);
    fd_row("PIPE\tread_end_drained_writer_closed", p[0]);
    close(p[0]);

    // One write of exactly 16384 bytes, and the same bytes one at a time: the
    // two measured Darwin buffers differ at 16384.
    nonblocking_pipe(p);
    put(p[1], 16384);
    fd_row("PIPE\tone_write_16384", p[0]);
    close(p[0]);
    close(p[1]);

    nonblocking_pipe(p);
    long long held = 0;
    long long previous = -1;
    for (;;) {
        struct stat st;
        fstat(p[0], &st);
        if ((long long)st.st_blksize != previous) {
            printf("PIPE\tbytewise_held=%lld\tblksize=%lld\tblocks=%lld\n", held, (long long)st.st_blksize,
                   (long long)st.st_blocks);
            previous = (long long)st.st_blksize;
        }
        if (write(p[1], bytes, 1) != 1)
            break;
        held++;
    }
    printf("PIPE\tbytewise_full_at=%lld\n", held);
    close(p[0]);
    close(p[1]);

    nonblocking_pipe(p);
    put(p[1], 70000);
    fd_row("PIPE\tread_end_after_70000", p[0]);
    for (int i = 0; i < 4; i++) {
        printf("READ\tread=%zd\n", read(p[0], drain, 20000));
        fd_row("PIPE\twrite_end_after_read", p[1]);
    }
    close(p[0]);
    close(p[1]);

    nonblocking_pipe(p);
    put(p[1], 100);
    close(p[0]);
    fd_row("PIPE\twrite_end_holding_100_reader_closed", p[1]);
    close(p[1]);

    nonblocking_pipe(p);
    put(p[1], 20000);
    close(p[0]);
    fd_row("PIPE\twrite_end_holding_20000_reader_closed", p[1]);
    close(p[1]);

    nonblocking_pipe(p);
    put(p[1], 20000);
    close(p[1]);
    fd_row("PIPE\tread_end_holding_20000_writer_closed", p[0]);
    close(p[0]);
}

struct hole {
    const char *name;
    long long offset;  // where one byte is written, if `extend` is 0
    long long extend;  // the length ftruncate(2) sets, if not 0
    int data_first;    // whether 4096 bytes are written at 0 first
    int sync;
};

static const struct hole holes[] = {
    {"extend_to_1MiB", 0, 1048576, 0, 0},
    {"extend_to_1MiB_fsync", 0, 1048576, 0, 1},
    {"byte_at_4096", 4096, 0, 0, 0},
    {"byte_at_4096_fsync", 4096, 0, 0, 1},
    {"byte_at_65536", 65536, 0, 0, 0},
    {"byte_at_65536_fsync", 65536, 0, 0, 1},
    {"byte_at_1MiB", 1048576, 0, 0, 0},
    {"byte_at_1MiB_fsync", 1048576, 0, 0, 1},
    {"byte_at_64MiB", 67108864, 0, 0, 0},
    {"byte_at_64MiB_fsync", 67108864, 0, 0, 1},
    {"4096_then_extend_to_1MiB", 0, 1048576, 1, 0},
    {"4096_then_extend_to_1MiB_fsync", 0, 1048576, 1, 1},
    {"4096_then_byte_at_1MiB", 1048576, 0, 1, 0},
    {"4096_then_byte_at_1MiB_fsync", 1048576, 0, 1, 1},
};

#define HOLES ((int)(sizeof holes / sizeof holes[0]))

static void files(const char *dir, int wait) {
    int fds[HOLES];
    char label[256];
    for (int i = 0; i < HOLES; i++) {
        int fd = fresh(dir, holes[i].name);
        fds[i] = fd;
        if (holes[i].data_first && write(fd, bytes, 4096) != 4096)
            perror("write");
        if (holes[i].extend) {
            if (ftruncate(fd, holes[i].extend) != 0)
                perror("ftruncate");
        } else if (pwrite(fd, "y", 1, holes[i].offset) != 1)
            perror("pwrite");
        if (holes[i].sync)
            fsync(fd);
        snprintf(label, sizeof label, "HOLE\t%s", holes[i].name);
        fd_row(label, fd);
    }
    sleep(wait);
    for (int i = 0; i < HOLES; i++) {
        snprintf(label, sizeof label, "HOLE\t%s_after_%ds", holes[i].name, wait);
        fd_row(label, fds[i]);
        close(fds[i]);
    }
    for (int i = 0; i < HOLES; i++) {
        char path[1024];
        in(path, sizeof path, dir, holes[i].name);
        snprintf(label, sizeof label, "HOLE\t%s_closed", holes[i].name);
        path_row(label, path);
    }

    int fd = fresh(dir, "dense_16MiB");
    if (write(fd, bytes, sizeof bytes) != (ssize_t)sizeof bytes)
        perror("write");
    fd_row("FILE\tdense_16MiB", fd);
    close(fd);

#ifdef __APPLE__
    char source[1024], clone[1024];
    in(source, sizeof source, dir, "clone_source");
    in(clone, sizeof clone, dir, "clone");
    fd = fresh(dir, "clone_source");
    if (write(fd, bytes, 40000) != 40000)
        perror("write");
    fsync(fd);
    close(fd);
    unlink(clone);
    if (clonefile(source, clone, 0) != 0)
        printf("FILE\tclone\terr=%s\n", strerror(errno));
    path_row("FILE\tclone_source_40000", source);
    path_row("FILE\tclone_of_40000", clone);
#endif
}

// A pwrite(2) from a buffer that faults as it is copied: NULL, or a
// PROT_NONE page. Each row names the file's shape before the call (its size
// and how it was made: `dense` one write from 0, `extended` ftruncate(2)
// alone, `empty` neither), the offset, the count and the buffer, and reports
// what pwrite returned, then the file's fields at once and after fsync(2).
static void faults(const char *dir) {
    static const struct {
        const char *shape;
        long long size;
        int dense;
    } shapes[] = {{"empty", 0, 0}, {"dense", 4096, 1}, {"dense", 5000, 1}, {"extended", 20000, 0}};
    static const long long offsets[] = {0, 1000, 4096, 5000, 8192, 12288, 100000};
    static const int counts[] = {1, 10000};
    void *protnone = mmap(NULL, 16384, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (protnone == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    for (int s = 0; s < (int)(sizeof shapes / sizeof shapes[0]); s++)
        for (int o = 0; o < (int)(sizeof offsets / sizeof offsets[0]); o++)
            for (int c = 0; c < (int)(sizeof counts / sizeof counts[0]); c++)
                for (int b = 0; b < 2; b++) {
                    int fd = fresh(dir, "fault");
                    if (shapes[s].dense) {
                        if (write(fd, bytes, (size_t)shapes[s].size) != (ssize_t)shapes[s].size)
                            perror("write");
                    } else if (shapes[s].size && ftruncate(fd, shapes[s].size) != 0)
                        perror("ftruncate");
                    errno = 0;
                    ssize_t ret = pwrite(fd, b ? protnone : NULL, (size_t)counts[c], offsets[o]);
                    int error = errno;
                    char label[256];
                    snprintf(label, sizeof label, "FAULT	%s_%lld_at_%lld_count_%d_%s_ret=%zd_errno=%d", shapes[s].shape,
                             shapes[s].size, offsets[o], counts[c], b ? "protnone" : "null", ret, error);
                    fd_row(label, fd);
                    fsync(fd);
                    snprintf(label, sizeof label, "FAULT	%s_%lld_at_%lld_count_%d_%s_fsync", shapes[s].shape,
                             shapes[s].size, offsets[o], counts[c], b ? "protnone" : "null");
                    fd_row(label, fd);
                    close(fd);
                }
}

// What becomes of the page a faulting pwrite(2) left at a page-aligned end
// of file: each row is a history of steps, `wN` a write of N bytes from 0,
// `fN` a faulting pwrite(2) of 1 byte from NULL at N, `tN` ftruncate(2) to N
// and `pN` a pwrite(2) of 1 byte at N.
static void fault_histories(const char *dir) {
    static const char *histories[] = {
        "f0",       "f0 t0",    "f0 t100",  "f0 p0",       "w4096 f4096",       "w4096 f4096 t4096",
        "w4096 f4096 t4095",    "w4096 f4096 t8192",       "w4096 f4096 p8192", "f8192",
        "f8192 f4096",          "f8192 t8192",             "f8192 t12288",      "f8192 t8191",
    };
    for (int h = 0; h < (int)(sizeof histories / sizeof histories[0]); h++) {
        int fd = fresh(dir, "history");
        char steps[128];
        snprintf(steps, sizeof steps, "%s", histories[h]);
        for (char *step = strtok(steps, " "); step; step = strtok(NULL, " ")) {
            long long n = atoll(step + 1);
            int ok;
            switch (step[0]) {
            case 'w': ok = write(fd, bytes, (size_t)n) == (ssize_t)n; break;
            case 'f': ok = pwrite(fd, NULL, 1, n) == -1 && errno == EFAULT; break;
            case 't': ok = ftruncate(fd, n) == 0; break;
            default: ok = pwrite(fd, "z", 1, n) == 1; break;
            }
            if (!ok)
                printf("HISTORY\t%s\tstep %s did not do what it names\n", histories[h], step);
        }
        char label[256];
        snprintf(label, sizeof label, "HISTORY\t%s", histories[h]);
        fd_row(label, fd);
        close(fd);
    }
}

static void symlinks(const char *dir) {
    static const int lengths[] = {126, 127, 128, 129, 1000, 1022, 1023, 1024, 4095};
    char target[4096];
    memset(target, 'a', sizeof target);
    for (int i = 0; i < (int)(sizeof lengths / sizeof lengths[0]); i++) {
        int length = lengths[i];
        char path[1024], label[64];
        snprintf(label, sizeof label, "LINK\ttarget_%d", length);
        snprintf(path, sizeof path, "%s/link_%d", dir, length);
        target[length] = 0;
        unlink(path);
        if (symlink(target, path) != 0)
            printf("%s\terr=%s\n", label, strerror(errno));
        else
            path_row(label, path);
        target[length] = 'a';
    }
}

static void directory(const char *dir) {
    char path[1024], name[1100];
    in(path, sizeof path, dir, "many");
    mkdir(path, 0755);
    for (int i = 1; i <= 20000; i++) {
        snprintf(name, sizeof name, "%s/f%d", path, i);
        close(open(name, O_CREAT | O_WRONLY, 0644));
        if (i == 5000 || i == 20000) {
            char label[64];
            snprintf(label, sizeof label, "DIR\tnames_%d", i);
            path_row(label, path);
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <scratch-dir> <wait-seconds>\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    memset(bytes, 'x', sizeof bytes);
    struct utsname u;
    uname(&u);
    printf("KERNEL\t%s %s %s\tuid=%d\tpagesize=%ld\tdir=%s\n", u.sysname, u.release, u.machine, (int)getuid(),
           sysconf(_SC_PAGESIZE), argv[1]);
    pipes();
    files(argv[1], atoi(argv[2]));
    faults(argv[1]);
    fault_histories(argv[1]);
    symlinks(argv[1]);
    directory(argv[1]);
    return 0;
}
