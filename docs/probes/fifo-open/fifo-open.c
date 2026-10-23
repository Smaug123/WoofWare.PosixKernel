// Opening a FIFO: when an open blocks, what wakes it, what a signal does to it,
// what the non-blocking opens answer, and what fstat reports of each end. For
// the design of a blocking open in WoofWare.PosixKernel.
//
// Both flavours; outputs beside this file.
//
//     cc -Wall -O1 -pthread -o /tmp/fifo-open fifo-open.c && uname -rm && sw_vers -productVersion && /tmp/fifo-open
//     container run --rm --cap-add CAP_SYS_NICE -v "$PWD:/probe" debian:trixie sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -O1 -pthread -o /tmp/p /probe/fifo-open.c && uname -rm && ldd --version | head -1 && /tmp/p'
//
// Every section runs in a forked child, on a FIFO made fresh (mode 0600) in a
// fresh directory under /tmp whose group is the caller's own. A child that
// hangs is killed by SIGALRM after 30 s, and the parent prints that. SIGPIPE is
// ignored, so a write with no reader reports EPIPE.
//
// An "opener" is a thread blocked in one open(2) of the FIFO. It is started
// and given 100 ms to fall asleep; "asleep" means the call had not returned
// when the main thread looked. "Main" is the section's main thread.
//
// Sections:
//   A  a blocking O_RDONLY open with no writer, and what wakes it.
//      A1 main opens O_WRONLY (blocking).
//      A2 main opens O_WRONLY|O_NONBLOCK and closes it at once. Unforced: the
//         reader may run before or after the close.
//      A3 (Linux) as A2, with the reader unable to run between the open and
//         the close: both threads on CPU 0, main under SCHED_FIFO. Needs
//         CAP_SYS_NICE; without it A3 says so.
//      A4 the reader is a child process, stopped (SIGSTOP) while main opens
//         O_WRONLY|O_NONBLOCK and closes it; then continued (SIGCONT).
//      A5 two readers asleep; main opens O_WRONLY|O_NONBLOCK and keeps it.
//      A6 main opens O_RDWR.
//      A7 main opens O_RDONLY|O_NONBLOCK: a second reader, no writer.
//      A8 (the control for A4) the reader child is stopped and continued, and
//         main opens nothing meanwhile.
//      A9 A2, 30 times, each on a fresh FIFO: how often the reader is still
//         asleep 50 ms after the partner's close.
//   B  the same for a blocking O_WRONLY open with no reader (B1-B6 mirror
//      A1-A6, B7 A8, B8 A9, the partner being O_RDONLY|O_NONBLOCK). In B2 and
//      B3 the writer, once returned, writes one byte.
//   C  the non-blocking opens and O_RDWR.
//      C1 O_RDONLY|O_NONBLOCK, no writer: read and poll; then a writer opens
//         O_WRONLY|O_NONBLOCK and closes, and read and poll again.
//      C2 O_WRONLY|O_NONBLOCK, no reader.
//      C3 O_WRONLY|O_NONBLOCK with a reader; poll the write end; the reader
//         closes; poll and write again.
//      C4 O_RDWR, nobody else (in a thread, in case it blocks); write 3
//         bytes and read them back through the same descriptor.
//      C5 O_RDWR|O_NONBLOCK.
//      C6 access mode 3 (O_ACCMODE), with O_NONBLOCK.
//   D  a signal with a handler sent to a blocked opener (pthread_kill).
//      D1 reader, no SA_RESTART. Then main opens O_WRONLY|O_NONBLOCK, which
//         says whether the interrupted reader still counts as a reader.
//      D2 reader, SA_RESTART. Then main opens O_WRONLY|O_NONBLOCK.
//      D3 writer, no SA_RESTART. Then another thread opens O_RDONLY, which
//         says whether the interrupted writer still counts as a writer.
//      D4 writer, SA_RESTART. Then main opens O_RDONLY|O_NONBLOCK.
//      D5 (the control for D2 and D4) a blocking read of an empty anonymous
//         pipe, SA_RESTART: still asleep after the handler runs.
//   E  stat and fstat.
//      E1 stat of the path: type, permissions, size, link count, device
//         (against the directory's), rdev, blksize, blocks.
//      E2 an O_RDWR descriptor: fstat; then 3 bytes written (10 ms after the
//         open), fstat, FIONREAD, and whether mtime, ctime moved; then 1 byte
//         read (10 ms later), whether atime moved, and fstat.
//      E3 separate read and write ends, 3 bytes held: each end's fstat, stat
//         of the path, and FIONREAD on each end.
//      E4 lseek and pread on the O_RDWR descriptor.
//      E5 fchmod through the descriptor, then stat of the path.
//   F  the bytes' lifetime.
//      F1 O_RDWR, write 3, close; reopen O_RDWR|O_NONBLOCK and read.
//      F2 a reader kept open; a writer opens, writes 3, closes; another writer
//         opens; the reader reads.
//   G  making a FIFO, and the creating opens of one (umask 022).
//   H  how much a FIFO takes against an anonymous pipe: non-blocking writes of
//      1 (H1), 4096 (H2) and 1000 (H3) bytes until EAGAIN, and whether the
//      write end then polls writable.
//   I  the descriptor a sleeping open will return. The child holds 0, 1 and 2,
//      so the lowest free descriptor is 3 when the reader starts.
//      I1 main opens /dev/null while the reader sleeps.
//      I2 fcntl(3, F_GETFD). I3 close(3). I4 dup2 of the /dev/null descriptor
//      onto 3, in a thread, since it may wait. I5 a writer opens: the reader's
//      answer, and the dup2's. I6 fstat(3): which of the two holds it.
//
// The uid 1000 Linux run is the same command with the last step replaced by
// `setpriv --reuid 1000 --regid 1000 --clear-groups /tmp/p` (after
// `chmod 755 /tmp/p`); SCHED_FIFO is then refused, so A3 and B3 say so.
//
// Measured 2026-10-11 on Darwin 27.0.0 arm64 (macOS 27.0.1, uid 501, APFS)
// and on Linux 6.18.5 aarch64 (Apple `container`, debian:trixie, glibc 2.41,
// ext4, five CPUs) as root and as uid 1000. Sections A-G were run five times on
// Darwin, four times as Linux root and three times as uid 1000; H and I twice
// on each. The answers were the same each time, bar the order of B5's lines.
// (An earlier version of I called dup2 from the main thread; on Darwin it
// never returned, and SIGALRM did not end it.)
//
// The same on both flavours:
//   - A blocking O_RDONLY open with no writer sleeps (A1), and so does a
//     blocking O_WRONLY open with no reader (B1). While it sleeps it counts as
//     a reader (a writer): main's O_WRONLY|O_NONBLOCK succeeds against a
//     sleeping reader rather than answering ENXIO (A2).
//   - Any open of the partner's kind wakes every sleeper (A5, B5), and O_RDWR
//     counts as either partner (A6, B6). An open of the sleeper's own kind does
//     not wake it (A7).
//   - A partner that opens and closes before the sleeper runs still completes
//     the open, with success: on Linux with the order forced by SCHED_FIFO (A3,
//     B3: the opener had not returned by the close, and returned OK after), on
//     Darwin with the sleeper stopped across the partner's open and close (A4,
//     B4; A8 and B7, stopping and continuing with no partner, wake nothing).
//     So neither kernel waits for a partner to be *present*: Linux waits for
//     the partner count to change (`wait_for_partner`). A writer that woke this
//     way then writes into a FIFO with no reader: EPIPE (B2, B3).
//   - O_RDONLY|O_NONBLOCK with no writer succeeds; a read answers 0 with no
//     writer and EAGAIN with a writer and nothing held (C1).
//     O_WRONLY|O_NONBLOCK with no reader is ENXIO (C2, G8, O_CREAT included).
//   - O_RDWR never blocks, with or without O_NONBLOCK, and the descriptor
//     reads back what it wrote (C4, C5). Access mode 3 is EINVAL (C6).
//   - A signal with a handler and no SA_RESTART ends a sleeping open with
//     EINTR, and the call no longer counts as a reader or writer: ENXIO for a
//     later O_WRONLY|O_NONBLOCK (D1); a later O_RDONLY sleeps (D3).
//   - fstat of either end, and of an O_RDWR descriptor: S_IFIFO, the path's
//     permissions, inode and device, st_size 0 whatever is held, nlink 1,
//     rdev 0, blksize 4096, blocks 0 (E1-E3). A write moves the inode's mtime
//     and ctime, as stat of the path sees, and a read its atime (E2). lseek and
//     pread are ESPIPE (E4). fchmod through the descriptor changes the inode
//     (E5).
//   - The bytes go when the last end closes (F1), and stay while any end is
//     open (F2).
//   - mkfifo and mknod(S_IFIFO) agree, and keep all twelve mode bits under the
//     umask: 07777 under 022 makes 07755, as root and as uid 1000 on Linux and
//     as uid 501 on Darwin (G1-G4). O_CREAT|O_EXCL of an existing FIFO is
//     EEXIST, O_CREAT alone opens it, O_TRUNC is accepted, O_DIRECTORY is
//     ENOTDIR, and mkfifoat and openat work from a directory descriptor
//     (G5-G12).
// Where they differ:
//   - SA_RESTART: Linux restarts the sleeping open, which sleeps on and
//     completes when a partner opens (D2, D4). Darwin answers EINTR as without
//     SA_RESTART, although the same handler restarts a blocking pipe read on
//     both (D5, the control).
//   - Stopping the sleeper: on Linux SIGSTOP ends the sleep (the call stops
//     counting as a reader, so the partner's O_WRONLY|O_NONBLOCK is ENXIO) and
//     SIGCONT restarts it, asleep again (A4, B4). On Darwin the stopped sleeper
//     still counts, and a partner that came and went while it was stopped
//     completes its open (A4, B4).
//   - poll(POLLIN|POLLOUT) of an O_RDONLY|O_NONBLOCK descriptor: Linux reports
//     nothing while no writer has ever opened, nothing while one is open with
//     nothing held, and POLLHUP once that writer has closed (C1). Darwin
//     reports POLLOUT, on a read-only descriptor, in all three states. A write
//     end whose reader closed: Linux POLLOUT|POLLERR, Darwin POLLOUT (C3).
//   - FIONREAD with 3 bytes held: Linux 3 on the read end, the write end and
//     an O_RDWR descriptor; Darwin 3 on the read end and 0 on the write end and
//     on an O_RDWR descriptor (E2, E3).
//   - The buffer: a Linux FIFO takes what a Linux pipe takes (65536 bytes in
//     writes of 1 and of 4096, 64000 in writes of 1000). A Darwin FIFO takes
//     8192 (8000 in writes of 1000, after which its write end polls
//     writable), where a Darwin pipe takes 65536 (H1-H3). So a Darwin FIFO is
//     not a Darwin pipe.
//   - The descriptor a sleeping open will return is taken before it sleeps,
//     on both: main's /dev/null gets 4 while the reader sleeps, and the reader
//     returns 3 (I1). Meanwhile fcntl and close of 3 are EBADF on both (I2,
//     I3). dup2 onto 3 is EBUSY on Linux, and the open then returns 3 (I4-I6).
//     On Darwin the dup2 waits until the open returns 3, and then replaces it:
//     fstat(3) is /dev/null's (I4-I6).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *en(int e)
{
    switch (e) {
    case 0: return "OK";
    case EBADF: return "EBADF";
    case EINVAL: return "EINVAL";
    case EINTR: return "EINTR";
    case EAGAIN: return "EAGAIN";
    case EPIPE: return "EPIPE";
    case ENXIO: return "ENXIO";
    case ESPIPE: return "ESPIPE";
    case EEXIST: return "EEXIST";
    case ENOTDIR: return "ENOTDIR";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case EISDIR: return "EISDIR";
    case EBUSY: return "EBUSY";
    default: {
        static char b[32];
        snprintf(b, sizeof b, "errno%d", e);
        return b;
    }
    }
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
}

static char dir[256], fifo[300];

static void fresh(void)
{
    strcpy(dir, "/tmp/fifo-open-XXXXXX");
    if (!mkdtemp(dir)) { perror("mkdtemp"); exit(1); }
    // New nodes take the directory's group under BSD rules; make it ours, so
    // that a set-group-ID bit is not stripped for want of membership.
    if (chown(dir, (uid_t)-1, getegid()) != 0) { perror("chown dir"); exit(1); }
    snprintf(fifo, sizeof fifo, "%s/f", dir);
    if (mkfifo(fifo, 0600) != 0) { perror("mkfifo"); exit(1); }
}

static const char *rvs(int rv, int err)
{
    static char b[4][48];
    static int i = 0;
    i = (i + 1) % 4;
    if (rv >= 0) snprintf(b[i], sizeof b[i], "OK(%d)", rv);
    else snprintf(b[i], sizeof b[i], "%s", en(err));
    return b[i];
}

#define OPEN(...) ({ int _r = open(__VA_ARGS__); int _e = errno; errno = _e; _r; })

struct opener {
    const char *path;
    int flags;
    pthread_t t;
    atomic_int done;
    int rv, err;
};

static void *open_thread(void *p)
{
    struct opener *o = p;
    int rv = open(o->path, o->flags);
    o->err = rv < 0 ? errno : 0;
    o->rv = rv;
    atomic_store(&o->done, 1);
    return NULL;
}

static void start(struct opener *o, int flags)
{
    o->path = fifo;
    o->flags = flags;
    atomic_store(&o->done, 0);
    pthread_create(&o->t, NULL, open_thread, o);
}

static const char *st(struct opener *o)
{
    static char b[4][48];
    static int i = 0;
    i = (i + 1) % 4;
    if (!atomic_load(&o->done)) return "asleep";
    snprintf(b[i], sizeof b[i], "returned %s", rvs(o->rv, o->err));
    return b[i];
}

static atomic_int handled;
static void on_usr1(int s) { (void)s; atomic_fetch_add(&handled, 1); }

static void install(int restart)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);
}

static const char *pollstr(int fd)
{
    static char b[4][96];
    static int i = 0;
    i = (i + 1) % 4;
    struct pollfd p = { fd, POLLIN | POLLOUT, 0 };
    int rv = poll(&p, 1, 0);
    if (rv < 0) { snprintf(b[i], sizeof b[i], "poll %s", en(errno)); return b[i]; }
    snprintf(b[i], sizeof b[i], "poll rv=%d revents=%s%s%s%s%s(0x%x)", rv,
             p.revents & POLLIN ? "IN|" : "", p.revents & POLLOUT ? "OUT|" : "",
             p.revents & POLLHUP ? "HUP|" : "", p.revents & POLLERR ? "ERR|" : "",
             p.revents & POLLNVAL ? "NVAL|" : "", p.revents);
    return b[i];
}

static const char *readstr(int fd, int n)
{
    static char b[4][48];
    static int i = 0;
    i = (i + 1) % 4;
    char buf[64];
    ssize_t r = read(fd, buf, (size_t)n);
    if (r < 0) snprintf(b[i], sizeof b[i], "read %s", en(errno));
    else snprintf(b[i], sizeof b[i], "read %zd", r);
    return b[i];
}

static const char *writestr(int fd, int n)
{
    static char b[4][48];
    static int i = 0;
    i = (i + 1) % 4;
    ssize_t r = write(fd, "abcdefgh", (size_t)n);
    if (r < 0) snprintf(b[i], sizeof b[i], "write %s", en(errno));
    else snprintf(b[i], sizeof b[i], "write %zd", r);
    return b[i];
}

static const char *statstr(const struct stat *s)
{
    static char b[2][160];
    static int i = 0;
    i = (i + 1) % 2;
    snprintf(b[i], sizeof b[i], "type=%s perm=%04o size=%lld nlink=%d rdev=%lld blksize=%d blocks=%lld",
             S_ISFIFO(s->st_mode) ? "S_IFIFO" : "other", (unsigned)(s->st_mode & 07777),
             (long long)s->st_size, (int)s->st_nlink, (long long)s->st_rdev, (int)s->st_blksize,
             (long long)s->st_blocks);
    return b[i];
}

#ifdef __APPLE__
#define MTIM(s) ((s).st_mtimespec)
#define CTIM(s) ((s).st_ctimespec)
#define ATIM(s) ((s).st_atimespec)
#else
#define MTIM(s) ((s).st_mtim)
#define CTIM(s) ((s).st_ctim)
#define ATIM(s) ((s).st_atim)
#endif
static int moved(struct timespec a, struct timespec b) { return a.tv_sec != b.tv_sec || a.tv_nsec != b.tv_nsec; }

// ---------------------------------------------------------------- A and B

// A blocked opener of `flags`; main opens `partner` and closes it at once.
static void partner_open_close(const char *tag, int flags, int partner)
{
    struct opener o;
    start(&o, flags);
    sleep_ms(100);
    printf("%s opener 100 ms in: %s\n", tag, st(&o));
    int fd = OPEN(fifo, partner);
    printf("%s main's partner open: %s\n", tag, rvs(fd, errno));
    if (fd >= 0) close(fd);
    sleep_ms(100);
    printf("%s opener 100 ms after the partner's close: %s\n", tag, st(&o));
    if (atomic_load(&o.done) && o.rv >= 0 && (flags & O_ACCMODE) == O_WRONLY)
        printf("%s opener's descriptor: %s\n", tag, writestr(o.rv, 1));
}

static void forced(const char *tag, int flags, int partner)
{
#ifdef __linux__
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    if (sched_setaffinity(0, sizeof one, &one) != 0) {
        printf("%s sched_setaffinity: %s; not measured\n", tag, en(errno));
        return;
    }
    struct opener o;
    start(&o, flags); // inherits the affinity
    sleep_ms(100);
    printf("%s opener 100 ms in: %s\n", tag, st(&o));
    struct sched_param sp = { .sched_priority = 50 };
    int e = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    if (e != 0) {
        printf("%s SCHED_FIFO: %s; not measured\n", tag, en(e));
        return;
    }
    int fd = OPEN(fifo, partner);
    int err = errno;
    int before = atomic_load(&o.done);
    if (fd >= 0) close(fd);
    int after_close = atomic_load(&o.done);
    sp.sched_priority = 0;
    pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp);
    printf("%s main's partner open: %s; opener had returned before the close: %d, by the close's return: %d\n", tag,
           rvs(fd, err), before, after_close);
    sleep_ms(100);
    printf("%s opener 100 ms after the partner's close: %s\n", tag, st(&o));
    if (atomic_load(&o.done) && o.rv >= 0 && (flags & O_ACCMODE) == O_WRONLY)
        printf("%s opener's descriptor: %s\n", tag, writestr(o.rv, 1));
#else
    (void)flags;
    (void)partner;
    printf("%s Linux only\n", tag);
#endif
}

static void stopped_child(const char *tag, int flags, int partner)
{
    int res[2];
    if (pipe(res) != 0) { perror("pipe"); exit(1); }
    pid_t pid = fork();
    if (pid == 0) {
        close(res[0]);
        int fd = open(fifo, flags);
        int r[2] = { fd, fd < 0 ? errno : 0 };
        write(res[1], r, sizeof r);
        _exit(0);
    }
    close(res[1]);
    sleep_ms(100);
    kill(pid, SIGSTOP);
    int status;
    waitpid(pid, &status, WUNTRACED);
    printf("%s child stopped: %d\n", tag, WIFSTOPPED(status));
    if (partner >= 0) {
        int fd = OPEN(fifo, partner);
        printf("%s main's partner open while the child is stopped: %s\n", tag, rvs(fd, errno));
        if (fd >= 0) close(fd);
    } else
        printf("%s main opens nothing while the child is stopped\n", tag);
    kill(pid, SIGCONT);
    sleep_ms(200);
    int r[2];
    fcntl(res[0], F_SETFL, O_NONBLOCK);
    if (read(res[0], r, sizeof r) == (ssize_t)sizeof r)
        printf("%s child 200 ms after SIGCONT: returned %s\n", tag, rvs(r[0], r[1]));
    else {
        printf("%s child 200 ms after SIGCONT: asleep\n", tag);
        int fd2 = OPEN(fifo, partner >= 0 ? partner : ((flags & O_ACCMODE) == O_RDONLY ? O_WRONLY | O_NONBLOCK : O_RDONLY | O_NONBLOCK));
        printf("%s main's second partner open: %s\n", tag, rvs(fd2, errno));
        sleep_ms(100);
        if (read(res[0], r, sizeof r) == (ssize_t)sizeof r)
            printf("%s child 100 ms later: returned %s\n", tag, rvs(r[0], r[1]));
        else
            printf("%s child 100 ms later: asleep\n", tag);
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
}

// 1: a blocked opener; main opens the partner, blocking, and keeps it.
static void blocking_partner(const char *tag, int flags, int partner)
{
    struct opener o;
    start(&o, flags);
    sleep_ms(100);
    printf("%s opener 100 ms in: %s\n", tag, st(&o));
    int fd = OPEN(fifo, partner);
    printf("%s main's blocking partner open: %s\n", tag, rvs(fd, errno));
    sleep_ms(100);
    printf("%s opener 100 ms later: %s\n", tag, st(&o));
}

// 5: two blocked openers; main opens the partner and keeps it.
static void two_openers(const char *tag, int flags, int partner)
{
    struct opener o, o2;
    start(&o, flags);
    start(&o2, flags);
    sleep_ms(100);
    printf("%s openers 100 ms in: %s, %s\n", tag, st(&o), st(&o2));
    int fd = OPEN(fifo, partner);
    printf("%s main's partner open: %s\n", tag, rvs(fd, errno));
    sleep_ms(100);
    printf("%s openers 100 ms later: %s, %s\n", tag, st(&o), st(&o2));
}

// A blocked opener; main opens `other` and keeps it.
static void other_open(const char *tag, int flags, int other)
{
    struct opener o;
    start(&o, flags);
    sleep_ms(100);
    printf("%s opener 100 ms in: %s\n", tag, st(&o));
    int fd = OPEN(fifo, other);
    printf("%s main's open: %s\n", tag, rvs(fd, errno));
    sleep_ms(100);
    printf("%s opener 100 ms later: %s\n", tag, st(&o));
}

static void A1(void) { blocking_partner("A1", O_RDONLY, O_WRONLY); }
static void A2(void) { partner_open_close("A2", O_RDONLY, O_WRONLY | O_NONBLOCK); }
static void A3(void) { forced("A3", O_RDONLY, O_WRONLY | O_NONBLOCK); }
static void A4(void) { stopped_child("A4", O_RDONLY, O_WRONLY | O_NONBLOCK); }
static void A8(void) { stopped_child("A8", O_RDONLY, -1); }

// A2 repeated: how often an opener found asleep is still asleep after a partner
// opened and closed while it slept.
static void repeated(const char *tag, int flags, int partner)
{
    int asleep_before = 0, returned = 0, still = 0, trials = 30;
    for (int i = 0; i < trials; i++) {
        snprintf(fifo, sizeof fifo, "%s/r%d", dir, i);
        mkfifo(fifo, 0600);
        struct opener o;
        start(&o, flags);
        sleep_ms(30);
        if (atomic_load(&o.done)) continue;
        asleep_before++;
        int fd = open(fifo, partner);
        if (fd >= 0) close(fd);
        sleep_ms(50);
        if (atomic_load(&o.done)) returned++;
        else {
            still++;
            // Release it.
            open(fifo, partner);
        }
    }
    printf("%s %d trials: opener asleep before the partner %d; returned after the partner's open and close %d; "
           "still asleep %d\n",
           tag, trials, asleep_before, returned, still);
}
static void A9(void) { repeated("A9", O_RDONLY, O_WRONLY | O_NONBLOCK); }
static void A5(void) { two_openers("A5", O_RDONLY, O_WRONLY | O_NONBLOCK); }
static void A6(void) { other_open("A6", O_RDONLY, O_RDWR); }
static void A7(void) { other_open("A7", O_RDONLY, O_RDONLY | O_NONBLOCK); }
static void B1(void) { blocking_partner("B1", O_WRONLY, O_RDONLY); }
static void B2(void) { partner_open_close("B2", O_WRONLY, O_RDONLY | O_NONBLOCK); }
static void B3(void) { forced("B3", O_WRONLY, O_RDONLY | O_NONBLOCK); }
static void B4(void) { stopped_child("B4", O_WRONLY, O_RDONLY | O_NONBLOCK); }
static void B7(void) { stopped_child("B7", O_WRONLY, -1); }
static void B8(void) { repeated("B8", O_WRONLY, O_RDONLY | O_NONBLOCK); }
static void B5(void) { two_openers("B5", O_WRONLY, O_RDONLY | O_NONBLOCK); }
static void B6(void) { other_open("B6", O_WRONLY, O_RDWR); }

// ---------------------------------------------------------------- C

static void C1(void)
{
    int r = OPEN(fifo, O_RDONLY | O_NONBLOCK);
    printf("C1 open(O_RDONLY|O_NONBLOCK), no writer: %s\n", rvs(r, errno));
    if (r < 0) return;
    printf("C1 no writer yet: %s; %s\n", readstr(r, 1), pollstr(r));
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("C1 a writer opens O_WRONLY|O_NONBLOCK: %s; reader's %s\n", rvs(w, errno), pollstr(r));
    printf("C1 writer open: reader's %s\n", readstr(r, 1));
    close(w);
    printf("C1 writer closed: reader's %s; %s\n", pollstr(r), readstr(r, 1));
}

static void C2(void)
{
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("C2 open(O_WRONLY|O_NONBLOCK), no reader: %s\n", rvs(w, errno));
}

static void C3(void)
{
    int r = OPEN(fifo, O_RDONLY | O_NONBLOCK);
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("C3 open(O_WRONLY|O_NONBLOCK) with a reader: %s; write end's %s\n", rvs(w, errno), pollstr(w));
    close(r);
    printf("C3 reader closed: write end's %s; %s\n", pollstr(w), writestr(w, 1));
}

static void C4(void)
{
    struct opener o;
    start(&o, O_RDWR);
    sleep_ms(100);
    printf("C4 open(O_RDWR), nobody else, 100 ms in: %s\n", st(&o));
    if (!atomic_load(&o.done) || o.rv < 0) return;
    printf("C4 through it: %s, %s; %s\n", writestr(o.rv, 3), readstr(o.rv, 8), pollstr(o.rv));
}

static void C5(void)
{
    int fd = OPEN(fifo, O_RDWR | O_NONBLOCK);
    printf("C5 open(O_RDWR|O_NONBLOCK): %s\n", rvs(fd, errno));
}

static void C6(void)
{
    int fd = OPEN(fifo, O_ACCMODE | O_NONBLOCK);
    printf("C6 open(O_ACCMODE|O_NONBLOCK): %s\n", rvs(fd, errno));
}

// ---------------------------------------------------------------- D

static void D_reader(const char *tag, int restart)
{
    install(restart);
    struct opener o;
    start(&o, O_RDONLY);
    sleep_ms(100);
    printf("%s reader 100 ms in: %s\n", tag, st(&o));
    pthread_kill(o.t, SIGUSR1);
    sleep_ms(100);
    printf("%s 100 ms after SIGUSR1 (handler ran %d times): reader %s\n", tag, atomic_load(&handled), st(&o));
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("%s then main's open(O_WRONLY|O_NONBLOCK): %s\n", tag, rvs(w, errno));
    sleep_ms(100);
    printf("%s reader 100 ms later: %s\n", tag, st(&o));
}

static void D_writer(const char *tag, int restart)
{
    install(restart);
    struct opener o, o2;
    start(&o, O_WRONLY);
    sleep_ms(100);
    printf("%s writer 100 ms in: %s\n", tag, st(&o));
    pthread_kill(o.t, SIGUSR1);
    sleep_ms(100);
    printf("%s 100 ms after SIGUSR1 (handler ran %d times): writer %s\n", tag, atomic_load(&handled), st(&o));
    if (!restart) {
        start(&o2, O_RDONLY);
        sleep_ms(100);
        printf("%s then another thread's open(O_RDONLY), 100 ms in: %s\n", tag, st(&o2));
    } else {
        int r = OPEN(fifo, O_RDONLY | O_NONBLOCK);
        printf("%s then main's open(O_RDONLY|O_NONBLOCK): %s\n", tag, rvs(r, errno));
        sleep_ms(100);
        printf("%s writer 100 ms later: %s\n", tag, st(&o));
    }
}

// The control for D2 and D4: SA_RESTART on a blocking read of an empty
// anonymous pipe whose write end is held.
static void *pipe_read_thread(void *p)
{
    int *fds = p;
    char c;
    ssize_t r = read(fds[0], &c, 1);
    fds[2] = r < 0 ? -errno : (int)r;
    atomic_store((atomic_int *)&fds[3], 1);
    return NULL;
}
static void D5(void)
{
    install(1);
    int fds[4] = { 0, 0, 0, 0 };
    pipe(fds);
    pthread_t t;
    pthread_create(&t, NULL, pipe_read_thread, fds);
    sleep_ms(100);
    pthread_kill(t, SIGUSR1);
    sleep_ms(100);
    printf("D5 (control) blocking pipe read, SA_RESTART, 100 ms after SIGUSR1 (handler ran %d times): %s\n",
           atomic_load(&handled), atomic_load((atomic_int *)&fds[3]) ? en(-fds[2]) : "asleep");
}

static void D1(void) { D_reader("D1", 0); }
static void D2(void) { D_reader("D2", 1); }
static void D3(void) { D_writer("D3", 0); }
static void D4(void) { D_writer("D4", 1); }

// ---------------------------------------------------------------- E

static void E(void)
{
    struct stat p, d, f;
    stat(fifo, &p);
    stat(dir, &d);
    printf("E1 stat(path): %s; dev is the directory's: %d\n", statstr(&p), p.st_dev == d.st_dev);

    int rw = OPEN(fifo, O_RDWR);
    fstat(rw, &f);
    printf("E2 fstat(O_RDWR): %s; ino is the path's: %d; dev is the path's: %d\n", statstr(&f),
           f.st_ino == p.st_ino, f.st_dev == p.st_dev);
    struct stat before = f, after;
    sleep_ms(10);
    printf("E2 %s\n", writestr(rw, 3));
    fstat(rw, &after);
    int n = -1;
    if (ioctl(rw, FIONREAD, &n) < 0) n = -errno;
    printf("E2 after the write: %s; FIONREAD=%d; mtime moved: %d; ctime moved: %d; atime moved: %d\n",
           statstr(&after), n, moved(MTIM(before), MTIM(after)), moved(CTIM(before), CTIM(after)),
           moved(ATIM(before), ATIM(after)));
    struct stat path_after;
    stat(fifo, &path_after);
    printf("E2 stat(path) after the write: size=%lld; mtime moved: %d\n", (long long)path_after.st_size,
           moved(MTIM(p), MTIM(path_after)));
    before = after;
    sleep_ms(10);
    printf("E2 %s\n", readstr(rw, 1));
    fstat(rw, &after);
    printf("E2 after the read: size=%lld; atime moved: %d; mtime moved: %d\n", (long long)after.st_size,
           moved(ATIM(before), ATIM(after)), moved(MTIM(before), MTIM(after)));

    printf("E4 lseek(SEEK_CUR): ");
    off_t o = lseek(rw, 0, SEEK_CUR);
    printf("%s; ", o < 0 ? en(errno) : "OK");
    char c;
    ssize_t pr = pread(rw, &c, 1, 0);
    printf("pread: %s\n", pr < 0 ? en(errno) : "OK");

    int fc = fchmod(rw, 0640);
    stat(fifo, &path_after);
    printf("E5 fchmod(0640) through the descriptor: %s; stat(path) perm=%04o\n", fc < 0 ? en(errno) : "OK",
           (unsigned)(path_after.st_mode & 07777));
    close(rw);
}

static void E3(void)
{
    struct stat p, r_st, w_st;
    stat(fifo, &p);
    int r = OPEN(fifo, O_RDONLY | O_NONBLOCK);
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("E3 %s\n", writestr(w, 3));
    fstat(r, &r_st);
    fstat(w, &w_st);
    struct stat q;
    stat(fifo, &q);
    printf("E3 read end:  %s; ino is the path's: %d\n", statstr(&r_st), r_st.st_ino == p.st_ino);
    printf("E3 write end: %s; ino is the path's: %d\n", statstr(&w_st), w_st.st_ino == p.st_ino);
    printf("E3 stat(path): size=%lld\n", (long long)q.st_size);
    int n = -1;
    int e = ioctl(w, FIONREAD, &n);
    printf("E3 FIONREAD on the write end: %s %d\n", e < 0 ? en(errno) : "OK", n);
    n = -1;
    e = ioctl(r, FIONREAD, &n);
    printf("E3 FIONREAD on the read end: %s %d\n", e < 0 ? en(errno) : "OK", n);
}

// ---------------------------------------------------------------- F

static void F1(void)
{
    int rw = OPEN(fifo, O_RDWR);
    printf("F1 %s; close\n", writestr(rw, 3));
    close(rw);
    rw = OPEN(fifo, O_RDWR | O_NONBLOCK);
    printf("F1 reopened O_RDWR|O_NONBLOCK: %s\n", readstr(rw, 8));
}

static void F2(void)
{
    int r = OPEN(fifo, O_RDONLY | O_NONBLOCK);
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("F2 %s; close the writer\n", writestr(w, 3));
    close(w);
    w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    printf("F2 a second writer opens: %s; the reader's %s\n", rvs(w, errno), readstr(r, 8));
}

// ---------------------------------------------------------------- G

static void mk(const char *tag, const char *name, int how, mode_t mode)
{
    char path[400];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    int rv = how == 0 ? mkfifo(path, mode) : mknod(path, S_IFIFO | mode, 0);
    int e = errno;
    struct stat s;
    if (rv == 0 && stat(path, &s) == 0)
        printf("%s %s(0%o): OK; %s\n", tag, how == 0 ? "mkfifo" : "mknod(S_IFIFO|...)", (unsigned)mode,
               statstr(&s));
    else
        printf("%s %s(0%o): %s\n", tag, how == 0 ? "mkfifo" : "mknod(S_IFIFO|...)", (unsigned)mode, en(e));
}

static void G(void)
{
    umask(022);
    mk("G1", "g1", 0, 0666);
    mk("G2", "g2", 0, 07777);
    mk("G3", "g3", 1, 0666);
    mk("G4", "g4", 1, 07777);
    mk("G5", "f", 0, 0600);
    int fd = OPEN(fifo, O_CREAT | O_EXCL | O_RDONLY | O_NONBLOCK, 0600);
    printf("G6 open(O_CREAT|O_EXCL|O_RDONLY|O_NONBLOCK) of the FIFO: %s\n", rvs(fd, errno));
    fd = OPEN(fifo, O_CREAT | O_RDONLY | O_NONBLOCK, 0600);
    struct stat s;
    if (fd >= 0) fstat(fd, &s);
    printf("G7 open(O_CREAT|O_RDONLY|O_NONBLOCK) of the FIFO: %s%s%s\n", rvs(fd, errno), fd >= 0 ? "; " : "",
           fd >= 0 ? statstr(&s) : "");
    if (fd >= 0) close(fd);
    fd = OPEN(fifo, O_CREAT | O_WRONLY | O_NONBLOCK, 0600);
    printf("G8 open(O_CREAT|O_WRONLY|O_NONBLOCK), no reader: %s\n", rvs(fd, errno));
    int r = OPEN(fifo, O_RDONLY | O_NONBLOCK);
    fd = OPEN(fifo, O_WRONLY | O_NONBLOCK | O_TRUNC);
    printf("G9 open(O_WRONLY|O_NONBLOCK|O_TRUNC), a reader open: %s\n", rvs(fd, errno));
    close(r);
    fd = OPEN(fifo, O_RDONLY | O_NONBLOCK | O_DIRECTORY);
    printf("G10 open(O_RDONLY|O_NONBLOCK|O_DIRECTORY): %s\n", rvs(fd, errno));
    int dfd = OPEN(dir, O_RDONLY);
    int rv = mkfifoat(dfd, "g11", 0600);
    printf("G11 mkfifoat(dirfd, \"g11\", 0600): %s\n", rv < 0 ? en(errno) : "OK");
    fd = openat(dfd, "g11", O_RDONLY | O_NONBLOCK);
    printf("G12 openat(dirfd, \"g11\", O_RDONLY|O_NONBLOCK): %s\n", rvs(fd, errno));
}

// ---------------------------------------------------------------- H and I

// Fill a non-blocking write end with writes of `chunk` until EAGAIN.
static long fill(int w, int chunk)
{
    static char buf[65536];
    long total = 0;
    for (;;) {
        ssize_t r = write(w, buf, (size_t)chunk);
        if (r < 0) break;
        total += r;
        if (total > 4L * 1024 * 1024) break;
    }
    return total;
}

static void capacity(const char *tag, int is_fifo, int chunk)
{
    int r, w;
    char name[400];
    if (is_fifo) {
        snprintf(name, sizeof name, "%s/cap%d", dir, chunk);
        mkfifo(name, 0600);
        r = open(name, O_RDONLY | O_NONBLOCK);
        w = open(name, O_WRONLY | O_NONBLOCK);
    } else {
        int fds[2];
        pipe(fds);
        r = fds[0];
        w = fds[1];
        fcntl(w, F_SETFL, O_NONBLOCK);
    }
    long total = fill(w, chunk);
    struct pollfd p = { w, POLLOUT, 0 };
    poll(&p, 1, 0);
    printf("%s %s, writes of %d until EAGAIN: %ld bytes; write end POLLOUT %d\n", tag, is_fifo ? "FIFO" : "pipe", chunk,
           total, !!(p.revents & POLLOUT));
    close(r);
    close(w);
}

static void H(void)
{
    capacity("H1", 1, 1);
    capacity("H1", 0, 1);
    capacity("H2", 1, 4096);
    capacity("H2", 0, 4096);
    capacity("H3", 1, 1000);
    capacity("H3", 0, 1000);
}

static int dup2_from, dup2_rv, dup2_err;
static atomic_int dup2_done;
static void *dup2_thread(void *p)
{
    (void)p;
    dup2_rv = dup2(dup2_from, 3);
    dup2_err = errno;
    atomic_store(&dup2_done, 1);
    return NULL;
}

static void I(void)
{
    struct opener o;
    start(&o, O_RDONLY);
    sleep_ms(100);
    printf("I1 reader 100 ms in: %s\n", st(&o));
    int n = open("/dev/null", O_RDONLY);
    printf("I1 main opens /dev/null: %s (the lowest free descriptor before the reader was 3)\n", rvs(n, errno));
    int f = fcntl(3, F_GETFD);
    printf("I2 fcntl(3, F_GETFD): %s\n", f < 0 ? en(errno) : "OK");
    int c = close(3);
    printf("I3 close(3): %s\n", c < 0 ? en(errno) : "OK");
    // In a thread: Darwin's dup2 onto the reserved descriptor waits.
    dup2_from = n;
    pthread_t t;
    pthread_create(&t, NULL, dup2_thread, NULL);
    sleep_ms(100);
    if (atomic_load(&dup2_done)) printf("I4 dup2(%d, 3): %s\n", n, dup2_rv < 0 ? en(dup2_err) : "OK");
    else printf("I4 dup2(%d, 3), 100 ms in: asleep\n", n);
    int w = OPEN(fifo, O_WRONLY | O_NONBLOCK);
    sleep_ms(100);
    printf("I5 a writer opens (%s); reader 100 ms later: %s\n", rvs(w, errno), st(&o));
    if (atomic_load(&dup2_done)) printf("I5 the dup2: %s\n", dup2_rv < 0 ? en(dup2_err) : "OK");
    else printf("I5 the dup2: asleep\n");
    struct stat s;
    if (fstat(3, &s) == 0) printf("I6 fstat(3): %s\n", S_ISFIFO(s.st_mode) ? "S_IFIFO" : S_ISCHR(s.st_mode) ? "S_IFCHR" : "other");
    else printf("I6 fstat(3): %s\n", en(errno));
}

// ---------------------------------------------------------------- driver

static void run(void (*f)(void))
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        signal(SIGPIPE, SIG_IGN);
        fresh();
        f();
        fflush(stdout);
        char cmd[400];
        snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
        system(cmd);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) printf("   (section killed by signal %d)\n", WTERMSIG(status));
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    void (*sections[])(void) = { A1, A2, A3, A4, A5, A6, A7, A8, A9, B1, B2, B3, B4, B5, B6, B7, B8, C1, C2,
                                 C3, C4, C5, C6, D1, D2, D3, D4, D5, E,  E3, F1, F2, G,  H,  I };
    for (size_t i = 0; i < sizeof sections / sizeof sections[0]; i++) run(sections[i]);
    return 0;
}
