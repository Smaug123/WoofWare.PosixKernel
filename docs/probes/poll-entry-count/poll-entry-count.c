// What poll(2) answers for each entry count, against the process's
// RLIMIT_NOFILE soft limit: where the screen falls among poll's other checks,
// and, on Linux, whether some count is EINVAL whatever the limit could be.
//
// Sections:
//   A  the soft limit lowered to the flavour's default (1024 on Linux, 256 on
//      Darwin; `SimulatedUnixPlatform.descriptorBound`), hard limit unchanged:
//      nfds around it, with a buffer of fd -1 entries and with an unmapped
//      buffer; then nfds = limit and limit + 1 with the first entry a ready
//      pipe, a descriptor that is not open, or an event queue (an empty epoll
//      instance on Linux, an empty kqueue on Darwin), and with timeout -1
//      (cut short by a 250 ms timer: EINTR means it slept).
//   B  the soft limit raised to the hard limit: nfds = hard and hard + 1.
//      Skipped when the hard limit is infinite or too large to back a buffer.
//   C  Linux, as root only: how far the soft limit can ever rise. fs.nr_open
//      is set to the largest value it takes and one more; the limit is set
//      above it, to RLIM_INFINITY, and to it; nfds is screened there; then
//      fs.nr_open is put back, and nfds screened again under the limit the
//      process still holds.
//
// Every row is `section label nfds=N rv=R errno=E` plus what else it names;
// errno is `-` when the call succeeded, and revents0 is the first entry's.
//
// Build and run, from this directory:
//   Darwin: nix develop -c clang -Wall -o /tmp/pec poll-entry-count.c && /tmp/pec
//   Linux, root:
//     container run --rm --cap-add ALL -v "$PWD":/probe gcc:14 sh -c 'mount -o remount,rw /proc/sys; gcc -Wall -O1 -o /tmp/pec /probe/poll-entry-count.c && /tmp/pec'
//   Linux, uid 1000:
//     container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/pec /probe/poll-entry-count.c && setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/pec'
//   Linux x86-64: a real x86-64 kernel (not `container --arch amd64`, which
//     is Rosetta on the aarch64 kernel). In an amd64 debian:trixie container,
//     install gcc, libc6-dev, cpio and linux-image-amd64; copy out
//     /boot/vmlinuz-*; build this probe with `gcc -static` as /init of an
//     initramfs that also holds an empty /proc (`find . | cpio -o -H newc |
//     gzip`); then boot it, as root and with nothing else running:
//       qemu-system-x86_64 -m 2G -cpu max -kernel vmlinuz -initrd init.cpio.gz
//         -append "console=ttyS0 panic=-1 quiet" -nographic -no-reboot
//
// Measured 2026-10-17 on Linux 6.18.5 aarch64 (Apple `container`, as root and
// as uid 1000), Linux 6.12.113 x86-64 (Debian's kernel under QEMU, as root, so
// the first process's own limit of 1024/4096) and Darwin 27.0.0 arm64 (uid
// 501); each `measured-*.txt` is one run's output.
//   A  every run: nfds above the soft limit is EINVAL, and at or below it is
//      not, whatever the buffer, the entries and the timeout: a ready pipe, a
//      closed descriptor or an event queue at nfds = limit answers as the scan
//      does (rv 1 POLLOUT, rv 1 POLLNVAL, rv 0), and at limit + 1 is EINVAL;
//      timeout -1 or -2 sleeps at the limit and is EINVAL at once above it.
//      Linux answers alike for root and uid 1000.
//   B  Linux: the same at the hard limit (1048576 in the container, 4096 for
//      the x86-64 first process). Darwin's hard limit is infinite, so skipped.
//   C  Linux, both architectures: fs.nr_open takes 2147483584 and refuses
//      2147483585 and 2147483647 (EINVAL); setrlimit refuses a limit above
//      fs.nr_open, and RLIM_INFINITY, with EPERM even for root. With the limit
//      at 2147483584, nfds 2147483584 passes the screen (EFAULT, at the
//      unmapped buffer) and 2147483585 and 4294967295 are EINVAL. Lowering
//      fs.nr_open afterwards leaves the process its limit, and the screen with
//      it. So no process's soft limit exceeds 2147483584, and every count above
//      it is EINVAL whatever the limit.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/mount.h>
#else
#include <sys/event.h>
#endif

static void on_alarm(int sig) { (void)sig; }

static void arm_timer_ms(int ms)
{
    struct itimerval it = { { 0, 0 }, { ms / 1000, (ms % 1000) * 1000 } };
    setitimer(ITIMER_REAL, &it, NULL);
}

static void disarm_timer(void)
{
    struct itimerval it = { { 0, 0 }, { 0, 0 } };
    setitimer(ITIMER_REAL, &it, NULL);
}

static void *const unmapped = (void *)(uintptr_t)8;

// A buffer of `n` entries, each fd -1 asking for POLLIN.
static struct pollfd *idle_entries(size_t n)
{
    size_t bytes = (n ? n : 1) * sizeof(struct pollfd);
    struct pollfd *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    for (size_t i = 0; i < n; i++) { p[i].fd = -1; p[i].events = POLLIN; p[i].revents = 0; }
    return p;
}

static void release(struct pollfd *p, size_t n)
{
    munmap(p, (n ? n : 1) * sizeof(struct pollfd));
}

static void row(const char *section, const char *label, void *buf, unsigned int nfds, int timeout)
{
    arm_timer_ms(250);
    errno = 0;
    int rv = poll(buf, nfds, timeout);
    int e = errno;
    disarm_timer();
    char revents[16] = "-";
    if (rv >= 0 && buf != unmapped && nfds > 0) snprintf(revents, sizeof revents, "0x%x", ((struct pollfd *)buf)[0].revents);
    printf("%s %s nfds=%u timeout=%d rv=%d errno=%s revents0=%s\n", section, label, nfds, timeout, rv,
           rv < 0 ? strerror(e) : "-", revents);
}

static void set_soft(rlim_t soft, rlim_t hard)
{
    struct rlimit rl = { soft, hard };
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) { perror("setrlimit"); exit(1); }
}

static void section_a(rlim_t limit, rlim_t hard)
{
    set_soft(limit, hard);
    printf("A soft limit set to %llu (hard %llu)\n", (unsigned long long)limit, (unsigned long long)hard);

    unsigned int counts[] = { 0, 1, (unsigned int)limit - 1, (unsigned int)limit, (unsigned int)limit + 1,
                              (unsigned int)limit * 2, 65536 };
    for (size_t k = 0; k < sizeof counts / sizeof counts[0]; k++)
    {
        struct pollfd *p = idle_entries(counts[k]);
        row("A", "idle-buffer", p, counts[k], 0);
        release(p, counts[k]);
        row("A", "unmapped-buffer", unmapped, counts[k], 0);
    }

    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) { perror("pipe"); exit(1); }
#ifdef __linux__
    int queue = epoll_create1(0);
    const char *queue_label = "lead=empty-epoll";
#else
    int queue = kqueue();
    const char *queue_label = "lead=empty-kqueue";
#endif
    if (queue < 0) { perror("event queue"); exit(1); }
    // Below every limit this probe sets, and not open.
    int closed = 200;
    close(closed);
    printf("A pipe write end fd=%d, event queue fd=%d, closed fd=%d\n", pipe_fds[1], queue, closed);

    for (unsigned int n = (unsigned int)limit; n <= (unsigned int)limit + 1; n++)
    {
        struct pollfd *p = idle_entries(n);
        p[0].fd = pipe_fds[1]; p[0].events = POLLOUT;
        row("A", "lead=ready-pipe-POLLOUT", p, n, 0);
        p[0].fd = closed; p[0].events = POLLIN; p[0].revents = 0;
        row("A", "lead=closed-fd", p, n, 0);
        p[0].fd = queue; p[0].events = POLLIN; p[0].revents = 0;
        row("A", queue_label, p, n, 0);
        p[0].fd = -1; p[0].revents = 0;
        row("A", "idle-buffer", p, n, -1);
        row("A", "idle-buffer", p, n, -2);
        release(p, n);
    }
    close(pipe_fds[0]); close(pipe_fds[1]); close(queue);
}

static void section_b(rlim_t hard)
{
    if (hard == RLIM_INFINITY || hard > (1u << 26))
    {
        printf("B skipped: hard limit %llu\n", (unsigned long long)hard);
        return;
    }
    set_soft(hard, hard);
    printf("B soft limit set to %llu (hard %llu)\n", (unsigned long long)hard, (unsigned long long)hard);
    for (unsigned int n = (unsigned int)hard; n <= (unsigned int)hard + 1; n++)
    {
        struct pollfd *p = idle_entries(n);
        row("B", "idle-buffer", p, n, 0);
        release(p, n);
        row("B", "unmapped-buffer", unmapped, n, 0);
    }
}

#ifdef __linux__
static long read_nr_open(void)
{
    FILE *f = fopen("/proc/sys/fs/nr_open", "r");
    if (!f) return -1;
    long v = -1;
    if (fscanf(f, "%ld", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static void write_nr_open(const char *value)
{
    int fd = open("/proc/sys/fs/nr_open", O_WRONLY);
    int e = errno;
    ssize_t w = -1;
    if (fd >= 0)
    {
        errno = 0;
        w = write(fd, value, strlen(value));
        e = errno;
        close(fd);
    }
    printf("C write fs.nr_open=%s rv=%zd errno=%s now=%ld\n", value, w, w < 0 ? strerror(e) : "-", read_nr_open());
}

static void try_limit(const char *label, rlim_t soft, rlim_t hard)
{
    struct rlimit rl = { soft, hard };
    errno = 0;
    int rv = setrlimit(RLIMIT_NOFILE, &rl);
    int e = errno;
    struct rlimit now;
    getrlimit(RLIMIT_NOFILE, &now);
    printf("C setrlimit %s rv=%d errno=%s now cur=%llu max=%llu\n", label, rv, rv < 0 ? strerror(e) : "-",
           (unsigned long long)now.rlim_cur, (unsigned long long)now.rlim_max);
}

static void section_c(void)
{
    if (geteuid() != 0)
    {
        printf("C skipped: not root\n");
        return;
    }
    long original = read_nr_open();
    char original_text[32];
    snprintf(original_text, sizeof original_text, "%ld", original);

    write_nr_open("2147483585");
    write_nr_open("2147483647");
    write_nr_open("2147483584");
    try_limit("2147483585", 2147483585u, 2147483585u);
    try_limit("RLIM_INFINITY", RLIM_INFINITY, RLIM_INFINITY);
    try_limit("2147483584", 2147483584u, 2147483584u);
    row("C", "unmapped-buffer", unmapped, 2147483584u, 0);
    row("C", "unmapped-buffer", unmapped, 2147483585u, 0);
    row("C", "unmapped-buffer", unmapped, 4294967295u, 0);

    write_nr_open(original_text);
    try_limit("unchanged", 2147483584u, 2147483584u);
    row("C", "unmapped-buffer", unmapped, 2147483584u, 0);
    row("C", "unmapped-buffer", unmapped, 2147483585u, 0);
}
#endif

int main(void)
{
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
#ifdef __linux__
    // As an initramfs's /init (the x86-64 run), nothing has mounted /proc.
    if (getpid() == 1 && mount("proc", "/proc", "proc", 0, NULL) != 0) perror("mount /proc");
#endif
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);

    struct utsname u;
    uname(&u);
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
#ifdef __linux__
    rlim_t bound = 1024;
    printf("# %s %s %s, uid %d, RLIMIT_NOFILE cur=%llu max=%llu, fs.nr_open=%ld\n", u.sysname, u.release, u.machine,
           (int)geteuid(), (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max, read_nr_open());
#else
    rlim_t bound = 256;
    printf("# %s %s %s, uid %d, RLIMIT_NOFILE cur=%llu max=%llu\n", u.sysname, u.release, u.machine, (int)geteuid(),
           (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);
#endif

    section_a(bound, rl.rlim_max);
    section_b(rl.rlim_max);
#ifdef __linux__
    section_c();
#endif
    return 0;
}
