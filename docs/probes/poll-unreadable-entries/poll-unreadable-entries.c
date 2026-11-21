// What poll(2) answers when the kernel cannot read the process's array of
// struct pollfd: where its EFAULT falls among poll's other answers, what an
// array of no entries answers at an address naming no storage, and what an
// array answers when its first entries can be read and the rest cannot.
//
// Sections:
//   O  the soft limit at the flavour's default (1024 on Linux, 256 on Darwin;
//      `SimulatedUnixPlatform.descriptorBound`): NULL and an unmapped address
//      (8), at nfds 1, the limit, the limit + 1, the flavour's ceiling
//      (Linux 2147483584, the most fs.nr_open takes; Darwin OPEN_MAX, 10240)
//      and one more, and 4294967295; each with timeout 0 and timeout -1. A
//      250 ms timer cuts a sleep short, so EINTR means the call slept.
//   Z  nfds 0, at NULL, at an unmapped address (8), and at a PROT_NONE page;
//      each with timeout 0, 100 and -1. `slept` says whether the call took
//      at least 50 ms; a delay in scheduling the probe can set it too, so it
//      means something only for a call that should sleep.
//   Y  addresses at and past the top of the user address space, which a
//      kernel can screen without reading anything: 2^48 - 1, 2^48, 2^48 + 1
//      (the arm64 limit with a 48-bit virtual address) and 2^64 - 1, at
//      nfds 0 with timeout 0, 100 and -1, and at nfds 1 with timeout 0 and
//      -1. `slept` as in section Z.
//   P  the soft limit raised to 4096: an array whose first k entries lie
//      whole on a readable page and whose next byte is the first of a
//      PROT_NONE page (`cut=entry`), or whose (k+1)th entry has its `fd`
//      readable and its `events` and `revents` on the PROT_NONE page
//      (`cut=mid-entry`); nfds = k + 1. As a control, `cut=none` is the
//      same k entries ending at the PROT_NONE page, with nfds = k, which the
//      kernel can read whole. Entry 0 is either a pipe's write end
//      asking for POLLOUT, which is ready (`lead=ready`), or fd -1
//      (`lead=idle`); every other readable entry is fd -1. Each readable
//      entry's revents is set to 0x5a5a beforehand, and `revents0` is entry
//      0's afterwards. A ready lead with timeout 0 shows whether the kernel
//      answers from the entries it could read; an idle lead with timeout -1
//      shows whether it sleeps on them.
//   W  a whole array on a page mapped PROT_READ: readable, but revents cannot
//      be written back. Entry 0 ready (timeout 0) or fd -1 (timeout 100).
//   S  Linux only: whether a partly readable array polls the entries it could
//      read, seen through a side effect of polling. A poll of a blocking UDP
//      socket moves its arrivals into its reader queue
//      (docs/plans/2026-10-18-udp-data-path/udp-release.c), which shows in
//      when the charge of taken datagrams comes back (SO_MEMINFO): ten
//      datagrams arrive at a fresh receiver, the row's poll is made with the
//      receiver as entry 0 asking for POLLIN, ten more arrive, and ten are
//      taken. `charge-after=23040` means the poll moved the first ten (it
//      polled the receiver); 46080 means it did not. Rows: no poll; the
//      array readable whole (nfds = k); and cut at an entry boundary
//      (nfds = k + 1), for k = 1, 31 and 600, with timeout 0. Each of the
//      ten takes must return a datagram of 1000 bytes, or the probe stops.
//   H  Linux only: an nfds_t wider than 32 bits (glibc's is unsigned long),
//      at NULL and at an unmapped address: 2^32, 2^32 + 1 and 2^32 + 1025,
//      with timeout 0, the soft limit at 1024 again. The kernel's own nfds
//      is an unsigned int.
//
// Every row is `section label nfds=N timeout=T rv=R errno=E` and what else it
// names; errno is `-` when the call succeeded.
//
// Build and run, from this directory:
//   Darwin: cc -Wall -O1 -o /tmp/pue poll-unreadable-entries.c && /tmp/pue
//   Linux, root (Apple's `container`, gcc:14 image):
//     container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/pue /probe/poll-unreadable-entries.c && /tmp/pue'
//   Linux, uid 1000:
//     container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/pue /probe/poll-unreadable-entries.c && setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/pue'
//
// Measured 2026-11-20 on Darwin 27.2.0 arm64 (uid 501) and Linux 6.18.5
// aarch64 (Apple `container`, as root and as uid 1000); each `measured-*.txt`
// is one run's output, the Linux ones with `container`'s progress lines
// (written to stderr) removed. Not measured on x86-64. Every run agrees:
//   O  a count above the soft limit is EINVAL whatever the pointer, and one
//      at or below it is EFAULT, at once, under timeout -1 as under 0. Linux
//      answers alike for root and uid 1000.
//   Z  nfds 0 is answered as an empty array wherever it points: 0 at once
//      for timeout 0, 0 after sleeping for timeout 100, and a sleep that the
//      timer ends (EINTR) for timeout -1.
//   P  every partly readable array, at every k and either cut, is EFAULT at
//      once: a ready lead is not reported, an idle lead under timeout -1
//      does not sleep, and entry 0's revents keeps 0x5a5a. The control,
//      readable whole, reports the ready lead (rv 1, revents0 0x4) and sleeps
//      on the idle one.
//   W  a read-only array is EFAULT on both, at the write-back: the idle lead
//      sleeps its 100 ms first, and the ready lead's revents is not written.
//   Y  nfds 1 is EFAULT at once at every address, on both. nfds 0 is
//      answered as an empty array on Darwin at every address, and on Linux
//      up to 2^48, the arm64 limit; past it (2^48 + 1 and 2^64 - 1) Linux
//      polls as for an empty array and then fails with EFAULT: at once for
//      timeout 0, after the wait for timeout 100, and for timeout -1 when the
//      timer ends the sleep, in place of EINTR.
//   S  Linux: the array cut after k entries is EFAULT and leaves the charge
//      at 46080, as no poll does, where the whole array polls the receiver
//      (rv 1, POLLIN, 23040), for every k: the entries it could read were
//      not polled.
//   H  Linux: the kernel reads the low 32 bits of nfds alone. 2^32 is
//      answered as nfds 0 (rv 0, wherever it points), 2^32 + 1 as nfds 1
//      (EFAULT), and 2^32 + 1025 as nfds 1025 (EINVAL, above the limit).
#define _GNU_SOURCE
#include <errno.h>
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
#include <time.h>
#include <unistd.h>

static void on_alarm(int sig) { (void)sig; }

// A repeating timer, so that one which fires before the call starts still
// ends a call that sleeps.
static void arm_timer_ms(int ms)
{
    struct itimerval it = { { ms / 1000, (ms % 1000) * 1000 }, { ms / 1000, (ms % 1000) * 1000 } };
    setitimer(ITIMER_REAL, &it, NULL);
}

static void disarm_timer(void)
{
    struct itimerval it = { { 0, 0 }, { 0, 0 } };
    setitimer(ITIMER_REAL, &it, NULL);
}

static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *const unmapped = (void *)(uintptr_t)8;

// One poll: its answer, whether it took 50 ms or more, and entry 0's revents
// when `revents0` is given.
static void row(const char *section, const char *label, void *buf, unsigned int nfds, int timeout,
                volatile short *revents0)
{
    arm_timer_ms(250);
    long long start = now_ms();
    errno = 0;
    int rv = poll(buf, nfds, timeout);
    int e = errno;
    long long elapsed = now_ms() - start;
    disarm_timer();
    char after[16] = "-";
    if (revents0) snprintf(after, sizeof after, "0x%hx", (unsigned short)*revents0);
    printf("%s %s nfds=%u timeout=%d rv=%d errno=%s slept=%s revents0=%s\n", section, label, nfds, timeout, rv,
           rv < 0 ? strerror(e) : "-", elapsed >= 50 ? "yes" : "no", after);
}

static void set_soft(rlim_t soft)
{
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) { perror("getrlimit"); exit(1); }
    // A lower limit would change which check a row measures.
    if (rl.rlim_max != RLIM_INFINITY && soft > rl.rlim_max)
    {
        fprintf(stderr, "the hard RLIMIT_NOFILE (%llu) is below %llu\n", (unsigned long long)rl.rlim_max,
                (unsigned long long)soft);
        exit(1);
    }
    rl.rlim_cur = soft;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) { perror("setrlimit"); exit(1); }
    getrlimit(RLIMIT_NOFILE, &rl);
    printf("soft limit set to %llu\n", (unsigned long long)rl.rlim_cur);
}

static void section_o(unsigned int limit)
{
    set_soft(limit);
#ifdef __linux__
    unsigned int ceiling = 2147483584u;
#else
    unsigned int ceiling = 10240u;
#endif
    unsigned int counts[] = { 1, limit, limit + 1, ceiling, ceiling + 1, 4294967295u };
    int timeouts[] = { 0, -1 };
    for (size_t t = 0; t < 2; t++)
        for (size_t k = 0; k < sizeof counts / sizeof counts[0]; k++)
        {
            row("O", "null", NULL, counts[k], timeouts[t], NULL);
            row("O", "unmapped", unmapped, counts[k], timeouts[t], NULL);
        }
}

static void section_z(long page)
{
    void *none = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (none == MAP_FAILED) { perror("mmap"); exit(1); }
    int timeouts[] = { 0, 100, -1 };
    for (size_t t = 0; t < 3; t++)
    {
        row("Z", "null", NULL, 0, timeouts[t], NULL);
        row("Z", "unmapped", unmapped, 0, timeouts[t], NULL);
        row("Z", "prot-none", none, 0, timeouts[t], NULL);
    }
    munmap(none, page);
}

static void section_y(void)
{
    uintptr_t addresses[] = { ((uintptr_t)1 << 48) - 1, (uintptr_t)1 << 48, ((uintptr_t)1 << 48) + 1, UINTPTR_MAX };
    for (size_t a = 0; a < sizeof addresses / sizeof addresses[0]; a++)
    {
        char label[48];
        snprintf(label, sizeof label, "addr=0x%llx", (unsigned long long)addresses[a]);
        void *buf = (void *)addresses[a];
        row("Y", label, buf, 0, 0, NULL);
        row("Y", label, buf, 0, 100, NULL);
        row("Y", label, buf, 0, -1, NULL);
        row("Y", label, buf, 1, 0, NULL);
        row("Y", label, buf, 1, -1, NULL);
    }
}

static void section_p(long page, int ready_fd)
{
    set_soft(4096);
    unsigned int ks[] = { 1, 2, 29, 30, 31, 32, 63, 64, 255, 256, 509, 510, 511, 512, 513, 1000, 2000 };
    size_t pages = (2000 + 1) * sizeof(struct pollfd) / page + 2;
    for (size_t i = 0; i < sizeof ks / sizeof ks[0]; i++)
        for (int cut = 0; cut < 3; cut++)
            for (int ready = 0; ready < 2; ready++)
            {
                unsigned int k = ks[i];
                char *base = mmap(NULL, (pages + 1) * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
                if (base == MAP_FAILED) { perror("mmap"); exit(1); }
                char *boundary = base + pages * page;
                if (mprotect(boundary, page, PROT_NONE) != 0) { perror("mprotect"); exit(1); }
                // `cut=mid-entry` puts entry k's fd (4 bytes) on the readable page.
                char *start = boundary - (size_t)k * sizeof(struct pollfd) - (cut == 1 ? sizeof(int) : 0);
                struct pollfd *p = (struct pollfd *)start;
                for (unsigned int j = 0; j < k; j++) { p[j].fd = -1; p[j].events = POLLIN; p[j].revents = 0x5a5a; }
                if (cut == 1) p[k].fd = -1;
                if (ready) { p[0].fd = ready_fd; p[0].events = POLLOUT; }
                char label[64];
                const char *cuts[] = { "entry", "mid-entry", "none" };
                snprintf(label, sizeof label, "k=%u cut=%s lead=%s", k, cuts[cut], ready ? "ready" : "idle");
                row("P", label, p, cut == 2 ? k : k + 1, ready ? 0 : -1, &p[0].revents);
                munmap(base, (pages + 1) * page);
            }
}

static void section_w(long page, int ready_fd)
{
    for (int ready = 0; ready < 2; ready++)
    {
        struct pollfd *p = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) { perror("mmap"); exit(1); }
        p[0].fd = ready ? ready_fd : -1;
        p[0].events = ready ? POLLOUT : POLLIN;
        p[0].revents = 0x5a5a;
        if (mprotect(p, page, PROT_READ) != 0) { perror("mprotect"); exit(1); }
        row("W", ready ? "read-only lead=ready" : "read-only lead=idle", p, 1, ready ? 0 : 100, &p[0].revents);
        munmap(p, page);
    }
}

#ifdef __linux__
#include <arpa/inet.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

static unsigned int meminfo(int s, int which)
{
    unsigned int mem[SK_MEMINFO_VARS];
    socklen_t len = sizeof mem;
    if (getsockopt(s, SOL_SOCKET, SO_MEMINFO, mem, &len) != 0) { perror("SO_MEMINFO"); exit(1); }
    return mem[which];
}

// Send one datagram of 1000 bytes and wait until the receiver has queued it.
static void send1(int s, int r, struct sockaddr_in *to)
{
    static char payload[1000];
    unsigned int r0 = meminfo(r, SK_MEMINFO_RMEM_ALLOC), d0 = meminfo(r, SK_MEMINFO_DROPS);
    if (sendto(s, payload, sizeof payload, 0, (struct sockaddr *)to, sizeof *to) != sizeof payload) { perror("sendto"); exit(1); }
    for (int spin = 0; spin < 100000; spin++)
    {
        if (meminfo(r, SK_MEMINFO_DROPS) != d0) { fprintf(stderr, "dropped\n"); exit(1); }
        if (meminfo(r, SK_MEMINFO_RMEM_ALLOC) != r0) return;
        if (spin > 100) usleep(10);
    }
    fprintf(stderr, "never arrived\n");
    exit(1);
}

// cut: 0 no poll, 1 readable whole, 2 cut at an entry boundary.
static void section_s_row(long page, unsigned int k, int cut)
{
    int r = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(r, (struct sockaddr *)&to, sizeof to) != 0) { perror("bind"); exit(1); }
    socklen_t len = sizeof to;
    getsockname(r, (struct sockaddr *)&to, &len);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    for (int i = 0; i < 10; i++) send1(s, r, &to);

    size_t pages = (k + 1) * sizeof(struct pollfd) / page + 2;
    char *base = mmap(NULL, (pages + 1) * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); exit(1); }
    char *boundary = base + pages * page;
    if (mprotect(boundary, page, PROT_NONE) != 0) { perror("mprotect"); exit(1); }
    struct pollfd *p = (struct pollfd *)(boundary - (size_t)k * sizeof(struct pollfd));
    for (unsigned int j = 0; j < k; j++) { p[j].fd = -1; p[j].events = POLLIN; p[j].revents = 0x5a5a; }
    p[0].fd = r;

    char label[64];
    const char *cuts[] = { "no-poll", "none", "entry" };
    snprintf(label, sizeof label, "k=%u cut=%s lead=udp", k, cuts[cut]);
    int rv = 0, e = 0;
    unsigned int nfds = cut == 2 ? k + 1 : k;
    if (cut != 0)
    {
        errno = 0;
        rv = poll(p, nfds, 0);
        e = errno;
    }
    for (int i = 0; i < 10; i++) send1(s, r, &to);
    char buf[2000];
    for (int i = 0; i < 10; i++)
        if (recv(r, buf, sizeof buf, MSG_DONTWAIT) != 1000) { fprintf(stderr, "S %s: take %d failed\n", label, i); exit(1); }
    printf("S %s nfds=%u timeout=0 rv=%d errno=%s charge-after=%u revents0=0x%hx\n", label, cut ? nfds : 0, rv,
           rv < 0 ? strerror(e) : "-", meminfo(r, SK_MEMINFO_RMEM_ALLOC), (unsigned short)p[0].revents);
    munmap(base, (pages + 1) * page);
    close(r);
    close(s);
}

static void section_h(void)
{
    set_soft(1024);
    nfds_t counts[] = { (nfds_t)1 << 32, ((nfds_t)1 << 32) + 1, ((nfds_t)1 << 32) + 1025 };
    for (size_t k = 0; k < sizeof counts / sizeof counts[0]; k++)
    {
        void *bufs[] = { NULL, unmapped };
        const char *labels[] = { "null", "unmapped" };
        for (int b = 0; b < 2; b++)
        {
            errno = 0;
            int rv = poll(bufs[b], counts[k], 0);
            int e = errno;
            printf("H %s nfds=%llu timeout=0 rv=%d errno=%s\n", labels[b], (unsigned long long)counts[k], rv,
                   rv < 0 ? strerror(e) : "-");
        }
    }
}

static void section_s(long page)
{
    unsigned int ks[] = { 1, 31, 600 };
    for (size_t i = 0; i < sizeof ks / sizeof ks[0]; i++)
        for (int cut = 0; cut < 3; cut++) section_s_row(page, ks[i], cut);
}
#endif

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname u;
    uname(&u);
    printf("uname %s %s %s uid=%d\n", u.sysname, u.release, u.machine, (int)getuid());

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);

    long page = sysconf(_SC_PAGESIZE);
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(1); }
    // fds[1] is the write end: an empty pipe's is ready for POLLOUT.
    int ready_fd = fds[1];
    printf("page=%ld ready_fd=%d (a pipe's write end)\n", page, ready_fd);

#ifdef __linux__
    section_o(1024);
#else
    section_o(256);
#endif
    section_z(page);
    section_y();
    section_p(page, ready_fd);
    section_w(page, ready_fd);
#ifdef __linux__
    section_s(page);
    section_h();
#endif
    return 0;
}
