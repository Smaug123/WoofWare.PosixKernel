// A blocking write on a connected loopback TCP socket whose own bytes make the
// peer's kernel answer with a reset, on Linux and Darwin: the peer has closed
// (with a FIN), or has shut its side so that bytes arriving there reset the
// connection. Does the call sleep for room before it sees that reset, and
// what does it answer?
//
// c is the connecting socket and p the accepted one, both blocking. SIGPIPE
// is caught and counted; SIGUSR1's handler counts too, installed without
// SA_RESTART. Each line is tab-separated, its first field the section.
//
// The peer states, each made with nothing sent either way, then 100 ms for
// the FIN (if any) to arrive:
//   open        p does nothing (the control: c's write fills the buffers and
//               sleeps).
//   close       p closes.
//   shut_rd     shutdown(p, SHUT_RD).
//   shut_rdwr   shutdown(p, SHUT_RDWR).
//
// Sections:
//   A   for each peer state, c makes one blocking write of N bytes, N = 100
//       or 8 MiB, in a thread. Reported: the answer, how long it took, or
//       "asleep" if it has not returned 300 ms in, and then what it answered
//       once p was closed (or, for a closed p, c shut down); SIGPIPEs,
//       SO_ERROR afterwards, then a second write of 100 bytes, non-blocking,
//       and its SIGPIPEs; and how often the writer slept in the call
//       (`slept`): its own voluntary context switches on Linux, and on
//       Darwin, which counts them only per process, the process's, while the
//       main thread spins rather than sleeps. Three trials each.
//   B   for each peer state, as A with N = 8 MiB, but another thread sends
//       SIGUSR1 to the writer over and over from just before the write until
//       it returns: a signal reaching the writer while it sleeps ends the
//       write with the count it has taken (or EINTR with none), which the
//       open control shows. Twenty trials each, tallied by answer.
//   C   (Linux only; needs CAP_SYS_NICE) the write is a woken one, as
//       tcp-blocking.c section D arranges: the writer, pinned to CPU 0
//       under SCHED_FIFO 10, is asleep in write(c, 8 MiB) with the buffers
//       full; a hog on CPU 0 under SCHED_FIFO 20 then reads p until p holds
//       nothing and c has nothing unsent, closes p (a FIN), and spins 20 ms
//       more before it lets go of the CPU, so the writer runs only once the
//       FIN has arrived. Reported: what the call had taken before the hog
//       (FIONREAD(p) + SIOCOUTQ(c)), what the hog read, the answer, and the
//       answer less what was read, which is what the woken call took. Ten
//       trials.
//
// Build and run, from this directory:
//   Darwin: cc -Wall -O1 -pthread -o /tmp/cwr connection-write-reset.c && /tmp/cwr
//   Linux:  container run --rm --cap-add CAP_SYS_NICE -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -pthread -o /tmp/p /probe/connection-write-reset.c && /tmp/p'
// An argument restricts the run to the sections it names, e.g. `AB`; the
// default is `ABC`. The first line of the output is the kernel's uname.
//
// Measured 2026-10-14 on Linux 6.18.5 aarch64 (Apple's container VM, root,
// default sysctls) and Darwin 27.0.0 arm64 (uid 501); one run of each is
// measured-linux-6.18.5-aarch64.txt and measured-darwin-27.0.txt, and earlier
// runs agreed but for which of Darwin's racing answers each trial gave. What
// they say:
//   Linux  a write whose bytes reset (the peer closed, or shut both sides;
//          SHUT_RD alone resets nothing there) never sleeps (slept=0, the
//          open control slept=1), and returns the count it took, 524288 of
//          8 MiB, with or without a stream of signals; it raises no SIGPIPE
//          and leaves EPIPE in SO_ERROR, so the next write answers EPIPE and
//          raises SIGPIPE. A woken one (C) does the same, taking 589347 more.
//   Darwin a write whose bytes reset (the peer closed, or shut its receive
//          side) either sleeps until the reset arrives, then answers EPIPE and
//          raises SIGPIPE (slept=1), or meets the reset while still copying
//          and answers ECONNRESET without SIGPIPE (slept=0); SO_ERROR reads
//          ECONNRESET either way. A signal reaching the sleeping writer
//          first ends the write with the count it took, 327212 (B). After a
//          write of 100 bytes, which returns 100, whether SO_ERROR and a
//          second write see the reset yet depends on how soon they ask: it
//          arrives on another thread.

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/sockios.h>
#endif

static atomic_int sigpipes;
static atomic_int sigusr1s;

static void on_sigpipe(int signo)
{
    (void)signo;
    atomic_fetch_add(&sigpipes, 1);
}

static void on_sigusr1(int signo)
{
    (void)signo;
    atomic_fetch_add(&sigusr1s, 1);
}

static void die(const char *what)
{
    perror(what);
    exit(2);
}

static void install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigusr1;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) < 0) die("sigaction SIGUSR1");
    sa.sa_handler = on_sigpipe;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) die("sigaction SIGPIPE");
}

static const char *errname(int e)
{
    static char other[32];
    switch (e)
    {
        case 0: return "0";
        case EAGAIN: return "EAGAIN";
        case EPIPE: return "EPIPE";
        case ECONNRESET: return "ECONNRESET";
        case ENOTCONN: return "ENOTCONN";
        case EINTR: return "EINTR";
        case EBADF: return "EBADF";
        default:
            snprintf(other, sizeof other, "errno%d", e);
            return other;
    }
}

static int64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) { }
}

static void set_nonblocking(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) die("F_GETFL");
    flags = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
    if (fcntl(fd, F_SETFL, flags) < 0) die("F_SETFL");
}

static int getint(int fd, int level, int name)
{
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(fd, level, name, &v, &len) < 0) return -1000 - errno;
    return v;
}

#ifdef __linux__
static int nread(int fd)
{
    int n = -1;
    if (ioctl(fd, FIONREAD, &n) < 0) return -1000 - errno;
    return n;
}

static int unsent(int fd)
{
    int n = -1;
    if (ioctl(fd, SIOCOUTQ, &n) < 0) return -1000 - errno;
    return n;
}
#endif

// A connected blocking pair over 127.0.0.1: *c connecting, *p accepted.
static void make_pair(int *c, int *p)
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    if (l < 0) die("socket");
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(l, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    if (listen(l, 8) < 0) die("listen");
    socklen_t al = sizeof a;
    if (getsockname(l, (struct sockaddr *)&a, &al) < 0) die("getsockname");
    *c = socket(AF_INET, SOCK_STREAM, 0);
    if (*c < 0) die("socket");
    if (connect(*c, (struct sockaddr *)&a, sizeof a) < 0) die("connect");
    *p = accept(l, NULL, NULL);
    if (*p < 0) die("accept");
    close(l);
}

static char payload[8 << 20];
static char sink[1 << 22];

static void answer(ssize_t rv, int error, char *out, size_t len)
{
    if (rv < 0)
        snprintf(out, len, "-1 %s", errname(error));
    else
        snprintf(out, len, "%zd", rv);
}

enum peer { OPEN, CLOSE, SHUT_READ, SHUT_BOTH, PEERS };
static const char *peer_names[] = { "open", "close", "shut_rd", "shut_rdwr" };

// A pair whose p is in `state`, 100 ms after it got there. *p is -1 once
// closed.
static void peer_in(enum peer state, int *c, int *p)
{
    make_pair(c, p);
    switch (state)
    {
        case OPEN: break;
        case CLOSE: close(*p); *p = -1; break;
        case SHUT_READ: if (shutdown(*p, SHUT_RD) < 0) die("SHUT_RD"); break;
        case SHUT_BOTH: if (shutdown(*p, SHUT_RDWR) < 0) die("SHUT_RDWR"); break;
        default: die("peer state");
    }
    sleep_ms(100);
}

typedef struct
{
    int fd;
    size_t len;
    atomic_int started;
    atomic_int done;
    ssize_t rv;
    int error;
    int64_t elapsed;
    long nvcsw;
    int fifo;
} call;

#ifdef __linux__
static int pin_fifo(int prio)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof set, &set) != 0) return -1;
    struct sched_param sp = { .sched_priority = prio };
    return pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
}
#endif

// The calling thread's voluntary context switches so far, on Linux: how
// often it has slept. Darwin counts them only for the whole process, so
// there they are the process's, which section A keeps to the writer's own by
// having the main thread spin rather than sleep while it waits.
static long voluntary_switches(void)
{
    struct rusage ru;
#ifdef RUSAGE_THREAD
    if (getrusage(RUSAGE_THREAD, &ru) < 0) return -1;
#else
    if (getrusage(RUSAGE_SELF, &ru) < 0) return -1;
#endif
    return ru.ru_nvcsw;
}

static void *run_write(void *arg)
{
    call *k = arg;
#ifdef __linux__
    if (k->fifo)
    {
        int pinned = pin_fifo(10);
        if (pinned != 0)
        {
            k->rv = -100 - pinned;
            atomic_store(&k->started, 1);
            atomic_store(&k->done, 1);
            return NULL;
        }
    }
#endif
    atomic_store(&k->started, 1);
    long switches = voluntary_switches();
    int64_t t0 = now_us();
    errno = 0;
    k->rv = write(k->fd, payload, k->len);
    k->error = k->rv < 0 ? errno : 0;
    k->elapsed = now_us() - t0;
    k->nvcsw = switches < 0 ? -1 : voluntary_switches() - switches;
    atomic_store(&k->done, 1);
    return NULL;
}

static void start(call *k, pthread_t *t, int fd, size_t len, int fifo)
{
    memset(k, 0, sizeof *k);
    k->fd = fd;
    k->len = len;
    k->fifo = fifo;
    atomic_init(&k->started, 0);
    atomic_init(&k->done, 0);
    if (pthread_create(t, NULL, run_write, k) != 0) die("pthread_create");
    while (!atomic_load(&k->started)) { }
}

// Ends a write still asleep 300 ms in: closes p, or shuts c down if p is
// closed already. Returns whether it was asleep.
static int end_if_asleep(call *k, int c, int *p)
{
    int64_t t0 = now_us();
    while (!atomic_load(&k->done) && now_us() - t0 < 300000) { }
    if (atomic_load(&k->done)) return 0;
    if (*p >= 0) { close(*p); *p = -1; }
    else shutdown(c, SHUT_RDWR);
    for (int i = 0; i < 100 && !atomic_load(&k->done); i++) sleep_ms(10);
    return 1;
}

static void section_a(void)
{
    size_t sizes[] = { 100, 8 << 20 };
    for (int state = 0; state < PEERS; state++)
    {
        for (int s = 0; s < 2; s++)
        {
            for (int trial = 0; trial < 3; trial++)
            {
                int c, p;
                peer_in(state, &c, &p);
                atomic_store(&sigpipes, 0);
                call k;
                pthread_t t;
                start(&k, &t, c, sizes[s], 0);
                int asleep = end_if_asleep(&k, c, &p);
                if (!atomic_load(&k.done))
                {
                    printf("A\t%s\tN=%zu\ttrial=%d\tstill asleep after its peer's close; leaving it\n",
                           peer_names[state], sizes[s], trial);
                    pthread_detach(t);
                    continue;
                }
                pthread_join(t, NULL);
                int pipes = atomic_load(&sigpipes);
                char first[64], second[64];
                answer(k.rv, k.error, first, sizeof first);
                int so_error = getint(c, SOL_SOCKET, SO_ERROR);
                atomic_store(&sigpipes, 0);
                set_nonblocking(c, 1);
                errno = 0;
                ssize_t rv2 = write(c, payload, 100);
                answer(rv2, rv2 < 0 ? errno : 0, second, sizeof second);
                printf("A\t%s\tN=%zu\ttrial=%d\t%s\tanswer=%s\telapsed_us=%lld\tslept=%ld\tsigpipe=%d\tso_error=%s\tsecond_write=%s\tsecond_sigpipe=%d\n",
                       peer_names[state], sizes[s], trial, asleep ? "asleep_at_300ms_then" : "returned", first,
                       (long long)k.elapsed, k.nvcsw, pipes, errname(so_error), second, atomic_load(&sigpipes));
                close(c);
                if (p >= 0) close(p);
            }
        }
    }
}

static void section_b(void)
{
    for (int state = 0; state < PEERS; state++)
    {
        int counts = 0, epipe = 0, econnreset = 0, eintr = 0, other = 0, slept = 0;
        long long smallest = -1, largest = -1;
        for (int trial = 0; trial < 20; trial++)
        {
            int c, p;
            peer_in(state, &c, &p);
            atomic_store(&sigpipes, 0);
            atomic_store(&sigusr1s, 0);
            call k;
            pthread_t t;
            start(&k, &t, c, 8 << 20, 0);
            long sent = 0;
            int64_t t0 = now_us();
            while (!atomic_load(&k.done) && now_us() - t0 < 300000)
            {
                pthread_kill(t, SIGUSR1);
                sent++;
            }
            if (!atomic_load(&k.done))
            {
                slept++;
                end_if_asleep(&k, c, &p);
            }
            if (!atomic_load(&k.done))
            {
                printf("B\t%s\ttrial=%d\tstill asleep; leaving it\n", peer_names[state], trial);
                pthread_detach(t);
                continue;
            }
            pthread_join(t, NULL);
            char first[64];
            answer(k.rv, k.error, first, sizeof first);
            printf("B\t%s\ttrial=%d\tanswer=%s\telapsed_us=%lld\tsigusr1_sent=%ld\tsigusr1_handled=%d\tsigpipe=%d\tso_error=%s\n",
                   peer_names[state], trial, first, (long long)k.elapsed, sent, atomic_load(&sigusr1s),
                   atomic_load(&sigpipes), errname(getint(c, SOL_SOCKET, SO_ERROR)));
            if (k.rv >= 0)
            {
                counts++;
                if (smallest < 0 || k.rv < smallest) smallest = k.rv;
                if (k.rv > largest) largest = k.rv;
            }
            else if (k.error == EPIPE) epipe++;
            else if (k.error == ECONNRESET) econnreset++;
            else if (k.error == EINTR) eintr++;
            else other++;
            close(c);
            if (p >= 0) close(p);
        }
        printf("B\t%s\ttally\tcount=%d (%lld..%lld)\tEPIPE=%d\tECONNRESET=%d\tEINTR=%d\tother=%d\tunanswered_after_300ms=%d\n",
               peer_names[state], counts, smallest, largest, epipe, econnreset, eintr, other, slept);
    }
}

#ifdef __linux__
static void section_c(void)
{
    for (int trial = 0; trial < 10; trial++)
    {
        int c, p;
        make_pair(&c, &p);
        atomic_store(&sigpipes, 0);
        call k;
        pthread_t t;
        start(&k, &t, c, 8 << 20, 1);
        if (k.rv <= -100)
        {
            printf("C\tthe writer could not take SCHED_FIFO on CPU 0: error %zd\n", -100 - k.rv);
            pthread_join(t, NULL);
            return;
        }
        sleep_ms(200);
        int asleep = !atomic_load(&k.done);
        long long before = (long long)nread(p) + unsent(c);
        int hog = pin_fifo(20);
        if (hog != 0)
        {
            printf("C\tthe hog could not take SCHED_FIFO on CPU 0: error %d\n", hog);
            close(p);
            pthread_join(t, NULL);
            return;
        }
        // Read until p holds nothing and c has nothing left to send; the
        // writer, on this CPU below the hog, takes nothing meanwhile.
        set_nonblocking(p, 1);
        long long drained = 0;
        int64_t t0 = now_us();
        while (now_us() - t0 < 200000)
        {
            ssize_t r = read(p, sink, sizeof sink);
            if (r > 0) { drained += r; continue; }
            if (nread(p) == 0 && unsent(c) == 0) break;
        }
        int left_p = nread(p), left_c = unsent(c);
        int writer_done_in_hog = atomic_load(&k.done);
        close(p);
        int64_t t1 = now_us();
        while (now_us() - t1 < 20000) { }
        struct sched_param sp = { .sched_priority = 0 };
        pthread_setschedparam(pthread_self(), SCHED_OTHER, &sp);
        {
            cpu_set_t all;
            CPU_ZERO(&all);
            for (int i = 0; i < 64; i++) CPU_SET(i, &all);
            pthread_setaffinity_np(pthread_self(), sizeof all, &all);
        }
        sleep_ms(100);
        if (!atomic_load(&k.done))
        {
            printf("C\ttrial=%d\tthe writer is still asleep 100 ms after the hog; leaving it\n", trial);
            pthread_detach(t);
            continue;
        }
        pthread_join(t, NULL);
        char first[64];
        answer(k.rv, k.error, first, sizeof first);
        printf("C\ttrial=%d\tasleep_at_200ms=%d\ttaken_before=%lld\tdrained=%lld\tleft_in_p=%d\tleft_in_c=%d\twriter_done_during_hog=%d\tanswer=%s\ttaken_after_wake=%lld\tsigpipe=%d\tso_error=%s\tsndbuf=%d\n",
               trial, asleep, before, drained, left_p, left_c, writer_done_in_hog, first,
               k.rv >= 0 ? (long long)k.rv - drained : -1, atomic_load(&sigpipes),
               errname(getint(c, SOL_SOCKET, SO_ERROR)), getint(c, SOL_SOCKET, SO_SNDBUF));
        close(c);
    }
}
#endif

int main(int argc, char **argv)
{
    const char *sections = argc > 1 ? argv[1] : "ABC";
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'x', sizeof payload);
    install();
    struct utsname u;
    if (uname(&u) < 0) die("uname");
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);
    if (strchr(sections, 'A')) section_a();
    if (strchr(sections, 'B')) section_b();
#ifdef __linux__
    if (strchr(sections, 'C')) section_c();
#else
    (void)sink;
#endif
    return 0;
}
