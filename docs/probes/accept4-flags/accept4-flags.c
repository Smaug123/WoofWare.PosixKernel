// Where Linux's accept4(2) screens its flag word, and what SOCK_NONBLOCK and
// SOCK_CLOEXEC do to the call and to the socket it makes.
//
// `fcntl-dup.c`'s KIND rows already hold the new descriptor's F_GETFL and
// F_GETFD for each flag alone; this probe measures the rest.
//
// A call's answer is "ok" (for a new descriptor, with its F_GETFL & O_NONBLOCK
// and F_GETFD) or an errno name. BAD is a flag word with a bit accept4 does not
// know (1, then INT_MIN, then SOCK_NONBLOCK|SOCK_CLOEXEC|1).
//
// Sections:
//   A  BAD against each screen accept4 has: a closed descriptor, -1, a regular
//      file, a datagram socket, an idle stream socket, an empty non-blocking
//      listener; and against a listener with a connection queued, after which
//      a non-blocking accept4 with flags 0 says whether the connection is
//      still queued. Then BAD with a negative length cell, the same, and
//      flags 0 with a negative length cell as the baseline.
//   B  with RLIMIT_NOFILE's soft limit at 1024 (Linux's default at process
//      start, `rlimit-nofile.c`) and every descriptor below it open: BAD
//      against a closed descriptor (2000), a regular file and a listener with
//      a connection queued; then flags 0 against the same three, as the
//      baseline.
//   C  each flag word in {0, NONBLOCK, CLOEXEC, both}, from a blocking and
//      from a non-blocking listener with a connection queued: the new
//      descriptor's flags, and the listener's own F_GETFL & O_NONBLOCK after.
//   D  accept4(SOCK_NONBLOCK|SOCK_CLOEXEC) on a blocking listener with nothing
//      queued, a thread connecting 200 ms later: whether the call slept, how
//      long it took, and the new descriptor's flags.
//
// Build and run, from this directory:
//   Linux:  container run --rm -v "$PWD:/probe" gcc:14 sh -c
//             "gcc -Wall -O1 -pthread -o /tmp/a4 /probe/accept4-flags.c && /tmp/a4"
//
// Darwin has no accept4.
//
// Measured 2026-10-20 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14
// image), twice with the same answers (measured-linux-6.18.5-aarch64.txt):
//   A-B  a closed or negative descriptor is EBADF whatever the flags; then an
//        unknown bit is EINVAL, ahead of the descriptor limit's EMFILE, of
//        ENOTSOCK, EOPNOTSUPP and a non-listener's EINVAL, of EAGAIN, and of
//        the queue: a queued connection stays queued, where flags 0 with a
//        negative length cell loses it.
//   C    SOCK_NONBLOCK and SOCK_CLOEXEC give the new socket O_NONBLOCK and
//        FD_CLOEXEC, and nothing else does: a non-blocking listener's
//        O_NONBLOCK is not inherited, and the listener's own is unchanged.
//   D    SOCK_NONBLOCK does not make the call non-blocking: a blocking
//        listener with nothing queued sleeps, and the socket it hands over
//        when it wakes has both flags.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static void die(const char *what)
{
    perror(what);
    exit(1);
}

static const char *errname(int e)
{
    switch (e) {
    case EBADF: return "EBADF";
    case EINVAL: return "EINVAL";
    case ENOTSOCK: return "ENOTSOCK";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EAGAIN: return "EAGAIN";
    case EMFILE: return "EMFILE";
    case EFAULT: return "EFAULT";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno %d", e);
        return buf;
    }
    }
}

// Describe accept4's answer `r`, and close the descriptor it made.
static const char *describe(int r)
{
    static char buf[96];
    if (r < 0) {
        snprintf(buf, sizeof buf, "%s", errname(errno));
        return buf;
    }
    int fl = fcntl(r, F_GETFL);
    int fd = fcntl(r, F_GETFD);
    snprintf(buf, sizeof buf, "ok nonblock=%d cloexec=%d", (fl & O_NONBLOCK) != 0, (fd & FD_CLOEXEC) != 0);
    close(r);
    return buf;
}

static int listener(int nonblocking, unsigned short *port)
{
    int s = socket(AF_INET, SOCK_STREAM | (nonblocking ? SOCK_NONBLOCK : 0), 0);
    if (s < 0) die("socket");
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    if (listen(s, 8) < 0) die("listen");
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) < 0) die("getsockname");
    *port = ntohs(a.sin_port);
    return s;
}

static int connect_to(unsigned short port)
{
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) die("client socket");
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (connect(c, (struct sockaddr *)&a, sizeof a) < 0) die("connect");
    return c;
}

// Whether `l` (a listener) still has a connection queued: an accept through
// the listener made non-blocking for the call, which takes it.
// (accept4's SOCK_NONBLOCK would not do: section D.)
static const char *still_queued(int l)
{
    int was = fcntl(l, F_GETFL);
    fcntl(l, F_SETFL, was | O_NONBLOCK);
    int r = accept(l, NULL, NULL);
    int e = errno;
    fcntl(l, F_SETFL, was);
    errno = e;
    if (r >= 0) {
        close(r);
        return "still queued";
    }
    return errno == EAGAIN ? "gone" : errname(errno);
}

static const int bad_flags[] = {1, INT_MIN, SOCK_NONBLOCK | SOCK_CLOEXEC | 1};

static void section_a(void)
{
    int file = open("/proc/self/exe", O_RDONLY);
    if (file < 0) die("open");
    int dgram = socket(AF_INET, SOCK_DGRAM, 0);
    int idle = socket(AF_INET, SOCK_STREAM, 0);
    unsigned short port;
    int empty = listener(1, &port);
    for (size_t i = 0; i < sizeof bad_flags / sizeof bad_flags[0]; i++) {
        int f = bad_flags[i];
        printf("A flags 0x%08x closed fd     -> %s\n", (unsigned)f, describe(accept4(500, NULL, NULL, f)));
        printf("A flags 0x%08x fd -1         -> %s\n", (unsigned)f, describe(accept4(-1, NULL, NULL, f)));
        printf("A flags 0x%08x regular file  -> %s\n", (unsigned)f, describe(accept4(file, NULL, NULL, f)));
        printf("A flags 0x%08x datagram      -> %s\n", (unsigned)f, describe(accept4(dgram, NULL, NULL, f)));
        printf("A flags 0x%08x idle stream   -> %s\n", (unsigned)f, describe(accept4(idle, NULL, NULL, f)));
        printf("A flags 0x%08x empty nb lis. -> %s\n", (unsigned)f, describe(accept4(empty, NULL, NULL, f)));

        unsigned short qport;
        int queued = listener(0, &qport);
        int c = connect_to(qport);
        printf("A flags 0x%08x queued lis.   -> %s", (unsigned)f, describe(accept4(queued, NULL, NULL, f)));
        printf("; then %s\n", still_queued(queued));
        close(c);

        c = connect_to(qport);
        struct sockaddr_in peer;
        int cell = -1;
        printf("A flags 0x%08x queued, len -1 -> %s", (unsigned)f,
               describe(accept4(queued, (struct sockaddr *)&peer, (socklen_t *)&cell, f)));
        printf("; then %s\n", still_queued(queued));
        close(c);
        close(queued);
    }
    // The baseline for the negative length: flags 0.
    unsigned short qport;
    int queued = listener(0, &qport);
    int c = connect_to(qport);
    struct sockaddr_in peer;
    int cell = -1;
    printf("A flags 0x00000000 queued, len -1 -> %s", describe(accept4(queued, (struct sockaddr *)&peer, (socklen_t *)&cell, 0)));
    printf("; then %s\n", still_queued(queued));
    close(c);
    close(queued);
    close(file);
    close(dgram);
    close(idle);
    close(empty);
}

#define BOUND 1024

static void section_b(void)
{
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    rl.rlim_cur = BOUND;
    if (setrlimit(RLIMIT_NOFILE, &rl) != 0) die("setrlimit");
    int file = open("/proc/self/exe", O_RDONLY);
    if (file < 0) die("open");
    unsigned short qport;
    int queued = listener(0, &qport);
    int c = connect_to(qport);
    // Fill every descriptor below the limit.
    int last = -1;
    for (;;) {
        int d = dup(0);
        if (d < 0) {
            if (errno != EMFILE) die("dup");
            break;
        }
        last = d;
    }
    (void)last;
    const int flags[] = {1, 0};
    for (size_t i = 0; i < 2; i++) {
        int f = flags[i];
        printf("B full, flags 0x%x closed fd    -> %s\n", (unsigned)f, describe(accept4(2000, NULL, NULL, f)));
        printf("B full, flags 0x%x regular file -> %s\n", (unsigned)f, describe(accept4(file, NULL, NULL, f)));
        printf("B full, flags 0x%x queued lis.  -> %s\n", (unsigned)f, describe(accept4(queued, NULL, NULL, f)));
    }
    for (int d = 3; d < BOUND; d++) {
        if (d != file && d != queued && d != c) close(d);
    }
    printf("B after freeing one, queued: %s\n", still_queued(queued));
    close(c);
    close(queued);
    close(file);
}

static void section_c(void)
{
    const int words[] = {0, SOCK_NONBLOCK, SOCK_CLOEXEC, SOCK_NONBLOCK | SOCK_CLOEXEC};
    const char *names[] = {"0", "NONBLOCK", "CLOEXEC", "NONBLOCK|CLOEXEC"};
    for (int nb = 0; nb < 2; nb++) {
        for (int i = 0; i < 4; i++) {
            unsigned short port;
            int l = listener(nb, &port);
            int c = connect_to(port);
            printf("C %s listener, flags %-16s -> %s", nb ? "non-blocking" : "blocking    ", names[i],
                   describe(accept4(l, NULL, NULL, words[i])));
            printf("; listener nonblock=%d\n", (fcntl(l, F_GETFL) & O_NONBLOCK) != 0);
            close(c);
            close(l);
        }
    }
}

static unsigned short d_port;

static void *late_connect(void *arg)
{
    (void)arg;
    struct timespec t = {0, 200 * 1000 * 1000};
    nanosleep(&t, NULL);
    int c = connect_to(d_port);
    t.tv_nsec = 100 * 1000 * 1000;
    nanosleep(&t, NULL);
    close(c);
    return NULL;
}

static void section_d(void)
{
    int l = listener(0, &d_port);
    pthread_t th;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (pthread_create(&th, NULL, late_connect, NULL) != 0) die("pthread_create");
    int r = accept4(l, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    printf("D blocking listener, nothing queued, NONBLOCK|CLOEXEC -> %s; %s\n", describe(r),
           ms >= 150 ? "slept" : "did not sleep");
    pthread_join(th, NULL);
    close(l);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    section_a();
    section_b();
    section_c();
    section_d();
    return 0;
}
