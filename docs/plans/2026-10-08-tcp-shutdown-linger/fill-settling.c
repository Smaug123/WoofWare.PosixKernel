// What tcp-shutdown.c's fill and settle leave still to happen, on loopback
// TCP, on Linux and Darwin: two conditions under which a row of that probe
// answers otherwise than it was recorded, each counted against the answer it
// changes.
//
// c is the connecting socket and p the accepted one, both non-blocking. A
// fill is tcp-shutdown.c's: c writes 1 MiB at a time until three tries 30 ms
// apart take nothing. Every call that can put a segment on the wire is
// followed by its 30 ms settle.
//
//   G   growth. S's cunsent WR row, call for call: fill; shutdown(c, WR);
//       rdy(p); c reads twice; p reads 4096; c writes 100 and 0; p writes
//       100; then rdy(p), where tcp-shutdown.c recorded c's FIN still
//       waiting behind bytes p cannot take. Counted by whether p's SO_RCVBUF
//       was larger at that rdy than when the fill ended (`grew` or `kept`),
//       and whether that rdy saw c's FIN (POLLHUP on Darwin, POLLRDHUP on
//       Linux: `fin` or `no-fin`).
//   A   acknowledgement. L's linger0 cunsent row: fill; then, at once, the
//       bytes c has sent that p has not acknowledged (`unacked` if any,
//       `acked` if none); close(c) with SO_LINGER {1, 0}; then whether p
//       sees the reset (POLLHUP) within 3 s (`reset` or `no-reset`).
//       tcp-shutdown.c recorded the reset seen at once.
//
// A row's unacknowledged bytes are, on Darwin, TCP_CONNECTION_INFO's bytes
// sent (tcpi_txbytes less tcpi_txretransmitbytes) less those acknowledged
// (what c wrote less tcpi_snd_sbbytes); on Linux, SIOCOUTQ less SIOCOUTQNSD.
//
// Each section runs its row 800 times, in 8 processes of 100 at once, since
// the rows answer otherwise rarely, and more often under concurrency; each
// line is a count of runs. Counts vary from one run of the probe to the
// next. The findings are the zeros: on Darwin, `G kept fin` and `A acked
// no-reset` (where the buffer kept its size, c's FIN stayed behind its
// bytes; where every byte was acknowledged, the reset was seen), beside a
// few runs in `G grew fin` and many in `A unacked no-reset`; on Linux,
// neither `grew` nor `unacked` at all.
//
// Build and run, from this directory:
//   Darwin: clang -Wall -O1 -o /tmp/fill-settling fill-settling.c && /tmp/fill-settling
//   Linux:  container run --rm -v "$PWD":/probe debian:trixie sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -O1 -o /tmp/p /probe/fill-settling.c && /tmp/p'
//
// Measured 2026-10-14 on Darwin 27.0.0 arm64 (uid 501) and Linux 6.18.5
// aarch64 (Apple's container VM, root, default sysctls), twice on each, with
// the same zeros each time; one run of each is fill-settling.darwin-27.0.txt
// and fill-settling.linux-6.18.5-aarch64.txt.

#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/sockios.h>
#define FIN_SEEN POLLRDHUP
#define RDY_EVENTS (POLLIN | POLLOUT | POLLPRI | POLLRDHUP)
#else
#define FIN_SEEN POLLHUP
#define RDY_EVENTS (POLLIN | POLLOUT | POLLPRI)
#endif

#define WORKERS 8
#define RUNS 100

static void die(const char *what) { perror(what); exit(2); }

static void settle(void) { usleep(30000); }

static char buf[1 << 20];

static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static void set_nb(int fd)
{
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) die("fcntl");
}

static void discard(int fd)
{
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
}

// A connected pair, both non-blocking, and the listener closed.
static void pair(int *c, int *p)
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    if (l < 0) die("socket");
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(l, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    if (listen(l, 4) < 0) die("listen");
    socklen_t al = sizeof a;
    if (getsockname(l, (struct sockaddr *)&a, &al) < 0) die("getsockname");
    *c = socket(AF_INET, SOCK_STREAM, 0);
    if (*c < 0) die("socket");
    if (connect(*c, (struct sockaddr *)&a, sizeof a) < 0) die("connect");
    settle();
    *p = accept(l, NULL, NULL);
    if (*p < 0) die("accept");
    close(l);
    set_nb(*c);
    set_nb(*p);
}

// tcp-shutdown.c's fill: what it took.
static long fill(int c)
{
    long total = 0;
    int dry = 0;
    while (dry < 3 && total < (64L << 20)) {
        long r = write(c, buf, sizeof buf);
        if (r > 0) { total += r; dry = 0; continue; }
        if (errno != EAGAIN) die("fill");
        dry++;
        settle();
    }
    return total;
}

static int rcvbuf(int fd)
{
    int n = -1;
    socklen_t l = sizeof n;
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &l) < 0) die("getsockopt(SO_RCVBUF)");
    return n;
}

static int revents(int fd)
{
    struct pollfd pf = { .fd = fd, .events = RDY_EVENTS };
    if (poll(&pf, 1, 0) < 0) die("poll");
    return pf.revents;
}

// Bytes c has sent that its peer has not acknowledged, `written` being all
// that c's writes took.
static long unacked(int c, long written)
{
#ifdef __linux__
    (void)written;
    int queued, unsent;
    if (ioctl(c, SIOCOUTQ, &queued) < 0) die("SIOCOUTQ");
    if (ioctl(c, SIOCOUTQNSD, &unsent) < 0) die("SIOCOUTQNSD");
    return (long)queued - unsent;
#else
    struct tcp_connection_info i;
    socklen_t l = sizeof i;
    if (getsockopt(c, IPPROTO_TCP, TCP_CONNECTION_INFO, &i, &l) < 0) die("TCP_CONNECTION_INFO");
    long sent = (long)(i.tcpi_txbytes - i.tcpi_txretransmitbytes);
    long acknowledged = written - (long)i.tcpi_snd_sbbytes;
    return sent - acknowledged;
#endif
}

// Section G's row: [grew][fin] counts.
static void growth(long counts[2][2])
{
    int c, p;
    pair(&c, &p);
    fill(c);
    int before = rcvbuf(p);
    shutdown(c, SHUT_WR);
    settle();
    revents(p);
    read(c, buf, 4096);
    settle();
    read(c, buf, 4096);
    settle();
    read(p, buf, 4096);
    settle();
    write(c, buf, 100);
    settle();
    write(c, buf, 0);
    settle();
    write(p, buf, 100);
    settle();
    int after = revents(p);
    int grew = rcvbuf(p) > before;
    counts[grew][(after & FIN_SEEN) != 0]++;
    discard(c);
    discard(p);
}

// Section A's row: [unacked][reset] counts.
static void acknowledgement(long counts[2][2])
{
    int c, p;
    pair(&c, &p);
    long written = fill(c);
    int pending = unacked(c, written) > 0;
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(c);
    long deadline = now_ms() + 3000;
    int reset = 0;
    while (!reset && now_ms() < deadline) {
        reset = (revents(p) & POLLHUP) != 0;
        if (!reset) usleep(1000);
    }
    counts[pending][reset]++;
    discard(p);
}

// Runs `row` RUNS times in each of WORKERS processes at once; the summed
// counts.
static void spread(void (*row)(long[2][2]), long total[2][2])
{
    int pipes[WORKERS][2];
    for (int w = 0; w < WORKERS; w++) {
        if (pipe(pipes[w]) < 0) die("pipe");
        pid_t pid = fork();
        if (pid < 0) die("fork");
        if (pid == 0) {
            long counts[2][2] = { { 0, 0 }, { 0, 0 } };
            for (int k = 0; k < RUNS; k++) row(counts);
            if (write(pipes[w][1], counts, sizeof counts) != sizeof counts) die("write");
            _exit(0);
        }
        close(pipes[w][1]);
    }
    memset(total, 0, sizeof(long[2][2]));
    for (int w = 0; w < WORKERS; w++) {
        long counts[2][2];
        if (read(pipes[w][0], counts, sizeof counts) != sizeof counts) die("read");
        close(pipes[w][0]);
        for (int i = 0; i < 2; i++)
            for (int j = 0; j < 2; j++) total[i][j] += counts[i][j];
    }
    while (wait(NULL) > 0) {
    }
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname u;
    if (uname(&u) == 0) printf("#\t%s %s %s\n", u.sysname, u.release, u.machine);

    long g[2][2];
    spread(growth, g);
    printf("G\tgrew\tfin\t%ld\n", g[1][1]);
    printf("G\tgrew\tno-fin\t%ld\n", g[1][0]);
    printf("G\tkept\tfin\t%ld\n", g[0][1]);
    printf("G\tkept\tno-fin\t%ld\n", g[0][0]);

    long a[2][2];
    spread(acknowledgement, a);
    printf("A\tunacked\treset\t%ld\n", a[1][1]);
    printf("A\tunacked\tno-reset\t%ld\n", a[1][0]);
    printf("A\tacked\treset\t%ld\n", a[0][1]);
    printf("A\tacked\tno-reset\t%ld\n", a[0][0]);
    return 0;
}
