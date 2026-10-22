// What closing a descriptor does to calls asleep on the same connected TCP
// socket, or pipe end, through a dup of it, and to calls made through the dup
// later, on Linux and Darwin.
//
// Each row makes a fresh loopback TCP pair (c connecting, p accepted) or a
// fresh pipe, and a dup d of the descriptor under test: c, the pipe's read end
// for a row of readers, or its write end for a row of writers. Its sleepers
// are threads, each making one blocking call through c (@fd), through d
// (@dup), or through d when a `park` event comes (@later); a sleeper started
// at the row's start has 100 ms to fall asleep. The calls:
//   read    read(fd, 4096) with nothing queued
//   recv    recv(fd, 4096, 0) with nothing queued
//   peek    recv(fd, 4096, MSG_PEEK) with nothing queued
//   write   write(fd, 1000) into buffers already full: a TCP socket filled by
//           non-blocking sends until three tries 50 ms apart take nothing,
//           whenever the row has a writer, a pipe filled by non-blocking
//           writes until EAGAIN
//   big     write(fd, 8 MiB), more than the buffers hold
//   poll    poll({fd, POLLIN}, 1, -1)
//   select  select with fd in the read set, no timeout
// The events, each followed by 100 ms and a report of every sleeper:
//   close   close(c), or of the pipe end, by the main thread
//   write   p writes "abc"; for a pipe, its write end does
//   fin     shutdown(p, SHUT_WR)
//   room    p, or the pipe's read end, reads non-blocking until twenty tries
//           50 ms apart find nothing
//   park    the next @later sleeper starts
//   nb      the main thread's recv(d, 4096, MSG_DONTWAIT), reported inline
//   poll0   the main thread's poll({d, POLLIN|POLLOUT}, 1, 0), reported inline
// After the last event every sleeper still asleep is sent SIGUSR1, whose
// handler (no SA_RESTART) counts it, and the row reports once more. A
// sleeper's report is its call's answer and the order it returned in (#n),
// or `asleep`, or `unparked` for an @later sleeper not yet started. SIGPIPE
// is caught and counted per row. Each row ends with what is still queued for
// d (FIONREAD; for a row of pipe writers, for the read end), d's status word
// (F_GETFL, whose 0x10000 is Darwin's FWASWRITTEN), and for TCP what p holds
// unread (FIONREAD) and what d has yet to send (SO_NWRITE on Darwin, SIOCOUTQ
// on Linux).
//
// Build and run, from this directory (row names as arguments run only those
// rows):
//   Darwin: clang -Wall -O1 -pthread -o /tmp/tcp-close-drain tcp-close-drain.c && /tmp/tcp-close-drain
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -pthread -o /tmp/p /probe/tcp-close-drain.c && /tmp/p'
//
// Measured 2026-10-21 on Darwin 27.0.0 arm64 (uid 501) and Linux 6.18.5
// aarch64 (Apple's container VM, gcc:14 image), twice each; one run of each is
// tcp-close-drain.darwin-27.0.txt and tcp-close-drain.linux-6.18.5-aarch64.txt.
// The runs differed only in the milliseconds a close took, the order in which
// sleepers woken together returned, how much of T21's 8 MiB write the buffers
// held, and whether Linux's T21 write had finished within 100 ms of the room
// it was given. What they say:
//   Linux: no close ended or changed any call. Every sleeper slept on and
//      answered what the peer then sent, or the room it made, through either
//      descriptor.
//   Darwin, TCP: a close of a descriptor that a read, recv, peek, write or
//      select was asleep through drains the socket (T3-T6, T14, T20): every
//      call asleep on it, through either descriptor and in either direction,
//      answers EBADF at once (T22, T23), a write marking nothing that had
//      taken nothing. The drain lasts. A later call through the dup that
//      would sleep answers EBADF instead, a read or a write, whichever
//      direction the sleeper that drained it was in (T7, T10, T12, T15, T17,
//      T18); a write that takes some of its bytes first answers EBADF having
//      left them queued, and marks the description written (T21). A call that
//      finds bytes, a FIN or room for all it writes answers as it would have
//      (T8, T9, T10, T16), and a non-blocking one that finds nothing answers
//      EAGAIN (T11). Queued bytes stay queued, and poll reports what Linux's
//      does (T11). A close with only a dup's sleeper (T1, T2, T13) or with a
//      poll asleep through the closed descriptor (T19) drains nothing: the
//      sleepers sleep on and answer the peer.
//   Darwin, pipes: nothing is drained. The call asleep through the closed
//      descriptor ends, a read with 0 and a write with EPIPE and SIGPIPE, as
//      `close-ends-call.c` measured; a call asleep through the dup sleeps on
//      (P1, P3), and so does a later one (P2, P4), until the other end writes
//      or makes room.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/sockios.h>
#endif

static atomic_int sigpipes;
static atomic_int returned;

static void on_sigpipe(int signo) { (void)signo; atomic_fetch_add(&sigpipes, 1); }
static void on_sigusr1(int signo) { (void)signo; }

static void die(const char *what)
{
    perror(what);
    exit(2);
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
        case EINVAL: return "EINVAL";
        default:
            snprintf(other, sizeof other, "errno%d", e);
            return other;
    }
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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

static int nread(int fd)
{
    int n = -1;
    if (ioctl(fd, FIONREAD, &n) < 0) return -1000 - errno;
    return n;
}

static int unsent(int fd)
{
#ifdef __linux__
    int n = -1;
    if (ioctl(fd, SIOCOUTQ, &n) < 0) return -1000 - errno;
    return n;
#else
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(fd, SOL_SOCKET, SO_NWRITE, &v, &len) < 0) return -1000 - errno;
    return v;
#endif
}

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
static char sink[1 << 20];

// Fill a TCP socket's buffers, and its peer's receive buffer, by send(2)
// through O_NONBLOCK until three tries 50 ms apart take nothing. (Darwin's
// send(MSG_DONTWAIT) of 65536 bytes sleeps once they are full; a send, unlike
// a write, leaves Darwin's FWASWRITTEN clear.)
static void fill_tcp(int fd)
{
    set_nonblocking(fd, 1);
    int idle = 0;
    while (idle < 3)
    {
        ssize_t n = send(fd, payload, 1 << 16, 0);
        if (n > 0)
        {
            idle = 0;
            continue;
        }
        if (errno != EAGAIN) die("fill send");
        idle++;
        sleep_ms(50);
    }
    set_nonblocking(fd, 0);
}

static void fill_pipe(int w)
{
    set_nonblocking(w, 1);
    while (write(w, payload, sizeof payload) > 0 || errno != EAGAIN) { }
    while (write(w, payload, 1) > 0) { }
    set_nonblocking(w, 0);
}

// Read everything queued on fd, non-blocking, until twenty tries 50 ms apart
// find nothing. (Three were too few for Linux: a writer that had slept 300 ms
// on full buffers was still asleep after them, with or without a close.)
static void empty_out(int fd)
{
    set_nonblocking(fd, 1);
    int idle = 0;
    while (idle < 20)
    {
        if (read(fd, sink, sizeof sink) > 0)
        {
            idle = 0;
            continue;
        }
        idle++;
        sleep_ms(50);
    }
    set_nonblocking(fd, 0);
}

enum kind { K_READ, K_RECV, K_PEEK, K_WRITE, K_POLL, K_SELECT, K_BIG };
enum via { V_FD, V_DUP, V_LATER };

static const char *kind_names[] = { "read", "recv", "peek", "write", "poll", "select", "big" };
static const char *via_names[] = { "fd", "dup", "later" };

typedef struct
{
    enum kind kind;
    enum via via;
    int fd;
    pthread_t thread;
    int launched;
    atomic_int started;
    atomic_int done;
    ssize_t rv;
    int error;
    int revents;
    int order;
} sleeper;

static void *run(void *arg)
{
    sleeper *s = arg;
    atomic_store(&s->started, 1);
    errno = 0;
    switch (s->kind)
    {
        case K_READ: s->rv = read(s->fd, sink, 4096); break;
        case K_RECV: s->rv = recv(s->fd, sink, 4096, 0); break;
        case K_PEEK: s->rv = recv(s->fd, sink, 4096, MSG_PEEK); break;
        case K_WRITE: s->rv = write(s->fd, payload, 1000); break;
        case K_BIG: s->rv = write(s->fd, payload, sizeof payload); break;
        case K_POLL:
        {
            struct pollfd pfd = { s->fd, POLLIN, 0 };
            s->rv = poll(&pfd, 1, -1);
            s->revents = pfd.revents;
            break;
        }
        case K_SELECT:
        {
            fd_set set;
            FD_ZERO(&set);
            FD_SET(s->fd, &set);
            s->rv = select(s->fd + 1, &set, NULL, NULL, NULL);
            break;
        }
    }
    s->error = s->rv < 0 ? errno : 0;
    s->order = atomic_fetch_add(&returned, 1) + 1;
    atomic_store(&s->done, 1);
    return NULL;
}

static void launch(sleeper *s, int fd)
{
    s->fd = fd;
    atomic_init(&s->started, 0);
    atomic_init(&s->done, 0);
    if (pthread_create(&s->thread, NULL, run, s) != 0) die("pthread_create");
    s->launched = 1;
    while (!atomic_load(&s->started)) { }
}

static void report(const char *row, const char *when, sleeper *ss, int n)
{
    int count = 0;
    for (int i = 0; i < n; i++)
        if (ss[i].launched && atomic_load(&ss[i].done)) count++;
    printf("%s %s: %d returned;", row, when, count);
    for (int i = 0; i < n; i++)
    {
        sleeper *s = &ss[i];
        printf(" [%d %s@%s ", i, kind_names[s->kind], via_names[s->via]);
        if (!s->launched)
            printf("unparked]");
        else if (!atomic_load(&s->done))
            printf("asleep]");
        else if (s->rv < 0)
            printf("-1 %s #%d]", errname(s->error), s->order);
        else if (s->kind == K_POLL)
            printf("%zd revents=0x%x #%d]", s->rv, s->revents, s->order);
        else
            printf("%zd #%d]", s->rv, s->order);
    }
    printf("\n");
}

typedef struct
{
    const char *name;
    int pipe;              // 0: TCP; 1: pipe
    const char *sleepers;  // e.g. "read@fd read@dup"
    const char *events;    // e.g. "close write"
} row;

static int parse_sleepers(const char *spec, sleeper *out)
{
    char buf[256];
    snprintf(buf, sizeof buf, "%s", spec);
    int n = 0;
    for (char *tok = strtok(buf, " "); tok; tok = strtok(NULL, " "))
    {
        char *at = strchr(tok, '@');
        if (!at) die("sleeper spec");
        *at = 0;
        memset(&out[n], 0, sizeof out[n]);
        int k;
        for (k = 0; k < 7 && strcmp(kind_names[k], tok) != 0; k++) { }
        if (k == 7) die("sleeper kind");
        int v;
        for (v = 0; v < 3 && strcmp(via_names[v], at + 1) != 0; v++) { }
        if (v == 3) die("sleeper via");
        out[n].kind = k;
        out[n].via = v;
        n++;
    }
    return n;
}

static void run_row(const row *r)
{
    sleeper ss[8];
    int n = parse_sleepers(r->sleepers, ss);
    int writers = ss[0].kind == K_WRITE;
    int anywriter = 0;
    for (int i = 0; i < n; i++) anywriter |= ss[i].kind == K_WRITE || ss[i].kind == K_BIG;

    // under: the descriptor the row closes; other: what the events act on.
    int under, other;
    if (r->pipe)
    {
        int fds[2];
        if (pipe(fds) < 0) die("pipe");
        under = writers ? fds[1] : fds[0];
        other = writers ? fds[0] : fds[1];
        if (writers) fill_pipe(under);
    }
    else
    {
        make_pair(&under, &other);
        if (anywriter) fill_tcp(under);
    }
    int d = dup(under);
    if (d < 0) die("dup");
    atomic_store(&returned, 0);
    int pipes_before = atomic_load(&sigpipes);

    printf("%s: %s, sleepers %s; events %s\n", r->name, r->pipe ? "pipe" : "tcp", r->sleepers, r->events);
    int any = 0;
    for (int i = 0; i < n; i++)
        if (ss[i].via != V_LATER)
        {
            launch(&ss[i], ss[i].via == V_FD ? under : d);
            any = 1;
        }
    if (any) sleep_ms(100);
    report(r->name, "parked", ss, n);

    char buf[256];
    snprintf(buf, sizeof buf, "%s", r->events);
    char *save = NULL;
    for (char *ev = strtok_r(buf, " ", &save); ev; ev = strtok_r(NULL, " ", &save))
    {
        if (strcmp(ev, "close") == 0)
        {
            int64_t t0 = now_ms();
            int rv = close(under);
            int e = rv < 0 ? errno : 0;
            printf("%s: close answered %d %s in %lld ms\n", r->name, rv, errname(e), (long long)(now_ms() - t0));
        }
        else if (strcmp(ev, "write") == 0)
        {
            if (write(other, "abc", 3) != 3) die("event write");
        }
        else if (strcmp(ev, "fin") == 0)
        {
            if (shutdown(other, SHUT_WR) < 0) die("event fin");
        }
        else if (strcmp(ev, "room") == 0)
        {
            empty_out(other);
        }
        else if (strcmp(ev, "park") == 0)
        {
            int i;
            for (i = 0; i < n && !(ss[i].via == V_LATER && !ss[i].launched); i++) { }
            if (i == n) die("park with no @later sleeper left");
            launch(&ss[i], d);
        }
        else if (strcmp(ev, "nb") == 0)
        {
            errno = 0;
            ssize_t rv = recv(d, sink, 4096, MSG_DONTWAIT);
            printf("%s: recv(dup, MSG_DONTWAIT) answered %zd %s\n", r->name, rv, errname(rv < 0 ? errno : 0));
        }
        else if (strcmp(ev, "poll0") == 0)
        {
            struct pollfd pfd = { d, POLLIN | POLLOUT, 0 };
            int rv = poll(&pfd, 1, 0);
            printf("%s: poll(dup, IN|OUT, 0) answered %d revents=0x%x\n", r->name, rv, pfd.revents);
        }
        else
            die("event");
        sleep_ms(100);
        char when[64];
        snprintf(when, sizeof when, "after %s", ev);
        report(r->name, when, ss, n);
    }

    for (int i = 0; i < n; i++)
        if (ss[i].launched && !atomic_load(&ss[i].done)) pthread_kill(ss[i].thread, SIGUSR1);
    sleep_ms(100);
    report(r->name, "after the signal", ss, n);
    for (int i = 0; i < n; i++)
        if (ss[i].launched)
        {
            if (!atomic_load(&ss[i].done)) die("a sleeper outlived its signal");
            pthread_join(ss[i].thread, NULL);
        }

    int queued = r->pipe ? nread(writers ? other : d) : nread(d);
    printf("%s: then %d bytes queued for the %s; dup's F_GETFL 0x%x", r->name, queued,
           writers && r->pipe ? "read end" : "dup", (unsigned)fcntl(d, F_GETFL));
    if (!r->pipe) printf("; peer holds %d, dup has %d unsent", nread(other), unsent(d));
    printf("; sigpipe %d\n", atomic_load(&sigpipes) - pipes_before);
    close(d);
    close(other);
}

static const row rows[] = {
    // A sleeper through the dup alone.
    { "T1", 0, "read@dup", "close write" },
    { "T2", 0, "read@dup read@later", "close park write" },
    // Sleepers through both.
    { "T3", 0, "read@fd read@dup", "close write" },
    { "T4", 0, "recv@fd recv@dup", "close write" },
    { "T5", 0, "peek@fd peek@dup", "close write" },
    { "T6", 0, "read@fd read@dup read@fd", "close write" },
    // A later sleeper, after a close that ended one through the closed descriptor.
    { "T7", 0, "read@fd read@later", "close park write" },
    { "T8", 0, "read@fd read@later", "close write park" },
    { "T9", 0, "read@fd read@later", "close fin park" },
    { "T10", 0, "read@fd read@later read@later", "close write park park" },
    { "T11", 0, "read@fd", "close nb poll0 write nb" },
    { "T12", 0, "recv@fd peek@later", "close park write" },
    // Writes.
    { "T13", 0, "write@dup", "close room" },
    { "T14", 0, "write@fd write@dup", "close room" },
    { "T15", 0, "write@fd write@later", "close park room" },
    { "T16", 0, "write@fd write@later", "close room park" },
    // A drain across directions.
    { "T17", 0, "read@fd write@later", "close park write room" },
    { "T18", 0, "write@fd read@later", "close park write room" },
    // A later write that takes some and would sleep for the rest.
    { "T21", 0, "write@fd big@later", "close room park" },
    // Sleepers in both directions.
    { "T22", 0, "read@fd write@dup", "close room write" },
    { "T23", 0, "write@fd read@dup", "close write room" },
    // Waits through the closed descriptor that are not transfers.
    { "T19", 0, "poll@fd read@dup", "close write" },
    { "T20", 0, "select@fd read@dup", "close write" },
    // Pipes.
    { "P1", 1, "read@fd read@dup", "close write" },
    { "P2", 1, "read@fd read@later", "close park write" },
    { "P3", 1, "write@fd write@dup", "close room" },
    { "P4", 1, "write@fd write@later", "close park room" },
};

int main(int argc, char **argv)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = on_sigusr1;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) die("sigaction SIGUSR1");
    sa.sa_handler = on_sigpipe;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) die("sigaction SIGPIPE");
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'x', sizeof payload);
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
    {
        int chosen = argc < 2;
        for (int a = 1; a < argc; a++) chosen |= strcmp(argv[a], rows[i].name) == 0;
        if (chosen) run_row(&rows[i]);
    }
    return 0;
}
