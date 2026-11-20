// When accept(2) reads the caller's length cell, what it answers when the
// cell cannot be read, and whether the connection survives that answer.
//
// The cell is given as
//   null       a NULL pointer
//   unmapped   the address of a page mapped PROT_NONE, which faults on any access
//   N          real storage holding the int N
// and the address buffer as
//   null       a NULL pointer
//   unmapped   the same PROT_NONE page
//   mapped     128 bytes of real storage
// Each row prints the answer, the cell afterwards (for real storage; "-"
// otherwise), how many bytes of a mapped buffer the call overwrote (counted
// over two fills, 0xAA and 0x55, in calls on two copies of the fixture), and,
// for a fixture with a connection queued, `client=` what the connecting socket
// sees within 200 ms of the call, `none`, `eof` (a read answers 0) or an errno
// name from the read, and then `queued=` whether a second, non-blocking accept
// with NULL pointers still finds the connection. A call that succeeds closes
// the descriptor it made at once, so its client sees `eof`.
//
// Sections:
//   A  a call that cannot sleep, on: a closed descriptor, a pipe, an idle
//      stream socket (EINVAL), a datagram socket (EOPNOTSUPP), an empty
//      non-blocking listener (EAGAIN), and a non-blocking listener with one
//      connection queued; on Linux also accept4 with an unknown flag bit
//      (EINVAL) on a listener with one connection queued.
//   B  a blocking listener with nothing queued, through a NULL or unmapped
//      cell and a NULL or mapped buffer, a thread connecting 200 ms later:
//      the answer, whether the call slept (`slept=`), and the connection's
//      fate as in A.
//   C  a blocking accept into a mapped buffer through a cell holding 16, asleep
//      on an empty listener, whose cell another thread changes to 4, 0 or -1
//      before it connects: which value the call used.
//
// The probe exits 1 if a fixture cannot be built, or if a state it waits for
// does not arrive within two seconds.
//
// Outputs beside this file, measured 2026-11-20:
//
// * darwin-27.2.0-arm64.txt: natively, from this directory,
//     cc -Wall -O1 -pthread -o /tmp/p accept-length-cell.c && /tmp/p
// * linux-6.18.5-aarch64.txt: Apple's `container`, gcc:14 image, from this
//   directory,
//     container run --rm -v "$PWD:/probe" gcc:14 sh -c 'cc -Wall -O1 -pthread -o /tmp/p /probe/accept-length-cell.c && /tmp/p'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>

static const char *en(int e) {
    switch (e) {
    case 0: return "OK";
    case EBADF: return "EBADF";
    case ENOTSOCK: return "ENOTSOCK";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case EAGAIN: return "EAGAIN";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case ECONNRESET: return "ECONNRESET";
    case ECONNABORTED: return "ECONNABORTED";
    default: { static char b[32]; snprintf(b, sizeof b, "errno%d", e); return b; }
    }
}

static void need(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "setup failed: %s (errno %d)\n", what, errno);
        exit(1);
    }
}

static void *faulting;

static struct sockaddr_in loopback(unsigned short port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
#ifdef __APPLE__
    a.sin_len = sizeof a;
#endif
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

static unsigned short port_of(int fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    memset(&a, 0, sizeof a);
    need(getsockname(fd, (struct sockaddr *)&a, &l) == 0, "getsockname for a port");
    need(a.sin_port != 0, "a bound port");
    return ntohs(a.sin_port);
}

static void set_nonblocking(int fd, int on) {
    int f = fcntl(fd, F_GETFL);
    need(f >= 0, "F_GETFL");
    need(fcntl(fd, F_SETFL, on ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK)) == 0, "F_SETFL");
}

static int listener(int nonblocking) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    need(l >= 0, "socket for a listener");
    struct sockaddr_in a = loopback(0);
    need(bind(l, (struct sockaddr *)&a, sizeof a) == 0, "bind a listener");
    need(listen(l, 4) == 0, "listen");
    if (nonblocking) set_nonblocking(l, 1);
    return l;
}

// A client connected to `l`, its connection queued once `l` polls readable.
static int connect_to(int l) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    need(c >= 0, "socket for a client");
    struct sockaddr_in a = loopback(port_of(l));
    need(connect(c, (struct sockaddr *)&a, sizeof a) == 0, "connect a client");
    struct pollfd p = { l, POLLIN, 0 };
    need(poll(&p, 1, 2000) == 1, "the connection queued at the listener");
    return c;
}

// What the client sees within 200 ms.
static const char *client_view(int c) {
    struct pollfd p = { c, POLLIN, 0 };
    if (poll(&p, 1, 200) == 0) return "none";
    char b;
    ssize_t n = recv(c, &b, 1, MSG_DONTWAIT);
    if (n == 0) return "eof";
    if (n > 0) return "data";
    return en(errno);
}

enum kind { NUL, UNMAPPED, HOLDS };

static void *pointer(enum kind k, void *storage) {
    return k == NUL ? NULL : k == UNMAPPED ? faulting : storage;
}

static void name(char *out, size_t size, enum kind k, int held, int is_cell) {
    if (k == NUL) snprintf(out, size, "null");
    else if (k == UNMAPPED) snprintf(out, size, "unmapped");
    else if (is_cell) snprintf(out, size, "%d", held);
    else snprintf(out, size, "mapped");
}

// The fixtures of section A, each built afresh for each call.
enum fixture { CLOSED, PIPE, IDLE, DGRAM, EMPTY, QUEUED, BADFLAGS };
static const char *fixture_names[] = { "closed", "pipe", "tcp-idle", "udp", "listener-empty", "listener-queued", "accept4-bad-flags" };

struct built { int fd; int client; int extra; };

static struct built build(enum fixture f) {
    struct built b = { -1, -1, -1 };
    switch (f) {
    case CLOSED:
        b.fd = socket(AF_INET, SOCK_STREAM, 0);
        need(b.fd >= 0, "socket");
        close(b.fd);
        break;
    case PIPE: {
        int p[2];
        need(pipe(p) == 0, "pipe");
        b.fd = p[0];
        b.extra = p[1];
        break;
    }
    case IDLE:
        b.fd = socket(AF_INET, SOCK_STREAM, 0);
        need(b.fd >= 0, "socket");
        set_nonblocking(b.fd, 1);
        break;
    case DGRAM:
        b.fd = socket(AF_INET, SOCK_DGRAM, 0);
        need(b.fd >= 0, "socket");
        set_nonblocking(b.fd, 1);
        break;
    case EMPTY:
        b.fd = listener(1);
        break;
    case QUEUED:
    case BADFLAGS:
        b.fd = listener(1);
        b.client = connect_to(b.fd);
        break;
    }
    return b;
}

static void tear(struct built b) {
    if (b.fd >= 0) close(b.fd);
    if (b.client >= 0) close(b.client);
    if (b.extra >= 0) close(b.extra);
}

static int call(enum fixture f, int fd, void *dest, socklen_t *cell) {
    errno = 0;
    int r;
#ifdef __linux__
    if (f == BADFLAGS) r = accept4(fd, (struct sockaddr *)dest, cell, 1);
    else
#endif
    r = accept(fd, (struct sockaddr *)dest, cell);
    if (r >= 0) {
        close(r);
        return 0;
    }
    return errno;
}

static void row_a(enum fixture f, enum kind ck, int held, enum kind dk) {
    unsigned char bufs[2][128];
    unsigned char fills[2] = { 0xAA, 0x55 };
    int e[2], cellafter[2];
    const char *queued = NULL, *client = NULL;
    for (int i = 0; i < 2; i++) {
        struct built b = build(f);
        memset(bufs[i], fills[i], 128);
        int cell = held;
        e[i] = call(f, b.fd, pointer(dk, bufs[i]), (socklen_t *)pointer(ck, &cell));
        cellafter[i] = cell;
        if (b.client >= 0 && i == 0) {
            client = client_view(b.client);
            int again = accept(b.fd, NULL, NULL);
            queued = again >= 0 ? "yes" : (errno == EAGAIN ? "no" : en(errno));
            if (again >= 0) close(again);
        }
        tear(b);
    }
    int written = 0;
    for (int i = 0; i < 128; i++) if (bufs[0][i] != 0xAA || bufs[1][i] != 0x55) written++;
    char cn[32], dn[32];
    name(cn, sizeof cn, ck, held, 1);
    name(dn, sizeof dn, dk, 0, 0);
    printf("A %s cell=%s dest=%s -> %s", fixture_names[f], cn, dn, en(e[0]));
    if (ck == HOLDS) printf(" cellafter=%d", cellafter[0]); else printf(" cellafter=-");
    printf(" written=%d", dk == HOLDS ? written : 0);
    if (queued) printf(" queued=%s client=%s", queued, client);
    if (e[0] != e[1] || cellafter[0] != cellafter[1]) printf(" MISMATCH %s cellafter=%d", en(e[1]), cellafter[1]);
    printf("\n");
}

static long now_ms(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec * 1000L + t.tv_usec / 1000;
}

struct connector { int listener; int delay_ms; int client; int *cell; int new_cell; };

static void *connector_main(void *arg) {
    struct connector *c = arg;
    usleep(c->delay_ms * 1000);
    if (c->cell) *c->cell = c->new_cell;
    c->client = connect_to(c->listener);
    return NULL;
}

static void row_b(enum kind ck, enum kind dk) {
    int l = listener(0);
    unsigned char buf[128];
    memset(buf, 0xAA, sizeof buf);
    int cell = 16;
    struct connector c = { l, 200, -1, NULL, 0 };
    pthread_t t;
    need(pthread_create(&t, NULL, connector_main, &c) == 0, "pthread_create");
    long start = now_ms();
    int e = call(QUEUED, l, pointer(dk, buf), (socklen_t *)pointer(ck, &cell));
    long took = now_ms() - start;
    pthread_join(t, NULL);
    const char *client = client_view(c.client);
    set_nonblocking(l, 1);
    int again = accept(l, NULL, NULL);
    const char *queued = again >= 0 ? "yes" : (errno == EAGAIN ? "no" : en(errno));
    if (again >= 0) close(again);
    int written = 0;
    for (int i = 0; i < 128; i++) if (buf[i] != 0xAA) written++;
    char cn[32], dn[32];
    name(cn, sizeof cn, ck, 16, 1);
    name(dn, sizeof dn, dk, 0, 0);
    printf("B blocking-empty cell=%s dest=%s -> %s slept=%s written=%d queued=%s client=%s\n", cn, dn, en(e),
           took >= 150 ? "yes" : "no", written, queued, client);
    close(c.client);
    close(l);
}

static void row_c(int new_cell) {
    int l = listener(0);
    unsigned char bufs[128];
    memset(bufs, 0xAA, sizeof bufs);
    int cell = 16;
    struct connector c = { l, 200, -1, &cell, new_cell };
    pthread_t t;
    need(pthread_create(&t, NULL, connector_main, &c) == 0, "pthread_create");
    long start = now_ms();
    int e = call(QUEUED, l, bufs, (socklen_t *)&cell);
    long took = now_ms() - start;
    pthread_join(t, NULL);
    int written = 0;
    for (int i = 0; i < 128; i++) if (bufs[i] != 0xAA) written++;
    const char *client = client_view(c.client);
    set_nonblocking(l, 1);
    int again = accept(l, NULL, NULL);
    const char *queued = again >= 0 ? "yes" : (errno == EAGAIN ? "no" : en(errno));
    if (again >= 0) close(again);
    printf("C cell=16 changed-to=%d dest=mapped -> %s slept=%s cellafter=%d written=%d queued=%s client=%s\n", new_cell, en(e),
           took >= 150 ? "yes" : "no", cell, written, queued, client);
    close(c.client);
    close(l);
}

int main(void) {
    struct utsname u;
    uname(&u);
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);

    // Kept mapped, and so never reused, for the whole run.
    faulting = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    need(faulting != MAP_FAILED, "mmap a PROT_NONE page");

    enum fixture fixtures[] = { CLOSED, PIPE, IDLE, DGRAM, EMPTY, QUEUED
#ifdef __linux__
                                , BADFLAGS
#endif
    };
    enum kind dests[] = { NUL, UNMAPPED, HOLDS };
    int helds[] = { 16, 0, -1 };
    for (unsigned f = 0; f < sizeof fixtures / sizeof fixtures[0]; f++) {
        for (unsigned d = 0; d < 3; d++) {
            row_a(fixtures[f], NUL, 0, dests[d]);
            row_a(fixtures[f], UNMAPPED, 0, dests[d]);
            for (unsigned h = 0; h < 3; h++) row_a(fixtures[f], HOLDS, helds[h], dests[d]);
        }
    }

    enum kind cells[] = { NUL, UNMAPPED };
    enum kind bdests[] = { NUL, HOLDS };
    for (unsigned i = 0; i < 2; i++)
        for (unsigned d = 0; d < 2; d++) row_b(cells[i], bdests[d]);

    int changes[] = { 4, 0, -1 };
    for (unsigned i = 0; i < 3; i++) row_c(changes[i]);
    return 0;
}
