// When getsockname(2) and getpeername(2) read the caller's length cell, and
// what they answer when the cell cannot be read.
//
// Each row is one call on one fixture, with the length cell given as
//   null       a NULL pointer
//   unmapped   the address of a page mapped PROT_NONE, which faults on any access
//   N          real storage holding the int N
// and the address buffer given as
//   null       a NULL pointer
//   unmapped   the same unmapped page
//   mapped     128 bytes of real storage
// The row prints the call's answer, what the cell holds afterwards (for real
// storage; "-" otherwise), and how many bytes of a mapped address buffer the
// call overwrote. The call is made twice, through a buffer filled with 0xAA
// and then with 0x55, and a byte counts as overwritten if either call changed
// it, so that an address byte equal to one fill is still counted; a row whose
// two calls disagree on the answer or the cell prints MISMATCH.
//
// A condition whose errno a row through a NULL or an unmapped cell still
// answers is checked before the kernel reads the cell; one that row answers
// EFAULT for instead is checked after it, if at all. A row through a cell
// holding -1 shows Linux's EINVAL for a negative length.
//
// Each fixture also prints what it is (its descriptor, its state, and for the
// refusal fixture the pending error) before and after its rows, so that a row
// that changed the fixture shows. The probe exits 1, before any row of the
// fixture, if a call that builds a fixture fails, or if a state a fixture waits
// for (a refusal, a reset, a FIN) has not arrived within two seconds; and after
// a fixture's rows, if its pending error is not the one it was built to hold.
// Reading that error takes it, and the same socket is then measured again as
// the fixture `tcp-refusal-taken` or `tcp-reset-taken`.
//
// Outputs beside this file, measured 2026-11-21:
//
// * darwin-27.2.0-arm64.txt: natively,
//     cc -Wall -O1 -o /tmp/p sockname-length-cell.c && /tmp/p
// * linux-6.18.5-aarch64.txt: Apple's `container`, gcc:14 image, from this
//   directory,
//     container run --rm -v "$PWD:/probe" gcc:14 sh -c 'cc -Wall -O1 -o /tmp/p /probe/sockname-length-cell.c && /tmp/p'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>

static const char *en(int e) {
    switch (e) {
    case 0: return "OK";
    case EBADF: return "EBADF";
    case ENOTSOCK: return "ENOTSOCK";
    case ENOTCONN: return "ENOTCONN";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ECONNRESET: return "ECONNRESET";
    case EINPROGRESS: return "EINPROGRESS";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    default: { static char b[32]; snprintf(b, sizeof b, "errno%d", e); return b; }
    }
}

static void *unmapped_page;

static void need(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "setup failed: %s (errno %d)\n", what, errno);
        exit(1);
    }
}

// Waits up to two seconds for `events` on `fd`, failing the probe otherwise.
static void await(int fd, short events, const char *what) {
    struct pollfd p = { fd, events, 0 };
    need(poll(&p, 1, 2000) == 1, what);
}

// Whether a read of `fd` would answer end of file: an orderly FIN, rather than
// an error, has arrived. Takes nothing.
static int at_eof(int fd) {
    char b;
    return recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT) == 0;
}

typedef int (*namefn)(int, struct sockaddr *, socklen_t *);

enum cellkind { CELL_NULL, CELL_UNMAPPED, CELL_HOLDS };
enum destkind { DEST_NULL, DEST_UNMAPPED, DEST_MAPPED };

// One call through a mapped buffer filled with `fill`: its errno, and the cell
// and the buffer it left.
static int once(namefn f, int fd, enum cellkind ck, int held, enum destkind dk, unsigned char fill, int *cellafter, unsigned char *buf) {
    memset(buf, fill, 128);
    int cell = held;
    socklen_t *cellp = ck == CELL_NULL ? NULL : ck == CELL_UNMAPPED ? (socklen_t *)unmapped_page : (socklen_t *)&cell;
    struct sockaddr *dest = dk == DEST_NULL ? NULL : dk == DEST_UNMAPPED ? (struct sockaddr *)unmapped_page : (struct sockaddr *)buf;
    errno = 0;
    int r = f(fd, dest, cellp);
    *cellafter = cell;
    return r == 0 ? 0 : errno;
}

static void row(const char *call, namefn f, const char *fixture, int fd, enum cellkind ck, int held, enum destkind dk) {
    unsigned char first[128], second[128];
    int cell, cellAgain;
    int e = once(f, fd, ck, held, dk, 0xAA, &cell, first);
    int eAgain = once(f, fd, ck, held, dk, 0x55, &cellAgain, second);
    int written = 0;
    for (unsigned i = 0; i < sizeof first; i++) if (first[i] != 0xAA || second[i] != 0x55) written++;
    char cellname[32];
    if (ck == CELL_NULL) snprintf(cellname, sizeof cellname, "null");
    else if (ck == CELL_UNMAPPED) snprintf(cellname, sizeof cellname, "unmapped");
    else snprintf(cellname, sizeof cellname, "%d", held);
    const char *destname = dk == DEST_NULL ? "null" : dk == DEST_UNMAPPED ? "unmapped" : "mapped";
    printf("%s %s cell=%s dest=%s -> %s", call, fixture, cellname, destname, en(e));
    if (ck == CELL_HOLDS) printf(" cellafter=%d", cell); else printf(" cellafter=-");
    printf(" written=%d", written);
    if (e != eAgain || cell != cellAgain) printf(" MISMATCH %s cellafter=%d", en(eAgain), cellAgain);
    printf("\n");
}

static void rows(const char *call, namefn f, const char *fixture, int fd) {
    enum destkind dests[] = { DEST_NULL, DEST_UNMAPPED, DEST_MAPPED };
    int helds[] = { 16, 0, -1 };
    for (unsigned d = 0; d < 3; d++) {
        row(call, f, fixture, fd, CELL_NULL, 0, dests[d]);
        row(call, f, fixture, fd, CELL_UNMAPPED, 0, dests[d]);
        for (unsigned h = 0; h < 3; h++) row(call, f, fixture, fd, CELL_HOLDS, helds[h], dests[d]);
    }
}

static void both(const char *fixture, int fd) {
    rows("getsockname", getsockname, fixture, fd);
    rows("getpeername", getpeername, fixture, fd);
}

static struct sockaddr_in sin_of(unsigned addr, unsigned short port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
#ifdef __APPLE__
    a.sin_len = sizeof a;
#endif
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(addr);
    a.sin_port = htons(port);
    return a;
}

static unsigned short port_of(int fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    memset(&a, 0, sizeof a);
    need(getsockname(fd, (struct sockaddr *)&a, &l) == 0, "getsockname for a fixture's port");
    need(a.sin_port != 0, "a bound port");
    return ntohs(a.sin_port);
}

static int tcp(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    need(fd >= 0, "socket(AF_INET, SOCK_STREAM)");
    return fd;
}

static int listener(void) {
    int l = tcp();
    struct sockaddr_in a = sin_of(INADDR_LOOPBACK, 0);
    need(bind(l, (struct sockaddr *)&a, sizeof a) == 0, "bind the listener");
    need(listen(l, 4) == 0, "listen");
    return l;
}

static int connect_to(int c, unsigned addr, unsigned short port) {
    struct sockaddr_in a = sin_of(addr, port);
    errno = 0;
    int r = connect(c, (struct sockaddr *)&a, sizeof a);
    return r == 0 ? 0 : errno;
}

static unsigned short dead_port(void) {
    int t = tcp();
    struct sockaddr_in a = sin_of(INADDR_LOOPBACK, 0);
    need(bind(t, (struct sockaddr *)&a, sizeof a) == 0, "bind for a dead port");
    unsigned short p = port_of(t);
    close(t);
    return p;
}

// The socket's pending error, read only after the fixture's rows, since
// reading SO_ERROR takes it.
static int so_error(int fd) {
    int v = -1;
    socklen_t vl = sizeof v;
    need(getsockopt(fd, SOL_SOCKET, SO_ERROR, &v, &vl) == 0, "getsockopt(SO_ERROR)");
    return v;
}

// The peer as a mapped 16-byte call reports it, to say which state the
// fixture is in.
static void state(const char *fixture, const char *when, int fd) {
    unsigned char buf[128];
    socklen_t l = sizeof buf;
    errno = 0;
    int r1 = getsockname(fd, (struct sockaddr *)buf, &l);
    int e1 = r1 == 0 ? 0 : errno;
    l = sizeof buf;
    errno = 0;
    int r2 = getpeername(fd, (struct sockaddr *)buf, &l);
    int e2 = r2 == 0 ? 0 : errno;
    printf("# %s %s: fd=%d getsockname=%s getpeername=%s\n", fixture, when, fd, en(e1), en(e2));
}

static void fixture(const char *name, int fd) {
    state(name, "before", fd);
    both(name, fd);
    state(name, "after", fd);
}

int main(void) {
    struct utsname u;
    uname(&u);
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);

    // Kept mapped, and so never reused, for the whole run.
    unmapped_page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    need(unmapped_page != MAP_FAILED, "mmap a PROT_NONE page");

    {
        int fd = tcp();
        close(fd);
        fixture("closed", fd);
    }
    {
        int p[2];
        need(pipe(p) == 0, "pipe");
        fixture("pipe", p[0]);
        close(p[0]);
        close(p[1]);
    }
    {
        int fd = tcp();
        fixture("tcp-fresh", fd);
        close(fd);
    }
    {
        int l = listener();
        fixture("tcp-listening", l);
        close(l);
    }
    {
        int l = listener();
        int c = tcp();
        int e = connect_to(c, INADDR_LOOPBACK, port_of(l));
        printf("# tcp-connected: connect -> %s\n", en(e));
        need(e == 0, "connect for tcp-connected");
        int s = accept(l, NULL, NULL);
        need(s >= 0, "accept for tcp-connected");
        fixture("tcp-connected", c);
        close(s);
        close(c);
        close(l);
    }
    {
        int c = tcp();
        int e = connect_to(c, INADDR_LOOPBACK, dead_port());
        printf("# tcp-refused: blocking connect -> %s\n", en(e));
        need(e == ECONNREFUSED, "a refused blocking connect");
        fixture("tcp-refused", c);
        printf("# tcp-refused: SO_ERROR after the rows -> %s\n", en(so_error(c)));
        close(c);
    }
    {
        int c = tcp();
        need(fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK) == 0, "O_NONBLOCK");
        int e = connect_to(c, INADDR_LOOPBACK, dead_port());
        printf("# tcp-refusal-pending: non-blocking connect -> %s\n", en(e));
        need(e == EINPROGRESS, "a non-blocking connect in progress");
        // The connect is over, refused, once the socket is writable.
        await(c, POLLOUT, "the refusal of the non-blocking connect");
        fixture("tcp-refusal-pending", c);
        int pending = so_error(c);
        printf("# tcp-refusal-pending: SO_ERROR after the rows -> %s\n", en(pending));
        need(pending == ECONNREFUSED, "ECONNREFUSED still pending after the rows");
        fixture("tcp-refusal-taken", c);
        printf("# tcp-refusal-taken: SO_ERROR after the rows -> %s\n", en(so_error(c)));
        close(c);
    }
    {
        int l = listener();
        int c = tcp();
        need(connect_to(c, INADDR_LOOPBACK, port_of(l)) == 0, "connect for tcp-reset");
        int s = accept(l, NULL, NULL);
        need(s >= 0, "accept for tcp-reset");
        struct linger lg = { 1, 0 };
        need(setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) == 0, "SO_LINGER {1, 0}");
        close(s);
        // The reset makes the client readable.
        await(c, POLLIN, "the reset at the client");
        fixture("tcp-reset", c);
        int pending = so_error(c);
        printf("# tcp-reset: SO_ERROR after the rows -> %s\n", en(pending));
        need(pending == ECONNRESET, "ECONNRESET still pending after the rows");
        fixture("tcp-reset-taken", c);
        printf("# tcp-reset-taken: SO_ERROR after the rows -> %s\n", en(so_error(c)));
        close(c);
        close(l);
    }
    {
        // Both ends shut their writing side, and each FIN has arrived.
        int l = listener();
        int c = tcp();
        need(connect_to(c, INADDR_LOOPBACK, port_of(l)) == 0, "connect for tcp-fins-exchanged");
        int s = accept(l, NULL, NULL);
        need(s >= 0, "accept for tcp-fins-exchanged");
        need(shutdown(c, SHUT_WR) == 0, "the client's shutdown(SHUT_WR)");
        // Each FIN makes the end it reaches readable, at end of file.
        await(s, POLLIN, "the client's FIN at the server");
        need(at_eof(s), "end of file, not an error, at the server");
        need(shutdown(s, SHUT_WR) == 0, "the server's shutdown(SHUT_WR)");
        await(c, POLLIN, "the server's FIN at the client");
        need(at_eof(c), "end of file, not an error, at the client");
        fixture("tcp-fins-exchanged", c);
        close(s);
        close(c);
        close(l);
    }
    {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        need(fd >= 0, "socket(AF_INET, SOCK_DGRAM, 0)");
        fixture("udp-fresh", fd);
        close(fd);
    }
    {
        int r = socket(AF_INET, SOCK_DGRAM, 0);
        need(r >= 0, "socket(AF_INET, SOCK_DGRAM)");
        struct sockaddr_in a = sin_of(INADDR_LOOPBACK, 0);
        need(bind(r, (struct sockaddr *)&a, sizeof a) == 0, "bind the UDP receiver");
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        need(s >= 0, "socket(AF_INET, SOCK_DGRAM)");
        int e = connect_to(s, INADDR_LOOPBACK, port_of(r));
        printf("# udp-connected: connect -> %s\n", en(e));
        need(e == 0, "connect for udp-connected");
        fixture("udp-connected", s);
        close(s);
        close(r);
    }
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        need(s >= 0, "socket(AF_INET, SOCK_DGRAM)");
        printf("# udp-port-zero: connect to port 0 -> %s\n", en(connect_to(s, INADDR_LOOPBACK, 0)));
        fixture("udp-port-zero", s);
        close(s);
    }
    {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        need(fd >= 0, "socket(AF_INET6, SOCK_STREAM, 0)");
        fixture("inet6-stream-fresh", fd);
        close(fd);
    }
    {
        int fd = socket(AF_INET6, SOCK_DGRAM, 0);
        need(fd >= 0, "socket(AF_INET6, SOCK_DGRAM, 0)");
        fixture("inet6-dgram-fresh", fd);
        close(fd);
    }
    {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        need(fd >= 0, "socket(AF_UNIX, SOCK_STREAM, 0)");
        fixture("unix-stream-fresh", fd);
        close(fd);
    }
    {
        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        need(fd >= 0, "socket(AF_UNIX, SOCK_DGRAM, 0)");
        fixture("unix-dgram-fresh", fd);
        close(fd);
    }
    {
        // Darwin has no Unix-domain SOCK_SEQPACKET.
        int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
        if (fd < 0) {
            printf("# unix-seqpacket-fresh: socket -> %s\n", en(errno));
        } else {
            fixture("unix-seqpacket-fresh", fd);
            close(fd);
        }
    }
    {
        int sv[2];
        need(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
        fixture("unix-socketpair", sv[0]);
        close(sv[0]);
        close(sv[1]);
    }
    return 0;
}
