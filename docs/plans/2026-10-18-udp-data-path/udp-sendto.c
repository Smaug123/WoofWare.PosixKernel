// What sendto(2) and recvfrom(2) answer when several of their arguments, or
// the socket's state, would each fail the call: which answer wins, and what
// each leaves behind. `udp-transfer.c` sections N and O varied one argument
// at a time; this probe crosses them. Plan: docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   Darwin: cc -Wall -O0 -o /tmp/us udp-sendto.c && /tmp/us
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c
//             'gcc -Wall -O0 -o /tmp/us /probe/udp-sendto.c && /tmp/us'
//
// Every row starts from fresh sockets, so no row's answer depends on another's.
// Each line is `<section> <key>=<value>...: <key>=<value>...`, the inputs
// before the colon and what was seen after it, for a test to parse.
//
// Sections:
//   Z1  sendto: the sender's state, its buffer, the count, the flags and the
//       destination, crossed. Seen: the answer; the sender's own address
//       afterwards, with any port it holds as `*`; what the receiver holds;
//       and SO_ERROR at the sender afterwards, which takes the error.
//   Z2  recvfrom: what the receiver holds, the length cell, the address
//       buffer, the data buffer, the count and the flags, crossed. Seen: the
//       answer; the bytes given (`data`), the address buffer's first 20 bytes
//       with the sender's port as `pppp` (`addr`), and the length cell
//       (`len`), where each is mapped; then SO_ERROR, which takes the error,
//       and how many datagrams are left.
//   Z3  (the charge Darwin gives a datagram) whether a send that only takes a
//       pending error marks a Darwin socket as having sent: the error comes
//       from another socket's sendto, the socket never sends a datagram, and
//       FIONREAD reads what a later datagram of 10 bytes cost it once an
//       AF_UNSPEC connect has disconnected it. 26 is the cheaper charge of a
//       socket that never sent, 42 the full one. On Linux the AF_UNSPEC
//       connect gives back the port bind(2) did not lock, so the later
//       datagram reaches no one: the section asks nothing of Linux.
//   Z4  (Darwin, as Z3) whether each sendto of Z1 that fails marks a socket
//       that has neither sent nor received as having sent: FIONREAD after a
//       datagram of 10 bytes, 26 unmarked and 42 marked.
//   Z5  whether recvfrom reads a length cell before it looks the descriptor
//       up: an unmapped cell through a closed descriptor, a pipe, and an
//       empty UDP socket, with the address NULL and not.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// An address nothing maps, hidden from the compiler's own checks.
static void *volatile unmapped = (void *)1;

static const char *ename(int e)
{
    switch (e) {
    case EAGAIN: return "EAGAIN";
    case EMSGSIZE: return "EMSGSIZE";
    case EDESTADDRREQ: return "EDESTADDRREQ";
    case EISCONN: return "EISCONN";
    case EINVAL: return "EINVAL";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EACCES: return "EACCES";
    case ENETUNREACH: return "ENETUNREACH";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EFAULT: return "EFAULT";
    case ENOTCONN: return "ENOTCONN";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EPIPE: return "EPIPE";
    case EBADF: return "EBADF";
    case ENOTSOCK: return "ENOTSOCK";
    case 0: return "0";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static const char *res(ssize_t r, int e)
{
    static char bufs[8][48];
    static int next = 0;
    char *b = bufs[next++ % 8];
    if (r < 0) snprintf(b, 48, "-1 %s", ename(e));
    else snprintf(b, 48, "%zd", r);
    return b;
}

static struct sockaddr_in at(uint32_t host, uint16_t port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
#ifdef __APPLE__
    a.sin_len = sizeof a;
#endif
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(host);
    a.sin_port = htons(port);
    return a;
}

static int udp(void) { return socket(AF_INET, SOCK_DGRAM, 0); }

static int bound_to(uint32_t host)
{
    int s = udp();
    struct sockaddr_in a = at(host, 0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    return s;
}

static uint16_t portof(int s)
{
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) return 0;
    return ntohs(a.sin_port);
}

// The socket's own address, with a port it holds as `*`.
static const char *self(int s)
{
    static char b[64];
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    memset(&a, 0, sizeof a);
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) snprintf(b, sizeof b, "getsockname-%s", ename(errno));
    else snprintf(b, sizeof b, "%s:%s", inet_ntoa(a.sin_addr), a.sin_port == 0 ? "0" : "*");
    return b;
}

static uint16_t unheld_port(void)
{
    int s = bound_to(INADDR_LOOPBACK);
    uint16_t p = portof(s);
    close(s);
    return p;
}

static int sock_error(int s)
{
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &len) != 0) return -errno;
    return v;
}

static void nonblocking(int s) { fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK); }

// Whether `s` shows the pending error within `ms`: Linux by POLLERR, Darwin by
// POLLIN with nothing queued.
static int error_shown(int s, int ms)
{
    struct pollfd p = { s, POLLIN, 0 };
    poll(&p, 1, ms);
#ifdef __APPLE__
    return (p.revents & POLLIN) != 0;
#else
    return (p.revents & POLLERR) != 0;
#endif
}

// Waits up to `ms` for a datagram at `s`.
static void await_datagram(int s, int ms)
{
    struct pollfd p = { s, POLLIN, 0 };
    poll(&p, 1, ms);
}

// The datagrams `s` holds, taken: their count and lengths, as `n` or
// `n:len,len`.
static const char *drain(int s)
{
    static char b[128];
    char lens[96] = "";
    static char buf[70000];
    int n = 0;
    for (;;) {
        ssize_t r = recv(s, buf, sizeof buf, MSG_DONTWAIT);
        if (r < 0) break;
        if (n < 8) {
            char one[32];
            snprintf(one, sizeof one, "%s%zd", n ? "," : "", r);
            strncat(lens, one, sizeof lens - strlen(lens) - 1);
        }
        n++;
    }
    if (n) snprintf(b, sizeof b, "%d:%s", n, lens);
    else snprintf(b, sizeof b, "0");
    return b;
}

static char payload[70000];

// ---------------------------------------------------------------- Z1

static const char *states[] = { "fresh", "wildcard", "loopback", "connected", "erred", "erred-dissolved" };
static const size_t counts[] = { 1, 0, 9217, 65508, 70000 };
static const char *dests[] = { "null", "good", "len0", "len1", "len8", "len17", "len129", "len300", "unmapped", "inet6", "family99",
                               "unspec", "port0", "any", "broadcast", "alias", "unheld" };

#define NSTATES (sizeof states / sizeof *states)
#define NCOUNTS (sizeof counts / sizeof *counts)
#define NDESTS (sizeof dests / sizeof *dests)

// A sender in `state`, beside a receiver at `rport`: connected to it, or
// erred by its own send to the unheld port `eport`.
static int sender(const char *state, uint16_t rport, uint16_t eport)
{
    if (!strcmp(state, "fresh")) return udp();
    if (!strcmp(state, "wildcard")) return bound_to(INADDR_ANY);
    if (!strcmp(state, "loopback")) return bound_to(INADDR_LOOPBACK);
    if (!strcmp(state, "connected")) {
        int s = udp();
        struct sockaddr_in to = at(INADDR_LOOPBACK, rport);
        if (connect(s, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); exit(1); }
        return s;
    }
    int s = udp();
    struct sockaddr_in to = at(INADDR_LOOPBACK, eport);
    if (connect(s, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); exit(1); }
    if (send(s, "x", 1, 0) != 1) { perror("send"); exit(1); }
    if (!error_shown(s, 200)) { fprintf(stderr, "no error pending\n"); exit(1); }
    if (!strcmp(state, "erred-dissolved")) {
        struct sockaddr_in unspec;
        memset(&unspec, 0, sizeof unspec);
#ifdef __APPLE__
        unspec.sin_len = sizeof unspec;
#endif
        unspec.sin_family = AF_UNSPEC;
        connect(s, (struct sockaddr *)&unspec, sizeof unspec);
        if (!error_shown(s, 0)) { fprintf(stderr, "no error pending after AF_UNSPEC\n"); exit(1); }
    }
    return s;
}

// The destination argument `dest` names, towards the receiver at `rport` or
// the unheld port `uport`: its address in `*to`, and its length.
static socklen_t destination(const char *dest, uint16_t rport, uint16_t uport, const void **to)
{
    static unsigned char addr[512];
    memset(addr, 0, sizeof addr);
    struct sockaddr_in good = at(INADDR_LOOPBACK, rport);
    *to = addr;
    socklen_t len = sizeof good;
    struct sockaddr_in a = good;

    if (!strcmp(dest, "len0")) len = 0;
    else if (!strcmp(dest, "len1")) len = 1;
    else if (!strcmp(dest, "len8")) len = 8;
    else if (!strcmp(dest, "len17")) len = 17;
    else if (!strcmp(dest, "len129")) len = 129;
    else if (!strcmp(dest, "len300")) len = 300;
    else if (!strcmp(dest, "inet6")) a.sin_family = AF_INET6;
    else if (!strcmp(dest, "family99")) a.sin_family = 99;
    else if (!strcmp(dest, "unspec")) a.sin_family = AF_UNSPEC;
    else if (!strcmp(dest, "port0")) a.sin_port = 0;
    else if (!strcmp(dest, "any")) a.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (!strcmp(dest, "broadcast")) a.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    else if (!strcmp(dest, "alias")) a.sin_addr.s_addr = htonl(0x7f000002);
    else if (!strcmp(dest, "unheld")) a.sin_port = htons(uport);
    memcpy(addr, &a, sizeof a);
    if (!strcmp(dest, "null")) *to = NULL;
    else if (!strcmp(dest, "unmapped")) *to = unmapped;
    return len;
}

static void z1_row(const char *state, int mapped, size_t count, int flags, const char *dest)
{
    int r = bound_to(INADDR_LOOPBACK);
    nonblocking(r);
    uint16_t rport = portof(r);
    // The port the erred sender's own send went to, and another nobody
    // holds, for the row's own send: so that Darwin's record of the last
    // datagram answered with the error never covers the row's.
    uint16_t eport = unheld_port();
    uint16_t uport = unheld_port();
    int s = sender(state, rport, eport);
    const void *to;
    socklen_t len = destination(dest, rport, uport, &to);

    const void *buf = mapped ? (const void *)payload : unmapped;
    ssize_t got = sendto(s, buf, count, flags, (const struct sockaddr *)to, len);
    int e = errno;

    await_datagram(r, 30);
    const char *after = self(s);
    printf("Z1 state=%s buffer=%s count=%zu flags=%s dest=%s: answer=%s self=%s received=%s error=%d\n", state,
           mapped ? "mapped" : "unmapped", count, flags ? "oob" : "0", dest, res(got, e), after, drain(r), sock_error(s));
    close(s);
    close(r);
}

static void z1(void)
{
    for (size_t st = 0; st < NSTATES; st++)
        for (int mapped = 1; mapped >= 0; mapped--)
            for (size_t c = 0; c < NCOUNTS; c++)
                for (int oob = 0; oob <= 1; oob++)
                    for (size_t d = 0; d < NDESTS; d++)
                        z1_row(states[st], mapped, counts[c], oob ? MSG_OOB : 0, dests[d]);
}

// ---------------------------------------------------------------- Z2

static const char *queues[] = { "empty", "abc", "zero", "erred" };
static const char *cells[] = { "null", "unmapped", "0", "1", "16", "ffffffff" };
static const char *addrs[] = { "null", "mapped", "unmapped" };
static const size_t rcounts[] = { 0, 2, 10 };
static const int rflags[] = { 0, MSG_PEEK, MSG_TRUNC, MSG_PEEK | MSG_TRUNC };
static const char *rflagnames[] = { "0", "peek", "trunc", "peek+trunc" };

#define NQUEUES (sizeof queues / sizeof *queues)
#define NCELLS (sizeof cells / sizeof *cells)
#define NADDRS (sizeof addrs / sizeof *addrs)
#define NRCOUNTS (sizeof rcounts / sizeof *rcounts)
#define NRFLAGS (sizeof rflags / sizeof *rflags)

static void hex(char *out, size_t outlen, const unsigned char *bytes, size_t n, uint16_t port)
{
    out[0] = 0;
    unsigned char hi = (unsigned char)(port >> 8), lo = (unsigned char)port;
    for (size_t i = 0; i < n; i++) {
        // The port's two bytes, network order, at bytes 2 and 3 of a
        // `struct sockaddr_in`.
        if (i == 2 && n > 3 && bytes[2] == hi && bytes[3] == lo) {
            strncat(out, "pppp", outlen - strlen(out) - 1);
            i++;
            continue;
        }
        char two[3];
        snprintf(two, sizeof two, "%02x", bytes[i]);
        strncat(out, two, outlen - strlen(out) - 1);
    }
}

static void z2_row(const char *queue, const char *cell, const char *addrkind, int mapped, size_t count, int flagi)
{
    int r = bound_to(INADDR_LOOPBACK);
    nonblocking(r);
    int t = bound_to(INADDR_LOOPBACK);
    struct sockaddr_in to = at(INADDR_LOOPBACK, portof(r));

    if (!strcmp(queue, "abc")) {
        sendto(t, "abc", 3, 0, (struct sockaddr *)&to, sizeof to);
        await_datagram(r, 200);
    } else if (!strcmp(queue, "zero")) {
        sendto(t, "", 0, 0, (struct sockaddr *)&to, sizeof to);
        await_datagram(r, 200);
    } else if (!strcmp(queue, "erred")) {
        struct sockaddr_in u = at(INADDR_LOOPBACK, unheld_port());
        if (connect(r, (struct sockaddr *)&u, sizeof u) != 0) { perror("connect"); exit(1); }
        if (send(r, "x", 1, 0) != 1) { perror("send"); exit(1); }
        if (!error_shown(r, 200)) { fprintf(stderr, "no error pending\n"); exit(1); }
    }

    static unsigned char data[16];
    static unsigned char addr[32];
    socklen_t length = 0;
    memset(data, 0xbb, sizeof data);
    memset(addr, 0xaa, sizeof addr);

    socklen_t *lenp = &length;
    if (!strcmp(cell, "null")) lenp = NULL;
    else if (!strcmp(cell, "unmapped")) lenp = unmapped;
    else if (!strcmp(cell, "ffffffff")) length = 0xffffffffu;
    else length = (socklen_t)strtoul(cell, NULL, 10);

    void *addrp = !strcmp(addrkind, "null") ? NULL : !strcmp(addrkind, "mapped") ? (void *)addr : unmapped;
    void *bufp = mapped ? (void *)data : unmapped;

    ssize_t got = recvfrom(r, bufp, count, rflags[flagi], (struct sockaddr *)addrp, lenp);
    int e = errno;

    char datahex[64] = "-", addrhex[64] = "-", lenout[16] = "-";
    if (mapped) {
        size_t shown = got > 0 ? (size_t)got : 0;
        if (shown > count) shown = count;
        if (shown > sizeof data) shown = sizeof data;
        // What the call wrote, and the first byte past it, to show it wrote no
        // further.
        hex(datahex, sizeof datahex, data, shown + (shown < sizeof data ? 1 : 0), 0);
    }
    if (!strcmp(addrkind, "mapped")) hex(addrhex, sizeof addrhex, addr, 20, portof(t));
    if (lenp == &length) snprintf(lenout, sizeof lenout, "%u", (unsigned)length);

    int error = sock_error(r);
    printf("Z2 queue=%s cell=%s address=%s buffer=%s count=%zu flags=%s: answer=%s data=%s addr=%s len=%s error=%d "
           "left=%s\n",
           queue, cell, addrkind, mapped ? "mapped" : "unmapped", count, rflagnames[flagi], res(got, e), datahex,
           addrhex, lenout, error, drain(r));
    close(t);
    close(r);
}

static void z2(void)
{
    for (size_t q = 0; q < NQUEUES; q++)
        for (size_t c = 0; c < NCELLS; c++)
            for (size_t a = 0; a < NADDRS; a++)
                for (int mapped = 1; mapped >= 0; mapped--)
                    for (size_t n = 0; n < NRCOUNTS; n++)
                        for (size_t f = 0; f < NRFLAGS; f++)
                            z2_row(queues[q], cells[c], addrs[a], mapped, rcounts[n], (int)f);
}

// ---------------------------------------------------------------- Z3

// `variant`: what the socket does with the error another socket's sendto
// left pending at it: `send` takes it by a send, `so_error` by SO_ERROR,
// `keep` leaves it, and `none` is a socket no error reached.
static void z3_row(const char *variant)
{
    int one = 1;
    int a = udp();
    setsockopt(a, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in self_addr = at(INADDR_LOOPBACK, 0);
    if (bind(a, (struct sockaddr *)&self_addr, sizeof self_addr) != 0) { perror("bind a"); exit(1); }
    struct sockaddr_in u = at(INADDR_LOOPBACK, unheld_port());
    if (connect(a, (struct sockaddr *)&u, sizeof u) != 0) { perror("connect a"); exit(1); }

    char seen[160] = "";
    if (strcmp(variant, "none")) {
        int b = udp();
        setsockopt(b, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in shared = at(INADDR_LOOPBACK, portof(a));
        if (bind(b, (struct sockaddr *)&shared, sizeof shared) != 0) { perror("bind b"); exit(1); }
        ssize_t sent = sendto(b, "x", 1, 0, (struct sockaddr *)&u, sizeof u);
        int es = errno;
        int shown = error_shown(a, 200);
        snprintf(seen, sizeof seen, " b-sendto=%s a-shows-error=%d b-error=%d", res(sent, es), shown, sock_error(b));
        close(b);
    }

    if (!strcmp(variant, "send")) {
        ssize_t got = send(a, "y", 1, 0);
        int e = errno;
        char more[48];
        snprintf(more, sizeof more, " a-send=%s", res(got, e));
        strncat(seen, more, sizeof seen - strlen(seen) - 1);
    } else if (!strcmp(variant, "so_error")) {
        char more[48];
        snprintf(more, sizeof more, " a-error=%d", sock_error(a));
        strncat(seen, more, sizeof seen - strlen(seen) - 1);
    }

    struct sockaddr_in unspec;
    memset(&unspec, 0, sizeof unspec);
#ifdef __APPLE__
    unspec.sin_len = sizeof unspec;
#endif
    unspec.sin_family = AF_UNSPEC;
    int c = connect(a, (struct sockaddr *)&unspec, sizeof unspec);
    int ec = errno;

    int t = bound_to(INADDR_LOOPBACK);
    struct sockaddr_in to = at(INADDR_LOOPBACK, portof(a));
    sendto(t, "0123456789", 10, 0, (struct sockaddr *)&to, sizeof to);
    // A fixed wait, not a poll: a pending error makes Darwin's socket
    // readable before the datagram arrives.
    usleep(50000);
    int available = -1;
    ioctl(a, FIONREAD, &available);
    printf("Z3 variant=%s:%s unspec=%s fionread=%d error=%d left=%s\n", variant, seen, res(c, ec), available,
           sock_error(a), drain(a));
    close(t);
    close(a);
}

static void z3(void)
{
    const char *variants[] = { "none", "keep", "so_error", "send" };
    for (int round = 0; round < 3; round++)
        for (size_t v = 0; v < sizeof variants / sizeof *variants; v++) z3_row(variants[v]);
}

// ---------------------------------------------------------------- Z4

// Whether a sendto from a fresh socket bound to 127.0.0.1, which has neither
// sent nor received, marks it as having sent on Darwin, by what a datagram
// of 10 bytes then costs it: 26 unmarked, 42 marked. `call` is `none`, or the
// destination of a sendto of 1 byte from a mapped buffer, `fault` one from
// an unmapped buffer, `large` one of 9217 bytes, or `oob` one with MSG_OOB.
static void z4_row(const char *call, const char *dest)
{
    int r = bound_to(INADDR_LOOPBACK);
    nonblocking(r);
    int s = bound_to(INADDR_LOOPBACK);
    const char *answer = "-";
    if (strcmp(call, "none")) {
        const void *to;
        socklen_t len = destination(dest, portof(r), unheld_port(), &to);
        const void *buf = strcmp(call, "fault") ? (const void *)payload : unmapped;
        size_t count = strcmp(call, "large") ? 1 : 9217;
        int flags = strcmp(call, "oob") ? 0 : MSG_OOB;
        ssize_t got = sendto(s, buf, count, flags, (const struct sockaddr *)to, len);
        answer = res(got, errno);
    }
    int t = bound_to(INADDR_LOOPBACK);
    struct sockaddr_in to = at(INADDR_LOOPBACK, portof(s));
    sendto(t, "0123456789", 10, 0, (struct sockaddr *)&to, sizeof to);
    usleep(30000);
    int available = -1;
    ioctl(s, FIONREAD, &available);
    printf("Z4 call=%s dest=%s: answer=%s fionread=%d\n", call, strcmp(call, "none") ? dest : "-", answer, available);
    close(t);
    close(s);
    close(r);
}

static void z4(void)
{
    const char *calls[] = { "sent", "fault", "large", "oob" };
    z4_row("none", "-");
    for (size_t c = 0; c < sizeof calls / sizeof *calls; c++)
        for (size_t d = 0; d < NDESTS; d++) z4_row(calls[c], dests[d]);
}

// ---------------------------------------------------------------- Z5

static void z5(void)
{
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(1); }
    int empty = bound_to(INADDR_LOOPBACK);
    nonblocking(empty);
    int closed = udp();
    close(closed);
    struct { const char *name; int fd; } targets[] = { { "closed", closed }, { "pipe", fds[0] }, { "empty", empty } };
    static unsigned char addr[32];
    char data[4];
    for (size_t i = 0; i < sizeof targets / sizeof *targets; i++)
        for (int null_address = 0; null_address <= 1; null_address++) {
            ssize_t got = recvfrom(targets[i].fd, data, sizeof data, MSG_DONTWAIT,
                                   null_address ? NULL : (struct sockaddr *)addr, unmapped);
            int e = errno;
            printf("Z5 fd=%s address=%s cell=unmapped: answer=%s\n", targets[i].name, null_address ? "null" : "mapped",
                   res(got, e));
        }
    close(fds[0]);
    close(fds[1]);
    close(empty);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'd', sizeof payload);
    z1();
    z2();
    z3();
    z4();
    z5();
    return 0;
}
