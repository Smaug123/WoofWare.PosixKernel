// What sendmsg(2) and recvmsg(2) answer when their arguments, or the socket's
// state, would each fail the call: which answer wins, and what each call
// leaves behind and writes back. Design note:
// docs/plans/2026-10-22-sendmsg-recvmsg.md, section 3; plan:
// docs/plans/2026-10-18-udp-data-path.md, section 2.12.
//
// Build and run:
//   Darwin: cc -Wall -O0 -o /tmp/um udp-msg.c -lpthread && /tmp/um
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c
//             'gcc -Wall -O0 -o /tmp/um /probe/udp-msg.c -lpthread && /tmp/um'
//
// Every row starts from fresh sockets, so no row's answer depends on another's.
// Each line is `<section> <key>=<value>...: <key>=<value>...`, the inputs
// before the colon and what was seen after it, for a test to parse.
//
// A call's arguments are dimensions, each with a default that leaves the call
// succeeding. Y1 and Y2 run, for each socket state, the call with every
// argument at its default, then with each one argument changed, then with
// each two of different dimensions changed: enough to place every rung of a
// ladder against every other. The header's own dimension (a header that
// faults, or is read-only) is changed alone, since a header that faults
// leaves nothing else read.
//
// Sections:
//   Y1  sendmsg: the sender's state; the header; msg_iovlen; the iovec
//       array; the iovecs; the name; the control buffer; the flags. Seen: the
//       answer; the sender's own address afterwards, with any port it holds
//       as `*`; what the receiver holds; and SO_ERROR at the sender
//       afterwards, which takes the error.
//   Y2  recvmsg: what the receiver holds; the header; msg_iovlen; the iovec
//       array; the iovecs; the name and msg_namelen; the control buffer; the
//       flags. Seen: the answer; the first 12 bytes of each of the two iovec
//       buffers (0xbb where nothing was written); the name buffer's first 20
//       bytes, with the sender's port as `pppp` (0xaa where nothing was
//       written); msg_namelen, msg_controllen and msg_flags as the header
//       holds them afterwards (msg_flags goes in as 0x7fffffff); the control
//       buffer's first 8 bytes (0xcc where nothing was written); SO_ERROR,
//       which takes the error; and the datagrams left.
//   Y3  a blocking recvmsg on an empty socket, for each argument that faults
//       or is out of range, with nothing arriving or a datagram arriving 60 ms
//       in, under SO_RCVTIMEO of 300 ms: whether it slept (returned 40 ms or
//       more after it was made), its answer, and what is left.
//   Y4  whether each call reads its header before it looks the descriptor
//       up: a header, an iovec array or a name that faults, an iovec count
//       of 1025, an iovec whose length is negative as a `ssize_t`, and a
//       msg_namelen of 0xffffffff, through a closed descriptor, a pipe's read
//       end and an empty UDP socket.
//   Y5  (Darwin, as `udp-sendto.c` Z4) whether each sendmsg of Y1, with one
//       argument changed, from a socket bound to 127.0.0.1 that has neither
//       sent nor received, marks it as having sent: FIONREAD after a later
//       datagram of 10 bytes, 26 unmarked and 42 marked. On Linux the column
//       is the datagram's own length.
//   Y6  the longest iovec each call lets through: one iovec of each length,
//       from a mapped buffer (the call fails before it copies so much), to a
//       sendmsg with a good name from a socket bound to 127.0.0.1 and a
//       recvmsg on an empty socket, non-blocking. Then the same total split
//       over two iovecs of half the length each.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
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
    case ENOBUFS: return "ENOBUFS";
    case ENOMEM: return "ENOMEM";
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

static void await_datagram(int s, int ms)
{
    struct pollfd p = { s, POLLIN, 0 };
    poll(&p, 1, ms);
}

// `s` connected to a port nobody holds, with the ICMP error its send there
// raised pending.
static void err(int s)
{
    struct sockaddr_in u = at(INADDR_LOOPBACK, unheld_port());
    if (connect(s, (struct sockaddr *)&u, sizeof u) != 0) { perror("connect"); exit(1); }
    if (send(s, "x", 1, 0) != 1) { perror("send"); exit(1); }
    if (!error_shown(s, 200)) { fprintf(stderr, "no error pending\n"); exit(1); }
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

static void hex(char *out, size_t outlen, const unsigned char *bytes, size_t n, uint16_t port)
{
    out[0] = 0;
    unsigned char hi = (unsigned char)(port >> 8), lo = (unsigned char)port;
    for (size_t i = 0; i < n; i++) {
        // The port's two bytes, network order, at bytes 2 and 3 of a
        // `struct sockaddr_in`, where an address was written: not over the
        // 0xaa an unwritten name buffer holds, which a port of 0xaaaa would
        // match.
        if (port != 0 && i == 2 && n > 3 && bytes[0] != 0xaa && bytes[2] == hi && bytes[3] == lo) {
            strncat(out, "pppp", outlen - strlen(out) - 1);
            i++;
            continue;
        }
        char two[3];
        snprintf(two, sizeof two, "%02x", bytes[i]);
        strncat(out, two, outlen - strlen(out) - 1);
    }
}

// A page holding a copy of `m`, made read-only.
static struct msghdr *readonly_copy(const struct msghdr *m)
{
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); exit(1); }
    memcpy(page, m, sizeof *m);
    if (mprotect(page, 4096, PROT_READ) != 0) { perror("mprotect"); exit(1); }
    return page;
}

// ---------------------------------------------------------------- the crossing

#define MAXDIMS 8

struct dim {
    const char *name;
    int count;
    const char *const *values;
};

// Calls `row` with the default of every dimension, then with each one, then
// each two of different dimensions, changed. Dimension 0 is the header,
// changed alone. `defaults[d]` is dimension d's default value.
// `cross`'s first two steps alone: every default, then each one dimension
// changed.
static void singles(const struct dim *dims, int ndims, const int *defaults, void (*row)(const int *choice, void *), void *ctx)
{
    int choice[MAXDIMS];
    memcpy(choice, defaults, sizeof(int) * (size_t)ndims);
    row(choice, ctx);
    for (int d = 0; d < ndims; d++)
        for (int v = 0; v < dims[d].count; v++) {
            if (v == defaults[d]) continue;
            memcpy(choice, defaults, sizeof(int) * (size_t)ndims);
            choice[d] = v;
            row(choice, ctx);
        }
}

static void cross(const struct dim *dims, int ndims, const int *defaults, void (*row)(const int *choice, void *), void *ctx)
{
    int choice[MAXDIMS];
    memcpy(choice, defaults, sizeof(int) * (size_t)ndims);
    row(choice, ctx);
    for (int v = 0; v < dims[0].count; v++) {
        if (v == defaults[0]) continue;
        memcpy(choice, defaults, sizeof(int) * (size_t)ndims);
        choice[0] = v;
        row(choice, ctx);
    }
    for (int d = 1; d < ndims; d++)
        for (int v = 0; v < dims[d].count; v++) {
            if (v == defaults[d]) continue;
            memcpy(choice, defaults, sizeof(int) * (size_t)ndims);
            choice[d] = v;
            row(choice, ctx);
        }
    for (int d = 1; d < ndims; d++)
        for (int e = d + 1; e < ndims; e++)
            for (int v = 0; v < dims[d].count; v++) {
                if (v == defaults[d]) continue;
                for (int w = 0; w < dims[e].count; w++) {
                    if (w == defaults[e]) continue;
                    memcpy(choice, defaults, sizeof(int) * (size_t)ndims);
                    choice[d] = v;
                    choice[e] = w;
                    row(choice, ctx);
                }
            }
}

static int is(const struct dim *dims, const int *choice, int d, const char *value)
{
    return !strcmp(dims[d].values[choice[d]], value);
}

static int index_of(const struct dim *d, const char *value)
{
    for (int i = 0; i < d->count; i++)
        if (!strcmp(d->values[i], value)) return i;
    fprintf(stderr, "no value %s in %s\n", value, d->name);
    exit(1);
}

// The row's inputs, `<section> <key>=<value>` first, then each dimension's.
static void print_inputs(const char *section, const char *key, const char *value, const struct dim *dims, int ndims,
                         const int *choice)
{
    printf("%s %s=%s", section, key, value);
    for (int d = 0; d < ndims; d++) printf(" %s=%s", dims[d].name, dims[d].values[choice[d]]);
    printf(":");
}

static char payload[70000];
static struct iovec iovs[2000];

// The iovec count each name of the count dimension means.
static void set_iovlen(struct msghdr *m, const char *count)
{
    if (!strcmp(count, "neg")) m->msg_iovlen = (__typeof__(m->msg_iovlen))-1;
    else m->msg_iovlen = (__typeof__(m->msg_iovlen))strtoul(count, NULL, 10);
}

// ---------------------------------------------------------------- Y1

static const char *const y1_headers[] = { "mapped", "unmapped", "readonly" };
static const char *const y1_counts[] = { "2", "0", "1", "1024", "1025", "neg" };
static const char *const y1_arrays[] = { "mapped", "unmapped" };
static const char *const y1_iovecs[] = { "good", "base0", "base1", "neg0", "huge", "big", "empty" };
static const char *const y1_names[] = { "good", "null", "nulllen16", "len0", "len8", "len129", "unmapped", "family99", "port0" };
static const char *const y1_controls[] = { "none", "nulllen16", "unmapped16", "zero8", "zero16", "big" };
static const char *const y1_flags[] = { "0", "oob" };

static const struct dim y1_dims[] = {
    { "header", 3, y1_headers },   { "iovlen", 6, y1_counts },     { "array", 2, y1_arrays },
    { "iov", 7, y1_iovecs },       { "name", 9, y1_names },        { "control", 6, y1_controls },
    { "flags", 2, y1_flags },
};
#define Y1DIMS 7

// Y1's state, and whether the row is Y5's, which reads the charge a later
// datagram costs the sender.
struct y1_ctx {
    const char *state;
    int charge;
};

static void y1_row(const int *choice, void *ctx_)
{
    const struct y1_ctx *ctx = ctx_;
    const char *state = ctx->state;
    const struct dim *dims = y1_dims;

    int r = bound_to(INADDR_LOOPBACK);
    nonblocking(r);
    uint16_t rport = portof(r);
    int s;
    if (!strcmp(state, "fresh")) s = udp();
    else if (!strcmp(state, "loopback")) s = bound_to(INADDR_LOOPBACK);
    else if (!strcmp(state, "connected")) {
        s = udp();
        struct sockaddr_in to = at(INADDR_LOOPBACK, rport);
        if (connect(s, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); exit(1); }
    } else {
        s = udp();
        err(s);
    }

    memset(iovs, 0, sizeof iovs);
    iovs[0].iov_base = payload;
    iovs[0].iov_len = 2;
    iovs[1].iov_base = payload + 2;
    iovs[1].iov_len = 1;
    if (is(dims, choice, 3, "base0")) iovs[0].iov_base = unmapped;
    else if (is(dims, choice, 3, "base1")) iovs[1].iov_base = unmapped;
    else if (is(dims, choice, 3, "neg0")) iovs[0].iov_len = (size_t)1 << (sizeof(size_t) * 8 - 1);
    else if (is(dims, choice, 3, "huge")) iovs[0].iov_len = iovs[1].iov_len = SIZE_MAX >> 1;
    else if (is(dims, choice, 3, "big")) {
        iovs[0].iov_len = 35000;
        iovs[1].iov_base = payload + 35000;
        iovs[1].iov_len = 35000;
    } else if (is(dims, choice, 3, "empty")) iovs[0].iov_len = iovs[1].iov_len = 0;

    static unsigned char name[512];
    memset(name, 0, sizeof name);
    struct sockaddr_in good = at(INADDR_LOOPBACK, rport);
    socklen_t namelen = sizeof good;
    void *namep = name;
    if (is(dims, choice, 4, "null")) { namep = NULL; namelen = 0; }
    else if (is(dims, choice, 4, "nulllen16")) namep = NULL;
    else if (is(dims, choice, 4, "len0")) namelen = 0;
    else if (is(dims, choice, 4, "len8")) namelen = 8;
    else if (is(dims, choice, 4, "len129")) namelen = 129;
    else if (is(dims, choice, 4, "unmapped")) namep = unmapped;
    else if (is(dims, choice, 4, "family99")) good.sin_family = 99;
    else if (is(dims, choice, 4, "port0")) good.sin_port = 0;
    memcpy(name, &good, sizeof good);

    static unsigned char control[64];
    memset(control, 0, sizeof control);
    void *controlp = NULL;
    size_t controllen = 0;
    if (is(dims, choice, 5, "nulllen16")) controllen = 16;
    else if (is(dims, choice, 5, "unmapped16")) { controlp = unmapped; controllen = 16; }
    else if (is(dims, choice, 5, "zero8")) { controlp = control; controllen = 8; }
    else if (is(dims, choice, 5, "zero16")) { controlp = control; controllen = 16; }
    else if (is(dims, choice, 5, "big")) { controlp = control; controllen = 0x80000000u; }

    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_name = namep;
    m.msg_namelen = namelen;
    m.msg_iov = is(dims, choice, 2, "unmapped") ? unmapped : iovs;
    set_iovlen(&m, dims[1].values[choice[1]]);
    m.msg_control = controlp;
    m.msg_controllen = (__typeof__(m.msg_controllen))controllen;
    m.msg_flags = 0x7fffffff;

    const struct msghdr *mp = &m;
    if (is(dims, choice, 0, "unmapped")) mp = unmapped;
    else if (is(dims, choice, 0, "readonly")) mp = readonly_copy(&m);

    ssize_t got = sendmsg(s, mp, is(dims, choice, 6, "oob") ? MSG_OOB : 0);
    int e = errno;
    if (is(dims, choice, 0, "readonly")) munmap((void *)mp, 4096);

    await_datagram(r, 30);
    if (ctx->charge) {
        int t = bound_to(INADDR_LOOPBACK);
        struct sockaddr_in back = at(INADDR_LOOPBACK, portof(s));
        sendto(t, "0123456789", 10, 0, (struct sockaddr *)&back, sizeof back);
        usleep(30000);
        int available = -1;
        ioctl(s, FIONREAD, &available);
        print_inputs("Y5", "state", state, dims, Y1DIMS, choice);
        printf(" answer=%s fionread=%d\n", res(got, e), available);
        close(t);
    } else {
        const char *after = self(s);
        print_inputs("Y1", "state", state, dims, Y1DIMS, choice);
        printf(" answer=%s self=%s received=%s error=%d\n", res(got, e), after, drain(r), sock_error(s));
    }
    close(s);
    close(r);
}

static void section_y1(void)
{
    const char *states[] = { "fresh", "loopback", "connected", "erred" };
    for (size_t st = 0; st < sizeof states / sizeof *states; st++) {
        int connected = !strcmp(states[st], "connected") || !strcmp(states[st], "erred");
        int defaults[Y1DIMS] = { 0, 0, 0, 0, index_of(&y1_dims[4], connected ? "null" : "good"), 0, 0 };
        struct y1_ctx ctx = { states[st], 0 };
        cross(y1_dims, Y1DIMS, defaults, y1_row, &ctx);
    }
}

// ---------------------------------------------------------------- Y5

static void section_y5(void)
{
    int defaults[Y1DIMS] = { 0, 0, 0, 0, 0, 0, 0 };
    struct y1_ctx ctx = { "loopback", 1 };
    singles(y1_dims, Y1DIMS, defaults, y1_row, &ctx);
}

// ---------------------------------------------------------------- Y2

static const char *const y2_headers[] = { "mapped", "unmapped", "readonly" };
static const char *const y2_counts[] = { "2", "0", "1", "1024", "1025", "neg" };
static const char *const y2_arrays[] = { "mapped", "unmapped" };
static const char *const y2_iovecs[] = { "good", "base0", "base1", "neg0", "huge", "zeros" };
static const char *const y2_names[] = { "mapped16", "null", "nulllen16", "unmapped", "len0", "len8", "len7fffffff", "lenffffffff" };
static const char *const y2_controls[] = { "none", "mapped8", "mapped64", "unmapped64", "nulllen64" };
static const char *const y2_flags[] = { "0", "peek", "trunc", "oob" };

static const struct dim y2_dims[] = {
    { "header", 3, y2_headers }, { "iovlen", 6, y2_counts },    { "array", 2, y2_arrays },
    { "iov", 6, y2_iovecs },     { "name", 8, y2_names },       { "control", 5, y2_controls },
    { "flags", 4, y2_flags },
};
#define Y2DIMS 7

static void y2_row(const int *choice, void *ctx)
{
    const char *queue = ctx;
    const struct dim *dims = y2_dims;

    int r = bound_to(INADDR_LOOPBACK);
    nonblocking(r);
    int t = bound_to(INADDR_LOOPBACK);
    struct sockaddr_in to = at(INADDR_LOOPBACK, portof(r));
    if (!strcmp(queue, "ten")) {
        sendto(t, "abcdefghij", 10, 0, (struct sockaddr *)&to, sizeof to);
        await_datagram(r, 200);
    } else if (!strcmp(queue, "zero")) {
        sendto(t, "", 0, 0, (struct sockaddr *)&to, sizeof to);
        await_datagram(r, 200);
    } else if (!strcmp(queue, "erred")) err(r);

    static unsigned char buf0[16], buf1[16];
    memset(buf0, 0xbb, sizeof buf0);
    memset(buf1, 0xbb, sizeof buf1);
    memset(iovs, 0, sizeof iovs);
    iovs[0].iov_base = buf0;
    iovs[0].iov_len = 4;
    iovs[1].iov_base = buf1;
    iovs[1].iov_len = 4;
    if (is(dims, choice, 3, "base0")) iovs[0].iov_base = unmapped;
    else if (is(dims, choice, 3, "base1")) iovs[1].iov_base = unmapped;
    else if (is(dims, choice, 3, "neg0")) iovs[0].iov_len = (size_t)1 << (sizeof(size_t) * 8 - 1);
    else if (is(dims, choice, 3, "huge")) iovs[0].iov_len = iovs[1].iov_len = SIZE_MAX >> 1;
    else if (is(dims, choice, 3, "zeros")) iovs[0].iov_len = iovs[1].iov_len = 0;

    static unsigned char name[32];
    memset(name, 0xaa, sizeof name);
    void *namep = name;
    socklen_t namelen = 16;
    if (is(dims, choice, 4, "null")) { namep = NULL; namelen = 0; }
    else if (is(dims, choice, 4, "nulllen16")) namep = NULL;
    else if (is(dims, choice, 4, "unmapped")) namep = unmapped;
    else if (is(dims, choice, 4, "len0")) namelen = 0;
    else if (is(dims, choice, 4, "len8")) namelen = 8;
    else if (is(dims, choice, 4, "len7fffffff")) namelen = 0x7fffffff;
    else if (is(dims, choice, 4, "lenffffffff")) namelen = 0xffffffffu;

    static unsigned char control[64];
    memset(control, 0xcc, sizeof control);
    void *controlp = NULL;
    size_t controllen = 0;
    if (is(dims, choice, 5, "mapped8")) { controlp = control; controllen = 8; }
    else if (is(dims, choice, 5, "mapped64")) { controlp = control; controllen = 64; }
    else if (is(dims, choice, 5, "unmapped64")) { controlp = unmapped; controllen = 64; }
    else if (is(dims, choice, 5, "nulllen64")) controllen = 64;

    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_name = namep;
    m.msg_namelen = namelen;
    m.msg_iov = is(dims, choice, 2, "unmapped") ? unmapped : iovs;
    set_iovlen(&m, dims[1].values[choice[1]]);
    m.msg_control = controlp;
    m.msg_controllen = (__typeof__(m.msg_controllen))controllen;
    m.msg_flags = 0x7fffffff;

    struct msghdr *mp = &m;
    if (is(dims, choice, 0, "unmapped")) mp = unmapped;
    else if (is(dims, choice, 0, "readonly")) mp = readonly_copy(&m);

    int flags = is(dims, choice, 6, "peek") ? MSG_PEEK : is(dims, choice, 6, "trunc") ? MSG_TRUNC
              : is(dims, choice, 6, "oob")  ? MSG_OOB
                                            : 0;
    ssize_t got = recvmsg(r, mp, flags);
    int e = errno;

    char h0[40], h1[40], hn[64], hc[24], fields[96] = "namelen=- controllen=- msgflags=-";
    hex(h0, sizeof h0, buf0, 12, 0);
    hex(h1, sizeof h1, buf1, 12, 0);
    hex(hn, sizeof hn, name, 20, portof(t));
    hex(hc, sizeof hc, control, 8, 0);
    if (mp != unmapped)
        snprintf(fields, sizeof fields, "namelen=%u controllen=%lu msgflags=0x%x", (unsigned)mp->msg_namelen,
                 (unsigned long)mp->msg_controllen, (unsigned)mp->msg_flags);
    if (is(dims, choice, 0, "readonly")) munmap(mp, 4096);

    int error = sock_error(r);
    print_inputs("Y2", "queue", queue, dims, Y2DIMS, choice);
    printf(" answer=%s iov0=%s iov1=%s name=%s %s control=%s error=%d left=%s\n", res(got, e), h0, h1, hn,
           fields, hc, error, drain(r));
    close(t);
    close(r);
}

static void section_y2(void)
{
    const char *queues[] = { "empty", "ten", "zero", "erred" };
    int defaults[Y2DIMS] = { 0, 0, 0, 0, 0, 0, 0 };
    for (size_t q = 0; q < sizeof queues / sizeof *queues; q++) cross(y2_dims, Y2DIMS, defaults, y2_row, (void *)queues[q]);
}

// ---------------------------------------------------------------- Y3

struct later {
    int to;
    uint16_t port;
};

static void *send_later(void *arg)
{
    struct later *l = arg;
    usleep(60000);
    struct sockaddr_in to = at(INADDR_LOOPBACK, l->port);
    sendto(l->to, "abcdefghij", 10, 0, (struct sockaddr *)&to, sizeof to);
    return NULL;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void section_y3(void)
{
    const char *faults[] = { "none", "header", "array", "base0", "name", "namelenffffffff", "control", "iovlen0", "iovlen1025" };
    for (size_t f = 0; f < sizeof faults / sizeof *faults; f++)
        for (int arrives = 0; arrives <= 1; arrives++) {
            const char *fault = faults[f];
            int r = bound_to(INADDR_LOOPBACK);
            struct timeval tv = { 0, 300000 };
            setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            int t = bound_to(INADDR_LOOPBACK);

            static unsigned char buf0[16], buf1[16], name[32];
            memset(iovs, 0, sizeof iovs);
            iovs[0].iov_base = buf0;
            iovs[0].iov_len = 4;
            iovs[1].iov_base = buf1;
            iovs[1].iov_len = 4;
            if (!strcmp(fault, "base0")) iovs[0].iov_base = unmapped;
            struct msghdr m;
            memset(&m, 0, sizeof m);
            m.msg_name = !strcmp(fault, "name") ? unmapped : (void *)name;
            m.msg_namelen = !strcmp(fault, "namelenffffffff") ? 0xffffffffu : 16;
            m.msg_iov = !strcmp(fault, "array") ? unmapped : iovs;
            m.msg_iovlen = !strcmp(fault, "iovlen0") ? 0 : !strcmp(fault, "iovlen1025") ? 1025 : 2;
            m.msg_control = !strcmp(fault, "control") ? unmapped : NULL;
            m.msg_controllen = !strcmp(fault, "control") ? 64 : 0;
            struct msghdr *mp = !strcmp(fault, "header") ? unmapped : &m;

            pthread_t sender;
            struct later l = { t, portof(r) };
            if (arrives) pthread_create(&sender, NULL, send_later, &l);
            long start = now_ms();
            ssize_t got = recvmsg(r, mp, 0);
            int e = errno;
            long took = now_ms() - start;
            if (arrives) pthread_join(sender, NULL);
            await_datagram(r, 30);
            printf("Y3 fault=%s arrives=%s: answer=%s slept=%s left=%s\n", fault, arrives ? "60ms" : "never", res(got, e),
                   took >= 40 ? "yes" : "no", drain(r));
            close(t);
            close(r);
        }
}

// ---------------------------------------------------------------- Y4

static void section_y4(void)
{
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(1); }
    int empty = bound_to(INADDR_LOOPBACK);
    nonblocking(empty);
    int closed = udp();
    close(closed);
    struct { const char *name; int fd; } targets[] = { { "closed", closed }, { "pipe", fds[0] }, { "empty", empty } };
    const char *faults[] = { "header", "array", "name", "iovlen1025", "neg0", "namelenffffffff" };
    static unsigned char buf[16];
    for (int call = 0; call <= 1; call++)
        for (size_t i = 0; i < sizeof targets / sizeof *targets; i++)
            for (size_t f = 0; f < sizeof faults / sizeof *faults; f++) {
                const char *fault = faults[f];
                memset(iovs, 0, sizeof iovs);
                iovs[0].iov_base = buf;
                iovs[0].iov_len = !strcmp(fault, "neg0") ? (size_t)1 << (sizeof(size_t) * 8 - 1) : sizeof buf;
                struct sockaddr_in to = at(INADDR_LOOPBACK, unheld_port());
                struct msghdr m;
                memset(&m, 0, sizeof m);
                m.msg_name = !strcmp(fault, "name") ? unmapped : (void *)&to;
                m.msg_namelen = !strcmp(fault, "namelenffffffff") ? 0xffffffffu : sizeof to;
                m.msg_iov = !strcmp(fault, "array") ? unmapped : iovs;
                m.msg_iovlen = !strcmp(fault, "iovlen1025") ? 1025 : 1;
                struct msghdr *mp = !strcmp(fault, "header") ? unmapped : &m;
                ssize_t got = call ? recvmsg(targets[i].fd, mp, MSG_DONTWAIT) : sendmsg(targets[i].fd, mp, 0);
                int e = errno;
                printf("Y4 call=%s fd=%s fault=%s: answer=%s\n", call ? "recvmsg" : "sendmsg", targets[i].name, fault,
                       res(got, e));
            }
    close(fds[0]);
    close(fds[1]);
    close(empty);
}

// ---------------------------------------------------------------- Y6

static void section_y6(void)
{
    const uint64_t lengths[] = { 65536, 0x7ffff000, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0x7fffffffffffffff };
    for (int call = 0; call <= 1; call++)
        for (int split = 0; split <= 1; split++)
            for (size_t l = 0; l < sizeof lengths / sizeof *lengths; l++) {
                int r = bound_to(INADDR_LOOPBACK);
                nonblocking(r);
                int s = bound_to(INADDR_LOOPBACK);
                struct sockaddr_in to = at(INADDR_LOOPBACK, portof(r));
                memset(iovs, 0, sizeof iovs);
                iovs[0].iov_base = payload;
                iovs[1].iov_base = payload;
                iovs[0].iov_len = split ? (size_t)(lengths[l] / 2) : (size_t)lengths[l];
                iovs[1].iov_len = split ? (size_t)(lengths[l] - lengths[l] / 2) : 0;
                struct msghdr m;
                memset(&m, 0, sizeof m);
                m.msg_name = &to;
                m.msg_namelen = sizeof to;
                m.msg_iov = iovs;
                m.msg_iovlen = split ? 2 : 1;
                ssize_t got = call ? recvmsg(r, &m, 0) : sendmsg(s, &m, 0);
                int e = errno;
                printf("Y6 call=%s iovecs=%d total=%llx: answer=%s\n", call ? "recvmsg" : "sendmsg", split ? 2 : 1,
                       (unsigned long long)lengths[l], res(got, e));
                close(s);
                close(r);
            }
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'd', sizeof payload);
    section_y1();
    section_y2();
    section_y3();
    section_y4();
    section_y5();
    section_y6();
    return 0;
}
