// What moving datagrams over IPv4 UDP on loopback answers, on both flavours.
// Plan: docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   Darwin: cc -Wall -O0 -pthread -o /tmp/ut udp-transfer.c && /tmp/ut
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c
//             'gcc -Wall -O0 -pthread -o /tmp/ut /probe/udp-transfer.c && /tmp/ut'
//
// Sections:
//   A  whether a datagram is queued at the receiver when sendto returns, and
//      the source address the receiver sees
//   B  message boundaries
//   C  a receive smaller than the datagram; MSG_TRUNC; zero-length receives
//   D  MSG_PEEK
//   E  zero-length datagrams
//   F  FIONREAD (and Darwin's SO_NREAD)
//   G  readiness: poll, epoll (edge and level), kqueue
//   H  datagram sizes, and the buffer sizes a fresh socket reports
//   I  how many datagrams a receiver nobody reads queues
//   J  what a connected socket accepts, and AF_UNSPEC
//   K  sending on a connected socket
//   L  sending to a port nobody holds: ICMP errors
//   M  sending to oneself
//   N  sendto's destination argument
//   O  recvfrom's source argument
//   P  recvmsg and sendmsg
//   Q  several sockets on one port
//   S  sleeping receivers: how many one datagram wakes
//   W  other flags
//   X  how often sends to a port nobody holds raise the ICMP error, and which
//      earlier error suppresses one
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/event.h>
#include <sys/sysctl.h>
#else
#include <sys/epoll.h>
#endif

#define SETTLE() usleep(5000)

// An address nothing maps, hidden from the compiler's own checks.
static void *volatile unmapped __attribute__((unused)) = (void *)1;

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

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
    case EADDRINUSE: return "EADDRINUSE";
    case EFAULT: return "EFAULT";
    case ENOTCONN: return "ENOTCONN";
    case ENOBUFS: return "ENOBUFS";
    case ENOTSOCK: return "ENOTSOCK";
    case EBADF: return "EBADF";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case EPIPE: return "EPIPE";
    case EINTR: return "EINTR";
    case EPROTOTYPE: return "EPROTOTYPE";
    case ENOPROTOOPT: return "ENOPROTOOPT";
    case 0: return "0";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

// "5" or "-1 EAGAIN"
static const char *res(ssize_t r, int e)
{
    static char bufs[32][48];
    static int next = 0;
    char *b = bufs[next++ % 32];
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

static struct sockaddr_in lo(uint16_t port) { return at(INADDR_LOOPBACK, port); }

static int udp(void) { return socket(AF_INET, SOCK_DGRAM, 0); }

static uint16_t portof(int s)
{
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) return 0;
    return ntohs(a.sin_port);
}

static const char *nameof(int s)
{
    static char bufs[16][64];
    static int next = 0;
    char *b = bufs[next++ % 16];
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) { snprintf(b, 64, "getsockname %s", ename(errno)); return b; }
    snprintf(b, 64, "%s:%u", inet_ntoa(a.sin_addr), ntohs(a.sin_port));
    return b;
}

// A UDP socket bound to 127.0.0.1 at an ephemeral port.
static int bound(void)
{
    int s = udp();
    struct sockaddr_in a = lo(0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    return s;
}

static int bound_any(void)
{
    int s = udp();
    struct sockaddr_in a = at(INADDR_ANY, 0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    return s;
}

static ssize_t send_to(int s, const void *buf, size_t n, uint16_t port)
{
    struct sockaddr_in a = lo(port);
    return sendto(s, buf, n, 0, (struct sockaddr *)&a, sizeof a);
}

static ssize_t take(int s, void *buf, size_t n, int flags) { return recv(s, buf, n, flags | MSG_DONTWAIT); }

// Every datagram the socket holds now: "len[,len...]" or "none".
static const char *drain(int s)
{
    static char outs[8][1024];
    static int next = 0;
    char *out = outs[next++ % 8];
    static char buf[70000];
    out[0] = 0;
    int count = 0;
    for (;;) {
        ssize_t r = take(s, buf, sizeof buf, 0);
        if (r < 0) {
            if (errno != EAGAIN) {
                size_t used = strlen(out);
                snprintf(out + used, 1024 - used, "%s%s", count ? "," : "", ename(errno));
                count++;
                if (errno == ECONNREFUSED) continue;
            }
            break;
        }
        size_t used = strlen(out);
        if (used < 1024 - 16) snprintf(out + used, 1024 - used, "%s%zd", count ? "," : "", r);
        count++;
    }
    if (count == 0) return "none";
    return out;
}

// The text of each datagram the socket holds now: "early|s1" or "none".
static const char *drain_text(int s)
{
    static char outs[8][1024];
    static int next = 0;
    char *out = outs[next++ % 8];
    char buf[256];
    out[0] = 0;
    int count = 0;
    for (;;) {
        struct sockaddr_in from;
        socklen_t len = sizeof from;
        ssize_t r = recvfrom(s, buf, sizeof buf - 1, MSG_DONTWAIT, (struct sockaddr *)&from, &len);
        if (r < 0) {
            if (errno != EAGAIN) {
                size_t used = strlen(out);
                snprintf(out + used, 1024 - used, "%s%s", count ? "|" : "", ename(errno));
                count++;
                continue;
            }
            break;
        }
        buf[r] = 0;
        size_t used = strlen(out);
        snprintf(out + used, 1024 - used, "%s%s", count ? "|" : "", buf);
        count++;
    }
    if (count == 0) return "none";
    return out;
}

static int sock_error(int s)
{
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &len) != 0) return -errno;
    return v;
}

static int intopt(int s, int level, int name)
{
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(s, level, name, &v, &len) != 0) return -errno;
    return v;
}

static int fionread(int s)
{
    int v = -1;
    if (ioctl(s, FIONREAD, &v) != 0) return -errno;
    return v;
}

static const char *revents(int s)
{
    static char bufs[16][96];
    static int next = 0;
    char *b = bufs[next++ % 16];
    short events = POLLIN | POLLPRI | POLLOUT | POLLRDNORM | POLLRDBAND | POLLWRNORM | POLLWRBAND;
#ifdef POLLRDHUP
    events |= POLLRDHUP;
#endif
    struct pollfd p = { s, events, 0 };
    int r = poll(&p, 1, 0);
    snprintf(b, 96, "poll=%d revents=0x%x", r, (unsigned)p.revents);
    return b;
}

// A port nobody holds: bind one, read its number, close it.
static uint16_t unheld_port(void)
{
    int s = bound();
    uint16_t p = portof(s);
    close(s);
    return p;
}

static void section_a(void)
{
    char buf[64];
    int eagain = 0, delivered = 0;
    for (int i = 0; i < 1000; i++) {
        int r = bound();
        int s = udp();
        send_to(s, "hello", 5, portof(r));
        ssize_t got = take(r, buf, sizeof buf, 0);
        if (got == 5) delivered++;
        else if (got < 0 && errno == EAGAIN) eagain++;
        close(r); close(s);
    }
    printf("A1 sendto then an immediate MSG_DONTWAIT recv, 1000 trials: delivered=%d EAGAIN=%d\n", delivered, eagain);

    // Delivery measured after a blocking receive instead, to see the source.
    for (int variant = 0; variant < 3; variant++) {
        int r = bound();
        int s = variant == 0 ? udp() : variant == 1 ? bound_any() : bound();
        printf("A2 sender %s: before sendto getsockname=%s", variant == 0 ? "unbound" : variant == 1 ? "bound 0.0.0.0:0" : "bound 127.0.0.1:0", nameof(s));
        ssize_t sent = send_to(s, "hello", 5, portof(r));
        int sentErrno = errno;
        struct sockaddr_in from;
        memset(&from, 0, sizeof from);
        socklen_t len = sizeof from;
        ssize_t got = recvfrom(r, buf, sizeof buf, 0, (struct sockaddr *)&from, &len);
        // Each formatted on its own line: nameof and inet_ntoa share
        // inet_ntoa's one static buffer, and errno is read before either
        // call can change it.
        int receiveErrno = errno;
        char sentText[64], gotText[64], fromText[32];
        snprintf(sentText, sizeof sentText, "%s", res(sent, sentErrno));
        snprintf(gotText, sizeof gotText, "%s", res(got, receiveErrno));
        snprintf(fromText, sizeof fromText, "%s", inet_ntoa(from.sin_addr));
        const char *after = nameof(s);
        printf(" sendto=%s after getsockname=%s; recvfrom=%s from=%s:%u len=%u\n", sentText, after, gotText, fromText, ntohs(from.sin_port), (unsigned)len);
        close(r); close(s);
    }

    // A receiver bound to the wildcard.
    {
        int r = bound_any();
        int s = udp();
        ssize_t sent = send_to(s, "hello", 5, portof(r));
        struct sockaddr_in from;
        socklen_t len = sizeof from;
        ssize_t got = recvfrom(r, buf, sizeof buf, 0, (struct sockaddr *)&from, &len);
        printf("A3 receiver bound 0.0.0.0, sent to 127.0.0.1: sendto=%s recvfrom=%s from=%s:%u\n", res(sent, errno), res(got, errno), inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        close(r); close(s);
    }
}

static void section_b(void)
{
    int r = bound(), s = udp();
    char buf[100];
    memset(buf, 'x', sizeof buf);
    send_to(s, buf, 10, portof(r));
    send_to(s, buf, 20, portof(r));
    send_to(s, buf, 30, portof(r));
    SETTLE();
    ssize_t a = take(r, buf, 100, 0); int ea = errno;
    ssize_t b = take(r, buf, 100, 0); int eb = errno;
    ssize_t c = take(r, buf, 100, 0); int ec = errno;
    ssize_t d = take(r, buf, 100, 0); int ed = errno;
    printf("B1 datagrams of 10, 20, 30; four recvs of 100: %s %s %s %s\n", res(a, ea), res(b, eb), res(c, ec), res(d, ed));
    // read(2) and write(2) are not allowed unconnected (write); read is.
    send_to(s, "abc", 3, portof(r));
    SETTLE();
    int fl = fcntl(r, F_GETFL);
    fcntl(r, F_SETFL, fl | O_NONBLOCK);
    ssize_t e = read(r, buf, 100); int ee = errno;
    ssize_t f = read(r, buf, 100); int ef = errno;
    fcntl(r, F_SETFL, fl);
    printf("B2 read(2) of an unconnected socket holding one datagram of 3: %s, then %s\n", res(e, ee), res(f, ef));
    close(r); close(s);
}

static void hex(const unsigned char *b, int n, char *out);

static void section_c(void)
{
    char buf[200];
    char data[100];
    for (int i = 0; i < 100; i++) data[i] = (char)('a' + i % 26);
    int r = bound(), s = udp();
    uint16_t p = portof(r);

    send_to(s, data, 100, p); send_to(s, "next", 4, p); SETTLE();
    ssize_t a = take(r, buf, 10, 0); int ea = errno;
    char first[4];
    memcpy(first, buf, 3); first[3] = 0;
    ssize_t b = take(r, buf, 200, 0); int eb = errno;
    printf("C1 a datagram of 100 then one of 4; recv of 10, then of 200: %s (first bytes %s), then %s (the next datagram if 4)\n", res(a, ea), first, res(b, eb));

    send_to(s, data, 100, p); SETTLE();
    a = take(r, buf, 10, MSG_TRUNC); ea = errno;
    printf("C2 recv of 10 with MSG_TRUNC, datagram of 100: %s; then %s\n", res(a, ea), drain(r));

    send_to(s, data, 100, p); SETTLE();
    a = take(r, buf, 0, 0); ea = errno;
    printf("C3 recv of 0 with a datagram of 100 queued: %s; then the queue holds %s\n", res(a, ea), drain(r));

    send_to(s, data, 100, p); SETTLE();
    a = take(r, buf, 0, MSG_TRUNC); ea = errno;
    printf("C4 recv of 0 with MSG_TRUNC, datagram of 100: %s; then %s\n", res(a, ea), drain(r));

    send_to(s, data, 100, p); SETTLE();
    {
        int fl = fcntl(r, F_GETFL);
        fcntl(r, F_SETFL, fl | O_NONBLOCK);
        a = read(r, buf, 0); ea = errno;
        fcntl(r, F_SETFL, fl);
    }
    printf("C5 read(2) of 0 with a datagram of 100 queued: %s; then %s\n", res(a, ea), drain(r));

    a = take(r, buf, 0, 0); ea = errno;
    printf("C6 recv of 0 MSG_DONTWAIT on an empty queue: %s\n", res(a, ea));

    a = take(r, NULL, 0, 0); ea = errno;
    printf("C7 recv of 0 into NULL on an empty queue: %s\n", res(a, ea));

    send_to(s, data, 100, p); SETTLE();
    a = take(r, (void *)1, 10, 0); ea = errno;
    printf("C8 recv of 10 into an unmapped buffer, datagram of 100 queued: %s; then %s\n", res(a, ea), drain(r));

    send_to(s, data, 100, p); SETTLE();
    a = take(r, (void *)1, 0, 0); ea = errno;
    printf("C9 recv of 0 into an unmapped buffer, datagram of 100 queued: %s; then %s\n", res(a, ea), drain(r));

    // C10: what a faulting receive leaves of the datagram: FIONREAD, and the
    // source a recvfrom then reports, for a take and for a peek.
    for (int peeking = 0; peeking <= 1; peeking++) {
        int r2 = bound(), s2 = bound();
        send_to(s2, data, 100, portof(r2)); SETTLE();
        int before = fionread(r2);
        ssize_t f = take(r2, (void *)1, 10, peeking ? MSG_PEEK : 0); int ef = errno;
        int after = fionread(r2);
        unsigned char addr[32];
        memset(addr, 0xaa, sizeof addr);
        socklen_t alen = sizeof addr;
        ssize_t g = recvfrom(r2, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)addr, &alen); int eg = errno;
        char h[80];
        hex(addr, 16, h);
        int last = fionread(r2);
        printf("C10 %s of 10 into an unmapped buffer, a datagram of 100 from %s queued: FIONREAD %d; %s; FIONREAD %d; then recvfrom %s, addrlen %u, address %s; FIONREAD %d\n",
               peeking ? "recv(MSG_PEEK)" : "recv", nameof(s2), before, res(f, ef), after, res(g, eg), (unsigned)alen, h, last);
        close(r2); close(s2);
    }

    close(r); close(s);
}

static void section_d(void)
{
    char buf[200];
    int r = bound(), s = udp();
    uint16_t p = portof(r);
    char data[20];
    memset(data, 'p', sizeof data);
    send_to(s, data, 20, p); send_to(s, "two", 3, p); SETTLE();
    ssize_t a = take(r, buf, 10, MSG_PEEK); int ea = errno;
    ssize_t b = take(r, buf, 100, MSG_PEEK); int eb = errno;
    ssize_t c = take(r, buf, 10, MSG_PEEK | MSG_TRUNC); int ec = errno;
    printf("D1 peeks of 10, 100, and 10 with MSG_TRUNC, datagrams of 20 and 3: %s %s %s; then the queue holds %s\n", res(a, ea), res(b, eb), res(c, ec), drain(r));
    a = take(r, buf, 10, MSG_PEEK); ea = errno;
    printf("D2 peek of an empty queue: %s\n", res(a, ea));
    close(r); close(s);
}

static void section_e(void)
{
    char buf[100];
    int r = bound(), s = udp();
    uint16_t p = portof(r);
    printf("E0 empty queue: %s FIONREAD=%d\n", revents(r), fionread(r));
    ssize_t a = send_to(s, buf, 0, p); int ea = errno;
    SETTLE();
    printf("E1 sendto of 0: %s; then %s FIONREAD=%d\n", res(a, ea), revents(r), fionread(r));
    ssize_t b = take(r, buf, 100, 0); int eb = errno;
    ssize_t c = take(r, buf, 100, 0); int ec = errno;
    printf("E2 recv of 100, twice: %s %s; then %s\n", res(b, eb), res(c, ec), revents(r));
    a = sendto(s, NULL, 0, 0, NULL, 0); ea = errno;
    printf("E3 sendto of 0 from NULL with no address, unconnected: %s\n", res(a, ea));
    struct sockaddr_in to = lo(p);
    a = sendto(s, NULL, 0, 0, (struct sockaddr *)&to, sizeof to); ea = errno;
    SETTLE();
    printf("E4 sendto of 0 from NULL: %s; the queue holds %s\n", res(a, ea), drain(r));
    a = sendto(s, (void *)1, 0, 0, (struct sockaddr *)&to, sizeof to); ea = errno;
    SETTLE();
    printf("E5 sendto of 0 from an unmapped buffer: %s; the queue holds %s\n", res(a, ea), drain(r));
    // A fresh sender, so that whether the fault binds it shows.
    int s6 = udp();
    const char *before6 = nameof(s6);
    a = sendto(s6, (void *)1, 5, 0, (struct sockaddr *)&to, sizeof to); ea = errno;
    SETTLE();
    printf("E6 a fresh sender's sendto of 5 from an unmapped buffer: %s; the queue holds %s; the sender was %s and is %s\n", res(a, ea), drain(r), before6, nameof(s6));
    close(s6);
    close(r); close(s);
}

static void section_f(void)
{
    char buf[100];
    memset(buf, 'f', sizeof buf);
    int r = bound(), s = udp();
    uint16_t p = portof(r);
    send_to(s, buf, 10, p); send_to(s, buf, 20, p); send_to(s, buf, 30, p); SETTLE();
#ifdef __APPLE__
    printf("F1 datagrams of 10, 20, 30: FIONREAD=%d SO_NREAD=%d\n", fionread(r), intopt(r, SOL_SOCKET, SO_NREAD));
    take(r, buf, 100, 0);
    printf("F2 after one recv: FIONREAD=%d SO_NREAD=%d\n", fionread(r), intopt(r, SOL_SOCKET, SO_NREAD));
#else
    printf("F1 datagrams of 10, 20, 30: FIONREAD=%d\n", fionread(r));
    take(r, buf, 100, 0);
    printf("F2 after one recv: FIONREAD=%d\n", fionread(r));
#endif
    drain(r);
    send_to(s, buf, 0, p); send_to(s, buf, 10, p); SETTLE();
#ifdef __APPLE__
    printf("F3 datagrams of 0, 10: FIONREAD=%d SO_NREAD=%d\n", fionread(r), intopt(r, SOL_SOCKET, SO_NREAD));
#else
    printf("F3 datagrams of 0, 10: FIONREAD=%d\n", fionread(r));
#endif
    drain(r);
    printf("F4 a fresh unbound socket: FIONREAD=%d\n", fionread(s));
    {
        // FIONREAD after each step of a sequence of sends (+n) and receives (-).
        int r2 = bound();
        const int steps[] = { 10, 10, -1, 10, -1, -1, 0, 5, -1, 7, 7, 7, -1, -1, -1 };
        printf("F5 sequence:");
        for (unsigned i = 0; i < sizeof steps / sizeof *steps; i++) {
            if (steps[i] >= 0) { send_to(s, buf, steps[i], portof(r2)); SETTLE(); printf(" +%d", steps[i]); }
            else { take(r2, buf, 100, 0); printf(" -"); }
#ifdef __APPLE__
            printf("=%d/%d", fionread(r2), intopt(r2, SOL_SOCKET, SO_NREAD));
#else
            printf("=%d", fionread(r2));
#endif
        }
        printf("\n");
        close(r2);
        // A fresh receiver whose first datagram comes from a second sender.
        int r3 = bound(), s3 = bound(), s4 = bound();
        printf("F6 two senders:");
        send_to(s3, buf, 10, portof(r3)); SETTLE(); printf(" s3+10=%d", fionread(r3));
        send_to(s4, buf, 10, portof(r3)); SETTLE(); printf(" s4+10=%d", fionread(r3));
        send_to(s3, buf, 10, portof(r3)); SETTLE(); printf(" s3+10=%d", fionread(r3));
        send_to(s3, buf, 10, portof(r3)); SETTLE(); printf(" s3+10=%d", fionread(r3));
        printf("\n");
        close(r3); close(s3); close(s4);
    }
    close(r); close(s);
}

#ifndef __APPLE__
static const char *epoll_now(int ep)
{
    static char bufs[16][64];
    static int next = 0;
    char *b = bufs[next++ % 16];
    struct epoll_event ev[4];
    int n = epoll_wait(ep, ev, 4, 0);
    if (n <= 0) snprintf(b, 64, "%d", n);
    else snprintf(b, 64, "%d:0x%x", n, ev[0].events);
    return b;
}
#else
static const char *kevent_now(int kq)
{
    static char bufs[16][160];
    static int next = 0;
    char *b = bufs[next++ % 16];
    struct kevent ev[4];
    struct timespec zero = { 0, 0 };
    int n = kevent(kq, NULL, 0, ev, 4, &zero);
    b[0] = 0;
    snprintf(b, 160, "%d", n);
    for (int i = 0; i < n; i++) {
        size_t used = strlen(b);
        snprintf(b + used, 160 - used, " [%s data=%ld flags=0x%x fflags=0x%x]",
                 ev[i].filter == EVFILT_READ ? "READ" : ev[i].filter == EVFILT_WRITE ? "WRITE" : "?",
                 (long)ev[i].data, ev[i].flags, ev[i].fflags);
    }
    return b;
}
#endif

static void section_g(void)
{
    char buf[100];
    memset(buf, 'g', sizeof buf);
    {
        int fresh = udp();
        printf("G1 fresh unbound: %s\n", revents(fresh));
        int r = bound(), s = udp();
        printf("G2 bound, empty: %s\n", revents(r));
        send_to(s, buf, 10, portof(r)); SETTLE();
        printf("G3 bound, one datagram queued: %s\n", revents(r));
        int c = bound();
        struct sockaddr_in to = lo(portof(r));
        connect(c, (struct sockaddr *)&to, sizeof to);
        printf("G4 connected to a bound socket, empty: %s\n", revents(c));
        close(fresh); close(r); close(s); close(c);
    }
#ifndef __APPLE__
    for (int et = 0; et <= 1; et++) {
        int r = bound(), s = udp();
        int ep = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT | (et ? EPOLLET : 0), .data.fd = r };
        epoll_ctl(ep, EPOLL_CTL_ADD, r, &ev);
        const char *w0 = epoll_now(ep);
        const char *w1 = epoll_now(ep);
        send_to(s, buf, 10, portof(r)); SETTLE();
        const char *w2 = epoll_now(ep);
        const char *w3 = epoll_now(ep);
        send_to(s, buf, 20, portof(r)); SETTLE();
        const char *w4 = epoll_now(ep);
        take(r, buf, 100, 0);
        const char *w5 = epoll_now(ep);
        take(r, buf, 100, 0);
        const char *w6 = epoll_now(ep);
        printf("G5 epoll IN|OUT%s on a bound receiver: registered %s, again %s; a datagram %s, again %s; a second %s; one taken %s; both taken %s\n",
               et ? "|ET" : "", w0, w1, w2, w3, w4, w5, w6);
        close(ep); close(r); close(s);
    }
    {
        // Does a sender's own send, or the receiver's read, give the sender an OUT edge?
        int r = bound(), s = bound();
        int ep = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLOUT | EPOLLET, .data.fd = s };
        epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev);
        const char *w0 = epoll_now(ep);
        send_to(s, buf, 10, portof(r)); SETTLE();
        const char *w1 = epoll_now(ep);
        take(r, buf, 100, 0); SETTLE();
        const char *w2 = epoll_now(ep);
        printf("G6 epoll OUT|ET on a sender: registered %s; after its send %s; after the receiver takes it %s\n", w0, w1, w2);
        close(ep); close(r); close(s);
    }
    {
        // G8: one epoll instance watching a sender for OUT|ET and its
        // receiver for IN|ET; after the registrations' own events are
        // drained, the sender sends, and epoll_wait with maxevents 1, twice.
        int r = bound(), s = bound();
        struct sockaddr_in to = lo(portof(r));
        connect(s, (struct sockaddr *)&to, sizeof to);
        int ep = epoll_create1(0);
        struct epoll_event es = { .events = EPOLLOUT | EPOLLET, .data.fd = s };
        struct epoll_event er = { .events = EPOLLIN | EPOLLET, .data.fd = r };
        epoll_ctl(ep, EPOLL_CTL_ADD, s, &es);
        epoll_ctl(ep, EPOLL_CTL_ADD, r, &er);
        struct epoll_event got[4];
        epoll_wait(ep, got, 4, 0);
        send(s, buf, 10, 0);
        SETTLE();
        const char *names[2] = { "-", "-" };
        for (int k = 0; k < 2; k++) {
            int n = epoll_wait(ep, got, 1, 0);
            names[k] = n <= 0 ? "none" : got[0].data.fd == s ? "sender" : got[0].data.fd == r ? "receiver" : "?";
        }
        printf("G8 one epoll, sender OUT|ET and receiver IN|ET, after a send, maxevents 1: first %s, then %s\n", names[0], names[1]);
        close(ep); close(r); close(s);
    }
    {
        // G9: a connected sender watched for OUT|ET; after the registration's
        // event, a call that fails: is it an OUT edge?
        static const char *what[] = { "write from an unmapped buffer (EFAULT)", "send of 65508 bytes (EMSGSIZE)", "write of 0 bytes (sent)", "send from an unmapped buffer (EFAULT)" };
        static char big[65508];
        for (int k = 0; k < 4; k++) {
            int r = bound(), s = bound();
            struct sockaddr_in to = lo(portof(r));
            connect(s, (struct sockaddr *)&to, sizeof to);
            int ep = epoll_create1(0);
            struct epoll_event es = { .events = EPOLLOUT | EPOLLET, .data.fd = s };
            epoll_ctl(ep, EPOLL_CTL_ADD, s, &es);
            const char *w0 = epoll_now(ep);
            ssize_t a;
            switch (k) {
            case 0: a = write(s, unmapped, 1); break;
            case 1: a = send(s, big, sizeof big, 0); break;
            case 2: a = write(s, buf, 0); break;
            default: a = send(s, unmapped, 1, 0); break;
            }
            int ea = errno;
            SETTLE();
            const char *w1 = epoll_now(ep);
            printf("G9 epoll OUT|ET on a connected sender: registered %s; a %s: %s, then %s\n", w0, what[k], res(a, ea), w1);
            close(ep); close(r); close(s);
        }
    }
    {
        // EPOLLIN|EPOLLET registered on an ICMP-errored connected socket.
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        int ep = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN | EPOLLET, .data.fd = c };
        epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev);
        const char *w0 = epoll_now(ep);
        send(c, "x", 1, 0); SETTLE();
        const char *w1 = epoll_now(ep);
        const char *w2 = epoll_now(ep);
        printf("G7 epoll IN|ET on a socket connected to an unheld port: registered %s; after a send %s; again %s\n", w0, w1, w2);
        close(ep); close(c);
    }
#else
    for (int clear = 0; clear <= 1; clear++) {
        int r = bound(), s = udp();
        int kq = kqueue();
        struct kevent ch[2];
        EV_SET(&ch[0], r, EVFILT_READ, EV_ADD | (clear ? EV_CLEAR : 0), 0, 0, NULL);
        EV_SET(&ch[1], r, EVFILT_WRITE, EV_ADD | (clear ? EV_CLEAR : 0), 0, 0, NULL);
        kevent(kq, ch, 2, NULL, 0, NULL);
        const char *w0 = kevent_now(kq);
        const char *w1 = kevent_now(kq);
        send_to(s, buf, 10, portof(r)); SETTLE();
        const char *w2 = kevent_now(kq);
        const char *w3 = kevent_now(kq);
        send_to(s, buf, 20, portof(r)); SETTLE();
        const char *w4 = kevent_now(kq);
        take(r, buf, 100, 0);
        const char *w5 = kevent_now(kq);
        take(r, buf, 100, 0);
        const char *w6 = kevent_now(kq);
        printf("G5 kqueue READ+WRITE%s on a bound receiver: registered %s; again %s; a datagram %s; again %s; a second %s; one taken %s; both taken %s\n",
               clear ? " EV_CLEAR" : "", w0, w1, w2, w3, w4, w5, w6);
        close(kq); close(r); close(s);
    }
    {
        int r = bound(), s = bound();
        int kq = kqueue();
        struct kevent ch;
        EV_SET(&ch, s, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, NULL);
        kevent(kq, &ch, 1, NULL, 0, NULL);
        const char *w0 = kevent_now(kq);
        send_to(s, buf, 10, portof(r)); SETTLE();
        const char *w1 = kevent_now(kq);
        take(r, buf, 100, 0); SETTLE();
        const char *w2 = kevent_now(kq);
        printf("G6 kqueue WRITE EV_CLEAR on a sender: registered %s; after its send %s; after the receiver takes it %s\n", w0, w1, w2);
        close(kq); close(r); close(s);
    }
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        int kq = kqueue();
        struct kevent ch[2];
        EV_SET(&ch[0], c, EVFILT_READ, EV_ADD, 0, 0, NULL);
        EV_SET(&ch[1], c, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        kevent(kq, ch, 2, NULL, 0, NULL);
        const char *w0 = kevent_now(kq);
        send(c, "x", 1, 0); SETTLE();
        const char *w1 = kevent_now(kq);
        printf("G7 kqueue READ+WRITE on a socket connected to an unheld port: registered %s; after a send %s\n", w0, w1);
        close(kq); close(c);
    }
#endif
}

static void section_h(void)
{
    {
        int s = udp();
        printf("H0 a fresh socket: SO_SNDBUF=%d SO_RCVBUF=%d\n", intopt(s, SOL_SOCKET, SO_SNDBUF), intopt(s, SOL_SOCKET, SO_RCVBUF));
        close(s);
    }
#ifdef __APPLE__
    {
        int v; size_t len;
        len = sizeof v; v = -1; sysctlbyname("net.inet.udp.maxdgram", &v, &len, NULL, 0);
        printf("H0 net.inet.udp.maxdgram=%d", v);
        len = sizeof v; v = -1; sysctlbyname("net.inet.udp.recvspace", &v, &len, NULL, 0);
        printf(" net.inet.udp.recvspace=%d", v);
        len = sizeof v; v = -1; sysctlbyname("kern.ipc.maxsockbuf", &v, &len, NULL, 0);
        printf(" kern.ipc.maxsockbuf=%d\n", v);
    }
#else
    {
        const char *files[] = { "/proc/sys/net/core/rmem_default", "/proc/sys/net/core/wmem_default", "/proc/sys/net/core/rmem_max", "/proc/sys/net/core/wmem_max", "/proc/sys/net/ipv4/udp_mem", "/proc/sys/net/ipv4/udp_rmem_min" };
        for (unsigned i = 0; i < sizeof files / sizeof *files; i++) {
            char line[128] = "?";
            FILE *f = fopen(files[i], "r");
            if (f) { if (!fgets(line, sizeof line, f)) strcpy(line, "?"); fclose(f); }
            line[strcspn(line, "\n")] = 0;
            printf("H0 %s=%s\n", files[i], line);
        }
    }
#endif
    static char big[70000];
    memset(big, 'h', sizeof big);
    size_t sizes[] = { 0, 1, 1472, 8192, 9216, 9217, 16384, 65507, 65508, 65527, 65535, 65536, 69999 };
    for (int connected = 0; connected <= 1; connected++) {
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            int r = bound(), s = udp();
            ssize_t a;
            if (connected) {
                struct sockaddr_in to = lo(portof(r));
                connect(s, (struct sockaddr *)&to, sizeof to);
                a = send(s, big, sizes[i], 0);
            } else {
                a = send_to(s, big, sizes[i], portof(r));
            }
            int ea = errno;
            SETTLE();
            printf("H1 %s of %zu: %s; the receiver holds %s\n", connected ? "send (connected)" : "sendto", sizes[i], res(a, ea), drain(r));
            close(r); close(s);
        }
    }
    // H3: a connected send or write from an unmapped buffer, of a size the
    // socket takes and of sizes it does not: which answer comes first.
    {
        size_t sz[] = { 5, 9217, 65508, 70000 };
        for (int call = 0; call < 2; call++) {
            for (unsigned i = 0; i < sizeof sz / sizeof *sz; i++) {
                int r = bound(), c = bound();
                struct sockaddr_in to = lo(portof(r));
                connect(c, (struct sockaddr *)&to, sizeof to);
                ssize_t a = call ? write(c, (void *)1, sz[i]) : send(c, (void *)1, sz[i], 0); int ea = errno;
                SETTLE();
                printf("H3 a connected %s of %zu from an unmapped buffer: %s; the receiver holds %s\n", call ? "write" : "send", sz[i], res(a, ea), drain(r));
                close(r); close(c);
            }
        }
    }
    // A larger SO_SNDBUF on Darwin, and a smaller one on both.
    for (int which = 0; which < 2; which++) {
        int sb = which == 0 ? 65536 : 2048;
        int r = bound(), s = udp();
        int set = setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
        printf("H2 SO_SNDBUF set to %d (%d), reads %d:", sb, set, intopt(s, SOL_SOCKET, SO_SNDBUF));
        size_t sz[] = { 2000, 4000, 9216, 9217, 65507 };
        for (unsigned i = 0; i < sizeof sz / sizeof *sz; i++) {
            ssize_t a = send_to(s, big, sz[i], portof(r)); int ea = errno;
            printf(" %zu->%s", sz[i], res(a, ea));
        }
        SETTLE();
        printf("; the receiver holds %s\n", drain(r));
        close(r); close(s);
    }
}

static void section_i(void)
{
    static char big[65507];
    memset(big, 'i', sizeof big);
    size_t sizes[] = { 0, 1, 100, 1000, 1472, 4096, 9216, 65507 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        for (int trial = 0; trial < 3; trial++) {
            int r = bound(), s = udp();
            int sent = 0, failed = 0, firstfail = 0;
            int count = sizes[i] <= 100 ? 30000 : 4000;
            for (int k = 0; k < count; k++) {
                ssize_t a = send_to(s, big, sizes[i], portof(r));
                if (a < 0) { if (!failed) firstfail = errno; failed++; }
                else sent++;
            }
            usleep(50000);
            int fion = fionread(r);
            int got = 0;
            long bytes = 0;
            static char buf[70000];
            for (;;) {
                ssize_t g = take(r, buf, sizeof buf, 0);
                if (g < 0) break;
                got++;
                bytes += g;
            }
            printf("I1 datagrams of %zu, trial %d: sent=%d failed=%d (first %s); FIONREAD before draining=%d; queued=%d bytes=%ld\n",
                   sizes[i], trial, sent, failed, failed ? ename(firstfail) : "-", fion, got, bytes);
            close(r); close(s);
        }
    }
    // With a smaller receive buffer.
    for (int which = 0; which < 2; which++) {
        int rb = which == 0 ? 4096 : 65536;
        int r = bound(), s = udp();
        setsockopt(r, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
        int sent = 0;
        for (int k = 0; k < 4000; k++) if (send_to(s, big, 100, portof(r)) >= 0) sent++;
        usleep(50000);
        int got = 0;
        static char buf[200];
        while (take(r, buf, sizeof buf, 0) >= 0) got++;
        printf("I2 SO_RCVBUF set to %d (reads %d), datagrams of 100: sent=%d queued=%d\n", rb, intopt(r, SOL_SOCKET, SO_RCVBUF), sent, got);
        close(r); close(s);
    }
}

static void section_j(void)
{
    int r = bound(), s1 = bound(), s2 = bound();
    uint16_t p = portof(r);
    send_to(s2, "early", 5, p); SETTLE();
    struct sockaddr_in to = lo(portof(s1));
    int c = connect(r, (struct sockaddr *)&to, sizeof to);
    send_to(s2, "late", 4, p);
    send_to(s1, "s1", 2, p);
    SETTLE();
    printf("J1 r holds 'early' from s2, connects to s1 (%d); s2 sends 'late', s1 sends 's1': r receives %s\n", c, drain_text(r));
    struct sockaddr un;
    memset(&un, 0, sizeof un);
    un.sa_family = AF_UNSPEC;
    c = connect(r, &un, sizeof un);
    send_to(s2, "after", 5, p);
    SETTLE();
    printf("J2 r disconnects with AF_UNSPEC (%d) and keeps %s; s2 sends 'after': r receives %s\n", c, nameof(r), drain_text(r));
    // Connected to the wildcard-bound peer's 127.0.0.1 address; the peer is bound to 0.0.0.0.
    int any = bound_any();
    struct sockaddr_in toany = lo(portof(any));
    c = connect(r, (struct sockaddr *)&toany, sizeof toany);
    send_to(any, "fromany", 7, portof(r));
    SETTLE();
    printf("J3 r connects to 127.0.0.1:port of a socket bound to 0.0.0.0 (%d); that socket sends: r receives %s\n", c, drain_text(r));
    close(r); close(s1); close(s2); close(any);
}

static void section_k(void)
{
    int r = bound(), r2 = bound(), c = bound();
    struct sockaddr_in to = lo(portof(r)), to2 = lo(portof(r2));
    connect(c, (struct sockaddr *)&to, sizeof to);
    ssize_t a = write(c, "w", 1); int ea = errno;
    ssize_t b = send(c, "s", 1, 0); int eb = errno;
    ssize_t d = sendto(c, "n", 1, 0, NULL, 0); int ed = errno;
    ssize_t e = sendto(c, "p", 1, 0, (struct sockaddr *)&to, sizeof to); int ee = errno;
    ssize_t f = sendto(c, "o", 1, 0, (struct sockaddr *)&to2, sizeof to2); int ef = errno;
    SETTLE();
    printf("K1 connected to r: write=%s send=%s sendto(NULL)=%s sendto(r)=%s sendto(r2)=%s; r receives %s; r2 receives %s\n",
           res(a, ea), res(b, eb), res(d, ed), res(e, ee), res(f, ef), drain_text(r), drain_text(r2));
    // The connected socket's receive through read(2) and recv(2).
    send_to(r, "back", 4, portof(c)); SETTLE();
    char buf[64];
    int fl = fcntl(c, F_GETFL);
    fcntl(c, F_SETFL, fl | O_NONBLOCK);
    a = read(c, buf, sizeof buf); ea = errno;
    b = read(c, buf, sizeof buf); eb = errno;
    fcntl(c, F_SETFL, fl);
    printf("K2 r sends to c: read=%s then read=%s\n", res(a, ea), res(b, eb));
    // write(2) of 0 on a connected socket.
    a = write(c, buf, 0); ea = errno;
    SETTLE();
    printf("K3 write of 0 on a connected socket: %s; r receives %s\n", res(a, ea), drain(r));
    close(r); close(r2); close(c);
}

static void on_alarm(int sig) { (void)sig; }

static void section_l(void)
{
    char buf[64];
    // L1: a connected socket's send to a port nobody holds, then what each call sees.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        ssize_t a = send(c, "x", 1, 0); int ea = errno;
        const char *p0 = revents(c);
        SETTLE();
        const char *p1 = revents(c);
        ssize_t b = take(c, buf, sizeof buf, 0); int eb = errno;
        const char *p2 = revents(c);
        ssize_t d = take(c, buf, sizeof buf, 0); int ed = errno;
        printf("L1 connected to an unheld port: send=%s; at once %s; later %s; recv=%s then %s; recv=%s; SO_ERROR=%d\n",
               res(a, ea), p0, p1, res(b, eb), p2, res(d, ed), sock_error(c));
        close(c);
    }
    // L2: three sends in a row.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        ssize_t a = send(c, "x", 1, 0); int ea = errno;
        ssize_t b = send(c, "x", 1, 0); int eb = errno;
        SETTLE();
        ssize_t d = send(c, "x", 1, 0); int ed = errno;
        ssize_t e = send(c, "x", 1, 0); int ee = errno;
        SETTLE();
        int first = sock_error(c);
        int second = sock_error(c);
        printf("L2 connected to an unheld port, sends: %s, at once %s, later %s, %s; SO_ERROR=%d then %d\n",
               res(a, ea), res(b, eb), res(d, ed), res(e, ee), first, second);
        close(c);
    }
    // L3: SO_ERROR takes it.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        int e1 = sock_error(c), e2 = sock_error(c);
        ssize_t b = take(c, buf, sizeof buf, 0); int eb = errno;
        printf("L3 connected to an unheld port, after a send: SO_ERROR=%d then %d; recv=%s\n", e1, e2, res(b, eb));
        close(c);
    }
    // L4: unconnected sendto a port nobody holds.
    {
        int u = bound();
        ssize_t a = send_to(u, "x", 1, unheld_port()); int ea = errno;
        SETTLE();
        const char *p = revents(u);
        ssize_t b = take(u, buf, sizeof buf, 0); int eb = errno;
        ssize_t d = send_to(u, "x", 1, unheld_port()); int ed = errno;
        printf("L4 unconnected sendto an unheld port: %s; then %s; recv=%s; sendto again=%s; SO_ERROR=%d\n", res(a, ea), p, res(b, eb), res(d, ed), sock_error(u));
        close(u);
    }
    // L5: the error and a datagram both waiting.
    {
        uint16_t x = unheld_port();
        int c = bound();
        struct sockaddr_in to = lo(x);
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        int q = udp();
        struct sockaddr_in qa = lo(x);
        int bq = bind(q, (struct sockaddr *)&qa, sizeof qa);
        send_to(q, "data", 4, portof(c)); SETTLE();
        int fion = fionread(c);
        const char *level = revents(c);
        const char *got = drain_text(c);
        int after = sock_error(c);
        printf("L5 an error pending, then the peer binds (%d) and sends 'data': FIONREAD=%d; %s; c receives %s; SO_ERROR=%d\n", bq, fion, level, got, after);
        close(c); close(q);
    }
    // L6: write(2) and read(2) see the error too.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        write(c, "x", 1); SETTLE();
        ssize_t a = write(c, "x", 1); int ea = errno;
        SETTLE();
        int fl = fcntl(c, F_GETFL);
        fcntl(c, F_SETFL, fl | O_NONBLOCK);
        ssize_t b = read(c, buf, sizeof buf); int eb = errno;
        fcntl(c, F_SETFL, fl);
        printf("L6 write then write: %s; read after the second write's error=%s\n", res(a, ea), res(b, eb));
        close(c);
    }
    // L7: a connect to another address while the error is pending.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        int r = bound();
        struct sockaddr_in tr = lo(portof(r));
        int cc = connect(c, (struct sockaddr *)&tr, sizeof tr); int ec = errno;
        struct sockaddr_in peer;
        socklen_t pl = sizeof peer;
        int gp = getpeername(c, (struct sockaddr *)&peer, &pl);
        printf("L7 an error pending, then connect elsewhere (to port %u): %s; SO_ERROR=%d; getpeername %d port %u\n", portof(r), res(cc, ec), sock_error(c), gp, ntohs(peer.sin_port));
        close(c); close(r);
    }
    // L8: an error pending, then sendto the same unheld port from the connected socket's peer address on Linux; on recv the zero-length buffer.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        ssize_t a = take(c, buf, 0, 0); int ea = errno;
        printf("L8 an error pending, recv of 0: %s; SO_ERROR=%d\n", res(a, ea), sock_error(c));
        close(c);
    }
    // L9: a blocking recv on the connected socket, woken by its own send's error.
    {
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        int fd2 = dup(c);
        if (fork() == 0) {
            usleep(100000);
            send(fd2, "x", 1, 0);
            _exit(0);
        }
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_alarm;
        sigaction(SIGALRM, &sa, NULL);
        alarm(1);
        ssize_t a = recv(c, buf, sizeof buf, 0); int ea = errno;
        alarm(0);
        while (waitpid(-1, NULL, WNOHANG) > 0) {}
        printf("L9 a blocking recv; another process sends through the socket at 100 ms: %s\n", res(a, ea));
        close(c); close(fd2);
    }
    // L10: the ICMP error on a socket bound to the wildcard and connected.
    {
        int c = bound_any();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        printf("L10 bound 0.0.0.0, connected to an unheld port, after a send: SO_ERROR=%d\n", sock_error(c));
        close(c);
    }
    // L12: the only socket at the port is connected to someone else.
    {
        int x = bound(), other = bound();
        struct sockaddr_in to = lo(portof(other));
        connect(x, (struct sockaddr *)&to, sizeof to);
        int c = bound();
        struct sockaddr_in tx = lo(portof(x));
        connect(c, (struct sockaddr *)&tx, sizeof tx);
        send(c, "x", 1, 0); SETTLE();
        printf("L12 connected to a port whose only socket is connected elsewhere, after a send: SO_ERROR=%d; that socket holds %s\n", sock_error(c), drain(x));
        close(c); close(x); close(other);
    }
    // L13: the receiver's queue is full.
    {
        int x = bound();
        int c = bound();
        struct sockaddr_in tx = lo(portof(x));
        connect(c, (struct sockaddr *)&tx, sizeof tx);
        static char big[9000];
        int sent = 0;
        for (int k = 0; k < 400; k++) if (send(c, big, sizeof big, 0) >= 0) sent++;
        SETTLE();
        printf("L13 connected, the receiver's queue overfilled with %d sends: SO_ERROR=%d\n", sent, sock_error(c));
        close(c); close(x);
    }
    // L14: zero-length calls with the error pending, each on a socket of its own.
    for (int call = 0; call < 4; call++) {
        static const char *names[] = { "read of 0", "read of 0 into NULL", "write of 0", "send of 0" };
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        int fl = fcntl(c, F_GETFL);
        fcntl(c, F_SETFL, fl | O_NONBLOCK);
        ssize_t a;
        switch (call) {
        case 0: a = read(c, buf, 0); break;
        case 1: a = read(c, NULL, 0); break;
        case 2: a = write(c, buf, 0); break;
        default: a = send(c, buf, 0, 0); break;
        }
        int ea = errno;
        fcntl(c, F_SETFL, fl);
        int after = sock_error(c);
        printf("L14 an error pending, %s: %s; then SO_ERROR=%d\n", names[call], res(a, ea), after);
        close(c);
    }
    // L15: connected to 127.0.0.2, which only Linux holds (as part of
    // loopback's 127.0.0.0/8): at a port a socket bound to 0.0.0.0 holds,
    // and at a port nobody holds.
    for (int held = 1; held >= 0; held--) {
        int r = held ? bound_any() : -1;
        uint16_t p = held ? portof(r) : unheld_port();
        int c = bound_any();
        struct sockaddr_in to = at(0x7f000002, p);
        int cr = connect(c, (struct sockaddr *)&to, sizeof to); int ec = errno;
        ssize_t a = send(c, "x", 1, 0); int ea = errno;
        SETTLE();
        int after = sock_error(c);
        printf("L15 connected to 127.0.0.2 at a port %s (connect %s, from %s): send %s; SO_ERROR %d; the receiver holds %s\n",
               held ? "a 0.0.0.0-bound socket holds" : "nobody holds", res(cr, ec), nameof(c), res(a, ea), after, held ? drain(r) : "-");
        close(c);
        if (held) close(r);
    }
    // L16: which socket the error reaches, when sockets share the sender's
    // local endpoint (SO_REUSEADDR on each). A is bound to L and connected to
    // P, nobody holding P; B is bound to L too; B sends to P.
    for (int row = 0; row < 4; row++) {
        static const char *names[] = {
            "B unconnected, sendto P",
            "B connected to P too, send",
            "A connected to Q instead; B unconnected, sendto P",
            "A unconnected; B unconnected, sendto P",
        };
        int one = 1;
        int a = udp(), b = udp();
        setsockopt(a, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(b, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        uint16_t P = unheld_port(), Q = unheld_port();
        struct sockaddr_in la = lo(0), toP = lo(P), toQ = lo(Q);
        bind(a, (struct sockaddr *)&la, sizeof la);
        struct sockaddr_in L = lo(portof(a));
        int ca = 0;
        if (row == 0 || row == 1) ca = connect(a, (struct sockaddr *)&toP, sizeof toP);
        if (row == 2) ca = connect(a, (struct sockaddr *)&toQ, sizeof toQ);
        int bb = bind(b, (struct sockaddr *)&L, sizeof L); int eb = errno;
        ssize_t sent;
        if (row == 1) { connect(b, (struct sockaddr *)&toP, sizeof toP); sent = send(b, "x", 1, 0); }
        else sent = sendto(b, "x", 1, 0, (struct sockaddr *)&toP, sizeof toP);
        int es = errno;
        SETTLE();
        const char *levelA = revents(a);
        const char *levelB = revents(b);
        int errA = sock_error(a);
        int errB = sock_error(b);
        printf("L16 %s (A's connect %d; B's bind %s; B's send %s): A %s, B %s; SO_ERROR A %d, B %d\n", names[row], ca, res(bb, eb), res(sent, es), levelA, levelB, errA, errB);
        close(a); close(b);
        usleep(150000);
    }
    // L11: a port held by a TCP listener only.
    {
        int t = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in ta = lo(0);
        bind(t, (struct sockaddr *)&ta, sizeof ta);
        listen(t, 1);
        int c = bound();
        struct sockaddr_in to = lo(portof(t));
        connect(c, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0); SETTLE();
        printf("L11 connected to a port only a TCP listener holds, after a send: SO_ERROR=%d\n", sock_error(c));
        close(c); close(t);
    }
}

static void section_m(void)
{
    int s = bound();
    ssize_t a = send_to(s, "self", 4, portof(s)); int ea = errno;
    SETTLE();
    printf("M1 sendto own address: %s; it receives %s\n", res(a, ea), drain_text(s));
    struct sockaddr_in to = lo(portof(s));
    connect(s, (struct sockaddr *)&to, sizeof to);
    a = send(s, "self2", 5, 0); ea = errno;
    SETTLE();
    printf("M2 connected to itself, send: %s; it receives %s\n", res(a, ea), drain_text(s));
    close(s);
}

static void try_dest(const char *label, const void *addr, socklen_t len, int receiver)
{
    int s = udp();
    ssize_t a = sendto(s, "n", 1, 0, (const struct sockaddr *)addr, len); int ea = errno;
    SETTLE();
    printf("N %s: %s; afterwards getsockname=%s; receiver holds %s\n", label, res(a, ea), nameof(s), receiver >= 0 ? drain(receiver) : "-");
    close(s);
}

static void section_n(void)
{
    int r = bound_any();
    uint16_t p = portof(r);
    struct sockaddr_in good = lo(p);
    unsigned char raw[200];
    try_dest("NULL address, length 0", NULL, 0, r);
    try_dest("good address, length 0", &good, 0, r);
    try_dest("good address, length 8", &good, 8, r);
    try_dest("good address, length 15", &good, 15, r);
    try_dest("good address, length 16", &good, 16, r);
    memset(raw, 0, sizeof raw); memcpy(raw, &good, sizeof good);
    try_dest("good address, length 17", raw, 17, r);
    try_dest("good address, length 128", raw, 128, r);
    try_dest("good address, length 129", raw, 129, r);
    try_dest("good address, length 200", raw, 200, r);
    try_dest("unmapped address, length 16", (void *)1, 16, r);
    try_dest("NULL address, length 16", NULL, 16, r);
    {
        struct sockaddr_in a = good; a.sin_family = AF_UNSPEC;
        try_dest("AF_UNSPEC, length 16", &a, 16, r);
        a.sin_family = AF_INET6;
        try_dest("AF_INET6 in a sockaddr_in, length 16", &a, 16, r);
        a.sin_family = 99;
        try_dest("family 99, length 16", &a, 16, r);
    }
    {
        struct sockaddr_in6 a6;
        memset(&a6, 0, sizeof a6);
#ifdef __APPLE__
        a6.sin6_len = sizeof a6;
#endif
        a6.sin6_family = AF_INET6;
        a6.sin6_port = htons(p);
        a6.sin6_addr = in6addr_loopback;
        try_dest("AF_INET6 ::1, length 28", &a6, sizeof a6, r);
    }
    {
        struct sockaddr_in a = lo(0);
        try_dest("127.0.0.1 port 0", &a, 16, r);
        a = at(INADDR_ANY, p);
        try_dest("0.0.0.0 at the receiver's port", &a, 16, r);
        a = at(0x7f000002, p);
        try_dest("127.0.0.2 at the receiver's port (receiver bound 0.0.0.0)", &a, 16, r);
        a = at(INADDR_BROADCAST, p);
        try_dest("255.255.255.255", &a, 16, r);
        a = good;
        memset(a.sin_zero, 0xff, sizeof a.sin_zero);
        try_dest("good address, sin_zero 0xff", &a, 16, r);
#ifdef __APPLE__
        a = good; a.sin_len = 0;
        try_dest("good address, sin_len 0", &a, 16, r);
        a = good; a.sin_len = 255;
        try_dest("good address, sin_len 255", &a, 16, r);
        a = good; a.sin_len = 8;
        try_dest("good address, sin_len 8", &a, 16, r);
#endif
    }
    {
        // 127.0.0.2 to a receiver bound to 127.0.0.1.
        int r1 = bound();
        struct sockaddr_in a = at(0x7f000002, portof(r1));
        try_dest("127.0.0.2 at a receiver bound 127.0.0.1", &a, 16, r1);
        close(r1);
    }
    {
        // The source a sender bound to 0.0.0.0 shows when sending to 127.0.0.2.
        int s = bound_any();
        struct sockaddr_in a = at(0x7f000002, p);
        sendto(s, "z", 1, 0, (struct sockaddr *)&a, sizeof a);
        SETTLE();
        struct sockaddr_in from;
        socklen_t len = sizeof from;
        char buf[8];
        ssize_t g = take(r, buf, sizeof buf, 0) ;
        (void)g;
        // re-send to read the source
        sendto(s, "z", 1, 0, (struct sockaddr *)&a, sizeof a);
        SETTLE();
        g = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &len); int eg = errno;
        if (g >= 0)
            printf("N source seen for a send to 127.0.0.2 from a 0.0.0.0-bound sender: %s from %s:%u\n", res(g, eg), inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        else
            printf("N source seen for a send to 127.0.0.2 from a 0.0.0.0-bound sender: %s, so no source\n", res(g, eg));
        close(s);
    }
    // Descriptors that are not UDP sockets.
    {
        int pfd[2];
        pipe(pfd);
        ssize_t a = sendto(pfd[1], "x", 1, 0, (struct sockaddr *)&good, sizeof good); int ea = errno;
        ssize_t b = sendto(999, "x", 1, 0, (struct sockaddr *)&good, sizeof good); int eb = errno;
        ssize_t c = sendto(999, (void *)1, 1, 0, (struct sockaddr *)&good, sizeof good); int ec = errno;
        ssize_t d = sendto(999, "x", 1, 0, (void *)1, 16); int ed = errno;
        printf("N sendto a pipe: %s; a closed descriptor: %s; a closed descriptor with an unmapped buffer: %s; with an unmapped address: %s\n", res(a, ea), res(b, eb), res(c, ec), res(d, ed));
        char buf[8];
        struct sockaddr_in from;
        socklen_t len = sizeof from;
        a = recvfrom(pfd[0], buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &len); ea = errno;
        b = recvfrom(999, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &len); eb = errno;
        printf("N recvfrom a pipe: %s; a closed descriptor: %s\n", res(a, ea), res(b, eb));
        close(pfd[0]); close(pfd[1]);
    }
    close(r);
}

static void hex(const unsigned char *b, int n, char *out)
{
    out[0] = 0;
    for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static void section_o(void)
{
    int r = bound(), s = bound();
    printf("O0 sender is %s\n", nameof(s));
    socklen_t lens[] = { 0, 1, 2, 4, 8, 15, 16, 17, 28, 128 };
    for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
        send_to(s, "src", 3, portof(r)); SETTLE();
        unsigned char addr[160];
        memset(addr, 0xaa, sizeof addr);
        socklen_t len = lens[i];
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)addr, &len); int ea = errno;
        char h[400];
        hex(addr, 20, h);
        printf("O1 addrlen %u: %s; addrlen out %u; first 20 bytes %s\n", (unsigned)lens[i], res(a, ea), (unsigned)len, h);
    }
    {
        send_to(s, "src", 3, portof(r)); SETTLE();
        socklen_t len = 16;
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, NULL, &len); int ea = errno;
        printf("O2 NULL address, addrlen 16: %s; addrlen out %u\n", res(a, ea), (unsigned)len);
    }
    {
        send_to(s, "src", 3, portof(r)); SETTLE();
        unsigned char addr[32];
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)addr, NULL); int ea = errno;
        printf("O3 an address, NULL addrlen: %s; then the queue holds %s\n", res(a, ea), drain(r));
    }
    {
        send_to(s, "src", 3, portof(r)); SETTLE();
        unsigned char addr[32];
        socklen_t len = (socklen_t)-1;
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)addr, &len); int ea = errno;
        printf("O4 addrlen 0xffffffff: %s; addrlen out %u; then the queue holds %s\n", res(a, ea), (unsigned)len, drain(r));
    }
    {
        send_to(s, "src", 3, portof(r)); SETTLE();
        socklen_t len = 16;
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (void *)1, &len); int ea = errno;
        printf("O5 unmapped address, addrlen 16: %s; then the queue holds %s\n", res(a, ea), drain(r));
    }
    {
        send_to(s, "src", 3, portof(r)); SETTLE();
        unsigned char addr[32];
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)addr, (void *)1); int ea = errno;
        printf("O6 an address, unmapped addrlen: %s; then the queue holds %s\n", res(a, ea), drain(r));
    }
    {
        unsigned char addr[32];
        memset(addr, 0xaa, sizeof addr);
        socklen_t len = 99;
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)addr, &len); int ea = errno;
        char h[80];
        hex(addr, 16, h);
        printf("O7 an empty queue, addrlen 99: %s; addrlen out %u; address %s\n", res(a, ea), (unsigned)len, h);
    }
    {
        // A connected receiver also reports the source.
        struct sockaddr_in to = lo(portof(s));
        connect(r, (struct sockaddr *)&to, sizeof to);
        send_to(s, "src", 3, portof(r)); SETTLE();
        struct sockaddr_in from;
        memset(&from, 0, sizeof from);
        socklen_t len = sizeof from;
        char buf[16];
        ssize_t a = recvfrom(r, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &len); int ea = errno;
        printf("O8 a connected receiver: %s from %s:%u len %u\n", res(a, ea), inet_ntoa(from.sin_addr), ntohs(from.sin_port), (unsigned)len);
    }
    close(r); close(s);
}

static void section_p(void)
{
    int r = bound(), s = bound();
    uint16_t p = portof(r);
    char data[100];
    for (int i = 0; i < 100; i++) data[i] = (char)('A' + i % 26);
    // P1: scatter over two iovecs, and the flags out.
    {
        send_to(s, data, 6, p); SETTLE();
        char a[4], b[4];
        memset(a, '.', 4); memset(b, '.', 4);
        struct iovec iov[2] = { { a, 4 }, { b, 4 } };
        struct sockaddr_in from;
        unsigned char ctl[64];
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_name = &from; m.msg_namelen = sizeof from;
        m.msg_iov = iov; m.msg_iovlen = 2;
        m.msg_control = ctl; m.msg_controllen = sizeof ctl;
        m.msg_flags = 0x7fffffff;
        ssize_t got = recvmsg(r, &m, 0); int e = errno;
        printf("P1 recvmsg, iovecs of 4 and 4, datagram of 6: %s; contents %.4s|%.4s; namelen %u; controllen %u; flags 0x%x\n",
               res(got, e), a, b, (unsigned)m.msg_namelen, (unsigned)m.msg_controllen, m.msg_flags);
    }
    // P2: truncation flags.
    {
        send_to(s, data, 100, p); SETTLE();
        char a[10];
        struct iovec iov = { a, 10 };
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = 1;
        ssize_t got = recvmsg(r, &m, 0); int e = errno;
        printf("P2 recvmsg of 10, datagram of 100: %s; flags 0x%x (MSG_TRUNC is 0x%x)\n", res(got, e), m.msg_flags, MSG_TRUNC);
        send_to(s, data, 100, p); SETTLE();
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = 1;
        got = recvmsg(r, &m, MSG_TRUNC); e = errno;
        printf("P3 recvmsg of 10 with MSG_TRUNC, datagram of 100: %s; flags 0x%x\n", res(got, e), m.msg_flags);
        send_to(s, data, 5, p); SETTLE();
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = 1;
        m.msg_flags = 0x7fffffff;
        got = recvmsg(r, &m, MSG_DONTWAIT); e = errno;
        printf("P3a recvmsg of 10 with MSG_DONTWAIT (0x%x), datagram of 5: %s; flags 0x%x\n", MSG_DONTWAIT, res(got, e), m.msg_flags);
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = 1;
        m.msg_flags = 0x7fffffff;
        got = recvmsg(r, &m, MSG_DONTWAIT); e = errno;
        printf("P3b recvmsg with MSG_DONTWAIT, empty queue: %s; flags 0x%x\n", res(got, e), m.msg_flags);
        send_to(s, data, 5, p); SETTLE();
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = 1;
        got = recvmsg(r, &m, MSG_PEEK); e = errno;
        printf("P3c recvmsg with MSG_PEEK (0x%x), datagram of 5: %s; flags 0x%x; then %s\n", MSG_PEEK, res(got, e), m.msg_flags, drain(r));
    }
    // P4: no iovecs.
    {
        send_to(s, data, 100, p); SETTLE();
        struct msghdr m;
        memset(&m, 0, sizeof m);
        ssize_t got = recvmsg(r, &m, 0); int e = errno;
        printf("P4 recvmsg with no iovecs, datagram of 100: %s; flags 0x%x; then the queue holds %s\n", res(got, e), m.msg_flags, drain(r));
    }
    // P5: msg_name NULL with a nonzero namelen.
    {
        send_to(s, data, 5, p); SETTLE();
        char a[10];
        struct iovec iov = { a, 10 };
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_namelen = 16;
        m.msg_iov = &iov; m.msg_iovlen = 1;
        ssize_t got = recvmsg(r, &m, MSG_DONTWAIT); int e = errno;
        printf("P5 recvmsg, msg_name NULL and namelen 16: %s; namelen out %u\n", res(got, e), (unsigned)m.msg_namelen);
    }
    // P6: sendmsg gathers.
    {
        struct iovec iov[3] = { { "ab", 2 }, { "", 0 }, { "cde", 3 } };
        struct sockaddr_in to = lo(p);
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_name = &to; m.msg_namelen = sizeof to;
        m.msg_iov = iov; m.msg_iovlen = 3;
        ssize_t got = sendmsg(s, &m, 0); int e = errno;
        SETTLE();
        printf("P6 sendmsg of iovecs 'ab', '', 'cde': %s; the receiver gets %s\n", res(got, e), drain_text(r));
    }
    // P7: sendmsg with no name on an unconnected socket, and with no iovecs.
    {
        struct iovec iov = { "x", 1 };
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_iov = &iov; m.msg_iovlen = 1;
        ssize_t got = sendmsg(s, &m, 0); int e = errno;
        struct sockaddr_in to = lo(p);
        struct msghdr m2;
        memset(&m2, 0, sizeof m2);
        m2.msg_name = &to; m2.msg_namelen = sizeof to;
        ssize_t got2 = sendmsg(s, &m2, 0); int e2 = errno;
        SETTLE();
        printf("P7 sendmsg with no name: %s; with no iovecs: %s; the receiver holds %s\n", res(got, e), res(got2, e2), drain(r));
    }
    // P8: an empty control buffer with a nonzero length on send.
    {
        struct iovec iov = { "x", 1 };
        struct sockaddr_in to = lo(p);
        unsigned char ctl[16];
        memset(ctl, 0, sizeof ctl);
        struct msghdr m;
        memset(&m, 0, sizeof m);
        m.msg_name = &to; m.msg_namelen = sizeof to;
        m.msg_iov = &iov; m.msg_iovlen = 1;
        m.msg_control = ctl; m.msg_controllen = sizeof ctl;
        ssize_t got = sendmsg(s, &m, 0); int e = errno;
        SETTLE();
        printf("P8 sendmsg with 16 zero bytes of control: %s; the receiver holds %s\n", res(got, e), drain(r));
    }
    close(r); close(s);
}

static void section_q(void)
{
    char buf[64];
    for (int opt = 0; opt < 2; opt++) {
        int one = 1;
        int name = opt == 0 ? SO_REUSEADDR : SO_REUSEPORT;
        int a = udp(), b = udp();
        setsockopt(a, SOL_SOCKET, name, &one, sizeof one);
        setsockopt(b, SOL_SOCKET, name, &one, sizeof one);
        struct sockaddr_in la = lo(0);
        bind(a, (struct sockaddr *)&la, sizeof la);
        struct sockaddr_in lb = lo(portof(a));
        int bb = bind(b, (struct sockaddr *)&lb, sizeof lb); int eb = errno;
        int s = udp();
        for (int k = 0; k < 8; k++) send_to(s, "q", 1, portof(a));
        SETTLE();
        int ga = 0, gb = 0;
        while (take(a, buf, sizeof buf, 0) >= 0) ga++;
        while (take(b, buf, sizeof buf, 0) >= 0) gb++;
        printf("Q1 two sockets on 127.0.0.1:p with %s (second bind %s); 8 datagrams from one sender: first bound got %d, second %d\n",
               opt == 0 ? "SO_REUSEADDR" : "SO_REUSEPORT", res(bb, eb), ga, gb);
        // Eight senders.
        int ga2 = 0, gb2 = 0;
        for (int k = 0; k < 8; k++) { int t = udp(); send_to(t, "q", 1, portof(a)); close(t); }
        SETTLE();
        while (take(a, buf, sizeof buf, 0) >= 0) ga2++;
        while (take(b, buf, sizeof buf, 0) >= 0) gb2++;
        printf("Q2 the same, 8 datagrams from 8 senders: first bound got %d, second %d\n", ga2, gb2);
        close(a); close(b); close(s);
    }
    // Wildcard and specific on one port.
    for (int order = 0; order < 2; order++) {
        int one = 1;
        int any = udp(), spec = udp();
        setsockopt(any, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(spec, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        int first = order == 0 ? any : spec;
        int second = order == 0 ? spec : any;
        struct sockaddr_in f = order == 0 ? at(INADDR_ANY, 0) : lo(0);
        bind(first, (struct sockaddr *)&f, sizeof f);
        uint16_t p = portof(first);
        struct sockaddr_in g = order == 0 ? lo(p) : at(INADDR_ANY, p);
        int bs = bind(second, (struct sockaddr *)&g, sizeof g); int es = errno;
        int s = udp();
        for (int k = 0; k < 4; k++) send_to(s, "q", 1, p);
        SETTLE();
        int gany = 0, gspec = 0;
        while (take(any, buf, sizeof buf, 0) >= 0) gany++;
        while (take(spec, buf, sizeof buf, 0) >= 0) gspec++;
        printf("Q3 %s bound first, the other second (%s), SO_REUSEADDR on both; 4 datagrams to 127.0.0.1: 0.0.0.0 got %d, 127.0.0.1 got %d\n",
               order == 0 ? "0.0.0.0" : "127.0.0.1", res(bs, es), gany, gspec);
        close(any); close(spec); close(s);
    }
    // A connected socket and an unconnected one on one port.
    {
        int one = 1;
        int a = udp(), b = udp();
        setsockopt(a, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        setsockopt(b, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in la = lo(0);
        bind(a, (struct sockaddr *)&la, sizeof la);
        struct sockaddr_in lb = lo(portof(a));
        bind(b, (struct sockaddr *)&lb, sizeof lb);
        int s = bound(), t = bound();
        struct sockaddr_in ts = lo(portof(s));
        connect(a, (struct sockaddr *)&ts, sizeof ts);
        for (int k = 0; k < 4; k++) { send_to(s, "s", 1, portof(a)); send_to(t, "t", 1, portof(a)); }
        SETTLE();
        printf("Q4 a (first bound, connected to s) and b (unconnected) share a port; s and t each send 4: a got %s; b got %s\n", drain_text(a), drain_text(b));
        close(a); close(b); close(s); close(t);
    }
}

static void section_q5(void)
{
    // A socket connected to s holds the port; a second binds the same endpoint
    // with SO_REUSEADDR after the first connected.
    int one = 1;
    int a = udp(), b = udp();
    setsockopt(a, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    setsockopt(b, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in la = lo(0);
    bind(a, (struct sockaddr *)&la, sizeof la);
    int s = bound(), t = bound();
    struct sockaddr_in ts = lo(portof(s));
    connect(a, (struct sockaddr *)&ts, sizeof ts);
    struct sockaddr_in lb = lo(portof(a));
    int bb = bind(b, (struct sockaddr *)&lb, sizeof lb); int eb = errno;
    for (int k = 0; k < 4; k++) { send_to(s, "s", 1, portof(a)); send_to(t, "t", 1, portof(a)); }
    SETTLE();
    printf("Q5 a (connected to s) holds the port; b binds it after (%s); s and t each send 4: a got %s; b got %s\n", res(bb, eb), drain_text(a), drain_text(b));
    close(a); close(b); close(s); close(t);
}

static int sleepers_done = 0;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int done_count(void) { pthread_mutex_lock(&mu); int v = sleepers_done; pthread_mutex_unlock(&mu); return v; }
static void done_reset(void) { pthread_mutex_lock(&mu); sleepers_done = 0; pthread_mutex_unlock(&mu); }
static void on_usr1(int sig) { (void)sig; }
struct sleeper { int fd; int flags; ssize_t ret; int err; };
static void *sleep_recv(void *p)
{
    struct sleeper *s = p;
    char buf[16];
    s->ret = recv(s->fd, buf, sizeof buf, s->flags);
    s->err = errno;
    pthread_mutex_lock(&mu); sleepers_done++; pthread_mutex_unlock(&mu);
    return NULL;
}

static void section_s(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);
    int r = bound(), s = udp();
    struct sleeper sl[3];
    pthread_t th[3];
    done_reset();
    for (int i = 0; i < 3; i++) { sl[i].fd = r; sl[i].flags = 0; sl[i].ret = -2; pthread_create(&th[i], NULL, sleep_recv, &sl[i]); }
    usleep(100000);
    send_to(s, "one", 3, portof(r));
    usleep(100000);
    int after_one = done_count();
    send_to(s, "two", 3, portof(r));
    usleep(100000);
    int after_two = done_count();
    for (int i = 0; i < 3; i++) pthread_kill(th[i], SIGUSR1);
    for (int i = 0; i < 3; i++) pthread_join(th[i], NULL);
    printf("S1 three threads asleep in recv on one socket: after one datagram %d returned, after two %d; answers %s %s %s\n",
           after_one, after_two, res(sl[0].ret, sl[0].err), res(sl[1].ret, sl[1].err), res(sl[2].ret, sl[2].err));
    // A sleeper with a buffer of 0, woken by a datagram.
    {
        struct sleeper z;
        z.fd = r;
        z.flags = 0;
        pthread_t t;
        done_reset();
        // recv of 0 bytes: does it sleep at all?
        int fl = fcntl(r, F_GETFL);
        (void)fl;
        pthread_create(&t, NULL, sleep_recv, &z);
        usleep(100000);
        int before = done_count();
        send_to(s, "z", 1, portof(r));
        usleep(100000);
        int after = done_count();
        if (!after) pthread_kill(t, SIGUSR1);
        pthread_join(t, NULL);
        printf("S2 (control) a sleeper with buffer 16: returned before the datagram %d, after %d, answer %s\n", before, after, res(z.ret, z.err));
    }
    // S3 to S5: sleepers that peek, and peekers beside a taker, parked 50 ms
    // apart in the order given; one datagram 100 ms after the last; who has
    // returned 100 ms later, before a signal ends the rest.
    {
        static const struct { const char *name; int n; int peek[3]; } rows[] = {
            { "S3 three peekers", 3, { 1, 1, 1 } },
            { "S4 a peeker, then a taker", 2, { 1, 0 } },
            { "S5 a taker, then a peeker", 2, { 0, 1 } },
        };
        for (unsigned row = 0; row < sizeof rows / sizeof *rows; row++) {
            int r2 = bound();
            struct sleeper sp[3];
            pthread_t tp[3];
            done_reset();
            for (int i = 0; i < rows[row].n; i++) {
                sp[i].fd = r2; sp[i].flags = rows[row].peek[i] ? MSG_PEEK : 0; sp[i].ret = -2;
                pthread_create(&tp[i], NULL, sleep_recv, &sp[i]);
                usleep(50000);
            }
            usleep(50000);
            send_to(s, "one", 3, portof(r2));
            usleep(100000);
            int returned = done_count();
            for (int i = 0; i < rows[row].n; i++) pthread_kill(tp[i], SIGUSR1);
            for (int i = 0; i < rows[row].n; i++) pthread_join(tp[i], NULL);
            printf("%s: %d returned after the datagram; answers", rows[row].name, returned);
            for (int i = 0; i < rows[row].n; i++) printf(" %s%s", rows[row].peek[i] ? "peek " : "take ", res(sp[i].ret, sp[i].err));
            printf("; then the queue holds %s\n", drain(r2));
            close(r2);
        }
    }
    close(r); close(s);
}

// X: how often a connected socket's sends to a port nobody holds raise an
// ICMP error: a second send after each gap, the first error taken in
// between; sends at a steady pace; two sockets aimed at one port, and at two;
// and a burst over many sockets.
static void section_x(void)
{
#ifdef __APPLE__
    {
        int v = -1; size_t len = sizeof v;
        sysctlbyname("net.inet.icmp.icmplim", &v, &len, NULL, 0);
        printf("X0 net.inet.icmp.icmplim=%d\n", v);
    }
#else
    {
        const char *files[] = { "/proc/sys/net/ipv4/icmp_ratelimit", "/proc/sys/net/ipv4/icmp_ratemask", "/proc/sys/net/ipv4/icmp_msgs_per_sec", "/proc/sys/net/ipv4/icmp_msgs_burst" };
        for (unsigned i = 0; i < sizeof files / sizeof *files; i++) {
            char line[64] = "?";
            FILE *f = fopen(files[i], "r");
            if (f) { if (!fgets(line, sizeof line, f)) strcpy(line, "?"); fclose(f); }
            line[strcspn(line, "\n")] = 0;
            printf("X0 %s=%s\n", files[i], line);
        }
    }
#endif
    // X1: two sends `gap` ms apart, measured from the first, the first's
    // error taken in between, five times each.
    int gaps[] = { 15, 50, 85, 95, 98, 100, 102, 110, 150, 500 };
    for (unsigned i = 0; i < sizeof gaps / sizeof *gaps; i++) {
        int raised = 0, firsts = 0;
        for (int trial = 0; trial < 5; trial++) {
            usleep(300000);
            int c = bound();
            struct sockaddr_in to = lo(unheld_port());
            connect(c, (struct sockaddr *)&to, sizeof to);
            double t0 = now_ms();
            send(c, "x", 1, 0);
            usleep(10000);
            if (sock_error(c) != 0) firsts++;
            while (now_ms() - t0 < gaps[i]) usleep(100);
            send(c, "x", 1, 0);
            usleep(30000);
            if (sock_error(c) != 0) raised++;
            close(c);
        }
        printf("X1 a send raising an error, taken, and another %d ms after the first: the first raised one in %d of 5, the second in %d of 5\n", gaps[i], firsts, raised);
    }
    // X4: sends every 40 ms, each error taken before the next.
    {
        usleep(300000);
        int c = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        double t0 = now_ms();
        printf("X4 sends every 40 ms, SO_ERROR 15 ms after each:");
        for (int k = 0; k < 12; k++) {
            while (now_ms() - t0 < k * 40.0) usleep(100);
            send(c, "x", 1, 0);
            usleep(15000);
            printf(" %d", sock_error(c));
        }
        printf("\n");
        close(c);
    }
    // X5: two sockets connected to the same unheld port, sending 5 ms apart.
    {
        usleep(300000);
        int c = bound(), d = bound();
        struct sockaddr_in to = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        connect(d, (struct sockaddr *)&to, sizeof to);
        send(c, "x", 1, 0);
        usleep(5000);
        send(d, "x", 1, 0);
        usleep(50000);
        int ec = sock_error(c);
        int ed = sock_error(d);
        printf("X5 two sockets connected to one unheld port, sending 5 ms apart: SO_ERROR %d and %d\n", ec, ed);
        close(c); close(d);
    }
    {
        usleep(300000);
        int c = bound(), d = bound();
        struct sockaddr_in to = lo(unheld_port()), to2 = lo(unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        connect(d, (struct sockaddr *)&to2, sizeof to2);
        send(c, "x", 1, 0);
        usleep(5000);
        send(d, "x", 1, 0);
        usleep(50000);
        int ec = sock_error(c);
        int ed = sock_error(d);
        printf("X2 two sockets, each connected to its own unheld port, sending 5 ms apart: SO_ERROR %d and %d\n", ec, ed);
        close(c); close(d);
    }
    // X6: what the window is kept by. Each row: socket c, bound to port L,
    // connected to unheld port P, sends and has its error taken; then the
    // row's second send, 20 ms after the first.
    for (int row = 0; row < 6; row++) {
        static const char *names[] = {
            "c sends again (control)",
            "c reconnects to another unheld port Q and sends",
            "c reconnects to Q, then back to P, and sends",
            "c closes; a new socket bound to L connects to P and sends",
            "a new socket bound elsewhere connects to P and sends",
            "c disconnects (AF_UNSPEC), rebinds to L, reconnects to P and sends",
        };
        usleep(300000);
        int c = bound();
        uint16_t L = portof(c);
        uint16_t P = unheld_port(), Q = unheld_port();
        struct sockaddr_in toP = lo(P), toQ = lo(Q), atL = lo(L);
        connect(c, (struct sockaddr *)&toP, sizeof toP);
        double t0 = now_ms();
        send(c, "x", 1, 0);
        usleep(10000);
        int first = sock_error(c);
        int s2 = c;
        switch (row) {
        case 1: connect(c, (struct sockaddr *)&toQ, sizeof toQ); break;
        case 2: connect(c, (struct sockaddr *)&toQ, sizeof toQ); connect(c, (struct sockaddr *)&toP, sizeof toP); break;
        case 3: {
            close(c);
            s2 = udp();
            int one = 1;
            setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
            if (bind(s2, (struct sockaddr *)&atL, sizeof atL) != 0) printf("X6 (rebind to L failed: %s)\n", ename(errno));
            connect(s2, (struct sockaddr *)&toP, sizeof toP);
            break;
        }
        case 4: s2 = bound(); connect(s2, (struct sockaddr *)&toP, sizeof toP); break;
        case 5: {
            struct sockaddr un; memset(&un, 0, sizeof un); un.sa_family = AF_UNSPEC;
            connect(c, &un, sizeof un);
            bind(c, (struct sockaddr *)&atL, sizeof atL);
            connect(c, (struct sockaddr *)&toP, sizeof toP);
            break;
        }
        default: break;
        }
        while (now_ms() - t0 < 20) usleep(100);
        ssize_t a2 = send(s2, "x", 1, 0); int e2 = errno;
        usleep(30000);
        int second = sock_error(s2);
        printf("X6 %s: the first raised %d; the second send %s, then SO_ERROR %d; the socket is %s\n", names[row], first, res(a2, e2), second, nameof(s2));
        close(s2);
        if (row == 4) close(c);
    }
    // X7: an unconnected socket's sendto P, which reports no error, then a
    // connect to P and a send 20 ms later.
    {
        usleep(300000);
        int c = bound();
        uint16_t P = unheld_port();
        struct sockaddr_in toP = lo(P);
        double t0 = now_ms();
        sendto(c, "x", 1, 0, (struct sockaddr *)&toP, sizeof toP);
        usleep(10000);
        int first = sock_error(c);
        connect(c, (struct sockaddr *)&toP, sizeof toP);
        while (now_ms() - t0 < 20) usleep(100);
        send(c, "x", 1, 0);
        usleep(30000);
        int second = sock_error(c);
        printf("X7 an unconnected sendto an unheld port (SO_ERROR %d), then connect to it and send 20 ms later: SO_ERROR %d\n", first, second);
        close(c);
    }
    // X8: interleaved senders. Each step is a send by one of up to three
    // sockets, each connected to its own port of P, Q and R, nobody holding
    // any; 8 ms later the sender's SO_ERROR is read (and taken), and printed
    // as 1 if it held the error. "A>P" is socket A, connected to P.
    {
        static const struct { const char *name; int dest[3]; int steps; int who[4]; } rows[] = {
            { "A>P A>P A>P", { 0 }, 3, { 0, 0, 0 } },
            { "A>P B>P A>P", { 0, 0 }, 3, { 0, 1, 0 } },
            { "A>P B>Q A>P", { 0, 1 }, 3, { 0, 1, 0 } },
            { "A>P A>P B>P A>P", { 0, 0 }, 4, { 0, 0, 1, 0 } },
            { "A>P B>Q C>R A>P", { 0, 1, 2 }, 4, { 0, 1, 2, 0 } },
            { "A>P B>Q A>P B>Q", { 0, 1 }, 4, { 0, 1, 0, 1 } },
        };
        for (unsigned row = 0; row < sizeof rows / sizeof *rows; row++) {
            usleep(300000);
            uint16_t ports[3] = { unheld_port(), unheld_port(), unheld_port() };
            int socks[3] = { -1, -1, -1 };
            int nsock = 0;
            for (int k = 0; k < rows[row].steps; k++) if (rows[row].who[k] + 1 > nsock) nsock = rows[row].who[k] + 1;
            for (int i = 0; i < nsock; i++) {
                socks[i] = bound();
                struct sockaddr_in to = lo(ports[rows[row].dest[i]]);
                connect(socks[i], (struct sockaddr *)&to, sizeof to);
            }
            printf("X8 %s:", rows[row].name);
            for (int k = 0; k < rows[row].steps; k++) {
                int w = rows[row].who[k];
                send(socks[w], "x", 1, 0);
                usleep(8000);
                printf(" %c%d", 'A' + w, sock_error(socks[w]) != 0);
            }
            printf("\n");
            for (int i = 0; i < nsock; i++) close(socks[i]);
        }
    }
    {
        usleep(300000);
        int count = 80, errors = 0;
        int socks[80];
        for (int i = 0; i < count; i++) {
            socks[i] = bound();
            struct sockaddr_in to = lo(unheld_port());
            connect(socks[i], (struct sockaddr *)&to, sizeof to);
        }
        for (int i = 0; i < count; i++) send(socks[i], "x", 1, 0);
        usleep(100000);
        for (int i = 0; i < count; i++) { if (sock_error(socks[i]) != 0) errors++; close(socks[i]); }
        printf("X3 %d sockets, each connected to an unheld port, sending at once: %d errors\n", count, errors);
    }
}

static void section_w(void)
{
    char buf[64];
    int r = bound(), s = udp();
    uint16_t p = portof(r);
    struct sockaddr_in to = lo(p);
    ssize_t a = sendto(s, "o", 1, MSG_OOB, (struct sockaddr *)&to, sizeof to); int ea = errno;
    SETTLE();
    printf("W1 sendto with MSG_OOB: %s; the receiver holds %s\n", res(a, ea), drain(r));
    send_to(s, "o", 1, p); SETTLE();
    a = take(r, buf, sizeof buf, MSG_OOB); ea = errno;
    printf("W2 recv with MSG_OOB, a datagram queued: %s; then the queue holds %s\n", res(a, ea), drain(r));
    send_to(s, "hello", 5, p); SETTLE();
    a = recv(r, buf, sizeof buf, MSG_WAITALL); ea = errno;
    printf("W3 recv of 64 with MSG_WAITALL, a datagram of 5 queued: %s\n", res(a, ea));
    a = sendto(s, "n", 1, MSG_NOSIGNAL, (struct sockaddr *)&to, sizeof to); ea = errno;
    SETTLE();
    printf("W4 sendto with MSG_NOSIGNAL: %s; the receiver holds %s\n", res(a, ea), drain(r));
    a = sendto(s, "d", 1, MSG_DONTROUTE, (struct sockaddr *)&to, sizeof to); ea = errno;
    SETTLE();
    printf("W5 sendto with MSG_DONTROUTE: %s; the receiver holds %s\n", res(a, ea), drain(r));
    a = sendto(s, "d", 1, 0x40000000, (struct sockaddr *)&to, sizeof to); ea = errno;
    SETTLE();
    printf("W6 sendto with flag 0x40000000: %s; the receiver holds %s\n", res(a, ea), drain(r));
    send_to(s, "x", 1, p); SETTLE();
    a = take(r, buf, sizeof buf, 0x40000000); ea = errno;
    printf("W7 recv with flag 0x40000000, a datagram queued: %s; then the queue holds %s\n", res(a, ea), drain(r));
    // A blocking socket with MSG_DONTWAIT, empty.
    a = recv(r, buf, sizeof buf, MSG_DONTWAIT); ea = errno;
    printf("W8 recv MSG_DONTWAIT on an empty blocking socket: %s\n", res(a, ea));
    // send() on an unconnected socket.
    a = send(s, "u", 1, 0); ea = errno;
    printf("W9 send on an unconnected socket: %s\n", res(a, ea));
    close(r); close(s);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    const char *only = argc > 1 ? argv[1] : NULL;
#define RUN(c, f) if (!only || strchr(only, c)) f()
    RUN('A', section_a);
    RUN('B', section_b);
    RUN('C', section_c);
    RUN('D', section_d);
    RUN('E', section_e);
    RUN('F', section_f);
    RUN('G', section_g);
    RUN('H', section_h);
    RUN('I', section_i);
    RUN('J', section_j);
    RUN('K', section_k);
    RUN('L', section_l);
    RUN('M', section_m);
    RUN('N', section_n);
    RUN('O', section_o);
    RUN('P', section_p);
    RUN('Q', section_q);
    RUN('Q', section_q5);
    RUN('S', section_s);
    RUN('W', section_w);
    RUN('X', section_x);
    return 0;
}
