// What each call does with an ICMP error pending at a connected UDP socket,
// beyond `udp-transfer.c` section L: the connects that fail or dissolve, the
// sends that fail for another reason as well, and the calls that might or
// might not take the error. Plan: docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   Darwin: cc -Wall -O0 -o /tmp/ue udp-error.c && /tmp/ue
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c
//             'gcc -Wall -O0 -o /tmp/ue /probe/udp-error.c && /tmp/ue'
//
// Every row starts from a fresh socket bound to 127.0.0.1, connected to a
// port nobody holds, that has sent one byte there and waited 20 ms for the
// error (Darwin's arrives a moment after the send returns), and confirms the
// error is pending by poll: Linux reports POLLERR, Darwin POLLIN. A row then
// makes its call and reports its answer, and SO_ERROR after it, which says
// whether the call took the error.
//
// Rows:
//   Y0  the sysctls that decide which datagrams are answered with the error
//   Y1  connects of every kind
//   Y2  sends too large to send
//   Y3  sends from an unmapped buffer
//   Y4  receives into an unmapped buffer, nothing queued
//   Y5  FIONREAD, getsockname, getpeername, bind, and SO_ERROR's own buffers
//   Y6  a send with the error pending
//   Y7  each call on a socket an AF_UNSPEC connect disconnected, the error
//       still pending
//   Y8  (Linux) epoll edges: a take after a registration, and the send that
//       raises the error
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
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#else
#include <sys/epoll.h>
#endif

static const char *ename(int e)
{
    switch (e) {
    case EAGAIN: return "EAGAIN";
    case EMSGSIZE: return "EMSGSIZE";
    case EDESTADDRREQ: return "EDESTADDRREQ";
    case EINVAL: return "EINVAL";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EACCES: return "EACCES";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EFAULT: return "EFAULT";
    case ENOTCONN: return "ENOTCONN";
    case EISCONN: return "EISCONN";
    case ENETUNREACH: return "ENETUNREACH";
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
    static char bufs[16][48];
    static int next = 0;
    char *b = bufs[next++ % 16];
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

static uint16_t portof(int s)
{
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) return 0;
    return ntohs(a.sin_port);
}

static int bound(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = at(INADDR_LOOPBACK, 0);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    return s;
}

static uint16_t unheld_port(void)
{
    int s = bound();
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

static const char *peer(int s)
{
    static char bufs[8][64];
    static int next = 0;
    char *b = bufs[next++ % 8];
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getpeername(s, (struct sockaddr *)&a, &len) != 0) snprintf(b, 64, "getpeername %s", ename(errno));
    else snprintf(b, 64, "peer %s:%u", inet_ntoa(a.sin_addr), ntohs(a.sin_port));
    return b;
}

static const char *self(int s)
{
    static char bufs[8][64];
    static int next = 0;
    char *b = bufs[next++ % 8];
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) snprintf(b, 64, "getsockname %s", ename(errno));
    else snprintf(b, 64, "self %s:%u", inet_ntoa(a.sin_addr), ntohs(a.sin_port));
    return b;
}

// A socket with ECONNREFUSED pending, or exits saying why not.
static int pending(void)
{
    int c = bound();
    struct sockaddr_in to = at(INADDR_LOOPBACK, unheld_port());
    if (connect(c, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); exit(1); }
    if (send(c, "x", 1, 0) != 1) { perror("send"); exit(1); }
    usleep(20000);
    struct pollfd p = { c, POLLIN | POLLOUT, 0 };
    poll(&p, 1, 0);
#ifdef __APPLE__
    int shown = p.revents & POLLIN;
#else
    int shown = p.revents & POLLERR;
#endif
    if (!shown) { fprintf(stderr, "no error pending: revents 0x%x\n", (unsigned)p.revents); exit(1); }
    return c;
}

static void connect_row(const char *label, const void *addr, socklen_t len)
{
    int c = pending();
    ssize_t r = connect(c, (const struct sockaddr *)addr, len); int e = errno;
    printf("Y1 %s: %s; then SO_ERROR=%d; %s; %s\n", label, res(r, e), sock_error(c), peer(c), self(c));
    close(c);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    static char big[70000];

    // Y0: the configuration the rows ran under.
#ifdef __APPLE__
    {
        const char *names[] = { "net.inet.udp.port_unreach_rlc_enable", "net.inet.udp.port_unreach_rlc_bucket_ms", "net.inet.udp.port_unreach_rlc_use_ts", "net.inet.udp.blackhole", "net.inet.icmp.suppress_icmp_port_unreach" };
        for (unsigned i = 0; i < sizeof names / sizeof *names; i++) {
            int v = -1; size_t len = sizeof v;
            if (sysctlbyname(names[i], &v, &len, NULL, 0) != 0) printf("Y0 %s: %s\n", names[i], ename(errno));
            else printf("Y0 %s=%d\n", names[i], v);
        }
    }
#else
    {
        const char *files[] = { "/proc/sys/net/ipv4/icmp_ratelimit", "/proc/sys/net/ipv4/icmp_ratemask", "/proc/sys/net/ipv4/icmp_msgs_per_sec", "/proc/sys/net/ipv4/icmp_msgs_burst", "/proc/sys/net/core/rmem_default" };
        for (unsigned i = 0; i < sizeof files / sizeof *files; i++) {
            char line[64] = "?";
            FILE *f = fopen(files[i], "r");
            if (f) { if (!fgets(line, sizeof line, f)) strcpy(line, "?"); fclose(f); }
            line[strcspn(line, "\n")] = 0;
            printf("Y0 %s=%s\n", files[i], line);
        }
    }
#endif

    // Y1: connects of every kind, with the error pending.
    {
        struct sockaddr_in other = at(INADDR_LOOPBACK, unheld_port());
        connect_row("connect elsewhere", &other, sizeof other);
    }
    {
        // The same peer again: `pending` connected to an unheld port, so
        // read it back first.
        int c = pending();
        struct sockaddr_in same;
        socklen_t len = sizeof same;
        getpeername(c, (struct sockaddr *)&same, &len);
        ssize_t r = connect(c, (struct sockaddr *)&same, sizeof same); int e = errno;
        printf("Y1 connect to the same peer: %s; then SO_ERROR=%d; %s; %s\n", res(r, e), sock_error(c), peer(c), self(c));
        close(c);
    }
    {
        struct sockaddr_in unspec = at(INADDR_LOOPBACK, 0);
        unspec.sin_family = AF_UNSPEC;
        connect_row("connect AF_UNSPEC, length 16", &unspec, sizeof unspec);
    }
    {
        struct sockaddr_in zero = at(INADDR_LOOPBACK, 0);
        connect_row("connect to 127.0.0.1:0", &zero, sizeof zero);
    }
    {
        struct sockaddr_in wrong = at(INADDR_LOOPBACK, 9);
        wrong.sin_family = 200;
        connect_row("connect with family 200", &wrong, sizeof wrong);
    }
    {
        struct sockaddr_in shortened = at(INADDR_LOOPBACK, 9);
        connect_row("connect with length 8", &shortened, 8);
    }
    {
        struct sockaddr_in broadcast = at(INADDR_BROADCAST, 9);
        connect_row("connect to 255.255.255.255:9", &broadcast, sizeof broadcast);
    }
    {
        int c = pending();
        ssize_t r = connect(c, (const struct sockaddr *)(uintptr_t)1, sizeof(struct sockaddr_in)); int e = errno;
        printf("Y1 connect from an unmapped address: %s; then SO_ERROR=%d; %s; %s\n", res(r, e), sock_error(c), peer(c), self(c));
        close(c);
    }

    // Y2: sends too large to send, with the error pending.
    {
        int sizes[] = { 9217, 65507, 65508, 65536 };
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            int c = pending();
            ssize_t r = write(c, big, sizes[i]); int e = errno;
            printf("Y2 write of %d: %s; then SO_ERROR=%d\n", sizes[i], res(r, e), sock_error(c));
            close(c);
            c = pending();
            r = send(c, big, sizes[i], 0); e = errno;
            printf("Y2 send of %d: %s; then SO_ERROR=%d\n", sizes[i], res(r, e), sock_error(c));
            close(c);
        }
    }

    // Y3: sends from an unmapped buffer, with the error pending.
    {
        int c = pending();
        ssize_t r = write(c, (const void *)(uintptr_t)1, 1); int e = errno;
        printf("Y3 write of 1 from an unmapped buffer: %s; then SO_ERROR=%d\n", res(r, e), sock_error(c));
        close(c);
        c = pending();
        r = send(c, (const void *)(uintptr_t)1, 1, 0); e = errno;
        printf("Y3 send of 1 from an unmapped buffer: %s; then SO_ERROR=%d\n", res(r, e), sock_error(c));
        close(c);
    }

    // Y4: receives into an unmapped buffer, with the error pending and
    // nothing queued.
    {
        int c = pending();
        ssize_t r = read(c, (void *)(uintptr_t)1, 1); int e = errno;
        printf("Y4 read of 1 into an unmapped buffer: %s; then SO_ERROR=%d\n", res(r, e), sock_error(c));
        close(c);
        c = pending();
        r = recv(c, (void *)(uintptr_t)1, 1, MSG_DONTWAIT); e = errno;
        printf("Y4 recv of 1 into an unmapped buffer: %s; then SO_ERROR=%d\n", res(r, e), sock_error(c));
        close(c);
    }

    // Y5: calls that report on the socket, and whether they take the error.
    {
        int c = pending();
        int v = -1;
        int r = ioctl(c, FIONREAD, &v); int e = errno;
        printf("Y5 FIONREAD: %s, value %d; then SO_ERROR=%d\n", res(r, e), v, sock_error(c));
        close(c);
        c = pending();
        const char *name = self(c);
        const char *named = peer(c);
        printf("Y5 getsockname and getpeername: %s; %s; then SO_ERROR=%d\n", name, named, sock_error(c));
        close(c);
        c = pending();
        struct sockaddr_in again = at(INADDR_LOOPBACK, 0);
        r = bind(c, (struct sockaddr *)&again, sizeof again); e = errno;
        printf("Y5 bind again: %s; then SO_ERROR=%d\n", res(r, e), sock_error(c));
        close(c);
        c = pending();
        socklen_t len = sizeof v;
        r = getsockopt(c, SOL_SOCKET, SO_ERROR, NULL, &len); e = errno;
        printf("Y5 SO_ERROR into a null value buffer: %s; then SO_ERROR=%d\n", res(r, e), sock_error(c));
        close(c);
        c = pending();
        len = 0;
        v = -1;
        r = getsockopt(c, SOL_SOCKET, SO_ERROR, &v, &len); e = errno;
        printf("Y5 SO_ERROR with length 0: %s, length %u, value %d; then SO_ERROR=%d\n", res(r, e), (unsigned)len, v, sock_error(c));
        close(c);
    }

    // Y6: a second error arriving while one is pending, then each take.
    {
        int c = pending();
        ssize_t r = send(c, "x", 1, 0); int e = errno;
        printf("Y6 a send with the error pending: %s; then SO_ERROR=%d, then SO_ERROR=%d\n", res(r, e), sock_error(c), sock_error(c));
        close(c);
    }
    // Y7: the error pending at a socket an AF_UNSPEC connect disconnected,
    // which both flavours leave pending (Y1), and what each call then answers.
    {
        struct sockaddr_in unspec = at(INADDR_LOOPBACK, 0);
        unspec.sin_family = AF_UNSPEC;
        const char *calls[] = { "write of 1", "write of 0", "send of 1", "read of 1", "read of 0", "recv of 1", "recv of 0", "connect elsewhere", "SO_ERROR" };
        for (unsigned i = 0; i < sizeof calls / sizeof *calls; i++) {
            int c = pending();
            connect(c, (struct sockaddr *)&unspec, sizeof unspec);
            char buf[8];
            ssize_t r = 0; int e = 0;
            struct sockaddr_in other = at(INADDR_LOOPBACK, unheld_port());
            switch (i) {
            case 0: r = write(c, "x", 1); break;
            case 1: r = write(c, "x", 0); break;
            case 2: r = send(c, "x", 1, 0); break;
            case 3: fcntl(c, F_SETFL, O_NONBLOCK); r = read(c, buf, 1); break;
            case 4: fcntl(c, F_SETFL, O_NONBLOCK); r = read(c, buf, 0); break;
            case 5: r = recv(c, buf, 1, MSG_DONTWAIT); break;
            case 6: r = recv(c, buf, 0, MSG_DONTWAIT); break;
            case 7: r = connect(c, (struct sockaddr *)&other, sizeof other); break;
            case 8: r = sock_error(c); break;
            }
            e = errno;
            printf("Y7 disconnected by AF_UNSPEC, then %s: %s; then SO_ERROR=%d; %s\n", calls[i], res(r, e), sock_error(c), peer(c));
            close(c);
        }
    }
#ifndef __APPLE__
    // Y8: Linux's epoll edges around the error. A registration made with the
    // error already pending, then a call that takes it; and one made before
    // the send that raises it.
    {
        const char *calls[] = { "write of 1", "recv of 1", "SO_ERROR", "connect elsewhere" };
        for (unsigned i = 0; i < sizeof calls / sizeof *calls; i++) {
            int c = pending();
            int ep = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT | EPOLLET, .data.u32 = 1 };
            epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev);
            struct epoll_event got;
            int n1 = epoll_wait(ep, &got, 1, 0); unsigned e1 = n1 > 0 ? got.events : 0;
            int n2 = epoll_wait(ep, &got, 1, 0);
            char buf[8];
            ssize_t r = 0;
            struct sockaddr_in other = at(INADDR_LOOPBACK, unheld_port());
            switch (i) {
            case 0: r = write(c, "x", 1); break;
            case 1: r = recv(c, buf, 1, MSG_DONTWAIT); break;
            case 2: r = sock_error(c); break;
            case 3: r = connect(c, (struct sockaddr *)&other, sizeof other); break;
            }
            int e = errno;
            int n3 = epoll_wait(ep, &got, 1, 0); unsigned e3 = n3 > 0 ? got.events : 0;
            printf("Y8 epoll IN|OUT|ET registered with the error pending: %d:0x%x, again %d; %s: %s; then %d:0x%x\n", n1, e1, n2, calls[i], res(r, e), n3, e3);
            close(ep); close(c);
        }
        int c = bound();
        struct sockaddr_in to = at(INADDR_LOOPBACK, unheld_port());
        connect(c, (struct sockaddr *)&to, sizeof to);
        int ep = epoll_create1(0);
        struct epoll_event ev = { .events = EPOLLIN | EPOLLOUT | EPOLLET, .data.u32 = 1 };
        epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev);
        struct epoll_event got;
        int n1 = epoll_wait(ep, &got, 1, 0); unsigned e1 = n1 > 0 ? got.events : 0;
        ssize_t r = send(c, "x", 1, 0); int e = errno;
        int n2 = epoll_wait(ep, &got, 1, 0); unsigned e2 = n2 > 0 ? got.events : 0;
        int n3 = epoll_wait(ep, &got, 1, 0);
        printf("Y8 epoll IN|OUT|ET on a socket connected to an unheld port: registered %d:0x%x; a send %s; then %d:0x%x; again %d\n", n1, e1, res(r, e), n2, e2, n3);
        close(ep); close(c);
    }
#endif
    return 0;
}
