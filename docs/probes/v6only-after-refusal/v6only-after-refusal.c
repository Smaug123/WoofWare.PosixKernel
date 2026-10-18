// What setsockopt(IPV6_V6ONLY) answers on a dual-mode IPv6 TCP socket (one
// with IPV6_V6ONLY off, talking IPv4 through v4-mapped addresses) whose
// connect(2) was refused, for each way the socket came by its port, and what
// the socket then is.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/v6r v6only-after-refusal.c && /tmp/v6r
//   Linux:  gcc -Wall -o /tmp/v6r v6only-after-refusal.c && /tmp/v6r
//
// Every row makes a fresh AF_INET6 stream socket with IPV6_V6ONLY set to 0,
// gives it its port one way, connects it to [::ffff:127.0.0.1]:1, where
// nothing is bound (so both kernels answer the SYN with a reset), and then
// sets IPV6_V6ONLY.
//
// How the socket came by its port:
//   I  connect's own implicit bind (the socket was unbound)
//   Z  bind(2) [::ffff:127.0.0.1]:0      W  bind(2) [::]:0
//   X  bind(2) [::ffff:127.0.0.1]:<port> Y  bind(2) [::]:<port>
// How the refusal arrived:
//   b  a blocking connect, which answers it
//   n  a non-blocking connect, then poll(2) until the socket reports it; the
//      refusal is still pending
//   s  as n, then an SO_ERROR read takes it
// What the row then sets:
//   1  IPV6_V6ONLY to 1
//   0  IPV6_V6ONLY to 0, the value it already has
// After the set, each row reads IPV6_V6ONLY back and prints getsockname; and
// where the set succeeded, it connects the socket twice to a listener at
// 127.0.0.1:L through [::ffff:127.0.0.1]:L (a pending refusal is answered by
// the first), printing each answer and getsockname after it.
//
// Control rows: C1 sets IPV6_V6ONLY to 1 on a fresh socket; C2 on a socket
// bound to [::ffff:127.0.0.1]:0 that has never connected.
//
// Measured 2026-10-17 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14) and
// Darwin 27.0.0 arm64 (uid 501). In short:
//   Linux takes IPV6_V6ONLY, 1 or 0, on a socket whose refusal gave its port
//   back (I, Z and W: no bind(2) chose the port), however the refusal
//   arrived, and answers EINVAL where bind(2) chose the port (X, Y), as on a
//   bound socket that never connected (C2). Turned IPv6-only, the socket
//   answers ENETUNREACH to a connect to a v4-mapped address, after reporting
//   a pending refusal first; left dual-mode, it connects.
//   Darwin answers EINVAL in every row.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

static int next_port = 45301;

static struct sockaddr_in6 at6(const char *addr, int port)
{
    struct sockaddr_in6 s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin6_len = sizeof s;
#endif
    s.sin6_family = AF_INET6;
    s.sin6_port = htons(port);
    inet_pton(AF_INET6, addr, &s.sin6_addr);
    return s;
}

static const char *err_name(int e)
{
    switch (e) {
    case 0: return "OK";
    case EINVAL: return "EINVAL";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ECONNABORTED: return "ECONNABORTED";
    case EINPROGRESS: return "EINPROGRESS";
    case EALREADY: return "EALREADY";
    case EISCONN: return "EISCONN";
    case ENETUNREACH: return "ENETUNREACH";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    case EAGAIN: return "EAGAIN";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static void name_of(int fd, char *out, size_t len)
{
    struct sockaddr_in6 s;
    socklen_t l = sizeof s;
    if (getsockname(fd, (struct sockaddr *)&s, &l) < 0) {
        snprintf(out, len, "%s", err_name(errno));
        return;
    }
    char a[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &s.sin6_addr, a, sizeof a);
    snprintf(out, len, "[%s]:%d", a, ntohs(s.sin6_port));
}

static int set_v6only(int fd, int v)
{
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof v) < 0 ? errno : 0;
}

static int get_v6only(int fd)
{
    int v = -1;
    socklen_t l = sizeof v;
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, &l) < 0) return -errno;
    return v;
}

static int dual(void)
{
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0 || set_v6only(fd, 0) != 0) {
        printf("dual-mode socket: %s\n", strerror(errno));
        exit(1);
    }
    return fd;
}

static int bind6(int fd, const char *addr, int port)
{
    struct sockaddr_in6 s = at6(addr, port);
    return bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

static int connect6(int fd, const char *addr, int port)
{
    struct sockaddr_in6 s = at6(addr, port);
    return connect(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

static int listener(int family, const char *addr, int port)
{
    int fd = socket(family, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int e;
    if (family == AF_INET6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        struct sockaddr_in6 s = at6(addr, port);
        e = bind(fd, (struct sockaddr *)&s, sizeof s);
    } else {
        struct sockaddr_in s;
        memset(&s, 0, sizeof s);
#ifdef __APPLE__
        s.sin_len = sizeof s;
#endif
        s.sin_family = AF_INET;
        s.sin_port = htons(port);
        inet_pton(AF_INET, addr, &s.sin_addr);
        e = bind(fd, (struct sockaddr *)&s, sizeof s);
    }
    if (e < 0 || listen(fd, 128) < 0) {
        printf("listener at %s:%d: %s\n", addr, port, strerror(errno));
        exit(1);
    }
    return fd;
}

static void row(char how, char arrival, int value, int L)
{
    int fd = dual();
    int e = 0;
    char label[8];
    snprintf(label, sizeof label, "%c%c%d", how, arrival, value);
    switch (how) {
    case 'Z': e = bind6(fd, "::ffff:127.0.0.1", 0); break;
    case 'W': e = bind6(fd, "::", 0); break;
    case 'X': e = bind6(fd, "::ffff:127.0.0.1", next_port++); break;
    case 'Y': e = bind6(fd, "::", next_port++); break;
    default: break;
    }
    printf("%s bind=%s", label, err_name(e));
    if (arrival != 'b') fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    e = connect6(fd, "::ffff:127.0.0.1", 1);
    printf(" connect=%s", err_name(e));
    if (arrival != 'b') {
        struct pollfd p = { fd, POLLOUT, 0 };
        int n = poll(&p, 1, 3000);
        printf(" poll=%d/0x%x", n, p.revents);
        if (arrival == 's') {
            int err = 0;
            socklen_t l = sizeof err;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l);
            printf(" SO_ERROR=%s", err_name(err));
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    }
    char name[96];
    name_of(fd, name, sizeof name);
    printf(" getsockname=%s", name);
    e = set_v6only(fd, value);
    name_of(fd, name, sizeof name);
    printf(" | IPV6_V6ONLY=%d -> %s, reads %d, getsockname=%s", value, err_name(e), get_v6only(fd), name);
    if (e == 0) {
        e = connect6(fd, "::ffff:127.0.0.1", L);
        name_of(fd, name, sizeof name);
        printf(" | connect v4-mapped listener=%s getsockname=%s", err_name(e), name);
        e = connect6(fd, "::ffff:127.0.0.1", L);
        name_of(fd, name, sizeof name);
        printf(" | again=%s getsockname=%s", err_name(e), name);
    }
    printf("\n");
    fflush(stdout);
    close(fd);
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    int L = 45201;
    int l4 = listener(AF_INET, "127.0.0.1", L);
    printf("listener at 127.0.0.1:%d\n", L);

    int fd = dual();
    int e = set_v6only(fd, 1);
    printf("C1 fresh | IPV6_V6ONLY=1 -> %s, reads %d\n", err_name(e), get_v6only(fd));
    close(fd);
    fd = dual();
    e = bind6(fd, "::ffff:127.0.0.1", 0);
    char name[96];
    name_of(fd, name, sizeof name);
    printf("C2 bind=%s getsockname=%s", err_name(e), name);
    e = set_v6only(fd, 1);
    printf(" | IPV6_V6ONLY=1 -> %s, reads %d\n", err_name(e), get_v6only(fd));
    close(fd);

    const char hows[] = "IZWXY";
    const char arrivals[] = "bns";
    for (int h = 0; hows[h]; h++)
        for (int a = 0; arrivals[a]; a++)
            for (int v = 1; v >= 0; v--) row(hows[h], arrivals[a], v, L);

    // Drain whatever the connects queued.
    close(l4);
    return 0;
}
