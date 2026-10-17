// What connect(2), send(2) and sendto(2) to 127.0.0.2 do: an address inside
// loopback's 127.0.0.0/8 that is not 127.0.0.1. Linux's local table holds the
// whole /8; Darwin's lo0 holds 127.0.0.1 alone, with a route to the /8.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/lac loopback-alias-connect.c && /tmp/lac [long]
//   Linux:  gcc -Wall -o /tmp/lac loopback-alias-connect.c && /tmp/lac [long]
//
// Every row makes fresh sockets. P is a port this program finds free; the
// rows print it as P.
//
// Stream rows. The listener is one of
//   W  a listener at 0.0.0.0:P      L  a listener at 127.0.0.1:P only
//   N  nothing at P
// and the client one of
//   f  fresh (unbound)    b  bound to 127.0.0.1:0    w  bound to 0.0.0.0:0
// Blocking rows (S): connect(2) to 127.0.0.2:P, cut short by a 3-second
// alarm whose handler does nothing (so a connect still waiting answers EINTR);
// then the client's getsockname, getpeername and SO_ERROR, and, if a
// listener exists, whether it has a connection to accept within a second and,
// if so, the accepted socket's getsockname and getpeername.
// Non-blocking rows (B): the same connect on an O_NONBLOCK socket; then
// poll(2) for POLLOUT for 3 seconds (the count and revents); then SO_ERROR;
// then getsockname; then connect(2) again.
// Control rows (C): a blocking connect to 127.0.0.1:P, which must succeed
// where W or L listens.
//
// Datagram rows. A receiver bound to 0.0.0.0:P (R W) or 127.0.0.1:P (R L)
// with SO_RCVTIMEO of a second. The sender is fresh and either
//   c  connect(2)s to 127.0.0.2:P and then send(2)s one byte
//   t  sendto(2)s one byte to 127.0.0.2:P
// and then the receiver's recvfrom(2) answer and the source it reports.
// Control rows (DC) send to 127.0.0.1:P instead.
//
// With the argument "long", one more row: a blocking connect from a fresh
// client to 127.0.0.2:P with a wildcard listener, with no alarm, timed.
//
// Measured 2026-10-17 with "long" on Darwin 27.0.0 arm64 (uid 501; the output
// starts with `sysctl net.inet.tcp.keepinit`, read just before) and on Linux
// 6.18.5 aarch64 (Apple `container`, gcc:14, uid 1000 through `setpriv`).
// In short:
//   Darwin, stream: every connect to 127.0.0.2 waits, whatever listens: the
//     SYN is dropped, not answered. The source is bound (127.0.0.1) first. A
//     non-blocking connect is EINPROGRESS, never writable within 3 s, with no
//     SO_ERROR, and a second connect is EALREADY. With no alarm the connect
//     fails ETIMEDOUT after 170 s.
//   Darwin, datagram: connect(2) and send(2) to 127.0.0.2 succeed, and
//     sendto(2) too, but nothing arrives, even at a wildcard receiver.
//   Linux: all of 127.0.0.0/8 is local. A wildcard listener accepts the
//     connection, its accepted end reporting 127.0.0.2, from 127.0.0.1; with
//     only a listener at 127.0.0.1, or none, the connect is refused
//     (ECONNREFUSED). Datagrams reach a wildcard receiver, from 127.0.0.1,
//     and not a receiver bound to 127.0.0.1.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static struct sockaddr_in at(const char *addr, int port)
{
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin_len = sizeof s;
#endif
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    inet_pton(AF_INET, addr, &s.sin_addr);
    return s;
}

static const char *err_name(int e)
{
    switch (e) {
    case 0: return "OK";
    case EINTR: return "EINTR";
    case EINPROGRESS: return "EINPROGRESS";
    case EALREADY: return "EALREADY";
    case EISCONN: return "EISCONN";
    case ECONNREFUSED: return "ECONNREFUSED";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case ENETUNREACH: return "ENETUNREACH";
    case EHOSTUNREACH: return "EHOSTUNREACH";
    case ENOTCONN: return "ENOTCONN";
    case EAGAIN: return "EAGAIN";
    case EINVAL: return "EINVAL";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static int P;

static void must(int ok, const char *what)
{
    if (!ok) { fprintf(stderr, "%s: %s\n", what, strerror(errno)); exit(2); }
}

static const char *endpoint(struct sockaddr_in *s)
{
    static char bufs[4][64];
    static int which = 0;
    char *buf = bufs[which++ % 4];
    char a[32];
    inet_ntop(AF_INET, &s->sin_addr, a, sizeof a);
    int port = ntohs(s->sin_port);
    if (port == P) snprintf(buf, 64, "%s:P", a);
    else if (port == 0) snprintf(buf, 64, "%s:0", a);
    else snprintf(buf, 64, "%s:eph", a);
    return buf;
}

static const char *name_of(int fd, int peer)
{
    struct sockaddr_in s;
    socklen_t len = sizeof s;
    memset(&s, 0, sizeof s);
    int r = peer ? getpeername(fd, (struct sockaddr *)&s, &len) : getsockname(fd, (struct sockaddr *)&s, &len);
    if (r != 0) return err_name(errno);
    return endpoint(&s);
}

static int so_error(int fd)
{
    int e = -1;
    socklen_t len = sizeof e;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &len);
    return e;
}

static void on_alarm(int sig) { (void)sig; }

static int find_port(void)
{
    // A port free for both kinds at the wildcard.
    for (;;) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = at("0.0.0.0", 0);
        must(bind(s, (struct sockaddr *)&a, sizeof a) == 0, "bind for a port");
        socklen_t len = sizeof a;
        getsockname(s, (struct sockaddr *)&a, &len);
        int port = ntohs(a.sin_port);
        close(s);
        int d = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in b = at("0.0.0.0", port);
        int ok = bind(d, (struct sockaddr *)&b, sizeof b) == 0;
        close(d);
        if (ok) return port;
    }
}

static int listener(char kind)
{
    if (kind == 'N') return -1;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = at(kind == 'W' ? "0.0.0.0" : "127.0.0.1", P);
    must(bind(l, (struct sockaddr *)&a, sizeof a) == 0, "bind listener");
    must(listen(l, 8) == 0, "listen");
    return l;
}

static int client(char kind)
{
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (kind != 'f') {
        struct sockaddr_in a = at(kind == 'b' ? "127.0.0.1" : "0.0.0.0", 0);
        must(bind(c, (struct sockaddr *)&a, sizeof a) == 0, "bind client");
    }
    return c;
}

static void report_accept(int l)
{
    if (l < 0) return;
    struct pollfd p = { l, POLLIN, 0 };
    int n = poll(&p, 1, 1000);
    if (n <= 0) { printf(" | accept: nothing queued"); return; }
    int a = accept(l, NULL, NULL);
    if (a < 0) { printf(" | accept=%s", err_name(errno)); return; }
    printf(" | accepted local=%s peer=%s", name_of(a, 0), name_of(a, 1));
    close(a);
}

static void stream_blocking(const char *label, const char *dest, char lk, char ck)
{
    int l = listener(lk);
    int c = client(ck);
    struct sockaddr_in d = at(dest, P);
    alarm(3);
    int r = connect(c, (struct sockaddr *)&d, sizeof d);
    int e = r == 0 ? 0 : errno;
    alarm(0);
    printf("%s%c%c connect %s:P=%s local=%s peer=%s SO_ERROR=%s", label, lk, ck, dest, err_name(e),
           name_of(c, 0), name_of(c, 1), err_name(so_error(c)));
    report_accept(l);
    printf("\n");
    close(c);
    if (l >= 0) close(l);
}

static void stream_nonblocking(char lk, char ck)
{
    int l = listener(lk);
    int c = client(ck);
    fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
    struct sockaddr_in d = at("127.0.0.2", P);
    int r = connect(c, (struct sockaddr *)&d, sizeof d);
    int e = r == 0 ? 0 : errno;
    struct pollfd p = { c, POLLOUT, 0 };
    int n = poll(&p, 1, 3000);
    int se = so_error(c);
    const char *local = name_of(c, 0);
    int r2 = connect(c, (struct sockaddr *)&d, sizeof d);
    int e2 = r2 == 0 ? 0 : errno;
    printf("B%c%c connect=%s poll=%d/0x%x SO_ERROR=%s local=%s again=%s", lk, ck, err_name(e), n, n > 0 ? p.revents : 0,
           err_name(se), local, err_name(e2));
    report_accept(l);
    printf("\n");
    close(c);
    if (l >= 0) close(l);
}

static void datagram(const char *label, const char *dest, char rk, char how)
{
    int r = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in ra = at(rk == 'W' ? "0.0.0.0" : "127.0.0.1", P);
    must(bind(r, (struct sockaddr *)&ra, sizeof ra) == 0, "bind receiver");
    struct timeval tv = { 1, 0 };
    setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in d = at(dest, P);
    char byte = 'x';
    printf("%s%c%c %s:P", label, rk, how, dest);
    if (how == 'c') {
        int c = connect(s, (struct sockaddr *)&d, sizeof d);
        printf(" connect=%s", err_name(c == 0 ? 0 : errno));
        ssize_t w = send(s, &byte, 1, 0);
        printf(" send=%s", w == 1 ? "OK" : err_name(errno));
    } else {
        ssize_t w = sendto(s, &byte, 1, 0, (struct sockaddr *)&d, sizeof d);
        printf(" sendto=%s", w == 1 ? "OK" : err_name(errno));
    }
    printf(" local=%s", name_of(s, 0));
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    memset(&from, 0, sizeof from);
    char got;
    ssize_t n = recvfrom(r, &got, 1, 0, (struct sockaddr *)&from, &fl);
    if (n == 1) printf(" recvfrom=OK from=%s", endpoint(&from));
    else printf(" recvfrom=%s", err_name(errno));
    printf("\n");
    close(s);
    close(r);
}

int main(int argc, char **argv)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    printf("uid=%d\n", (int)getuid());
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);
    P = find_port();

    const char lks[] = { 'W', 'L', 'N' };
    const char cks[] = { 'f', 'b', 'w' };
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            stream_blocking("S", "127.0.0.2", lks[i], cks[j]);
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            stream_nonblocking(lks[i], cks[j]);
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 3; j++)
            stream_blocking("C", "127.0.0.1", lks[i], cks[j]);

    const char rks[] = { 'W', 'L' };
    const char hows[] = { 'c', 't' };
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++)
            datagram("D", "127.0.0.2", rks[i], hows[j]);
    for (int i = 0; i < 2; i++)
        for (int j = 0; j < 2; j++)
            datagram("DC", "127.0.0.1", rks[i], hows[j]);

    if (argc > 1 && strcmp(argv[1], "long") == 0) {
        int l = listener('W');
        int c = client('f');
        struct sockaddr_in d = at("127.0.0.2", P);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int r = connect(c, (struct sockaddr *)&d, sizeof d);
        int e = r == 0 ? 0 : errno;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        printf("TWf connect 127.0.0.2:P=%s after %lds local=%s\n", err_name(e), (long)(t1.tv_sec - t0.tv_sec),
               name_of(c, 0));
        close(c);
        close(l);
    }
    return 0;
}
