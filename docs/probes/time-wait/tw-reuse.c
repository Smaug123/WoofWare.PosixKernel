// Whether a new TCP connection may take over the four-tuple of a connection
// whose client is in TIME_WAIT: by a connect's own search for a port
// (Linux, rows R), and by a connect from a socket bind(2) put at the port
// (both, rows E, V and Z); and what a new connection from the client's port
// does to the server's end in TIME_WAIT (rows Q and Y).
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/twr tw-reuse.c && /tmp/twr
//   Linux:  gcc -Wall -o /tmp/twr tw-reuse.c && /tmp/twr
//
// Each row makes a connection from a client at a port T of its own to the
// listener X, closes the client and then, once the client's FIN has arrived
// (a read at the accepted socket answers end of file), the accepted socket:
// the client's end is in TIME_WAIT at T. `tw` is whether the client carried
// SO_REUSEADDR.
//
//   R<tw><s>@<d>  Linux: after d seconds, a socket carrying SO_REUSEADDR if
//                 `s`, its ephemeral range narrowed to T with
//                 IP_LOCAL_PORT_RANGE (Linux 6.3), connects to X: the
//                 search can take T only by taking over the four-tuple.
//   E<tw><s>@<d>  after d seconds, a socket carrying SO_REUSEADDR if `s`
//                 binds 127.0.0.1:T and, if that succeeds, connects to X.
//                 Darwin takes the client's port by the sequence its
//                 implicit ports follow, aimed by refused connects to
//                 127.0.0.1:1.
//   V<tw>1@1.5    as E, the socket carrying SO_REUSEADDR and bound to
//                 0.0.0.0:T, printing the address getsockname reports after.
//   Z<tw><how>    the client's connection was to a listener Z of the
//                 row's own, closed once the TIME_WAIT is entered; after 1.5
//                 s a socket carrying SO_REUSEADDR connects to Z, by a
//                 search narrowed to T (s, Linux) or bound to 127.0.0.1:T
//                 (e); then a fresh socket binds 127.0.0.1:T without
//                 SO_REUSEADDR, to see whether the TIME_WAIT is still there.
//   Q<how>@<d>    the accepted socket closed first, so the server's end is
//                 in TIME_WAIT towards the client's port T; after d seconds,
//                 a socket carrying SO_REUSEADDR connects from T to X again,
//                 by a search aimed at T (s) or bound to 127.0.0.1:T (e),
//                 and the listener accepts.
//   Y<how>        as Q at 1.5 s, the listener Z of the row's own closed
//                 once the server's end entered TIME_WAIT; then a fresh
//                 socket binds Z's port without SO_REUSEADDR, to see whether
//                 the TIME_WAIT is still there.
//   D             a fresh socket connects to 127.0.0.1:T, where nothing
//                 listens and only the TIME_WAIT end holds the port.
//
// Linux rows wait until the machine has been up two seconds (tw-boot.c).
//
// Measured 2026-10-14 on Linux 6.18.5 aarch64 (Apple's container VM, the
// gcc:14 image, root, default sysctls: tcp_tw_reuse 2, tcp_tw_reuse_delay
// 1000) and Darwin 27.0.0 arm64 (uid 501). Linux's search takes the
// four-tuple over 1.01 s or more after the TIME_WAIT was entered, and not at
// 0.99 s or less, whatever SO_REUSEADDR either carries; a socket bound to the
// port, at 127.0.0.1 or the wildcard, takes it over at once; and a takeover
// goes ahead, and the TIME_WAIT is gone, whether or not anything listens at
// the destination. Darwin's connect from a socket bound to the port answers
// EADDRINUSE, leaving the socket bound where it was and unconnected, and the
// TIME_WAIT stays. On both, a new connection from the client's port to the
// server's end in TIME_WAIT goes ahead, by a search or from a bound socket,
// at once or later, and ends that TIME_WAIT, whether the listener accepts it
// or, closed, the connect is refused. A connect to the TIME_WAIT end's own
// endpoint, where nothing listens, is refused on both.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
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
    case EINVAL: return "EINVAL";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EISCONN: return "EISCONN";
    default: return "other";
    }
}

static int port_of(int fd)
{
    struct sockaddr_in s;
    socklen_t l = sizeof s;
    if (getsockname(fd, (struct sockaddr *)&s, &l) < 0) return -1;
    return ntohs(s.sin_port);
}

static int tcp(int reuse)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (reuse) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    return fd;
}

static int bind_at(int fd, const char *addr, int port)
{
    struct sockaddr_in s = at(addr, port);
    return bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

static int connect_to(int fd, const char *addr, int port)
{
    struct sockaddr_in s = at(addr, port);
    return connect(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void pause_for(double seconds)
{
    struct timespec t = { (time_t)seconds, (long)((seconds - (time_t)seconds) * 1e9) };
    nanosleep(&t, NULL);
}

#ifdef __linux__
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif
static int next_port = 44500;
static int fresh_port(void) { return ++next_port; }
static void aim(int fd, int port)
{
    unsigned int range = (unsigned int)port | ((unsigned int)port << 16);
    if (setsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &range, sizeof range) < 0) {
        printf("IP_LOCAL_PORT_RANGE: %s\n", strerror(errno));
        exit(1);
    }
    unsigned int back = 0;
    socklen_t l = sizeof back;
    getsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &back, &l);
    if (back != range) {
        printf("IP_LOCAL_PORT_RANGE read back wrong\n");
        exit(1);
    }
}
#else
static int cursor(void)
{
    int fd = tcp(0);
    connect_to(fd, "127.0.0.1", 1);
    int p = port_of(fd);
    close(fd);
    return p;
}
static int fresh_port(void)
{
    for (;;) {
        int p = cursor() + 2;
        int b = tcp(0), a = tcp(0);
        int free = p <= 65535 && bind_at(b, "0.0.0.0", p) == 0 && bind_at(a, "0.0.0.0", p - 1) == 0;
        close(b);
        close(a);
        if (free) return p;
    }
}
static void aim(int fd, int port)
{
    (void)fd;
    for (int i = 0; i < 40000; i++)
        if (cursor() == port - 1) return;
    printf("the sequence never reached %d\n", port - 1);
    exit(1);
}
#endif

// A client in TIME_WAIT at a port of its own, which is answered, with the
// instant its connection ended in *ended.
static int client_time_wait(int l, int lport, int tw, double *ended)
{
    int p = fresh_port();
    int c = tcp(tw);
    aim(c, p);
    int e = connect_to(c, "127.0.0.1", lport);
    if (e != 0 || port_of(c) != p) {
        printf("connection from %d: %s, from %d\n", p, err_name(e), port_of(c));
        exit(1);
    }
    int s = accept(l, NULL, NULL);
    struct timeval tv = { 2, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    close(c);
    char b;
    if (read(s, &b, 1) != 0) {
        printf("the client's FIN did not arrive\n");
        exit(1);
    }
    close(s);
    *ended = now();
    return p;
}

// The same, but the accepted socket closes first: the server's end is in
// TIME_WAIT, towards the client's port, which is answered, and which the
// client's FIN, made after the server's arrived, has let go of.
static int server_time_wait(int l, int lport, double *ended)
{
    int p = fresh_port();
    int c = tcp(0);
    aim(c, p);
    int e = connect_to(c, "127.0.0.1", lport);
    if (e != 0 || port_of(c) != p) {
        printf("connection from %d: %s, from %d\n", p, err_name(e), port_of(c));
        exit(1);
    }
    int s = accept(l, NULL, NULL);
    struct timeval tv = { 2, 0 };
    setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    close(s);
    char b;
    if (read(c, &b, 1) != 0) {
        printf("the server's FIN did not arrive\n");
        exit(1);
    }
    close(c);
    *ended = now();
    return p;
}

#ifdef __linux__
// A TIME_WAIT entered in the machine's first second of uptime is never taken
// over by a connect (tw-boot.c), so every row waits until that has passed.
static void past_first_seconds(void)
{
    struct timespec t;
    for (;;) {
        clock_gettime(CLOCK_BOOTTIME, &t);
        if (t.tv_sec >= 2) break;
        usleep(10000);
    }
    printf("uptime at the first row %ld.%03ld s\n", (long)t.tv_sec, t.tv_nsec / 1000000);
}
#endif

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
#ifdef __linux__
    past_first_seconds();
#endif
    int x = 45601;
    int l = tcp(1);
    if (bind_at(l, "127.0.0.1", x) != 0 || listen(l, 128) != 0) {
        printf("listener: %s\n", strerror(errno));
        return 1;
    }

#ifdef __linux__
    double delays[] = { 0, 0.25, 0.5, 0.75, 0.95, 0.98, 0.99, 1.01, 1.02, 1.05, 1.25, 1.5, 2.0, 3.0 };
    for (int tw = 0; tw < 2; tw++) {
        for (int sr = 0; sr < 2; sr++) {
            for (size_t i = 0; i < sizeof delays / sizeof *delays; i++) {
                double ended;
                int p = client_time_wait(l, x, tw, &ended);
                pause_for(delays[i]);
                int fd = tcp(sr);
                aim(fd, p);
                double t = now() - ended;
                int e = connect_to(fd, "127.0.0.1", x);
                printf("R%d%d@%.2f connect to X after %.2f s -> %s from %s\n", tw, sr, delays[i], t, err_name(e),
                       port_of(fd) == p ? "T" : "none");
                if (e == 0) {
                    int s = accept(l, NULL, NULL);
                    close(fd);
                    if (s >= 0) close(s);
                } else {
                    close(fd);
                }
            }
        }
    }
#endif

    double edelays[] = { 0, 0.5, 1.5 };
    for (int tw = 0; tw < 2; tw++) {
        for (int sr = 0; sr < 2; sr++) {
            for (size_t i = 0; i < sizeof edelays / sizeof *edelays; i++) {
                double ended;
                int p = client_time_wait(l, x, tw, &ended);
                pause_for(edelays[i]);
                int fd = tcp(sr);
                int eb = bind_at(fd, "127.0.0.1", p);
                printf("E%d%d@%.1f bind 127.0.0.1:T -> %s", tw, sr, edelays[i], err_name(eb));
                if (eb == 0) {
                    int e = connect_to(fd, "127.0.0.1", x);
                    struct sockaddr_in me, peer;
                    socklen_t ml = sizeof me, pl = sizeof peer;
                    getsockname(fd, (struct sockaddr *)&me, &ml);
                    int ep = getpeername(fd, (struct sockaddr *)&peer, &pl) < 0 ? errno : 0;
                    printf("; connect to X -> %s; then getsockname port %s, getpeername %s", err_name(e),
                           ntohs(me.sin_port) == p ? "T" : "other", ep == 0 ? "X" : ep == ENOTCONN ? "ENOTCONN" : "other");
                    if (e == 0) {
                        int s = accept(l, NULL, NULL);
                        if (s >= 0) close(s);
                    }
                }
                printf("\n");
                close(fd);
            }
        }
    }

    // V: as E, bound to the wildcard at T rather than to 127.0.0.1.
    for (int tw = 0; tw < 2; tw++) {
        double ended;
        int p = client_time_wait(l, x, tw, &ended);
        pause_for(1.5);
        int fd = tcp(1);
        int eb = bind_at(fd, "0.0.0.0", p);
        printf("V%d1@1.5 bind 0.0.0.0:T -> %s", tw, err_name(eb));
        if (eb == 0) {
            int e = connect_to(fd, "127.0.0.1", x);
            struct sockaddr_in me;
            socklen_t ml = sizeof me;
            getsockname(fd, (struct sockaddr *)&me, &ml);
            char a[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &me.sin_addr, a, sizeof a);
            printf("; connect to X -> %s; then getsockname %s:%s", err_name(e), a, ntohs(me.sin_port) == p ? "T" : "other");
            if (e == 0) {
                int s = accept(l, NULL, NULL);
                if (s >= 0) close(s);
            }
        }
        printf("\n");
        close(fd);
    }

    // Z: the TIME_WAIT's listener closed, so nothing listens at its remote end.
    for (int tw = 0; tw < 2; tw++) {
        for (int explicit_bind = 0; explicit_bind < 2; explicit_bind++) {
#ifndef __linux__
            if (!explicit_bind) continue;
#endif
            int z = 45650 + tw * 2 + explicit_bind;
            int lz = tcp(1);
            if (bind_at(lz, "127.0.0.1", z) != 0 || listen(lz, 8) != 0) {
                printf("listener Z: %s\n", strerror(errno));
                return 1;
            }
            double ended;
            int p = client_time_wait(lz, z, tw, &ended);
            close(lz);
            pause_for(1.5);
            int fd = tcp(1);
            int e;
            if (explicit_bind) {
                int eb = bind_at(fd, "127.0.0.1", p);
                printf("Z%de bind 127.0.0.1:T reuse=1 -> %s", tw, err_name(eb));
                e = eb == 0 ? connect_to(fd, "127.0.0.1", z) : -1;
            } else {
                aim(fd, p);
                printf("Z%ds search aimed at T", tw);
                e = connect_to(fd, "127.0.0.1", z);
            }
            if (e >= 0) printf("; connect to Z -> %s from %s", err_name(e), port_of(fd) == p ? "T" : "other");
            close(fd);
            int b = tcp(0);
            printf("; then bind 127.0.0.1:T reuse=0 -> %s\n", err_name(bind_at(b, "127.0.0.1", p)));
            close(b);
        }
    }

    // Q: the server's end in TIME_WAIT, and a new connection from the
    // client's port to the same listener, by a search aimed at the port or
    // from a socket bound to it.
    for (int explicit_bind = 0; explicit_bind < 2; explicit_bind++) {
        double delays[] = { 0, 1.5 };
        for (int i = 0; i < 2; i++) {
            double ended;
            int p = server_time_wait(l, x, &ended);
            pause_for(delays[i]);
            int fd = tcp(1);
            int e = -1;
            if (explicit_bind) {
                int eb = bind_at(fd, "127.0.0.1", p);
                printf("Q%c@%.1f bind 127.0.0.1:T reuse=1 -> %s", 'e', delays[i], err_name(eb));
                if (eb == 0) e = connect_to(fd, "127.0.0.1", x);
            } else {
                aim(fd, p);
                printf("Q%c@%.1f search aimed at T", 's', delays[i]);
                e = connect_to(fd, "127.0.0.1", x);
            }
            int a = -1;
            if (e == 0) a = accept(l, NULL, NULL);
            if (e >= 0) printf("; connect to X -> %s from %s", err_name(e), port_of(fd) == p ? "T" : "other");
            if (e == 0) printf("; accept -> %s", a >= 0 ? "OK" : err_name(errno));
            printf("\n");
            close(fd);
            if (a >= 0) close(a);
        }
    }

    // Y: as Q, but the listener closed once its end entered TIME_WAIT.
    for (int explicit_bind = 0; explicit_bind < 2; explicit_bind++) {
        int z = 45660 + explicit_bind;
        int lz = tcp(1);
        if (bind_at(lz, "127.0.0.1", z) != 0 || listen(lz, 8) != 0) {
            printf("listener Z: %s\n", strerror(errno));
            return 1;
        }
        double ended;
        int p = server_time_wait(lz, z, &ended);
        close(lz);
        pause_for(1.5);
        int fd = tcp(1);
        int e = -1;
        if (explicit_bind) {
            int eb = bind_at(fd, "127.0.0.1", p);
            printf("Y%c bind 127.0.0.1:T reuse=1 -> %s", 'e', err_name(eb));
            if (eb == 0) e = connect_to(fd, "127.0.0.1", z);
        } else {
            aim(fd, p);
            printf("Y%c search aimed at T", 's');
            e = connect_to(fd, "127.0.0.1", z);
        }
        if (e >= 0) printf("; connect to Z -> %s from %s", err_name(e), port_of(fd) == p ? "T" : "other");
        close(fd);
        int b = tcp(0);
        printf("; then bind 127.0.0.1:Z reuse=0 -> %s\n", err_name(bind_at(b, "127.0.0.1", z)));
        close(b);
    }

    // D: a connect to the TIME_WAIT end's own endpoint, where nothing listens.
    {
        double ended;
        int p = client_time_wait(l, x, 0, &ended);
        int fd = tcp(0);
        int e = connect_to(fd, "127.0.0.1", p);
        printf("D connect to 127.0.0.1:T -> %s\n", err_name(e));
        close(fd);
    }
    close(l);
    return 0;
}
