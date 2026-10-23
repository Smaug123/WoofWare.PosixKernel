// Which ports a TCP connect's implicit bind passes over, for each kind of
// thing that can hold a port: an idle socket, a listener, a connected socket
// and a connection end whose socket has closed (its peer still open, so the
// end is in FIN_WAIT_2), each with and without SO_REUSEADDR, against a
// connect carrying the flag and one not.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/csh connect-search-holders.c && /tmp/csh
//   Linux:  gcc -Wall -o /tmp/csh connect-search-holders.c && /tmp/csh
//
// Holders, each at port T, 127.0.0.1 unless named:
//   i    idle, bound by bind(2)              ir   the same with SO_REUSEADDR
//   o    idle, bound by bind(2) at 0.0.0.0   (Linux only: 127.0.0.2, the
//        search's source does not overlap it; Darwin: the machine's first
//        non-loopback address)
//   L    listening, bound by bind(2) first
//   e    connected to listener X from T, bind(2) having chosen T
//   er   the same with SO_REUSEADDR
//   c    connected to listener X from T, connect's own implicit bind having
//        chosen T
//   cr   the same with SO_REUSEADDR
//   f    c, then closed while the accepted socket stays open: the end is in
//        FIN_WAIT_2 and its socket is gone
//   fr   the same with SO_REUSEADDR
//   fe   e, then closed while the accepted socket stays open
// Searches, each a fresh socket connecting to listener Y, a destination no
// holder is connected to:
//   s    without SO_REUSEADDR             sr   with SO_REUSEADDR
//
// Linux narrows each socket's ephemeral range to the one port T (with
// IP_LOCAL_PORT_RANGE, Linux 6.3, read back to show it reached the socket),
// so a search either takes T (OK, from T) or finds nothing (EADDRNOTAVAIL).
// Each row has a T of its own.
//
// Darwin has no per-socket range, but hands out implicit ports in sequence
// (each takes the port after the last one taken, passing over ports it will
// not share), so each row finds where the sequence stands (a refused connect
// to 127.0.0.1:1, which gives its port back), aims T two past it at a port no
// socket holds, puts the holder at T, and then connects four searching
// sockets in turn, printing the port each took relative to T. A sequence
// that never shows T passed it over; one that shows T shared it. Another
// process taking a port meanwhile shows as a gap elsewhere in the sequence.
// A holder whose port connect's own implicit bind chooses is put at T by
// refused connects to 127.0.0.1:1 (each gives its port straight back) until
// the sequence stands at T-1, and then its connect. That leaves the sequence
// at T, so for those rows it is walked once round the whole range, by more
// refused connects, to two before T, counting any that took T on the way.
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
#include <unistd.h>
#ifdef __APPLE__
#include <ifaddrs.h>
#endif

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
    case EINPROGRESS: return "EINPROGRESS";
    case EISCONN: return "EISCONN";
    case EAGAIN: return "EAGAIN";
    default: return "other";
    }
}

#ifdef __APPLE__
static int port_of(int fd)
{
    struct sockaddr_in s;
    socklen_t l = sizeof s;
    if (getsockname(fd, (struct sockaddr *)&s, &l) < 0) return -1;
    return ntohs(s.sin_port);
}
#endif

static void name_of(int fd, char *out, size_t len)
{
    struct sockaddr_in s;
    socklen_t l = sizeof s;
    if (getsockname(fd, (struct sockaddr *)&s, &l) < 0) {
        snprintf(out, len, "%s", err_name(errno));
        return;
    }
    char a[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s.sin_addr, a, sizeof a);
    snprintf(out, len, "%s:%d", a, ntohs(s.sin_port));
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

static int listener(int port)
{
    int fd = tcp(1);
    if (bind_at(fd, "127.0.0.1", port) != 0 || listen(fd, 128) != 0) {
        printf("listener at %d: %s\n", port, strerror(errno));
        exit(1);
    }
    struct timeval tv = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    return fd;
}

// The connection just made to `l`, accepted; -1 if none came.
static int accept_one(int l)
{
    return accept(l, NULL, NULL);
}

static const char *holders[] = { "i", "ir", "o", "L", "e", "er", "c", "cr", "f", "fr", "fe" };

static int holder_reuse(const char *kind) { return kind[strlen(kind) - 1] == 'r'; }

#ifdef __APPLE__
// Whether connect's own implicit bind gives the holder its port.
static int implicit(const char *kind) { return kind[0] == 'c' || (kind[0] == 'f' && kind[1] != 'e'); }
#endif

#ifdef __linux__
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif

static void narrow(int fd, int port)
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
        printf("IP_LOCAL_PORT_RANGE read back [%u, %u], not [%d, %d]\n", back & 0xffff, back >> 16, port, port);
        exit(1);
    }
}
#endif

#ifdef __APPLE__
// Where the sequence stands: the port a refused connect took.
static int cursor(void)
{
    int fd = tcp(0);
    connect_to(fd, "127.0.0.1", 1);
    int p = port_of(fd);
    close(fd);
    return p;
}
#endif

// Puts the holder `kind` at `port`, connected ones to listener `lx` at
// `x`; answers its socket (closed for f, fr and fe), and in `*server` the
// accepted socket of a connected holder, else -1.
static int place(const char *kind, int port, int lx, int x, int *server, char *line, size_t len)
{
    int fd = tcp(holder_reuse(kind));
    int e = 0;
    *server = -1;
    if (!strcmp(kind, "i") || !strcmp(kind, "ir") || !strcmp(kind, "L")) {
        e = bind_at(fd, "127.0.0.1", port);
        if (e == 0 && !strcmp(kind, "L")) e = listen(fd, 8) < 0 ? errno : 0;
    } else if (!strcmp(kind, "o")) {
#ifdef __linux__
        e = bind_at(fd, "127.0.0.2", port);
#else
        char other[INET_ADDRSTRLEN] = "";
        struct ifaddrs *all;
        if (getifaddrs(&all) == 0) {
            for (struct ifaddrs *i = all; i && !other[0]; i = i->ifa_next) {
                if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
                struct in_addr a = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
                if ((ntohl(a.s_addr) >> 24) == 127) continue;
                inet_ntop(AF_INET, &a, other, sizeof other);
            }
            freeifaddrs(all);
        }
        e = other[0] ? bind_at(fd, other, port) : EADDRNOTAVAIL;
#endif
    } else if (!strcmp(kind, "e") || !strcmp(kind, "er") || !strcmp(kind, "fe")) {
        e = bind_at(fd, "127.0.0.1", port);
        if (e == 0) e = connect_to(fd, "127.0.0.1", x);
        if (e == 0) *server = accept_one(lx);
    } else {
        // c, cr, f, fr: connect's own implicit bind chooses the port.
#ifdef __linux__
        narrow(fd, port);
        e = connect_to(fd, "127.0.0.1", x);
        if (e == 0) *server = accept_one(lx);
#else
        // Refused connects, which give their ports straight back, until the
        // sequence stands one before `port`; the holder's connect takes it.
        for (int attempt = 0; cursor() != port - 1; attempt++) {
            if (attempt > 50) {
                snprintf(line, len, "the sequence never reached T");
                return -1;
            }
        }
        e = connect_to(fd, "127.0.0.1", x);
        if (e == 0) *server = accept_one(lx);
#endif
    }
    char name[64];
    name_of(fd, name, sizeof name);
    snprintf(line, len, "%s at %s", err_name(e), name);
    if (kind[0] == 'f') {
        close(fd);
        strncat(line, ", closed", len - strlen(line) - 1);
        fd = -1;
    }
    return fd;
}

#ifdef __linux__
static void rows(void)
{
    int x = 45401, y = 45402;
    int lx = listener(x), ly = listener(y);
    int port = 43100;
    for (size_t h = 0; h < sizeof holders / sizeof *holders; h++) {
        for (int reuse = 0; reuse < 2; reuse++) {
            port++;
            char held[128];
            int server;
            int hfd = place(holders[h], port, lx, x, &server, held, sizeof held);
            int fd = tcp(reuse);
            narrow(fd, port);
            int e = connect_to(fd, "127.0.0.1", y);
            int s = e == 0 ? accept_one(ly) : -1;
            char name[64];
            name_of(fd, name, sizeof name);
            printf("%s/%s T=%d holder %s; connect to Y -> %s getsockname=%s\n", holders[h], reuse ? "sr" : "s", port,
                   held, err_name(e), name);
            if (s >= 0) close(s);
            close(fd);
            if (hfd >= 0) close(hfd);
            if (server >= 0) close(server);
        }
    }
    close(lx);
    close(ly);
}
#else
static void rows(void)
{
    int x = 45401, y = 45402;
    int lx = listener(x), ly = listener(y);
    for (size_t h = 0; h < sizeof holders / sizeof *holders; h++) {
        for (int reuse = 0; reuse < 2; reuse++) {
            int target;
            for (;;) {
                target = cursor() + 2;
                int b = tcp(0);
                int free = target <= 65535 && bind_at(b, "0.0.0.0", target) == 0;
                close(b);
                if (free) break;
            }
            char held[128];
            int server;
            int hfd = place(holders[h], target, lx, x, &server, held, sizeof held);
            printf("%s/%s holder %s (T=%d)\n", holders[h], reuse ? "sr" : "s", held, target);
            if (implicit(holders[h])) {
                // The holder's own implicit bind left the sequence at T, so
                // walk it once round the range, to two before T.
                int round = 0, tookT = 0;
                for (;;) {
                    int p = cursor();
                    round++;
                    if (p == target) tookT++;
                    if (p == target - 2 || round > 40000) break;
                }
                printf("%s/%s walked the sequence round in %d refused connects, %d of which took T\n", holders[h],
                       reuse ? "sr" : "s", round, tookT);
            }
            for (int attempt = 0; attempt < 4; attempt++) {
                int fd = tcp(reuse);
                int e = connect_to(fd, "127.0.0.1", y);
                int s = e == 0 ? accept_one(ly) : -1;
                printf("%s/%s connect to Y -> %s from port T%+d\n", holders[h], reuse ? "sr" : "s", err_name(e),
                       port_of(fd) - target);
                if (s >= 0) close(s);
                close(fd);
            }
            if (hfd >= 0) close(hfd);
            if (server >= 0) close(server);
        }
    }
    close(lx);
    close(ly);
}
#endif

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    rows();
    return 0;
}
