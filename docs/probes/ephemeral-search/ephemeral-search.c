// Which ports a TCP socket's ephemeral search passes over because another
// socket holds them, and what bind(2), listen(2) and connect(2) answer when
// it finds none.
//
// Build and run:
//   Linux:  gcc -Wall -o /tmp/es ephemeral-search.c && /tmp/es
//   Darwin: cc -Wall -o /tmp/es ephemeral-search.c && /tmp/es
//
// Linux: every row narrows the searching socket's range to the one port the
// row's holder holds (IP_LOCAL_PORT_RANGE, Linux 6.3, read back to show it
// reached the socket), so the search has exactly that port to consider; a
// control row with no holder shows the port is otherwise free. Each row has a
// port of its own.
//
// Holders, each at port L:
//   none  nothing (the control)
//   lr    idle, SO_REUSEADDR, bound 127.0.0.1:L
//   l     idle, bound 127.0.0.1:L
//   wr    idle, SO_REUSEADDR, bound 0.0.0.0:L
//   or    idle, SO_REUSEADDR, bound 127.0.0.2:L, an address the search's does
//         not overlap
//   Lr    listening, SO_REUSEADDR, bound 127.0.0.1:L
//   c     connected to listener X from L, by connect's implicit bind
//   cr    the same, carrying SO_REUSEADDR
//   br    connected to listener X from L, by bind(2) 127.0.0.1:L first, with
//         SO_REUSEADDR
// Searches, each with its range narrowed to [L, L]:
//   B    bind 127.0.0.1:0            Br   the same with SO_REUSEADDR
//   W    bind 0.0.0.0:0              Wr   the same with SO_REUSEADDR
//   Lsr  listen(2) on an unbound socket with SO_REUSEADDR
//   Y    connect to listener Y       Yr   the same with SO_REUSEADDR
//   Xr   connect to listener X, with SO_REUSEADDR
//
// Darwin has no per-socket range and allocates from its whole range
// (net.inet.ip.portrange.first..last), so it is measured only at exhaustion:
// every port of the range is bound at 127.0.0.1 by a socket carrying
// SO_REUSEADDR (a port some other socket on the machine already holds
// cannot be, and is counted), and then each search is made once; then, the
// fill released, the first search is made again, as the control. The fill
// holds the range for well under a second, during which no other process on
// the machine can make an outgoing connection.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
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
    return fd;
}

// What a search does, on a socket `fd` already given its SO_REUSEADDR.
static int search(const char *what, int fd, int x, int y)
{
    if (!strcmp(what, "B") || !strcmp(what, "Br")) return bind_at(fd, "127.0.0.1", 0);
    if (!strcmp(what, "W") || !strcmp(what, "Wr")) return bind_at(fd, "0.0.0.0", 0);
    if (!strcmp(what, "Lsr")) return listen(fd, 8) < 0 ? errno : 0;
    if (!strcmp(what, "Y") || !strcmp(what, "Yr")) return connect_to(fd, "127.0.0.1", y);
    if (!strcmp(what, "Xr")) return connect_to(fd, "127.0.0.1", x);
    printf("unknown search %s\n", what);
    exit(1);
}

static int search_reuse(const char *what) { return what[strlen(what) - 1] == 'r'; }

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

// The holder `kind` at `port`, or -1 for none; prints how it got there.
static int holder(const char *kind, int port, int x, char *line, size_t len)
{
    int fd = -1, e = 0;
    if (!strcmp(kind, "none")) {
        snprintf(line, len, "-");
        return -1;
    } else if (!strcmp(kind, "lr")) {
        fd = tcp(1);
        e = bind_at(fd, "127.0.0.1", port);
    } else if (!strcmp(kind, "l")) {
        fd = tcp(0);
        e = bind_at(fd, "127.0.0.1", port);
    } else if (!strcmp(kind, "wr")) {
        fd = tcp(1);
        e = bind_at(fd, "0.0.0.0", port);
    } else if (!strcmp(kind, "or")) {
        fd = tcp(1);
        e = bind_at(fd, "127.0.0.2", port);
    } else if (!strcmp(kind, "Lr")) {
        fd = tcp(1);
        e = bind_at(fd, "127.0.0.1", port);
        if (e == 0) e = listen(fd, 8) < 0 ? errno : 0;
    } else if (!strcmp(kind, "c") || !strcmp(kind, "cr")) {
        fd = tcp(!strcmp(kind, "cr"));
        narrow(fd, port);
        e = connect_to(fd, "127.0.0.1", x);
    } else if (!strcmp(kind, "br")) {
        fd = tcp(1);
        e = bind_at(fd, "127.0.0.1", port);
        if (e == 0) e = connect_to(fd, "127.0.0.1", x);
    }
    char name[64];
    name_of(fd, name, sizeof name);
    snprintf(line, len, "%s at %s", err_name(e), name);
    return fd;
}

static void linux_rows(void)
{
    int x_port = 45301, y_port = 45302;
    int lx = listener(x_port), ly = listener(y_port);
    const char *holders[] = { "none", "lr", "l", "wr", "or", "Lr", "c", "cr", "br" };
    const char *searches[] = { "B", "Br", "W", "Wr", "Lsr", "Y", "Yr", "Xr" };
    int port = 43000;
    for (size_t h = 0; h < sizeof holders / sizeof *holders; h++) {
        for (size_t s = 0; s < sizeof searches / sizeof *searches; s++) {
            port++;
            char held[96];
            int hfd = holder(holders[h], port, x_port, held, sizeof held);
            int fd = tcp(search_reuse(searches[s]));
            narrow(fd, port);
            int e = search(searches[s], fd, x_port, y_port);
            char name[64];
            name_of(fd, name, sizeof name);
            printf("%s/%s L=%d holder %s; %s -> %s getsockname=%s\n", holders[h], searches[s], port, held, searches[s],
                   err_name(e), name);
            close(fd);
            if (hfd >= 0) close(hfd);
            // Drain the listeners' queues, so that neither fills.
            int a;
            struct timeval tv = { 0, 1000 };
            setsockopt(lx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            setsockopt(ly, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            while ((a = accept(lx, NULL, NULL)) >= 0) close(a);
            while ((a = accept(ly, NULL, NULL)) >= 0) close(a);
        }
    }
    close(lx);
    close(ly);
}
#endif

#ifdef __APPLE__
static void darwin_rows(void)
{
    int first = 0, last = 0;
    size_t sz = sizeof first;
    sysctlbyname("net.inet.ip.portrange.first", &first, &sz, NULL, 0);
    sz = sizeof last;
    sysctlbyname("net.inet.ip.portrange.last", &last, &sz, NULL, 0);
    printf("range [%d, %d]\n", first, last);

    int x_port = 45301;
    int lx = listener(x_port);

    int count = last - first + 1;
    int *fds = calloc(count, sizeof *fds);
    int filled = 0, taken = 0, other = 0;
    for (int i = 0; i < count; i++) {
        fds[i] = tcp(1);
        int e = bind_at(fds[i], "127.0.0.1", first + i);
        if (e == 0) filled++;
        else if (e == EADDRINUSE) taken++;
        else other++;
    }
    // A second pass, for any port another socket let go of meanwhile.
    for (int i = 0; i < count; i++) {
        char name[64];
        name_of(fds[i], name, sizeof name);
        if (strcmp(name, "0.0.0.0:0") == 0 && bind_at(fds[i], "127.0.0.1", first + i) == 0) {
            filled++;
            taken--;
        }
    }
    const char *searches[] = { "W", "B", "Br", "Wr", "Lsr", "Y", "Yr" };
    int results[7];
    char names[7][64];
    for (int s = 0; s < 7; s++) {
        int fd = tcp(search_reuse(searches[s]));
        results[s] = search(searches[s], fd, x_port, x_port);
        name_of(fd, names[s], sizeof names[s]);
        close(fd);
    }
    for (int i = 0; i < count; i++) close(fds[i]);
    free(fds);
    // The control: with the range free again, the first search finds a port.
    int control = tcp(0);
    int ec = search("W", control, x_port, x_port);
    close(control);
    printf("filled %d of %d ports at 127.0.0.1 with SO_REUSEADDR; %d held by other sockets, %d other errors\n", filled,
           count, taken, other);
    for (int s = 0; s < 7; s++)
        printf("exhausted/%s -> %s getsockname=%s\n", searches[s], err_name(results[s]), names[s]);
    printf("released/W -> %s\n", err_name(ec));
    close(lx);
}
#endif

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
#ifdef __linux__
    linux_rows();
#else
    darwin_rows();
#endif
    return 0;
}
