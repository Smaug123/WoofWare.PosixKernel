// What connect(2) answers when its own implicit bind gives an unbound TCP
// socket the destination's port, with nothing listening there: the socket's
// source would then be its own destination.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/isc implicit-self-connect.c && /tmp/isc
//   Linux:  gcc -Wall -o /tmp/isc implicit-self-connect.c && /tmp/isc
//
// Linux narrows each socket's ephemeral range to one port with
// IP_LOCAL_PORT_RANGE (Linux 6.3; the probe does not need /proc/sys), and
// reads the range back, so the implicit port is chosen, not hoped for.
// Darwin has no per-socket range, so the probe connects fresh sockets until
// the kernel's own choice lands on the target, tallying every other attempt as
// the control. Darwin hands out ports in sequence (each implicit bind takes the
// port after the last one it took, passing over ports in use), so each Darwin
// row aims two ports past where the sequence stands, at a port no socket holds.
// A target some socket holds is never reached, which is why a fixed target can
// spin forever.
//
// Rows:
//   L1  Linux, blocking, range [T, T]: the implicit port is the destination's.
//   L2  Linux, non-blocking, range [T+2, T+2], connecting to T+2.
//   L0  Linux, blocking, range [T+5, T+5], connecting to T+4: the control,
//       a port of its own.
//   D*  Darwin, blocking: each attempt connects to 127.0.0.1:T; the tally
//       counts the attempts whose port was not T, and each hit row reports the
//       attempt whose port was T, then makes one more call:
//       D1 nothing more (getsockname, getpeername, SO_ERROR), then binds
//          127.0.0.1:T and 0.0.0.0:T from fresh sockets;
//       D2 a second connect to 127.0.0.1:T on the same socket;
//       D3 a connect to a listener on the same socket;
//       D4 listen(2) on the same socket.
//   N*  Darwin, the same with O_NONBLOCK set before the connect.
//   E1  Both, for comparison: bind(2) 127.0.0.1:P, then connect 127.0.0.1:P.
//   E2  Both: bind(2) 0.0.0.0:P, then connect 127.0.0.1:P.
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
    case ENOTCONN: return "ENOTCONN";
    case ECONNABORTED: return "ECONNABORTED";
    case ECONNRESET: return "ECONNRESET";
    case EALREADY: return "EALREADY";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    default: return "other";
    }
}

// "addr:port", or "errno NAME" when the call fails.
static void name_of(int fd, int peer, char *out, size_t len)
{
    struct sockaddr_in s;
    socklen_t l = sizeof s;
    int r = peer ? getpeername(fd, (struct sockaddr *)&s, &l) : getsockname(fd, (struct sockaddr *)&s, &l);
    if (r < 0) {
        snprintf(out, len, "%s", err_name(errno));
        return;
    }
    char a[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &s.sin_addr, a, sizeof a);
    snprintf(out, len, "%s:%d", a, ntohs(s.sin_port));
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

static int so_error(int fd)
{
    int e = -1;
    socklen_t l = sizeof e;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &l) < 0) return -errno;
    return e;
}

static int connect_to(int fd, const char *addr, int port)
{
    struct sockaddr_in s = at(addr, port);
    return connect(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

static int bind_at(int fd, const char *addr, int port)
{
    struct sockaddr_in s = at(addr, port);
    return bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

static void describe(const char *row, int fd)
{
    char local[64], peer[64];
    name_of(fd, 0, local, sizeof local);
    name_of(fd, 1, peer, sizeof peer);
    printf("%s getsockname=%s getpeername=%s SO_ERROR=%s\n", row, local, peer, err_name(so_error(fd)));
}

// The same self-tuple reached through an explicit bind(2), for comparison.
static void explicit_rows(int port)
{
    const char *addresses[2] = { "127.0.0.1", "0.0.0.0" };
    for (int i = 0; i < 2; i++) {
        char row[8];
        snprintf(row, sizeof row, "E%d", i + 1);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        int eb = bind_at(fd, addresses[i], port + i);
        int e = connect_to(fd, "127.0.0.1", port + i);
        printf("%s bind %s:%d -> %s; connect 127.0.0.1:%d -> %s\n", row, addresses[i], port + i, err_name(eb), port + i,
               err_name(e));
        describe(row, fd);
        close(fd);
    }
}

#ifdef __linux__
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif

static int narrowed(int lo, int hi)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    unsigned int range = (unsigned int)lo | ((unsigned int)hi << 16);
    if (setsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &range, sizeof range) < 0) {
        printf("IP_LOCAL_PORT_RANGE set failed: %s\n", strerror(errno));
        exit(1);
    }
    unsigned int back = 0;
    socklen_t l = sizeof back;
    getsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &back, &l);
    printf("  range read back: [%u, %u]\n", back & 0xffff, back >> 16);
    return fd;
}

// Each row has a target of its own: a self-connected socket's close leaves
// its four-tuple in TIME_WAIT, so a later row aimed at the same port would
// find its one port's tuple taken.
static void linux_rows(int base)
{
    int target = base;
    int fd = narrowed(target, target);
    int e = connect_to(fd, "127.0.0.1", target);
    printf("L1 blocking range [%d, %d] connect 127.0.0.1:%d -> %s\n", target, target, target, err_name(e));
    describe("L1", fd);
    close(fd);

    target = base + 2;
    fd = narrowed(target, target);
    fcntl(fd, F_SETFL, O_NONBLOCK);
    e = connect_to(fd, "127.0.0.1", target);
    printf("L2 non-blocking range [%d, %d] connect 127.0.0.1:%d -> %s\n", target, target, target, err_name(e));
    struct pollfd p = { fd, POLLOUT, 0 };
    int n = poll(&p, 1, 1000);
    printf("L2 poll -> %d revents=0x%x\n", n, p.revents);
    describe("L2", fd);
    e = connect_to(fd, "127.0.0.1", target);
    printf("L2 second connect -> %s\n", err_name(e));
    close(fd);

    target = base + 4;
    fd = narrowed(target + 1, target + 1);
    e = connect_to(fd, "127.0.0.1", target);
    printf("L0 blocking range [%d, %d] connect 127.0.0.1:%d -> %s\n", target + 1, target + 1, target, err_name(e));
    describe("L0", fd);
    close(fd);
}
#endif

#ifdef __APPLE__
// A target the kernel's sequential choice will reach within a few attempts:
// two past the port an implicit bind takes now, and one no socket holds, so
// that the choice does not pass over it.
static int next_target(void)
{
    for (;;) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        connect_to(fd, "127.0.0.1", 1);
        int cursor = port_of(fd);
        close(fd);
        int target = cursor + 2;
        int b = socket(AF_INET, SOCK_STREAM, 0);
        int free = target <= 65535 && bind_at(b, "0.0.0.0", target) == 0;
        close(b);
        if (free) return target;
    }
}

// Connects fresh sockets to 127.0.0.1:target until one's implicit port is
// target; answers that socket, still open, and its connect's errno.
static int hit(int target, int nonblocking, int *answer)
{
    long attempts = 0;
    long tally[8] = { 0 };  // OK, ECONNREFUSED, EINPROGRESS, other
    for (;;) {
        attempts++;
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (nonblocking) fcntl(fd, F_SETFL, O_NONBLOCK);
        int e = connect_to(fd, "127.0.0.1", target);
        if (port_of(fd) == target) {
            printf("  attempt %ld had port %d; the %ld before it: OK=%ld ECONNREFUSED=%ld EINPROGRESS=%ld other=%ld\n",
                   attempts, target, attempts - 1, tally[0], tally[1], tally[2], tally[3]);
            *answer = e;
            return fd;
        }
        tally[e == 0 ? 0 : e == ECONNREFUSED ? 1 : e == EINPROGRESS ? 2 : 3]++;
        if (e != 0 && e != ECONNREFUSED && e != EINPROGRESS && tally[3] <= 3)
            printf("  attempt %ld at port %d: %s\n", attempts, port_of(fd), err_name(e));
        close(fd);
        if (attempts > 100000) {
            printf("  no hit in %ld attempts\n", attempts);
            exit(1);
        }
    }
}

static void darwin_rows(const char *prefix, int nonblocking, int listener_port)
{
    char row[16];
    int e;
    int target;

    snprintf(row, sizeof row, "%s1", prefix);
    target = next_target();
    int fd = hit(target, nonblocking, &e);
    printf("%s connect 127.0.0.1:%d -> %s\n", row, target, err_name(e));
    if (nonblocking) {
        struct pollfd p = { fd, POLLOUT, 0 };
        int n = poll(&p, 1, 1000);
        printf("%s poll -> %d revents=0x%x\n", row, n, p.revents);
    }
    describe(row, fd);
    int b = socket(AF_INET, SOCK_STREAM, 0);
    printf("%s fresh bind 127.0.0.1:%d -> %s\n", row, target, err_name(bind_at(b, "127.0.0.1", target)));
    close(b);
    b = socket(AF_INET, SOCK_STREAM, 0);
    printf("%s fresh bind 0.0.0.0:%d -> %s\n", row, target, err_name(bind_at(b, "0.0.0.0", target)));
    close(b);
    close(fd);

    snprintf(row, sizeof row, "%s2", prefix);
    target = next_target();
    fd = hit(target, nonblocking, &e);
    printf("%s connect 127.0.0.1:%d -> %s\n", row, target, err_name(e));
    e = connect_to(fd, "127.0.0.1", target);
    printf("%s second connect 127.0.0.1:%d -> %s\n", row, target, err_name(e));
    describe(row, fd);
    close(fd);

    snprintf(row, sizeof row, "%s3", prefix);
    target = next_target();
    fd = hit(target, nonblocking, &e);
    printf("%s connect 127.0.0.1:%d -> %s\n", row, target, err_name(e));
    e = connect_to(fd, "127.0.0.1", listener_port);
    printf("%s connect to the listener at 127.0.0.1:%d -> %s\n", row, listener_port, err_name(e));
    if (nonblocking) {
        // Let the handshake finish before reading the peer back.
        struct pollfd p = { fd, POLLOUT, 0 };
        int n = poll(&p, 1, 1000);
        printf("%s poll -> %d revents=0x%x\n", row, n, p.revents);
    }
    describe(row, fd);
    close(fd);

    snprintf(row, sizeof row, "%s4", prefix);
    target = next_target();
    fd = hit(target, nonblocking, &e);
    printf("%s connect 127.0.0.1:%d -> %s\n", row, target, err_name(e));
    e = listen(fd, 8) < 0 ? errno : 0;
    printf("%s listen -> %s\n", row, err_name(e));
    describe(row, fd);
    close(fd);
}
#endif

int main(int argc, char **argv)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
#ifdef __linux__
    int target = argc > 1 ? atoi(argv[1]) : 42000;
    linux_rows(target);
    explicit_rows(46000);
#else
    explicit_rows(46000);
    int listener_port = argc > 1 ? atoi(argv[1]) : 45123;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int el = bind_at(l, "127.0.0.1", listener_port);
    if (el == 0) el = listen(l, 64) < 0 ? errno : 0;
    printf("listener at 127.0.0.1:%d -> %s\n", listener_port, err_name(el));
    darwin_rows("D", 0, listener_port);
    darwin_rows("N", 1, listener_port);
    close(l);
#endif
    return 0;
}
