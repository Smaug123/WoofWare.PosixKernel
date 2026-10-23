// Which binds two sockets may share a port through, by SO_REUSEADDR and
// SO_REUSEPORT, when the two belong to processes of the same uid or of
// different uids; and which ports a datagram socket's ephemeral search
// (bind(2) of port 0, and the implicit bind of connect(2) and sendto(2)) takes
// beside such a holder.
//
// Build and run:
//   Linux, as root (each socket is made by a child that first drops to its
//   row's uid with setresgid/setresuid, so rows of both kinds are measured):
//     container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/ps /probe/port-sharing.c && /tmp/ps'
//   Darwin, as an ordinary user (only the same-uid rows, and no search rows):
//     cc -Wall -O1 -o /tmp/ps port-sharing.c && /tmp/ps
//
// Every row has a port L of its own, and two processes: the holder's, which
// makes its socket at L and keeps it open, and then the candidate's, which
// makes its socket and asks for L. Each socket carries the row's flags:
//   -   neither    a   SO_REUSEADDR    p   SO_REUSEPORT    ap  both
// The holder's process runs as uid 1000; the candidate's as uid 1000 (same)
// or 1001 (diff). The header prints the uids each process ran with, read back
// after the drop.
//
// Holders:
//   udp/i  a UDP socket bound at A:L, A 127.0.0.1, 0.0.0.0 or (Linux only)
//          127.0.0.2
//   udp/c  a UDP socket bound at 0.0.0.0:L and then connected to
//          127.0.0.1:X (a port nothing uses); the row prints the address it
//          then reports, since connect(2) may give it a local address
//   tcp/i  a TCP socket bound at A:L
//   tcp/L  a TCP socket bound at A:L and listening
// Candidates, of the holder's transport:
//   bind     bind(2) of B:L, B 127.0.0.1, 0.0.0.0 or (Linux only) 127.0.0.2,
//            which overlaps 127.0.0.1 nowhere, so that the address changes
//            some answers
//   search   bind(2) of B:0, B 127.0.0.1 or 0.0.0.0, with the socket's range
//            narrowed to [L, L] by IP_LOCAL_PORT_RANGE (Linux 6.3; read back
//            to show it reached the socket), so the search has L alone to
//            consider (Linux only)
//   connect  udp only: connect(2) of an unbound socket to 127.0.0.1:X, its
//            range narrowed to [L, L] (Linux only); a holder at 127.0.0.2
//            shows whether the search for its port is made at the wildcard
//            or at the source the connect will have
//   sendto   udp only: sendto(2) of one byte from an unbound socket to
//            127.0.0.1:X, its range narrowed to [L, L] (Linux only)
//   write    udp only: write(2) of one byte on an unbound, unconnected
//            socket, its range narrowed to [L, L] (Linux only), which binds
//            the socket before it fails EDESTADDRREQ
// A control row (holder "none") for each search shows L is otherwise free.
//
// Each row prints the candidate's answer and then the address it reports.
//
// Measured 2026-10-17 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14, as
// root, each socket made by a process dropped to uid 1000 or 1001) and on
// Darwin 27.0.0 arm64 (uid 501). In short:
//   Linux, every row: a holder stands in the way of a candidate at an
//     overlapping address (the wildcard overlaps every address) unless both
//     carry SO_REUSEADDR and the holder is not a TCP listener, or both carry
//     SO_REUSEPORT and their processes have one uid. The uids matter nowhere
//     else. A UDP search asks the explicit bind's question; a TCP search
//     passes over every holder at an overlapping address, whatever either
//     carries. connect(2), sendto(2) and write(2) on an unbound UDP socket
//     search at the wildcard (a holder at 127.0.0.2 stands in the way of a
//     connect to 127.0.0.1) and, finding no port, fail EAGAIN, leaving the
//     socket unbound. A UDP socket bound at the wildcard and then connected
//     reports, and holds, 127.0.0.1.
//   Darwin: a candidate carrying neither flag meets every holder at an
//     overlapping address; one carrying SO_REUSEADDR alone only a holder at
//     its very address; one carrying SO_REUSEPORT only a holder at its very
//     address that does not; and a connected UDP holder stands in the way of
//     no candidate carrying either flag, at any address.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __linux__
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif
#endif

static int next_port = 40001;
static const int X = 40000;

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
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EAGAIN: return "EAGAIN";
    case EDESTADDRREQ: return "EDESTADDRREQ";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
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

// The socket of `transport` carrying `flags`, or exits.
static int make(const char *transport, const char *flags)
{
    int fd = socket(AF_INET, strcmp(transport, "udp") == 0 ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket: %s\n", strerror(errno));
        exit(1);
    }
    int one = 1;
    if (strchr(flags, 'a') && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) {
        printf("SO_REUSEADDR: %s\n", strerror(errno));
        exit(1);
    }
    if (strchr(flags, 'p') && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) < 0) {
        printf("SO_REUSEPORT: %s\n", strerror(errno));
        exit(1);
    }
    // Read both back, so that a flag the kernel ignored cannot pass for one
    // it honoured.
    int a = 0, p = 0;
    socklen_t l = sizeof a;
    getsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &a, &l);
    l = sizeof p;
    getsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &p, &l);
    if ((a != 0) != (strchr(flags, 'a') != NULL) || (p != 0) != (strchr(flags, 'p') != NULL)) {
        printf("flags %s read back as SO_REUSEADDR=%d SO_REUSEPORT=%d\n", flags, a, p);
        exit(1);
    }
    return fd;
}

static int bind_at(int fd, const char *addr, int port)
{
    struct sockaddr_in s = at(addr, port);
    return bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
}

#ifdef __linux__
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

static int as_root;

// Drops to `uid` (and the same gid), or exits; does nothing when not root.
static void become(uid_t uid)
{
    if (!as_root) return;
#ifdef __linux__
    if (setgroups(0, NULL) < 0 || setresgid(uid, uid, uid) < 0 || setresuid(uid, uid, uid) < 0) {
        printf("dropping to %d: %s\n", (int)uid, strerror(errno));
        exit(1);
    }
#else
    printf("dropping to %d: only measured on Linux\n", (int)uid);
    exit(1);
#endif
}

// Writes `text` to `fd` whole, NUL included.
static void say(int fd, const char *text)
{
    size_t n = strlen(text) + 1;
    if (write(fd, text, n) != (ssize_t)n) exit(1);
}

static void hear(int fd, char *out, size_t len)
{
    ssize_t n = read(fd, out, len - 1);
    if (n <= 0) {
        snprintf(out, len, "(no answer)");
        return;
    }
    out[n] = 0;
}

// One row. `holder` is "i", "c", "L" or "none"; `op` is "bind", "search",
// "connect", "sendto" or "write".
static void row(const char *transport, const char *holder, const char *hflags, const char *haddr,
                const char *cflags, const char *caddr, int diff, const char *op)
{
    int port = next_port++;
    char hline[128] = "-", cline[128];
    int hres[2], gate[2], cres[2];
    pid_t h = -1;

    if (pipe(gate) < 0 || pipe(hres) < 0 || pipe(cres) < 0) exit(1);

    if (strcmp(holder, "none") != 0) {
        h = fork();
        if (h == 0) {
            close(gate[1]);
            become(1000);
            int fd = make(transport, hflags);
            int e = bind_at(fd, haddr, port);
            if (e == 0 && !strcmp(holder, "c")) {
                struct sockaddr_in s = at("127.0.0.1", X);
                e = connect(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
            }
            if (e == 0 && !strcmp(holder, "L")) e = listen(fd, 8) < 0 ? errno : 0;
            char name[64], line[128];
            name_of(fd, name, sizeof name);
            snprintf(line, sizeof line, "%s at %s", err_name(e), name);
            say(hres[1], line);
            char c;
            read(gate[0], &c, 1);
            _exit(0);
        }
        hear(hres[0], hline, sizeof hline);
    }

    pid_t c = fork();
    if (c == 0) {
        become(diff ? 1001 : 1000);
        int fd = make(transport, cflags);
        int e = 0;
        if (!strcmp(op, "bind")) {
            e = bind_at(fd, caddr, port);
        } else {
#ifdef __linux__
            narrow(fd, port);
#endif
            if (!strcmp(op, "search")) {
                e = bind_at(fd, caddr, 0);
            } else if (!strcmp(op, "connect")) {
                struct sockaddr_in s = at("127.0.0.1", X);
                e = connect(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
            } else if (!strcmp(op, "sendto")) {
                struct sockaddr_in s = at("127.0.0.1", X);
                e = sendto(fd, "x", 1, 0, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
            } else {
                e = write(fd, "x", 1) < 0 ? errno : 0;
            }
        }
        char name[64], line[128];
        name_of(fd, name, sizeof name);
        snprintf(line, sizeof line, "%s name=%s", err_name(e), name);
        say(cres[1], line);
        _exit(0);
    }
    hear(cres[0], cline, sizeof cline);
    waitpid(c, NULL, 0);
    close(gate[1]);
    if (h > 0) waitpid(h, NULL, 0);
    close(gate[0]);
    close(hres[0]);
    close(hres[1]);
    close(cres[0]);
    close(cres[1]);

    printf("%s/%s H=%s@%s (%s) C=%s@%s %s %s L=%d -> %s\n", transport, holder, hflags, haddr, hline, cflags, caddr,
           diff ? "diff" : "same", op, port, cline);
    fflush(stdout);
}

static void uids(void)
{
    int p[2];
    char line[128];
    for (int u = 1000; u <= 1001; u++) {
        if (pipe(p) < 0) exit(1);
        pid_t c = fork();
        if (c == 0) {
            become(u);
#ifdef __linux__
            uid_t r, e, s;
            getresuid(&r, &e, &s);
            snprintf(line, sizeof line, "%d/%d/%d", (int)r, (int)e, (int)s);
#endif
            say(p[1], line);
            _exit(0);
        }
        hear(p[0], line, sizeof line);
        waitpid(c, NULL, 0);
        close(p[0]);
        close(p[1]);
        printf("a process dropped to %d runs as ruid/euid/suid %s\n", u, line);
    }
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    as_root = geteuid() == 0;
    printf("probe uid=%d\n", (int)geteuid());
    if (as_root) {
        uids();
    } else {
        printf("not root: every row's processes run as uid %d, and only the same-uid rows run\n", (int)geteuid());
    }

    const char *flags[] = { "-", "a", "p", "ap" };
    const char *two[] = { "127.0.0.1", "0.0.0.0" };
#ifdef __linux__
    // Linux holds all of 127.0.0.0/8; Darwin holds 127.0.0.1 alone, and
    // answers a bind of 127.0.0.2 EADDRNOTAVAIL.
    const char *three[] = { "127.0.0.1", "0.0.0.0", "127.0.0.2" };
    int nthree = 3;
#else
    const char *three[] = { "127.0.0.1", "0.0.0.0" };
    int nthree = 2;
#endif
    int ndiff = as_root ? 2 : 1;
#ifdef __linux__
    int searches = 1;
#else
    int searches = 0;
#endif

    struct {
        const char *transport, *holder;
    } holders[] = { { "udp", "i" }, { "udp", "c" }, { "tcp", "i" }, { "tcp", "L" } };

    for (size_t k = 0; k < sizeof holders / sizeof holders[0]; k++) {
        const char *t = holders[k].transport, *hk = holders[k].holder;
        int naddr = strcmp(hk, "c") == 0 ? 1 : nthree;
        const char *haddrs[] = { strcmp(hk, "c") == 0 ? "0.0.0.0" : three[0], three[1], three[nthree - 1] };
        for (int diff = 0; diff < ndiff; diff++)
            for (int hf = 0; hf < 4; hf++)
                for (int ha = 0; ha < naddr; ha++)
                    for (int cf = 0; cf < 4; cf++)
                        for (int ca = 0; ca < nthree; ca++)
                            row(t, hk, flags[hf], haddrs[ha], flags[cf], three[ca], diff, "bind");
        if (!searches) continue;
        for (int diff = 0; diff < ndiff; diff++)
            for (int hf = 0; hf < 4; hf++)
                for (int ha = 0; ha < naddr; ha++)
                    for (int cf = 0; cf < 4; cf++) {
                        for (int ca = 0; ca < 2; ca++)
                            row(t, hk, flags[hf], haddrs[ha], flags[cf], two[ca], diff, "search");
                        if (!strcmp(t, "udp")) {
                            row(t, hk, flags[hf], haddrs[ha], flags[cf], "-", diff, "connect");
                            row(t, hk, flags[hf], haddrs[ha], flags[cf], "-", diff, "sendto");
                            row(t, hk, flags[hf], haddrs[ha], flags[cf], "-", diff, "write");
                        }
                    }
    }

    if (searches) {
        for (int cf = 0; cf < 4; cf++) {
            for (int ca = 0; ca < 2; ca++) {
                row("udp", "none", "-", "-", flags[cf], two[ca], 0, "search");
                row("tcp", "none", "-", "-", flags[cf], two[ca], 0, "search");
            }
            row("udp", "none", "-", "-", flags[cf], "-", 0, "connect");
            row("udp", "none", "-", "-", flags[cf], "-", 0, "sendto");
            row("udp", "none", "-", "-", flags[cf], "-", 0, "write");
        }
    }
    return 0;
}
