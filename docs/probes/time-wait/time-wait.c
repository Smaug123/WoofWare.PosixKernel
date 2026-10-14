// What a TCP connection's TIME_WAIT holds once both its sockets have closed:
// the port of the end whose FIN was made first, against which bind(2),
// listen(2) and connect(2), and for how long.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/tw time-wait.c && /tmp/tw
//   Linux:  gcc -Wall -o /tmp/tw time-wait.c && /tmp/tw
//
// Every connection is on loopback, from a client to a listener, and is ended
// by two close(2)s, the second made once the first's FIN has arrived (a read
// at the second end answers end of file): the first end's FIN is made first,
// and it goes to TIME_WAIT. Nothing is written. "Client first" closes the client
// first, leaving the client's end in TIME_WAIT at its port T; "server first"
// closes the accepted socket first, leaving the server's end in TIME_WAIT at
// the listener's port T, and then closes the listener too. Each row has a
// connection, and a port, of its own.
//
// Linux narrows each socket whose port a search chooses to one port with
// IP_LOCAL_PORT_RANGE (Linux 6.3), read back to show it reached the socket,
// so the client's port, and each later search's, is the one asked for.
// Darwin hands out implicit ports in sequence: a socket is aimed at a port by
// refused connects to 127.0.0.1:1 (each gives its port straight back) that
// walk the sequence, round the range if need be, to one before it.
//
// Rows (rc: the client carried SO_REUSEADDR; rl: the listener did, and so the
// socket accept made):
//   B<rc>  client first: fresh sockets bind 127.0.0.1:T and 0.0.0.0:T,
//          without and with SO_REUSEADDR, and one that binds then listens.
//   S<rl>  server first: the same, at the listener's port.
//   P      server first: a fresh socket binds the client's port, which the
//          client's FIN, made after the server's arrived, let go of; and a
//          connect's search aimed at it.
//   C<how><rc><to>[+2s]
//          client first, the client's port chosen by connect's own bind (c)
//          or by bind(2) (b): a connect's search aimed at T, connecting to
//          the same listener (x: the same four-tuple) or another (y); on
//          Linux once at once and once two seconds after the close.
//   L<what> client first: a search for a port to bind aimed at T, by
//          bind(127.0.0.1:0) (b) or listen(2) with no port (l), without and
//          with SO_REUSEADDR.
//   W      client first: every second, a fresh socket binds 127.0.0.1:T
//          without SO_REUSEADDR, until one succeeds or a bound passes.
//
// Linux rows wait until the machine has been up two seconds: a TIME_WAIT
// entered in its first second is never taken over (tw-boot.c).
//
// Measured 2026-10-14 on Linux 6.18.5 aarch64 (Apple's container VM, the
// gcc:14 image, root, default sysctls: tcp_tw_reuse 2, tcp_timestamps 1) and
// Darwin 27.0.0 arm64 (uid 501, net.inet.tcp.msl 15000), with the outputs
// beside this file. On both, the TIME_WAIT end holds its port exactly as a
// connection end whose socket has closed does: a bind is refused on Linux
// unless both the end and the candidate carry SO_REUSEADDR (the end keeping
// the flag its socket closed with) and on Darwin unless the candidate does;
// a candidate that bound then listens; and a search for a port to bind
// passes the port over. A connect's search passes it over on Darwin; on
// Linux it shares a port connect's own bind chose, towards another
// destination, and takes the four-tuple itself over once tcp_tw_reuse allows
// (tw-reuse.c), and passes over one bind(2) chose. The passive end's port is
// free. Linux's TIME_WAIT held the port 60.2 s and let it go by 61.2 s;
// Darwin's held it 30.1 s and let it go by 31.1 s, twice its msl.
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

static int listener(int port, int reuse)
{
    int fd = tcp(reuse);
    if (bind_at(fd, "127.0.0.1", port) != 0 || listen(fd, 128) != 0) {
        printf("listener at %d: %s\n", port, strerror(errno));
        exit(1);
    }
    return fd;
}

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

#ifdef __linux__
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif

static int next_port = 44000;

static int fresh_port(void) { return ++next_port; }

// Readies `fd` for a search that can take only `port`.
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
        printf("IP_LOCAL_PORT_RANGE read back [%u, %u], not [%d, %d]\n", back & 0xffff, back >> 16, port, port);
        exit(1);
    }
}
#else
// Where the sequence stands: the port a refused connect took.
static int cursor(void)
{
    int fd = tcp(0);
    connect_to(fd, "127.0.0.1", 1);
    int p = port_of(fd);
    close(fd);
    return p;
}

// Two past where the sequence stands, at a port nothing holds, with nothing
// holding the port before it either, where the sequence is walked to.
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

// Walks the sequence until it stands one before `port`.
static void aim(int fd, int port)
{
    (void)fd;
    for (int i = 0; i < 40000; i++)
        if (cursor() == port - 1) return;
    printf("the sequence never reached %d\n", port - 1);
    exit(1);
}
#endif

// A connection to the listener `l` at `lport` from a client carrying
// SO_REUSEADDR if `rc`, at `port`, chosen by bind(2) if `by_bind` and by
// connect's own bind otherwise; answers the client and, in *server, the
// accepted socket.
static int connection(int l, int lport, int rc, int port, int by_bind, int *server)
{
    int c = tcp(rc);
    if (by_bind) bind_at(c, "127.0.0.1", port);
    else aim(c, port);
    int e = connect_to(c, "127.0.0.1", lport);
    if (e != 0 || port_of(c) != port) {
        printf("connection to %d from %d: %s, from port %d\n", lport, port, err_name(e), port_of(c));
        exit(1);
    }
    *server = accept(l, NULL, NULL);
    return c;
}

// Closes `first`, waits until its FIN has arrived at `second` (a read
// answers end of file), and closes `second`: `first`'s end goes to
// TIME_WAIT, and `second`'s FIN is made after `first`'s arrived.
static void end_connection(int first, int second)
{
    struct timeval tv = { 2, 0 };
    setsockopt(second, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    close(first);
    char b;
    ssize_t n = read(second, &b, 1);
    if (n != 0) {
        printf("the first FIN did not arrive: read answered %zd (%s)\n", n, n < 0 ? strerror(errno) : "bytes");
        exit(1);
    }
    close(second);
}

// A client in TIME_WAIT at its port, which is answered.
static int client_time_wait(int l, int lport, int rc, int by_bind)
{
    int server;
    int p = fresh_port();
    int c = connection(l, lport, rc, p, by_bind, &server);
    end_connection(c, server);
    return p;
}

static void binds(const char *row, int port)
{
    const char *addrs[2] = { "127.0.0.1", "0.0.0.0" };
    for (int a = 0; a < 2; a++) {
        for (int reuse = 0; reuse < 2; reuse++) {
            int fd = tcp(reuse);
            int e = bind_at(fd, addrs[a], port);
            printf("%s bind %s:T reuse=%d -> %s", row, addrs[a], reuse, err_name(e));
            if (e == 0) printf("; listen -> %s", err_name(listen(fd, 8) < 0 ? errno : 0));
            printf("\n");
            close(fd);
        }
    }
}

// A search, by a fresh socket carrying SO_REUSEADDR if `reuse`, aimed at
// `port`: a connect to the listener `l` at `lport` (when `lport`), else
// bind(127.0.0.1:0), or listen(2) with no port if `listen_search`.
static void search(const char *row, int port, int reuse, int lport, int l, int listen_search)
{
    int fd = tcp(reuse);
    aim(fd, port);
    int e;
    const char *what;
    int s = -1;
    if (lport) {
        what = "connect";
        e = connect_to(fd, "127.0.0.1", lport);
        if (e == 0) s = accept(l, NULL, NULL);
    } else if (!listen_search) {
        what = "bind 127.0.0.1:0";
        e = bind_at(fd, "127.0.0.1", 0);
    } else {
        what = "listen";
        e = listen(fd, 8) < 0 ? errno : 0;
    }
    int p = port_of(fd);
    printf("%s %s reuse=%d -> %s from port ", row, what, reuse, err_name(e));
    if (p == 0) printf("none\n");
    else printf("T%+d\n", p - port);
    close(fd);
    if (s >= 0) close(s);
}

static void duration_row(int lx, int x, double bound)
{
    int p = client_time_wait(lx, x, 0, 0);
    double start = now();
    double last_failure = -1;
    for (;;) {
        double t = now() - start;
        int fd = tcp(0);
        int e = bind_at(fd, "127.0.0.1", p);
        close(fd);
        if (e == 0) {
            printf("W bind 127.0.0.1:T after %.1f s -> OK; the last EADDRINUSE was after %.1f s\n", t, last_failure);
            return;
        }
        if (e != EADDRINUSE) {
            printf("W bind 127.0.0.1:T after %.1f s -> %s\n", t, err_name(e));
            return;
        }
        last_failure = t;
        if (t > bound) {
            printf("W bind 127.0.0.1:T -> EADDRINUSE throughout %.1f s\n", t);
            return;
        }
        sleep(1);
    }
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
#ifdef __APPLE__
    int msl = 0;
    size_t sz = sizeof msl;
    sysctlbyname("net.inet.tcp.msl", &msl, &sz, NULL, 0);
    printf("net.inet.tcp.msl %d\n", msl);
    double bound = 45;
#else
    const char *files[] = { "/proc/sys/net/ipv4/tcp_tw_reuse", "/proc/sys/net/ipv4/tcp_timestamps",
                            "/proc/sys/net/ipv4/tcp_fin_timeout", "/proc/sys/net/ipv4/ip_local_port_range" };
    for (int i = 0; i < 4; i++) {
        FILE *f = fopen(files[i], "r");
        char line[64] = "?";
        if (f) {
            if (!fgets(line, sizeof line, f)) strcpy(line, "?");
            fclose(f);
        }
        line[strcspn(line, "\n")] = 0;
        printf("%s %s\n", files[i], line);
    }
    double bound = 75;
#endif
    int x = 45501, y = 45502;
    int lx = listener(x, 1), ly = listener(y, 1);

    for (int rc = 0; rc < 2; rc++) {
        char row[8];
        snprintf(row, sizeof row, "B%d", rc);
        binds(row, client_time_wait(lx, x, rc, 0));
    }

    for (int rl = 0; rl < 2; rl++) {
        char row[8];
        snprintf(row, sizeof row, "S%d", rl);
        int q = fresh_port();
        int l = listener(q, rl);
        int server;
        int c = connection(l, q, 0, fresh_port(), 0, &server);
        int cport = port_of(c);
        end_connection(server, c);
        close(l);
        binds(row, q);
        if (rl == 0) {
            int fd = tcp(0);
            printf("P bind 127.0.0.1:T -> %s\n", err_name(bind_at(fd, "127.0.0.1", cport)));
            close(fd);
        }
    }

    {
        int q = fresh_port();
        int l = listener(q, 1);
        int server;
        int c = connection(l, q, 0, fresh_port(), 0, &server);
        int cport = port_of(c);
        end_connection(server, c);
        close(l);
        search("P", cport, 0, y, ly, 0);
    }

    for (int by_bind = 0; by_bind < 2; by_bind++) {
        for (int rc = 0; rc < 2; rc++) {
            for (int to_y = 0; to_y < 2; to_y++) {
#ifdef __linux__
                int delays = 2;
#else
                int delays = 1;
#endif
                for (int d = 0; d < delays; d++) {
                    char row[24];
                    snprintf(row, sizeof row, "C%c%d%s%s", by_bind ? 'b' : 'c', rc, to_y ? "y" : "x", d ? "+2s" : "");
                    int p = client_time_wait(lx, x, rc, by_bind);
                    if (d) sleep(2);
                    search(row, p, rc, to_y ? y : x, to_y ? ly : lx, 0);
                }
            }
        }
    }

    for (int listen_search = 0; listen_search < 2; listen_search++) {
        for (int reuse = 0; reuse < 2; reuse++) {
            char row[8];
            snprintf(row, sizeof row, "L%c", listen_search ? 'l' : 'b');
            search(row, client_time_wait(lx, x, reuse, 0), reuse, 0, -1, listen_search);
        }
    }

    duration_row(lx, x, bound);

    close(lx);
    close(ly);
    return 0;
}
