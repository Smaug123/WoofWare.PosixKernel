// What a socket holding a port at another of the host's addresses does to
// bind-held-endpoint.c's rows, and how a replay of them can tell it is there.
//
// "Elsewhere" is a local IPv4 address that is not loopback (the first such on
// an interface that is up); "lo" is 127.0.0.1 and "any" the wildcard. A
// holder is a socket outside the pair, bound explicitly: bound only,
// listening, connected to a listener at 127.0.0.1, or left in TIME_WAIT by
// closing such a connection first, with no descriptor.
//
// A  Which port choosers give a port that a holder already has: a bind of
//    127.0.0.1:0, the same with SO_REUSEADDR, and connect(2) from an unbound
//    socket (an implicit bind). `shares` if the chooser was given a port a
//    holder has, `skips` if it was given another or refused. On Darwin the
//    allocator hands out ports in sequence (net.inet.tcp.randomize_ports=0),
//    so the holder takes the port after one the probe was just given; of
//    five attempts, `shares` if any chooser was given the holder's port.
//    On Linux, as root, the ephemeral range is narrowed to the two ports the
//    holders have.
// B  bind-held-endpoint.c's four candidates on a port that only a holder
//    elsewhere has: without and with SO_REUSEADDR, at 127.0.0.1 and the
//    wildcard, each listening if it bound and closed before the next.
// C  A bind elsewhere, without SO_REUSEADDR, of the port of each of
//    bind-held-endpoint.c's rows, made after that row's candidates: whether
//    the pair's own sockets, all at 127.0.0.1, ever refuse it; and of a port
//    a holder elsewhere or at the wildcard has. A row is made on a pair whose
//    port such a bind found free before the row began.
// D  On Darwin: whether net.inet.tcp.pcblist64, the kernel's list of TCP
//    sockets, lists a listener of this process's own, and one of a child's.
//
// Build and run, from this directory (on Linux, CAP_SYS_ADMIN lets the probe
// make /proc/sys writable, to narrow the range for A):
//   Darwin: clang -Wall -O1 -o /tmp/port-held-elsewhere port-held-elsewhere.c && /tmp/port-held-elsewhere
//   Linux:  container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe debian:trixie sh -c 'mount -o remount,rw /proc/sys && apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -O1 -o /tmp/p /probe/port-held-elsewhere.c && /tmp/p'
//
// This probe followed a host replay of bind-held-endpoint.c's `p released
// closed oreuse=1` row on Darwin 27.0 that answered `any bind-EADDRINUSE`,
// once in 48 runs. A loop of the `released` rows, nine copies at once beside
// 18 busy loops, refused one `any` candidate in 4320, and
// `lsof -nP -iTCP:<port>` then listed a web browser's connection from the
// host's Wi-Fi address on that port.
//
// Measured 2026-10-14 on Darwin 27.0.0 arm64 (macOS 27.0.1, uid 501) nine
// times and Linux 6.18.5 aarch64 (Apple's container VM, root) seven times,
// with identical output each time; one run of each is
// port-held-elsewhere.darwin-27.0.txt and
// port-held-elsewhere.linux-6.18.5-aarch64.txt. On both, a bind of
// 127.0.0.1:0, with or without SO_REUSEADDR, can be given a port that a
// socket elsewhere holds, whatever its kind, while connect(2) never is, and
// neither is given a port held at 127.0.0.1 or the wildcard. A holder
// elsewhere lets both 127.0.0.1 candidates bind and refuses the wildcard
// one without SO_REUSEADDR (and, on Linux, the one with it), so a replay of
// a row whose port a socket elsewhere holds can answer bind-EADDRINUSE where
// the row was measured to bind. A bind elsewhere of the port, without
// SO_REUSEADDR, is refused by a holder there of every kind and by one at the
// wildcard, and the pair's own sockets never refused it, in any row. On
// Darwin, net.inet.tcp.pcblist64 lists only the calling process's own
// sockets (and `netstat -an -p tcp`, run as the same user, listed no TCP
// socket at all), so a process cannot list another's there.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#endif

static void die(const char *what) { perror(what); exit(2); }

static void settle(void) { usleep(30000); }

static const char *ename(int e)
{
    switch (e) {
    case EADDRINUSE: return "EADDRINUSE";
    case EINVAL: return "EINVAL";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    default: {
        static char b[8][32];
        static int i;
        i = (i + 1) % 8;
        snprintf(b[i], 32, "errno%d", e);
        return b[i];
    }
    }
}

static const uint32_t LO = 0x7f000001;
static const uint32_t ANY = 0;
// Host byte order, as `at` takes it.
static uint32_t elsewhere;

static void set_nb(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) die("fcntl");
}

static void set_reuse(int fd)
{
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) < 0) die("SO_REUSEADDR");
}

static void discard(int fd)
{
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
}

static struct sockaddr_in at(uint32_t address, int port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(address);
    return a;
}

static int port_of(int fd)
{
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    if (getsockname(fd, (struct sockaddr *)&a, &l) < 0) die("getsockname");
    return ntohs(a.sin_port);
}

// A bind of `address`:`port` on a fresh socket: 0 or the errno. The socket
// is returned in *fd, open.
static int bind_fresh(int reuse, uint32_t address, int port, int *fd)
{
    int n = socket(AF_INET, SOCK_STREAM, 0);
    if (n < 0) die("socket");
    if (reuse) set_reuse(n);
    struct sockaddr_in a = at(address, port);
    *fd = n;
    return bind(n, (struct sockaddr *)&a, sizeof a) < 0 ? errno : 0;
}

static int listener_at(uint32_t address)
{
    int l;
    if (bind_fresh(0, address, 0, &l)) die("bind listener");
    if (listen(l, 8) < 0) die("listen");
    return l;
}

// bind-held-endpoint.c's `candidate`, verbatim in effect.
static const char *candidate(int reuse, uint32_t address, int port)
{
    static char b[4][64];
    static int i;
    i = (i + 1) % 4;
    int n;
    int e = bind_fresh(reuse, address, port, &n);
    if (e) {
        snprintf(b[i], 64, "bind-%s", ename(e));
    } else if (listen(n, 4) < 0) {
        snprintf(b[i], 64, "bind-ok listen-%s", ename(errno));
    } else {
        snprintf(b[i], 64, "bind-ok listen-ok");
    }
    close(n);
    return b[i];
}

// The detector: a bind elsewhere of `port`, without SO_REUSEADDR.
static const char *detect(int port)
{
    int n;
    int e = bind_fresh(0, elsewhere, port, &n);
    close(n);
    return e ? (e == EADDRINUSE ? "bind-EADDRINUSE" : ename(e)) : "bind-ok";
}

enum kind { BOUND, LISTENING, CONNECTED, TIME_WAIT };
static const char *kind_name[] = { "bound", "listening", "connected", "time-wait" };

// A holder's descriptors, each -1 once closed: a TIME_WAIT holder has none.
struct held {
    int fd;
    int accepted;
};

// The listener at 127.0.0.1 that CONNECTED and TIME_WAIT holders connect to,
// wherever they are: on Darwin 27.0, a connection from the host's
// non-loopback address to a listener at that address was in CLOSE_WAIT
// within 30 ms, a FIN having arrived though the probe had closed neither
// end, while one to 127.0.0.1 stays up.
static int peer;

// A holder of `address`:`port` of the given kind, bound explicitly: 0, or
// the bind's errno. A CONNECTED holder connects to `peer`; a TIME_WAIT one
// does, then closes before its accepted end does, and is left in TIME_WAIT
// with no descriptor.
static int holder(uint32_t address, int port, enum kind k, struct held *out)
{
    int h;
    int e = bind_fresh(0, address, port, &h);
    out->fd = -1;
    out->accepted = -1;
    if (e) {
        close(h);
        return e;
    }
    out->fd = h;
    if (k == LISTENING && listen(h, 4) < 0) die("listen holder");
    if (k == CONNECTED || k == TIME_WAIT) {
        struct sockaddr_in d = at(LO, port_of(peer));
        if (connect(h, (struct sockaddr *)&d, sizeof d) < 0) die("connect holder");
        settle();
        out->accepted = accept(peer, NULL, NULL);
        if (out->accepted < 0) die("accept holder");
        // Still up: neither end has had end of file or a reset.
        char b;
        if (recv(h, &b, 1, MSG_PEEK | MSG_DONTWAIT) >= 0 || errno != EAGAIN
            || recv(out->accepted, &b, 1, MSG_PEEK | MSG_DONTWAIT) >= 0 || errno != EAGAIN) {
            fprintf(stderr, "a holder's connection ended before it closed\n");
            exit(2);
        }
    }
    if (k == TIME_WAIT) {
        close(out->fd);
        settle();
        close(out->accepted);
        settle();
        out->fd = -1;
        out->accepted = -1;
    }
    return 0;
}

static void drop_holder(struct held h)
{
    if (h.fd >= 0) discard(h.fd);
    if (h.accepted >= 0) discard(h.accepted);
}

// A holder at the wildcard that connects takes a local address, so it is
// not at the wildcard: only one bound or listening is made there.
static int kind_fits(int at_any, enum kind k)
{
    return !at_any || k == BOUND || k == LISTENING;
}

enum chooser { BIND_LO, BIND_LO_REUSE, CONNECT };
static const char *chooser_name[] = { "bind-lo-0", "bind-lo-0+reuse", "connect" };

// Runs `c`, connecting to `target` if it connects; the port it was given,
// or -errno. The socket stays open in *fd.
static int choose(enum chooser c, int target, int *fd)
{
    int y;
    if (c == CONNECT) {
        y = socket(AF_INET, SOCK_STREAM, 0);
        if (y < 0) die("socket");
        struct sockaddr_in d = at(LO, port_of(target));
        *fd = y;
        if (connect(y, (struct sockaddr *)&d, sizeof d) < 0) return -errno;
        return port_of(y);
    }
    int e = bind_fresh(c == BIND_LO_REUSE, LO, 0, &y);
    *fd = y;
    return e ? -e : port_of(y);
}

#ifdef __APPLE__
static void section_a(void)
{
    const uint32_t places[] = { 0, LO, ANY };  // 0 is replaced by elsewhere
    const char *place_name[] = { "elsewhere", "lo", "any" };
    for (int c = 0; c < 3; c++)
        for (int p = 0; p < 3; p++)
            for (int k = 0; k < 4; k++) {
                uint32_t address = p == 0 ? elsewhere : places[p];
                if (!kind_fits(p == 2, k)) continue;
                // Five attempts in which the chooser was given q + 1 or
                // q + 2. Only sharing gives q + 1, but another process
                // taking q + 1 first gives q + 2 whether the chooser would
                // have shared or not, so one q + 1 settles `shares`.
                int determined = 0, shared = 0;
                for (int attempt = 0; attempt < 100 && determined < 5; attempt++) {
                    int t;
                    if (bind_fresh(0, LO, 0, &t)) die("bind 0");
                    int q = port_of(t);
                    close(t);
                    struct held h;
                    // q + 1 is held by another process: again.
                    if (holder(address, q + 1, k, &h)) continue;
                    int y;
                    int got = choose(c, peer, &y);
                    if (got == q + 1) shared = 1;
                    // Any port but these: one was taken meanwhile; again.
                    if (got == q + 1 || got == q + 2) determined++;
                    discard(y);
                    if (c == CONNECT && got > 0) {
                        int a = accept(peer, NULL, NULL);
                        if (a >= 0) discard(a);
                    }
                    drop_holder(h);
                }
                printf("A\t%s\tholder %s %s\t%s\n", chooser_name[c], place_name[p], kind_name[k],
                       determined < 5 ? "undetermined" : shared ? "shares" : "skips");
                fflush(stdout);
            }
}
#else
static int set_range(int low, int high)
{
    FILE *f = fopen("/proc/sys/net/ipv4/ip_local_port_range", "w");
    if (!f) return -1;
    int r = fprintf(f, "%d %d\n", low, high) < 0 ? -1 : 0;
    if (fclose(f) != 0) r = -1;
    return r;
}

static void section_a(void)
{
    char saved[64] = "";
    FILE *f = fopen("/proc/sys/net/ipv4/ip_local_port_range", "r");
    if (!f || !fgets(saved, sizeof saved, f)) die("read ip_local_port_range");
    fclose(f);
    // Each case takes two ports of its own, not the peer's, since a
    // TIME_WAIT holder outlives its case.
    int next_low = 40000;
    const uint32_t places[] = { 0, LO, ANY };
    const char *place_name[] = { "elsewhere", "lo", "any" };
    for (int c = 0; c < 3; c++)
        for (int p = 0; p < 3; p++)
            for (int k = 0; k < 4; k++) {
                uint32_t address = p == 0 ? elsewhere : places[p];
                if (!kind_fits(p == 2, k)) continue;
                while (abs(next_low - port_of(peer)) < 2) next_low += 2;
                int low = next_low;
                next_low += 2;
                if (set_range(low, low + 1) < 0) {
                    printf("A\tnot measured: the ephemeral range cannot be narrowed (%s)\n", strerror(errno));
                    return;
                }
                struct held h[2];
                for (int i = 0; i < 2; i++) {
                    int e = holder(address, low + i, k, &h[i]);
                    if (e) { errno = e; die("holder"); }
                }
                int y;
                int got = choose(c, peer, &y);
                const char *verdict = got == low || got == low + 1 ? "shares" : "skips";
                discard(y);
                if (c == CONNECT && got > 0) {
                    int a = accept(peer, NULL, NULL);
                    if (a >= 0) discard(a);
                }
                for (int i = 0; i < 2; i++) drop_holder(h[i]);
                printf("A\t%s\tholder %s %s\t%s\n", chooser_name[c], place_name[p], kind_name[k], verdict);
                fflush(stdout);
            }
    int lo2, hi2;
    if (sscanf(saved, "%d %d", &lo2, &hi2) != 2 || set_range(lo2, hi2) < 0) die("restore ip_local_port_range");
}
#endif

// A port no socket has at any address: one a wildcard bind was given.
static int free_port(void)
{
    int t;
    if (bind_fresh(0, ANY, 0, &t)) die("bind any 0");
    int port = port_of(t);
    close(t);
    return port;
}

// A holder at `address` of a port free at every address; another free port
// if another process takes the first meanwhile.
static struct held holder_on_free_port(uint32_t address, enum kind k, int *port)
{
    for (int attempt = 0; attempt < 20; attempt++) {
        *port = free_port();
        struct held h;
        if (!holder(address, *port, k, &h)) return h;
    }
    fprintf(stderr, "twenty free ports were each taken before a holder could bind them\n");
    exit(2);
}

static void section_b_and_c_holders(void)
{
    for (int k = 0; k < 4; k++) {
        int port;
        struct held h = holder_on_free_port(elsewhere, k, &port);
        const char *lo = candidate(0, LO, port);
        const char *lor = candidate(1, LO, port);
        const char *any = candidate(0, ANY, port);
        const char *anyr = candidate(1, ANY, port);
        printf("B\tholder elsewhere %s\tlo %s\tlo+reuse %s\tany %s\tany+reuse %s\n", kind_name[k], lo, lor, any, anyr);
        printf("C\tholder elsewhere %s\tdetector %s\n", kind_name[k], detect(port));
        drop_holder(h);
    }
    for (int k = 0; k < 4; k++) {
        if (!kind_fits(1, k)) continue;
        int port;
        struct held h = holder_on_free_port(ANY, k, &port);
        printf("C\tholder any %s\tdetector %s\n", kind_name[k], detect(port));
        drop_holder(h);
    }
    fflush(stdout);
}

// bind-held-endpoint.c's pair, fill and rows, with the detector after each
// row's candidates.
static void pair(int creuse, int lreuse, int *c, int *p)
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    if (l < 0) die("socket");
    if (lreuse) set_reuse(l);
    struct sockaddr_in a = at(LO, 0);
    if (bind(l, (struct sockaddr *)&a, sizeof a) < 0) die("bind");
    if (listen(l, 4) < 0) die("listen");
    *c = socket(AF_INET, SOCK_STREAM, 0);
    if (*c < 0) die("socket");
    if (creuse) set_reuse(*c);
    struct sockaddr_in d = at(LO, port_of(l));
    if (connect(*c, (struct sockaddr *)&d, sizeof d) < 0) die("connect");
    settle();
    *p = accept(l, NULL, NULL);
    if (*p < 0) die("accept");
    close(l);
    set_nb(*c);
    set_nb(*p);
}

static long fill(int o, int q)
{
    static char buf[1 << 16];
    long written = 0;
    for (int round = 0; round < 20; round++) {
        int idle = 0;
        while (idle < 3) {
            long r = write(o, buf, sizeof buf);
            if (r < 0) {
                if (errno != EAGAIN) die("fill");
                idle++;
                settle();
            } else {
                written += r;
            }
        }
        settle();
        int unread = 0;
        if (ioctl(q, FIONREAD, &unread) < 0) die("FIONREAD");
        if (written > unread) return written;
    }
    fprintf(stderr, "fill: nothing stays unsent\n");
    exit(2);
}

static void fin(int o, int open)
{
    if (open) shutdown(o, SHUT_WR);
    else close(o);
    settle();
}

// How many rows `section_c_rows` made again; on stderr, as it varies.
static int redrawn;

static void section_c_rows(void)
{
    const char *states[] = { "released", "tw", "fw2", "active-queued", "passive-queued" };
    for (int oc = 1; oc >= 0; oc--)
        for (int s = 0; s < 5; s++)
            for (int open = 0; open < 2; open++)
                for (int oreuse = 0; oreuse < 2; oreuse++) {
                    int c, p, o, q, port;
                    // A row whose port a socket elsewhere already has (a
                    // bind of 127.0.0.1:0 can be given such a port, as A
                    // finds) is made again on a fresh pair, so that what the
                    // detector finds after the row is the pair's own doing.
                    for (int draw = 0;; draw++) {
                        if (draw == 20) {
                            fprintf(stderr, "twenty pairs' ports were each held elsewhere\n");
                            exit(2);
                        }
                        pair(oc && oreuse, !oc && oreuse, &c, &p);
                        o = oc ? c : p;
                        q = oc ? p : c;
                        port = port_of(o);
                        if (!strcmp(detect(port), "bind-ok")) break;
                        redrawn++;
                        discard(c);
                        discard(p);
                    }
                    const char *state = states[s];
                    if (!strcmp(state, "released")) {
                        shutdown(q, SHUT_WR);
                        settle();
                        fin(o, open);
                    } else if (!strcmp(state, "tw")) {
                        fin(o, open);
                        shutdown(q, SHUT_WR);
                        settle();
                    } else if (!strcmp(state, "fw2")) {
                        fin(o, open);
                    } else if (!strcmp(state, "active-queued")) {
                        fill(o, q);
                        fin(o, open);
                    } else {
                        shutdown(q, SHUT_WR);
                        settle();
                        fill(o, q);
                        fin(o, open);
                    }
                    candidate(0, LO, port);
                    candidate(1, LO, port);
                    candidate(0, ANY, port);
                    candidate(1, ANY, port);
                    printf("C\t%s\t%s\t%s\toreuse=%d\tdetector %s\n", oc ? "c" : "p", state, open ? "open" : "closed",
                           oreuse, detect(port));
                    fflush(stdout);
                    if (open) discard(o);
                    discard(q);
                    settle();
                }
}

#ifdef __APPLE__
// Whether net.inet.tcp.pcblist64 lists a PCB whose local port is `port`.
static int pcb_listed(int port)
{
    size_t len = 0;
    if (sysctlbyname("net.inet.tcp.pcblist64", NULL, &len, NULL, 0) < 0) die("pcblist64 size");
    len += 1 << 16;
    char *buf = malloc(len);
    if (!buf) die("malloc");
    if (sysctlbyname("net.inet.tcp.pcblist64", buf, &len, NULL, 0) < 0) die("pcblist64");
    struct xinpgen *head = (struct xinpgen *)buf;
    int found = 0;
    for (char *p = buf + head->xig_len; p + sizeof(struct xinpgen) < buf + len;) {
        struct xtcpcb64 *t = (struct xtcpcb64 *)p;
        if (t->xt_len <= sizeof(struct xinpgen)) break;
        if (ntohs(t->xt_inpcb.inp_lport) == port) found = 1;
        p += t->xt_len;
    }
    free(buf);
    return found;
}

static void section_d(void)
{
    int l = listener_at(LO);
    int up[2], down[2];
    if (pipe(up) < 0 || pipe(down) < 0) die("pipe");
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        // The child's own listener, made after the fork.
        close(l);
        int cl = listener_at(LO);
        int port = port_of(cl);
        if (write(up[1], &port, sizeof port) != sizeof port) _exit(2);
        char done;
        if (read(down[0], &done, 1) < 0) _exit(2);
        _exit(0);
    }
    int child_port;
    if (read(up[0], &child_port, sizeof child_port) != sizeof child_port) die("read child port");
    printf("D\tpcblist64 as uid %s\tthe probe's own listener %s\ta child process's listener %s\n",
           geteuid() == 0 ? "0" : "other than 0", pcb_listed(port_of(l)) ? "listed" : "not listed",
           pcb_listed(child_port) ? "listed" : "not listed");
    if (write(down[1], "x", 1) != 1) die("write");
    int status;
    waitpid(child, &status, 0);
    close(l);
}
#endif

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    struct utsname u;
    if (uname(&u) < 0) die("uname");
    printf("#\t%s %s %s\n", u.sysname, u.release, u.machine);
    struct ifaddrs *ifs;
    if (getifaddrs(&ifs) < 0) die("getifaddrs");
    for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
        if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK)) continue;
        uint32_t a = ntohl(((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr);
        if ((a >> 24) == 127) continue;
        elsewhere = a;
        printf("#\telsewhere: an address of %s\n", i->ifa_name);
        break;
    }
    freeifaddrs(ifs);
    if (!elsewhere) {
        fprintf(stderr, "no up, non-loopback IPv4 address\n");
        return 2;
    }
    peer = listener_at(LO);
    section_a();
    section_b_and_c_holders();
    section_c_rows();
    fprintf(stderr, "rows made again because their port was held elsewhere: %d\n", redrawn);
#ifdef __APPLE__
    section_d();
#endif
    return 0;
}
