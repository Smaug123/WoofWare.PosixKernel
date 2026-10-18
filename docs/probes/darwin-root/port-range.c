// Which values Darwin's ephemeral port range sysctls take
// (net.inet.ip.portrange.first, last, hifirst, hilast, lowfirst, lowlast), and
// which ports bind(2) of port 0, and connect(2) of an unbound socket, then
// hand out.
//
// Darwin only. Run it as root, through run.sh beside this file:
//   cd /tmp && sudo sh <checkout>/docs/probes/darwin-root/run.sh
// By hand: cc -Wall -Werror -o /tmp/port-range port-range.c && sudo /tmp/port-range
// As an ordinary user every write is refused, and it says so row by row.
//
// It changes machine-wide settings, for as short a time as it can: each SET
// row writes one sysctl, reads it back and puts it back at once; each ALLOC
// row narrows the range to a few ports, takes them, and puts the range back
// before printing anything. Every original value is restored on exit, on a
// fatal signal, and again by run.sh, from the values it read first; each
// restoration is read back, a sysctl that is not then what it was is named on
// stderr (RESTORE-FAILED), the probe changes nothing more, and it exits 3.
// It exits 1 if a child failed. While a
// range is narrowed (a few milliseconds a row) another process's outgoing
// connection or port-0 bind on the machine can fail or take one of the
// probe's ports.
//
// Rows:
//   READ <name> = <value>                 before anything is changed
//   SET <name> <value> -> <errno> readback=<value>
//   ALLOC <who> <config> <socket> -> <port or errno> ...
//       <config> names what was written and what was read back; each socket
//       is fresh and kept open until the row ends, so the five answers are
//       five different ports or a refusal. A tcp socket and a udp socket are
//       bound at 0.0.0.0:0 (or 127.0.0.1:0); "connect" is a tcp socket with
//       no port connecting to a listener at loopback; "high" and "low" set
//       IP_PORTRANGE to IP_PORTRANGE_HIGH or IP_PORTRANGE_LOW first.
//   RESTORED <name> = <value>             after the last row
#ifndef __APPLE__
#error "Darwin only"
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define NNAMES 6
static const char *names[NNAMES] = {
    "net.inet.ip.portrange.first",   "net.inet.ip.portrange.last",     "net.inet.ip.portrange.hifirst",
    "net.inet.ip.portrange.hilast",  "net.inet.ip.portrange.lowfirst", "net.inet.ip.portrange.lowlast",
};
static int orig[NNAMES];
static volatile sig_atomic_t have_orig;

static const char *en(int e) {
    static char b[4][32];
    static int k;
    k = (k + 1) % 4;
    switch (e) {
    case 0: return "ok";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case EINVAL: return "EINVAL";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case ECONNREFUSED: return "ECONNREFUSED";
    default: snprintf(b[k], sizeof b[k], "errno%d", e); return b[k];
    }
}

static int get(const char *name, int *v) {
    size_t l = sizeof *v;
    return sysctlbyname(name, v, &l, NULL, 0) == 0 ? 0 : errno;
}

static int set(const char *name, int v) { return sysctlbyname(name, NULL, NULL, &v, sizeof v) == 0 ? 0 : errno; }

// Writes to stderr with write(2) alone, so a signal handler may call it.
static void put(const char *s) {
    ssize_t r = write(2, s, strlen(s));
    (void)r;
}

static void put_int(int v) {
    char b[16];
    int i = (int)sizeof b;
    b[--i] = 0;
    unsigned u = v < 0 ? 0u - (unsigned)v : (unsigned)v;
    do b[--i] = (char)('0' + u % 10); while ((u /= 10) && i > 1);
    if (v < 0) b[--i] = '-';
    put(b + i);
}

static volatile sig_atomic_t restore_failed;

// How many takes failed: a child that did not exit 0 or report, or, as root,
// one that could not take its uid. Any makes the probe exit 1.
static int failures;

// Put back every sysctl that is not what it was, read each back, and name on
// stderr any that is still not what it was. Returns how many such there are.
// Calls only sysctl and write(2), so a signal handler may call it.
static int restore(void) {
    if (!have_orig) return 0;
    int failed = 0;
    for (int i = 0; i < NNAMES; i++) {
        int now = -1;
        if (get(names[i], &now) == 0 && now == orig[i]) continue;
        int e = set(names[i], orig[i]);
        int back = -1;
        int ge = get(names[i], &back);
        if (e != 0 || ge != 0 || back != orig[i]) {
            failed++;
            restore_failed = 1;
            put("RESTORE-FAILED\t");
            put(names[i]);
            put(" is ");
            put_int(back);
            put(", should be ");
            put_int(orig[i]);
            put(" (write errno ");
            put_int(e);
            put("): put it back with sudo sysctl -w\n");
        }
    }
    return failed;
}

static void restore_at_exit(void) {
    if (restore() != 0) {
        fflush(stdout);
        _exit(3);
    }
}

static void on_signal(int sig) {
    restore();
    signal(sig, SIG_DFL);
    raise(sig);
}

static int become(uid_t uid) {
    if (geteuid() == uid) return 0;
    if (geteuid() != 0) return EPERM;
    gid_t g = 20;
    if (setgroups(1, &g) != 0) return errno;
    if (setgid(20) != 0) return errno;
    return setuid(uid) == 0 ? 0 : errno;
}

static struct sockaddr_in at(const char *addr, int port) {
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
    s.sin_len = sizeof s;
    s.sin_family = AF_INET;
    s.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, addr, &s.sin_addr);
    return s;
}

// Whether `port` is free for both TCP and UDP at the wildcard.
static int free_port(int port) {
    int types[] = {SOCK_STREAM, SOCK_DGRAM};
    for (int t = 0; t < 2; t++) {
        int s = socket(AF_INET, types[t], 0);
        if (s < 0) return 0;
        struct sockaddr_in sa = at("0.0.0.0", port);
        int ok = bind(s, (struct sockaddr *)&sa, sizeof sa) == 0;
        close(s);
        if (!ok) return 0;
    }
    return 1;
}

enum sock_kind { TCP_ANY, TCP_LOOP, UDP_ANY, TCP_CONNECT, TCP_HIGH, TCP_LOW };
static const char *sock_name[] = {"tcp 0.0.0.0:0", "tcp 127.0.0.1:0", "udp 0.0.0.0:0", "connect", "tcp high 0.0.0.0:0", "tcp low 0.0.0.0:0"};

// Take `n` ports the way `k` says, as `uid` (in a child when it is not this
// process's), writing each port or -errno into `out`.
static void take(uid_t uid, enum sock_kind k, int n, int listen_port, int *out) {
    int pfd[2];
    if (pipe(pfd) != 0) {
        for (int i = 0; i < n; i++) out[i] = -9999;
        failures++;
        return;
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        close(pfd[0]);
        int res[16];
        int fds[16];
        int e = become(uid);
        for (int i = 0; i < n; i++) {
            fds[i] = -1;
            if (e != 0) {
                res[i] = -100000 - e;
                continue;
            }
            int s = socket(AF_INET, k == UDP_ANY ? SOCK_DGRAM : SOCK_STREAM, 0);
            if (s < 0) {
                res[i] = -errno;
                continue;
            }
            fds[i] = s;
            if (k == TCP_HIGH || k == TCP_LOW) {
                int r = k == TCP_HIGH ? IP_PORTRANGE_HIGH : IP_PORTRANGE_LOW;
                if (setsockopt(s, IPPROTO_IP, IP_PORTRANGE, &r, sizeof r) != 0) {
                    res[i] = -200000 - errno;
                    continue;
                }
            }
            int r;
            if (k == TCP_CONNECT) {
                struct sockaddr_in sa = at("127.0.0.1", listen_port);
                r = connect(s, (struct sockaddr *)&sa, sizeof sa);
            } else {
                struct sockaddr_in sa = at(k == TCP_LOOP ? "127.0.0.1" : "0.0.0.0", 0);
                r = bind(s, (struct sockaddr *)&sa, sizeof sa);
            }
            if (r != 0) {
                res[i] = -errno;
                continue;
            }
            struct sockaddr_in got;
            socklen_t len = sizeof got;
            getsockname(s, (struct sockaddr *)&got, &len);
            res[i] = ntohs(got.sin_port);
        }
        if (write(pfd[1], res, sizeof(int) * (size_t)n) != (ssize_t)(sizeof(int) * (size_t)n)) _exit(1);
        // A connection closes with a reset, so its port is not left in
        // TIME_WAIT for the rows after it.
        struct linger lg = {1, 0};
        for (int i = 0; i < n; i++)
            if (fds[i] >= 0) {
                if (k == TCP_CONNECT) setsockopt(fds[i], SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
                close(fds[i]);
            }
        _exit(0);
    }
    close(pfd[1]);
    if (read(pfd[0], out, sizeof(int) * (size_t)n) != (ssize_t)(sizeof(int) * (size_t)n))
        for (int i = 0; i < n; i++) out[i] = -9999;
    close(pfd[0]);
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0)
        for (int i = 0; i < n; i++) out[i] = -9999;
    for (int i = 0; i < n; i++)
        if (out[i] == -9999 || (geteuid() == 0 && out[i] <= -100000 && out[i] > -200000)) {
            failures++;
            break;
        }
}

static void answer_text(char *b, size_t cap, int v) {
    if (v >= 0) snprintf(b, cap, "%d", v);
    else if (v == -9999) snprintf(b, cap, "probe-failure");
    else if (v <= -200000) snprintf(b, cap, "setsockopt:%s", en(-200000 - v));
    else if (v <= -100000) snprintf(b, cap, "SKIP(become: %s)", en(-100000 - v));
    else snprintf(b, cap, "%s", en(-v));
}

typedef struct {
    const char *label;
    int idx[2];
    int val[2];
    int nset;
} config;

int main(void) {
    int ls = -1;
    int stopped = 0;
    struct utsname u;
    uname(&u);
    char product[64] = "?";
    size_t plen = sizeof product;
    sysctlbyname("kern.osproductversion", product, &plen, NULL, 0);
    printf("# port-range: %s %s %s (macOS %s)\tuid=%u euid=%u\n", u.sysname, u.release, u.machine, product, (unsigned)getuid(), (unsigned)geteuid());
    for (int i = 0; i < NNAMES; i++) {
        int e = get(names[i], &orig[i]);
        if (e != 0) {
            printf("READ\t%s\t%s\n", names[i], en(e));
            return 2;
        }
        printf("READ\t%s = %d\n", names[i], orig[i]);
    }
    const char *others[] = {"net.inet.tcp.randomize_ports", "net.inet.udp.randomize_ports", "net.inet.ip.portrange.ipport_allow_udp_port_exhaustion"};
    for (int i = 0; i < 3; i++) {
        int v;
        int e = get(others[i], &v);
        if (e == 0) printf("READ\t%s = %d\n", others[i], v);
        else printf("READ\t%s\t%s\n", others[i], en(e));
    }
    fflush(stdout);
    have_orig = 1;
    atexit(restore_at_exit);
    int sigs[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGSEGV, SIGBUS, SIGABRT, SIGALRM, SIGPIPE};
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) signal(sigs[i], on_signal);
    alarm(600);

    // SET: one sysctl at a time, put back at once.
    const int values[] = {-1, 0, 1, 599, 600, 1023, 1024, 1025, 2000, 49151, 49152, 65535, 65536, 70000};
    for (int i = 0; i < NNAMES; i++)
        for (size_t v = 0; v < sizeof values / sizeof values[0]; v++) {
            int e = set(names[i], values[v]);
            int back = -1;
            int ge = get(names[i], &back);
            int unrestored = restore();
            int after = -1;
            get(names[i], &after);
            printf("SET\t%s\t%d\t-> %s\treadback=%d%s", names[i], values[v], en(e), back, ge ? " (read failed)" : "");
            if (unrestored) printf("\tRESTORE-FAILED now=%d", after);
            printf("\n");
            fflush(stdout);
            if (unrestored) {
                stopped = 1;
                goto finish;
            }
        }

    // A block of four ports free for TCP and UDP at the wildcard.
    int B = 0;
    for (int c = 40000; c < 48000 && !B; c += 8)
        if (free_port(c) && free_port(c + 1) && free_port(c + 2) && free_port(c + 3)) B = c;
    if (!B) {
        printf("ALLOC\tSKIP: no four free ports found in 40000-48000\nDONE\n");
        return 0;
    }
    // A listener for the connect rows, at a port from the unchanged range.
    ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la = at("127.0.0.1", 0);
    socklen_t llen = sizeof la;
    if (ls < 0 || bind(ls, (struct sockaddr *)&la, sizeof la) != 0 || listen(ls, 16) != 0 || getsockname(ls, (struct sockaddr *)&la, &llen) != 0) {
        perror("listener");
        return 2;
    }
    int L = ntohs(la.sin_port);
    fcntl(ls, F_SETFL, fcntl(ls, F_GETFL) | O_NONBLOCK);
    printf("# block B=%d (ports %d-%d free for tcp and udp at 0.0.0.0), listener at 127.0.0.1:%d\n", B, B, B + 3, L);

    // first/last indices: 0 1; hifirst/hilast: 2 3.
    config configs[] = {
        {"first=B last=B+3", {0, 1}, {B, B + 3}, 2},
        {"first=B+3 last=B", {0, 1}, {B + 3, B}, 2},
        {"first=B+1 last=B+1", {0, 1}, {B + 1, B + 1}, 2},
        {"hifirst=B hilast=B+3", {2, 3}, {B, B + 3}, 2},
        {"first=1 last=1027", {0, 1}, {1, 1027}, 2},
        {"unchanged", {0, 0}, {0, 0}, 0},
    };
    const uid_t whos[] = {0, 501};
    for (size_t ci = 0; ci < sizeof configs / sizeof configs[0]; ci++)
        for (size_t w = 0; w < 2; w++) {
            config *c = &configs[ci];
            enum sock_kind kinds[] = {TCP_ANY, TCP_LOOP, UDP_ANY, TCP_CONNECT, TCP_HIGH, TCP_LOW};
            int res[6][5];
            int e[2] = {0, 0}, back[2] = {-1, -1};
            for (int i = 0; i < c->nset; i++) e[i] = set(names[c->idx[i]], c->val[i]);
            for (int i = 0; i < c->nset; i++) get(names[c->idx[i]], &back[i]);
            int any_set = c->nset == 0 || (e[0] == 0 && e[1] == 0);
            if (any_set)
                for (int k = 0; k < 6; k++) take(whos[w], kinds[k], (kinds[k] == TCP_LOW) ? 2 : 5, L, res[k]);
            int unrestored = restore();
            // Empty the listener's queue of the connections just made.
            for (int a; (a = accept(ls, NULL, NULL)) >= 0;) close(a);
            char head[256];
            if (c->nset)
                snprintf(head, sizeof head, "ALLOC\t%s\t%s (wrote %s=%d %s, %s=%d %s; read back %d, %d)", whos[w] ? "u501" : "root", c->label, names[c->idx[0]] + 22,
                         c->val[0], en(e[0]), names[c->idx[1]] + 22, c->val[1], en(e[1]), back[0], back[1]);
            else snprintf(head, sizeof head, "ALLOC\t%s\t%s", whos[w] ? "u501" : "root", c->label);
            if (!any_set) {
                printf("%s\tSKIP: the range could not be written\n", head);
                if (unrestored) {
                    stopped = 1;
                    goto finish;
                }
                continue;
            }
            for (int k = 0; k < 6; k++) {
                printf("%s\t%s\t->", head, sock_name[kinds[k]]);
                for (int i = 0; i < ((kinds[k] == TCP_LOW) ? 2 : 5); i++) {
                    char b[64];
                    answer_text(b, sizeof b, res[k][i]);
                    printf(" %s", b);
                }
                printf("\n");
            }
            fflush(stdout);
            if (unrestored) {
                stopped = 1;
                goto finish;
            }
        }
finish:
    if (stopped) printf("STOPPED\ta sysctl could not be put back (RESTORE-FAILED on stderr), so nothing more was changed\n");
    if (ls >= 0) close(ls);
    restore();
    for (int i = 0; i < NNAMES; i++) {
        int v = -1;
        get(names[i], &v);
        printf("RESTORED\t%s = %d%s\n", names[i], v, v == orig[i] ? "" : "\tDIFFERS FROM THE ORIGINAL");
    }
    if (failures) printf("FAILURES\t%d takes failed: see the probe-failure answers\n", failures);
    printf("DONE\n");
    fflush(stdout);
    return restore_failed ? 3 : failures ? 1 : 0;
}
