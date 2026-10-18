// Whether Darwin's bind(2) answers EADDRINUSE because the socket already
// holding the port belongs to another user: an IPv4 port held by one uid,
// then bound by another, over the wildcard and loopback on each side, with
// and without SO_REUSEADDR and SO_REUSEPORT on each side, for TCP (the holder
// idle or listening) and UDP, with root on either side.
//
// Darwin only. Run it as root, through run.sh beside this file:
//   sudo sh docs/probes/darwin-root/run.sh
// By hand: cc -Wall -Werror -o /tmp/bind-uids bind-uids.c && sudo /tmp/bind-uids
// As an ordinary user it measures the rows whose holder and binder are both
// that user, and prints SKIP for the rest.
//
// Each BIND row: a holder process takes its uid (setgroups 20, setgid 20,
// setuid; root keeps 0), makes its socket, sets its options, binds its address
// at port 0 (so the kernel picks a port no socket holds at an overlapping
// address), and listens if the row says so; it holds the socket until the row
// ends. A binder process then takes its own uid, makes a socket with its own
// options, and binds its address at the holder's port: that answer is the
// row's. Then the holder exits and a fresh binder, with the same uid and
// options, binds the same address and port again: `control` must be ok, or
// something other than the holder was in the way and the row says nothing.
//   BIND proto= holder=<uid> haddr= hopts= hstate= binder=<uid> baddr= bopts= -> <errno> control=<errno> port=
// Options: - none, A SO_REUSEADDR, P SO_REUSEPORT, AP both.
// A TCP holder listens only at loopback: listening at the wildcard would ask
// the application firewall to admit the probe.
//
// It exits 1 if any child failed, so that its output is not taken for a
// complete measurement.
//
// CRED rows ask whether the uid that counts is the socket's (fixed when
// socket(2) made it) or the process's at bind(2): a socket made as root and
// bound after setuid, against a holder of another uid, and the converse.
//   CRED proto= holder=<how> haddr= binder=<how> baddr= -> <errno> control=<errno>
#ifndef __APPLE__
#error "Darwin only"
#endif
#include <arpa/inet.h>
#include <errno.h>
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

static const char *en(int e) {
    static char b[32];
    switch (e) {
    case 0: return "ok";
    case EADDRINUSE: return "EADDRINUSE";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EINVAL: return "EINVAL";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}

static int become(uid_t uid) {
    if (geteuid() == uid) return 0;
    if (geteuid() != 0) return EPERM;
    gid_t g = 20;
    if (setgroups(1, &g) != 0) return errno;
    if (setgid(20) != 0) return errno;
    if (setuid(uid) != 0) return errno;
    return 0;
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

static int set_opts(int s, int opts) {
    int one = 1;
    if ((opts & 1) && setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) return errno;
    if ((opts & 2) && setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) != 0) return errno;
    return 0;
}

static const char *opts_name(int o) {
    static const char *n[] = {"-", "A", "P", "AP"};
    return n[o];
}

static const char *uid_name(uid_t u) {
    static char b[4][16];
    static int k;
    k = (k + 1) % 4;
    if (u == 0) snprintf(b[k], sizeof b[k], "root");
    else snprintf(b[k], sizeof b[k], "u%u", (unsigned)u);
    return b[k];
}

typedef struct {
    int err;
    int port;
} answer;

// How many rows had a child fail: one that did not exit 0 or report, or, as
// root, one that could not take its uid. Any makes the probe exit 1.
static int failures;

// Whether a child's answer, or its exit, is a failure of the probe rather
// than a measurement.
static int failed(int err) { return err == -1 || (geteuid() == 0 && err <= -100); }

// What a process becoming `uid` then making a socket (or, if `socket_first`,
// making it and then becoming `uid`) answers binding addr:port with `opts`.
static int bind_as(uid_t uid, int socket_first, int type, const char *addr, int port, int opts) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        close(pfd[0]);
        answer a = {0, 0};
        int s = -1;
        if (socket_first) s = socket(AF_INET, type, 0);
        int e = become(uid);
        if (e != 0) a.err = -100 - e;
        else {
            if (!socket_first) s = socket(AF_INET, type, 0);
            if (s < 0) a.err = errno;
            else if ((e = set_opts(s, opts)) != 0) a.err = e;
            else {
                struct sockaddr_in sa = at(addr, port);
                a.err = bind(s, (struct sockaddr *)&sa, sizeof sa) == 0 ? 0 : errno;
            }
        }
        if (write(pfd[1], &a, sizeof a) != sizeof a) _exit(1);
        _exit(0);
    }
    close(pfd[1]);
    answer a = {-1, 0};
    if (read(pfd[0], &a, sizeof a) != sizeof a) a.err = -1;
    close(pfd[0]);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) a.err = -1;
    return a.err;
}

typedef struct {
    pid_t pid;
    int hold_w;
    int err;
    int port;
} holder;

static holder hold(uid_t uid, int socket_first, int type, const char *addr, int opts, int listening) {
    holder h = {-1, -1, -1, 0};
    int ready[2], go[2];
    if (pipe(ready) != 0 || pipe(go) != 0) return h;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(20);
        close(ready[0]);
        close(go[1]);
        answer a = {0, 0};
        int s = -1;
        if (socket_first) s = socket(AF_INET, type, 0);
        int e = become(uid);
        if (e != 0) a.err = -100 - e;
        else {
            if (!socket_first) s = socket(AF_INET, type, 0);
            struct sockaddr_in sa = at(addr, 0);
            socklen_t len = sizeof sa;
            if (s < 0) a.err = errno;
            else if ((e = set_opts(s, opts)) != 0) a.err = e;
            else if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0) a.err = errno;
            else if (listening && listen(s, 1) != 0) a.err = errno;
            else if (getsockname(s, (struct sockaddr *)&sa, &len) != 0) a.err = errno;
            else a.port = ntohs(sa.sin_port);
        }
        if (write(ready[1], &a, sizeof a) != sizeof a) _exit(1);
        char c;
        while (read(go[0], &c, 1) > 0) {
        }
        _exit(0);
    }
    close(ready[1]);
    close(go[0]);
    answer a = {-1, 0};
    if (read(ready[0], &a, sizeof a) != sizeof a) a.err = -1;
    close(ready[0]);
    h.pid = pid;
    h.hold_w = go[1];
    h.err = a.err;
    h.port = a.port;
    return h;
}

// Let the holder go; answers -1 if it did not exit 0, and 0 otherwise.
static int release(holder *h) {
    if (h->hold_w >= 0) close(h->hold_w);
    int st = 0;
    if (h->pid > 0 && (waitpid(h->pid, &st, 0) != h->pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0)) return -1;
    return 0;
}

static const char *result_text(int e) {
    static char b[4][48];
    static int k;
    k = (k + 1) % 4;
    if (e <= -100) snprintf(b[k], sizeof b[k], "SKIP(become: %s, needs root)", en(-100 - e));
    else if (e < 0) snprintf(b[k], sizeof b[k], "SKIP(probe failure)");
    else snprintf(b[k], sizeof b[k], "%s", en(e));
    return b[k];
}

int main(void) {
    struct utsname u;
    uname(&u);
    char product[64] = "?";
    size_t plen = sizeof product;
    sysctlbyname("kern.osproductversion", product, &plen, NULL, 0);
    int first = 0, last = 0;
    size_t il = sizeof first;
    sysctlbyname("net.inet.ip.portrange.first", &first, &il, NULL, 0);
    il = sizeof last;
    sysctlbyname("net.inet.ip.portrange.last", &last, &il, NULL, 0);
    printf("# bind-uids: %s %s %s (macOS %s)\tuid=%u euid=%u\tportrange=%d-%d\n", u.sysname, u.release, u.machine, product, (unsigned)getuid(), (unsigned)geteuid(),
           first, last);
    fflush(stdout);

    const uid_t me = geteuid();
    // (holder, binder) pairs. As an ordinary user only the first can run.
    const uid_t pairs[][2] = {{501, 501}, {502, 501}, {501, 504}, {0, 501}, {501, 0}, {0, 0}};
    const char *addrs[] = {"0.0.0.0", "127.0.0.1"};
    const int types[] = {SOCK_STREAM, SOCK_DGRAM};
    for (int t = 0; t < 2; t++)
        for (size_t pi = 0; pi < sizeof pairs / sizeof pairs[0]; pi++)
            for (int ha = 0; ha < 2; ha++)
                for (int ba = 0; ba < 2; ba++)
                    for (int listening = 0; listening < (types[t] == SOCK_STREAM ? 2 : 1); listening++) {
                        if (listening && ha == 0) continue;
                        for (int ho = 0; ho < 4; ho++)
                            for (int bo = 0; bo < 4; bo++) {
                                uid_t hu = pairs[pi][0], bu = pairs[pi][1];
                                char lead[256];
                                snprintf(lead, sizeof lead, "BIND\tproto=%s\tholder=%s\thaddr=%s\thopts=%s\thstate=%s\tbinder=%s\tbaddr=%s\tbopts=%s",
                                         types[t] == SOCK_STREAM ? "tcp" : "udp", uid_name(hu), addrs[ha], opts_name(ho), types[t] == SOCK_DGRAM ? "bound"
                                         : listening                                                                         ? "listen"
                                                                                                                              : "idle",
                                         uid_name(bu), addrs[ba], opts_name(bo));
                                if (me != 0 && (hu != me || bu != me)) {
                                    printf("%s\t-> SKIP(needs root)\n", lead);
                                    continue;
                                }
                                holder h = hold(hu, 0, types[t], addrs[ha], ho, listening);
                                if (h.err != 0) {
                                    printf("%s\t-> SKIP(holder: %s)\n", lead, result_text(h.err));
                                    release(&h);
                                    if (failed(h.err)) failures++;
                                    continue;
                                }
                                int e = bind_as(bu, 0, types[t], addrs[ba], h.port, bo);
                                int r = release(&h);
                                int c = bind_as(bu, 0, types[t], addrs[ba], h.port, bo);
                                if (r != 0) printf("CHILD-FAILED\tthe holder of the next row did not exit 0\n");
                                if (failed(e) || failed(c) || r != 0) failures++;
                                printf("%s\t-> %s\tcontrol=%s\tport=%d\n", lead, result_text(e), result_text(c), h.port);
                                fflush(stdout);
                            }
                    }

    // CRED: whose uid counts.
    struct {
        const char *hname;
        uid_t hu;
        int hfirst;
        const char *bname;
        uid_t bu;
        int bfirst;
    } creds[] = {
        {"u502", 502, 0, "socket as root, then setuid(501)", 501, 1},
        {"socket as root, then setuid(502)", 502, 1, "u501", 501, 0},
        {"u502", 502, 0, "u501", 501, 0},
    };
    for (int t = 0; t < 2; t++)
        for (size_t i = 0; i < sizeof creds / sizeof creds[0]; i++)
            for (int ha = 0; ha < 2; ha++)
                for (int ba = 0; ba < 2; ba++) {
                    if (ha == 0 && ba == 0) continue;
                    char lead[256];
                    snprintf(lead, sizeof lead, "CRED\tproto=%s\tholder=%s\thaddr=%s\tbinder=%s\tbaddr=%s\t(both SO_REUSEADDR)", types[t] == SOCK_STREAM ? "tcp" : "udp",
                             creds[i].hname, addrs[ha], creds[i].bname, addrs[ba]);
                    if (me != 0) {
                        printf("%s\t-> SKIP(needs root)\n", lead);
                        continue;
                    }
                    holder h = hold(creds[i].hu, creds[i].hfirst, types[t], addrs[ha], 1, 0);
                    if (h.err != 0) {
                        printf("%s\t-> SKIP(holder: %s)\n", lead, result_text(h.err));
                        release(&h);
                        if (failed(h.err)) failures++;
                        continue;
                    }
                    int e = bind_as(creds[i].bu, creds[i].bfirst, types[t], addrs[ba], h.port, 1);
                    int r = release(&h);
                    int c = bind_as(creds[i].bu, creds[i].bfirst, types[t], addrs[ba], h.port, 1);
                    if (r != 0) printf("CHILD-FAILED\tthe holder of the next row did not exit 0\n");
                    if (failed(e) || failed(c) || r != 0) failures++;
                    printf("%s\t-> %s\tcontrol=%s\tport=%d\n", lead, result_text(e), result_text(c), h.port);
                    fflush(stdout);
                }
    if (failures) printf("FAILURES\t%d rows had a child fail: see SKIP(probe failure), SKIP(become ...) and CHILD-FAILED\n", failures);
    printf("DONE\n");
    return failures ? 1 : 0;
}
