// Which uid a TCP socket carries for the kernel's own checks: the one its
// creator had when socket(2) made it, and what an accepted socket carries.
//
// Darwin's bind(2) refuses a binder that is not root near a socket of another
// uid (docs/probes/darwin-root/bind-uids.c); that uid is the socket's
// credential (XNU's so_cred), fixed when socket(2) made it. Linux keeps
// sk_uid and reports it in /proc/net/tcp.
//
// Run as root; each row forks its own processes, and nothing outlives the row.
//   Darwin: cc -Wall -Werror -O1 -o /tmp/socket-creator-uid socket-creator-uid.c && sudo /tmp/socket-creator-uid
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -Werror -O1 -o /tmp/p /probe/socket-creator-uid.c && /tmp/p'
// It exits 1 if any step failed, so that its output is not taken for a
// complete measurement.
//
// ACCEPT rows. A listener process makes a socket with effective uid
// `listener`, binds it at 127.0.0.1 and port 0 and listens, then changes its
// effective uid to `acceptor` (through root) and accepts one connection from a
// client of a third uid. Then:
//   Darwin: the listener closes its listening socket, so that the accepted
//   socket is the only one holding the port, and a fresh process of each uid
//   in turn makes a socket with SO_REUSEADDR and binds 0.0.0.0 at that port.
//   bind-uids.c measured that a binder of the holder's own uid succeeds there
//   and a binder of another uid that is not root gets EADDRINUSE, so the
//   answers say whose uid the accepted socket carries. The control binds the
//   same once every socket of the row is closed.
//     ACCEPT listener= acceptor= client= binder=<uid> -> <errno>
//     ACCEPT ... control binder=<uid> -> <errno>
//   Linux: the uid /proc/net/tcp reports for the listening socket and for the
//   accepted one, before the listener closes.
//     ACCEPT listener= acceptor= client= proc-uid listening= accepted=
//
// CREATE rows (Linux): a socket made with effective uid `made`, after which
// the process changes its effective uid to `later` before it binds and
// listens; the uid /proc/net/tcp reports for it.
//     CREATE made= later= proc-uid=

#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
static const uid_t U1 = 502, U2 = 504, U3 = 501;
#else
static const uid_t U1 = 1000, U2 = 1001, U3 = 1002;
#endif

static int failures;

#ifdef __APPLE__
static const char *en(int e) {
    static char b[32];
    switch (e) {
    case 0: return "ok";
    case EADDRINUSE: return "EADDRINUSE";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}
#endif

static const char *uid_name(uid_t u) {
    static char b[4][16];
    static int k;
    k = (k + 1) % 4;
    if (u == 0) snprintf(b[k], sizeof b[k], "root");
    else snprintf(b[k], sizeof b[k], "u%u", (unsigned)u);
    return b[k];
}

static struct sockaddr_in at(const char *addr, int port) {
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin_len = sizeof s;
#endif
    s.sin_family = AF_INET;
    s.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, addr, &s.sin_addr);
    return s;
}

// Become `uid` for good, in group 20 alone (root keeps 0).
static int become(uid_t uid) {
    if (uid == 0) return 0;
    gid_t g = 20;
    if (setgroups(1, &g) != 0) return errno;
    if (setgid(20) != 0) return errno;
    if (setuid(uid) != 0) return errno;
    return 0;
}

// Take effective uid `uid`, from whatever effective uid, keeping real uid 0.
static int effective(uid_t uid) {
    if (geteuid() != 0 && seteuid(0) != 0) return errno;
    if (uid != 0 && seteuid(uid) != 0) return errno;
    return 0;
}

static void die(const char *what) {
    perror(what);
    exit(2);
}

static int read_int(int fd, int *v) { return read(fd, v, sizeof *v) == (ssize_t)sizeof *v ? 0 : -1; }

static int write_int(int fd, int v) { return write(fd, &v, sizeof v) == (ssize_t)sizeof v ? 0 : -1; }

#ifdef __APPLE__
// What a fresh process of `uid` answers binding 0.0.0.0:port with
// SO_REUSEADDR; -1 if the process failed.
static int bind_as(uid_t uid, int port) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        close(pfd[0]);
        int err = become(uid);
        if (err == 0) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            int one = 1;
            struct sockaddr_in sa = at("0.0.0.0", port);
            if (s < 0) err = errno;
            else if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) err = errno;
            else err = bind(s, (struct sockaddr *)&sa, sizeof sa) == 0 ? 0 : errno;
        } else {
            err = -100 - err;
        }
        if (write_int(pfd[1], err) != 0) _exit(1);
        _exit(0);
    }
    close(pfd[1]);
    int err = -1;
    if (read_int(pfd[0], &err) != 0) err = -1;
    close(pfd[0]);
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) err = -1;
    if (err < 0) failures++;
    return err;
}
#endif

#ifndef __APPLE__
// The uid /proc/net/tcp reports for the IPv4 socket at local port `port` in
// state `state` (0x0A listening, 0x01 established), or -1.
static long proc_uid(int port, int state) {
    FILE *f = fopen("/proc/net/tcp", "r");
    if (!f) return -1;
    char line[512];
    long found = -1;
    if (!fgets(line, sizeof line, f)) {
        fclose(f);
        return -1;
    }
    while (fgets(line, sizeof line, f)) {
        unsigned laddr, lport, raddr, rport, st;
        long uid;
        char rest[64];
        // sl local rem st tx:rx tr:when retrnsmt uid
        if (sscanf(line, " %*d: %8X:%4X %8X:%4X %2X %63s %63s %*s %ld", &laddr, &lport, &raddr, &rport, &st, rest,
                   rest, &uid) == 8 &&
            (int)lport == port && (int)st == state)
            found = uid;
    }
    fclose(f);
    return found;
}
#endif

// One ACCEPT row.
static void accept_row(uid_t listener_uid, uid_t acceptor_uid, uid_t client_uid) {
    int to_parent[2], from_parent[2];
    if (pipe(to_parent) != 0 || pipe(from_parent) != 0) die("pipe");
    fflush(stdout);
    pid_t lpid = fork();
    if (lpid < 0) die("fork");
    if (lpid == 0) {
        alarm(30);
        close(to_parent[0]);
        close(from_parent[1]);
        int port = -1, s = -1, c = -1;
        struct sockaddr_in sa = at("127.0.0.1", 0);
        socklen_t len = sizeof sa;
        if (effective(listener_uid) != 0) _exit(3);
        if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) _exit(4);
        if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0) _exit(5);
        if (listen(s, 1) != 0) _exit(6);
        if (getsockname(s, (struct sockaddr *)&sa, &len) != 0) _exit(7);
        port = ntohs(sa.sin_port);
        if (effective(acceptor_uid) != 0) _exit(8);
        if (write_int(to_parent[1], port) != 0) _exit(9);
        if ((c = accept(s, NULL, NULL)) < 0) _exit(10);
        if (write_int(to_parent[1], 1) != 0) _exit(11);
        int cmd;
        // 1: close the listening socket; 0: exit.
        while (read_int(from_parent[0], &cmd) == 0 && cmd != 0) {
            if (cmd == 1) {
                close(s);
                if (write_int(to_parent[1], 1) != 0) _exit(12);
            }
        }
        _exit(0);
    }
    close(to_parent[1]);
    close(from_parent[0]);
    int port = -1, ack = 0;
    if (read_int(to_parent[0], &port) != 0) die("listener's port");

    // The client, of a third uid, connects and holds its end until told.
    int go[2];
    if (pipe(go) != 0) die("pipe");
    fflush(stdout);
    pid_t cpid = fork();
    if (cpid < 0) die("fork");
    if (cpid == 0) {
        alarm(30);
        close(go[1]);
        if (become(client_uid) != 0) _exit(3);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = at("127.0.0.1", port);
        if (s < 0 || connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) _exit(4);
        char ch;
        while (read(go[0], &ch, 1) > 0) {
        }
        _exit(0);
    }
    close(go[0]);
    if (read_int(to_parent[0], &ack) != 0) die("accept");

#ifdef __APPLE__
    if (write_int(from_parent[1], 1) != 0 || read_int(to_parent[0], &ack) != 0) die("closing the listener");
    uid_t binders[] = {listener_uid, acceptor_uid, client_uid, 0};
    for (size_t i = 0; i < sizeof binders / sizeof binders[0]; i++) {
        int err = bind_as(binders[i], port);
        printf("ACCEPT\tlistener=%s\tacceptor=%s\tclient=%s\tbinder=%s\tbaddr=0.0.0.0\t(SO_REUSEADDR)\t-> %s\tport=%d\n",
               uid_name(listener_uid), uid_name(acceptor_uid), uid_name(client_uid), uid_name(binders[i]),
               err < 0 ? "FAILED" : en(err), port);
    }
#else
    long listening = proc_uid(port, 0x0A), accepted = proc_uid(port, 0x01);
    if (listening < 0 || accepted < 0) failures++;
    printf("ACCEPT\tlistener=%s\tacceptor=%s\tclient=%s\tproc-uid\tlistening=%ld\taccepted=%ld\n", uid_name(listener_uid),
           uid_name(acceptor_uid), uid_name(client_uid), listening, accepted);
#endif

    if (write_int(from_parent[1], 0) != 0) die("ending the listener");
    close(go[1]);
    int st = 0;
    if (waitpid(lpid, &st, 0) != lpid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("ACCEPT\tthe listener process failed (status %d)\n", st);
        failures++;
    }
    if (waitpid(cpid, &st, 0) != cpid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        printf("ACCEPT\tthe client process failed (status %d)\n", st);
        failures++;
    }
    close(to_parent[0]);
    close(from_parent[1]);

#ifdef __APPLE__
    // Every socket of the row is closed: nothing should be in the way now
    // but a closed end, which SO_REUSEADDR passes.
    int err = bind_as(client_uid, port);
    printf("ACCEPT\tlistener=%s\tacceptor=%s\tclient=%s\tcontrol\tbinder=%s\tbaddr=0.0.0.0\t(SO_REUSEADDR)\t-> %s\tport=%d\n",
           uid_name(listener_uid), uid_name(acceptor_uid), uid_name(client_uid), uid_name(client_uid),
           err < 0 ? "FAILED" : en(err), port);
#endif
}

#ifndef __APPLE__
// One CREATE row.
static void create_row(uid_t made, uid_t later) {
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        alarm(10);
        close(pfd[0]);
        struct sockaddr_in sa = at("127.0.0.1", 0);
        socklen_t len = sizeof sa;
        if (effective(made) != 0) _exit(3);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) _exit(4);
        if (effective(later) != 0) _exit(5);
        if (bind(s, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(s, 1) != 0) _exit(6);
        if (getsockname(s, (struct sockaddr *)&sa, &len) != 0) _exit(7);
        long uid = proc_uid(ntohs(sa.sin_port), 0x0A);
        if (write(pfd[1], &uid, sizeof uid) != (ssize_t)sizeof uid) _exit(8);
        _exit(0);
    }
    close(pfd[1]);
    long uid = -1;
    if (read(pfd[0], &uid, sizeof uid) != (ssize_t)sizeof uid) uid = -1;
    close(pfd[0]);
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0 || uid < 0) failures++;
    printf("CREATE\tmade=%s\tlater=%s\tproc-uid=%ld\n", uid_name(made), uid_name(later), uid);
}
#endif

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    if (geteuid() != 0) {
        fprintf(stderr, "socket-creator-uid: run as root\n");
        return 2;
    }
#ifdef __APPLE__
    printf("# socket-creator-uid: Darwin\n");
#else
    printf("# socket-creator-uid: Linux\n");
#endif
    accept_row(U1, U2, U3);
    accept_row(0, U2, U3);
    accept_row(U1, 0, U3);
#ifndef __APPLE__
    create_row(U1, U2);
    create_row(U1, 0);
    create_row(0, U1);
#endif
    printf("DONE\tfailures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
