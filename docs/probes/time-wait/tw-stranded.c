// What a TCP connection leaves holding its ports once both sockets have
// closed, where the client's FIN was still queued behind bytes the server
// never read: whether either end is left in TIME_WAIT.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/tws tw-stranded.c && /tmp/tws
//   Linux:  gcc -Wall -o /tmp/tws tw-stranded.c && /tmp/tws
//
// Each row connects a client to a listener Z of the row's own, accepts, and
// closes Z, so only the connection holds Z's port. Then:
//
//   S  the client, non-blocking, writes until EAGAIN, filling the server's
//      receive buffer and its own send buffer; the client shuts its send
//      side (its FIN queued behind what is unsent), the server shuts its
//      own (its FIN reaches the client), and the server closes without
//      reading; then the client closes.
//   C  the control: as S, but the client writes nothing, so its FIN
//      arrives at once and it ends in TIME_WAIT.
//
// Each row prints the client's SO_ERROR once the server has closed, and then
// whether a fresh socket without SO_REUSEADDR binds the client's port T and
// Z's port, at once and after 1 and 5 seconds.
//
// Measured 2026-10-14 on Linux 6.18.5 aarch64 (Apple's container VM, the
// gcc:14 image) and Darwin 27.0.0 arm64 (uid 501). Linux resets the client at
// the server's close (the server closed over bytes it never read before the
// FINs were exchanged), and then holds neither port. Darwin does not reset
// the client, and once the client closes too, holds neither port either: in
// 13 of 14 rows S over three runs both ports bound at once and stayed free.
// In the other, T alone stayed held for 5 s, and that run had no netstat
// check to say what held it; this machine was running other test suites,
// whose sockets take ephemeral ports. Row C on Linux leaves the client in
// TIME_WAIT at T. Row C on Darwin held both ports: Darwin's loopback
// delivered the client's FIN after the server had shut its own side, so the
// two FINs crossed and both ends went to TIME_WAIT.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static struct sockaddr_in at(int port)
{
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin_len = sizeof s;
#endif
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &s.sin_addr);
    return s;
}

static const char *err_name(int e)
{
    switch (e) {
    case 0: return "OK";
    case EADDRINUSE: return "EADDRINUSE";
    case ECONNRESET: return "ECONNRESET";
    case EPIPE: return "EPIPE";
    default: return "other";
    }
}

static int bind_free(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in s = at(port);
    int e = bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
    close(fd);
    return e;
}

static void pause_for(double seconds)
{
    struct timespec t = { (time_t)seconds, (long)((seconds - (time_t)seconds) * 1e9) };
    nanosleep(&t, NULL);
}

static void row(const char *name, int z, int fill)
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in zs = at(z);
    if (bind(l, (struct sockaddr *)&zs, sizeof zs) != 0 || listen(l, 8) != 0) {
        printf("%s listener: %s\n", name, strerror(errno));
        exit(1);
    }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&zs, sizeof zs) != 0) {
        printf("%s connect: %s\n", name, strerror(errno));
        exit(1);
    }
    struct sockaddr_in me;
    socklen_t ml = sizeof me;
    getsockname(c, (struct sockaddr *)&me, &ml);
    int t = ntohs(me.sin_port);
    int s = accept(l, NULL, NULL);
    close(l);

    long written = 0;
    if (fill) {
        fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
        char buf[4096];
        memset(buf, 'x', sizeof buf);
        for (;;) {
            ssize_t n = write(c, buf, sizeof buf);
            if (n < 0) break;
            written += n;
        }
        // Let loopback move what it will.
        pause_for(0.2);
        for (;;) {
            ssize_t n = write(c, buf, sizeof buf);
            if (n < 0) break;
            written += n;
        }
    }
    shutdown(c, SHUT_WR);
    shutdown(s, SHUT_WR);
    pause_for(0.2);
    close(s);
    pause_for(0.2);
    int so_error = 0;
    socklen_t el = sizeof so_error;
    getsockopt(c, SOL_SOCKET, SO_ERROR, &so_error, &el);
    close(c);
    int bt = bind_free(t), bz = bind_free(z);
    printf("%s wrote %s; client SO_ERROR after the server's close -> %s; then bind T -> %s, Z -> %s", name,
           fill ? "until EAGAIN" : "nothing", err_name(so_error), err_name(bt), err_name(bz));
    if (fill && (bt != 0 || bz != 0)) {
        // Who holds the port: this connection's ends, or another process.
        char cmd[128];
        snprintf(cmd, sizeof cmd, "netstat -an | grep -E '[.:](%d|%d) ' 1>&2", t, z);
        fflush(stdout);
        if (system(cmd) != 0) fprintf(stderr, "(netstat lists nothing at those ports)\n");
    }
    pause_for(1.0);
    printf("; after 1 s T -> %s, Z -> %s", err_name(bind_free(t)), err_name(bind_free(z)));
    pause_for(4.0);
    printf("; after 5 s T -> %s, Z -> %s\n", err_name(bind_free(t)), err_name(bind_free(z)));
    (void)written;
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    row("C", 45701, 0);
    for (int i = 0; i < 6; i++) row("S", 45702 + i, 1);
    return 0;
}
