// What a TCP socket whose connect(2) was refused still holds of its port, for
// each way it came by the port, and what its next bind(2), listen(2) or
// connect(2) makes of what it holds.
//
// Build and run:
//   Darwin: cc -Wall -o /tmp/rcp refused-connect-port.c && /tmp/rcp
//   Linux:  gcc -Wall -o /tmp/rcp refused-connect-port.c && /tmp/rcp
//
// Every row makes a fresh socket, gives it its port one way, connects it to
// 127.0.0.1:1, where nothing is bound (so both kernels answer the SYN with a
// reset), and then does one thing with it.
//
// How the socket came by its port:
//   I  connect's own implicit bind (the socket was unbound)
//   Z  bind(2) 127.0.0.1:0          W  bind(2) 0.0.0.0:0
//   X  bind(2) 127.0.0.1:<port>     Y  bind(2) 0.0.0.0:<port>
// How the refusal arrived:
//   b  a blocking connect, which answers it
//   n  a non-blocking connect, then poll(2) until the socket reports it; the
//      refusal is still pending
//   s  as n, then an SO_ERROR read takes it
// What the row then does:
//   1  bind 127.0.0.1:<p> from a fresh socket, close that, then bind
//      0.0.0.0:<p> from another, <p> being the port getsockname reports for
//      the refused socket; a third fresh socket, carrying SO_REUSEADDR, binds
//      127.0.0.1:<p>
//   2  bind(2) the refused socket to 127.0.0.1:0
//   3  listen(2) on the refused socket
//   4  connect the refused socket to a listener, twice (on Linux a pending
//      refusal is answered by the first)
//   5  connect the refused socket to 127.0.0.1:1 again
//
// Each row prints getsockname before and after its action.
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

static int port_of(int fd)
{
    struct sockaddr_in s;
    socklen_t l = sizeof s;
    if (getsockname(fd, (struct sockaddr *)&s, &l) < 0) return -1;
    return ntohs(s.sin_port);
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

static int so_error(int fd)
{
    int e = -1;
    socklen_t l = sizeof e;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &l) < 0) return -errno;
    return e;
}

static int fresh_bind(const char *addr, int port, int reuse)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (reuse) {
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    int e = bind_at(fd, addr, port);
    close(fd);
    return e;
}

// A socket whose connect to 127.0.0.1:1 has been refused, its port given by
// `provenance` and the refusal delivered by `path`; prints how it got there.
static int refused(char provenance, char path, int explicit_port, char *line, size_t len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int eb = 0;
    switch (provenance) {
    case 'Z': eb = bind_at(fd, "127.0.0.1", 0); break;
    case 'W': eb = bind_at(fd, "0.0.0.0", 0); break;
    case 'X': eb = bind_at(fd, "127.0.0.1", explicit_port); break;
    case 'Y': eb = bind_at(fd, "0.0.0.0", explicit_port); break;
    default: break;
    }
    if (path != 'b') fcntl(fd, F_SETFL, O_NONBLOCK);
    int ec = connect_to(fd, "127.0.0.1", 1);
    int n = 0, revents = 0, taken = -1;
    if (path != 'b') {
        struct pollfd p = { fd, POLLOUT, 0 };
        n = poll(&p, 1, 2000);
        revents = p.revents;
        if (path == 's') taken = so_error(fd);
    }
    char name[64];
    name_of(fd, name, sizeof name);
    int used = snprintf(line, len, "bind=%s connect=%s", err_name(eb), err_name(ec));
    if (path != 'b') used += snprintf(line + used, len - used, " poll=%d/0x%x", n, revents);
    if (path == 's') used += snprintf(line + used, len - used, " SO_ERROR=%s", err_name(taken));
    snprintf(line + used, len - used, " getsockname=%s", name);
    return fd;
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);

    int listener_port = 45200;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int el = bind_at(l, "127.0.0.1", listener_port);
    if (el == 0) el = listen(l, 128) < 0 ? errno : 0;
    printf("listener at 127.0.0.1:%d -> %s\n", listener_port, err_name(el));

    const char provenances[] = "IZWXY";
    const char paths[] = "bns";
    int explicit_port = 47100;
    for (const char *pv = provenances; *pv; pv++) {
        for (const char *pa = paths; *pa; pa++) {
            for (int action = 1; action <= 5; action++) {
                char line[256], after[64];
                explicit_port++;
                int fd = refused(*pv, *pa, explicit_port, line, sizeof line);
                int p = port_of(fd);
                printf("%c%c%d %s |", *pv, *pa, action, line);
                switch (action) {
                case 1:
                    printf(" fresh bind 127.0.0.1:%d=%s, 0.0.0.0:%d=%s, reuse 127.0.0.1:%d=%s", p,
                           err_name(fresh_bind("127.0.0.1", p, 0)), p, err_name(fresh_bind("0.0.0.0", p, 0)), p,
                           err_name(fresh_bind("127.0.0.1", p, 1)));
                    break;
                case 2:
                    printf(" bind 127.0.0.1:0=%s", err_name(bind_at(fd, "127.0.0.1", 0)));
                    break;
                case 3:
                    printf(" listen=%s", err_name(listen(fd, 8) < 0 ? errno : 0));
                    break;
                case 4: {
                    int e1 = connect_to(fd, "127.0.0.1", listener_port);
                    char mid[64];
                    name_of(fd, mid, sizeof mid);
                    int e2 = connect_to(fd, "127.0.0.1", listener_port);
                    printf(" connect listener=%s (getsockname=%s), again=%s", err_name(e1), mid, err_name(e2));
                    break;
                }
                case 5:
                    printf(" connect 127.0.0.1:1 again=%s", err_name(connect_to(fd, "127.0.0.1", 1)));
                    break;
                }
                name_of(fd, after, sizeof after);
                printf(" | getsockname=%s\n", after);
                close(fd);
            }
        }
    }
    close(l);
    return 0;
}
