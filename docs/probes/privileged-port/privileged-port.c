// Which addresses an unprivileged bind(2) to a port below 1024 is refused for.
//
// Build and run, as a user that is not root:
//   Darwin: cc -Wall -o /tmp/pp privileged-port.c && /tmp/pp
//   Linux:  gcc -Wall -o /tmp/pp privileged-port.c && /tmp/pp
//
// Every row makes a fresh socket, binds it once, prints the answer and closes
// it. The rows cover:
//   socket   v4 (AF_INET), v6 (AF_INET6 with IPV6_V6ONLY off, so dual-mode),
//            v6only (AF_INET6 with IPV6_V6ONLY on)
//   kind     stream (SOCK_STREAM), dgram (SOCK_DGRAM)
//   address  the wildcard and loopback of the socket's family, and for an
//            AF_INET6 socket also the v4-mapped wildcard and loopback
//   port     1, 80, 1023, and 1024 as the control that is not privileged
//
// The header prints the caller's uids, so that a row cannot silently come from
// root, and the kernel's own setting for where the privileged range ends:
// Linux's net.ipv4.ip_unprivileged_port_start (which a container runtime may
// set to 0 in its network namespace) and Darwin's
// net.inet.ip.portrange.reservedlow and reservedhigh.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

static const char *err_name(int e)
{
    switch (e) {
    case 0: return "OK";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EADDRINUSE: return "EADDRINUSE";
    case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
    case EINVAL: return "EINVAL";
    case EAFNOSUPPORT: return "EAFNOSUPPORT";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static int bind_v4(int kind, const char *addr, int port)
{
    int fd = socket(AF_INET, kind, 0);
    if (fd < 0) return errno;
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin_len = sizeof s;
#endif
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &s.sin_addr) != 1) { fprintf(stderr, "bad address %s\n", addr); exit(2); }
    int r = bind(fd, (struct sockaddr *)&s, sizeof s);
    int e = r == 0 ? 0 : errno;
    close(fd);
    return e;
}

static int bind_v6(int kind, int v6only, const char *addr, int port)
{
    int fd = socket(AF_INET6, kind, 0);
    if (fd < 0) return errno;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only) != 0) {
        fprintf(stderr, "IPV6_V6ONLY=%d: %s\n", v6only, err_name(errno));
        exit(2);
    }
    int got = -1;
    socklen_t gotlen = sizeof got;
    getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &got, &gotlen);
    if (got != v6only) { fprintf(stderr, "IPV6_V6ONLY reads %d, set %d\n", got, v6only); exit(2); }
    struct sockaddr_in6 s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin6_len = sizeof s;
#endif
    s.sin6_family = AF_INET6;
    s.sin6_port = htons(port);
    if (inet_pton(AF_INET6, addr, &s.sin6_addr) != 1) { fprintf(stderr, "bad address %s\n", addr); exit(2); }
    int r = bind(fd, (struct sockaddr *)&s, sizeof s);
    int e = r == 0 ? 0 : errno;
    close(fd);
    return e;
}

static void print_setting(void)
{
#ifdef __APPLE__
    const char *names[] = { "net.inet.ip.portrange.reservedlow", "net.inet.ip.portrange.reservedhigh" };
    for (int i = 0; i < 2; i++) {
        int v = 0;
        size_t len = sizeof v;
        if (sysctlbyname(names[i], &v, &len, NULL, 0) == 0)
            printf("%s = %d\n", names[i], v);
        else
            printf("%s: %s\n", names[i], err_name(errno));
    }
#else
    FILE *f = fopen("/proc/sys/net/ipv4/ip_unprivileged_port_start", "r");
    int v = -1;
    if (f && fscanf(f, "%d", &v) == 1)
        printf("net.ipv4.ip_unprivileged_port_start = %d\n", v);
    else
        printf("net.ipv4.ip_unprivileged_port_start: unreadable\n");
    if (f) fclose(f);
#endif
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
#ifdef __APPLE__
    printf("uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
#else
    uid_t r, e, s;
    getresuid(&r, &e, &s);
    printf("uid=%d euid=%d suid=%d\n", (int)r, (int)e, (int)s);
#endif
    print_setting();

    const int ports[] = { 1, 80, 1023, 1024 };
    const int kinds[] = { SOCK_STREAM, SOCK_DGRAM };
    const char *kind_names[] = { "stream", "dgram" };
    const char *v4_addrs[] = { "0.0.0.0", "127.0.0.1" };
    const char *v6_addrs[] = { "::", "::1", "::ffff:0.0.0.0", "::ffff:127.0.0.1" };

    for (int k = 0; k < 2; k++) {
        for (int a = 0; a < 2; a++) {
            printf("v4 %s %s", kind_names[k], v4_addrs[a]);
            for (int p = 0; p < 4; p++)
                printf(" %d=%s", ports[p], err_name(bind_v4(kinds[k], v4_addrs[a], ports[p])));
            printf("\n");
        }
        for (int only = 0; only < 2; only++) {
            for (int a = 0; a < 4; a++) {
                printf("%s %s %s", only ? "v6only" : "v6", kind_names[k], v6_addrs[a]);
                for (int p = 0; p < 4; p++)
                    printf(" %d=%s", ports[p], err_name(bind_v6(kinds[k], only, v6_addrs[a], ports[p])));
                printf("\n");
            }
        }
    }
    return 0;
}
