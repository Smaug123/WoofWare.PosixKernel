// Which ports an unprivileged process may bind under each value of Linux's
// net.ipv4.ip_unprivileged_port_start, and which values the sysctl takes
// against the local port range.
//
// Build and run, as root in a network namespace of its own, with /proc/sys
// writable:
//   container run --rm --cap-add ALL -v "$PWD":/probe gcc:14 sh -c 'mount -o remount,rw /proc/sys && gcc -Wall -O1 -o /tmp/ups /probe/unprivileged-port-start.c && /tmp/ups'
//
// Section S: with ip_local_port_range set as the row says, one write(2) of
//   the value to ip_unprivileged_port_start, its errno, and what both files
//   read back.
// Section B: with ip_unprivileged_port_start set to S (the range at its
//   default, 32768-60999), a child that drops to uid 1000 binds each port P
//   from a fresh socket of each kind, closing it again:
//     v4 stream / v4 dgram at 0.0.0.0 and 127.0.0.1, and a dual-mode v6
//     stream socket at ::ffff:127.0.0.1
//   and prints each answer.
//
// Darwin has no such sysctl: `sysctl net.inet.ip.portrange` lists first,
// last, hifirst, hilast, lowfirst and lowlast, and reservedlow and
// reservedhigh answer ENOENT (docs/probes/privileged-port), so it is measured
// on Linux alone.
//
// Measured 2026-10-18 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14,
// root, the children at uid 1000). In short:
//   ip_unprivileged_port_start takes 0 through the range's low end, up to
//   65535 when the range is there, and no further. An unprivileged bind of a
//   port below it is EACCES and of one at or above it succeeds, at the
//   wildcard and at loopback, stream and datagram, IPv4 and v4-mapped alike;
//   at 0 and 1 every port binds. (What bind(2) of port 0 and connect's
//   implicit bind hand out with it lowered is section B of
//   docs/probes/local-port-range.)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
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

static const char *RANGE = "/proc/sys/net/ipv4/ip_local_port_range";
static const char *UNPRIV = "/proc/sys/net/ipv4/ip_unprivileged_port_start";
static char default_range[64], default_unpriv[64];

static const char *err_name(int e)
{
    switch (e) {
    case 0: return "OK";
    case EINVAL: return "EINVAL";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case EADDRINUSE: return "EADDRINUSE";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static void read_file(const char *path, char *out, size_t len)
{
    FILE *f = fopen(path, "r");
    if (!f || !fgets(out, (int)len, f)) {
        snprintf(out, len, "(unreadable: %s)", strerror(errno));
        if (f) fclose(f);
        return;
    }
    fclose(f);
    out[strcspn(out, "\n")] = 0;
    for (char *c = out; *c; c++)
        if (*c == '\t') *c = ' ';
}

static int write_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return errno;
    ssize_t n = write(fd, text, strlen(text));
    int e = n < 0 ? errno : 0;
    close(fd);
    return e;
}

static void restore(void)
{
    write_file(UNPRIV, "0");
    write_file(RANGE, default_range);
    write_file(UNPRIV, default_unpriv);
    char r[64], u[64];
    read_file(RANGE, r, sizeof r);
    read_file(UNPRIV, u, sizeof u);
    if (strcmp(r, default_range) || strcmp(u, default_unpriv)) {
        printf("could not restore the defaults: range %s, unprivileged start %s\n", r, u);
        exit(1);
    }
}

static void sysctl_row(const char *range, const char *value)
{
    restore();
    int er = write_file(RANGE, range);
    int eu = write_file(UNPRIV, value);
    char r[64], u[64];
    read_file(RANGE, r, sizeof r);
    read_file(UNPRIV, u, sizeof u);
    printf("S range \"%s\" -> %s, unprivileged_start \"%s\" -> %s | range=%s unprivileged_start=%s\n", range,
           err_name(er), value, err_name(eu), r, u);
}

static int bind_one(int family, int type, const char *addr, int port)
{
    int fd = socket(family, type, 0);
    int e;
    if (family == AF_INET6) {
        int zero = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        struct sockaddr_in6 s;
        memset(&s, 0, sizeof s);
        s.sin6_family = AF_INET6;
        s.sin6_port = htons(port);
        inet_pton(AF_INET6, addr, &s.sin6_addr);
        e = bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
    } else {
        struct sockaddr_in s;
        memset(&s, 0, sizeof s);
        s.sin_family = AF_INET;
        s.sin_port = htons(port);
        inet_pton(AF_INET, addr, &s.sin_addr);
        e = bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
    }
    close(fd);
    return e;
}

static void bind_rows(const char *start)
{
    restore();
    int e = write_file(UNPRIV, start);
    char u[64];
    read_file(UNPRIV, u, sizeof u);
    printf("B unprivileged_start \"%s\" -> %s, reads %s\n", start, err_name(e), u);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (setgroups(0, NULL) < 0 || setresgid(1000, 1000, 1000) < 0 || setresuid(1000, 1000, 1000) < 0) {
            printf("drop: %s\n", strerror(errno));
            _exit(1);
        }
        const int ports[] = { 1, 79, 80, 81, 499, 500, 1022, 1023, 1024, 1025, 1999, 2000, 32767, 32768 };
        struct {
            const char *name;
            int family, type;
            const char *addr;
        } kinds[] = {
            { "v4 stream 0.0.0.0", AF_INET, SOCK_STREAM, "0.0.0.0" },
            { "v4 stream 127.0.0.1", AF_INET, SOCK_STREAM, "127.0.0.1" },
            { "v4 dgram 0.0.0.0", AF_INET, SOCK_DGRAM, "0.0.0.0" },
            { "v4 dgram 127.0.0.1", AF_INET, SOCK_DGRAM, "127.0.0.1" },
            { "v6 stream ::ffff:127.0.0.1", AF_INET6, SOCK_STREAM, "::ffff:127.0.0.1" },
        };
        for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
            printf("  S=%s uid=%d %s", start, (int)geteuid(), kinds[k].name);
            for (size_t i = 0; i < sizeof ports / sizeof ports[0]; i++)
                printf(" %d=%s", ports[i], err_name(bind_one(kinds[k].family, kinds[k].type, kinds[k].addr, ports[i])));
            printf("\n");
        }
        fflush(stdout);
        _exit(0);
    }
    waitpid(c, NULL, 0);
}

int main(void)
{
    struct utsname un;
    uname(&un);
    printf("%s %s %s\n", un.sysname, un.release, un.machine);
    printf("uid=%d\n", (int)geteuid());
    read_file(RANGE, default_range, sizeof default_range);
    read_file(UNPRIV, default_unpriv, sizeof default_unpriv);
    printf("defaults: range=%s unprivileged_start=%s\n", default_range, default_unpriv);

    sysctl_row("32768 60999", "0");
    sysctl_row("32768 60999", "32768");
    sysctl_row("32768 60999", "32769");
    sysctl_row("40000 40000", "40000");
    sysctl_row("40000 40000", "40001");
    sysctl_row("65535 65535", "65535");
    sysctl_row("65535 65535", "65536");
    sysctl_row("65535 65535", "-1");

    const char *starts[] = { "0", "1", "80", "500", "1023", "1024", "2000", "32768" };
    for (size_t i = 0; i < sizeof starts / sizeof starts[0]; i++) bind_rows(starts[i]);
    restore();
    return 0;
}
