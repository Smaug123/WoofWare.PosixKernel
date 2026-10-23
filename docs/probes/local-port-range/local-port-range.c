// Which values Linux's net.ipv4.ip_local_port_range and
// net.ipv4.ip_unprivileged_port_start accept, how each constrains the other,
// and which port bind(2) of port 0 and connect(2)'s implicit bind hand an
// unprivileged process when the range reaches below 1024.
//
// Build and run, as root in a network namespace of its own, with /proc/sys
// writable:
//   container run --rm --cap-add ALL -v "$PWD":/probe gcc:14 sh -c 'mount -o remount,rw /proc/sys && gcc -Wall -O1 -o /tmp/lpr /probe/local-port-range.c && /tmp/lpr'
//
// Each write is one write(2) of the text shown to the sysctl's file, and each
// row prints the errno it answered and what the file reads back afterwards.
// Before each row both settings are put back to the namespace's defaults
// (read at the start), unless the row says otherwise.
//
// Section R: ip_local_port_range writes, ip_unprivileged_port_start at its
//   default.
// Section U: ip_unprivileged_port_start writes, the range at its default.
// Section O: the two together, in the order each row names.
// Section B: with ip_unprivileged_port_start and the range set as the row
//   says, a child that drops to uid 1000 makes, in turn: a TCP socket that
//   binds 127.0.0.1 at the range's low end explicitly; a TCP socket that binds
//   127.0.0.1:0; a UDP socket that binds 0.0.0.0:0; a UDP socket that connects
//   to 127.0.0.1:X; and a TCP socket that connects to a listener at
//   127.0.0.1:X (bound by root before the drop, X outside the range). Each
//   prints its answer and the port it reports. A range of one port leaves
//   each search one port to take; each socket is closed before the next is
//   made, and the TCP connect, whose closed end goes on holding its port, is
//   made last.
//
// Darwin's net.inet.ip.portrange sysctls need root to write, so they are not
// measured here.
//
// Measured 2026-10-17 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14,
// root, defaults 32768-60999 and 1024). In short:
//   ip_local_port_range takes two ports with ip_unprivileged_port_start <=
//   low <= high <= 65535: equal ends, and ends of either parity, are taken;
//   a low end of 0 is refused even with ip_unprivileged_port_start at 0.
//   ip_unprivileged_port_start takes 0 up to the range's low end, and no
//   further. So the range never reaches a port an unprivileged process could
//   not bind explicitly: a process at uid 1000 binds the range's low end, and
//   its searches hand it ports of the range, below 1024 only once
//   ip_unprivileged_port_start has been lowered.
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
static const int X = 20000;

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
    case EROFS: return "EROFS";
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
    // The range first could be refused while unprivileged_port_start is above
    // its default low end, and the other way round; try both orders.
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

static void show_write(const char *section, const char *path, const char *text)
{
    int e = write_file(path, text);
    char r[64], u[64];
    read_file(RANGE, r, sizeof r);
    read_file(UNPRIV, u, sizeof u);
    printf("%s write %s \"%s\" -> %s | range=%s unprivileged_start=%s\n", section,
           path == RANGE ? "ip_local_port_range" : "ip_unprivileged_port_start", text, err_name(e), r, u);
}

static struct sockaddr_in at(const char *addr, int port)
{
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    inet_pton(AF_INET, addr, &s.sin_addr);
    return s;
}

static int port_of(int fd)
{
    struct sockaddr_in s;
    socklen_t l = sizeof s;
    if (getsockname(fd, (struct sockaddr *)&s, &l) < 0) return -1;
    return ntohs(s.sin_port);
}

static void attempt(const char *what, int type, const char *addr, int port, int connect_to)
{
    int fd = socket(AF_INET, type, 0);
    int e;
    if (connect_to) {
        struct sockaddr_in s = at("127.0.0.1", connect_to);
        e = connect(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
    } else {
        struct sockaddr_in s = at(addr, port);
        e = bind(fd, (struct sockaddr *)&s, sizeof s) < 0 ? errno : 0;
    }
    printf("  %s -> %s port=%d\n", what, err_name(e), port_of(fd));
    close(fd);
}

static void handouts(const char *unpriv, const char *range)
{
    restore();
    int eu, er;
    // Lower the unprivileged start first, so that the range may follow it.
    eu = write_file(UNPRIV, unpriv);
    er = write_file(RANGE, range);
    char r[64], u[64];
    read_file(RANGE, r, sizeof r);
    read_file(UNPRIV, u, sizeof u);
    printf("B unprivileged_start \"%s\" -> %s, range \"%s\" -> %s | range=%s unprivileged_start=%s\n", unpriv,
           err_name(eu), range, err_name(er), r, u);
    int low = atoi(r);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in s = at("127.0.0.1", X);
    if (bind(listener, (struct sockaddr *)&s, sizeof s) < 0 || listen(listener, 8) < 0) {
        printf("listener: %s\n", strerror(errno));
        exit(1);
    }
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        if (setgroups(0, NULL) < 0 || setresgid(1000, 1000, 1000) < 0 || setresuid(1000, 1000, 1000) < 0) {
            printf("drop: %s\n", strerror(errno));
            _exit(1);
        }
        printf("  as uid %d\n", (int)geteuid());
        char what[64];
        snprintf(what, sizeof what, "tcp bind 127.0.0.1:%d", low);
        attempt(what, SOCK_STREAM, "127.0.0.1", low, 0);
        attempt("tcp bind 127.0.0.1:0", SOCK_STREAM, "127.0.0.1", 0, 0);
        attempt("udp bind 0.0.0.0:0", SOCK_DGRAM, "0.0.0.0", 0, 0);
        attempt("udp connect 127.0.0.1:X", SOCK_DGRAM, NULL, 0, X);
        attempt("tcp connect 127.0.0.1:X", SOCK_STREAM, NULL, 0, X);
        fflush(stdout);
        _exit(0);
    }
    waitpid(c, NULL, 0);
    close(listener);
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

    const char *ranges[] = {
        "32768 60999", "1024 2000", "1023 2000", "1 2000", "0 2000", "1024 1024", "2000 2000", "2000 1999",
        "2000 2001", "2000 2002", "2001 2003", "60000 65535", "60000 65536", "65535 65535", "65536 65536",
        "-1 2000", "2000", "2000 3000 4000", "",
    };
    for (size_t i = 0; i < sizeof ranges / sizeof ranges[0]; i++) {
        restore();
        show_write("R", RANGE, ranges[i]);
    }

    const char *unprivs[] = { "0", "1", "1023", "1024", "1025", "32767", "32768", "32769", "60999", "65535",
                              "65536", "-1" };
    for (size_t i = 0; i < sizeof unprivs / sizeof unprivs[0]; i++) {
        restore();
        show_write("U", UNPRIV, unprivs[i]);
    }

    // O: orders.
    restore();
    show_write("O1", UNPRIV, "0");
    show_write("O1", RANGE, "0 2000");
    show_write("O1", RANGE, "1 2000");
    show_write("O1", UNPRIV, "1");
    show_write("O1", UNPRIV, "2");
    restore();
    show_write("O2", UNPRIV, "500");
    show_write("O2", RANGE, "499 2000");
    show_write("O2", RANGE, "500 2000");
    show_write("O2", RANGE, "600 600");
    show_write("O2", UNPRIV, "600");
    show_write("O2", UNPRIV, "601");
    restore();
    show_write("O3", RANGE, "2000 3000");
    show_write("O3", UNPRIV, "2000");
    show_write("O3", UNPRIV, "2001");
    show_write("O3", RANGE, "1999 3000");

    handouts("1024", "1024 1024");
    handouts("500", "600 600");
    handouts("500", "600 601");
    handouts("0", "1 1");
    handouts("0", "80 80");
    restore();
    return 0;
}
