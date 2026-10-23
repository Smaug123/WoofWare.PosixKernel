// Linux: whether a connect's search may take over a TIME_WAIT four-tuple
// that was entered within the first second after the machine booted.
//
// Build in one container and run in a fresh one, so that the first row's
// connection ends while the machine's uptime is under a second (it starts at
// 0.6 to 1.1 s):
//   container run --rm -v "$PWD":/probe gcc:14 gcc -Wall -O1 -static -o /probe/tw-boot /probe/tw-boot.c
//   container run --rm -v "$PWD":/probe gcc:14 /probe/tw-boot
//
// Measured 2026-10-14 on Linux 6.18.5 aarch64 (Apple's container VM, default
// sysctls), five runs, three of them in tw-boot.linux-6.18.5-aarch64.txt: a
// TIME_WAIT entered at an uptime under a second (0.641, 0.703, 0.778 s) was
// not taken over two seconds later, and one entered later (1.098 s and every
// second row) was. That fits Linux's `tcp_twsk_unique`, which takes over
// only a TIME_WAIT whose last timestamp's stamp, in whole seconds of uptime,
// is not 0.
//
// Each row ends a connection from a client at a port T of its own (narrowed
// with IP_LOCAL_PORT_RANGE) to the listener X, the client closing first, and
// once two seconds have passed, connects a fresh socket narrowed to T to X:
// the search can take T only by taking over the four-tuple. /proc/uptime is
// printed when each connection ends and when each search is made.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif

static struct sockaddr_in at(int port)
{
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
    s.sin_family = AF_INET;
    s.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &s.sin_addr);
    return s;
}

static double uptime(void)
{
    struct timespec t;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static double monotonic(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void narrow(int fd, int port)
{
    unsigned int range = (unsigned int)port | ((unsigned int)port << 16);
    if (setsockopt(fd, IPPROTO_IP, IP_LOCAL_PORT_RANGE, &range, sizeof range) < 0) {
        printf("IP_LOCAL_PORT_RANGE: %s\n", strerror(errno));
        exit(1);
    }
}

static void row(int l, int x, int port)
{
    int c = socket(AF_INET, SOCK_STREAM, 0);
    narrow(c, port);
    struct sockaddr_in sx = at(x);
    if (connect(c, (struct sockaddr *)&sx, sizeof sx) != 0) {
        printf("connect: %s\n", strerror(errno));
        exit(1);
    }
    int s = accept(l, NULL, NULL);
    close(c);
    char b;
    if (read(s, &b, 1) != 0) {
        printf("the client's FIN did not arrive\n");
        exit(1);
    }
    close(s);
    double ended = uptime(), ended_mono = monotonic();
    printf("T=%d ended at uptime %.3f s (CLOCK_MONOTONIC %.3f s)\n", port, ended, ended_mono);
    while (uptime() < ended + 2.0) usleep(10000);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    narrow(fd, port);
    double searched = uptime();
    int e = connect(fd, (struct sockaddr *)&sx, sizeof sx) < 0 ? errno : 0;
    printf("T=%d connect to X at uptime %.3f s, %.3f s after -> %s\n", port, searched, searched - ended,
           e == 0 ? "OK" : e == EADDRNOTAVAIL ? "EADDRNOTAVAIL" : strerror(e));
    if (e == 0) {
        int a = accept(l, NULL, NULL);
        if (a >= 0) close(a);
    }
    close(fd);
}

int main(void)
{
    printf("started at uptime %.3f s\n", uptime());
    int x = 45701;
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sx = at(x);
    if (bind(l, (struct sockaddr *)&sx, sizeof sx) != 0 || listen(l, 16) != 0) {
        printf("listener: %s\n", strerror(errno));
        return 1;
    }
    row(l, x, 44801);
    row(l, x, 44802);
    close(l);
    return 0;
}
