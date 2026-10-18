// Which calls move a Linux UDP receiver's arrivals into its reader queue, as
// a receive does when the reader queue is empty: seen through when the charge
// of taken datagrams comes back (SO_MEMINFO), which is when the reader queue
// empties. Linux only. Plan: docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O0 -o /tmp/ur /probe/udp-release.c && /tmp/ur'
//
// Each row: ten datagrams of 1000 bytes (charged 2304 each) arrive at a fresh
// receiver; the row's call is made; ten more arrive; ten are taken. If the
// call moved the first ten into the reader queue, the tenth take empties it
// and their 23040 comes back (charge 23040). Otherwise the first take moved
// all twenty, ten remain in the reader queue, the 23040 owed is under a
// quarter of SO_RCVBUF, and nothing comes back (charge 46080).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

static char payload[1000];

static unsigned int meminfo(int s, int which)
{
    unsigned int mem[SK_MEMINFO_VARS];
    socklen_t len = sizeof mem;
    if (getsockopt(s, SOL_SOCKET, SO_MEMINFO, mem, &len) != 0) { perror("SO_MEMINFO"); exit(1); }
    return mem[which];
}

// Send one datagram and wait until the receiver has queued or dropped it.
static void send1(int s, int r, struct sockaddr_in *to)
{
    unsigned int r0 = meminfo(r, SK_MEMINFO_RMEM_ALLOC), d0 = meminfo(r, SK_MEMINFO_DROPS);
    if (sendto(s, payload, sizeof payload, 0, (struct sockaddr *)to, sizeof *to) != sizeof payload) { perror("sendto"); exit(1); }
    for (int spin = 0; spin < 100000; spin++) {
        if (meminfo(r, SK_MEMINFO_DROPS) != d0) { fprintf(stderr, "dropped\n"); exit(1); }
        if (meminfo(r, SK_MEMINFO_RMEM_ALLOC) != r0) return;
        if (spin > 100) usleep(10);
    }
    fprintf(stderr, "never arrived\n");
    exit(1);
}

enum call { NONE, FIONREAD_CALL, POLL_BLOCKING, POLL_NONBLOCKING, PEEK, EPOLL_ADD_BLOCKING, EPOLL_WAIT_BLOCKING, EPOLL_WAIT_NONBLOCKING, FIONREAD_THEN_TAKE };
static const char *names[] = {
    "no call", "FIONREAD", "poll(POLLIN) on a blocking socket", "poll(POLLIN) on a non-blocking socket",
    "recv(MSG_PEEK)", "epoll_ctl(ADD, EPOLLIN) on a blocking socket",
    "epoll_wait (registered before the arrivals) on a blocking socket",
    "epoll_wait (registered before the arrivals) on a non-blocking socket",
    "FIONREAD, then one take, then FIONREAD"
};

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'r', sizeof payload);
    for (int call = NONE; call <= FIONREAD_THEN_TAKE; call++) {
        int r = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in to;
        memset(&to, 0, sizeof to);
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(r, (struct sockaddr *)&to, sizeof to);
        socklen_t len = sizeof to;
        getsockname(r, (struct sockaddr *)&to, &len);
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (call == POLL_NONBLOCKING || call == EPOLL_WAIT_NONBLOCKING) fcntl(r, F_SETFL, fcntl(r, F_GETFL) | O_NONBLOCK);
        int ep = -1;
        if (call == EPOLL_WAIT_BLOCKING || call == EPOLL_WAIT_NONBLOCKING) {
            ep = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN, .data.fd = r };
            epoll_ctl(ep, EPOLL_CTL_ADD, r, &ev);
        }
        for (int k = 0; k < 10; k++) send1(s, r, &to);
        char buf[2000];
        int answer = -1;
        switch (call) {
        case FIONREAD_CALL:
        case FIONREAD_THEN_TAKE: ioctl(r, FIONREAD, &answer); break;
        case POLL_BLOCKING:
        case POLL_NONBLOCKING: {
            struct pollfd p = { r, POLLIN, 0 };
            answer = poll(&p, 1, 0);
            break;
        }
        case PEEK: answer = recv(r, buf, sizeof buf, MSG_PEEK | MSG_DONTWAIT); break;
        case EPOLL_ADD_BLOCKING: {
            ep = epoll_create1(0);
            struct epoll_event ev = { .events = EPOLLIN, .data.fd = r };
            answer = epoll_ctl(ep, EPOLL_CTL_ADD, r, &ev);
            break;
        }
        case EPOLL_WAIT_BLOCKING:
        case EPOLL_WAIT_NONBLOCKING: {
            struct epoll_event ev;
            answer = epoll_wait(ep, &ev, 1, 0);
            break;
        }
        default: break;
        }
        int extra = -1;
        if (call == FIONREAD_THEN_TAKE) {
            recv(r, buf, sizeof buf, MSG_DONTWAIT);
            ioctl(r, FIONREAD, &extra);
        }
        for (int k = 0; k < 10; k++) send1(s, r, &to);
        unsigned int before = meminfo(r, SK_MEMINFO_RMEM_ALLOC);
        int takes = call == FIONREAD_THEN_TAKE ? 9 : 10;
        for (int k = 0; k < takes; k++) recv(r, buf, sizeof buf, MSG_DONTWAIT);
        printf("%s (answered %d%s): charge %u before the takes, %u after %d takes\n",
               names[call], answer, call == FIONREAD_THEN_TAKE ? ", then FIONREAD answered" : "",
               before, meminfo(r, SK_MEMINFO_RMEM_ALLOC), takes);
        if (call == FIONREAD_THEN_TAKE) printf("  (the second FIONREAD answered %d)\n", extra);
        if (ep >= 0) close(ep);
        close(r); close(s);
    }
    return 0;
}
