// What a level-triggered and a one-shot epoll registration do that an
// edge-triggered one does not: where a delivered level-triggered entry goes
// back on the ready list, and when a one-shot entry stops reporting and starts
// again.
//
// Every target is a loopback TCP listener, readable while a connection is
// queued on it (a connect is its edge, and an accept drains it), except in
// sections H and I, which use a connected client socket and its peer. Every
// wait has timeout 0. A row prints each wait's return and the `data` of each
// event, which is the listener's number; `events` is printed only where it can
// differ from EPOLLIN.
//
// Sections:
//   A  one LT listener with a connection queued: four waits in a row, then an
//      accept and two more waits.
//   B  three LT listeners, edges l1 l2 l3, a wait with maxevents 1, then two
//      waits with maxevents 8: where the re-queued l1 goes relative to the l2
//      and l3 the first wait spared.
//   C  l1 LT, l2 ET, l3 LT, edges in that order: two waits with maxevents 8.
//   D  l1 and l2 LT, both delivered once (so both re-queued, l1 first); a
//      second connect to l1 (its edge while pending), then a wait: does the
//      edge move l1?
//   E  l1 LT and l2 ET; l1 delivered once and re-queued; l1 drained by
//      accept; l2's edge; a wait (is the stale l1 dropped?), then l1's edge
//      and l2's edge again and a wait (l1 back at its new edge's place?).
//   F  one-shot, LT and ET: a listener registered IN|ONESHOT (and
//      IN|ONESHOT|ET) with a connection queued: a wait, a wait, a second
//      connect and a wait; then a MOD to IN|ONESHOT and two waits; then a MOD
//      to IN alone and two waits.
//   G  one-shot with maxevents: l1 and l2 IN|ONESHOT, edges l1 l2, a wait
//      with maxevents 1 and two more.
//   H  a one-shot entry that is stale when walked: l1 IN|ONESHOT, an edge,
//      an accept, a wait (nothing), then a second connect and a wait: did the
//      stale walk disarm it?
//   I  a disarmed entry and an unkeyed wake: a connected client c registered
//      IN|RDHUP|ONESHOT|ET and delivered once (its peer wrote a byte), so
//      disarmed; the peer closes (a FIN, which wakes unkeyed, `order8.c`);
//      then listener l2's edge (l2 IN|ET); then a MOD of c to
//      IN|RDHUP|ONESHOT|ET; then a wait. If the FIN queued the disarmed c,
//      c reports ahead of l2; if not, the MOD queues it behind l2.
//   J  a MOD that clears ONESHOT on a disarmed entry whose target is not
//      ready: l1 IN|ONESHOT delivered and drained, then MOD to IN, then an
//      edge and a wait.
//
// Build and run, from this directory:
//   Linux:  container run --rm -v "$PWD:/probe" gcc:14 sh -c
//             "gcc -Wall -O1 -o /tmp/em /probe/epoll-modes.c && /tmp/em"
//
// Darwin has no epoll.
//
// Measured 2026-10-18 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14
// image), twice with the same answers (measured-linux-6.18.5-aarch64.txt):
//   A-E  a level-triggered entry reports at every wait while its target is
//        ready, and its target's next wake does not move it while it is
//        pending; a reported one goes back behind the entries maxevents
//        spared, in the order the wait reported them; a wait that finds it
//        stale drops it, and its next edge queues it afresh.
//   F-J  a one-shot entry, level- or edge-triggered, reports once and is then
//        silent through a fresh edge until a MOD re-arms it (a MOD of a
//        ready target queues it at once, of an idle one not); an entry
//        maxevents spared, or one a wait found stale, is not disarmed; the
//        peer's FIN does not queue a disarmed entry, so the re-arming MOD
//        queues it behind an edge that came after the FIN.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>

static int listener(struct sockaddr_in *out)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0 || listen(fd, 8) < 0) {
        perror("listener");
        _exit(1);
    }
    socklen_t sl = sizeof *out;
    getsockname(fd, (struct sockaddr *)out, &sl);
    return fd;
}

static int connect_to(struct sockaddr_in *a)
{
    int c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect(c, (struct sockaddr *)a, sizeof *a) < 0) {
        perror("connect");
        _exit(1);
    }
    return c;
}

static void drain(int l)
{
    int s = accept(l, NULL, NULL);
    if (s < 0) {
        perror("accept");
        _exit(1);
    }
}

static void wait_n(int ep, int maxevents, const char *label, int show_events)
{
    struct epoll_event evs[8];
    int n = epoll_wait(ep, evs, maxevents, 0);
    printf("  %-60s -> %d:", label, n);
    if (n < 0)
        printf(" errno=%d", errno);
    for (int i = 0; i < n; i++) {
        printf(" %llu", (unsigned long long)evs[i].data.u64);
        if (show_events)
            printf("/0x%x", evs[i].events);
    }
    printf("\n");
}

static void ctl(int ep, int op, int fd, unsigned events, unsigned long long data)
{
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events = events;
    ev.data.u64 = data;
    if (epoll_ctl(ep, op, fd, &ev) < 0) {
        printf("  epoll_ctl(op %d, events 0x%x) failed: errno %d\n", op, events, errno);
        _exit(1);
    }
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);

    printf("A. one LT listener\n");
    {
        struct sockaddr_in a1;
        int l1 = listener(&a1);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN, 1);
        connect_to(&a1);
        wait_n(ep, 8, "first wait", 0);
        wait_n(ep, 8, "second wait", 0);
        wait_n(ep, 8, "third wait", 0);
        wait_n(ep, 8, "fourth wait", 0);
        drain(l1);
        wait_n(ep, 8, "after accept", 0);
        wait_n(ep, 8, "again", 0);
    }

    printf("B. three LT listeners, maxevents 1 then 8\n");
    {
        struct sockaddr_in a1, a2, a3;
        int l1 = listener(&a1), l2 = listener(&a2), l3 = listener(&a3);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN, 1);
        ctl(ep, EPOLL_CTL_ADD, l2, EPOLLIN, 2);
        ctl(ep, EPOLL_CTL_ADD, l3, EPOLLIN, 3);
        connect_to(&a1);
        connect_to(&a2);
        connect_to(&a3);
        wait_n(ep, 1, "maxevents 1", 0);
        wait_n(ep, 8, "maxevents 8", 0);
        wait_n(ep, 8, "maxevents 8 again", 0);
        wait_n(ep, 2, "maxevents 2", 0);
        wait_n(ep, 8, "maxevents 8 after that", 0);
    }

    printf("C. l1 LT, l2 ET, l3 LT\n");
    {
        struct sockaddr_in a1, a2, a3;
        int l1 = listener(&a1), l2 = listener(&a2), l3 = listener(&a3);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN, 1);
        ctl(ep, EPOLL_CTL_ADD, l2, EPOLLIN | EPOLLET, 2);
        ctl(ep, EPOLL_CTL_ADD, l3, EPOLLIN, 3);
        connect_to(&a1);
        connect_to(&a2);
        connect_to(&a3);
        wait_n(ep, 8, "first wait", 0);
        wait_n(ep, 8, "second wait", 0);
    }

    printf("D. an edge on a re-queued LT entry\n");
    {
        struct sockaddr_in a1, a2;
        int l1 = listener(&a1), l2 = listener(&a2);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN, 1);
        ctl(ep, EPOLL_CTL_ADD, l2, EPOLLIN, 2);
        connect_to(&a1);
        connect_to(&a2);
        wait_n(ep, 8, "first wait", 0);
        connect_to(&a1);
        wait_n(ep, 8, "after a second connect to l1", 0);
    }

    printf("E. a re-queued LT entry drained\n");
    {
        struct sockaddr_in a1, a2;
        int l1 = listener(&a1), l2 = listener(&a2);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN, 1);
        ctl(ep, EPOLL_CTL_ADD, l2, EPOLLIN | EPOLLET, 2);
        connect_to(&a1);
        wait_n(ep, 8, "first wait", 0);
        drain(l1);
        connect_to(&a2);
        wait_n(ep, 8, "after accept on l1, edge on l2", 0);
        connect_to(&a1);
        connect_to(&a2);
        wait_n(ep, 8, "after edges l1 l2", 0);
    }

    for (int et = 0; et < 2; et++) {
        printf("F. one-shot%s\n", et ? ", ET" : ", LT");
        unsigned mode = EPOLLONESHOT | (et ? EPOLLET : 0);
        struct sockaddr_in a1;
        int l1 = listener(&a1);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN | mode, 1);
        connect_to(&a1);
        wait_n(ep, 8, "first wait", 1);
        wait_n(ep, 8, "second wait", 1);
        connect_to(&a1);
        wait_n(ep, 8, "after a second connect", 1);
        ctl(ep, EPOLL_CTL_MOD, l1, EPOLLIN | mode, 1);
        wait_n(ep, 8, "after MOD to the same mask", 1);
        wait_n(ep, 8, "again", 1);
        ctl(ep, EPOLL_CTL_MOD, l1, EPOLLIN | (et ? EPOLLET : 0), 1);
        wait_n(ep, 8, "after MOD without ONESHOT", 1);
        wait_n(ep, 8, "again", 1);
    }

    printf("G. one-shot with maxevents 1\n");
    {
        struct sockaddr_in a1, a2;
        int l1 = listener(&a1), l2 = listener(&a2);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN | EPOLLONESHOT, 1);
        ctl(ep, EPOLL_CTL_ADD, l2, EPOLLIN | EPOLLONESHOT, 2);
        connect_to(&a1);
        connect_to(&a2);
        wait_n(ep, 1, "maxevents 1", 0);
        wait_n(ep, 1, "maxevents 1 again", 0);
        wait_n(ep, 8, "maxevents 8", 0);
    }

    printf("H. a one-shot entry stale when walked\n");
    {
        struct sockaddr_in a1;
        int l1 = listener(&a1);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN | EPOLLONESHOT, 1);
        connect_to(&a1);
        drain(l1);
        wait_n(ep, 8, "after edge and accept", 0);
        connect_to(&a1);
        wait_n(ep, 8, "after a second connect", 0);
    }

    printf("I. a disarmed entry and an unkeyed wake\n");
    {
        struct sockaddr_in a1, a2;
        int l1 = listener(&a1), l2 = listener(&a2);
        int c = connect_to(&a1);
        int peer = accept(l1, NULL, NULL);
        int ep = epoll_create1(0);
        unsigned cmask = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT | EPOLLET;
        ctl(ep, EPOLL_CTL_ADD, c, cmask, 1);
        ctl(ep, EPOLL_CTL_ADD, l2, EPOLLIN | EPOLLET, 2);
        wait_n(ep, 8, "fresh", 1);
        if (write(peer, "x", 1) != 1)
            perror("write");
        usleep(50000);
        wait_n(ep, 8, "after the peer's byte", 1);
        close(peer);
        usleep(50000);
        connect_to(&a2);
        ctl(ep, EPOLL_CTL_MOD, c, cmask, 1);
        wait_n(ep, 8, "after FIN, l2's edge, MOD of c", 1);
    }

    printf("J. ONESHOT cleared by MOD on a disarmed, idle entry\n");
    {
        struct sockaddr_in a1;
        int l1 = listener(&a1);
        int ep = epoll_create1(0);
        ctl(ep, EPOLL_CTL_ADD, l1, EPOLLIN | EPOLLONESHOT, 1);
        connect_to(&a1);
        wait_n(ep, 8, "first wait", 0);
        drain(l1);
        ctl(ep, EPOLL_CTL_MOD, l1, EPOLLIN, 1);
        wait_n(ep, 8, "after accept and MOD to IN", 0);
        connect_to(&a1);
        wait_n(ep, 8, "after a second connect", 0);
        wait_n(ep, 8, "again", 0);
    }

    return 0;
}
