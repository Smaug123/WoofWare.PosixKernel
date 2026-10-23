// What a Linux UDP receiver is charged for each datagram it holds
// (sk_rmem_alloc, read through SO_MEMINFO), as a function of the size; whether
// the charges add, across sizes and as the queue passes half its buffer; and
// whether a datagram is admitted exactly when the charge already held plus
// its own is at most SO_RCVBUF. Linux only. Plan: docs/plans/2026-10-18-udp-data-path.md.
//
// Loopback delivers from a softirq, which under a burst of sends runs later in
// ksoftirqd, so each send waits until the receiver's charge or its drop count
// (both from SO_MEMINFO) has moved before anything is read.
//
// Build and run:
//   container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O0 -o /tmp/ut /probe/udp-truesize.c && /tmp/ut'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif

static char payload[65536];

struct pair { int r, s; struct sockaddr_in to; };

static struct pair fresh(void)
{
    struct pair p;
    p.r = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&p.to, 0, sizeof p.to);
    p.to.sin_family = AF_INET;
    p.to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(p.r, (struct sockaddr *)&p.to, sizeof p.to) != 0) { perror("bind"); exit(1); }
    socklen_t len = sizeof p.to;
    getsockname(p.r, (struct sockaddr *)&p.to, &len);
    p.s = socket(AF_INET, SOCK_DGRAM, 0);
    return p;
}

static void done(struct pair p) { close(p.r); close(p.s); }

static unsigned int meminfo(int s, int which)
{
    unsigned int mem[SK_MEMINFO_VARS];
    socklen_t len = sizeof mem;
    if (getsockopt(s, SOL_SOCKET, SO_MEMINFO, mem, &len) != 0) { perror("SO_MEMINFO"); exit(1); }
    return mem[which];
}

static long rmem(int s) { return meminfo(s, SK_MEMINFO_RMEM_ALLOC); }

static long drops(int s) { return meminfo(s, SK_MEMINFO_DROPS); }

static int queued(int r)
{
    static char buf[65536];
    int n = 0;
    while (recv(r, buf, sizeof buf, MSG_DONTWAIT) >= 0) n++;
    return n;
}

// Send one datagram and wait until the receiver has queued or dropped it.
// Answers whether it was queued.
static int send1(struct pair p, int size)
{
    long r0 = rmem(p.r), d0 = drops(p.r);
    if (sendto(p.s, payload, size, 0, (struct sockaddr *)&p.to, sizeof p.to) != size) { perror("sendto"); exit(1); }
    for (int spin = 0; spin < 100000; spin++) {
        if (drops(p.r) != d0) return 0;
        if (rmem(p.r) != r0) return 1;
        if (spin > 100) usleep(10);
    }
    fprintf(stderr, "a datagram of %d was neither queued nor dropped\n", size);
    exit(1);
}

static long charge(int size)
{
    struct pair p = fresh();
    send1(p, size);
    long c = rmem(p.r);
    done(p);
    return c;
}

// Every size in [lo, hi] at which the charge differs from the size before.
static void steps(int lo, long clo, int hi, long chi)
{
    if (clo == chi) return;
    if (hi == lo + 1) {
        printf("charge: size %d is %ld; size %d is %ld\n", lo, clo, hi, chi);
        return;
    }
    int mid = lo + (hi - lo) / 2;
    long cmid = charge(mid);
    steps(lo, clo, mid, cmid);
    steps(mid, cmid, hi, chi);
}

// A fresh receiver's SO_RCVBUF, which every admission is predicted against.
static int rcv = 0;

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 't', sizeof payload);
    {
        struct pair p = fresh();
        socklen_t l = sizeof rcv;
        getsockopt(p.r, SOL_SOCKET, SO_RCVBUF, &rcv, &l);
        printf("SO_RCVBUF %d; an empty receiver's charge %ld\n", rcv, rmem(p.r));
        done(p);
    }
    // Additivity: the charge after each datagram of a fill with one size, and
    // the count admitted, against the rule "admitted when the charge already
    // held plus its own is at most SO_RCVBUF".
    int sizes[] = { 0, 100, 198, 1000, 4096, 9216, 16918, 40000, 65507 };
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        struct pair p = fresh();
        long one = charge(sizes[i]);
        long before = 0;
        int admitted = 0, nonadditive = 0, ruleBroken = 0;
        for (int k = 0; k < 400; k++) {
            int took = send1(p, sizes[i]);
            long after = rmem(p.r);
            int predicted = before + one <= rcv;
            if (took != predicted) ruleBroken++;
            if (took) {
                admitted++;
                if (after - before != one) {
                    if (nonadditive < 3) printf("fill %d: datagram %d charged %ld, not %ld (charge before %ld)\n", sizes[i], admitted, after - before, one, before);
                    nonadditive++;
                }
            }
            before = after;
        }
        printf("fill %d: charge each %ld; admitted %d (drained %d); charges that differ %d; admissions against the rule %d; final charge %ld\n",
               sizes[i], one, admitted, queued(p.r), nonadditive, ruleBroken, before);
        done(p);
    }

    // Mixed sizes, pseudo-random, from a fixed seed: does the rule predict
    // every admission, with each datagram charged as it would be alone?
    for (int trial = 0; trial < 5; trial++) {
        srand(1000 + trial);
        struct pair p = fresh();
        long before = 0, predictedCharge = 0;
        int admitted = 0, ruleBroken = 0, chargeBroken = 0;
        for (int k = 0; k < 600; k++) {
            int size = rand() % 4 == 0 ? rand() % 65508 : rand() % 2000;
            long alone = charge(size);
            int took = send1(p, size);
            long after = rmem(p.r);
            int predicted = before + alone <= rcv;
            if (took != predicted) ruleBroken++;
            if (took) {
                admitted++;
                predictedCharge += alone;
                if (after != predictedCharge) { chargeBroken++; predictedCharge = after; }
            }
            before = after;
        }
        printf("mixed trial %d: admitted %d (drained %d); admissions against the rule %d; charges that differ from alone %d\n",
               trial, admitted, queued(p.r), ruleBroken, chargeBroken);
        done(p);
    }

    // The charge as a function of the size: a staircase found by bisection
    // up to 16100, and above that, where it rises a byte at a time, sampled
    // against size + 832. These run last: tens of thousands of short-lived
    // sockets leave later fills dropping datagrams that a fresh machine keeps.
    steps(0, charge(0), 16100, charge(16100));
    {
        int samples = 0, mismatches = 0;
        for (int size = 16005; size <= 65507 + 96; size += 97) {
            int sz = size <= 65507 ? size : 65507;
            long c = charge(sz);
            samples++;
            if (c != sz + 832) { mismatches++; printf("charge: size %d is %ld, not size + 832\n", sz, c); }
        }
        printf("charge: sampled %d sizes from 16005 to 65507 against size + 832: %d mismatches\n", samples, mismatches);
    }

    // When taking a datagram gives its charge back: after each take from a
    // fill of 92 datagrams of 1000 (charge 2304 each), and after each take
    // from a queue that a send refills between takes.
    {
        struct pair p = fresh();
        for (int k = 0; k < 92; k++) send1(p, 1000);
        printf("release: 92 datagrams of 1000 held, charge %ld; after each take:", rmem(p.r));
        char buf[2000];
        for (int k = 0; k < 92; k++) {
            recv(p.r, buf, sizeof buf, MSG_DONTWAIT);
            printf(" %ld", rmem(p.r));
        }
        printf("\n");
        done(p);
    }
    {
        struct pair p = fresh();
        for (int k = 0; k < 40; k++) send1(p, 1000);
        char buf[2000];
        printf("release: 40 held; take one, send one, 30 times; charge after each pair, and whether the send was queued:");
        for (int k = 0; k < 30; k++) {
            recv(p.r, buf, sizeof buf, MSG_DONTWAIT);
            int q = send1(p, 1000);
            printf(" %ld%s", rmem(p.r), q ? "" : "(dropped)");
        }
        printf("\n");
        done(p);
    }
    {
        // A full queue, partly drained: how many more does it admit?
        for (int taken = 1; taken <= 30; taken += 7) {
            struct pair p = fresh();
            for (int k = 0; k < 92; k++) send1(p, 1000);
            char buf[2000];
            for (int k = 0; k < taken; k++) recv(p.r, buf, sizeof buf, MSG_DONTWAIT);
            long before = rmem(p.r);
            int more = 0;
            for (int k = 0; k < 100; k++) more += send1(p, 1000);
            printf("release: 92 of 1000 held, %d taken (charge then %ld): %d more admitted\n", taken, before, more);
            done(p);
        }
    }

    // Does taking a datagram return its whole charge?
    {
        struct pair p = fresh();
        send1(p, 1000); send1(p, 100);
        long both = rmem(p.r);
        char buf[2000];
        recv(p.r, buf, sizeof buf, 0);
        long one = rmem(p.r);
        recv(p.r, buf, sizeof buf, 0);
        printf("taking: 1000+100 charged %ld; after taking the 1000, %ld; after both, %ld\n", both, one, rmem(p.r));
        done(p);
    }
    return 0;
}
