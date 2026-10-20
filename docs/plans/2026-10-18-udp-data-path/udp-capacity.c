// How many datagrams of one size a UDP receiver that nobody reads holds, at
// the default receive buffer, as a function of the size: the boundaries at
// which the count changes, found by bisection. Plan:
// docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   Darwin: cc -Wall -O0 -o /tmp/uc udp-capacity.c && /tmp/uc
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O0 -o /tmp/uc /probe/udp-capacity.c && /tmp/uc'
//
// Each measurement makes a fresh receiver bound to 127.0.0.1 and a fresh
// sender, sends 40000 datagrams, then drains and counts. "paced" sends in
// batches with a pause between, so that a queue in front of the socket
// (Darwin's loopback input queue) cannot be what drops them; "primed" first
// sends the receiver one datagram of 1 byte and takes it, so that the
// receiver is not fresh when the fill starts.
//
// Linux's count is a staircase, found by bisection over every size. Darwin's
// count changes at almost every size above 160 bytes, so bisection there
// covers 0..300 only, and the rest is checked against
// floor((recvspace + 16) / (size + 32)) fresh and floor(recvspace / (size +
// 32)) primed, at a stride.
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __APPLE__
#define MAXDGRAM 9216
#else
#define MAXDGRAM 65507
#endif

static char payload[65536];

static int count_held(int size, int paced, int prime)
{
    int r = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
#ifdef __APPLE__
    a.sin_len = sizeof a;
#endif
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(r, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    socklen_t len = sizeof a;
    getsockname(r, (struct sockaddr *)&a, &len);
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    static char buf[65536];
    if (prime) {
        sendto(s, payload, 1, 0, (struct sockaddr *)&a, sizeof a);
        usleep(20000);
        if (recv(r, buf, sizeof buf, MSG_DONTWAIT) != 1) { fprintf(stderr, "prime failed\n"); exit(1); }
    }
    // Enough to overfill: the receive buffer is under 1 MB on both, and a
    // datagram costs at least 32 bytes.
    int total = 40000;
    int batch = paced ? 50 : total;
    for (int sent = 0; sent < total; sent += batch) {
        for (int k = 0; k < batch; k++) {
            if (sendto(s, payload, size, 0, (struct sockaddr *)&a, sizeof a) < 0) {
                fprintf(stderr, "sendto %d: %s\n", size, strerror(errno));
                exit(1);
            }
        }
        if (paced) usleep(2000);
    }
    usleep(50000);
    int n = 0;
    while (recv(r, buf, sizeof buf, MSG_DONTWAIT) >= 0) n++;
    close(r);
    close(s);
    return n;
}

// Report every size in [lo, hi] at which the count differs from the size
// before, given count(lo) and count(hi). The count is non-increasing in the
// size, so bisection finds each step.
static void steps(int lo, int clo, int hi, int chi)
{
    if (clo == chi) return;
    if (hi == lo + 1) {
        printf("size %d holds %d; size %d holds %d\n", lo, clo, hi, chi);
        return;
    }
    int mid = lo + (hi - lo) / 2;
    int cmid = count_held(mid, 0, 0);
    steps(lo, clo, mid, cmid);
    steps(mid, cmid, hi, chi);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'c', sizeof payload);
    int r = socket(AF_INET, SOCK_DGRAM, 0);
    int rcv = 0;
    socklen_t l = sizeof rcv;
    getsockopt(r, SOL_SOCKET, SO_RCVBUF, &rcv, &l);
    close(r);
    printf("SO_RCVBUF %d\n", rcv);
    // Repeatability, and whether pacing changes anything.
    int probes[] = { 0, 1, 16, 100, 200, 500, 1000, 2000, 4096, 9216, MAXDGRAM };
    for (unsigned i = 0; i < sizeof probes / sizeof *probes; i++) {
        int a = count_held(probes[i], 0, 0), b = count_held(probes[i], 0, 0), c = count_held(probes[i], 1, 0), d = count_held(probes[i], 0, 1);
        printf("size %d: unpaced %d, %d; paced %d; primed %d\n", probes[i], a, b, c, d);
    }
#ifdef __APPLE__
    steps(0, count_held(0, 0, 0), 300, count_held(300, 0, 0));
    int mismatches = 0, checked = 0;
    for (int size = 160; size <= MAXDGRAM + 60; size += 61) {
        int sz = size <= MAXDGRAM ? size : MAXDGRAM;
        int fresh = count_held(sz, 0, 0), primed = count_held(sz, 0, 1);
        int ffresh = (rcv + 16) / (sz + 32), fprimed = rcv / (sz + 32);
        checked++;
        if (fresh != ffresh || primed != fprimed) {
            mismatches++;
            printf("size %d: fresh %d (formula %d), primed %d (formula %d) MISMATCH\n", sz, fresh, ffresh, primed, fprimed);
        }
    }
    printf("formula checked at %d sizes from 160 to %d: %d mismatches\n", checked, MAXDGRAM, mismatches);
    // Where the two formulas differ.
    int extra[] = { 1138, 1139, 1140 };
    for (unsigned i = 0; i < 3; i++) printf("size %d: fresh %d, primed %d\n", extra[i], count_held(extra[i], 0, 0), count_held(extra[i], 0, 1));
#else
    steps(0, count_held(0, 0, 0), MAXDGRAM, count_held(MAXDGRAM, 0, 0));
#endif
    return 0;
}
