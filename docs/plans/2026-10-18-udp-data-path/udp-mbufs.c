// What Darwin charges a UDP receiver for each datagram, in bytes (sb_cc,
// which FIONREAD reports) and in mbuf memory (sb_mbcnt), read for each socket
// from the net.inet.udp.pcblist_n sysctl as netstat reads it; what a
// receiver's history does to the charge of its next datagram; and whether
// "admitted exactly when both budgets have room for the datagram's bytes"
// predicts every admission. Darwin only. Plan:
// docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   cc -Wall -O0 -o /tmp/um udp-mbufs.c && /tmp/um
//
// The pcblist_n records are private to XNU, so their layout is declared here
// from bsd/sys/socketvar.h and bsd/netinet/in_pcb.h (xsockbuf_n, xinpcb_n),
// and section 0 prints what it reads of a fresh socket, so that a wrong
// layout shows.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#define XSO_RCVBUF 0x002
#define XSO_INPCB 0x010

struct record_head { uint32_t len; uint32_t kind; };
struct xsockbuf_n {
    uint32_t xsb_len;
    uint32_t xsb_kind;
    uint32_t sb_cc;
    uint32_t sb_hiwat;
    uint32_t sb_mbcnt;
    uint32_t sb_mbmax;
    int32_t sb_lowat;
    short sb_flags;
    short sb_timeo;
};
struct xinpcb_n_head {
    uint32_t xi_len;
    uint32_t xi_kind;
    uint64_t xi_inpp;
    uint16_t inp_fport;
    uint16_t inp_lport;
};

#define ROUNDUP64(x) (((x) + 7) & ~7u)

struct rcvbuf { uint32_t cc, hiwat, mbcnt, mbmax; };

// The receive buffer of the UDP socket bound to `port`, as the kernel reports
// it now. Exits if no such socket is listed.
static struct rcvbuf rcvbuf_of(uint16_t port)
{
    static char *buf = NULL;
    static size_t cap = 0;
    size_t len = 0;
    if (sysctlbyname("net.inet.udp.pcblist_n", NULL, &len, NULL, 0) != 0) { perror("pcblist_n size"); exit(1); }
    len += len / 2 + 4096;
    if (len > cap) { buf = realloc(buf, len); cap = len; }
    if (sysctlbyname("net.inet.udp.pcblist_n", buf, &len, NULL, 0) != 0) { perror("pcblist_n"); exit(1); }
    struct record_head *head = (struct record_head *)buf;
    size_t off = ROUNDUP64(head->len);
    int ours = 0;
    while (off + sizeof(struct record_head) <= len) {
        struct record_head *r = (struct record_head *)(buf + off);
        if (r->len == 0 || r->len < sizeof(struct record_head)) break;
        if (r->kind == XSO_INPCB) {
            struct xinpcb_n_head *in = (struct xinpcb_n_head *)r;
            ours = ntohs(in->inp_lport) == port;
        } else if (r->kind == XSO_RCVBUF && ours) {
            struct xsockbuf_n *sb = (struct xsockbuf_n *)r;
            struct rcvbuf out = { sb->sb_cc, sb->sb_hiwat, sb->sb_mbcnt, sb->sb_mbmax };
            return out;
        }
        off += ROUNDUP64(r->len);
    }
    fprintf(stderr, "no UDP socket at port %u in pcblist_n\n", port);
    exit(1);
}

static char payload[65536];

struct pair { int r, s; struct sockaddr_in to; uint16_t port; };

static int udp(void) { return socket(AF_INET, SOCK_DGRAM, 0); }

static struct sockaddr_in lo(uint16_t port)
{
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_len = sizeof a;
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

static uint16_t portof(int s)
{
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    getsockname(s, (struct sockaddr *)&a, &len);
    return ntohs(a.sin_port);
}

static struct pair fresh(void)
{
    struct pair p;
    p.r = udp();
    struct sockaddr_in a = lo(0);
    if (bind(p.r, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    p.port = portof(p.r);
    p.to = lo(p.port);
    p.s = udp();
    return p;
}

static void done(struct pair p) { close(p.r); close(p.s); }

// Send a datagram of `size` from `s` to `p` and wait until the receiver's
// byte count moves, or 30 ms pass. Answers whether it arrived, with the
// buffer before and after.
static int send_from(int s, struct pair p, int size, struct rcvbuf *before, struct rcvbuf *after)
{
    *before = rcvbuf_of(p.port);
    // A sender connected to the receiver sends with send(2): Darwin refuses
    // sendto(2) with an address on a connected socket.
    ssize_t sent = sendto(s, payload, size, 0, (struct sockaddr *)&p.to, sizeof p.to);
    if (sent < 0 && errno == EISCONN) sent = send(s, payload, size, 0);
    if (sent != size) { perror("sendto"); exit(1); }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        *after = rcvbuf_of(p.port);
        if (after->cc != before->cc || after->mbcnt != before->mbcnt) {
            // The delivery may be partway through updating the buffer: wait
            // until two readings 1 ms apart agree.
            for (;;) {
                usleep(1000);
                struct rcvbuf again = rcvbuf_of(p.port);
                if (again.cc == after->cc && again.mbcnt == after->mbcnt) return 1;
                *after = again;
            }
        }
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        if ((t.tv_sec - t0.tv_sec) * 1000 + (t.tv_nsec - t0.tv_nsec) / 1000000 > 30) return 0;
        usleep(50);
    }
}

static int send1(struct pair p, int size, struct rcvbuf *before, struct rcvbuf *after)
{
    return send_from(p.s, p, size, before, after);
}

static void take(int r)
{
    char buf[65536];
    if (recv(r, buf, sizeof buf, MSG_DONTWAIT) < 0) { perror("recv"); exit(1); }
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    memset(payload, 'm', sizeof payload);
    const char *only = argc > 1 ? argv[1] : "0123";

    if (strchr(only, '0')) {
        struct pair p = fresh();
        struct rcvbuf b = rcvbuf_of(p.port);
        printf("0 a fresh receiver: cc %u hiwat %u mbcnt %u mbmax %u\n", b.cc, b.hiwat, b.mbcnt, b.mbmax);
        struct rcvbuf before, after;
        send1(p, 10, &before, &after);
        int fion = -1;
        ioctl(p.r, FIONREAD, &fion);
        printf("0 one datagram of 10: cc %u mbcnt %u; FIONREAD %d\n", after.cc, after.mbcnt, fion);
        take(p.r);
        b = rcvbuf_of(p.port);
        printf("0 after taking it: cc %u mbcnt %u\n", b.cc, b.mbcnt);
        done(p);
    }

    // 1: the charges of a fresh receiver's first and second datagram, at every
    // size; printed where they change.
    if (strchr(only, '1')) {
        long last[4] = { -1, -1, -1, -1 };
        int lastSize = -1;
        for (int size = 0; size <= 9216; size++) {
            struct pair p = fresh();
            struct rcvbuf b0, b1, b2, b3;
            if (!send1(p, size, &b0, &b1) || !send1(p, size, &b2, &b3)) { fprintf(stderr, "size %d dropped\n", size); exit(1); }
            // The byte charge less the datagram's own bytes, so that a run
            // is a range of sizes with one overhead and one mbuf charge.
            long now[4] = { (long)b1.cc - b0.cc - size, (long)b1.mbcnt - b0.mbcnt, (long)b3.cc - b2.cc - size, (long)b3.mbcnt - b2.mbcnt };
            if (memcmp(now, last, sizeof now) != 0) {
                if (lastSize >= 0) printf("1 sizes %d..%d: first datagram cc +size%+ld mbcnt +%ld; second cc +size%+ld mbcnt +%ld\n", lastSize, size - 1, last[0], last[1], last[2], last[3]);
                memcpy(last, now, sizeof now);
                lastSize = size;
            }
            done(p);
        }
        printf("1 sizes %d..9216: first datagram cc +size%+ld mbcnt +%ld; second cc +size%+ld mbcnt +%ld\n", lastSize, last[0], last[1], last[2], last[3]);
    }

    // 2: what the receiver did before its first datagram, and that
    // datagram's charge (4 bytes).
    if (strchr(only, '2')) {
        static const char *names[] = {
            "nothing", "connect to a bound socket", "connect, then AF_UNSPEC", "sendto another socket",
            "sendto itself (the datagram it then receives)", "getsockname", "SO_REUSEADDR", "a non-blocking recv on its empty queue",
            "poll", "FIONREAD", "connect to the sender, which sends",
            "the sender connected to it first", "a datagram from another sender, taken",
            "sendto another socket, then AF_UNSPEC", "a datagram taken, then AF_UNSPEC",
            "connect, send, then AF_UNSPEC", "bind only (the fresh receiver is bound)",
            "send(2) unconnected (EDESTADDRREQ)", "write(2) unconnected (EDESTADDRREQ)", "sendto of 9217 bytes (EMSGSIZE)",
            "sendto from an unmapped buffer (EFAULT)", "sendto with a 15-byte address (EINVAL)", "sendto to family 99 (EAFNOSUPPORT)",
            "sendto to 0.0.0.0 (EHOSTUNREACH)", "connect to port 0 (EADDRNOTAVAIL)", "sendto to a closed descriptor (EBADF)",
            "send of 0 bytes, connected to the sender", "recv of 0 on its empty queue",
        };
        for (unsigned row = 0; row < sizeof names / sizeof *names; row++) {
            struct pair p = fresh();
            int other = udp();
            struct sockaddr_in oa = lo(0);
            bind(other, (struct sockaddr *)&oa, sizeof oa);
            struct sockaddr_in to_other = lo(portof(other));
            char buf[64];
            int one = 1, fion;
            struct rcvbuf before, after;
            int sender = p.s;
            switch (row) {
            case 1: connect(p.r, (struct sockaddr *)&to_other, sizeof to_other); sender = other; break;
            case 2: {
                connect(p.r, (struct sockaddr *)&to_other, sizeof to_other);
                struct sockaddr un; memset(&un, 0, sizeof un); un.sa_family = AF_UNSPEC;
                connect(p.r, &un, sizeof un);
                break;
            }
            case 3: sendto(p.r, "x", 1, 0, (struct sockaddr *)&to_other, sizeof to_other); break;
            case 4: sender = p.r; break;
            case 5: portof(p.r); break;
            case 6: setsockopt(p.r, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one); break;
            case 7: recv(p.r, buf, sizeof buf, MSG_DONTWAIT); break;
            case 8: { struct pollfd pf = { p.r, POLLIN, 0 }; poll(&pf, 1, 0); break; }
            case 9: ioctl(p.r, FIONREAD, &fion); break;
            case 10: {
                // p.s must be bound for the receiver to connect to it.
                struct sockaddr_in sa = lo(0);
                bind(p.s, (struct sockaddr *)&sa, sizeof sa);
                struct sockaddr_in ts = lo(portof(p.s));
                connect(p.r, (struct sockaddr *)&ts, sizeof ts);
                break;
            }
            case 11: connect(p.s, (struct sockaddr *)&p.to, sizeof p.to); break;
            case 12:
            case 14: {
                struct rcvbuf b0, b1;
                send_from(other, p, 4, &b0, &b1);
                take(p.r);
                if (row == 14) {
                    struct sockaddr un; memset(&un, 0, sizeof un); un.sa_family = AF_UNSPEC;
                    connect(p.r, &un, sizeof un);
                }
                break;
            }
            case 13: {
                sendto(p.r, "x", 1, 0, (struct sockaddr *)&to_other, sizeof to_other);
                struct sockaddr un; memset(&un, 0, sizeof un); un.sa_family = AF_UNSPEC;
                connect(p.r, &un, sizeof un);
                break;
            }
            case 15: {
                connect(p.r, (struct sockaddr *)&to_other, sizeof to_other);
                send(p.r, "x", 1, 0);
                struct sockaddr un; memset(&un, 0, sizeof un); un.sa_family = AF_UNSPEC;
                connect(p.r, &un, sizeof un);
                break;
            }
            case 17: send(p.r, "x", 1, 0); break;
            case 18: write(p.r, "x", 1); break;
            case 19: sendto(p.r, payload, 9217, 0, (struct sockaddr *)&to_other, sizeof to_other); break;
            case 20: sendto(p.r, (void *)1, 5, 0, (struct sockaddr *)&to_other, sizeof to_other); break;
            case 21: sendto(p.r, "x", 1, 0, (struct sockaddr *)&to_other, 15); break;
            case 22: { struct sockaddr_in bad = to_other; bad.sin_family = 99; sendto(p.r, "x", 1, 0, (struct sockaddr *)&bad, sizeof bad); break; }
            case 23: { struct sockaddr_in any = lo(portof(other)); any.sin_addr.s_addr = htonl(INADDR_ANY); sendto(p.r, "x", 1, 0, (struct sockaddr *)&any, sizeof any); break; }
            case 24: { struct sockaddr_in zero = lo(0); connect(p.r, (struct sockaddr *)&zero, sizeof zero); break; }
            case 25: sendto(9999, "x", 1, 0, (struct sockaddr *)&to_other, sizeof to_other); break;
            case 26: {
                struct sockaddr_in sa = lo(0);
                bind(p.s, (struct sockaddr *)&sa, sizeof sa);
                struct sockaddr_in ts = lo(portof(p.s));
                connect(p.r, (struct sockaddr *)&ts, sizeof ts);
                send(p.r, "", 0, 0);
                struct sockaddr un; memset(&un, 0, sizeof un); un.sa_family = AF_UNSPEC;
                connect(p.r, &un, sizeof un);
                break;
            }
            case 27: recv(p.r, buf, 0, MSG_DONTWAIT); break;
            default: break;
            }
            int arrived = send_from(sender, p, 4, &before, &after);
            struct rcvbuf b2, b3;
            int arrived2 = send_from(sender, p, 4, &b2, &b3);
            printf("2 %s: first datagram %s cc +%d mbcnt +%d; the next %s cc +%d mbcnt +%d\n", names[row],
                   arrived ? "arrived," : "did not arrive;", (int)(after.cc - before.cc), (int)(after.mbcnt - before.mbcnt),
                   arrived2 ? "arrived," : "did not arrive;", (int)(b3.cc - b2.cc), (int)(b3.mbcnt - b2.mbcnt));
            close(other);
            done(p);
        }
    }

    // 3: random mixtures: whether each datagram arrived, against the rule
    // "admitted exactly when cc + bytes <= hiwat and mbcnt + bytes <= mbmax",
    // where bytes is what the datagram adds to cc. Each trial stops at its
    // tenth drop.
    if (strchr(only, '3')) {
        for (int trial = 0; trial < 8; trial++) {
            srand(2000 + trial);
            struct pair p = fresh();
            int sent = 0, arrived = 0, drops = 0, broken = 0, takes = 0;
            int lastBytes = 32;
            while (drops < 10 && sent < 20000) {
                int choice = rand() % 10;
                if (choice == 0 && arrived > takes) {
                    take(p.r);
                    takes++;
                    continue;
                }
                int size = choice < 3 ? rand() % 160 : choice < 5 ? 257 + rand() % 160 : choice < 6 ? rand() % 9217 : rand() % 2100;
                struct rcvbuf before, after;
                int got = send1(p, size, &before, &after);
                sent++;
                // The bytes it would add: measured as size + 32 for any but a
                // fresh receiver's first datagram.
                int bytes = got ? (int)(after.cc - before.cc) : size + lastBytes - (lastBytes - 32);
                if (got) { lastBytes = bytes - size; arrived++; } else drops++;
                int predicted = before.cc + (uint32_t)bytes <= before.hiwat && before.mbcnt + (uint32_t)bytes <= before.mbmax;
                if (predicted != got) {
                    broken++;
                    if (broken <= 5)
                        printf("3 trial %d: a datagram of %d (adding %d) %s at cc %u/%u mbcnt %u/%u, against the rule\n", trial, size, bytes,
                               got ? "arrived" : "was dropped", before.cc, before.hiwat, before.mbcnt, before.mbmax);
                }
            }
            struct rcvbuf end = rcvbuf_of(p.port);
            printf("3 trial %d: sent %d, arrived %d, dropped %d, taken %d; arrivals against the rule %d; ended at cc %u mbcnt %u\n",
                   trial, sent, arrived, drops, takes, broken, end.cc, end.mbcnt);
            done(p);
        }
        // The reviewer's case: five of 9216, then 1737 of 257, from an
        // unbound sender.
        struct pair p = fresh();
        struct rcvbuf before, after;
        int arrived = 0;
        for (int k = 0; k < 5; k++) arrived += send1(p, 9216, &before, &after);
        for (int k = 0; k < 1737; k++) arrived += send1(p, 257, &before, &after);
        struct rcvbuf end = rcvbuf_of(p.port);
        printf("3 five of 9216 then 1737 of 257: %d arrived; cc %u mbcnt %u\n", arrived, end.cc, end.mbcnt);
        done(p);
    }
    return 0;
}
