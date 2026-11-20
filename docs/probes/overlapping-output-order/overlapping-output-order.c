// In which order getsockname(2), getpeername(2), accept(2), recvfrom(2) and
// getsockopt(2) store their two outputs -- the address (or option value) into
// the process's buffer, and the length into its socklen_t cell -- observed by
// making the two overlap, so that the store made second overwrites the bytes
// they share. getsockname and getpeername are measured on a connected IPv4
// TCP socket (a struct sockaddr_in, 16 bytes) and, as getsockname6 and
// getpeername6, on a dual-mode IPv6 one connected through a v4-mapped address
// (a struct sockaddr_in6, 28 bytes); accept and recvfrom on IPv4 TCP and UDP.
//
// Each row puts the cell at offset k from the start of the buffer (k < 0: the
// buffer starts inside the cell), declares the length D in the cell, makes the
// call, and prints the bytes around the buffer afterwards. Before the
// overlapping rows of a (call, D) pair, a control makes the same call with a
// separate buffer and cell, twice, over two different fill bytes: where each
// run's unbroken tail of fill begins bounds what the kernel stored (n bytes),
// and the cell gives the length it reported (L). Each overlapping row then
// predicts the region for both orders, from the fill, D in the cell, the n
// bytes the structure the kernel copies starts with (taken afresh for every
// call: for accept the connecting socket's own getsockname, for recvfrom the
// sender's) and L:
//
//   addr-first:   the n bytes at the buffer, then L at the cell
//   length-first: L at the cell, then the n bytes at the buffer
//
// ("addr-first" stands for the option value first, too) and says which one the
// observed bytes match: "addr-first", "length-first", "either" (the two
// predictions are the same bytes, so the row tells nothing: the two do not
// overlap, or share only bytes on which they agree) or "NEITHER" (printing
// both predictions). A control prints whether its stored bytes are the
// expected structure's first n bytes ("expected=yes"), which is what licenses
// predicting from that structure.
//
// Outputs beside this file, measured 2026-11-20; every control reads
// expected=yes, and no row reads NEITHER:
//
// * darwin-27.2.0-arm64.txt: natively (macOS 27.2.1),
//     cc -Wall -O1 -o /tmp/p overlapping-output-order.c && /tmp/p
//   Every row that tells the orders apart reads addr-first, for every call,
//   address family and option.
// * linux-6.18.5-aarch64.txt: Apple's `container` 1.4.1, gcc:14 image,
//     container run --rm -v "$PWD":/p -w /p gcc:14 sh -c
//       'cc -Wall -O1 -o /tmp/p overlapping-output-order.c && /tmp/p'
//   getsockname, getpeername (IPv4 and IPv6), accept and recvfrom read
//   length-first (their move_addr_to_user stores the length first from 6.18,
//   commit 1fb0e471611d);
//   getsockopt reads addr-first for SO_REUSEADDR, SO_ERROR and SO_LINGER, the
//   SOL_SOCKET options, and length-first for TCP_NODELAY and IPV6_V6ONLY.
// * linux-6.12.111-x86_64.txt, linux-6.17.13-x86_64.txt,
//   linux-6.18.5-x86_64.txt: Debian trixie's and trixie-backports'
//   linux-image-*-amd64, booted under full-system emulation with this probe
//   linked statically (`gcc -static`, built in `container --arch amd64` with
//   the gcc:14 image) as the initramfs's /init, which brings up the loopback
//   interface itself and powers off when done, as the sockname-fault-length
//   probe beside this one was run:
//     qemu-system-x86_64 -m 1G -cpu max -kernel vmlinuz -initrd init.cpio.gz \
//       -append "console=ttyS0 panic=-1 quiet" -nographic -no-reboot
//   The console's firmware and kernel-log lines are removed. 6.18.5 reads as
//   it does on aarch64. 6.12.111 and 6.17.13 read addr-first for getsockname,
//   getpeername (IPv4 and IPv6), accept and recvfrom, and getsockopt reads as
//   it does on 6.18.5.
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <sys/reboot.h>
#endif
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#define REGION 160
// Where the buffer starts in the region; the cell is at BUF + k.
#define BUF 8
// The region printed: from SHOW_FROM, SHOW bytes.
#define SHOW_FROM 4
#define SHOW 40
#define KMIN (-3)
#define KMAX 30

// The calls go through syscall(2) with the buffer and the cell as plain byte
// addresses: the cell is often misaligned for a socklen_t, and libc declares
// the two output pointers of these calls restrict, so neither may reach libc's
// own declarations. Darwin deprecates syscall(2), which still makes the call.
#ifdef __APPLE__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

static void lo_up(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP;
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
}

static void die(const char *what) {
    perror(what);
    exit(1);
}

// One kind of call. `make` makes the call through `buf` and `cell`, and
// writes into `expect` (up to 128 bytes) the whole structure the kernel copies
// out for this very call, read through a separate, ample buffer.
struct call {
    const char *name;
    int (*make)(struct call *self, void *buf, void *cell, unsigned char *expect);
    int fd;      // the socket the call is made on
    int peer;    // accept: the listener's address is in `addr`; recvfrom: the sender
    int level;   // getsockopt
    int option;  // getsockopt
    struct sockaddr_in addr;
};

static int answer(long r) { return r < 0 ? -1 : 0; }

static int make_getsockname(struct call *self, void *buf, void *cell, unsigned char *expect) {
    unsigned char big[128];
    socklen_t bl = sizeof big;
    if (getsockname(self->fd, (struct sockaddr *)big, &bl) != 0) die("getsockname expect");
    memcpy(expect, big, sizeof big);
    return answer(syscall(SYS_getsockname, self->fd, buf, cell));
}

static int make_getpeername(struct call *self, void *buf, void *cell, unsigned char *expect) {
    unsigned char big[128];
    socklen_t bl = sizeof big;
    if (getpeername(self->fd, (struct sockaddr *)big, &bl) != 0) die("getpeername expect");
    memcpy(expect, big, sizeof big);
    return answer(syscall(SYS_getpeername, self->fd, buf, cell));
}

static int make_accept(struct call *self, void *buf, void *cell, unsigned char *expect) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&self->addr, sizeof self->addr) != 0) die("connect");
    unsigned char big[128];
    memset(big, 0, sizeof big);
    socklen_t bl = sizeof big;
    if (getsockname(c, (struct sockaddr *)big, &bl) != 0) die("getsockname client");
    memcpy(expect, big, sizeof big);
    int a = (int)syscall(SYS_accept, self->fd, buf, cell);
    int e = errno;
    if (a >= 0) close(a);
    close(c);
    errno = e;
    return a >= 0 ? 0 : -1;
}

static int make_recvfrom(struct call *self, void *buf, void *cell, unsigned char *expect) {
    unsigned char big[128];
    memset(big, 0, sizeof big);
    socklen_t bl = sizeof big;
    if (getsockname(self->peer, (struct sockaddr *)big, &bl) != 0) die("getsockname sender");
    memcpy(expect, big, sizeof big);
    if (sendto(self->peer, "x", 1, 0, (struct sockaddr *)&self->addr, sizeof self->addr) != 1) die("sendto");
    char data[16];
    long r = syscall(SYS_recvfrom, self->fd, data, sizeof data, 0, buf, cell);
    return r == 1 ? 0 : -1;
}

static int make_getsockopt(struct call *self, void *buf, void *cell, unsigned char *expect) {
    unsigned char big[128];
    memset(big, 0, sizeof big);
    socklen_t bl = sizeof big;
    if (getsockopt(self->fd, self->level, self->option, big, &bl) != 0) die("getsockopt expect");
    memcpy(expect, big, sizeof big);
    return answer(syscall(SYS_getsockopt, self->fd, self->level, self->option, buf, cell));
}

static void hex(const unsigned char *p, int n) {
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
}

static void put_cell(unsigned char *at, socklen_t v) { memcpy(at, &v, sizeof v); }

// The control for (call, D): n, the bytes stored, and L, the length reported.
// Answers 0, or -1 if the call failed or stored other than the expected
// structure's first n bytes.
static int control(struct call *c, int declared, int *n_out, socklen_t *l_out) {
    unsigned char run[2][REGION];
    unsigned char expect[2][128];
    socklen_t cell[2];
    int r[2], e[2];
    const unsigned char fill[2] = { 0xaa, 0x55 };
    for (int i = 0; i < 2; i++) {
        memset(run[i], fill[i], REGION);
        cell[i] = (socklen_t)declared;
        errno = 0;
        r[i] = c->make(c, run[i], &cell[i], expect[i]);
        e[i] = r[i] == 0 ? 0 : errno;
    }
    // Each run's stores end where its unbroken tail of fill begins; a stored
    // byte can equal at most one of the two fills, so the later end is the
    // count stored. (The two runs need not store the same bytes: each accept
    // takes a new connection, from a new port.)
    int end[2];
    for (int i = 0; i < 2; i++) {
        end[i] = REGION;
        while (end[i] > 0 && run[i][end[i] - 1] == fill[i]) end[i]--;
    }
    int n = end[0] > end[1] ? end[0] : end[1];
    int expected = memcmp(run[0], expect[0], n) == 0 && memcmp(run[1], expect[1], n) == 0;
    printf("%-13s D=%-3d control  r=%d,%d errno=%d,%d n=%d L=%u,%u expected=%s stored=",
           c->name, declared, r[0], r[1], e[0], e[1], n, cell[0], cell[1],
           expected ? "yes" : "no");
    hex(run[0], n);
    printf("\n");
    *n_out = n;
    *l_out = cell[0];
    return r[0] == 0 && r[1] == 0 && expected && cell[0] == cell[1] ? 0 : -1;
}

static void overlapping(struct call *c, int declared, int n, socklen_t l, int k) {
    unsigned char region[REGION], before[REGION], al[REGION], la[REGION], expect[128];
    memset(region, 0xaa, REGION);
    unsigned char *buf = region + BUF;
    unsigned char *cellp = region + BUF + k;
    put_cell(cellp, (socklen_t)declared);
    memcpy(before, region, REGION);
    errno = 0;
    int r = c->make(c, buf, cellp, expect);
    int e = r == 0 ? 0 : errno;

    memcpy(al, before, REGION);
    memcpy(al + BUF, expect, n);
    put_cell(al + BUF + k, l);
    memcpy(la, before, REGION);
    put_cell(la + BUF + k, l);
    memcpy(la + BUF, expect, n);

    const char *verdict;
    int same = memcmp(al, la, REGION) == 0;
    if (r != 0) verdict = "FAILED";
    else if (memcmp(region, al, REGION) == 0) verdict = same ? "either" : "addr-first";
    else if (memcmp(region, la, REGION) == 0) verdict = "length-first";
    else verdict = "NEITHER";
    printf("%-13s D=%-3d k=%-3d r=%d errno=%d %-12s ", c->name, declared, k, r, e, verdict);
    hex(region + SHOW_FROM, SHOW);
    if (verdict[0] == 'N') {
        printf(" addr-first=");
        hex(al + SHOW_FROM, SHOW);
        printf(" length-first=");
        hex(la + SHOW_FROM, SHOW);
    }
    printf("\n");
}

static void sweep(struct call *c, const int *declared, int count) {
    for (int i = 0; i < count; i++) {
        int n;
        socklen_t l;
        if (control(c, declared[i], &n, &l) != 0) continue;
        for (int k = KMIN; k <= KMAX; k++) overlapping(c, declared[i], n, l, k);
    }
}

int main(void) {
    struct utsname u;
    uname(&u);
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);
    printf("buffer at region+%d, cell at buffer+k, fill aa; bytes shown are region[%d..%d)\n",
           BUF, SHOW_FROM, SHOW_FROM + SHOW);
    lo_up();

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int l = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(l, (struct sockaddr *)&a, sizeof a) != 0) die("bind");
    if (listen(l, 64) != 0) die("listen");
    struct sockaddr_in la;
    socklen_t lal = sizeof la;
    getsockname(l, (struct sockaddr *)&la, &lal);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(c, (struct sockaddr *)&la, sizeof la) != 0) die("connect");
    // Taken off the queue, so that each accept below takes its own connection.
    int cs = accept(l, NULL, NULL);
    if (cs < 0) die("accept");

    int ur = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(ur, (struct sockaddr *)&a, sizeof a) != 0) die("bind udp");
    struct sockaddr_in ura;
    socklen_t ural = sizeof ura;
    getsockname(ur, (struct sockaddr *)&ura, &ural);
    int us = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(us, (struct sockaddr *)&a, sizeof a) != 0) die("bind udp sender");

    const int addr_lengths[] = { 6, 10, 16, 128 };
    const int nal = sizeof addr_lengths / sizeof addr_lengths[0];

    struct call gsn = { .name = "getsockname", .make = make_getsockname, .fd = c };
    struct call gpn = { .name = "getpeername", .make = make_getpeername, .fd = c };
    struct call acc = { .name = "accept", .make = make_accept, .fd = l, .addr = la };
    struct call rcv = { .name = "recvfrom", .make = make_recvfrom, .fd = ur, .peer = us, .addr = ura };
    sweep(&gsn, addr_lengths, nal);
    sweep(&gpn, addr_lengths, nal);
    sweep(&acc, addr_lengths, nal);
    sweep(&rcv, addr_lengths, nal);

    // A dual-mode IPv6 stream socket connected to the IPv4 listener through
    // its v4-mapped address, whose names are a 28-byte struct sockaddr_in6.
    int zero = 0;
    int c6 = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 mapped;
    memset(&mapped, 0, sizeof mapped);
#ifdef __APPLE__
    mapped.sin6_len = sizeof mapped;
#endif
    mapped.sin6_family = AF_INET6;
    mapped.sin6_port = la.sin_port;
    mapped.sin6_addr.s6_addr[10] = 0xff;
    mapped.sin6_addr.s6_addr[11] = 0xff;
    memcpy(&mapped.sin6_addr.s6_addr[12], &la.sin_addr, 4);
    if (c6 < 0 || setsockopt(c6, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero) != 0
        || connect(c6, (struct sockaddr *)&mapped, sizeof mapped) != 0) {
        perror("dual-mode connect: the IPv6 getsockname and getpeername rows are skipped");
    } else {
        int cs6 = accept(l, NULL, NULL);
        if (cs6 < 0) die("accept dual-mode");
        const int addr6_lengths[] = { 10, 20, 26, 28, 128 };
        struct call gsn6 = { .name = "getsockname6", .make = make_getsockname, .fd = c6 };
        struct call gpn6 = { .name = "getpeername6", .make = make_getpeername, .fd = c6 };
        sweep(&gsn6, addr6_lengths, sizeof addr6_lengths / sizeof addr6_lengths[0]);
        sweep(&gpn6, addr6_lengths, sizeof addr6_lengths / sizeof addr6_lengths[0]);
    }

    // Options, on unconnected sockets, set to values whose bytes differ from
    // the lengths stored beside them.
    int t = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) die("SO_REUSEADDR");
    if (setsockopt(t, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one) != 0) die("TCP_NODELAY");
    struct linger lg = { .l_onoff = 1, .l_linger = 0x1234 };
    if (setsockopt(t, SOL_SOCKET, SO_LINGER, &lg, sizeof lg) != 0) die("SO_LINGER");
    int t6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (t6 < 0) perror("socket AF_INET6: IPV6_V6ONLY's rows are skipped");
    else if (setsockopt(t6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) != 0) die("IPV6_V6ONLY");

    const int int_lengths[] = { 2, 4, 64 };
    const int linger_lengths[] = { 4, 6, 8, 64 };
    struct call opts[] = {
        { .name = "SO_REUSEADDR", .make = make_getsockopt, .fd = t, .level = SOL_SOCKET, .option = SO_REUSEADDR },
        { .name = "SO_ERROR", .make = make_getsockopt, .fd = t, .level = SOL_SOCKET, .option = SO_ERROR },
        { .name = "SO_LINGER", .make = make_getsockopt, .fd = t, .level = SOL_SOCKET, .option = SO_LINGER },
#ifdef SO_LINGER_SEC
        { .name = "SO_LINGER_SEC", .make = make_getsockopt, .fd = t, .level = SOL_SOCKET, .option = SO_LINGER_SEC },
#endif
        { .name = "TCP_NODELAY", .make = make_getsockopt, .fd = t, .level = IPPROTO_TCP, .option = TCP_NODELAY },
        { .name = "IPV6_V6ONLY", .make = make_getsockopt, .fd = t6, .level = IPPROTO_IPV6, .option = IPV6_V6ONLY },
    };
    for (unsigned i = 0; i < sizeof opts / sizeof opts[0]; i++) {
        if (opts[i].fd < 0) continue;
        int linger = opts[i].level == SOL_SOCKET && (opts[i].option == SO_LINGER
#ifdef SO_LINGER_SEC
            || opts[i].option == SO_LINGER_SEC
#endif
            );
        if (linger) sweep(&opts[i], linger_lengths, sizeof linger_lengths / sizeof linger_lengths[0]);
        else sweep(&opts[i], int_lengths, sizeof int_lengths / sizeof int_lengths[0]);
    }

    fflush(stdout);
#ifdef __linux__
    if (getpid() == 1) reboot(RB_POWER_OFF);
#endif
    return 0;
}
