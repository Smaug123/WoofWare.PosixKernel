// When accept(2) reads the caller's length cell, what it answers when the
// cell cannot be read, and whether the connection survives that answer.
//
// The cell is given as
//   null       a NULL pointer
//   unmapped   the address of a page mapped PROT_NONE, which faults on any access
//   N          real storage holding the int N
// and the address buffer as
//   null       a NULL pointer
//   unmapped   the same PROT_NONE page
//   mapped     128 bytes of real storage
// Each row prints the answer, the cell afterwards (for real storage; "-"
// otherwise), how many bytes of a mapped buffer the call overwrote (the buffer
// filled with a byte that appears nowhere in the address the call could copy,
// the connecting socket's, which is known before the call), and,
// for a fixture with a connection queued, `client=` what the connecting socket
// sees within 200 ms of the call, `none`, `eof` (a read answers 0) or an errno
// name from the read, and then `queued=` whether a second, non-blocking accept
// with NULL pointers still finds the connection. A call that succeeds closes
// the descriptor it made at once, so its client sees `eof`.
//
// Sections:
//   A  a call that cannot sleep, on: a closed descriptor, a pipe, an idle
//      stream socket (EINVAL), a datagram socket (EOPNOTSUPP), an empty
//      non-blocking listener (EAGAIN), a non-blocking and a blocking listener
//      with one connection queued, a Unix-domain stream listener (empty and
//      non-blocking), a Unix-domain datagram socket, a Unix-domain seqpacket
//      listener (empty and non-blocking; Linux alone has one), an IPv6 stream
//      listener (empty and non-blocking) and an IPv6 datagram socket; on Linux
//      also accept4 with an unknown flag bit (EINVAL) on a listener with one
//      connection queued.
//   B  a blocking listener with nothing queued, through a NULL or unmapped
//      cell and a NULL or mapped buffer, and a thread that connects once the
//      call is asleep in accept, or once it has returned: the answer, whether
//      the call slept (`slept=`), and the connection's fate as in A.
//   C  a blocking accept into a mapped buffer through a cell holding 16, asleep
//      on an empty listener, whose cell another thread changes to 4, 0 or -1
//      once the call is asleep in accept, and then connects: which value the
//      call used.
// A thread is asleep in accept when, on Linux, /proc/self/task/<tid>/stat
// says S and .../syscall names accept or accept4, and on Darwin when
// thread_info says TH_STATE_WAITING.
//
// The probe exits 1 if a fixture cannot be built; if a state it waits for (a
// queued connection, a sleeping call or a returned one) does not arrive
// within two seconds; or if a call that slept returned before the other
// thread acted.
//
// Outputs beside this file, measured 2026-11-21:
//
// * darwin-27.2.0-arm64.txt: natively, from this directory,
//     cc -Wall -O1 -pthread -o /tmp/p accept-length-cell.c && /tmp/p
// * linux-6.18.5-aarch64.txt: Apple's `container`, gcc:14 image, from this
//   directory,
//     container run --rm -v "$PWD:/probe" gcc:14 sh -c 'cc -Wall -O1 -pthread -o /tmp/p /probe/accept-length-cell.c && /tmp/p'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#endif

static const char *en(int e) {
    switch (e) {
    case 0: return "OK";
    case EBADF: return "EBADF";
    case ENOTSOCK: return "ENOTSOCK";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case EAGAIN: return "EAGAIN";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case ECONNRESET: return "ECONNRESET";
    case ECONNABORTED: return "ECONNABORTED";
    default: { static char b[32]; snprintf(b, sizeof b, "errno%d", e); return b; }
    }
}

static void need(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "setup failed: %s (errno %d)\n", what, errno);
        exit(1);
    }
}

static void *faulting;

static struct sockaddr_in loopback(unsigned short port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
#ifdef __APPLE__
    a.sin_len = sizeof a;
#endif
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    return a;
}

static unsigned short port_of(int fd) {
    struct sockaddr_in a;
    socklen_t l = sizeof a;
    memset(&a, 0, sizeof a);
    need(getsockname(fd, (struct sockaddr *)&a, &l) == 0, "getsockname for a port");
    need(a.sin_port != 0, "a bound port");
    return ntohs(a.sin_port);
}

static void set_nonblocking(int fd, int on) {
    int f = fcntl(fd, F_GETFL);
    need(f >= 0, "F_GETFL");
    need(fcntl(fd, F_SETFL, on ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK)) == 0, "F_SETFL");
}

static int listener(int nonblocking) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    need(l >= 0, "socket for a listener");
    struct sockaddr_in a = loopback(0);
    need(bind(l, (struct sockaddr *)&a, sizeof a) == 0, "bind a listener");
    need(listen(l, 4) == 0, "listen");
    if (nonblocking) set_nonblocking(l, 1);
    return l;
}

// A client connected to `l`, its connection queued once `l` polls readable.
static int connect_to(int l) {
    int c = socket(AF_INET, SOCK_STREAM, 0);
    need(c >= 0, "socket for a client");
    struct sockaddr_in a = loopback(port_of(l));
    need(connect(c, (struct sockaddr *)&a, sizeof a) == 0, "connect a client");
    struct pollfd p = { l, POLLIN, 0 };
    need(poll(&p, 1, 2000) == 1, "the connection queued at the listener");
    return c;
}

// What the client sees within 200 ms.
static const char *client_view(int c) {
    struct pollfd p = { c, POLLIN, 0 };
    if (poll(&p, 1, 200) == 0) return "none";
    char b;
    ssize_t n = recv(c, &b, 1, MSG_DONTWAIT);
    if (n == 0) return "eof";
    if (n > 0) return "data";
    return en(errno);
}

// A byte that appears nowhere in the address an accept of the client `c`
// could copy out, which is `c`'s own, as getsockname reports it.
static unsigned char fill_for(int c) {
    unsigned char seen[256] = { 0 };
    if (c >= 0) {
        unsigned char a[128];
        socklen_t l = sizeof a;
        memset(a, 0, sizeof a);
        need(getsockname(c, (struct sockaddr *)a, &l) == 0, "getsockname of the client");
        for (socklen_t i = 0; i < l && i < sizeof a; i++) seen[a[i]] = 1;
    }
    static const unsigned char candidates[] = { 0xAA, 0x55, 0x33, 0xCC, 0x5A, 0xA5 };
    for (unsigned i = 0; i < sizeof candidates; i++) if (!seen[candidates[i]]) return candidates[i];
    need(0, "a fill byte absent from the client's address");
    return 0;
}

static int written_of(const unsigned char *buf, unsigned char fill) {
    int written = 0;
    for (int i = 0; i < 128; i++) if (buf[i] != fill) written++;
    return written;
}

enum kind { NUL, UNMAPPED, HOLDS };

static void *pointer(enum kind k, void *storage) {
    return k == NUL ? NULL : k == UNMAPPED ? faulting : storage;
}

static void name(char *out, size_t size, enum kind k, int held, int is_cell) {
    if (k == NUL) snprintf(out, size, "null");
    else if (k == UNMAPPED) snprintf(out, size, "unmapped");
    else if (is_cell) snprintf(out, size, "%d", held);
    else snprintf(out, size, "mapped");
}

// The fixtures of section A, each built afresh for each call.
enum fixture { CLOSED, PIPE, IDLE, DGRAM, EMPTY, QUEUED, QUEUED_BLOCKING, UNIX_STREAM, UNIX_DGRAM, UNIX_SEQPACKET, INET6_STREAM, INET6_DGRAM, BADFLAGS };
static const char *fixture_names[] = { "closed", "pipe", "tcp-idle", "udp", "listener-empty", "listener-queued", "listener-queued-blocking", "unix-stream-listener", "unix-dgram", "unix-seqpacket-listener", "inet6-stream-listener", "inet6-dgram", "accept4-bad-flags" };

// A socket of `domain` and `type`, non-blocking, and listening if `listens`:
// a Unix-domain one bound to a fresh path, an IPv6 one to the loopback.
static int other_family(int domain, int type, int listens) {
    int fd = socket(domain, type, 0);
    need(fd >= 0, "socket of another family");
    if (domain == AF_UNIX) {
        static int serial = 0;
        struct sockaddr_un a;
        memset(&a, 0, sizeof a);
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof a.sun_path, "/tmp/alc-%d-%d", (int)getpid(), serial++);
        unlink(a.sun_path);
        need(bind(fd, (struct sockaddr *)&a, sizeof a) == 0, "bind a Unix-domain socket");
        unlink(a.sun_path);
    } else {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
#ifdef __APPLE__
        a.sin6_len = sizeof a;
#endif
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_loopback;
        need(bind(fd, (struct sockaddr *)&a, sizeof a) == 0, "bind an IPv6 socket");
    }
    if (listens) need(listen(fd, 4) == 0, "listen on another family");
    set_nonblocking(fd, 1);
    return fd;
}

struct built { int fd; int client; int extra; };

static struct built build(enum fixture f) {
    struct built b = { -1, -1, -1 };
    switch (f) {
    case CLOSED:
        b.fd = socket(AF_INET, SOCK_STREAM, 0);
        need(b.fd >= 0, "socket");
        close(b.fd);
        break;
    case PIPE: {
        int p[2];
        need(pipe(p) == 0, "pipe");
        b.fd = p[0];
        b.extra = p[1];
        break;
    }
    case IDLE:
        b.fd = socket(AF_INET, SOCK_STREAM, 0);
        need(b.fd >= 0, "socket");
        set_nonblocking(b.fd, 1);
        break;
    case DGRAM:
        b.fd = socket(AF_INET, SOCK_DGRAM, 0);
        need(b.fd >= 0, "socket");
        set_nonblocking(b.fd, 1);
        break;
    case EMPTY:
        b.fd = listener(1);
        break;
    case QUEUED:
    case BADFLAGS:
        b.fd = listener(1);
        b.client = connect_to(b.fd);
        break;
    case QUEUED_BLOCKING:
        b.fd = listener(0);
        b.client = connect_to(b.fd);
        break;
    case UNIX_STREAM: b.fd = other_family(AF_UNIX, SOCK_STREAM, 1); break;
    case UNIX_DGRAM: b.fd = other_family(AF_UNIX, SOCK_DGRAM, 0); break;
    case UNIX_SEQPACKET: b.fd = other_family(AF_UNIX, SOCK_SEQPACKET, 1); break;
    case INET6_STREAM: b.fd = other_family(AF_INET6, SOCK_STREAM, 1); break;
    case INET6_DGRAM: b.fd = other_family(AF_INET6, SOCK_DGRAM, 0); break;
    }
    return b;
}

static void tear(struct built b) {
    if (b.fd >= 0) close(b.fd);
    if (b.client >= 0) close(b.client);
    if (b.extra >= 0) close(b.extra);
}

static int call(enum fixture f, int fd, void *dest, socklen_t *cell) {
    errno = 0;
    int r;
#ifdef __linux__
    if (f == BADFLAGS) r = accept4(fd, (struct sockaddr *)dest, cell, 1);
    else
#endif
    r = accept(fd, (struct sockaddr *)dest, cell);
    if (r >= 0) {
        close(r);
        return 0;
    }
    return errno;
}

static void row_a(enum fixture f, enum kind ck, int held, enum kind dk) {
    unsigned char buf[128];
    struct built b = build(f);
    unsigned char fill = fill_for(b.client);
    memset(buf, fill, sizeof buf);
    int cell = held;
    int e = call(f, b.fd, pointer(dk, buf), (socklen_t *)pointer(ck, &cell));
    const char *queued = NULL, *client = NULL;
    if (b.client >= 0) {
        client = client_view(b.client);
        set_nonblocking(b.fd, 1);
        int again = accept(b.fd, NULL, NULL);
        queued = again >= 0 ? "yes" : (errno == EAGAIN ? "no" : en(errno));
        if (again >= 0) close(again);
    }
    tear(b);
    char cn[32], dn[32];
    name(cn, sizeof cn, ck, held, 1);
    name(dn, sizeof dn, dk, 0, 0);
    printf("A %s cell=%s dest=%s -> %s", fixture_names[f], cn, dn, en(e));
    if (ck == HOLDS) printf(" cellafter=%d", cell); else printf(" cellafter=-");
    printf(" written=%d", dk == HOLDS ? written_of(buf, fill) : 0);
    if (queued) printf(" queued=%s client=%s", queued, client);
    printf("\n");
}

static long now_ms(void) {
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec * 1000L + t.tv_usec / 1000;
}

// The thread that makes the accept, and whether it is asleep in it.
#ifdef __APPLE__
static mach_port_t accepter;
static void note_accepter(void) { accepter = pthread_mach_thread_np(pthread_self()); }
static int accepter_asleep(void) {
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (thread_info(accepter, THREAD_BASIC_INFO, (thread_info_t)&info, &count) != KERN_SUCCESS) return 0;
    return info.run_state == TH_STATE_WAITING;
}
#else
static pid_t accepter;
static void note_accepter(void) { accepter = (pid_t)syscall(SYS_gettid); }
static int read_file(const char *path, char *buf, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, n - 1, f);
    fclose(f);
    buf[got] = 0;
    return (int)got;
}
static int accepter_asleep(void) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", (int)accepter);
    if (read_file(path, buf, sizeof buf) < 0) return 0;
    char *close_paren = strrchr(buf, ')');
    if (!close_paren || close_paren[1] != ' ' || close_paren[2] != 'S') return 0;
    snprintf(path, sizeof path, "/proc/self/task/%d/syscall", (int)accepter);
    if (read_file(path, buf, sizeof buf) < 0) return 0;
    long nr = strtol(buf, NULL, 10);
#ifdef SYS_accept
    if (nr == SYS_accept) return 1;
#endif
    return nr == SYS_accept4;
}
#endif

// A thread that waits until the accept is asleep in the kernel, or has
// returned, then writes `new_cell` to the cell (if `cell` is not NULL) and
// connects `client`, which is bound already, to the listener.
struct connector {
    int listener;
    int client;
    int *cell;
    int new_cell;
    volatile int returned;
    int saw_asleep;
    long acted;
};

static void *connector_main(void *arg) {
    struct connector *c = arg;
    int waited = 0;
    while (!c->returned && !accepter_asleep()) {
        need(waited < 2000, "the accept asleep, or returned");
        usleep(1000);
        waited++;
    }
    c->saw_asleep = !c->returned;
    c->acted = now_ms();
    if (c->cell) *c->cell = c->new_cell;
    struct sockaddr_in a = loopback(port_of(c->listener));
    need(connect(c->client, (struct sockaddr *)&a, sizeof a) == 0, "connect a client");
    return NULL;
}

// One blocking accept on an empty listener through the cell `ck` (holding 16
// where it is storage) and the buffer `dk`, and a thread acting as
// `connector_main` says, changing the cell to `new_cell` if `change`.
static void sleeper(enum kind ck, enum kind dk, int change, int new_cell) {
    int l = listener(0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    need(client >= 0, "socket for a client");
    struct sockaddr_in any = loopback(0);
    need(bind(client, (struct sockaddr *)&any, sizeof any) == 0, "bind the client");
    unsigned char buf[128];
    unsigned char fill = fill_for(client);
    memset(buf, fill, sizeof buf);
    int cell = 16;
    struct connector c = { l, client, change ? &cell : NULL, new_cell, 0, 0, 0 };
    note_accepter();
    pthread_t t;
    need(pthread_create(&t, NULL, connector_main, &c) == 0, "pthread_create");
    int e = call(QUEUED, l, pointer(dk, buf), (socklen_t *)pointer(ck, &cell));
    long returned = now_ms();
    c.returned = 1;
    pthread_join(t, NULL);
    if (c.saw_asleep) need(returned >= c.acted, "a call that slept returning after the thread acted");
    const char *seen = client_view(client);
    set_nonblocking(l, 1);
    int again = accept(l, NULL, NULL);
    const char *queued = again >= 0 ? "yes" : (errno == EAGAIN ? "no" : en(errno));
    if (again >= 0) close(again);
    char cn[32], dn[32];
    name(cn, sizeof cn, ck, 16, 1);
    name(dn, sizeof dn, dk, 0, 0);
    if (change)
        printf("C cell=16 changed-to=%d dest=mapped -> %s slept=%s cellafter=%d written=%d queued=%s client=%s\n",
               new_cell, en(e), c.saw_asleep ? "yes" : "no", cell, written_of(buf, fill), queued, seen);
    else
        printf("B blocking-empty cell=%s dest=%s -> %s slept=%s written=%d queued=%s client=%s\n", cn, dn, en(e),
               c.saw_asleep ? "yes" : "no", dk == HOLDS ? written_of(buf, fill) : 0, queued, seen);
    close(client);
    close(l);
}

static void row_b(enum kind ck, enum kind dk) { sleeper(ck, dk, 0, 0); }

static void row_c(int new_cell) { sleeper(HOLDS, HOLDS, 1, new_cell); }

int main(void) {
    struct utsname u;
    uname(&u);
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);

    // Kept mapped, and so never reused, for the whole run.
    faulting = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    need(faulting != MAP_FAILED, "mmap a PROT_NONE page");

    enum fixture fixtures[] = { CLOSED, PIPE, IDLE, DGRAM, EMPTY, QUEUED, QUEUED_BLOCKING, UNIX_STREAM, UNIX_DGRAM,
#ifdef __linux__
                                UNIX_SEQPACKET,
#endif
                                INET6_STREAM, INET6_DGRAM
#ifdef __linux__
                                , BADFLAGS
#endif
    };
    enum kind dests[] = { NUL, UNMAPPED, HOLDS };
    int helds[] = { 16, 0, -1 };
    for (unsigned f = 0; f < sizeof fixtures / sizeof fixtures[0]; f++) {
        for (unsigned d = 0; d < 3; d++) {
            row_a(fixtures[f], NUL, 0, dests[d]);
            row_a(fixtures[f], UNMAPPED, 0, dests[d]);
            for (unsigned h = 0; h < 3; h++) row_a(fixtures[f], HOLDS, helds[h], dests[d]);
        }
    }

    enum kind cells[] = { NUL, UNMAPPED };
    enum kind bdests[] = { NUL, HOLDS };
    for (unsigned i = 0; i < 2; i++)
        for (unsigned d = 0; d < 2; d++) row_b(cells[i], bdests[d]);

    int changes[] = { 4, 0, -1 };
    for (unsigned i = 0; i < 3; i++) row_c(changes[i]);
    return 0;
}
