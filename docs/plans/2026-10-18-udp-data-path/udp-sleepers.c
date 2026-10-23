// Whom each wake reaches when threads sleep in a receive on one IPv4 UDP
// socket, on both flavours, and what each receiving call answers once woken.
// Plan: docs/plans/2026-10-18-udp-data-path.md, section 2.16.
//
// Build and run:
//   Darwin: cc -Wall -O0 -pthread -o /tmp/us udp-sleepers.c && /tmp/us
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c
//             'gcc -Wall -O0 -pthread -o /tmp/us /probe/udp-sleepers.c && /tmp/us'
//
// Each row parks its sleepers 50 ms apart, in the order listed, each in its
// own thread and its own blocking call, then makes its events one at a time,
// 100 ms apart, and after each prints every sleeper: the answer of one that
// has returned, with the order it returned in, or "asleep". On Linux each
// sleeper also shows how many times it has gone to sleep since the last one
// parked (`voluntary_ctxt_switches` in /proc), so a sleeper that was woken
// and slept again shows +1 where one never woken shows +0. Once the events
// are done, a SIGUSR1 (a handler, no SA_RESTART) ends every sleeper still
// asleep, and the row prints what each answered then, what the socket still
// holds, and its SO_ERROR.
//
// Events:
//   datagram   a datagram "one" (then "two", ...) from another socket
//   two        two datagrams, back to back, from another socket
//   error      a send through the sleepers' socket, which is connected to a
//              port nobody holds, so that the ICMP error comes back to it
//   peer       a datagram from a socket bound to the port the sleepers'
//              socket is connected to, which it accepts
//   close      a close of the descriptor sleepers marked "fd" sleep through
//   park       park the next sleeper marked "late"
//   nothing    no event: whether anything returns on its own
//
// Sleepers ("kind@descriptor"; the descriptor is "fd", or "dup", a dup of it,
// or "latedup", the dup again for a sleeper that parks only at a "park"
// event):
//   take       recv of 16 bytes
//   peek       recv of 16 bytes with MSG_PEEK
//   zero       recv of 0 bytes
//   read       read of 16 bytes
//   readzero   read of 0 bytes
//   waitall    recv of 16 bytes with MSG_WAITALL
//   badbuf     recv of 16 bytes into an address nothing maps
//   from       recvfrom of 16 bytes, its length cell holding 16; prints the
//              cell after, and the source's port as "self" (the sender's
//              port) or the number
//   fromtrunc  recvfrom of 2 bytes with MSG_TRUNC, the cell holding 16
//   cellnull   recvfrom with a source buffer and a NULL length cell
//   cellbad    recvfrom with a source buffer and a length cell nothing maps
//   cellneg    recvfrom with its length cell holding -1
//   addrbad    recvfrom with a source buffer nothing maps, the cell holding 16
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef __APPLE__
#include <sys/syscall.h>
#endif

// An address nothing maps, hidden from the compiler's own checks.
static void *volatile unmapped = (void *)1;

static const char *ename(int e)
{
    switch (e) {
    case EAGAIN: return "EAGAIN";
    case EINVAL: return "EINVAL";
    case ECONNREFUSED: return "ECONNREFUSED";
    case EFAULT: return "EFAULT";
    case ENOTCONN: return "ENOTCONN";
    case EBADF: return "EBADF";
    case EINTR: return "EINTR";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    case 0: return "0";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static struct sockaddr_in lo(uint16_t port)
{
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

static uint16_t portof(int s)
{
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    if (getsockname(s, (struct sockaddr *)&a, &len) != 0) return 0;
    return ntohs(a.sin_port);
}

static int bound_at(uint16_t port)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = lo(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { perror("bind"); exit(1); }
    return s;
}

static int bound(void) { return bound_at(0); }

static uint16_t unheld_port(void)
{
    int s = bound();
    uint16_t p = portof(s);
    close(s);
    return p;
}

static int sock_error(int s)
{
    int v = -1;
    socklen_t len = sizeof v;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, &v, &len) != 0) return -errno;
    return v;
}

// Every datagram the socket holds now, as text: "one|two", or "none".
static const char *drain_text(int s)
{
    static char out[512];
    char buf[64];
    out[0] = 0;
    int count = 0;
    for (;;) {
        ssize_t r = recv(s, buf, sizeof buf - 1, MSG_DONTWAIT);
        if (r < 0) {
            if (errno == EAGAIN) break;
            size_t used = strlen(out);
            snprintf(out + used, sizeof out - used, "%s%s", count ? "|" : "", ename(errno));
            count++;
            if (errno == ECONNREFUSED) continue;
            break;
        }
        buf[r] = 0;
        size_t used = strlen(out);
        snprintf(out + used, sizeof out - used, "%s%s", count ? "|" : "", buf);
        count++;
    }
    return count ? out : "none";
}

#ifndef __APPLE__
static long sleeps_of(pid_t tid)
{
    char path[64], line[128];
    snprintf(path, sizeof path, "/proc/self/task/%d/status", (int)tid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long v = -1;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "voluntary_ctxt_switches: %ld", &v) == 1) break;
    fclose(f);
    return v;
}
#endif

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int returned_count = 0;
static uint16_t sender_port = 0;

struct sleeper {
    const char *kind;
    int fd;
    volatile int started;
#ifndef __APPLE__
    pid_t tid;
    long base;
#endif
    // Written by the sleeper before it takes the lock and sets `order`.
    ssize_t ret;
    int err;
    char text[24];
    struct sockaddr_in source;
    socklen_t cell;
    int order; // 0 while asleep, else 1 + how many returned before it
};

static void *sleep_in(void *p)
{
    struct sleeper *s = p;
    char buf[16];
    memset(buf, 0, sizeof buf);
    memset(&s->source, 0, sizeof s->source);
#ifndef __APPLE__
    s->tid = (pid_t)syscall(SYS_gettid);
#endif
    s->started = 1;
    ssize_t r;
    const char *k = s->kind;
    if (!strcmp(k, "take")) r = recv(s->fd, buf, 16, 0);
    else if (!strcmp(k, "peek")) r = recv(s->fd, buf, 16, MSG_PEEK);
    else if (!strcmp(k, "zero")) r = recv(s->fd, buf, 0, 0);
    else if (!strcmp(k, "read")) r = read(s->fd, buf, 16);
    else if (!strcmp(k, "readzero")) r = read(s->fd, buf, 0);
    else if (!strcmp(k, "waitall")) r = recv(s->fd, buf, 16, MSG_WAITALL);
    else if (!strcmp(k, "badbuf")) r = recv(s->fd, unmapped, 16, 0);
    else if (!strcmp(k, "from")) {
        s->cell = 16;
        r = recvfrom(s->fd, buf, 16, 0, (struct sockaddr *)&s->source, &s->cell);
    } else if (!strcmp(k, "fromtrunc")) {
        s->cell = 16;
        r = recvfrom(s->fd, buf, 2, MSG_TRUNC, (struct sockaddr *)&s->source, &s->cell);
    } else if (!strcmp(k, "cellnull")) r = recvfrom(s->fd, buf, 16, 0, (struct sockaddr *)&s->source, NULL);
    else if (!strcmp(k, "cellbad")) r = recvfrom(s->fd, buf, 16, 0, (struct sockaddr *)&s->source, unmapped);
    else if (!strcmp(k, "cellneg")) {
        s->cell = (socklen_t)-1;
        r = recvfrom(s->fd, buf, 16, 0, (struct sockaddr *)&s->source, &s->cell);
    } else if (!strcmp(k, "addrbad")) {
        s->cell = 16;
        r = recvfrom(s->fd, buf, 16, 0, unmapped, &s->cell);
    } else { fprintf(stderr, "unknown kind %s\n", k); exit(1); }
    int e = errno;
    pthread_mutex_lock(&mu);
    s->ret = r;
    s->err = e;
    memcpy(s->text, buf, 16);
    s->text[16] = 0;
    s->order = ++returned_count;
    pthread_mutex_unlock(&mu);
    return NULL;
}

static void on_usr1(int sig) { (void)sig; }

static void describe(const struct sleeper *s, char *out, size_t n)
{
    if (s->ret < 0) {
        snprintf(out, n, "-1 %s", ename(s->err));
        return;
    }
    int used = snprintf(out, n, "%zd", s->ret);
    if (s->ret > 0 && strcmp(s->kind, "badbuf")) used += snprintf(out + used, n - used, " '%.*s'", (int)(s->ret < 16 ? s->ret : 16), s->text);
    if (!strcmp(s->kind, "from") || !strcmp(s->kind, "fromtrunc") || !strcmp(s->kind, "cellneg") || !strcmp(s->kind, "addrbad"))
        used += snprintf(out + used, n - used, " cell=%u", (unsigned)s->cell);
    if (!strcmp(s->kind, "from") || !strcmp(s->kind, "fromtrunc") || !strcmp(s->kind, "cellnull") || !strcmp(s->kind, "cellneg")) {
        uint16_t port = ntohs(s->source.sin_port);
        if (s->source.sin_family == 0 && port == 0) snprintf(out + used, n - used, " source=unwritten");
        else if (port == sender_port) snprintf(out + used, n - used, " source=sender");
        else snprintf(out + used, n - used, " source=%u", (unsigned)port);
    }
}

static void observe(const char *row, const char *when, struct sleeper *sl, int n)
{
    pthread_mutex_lock(&mu);
    printf("%s %s: %d returned;", row, when, returned_count);
    for (int i = 0; i < n; i++) {
        char what[96];
        if (sl[i].order) {
            describe(&sl[i], what, sizeof what);
            printf(" [%d %s %s #%d", i, sl[i].kind, what, sl[i].order);
        } else if (!sl[i].started)
            printf(" [%d %s unparked", i, sl[i].kind);
        else
            printf(" [%d %s asleep", i, sl[i].kind);
#ifndef __APPLE__
        if (sl[i].started && !sl[i].order) printf(" sleeps+%ld", sleeps_of(sl[i].tid) - sl[i].base);
#endif
        printf("]");
    }
    printf("\n");
    pthread_mutex_unlock(&mu);
    fflush(stdout);
}

struct row {
    const char *name;
    int connected; // connect the sleepers' socket to a port nobody holds
    const char *sleepers[4]; // "kind@fd" or "kind@dup"
    const char *events[4];
};

static void run(const struct row *row)
{
    int r = bound();
    uint16_t rport = portof(r);
    uint16_t peer = 0;
    if (row->connected) {
        peer = unheld_port();
        struct sockaddr_in to = lo(peer);
        if (connect(r, (struct sockaddr *)&to, sizeof to) != 0) { perror("connect"); exit(1); }
    }
    int d = dup(r);
    int sender = bound();
    sender_port = portof(sender);
    int peer_socket = -1;
    int closed = 0;

    struct sleeper sl[4];
    pthread_t th[4];
    int n = 0;
    pthread_mutex_lock(&mu);
    returned_count = 0;
    pthread_mutex_unlock(&mu);
    printf("%s: sleepers", row->name);
    for (; n < 4 && row->sleepers[n]; n++) printf(" %s", row->sleepers[n]);
    printf("; events");
    for (int i = 0; i < 4 && row->events[i]; i++) printf(" %s", row->events[i]);
    printf("\n");
    for (int i = 0; i < n; i++) {
        memset(&sl[i], 0, sizeof sl[i]);
        static char kinds[4][16];
        const char *at = strchr(row->sleepers[i], '@');
        snprintf(kinds[i], sizeof kinds[i], "%.*s", (int)(at - row->sleepers[i]), row->sleepers[i]);
        sl[i].kind = kinds[i];
        sl[i].fd = strcmp(at + 1, "fd") ? d : r;
        if (!strcmp(at + 1, "latedup")) continue;
        pthread_create(&th[i], NULL, sleep_in, &sl[i]);
        while (!sl[i].started) usleep(100);
        usleep(50000);
    }
#ifndef __APPLE__
    for (int i = 0; i < n; i++) if (sl[i].started) sl[i].base = sleeps_of(sl[i].tid);
#endif
    observe(row->name, "parked", sl, n);
    int sent = 0;
    static const char *texts[] = { "one", "two", "three", "four", "five", "six" };
    for (int i = 0; i < 4 && row->events[i]; i++) {
        const char *ev = row->events[i];
        char when[48];
        if (!strcmp(ev, "datagram") || !strcmp(ev, "two")) {
            int times = strcmp(ev, "two") ? 1 : 2;
            for (int k = 0; k < times; k++) {
                struct sockaddr_in to = lo(rport);
                sendto(sender, texts[sent], strlen(texts[sent]), 0, (struct sockaddr *)&to, sizeof to);
                sent++;
            }
        } else if (!strcmp(ev, "error")) {
            ssize_t x = send(r, "x", 1, 0);
            if (x != 1) printf("%s: the send that raises the error answered %zd %s\n", row->name, x, ename(errno));
        } else if (!strcmp(ev, "peer")) {
            if (peer_socket < 0) peer_socket = bound_at(peer);
            sender_port = peer;
            struct sockaddr_in to = lo(rport);
            sendto(peer_socket, texts[sent], strlen(texts[sent]), 0, (struct sockaddr *)&to, sizeof to);
            sent++;
        } else if (!strcmp(ev, "close")) {
            printf("%s: close answered %d\n", row->name, close(r));
            closed = 1;
        } else if (!strcmp(ev, "park")) {
            int i = 0;
            while (i < n && (sl[i].started || !strstr(row->sleepers[i], "@latedup"))) i++;
            if (i == n) { fprintf(stderr, "%s: no late sleeper to park\n", row->name); exit(1); }
            pthread_create(&th[i], NULL, sleep_in, &sl[i]);
            while (!sl[i].started) usleep(100);
            usleep(50000);
#ifndef __APPLE__
            sl[i].base = sleeps_of(sl[i].tid);
#endif
        } else if (!strcmp(ev, "nothing")) {
        } else { fprintf(stderr, "unknown event %s\n", ev); exit(1); }
        usleep(100000);
        snprintf(when, sizeof when, "after %s", ev);
        observe(row->name, when, sl, n);
    }
    for (int i = 0; i < n; i++) if (sl[i].started && !sl[i].order) pthread_kill(th[i], SIGUSR1);
    for (int i = 0; i < n; i++) if (sl[i].started) pthread_join(th[i], NULL);
    observe(row->name, "after the signal", sl, n);
    int live = closed ? d : r;
    printf("%s: then the socket holds %s; SO_ERROR=%d\n", row->name, drain_text(live), sock_error(live));
    if (!closed) close(r);
    close(d);
    close(sender);
    if (peer_socket >= 0) close(peer_socket);
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, NULL);

    static const struct row rows[] = {
        // Who a datagram wakes.
        { "V1", 0, { "take@fd", "take@fd", "take@fd" }, { "datagram", "datagram" } },
        { "V2", 0, { "peek@fd", "peek@fd", "peek@fd" }, { "datagram", "datagram", "datagram" } },
        { "V3", 0, { "peek@fd", "peek@fd", "peek@fd" }, { "two" } },
        { "V4", 0, { "peek@fd", "take@fd", "peek@fd" }, { "datagram", "datagram" } },
        { "V5", 0, { "take@fd", "take@dup", "take@fd" }, { "two" } },
        // Who the ICMP error wakes.
        { "V6", 1, { "take@fd", "take@fd", "take@fd" }, { "error", "peer", "peer" } },
        { "V7", 1, { "peek@fd", "peek@fd", "peek@fd" }, { "error", "peer" } },
        { "V8", 1, { "peek@fd", "take@fd" }, { "error", "peer" } },
        { "V9", 1, { "take@fd", "peek@fd" }, { "error", "peer" } },
        { "V10", 1, { "from@fd", "zero@fd", "read@fd" }, { "error", "error", "error" } },
        // What a close does to sleepers through it and through a dup.
        { "V11", 0, { "take@fd", "take@dup", "take@fd" }, { "close", "datagram", "datagram" } },
        { "V12", 0, { "peek@fd", "peek@dup" }, { "close", "datagram" } },
        // What each receiving call answers once a datagram wakes it.
        { "V13", 0, { "zero@fd" }, { "nothing", "datagram" } },
        { "V14", 0, { "read@fd" }, { "datagram" } },
        { "V15", 0, { "waitall@fd" }, { "datagram" } },
        { "V16", 0, { "badbuf@fd" }, { "datagram" } },
        { "V17", 0, { "from@fd" }, { "datagram" } },
        { "V18", 0, { "fromtrunc@fd" }, { "datagram" } },
        { "V19", 0, { "cellnull@fd" }, { "datagram" } },
        { "V20", 0, { "cellbad@fd" }, { "datagram" } },
        { "V21", 0, { "cellneg@fd" }, { "datagram" } },
        { "V22", 0, { "addrbad@fd" }, { "datagram" } },
        { "V23", 1, { "from@fd" }, { "peer" } },
        { "V30", 0, { "readzero@fd" }, { "nothing", "datagram" } },
        // Whether what a close does to the socket outlasts the close: a
        // sleeper that parks through the dup afterwards, with a sleeper
        // through the dup at the close, with none, with one through the
        // closed descriptor, and with a datagram queued.
        { "V24", 0, { "take@dup", "take@latedup" }, { "close", "park", "datagram" } },
        { "V25", 0, { "take@latedup" }, { "close", "park", "datagram" } },
        { "V26", 0, { "peek@dup", "take@latedup" }, { "close", "datagram", "park" } },
        { "V27", 0, { "take@fd", "take@latedup" }, { "close", "park", "datagram" } },
        { "V28", 0, { "take@fd", "take@latedup" }, { "close", "datagram", "park" } },
        { "V29", 0, { "take@fd", "take@latedup", "take@latedup" }, { "close", "park", "park", "datagram" } },
    };
    for (unsigned i = 0; i < sizeof rows / sizeof *rows; i++) run(&rows[i]);
    return 0;
}
