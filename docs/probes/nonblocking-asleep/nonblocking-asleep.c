// A transfer asleep on a pipe or a connected TCP socket, its open file
// description made non-blocking (F_SETFL O_NONBLOCK, by another thread) while
// it sleeps, then sent a caught SIGUSR1 with what it waits for still absent:
// what the call answers.
//
// Build and run, from this directory:
//   Darwin: cc -Wall -o /tmp/nba nonblocking-asleep.c -lpthread && /tmp/nba
//   Linux:  container run --rm -v "$PWD:/probe" gcc:14 sh -c
//             "gcc -Wall -o /tmp/nba /probe/nonblocking-asleep.c -lpthread && /tmp/nba"
//   An argument names the sections to run: P (pipes), T (TCP), or both
//   (the default).
//
// Rows, each with O_NONBLOCK set while asleep (nonblock=1) or not (the
// control, nonblock=0), the handler installed with SA_RESTART or not, and five
// trials:
//   P-write0   a 1-byte write into a pipe filled by 1-byte non-blocking writes
//              until EAGAIN: it has put nothing in.
//   P-partial  a 200000-byte write into an empty pipe: it has put some in.
//   P-read     a 1-byte read of an empty pipe.
//   T-write0   a 1-byte write through the connecting end of a loopback TCP
//              connection, SO_SNDBUF and SO_RCVBUF set to 65536 on every
//              socket, filled by non-blocking writes until EAGAIN, and again
//              after a pause of TCP_SETTLE_MS until a pause makes no room: it
//              has taken nothing.
//   T-read     a 1-byte read through the connecting end of an empty
//              connection.
//
// The call runs on a second thread. The main thread waits 150 ms, records
// whether the call is still in progress (asleep_at_flag), sets the flag (or
// not), waits 50 ms, records whether it is still in progress
// (asleep_at_signal), sends SIGUSR1 to it with pthread_kill, and waits 150 ms:
// at_signal=returned if the call returned by then, and slept-on otherwise,
// when the main thread then drains the other end (a write) or writes a byte
// into it (a read) until the call returns. rv and errno are the call's, and
// handled is how many times the handler had run when the call returned. held
// is what the other end could read just before the flag was set (FIONREAD).
// then is what the same call of one byte, made non-blocking, answered once a
// call that returned at the signal had returned: EAGAIN says what the call
// waited for was still absent. A row with asleep_at_flag=0 or
// asleep_at_signal=0 measured nothing, and so does one whose then is not
// EAGAIN.
//
// Measured 2026-10-13 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14
// image) and Darwin 27.0.0 arm64, every trial of every row alike:
//   P-write0   nonblock=1, no SA_RESTART: Linux EAGAIN, Darwin EINTR. With
//              SA_RESTART, EAGAIN on both. The controls: EINTR without
//              SA_RESTART, and with it the write slept on and wrote its byte
//              once given room. Linux's `pipe_write` (fs/pipe.c) ignores what
//              its sleep answers, and on waking looks for room, then at
//              O_NONBLOCK, and only then for a signal; so the EAGAIN of
//              pipe-blocking.c's N4 for a write, whose sleep a stop ended,
//              needs no restart to explain it.
//   P-partial  65536, on both, in every row: the count it had put in.
//   P-read     EINTR without SA_RESTART on both, nonblock=1 or not; with it,
//              EAGAIN where the flag was set (the restarted call is
//              non-blocking), and the control slept on and read its byte.
//   T-write0   and T-read: as P-read, on both. Linux's `tcp_sendmsg` and
//              `tcp_recvmsg` fix the timeout they sleep with as they begin,
//              from the flag as it was then.
//   then was EAGAIN in every row that has one, and every row was asleep at
//   the flag and at the signal.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define TRIALS 5
#define PARTIAL_COUNT 200000
// How long the TCP fill pauses before it looks for room again. At 50 ms a
// Linux connection made room a fresh write could take within the ~350 ms a
// row lasts (its post-call write took a byte, and a restarted one did too);
// at 500 ms it made none.
#define TCP_SETTLE_MS 500

static volatile sig_atomic_t handled = 0;
static void on_usr1(int sig) { (void)sig; handled++; }

static void install(int restart)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigaction(SIGUSR1, &sa, NULL);
}

static void sleep_ms(int ms) { usleep(ms * 1000); }

static const char *errname(int e)
{
    switch (e) {
    case EAGAIN: return "EAGAIN";
    case EINTR: return "EINTR";
    case EPIPE: return "EPIPE";
    case EBADF: return "EBADF";
    case ECONNRESET: return "ECONNRESET";
    default: return "OTHER";
    }
}

static void set_nonblocking(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}

static int readable(int fd)
{
    int n = 0;
    ioctl(fd, FIONREAD, &n);
    return n;
}

enum kind { WRITE0, PARTIAL, READ };

struct call {
    enum kind kind;
    int fd;
    char *buf;
    size_t count;
    ssize_t rv;
    int err;
    int handled_at_return;
    atomic_int done;
};

static void *run_call(void *p)
{
    struct call *c = p;
    ssize_t rv;
    errno = 0;
    if (c->kind == READ)
        rv = read(c->fd, c->buf, c->count);
    else
        rv = write(c->fd, c->buf, c->count);
    c->err = errno;
    c->rv = rv;
    c->handled_at_return = (int)handled;
    atomic_store(&c->done, 1);
    return NULL;
}

// Fill `fd` with non-blocking writes of `chunk` bytes until EAGAIN, then
// pause and fill again, until a pause makes no room.
static void fill(int fd, size_t chunk, int pause)
{
    static char buf[65536];
    memset(buf, 'f', sizeof buf);
    set_nonblocking(fd, 1);
    for (;;) {
        long wrote = 0;
        while (write(fd, buf, chunk) > 0) wrote++;
        if (!pause || wrote == 0) break;
        sleep_ms(pause);
    }
    set_nonblocking(fd, 0);
}

// Unstick a call that slept on after the signal: take what fills the other
// end, or give it a byte, until the call returns.
static void unstick(struct call *c, int other)
{
    static char buf[65536];
    if (c->kind == READ) {
        (void)!write(other, "z", 1);
    }
    set_nonblocking(other, 1);
    for (int i = 0; i < 400 && !atomic_load(&c->done); i++) {
        if (c->kind != READ) while (read(other, buf, sizeof buf) > 0) {}
        sleep_ms(5);
    }
}

static void row(const char *name, struct call *c, int other, int nonblock, int restart, int trial)
{
    install(restart);
    handled = 0;
    atomic_store(&c->done, 0);
    pthread_t t;
    pthread_create(&t, NULL, run_call, c);
    sleep_ms(150);
    int asleep_at_flag = !atomic_load(&c->done);
    int held = readable(other);
    if (nonblock) set_nonblocking(c->fd, 1);
    sleep_ms(50);
    int asleep_at_signal = !atomic_load(&c->done);
    pthread_kill(t, SIGUSR1);
    sleep_ms(150);
    int returned = atomic_load(&c->done);
    if (!returned) unstick(c, other);
    pthread_join(t, NULL);
    // Whether what the call waited for was still absent once it had returned:
    // the same call again, of one byte, made non-blocking.
    char then[24] = "-";
    if (returned) {
        char b = 'y';
        set_nonblocking(c->fd, 1);
        errno = 0;
        ssize_t again = c->kind == READ ? read(c->fd, &b, 1) : write(c->fd, &b, 1);
        if (again < 0) snprintf(then, sizeof then, "%s", errname(errno));
        else snprintf(then, sizeof then, "%zd", again);
    }
    printf("%s nonblock=%d restart=%d trial=%d: held=%d asleep_at_flag=%d asleep_at_signal=%d at_signal=%s rv=%zd errno=%s handled=%d then=%s\n",
           name, nonblock, restart, trial, held, asleep_at_flag, asleep_at_signal,
           returned ? "returned" : "slept-on", c->rv, c->rv < 0 ? errname(c->err) : "-", c->handled_at_return, then);
    fflush(stdout);
}

static void pipe_row(enum kind kind, int nonblock, int restart, int trial)
{
    static char buf[PARTIAL_COUNT];
    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); exit(1); }
    struct call c;
    memset(&c, 0, sizeof c);
    c.kind = kind;
    c.buf = buf;
    switch (kind) {
    case WRITE0:
        fill(fds[1], 1, 0);
        c.fd = fds[1]; c.count = 1;
        row("P-write0", &c, fds[0], nonblock, restart, trial);
        break;
    case PARTIAL:
        c.fd = fds[1]; c.count = PARTIAL_COUNT;
        row("P-partial", &c, fds[0], nonblock, restart, trial);
        break;
    case READ:
        c.fd = fds[0]; c.count = 1;
        row("P-read", &c, fds[1], nonblock, restart, trial);
        break;
    }
    close(fds[0]);
    close(fds[1]);
}

// Buffers of a size set by the caller, which turns off both kernels' automatic
// sizing: a buffer that grew as a fill ran would make room for the sleeping
// write.
static void fix_buffers(int s)
{
    int size = 65536;
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &size, sizeof size);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, sizeof size);
}

static void tcp_pair(int *client, int *server)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    fix_buffers(listener);
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("bind"); exit(1); }
    listen(listener, 1);
    socklen_t len = sizeof addr;
    getsockname(listener, (struct sockaddr *)&addr, &len);
    *client = socket(AF_INET, SOCK_STREAM, 0);
    fix_buffers(*client);
    if (connect(*client, (struct sockaddr *)&addr, sizeof addr) != 0) { perror("connect"); exit(1); }
    *server = accept(listener, NULL, NULL);
    fix_buffers(*server);
    close(listener);
}

static void tcp_row(enum kind kind, int nonblock, int restart, int trial)
{
    static char buf[1];
    int client, server;
    tcp_pair(&client, &server);
    struct call c;
    memset(&c, 0, sizeof c);
    c.kind = kind;
    c.buf = buf;
    c.fd = client;
    c.count = 1;
    if (kind == WRITE0) {
        fill(client, 65536, TCP_SETTLE_MS);
        row("T-write0", &c, server, nonblock, restart, trial);
    } else {
        row("T-read", &c, server, nonblock, restart, trial);
    }
    close(client);
    close(server);
}

int main(int argc, char **argv)
{
    const char *sections = argc > 1 ? argv[1] : "PT";
    int pipes = strchr(sections, 'P') != NULL;
    int tcp = strchr(sections, 'T') != NULL;
    struct utsname u;
    uname(&u);
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);
    fflush(stdout);
    for (int nonblock = 1; nonblock >= 0; nonblock--)
        for (int restart = 0; restart <= 1; restart++)
            for (int trial = 1; trial <= TRIALS; trial++) {
                if (pipes) {
                    pipe_row(WRITE0, nonblock, restart, trial);
                    pipe_row(PARTIAL, nonblock, restart, trial);
                    pipe_row(READ, nonblock, restart, trial);
                }
                if (tcp) {
                    tcp_row(WRITE0, nonblock, restart, trial);
                    tcp_row(READ, nonblock, restart, trial);
                }
            }
    return 0;
}
