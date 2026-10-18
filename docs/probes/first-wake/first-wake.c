// What a blocking call answers when two of the things that end its sleep
// reach it one after the other, the first having woken the sleeping thread and
// the second arriving before that thread has run again; and, for a queue whose
// waiters a kernel wakes one at a time, whether a thread a signal has woken
// still stands in the queue for the next wake.
//
// Every trial runs in a fresh forked child. Its thread F makes a blocking call
// (and, in a two-sleeper row, its thread O makes the same call first or after
// it); the main thread M holds the sleepers off the processor, makes two
// events in the row's order, checks that F was woken by the first and had not
// run by the end of the second, and only then lets the sleepers run. The
// calls:
//
//   accept     accept() on a loopback listener with nothing queued
//   flock      flock(LOCK_EX) of a file another open file description holds locked
//   read       read() of 1 byte from an empty pipe whose write end stays open
//   write      a 1-byte write() into a full pipe
//   tcp-read   read() of 1 byte from a connected loopback TCP socket with nothing to read
//   tcp-write  a 1000-byte write() to a connected loopback TCP socket whose
//              send buffer is full
//   poll       poll() of the empty pipe's read end for POLLIN
//   events     Linux: epoll_wait() for 1 event on an epoll instance holding
//              the TCP socket for EPOLLIN; Darwin: kevent() for 1 event on a
//              kqueue holding EVFILT_READ of the TCP socket
//
// The events:
//
//   own       what the call waits for: a connect to the listener, an unlock,
//             a byte into the pipe or from the peer socket, the full pipe or
//             the peer's receive buffer read empty
//   signal    pthread_kill(F, SIGUSR1), caught by a handler installed
//             without SA_RESTART, so that EINTR is seen
//   deadline  the call's timeout passing (poll and events only, made with a
//             timeout of 100 ms in a row that has this event, and with none
//             otherwise)
//   drain     Darwin only: close() of the kqueue's only descriptor, which
//             ends a kevent asleep on it (`kqueue-kevent.c` section E)
//   close     the far end going: for read, the pipe's write end closed (end
//             of file); for write, its read end closed (EPIPE, SIGPIPE being
//             ignored); for tcp-read, the peer's shutdown(SHUT_WR) (a FIN);
//             for tcp-write, the peer closed with bytes unread (a reset)
//
// In a two-sleeper row (`sleepers=2`), F is the sleeper the queue wakes first:
// the first to sleep, but for Linux's epoll_wait, the last (`epoll-wait.c`
// section F). The signal goes to F, and `other-woken` says whether O was
// woken before the sleepers were let go.
//
// How M holds the sleepers off the processor:
//
//   Linux: the sleepers and M share CPU 0 under SCHED_FIFO, the sleepers at
//     priority 10; once they sleep M takes priority 50 and does not sleep
//     again until it lets them go, so nothing it waits for (the deadline, a
//     wake) is waited for but by spinning. `woken` reads the state in
//     /proc/self/task/<tid>/stat (R), and `held` that the sleeper's count of
//     times scheduled in /proc/self/task/<tid>/schedstat did not change from
//     before the first event to after the second.
//   Darwin: the sleepers run at QOS_CLASS_BACKGROUND, and once they sleep M
//     starts twice as many spinning threads as there are processors, at
//     QOS_CLASS_USER_INITIATED, M itself running at QOS_CLASS_USER_INTERACTIVE.
//     `woken` reads thread_info()'s run state (TH_STATE_RUNNING), and `held`
//     that the sleeper's user and system time (THREAD_EXTENDED_INFO, to the
//     microsecond) did not change from before the first event to after the
//     second.
//   Both: `held` also requires that the sleeper had not returned from its call.
//
// So a trial with `woken=1 held=1` is one in which the first event woke F and
// the second arrived while F, woken, had not yet run. Where the deadline is
// the second event, `held` also requires that the first woke F before the
// deadline (`woken-by`, in ms since F made its call; `first-at` is when the
// first event was made). Darwin's close of a kqueue, and of a pipe's read end
// under a sleeping writer, waits for the sleeper to leave its call, so for
// those as the second event `held` is read as the close begins; as the first,
// no trial can hold. Each row runs 10 trials; the summary line after them
// counts the answers of the held trials, then of the rest (`unheld:`).
//
// After letting the sleepers go, M waits up to 1 s for each to return (the
// answer, as the return value or the errno's name, and `h1`, the runs of the
// SIGUSR1 handler); a sleeper still asleep then is reported `asleep`, and the
// child exits.
//
// Bounded: an alarm of 10 s in each child, and a fixed list of rows. An
// argument restricts the run to the rows whose label contains it.
//
// Darwin: cc -Wall -O1 -o /tmp/first-wake first-wake.c && /tmp/first-wake
// Linux:  container run --rm --cap-add CAP_SYS_NICE -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -pthread -o /tmp/first-wake /probe/first-wake.c && /tmp/first-wake'
//
// Measured 2026-10-17 on Darwin 27.0.0 arm64 (uid 501) and Linux 6.18.5
// aarch64 (Apple `container`, gcc:14 image, root), twice each, the held
// trials giving the same answers in both runs (Darwin's rows without the
// close event in two earlier runs too); the outputs are
// measured-darwin-27.0-uid501.txt and measured-linux-6.18.5-aarch64-uid0.txt.
// Darwin held between 3 and 10 trials of 10 in each row that can hold, on a
// loaded machine; Linux every trial. In the held trials:
//
//   Darwin, accept, flock, read, write, tcp-read, tcp-write: EINTR, in both
//     orders of the call's own event and the signal, and of the far end's
//     close and the signal for read, tcp-read and tcp-write. A woken sleeper
//     that runs with a caught signal pending fails with it, whatever woke it
//     (XNU's `_sleep` looks for a signal after any wake of a PCATCH sleep).
//     The unheld trials in which the sleeper ran before the signal answered
//     the event instead (accept, write, tcp-read, tcp-write own,signal).
//   Darwin, write, close then signal: no trial held; every one answered
//     EPIPE, the sleeper having left its call inside the close. Signal then
//     close: EINTR.
//   Darwin, poll and events: the first wake decides. Own then signal or
//     deadline: 1; signal then own or deadline: EINTR; deadline then own or
//     signal: 0. The drain: own then drain EBADF, deadline then drain 0,
//     signal then drain EINTR; with the drain first no trial held, and every
//     one answered EBADF.
//   Darwin, two sleepers: accept, signal then own: F EINTR, O woken, O
//     accepted. Own then signal: F EINTR, O not woken and still asleep a
//     second later, the connection left queued. read and events: O woken by
//     the event either way (each wakes every sleeper), and answered it.
//   Linux, every call but tcp-write: the call's own event, or the far end's
//     close, in either order with the signal: the event's answer (accept,
//     0 for flock, 1 for read, write, tcp-read, poll and epoll_wait; 0, EPIPE,
//     0 and ECONNRESET for the closes). tcp-write: EINTR either way, and
//     ECONNRESET for the reset either way.
//   Linux, deadlines: poll 1 for own and the deadline in either order, EINTR
//     for the signal and the deadline in either order; epoll_wait 1 and 0
//     respectively.
//   Linux, two sleepers: accept, read and epoll_wait, signal then own: O woken
//     as well as F, F answering the event (and O, for accept and read, then
//     asleep again; for a level-triggered epoll_wait, 1 too). Own then
//     signal: O not woken.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/syscall.h>
#define FLAVOUR "linux"
#else
#include <mach/mach.h>
#include <pthread/qos.h>
#include <sys/event.h>
#define FLAVOUR "darwin"
#endif

static void die(const char *what) { perror(what); _exit(99); }

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
}

static volatile sig_atomic_t h1_runs = 0;
static void h1(int sig) { (void)sig; h1_runs++; }

static void install(int signo, void (*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(signo, &sa, NULL) != 0) die("sigaction");
}

static void set_nonblocking(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) die("F_GETFL");
    if (fcntl(fd, F_SETFL, on ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) != 0) die("F_SETFL");
}

enum call { C_ACCEPT, C_FLOCK, C_READ, C_WRITE, C_TCP_READ, C_TCP_WRITE, C_POLL, C_EVENTS };
static const char *call_names[] = { "accept", "flock", "read", "write", "tcp-read", "tcp-write", "poll", "events" };

enum event { E_OWN, E_SIGNAL, E_DEADLINE, E_DRAIN, E_CLOSE };
static const char *event_names[] = { "own", "signal", "deadline", "drain", "close" };

struct row {
    enum call call;
    int sleepers;
    enum event first;
    enum event second;
};

static int has_deadline(const struct row *row) { return row->first == E_DEADLINE || row->second == E_DEADLINE; }

#define TIMEOUT_MS 100
#define TRIALS 10

// What the calls work on, made before the sleepers start.
static int empty_pipe[2];
static int full_pipe[2];
static int events_fd = -1;
static int lock_holder = -1;
static int lock_waiter = -1;
static int listener = -1;
static struct sockaddr_in listener_address;
static int tcp_mine = -1;
static int tcp_peer = -1;

struct sleeper {
    pthread_t thread;
    const struct row *row;
    atomic_int entered;
    atomic_int returned;
    int ret;
    int err;
    int64_t entered_ns;
#ifdef __linux__
    atomic_int tid;
#else
    mach_port_t port;
#endif
};

static struct sleeper sleepers[2];

static int loopback_listener(struct sockaddr_in *address)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket");
    memset(address, 0, sizeof *address);
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)address, sizeof *address) != 0) die("bind");
    socklen_t length = sizeof *address;
    if (getsockname(s, (struct sockaddr *)address, &length) != 0) die("getsockname");
    if (listen(s, 8) != 0) die("listen");
    return s;
}

static int connect_to(struct sockaddr_in *address)
{
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) die("socket");
    if (connect(c, (struct sockaddr *)address, sizeof *address) != 0) die("connect");
    return c;
}

static void fill(int fd)
{
    static char chunk[4096];
    set_nonblocking(fd, 1);
    // Until a write of one byte has found no room three times running, 20 ms
    // apart: a TCP connection goes on moving bytes into the peer's receive
    // buffer for a while after the sender's has filled.
    for (int full = 0; full < 3;) {
        int moved = 0;
        for (;;) {
            ssize_t n = write(fd, chunk, sizeof chunk);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) die("fill");
            moved = 1;
        }
        for (;;) {
            ssize_t n = write(fd, chunk, 1);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) die("fill");
            moved = 1;
        }
        full = moved ? 0 : full + 1;
        sleep_ms(20);
    }
    set_nonblocking(fd, 0);
}

// Reads `fd` empty without blocking or sleeping, `rounds` times with a
// millisecond's spin between: under Linux's hold, M may not sleep.
static void drain_spinning(int fd, int rounds)
{
    static char chunk[65536];
    set_nonblocking(fd, 1);
    for (int i = 0; i < rounds; i++) {
        while (read(fd, chunk, sizeof chunk) > 0) { }
        int64_t until = now_ns() + 1000000;
        while (now_ns() < until) { }
    }
}

static void set_up(const struct row *row)
{
    if (pipe(empty_pipe) != 0) die("pipe");
    switch (row->call) {
    case C_WRITE:
        if (pipe(full_pipe) != 0) die("pipe");
        fill(full_pipe[1]);
        break;
    case C_FLOCK: {
        char path[64];
        snprintf(path, sizeof path, "/tmp/first-wake-lock-%d", (int)getpid());
        lock_holder = open(path, O_RDWR | O_CREAT, 0600);
        lock_waiter = open(path, O_RDWR);
        unlink(path);
        if (lock_holder < 0 || lock_waiter < 0) die("open lock file");
        if (flock(lock_holder, LOCK_EX) != 0) die("flock holder");
        break;
    }
    case C_ACCEPT: listener = loopback_listener(&listener_address); break;
    case C_TCP_READ:
    case C_TCP_WRITE:
    case C_EVENTS: {
        struct sockaddr_in address;
        int l = loopback_listener(&address);
        tcp_mine = connect_to(&address);
        tcp_peer = accept(l, NULL, NULL);
        if (tcp_peer < 0) die("accept");
        close(l);
        if (row->call == C_TCP_WRITE) fill(tcp_mine);
        if (row->call == C_EVENTS) {
#ifdef __linux__
            events_fd = epoll_create1(0);
            if (events_fd < 0) die("epoll_create1");
            struct epoll_event ev = { .events = EPOLLIN, .data.fd = tcp_mine };
            if (epoll_ctl(events_fd, EPOLL_CTL_ADD, tcp_mine, &ev) != 0) die("epoll_ctl");
#else
            events_fd = kqueue();
            if (events_fd < 0) die("kqueue");
            struct kevent change;
            EV_SET(&change, tcp_mine, EVFILT_READ, EV_ADD, 0, 0, NULL);
            if (kevent(events_fd, &change, 1, NULL, 0, NULL) != 0) die("kevent register");
#endif
        }
        break;
    }
    default: break;
    }
}

static void *sleep_in_call(void *arg)
{
    struct sleeper *s = arg;
    const struct row *row = s->row;
#ifdef __linux__
    atomic_store(&s->tid, (int)syscall(SYS_gettid));
#endif
    char buffer[1000];
    memset(buffer, 'w', sizeof buffer);
    int timeout = has_deadline(row) ? TIMEOUT_MS : -1;
    struct pollfd pfd = { empty_pipe[0], POLLIN, 0 };
    s->entered_ns = now_ns();
    atomic_store(&s->entered, 1);
    int r = 0;
    switch (row->call) {
    case C_ACCEPT: r = accept(listener, NULL, NULL); break;
    case C_FLOCK: r = flock(lock_waiter, LOCK_EX); break;
    case C_READ: r = (int)read(empty_pipe[0], buffer, 1); break;
    case C_WRITE: r = (int)write(full_pipe[1], buffer, 1); break;
    case C_TCP_READ: r = (int)read(tcp_mine, buffer, 1); break;
    case C_TCP_WRITE: r = (int)write(tcp_mine, buffer, sizeof buffer); break;
    case C_POLL: r = poll(&pfd, 1, timeout); break;
    case C_EVENTS: {
#ifdef __linux__
        struct epoll_event ev;
        r = epoll_wait(events_fd, &ev, 1, timeout);
#else
        struct kevent ev;
        struct timespec ts = { 0, (long)TIMEOUT_MS * 1000000L };
        r = kevent(events_fd, NULL, 0, &ev, 1, timeout < 0 ? NULL : &ts);
#endif
        break;
    }
    }
    s->err = errno;
    s->ret = r;
    atomic_store(&s->returned, 1);
    return NULL;
}

// Whether `s` is woken (runnable) rather than asleep, and how much it has run.
#ifdef __linux__
static char task_state(int tid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    FILE *f = fopen(path, "r");
    if (!f) return '?';
    char buf[512];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *close = strrchr(buf, ')');
    return close && close[1] == ' ' ? close[2] : '?';
}

static int is_woken(struct sleeper *s) { return task_state(atomic_load(&s->tid)) == 'R'; }
static int is_asleep(struct sleeper *s) { return task_state(atomic_load(&s->tid)) == 'S'; }

static unsigned long long times_run(struct sleeper *s)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/schedstat", atomic_load(&s->tid));
    FILE *f = fopen(path, "r");
    if (!f) return ~0ULL;
    unsigned long long run_ns = 0, wait_ns = 0, slices = 0;
    if (fscanf(f, "%llu %llu %llu", &run_ns, &wait_ns, &slices) != 3) die("schedstat parse");
    fclose(f);
    return slices;
}
#else
// A sleeper that has returned from its call may have exited, and its port
// with it: that is no run state, and as much time run as can be counted.
static int run_state(struct sleeper *s, uint64_t *cpu)
{
    struct thread_extended_info info;
    mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
    if (thread_info(s->port, THREAD_EXTENDED_INFO, (thread_info_t)&info, &count) != KERN_SUCCESS) {
        if (cpu) *cpu = UINT64_MAX;
        return -1;
    }
    if (cpu) *cpu = info.pth_user_time + info.pth_system_time;
    return info.pth_run_state;
}

static int is_woken(struct sleeper *s) { return run_state(s, NULL) == TH_STATE_RUNNING; }
static int is_asleep(struct sleeper *s) { return run_state(s, NULL) == TH_STATE_WAITING; }

static unsigned long long times_run(struct sleeper *s)
{
    uint64_t cpu;
    run_state(s, &cpu);
    return cpu;
}
#endif

// Waiting while the sleepers are held: under Linux M spins, since a sleep
// would let them run.
static void pause_held(int64_t ns)
{
#ifdef __linux__
    int64_t until = now_ns() + ns;
    while (now_ns() < until) { }
#else
    struct timespec ts = { (time_t)(ns / 1000000000), (long)(ns % 1000000000) };
    nanosleep(&ts, NULL);
#endif
}

static int wait_until_woken(struct sleeper *s, int64_t ns)
{
    int64_t until = now_ns() + ns;
    while (now_ns() < until) {
        if (is_woken(s)) return 1;
        pause_held(200000);
    }
    return is_woken(s);
}

static void own_event(const struct row *row)
{
    char byte = 'x';
    switch (row->call) {
    case C_ACCEPT: connect_to(&listener_address); break;
    case C_FLOCK:
        if (flock(lock_holder, LOCK_UN) != 0) die("unlock");
        break;
    case C_READ:
    case C_POLL:
        if (write(empty_pipe[1], &byte, 1) != 1) die("write own");
        break;
    case C_WRITE: drain_spinning(full_pipe[0], 1); break;
    case C_TCP_READ:
    case C_EVENTS:
        if (write(tcp_peer, &byte, 1) != 1) die("send own");
        break;
    case C_TCP_WRITE: drain_spinning(tcp_peer, 30); break;
    }
}

static void event(const struct row *row, enum event e, struct sleeper *front, int64_t deadline_ns, int is_first)
{
    switch (e) {
    case E_OWN: own_event(row); break;
    case E_SIGNAL: pthread_kill(front->thread, SIGUSR1); break;
    case E_DEADLINE:
        // As the second event: by the time this returns the deadline has
        // passed. As the first, the caller waits for it to wake the sleeper.
        if (!is_first) {
            int64_t remaining = deadline_ns + 20000000 - now_ns();
            if (remaining > 0) pause_held(remaining);
        }
        break;
    case E_DRAIN:
        if (close(events_fd) != 0) die("close kqueue");
        break;
    case E_CLOSE:
        switch (row->call) {
        case C_READ: close(empty_pipe[1]); break;
        case C_WRITE: close(full_pipe[0]); break;
        case C_TCP_READ:
            if (shutdown(tcp_peer, SHUT_WR) != 0) die("shutdown");
            break;
        case C_TCP_WRITE: close(tcp_peer); break;
        default: die("close event on a call with no far end");
        }
        break;
    }
}

#ifdef __APPLE__
static atomic_int spin = 0;
static pthread_t spinners[256];
static int spinner_count = 0;

static void *spinner(void *arg)
{
    (void)arg;
    while (atomic_load(&spin)) { }
    return NULL;
}
#endif

#ifdef __linux__
static void pin_fifo(pthread_attr_t *attr, int priority)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    struct sched_param param = { .sched_priority = priority };
    if (pthread_attr_setaffinity_np(attr, sizeof cpus, &cpus) != 0) die("setaffinity");
    if (pthread_attr_setinheritsched(attr, PTHREAD_EXPLICIT_SCHED) != 0) die("setinheritsched");
    if (pthread_attr_setschedpolicy(attr, SCHED_FIFO) != 0) die("setschedpolicy");
    if (pthread_attr_setschedparam(attr, &param) != 0) die("setschedparam");
}

static void become_fifo_on_cpu0(int priority)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    if (sched_setaffinity(0, sizeof cpus, &cpus) != 0) die("sched_setaffinity");
    struct sched_param param = { .sched_priority = priority };
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) die("sched_setscheduler");
}
#endif

static void hold(void)
{
#ifdef __linux__
    become_fifo_on_cpu0(50);
#else
    atomic_store(&spin, 1);
    spinner_count = 2 * (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (spinner_count > 256) spinner_count = 256;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_set_qos_class_np(&attr, QOS_CLASS_USER_INITIATED, 0);
    for (int i = 0; i < spinner_count; i++)
        if (pthread_create(&spinners[i], &attr, spinner, NULL) != 0) die("pthread_create spinner");
    sleep_ms(5);
#endif
}

static void let_go(void)
{
#ifdef __linux__
    struct sched_param param = { .sched_priority = 0 };
    if (sched_setscheduler(0, SCHED_OTHER, &param) != 0) die("sched_setscheduler other");
#else
    atomic_store(&spin, 0);
    for (int i = 0; i < spinner_count; i++) pthread_join(spinners[i], NULL);
#endif
}

static void start_sleeper(struct sleeper *s, const struct row *row)
{
    s->row = row;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
#ifdef __linux__
    pin_fifo(&attr, 10);
#else
    pthread_attr_set_qos_class_np(&attr, QOS_CLASS_BACKGROUND, 0);
#endif
    if (pthread_create(&s->thread, &attr, sleep_in_call, s) != 0) die("pthread_create");
#ifdef __APPLE__
    s->port = pthread_mach_thread_np(s->thread);
#endif
    while (!atomic_load(&s->entered)) sleep_ms(1);
    int64_t until = now_ns() + 2000000000LL;
    while (!is_asleep(s)) {
        if (now_ns() > until) die("sleeper never slept");
        sleep_ms(1);
    }
    sleep_ms(5);
    if (!is_asleep(s) || atomic_load(&s->returned)) die("sleeper did not stay asleep");
}

// One trial's answer, as the child reports it to the parent.
struct outcome {
    int woken;
    int held;
    int other_woken;
    int front_returned;
    int front_ret;
    int front_errno;
    int other_returned;
    int other_ret;
    int other_errno;
    int h1;
    int first_ms;
    int woken_ms;
};

static struct outcome run_trial(const struct row *row)
{
    alarm(10);
    install(SIGUSR1, h1);
    signal(SIGPIPE, SIG_IGN);
#ifdef __APPLE__
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
    set_up(row);

    for (int i = 0; i < row->sleepers; i++) start_sleeper(&sleepers[i], row);

#ifdef __linux__
    int front_index = row->call == C_EVENTS ? row->sleepers - 1 : 0;
#else
    int front_index = 0;
#endif
    struct sleeper *front = &sleepers[front_index];
    struct sleeper *other = row->sleepers == 2 ? &sleepers[1 - front_index] : NULL;
    int64_t deadline_ns = front->entered_ns + (int64_t)TIMEOUT_MS * 1000000;

    hold();
    unsigned long long before = times_run(front);

    struct outcome o;
    memset(&o, 0, sizeof o);
    o.first_ms = (int)((now_ns() - front->entered_ns) / 1000000);
    event(row, row->first, front, deadline_ns, 1);
    o.woken = wait_until_woken(front, row->first == E_DEADLINE ? 1000000000LL : 200000000LL);
    o.woken_ms = (int)((now_ns() - front->entered_ns) / 1000000);
    // Darwin's close of a kqueue waits for the sleeper to leave its kevent,
    // and its close of a pipe's read end for a writer asleep on the pipe to
    // leave its write (measured: no trial with that close first held), so
    // that the sleeper runs inside the close: for such a close second,
    // `held` says that the sleeper had not run when the close began.
    int second_waits = row->second == E_DRAIN || (row->second == E_CLOSE && row->call == C_WRITE);
    unsigned long long middle = times_run(front);
    int returned_before_second = atomic_load(&front->returned);
    event(row, row->second, front, deadline_ns, 0);
    pause_held(5000000);
    if (other) o.other_woken = wait_until_woken(other, 50000000LL);
    unsigned long long after = times_run(front);
    o.held = before == middle && !returned_before_second
             && (second_waits || (middle == after && !atomic_load(&front->returned)));
    // The first event must have woken the sleeper before its deadline, where
    // the deadline comes second.
    if (row->second == E_DEADLINE && o.woken_ms >= TIMEOUT_MS) o.held = 0;

    let_go();

    for (int i = 0; i < row->sleepers; i++) {
        int64_t until = now_ns() + 1000000000LL;
        while (!atomic_load(&sleepers[i].returned) && now_ns() < until) sleep_ms(1);
    }
    o.front_returned = atomic_load(&front->returned);
    o.front_ret = front->ret;
    o.front_errno = front->err;
    if (other) {
        o.other_returned = atomic_load(&other->returned);
        o.other_ret = other->ret;
        o.other_errno = other->err;
    }
    o.h1 = h1_runs;
    return o;
}

static void describe(char *out, size_t size, const struct row *row, int returned, int ret, int err)
{
    if (!returned)
        snprintf(out, size, "asleep");
    else if (ret < 0)
        snprintf(out, size, "%s",
                 err == EINTR        ? "EINTR"
                 : err == EBADF      ? "EBADF"
                 : err == EPIPE      ? "EPIPE"
                 : err == ECONNRESET ? "ECONNRESET"
                                     : strerror(err));
    else if (row->call == C_ACCEPT)
        snprintf(out, size, "accepted");
    else
        snprintf(out, size, "%d", ret);
}

static const char *only = NULL;

// Prints each distinct answer of `answers` with how many times it occurs.
static void tally(char answers[][160], int count)
{
    int counted[TRIALS] = { 0 };
    for (int i = 0; i < count; i++) {
        if (counted[i]) continue;
        int n = 0;
        for (int j = i; j < count; j++)
            if (!counted[j] && strcmp(answers[i], answers[j]) == 0) {
                counted[j] = 1;
                n++;
            }
        printf(" [%s]x%d", answers[i], n);
    }
}

static void run_row(const struct row *row)
{
    char label[128];
    snprintf(label, sizeof label, "%s call=%s sleepers=%d order=%s,%s", FLAVOUR, call_names[row->call], row->sleepers,
             event_names[row->first], event_names[row->second]);
    if (only && !strstr(label, only)) return;

    // Each held trial's answer, as text, to count them.
    char answers[TRIALS][160];
    int held_count = 0;
    char unheld[TRIALS][160];
    int unheld_count = 0;

    for (int trial = 0; trial < TRIALS; trial++) {
        int channel[2];
        if (pipe(channel) != 0) die("pipe");
        fflush(stdout);
        pid_t child = fork();
        if (child < 0) die("fork");
        if (child == 0) {
            close(channel[0]);
            struct outcome o = run_trial(row);
            if (write(channel[1], &o, sizeof o) != sizeof o) die("report");
            _exit(0);
        }
        close(channel[1]);
        struct outcome o;
        ssize_t got = read(channel[0], &o, sizeof o);
        close(channel[0]);
        int status;
        if (waitpid(child, &status, 0) != child) die("waitpid");
        if (got != sizeof o || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            printf("%s trial=%d failed (status %d)\n", label, trial, status);
            continue;
        }
        char front[32], other[32] = "-";
        describe(front, sizeof front, row, o.front_returned, o.front_ret, o.front_errno);
        if (row->sleepers == 2) describe(other, sizeof other, row, o.other_returned, o.other_ret, o.other_errno);
        printf("%s trial=%d first-at=%dms woken-by=%dms woken=%d held=%d front=%s h1=%d", label, trial, o.first_ms,
               o.woken_ms, o.woken, o.held, front, o.h1);
        if (row->sleepers == 2) printf(" other-woken=%d other=%s", o.other_woken, other);
        printf("\n");
        char *slot = o.woken && o.held ? answers[held_count++] : unheld[unheld_count++];
        if (row->sleepers == 2)
            snprintf(slot, 160, "front=%s other-woken=%d other=%s", front, o.other_woken, other);
        else
            snprintf(slot, 160, "front=%s", front);
    }

    printf("%s summary held=%d/%d", label, held_count, TRIALS);
    tally(answers, held_count);
    printf(" unheld:");
    tally(unheld, unheld_count);
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc > 1) only = argv[1];
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d\n", u.sysname, u.release, u.machine, (int)getuid());

    static const enum call single[] = { C_ACCEPT, C_FLOCK, C_READ, C_WRITE, C_TCP_READ, C_TCP_WRITE, C_POLL, C_EVENTS };
    for (size_t i = 0; i < sizeof single / sizeof single[0]; i++) {
        struct row a = { single[i], 1, E_OWN, E_SIGNAL };
        struct row b = { single[i], 1, E_SIGNAL, E_OWN };
        run_row(&a);
        run_row(&b);
    }

    static const enum call far_ends[] = { C_READ, C_WRITE, C_TCP_READ, C_TCP_WRITE };
    for (size_t i = 0; i < 4; i++) {
        struct row a = { far_ends[i], 1, E_CLOSE, E_SIGNAL };
        struct row b = { far_ends[i], 1, E_SIGNAL, E_CLOSE };
        run_row(&a);
        run_row(&b);
    }

    static const enum call timed[] = { C_POLL, C_EVENTS };
    static const enum event against[] = { E_OWN, E_SIGNAL };
    for (size_t i = 0; i < 2; i++)
        for (size_t j = 0; j < 2; j++) {
            struct row a = { timed[i], 1, E_DEADLINE, against[j] };
            struct row b = { timed[i], 1, against[j], E_DEADLINE };
            run_row(&a);
            run_row(&b);
        }

#ifdef __APPLE__
    static const enum event beside_drain[] = { E_DEADLINE, E_OWN, E_SIGNAL };
    for (size_t j = 0; j < 3; j++) {
        struct row a = { C_EVENTS, 1, E_DRAIN, beside_drain[j] };
        struct row b = { C_EVENTS, 1, beside_drain[j], E_DRAIN };
        run_row(&a);
        run_row(&b);
    }
#endif

    static const enum call queued[] = { C_ACCEPT, C_READ, C_EVENTS };
    for (size_t i = 0; i < 3; i++) {
        struct row a = { queued[i], 2, E_SIGNAL, E_OWN };
        struct row b = { queued[i], 2, E_OWN, E_SIGNAL };
        run_row(&a);
        run_row(&b);
    }
    return 0;
}
