// What a sleeping call answers for a timeout too large for the monotonic
// clock: an error at once, a timeout, or a sleep that only something else
// ends. Linux: futex(FUTEX_WAIT_PRIVATE), poll, ppoll, epoll_wait and
// epoll_pwait2. Darwin: poll and kevent.
//
// Build and run:
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1)" && gcc -Wall -O1 -pthread -o /tmp/p /probe/huge-timeout.c && /tmp/p'
//   Darwin: cc -Wall -O1 -o /tmp/p huge-timeout.c && /tmp/p
//
// Every row runs in a forked child of its own, and the rows run at once, each
// printing one line, which the parent prints in row order. A row's call is
// made by a waiter thread. The row's main thread waits WATCH_MS; if the call
// has not returned by then it prints `asleep-at=<WATCH_MS>` and ends the call
// by the row's ender:
//   wake    - FUTEX_WAKE_PRIVATE of 1 on the futex word; `woke` is what it
//             returned.
//   write   - one byte written to a pipe whose read end the call watches.
//   restart - SIGUSR1, whose handler is installed with SA_RESTART, sent to the
//             waiter: `after-signal` is what the call returned within 300 ms
//             of the signal, or `asleep` if it had not, in which case the row
//             then wakes it as `wake` does. A futex wait with a timeout
//             answers EINTR here, and one without goes on sleeping
//             (`docs/probes/futex`, the "signal" rows), so this tells which
//             kind of wait the kernel made of the timeout.
// On aarch64 Linux has no poll or epoll_wait syscall: glibc makes poll a ppoll
// of the milliseconds as a timespec (a null one for a negative timeout), and
// epoll_wait an epoll_pwait with no mask. The header records the machine.
//
// Fields: `ret` and `errno` are what the call returned (errno=0 for none);
// `at` is the millisecond, from the row's start, at which it returned. A child
// that hangs is killed by its own alarm (`end=signal14`).
//
// The header records the kernel, sizeof(long) and sizeof(time_t), and the
// monotonic clock's reading when the probe started: Linux adds a relative
// timeout to the time now (`ktime_add_safe`), so whether a sum overflows
// depends on it. KTIME_MAX is INT64_MAX nanoseconds; KTIME_SEC_MAX is
// 9223372036 seconds. A fresh container's clock starts near 0, so the probe
// first waits until the clock reads 3 s: then a sum with tv_sec 9223372035
// overflows (any tv_nsec), a tv_sec of KTIME_SEC_MAX or more saturates the
// timeout itself, and tv_sec 8589934592 (about 272 years) does neither, so the
// rows reach all three of Linux's cases.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#else
#include <sys/event.h>
#endif

#define WATCH_MS 2000
#define ALARM_S 12

// ---------------------------------------------------------------- utilities

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int64_t row_start;

static int64_t ms_since_start(void)
{
    return (now_ns() - row_start) / 1000000;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static const char *errname(int e)
{
    switch (e) {
    case 0: return "0";
    case EINVAL: return "EINVAL";
    case EAGAIN: return "EAGAIN";
    case EFAULT: return "EFAULT";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EINTR: return "EINTR";
    case ENOSYS: return "ENOSYS";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static char line[4096];

static void out(const char *fmt, ...)
{
    size_t used = strlen(line);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + used, sizeof line - used, fmt, ap);
    va_end(ap);
}

// ---------------------------------------------------------------- the rows

enum call {
#ifdef __linux__
    CALL_FUTEX,
    CALL_PPOLL,
    CALL_EPOLL_WAIT,
    CALL_EPOLL_PWAIT2,
#else
    CALL_KEVENT,
#endif
    CALL_POLL,
};

enum ender { END_WAKE, END_WRITE, END_RESTART };

struct row {
    enum call call;
    enum ender ender;
    const char *label;
    // A timespec for futex, ppoll, epoll_pwait2 and kevent; `null` for a null
    // pointer.
    int64_t sec;
    int64_t nsec;
    int null;
    // Milliseconds for poll and epoll_wait.
    int ms;
};

static const struct row *the_row;
#ifdef __linux__
static _Atomic uint32_t word;
#endif
static int pipe_fds[2];
static int port = -1;
static _Atomic int done;
static long call_ret;
static int call_errno;
static int64_t call_at;

static void on_usr1(int sig)
{
    (void)sig;
}

static void *waiter(void *unused)
{
    (void)unused;
    const struct row *r = the_row;
    long ret = -1;
    errno = 0;
    switch (r->call) {
#ifdef __linux__
    case CALL_FUTEX: {
        struct timespec ts = { (time_t)r->sec, (long)r->nsec };
        ret = syscall(SYS_futex, &word, FUTEX_WAIT_PRIVATE, 0, r->null ? NULL : &ts, NULL, 0);
        break;
    }
    case CALL_PPOLL: {
        struct timespec ts = { (time_t)r->sec, (long)r->nsec };
        struct pollfd p = { pipe_fds[0], POLLIN, 0 };
        // Raw, so that libc screens nothing; the sigset pointer is null.
        ret = syscall(SYS_ppoll, &p, 1, r->null ? NULL : &ts, NULL, 8);
        break;
    }
    case CALL_EPOLL_WAIT: {
        struct epoll_event e;
        ret = epoll_wait(port, &e, 1, r->ms);
        break;
    }
    case CALL_EPOLL_PWAIT2: {
        struct timespec ts = { (time_t)r->sec, (long)r->nsec };
        struct epoll_event e;
        ret = syscall(SYS_epoll_pwait2, port, &e, 1, r->null ? NULL : &ts, NULL, 8);
        break;
    }
#else
    case CALL_KEVENT: {
        struct timespec ts = { (time_t)r->sec, (long)r->nsec };
        struct kevent e;
        ret = kevent(port, NULL, 0, &e, 1, r->null ? NULL : &ts);
        break;
    }
#endif
    case CALL_POLL: {
        struct pollfd p = { pipe_fds[0], POLLIN, 0 };
        ret = poll(&p, 1, r->ms);
        break;
    }
    }
    call_errno = ret < 0 ? errno : 0;
    call_ret = ret;
    call_at = ms_since_start();
    atomic_store(&done, 1);
    return NULL;
}

static void report_call(void)
{
    out(" ret=%ld errno=%s at=%lld", call_ret, errname(call_errno), (long long)call_at);
}

static void wake_it(void)
{
#ifdef __linux__
    long woke = syscall(SYS_futex, &word, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    out(" woke=%ld", woke);
#endif
}

static void run(const struct row *r)
{
    the_row = r;
    if (pipe(pipe_fds) != 0) {
        perror("pipe");
        exit(1);
    }
#ifdef __linux__
    port = epoll_create1(0);
    struct epoll_event e = { .events = EPOLLIN, .data.fd = pipe_fds[0] };
    epoll_ctl(port, EPOLL_CTL_ADD, pipe_fds[0], &e);
#else
    port = kqueue();
    struct kevent change;
    EV_SET(&change, pipe_fds[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(port, &change, 1, NULL, 0, NULL);
#endif
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    row_start = now_ns();
    pthread_t t;
    pthread_create(&t, NULL, waiter, NULL);
    sleep_ms(WATCH_MS);
    if (atomic_load(&done)) {
        report_call();
        pthread_join(t, NULL);
        return;
    }
    out(" asleep-at=%d", WATCH_MS);
    switch (r->ender) {
    case END_WAKE:
        wake_it();
        break;
    case END_WRITE:
        if (write(pipe_fds[1], "x", 1) != 1)
            out(" write-failed");
        break;
    case END_RESTART:
        pthread_kill(t, SIGUSR1);
        sleep_ms(300);
        if (atomic_load(&done)) {
            out(" after-signal:");
            report_call();
            pthread_join(t, NULL);
            return;
        }
        out(" after-signal=asleep");
        wake_it();
        break;
    }
    pthread_join(t, NULL);
    report_call();
}

// ---------------------------------------------------------------- the table

#define TS(c, e, s, n) { c, e, #s "," #n, (int64_t)(s), (int64_t)(n), 0, 0 }
#define TSNULL(c, e) { c, e, "null", 0, 0, 1, 0 }
#define MS(c, e, m) { c, e, #m, 0, 0, 0, (int)(m) }

// tv_sec values around KTIME_SEC_MAX (9223372036), and past it to INT64_MAX
// (LONG_MAX, on every 64-bit kernel this probe runs on).
#define HUGE_TIMESPECS(c, e)                                         \
    TS(c, e, 1, 500000000), TS(c, e, 8589934592, 0),                 \
        TS(c, e, 9223372035, 0), TS(c, e, 9223372035, 999999999),    \
        TS(c, e, 9223372036, 0), TS(c, e, 9223372036, 854775807),    \
        TS(c, e, 9223372036, 999999999), TS(c, e, 9223372037, 0),    \
        TS(c, e, 10000000000, 0), TS(c, e, 1000000000000000, 0),     \
        TS(c, e, 4611686018427387904, 0),                            \
        TS(c, e, 9223372036854775806, 0),                            \
        TS(c, e, INT64_MAX, 0), TS(c, e, INT64_MAX, 999999999)

// Fields out of range: negative tv_sec, and tv_nsec outside [0, 1e9).
#define BAD_TIMESPECS(c, e)                                          \
    TS(c, e, -1, 0), TS(c, e, -9223372036, 0), TS(c, e, INT64_MIN, 0), \
        TS(c, e, INT64_MIN, 999999999), TS(c, e, 0, 1000000000),     \
        TS(c, e, 0, -1), TS(c, e, 0, INT64_MAX), TS(c, e, 0, INT64_MIN), \
        TS(c, e, INT64_MAX, 1000000000), TS(c, e, INT64_MAX, -1),    \
        TS(c, e, 9223372036, 1000000000), TS(c, e, -1, 999999999)

#define HUGE_MS(c, e)                                                \
    MS(c, e, 1500), MS(c, e, 100000000), MS(c, e, 1073741824),       \
        MS(c, e, INT_MAX), MS(c, e, -1), MS(c, e, INT_MIN)

static const struct row rows[] = {
#ifdef __linux__
    HUGE_TIMESPECS(CALL_FUTEX, END_WAKE),
    BAD_TIMESPECS(CALL_FUTEX, END_WAKE),
    TSNULL(CALL_FUTEX, END_RESTART),
    TS(CALL_FUTEX, END_RESTART, 100, 0),
    TS(CALL_FUTEX, END_RESTART, 8589934592, 0),
    TS(CALL_FUTEX, END_RESTART, 9223372035, 999999999),
    TS(CALL_FUTEX, END_RESTART, 9223372036, 0),
    TS(CALL_FUTEX, END_RESTART, 10000000000, 0),
    TS(CALL_FUTEX, END_RESTART, INT64_MAX, 0),
    HUGE_MS(CALL_POLL, END_WRITE),
    HUGE_TIMESPECS(CALL_PPOLL, END_WRITE),
    BAD_TIMESPECS(CALL_PPOLL, END_WRITE),
    HUGE_MS(CALL_EPOLL_WAIT, END_WRITE),
    HUGE_TIMESPECS(CALL_EPOLL_PWAIT2, END_WRITE),
    BAD_TIMESPECS(CALL_EPOLL_PWAIT2, END_WRITE),
#else
    HUGE_MS(CALL_POLL, END_WRITE),
    TS(CALL_KEVENT, END_WRITE, 1, 500000000),
    TS(CALL_KEVENT, END_WRITE, 100000000, 0),
    TS(CALL_KEVENT, END_WRITE, 100000001, 0),
    TS(CALL_KEVENT, END_WRITE, 2147483647, 0),
    TS(CALL_KEVENT, END_WRITE, 2147483647, 999999999),
    TS(CALL_KEVENT, END_WRITE, 2147483647, 1000000000),
    TS(CALL_KEVENT, END_WRITE, 2147483648, 0),
    TS(CALL_KEVENT, END_WRITE, 9223372036, 0),
    TS(CALL_KEVENT, END_WRITE, INT64_MAX, 0),
    TS(CALL_KEVENT, END_WRITE, -1, 0),
    TS(CALL_KEVENT, END_WRITE, 0, 1000000001),
#endif
};

static const char *call_name(enum call c)
{
    switch (c) {
#ifdef __linux__
    case CALL_FUTEX: return "futex-wait-private";
    case CALL_PPOLL: return "ppoll";
    case CALL_EPOLL_WAIT: return "epoll_wait";
    case CALL_EPOLL_PWAIT2: return "epoll_pwait2";
#else
    case CALL_KEVENT: return "kevent";
#endif
    case CALL_POLL: return "poll";
    }
    return "?";
}

static const char *ender_name(enum ender e)
{
    switch (e) {
    case END_WAKE: return "wake";
    case END_WRITE: return "write";
    case END_RESTART: return "restart";
    }
    return "?";
}

int main(void)
{
    struct utsname u;
    uname(&u);
    struct timespec mono;
    clock_gettime(CLOCK_MONOTONIC, &mono);
    while (mono.tv_sec < 3) {
        sleep_ms(100);
        clock_gettime(CLOCK_MONOTONIC, &mono);
    }
    printf("# %s %s %s, uid %d, sizeof(long)=%zu sizeof(time_t)=%zu, CLOCK_MONOTONIC at start %lld.%09ld s\n",
        u.sysname, u.release, u.machine, (int)getuid(), sizeof(long), sizeof(time_t), (long long)mono.tv_sec,
        mono.tv_nsec);
    printf("# watch %d ms\n", WATCH_MS);
    fflush(stdout);

    size_t n = sizeof rows / sizeof rows[0];
    pid_t pids[sizeof rows / sizeof rows[0]];
    int outs[sizeof rows / sizeof rows[0]];
    for (size_t i = 0; i < n; i++) {
        int fds[2];
        if (pipe(fds) != 0) {
            perror("pipe");
            return 1;
        }
        pid_t pid = fork();
        if (pid == 0) {
            close(fds[0]);
            dup2(fds[1], STDOUT_FILENO);
            alarm(ALARM_S);
            line[0] = 0;
            run(&rows[i]);
            printf("%s\n", line);
            fflush(stdout);
            _exit(0);
        }
        close(fds[1]);
        pids[i] = pid;
        outs[i] = fds[0];
    }
    for (size_t i = 0; i < n; i++) {
        char buf[4096];
        size_t used = 0;
        ssize_t got;
        while (used < sizeof buf - 1 && (got = read(outs[i], buf + used, sizeof buf - 1 - used)) > 0)
            used += (size_t)got;
        buf[used] = 0;
        if (used > 0 && buf[used - 1] == '\n')
            buf[used - 1] = 0;
        close(outs[i]);
        int status;
        waitpid(pids[i], &status, 0);
        printf("%s ender=%s timeout=%s%s", call_name(rows[i].call), ender_name(rows[i].ender), rows[i].label, buf);
        if (WIFSIGNALED(status))
            printf(" end=signal%d", WTERMSIG(status));
        printf("\n");
    }
    return 0;
}
