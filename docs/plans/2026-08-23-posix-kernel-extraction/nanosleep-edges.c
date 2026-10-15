// nanosleep(2) and clock_nanosleep(2): which arguments are refused, what a
// signal that ends the sleep leaves in `rem`, whether anything restarts the
// sleep, which clocks clock_nanosleep sleeps on, and what TIMER_ABSTIME
// changes. For the design of nanosleep in WoofWare.PosixKernel
// (Smaug123/WoofWare.PosixKernel#8).
//
// Every row runs in a fresh forked child, so no row sees another's
// dispositions or masks. A row ends `end=exit0` when the child finished, and
// `end=signalN` when signal N killed it (14 is the guard alarm, so a sleep
// that never ended).
//
// Times: `el` is the sleep's elapsed CLOCK_MONOTONIC time; `rem` is what the
// call left in its remainder argument, `-` when it left the sentinel there;
// `excess` is rem + el - req, in nanoseconds: how much longer than the
// request the remainder says the sleep would have lasted.
//
// Sections:
//   args     - argument screens: a null or unmapped request; tv_nsec of 1e9,
//              -1 and LONG_MIN; tv_sec -1; and huge requests that a signal
//              ends after 100 ms (are they refused, saturated, truncated?),
//              (2^32-1e9 s tells a remainder counted from the uptime, which
//              does not wrap, from one counted from the epoch, which does),
//              and some that one ends only after 2 or 3 s: does the sleep
//              itself truncate tv_sec to 32 bits, and does it wrap where
//              tv_sec * 1e9 passes 2^64 (18446744074 s is 2^64 ns + 0.29 s;
//              36893488148 s is 2^65 ns + 0.58 s)?
//              Also whether `rem` is written when nothing interrupts, and an
//              unmapped `rem` with nothing interrupting.
//   zero     - 1000 calls each of a zero-length nanosleep, a 1 ns one, an
//              absolute clock_nanosleep in the past, sched_yield and getppid:
//              voluntary and involuntary context switches, and the time
//              taken. Does a sleep that ends at once still give up the CPU?
//   eintr    - a 2 s sleep that a caught USR1, sent to the thread 100 ms in by
//              a helper thread that blocks everything, ends. Ten trials with
//              `rem`, the excess range, and the remainder's nanosecond digits.
//              Then SA_RESTART; `rem` null; `rem` unmapped; `rem` the same
//              pointer as the request. On Linux, the timer slack (prctl) at
//              its default and at 1 ns.
//   ignored  - a 400 ms sleep. USR2 under SIG_IGN at 100 ms, URG at its
//              default (ignore) at 200 ms, USR1 caught but blocked at 300 ms:
//              does any of them end it?
//   stopcont - the parent stops the sleeping child with STOP 100 ms into a 2 s
//              sleep, continues it 500 ms later, and the child reports. With
//              and without a handler for CONT. Then a 300 ms sleep stopped for
//              longer than it had left.
//   clock    - (Linux) clock_nanosleep: every clock id from -2 to 24,
//              relative 1 ms and absolute at 0 (the past), through glibc
//              (which returns the error) and the raw system call (which
//              returns -1 and sets errno); errno is set to a sentinel first,
//              to show whether glibc's wrapper touches it. The CPU-time
//              clocks with a spinning helper. Then the order of the screens:
//              an invalid clock, a clock that cannot sleep, a null request
//              and an invalid tv_nsec, in combination. Then the flags word.
//   abs      - (Linux) TIMER_ABSTIME: a deadline 50 ms ahead on MONOTONIC,
//              REALTIME and BOOTTIME; a deadline in the past; negative
//              tv_sec; an invalid tv_nsec in the past. Then interrupted by
//              USR1 at 100 ms into 2 s: the return, and whether `rem` is
//              written, with and without SA_RESTART. Then a relative
//              clock_nanosleep on MONOTONIC interrupted the same way.
//   step     - (Linux, needs CAP_SYS_TIME) the realtime clock is stepped by a
//              helper 100 ms into a sleep: an absolute REALTIME sleep with the
//              clock stepped forward past its deadline, and stepped back; a
//              relative REALTIME clock_nanosleep, a nanosleep and an absolute
//              MONOTONIC sleep, with the clock stepped forward. The step is
//              undone after each row.
//
// Bounded: GUARD_MAIN (300 s), GUARD_CHILD (10 s) in every child, and every
// loop over a fixed list.
//
// Darwin: clang -Wall -Wno-unused-function -Wno-deprecated-declarations -o /tmp/nanosleep-edges nanosleep-edges.c && /tmp/nanosleep-edges
// Linux:  container run --rm --cap-add SYS_TIME -v "$PWD":/probe debian:trixie sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -Wno-unused-function -pthread -o /tmp/p /probe/nanosleep-edges.c && /tmp/p'
//
// Run on Darwin 27.0.0 (arm64, uid 501) and Linux 6.18.5 (aarch64, glibc
// 2.41, root in Apple's `container`, with CAP_SYS_TIME), 2026-10-11; the
// output is beside this file as nanosleep-edges.darwin-27.0-uid501.txt and
// nanosleep-edges.linux-6.18.5-aarch64.txt. Measured:
//   args     both: tv_nsec outside [0, 1e9) and tv_sec < 0 are EINVAL, at
//            once, with `rem` untouched (an unmapped `rem` too). `rem` is
//            never written by a sleep that runs its course, and an unmapped
//            one is not noticed then. A null request is EFAULT on Linux and
//            EINVAL on Darwin; an unmapped one is EFAULT on Linux and kills
//            a Darwin process with SIGSEGV (its C library reads it).
//            Huge requests: Linux saturates the deadline at KTIME_MAX
//            (2^63-1 ns since boot), so the remainder of every request past
//            it reads KTIME_MAX less the uptime. Darwin's sleep does not end
//            early for any of them (not at 2^32 s, nor where tv_sec * 1e9
//            passes 2^64), but its `rem` is the request's tv_sec modulo 2^32
//            less the time slept, and 0 once that has passed: 2^32+10 s
//            interrupted at 100 ms leaves 9.9 s, and 2^32+1 s interrupted
//            at 3 s leaves 0. It counts from the uptime, not the epoch:
//            2^32-1e9 s, which would wrap from the epoch, leaves 3294967295.9 s.
//   zero     Linux: a zero-length or 1 ns nanosleep blocks every time (1000
//            voluntary switches in 1000 calls, about 71 us each, which is
//            the 50 us timer slack); an absolute clock_nanosleep in the past
//            blocks too (about 3-5 us each). Darwin: a zero-length nanosleep
//            returns with no switch at all; a 1 ns one counts an involuntary
//            switch each time.
//   eintr    both: EINTR, with or without SA_RESTART. `rem` is the time to
//            the deadline: on Darwin to within 1-3 us of the request less
//            the time slept, with nanosecond digits; on Linux it is longer
//            by the task's timer slack (excess 55-63 us at the default 50 us,
//            5-17 us at 1 ns, 1.006-1.011 ms at 1 ms), since Linux reports
//            the time to the timer's latest expiry. A null `rem` is plain
//            EINTR. An unmapped `rem` makes the interrupted call fail with
//            EFAULT on Linux, and kills a Darwin process with SIGSEGV.
//   ignored  both: neither an ignored signal, nor one at a default that
//            ignores, nor a blocked one ends the sleep.
//   stopcont both: with no handler for CONT, a stopped and continued sleep
//            returns 0 at its original deadline (2000 ms), or at the
//            continue when that is later. Linux has written `rem` (as at the
//            stop) even so; Darwin has not. With a handler for CONT: EINTR on
//            both, Linux's `rem` as at the stop, Darwin's as at the continue;
//            and when the deadline passed during the stop, Linux still EINTR
//            but Darwin 0.
//   clock    Linux: clock_nanosleep sleeps on REALTIME (0), MONOTONIC (1),
//            PROCESS_CPUTIME (2, ending once the process has used the CPU
//            time), BOOTTIME (7) and TAI (11). THREAD_CPUTIME (3) is EINVAL
//            from glibc and EOPNOTSUPP from the system call. MONOTONIC_RAW
//            and the two COARSE clocks (4, 5, 6) are EOPNOTSUPP; the two
//            ALARM clocks (8, 9) EPERM without CAP_WAKE_ALARM; every other id
//            from -2 to 24, the auxiliary clocks 16-23 included, EINVAL.
//            glibc returns the error and leaves errno alone; the system call
//            returns -1 and sets errno. Absolute and relative agree.
//            Screens, in order: the clock (EINVAL), whether it can sleep
//            (EOPNOTSUPP), reading the request (EFAULT), the request
//            (EINVAL). Only bit 0 of the flags is read: 2, -2 and 256 sleep
//            relative, 3 and -1 absolute.
//   abs      Linux: an absolute deadline on MONOTONIC, REALTIME, BOOTTIME
//            or TAI ends on time; one in the past returns 0 at once. A
//            signal ends an absolute sleep with EINTR, SA_RESTART or not,
//            and `rem` is never written; a relative clock_nanosleep is
//            EINTR with `rem`, as nanosleep is.
//   step     Linux: stepping the realtime clock forward past an absolute
//            REALTIME deadline ends the sleep at the step (101 ms); stepping
//            it back 1 s lengthens a 500 ms sleep to 1503 ms. A relative
//            REALTIME clock_nanosleep, a nanosleep and an absolute MONOTONIC
//            sleep run their 1000 ms whatever the step.
#include "signal-probe-common.h"
#include <limits.h>
#include <stdarg.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#ifndef __APPLE__
#include <sys/prctl.h>
#endif

#define NS 1000000000LL

static int g_out = -1;

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...)
{
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (write(g_out, line, strlen(line)) < 0) _exit(98);
}

static int64_t mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * NS + ts.tv_nsec;
}

static void *unmapped_page(void)
{
    long page = sysconf(_SC_PAGESIZE);
    void *p = mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED) die("mmap");
    if (munmap(p, (size_t)page) != 0) die("munmap");
    return p;
}

#define SENTINEL_SEC ((time_t)0x5a5a5a5a)
#define SENTINEL_NSEC (0x5a5a5a5aL)

static void sentinel(struct timespec *t)
{
    t->tv_sec = SENTINEL_SEC;
    t->tv_nsec = SENTINEL_NSEC;
}

static void print_rem(const struct timespec *rem)
{
    if (rem->tv_sec == SENTINEL_SEC && rem->tv_nsec == SENTINEL_NSEC)
        out(" rem=-");
    else
        out(" rem=%lld.%09ld", (long long)rem->tv_sec, (long)rem->tv_nsec);
}

static void on_signal(int s) { (void)s; }

static void catch_flags(int s, int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = flags;
    if (sigaction(s, &sa, NULL) != 0) die("sigaction");
}

static void disposition(int s, void (*h)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h;
    if (sigaction(s, &sa, NULL) != 0) die("sigaction");
}

static void block_all(void)
{
    sigset_t all;
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, NULL);
}

// The helper: blocks every signal, then sends each of up to four signals to
// the main thread at its offset from the start, in milliseconds.
struct plan { int n; int sig[4]; int at_ms[4]; };
static struct plan g_plan;
static pthread_t g_main;

static void *sender(void *arg)
{
    (void)arg;
    block_all();
    int64_t start = mono_ns();
    for (int i = 0; i < g_plan.n; i++) {
        int64_t due = start + (int64_t)g_plan.at_ms[i] * 1000000LL;
        int64_t now;
        while ((now = mono_ns()) < due) {
            struct timespec t = { (time_t)((due - now) / NS), (long)((due - now) % NS) };
            nanosleep(&t, NULL);
        }
        pthread_kill(g_main, g_plan.sig[i]);
    }
    return NULL;
}

static pthread_t start_sender(int n, const int *sig, const int *at_ms)
{
    g_plan.n = n;
    for (int i = 0; i < n; i++) {
        g_plan.sig[i] = sig[i];
        g_plan.at_ms[i] = at_ms[i];
    }
    g_main = pthread_self();
    pthread_t t;
    if (pthread_create(&t, NULL, sender, NULL) != 0) die("pthread_create");
    return t;
}

static pthread_t usr1_at(int ms)
{
    int sig[] = { SIGUSR1 };
    int at[] = { ms };
    return start_sender(1, sig, at);
}

// Run `body` in a child that reports through the pipe, and print the row.
static void in_child(const char *tag, void (*body)(void *), void *arg)
{
    int fds[2];
    if (pipe(fds) != 0) die("pipe");
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        GUARD_CHILD();
        close(fds[0]);
        g_out = fds[1];
        body(arg);
        _exit(0);
    }
    close(fds[1]);
    char buf[4096];
    size_t len = 0;
    ssize_t r;
    while (len < sizeof buf - 1 && (r = read(fds[0], buf + len, sizeof buf - 1 - len)) > 0) len += (size_t)r;
    buf[len] = 0;
    close(fds[0]);
    int status;
    waitpid(child, &status, 0);
    printf("%s%s end=%s%d\n", tag, buf, WIFEXITED(status) ? "exit" : "signal",
           WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
    fflush(stdout);
}

// One nanosleep, reported.
static void sleep_report(const struct timespec *req, struct timespec *rem)
{
    int64_t start = mono_ns();
    errno = 0;
    int ret = nanosleep(req, rem);
    int err = errno;
    int64_t el = mono_ns() - start;
    out(" ret=%d errno=%d el=%lldus", ret, ret == 0 ? 0 : err, (long long)(el / 1000));
}

// ---- args ----

struct args_row { time_t sec; long nsec; int req_kind; int rem_kind; int usr1_ms; };
// req_kind: 0 the timespec, 1 NULL, 2 unmapped. rem_kind: 0 a sentinel, 1 NULL, 2 unmapped.

static void args_body(void *arg)
{
    struct args_row *row = arg;
    catch_flags(SIGUSR1, 0);
    struct timespec req = { row->sec, row->nsec };
    struct timespec rem;
    sentinel(&rem);
    const struct timespec *reqp = row->req_kind == 0 ? &req : row->req_kind == 1 ? NULL : unmapped_page();
    struct timespec *remp = row->rem_kind == 0 ? &rem : row->rem_kind == 1 ? NULL : unmapped_page();
    pthread_t t = 0;
    if (row->usr1_ms > 0) t = usr1_at(row->usr1_ms);
    sleep_report(reqp, remp);
    if (row->rem_kind == 0) print_rem(&rem);
    if (row->usr1_ms > 0) pthread_join(t, NULL);
}

static void args_section(void)
{
    struct { const char *name; struct args_row row; } rows[] = {
        { "req=NULL", { 0, 0, 1, 0, 0 } },
        { "req=unmapped", { 0, 0, 2, 0, 0 } },
        { "nsec=1e9", { 0, 1000000000L, 0, 0, 0 } },
        { "nsec=1e9-1", { 0, 999999999L, 0, 0, 0 } },
        { "nsec=-1", { 0, -1L, 0, 0, 2000 } },
        { "sec=1,nsec=-1", { 1, -1L, 0, 0, 2000 } },
        { "nsec=LONG_MIN", { 0, LONG_MIN, 0, 0, 2000 } },
        { "sec=-1", { -1, 0, 0, 0, 0 } },
        { "sec=-1,nsec=1e9", { -1, 1000000000L, 0, 0, 0 } },
        { "sec=-1,unmapped-rem", { -1, 0, 0, 2, 0 } },
        { "1ms rem-written?", { 0, 1000000L, 0, 0, 0 } },
        { "1ms rem=unmapped", { 0, 1000000L, 0, 2, 0 } },
        { "sec=2^31", { (time_t)1 << 31, 0, 0, 0, 100 } },
        { "sec=2^32+10", { ((time_t)1 << 32) + 10, 0, 0, 0, 100 } },
        { "sec=2^33+10", { ((time_t)1 << 33) + 10, 0, 0, 0, 100 } },
        { "sec=2^32-1e9", { ((time_t)1 << 32) - 1000000000LL, 0, 0, 0, 100 } },
        { "sec=2^32,nsec=2e8", { (time_t)1 << 32, 200000000L, 0, 0, 2000 } },
        { "sec=2^32+1", { ((time_t)1 << 32) + 1, 0, 0, 0, 3000 } },
        { "sec=18446744073", { 18446744073LL, 0, 0, 0, 2000 } },
        { "sec=18446744074", { 18446744074LL, 0, 0, 0, 2000 } },
        { "sec=36893488148", { 36893488148LL, 0, 0, 0, 2000 } },
        { "sec=9223372035", { 9223372035LL, 0, 0, 0, 100 } },
        { "sec=9223372037", { 9223372037LL, 0, 0, 0, 100 } },
        { "sec=INT64_MAX,nsec=1e9-1", { (time_t)INT64_MAX, 999999999L, 0, 0, 100 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char tag[128];
        snprintf(tag, sizeof tag, "args %s%s", rows[i].name, rows[i].row.usr1_ms ? " (USR1 later)" : "");
        in_child(tag, args_body, &rows[i].row);
    }
}

// ---- zero ----

static long switches(int voluntary)
{
    struct rusage ru;
#ifdef __APPLE__
    getrusage(RUSAGE_SELF, &ru);
#else
    getrusage(RUSAGE_THREAD, &ru);
#endif
    return voluntary ? ru.ru_nvcsw : ru.ru_nivcsw;
}

static void zero_body(void *arg)
{
    int which = *(int *)arg;
    struct timespec zero = { 0, 0 };
    struct timespec one = { 0, 1 };
    long v0 = switches(1), i0 = switches(0);
    int64_t start = mono_ns();
    int fails = 0;
    for (int i = 0; i < 1000; i++) {
        switch (which) {
        case 0: fails += nanosleep(&zero, NULL) != 0; break;
        case 1: fails += nanosleep(&one, NULL) != 0; break;
        case 2: sched_yield(); break;
        case 3: getppid(); break;
#ifndef __APPLE__
        case 4: fails += clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &zero, NULL) != 0; break;
#endif
        }
    }
    int64_t el = mono_ns() - start;
    out(" fails=%d voluntary=%ld involuntary=%ld total=%lldus", fails, switches(1) - v0, switches(0) - i0,
        (long long)(el / 1000));
}

static void zero_section(void)
{
    const char *names[] = { "nanosleep{0,0}", "nanosleep{0,1}", "sched_yield", "getppid", "clock_nanosleep-abs{0,0}" };
#ifdef __APPLE__
    int n = 4;
#else
    int n = 5;
#endif
    for (int i = 0; i < n; i++) {
        char tag[128];
        snprintf(tag, sizeof tag, "zero %s x1000", names[i]);
        in_child(tag, zero_body, &i);
    }
}

// ---- eintr ----

struct eintr_row { int flags; int rem_kind; int same_pointer; long slack; time_t sec; };
// rem_kind: 0 a sentinel, 1 NULL, 2 unmapped. slack: 0 leave it, else prctl it.

static int64_t g_excess_min, g_excess_max;

static void eintr_once(struct eintr_row *row, int verbose)
{
    struct timespec req = { row->sec, 0 };
    struct timespec rem;
    sentinel(&rem);
    struct timespec *remp = row->rem_kind == 0 ? &rem : row->rem_kind == 1 ? NULL : unmapped_page();
    if (row->same_pointer) remp = &req;
    pthread_t t = usr1_at(100);
    int64_t start = mono_ns();
    errno = 0;
    int ret = nanosleep(&req, remp);
    int err = errno;
    int64_t el = mono_ns() - start;
    pthread_join(t, NULL);
    const struct timespec *written = row->same_pointer ? &req : &rem;
    int64_t excess = 0;
    if (row->rem_kind == 0 && !(written->tv_sec == SENTINEL_SEC && written->tv_nsec == SENTINEL_NSEC))
        excess = (int64_t)written->tv_sec * NS + written->tv_nsec + el - (int64_t)row->sec * NS;
    if (excess < g_excess_min) g_excess_min = excess;
    if (excess > g_excess_max) g_excess_max = excess;
    if (verbose) {
        out(" ret=%d errno=%d el=%lldus", ret, ret == 0 ? 0 : err, (long long)(el / 1000));
        if (row->rem_kind == 0) {
            print_rem(written);
            out(" excess=%lldns", (long long)excess);
        }
    } else {
        out(" %d/%d/%lld.%09ld/%lld", ret, ret == 0 ? 0 : err, (long long)written->tv_sec, (long)written->tv_nsec,
            (long long)excess);
    }
}

static void eintr_body(void *arg)
{
    struct eintr_row *row = arg;
    catch_flags(SIGUSR1, row->flags);
#ifndef __APPLE__
    if (row->slack) {
        if (prctl(PR_SET_TIMERSLACK, row->slack, 0, 0, 0) != 0) die("prctl");
    }
    out(" slack=%ldns", (long)prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
#endif
    eintr_once(row, 1);
}

static void eintr_trials_body(void *arg)
{
    struct eintr_row *row = arg;
    catch_flags(SIGUSR1, row->flags);
#ifndef __APPLE__
    if (row->slack) {
        if (prctl(PR_SET_TIMERSLACK, row->slack, 0, 0, 0) != 0) die("prctl");
    }
    out(" slack=%ldns", (long)prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0));
#endif
    g_excess_min = INT64_MAX;
    g_excess_max = INT64_MIN;
    out(" ret/errno/rem/excess:");
    for (int i = 0; i < 10; i++) eintr_once(row, 0);
    out(" excess-range=[%lld,%lld]ns", (long long)g_excess_min, (long long)g_excess_max);
}

static void eintr_section(void)
{
    struct eintr_row base = { 0, 0, 0, 0, 2 };
    in_child("eintr trials", eintr_trials_body, &base);
#ifndef __APPLE__
    struct eintr_row slack1 = { 0, 0, 0, 1, 2 };
    in_child("eintr trials slack=1", eintr_trials_body, &slack1);
    struct eintr_row slack1ms = { 0, 0, 0, 1000000, 2 };
    in_child("eintr trials slack=1ms", eintr_trials_body, &slack1ms);
#endif
    struct { const char *name; struct eintr_row row; } rows[] = {
        { "SA_RESTART", { SA_RESTART, 0, 0, 0, 2 } },
        { "rem=NULL", { 0, 1, 0, 0, 2 } },
        { "rem=NULL SA_RESTART", { SA_RESTART, 1, 0, 0, 2 } },
        { "rem=unmapped", { 0, 2, 0, 0, 2 } },
        { "rem=req", { 0, 0, 1, 0, 2 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char tag[128];
        snprintf(tag, sizeof tag, "eintr %s", rows[i].name);
        in_child(tag, eintr_body, &rows[i].row);
    }
}

// ---- ignored ----

static void ignored_body(void *arg)
{
    (void)arg;
    disposition(SIGUSR2, SIG_IGN);
    disposition(SIGURG, SIG_DFL);
    catch_flags(SIGUSR1, 0);
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
    int sig[] = { SIGUSR2, SIGURG, SIGUSR1 };
    int at[] = { 100, 200, 300 };
    pthread_t t = start_sender(3, sig, at);
    struct timespec req = { 0, 400000000L };
    struct timespec rem;
    sentinel(&rem);
    sleep_report(&req, &rem);
    print_rem(&rem);
    pthread_join(t, NULL);
    sigset_t pending;
    sigpending(&pending);
    out(" USR1-pending-after=%d", sigismember(&pending, SIGUSR1));
}

// ---- stopcont ----

struct stop_row { int cont_handler; time_t sec; long nsec; int stop_ms; int abs; };

static void stopcont(const char *tag, struct stop_row *row)
{
    int fds[2];
    if (pipe(fds) != 0) die("pipe");
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        GUARD_CHILD();
        close(fds[0]);
        g_out = fds[1];
        catch_flags(SIGUSR1, 0);
        if (row->cont_handler) catch_flags(SIGCONT, 0);
        struct timespec req = { row->sec, row->nsec };
        struct timespec rem;
        sentinel(&rem);
        int64_t start = mono_ns();
        int ret, err;
        errno = 0;
#ifndef __APPLE__
        if (row->abs) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            struct timespec until = { now.tv_sec + row->sec, now.tv_nsec + row->nsec };
            if (until.tv_nsec >= NS) {
                until.tv_sec++;
                until.tv_nsec -= NS;
            }
            ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, &rem);
            err = ret;
        } else
#endif
        {
            ret = nanosleep(&req, &rem);
            err = errno;
        }
        int64_t el = mono_ns() - start;
        out(" ret=%d errno=%d el=%lldms", ret, ret == 0 ? 0 : err, (long long)(el / 1000000));
        print_rem(&rem);
        _exit(0);
    }
    close(fds[1]);
    sleep_ms(100);
    kill(child, SIGSTOP);
    int status;
    pid_t w = waitpid(child, &status, WUNTRACED);
    int stopped = w == child && WIFSTOPPED(status);
    sleep_ms(row->stop_ms);
    kill(child, SIGCONT);
    char buf[1024];
    size_t len = 0;
    ssize_t r;
    while (len < sizeof buf - 1 && (r = read(fds[0], buf + len, sizeof buf - 1 - len)) > 0) len += (size_t)r;
    buf[len] = 0;
    close(fds[0]);
    waitpid(child, &status, 0);
    printf("%s stopped=%d%s end=%s%d\n", tag, stopped, buf, WIFEXITED(status) ? "exit" : "signal",
           WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
    fflush(stdout);
}

static void stopcont_section(void)
{
    struct { const char *name; struct stop_row row; } rows[] = {
        { "2s stop@100ms for 500ms cont-handler=0", { 0, 2, 0, 500, 0 } },
        { "2s stop@100ms for 500ms cont-handler=1", { 1, 2, 0, 500, 0 } },
        { "300ms stop@100ms for 500ms cont-handler=0", { 0, 0, 300000000L, 500, 0 } },
        { "300ms stop@100ms for 500ms cont-handler=1", { 1, 0, 300000000L, 500, 0 } },
#ifndef __APPLE__
        { "abs-monotonic 2s stop@100ms for 500ms cont-handler=0", { 0, 2, 0, 500, 1 } },
        { "abs-monotonic 2s stop@100ms for 500ms cont-handler=1", { 1, 2, 0, 500, 1 } },
#endif
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char tag[160];
        snprintf(tag, sizeof tag, "stopcont %s", rows[i].name);
        stopcont(tag, &rows[i].row);
    }
}

#ifndef __APPLE__

// ---- clock ----

struct clock_row { int clock; int abs; int spin; };

static volatile int g_spin;

static void *spinner(void *arg)
{
    (void)arg;
    block_all();
    while (__atomic_load_n(&g_spin, __ATOMIC_RELAXED)) {}
    return NULL;
}

static void clock_body(void *arg)
{
    struct clock_row *row = arg;
    pthread_t t = 0;
    if (row->spin) {
        g_spin = 1;
        if (pthread_create(&t, NULL, spinner, NULL) != 0) die("pthread_create");
    }
    struct timespec rel = { 0, 1000000L };
    struct timespec past = { 0, 0 };
    const struct timespec *req = row->abs ? &past : &rel;
    int flags = row->abs ? TIMER_ABSTIME : 0;
    int64_t start = mono_ns();
    errno = 12345;
    int ret = clock_nanosleep((clockid_t)row->clock, flags, req, NULL);
    int err = errno;
    int64_t el = mono_ns() - start;
    out(" glibc=%d errno-after=%d el=%lldus", ret, err, (long long)(el / 1000));
    start = mono_ns();
    errno = 0;
    long raw = syscall(SYS_clock_nanosleep, row->clock, flags, req, NULL);
    err = errno;
    el = mono_ns() - start;
    out(" raw=%ld errno=%d el=%lldus", raw, raw == 0 ? 0 : err, (long long)(el / 1000));
    if (row->spin) {
        g_spin = 0;
        pthread_join(t, NULL);
    }
}

static void clock_section(void)
{
    for (int abs = 0; abs <= 1; abs++) {
        for (int c = -2; c <= 24; c++) {
            struct clock_row row = { c, abs, c == CLOCK_PROCESS_CPUTIME_ID || c == CLOCK_THREAD_CPUTIME_ID || c < 0 };
            char tag[128];
            snprintf(tag, sizeof tag, "clock id=%d %s%s", c, abs ? "abs{0,0}" : "rel1ms", row.spin ? " spin" : "");
            in_child(tag, clock_body, &row);
        }
    }
}

// Screen order: the raw system call with each combination of a clock that
// is invalid (99), one that cannot sleep (MONOTONIC_RAW), or MONOTONIC; a
// request that is NULL, unmapped, has tv_nsec 1e9, or is valid in the past;
// and the flags word.
struct order_row { int clock; int req_kind; int flags; };

static void order_body(void *arg)
{
    struct order_row *row = arg;
    struct timespec bad = { 0, 1000000000L };
    struct timespec past = { 0, 0 };
    struct timespec negative = { -1, 0 };
    struct timespec rel = { 0, 1000000L };
    const struct timespec *req = row->req_kind == 0   ? NULL
                                 : row->req_kind == 1 ? unmapped_page()
                                 : row->req_kind == 2 ? &bad
                                 : row->req_kind == 3 ? &past
                                 : row->req_kind == 4 ? &negative
                                                      : &rel;
    struct timespec rem;
    sentinel(&rem);
    int64_t start = mono_ns();
    errno = 0;
    long raw = syscall(SYS_clock_nanosleep, row->clock, row->flags, req, &rem);
    int err = errno;
    int64_t el = mono_ns() - start;
    out(" raw=%ld errno=%d el=%lldus", raw, raw == 0 ? 0 : err, (long long)(el / 1000));
    print_rem(&rem);
}

static void order_section(void)
{
    const char *req_names[] = { "NULL", "unmapped", "nsec=1e9", "{0,0}", "sec=-1", "rel1ms" };
    int clocks[] = { 99, CLOCK_MONOTONIC_RAW, CLOCK_MONOTONIC };
    int flags[] = { 0, TIMER_ABSTIME };
    for (int c = 0; c < 3; c++)
        for (int r = 0; r < 5; r++)
            for (int f = 0; f < 2; f++) {
                struct order_row row = { clocks[c], r, flags[f] };
                char tag[128];
                snprintf(tag, sizeof tag, "order clock=%d req=%s flags=%d", clocks[c], req_names[r], flags[f]);
                in_child(tag, order_body, &row);
            }
    int odd_flags[] = { 2, 3, -1, -2, 0x100 };
    for (int f = 0; f < 5; f++) {
        // A relative 1 ms request read as absolute is in the past, and ends at once.
        struct order_row row = { CLOCK_MONOTONIC, 5, odd_flags[f] };
        char tag[128];
        snprintf(tag, sizeof tag, "flags clock=MONOTONIC req=rel1ms flags=%d", odd_flags[f]);
        in_child(tag, order_body, &row);
    }
}

// ---- abs ----

struct abs_row { int clock; int64_t offset_ms; int restart; int usr1; int abs; };

static void abs_body(void *arg)
{
    struct abs_row *row = arg;
    catch_flags(SIGUSR1, row->restart ? SA_RESTART : 0);
    struct timespec now;
    clock_gettime((clockid_t)row->clock, &now);
    int64_t target = row->abs ? (int64_t)now.tv_sec * NS + now.tv_nsec + row->offset_ms * 1000000LL : row->offset_ms * 1000000LL;
    struct timespec req = { (time_t)(target / NS), (long)(target % NS) };
    struct timespec rem;
    sentinel(&rem);
    pthread_t t = 0;
    if (row->usr1) t = usr1_at(100);
    int64_t start = mono_ns();
    errno = 12345;
    int ret = clock_nanosleep((clockid_t)row->clock, row->abs ? TIMER_ABSTIME : 0, &req, &rem);
    int err = errno;
    int64_t el = mono_ns() - start;
    if (row->usr1) pthread_join(t, NULL);
    out(" ret=%d errno-after=%d el=%lldus", ret, err, (long long)(el / 1000));
    print_rem(&rem);
}

static void abs_section(void)
{
    struct { const char *name; struct abs_row row; } rows[] = {
        { "MONOTONIC +50ms", { CLOCK_MONOTONIC, 50, 0, 0, 1 } },
        { "REALTIME +50ms", { CLOCK_REALTIME, 50, 0, 0, 1 } },
        { "BOOTTIME +50ms", { CLOCK_BOOTTIME, 50, 0, 0, 1 } },
        { "TAI +50ms", { CLOCK_TAI, 50, 0, 0, 1 } },
        { "MONOTONIC -1000ms", { CLOCK_MONOTONIC, -1000, 0, 0, 1 } },
        { "REALTIME -1000ms", { CLOCK_REALTIME, -1000, 0, 0, 1 } },
        { "MONOTONIC +2s USR1", { CLOCK_MONOTONIC, 2000, 0, 1, 1 } },
        { "MONOTONIC +2s USR1 SA_RESTART", { CLOCK_MONOTONIC, 2000, 1, 1, 1 } },
        { "REALTIME +2s USR1", { CLOCK_REALTIME, 2000, 0, 1, 1 } },
        { "relative MONOTONIC 2s USR1", { CLOCK_MONOTONIC, 2000, 0, 1, 0 } },
        { "relative MONOTONIC 2s USR1 SA_RESTART", { CLOCK_MONOTONIC, 2000, 1, 1, 0 } },
        { "relative REALTIME 2s USR1", { CLOCK_REALTIME, 2000, 0, 1, 0 } },
        { "relative BOOTTIME 2s USR1", { CLOCK_BOOTTIME, 2000, 0, 1, 0 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char tag[128];
        snprintf(tag, sizeof tag, "abs %s", rows[i].name);
        in_child(tag, abs_body, &rows[i].row);
    }
}

// ---- step ----

struct step_row { int kind; int64_t sleep_ms; int64_t step_ms; };
// kind: 0 abs REALTIME, 1 rel REALTIME clock_nanosleep, 2 nanosleep, 3 abs MONOTONIC.

static int64_t g_step_ms;
static int g_step_ret;

static void *stepper(void *arg)
{
    (void)arg;
    block_all();
    sleep_ms(100);
    struct timespec rt;
    clock_gettime(CLOCK_REALTIME, &rt);
    int64_t t = (int64_t)rt.tv_sec * NS + rt.tv_nsec + g_step_ms * 1000000LL;
    struct timespec set = { (time_t)(t / NS), (long)(t % NS) };
    g_step_ret = clock_settime(CLOCK_REALTIME, &set) == 0 ? 0 : errno;
    return NULL;
}

static void step_body(void *arg)
{
    struct step_row *row = arg;
    g_step_ms = row->step_ms;
    clockid_t clock = row->kind == 3 ? CLOCK_MONOTONIC : CLOCK_REALTIME;
    struct timespec now;
    clock_gettime(clock, &now);
    int abs = row->kind == 0 || row->kind == 3;
    int64_t target = abs ? (int64_t)now.tv_sec * NS + now.tv_nsec + row->sleep_ms * 1000000LL : row->sleep_ms * 1000000LL;
    struct timespec req = { (time_t)(target / NS), (long)(target % NS) };
    pthread_t t;
    if (pthread_create(&t, NULL, stepper, NULL) != 0) die("pthread_create");
    int64_t start = mono_ns();
    int ret;
    if (row->kind == 2)
        ret = nanosleep(&req, NULL) == 0 ? 0 : errno;
    else
        ret = clock_nanosleep(clock, abs ? TIMER_ABSTIME : 0, &req, NULL);
    int64_t el = mono_ns() - start;
    pthread_join(t, NULL);
    out(" settime=%d ret=%d el=%lldms", g_step_ret, ret, (long long)(el / 1000000));
    if (g_step_ret == 0) {
        struct timespec rt;
        clock_gettime(CLOCK_REALTIME, &rt);
        int64_t back = (int64_t)rt.tv_sec * NS + rt.tv_nsec - row->step_ms * 1000000LL;
        struct timespec set = { (time_t)(back / NS), (long)(back % NS) };
        if (clock_settime(CLOCK_REALTIME, &set) != 0) die("clock_settime undo");
    }
}

static void step_section(void)
{
    struct { const char *name; struct step_row row; } rows[] = {
        { "abs-REALTIME 1000ms, +10s at 100ms", { 0, 1000, 10000 } },
        { "abs-REALTIME 500ms, -1s at 100ms", { 0, 500, -1000 } },
        { "rel-REALTIME clock_nanosleep 1000ms, +10s at 100ms", { 1, 1000, 10000 } },
        { "nanosleep 1000ms, +10s at 100ms", { 2, 1000, 10000 } },
        { "abs-MONOTONIC 1000ms, +10s at 100ms", { 3, 1000, 10000 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char tag[128];
        snprintf(tag, sizeof tag, "step %s", rows[i].name);
        in_child(tag, step_body, &rows[i].row);
    }
}

#endif

int main(void)
{
    GUARD_MAIN();
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d, flavour %s\n", u.sysname, u.release, u.machine, (int)getuid(), FLAVOUR);
#ifndef __APPLE__
    printf("# CLOCK ids: REALTIME=%d MONOTONIC=%d PROCESS_CPUTIME=%d THREAD_CPUTIME=%d MONOTONIC_RAW=%d "
           "REALTIME_COARSE=%d MONOTONIC_COARSE=%d BOOTTIME=%d REALTIME_ALARM=%d BOOTTIME_ALARM=%d TAI=%d; "
           "EINVAL=%d EFAULT=%d EOPNOTSUPP=%d ENOTSUP=%d EPERM=%d ENODEV=%d EINTR=%d\n",
           CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW,
           CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME, CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
           CLOCK_TAI, EINVAL, EFAULT, EOPNOTSUPP, ENOTSUP, EPERM, ENODEV, EINTR);
#else
    printf("# EINVAL=%d EFAULT=%d EINTR=%d ETIMEDOUT=%d\n", EINVAL, EFAULT, EINTR, ETIMEDOUT);
#endif
    fflush(stdout);
    args_section();
    zero_section();
    eintr_section();
    in_child("ignored USR2(SIG_IGN)@100 URG(default)@200 USR1(blocked)@300 in 400ms", ignored_body, NULL);
    stopcont_section();
#ifndef __APPLE__
    clock_section();
    order_section();
    abs_section();
    step_section();
#endif
    return 0;
}
