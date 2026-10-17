// What Linux's futex(2) answers for the private wait and wake that a client
// asks the kernel for (FUTEX_WAIT_PRIVATE, with or without a relative timeout,
// and FUTEX_WAKE_PRIVATE), and in what order, so that the kernel's model of the
// two can be held to it. Linux only: Darwin has no futex(2).
//
// Build and run (root, for the `race` rows, which need SCHED_FIFO):
//   container run --rm --cap-add ALL -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1), container --cap-add ALL" && gcc -Wall -O1 -pthread -o /tmp/p /probe/futex.c && /tmp/p'
//
// Every row runs in a fresh forked child, so no row sees another's threads,
// mask or dispositions; a row whose child a signal kills reports
// `end=signalN`, and a child that hangs is killed by its own alarm
// (`end=signal14`).
//
// Fields: `ret` and `errno` are what the call returned (errno=0 on success);
// `took` is its duration in milliseconds; a waiter's `at` is the millisecond,
// from the row's start, at which its call returned; `handled` is the
// millisecond at which the handler ran, or `-` for never; `woke` is what a
// FUTEX_WAKE returned.
//
// "Unmapped" memory is a PROT_NONE page, which a thread's stack mapping cannot
// later land on, as it could on a page mapped and then unmapped.
//
// Sections:
//   wait-screen  - FUTEX_WAIT_PRIVATE on every combination of an address
//                  (the word matching, not matching, misaligned, unmapped,
//                  unmapped and misaligned, null) and a timeout (none for the
//                  non-blocking addresses, 10 ms, zero, tv_nsec 1e9, tv_nsec
//                  -1, tv_sec -1, an unmapped timespec): which answer wins.
//   wake-screen  - FUTEX_WAKE_PRIVATE of 1 on an address with no waiters,
//                  misaligned, unmapped, unmapped and misaligned, and null.
//   compare      - the comparison is of 32-bit words: a word of 0xFFFFFFFF
//                  against val -1.
//   switches     - voluntary context switches over 1000 waits with a zero
//                  timeout, a 1 ns timeout, and a mismatching word: does the
//                  call sleep before answering?
//   huge         - relative timeouts too large for the clock (tv_sec
//                  9223372035, 9223372036 and INT64_MAX): an error, a timeout,
//                  or a sleep that a wake ends 100 ms in?
//   count        - FUTEX_WAKE_PRIVATE with n of 0, 1, 2, INT_MAX, -1 and
//                  INT_MIN on an address with 0, 1 and 3 waiters: what it
//                  returns, and how many waiters returned.
//   order        - three waiters parked in the order A, B, C, each asleep
//                  (state S in /proc) before the next starts; FUTEX_WAKE 1
//                  three times, 30 ms apart: who returns each time. Then the
//                  same with each waiter waiting again once woken (`rewait`),
//                  and six wakes; and one wake of 2.
//   signal       - a waiter, asleep on a matching word, is sent a signal by
//                  pthread_kill 100 ms in; FUTEX_WAKE 1 at 300 ms. With a
//                  handler and flags 0 or SA_RESTART, untimed or with a 2 s
//                  timeout; a handler that stores 1 to the word (does a
//                  restarted wait read it again?); SIG_IGN; URG at its default
//                  (ignore); the signal blocked by the waiter.
//   stop         - the row's process P stops a child C with SIGSTOP 100 ms
//                  into C's wait, optionally stores 1 to the (shared) word,
//                  and continues C 100 ms later; no handler runs. C's own main
//                  thread wakes the word at 600 ms. Untimed and with a 300 ms
//                  timeout: does the wait restart, does it read the word
//                  again, and does a restarted timeout keep its deadline?
//   race         - the sender (SCHED_FIFO 50) and the waiters (SCHED_FIFO 10)
//                  share CPU 0, so whatever the sender does between its own
//                  sleeps happens before any waiter runs. A signal and then a
//                  FUTEX_WAKE 1 before the waiter runs (handler, flags 0 or
//                  SA_RESTART, untimed or timed); a timeout that expires, and
//                  then a FUTEX_WAKE 1, before the waiter runs; a timeout
//                  that expires, and then a signal, before the waiter runs
//                  (`woke=-1`: no wake was made); whether a
//                  waiter woken by a signal or a timeout, but not yet run,
//                  keeps its place at the head of the queue; whether a waiter
//                  taken by one wake is skipped by the next. `ran-early`
//                  counts waiters that returned before the sender slept: the
//                  control, which must be 0.
//   xproc        - a child waits on a MAP_SHARED word; its parent wakes it,
//                  privately and not. A private key is the address space's.
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// ---------------------------------------------------------------- utilities

static long futex(void *addr, int op, int val, const void *timeout)
{
    return syscall(SYS_futex, addr, op, val, timeout, NULL, 0);
}

static int64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int64_t row_start;

static int64_t ms_since_start(int64_t ns)
{
    return (ns - row_start) / 1000000;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000 };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

static void sleep_until_ms(int ms)
{
    int64_t target = row_start + (int64_t)ms * 1000000;
    struct timespec ts = { target / 1000000000, target % 1000000000 };
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
    }
}

static void spin_ms(int ms)
{
    int64_t until = now_ns() + (int64_t)ms * 1000000;
    while (now_ns() < until) {
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
    case EPERM: return "EPERM";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

// One output line per row, built in the child and printed whole.
static char line[8192];

static void out(const char *fmt, ...)
{
    size_t used = strlen(line);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line + used, sizeof line - used, fmt, ap);
    va_end(ap);
}

static void run_row(const char *label, void (*fn)(const void *), const void *arg, int alarm_s)
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(alarm_s);
        line[0] = 0;
        row_start = now_ns();
        fn(arg);
        printf("%s %s\n", label, line);
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf("%s end=signal%d\n", label, WTERMSIG(status));
}

static uint32_t *prot_none_page(void)
{
    void *p = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    return p;
}

// ---------------------------------------------------------------- waiters

static atomic_int return_order;

struct waiter {
    uint32_t *addr;
    uint32_t val;
    const struct timespec *timeout;
    // The main thread lowers this while the waiter runs, to let it stop.
    atomic_int rewaits;
    int policy_fifo;
    char name;
    pthread_t thread;
    atomic_int tid;
    atomic_int returns;
    long ret[8];
    int err[8];
    int64_t start[8];
    int64_t end[8];
    int order[8];
    sigset_t block;
    int block_set;
};

static void *waiter_main(void *p)
{
    struct waiter *w = p;
    if (w->block_set)
        pthread_sigmask(SIG_BLOCK, &w->block, NULL);
    atomic_store(&w->tid, (int)gettid());
    for (int i = 0; i <= atomic_load(&w->rewaits) && i < 8; i++) {
        w->start[i] = now_ns();
        long r = futex(w->addr, FUTEX_WAIT_PRIVATE, (int)w->val, w->timeout);
        w->err[i] = r < 0 ? errno : 0;
        w->ret[i] = r;
        w->end[i] = now_ns();
        w->order[i] = atomic_fetch_add(&return_order, 1);
        atomic_store(&w->returns, i + 1);
    }
    return NULL;
}

static char thread_state(int tid)
{
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    FILE *f = fopen(path, "r");
    if (!f)
        return '?';
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *close = strrchr(buf, ')');
    return close && close[1] == ' ' ? close[2] : '?';
}

static void thread_wchan(int tid, char *out_buf, size_t size)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/wchan", tid);
    FILE *f = fopen(path, "r");
    out_buf[0] = 0;
    if (!f)
        return;
    size_t n = fread(out_buf, 1, size - 1, f);
    fclose(f);
    out_buf[n] = 0;
}

// Wait, up to 2 s, until `w` has made its call and is asleep in it.
static int wait_asleep(struct waiter *w)
{
    for (int i = 0; i < 2000; i++) {
        int tid = atomic_load(&w->tid);
        if (tid != 0 && thread_state(tid) == 'S')
            return 1;
        sleep_ms(1);
    }
    return 0;
}

static void start_waiter(struct waiter *w)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (w->policy_fifo) {
        struct sched_param sp = { .sched_priority = 10 };
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
        pthread_attr_setschedparam(&attr, &sp);
    }
    if (pthread_create(&w->thread, &attr, waiter_main, w) != 0) {
        out("pthread_create-failed");
        printf("%s\n", line);
        _exit(1);
    }
    pthread_attr_destroy(&attr);
}

// Wake everything left on `addr` and join the waiters.
static void finish(uint32_t *addr, struct waiter *ws, int count)
{
    for (int i = 0; i < 100; i++) {
        int pending = 0;
        for (int j = 0; j < count; j++)
            if (atomic_load(&ws[j].returns) <= atomic_load(&ws[j].rewaits))
                pending = 1;
        if (!pending)
            break;
        futex(addr, FUTEX_WAKE_PRIVATE, INT_MAX, NULL);
        sleep_ms(5);
    }
    for (int j = 0; j < count; j++)
        pthread_join(ws[j].thread, NULL);
}

static void report_waiter(const struct waiter *w, int call)
{
    if (atomic_load(&w->returns) <= call) {
        out(" %c=asleep", w->name);
        return;
    }
    out(" %c:ret=%ld errno=%s at=%lld", w->name, w->ret[call], errname(w->err[call]),
        (long long)ms_since_start(w->end[call]));
}

// ---------------------------------------------------------------- wait-screen

enum addr_kind { A_MATCH, A_MISMATCH, A_MISALIGNED, A_MISALIGNED_MISMATCH, A_UNMAPPED, A_UNMAPPED_MISALIGNED, A_NULL };
enum timeout_kind { T_NULL, T_10MS, T_ZERO, T_NSEC_1E9, T_NSEC_NEG, T_SEC_NEG, T_UNMAPPED };

static const char *addr_names[] = { "match", "mismatch", "misaligned", "misaligned-mismatch", "unmapped", "unmapped-misaligned", "null" };
static const char *timeout_names[] = { "null", "10ms", "zero", "nsec=1e9", "nsec=-1", "sec=-1", "unmapped" };

struct screen {
    enum addr_kind addr;
    enum timeout_kind timeout;
};

static uint32_t words[16] __attribute__((aligned(64)));

static void resolve(enum addr_kind kind, uint32_t **addr, uint32_t *val)
{
    memset(words, 0, sizeof words);
    *val = 0;
    switch (kind) {
    case A_MATCH: *addr = &words[0]; break;
    case A_MISMATCH: *addr = &words[0]; *val = 7; break;
    // Bytes 1 to 4 of a zeroed buffer: a read, were one made, would match 0.
    case A_MISALIGNED: *addr = (uint32_t *)((char *)&words[0] + 1); break;
    case A_MISALIGNED_MISMATCH: *addr = (uint32_t *)((char *)&words[0] + 1); *val = 7; break;
    case A_UNMAPPED: *addr = prot_none_page(); break;
    case A_UNMAPPED_MISALIGNED: *addr = (uint32_t *)((char *)prot_none_page() + 1); break;
    case A_NULL: *addr = NULL; break;
    }
}

static const struct timespec *resolve_timeout(enum timeout_kind kind)
{
    static struct timespec ts;
    switch (kind) {
    case T_NULL: return NULL;
    case T_10MS: ts = (struct timespec){ 0, 10000000 }; return &ts;
    case T_ZERO: ts = (struct timespec){ 0, 0 }; return &ts;
    case T_NSEC_1E9: ts = (struct timespec){ 0, 1000000000 }; return &ts;
    case T_NSEC_NEG: ts = (struct timespec){ 0, -1 }; return &ts;
    case T_SEC_NEG: ts = (struct timespec){ -1, 0 }; return &ts;
    case T_UNMAPPED: return (const struct timespec *)prot_none_page();
    }
    return NULL;
}

static void row_wait_screen(const void *arg)
{
    const struct screen *s = arg;
    uint32_t *addr;
    uint32_t val;
    resolve(s->addr, &addr, &val);
    const struct timespec *timeout = resolve_timeout(s->timeout);
    int64_t start = now_ns();
    long r = futex(addr, FUTEX_WAIT_PRIVATE, (int)val, timeout);
    int e = r < 0 ? errno : 0;
    out("ret=%ld errno=%s took=%lld", r, errname(e), (long long)((now_ns() - start) / 1000000));
}

static void section_wait_screen(void)
{
    for (int a = A_MATCH; a <= A_NULL; a++) {
        for (int t = T_NULL; t <= T_UNMAPPED; t++) {
            // A matching word with no timeout would sleep for ever.
            if (t == T_NULL && a == A_MATCH)
                continue;
            struct screen s = { a, t };
            char label[128];
            snprintf(label, sizeof label, "wait-screen addr=%s timeout=%s", addr_names[a], timeout_names[t]);
            run_row(label, row_wait_screen, &s, 2);
        }
    }
}

// ---------------------------------------------------------------- wake-screen

static void row_wake_screen(const void *arg)
{
    enum addr_kind kind = *(const enum addr_kind *)arg;
    uint32_t *addr;
    uint32_t val;
    resolve(kind, &addr, &val);
    long r = futex(addr, FUTEX_WAKE_PRIVATE, 1, NULL);
    int e = r < 0 ? errno : 0;
    out("ret=%ld errno=%s", r, errname(e));
}

static void section_wake_screen(void)
{
    enum addr_kind kinds[] = { A_MATCH, A_MISALIGNED, A_UNMAPPED, A_UNMAPPED_MISALIGNED, A_NULL };
    const char *names[] = { "aligned-no-waiters", "misaligned", "unmapped", "unmapped-misaligned", "null" };
    for (int i = 0; i < 5; i++) {
        char label[128];
        snprintf(label, sizeof label, "wake-screen addr=%s n=1", names[i]);
        run_row(label, row_wake_screen, &kinds[i], 2);
    }
}

// ---------------------------------------------------------------- compare

static void row_compare(const void *arg)
{
    (void)arg;
    words[0] = 0xFFFFFFFFu;
    struct timespec ts = { 0, 10000000 };
    long r = futex(&words[0], FUTEX_WAIT_PRIVATE, -1, &ts);
    int e = r < 0 ? errno : 0;
    out("ret=%ld errno=%s", r, errname(e));
    words[0] = 0x80000000u;
    r = futex(&words[0], FUTEX_WAIT_PRIVATE, INT_MIN, &ts);
    e = r < 0 ? errno : 0;
    out(" | word=0x80000000 val=INT_MIN ret=%ld errno=%s", r, errname(e));
}

// ---------------------------------------------------------------- switches

static long voluntary_switches(void)
{
    struct rusage ru;
    getrusage(RUSAGE_THREAD, &ru);
    return ru.ru_nvcsw;
}

static void row_switches(const void *arg)
{
    int kind = *(const int *)arg;
    words[0] = 0;
    struct timespec ts = { 0, kind == 1 ? 1 : 0 };
    uint32_t val = kind == 2 ? 7 : 0;
    int codes[8] = { 0 };
    long before = voluntary_switches();
    int64_t start = now_ns();
    for (int i = 0; i < 1000; i++) {
        long r = futex(&words[0], FUTEX_WAIT_PRIVATE, (int)val, &ts);
        int e = r < 0 ? errno : 0;
        codes[e == ETIMEDOUT ? 0 : e == EAGAIN ? 1 : e == 0 ? 2 : 3]++;
    }
    int64_t took_us = (now_ns() - start) / 1000;
    out("switches=%ld ETIMEDOUT=%d EAGAIN=%d ok=%d other=%d took-us=%lld", voluntary_switches() - before,
        codes[0], codes[1], codes[2], codes[3], (long long)took_us);
}

// ---------------------------------------------------------------- huge

static void row_huge(const void *arg)
{
    int64_t seconds = *(const int64_t *)arg;
    words[0] = 0;
    struct timespec ts = { (time_t)seconds, 0 };
    struct waiter w = { .addr = &words[0], .val = 0, .timeout = &ts, .name = 'W' };
    start_waiter(&w);
    int asleep = wait_asleep(&w);
    out("asleep=%d", asleep);
    sleep_until_ms(100);
    long woke = futex(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL);
    sleep_ms(20);
    out(" woke=%ld", woke);
    report_waiter(&w, 0);
    finish(&words[0], &w, 1);
}

// ---------------------------------------------------------------- count

struct count {
    int waiters;
    int n;
    const char *n_name;
};

static void row_count(const void *arg)
{
    const struct count *c = arg;
    words[0] = 0;
    struct waiter ws[3];
    memset(ws, 0, sizeof ws);
    for (int i = 0; i < c->waiters; i++) {
        ws[i] = (struct waiter){ .addr = &words[0], .val = 0, .name = (char)('A' + i) };
        start_waiter(&ws[i]);
        if (!wait_asleep(&ws[i]))
            out("not-asleep=%c ", ws[i].name);
    }
    long r = futex(&words[0], FUTEX_WAKE_PRIVATE, c->n, NULL);
    int e = r < 0 ? errno : 0;
    sleep_ms(50);
    int returned = 0;
    for (int i = 0; i < c->waiters; i++)
        if (atomic_load(&ws[i].returns) > 0)
            returned++;
    out("ret=%ld errno=%s returned=%d", r, errname(e), returned);
    for (int i = 0; i < c->waiters; i++)
        report_waiter(&ws[i], 0);
    finish(&words[0], ws, c->waiters);
}

// ---------------------------------------------------------------- order

struct order {
    int rewait;
    int wakes;
    int n;
};

static void row_order(const void *arg)
{
    const struct order *o = arg;
    words[0] = 0;
    struct waiter ws[3];
    memset(ws, 0, sizeof ws);
    char wchan[64] = "";
    for (int i = 0; i < 3; i++) {
        ws[i] = (struct waiter){ .addr = &words[0], .val = 0, .rewaits = o->rewait ? 7 : 0, .name = (char)('A' + i) };
        start_waiter(&ws[i]);
        if (!wait_asleep(&ws[i]))
            out("not-asleep=%c ", ws[i].name);
        if (i == 0)
            thread_wchan(atomic_load(&ws[0].tid), wchan, sizeof wchan);
    }
    out("wchan=%s woke=", wchan[0] ? wchan : "-");
    for (int k = 0; k < o->wakes; k++) {
        int before[3];
        for (int i = 0; i < 3; i++)
            before[i] = atomic_load(&ws[i].returns);
        long r = futex(&words[0], FUTEX_WAKE_PRIVATE, o->n, NULL);
        sleep_ms(30);
        out("%s%ld:", k ? "," : "", r);
        for (int i = 0; i < 3; i++)
            if (atomic_load(&ws[i].returns) > before[i])
                out("%c", ws[i].name);
        // A woken rewaiter must be asleep again before the next wake.
        if (o->rewait)
            for (int i = 0; i < 3; i++)
                if (atomic_load(&ws[i].returns) > before[i])
                    wait_asleep(&ws[i]);
    }
    for (int i = 0; i < 3; i++)
        atomic_store(&ws[i].rewaits, atomic_load(&ws[i].returns));
    // Rewaiters loop for ever otherwise: let each fall out at its next return.
    finish(&words[0], ws, 3);
}

static void section_order(void)
{
    for (int trial = 0; trial < 10; trial++) {
        struct order o = { 0, 3, 1 };
        char label[64];
        snprintf(label, sizeof label, "order fifo trial=%d", trial);
        run_row(label, row_order, &o, 4);
    }
    for (int trial = 0; trial < 10; trial++) {
        struct order o = { 1, 6, 1 };
        char label[64];
        snprintf(label, sizeof label, "order rewait trial=%d", trial);
        run_row(label, row_order, &o, 4);
    }
    for (int trial = 0; trial < 5; trial++) {
        struct order o = { 0, 2, 2 };
        char label[64];
        snprintf(label, sizeof label, "order n=2 trial=%d", trial);
        run_row(label, row_order, &o, 4);
    }
}

// ---------------------------------------------------------------- signal

enum disposition { D_HANDLER, D_IGNORE, D_URG_DEFAULT, D_BLOCKED };

struct signal_row {
    enum disposition disposition;
    int flags;
    int timed;
    int handler_stores;
};

static atomic_llong handled_at = -1;
static uint32_t *volatile store_target;

static void handler(int sig)
{
    (void)sig;
    if (atomic_load(&handled_at) < 0)
        atomic_store(&handled_at, (long long)ms_since_start(now_ns()));
    if (store_target)
        *store_target = 1;
}

static void install(int sig, void (*fn)(int), int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = fn;
    sa.sa_flags = flags;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, NULL);
}

static void row_signal(const void *arg)
{
    const struct signal_row *s = arg;
    words[0] = 0;
    int sig = SIGUSR1;
    switch (s->disposition) {
    case D_HANDLER: install(SIGUSR1, handler, s->flags); break;
    case D_IGNORE: install(SIGUSR1, SIG_IGN, 0); break;
    case D_URG_DEFAULT: sig = SIGURG; break;
    case D_BLOCKED: install(SIGUSR1, handler, s->flags); break;
    }
    if (s->handler_stores)
        store_target = &words[0];
    struct timespec ts = { 2, 0 };
    struct waiter w = { .addr = &words[0], .val = 0, .timeout = s->timed ? &ts : NULL, .name = 'W' };
    if (s->disposition == D_BLOCKED) {
        sigemptyset(&w.block);
        sigaddset(&w.block, SIGUSR1);
        w.block_set = 1;
    }
    start_waiter(&w);
    if (!wait_asleep(&w))
        out("not-asleep ");
    sleep_until_ms(100);
    pthread_kill(w.thread, sig);
    sleep_until_ms(300);
    long woke = futex(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL);
    sleep_ms(20);
    long long h = atomic_load(&handled_at);
    if (h < 0)
        out("handled=-");
    else
        out("handled=%lld", h);
    out(" woke=%ld", woke);
    report_waiter(&w, 0);
    finish(&words[0], &w, 1);
}

static void section_signal(void)
{
    struct {
        const char *label;
        struct signal_row row;
    } rows[] = {
        { "signal handler flags=0 untimed", { D_HANDLER, 0, 0, 0 } },
        { "signal handler flags=SA_RESTART untimed", { D_HANDLER, SA_RESTART, 0, 0 } },
        { "signal handler flags=0 timed=2s", { D_HANDLER, 0, 1, 0 } },
        { "signal handler flags=SA_RESTART timed=2s", { D_HANDLER, SA_RESTART, 1, 0 } },
        { "signal handler-stores-1 flags=0 untimed", { D_HANDLER, 0, 0, 1 } },
        { "signal handler-stores-1 flags=SA_RESTART untimed", { D_HANDLER, SA_RESTART, 0, 1 } },
        { "signal handler-stores-1 flags=SA_RESTART timed=2s", { D_HANDLER, SA_RESTART, 1, 1 } },
        { "signal SIG_IGN untimed", { D_IGNORE, 0, 0, 0 } },
        { "signal URG-default untimed", { D_URG_DEFAULT, 0, 0, 0 } },
        { "signal blocked-by-waiter handler untimed", { D_BLOCKED, 0, 0, 0 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        run_row(rows[i].label, row_signal, &rows[i].row, 4);
}

// ---------------------------------------------------------------- stop

struct stop_row {
    int timeout_ms;
    int store;
};

struct stop_shared {
    uint32_t word;
    long ret;
    int err;
    long long at;
    long woke;
    int done;
};

static void row_stop(const void *arg)
{
    const struct stop_row *s = arg;
    struct stop_shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(sh, 0, sizeof *sh);
    pid_t child = fork();
    if (child == 0) {
        struct timespec ts = { s->timeout_ms / 1000, (long)(s->timeout_ms % 1000) * 1000000 };
        struct waiter w = { .addr = &sh->word, .val = 0, .timeout = s->timeout_ms ? &ts : NULL, .name = 'W' };
        start_waiter(&w);
        wait_asleep(&w);
        sleep_until_ms(600);
        sh->woke = futex(&sh->word, FUTEX_WAKE_PRIVATE, 1, NULL);
        sleep_ms(20);
        if (atomic_load(&w.returns) > 0) {
            sh->ret = w.ret[0];
            sh->err = w.err[0];
            sh->at = ms_since_start(w.end[0]);
        } else {
            sh->ret = -99;
        }
        sh->done = 1;
        _exit(0);
    }
    sleep_until_ms(100);
    kill(child, SIGSTOP);
    int status;
    waitpid(child, &status, WUNTRACED);
    out("stopped=%d", WIFSTOPPED(status));
    if (s->store)
        sh->word = 1;
    sleep_until_ms(200);
    kill(child, SIGCONT);
    waitpid(child, &status, 0);
    if (sh->ret == -99)
        out(" woke=%ld W=asleep", sh->woke);
    else
        out(" woke=%ld W:ret=%ld errno=%s at=%lld", sh->woke, sh->ret, errname(sh->err), sh->at);
}

static void section_stop(void)
{
    struct {
        const char *label;
        struct stop_row row;
    } rows[] = {
        { "stop untimed no-store", { 0, 0 } },
        { "stop untimed store-1", { 0, 1 } },
        { "stop timed=300ms no-store", { 300, 0 } },
        { "stop timed=2s store-1", { 2000, 1 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        run_row(rows[i].label, row_stop, &rows[i].row, 4);
}

// ---------------------------------------------------------------- race

enum race_kind {
    R_SIGNAL_THEN_WAKE,
    R_TIMEOUT_THEN_WAKE,
    R_TIMEOUT_THEN_SIGNAL,
    R_SIGNALLED_KEEPS_SLOT,
    R_TIMED_OUT_KEEPS_SLOT,
    R_TAKEN_IS_SKIPPED,
};

struct race_row {
    enum race_kind kind;
    int flags;
    int timed;
};

static int go_fifo(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0)
        return 0;
    struct sched_param sp = { .sched_priority = 50 };
    return pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) == 0;
}

static int ran_early(struct waiter *ws, int count)
{
    int n = 0;
    for (int i = 0; i < count; i++)
        n += atomic_load(&ws[i].returns);
    return n;
}

static void row_race(const void *arg)
{
    const struct race_row *r = arg;
    if (!go_fifo()) {
        out("skipped (needs CAP_SYS_NICE)");
        return;
    }
    words[0] = 0;
    install(SIGUSR1, handler, r->flags);
    struct timespec two_s = { 2, 0 };
    struct timespec ten_ms = { 0, 10000000 };
    struct waiter ws[2];
    memset(ws, 0, sizeof ws);
    int count = 1;
    ws[0] = (struct waiter){ .addr = &words[0], .val = 0, .timeout = r->timed ? &two_s : NULL, .policy_fifo = 1, .name = 'A' };
    switch (r->kind) {
    case R_SIGNAL_THEN_WAKE: break;
    case R_TIMEOUT_THEN_WAKE:
    case R_TIMEOUT_THEN_SIGNAL: ws[0].timeout = &ten_ms; break;
    case R_SIGNALLED_KEEPS_SLOT:
    case R_TAKEN_IS_SKIPPED: count = 2; break;
    case R_TIMED_OUT_KEEPS_SLOT: ws[0].timeout = &ten_ms; count = 2; break;
    }
    if (count == 2)
        ws[1] = (struct waiter){ .addr = &words[0], .val = 0, .policy_fifo = 1, .name = 'B' };
    for (int i = 0; i < count; i++) {
        start_waiter(&ws[i]);
        if (!wait_asleep(&ws[i]))
            out("not-asleep=%c ", ws[i].name);
    }
    int policy;
    struct sched_param sp;
    pthread_getschedparam(ws[0].thread, &policy, &sp);
    out("waiter-policy=%s/%d", policy == SCHED_FIFO ? "FIFO" : "other", sp.sched_priority);

    // Nothing below blocks the sender until its sleep, so no waiter runs.
    long woke1 = -1, woke2 = -1;
    switch (r->kind) {
    case R_SIGNAL_THEN_WAKE:
    case R_SIGNALLED_KEEPS_SLOT:
        pthread_kill(ws[0].thread, SIGUSR1);
        woke1 = futex(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL);
        break;
    case R_TIMEOUT_THEN_WAKE:
    case R_TIMED_OUT_KEEPS_SLOT:
        spin_ms(50);
        woke1 = futex(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL);
        break;
    case R_TIMEOUT_THEN_SIGNAL:
        spin_ms(50);
        pthread_kill(ws[0].thread, SIGUSR1);
        break;
    case R_TAKEN_IS_SKIPPED:
        woke1 = futex(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL);
        woke2 = futex(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL);
        break;
    }
    int early = ran_early(ws, count);
    sleep_ms(50);
    out(" ran-early=%d woke=%ld", early, woke1);
    if (woke2 >= 0)
        out(",%ld", woke2);
    long long h = atomic_load(&handled_at);
    if (h < 0)
        out(" handled=-");
    else
        out(" handled=yes");
    for (int i = 0; i < count; i++)
        report_waiter(&ws[i], 0);
    if (count == 2 && atomic_load(&ws[0].returns) > 0 && atomic_load(&ws[1].returns) > 0)
        out(" first-to-return=%c", ws[0].order[0] < ws[1].order[0] ? 'A' : 'B');
    finish(&words[0], ws, count);
}

static void section_race(void)
{
    struct {
        const char *label;
        struct race_row row;
    } rows[] = {
        { "race signal-then-wake flags=0 untimed", { R_SIGNAL_THEN_WAKE, 0, 0 } },
        { "race signal-then-wake flags=SA_RESTART untimed", { R_SIGNAL_THEN_WAKE, SA_RESTART, 0 } },
        { "race signal-then-wake flags=0 timed=2s", { R_SIGNAL_THEN_WAKE, 0, 1 } },
        { "race timeout-then-wake timed=10ms spin=50ms", { R_TIMEOUT_THEN_WAKE, 0, 0 } },
        { "race timeout-then-signal timed=10ms spin=50ms flags=0", { R_TIMEOUT_THEN_SIGNAL, 0, 0 } },
        { "race timeout-then-signal timed=10ms spin=50ms flags=SA_RESTART", { R_TIMEOUT_THEN_SIGNAL, SA_RESTART, 0 } },
        { "race signalled-A-keeps-slot (A then B parked; signal A; wake 1)", { R_SIGNALLED_KEEPS_SLOT, 0, 0 } },
        { "race timed-out-A-keeps-slot (A 10ms then B parked; spin 50ms; wake 1)", { R_TIMED_OUT_KEEPS_SLOT, 0, 0 } },
        { "race taken-A-is-skipped (A then B parked; wake 1; wake 1)", { R_TAKEN_IS_SKIPPED, 0, 0 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        for (int trial = 0; trial < 5; trial++) {
            char label[160];
            snprintf(label, sizeof label, "%s trial=%d", rows[i].label, trial);
            run_row(label, row_race, &rows[i].row, 4);
        }
}

// ---------------------------------------------------------------- xproc

struct xproc_row {
    int wait_op;
    int wake_op;
};

static void row_xproc(const void *arg)
{
    const struct xproc_row *x = arg;
    struct stop_shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(sh, 0, sizeof *sh);
    pid_t child = fork();
    if (child == 0) {
        struct timespec ts = { 0, 300000000 };
        long r = futex(&sh->word, x->wait_op, 0, &ts);
        sh->err = r < 0 ? errno : 0;
        sh->ret = r;
        sh->at = ms_since_start(now_ns());
        _exit(0);
    }
    sleep_until_ms(100);
    long woke = futex(&sh->word, x->wake_op, 1, NULL);
    int status;
    waitpid(child, &status, 0);
    out("woke=%ld child:ret=%ld errno=%s at=%lld", woke, sh->ret, errname(sh->err), sh->at);
}

static void section_xproc(void)
{
    struct {
        const char *label;
        struct xproc_row row;
    } rows[] = {
        { "xproc wait=PRIVATE wake=PRIVATE", { FUTEX_WAIT_PRIVATE, FUTEX_WAKE_PRIVATE } },
        { "xproc wait=PRIVATE wake=shared", { FUTEX_WAIT_PRIVATE, FUTEX_WAKE } },
        { "xproc wait=shared wake=shared (control)", { FUTEX_WAIT, FUTEX_WAKE } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        run_row(rows[i].label, row_xproc, &rows[i].row, 4);
}

// ---------------------------------------------------------------- main

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d, %ld CPUs\n", u.sysname, u.release, u.machine, (int)getuid(), sysconf(_SC_NPROCESSORS_ONLN));

    section_wait_screen();
    section_wake_screen();
    run_row("compare word=0xFFFFFFFF val=-1", row_compare, NULL, 2);

    const char *switch_labels[] = { "switches zero-timeout x1000", "switches 1ns-timeout x1000", "switches mismatch zero-timeout x1000" };
    for (int k = 0; k < 3; k++)
        run_row(switch_labels[k], row_switches, &k, 4);

    int64_t huge[] = { 9223372035LL, 9223372036LL, INT64_MAX };
    for (int i = 0; i < 3; i++) {
        char label[64];
        snprintf(label, sizeof label, "huge tv_sec=%lld", (long long)huge[i]);
        run_row(label, row_huge, &huge[i], 3);
    }

    struct count counts[] = {
        { 0, 1, "1" }, { 0, 0, "0" }, { 0, -1, "-1" },
        { 1, 0, "0" }, { 1, 1, "1" }, { 1, -1, "-1" }, { 1, INT_MIN, "INT_MIN" },
        { 3, 0, "0" }, { 3, 1, "1" }, { 3, 2, "2" }, { 3, INT_MAX, "INT_MAX" }, { 3, -1, "-1" }, { 3, -2, "-2" }, { 3, INT_MIN, "INT_MIN" },
    };
    for (size_t i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        char label[64];
        snprintf(label, sizeof label, "count waiters=%d n=%s", counts[i].waiters, counts[i].n_name);
        run_row(label, row_count, &counts[i], 3);
    }

    section_order();
    section_signal();
    section_stop();
    section_race();
    section_xproc();
    return 0;
}
