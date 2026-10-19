// What Linux's futex(2) answers for FUTEX_WAIT_BITSET and FUTEX_WAKE_BITSET,
// private, with and without FUTEX_CLOCK_REALTIME, and how it decodes an `op`
// it does not take, so that the kernel's model of them can be held to it.
// `docs/probes/futex` measured FUTEX_WAIT_PRIVATE and FUTEX_WAKE_PRIVATE;
// this probe measures what a bitset wait and wake add to them. glibc's
// pthread_cond_wait, sem_wait and timed locks wait with FUTEX_WAIT_BITSET
// (op 137, or 393 with FUTEX_CLOCK_REALTIME) and a mask of
// FUTEX_BITSET_MATCH_ANY, and wake with FUTEX_WAKE_PRIVATE. Linux only.
//
// Build and run (root, for the `race` rows, which need SCHED_FIFO):
//   container run --rm --cap-add ALL -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1), container --cap-add ALL" && gcc -Wall -O1 -pthread -o /tmp/p /probe/futex-bitset.c && /tmp/p'
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
// wake returned. `mask` is a wait's or wake's bitset (val3); `any` is
// FUTEX_BITSET_MATCH_ANY (0xffffffff).
//
// A bitset wait's timeout is an absolute time on the clock its op names:
// CLOCK_MONOTONIC, or CLOCK_REALTIME with FUTEX_CLOCK_REALTIME. `soon` is 10 ms
// after the row started, on that clock; `past` is {0, 0}, which both clocks
// passed long ago.
//
// "Unmapped" memory is a PROT_NONE page. "Beyond" is 2^48, the first address
// past this aarch64 kernel's user address space (`docs/probes/futex`, the
// "range" rows).
//
// Sections:
//   decode       - each `op` (known commands with and without the private and
//                  realtime flags, unknown commands, stray high bits) on an
//                  aligned word that does not hold `val` (so no wait sleeps),
//                  with no timeout, a past one, a malformed one and an
//                  unmapped one: which answer, and is the timeout screened
//                  before the command is? Then the commands that would act on
//                  the word, with a malformed or unmapped timeout only.
//   wait-screen  - FUTEX_WAIT_BITSET_PRIVATE, with and without
//                  FUTEX_CLOCK_REALTIME, on every combination of an address,
//                  a timeout and a mask of any or 0: which answer wins.
//   wake-screen  - FUTEX_WAKE_BITSET_PRIVATE of 1 at every address kind, with
//                  a mask of any, 1 and 0.
//   switches     - voluntary context switches over 1000 bitset waits whose
//                  absolute deadline has passed: does the call sleep before
//                  answering ETIMEDOUT? With FUTEX_WAIT_PRIVATE and a zero
//                  relative timeout as the control `docs/probes/futex` measured.
//   huge         - absolute deadlines too large for the clock (tv_sec
//                  9223372035, 9223372036 and INT64_MAX), on each clock: a
//                  timeout, an error, or a sleep a wake ends 100 ms in?
//   match        - one waiter with mask m and one FUTEX_WAKE_BITSET of 1 with
//                  mask k: is it taken? And a plain wait woken by a bitset
//                  wake, and a bitset wait woken by a plain wake.
//   order        - waiters A (mask 1), B (mask 2), C (mask 1), D (any) parked
//                  in that order: which wakes of which masks and counts take
//                  which waiters.
//   signal       - a bitset waiter, asleep on a matching word, is sent a
//                  signal 100 ms in; FUTEX_WAKE_PRIVATE 1 at 300 ms. Untimed
//                  and timed (an absolute deadline 2 s in), on each clock, with
//                  flags 0 and SA_RESTART, and with a handler that stores 1 to
//                  the word.
//   stop         - the waiter's process is stopped 100 ms into its wait and
//                  continued at 200 ms, no handler; its own main thread wakes
//                  the word at 600 ms. Untimed, and with an absolute deadline
//                  300 ms in on each clock: does a restarted wait keep its
//                  deadline, and read the word again?
//   race         - the sender (SCHED_FIFO 50) and the waiter (SCHED_FIFO 10)
//                  share CPU 0, so whatever the sender does between its own
//                  sleeps happens before the waiter runs. A bitset wait whose
//                  deadline passes, and then a wake or a signal, before it
//                  runs; and a signal and then a wake. `ran-early` is the
//                  control, which must be 0.
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

#define ANY FUTEX_BITSET_MATCH_ANY
#define WAIT_BITSET_RT_PRIVATE (FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME)

// ---------------------------------------------------------------- utilities

static long futex6(void *addr, int op, int val, const void *timeout, uint32_t val3)
{
    return syscall(SYS_futex, addr, op, val, timeout, NULL, val3);
}

static int64_t clock_ns(clockid_t clock)
{
    struct timespec ts;
    clock_gettime(clock, &ts);
    return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static int64_t now_ns(void)
{
    return clock_ns(CLOCK_MONOTONIC);
}

static int64_t row_start;
static int64_t row_start_realtime;

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

// The instant `ms` after the row started, on the clock a bitset wait with `op`
// measures its deadline on.
static struct timespec deadline_ms(int op, int ms)
{
    int64_t base = (op & FUTEX_CLOCK_REALTIME) ? row_start_realtime : row_start;
    int64_t at = base + (int64_t)ms * 1000000;
    return (struct timespec){ at / 1000000000, at % 1000000000 };
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
    case ESRCH: return "ESRCH";
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

static const char *maskname(uint32_t mask)
{
    static char buf[4][16];
    static int next;
    char *b = buf[next++ % 4];
    if (mask == ANY)
        return "any";
    snprintf(b, 16, "0x%x", mask);
    return b;
}

static const char *opname(int op)
{
    switch (op) {
    case FUTEX_WAIT_PRIVATE: return "WAIT_PRIVATE";
    case FUTEX_WAKE_PRIVATE: return "WAKE_PRIVATE";
    case FUTEX_WAIT_BITSET_PRIVATE: return "WAIT_BITSET_PRIVATE";
    case FUTEX_WAKE_BITSET_PRIVATE: return "WAKE_BITSET_PRIVATE";
    case WAIT_BITSET_RT_PRIVATE: return "WAIT_BITSET_PRIVATE|CLOCK_REALTIME";
    default: return "?";
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
        row_start_realtime = clock_ns(CLOCK_REALTIME);
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
    int op;
    uint32_t mask;
    // An absolute deadline `timeout_ms` after the row started, on the op's
    // clock; 0 for none. A FUTEX_WAIT_PRIVATE waiter's is relative instead.
    int timeout_ms;
    // A timeout passed as it stands, in place of `timeout_ms`'s.
    const struct timespec *raw_timeout;
    int policy_fifo;
    char name;
    pthread_t thread;
    atomic_int tid;
    atomic_int returns;
    long ret;
    int err;
    int64_t end;
    int order;
};

static void *waiter_main(void *p)
{
    struct waiter *w = p;
    atomic_store(&w->tid, (int)gettid());
    struct timespec ts;
    const struct timespec *timeout = w->raw_timeout;
    if (w->timeout_ms) {
        if (w->op == FUTEX_WAIT_PRIVATE)
            ts = (struct timespec){ w->timeout_ms / 1000, (long)(w->timeout_ms % 1000) * 1000000 };
        else
            ts = deadline_ms(w->op, w->timeout_ms);
        timeout = &ts;
    }
    long r = futex6(w->addr, w->op, (int)w->val, timeout, w->mask);
    w->err = r < 0 ? errno : 0;
    w->ret = r;
    w->end = now_ns();
    w->order = atomic_fetch_add(&return_order, 1);
    atomic_store(&w->returns, 1);
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

// Start `w` and wait for it to sleep, saying so if it never does.
static void park(struct waiter *w)
{
    start_waiter(w);
    if (!wait_asleep(w))
        out("not-asleep=%c ", w->name);
}

// Wake everything left on `addr` and join the waiters.
static void finish(uint32_t *addr, struct waiter *ws, int count)
{
    for (int i = 0; i < 100; i++) {
        int pending = 0;
        for (int j = 0; j < count; j++)
            if (atomic_load(&ws[j].returns) == 0)
                pending = 1;
        if (!pending)
            break;
        futex6(addr, FUTEX_WAKE_BITSET_PRIVATE, INT_MAX, NULL, ANY);
        sleep_ms(5);
    }
    for (int j = 0; j < count; j++)
        pthread_join(ws[j].thread, NULL);
}

static void report_waiter(const struct waiter *w)
{
    if (atomic_load(&w->returns) == 0) {
        out(" %c=asleep", w->name);
        return;
    }
    out(" %c:ret=%ld errno=%s at=%lld", w->name, w->ret, errname(w->err), (long long)ms_since_start(w->end));
}

// ---------------------------------------------------------------- addresses and timeouts

enum addr_kind {
    A_MATCH,
    A_MISMATCH,
    A_MISALIGNED,
    A_MISALIGNED_MISMATCH,
    A_UNMAPPED,
    A_UNMAPPED_MISALIGNED,
    A_NULL,
    A_BEYOND,
    A_BEYOND_MISALIGNED,
    A_KERNEL_HALF,
};
static const char *addr_names[] = {
    "match", "mismatch", "misaligned", "misaligned-mismatch", "unmapped", "unmapped-misaligned", "null", "beyond",
    "beyond-misaligned", "kernel-half",
};

enum timeout_kind { T_NULL, T_PAST, T_SOON, T_NSEC_1E9, T_NSEC_NEG, T_SEC_NEG, T_UNMAPPED };
static const char *timeout_names[] = { "null", "past", "soon", "nsec=1e9", "nsec=-1", "sec=-1", "unmapped" };

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
    case A_BEYOND: *addr = (uint32_t *)(uintptr_t)0x0001000000000000ULL; break;
    case A_BEYOND_MISALIGNED: *addr = (uint32_t *)(uintptr_t)0x0001000000000002ULL; break;
    case A_KERNEL_HALF: *addr = (uint32_t *)(uintptr_t)0x8000000000000000ULL; break;
    }
}

static const struct timespec *resolve_timeout(enum timeout_kind kind, int op)
{
    static struct timespec ts;
    switch (kind) {
    case T_NULL: return NULL;
    case T_PAST: ts = (struct timespec){ 0, 0 }; return &ts;
    case T_SOON: ts = deadline_ms(op, 10); return &ts;
    case T_NSEC_1E9: ts = (struct timespec){ 0, 1000000000 }; return &ts;
    case T_NSEC_NEG: ts = (struct timespec){ 0, -1 }; return &ts;
    case T_SEC_NEG: ts = (struct timespec){ -1, 0 }; return &ts;
    case T_UNMAPPED: return (const struct timespec *)prot_none_page();
    }
    return NULL;
}

// ---------------------------------------------------------------- decode

struct decode_row {
    int op;
    enum timeout_kind timeout;
};

static void row_decode(const void *arg)
{
    const struct decode_row *d = arg;
    uint32_t *addr;
    uint32_t val;
    resolve(A_MISMATCH, &addr, &val);
    const struct timespec *timeout = resolve_timeout(d->timeout, d->op);
    long r = futex6(addr, d->op, (int)val, timeout, ANY);
    int e = r < 0 ? errno : 0;
    out("ret=%ld errno=%s", r, errname(e));
}

static void section_decode(void)
{
    // A command this probe makes only with FUTEX_CLOCK_REALTIME, which
    // Linux's source rejects for every command but FUTEX_WAIT_BITSET,
    // FUTEX_WAIT_REQUEUE_PI and FUTEX_LOCK_PI2 before it acts on any: without
    // the flag, FUTEX_LOCK_PI and its kin would act on the word.
    struct {
        int op;
        const char *name;
    } ops[] = {
        { 0, "WAIT" },
        { 1, "WAKE" },
        { 9, "WAIT_BITSET" },
        { 10, "WAKE_BITSET" },
        { 128, "WAIT_PRIVATE" },
        { 129, "WAKE_PRIVATE" },
        { 137, "WAIT_BITSET_PRIVATE" },
        { 138, "WAKE_BITSET_PRIVATE" },
        { 256, "WAIT|CLOCK_REALTIME" },
        { 257, "WAKE|CLOCK_REALTIME" },
        { 259, "REQUEUE|CLOCK_REALTIME" },
        { 260, "CMP_REQUEUE|CLOCK_REALTIME" },
        { 261, "WAKE_OP|CLOCK_REALTIME" },
        { 262, "LOCK_PI|CLOCK_REALTIME" },
        { 263, "UNLOCK_PI|CLOCK_REALTIME" },
        { 264, "TRYLOCK_PI|CLOCK_REALTIME" },
        { 265, "WAIT_BITSET|CLOCK_REALTIME" },
        { 266, "WAKE_BITSET|CLOCK_REALTIME" },
        { 268, "CMP_REQUEUE_PI|CLOCK_REALTIME" },
        { 384, "WAIT_PRIVATE|CLOCK_REALTIME" },
        { 385, "WAKE_PRIVATE|CLOCK_REALTIME" },
        { 393, "WAIT_BITSET_PRIVATE|CLOCK_REALTIME" },
        { 394, "WAKE_BITSET_PRIVATE|CLOCK_REALTIME" },
        { 2, "FD" },
        { 130, "FD_PRIVATE" },
        { 14, "cmd14" },
        { 142, "cmd14|PRIVATE" },
        { 15, "cmd15" },
        { 127, "cmd127" },
        { 511, "cmd127|PRIVATE|CLOCK_REALTIME" },
        { 512, "cmd512" },
        { 649, "WAIT_BITSET_PRIVATE|512" },
        { 1153, "WAKE_PRIVATE|1024" },
        { -1, "-1" },
        { INT_MIN, "INT_MIN" },
        { (int)(0x80000000u | 137u), "WAIT_BITSET_PRIVATE|0x80000000" },
    };
    enum timeout_kind kinds[] = { T_NULL, T_PAST, T_NSEC_1E9, T_UNMAPPED };
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++)
        for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++) {
            struct decode_row d = { ops[i].op, kinds[k] };
            char label[160];
            snprintf(label, sizeof label, "decode op=%d (%s) timeout=%s", ops[i].op, ops[i].name, timeout_names[kinds[k]]);
            run_row(label, row_decode, &d, 2);
        }
    // Commands that would act on the word were their timeout good, so only
    // a malformed timeout and an unmapped one, which Linux's source screens
    // before it decodes the command: do they?
    struct {
        int op;
        const char *name;
    } timed_ops[] = {
        { 6, "LOCK_PI" },
        { 134, "LOCK_PI_PRIVATE" },
        { 11, "WAIT_REQUEUE_PI" },
        { 139, "WAIT_REQUEUE_PI_PRIVATE" },
        { 267, "WAIT_REQUEUE_PI|CLOCK_REALTIME" },
        { 13, "LOCK_PI2" },
        { 141, "LOCK_PI2_PRIVATE" },
        { 269, "LOCK_PI2|CLOCK_REALTIME" },
    };
    enum timeout_kind bad[] = { T_NSEC_1E9, T_UNMAPPED };
    for (size_t i = 0; i < sizeof timed_ops / sizeof timed_ops[0]; i++)
        for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
            struct decode_row d = { timed_ops[i].op, bad[k] };
            char label[160];
            snprintf(label, sizeof label, "decode op=%d (%s) timeout=%s", timed_ops[i].op, timed_ops[i].name, timeout_names[bad[k]]);
            run_row(label, row_decode, &d, 2);
        }
}

// ---------------------------------------------------------------- wait-screen

struct screen {
    int op;
    enum addr_kind addr;
    enum timeout_kind timeout;
    uint32_t mask;
};

static void row_wait_screen(const void *arg)
{
    const struct screen *s = arg;
    uint32_t *addr;
    uint32_t val;
    resolve(s->addr, &addr, &val);
    const struct timespec *timeout = resolve_timeout(s->timeout, s->op);
    int64_t start = now_ns();
    long r = futex6(addr, s->op, (int)val, timeout, s->mask);
    int e = r < 0 ? errno : 0;
    out("ret=%ld errno=%s took=%lld", r, errname(e), (long long)((now_ns() - start) / 1000000));
}

static void section_wait_screen(void)
{
    int ops[] = { FUTEX_WAIT_BITSET_PRIVATE, WAIT_BITSET_RT_PRIVATE };
    uint32_t masks[] = { ANY, 0 };
    for (int o = 0; o < 2; o++)
        for (int a = A_MATCH; a <= A_BEYOND_MISALIGNED; a++)
            for (int t = T_NULL; t <= T_UNMAPPED; t++)
                for (int m = 0; m < 2; m++) {
                    // A matching word with no timeout would sleep for ever.
                    if (t == T_NULL && a == A_MATCH && masks[m] != 0)
                        continue;
                    struct screen s = { ops[o], a, t, masks[m] };
                    char label[160];
                    snprintf(label, sizeof label, "wait-screen op=%s addr=%s timeout=%s mask=%s", opname(ops[o]),
                             addr_names[a], timeout_names[t], maskname(masks[m]));
                    run_row(label, row_wait_screen, &s, 2);
                }
}

// ---------------------------------------------------------------- wake-screen

static void row_wake_screen(const void *arg)
{
    const struct screen *s = arg;
    uint32_t *addr;
    uint32_t val;
    resolve(s->addr, &addr, &val);
    long r = futex6(addr, FUTEX_WAKE_BITSET_PRIVATE, 1, NULL, s->mask);
    int e = r < 0 ? errno : 0;
    out("ret=%ld errno=%s", r, errname(e));
}

static void section_wake_screen(void)
{
    enum addr_kind kinds[] = { A_MATCH, A_MISALIGNED, A_UNMAPPED, A_UNMAPPED_MISALIGNED, A_NULL, A_BEYOND, A_BEYOND_MISALIGNED, A_KERNEL_HALF };
    uint32_t masks[] = { ANY, 1, 0 };
    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++)
        for (int m = 0; m < 3; m++) {
            struct screen s = { FUTEX_WAKE_BITSET_PRIVATE, kinds[i], T_NULL, masks[m] };
            char label[128];
            snprintf(label, sizeof label, "wake-screen addr=%s mask=%s n=1",
                     kinds[i] == A_MATCH ? "aligned-no-waiters" : addr_names[kinds[i]], maskname(masks[m]));
            run_row(label, row_wake_screen, &s, 2);
        }
}

// ---------------------------------------------------------------- switches

static long voluntary_switches(void)
{
    struct rusage ru;
    getrusage(RUSAGE_THREAD, &ru);
    return ru.ru_nvcsw;
}

struct switches_row {
    int op;
    // 0: {0, 0}; 1: the clock's reading as the call is made; 2: a relative
    // zero (FUTEX_WAIT_PRIVATE only).
    int deadline;
    int mismatch;
};

static void row_switches(const void *arg)
{
    const struct switches_row *s = arg;
    words[0] = 0;
    uint32_t val = s->mismatch ? 7 : 0;
    clockid_t clock = (s->op & FUTEX_CLOCK_REALTIME) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    int codes[4] = { 0 };
    long before = voluntary_switches();
    int64_t start = now_ns();
    for (int i = 0; i < 1000; i++) {
        struct timespec ts = { 0, 0 };
        if (s->deadline == 1) {
            int64_t at = clock_ns(clock);
            ts = (struct timespec){ at / 1000000000, at % 1000000000 };
        }
        long r = futex6(&words[0], s->op, (int)val, &ts, ANY);
        int e = r < 0 ? errno : 0;
        codes[e == ETIMEDOUT ? 0 : e == EAGAIN ? 1 : e == 0 ? 2 : 3]++;
    }
    int64_t took_us = (now_ns() - start) / 1000;
    out("switches=%ld ETIMEDOUT=%d EAGAIN=%d ok=%d other=%d took-us=%lld", voluntary_switches() - before, codes[0],
        codes[1], codes[2], codes[3], (long long)took_us);
}

static void section_switches(void)
{
    struct {
        const char *label;
        struct switches_row row;
    } rows[] = {
        { "switches op=WAIT_BITSET_PRIVATE deadline=past x1000", { FUTEX_WAIT_BITSET_PRIVATE, 0, 0 } },
        { "switches op=WAIT_BITSET_PRIVATE deadline=now x1000", { FUTEX_WAIT_BITSET_PRIVATE, 1, 0 } },
        { "switches op=WAIT_BITSET_PRIVATE|CLOCK_REALTIME deadline=past x1000", { WAIT_BITSET_RT_PRIVATE, 0, 0 } },
        { "switches op=WAIT_BITSET_PRIVATE|CLOCK_REALTIME deadline=now x1000", { WAIT_BITSET_RT_PRIVATE, 1, 0 } },
        { "switches op=WAIT_BITSET_PRIVATE deadline=past mismatch x1000", { FUTEX_WAIT_BITSET_PRIVATE, 0, 1 } },
        { "switches op=WAIT_PRIVATE timeout=zero x1000 (control)", { FUTEX_WAIT_PRIVATE, 2, 0 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        run_row(rows[i].label, row_switches, &rows[i].row, 4);
}

// ---------------------------------------------------------------- huge

struct huge_row {
    int op;
    int64_t seconds;
};

static void row_huge(const void *arg)
{
    const struct huge_row *h = arg;
    words[0] = 0;
    struct timespec ts = { (time_t)h->seconds, 0 };
    struct waiter w = { .addr = &words[0], .op = h->op, .mask = ANY, .raw_timeout = &ts, .name = 'W' };
    park(&w);
    sleep_until_ms(100);
    long woke = futex6(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL, 0);
    sleep_ms(20);
    out("woke=%ld", woke);
    report_waiter(&w);
    finish(&words[0], &w, 1);
}

// ---------------------------------------------------------------- match

struct match_row {
    int wait_op;
    uint32_t wait_mask;
    int wake_op;
    uint32_t wake_mask;
};

static void row_match(const void *arg)
{
    const struct match_row *m = arg;
    words[0] = 0;
    struct waiter w = { .addr = &words[0], .op = m->wait_op, .mask = m->wait_mask, .timeout_ms = 300, .name = 'W' };
    park(&w);
    long woke = futex6(&words[0], m->wake_op, 1, NULL, m->wake_mask);
    int e = woke < 0 ? errno : 0;
    sleep_ms(30);
    out("woke=%ld errno=%s", woke, errname(e));
    report_waiter(&w);
    finish(&words[0], &w, 1);
}

static void section_match(void)
{
    uint32_t wait_masks[] = { 1, 2, 3, 0x80000000u, ANY };
    uint32_t wake_masks[] = { 1, 2, 4, 0x80000000u, ANY };
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++) {
            struct match_row m = { FUTEX_WAIT_BITSET_PRIVATE, wait_masks[i], FUTEX_WAKE_BITSET_PRIVATE, wake_masks[j] };
            char label[128];
            snprintf(label, sizeof label, "match wait-mask=%s wake-mask=%s", maskname(wait_masks[i]), maskname(wake_masks[j]));
            run_row(label, row_match, &m, 2);
        }
    struct {
        const char *label;
        struct match_row row;
    } rows[] = {
        { "match wait=WAIT_PRIVATE wake=WAKE_BITSET_PRIVATE wake-mask=0x1", { FUTEX_WAIT_PRIVATE, 0, FUTEX_WAKE_BITSET_PRIVATE, 1 } },
        { "match wait=WAIT_PRIVATE wake=WAKE_BITSET_PRIVATE wake-mask=0x80000000", { FUTEX_WAIT_PRIVATE, 0, FUTEX_WAKE_BITSET_PRIVATE, 0x80000000u } },
        { "match wait=WAIT_BITSET_PRIVATE wait-mask=0x1 wake=WAKE_PRIVATE", { FUTEX_WAIT_BITSET_PRIVATE, 1, FUTEX_WAKE_PRIVATE, 0 } },
        { "match wait=WAIT_BITSET_PRIVATE|CLOCK_REALTIME wait-mask=0x2 wake=WAKE_PRIVATE", { WAIT_BITSET_RT_PRIVATE, 2, FUTEX_WAKE_PRIVATE, 0 } },
        { "match wait=WAIT_BITSET_PRIVATE|CLOCK_REALTIME wait-mask=0x2 wake=WAKE_BITSET_PRIVATE wake-mask=0x1", { WAIT_BITSET_RT_PRIVATE, 2, FUTEX_WAKE_BITSET_PRIVATE, 1 } },
        { "match wait=WAIT_BITSET_PRIVATE|CLOCK_REALTIME wait-mask=0x2 wake=WAKE_BITSET_PRIVATE wake-mask=0x2", { WAIT_BITSET_RT_PRIVATE, 2, FUTEX_WAKE_BITSET_PRIVATE, 2 } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        run_row(rows[i].label, row_match, &rows[i].row, 2);
}

// ---------------------------------------------------------------- order

struct wake {
    uint32_t mask;
    int n;
};

struct order_row {
    int wakes;
    struct wake wake[4];
};

static void row_order(const void *arg)
{
    const struct order_row *o = arg;
    words[0] = 0;
    uint32_t masks[] = { 1, 2, 1, ANY };
    struct waiter ws[4];
    memset(ws, 0, sizeof ws);
    for (int i = 0; i < 4; i++) {
        ws[i] = (struct waiter){ .addr = &words[0], .op = FUTEX_WAIT_BITSET_PRIVATE, .mask = masks[i], .name = (char)('A' + i) };
        park(&ws[i]);
    }
    out("woke=");
    for (int k = 0; k < o->wakes; k++) {
        int before[4];
        for (int i = 0; i < 4; i++)
            before[i] = atomic_load(&ws[i].returns);
        long r = futex6(&words[0], FUTEX_WAKE_BITSET_PRIVATE, o->wake[k].n, NULL, o->wake[k].mask);
        sleep_ms(30);
        out("%s%ld:", k ? "," : "", r);
        for (int i = 0; i < 4; i++)
            if (atomic_load(&ws[i].returns) > before[i])
                out("%c", ws[i].name);
    }
    for (int i = 0; i < 4; i++)
        if (atomic_load(&ws[i].returns) == 0)
            out(" %c=asleep", ws[i].name);
    finish(&words[0], ws, 4);
}

static void section_order(void)
{
    struct {
        const char *label;
        struct order_row row;
    } rows[] = {
        { "order mask=0x1,n=1 x3; mask=0x2,n=1", { 4, { { 1, 1 }, { 1, 1 }, { 1, 1 }, { 2, 1 } } } },
        { "order mask=0x1,n=0", { 1, { { 1, 0 } } } },
        { "order mask=0x1,n=-1", { 1, { { 1, -1 } } } },
        { "order mask=0x1,n=INT_MIN", { 1, { { 1, INT_MIN } } } },
        { "order mask=0x2,n=0", { 1, { { 2, 0 } } } },
        { "order mask=0x1,n=INT_MAX", { 1, { { 1, INT_MAX } } } },
        { "order mask=0x4,n=INT_MAX", { 1, { { 4, INT_MAX } } } },
        { "order mask=0x4,n=0", { 1, { { 4, 0 } } } },
        { "order mask=0x3,n=2; mask=0x3,n=2", { 2, { { 3, 2 }, { 3, 2 } } } },
        { "order mask=any,n=2; mask=0x1,n=1", { 2, { { ANY, 2 }, { 1, 1 } } } },
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        for (int trial = 0; trial < (i == 0 ? 5 : 2); trial++) {
            char label[128];
            snprintf(label, sizeof label, "%s trial=%d", rows[i].label, trial);
            run_row(label, row_order, &rows[i].row, 4);
        }
}

// ---------------------------------------------------------------- signal

struct signal_row {
    int op;
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
    install(SIGUSR1, handler, s->flags);
    if (s->handler_stores)
        store_target = &words[0];
    struct waiter w = { .addr = &words[0], .op = s->op, .mask = ANY, .timeout_ms = s->timed ? 2000 : 0, .name = 'W' };
    park(&w);
    sleep_until_ms(100);
    pthread_kill(w.thread, SIGUSR1);
    sleep_until_ms(300);
    long woke = futex6(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL, 0);
    sleep_ms(20);
    long long h = atomic_load(&handled_at);
    if (h < 0)
        out("handled=-");
    else
        out("handled=%lld", h);
    out(" woke=%ld", woke);
    report_waiter(&w);
    finish(&words[0], &w, 1);
}

static void section_signal(void)
{
    int ops[] = { FUTEX_WAIT_BITSET_PRIVATE, WAIT_BITSET_RT_PRIVATE };
    for (int o = 0; o < 2; o++)
        for (int timed = 0; timed < 2; timed++)
            for (int stores = 0; stores < 2; stores++)
                for (int f = 0; f < 2; f++) {
                    struct signal_row row = { ops[o], f ? SA_RESTART : 0, timed, stores };
                    char label[160];
                    snprintf(label, sizeof label, "signal op=%s %s flags=%s %s", opname(ops[o]),
                             stores ? "handler-stores-1" : "handler", f ? "SA_RESTART" : "0", timed ? "deadline=2s" : "untimed");
                    run_row(label, row_signal, &row, 4);
                }
}

// ---------------------------------------------------------------- stop

struct stop_row {
    int op;
    int timeout_ms;
    int store;
};

struct stop_shared {
    uint32_t word;
    long ret;
    int err;
    long long at;
    long woke;
    atomic_int ready;
    long long ready_at;
};

static int await_ready(struct stop_shared *sh)
{
    for (int i = 0; i < 2000; i++) {
        int ready = atomic_load(&sh->ready);
        if (ready != 0)
            return ready == 1;
        sleep_ms(1);
    }
    return 0;
}

static void row_stop(const void *arg)
{
    const struct stop_row *s = arg;
    struct stop_shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(sh, 0, sizeof *sh);
    pid_t child = fork();
    if (child == 0) {
        struct waiter w = { .addr = &sh->word, .op = s->op, .mask = ANY, .timeout_ms = s->timeout_ms, .name = 'W' };
        start_waiter(&w);
        int asleep = wait_asleep(&w);
        sh->ready_at = ms_since_start(now_ns());
        atomic_store(&sh->ready, asleep ? 1 : -1);
        sleep_until_ms(600);
        sh->woke = futex6(&sh->word, FUTEX_WAKE_PRIVATE, 1, NULL, 0);
        sleep_ms(20);
        if (atomic_load(&w.returns) > 0) {
            sh->ret = w.ret;
            sh->err = w.err;
            sh->at = ms_since_start(w.end);
        } else {
            sh->ret = -99;
        }
        _exit(0);
    }
    int status;
    if (!await_ready(sh)) {
        out("child-never-asleep");
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        return;
    }
    sleep_until_ms(100);
    long long stop_at = ms_since_start(now_ns());
    kill(child, SIGSTOP);
    waitpid(child, &status, WUNTRACED);
    out("ready-at=%lld stop-at=%lld stopped=%d", sh->ready_at, stop_at, WIFSTOPPED(status));
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
    int ops[] = { FUTEX_WAIT_BITSET_PRIVATE, WAIT_BITSET_RT_PRIVATE };
    for (int o = 0; o < 2; o++) {
        struct {
            const char *label;
            struct stop_row row;
        } rows[] = {
            { "untimed no-store", { ops[o], 0, 0 } },
            { "untimed store-1", { ops[o], 0, 1 } },
            { "deadline=300ms no-store", { ops[o], 300, 0 } },
            { "deadline=2s store-1", { ops[o], 2000, 1 } },
        };
        for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
            char label[128];
            snprintf(label, sizeof label, "stop op=%s %s", opname(ops[o]), rows[i].label);
            run_row(label, row_stop, &rows[i].row, 4);
        }
    }
}

// ---------------------------------------------------------------- race

enum race_kind { R_SIGNAL_THEN_WAKE, R_TIMEOUT_THEN_WAKE, R_TIMEOUT_THEN_SIGNAL };

struct race_row {
    int op;
    enum race_kind kind;
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

static void row_race(const void *arg)
{
    const struct race_row *r = arg;
    if (!go_fifo()) {
        out("skipped (needs CAP_SYS_NICE)");
        return;
    }
    words[0] = 0;
    install(SIGUSR1, handler, SA_RESTART);
    struct waiter w = { .addr = &words[0], .op = r->op, .mask = ANY, .policy_fifo = 1, .name = 'A' };
    w.timeout_ms = r->kind == R_SIGNAL_THEN_WAKE ? 2000 : 10;
    park(&w);
    long woke = -1;
    switch (r->kind) {
    case R_SIGNAL_THEN_WAKE:
        pthread_kill(w.thread, SIGUSR1);
        woke = futex6(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL, 0);
        break;
    case R_TIMEOUT_THEN_WAKE:
        spin_ms(50);
        woke = futex6(&words[0], FUTEX_WAKE_PRIVATE, 1, NULL, 0);
        break;
    case R_TIMEOUT_THEN_SIGNAL:
        spin_ms(50);
        pthread_kill(w.thread, SIGUSR1);
        break;
    }
    int early = atomic_load(&w.returns);
    sleep_ms(50);
    out("ran-early=%d woke=%ld handled=%s", early, woke, atomic_load(&handled_at) < 0 ? "-" : "yes");
    report_waiter(&w);
    finish(&words[0], &w, 1);
}

static void section_race(void)
{
    const char *kinds[] = { "signal-then-wake deadline=2s", "timeout-then-wake deadline=10ms spin=50ms",
                            "timeout-then-signal deadline=10ms spin=50ms" };
    int ops[] = { FUTEX_WAIT_BITSET_PRIVATE, WAIT_BITSET_RT_PRIVATE };
    for (int o = 0; o < 2; o++)
        for (int k = 0; k < 3; k++)
            for (int trial = 0; trial < 3; trial++) {
                struct race_row r = { ops[o], (enum race_kind)k };
                char label[160];
                snprintf(label, sizeof label, "race op=%s %s flags=SA_RESTART trial=%d", opname(ops[o]), kinds[k], trial);
                run_row(label, row_race, &r, 4);
            }
}

// ---------------------------------------------------------------- main

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d, %ld CPUs\n", u.sysname, u.release, u.machine, (int)getuid(), sysconf(_SC_NPROCESSORS_ONLN));

    section_decode();
    section_wait_screen();
    section_wake_screen();
    section_switches();

    int huge_ops[] = { FUTEX_WAIT_BITSET_PRIVATE, WAIT_BITSET_RT_PRIVATE };
    int64_t huge[] = { 9223372035LL, 9223372036LL, INT64_MAX };
    for (int o = 0; o < 2; o++)
        for (int i = 0; i < 3; i++) {
            struct huge_row h = { huge_ops[o], huge[i] };
            char label[128];
            snprintf(label, sizeof label, "huge op=%s tv_sec=%lld", opname(huge_ops[o]), (long long)huge[i]);
            run_row(label, row_huge, &h, 3);
        }

    section_match();
    section_order();
    section_signal();
    section_stop();
    section_race();
    return 0;
}
