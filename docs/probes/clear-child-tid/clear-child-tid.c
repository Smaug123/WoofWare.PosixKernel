// What Linux does at a thread's exit with the thread's clear_child_tid word,
// the address which clone(2)'s CLONE_CHILD_CLEARTID or set_tid_address(2)
// gives it: whether it stores 0 there, how many bytes it writes, which futex
// waiters on the word it wakes, and what happens when the word cannot be
// written. Linux only: Darwin has neither call, so there is nothing to measure
// there. Its <sys/syscall.h> (MacOSX26.4.sdk) lists no clone and no
// set_tid_address; the thread calls it does list are bsdthread_create,
// bsdthread_terminate, bsdthread_register and bsdthread_ctl (its SYS_gettid
// and SYS_settid are a thread's credentials, not its ID):
//   grep -i -E 'tid|bsdthread' /Library/Developer/CommandLineTools/SDKs/MacOSX26.4.sdk/usr/include/sys/syscall.h
//
// Results on Linux 6.18.5 aarch64. When a thread exits while another thread
// shares its address space, the kernel stores 0 into the 4 bytes of its
// clear_child_tid word, leaving the bytes either side alone, and wakes one
// waiter in a shared futex wait on the word (FUTEX_WAIT or FUTEX_WAIT_BITSET):
// of two such waiters, one wakes and the other times out. A waiter in a
// private wait (FUTEX_WAIT_PRIVATE or FUTEX_WAIT_BITSET_PRIVATE) is not woken,
// and times out, though the word has become 0. The other user of the address
// space may be another process: a child made by clone(CLONE_VM) without
// CLONE_THREAD, the only thread of its process, clears the word and wakes the
// waiter in its parent. When nothing else shares the address space (a forked
// child's only thread ending by SYS_exit or SYS_exit_group), the word keeps
// its value and nothing is woken. A thread which never set the address leaves
// the word alone. A word the process cannot write (read-only, PROT_NONE, or
// in the unmapped page at 0) is left as it was, and the thread exits as any
// other does: the process carries on, unsignalled. Nor is a shared waiter on
// such a word woken: one asleep on the word before its page became read-only
// or PROT_NONE times out. set_tid_address returns the caller's thread ID.
//
// Output beside this file, measured 2026-11-20, three runs with the same rows
// (timings aside; which of the two-shared row's waiters woke could differ,
// since the two begin their waits concurrently, but one woke in every run):
// measured-linux-6.18.5-aarch64.txt, in Apple's `container` (gcc:14 image,
// glibc 2.41, 5 CPUs), by the command at the end of this header. The probe
// exits nonzero if any row failed to run to its end, or if a waiter was not
// asleep in its wait before the exit, or timed out before the exit.
//
// A thread here is a pthread which calls set_tid_address(2) on a word of the
// probe's own, holding SENTINEL, and then leaves by the raw thread-exit call
// (SYS_exit), so nothing in the C library runs between the two. A waiter is a
// thread in a futex wait on that word for SENTINEL, with a 1 s timeout. The
// exiting thread waits to be released until every waiter is asleep in its
// wait (its /proc state is S), and each waiter row reports whether the exit
// was seen complete (the thread gone, or the child process reaped) before the
// waiter's deadline. Every row runs in a fresh forked child.
//
// Rows:
//   store            the word and its neighbours after the thread has gone,
//                    and whether set_tid_address returned the caller's
//                    thread ID (gettid).
//   store-control    the same, with a thread that never calls
//                    set_tid_address: the word must be left alone.
//   wait=<op>        one waiter in each kind of futex wait: FUTEX_WAIT (the
//                    shared form, op 0), FUTEX_WAIT_PRIVATE (128),
//                    FUTEX_WAIT_BITSET (9, shared) and
//                    FUTEX_WAIT_BITSET_PRIVATE (137), each bitset wait with
//                    every bit set.
//   two-shared       two FUTEX_WAIT waiters: how many the exit wakes.
//   unwritable=<kind> the address in a read-only page holding SENTINEL, in a
//                    PROT_NONE page, and at 0x10, in the page at 0 which
//                    Linux never maps: whether the thread's exit is otherwise
//                    ordinary, and what the word holds after (read access
//                    restored to read it).
//   wait-then-protect=<kind> a shared FUTEX_WAIT waiter asleep on the word,
//                    whose page then becomes read-only or PROT_NONE before
//                    the exit: whether the waiter wakes.
//   last-thread=<how> the word in a MAP_SHARED page, set by a single-threaded
//                    forked child process which then ends by SYS_exit or by
//                    SYS_exit_group; a thread of the parent waits on the word
//                    (shared), and the parent reads it after the child is
//                    reaped.
//   last-thread=control the same page and parent, with a two-threaded child
//                    whose second thread exits while its first lives on, and
//                    then ends the child.
//   last-thread=clone-vm a child made by clone(CLONE_VM | SIGCHLD), which
//                    shares the parent's address space but is a process of
//                    its own, sets a word of the parent's and exits by
//                    SYS_exit; a thread of the parent waits on the word.
//
// Fields: `asleep` is whether every waiter was asleep in its wait when the
// exit was released; `exit-seen-before-deadline` whether the exit was seen
// complete before each waiter's 1 s had run out; `ret` and `errno` are
// what a wait returned (errno=0 on success), `took` its duration in
// milliseconds; `before`, `word` and `after` are the word and the 32-bit words
// either side of it, all three of which start as SENTINEL.
//
// Linux: container run --rm -v "$PWD":/probe gcc:14 sh -c 'uname -srm; ldd --version | head -1; nproc; gcc -Wall -O1 -pthread -o /tmp/p /probe/clear-child-tid.c && /tmp/p'
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SENTINEL 0x5A5A5A5Au

// A row's child exits with this when the row's own preconditions failed.
#define ROW_INVALID 2

struct cell {
    uint32_t before;
    uint32_t word;
    uint32_t after;
};

static struct timespec row_start;

static long now_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - row_start.tv_sec) * 1000 + (now.tv_nsec - row_start.tv_nsec) / 1000000;
}

static long futex_wait(uint32_t *word, int op) {
    struct timespec ts;
    if (op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT_BITSET_PRIVATE) {
        // A bitset wait's timeout is an absolute instant on the monotonic clock.
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 1;
        return syscall(SYS_futex, word, op, SENTINEL, &ts, NULL, FUTEX_BITSET_MATCH_ANY);
    }
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    return syscall(SYS_futex, word, op, SENTINEL, &ts, NULL, 0);
}

static char thread_state(long tid) {
    char path[64], buf[256];
    snprintf(path, sizeof path, "/proc/self/task/%ld/stat", tid);
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return '?';
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *close_paren = strrchr(buf, ')');
    return close_paren != NULL && close_paren[1] == ' ' ? close_paren[2] : '?';
}

// ------------------------------------------------------------------ waiters

struct waiter {
    uint32_t *word;
    int op;
    volatile long tid;
    long started;
    long ret;
    int err;
    long took;
};

static void *waiter_main(void *arg) {
    struct waiter *w = arg;
    w->started = now_ms();
    __atomic_store_n(&w->tid, syscall(SYS_gettid), __ATOMIC_SEQ_CST);
    errno = 0;
    w->ret = futex_wait(w->word, w->op);
    w->err = w->ret < 0 ? errno : 0;
    w->took = now_ms() - w->started;
    return NULL;
}

// Wait, up to 2 s, until `w` has made its call and is asleep in it.
static int wait_asleep(struct waiter *w) {
    for (int i = 0; i < 2000; i++) {
        long tid = __atomic_load_n(&w->tid, __ATOMIC_SEQ_CST);
        if (tid != 0 && thread_state(tid) == 'S')
            return 1;
        usleep(1000);
    }
    return 0;
}

static const char *ename(int e) {
    switch (e) {
    case 0: return "0";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EAGAIN: return "EAGAIN";
    case EINTR: return "EINTR";
    case EFAULT: return "EFAULT";
    default: return strerror(e);
    }
}

static void print_waiter(const struct waiter *w) {
    printf("ret=%ld errno=%s took=%ld", w->ret, ename(w->err), w->took);
}

static void print_cell(const struct cell *c) {
    printf("before=0x%08x word=0x%08x after=0x%08x", c->before, c->word, c->after);
}

static struct cell fresh_cell(void) {
    struct cell c = {SENTINEL, SENTINEL, SENTINEL};
    return c;
}

// ---------------------------------------------------------------- exiters

struct exiter {
    uint32_t *word; // NULL: never call set_tid_address
    volatile int release;
    volatile long tid;
    long set_returned; // what set_tid_address returned
};

static void *exiter_main(void *arg) {
    struct exiter *e = arg;
    while (!__atomic_load_n(&e->release, __ATOMIC_SEQ_CST))
        usleep(1000);
    long tid = syscall(SYS_gettid);
    if (e->word != NULL)
        e->set_returned = syscall(SYS_set_tid_address, e->word);
    __atomic_store_n(&e->tid, tid, __ATOMIC_SEQ_CST);
    syscall(SYS_exit, 0);
    return NULL;
}

// Wait until the thread `e` names has gone: tgkill answers ESRCH.
static void await_gone(struct exiter *e) {
    while (__atomic_load_n(&e->tid, __ATOMIC_SEQ_CST) == 0)
        usleep(1000);
    while (syscall(SYS_tgkill, getpid(), e->tid, 0) == 0)
        usleep(1000);
}

static void start_exiter(struct exiter *e) {
    pthread_t t;
    pthread_create(&t, NULL, exiter_main, e);
}

// Start `n` waiters, wait until each is asleep, change the protection of
// `protect`'s page to `prot` if `protect` is not NULL, release `e`, wait for
// `e`'s thread to go, and then for the waiters to return. Answers whether the
// row's preconditions held, having printed them: every waiter asleep before
// the release, and `e`'s thread seen gone (which a thread is only once its
// exit has dealt with its clear_child_tid word) before any waiter's 1 s ran
// out.
static int run_waiters(struct waiter *ws, int n, struct exiter *e, void *protect, int prot) {
    pthread_t ts[4];
    for (int i = 0; i < n; i++)
        pthread_create(&ts[i], NULL, waiter_main, &ws[i]);
    int asleep = 1;
    for (int i = 0; i < n; i++)
        asleep &= wait_asleep(&ws[i]);
    int protected_ok = protect == NULL || mprotect(protect, sysconf(_SC_PAGESIZE), prot) == 0;
    __atomic_store_n(&e->release, 1, __ATOMIC_SEQ_CST);
    await_gone(e);
    long gone_at = now_ms();
    for (int i = 0; i < n; i++)
        pthread_join(ts[i], NULL);
    int seen = 1;
    for (int i = 0; i < n; i++)
        seen &= gone_at < ws[i].started + 1000;
    printf("asleep=%d exit-seen-before-deadline=%s ", asleep, seen ? "yes" : "no");
    if (!protected_ok)
        printf("mprotect-failed ");
    return asleep && seen && protected_ok;
}

// ------------------------------------------------------------------- rows

static int row_store(int set_address) {
    struct cell c = fresh_cell();
    struct exiter e = {set_address ? &c.word : NULL, 1, 0, 0};
    start_exiter(&e);
    await_gone(&e);
    printf("%s: ", set_address ? "store" : "store-control");
    print_cell(&c);
    if (set_address)
        printf(" set_tid_address-returned-gettid=%s", e.set_returned == e.tid ? "yes" : "no");
    printf("\n");
    return 0;
}

static int row_wait(const char *name, int op) {
    struct cell c = fresh_cell();
    struct waiter w = {&c.word, op, 0, 0, 0, 0, 0};
    struct exiter e = {&c.word, 0, 0, 0};
    start_exiter(&e);
    printf("wait=%s: ", name);
    int ok = run_waiters(&w, 1, &e, NULL, 0);
    print_waiter(&w);
    printf(" ");
    print_cell(&c);
    printf("\n");
    return ok ? 0 : ROW_INVALID;
}

static int row_two_shared(void) {
    struct cell c = fresh_cell();
    struct waiter w[2] = {{&c.word, FUTEX_WAIT, 0, 0, 0, 0, 0}, {&c.word, FUTEX_WAIT, 0, 0, 0, 0, 0}};
    struct exiter e = {&c.word, 0, 0, 0};
    start_exiter(&e);
    printf("two-shared: ");
    int ok = run_waiters(w, 2, &e, NULL, 0);
    printf("woken=%d", (w[0].ret == 0) + (w[1].ret == 0));
    for (int i = 0; i < 2; i++) {
        printf(" waiter%d: ", i);
        print_waiter(&w[i]);
    }
    printf(" ");
    print_cell(&c);
    printf("\n");
    return ok ? 0 : ROW_INVALID;
}

// A process-private page holding SENTINEL at offset 64.
static unsigned char *sentinel_page(void) {
    unsigned char *map =
        mmap(NULL, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *(uint32_t *)(map + 64) = SENTINEL;
    return map;
}

static int row_unwritable(const char *kind) {
    long page = sysconf(_SC_PAGESIZE);
    uint32_t *word;
    unsigned char *map = NULL;
    if (strcmp(kind, "null-page") == 0) {
        word = (uint32_t *)0x10;
    } else {
        map = sentinel_page();
        word = (uint32_t *)(map + 64);
        if (mprotect(map, page, strcmp(kind, "read-only") == 0 ? PROT_READ : PROT_NONE) != 0) {
            printf("unwritable=%s: mprotect-failed\n", kind);
            return ROW_INVALID;
        }
    }
    struct exiter e = {word, 1, 0, 0};
    start_exiter(&e);
    await_gone(&e);
    // Reaching here at all, with the thread gone, is the measurement that the
    // exit was otherwise ordinary: a signal would have ended this row's child.
    printf("unwritable=%s: thread-gone=yes process-runs=yes", kind);
    if (map != NULL) {
        if (mprotect(map, page, PROT_READ) != 0) {
            printf(" mprotect-failed\n");
            return ROW_INVALID;
        }
        printf(" word=0x%08x", *word);
    }
    printf("\n");
    return 0;
}

// A shared FUTEX_WAIT waiter asleep on a word of a process-private page, whose
// protection then becomes `prot`, so that the process cannot write the word,
// before the thread whose clear_child_tid it is exits.
static int row_wait_then_protect(const char *kind, int prot) {
    unsigned char *map = sentinel_page();
    uint32_t *word = (uint32_t *)(map + 64);
    struct waiter w = {word, FUTEX_WAIT, 0, 0, 0, 0, 0};
    struct exiter e = {word, 0, 0, 0};
    start_exiter(&e);
    printf("wait-then-protect=%s: ", kind);
    int ok = run_waiters(&w, 1, &e, map, prot);
    print_waiter(&w);
    if (mprotect(map, sysconf(_SC_PAGESIZE), PROT_READ) != 0) {
        printf(" mprotect-failed\n");
        return ROW_INVALID;
    }
    printf(" word=0x%08x\n", *word);
    return ok ? 0 : ROW_INVALID;
}

// A forked child process, or its second thread in the control row, sets the
// address in `shared` and exits once `shared->release` is set.
struct shared_page {
    struct cell cell;
    volatile int release;
    volatile long control_tid; // the control row's second thread
};

static void await_release(struct shared_page *p) {
    while (!__atomic_load_n(&p->release, __ATOMIC_SEQ_CST))
        usleep(1000);
}

static void *control_thread(void *arg) {
    struct shared_page *p = arg;
    syscall(SYS_set_tid_address, &p->cell.word);
    __atomic_store_n(&p->control_tid, syscall(SYS_gettid), __ATOMIC_SEQ_CST);
    await_release(p);
    syscall(SYS_exit, 0);
    return NULL;
}

// The clone(CLONE_VM) child: a process of its own in its parent's address
// space. It makes no C library call that could touch the parent's state.
static int clone_vm_child(void *arg) {
    struct shared_page *p = arg;
    syscall(SYS_set_tid_address, &p->cell.word);
    while (!__atomic_load_n(&p->release, __ATOMIC_SEQ_CST))
        syscall(SYS_sched_yield);
    syscall(SYS_exit, 0);
    return 0;
}

static int row_last_thread(const char *how) {
    struct shared_page *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    p->cell = fresh_cell();
    p->release = 0;
    p->control_tid = 0;
    pid_t child;
    if (strcmp(how, "clone-vm") == 0) {
        size_t stack_size = 1 << 16;
        char *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        child = clone(clone_vm_child, stack + stack_size, CLONE_VM | SIGCHLD, p);
    } else {
        child = fork();
        if (child == 0) {
            if (strcmp(how, "control") == 0) {
                // The child's first thread outlives its second, and ends the
                // child once the second has gone.
                pthread_t t;
                pthread_create(&t, NULL, control_thread, p);
                while (__atomic_load_n(&p->control_tid, __ATOMIC_SEQ_CST) == 0)
                    usleep(1000);
                while (syscall(SYS_tgkill, getpid(), p->control_tid, 0) == 0)
                    usleep(1000);
                _exit(0);
            }
            syscall(SYS_set_tid_address, &p->cell.word);
            await_release(p);
            if (strcmp(how, "exit") == 0)
                syscall(SYS_exit, 0);
            else
                syscall(SYS_exit_group, 0);
            _exit(99);
        }
    }
    if (child <= 0) {
        printf("last-thread=%s: no-child\n", how);
        return ROW_INVALID;
    }
    struct waiter w = {&p->cell.word, FUTEX_WAIT, 0, 0, 0, 0, 0};
    pthread_t t;
    pthread_create(&t, NULL, waiter_main, &w);
    int asleep = wait_asleep(&w);
    __atomic_store_n(&p->release, 1, __ATOMIC_SEQ_CST);
    // A child is reaped only once its exit is complete.
    int status = 0;
    pid_t reaped = waitpid(child, &status, 0);
    long reaped_at = now_ms();
    pthread_join(t, NULL);
    if (reaped != child) {
        printf("last-thread=%s: waitpid-failed\n", how);
        return ROW_INVALID;
    }
    int seen = reaped_at < w.started + 1000;
    printf("last-thread=%s: asleep=%d exit-seen-before-deadline=%s ", how, asleep, seen ? "yes" : "no");
    print_waiter(&w);
    printf(" ");
    print_cell(&p->cell);
    printf(" child-exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return asleep && seen ? 0 : ROW_INVALID;
}

// ------------------------------------------------------------------- main

static int failures = 0;

static void in_child(int (*row)(void)) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        clock_gettime(CLOCK_MONOTONIC, &row_start);
        int rc = row();
        fflush(stdout);
        _exit(rc);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("row ended by signal %d\n", WTERMSIG(status));
        failures++;
    } else if (WEXITSTATUS(status) != 0) {
        printf("row invalid: exit status %d\n", WEXITSTATUS(status));
        failures++;
    }
}

static int r_store(void) { return row_store(1); }
static int r_store_control(void) { return row_store(0); }
static int r_wait_shared(void) { return row_wait("FUTEX_WAIT", FUTEX_WAIT); }
static int r_wait_private(void) { return row_wait("FUTEX_WAIT_PRIVATE", FUTEX_WAIT_PRIVATE); }
static int r_wait_bitset(void) { return row_wait("FUTEX_WAIT_BITSET", FUTEX_WAIT_BITSET); }
static int r_wait_bitset_private(void) { return row_wait("FUTEX_WAIT_BITSET_PRIVATE", FUTEX_WAIT_BITSET_PRIVATE); }
static int r_unwritable_read_only(void) { return row_unwritable("read-only"); }
static int r_unwritable_prot_none(void) { return row_unwritable("prot-none"); }
static int r_unwritable_null_page(void) { return row_unwritable("null-page"); }
static int r_protect_read_only(void) { return row_wait_then_protect("read-only", PROT_READ); }
static int r_protect_none(void) { return row_wait_then_protect("prot-none", PROT_NONE); }
static int r_last_exit(void) { return row_last_thread("exit"); }
static int r_last_exit_group(void) { return row_last_thread("exit_group"); }
static int r_last_control(void) { return row_last_thread("control"); }
static int r_last_clone_vm(void) { return row_last_thread("clone-vm"); }

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    in_child(r_store);
    in_child(r_store_control);
    in_child(r_wait_shared);
    in_child(r_wait_private);
    in_child(r_wait_bitset);
    in_child(r_wait_bitset_private);
    in_child(row_two_shared);
    in_child(r_unwritable_read_only);
    in_child(r_unwritable_prot_none);
    in_child(r_unwritable_null_page);
    in_child(r_protect_read_only);
    in_child(r_protect_none);
    in_child(r_last_exit);
    in_child(r_last_exit_group);
    in_child(r_last_control);
    in_child(r_last_clone_vm);
    return failures == 0 ? 0 : 1;
}
