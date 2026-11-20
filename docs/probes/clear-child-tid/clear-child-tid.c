// What Linux does at a thread's exit with the thread's clear_child_tid word,
// the address which clone(2)'s CLONE_CHILD_CLEARTID or set_tid_address(2)
// gives it: whether it stores 0 there, how many bytes it writes, and which
// futex waiters on the word it wakes. Linux only: Darwin has neither call, so
// there is nothing to measure there. Its <sys/syscall.h> (MacOSX26.4.sdk)
// lists no clone and no set_tid_address; the thread calls it does list are
// bsdthread_create, bsdthread_terminate, bsdthread_register and
// bsdthread_ctl (its SYS_gettid and SYS_settid are a thread's credentials,
// not its ID):
//   grep -i -E 'tid|bsdthread' /Library/Developer/CommandLineTools/SDKs/MacOSX26.4.sdk/usr/include/sys/syscall.h
//
// Results on Linux 6.18.5 aarch64. When a thread exits while another thread
// of its process lives, the kernel stores 0 into the 4 bytes of its
// clear_child_tid word, leaving the bytes either side alone, and wakes one
// waiter in a shared futex wait on the word (FUTEX_WAIT or FUTEX_WAIT_BITSET):
// of two such waiters, one wakes and the other times out. A waiter in a
// private wait (FUTEX_WAIT_PRIVATE or FUTEX_WAIT_BITSET_PRIVATE) is not woken,
// and times out, though the word has become 0. When the exiting thread is the
// process's last, by SYS_exit or SYS_exit_group, the word keeps its value and
// nothing is woken. A thread which never set the address leaves the word
// alone. set_tid_address returns the caller's thread ID.
//
// Output beside this file, measured 2026-11-20, three runs with the same rows
// (timings aside, and which of the two-shared row's waiters woke, since the
// two begin their waits concurrently; one woke in every run):
// measured-linux-6.18.5-aarch64.txt, in Apple's `container`
// (gcc:14 image, glibc 2.41, 5 CPUs), by the command at the end of this
// header.
//
// A thread here is a pthread which calls set_tid_address(2) on a word of the
// probe's own, holding SENTINEL, and then leaves by the raw thread-exit call
// (SYS_exit), so nothing in the C library runs between the two. A waiter is a
// thread (or, across processes, the parent) in a futex wait on that word for
// SENTINEL, with a 1 s timeout, long enough to outlast the 200 ms for which
// the exiting thread first sleeps. Every row runs in a fresh forked child.
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
//   last-thread=<how> the word in a MAP_SHARED page, set by a single-threaded
//                    child process which then ends by SYS_exit or by
//                    SYS_exit_group; the parent waits on the word (shared) and
//                    reads it after the child is reaped.
//   last-thread=control the same page and parent, with a two-threaded child
//                    whose second thread exits while its first lives on.
//
// Fields: `ret` and `errno` are what the wait returned (errno=0 on success),
// `took` its duration in milliseconds; `before`, `word` and `after` are the
// word and the 32-bit words either side of it, all three of which start as
// SENTINEL.
//
// Linux: container run --rm -v "$PWD":/probe gcc:14 sh -c 'uname -srm; ldd --version | head -1; nproc; gcc -Wall -O1 -pthread -o /tmp/p /probe/clear-child-tid.c && /tmp/p'
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
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

struct cell {
    uint32_t before;
    uint32_t word;
    uint32_t after;
};

static long ms_since(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
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

struct exiter {
    uint32_t *word; // NULL: never call set_tid_address
    useconds_t delay;
    volatile long tid;
    long set_returned; // what set_tid_address returned, or 0 if never called
};

static void *exiter_main(void *arg) {
    struct exiter *e = arg;
    usleep(e->delay);
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

static void print_cell(const struct cell *c) {
    printf("before=0x%08x word=0x%08x after=0x%08x", c->before, c->word, c->after);
}

static struct cell fresh_cell(void) {
    struct cell c = {SENTINEL, SENTINEL, SENTINEL};
    return c;
}

static void row_store(int set_address) {
    struct cell c = fresh_cell();
    struct exiter e = {set_address ? &c.word : NULL, 0, 0, 0};
    pthread_t t;
    pthread_create(&t, NULL, exiter_main, &e);
    await_gone(&e);
    printf("%s: ", set_address ? "store" : "store-control");
    print_cell(&c);
    if (set_address)
        printf(" set_tid_address-returned-gettid=%s", e.set_returned == e.tid ? "yes" : "no");
    printf("\n");
}

struct waiter {
    uint32_t *word;
    int op;
    long ret;
    int err;
    long took;
};

static void *waiter_main(void *arg) {
    struct waiter *w = arg;
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    errno = 0;
    w->ret = futex_wait(w->word, w->op);
    w->err = w->ret < 0 ? errno : 0;
    w->took = ms_since(&start);
    return NULL;
}

static const char *ename(int e) {
    switch (e) {
    case 0: return "0";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EAGAIN: return "EAGAIN";
    case EINTR: return "EINTR";
    default: return strerror(e);
    }
}

static void print_waiter(const struct waiter *w) {
    printf("ret=%ld errno=%s took=%ld", w->ret, ename(w->err), w->took);
}

static void row_wait(const char *name, int op) {
    struct cell c = fresh_cell();
    struct waiter w = {&c.word, op, 0, 0, 0};
    struct exiter e = {&c.word, 200000, 0, 0};
    pthread_t tw, te;
    pthread_create(&tw, NULL, waiter_main, &w);
    pthread_create(&te, NULL, exiter_main, &e);
    pthread_join(tw, NULL);
    await_gone(&e);
    printf("wait=%s: ", name);
    print_waiter(&w);
    printf(" ");
    print_cell(&c);
    printf("\n");
}

static void row_two_shared(void) {
    struct cell c = fresh_cell();
    struct waiter w[2] = {{&c.word, FUTEX_WAIT, 0, 0, 0}, {&c.word, FUTEX_WAIT, 0, 0, 0}};
    struct exiter e = {&c.word, 200000, 0, 0};
    pthread_t tw[2], te;
    pthread_create(&tw[0], NULL, waiter_main, &w[0]);
    pthread_create(&tw[1], NULL, waiter_main, &w[1]);
    pthread_create(&te, NULL, exiter_main, &e);
    pthread_join(tw[0], NULL);
    pthread_join(tw[1], NULL);
    await_gone(&e);
    int woken = (w[0].ret == 0) + (w[1].ret == 0);
    printf("two-shared: woken=%d", woken);
    for (int i = 0; i < 2; i++) {
        printf(" waiter%d: ", i);
        print_waiter(&w[i]);
    }
    printf(" ");
    print_cell(&c);
    printf("\n");
}

// The child process's second thread, in the control row: it sets the address
// and exits while the child's first thread lives on.
static void *control_thread(void *arg) {
    usleep(200000);
    syscall(SYS_set_tid_address, (uint32_t *)arg);
    syscall(SYS_exit, 0);
    return NULL;
}

static void row_last_thread(const char *how) {
    struct cell *c = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *c = fresh_cell();
    pid_t child = fork();
    if (child == 0) {
        if (strcmp(how, "control") == 0) {
            pthread_t t;
            pthread_create(&t, NULL, control_thread, &c->word);
            usleep(1500000);
            _exit(0);
        }
        usleep(200000);
        syscall(SYS_set_tid_address, &c->word);
        if (strcmp(how, "exit") == 0)
            syscall(SYS_exit, 0);
        else
            syscall(SYS_exit_group, 0);
        _exit(99);
    }
    struct waiter w = {&c->word, FUTEX_WAIT, 0, 0, 0};
    waiter_main(&w);
    int status;
    waitpid(child, &status, 0);
    printf("last-thread=%s: ", how);
    print_waiter(&w);
    printf(" ");
    print_cell(c);
    printf(" child-exited=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
}

static void in_child(void (*row)(void)) {
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        row();
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status))
        printf("row ended by signal %d\n", WTERMSIG(status));
}

static void r_store(void) { row_store(1); }
static void r_store_control(void) { row_store(0); }
static void r_wait_shared(void) { row_wait("FUTEX_WAIT", FUTEX_WAIT); }
static void r_wait_private(void) { row_wait("FUTEX_WAIT_PRIVATE", FUTEX_WAIT_PRIVATE); }
static void r_wait_bitset(void) { row_wait("FUTEX_WAIT_BITSET", FUTEX_WAIT_BITSET); }
static void r_wait_bitset_private(void) { row_wait("FUTEX_WAIT_BITSET_PRIVATE", FUTEX_WAIT_BITSET_PRIVATE); }
static void r_last_exit(void) { row_last_thread("exit"); }
static void r_last_exit_group(void) { row_last_thread("exit_group"); }
static void r_last_control(void) { row_last_thread("control"); }

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    in_child(r_store);
    in_child(r_store_control);
    in_child(r_wait_shared);
    in_child(r_wait_private);
    in_child(r_wait_bitset);
    in_child(r_wait_bitset_private);
    in_child(row_two_shared);
    in_child(r_last_exit);
    in_child(r_last_exit_group);
    in_child(r_last_control);
    return 0;
}
