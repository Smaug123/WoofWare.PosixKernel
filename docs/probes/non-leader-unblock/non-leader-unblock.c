// What a signal sent to the process does when every thread blocks it, and
// then a thread other than the main one unblocks it.
//
// Every row runs in a fresh forked child: the main thread blocks the signal,
// creates a second thread (which inherits the mask), and sends the signal to
// the process with kill(getpid(), sig). Both threads then report sigpending
// (bit n-1 is signo n). Then `who` changes its mask:
//
//   none      - nobody: the control in which the signal stays pending.
//   main      - the main thread unblocks it with pthread_sigmask(SIG_UNBLOCK).
//   second    - the second thread unblocks it the same way.
//   second-ss - the second thread calls sigsuspend with an empty mask.
//
// The thread that unblocked it reports `<who>-returned` once its call returns.
// 50 ms later the second thread, if it is still running and not in
// sigsuspend, reports `alive` with its sigpending; 100 ms later the main
// thread does, and exits 0. The parent waits with WUNTRACED, so `end=` is
// how the child ended: `exit0`, `signalN`, or `stoppedN` (the parent then
// kills it with SIGKILL).
//
// Signals: TERM at its default (terminate), TSTP at its default (stop), and
// USR1 caught by a handler that reports which thread ran it.
//
// Each child is put in a process group of its own, which is not orphaned, so
// that TSTP at its default stops it rather than being discarded.
//
// Bounded: an alarm of 10 s in each child, and a fixed list of rows.
//
// Darwin: cc -Wall -o /tmp/non-leader-unblock non-leader-unblock.c && /tmp/non-leader-unblock
// Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -pthread -o /tmp/p /probe/non-leader-unblock.c && /tmp/p'
//
// Run on Darwin 27.0.0 (arm64, uid 501) and Linux 6.18.5 (aarch64, glibc
// 2.41, root in the container), 2026-10-13; the outputs are beside this file
// as measured-darwin-27.0-uid501.txt and measured-linux-6.18.5-aarch64-uid0.txt.
// WoofWare.PosixKernel.Test/TestSignalReceiver.fs replays every row.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#define FLAVOUR "darwin"
#else
#define FLAVOUR "linux"
#endif

static void die(const char *what) { perror(what); _exit(99); }

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

static uint64_t bits_of(const sigset_t *set)
{
#ifdef __APPLE__
    uint32_t w;
#else
    uint64_t w;
#endif
    memcpy(&w, set, sizeof w);
    return (uint64_t)w;
}

static uint64_t pending_now(void)
{
    sigset_t s;
    memset(&s, 0, sizeof s);
    if (sigpending(&s) != 0) die("sigpending");
    return bits_of(&s);
}

static int g_fd;

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void out(const char *fmt, ...)
{
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    write(g_fd, line, strlen(line));
}

enum who { WHO_NONE, WHO_MAIN, WHO_SECOND, WHO_SECOND_SIGSUSPEND };
static const char *who_name[] = { "none", "main", "second", "second-ss" };

struct row { int sig; int caught; enum who who; };

static struct row g_row;
static pthread_t g_main;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static int g_stage;

static void wait_stage(int stage)
{
    pthread_mutex_lock(&g_lock);
    while (g_stage < stage) pthread_cond_wait(&g_cond, &g_lock);
    pthread_mutex_unlock(&g_lock);
}

static void advance(int stage)
{
    pthread_mutex_lock(&g_lock);
    g_stage = stage;
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_lock);
}

static void on_signal(int s)
{
    (void)s;
    out(" handler-on=%s", pthread_equal(pthread_self(), g_main) ? "main" : "second");
}

static void unblock(void)
{
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, g_row.sig);
    pthread_sigmask(SIG_UNBLOCK, &s, NULL);
}

static void *second(void *arg)
{
    (void)arg;
    wait_stage(1);
    out(" second-pending=%llx", (unsigned long long)pending_now());
    advance(2);
    wait_stage(3);
    if (g_row.who == WHO_SECOND) {
        unblock();
        out(" second-returned");
    } else if (g_row.who == WHO_SECOND_SIGSUSPEND) {
        sigset_t empty;
        sigemptyset(&empty);
        sigsuspend(&empty);
        out(" second-returned");
    }
    if (g_row.who != WHO_SECOND_SIGSUSPEND) {
        sleep_ms(50);
        out(" second-alive pending=%llx", (unsigned long long)pending_now());
    }
    return NULL;
}

static void body(void)
{
    g_main = pthread_self();
    if (g_row.caught) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(g_row.sig, &sa, NULL);
    }
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, g_row.sig);
    pthread_sigmask(SIG_BLOCK, &s, NULL);
    pthread_t t;
    if (pthread_create(&t, NULL, second, NULL) != 0) die("pthread_create");
    kill(getpid(), g_row.sig);
    out(" main-pending=%llx", (unsigned long long)pending_now());
    advance(1);
    wait_stage(2);
    advance(3);
    if (g_row.who == WHO_MAIN) {
        unblock();
        out(" main-returned");
    }
    sleep_ms(100);
    out(" main-alive pending=%llx", (unsigned long long)pending_now());
    _exit(0);
}

static void run(struct row row)
{
    int fds[2];
    if (pipe(fds) != 0) die("pipe");
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        alarm(10);
        // A process group of its own, whose parent is in another group of the
        // same session, so that it is not orphaned: a kernel discards TSTP at
        // its default for an orphaned group rather than stopping it.
        if (setpgid(0, 0) != 0) die("setpgid");
        close(fds[0]);
        g_fd = fds[1];
        g_row = row;
        body();
        _exit(0);
    }
    close(fds[1]);
    int status;
    if (waitpid(child, &status, WUNTRACED) != child) die("waitpid");
    char end[32];
    if (WIFSTOPPED(status)) {
        snprintf(end, sizeof end, "stopped%d", WSTOPSIG(status));
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
    } else if (WIFSIGNALED(status)) {
        snprintf(end, sizeof end, "signal%d", WTERMSIG(status));
    } else {
        snprintf(end, sizeof end, "exit%d", WEXITSTATUS(status));
    }
    char buf[2048];
    ssize_t total = 0, n;
    while (total < (ssize_t)sizeof buf - 1 && (n = read(fds[0], buf + total, sizeof buf - 1 - total)) > 0)
        total += n;
    buf[total] = 0;
    close(fds[0]);
    printf("sig=%d%s who=%s%s end=%s\n", row.sig, row.caught ? "(caught)" : "(default)", who_name[row.who], buf, end);
    fflush(stdout);
}

int main(void)
{
    alarm(120);
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d\n", u.sysname, u.release, u.machine, (int)getuid());
    printf("# flavour %s TERM=%d TSTP=%d USR1=%d\n", FLAVOUR, SIGTERM, SIGTSTP, SIGUSR1);

    int sigs[] = { SIGTERM, SIGTSTP, SIGUSR1 };
    for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
        for (int w = WHO_NONE; w <= WHO_SECOND_SIGSUSPEND; w++) {
            struct row row = { sigs[i], sigs[i] == SIGUSR1, (enum who)w };
            run(row);
        }
    }
    return 0;
}
