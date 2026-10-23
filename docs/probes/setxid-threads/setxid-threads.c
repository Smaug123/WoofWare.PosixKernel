// Which threads a change of credentials reaches, and what the C library's way
// of reaching them does to the other threads' calls.
//
// Linux's credential system calls (setresuid, setresgid, setgroups and the
// rest) change only the thread that makes them. POSIX says a process has one
// set of IDs, so glibc's wrappers make every other thread repeat the call: they
// send each one SIGSETXID (signal 33), whose handler, installed by glibc with
// SA_RESTART, makes the same system call in that thread. Darwin's calls change
// the process.
//
// Linux (root in the container; the probe takes each row's credentials itself):
//   container run --rm -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1)" && gcc -Wall -O1 -pthread -o /tmp/p /probe/setxid-threads.c && /tmp/p'
// Darwin (uid 501, no root), from a set-group-ID copy, so that the process
// holds a group it can change to and back (`everyone`, 12, is one of uid 501's
// supplementary groups; /private/tmp honours set-ID bits):
//   nix develop -c clang -Wall -O1 -o /private/tmp/setxid-threads setxid-threads.c
//   chgrp everyone /private/tmp/setxid-threads && chmod 2755 /private/tmp/setxid-threads
//   /private/tmp/setxid-threads
//
// Every row runs in a fresh forked child, so no row sees another's threads,
// credentials or dispositions. A child that a signal kills reports
// `end=signalN`; one that hangs is killed by its own alarm (`end=signal14`).
//
// Sections:
//   scope (Linux) - a process of three threads (main, w1, w2; the workers wait
//       in read(2) of a pipe for commands) makes one call, as the raw system
//       call (`raw`, syscall(SYS_...)) or through glibc (`libc`), from main or
//       from w1. Then each thread reads its own IDs back (getresuid,
//       getresgid, getgroups, as raw system calls), and main reads every
//       thread's /proc/self/task/<tid>/status (`proc=`, whose uid and gid are
//       real/effective/saved/filesystem). Cases: root dropping to 1000; a
//       process of uid (1000,1000,1001) taking its saved uid as effective; the
//       same two for the group IDs; root installing two supplementary groups;
//       and an unprivileged setgroups (EPERM). `cmd-eintr` counts the
//       workers' command reads that returned EINTR.
//   running (Linux) - w1 spins in user mode, making no call, while main makes
//       the glibc call; w1 then reads its IDs back.
//   handler (Linux) - signal 33's disposition, read with the raw
//       rt_sigaction, in a process that has made no thread yet and in one
//       that has; and what glibc's sigaction(3) answers for it.
//   interrupt - a waiter thread sleeps in a call; once it is asleep (Linux:
//       state S in /proc/self/task/<tid>/stat, `asleep-in` naming the system
//       call number /proc/self/task/<tid>/syscall reported; Darwin: 50 ms
//       after it started), and 20 ms more, main makes the row's `action`:
//         none          - nothing (the control).
//         signal        - pthread_kill of SIGUSR2 to the waiter, caught with
//                         SA_RESTART by a handler that does nothing.
//         libc-setresuid, raw-setresuid (Linux) - setresuid(-1, -1, -1), which
//                         changes nothing.
//         libc-setgroups-einval (Linux, root) - setgroups(65537, list), which
//                         fails (EINVAL: more than NGROUPS_MAX).
//         libc-setresuid-eperm (Linux, uid 1000) - setresuid(-1, 0, -1).
//         setegid (Darwin) - setegid to the real group, a real change.
//         seteuid-noop (Darwin) - seteuid(geteuid()).
//         setgroups-eperm (Darwin) - setgroups of one group, EPERM at uid 501.
//       150 ms after the action main checks whether the waiter's call has
//       returned (`before-release`); if not, it releases the call the way
//       that call ends of itself: a byte into the pipe (poll, epoll_wait,
//       kevent, read), a connect (accept), a FUTEX_WAKE_PRIVATE (futex),
//       SIGUSR1 caught with SA_RESTART (sigsuspend, pause), or nothing for a
//       call with a timeout, which is 400 ms (`after-release`). Each line
//       groups the trials by phase, return value and errno, with how long the
//       waiter's call took (from its start, in ms) and what the action
//       itself returned.
//   blocked (Linux) - the glibc call while another thread blocks signal 33
//       with the raw rt_sigprocmask: asleep in read(2), spinning in user
//       mode, and asleep in a raw rt_sigsuspend whose mask blocks it. And two
//       controls: the other thread asleep in read(2) blocking nothing, with
//       the caller blocking nothing and with the caller blocking signal 33.
//   dscope (Darwin) - as scope, with the process's own calls: setegid,
//       setgid and setregid between the real group and the set-group-ID
//       group, from main or from w1; and the uid calls (setuid, seteuid,
//       setreuid), which uid 501 can make only to change nothing or to fail.
//       Each thread reads back getuid, geteuid, getgid, getegid and
//       getgroups. Darwin has no getresuid/getresgid, so the saved IDs are
//       not read.
//
// Measured on Linux 6.18.5 (aarch64, glibc 2.41, root in the container) and
// Darwin 27.0 (arm64, uid 501, set-group-ID to `everyone`) on 2026-10-17. The
// outputs are beside this file, and
// WoofWare.PosixKernel.Test/TestCredentialThreadsMeasured.fs replays them.
// Darwin's uid calls could only be measured changing nothing or failing: a row
// that changes a uid needs root.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/futex.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#else
#include <sys/event.h>
#endif

#define TRIALS 20
#define TIMEOUT_MS 400

static long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void msleep(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
    }
}

static const char *en(int e)
{
    static char buf[32];
    switch (e) {
    case 0: return "0";
    case EINTR: return "EINTR";
    case EAGAIN: return "EAGAIN";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL";
    case ETIMEDOUT: return "ETIMEDOUT";
    case EFAULT: return "EFAULT";
    default: snprintf(buf, sizeof buf, "errno%d", e); return buf;
    }
}

// Runs fn(arg) in a forked child with an alarm, and reports how it ended.
static void in_child(void (*fn)(void *), void *arg, unsigned alarm_s)
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(alarm_s);
        fn(arg);
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status))
        printf(" end=signal%d\n", WTERMSIG(status));
    else
        printf(" end=exit%d\n", WEXITSTATUS(status));
    fflush(stdout);
}

static void on_signal(int s) { (void)s; }

static void catch_restart(int signo)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(signo, &sa, NULL);
}

// ---------------------------------------------------------------------------
// The interrupt section, shared by both flavours.

enum kind {
    K_POLL,
    K_POLL_T,
    K_MULTI, // epoll_wait on Linux, kevent on Darwin
    K_SIGSUSPEND,
    K_PAUSE,
    K_FUTEX,
    K_FUTEX_T,
    K_READ,
    K_ACCEPT,
    K_NANOSLEEP,
    K_COUNT
};

static const char *kind_name(enum kind k)
{
    switch (k) {
    case K_POLL: return "poll";
    case K_POLL_T: return "poll-timeout";
#ifdef __linux__
    case K_MULTI: return "epoll_wait";
#else
    case K_MULTI: return "kevent";
#endif
    case K_SIGSUSPEND: return "sigsuspend";
    case K_PAUSE: return "pause";
    case K_FUTEX: return "futex-wait";
    case K_FUTEX_T: return "futex-wait-timeout";
    case K_READ: return "read-pipe";
    case K_ACCEPT: return "accept";
    case K_NANOSLEEP: return "nanosleep";
    default: return "?";
    }
}

enum action {
    A_NONE,
    A_SIGNAL,
#ifdef __linux__
    A_LIBC_SETRESUID,
    A_RAW_SETRESUID,
    A_LIBC_SETGROUPS_EINVAL,
    A_LIBC_SETRESUID_EPERM,
#else
    A_SETEGID,
    A_SETEUID_NOOP,
    A_SETGROUPS_EPERM,
#endif
};

static const char *action_name(enum action a)
{
    switch (a) {
    case A_NONE: return "none";
    case A_SIGNAL: return "signal";
#ifdef __linux__
    case A_LIBC_SETRESUID: return "libc-setresuid";
    case A_RAW_SETRESUID: return "raw-setresuid";
    case A_LIBC_SETGROUPS_EINVAL: return "libc-setgroups-einval";
    case A_LIBC_SETRESUID_EPERM: return "libc-setresuid-eperm";
#else
    case A_SETEGID: return "setegid";
    case A_SETEUID_NOOP: return "seteuid-noop";
    case A_SETGROUPS_EPERM: return "setgroups-eperm";
#endif
    default: return "?";
    }
}

struct trial_result {
    int ok; // the trial ran to the end
    int before; // returned before the release
    long ret;
    int err;
    long took;
    long action_ret;
    int action_err;
    long asleep_in; // Linux: the syscall number /proc reported; -1 if never asleep
};

static int pfd[2];
static int multi_fd;
static int lsock;
static struct sockaddr_in laddr;
static _Atomic int fword;
static _Atomic int w_done;
static _Atomic long w_start;
static _Atomic long w_end;
static _Atomic long w_tid;
static long w_ret;
static int w_err;

static long my_tid(void)
{
#ifdef __linux__
    return syscall(SYS_gettid);
#else
    uint64_t t;
    pthread_threadid_np(NULL, &t);
    return (long)t;
#endif
}

static void *waiter(void *p)
{
    enum kind k = (enum kind)(intptr_t)p;
    long r = -1;
    w_tid = my_tid();
    w_start = mono_ms();
    errno = 0;
    switch (k) {
    case K_POLL: {
        struct pollfd x = { pfd[0], POLLIN, 0 };
        r = poll(&x, 1, -1);
        break;
    }
    case K_POLL_T: {
        struct pollfd x = { pfd[0], POLLIN, 0 };
        r = poll(&x, 1, TIMEOUT_MS);
        break;
    }
    case K_MULTI: {
#ifdef __linux__
        struct epoll_event ev;
        r = epoll_wait(multi_fd, &ev, 1, -1);
#else
        struct kevent ev;
        r = kevent(multi_fd, NULL, 0, &ev, 1, NULL);
#endif
        break;
    }
    case K_SIGSUSPEND: {
        sigset_t s;
        sigemptyset(&s);
        r = sigsuspend(&s);
        break;
    }
    case K_PAUSE: r = pause(); break;
#ifdef __linux__
    case K_FUTEX: r = syscall(SYS_futex, &fword, FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0); break;
    case K_FUTEX_T: {
        struct timespec ts = { 0, TIMEOUT_MS * 1000000L };
        r = syscall(SYS_futex, &fword, FUTEX_WAIT_PRIVATE, 0, &ts, NULL, 0);
        break;
    }
#endif
    case K_READ: {
        char c;
        r = read(pfd[0], &c, 1);
        break;
    }
    case K_ACCEPT: r = accept(lsock, NULL, NULL); break;
    case K_NANOSLEEP: {
        struct timespec ts = { 0, TIMEOUT_MS * 1000000L }, rem = { 0, 0 };
        r = nanosleep(&ts, &rem);
        break;
    }
    default: break;
    }
    w_err = r == -1 ? errno : 0;
    w_ret = r;
    w_end = mono_ms();
    w_done = 1;
    return NULL;
}

#ifdef __linux__
// The syscall number a thread is asleep in, or -1 while it is not asleep.
static long asleep_in(long tid)
{
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/self/task/%ld/stat", tid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *close = strrchr(buf, ')');
    if (!close || close[1] != ' ' || close[2] != 'S') return -1;
    snprintf(path, sizeof path, "/proc/self/task/%ld/syscall", tid);
    f = fopen(path, "r");
    if (!f) return -1;
    long nr = -1;
    if (fscanf(f, "%ld", &nr) != 1) nr = -1;
    fclose(f);
    return nr;
}
#endif

struct trial_args {
    enum kind kind;
    enum action action;
    int as_uid1000; // Linux: run the trial as uid/gid 1000
    struct trial_result *out;
};

static void trial(void *p)
{
    struct trial_args *a = p;
    struct trial_result *out = a->out;
    memset(out, 0, sizeof *out);
    out->asleep_in = -1;
#ifdef __linux__
    if (a->as_uid1000) {
        if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) return;
        // Changing the effective uid cleared the dumpable flag, which would
        // keep the process from reading its own /proc/self/task/*/syscall.
        prctl(PR_SET_DUMPABLE, 1);
    }
#endif
    catch_restart(SIGUSR1);
    catch_restart(SIGUSR2);
    if (pipe(pfd)) return;
#ifdef __linux__
    multi_fd = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN };
    ev.data.fd = pfd[0];
    epoll_ctl(multi_fd, EPOLL_CTL_ADD, pfd[0], &ev);
#else
    multi_fd = kqueue();
    struct kevent kev;
    EV_SET(&kev, pfd[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    kevent(multi_fd, &kev, 1, NULL, 0, NULL);
#endif
    lsock = socket(AF_INET, SOCK_STREAM, 0);
    memset(&laddr, 0, sizeof laddr);
    laddr.sin_family = AF_INET;
    laddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t ll = sizeof laddr;
    if (bind(lsock, (struct sockaddr *)&laddr, sizeof laddr) || listen(lsock, 4)
        || getsockname(lsock, (struct sockaddr *)&laddr, &ll))
        return;
    fword = 0;
    w_done = 0;

    pthread_t th;
    pthread_create(&th, NULL, waiter, (void *)(intptr_t)a->kind);
#ifdef __linux__
    long deadline = mono_ms() + 2000;
    while (w_tid == 0 && mono_ms() < deadline) msleep(1);
    long nr = -1;
    while ((nr = asleep_in(w_tid)) == -1 && mono_ms() < deadline) msleep(1);
    out->asleep_in = nr;
#else
    while (w_start == 0) msleep(1);
    msleep(50);
    out->asleep_in = 0;
#endif
    msleep(20);

    long ar = 0;
    errno = 0;
    switch (a->action) {
    case A_NONE: break;
    case A_SIGNAL: ar = pthread_kill(th, SIGUSR2); break;
#ifdef __linux__
    case A_LIBC_SETRESUID: ar = setresuid(-1, -1, -1); break;
    case A_RAW_SETRESUID: ar = syscall(SYS_setresuid, -1, -1, -1); break;
    case A_LIBC_SETGROUPS_EINVAL: {
        gid_t g[1] = { 0 };
        ar = setgroups(65537, g);
        break;
    }
    case A_LIBC_SETRESUID_EPERM: ar = setresuid(-1, 0, -1); break;
#else
    case A_SETEGID: ar = setegid(getgid()); break;
    case A_SETEUID_NOOP: ar = seteuid(geteuid()); break;
    case A_SETGROUPS_EPERM: {
        gid_t g[1] = { getgid() };
        ar = setgroups(1, g);
        break;
    }
#endif
    }
    out->action_ret = ar;
    out->action_err = ar == -1 ? errno : 0;

    msleep(150);
    out->before = w_done;
    if (!out->before) {
        switch (a->kind) {
        case K_POLL:
        case K_MULTI:
        case K_READ:
            if (write(pfd[1], "x", 1) != 1) return;
            break;
        case K_SIGSUSPEND:
        case K_PAUSE: pthread_kill(th, SIGUSR1); break;
#ifdef __linux__
        case K_FUTEX: syscall(SYS_futex, &fword, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0); break;
#endif
        case K_ACCEPT: {
            int c = socket(AF_INET, SOCK_STREAM, 0);
            connect(c, (struct sockaddr *)&laddr, sizeof laddr);
            break;
        }
        default: break;
        }
    }
    pthread_join(th, NULL);
    out->ret = w_ret;
    out->err = w_err;
    out->took = w_end - w_start;
    out->ok = 1;
}

static void interrupt_row(enum kind k, enum action act, int as_uid1000, struct trial_result *shared)
{
    struct group {
        int before;
        long ret;
        int err;
        int count;
        long lo, hi;
    } groups[TRIALS];
    int ngroups = 0, failed = 0;
    long action_ret = 0, asleep = -2;
    int action_err = 0, action_varies = 0, asleep_varies = 0;
    for (int t = 0; t < TRIALS; t++) {
        struct trial_args args = { k, act, as_uid1000, shared };
        shared->ok = 0;
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            alarm(5);
            trial(&args);
            _exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        if (!shared->ok || !WIFEXITED(status)) {
            failed++;
            continue;
        }
        if (t == 0 || asleep == -2) {
            action_ret = shared->action_ret;
            action_err = shared->action_err;
            asleep = shared->asleep_in;
        } else {
            if (shared->action_ret != action_ret || shared->action_err != action_err) action_varies = 1;
            if (shared->asleep_in != asleep) asleep_varies = 1;
        }
        int g;
        for (g = 0; g < ngroups; g++)
            if (groups[g].before == shared->before && groups[g].ret == shared->ret && groups[g].err == shared->err)
                break;
        if (g == ngroups) {
            groups[g].before = shared->before;
            groups[g].ret = shared->ret;
            groups[g].err = shared->err;
            groups[g].count = 0;
            groups[g].lo = shared->took;
            groups[g].hi = shared->took;
            ngroups++;
        }
        groups[g].count++;
        if (shared->took < groups[g].lo) groups[g].lo = shared->took;
        if (shared->took > groups[g].hi) groups[g].hi = shared->took;
    }
    printf("interrupt call=%s action=%s as=%s trials=%d", kind_name(k), action_name(act), as_uid1000 ? "uid1000" : "self",
           TRIALS);
#ifdef __linux__
    printf(" asleep-in=%ld%s", asleep, asleep_varies ? "(varies)" : "");
#else
    (void)asleep_varies;
#endif
    printf(" action-ret=%ld/%s%s", action_ret, en(action_err), action_varies ? "(varies)" : "");
    printf(" outcomes=");
    for (int g = 0; g < ngroups; g++)
        printf("%s%s:ret=%ld:errno=%s*%d:took=%ld..%ld", g ? "," : "", groups[g].before ? "before-release" : "after-release",
               groups[g].ret, en(groups[g].err), groups[g].count, groups[g].lo, groups[g].hi);
    if (failed) printf(" failed=%d", failed);
    printf("\n");
    fflush(stdout);
}

#ifdef __linux__
// ---------------------------------------------------------------------------
// Linux: which threads a call reaches.

enum which { W_UID, W_GID, W_GROUPS };
struct call {
    enum which which;
    int raw;
    long a, b, c;
    int n;
    gid_t list[4];
};
static struct call g_call;
static long g_ret;
static int g_err;

static void do_call(void)
{
    long r = 0;
    errno = 0;
    switch (g_call.which) {
    case W_UID:
        r = g_call.raw ? syscall(SYS_setresuid, g_call.a, g_call.b, g_call.c)
                       : setresuid((uid_t)g_call.a, (uid_t)g_call.b, (uid_t)g_call.c);
        break;
    case W_GID:
        r = g_call.raw ? syscall(SYS_setresgid, g_call.a, g_call.b, g_call.c)
                       : setresgid((gid_t)g_call.a, (gid_t)g_call.b, (gid_t)g_call.c);
        break;
    case W_GROUPS:
        r = g_call.raw ? syscall(SYS_setgroups, g_call.n, g_call.list) : setgroups(g_call.n, g_call.list);
        break;
    }
    g_ret = r;
    g_err = r == -1 ? errno : 0;
}

struct report {
    long tid;
    unsigned r, e, s, gr, ge, gs;
    int ng;
    gid_t groups[8];
};

#define NW 2
static struct report reps[NW + 1];
static int cmd_pipe[NW][2];
static int resp_pipe[2];
static _Atomic int cmd_eintr;

static void self_report(struct report *rep)
{
    uid_t r, e, s;
    gid_t gr, ge, gs;
    rep->tid = syscall(SYS_gettid);
    syscall(SYS_getresuid, &r, &e, &s);
    syscall(SYS_getresgid, &gr, &ge, &gs);
    rep->r = r;
    rep->e = e;
    rep->s = s;
    rep->gr = gr;
    rep->ge = ge;
    rep->gs = gs;
    rep->ng = syscall(SYS_getgroups, 8, rep->groups);
}

static void *worker(void *p)
{
    int i = (int)(intptr_t)p;
    reps[i + 1].tid = syscall(SYS_gettid);
    if (write(resp_pipe[1], "t", 1) != 1) return NULL;
    for (;;) {
        char c;
        ssize_t k = read(cmd_pipe[i][0], &c, 1);
        if (k == -1 && errno == EINTR) {
            cmd_eintr++;
            continue;
        }
        if (k != 1) return NULL;
        if (c == 'c')
            do_call();
        else if (c == 'r')
            self_report(&reps[i + 1]);
        if (write(resp_pipe[1], "a", 1) != 1) return NULL;
        if (c == 'q') return NULL;
    }
}

static void ask(int i, char c)
{
    char a;
    if (write(cmd_pipe[i][1], &c, 1) != 1) return;
    while (read(resp_pipe[0], &a, 1) != 1) {
    }
}

static void proc_status(long tid, char *out, size_t n)
{
    char path[64], line[256], uid[64] = "?", gid[64] = "?", groups[128] = "";
    snprintf(path, sizeof path, "/proc/self/task/%ld/status", tid);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(out, n, "unreadable(%s)", en(errno));
        return;
    }
    while (fgets(line, sizeof line, f)) {
        unsigned a, b, c, d;
        if (sscanf(line, "Uid: %u %u %u %u", &a, &b, &c, &d) == 4) snprintf(uid, sizeof uid, "%u/%u/%u/%u", a, b, c, d);
        if (sscanf(line, "Gid: %u %u %u %u", &a, &b, &c, &d) == 4) snprintf(gid, sizeof gid, "%u/%u/%u/%u", a, b, c, d);
        if (strncmp(line, "Groups:", 7) == 0) {
            char *s = line + 7;
            while (*s == ' ' || *s == '\t') s++;
            size_t len = strcspn(s, "\n");
            while (len > 0 && s[len - 1] == ' ') len--;
            snprintf(groups, sizeof groups, "%.*s", (int)len, s);
            for (char *q = groups; *q; q++)
                if (*q == ' ') *q = ',';
        }
    }
    fclose(f);
    snprintf(out, n, "uid=%s gid=%s groups=[%s]", uid, gid, groups);
}

struct scope_row {
    const char *label;
    unsigned uid[3], gid[3];
    int ng;
    gid_t groups[4];
    struct call call;
    int caller; // 0 is main, 1 is w1
};

static void start_as(const unsigned uid[3], const unsigned gid[3], int ng, const gid_t *groups)
{
    if (setgroups(ng, groups) || setresgid(gid[0], gid[1], gid[2]) || setresuid(uid[0], uid[1], uid[2])) {
        printf("setup-failed=%s", en(errno));
        fflush(stdout);
        _exit(1);
    }
}

static void scope_child(void *p)
{
    struct scope_row *row = p;
    start_as(row->uid, row->gid, row->ng, row->groups);
    if (pipe(resp_pipe)) _exit(1);
    pthread_t th[NW];
    for (int i = 0; i < NW; i++) {
        if (pipe(cmd_pipe[i])) _exit(1);
        pthread_create(&th[i], NULL, worker, (void *)(intptr_t)i);
    }
    for (int i = 0; i < NW; i++) {
        char a;
        while (read(resp_pipe[0], &a, 1) != 1) {
        }
    }
    msleep(20);
    g_call = row->call;
    if (row->caller == 0)
        do_call();
    else
        ask(row->caller - 1, 'c');
    self_report(&reps[0]);
    for (int i = 0; i < NW; i++) ask(i, 'r');
    printf("ret=%ld errno=%s cmd-eintr=%d", g_ret, en(g_err), (int)cmd_eintr);
    static const char *names[] = { "main", "w1", "w2" };
    for (int t = 0; t <= NW; t++) {
        char proc[512], gl[64] = "";
        size_t off = 0;
        for (int g = 0; g < reps[t].ng && g < 8; g++)
            off += snprintf(gl + off, sizeof gl - off, "%s%u", g ? "," : "", (unsigned)reps[t].groups[g]);
        proc_status(reps[t].tid, proc, sizeof proc);
        printf(" | %s getres=uid:%u/%u/%u,gid:%u/%u/%u,groups:[%s] proc=%s", names[t], reps[t].r, reps[t].e, reps[t].s,
               reps[t].gr, reps[t].ge, reps[t].gs, gl, proc);
    }
    for (int i = 0; i < NW; i++) ask(i, 'q');
    for (int i = 0; i < NW; i++) pthread_join(th[i], NULL);
}

static void scope_section(void)
{
    struct scope_row cases[] = {
        { "setresuid-drop", { 0, 0, 0 }, { 0, 0, 0 }, 0, { 0 }, { W_UID, 0, 1000, 1000, 1000, 0, { 0 } }, 0 },
        { "setresuid-saved", { 1000, 1000, 1001 }, { 1000, 1000, 1000 }, 0, { 0 }, { W_UID, 0, -1, 1001, -1, 0, { 0 } }, 0 },
        { "setresgid-root", { 0, 0, 0 }, { 0, 0, 0 }, 0, { 0 }, { W_GID, 0, 1000, 1000, 1000, 0, { 0 } }, 0 },
        { "setresgid-saved", { 1000, 1000, 1000 }, { 1000, 1000, 1001 }, 0, { 0 }, { W_GID, 0, -1, 1001, -1, 0, { 0 } }, 0 },
        { "setgroups-root", { 0, 0, 0 }, { 0, 0, 0 }, 0, { 0 }, { W_GROUPS, 0, 0, 0, 0, 2, { 1002, 1003 } }, 0 },
        { "setgroups-unprivileged", { 1000, 1000, 1000 }, { 1000, 1000, 1000 }, 1, { 1002 }, { W_GROUPS, 0, 0, 0, 0, 1, { 1003 } }, 0 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        for (int raw = 1; raw >= 0; raw--) {
            for (int caller = 0; caller <= 1; caller++) {
                struct scope_row row = cases[i];
                row.call.raw = raw;
                row.caller = caller;
                printf("scope case=%s mode=%s caller=%s start-uid=%u/%u/%u start-gid=%u/%u/%u start-groups=[", row.label,
                       raw ? "raw" : "libc", caller ? "w1" : "main", row.uid[0], row.uid[1], row.uid[2], row.gid[0],
                       row.gid[1], row.gid[2]);
                for (int g = 0; g < row.ng; g++) printf("%s%u", g ? "," : "", (unsigned)row.groups[g]);
                switch (row.call.which) {
                case W_UID:
                    printf("] request=setresuid(%ld,%ld,%ld) ", row.call.a, row.call.b, row.call.c);
                    break;
                case W_GID:
                    printf("] request=setresgid(%ld,%ld,%ld) ", row.call.a, row.call.b, row.call.c);
                    break;
                case W_GROUPS:
                    printf("] request=setgroups(%d,[", row.call.n);
                    for (int g = 0; g < row.call.n; g++) printf("%s%u", g ? "," : "", (unsigned)row.call.list[g]);
                    printf("]) ");
                    break;
                }
                in_child(scope_child, &row, 5);
            }
        }
    }
}

static _Atomic int spin_stop;
static _Atomic int spinning;
static void *spinner(void *p)
{
    (void)p;
    volatile unsigned long n = 0;
    spinning = 1;
    while (!spin_stop) n++;
    self_report(&reps[1]);
    return NULL;
}

static void running_child(void *p)
{
    (void)p;
    pthread_t th;
    pthread_create(&th, NULL, spinner, NULL);
    while (!spinning) msleep(1);
    msleep(20);
    long r = setresuid(1000, 1000, 1000);
    int e = r == -1 ? errno : 0;
    spin_stop = 1;
    pthread_join(th, NULL);
    printf("call=libc-setresuid(1000,1000,1000) ret=%ld errno=%s spinner-getresuid=%u/%u/%u", r, en(e), reps[1].r,
           reps[1].e, reps[1].s);
}

struct ksigaction {
    void *handler;
    unsigned long flags;
    void *restorer;
    uint64_t mask;
};

static void print_disposition(const char *when)
{
    for (int signo = 32; signo <= 33; signo++) {
        struct ksigaction old;
        memset(&old, 0, sizeof old);
        long r = syscall(SYS_rt_sigaction, signo, NULL, &old, 8);
        printf("handler signo=%d when=%s ret=%ld disposition=%s flags=0x%lx sa-restart=%s sa-siginfo=%s sa-onstack=%s "
               "mask=0x%llx\n",
               signo,
               when, r,
               old.handler == SIG_DFL   ? "default"
               : old.handler == SIG_IGN ? "ignore"
                                        : "caught",
               old.flags, (old.flags & SA_RESTART) ? "yes" : "no", (old.flags & SA_SIGINFO) ? "yes" : "no",
               (old.flags & SA_ONSTACK) ? "yes" : "no", (unsigned long long)old.mask);
    }
}

static void *nothing(void *p) { return p; }

static void handler_child(void *p)
{
    (void)p;
    print_disposition("before-any-thread");
    struct sigaction sa;
    errno = 0;
    int r = sigaction(33, NULL, &sa);
    printf("handler libc-sigaction(33,query) ret=%d errno=%s\n", r, en(r == -1 ? errno : 0));
    pthread_t th;
    pthread_create(&th, NULL, nothing, NULL);
    pthread_join(th, NULL);
    print_disposition("after-a-thread");
    printf("handler done");
}

// The blocked section: another thread blocks signal 33 with the raw call.
enum blocked_kind { B_CONTROL, B_CALLER_BLOCKS, B_READ, B_SPIN, B_SIGSUSPEND };
static _Atomic int b_ready;
static void block33(void)
{
    uint64_t set = 1ULL << (33 - 1);
    syscall(SYS_rt_sigprocmask, SIG_BLOCK, &set, NULL, 8);
}
static void *blocked_waiter(void *p)
{
    enum blocked_kind k = (enum blocked_kind)(intptr_t)p;
    if (k == B_READ || k == B_SPIN) block33();
    b_ready = 1;
    switch (k) {
    case B_CONTROL:
    case B_CALLER_BLOCKS:
    case B_READ: {
        char c;
        while (read(pfd[0], &c, 1) == -1) {
        }
        break;
    }
    case B_SPIN:
        for (;;) {
        }
    case B_SIGSUSPEND: {
        uint64_t all = ~0ULL;
        syscall(SYS_rt_sigsuspend, &all, 8);
        break;
    }
    }
    return NULL;
}

static void blocked_child(void *p)
{
    enum blocked_kind k = (enum blocked_kind)(intptr_t)p;
    if (pipe(pfd)) return;
    pthread_t th;
    pthread_create(&th, NULL, blocked_waiter, (void *)(intptr_t)k);
    while (!b_ready) msleep(1);
    msleep(50);
    if (k == B_CALLER_BLOCKS) block33();
    alarm(2);
    printf("calling ");
    fflush(stdout);
    long r = setresuid(-1, -1, -1);
    printf("ret=%ld errno=%s", r, en(r == -1 ? errno : 0));
}

static void linux_sections(void)
{
    scope_section();

    printf("running ");
    in_child(running_child, NULL, 5);

    in_child(handler_child, NULL, 5);

    static const char *bnames[] = { "read-pipe-not-blocking-33", "read-pipe-while-the-caller-blocks-33", "read-pipe", "spin",
                                    "raw-rt_sigsuspend-blocking-33" };
    for (int k = B_CONTROL; k <= B_SIGSUSPEND; k++) {
        printf("blocked waiter=%s call=libc-setresuid(-1,-1,-1) ", bnames[k]);
        in_child(blocked_child, (void *)(intptr_t)k, 5);
    }

    struct trial_result *shared =
        mmap(NULL, sizeof *shared, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    enum action actions[] = { A_NONE, A_SIGNAL, A_LIBC_SETRESUID, A_RAW_SETRESUID, A_LIBC_SETGROUPS_EINVAL };
    for (int k = 0; k < K_COUNT; k++)
        for (size_t a = 0; a < sizeof actions / sizeof actions[0]; a++) interrupt_row(k, actions[a], 0, shared);
    enum kind eperm_kinds[] = { K_POLL, K_SIGSUSPEND, K_FUTEX, K_READ, K_NANOSLEEP };
    for (size_t k = 0; k < sizeof eperm_kinds / sizeof eperm_kinds[0]; k++)
        interrupt_row(eperm_kinds[k], A_LIBC_SETRESUID_EPERM, 1, shared);
}

#else
// ---------------------------------------------------------------------------
// Darwin.

struct dreport {
    unsigned r, e, gr, ge;
    int ng;
    gid_t groups[16];
};
#define NW 2
static struct dreport dreps[NW + 1];
static int cmd_pipe[NW][2];
static int resp_pipe[2];
static _Atomic int cmd_eintr;

enum dcall { D_SETEGID_REAL, D_SETEGID_SGID, D_SETGID_REAL, D_SETREGID_E_REAL, D_SETREGID_SWAP, D_SETUID_SELF,
             D_SETEUID_SELF, D_SETREUID_NONE, D_SETUID_ROOT, D_SETEUID_ROOT, D_SETGROUPS_SAME, D_COUNT };
static const char *dcall_name(enum dcall c)
{
    switch (c) {
    case D_SETEGID_REAL: return "setegid(rgid)";
    case D_SETEGID_SGID: return "setegid(rgid);setegid(sgid)";
    case D_SETGID_REAL: return "setgid(rgid)";
    case D_SETREGID_E_REAL: return "setregid(-1,rgid)";
    case D_SETREGID_SWAP: return "setregid(egid,rgid)";
    case D_SETUID_SELF: return "setuid(getuid())";
    case D_SETEUID_SELF: return "seteuid(geteuid())";
    case D_SETREUID_NONE: return "setreuid(-1,-1)";
    case D_SETUID_ROOT: return "setuid(0)";
    case D_SETEUID_ROOT: return "seteuid(0)";
    case D_SETGROUPS_SAME: return "setgroups(getgroups())";
    default: return "?";
    }
}
static enum dcall g_dcall;
static gid_t start_rgid, start_egid;
static long g_ret;
static int g_err;

static void do_dcall(void)
{
    long r = 0;
    errno = 0;
    switch (g_dcall) {
    case D_SETEGID_REAL: r = setegid(start_rgid); break;
    case D_SETEGID_SGID:
        r = setegid(start_rgid);
        if (r == 0) r = setegid(start_egid);
        break;
    case D_SETGID_REAL: r = setgid(start_rgid); break;
    case D_SETREGID_E_REAL: r = setregid((gid_t)-1, start_rgid); break;
    case D_SETREGID_SWAP: r = setregid(start_egid, start_rgid); break;
    case D_SETUID_SELF: r = setuid(getuid()); break;
    case D_SETEUID_SELF: r = seteuid(geteuid()); break;
    case D_SETREUID_NONE: r = setreuid((uid_t)-1, (uid_t)-1); break;
    case D_SETUID_ROOT: r = setuid(0); break;
    case D_SETEUID_ROOT: r = seteuid(0); break;
    case D_SETGROUPS_SAME: {
        gid_t g[16];
        int n = getgroups(16, g);
        r = n < 0 ? -1 : setgroups(n, g);
        break;
    }
    default: break;
    }
    g_ret = r;
    g_err = r == -1 ? errno : 0;
}

static void dself_report(struct dreport *rep)
{
    rep->r = getuid();
    rep->e = geteuid();
    rep->gr = getgid();
    rep->ge = getegid();
    rep->ng = getgroups(16, rep->groups);
}

static void *dworker(void *p)
{
    int i = (int)(intptr_t)p;
    if (write(resp_pipe[1], "t", 1) != 1) return NULL;
    for (;;) {
        char c;
        ssize_t k = read(cmd_pipe[i][0], &c, 1);
        if (k == -1 && errno == EINTR) {
            cmd_eintr++;
            continue;
        }
        if (k != 1) return NULL;
        if (c == 'c')
            do_dcall();
        else if (c == 'r')
            dself_report(&dreps[i + 1]);
        if (write(resp_pipe[1], "a", 1) != 1) return NULL;
        if (c == 'q') return NULL;
    }
}

static void dask(int i, char c)
{
    char a;
    if (write(cmd_pipe[i][1], &c, 1) != 1) return;
    while (read(resp_pipe[0], &a, 1) != 1) {
    }
}

struct drow {
    enum dcall call;
    int caller;
};

static void dscope_child(void *p)
{
    struct drow *row = p;
    if (pipe(resp_pipe)) _exit(1);
    pthread_t th[NW];
    for (int i = 0; i < NW; i++) {
        if (pipe(cmd_pipe[i])) _exit(1);
        pthread_create(&th[i], NULL, dworker, (void *)(intptr_t)i);
    }
    for (int i = 0; i < NW; i++) {
        char a;
        while (read(resp_pipe[0], &a, 1) != 1) {
        }
    }
    msleep(20);
    g_dcall = row->call;
    if (row->caller == 0)
        do_dcall();
    else
        dask(row->caller - 1, 'c');
    dself_report(&dreps[0]);
    for (int i = 0; i < NW; i++) dask(i, 'r');
    printf("ret=%ld errno=%s cmd-eintr=%d", g_ret, en(g_err), (int)cmd_eintr);
    static const char *names[] = { "main", "w1", "w2" };
    for (int t = 0; t <= NW; t++) {
        char gl[128] = "";
        size_t off = 0;
        for (int g = 0; g < dreps[t].ng && g < 16; g++)
            off += snprintf(gl + off, sizeof gl - off, "%s%u", g ? "," : "", (unsigned)dreps[t].groups[g]);
        printf(" | %s uid=%u/%u gid=%u/%u groups=[%s]", names[t], dreps[t].r, dreps[t].e, dreps[t].gr, dreps[t].ge, gl);
    }
    for (int i = 0; i < NW; i++) dask(i, 'q');
    for (int i = 0; i < NW; i++) pthread_join(th[i], NULL);
}

static void darwin_sections(void)
{
    start_rgid = getgid();
    start_egid = getegid();
    printf("# start uid=%u/%u gid=%u/%u (real/effective)%s\n", getuid(), geteuid(), start_rgid, start_egid,
           start_rgid == start_egid ? " -- not set-group-ID: the gid rows change nothing" : "");
    for (int c = 0; c < D_COUNT; c++) {
        for (int caller = 0; caller <= 1; caller++) {
            struct drow row = { c, caller };
            printf("dscope call=%s caller=%s ", dcall_name(c), caller ? "w1" : "main");
            in_child(dscope_child, &row, 5);
        }
    }

    struct trial_result *shared =
        mmap(NULL, sizeof *shared, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    enum kind kinds[] = { K_POLL, K_POLL_T, K_MULTI, K_SIGSUSPEND, K_PAUSE, K_READ, K_ACCEPT, K_NANOSLEEP };
    enum action actions[] = { A_NONE, A_SIGNAL, A_SETEGID, A_SETEUID_NOOP, A_SETGROUPS_EPERM };
    for (size_t k = 0; k < sizeof kinds / sizeof kinds[0]; k++)
        for (size_t a = 0; a < sizeof actions / sizeof actions[0]; a++) interrupt_row(kinds[k], actions[a], 0, shared);
}
#endif

int main(void)
{
    struct utsname u;
    uname(&u);
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("# %s %s %s, uid %u, %ld CPUs, %d trials per interrupt row\n", u.sysname, u.release, u.machine, getuid(), cpus,
           TRIALS);
#ifdef __linux__
    linux_sections();
#else
    darwin_sections();
#endif
    return 0;
}
