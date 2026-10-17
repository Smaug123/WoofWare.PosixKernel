// What kill(2) answers for each kind of target: a pid that names no process,
// 0, -1, a process group, a thread's ID, and another process, by the
// credentials of the sender and of the target.
//
// Sections:
//   target - the calling process sends to each target with signal 0 (which
//            sends nothing) and with 999 (no signal): its own pid; a pid that
//            names no process (a child it forked and reaped: `reaped`); the
//            largest int; 0 (its own process group); -1 (every process it may
//            signal); its own process group negated; a reaped child's pid
//            negated (a group nobody leads); INT_MIN; process 1 (root's,
//            on both machines here); and, on Linux, the ID of
//            a second thread of its own (`tid`), where SIGUSR1 is also sent,
//            with which thread ran the handler. Each row is a fresh forked
//            child in a process group of its own, so 0 and -pgid reach no
//            other process; -1 and 1 are sent only 0 and 999, neither of which
//            sends anything.
//   group  - a child in a process group of its own, beside a sibling in the
//            same group, sends SIGUSR1 to 0 and to -pgid: which of the two ran
//            the handler, and what the call answered.
//   cred   - (root only) a target process whose real, effective and saved
//            user IDs are each 1000 or 1001, and a sender whose IDs are each
//            1000 or 1001 (all 64 pairs), the sender sending signal 0 and
//            SIGUSR1 (the target's handler reports whether it ran); then the
//            same with uid 0 on one side; and 999 to a target it may not
//            signal, for the order of the checks.
//   cont   - (root only) SIGCONT from uid 1000 to uid 1001, in the sender's
//            session and in a session of its own.
//   all    - (root only) kill(-1, 0) by uid 1000 with no other uid-1000
//            process, and beside a sibling of uid 1000.
//
// A sender's or target's IDs are set with setresgid/setresuid in a forked
// child of the root parent. Each child is bounded by an alarm of 5 s.
//
// Darwin: cc -Wall -o /tmp/kill-targets kill-targets.c && /tmp/kill-targets
// Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1), gcc:14 container" && gcc -Wall -O1 -pthread -o /tmp/p /probe/kill-targets.c && /tmp/p'
//         and as uid 1000: ... && setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/p'
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <grp.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *errname(int e)
{
    switch (e) {
    case 0: return "0";
    case ESRCH: return "ESRCH";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL";
    }
    static char b[16];
    snprintf(b, sizeof b, "errno%d", e);
    return b;
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/* fork(2), or the probe stops: a failed fork's -1, later killed, would be
 * kill(-1, SIGKILL). */
static pid_t fork_or_die(void)
{
    pid_t p = fork();
    if (p < 0) { perror("fork"); exit(98); }
    return p;
}

static const char *call(pid_t pid, int sig)
{
    errno = 0;
    int r = kill(pid, sig);
    return r == 0 ? "0" : errname(errno);
}

static pid_t reaped_pid(void)
{
    pid_t p = fork_or_die();
    if (p == 0) _exit(0);
    waitpid(p, NULL, 0);
    return p;
}

static volatile int handled_by = -1; /* 0 main thread, 1 second thread */
static pthread_t main_th;
static int report_fd = -1;

static void on_usr1(int s)
{
    (void)s;
    handled_by = pthread_equal(pthread_self(), main_th) ? 0 : 1;
    if (report_fd >= 0) { char c = 'h'; write(report_fd, &c, 1); }
}

#ifndef __APPLE__
static volatile pid_t second_tid;
static volatile int second_stop;
static void *second(void *arg)
{
    (void)arg;
    second_tid = (pid_t)syscall(SYS_gettid);
    while (!second_stop) sleep_ms(1);
    return NULL;
}
#endif

static void section_target(void)
{
    pid_t gone = reaped_pid();
    pid_t gone2 = reaped_pid();
    struct { const char *name; pid_t pid; } targets[] = {
        { "self", 0 }, { "reaped", gone }, { "INT_MAX", INT_MAX }, { "zero", 0 }, { "minus-one", -1 },
        { "minus-own-pgid", 0 }, { "minus-reaped", -gone2 }, { "INT_MIN", INT_MIN }, { "pid-one", 1 },
    };
    int sigs[] = { 0, 999 };
    for (size_t t = 0; t < sizeof targets / sizeof targets[0]; t++)
        for (size_t s = 0; s < 2; s++) {
            int pfd[2];
            pipe(pfd);
            fflush(stdout);
            pid_t c = fork_or_die();
            if (c == 0) {
                alarm(5);
                setpgid(0, 0);
                pid_t pid = targets[t].pid;
                if (!strcmp(targets[t].name, "self")) pid = getpid();
                if (!strcmp(targets[t].name, "minus-own-pgid")) pid = -getpgrp();
                char line[256];
                int n = snprintf(line, sizeof line, "section=target target=%s sig=%d answer=%s\n", targets[t].name, sigs[s], call(pid, sigs[s]));
                write(pfd[1], line, n);
                _exit(0);
            }
            close(pfd[1]);
            char buf[256];
            int n = (int)read(pfd[0], buf, sizeof buf - 1);
            close(pfd[0]);
            waitpid(c, NULL, 0);
            if (n > 0) { buf[n] = 0; fputs(buf, stdout); }
        }
#ifndef __APPLE__
    /* A second thread's ID. */
    int pfd[2];
    pipe(pfd);
    fflush(stdout);
    pid_t c = fork_or_die();
    if (c == 0) {
        alarm(5);
        setpgid(0, 0);
        main_th = pthread_self();
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_usr1;
        sigaction(SIGUSR1, &sa, NULL);
        pthread_t th;
        pthread_create(&th, NULL, second, NULL);
        while (!second_tid) sleep_ms(1);
        char line[512];
        int n = 0;
        n += snprintf(line + n, sizeof line - n, "section=target target=tid sig=0 answer=%s\n", call(second_tid, 0));
        n += snprintf(line + n, sizeof line - n, "section=target target=tid sig=999 answer=%s\n", call(second_tid, 999));
        const char *a = call(second_tid, SIGUSR1);
        for (int i = 0; i < 200 && handled_by < 0; i++) sleep_ms(1);
        n += snprintf(line + n, sizeof line - n, "section=target target=tid sig=USR1 answer=%s handler-on=%s\n", a,
                      handled_by == 0 ? "main" : handled_by == 1 ? "second" : "none");
        second_stop = 1;
        pthread_join(th, NULL);
        /* The thread has exited: its ID names nothing now. */
        n += snprintf(line + n, sizeof line - n, "section=target target=exited-tid sig=0 answer=%s\n", call(second_tid, 0));
        write(pfd[1], line, n);
        _exit(0);
    }
    close(pfd[1]);
    char buf[512];
    int n = (int)read(pfd[0], buf, sizeof buf - 1);
    close(pfd[0]);
    waitpid(c, NULL, 0);
    if (n > 0) { buf[n] = 0; fputs(buf, stdout); }
#endif
}

static void section_group(void)
{
    const char *how[] = { "zero", "minus-pgid" };
    for (int h = 0; h < 2; h++) {
        int pfd[2];
        pipe(pfd);
        fflush(stdout);
        pid_t c = fork_or_die();
        if (c == 0) {
            alarm(5);
            setpgid(0, 0);
            struct sigaction sa;
            memset(&sa, 0, sizeof sa);
            sa.sa_handler = on_usr1;
            sigaction(SIGUSR1, &sa, NULL);
            int sib_pipe[2], ready[2];
            pipe(sib_pipe);
            pipe(ready);
            pid_t sib = fork_or_die();
            if (sib == 0) {
                /* Same process group as its parent. It says it is ready only
                 * once its handler has somewhere to report to. */
                alarm(5);
                close(pfd[0]);
                close(pfd[1]);
                close(sib_pipe[0]);
                close(ready[0]);
                report_fd = sib_pipe[1];
                char r = 'r';
                write(ready[1], &r, 1);
                for (;;) pause();
            }
            close(sib_pipe[1]);
            close(ready[1]);
            char x;
            if (read(ready[0], &x, 1) != 1) { perror("sibling never ready"); _exit(97); }
            main_th = pthread_self();
            const char *a = call(h == 0 ? 0 : -getpgrp(), SIGUSR1);
            for (int i = 0; i < 500 && handled_by < 0; i++) sleep_ms(1);
            /* The sibling writes one byte if its handler ran: wait up to
             * 500 ms for it. */
            fd_set set;
            FD_ZERO(&set);
            FD_SET(sib_pipe[0], &set);
            struct timeval wait = { 0, 500000 };
            int sib_ran = select(sib_pipe[0] + 1, &set, NULL, NULL, &wait) == 1 && read(sib_pipe[0], &x, 1) == 1;
            kill(sib, SIGKILL);
            waitpid(sib, NULL, 0);
            char line[256];
            int n = snprintf(line, sizeof line, "section=group target=%s sig=USR1 answer=%s self-handled=%d sibling-handled=%d\n", how[h], a, handled_by >= 0, sib_ran);
            write(pfd[1], line, n);
            _exit(0);
        }
        close(pfd[1]);
        char buf[256];
        int n = (int)read(pfd[0], buf, sizeof buf - 1);
        close(pfd[0]);
        waitpid(c, NULL, 0);
        if (n > 0) { buf[n] = 0; fputs(buf, stdout); }
    }
}

#ifndef __APPLE__
struct ids { uid_t r, e, s; };

static void become(struct ids id)
{
    gid_t g = id.r == 0 ? 0 : 1000;
    if (setgroups(0, NULL) != 0 && id.r != 0) {}
    if (setresgid(g, g, g) != 0) { perror("setresgid"); _exit(97); }
    if (setresuid(id.r, id.e, id.s) != 0) { perror("setresuid"); _exit(97); }
}

/* A target with `id` that reports on `fd` each time its SIGUSR1 handler runs. */
static pid_t spawn_target(struct ids id, int fd, int new_session)
{
    int ready[2];
    pipe(ready);
    pid_t t = fork_or_die();
    if (t == 0) {
        alarm(10);
        if (new_session) setsid();
        report_fd = fd;
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = on_usr1;
        sigaction(SIGUSR1, &sa, NULL);
        become(id);
        char c = 'r';
        write(ready[1], &c, 1);
        for (;;) pause();
    }
    close(ready[1]);
    char c;
    read(ready[0], &c, 1);
    close(ready[0]);
    return t;
}

static const char *send_as(struct ids id, pid_t target, int sig)
{
    static char answer[32];
    int pfd[2];
    pipe(pfd);
    fflush(stdout);
    pid_t c = fork_or_die();
    if (c == 0) {
        alarm(5);
        become(id);
        const char *a = call(target, sig);
        write(pfd[1], a, strlen(a));
        _exit(0);
    }
    close(pfd[1]);
    int n = (int)read(pfd[0], answer, sizeof answer - 1);
    close(pfd[0]);
    waitpid(c, NULL, 0);
    answer[n > 0 ? n : 0] = 0;
    return answer;
}

/* How many reports a target's handler has written on `fd`: waiting up to
 * 300 ms for the first, and then taking what is there. */
static int drained(int fd)
{
    int got = 0;
    char x;
    while (1) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        struct timeval z = { 0, got == 0 ? 300000 : 0 };
        if (select(fd + 1, &set, NULL, NULL, &z) <= 0) break;
        if (read(fd, &x, 1) != 1) break;
        got++;
    }
    return got;
}

static void ids_name(char *b, size_t n, struct ids id)
{
    snprintf(b, n, "%d/%d/%d", (int)id.r, (int)id.e, (int)id.s);
}

static void section_cred(void)
{
    struct ids all[8];
    for (int i = 0; i < 8; i++) {
        all[i].r = (i & 4) ? 1001 : 1000;
        all[i].e = (i & 2) ? 1001 : 1000;
        all[i].s = (i & 1) ? 1001 : 1000;
    }
    int rep[2];
    pipe(rep);
    for (int ti = 0; ti < 8; ti++) {
        pid_t t = spawn_target(all[ti], rep[1], 0);
        for (int si = 0; si < 8; si++) {
            char sn[32], tn[32];
            ids_name(sn, sizeof sn, all[si]);
            ids_name(tn, sizeof tn, all[ti]);
            const char *a0 = send_as(all[si], t, 0);
            printf("section=cred sender=%s target=%s sig=0 answer=%s\n", sn, tn, a0);
            drained(rep[0]);
            const char *a1 = send_as(all[si], t, SIGUSR1);
            printf("section=cred sender=%s target=%s sig=USR1 answer=%s handled=%d\n", sn, tn, a1, drained(rep[0]));
        }
        kill(t, SIGKILL);
        waitpid(t, NULL, 0);
    }
    struct ids root = { 0, 0, 0 }, u1000 = { 1000, 1000, 1000 }, u1001 = { 1001, 1001, 1001 };
    pid_t t = spawn_target(u1000, rep[1], 0);
    const char *a = send_as(root, t, SIGUSR1);
    int handled = drained(rep[0]);
    printf("section=cred sender=0/0/0 target=1000/1000/1000 sig=USR1 answer=%s handled=%d\n", a, handled);
    printf("section=cred sender=1001/1001/1001 target=1000/1000/1000 sig=999 answer=%s\n", send_as(u1001, t, 999));
    kill(t, SIGKILL);
    waitpid(t, NULL, 0);
    t = spawn_target(root, rep[1], 0);
    a = send_as(u1000, t, SIGUSR1);
    handled = drained(rep[0]);
    printf("section=cred sender=1000/1000/1000 target=0/0/0 sig=USR1 answer=%s handled=%d\n", a, handled);
    printf("section=cred sender=1000/1000/1000 target=0/0/0 sig=0 answer=%s\n", send_as(u1000, t, 0));
    kill(t, SIGKILL);
    waitpid(t, NULL, 0);
    pid_t gone = reaped_pid();
    printf("section=cred sender=1000/1000/1000 target=reaped sig=999 answer=%s\n", send_as(u1000, gone, 999));
}

static void section_cont(void)
{
    struct ids u1000 = { 1000, 1000, 1000 }, u1001 = { 1001, 1001, 1001 };
    int rep[2];
    pipe(rep);
    for (int ns = 0; ns < 2; ns++) {
        pid_t t = spawn_target(u1001, rep[1], ns);
        printf("section=cont sender=1000 target=1001 session=%s sig=CONT answer=%s\n", ns ? "other" : "same", send_as(u1000, t, SIGCONT));
        printf("section=cont sender=1000 target=1001 session=%s sig=0 answer=%s\n", ns ? "other" : "same", send_as(u1000, t, 0));
        kill(t, SIGKILL);
        waitpid(t, NULL, 0);
    }
}

static void section_all(void)
{
    struct ids u1000 = { 1000, 1000, 1000 };
    printf("section=all sender=1000 others=none sig=0 answer=%s\n", send_as(u1000, -1, 0));
    int rep[2];
    pipe(rep);
    pid_t t = spawn_target(u1000, rep[1], 0);
    printf("section=all sender=1000 others=sibling-1000 sig=0 answer=%s\n", send_as(u1000, -1, 0));
    const char *a = send_as(u1000, -1, SIGUSR1);
    int handled = drained(rep[0]);
    printf("section=all sender=1000 others=sibling-1000 sig=USR1 answer=%s sibling-handled=%d\n", a, handled);
    kill(t, SIGKILL);
    waitpid(t, NULL, 0);
}

#endif

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d euid %d\n", u.sysname, u.release, u.machine, (int)getuid(), (int)geteuid());
    section_target();
    section_group();
#ifndef __APPLE__
    if (geteuid() == 0) {
        section_cred();
        section_cont();
        section_all();
    } else {
        printf("# not root: sections cred, cont and all skipped\n");
    }
#else
    printf("# Darwin has no setresuid: sections cred, cont and all skipped\n");
#endif
    return 0;
}
