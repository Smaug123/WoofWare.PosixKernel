// What happens to a signal sent while the sender's user already has
// RLIMIT_SIGPENDING signals queued: real-time and standard, by kill(2),
// sigqueue(3) and pthread_kill(3) (Linux's tgkill), as the user the probe runs
// as. On Darwin, which has no real-time signals and no RLIMIT_SIGPENDING, it
// reports what the platform has and how often a blocked standard signal sent
// eight times is delivered.
//
// Linux sections, each row in a fresh forked child that blocks every signal but SIGALRM (its watchdog),
// lowers its RLIMIT_SIGPENDING (soft and hard) to `limit`, and sends to itself:
//   send  - eight sends of one signal by one method, each send's answer, then
//           SigQ from /proc/self/status, then every instance drained with
//           sigtimedwait (zero timeout), each with its si_code and whether its
//           si_pid is the sender's (`pid=own`) or 0 (`pid=0`): an instance
//           whose information was lost on the way.
//   mixed - `limit` real-time signals queued by sigqueue, then one more send
//           of another signal (standard or real-time) by each method.
//   user  - the limit is the user's, not the process's: a sibling process of
//           the same user holds `limit` real-time signals queued while this
//           one sends.
//   bare  - a send whose allocation failed leaves the pending bit alone: what
//           that instance counts against the limit, and what an allocated
//           instance of the same signal does beside it.
//   other - the queue of a different user: as root only, a child that becomes
//           uid 1000 (with its limit lowered) and holds `limit` signals queued
//           is sent sigqueue by root, and root's own queue is empty.
//
// Bounded: an alarm of 5 s in each child, and a fixed list of rows.
//
// Darwin: cc -Wall -o /tmp/rt-queue-limit rt-queue-limit.c && /tmp/rt-queue-limit
// Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1), gcc:14 container" && gcc -Wall -O1 -pthread -o /tmp/p /probe/rt-queue-limit.c && /tmp/p'
//         and as uid 1000: ... && setpriv --reuid=1000 --regid=1000 --clear-groups /tmp/p'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
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
    case EAGAIN: return "EAGAIN";
    case EINVAL: return "EINVAL";
    case EPERM: return "EPERM";
    case ESRCH: return "ESRCH";
    }
    static char b[16];
    snprintf(b, sizeof b, "errno%d", e);
    return b;
}

/* fork(2), or the probe stops: a failed fork's -1, later signalled, would be
 * kill(-1, ...). */
static pid_t fork_or_die(void)
{
    pid_t p = fork();
    if (p < 0) { perror("fork"); exit(98); }
    return p;
}

/* Every signal but SIGALRM, which a row's watchdog alarm raises. */
static void all_but_alarm(sigset_t *set)
{
    sigfillset(set);
    sigdelset(set, SIGALRM);
}

static void block_all(void)
{
    sigset_t all;
    all_but_alarm(&all);
    sigprocmask(SIG_BLOCK, &all, NULL);
}

#ifndef __APPLE__
static const char *signame(int s)
{
    static char b[4][16];
    static int k;
    char *o = b[k++ & 3];
    if (s == SIGUSR1) return "USR1";
    if (s == SIGUSR2) return "USR2";
    if (s >= SIGRTMIN && s <= SIGRTMAX) { snprintf(o, 16, "RTMIN+%d", s - SIGRTMIN); return o; }
    snprintf(o, 16, "sig%d", s);
    return o;
}

static const char *codename(int c)
{
    switch (c) {
    case SI_USER: return "SI_USER";
    case SI_QUEUE: return "SI_QUEUE";
    case SI_TKILL: return "SI_TKILL";
    }
    static char b[16];
    snprintf(b, sizeof b, "code%d", c);
    return b;
}

static int send_by(const char *method, int sig)
{
    errno = 0;
    int r;
    if (!strcmp(method, "kill")) r = kill(getpid(), sig);
    else if (!strcmp(method, "sigqueue")) { union sigval v = { .sival_int = 7 }; r = sigqueue(getpid(), sig, v); }
    else { int e = pthread_kill(pthread_self(), sig); r = e ? -1 : 0; errno = e; }
    return r == 0 ? 0 : errno;
}

static void set_limit(rlim_t limit)
{
    struct rlimit rl = { limit, limit };
    if (setrlimit(RLIMIT_SIGPENDING, &rl) != 0) { perror("setrlimit"); _exit(96); }
}

static void sigq(char *out, size_t n)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    out[0] = 0;
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "SigQ:", 5)) {
            char *p = line + 5;
            while (*p == ' ' || *p == '\t') p++;
            p[strcspn(p, "\n")] = 0;
            snprintf(out, n, "%s", p);
        }
    if (f) fclose(f);
}

static int drain(char *out, size_t n)
{
    sigset_t all;
    all_but_alarm(&all);
    struct timespec zero = { 0, 0 };
    int count = 0;
    size_t len = strlen(out);
    for (;;) {
        siginfo_t si;
        int s = sigtimedwait(&all, &si, &zero);
        if (s < 0) break;
        count++;
        len += snprintf(out + len, n - len, " %s/%s/pid=%s", signame(s), codename(si.si_code), si.si_pid == getpid() ? "own" : si.si_pid == 0 ? "0" : "other");
    }
    return count;
}

/* One child: run `body`, which prints one line to `fd`. */
static void in_child(void (*body)(int fd, void *arg), void *arg)
{
    int p[2];
    pipe(p);
    fflush(stdout);
    pid_t c = fork_or_die();
    if (c == 0) {
        alarm(5);
        close(p[0]);
        body(p[1], arg);
        _exit(0);
    }
    close(p[1]);
    char buf[4096];
    int len = 0, got;
    while ((got = (int)read(p[0], buf + len, sizeof buf - 1 - len)) > 0) len += got;
    close(p[0]);
    int status;
    waitpid(c, &status, 0);
    buf[len] = 0;
    fputs(buf, stdout);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) printf("  (child ended with status 0x%x)\n", status);
}

struct send_row { const char *method; int sig; rlim_t limit; };

static void send_body(int fd, void *arg)
{
    struct send_row *r = arg;
    block_all();
    set_limit(r->limit);
    char out[2048];
    int len = snprintf(out, sizeof out, "section=send limit=%d method=%s sig=%s answers:", (int)r->limit, r->method, signame(r->sig));
    for (int i = 0; i < 8; i++) len += snprintf(out + len, sizeof out - len, " %s", errname(send_by(r->method, r->sig)));
    char q[64];
    sigq(q, sizeof q);
    len += snprintf(out + len, sizeof out - len, " sigq=%s drained:", q);
    int n = drain(out, sizeof out);
    len = (int)strlen(out);
    len += snprintf(out + len, sizeof out - len, " count=%d\n", n);
    write(fd, out, len);
}

struct mixed_row { const char *method; int sig; rlim_t limit; };

static void mixed_body(int fd, void *arg)
{
    struct mixed_row *r = arg;
    block_all();
    set_limit(r->limit);
    char out[2048];
    int len = snprintf(out, sizeof out, "section=mixed limit=%d fill=sigqueue(RTMIN)x%d then method=%s sig=%s fill-answers:", (int)r->limit, (int)r->limit, r->method, signame(r->sig));
    for (rlim_t i = 0; i < r->limit; i++) len += snprintf(out + len, sizeof out - len, " %s", errname(send_by("sigqueue", SIGRTMIN)));
    len += snprintf(out + len, sizeof out - len, " answer=%s", errname(send_by(r->method, r->sig)));
    char q[64];
    sigq(q, sizeof q);
    len += snprintf(out + len, sizeof out - len, " sigq=%s drained:", q);
    int n = drain(out, sizeof out);
    len = (int)strlen(out);
    len += snprintf(out + len, sizeof out - len, " count=%d\n", n);
    write(fd, out, len);
}

static void user_body(int fd, void *arg)
{
    const char *method = arg;
    rlim_t limit = 4;
    int ready[2], done[2];
    pipe(ready);
    pipe(done);
    pid_t sib = fork_or_die();
    if (sib == 0) {
        alarm(5);
        close(fd);
        block_all();
        set_limit(limit);
        char c = 0;
        for (rlim_t i = 0; i < limit; i++) if (send_by("sigqueue", SIGRTMIN) == 0) c++;
        write(ready[1], &c, 1);
        read(done[0], &c, 1);
        _exit(0);
    }
    char c;
    if (read(ready[0], &c, 1) != 1) { perror("sibling never ready"); _exit(94); }
    int held = c;
    block_all();
    set_limit(limit);
    char out[1024];
    int answer = send_by(method, SIGRTMIN);
    int len = snprintf(out, sizeof out, "section=user limit=%d sibling-holds=%d%s method=%s sig=RTMIN answer=%s", (int)limit, held, held == (int)limit ? "" : "(incomplete)", method, errname(answer));
    char q[64];
    sigq(q, sizeof q);
    len += snprintf(out + len, sizeof out - len, " sigq=%s drained:", q);
    int n = drain(out, sizeof out);
    len = (int)strlen(out);
    len += snprintf(out + len, sizeof out - len, " count=%d\n", n);
    write(done[1], &c, 1);
    waitpid(sib, NULL, 0);
    write(fd, out, len);
}

/* Take one instance of `sig` alone, and say what it carried. */
static void take_one(int sig, char *out, size_t n)
{
    sigset_t one;
    sigemptyset(&one);
    sigaddset(&one, sig);
    struct timespec zero = { 0, 0 };
    siginfo_t si;
    int s = sigtimedwait(&one, &si, &zero);
    size_t len = strlen(out);
    if (s < 0) snprintf(out + len, n - len, " took-%s:none", signame(sig));
    else snprintf(out + len, n - len, " took-%s:%s/pid=%s", signame(s), codename(si.si_code), si.si_pid == getpid() ? "own" : si.si_pid == 0 ? "0" : "other");
}

static void sigq_into(char *out, size_t n)
{
    char q[64];
    sigq(q, sizeof q);
    size_t len = strlen(out);
    snprintf(out + len, n - len, " sigq=%s", q);
}

/* A signal whose allocation failed is held as the pending bit alone: what
 * that instance counts against the limit, and what becomes of it beside an
 * instance that was allocated. */
static void bare_body(int fd, void *arg)
{
    int row = (int)(long)arg;
    block_all();
    char out[2048] = "";
    int len = 0;
    switch (row) {
    case 0:
        /* A real-time instance with no allocation, then an allocated one of
         * the same signal once there is room again. */
        set_limit(1);
        len = snprintf(out, sizeof out, "section=bare row=rt-bare-then-allocated limit=1 sigqueue(RTMIN)=%s", errname(send_by("sigqueue", SIGRTMIN)));
        len += snprintf(out + len, sizeof out - len, " kill(RTMIN+1)=%s", errname(send_by("kill", SIGRTMIN + 1)));
        sigq_into(out, sizeof out);
        take_one(SIGRTMIN, out, sizeof out);
        sigq_into(out, sizeof out);
        len = (int)strlen(out);
        len += snprintf(out + len, sizeof out - len, " sigqueue(RTMIN+1)=%s", errname(send_by("sigqueue", SIGRTMIN + 1)));
        sigq_into(out, sizeof out);
        break;
    case 1:
        /* An allocated real-time instance, then a kill of the same signal with
         * no room. */
        set_limit(1);
        len = snprintf(out, sizeof out, "section=bare row=rt-allocated-then-bare limit=1 sigqueue(RTMIN+1)=%s", errname(send_by("sigqueue", SIGRTMIN + 1)));
        len += snprintf(out + len, sizeof out - len, " kill(RTMIN+1)=%s", errname(send_by("kill", SIGRTMIN + 1)));
        sigq_into(out, sizeof out);
        break;
    case 2:
        /* A standard instance with no allocation does not count: with it
         * pending, there is room for an allocated one. */
        set_limit(1);
        len = snprintf(out, sizeof out, "section=bare row=standard-bare-counts limit=1 sigqueue(RTMIN)=%s", errname(send_by("sigqueue", SIGRTMIN)));
        len += snprintf(out + len, sizeof out - len, " pthread_kill(USR1)=%s", errname(send_by("pthread_kill", SIGUSR1)));
        sigq_into(out, sizeof out);
        take_one(SIGRTMIN, out, sizeof out);
        sigq_into(out, sizeof out);
        len = (int)strlen(out);
        len += snprintf(out + len, sizeof out - len, " sigqueue(RTMIN+1)=%s", errname(send_by("sigqueue", SIGRTMIN + 1)));
        sigq_into(out, sizeof out);
        break;
    case 3:
        /* A standard instance with no allocation on the thread, sent to the
         * thread again (coalesced?), then sent to the process, which has a
         * pending set of its own and allocates past the limit. */
        set_limit(0);
        len = snprintf(out, sizeof out, "section=bare row=standard-bare-twice-then-kill limit=0 pthread_kill(USR1)=%s", errname(send_by("pthread_kill", SIGUSR1)));
        len += snprintf(out + len, sizeof out - len, " pthread_kill(USR1)=%s", errname(send_by("pthread_kill", SIGUSR1)));
        len += snprintf(out + len, sizeof out - len, " kill(USR1)=%s", errname(send_by("kill", SIGUSR1)));
        sigq_into(out, sizeof out);
        break;
    }
    len = (int)strlen(out);
    len += snprintf(out + len, sizeof out - len, " drained:");
    int count = drain(out, sizeof out);
    len = (int)strlen(out);
    len += snprintf(out + len, sizeof out - len, " count=%d\n", count);
    write(fd, out, len);
}

static void other_body(int fd, void *arg)
{
    (void)arg;
    rlim_t limit = 4;
    int ready[2], done[2], res[2];
    pipe(ready);
    pipe(done);
    pipe(res);
    pid_t t = fork_or_die();
    if (t == 0) {
        alarm(5);
        close(fd);
        block_all();
        set_limit(limit);
        if (setresgid(1000, 1000, 1000) || setresuid(1000, 1000, 1000)) { perror("setresuid"); _exit(95); }
        char c = 0;
        for (rlim_t i = 0; i < limit; i++) if (send_by("sigqueue", SIGRTMIN) == 0) c++;
        write(ready[1], &c, 1);
        read(done[0], &c, 1);
        char out[1024] = "";
        char q[64];
        sigq(q, sizeof q);
        snprintf(out, sizeof out, " target-sigq-after=%s target-drained:", q);
        int n = drain(out, sizeof out);
        size_t len = strlen(out);
        len += snprintf(out + len, sizeof out - len, " count=%d", n);
        write(res[1], out, len);
        _exit(0);
    }
    char c;
    if (read(ready[0], &c, 1) != 1) { perror("target never ready"); _exit(94); }
    int held = c;
    char out[2048];
    union sigval v = { .sival_int = 7 };
    errno = 0;
    int r = sigqueue(t, SIGRTMIN, v);
    int e = r == 0 ? 0 : errno;
    errno = 0;
    int r2 = kill(t, SIGRTMIN + 1);
    int e2 = r2 == 0 ? 0 : errno;
    int len = snprintf(out, sizeof out, "section=other limit=%d target=uid1000-holding-%d%s sender=uid%d sigqueue(RTMIN)=%s", (int)limit, held, held == (int)limit ? "" : "(incomplete)", (int)getuid(), errname(e));
    len += snprintf(out + len, sizeof out - len, " kill(RTMIN+1)=%s", errname(e2));
    write(done[1], &c, 1);
    close(res[1]);
    int got;
    while ((got = (int)read(res[0], out + len, sizeof out - 1 - len)) > 0) len += got;
    waitpid(t, NULL, 0);
    out[len++] = '\n';
    write(fd, out, len);
}
#endif

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d\n", u.sysname, u.release, u.machine, (int)getuid());
    printf("# NSIG=%d sigqueue=%s", NSIG, dlsym(RTLD_DEFAULT, "sigqueue") ? "present" : "absent");
#ifdef SIGRTMIN
    printf(" SIGRTMIN=%d SIGRTMAX=%d", SIGRTMIN, SIGRTMAX);
#else
    printf(" SIGRTMIN=undefined");
#endif
#ifdef RLIMIT_SIGPENDING
    struct rlimit rl;
    getrlimit(RLIMIT_SIGPENDING, &rl);
    printf(" RLIMIT_SIGPENDING=%llu/%llu", (unsigned long long)rl.rlim_cur, (unsigned long long)rl.rlim_max);
#else
    printf(" RLIMIT_SIGPENDING=undefined");
#endif
    printf("\n");
#ifdef __APPLE__
    {
        /* Eight blocked SIGUSR1 by kill, then unblocked under a counting handler. */
        fflush(stdout);
        pid_t c = fork_or_die();
        if (c == 0) {
            alarm(5);
            block_all();
            int answers[8];
            for (int i = 0; i < 8; i++) answers[i] = kill(getpid(), SIGUSR1) == 0 ? 0 : errno;
            sigset_t pending;
            sigpending(&pending);
            int delivered = 0;
            for (;;) {
                sigset_t want;
                sigemptyset(&want);
                sigaddset(&want, SIGUSR1);
                sigpending(&pending);
                if (!sigismember(&pending, SIGUSR1)) break;
                int s;
                sigwait(&want, &s);
                delivered++;
            }
            printf("section=send method=kill sig=USR1 answers:");
            for (int i = 0; i < 8; i++) printf(" %s", errname(answers[i]));
            printf(" delivered=%d\n", delivered);
            fflush(stdout);
            _exit(0);
        }
        waitpid(c, NULL, 0);
    }
#else
    const char *methods[] = { "kill", "sigqueue", "pthread_kill" };
    rlim_t limits[] = { 4, 0 };
    for (int l = 0; l < 2; l++)
        for (int m = 0; m < 3; m++) {
            struct send_row rt = { methods[m], SIGRTMIN, limits[l] };
            in_child(send_body, &rt);
            struct send_row std = { methods[m], SIGUSR1, limits[l] };
            in_child(send_body, &std);
        }
    for (int m = 0; m < 3; m++) {
        struct mixed_row a = { methods[m], SIGUSR1, 4 };
        in_child(mixed_body, &a);
        struct mixed_row b = { methods[m], SIGRTMIN + 1, 4 };
        in_child(mixed_body, &b);
    }
    for (int m = 0; m < 3; m++) in_child(user_body, (void *)methods[m]);
    for (long row = 0; row < 4; row++) in_child(bare_body, (void *)row);
    if (geteuid() == 0) in_child(other_body, NULL);
    else printf("# not root: section other skipped\n");
#endif
    return 0;
}
