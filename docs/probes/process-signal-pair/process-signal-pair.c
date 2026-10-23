// Which thread runs the handlers of two signals sent to the process in a row,
// and how a call the main thread is asleep in ends.
//
// Two threads: the main thread (the thread-group leader, `L`) and a second
// thread (`T`). Every signal involved has a handler that records which thread
// ran it, in the order the handlers start. T sends both signals with
// kill(getpid(), sig), A then B.
//
// What L does while T sends (`leader=`):
//   poll - L sleeps in poll(NULL, 0, -1). T sends A only once L is asleep in
//          it (Linux: /proc/self/task/<L>/stat says S and .../syscall names
//          the poll; Darwin: thread_info says TH_STATE_WAITING). L calls poll
//          again each time it returns, until T ends the row.
//   spin - L spins in user space, making no call, until T ends the row.
//
// What T does between the two kills (`gap=`):
//   none - nothing: B follows A at once.
//   ran  - T waits until L's first poll has returned and L is asleep in its
//          second poll, so L has run (and taken what it took) between the two.
//
// What T blocks, and whether there is a third thread (`others=`, only with
// leader=poll and gap=none):
//   T        - T blocks nothing, and is the only other thread.
//   T-blocks - T blocks A and B, and is the only other thread.
//   T-blocks+U - T blocks A and B, and a third thread, U, which blocks
//              nothing, sleeps in poll(NULL, 0, -1) (created after T).
//
// Where the threads run (`cpus=`, Linux only; Darwin cannot pin):
//   free  - wherever the scheduler puts them.
//   same  - both pinned to CPU 1.
//   apart - L pinned to CPU 1, T to CPU 2.
//
// 30 ms after B, T ends the row: it sets a flag and sends SIGWINCH to L
// with pthread_kill (its handler is recorded as `W`), which ends whichever
// poll L is in, and L leaves its loop.
//
// Each row is a fresh forked child, run TRIALS times, and its outcomes are
// counted. An outcome is:
//   the handlers in the order they started, each `<thread>:<signal>`;
//   for each poll L made, how it ended: `eintr` if it failed with EINTR and L
//     ran a handler for A or B as it returned (W's may have run at the same
//     return, where L ran only once T had sent W), `woken` if only W's ran
//     (the poll had not ended for A or B, so it slept on or restarted);
//     `poll1=` is the poll L was asleep in when A was sent;
//   on Linux, `lsw=` the voluntary context switches L made between just
//     before A and just before W (0: L never woke).
//
// Bounded: an alarm of 5 s in each child, TRIALS children per row, and a
// fixed list of rows.
//
// Darwin: cc -Wall -O1 -o /tmp/process-signal-pair process-signal-pair.c && /tmp/process-signal-pair
// Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'echo "# $(ldd --version | head -1), gcc:14 container" && gcc -Wall -O1 -pthread -o /tmp/p /probe/process-signal-pair.c && /tmp/p'
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <mach/mach.h>
#define FLAVOUR "darwin"
#else
#define FLAVOUR "linux"
#endif

#ifndef TRIALS
#define TRIALS 200
#endif
#define WAKE SIGWINCH

static const char *signame(int s)
{
    static char buf[4][16];
    static int k;
    char *b = buf[k++ & 3];
    if (s == SIGUSR1) return "USR1";
    if (s == SIGUSR2) return "USR2";
    if (s == WAKE) return "W";
#ifndef __APPLE__
    if (s >= SIGRTMIN && s <= SIGRTMAX) { snprintf(b, 16, "RTMIN+%d", s - SIGRTMIN); return b; }
#endif
    snprintf(b, 16, "sig%d", s);
    return b;
}

static void sleep_us(long us)
{
    struct timespec ts = { us / 1000000L, (us % 1000000L) * 1000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

#define MAXLOG 16
static volatile int log_sig[MAXLOG], log_who[MAXLOG];
static volatile int nlog;
static pthread_t leader_th;
static __thread int my_index; /* 0 L, 1 T, 2 U */

static void handler(int s)
{
    int i = __atomic_fetch_add(&nlog, 1, __ATOMIC_SEQ_CST);
    if (i < MAXLOG) {
        log_sig[i] = s;
        log_who[i] = my_index;
    }
}

#define MAXPOLL 8
static volatile int polls_returned;
static volatile int poll_wake_seen[MAXPOLL], poll_errno[MAXPOLL], poll_ret[MAXPOLL], poll_led[MAXPOLL];
static volatile int stop;

/* How many handlers for A or B the leader has run. */
static int leader_ran(void)
{
    int n = nlog < MAXLOG ? nlog : MAXLOG, c = 0;
    for (int i = 0; i < n; i++) if (log_sig[i] != WAKE && log_who[i] == 0) c++;
    return c;
}

static int wake_in_log(void)
{
    int n = nlog < MAXLOG ? nlog : MAXLOG;
    for (int i = 0; i < n; i++) if (log_sig[i] == WAKE) return 1;
    return 0;
}

#ifndef __APPLE__
static pid_t leader_tid;

static int read_file(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, n - 1, f);
    fclose(f);
    buf[got] = 0;
    return (int)got;
}

static int leader_asleep_in_poll(void)
{
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", (int)leader_tid);
    if (read_file(path, buf, sizeof buf) < 0) return 0;
    char *close = strrchr(buf, ')');
    if (!close || close[1] != ' ' || close[2] != 'S') return 0;
    snprintf(path, sizeof path, "/proc/self/task/%d/syscall", (int)leader_tid);
    if (read_file(path, buf, sizeof buf) < 0) return 0;
    long nr = strtol(buf, NULL, 10);
#ifdef SYS_poll
    if (nr == SYS_poll) return 1;
#endif
    return nr == SYS_ppoll;
}

static long leader_switches(void)
{
    char path[64], buf[2048];
    snprintf(path, sizeof path, "/proc/self/task/%d/status", (int)leader_tid);
    if (read_file(path, buf, sizeof buf) < 0) return -1;
    char *p = strstr(buf, "\nvoluntary_ctxt_switches:");
    return p ? strtol(p + strlen("\nvoluntary_ctxt_switches:"), NULL, 10) : -1;
}

static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) { perror("sched_setaffinity"); _exit(98); }
}
#else
static int leader_asleep_in_poll(void)
{
    mach_port_t port = pthread_mach_thread_np(leader_th);
    thread_basic_info_data_t info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (thread_info(port, THREAD_BASIC_INFO, (thread_info_t)&info, &count) != KERN_SUCCESS) return 0;
    return info.run_state == TH_STATE_WAITING;
}
#endif

struct row {
    const char *leader; /* "poll" or "spin" */
    const char *gap;    /* "none" or "ran" */
    const char *cpus;   /* "free", "same", "apart" */
    const char *others; /* "T", "T-blocks", "T-blocks+U" */
    int a, b;
};

static struct row cur;
static int out_fd;

static int wait_until(int (*cond)(void), long budget_us)
{
    for (long t = 0; t < budget_us; t += 100) {
        if (cond()) return 1;
        sleep_us(100);
    }
    return cond();
}

static int leader_asleep_in_second(void)
{
    return polls_returned >= 1 && leader_asleep_in_poll();
}

static void *idler(void *arg)
{
    (void)arg;
    my_index = 2;
#ifndef __APPLE__
    if (!strcmp(cur.cpus, "same")) pin(1);
    else if (!strcmp(cur.cpus, "apart")) pin(3);
#endif
    for (;;) poll(NULL, 0, -1);
    return NULL;
}

static void *sender(void *arg)
{
    (void)arg;
    my_index = 1;
#ifndef __APPLE__
    if (!strcmp(cur.cpus, "same")) pin(1);
    else if (!strcmp(cur.cpus, "apart")) pin(2);
#endif
    if (strcmp(cur.others, "T")) {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, cur.a);
        sigaddset(&set, cur.b);
        pthread_sigmask(SIG_BLOCK, &set, NULL);
    }
    char note[64] = "";
    if (!strcmp(cur.leader, "poll")) {
        if (!wait_until(leader_asleep_in_poll, 1000000)) strcpy(note, " never-asleep");
    } else {
        sleep_us(2000);
    }
#ifndef __APPLE__
    long sw0 = leader_switches();
#endif
    kill(getpid(), cur.a);
    if (!strcmp(cur.gap, "ran")) {
        if (!wait_until(leader_asleep_in_second, 1000000)) strcat(note, " never-reslept");
    }
    kill(getpid(), cur.b);
    sleep_us(30000);
#ifndef __APPLE__
    long sw1 = leader_switches();
#endif
    stop = 1;
    pthread_kill(leader_th, WAKE);

    char line[512];
    int len = 0;
    int n = nlog < MAXLOG ? nlog : MAXLOG;
    /* The handlers that ran before W: W's own, and any after it, are left out. */
    int first = 1;
    for (int i = 0; i < n; i++) {
        if (log_sig[i] == WAKE) continue;
        len += snprintf(line + len, sizeof line - len, "%s%s:%s", first ? "" : ",", log_who[i] == 0 ? "L" : log_who[i] == 1 ? "T" : "U", signame(log_sig[i]));
        first = 0;
    }
    if (first) len += snprintf(line + len, sizeof line - len, "nothing");
    /* Give L time to leave its last poll. */
    for (int t = 0; t < 1000 && !(polls_returned > 0 && poll_wake_seen[polls_returned - 1]) && strcmp(cur.leader, "spin"); t++)
        sleep_us(1000);
    for (int k = 0; k < polls_returned && k < MAXPOLL; k++) {
        if (poll_ret[k] != -1 || poll_errno[k] != EINTR)
            len += snprintf(line + len, sizeof line - len, " poll%d=ret%d/errno%d", k + 1, poll_ret[k], poll_errno[k]);
        else
            len += snprintf(line + len, sizeof line - len, " poll%d=%s", k + 1, poll_led[k] > (k == 0 ? 0 : poll_led[k - 1]) ? "eintr" : "woken");
    }
#ifndef __APPLE__
    len += snprintf(line + len, sizeof line - len, " lsw=%ld", sw1 - sw0);
#endif
    len += snprintf(line + len, sizeof line - len, "%s\n", note);
    write(out_fd, line, len);
    return NULL;
}

static void child(void)
{
    alarm(5);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sigaction(cur.a, &sa, NULL);
    sigaction(cur.b, &sa, NULL);
    sigaction(WAKE, &sa, NULL);
    leader_th = pthread_self();
#ifndef __APPLE__
    leader_tid = (pid_t)syscall(SYS_gettid);
    if (!strcmp(cur.cpus, "same") || !strcmp(cur.cpus, "apart")) pin(1);
#endif
    pthread_t t, u;
    pthread_create(&t, NULL, sender, NULL);
    if (!strcmp(cur.others, "T-blocks+U")) pthread_create(&u, NULL, idler, NULL);
    if (!strcmp(cur.leader, "poll")) {
        while (polls_returned < MAXPOLL) {
            int r = poll(NULL, 0, -1);
            int e = errno;
            int k = polls_returned;
            poll_ret[k] = r;
            poll_errno[k] = e;
            poll_wake_seen[k] = wake_in_log();
            poll_led[k] = leader_ran();
            __atomic_store_n(&polls_returned, k + 1, __ATOMIC_SEQ_CST);
            if (stop && poll_wake_seen[k]) break;
        }
    } else {
        while (!stop || !wake_in_log()) {}
    }
    pthread_join(t, NULL);
    _exit(0);
}

#define MAXOUT 64
static char outcomes[MAXOUT][512];
static int counts[MAXOUT], nout;

static void tally(const char *line)
{
    for (int i = 0; i < nout; i++)
        if (!strcmp(outcomes[i], line)) { counts[i]++; return; }
    if (nout < MAXOUT) { strcpy(outcomes[nout], line); counts[nout++] = 1; }
}

static void run(struct row r)
{
    cur = r;
    nout = 0;
    for (int trial = 0; trial < TRIALS; trial++) {
        int p[2];
        if (pipe(p) != 0) { perror("pipe"); exit(1); }
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) { close(p[0]); out_fd = p[1]; child(); }
        close(p[1]);
        char line[512];
        int len = 0, got;
        while ((got = (int)read(p[0], line + len, sizeof line - 1 - len)) > 0) len += got;
        close(p[0]);
        line[len] = 0;
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = 0;
        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            char end[640];
            snprintf(end, sizeof end, "%s end=%s%d", line, WIFSIGNALED(status) ? "signal" : "exit", WIFSIGNALED(status) ? WTERMSIG(status) : WEXITSTATUS(status));
            tally(end);
        } else {
            tally(line);
        }
    }
    for (int i = 0; i < nout; i++)
        printf("leader=%s gap=%s others=%s cpus=%s A=%s B=%s count=%d/%d outcome: %s\n", r.leader, r.gap, r.others, r.cpus, signame(r.a), signame(r.b), counts[i], TRIALS, outcomes[i]);
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d, %ld cpus online\n", u.sysname, u.release, u.machine, (int)getuid(), sysconf(_SC_NPROCESSORS_ONLN));
    printf("# flavour %s USR1=%d USR2=%d W=SIGWINCH=%d", FLAVOUR, SIGUSR1, SIGUSR2, WAKE);
#ifndef __APPLE__
    printf(" RTMIN=%d", SIGRTMIN);
#endif
    printf("\n");
    int pairs[8][2];
    int npairs = 0;
    pairs[npairs][0] = SIGUSR1; pairs[npairs++][1] = SIGUSR2;
    pairs[npairs][0] = SIGUSR2; pairs[npairs++][1] = SIGUSR1;
    pairs[npairs][0] = SIGUSR1; pairs[npairs++][1] = SIGUSR1;
#ifndef __APPLE__
    pairs[npairs][0] = SIGRTMIN; pairs[npairs++][1] = SIGRTMIN;
    pairs[npairs][0] = SIGRTMIN; pairs[npairs++][1] = SIGRTMIN + 1;
    pairs[npairs][0] = SIGRTMIN + 1; pairs[npairs++][1] = SIGRTMIN;
    const char *cpus[] = { "free", "same", "apart" };
    int ncpus = 3;
#else
    const char *cpus[] = { "free" };
    int ncpus = 1;
#endif
    for (int c = 0; c < ncpus; c++)
        for (int i = 0; i < npairs; i++) {
            run((struct row){ "poll", "none", cpus[c], "T", pairs[i][0], pairs[i][1] });
            run((struct row){ "poll", "ran", cpus[c], "T", pairs[i][0], pairs[i][1] });
            run((struct row){ "spin", "none", cpus[c], "T", pairs[i][0], pairs[i][1] });
            run((struct row){ "poll", "none", cpus[c], "T-blocks", pairs[i][0], pairs[i][1] });
            run((struct row){ "poll", "none", cpus[c], "T-blocks+U", pairs[i][0], pairs[i][1] });
        }
    return 0;
}
