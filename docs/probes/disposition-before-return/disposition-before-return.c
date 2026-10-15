// What a call a caught signal interrupted answers when another thread changes
// that signal's disposition after the signal has woken the sleeping thread and
// before that thread has run again.
//
// Every row runs in a fresh forked child. Its thread S makes a blocking call
// that nothing else will end; its main thread M sends S the signal
// (pthread_kill) and changes the signal's disposition while S, woken, waits
// for a processor, and only then lets S run. The calls:
//
//   pause      pause() (on Linux aarch64, glibc makes it ppoll(NULL, 0, NULL, NULL))
//   sigsuspend sigsuspend() of an empty mask
//   read       read() of an empty pipe whose write end stays open
//   write      a 1-byte write() into a full pipe, nothing of it written
//   poll       poll() of the empty pipe's read end, timeout -1
//   epoll      Linux: epoll_wait(-1) on an epoll instance holding that read end
//   kevent     Darwin: kevent() with no timeout on a kqueue holding EVFILT_READ of it
//   flock      flock(LOCK_EX) of a file another open file description holds locked
//   accept     accept() on a loopback listener with nothing queued
//   tcp-read   read() of a connected loopback TCP socket with nothing to read
//   tcp-write  a 1000-byte write() to a connected loopback TCP socket whose
//              send buffer is full, nothing of it taken (as `tcp-blocking.c`'s
//              W-empty makes it: Darwin takes a 1-byte write into a "full" one)
//   inotify    Linux: read() of an inotify instance with no record queued
//
// The signal is SIGUSR1, caught by handler h1, installed with SA_RESTART
// (`restart=1`) or without. The changes M makes:
//
//   none  nothing: the control, in which h1 runs.
//   ign   sigaction(SIGUSR1, SIG_IGN), which discards the pending signal.
//   dfl   sigaction(SIGUSR1, SIG_DFL), whose default terminates the process.
//   swap  sigaction(SIGUSR1, h2), with the opposite SA_RESTART to h1's.
//
// How M holds S off the processor between the signal and the change:
//
//   Linux, held: S and M share CPU 0 under SCHED_FIFO, M at the higher
//     priority, so the signal makes S runnable and S cannot run until M
//     sleeps, after the change. M reads S's state from /proc just before it
//     changes the disposition (`s-state`: R is runnable, S is asleep).
//   Darwin, held: S runs at QOS_CLASS_BACKGROUND, and while S sleeps M starts
//     twice as many spinning threads as there are processors, at
//     QOS_CLASS_USER_INTERACTIVE, as M itself runs; M sends the signal,
//     changes the disposition, and stops the spinners. Nothing pins S off the
//     processors, so each row says whether the hold held: in a row that
//     changes the disposition, h1 runs only if S took its signal before the
//     change. `h1-at-change` is how often h1 had run when M made the change.
//   free (both): no hold. M changes the disposition 50 ms after the signal,
//     by which time S has long since run: the control, in which the change
//     comes too late to matter.
//
// 50 ms after it lets S go (250 ms in Darwin's held mode, whose S runs in
// the background QoS class), M reports whether S's call has returned. If it
// has not, M ends it: pause and sigsuspend with SIGUSR2, whose handler is
// installed without SA_RESTART, and every other call by making its condition
// hold (a byte into the pipe or the socket, a read of the full pipe or of the
// peer's socket, a connect, an unlock, a file created in the watched
// directory). S then reports what the call answered (`ret`, `errno`), and the
// runs of h1, h2 and the SIGUSR2 handler. `end=` is how the child ended:
// `exit0`, or `signalN` if a signal killed it.
//
// So `returned-before-release=0` with the release's answer is a call that
// went on sleeping (or was restarted, which no row tells apart), and
// `returned-before-release=1` is one that returned.
//
// Bounded: an alarm of 5 s in each child, and a fixed list of rows.
//
// Darwin: cc -Wall -o /tmp/dbr disposition-before-return.c && /tmp/dbr
// Linux:  container run --rm --cap-add CAP_SYS_NICE -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -pthread -o /tmp/dbr /probe/disposition-before-return.c && /tmp/dbr'
//
// Measured 2026-10-15 on Linux 6.18.5 aarch64 (Apple `container`, gcc:14
// image, glibc 2.41, root) and Darwin 27.0.0 arm64 (uid 501); the outputs are
// measured-linux-6.18.5-aarch64-uid0.txt and measured-darwin-27.0-uid501.txt.
// Linux gave the same output in four runs. Darwin gave the committed output in
// two runs of three; in the third one held row (kevent, restart=1, ign) ran
// h1, its hold having failed, and every other row was the same. In the held
// rows, on both flavours:
//   none  h1 runs and the call answers EINTR, or under SA_RESTART goes on
//         sleeping where `SyscallInterruption.ruleOf` says it restarts.
//   ign   no handler runs. Linux's epoll_wait, and Darwin's poll and kevent,
//         answer EINTR; every other call goes on sleeping, SA_RESTART or not,
//         and answers what its release makes it answer.
//   dfl   the process dies of SIGUSR1, the call never answering.
//   swap  h2 runs, never h1, and the call answers as h2's SA_RESTART says:
//         EINTR without it, and with it, sleeping on where the call restarts.
// So the signal that woke S is taken with the disposition it has as S runs,
// which the calls' own answers follow. By Linux's source, a call's own code
// only asks whether a signal is pending, and the disposition is read as the
// thread returns to user mode (`get_signal`), so this is also what a change
// made after the call has answered and before that return does. By XNU's,
// `_sleep` reads the signal's `SA_RESTART` as the woken thread runs, before
// its return delivers the signal, and this hold cannot tell those apart.
// In the free rows nothing changes what was already done: h1 has run.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/syscall.h>
#define FLAVOUR "linux"
#else
#include <pthread/qos.h>
#include <sys/event.h>
#define FLAVOUR "darwin"
#endif

static void die(const char *what) { perror(what); _exit(99); }

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
}

static volatile sig_atomic_t h1_runs = 0;
static volatile sig_atomic_t h2_runs = 0;
static volatile sig_atomic_t release_runs = 0;
static void h1(int sig) { (void)sig; h1_runs++; }
static void h2(int sig) { (void)sig; h2_runs++; }
static void on_release(int sig) { (void)sig; release_runs++; }

static void install(int signo, void (*handler)(int), int restart)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(signo, &sa, NULL) != 0) die("sigaction");
}

static void set_nonblocking(int fd, int on)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) die("F_GETFL");
    if (fcntl(fd, F_SETFL, on ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) != 0) die("F_SETFL");
}

enum call {
    CALL_PAUSE,
    CALL_SIGSUSPEND,
    CALL_READ,
    CALL_WRITE,
    CALL_POLL,
    CALL_EVENTS,
    CALL_FLOCK,
    CALL_ACCEPT,
    CALL_TCP_READ,
    CALL_TCP_WRITE,
    CALL_INOTIFY,
    CALL_COUNT
};
static const char *call_names[] = {
    "pause", "sigsuspend", "read", "write", "poll",
#ifdef __linux__
    "epoll",
#else
    "kevent",
#endif
    "flock", "accept", "tcp-read", "tcp-write", "inotify",
};

enum change { CHANGE_NONE, CHANGE_IGN, CHANGE_DFL, CHANGE_SWAP };
static const char *change_names[] = { "none", "ign", "dfl", "swap" };

struct row {
    enum call call;
    int restart;
    enum change change;
    int held;
};

// What S's call works on, made before S starts.
static int empty_pipe[2];
static int full_pipe[2];
static int events_fd = -1;
static int lock_holder = -1;
static int lock_waiter = -1;
static int listener = -1;
static struct sockaddr_in listener_address;
static int tcp_mine = -1;
static int tcp_peer = -1;
static int inotify_fd = -1;
static char scratch_dir[64];

static atomic_int s_entered = 0;
static atomic_int s_returned = 0;
static int s_ret = 0;
static int s_errno = 0;
#ifdef __linux__
static atomic_int s_tid = 0;
#endif

static int loopback_listener(struct sockaddr_in *address)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket");
    memset(address, 0, sizeof *address);
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)address, sizeof *address) != 0) die("bind");
    socklen_t length = sizeof *address;
    if (getsockname(s, (struct sockaddr *)address, &length) != 0) die("getsockname");
    if (listen(s, 8) != 0) die("listen");
    return s;
}

static int connect_to(struct sockaddr_in *address)
{
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0) die("socket");
    if (connect(c, (struct sockaddr *)address, sizeof *address) != 0) die("connect");
    return c;
}

static void fill(int fd)
{
    static char chunk[4096];
    set_nonblocking(fd, 1);
    // Until a write of one byte has found no room three times running, 20 ms
    // apart: a TCP connection goes on moving bytes into the peer's receive
    // buffer for a while after the sender's has filled.
    for (int full = 0; full < 3;) {
        int moved = 0;
        for (;;) {
            ssize_t n = write(fd, chunk, sizeof chunk);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) die("fill");
            moved = 1;
        }
        for (;;) {
            ssize_t n = write(fd, chunk, 1);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) die("fill");
            moved = 1;
        }
        full = moved ? 0 : full + 1;
        sleep_ms(20);
    }
    set_nonblocking(fd, 0);
}

static void drain(int fd)
{
    static char chunk[65536];
    set_nonblocking(fd, 1);
    for (int idle = 0; idle < 20;) {
        ssize_t n = read(fd, chunk, sizeof chunk);
        if (n > 0) {
            idle = 0;
            continue;
        }
        idle++;
        sleep_ms(5);
    }
}

static void set_up(struct row *row)
{
    if (pipe(empty_pipe) != 0) die("pipe");
    switch (row->call) {
    case CALL_WRITE:
        if (pipe(full_pipe) != 0) die("pipe");
        fill(full_pipe[1]);
        break;
    case CALL_EVENTS: {
#ifdef __linux__
        events_fd = epoll_create1(0);
        if (events_fd < 0) die("epoll_create1");
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = empty_pipe[0] };
        if (epoll_ctl(events_fd, EPOLL_CTL_ADD, empty_pipe[0], &ev) != 0) die("epoll_ctl");
#else
        events_fd = kqueue();
        if (events_fd < 0) die("kqueue");
        struct kevent change;
        EV_SET(&change, empty_pipe[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (kevent(events_fd, &change, 1, NULL, 0, NULL) != 0) die("kevent register");
#endif
        break;
    }
    case CALL_FLOCK: {
        char path[64];
        snprintf(path, sizeof path, "/tmp/dbr-lock-%d", (int)getpid());
        lock_holder = open(path, O_RDWR | O_CREAT, 0600);
        lock_waiter = open(path, O_RDWR);
        unlink(path);
        if (lock_holder < 0 || lock_waiter < 0) die("open lock file");
        if (flock(lock_holder, LOCK_EX) != 0) die("flock holder");
        break;
    }
    case CALL_ACCEPT: listener = loopback_listener(&listener_address); break;
    case CALL_TCP_READ:
    case CALL_TCP_WRITE: {
        struct sockaddr_in address;
        int l = loopback_listener(&address);
        tcp_mine = connect_to(&address);
        tcp_peer = accept(l, NULL, NULL);
        if (tcp_peer < 0) die("accept");
        close(l);
        if (row->call == CALL_TCP_WRITE) fill(tcp_mine);
        break;
    }
    case CALL_INOTIFY: {
#ifdef __linux__
        snprintf(scratch_dir, sizeof scratch_dir, "/tmp/dbr-dir-%d", (int)getpid());
        if (mkdir(scratch_dir, 0700) != 0) die("mkdir");
        inotify_fd = inotify_init1(0);
        if (inotify_fd < 0) die("inotify_init1");
        if (inotify_add_watch(inotify_fd, scratch_dir, IN_CREATE) < 0) die("inotify_add_watch");
#endif
        break;
    }
    default: break;
    }
}

static void *sleeper(void *arg)
{
    struct row *row = arg;
#ifdef __linux__
    atomic_store(&s_tid, (int)syscall(SYS_gettid));
#endif
    char buffer[4096];
    struct pollfd pfd = { empty_pipe[0], POLLIN, 0 };
    sigset_t empty;
    sigemptyset(&empty);
    atomic_store(&s_entered, 1);
    int r = 0;
    switch (row->call) {
    case CALL_PAUSE: r = pause(); break;
    case CALL_SIGSUSPEND: r = sigsuspend(&empty); break;
    case CALL_READ: r = (int)read(empty_pipe[0], buffer, 1); break;
    case CALL_WRITE: r = (int)write(full_pipe[1], buffer, 1); break;
    case CALL_POLL: r = poll(&pfd, 1, -1); break;
    case CALL_EVENTS: {
#ifdef __linux__
        struct epoll_event ev;
        r = epoll_wait(events_fd, &ev, 1, -1);
#else
        struct kevent ev;
        r = kevent(events_fd, NULL, 0, &ev, 1, NULL);
#endif
        break;
    }
    case CALL_FLOCK: r = flock(lock_waiter, LOCK_EX); break;
    case CALL_ACCEPT: r = accept(listener, NULL, NULL); break;
    case CALL_TCP_READ: r = (int)read(tcp_mine, buffer, 1); break;
    case CALL_TCP_WRITE: r = (int)write(tcp_mine, buffer, 1000); break;
    case CALL_INOTIFY: r = (int)read(inotify_fd, buffer, sizeof buffer); break;
    default: break;
    }
    s_errno = errno;
    s_ret = r;
    atomic_store(&s_returned, 1);
    return NULL;
}

static void release(struct row *row, pthread_t s)
{
    char byte = 'x';
    switch (row->call) {
    case CALL_PAUSE:
    case CALL_SIGSUSPEND: pthread_kill(s, SIGUSR2); break;
    case CALL_READ:
    case CALL_POLL:
    case CALL_EVENTS:
        if (write(empty_pipe[1], &byte, 1) != 1) die("write release");
        break;
    case CALL_WRITE: drain(full_pipe[0]); break;
    case CALL_FLOCK:
        if (flock(lock_holder, LOCK_UN) != 0) die("unlock");
        break;
    case CALL_ACCEPT: connect_to(&listener_address); break;
    case CALL_TCP_READ:
        if (write(tcp_peer, &byte, 1) != 1) die("send release");
        break;
    case CALL_TCP_WRITE: drain(tcp_peer); break;
    case CALL_INOTIFY: {
        char path[128];
        snprintf(path, sizeof path, "%s/created", scratch_dir);
        int fd = open(path, O_RDWR | O_CREAT, 0600);
        if (fd < 0) die("create release");
        close(fd);
        unlink(path);
        break;
    }
    default: break;
    }
}

#ifdef __APPLE__
static atomic_int spin = 0;

static void *spinner(void *arg)
{
    (void)arg;
    while (atomic_load(&spin)) { }
    return NULL;
}
#endif

#ifdef __linux__
static void pin_fifo(pthread_attr_t *attr, int priority)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    struct sched_param param = { .sched_priority = priority };
    if (pthread_attr_setaffinity_np(attr, sizeof cpus, &cpus) != 0) die("setaffinity");
    if (pthread_attr_setinheritsched(attr, PTHREAD_EXPLICIT_SCHED) != 0) die("setinheritsched");
    if (pthread_attr_setschedpolicy(attr, SCHED_FIFO) != 0) die("setschedpolicy");
    if (pthread_attr_setschedparam(attr, &param) != 0) die("setschedparam");
}

static void become_fifo_on_cpu0(int priority)
{
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    if (sched_setaffinity(0, sizeof cpus, &cpus) != 0) die("sched_setaffinity");
    struct sched_param param = { .sched_priority = priority };
    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) die("sched_setscheduler");
}

static char thread_state(int tid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    FILE *f = fopen(path, "r");
    if (!f) return '?';
    char buf[512];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *close = strrchr(buf, ')');
    return close && close[1] == ' ' ? close[2] : '?';
}
#endif

static void change_disposition(struct row *row)
{
    switch (row->change) {
    case CHANGE_NONE: break;
    case CHANGE_IGN: {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = SIG_IGN;
        if (sigaction(SIGUSR1, &sa, NULL) != 0) die("sigaction ign");
        break;
    }
    case CHANGE_DFL: {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = SIG_DFL;
        if (sigaction(SIGUSR1, &sa, NULL) != 0) die("sigaction dfl");
        break;
    }
    case CHANGE_SWAP: install(SIGUSR1, h2, !row->restart); break;
    }
}

static void run_row(struct row *row)
{
    // Unbuffered, so that a row whose signal kills the child keeps what it printed.
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(5);
    install(SIGUSR1, h1, row->restart);
    install(SIGUSR2, on_release, 0);
    set_up(row);

    pthread_t s;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
#ifdef __linux__
    if (row->held) pin_fifo(&attr, 10);
#else
    if (row->held) {
        pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
        pthread_attr_set_qos_class_np(&attr, QOS_CLASS_BACKGROUND, 0);
    }
#endif
    if (pthread_create(&s, &attr, sleeper, row) != 0) die("pthread_create");
    while (!atomic_load(&s_entered)) sleep_ms(1);
    sleep_ms(30);

    printf("%s call=%s restart=%d change=%s mode=%s", FLAVOUR, call_names[row->call], row->restart,
           change_names[row->change], row->held ? "held" : "free");

    if (row->held) {
#ifdef __linux__
        become_fifo_on_cpu0(20);
        pthread_kill(s, SIGUSR1);
        char state = thread_state(atomic_load(&s_tid));
        int returned_at_change = atomic_load(&s_returned);
        int h1_at_change = h1_runs;
        printf(" s-state=%c returned-at-change=%d h1-at-change=%d", state, returned_at_change, h1_at_change);
        change_disposition(row);
        // Sleeping lets S have CPU 0.
        sleep_ms(50);
#else
        atomic_store(&spin, 1);
        int spinner_count = 2 * (int)sysconf(_SC_NPROCESSORS_ONLN);
        pthread_t spinners[256];
        if (spinner_count > 256) spinner_count = 256;
        pthread_attr_t spinner_attr;
        pthread_attr_init(&spinner_attr);
        pthread_attr_set_qos_class_np(&spinner_attr, QOS_CLASS_USER_INTERACTIVE, 0);
        for (int i = 0; i < spinner_count; i++)
            if (pthread_create(&spinners[i], &spinner_attr, spinner, NULL) != 0) die("pthread_create spinner");
        sleep_ms(20);
        pthread_kill(s, SIGUSR1);
        int returned_at_change = atomic_load(&s_returned);
        int h1_at_change = h1_runs;
        printf(" s-state=- returned-at-change=%d h1-at-change=%d", returned_at_change, h1_at_change);
        change_disposition(row);
        atomic_store(&spin, 0);
        for (int i = 0; i < spinner_count; i++) pthread_join(spinners[i], NULL);
        // S runs in the background QoS class, which can wait a while for a
        // processor even once the spinners have stopped.
        sleep_ms(250);
#endif
    } else {
        pthread_kill(s, SIGUSR1);
        sleep_ms(50);
        int returned_at_change = atomic_load(&s_returned);
        int h1_at_change = h1_runs;
        printf(" s-state=- returned-at-change=%d h1-at-change=%d", returned_at_change, h1_at_change);
        change_disposition(row);
        sleep_ms(50);
    }

    int returned = atomic_load(&s_returned);
    printf(" returned-before-release=%d", returned);
    if (!returned) release(row, s);
    pthread_join(s, NULL);
    printf(" ret=%d errno=%s h1=%d h2=%d release-handler=%d", s_ret, s_ret < 0 ? strerror(s_errno) : "-",
           (int)h1_runs, (int)h2_runs, (int)release_runs);
#ifdef __linux__
    if (row->call == CALL_INOTIFY) rmdir(scratch_dir);
#endif
}

int main(void)
{
    struct utsname u;
    uname(&u);
    printf("# %s %s %s, uid %d\n", u.sysname, u.release, u.machine, (int)getuid());
    fflush(stdout);

    for (int held = 1; held >= 0; held--) {
        for (int call = CALL_PAUSE; call < CALL_COUNT; call++) {
#ifndef __linux__
            if (call == CALL_INOTIFY) continue;
#endif
            for (int restart = 0; restart <= 1; restart++) {
                for (int change = CHANGE_NONE; change <= CHANGE_SWAP; change++) {
                    struct row row = { (enum call)call, restart, (enum change)change, held };
                    fflush(stdout);
                    pid_t child = fork();
                    if (child < 0) die("fork");
                    if (child == 0) {
                        run_row(&row);
                        _exit(0);
                    }
                    int status;
                    if (waitpid(child, &status, 0) != child) die("waitpid");
                    if (WIFEXITED(status))
                        printf(" end=exit%d\n", WEXITSTATUS(status));
                    else if (WIFSIGNALED(status))
                        printf(" end=signal%d\n", WTERMSIG(status));
                    else
                        printf(" end=?\n");
                    fflush(stdout);
                }
            }
        }
    }
    return 0;
}
