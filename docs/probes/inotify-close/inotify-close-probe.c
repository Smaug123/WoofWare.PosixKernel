// What Linux's inotify reports when an open file description is released:
// IN_CLOSE_WRITE when the description was opened for writing, whether or not
// anything was written, IN_CLOSE_NOWRITE otherwise, and when each is raised.
//
// Every line is `SECTION<TAB>case<TAB>result`, rendered as in
// docs/plans/2026-10-11-inotify/inotify-probe.c: an event is
// `wd=N mask=NAMES cookie=C len=L name="..."`, cookies numbered in the order
// first seen, and `|` separating the events of one drain. Every watch asks for
// every event but IN_OPEN and IN_ACCESS (`closeEvents`), so that opening and
// reading raise nothing and identical records can merge as they would under a
// watch this kernel takes.
//
// Sections:
//   A  the access mode: O_RDONLY, O_WRONLY never written, O_RDWR only read,
//      O_RDONLY|O_TRUNC of a non-empty file, O_WRONLY|O_TRUNC, O_PATH; at the
//      parent's watch and the file's own
//   K  kinds: a directory, the watched directory itself, a FIFO opened O_RDWR,
//      /dev/null opened for writing
//   M  a watch's mask: one asking for IN_CLOSE_WRITE alone, IN_CLOSE_NOWRITE
//      alone
//   R  references: two closes merging under one watch, a dup, a description a
//      child inherited by fork, the descriptors a process held at its exit
//   U  names: the file renamed, moved, unlinked (with and without
//      IN_EXCL_UNLINK at the parent's watch and at its own), and a removed
//      directory opened by name before and by "." after
//   L  a close while another thread's flock, parked, holds the description
//   X  a process's end while a thread of it is parked in flock on a
//      description no descriptor names: which goes first, that description
//      or one the process held at a descriptor (200 runs)
//
// Build and run, from this directory, as root:
//   container run --rm -v "$PWD":/probe debian:trixie sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -O1 -pthread -o /tmp/probe-bin /probe/inotify-close-probe.c && mkdir -p /tmp/run && chmod 0777 /tmp/run && cd /tmp/run && /tmp/probe-bin'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(const char *what, long result)
{
    if (result < 0) { perror(what); exit(1); }
}

static const char *maskNames(uint32_t mask)
{
    static char b[4][256];
    static int k = 0;
    k = (k + 1) % 4;
    char *out = b[k];
    out[0] = 0;
    struct { uint32_t bit; const char *name; } bits[] = {
        { IN_ACCESS, "ACCESS" }, { IN_MODIFY, "MODIFY" }, { IN_ATTRIB, "ATTRIB" },
        { IN_CLOSE_WRITE, "CLOSE_WRITE" }, { IN_CLOSE_NOWRITE, "CLOSE_NOWRITE" },
        { IN_OPEN, "OPEN" }, { IN_MOVED_FROM, "MOVED_FROM" }, { IN_MOVED_TO, "MOVED_TO" },
        { IN_CREATE, "CREATE" }, { IN_DELETE, "DELETE" }, { IN_DELETE_SELF, "DELETE_SELF" },
        { IN_MOVE_SELF, "MOVE_SELF" }, { IN_UNMOUNT, "UNMOUNT" }, { IN_Q_OVERFLOW, "Q_OVERFLOW" },
        { IN_IGNORED, "IGNORED" }, { IN_ISDIR, "ISDIR" },
    };
    uint32_t seen = 0;
    for (size_t i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        if (mask & bits[i].bit) {
            if (out[0]) strcat(out, "+");
            strcat(out, bits[i].name);
            seen |= bits[i].bit;
        }
    }
    if (mask & ~seen) { char extra[32]; snprintf(extra, sizeof extra, "%s0x%x", out[0] ? "+" : "", mask & ~seen); strcat(out, extra); }
    if (!out[0]) strcpy(out, "0");
    return out;
}

static uint32_t cookies[64];
static int cookieCount = 0;
static const char *cookieName(uint32_t cookie)
{
    static char b[4][16];
    static int k = 0;
    k = (k + 1) % 4;
    if (cookie == 0) return "0";
    for (int i = 0; i < cookieCount; i++) if (cookies[i] == cookie) { snprintf(b[k], sizeof b[k], "k%d", i + 1); return b[k]; }
    cookies[cookieCount++] = cookie;
    snprintf(b[k], sizeof b[k], "k%d", cookieCount);
    return b[k];
}

static char rendered[1 << 16];

// Read a non-blocking descriptor until EAGAIN: the rendered events.
static const char *drain(int fd)
{
    static char buf[1 << 16];
    rendered[0] = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno != EAGAIN) { char line[64]; snprintf(line, sizeof line, "%sREAD errno%d", rendered[0] ? " | " : "", errno); strcat(rendered, line); }
            break;
        }
        ssize_t pos = 0;
        while (pos + (ssize_t)sizeof(struct inotify_event) <= n) {
            const struct inotify_event *e = (const struct inotify_event *)(buf + pos);
            char line[512];
            snprintf(line, sizeof line, "%swd=%d mask=%s cookie=%s len=%u name=\"%s\"",
                     rendered[0] ? " | " : "", e->wd, maskNames(e->mask), cookieName(e->cookie), e->len, e->len ? e->name : "");
            strcat(rendered, line);
            pos += sizeof(struct inotify_event) + e->len;
        }
    }
    if (!rendered[0]) strcpy(rendered, "(none)");
    return rendered;
}

static void line(const char *section, const char *name, const char *fmt, ...)
{
    printf("%s\t%s\t", section, name);
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

static void fresh(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof cmd, "rm -rf %s && mkdir -p %s && chmod 0777 %s", dir, dir, dir);
    if (system(cmd) != 0) exit(1);
}

static const uint32_t closeEvents = IN_ALL_EVENTS & ~(IN_OPEN | IN_ACCESS);

static char home[4096];

static void goHome(void)
{
    check("chdir home", chdir(home));
}

static void writeFile(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    check(path, fd);
    check("write", write(fd, text, strlen(text)));
    check("close", close(fd));
}

static off_t sizeOf(const char *path)
{
    struct stat st;
    check(path, stat(path, &st));
    return st.st_size;
}

// "a/f", holding "abc", watched with its parent "a"; the instance, drained.
static int watchedFile(int *wa, int *wf)
{
    fresh("a");
    writeFile("a/f", "abc");
    int fd = inotify_init1(IN_NONBLOCK);
    check("inotify_init1", fd);
    *wa = inotify_add_watch(fd, "a", closeEvents);
    *wf = inotify_add_watch(fd, "a/f", closeEvents);
    check("add a", *wa);
    check("add a/f", *wf);
    drain(fd);
    return fd;
}

// Open "a/f" with `flags`, do `act` to it, close it: one row, the opening's
// and acting's records first, then the closing's.
static void accessRow(const char *name, int flags, int act)
{
    int wa, wf;
    int fd = watchedFile(&wa, &wf);
    int f = open("a/f", flags);
    if (f < 0) { line("A", name, "open=-1 errno=%d", errno); close(fd); return; }
    char buf[8];
    long r = 0;
    if (act == 'r') r = read(f, buf, sizeof buf);
    if (act == 'w') r = write(f, "x", 1);
    char opened[1 << 12];
    snprintf(opened, sizeof opened, "%s", drain(fd));
    check("close", close(f));
    line("A", name, "a=%d f=%d act=%ld size=%ld; opened: %s; closed: %s", wa, wf, r, (long)sizeOf("a/f"), opened, drain(fd));
    close(fd);
}

static void sectionA(void)
{
    accessRow("rdonly", O_RDONLY, 0);
    accessRow("rdonly-read", O_RDONLY, 'r');
    accessRow("wronly-unwritten", O_WRONLY, 0);
    accessRow("wronly-written", O_WRONLY, 'w');
    accessRow("rdwr-unused", O_RDWR, 0);
    accessRow("rdwr-read", O_RDWR, 'r');
    accessRow("rdonly-trunc", O_RDONLY | O_TRUNC, 0);
    accessRow("wronly-trunc", O_WRONLY | O_TRUNC, 0);
    accessRow("rdonly-append", O_RDONLY | O_APPEND, 0);
    accessRow("path", O_PATH, 0);
}

static void sectionK(void)
{
    // A directory in a watched one, watched itself too.
    fresh("k");
    check("mkdir", mkdir("k/d", 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    int wk = inotify_add_watch(fd, "k", closeEvents);
    int wd = inotify_add_watch(fd, "k/d", closeEvents);
    int d = open("k/d", O_RDONLY | O_DIRECTORY);
    check("open k/d", d);
    check("close", close(d));
    line("K", "directory", "k=%d d=%d: %s", wk, wd, drain(fd));

    // The watched directory itself, whose parent is not watched.
    d = open("k", O_RDONLY | O_DIRECTORY);
    check("open k", d);
    check("close", close(d));
    line("K", "watched-directory", "%s", drain(fd));

    // Through "." from inside it.
    check("chdir", chdir("k/d"));
    d = open(".", O_RDONLY | O_DIRECTORY);
    check("open .", d);
    check("close", close(d));
    line("K", "directory-by-dot", "%s", drain(fd));
    goHome();

    // A FIFO, opened read-write so the open does not wait.
    check("mkfifo", mkfifo("k/p", 0644));
    drain(fd);
    int wp = inotify_add_watch(fd, "k/p", closeEvents);
    int p = open("k/p", O_RDWR);
    check("open k/p", p);
    check("close", close(p));
    line("K", "fifo-rdwr", "p=%d: %s", wp, drain(fd));
    p = open("k/p", O_RDONLY | O_NONBLOCK);
    check("open k/p", p);
    check("close", close(p));
    line("K", "fifo-rdonly", "%s", drain(fd));
    close(fd);

    // /dev/null, for writing, with /dev and it watched.
    fd = inotify_init1(IN_NONBLOCK);
    int wdev = inotify_add_watch(fd, "/dev", closeEvents);
    int wnull = inotify_add_watch(fd, "/dev/null", closeEvents);
    int n = open("/dev/null", O_WRONLY);
    check("open /dev/null", n);
    check("write", write(n, "x", 1));
    char written[1 << 12];
    snprintf(written, sizeof written, "%s", drain(fd));
    check("close", close(n));
    line("K", "dev-null", "dev=%d null=%d; written: %s; closed: %s", wdev, wnull, written, drain(fd));
    n = open("/dev/null", O_RDONLY);
    check("open /dev/null", n);
    check("close", close(n));
    line("K", "dev-null-rdonly", "%s", drain(fd));
    n = open("/dev/null", O_WRONLY);
    check("open /dev/null", n);
    check("write", write(n, "x", 1));
    check("write", write(n, "y", 1));
    snprintf(written, sizeof written, "%s", drain(fd));
    check("close", close(n));
    line("K", "dev-null-again", "written: %s; closed: %s", written, drain(fd));
    check("chmod /dev/null", chmod("/dev/null", 0666));
    line("K", "dev-null-chmod", "%s", drain(fd));
    close(fd);
}

static void sectionM(void)
{
    fresh("m");
    writeFile("m/f", "abc");
    int fd = inotify_init1(IN_NONBLOCK);
    int w = inotify_add_watch(fd, "m", IN_CLOSE_WRITE);
    int f = open("m/f", O_RDONLY);
    check("close", close(f));
    f = open("m/f", O_WRONLY);
    check("close", close(f));
    line("M", "close-write-only", "m=%d: %s", w, drain(fd));
    inotify_add_watch(fd, "m", IN_CLOSE_NOWRITE);
    f = open("m/f", O_RDONLY);
    check("close", close(f));
    f = open("m/f", O_WRONLY);
    check("close", close(f));
    line("M", "close-nowrite-only", "%s", drain(fd));
    inotify_add_watch(fd, "m", IN_CLOSE);
    f = open("m/f", O_WRONLY);
    check("close", close(f));
    f = open("m/f", O_RDONLY);
    check("close", close(f));
    line("M", "close-both", "%s", drain(fd));
    close(fd);
}

static void sectionR(void)
{
    // Under the parent's watch alone, two closes of the same kind in a row.
    fresh("r");
    writeFile("r/f", "abc");
    writeFile("r/g", "abc");
    int fd = inotify_init1(IN_NONBLOCK);
    int w = inotify_add_watch(fd, "r", closeEvents);
    for (int i = 0; i < 2; i++) { int f = open("r/f", O_RDONLY); check("close", close(f)); }
    line("R", "two-nowrite-merge", "r=%d: %s", w, drain(fd));
    for (int i = 0; i < 2; i++) { int f = open("r/f", O_WRONLY); check("close", close(f)); }
    line("R", "two-write-merge", "%s", drain(fd));
    { int f = open("r/f", O_RDONLY); check("close", close(f)); f = open("r/f", O_WRONLY); check("close", close(f)); f = open("r/f", O_RDONLY); check("close", close(f)); }
    line("R", "alternating", "%s", drain(fd));
    { int f = open("r/f", O_RDONLY); check("close", close(f)); f = open("r/g", O_RDONLY); check("close", close(f)); f = open("r/f", O_RDONLY); check("close", close(f)); }
    line("R", "two-files", "%s", drain(fd));
    // Two descriptions open at once, closed in turn.
    { int f1 = open("r/f", O_RDONLY); int f2 = open("r/f", O_RDONLY); check("close", close(f1)); line("R", "two-descriptions-first", "%s", drain(fd)); check("close", close(f2)); line("R", "two-descriptions-second", "%s", drain(fd)); }

    // A dup: the close of either name alone releases nothing.
    int f = open("r/f", O_WRONLY);
    int g = dup(f);
    check("close", close(f));
    line("R", "dup-first", "%s", drain(fd));
    check("close", close(g));
    line("R", "dup-second", "%s", drain(fd));

    // Inherited by fork: the child's exit releases nothing, the parent's close
    // the description.
    f = open("r/f", O_WRONLY);
    pid_t child = fork();
    if (child == 0) _exit(0);
    int status;
    waitpid(child, &status, 0);
    line("R", "fork-child-exit", "%s", drain(fd));
    check("close", close(f));
    line("R", "fork-parent-close", "%s", drain(fd));

    // A child holding f for writing at descriptor 4 and g for reading at
    // descriptor 3 (and f again, read-only, at 5) when it exits.
    child = fork();
    if (child == 0) {
        for (int i = 3; i < 64; i++) if (i != fd) close(i);
        int a = open("r/g", O_RDONLY);
        int b = open("r/f", O_WRONLY);
        int c = open("r/f", O_RDONLY);
        dprintf(1, "R\texit-descriptors\tg=%d f=%d f-again=%d inotify=%d\n", a, b, c, fd);
        _exit(0);
    }
    waitpid(child, &status, 0);
    line("R", "exit", "%s", drain(fd));

    // Which order, at an exit, the descriptions go in: by descriptor, by
    // opening, or by which descriptor held a description's last reference.
    // g at 4, then f at 5; 4 closed and h opened into it.
    fresh("o");
    writeFile("o/f", "abc");
    writeFile("o/g", "abc");
    writeFile("o/h", "abc");
    int wo = inotify_add_watch(fd, "o", closeEvents);
    child = fork();
    if (child == 0) {
        for (int i = 3; i < 64; i++) if (i != fd) close(i);
        int a = open("o/g", O_RDONLY);
        int b = open("o/f", O_RDONLY);
        close(a);
        int c = open("o/h", O_RDONLY);
        dprintf(1, "R\texit-reused-slot-descriptors\tf=%d h=%d inotify=%d\n", b, c, fd);
        _exit(0);
    }
    waitpid(child, &status, 0);
    line("R", "exit-reused-slot", "o=%d: %s", wo, drain(fd));

    // g at 4, f at 5, and g again by dup at 6: g's last reference is at 6.
    child = fork();
    if (child == 0) {
        for (int i = 3; i < 64; i++) if (i != fd) close(i);
        int a = open("o/g", O_RDONLY);
        int b = open("o/f", O_RDONLY);
        int c = dup(a);
        dprintf(1, "R\texit-dup-last-descriptors\tg=%d f=%d g-dup=%d inotify=%d\n", a, b, c, fd);
        _exit(0);
    }
    waitpid(child, &status, 0);
    line("R", "exit-dup-last", "%s", drain(fd));

    // Four, at 4..7, opened g, f, h, g.
    child = fork();
    if (child == 0) {
        for (int i = 3; i < 64; i++) if (i != fd) close(i);
        open("o/g", O_RDONLY);
        open("o/f", O_WRONLY);
        open("o/h", O_RDONLY);
        open("o/g", O_WRONLY);
        _exit(0);
    }
    waitpid(child, &status, 0);
    line("R", "exit-four", "%s", drain(fd));
    close(fd);
}

static void sectionU(void)
{
    int wa, wf;

    // Renamed within its parent while open.
    int fd = watchedFile(&wa, &wf);
    int f = open("a/f", O_WRONLY);
    check("rename", rename("a/f", "a/g"));
    drain(fd);
    check("close", close(f));
    line("U", "renamed", "a=%d f=%d: %s", wa, wf, drain(fd));
    close(fd);

    // Moved to another, watched, directory while open.
    fd = watchedFile(&wa, &wf);
    fresh("b");
    int wb = inotify_add_watch(fd, "b", closeEvents);
    f = open("a/f", O_RDONLY);
    check("rename", rename("a/f", "b/h"));
    drain(fd);
    check("close", close(f));
    line("U", "moved", "b=%d: %s", wb, drain(fd));
    close(fd);

    // Unlinked while open, no IN_EXCL_UNLINK.
    fd = watchedFile(&wa, &wf);
    f = open("a/f", O_WRONLY);
    check("unlink", unlink("a/f"));
    line("U", "unlinked-unlink", "%s", drain(fd));
    check("close", close(f));
    line("U", "unlinked-close", "%s", drain(fd));
    close(fd);

    // Unlinked while open, IN_EXCL_UNLINK at the parent's watch.
    fd = watchedFile(&wa, &wf);
    inotify_add_watch(fd, "a", closeEvents | IN_EXCL_UNLINK);
    f = open("a/f", O_WRONLY);
    check("unlink", unlink("a/f"));
    drain(fd);
    check("close", close(f));
    line("U", "excl-unlink-parent", "%s", drain(fd));
    close(fd);

    // Unlinked while open, IN_EXCL_UNLINK at its own watch.
    fd = watchedFile(&wa, &wf);
    inotify_add_watch(fd, "a/f", closeEvents | IN_EXCL_UNLINK);
    f = open("a/f", O_WRONLY);
    check("unlink", unlink("a/f"));
    drain(fd);
    check("close", close(f));
    line("U", "excl-unlink-own", "%s", drain(fd));
    close(fd);

    // Unlinked from one of two names while open through it.
    fd = watchedFile(&wa, &wf);
    check("link", link("a/f", "a/f2"));
    f = open("a/f", O_RDONLY);
    check("unlink", unlink("a/f"));
    drain(fd);
    check("close", close(f));
    line("U", "one-of-two-names-unlinked", "%s", drain(fd));
    close(fd);

    // A removed directory, opened by name before and by "." after, closed
    // by "." first; and with IN_EXCL_UNLINK at both watches.
    for (int excl = 0; excl < 2; excl++) {
        fresh("u");
        check("mkdir", mkdir("u/d", 0755));
        fd = inotify_init1(IN_NONBLOCK);
        int wu = inotify_add_watch(fd, "u", closeEvents | (excl ? IN_EXCL_UNLINK : 0));
        int wd = inotify_add_watch(fd, "u/d", closeEvents | (excl ? IN_EXCL_UNLINK : 0));
        int byName = open("u/d", O_RDONLY | O_DIRECTORY);
        check("open u/d", byName);
        check("chdir", chdir("u/d"));
        check("rmdir", rmdir("../d"));
        drain(fd);
        int byDot = open(".", O_RDONLY | O_DIRECTORY);
        check("open .", byDot);
        check("close", close(byDot));
        line("U", excl ? "removed-directory-by-dot-excl" : "removed-directory-by-dot", "u=%d d=%d: %s", wu, wd, drain(fd));
        goHome();
        check("close", close(byName));
        line("U", excl ? "removed-directory-by-name-excl" : "removed-directory-by-name", "%s", drain(fd));
        close(fd);
    }
}

static int lockFd;
static volatile int lockReturned = -2;

static void *lockThread(void *unused)
{
    (void)unused;
    lockReturned = flock(lockFd, LOCK_EX);
    return NULL;
}

static void sleepMs(int ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&t, NULL);
}

static void sectionL(void)
{
    fresh("l");
    writeFile("l/f", "abc");
    int fd = inotify_init1(IN_NONBLOCK);
    int w = inotify_add_watch(fd, "l", closeEvents);
    int holder = open("l/f", O_RDONLY);
    check("flock holder", flock(holder, LOCK_EX));
    lockFd = open("l/f", O_WRONLY);
    pthread_t t;
    pthread_create(&t, NULL, lockThread, NULL);
    sleepMs(150);
    int r = close(lockFd);
    sleepMs(50);
    line("L", "close-under-flock", "l=%d close=%d flock returned=%d: %s", w, r, lockReturned, drain(fd));
    check("unlock", flock(holder, LOCK_UN));
    pthread_join(t, NULL);
    line("L", "flock-returns", "flock=%d: %s", lockReturned, drain(fd));
    check("close", close(holder));
    line("L", "holder-close", "%s", drain(fd));
    close(fd);
}

// A child whose second thread is parked in flock on x, whose descriptor
// the first thread closed, and which holds y at a descriptor, ends by
// _exit: which of the two descriptions goes first.
static void *exitLockThread(void *unused)
{
    (void)unused;
    flock(lockFd, LOCK_EX);
    return NULL;
}

static void sectionX(void)
{
    fresh("x");
    writeFile("x/x", "abc");
    writeFile("x/y", "abc");
    int fd = inotify_init1(IN_NONBLOCK);
    int w = inotify_add_watch(fd, "x", closeEvents);
    int holder = open("x/x", O_RDONLY);
    check("flock holder", flock(holder, LOCK_EX));
    int xFirst = 0, yFirst = 0, other = 0;
    char sample[1 << 12] = "";
    for (int i = 0; i < 200; i++) {
        pid_t child = fork();
        if (child == 0) {
            lockFd = open("x/x", O_WRONLY);
            int y = open("x/y", O_RDONLY);
            (void)y;
            pthread_t t;
            pthread_create(&t, NULL, exitLockThread, NULL);
            sleepMs(20);
            close(lockFd);
            _exit(0);
        }
        int status;
        waitpid(child, &status, 0);
        const char *r = drain(fd);
        if (i == 0) snprintf(sample, sizeof sample, "%s", r);
        const char *px = strstr(r, "name=\"x\""), *py = strstr(r, "name=\"y\"");
        if (px && py && px < py) xFirst++;
        else if (px && py) yFirst++;
        else other++;
    }
    line("X", "exit-parked-flock", "x=%d; x first=%d y first=%d other=%d; first run: %s", w, xFirst, yFirst, other, sample);
    close(holder);
    close(fd);
}

int main(void)
{
    FILE *u = popen("uname -rm", "r");
    char release[128] = "";
    if (u && fgets(release, sizeof release, u)) fputs(release, stdout);
    if (u) pclose(u);
    if (!getcwd(home, sizeof home)) exit(1);
    sectionA();
    sectionK();
    sectionM();
    sectionR();
    sectionU();
    sectionL();
    sectionX();
    return 0;
}
