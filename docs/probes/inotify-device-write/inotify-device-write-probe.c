// What Linux's inotify reports when a process writes to a character device:
// which watches hear the write's IN_MODIFY (the device's own, the directory's
// of the name it was opened through), for which writes (empty, faulting,
// positioned, gathered), and under IN_EXCL_UNLINK once that name is unlinked.
//
// Every line is `SECTION<TAB>case<TAB>result`, rendered as in
// docs/probes/inotify-close/inotify-close-probe.c: an event is
// `wd=N mask=NAMES cookie=C len=L name="..."`, and `|` separates the events of
// one drain. Every watch asks for every event but IN_OPEN and IN_ACCESS
// (`deviceEvents`), so that opening a device raises nothing, and a watch with
// IN_EXCL_UNLINK asks for the same and that flag. A write's result is its
// return value, or `errnoN`.
//
// Sections:
//   D  /dev/null, /dev/zero and /dev/urandom, each opened O_WRONLY with /dev
//      and the device watched: one write, an empty write, two writes in a row,
//      a write from (void*)-1 and from an unmapped user address, pwrite,
//      writev, and the close
//   N  outside /dev: a character device node mknod'd as 1,3 (/dev/null's
//      number), a FIFO, and a regular file, each written once with its
//      directory and itself watched; the regular file is the control that the
//      directory's watch hears a write
//   E  IN_EXCL_UNLINK: /dev/null written through a second name, a hard link in
//      /dev, before and after that name is unlinked, under one instance whose
//      watches on /dev and /dev/null are plain and one whose are
//      IN_EXCL_UNLINK; /dev/null and /dev/urandom each written through its
//      own name, unlinked (and made again after), with how many descriptors
//      of other processes hold each; and the same as the first for a node
//      mknod'd outside /dev, watched at its directory and itself
//
// Build and run, from this directory, as root:
//   container run --rm -v "$PWD":/probe debian:trixie sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -O1 -o /tmp/probe-bin /probe/inotify-device-write-probe.c && mkdir -p /tmp/run && chmod 0777 /tmp/run && cd /tmp/run && /tmp/probe-bin'
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
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

// Read a non-blocking descriptor until EAGAIN: the rendered events, in one of
// four rotating buffers so that two drains can share a line.
static const char *drain(int fd)
{
    static char rendered[4][1 << 14];
    static int k = 0;
    k = (k + 1) % 4;
    char *out = rendered[k];
    char buf[1 << 14];
    out[0] = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno != EAGAIN) { char line[64]; snprintf(line, sizeof line, "%sREAD errno%d", out[0] ? " | " : "", errno); strcat(out, line); }
            break;
        }
        ssize_t pos = 0;
        while (pos + (ssize_t)sizeof(struct inotify_event) <= n) {
            const struct inotify_event *e = (const struct inotify_event *)(buf + pos);
            char line[512];
            if (e->cookie != 0) { fprintf(stderr, "unexpected cookie\n"); exit(1); }
            snprintf(line, sizeof line, "%swd=%d mask=%s cookie=0 len=%u name=\"%s\"",
                     out[0] ? " | " : "", e->wd, maskNames(e->mask), e->len, e->len ? e->name : "");
            strcat(out, line);
            pos += sizeof(struct inotify_event) + e->len;
        }
    }
    if (!out[0]) strcpy(out, "(none)");
    return out;
}

// A write's result, as the process sees it.
static const char *rc(ssize_t r)
{
    static char b[4][32];
    static int k = 0;
    k = (k + 1) % 4;
    if (r < 0) snprintf(b[k], sizeof b[k], "errno%d", errno);
    else snprintf(b[k], sizeof b[k], "%zd", r);
    return b[k];
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

static const uint32_t deviceEvents = IN_ALL_EVENTS & ~(IN_OPEN | IN_ACCESS);

// The inode and the device number a path names: printed beside a row whose
// meaning depends on which inode it reached.
static const char *identity(const char *path)
{
    static char b[4][96];
    static int k = 0;
    k = (k + 1) % 4;
    struct stat st;
    check(path, stat(path, &st));
    snprintf(b[k], sizeof b[k], "ino=%lu rdev=%u,%u nlink=%lu", (unsigned long)st.st_ino,
             major(st.st_rdev), minor(st.st_rdev), (unsigned long)st.st_nlink);
    return b[k];
}

static void deviceRows(const char *name)
{
    char path[64];
    snprintf(path, sizeof path, "/dev/%s", name);
    char row[64];
    int fd = inotify_init1(IN_NONBLOCK);
    check("inotify_init1", fd);
    int wdev = inotify_add_watch(fd, "/dev", deviceEvents);
    check("watch /dev", wdev);
    int wown = inotify_add_watch(fd, path, deviceEvents);
    check("watch device", wown);
    int n = open(path, O_WRONLY);
    check("open device", n);
    const char *opened = drain(fd);

    ssize_t r = write(n, "x", 1);
    snprintf(row, sizeof row, "%s-write", name);
    line("D", row, "%s dev=%d own=%d opened: %s; write=%s: %s", identity(path), wdev, wown, opened, rc(r), drain(fd));

    r = write(n, "x", 0);
    snprintf(row, sizeof row, "%s-empty", name);
    line("D", row, "write=%s: %s", rc(r), drain(fd));

    ssize_t r1 = write(n, "x", 1);
    ssize_t r2 = write(n, "yz", 2);
    snprintf(row, sizeof row, "%s-twice", name);
    line("D", row, "write=%s write=%s: %s", rc(r1), rc(r2), drain(fd));

    r = write(n, (const void *)-1, 1);
    snprintf(row, sizeof row, "%s-fault", name);
    line("D", row, "write=%s: %s", rc(r), drain(fd));

    // A user address with nothing mapped at it, which passes the screen ahead
    // of the driver that (void*)-1 fails.
    void *gone = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check("mmap", gone == MAP_FAILED ? -1 : 0);
    check("munmap", munmap(gone, 4096));
    r = write(n, gone, 1);
    snprintf(row, sizeof row, "%s-unmapped", name);
    line("D", row, "write=%s: %s", rc(r), drain(fd));

    r = pwrite(n, "x", 1, 5);
    snprintf(row, sizeof row, "%s-pwrite", name);
    line("D", row, "pwrite=%s: %s", rc(r), drain(fd));

    struct iovec iov[2] = { { "ab", 2 }, { "c", 1 } };
    r = writev(n, iov, 2);
    snprintf(row, sizeof row, "%s-writev", name);
    line("D", row, "writev=%s: %s", rc(r), drain(fd));

    check("close", close(n));
    snprintf(row, sizeof row, "%s-close", name);
    line("D", row, "%s", drain(fd));
    close(fd);
}

static void sectionD(void)
{
    deviceRows("null");
    deviceRows("zero");
    deviceRows("urandom");
}

static void sectionN(void)
{
    fresh("n");
    check("mknod n/c", mknod("n/c", S_IFCHR | 0666, makedev(1, 3)));
    check("mkfifo n/p", mkfifo("n/p", 0666));
    int f = open("n/f", O_WRONLY | O_CREAT | O_EXCL, 0666);
    check("create n/f", f);
    check("close", close(f));

    int fd = inotify_init1(IN_NONBLOCK);
    check("inotify_init1", fd);
    int wn = inotify_add_watch(fd, "n", deviceEvents);
    int wc = inotify_add_watch(fd, "n/c", deviceEvents);
    int wp = inotify_add_watch(fd, "n/p", deviceEvents);
    int wf = inotify_add_watch(fd, "n/f", deviceEvents);
    check("watch", wn < 0 || wc < 0 || wp < 0 || wf < 0 ? -1 : 0);

    int c = open("n/c", O_WRONLY);
    check("open n/c", c);
    const char *opened = drain(fd);
    ssize_t r = write(c, "x", 1);
    line("N", "node", "%s n=%d c=%d opened: %s; write=%s: %s", identity("n/c"), wn, wc, opened, rc(r), drain(fd));
    check("close", close(c));
    line("N", "node-close", "%s", drain(fd));

    int p = open("n/p", O_RDWR | O_NONBLOCK);
    check("open n/p", p);
    opened = drain(fd);
    r = write(p, "x", 1);
    line("N", "fifo", "p=%d opened: %s; write=%s: %s", wp, opened, rc(r), drain(fd));
    check("close", close(p));
    line("N", "fifo-close", "%s", drain(fd));

    f = open("n/f", O_WRONLY);
    check("open n/f", f);
    opened = drain(fd);
    r = write(f, "x", 1);
    line("N", "file", "f=%d opened: %s; write=%s: %s", wf, opened, rc(r), drain(fd));
    check("close", close(f));
    line("N", "file-close", "%s", drain(fd));
    close(fd);
}

// Writes through `second`, a second name of `first`'s inode in `directory`,
// before and after `second` is unlinked, under a plain instance and an
// IN_EXCL_UNLINK one, each watching `directory` and `first`.
static void exclUnlinkRows(const char *prefix, const char *directory, const char *first, const char *second)
{
    char row[64];
    int plain = inotify_init1(IN_NONBLOCK);
    int excl = inotify_init1(IN_NONBLOCK);
    check("inotify_init1", plain < 0 || excl < 0 ? -1 : 0);
    int pd = inotify_add_watch(plain, directory, deviceEvents);
    int po = inotify_add_watch(plain, first, deviceEvents);
    int ed = inotify_add_watch(excl, directory, deviceEvents | IN_EXCL_UNLINK);
    int eo = inotify_add_watch(excl, first, deviceEvents | IN_EXCL_UNLINK);
    check("watch", pd < 0 || po < 0 || ed < 0 || eo < 0 ? -1 : 0);

    int n = open(second, O_WRONLY);
    check("open second name", n);
    const char *plainOpened = drain(plain);
    const char *exclOpened = drain(excl);
    snprintf(row, sizeof row, "%s-fixture", prefix);
    line("E", row, "%s: %s; %s: %s; plain dir=%d own=%d; excl dir=%d own=%d; opened: plain: %s; excl: %s",
         first, identity(first), second, identity(second), pd, po, ed, eo, plainOpened, exclOpened);

    ssize_t r = write(n, "x", 1);
    snprintf(row, sizeof row, "%s-linked", prefix);
    line("E", row, "write=%s: plain: %s; excl: %s", rc(r), drain(plain), drain(excl));

    check("unlink second name", unlink(second));
    snprintf(row, sizeof row, "%s-unlink", prefix);
    line("E", row, "plain: %s; excl: %s", drain(plain), drain(excl));

    r = write(n, "x", 1);
    snprintf(row, sizeof row, "%s-unlinked", prefix);
    line("E", row, "write=%s: plain: %s; excl: %s", rc(r), drain(plain), drain(excl));

    check("close", close(n));
    snprintf(row, sizeof row, "%s-close", prefix);
    line("E", row, "plain: %s; excl: %s", drain(plain), drain(excl));
    close(plain);
    close(excl);
}

// How many descriptors of processes other than this one name `path`, read
// from /proc without starting a process that would hold some of its own.
static int otherHolders(const char *path)
{
    DIR *proc = opendir("/proc");
    if (!proc) { perror("opendir /proc"); exit(1); }
    int count = 0;
    struct dirent *p;
    while ((p = readdir(proc))) {
        char *end;
        long pid = strtol(p->d_name, &end, 10);
        if (*end || pid <= 0 || pid == getpid()) continue;
        char fdDir[64];
        snprintf(fdDir, sizeof fdDir, "/proc/%ld/fd", pid);
        DIR *fds = opendir(fdDir);
        if (!fds) continue;
        struct dirent *f;
        while ((f = readdir(fds))) {
            if (f->d_name[0] == '.') continue;
            char link[384], target[4096];
            snprintf(link, sizeof link, "%s/%s", fdDir, f->d_name);
            ssize_t n = readlink(link, target, sizeof target - 1);
            if (n < 0) continue;
            target[n] = 0;
            if (strcmp(target, path) == 0) count++;
        }
        closedir(fds);
    }
    closedir(proc);
    return count;
}

static void sectionE(void)
{
    unlink("/dev/probe-null");
    check("link /dev/null", link("/dev/null", "/dev/probe-null"));
    exclUnlinkRows("dev-null", "/dev", "/dev/null", "/dev/probe-null");

    // The name the watch was added through, unlinked under its own
    // description; then the node made again, for whatever runs after. For
    // each, how many descriptors of other processes are open on it, which
    // hold the unlinked name past this one's close.
    line("E", "holders", "null=%d urandom=%d", otherHolders("/dev/null"), otherHolders("/dev/urandom"));
    exclUnlinkRows("dev-null-self", "/dev", "/dev/null", "/dev/null");
    check("mknod /dev/null", mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)));
    exclUnlinkRows("urandom-self", "/dev", "/dev/urandom", "/dev/urandom");
    check("mknod /dev/urandom", mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)));

    fresh("e");
    check("mknod e/c", mknod("e/c", S_IFCHR | 0666, makedev(1, 3)));
    check("link e/c", link("e/c", "e/d"));
    exclUnlinkRows("node", "e", "e/c", "e/d");
}

int main(void)
{
    FILE *u = popen("uname -rm", "r");
    char release[128] = "";
    if (u && fgets(release, sizeof release, u)) fputs(release, stdout);
    if (u) pclose(u);
    sectionD();
    sectionN();
    sectionE();
    return 0;
}
