// Which name Linux's inotify reports a change to a removed directory under,
// when the change reached it by "." or "..", or through a descriptor opened
// that way, after its last name had gone: the name it had when that name went,
// in the directory it was named in then, whatever happened to it before.
//
// Every line is `SECTION<TAB>case<TAB>result`, rendered as in
// docs/plans/2026-10-11-inotify/inotify-probe.c: an event is
// `wd=N mask=NAMES cookie=C len=L name="..."`, cookies numbered in the order
// first seen, and `|` separating the events of one drain. Every watch asks for
// every event but those opening, reading and closing raise, so that opening
// "." raises nothing.
//
// Sections:
//   N  the name: a directory removed as it was named at first, renamed within
//      its parent first, moved to another parent first, or displaced by a
//      rename over it, each the current directory, then changed by `chmod(".")`
//   U  the old parent removed too: a change to the child by "." and to the
//      parent by ".." from the child
//   E  IN_EXCL_UNLINK on the old parent's watch
//   F  descriptors: one opened by name before the removal and one by "."
//      after, `fchmod`ed in turn; one opened by `openat(dirfd, ".")` after;
//      and `utimensat` of "."
//
// Build and run, from this directory, as root:
//   container run --rm -v "$PWD":/probe debian:trixie sh -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc libc6-dev >/dev/null 2>&1 && gcc -Wall -O1 -o /tmp/probe-bin /probe/inotify-removed-directory-probe.c && mkdir -p /tmp/run && chmod 0777 /tmp/run && cd /tmp/run && /tmp/probe-bin'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
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

static const uint32_t graphEvents = IN_ALL_EVENTS & ~(IN_OPEN | IN_CLOSE | IN_ACCESS);

static char home[4096];

static void goHome(void)
{
    check("chdir home", chdir(home));
}

// The mode of ".", in octal, so a row shows the chmod reached the directory.
static unsigned modeOfDot(void)
{
    struct stat st;
    check("stat .", stat(".", &st));
    return st.st_mode & 07777;
}

static void sectionN(void)
{
    // Named "a" in "n" throughout.
    fresh("n");
    check("mkdir", mkdir("n/a", 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    int wn = inotify_add_watch(fd, "n", graphEvents);
    int wa = inotify_add_watch(fd, "n/a", graphEvents);
    check("chdir", chdir("n/a"));
    check("rmdir", rmdir("../a"));
    line("N", "as-named-rmdir", "n=%d a=%d: %s", wn, wa, drain(fd));
    int r = chmod(".", 0700);
    line("N", "as-named-chmod", "chmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    goHome();
    close(fd);

    // Renamed "a" to "b" within "n", then removed as "b".
    fresh("n");
    check("mkdir", mkdir("n/a", 0755));
    fd = inotify_init1(IN_NONBLOCK);
    wn = inotify_add_watch(fd, "n", graphEvents);
    wa = inotify_add_watch(fd, "n/a", graphEvents);
    check("chdir", chdir("n/a"));
    check("rename", rename("../a", "../b"));
    check("rmdir", rmdir("../b"));
    line("N", "renamed-rmdir", "n=%d a=%d: %s", wn, wa, drain(fd));
    r = chmod(".", 0700);
    line("N", "renamed-chmod", "chmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    goHome();
    close(fd);

    // Moved from "n" to "m" as "c", then removed there.
    fresh("n");
    fresh("m");
    check("mkdir", mkdir("n/a", 0755));
    fd = inotify_init1(IN_NONBLOCK);
    wn = inotify_add_watch(fd, "n", graphEvents);
    int wm = inotify_add_watch(fd, "m", graphEvents);
    wa = inotify_add_watch(fd, "n/a", graphEvents);
    check("chdir", chdir("n/a"));
    check("rename", rename("../a", "../../m/c"));
    check("rmdir", rmdir("../c"));
    line("N", "moved-rmdir", "n=%d m=%d a=%d: %s", wn, wm, wa, drain(fd));
    r = chmod(".", 0700);
    line("N", "moved-chmod", "chmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    goHome();
    close(fd);

    // Displaced: "x" renamed over "y", the current directory, which is empty.
    fresh("n");
    check("mkdir", mkdir("n/x", 0755));
    check("mkdir", mkdir("n/y", 0755));
    fd = inotify_init1(IN_NONBLOCK);
    wn = inotify_add_watch(fd, "n", graphEvents);
    int wx = inotify_add_watch(fd, "n/x", graphEvents);
    int wy = inotify_add_watch(fd, "n/y", graphEvents);
    check("chdir", chdir("n/y"));
    check("rename", rename("../x", "../y"));
    line("N", "displaced-rename", "n=%d x=%d y=%d: %s", wn, wx, wy, drain(fd));
    r = chmod(".", 0700);
    line("N", "displaced-chmod", "chmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    goHome();
    close(fd);
}

static void sectionU(void)
{
    // "u/par/child", the current directory, removed; then "u/par".
    fresh("u");
    check("mkdir", mkdir("u/par", 0755));
    check("mkdir", mkdir("u/par/child", 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    int wu = inotify_add_watch(fd, "u", graphEvents);
    int wp = inotify_add_watch(fd, "u/par", graphEvents);
    int wc = inotify_add_watch(fd, "u/par/child", graphEvents);
    check("chdir", chdir("u/par/child"));
    check("rmdir", rmdir("../child"));
    line("U", "child-rmdir", "u=%d par=%d child=%d: %s", wu, wp, wc, drain(fd));
    check("rmdir", rmdir("../../par"));
    line("U", "parent-rmdir", "%s", drain(fd));
    int r = chmod(".", 0700);
    line("U", "child-chmod", "chmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    r = chmod("..", 0700);
    struct stat st;
    check("stat ..", stat("..", &st));
    line("U", "parent-chmod-by-dotdot", "chmod=%d mode=%o: %s", r, st.st_mode & 07777, drain(fd));
    goHome();
    line("U", "after-leaving", "%s", drain(fd));
    close(fd);
}

static void sectionE(void)
{
    fresh("e");
    check("mkdir", mkdir("e/a", 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    int we = inotify_add_watch(fd, "e", graphEvents | IN_EXCL_UNLINK);
    int wa = inotify_add_watch(fd, "e/a", graphEvents | IN_EXCL_UNLINK);
    check("chdir", chdir("e/a"));
    check("rmdir", rmdir("../a"));
    line("E", "excl-unlink-rmdir", "e=%d a=%d: %s", we, wa, drain(fd));
    int r = chmod(".", 0700);
    line("E", "excl-unlink-chmod", "chmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    goHome();
    close(fd);
}

static void sectionF(void)
{
    fresh("f");
    check("mkdir", mkdir("f/a", 0755));
    int fd = inotify_init1(IN_NONBLOCK);
    int wf = inotify_add_watch(fd, "f", graphEvents);
    int wa = inotify_add_watch(fd, "f/a", graphEvents);
    int byName = open("f/a", O_RDONLY | O_DIRECTORY);
    check("open f/a", byName);
    check("chdir", chdir("f/a"));
    check("rmdir", rmdir("../a"));
    line("F", "rmdir", "f=%d a=%d: %s", wf, wa, drain(fd));
    int byDot = open(".", O_RDONLY | O_DIRECTORY);
    line("F", "open-dot", "fd=%s errno=%d: %s", byDot >= 0 ? "ok" : "-1", byDot >= 0 ? 0 : errno, drain(fd));
    check("open .", byDot);
    int r = fchmod(byName, 0700);
    line("F", "fchmod-by-name", "fchmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    r = fchmod(byDot, 0750);
    line("F", "fchmod-by-dot", "fchmod=%d mode=%o: %s", r, modeOfDot(), drain(fd));
    goHome();
    int byAt = openat(byName, ".", O_RDONLY | O_DIRECTORY);
    line("F", "openat-dot", "fd=%s errno=%d: %s", byAt >= 0 ? "ok" : "-1", byAt >= 0 ? 0 : errno, drain(fd));
    check("openat .", byAt);
    r = fchmod(byAt, 0755);
    struct stat st;
    check("fstat", fstat(byAt, &st));
    line("F", "fchmod-by-openat-dot", "fchmod=%d mode=%o: %s", r, st.st_mode & 07777, drain(fd));
    r = utimensat(byName, ".", NULL, 0);
    line("F", "utimensat-at-dot", "utimensat=%d: %s", r, drain(fd));
    close(byAt);
    close(byDot);
    close(byName);
    line("F", "closed", "%s", drain(fd));
    close(fd);
}

int main(void)
{
    FILE *u = popen("uname -rm", "r");
    char release[128] = "";
    if (u && fgets(release, sizeof release, u)) fputs(release, stdout);
    if (u) pclose(u);
    if (!getcwd(home, sizeof home)) exit(1);
    sectionN();
    sectionU();
    sectionE();
    sectionF();
    return 0;
}
