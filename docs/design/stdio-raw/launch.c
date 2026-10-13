// What a process sees on fds 0, 1 and 2 under whatever launch shape its parent
// chose. Reports to fd 3 if open (so the streams under test stay untouched),
// else to stderr. With argument "pty", instead forkpty()s and runs itself under
// a fresh terminal, relaying what the child reports.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#ifdef __APPLE__
#include <util.h>
#else
#include <pty.h>
#endif

static FILE *out;

static const char *kind(mode_t m) {
    if (S_ISFIFO(m)) return "FIFO";
    if (S_ISCHR(m)) return "CHR";
    if (S_ISREG(m)) return "REG";
    if (S_ISSOCK(m)) return "SOCK";
    if (S_ISDIR(m)) return "DIR";
    return "?";
}

static void one(int fd) {
    int fdfl = fcntl(fd, F_GETFD);
    if (fdfl < 0) { fprintf(out, "fd %d: not open (errno %d)\n", fd, errno); return; }
    int fl = fcntl(fd, F_GETFL);
    struct stat st;
    fstat(fd, &st);
    errno = 0;
    int tty = isatty(fd);
    int ttyerr = errno;
    off_t pos = lseek(fd, 0, SEEK_CUR);
    int poserr = pos < 0 ? errno : 0;
    struct pollfd p = {fd, POLLIN | POLLOUT, 0};
    poll(&p, 1, 0);
    fprintf(out, "fd %d: accmode %d nonblock %d append %d cloexec %d | %s mode %#o size %lld rdev %#llx | isatty %d (errno %d) | lseek %lld (errno %d) | poll %#x\n",
            fd, fl & O_ACCMODE, !!(fl & O_NONBLOCK), !!(fl & O_APPEND), fdfl & FD_CLOEXEC, kind(st.st_mode),
            (unsigned)st.st_mode, (long long)st.st_size, (unsigned long long)st.st_rdev, tty, ttyerr, (long long)pos, poserr,
            p.revents);
}

static void shared(void) {
    // Does setting O_NONBLOCK through one descriptor show through the others?
    // Only descriptors sharing an open file description see it. Restored at once.
    for (int a = 0; a <= 2; a++) {
        int fl = fcntl(a, F_GETFL);
        if (fl < 0 || (fl & O_NONBLOCK)) continue;
        fcntl(a, F_SETFL, fl | O_NONBLOCK);
        fprintf(out, "O_NONBLOCK set via %d shows on:", a);
        for (int b = 0; b <= 2; b++) {
            if (b == a) continue;
            int g = fcntl(b, F_GETFL);
            if (g >= 0 && (g & O_NONBLOCK)) fprintf(out, " %d", b);
        }
        fprintf(out, "\n");
        fcntl(a, F_SETFL, fl);
    }
}

static void probe_stdin(void) {
    int fl = fcntl(0, F_GETFL);
    if (fl < 0) return;
    fcntl(0, F_SETFL, fl | O_NONBLOCK);
    char b[16];
    ssize_t r = read(0, b, sizeof b);
    int e = r < 0 ? errno : 0;
    fcntl(0, F_SETFL, fl);
    fprintf(out, "non-blocking read(0, 16) -> %zd errno %d\n", r, e);
    ssize_t w = write(0, "", 0);
    fprintf(out, "write(0, 0 bytes) -> %zd errno %d\n", w, w < 0 ? errno : 0);
    struct termios t;
    int g = tcgetattr(0, &t);
    fprintf(out, "tcgetattr(0) -> %d errno %d\n", g, g < 0 ? errno : 0);
}

static void first_open(void) {
    // The first descriptor a fresh open gets: 0 when the launch left stdin
    // closed. (Under "pty" the relay's own descriptors leak into the child, so
    // that row's number says nothing about the launch.)
    int fd = open("/", O_RDONLY);
    fprintf(out, "first open() gets fd %d\n", fd);
    if (fd >= 0) close(fd);
}

int main(int argc, char **argv) {
    alarm(10);
    if (argc > 1 && strcmp(argv[1], "pty") == 0) {
        int report[2];
        pipe(report);
        int master;
        pid_t c = forkpty(&master, NULL, NULL, NULL);
        if (c == 0) {
            dup2(report[1], 3);
            execl(argv[0], argv[0], (char *)NULL);
            _exit(127);
        }
        close(report[1]);
        char b[4096];
        ssize_t n;
        while ((n = read(report[0], b, sizeof b)) > 0) fwrite(b, 1, n, stdout);
        int ws;
        waitpid(c, &ws, 0);
        return 0;
    }
    // Duplicate the report channel high, so that a closed 0-2 stays closed
    // and the lowest-free check below measures the launch rather than us.
    out = fdopen(fcntl(fcntl(3, F_GETFD) >= 0 ? 3 : 2, F_DUPFD, 10), "w");
    if (!out) return 1;
    one(0); one(1); one(2);
    shared();
    probe_stdin();
    first_open();
    fclose(out);
    return 0;
}
