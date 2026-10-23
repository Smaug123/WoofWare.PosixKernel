// What Darwin's root may do to files it does not own, and what a second user
// may do to files only root could set up: the permission checks, the set-ID
// bits a write, truncation, chmod, chown or clonefile keeps, utimensat,
// sticky directories, mknod, and the real/effective split of access(2).
//
// Darwin only. Run it as root, through run.sh beside this file, which makes
// the base directory and removes it afterwards:
//   cd /tmp && sudo sh <checkout>/docs/probes/darwin-root/run.sh
// By hand: cc -Wall -Werror -o /tmp/root-files root-files.c && sudo /tmp/root-files "$(mktemp -d /private/tmp/rootfiles.XXXXXX)" [SECTION...]
// (as root it gives the base directory to root, mode 0700). It exits 1 if any
// of its child processes failed (a CHILD-FAILED row says which), so that its
// output is not taken for a complete measurement.
// Run as an ordinary user it measures what that user can set up alone (its
// own inodes in its own groups) and prints a SKIP row for everything else.
//
// Who is who. Every caller is a forked child that sets its groups with
// setgroups(2) before setgid(2) and setuid(2), so its group list is exactly
// the one named (a list set by setgroups is never extended by the directory
// service), and the parent checks the child's IDs rather than assuming them:
//   root  uid 0,   gid 0,  groups 0
//   u501  uid 501, gid 20, groups 20,701
//   u502  uid 502, gid 20, groups 20,701   (an existing account: factotum)
//   u504  uid 504, gid 20, groups 20,701   (an existing account: work)
// Group 20 is staff (every caller's effective group but root's), 701 a group
// every one of them holds as a supplementary group, and 7777 and 7778 groups
// no account is in (the directory has no group with either ID). An inode is
// named by its owner and group: "502:7777" is owned by uid 502 in group 7777.
//
// Sweeps. A sweep prepares 4096 inodes of one kind (file, dir or link) in a
// fresh directory, inode N carrying mode N (or, for chmod, mode 0 until the
// call asks for N), owned as the row says; the caller then makes the call on
// each, and the parent reads the result back. One MAP row per call:
//   MAP <section> <caller> <kind> <owner>:<group> <call> <8 segments>
// Segment h covers the modes h000 to h777 in order, as 512 characters, or as
// one character when all 512 agree. A character is:
//   .  the call succeeded and the mode is what it should be: the mode asked
//      for (chmod), or the mode before (every other call; for clonefile, the
//      clone's mode against the source's)
//   1-7  the call succeeded and the mode is that less the special bits this
//      digit names (4 S_ISUID, 2 S_ISGID, 1 S_ISVTX): "6" lost both set-ID bits
//   x  the call succeeded and the mode is something else (an ODD row says what)
//   y  the call failed and the mode changed anyway (an ODD row says what)
//   U  the mode could not be set up (the caller's own chmod dropped a bit)
//   -  not asked (exec is asked only of the modes below 01000 whose three
//      read bits are all set or all clear)
//   r  exec: the kernel ran the script, but the interpreter could not read it
//   an errno: A EACCES, P EPERM, N ENOENT, I EINVAL, F EFAULT, R EROFS,
//      S ENOTSUP, E EEXIST, L ELOOP, D EISDIR, T ENOTDIR, B EBADF, X ENOEXEC,
//      # any other (an ODD row says which), ? exec neither failed nor ran
//      to any exit status
// For a call that changes an inode, an IDS row gives the owner and group of
// the objects it succeeded on, with how many had each.
//
// Spot rows (UTIMENS, STICKY, MKNOD, REALEFF, CTIME) each print one call and
// what it did; their headers say what the fields are.
#ifndef __APPLE__
#error "Darwin only: Linux's root rows are measured by the probes under docs/plans"
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NMODES 4096
#define MAXOPS 10

static char base[PATH_MAX - 64];
static char swdir[PATH_MAX - 32];

static void die(const char *what) {
    perror(what);
    exit(2);
}

static void p(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static const char *en(int e) {
    static char b[32];
    switch (e) {
    case 0: return "ok";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case EROFS: return "EROFS";
    case ENOTSUP: return "ENOTSUP";
    case EEXIST: return "EEXIST";
    case ELOOP: return "ELOOP";
    case EISDIR: return "EISDIR";
    case ENOTDIR: return "ENOTDIR";
    case EBADF: return "EBADF";
    case ENOEXEC: return "ENOEXEC";
    case ENOTEMPTY: return "ENOTEMPTY";
    case EXDEV: return "EXDEV";
    case EBUSY: return "EBUSY";
    case -2: return "not-asked";
    case -3: return "neither-failed-nor-ran";
    case -4: return "ran-but-unreadable";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}

static char ech(int e) {
    switch (e) {
    case 0: return '.';
    case EACCES: return 'A';
    case EPERM: return 'P';
    case ENOENT: return 'N';
    case EINVAL: return 'I';
    case EFAULT: return 'F';
    case EROFS: return 'R';
    case ENOTSUP: return 'S';
    case EEXIST: return 'E';
    case ELOOP: return 'L';
    case EISDIR: return 'D';
    case ENOTDIR: return 'T';
    case EBADF: return 'B';
    case ENOEXEC: return 'X';
    case -2: return '-';
    case -3: return '?';
    case -4: return 'r';
    default: return '#';
    }
}

static void sleep_ms(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

// Which sections to run: all, or those named on the command line.
static int nsections;
static char **sections;
static int wanted(const char *name) {
    if (nsections == 0) return 1;
    for (int i = 0; i < nsections; i++)
        if (strcmp(sections[i], name) == 0) return 1;
    return 0;
}

// How many child processes failed: one that did not exit 0, or, as root, one
// that could not take the credentials its row names. Any failure makes the
// probe exit 1, so that run.sh does not publish its output as a measurement.
static int failures;

// Wait for `pid`, counting it as a failure (and saying so) unless it exited 0.
static void wait_child(pid_t pid, const char *what) {
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        failures++;
        p("CHILD-FAILED\t%s\tstatus=0x%x\n", what, st);
    }
}

// ---------------------------------------------------------------- callers

// Every child first enters the directory it works in, while it is still root,
// and then names its files relative to it. The base is root's, mode 0700, so
// no process outside the probe can reach a fixture by path (in particular, a
// script root executes cannot be rewritten by the user who owns it), and a
// child that has become another user still reaches its own directory's
// entries, since a relative lookup checks no ancestor.
static void enter(const char *dir) {
    if (chdir(dir) != 0) {
        perror("chdir into the fixture directory");
        _exit(3);
    }
}

typedef struct {
    const char *name;
    uid_t uid;
    gid_t gid;
    int ng;
    gid_t g[4];
} cred;

static const cred ROOT = {"root", 0, 0, 1, {0}};
static const cred U501 = {"u501", 501, 20, 2, {20, 701}};
static const cred U502 = {"u502", 502, 20, 2, {20, 701}};
static const cred U504 = {"u504", 504, 20, 2, {20, 701}};

static const gid_t G_OUT = 7777;
static const gid_t G_OTHER = 7778;

// Take `c`'s credentials. Returns 0 or the errno of the step that failed. An
// ordinary user can only "become" itself, with the groups it logged in with.
static int become(const cred *c) {
    if (geteuid() != 0) return c->uid == geteuid() ? 0 : EPERM;
    if (setgroups(c->ng, c->g) != 0) return errno;
    if (setgid(c->gid) != 0) return errno;
    if (c->uid != 0 && setuid(c->uid) != 0) return errno;
    return 0;
}

static void groups_text(char *out, size_t n) {
    gid_t gs[64];
    int k = getgroups(64, gs);
    size_t used = (size_t)snprintf(out, n, "[");
    for (int i = 0; i < k && used < n; i++) used += (size_t)snprintf(out + used, n - used, "%s%u", i ? "," : "", (unsigned)gs[i]);
    if (used < n) snprintf(out + used, n - used, "]");
}

// ---------------------------------------------------------------- the tree

// Remove the entry `name` of the directory open as `dfd`, and everything
// under it. Every step is relative to a descriptor and never follows a link,
// so a link put in place of a directory while this runs (by one of the
// probe's other users, which own some of these directories) is removed, not
// followed out of the tree. Each directory is fchmod 0700 first, which clears
// a sticky bit and lets an ordinary user descend its own mode-0 directories.
static void rmtree_at(int dfd, const char *name) {
    struct stat st;
    if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (fd < 0 && errno == EACCES) {
            // An ordinary user's own directory without its read bit: give it
            // one first (which changes a link put in its place, not what the
            // link names).
            fchmodat(dfd, name, 0700, AT_SYMLINK_NOFOLLOW);
            fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        }
        if (fd >= 0) {
            fchmod(fd, 0700);
            DIR *d = fdopendir(fd);
            if (d == NULL) close(fd);
            else {
                // Again until a pass finds nothing, since removing entries
                // while reading a directory may skip some.
                for (int pass = 0; pass < 4; pass++) {
                    int found = 0;
                    rewinddir(d);
                    struct dirent *e;
                    while ((e = readdir(d)) != NULL) {
                        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
                        found = 1;
                        rmtree_at(dirfd(d), e->d_name);
                    }
                    if (!found) break;
                }
                closedir(d);
            }
        }
        if (unlinkat(dfd, name, AT_REMOVEDIR) != 0) p("CLEANUP-FAILED\trmdir %s\t%s\n", name, en(errno));
    } else if (unlinkat(dfd, name, 0) != 0) {
        p("CLEANUP-FAILED\tunlink %s\t%s\n", name, en(errno));
    }
}

// Remove `path`, which must be an entry directly under the base (which only
// root, or the ordinary user running this, may change), and everything under
// it.
static void rmtree(const char *path) {
    size_t n = strlen(base);
    if (strncmp(path, base, n) != 0 || path[n] != '/' || path[n + 1] == 0 || strchr(path + n + 1, '/') != NULL) {
        fprintf(stderr, "refusing to remove %s, which is not an entry of %s\n", path, base);
        exit(2);
    }
    int bfd = open(base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (bfd < 0) die("open base");
    rmtree_at(bfd, path + n + 1);
    close(bfd);
}

// A fresh directory under the base, owned as asked, mode 0755.
static int fresh_dir(char *out, size_t n, const char *name, uid_t u, gid_t g, int mode) {
    snprintf(out, n, "%s/%s", base, name);
    // An ordinary user cannot give a directory to root; it keeps its own.
    if (geteuid() != 0 && u == 0) {
        u = geteuid();
        g = getegid();
    }
    rmtree(out);
    if (mkdir(out, 0700) != 0) die("mkdir fresh");
    if (chown(out, u, g) != 0) return errno;
    if (chmod(out, mode) != 0) return errno;
    return 0;
}

static const char script[] = "#!/bin/sh\nexit 7\n";

static int make_file(const char *pth, int mode) {
    int fd = open(pth, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return errno;
    if (write(fd, script, sizeof script - 1) != (ssize_t)(sizeof script - 1)) {
        int e = errno;
        close(fd);
        return e;
    }
    int r = fchmod(fd, mode) == 0 ? 0 : errno;
    close(fd);
    return r;
}

// Give `pth` an owner, a group and a mode, in that order (a chown may clear
// set-ID bits, so the mode goes last), never following a link: a file or
// directory through a descriptor opened with O_NOFOLLOW (every caller hands
// over an inode it has just made, which its maker may open), a link through
// lchown and lchmod. If root's chmod would not set the mode in that group,
// root tries the mode in its own group 0 and then the group; the caller reads
// back what stuck.
static int own(const char *pth, int is_link, uid_t u, gid_t g, int mode) {
    struct stat st;
    if (is_link) {
        if (lchown(pth, u, g) != 0 || fchmodat(AT_FDCWD, pth, mode, AT_SYMLINK_NOFOLLOW) != 0) return errno;
        if (geteuid() == 0 && lstat(pth, &st) == 0 && (int)(st.st_mode & 07777) != mode)
            if (lchown(pth, u, 0) != 0 || fchmodat(AT_FDCWD, pth, mode, AT_SYMLINK_NOFOLLOW) != 0 || lchown(pth, (uid_t)-1, g) != 0) return errno;
        return 0;
    }
    int fd = open(pth, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return errno;
    int r = 0;
    if (fchown(fd, u, g) != 0 || fchmod(fd, mode) != 0) r = errno;
    else if (geteuid() == 0 && fstat(fd, &st) == 0 && (int)(st.st_mode & 07777) != mode)
        if (fchown(fd, u, 0) != 0 || fchmod(fd, mode) != 0 || fchown(fd, (uid_t)-1, g) != 0) r = errno;
    close(fd);
    return r;
}

// ---------------------------------------------------------------- sweeps

enum kind { K_FILE, K_DIR, K_LINK };
static const char *kind_name[] = {"file", "dir", "link"};
enum { ASK_ALL, ASK_EXEC };

static int asked(int asks, int m) {
    if (asks == ASK_ALL) return 1;
    return m < 01000 && ((m & 0444) == 0444 || (m & 0444) == 0);
}

typedef struct op {
    const char *name;
    int (*run)(const char *path, int m, const struct op *o);
    int a, b;
    uid_t ru;
    gid_t rg;
    // 0: asks only; 1: the call may change the inode's mode; 2: it makes
    // `<inode>.clone`, whose mode is compared with the inode's.
    int mutates;
    // chmod: the mode the call should leave is the one it asked for.
    int expect_requested;
    // Which modes the call is asked of: ASK_ALL, or ASK_EXEC, the modes
    // below 01000 whose three read bits are all set or all clear.
    int asks;
} op;

typedef struct {
    int become_err;
    uid_t uid, euid;
    gid_t gid, egid;
    int res[MAXOPS][NMODES];
} shared_t;

static shared_t *sh;

static void nth(char *out, int m) { snprintf(out, PATH_MAX, "%s/%04o", swdir, m); }

static int op_open(const char *pth, int m, const op *o) {
    (void)m;
    int fd = open(pth, o->a);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

static int op_access(const char *pth, int m, const op *o) {
    (void)m;
    return faccessat(AT_FDCWD, pth, o->a, o->b) == 0 ? 0 : errno;
}

static int op_exec(const char *pth, int m, const op *o) {
    (void)m;
    (void)o;
    int pfd[2];
    if (pipe(pfd) != 0) return -3;
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) return -3;
    if (pid == 0) {
        close(pfd[0]);
        fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
        char *argv[] = {(char *)pth, NULL};
        char *envp[] = {"PATH=/usr/bin:/bin", NULL};
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, 2);
        execve(pth, argv, envp);
        int e = errno;
        if (write(pfd[1], &e, sizeof e) != sizeof e) _exit(3);
        _exit(1);
    }
    close(pfd[1]);
    int e = 0;
    ssize_t n = read(pfd[0], &e, sizeof e);
    close(pfd[0]);
    int st;
    waitpid(pid, &st, 0);
    if (n == (ssize_t)sizeof e) return e;
    if (WIFEXITED(st) && WEXITSTATUS(st) == 7) return 0;
    return WIFEXITED(st) ? -4 : -3;
}

static int op_search(const char *pth, int m, const op *o) {
    (void)m;
    (void)o;
    char c[PATH_MAX];
    snprintf(c, sizeof c, "%s/c", pth);
    struct stat st;
    return stat(c, &st) == 0 ? 0 : errno;
}

static int op_create(const char *pth, int m, const op *o) {
    (void)m;
    (void)o;
    char c[PATH_MAX];
    snprintf(c, sizeof c, "%s/n", pth);
    int fd = open(c, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return errno;
    close(fd);
    unlink(c);
    return 0;
}

static int op_readlink(const char *pth, int m, const op *o) {
    (void)m;
    (void)o;
    char b[64];
    return readlink(pth, b, sizeof b) >= 0 ? 0 : errno;
}

static int op_chmod(const char *pth, int m, const op *o) {
    int r = o->a ? fchmodat(AT_FDCWD, pth, m, AT_SYMLINK_NOFOLLOW) : chmod(pth, m);
    return r == 0 ? 0 : errno;
}

static int op_chown(const char *pth, int m, const op *o) {
    (void)m;
    int r = o->a ? lchown(pth, o->ru, o->rg) : chown(pth, o->ru, o->rg);
    return r == 0 ? 0 : errno;
}

enum { W_WRITE1, W_WRITE0, W_TRUNC0, W_TRUNCSAME, W_OTRUNC };

static int op_write(const char *pth, int m, const op *o) {
    (void)m;
    int fd = open(pth, O_WRONLY | (o->a == W_OTRUNC ? O_TRUNC : 0));
    if (fd < 0) return errno;
    int r = 0;
    switch (o->a) {
    case W_WRITE1: r = write(fd, "X", 1) == 1 ? 0 : errno; break;
    case W_WRITE0: r = write(fd, "X", 0) == 0 ? 0 : errno; break;
    case W_TRUNC0: r = ftruncate(fd, 0) == 0 ? 0 : errno; break;
    case W_TRUNCSAME: r = ftruncate(fd, (off_t)(sizeof script - 1)) == 0 ? 0 : errno; break;
    default: break;
    }
    close(fd);
    return r;
}

static int op_clone(const char *pth, int m, const op *o) {
    (void)m;
    char c[PATH_MAX];
    snprintf(c, sizeof c, "%s.clone", pth);
    return clonefile(pth, c, (uint32_t)o->a) == 0 ? 0 : errno;
}

typedef struct {
    const char *section;
    const cred *caller;
    enum kind kind;
    uid_t ou;
    gid_t og;
    // -1: inode N gets mode N; otherwise every inode gets this mode.
    int fixed_mode;
    // The sweep directory's owner and group (its mode is 0755).
    uid_t du;
    gid_t dg;
    // Directories get a file "c" inside them.
    int with_child;
} sweep_t;

static void print_map(const char *lab, const char *c) {
    printf("MAP\t%s\t", lab);
    for (int h = 0; h < 8; h++) {
        const char *seg = c + h * 512;
        int uniform = 1;
        for (int j = 1; j < 512; j++)
            if (seg[j] != seg[0]) {
                uniform = 0;
                break;
            }
        if (h) putchar(' ');
        if (uniform) putchar(seg[0]);
        else fwrite(seg, 1, 512, stdout);
    }
    putchar('\n');
    fflush(stdout);
}

typedef struct {
    uid_t u;
    gid_t g;
    int n;
} idcount;

static void sweep(const sweep_t *s, const op *ops, int nops) {
    char lab[MAXOPS][256];
    for (int i = 0; i < nops; i++) {
        char modebit[32] = "";
        if (s->fixed_mode >= 0) snprintf(modebit, sizeof modebit, " from %04o", s->fixed_mode);
        snprintf(lab[i], sizeof lab[i], "%s\t%s\t%s %u:%u%s\t%s", s->section, s->caller->name, kind_name[s->kind], (unsigned)s->ou,
                 (unsigned)s->og, modebit, ops[i].name);
    }
    int mutating = 0;
    for (int i = 0; i < nops; i++)
        if (ops[i].mutates) mutating = 1;
    if (mutating && nops != 1) {
        fprintf(stderr, "a sweep with a call that changes the inode must have only that call\n");
        exit(2);
    }

    char dummy[PATH_MAX];
    int e = fresh_dir(dummy, sizeof dummy, "sweep", s->du, s->dg, 0755);
    snprintf(swdir, sizeof swdir, "%s", dummy);
    if (e != 0) {
        if (geteuid() == 0) failures++;
        for (int i = 0; i < nops; i++) p("SKIP\t%s\tthe sweep directory cannot be given to %u:%u: %s\n", lab[i], (unsigned)s->du, (unsigned)s->dg, en(e));
        rmtree(swdir);
        return;
    }
    {
        char t[PATH_MAX];
        snprintf(t, sizeof t, "%s/t", swdir);
        if (make_file(t, 0644) != 0) die("link target");
    }

    static int before[NMODES];
    static int settable[NMODES];
    for (int m = 0; m < NMODES; m++) {
        char pth[PATH_MAX];
        nth(pth, m);
        int r;
        switch (s->kind) {
        case K_FILE: r = make_file(pth, 0600); break;
        case K_DIR:
            r = mkdir(pth, 0700) == 0 ? 0 : errno;
            if (r == 0 && s->with_child) {
                char c[PATH_MAX];
                snprintf(c, sizeof c, "%s/c", pth);
                r = make_file(c, 0644);
            }
            break;
        default: r = symlink("t", pth) == 0 ? 0 : errno; break;
        }
        if (r != 0) die("make inode");
        int want = s->fixed_mode >= 0 ? s->fixed_mode : m;
        r = own(pth, s->kind == K_LINK, s->ou, s->og, want);
        if (r != 0) {
            if (geteuid() == 0) failures++;
            for (int i = 0; i < nops; i++) p("SKIP\t%s\tthe inodes cannot be given to %u:%u: %s\n", lab[i], (unsigned)s->ou, (unsigned)s->og, en(r));
            rmtree(swdir);
            return;
        }
        struct stat st;
        if (lstat(pth, &st) != 0) die("lstat before");
        before[m] = st.st_mode & 07777;
        settable[m] = before[m] == want;
    }

    memset(sh, 0, sizeof *sh);
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        alarm(900);
        enter(swdir);
        sh->become_err = become(s->caller);
        sh->uid = getuid();
        sh->euid = geteuid();
        sh->gid = getgid();
        sh->egid = getegid();
        if (sh->become_err != 0) _exit(geteuid() == 0 ? 1 : 0);
        for (int m = 0; m < NMODES; m++) {
            char rel[16];
            snprintf(rel, sizeof rel, "./%04o", m);
            for (int i = 0; i < nops; i++) sh->res[i][m] = asked(ops[i].asks, m) ? ops[i].run(rel, m, &ops[i]) : -2;
        }
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (sh->become_err != 0) {
        if (geteuid() == 0) failures++;
        for (int i = 0; i < nops; i++)
            p("%s\t%s\tbecoming %s: %s%s\n", geteuid() == 0 ? "CHILD-FAILED" : "SKIP", lab[i], s->caller->name, en(sh->become_err),
              geteuid() == 0 ? "" : " (needs root)");
        rmtree(swdir);
        return;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        failures++;
        for (int i = 0; i < nops; i++) p("CHILD-FAILED\t%s\tthe caller's process ended with status 0x%x\n", lab[i], status);
        rmtree(swdir);
        return;
    }
    if (sh->euid != s->caller->uid || (geteuid() == 0 && sh->egid != s->caller->gid)) {
        failures++;
        for (int i = 0; i < nops; i++)
            p("CHILD-FAILED\t%s\tthe caller's IDs are uid=%u euid=%u gid=%u egid=%u, not the row's\n", lab[i], (unsigned)sh->uid, (unsigned)sh->euid, (unsigned)sh->gid,
              (unsigned)sh->egid);
        rmtree(swdir);
        return;
    }

    static char c[NMODES];
    for (int i = 0; i < nops; i++) {
        const op *o = &ops[i];
        idcount ids[8];
        int nids = 0, idoverflow = 0, odd = 0;
        for (int m = 0; m < NMODES; m++) {
            int r = sh->res[i][m];
            if (!settable[m]) {
                c[m] = 'U';
                continue;
            }
            if (!o->mutates) {
                c[m] = ech(r);
                if (c[m] == '#' && odd++ < 16) p("ODD\t%s\tmode=%04o\tresult=%s\n", lab[i], m, en(r));
                continue;
            }
            char pth[PATH_MAX], ip[PATH_MAX];
            nth(pth, m);
            if (o->mutates == 2) snprintf(ip, sizeof ip, "%s.clone", pth);
            else snprintf(ip, sizeof ip, "%s", pth);
            struct stat st;
            int have = lstat(ip, &st) == 0;
            int after = have ? (int)(st.st_mode & 07777) : -1;
            int expect = o->expect_requested ? m : before[m];
            if (r == -2) c[m] = '-';
            else if (r != 0) {
                c[m] = ech(r);
                if (o->mutates == 1 && after != before[m]) {
                    c[m] = 'y';
                    if (odd++ < 16) p("ODD\t%s\tmode=%04o\tresult=%s\tbefore=%04o\tafter=%04o\n", lab[i], m, en(r), before[m], after);
                } else if (c[m] == '#' && odd++ < 16)
                    p("ODD\t%s\tmode=%04o\tresult=%s\n", lab[i], m, en(r));
            } else if (!have) {
                c[m] = 'x';
                if (odd++ < 16) p("ODD\t%s\tmode=%04o\tresult=ok\tbut there is nothing at %s\n", lab[i], m, ip);
            } else {
                if (after == expect) c[m] = '.';
                else if ((after & 0777) == (expect & 0777) && (after & ~expect & 07000) == 0) c[m] = (char)('0' + ((expect & ~after) >> 9));
                else {
                    c[m] = 'x';
                    if (odd++ < 16) p("ODD\t%s\tmode=%04o\tresult=ok\tbefore=%04o\texpected=%04o\tafter=%04o\n", lab[i], m, before[m], expect, after);
                }
                int k;
                for (k = 0; k < nids; k++)
                    if (ids[k].u == st.st_uid && ids[k].g == st.st_gid) break;
                if (k < nids) ids[k].n++;
                else if (nids < 8) ids[nids++] = (idcount){st.st_uid, st.st_gid, 1};
                else idoverflow++;
            }
        }
        if (odd > 16) p("ODD\t%s\t%d more\n", lab[i], odd - 16);
        print_map(lab[i], c);
        if (o->mutates) {
            printf("IDS\t%s\t", lab[i]);
            if (nids == 0) printf("none");
            for (int k = 0; k < nids; k++) printf("%s%u:%u=%d", k ? " " : "", (unsigned)ids[k].u, (unsigned)ids[k].g, ids[k].n);
            if (idoverflow) printf(" others=%d", idoverflow);
            printf("\n");
            fflush(stdout);
        }
    }
    rmtree(swdir);
}

// ---------------------------------------------------------------- CRED

// Each caller as it stands after becoming itself, and which groups it is a
// member of as the kernel judges membership: whether it may open a file root
// owns in that group with mode 0040.
static void cred_section(void) {
    p("# CRED <caller> uid euid gid egid groups, then member=<gid>:<open of a 0:<gid> 0040 file>\n");
    char dir[PATH_MAX];
    if (fresh_dir(dir, sizeof dir, "cred", 0, 0, 0755) != 0) die("cred dir");
    const gid_t probe_groups[] = {0, 20, 701, G_OUT};
    int can_chown = 1;
    for (size_t i = 0; i < sizeof probe_groups / sizeof probe_groups[0]; i++) {
        char f[PATH_MAX];
        snprintf(f, sizeof f, "%s/g%u", dir, (unsigned)probe_groups[i]);
        if (make_file(f, 0600) != 0) die("cred file");
        if (own(f, 0, 0, probe_groups[i], 0040) != 0) can_chown = 0;
    }
    if (!can_chown && geteuid() == 0) {
        failures++;
        p("CHILD-FAILED\tCRED\tthe membership files could not be set up\n");
    }
    const cred *all[] = {&ROOT, &U501, &U502, &U504};
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            enter(dir);
            int e = become(all[i]);
            if (e != 0) {
                p("CRED\t%s\tbecome: %s (needs root)\n", all[i]->name, en(e));
                _exit(geteuid() == 0 ? 1 : 0);
            }
            char g[512];
            groups_text(g, sizeof g);
            printf("CRED\t%s\tuid=%u euid=%u gid=%u egid=%u groups=%s", all[i]->name, (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(),
                   (unsigned)getegid(), g);
            if (can_chown && geteuid() != 0)
                for (size_t j = 0; j < sizeof probe_groups / sizeof probe_groups[0]; j++) {
                    char f[PATH_MAX];
                    snprintf(f, sizeof f, "g%u", (unsigned)probe_groups[j]);
                    int fd = open(f, O_RDONLY);
                    printf("\tmember=%u:%s", (unsigned)probe_groups[j], fd >= 0 ? "ok" : en(errno));
                    if (fd >= 0) close(fd);
                }
            printf("\n");
            fflush(stdout);
            _exit(0);
        }
        wait_child(pid, __func__);
    }
    rmtree(dir);
}

// ---------------------------------------------------------------- ACCESS

static void access_section(void) {
    p("# ACCESS: open, access(2) (real IDs = effective IDs here), execve of a\n");
    p("# '#!/bin/sh' script that exits 7, search of a directory (stat of its\n");
    p("# file c), creating a file in it, readlink, and faccessat with\n");
    p("# AT_SYMLINK_NOFOLLOW asked of the link itself.\n");
    const op file_ops[] = {
        {"open(O_RDONLY)", op_open, O_RDONLY, 0, 0, 0, 0, 0, 0},
        {"open(O_WRONLY)", op_open, O_WRONLY, 0, 0, 0, 0, 0, 0},
        {"open(O_RDWR)", op_open, O_RDWR, 0, 0, 0, 0, 0, 0},
        {"access(R_OK)", op_access, R_OK, 0, 0, 0, 0, 0, 0},
        {"access(W_OK)", op_access, W_OK, 0, 0, 0, 0, 0, 0},
        {"access(X_OK)", op_access, X_OK, 0, 0, 0, 0, 0, 0},
        {"execve", op_exec, 0, 0, 0, 0, 0, 0, ASK_EXEC},
    };
    const op dir_ops[] = {
        {"open(O_RDONLY|O_DIRECTORY)", op_open, O_RDONLY | O_DIRECTORY, 0, 0, 0, 0, 0, 0},
        {"search", op_search, 0, 0, 0, 0, 0, 0, 0},
        {"create", op_create, 0, 0, 0, 0, 0, 0, 0},
        {"access(R_OK)", op_access, R_OK, 0, 0, 0, 0, 0, 0},
        {"access(W_OK)", op_access, W_OK, 0, 0, 0, 0, 0, 0},
        {"access(X_OK)", op_access, X_OK, 0, 0, 0, 0, 0, 0},
    };
    const op link_ops[] = {
        {"readlink", op_readlink, 0, 0, 0, 0, 0, 0, 0},
        {"faccessat(R_OK,NOFOLLOW)", op_access, R_OK, AT_SYMLINK_NOFOLLOW, 0, 0, 0, 0, 0},
        {"faccessat(W_OK,NOFOLLOW)", op_access, W_OK, AT_SYMLINK_NOFOLLOW, 0, 0, 0, 0, 0},
        {"faccessat(X_OK,NOFOLLOW)", op_access, X_OK, AT_SYMLINK_NOFOLLOW, 0, 0, 0, 0, 0},
    };
    struct {
        const cred *c;
        uid_t ou;
        gid_t og;
    } rows[] = {
        {&ROOT, 502, G_OUT}, {&ROOT, 502, 0}, {&ROOT, 502, 701}, {&ROOT, 0, G_OUT}, {&ROOT, 0, 0},
        {&U501, 502, 20},    {&U501, 502, 701}, {&U501, 502, G_OUT}, {&U501, 501, G_OUT}, {&U501, 501, 20},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        sweep_t s = {"ACCESS", rows[i].c, K_FILE, rows[i].ou, rows[i].og, -1, 0, 0, 0};
        sweep(&s, file_ops, sizeof file_ops / sizeof file_ops[0]);
    }
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        sweep_t s = {"ACCESS", rows[i].c, K_DIR, rows[i].ou, rows[i].og, -1, 0, 0, 1};
        sweep(&s, dir_ops, sizeof dir_ops / sizeof dir_ops[0]);
    }
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        sweep_t s = {"ACCESS", rows[i].c, K_LINK, rows[i].ou, rows[i].og, -1, 0, 0, 0};
        sweep(&s, link_ops, sizeof link_ops / sizeof link_ops[0]);
    }
}

// ---------------------------------------------------------------- CHMOD

static void chmod_section(void) {
    p("# CHMOD: every inode starts at mode 0000 and is asked for mode N; '.' means it got N.\n");
    struct {
        const cred *c;
        enum kind k;
        uid_t ou;
        gid_t og;
    } rows[] = {
        {&ROOT, K_FILE, 502, G_OUT}, {&ROOT, K_FILE, 502, 0}, {&ROOT, K_FILE, 0, G_OUT}, {&ROOT, K_FILE, 0, 0},
        {&ROOT, K_DIR, 502, G_OUT},  {&ROOT, K_DIR, 502, 0},  {&ROOT, K_DIR, 0, G_OUT},  {&ROOT, K_DIR, 0, 0},
        {&ROOT, K_LINK, 502, G_OUT}, {&ROOT, K_LINK, 502, 0}, {&ROOT, K_LINK, 0, G_OUT}, {&ROOT, K_LINK, 0, 0},
        {&U501, K_FILE, 502, 20},    {&U501, K_FILE, 502, G_OUT}, {&U501, K_DIR, 502, 20}, {&U501, K_LINK, 502, 20},
        {&U501, K_FILE, 501, G_OUT}, {&U501, K_FILE, 501, 20},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        op o = {rows[i].k == K_LINK ? "fchmodat(N,NOFOLLOW)" : "chmod(N)", op_chmod, rows[i].k == K_LINK, 0, 0, 0, 1, 1, 0};
        sweep_t s = {"CHMOD", rows[i].c, rows[i].k, rows[i].ou, rows[i].og, 0, 0, 0, 0};
        sweep(&s, &o, 1);
    }
}

// ---------------------------------------------------------------- CHOWN

static void chown_section(void) {
    p("# CHOWN: chown(2) (lchown(2) on a link) asking the IDs named; '.' means the mode is unchanged.\n");
    p("# Requests: owner/group = the inode's own; self/callersgroup = the caller's uid/egid;\n");
    p("# other = uid 504; othergroup = gid 7778 (no account's).\n");
    struct {
        const cred *c;
        uid_t ou;
        gid_t og;
    } rows[] = {
        {&ROOT, 0, 0}, {&ROOT, 0, G_OUT}, {&ROOT, 502, 0}, {&ROOT, 502, G_OUT}, {&U501, 501, G_OUT}, {&U501, 502, 20}, {&U501, 502, G_OUT},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        const cred *c = rows[i].c;
        uid_t ou = rows[i].ou;
        gid_t og = rows[i].og;
        struct {
            const char *name;
            uid_t ru;
            gid_t rg;
        } reqs[] = {
            {"(-1,-1)", (uid_t)-1, (gid_t)-1},
            {"(owner,-1)", ou, (gid_t)-1},
            {"(-1,group)", (uid_t)-1, og},
            {"(self,-1)", c->uid, (gid_t)-1},
            {"(-1,callersgroup)", (uid_t)-1, c->gid},
            {"(other,-1)", 504, (gid_t)-1},
            {"(-1,othergroup)", (uid_t)-1, G_OTHER},
            {"(other,othergroup)", 504, G_OTHER},
        };
        for (int k = K_FILE; k <= K_LINK; k++)
            for (size_t r = 0; r < sizeof reqs / sizeof reqs[0]; r++) {
                char name[96];
                snprintf(name, sizeof name, "%s%s=(%d,%d)", k == K_LINK ? "lchown" : "chown", reqs[r].name, (int)reqs[r].ru, (int)reqs[r].rg);
                op o = {name, op_chown, k == K_LINK, 0, reqs[r].ru, reqs[r].rg, 1, 0, 0};
                sweep_t s = {"CHOWN", c, (enum kind)k, ou, og, -1, 0, 0, 0};
                sweep(&s, &o, 1);
            }
    }
}

// ---------------------------------------------------------------- SETID

static void setid_section(void) {
    p("# SETID: a 17-byte file opened O_WRONLY (O_WRONLY|O_TRUNC for open(O_TRUNC)), then one byte\n");
    p("# written at offset 0, no bytes written, ftruncate to 0, or ftruncate to its length;\n");
    p("# '.' means the mode is unchanged.\n");
    struct {
        const cred *c;
        uid_t ou;
        gid_t og;
    } rows[] = {
        {&ROOT, 0, 0},     {&ROOT, 0, G_OUT},    {&ROOT, 502, 0},     {&ROOT, 502, G_OUT},  {&U501, 501, 20},
        {&U501, 501, G_OUT}, {&U501, 502, 20}, {&U501, 502, 701}, {&U501, 502, G_OUT},
    };
    const op ops[] = {
        {"write(1)", op_write, W_WRITE1, 0, 0, 0, 1, 0, 0},
        {"write(0)", op_write, W_WRITE0, 0, 0, 0, 1, 0, 0},
        {"ftruncate(0)", op_write, W_TRUNC0, 0, 0, 0, 1, 0, 0},
        {"ftruncate(same)", op_write, W_TRUNCSAME, 0, 0, 0, 1, 0, 0},
        {"open(O_TRUNC)", op_write, W_OTRUNC, 0, 0, 0, 1, 0, 0},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        for (size_t j = 0; j < sizeof ops / sizeof ops[0]; j++) {
            sweep_t s = {"SETID", rows[i].c, K_FILE, rows[i].ou, rows[i].og, -1, 0, 0, 0};
            sweep(&s, &ops[j], 1);
        }
}

// ---------------------------------------------------------------- CLONE

static void clone_section(void) {
    p("# CLONE: clonefile(<inode>, <inode>.clone, flags) into the same directory, whose owner is\n");
    p("# given; '.' means the clone has the source's mode, IDS gives the clone's owner and group.\n");
    struct {
        const cred *c;
        uid_t ou;
        gid_t og;
        int flags;
        uid_t du;
        gid_t dg;
    } rows[] = {
        {&ROOT, 502, G_OUT, 0, 0, 20},
        {&ROOT, 502, 0, 0, 0, 20},
        {&ROOT, 0, 0, 0, 0, 20},
        {&ROOT, 0, G_OUT, 0, 0, 20},
        {&ROOT, 502, G_OUT, CLONE_NOOWNERCOPY, 0, 20},
        {&ROOT, 502, 0, CLONE_NOOWNERCOPY, 0, 20},
        {&ROOT, 0, 0, CLONE_NOOWNERCOPY, 0, 20},
        {&ROOT, 0, G_OUT, CLONE_NOOWNERCOPY, 0, 20},
        {&U501, 504, 20, 0, 501, 20},
        {&U501, 504, G_OUT, 0, 501, 20},
        {&U501, 501, G_OUT, 0, 501, 20},
        {&U501, 501, 20, 0, 501, 20},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char name[96];
        snprintf(name, sizeof name, "clonefile(flags=%s) into a dir %u:%u", rows[i].flags ? "CLONE_NOOWNERCOPY" : "0", (unsigned)rows[i].du,
                 (unsigned)rows[i].dg);
        op o = {name, op_clone, rows[i].flags, 0, 0, 0, 2, 0, 0};
        sweep_t s = {"CLONE", rows[i].c, K_FILE, rows[i].ou, rows[i].og, -1, rows[i].du, rows[i].dg, 0};
        sweep(&s, &o, 1);
    }
}

// ---------------------------------------------------------------- UTIMENS

static const struct timespec P0 = {1000000000, 0};
static const struct timespec TA = {1500000000, 123456789};
static const struct timespec TM = {1600000000, 987654321};

static void time_text(char *out, size_t n, struct timespec before, struct timespec after, struct timespec explicit) {
    struct timeval now;
    gettimeofday(&now, NULL);
    if (after.tv_sec == before.tv_sec && after.tv_nsec == before.tv_nsec) snprintf(out, n, "same");
    else if (after.tv_sec == explicit.tv_sec && after.tv_nsec == explicit.tv_nsec) snprintf(out, n, "T");
    else if (after.tv_sec >= now.tv_sec - 10 && after.tv_sec <= now.tv_sec + 1) snprintf(out, n, "now");
    else snprintf(out, n, "%ld.%09ld", (long)after.tv_sec, after.tv_nsec);
}

static void utimens_row(const cred *c, enum kind k, uid_t ou, gid_t og, int mode, int tcase) {
    static const char *tnames[] = {"NULL", "now,now", "T,T", "now,omit", "omit,now", "T,omit", "omit,T", "omit,omit"};
    struct timespec ts[2];
    struct timespec now = {0, UTIME_NOW}, omit = {0, UTIME_OMIT};
    switch (tcase) {
    case 1: ts[0] = now; ts[1] = now; break;
    case 2: ts[0] = TA; ts[1] = TM; break;
    case 3: ts[0] = now; ts[1] = omit; break;
    case 4: ts[0] = omit; ts[1] = now; break;
    case 5: ts[0] = TA; ts[1] = omit; break;
    case 6: ts[0] = omit; ts[1] = TM; break;
    case 7: ts[0] = omit; ts[1] = omit; break;
    default: break;
    }
    char dir[PATH_MAX], o[PATH_MAX];
    if (fresh_dir(dir, sizeof dir, "ut", 0, 0, 0755) != 0) die("ut dir");
    snprintf(o, sizeof o, "%s/o", dir);
    int flags = k == K_LINK ? AT_SYMLINK_NOFOLLOW : 0;
    int r;
    if (k == K_FILE) r = make_file(o, 0600);
    else if (k == K_DIR) r = mkdir(o, 0700) == 0 ? 0 : errno;
    else {
        char t[PATH_MAX];
        snprintf(t, sizeof t, "%s/t", dir);
        if (make_file(t, 0644) != 0) die("ut target");
        r = symlink("t", o) == 0 ? 0 : errno;
    }
    if (r != 0) die("ut object");
    struct timespec past[2] = {P0, P0};
    if (utimensat(AT_FDCWD, o, past, flags) != 0) die("ut past");
    const char *label = k == K_LINK ? "utimensat(NOFOLLOW)" : "utimensat";
    r = own(o, k == K_LINK, ou, og, mode);
    if (r != 0) {
        if (geteuid() == 0) failures++;
        p("UTIMENS\t%s\t%s %u:%u %04o\t%s\ttimes=%s\tSKIP: the object cannot be given to %u:%u: %s\n", c->name, kind_name[k], (unsigned)ou, (unsigned)og, mode, label,
          tnames[tcase], (unsigned)ou, (unsigned)og, en(r));
        rmtree(dir);
        return;
    }
    struct stat b, a;
    if (lstat(o, &b) != 0) die("ut lstat");
    sleep_ms(20);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        enter(dir);
        int e = become(c);
        if (e != 0) {
            sh->become_err = e;
            _exit(geteuid() == 0 ? 1 : 0);
        }
        sh->become_err = 0;
        sh->res[0][0] = utimensat(AT_FDCWD, "o", tcase == 0 ? NULL : ts, flags) == 0 ? 0 : errno;
        _exit(0);
    }
    wait_child(pid, __func__);
    if (sh->become_err != 0) {
        p("UTIMENS\t%s\t%s %u:%u %04o\t%s\ttimes=%s\tSKIP: becoming %s: %s\n", c->name, kind_name[k], (unsigned)ou, (unsigned)og, mode, label, tnames[tcase], c->name,
          en(sh->become_err));
        rmtree(dir);
        return;
    }
    if (lstat(o, &a) != 0) die("ut lstat after");
    char at[48], mt[48];
    time_text(at, sizeof at, b.st_atimespec, a.st_atimespec, TA);
    time_text(mt, sizeof mt, b.st_mtimespec, a.st_mtimespec, TM);
    int cmoved = a.st_ctimespec.tv_sec != b.st_ctimespec.tv_sec || a.st_ctimespec.tv_nsec != b.st_ctimespec.tv_nsec;
    p("UTIMENS\t%s\t%s %u:%u %04o\t%s\ttimes=%s\t-> %s\tatime=%s mtime=%s ctime=%s\n", c->name, kind_name[k], (unsigned)ou, (unsigned)og, mode, label, tnames[tcase],
      en(sh->res[0][0]), at, mt, cmoved ? "moved" : "same");
    rmtree(dir);
}

static void utimens_section(void) {
    p("# UTIMENS <caller> <object> <call> times=<atime,mtime asked> -> <errno> atime= mtime= ctime=\n");
    p("# Each time: same (as before, 1000000000.0), T (the explicit time asked: atime\n");
    p("# 1500000000.123456789, mtime 1600000000.987654321), now, or the value; ctime: moved or same.\n");
    struct {
        const cred *c;
        enum kind k;
        uid_t ou;
        gid_t og;
        int mode;
        int all_times;
    } rows[] = {
        {&ROOT, K_FILE, 502, G_OUT, 0000, 1}, {&ROOT, K_FILE, 502, G_OUT, 0444, 1}, {&ROOT, K_FILE, 502, G_OUT, 0644, 1},
        {&ROOT, K_FILE, 502, G_OUT, 0666, 1}, {&ROOT, K_DIR, 502, G_OUT, 0755, 1},  {&ROOT, K_DIR, 502, G_OUT, 0000, 1},
        {&ROOT, K_LINK, 502, G_OUT, 0755, 1}, {&ROOT, K_LINK, 502, G_OUT, 0000, 1}, {&U501, K_LINK, 502, G_OUT, 0666, 0},
        {&U501, K_LINK, 502, G_OUT, 0777, 0}, {&U501, K_LINK, 502, 20, 0664, 0},    {&U501, K_LINK, 502, 20, 0644, 0},
        {&U501, K_LINK, 502, G_OUT, 0644, 0}, {&U501, K_FILE, 502, 20, 0664, 0},    {&U501, K_FILE, 502, G_OUT, 0666, 0},
        {&U501, K_FILE, 502, G_OUT, 0644, 0},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++)
        for (int t = 0; t < 8; t++) {
            if (!rows[i].all_times && !(t == 0 || t == 1 || t == 2 || t == 7)) continue;
            utimens_row(rows[i].c, rows[i].k, rows[i].ou, rows[i].og, rows[i].mode, t);
        }
}

// ---------------------------------------------------------------- STICKY

// The tree each sticky row starts from, under <base>/st:
//   S          the directory under test, owned by 502:20, mode `smode`
//   S/f, S/f2  files owned by 504:20, mode 0644
//   S/d        an empty directory owned by 504:20, mode `dmode`
//   S/n        a directory owned by 504:20, mode 0755, holding a file
//   S/m501     a file owned by 501:20
//   O          a directory owned by root, mode 0777, not sticky
//   O/of       a file owned by root;   O/od  an empty directory owned by root
//   O/f501     a file owned by 501:20; O/d501 an empty directory owned by 501:20
static int sticky_tree(char *S, char *O, int smode, int dmode) {
    char st[PATH_MAX], q[PATH_MAX];
    if (fresh_dir(st, sizeof st, "st", 0, 0, 0755) != 0) die("st dir");
    snprintf(S, PATH_MAX, "%s/S", st);
    snprintf(O, PATH_MAX, "%s/O", st);
    if (mkdir(S, 0700) != 0 || mkdir(O, 0700) != 0) die("st mkdir");
    int r = 0;
#define TRY(x) \
    if (r == 0) r = (x)
    snprintf(q, sizeof q, "%s/f", S);
    if (make_file(q, 0644) != 0) die("st f");
    TRY(own(q, 0, 504, 20, 0644));
    snprintf(q, sizeof q, "%s/f2", S);
    if (make_file(q, 0644) != 0) die("st f2");
    TRY(own(q, 0, 504, 20, 0644));
    snprintf(q, sizeof q, "%s/d", S);
    if (mkdir(q, 0700) != 0) die("st d");
    TRY(own(q, 0, 504, 20, dmode));
    snprintf(q, sizeof q, "%s/n", S);
    if (mkdir(q, 0700) != 0) die("st n");
    {
        char c[PATH_MAX];
        snprintf(c, sizeof c, "%s/c", q);
        if (make_file(c, 0644) != 0) die("st n/c");
        TRY(own(c, 0, 504, 20, 0644));
    }
    TRY(own(q, 0, 504, 20, 0755));
    snprintf(q, sizeof q, "%s/m501", S);
    if (make_file(q, 0644) != 0) die("st m501");
    TRY(own(q, 0, 501, 20, 0644));
    snprintf(q, sizeof q, "%s/of", O);
    if (make_file(q, 0644) != 0) die("st of");
    snprintf(q, sizeof q, "%s/od", O);
    if (mkdir(q, 0755) != 0) die("st od");
    snprintf(q, sizeof q, "%s/f501", O);
    if (make_file(q, 0644) != 0) die("st f501");
    TRY(own(q, 0, 501, 20, 0644));
    snprintf(q, sizeof q, "%s/d501", O);
    if (mkdir(q, 0700) != 0) die("st d501");
    TRY(own(q, 0, 501, 20, 0755));
    if (chmod(O, 0777) != 0) die("st O");
    TRY(own(S, 0, 502, 20, smode));
#undef TRY
    return r;
}

static const char *exists_text(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return "absent";
    static char b[64];
    snprintf(b, sizeof b, "%s %u:%u", S_ISDIR(st.st_mode) ? "dir" : "file", (unsigned)st.st_uid, (unsigned)st.st_gid);
    return b;
}

enum st_op { ST_UNLINK, ST_RMDIR, ST_RENAME };

static void sticky_row(const cred *c, int smode, int dmode, enum st_op op, const char *a, const char *b) {
    char S[PATH_MAX], O[PATH_MAX], pa[PATH_MAX], pb[PATH_MAX];
    int r = sticky_tree(S, O, smode, dmode);
    // `a` and `b` are relative to <base>/st.
    char st[PATH_MAX];
    snprintf(st, sizeof st, "%s/st", base);
    snprintf(pa, sizeof pa, "%s/%s", st, a);
    if (b) snprintf(pb, sizeof pb, "%s/%s", st, b);
    const char *opname = op == ST_UNLINK ? "unlink" : op == ST_RMDIR ? "rmdir" : "rename";
    char desc[256];
    if (b) snprintf(desc, sizeof desc, "%s(%s, %s)", opname, a, b);
    else snprintf(desc, sizeof desc, "%s(%s)", opname, a);
    if (r != 0) {
        if (geteuid() == 0) failures++;
        p("STICKY\t%s\tS=%04o d=%04o\t%s\tSKIP: the tree needs root: %s\n", c->name, smode, dmode, desc, en(r));
        rmtree(st);
        return;
    }
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        enter(st);
        int e = become(c);
        if (e != 0) {
            sh->become_err = e;
            _exit(geteuid() == 0 ? 1 : 0);
        }
        sh->become_err = 0;
        int rr;
        if (op == ST_UNLINK) rr = unlink(a);
        else if (op == ST_RMDIR) rr = rmdir(a);
        else rr = rename(a, b);
        sh->res[0][0] = rr == 0 ? 0 : errno;
        _exit(0);
    }
    wait_child(pid, __func__);
    if (sh->become_err != 0) {
        p("STICKY\t%s\tS=%04o d=%04o\t%s\tSKIP: becoming %s: %s\n", c->name, smode, dmode, desc, c->name, en(sh->become_err));
    } else {
        char ea[96];
        snprintf(ea, sizeof ea, "%s", exists_text(pa));
        if (b) p("STICKY\t%s\tS=%04o d=%04o\t%s\t-> %s\tafter: %s=%s %s=%s\n", c->name, smode, dmode, desc, en(sh->res[0][0]), a, ea, b, exists_text(pb));
        else p("STICKY\t%s\tS=%04o d=%04o\t%s\t-> %s\tafter: %s=%s\n", c->name, smode, dmode, desc, en(sh->res[0][0]), a, ea);
    }
    rmtree(st);
}

static void sticky_section(void) {
    p("# STICKY <caller> S=<mode of S> d=<mode of S/d> <call> -> <errno> after: <what each path names>\n");
    p("# S is 502:20; S/f, S/f2, S/d, S/n are 504:20; S/m501 is 501:20; O is root's 0777; O/of and\n");
    p("# O/od are root's; O/f501 and O/d501 are 501:20. Every row starts from a fresh tree.\n");
    const int smodes_root[] = {01777, 01555, 0777};
    for (size_t i = 0; i < sizeof smodes_root / sizeof smodes_root[0]; i++) {
        int sm = smodes_root[i];
        sticky_row(&ROOT, sm, 0755, ST_UNLINK, "S/f", NULL);
        sticky_row(&ROOT, sm, 0755, ST_RMDIR, "S/d", NULL);
        sticky_row(&ROOT, sm, 0755, ST_RMDIR, "S/n", NULL);
        sticky_row(&ROOT, sm, 0755, ST_RENAME, "S/f", "O/x");
        sticky_row(&ROOT, sm, 0755, ST_RENAME, "O/of", "S/f");
        sticky_row(&ROOT, sm, 0755, ST_RENAME, "S/f", "S/y");
        sticky_row(&ROOT, sm, 0755, ST_RENAME, "S/f", "S/f2");
        sticky_row(&ROOT, sm, 0755, ST_RENAME, "O/od", "S/d");
        sticky_row(&ROOT, sm, 0755, ST_RENAME, "S/d", "O/z");
    }
    const int smodes_user[] = {01777, 0777};
    const int dmodes[] = {0755, 0777};
    for (size_t i = 0; i < sizeof smodes_user / sizeof smodes_user[0]; i++) {
        int sm = smodes_user[i];
        sticky_row(&U501, sm, 0755, ST_UNLINK, "S/f", NULL);
        sticky_row(&U501, sm, 0755, ST_UNLINK, "S/m501", NULL);
        sticky_row(&U501, sm, 0755, ST_RMDIR, "S/d", NULL);
        sticky_row(&U501, sm, 0755, ST_RENAME, "S/f", "O/x");
        sticky_row(&U501, sm, 0755, ST_RENAME, "O/f501", "S/f");
        for (size_t j = 0; j < sizeof dmodes / sizeof dmodes[0]; j++) {
            sticky_row(&U501, sm, dmodes[j], ST_RENAME, "O/d501", "S/d");
            sticky_row(&U501, sm, dmodes[j], ST_RENAME, "S/d", "O/z");
        }
    }
}

// ---------------------------------------------------------------- MKNOD

static void mknod_section(void) {
    p("# MKNOD <caller> type=<S_IFMT field, octal> perm=<low 12 bits asked> dev=<major,minor> path=<which> umask=022\n");
    p("#   -> <errno> node=<what lstat then finds: type perm rdev uid:gid>\n");
    p("# Paths: new (a free name in a directory root owns, mode 0777), existing (a file there),\n");
    p("# missing-parent (nx/new), trailing-slash (new/), empty (\"\"), null (NULL).\n");
    // Every value of the type field: the seven named types, S_IFWHT (0160000,
    // a whiteout), and the seven that name nothing.
    const int types[] = {0, S_IFREG, S_IFIFO, S_IFSOCK, S_IFCHR, S_IFBLK, S_IFDIR, S_IFLNK, S_IFWHT, 0030000, 0050000, 0070000, 0110000, 0130000, 0150000, 0170000};
    const char *paths[] = {"new", "existing", "missing-parent", "trailing-slash", "empty", "null"};
    const cred *callers[] = {&ROOT, &U501};
    // Major 126 has no driver on this machine, so a device node made here
    // names no device. (Major 0 would be the console.) Only a device type is
    // given a device number.
    const dev_t devs[] = {makedev(126, 0), makedev(126, 1)};
    umask(022);
    for (size_t ci = 0; ci < 2; ci++)
        for (size_t ti = 0; ti < sizeof types / sizeof types[0]; ti++)
            for (size_t pi = 0; pi < sizeof paths / sizeof paths[0]; pi++)
                for (int perm = 0; perm < 2; perm++)
                    for (size_t di = 0; di < 2; di++) {
                        // Only a device type has a second device number to try, and
                        // only a fresh name a second permission word.
                        if (di == 1 && types[ti] != S_IFCHR && types[ti] != S_IFBLK) continue;
                        if (perm == 1 && pi != 0) continue;
                        int pbits = perm ? 07777 : 0644;
                        int is_dev = types[ti] == S_IFCHR || types[ti] == S_IFBLK;
                        dev_t dev = is_dev ? devs[di] : 0;
                        char dir[PATH_MAX];
                        if (fresh_dir(dir, sizeof dir, "mk", 0, 0, 0777) != 0) die("mk dir");
                        char e[PATH_MAX];
                        snprintf(e, sizeof e, "%s/existing", dir);
                        if (make_file(e, 0644) != 0) die("mk existing");
                        // Relative to `dir`, which the child enters.
                        static const char *const rels[] = {"new", "existing", "nx/new", "new/", ""};
                        const char *arg = pi < 5 ? rels[pi] : NULL;
                        fflush(stdout);
                        pid_t pid = fork();
                        if (pid == 0) {
                            enter(dir);
                            umask(022);
                            int be = become(callers[ci]);
                            if (be != 0) {
                                sh->become_err = be;
                                _exit(geteuid() == 0 ? 1 : 0);
                            }
                            sh->become_err = 0;
                            sh->res[0][0] = mknod(arg, (mode_t)(types[ti] | pbits), dev) == 0 ? 0 : errno;
                            _exit(0);
                        }
                        wait_child(pid, __func__);
                        char lead[256];
                        snprintf(lead, sizeof lead, "MKNOD\t%s\ttype=%06o\tperm=%04o\tdev=%d,%d\tpath=%s", callers[ci]->name, types[ti], pbits, major(dev), minor(dev), paths[pi]);
                        if (sh->become_err != 0) {
                            p("%s\tSKIP: becoming %s: %s\n", lead, callers[ci]->name, en(sh->become_err));
                        } else {
                            char node[128] = "-";
                            char n[PATH_MAX];
                            snprintf(n, sizeof n, "%s/new", dir);
                            struct stat st;
                            if ((pi == 0 || pi == 3) && lstat(n, &st) == 0)
                                snprintf(node, sizeof node, "%06o %04o %d,%d %u:%u", (int)(st.st_mode & S_IFMT), (int)(st.st_mode & 07777), major(st.st_rdev),
                                         minor(st.st_rdev), (unsigned)st.st_uid, (unsigned)st.st_gid);
                            else if (pi == 1 && lstat(e, &st) == 0 && !S_ISREG(st.st_mode))
                                snprintf(node, sizeof node, "existing replaced: %06o", (int)(st.st_mode & S_IFMT));
                            p("%s\t-> %s\tnode=%s\n", lead, en(sh->res[0][0]), node);
                        }
                        rmtree(dir);
                    }
}

// ---------------------------------------------------------------- REALEFF

typedef struct {
    const char *name;
    uid_t ruid, euid;
    gid_t rgid, egid;
} split;

static int become_split(const split *s) {
    if (geteuid() != 0) return EPERM;
    gid_t g[2] = {20, 701};
    if (setgroups(2, g) != 0) return errno;
    if (setregid(s->rgid, s->egid) != 0) return errno;
    if (s->ruid == s->euid) return setuid(s->ruid) == 0 ? 0 : errno;
    if (s->euid == 0) return setreuid(s->ruid, 0) == 0 ? 0 : errno;
    return seteuid(s->euid) == 0 ? 0 : errno;
}

static void realeff_section(void) {
    p("# REALEFF <ruid/euid rgid/egid> <inode> <call> -> <errno>. Every inode is 504:7777 except\n");
    p("# those named 504:20; groups are 20,701. access(2) is asked as itself and as\n");
    p("# faccessat(AT_EACCESS).\n");
    const split splits[] = {
        {"r0/e502 rg20/eg20", 0, 502, 20, 20},
        {"r502/e0 rg20/eg20", 502, 0, 20, 20},
        {"r502/e502 rg7777/eg20", 502, 502, G_OUT, 20},
        {"r502/e502 rg20/eg7777", 502, 502, 20, G_OUT},
    };
    struct {
        int is_dir;
        gid_t g;
        int mode;
    } inodes[] = {
        {0, G_OUT, 0000}, {0, G_OUT, 0400}, {0, G_OUT, 0200}, {0, G_OUT, 0100}, {0, G_OUT, 0040}, {0, G_OUT, 0020}, {0, G_OUT, 0010},
        {0, G_OUT, 0004}, {0, G_OUT, 0002}, {0, G_OUT, 0001}, {0, G_OUT, 0644}, {0, G_OUT, 0755}, {0, 20, 0040},   {0, 20, 0010},
        {1, G_OUT, 0000}, {1, G_OUT, 0100}, {1, G_OUT, 0010}, {1, G_OUT, 0001},
    };
    struct {
        const char *name;
        int amode, flags, oflags;
    } calls[] = {
        {"access(R_OK)", R_OK, 0, -1},     {"access(W_OK)", W_OK, 0, -1},         {"access(X_OK)", X_OK, 0, -1},
        {"eaccess(R_OK)", R_OK, AT_EACCESS, -1}, {"eaccess(W_OK)", W_OK, AT_EACCESS, -1}, {"eaccess(X_OK)", X_OK, AT_EACCESS, -1},
        {"open(O_RDONLY)", 0, 0, O_RDONLY}, {"open(O_WRONLY)", 0, 0, O_WRONLY},
    };
    const int ncalls = (int)(sizeof calls / sizeof calls[0]);
    char dir[PATH_MAX];
    if (fresh_dir(dir, sizeof dir, "re", 0, 0, 0755) != 0) die("re dir");
    int setup_err = 0;
    for (size_t i = 0; i < sizeof inodes / sizeof inodes[0]; i++) {
        char q[PATH_MAX];
        snprintf(q, sizeof q, "%s/%zu", dir, i);
        if (inodes[i].is_dir) {
            if (mkdir(q, 0700) != 0) die("re mkdir");
        } else if (make_file(q, 0600) != 0)
            die("re file");
        int r = own(q, 0, 504, inodes[i].g, inodes[i].mode);
        if (r != 0) setup_err = r;
    }
    for (size_t si = 0; si < sizeof splits / sizeof splits[0]; si++) {
        if (setup_err != 0) {
            if (geteuid() == 0) failures++;
            p("REALEFF\t%s\tSKIP: the inodes need root: %s\n", splits[si].name, en(setup_err));
            continue;
        }
        memset(sh, 0, sizeof *sh);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            enter(dir);
            sh->become_err = become_split(&splits[si]);
            sh->uid = getuid();
            sh->euid = geteuid();
            sh->gid = getgid();
            sh->egid = getegid();
            if (sh->become_err != 0) _exit(geteuid() == 0 ? 1 : 0);
            for (size_t i = 0; i < sizeof inodes / sizeof inodes[0]; i++) {
                char q[32];
                snprintf(q, sizeof q, "%zu", i);
                for (int k = 0; k < ncalls; k++) {
                    int r;
                    if (calls[k].oflags >= 0) {
                        int fd = open(q, calls[k].oflags);
                        r = fd >= 0 ? 0 : errno;
                        if (fd >= 0) close(fd);
                    } else
                        r = faccessat(AT_FDCWD, q, calls[k].amode, calls[k].flags) == 0 ? 0 : errno;
                    sh->res[k][i] = r;
                }
            }
            _exit(0);
        }
        wait_child(pid, __func__);
        if (sh->become_err != 0) {
            if (geteuid() == 0) failures++;
            p("REALEFF\t%s\t%s: %s\n", splits[si].name, geteuid() == 0 ? "CHILD-FAILED" : "SKIP", en(sh->become_err));
            continue;
        }
        p("REALEFF\t%s\tthe caller holds uid=%u euid=%u gid=%u egid=%u\n", splits[si].name, (unsigned)sh->uid, (unsigned)sh->euid, (unsigned)sh->gid,
          (unsigned)sh->egid);
        for (size_t i = 0; i < sizeof inodes / sizeof inodes[0]; i++)
            for (int k = 0; k < ncalls; k++)
                p("REALEFF\t%s\t%s 504:%u %04o\t%s\t-> %s\n", splits[si].name, inodes[i].is_dir ? "dir" : "file", (unsigned)inodes[i].g, inodes[i].mode, calls[k].name,
                  en(sh->res[k][i]));
    }
    rmtree(dir);
}

// ---------------------------------------------------------------- CTIME

static void ctime_row(const cred *c, uid_t ou, gid_t og, int mode, const char *what, uid_t ru, gid_t rg, int chmod_to) {
    char dir[PATH_MAX], f[PATH_MAX];
    if (fresh_dir(dir, sizeof dir, "ct", 0, 0, 0755) != 0) die("ct dir");
    snprintf(f, sizeof f, "%s/f", dir);
    if (make_file(f, 0600) != 0) die("ct file");
    int r = own(f, 0, ou, og, mode);
    if (r != 0) {
        if (geteuid() == 0) failures++;
        p("CTIME\t%s\tfile %u:%u %04o\t%s\tSKIP: the file needs root: %s\n", c->name, (unsigned)ou, (unsigned)og, mode, what, en(r));
        rmtree(dir);
        return;
    }
    struct stat b, a;
    if (lstat(f, &b) != 0) die("ct lstat");
    sleep_ms(20);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        enter(dir);
        int e = become(c);
        if (e != 0) {
            sh->become_err = e;
            _exit(geteuid() == 0 ? 1 : 0);
        }
        sh->become_err = 0;
        int rr = chmod_to >= 0 ? chmod("f", chmod_to) : chown("f", ru, rg);
        sh->res[0][0] = rr == 0 ? 0 : errno;
        _exit(0);
    }
    wait_child(pid, __func__);
    if (sh->become_err != 0) {
        p("CTIME\t%s\tfile %u:%u %04o\t%s\tSKIP: becoming %s: %s\n", c->name, (unsigned)ou, (unsigned)og, mode, what, c->name, en(sh->become_err));
    } else {
        if (lstat(f, &a) != 0) die("ct lstat after");
        int moved = a.st_ctimespec.tv_sec != b.st_ctimespec.tv_sec || a.st_ctimespec.tv_nsec != b.st_ctimespec.tv_nsec;
        p("CTIME\t%s\tfile %u:%u %04o\t%s\t-> %s\tafter=%04o %u:%u ctime=%s\n", c->name, (unsigned)ou, (unsigned)og, mode, what, en(sh->res[0][0]),
          (int)(a.st_mode & 07777), (unsigned)a.st_uid, (unsigned)a.st_gid, moved ? "moved" : "same");
    }
    rmtree(dir);
}

static void ctime_section(void) {
    p("# CTIME <caller> <file> <call> -> <errno> after=<mode owner:group> ctime=<moved|same>\n");
    const int modes[] = {0644, 04755, 02755, 02745, 06755};
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) {
        int m = modes[i];
        ctime_row(&ROOT, 502, G_OUT, m, "chown(-1,-1)", (uid_t)-1, (gid_t)-1, -1);
        ctime_row(&ROOT, 502, G_OUT, m, "chown(502,7777)", 502, G_OUT, -1);
        ctime_row(&ROOT, 502, G_OUT, m, "chown(504,-1)", 504, (gid_t)-1, -1);
        ctime_row(&ROOT, 0, 0, m, "chown(-1,-1)", (uid_t)-1, (gid_t)-1, -1);
        ctime_row(&ROOT, 0, 0, m, "chown(0,0)", 0, 0, -1);
        char what[32];
        snprintf(what, sizeof what, "chmod(%04o)", m);
        ctime_row(&ROOT, 502, G_OUT, m, what, 0, 0, m);
        ctime_row(&U501, 502, 20, m, "chown(-1,-1)", (uid_t)-1, (gid_t)-1, -1);
        ctime_row(&U501, 502, G_OUT, m, "chown(-1,-1)", (uid_t)-1, (gid_t)-1, -1);
        ctime_row(&U501, 501, G_OUT, m, "chown(-1,-1)", (uid_t)-1, (gid_t)-1, -1);
        ctime_row(&U501, 501, G_OUT, m, "chown(501,-1)", 501, (gid_t)-1, -1);
        ctime_row(&U501, 501, G_OUT, m, "chown(-1,7777)", (uid_t)-1, G_OUT, -1);
    }
}

// ---------------------------------------------------------------- main

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fresh base directory> [SECTION...]\n", argv[0]);
        return 2;
    }
    snprintf(base, sizeof base, "%s", argv[1]);
    nsections = argc - 2;
    sections = argv + 2;
    // As root, the base is given to root and made 0700: no other user may
    // then change its entries or reach anything under it by path; the
    // probe's own children reach their directories by entering them first
    // (see `enter`).
    int bfd = open(base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (bfd < 0) die("base directory");
    if (geteuid() == 0 && (fchown(bfd, 0, 0) != 0 || fchmod(bfd, 0700) != 0)) die("base directory to root, 0700");
    struct stat bs;
    if (fstat(bfd, &bs) != 0) die("base directory");
    close(bfd);
    sh = mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if (sh == MAP_FAILED) die("mmap");
    umask(022);

    struct utsname u;
    uname(&u);
    char product[64] = "?";
    size_t plen = sizeof product;
    sysctlbyname("kern.osproductversion", product, &plen, NULL, 0);
    char g[512];
    groups_text(g, sizeof g);
    p("# root-files: %s %s %s (macOS %s)\tuid=%u euid=%u gid=%u egid=%u groups=%s\n", u.sysname, u.release, u.machine, product, (unsigned)getuid(), (unsigned)geteuid(),
      (unsigned)getgid(), (unsigned)getegid(), g);
    p("# base=%s (owner %u:%u mode %04o)\n", base, (unsigned)bs.st_uid, (unsigned)bs.st_gid, (int)(bs.st_mode & 07777));
    if (geteuid() != 0) p("# NOT ROOT: every row that needs root prints SKIP.\n");

    if (wanted("CRED")) cred_section();
    if (wanted("ACCESS")) access_section();
    if (wanted("CHMOD")) chmod_section();
    if (wanted("CHOWN")) chown_section();
    if (wanted("SETID")) setid_section();
    if (wanted("CLONE")) clone_section();
    if (wanted("UTIMENS")) utimens_section();
    if (wanted("STICKY")) sticky_section();
    if (wanted("MKNOD")) mknod_section();
    if (wanted("REALEFF")) realeff_section();
    if (wanted("CTIME")) ctime_section();
    if (failures) p("FAILURES\t%d child processes failed: see the CHILD-FAILED rows\n", failures);
    p("DONE\n");
    return failures ? 1 : 0;
}
