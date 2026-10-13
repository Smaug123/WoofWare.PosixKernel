// Ownership and credentials probe, for the WoofWare.PosixKernel ownership options document.
//
// Usage: ownership-probe <base-dir> [<wheel-dir>]
//   Linux: run as root (with every capability for the protected_* section);
//          the probe forks children with chosen credentials.
//   Darwin: run as an ordinary user; only the caller's own credentials are available.
//          <wheel-dir> is a directory whose group the caller is NOT a member of
//          (on macOS, any fresh directory directly under /private/tmp is group wheel).
//
// Every row prints what the kernel did; sweeps print a mismatch count against a
// stated rule plus the first few mismatches, so a zero is a claim, not a silence.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static char base[PATH_MAX];
static char wheel[PATH_MAX];

static const char *en(int e) {
    switch (e) {
    case 0: return "ok";
    case EPERM: return "EPERM";
    case EACCES: return "EACCES";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case EINVAL: return "EINVAL";
    case EISDIR: return "EISDIR";
    case ENOTDIR: return "ENOTDIR";
    case EROFS: return "EROFS";
    case ENOTEMPTY: return "ENOTEMPTY";
    case EBUSY: return "EBUSY";
#ifdef EFTYPE
    case EFTYPE: return "EFTYPE";
#endif
    default: {
        static char buf[32];
        snprintf(buf, sizeof buf, "errno%d", e);
        return buf;
    }
    }
}

#define R(call) ((call) == 0 ? 0 : errno)

static void die(const char *what) {
    fprintf(stderr, "FATAL %s: %s\n", what, strerror(errno));
    exit(2);
}

static void p(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void p(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    fflush(stdout);
}

static void path(char *out, const char *dir, const char *name) { snprintf(out, PATH_MAX, "%s/%s", dir, name); }

static void rmrf(const char *pth) {
    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", pth);
    if (system(cmd) != 0) { /* best effort */ }
}

static void describe(const char *pth, char *out, size_t n) {
    struct stat st;
    if (lstat(pth, &st) != 0) { snprintf(out, n, "stat:%s", en(errno)); return; }
    snprintf(out, n, "uid=%u gid=%u mode=%04o", (unsigned)st.st_uid, (unsigned)st.st_gid, (unsigned)(st.st_mode & 07777));
}

// ---------------------------------------------------------------- credentials

typedef struct {
    const char *name;
    uid_t ruid, euid;
    gid_t rgid, egid;
    int ng;
    gid_t g[4];
} cred;

static int am_root;

static void become(const cred *c) {
#ifdef __linux__
    if (!am_root) return;
    if (setgroups(c->ng, c->g) != 0) die("setgroups");
    if (setresgid(c->rgid, c->egid, c->egid) != 0) die("setresgid");
    if (setresuid(c->ruid, c->euid, c->euid) != 0) die("setresuid");
#else
    (void)c;
#endif
}

// Run fn as c in a child; returns the int the child wrote.
static int as(const cred *c, int (*fn)(void *), void *arg) {
    int fds[2];
    if (pipe(fds) != 0) die("pipe");
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        alarm(20);
        close(fds[0]);
        become(c);
        int v = fn(arg);
        if (write(fds[1], &v, sizeof v) != sizeof v) _exit(3);
        fflush(stdout);
        _exit(0);
    }
    close(fds[1]);
    int v = -12345;
    ssize_t got = read(fds[0], &v, sizeof v);
    close(fds[0]);
    int status;
    waitpid(pid, &status, 0);
    if (got != sizeof v || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        p("CHILD-FAILED\t%s\tstatus=%d\n", c->name, status);
        return -99999;
    }
    return v;
}

#ifdef __linux__
static const cred ROOT = {"root", 0, 0, 0, 0, 1, {0}};
static const cred U1000 = {"u1000(g1000;groups 1000,2000)", 1000, 1000, 1000, 1000, 2, {1000, 2000}};
static const cred U1001 = {"u1001(g1001;groups 1001,2000)", 1001, 1001, 1001, 1001, 2, {1001, 2000}};
static const cred UEFF = {"r1000/e1001(rg1000/eg1001;groups 1000)", 1000, 1001, 1000, 1001, 1, {1000}};
#endif

// ---------------------------------------------------------------- sweep of the permission classes

typedef struct {
    const char *pth;
    int isdir;
} target;

static int outcome(void *arg) {
    const target *t = arg;
    int m = 0;
    if (!t->isdir) {
        int fd = open(t->pth, O_RDONLY);
        if (fd >= 0) { m |= 1; close(fd); }
        fd = open(t->pth, O_WRONLY);
        if (fd >= 0) { m |= 2; close(fd); }
        if (access(t->pth, R_OK) == 0) m |= 4;
        if (access(t->pth, W_OK) == 0) m |= 8;
        if (access(t->pth, X_OK) == 0) m |= 16;
    } else {
        char nx[PATH_MAX], c[PATH_MAX];
        struct stat st;
        path(nx, t->pth, "nx");
        path(c, t->pth, "c");
        if (stat(nx, &st) != 0 && errno == ENOENT) m |= 1;
        DIR *d = opendir(t->pth);
        if (d) { m |= 2; closedir(d); }
        if (mkdir(c, 0700) == 0) { m |= 4; rmdir(c); }
        if (access(t->pth, R_OK) == 0) m |= 8;
        if (access(t->pth, W_OK) == 0) m |= 16;
        if (access(t->pth, X_OK) == 0) m |= 32;
    }
    return m;
}

// relation: 0 owner, 1 group, 2 other, 3 root
static int predict(int relation, int isdir, int mode) {
    if (relation == 3) {
        if (!isdir) return 1 | 2 | 4 | 8 | ((mode & 0111) ? 16 : 0);
        return 1 | 2 | 4 | 8 | 16 | 32;
    }
    int bits = relation == 0 ? (mode >> 6) & 7 : relation == 1 ? (mode >> 3) & 7 : mode & 7;
    int r = bits & 4, w = bits & 2, x = bits & 1;
    if (!isdir) return (r ? 1 : 0) | (w ? 2 : 0) | (r ? 4 : 0) | (w ? 8 : 0) | (x ? 16 : 0);
    return (x ? 1 : 0) | (r ? 2 : 0) | ((w && x) ? 4 : 0) | (r ? 8 : 0) | (w ? 16 : 0) | (x ? 32 : 0);
}

static void sweep(const char *label, const cred *c, int relation, uid_t ouid, gid_t ogid) {
    for (int isdir = 0; isdir <= 1; isdir++) {
        char t[PATH_MAX];
        path(t, base, isdir ? "sweep_d" : "sweep_f");
        rmrf(t);
        if (isdir) { if (mkdir(t, 0700) != 0) die("mkdir sweep"); }
        else { int fd = open(t, O_CREAT | O_WRONLY, 0600); if (fd < 0) die("create sweep"); close(fd); }
#ifdef __linux__
        if (am_root && chown(t, ouid, ogid) != 0) die("chown sweep");
#else
        (void)ouid; (void)ogid;
#endif
        int mismatches = 0;
        for (int mode = 0; mode <= 0777; mode++) {
            if (chmod(t, mode) != 0) die("chmod sweep");
            target tg = {t, isdir};
            int got = as(c, outcome, &tg);
            int want = predict(relation, isdir, mode);
            if (got != want) {
                if (mismatches < 8) p("SWEEP-MISMATCH\t%s\t%s\tmode=%03o\tgot=%#x\twant=%#x\n", label, isdir ? "dir" : "file", mode, got, want);
                mismatches++;
            }
        }
        chmod(t, 0700);
        p("SWEEP\t%s\t%s\tmodes=512\tmismatches=%d\n", label, isdir ? "dir" : "file", mismatches);
        rmrf(t);
    }
}

// ---------------------------------------------------------------- creation ownership

typedef struct {
    const char *dir;
} dirarg;

static int create_in(void *arg) {
    const dirarg *d = arg;
    umask(0);
    struct { const char *name; int kind; int mode; } rows[] = {
        {"open0666", 0, 0666}, {"open02775", 0, 02775}, {"open02765", 0, 02765}, {"open06775", 0, 06775},
        {"mkdir0777", 1, 0777}, {"mkdir02777", 1, 02777}, {"mkfifo0666", 2, 0666}, {"mkfifo02775", 2, 02775},
    };
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        char t[PATH_MAX];
        path(t, d->dir, rows[i].name);
        int e;
        if (rows[i].kind == 0) { int fd = open(t, O_CREAT | O_EXCL | O_WRONLY, rows[i].mode); e = fd < 0 ? errno : 0; if (fd >= 0) close(fd); }
        else if (rows[i].kind == 1) e = R(mkdir(t, rows[i].mode));
        else e = R(mkfifo(t, rows[i].mode));
        char desc[128];
        describe(t, desc, sizeof desc);
        p("CREATE\t%s\t%s\t%s\t%s\n", d->dir, rows[i].name, en(e), desc);
    }
    return 0;
}

static void creation_linux(void) {
#ifdef __linux__
    struct { const char *name; gid_t gid; int mode; } parents[] = {
        {"pA_g2000_0777", 2000, 0777}, {"pB_g2000_02777", 2000, 02777},
        {"pC_g3000_02777", 3000, 02777}, {"pD_g3000_0777", 3000, 0777},
    };
    const cred *callers[] = {&U1000, &UEFF, &ROOT};
    for (size_t c = 0; c < 3; c++) {
        for (size_t i = 0; i < 4; i++) {
            char d[PATH_MAX];
            char nm[PATH_MAX];
            snprintf(nm, sizeof nm, "%s_by%zu", parents[i].name, c);
            path(d, base, nm);
            rmrf(d);
            if (mkdir(d, 0700) != 0) die("mkdir parent");
            if (chown(d, 0, parents[i].gid) != 0) die("chown parent");
            if (chmod(d, parents[i].mode) != 0) die("chmod parent");
            char desc[128];
            describe(d, desc, sizeof desc);
            p("PARENT\t%s\tcaller=%s\t%s\n", nm, callers[c]->name, desc);
            dirarg a = {d};
            as(callers[c], create_in, &a);
        }
    }
#endif
}

static void creation_darwin(void) {
#ifndef __linux__
    // pA: group = egid; pB: group = a supplementary group; pC: supplementary + setgid;
    // pW: group wheel, of which the caller is not a member.
    struct { const char *name; const char *in; gid_t gid; int mode; } parents[] = {
        {"pA_egid_0777", base, (gid_t)-2, 0777},
        {"pB_supp12_0777", base, 12, 0777},
        {"pC_supp12_02777", base, 12, 02777},
        {"pW_wheel_0777", wheel, (gid_t)-1, 0777},
        {"pW_wheel_02777", wheel, (gid_t)-1, 02777},
    };
    for (size_t i = 0; i < sizeof parents / sizeof parents[0]; i++) {
        char d[PATH_MAX];
        path(d, parents[i].in, parents[i].name);
        rmrf(d);
        if (mkdir(d, 0700) != 0) die("mkdir parent");
        gid_t g = parents[i].gid == (gid_t)-2 ? getegid() : parents[i].gid;
        int ce = 0;
        if (g != (gid_t)-1) ce = R(chown(d, (uid_t)-1, g));
        int me = R(chmod(d, parents[i].mode));
        char desc[128];
        describe(d, desc, sizeof desc);
        p("PARENT\t%s\tchown=%s chmod=%s\t%s\n", parents[i].name, en(ce), en(me), desc);
        dirarg a = {d};
        create_in(&a);
    }
#endif
}

// ---------------------------------------------------------------- chown

typedef struct {
    const char *pth;
    uid_t u;
    gid_t g;
} chownarg;

static int do_chown(void *arg) {
    const chownarg *a = arg;
    return R(chown(a->pth, a->u, a->g));
}

static void chown_row(const char *label, const cred *c, int isdir, uid_t ou, gid_t og, int mode, uid_t u, gid_t g) {
    char t[PATH_MAX];
    path(t, base, "chown_t");
    rmrf(t);
    if (isdir) { if (mkdir(t, 0700) != 0) die("mkdir chown"); }
    else { int fd = open(t, O_CREAT | O_WRONLY, 0600); if (fd < 0) die("create chown"); close(fd); }
#ifdef __linux__
    if (am_root && chown(t, ou, og) != 0) die("chown setup");
#else
    (void)ou;
    if (og != (gid_t)-1 && chown(t, (uid_t)-1, og) != 0) die("chgrp setup");
#endif
    if (chmod(t, mode) != 0) die("chmod setup");
    char before[128], after[128];
    describe(t, before, sizeof before);
    chownarg a = {t, u, g};
    int e = c ? as(c, do_chown, &a) : do_chown(&a);
    describe(t, after, sizeof after);
    p("CHOWN\t%s\t%s\tchown(%d,%d)\t%s\tbefore[%s]\tafter[%s]\n", label, isdir ? "dir" : "file", (int)u, (int)g, en(e), before, after);
    rmrf(t);
}

static void chowns(void) {
#ifdef __linux__
    int modes[] = {06755, 06745};
    for (int isdir = 0; isdir <= 1; isdir++)
        for (int mi = 0; mi < 2; mi++) {
            int m = modes[mi];
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, -1, -1);
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, 1000, -1);
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, -1, 1000);
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, -1, 2000);
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, -1, 3000);
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, 1001, -1);
            chown_row("owner u1000", &U1000, isdir, 1000, 1000, m, 1000, 2000);
            chown_row("nonowner u1001", &U1001, isdir, 1000, 1000, m, -1, -1);
            chown_row("nonowner u1001", &U1001, isdir, 1000, 1000, m, -1, 2000);
            chown_row("nonowner u1001", &U1001, isdir, 1000, 1000, m, 1001, -1);
            chown_row("root", &ROOT, isdir, 1000, 1000, m, -1, -1);
            chown_row("root", &ROOT, isdir, 1000, 1000, m, 1001, -1);
            chown_row("root", &ROOT, isdir, 1000, 1000, m, -1, 3000);
            chown_row("root", &ROOT, isdir, 1000, 1000, m, 1000, 1000);
        }
#else
    uid_t me = getuid();
    gid_t eg = getegid();
    int modes[] = {06755, 06745};
    for (int isdir = 0; isdir <= 1; isdir++)
        for (int mi = 0; mi < 2; mi++) {
            int m = modes[mi];
            chown_row("owner", NULL, isdir, me, eg, m, -1, -1);
            chown_row("owner", NULL, isdir, me, eg, m, me, -1);
            chown_row("owner", NULL, isdir, me, eg, m, -1, eg);
            chown_row("owner", NULL, isdir, me, eg, m, -1, 12);
            chown_row("owner", NULL, isdir, me, eg, m, -1, 0);
            chown_row("owner", NULL, isdir, me, eg, m, 0, -1);
            chown_row("owner", NULL, isdir, me, eg, m, me, 12);
        }
    // Non-owner, on a root-owned file with no special bits. Harmless even if it succeeded.
    const char *nonowned[] = {"/etc/hosts"};
    for (size_t i = 0; i < 1; i++) {
        char before[128], after[128];
        describe(nonowned[i], before, sizeof before);
        int e1 = R(chown(nonowned[i], (uid_t)-1, (gid_t)-1));
        int e2 = R(chown(nonowned[i], (uid_t)-1, eg));
        describe(nonowned[i], after, sizeof after);
        p("CHOWN\tnonowner\t%s\tchown(-1,-1)=%s\tchown(-1,egid)=%s\tbefore[%s]\tafter[%s]\n", nonowned[i], en(e1), en(e2), before, after);
    }
#endif
}

// ---------------------------------------------------------------- chmod

typedef struct {
    const char *pth;
    int mode;
} chmodarg;

static int do_chmod(void *arg) {
    const chmodarg *a = arg;
    return R(chmod(a->pth, a->mode));
}

static void chmod_row(const char *label, const cred *c, const char *in, int isdir, uid_t ou, gid_t og, int mode) {
    char t[PATH_MAX];
    path(t, in, "chmod_t");
    rmrf(t);
    if (isdir) { if (mkdir(t, 0700) != 0) die("mkdir chmod"); }
    else { int fd = open(t, O_CREAT | O_WRONLY, 0600); if (fd < 0) die("create chmod"); close(fd); }
#ifdef __linux__
    if (am_root && chown(t, ou, og) != 0) die("chown chmod");
#else
    (void)ou;
    if (og != (gid_t)-1 && chown(t, (uid_t)-1, og) != 0) die("chgrp chmod");
#endif
    char before[128], after[128];
    describe(t, before, sizeof before);
    chmodarg a = {t, mode};
    int e = c ? as(c, do_chmod, &a) : do_chmod(&a);
    describe(t, after, sizeof after);
    p("CHMOD\t%s\t%s\tchmod(%04o)\t%s\tbefore[%s]\tafter[%s]\n", label, isdir ? "dir" : "file", mode, en(e), before, after);
    rmrf(t);
}

static void chmods(void) {
    int modes[] = {02755, 02745, 06755, 04755, 01644, 01755};
    for (int isdir = 0; isdir <= 1; isdir++)
        for (size_t mi = 0; mi < sizeof modes / sizeof modes[0]; mi++) {
            int m = modes[mi];
#ifdef __linux__
            chmod_row("owner u1000, file group = egid", &U1000, base, isdir, 1000, 1000, m);
            chmod_row("owner u1000, file group = supplementary", &U1000, base, isdir, 1000, 2000, m);
            chmod_row("owner u1000, file group not a member", &U1000, base, isdir, 1000, 3000, m);
            chmod_row("nonowner u1001", &U1001, base, isdir, 1000, 1000, m);
            chmod_row("root, file group not root's", &ROOT, base, isdir, 1000, 3000, m);
#else
            chmod_row("owner, file group = egid", NULL, base, isdir, 0, getegid(), m);
            chmod_row("owner, file group = supplementary 12", NULL, base, isdir, 0, 12, m);
            chmod_row("owner, file group wheel (not a member)", NULL, wheel, isdir, 0, (gid_t)-1, m);
#endif
        }
#ifndef __linux__
    {
        struct stat st;
        stat("/etc/hosts", &st);
        int e = R(chmod("/etc/hosts", st.st_mode & 07777));
        p("CHMOD\tnonowner\t/etc/hosts\tchmod(current mode %04o)\t%s\n", (unsigned)(st.st_mode & 07777), en(e));
    }
#endif
}

// ---------------------------------------------------------------- umask

static void umasks(void) {
    mode_t u0 = umask(0);
    p("UMASK\tinherited\t%04o\n", (unsigned)u0);
    unsigned tries[] = {07777, 0177777, 0xffffffffu, 01022, 04000};
    for (size_t i = 0; i < sizeof tries / sizeof tries[0]; i++) {
        umask((mode_t)tries[i]);
        mode_t back = umask(0);
        p("UMASK\tset %#x\treads back %04o\n", tries[i], (unsigned)back);
    }
    // Derive each syscall's own mask at umask 0, then check mode & M & ~u for every u.
    const char *names[] = {"open", "mkdir", "mkfifo"};
    int modes[] = {07777, 0777, 0666, 02775, 04775, 01777};
    char d[PATH_MAX];
    path(d, base, "umask_d");
    for (int s = 0; s < 3; s++) {
        int M = -1;
        long mismatches = 0, rows = 0;
        unsigned umasks_to_try[513];
        int nu = 0;
        for (unsigned u = 0; u <= 0777; u++) umasks_to_try[nu++] = u;
        umasks_to_try[nu++] = 07777;
        for (int k = 0; k < nu; k++) {
            unsigned u = umasks_to_try[k];
            for (size_t mi = 0; mi < sizeof modes / sizeof modes[0]; mi++) {
                rmrf(d);
                if (mkdir(d, 0777) != 0) die("mkdir umask");
                chmod(d, 0777);
                char t[PATH_MAX];
                path(t, d, "x");
                umask(u);
                int e;
                if (s == 0) { int fd = open(t, O_CREAT | O_EXCL | O_WRONLY, modes[mi]); e = fd < 0 ? errno : 0; if (fd >= 0) close(fd); }
                else if (s == 1) e = R(mkdir(t, modes[mi]));
                else e = R(mkfifo(t, modes[mi]));
                umask(0);
                struct stat st;
                if (e != 0 || lstat(t, &st) != 0) { p("UMASK-FAIL\t%s\tu=%04o\tmode=%04o\t%s\n", names[s], u, modes[mi], en(e)); continue; }
                int got = st.st_mode & 07777;
                if (u == 0 && modes[mi] == 07777) { M = got; p("UMASK-MASK\t%s\tmode 07777 at umask 0 gives %04o\n", names[s], got); }
                if (M < 0) continue;
                int want = modes[mi] & M & ~(int)(u & 0777);
                rows++;
                if (got != want) {
                    if (mismatches < 8) p("UMASK-MISMATCH\t%s\tu=%04o\tmode=%04o\tgot=%04o\twant=%04o\n", names[s], u, modes[mi], got, want);
                    mismatches++;
                }
            }
        }
        p("UMASK-SWEEP\t%s\trows=%ld\tmismatches=%ld\trule: mode & %04o & ~(umask & 0777)\n", names[s], rows, mismatches, M);
    }
    rmrf(d);
    umask(u0);
}

// ---------------------------------------------------------------- access: real versus effective ids

static int acc_rows(void *arg) {
    const char *t = arg;
    int a = R(access(t, R_OK));
#ifdef AT_EACCESS
    int b = R(faccessat(AT_FDCWD, t, R_OK, AT_EACCESS));
#else
    int b = -1;
#endif
    int fd = open(t, O_RDONLY);
    int c = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd);
    p("ACCESS\t%s\truid=%u euid=%u rgid=%u egid=%u\taccess(R_OK)=%s\tfaccessat(AT_EACCESS,R_OK)=%s\topen(O_RDONLY)=%s\n", t,
      (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(), (unsigned)getegid(), en(a), b < 0 ? "n/a" : en(b), en(c));
    return 0;
}

static int acc_x(void *arg) {
    const char *t = arg;
    int a = R(access(t, X_OK));
    p("ACCESS-X\t%s\truid=%u euid=%u\taccess(X_OK)=%s\n", t, (unsigned)getuid(), (unsigned)geteuid(), en(a));
    return 0;
}

static void accesses(void) {
#ifdef __linux__
    char f1[PATH_MAX], f2[PATH_MAX];
    path(f1, base, "acc_root_0600");
    path(f2, base, "acc_u1001_g2000_0060");
    int fd = open(f1, O_CREAT | O_WRONLY, 0600); close(fd);
    chown(f1, 0, 0); chmod(f1, 0600);
    fd = open(f2, O_CREAT | O_WRONLY, 0600); close(fd);
    chown(f2, 1001, 2000); chmod(f2, 0060);
    cred c1 = {"r1000/e0", 1000, 0, 1000, 1000, 1, {1000}};
    cred c2 = {"r0/e1000", 0, 1000, 1000, 1000, 1, {1000}};
    cred c3 = {"rg2000/eg1000, no groups", 1000, 1000, 2000, 1000, 0, {0}};
    cred c4 = {"rg1000/eg2000, no groups", 1000, 1000, 1000, 2000, 0, {0}};
    cred c5 = {"g1000, groups {2000} only", 1000, 1000, 1000, 1000, 1, {2000}};
    as(&c1, acc_rows, f1);
    as(&c2, acc_rows, f1);
    as(&c3, acc_rows, f2);
    as(&c4, acc_rows, f2);
    as(&c5, acc_rows, f2);
    int xm[] = {0644, 0100, 0010, 0001, 0000};
    for (size_t i = 0; i < 5; i++) {
        char t[PATH_MAX];
        char nm[64];
        snprintf(nm, sizeof nm, "accx_file_%04o", xm[i]);
        path(t, base, nm);
        fd = open(t, O_CREAT | O_WRONLY, 0600); close(fd);
        chmod(t, xm[i]);
        as(&ROOT, acc_x, t);
        as(&c2, acc_x, t);
        as(&c1, acc_x, t);
    }
    char d[PATH_MAX];
    path(d, base, "accx_dir_0000");
    mkdir(d, 0);
    chmod(d, 0);
    as(&ROOT, acc_x, d);
    as(&c2, acc_x, d);
#endif
}

// ---------------------------------------------------------------- sticky directories

typedef struct {
    const char *dir;
    int op;
} stickyarg;

static const char *sticky_ops[] = {
    "unlink(f: other's file)", "unlink(g: caller's file)", "rename(f -> f2)", "rename(g -> f: replace other's)",
    "rmdir(sub: other's dir)", "rename(sub -> sub2)", "rename(g -> outside)",
};

static int sticky_do(void *arg) {
    const stickyarg *a = arg;
    char f[PATH_MAX], f2[PATH_MAX], g[PATH_MAX], sub[PATH_MAX], sub2[PATH_MAX], out[PATH_MAX];
    path(f, a->dir, "f");
    path(f2, a->dir, "f2");
    path(g, a->dir, "g");
    path(sub, a->dir, "sub");
    path(sub2, a->dir, "sub2");
    path(out, base, "sticky_out");
    switch (a->op) {
    case 0: return R(unlink(f));
    case 1: return R(unlink(g));
    case 2: return R(rename(f, f2));
    case 3: return R(rename(g, f));
    case 4: return R(rmdir(sub));
    case 5: return R(rename(sub, sub2));
    case 6: { int e = R(rename(g, out)); unlink(out); return e; }
    }
    return -1;
}

static void stickies(void) {
#ifdef __linux__
    struct { const char *name; uid_t u; int mode; } dirs[] = {
        {"S_root_01777", 0, 01777}, {"S_u1000_01777", 1000, 01777}, {"N_root_0777", 0, 0777},
    };
    const cred *callers[] = {&U1000, &U1001, &ROOT};
    for (size_t di = 0; di < 3; di++)
        for (size_t ci = 0; ci < 3; ci++)
            for (int op = 0; op < 7; op++) {
                char d[PATH_MAX];
                path(d, base, dirs[di].name);
                rmrf(d);
                mkdir(d, 0700);
                char f[PATH_MAX], g[PATH_MAX], sub[PATH_MAX];
                path(f, d, "f");
                path(g, d, "g");
                path(sub, d, "sub");
                int fd = open(f, O_CREAT | O_WRONLY, 0644); close(fd); chown(f, 1001, 1001);
                fd = open(g, O_CREAT | O_WRONLY, 0644); close(fd); chown(g, 1000, 1000);
                mkdir(sub, 0755); chown(sub, 1001, 1001);
                chown(d, dirs[di].u, 0);
                chmod(d, dirs[di].mode);
                stickyarg a = {d, op};
                int e = as(callers[ci], sticky_do, &a);
                p("STICKY\t%s\t%s\t%s\t%s\n", dirs[di].name, callers[ci]->name, sticky_ops[op], en(e));
                rmrf(d);
            }
#endif
}

// ---------------------------------------------------------------- Linux protected_* sysctls

static int write_sysctl(const char *name, const char *v) {
    char pth[128];
    snprintf(pth, sizeof pth, "/proc/sys/fs/%s", name);
    FILE *f = fopen(pth, "w");
    if (!f) return errno;
    int e = fputs(v, f) < 0 ? errno : 0;
    if (fclose(f) != 0 && e == 0) e = errno;
    return e;
}

typedef struct {
    const char *pth;
    int flags;
} openarg;

static int do_open(void *arg) {
    const openarg *a = arg;
    int fd = open(a->pth, a->flags, 0666);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

static void protecteds(void) {
#ifdef __linux__
    const char *settings[][2] = {{"0", "0"}, {"1", "1"}, {"1", "2"}};
    for (int s = 0; s < 3; s++) {
        int e1 = write_sysctl("protected_symlinks", settings[s][0]);
        int e2 = write_sysctl("protected_regular", settings[s][1]);
        if (e1 || e2) { p("PROTECTED\tcannot set sysctls (%s, %s); skipping\n", en(e1), en(e2)); return; }
        struct { const char *name; int mode; } dirs[] = {{"W_root_01777", 01777}, {"W_root_01775_g1000", 01775}};
        for (int di = 0; di < 2; di++) {
            char d[PATH_MAX], tgt[PATH_MAX], l[PATH_MAX], lr[PATH_MAX], lm[PATH_MAX], r[PATH_MAX];
            path(d, base, dirs[di].name);
            rmrf(d);
            mkdir(d, 0700);
            path(tgt, base, "prot_target");
            int fd = open(tgt, O_CREAT | O_WRONLY, 0644); close(fd); chmod(tgt, 0644);
            path(l, d, "link_by_1001");
            path(lr, d, "link_by_root");
            path(lm, d, "link_by_1000");
            path(r, d, "reg_by_1001");
            symlink(tgt, l); lchown(l, 1001, 1001);
            symlink(tgt, lr);
            symlink(tgt, lm); lchown(lm, 1000, 1000);
            fd = open(r, O_CREAT | O_WRONLY, 0666); close(fd); chown(r, 1001, 1001); chmod(r, 0666);
            chown(d, 0, 1000);
            chmod(d, dirs[di].mode);
            openarg rows[] = {{l, O_RDONLY}, {lr, O_RDONLY}, {lm, O_RDONLY}, {r, O_WRONLY}, {r, O_WRONLY | O_CREAT}};
            const char *rn[] = {"follow link owned by 1001", "follow link owned by root (dir owner)", "follow link owned by caller",
                                "open other's file O_WRONLY", "open other's file O_WRONLY|O_CREAT"};
            for (int i = 0; i < 5; i++) {
                int e = as(&U1000, do_open, &rows[i]);
                p("PROTECTED\tsymlinks=%s regular=%s\t%s\tu1000\t%s\t%s\n", settings[s][0], settings[s][1], dirs[di].name, rn[i], en(e));
            }
            rmrf(d);
        }
    }
    write_sysctl("protected_symlinks", "0");
    write_sysctl("protected_regular", "0");
#endif
}

// ---------------------------------------------------------------- writes and set-group-ID, by group membership

typedef struct {
    const char *pth;
    int trunc;
} writearg;

static int do_write(void *arg) {
    const writearg *a = arg;
    int fd = open(a->pth, O_WRONLY);
    if (fd < 0) return errno;
    int e = 0;
    if (a->trunc) e = R(ftruncate(fd, 0));
    else if (write(fd, "x", 1) != 1) e = errno;
    close(fd);
    return e;
}

static void writes(void) {
#ifdef __linux__
    struct { const char *label; uid_t u; gid_t g; int mode; const cred *c; } rows[] = {
        {"nonowner writer in file's group", 1001, 2000, 02666, &U1000},
        {"nonowner writer not in file's group", 1001, 3000, 02666, &U1000},
        {"nonowner writer not in group, g+x", 1001, 3000, 02676, &U1000},
        {"owner writer not in file's group", 1000, 3000, 02666, &U1000},
        {"owner writer in file's group", 1000, 1000, 02666, &U1000},
        {"nonowner writer, setuid", 1001, 3000, 04666, &U1000},
        {"root writer not in file's group", 1001, 3000, 02666, &ROOT},
    };
    for (int tr = 0; tr <= 1; tr++)
        for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
            char t[PATH_MAX];
            path(t, base, "w_t");
            rmrf(t);
            int fd = open(t, O_CREAT | O_WRONLY, 0600);
            if (write(fd, "abc", 3) != 3) die("write setup");
            close(fd);
            chown(t, rows[i].u, rows[i].g);
            chmod(t, rows[i].mode);
            char before[128], after[128];
            describe(t, before, sizeof before);
            writearg a = {t, tr};
            int e = as(rows[i].c, do_write, &a);
            describe(t, after, sizeof after);
            p("WRITE-SGID\t%s\t%s\t%s\tbefore[%s]\tafter[%s]\n", tr ? "ftruncate(0)" : "write(1 byte)", rows[i].label, en(e), before, after);
            rmrf(t);
        }
#endif
}

// ---------------------------------------------------------------- getgroups

static int groups_row(void *arg) {
    (void)arg;
    gid_t gs[256];
    int n0 = getgroups(0, NULL);
    int n = getgroups(256, gs);
    char buf[1024] = "";
    for (int i = 0; i < n; i++) { char one[16]; snprintf(one, sizeof one, "%s%u", i ? "," : "", (unsigned)gs[i]); strcat(buf, one); }
    int small = -2, smallerr = 0;
    if (n0 > 1) { gid_t one[1]; small = getgroups(1, one); smallerr = small < 0 ? errno : 0; }
    p("GETGROUPS\tegid=%u rgid=%u\tgetgroups(0)=%d\tlist=[%s]\tgetgroups(1) with more=%d %s\tNGROUPS_MAX=%ld\n", (unsigned)getegid(),
      (unsigned)getgid(), n0, buf, small, en(smallerr), sysconf(_SC_NGROUPS_MAX));
    return 0;
}

static void groups(void) {
#ifdef __linux__
    cred a = {"g1000, groups {2000}", 1000, 1000, 1000, 1000, 1, {2000}};
    cred b = {"g1000, groups {}", 1000, 1000, 1000, 1000, 0, {0}};
    cred c = {"g1000, groups {1000,2000}", 1000, 1000, 1000, 1000, 2, {1000, 2000}};
    as(&a, groups_row, NULL);
    as(&b, groups_row, NULL);
    as(&c, groups_row, NULL);
#else
    groups_row(NULL);
#endif
}

// ---------------------------------------------------------------- Darwin: rows on objects the caller does not own

static void system_rows(void) {
#ifndef __linux__
    const char *dirs[] = {"/private/var/db/searchparty", "/var/root", "/Library", "/private/var/db/com.apple.countryd"};
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        char desc[128], nx[PATH_MAX];
        describe(dirs[i], desc, sizeof desc);
        path(nx, dirs[i], "nx-ownership-probe");
        struct stat st;
        int s = R(stat(nx, &st));
        DIR *d = opendir(dirs[i]);
        int o = d ? 0 : errno;
        if (d) closedir(d);
        p("OTHERS\t%s\t%s\tstat(dir/nx)=%s\topendir=%s\taccess R=%s W=%s X=%s\n", dirs[i], desc, en(s), en(o), en(R(access(dirs[i], R_OK))),
          en(R(access(dirs[i], W_OK))), en(R(access(dirs[i], X_OK))));
    }
    // A directory whose owner is someone else and whose group is the caller's egid, mode 0700.
    const char *owneronly = getenv("OWNER_ONLY_DIR");
    if (owneronly) {
        char desc[128], nx[PATH_MAX];
        describe(owneronly, desc, sizeof desc);
        path(nx, owneronly, "nx-ownership-probe");
        struct stat st;
        p("OTHERS\t%s\t%s\tstat(dir/nx)=%s\taccess X=%s\n", owneronly, desc, en(R(stat(nx, &st))), en(R(access(owneronly, X_OK))));
    }
    const char *files[] = {"/etc/master.passwd", "/etc/hosts"};
    for (size_t i = 0; i < 2; i++) {
        char desc[128];
        describe(files[i], desc, sizeof desc);
        int fd = open(files[i], O_RDONLY);
        int r = fd < 0 ? errno : 0;
        if (fd >= 0) close(fd);
        fd = open(files[i], O_WRONLY);
        int w = fd < 0 ? errno : 0;
        if (fd >= 0) close(fd);
        p("OTHERS\t%s\t%s\topen R=%s W=%s\taccess R=%s W=%s\n", files[i], desc, en(r), en(w), en(R(access(files[i], R_OK))), en(R(access(files[i], W_OK))));
    }
    int e = R(mkdir("/Library/.ownership-probe-should-fail", 0755));
    if (e == 0) rmdir("/Library/.ownership-probe-should-fail");
    p("OTHERS\tmkdir(/Library/x)\t%s\n", en(e));
#endif
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <base-dir> [<wheel-dir>]\n", argv[0]); return 2; }
    alarm(900);
    snprintf(base, sizeof base, "%s", argv[1]);
    if (argc > 2) snprintf(wheel, sizeof wheel, "%s", argv[2]);
    am_root = geteuid() == 0;
    setvbuf(stdout, NULL, _IOLBF, 0);
    p("# ownership-probe: uid=%u euid=%u gid=%u egid=%u base=%s wheel=%s\n", (unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(),
      (unsigned)getegid(), base, wheel);
    groups();
    umasks();
#ifdef __linux__
    if (!am_root) { fprintf(stderr, "Linux runs need root\n"); return 2; }
    sweep("owner u1000 (file 1000:3000)", &U1000, 0, 1000, 3000);
    sweep("group-primary u1000 (file 1001:1000)", &U1000, 1, 1001, 1000);
    sweep("group-supplementary u1000 (file 1001:2000)", &U1000, 1, 1001, 2000);
    sweep("other u1000 (file 1001:3000)", &U1000, 2, 1001, 3000);
    sweep("root (file 1001:3000)", &ROOT, 3, 1001, 3000);
    creation_linux();
    accesses();
    stickies();
    writes();
    protecteds();
#else
    cred self = {"self", getuid(), geteuid(), getgid(), getegid(), 0, {0}};
    sweep("owner (own file)", &self, 0, 0, 0);
    creation_darwin();
    system_rows();
#endif
    chowns();
    chmods();
    p("# done\n");
    return 0;
}
