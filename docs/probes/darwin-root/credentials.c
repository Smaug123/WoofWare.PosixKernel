// What Darwin's setgroups(2) does for a privileged process: which lists it
// takes, what getgroups(2) and getegid(2) then report, what a later setgid(2)
// or setegid(2) does to that list, and which groups the kernel then counts the
// process as a member of when it checks a file's group bits.
//
// Darwin only. Run it as root, through run.sh beside this file:
//   sudo sh docs/probes/darwin-root/run.sh
// By hand: cc -Wall -Werror -o /tmp/credentials credentials.c && sudo /tmp/credentials "$(mktemp -d /private/tmp/creds.XXXXXX)"
// (it gives the base directory to root, mode 0711). It exits 1 if a child
// process failed, which a CHILD-FAILED row after the row it was making says.
// As an ordinary user every row needs root and prints SKIP (except INITIAL).
//
// Every row forks a child that starts as root with real, effective and saved
// IDs 0 and the groups sudo gave it.
//   SETGROUPS <list> -> <errno> groups=<getgroups> egid= rgid=
//     setgroups(size, list) and what the process then holds.
//   THEN <list> <step> -> <errno> groups= egid= rgid=
//     after that setgroups, one more step: setgid(9), setegid(9), or
//     setregid(9, 10).
//   MEMBER <list> -> member=<gid>:<ok|EACCES>...
//     after that setgroups, setuid(502), and then open(O_RDONLY) of a file
//     uid 504 owns, mode 0040, in each group: ok means the kernel counted the
//     process a member of that group. groups= is what getgroups reports then.
//   SPLIT <who> <list> -> <errno>
//     setgroups from a process whose real and effective uids differ.
//   INITGROUPS factotum 20 -> <errno> groups=
//     initgroups(3), which takes the list from the directory service.
#ifndef __APPLE__
#error "Darwin only: Linux's rows are setresid.c's, under docs/plans"
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static char base[PATH_MAX - 64];

static const char *en(int e) {
    static char b[32];
    switch (e) {
    case 0: return "ok";
    case EPERM: return "EPERM";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case EACCES: return "EACCES";
    default: snprintf(b, sizeof b, "errno%d", e); return b;
    }
}

static void groups_text(char *out, size_t n) {
    gid_t gs[64];
    int k = getgroups(64, gs);
    if (k < 0) {
        snprintf(out, n, "getgroups:%s", en(errno));
        return;
    }
    size_t used = (size_t)snprintf(out, n, "[");
    for (int i = 0; i < k && used < n; i++) used += (size_t)snprintf(out + used, n - used, "%s%u", i ? "," : "", (unsigned)gs[i]);
    if (used < n) snprintf(out + used, n - used, "]");
}

static void state_text(char *out, size_t n) {
    char g[512];
    groups_text(g, sizeof g);
    snprintf(out, n, "groups=%s egid=%u rgid=%u", g, (unsigned)getegid(), (unsigned)getgid());
}

typedef struct {
    const char *label;
    int size;
    gid_t g[20];
} list;

static const gid_t member_probe[] = {0, 5, 6, 9, 10, 20, 701, 3000, 3015, 3016, 7777};
// The file MEMBER opens first, which everyone may read: if that fails, the
// child cannot reach the files at all, and the row says nothing about groups.
#define CONTROL "control-0444"
#define NPROBE (sizeof member_probe / sizeof member_probe[0])

// How many child processes did not exit 0. Any makes the probe exit 1, so
// that its output is not taken for a complete measurement.
static int failures;

static void wait_child(pid_t pid) {
    int st = 0;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        failures++;
        printf("CHILD-FAILED\tstatus=0x%x\n", st);
        fflush(stdout);
    }
}

static void setgroups_rows(const list *l) {
    char s[640];
    // SETGROUPS
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(10);
        int e = setgroups(l->size, l->size ? l->g : NULL) == 0 ? 0 : errno;
        state_text(s, sizeof s);
        printf("SETGROUPS\t%s\t-> %s\t%s\n", l->label, en(e), s);
        fflush(stdout);
        _exit(0);
    }
    wait_child(pid);
    // THEN
    const char *steps[] = {"setgid(9)", "setegid(9)", "setregid(9,10)"};
    for (int k = 0; k < 3; k++) {
        fflush(stdout);
        pid = fork();
        if (pid == 0) {
            alarm(10);
            if (setgroups(l->size, l->size ? l->g : NULL) != 0) {
                printf("THEN\t%s\t%s\tSKIP: setgroups: %s\n", l->label, steps[k], en(errno));
                fflush(stdout);
                _exit(0); // the SETGROUPS row reports this refusal
            }
            int r = k == 0 ? setgid(9) : k == 1 ? setegid(9) : setregid(9, 10);
            int e = r == 0 ? 0 : errno;
            state_text(s, sizeof s);
            printf("THEN\t%s\t%s\t-> %s\t%s\n", l->label, steps[k], en(e), s);
            fflush(stdout);
            _exit(0);
        }
        wait_child(pid);
    }
    // MEMBER
    fflush(stdout);
    pid = fork();
    if (pid == 0) {
        alarm(10);
        if (setgroups(l->size, l->size ? l->g : NULL) != 0) {
            printf("MEMBER\t%s\tSKIP: setgroups: %s\n", l->label, en(errno));
            fflush(stdout);
            _exit(0); // the SETGROUPS row reports this refusal
        }
        if (setuid(502) != 0) {
            printf("MEMBER\t%s\tSKIP: setuid(502): %s\n", l->label, en(errno));
            fflush(stdout);
            _exit(1);
        }
        state_text(s, sizeof s);
        char c[PATH_MAX];
        snprintf(c, sizeof c, "%s/" CONTROL, base);
        int cfd = open(c, O_RDONLY);
        if (cfd < 0) {
            printf("MEMBER\t%s\tINVALID: the control file, mode 0444, cannot be opened: %s\n", l->label, en(errno));
            fflush(stdout);
            _exit(1);
        }
        close(cfd);
        printf("MEMBER\t%s\tuid=%u euid=%u %s\tcontrol=ok\t->", l->label, (unsigned)getuid(), (unsigned)geteuid(), s);
        for (size_t i = 0; i < NPROBE; i++) {
            char f[PATH_MAX];
            snprintf(f, sizeof f, "%s/g%u", base, (unsigned)member_probe[i]);
            int fd = open(f, O_RDONLY);
            printf(" member=%u:%s", (unsigned)member_probe[i], fd >= 0 ? "ok" : en(errno));
            if (fd >= 0) close(fd);
        }
        printf("\n");
        fflush(stdout);
        _exit(0);
    }
    wait_child(pid);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <fresh base directory>\n", argv[0]);
        return 2;
    }
    snprintf(base, sizeof base, "%s", argv[1]);
    struct utsname u;
    uname(&u);
    char product[64] = "?";
    size_t plen = sizeof product;
    sysctlbyname("kern.osproductversion", product, &plen, NULL, 0);
    char s[640];
    state_text(s, sizeof s);
    printf("# credentials: %s %s %s (macOS %s) NGROUPS_MAX=%ld\n", u.sysname, u.release, u.machine, product, sysconf(_SC_NGROUPS_MAX));
    printf("INITIAL\tuid=%u euid=%u %s\n", (unsigned)getuid(), (unsigned)geteuid(), s);
    fflush(stdout);
    if (geteuid() != 0) {
        printf("SKIP\tevery other row needs root\nDONE\n");
        return 0;
    }

    // The base is given to root and made 0711: no other user may change its
    // entries, and MEMBER's children (uid 502) can reach the files by name.
    int bfd = open(base, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (bfd < 0 || fchown(bfd, 0, 0) != 0 || fchmod(bfd, 0711) != 0) {
        perror("base directory to root, 0711");
        return 2;
    }
    close(bfd);
    {
        char c[PATH_MAX];
        snprintf(c, sizeof c, "%s/" CONTROL, base);
        int fd = open(c, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0 || fchown(fd, 504, 7777) != 0 || fchmod(fd, 0444) != 0) {
            perror("control file");
            return 2;
        }
        close(fd);
    }
    // The files MEMBER opens: uid 504's, mode 0040, one in each group probed.
    for (size_t i = 0; i < NPROBE; i++) {
        char f[PATH_MAX];
        snprintf(f, sizeof f, "%s/g%u", base, (unsigned)member_probe[i]);
        int fd = open(f, O_CREAT | O_EXCL | O_WRONLY, 0600);
        if (fd < 0 || fchown(fd, 504, member_probe[i]) != 0 || fchmod(fd, 0040) != 0) {
            perror("member file");
            return 2;
        }
        close(fd);
    }

    list lists[] = {
        {"size=0 NULL", 0, {0}},
        {"[0]", 1, {0}},
        {"[5]", 1, {5}},
        {"[5,6]", 2, {5, 6}},
        {"[6,5]", 2, {6, 5}},
        {"[20,701]", 2, {20, 701}},
        {"[701,20]", 2, {701, 20}},
        {"[7777]", 1, {7777}},
        {"[5,5,6]", 3, {5, 5, 6}},
        {"[6,0,5]", 3, {6, 0, 5}},
        {"[30,10,20]", 3, {30, 10, 20}},
        {"16 distinct [3000..3015]", 16, {0}},
        {"17 distinct [3000..3016]", 17, {0}},
    };
    for (size_t i = 0; i < sizeof lists / sizeof lists[0]; i++) {
        if (lists[i].size >= 16)
            for (int k = 0; k < lists[i].size; k++) lists[i].g[k] = (gid_t)(3000 + k);
        setgroups_rows(&lists[i]);
    }

    // SPLIT: setgroups from a process whose real and effective uids differ.
    struct {
        const char *who;
        uid_t r, e;
    } splits[] = {{"ruid=0 euid=502", 0, 502}, {"ruid=502 euid=0", 502, 0}};
    for (size_t i = 0; i < 2; i++) {
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            alarm(10);
            int r = splits[i].e == 0 ? setreuid(splits[i].r, 0) : seteuid(splits[i].e);
            if (r != 0) {
                printf("SPLIT\t%s\tSKIP: %s\n", splits[i].who, en(errno));
                fflush(stdout);
                _exit(1);
            }
            gid_t g[2] = {5, 6};
            int e = setgroups(2, g) == 0 ? 0 : errno;
            state_text(s, sizeof s);
            printf("SPLIT\t%s (holds uid=%u euid=%u)\tsetgroups([5,6])\t-> %s\t%s\n", splits[i].who, (unsigned)getuid(), (unsigned)geteuid(), en(e), s);
            fflush(stdout);
            _exit(0);
        }
        wait_child(pid);
    }

    // INITGROUPS
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        alarm(30);
        int e = initgroups("factotum", 20) == 0 ? 0 : errno;
        state_text(s, sizeof s);
        printf("INITGROUPS\tfactotum 20\t-> %s\t%s\n", en(e), s);
        fflush(stdout);
        _exit(0);
    }
    wait_child(pid);

    for (size_t i = 0; i < NPROBE; i++) {
        char f[PATH_MAX];
        snprintf(f, sizeof f, "%s/g%u", base, (unsigned)member_probe[i]);
        unlink(f);
    }
    {
        char c[PATH_MAX];
        snprintf(c, sizeof c, "%s/" CONTROL, base);
        unlink(c);
    }
    if (failures) printf("FAILURES\t%d child processes failed: see the CHILD-FAILED rows\n", failures);
    printf("DONE\n");
    return failures ? 1 : 0;
}
