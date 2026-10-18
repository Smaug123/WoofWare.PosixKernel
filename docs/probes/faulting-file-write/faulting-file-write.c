// What a write(2) or pwrite(2) to a regular file does to the file when the
// caller's buffer faults: whether it answers EFAULT, and whether, before the
// fault, it has already stripped set-ID bits, moved timestamps, extended the
// file, moved the descriptor's offset, or (on Linux) raised inotify events.
//
// Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/p /probe/faulting-file-write.c && /tmp/p /dev/shm/fw && /tmp/p /tmp/fw'
//         Run it as root. Each row forks a child; root sets the file up,
//         chowned to uid 1000 and to group 1000 (the writer's) or 2000 (not
//         the writer's), then the child either keeps root or becomes uid 1000,
//         gid 1000, no supplementary groups, before it opens and writes.
//         /dev/shm is tmpfs; /tmp is the container's root filesystem.
// Darwin: nix develop -c clang -Wall -o /tmp/p faulting-file-write.c && /tmp/p "$(mktemp -d /private/tmp/fw.XXXXXX)"
//         As an ordinary user, which cannot chown. The base directory's group
//         must be one the caller is not in (/private/tmp is wheel); a file
//         created there takes that group, and an "in" row chowns it to the
//         caller's egid. A mode the caller could not set is reported as
//         `unsettable` rather than measured.
// Darwin, as root: docs/probes/darwin-root/run.sh runs it so. Each row forks
//         a child as on Linux, with the machine's own accounts: root chowns
//         the file to uid 501 and to group 20 (the writer's) or 7777 (a group
//         no account is in), and the child keeps root or takes uid 501 or 502,
//         gid 20, groups 20 alone.
//
// Fields of a row:
//   writer   uid1000 (the file's owner), uid1001 (not its owner, writing
//            through the group or other write bit, which its rows' modes
//            add: 06755 is measured as 06777, 04644 as 04666), root, or self
//            (Darwin's caller, which owns the file). Darwin's root run names
//            them uid501 and uid502, and adds rootowner: root writing a file
//            it owns, in group 0 (in) or 7777 (out).
//   group    in or out: whether the writer's groups hold the file's group.
//   call     write (lseek to the offset first) or pwrite (at the offset).
//   size     the file's length before the call, all of it bytes 'h'.
//   offset   where the write starts.
//   buffer   null; protnone, a PROT_NONE page; past48, 1<<48, just past a
//            48-bit user address space; top, (void *)-4096; or mapped, five
//            readable bytes (the control, which must change the file).
//   count    the count passed.
//   before   the mode the setup left (st_mode & 07777).
// and after the call:
//   ret, errno   what it returned (errno=0 on success).
//   mode         st_mode & 07777.
//   size         st_size.
//   pos          the descriptor's offset, lseek(fd, 0, SEEK_CUR).
//   atime, mtime, ctime   `moved` or `same`, against an fstat made just
//            before the call, 20 ms after the setup last changed the inode.
//   flags    fcntl(fd, F_GETFL): the access mode and status flags, in which
//            Darwin records a description written through (0x10000).
//   events   (Linux) the inotify events a watch on the file, added after the
//            open, read after the call: IN_* names joined by `|`, in order,
//            or `none`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/inotify.h>
#endif

#ifdef __APPLE__
#define ATIM st_atimespec
#define MTIM st_mtimespec
#define CTIM st_ctimespec
#else
#define ATIM st_atim
#define MTIM st_mtim
#define CTIM st_ctim
#endif

static char base[PATH_MAX - 2];
static void *protnone;
// How many rows' children did not exit 0; any makes the probe exit 1.
static int failures;

// The file's owner and another user, the writer's group and one it is not in,
// as root sets them up.
#ifdef __APPLE__
static const uid_t OWNER = 501, OTHER = 502;
static const gid_t GROUP_IN = 20, GROUP_OUT = 7777;
static const char *const OWNER_NAME = "uid501", *const OTHER_NAME = "uid502";
#else
static const uid_t OWNER = 1000, OTHER = 1001;
static const gid_t GROUP_IN = 1000, GROUP_OUT = 2000;
static const char *const OWNER_NAME = "uid1000", *const OTHER_NAME = "uid1001";
#endif

static void die(const char *what) {
    perror(what);
    exit(2);
}

static int same_ts(struct timespec a, struct timespec b) { return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec; }

static const char *moved(struct timespec before, struct timespec after) { return same_ts(before, after) ? "same" : "moved"; }

static void sleep_ms(int ms) {
    struct timespec t = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&t, NULL);
}

static void *buffer_named(const char *name) {
    static const char bytes[] = "WORLD";
    if (strcmp(name, "null") == 0) return NULL;
    if (strcmp(name, "protnone") == 0) return protnone;
    if (strcmp(name, "past48") == 0) return (void *)((uintptr_t)1 << 48);
    if (strcmp(name, "top") == 0) return (void *)(uintptr_t)-4096;
    if (strcmp(name, "mapped") == 0) return (void *)bytes;
    fprintf(stderr, "unknown buffer %s\n", name);
    exit(2);
}

#ifdef __linux__
static void events(int in, char *out, size_t cap) {
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    out[0] = 0;
    ssize_t n = read(in, buf, sizeof buf);
    if (n <= 0) {
        snprintf(out, cap, "none");
        return;
    }
    for (char *q = buf; q < buf + n;) {
        struct inotify_event *e = (struct inotify_event *)q;
        uint32_t m = e->mask;
        static const struct {
            uint32_t bit;
            const char *name;
        } names[] = {{IN_ACCESS, "IN_ACCESS"}, {IN_MODIFY, "IN_MODIFY"}, {IN_ATTRIB, "IN_ATTRIB"},
                     {IN_CLOSE_WRITE, "IN_CLOSE_WRITE"}, {IN_CLOSE_NOWRITE, "IN_CLOSE_NOWRITE"},
                     {IN_OPEN, "IN_OPEN"}};
        for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
            if (m & names[i].bit) {
                if (out[0]) strncat(out, "|", cap - strlen(out) - 1);
                strncat(out, names[i].name, cap - strlen(out) - 1);
                m &= ~names[i].bit;
            }
        }
        if (m) {
            char hex[32];
            snprintf(hex, sizeof hex, "%s0x%x", out[0] ? "|" : "", m);
            strncat(out, hex, cap - strlen(out) - 1);
        }
        q += sizeof(struct inotify_event) + e->len;
    }
}
#endif

// Make the file as the row needs it. Returns 0, or -1 when the mode would not
// stick (a mode the caller may not set), having printed nothing.
static int setup(const char *pth, int mode, int group_in, long size, int root_owns) {
    unlink(pth);
    int fd = open(pth, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) die("create");
    char *seed = malloc(size + 1);
    if (!seed) die("malloc");
    memset(seed, 'h', size);
    if (write(fd, seed, size) != size) die("seed");
    free(seed);
    if (geteuid() == 0) {
        if (fchown(fd, root_owns ? 0 : OWNER, root_owns ? (group_in ? 0 : GROUP_OUT) : group_in ? GROUP_IN : GROUP_OUT) != 0) die("fchown");
    } else if (group_in) {
        if (fchown(fd, (uid_t)-1, getegid()) != 0) die("fchown egid");
    }
    // After the chown, which clears set-ID bits.
    fchmod(fd, mode);
    struct timespec past[2] = {{1000000000, 0}, {1000000000, 0}};
    if (futimens(fd, past) != 0) die("futimens");
    struct stat st;
    if (fstat(fd, &st) != 0) die("fstat setup");
    close(fd);
    return (st.st_mode & 07777) == mode ? 0 : -1;
}

static int writer_in_group(gid_t g) {
    if (getegid() == g) return 1;
    gid_t groups[NGROUPS_MAX + 1];
    int n = getgroups(NGROUPS_MAX + 1, groups);
    for (int i = 0; i < n; i++)
        if (groups[i] == g) return 1;
    return 0;
}

static void row(const char *writer, int group_in, long size, const char *call, long offset, const char *bufname,
                size_t count, int mode) {
    char pth[PATH_MAX];
    snprintf(pth, sizeof pth, "%s/f", base);
    const char *group = group_in ? "in" : "out";
    if (setup(pth, mode, group_in, size, strcmp(writer, "rootowner") == 0) != 0) {
        printf("writer=%s group=%s size=%ld call=%s offset=%ld buffer=%s count=%zu before=%05o -> unsettable\n", writer,
               group, size, call, offset, bufname, count, mode);
        fflush(stdout);
        return;
    }
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) die("fork");
    if (child == 0) {
        if (strcmp(writer, OWNER_NAME) == 0 || strcmp(writer, OTHER_NAME) == 0) {
#ifdef __APPLE__
            // Darwin's setgroups(0, NULL) would leave a group of its own
            // choosing; name the writer's one group.
            if (setgroups(1, &GROUP_IN) != 0) die("setgroups");
#else
            if (setgroups(0, NULL) != 0) die("setgroups");
#endif
            if (setgid(GROUP_IN) != 0) die("setgid");
            if (setuid(strcmp(writer, OWNER_NAME) == 0 ? OWNER : OTHER) != 0) die("setuid");
        }
        int fd = open(pth, O_RDWR);
        if (fd < 0) die("open");
        struct stat st0;
        if (fstat(fd, &st0) != 0) die("fstat");
        // The group as the writer stands towards it, checked rather than assumed.
        if (writer_in_group(st0.st_gid) != group_in && strcmp(writer, "root") != 0 && strcmp(writer, "rootowner") != 0) {
            printf("writer=%s group=%s: the writer's groups disagree with the row (file gid %d)\n", writer, group,
                   (int)st0.st_gid);
            exit(3);
        }
#ifdef __linux__
        int in = inotify_init1(IN_NONBLOCK);
        if (in < 0) die("inotify_init1");
        if (inotify_add_watch(in, pth, IN_ALL_EVENTS) < 0) die("inotify_add_watch");
#endif
        if (strcmp(call, "write") == 0 && lseek(fd, offset, SEEK_SET) != offset) die("lseek");
        sleep_ms(20);
        struct stat before, after;
        if (fstat(fd, &before) != 0) die("fstat before");
        void *buf = buffer_named(bufname);
        errno = 0;
        ssize_t r = strcmp(call, "write") == 0 ? write(fd, buf, count) : pwrite(fd, buf, count, offset);
        int e = r < 0 ? errno : 0;
        if (fstat(fd, &after) != 0) die("fstat after");
        off_t pos = lseek(fd, 0, SEEK_CUR);
        int flags = fcntl(fd, F_GETFL);
        char ev[512];
#ifdef __linux__
        events(in, ev, sizeof ev);
#else
        snprintf(ev, sizeof ev, "-");
#endif
        printf("writer=%s group=%s size=%ld call=%s offset=%ld buffer=%s count=%zu before=%05o -> ret=%zd errno=%d "
               "mode=%05o size=%lld pos=%lld atime=%s mtime=%s ctime=%s flags=0x%x events=%s\n",
               writer, group, size, call, offset, bufname, count, mode, r, e, (int)(after.st_mode & 07777),
               (long long)after.st_size, (long long)pos, moved(before.ATIM, after.ATIM),
               moved(before.MTIM, after.MTIM), moved(before.CTIM, after.CTIM), flags, ev);
        fflush(stdout);
        exit(0);
    }
    int status;
    if (waitpid(child, &status, 0) != child) die("waitpid");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        failures++;
        printf("writer=%s group=%s size=%ld call=%s offset=%ld buffer=%s: child ended with status 0x%x\n", writer, group,
               size, call, offset, bufname, status);
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <base directory>\n", argv[0]);
        return 2;
    }
    snprintf(base, sizeof base, "%s", argv[1]);
    mkdir(base, 0755);
    protnone = mmap(NULL, 65536, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (protnone == MAP_FAILED) die("mmap");

    struct utsname u;
    uname(&u);
    struct stat bs;
    if (stat(base, &bs) != 0) die("stat base");
    printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);
    printf("# caller uid=%d egid=%d, base directory gid=%d\n", (int)geteuid(), (int)getegid(), (int)bs.st_gid);
    fflush(stdout);

#ifdef __APPLE__
    // Darwin's root run adds root writing a file it owns, in group 0 or 7777.
    const char *writers_root[] = {OWNER_NAME, OTHER_NAME, "root", "rootowner"};
#else
    const char *writers_root[] = {OWNER_NAME, OTHER_NAME, "root"};
#endif
    const char *writers_self[] = {"self"};
    const char **writers = geteuid() == 0 ? writers_root : writers_self;
    int nwriters = geteuid() == 0 ? (int)(sizeof writers_root / sizeof writers_root[0]) : 1;
    if (geteuid() != 0 && writer_in_group(bs.st_gid)) {
        printf("# the caller is in the base directory's group, so no `out` row can be measured here\n");
    }

    const char *calls[] = {"write", "pwrite"};
    const char *buffers[] = {"mapped", "null", "protnone", "past48", "top"};
    const size_t nbuffers = sizeof buffers / sizeof buffers[0];

    // Section matrix: a five-byte file, written five bytes at 0 (wholly
    // inside it), 1 (from inside it to past its end), 5 (its end) and 100
    // (past it), by every writer and standing, over modes with and without
    // each set-ID bit.
    printf("# section matrix\n");
    const long offsets[] = {0, 1, 5, 100};
    const int modes[] = {06755, 04755, 04644, 02755, 02644, 00755};
    for (int w = 0; w < nwriters; w++)
        for (int g = 1; g >= 0; g--)
            for (size_t m = 0; m < sizeof modes / sizeof modes[0]; m++)
                for (size_t c = 0; c < 2; c++)
                    for (size_t o = 0; o < sizeof offsets / sizeof offsets[0]; o++)
                        for (size_t b = 0; b < nbuffers; b++)
                            row(writers[w], g, 5, calls[c], offsets[o], buffers[b], 5,
                                strcmp(writers[w], OTHER_NAME) == 0 ? modes[m] | 0066 : modes[m]);

    // Section zero: a count of zero, through each faulting buffer.
    printf("# section zero\n");
    for (int w = 0; w < nwriters; w++)
        for (size_t c = 0; c < 2; c++)
            for (size_t o = 0; o < sizeof offsets / sizeof offsets[0]; o++)
                for (size_t b = 1; b < nbuffers; b++)
                    row(writers[w], 1, 5, calls[c], offsets[o], buffers[b], 0,
                        strcmp(writers[w], OTHER_NAME) == 0 ? 06777 : 06755);

    // Section extent: which of the file's length, the write's offset and its
    // count decide what moves, around page boundaries (4 KiB on Linux, 16 KiB
    // on Darwin), by the unprivileged owner in the file's group, through the
    // two faulting buffers every platform admits past its address screen.
    printf("# section extent\n");
    const long sizes[] = {0, 5, 4096, 16384, 20000};
    const long extent_offsets[] = {0, 1, 5, 4095, 4096, 4097, 16383, 16384, 16385, 20000, 32768};
    const size_t counts[] = {5, 16384};
    for (size_t s = 0; s < sizeof sizes / sizeof sizes[0]; s++)
        for (size_t o = 0; o < sizeof extent_offsets / sizeof extent_offsets[0]; o++)
            for (size_t c = 0; c < sizeof counts / sizeof counts[0]; c++)
                for (size_t b = 1; b <= 2; b++)
                    row(writers[0], 1, sizes[s], "pwrite", extent_offsets[o], buffers[b], counts[c], 04755);
    return failures ? 1 : 0;
}
