// What gethostname(3) does with each buffer capacity, around the length of
// the name it reports, and with a destination the caller cannot write.
//
// With no arguments it measures the machine's current name. With arguments
// (Linux, as root in a UTS namespace of its own) each argument is a length:
// the probe first calls sethostname(2) with that many 'h' bytes, prints what
// that answered, and measures the name if it was set.
//
// The name itself is never printed, only its length, so a recording does not
// name the machine it was made on. A row is
//   cap=<n> dest=<kind>: ret=<r> errno=<e> changed=<k> nul=<i|none> prefix=<y|n>
// where `changed` counts the bytes of a buffer pre-filled with 0xAA that the
// call overwrote, `nul` is the index of the first NUL among them, and
// `prefix` says whether the bytes before it are a prefix of the name. A
// destination the caller cannot write is measured in a child, and a child
// killed by a signal prints `signal=<name>` instead.
//
// Linux:  container run --rm --cap-add CAP_SYS_ADMIN -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
// Darwin: nix develop -c clang -Wall -o gethostname gethostname.c && ./gethostname
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *en(int e) {
    switch (e) {
    case 0: return "0";
    case ENAMETOOLONG: return "ENAMETOOLONG";
    case EINVAL: return "EINVAL";
    case EFAULT: return "EFAULT";
    case ENOMEM: return "ENOMEM";
    case EPERM: return "EPERM";
    default: return strerror(e);
    }
}

static const char *sn(int s) {
    switch (s) {
    case SIGSEGV: return "SIGSEGV";
    case SIGBUS: return "SIGBUS";
    case SIGABRT: return "SIGABRT";
    case SIGILL: return "SIGILL";
    case SIGTRAP: return "SIGTRAP";
    default: return "other";
    }
}

#define BUF 4096
// Room before the buffer, so a write at index -1 lands in the sentinel too.
#define GUARD 16

static char name[BUF];
static size_t nameLength;

static void mapped(size_t cap) {
    static unsigned char raw[GUARD + BUF + GUARD];
    memset(raw, 0xAA, sizeof raw);
    unsigned char *buf = raw + GUARD;
    errno = 0;
    int r = gethostname((char *)buf, cap);
    int e = r == 0 ? 0 : errno;
    int before = 0;
    for (int i = 0; i < GUARD; i++)
        if (raw[i] != 0xAA) before++;
    size_t changed = 0;
    long nul = -1;
    for (size_t i = 0; i < BUF; i++) {
        if (buf[i] != 0xAA) changed = i + 1;
        if (nul < 0 && buf[i] == 0 && i < changed) nul = (long)i;
    }
    size_t compared = nul >= 0 ? (size_t)nul : changed;
    int prefix = compared <= nameLength && memcmp(buf, name, compared) == 0;
    printf("cap=%zu dest=mapped: ret=%d errno=%s changed=%zu", cap, r, en(e), changed);
    if (nul >= 0)
        printf(" nul=%ld", nul);
    else
        printf(" nul=none");
    printf(" prefix=%s", prefix ? "y" : "n");
    if (before)
        printf(" before=%d", before);
    printf("\n");
}

static void unwritable(size_t cap, const char *kind, void *dest) {
    fflush(stdout);
    pid_t child = fork();
    if (child == 0) {
        errno = 0;
        int r = gethostname((char *)dest, cap);
        int e = r == 0 ? 0 : errno;
        printf("cap=%zu dest=%s: ret=%d errno=%s\n", cap, kind, r, en(e));
        fflush(stdout);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status))
        printf("cap=%zu dest=%s: signal=%s\n", cap, kind, sn(WTERMSIG(status)));
}

static void measure(void) {
    // The reference name, read through a buffer comfortably larger than any
    // name either flavour can hold.
    static char reference[BUF];
    memset(reference, 0, sizeof reference);
    if (gethostname(reference, sizeof reference) != 0) {
        printf("reference gethostname failed: %s\n", en(errno));
        return;
    }
    memcpy(name, reference, sizeof name);
    nameLength = strlen(name);
    struct utsname u;
    uname(&u);
    printf("# name length %zu; uname nodename %s the name\n", nameLength,
           strcmp(u.nodename, name) == 0 ? "is" : "is NOT");

    size_t L = nameLength;
    size_t caps[] = {0, 1, 2, L == 0 ? 0 : L - 1, L, L + 1, L + 2, 64, 65, 255, 256, 257, 258, 1024};
    for (size_t i = 0; i < sizeof caps / sizeof caps[0]; i++)
        mapped(caps[i]);

    long page = sysconf(_SC_PAGESIZE);
    void *none = mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    void *ro = mmap(NULL, (size_t)page, PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
    size_t ucaps[] = {0, 1, L, L + 1, 256, 257, 1024};
    for (size_t i = 0; i < sizeof ucaps / sizeof ucaps[0]; i++) {
        unwritable(ucaps[i], "null", NULL);
        unwritable(ucaps[i], "prot_none", none);
        unwritable(ucaps[i], "read_only", ro);
    }
}

int main(int argc, char **argv) {
#ifdef HOST_NAME_MAX
    printf("# HOST_NAME_MAX=%d", HOST_NAME_MAX);
#else
    printf("# HOST_NAME_MAX undefined");
#endif
#ifdef MAXHOSTNAMELEN
    printf(" MAXHOSTNAMELEN=%d", MAXHOSTNAMELEN);
#endif
    printf(" _SC_HOST_NAME_MAX=%ld\n", sysconf(_SC_HOST_NAME_MAX));
    if (argc == 1) {
        measure();
        return 0;
    }
    for (int a = 1; a < argc; a++) {
        size_t len = (size_t)atol(argv[a]);
        static char wanted[BUF];
        memset(wanted, 'h', len);
        wanted[len] = 0;
        errno = 0;
        int r = sethostname(wanted, len);
        int e = r == 0 ? 0 : errno;
        printf("## sethostname len=%zu: ret=%d errno=%s\n", len, r, en(e));
        if (r == 0)
            measure();
    }
    return 0;
}
