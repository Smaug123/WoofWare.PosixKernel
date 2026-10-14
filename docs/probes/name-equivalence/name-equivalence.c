// Which spellings of a name a filesystem takes as the name a directory binds:
// whether a lookup, a creation or a rename that spells a bound name in another
// way (another Unicode normalisation form, a canonical singleton such as KELVIN
// SIGN for "K", a compatibility character, another case, bytes that are not
// UTF-8) reaches the entry bound under the first spelling, and which spelling
// `readdir` then reports.
//
// Every row runs in a fresh, empty directory made under the directory named on
// the command line. Names are printed as their bytes in hex, so a row says
// exactly what it created and what it looked up.
//
//   L  first  second: creates `first` with O_CREAT|O_EXCL, then
//        stat(second): `same` if it reaches the inode just created, `other` if
//          it reaches a different one, else the errno;
//        open(second, O_CREAT|O_EXCL): its answer;
//        readdir: every name the directory then holds, in hex.
//      Controls: `first` itself as `second` (an exact hit), a different
//      letter (a miss), another case (a miss only where names are
//      case-sensitive).
//   I  an interior component: mkdir(first), creat(first/x), stat(second/x).
//   O  first  second  op: binds `first` (a regular file, or a directory for
//      rmdir, chdir and the directory rename), then applies `op` to `second`,
//      and prints its answer and the directory's names afterwards. `src` is a
//      second regular file the link and rename rows use as their source.
//   B  name: creat(name) with O_CREAT|O_EXCL, for the names the L rows look up
//      that are not UTF-8 (the control that such a name cannot be bound here).
//
// The fixture line `#fs` names the filesystem under test: on Darwin its
// f_fstypename and f_fssubtype (for APFS, 0 is case-sensitive and 1 is
// case-insensitive), on Linux its f_type.
//
// Build and run, from this directory:
//   Darwin, a fresh case-sensitive APFS volume:
//     hdiutil create -size 20m -fs "Case-sensitive APFS" -volname probecs -type UDIF /tmp/probecs.dmg
//     hdiutil attach /tmp/probecs.dmg -mountpoint /tmp/probecs -nobrowse
//     cc -Wall -O1 -o /tmp/name-equivalence name-equivalence.c && /tmp/name-equivalence /tmp/probecs
//     hdiutil detach /tmp/probecs
//   Darwin, the default (case-insensitive) volume:
//     /tmp/name-equivalence "$(mktemp -d)"
//   Linux (tmpfs, and the container's root filesystem):
//     container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/p /probe/name-equivalence.c && mkdir -p /dev/shm/p && /tmp/p /dev/shm/p && mkdir -p /var/p && /tmp/p /var/p'
//
// Measured 2026-10-13; the outputs are beside this file. See README.md.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif

static const char *errno_name(int e) {
    static char other[32];
    switch (e) {
    case 0: return "OK";
    case ENOENT: return "ENOENT";
    case EEXIST: return "EEXIST";
    case EILSEQ: return "EILSEQ";
    case EINVAL: return "EINVAL";
    case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR";
    case EACCES: return "EACCES";
    case EPERM: return "EPERM";
    case ENOTEMPTY: return "ENOTEMPTY";
    default:
        snprintf(other, sizeof other, "errno=%d", e);
        return other;
    }
}

// The name's bytes in hex; a returned pointer is valid until the fourth call
// after it.
static const char *hex(const char *s) {
    static char buffers[4][1024];
    static int next = 0;
    char *out = buffers[next];
    next = (next + 1) % 4;
    out[0] = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        sprintf(out + strlen(out), "%02x", *p);
    return out;
}

static char base[4096];
static int counter = 0;

// A fresh, empty directory under `base`, made the current directory.
static void fresh(void) {
    char path[4200];
    snprintf(path, sizeof path, "%s/row%d", base, counter++);
    if (mkdir(path, 0755) != 0 || chdir(path) != 0) {
        perror(path);
        exit(1);
    }
}

static int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

// The current directory's names in hex, sorted, comma-separated.
static const char *listing(void) {
    static char out[4096];
    char *names[64];
    int count = 0;
    DIR *d = opendir(".");
    if (!d) {
        snprintf(out, sizeof out, "opendir:%s", errno_name(errno));
        return out;
    }
    struct dirent *e;
    while ((e = readdir(d)) && count < 64) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        names[count++] = strdup(hex(e->d_name));
    }
    closedir(d);
    qsort(names, count, sizeof names[0], compare_strings);
    out[0] = 0;
    for (int i = 0; i < count; i++) {
        strcat(out, i ? "," : "");
        strcat(out, names[i]);
        free(names[i]);
    }
    if (count == 0)
        strcpy(out, "(empty)");
    return out;
}

// stat(path) relative to the inode `expected`.
static const char *stat_answer(const char *path, ino_t expected) {
    struct stat st;
    if (stat(path, &st) != 0)
        return errno_name(errno);
    return st.st_ino == expected ? "same" : "other";
}

static int create_excl(const char *name) {
    int fd = open(name, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0)
        return errno;
    close(fd);
    return 0;
}

static ino_t inode_of(const char *name) {
    struct stat st;
    if (lstat(name, &st) != 0) {
        perror(name);
        exit(1);
    }
    return st.st_ino;
}

static void lookup_row(const char *what, const char *first, const char *second) {
    fresh();
    int created = create_excl(first);
    if (created != 0) {
        printf("L\t%s\t%s\t%s\tcreate-first=%s\n", what, hex(first), hex(second), errno_name(created));
        return;
    }
    ino_t ino = inode_of(first);
    const char *looked = stat_answer(second, ino);
    char looked_copy[32];
    snprintf(looked_copy, sizeof looked_copy, "%s", looked);
    int excl = create_excl(second);
    printf("L\t%s\t%s\t%s\tstat=%s\texcl=%s\tnames=%s\n", what, hex(first), hex(second), looked_copy,
           errno_name(excl), listing());
}

static void interior_row(const char *what, const char *first, const char *second) {
    fresh();
    char inner[1024], through[1024];
    snprintf(inner, sizeof inner, "%s/x", first);
    snprintf(through, sizeof through, "%s/x", second);
    if (mkdir(first, 0755) != 0 || create_excl(inner) != 0) {
        printf("I\t%s\tsetup failed: %s\n", what, errno_name(errno));
        return;
    }
    printf("I\t%s\t%s\t%s\tstat(second/x)=%s\n", what, hex(first), hex(second), stat_answer(through, inode_of(inner)));
}

enum op { MKDIR, LINK, SYMLINK, UNLINK, RMDIR, RENAME_ONTO, RENAME_SELF, RENAME_FROM, RENAME_DIR_SELF, CHDIR, OPEN_CREAT };
static const char *op_names[] = { "mkdir(second)",
                                  "link(src,second)",
                                  "symlink(t,second)",
                                  "unlink(second)",
                                  "rmdir(second)",
                                  "rename(src,second)",
                                  "rename(first,second)",
                                  "rename(second,moved)",
                                  "rename(firstdir,second)",
                                  "chdir(second)",
                                  "open(second,O_CREAT)" };

static void op_row(const char *what, const char *first, const char *second, enum op op) {
    fresh();
    int as_directory = op == RMDIR || op == RENAME_DIR_SELF || op == CHDIR;
    int made = as_directory ? (mkdir(first, 0755) == 0 ? 0 : errno) : create_excl(first);
    if (made != 0 || create_excl("src") != 0) {
        printf("O\t%s\tsetup failed: %s\n", what, errno_name(made ? made : errno));
        return;
    }
    ino_t first_ino = inode_of(first);
    ino_t src_ino = inode_of("src");
    int result = 0;
    char extra[64] = "";
    switch (op) {
    case MKDIR: result = mkdir(second, 0755) == 0 ? 0 : errno; break;
    case LINK: result = link("src", second) == 0 ? 0 : errno; break;
    case SYMLINK: result = symlink("t", second) == 0 ? 0 : errno; break;
    case UNLINK: result = unlink(second) == 0 ? 0 : errno; break;
    case RMDIR: result = rmdir(second) == 0 ? 0 : errno; break;
    case RENAME_ONTO:
    case RENAME_SELF:
    case RENAME_DIR_SELF: {
        const char *source = op == RENAME_ONTO ? "src" : first;
        result = rename(source, second) == 0 ? 0 : errno;
        break;
    }
    case RENAME_FROM: result = rename(second, "moved") == 0 ? 0 : errno; break;
    case CHDIR: {
        result = chdir(second) == 0 ? 0 : errno;
        if (result == 0) {
            struct stat here;
            stat(".", &here);
            snprintf(extra, sizeof extra, "\tcwd=%s", here.st_ino == first_ino ? "first" : "other");
            chdir("..");
        }
        break;
    }
    case OPEN_CREAT: {
        int fd = open(second, O_CREAT | O_WRONLY, 0644);
        if (fd < 0) {
            result = errno;
        } else {
            struct stat st;
            fstat(fd, &st);
            snprintf(extra, sizeof extra, "\topened=%s", st.st_ino == first_ino ? "first" : "other");
            close(fd);
        }
        break;
    }
    }
    // What each name the directory now holds is: the inode bound under `first`,
    // `src`'s, or another.
    char kinds[512] = "";
    DIR *d = opendir(".");
    struct dirent *e;
    char *entries[64];
    int count = 0;
    while (d && (e = readdir(d)) && count < 64) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        struct stat st;
        lstat(e->d_name, &st);
        const char *which = st.st_ino == first_ino ? "first" : st.st_ino == src_ino ? "src" : "new";
        char entry[256];
        snprintf(entry, sizeof entry, "%s=%s", hex(e->d_name), which);
        entries[count++] = strdup(entry);
    }
    if (d)
        closedir(d);
    qsort(entries, count, sizeof entries[0], compare_strings);
    for (int i = 0; i < count; i++) {
        strcat(kinds, i ? "," : "");
        strcat(kinds, entries[i]);
        free(entries[i]);
    }
    printf("O\t%s\t%s\t%s\t%s=%s%s\tnames=%s\n", what, hex(first), hex(second), op_names[op], errno_name(result), extra,
           count ? kinds : "(empty)");
}

static void bind_row(const char *what, const char *name) {
    fresh();
    printf("B\t%s\t%s\tcreate=%s\n", what, hex(name), errno_name(create_excl(name)));
}

#define NFC_E "\xc3\xa9"
#define NFD_E "e\xcc\x81"
#define KELVIN "\xe2\x84\xaa"
#define GREEK_QUESTION "\xcd\xbe"
#define VARIA "\xe1\xbf\xaf"
#define OHM "\xe2\x84\xa6"
#define OMEGA "\xce\xa9"
#define ANGSTROM "\xe2\x84\xab"
#define A_RING "\xc3\x85"
#define A_RING_NFD "A\xcc\x8a"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <empty directory on the filesystem under test>\n", argv[0]);
        return 2;
    }
    if (!realpath(argv[1], base)) {
        perror(argv[1]);
        return 1;
    }
    struct utsname u;
    uname(&u);
    printf("#\t%s %s %s\n", u.sysname, u.release, u.machine);
#ifdef __APPLE__
    struct statfs fs;
    if (statfs(base, &fs) == 0)
        printf("#fs\tf_fstypename=%s\tf_fssubtype=%u\n", fs.f_fstypename, fs.f_fssubtype);
#else
    struct statfs fs;
    if (statfs(base, &fs) == 0)
        printf("#fs\tf_type=0x%lx\n", (unsigned long)fs.f_type);
#endif

    // Controls.
    lookup_row("exact", NFC_E, NFC_E);
    lookup_row("another letter", NFC_E, "\xc3\xa8");
    lookup_row("another case", "A", "a");
    lookup_row("another case, non-ASCII", "\xc3\x89", NFC_E);

    // Canonical equivalence.
    lookup_row("NFC then NFD", NFC_E, NFD_E);
    lookup_row("NFD then NFC", NFD_E, NFC_E);
    lookup_row("NFC then NFD, within a name", "caf" NFC_E ".txt", "cafe\xcc\x81.txt");
    lookup_row("mark order", "a\xcc\x81\xcc\xa7", "a\xcc\xa7\xcc\x81");
    lookup_row("Hangul syllable then jamo", "\xea\xb0\x80", "\xe1\x84\x80\xe1\x85\xa1");
    lookup_row("Hangul jamo then syllable", "\xe1\x84\x80\xe1\x85\xa1", "\xea\xb0\x80");

    // The canonical singletons whose decomposition is ASCII, both ways, and
    // against the other case of that ASCII.
    lookup_row("K then KELVIN SIGN", "K", KELVIN);
    lookup_row("KELVIN SIGN then K", KELVIN, "K");
    lookup_row("KELVIN SIGN then k", KELVIN, "k");
    lookup_row("k then KELVIN SIGN", "k", KELVIN);
    lookup_row("; then GREEK QUESTION MARK", ";", GREEK_QUESTION);
    lookup_row("GREEK QUESTION MARK then ;", GREEK_QUESTION, ";");
    lookup_row("` then GREEK VARIA", "`", VARIA);
    lookup_row("GREEK VARIA then `", VARIA, "`");
    lookup_row("aKb then a KELVIN SIGN b", "aKb", "a" KELVIN "b");

    // Canonical singletons whose decomposition is not ASCII.
    lookup_row("OHM SIGN then OMEGA", OHM, OMEGA);
    lookup_row("OMEGA then OHM SIGN", OMEGA, OHM);
    lookup_row("ANGSTROM SIGN then A RING", ANGSTROM, A_RING);
    lookup_row("A RING then A + RING", A_RING, A_RING_NFD);
    lookup_row("CJK COMPATIBILITY IDEOGRAPH-F900 then U+8C48", "\xef\xa4\x80", "\xe8\xb1\x88");

    // Compatibility (not canonical) equivalents.
    lookup_row("fi ligature then fi", "\xef\xac\x81", "fi");
    lookup_row("fi then fi ligature", "fi", "\xef\xac\x81");
    lookup_row("fullwidth A then A", "\xef\xbc\xa1", "A");
    lookup_row("A then fullwidth A", "A", "\xef\xbc\xa1");
    lookup_row("vulgar half then 1 fraction-slash 2", "\xc2\xbd", "1\xe2\x81\x84" "2");

    // Lookups that are not UTF-8, beside a name some decoder might take them for.
    lookup_row("NFC e-acute then Latin-1 e-acute", NFC_E, "\xe9");
    lookup_row("emoji then its CESU-8", "\xf0\x9f\x98\x80", "\xed\xa0\xbd\xed\xb8\x80");
    lookup_row("e then an overlong e", "e", "\xc1\xa5");
    bind_row("Latin-1 e-acute", "\xe9");
    bind_row("CESU-8 emoji", "\xed\xa0\xbd\xed\xb8\x80");
    bind_row("overlong e", "\xc1\xa5");

    interior_row("NFC directory through NFD", NFC_E, NFD_E);
    interior_row("K directory through KELVIN SIGN", "K", KELVIN);

    // The other syscalls that look a final name up, each given the NFD
    // spelling of a name bound in NFC.
    op_row("mkdir", NFC_E, NFD_E, MKDIR);
    op_row("link", NFC_E, NFD_E, LINK);
    op_row("symlink", NFC_E, NFD_E, SYMLINK);
    op_row("unlink", NFC_E, NFD_E, UNLINK);
    op_row("rmdir", NFC_E, NFD_E, RMDIR);
    op_row("chdir", NFC_E, NFD_E, CHDIR);
    op_row("open O_CREAT", NFC_E, NFD_E, OPEN_CREAT);
    op_row("rename onto", NFC_E, NFD_E, RENAME_ONTO);
    op_row("rename from", NFC_E, NFD_E, RENAME_FROM);
    op_row("rename to its other spelling", NFC_E, NFD_E, RENAME_SELF);
    op_row("rename to its other spelling", NFD_E, NFC_E, RENAME_SELF);
    op_row("rename a directory to its other spelling", NFC_E, NFD_E, RENAME_DIR_SELF);
    op_row("rename to its other spelling", "K", KELVIN, RENAME_SELF);
    op_row("rename to its other spelling", KELVIN, "K", RENAME_SELF);
    op_row("rename to another case", "A", "a", RENAME_SELF);
    op_row("unlink", "K", KELVIN, UNLINK);
    op_row("link", "K", KELVIN, LINK);
    return 0;
}
