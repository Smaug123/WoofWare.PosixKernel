// rename(2) of a mount point onto itself. Linux's vfs_rename answers 0 when
// source and target are one inode, before its is_local_mountpoint EBUSY; this
// measures whether that holds for /dev, a mount point, as root and as uid 1000.
//
// Fixture first, so a reader can check /dev really is a mount point here: its
// st_dev differs from the root's, and /proc/self/mountinfo lists /dev. Then
// controls that must change the answer: renaming the mount point to another
// name (EBUSY as root, as `mountpoint.c` measured), and renaming a plain
// directory onto itself (0), and onto another name (0, then renamed back).
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *e(int r) {
    static char b[8][48];
    static int k;
    char *s = b[k++ & 7];
    if (r < 0)
        snprintf(s, 48, "-1 %s", strerrorname_np(errno));
    else
        snprintf(s, 48, "%d", r);
    return s;
}

static void row(const char *label, const char *from, const char *to) {
    struct stat before, after;
    int hadBefore = stat(from, &before);
    int r = rename(from, to);
    const char *answer = e(r);
    int hasAfter = stat(from, &after);
    printf("SELF euid=%u %s rename(%s, %s) %s; %s still there: %s\n", geteuid(), label, from, to, answer, from,
           hadBefore == 0 && hasAfter == 0 && before.st_ino == after.st_ino ? "yes" : "no");
}

int main(void) {
    alarm(20);
    struct stat dev, root;
    stat("/dev", &dev);
    stat("/", &root);
    printf("FIXTURE euid=%u stat(/) st_dev=%llu st_ino=%llu; stat(/dev) st_dev=%llu st_ino=%llu; /dev is %s\n",
           geteuid(), (unsigned long long)root.st_dev, (unsigned long long)root.st_ino,
           (unsigned long long)dev.st_dev, (unsigned long long)dev.st_ino,
           dev.st_dev != root.st_dev ? "on another filesystem" : "on the root filesystem");
    FILE *m = fopen("/proc/self/mountinfo", "r");
    char line[512];
    while (m && fgets(line, sizeof line, m)) {
        char a[64], b[64], c[64], d[256], mp[256];
        if (sscanf(line, "%63s %63s %63s %255s %255s", a, b, c, d, mp) == 5 && !strcmp(mp, "/dev"))
            printf("FIXTURE mountinfo: %s", line);
    }
    if (m) fclose(m);

    mkdir("/tmp/plain", 0755);
    row("mount point onto itself", "/dev", "/dev");
    row("mount point onto itself, other spelling", "/dev", "//dev");
    row("mount point to another name", "/dev", "/devx");
    row("plain directory onto itself", "/tmp/plain", "/tmp/plain");
    row("plain directory to another name", "/tmp/plain", "/tmp/plain2");
    rename("/tmp/plain2", "/tmp/plain");

    if (geteuid() == 0) {
        fflush(stdout);
        if (setresgid(1000, 1000, 1000) != 0 || setresuid(1000, 1000, 1000) != 0) {
            printf("SELF could not become uid 1000: %s\n", strerror(errno));
            return 1;
        }
        row("mount point onto itself", "/dev", "/dev");
        row("mount point to another name", "/dev", "/devx");
        row("plain directory onto itself", "/tmp/plain", "/tmp/plain");
    }
    return 0;
}
