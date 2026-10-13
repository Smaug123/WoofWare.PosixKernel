// What a process learns about its own executable's path, before and after the
// executable is renamed and then unlinked. Stage 1 copies this binary to a
// scratch directory and execs the copy by a relative path (so the exec string,
// AT_EXECFN and argv[0] differ from the canonical path); stage 2 reports.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/auxv.h>
#else
#include <libproc.h>
#include <mach-o/dyld.h>
#endif

static void report(const char *when) {
    char buf[PATH_MAX * 2];
#ifdef __linux__
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n >= 0) { buf[n] = 0; printf("%s\treadlink(/proc/self/exe)\t\"%s\"\n", when, buf); }
    else printf("%s\treadlink(/proc/self/exe)\terrno=%d (%s)\n", when, errno, strerror(errno));
    char *r = realpath("/proc/self/exe", NULL);
    printf("%s\trealpath(/proc/self/exe)\t%s%s%s\n", when, r ? "\"" : "", r ? r : strerror(errno), r ? "\"" : "");
    free(r);
    const char *execfn = (const char *)getauxval(AT_EXECFN);
    printf("%s\tAT_EXECFN\t\"%s\"\n", when, execfn ? execfn : "(null)");
    r = execfn ? realpath(execfn, NULL) : NULL;
    printf("%s\trealpath(AT_EXECFN)\t%s%s%s\n", when, r ? "\"" : "", r ? r : strerror(errno), r ? "\"" : "");
    free(r);
    int fd = open("/proc/self/exe", O_RDONLY);
    struct stat st;
    printf("%s\topen(/proc/self/exe)\t%s", when, fd >= 0 ? "ok" : strerror(errno));
    if (fd >= 0 && fstat(fd, &st) == 0) printf(" st_nlink=%lu", (unsigned long)st.st_nlink);
    printf("\n");
    if (fd >= 0) close(fd);
#else
    int n = proc_pidpath(getpid(), buf, sizeof buf);
    if (n > 0) printf("%s\tproc_pidpath\t\"%s\"\n", when, buf);
    else printf("%s\tproc_pidpath\tret=%d errno=%d (%s)\n", when, n, errno, strerror(errno));
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath(buf, &size) == 0) {
        printf("%s\t_NSGetExecutablePath\t\"%s\"\n", when, buf);
        char *r = realpath(buf, NULL);
        printf("%s\trealpath(_NSGetExecutablePath)\t%s%s%s\n", when, r ? "\"" : "", r ? r : strerror(errno), r ? "\"" : "");
        free(r);
    } else printf("%s\t_NSGetExecutablePath\tfailed\n", when);
#endif
    fflush(stdout);
}

int main(int argc, char **argv) {
    alarm(30);
    if (argc >= 3 && !strcmp(argv[1], "stage2")) {
        const char *dir = argv[2];
        char cwd[PATH_MAX];
        getcwd(cwd, sizeof cwd);
        printf("stage2\tcwd\t\"%s\"\targv0=\"%s\"\n", cwd, argv[0]);
        report("initial");
        char from[PATH_MAX], to[PATH_MAX];
        snprintf(from, sizeof from, "%s/exe-copy", dir);
        snprintf(to, sizeof to, "%s/exe-renamed", dir);
        if (rename(from, to) != 0) perror("rename");
        report("after_rename");
        if (unlink(to) != 0) perror("unlink");
        report("after_unlink");
        // A new, unrelated file at the old name: does anything now point at it?
        int fd = open(from, O_CREAT | O_WRONLY, 0755);
        if (fd >= 0) close(fd);
        report("after_new_file_at_original_name");
        unlink(from);
        return 0;
    }
    char dir[] = "/tmp/exepathXXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
    char self[PATH_MAX * 2];
#ifdef __linux__
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    self[n] = 0;
#else
    uint32_t size = sizeof self;
    _NSGetExecutablePath(self, &size);
#endif
    char copy[PATH_MAX];
    snprintf(copy, sizeof copy, "%s/exe-copy", dir);
    char cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof cmd, "cp '%s' '%s'", self, copy);
    if (system(cmd) != 0) { fprintf(stderr, "copy failed\n"); return 2; }
    if (chdir(dir) != 0) { perror("chdir"); return 2; }
    execl("./exe-copy", "argv0-is-not-the-path", "stage2", dir, (char *)NULL);
    perror("execl");
    return 2;
}
