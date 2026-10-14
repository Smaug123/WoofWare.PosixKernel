// flock contention between a pipe's two ends, and between two pipes: is the
// pipe (one inode) the contention key, or each end?
#include <errno.h>
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>
int main(void) {
    alarm(10);
    int p[2], q[2];
    pipe(p); pipe(q);
    int a = flock(p[0], LOCK_EX | LOCK_NB); int ea = a ? errno : 0;
    int b = flock(p[1], LOCK_EX | LOCK_NB); int eb = b ? errno : 0;
    int c = flock(q[0], LOCK_EX | LOCK_NB); int ec = c ? errno : 0;
    printf("LOCK_EX read end -> %d errno %d; same pipe's write end -> %d errno %d; another pipe -> %d errno %d\n", a, ea, b, eb, c, ec);
    return 0;
}
