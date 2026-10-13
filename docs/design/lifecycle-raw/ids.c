// A process's family identifiers, and what an orphan's getppid becomes.
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    alarm(20);
    printf("self\tpid=%d ppid=%d pgrp=%d sid=%d\n", (int)getpid(), (int)getppid(), (int)getpgrp(), (int)getsid(0));
    fflush(stdout);
    int p[2];
    pipe(p);
    pid_t mid = fork();
    if (mid == 0) {
        // Middle process: fork a grandchild, then exit so the grandchild is orphaned.
        pid_t gc = fork();
        if (gc == 0) {
            printf("grandchild\tbefore\tpid=%d ppid=%d pgrp=%d sid=%d\n", (int)getpid(), (int)getppid(), (int)getpgrp(), (int)getsid(0));
            fflush(stdout);
            char c;
            read(p[0], &c, 1); // wait for the go-ahead after the middle has died
            printf("grandchild\tafter_parent_exit\tppid=%d\n", (int)getppid());
            fflush(stdout);
            _exit(0);
        }
        _exit(0);
    }
    int st;
    waitpid(mid, &st, 0);
    struct timespec ts = { 0, 100 * 1000000L };
    nanosleep(&ts, NULL);
    write(p[1], "g", 1);
    nanosleep(&ts, NULL);
    printf("self\tmiddle_pid=%d\n", (int)mid);
    // Our own child's view: fork inherits pgrp and sid.
    return 0;
}
