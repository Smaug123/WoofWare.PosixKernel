// A thread blocked mid-syscall when another thread ends the process: does the
// in-flight call's partial effect survive? Worker writes 1 MiB to a pipe whose
// reader (the parent) drains it slowly; the leader _exit()s after 100 ms. The
// parent counts the bytes it receives; anything strictly between 0 and 1 MiB
// is a write the process death cut short, with the part already copied kept.
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int g_w;
enum { TOTAL = 1 << 20 };

static void *writer(void *arg) {
    (void)arg;
    static char buf[TOTAL];
    memset(buf, 'x', sizeof buf);
    ssize_t n = write(g_w, buf, sizeof buf); // blocks: pipe capacity is far below 1 MiB
    (void)n;
    return NULL;
}

int main(void) {
    alarm(30);
    for (int round = 0; round < 5; round++) {
        int p[2];
        pipe(p);
        pid_t pid = fork();
        if (pid == 0) {
            close(p[0]);
            g_w = p[1];
            pthread_t t;
            pthread_create(&t, NULL, writer, NULL);
            struct timespec ts = { 0, 100 * 1000000L };
            nanosleep(&ts, NULL);
            _exit(3);
        }
        close(p[1]);
        long got = 0;
        char buf[4096];
        ssize_t n;
        struct timespec slow = { 0, 1000000L };
        while ((n = read(p[0], buf, sizeof buf)) > 0) { got += n; nanosleep(&slow, NULL); }
        int st;
        waitpid(pid, &st, 0);
        printf("round\t%d\tbytes_received\t%ld\tof\t%d\tstatus\t0x%x\n", round, got, TOTAL, st);
        close(p[0]);
    }
    return 0;
}
