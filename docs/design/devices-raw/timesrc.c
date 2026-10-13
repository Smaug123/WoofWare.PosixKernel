// Which clock glibc's time(NULL) reads: around each of 20 second boundaries,
// compare it with CLOCK_REALTIME and CLOCK_REALTIME_COARSE read just before and
// just after. Counts the readings where time() agrees with one but not the
// other.
#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>
int main(void) {
    alarm(60);
    long agreeFineOnly = 0, agreeCoarseOnly = 0, both = 0, neither = 0, n = 0;
    struct timespec f0, c0, f1, c1;
    time_t start = time(NULL);
    while (time(NULL) < start + 21) {
        clock_gettime(CLOCK_REALTIME, &f0);
        clock_gettime(CLOCK_REALTIME_COARSE, &c0);
        time_t t = time(NULL);
        clock_gettime(CLOCK_REALTIME_COARSE, &c1);
        clock_gettime(CLOCK_REALTIME, &f1);
        if (f0.tv_sec != f1.tv_sec || c0.tv_sec != c1.tv_sec) continue; // straddles a boundary
        n++;
        int fine = t == f0.tv_sec, coarse = t == c0.tv_sec;
        if (fine && coarse) both++;
        else if (fine) agreeFineOnly++;
        else if (coarse) agreeCoarseOnly++;
        else neither++;
    }
    printf("TIMESRC readings=%ld both=%ld fine_only=%ld coarse_only=%ld neither=%ld\n", n, both, agreeFineOnly, agreeCoarseOnly, neither);
    return 0;
}
