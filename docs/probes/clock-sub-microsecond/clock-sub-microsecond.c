// How often each clock's readings carry a digit finer than a microsecond, and
// how two ways of judging from its readings whether it keeps whole microseconds
// fare when the reader is held up.
//
// For each clock id given (default: every id the host answers among 0..16) it
// prints clock_getres, then takes READS back-to-back readings and reports
//   reads=<n> distinct=<d> whole_us=<w> longest_whole_run=<r> min_gap_ns=<g> median_gap_ns=<m>
// where `distinct` counts readings that differ from the one before, `whole_us`
// counts those distinct readings whose nanosecond part is a multiple of 1000,
// `longest_whole_run` is the longest run of consecutive distinct readings that
// all are, and the gaps are between consecutive distinct readings.
//
// It then judges the clock over and over for JUDGE_SECONDS, alternating two
// rules, each of which says "sub-microsecond" at the first reading with a
// non-zero sub-microsecond part:
//   window:   otherwise "whole microseconds" once 50 ms of CLOCK_MONOTONIC_RAW
//             have passed since the judgement began (TestClockAgainstHost's
//             rule before this probe);
//   distinct: otherwise "whole microseconds" once 20 distinct readings have
//             not had one (its rule after).
// and reports, for each rule, how many judgements it made, how many said
// "whole microseconds", and (for the window) how many of those took no
// reading at all.
//
// With -b <n> it first starts n threads that spin forever, to load the CPUs,
// so that the reader is descheduled.
//
// Darwin: nix develop -c clang -Wall -O1 -pthread -o p clock-sub-microsecond.c && ./p && ./p -b 72 8 4
// Linux:  container run --rm -v "$PWD":/probe gcc:14 /bin/sh /probe/run-linux.sh
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define READS 1000000
#define JUDGE_SECONDS 30
#define DISTINCT 20

#ifdef CLOCK_MONOTONIC_RAW
#define WALL CLOCK_MONOTONIC_RAW
#else
#define WALL CLOCK_MONOTONIC
#endif

static int64_t ns_of(struct timespec t) { return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec; }

static int64_t wall_now(void) {
    struct timespec t;
    clock_gettime(WALL, &t);
    return ns_of(t);
}

static void *spin(void *arg) {
    (void)arg;
    volatile uint64_t x = 0;
    for (;;) x++;
    return NULL;
}

static int cmp(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

// 1 if the window rule says "sub-microsecond"; *reads is how many readings it took.
static int judge_window(int id, long *reads) {
    struct timespec t;
    int64_t start = wall_now();
    *reads = 0;
    while (wall_now() - start < 50000000) {
        clock_gettime(id, &t);
        (*reads)++;
        if (t.tv_nsec % 1000 != 0) return 1;
    }
    return 0;
}

static int judge_distinct(int id) {
    struct timespec t;
    int64_t previous = -1;
    int distinct = 0;
    while (distinct < DISTINCT) {
        clock_gettime(id, &t);
        if (t.tv_nsec % 1000 != 0) return 1;
        if (ns_of(t) != previous) {
            distinct++;
            previous = ns_of(t);
        }
    }
    return 0;
}

static void measure(int id) {
    struct timespec res, t;
    if (clock_gettime(id, &t) != 0) return;
    if (clock_getres(id, &res) != 0) printf("id=%d res: errno=%d\n", id, errno);
    else printf("id=%d res=%lld.%09ld\n", id, (long long)res.tv_sec, res.tv_nsec);

    int64_t *gaps = malloc(sizeof(int64_t) * READS);
    int64_t prev = ns_of(t);
    long distinct = 0, whole = 0, run = 0, longest = 0;
    for (long i = 0; i < READS; i++) {
        clock_gettime(id, &t);
        int64_t now = ns_of(t);
        if (now != prev) {
            gaps[distinct++] = now - prev;
            if (t.tv_nsec % 1000 == 0) {
                whole++;
                if (++run > longest) longest = run;
            } else {
                run = 0;
            }
            prev = now;
        }
    }
    int64_t mingap = 0, median = 0;
    if (distinct > 0) {
        qsort(gaps, distinct, sizeof(int64_t), cmp);
        mingap = gaps[0];
        median = gaps[distinct / 2];
    }
    printf("id=%d reads=%d distinct=%ld whole_us=%ld longest_whole_run=%ld min_gap_ns=%lld median_gap_ns=%lld\n",
           id, READS, distinct, whole, longest, (long long)mingap, (long long)median);
    free(gaps);

    long window_judged = 0, window_whole = 0, window_empty = 0;
    long distinct_judged = 0, distinct_whole = 0;
    int64_t start = wall_now();
    while (wall_now() - start < (int64_t)JUDGE_SECONDS * 1000000000) {
        long reads;
        window_judged++;
        if (!judge_window(id, &reads)) {
            window_whole++;
            if (reads == 0) window_empty++;
        }
        distinct_judged++;
        if (!judge_distinct(id)) distinct_whole++;
    }
    printf("id=%d window: judged=%ld said_whole_us=%ld of_which_no_reads=%ld\n",
           id, window_judged, window_whole, window_empty);
    printf("id=%d distinct: judged=%ld said_whole_us=%ld\n", id, distinct_judged, distinct_whole);
    fflush(stdout);
}

int main(int argc, char **argv) {
    int busy = 0, first = 1;
    if (argc > 2 && strcmp(argv[1], "-b") == 0) {
        busy = atoi(argv[2]);
        first = 3;
    }
    for (int i = 0; i < busy; i++) {
        pthread_t th;
        pthread_create(&th, NULL, spin, NULL);
    }
    printf("# busy_threads=%d ncpu=%ld\n", busy, sysconf(_SC_NPROCESSORS_ONLN));
    if (argc > first)
        for (int i = first; i < argc; i++) measure(atoi(argv[i]));
    else
        for (int id = 0; id <= 16; id++) measure(id);
    return 0;
}
