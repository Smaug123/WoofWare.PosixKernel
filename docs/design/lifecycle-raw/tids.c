// Thread ids: what the leader and created threads report, whether the leader's
// id is the pid, how ids are minted (sequential? system-wide?), their width,
// and whether an exited thread's id comes back.
//
// Output is TSV rows: section, key, value.
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

static uint64_t my_tid(void) {
#ifdef __linux__
    return (uint64_t)syscall(SYS_gettid);
#else
    uint64_t t = 0;
    pthread_threadid_np(NULL, &t);
    return t;
#endif
}

static void *report(void *arg) {
    *(uint64_t *)arg = my_tid();
    return NULL;
}

static uint64_t spawn_and_join(void) {
    pthread_t t;
    uint64_t id = 0;
    if (pthread_create(&t, NULL, report, &id) != 0) { perror("pthread_create"); exit(2); }
    pthread_join(t, NULL);
    return id;
}

// Several threads alive at once, each parked on a barrier until all have
// reported, so none can exit and free its id early.
#ifndef __linux__
// Darwin has no pthread_barrier_t; a counter under a mutex does the job.
typedef struct { pthread_mutex_t m; pthread_cond_t c; int n, arrived; } bar_t;
static bar_t g_bar;
static void bar_wait(void) {
    pthread_mutex_lock(&g_bar.m);
    if (++g_bar.arrived == g_bar.n) pthread_cond_broadcast(&g_bar.c);
    else while (g_bar.arrived < g_bar.n) pthread_cond_wait(&g_bar.c, &g_bar.m);
    pthread_mutex_unlock(&g_bar.m);
}
#else
static pthread_barrier_t g_pb;
static void bar_wait(void) { pthread_barrier_wait(&g_pb); }
#endif

static void *report_and_wait(void *arg) {
    *(uint64_t *)arg = my_tid();
    bar_wait();
    return NULL;
}

int main(int argc, char **argv) {
    alarm(120);
    int reuse_rounds = argc > 1 ? atoi(argv[1]) : 0;

    uint64_t leader = my_tid();
    printf("leader\tpid\t%d\n", (int)getpid());
    printf("leader\ttid\t%llu\n", (unsigned long long)leader);
    printf("leader\ttid_equals_pid\t%d\n", leader == (uint64_t)getpid());

    // Concurrent: 8 threads alive at once.
    enum { N = 8 };
    pthread_t ts[N];
    uint64_t ids[N];
#ifdef __linux__
    pthread_barrier_init(&g_pb, NULL, N + 1);
#else
    pthread_mutex_init(&g_bar.m, NULL); pthread_cond_init(&g_bar.c, NULL); g_bar.n = N + 1; g_bar.arrived = 0;
#endif
    for (int i = 0; i < N; i++) pthread_create(&ts[i], NULL, report_and_wait, &ids[i]);
    bar_wait();
    for (int i = 0; i < N; i++) pthread_join(ts[i], NULL);
    for (int i = 0; i < N; i++)
        printf("concurrent\t%d\t%llu\tdelta_from_leader=%lld\n", i, (unsigned long long)ids[i], (long long)(ids[i] - leader));

    // Sequential, each joined before the next is created.
    uint64_t prev = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t id = spawn_and_join();
        printf("sequential\t%d\t%llu\tdelta_from_previous=%lld\n", i, (unsigned long long)id, prev ? (long long)(id - prev) : 0LL);
        prev = id;
    }

    // A fork between two thread creations: does the child's pid come from the
    // same counter as thread ids?
    uint64_t before = spawn_and_join();
    pid_t child = fork();
    if (child == 0) _exit(0);
    waitpid(child, NULL, 0);
    uint64_t after = spawn_and_join();
    printf("fork_between\tthread_before\t%llu\n", (unsigned long long)before);
    printf("fork_between\tchild_pid\t%d\n", (int)child);
    printf("fork_between\tthread_after\t%llu\n", (unsigned long long)after);

    // Width: does any id exceed 32 bits?
    printf("width\tleader_high_word\t%llu\n", (unsigned long long)(leader >> 32));

    // Reuse: create-and-join many threads, recording whether any id repeats and
    // whether the sequence ever goes backwards (a wrap).
    if (reuse_rounds > 0) {
        uint64_t first = spawn_and_join(), last = first, min = first, max = first;
        long backwards = 0, repeats_of_first = 0, repeats_of_leader = 0;
        for (int i = 1; i < reuse_rounds; i++) {
            uint64_t id = spawn_and_join();
            if (id < last) {
                if (backwards < 5) printf("reuse\twrap_at_round\t%d\tfrom=%llu\tto=%llu\n", i, (unsigned long long)last, (unsigned long long)id);
                backwards++;
            }
            if (id == first) repeats_of_first++;
            if (id == leader) repeats_of_leader++;
            if (id < min) min = id;
            if (id > max) max = id;
            last = id;
        }
        printf("reuse\trounds\t%d\n", reuse_rounds);
        printf("reuse\tfirst\t%llu\n", (unsigned long long)first);
        printf("reuse\tmin\t%llu\n", (unsigned long long)min);
        printf("reuse\tmax\t%llu\n", (unsigned long long)max);
        printf("reuse\tbackwards_steps\t%ld\n", backwards);
        printf("reuse\tfirst_id_seen_again\t%ld\n", repeats_of_first);
        printf("reuse\tleader_id_seen_again\t%ld\n", repeats_of_leader);
    }
    return 0;
}
