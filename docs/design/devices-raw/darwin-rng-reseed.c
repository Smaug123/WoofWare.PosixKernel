// Darwin: when the process generator behind arc4random_buf and
// CCRandomGenerateBytes goes back to getentropy as time passes, and for how
// many bytes. Draws after a sequence of sleeps and reports, for each draw, the
// time since the last reseed and the getentropy calls the draw made (run with
// DYLD_INSERT_LIBRARIES=libinterpose.dylib from darwin-rng-interpose.c).
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <CommonCrypto/CommonRandom.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec / 1e9; }
int main(int argc, char **argv) {
    alarm(400);
    int *calls = dlsym(RTLD_DEFAULT, "interposed_calls");
    char *log = dlsym(RTLD_DEFAULT, "interposed_log");
    if (!calls) { printf("not interposed\n"); return 1; }
    int useArc4 = argc > 1 && !strcmp(argv[1], "arc4");
    unsigned char b[64];
    int sleeps[] = {0, 2, 5, 10, 15, 20, 25, 30, 40, 50, 60, 70};
    double lastReseed = now();
    for (unsigned i = 0; i < sizeof sleeps / sizeof *sleeps; i++) {
        sleep(sleeps[i]);
        int before = *calls;
        log[0] = 0;
        double t = now();
        if (useArc4) arc4random_buf(b, 64); else CCRandomGenerateBytes(b, 64);
        int made = *calls - before;
        printf("%s draw after %.1fs since last reseed: getentropy calls=%d [%s]\n", useArc4 ? "arc4random_buf" : "CCRandomGenerateBytes", t - lastReseed, made, log);
        if (made) lastReseed = t;
    }
    return 0;
}
