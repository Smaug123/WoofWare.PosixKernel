// Darwin devfs: is a device's atime set when it is read, or when it is next
// stat'ed after a read; and does every read move it, however close together?
// Writes likewise for mtime/ctime. Reads /dev/zero, writes /dev/null.
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); return t.tv_sec + t.tv_nsec / 1e9; }
static double tsd(struct timespec t) { return t.tv_sec + t.tv_nsec / 1e9; }
int main(void) {
    alarm(30);
    char b[16];
    int z = open("/dev/zero", O_RDONLY), n = open("/dev/null", O_WRONLY);
    struct stat s;
    double t0 = now();
    read(z, b, 16);
    usleep(1500000);
    double t1 = now();
    fstat(z, &s);
    printf("READ at %.6f, fstat at %.6f: atime %.6f (%s)\n", t0, t1, tsd(s.st_atimespec),
           tsd(s.st_atimespec) < t0 + 0.5 ? "set at the read" : "set at the stat");
    for (int i = 0; i < 5; i++) {
        double t = now();
        read(z, b, 16);
        fstat(z, &s);
        printf("READ %d at %.6f atime %.6f\n", i, t, tsd(s.st_atimespec));
        usleep(20000);
    }
    t0 = now();
    write(n, b, 16);
    usleep(1500000);
    t1 = now();
    fstat(n, &s);
    printf("WRITE at %.6f, fstat at %.6f: mtime %.6f ctime %.6f atime %.6f\n", t0, t1, tsd(s.st_mtimespec), tsd(s.st_ctimespec), tsd(s.st_atimespec));
    // a zero-length read and a zero-length write
    usleep(1100000);
    t0 = now();
    read(z, b, 0);
    fstat(z, &s);
    printf("READ0 at %.6f atime %.6f\n", t0, tsd(s.st_atimespec));
    t0 = now();
    write(n, b, 0);
    fstat(n, &s);
    printf("WRITE0 at %.6f mtime %.6f\n", t0, tsd(s.st_mtimespec));
    // open alone, and close
    usleep(1100000);
    t0 = now();
    int z2 = open("/dev/zero", O_RDONLY);
    close(z2);
    fstat(z, &s);
    printf("OPEN+CLOSE at %.6f atime %.6f mtime %.6f ctime %.6f\n", t0, tsd(s.st_atimespec), tsd(s.st_mtimespec), tsd(s.st_ctimespec));
    return 0;
}
