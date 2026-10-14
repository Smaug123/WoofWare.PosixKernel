// Does Darwin's libc offer pipe2, and which flags does it take? Looked up with
// dlsym so the probe builds against an SDK that does not declare it.
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int (*p2)(int[2], int) = (int (*)(int[2], int))dlsym(RTLD_DEFAULT, "pipe2");
    printf("dlsym(pipe2) = %s\n", p2 ? "present" : "absent");
    if (!p2) return 0;
    int flags[] = {0, O_CLOEXEC, O_NONBLOCK, O_CLOEXEC | O_NONBLOCK, 1, O_RDWR, O_APPEND, 0x10000, 0x7fffffff};
    for (unsigned k = 0; k < sizeof flags / sizeof *flags; k++) {
        int z[2] = {-1, -1};
        int rc = p2(z, flags[k]);
        printf("pipe2(%#x) -> %d errno %d fds %d %d", flags[k], rc, rc < 0 ? errno : 0, z[0], z[1]);
        if (rc == 0) {
            printf(" F_GETFL %#x %#x F_GETFD %d %d", fcntl(z[0], F_GETFL), fcntl(z[1], F_GETFL), fcntl(z[0], F_GETFD), fcntl(z[1], F_GETFD));
            close(z[0]); close(z[1]);
        }
        printf("\n");
    }
    return 0;
}
