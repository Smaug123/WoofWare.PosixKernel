// waitpid and waitid in a process that has no children.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    alarm(10);
    int st;
    pid_t r = waitpid(-1, &st, 0);
    printf("waitpid(-1,0)\tret=%d\terrno=%d (%s)\n", (int)r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "");
    r = waitpid(-1, &st, WNOHANG);
    printf("waitpid(-1,WNOHANG)\tret=%d\terrno=%d (%s)\n", (int)r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "");
    r = waitpid(getpid(), &st, WNOHANG);
    printf("waitpid(self,WNOHANG)\tret=%d\terrno=%d (%s)\n", (int)r, r < 0 ? errno : 0, r < 0 ? strerror(errno) : "");
    siginfo_t si;
    int w = waitid(P_ALL, 0, &si, WEXITED | WNOHANG);
    printf("waitid(P_ALL,WNOHANG)\tret=%d\terrno=%d (%s)\n", w, w < 0 ? errno : 0, w < 0 ? strerror(errno) : "");
    return 0;
}
