#define _GNU_SOURCE
#include <grp.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(void) {
    gid_t set[] = {3000, 1000, 2000, 1000};
    int r = setgroups(4, set);
    printf("setgroups({3000,1000,2000,1000}) = %d %s\n", r, r ? strerror(errno) : "");
    gid_t got[16];
    int n = getgroups(16, got);
    printf("getgroups -> %d:", n);
    for (int i = 0; i < n; i++) printf(" %u", got[i]);
    printf("\n");
    return 0;
}
