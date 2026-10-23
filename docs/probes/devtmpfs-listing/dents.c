/* Print every record getdents64 yields for each directory named on the command
 * line, and that directory's own st_ino and st_dev, so that what `.` and `..`
 * report can be read against them.
 *
 *   DIR <path> st_ino=<n> st_dev=<major>:<minor>
 *   DENT <path> <d_ino> <d_type> <name>
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int main(int argc, char **argv) {
  for (int i = 1; i < argc; i++) {
    struct stat st;
    if (stat(argv[i], &st) != 0) { perror(argv[i]); return 1; }
    printf("DIR %s st_ino=%llu st_dev=%u:%u\n", argv[i], (unsigned long long)st.st_ino, major(st.st_dev), minor(st.st_dev));
    int fd = open(argv[i], O_RDONLY | O_DIRECTORY);
    if (fd < 0) { perror(argv[i]); return 1; }
    char buf[65536];
    for (;;) {
      long n = syscall(SYS_getdents64, fd, buf, sizeof buf);
      if (n < 0) { perror("getdents64"); return 1; }
      if (n == 0) break;
      for (long off = 0; off < n;) {
        struct dirent64 *d = (struct dirent64 *)(buf + off);
        printf("DENT %s %llu %u %s\n", argv[i], (unsigned long long)d->d_ino, d->d_type, d->d_name);
        off += d->d_reclen;
      }
    }
    close(fd);
  }
  return 0;
}
