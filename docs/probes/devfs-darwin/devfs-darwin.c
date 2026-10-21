// Darwin's devfs, as an unprivileged process sees it: the status of `/dev`,
// its memory and random nodes and a subdirectory; what a listing reports and
// when it moves a directory's access time; what a directory descriptor on it
// answers to read, lseek and fstatfs; and the errno of each call that would
// create, remove or rename a name in it, and of the attribute changes, so
// that their order against the checks every filesystem makes can be read off.
//
// Darwin only, and never as root: as root the namespace rows would change the
// machine's /dev. Run as an ordinary user, from anywhere:
//   cc -Wall -Werror -o /tmp/devfs-darwin devfs-darwin.c && /tmp/devfs-darwin
// It reads /dev and /dev/monotonic (a directory every arm64 Mac measured so
// far holds) and nothing else of the machine's tree. The only things it
// changes are the times of /dev/null (utimes with a NULL times pointer), and,
// when the caller owns /dev/console, that node's times and mode, each put
// back as it was (CONSOLE rows). Every name it tries to create in /dev is
// refused; a row that is not refused says so (UNEXPECTED), and the probe
// stops there.
//
// Rows (tab-separated):
//   BOOT <sec> <usec>                      kern.boottime
//   STAT <path> type= mode= uid= gid= ino= nlink= size= blksize= blocks=
//        rdev=<major>,<minor> dev= atime= mtime= ctime= birth=
//   DENT <path> <d_ino> <d_type> <name>    every record of a full listing
//   DIRFD <op> -> <result>                 a descriptor open on /dev
//   STATFS <path> type= name= bsize= iosize= fsid= owner= flags= flags_ext= subtype= on= from=
//        blocks= bfree= bavail= files= ffree=
//   TIMES <dir> <step> clock=<before the step> atime= mtime= ctime=
//   NS <call> -> <ok|errno>
//   CONSOLE <op> -> <ok|errno> ...
#ifndef __APPLE__
#error "Darwin only"
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/clonefile.h>
#include <time.h>
#include <unistd.h>

extern ssize_t __getdirentries64(int fd, void *buf, size_t bufsize, off_t *basep);

static const char *errname(int e) {
  switch (e) {
  case EPERM: return "EPERM";
  case ENOENT: return "ENOENT";
  case EBADF: return "EBADF";
  case EACCES: return "EACCES";
  case EBUSY: return "EBUSY";
  case EEXIST: return "EEXIST";
  case EXDEV: return "EXDEV";
  case ENOTDIR: return "ENOTDIR";
  case EISDIR: return "EISDIR";
  case EINVAL: return "EINVAL";
  case ENOSPC: return "ENOSPC";
  case EROFS: return "EROFS";
  case EMLINK: return "EMLINK";
  case ENAMETOOLONG: return "ENAMETOOLONG";
  case ENOTEMPTY: return "ENOTEMPTY";
  case ENOTSUP: return "ENOTSUP";
  case EOVERFLOW: return "EOVERFLOW";
  case ENXIO: return "ENXIO";
  case ENODEV: return "ENODEV";
  case EFTYPE: return "EFTYPE";
  case ELOOP: return "ELOOP";
  default: {
    static char b[32];
    snprintf(b, sizeof b, "errno%d", e);
    return b;
  }
  }
}

static const char *typeof_mode(mode_t m) {
  switch (m & S_IFMT) {
  case S_IFDIR: return "dir";
  case S_IFCHR: return "chr";
  case S_IFBLK: return "blk";
  case S_IFLNK: return "lnk";
  case S_IFREG: return "reg";
  case S_IFIFO: return "fifo";
  case S_IFSOCK: return "sock";
  default: return "?";
  }
}

static double clock_now(void) {
  struct timespec t;
  clock_gettime(CLOCK_REALTIME, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}

static void stat_row(const char *path) {
  struct stat s;
  if (lstat(path, &s) != 0) {
    printf("STAT\t%s\t-> %s\n", path, errname(errno));
    return;
  }
  printf("STAT\t%s\ttype=%s mode=0%o uid=%u gid=%u ino=%llu nlink=%u size=%lld blksize=%d blocks=%lld "
         "rdev=%d,%d dev=0x%x atime=%ld.%09ld mtime=%ld.%09ld ctime=%ld.%09ld birth=%ld.%09ld\n",
         path, typeof_mode(s.st_mode), s.st_mode & 07777, s.st_uid, s.st_gid, (unsigned long long)s.st_ino,
         s.st_nlink, (long long)s.st_size, s.st_blksize, (long long)s.st_blocks, major(s.st_rdev),
         minor(s.st_rdev), (unsigned)s.st_dev, s.st_atimespec.tv_sec, s.st_atimespec.tv_nsec,
         s.st_mtimespec.tv_sec, s.st_mtimespec.tv_nsec, s.st_ctimespec.tv_sec, s.st_ctimespec.tv_nsec,
         s.st_birthtimespec.tv_sec, s.st_birthtimespec.tv_nsec);
}

static void times_row(const char *dir, const char *step, double clock) {
  struct stat s;
  if (lstat(dir, &s) != 0) {
    printf("TIMES\t%s\t%s\t-> %s\n", dir, step, errname(errno));
    return;
  }
  printf("TIMES\t%s\t%s\tclock=%.9f atime=%ld.%09ld mtime=%ld.%09ld ctime=%ld.%09ld\n", dir, step, clock,
         s.st_atimespec.tv_sec, s.st_atimespec.tv_nsec, s.st_mtimespec.tv_sec, s.st_mtimespec.tv_nsec,
         s.st_ctimespec.tv_sec, s.st_ctimespec.tv_nsec);
}

// One __getdirentries64 call into a buffer of `size` bytes: the number of
// records it returned, or -1.
static long dents_once(int fd, size_t size, const char *path, int print) {
  static char buf[65536];
  off_t base = 0;
  ssize_t n = __getdirentries64(fd, buf, size, &base);
  if (n < 0) return -1;
  long records = 0;
  for (ssize_t off = 0; off < n;) {
    struct dirent *d = (struct dirent *)(buf + off);
    if (print) printf("DENT\t%s\t%llu\t%u\t%s\n", path, (unsigned long long)d->d_ino, d->d_type, d->d_name);
    records++;
    off += d->d_reclen;
  }
  return records;
}

static void list_all(const char *path) {
  int fd = open(path, O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    printf("DENT\t%s\t-> %s\n", path, errname(errno));
    return;
  }
  long r;
  while ((r = dents_once(fd, 65536, path, 1)) > 0) {
  }
  if (r < 0) printf("DENT\t%s\t-> %s\n", path, errname(errno));
  close(fd);
}

static void statfs_row(const char *path) {
  struct statfs f;
  if (statfs(path, &f) != 0) {
    printf("STATFS\t%s\t-> %s\n", path, errname(errno));
    return;
  }
  printf("STATFS\t%s\ttype=%u name=%s bsize=%u iosize=%d fsid=%08x:%08x owner=%u flags=0x%x flags_ext=0x%x "
         "subtype=%u on=%s from=%s blocks=%llu bfree=%llu bavail=%llu files=%llu ffree=%llu\n",
         path, f.f_type, f.f_fstypename, f.f_bsize, f.f_iosize, (unsigned)f.f_fsid.val[0], (unsigned)f.f_fsid.val[1],
         f.f_owner, f.f_flags, f.f_flags_ext, f.f_fssubtype, f.f_mntonname, f.f_mntfromname,
         (unsigned long long)f.f_blocks, (unsigned long long)f.f_bfree, (unsigned long long)f.f_bavail,
         (unsigned long long)f.f_files, (unsigned long long)f.f_ffree);
}

static int unexpected = 0;

// A namespace row: `ret` is the call's return value, and `created` is the
// /dev name it would have made, which must not exist afterwards.
static void ns(const char *call, int ret, const char *created) {
  int e = errno;
  if (ret >= 0) {
    printf("NS\t%s\t-> ok\n", call);
  } else {
    printf("NS\t%s\t-> %s\n", call, errname(e));
  }
  struct stat s;
  if (created != NULL && lstat(created, &s) == 0) {
    printf("UNEXPECTED\t%s made %s\n", call, created);
    unexpected = 1;
  }
}

static void ns_open(const char *path, int flags, const char *flagname, const char *created) {
  char call[512];
  snprintf(call, sizeof call, "open(%s, %s)", path, flagname);
  int fd = open(path, flags, 0644);
  int e = errno;
  if (fd >= 0) close(fd);
  errno = e;
  ns(call, fd, created);
}

#define NS(callstr, expr, created)                                                                                  \
  do {                                                                                                              \
    errno = 0;                                                                                                      \
    int r_ = (expr);                                                                                                \
    ns(callstr, r_, created);                                                                                       \
    if (unexpected) exit(2);                                                                                        \
  } while (0)

static char *repeat(char c, int n) {
  char *s = malloc(n + 6);
  strcpy(s, "/dev/");
  memset(s + 5, c, n);
  s[5 + n] = 0;
  return s;
}

int main(void) {
  if (geteuid() == 0) {
    fprintf(stderr, "devfs-darwin: refusing to run as root, whose namespace rows would change /dev\n");
    return 1;
  }
  alarm(120);
  setvbuf(stdout, NULL, _IOLBF, 0);

  struct timeval boot;
  size_t len = sizeof boot;
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};
  if (sysctl(mib, 2, &boot, &len, NULL, 0) != 0) {
    perror("sysctl");
    return 1;
  }
  struct utsname u;
  uname(&u);
  printf("# %s %s %s, %s\n", u.sysname, u.release, u.machine, u.version);
  printf("# euid=%u egid=%u\n", geteuid(), getegid());
  printf("BOOT\t%ld\t%d\n", (long)boot.tv_sec, (int)boot.tv_usec);

  // Status of the directory, the memory and random nodes, and a subdirectory
  // with its one node.
  const char *paths[] = {"/dev", "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/monotonic",
                         "/dev/monotonic/uncore", "/dev/full", NULL};
  for (int i = 0; paths[i]; i++) stat_row(paths[i]);

  // A full listing of the subdirectory, and the dots and the four nodes of
  // /dev's (whose other records depend on the machine), with the number of
  // records and the sum of (name length + 8) over the records that are not a
  // dot, against which st_size can be read.
  list_all("/dev/monotonic");
  {
    int fd = open("/dev", O_RDONLY | O_DIRECTORY);
    static char buf[65536];
    long records = 0, sum = 0, dirs = 0;
    for (;;) {
      off_t base = 0;
      ssize_t n = __getdirentries64(fd, buf, sizeof buf, &base);
      if (n <= 0) break;
      for (ssize_t off = 0; off < n;) {
        struct dirent *d = (struct dirent *)(buf + off);
        int dot = strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0;
        if (dot || !strcmp(d->d_name, "null") || !strcmp(d->d_name, "zero") || !strcmp(d->d_name, "random") ||
            !strcmp(d->d_name, "urandom") || !strcmp(d->d_name, "monotonic"))
          printf("DENT\t/dev\t%llu\t%u\t%s\n", (unsigned long long)d->d_ino, d->d_type, d->d_name);
        records++;
        if (!dot) {
          sum += d->d_namlen + 8;
          char p[1100];
          snprintf(p, sizeof p, "/dev/%s", d->d_name);
          struct stat s;
          if (lstat(p, &s) == 0 && S_ISDIR(s.st_mode)) dirs++;
        }
        off += d->d_reclen;
      }
    }
    close(fd);
    struct stat s;
    lstat("/dev", &s);
    printf("DENTS\t/dev\trecords=%ld sum_namelen_plus_8=%ld subdirectories=%ld size=%lld nlink=%u\n", records, sum,
           dirs, (long long)s.st_size, s.st_nlink);
  }

  // A descriptor on /dev: what read, lseek and fstatfs answer, and what a
  // listing after an lseek yields.
  {
    int fd = open("/dev", O_RDONLY | O_DIRECTORY);
    char b[16];
    ssize_t n = read(fd, b, sizeof b);
    printf("DIRFD\tread(16)\t-> %s\n", n >= 0 ? "ok" : errname(errno));
    off_t o = lseek(fd, 0, SEEK_CUR);
    printf("DIRFD\tlseek(0, SEEK_CUR) fresh\t-> %lld %s\n", (long long)o, o >= 0 ? "" : errname(errno));
    o = lseek(fd, 0, SEEK_END);
    printf("DIRFD\tlseek(0, SEEK_END)\t-> %lld %s\n", (long long)o, o >= 0 ? "" : errname(errno));
    o = lseek(fd, 0, SEEK_SET);
    printf("DIRFD\tlseek(0, SEEK_SET)\t-> %lld %s\n", (long long)o, o >= 0 ? "" : errname(errno));
    long r = dents_once(fd, 64 * 3, "/dev", 0);
    o = lseek(fd, 0, SEEK_CUR);
    printf("DIRFD\tafter one call of %ld records lseek(0, SEEK_CUR)\t-> %lld\n", r, (long long)o);
    o = lseek(fd, 5, SEEK_SET);
    printf("DIRFD\tlseek(5, SEEK_SET)\t-> %lld %s\n", (long long)o, o >= 0 ? "" : errname(errno));
    o = lseek(fd, -1, SEEK_SET);
    printf("DIRFD\tlseek(-1, SEEK_SET)\t-> %lld %s\n", (long long)o, o >= 0 ? "" : errname(errno));
    struct statfs f;
    if (fstatfs(fd, &f) == 0)
      printf("DIRFD\tfstatfs\t-> type=%u name=%s\n", f.f_type, f.f_fstypename);
    else
      printf("DIRFD\tfstatfs\t-> %s\n", errname(errno));
    close(fd);
  }

  statfs_row("/dev");
  statfs_row("/dev/null");
  statfs_row("/dev/monotonic");

  // When a listing moves a directory's access time: a call that returns
  // records, a second one, the call at the end, and an open and a lookup,
  // each over a second apart, for /dev and the subdirectory.
  const char *dirs[] = {"/dev", "/dev/monotonic", NULL};
  for (int i = 0; dirs[i]; i++) {
    const char *d = dirs[i];
    times_row(d, "start", clock_now());
    usleep(1100000);
    double c = clock_now();
    int fd = open(d, O_RDONLY | O_DIRECTORY);
    times_row(d, "after-open", c);
    usleep(1100000);
    c = clock_now();
    struct stat s;
    char p[64];
    snprintf(p, sizeof p, "%s/nonexistent", d);
    lstat(p, &s);
    times_row(d, "after-failed-lookup", c);
    usleep(1100000);
    c = clock_now();
    long r = dents_once(fd, 64 * 2, d, 0);
    char step[64];
    snprintf(step, sizeof step, "after-call-of-%ld-records", r);
    times_row(d, step, c);
    usleep(1100000);
    c = clock_now();
    r = dents_once(fd, 64 * 2, d, 0);
    snprintf(step, sizeof step, "after-second-call-of-%ld-records", r);
    times_row(d, step, c);
    while (dents_once(fd, 65536, d, 0) > 0) {
    }
    usleep(1100000);
    c = clock_now();
    r = dents_once(fd, 65536, d, 0);
    snprintf(step, sizeof step, "after-call-at-end-of-%ld-records", r);
    times_row(d, step, c);
    close(fd);
  }

  // utimes with no times on a node the caller may write: which times it
  // sets, and to what precision.
  {
    double c = clock_now();
    int r = utimes("/dev/null", NULL);
    printf("NS\tutimes(/dev/null, NULL)\t-> %s\n", r == 0 ? "ok" : errname(errno));
    times_row("/dev/null", "after-utimes-null", c);
    usleep(2200000);
    struct timespec bothNow[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    c = clock_now();
    r = utimensat(AT_FDCWD, "/dev/null", bothNow, 0);
    printf("NS\tutimensat(/dev/null, NOW, NOW)\t-> %s\n", r == 0 ? "ok" : errname(errno));
    times_row("/dev/null", "after-utimensat-now-now", c);
    usleep(2200000);
    c = clock_now();
    r = utimensat(AT_FDCWD, "/dev/null", NULL, 0);
    printf("NS\tutimensat(/dev/null, NULL)\t-> %s\n", r == 0 ? "ok" : errname(errno));
    times_row("/dev/null", "after-utimensat-null", c);
    struct timespec ts[2] = {{1000000000, 123456789}, {1000000000, 987654321}};
    r = utimensat(AT_FDCWD, "/dev/null", ts, 0);
    printf("NS\tutimensat(/dev/null, explicit)\t-> %s\n", r == 0 ? "ok" : errname(errno));
    struct timespec now2[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
    r = utimensat(AT_FDCWD, "/dev/null", now2, 0);
    printf("NS\tutimensat(/dev/null, NOW, OMIT)\t-> %s\n", r == 0 ? "ok" : errname(errno));
    r = utimes("/dev", NULL);
    printf("NS\tutimes(/dev, NULL)\t-> %s\n", r == 0 ? "ok" : errname(errno));
  }

  // A scratch directory on the root filesystem, holding a file f and a
  // directory sub, for the calls that cross between the two filesystems.
  char tmpl[] = "/tmp/devfs-darwin.XXXXXX";
  char *tmp = mkdtemp(tmpl);
  if (!tmp) {
    perror("mkdtemp");
    return 1;
  }
  char tf[256], tl[256], tx[256], tsub[256], tnope[256], tro[256], tron[256], tnox[256], tnoxn[256];
  snprintf(tf, sizeof tf, "%s/f", tmp);
  snprintf(tl, sizeof tl, "%s/l", tmp);
  snprintf(tx, sizeof tx, "%s/x", tmp);
  snprintf(tsub, sizeof tsub, "%s/sub", tmp);
  snprintf(tnope, sizeof tnope, "%s/nope", tmp);
  snprintf(tro, sizeof tro, "%s/ro", tmp);
  snprintf(tron, sizeof tron, "%s/ro/n", tmp);
  snprintf(tnox, sizeof tnox, "%s/nox", tmp);
  snprintf(tnoxn, sizeof tnoxn, "%s/nox/n", tmp);
  close(open(tf, O_CREAT | O_WRONLY, 0644));
  mkdir(tsub, 0755);
  // ro: the caller may search it but not write it; nox: neither.
  mkdir(tro, 0555);
  mkdir(tnox, 0600);
  char call[1024];

  // Creating a name. /dev/n and /dev/monotonic/n are names devfs does not
  // hold; /dev/nope is a directory it does not hold.
  ns_open("/dev/n", O_CREAT | O_WRONLY, "O_CREAT|O_WRONLY", "/dev/n");
  ns_open("/dev/n", O_CREAT | O_RDONLY, "O_CREAT|O_RDONLY", "/dev/n");
  ns_open("/dev/n", O_CREAT | O_EXCL | O_WRONLY, "O_CREAT|O_EXCL|O_WRONLY", "/dev/n");
  ns_open("/dev/null", O_CREAT | O_EXCL | O_WRONLY, "O_CREAT|O_EXCL|O_WRONLY", NULL);
  ns_open("/dev/monotonic", O_CREAT | O_WRONLY, "O_CREAT|O_WRONLY", NULL);
  ns_open("/dev/monotonic", O_CREAT | O_EXCL | O_RDONLY, "O_CREAT|O_EXCL|O_RDONLY", NULL);
  ns_open("/dev/n/", O_CREAT | O_WRONLY, "O_CREAT|O_WRONLY", "/dev/n");
  ns_open("/dev/nope/x", O_CREAT | O_WRONLY, "O_CREAT|O_WRONLY", NULL);
  ns_open("/dev/null/x", O_CREAT | O_WRONLY, "O_CREAT|O_WRONLY", NULL);
  ns_open("/dev/monotonic/n", O_CREAT | O_WRONLY, "O_CREAT|O_WRONLY", "/dev/monotonic/n");
  ns_open("/dev/monotonic/uncore", O_CREAT | O_EXCL | O_WRONLY, "O_CREAT|O_EXCL|O_WRONLY", NULL);
  {
    int lens[] = {31, 32, 255, 256, 0};
    for (int i = 0; lens[i]; i++) {
      char *p = repeat('a', lens[i]);
      snprintf(call, sizeof call, "open(/dev/<%d a>, O_RDONLY)", lens[i]);
      NS(call, open(p, O_RDONLY), NULL);
      snprintf(call, sizeof call, "open(/dev/<%d a>, O_CREAT|O_WRONLY)", lens[i]);
      NS(call, open(p, O_CREAT | O_WRONLY, 0644), p);
      snprintf(call, sizeof call, "mkdir(/dev/<%d a>)", lens[i]);
      NS(call, mkdir(p, 0755), p);
      free(p);
    }
  }
  NS("mkdir(/dev/n)", mkdir("/dev/n", 0755), "/dev/n");
  NS("mkdir(/dev/n/)", mkdir("/dev/n/", 0755), "/dev/n");
  NS("mkdir(/dev/null)", mkdir("/dev/null", 0755), NULL);
  NS("mkdir(/dev/monotonic)", mkdir("/dev/monotonic", 0755), NULL);
  NS("mkdir(/dev/monotonic/)", mkdir("/dev/monotonic/", 0755), NULL);
  NS("mkdir(/dev/nope/x)", mkdir("/dev/nope/x", 0755), NULL);
  NS("mkdir(/dev/null/x)", mkdir("/dev/null/x", 0755), NULL);
  NS("mkdir(/dev/monotonic/n)", mkdir("/dev/monotonic/n", 0755), "/dev/monotonic/n");
  NS("mkdir(/dev)", mkdir("/dev", 0755), NULL);
  NS("mkdir(/dev/.)", mkdir("/dev/.", 0755), NULL);
  NS("mkfifo(/dev/n)", mkfifo("/dev/n", 0644), "/dev/n");
  NS("mkfifo(/dev/null)", mkfifo("/dev/null", 0644), NULL);
  NS("mknod(/dev/n, S_IFCHR, 3,2)", mknod("/dev/n", S_IFCHR | 0644, makedev(3, 2)), "/dev/n");
  NS("mknod(/dev/null, S_IFCHR, 3,2)", mknod("/dev/null", S_IFCHR | 0644, makedev(3, 2)), NULL);
  NS("mknod(/dev/n, S_IFIFO)", mknod("/dev/n", S_IFIFO | 0644, 0), "/dev/n");
  NS("symlink(x, /dev/n)", symlink("x", "/dev/n"), "/dev/n");
  NS("symlink(x, /dev/null)", symlink("x", "/dev/null"), NULL);
  NS("symlink(x, /dev/monotonic)", symlink("x", "/dev/monotonic"), NULL);
  NS("symlink(x, /dev/n/)", symlink("x", "/dev/n/"), "/dev/n");
  NS("symlink(x, /dev/monotonic/n)", symlink("x", "/dev/monotonic/n"), "/dev/monotonic/n");
  NS("link(/dev/null, /dev/n)", link("/dev/null", "/dev/n"), "/dev/n");
  NS("link(/dev/null, /dev/zero)", link("/dev/null", "/dev/zero"), NULL);
  NS("link(/dev/null, /dev/null)", link("/dev/null", "/dev/null"), NULL);
  NS("link(/dev/null, /dev/monotonic/n)", link("/dev/null", "/dev/monotonic/n"), "/dev/monotonic/n");
  NS("link(/dev/null, tmp/l)", link("/dev/null", tl), NULL);
  NS("link(/dev/nope, /dev/n)", link("/dev/nope", "/dev/n"), "/dev/n");
  NS("link(/dev/nope, tmp/l)", link("/dev/nope", tl), NULL);
  NS("link(/dev/monotonic, /dev/n)", link("/dev/monotonic", "/dev/n"), "/dev/n");
  NS("link(/dev/monotonic, tmp/l)", link("/dev/monotonic", tl), NULL);
  NS("link(tmp/f, /dev/n)", link(tf, "/dev/n"), "/dev/n");
  NS("link(tmp/f, /dev/null)", link(tf, "/dev/null"), NULL);
  NS("link(tmp/nope, /dev/n)", link(tnope, "/dev/n"), "/dev/n");
  NS("link(tmp/sub, /dev/n)", link(tsub, "/dev/n"), "/dev/n");
  NS("link(tmp/f, /dev/nope/x)", link(tf, "/dev/nope/x"), NULL);
  NS("link(tmp/f, /dev/null/x)", link(tf, "/dev/null/x"), NULL);
  NS("link(/dev/null, /dev/nope/x)", link("/dev/null", "/dev/nope/x"), NULL);
  NS("link(/dev/null, tmp/f)", link("/dev/null", tf), NULL);
  NS("link(/dev/null, tmp/nope)", link("/dev/null", tnope), NULL);
  NS("link(/dev/null, tmp/ro/n)", link("/dev/null", tron), NULL);
  NS("link(/dev/null, tmp/nox/n)", link("/dev/null", tnoxn), NULL);
  {
    char tn[300];
    snprintf(tn, sizeof tn, "%s/n/", tmp);
    NS("link(/dev/null, tmp/n/)", link("/dev/null", tn), NULL);
  }
  NS("link(tmp/f, tmp/ro/n)", link(tf, tron), NULL);
  NS("rename(/dev/null, tmp/ro/n)", rename("/dev/null", tron), NULL);
  NS("rename(/dev/null, tmp/nox/n)", rename("/dev/null", tnoxn), NULL);
  NS("clonefile(tmp/f, /dev/n)", clonefile(tf, "/dev/n", 0), "/dev/n");
  NS("clonefile(tmp/f, /dev/null)", clonefile(tf, "/dev/null", 0), NULL);
  NS("clonefile(tmp/f, /dev/nope/x)", clonefile(tf, "/dev/nope/x", 0), NULL);
  NS("clonefile(/dev/null, tmp/n)", clonefile("/dev/null", tl, 0), NULL);
  NS("symlink(x, /dev/nope/x)", symlink("x", "/dev/nope/x"), NULL);
  NS("symlink(x, /dev/null/x)", symlink("x", "/dev/null/x"), NULL);
  NS("symlink(x, /dev/monotonic/uncore)", symlink("x", "/dev/monotonic/uncore"), NULL);
  NS("mkdir(/dev/monotonic/uncore)", mkdir("/dev/monotonic/uncore", 0755), NULL);
  NS("mkfifo(/dev/monotonic)", mkfifo("/dev/monotonic", 0644), NULL);
  NS("mkfifo(/dev/n/)", mkfifo("/dev/n/", 0644), "/dev/n");

  // Removing a name.
  NS("unlink(/dev/null)", unlink("/dev/null"), NULL);
  NS("unlink(/dev/null/)", unlink("/dev/null/"), NULL);
  NS("unlink(/dev/null/x)", unlink("/dev/null/x"), NULL);
  NS("unlink(/dev/nope)", unlink("/dev/nope"), NULL);
  NS("unlink(/dev/monotonic)", unlink("/dev/monotonic"), NULL);
  NS("unlink(/dev/monotonic/)", unlink("/dev/monotonic/"), NULL);
  NS("unlink(/dev/monotonic/uncore)", unlink("/dev/monotonic/uncore"), NULL);
  NS("unlink(/dev/monotonic/nope)", unlink("/dev/monotonic/nope"), NULL);
  NS("rmdir(/dev/monotonic)", rmdir("/dev/monotonic"), NULL);
  NS("rmdir(/dev/monotonic/)", rmdir("/dev/monotonic/"), NULL);
  NS("rmdir(/dev/monotonic/.)", rmdir("/dev/monotonic/."), NULL);
  NS("rmdir(/dev/monotonic/..)", rmdir("/dev/monotonic/.."), NULL);
  NS("rmdir(/dev/null)", rmdir("/dev/null"), NULL);
  NS("rmdir(/dev/nope)", rmdir("/dev/nope"), NULL);
  NS("rmdir(/dev/monotonic/uncore)", rmdir("/dev/monotonic/uncore"), NULL);
  NS("rmdir(/dev/monotonic/nope)", rmdir("/dev/monotonic/nope"), NULL);

  // Renaming a name.
  NS("rename(/dev/null, /dev/n)", rename("/dev/null", "/dev/n"), "/dev/n");
  NS("rename(/dev/null, /dev/zero)", rename("/dev/null", "/dev/zero"), NULL);
  NS("rename(/dev/null, /dev/null)", rename("/dev/null", "/dev/null"), NULL);
  NS("rename(/dev/null, /dev/monotonic)", rename("/dev/null", "/dev/monotonic"), NULL);
  NS("rename(/dev/null, /dev/monotonic/n)", rename("/dev/null", "/dev/monotonic/n"), "/dev/monotonic/n");
  NS("rename(/dev/null, /dev/monotonic/uncore)", rename("/dev/null", "/dev/monotonic/uncore"), NULL);
  NS("rename(/dev/null, /dev/n/)", rename("/dev/null", "/dev/n/"), "/dev/n");
  NS("rename(/dev/null/, /dev/n)", rename("/dev/null/", "/dev/n"), "/dev/n");
  NS("rename(/dev/monotonic, /dev/null)", rename("/dev/monotonic", "/dev/null"), NULL);
  NS("rename(/dev/monotonic, /dev/n)", rename("/dev/monotonic", "/dev/n"), "/dev/n");
  NS("rename(/dev/monotonic, /dev/monotonic)", rename("/dev/monotonic", "/dev/monotonic"), NULL);
  NS("rename(/dev/monotonic, /dev/monotonic/n)", rename("/dev/monotonic", "/dev/monotonic/n"), "/dev/monotonic/n");
  NS("rename(/dev/monotonic/uncore, /dev/n)", rename("/dev/monotonic/uncore", "/dev/n"), "/dev/n");
  NS("rename(/dev/monotonic/uncore, /dev/null)", rename("/dev/monotonic/uncore", "/dev/null"), NULL);
  NS("rename(/dev/nope, /dev/n)", rename("/dev/nope", "/dev/n"), "/dev/n");
  NS("rename(/dev/nope, /dev/null)", rename("/dev/nope", "/dev/null"), NULL);
  NS("rename(/dev/nope, tmp/x)", rename("/dev/nope", tx), NULL);
  NS("rename(/dev/null, tmp/x)", rename("/dev/null", tx), NULL);
  NS("rename(/dev/null, tmp/f)", rename("/dev/null", tf), NULL);
  NS("rename(/dev/monotonic, tmp/sub)", rename("/dev/monotonic", tsub), NULL);
  NS("rename(tmp/f, /dev/n)", rename(tf, "/dev/n"), "/dev/n");
  NS("rename(tmp/f, /dev/null)", rename(tf, "/dev/null"), NULL);
  NS("rename(tmp/nope, /dev/n)", rename(tnope, "/dev/n"), "/dev/n");
  NS("rename(tmp/nope, /dev/null)", rename(tnope, "/dev/null"), NULL);
  NS("rename(tmp/sub, /dev/n)", rename(tsub, "/dev/n"), "/dev/n");
  NS("rename(tmp/sub, /dev/monotonic)", rename(tsub, "/dev/monotonic"), NULL);
  {
    char tdot[300], tsubslash[300], tnslash[300];
    snprintf(tdot, sizeof tdot, "%s/.", tmp);
    snprintf(tsubslash, sizeof tsubslash, "%s/sub/", tmp);
    snprintf(tnslash, sizeof tnslash, "%s/n/", tmp);
    NS("rename(/dev/null, tmp/sub)", rename("/dev/null", tsub), NULL);
    NS("rename(/dev/monotonic, tmp/f)", rename("/dev/monotonic", tf), NULL);
    NS("rename(tmp/f, /dev/monotonic)", rename(tf, "/dev/monotonic"), NULL);
    NS("rename(tmp/sub, /dev/null)", rename(tsub, "/dev/null"), NULL);
    NS("rename(/dev/null, tmp/n/)", rename("/dev/null", tnslash), NULL);
    NS("rename(/dev/monotonic, tmp/n/)", rename("/dev/monotonic", tnslash), NULL);
    NS("rename(tmp/sub/, /dev/n)", rename(tsubslash, "/dev/n"), "/dev/n");
    NS("rename(tmp/., /dev/n)", rename(tdot, "/dev/n"), "/dev/n");
    NS("rename(/dev/., tmp/x)", rename("/dev/.", tx), NULL);
    NS("rename(/dev/null, tmp/.)", rename("/dev/null", tdot), NULL);
    NS("rename(tmp/f, /dev/.)", rename(tf, "/dev/."), NULL);
    NS("rename(tmp/f, /dev)", rename(tf, "/dev"), NULL);
    NS("rename(/dev/monotonic, /dev/.)", rename("/dev/monotonic", "/dev/."), NULL);
    NS("rename(/dev/monotonic, /dev/monotonic/..)", rename("/dev/monotonic", "/dev/monotonic/.."), NULL);
    NS("rename(/dev/null, /dev/monotonic/..)", rename("/dev/null", "/dev/monotonic/.."), NULL);
    NS("rename(/dev/null, /dev/monotonic/.)", rename("/dev/null", "/dev/monotonic/."), NULL);
    NS("rename(tmp/sub, /dev/.)", rename(tsub, "/dev/."), NULL);
    NS("rename(tmp/f, /dev/monotonic/.)", rename(tf, "/dev/monotonic/."), NULL);
    NS("rename(/dev/nope, /dev/.)", rename("/dev/nope", "/dev/."), NULL);
    NS("rename(/dev/monotonic/., tmp/x)", rename("/dev/monotonic/.", tx), NULL);
  }
  NS("rename(/dev/null, /dev/nope/x)", rename("/dev/null", "/dev/nope/x"), NULL);
  NS("rename(/dev/monotonic/, /dev/n)", rename("/dev/monotonic/", "/dev/n"), "/dev/n");
  NS("rename(/dev/monotonic, /dev/n/)", rename("/dev/monotonic", "/dev/n/"), "/dev/n");
  NS("rename(/dev/monotonic/uncore, /dev/monotonic/uncore)", rename("/dev/monotonic/uncore", "/dev/monotonic/uncore"), NULL);
  NS("rename(/dev, tmp/x)", rename("/dev", tx), NULL);
  NS("rename(/dev/., /dev/n)", rename("/dev/.", "/dev/n"), "/dev/n");
  NS("rename(/dev/null, /dev/.)", rename("/dev/null", "/dev/."), NULL);
  NS("rmdir(/dev)", rmdir("/dev"), NULL);
  NS("unlink(/dev)", unlink("/dev"), NULL);
  NS("rmdir(/dev/.)", rmdir("/dev/."), NULL);

  // Attribute changes on nodes and directories the caller does not own.
  {
    struct timeval tv[2] = {{1000000000, 123456}, {1000000000, 654321}};
    NS("utimes(/dev/null, explicit)", utimes("/dev/null", tv), NULL);
  }
  NS("chmod(/dev/null, 0666)", chmod("/dev/null", 0666), NULL);
  NS("chmod(/dev/monotonic, 0555)", chmod("/dev/monotonic", 0555), NULL);
  NS("chown(/dev/null, -1, -1)", chown("/dev/null", -1, -1), NULL);
  NS("chown(/dev/null, self, -1)", chown("/dev/null", geteuid(), -1), NULL);
  NS("chown(/dev/monotonic, -1, -1)", chown("/dev/monotonic", -1, -1), NULL);
  NS("truncate(/dev/null, 0)", truncate("/dev/null", 0), NULL);
  NS("truncate(/dev/monotonic, 0)", truncate("/dev/monotonic", 0), NULL);
  NS("access(/dev/null, R_OK|W_OK)", access("/dev/null", R_OK | W_OK), NULL);
  NS("access(/dev/null, X_OK)", access("/dev/null", X_OK), NULL);
  NS("access(/dev, W_OK)", access("/dev", W_OK), NULL);
  NS("access(/dev, R_OK|X_OK)", access("/dev", R_OK | X_OK), NULL);
  NS("access(/dev/monotonic, W_OK)", access("/dev/monotonic", W_OK), NULL);

  // A node the caller owns: /dev/console belongs to the console user. Each
  // change is put back.
  {
    struct stat s;
    if (lstat("/dev/console", &s) == 0 && s.st_uid == geteuid()) {
      struct timespec orig[2] = {s.st_atimespec, s.st_mtimespec};
      mode_t mode = s.st_mode & 07777;
      double c = clock_now();
      int r = chmod("/dev/console", mode);
      int e = errno;
      struct stat t;
      lstat("/dev/console", &t);
      printf("CONSOLE\tchmod(same mode 0%o)\t-> %s clock=%.9f mode=0%o ctime=%ld.%09ld\n", mode,
             r == 0 ? "ok" : errname(e), c, t.st_mode & 07777, t.st_ctimespec.tv_sec, t.st_ctimespec.tv_nsec);
      r = chown("/dev/console", s.st_uid, s.st_gid);
      e = errno;
      printf("CONSOLE\tchown(same owner %u:%u)\t-> %s\n", s.st_uid, s.st_gid, r == 0 ? "ok" : errname(e));
      struct timespec ts[2] = {{1000000000, 123456789}, {1000000001, 987654321}};
      r = utimensat(AT_FDCWD, "/dev/console", ts, 0);
      e = errno;
      lstat("/dev/console", &t);
      printf("CONSOLE\tutimensat(1000000000.123456789, 1000000001.987654321)\t-> %s atime=%ld.%09ld "
             "mtime=%ld.%09ld\n",
             r == 0 ? "ok" : errname(e), t.st_atimespec.tv_sec, t.st_atimespec.tv_nsec, t.st_mtimespec.tv_sec,
             t.st_mtimespec.tv_nsec);
      // Explicit times at the edges: what devfs stores for each, through
      // utimensat (atime, mtime) and the birth time it then reports.
      struct {
        long long sec;
        long nsec;
      } edges[] = {{0, 0},
                   {0, 999},
                   {1, 1000},
                   {-1, 500000000},
                   {-1000000, 0},
                   {5, 1500000000},
                   {5, -3},
                   {4294967296LL, 5000},
                   {8589934592LL, 123456789},
                   {9223372036LL, 854775807},
                   {9223372037LL, 0},
                   {9223372036854775807LL, 999999999},
                   {-9223372036854775807LL - 1, 0}};
      for (size_t i = 0; i < sizeof edges / sizeof edges[0]; i++) {
        struct timespec e2[2] = {{edges[i].sec, edges[i].nsec}, {edges[i].sec, edges[i].nsec}};
        double c2 = clock_now();
        r = utimensat(AT_FDCWD, "/dev/console", e2, 0);
        e = errno;
        lstat("/dev/console", &t);
        printf("CONSOLE\tutimensat(%lld.%ld both)\t-> %s atime=%ld.%09ld mtime=%ld.%09ld ctime=%ld.%09ld "
               "birth=%ld.%09ld clock=%.9f\n",
               edges[i].sec, edges[i].nsec, r == 0 ? "ok" : errname(e), t.st_atimespec.tv_sec,
               t.st_atimespec.tv_nsec, t.st_mtimespec.tv_sec, t.st_mtimespec.tv_nsec, t.st_ctimespec.tv_sec,
               t.st_ctimespec.tv_nsec, t.st_birthtimespec.tv_sec, t.st_birthtimespec.tv_nsec, c2);
      }
      r = utimensat(AT_FDCWD, "/dev/console", orig, 0);
      e = errno;
      lstat("/dev/console", &t);
      printf("CONSOLE\trestore times\t-> %s atime=%ld.%09ld mtime=%ld.%09ld\n", r == 0 ? "ok" : errname(e),
             t.st_atimespec.tv_sec, t.st_atimespec.tv_nsec, t.st_mtimespec.tv_sec, t.st_mtimespec.tv_nsec);
    } else {
      printf("CONSOLE\tskipped: /dev/console is not the caller's\n");
    }
  }

  unlink(tf);
  rmdir(tsub);
  rmdir(tro);
  rmdir(tnox);
  rmdir(tmp);
  return unexpected ? 2 : 0;
}
