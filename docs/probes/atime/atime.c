// Which calls move a file's access time, and when, on the mount holding a
// directory: each call on a fresh file whose three times were first put in a
// chosen relation to each other and to now, reporting whether st_atime moved.
//
// Usage: atime <dir> <mount-label> [clock]
//   Without `clock`, runs every state against every call, as whoever runs it
//   (the run scripts use uid 1000 on Linux and uid 501 on Darwin, the owner of
//   <dir>).
//   With `clock` (Linux, root, CAP_SYS_TIME), runs the 24-hour rows: a file
//   read once, so that its atime is after its mtime and ctime, read again after
//   the realtime clock is stepped forward 23 h and then 25 h past that atime.
//   Run it in a VM of its own: it moves the machine's clock.
//
// Build and run: see run-linux.sh and run-darwin.sh beside this file.
//
// States (the times each row's target has before its call):
//   created     - as created, then 30 ms of sleep: atime = mtime = ctime.
//   written     - created, 30 ms, one byte appended (mtime and ctime move), 30 ms.
//                 For a directory, an entry created; for a link, nothing more.
//   read        - created, 30 ms, the row's own call made once, 30 ms: the row
//                 is the second call. So atime is after mtime and ctime, and recent.
//   future      - utimensat: atime now + 1 h, mtime now - 1 h; so ctime (now)
//                 is before atime and after mtime.
//   read-older  - as `read`, then utimensat: atime now - 2 h, mtime now - 1 h.
//                 For getdents-eof, a call at the end of a directory whose
//                 atime is before its mtime.
//   equal       - utimensat: atime and mtime both now - 1 h; ctime is now.
//   older       - utimensat: atime now - 2 h, mtime now - 1 h; ctime is now.
//   past-<h>    - utimensat: atime now - <h> hours, mtime an hour before that;
//                 ctime is now, so after both. <h> is 1, 23, 25, 48, 720 and
//                 9000.
//
// Calls (the target is f, a 4096-byte file, unless named):
//   read1        read(2) of 1 byte at offset 0.
//   read0        read(2) of 0 bytes.
//   readeof      read(2) of 16 bytes at end of file (answers 0).
//   pread1       pread(2) of 1 byte at offset 0.
//   readv1       readv(2) of 1 byte at offset 0.
//   empty-read   read(2) of 16 bytes from an empty file e (answers 0).
//   getdents     one getdents call (Linux getdents64, Darwin getdirentries64)
//                with a 64 KiB buffer on directory d.
//   getdents-eof a second such call, at the end of d (answers 0); `read` and
//                `read-older` make the first call. Runs only in those states.
//   readlink     readlink(2) of symlink l (pointing at f): l's atime.
//   read-efault, pread-efault, getdents-efault, readlink-efault
//                the call into a PROT_NONE buffer (answers EFAULT).
//   readeof-efault read(2) of 16 bytes at end of file into a PROT_NONE buffer.
//   read-efault-kernel read(2) of 16 bytes into 0xFFFFFFFFFFFFF000, an address
//                in the kernel's half, which Linux screens before the read.
//   pread0       pread(2) of 0 bytes at offset 0.
//   preadeof     pread(2) of 16 bytes at offset 4096 (answers 0).
//   read-at-max  read(2) of 16 bytes at position INT64_MAX (lseek first).
//   pread-at-max pread(2) of 16 bytes at offset INT64_MAX.
//   read-big     read(2) of 0x80000000 bytes, past Darwin's INT_MAX limit.
//   read-dir     read(2) of 16 bytes from directory d (answers EISDIR).
//   follow       stat(2) through l: l's atime (the target's row is follow-target).
//   follow-target stat(2) through l: f's atime.
//   lstat        lstat(2) of l: l's atime.
//   open         open(2) O_RDONLY then close(2), no read.
//   lookup       stat(2) of d/x: d's atime.
//   write        write(2) of 1 byte at offset 0 (atime should not move).
//   utime-atime  utimensat(2), atime UTIME_NOW, mtime UTIME_OMIT.
//   mmap         mmap(2) of f, no access, munmap.
//   mmap-touch   mmap(2) of f, one byte read through it, munmap.
//   exec         fork and execve(2) of x, a copy of /bin/true (or /usr/bin/true):
//                x's atime.
//   cfr          Linux: copy_file_range(2) of 1 byte from f to a new file.
//   sendfile     Linux: sendfile(2) of 1 byte from f to a new file.
//   noatime-read Linux: read1 through a descriptor opened with O_NOATIME.
//   dev-null     read(2) of 16 bytes from /dev/null: its atime.
//   dev-urandom  read(2) of 16 bytes from /dev/urandom: its atime.
//
// Columns: `ret` is the call's return value (or -errno); `atime` the atime
// before and after; `moved` whether it changed; `mtime` and `ctime` whether
// those moved; `events` the inotify events (Linux, IN_ACCESS|IN_ATTRIB|IN_MODIFY)
// or the kqueue vnode notes (Darwin, NOTE_ATTRIB|NOTE_WRITE|NOTE_EXTEND) the
// call raised on the target, or `-` for none.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/inotify.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>
#define ATIM(st) ((st).st_atim)
#define MTIM(st) ((st).st_mtim)
#define CTIM(st) ((st).st_ctim)
#else
#include <sys/event.h>
#include <sys/syscall.h>
#define ATIM(st) ((st).st_atimespec)
#define MTIM(st) ((st).st_mtimespec)
#define CTIM(st) ((st).st_ctimespec)
#endif

static char dir[4096];
static const char *label;

static void path(char *out, const char *name) {
  snprintf(out, 4096, "%s/%s", dir, name);
}

static void die(const char *what) {
  fprintf(stderr, "FATAL %s: %s\n", what, strerror(errno));
  exit(2);
}

static void nap(void) {
  struct timespec ts = {0, 30 * 1000 * 1000};
  nanosleep(&ts, NULL);
}

static int same(struct timespec a, struct timespec b) {
  return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

static const char *exe_source(void) {
  if (access("/bin/true", X_OK) == 0)
    return "/bin/true";
  return "/usr/bin/true";
}

// Make the fixture afresh: f (4096 bytes), e (empty), d (holding x), l -> f,
// x (an executable copy of true).
static void fixture(void) {
  char cmd[9000];
  snprintf(cmd, sizeof cmd, "rm -rf '%s'/f '%s'/e '%s'/d '%s'/l '%s'/x '%s'/out", dir, dir, dir, dir,
           dir, dir);
  if (system(cmd) != 0)
    die("rm");
  char p[4096];
  path(p, "f");
  int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd < 0)
    die("create f");
  char buf[4096];
  memset(buf, 'x', sizeof buf);
  if (write(fd, buf, sizeof buf) != (ssize_t)sizeof buf)
    die("fill f");
  close(fd);
  path(p, "e");
  fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd < 0)
    die("create e");
  close(fd);
  path(p, "d");
  if (mkdir(p, 0755) != 0)
    die("mkdir d");
  path(p, "d/x");
  fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0644);
  if (fd < 0)
    die("create d/x");
  close(fd);
  path(p, "l");
  if (symlink("f", p) != 0)
    die("symlink l");
  snprintf(cmd, sizeof cmd, "cp '%s' '%s'/x && chmod 0755 '%s'/x", exe_source(), dir, dir);
  if (system(cmd) != 0)
    die("cp true");
}

// The object a call's atime is read from, and whether to stat it without
// following a link.
struct target {
  const char *name; // relative to dir, or absolute when it starts with '/'
  int nofollow;
};

static struct target target_of(const char *op) {
  struct target t = {"f", 0};
  if (!strcmp(op, "getdents") || !strcmp(op, "getdents-eof") || !strcmp(op, "getdents-efault") ||
      !strcmp(op, "lookup") || !strcmp(op, "read-dir"))
    t.name = "d";
  else if (!strcmp(op, "readlink") || !strcmp(op, "readlink-efault") || !strcmp(op, "follow") ||
           !strcmp(op, "lstat")) {
    t.name = "l";
    t.nofollow = 1;
  } else if (!strcmp(op, "empty-read"))
    t.name = "e";
  else if (!strcmp(op, "exec"))
    t.name = "x";
  else if (!strcmp(op, "dev-null"))
    t.name = "/dev/null";
  else if (!strcmp(op, "dev-urandom"))
    t.name = "/dev/urandom";
  return t;
}

static void target_path(char *out, struct target t) {
  if (t.name[0] == '/')
    snprintf(out, 4096, "%s", t.name);
  else
    path(out, t.name);
}

static int stat_target(struct target t, struct stat *st) {
  char p[4096];
  target_path(p, t);
  return t.nofollow ? lstat(p, st) : stat(p, st);
}

static int open_read(const char *name, int extra) {
  char p[4096];
  if (name[0] == '/')
    snprintf(p, sizeof p, "%s", name);
  else
    path(p, name);
  return open(p, O_RDONLY | extra);
}

static long getdents_into(int fd, void *buf, size_t size) {
#ifdef __linux__
  return syscall(SYS_getdents64, fd, buf, size);
#else
  long base = 0;
  return syscall(344 /* SYS_getdirentries64 */, fd, buf, size, &base);
#endif
}

static long getdents_once(int fd) {
  static char buf[65536];
  return getdents_into(fd, buf, sizeof buf);
}

// A page no call can copy into or out of.
static void *bad_page(void) {
  static void *page = NULL;
  if (page == NULL) {
    page = mmap(NULL, 65536, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED)
      die("mmap PROT_NONE");
  }
  return page;
}

// For getdents-eof: the descriptor whose first call the state made.
static int held_fd = -1;

static long result(long r) { return r < 0 ? -errno : r; }

static long do_op(const char *op) {
  char p[4096], q[4096];
  char b[16];
  long r;
  int fd;
  if (!strcmp(op, "read1") || !strcmp(op, "read0") || !strcmp(op, "readeof") ||
      !strcmp(op, "pread1") || !strcmp(op, "readv1") || !strcmp(op, "empty-read") ||
      !strcmp(op, "dev-null") || !strcmp(op, "dev-urandom")) {
    struct target t = target_of(op);
    fd = open_read(t.name, 0);
    if (fd < 0)
      return -errno;
    if (!strcmp(op, "read1"))
      r = result(read(fd, b, 1));
    else if (!strcmp(op, "read0"))
      r = result(read(fd, b, 0));
    else if (!strcmp(op, "readeof")) {
      lseek(fd, 0, SEEK_END);
      r = result(read(fd, b, 16));
    } else if (!strcmp(op, "pread1"))
      r = result(pread(fd, b, 1, 0));
    else if (!strcmp(op, "readv1")) {
      struct iovec v = {b, 1};
      r = result(readv(fd, &v, 1));
    } else
      r = result(read(fd, b, 16));
    close(fd);
    return r;
  }
  if (!strcmp(op, "getdents")) {
    fd = open_read("d", O_DIRECTORY);
    if (fd < 0)
      return -errno;
    r = result(getdents_once(fd));
    close(fd);
    return r;
  }
  if (!strcmp(op, "getdents-eof")) {
    if (held_fd < 0) {
      held_fd = open_read("d", O_DIRECTORY);
      if (held_fd < 0)
        return -errno;
    }
    r = result(getdents_once(held_fd));
    return r;
  }
  if (!strcmp(op, "readlink")) {
    path(p, "l");
    return result(readlink(p, q, sizeof q));
  }
  if (!strcmp(op, "readlink-efault")) {
    path(p, "l");
    return result(readlink(p, bad_page(), 4096));
  }
  if (!strcmp(op, "read-efault") || !strcmp(op, "pread-efault")) {
    fd = open_read("f", 0);
    if (fd < 0)
      return -errno;
    if (!strcmp(op, "read-efault"))
      r = result(read(fd, bad_page(), 16));
    else
      r = result(pread(fd, bad_page(), 16, 0));
    close(fd);
    return r;
  }
  if (!strcmp(op, "readeof-efault") || !strcmp(op, "read-efault-kernel") ||
      !strcmp(op, "pread0") || !strcmp(op, "preadeof") || !strcmp(op, "read-at-max") ||
      !strcmp(op, "pread-at-max") || !strcmp(op, "read-big")) {
    fd = open_read("f", 0);
    if (fd < 0)
      return -errno;
    if (!strcmp(op, "readeof-efault")) {
      lseek(fd, 0, SEEK_END);
      r = result(read(fd, bad_page(), 16));
    } else if (!strcmp(op, "read-efault-kernel"))
      r = result(read(fd, (void *)(uintptr_t)0xFFFFFFFFFFFFF000ull, 16));
    else if (!strcmp(op, "pread0"))
      r = result(pread(fd, b, 0, 0));
    else if (!strcmp(op, "preadeof"))
      r = result(pread(fd, b, 16, 4096));
    else if (!strcmp(op, "read-at-max")) {
      if (lseek(fd, INT64_MAX, SEEK_SET) < 0)
        r = -100000 - errno;
      else
        r = result(read(fd, b, 16));
    } else if (!strcmp(op, "pread-at-max"))
      r = result(pread(fd, b, 16, INT64_MAX));
    else {
      // Room for all of f, which is what Linux moves of the count.
      static char big[8192];
      r = result(read(fd, big, 0x80000000ul));
    }
    close(fd);
    return r;
  }
  if (!strcmp(op, "read-dir")) {
    fd = open_read("d", O_DIRECTORY);
    if (fd < 0)
      return -errno;
    r = result(read(fd, b, 16));
    close(fd);
    return r;
  }
  if (!strcmp(op, "getdents-efault")) {
    fd = open_read("d", O_DIRECTORY);
    if (fd < 0)
      return -errno;
    r = result(getdents_into(fd, bad_page(), 65536));
    close(fd);
    return r;
  }
  if (!strcmp(op, "follow") || !strcmp(op, "follow-target")) {
    struct stat st;
    path(p, "l");
    return result(stat(p, &st));
  }
  if (!strcmp(op, "lstat")) {
    struct stat st;
    path(p, "l");
    return result(lstat(p, &st));
  }
  if (!strcmp(op, "open")) {
    fd = open_read("f", 0);
    if (fd < 0)
      return -errno;
    close(fd);
    return 0;
  }
  if (!strcmp(op, "lookup")) {
    struct stat st;
    path(p, "d/x");
    return result(stat(p, &st));
  }
  if (!strcmp(op, "write")) {
    path(p, "f");
    fd = open(p, O_WRONLY);
    if (fd < 0)
      return -errno;
    r = result(pwrite(fd, "y", 1, 0));
    close(fd);
    return r;
  }
  if (!strcmp(op, "utime-atime")) {
    struct timespec ts[2] = {{0, UTIME_NOW}, {0, UTIME_OMIT}};
    path(p, "f");
    return result(utimensat(AT_FDCWD, p, ts, 0));
  }
  if (!strcmp(op, "mmap") || !strcmp(op, "mmap-touch")) {
    fd = open_read("f", 0);
    if (fd < 0)
      return -errno;
    volatile char *m = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
      r = -errno;
      close(fd);
      return r;
    }
    r = 0;
    if (!strcmp(op, "mmap-touch"))
      r = m[0];
    munmap((void *)m, 4096);
    close(fd);
    return r;
  }
  if (!strcmp(op, "exec")) {
    path(p, "x");
    pid_t pid = fork();
    if (pid == 0) {
      char *argv[] = {p, NULL};
      char *envp[] = {NULL};
      execve(p, argv, envp);
      _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1000 - WTERMSIG(status);
  }
#ifdef __linux__
  if (!strcmp(op, "cfr") || !strcmp(op, "sendfile")) {
    fd = open_read("f", 0);
    if (fd < 0)
      return -errno;
    path(q, "out");
    int out = open(q, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0)
      die("create out");
    if (!strcmp(op, "cfr"))
      r = result(copy_file_range(fd, NULL, out, NULL, 1, 0));
    else
      r = result(sendfile(out, fd, NULL, 1));
    close(out);
    close(fd);
    return r;
  }
  if (!strcmp(op, "noatime-read")) {
    fd = open_read("f", O_NOATIME);
    if (fd < 0)
      return -errno;
    r = result(read(fd, b, 1));
    close(fd);
    return r;
  }
#endif
  fprintf(stderr, "unknown op %s\n", op);
  exit(2);
}

// Put the target in a state; answers 0, or -1 where the state does not apply.
static int set_state(const char *state, const char *op, struct target t) {
  char p[4096];
  target_path(p, t);
  if (!strcmp(state, "created")) {
    nap();
    return 0;
  }
  if (!strcmp(state, "written")) {
    if (t.name[0] == '/')
      return -1;
    nap();
    if (!strcmp(t.name, "d")) {
      char q[4096];
      path(q, "d/y");
      int fd = open(q, O_WRONLY | O_CREAT | O_EXCL, 0644);
      if (fd < 0)
        die("create d/y");
      close(fd);
    } else if (!strcmp(t.name, "l")) {
      return -1;
    } else {
      // Appended, so that x stays a program.
      int fd = open(p, O_WRONLY | O_APPEND);
      if (fd < 0)
        die("open for state write");
      if (write(fd, "z", 1) != 1)
        die("state write");
      close(fd);
    }
    nap();
    return 0;
  }
  if (!strcmp(state, "read")) {
    nap();
    do_op(op);
    nap();
    return 0;
  }
  if (!strcmp(state, "read-older")) {
    if (t.name[0] == '/')
      return -1;
    nap();
    do_op(op);
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    struct timespec ts[2] = {{now.tv_sec - 7200, 0}, {now.tv_sec - 3600, 0}};
    if (utimensat(AT_FDCWD, p, ts, t.nofollow ? AT_SYMLINK_NOFOLLOW : 0) != 0)
      die("utimensat state");
    nap();
    return 0;
  }
  if (t.name[0] == '/')
    return -1;
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  struct timespec ts[2];
  if (!strcmp(state, "future")) {
    ts[0].tv_sec = now.tv_sec + 3600;
    ts[1].tv_sec = now.tv_sec - 3600;
  } else if (!strcmp(state, "equal")) {
    ts[0].tv_sec = now.tv_sec - 3600;
    ts[1].tv_sec = now.tv_sec - 3600;
  } else if (!strcmp(state, "older")) {
    ts[0].tv_sec = now.tv_sec - 7200;
    ts[1].tv_sec = now.tv_sec - 3600;
  } else if (!strncmp(state, "past-", 5)) {
    long h = atol(state + 5);
    ts[0].tv_sec = now.tv_sec - h * 3600;
    ts[1].tv_sec = ts[0].tv_sec - 3600;
  } else {
    fprintf(stderr, "unknown state %s\n", state);
    exit(2);
  }
  ts[0].tv_nsec = 0;
  ts[1].tv_nsec = 0;
  if (utimensat(AT_FDCWD, p, ts, t.nofollow ? AT_SYMLINK_NOFOLLOW : 0) != 0)
    die("utimensat state");
  nap();
  return 0;
}

// Darwin: the descriptor the kqueue watches, which closing the kqueue does not
// close.
static int watched_fd = -1;

// Start watching the target for the events the columns name; answers a handle.
static int watch(struct target t) {
  char p[4096];
  target_path(p, t);
#ifdef __linux__
  int in = inotify_init1(IN_NONBLOCK);
  if (in < 0)
    die("inotify_init1");
  if (inotify_add_watch(in, p, IN_ACCESS | IN_ATTRIB | IN_MODIFY | IN_DONT_FOLLOW) < 0)
    die("inotify_add_watch");
  return in;
#else
  int kq = kqueue();
  if (kq < 0)
    die("kqueue");
  int fd = open(p, O_EVTONLY | (t.nofollow ? O_SYMLINK : 0));
  if (fd < 0)
    die("open O_EVTONLY");
  watched_fd = fd;
  struct kevent ev;
  EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_ATTRIB | NOTE_WRITE | NOTE_EXTEND, 0, NULL);
  if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0)
    die("kevent add");
  return kq;
#endif
}

static void events(int handle, char *out) {
  out[0] = 0;
#ifdef __linux__
  char buf[4096];
  unsigned mask = 0;
  ssize_t n;
  while ((n = read(handle, buf, sizeof buf)) > 0) {
    for (char *c = buf; c < buf + n;) {
      struct inotify_event *e = (struct inotify_event *)c;
      mask |= e->mask;
      c += sizeof *e + e->len;
    }
  }
  if (mask & IN_ACCESS)
    strcat(out, "ACCESS,");
  if (mask & IN_ATTRIB)
    strcat(out, "ATTRIB,");
  if (mask & IN_MODIFY)
    strcat(out, "MODIFY,");
#else
  struct kevent ev;
  struct timespec zero = {0, 0};
  unsigned fflags = 0;
  while (kevent(handle, NULL, 0, &ev, 1, &zero) > 0)
    fflags |= ev.fflags;
  if (fflags & NOTE_ATTRIB)
    strcat(out, "ATTRIB,");
  if (fflags & NOTE_WRITE)
    strcat(out, "WRITE,");
  if (fflags & NOTE_EXTEND)
    strcat(out, "EXTEND,");
#endif
  size_t len = strlen(out);
  if (len == 0)
    strcpy(out, "-");
  else
    out[len - 1] = 0;
}

static void row(const char *state, const char *op) {
  fixture();
  held_fd = -1;
  struct target t = target_of(op);
  if (set_state(state, op, t) != 0)
    return;
  struct stat before, after;
  if (stat_target(t, &before) != 0)
    die("stat before");
  int handle = watch(t);
  long r = do_op(op);
  if (stat_target(t, &after) != 0)
    die("stat after");
  char ev[64];
  events(handle, ev);
  close(handle);
  if (watched_fd >= 0) {
    close(watched_fd);
    watched_fd = -1;
  }
  if (held_fd >= 0)
    close(held_fd);
  printf("%s %s %s ret=%ld atime=%lld.%09ld->%lld.%09ld moved=%d mtime=%d ctime=%d events=%s\n", label,
         state, op, r, (long long)ATIM(before).tv_sec, ATIM(before).tv_nsec,
         (long long)ATIM(after).tv_sec, ATIM(after).tv_nsec, !same(ATIM(before), ATIM(after)),
         !same(MTIM(before), MTIM(after)), !same(CTIM(before), CTIM(after)), ev);
  fflush(stdout);
}

#ifdef __linux__
// Step the realtime clock to `to` seconds.
static void set_clock(time_t to) {
  struct timespec ts = {to, 0};
  if (clock_settime(CLOCK_REALTIME, &ts) != 0)
    die("clock_settime");
}

// The 24-hour rows. A file is read once, so that its atime is after its mtime
// and ctime, and the clock is then stepped to `hours` past that atime (less
// one second, exactly, and plus one second) before it is read again.
static void clock_rows(void) {
  const char *ops[] = {"read1", "getdents", "readlink", "follow"};
  long offsets[] = {23 * 3600, 24 * 3600 - 1, 24 * 3600, 24 * 3600 + 1, 25 * 3600};
  for (size_t i = 0; i < sizeof ops / sizeof *ops; i++) {
    for (size_t j = 0; j < sizeof offsets / sizeof *offsets; j++) {
      struct timespec start;
      clock_gettime(CLOCK_REALTIME, &start);
      fixture();
      struct target t = target_of(ops[i]);
      nap();
      do_op(ops[i]);
      struct stat before, after;
      if (stat_target(t, &before) != 0)
        die("stat before");
      set_clock(ATIM(before).tv_sec + offsets[j]);
      long r = do_op(ops[i]);
      if (stat_target(t, &after) != 0)
        die("stat after");
      printf("%s clock+%lds %s ret=%ld atime=%lld.%09ld->%lld.%09ld moved=%d mtime=%d ctime=%d "
             "atime-after-mtime=%d atime-after-ctime=%d\n",
             label, offsets[j], ops[i], r, (long long)ATIM(before).tv_sec, ATIM(before).tv_nsec,
             (long long)ATIM(after).tv_sec, ATIM(after).tv_nsec, !same(ATIM(before), ATIM(after)),
             !same(MTIM(before), MTIM(after)), !same(CTIM(before), CTIM(after)),
             ATIM(before).tv_sec > MTIM(before).tv_sec ||
                 (ATIM(before).tv_sec == MTIM(before).tv_sec &&
                  ATIM(before).tv_nsec > MTIM(before).tv_nsec),
             ATIM(before).tv_sec > CTIM(before).tv_sec ||
                 (ATIM(before).tv_sec == CTIM(before).tv_sec &&
                  ATIM(before).tv_nsec > CTIM(before).tv_nsec));
      fflush(stdout);
      // Put the clock back where it would have been.
      set_clock(start.tv_sec + 1);
    }
  }
}
#endif

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "usage: atime <dir> <label> [clock]\n");
    return 2;
  }
  snprintf(dir, sizeof dir, "%s", argv[1]);
  label = argv[2];
  signal(SIGPIPE, SIG_IGN);
#ifdef __linux__
  if (argc > 3 && !strcmp(argv[3], "clock")) {
    clock_rows();
    return 0;
  }
#endif
  const char *states[] = {"created", "written", "read", "read-older", "future", "equal", "older",
                          "past-1",  "past-23", "past-25", "past-48", "past-720", "past-9000"};
  const char *ops[] = {"read1",    "read0",       "readeof",     "pread1",       "readv1",
                       "empty-read", "getdents",  "getdents-eof", "readlink",    "follow",
                       "read-efault", "pread-efault", "getdents-efault", "readlink-efault",
                       "readeof-efault", "read-efault-kernel", "pread0", "preadeof", "read-at-max",
                       "pread-at-max", "read-big", "read-dir",
                       "follow-target", "lstat",  "open",        "lookup",       "write",
                       "utime-atime", "mmap",     "mmap-touch",  "exec",
#ifdef __linux__
                       "cfr",      "sendfile",    "noatime-read",
#endif
                       "dev-null", "dev-urandom"};
  for (size_t i = 0; i < sizeof states / sizeof *states; i++)
    for (size_t j = 0; j < sizeof ops / sizeof *ops; j++) {
      // getdents-eof's first call is made by its `read` and `read-older`
      // states; without one it is not at the end, so it runs only in those.
      if (!strcmp(ops[j], "getdents-eof") && strcmp(states[i], "read") &&
          strcmp(states[i], "read-older"))
        continue;
      row(states[i], ops[j]);
    }
  return 0;
}
