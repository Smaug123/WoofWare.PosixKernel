// How a raw syscall instruction reports failure to the process, with no C
// library wrapper between them: what the result register holds, and whether
// the carry flag says anything.
//
// Each call is made twice by inline assembly, once with the carry flag set
// before the instruction and once with it clear, and the result register and
// the carry flag are read straight after it. Beside each, the C library's own
// wrapper of the same call reports its return value and errno, as a control.
//   getpid()             succeeds;
//   close(-1)            fails with EBADF (9 on both flavours);
//   chdir(<missing>)     fails with ENOENT (2 on both);
//   chdir(<loop>)        fails with ELOOP through a symbolic link to itself,
//                        whose number differs: 40 on Linux, 62 on Darwin.
//
// Results. Darwin 27.2.0 arm64: a failed call returns with the carry flag set
// and the flavour's own errno, positive, in x0 (9, 2, 62); a call that
// succeeds clears the flag, whatever it was before. Linux 6.18.5 aarch64: a
// failed call returns the errno negated in x0 (-9, -2, -40), and leaves the
// carry flag as it was before the call. Rosetta's x86-64 Linux process sees
// the same in rax, with its carry flag likewise left alone.
//
// Outputs beside this file, measured 2026-11-20:
// * darwin-27.2.0-arm64.txt: natively (`svc #0x80`, number in x16).
//     nix develop -c clang -Wall -O1 -o /tmp/rse raw-syscall-error.c && /tmp/rse
// * linux-6.18.5-aarch64.txt: Apple's `container`, gcc:14 image (`svc #0`,
//   number in x8).
//     container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O1 -o /tmp/rse /probe/raw-syscall-error.c && /tmp/rse'
// * linux-rosetta-x86_64.txt: the same image as linux/amd64 under
//   `container run --arch amd64 --rosetta`, which runs the x86-64 process on
//   the same aarch64 6.18.5 kernel through Rosetta's translation. It records
//   what Rosetta presents to an x86-64 process (`syscall`, number in rax), not
//   what an x86-64 Linux kernel does, which nothing here has measured.
// Darwin x86-64 is not measured: the measuring machine has no Rosetta to run
// an x86-64 Darwin process under (`arch -x86_64` answers "Bad CPU type in
// executable"). The x86-64 Darwin arm of the assembly below (`syscall`, number
// 0x2000000 + n in rax) compiles but has never run.
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

struct raw {
    uint64_t ret;
    int carry;
};

static struct raw raw1(long nr, uint64_t a0, int carry_in) {
    struct raw r;
#if defined(__APPLE__) && defined(__aarch64__)
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x16 __asm__("x16") = (uint64_t)nr;
    uint64_t in = carry_in ? (1ull << 29) : 0, out;
    __asm__ volatile("msr nzcv, %[in]\n\tsvc #0x80\n\tmrs %[out], nzcv"
                     : "+r"(x0), "+r"(x16), [out] "=&r"(out)
                     : [in] "r"(in)
                     : "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                       "x15", "x17", "memory", "cc");
    r.ret = x0;
    r.carry = (int)((out >> 29) & 1);
#elif defined(__linux__) && defined(__aarch64__)
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x8 __asm__("x8") = (uint64_t)nr;
    uint64_t in = carry_in ? (1ull << 29) : 0, out;
    __asm__ volatile("msr nzcv, %[in]\n\tsvc #0\n\tmrs %[out], nzcv"
                     : "+r"(x0), [out] "=&r"(out)
                     : "r"(x8), [in] "r"(in)
                     : "memory", "cc");
    r.ret = x0;
    r.carry = (int)((out >> 29) & 1);
#elif defined(__x86_64__)
#if defined(__APPLE__)
    uint64_t rax = 0x2000000ull + (uint64_t)nr;
#else
    uint64_t rax = (uint64_t)nr;
#endif
    uint64_t flags;
    if (carry_in)
        __asm__ volatile("stc\n\tsyscall\n\tpushfq\n\tpopq %[f]"
                         : "+a"(rax), [f] "=r"(flags)
                         : "D"(a0)
                         : "rcx", "r11", "rdx", "memory", "cc");
    else
        __asm__ volatile("clc\n\tsyscall\n\tpushfq\n\tpopq %[f]"
                         : "+a"(rax), [f] "=r"(flags)
                         : "D"(a0)
                         : "rcx", "r11", "rdx", "memory", "cc");
    r.ret = rax;
    r.carry = (int)(flags & 1);
#else
#error "unmeasured architecture"
#endif
    return r;
}

static const char *ename(int e) {
    switch (e) {
    case 0: return "0";
    case EBADF: return "EBADF";
    case ENOENT: return "ENOENT";
    case ELOOP: return "ELOOP";
    default: return strerror(e);
    }
}

static void row(const char *name, long nr, uint64_t a0, long libc_ret, int libc_errno) {
    for (int carry_in = 0; carry_in <= 1; carry_in++) {
        struct raw r = raw1(nr, a0, carry_in);
        printf("%-16s carry_in=%d: ret=0x%016llx (%lld) carry_out=%d | libc: ret=%ld errno=%d(%s)\n", name, carry_in,
               (unsigned long long)r.ret, (long long)r.ret, r.carry, libc_ret, libc_errno, ename(libc_errno));
    }
}

int main(void) {
    struct utsname u;
    uname(&u);
    printf("%s %s %s; ENOENT=%d EBADF=%d ELOOP=%d; getpid()=%d\n", u.sysname, u.release, u.machine, ENOENT, EBADF,
           ELOOP, (int)getpid());

    char loop[64];
    snprintf(loop, sizeof loop, "/tmp/rse-loop-%d", (int)getpid());
    unlink(loop);
    if (symlink(loop, loop) != 0) {
        perror("symlink");
        return 1;
    }
    const char *missing = "/nonexistent-raw-syscall-error-probe";

    long lr;
    int le;

    errno = 0;
    lr = getpid();
    le = errno;
    row("getpid()", SYS_getpid, 0, lr, le);

    errno = 0;
    lr = close(-1);
    le = errno;
    row("close(-1)", SYS_close, (uint64_t)(int64_t)-1, lr, le);

    errno = 0;
    lr = chdir(missing);
    le = errno;
    row("chdir(missing)", SYS_chdir, (uint64_t)(uintptr_t)missing, lr, le);

    errno = 0;
    lr = chdir(loop);
    le = errno;
    row("chdir(loop)", SYS_chdir, (uint64_t)(uintptr_t)loop, lr, le);

    unlink(loop);
    return 0;
}
