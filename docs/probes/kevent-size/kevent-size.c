// The size of the entries Darwin's kevent(2) and kevent64(2) store into an
// eventlist, measured two ways: the compiler's sizeof, and the stride at which
// the kernel itself stores two events into a buffer filled with a known byte
// (the offsets of the two events' `ident`, and the last byte the call
// changed, over two fills, 0xAA and 0x55, so that a stored byte which happens
// to equal one fill still shows). And whether kevent screens the eventlist
// against nevents * sizeof(struct kevent) before it copies anything out, as
// Linux's epoll_wait screens maxevents * sizeof(struct epoll_event): an
// nevents of INT_MAX, both on an empty kqueue and with two events ready and
// room for only those two; an eventlist that reaches a PROT_NONE page; and an
// eventlist outside user space.
//
// The events are two EVFILT_USER registrations, idents 0x1111 and 0x2222,
// each triggered with NOTE_TRIGGER.
//
// Results on Darwin 27.2.0 arm64: struct kevent is 32 bytes and kevent64_s
// 48, by sizeof and by the stride of the kernel's stores alike, and kevent
// screens nothing against nevents: INT_MAX is answered as any count is, an
// eventlist which reaches an unmapped page faults (EFAULT) only once an event
// is copied onto it, and an eventlist outside user space altogether is
// answered as any other while no event is copied, and with EFAULT once one
// is. The x86-64 compiler lays both structs out at the same sizes.
//
// Output beside this file, measured 2026-11-20: darwin-27.2.0-arm64.txt,
// natively:
//   nix develop -c clang -Wall -O1 -o /tmp/ks kevent-size.c && /tmp/ks
// Darwin x86-64 is not run: the measuring machine has no Rosetta to run an
// x86-64 Darwin process under. The compiler's layout for x86-64 is in
// compiled-x86_64.txt, from the globals `probe_sizeof_*` below:
//   nix develop -c clang -O1 -arch x86_64 -S -o - kevent-size.c | grep -A3 '^_probe_sizeof'
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

const unsigned long probe_sizeof_kevent = sizeof(struct kevent);
const unsigned long probe_sizeof_kevent64_s = sizeof(struct kevent64_s);

static const struct timespec zero = {0, 0};

// A kqueue with two EVFILT_USER events ready, registered and triggered
// through kevent64 when `use64` is set: a kqueue registered through kevent
// answers kevent64 with EINVAL.
static int ready_kqueue(int use64) {
    int kq = kqueue();
    int rv[2];
    if (use64) {
        struct kevent64_s ch[2];
        EV_SET64(&ch[0], 0x1111, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, 0, 0, 0);
        EV_SET64(&ch[1], 0x2222, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, 0, 0, 0);
        rv[0] = kevent64(kq, ch, 2, NULL, 0, 0, NULL);
        EV_SET64(&ch[0], 0x1111, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0, 0, 0);
        EV_SET64(&ch[1], 0x2222, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0, 0, 0);
        rv[1] = kevent64(kq, ch, 2, NULL, 0, 0, NULL);
    } else {
        struct kevent ch[2];
        EV_SET(&ch[0], 0x1111, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
        EV_SET(&ch[1], 0x2222, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
        rv[0] = kevent(kq, ch, 2, NULL, 0, NULL);
        EV_SET(&ch[0], 0x1111, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        EV_SET(&ch[1], 0x2222, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
        rv[1] = kevent(kq, ch, 2, NULL, 0, NULL);
    }
    if (rv[0] != 0 || rv[1] != 0)
        printf("ready_kqueue(%d): register rv=%d, trigger rv=%d, errno=%d\n", use64, rv[0], rv[1], errno);
    return kq;
}

static _Alignas(16) unsigned char buf[2][512];

// Store two events into each fill with `use64`'s call, and report where they
// went.
static void stride(int use64) {
    int rv[2];
    for (int f = 0; f < 2; f++) {
        memset(buf[f], f == 0 ? 0xAA : 0x55, sizeof buf[f]);
        int kq = ready_kqueue(use64);
        if (use64)
            rv[f] = kevent64(kq, NULL, 0, (struct kevent64_s *)buf[f], 2, 0, &zero);
        else
            rv[f] = kevent(kq, NULL, 0, (struct kevent *)buf[f], 2, &zero);
        close(kq);
    }
    int last = -1;
    for (int i = 0; i < (int)sizeof buf[0]; i++)
        if (buf[0][i] != 0xAA || buf[1][i] != 0x55)
            last = i;
    printf("%s: rv=%d,%d bytes changed=[0, %d]", use64 ? "kevent64" : "kevent", rv[0], rv[1], last);
    for (int i = 0; i + 8 <= (int)sizeof buf[0]; i += 8) {
        uint64_t v;
        memcpy(&v, buf[0] + i, 8);
        if (v == 0x1111 || v == 0x2222)
            printf(" ident 0x%llx at %d", (unsigned long long)v, i);
    }
    printf("\n");
}

int main(void) {
    struct utsname u;
    uname(&u);
    printf("%s %s %s\n", u.sysname, u.release, u.machine);
    printf("sizeof(struct kevent)=%zu: ident@%zu filter@%zu flags@%zu fflags@%zu data@%zu udata@%zu\n",
           sizeof(struct kevent), offsetof(struct kevent, ident), offsetof(struct kevent, filter),
           offsetof(struct kevent, flags), offsetof(struct kevent, fflags), offsetof(struct kevent, data),
           offsetof(struct kevent, udata));
    printf("sizeof(struct kevent64_s)=%zu: ident@%zu filter@%zu flags@%zu fflags@%zu data@%zu udata@%zu ext@%zu\n",
           sizeof(struct kevent64_s), offsetof(struct kevent64_s, ident), offsetof(struct kevent64_s, filter),
           offsetof(struct kevent64_s, flags), offsetof(struct kevent64_s, fflags), offsetof(struct kevent64_s, data),
           offsetof(struct kevent64_s, udata), offsetof(struct kevent64_s, ext));

    stride(0);
    stride(1);

    // nevents = INT_MAX on an empty kqueue: no event, so nothing is copied.
    {
        int kq = kqueue();
        struct kevent out[2];
        errno = 0;
        int rv = kevent(kq, NULL, 0, out, INT_MAX, &zero);
        printf("empty kqueue, nevents=INT_MAX: rv=%d errno=%d\n", rv, rv < 0 ? errno : 0);
        close(kq);
    }
    // nevents = INT_MAX with two events ready and room for exactly two.
    {
        int kq = ready_kqueue(0);
        struct kevent out[2];
        errno = 0;
        int rv = kevent(kq, NULL, 0, out, INT_MAX, &zero);
        printf("two ready, room for two, nevents=INT_MAX: rv=%d errno=%d", rv, rv < 0 ? errno : 0);
        for (int i = 0; i < rv; i++)
            printf(" ident=0x%lx", (unsigned long)out[i].ident);
        printf("\n");
        close(kq);
    }
    // An eventlist whose third entry would lie on a PROT_NONE page, with two
    // events ready and with three: whether the unmapped page matters before
    // an event is copied onto it.
    {
        long page = sysconf(_SC_PAGESIZE);
        unsigned char *map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        mprotect(map + page, page, PROT_NONE);
        struct kevent *list = (struct kevent *)(map + page - 2 * sizeof(struct kevent));
        for (int ready = 2; ready <= 3; ready++) {
            int kq = ready_kqueue(0);
            if (ready == 3) {
                struct kevent ch[2];
                EV_SET(&ch[0], 0x3333, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
                EV_SET(&ch[1], 0x3333, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
                kevent(kq, ch, 2, NULL, 0, NULL);
            }
            errno = 0;
            int rv = kevent(kq, NULL, 0, list, 3, &zero);
            printf("%d ready, room for two before PROT_NONE, nevents=3: rv=%d errno=%d\n", ready, rv,
                   rv < 0 ? errno : 0);
            close(kq);
        }
    }
    // An eventlist at an address outside user space altogether, so that any
    // range check of it, numeric or by mapping, would fail: an empty kqueue,
    // for one event and for INT_MAX, and, as the control, two events ready.
    {
        struct kevent *outside = (struct kevent *)(uintptr_t)0xFFFFFFFFFFFF0000ull;
        int kq = kqueue();
        int counts[] = {1, INT_MAX};
        for (int i = 0; i < 2; i++) {
            errno = 0;
            int rv = kevent(kq, NULL, 0, outside, counts[i], &zero);
            printf("empty kqueue, eventlist=0xFFFFFFFFFFFF0000, nevents=%d: rv=%d errno=%d\n", counts[i], rv,
                   rv < 0 ? errno : 0);
        }
        close(kq);
        kq = ready_kqueue(0);
        errno = 0;
        int rv = kevent(kq, NULL, 0, outside, 1, &zero);
        printf("two ready, eventlist=0xFFFFFFFFFFFF0000, nevents=1: rv=%d errno=%d\n", rv, rv < 0 ? errno : 0);
        close(kq);
    }
    return 0;
}
