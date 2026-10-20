// Which source address a receiver sees for a datagram over loopback, by how
// the sender is bound and where it sends, and whether a receiver connected to
// the sender's 127.0.0.1 address takes it: twenty trials of each. Each address
// is formatted on its own, because inet_ntoa has one static buffer.
// Plan: docs/plans/2026-10-18-udp-data-path.md.
//
// Build and run:
//   Darwin: cc -Wall -O0 -o /tmp/us udp-source.c && /tmp/us
//   Linux:  container run --rm -v "$PWD":/probe gcc:14 sh -c 'gcc -Wall -O0 -o /tmp/us /probe/udp-source.c && /tmp/us'
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static int udp(void) { return socket(AF_INET, SOCK_DGRAM, 0); }

static void bind_to(int s, const char *addr) {
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = 0 };
    inet_pton(AF_INET, addr, &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) perror("bind");
}

static struct sockaddr_in name_of(int s) {
    struct sockaddr_in a; socklen_t l = sizeof a; memset(&a, 0, sizeof a);
    getsockname(s, (struct sockaddr *)&a, &l);
    return a;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *senders[] = { "unbound", "0.0.0.0", "127.0.0.1" };
    const char *dests[] = { "127.0.0.1", "127.0.0.2", "0.0.0.0" };
    for (int si = 0; si < 3; si++) {
        for (int di = 0; di < 3; di++) {
            for (int connected = 0; connected < 2; connected++) {
                // An unbound sender has no port for a receiver to connect to.
                if (connected && si == 0) continue;
                char seen[256] = ""; int took = 0, timedout = 0;
                for (int t = 0; t < 20; t++) {
                    int r = udp(); bind_to(r, "0.0.0.0");
                    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
                    setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                    int s = udp();
                    if (si == 1) bind_to(s, "0.0.0.0");
                    if (si == 2) bind_to(s, "127.0.0.1");
                    struct sockaddr_in d = { .sin_family = AF_INET, .sin_port = name_of(r).sin_port };
                    inet_pton(AF_INET, dests[di], &d.sin_addr);
                    if (connected) {
                        struct sockaddr_in peer = { .sin_family = AF_INET, .sin_port = name_of(s).sin_port };
                        inet_pton(AF_INET, "127.0.0.1", &peer.sin_addr);
                        if (connect(r, (struct sockaddr *)&peer, sizeof peer) != 0) perror("connect");
                    }
                    ssize_t sent = sendto(s, "hello", 5, 0, (struct sockaddr *)&d, sizeof d);
                    struct sockaddr_in from; memset(&from, 0xaa, sizeof from); socklen_t fl = sizeof from;
                    char buf[16];
                    ssize_t got = recvfrom(r, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
                    if (got == 5) {
                        took++;
                        char one[32]; snprintf(one, sizeof one, "%s", inet_ntoa(from.sin_addr));
                        if (!strstr(seen, one)) { strcat(seen, one); strcat(seen, " "); }
                    } else if (got < 0 && errno == EAGAIN) timedout++;
                    (void)sent;
                    close(r); close(s);
                }
                printf("sender %s, to %s, receiver %s: took %d of 20 (timed out %d); sources seen: %s\n",
                       senders[si], dests[di], connected ? "connected to 127.0.0.1:sender" : "unconnected",
                       took, timedout, took ? seen : "-");
            }
        }
    }
    return 0;
}
