// Which end of a loopback TCP connection is left in TIME_WAIT when the
// processes holding its two ends exit as socket-creator-uid.c's ACCEPT rows
// end them: the parent tells the listener process to exit (closing the
// accepted end) and at once closes the pipe that keeps the client process
// alive (closing the client's end). Neither waits for the other, so which FIN
// leaves first could be a race; this counts, over many trials, which ends are
// left holding their local address (a plain bind of exactly it is refused)
// once both processes have exited: the end or ends in TIME_WAIT.
//
// No privilege is needed: every process here is the caller's.
//   cc -Wall -Werror -O1 -o /tmp/close-order close-order.c && /tmp/close-order
//
//   TRIALS n= accepted-end= client-end= both= neither=

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what) {
    perror(what);
    exit(2);
}

static int read_int(int fd, int *v) { return read(fd, v, sizeof *v) == (ssize_t)sizeof *v ? 0 : -1; }

static int write_int(int fd, int v) { return write(fd, &v, sizeof v) == (ssize_t)sizeof v ? 0 : -1; }

static struct sockaddr_in at(int port) {
    struct sockaddr_in s;
    memset(&s, 0, sizeof s);
#ifdef __APPLE__
    s.sin_len = sizeof s;
#endif
    s.sin_family = AF_INET;
    s.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &s.sin_addr);
    return s;
}

// One trial: the server port, and the client's local port.
static void trial(int *server_port, int *client_port) {
    // The pipes are made where socket-creator-uid.c makes them: the one that
    // keeps the client alive only after the listener has forked, so that the
    // listener holds no end of it and the client sees it close the moment the
    // parent closes it.
    int to_parent[2], from_parent[2], go[2], cport[2];
    if (pipe(to_parent) != 0 || pipe(from_parent) != 0) die("pipe");
    fflush(stdout);
    pid_t lpid = fork();
    if (lpid < 0) die("fork");
    if (lpid == 0) {
        alarm(30);
        struct sockaddr_in sa = at(0);
        socklen_t len = sizeof sa;
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0 || bind(s, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(s, 1) != 0) _exit(3);
        if (getsockname(s, (struct sockaddr *)&sa, &len) != 0) _exit(4);
        if (write_int(to_parent[1], ntohs(sa.sin_port)) != 0) _exit(5);
        int c = accept(s, NULL, NULL);
        if (c < 0 || write_int(to_parent[1], 1) != 0) _exit(6);
        int cmd;
        while (read_int(from_parent[0], &cmd) == 0 && cmd != 0) {
            if (cmd == 1) {
                close(s);
                if (write_int(to_parent[1], 1) != 0) _exit(7);
            }
        }
        _exit(0);
    }
    int port = -1, ack = 0;
    if (read_int(to_parent[0], &port) != 0) die("port");
    if (pipe(go) != 0 || pipe(cport) != 0) die("pipe");
    fflush(stdout);
    pid_t cpid = fork();
    if (cpid < 0) die("fork");
    if (cpid == 0) {
        alarm(30);
        close(go[1]);
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa = at(port);
        socklen_t len = sizeof sa;
        if (s < 0 || connect(s, (struct sockaddr *)&sa, sizeof sa) != 0) _exit(3);
        if (getsockname(s, (struct sockaddr *)&sa, &len) != 0) _exit(4);
        if (write_int(cport[1], ntohs(sa.sin_port)) != 0) _exit(5);
        char ch;
        while (read(go[0], &ch, 1) > 0) {
        }
        _exit(0);
    }
    close(go[0]);
    if (read_int(to_parent[0], &ack) != 0 || read_int(cport[0], client_port) != 0) die("accept");
    if (write_int(from_parent[1], 1) != 0 || read_int(to_parent[0], &ack) != 0) die("close listener");
    // As socket-creator-uid.c ends a row.
    if (write_int(from_parent[1], 0) != 0) die("end");
    close(go[1]);
    int st;
    waitpid(lpid, &st, 0);
    waitpid(cpid, &st, 0);
    close(to_parent[0]);
    close(to_parent[1]);
    close(from_parent[0]);
    close(from_parent[1]);
    close(cport[0]);
    close(cport[1]);
    *server_port = port;
}

// Whether something still holds 127.0.0.1:<port>: a socket binding exactly
// that address without SO_REUSEADDR is refused. Once both processes have
// exited, only an end left in TIME_WAIT holds its local address.
static int held(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket");
    struct sockaddr_in sa = at(port);
    int held = bind(s, (struct sockaddr *)&sa, sizeof sa) != 0;
    close(s);
    return held;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    int n = argc > 1 ? atoi(argv[1]) : 40;
    int accepted_end = 0, client_end = 0, both = 0, neither = 0;
    for (int i = 0; i < n; i++) {
        int sport = -1, cport = -1;
        trial(&sport, &cport);
        usleep(200000);
        int a = held(sport), c = held(cport);
        if (a && c) both++;
        else if (a) accepted_end++;
        else if (c) client_end++;
        else neither++;
    }
    printf("TRIALS\tn=%d\taccepted-end=%d\tclient-end=%d\tboth=%d\tneither=%d\n", n, accepted_end, client_end, both,
           neither);
    return 0;
}
