/* rawsnap：只抓 0.5s / 3 CPU 的 trace_pipe_raw 到文件，供本地离线分析 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>

int main(int argc, char **argv)
{
    const char *out = argc > 1 ? argv[1] : "/data/local/tmp/raw.bin";
    static unsigned char buf[65536];
    int fds[3], nfd = 0;
    for (int c = 0; c < 3; c++) {
        char p[128];
        snprintf(p, sizeof p, "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", c);
        int f = open(p, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (f >= 0) fds[nfd++] = f;
    }
    if (!nfd) { printf("no fds\n"); return 1; }

    int ow = open(out, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (ow < 0) { printf("open out fail\n"); return 1; }

    long total = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long long deadline = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 500;
    while (total < 262144) {
        struct timespec te;
        clock_gettime(CLOCK_MONOTONIC, &te);
        if ((long long)te.tv_sec * 1000 + te.tv_nsec / 1000000 > deadline) break;
        struct pollfd pf[3];
        for (int i = 0; i < nfd; i++) { pf[i].fd = fds[i]; pf[i].events = POLLIN; pf[i].revents = 0; }
        if (poll(pf, nfd, 20) <= 0) continue;
        for (int i = 0; i < nfd; i++) {
            if (!(pf[i].revents & POLLIN)) continue;
            ssize_t n = read(fds[i], buf, sizeof buf);
            if (n > 0) { write(ow, buf, n); total += n; }
        }
    }
    close(ow);
    for (int i = 0; i < nfd; i++) close(fds[i]);
    printf("raw bytes=%ld -> %s\n", total, out);
    return 0;
}
