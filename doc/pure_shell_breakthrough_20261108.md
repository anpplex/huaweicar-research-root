# 纯 shell 突破记录 —— 2026-11-08

## 1. 事件可写面（实测，非推测）
`find events -name enable` 逐个写 0，**73 个事件对 shell 放行**（此前文档只记了 sched/vmscan，严重低估）。

关键可用组：
| 事件 | 字段 | 价值 |
|---|---|---|
| irq/irq_handler_entry | handler=%ps | **内核 text 地址** |
| irq/softirq_entry | func | 内核 text 地址 |
| irq/tasklet_entry | func, t | text + 堆地址 |
| **filemap/mm_filemap_add_to_page_cache** | **pfn=明文** | **pfn 通道** |
| filemap/mm_filemap_delete_from_page_cache | pfn | 制造空洞 |
| binder/binder_transaction | target_node | 堆地址 |
| oom/mark_victim | task | 堆地址 |
| task/task_newtask | 无指针 | — |
| sched/sched_switch | 无指针 | 仅时序 |
| kmem/rss_stat | mm_id | 无地址 |
| vmscan/* | 无地址 | 仅时序 |

仍封闭：kmem 除 rss_stat 外全部 -13；sched_process_free -13；dma_fence 子项 -13；cgroup 子项 -13。

## 2. slide 纯 shell 成立
`kaslr_self.sh` 写 `irq/tasklet_entry/enable`（0666），读 `trace_pipe_raw` 的 func 地址，
减 PRE1/2/3（peri_dma_tasklet.cfi_jt 等）得候选，取 64KB 对齐众数。

本 boot 实测：`slide=0x2f77000000`，`base=0xffffffef87000000`。
两次独立计算（raw_values=3/hits=3 与 raw_values=269/hits=1）结果一致。

注意：脚本 `hits>=2` 门槛有时不满足，值仍可信；建议改为允许多次采样取众数。

## 3. filemap 事件直接给 pfn（本机实测）
```
echo 1 > events/filemap/mm_filemap_add_to_page_cache/enable
dd if=/dev/zero of=/data/local/tmp/fmtest bs=4096 count=8
grep filemap /sys/kernel/tracing/trace
```
输出：
```
mm_filemap_add_to_page_cache: dev 259:111 ino 55a32 page=000000000090f8c4 pfn=3119880 ofs=0
mm_filemap_add_to_page_cache: dev 259:111 ino 55a32 page=000000003aafabb1 pfn=3119881 ofs=4096
```
**pfn 是十进制明文**，不需要 raw pipe、不需要 root。

## 4. 与 wr1 的差距
wr1 的 GATE 需要两样：
1. `node_pfn`（timer 对象所在 slab 页）—— 来自 kmem type=267 的 ptr（`(ptr-PAGE_OFFSET)>>12`）
2. 验证我方喷洒页拿到该 pfn —— 原来用 `mm_page_alloc`，**可用 filemap 替代**

缺的是 (1)。kmem 事件在重启后关闭，shell 无法打开。

## 5. 两条路
**A. 本 boot 直接开火**：本 boot 的 kmem 事件已被 relay 打开（raw 有 14168 条记录），
node_pfn 可得；slide=0x2f77000000；wr93x 由 shell 直接执行。风险：上次同条件崩溃。

**B. 改成完全纯 shell（重启后也能跑）**：
用 filemap 空洞法制造"已知 pfn 的空洞"——
1. 喷文件页，filemap 记录其 pfn 集合 A
2. `delete_from_page_cache` 释放其中 k 页 → 这 k 个 pfn 回到 buddy（**我方已知**）
3. 创建 timer → slab 优先拿这些 pfn
4. 释放 timer → slab 页回 buddy
5. 再喷文件页 → 新页 pfn 若落在已知集合 → 确认抢到，无需 kmem

需要改 wr1 的 `trace_scan`/`watcher`：把 `: mm_page_alloc:` 匹配扩成 `mm_filemap_add_to_page_cache:`
并增加"空洞 pfn 集合"判据。改动集中在 L728/L806/L829/L894/L900/L1031/L1090。

## 6. 设备现状
boot_id=4a132d79，uptime>300s，`tracing_on` 可写，kmem 事件当前为 relay 所开（重启即失）。
锚点进程 17407 停在 sigsuspend（误触发的 wr93x 父进程，未清理）。
