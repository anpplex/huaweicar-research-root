# 路径 C：纯 shell（无 relay）利用链 —— 源码与数据包

> 2026-11-10 整理。只含 `--puresh` 这一条链路，relay/KO/KSU 的东西一概不在包内。
> 设备：LTO-AL00 Kirin 9000 / Android 12 / Linux 5.10.43 aarch64 / 4KB 页 / SELinux enforcing
> 起手身份：`uid=2000(shell) u:r:shell:s0`，`adb 192.168.86.1:5555`

---

## 1. 一句话现状

链路已经能 **稳定建洞 → 稳定命中窗口 → 真正执行到 `rb_erase` 写原语**；
唯一卡点是「631 颗 posix timer 中被 arm 的那颗落在 slab 的哪个对象槽」无法用 filemap 通道确定，
模板几何 `arm_i=29 → off=0xF58` 是推测值，落错槽即 `release_task+0x2a4` 野指针 panic。

---

## 2. 原理（改动只在 wr1.c，无 relay）

原链路 GATE 需要两样东西：`node_pfn`（timer 对象所在 slab 页，来自 kmem type=267 的 ptr）+ 验证我方喷洒页拿到该 pfn。

纯 shell 链把这两样都换了：

1. 事件换成 `filemap/mm_filemap_add_to_page_cache` / `delete_from_page_cache`（shell 可 enable，明文 `pfn=`，见 `doc/pure_shell_breakthrough_20261108.md`）。
2. 建洞：写 filler 4096 页 fsync 后整文件 `posix_fadvise(DONTNEED)` 灌满 pcp；再逐对释放空洞页（要求 pfn 偶 + pfn+1 同文件物理相邻）。
3. 模板：`ps_make_holes` 在 **fadvise 之前** 把假 rb_node 写进每个空洞页（`ps_grid`：每 0x110 一槽，`parent=(misc-8)|1, right=Pnode, left=0`；公共桥页额外 `build_ins_tmpl(0xF58)`）。
4. 常量：`PAGE_OFFSET=0xffffff8000000000`、`MISC_LIST_OFF=0xffffffc0135c7860`、`posix_timers_cache` 对象 0x110 / 30 对象每 order-1 slab、`node=+0x88` → 对象 29 的 node 在 8KB 块头页 `0xF58`。
5. 公共桥页保证「不管命中哪一对，rb_right 都指向同一个 Pnode」，桥地址确定。

---

## 3. 代码地图（`src/wr1.c`，6.5k 行，全模式共存）

| 环节 | 位置 |
|---|---|
| `--puresh` 开关（置 `g_puresh=1, g_norelay=1`） | L4567–4570 |
| 主流程按 puresh 分支 | L4702、L5236、L5293、L5320、L5800 |
| 建洞 `ps_make_holes` | L313（模板预置在 L369–L387） |
| 槽位模板 `ps_grid` | L1778 |
| GATE / 占用识别 `ps_gate_run` | L1794–1845 |
| **PSHOLD 探针（当前有 bug）** | L5581–5599 |
| 快速路径 reader + killer fork | L5573–5579（`PSNOKILL=1` 可跳过） |
| reap（写原语真正发生处） | L5223–5440 附近，`kill(victim,SIGKILL)+waitpid` 各分支 |
| 桥 `ins_bridge` | L1848 |
| 模板低两位 `parent=(misc-8)\|1`（black） | L1645 |
| 清理 `ps_cleanup_exit` | L224 |

关键环境变量：

| 变量 | 作用 |
|---|---|
| `PSNOKILL=1` | 只诊断，不起 killer（**该模式注定 MISS**，因为不 kill 就没有 reap 窗口） |
| `PSHOLD=1` | 父进程发 `go` 之前卡住，想「arm 完 → 测量 → 再落刀」 |
| `PSPARK=1` | 验证模式，`ps_gate_run` 打印完直接退出，不 reap |
| `--puresh` | 关 relay，走 filemap 通道 |

---

## 4. 跑法

前置：uptime > 300s；`grep posix_timers_cache /proc/slabinfo` 的 slabdata 越接近 6 越好；`/proc/modules` 无 kernelsu；
一个 boot 只跑一次；**不激活 relay**（`am instrument …InvokeRoot` 不要碰）。

### 4.1 先取 slide（puresh 也要 `-s`）

```powershell
adb push bin\skslide2 bin\rawsnap bin\gtest /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/skslide2 /data/local/tmp/rawsnap /data/local/tmp/gtest"

# 方式一：skslide2（irq/tasklet_entry + 3 CPU + 4 字节步进匹配 kallsyms）
adb shell "/data/local/tmp/skslide2"   # 连跑两次，结果必须完全一致才用

# 方式二（更可信）：gtest 反解 prepare_creds+0x28
adb push src\raw_gt.sh src\parse_slide_gt.py src\parse_slide.py /data/local/tmp/
adb shell "sh /data/local/tmp/raw_gt.sh"         # rawsnap + taskset 2 ./gtest
adb pull /data/local/tmp/raw_gt.bin
python src\parse_slide_gt.py raw_gt.bin          # 输出 PICK=0x…，votes>=2 才可信
# slide = cs - 0xffffffc0101e38d4
```

注意：`skslide2` 在本机整体偏 `+0x80000`（三个峰 bit19 全为 1，真值 bit19=0），只作交叉参考；
抓 raw 前必须先清 ring buffer（`logs/raw_gt.bin` 是 11-09 的一份样本）。

### 4.2 编译与推送

```powershell
$zig='d:\98260\tools\zig-windows-x86_64-0.13.0\zig.exe'
& $zig cc -target aarch64-linux-musl -O2 -static 'src\wr1.c' -o 'bin\wr93x'
adb push bin\wr93x /data/local/tmp/wr93x
adb shell "chmod 755 /data/local/tmp/wr93x"
# 唯一已知警告：wr1.c:2298 label followed by a declaration，无害
```

### 4.3 开火

```powershell
adb push src\fire_ps.sh /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/fire_ps.sh"
```

设备端等价命令（`fire_ps.sh` 只是把下面这行包了一层，并把日志落到 `psvX.log`）：

```sh
cd /data/local/tmp
(while :; do sync; sleep 1; done) >/dev/null 2>&1 &
nohup setsid env PSHOLD=1 PSPARK=1 ./wr93x --puresh -s 0x<slide> > /data/local/tmp/psvX.log 2>&1 &
```

日志关键行：

```
[PS] 喷涂 ino=… wrote=16384 add=16384
[PS] 空洞仍空闲=N/24（已被占用=M 对）
[PS] 被占用 pair[i] pfn=…
[PS] 唯一命中: pfn=… node=0x…f58 (模板已在该页预置)
```

验收：`每 boot 只打一枪`，出现 `WINDOW HIT` + `GATE` 通过 + `VERDICT: STAGE1 桥就绪` 才算打到；
`VERDICT: PARKED` 或 `被占用空洞对≠1` 就停手，别重试。

---

## 5. 已实测数据（见 logs/）

| 项目 | 结果 |
|---|---|
| 建洞 | 24/24 对相邻页，`fadvise_ok=48`，稳定成功 |
| 无 victim 喷涂抢回 | 7/8 对（空洞机制有效） |
| 有 victim 占洞 | 7/24 对（slab 真的吃了空洞页） |
| 喷涂规模 | 16384 页 / 64MB，`add=16384` |
| slab | 运行前 6 slab(180 obj)，victim 造 631 timer 后 27 slab(810 obj) |
| slabdata 闸 | `>33` 弃用该 victim（成功样本都 ≤32） |
| 窗口 | `[B8] zombie=Z comm='timer-exec'`，`kill+310~665us`，多次 attempt 1 即 HIT |
| 崩溃签名 | `pc: release_task+0x2a4`，`x27=dead000000000122 (LIST_POISON2)`，WnR=0 野指针读 |
| 早期 | kill 后崩；去掉 kill 的版本全程无崩溃，但也打不到写原语 |

数据文件：
- `logs/psv3.log`…`psvA.log`、`psv_1239.log`：puresh 逐次运行日志（含 GATE / 占用对 / VERDICT）
- `logs/shots_record.txt`：全部开火记录汇总
- `logs/console_1109_1654.txt`、`pstore_dmesg_1109.txt`、`pstore_window.txt`：崩溃现场（`cat /sys/fs/pstore/…`，shell 可读）

---

## 6. 卡点与三条候选路径

**核心问题：arm 的那颗 timer 在哪个 slab / 哪个槽？**
filemap 通道只能给「页 pfn」，给不到「页内对象序号」；27 个 slab 里挑错一个 → `rb_erase` 读野指针 → panic。

| 方案 | 内容 | 代价 |
|---|---|---|
| A | 纯 shell + 槽位轮询：每次 boot 只试一个对象序号（0..29），命中即停 | 最多 30 次重启，完全不碰 relay |
| B | 只让 relay 开 `kmem_cache_alloc` 一个事件拿精确对象地址，其余仍直写 | 用一次 relay，风险已知 |
| C | 修 `PSHOLD` 握手（`ai` 单独 pipe，见 L5581）+ 修正 black/red 位，先验证页占用再落刀 | 一次代码改动 + 多次 boot |

推荐 **C → A**：先把页级占用与颜色位验证对，再用轮询补槽位。

`PSHOLD` 现有 bug：它读的 `g_wfd` 4 字节通道已被父进程 `xread(g_wfd,&okc,4)` 消费，只能 2s 超时跳过。
修法二选一：给 `ai` 单独开一条 pipe；或把消息格式改成定长 8 字节 `[ok][ai]`。

另一嫌疑：模板低两位 `parent=(misc-8)|1` 表示 black，若 `rb_erase` 命中我们的节点会进 rebalance 分支而非 Case1，
需要与「槽位不对」一起排除（L1645）。

---

## 7. 红线

1. **绝不 SIGKILL** 任何带 timer 的进程（wr93x / victim / 其子进程）。reap 走 `release_task → posix_cpu_timers_exit`，脏 timer 链直接 panic。
2. **不要用 `timeout|head` 读 `trace_pipe_raw`**（`kaslr_self.sh` 老做法），被杀的阻塞进程同样触发上述 UAF。
3. **一个 boot 只跑一次 wr93x**。反复跑会把 `posix_timers_cache` 从 6 个 slab 涨到 37+，撞 `slabdata > 33` 硬闸。
4. **不要激活 relay**：历史多次崩溃发生在 `am instrument …InvokeRoot` 之后 20~40 分钟的延迟窗口。
5. 执行完不 kill、不 reboot；重启用征得用户同意。
6. 失败（`GATE FAIL` / `PARKED`）就等下次干净 boot，不要同 boot 重试。

---

## 8. 包内清单

```
00_README_路径C_纯shell链路.md   本文件
doc/
  HANDOFF_20261109.md              11-09 交接（卡点、KASLR、取证方法、三条路径）
  pure_shell_breakthrough_20261108.md  filemap pfn 通道的发现与实测
  可用成果_20261108.md               shell 可写面 / 判死面总表
src/
  wr1.c               主源码（含 --puresh 全实现，306 KB）
  fire_ps.sh          puresh 开火脚本
  kaslr_self.sh       纯 shell slide（irq/tasklet_entry，已弃用但保留）
  skslide2.c rawsnap.c gtest.c         slide 工具源码
  raw_gt.sh gt_probe.sh gt_addr.sh symoff.sh   设备端采集脚本
  parse_slide_gt.py parse_slide.py parse_raw.py  raw trace 解析
bin/
  wr93x_new           1,787,200 B，puresh 编译产物（与 HANDOFF 记录的尺寸一致）
  skslide2 rawsnap gtest
logs/
  psv3…psvA.log psv_1239.log    puresh 逐次运行日志
  shots_record.txt              全部开火记录
  console_1109_1654.txt pstore_dmesg_1109.txt pstore_window.txt   崩溃现场
  raw_gt.bin                    11-09 slide 采集样本（256 KB）
MD5SUMS.txt
```
