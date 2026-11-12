#!/system/bin/sh
cd /data/local/tmp || exit 1
D=./dirtyinit
echo "symaddr_before=$($D cat /sys/kernel/tracing/options/sym-addr)"
$D echo 1 '>' /sys/kernel/tracing/options/sym-addr
echo "symaddr_after=$($D cat /sys/kernel/tracing/options/sym-addr)"
$D echo 0 '>' /sys/kernel/tracing/trace
$D echo 1 '>' /sys/kernel/tracing/tracing_on
OUT=$(./gtest)
$D echo 0 '>' /sys/kernel/tracing/tracing_on
echo "GTEST: $OUT"
P=$(echo "$OUT" | sed -n 's/.*pid=\([0-9]*\).*/\1/p')
echo "PID=$P"
grep -a kmem_cache_alloc /sys/kernel/tracing/trace | grep -a -- "-$P " | head -25
