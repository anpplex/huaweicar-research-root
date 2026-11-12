#!/system/bin/sh
cd /data/local/tmp || exit 1
D=./dirtyinit
$D echo 1 '>' /sys/kernel/tracing/options/sym-addr
$D echo 1 '>' /sys/kernel/tracing/options/sym-offset
$D echo 0 '>' /sys/kernel/tracing/tracing_on
$D echo 0 '>' /sys/kernel/tracing/trace
$D echo 1 '>' /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable
$D echo 1 '>' /sys/kernel/tracing/tracing_on
OUT=$(./gtest)
$D echo 0 '>' /sys/kernel/tracing/tracing_on
echo "GTEST: $OUT"
echo "--- prepare_creds ---"
grep -a prepare_creds /sys/kernel/tracing/trace | head -8
echo "--- copy_process ---"
grep -a copy_process /sys/kernel/tracing/trace | head -4
