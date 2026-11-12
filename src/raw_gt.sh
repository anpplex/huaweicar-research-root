#!/system/bin/sh
cd /data/local/tmp || exit 1
D=./dirtyinit
$D echo 0 '>' /sys/kernel/tracing/events/kmem/mm_page_alloc/enable
$D echo 0 '>' /sys/kernel/tracing/events/kmem/mm_page_free/enable
$D echo 1 '>' /sys/kernel/tracing/events/kmem/kmem_cache_alloc/enable
$D echo 0 '>' /sys/kernel/tracing/tracing_on
$D echo 0 '>' /sys/kernel/tracing/trace
$D echo 1 '>' /sys/kernel/tracing/tracing_on
rm -f /data/local/tmp/raw_gt.bin
taskset -c 0 ./rawsnap /data/local/tmp/raw_gt.bin > /data/local/tmp/rawsnap.out 2>&1 &
RP=$!
sleep 0.1
taskset -c 0 ./gtest
wait $RP
$D echo 0 '>' /sys/kernel/tracing/tracing_on
cat /data/local/tmp/rawsnap.out
ls -l /data/local/tmp/raw_gt.bin
