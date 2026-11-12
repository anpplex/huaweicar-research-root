#!/system/bin/sh
cd /data/local/tmp || exit 1
(while :; do sync; sleep 1; done) >/dev/null 2>&1 &
nohup setsid ./wr93x --puresh -D -s 0x17bd280000 > /data/local/tmp/psv6.log 2>&1 &
echo started
