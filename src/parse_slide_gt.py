import struct, sys, collections

# parse_slide_gt.py — 从 rawsnap 抓的 raw_gt.bin 反解真实 slide
# SLIDE = call_site(prepare_creds+0x28) - CRED_CS_LINK
# 判定：req=192 且 cs 低 12 位 == 0x8d4 的记录（cred_jar 分配）
CRED_CS_LINK = 0xffffffc0101e38d4

path = sys.argv[1] if len(sys.argv) > 1 else 'raw_gt.bin'
d = open(path, 'rb').read()
n = len(d)
rows = []
o = 8
while o + 40 <= n:
    t = struct.unpack_from('<H', d, o - 8)[0]
    if t == 267:  # kmem_cache_alloc entry type
        pid = struct.unpack_from('<i', d, o - 4)[0]
        cs, ptr, req = struct.unpack_from('<QQQ', d, o)
        if (cs >> 48) == 0xffff and (cs & 3) == 0:
            rows.append((pid, cs, req))
    o += 4

cand = collections.Counter()
for pid, cs, req in rows:
    if req == 192 and (cs & 0xfff) == (CRED_CS_LINK & 0xfff):
        s = (cs - CRED_CS_LINK) & 0xffffffffffffffff
        if s & 0xffff == 0 and s < 0x4000000000:
            cand[s] += 1

print('records=%d' % len(rows))
if not cand:
    print('NO MATCH — 检查 taskset 是否在 cpu0-2、事件是否开启')
    sys.exit(1)

for s, cnt in cand.most_common(6):
    print('slide=0x%x  votes=%d  verified=%s' % (s, cnt, cnt >= 2))
print('PICK = 0x%x' % cand.most_common(1)[0][0])
