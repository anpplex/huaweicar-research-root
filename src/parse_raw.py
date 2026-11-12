import struct, sys
p = r"d:\98260\logs\raw_gt.bin"
pid_want = int(sys.argv[1]) if len(sys.argv) > 1 else 19213
d = open(p, 'rb').read()
n = len(d)
rows = []
o = 8
while o + 40 <= n:
    t = struct.unpack_from('<H', d, o - 8)[0]
    if t == 267:
        pid = struct.unpack_from('<i', d, o - 4)[0]
        cs, ptr, req = struct.unpack_from('<QQQ', d, o)
        if (cs >> 48) == 0xffff and (cs & 3) == 0:
            rows.append((pid, cs, req))
    o += 4
print("total kmem records:", len(rows))
mine = [r for r in rows if r[0] == pid_want]
print("pid", pid_want, "records:", len(mine))
for i, (pid, cs, req) in enumerate(mine[:70]):
    print("%3d cs=%#x req=%d(%#x)" % (i, cs, req, req))
print("--- all 192-byte cs for this pid ---")
seen = []
for pid, cs, req in mine:
    if req == 192 and (not seen or seen[-1] != cs):
        seen.append(cs)
for cs in seen:
    print("192cs=%#x" % cs)
