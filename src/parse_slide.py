import struct, sys, collections
p = sys.argv[1] if len(sys.argv) > 1 else r"d:\98260\logs\raw_slide.bin"
d = open(p, 'rb').read()
n = len(d)
TIMER_CS_LINK = 0xffffffc0102bf748
votes = collections.Counter()
reqs = collections.Counter()
o = 8
while o + 40 <= n:
    t = struct.unpack_from('<H', d, o - 8)[0]
    if t == 267:
        pid = struct.unpack_from('<i', d, o - 4)[0]
        cs, ptr, req = struct.unpack_from('<QQQ', d, o)
        if (cs >> 48) == 0xffff and (cs & 3) == 0:
            reqs[req] += 1
            if req == 0x110 and (cs & 0xfff) == (TIMER_CS_LINK & 0xfff):
                votes[cs - TIMER_CS_LINK] += 1
    o += 4
print("total bytes", n, "req classes", len(reqs))
print("top req sizes:", reqs.most_common(8))
print("slide votes:", votes.most_common(8))
