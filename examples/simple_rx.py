from pprint import pprint
from _pynetmap import lib, ffi
import select
import time

def insp(d):
    return {k:getattr(d, k) for k in dir(d)}

IFNAME = 'netmap:ve0b'


ifname = ffi.new('char[]', IFNAME)
nm_desc = ffi.new('struct nm_desc*')
ring = ffi.new('struct netmap_ring*')

nm_desc = lib.nm_open(ifname, ffi.NULL, 0, ffi.NULL)
rxr = lib.netmap_rxring(nm_desc.nifp, 0)
pprint(insp(rxr))

poller = select.poll()
print poller.register(nm_desc.fd, select.POLLIN)

ts = time.time()
cnt, thr = 0, 10**7
while 1:
    events = poller.poll(-1)
    while not lib.nm_ring_empty(rxr):
        i = ring.cur
        buf = lib.netmap_buf(rxr, i)
        rxr.head = rxr.cur = lib.nm_ring_next(rxr, i)
        cnt += 1
        if cnt >= thr:
            now = time.time()
            delta = now - ts
            print float(cnt/delta) / 1000000
            cnt, ts = 0, now


lib.nm_close(nm_desc)