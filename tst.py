from pprint import pprint
from _pynetmap import lib, ffi
import select
import time

def insp(d):
    return {k:getattr(d, k) for k in dir(d)}

IFNAME = 'netmap:ve0b'


def netmap_txring(nifp, index):
    return ffi.cast('char*', ffi.cast('char*', nifp) + nifp.ring_ofs[index])

def netmap_rxring(nifp, index):
    return ffi.cast('char*', ffi.cast('char*', nifp) + nifp.ring_ofs[index + nifp.ni_tx_rings + 1])


ifname = ffi.new('char[]', IFNAME)
nm_desc = lib.nm_open(ifname, ffi.NULL, 0, ffi.NULL)
nifp = nm_desc.nifp
rxr = lib.netmap_rxring(nifp, 0)
txr = lib.netmap_txring(nifp, 0)
print 'nm_desc:'
pprint(insp(nm_desc))
print 'netmap_if:'
pprint(insp(nifp))
index = 0
base_ptr = ffi.cast('char*', nifp)
rx_ptr = ffi.cast('char*', rxr)
tx_ptr = ffi.cast('char*', txr)
idx = 0
print netmap_rxring(nifp, 0)
print 'rx:', rx_ptr, rx_ptr - base_ptr, insp(rxr)
print netmap_txring(nifp, 0)
print 'tx:', tx_ptr, tx_ptr - base_ptr, insp(txr)
print 'rx-tx:', tx_ptr - rx_ptr

lib.nm_close(nm_desc)