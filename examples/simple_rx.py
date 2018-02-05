from _pynetmap import lib, ffi
import select
import argparse

def insp(d):
    return {k: getattr(d, k) for k in dir(d)}


def get_avail(ring):
    if ring.tail < ring.cur:
        return ring.tail - ring.cur + ring.num_slots
    else:
        return ring.tail - ring.cur

def ring_next(r, cur, move=True):
    i = cur + 1
    if i == r.num_slots: 
        i = 0
    if move:
        r.cur = r.head = i
    return i


def get_buf(r, cur):
    base_ptr = ffi.cast('char*', r) + r.buf_ofs
    buf_ptr = base_ptr + r.slot[cur].buf_idx * r.nr_buf_size
    return buf_ptr


def process_batch(r):
    processed, i, tail = 0, r.cur, r.tail
    while i != tail:
        buf_ptr = get_buf(r, i)
        i = ring_next(r, i)
        processed += 1
    return processed



def process(iname):
    nm_desc = lib.nm_open(iname, ffi.NULL, 0, ffi.NULL)
    ring = lib.netmap_rxring(nm_desc.nifp, 0)
    poller = select.poll()
    poller.register(nm_desc.fd, select.POLLIN)
    while 1:
        poller.poll(-1)
        processed = process_batch(ring)
    lib.nm_close(nm_desc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default='netmap:p{0')
    args = parser.parse_args()
    process(args.interface)
