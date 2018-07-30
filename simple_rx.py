from _pynetmap import ffi
from _pynetmap import lib as netmap
import select
import argparse
import dpkt
import struct
from collections import namedtuple


class TypeStruct:
    def __init__(self, Tcls, Tstruct):
        self.cls = Tcls
        self.struct = Tstruct

    def unpack_from(self, *args, **kwargs):
        return self.struct.unpack_from(*args, **kwargs)

    def cls_unpack_from(self, *args, **kwargs):
        return self.cls(*self.struct.unpack_from(*args, **kwargs))

    def pack_into(self, *args, **kwargs):
        return self.cls.pack_into(*args, **kwargs)


def make_tuple(cls):
    clsTuple = namedtuple(cls.__name__, [x[0].replace('_', '') for x in cls.__hdr__])
    clsStruct = struct.Struct('!' + ''.join([x[1] for x in cls.__hdr__]))
    return TypeStruct(clsTuple, clsStruct)


Eth = make_tuple(dpkt.ethernet.Ethernet)
Ip = make_tuple(dpkt.ip.IP)
Udp = make_tuple(dpkt.udp.UDP)
Tcp = make_tuple(dpkt.tcp.TCP)
Icmp = make_tuple(dpkt.icmp.ICMP)

Ip6 = make_tuple(dpkt.ip6.IP6)
Icmp6 = make_tuple(dpkt.icmp6.ICMP6)

PORTS = {x:x for x in range(2048)}


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


def get_slot_buf(r, cur):
    base_ptr = ffi.cast('char*', r) + r.buf_ofs
    buf_ptr = base_ptr + r.slot[cur].buf_idx * r.nr_buf_size
    return buf_ptr


def get_buf(r, buf_idx):
    base_ptr = ffi.cast('char*', r) + r.buf_ofs
    buf_ptr = base_ptr + buf_idx * r.nr_buf_size
    return buf_ptr


def swap16(v):
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)


def swap32(v):
    return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v >> 8) & 0xFF00) | ((v >> 24) & 0xFF)


def process_slot(r, s):
    s.flags |= netmap.NS_FORWARD
    buf = ffi.buffer(get_buf(r, s.buf_idx), s.len)

    eth = Eth.cls_unpack_from(buf)
    offset = Eth.struct.size
    port = 0
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = Ip.cls_unpack_from(buf[offset:])
        offset += Ip.struct.size
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = Udp.cls_unpack_from(buf[offset:])
            if udp.sport in PORTS:
                port = udp.sport + udp.dport


def process_slot_fast(r, s):
    s.flags |= netmap.NS_FORWARD
    buf_ptr = get_buf(r, s.buf_idx)
    ethhdr = ffi.cast('struct ethhdr*', buf_ptr)
    offset = Eth.struct.size
    port = 0
    if swap16(ethhdr.h_proto) == dpkt.ethernet.ETH_TYPE_IP:
        iphdr = ffi.cast('struct iphdr*', buf_ptr + offset)
        offset += Ip.struct.size
        if iphdr.protocol == dpkt.ip.IP_PROTO_UDP:
            udphdr = ffi.cast('struct udphdr*', buf_ptr + offset)
            sport, dport = swap16(udphdr.uh_sport), swap16(udphdr.uh_dport)
            if sport in PORTS:
                port = sport + dport


def process_ring(r):
    processed, i, tail = 0, r.cur, r.tail
    while i != tail:
        slot = r.slot[i]
        process_slot_fast(r, slot)
        i = ring_next(r, i)
        processed += 1
    return processed


def process(iname):
    nm_desc = netmap.nm_open(iname, ffi.NULL, 0, ffi.NULL)
    poller = select.poll()
    poller.register(nm_desc.fd, select.POLLIN)
    while 1:
        poller.poll(-1)
        idx = 0
        while idx <= nm_desc.last_rx_ring:
            r = netmap.netmap_rxring(nm_desc.nifp, idx)
            r.flags = netmap.NR_FORWARD
            processed = process_ring(r)
            idx += 1
    netmap.nm_close(nm_desc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default='netmap:p{0')
    args = parser.parse_args()
    process(args.interface)
