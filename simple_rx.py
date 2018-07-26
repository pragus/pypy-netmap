from _pynetmap import lib, ffi
import select
import argparse
import dpkt
import struct
from collections import namedtuple


def make_tuple(cls):
    clsTuple = namedtuple(cls.__name__, [x[0].replace('_', '') for x in cls.__hdr__])
    clsStruct = struct.Struct('!' + ''.join([x[1] for x in cls.__hdr__]))
    return clsTuple, clsStruct


EthCls, EthStruct = make_tuple(dpkt.ethernet.Ethernet)
IpCls, IpStruct = make_tuple(dpkt.ip.IP)
UdpCls, UdpStruct = make_tuple(dpkt.udp.UDP)
TcpCls, TcpStruct = make_tuple(dpkt.tcp.TCP)


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


def process_slot(r, s):
    buf_ptr = get_buf(r, s.buf_idx)
    buf = ffi.buffer(buf_ptr, s.len)
    eth = EthCls(*EthStruct.unpack_from(buf))
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        offset = EthStruct.size
        ip = IpCls(*IpStruct.unpack_from(buf, offset=offset))
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            offset += UdpStruct.size
            udp = UdpCls(*UdpStruct.unpack_from(buf, offset=offset))

        if ip.p == dpkt.ip.IP_PROTO_TCP:
            offset += TcpStruct.size
            tcp = TcpCls(*TcpStruct.unpack_from(buf, offset=offset))


def process_ring(r):
    processed, i, tail = 0, r.cur, r.tail
    while i != tail:
        process_slot(r, r.slot[i])
        r.slot[i].flags |= lib.NS_FORWARD
        i = ring_next(r, i)
        processed += 1
    return processed


def process(iname):
    nm_desc = lib.nm_open(iname, ffi.NULL, 0, ffi.NULL)
    poller = select.poll()
    poller.register(nm_desc.fd, select.POLLIN)
    while 1:
        poller.poll(-1)
        idx = 0
        while idx <= nm_desc.last_rx_ring:
            r = lib.netmap_rxring(nm_desc.nifp, idx)
            r.flags = lib.NR_FORWARD
            processed = process_ring(r)
            idx += 1
    lib.nm_close(nm_desc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', default='netmap:p{0')
    args = parser.parse_args()
    process(args.interface)
