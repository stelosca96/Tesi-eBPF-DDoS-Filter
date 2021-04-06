#!/usr/bin/env python3
from bcc import BPF
import time
from bcc.table import HashTable
from bcc import BPF
import time
from ipaddress import IPv4Address
from socket import ntohl, ntohs

device = "lo"
b = BPF(src_file="filter.c")
fn = b.load_func("filter", BPF.XDP)
b.attach_xdp(device, fn, 0)

try:
    # b.trace_print()
    while True:
        print('get table')
        syn_dst: HashTable = b.get_table("syn_counter_by_dst")
        fin_dst: HashTable = b.get_table("fin_counter_by_dst")
        for k, v in syn_dst.items():
            fin_count = fin_dst.get(k)
            # print(fin_count)
            print("dest ip: %10s, syn_count: %3d, fin_count: %3d" %
                  (IPv4Address(ntohl(k.value)), v.value,
                   fin_count.value if fin_count is not None else 0))

        syn_src: HashTable = b.get_table("syn_counter_by_src")
        fin_src: HashTable = b.get_table("fin_counter_by_src")
        for k, v in syn_src.items():
            fin_count = fin_dst.get(k)
            dst_port = ntohs((k.value & 0xFFFF000000000000) >> 48)
            dst_ip = IPv4Address(ntohl((k.value & 0xFFFFFFFF)))
            src_ip = IPv4Address(ntohl((k.value & 0xFFFF00000000) >> 16))
            print("dest ip: %s:%d, src ip: %s, syn_count: %3d, fin_count: %3d" %
                  (dst_ip, dst_port, src_ip, v.value,
                   fin_count.value if fin_count is not None else 0))

        time.sleep(5)
except KeyboardInterrupt:
    pass
b.remove_xdp(device, 0)
