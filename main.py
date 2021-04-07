#!/usr/bin/env python3
from bcc import BPF
import time
from bcc.table import HashTable
from bcc import BPF
import time
from ipaddress import IPv4Address
from socket import ntohl, ntohs
import os

device = "enp0s3"
b = BPF(src_file="filter.c")
fn = b.load_func("filter", BPF.XDP)
b.attach_xdp(device, fn, 0)


blacklist = set()

try:
    # b.trace_print()
    while True:
        print('get table')
        os.system('clear')

        syn_dst: HashTable = b.get_table("syn_counter_by_dst")
        fin_dst: HashTable = b.get_table("fin_counter_by_dst")
        # print(syn_dst.items())

        for k, v in syn_dst.items():
            fin_count = fin_dst.get(k)
            # print(fin_count)
            print("dest ip: %15s, syn_count: %3d, fin_count: %3d" %
                  (IPv4Address(ntohl(k.value)), v.value,
                   fin_count.value if fin_count is not None else 0))
        syn_src: HashTable = b.get_table("syn_counter_by_src")
        fin_src: HashTable = b.get_table("fin_counter_by_src")
        rst_src: HashTable = b.get_table("rst_counter_by_src")
        for k, v in syn_src.items():
            syn_count = v.value
            fin_count = fin_src.get(k).value if fin_src.get(k) is not None else 0
            rst_count = rst_src.get(k).value if rst_src.get(k) is not None else 0
            dst_port = ntohs((k.value & 0xFFFF000000000000) >> 48)
            dst_ip = IPv4Address(ntohl((k.value & 0xFFFFFFFF)))
            src_ip = IPv4Address(ntohl((k.value & 0xFFFF00000000) >> 16))
            print("dest ip: %15s:%4d, src ip: %3s, syn_count: %3d, fin_count: %3d, rst_count: %3d" %
                  (dst_ip, dst_port, src_ip, syn_count, fin_count, rst_count))
            if syn_count > 10 and syn_count/(syn_count+fin_count+rst_count) > 0.6:
                blacklist.add(f"{src_ip} => {dst_ip}:{dst_port}")
        print(len(syn_dst.items()))
        print(len(syn_src.items()))
        print(blacklist)
        time.sleep(10)
except KeyboardInterrupt:
    pass
b.remove_xdp(device, 0)
