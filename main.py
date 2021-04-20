#!/usr/bin/env python3
from bcc import BPF
from bcc.table import HashTable
from bcc import BPF
import time
from ipaddress import IPv4Address
from socket import ntohl, ntohs
from ctypes import c_ulong, c_bool
from db import Db
import os


# conto i syn già considerati anomali,
# così da escluderli nel conto generale
def add_anomaly(ip, port, syn, fin):
    global anomaly_by_ip_port
    key = f"{ip}:{port}"
    if key in anomaly_by_ip_port.keys():
        anomaly_by_ip_port[key]['syn_count'] += syn
        anomaly_by_ip_port[key]['fin_count'] += fin
    else:
        anomaly_by_ip_port[key] = {
            'syn_count': syn,
            'fin_count': fin
        }


def clear_maps():
    syn_dst.clear()
    fin_dst.clear()
    syn_src.clear()
    fin_src.clear()
    rst_src.clear()
    blacklist.clear()
    anomaly_by_ip_port.clear()


def get_anomaly_syn_fin(ip, port):
    key = f"{ip}:{port}"
    if key in anomaly_by_ip_port.keys():
        return anomaly_by_ip_port[key]['syn_count'],  anomaly_by_ip_port[key]['fin_count']
    return 0, 0


device = "enp0s3"
b = BPF(src_file="filter.c")
fn = b.load_func("filter", BPF.XDP)
b.attach_xdp(device, fn, 0)

anomaly_by_ip_port = dict()
blacklist = set()

syn_dst: HashTable = b.get_table("syn_counter_by_dst")
fin_dst: HashTable = b.get_table("fin_counter_by_dst")
syn_src: HashTable = b.get_table("syn_counter_by_src")
fin_src: HashTable = b.get_table("fin_counter_by_src")
rst_src: HashTable = b.get_table("rst_counter_by_src")
db = Db('root', 'ciao12345', 'anomaly_detection', '192.168.1.20')
blacklist_table: HashTable = b.get_table("blacklist_table")
try:
    # b.trace_print()
    while True:
        print('get data')
        blacklist_table.clear()

        for k, v in syn_src.items():
            syn_count = v.value
            fin_count = fin_src.get(k).value if fin_src.get(k) is not None else 0
            rst_count = rst_src.get(k).value if rst_src.get(k) is not None else 0
            dst_port = ntohs((k.value & 0xFFFF000000000000) >> 48)
            dst_ip = IPv4Address(ntohl((k.value & 0xFFFFFFFF)))
            src_ip = IPv4Address(ntohl((k.value & 0xFFFF00000000) >> 16))
            data = {
                'ip_src': ntohl((k.value & 0xFFFF00000000) >> 16),
                'ip_dst': ntohl((k.value & 0xFFFFFFFF)),
                'port_dst': ntohs((k.value & 0xFFFF000000000000) >> 48),
                'syn_tx': syn_count,
                'rst_tx': rst_count,
                'fin_tx': fin_count,
            }
            db.add_data(data)
            print("dest ip: %15s:%4d, src ip: %3s, syn_count: %3d, fin_count: %3d, rst_count: %3d" %
                  (dst_ip, dst_port, src_ip, syn_count, fin_count, rst_count))
            # todo: scegliere una soglia
            if syn_count > 10 and syn_count/(syn_count+fin_count+rst_count) > 0.7:
                blacklist.add(f"{src_ip} =>a {dst_ip}:{dst_port}")
                blacklist_table[k] = c_bool(True)
                add_anomaly(dst_ip, dst_port, syn_count, fin_count+rst_count)

        for k, v in syn_dst.items():
            syn_count = v.value
            fin_count = fin_dst.get(k).value if fin_dst.get(k) is not None else 0
            dst_port = ntohs((k.value & 0xFFFF000000000000) >> 48)
            dst_ip = IPv4Address(ntohl((k.value & 0xFFFFFFFF)))
            # print(fin_count)
            print("dest ip: %15s:%4d, syn_count: %3d, fin_count: %3d" %
                  (dst_ip, dst_port, syn_count, fin_count))
            # sottraggo i syn e i fin già considerati un'anomalia
            s, f = get_anomaly_syn_fin(dst_ip, dst_port)
            syn_count -= s
            fin_count -= f
            if syn_count > 10 and syn_count / (syn_count + fin_count) > 0.7:
                blacklist.add(f"{dst_ip}:{dst_port}")
                blacklist_table[k] = c_bool(True)
                print("new: dest ip: %15s:%4d, syn_count: %3d, fin_count: %3d" %
                      (dst_ip, dst_port, syn_count, fin_count))

        print(len(syn_dst.items()))
        print(len(syn_src.items()))
        print(blacklist)
        clear_maps()
        # todo: pulire mappe
        time.sleep(20)
except KeyboardInterrupt:
    pass
b.remove_xdp(device, 0)
