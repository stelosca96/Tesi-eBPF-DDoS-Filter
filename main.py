#!/usr/bin/env python3
import ctypes
from typing import Dict

from bcc import BPF
from bcc.table import HashTable
from bcc import BPF
import time
from ipaddress import IPv4Address
from socket import ntohl, ntohs
from ctypes import c_ulong, c_bool
from db import Db
import os

features = ['syn_tx', 'rst_tx', 'fin_tx', 'udp_tx', 'icmp_tx', 'tcp_tx',
            'packet_rate_tx', 'udp_tx_53', 'throughput_tx']
# class CounterData(ctypes.Structure):
#     _fields_ = [
#         ("syn_tx", ctypes.c_uint),
#         ("rst_tx", ctypes.c_uint),
#         ("fin_tx", ctypes.c_uint),
#         ("udp_tx", ctypes.c_uint),s
#         ("icmp_tx", ctypes.c_uint),
#         ("tcp_tx", ctypes.c_uint),
#         ("packet_rate_tx", ctypes.c_uint),
#         ("throughput_tx", ctypes.c_uint),
#     ]


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
    # syn_dst.clear()
    # fin_dst.clear()
    blacklist.clear()
    anomaly_by_ip_port.clear()
    for i in features:
        tables[i].clear()


def get_anomaly_syn_fin(ip, port):
    key = f"{ip}:{port}"
    if key in anomaly_by_ip_port.keys():
        return anomaly_by_ip_port[key]['syn_count'],  anomaly_by_ip_port[key]['fin_count']
    return 0, 0


device = "wlan0"
b = BPF(src_file="counter.c")
fn = b.load_func("filter", BPF.XDP)
b.attach_xdp(device, fn, 0)

anomaly_by_ip_port = dict()
blacklist = set()

# syn_dst: HashTable = b.get_table("syn_counter_by_dst")
# fin_dst: HashTable = b.get_table("fin_counter_by_dst")

tables: Dict[str, HashTable] = dict()
for feature in features:
    key = f"{feature}_counter_by_src"
    print(key)
    tables[feature]: HashTable = b.get_table(key)

db = Db('ste_tgr', 'root', 'ciao12345', 'anomaly_detection', '192.168.1.55', 3307)
blacklist_table: HashTable = b.get_table("blacklist_table")

try:
    # b.trace_print()
    while True:
        print('get data')
        blacklist_table.clear()
        # for k, v in tables['throughput_tx'].items():
        #     print('throughput_tx', k.value, v.value)
        for k, v in tables['packet_rate_tx'].items():
            data = dict()
            data['packet_rate_tx'] = v.value
            for feature in features:
                data[feature] = tables[feature].get(k).value if tables[feature].get(k) is not None else 0
            data.update({
                'ip_src': ntohl((k.value & 0xFFFF00000000) >> 16),
                'ip_dst': ntohl((k.value & 0xFFFFFFFF)),
                'port_dst': ntohs((k.value & 0xFFFF000000000000) >> 48)
            })

            db.add_data(data)
            print("dest ip: %15s:%4d, src ip: %3s, syn_count: %3d, fin_count: %3d, rst_count: %3d throughput_tx: %d %d"
                  % (
                      IPv4Address(data["ip_dst"]),
                      data["port_dst"],
                      IPv4Address(data["ip_src"]),
                      data["syn_tx"],
                      data["fin_tx"],
                      data["rst_tx"],
                      data["throughput_tx"],
                      ntohs(data["throughput_tx"])
                  )
                  )
            # todo: scegliere una soglia
            # if syn_count > 10 and syn_count/(syn_count+fin_count+rst_count) > 0.7:
            #     blacklist.add(f"{src_ip} =>a {dst_ip}:{dst_port}")
            #     blacklist_table[k] = c_bool(True)
            #     add_anomaly(dst_ip, dst_port, syn_count, fin_count+rst_count)

        # for k, v in syn_dst.items():
        #     syn_count = v.value
        #     fin_count = fin_dst.get(k).value if fin_dst.get(k) is not None else 0
        #     dst_port = ntohs((k.value & 0xFFFF000000000000) >> 48)
        #     dst_ip = IPv4Address(ntohl((k.value & 0xFFFFFFFF)))
        #     # print(fin_count)
        #     print("dest ip: %15s:%4d, syn_count: %3d, fin_count: %3d" %
        #           (dst_ip, dst_port, syn_count, fin_count))
        #     # sottraggo i syn e i fin già considerati un'anomalia
        #     s, f = get_anomaly_syn_fin(dst_ip, dst_port)
        #     syn_count -= s
        #     fin_count -= f
        #     if syn_count > 10 and syn_count / (syn_count + fin_count) > 0.7:
        #         blacklist.add(f"{dst_ip}:{dst_port}")
        #         blacklist_table[k] = c_bool(True)
        #         print("new: dest ip: %15s:%4d, syn_count: %3d, fin_count: %3d" %
        #               (dst_ip, dst_port, syn_count, fin_count))
        #
        # print(len(syn_dst.items()))
        # print(len(syn_src.items()))
        print(blacklist)
        clear_maps()
        # todo: pulire mappe
        time.sleep(20)
except KeyboardInterrupt:
    pass
b.remove_xdp(device, 0)
