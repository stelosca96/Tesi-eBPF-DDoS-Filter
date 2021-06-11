#!/usr/bin/env python3
from typing import Dict
import json

from bcc import BPF
from bcc.table import HashTable
from bcc import BPF
import time
from ipaddress import IPv4Address
from socket import ntohl, ntohs
from ctypes import c_ulong, c_bool, Structure, c_uint
from db import Db
import os
from texttable import Texttable


class CounterData(Structure):
    _fields_ = [
        ("syn_tx", c_uint),
        ("rst_tx", c_uint),
        ("fin_tx", c_uint),
        ("udp_tx", c_uint),
        ("icmp_tx", c_uint),
        ("tcp_tx", c_uint),
        ("packet_rate_tx", c_uint),
        ("throughput_tx", c_uint),
    ]


def get_ip_port(key: c_ulong) -> dict:
    return {
        'ip_src': IPv4Address(ntohl((key.value & 0xFFFF00000000) >> 16)),
        'ip_dst': IPv4Address(ntohl((key.value & 0xFFFFFFFF))),
        'port_dst': ntohs((key.value & 0xFFFF000000000000) >> 48)
    }


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


device = "wlan0"
b = BPF(src_file="counter.c")
fn = b.load_func("filter", BPF.XDP)
b.attach_xdp(device, fn, 0)

anomaly_by_ip_port = dict()
blacklist = set()

counters: HashTable = b.get_table('counters')

db = Db('ste_tgr', 'root', 'ciao12345', 'anomaly_detection', '192.168.1.55', 3307)
blacklist_table: HashTable = b.get_table("blacklist_table")

try:
    while True:
        print('\n- - - - - - - - - - - - - - - - - -\n')
        blacklist_table.clear()
        for k, v in counters.items():
            key = get_ip_port(k)
            print(key['ip_src'], '=>', key['ip_dst'], ':', key['port_dst'])
            t = Texttable()
            t.add_rows([
                ['ICMP', 'TCP', 'UDP', 'SYN', 'RST', 'FIN', 'PACKETS', 'THROUGHPUT'],
                [v.icmp_tx, v.tcp_tx, v.udp_tx, v.syn_tx, v.rst_tx, v.fin_tx, v.packet_rate_tx, v.throughput_tx]
            ])
            print(t.draw())
            db.add_data(key, v)
        counters.clear()
        time.sleep(20)
except KeyboardInterrupt:
    pass
b.remove_xdp(device, 0)
