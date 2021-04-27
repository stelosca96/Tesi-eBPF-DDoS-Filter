import time

from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
from scapy.sendrecv import send

dst = '10.10.113.4'
flag = 'S'
# packet = IP(src='192.168.100.18', dst=dst) / TCP(flags=flag, dport=9000)
# for i in range(15):
#     send(packet)
while True:
    # packet = IP(src='192.168.100.18', dst=dst) / TCP(flags=flag, dport=90)
    # for i in range(15):
    #     send(packet)
    for i in range(6, 30):
        print(f"192.168.100.{i}")
        packet = IP(src=f"192.168.100.{i}", dst=dst) / TCP(flags=flag, dport=9000)
        send(packet)
    time.sleep(10)
# packet = IP(src='192.168.100.5', dst=dst) / TCP(flags=flag, dport=8096)
# for i in range(1):
#     send(packet)
# packet = IP(src='192.168.100.6', dst=dst) / TCP(flags=flag, dport=8096)
# for i in range(1):
#     send(packet)
# packet = IP(src='192.168.100.7', dst=dst) / TCP(flags=flag, dport=8096)
# for i in range(1):
#     send(packet)
# packet = IP(src='192.168.100.8', dst=dst) / TCP(flags=flag, dport=8096)
# for i in range(1):
#     send(packet)

# flag = 'R'
# packet = IP(dst=dst) / TCP(flags=flag, dport=80)
# send(packet)
