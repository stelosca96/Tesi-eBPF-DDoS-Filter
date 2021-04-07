from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
from scapy.sendrecv import send

dst = '192.168.100.4'
flag = 'S'
packet = IP(dst=dst) / TCP(flags=flag, dport=80)
for i in range(12):
    send(packet)

# flag = 'R'
# packet = IP(dst=dst) / TCP(flags=flag, dport=80)
# send(packet)
