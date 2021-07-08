import asyncio
import pyshark
from collections import defaultdict

dif = defaultdict(int)

def func(pkt):
    global dif

    try:
        ipD = str(pkt.ip.dst)
    except AttributeError:
        ipD = str(pkt.ipv6.dst)
    
    try:
        ipS = str(pkt.ip.src)
    except AttributeError:
        ipS = str(pkt.ipv6.src)
    
    if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '0':   #tcp connection request sent to ipD
        dif[ipD] += 1
    
    if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '1':   #tcp connection request sent to ipD
        dif[ipD] -= 1


def main():
    # print(pyshark.tshark.tshark.get_tshark_interfaces())
    c = pyshark.LiveCapture(interface=r'\\Device\\NPF_{CA6121FC-E7A0-4AF4-8E7B-6C72C5ED2966}', display_filter="tcp")


    try:
        c.apply_on_packets(func, timeout=10)
    except asyncio.exceptions.TimeoutError:
        print("Timeout!")

    c.close()
    global dif

    for k in dif.keys():
        print("Node with IP " + k + " has the difference between SYNs and SYN/ACKs = to " + str(dif[k]), end=". ")
        if dif[k] > 0:
            print("A SYN flood is in progress.")
        else:
            print("All is well.")


if __name__ == '__main__':
    main()