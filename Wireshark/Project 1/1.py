import asyncio
import pyshark
import re

def packet_process(p):
    if re.search('facebook', p.dns.qry_name, re.IGNORECASE):
        print("FACEBOOK DETECTED")
    if re.search('instagram', p.dns.qry_name, re.IGNORECASE):
        print("INSTAGRAM DETECTED")
    if re.search('twitter', p.dns.qry_name, re.IGNORECASE):
        print("TWITTER DETECTED")


def main():
    print(pyshark.tshark.tshark.get_tshark_interfaces())

    c = pyshark.LiveCapture(interface=r'\\Device\\NPF_{CA6121FC-E7A0-4AF4-8E7B-6C72C5ED2966}', display_filter="dns")
    
    try:
        c.apply_on_packets(packet_process, timeout=20)
    except asyncio.exceptions.TimeoutError:
        print("Working hours have ended. Continue browsing social media.")
    
    c.close()


if __name__ == '__main__':
    main()