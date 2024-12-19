from tendo import singleton

me = singleton.SingleInstance()

import scapy.all as scapy
from scapy.all import conf
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send
import yaml, sys, os, hashlib, signal

try:
    with open('C:\Program Files (x86)\Artemis Arrow\conf.yaml', 'r') as f:
        conf = yaml.safe_load(f)
        dip = conf['target']['ip']
        dport = conf['target']['port']
        vid = conf['target']['vid']
        mtu = conf['target']['mtu']
        
except FileNotFoundError:
    print(f"Error: Config file '{config_file}' not found")
    sys.exit(1)
except yaml.YAMLError as e:
    print(f"Error parsing YAML file: {e}")
    sys.exit(1)
    
payload = b'\x08\x00\x00\x00' + int(vid).to_bytes(3, byteorder='big') + b'\x00'
filterText = f"not (udp and dst host {dip} and dst port {dport}) and not net 10.10"
signal.signal( signal.SIGINT, lambda s, f : sys.exit(0))

def modify_and_forward_packet(packet):
    try:
        packetPayload = payload + bytes(packet)
        vxlanPacket = IP(dst=dip)/UDP(dport=dport, sport=calc_sport(packet))/Raw(load=packetPayload)
        if len(vxlanPacket) <= mtu:
            send(vxlanPacket, verbose=False)
        else:
            for p in scapy.fragment(vxlanPacket, mtu - 50):
                send(p)
    except:
        pass

def calc_sport(packet):
    return 49152 + ( int(hashlib.sha1(bytes(packet)).hexdigest(), 16) % (65536-49152) )

def main():
    while(True):
        scapy.sniff(filter=filterText, prn=lambda pkt: modify_and_forward_packet(pkt), store=0)

if __name__ == "__main__":
    main()
