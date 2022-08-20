from scapy.all import *

print("packet sniffing starts......")
f = open("network.txt", "a")

def print_pkt(pkt):
	# write the packet to the file
	f.write(f"""
    Src IP: {pkt[IP].src}
    Dst IP: {pkt[IP].dst}
    Protocol: {pkt[TCP].proto}
""")


pkt = sniff(filter="udp", prn=print_pkt)
