from pathlib import Path
from collections import defaultdict

from tqdm import tqdm

import pyshark


def extract_dns(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='dns')

    hosts = set()
    
    i = 0
    for packet in cap:
        try:
            hostname = packet.dns.qry_name
            ip = packet.dns.a

            print(hostname, ip)
            hosts.add((hostname, ip))

            i += 1

        # skip if a packet that doesn't have the expected fields
        except AttributeError as e:
            continue

    print(f"Packets considered: {i}")

    return hosts


def count(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="tls", only_summaries=True)

    stats = defaultdict(lambda: {"count": 0, "volume": 0})

    for packet in tqdm(cap):
        # Check if the necessary fields are present without using try-except
        if hasattr(packet, 'ip'):
            ip = packet.ip.dst
            length = int(packet.length)

            stats[ip]["count"] += 1
            stats[ip]["volume"] += length

    print("Host stats:")
    for ip, data in stats.items():
        print(f"{ip}: Count = {data['count']}, Volume = {data['volume']} bytes")

    return stats


from scapy.all import rdpcap, IP

def count_scapy(pcap_file):
    # Initialize a dictionary to hold counts and volumes for each IP address
    stats = defaultdict(lambda: {"count": 0, "volume": 0})

    # Read packets from the pcap file
    # packets = rdpcap(pcap_file, count=10000)
    packets = rdpcap(pcap_file, count=-1)

    for packet in tqdm(packets):
        # Check if the packet has an IP layer
        if IP in packet:
            ip_dst = packet[IP].dst
            packet_length = len(packet)

            # Update the packet count and volume for the destination IP address
            stats[ip_dst]["count"] += 1
            stats[ip_dst]["volume"] += packet_length

    return stats



CAPTURE_FOLDER = Path("captures")

if __name__ == "__main__":
    # pcap = CAPTURE_FOLDER / "output_login.pcap"
    # pcap = CAPTURE_FOLDER / "capture_file_us-east-2.pcap"
    # pcap = CAPTURE_FOLDER / "capture_file_south-america-sao-paulo.pcap"
    # pcap = CAPTURE_FOLDER / "tokyo_ext_block_test1.pcap"
    # pcap = CAPTURE_FOLDER / "tokyo_cache_block_test2.pcap"
    pcap = CAPTURE_FOLDER / "tokyo2_test2.pcap"

    known = {}
    dns_hosts = extract_dns(pcap)
    for h, ip in dns_hosts:
        known[ip] = h


    stats = count_scapy(str(pcap))

    for ip, stat in sorted(stats.items(), key=lambda x: x[1]['volume'], reverse=True):
        n, volume = stat["count"], stat["volume"]
        
        if ip in known:
            print(f"{ip} ({known[ip]}): {n:,} total, {volume:,} bytes")
        else:
            print(f"{ip}: {n:,} total, {volume:,} bytes")
    