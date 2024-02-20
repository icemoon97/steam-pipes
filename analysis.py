from pathlib import Path

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

def all_source_ips(pcap_file):
    # SSH is over TCP port 22
    # cap = pyshark.FileCapture(pcap_file, display_filter="http && !(tcp.port == 22)")
    cap = pyshark.FileCapture(pcap_file, display_filter="http")

    unique = set(packet.ip.src for packet in cap)

    return unique

CAPTURE_FOLDER = Path("captures")

if __name__ == "__main__":
    # pcap = CAPTURE_FOLDER / "output_login.pcap"
    pcap = CAPTURE_FOLDER / "capture_file_us-east-2.pcap"

    dns = extract_dns(pcap)

    print(all_source_ips(pcap))
    
