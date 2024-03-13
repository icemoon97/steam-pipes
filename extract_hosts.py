from scapy.all import rdpcap, DNSRR, DNS
import json

def extract_hostnames(pcap_path):

    packets = rdpcap(pcap_path)

    ip_to_host = {}

    for packet in packets:
        if not packet.haslayer(DNSRR):
            continue

        for i in range(packet[DNS].ancount):
            response = packet[DNSRR][i]

            # check for A records, which maps hostname to IPv4 address
            if response.type == 1:
                hostname = response.rrname.decode('utf-8').rstrip('.')
                ip = response.rdata

                ip_to_host[ip] = hostname

    return ip_to_host

# print(extract_hostnames('captures/tokyo2_test1.pcap'))

pcaps = [
    'tokyo_cache_block_test1.pcap',
    'tokyo_cache_block_test2.pcap',
    'tokyo_cache_block_test3.pcap',
    'tokyo_ext_block_test1.pcap',
    'tokyo_ext_block_test2.pcap',
    'tokyo_ext_block_test3.pcap',
    'tokyo_ext_block_test4.pcap',
    'tokyo_ext_block_test5.pcap',
    'tokyo2_test1.pcap',
    'tokyo2_test2.pcap',
]

master_map = {}
for path in pcaps:
    print("extracting from", path)
    cur = extract_hostnames(f"captures/{path}")

    for ip, host in cur.items():
        if ip in master_map:
            if host != master_map[ip]:
                print(f"CONFLICT: {ip}, existing: {master_map[ip]}, new: {host} from capture {path}")
        else:
            master_map[ip] = host

print(master_map)

with open('data/tokyo_hosts.json', 'w') as outfile:
    json.dump(master_map, outfile)