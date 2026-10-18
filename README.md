# Scapy Packet Sniffer

A lightweight Python packet sniffer built with Scapy. It captures live
network traffic and flags simple suspicious patterns, such as port
scans and cleartext credentials on FTP and Telnet.

## Features
- Captures live IP traffic with a configurable BPF filter
- Logs source, destination and protocol for each packet
- Detects possible port scans (15+ distinct ports from one IP)
- Flags cleartext credential keywords on FTP (21) and Telnet (23)
- Choose the interface and packet count from the command line

## Requirements
- Python 3
- Scapy (`pip install scapy`)
- Root privileges (`sudo`) to capture packets

## Usage
```
sudo python3 sniffer.py
sudo python3 sniffer.py -i eth0 -c 100
sudo python3 sniffer.py -f "tcp port 80"
```

## Example Output
```
[18:42:10] 192.168.1.10 -> 142.250.183.14 [TCP]
[18:42:11] 192.168.1.10 -> 8.8.8.8 [UDP]
[18:42:15] [ALERT] Possible port scan from 192.168.1.50 (15 distinct ports)
```

## Detection Logic
For every TCP packet, the script records the destination port per
source IP. When one source touches 15 distinct ports, it raises a
port scan alert. On ports 21 and 23 it also checks the payload for
USER or PASS keywords to catch cleartext logins.

## Legal Notice
Only capture traffic on networks you own or have permission to monitor.

## MITRE ATT&CK Mapping
- T1040 - Network Sniffing
- T1046 - Network Service Discovery (scan detection)

## Future Improvements
- Time-window based scan detection
- DNS query logging and anomaly checks
- Save captures to a .pcap file
- Alert export to CSV or JSON2
