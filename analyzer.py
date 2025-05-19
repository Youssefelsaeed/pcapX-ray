import pyshark
import argparse
import csv
import json
import matplotlib.pyplot as plt
import pandas as pd
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv
import os

# Load configuration from .env file
load_dotenv()

# Detection thresholds (can be overridden by .env or CLI)
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", 10))
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))
DNS_QUERY_LENGTH_THRESHOLD = int(os.getenv("DNS_QUERY_LENGTH_THRESHOLD", 50))
DATA_EXFIL_THRESHOLD_MB = int(os.getenv("DATA_EXFIL_THRESHOLD_MB", 10))


def detect_port_scans(packets, threshold=PORT_SCAN_THRESHOLD):
    scan_tracker = defaultdict(set)
    alerts = []
    for pkt in packets:
        try:
            if pkt.transport_layer == 'TCP' and 'SYN' in pkt.tcp.flags:
                src = pkt.ip.src
                dst_port = pkt[pkt.transport_layer].dstport
                scan_tracker[src].add(dst_port)
        except AttributeError:
            continue
    for ip, ports in scan_tracker.items():
        if len(ports) >= threshold:
            alerts.append({
                'type': 'Port Scan',
                'source_ip': ip,
                'destination_ip': 'Multiple',
                'details': f"Scanned Ports: {', '.join(ports)}",
                'timestamp': datetime.now().isoformat()
            })
    return alerts


def detect_dns_tunneling(packets):
    alerts = []
    for pkt in packets:
        try:
            if 'DNS' in pkt:
                query = pkt.dns.qry_name
                if len(query) > DNS_QUERY_LENGTH_THRESHOLD:
                    alerts.append({
                        'type': 'DNS Tunneling',
                        'source_ip': pkt.ip.src,
                        'destination_ip': pkt.ip.dst,
                        'details': f"Long DNS query: {query}",
                        'timestamp': pkt.sniff_time.isoformat()
                    })
        except AttributeError:
            continue
    return alerts


def detect_brute_force(packets):
    login_attempts = defaultdict(int)
    alerts = []
    for pkt in packets:
        try:
            if 'FTP' in pkt or 'SSH' in pkt:
                src = pkt.ip.src
                login_attempts[src] += 1
        except AttributeError:
            continue
    for ip, count in login_attempts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            alerts.append({
                'type': 'Brute Force Attempt',
                'source_ip': ip,
                'destination_ip': 'Unknown',
                'details': f"Login attempts: {count}",
                'timestamp': datetime.now().isoformat()
            })
    return alerts


def detect_data_exfiltration(packets):
    data_sent = defaultdict(int)  # IP -> total bytes sent
    alerts = []
    for pkt in packets:
        try:
            if pkt.highest_layer in ['HTTP', 'FTP', 'TCP']:
                src = pkt.ip.src
                length = int(pkt.length)
                data_sent[src] += length
        except (AttributeError, ValueError):
            continue

    for ip, total_bytes in data_sent.items():
        total_mb = total_bytes / (1024 * 1024)
        if total_mb > DATA_EXFIL_THRESHOLD_MB:
            alerts.append({
                'type': 'Data Exfiltration',
                'source_ip': ip,
                'destination_ip': 'External',
                'details': f"Data sent: {total_mb:.2f} MB",
                'timestamp': datetime.now().isoformat()
            })
    return alerts


def analyze_pcap(pcap_file, syn_threshold, run_dns, run_brute, run_exfil, max_packets=None):
    print(f"[+] Reading PCAP file: {pcap_file}")
    packets = pyshark.FileCapture(
        pcap_file,
        keep_packets=False,
        display_filter="tcp or udp or dns"
    )

    # Optional: limit packet count
    if max_packets:
        packets = [pkt for i, pkt in enumerate(packets) if i < max_packets]
        print(f"[+] Loaded {len(packets)} packets (capped at {max_packets})")
    else:
        packets = list(packets)
        print(f"[+] Loaded {len(packets)} packets")

    findings = []
    findings.extend(detect_port_scans(packets, threshold=syn_threshold))
    if run_dns:
        findings.extend(detect_dns_tunneling(packets))
    if run_brute:
        findings.extend(detect_brute_force(packets))
    if run_exfil:
        findings.extend(detect_data_exfiltration(packets))

    return findings


def export_to_csv(findings, output_file):
    print(f"[+] Writing results to: {output_file}")
    keys = ['type', 'source_ip', 'destination_ip', 'details', 'timestamp']
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys)
        writer.writeheader()
        for row in findings:
            writer.writerow(row)


def export_to_json(findings, output_file):
    print(f"[+] Writing results to: {output_file}")
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=4)


def plot_timeline(findings, output_img='report.png'):
    df = pd.DataFrame(findings)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')

    plt.figure(figsize=(10, 6))
    for attack_type in df['type'].unique():
        subset = df[df['type'] == attack_type]
        plt.plot(subset['timestamp'], [attack_type]*len(subset), 'o', label=attack_type)

    plt.xlabel('Time')
    plt.title('Suspicious Activity Timeline')
    plt.legend()
    plt.tight_layout()
    plt.xticks(rotation=45)
    plt.savefig(output_img)
    print(f"[+] Timeline plot saved as {output_img}")


def main():
    parser = argparse.ArgumentParser(description="PCAP Intrusion Detection Tool")
    parser.add_argument("pcap", help="Path to the PCAP file")
    parser.add_argument("-o", "--output", default="report.csv", help="Output report file")
    parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Output file format")
    parser.add_argument("--plot", action="store_true", help="Generate timeline plot of events")
    parser.add_argument("--syn-threshold", type=int, default=PORT_SCAN_THRESHOLD, help="Threshold for SYN packets to detect port scans")
    parser.add_argument("--no-dns", action="store_true", help="Disable DNS tunneling detection")
    parser.add_argument("--no-brute", action="store_true", help="Disable brute-force detection")
    parser.add_argument("--no-exfil", action="store_true", help="Disable data exfiltration detection")
    parser.add_argument("--max-packets", type=int, help="Maximum number of packets to analyze")
    args = parser.parse_args()

    results = analyze_pcap(
        args.pcap,
        syn_threshold=args.syn_threshold,
        run_dns=not args.no_dns,
        run_brute=not args.no_brute,
        run_exfil=not args.no_exfil,
        max_packets=args.max_packets
    )

    if results:
        if args.format == 'csv':
            export_to_csv(results, args.output)
        else:
            export_to_json(results, args.output)

        if args.plot:
            plot_timeline(results)
        print(f"[+] Detected {len(results)} suspicious activities.")
    else:
        print("[+] No suspicious activity detected.")


if __name__ == "__main__":
    main()
