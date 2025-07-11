# run with "sudo python3 NetworkAnalyzer.py"

"""
---------------------
Network Analyzer Tool
---------------------

Purpose:
This script captures network packets for a user-defined duration on a user-selected network interface and provides multiple analysis reports:
- Protocol distribution summary
- Traffic insights: top talkers, ports, packet sizes, and frequency
- DNS analysis for unencrypted queries and visited domains
- Suspicious activity detection (ICMP flood and TCP SYN flood detection)
- Option to save the report to a file

Usage:
- Must be run as root due to raw packet capture requirements
- User can select network interface, report mode, and capture duration
- Requires 'scapy' Python package installed (pip install scapy)

Author: Jorg Gradwohl
Date: 08-07-2025
"""

import os
import time
from datetime import datetime
try:
    from scapy.all import sniff, DNS, IP, TCP, UDP, ICMP, ARP, get_if_list
except ImportError:
    raise ImportError(
        "\n[!] Scapy is not installed.\n"
        "    Please install it before running this script:\n\n"
        "    pip install scapy\n"
    )

# Helper function to format top N items for reporting
def print_top_items_lines(title, data_dict, n=5, label="packets"):
    lines = []
    lines.append(f"\n===== Top {n} {title} =====\n")
    lines.append(f"{title:<25} {'Count':>10}")
    lines.append("-" * 37)
    # Sort the data_dict by count descending, take top n
    for key, count in sorted(data_dict.items(), key=lambda x: x[1], reverse=True)[:n]:
        count_int = round(count)
        lines.append(f"{str(key):<25} {count_int:>10} {label}")
    lines.append("") # Blank line for spacing
    return lines
    

# ===============================
# Check root permission and ask for user input
# ===============================

if os.geteuid() != 0:
    raise PermissionError(
        f"\n[!] This script must be run as root.\n"
        f"    Try running it with:\n\n"
        f"    sudo python3 {__file__}\n"
    )


# ===============================
# List available interfaces and prompt user for interface selection
# ===============================

interfaces = get_if_list()
print("\nAvailable network interfaces:")
for i, iface in enumerate(interfaces, 1):
    print(f"{i}. {iface}")

print("\nNote: On macOS, 'en0' is usually your Wi-Fi interface. On Linux, interfaces like 'eth0' or 'wlan0' are common.")
iface_input = input("Enter the interface to use (number or name, leave blank for default): ").strip()

if iface_input == "":
    chosen_iface = None  # Default interface
else:
    # If user entered a number, convert to interface name if valid
    if iface_input.isdigit():
        idx = int(iface_input) - 1
        if 0 <= idx < len(interfaces):
            chosen_iface = interfaces[idx]
        else:
            print("Invalid interface number, using default.")
            chosen_iface = None
    else:
        # Use the literal string if it matches an interface
        if iface_input in interfaces:
            chosen_iface = iface_input
        else:
            print("Interface not found, using default.")
            chosen_iface = None



# ===============================
# Prompt user to select report mode
# ===============================

print("\n===== Network Analyzer =====\n")
print("Select mode:")
print("1 - Full report (all sections)")
print("2 - Traffic insights only")
print("3 - DNS analysis only")
print("4 - Suspicious activity detection only")

mode = input("Enter your selection (default 1): ").strip()
if mode not in {'1', '2', '3', '4'}: # using a set because it's faster for membership tests
    print("Invalid choice, defaulting to full report (1).")
    mode = '1'

# Prompt user for capture duration in seconds with validation
try:
    user_input = input("\nEnter capture duration in seconds (default 5): ").strip()
    capture_duration = int(user_input) if user_input else 5
    if capture_duration <= 0:
        print("Duration must be a positive integer. Using default 5 seconds.")
        capture_duration = 5
except ValueError:
    print("Invalid input. Using default capture duration of 5 seconds.")
    capture_duration = 5

# Print summary of user selections
print(f"\nRunning on interface: {chosen_iface if chosen_iface else 'default'}")
print(f"Mode: {mode}")
print(f"Duration: {capture_duration} seconds\n")


# ===============================
# Capture packets for analysis
# ===============================

print(f"Starting packet capture for {capture_duration} seconds...")
# Record start time to measure actual capture duration
start_time = time.time()

# Capture packets for the specified duration and interface using scapy
packets = sniff(timeout=capture_duration, iface=chosen_iface)

# Record end time after capture completes and calculate actual duration of packet capture
end_time = time.time()
duration = end_time - start_time
print(f"Capture duration: {duration:.2f} seconds")

# Check if any packets were captured
if len(packets) == 0:
    print("\nNo packets captured during the capture duration.")
    print("Try increasing the capture duration or check your network connection.")
    exit(0)

# ===============================
# Prepare report lines for optional saved report
# ===============================

report_lines = []

# ===============================
# 1. Protocol Identification & Summary (all modes)
# ===============================

# Initialize a dictionary to count occurrences of common network protocols
protocol_counts = {
    "DNS": 0,   # DNS queries
    "TCP": 0,   # TCP connections
    "UDP": 0,   # UDP connections
    "ICMP": 0,  # ICMP messages
    "ARP": 0,   # ARP requests
    "Other": 0  # Other protocols not explicitly handled
}

# Iterate through each captured packet and increment the count for its protocol
# Use try-except to skip any malformed packets without crashing
for pkt in packets:
    try:
        # Count DNS packets
        if pkt.haslayer(DNS):
            protocol_counts["DNS"] += 1
        elif pkt.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
        elif pkt.haslayer(ARP):
            protocol_counts["ARP"] += 1
        else:
            protocol_counts["Other"] += 1
    except Exception as e:
        # Log skipped packet info for debugging and transparency
        report_lines.append(f"Skipped malformed packet during protocol count: {e}")

# Add a formatted summary header to the report output
report_lines.append("\n===== Protocol Summary =====\n")

# Append each protocol and its count to the report output with aligned formatting
for proto, count in protocol_counts.items():
    report_lines.append(f"{proto:<6}: {count}")



# ===============================
# 2. Traffic Insights (mode 1 or 2)
# ===============================

if mode in {'1', '2'}:
    # Initialize dictionaries to count occurrences of IP addresses and ports
    src_counts = {}
    dst_counts = {}
    src_ports = {}
    dst_ports = {}

    # Analyze captured packets to count source/destination IPs and ports with error handling
    for pkt in packets:
        try:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                # Increment counts for source and destination IPs
                src_counts[src_ip] = src_counts.get(src_ip, 0) + 1
                dst_counts[dst_ip] = dst_counts.get(dst_ip, 0) + 1
        except Exception as e:
            report_lines.append(f"Skipped malformed IP packet: {e}")

        # Check for TCP or UDP layers to count source and destination ports with error handling
        try:
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                # Increment counts for source and destination ports
                src_ports[src_port] = src_ports.get(src_port, 0) + 1
                dst_ports[dst_port] = dst_ports.get(dst_port, 0) + 1

            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                # Increment counts for source and destination ports
                src_ports[src_port] = src_ports.get(src_port, 0) + 1
                dst_ports[dst_port] = dst_ports.get(dst_port, 0) + 1
        except Exception as e:
            report_lines.append(f"Skipped malformed TCP/UDP packet: {e}")

    # Add top source/destination IPs and ports stats to the report
    report_lines.extend(print_top_items_lines("Source IP Addresses", src_counts))
    report_lines.extend(print_top_items_lines("Destination IP Addresses", dst_counts))
    report_lines.extend(print_top_items_lines("Source Ports", src_ports))
    report_lines.extend(print_top_items_lines("Destination Ports", dst_ports))

    # Calculate packet size statistics
    packet_sizes = [len(pkt) for pkt in packets]
    min_size = min(packet_sizes) if packet_sizes else 0
    max_size = max(packet_sizes) if packet_sizes else 0
    avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0

    # Append packet size summary to the report
    report_lines.append("===== Packet Size Summary (bytes) =====\n")
    report_lines.append(f"Minimum packet size: {min_size}")
    report_lines.append(f"Maximum packet size: {max_size}")
    report_lines.append(f"Average packet size: {avg_size:.2f}\n")

    
    # Calculate packet frequency (packets per second) for IP addresses
    src_pps = {}  
    for ip, count in src_counts.items():
        # Calculate packets per second for this IP by dividing count by capture duration with error handling
        try:
            pps = count / duration
            # Store the result in the new dictionary, with IP as the key and packets per second as the value
            src_pps[ip] = pps 
        except Exception as e:
            report_lines.append(f"Error calculating packet frequency for {ip}: {e}")
    
    dst_pps = {}  
    for ip, count in dst_counts.items():
        # Calculate packets per second for this IP by dividing count by capture duration with error handling
        try:
            pps = count / duration
            # Store the result in the new dictionary, with IP as the key and packets per second as the value
            dst_pps[ip] = pps
        except Exception as e:
            report_lines.append(f"Error calculating packet frequency for {ip}: {e}")    

    # Append packet frequency stats to the report
    report_lines.extend(print_top_items_lines("Src IP packet frequency", src_pps, label="pps"))
    report_lines.extend(print_top_items_lines("Dst IP packet frequency", dst_pps, label="pps"))


# ===============================
# 3. DNS Analysis (mode 1 or 3)
# ===============================

if mode in {'1', '3'}:
    unique_domains = set()
    malformed_dns_flag = False  # Track if any malformed packets were skipped

    # Iterate through captured packets to extract DNS query names
    for pkt in packets:
        if pkt.haslayer(DNS):
            try:
                qd = pkt[DNS].qd
                if qd is None:
                    continue

                # Handle single query
                if hasattr(qd, 'qname'):
                    qname = qd.qname.decode(errors='ignore').rstrip('.')
                    unique_domains.add(qname)
                # Handle multiple queries
                elif isinstance(qd, list) or hasattr(qd, '__iter__'):
                    for query in qd:
                        if hasattr(query, 'qname'):
                            qname = query.qname.decode(errors='ignore').rstrip('.')
                            unique_domains.add(qname)
            except Exception as e:
                # Set flag on first error, no repeated messages
                malformed_dns_flag = True

    report_lines.append("\n=== DNS Encryption Check Report ===\n")

    if len(unique_domains) == 0:
        # No DNS queries found (possibly encrypted DNS or no DNS activity)
        report_lines.append("No DNS queries found in captured packets.")
        report_lines.append("This could mean DNS queries are encrypted (DoH, DoT, or similar) or no DNS queries were made.")
    else:
        # Report detected unencrypted DNS queries and user-visited domains
        report_lines.append("Warning: Unencrypted DNS traffic detected.\n")
        report_lines.append(f"Total DNS packets parsed: {sum(1 for pkt in packets if pkt.haslayer(DNS))}")
        filtered_domains = sorted([d for d in unique_domains if d.startswith("www.")])
        report_lines.append(f"Unique user-visited domains ({len(filtered_domains)}):")
        for domain in filtered_domains:
            report_lines.append(f"- {domain}")

    # If any malformed DNS packets were skipped, add a note to the report
    if malformed_dns_flag:
        report_lines.append("Note: Some malformed DNS packets were skipped during analysis.")

    report_lines.append("\nDNS Analysis complete.\n")

# ===============================
# 4. Suspicious Activity Detection (mode 1 or 4)
# ===============================

if mode in {'1', '4'}:
    # Dictionaries to count suspicious ICMP echo requests and TCP SYN packets per source IP
    icmp_echo_counts = {}
    tcp_syn_counts = {}

    for pkt in packets:
        # Check if packet contains ICMP layer with error handling
        try:
            if pkt.haslayer(ICMP):
                icmp_layer = pkt[ICMP]
                # ICMP type 8 is echo request (ping)
                if icmp_layer.type == 8 and pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    # Increment count for source IP
                    icmp_echo_counts[src_ip] = icmp_echo_counts.get(src_ip, 0) + 1
        except Exception as e:
            report_lines.append(f"Skipped malformed ICMP packet: {e}")

        # Check if packet contains TCP layer with error handling
        try:
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                flags = tcp_layer.flags
                # TCP SYN flag set (0x02) and ACK flag not set (0x10) indicates a SYN request
                if flags & 0x02 and not flags & 0x10 and pkt.haslayer(IP):
                    src_ip = pkt[IP].src
                    # Increment count for source IP
                    tcp_syn_counts[src_ip] = tcp_syn_counts.get(src_ip, 0) + 1
        except Exception as e:
            report_lines.append(f"Skipped malformed TCP packet: {e}")

    # Calculate packets per second for ICMP echo requests and TCP SYN packets
    icmp_echo_pps = {}
    for ip, count in icmp_echo_counts.items():
        try:
            icmp_echo_pps[ip] = count / duration
        except Exception as e:
            report_lines.append(f"Error calculating ICMP packet frequency for {ip}: {e}")

    tcp_syn_pps = {}
    for ip, count in tcp_syn_counts.items():
        try:
            tcp_syn_pps[ip] = count / duration
        except Exception as e:
            report_lines.append(f"Error calculating TCP SYN packet frequency for {ip}: {e}")

    # Thresholds to flag suspicious flood activity (packets per second)
    ICMP_THRESHOLD = 20
    SYN_THRESHOLD = 50

    report_lines.append("\n===== Suspicious Activity Detection =====\n")

    # Check and report potential ICMP flooders exceeding threshold
    report_lines.append("Potential ICMP flooders:")
    alerted = False
    for ip, pps in sorted(icmp_echo_pps.items(), key=lambda x: x[1], reverse=True):
        if pps > ICMP_THRESHOLD:
            report_lines.append(f" - {ip} : {pps:.2f} pps (ICMP echo requests)")
            alerted = True
    if not alerted:
        report_lines.append("No suspicious ICMP flood activity detected.")

    # Check and report potential TCP SYN flooders exceeding threshold
    report_lines.append("\nPotential TCP SYN flooders:")
    alerted = False
    for ip, pps in sorted(tcp_syn_pps.items(), key=lambda x: x[1], reverse=True):
        if pps > SYN_THRESHOLD:
            report_lines.append(f" - {ip} : {pps:.2f} pps (TCP SYN packets)")
            alerted = True
    if not alerted:
        report_lines.append("No suspicious TCP SYN flood activity detected.")

# ===============================
# Print or save report
# ===============================

# Print entire report
for line in report_lines:
    print(line)

# Prompt user if they want to save the report
save_report = input("\nSave report to file? (y/n): ").strip().lower()

if save_report == 'y':
    # Create a filename with a timestamp to avoid overwriting existing files
    filename = f"network_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    # Open the file in write mode and write the report lines
    with open(filename, 'w') as f:
        for line in report_lines:
            f.write(line + "\n")
    # Confirm successful save to the user
    print(f"Report saved to {filename}")
else:
    # Inform the user that the report was not saved
    print("Report not saved.")