# Network Analyzer

## Description

Network Analyzer is a Python-based tool designed for capturing and analyzing network traffic on a user-selected network interface.\
It provides detailed reports including protocol distribution, traffic insights, DNS query analysis, and detection of suspicious activities such as ICMP and TCP SYN floods.

This project was designed for learning foundational network monitoring and cybersecurity skills.

---

## Features

- **Protocol Summary**: Counts DNS, TCP, UDP, ICMP, ARP, and other packet types.
- **Traffic Insights**: Shows top talkers by IP address and ports, packet sizes, and packet frequency (packets per second).
- **DNS Analysis**: Detects unencrypted DNS queries and reports visited domains.
- **Suspicious Activity Detection**: Flags potential ICMP flood and TCP SYN flood attacks based on packet rates.
- **Report Saving**: Optionally save analysis reports to timestamped text files for further review or incident documentation.

---

## Usage

1. Ensure you run the script with root privileges to allow packet capture:

   ```bash
   sudo python3 NetworkAnalyzer.py
   ```
2. Select the network interface to monitor from the displayed list (or leave blank to use the default interface).
3. Choose the report mode:
   - 1 - Full report (all sections)
   - 2 - Traffic insights only
   - 3 - DNS analysis only
   - 4 - Suspicious activity detection only
4. Enter the capture duration in seconds (default is 5).
5. After capture and analysis, choose whether to save the report to a file.

---

## Requirements

- Python 3.x
- Scapy Python package (`pip install scapy`)
- Root/Administrator privileges for packet capture
- Linux or macOS operating system (supports libpcap)

### Installation Notes

- On macOS, ensure libpcap is installed (usually pre-installed). You may need to allow terminal or Python access to capture packets due to macOS security policies.
- On Linux, you typically need to run with root permissions or configure capabilities for packet capture.

---

## Example Output Snippet

```yaml
===== Protocol Summary =====

DNS   : 10
TCP   : 150
UDP   : 50
ICMP  : 20
ARP   : 5
Other : 3

===== Top 5 Source IP Addresses =====

Source IP Addresses            Count
-------------------------------------
192.168.1.2                    100 packets
10.0.0.5                       50 packets
...

=== DNS Encryption Check Report ===

Warning: Unencrypted DNS traffic detected.
Unique user-visited domains (3):
- www.example.com
- www.google.com
...

===== Suspicious Activity Detection =====

Potential ICMP flooders:
 - 192.168.1.10 : 25.00 pps (ICMP echo requests)
Potential TCP SYN flooders:
No suspicious TCP SYN flood activity detected.
```

---

## Author

Jorg Gradwohl

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Contributing

Feel free to fork the repository, report issues, or submit pull requests to improve the tool.

---

## Future Improvements

- Add support for encrypted DNS detection (DoH/DoT)
- Make suspicious activity detection thresholds user-configurable or adaptive
- Add detection for other network threats (port scans, brute force attempts)
- Integrate visualization (e.g., Chart.js) for protocol distribution and traffic stats