# Simple Dynamic Packet Monitoring Firewall

A dynamic on-device packet monitoring and firewall system built with Python. This tool leverages Scapy for packet capture, Tkinter for a user-friendly GUI, and Matplotlib for real-time graphing. It not only monitors network traffic in real time but also allows you to apply custom block rules on the fly.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)

---

## Features

-   **Real-Time Monitoring:** Capture and analyze network packets in real time using Scapy.
-   **Dynamic Rule Enforcement:** Automatically block malicious traffic (e.g., UDP flooding) via iptables and custom rules.
-   **Interactive GUI:** A user-friendly interface built with Tkinter to start/stop monitoring, view logs, and manage block rules.
-   **Real-Time Graphs:** Visualize network traffic with Matplotlib. Hover over graphs to view detailed stats like top IPs, protocols, and ports.
-   **Extensive Analytics:** Collects statistics such as packet counts, source/destination IPs, ports, and even MAC addresses for deeper insights.

---

## Prerequisites

Before getting started, ensure your system has the following:

-   **Operating System:** Windows/Ubuntu/Linux (Ubuntu 20.04 or later is recommended)
-   **Python 3.x:** The script is written in Python.
-   **Scapy:** For packet sniffing and manipulation.
-   **Tkinter:** For the graphical interface (usually included with Python on Linux).
-   **Matplotlib:** For generating dynamic graphs.
-   **iptables:** For applying firewall rules.
-   **Admin Privileges:** Required to monitor network traffic and apply iptables rules.

Install the necessary packages:

```sh
sudo apt update
sudo apt install python3 python3-pip iptables python3-tk
pip install scapy matplotlib
```

## Installation

Clone the repository to your local machine:

```sh
git clone [https://github.com/antnjhn/Simple-dynamic-packet-monitoring-Firewall.git](https://github.com/antnjhn/Simple-dynamic-packet-monitoring-Firewall.git)
cd Simple-dynamic-packet-monitoring-Firewall
```

## Usage

Run the firewall script with administrative privileges:

```sh
sudo python3 firewall.py
```

Once started, the GUI will appear. You can then:

-   **Start/Stop Monitoring:** Control packet sniffing.
-   **Clear Logs:** Reset current packet logs and counters.
-   **Add Block Rules:** Enter rules manually to block specific traffic.
-   **View Graphs:** Interactively analyze network traffic through various views (by protocol, IP, port, and MAC).

## How It Works

### Packet Capture & Analysis

The tool uses Scapy to sniff network packets, extracting details like IP addresses, ports, protocols, and MAC addresses.

### Dynamic Rule Enforcement

Implements automated detection (e.g., for UDP floods) and applies iptables rules to block suspicious traffic. A UDP attack is detected if too many UDP packets are received from a single IP within a given time window.

### GUI & Real-Time Data

The Tkinter interface shows a live packet log and dynamic graphs generated with Matplotlib. The graphs update every second and display detailed statistics on hover.

### Data Aggregation

Internally uses Python’s `Counter`, `defaultdict`, and `deque` to aggregate and manage traffic data, which is then visualized for quick insights.

## Detailed Code Walkthrough

### Packet Processing

`process_packet(packet)`:

The main function that processes each captured packet. It extracts protocol information (TCP, UDP, ICMP, or Other), updates various counters, and applies block rules if a packet meets certain criteria.

`update_details(protocol, src_ip, dst_ip, dst_port)`:

Updates detailed statistics for each protocol, including source and destination IP and port counts. This helps in visualizing which IPs or ports are most active.

### UDP Attack Detection

The script uses a `defaultdict` of `deque` objects (`udp_packets`) to track UDP packet timestamps per source IP. If the number of UDP packets from a single IP exceeds the `udp_threshold` within the `TIME_WINDOW`, a popup alert (`show_udp_attack_popup`) is triggered, and the offending IP is blocked via iptables.

### GUI Components

Built with Tkinter, the GUI includes buttons for starting/stopping monitoring, clearing logs, and adding block rules. A tree view displays live packet logs, while interactive graphs generated with Matplotlib provide visual summaries. The function `on_hover(event)` handles tooltips on the graph, displaying additional details like top source/destination IPs and ports when hovering over graph bars.

### Threading and Real-Time Updates

Packet sniffing runs on a separate thread (`start_sniffing_thread`) to ensure the GUI remains responsive. The elapsed time of monitoring and graph updates are refreshed periodically using Tkinter’s `after` method.

### Rule Management

Block rules can be added manually via the GUI (`add_block_rule`), and the current list of rules is displayed and managed dynamically. The function `block_ip(src_ip)` uses the system's `iptables` command to enforce a block on malicious IP addresses.

## Customization

### Thresholds

Modify the UDP attack threshold and time window by editing:

```python
udp_threshold = 100  # Maximum allowed UDP packets in the time window
TIME_WINDOW = 1      # Time window in seconds for UDP packet count
```

### Block Rules

Add your own block rules using the GUI or directly in the code.

### Graph Options

Choose different graph views (by protocol, source/destination IP, port, or MAC address) to see the metrics that matter most to you.

## Troubleshooting

### Permissions

Ensure you run the script with `sudo` to grant necessary privileges.

### Dependencies

Confirm all Python dependencies and system packages are installed.

### Graph Issues

If the graph does not update, verify your system's graphical backend for Matplotlib.

### iptables Verification

Use `iptables -L` to check if firewall rules are applied correctly.

## Contributing

Contributions are welcome! If you have suggestions or improvements, feel free to fork the repository, create a new branch, and submit a pull request.

## License

This project is licensed under the MIT License. 
