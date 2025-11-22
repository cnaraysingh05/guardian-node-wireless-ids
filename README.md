# Guardian Node – Raspberry Pi Wireless IDS

A lightweight, always-on wireless intrusion detection system running on a Raspberry Pi. 
It monitors the 2.4GHz spectrum in monitor mode and detects:

- Evil twin access points
- Rogue probe requests for your home SSID
- Deauthentication attacks
- New/unknown wireless clients
- Passive device fingerprinting (MAC vendor parsing)
- Automatic Packet captures for forensic review
- Real-time dashboard via Flask
- Discord webhook security alerts
- Automatic PCAP rotation + JSON state management
- 24/7 daemonized service using systemd

This repository contains **the source code only** (dashboard + IDS engine).
All sensitive details (SSID, logs, PCAPs, webhook URLs, JSON state files) were removed intentionally.

### Features
- Python-based IDS engine using Scapy
- Flask dashboard for live monitoring
- Fully automated systemd service on boot
- AR9271 / Realtek monitor-mode compatible
- Headless operation
- Modular structure for expansion
- PCAP evidence capture for all detected attacks
- JSON state files for dashboard integration

### System Architecture
[ Wi-Fi Spectrum ]
        ↓ Monitor Mode (wlan1)
[ Scapy Sniffer ]
        ↓ Packets
[ IDS Engine ]
    - Evil Twin detection
    - Probe request analysis
    - Deauth detection
    - Client fingerprinting
        ↓ Events
[ JSON State Files ] → Flask Dashboard
        ↓ Alerts
[ Discord Webhook ]

### Technologies Used
- Python 3
- Scapy
- Flask
- systemd
- Atheros AR9271 monitor-mode adapter
- Raspberry Pi OS

### Disclaimer
This is for educational, home-lab, and security-research purposes only.
Do not use it to monitor networks you do not own.

### Author
**Christopher Naraysingh**
Florida Atlantic University — Computer Science / Cybersecurity Track

Github: https://github.com/cnaraysingh05
