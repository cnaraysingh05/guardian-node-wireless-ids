# Guardian Node – Raspberry Pi Wireless IDS

A lightweight, always-on wireless intrusion detection system running on a Raspberry Pi. 
It monitors the 2.4GHz spectrum in monitor mode and detects:

- Evil twin access points
- Rogue probe requests for your home SSID
- Deauthentication attacks
- New/unknown wireless clients
- Packet captures for forensic review
- Live dashboard via Flask
- Discord webhook alerts
- Automatic PCAP rotation + JSON state files
- Fully automated systemd service on boot

This repository contains **the source code only** (dashboard + IDS engine).
All sensitive details (SSID, logs, PCAPs, webhook URLs, JSON state files) were removed intentionally.

### Features
- Written in Python using Scapy, Flask, and systemd
- Runs headless as a service
- Forensic packet captures saved automatically
- Modular and hackable design for expansion
- Works with Atheros AR9271 and Realtek monitor-mode adapters

### Disclaimer
This is for educational, home-lab, and security-research purposes only.
Do not use it to monitor networks you do not own.

### Author
**Christopher Naraysingh**
Florida Atlantic University — Computer Science / Cybersecurity Track
