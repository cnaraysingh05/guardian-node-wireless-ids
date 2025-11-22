from scapy.all import *
import requests
import time
from scapy.utils import PcapWriter
import os
import json
import threading
import re

# ========================
# Configuration
# ========================

INTERFACE = "wlan1"
HOME_SSID = "YOUR_SSID_HERE"
WEBHOOK_URL = "YOUR_WEBHOOK_HERE"

KNOWN_DEVICES = {
    "88:71:b1:58:15:70": "Home Router",
    "d2:50:c2:b2:68:cf": "iPhone",
    "d8:b3:2f:c3:b6:3f": "Windows PC WiFi",
    "86:aa:fb:dc:cc:ec": "MacBook Air",
    "d8:b3:2f:c3:b6:40": "Windows Bluetooth Network"
}

LOG_PATH = "/home/cnaraysingh/guardian/log.txt"
PCAP_DIR = "/home/cnaraysingh/guardian/pcaps"
os.makedirs(PCAP_DIR, exist_ok=True)

def save_pcap(pkt, tag):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{PCAP_DIR}/{tag}_{timestamp}.pcap"
    writer = PcapWriter(filename, append=True, sync=True)
    writer.write(pkt)

def cleanup_pcaps(max_age_days=7, max_files=200):
    now = time.time()

    for fname in os.listdir(PCAP_DIR):
        path = os.path.join(PCAP_DIR, fname)
        if not os.path.isfile(path):
            continue
        age_days = (now - os.path.getmtime(path)) / 86400
        if age_days > max_age_days:
            os.remove(path)

    files = sorted(
        [os.path.join(PCAP_DIR, f) for f in os.listdir(PCAP_DIR)],
        key=os.path.getmtime
    )

    if len(files) > max_files:
        excess = len(files) - max_files
        for f in files[:excess]:
            os.remove(f)


LAST_ALERT_TIME = 0
ALERT_COOLDOWN = 10  # seconds


# ========================
# MAC Vendor Lookup Table
# ========================

OUI_TABLE = {
    "88:71:b1": "ARRIS / AT&T Router",
    "d2:50:c2": "Apple (iPhone/iPad/Mac)",
    "d8:b3:2f": "Intel / Windows Device",
    "86:aa:fb": "Apple",
    "fc:ec:da": "Samsung",
    "f4:0f:24": "Samsung",
    "ac:ae:19": "Google",
    "3c:28:6d": "Google",
    "50:32:37": "Amazon",
    "44:65:0d": "Amazon",
    "b8:27:eb": "Raspberry Pi",
    "00:e0:4c": "Realtek",
    "00:1a:79": "Microsoft",
}

def lookup_vendor(mac):
    """Return vendor name based on MAC prefix from the local table."""
    if not mac or len(mac) < 8:
        return "Unknown Vendor"
    prefix = mac.lower()[0:8]
    return OUI_TABLE.get(prefix, "Unknown Vendor")

# ========================
# Passive Client Tracking
# ========================

SEEN_CLIENTS = {}
CLIENT_TIMEOUT = 24 * 3600  # 24 hours

DEVICES_JSON = "/home/cnaraysingh/guardian/devices.json"
ATTACKS_JSON = "/home/cnaraysingh/guardian/attacks.json"

CURRENT_DEVICES = {}
CURRENT_ATTACKS = []

def track_client(mac, vendor):
    now = time.time()

    if not mac or mac == "":
        return

    SEEN_CLIENTS[mac] = now

    if mac in KNOWN_DEVICES:
        return

    if mac not in CURRENT_DEVICES:
        CURRENT_DEVICES[mac] = {
            "vendor": vendor,
            "first_seen": now,
            "last_seen": now
        }

        alert(
            f"**New Wireless Device Detected**\n"
            f"MAC: `{mac}`\n"
            f"Vendor: `{vendor}`"
        )
    else:
        CURRENT_DEVICES[mac]["last_seen"] = now


def cleanup_clients():
    """Remove clients not seen for > 24 hours."""
    now = time.time()
    dead = [mac for mac, t in SEEN_CLIENTS.items() if now - t > CLIENT_TIMEOUT]

    for mac in dead:
        del SEEN_CLIENTS[mac]

# ========================
# Utility Functions
# ========================

def log(message):
    """Write events to log file for dashboard."""
    with open(LOG_PATH, "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {message}\n")


def alert(message):
    """Send Discord alerts with cooldown."""
    global LAST_ALERT_TIME

    if time.time() - LAST_ALERT_TIME < ALERT_COOLDOWN:
        return

    LAST_ALERT_TIME = time.time()

    log(message)

    try:
        requests.post(WEBHOOK_URL, json={"content": message})
    except Exception as e:
        print(f"[!] Alert error: {e}")


print("\n Guardian Node Armed - Monitoring Wireless Space...\n")


# ========================
# Packet Handler
# ========================

def packet_handler(pkt):

    cleanup_pcaps()

    if not pkt.haslayer(Dot11):
        return

    mac = (pkt.addr2 or "").lower()
    vendor = lookup_vendor(mac)
    ssid = ""

    if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")

    # -------------------------------------
    # 1. Passive Client Tracking (Data Frames)
    # -------------------------------------
    if pkt.type == 2:
        track_client(mac, vendor)

    # -----------------------------
    # 2. Evil Twin Detection
    # -----------------------------
    if ssid == HOME_SSID and mac not in KNOWN_DEVICES and mac != "":
        if pkt.type == 0 and pkt.subtype == 8:
            CURRENT_ATTACKS.append({
                "type": "evil_twin",
                "mac": mac,
                "vendor": vendor,
                "ssid": ssid,
                "timestamp": time.time()
            })
            save_pcap(pkt, "evil_twin")
            alert(f"**Evil Twin Detected!**\nMAC: `{mac}`\nVendor: `{vendor}`\nSSID: `{ssid}`")

    # -----------------------------
    # 3. Probe Requests Targeting Home WiFi
    # -----------------------------
    if pkt.type == 0 and pkt.subtype == 4:
        if ssid == HOME_SSID and mac not in KNOWN_DEVICES:
            CURRENT_ATTACKS.append({
                "type": "probe",
                "mac": mac,
                "vendor": vendor,
                "ssid": ssid,
                "timestamp": time.time()
            })
            save_pcap(pkt, "probe_attack")
            alert(f"**Unknown Device Probing for Your WiFi**\nMAC: `{mac}`\nVendor: `{vendor}`")

    # -----------------------------
    # 4. Deauthentication Attack Detection
    # -----------------------------
    if pkt.type == 0 and pkt.subtype == 12:
        victim = pkt.addr1 or "unknown"
        source = pkt.addr2 or "unknown"

        vendor_src = lookup_vendor(source.lower())
        vendor_vic = lookup_vendor(victim.lower())

        CURRENT_ATTACKS.append({
            "type": "deauth",
            "source": source,
            "target": victim,
            "vendor_source": vendor_src,
            "vendor_target": vendor_vic,
            "timestamp": time.time()
        })

        save_pcap(pkt, "deauth_attack")

        alert(
            f"**Deauthentication Attack Detected!**\n"
            f"Source MAC: `{source}` ({vendor_src})\n"
            f"Target MAC: `{victim}` ({vendor_vic})"
        )

# ========================
# JSON writer
# ========================

def write_json_state():
    while True:
        try:
            with open(DEVICES_JSON, "w") as f:
                json.dump(CURRENT_DEVICES, f)

            # keep last 300 attacks
            if len(CURRENT_ATTACKS) > 300:
                del CURRENT_ATTACKS[:-300]

            with open(ATTACKS_JSON, "w") as f:
                json.dump(CURRENT_ATTACKS, f)

        except Exception as e:
            print("JSON write error:", e)

        time.sleep(3)

threading.Thread(target=write_json_state, daemon=True).start()


# ========================
# Sniffer Start
# ========================
if __name__ == "__main__":
    sniff(iface=INTERFACE, prn=packet_handler, store=0)
