from flask import Flask, render_template_string, send_from_directory
import json
import os
import time

BASE_DIR = "/home/cnaraysingh/guardian"
LOG_PATH = f"{BASE_DIR}/log.txt"
DEVICES_JSON = f"{BASE_DIR}/devices.json"
ATTACKS_JSON = f"{BASE_DIR}/attacks.json"
PCAP_DIR = f"{BASE_DIR}/pcaps"

app = Flask(__name__)

html = """
<!DOCTYPE html>
<html>
<head>
<title>Guardian Dashboard</title>
<meta http-equiv="refresh" content="5">
<style>
    body { background-color:#111; color:white; font-family:Arial; padding:20px; }
    h1 { color:#00ffae; }
    h2 { margin-top:40px; }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th, td { padding:8px; border-bottom:1px solid #333; }
    th { color:#00ffae; text-align:left; }
    .pcap-link a { color:#00c8ff; text-decoration:none; }
    .pcap-link a:hover { text-decoration:underline; }
    pre { background:#222; padding:15px; border-radius:8px; white-space:pre-wrap; }
</style>
</head>

<body>

<h1>Guardian Node - Live Dashboard</h1>

<!-- ======================= -->
<!-- Live Devices Table -->
<!-- ======================= -->

<h2>Active Devices</h2>
<table>
    <tr>
        <th>MAC</th>
        <th>Vendor</th>
        <th>First Seen</th>
        <th>Last Seen</th>
    </tr>
    {% for mac, dev in devices.items() %}
    <tr>
        <td>{{ mac }}</td>
        <td>{{ dev.vendor }}</td>
        <td>{{ dev.first }}</td>
        <td>{{ dev.last }}</td>
    </tr>
    {% endfor %}
</table>

<!-- ======================= -->
<!-- Recent Attacks Table -->
<!-- ======================= -->

<h2>Recent Attacks</h2>
<table>
    <tr>
        <th>Type</th>
        <th>MAC / Source</th>
        <th>Target</th>
        <th>Vendor</th>
        <th>Timestamp</th>
    </tr>
    {% for atk in attacks %}
    <tr>
        <td>{{ atk.type }}</td>
        <td>{{ atk.mac or atk.source }}</td>
        <td>{{ atk.target or "-" }}</td>
        <td>{{ atk.vendor or atk.vendor_source }}</td>
        <td>{{ atk.time }}</td>
    </tr>
    {% endfor %}
</table>

<!-- ======================= -->
<!-- PCAP File Downloads -->
<!-- ======================= -->

<h2>Saved PCAP Files</h2>
<table>
    <tr>
        <th>File</th>
        <th>Download</th>
    </tr>
    {% for p in pcaps %}
    <tr>
        <td>{{ p }}</td>
        <td class="pcap-link"><a href="/pcap/{{ p }}">Download</a></td>
    </tr>
    {% endfor %}
</table>

<!-- ======================= -->
<!-- Log Viewer -->
<!-- ======================= -->

<h2>Last 100 Log Entries</h2>
<pre>{{ logs }}</pre>

</body>
</html>
"""

def load_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except:
        return {}

@app.route("/")
def dashboard():
    # Load devices.json
    raw_devices = load_json(DEVICES_JSON)
    devices = {}
    for mac, d in raw_devices.items():
        devices[mac] = {
            "vendor": d.get("vendor", "Unknown"),
            "first": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.get("first_seen", 0))),
            "last": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.get("last_seen", 0))),
        }

    # Load attacks.json
    raw_attacks = load_json(ATTACKS_JSON)
    attacks = []
    for a in raw_attacks:
        attacks.append({
            "type": a.get("type", "-"),
            "mac": a.get("mac"),
            "source": a.get("source"),
            "target": a.get("target"),
            "vendor": a.get("vendor"),
            "vendor_source": a.get("vendor_source"),
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a.get("timestamp", 0))),
        })

    # Load last 100 logs
    try:
        with open(LOG_PATH, "r") as f:
            logs = "".join(f.readlines()[-100:])
    except:
        logs = "No logs yet."

    # PCAP list
    try:
        pcaps = sorted(os.listdir(PCAP_DIR))
    except:
        pcaps = []

    return render_template_string(html, devices=devices, attacks=attacks, logs=logs, pcaps=pcaps)

@app.route("/pcap/<filename>")
def download_pcap(filename):
    return send_from_directory(PCAP_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=False)

