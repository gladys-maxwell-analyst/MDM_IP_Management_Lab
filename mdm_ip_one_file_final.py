#!/usr/bin/env python3
"""
IP-Based MDM Lab - Final One File
Authorized devices only.

Run server:
    python mdm_ip_one_file_final.py server

Run agent:
    python mdm_ip_one_file_final.py agent --server http://localhost:5000

Open:
    http://localhost:5000

This lab version intentionally uses the device's IP address as a network
attribute and does NOT use an enrollment token. IP address is not a secure
device identity for production MDM.
"""

import argparse
import json
import os
import platform
import shutil
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, quote

DB_FILE = "mdm_ip_lab.db"
HEARTBEAT_SECONDS = 15


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT UNIQUE NOT NULL,
            hostname TEXT,
            ip_address TEXT,
            os_name TEXT,
            os_version TEXT,
            cpu TEXT,
            memory_gb REAL,
            disk_percent REAL,
            battery_percent REAL,
            last_seen TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_key TEXT,
            action TEXT,
            ip_address TEXT,
            created_at TEXT
        )
    """)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
    if "memory_used_percent" not in existing:
        conn.execute("ALTER TABLE devices ADD COLUMN memory_used_percent REAL")
    if "uptime_hours" not in existing:
        conn.execute("ALTER TABLE devices ADD COLUMN uptime_hours REAL")
    conn.commit()
    conn.close()


def local_ip():
    # Best-effort LAN IP detection without transmitting data anywhere.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        host = socket.gethostbyname(socket.gethostname())
        s.connect((host, 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    finally:
        s.close()

    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass
    return socket.gethostbyname("localhost")


def memory_gb():
    try:
        if os.name == "nt":
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            m = MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return round(m.ullTotalPhys / (1024 ** 3), 2)
    except Exception:
        pass
    return None


def memory_used_percent():
    try:
        if os.name == "nt":
            import ctypes
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            m = MEMORYSTATUSEX()
            m.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return int(m.dwMemoryLoad)
    except Exception:
        pass
    return None


def uptime_hours():
    try:
        if os.name == "nt":
            import ctypes
            ms = ctypes.windll.kernel32.GetTickCount64()
            return round(ms / 1000 / 3600, 1)
    except Exception:
        pass
    return None


def compliance_status(d):
    reasons = []
    if d["disk_percent"] is not None and d["disk_percent"] >= 90:
        reasons.append("Disk usage >= 90%")
    if d["memory_used_percent"] is not None and d["memory_used_percent"] >= 90:
        reasons.append("Memory usage >= 90%")
    if d["battery_percent"] is not None and d["battery_percent"] <= 15:
        reasons.append("Battery <= 15%")
    return ("NON-COMPLIANT" if reasons else "COMPLIANT"), reasons


def audit_rows(limit=50):
    conn = db()
    rows = conn.execute(
        "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return rows


def health_status(d):
    disk = d["disk_percent"]
    mem = d["memory_used_percent"]
    battery = d["battery_percent"]
    if disk is not None and disk >= 90:
        return "WARNING"
    if mem is not None and mem >= 90:
        return "WARNING"
    if battery is not None and battery <= 15:
        return "WARNING"
    return "HEALTHY"


def battery_percent():
    try:
        if hasattr(shutil, "disk_usage") and os.name == "nt":
            import ctypes
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ("ACLineStatus", ctypes.c_byte),
                    ("BatteryFlag", ctypes.c_byte),
                    ("BatteryLifePercent", ctypes.c_byte),
                    ("Reserved", ctypes.c_byte),
                    ("BatteryLifeTime", ctypes.c_ulong),
                    ("BatteryFullLifeTime", ctypes.c_ulong),
                ]
            s = SYSTEM_POWER_STATUS()
            if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(s)):
                if s.BatteryLifePercent <= 100:
                    return int(s.BatteryLifePercent)
    except Exception:
        pass
    return None


def device_info():
    hostname = socket.gethostname()
    ip = local_ip()
    # Stable lab key based on hostname + IP. This is not cryptographic identity.
    device_key = f"{hostname}@{ip}"

    root = os.path.abspath(os.sep)
    try:
        du = shutil.disk_usage(root)
        disk_percent = round((du.used / du.total) * 100, 1)
    except Exception:
        disk_percent = None

    return {
        "device_key": device_key,
        "hostname": hostname,
        "ip_address": ip,
        "os_name": platform.system(),
        "os_version": platform.version(),
        "cpu": platform.processor() or platform.machine(),
        "memory_gb": memory_gb(),
        "memory_used_percent": memory_used_percent(),
        "disk_percent": disk_percent,
        "battery_percent": battery_percent(),
        "uptime_hours": uptime_hours(),
        "last_seen": now(),
    }


def upsert_device(info):
    conn = db()
    conn.execute("""
        INSERT INTO devices (
            device_key, hostname, ip_address, os_name, os_version,
            cpu, memory_gb, disk_percent, battery_percent,
            memory_used_percent, uptime_hours, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(device_key) DO UPDATE SET
            hostname=excluded.hostname,
            ip_address=excluded.ip_address,
            os_name=excluded.os_name,
            os_version=excluded.os_version,
            cpu=excluded.cpu,
            memory_gb=excluded.memory_gb,
            disk_percent=excluded.disk_percent,
            battery_percent=excluded.battery_percent,
            memory_used_percent=excluded.memory_used_percent,
            uptime_hours=excluded.uptime_hours,
            last_seen=excluded.last_seen
    """, (
        info["device_key"], info["hostname"], info["ip_address"],
        info["os_name"], info["os_version"], info["cpu"],
        info["memory_gb"], info["disk_percent"],
        info["battery_percent"], info["memory_used_percent"],
        info["uptime_hours"], info["last_seen"]
    ))
    conn.execute(
        "INSERT INTO audit(device_key, action, ip_address, created_at) VALUES (?, ?, ?, ?)",
        (info["device_key"], "device check-in", info["ip_address"], now())
    )
    conn.commit()
    conn.close()


def post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP-Based MDM Lab — Final</title>
<style>
body{font-family:Arial,sans-serif;background:#f5f7fb;margin:0;color:#18212f}
header{background:#182b49;color:white;padding:22px}
main{max-width:1100px;margin:24px auto;padding:0 16px}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.card{background:white;border-radius:12px;padding:18px;min-width:150px;box-shadow:0 2px 8px #0001}
.num{font-size:28px;font-weight:700}
input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ccd3df;border-radius:8px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden}
th,td{padding:12px;text-align:left;border-bottom:1px solid #edf0f5}
th{background:#eef2f7}
.online{font-weight:700}
a{color:#1f5fbf;text-decoration:none}
.small{color:#667085;font-size:13px}
</style>
</head>
<body>
<header>
<h1>IP-Based MDM Lab — Final</h1>
<div>Authorized device management dashboard</div>
</header>
<main>
<div class="cards">
<div class="card"><div class="small">Total Devices</div><div class="num">{{TOTAL}}</div></div>
<div class="card"><div class="small">Online</div><div class="num">{{ONLINE}}</div></div>
<div class="card"><div class="small">Offline</div><div class="num">{{OFFLINE}}</div></div>
<div class="card"><div class="small">Compliant</div><div class="num">{{COMPLIANT}}</div></div>
<div class="card"><div class="small">Attention</div><div class="num">{{ATTENTION}}</div></div>
</div>

<p><a href="/audit">View Audit Log →</a></p>
<input id="search" placeholder="Search by device name or IP address..." onkeyup="filterTable()">

<table id="devices">
<thead><tr>
<th>Device</th><th>IP Address</th><th>OS</th><th>Disk</th><th>Memory</th><th>Health</th><th>Compliance</th><th>Status</th><th>Last Seen</th>
</tr></thead>
<tbody>
{{ROWS}}
</tbody>
</table>
<p class="small">IP is a network attribute, not secure authentication. Compliance uses simple lab thresholds. See the audit log for recorded activity.</p>
</main>
<script>
function filterTable(){
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#devices tbody tr').forEach(r=>{
    r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';
  });
}
setTimeout(()=>location.reload(),15000);
</script>
</body>
</html>"""


def dashboard():
    conn = db()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()

    online_count = 0
    compliant_count = 0
    attention_count = 0
    html_rows = []

    for d in rows:
        try:
            seen = datetime.fromisoformat(d["last_seen"])
            age = (datetime.now(timezone.utc) - seen).total_seconds()
        except Exception:
            age = 999999

        online = age <= 45
        if online:
            online_count += 1

        status = "ONLINE" if online else "OFFLINE"
        disk = "N/A" if d["disk_percent"] is None else f'{d["disk_percent"]}%'
        mem = "N/A" if d["memory_used_percent"] is None else f'{d["memory_used_percent"]}%'
        health = health_status(d)
        compliance, reasons = compliance_status(d)
        if compliance == "COMPLIANT":
            compliant_count += 1
        else:
            attention_count += 1
        html_rows.append(
            f'<tr><td><a href="/device/{quote(d["device_key"], safe="")}">{d["hostname"]}</a></td>'
            f'<td>{d["ip_address"]}</td><td>{d["os_name"]}</td>'
            f'<td>{disk}</td><td>{mem}</td><td>{health}</td>'
            f'<td>{compliance}</td><td class="online">{status}</td><td>{d["last_seen"]}</td></tr>'
        )

    total = len(rows)
    html = HTML.replace("{{TOTAL}}", str(total))
    html = html.replace("{{ONLINE}}", str(online_count))
    html = html.replace("{{OFFLINE}}", str(total - online_count))
    html = html.replace("{{COMPLIANT}}", str(compliant_count))
    html = html.replace("{{ATTENTION}}", str(attention_count))
    html = html.replace("{{ROWS}}", "\n".join(html_rows) or
                        '<tr><td colspan="6">No devices enrolled yet.</td></tr>')
    return html


class Handler(BaseHTTPRequestHandler):
    def send_json(self, obj, status=200):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            raw = dashboard().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if parsed.path == "/audit":
            rows = audit_rows(100)
            items = []
            for r in rows:
                items.append(
                    f"<tr><td>{r['created_at']}</td><td>{r['device_key']}</td>"
                    f"<td>{r['action']}</td><td>{r['ip_address']}</td></tr>"
                )
            body = """
            <html><body style="font-family:Arial;padding:30px">
            <h1>Audit Log</h1>
            <p><a href="/">← Back to Dashboard</a></p>
            <table border="1" cellpadding="8" cellspacing="0">
            <tr><th>Time</th><th>Device</th><th>Action</th><th>IP</th></tr>
            """ + ("\n".join(items) or "<tr><td colspan='4'>No audit events yet.</td></tr>") + """
            </table></body></html>"""
            raw = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if parsed.path.startswith("/device/"):
            key = parsed.path[len("/device/"):]
            conn = db()
            d = conn.execute(
                "SELECT * FROM devices WHERE device_key=?",
                (key,)
            ).fetchone()
            conn.close()
            if not d:
                self.send_error(404)
                return
            compliance, reasons = compliance_status(d)
            details = "<h1>Device Details</h1><p><b>Health:</b> " + health_status(d) + "</p><p><b>Compliance:</b> " + compliance + "</p><p><b>Reasons:</b> " + (", ".join(reasons) if reasons else "None") + "</p><pre>" + json.dumps(dict(d), indent=2) + "</pre>"
            raw = f"<html><body style='font-family:Arial;padding:30px'>{details}<p><a href='/'>Back</a></p></body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path in ("/api/enroll", "/api/heartbeat"):
            try:
                data = self.read_json()
                if not data:
                    self.send_json({"error": "Empty request"}, 400)
                    return

                # Server records the network source address too.
                peer_ip = self.client_address[0]
                data["ip_address"] = data.get("ip_address") or peer_ip

                # The IP is deliberately treated as a network attribute only.
                # No enrollment token is required in this local lab.
                data["last_seen"] = now()
                upsert_device(data)

                self.send_json({
                    "ok": True,
                    "message": "Device registered successfully",
                    "device_key": data["device_key"],
                    "ip_address": data["ip_address"],
                })
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        self.send_json({"error": "Not found"}, 404)


def server(port):
    init_db()
    httpd = ThreadingHTTPServer(("", port), Handler)
    print("IP-BASED MDM LAB")
    print(f"Dashboard: http://localhost:{port}")
    print("Enrollment token: NOT REQUIRED")
    print("IP address is recorded as a network attribute.")
    print("Use only with devices you own or are authorized to manage.")
    httpd.serve_forever()


def agent(server_url):
    info = device_info()
    url = server_url.rstrip("/") + "/api/enroll"
    print(f"Registering device: {info['hostname']}")
    print(f"Detected IP: {info['ip_address']}")
    try:
        result = post_json(url, info)
        print(result.get("message", "Device registered."))
        print(f"Device key: {result.get('device_key', info['device_key'])}")
        print("Sending heartbeats every 15 seconds. Press Ctrl+C to stop.")
        while True:
            time.sleep(HEARTBEAT_SECONDS)
            info = device_info()
            post_json(server_url.rstrip("/") + "/api/heartbeat", info)
            print(f"Heartbeat sent: {info['ip_address']}  {info['last_seen']}")
    except urllib.error.URLError as e:
        print(f"Server error: {e}")
    except KeyboardInterrupt:
        print("\nAgent stopped.")
    except Exception as e:
        print(f"Agent error: {e}")


def main():
    parser = argparse.ArgumentParser(description="One-file IP-based MDM lab")
    sub = parser.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("server")
    s.add_argument("--port", type=int, default=5000)

    a = sub.add_parser("agent")
    a.add_argument("--server", default="http://localhost:5000")

    args = parser.parse_args()

    if args.mode == "server":
        server(args.port)
    elif args.mode == "agent":
        agent(args.server)


if __name__ == "__main__":
    main()
