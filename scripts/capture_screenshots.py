import os
import sys
import time
import subprocess
import json
import urllib.request
import websocket
import base64
import sqlite3
import shutil
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_DB = os.path.join(BASE_DIR, "pulsecheck_demo.db")
PROD_DB = os.path.join(BASE_DIR, "pulsecheck.db")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "docs", "screenshots")

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# 1. Prepare demo database
shutil.copyfile(PROD_DB, DEMO_DB)
conn = sqlite3.connect(DEMO_DB)
cursor = conn.cursor()

# Remove bogus dummy service id 941
cursor.execute("DELETE FROM port_checks WHERE service_id = 941")
cursor.execute("DELETE FROM services WHERE id = 941")

# Clean services: replace domains with .dummy.net and clean comments/matches
cursor.execute("SELECT id, name, comment, port_protocol FROM services")
rows = cursor.fetchall()
seen_names = set()
for sid, name, comment, port_protocol in rows:
    base_name = re.sub(r"\.galleon\.(co\.za|dedyn\.io)$", "", name)
    base_name = re.sub(r"\.galleon$", "", base_name)
    base_name = re.sub(r"\.(com|co\.za|dedyn\.io|local|org|net)$", "", base_name)
    base_name = base_name.replace("galleon", "").strip(".-_")
    if not base_name:
        base_name = f"service-{sid}"
    
    clean_name = f"{base_name}.dummy.net"
    if clean_name in seen_names:
        cursor.execute("DELETE FROM port_checks WHERE service_id = ?", (sid,))
        cursor.execute("DELETE FROM services WHERE id = ?", (sid,))
        continue
    seen_names.add(clean_name)
    
    clean_comment = (comment or "").replace("galleon", "internal").strip()
    if "OpenWrt" in clean_comment:
        clean_comment = "Edge Gateway Appliance"
    elif "Machine is not always on" in clean_comment:
        clean_comment = "Development Workstation"
    elif "placeholder" in clean_comment:
        clean_comment = "Core Infrastructure Node"
    elif base_name == "bitwarden":
        clean_comment = "Production Password Vault"
    elif base_name == "bookstack":
        clean_comment = "Internal Documentation Wiki"
    elif base_name == "cockpit":
        clean_comment = "Server Telemetry Dashboard"
    elif base_name == "authelia":
        clean_comment = "Single Sign-On & 2FA Portal"
    elif base_name == "acme":
        clean_comment = "Automated TLS Certificate Authority"
    elif base_name == "beszel-lenovo":
        clean_comment = "Linux Metrics Agent"
    elif base_name == "camera":
        clean_comment = "Security RTSP Stream"

    # Clean port_protocol JSON to strip galleon
    clean_pp = (port_protocol or "[]").replace("galleon", "")
    cursor.execute("UPDATE services SET name = ?, comment = ?, port_protocol = ? WHERE id = ?", (clean_name, clean_comment, clean_pp, sid))

# Update settings: clean example values with .dummy.net
cursor.execute("UPDATE settings SET value = 'smtp.dummy.net' WHERE key = 'smtp_host'")
cursor.execute("UPDATE settings SET value = '587' WHERE key = 'smtp_port'")
cursor.execute("UPDATE settings SET value = 'tls' WHERE key = 'smtp_security'")
cursor.execute("UPDATE settings SET value = 'alerts@dummy.net' WHERE key = 'smtp_username'")
cursor.execute("UPDATE settings SET value = 'alerts@dummy.net' WHERE key = 'from_email'")
cursor.execute("UPDATE settings SET value = 'ops-team@dummy.net' WHERE key = 'recipient_email'")
cursor.execute("UPDATE settings SET value = 'proxy.dummy.net' WHERE key = 'proxy_host'")
cursor.execute("UPDATE settings SET value = '8080' WHERE key = 'proxy_port'")

# Ensure bitwarden.dummy.net has ports 80, 443 with per-port match and url_path
bitwarden_pp = json.dumps([
    {"port": 443, "protocol": "https", "match": "bitwarden", "url_path": ""},
    {"port": 80, "protocol": "http", "match": "bitwarden", "url_path": ""},
])
cursor.execute("UPDATE services SET port_protocol = ? WHERE name = 'bitwarden.dummy.net'", (bitwarden_pp,))

# Set beszel-lenovo.dummy.net to degraded and camera.dummy.net to offline to show color-coded badges
cursor.execute("SELECT id FROM services WHERE name = 'beszel-lenovo.dummy.net'")
row = cursor.fetchone()
if row:
    cursor.execute("UPDATE port_checks SET status = 'degraded', last_response_ms = 412 WHERE service_id = ?", (row[0],))

cursor.execute("SELECT id FROM services WHERE name = 'camera.dummy.net'")
row = cursor.fetchone()
if row:
    cursor.execute("UPDATE port_checks SET status = 'offline', is_online = 0, last_response_ms = NULL WHERE service_id = ?", (row[0],))

# Seed network discovery metadata with demo IP/MAC/manufacturers
cursor.execute("UPDATE services SET discovered_ip = '192.168.1.50', discovered_mac = 'B8:27:EB:12:34:56', discovered_manufacturer = 'Realtek Semiconductor' WHERE name = 'bitwarden.dummy.net'")
cursor.execute("UPDATE services SET discovered_ip = '192.168.1.1', discovered_mac = '64:D1:54:88:99:AA', discovered_manufacturer = 'MikroTik' WHERE name = 'edge-gateway.dummy.net' OR comment LIKE '%Edge Gateway%'")
cursor.execute("UPDATE services SET discovered_ip = '192.168.1.102', discovered_mac = 'A4:83:E7:33:44:55', discovered_manufacturer = 'Apple' WHERE name = 'cockpit.dummy.net'")

conn.commit()

# Verify no galleon occurrences remain anywhere in the database
found = []
for t in ["services", "port_checks", "settings"]:
    cursor.execute(f"PRAGMA table_info({t})")
    cols = [c[1] for c in cursor.fetchall()]
    for c in cols:
        cursor.execute(f"SELECT COUNT(*) FROM {t} WHERE CAST({c} AS TEXT) LIKE '%galleon%'")
        cnt = cursor.fetchone()[0]
        if cnt > 0:
            found.append(f"{t}.{c}: {cnt}")
conn.close()

if found:
    print("WARNING: Galleon occurrences found in demo DB:", found)
else:
    print("SUCCESS: 0 galleon occurrences in demo DB!")

# Get bitwarden.dummy.net ID
conn = sqlite3.connect(DEMO_DB)
cursor = conn.cursor()
cursor.execute("SELECT id FROM services WHERE name = 'bitwarden.dummy.net'")
bitwarden_row = cursor.fetchone()
bitwarden_id = bitwarden_row[0] if bitwarden_row else 1
conn.close()

# 2. Launch Flask on port 8189
env = os.environ.copy()
env["PULSECHECK_HEADLESS"] = "1"
env["PULSECHECK_DB_PATH"] = DEMO_DB
env["PULSECHECK_PORT"] = "8189"
flask_proc = subprocess.Popen([sys.executable, "app.py"], cwd=BASE_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2.5)

# Wait for Flask
for _ in range(15):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8189/status") as r:
            if r.status == 200:
                print("PulseCheck Flask is ready on port 8189!")
                break
    except Exception:
        time.sleep(0.5)

# 3. Launch Chrome Headless via Flatpak
chrome_cmd = [
    "flatpak", "run",
    f"--filesystem={BASE_DIR}",
    "com.google.Chrome",
    "--headless=new",
    "--remote-debugging-port=9222",
    "--remote-allow-origins=*",
    "--user-data-dir=/tmp/pulsecheck_clean_profile",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-gpu",
    "--no-sandbox",
    "--window-size=1440,960",
]
chrome_proc = subprocess.Popen(chrome_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2.0)

try:
    tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:9222/json").read())
    page_tabs = [t for t in tabs if t.get("type") == "page"]
    ws_url = page_tabs[0]["webSocketDebuggerUrl"]
    ws = websocket.create_connection(ws_url)
    
    _id = 0
    def send_cmd(method, params=None):
        global _id
        _id += 1
        payload = {"id": _id, "method": method, "params": params or {}}
        ws.send(json.dumps(payload))
        while True:
            resp = json.loads(ws.recv())
            if resp.get("id") == payload["id"]:
                return resp.get("result")

    def capture(name, path, js_action=None, wait=1.5, height=920):
        print(f"Capturing {name} ({path})...")
        send_cmd("Page.navigate", {"url": f"http://127.0.0.1:8189{path}"})
        time.sleep(wait)
        if js_action:
            send_cmd("Runtime.evaluate", {"expression": js_action})
            time.sleep(0.6)
        res = send_cmd("Page.captureScreenshot", {
            "format": "png",
            "clip": {"x": 0, "y": 0, "width": 1440, "height": height, "scale": 1}
        })
        filename = os.path.join(SCREENSHOTS_DIR, f"{name}.png")
        with open(filename, "wb") as f:
            f.write(base64.b64decode(res["data"]))
        print(f"Saved: {filename}")

    send_cmd("Emulation.setDeviceMetricsOverride", {
        "width": 1440,
        "height": 960,
        "deviceScaleFactor": 1,
        "mobile": False,
    })
    send_cmd("Page.enable")

    # 1. Live Status Dashboard
    # Expand first card to showcase the discovery metadata and port chips with protocol micro-icons
    js_dashboard = """
    (function() {
      const firstCard = document.querySelector('.status-card[data-service="bitwarden.dummy.net"]') || document.querySelector('.status-card');
      if (firstCard) {
        const header = firstCard.querySelector('.status-card-header');
        if (header) header.click();
      }
    })();
    """
    capture("dashboard", "/status", js_action=js_dashboard, height=920)

    # 2. Services Inventory & Management
    capture("services", "/services", height=880)

    # 3. Service Configuration & Ports Form
    capture("edit_service", f"/services/{bitwarden_id}/edit", height=920)

    # 4. Live Diagnostics ("Test Probes") on Add/Edit
    js_diag = """
    (function() {
      const mockData = {
        success: true,
        service_name: "bitwarden.dummy.net",
        overall_status: "online",
        timestamp: "2026-09-30 15:30:12",
        ports: [
          {
            port: 443,
            status: "online",
            protocol: "https",
            status_code: 200,
            status_text: "HTTP 200",
            duration_ms: 28,
            fallback_level: 0,
            timestamp: "2026-09-30 15:30:12",
            match_found: true,
            match_token: "bitwarden",
            match_count: 2,
            error_message: null,
            response_snippet: "HTTP/1.1 200 OK\\r\\nServer: nginx\\r\\nContent-Type: text/html\\r\\n\\r\\n<!DOCTYPE html>\\n<html><head><title>Bitwarden Web Vault</title></head>\\n<body><div id=\\\"app\\\">Bitwarden Vault loading...</div></body></html>"
          },
          {
            port: 80,
            status: "online",
            protocol: "http",
            status_code: 301,
            status_text: "HTTP 301",
            duration_ms: 14,
            fallback_level: 0,
            timestamp: "2026-09-30 15:30:12",
            match_found: true,
            match_token: "bitwarden",
            match_count: 1,
            error_message: null,
            response_snippet: "HTTP/1.1 301 Moved Permanently\\r\\nLocation: https://bitwarden.dummy.net/\\r\\nServer: nginx\\r\\nContent-Length: 178"
          }
        ]
      };
      const diagTabBtn = document.getElementById('tab-port-diagnostics');
      if (diagTabBtn) diagTabBtn.click();
      if (typeof window.renderDiagnosticResults === 'function') {
        window.renderDiagnosticResults(mockData);
        const tabBtn = document.querySelector('[data-target="tab-panel-port-443"]');
        if (tabBtn) tabBtn.click();
      }
    })();
    """
    capture("live_diagnostics", f"/services/{bitwarden_id}/edit", js_action=js_diag, wait=1.5, height=920)

    # 5. Settings & SMTP Alerts
    capture("settings", "/settings", height=920)

    # 6. Data Import & Export
    js_import = """
    (function() {
      const ta = document.getElementById('services');
      if (ta) {
        ta.value = 'bitwarden.dummy.net\\nbookstack.dummy.net\\ncockpit.dummy.net\\ngrafana.dummy.net\\nnextcloud.dummy.net\\nauth.dummy.net\\napi.dummy.net';
        ta.dispatchEvent(new Event('input'));
      }
    })();
    """
    capture("import_export", "/import", js_action=js_import, wait=1.2, height=880)

    # 7. State Change Email Alert Notification Preview
    capture("email_alert", "/preview/email", wait=1.0, height=820)

finally:
    chrome_proc.terminate()
    flask_proc.terminate()
    if os.path.exists(DEMO_DB):
        os.remove(DEMO_DB)

print("All screenshots generated and verified successfully!")
