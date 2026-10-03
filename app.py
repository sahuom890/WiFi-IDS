"""
Wi-Fi Intrusion Detection and Investigation System
====================================================
A Flask-based web application that monitors Wi-Fi traffic using Scapy,
detects intrusion patterns (deauth attacks, suspicious MACs, brute-force
attempts), and logs them in an SQLite database for investigation.

Includes a SIMULATION MODE (enabled by default) so the app works seamlessly
on cloud hosts (Render, Railway, Vercel) and machines without a monitor-mode adapter.
"""

import os
import sqlite3
import threading
import time
import random
import string
from datetime import datetime

from flask import Flask, render_template, jsonify, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

app = Flask(__name__)

DATABASE = os.environ.get("IDS_DATABASE", "ids_database.db")

# Simulation mode: true by default for zero-hardware cloud demos & local testing
SIMULATION_MODE = os.environ.get("SIMULATION_MODE", "true").lower() in ("true", "1", "yes")

# Suspicious MAC addresses blocklist (example rogue / known attacker OUIs)
SUSPICIOUS_MACS = [
    "de:ad:be:ef:00:01",
    "aa:bb:cc:dd:ee:ff",
    "66:66:66:66:66:66",
]

# Brute-force detection: max auth attempts per MAC within the time window
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW = 60  # seconds

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a new database connection (one per call / per thread)."""
    conn = sqlite3.connect(DATABASE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the alerts table if it does not already exist."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            source_mac  TEXT    NOT NULL,
            attack_type TEXT    NOT NULL,
            details     TEXT
        )
    """)
    conn.commit()
    conn.close()


# Ensure database tables exist at application startup (critical for WSGI / Gunicorn)
init_db()


def insert_alert(source_mac: str, attack_type: str, details: str = ""):
    """Insert a new alert row into the database."""
    conn = get_db()
    conn.execute(
        "INSERT INTO alerts (timestamp, source_mac, attack_type, details) VALUES (?, ?, ?, ?)",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_mac, attack_type, details),
    )
    conn.commit()
    conn.close()


def fetch_alerts(limit: int = 50):
    """Return the most recent `limit` alerts, newest first."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def fetch_all_alerts():
    """Return every alert in the database, newest first."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------------------------------------------------------------------------
# Monitoring engine
# ---------------------------------------------------------------------------

monitor_thread = None
monitoring_active = False

auth_tracker: dict[str, list[float]] = {}


def _random_mac() -> str:
    """Generate a random MAC address string."""
    return ":".join(
        "".join(random.choices(string.hexdigits[:16].lower(), k=2)) for _ in range(6)
    )


def _detect_packet(packet):
    """
    Analyse a single Scapy packet for intrusion indicators.
    Called from the real sniffer callback (non-simulation mode).
    """
    try:
        from scapy.layers.dot11 import Dot11, Dot11Deauth

        if packet.haslayer(Dot11):
            src_mac = packet[Dot11].addr2
            if src_mac is None:
                return

            # --- Deauthentication attack detection ---
            if packet.haslayer(Dot11Deauth):
                detail = f"Deauth frame detected from {src_mac}"
                insert_alert(src_mac, "Deauthentication Attack", detail)
                return

            # --- Suspicious MAC detection ---
            if src_mac.lower() in [m.lower() for m in SUSPICIOUS_MACS]:
                detail = f"Traffic from blocklisted MAC {src_mac}"
                insert_alert(src_mac, "Suspicious MAC Address", detail)
                return

            # --- Brute-force detection (auth frame flood) ---
            if packet[Dot11].type == 0 and packet[Dot11].subtype == 11:
                now = time.time()
                auth_tracker.setdefault(src_mac, [])
                auth_tracker[src_mac].append(now)
                auth_tracker[src_mac] = [
                    t for t in auth_tracker[src_mac] if now - t < BRUTE_FORCE_WINDOW
                ]
                if len(auth_tracker[src_mac]) >= BRUTE_FORCE_THRESHOLD:
                    detail = (
                        f"{len(auth_tracker[src_mac])} auth attempts from {src_mac} "
                        f"in the last {BRUTE_FORCE_WINDOW}s"
                    )
                    insert_alert(src_mac, "Brute-Force Attempt", detail)
                    auth_tracker[src_mac] = []
    except Exception as exc:
        print(f"[!] Packet analysis error: {exc}")


def _real_sniff():
    """Start Scapy sniffing on the default monitor-mode interface."""
    try:
        from scapy.all import sniff as scapy_sniff

        scapy_sniff(
            iface="wlan0mon",
            prn=_detect_packet,
            store=False,
            stop_filter=lambda _: not monitoring_active,
        )
    except Exception as exc:
        print(f"[!] Scapy sniff error (ensure monitor mode & root permissions): {exc}")


def _simulated_sniff():
    """Generate fake intrusion events at random intervals for demo purposes."""
    global monitoring_active

    attack_types = [
        ("Deauthentication Attack", "Deauth frame detected from {mac}"),
        ("Suspicious MAC Address", "Traffic from blocklisted MAC {mac}"),
        ("Brute-Force Attempt", "{count} auth attempts from {mac} in the last 60s"),
    ]

    while monitoring_active:
        time.sleep(random.uniform(2, 6))
        if not monitoring_active:
            break

        attack, detail_template = random.choice(attack_types)
        mac = (
            random.choice(SUSPICIOUS_MACS)
            if attack == "Suspicious MAC Address"
            else _random_mac()
        )
        detail = detail_template.format(mac=mac, count=random.randint(10, 50))
        insert_alert(mac, attack, detail)


def start_monitoring():
    """Spin up the background monitoring thread."""
    global monitor_thread, monitoring_active

    if monitoring_active:
        return

    monitoring_active = True
    target = _simulated_sniff if SIMULATION_MODE else _real_sniff
    monitor_thread = threading.Thread(target=target, daemon=True)
    monitor_thread.start()


def stop_monitoring():
    """Signal the monitoring thread to stop."""
    global monitoring_active
    monitoring_active = False

# ---------------------------------------------------------------------------
# Flask routes — Pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    """Render the landing / home page."""
    return render_template("home.html")


@app.route("/dashboard")
def dashboard():
    """Render the live dashboard page."""
    return render_template("dashboard.html")


@app.route("/logs")
def logs():
    """Render the historical logs page."""
    return render_template("logs.html")

# ---------------------------------------------------------------------------
# Flask routes — API
# ---------------------------------------------------------------------------

@app.route("/api/status")
def api_status():
    """Return the current monitoring status."""
    return jsonify({"running": monitoring_active, "simulation": SIMULATION_MODE})


@app.route("/api/start", methods=["POST"])
def api_start():
    """Start the monitoring engine."""
    start_monitoring()
    return jsonify({"running": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    """Stop the monitoring engine."""
    stop_monitoring()
    return jsonify({"running": False})


@app.route("/api/alerts")
def api_alerts():
    """Return the latest 50 alerts as JSON (for dashboard polling)."""
    return jsonify(fetch_alerts(limit=50))


@app.route("/api/alerts/all")
def api_all_alerts():
    """Return all alerts as JSON (for the Logs page)."""
    return jsonify(fetch_all_alerts())


@app.route("/api/alerts/clear", methods=["POST"])
def api_clear_alerts():
    """Delete every alert from the database."""
    conn = get_db()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return jsonify({"cleared": True})

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")
    print("[*] Wi-Fi IDS starting in", "SIMULATION" if SIMULATION_MODE else "LIVE", "mode")
    print(f"[*] Open http://127.0.0.1:{port} in your browser")
    app.run(debug=True, host=host, port=port)
