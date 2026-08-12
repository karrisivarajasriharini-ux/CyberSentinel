import os
import sys
import sqlite3
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP

# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ============================================================
# RISK ENGINE
# ============================================================

from detection.risk_engine import calculate_risk


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_NAME = os.path.join(
    PROJECT_ROOT,
    "database",
    "cybersentinel.db"
)


# ============================================================
# SAVE SECURITY EVENT
# ============================================================

def save_event(
    source_ip,
    destination_ip,
    threat_type
):

    risk_score, severity = calculate_risk(
        threat_type
    )

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO security_events
        (
            timestamp,
            source_ip,
            destination_ip,
            threat_type,
            risk_score,
            severity
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            source_ip,
            destination_ip,
            threat_type,
            risk_score,
            severity
        )
    )

    connection.commit()
    connection.close()

    print()
    print("=" * 60)
    print("CYBERSENTINEL THREAT DETECTED")
    print("=" * 60)
    print("Source IP      :", source_ip)
    print("Destination IP :", destination_ip)
    print("Threat         :", threat_type)
    print("Risk Score     :", risk_score)
    print("Severity       :", severity)
    print("=" * 60)
    print()


# ============================================================
# PORT SCAN TRACKING
# ============================================================

connection_tracker = defaultdict(set)


def detect_port_scan(
    source_ip,
    destination_ip,
    destination_port
):

    key = (
        source_ip,
        destination_ip
    )

    connection_tracker[key].add(
        destination_port
    )

    port_count = len(
        connection_tracker[key]
    )

    print(
        f"[PORT] {source_ip} -> "
        f"{destination_ip}:{destination_port} "
        f"| Ports observed: {port_count}"
    )

    # Detect possible port scan
    if port_count == 10:

        save_event(
            source_ip,
            destination_ip,
            "Port Scanning"
        )


# ============================================================
# PACKET PROCESSOR
# ============================================================

def process_packet(packet):

    # Ignore packets without IP layer
    if not packet.haslayer(IP):
        return

    source_ip = packet[IP].src

    destination_ip = packet[IP].dst

    print(
        f"[TRAFFIC] "
        f"{source_ip} -> "
        f"{destination_ip}"
    )

    # Process TCP packets
    if packet.haslayer(TCP):

        destination_port = packet[TCP].dport

        detect_port_scan(
            source_ip,
            destination_ip,
            destination_port
        )


# ============================================================
# START NETWORK MONITOR
# ============================================================

def start_monitor():

    print("=" * 60)
    print("        CyberSentinel Network Monitor")
    print("=" * 60)

    print(
        "Network monitoring started..."
    )

    print(
        "Threat detection is active."
    )

    print(
        "Risk Engine is active."
    )

    print(
        "Database connection is ready."
    )

    print(
        "Monitoring TCP traffic..."
    )

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 60)

    try:

        sniff(
            filter="tcp",
            prn=process_packet,
            store=False
        )

    except PermissionError:

        print()
        print("=" * 60)
        print("PERMISSION ERROR")
        print("=" * 60)

        print(
            "Please run Command Prompt "
            "as Administrator."
        )

        print("=" * 60)

    except KeyboardInterrupt:

        print()
        print("=" * 60)
        print("Network monitoring stopped.")
        print("=" * 60)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    start_monitor()