import sqlite3
import random
import time
from datetime import datetime
import os

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE_NAME = os.path.join(
    BASE_DIR,
    "database",
    "cybersentinel.db"
)

IPS = [
    "192.168.1.100",
    "192.168.1.101",
    "192.168.1.102",
    "192.168.1.103",
    "192.168.1.117",
    "192.168.1.118",
    "192.168.1.147",
    "192.168.1.150",
    "192.168.1.169",
    "192.168.1.197"
]

EVENT_TYPES = [
    "Login Attempt",
    "Port Activity",
    "File Access",
    "Network Connection"
]


def detect_threat(event_type, activity_count):

    if event_type == "Login Attempt":

        if activity_count >= 5:
            return (
                "Brute Force Attack",
                95,
                "Critical"
            )

        elif activity_count >= 3:
            return (
                "Suspicious Login",
                75,
                "High"
            )

        else:
            return (
                "Normal Login",
                20,
                "Low"
            )


    elif event_type == "Port Activity":

        if activity_count >= 6:
            return (
                "Port Scanning",
                90,
                "Critical"
            )

        elif activity_count >= 3:
            return (
                "Suspicious Port Activity",
                65,
                "Medium"
            )

        else:
            return (
                "Normal Network Activity",
                20,
                "Low"
            )


    elif event_type == "File Access":

        if activity_count >= 5:
            return (
                "Unauthorized Access",
                90,
                "Critical"
            )

        else:
            return (
                "File Access",
                30,
                "Low"
            )


    else:

        if activity_count >= 5:
            return (
                "Suspicious Network Activity",
                80,
                "High"
            )

        return (
            "Normal Network Connection",
            25,
            "Low"
        )


def get_recent_count(ip, event_type):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM security_events
        WHERE source_ip = ?
        AND timestamp >= datetime('now', '-1 minute')
        """,
        (ip,)
    )

    count = cursor.fetchone()[0]

    connection.close()

    return count


def create_event():

    source_ip = random.choice(IPS)

    event_type = random.choice(
        EVENT_TYPES
    )

    activity_count = get_recent_count(
        source_ip,
        event_type
    )

    activity_count += 1

    threat, risk, severity = detect_threat(
        event_type,
        activity_count
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
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
            threat_type,
            risk_score,
            severity
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            source_ip,
            threat,
            risk,
            severity
        )
    )

    connection.commit()

    connection.close()

    print(
        f"[{timestamp}] "
        f"{severity} | "
        f"{threat} | "
        f"{source_ip} | "
        f"Risk: {risk}"
    )


print("================================")
print("     CyberSentinel Detector")
print("================================")
print("Automatic threat detection started")
print("Press CTRL+C to stop.")
print()


while True:

    try:

        create_event()

        time.sleep(5)

    except KeyboardInterrupt:

        print()
        print("Threat detection stopped.")
        break

    except Exception as error:

        print(
            "ERROR:",
            error
        )

        time.sleep(5)