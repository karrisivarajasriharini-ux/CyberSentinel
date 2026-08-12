import sqlite3
from datetime import datetime
import random
import time

DATABASE_NAME = "database/cybersentinel.db"


def add_security_event(
    source_ip,
    threat_type,
    risk_score,
    severity
):

    connection = sqlite3.connect(DATABASE_NAME)

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
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            source_ip,
            threat_type,
            risk_score,
            severity
        )
    )

    connection.commit()

    connection.close()

    print(
        f"[ALERT] {threat_type} | "
        f"{source_ip} | "
        f"Risk: {risk_score} | "
        f"{severity}"
    )


def generate_test_event():

    threats = [

        (
            "Brute Force Attack",
            85,
            "High"
        ),

        (
            "Port Scanning",
            65,
            "Medium"
        ),

        (
            "Malware Detection",
            95,
            "Critical"
        ),

        (
            "Suspicious Login",
            75,
            "High"
        ),

        (
            "Unauthorized Access",
            90,
            "Critical"
        )

    ]

    threat = random.choice(threats)

    source_ip = (
        "192.168.1."
        + str(random.randint(100, 200))
    )

    add_security_event(
        source_ip,
        threat[0],
        threat[1],
        threat[2]
    )


if __name__ == "__main__":

    print("CyberSentinel Detection Engine Started")

    while True:

        generate_test_event()

        time.sleep(10)