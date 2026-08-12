import sqlite3
from datetime import datetime


DATABASE_NAME = "database/cybersentinel.db"


def create_database():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            threat_type TEXT,
            risk_score INTEGER,
            severity TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("Database initialized successfully.")


def save_event(
    source_ip,
    destination_ip,
    threat_type,
    risk_score,
    severity
):

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, source_ip, destination_ip,
         threat_type, risk_score, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        destination_ip,
        threat_type,
        risk_score,
        severity
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":
    create_database()