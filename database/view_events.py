import sqlite3


DATABASE_NAME = "database/cybersentinel.db"


connection = sqlite3.connect(DATABASE_NAME)

cursor = connection.cursor()

cursor.execute("""
    SELECT
        id,
        timestamp,
        source_ip,
        destination_ip,
        threat_type,
        risk_score,
        severity
    FROM security_events
    ORDER BY id DESC
""")


events = cursor.fetchall()


print("=" * 100)
print("CyberSentinel - Security Event History")
print("=" * 100)


if not events:

    print("No security events found.")

else:

    for event in events:

        print(
            f"\nID              : {event[0]}"
            f"\nTimestamp       : {event[1]}"
            f"\nSource IP       : {event[2]}"
            f"\nDestination IP  : {event[3]}"
            f"\nThreat Type     : {event[4]}"
            f"\nRisk Score      : {event[5]}/100"
            f"\nSeverity        : {event[6]}"
        )

        print("-" * 100)


connection.close()