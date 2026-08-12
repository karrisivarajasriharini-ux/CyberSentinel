import os
import time
import sqlite3
from datetime import datetime

# =========================================================
# CONFIGURATION
# =========================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MONITORED_FOLDER = os.path.join(
    PROJECT_ROOT,
    "monitored_files"
)

DATABASE_NAME = os.path.join(
    PROJECT_ROOT,
    "database",
    "cybersentinel.db"
)

# Suspicious extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".scr",
    ".msi",
    ".js"
}


# =========================================================
# SAVE EVENT
# =========================================================

def save_event(
    file_name,
    threat_type,
    risk_score,
    severity
):

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
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "LOCAL_SYSTEM",
            threat_type,
            risk_score,
            severity
        )
    )

    connection.commit()
    connection.close()

    print()
    print("=" * 60)
    print("CYBERSENTINEL SECURITY ALERT")
    print("=" * 60)
    print("File     :", file_name)
    print("Threat   :", threat_type)
    print("Risk     :", risk_score)
    print("Severity :", severity)
    print("=" * 60)


# =========================================================
# GET FILE SNAPSHOT
# =========================================================

def get_files():

    files = {}

    if not os.path.exists(
        MONITORED_FOLDER
    ):
        os.makedirs(
            MONITORED_FOLDER
        )

    for root, directories, filenames in os.walk(
        MONITORED_FOLDER
    ):

        for filename in filenames:

            full_path = os.path.join(
                root,
                filename
            )

            try:

                files[full_path] = os.path.getmtime(
                    full_path
                )

            except OSError:
                pass

    return files


# =========================================================
# CHECK SUSPICIOUS FILE
# =========================================================

def check_suspicious_file(
    file_name
):

    extension = os.path.splitext(
        file_name
    )[1].lower()

    if extension in SUSPICIOUS_EXTENSIONS:

        save_event(
            file_name,
            "Suspicious File Detected",
            90,
            "Critical"
        )

        return True

    return False


# =========================================================
# START MONITOR
# =========================================================

def start_monitor():

    print("=" * 60)
    print("CyberSentinel File Monitoring Engine")
    print("=" * 60)

    print(
        "Monitoring folder:"
    )

    print(
        MONITORED_FOLDER
    )

    print()

    print(
        "Suspicious file detection: ACTIVE"
    )

    print(
        "File creation detection: ACTIVE"
    )

    print(
        "File modification detection: ACTIVE"
    )

    print(
        "File deletion detection: ACTIVE"
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print("=" * 60)

    old_files = get_files()

    try:

        while True:

            time.sleep(2)

            new_files = get_files()

            # =================================================
            # CREATED FILES
            # =================================================

            created_files = (
                set(new_files)
                - set(old_files)
            )

            for file_path in created_files:

                file_name = os.path.basename(
                    file_path
                )

                # Check suspicious extension
                suspicious = check_suspicious_file(
                    file_name
                )

                # Normal file
                if not suspicious:

                    save_event(
                        file_name,
                        "File Created",
                        65,
                        "Medium"
                    )

            # =================================================
            # DELETED FILES
            # =================================================

            deleted_files = (
                set(old_files)
                - set(new_files)
            )

            for file_path in deleted_files:

                file_name = os.path.basename(
                    file_path
                )

                save_event(
                    file_name,
                    "File Deleted",
                    70,
                    "Medium"
                )

            # =================================================
            # MODIFIED FILES
            # =================================================

            common_files = (
                set(old_files)
                &
                set(new_files)
            )

            for file_path in common_files:

                old_time = old_files[
                    file_path
                ]

                new_time = new_files[
                    file_path
                ]

                if new_time != old_time:

                    file_name = os.path.basename(
                        file_path
                    )

                    save_event(
                        file_name,
                        "File Modified",
                        60,
                        "Medium"
                    )

            old_files = new_files

    except KeyboardInterrupt:

        print()
        print(
            "File monitoring stopped."
        )


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    start_monitor()