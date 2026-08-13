# 🛡️ CyberSentinel

CyberSentinel is a cybersecurity monitoring and threat detection platform designed to monitor security events, identify potential threats, calculate risk scores, classify threat severity, and display security information through a web-based dashboard.

## 🚀 Features

- Real-time security event monitoring
- Threat detection
- Risk score calculation
- Severity classification
- Suspicious login detection
- Port scanning detection
- Unauthorized access detection
- Malware detection
- Brute force attack detection
- File monitoring
- Network monitoring
- SQLite database integration
- FastAPI backend
- Interactive security dashboard
- Security event table
- REST API
- Responsive web interface

## 🏗️ Project Structure

```text
CyberSentinel/
│
├── backend/
│   ├── app.py
│   ├── auth.py
│   └── database/
│
├── database/
│   ├── security_database.py
│   └── view_events.py
│
├── detection/
│   ├── __init__.py
│   └── risk_engine.py
│
├── monitoring/
│   ├── __init__.py
│   ├── file_monitor.py
│   └── network_monitor.py
│
├── screenshots/
│   └── dashboard.png
│
├── detector.py
├── monitor.py
├── requirements.txt
├── .gitignore
└── README.md