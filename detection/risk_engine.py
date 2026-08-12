# CyberSentinel Risk Engine


def calculate_risk(threat_type):
    """
    Calculate risk score and severity
    based on detected threat type.
    """

    threat = threat_type.lower()

    if "malware" in threat:
        return 95, "CRITICAL"

    elif "brute" in threat:
        return 85, "HIGH"

    elif "port" in threat:
        return 75, "HIGH"

    elif "suspicious" in threat:
        return 60, "MEDIUM"

    elif "scan" in threat:
        return 70, "HIGH"

    else:
        return 30, "LOW"


def get_risk_level(risk_score):
    """
    Convert risk score into severity level.
    """

    if risk_score >= 90:
        return "CRITICAL"

    elif risk_score >= 70:
        return "HIGH"

    elif risk_score >= 40:
        return "MEDIUM"

    else:
        return "LOW"