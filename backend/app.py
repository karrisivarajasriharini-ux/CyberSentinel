from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
import sqlite3
import os
import csv
import io
from collections import Counter

from backend import auth


app = FastAPI(
    title="CyberSentinel",
    description="Cybersecurity Monitoring & Threat Detection Platform",
    version="1.0"
)


# =========================================================
# DATABASE
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_NAME = os.path.join(
    BASE_DIR,
    "database",
    "cybersentinel.db"
)


def get_connection():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def get_events():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                timestamp,
                source_ip,
                destination_ip,
                threat_type,
                severity,
                risk_score
            FROM security_events
            ORDER BY id DESC
        """)

        events = cursor.fetchall()

    except sqlite3.Error as error:

        print("Database Error:", error)
        events = []

    finally:
        connection.close()

    return events


# =========================================================
# AUTH
# =========================================================

app.include_router(auth.router)


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home(request: Request):

    if request.cookies.get("cybersentinel_auth") != "authenticated":
        return RedirectResponse("/login", status_code=303)

    return RedirectResponse("/dashboard", status_code=303)


# =========================================================
# CSV EXPORT
# =========================================================

@app.get("/export-csv")
def export_csv(request: Request):

    if request.cookies.get("cybersentinel_auth") != "authenticated":
        return RedirectResponse("/login", status_code=303)

    events = get_events()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Threat Type",
        "Severity",
        "Risk Score"
    ])

    for event in events:

        writer.writerow([
            event["id"],
            event["timestamp"],
            event["source_ip"],
            event["destination_ip"],
            event["threat_type"],
            event["severity"],
            event["risk_score"]
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=cybersentinel_security_events.csv"
        }
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):

    if request.cookies.get("cybersentinel_auth") != "authenticated":
        return RedirectResponse("/login", status_code=303)

    events = get_events()

    total = len(events)

    # -----------------------------------------------------
    # COUNTS
    # -----------------------------------------------------

    critical = sum(
        1 for e in events
        if str(e["severity"]).lower() == "critical"
    )

    high = sum(
        1 for e in events
        if str(e["severity"]).lower() == "high"
    )

    medium = sum(
        1 for e in events
        if str(e["severity"]).lower() == "medium"
    )

    low = sum(
        1 for e in events
        if str(e["severity"]).lower() == "low"
    )

    if total:

        average_risk = round(
            sum(float(e["risk_score"] or 0) for e in events)
            / total,
            1
        )

    else:
        average_risk = 0


    # -----------------------------------------------------
    # THREAT TYPES
    # -----------------------------------------------------

    threat_counter = Counter(
        str(e["threat_type"])
        for e in events
    )

    threat_types = threat_counter.most_common(7)

    max_threat = max(
        [x[1] for x in threat_types],
        default=1
    )


    # -----------------------------------------------------
    # ALERT
    # -----------------------------------------------------

    critical_events = [
        e for e in events
        if str(e["severity"]).lower() == "critical"
    ]

    if critical_events:

        alert_event = critical_events[0]

        alert_text = (
            f"Critical threat detected: "
            f"{alert_event['threat_type']} "
            f"from {alert_event['source_ip']} "
            f"| Risk Score: {alert_event['risk_score']}"
        )

    else:

        alert_text = "No critical threats detected."


    # -----------------------------------------------------
    # THREAT BAR CHART
    # -----------------------------------------------------

    bars = ""

    for threat, count in threat_types:

        width = (count / max_threat) * 100

        bars += f"""
        <div class="threat-row">

            <div class="threat-name">
                {threat}
            </div>

            <div class="threat-track">
                <div
                    class="threat-fill"
                    style="width:{width}%">
                </div>
            </div>

            <div class="threat-count">
                {count}
            </div>

        </div>
        """


    # -----------------------------------------------------
    # THREAT OPTIONS
    # -----------------------------------------------------

    threat_options = ""

    for threat in sorted(threat_counter.keys()):

        threat_options += f"""
        <option value="{threat}">
            {threat}
        </option>
        """


    # -----------------------------------------------------
    # EVENT TABLE
    # -----------------------------------------------------

    rows = ""

    for event in events:

        severity = str(
            event["severity"] or "unknown"
        )

        severity_lower = severity.lower()

        if severity_lower == "critical":
            severity_class = "critical"

        elif severity_lower == "high":
            severity_class = "high"

        elif severity_lower == "medium":
            severity_class = "medium"

        else:
            severity_class = "low"


        risk = float(event["risk_score"] or 0)

        if risk >= 80:
            risk_class = "danger"

        elif risk >= 60:
            risk_class = "warning"

        else:
            risk_class = "safe"


        rows += f"""
        <tr
            data-source="{event['source_ip']}"
            data-severity="{severity_lower}"
            data-threat="{event['threat_type']}"
        >

            <td class="event-id">
                #{event['id']}
            </td>

            <td>
                <span class="timestamp">
                    {event['timestamp']}
                </span>
            </td>

            <td>
                <span class="ip">
                    {event['source_ip']}
                </span>
            </td>

            <td>
                {event['destination_ip'] or "-"}
            </td>

            <td>
                {event['threat_type']}
            </td>

            <td>
                <span class="badge {severity_class}">
                    {severity.upper()}
                </span>
            </td>

            <td>
                <span class="risk {risk_class}">
                    {event['risk_score']}/100
                </span>
            </td>

        </tr>
        """


    if not rows:

        rows = """
        <tr>
            <td colspan="7" class="empty">
                <div class="empty-icon">◈</div>
                No security events found
            </td>
        </tr>
        """


    # =====================================================
    # HTML
    # =====================================================

    html = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>CyberSentinel | Security Operations Center</title>


<style>

/* =====================================================
   RESET
   ===================================================== */

* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}

body {{

    font-family:
        "Segoe UI",
        Arial,
        sans-serif;

    background:
        #050b14;

    color:
        #dbeafe;

    min-height:
        100vh;

}}


/* =====================================================
   CYBER GRID
   ===================================================== */

body::before {{

    content: "";

    position: fixed;

    inset: 0;

    pointer-events: none;

    background-image:
        linear-gradient(
            rgba(56,189,248,0.035) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(56,189,248,0.035) 1px,
            transparent 1px
        );

    background-size:
        38px 38px;

    z-index: -1;
}}


/* =====================================================
   SIDEBAR
   ===================================================== */

.sidebar {{

    position: fixed;

    left: 0;
    top: 0;
    bottom: 0;

    width: 225px;

    background:
        linear-gradient(
            180deg,
            #0b1424 0%,
            #07101d 100%
        );

    border-right:
        1px solid #1c334d;

    z-index: 100;

    padding:
        22px 14px;

}}


.logo {{

    display: flex;

    align-items: center;

    gap: 11px;

    padding:
        5px 11px 24px;

    border-bottom:
        1px solid #1b2d44;

}}


.logo-shield {{

    width: 34px;
    height: 34px;

    display: flex;

    align-items: center;
    justify-content: center;

    font-size: 22px;

    background:
        linear-gradient(
            145deg,
            #0ea5e9,
            #2563eb
        );

    border-radius: 9px;

    box-shadow:
        0 0 20px rgba(14,165,233,.28);

}}


.logo-text {{

    font-size: 19px;

    font-weight: 800;

    color: #f8fafc;

}}

.logo-text span {{
    color: #38bdf8;
}}


.nav {{
    margin-top: 24px;
}}


.nav-label {{

    font-size: 9px;

    color: #526982;

    letter-spacing: 1.5px;

    margin:
        0 11px 9px;

    text-transform:
        uppercase;

}}


.nav a {{

    display: flex;

    align-items: center;

    gap: 12px;

    color: #7890aa;

    text-decoration: none;

    padding:
        12px 12px;

    margin-bottom: 5px;

    border-radius: 8px;

    font-size: 12px;

    transition: .2s;

}}


.nav a:hover {{

    background:
        #122238;

    color:
        #e0f2fe;

}}


.nav a.active {{

    color: #ffffff;

    background:
        linear-gradient(
            90deg,
            #162b45,
            #112239
        );

    border:
        1px solid #244666;

    box-shadow:
        inset 3px 0 #38bdf8;

}}


.nav-icon {{

    width: 24px;

    text-align: center;

    font-size: 15px;

}}


/* =====================================================
   SIDEBAR STATUS
   ===================================================== */

.sidebar-status {{

    position: absolute;

    left: 14px;
    right: 14px;
    bottom: 20px;

    padding: 12px;

    background:
        #09182a;

    border:
        1px solid #183b43;

    border-radius: 9px;

}}


.status-line {{

    display: flex;

    align-items: center;

    gap: 7px;

    color: #4ade80;

    font-size: 10px;

    font-weight: 700;

}}


.status-dot {{

    width: 7px;
    height: 7px;

    border-radius: 50%;

    background: #22c55e;

    box-shadow:
        0 0 10px #22c55e;

}}


.status-sub {{

    color: #526982;

    font-size: 8px;

    margin-top: 5px;

}}


/* =====================================================
   MAIN
   ===================================================== */

.main {{

    margin-left:
        225px;

    min-height:
        100vh;

}}


/* =====================================================
   HEADER
   ===================================================== */

.header {{

    height: 76px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding:
        0 30px;

    background:
        rgba(5,11,20,.92);

    border-bottom:
        1px solid #172a40;

    position: sticky;

    top: 0;

    z-index: 50;

    backdrop-filter:
        blur(12px);

}}


.heading h1 {{

    font-size: 24px;

    color: #f8fafc;

    letter-spacing:
        -.3px;

}}


.heading p {{

    font-size: 11px;

    color: #607895;

    margin-top: 4px;

}}


.system-online {{

    display: flex;

    align-items: center;

    gap: 8px;

    padding:
        8px 13px;

    border-radius: 20px;

    color: #4ade80;

    background:
        rgba(34,197,94,.06);

    border:
        1px solid rgba(34,197,94,.35);

    font-size: 10px;

    font-weight: 700;

    letter-spacing: .5px;

}}


.pulse {{

    width: 8px;
    height: 8px;

    background: #22c55e;

    border-radius: 50%;

    box-shadow:
        0 0 0 0 rgba(34,197,94,.7);

    animation:
        pulse 1.7s infinite;

}}


@keyframes pulse {{

    0% {{
        box-shadow:
            0 0 0 0 rgba(34,197,94,.7);
    }}

    70% {{
        box-shadow:
            0 0 0 8px rgba(34,197,94,0);
    }}

    100% {{
        box-shadow:
            0 0 0 0 rgba(34,197,94,0);
    }}

}}


/* =====================================================
   CONTENT
   ===================================================== */

.content {{

    padding:
        24px 30px 45px;

}}


/* =====================================================
   LIVE BAR
   ===================================================== */

.live-bar {{

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding:
        12px 16px;

    background:
        #0c1728;

    border:
        1px solid #1d3852;

    border-radius: 9px;

    margin-bottom: 14px;

}}


.live-left {{

    display: flex;

    align-items: center;

    gap: 9px;

    color: #a7f3d0;

    font-size: 11px;

    font-weight: 700;

}}


.live-dot {{

    width: 9px;
    height: 9px;

    border-radius: 50%;

    background: #34d399;

    box-shadow:
        0 0 12px #34d399;

}}


.last-update {{

    color: #637a94;

    font-size: 10px;

}}


/* =====================================================
   ALERT
   ===================================================== */

.alert {{

    position: relative;

    overflow: hidden;

    padding:
        13px 17px;

    margin-bottom: 16px;

    border-radius: 9px;

    background:
        linear-gradient(
            90deg,
            #3d080b,
            #260b11
        );

    border:
        1px solid #a51d2d;

    box-shadow:
        0 0 25px rgba(239,68,68,.06);

}}


.alert::before {{

    content: "";

    position: absolute;

    left: 0;
    top: 0;
    bottom: 0;

    width: 3px;

    background: #ef4444;

    box-shadow:
        0 0 15px #ef4444;

}}


.alert-title {{

    color: #fb7185;

    font-size: 11px;

    font-weight: 800;

    margin-bottom: 4px;

}}


.alert-text {{

    color: #fecdd3;

    font-size: 11px;

}}


/* =====================================================
   STATISTICS
   ===================================================== */

.stats {{

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 14px;

    margin-bottom: 16px;

}}


.stat {{

    position: relative;

    overflow: hidden;

    background:
        linear-gradient(
            145deg,
            #0e1a2c,
            #091321
        );

    border:
        1px solid #203852;

    border-radius: 11px;

    padding:
        17px 18px;

    transition:
        .25s;

}}


.stat:hover {{

    transform:
        translateY(-3px);

    border-color:
        #2d5778;

    box-shadow:
        0 10px 30px rgba(0,0,0,.25);

}}


.stat::after {{

    content: "";

    position: absolute;

    width: 70px;
    height: 70px;

    right: -25px;
    bottom: -30px;

    border-radius: 50%;

    background:
        rgba(56,189,248,.06);

}}


.stat-label {{

    color: #6f87a1;

    font-size: 9px;

    text-transform:
        uppercase;

    letter-spacing:
        1px;

    font-weight:
        700;

}}


.stat-value {{

    font-size: 29px;

    font-weight: 800;

    margin-top: 8px;

}}


.stat-meta {{

    font-size: 9px;

    color: #526982;

    margin-top: 4px;

}}


.blue {{
    color: #38bdf8;
}}

.orange {{
    color: #fb923c;
}}

.red {{
    color: #f87171;
}}

.purple {{
    color: #a78bfa;
}}


/* =====================================================
   CHARTS
   ===================================================== */

.chart-grid {{

    display: grid;

    grid-template-columns:
        1fr 1fr;

    gap: 15px;

    margin-bottom: 16px;

}}


.panel {{

    background:
        linear-gradient(
            145deg,
            #0e1a2c,
            #091321
        );

    border:
        1px solid #203852;

    border-radius: 11px;

    padding:
        18px;

}}


.panel-header {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 12px;

}}


.panel-title {{

    font-size: 13px;

    font-weight: 750;

    color: #e2e8f0;

}}


.panel-tag {{

    color: #38bdf8;

    font-size: 8px;

    padding:
        4px 7px;

    border-radius: 10px;

    background:
        rgba(56,189,248,.07);

    border:
        1px solid rgba(56,189,248,.2);

}}


/* =====================================================
   DONUT
   ===================================================== */

.donut-wrapper {{

    display: flex;

    align-items: center;

    justify-content: center;

    gap: 30px;

    min-height: 220px;

}}


.donut {{

    width: 165px;

    height: 165px;

    border-radius: 50%;

    background:
        conic-gradient(
            #ef4444
            0deg
            {critical / max(total,1) * 360}deg,

            #f97316
            {critical / max(total,1) * 360}deg
            {(critical + high) / max(total,1) * 360}deg,

            #eab308
            {(critical + high) / max(total,1) * 360}deg
            {(critical + high + medium) / max(total,1) * 360}deg,

            #22c55e
            {(critical + high + medium) / max(total,1) * 360}deg
            360deg
        );

    display: flex;

    align-items: center;

    justify-content: center;

    box-shadow:
        0 0 35px rgba(239,68,68,.08);

}}


.donut-inner {{

    width: 104px;
    height: 104px;

    border-radius: 50%;

    background:
        #0b1626;

    display: flex;

    flex-direction: column;

    align-items: center;

    justify-content: center;

}}


.donut-number {{

    color: #f8fafc;

    font-size: 22px;

    font-weight: 800;

}}


.donut-label {{

    color: #637a94;

    font-size: 8px;

    text-transform:
        uppercase;

    margin-top: 2px;

}}


.legend-item {{

    display: flex;

    align-items: center;

    gap: 8px;

    font-size: 10px;

    color: #8da1b7;

    margin: 10px 0;

}}


.legend-color {{

    width: 9px;
    height: 9px;

    border-radius: 2px;

}}


/* =====================================================
   THREAT BARS
   ===================================================== */

.threat-row {{

    display: grid;

    grid-template-columns:
        135px 1fr 35px;

    gap: 9px;

    align-items: center;

    margin: 11px 0;

}}


.threat-name {{

    color: #8da1b7;

    font-size: 9px;

    white-space: nowrap;

    overflow: hidden;

    text-overflow: ellipsis;

}}


.threat-track {{

    height: 8px;

    background: #142337;

    border-radius: 10px;

    overflow: hidden;

}}


.threat-fill {{

    height: 100%;

    background:
        linear-gradient(
            90deg,
            #2563eb,
            #38bdf8
        );

    border-radius: 10px;

    box-shadow:
        0 0 10px rgba(56,189,248,.25);

}}


.threat-count {{

    text-align: right;

    color: #cbd5e1;

    font-size: 9px;

    font-weight: 700;

}}


/* =====================================================
   FILTERS
   ===================================================== */

.filter-panel {{

    display: grid;

    grid-template-columns:
        1.2fr 1fr 1fr auto;

    gap: 9px;

    margin-bottom: 16px;

}}


.filter {{

    width: 100%;

    height: 38px;

    padding:
        0 12px;

    color: #9fb2c8;

    background:
        #0a1525;

    border:
        1px solid #203852;

    border-radius: 7px;

    outline: none;

    font-size: 10px;

}}


.filter:focus {{

    border-color:
        #38bdf8;

    box-shadow:
        0 0 0 2px rgba(56,189,248,.07);

}}


.export-btn {{

    height: 38px;

    padding:
        0 15px;

    display: flex;

    align-items: center;

    gap: 7px;

    color: #dbeafe;

    text-decoration: none;

    background:
        linear-gradient(
            135deg,
            #0f4c81,
            #075985
        );

    border:
        1px solid #1675aa;

    border-radius: 7px;

    font-size: 10px;

    font-weight: 700;

    transition: .2s;

}}


.export-btn:hover {{

    box-shadow:
        0 0 18px rgba(14,165,233,.2);

    transform:
        translateY(-1px);

}}


/* =====================================================
   TABLE
   ===================================================== */

.events-panel {{

    background:
        linear-gradient(
            145deg,
            #0e1a2c,
            #091321
        );

    border:
        1px solid #203852;

    border-radius: 11px;

    overflow: hidden;

}}


.events-header {{

    padding:
        17px 18px;

    display: flex;

    justify-content: space-between;

    align-items: center;

    border-bottom:
        1px solid #1b3048;

}}


.events-title {{

    display: flex;

    align-items: center;

    gap: 9px;

    font-size: 14px;

    font-weight: 750;

}}


.events-title-icon {{

    color: #38bdf8;

}}


.event-count {{

    color: #38bdf8;

    font-size: 9px;

    padding:
        5px 9px;

    border:
        1px solid #155e75;

    background:
        rgba(56,189,248,.05);

    border-radius: 15px;

}}


.table-wrapper {{

    overflow-x: auto;

}}


table {{

    width: 100%;

    border-collapse: collapse;

    min-width: 950px;

}}


th {{

    padding:
        11px 15px;

    background:
        #091423;

    color: #607995;

    font-size: 8px;

    letter-spacing:
        1px;

    text-transform:
        uppercase;

    text-align:
        left;

}}


td {{

    padding:
        12px 15px;

    border-top:
        1px solid #172b41;

    color: #b7c7d9;

    font-size: 10px;

}}


tbody tr {{

    transition:
        .15s;

}}


tbody tr:hover {{

    background:
        rgba(56,189,248,.035);

}}


.event-id {{
    color: #526982;
}}


.timestamp {{
    color: #93a8bf;
}}


.ip {{

    color: #38bdf8;

    font-family:
        Consolas,
        monospace;

}}


/* =====================================================
   BADGES
   ===================================================== */

.badge,
.risk {{

    display: inline-block;

    padding:
        4px 8px;

    border-radius:
        5px;

    font-size: 8px;

    font-weight: 800;

    letter-spacing:
        .3px;

}}


.badge.critical {{

    color: #fda4af;

    background:
        rgba(239,68,68,.1);

    border:
        1px solid rgba(239,68,68,.35);

    box-shadow:
        0 0 8px rgba(239,68,68,.06);

}}


.badge.high {{

    color: #fdba74;

    background:
        rgba(249,115,22,.1);

    border:
        1px solid rgba(249,115,22,.3);

}}


.badge.medium {{

    color: #fde68a;

    background:
        rgba(234,179,8,.1);

    border:
        1px solid rgba(234,179,8,.3);

}}


.badge.low {{

    color: #86efac;

    background:
        rgba(34,197,94,.1);

    border:
        1px solid rgba(34,197,94,.3);

}}


.risk.danger {{

    color: #fda4af;

    background:
        rgba(239,68,68,.09);

}}


.risk.warning {{

    color: #fdba74;

    background:
        rgba(249,115,22,.09);

}}


.risk.safe {{

    color: #86efac;

    background:
        rgba(34,197,94,.09);

}}


.empty {{

    text-align: center;

    padding: 50px;

    color: #607995;

}}


.empty-icon {{

    color: #38bdf8;

    font-size: 25px;

    margin-bottom: 8px;

}}


/* =====================================================
   RESPONSIVE
   ===================================================== */

@media(max-width: 1150px) {{

    .stats {{
        grid-template-columns:
            repeat(2,1fr);
    }}

    .filter-panel {{
        grid-template-columns:
            1fr 1fr;
    }}

}}


@media(max-width: 850px) {{

    .sidebar {{
        width: 68px;
    }}

    .logo-text,
    .nav-text,
    .nav-label,
    .sidebar-status {{
        display: none;
    }}

    .logo {{
        justify-content: center;
        padding-left: 0;
        padding-right: 0;
    }}

    .nav a {{
        justify-content: center;
    }}

    .main {{
        margin-left: 68px;
    }}

    .chart-grid {{
        grid-template-columns:
            1fr;
    }}

}}


@media(max-width: 600px) {{

    .content {{
        padding: 15px;
    }}

    .stats {{
        grid-template-columns:
            1fr;
    }}

    .filter-panel {{
        grid-template-columns:
            1fr;
    }}

    .header {{
        padding: 0 15px;
    }}

    .heading h1 {{
        font-size: 18px;
    }}

}}

</style>

</head>


<body>


<!-- =====================================================
     SIDEBAR
     ===================================================== -->

<aside class="sidebar">


    <div class="logo">

        <div class="logo-shield">
            🛡️
        </div>

        <div class="logo-text">
            Cyber<span>Sentinel</span>
        </div>

    </div>


    <nav class="nav">

        <div class="nav-label">
            Security Center
        </div>


        <a
            href="/dashboard"
            class="active"
        >
            <span class="nav-icon">📊</span>
            <span class="nav-text">
                Dashboard
            </span>
        </a>


        <a href="#events">

            <span class="nav-icon">🚨</span>

            <span class="nav-text">
                Security Events
            </span>

        </a>


        <a href="#alerts">

            <span class="nav-icon">🔔</span>

            <span class="nav-text">
                Alert History
            </span>

        </a>


        <a href="#statistics">

            <span class="nav-icon">📈</span>

            <span class="nav-text">
                Statistics
            </span>

        </a>


        <a href="/export-csv">

            <span class="nav-icon">📥</span>

            <span class="nav-text">
                Export CSV
            </span>

        </a>


        <a href="/docs">

            <span class="nav-icon">📘</span>

            <span class="nav-text">
                API Docs
            </span>

        </a>

    </nav>


    <div class="sidebar-status">

        <div class="status-line">

            <span class="status-dot"></span>

            SYSTEM ONLINE

        </div>

        <div class="status-sub">
            Monitoring services operational
        </div>

    </div>

</aside>


<!-- =====================================================
     MAIN
     ===================================================== -->

<main class="main">


    <header class="header">


        <div class="heading">

            <h1>
                Security Operations Center
            </h1>

            <p>
                Cybersecurity Monitoring & Threat Detection Platform
            </p>

        </div>


        <div class="system-online">

            <span class="pulse"></span>

            SYSTEM ONLINE

        </div>

    </header>


    <section class="content">


        <!-- LIVE MONITORING -->

        <div class="live-bar">

            <div class="live-left">

                <span class="live-dot"></span>

                LIVE MONITORING ACTIVE

            </div>


            <div class="last-update">

                Last update:
                <span id="clock">
                    --
                </span>

            </div>

        </div>


        <!-- SECURITY ALERT -->

        <div
            class="alert"
            id="alerts"
        >

            <div class="alert-title">
                🚨 SECURITY ALERT
            </div>

            <div class="alert-text">
                {alert_text}
            </div>

        </div>


        <!-- STATISTICS -->

        <div
            class="stats"
            id="statistics"
        >


            <div class="stat">

                <div class="stat-label">
                    Total Security Events
                </div>

                <div class="stat-value blue">
                    {total}
                </div>

                <div class="stat-meta">
                    Events monitored
                </div>

            </div>


            <div class="stat">

                <div class="stat-label">
                    High Threats
                </div>

                <div class="stat-value orange">
                    {high}
                </div>

                <div class="stat-meta">
                    Requires attention
                </div>

            </div>


            <div class="stat">

                <div class="stat-label">
                    Critical Threats
                </div>

                <div class="stat-value red">
                    {critical}
                </div>

                <div class="stat-meta">
                    Immediate response
                </div>

            </div>


            <div class="stat">

                <div class="stat-label">
                    Average Risk
                </div>

                <div class="stat-value purple">
                    {average_risk}/100
                </div>

                <div class="stat-meta">
                    Overall threat score
                </div>

            </div>


        </div>


        <!-- CHARTS -->

        <div class="chart-grid">


            <!-- DONUT -->

            <div class="panel">

                <div class="panel-header">

                    <div class="panel-title">
                        Threat Severity
                    </div>

                    <div class="panel-tag">
                        LIVE
                    </div>

                </div>


                <div class="donut-wrapper">


                    <div class="donut">

                        <div class="donut-inner">

                            <div class="donut-number">
                                {total}
                            </div>

                            <div class="donut-label">
                                Events
                            </div>

                        </div>

                    </div>


                    <div>

                        <div class="legend-item">

                            <span
                                class="legend-color"
                                style="background:#ef4444">
                            </span>

                            Critical

                            <strong>
                                {critical}
                            </strong>

                        </div>


                        <div class="legend-item">

                            <span
                                class="legend-color"
                                style="background:#f97316">
                            </span>

                            High

                            <strong>
                                {high}
                            </strong>

                        </div>


                        <div class="legend-item">

                            <span
                                class="legend-color"
                                style="background:#eab308">
                            </span>

                            Medium

                            <strong>
                                {medium}
                            </strong>

                        </div>


                        <div class="legend-item">

                            <span
                                class="legend-color"
                                style="background:#22c55e">
                            </span>

                            Low

                            <strong>
                                {low}
                            </strong>

                        </div>

                    </div>


                </div>

            </div>


            <!-- THREAT TYPES -->

            <div class="panel">

                <div class="panel-header">

                    <div class="panel-title">
                        Threat Types
                    </div>

                    <div class="panel-tag">
                        ANALYTICS
                    </div>

                </div>


                {bars}

            </div>


        </div>


        <!-- FILTERS -->

        <div class="filter-panel">


            <input
                id="sourceFilter"
                class="filter"
                placeholder="🔍  Search Source IP..."
                oninput="filterEvents()"
            >


            <select
                id="severityFilter"
                class="filter"
                onchange="filterEvents()"
            >

                <option value="">
                    All Severity
                </option>

                <option value="critical">
                    Critical
                </option>

                <option value="high">
                    High
                </option>

                <option value="medium">
                    Medium
                </option>

                <option value="low">
                    Low
                </option>

            </select>


            <select
                id="threatFilter"
                class="filter"
                onchange="filterEvents()"
            >

                <option value="">
                    All Threat Types
                </option>

                {threat_options}

            </select>


            <a
                href="/export-csv"
                class="export-btn"
            >

                📥 Export CSV

            </a>


        </div>


        <!-- SECURITY EVENTS -->

        <section
            class="events-panel"
            id="events"
        >


            <div class="events-header">

                <div class="events-title">

                    <span class="events-title-icon">
                        ◈
                    </span>

                    Security Events

                </div>


                <div class="event-count">

                    {total} EVENTS

                </div>

            </div>


            <div class="table-wrapper">

                <table>

                    <thead>

                        <tr>

                            <th>ID</th>

                            <th>Timestamp</th>

                            <th>Source IP</th>

                            <th>Destination IP</th>

                            <th>Threat Type</th>

                            <th>Severity</th>

                            <th>Risk Score</th>

                        </tr>

                    </thead>


                    <tbody id="eventTable">

                        {rows}

                    </tbody>

                </table>

            </div>


        </section>


    </section>

</main>


<script>


// =======================================================
// CLOCK
// =======================================================

function updateClock() {{

    const now = new Date();

    document.getElementById(
        "clock"
    ).textContent =
        now.toLocaleTimeString();

}}

updateClock();

setInterval(
    updateClock,
    1000
);


// =======================================================
// FILTER
// =======================================================

function filterEvents() {{

    const source =
        document
        .getElementById("sourceFilter")
        .value
        .toLowerCase();

    const severity =
        document
        .getElementById("severityFilter")
        .value
        .toLowerCase();

    const threat =
        document
        .getElementById("threatFilter")
        .value
        .toLowerCase();


    const rows =
        document.querySelectorAll(
            "#eventTable tr"
        );


    rows.forEach(
        function(row) {{

            const rowSource =
                (
                    row.dataset.source ||
                    ""
                ).toLowerCase();

            const rowSeverity =
                (
                    row.dataset.severity ||
                    ""
                ).toLowerCase();

            const rowThreat =
                (
                    row.dataset.threat ||
                    ""
                ).toLowerCase();


            const sourceMatch =
                !source ||
                rowSource.includes(source);

            const severityMatch =
                !severity ||
                rowSeverity === severity;

            const threatMatch =
                !threat ||
                rowThreat === threat;


            row.style.display =
                sourceMatch &&
                severityMatch &&
                threatMatch
                    ? ""
                    : "none";

        }}
    );

}}


</script>


</body>

</html>
"""

    return HTMLResponse(content=html)


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health():

    return {
        "status": "online",
        "service": "CyberSentinel"
    }