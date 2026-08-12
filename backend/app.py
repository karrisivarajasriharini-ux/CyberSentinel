from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
import sqlite3
import os
import html
import csv
import io
import json


app = FastAPI(
    title="CyberSentinel",
    description="Cybersecurity Monitoring Dashboard",
    version="5.0"
)


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

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


# ============================================================
# DATABASE FUNCTIONS
# ============================================================

def get_events():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            threat_type,
            risk_score,
            severity
        FROM security_events
        ORDER BY id DESC
    """)

    events = [
        dict(row)
        for row in cursor.fetchall()
    ]

    connection.close()

    return events


def get_single_event(event_id):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            threat_type,
            risk_score,
            severity
        FROM security_events
        WHERE id = ?
    """, (event_id,))

    row = cursor.fetchone()

    connection.close()

    if row:
        return dict(row)

    return None


# ============================================================
# STATISTICS
# ============================================================

def calculate_stats(events):

    critical = 0
    high = 0
    medium = 0
    low = 0

    total_risk = 0

    threat_counts = {}

    ip_counts = {}

    for event in events:

        severity = str(
            event.get("severity", "")
        ).lower()

        if severity == "critical":
            critical += 1

        elif severity == "high":
            high += 1

        elif severity == "medium":
            medium += 1

        elif severity == "low":
            low += 1

        try:
            total_risk += int(
                event.get("risk_score", 0)
            )
        except (TypeError, ValueError):
            pass

        threat = str(
            event.get(
                "threat_type",
                "Unknown"
            )
        )

        threat_counts[threat] = (
            threat_counts.get(
                threat,
                0
            ) + 1
        )

        ip = str(
            event.get(
                "source_ip",
                "Unknown"
            )
        )

        ip_counts[ip] = (
            ip_counts.get(
                ip,
                0
            ) + 1
        )

    total_events = len(events)

    if total_events:
        average_risk = round(
            total_risk / total_events
        )
    else:
        average_risk = 0

    return {
        "total_events": total_events,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "average_risk": average_risk,
        "threat_counts": threat_counts,
        "ip_counts": ip_counts
    }


# ============================================================
# LOGIN PAGE
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
def login_page():

    return """
<!DOCTYPE html>

<html>

<head>

<title>CyberSentinel Login</title>

<meta
name="viewport"
content="width=device-width, initial-scale=1.0"
>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family: Arial, sans-serif;

    background:
        radial-gradient(
            circle at top,
            #1e3a8a,
            #020617 55%
        );

    color: white;

    min-height: 100vh;

    display: flex;

    justify-content: center;

    align-items: center;
}

.login-box {

    width: 400px;

    max-width: 90%;

    background: rgba(
        15,
        23,
        42,
        0.95
    );

    padding: 40px;

    border-radius: 18px;

    border: 1px solid #334155;

    box-shadow:
        0 25px 70px
        rgba(0,0,0,0.5);
}

.logo {

    text-align: center;

    font-size: 50px;

    margin-bottom: 10px;
}

h1 {

    text-align: center;

    margin: 0;

    font-size: 30px;
}

.subtitle {

    text-align: center;

    color: #94a3b8;

    margin-top: 10px;

    margin-bottom: 30px;
}

label {

    display: block;

    color: #cbd5e1;

    margin-bottom: 7px;

    font-size: 13px;
}

input {

    width: 100%;

    padding: 13px;

    margin-bottom: 18px;

    background: #020617;

    color: white;

    border: 1px solid #334155;

    border-radius: 8px;

    outline: none;
}

input:focus {

    border-color: #3b82f6;
}

button {

    width: 100%;

    padding: 13px;

    background: #2563eb;

    color: white;

    border: none;

    border-radius: 8px;

    cursor: pointer;

    font-weight: bold;

    font-size: 15px;
}

button:hover {

    background: #1d4ed8;
}

.demo {

    margin-top: 20px;

    text-align: center;

    font-size: 12px;

    color: #64748b;
}

</style>

</head>

<body>

<div class="login-box">

<div class="logo">
🛡️
</div>

<h1>
CyberSentinel
</h1>

<div class="subtitle">
Security Operations Center
</div>

<form
method="post"
action="/login"
>

<label>
Username
</label>

<input
type="text"
name="username"
placeholder="Enter username"
required
>

<label>
Password
</label>

<input
type="password"
name="password"
placeholder="Enter password"
required
>

<button type="submit">
LOGIN
</button>

</form>

<div class="demo">
Cybersecurity Monitoring Dashboard
</div>

</div>

</body>

</html>
"""


# ============================================================
# LOGIN
# ============================================================

@app.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...)
):

    if (
        username == "admin"
        and password == "admin123"
    ):

        return RedirectResponse(
            url="/dashboard",
            status_code=303
        )

    return HTMLResponse(
        """
<!DOCTYPE html>

<html>

<head>

<title>Login Failed</title>

<style>

body {
    background: #020617;
    color: white;
    font-family: Arial;
    text-align: center;
    padding-top: 150px;
}

.box {
    background: #0f172a;
    display: inline-block;
    padding: 40px;
    border-radius: 15px;
}

a {
    color: #60a5fa;
}

</style>

</head>

<body>

<div class="box">

<h2>
❌ Invalid Username or Password
</h2>

<p>
Please try again.
</p>

<a href="/">
Back to Login
</a>

</div>

</body>

</html>
""",
        status_code=401
    )


# ============================================================
# EVENTS API
# ============================================================

@app.get("/events")
def events():

    return get_events()


# ============================================================
# STATISTICS API
# ============================================================

@app.get("/stats")
def stats():

    return calculate_stats(
        get_events()
    )


# ============================================================
# ALERTS API
# ============================================================

@app.get("/alerts")
def alerts():

    events = get_events()

    result = []

    for event in events:

        severity = str(
            event.get(
                "severity",
                ""
            )
        ).lower()

        if severity in [
            "critical",
            "high"
        ]:

            result.append(event)

    return result[:20]


# ============================================================
# ALERT HISTORY
# ============================================================

@app.get("/alerts/history")
def alert_history():

    events = get_events()

    history = []

    for event in events:

        severity = str(
            event.get(
                "severity",
                ""
            )
        ).lower()

        if severity in [
            "critical",
            "high"
        ]:

            history.append(event)

    return history


# ============================================================
# FILTER EVENTS
# ============================================================

@app.get("/events/filter")
def filter_events(
    severity: str = "",
    source_ip: str = "",
    threat: str = ""
):

    events = get_events()

    filtered = []

    for event in events:

        if severity:

            if str(
                event["severity"]
            ).lower() != severity.lower():

                continue

        if source_ip:

            if source_ip.lower() not in str(
                event["source_ip"]
            ).lower():

                continue

        if threat:

            if threat.lower() not in str(
                event["threat_type"]
            ).lower():

                continue

        filtered.append(event)

    return filtered


# ============================================================
# SINGLE EVENT
# ============================================================

@app.get("/events/{event_id}")
def event_details(event_id: int):

    event = get_single_event(
        event_id
    )

    if event:

        return event

    return {
        "error":
        "Event not found"
    }


# ============================================================
# CSV EXPORT
# ============================================================

@app.get("/events/export")
def export_events():

    events = get_events()

    output = io.StringIO()

    writer = csv.writer(
        output
    )

    writer.writerow([
        "ID",
        "Timestamp",
        "Source IP",
        "Threat Type",
        "Risk Score",
        "Severity"
    ])

    for event in events:

        writer.writerow([
            event["id"],
            event["timestamp"],
            event["source_ip"],
            event["threat_type"],
            event["risk_score"],
            event["severity"]
        ])

    output.seek(0)

    return StreamingResponse(
        iter([
            output.getvalue()
        ]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
            "attachment; "
            "filename="
            "cybersentinel_events.csv"
        }
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
def dashboard():

    events = get_events()

    stats_data = calculate_stats(
        events
    )

    total_events = stats_data[
        "total_events"
    ]

    critical = stats_data[
        "critical"
    ]

    high = stats_data[
        "high"
    ]

    medium = stats_data[
        "medium"
    ]

    low = stats_data[
        "low"
    ]

    average_risk = stats_data[
        "average_risk"
    ]

    threat_counts = stats_data[
        "threat_counts"
    ]

    threat_labels = list(
        threat_counts.keys()
    )

    threat_values = list(
        threat_counts.values()
    )

    threat_labels_json = json.dumps(
        threat_labels
    )

    threat_values_json = json.dumps(
        threat_values
    )


    # --------------------------------------------------------
    # TABLE ROWS
    # --------------------------------------------------------

    rows = ""

    for event in events:

        severity = str(
            event.get(
                "severity",
                "unknown"
            )
        ).lower()

        timestamp = html.escape(
            str(
                event.get(
                    "timestamp",
                    ""
                )
            )
        )

        source_ip = html.escape(
            str(
                event.get(
                    "source_ip",
                    ""
                )
            )
        )

        threat = html.escape(
            str(
                event.get(
                    "threat_type",
                    ""
                )
            )
        )

        severity_text = html.escape(
            str(
                event.get(
                    "severity",
                    ""
                )
            )
        )

        try:

            risk = int(
                event.get(
                    "risk_score",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):

            risk = 0

        rows += f"""

<tr>

<td>
#{event["id"]}
</td>

<td>
{timestamp}
</td>

<td>
<span class="ip">
{source_ip}
</span>
</td>

<td>
{threat}
</td>

<td>

<div class="risk">

<div class="risk-bar">

<div
class="risk-fill"
style="width:{risk}%"
></div>

</div>

<span>
{risk}
</span>

</div>

</td>

<td>

<span
class="severity {severity}"
>
{severity_text}
</span>

</td>

<td>

<button
class="details-button"
onclick="showEvent({event['id']})"
>
View
</button>

</td>

</tr>

"""


    # ========================================================
    # DASHBOARD HTML
    # ========================================================

    return f"""
<!DOCTYPE html>

<html>

<head>

<title>
CyberSentinel Dashboard
</title>

<meta
name="viewport"
content="width=device-width, initial-scale=1.0"
>

<script
src="https://cdn.jsdelivr.net/npm/chart.js"
></script>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    font-family: Arial, sans-serif;

    background: #020617;

    color: #e2e8f0;
}}


/* ==========================================================
   SIDEBAR
   ========================================================== */

.sidebar {{

    position: fixed;

    left: 0;

    top: 0;

    width: 230px;

    height: 100vh;

    background: #0f172a;

    border-right:
        1px solid #1e293b;

    padding: 25px 15px;
}}

.logo {{

    font-size: 20px;

    font-weight: bold;

    padding: 10px;

    margin-bottom: 25px;
}}

.logo span {{

    color: #3b82f6;
}}

.nav {{

    display: block;

    color: #94a3b8;

    text-decoration: none;

    padding: 13px;

    margin: 5px 0;

    border-radius: 8px;
}}

.nav:hover,
.active {{

    background: #1e293b;

    color: white;
}}


/* ==========================================================
   MAIN
   ========================================================== */

.main {{

    margin-left: 230px;

    padding: 30px;
}}


/* ==========================================================
   HEADER
   ========================================================== */

.header {{

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    margin-bottom: 20px;
}}

.header h1 {{

    margin: 0;

    font-size: 28px;
}}

.header p {{

    color: #64748b;

    margin-bottom: 0;
}}

.status {{

    background: #052e16;

    color: #4ade80;

    border:
        1px solid #166534;

    padding: 9px 15px;

    border-radius: 20px;

    font-size: 13px;

    font-weight: bold;
}}


/* ==========================================================
   LIVE MONITOR
   ========================================================== */

.live {{

    background: #0f172a;

    border:
        1px solid #1e293b;

    padding: 13px 15px;

    border-radius: 10px;

    margin-bottom: 20px;

    display: flex;

    justify-content:
        space-between;
}}


/* ==========================================================
   ALERT
   ========================================================== */

.alert-box {{

    display: none;

    background: #450a0a;

    border:
        1px solid #ef4444;

    color: #fecaca;

    padding: 16px;

    border-radius: 10px;

    margin-bottom: 20px;
}}

.alert-title {{

    color: #f87171;

    font-weight: bold;

    margin-bottom: 5px;
}}


/* ==========================================================
   CARDS
   ========================================================== */

.cards {{

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 18px;

    margin-bottom: 20px;
}}

.card {{

    background: #0f172a;

    border:
        1px solid #1e293b;

    padding: 25px;

    border-radius: 14px;
}}

.card-title {{

    color: #94a3b8;

    font-size: 13px;

    margin-bottom: 12px;

    text-transform:
        uppercase;
}}

.number {{

    font-size: 35px;

    font-weight: bold;
}}

.blue {{
    color: #3b82f6;
}}

.orange {{
    color: #f97316;
}}

.red {{
    color: #ef4444;
}}

.green {{
    color: #22c55e;
}}


/* ==========================================================
   CHARTS
   ========================================================== */

.charts {{

    display: grid;

    grid-template-columns:
        1fr 1fr;

    gap: 20px;

    margin-bottom: 20px;
}}

.chart-box {{

    background: #0f172a;

    border:
        1px solid #1e293b;

    border-radius: 14px;

    padding: 20px;

    height: 340px;
}}

.chart-box h3 {{

    margin-top: 0;
}}

.chart-container {{

    height: 270px;
}}


/* ==========================================================
   FILTERS
   ========================================================== */

.filters {{

    display: grid;

    grid-template-columns:
        1fr 1fr 1fr auto auto;

    gap: 10px;

    margin-bottom: 20px;
}}

.filter-input,
.filter-select {{

    background: #020617;

    color: white;

    border:
        1px solid #334155;

    padding: 11px;

    border-radius: 8px;

    outline: none;
}}

.filter-button {{

    background: #2563eb;

    color: white;

    border: none;

    padding: 11px 18px;

    border-radius: 8px;

    cursor: pointer;
}}

.filter-button:hover {{

    background: #1d4ed8;
}}

.export-button {{

    background: #16a34a;

    color: white;

    border: none;

    padding: 11px 18px;

    border-radius: 8px;

    cursor: pointer;

    text-decoration: none;

    text-align: center;
}}


/* ==========================================================
   TABLE
   ========================================================== */

.table-box {{

    background: #0f172a;

    border:
        1px solid #1e293b;

    border-radius: 14px;

    padding: 20px;

    overflow-x: auto;
}}

.table-header {{

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    margin-bottom: 20px;
}}

.table-header h2 {{

    margin: 0;
}}

table {{

    width: 100%;

    border-collapse:
        collapse;

    min-width: 1000px;
}}

th {{

    text-align: left;

    color: #94a3b8;

    font-size: 12px;

    padding: 13px;

    border-bottom:
        1px solid #1e293b;
}}

td {{

    padding: 14px;

    border-bottom:
        1px solid #1e293b;

    font-size: 13px;
}}

tr:hover {{

    background: #111827;
}}

.ip {{

    color: #38bdf8;

    font-family:
        monospace;
}}


/* ==========================================================
   RISK
   ========================================================== */

.risk {{

    display: flex;

    align-items: center;

    gap: 8px;
}}

.risk-bar {{

    width: 80px;

    height: 6px;

    background: #1e293b;

    border-radius: 10px;

    overflow: hidden;
}}

.risk-fill {{

    height: 100%;

    background: #3b82f6;
}}


/* ==========================================================
   SEVERITY
   ========================================================== */

.severity {{

    padding: 5px 10px;

    border-radius: 20px;

    font-size: 11px;

    font-weight: bold;

    text-transform:
        uppercase;
}}

.critical {{

    background: #450a0a;

    color: #f87171;
}}

.high {{

    background: #431407;

    color: #fb923c;
}}

.medium {{

    background: #422006;

    color: #facc15;
}}

.low {{

    background: #052e16;

    color: #4ade80;
}}


/* ==========================================================
   DETAILS BUTTON
   ========================================================== */

.details-button {{

    background: #1e293b;

    color: #93c5fd;

    border:
        1px solid #334155;

    padding: 6px 12px;

    border-radius: 6px;

    cursor: pointer;
}}

.details-button:hover {{

    background: #334155;
}}


/* ==========================================================
   MODAL
   ========================================================== */

.modal {{

    display: none;

    position: fixed;

    inset: 0;

    background:
        rgba(0,0,0,0.75);

    justify-content:
        center;

    align-items:
        center;

    z-index: 1000;
}}

.modal-content {{

    background: #0f172a;

    border:
        1px solid #334155;

    border-radius: 15px;

    padding: 30px;

    width: 450px;

    max-width: 90%;
}}

.modal-content h2 {{

    margin-top: 0;
}}

.detail-row {{

    display: flex;

    justify-content:
        space-between;

    padding: 12px 0;

    border-bottom:
        1px solid #1e293b;
}}

.close-button {{

    margin-top: 20px;

    width: 100%;

    padding: 10px;

    background: #334155;

    color: white;

    border: none;

    border-radius: 8px;

    cursor: pointer;
}}


/* ==========================================================
   RESPONSIVE
   ========================================================== */

@media(max-width:1000px) {{

    .cards {{

        grid-template-columns:
            repeat(2,1fr);
    }}

    .charts {{

        grid-template-columns:
            1fr;
    }}

    .filters {{

        grid-template-columns:
            1fr 1fr;
    }}
}}

@media(max-width:650px) {{

    .sidebar {{

        width: 65px;
    }}

    .logo {{

        font-size: 0;
    }}

    .main {{

        margin-left: 65px;

        padding: 15px;
    }}

    .cards {{

        grid-template-columns:
            1fr;
    }}

    .header {{

        display: block;
    }}

    .filters {{

        grid-template-columns:
            1fr;
    }}

    .status {{

        display: inline-block;

        margin-top: 10px;
    }}

}}

</style>

</head>


<body>


<!-- ========================================================
     SIDEBAR
     ======================================================== -->

<aside class="sidebar">

<div class="logo">

🛡️ Cyber<span>Sentinel</span>

</div>

<a
href="/dashboard"
class="nav active"
>
📊 Dashboard
</a>

<a
href="/events"
class="nav"
>
🚨 Security Events
</a>

<a
href="/alerts/history"
class="nav"
>
🔔 Alert History
</a>

<a
href="/stats"
class="nav"
>
📈 Statistics
</a>

<a
href="/events/export"
class="nav"
>
📥 Export CSV
</a>

<a
href="/docs"
class="nav"
>
📚 API Docs
</a>

</aside>


<!-- ========================================================
     MAIN
     ======================================================== -->

<main class="main">


<div class="header">

<div>

<h1>
Security Operations Center
</h1>

<p>
Cybersecurity Monitoring
& Threat Detection Platform
</p>

</div>

<div class="status">
● SYSTEM ONLINE
</div>

</div>


<!-- LIVE -->

<div class="live">

<span>
🟢 LIVE MONITORING ACTIVE
</span>

<span id="lastUpdate">
Loading...
</span>

</div>


<!-- ALERT -->

<div
id="alertBox"
class="alert-box"
>

<div class="alert-title">
🚨 SECURITY ALERT
</div>

<div id="alertMessage">
No critical alerts.
</div>

</div>


<!-- CARDS -->

<div class="cards">


<div class="card">

<div class="card-title">
Total Security Events
</div>

<div
id="totalEvents"
class="number blue"
>
{total_events}
</div>

</div>


<div class="card">

<div class="card-title">
High Threats
</div>

<div
id="highThreats"
class="number orange"
>
{high}
</div>

</div>


<div class="card">

<div class="card-title">
Critical Threats
</div>

<div
id="criticalThreats"
class="number red"
>
{critical}
</div>

</div>


<div class="card">

<div class="card-title">
Average Risk
</div>

<div
id="averageRisk"
class="number blue"
>
{average_risk}/100
</div>

</div>


</div>


<!-- CHARTS -->

<div class="charts">


<div class="chart-box">

<h3>
Threat Severity
</h3>

<div class="chart-container">

<canvas
id="severityChart"
></canvas>

</div>

</div>


<div class="chart-box">

<h3>
Threat Types
</h3>

<div class="chart-container">

<canvas
id="threatChart"
></canvas>

</div>

</div>


</div>


<!-- FILTERS -->

<div class="filters">

<input
id="ipFilter"
class="filter-input"
placeholder="Source IP"
/>


<select
id="severityFilter"
class="filter-select"
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


<input
id="threatFilter"
class="filter-input"
placeholder="Threat type"
/>


<button
class="filter-button"
onclick="applyFilters()"
>
Filter
</button>


<a
class="export-button"
href="/events/export"
>
Export CSV
</a>

</div>


<!-- TABLE -->

<div class="table-box">

<div class="table-header">

<h2>
Security Events
</h2>

<span id="eventCount">
{total_events} events
</span>

</div>


<table>

<thead>

<tr>

<th>ID</th>

<th>Timestamp</th>

<th>Source IP</th>

<th>Threat</th>

<th>Risk</th>

<th>Severity</th>

<th>Details</th>

</tr>

</thead>


<tbody id="eventTable">

{rows}

</tbody>

</table>

</div>


</main>


<!-- ========================================================
     MODAL
     ======================================================== -->

<div
id="eventModal"
class="modal"
>

<div class="modal-content">

<h2>
Security Event Details
</h2>

<div id="eventDetails">
Loading...
</div>

<button
class="close-button"
onclick="closeModal()"
>
Close
</button>

</div>

</div>


<script>


let severityChart;

let threatChart;


// ========================================================
// CREATE CHARTS
// ========================================================

function createCharts() {{

    const severityCanvas =
        document.getElementById(
            "severityChart"
        );


    severityChart = new Chart(
        severityCanvas,
        {{

            type: "doughnut",

            data: {{

                labels: [
                    "Critical",
                    "High",
                    "Medium",
                    "Low"
                ],

                datasets: [{{

                    data: [
                        {critical},
                        {high},
                        {medium},
                        {low}
                    ],

                    backgroundColor: [
                        "#ef4444",
                        "#f97316",
                        "#eab308",
                        "#22c55e"
                    ],

                    borderWidth: 0

                }}]

            }},

            options: {{

                responsive: true,

                maintainAspectRatio: false,

                plugins: {{

                    legend: {{

                        position: "bottom",

                        labels: {{

                            color: "#cbd5e1"

                        }}

                    }}

                }}

            }}

        }}
    );


    const threatCanvas =
        document.getElementById(
            "threatChart"
        );


    threatChart = new Chart(
        threatCanvas,
        {{

            type: "bar",

            data: {{

                labels:
                    {threat_labels_json},

                datasets: [{{

                    label: "Events",

                    data:
                        {threat_values_json},

                    backgroundColor:
                        "#3b82f6",

                    borderRadius: 5

                }}]

            }},

            options: {{

                responsive: true,

                maintainAspectRatio: false,

                scales: {{

                    x: {{

                        ticks: {{

                            color:
                                "#94a3b8"

                        }},

                        grid: {{

                            display: false

                        }}

                    }},

                    y: {{

                        beginAtZero: true,

                        ticks: {{

                            color:
                                "#94a3b8",

                            stepSize: 1

                        }},

                        grid: {{

                            color:
                                "#1e293b"

                        }}

                    }}

                }},

                plugins: {{

                    legend: {{

                        display: false

                    }}

                }}

            }}

        }}
    );

}}


// ========================================================
// LOAD EVENTS
// ========================================================

async function loadEvents() {{

    try {{

        const response =
            await fetch("/events");

        const events =
            await response.json();

        renderEvents(events);

        updateDashboard(events);

        document.getElementById(
            "lastUpdate"
        ).innerText =
            "Last update: " +
            new Date().toLocaleTimeString();

    }}

    catch(error) {{

        console.log(
            "Event error:",
            error
        );

    }}

}}


// ========================================================
// RENDER EVENTS
// ========================================================

function renderEvents(events){{

    const table =
        document.getElementById(
            "eventTable"
        );

    table.innerHTML = "";


    events.forEach(
        event => {{

            const severity =
                String(
                    event.severity || ""
                ).toLowerCase();


            const row =
                document.createElement(
                    "tr"
                );


            row.innerHTML = `

<td>
#${{event.id}}
</td>

<td>
${{event.timestamp}}
</td>

<td>

<span class="ip">
${{event.source_ip}}
</span>

</td>

<td>
${{event.threat_type}}
</td>

<td>

<div class="risk">

<div class="risk-bar">

<div
class="risk-fill"
style="width:${{event.risk_score}}%"
></div>

</div>

<span>
${{event.risk_score}}
</span>

</div>

</td>

<td>

<span
class="severity ${{severity}}"
>
${{event.severity}}
</span>

</td>

<td>

<button
class="details-button"
onclick="showEvent(${{event.id}})"
>
View
</button>

</td>

`;

            table.appendChild(row);

        }}
    );


    document.getElementById(
        "eventCount"
    ).innerText =
        events.length +
        " events";

}}


// ========================================================
// UPDATE DASHBOARD
// ========================================================

function updateDashboard(events){{

    let critical = 0;

    let high = 0;

    let medium = 0;

    let low = 0;

    let totalRisk = 0;

    let threats = {{}};


    events.forEach(
        event => {{

            const severity =
                String(
                    event.severity || ""
                ).toLowerCase();


            if (
                severity === "critical"
            )
                critical++;


            if (
                severity === "high"
            )
                high++;


            if (
                severity === "medium"
            )
                medium++;


            if (
                severity === "low"
            )
                low++;


            totalRisk += Number(
                event.risk_score || 0
            );


            const threat =
                event.threat_type ||
                "Unknown";


            threats[threat] =
                (
                    threats[threat] || 0
                ) + 1;

        }}
    );


    let average = 0;


    if (events.length > 0) {{

        average =
            Math.round(
                totalRisk /
                events.length
            );

    }}


    document.getElementById(
        "totalEvents"
    ).innerText =
        events.length;


    document.getElementById(
        "highThreats"
    ).innerText =
        high;


    document.getElementById(
        "criticalThreats"
    ).innerText =
        critical;


    document.getElementById(
        "averageRisk"
    ).innerText =
        average + "/100";


    severityChart
        .data
        .datasets[0]
        .data = [

            critical,
            high,
            medium,
            low

        ];


    severityChart.update();


    threatChart
        .data
        .labels =
            Object.keys(threats);


    threatChart
        .data
        .datasets[0]
        .data =
            Object.values(threats);


    threatChart.update();

}}


// ========================================================
// CHECK ALERTS
// ========================================================

async function checkAlerts(){{

    try {{

        const response =
            await fetch("/alerts");

        const alerts =
            await response.json();


        const box =
            document.getElementById(
                "alertBox"
            );


        const message =
            document.getElementById(
                "alertMessage"
            );


        if (
            alerts.length > 0
        ) {{

            const latest =
                alerts[0];


            box.style.display =
                "block";


            message.innerText =

                latest.severity +
                " threat detected: " +

                latest.threat_type +

                " from " +

                latest.source_ip +

                " | Risk Score: " +

                latest.risk_score;

        }}

        else {{

            box.style.display =
                "none";

        }}

    }}

    catch(error) {{

        console.log(
            "Alert error:",
            error
        );

    }}

}}


// ========================================================
// FILTER
// ========================================================

async function applyFilters(){{

    const ip =
        document.getElementById(
            "ipFilter"
        ).value;


    const severity =
        document.getElementById(
            "severityFilter"
        ).value;


    const threat =
        document.getElementById(
            "threatFilter"
        ).value;


    const url =
        "/events/filter?" +

        "severity=" +
        encodeURIComponent(
            severity
        ) +

        "&source_ip=" +
        encodeURIComponent(
            ip
        ) +

        "&threat=" +
        encodeURIComponent(
            threat
        );


    try {{

        const response =
            await fetch(url);

        const events =
            await response.json();

        renderEvents(events);

    }}

    catch(error) {{

        console.log(
            "Filter error:",
            error
        );

    }}

}}


// ========================================================
// EVENT DETAILS
// ========================================================

async function showEvent(id){{

    const modal =
        document.getElementById(
            "eventModal"
        );


    const details =
        document.getElementById(
            "eventDetails"
        );


    modal.style.display =
        "flex";


    details.innerHTML =
        "Loading...";


    try {{

        const response =
            await fetch(
                "/events/" + id
            );


        const event =
            await response.json();


        if (event.error) {{

            details.innerHTML =
                "<p>Event not found.</p>";

            return;

        }}


        details.innerHTML = `

<div class="detail-row">

<span>
ID
</span>

<strong>
#${{event.id}}
</strong>

</div>


<div class="detail-row">

<span>
Timestamp
</span>

<strong>
${{event.timestamp}}
</strong>

</div>


<div class="detail-row">

<span>
Source IP
</span>

<strong>
${{event.source_ip}}
</strong>

</div>


<div class="detail-row">

<span>
Threat
</span>

<strong>
${{event.threat_type}}
</strong>

</div>


<div class="detail-row">

<span>
Risk Score
</span>

<strong>
${{event.risk_score}} / 100
</strong>

</div>


<div class="detail-row">

<span>
Severity
</span>

<strong>
${{event.severity}}
</strong>

</div>

`;

    }}

    catch(error) {{

        details.innerHTML =
            "<p>Unable to load event.</p>";

    }}

}}


// ========================================================
// CLOSE MODAL
// ========================================================

function closeModal(){{

    document.getElementById(
        "eventModal"
    ).style.display =
        "none";

}}


// ========================================================
// INITIALIZE
// ========================================================

createCharts();

loadEvents();

checkAlerts();


setInterval(
    loadEvents,
    5000
);


setInterval(
    checkAlerts,
    5000
);

</script>

</body>

</html>
"""


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend.app:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )