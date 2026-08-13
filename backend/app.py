from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import sqlite3
import os

from backend import auth


app = FastAPI(
    title="CyberSentinel",
    description="Cybersecurity Monitoring Dashboard",
    version="1.0"
)


# ==========================================================
# DATABASE
# ==========================================================

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

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    return connection


def get_events():

    connection = get_connection()

    cursor = connection.cursor()

    try:

        cursor.execute("""
            SELECT
                id,
                timestamp,
                source_ip,
                destination_ip,
                threat_type,
                risk_score,
                severity
            FROM events
            ORDER BY id DESC
        """)

        events = cursor.fetchall()

    except sqlite3.Error as error:

        print("Database Error:", error)

        events = []

    connection.close()

    return events


# ==========================================================
# AUTHENTICATION
# ==========================================================

app.include_router(
    auth.router
)


# ==========================================================
# HOME
# ==========================================================

@app.get("/")
def home(
    request: Request
):

    authenticated = request.cookies.get(
        "cybersentinel_auth"
    )

    if authenticated != "authenticated":

        return RedirectResponse(
            url="/login",
            status_code=303
        )

    return RedirectResponse(
        url="/dashboard",
        status_code=303
    )


# ==========================================================
# DASHBOARD
# ==========================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
def dashboard(
    request: Request
):

    authenticated = request.cookies.get(
        "cybersentinel_auth"
    )

    if authenticated != "authenticated":

        return RedirectResponse(
            url="/login",
            status_code=303
        )


    events = get_events()


    # ------------------------------------------------------
    # STATISTICS
    # ------------------------------------------------------

    total_events = len(events)

    critical_count = sum(
        1
        for event in events
        if str(event["severity"]).lower()
        == "critical"
    )

    high_count = sum(
        1
        for event in events
        if str(event["severity"]).lower()
        == "high"
    )

    medium_count = sum(
        1
        for event in events
        if str(event["severity"]).lower()
        == "medium"
    )

    low_count = sum(
        1
        for event in events
        if str(event["severity"]).lower()
        == "low"
    )


    if total_events > 0:

        average_risk = round(
            sum(
                float(event["risk_score"] or 0)
                for event in events
            )
            / total_events,
            2
        )

    else:

        average_risk = 0


    # ------------------------------------------------------
    # EVENT TABLE
    # ------------------------------------------------------

    rows = ""


    for event in events:

        severity = str(
            event["severity"]
        )

        severity_lower = severity.lower()


        if severity_lower == "critical":

            badge_class = "critical"

        elif severity_lower == "high":

            badge_class = "high"

        elif severity_lower == "medium":

            badge_class = "medium"

        else:

            badge_class = "low"


        destination_ip = (
            event["destination_ip"]
            if event["destination_ip"]
            else "-"
        )


        rows += f"""
        <tr>

            <td>{event["id"]}</td>

            <td>{event["timestamp"]}</td>

            <td>{event["source_ip"]}</td>

            <td>{destination_ip}</td>

            <td>{event["threat_type"]}</td>

            <td>
                <span class="badge {badge_class}">
                    {severity}
                </span>
            </td>

            <td>
                <strong>
                    {event["risk_score"]}/100
                </strong>
            </td>

        </tr>
        """


    if not rows:

        rows = """
        <tr>
            <td
                colspan="7"
                class="no-events"
            >
                No security events found.
            </td>
        </tr>
        """


    # ======================================================
    # HTML
    # ======================================================

    html = f"""
<!DOCTYPE html>

<html>

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        CyberSentinel Dashboard
    </title>


    <style>

        * {{
            box-sizing: border-box;
        }}


        body {{

            margin: 0;

            font-family:
                Arial,
                sans-serif;

            background:
                #0f172a;

            color:
                #e2e8f0;

        }}


        /* HEADER */

        .header {{

            background:
                #111827;

            padding:
                20px 30px;

            display:
                flex;

            justify-content:
                space-between;

            align-items:
                center;

            border-bottom:
                1px solid #334155;

        }}


        .header h1 {{

            margin: 0;

            color:
                white;

            font-size:
                26px;

        }}


        .logout {{

            background:
                #dc2626;

            color:
                white;

            text-decoration:
                none;

            padding:
                10px 18px;

            border-radius:
                8px;

            font-weight:
                bold;

        }}


        .logout:hover {{

            background:
                #b91c1c;

        }}


        /* CONTAINER */

        .container {{

            padding:
                30px;

        }}


        /* CARDS */

        .cards {{

            display:
                grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(
                        180px,
                        1fr
                    )
                );

            gap:
                20px;

            margin-bottom:
                30px;

        }}


        .card {{

            background:
                #1e293b;

            padding:
                25px;

            border-radius:
                14px;

            border:
                1px solid #334155;

        }}


        .card h3 {{

            margin:
                0 0 12px 0;

            color:
                #94a3b8;

            font-size:
                15px;

        }}


        .number {{

            font-size:
                32px;

            font-weight:
                bold;

            color:
                white;

        }}


        /* TABLE */

        .table-container {{

            background:
                #1e293b;

            padding:
                25px;

            border-radius:
                14px;

            border:
                1px solid #334155;

            overflow-x:
                auto;

        }}


        .table-container h2 {{

            margin-top:
                0;

            color:
                white;

        }}


        table {{

            width:
                100%;

            border-collapse:
                collapse;

        }}


        th,
        td {{

            padding:
                14px;

            text-align:
                left;

            border-bottom:
                1px solid #334155;

        }}


        th {{

            color:
                #94a3b8;

            font-size:
                13px;

            text-transform:
                uppercase;

        }}


        td {{

            color:
                #e2e8f0;

        }}


        /* SEVERITY */

        .badge {{

            display:
                inline-block;

            padding:
                5px 10px;

            border-radius:
                20px;

            font-size:
                12px;

            font-weight:
                bold;

        }}


        .critical {{

            background:
                #7f1d1d;

            color:
                #fecaca;

        }}


        .high {{

            background:
                #9a3412;

            color:
                #fed7aa;

        }}


        .medium {{

            background:
                #854d0e;

            color:
                #fef08a;

        }}


        .low {{

            background:
                #166534;

            color:
                #bbf7d0;

        }}


        .no-events {{

            text-align:
                center;

            padding:
                30px;

            color:
                #94a3b8;

        }}

    </style>

</head>


<body>


    <!-- HEADER -->

    <div class="header">

        <h1>
            🛡️ CyberSentinel
        </h1>


        <a
            class="logout"
            href="/logout"
        >
            Logout
        </a>

    </div>


    <!-- MAIN -->

    <div class="container">


        <!-- STATISTICS -->

        <div class="cards">


            <div class="card">

                <h3>
                    Total Security Events
                </h3>

                <div class="number">
                    {total_events}
                </div>

            </div>


            <div class="card">

                <h3>
                    Critical Threats
                </h3>

                <div class="number">
                    {critical_count}
                </div>

            </div>


            <div class="card">

                <h3>
                    High Threats
                </h3>

                <div class="number">
                    {high_count}
                </div>

            </div>


            <div class="card">

                <h3>
                    Medium Threats
                </h3>

                <div class="number">
                    {medium_count}
                </div>

            </div>


            <div class="card">

                <h3>
                    Low Threats
                </h3>

                <div class="number">
                    {low_count}
                </div>

            </div>


            <div class="card">

                <h3>
                    Average Risk Score
                </h3>

                <div class="number">
                    {average_risk}
                </div>

            </div>


        </div>


        <!-- EVENTS -->

        <div class="table-container">

            <h2>
                Security Events
            </h2>


            <table>

                <thead>

                    <tr>

                        <th>
                            ID
                        </th>

                        <th>
                            Timestamp
                        </th>

                        <th>
                            Source IP
                        </th>

                        <th>
                            Destination IP
                        </th>

                        <th>
                            Threat Type
                        </th>

                        <th>
                            Severity
                        </th>

                        <th>
                            Risk Score
                        </th>

                    </tr>

                </thead>


                <tbody>

                    {rows}

                </tbody>

            </table>

        </div>


    </div>


</body>

</html>
"""


    return HTMLResponse(
        content=html
    )


# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.get("/health")
def health():

    return {
        "status": "online",
        "service": "CyberSentinel"
    }

