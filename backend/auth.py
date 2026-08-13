from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()

USERNAME = "admin"
PASSWORD = "CyberSentinel@123"


# ==========================================================
# LOGIN PAGE
# ==========================================================

@router.get("/login", response_class=HTMLResponse)
def login_page():

    return """
<!DOCTYPE html>
<html>
<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>CyberSentinel Login</title>

    <style>

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;

            font-family: Arial, sans-serif;

            background:
                radial-gradient(circle at 20% 20%, #12315c 0%, transparent 30%),
                radial-gradient(circle at 80% 80%, #0b4f55 0%, transparent 30%),
                #020617;

            color: #e2e8f0;

            display: flex;
            justify-content: center;
            align-items: center;

            overflow: hidden;
        }

        .grid {
            position: fixed;
            inset: 0;

            background-image:
                linear-gradient(rgba(56,189,248,0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(56,189,248,0.05) 1px, transparent 1px);

            background-size: 45px 45px;

            pointer-events: none;
        }

        .login-box {

            width: 390px;
            max-width: 90%;

            padding: 40px;

            background: rgba(15, 23, 42, 0.92);

            border: 1px solid #1e40af;

            border-radius: 18px;

            box-shadow:
                0 0 35px rgba(14,165,233,0.15),
                inset 0 0 25px rgba(14,165,233,0.03);

            position: relative;
            z-index: 2;
        }

        .logo {
            text-align: center;
            margin-bottom: 25px;
        }

        .shield {
            font-size: 52px;
            margin-bottom: 10px;
        }

        .logo h1 {
            margin: 0;

            font-size: 28px;

            color: white;
        }

        .logo h1 span {
            color: #38bdf8;
        }

        .logo p {
            margin-top: 8px;

            color: #64748b;

            font-size: 13px;
        }

        .status {

            display: flex;
            align-items: center;
            justify-content: center;

            gap: 8px;

            margin-bottom: 25px;

            color: #4ade80;

            font-size: 12px;
            font-weight: bold;
        }

        .dot {

            width: 8px;
            height: 8px;

            background: #22c55e;

            border-radius: 50%;

            box-shadow: 0 0 10px #22c55e;
        }

        label {

            display: block;

            margin-bottom: 7px;

            color: #94a3b8;

            font-size: 13px;
        }

        input {

            width: 100%;

            padding: 13px 14px;

            margin-bottom: 18px;

            border-radius: 9px;

            border: 1px solid #334155;

            background: #020617;

            color: white;

            outline: none;

            font-size: 14px;

            transition: 0.2s;
        }

        input:focus {

            border-color: #38bdf8;

            box-shadow:
                0 0 0 2px rgba(56,189,248,0.1);
        }

        button {

            width: 100%;

            padding: 13px;

            border: none;

            border-radius: 9px;

            background: linear-gradient(
                90deg,
                #2563eb,
                #0891b2
            );

            color: white;

            font-size: 15px;

            font-weight: bold;

            cursor: pointer;

            transition: 0.2s;
        }

        button:hover {

            transform: translateY(-1px);

            box-shadow:
                0 0 20px rgba(14,165,233,0.3);
        }

        .footer {

            text-align: center;

            margin-top: 22px;

            font-size: 11px;

            color: #475569;
        }

    </style>

</head>

<body>

<div class="grid"></div>

<div class="login-box">

    <div class="logo">

        <div class="shield">🛡️</div>

        <h1>Cyber<span>Sentinel</span></h1>

        <p>Security Operations Center</p>

    </div>


    <div class="status">

        <span class="dot"></span>

        SECURE AUTHENTICATION PORTAL

    </div>


    <form method="post" action="/login">

        <label>Username</label>

        <input
            type="text"
            name="username"
            placeholder="Enter username"
            autocomplete="username"
            required
        >


        <label>Password</label>

        <input
            type="password"
            name="password"
            placeholder="Enter password"
            autocomplete="current-password"
            required
        >


        <button type="submit">
            🔐 Secure Login
        </button>

    </form>


    <div class="footer">
        CyberSentinel Security Monitoring Platform
    </div>

</div>

</body>
</html>
"""


# ==========================================================
# LOGIN
# ==========================================================

@router.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...)
):

    if username == USERNAME and password == PASSWORD:

        response = RedirectResponse(
            url="/dashboard",
            status_code=303
        )

        response.set_cookie(
            key="cybersentinel_auth",
            value="authenticated",
            httponly=True,
            samesite="lax"
        )

        return response

    return HTMLResponse(
        """
        <html>
        <body style="
            background:#020617;
            color:white;
            font-family:Arial;
            text-align:center;
            padding-top:100px;
        ">

        <h2 style="color:#ef4444;">
            ❌ Invalid username or password
        </h2>

        <a
            href="/login"
            style="color:#38bdf8;"
        >
            Try Again
        </a>

        </body>
        </html>
        """,
        status_code=401
    )


# ==========================================================
# LOGOUT
# ==========================================================

@router.get("/logout")
def logout():

    response = RedirectResponse(
        url="/login",
        status_code=303
    )

    response.delete_cookie(
        key="cybersentinel_auth"
    )

    return response