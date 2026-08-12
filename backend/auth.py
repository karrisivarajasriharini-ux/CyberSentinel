from fastapi import APIRouter, Form
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter()

USERNAME = "admin"
PASSWORD = "CyberSentinel@123"


@router.get("/login", response_class=HTMLResponse)
def login_page():

    return """
    <!DOCTYPE html>
    <html>
    <head>

        <title>CyberSentinel Login</title>

        <style>

            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #0f172a;

                display: flex;
                justify-content: center;
                align-items: center;

                min-height: 100vh;
            }

            .login-box {

                width: 360px;

                background: white;

                padding: 35px;

                border-radius: 15px;

                box-shadow:
                    0 10px 30px
                    rgba(0,0,0,0.3);
            }

            h1 {
                text-align: center;
                margin-bottom: 10px;
            }

            p {
                text-align: center;
                color: #64748b;
                margin-bottom: 25px;
            }

            input {

                width: 100%;

                padding: 12px;

                margin-bottom: 15px;

                border: 1px solid #cbd5e1;

                border-radius: 8px;

                box-sizing: border-box;
            }

            button {

                width: 100%;

                padding: 12px;

                border: none;

                border-radius: 8px;

                background: #2563eb;

                color: white;

                font-size: 16px;

                cursor: pointer;
            }

            button:hover {
                background: #1d4ed8;
            }

        </style>

    </head>

    <body>

        <div class="login-box">

            <h1>🛡️ CyberSentinel</h1>

            <p>Security Monitoring Login</p>

            <form method="post" action="/login">

                <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    required
                >

                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                >

                <button type="submit">
                    Login
                </button>

            </form>

        </div>

    </body>
    </html>
    """


@router.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...)
):

    if username == USERNAME and password == PASSWORD:

        response = RedirectResponse(
            url="/",
            status_code=303
        )

        response.set_cookie(
            key="cybersentinel_auth",
            value="authenticated",
            httponly=True
        )

        return response

    return HTMLResponse(
        """
        <h2>❌ Invalid username or password</h2>
        <a href="/login">Try again</a>
        """,
        status_code=401
    )


@router.get("/logout")
def logout():

    response = RedirectResponse(
        url="/login",
        status_code=303
    )

    response.delete_cookie(
        "cybersentinel_auth"
    )

    return response