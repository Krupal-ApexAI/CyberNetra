"""
Authentication routes for Vulnerable Lab:
Login, logout, credential verification, and brute-force simulation.
"""

from fastapi import APIRouter, Request, Form, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import os

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Valid user database for the lab
VALID_ACCOUNTS = {
    "admin": "admin123",
    "operator": "cyber2026",
    "analyst": "netra2026"
}


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Render login page."""
    return templates.TemplateResponse(request, "login.html", context={
        "error": None
    })


@router.post("/login", response_class=HTMLResponse)
async def process_login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    """
    Login handler with intentional vulnerabilities:
    1. SQL injection auth bypass: ' OR 1=1 --
    2. Returns HTTP 401 on failure (enabling brute-force detection telemetry)
    """
    lower_user = username.strip().lower()

    # 1. SQL Injection Authentication Bypass Vulnerability
    is_sqli_bypass = (
        "' or 1=1" in lower_user or
        "' or '1'='1" in lower_user or
        "admin'--" in lower_user or
        "admin' #" in lower_user
    )

    if is_sqli_bypass:
        # Bypass successful!
        return templates.TemplateResponse(request, "login.html", context={
            "success": f"SQL Injection Authentication Bypass Succeeded! Logged in as: {username}",
            "role": "SYSTEM_ADMINISTRATOR"
        })

    # Standard check
    expected_password = VALID_ACCOUNTS.get(username.strip())
    if expected_password and expected_password == password.strip():
        return templates.TemplateResponse(request, "login.html", context={
            "success": f"Welcome back, {username}! Authentication successful.",
            "role": "SECURITY_OPERATOR"
        })

    # Authentication failure -> return 401 Unauthorized
    # Note: Status 401 is specifically monitored by SecurityLoggingMiddleware
    response.status_code = status.HTTP_401_UNAUTHORIZED
    return templates.TemplateResponse(request, "login.html", context={
        "error": "Invalid username or password. Authentication failed.",
    }, status_code=401)


@router.get("/logout")
async def logout():
    """Logout redirect."""
    return RedirectResponse(url="/auth/login")
