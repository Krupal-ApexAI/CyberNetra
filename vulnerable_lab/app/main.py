"""
CyberNetra Controlled Vulnerable Web Lab - Application Entrypoint
Runs as an isolated FastAPI web application on port 9000.
Generates structured security telemetry for CyberNetra AI detection.
"""

import os
import sys
from pathlib import Path

# Ensure vulnerable_lab is in python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load local .env if available
try:
    from dotenv import load_dotenv
    env_path = os.path.join(Path(__file__).resolve().parent.parent, ".env")
    if os.path.exists(env_path):
        load_dotenv(env_path)
except ImportError:
    pass

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.middleware import SecurityLoggingMiddleware
from app.routes import general, auth, api, status

app = FastAPI(
    title="CyberNetra Controlled Vulnerable Web Lab",
    description="Isolated security-testing web application generating realistic security telemetry for CyberNetra AI.",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Security Telemetry Logging Middleware
app.add_middleware(SecurityLoggingMiddleware)

# Static files
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))
os.makedirs(STATIC_DIR, exist_ok=True)
os.makedirs(os.path.join(STATIC_DIR, "css"), exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Mount Routers
app.include_router(general.router)
app.include_router(auth.router)
app.include_router(api.router)
app.include_router(status.router)

# Convenience redirects
@app.get("/login")
async def redirect_login():
    return RedirectResponse(url="/auth/login")


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("LAB_HOST", "127.0.0.1")
    port = int(os.getenv("LAB_PORT", 9000))
    print(f"[*] Starting CyberNetra Vulnerable Lab on http://{host}:{port}")
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
