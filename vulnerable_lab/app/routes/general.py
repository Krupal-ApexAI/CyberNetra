"""
General routes for the Vulnerable Lab:
Home, search, feedback, admin, and health check.
"""

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import os

TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
templates = Jinja2Templates(directory=TEMPLATES_DIR)

router = APIRouter(tags=["General"])

# In-memory storage for feedback
FEEDBACK_STORE = [
    {"author": "Alice", "comment": "Great internal company portal!"},
    {"author": "Bob", "comment": "Can we improve network connection speeds?"}
]

# Simulated catalog items for search
CATALOG_ITEMS = [
    {"id": 1, "title": "Corporate VPN Gateway Configuration", "category": "Network", "author": "admin"},
    {"id": 2, "title": "Quarterly Financial Audit Report 2026", "category": "Finance", "author": "cfo"},
    {"id": 3, "title": "Employee Directory and Org Chart", "category": "HR", "author": "hr_lead"},
    {"id": 4, "title": "Database Connection Strings & Secrets", "category": "IT", "author": "sysadmin"},
    {"id": 5, "title": "Core Router Firmware v4.2 Upgrade", "category": "Infrastructure", "author": "net_ops"},
]


@router.get("/", response_class=HTMLResponse)
async def home_page(request: Request):
    """Lab portal landing page."""
    return templates.TemplateResponse(request, "index.html", context={
        "title": "Apex Enterprise Portal — Staging Lab",
        "items": CATALOG_ITEMS
    })


@router.get("/health")
async def health_check():
    """Health check endpoint for telemetry verification."""
    return {
        "status": "healthy",
        "app": "cybernetra-vulnerable-lab",
        "version": "1.0.0",
        "environment": "isolated-test-lab"
    }


@router.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, q: str = ""):
    """
    Search route intentionally vulnerable to:
    1. Reflected XSS: unescaped 'q' displayed directly in HTML
    2. Simulated SQL Injection: accepts SQL tokens for telemetry triggers
    """
    results = []
    if q:
        # Simulate simple search
        lower_q = q.lower()
        # If SQL injection bypass used, return all records
        if "or 1=1" in lower_q or "' or '1'='1" in lower_q or "union select" in lower_q:
            results = CATALOG_ITEMS
        else:
            results = [item for item in CATALOG_ITEMS if lower_q in item["title"].lower() or lower_q in item["category"].lower()]

    return templates.TemplateResponse(request, "search.html", context={
        "query": q,
        "results": results
    })


@router.get("/admin", response_class=HTMLResponse)
async def admin_portal(request: Request):
    """
    Simulated unprotected/sensitive admin portal:
    Demonstrates broken access control / sensitive data exposure.
    """
    server_info = {
        "os": "Linux Ubuntu 22.04 LTS (Kernel 5.15)",
        "database": "PostgreSQL 14.5 (Internal)",
        "internal_ip": "10.0.4.15",
        "gateway": "10.0.4.1",
        "debug_mode": "ENABLED",
        "api_keys": "sk_test_51Mz49Q..."
    }
    return templates.TemplateResponse(request, "admin.html", context={
        "server_info": server_info
    })


@router.get("/feedback", response_class=HTMLResponse)
async def feedback_page(request: Request):
    """View stored feedback."""
    return templates.TemplateResponse(request, "feedback.html", context={
        "feedbacks": FEEDBACK_STORE
    })


@router.post("/feedback", response_class=HTMLResponse)
async def submit_feedback(request: Request, author: str = Form("Anonymous"), comment: str = Form("")):
    """
    Stored XSS demonstration:
    Comments are stored without sanitization.
    """
    if comment:
        FEEDBACK_STORE.append({"author": author, "comment": comment})
    return templates.TemplateResponse(request, "feedback.html", context={
        "feedbacks": FEEDBACK_STORE,
        "message": "Feedback submitted successfully!"
    })
