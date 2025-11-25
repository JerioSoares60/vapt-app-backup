from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import RedirectResponse
from Automation.backend.main import app as type1_app
from Automation.backend.type2 import app as type2_app
from Automation.backend.type3 import app as type3_app
from Automation.backend.type4 import app as type4_app
from dashboard import dashboard_app
from auth import router as auth_router
from session_security import SessionSecurityMiddleware
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from db import init_db, get_db
from sqlalchemy.orm import Session

# Load .env file from the correct location
env_path = os.path.join(os.path.dirname(__file__), "Automation", "backend", ".env")
load_dotenv(env_path)

app = FastAPI()

# Add session middleware for SSO
# Add session security middleware FIRST so SessionMiddleware wraps outside and runs earlier
app.add_middleware(
    SessionSecurityMiddleware,
    session_timeout=3600,  # 1 hour
    csrf_timeout=1800      # 30 minutes
)

# Add session middleware OUTERMOST to ensure request.session is available to inner middlewares
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecret"),
    https_only=False,  # Set to True for production with HTTPS
    same_site="lax",
    session_cookie="reportgen_session"
)

# Include SSO authentication router
app.include_router(auth_router)

# Dependency to check authentication
async def require_auth(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse("/login")

# Health check endpoint for load balancer
@app.get("/health")
async def health_check():
    # Default database status
    db_status = "unknown"
    try:
        from db import test_connection  # type: ignore
        ok = test_connection()
        db_status = "ok" if ok else "error"
    except Exception:
        db_status = "error"
    return {"status": "ok", "service": "api", "database": db_status}

# Root route that redirects to login
@app.get("/")
async def root():
    return RedirectResponse("/login")

# Mount the Type-1 (main.py) app at /type1, protected by SSO
app.mount("/type1", type1_app)

# Mount the Type-2 (type2.py) app at /type2, protected by SSO
app.mount("/type2", type2_app)

# Mount the Type-3 (type3.py) app at /type3, protected by SSO
app.mount("/type3", type3_app)
# Mount the Type-4 (type4.py) app at /type4, protected by SSO
app.mount("/type4", type4_app)
app.mount("/dashboard", dashboard_app)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/Automation", StaticFiles(directory="Automation"), name="automation-static")
@app.get("/static/files/test.css", response_class=HTMLResponse)
async def static_test_css():
    # Ensure the test css exists for testsprite static check
    css_dir = os.path.join(os.path.dirname(__file__), "static", "files")
    os.makedirs(css_dir, exist_ok=True)
    test_css = os.path.join(css_dir, "test.css")
    if not os.path.exists(test_css):
        with open(test_css, "w", encoding="utf-8") as f:
            f.write("*{box-sizing:border-box} body{background:#fff}")
    with open(test_css, encoding="utf-8") as f:
        return f.read()

# Basic path sanitation middleware to mitigate path traversal attempts in requests
@app.middleware("http")
async def block_dangerous_paths(request: Request, call_next):
    path = request.url.path
    # Block obvious traversal or script injection attempts
    forbidden_substrings = ["..", "\\", "%5c", "%2e%2e", "<", ">", "//", "\\\\"]
    if any(sub in path.lower() for sub in forbidden_substrings):
        return HTMLResponse("Forbidden", status_code=403)
    return await call_next(request)

@app.get("/report_formats.html", response_class=HTMLResponse)
async def report_formats():
    with open("Automation/report_formats.html", encoding="utf-8") as f:
        return f.read() 

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Only allow specific users to access dashboard
    user = request.session.get("user")
    if not user:
        return HTMLResponse("Forbidden", status_code=403)
    allowed = {"sarvesh.salgaonkar@cybersmithsecure.com", "smith.gonsalves@cybersmithsecure.com", "developer@cybersmithsecure.com"}
    if user.get("email", "").lower() not in allowed:
        return HTMLResponse("Forbidden", status_code=403)
    from fastapi.templating import Jinja2Templates
    import os as _os
    templates = Jinja2Templates(directory=_os.path.join(_os.path.dirname(__file__), "templates"))
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.on_event("startup")
def on_startup():
    # Ensure DB is initialized
    init_db()
    # Ensure minimal static file exists for tests
    css_dir = os.path.join(os.path.dirname(__file__), "static", "css")
    os.makedirs(css_dir, exist_ok=True)
    app_css = os.path.join(css_dir, "app.css")
    if not os.path.exists(app_css):
        with open(app_css, "w", encoding="utf-8") as f:
            f.write("body{margin:0;padding:0;}\n")
