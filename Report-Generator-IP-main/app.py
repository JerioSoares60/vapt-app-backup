from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import RedirectResponse
from Automation.backend.main import app as type1_app
from Automation.backend.type2 import app as type2_app
from auth import router as auth_router
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from dotenv import load_dotenv
from db import init_db

# Load .env file from the correct location
env_path = os.path.join(os.path.dirname(__file__), "Automation", "backend", ".env")
load_dotenv(env_path)

app = FastAPI()

# Add session middleware for SSO
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
    return {"status": "healthy", "service": "vapt-report-generator"}

# Root route that redirects to login
@app.get("/")
async def root():
    return RedirectResponse("/login")

# Mount the Type-1 (main.py) app at /type1, protected by SSO
app.mount("/type1", type1_app)

# Mount the Type-2 (type2.py) app at /type2, protected by SSO
app.mount("/type2", type2_app)

app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/Automation", StaticFiles(directory="Automation"), name="automation-static")

@app.get("/report_formats.html", response_class=HTMLResponse)
async def report_formats():
    with open("Automation/report_formats.html", encoding="utf-8") as f:
        return f.read() 

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    # Only allow specific users to access dashboard
    user = request.session.get("user")
    if not user:
        return RedirectResponse("/login")
    allowed = {"sarvesh.salgaonkar@cybersmithsecure.com", "developer@cybersmithsecure.com"}
    if user.get("email", "").lower() not in allowed:
        return RedirectResponse("/report_formats.html")
    from fastapi.templating import Jinja2Templates
    import os as _os
    templates = Jinja2Templates(directory=_os.path.join(_os.path.dirname(__file__), "templates"))
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.on_event("startup")
def on_startup():
    # Ensure DB is initialized
    init_db()
