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
from db_aws import init_db, test_connection, db_health_check
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI(
    title="VAPT Report Generator",
    description="Vulnerability Assessment and Penetration Testing Report Generator",
    version="1.0.0"
)

# Add session middleware for SSO
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecret"),
    https_only=True,  # Set to True for production with HTTPS
    same_site="lax",
    session_cookie="reportgen_session"
)

# Include SSO authentication router
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecret"),
    https_only=True,  # Set to True for production with HTTPS
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
    """Health check endpoint for AWS ALB/ELB"""
    db_status = db_health_check()
    return {
        "status": "healthy" if db_status["status"] == "healthy" else "degraded",
        "service": "vapt-report-generator",
        "database": db_status["status"],
        "timestamp": db_status.get("timestamp")
    }

# Root route that redirects to login
@app.get("/")
async def root():
    return RedirectResponse("/login")

# Mount the Type-1 (main.py) app at /type1, protected by SSO
app.mount("/type1", type1_app)

# Mount the Type-2 (type2.py) app at /type2, protected by SSO
app.mount("/type2", type2_app)

# Mount static files
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
async def on_startup():
    """Initialize application on startup"""
    try:
        logger.info("Starting VAPT Report Generator...")
        
        # Test database connection
        if test_connection():
            logger.info("Database connection successful")
            
            # Initialize database tables
            init_db()
            logger.info("Database initialized successfully")
        else:
            logger.error("Failed to connect to database")
            
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        raise

@app.on_event("shutdown")
async def on_shutdown():
    """Cleanup on shutdown"""
    logger.info("Shutting down VAPT Report Generator...")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app_aws:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=False,  # Disable reload in production
        log_level="info"
    )
