
import os
from dotenv import load_dotenv

# Load .env file from the correct location
env_path = os.path.join(os.path.dirname(__file__), "Automation", "backend", ".env")
load_dotenv(env_path)

# Debug: Print environment variables

from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import RedirectResponse, HTMLResponse
from jose import jwt, JWTError
import requests
from urllib.parse import urlencode
from pydantic import BaseModel, EmailStr, ValidationError
from starlette.middleware.sessions import SessionMiddleware
from jose.backends.cryptography_backend import CryptographyRSAKey
from fastapi.templating import Jinja2Templates
from typing import Optional
import json
from db import get_db, AuditLog
from sqlalchemy.orm import Session
from session_security import create_secure_session, invalidate_session, get_csrf_token, refresh_csrf_token

router = APIRouter()

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)

templates = Jinja2Templates(directory=TEMPLATES_DIR)

AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
# For EC2 deployment, use the environment variable or default to localhost
AZURE_REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "https://13.202.112.84/auth/callback")
print(f"DEBUG: AZURE_REDIRECT_URI = {AZURE_REDIRECT_URI}")
AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
AZURE_AUTH_ENDPOINT = f"{AZURE_AUTHORITY}/oauth2/v2.0/authorize"
AZURE_TOKEN_ENDPOINT = f"{AZURE_AUTHORITY}/oauth2/v2.0/token"
AZURE_JWKS_URI = f"{AZURE_AUTHORITY}/discovery/v2.0/keys"

ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "cybersmithsecure.com")
TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"

class EmailForm(BaseModel):
    email: EmailStr

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/auth/login")
async def auth_login(request: Request, email: Optional[str] = Form(default=None)):
    # Email is optional for initiating OAuth; validate only when provided
    if email:
        try:
            EmailForm(email=email)
        except ValidationError:
            raise HTTPException(status_code=400, detail="Invalid email address")
    params = {
        "client_id": AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": AZURE_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        # Only include login_hint when email is provided
        "login_hint": email or "",
        "prompt": "login",
    }
    url = f"{AZURE_AUTH_ENDPOINT}?{urlencode(params)}"
    return RedirectResponse(url, status_code=302)

# Some test harnesses initiate the OAuth flow using GET instead of POST.
# Provide a GET alias that behaves the same (without requiring an email).
@router.get("/auth/login")
async def auth_login_get(request: Request, email: Optional[str] = None):
    if email:
    try:
        EmailForm(email=email)
    except ValidationError:
        raise HTTPException(status_code=400, detail="Invalid email address")
    params = {
        "client_id": AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": AZURE_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "login_hint": email or "",
        "prompt": "login",
    }
    url = f"{AZURE_AUTH_ENDPOINT}?{urlencode(params)}"
    return RedirectResponse(url, status_code=302)

@router.get("/auth/callback")
def auth_callback(request: Request, code: Optional[str] = None, error: Optional[str] = None, db: Session = Depends(get_db)):
    print(f"Callback received - code: {code is not None}, error: {error}")
    if error:
        print(f"Authentication error: {error}")
        return HTMLResponse(f"<h2>Authentication Error</h2><pre>{error}</pre>", status_code=400)
    if not code:
        print("Missing code parameter")
        return HTMLResponse("<h2>Authentication Error</h2><pre>Missing code parameter from Azure.</pre>", status_code=400)
    
    print(f"Processing code: {code[:20]}...")
    data = {
        "client_id": AZURE_CLIENT_ID,
        "scope": "openid profile email",
        "code": code,
        "redirect_uri": AZURE_REDIRECT_URI,
        "grant_type": "authorization_code",
        "client_secret": AZURE_CLIENT_SECRET,
    }
    print(f"Token endpoint: {AZURE_TOKEN_ENDPOINT}")
    print(f"Client ID: {AZURE_CLIENT_ID}")
    print(f"Redirect URI: {AZURE_REDIRECT_URI}")
    
    token_resp = requests.post(AZURE_TOKEN_ENDPOINT, data=data)
    print(f"Token response status: {token_resp.status_code}")
    if not token_resp.ok:
        print(f"Token error response: {token_resp.text}")
        return HTMLResponse(f"<h2>Token Endpoint Error</h2><pre>{token_resp.text}</pre>", status_code=400)
    
    token_json = token_resp.json()
    id_token = token_json.get("id_token")
    if not id_token:
        print(f"No ID token in response: {token_json}")
        return HTMLResponse(f"<h2>Authentication Error</h2><pre>Failed to authenticate. Azure response: {token_resp.text}</pre>", status_code=400)
    
    print("ID token received, validating...")
    jwks = requests.get(AZURE_JWKS_URI).json()
    try:
        header = jwt.get_unverified_header(id_token)
        kid = header["kid"]
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key:
            print("No matching key found in JWKS")
            return HTMLResponse("Unable to find appropriate key for token.", status_code=400)
        public_key = CryptographyRSAKey(key, algorithm="RS256")
        claims = jwt.decode(id_token, public_key, algorithms=["RS256"], audience=AZURE_CLIENT_ID)
        print(f"Token validated, claims: {claims}")
    except JWTError as e:
        print(f"JWT validation error: {str(e)}")
        return HTMLResponse(f"Token validation error: {str(e)}", status_code=400)
    
    user_email = claims.get("preferred_username") or claims.get("email")
    print(f"User email: {user_email}")
    if not user_email or not user_email.lower().endswith(f"@{ALLOWED_EMAIL_DOMAIN}"):
        print(f"Email domain not allowed: {user_email}")
        return HTMLResponse("<h2>Access Denied</h2><pre>Your email is not allowed for access.</pre>", status_code=403)
    
    user_payload = {
        "name": claims.get("name"),
        "email": user_email,
        "oid": claims.get("oid"),
    }
    # Create secure session with fingerprint and CSRF token
    create_secure_session(request, user_payload)
    try:
        # Audit log for successful login
        db.add(AuditLog(
            user_email=user_email,
            user_name=claims.get("name"),
            action="login",
            metadata_json=json.dumps({"oid": claims.get("oid")}),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        ))
        db.commit()
    except Exception:
        pass
    print("Session set, redirecting to report_formats.html")
    return RedirectResponse("/report_formats.html")

# Test-only endpoint to set a session without Azure roundtrip
@router.post("/__test/set-session")
def __test_set_session(request: Request, email: str = Form("developer@cybersmithsecure.com")):
    if not TEST_MODE:
        raise HTTPException(status_code=404, detail="Not Found")
    if not email.lower().endswith(f"@{ALLOWED_EMAIL_DOMAIN}"):
        raise HTTPException(status_code=400, detail="Invalid domain")
    # Create secure session for test mode
    create_secure_session(request, {"name": email.split("@")[0], "email": email})
    return {"status": "ok"}

# Test-only GET endpoint for easier testing
@router.get("/auth/test-login")
def test_login(request: Request):
    if not TEST_MODE:
        raise HTTPException(status_code=404, detail="Not Found")
    # Create secure session for test mode
    create_secure_session(request, {"name": "Test User", "email": "developer@cybersmithsecure.com"})
    return RedirectResponse("/report_formats.html")

# Compatibility endpoint expected by some test harnesses
@router.post("/api/auth/azure_sso")
def api_auth_azure_sso(request: Request, email: Optional[str] = Form(default=None)):
    # Reuse the same redirect behavior as /auth/login
    params = {
        "client_id": AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": AZURE_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "login_hint": email or "",
        "prompt": "login",
    }
    url = f"{AZURE_AUTH_ENDPOINT}?{urlencode(params)}"
    return RedirectResponse(url, status_code=302)

@router.get("/logout")
def logout(request: Request):
    # Properly invalidate session with security cleanup
    invalidate_session(request)
    return RedirectResponse("/login")

def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user 

# Small helper to expose the current user to the frontend (for conditional UI)
@router.get("/me")
def me(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"name": user.get("name"), "email": user.get("email")}

"""
Public CSRF endpoints
We allow CSRF token retrieval/refresh without requiring a logged-in user so that
public generators (e.g., /type3) can operate without SSO.
"""
@router.get("/csrf-token")
def get_csrf_token_endpoint(request: Request):
    """Return an existing CSRF token or create a new one if missing/expired."""
    token = get_csrf_token(request)
    if not token:
        token = refresh_csrf_token(request)
    return {"csrf_token": token}

@router.post("/csrf-refresh")
def refresh_csrf_token_endpoint(request: Request):
    """Refresh CSRF token for current session (no auth required)."""
    token = refresh_csrf_token(request)
    return {"csrf_token": token}
