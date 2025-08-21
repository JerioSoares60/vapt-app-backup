
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

router = APIRouter()

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
if not os.path.exists(TEMPLATES_DIR):
    os.makedirs(TEMPLATES_DIR)

templates = Jinja2Templates(directory=TEMPLATES_DIR)

AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
# For EC2 deployment, use the environment variable or default to localhost
AZURE_REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI", "http://localhost:8000/auth/callback")
print(f"DEBUG: AZURE_REDIRECT_URI = {AZURE_REDIRECT_URI}")
AZURE_AUTHORITY = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}"
AZURE_AUTH_ENDPOINT = f"{AZURE_AUTHORITY}/oauth2/v2.0/authorize"
AZURE_TOKEN_ENDPOINT = f"{AZURE_AUTHORITY}/oauth2/v2.0/token"
AZURE_JWKS_URI = f"{AZURE_AUTHORITY}/discovery/v2.0/keys"

ALLOWED_EMAIL_DOMAIN = os.getenv("ALLOWED_EMAIL_DOMAIN", "cybersmithsecure.com")

class EmailForm(BaseModel):
    email: EmailStr

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/auth/login")
async def auth_login(request: Request, email: str = Form(...)):
    try:
        EmailForm(email=email)
    except ValidationError:
        raise HTTPException(status_code=400, detail="Invalid email address")
    if not email:
        raise HTTPException(status_code=400, detail="Email required")
    params = {
        "client_id": AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": AZURE_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "login_hint": email,
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
    request.session["user"] = user_payload
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

@router.get("/logout")
def logout(request: Request):
    request.session.clear()
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
