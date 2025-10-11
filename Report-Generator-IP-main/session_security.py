"""
Session Security Module
Implements comprehensive session security including:
- Session timeout
- Session fingerprinting (IP + User-Agent)
- CSRF protection
- Session validation
"""

import os
import hashlib
import time
import secrets
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse
import json


class SessionSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for session security validation"""
    
    def __init__(self, app, session_timeout: int = 3600, csrf_timeout: int = 1800):
        super().__init__(app)
        self.session_timeout = session_timeout  # 1 hour default
        self.csrf_timeout = csrf_timeout  # 30 minutes default
        
    def _generate_session_fingerprint(self, request: Request) -> str:
        """Generate a unique fingerprint based on IP and User-Agent"""
        ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        fingerprint_data = f"{ip}:{user_agent}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    
    def _is_session_valid(self, session_data: Dict[str, Any], fingerprint: str, request: Request) -> bool:
        """Check if session is valid and not expired"""
        if not session_data:
            return False
            
        # Check if session has user data
        if "user" not in session_data:
            return False
            
        # Check session timeout
        session_time = session_data.get("session_time", 0)
        if time.time() - session_time > self.session_timeout:
            return False
            
        # Check session fingerprint
        stored_fingerprint = session_data.get("fingerprint")
        if stored_fingerprint != fingerprint:
            return False
            
        return True
    
    def _generate_csrf_token(self) -> str:
        """Generate a CSRF token"""
        return secrets.token_urlsafe(32)
    
    def _is_csrf_token_valid(self, session_data: Dict[str, Any], token: str) -> bool:
        """Check if CSRF token is valid and not expired"""
        if not session_data or not token:
            return False
            
        stored_token = session_data.get("csrf_token")
        token_time = session_data.get("csrf_time", 0)
        
        if not stored_token or stored_token != token:
            return False
            
        # Check CSRF token timeout
        if time.time() - token_time > self.csrf_timeout:
            return False
            
        return True
    
    async def dispatch(self, request: Request, call_next):
        """Process request and validate session security"""
        path = request.url.path
        
        # Skip security checks for login, callback, logout, and static files
        skip_paths = ["/login", "/auth/", "/logout", "/health", "/static/", "/favicon.ico"]
        if any(path.startswith(skip) for skip in skip_paths):
            response = await call_next(request)
            return response
        
        # Get current session
        session_data = request.session
        
        # Generate current fingerprint
        current_fingerprint = self._generate_session_fingerprint(request)
        
        # Check if session is valid
        if not self._is_session_valid(session_data, current_fingerprint, request):
            # Clear invalid session
            request.session.clear()
            
            # For API endpoints, return 401
            if path.startswith("/api/") or path.startswith("/type1/") or path.startswith("/type2/"):
                return Response("Unauthorized - Session expired or invalid", status_code=401)
            
            # For web pages, redirect to login
            return RedirectResponse("/login", status_code=302)
        
        # For POST requests, validate CSRF token
        if request.method == "POST" and not path.startswith("/auth/"):
            csrf_token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
            if not self._is_csrf_token_valid(session_data, csrf_token):
                return Response("CSRF token invalid or expired", status_code=403)
        
        # Update session timestamp on each request
        session_data["last_activity"] = time.time()
        
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        return response


def create_secure_session(request: Request, user_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new secure session with fingerprint and CSRF token"""
    fingerprint = SessionSecurityMiddleware(None)._generate_session_fingerprint(request)
    csrf_token = SessionSecurityMiddleware(None)._generate_csrf_token()
    
    session_data = {
        "user": user_data,
        "session_time": time.time(),
        "last_activity": time.time(),
        "fingerprint": fingerprint,
        "csrf_token": csrf_token,
        "csrf_time": time.time()
    }
    
    request.session.update(session_data)
    return session_data


def get_csrf_token(request: Request) -> Optional[str]:
    """Get current CSRF token from session"""
    session_data = request.session
    if not session_data or not session_data.get("user"):
        return None
    return session_data.get("csrf_token")


def validate_csrf_token(request: Request, token: str) -> bool:
    """Validate CSRF token"""
    session_data = request.session
    if not session_data:
        return False
    return SessionSecurityMiddleware(None)._is_csrf_token_valid(session_data, token)


def invalidate_session(request: Request):
    """Invalidate current session"""
    request.session.clear()


def refresh_csrf_token(request: Request) -> str:
    """Refresh CSRF token and return new token"""
    csrf_token = SessionSecurityMiddleware(None)._generate_csrf_token()
    request.session["csrf_token"] = csrf_token
    request.session["csrf_time"] = time.time()
    return csrf_token
