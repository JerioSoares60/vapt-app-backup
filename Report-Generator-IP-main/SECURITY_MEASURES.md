# Security Measures Implementation

## Overview
This document outlines the comprehensive security measures implemented in the VAPT Report Generator application to prevent session hijacking, unauthorized access, and protect confidential data.

## Implemented Security Features

### 1. Session Security Middleware
- **Location**: `session_security.py`
- **Purpose**: Validates sessions and prevents hijacking
- **Features**:
  - Session timeout (1 hour default)
  - Session fingerprinting based on IP + User-Agent
  - Automatic session invalidation on timeout or fingerprint mismatch
  - CSRF token validation for POST requests

### 2. Session Fingerprinting
- **Method**: SHA256 hash of IP address + User-Agent
- **Purpose**: Ensures sessions are tied to specific browser/device combinations
- **Behavior**: 
  - If user changes browser, IP, or User-Agent, session is invalidated
  - Forces re-authentication when accessing from different devices/browsers

### 3. CSRF Protection
- **Location**: `static/js/csrf.js`
- **Purpose**: Prevents Cross-Site Request Forgery attacks
- **Features**:
  - Automatic token generation and refresh
  - Token validation on all POST requests
  - 30-minute token timeout
  - Auto-injection into forms and AJAX requests

### 4. Session Timeout Management
- **Location**: `static/js/session-timeout.js`
- **Purpose**: Provides user-friendly session timeout warnings
- **Features**:
  - 5-minute warning before session expires
  - Visual countdown timer
  - "Stay Logged In" option to extend session
  - Automatic logout on timeout

### 5. Security Headers
- **Implementation**: Added to all responses via middleware
- **Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Referrer-Policy: strict-origin-when-cross-origin`

### 6. Path Traversal Protection
- **Location**: `app.py` middleware
- **Purpose**: Prevents directory traversal attacks
- **Blocks**: `..`, `\\`, `%5c`, `%2e%2e`, `<`, `>`, `//`, `\\\\`

## Security Behavior

### When User Opens Application in Different Browser/Tab:
1. **Session Fingerprint Check**: New browser has different User-Agent
2. **Session Invalidation**: Current session is marked as invalid
3. **Redirect to Login**: User is automatically redirected to login page
4. **Re-authentication Required**: User must go through full Azure SSO process

### Session Lifecycle:
1. **Login**: Secure session created with fingerprint and CSRF token
2. **Activity Tracking**: User activity resets timeout timer
3. **Warning**: 5 minutes before timeout, warning modal appears
4. **Timeout**: After 1 hour of inactivity, session expires
5. **Logout**: Session completely cleared and invalidated

### CSRF Protection Flow:
1. **Token Generation**: Unique token generated on login
2. **Form Injection**: Tokens automatically added to all forms
3. **Request Validation**: All POST requests validated against token
4. **Token Refresh**: Tokens refreshed every 30 minutes or on request

## Configuration

### Environment Variables:
```bash
# Session security
SESSION_SECRET_KEY=your-secret-key-here
SESSION_TIMEOUT=3600  # 1 hour in seconds
CSRF_TIMEOUT=1800     # 30 minutes in seconds

# Test mode (disables some security for development)
TEST_MODE=false
```

### Session Timeout Settings:
- **Session Timeout**: 1 hour (3600 seconds)
- **CSRF Token Timeout**: 30 minutes (1800 seconds)
- **Warning Time**: 5 minutes before session expires

## Testing Security

### Test Mode:
- **Endpoint**: `/auth/test-login` (only available when `TEST_MODE=true`)
- **Purpose**: Bypass Azure SSO for development/testing
- **Security**: Still enforces session fingerprinting and timeouts

### Security Validation:
1. **Different Browser Test**: Open app in different browser → Should redirect to login
2. **Different Tab Test**: Open in private/incognito → Should redirect to login
3. **Session Timeout Test**: Wait 1 hour → Should show warning then logout
4. **CSRF Test**: Submit form without token → Should be rejected

## Production Considerations

### HTTPS Requirements:
- **Azure SSO**: Requires HTTPS in production
- **Session Cookies**: Should use `https_only=True` in production
- **Security Headers**: HSTS header included for HTTPS enforcement

### Session Storage:
- **Current**: Server-side session storage
- **Future**: Consider Redis for distributed sessions
- **Encryption**: Sessions encrypted with secret key

## Monitoring and Logging

### Audit Logging:
- **Login Events**: Track successful and failed logins
- **Session Events**: Track session creation and invalidation
- **Security Events**: Track CSRF violations and suspicious activity

### Database Tables:
- `audit_logs`: User actions and security events
- `dashboard_datasets`: User uploads and report generations

## Security Best Practices Implemented

1. **Defense in Depth**: Multiple layers of security
2. **Principle of Least Privilege**: Users only access what they need
3. **Session Management**: Proper session lifecycle management
4. **Input Validation**: Path traversal and XSS protection
5. **Secure Headers**: Comprehensive security headers
6. **CSRF Protection**: Token-based CSRF prevention
7. **Session Fingerprinting**: Device/browser binding
8. **Automatic Timeout**: Prevents long-lived sessions
9. **Secure Logout**: Complete session cleanup
10. **Audit Trail**: Security event logging

## Troubleshooting

### Common Issues:

1. **Session Expired Errors**:
   - Check if user changed browser/device
   - Verify session timeout settings
   - Check for proxy/CDN changes

2. **CSRF Token Errors**:
   - Ensure CSRF script is loaded
   - Check token refresh mechanism
   - Verify form submission includes token

3. **Azure SSO Issues**:
   - Verify HTTPS configuration
   - Check redirect URI settings
   - Validate client credentials

### Debug Mode:
Set `TEST_MODE=true` to enable:
- Test login endpoint
- Detailed error logging
- Bypass some security checks for development
