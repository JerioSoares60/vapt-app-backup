# Quick Fix for 502 Bad Gateway Error

## Immediate Steps to Fix 502 Error

### Step 1: Check if Backend Server is Running
```bash
# On Linux/Mac
ps aux | grep uvicorn

# On Windows
tasklist | findstr uvicorn
```

If not running, start it:
```bash
# Linux/Mac
cd Report-Generator-IP-main
./start_backend.sh

# Windows
cd Report-Generator-IP-main
start_backend.bat

# Or manually
uvicorn app:app --host 0.0.0.0 --port 8000
```

### Step 2: Test Backend Directly
```bash
# Test health endpoint
curl http://127.0.0.1:8000/health

# Test login endpoint
curl http://127.0.0.1:8000/login
```

If these work, the backend is fine. The issue is with nginx.

### Step 3: Check Nginx Configuration
Edit nginx config (usually `/etc/nginx/sites-available/default` or `/etc/nginx/nginx.conf`):

```nginx
server {
    listen 80;
    server_name 13.202.112.84;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Important: Increase timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Step 4: Restart Nginx
```bash
sudo systemctl restart nginx
# Or
sudo service nginx restart

# Check nginx status
sudo systemctl status nginx
```

### Step 5: Check Nginx Error Logs
```bash
sudo tail -f /var/log/nginx/error.log
```

Look for errors like:
- `connect() failed (111: Connection refused)`
- `upstream timed out`
- `upstream prematurely closed connection`

## Common Issues and Fixes

### Issue: "Connection refused"
**Cause:** Backend server not running
**Fix:** Start backend server (see Step 1)

### Issue: "Upstream timed out"
**Cause:** Backend taking too long to respond
**Fix:** Increase timeout in nginx config

### Issue: "502 Bad Gateway" but backend works
**Cause:** Nginx can't reach backend or wrong port
**Fix:** 
1. Check `proxy_pass` URL matches backend port
2. Check firewall allows localhost connections
3. Verify backend is binding to `0.0.0.0` not `127.0.0.1`

## Security Fix Applied

✅ **Moved `temp_auth_check.py` to safe location:**
- Old location: `temp_auth_check.py` (root directory - UNSAFE)
- New location: `Report-Generator-IP-main/Automation/backend/auth_utils.py` (SAFE)

This file is now protected inside the project structure and not accessible from the web root.

## Verification

After applying fixes, verify:

1. Backend is running: `curl http://127.0.0.1:8000/health`
2. Login page accessible: `curl http://127.0.0.1:8000/login`
3. Through nginx: `curl http://13.202.112.84/login` (should return HTML, not 502)

## Diagnostic Script

Use the provided diagnostic script:
```bash
python3 check_backend_status.py
# Or with custom host/port
python3 check_backend_status.py --host 127.0.0.1 --port 8000
```

This will check:
- Backend server connectivity
- Health endpoint
- Login endpoint
- Root endpoint

