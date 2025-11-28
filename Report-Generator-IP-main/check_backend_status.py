#!/usr/bin/env python3
"""
Diagnostic script to check backend server status and diagnose 502 errors.
Run this script to verify if the backend is running and accessible.
"""
import requests
import sys
import os

def check_backend_status(host="127.0.0.1", port=8000):
    """Check if backend server is running and accessible"""
    base_url = f"http://{host}:{port}"
    
    print(f"Checking backend server at {base_url}...")
    print("=" * 60)
    
    # Check health endpoint
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print(f"✅ Health check: OK")
            print(f"   Response: {response.json()}")
        else:
            print(f"⚠️  Health check: Status {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"❌ Health check: Connection refused - Backend server is NOT running")
        print(f"   Solution: Start the server with: uvicorn app:app --host 0.0.0.0 --port {port}")
        return False
    except requests.exceptions.Timeout:
        print(f"❌ Health check: Timeout - Server may be overloaded or not responding")
        return False
    except Exception as e:
        print(f"❌ Health check: Error - {e}")
        return False
    
    # Check login endpoint
    try:
        response = requests.get(f"{base_url}/login", timeout=5)
        if response.status_code == 200:
            print(f"✅ Login endpoint: OK (Status {response.status_code})")
        else:
            print(f"⚠️  Login endpoint: Status {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"❌ Login endpoint: Connection refused")
        return False
    except Exception as e:
        print(f"❌ Login endpoint: Error - {e}")
        return False
    
    # Check root endpoint
    try:
        response = requests.get(f"{base_url}/", timeout=5, allow_redirects=False)
        if response.status_code in [200, 302, 307]:
            print(f"✅ Root endpoint: OK (Status {response.status_code})")
        else:
            print(f"⚠️  Root endpoint: Status {response.status_code}")
    except Exception as e:
        print(f"❌ Root endpoint: Error - {e}")
    
    print("=" * 60)
    print("✅ Backend server appears to be running correctly!")
    print("\nIf you're still getting 502 errors, check:")
    print("1. Nginx configuration (proxy_pass URL)")
    print("2. Nginx error logs: tail -f /var/log/nginx/error.log")
    print("3. Backend server logs for errors")
    print("4. Firewall rules between nginx and backend")
    
    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Check backend server status")
    parser.add_argument("--host", default="127.0.0.1", help="Backend host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Backend port (default: 8000)")
    args = parser.parse_args()
    
    success = check_backend_status(args.host, args.port)
    sys.exit(0 if success else 1)

