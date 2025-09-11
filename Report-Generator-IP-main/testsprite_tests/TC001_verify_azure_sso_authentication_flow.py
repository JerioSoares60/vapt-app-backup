import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_verify_azure_sso_authentication_flow():
    session = requests.Session()
    try:
        # Step 1: Access login page to get any cookies (if needed)
        login_page_resp = session.get(f"{BASE_URL}/login", timeout=TIMEOUT)
        assert login_page_resp.status_code == 200
        assert "text/html" in login_page_resp.headers.get("Content-Type", "")

        # Step 2: Initiate Azure SSO login (POST to /auth/login) - expect 302 redirect
        initiate_login_resp = session.post(f"{BASE_URL}/auth/login", allow_redirects=False, timeout=TIMEOUT)
        assert initiate_login_resp.status_code == 302
        assert "Location" in initiate_login_resp.headers
        redirect_url = initiate_login_resp.headers["Location"]
        # The redirect location should be to an Azure SSO login URL containing 'login.microsoftonline.com' or 'azure'
        assert redirect_url.startswith("https://") and ("login.microsoftonline.com" in redirect_url.lower() or "azure" in redirect_url.lower())

        # Step 3: Simulate callback from Azure after user authentication
        callback_resp = session.get(f"{BASE_URL}/auth/callback", allow_redirects=False, timeout=TIMEOUT)
        assert callback_resp.status_code == 302
        assert "Location" in callback_resp.headers
        post_auth_redirect = callback_resp.headers["Location"]
        assert post_auth_redirect.startswith("/") or post_auth_redirect.startswith("http")

        # Step 4: After callback, access /me to confirm authenticated user and role info
        me_resp = session.get(f"{BASE_URL}/me", timeout=TIMEOUT)
        assert me_resp.status_code == 200
        me_json = me_resp.json()
        # Validate expected keys in user info by checking it's a dict with some string keys
        assert isinstance(me_json, dict)
        assert any(isinstance(v, str) for v in me_json.values())

    except (requests.RequestException, AssertionError) as e:
        raise AssertionError(f"Azure SSO Authentication flow test failed: {e}")

test_verify_azure_sso_authentication_flow()
