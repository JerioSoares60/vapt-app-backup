import requests
from requests.exceptions import RequestException
import io
import json

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

# Placeholder credentials or token for authorized access
# In real scenario, this should be replaced with actual auth flow and token retrieval
AUTH_TOKEN = None

def get_auth_token():
    """
    Simulate retrieval of an auth token or session cookie after Azure SSO login.
    This function is a stub and should be adapted to the real auth mechanism.
    For testing purposes, we assume authorization is done via a session cookie or bearer token.
    """
    # For illustration, attempt to login and get a session cookie or token from /login or /auth/login
    # Since the real auth flow involves redirects to Azure SSO, here we simulate a successful login with a dummy token.
    # Replace with actual login code if available.
    # Return session headers for authenticated requests.
    return {"Authorization": "Bearer dummy-authtoken"}

def dashboard_access_and_data_handling():
    headers = {}
    global AUTH_TOKEN
    # Get auth token/headers for authorized requests
    AUTH_TOKEN = get_auth_token()
    if AUTH_TOKEN:
        headers.update(AUTH_TOKEN)

    # 1. Access dashboard and verify access control
    try:
        # Unauthorized access check (without auth headers)
        resp = requests.get(f"{BASE_URL}/dashboard", timeout=TIMEOUT, allow_redirects=False)
        # Should redirect to login (302) for unauthorized or return 200 if public
        assert resp.status_code in (200, 302), f"Unauthorized access to /dashboard did not redirect or return 200, got {resp.status_code}"

        # Authorized access check (with auth headers)
        resp = requests.get(f"{BASE_URL}/dashboard", headers=headers, timeout=TIMEOUT, allow_redirects=False)
        assert resp.status_code == 200, f"Authorized access to /dashboard failed with status {resp.status_code}"
        assert "text/html" in resp.headers.get("Content-Type", ""), "Dashboard response content type not HTML"

        # 2. Upload a dashboard dataset
        # Create a dummy file in-memory
        dummy_csv_content = "column1,column2\nvalue1,value2\n"
        file_bytes = io.BytesIO(dummy_csv_content.encode("utf-8"))
        files = {"file": ("test_dataset.csv", file_bytes, "text/csv")}
        data = {
            "title": "Test Dataset",
            "project_name": "Test Project"
        }
        resp = requests.post(f"{BASE_URL}/type1/dashboard/upload", headers=headers, files=files, data=data, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Dataset upload failed with status {resp.status_code}"
        resp_json = resp.json() if resp.headers.get("Content-Type","").startswith("application/json") else {}
        # The API doc does not specify response body; just check for success status

        # 3. List dashboard datasets and find the uploaded dataset
        resp = requests.get(f"{BASE_URL}/type1/dashboard-datasets", headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Dashboard datasets listing failed with status {resp.status_code}"
        datasets = resp.json()
        assert isinstance(datasets, list), "Dashboard datasets response is not a list"
        # Try to find the dataset named "Test Dataset"
        dataset_id = None
        for ds in datasets:
            if isinstance(ds, dict) and ds.get("title") == "Test Dataset" and ds.get("project_name") == "Test Project":
                dataset_id = ds.get("id") or ds.get("dataset_id") or ds.get("datasetId")
                break
        assert dataset_id is not None, "Uploaded dataset not found in datasets list"

        # 4. Download the uploaded dataset file
        resp = requests.get(f"{BASE_URL}/type1/dashboard-datasets/{dataset_id}/file", headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Failed to download dataset {dataset_id}, status {resp.status_code}"
        content_disp = resp.headers.get("Content-Disposition", "")
        assert "attachment" in content_disp or resp.headers.get("Content-Type") == "text/csv", "Downloaded dataset does not seem to be a file"
        file_content = resp.content
        assert len(file_content) > 0, "Downloaded dataset file is empty"

        # 5. Retrieve project history
        resp = requests.get(f"{BASE_URL}/type1/project-history", headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Project history retrieval failed with status {resp.status_code}"
        project_history = resp.json()
        assert isinstance(project_history, (list, dict)), "Project history response format unexpected"

        # 6. Update project history
        update_data = {
            "project_data": {
                "project_name": "Test Project",
                "update_note": "Automated test update"
            }
        }
        resp = requests.post(f"{BASE_URL}/type1/project-history/update", headers={**headers, "Content-Type": "application/json"},
                             data=json.dumps(update_data), timeout=TIMEOUT)
        assert resp.status_code == 200, f"Project history update failed with status {resp.status_code}"

        # 7. Retrieve audit logs
        resp = requests.get(f"{BASE_URL}/type1/audit-logs", headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Audit logs retrieval failed with status {resp.status_code}"
        audit_logs = resp.json()
        assert isinstance(audit_logs, (list, dict)), "Audit logs response format unexpected"

    except RequestException as e:
        assert False, f"HTTP Request failed: {e}"


dashboard_access_and_data_handling()
