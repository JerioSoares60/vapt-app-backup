import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_health_check_endpoint_functionality():
    url = f"{BASE_URL}/health"
    headers = {
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as e:
        assert False, f"Request to health endpoint failed: {e}"

    # Validate status code
    assert response.status_code == 200, f"Expected status code 200, got {response.status_code}"

    # Validate response content type
    content_type = response.headers.get("Content-Type", "")
    assert "application/json" in content_type, f"Expected JSON response, got {content_type}"

    # Validate response JSON schema and values
    json_data = response.json()
    expected_keys = {"status", "service", "database"}
    actual_keys = set(json_data.keys())
    assert expected_keys == actual_keys, f"Response keys mismatch. Expected {expected_keys}, got {actual_keys}"

    # Validate that status, service and database are non-empty strings
    for key in expected_keys:
        value = json_data.get(key)
        assert isinstance(value, str) and len(value) > 0, f"Key '{key}' should be a non-empty string"

test_health_check_endpoint_functionality()