import requests

BASE_URL = "http://localhost:8000"
TIMEOUT = 30
HEADERS = {
    "Accept": "*/*"
}

def test_static_file_serving_endpoints():
    # Test static file serving
    static_file = "dashboard.html"  # Changed to a likely existing static file from PRD
    static_url = f"{BASE_URL}/static/{static_file}"
    try:
        static_resp = requests.get(static_url, headers=HEADERS, timeout=TIMEOUT)
        assert static_resp.status_code == 200, f"Static file {static_file} not served correctly"
        assert static_resp.content, "Static file response content is empty"
    except requests.RequestException as e:
        assert False, f"Request to static file endpoint failed: {e}"

    # Test automation file serving
    automation_file = "test.html"  # From PRD files, Automation/test.html should exist
    automation_url = f"{BASE_URL}/Automation/{automation_file}"
    try:
        automation_resp = requests.get(automation_url, headers=HEADERS, timeout=TIMEOUT)
        assert automation_resp.status_code == 200, f"Automation file {automation_file} not served correctly"
        assert automation_resp.content, "Automation file response content is empty"
    except requests.RequestException as e:
        assert False, f"Request to automation file endpoint failed: {e}"

    # Test report_formats.html page loads successfully
    report_formats_url = f"{BASE_URL}/report_formats.html"
    try:
        report_formats_resp = requests.get(report_formats_url, headers=HEADERS, timeout=TIMEOUT)
        assert report_formats_resp.status_code == 200, "Report formats page did not load successfully"
        # Check if content-type is HTML
        content_type = report_formats_resp.headers.get("Content-Type", "")
        assert "text/html" in content_type, f"Unexpected content-type for report_formats.html: {content_type}"
        assert report_formats_resp.text.strip(), "Report formats page content is empty"
    except requests.RequestException as e:
        assert False, f"Request to report_formats.html failed: {e}"

test_static_file_serving_endpoints()