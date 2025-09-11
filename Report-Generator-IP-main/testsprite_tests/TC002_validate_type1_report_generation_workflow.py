import requests
import os
import io

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def test_validate_type1_report_generation_workflow():
    session = requests.Session()
    headers = {}  # Add auth headers here if needed

    # Prepare test files paths
    excel_filename = "test_template.xlsx"
    screenshot_filenames = ["screenshot1.png", "screenshot2.png"]

    # Create dummy Excel file content (minimal valid Excel file content)
    # Here we use a simple binary content to simulate an Excel file
    excel_content = (
        b"PK\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00!\x00\xB7\x9D\xB4L"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00"
        b"xl/workbook.xmlPK\x01\x02\x14\x03\x14\x00\x06\x00\x08\x00\x00\x00!"
        b"\x00\xb7\x9d\xb4L\x08\x00\x00\x00\x08\x00\x00\x00\x13\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00PK\x05\x06\x00"
        b"\x00\x00\x00\x01\x00\x01\x00:\x00\x00\x00H\x00\x00\x00\x00\x00"
    )

    # Create dummy screenshot content (simple PNG header)
    screenshot_content = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
        b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xdac`\x00\x00\x00\x02\x00\x01"
        b"\xe2!\xbc\x33\x00\x00\x00\x00IEND\xaeB`\x82"
    )

    try:
        # 1. Upload Excel file
        files = {'file': (excel_filename, io.BytesIO(excel_content), 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        resp = session.post(f"{BASE_URL}/type1/upload/", files=files, headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Excel upload failed: {resp.status_code}, {resp.text}"
        assert "success" in resp.text.lower() or "uploaded" in resp.text.lower()

        # 2. Upload screenshots (multiple files)
        files = [('files', (fn, io.BytesIO(screenshot_content), 'image/png')) for fn in screenshot_filenames]
        resp = session.post(f"{BASE_URL}/type1/upload-screenshots/", files=files, headers=headers, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Screenshots upload failed: {resp.status_code}, {resp.text}"
        assert "success" in resp.text.lower() or "uploaded" in resp.text.lower()

        # 3. Generate report
        json_data = {
            "client_name": "Test Client",
            "client_code": "TC-001",
            "project_name": "Test Project",
            "assessment_date": "2025-08-30",
            "report_type": "Type-1"
        }
        resp = session.post(f"{BASE_URL}/type1/generate-report/", json=json_data, headers={**headers, "Content-Type": "application/json"}, timeout=TIMEOUT)
        assert resp.status_code == 200, f"Report generation failed: {resp.status_code}, {resp.text}"
        # Validate response content contains expected keys (could be a URL or binary report, assume JSON with report link or similar)
        if 'application/json' in resp.headers.get('Content-Type', ''):
            resp_json = resp.json()
            assert any(key in resp_json for key in ("report_url", "message", "status")), "Unexpected response JSON structure"
        else:
            # If raw content (e.g. docx), check content length > 0
            assert len(resp.content) > 0, "Empty report content"

    finally:
        # No explicit resource ID given; no deletion endpoint or resource cleanup instructed for these uploads
        # So just end test. If a cleanup endpoint existed, implement here.
        pass

test_validate_type1_report_generation_workflow()