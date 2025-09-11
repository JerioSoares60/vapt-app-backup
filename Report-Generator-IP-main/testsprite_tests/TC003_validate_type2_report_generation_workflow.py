import requests
from requests.exceptions import RequestException, Timeout
import io

BASE_URL = "http://localhost:8000"
TIMEOUT = 30

def validate_type2_report_generation_workflow():
    session = requests.Session()
    try:
        # Step 1: Upload Excel file to /type2/upload/
        excel_content = b"PK\x03\x04\x14\x00\x06\x00"  # Minimal valid zip header (xlsx is a zip file)
        excel_file = io.BytesIO(excel_content)
        excel_file.name = 'template.xlsx'
        files = {'file': (excel_file.name, excel_file, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
        
        resp_upload_excel = session.post(f"{BASE_URL}/type2/upload/", files=files, timeout=TIMEOUT)
        assert resp_upload_excel.status_code == 200, f"Excel upload failed with status {resp_upload_excel.status_code}"

        # Step 2: Upload screenshots to /type2/upload-screenshots/
        # Prepare two minimal PNG files in memory
        png_header = (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            b'\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xdacd\xf8\x0f'
            b'\x00\x01\x01\x01\x00\x18\xdd\xdc\xdc\x00\x00\x00\x00IEND\xaeB`\x82'
        )
        screenshot1 = io.BytesIO(png_header)
        screenshot1.name = 'screenshot1.png'
        screenshot2 = io.BytesIO(png_header)
        screenshot2.name = 'screenshot2.png'
        files = [
            ('files', (screenshot1.name, screenshot1, 'image/png')),
            ('files', (screenshot2.name, screenshot2, 'image/png'))
        ]
        
        resp_upload_screenshots = session.post(f"{BASE_URL}/type2/upload-screenshots/", files=files, timeout=TIMEOUT)
        assert resp_upload_screenshots.status_code == 200, f"Screenshots upload failed with status {resp_upload_screenshots.status_code}"

        # Step 3: Generate report at /type2/generate-report/
        payload = {
            "client_name": "Test Client",
            "client_code": "TC123",
            "project_name": "VAPT Project",
            "assessment_date": "2025-08-30",
            "report_type": "Type-2"
        }
        headers = {"Content-Type": "application/json"}
        resp_generate = session.post(f"{BASE_URL}/type2/generate-report/", json=payload, headers=headers, timeout=TIMEOUT)
        assert resp_generate.status_code == 200, f"Report generation failed with status {resp_generate.status_code}"
        json_response = resp_generate.json()
        
        # Validate JSON keys expected in a successful report generation response
        # Assuming response contains keys such as 'report_url' or 'message'
        assert ("report_url" in json_response or "message" in json_response), "Missing expected keys in report generation response"
        if "message" in json_response:
            assert "success" in json_response["message"].lower(), "Report generation message does not indicate success"
    except (RequestException, Timeout) as e:
        assert False, f"Request failed: {e}"

validate_type2_report_generation_workflow()
