# VAPT Report Automation System

This system automates the generation of Vulnerability Assessment and Penetration Testing (VAPT) reports from Excel templates.

## Overview

The VAPT Report Automation system allows you to:
1. Prepare a single Excel file containing vulnerability details with embedded screenshot references
2. Generate a professionally formatted Word document report with all vulnerabilities
3. Download the report for sharing with clients

## Setup and Installation

### Prerequisites
- Python 3.7+
- Required Python packages: fastapi, uvicorn, pandas, python-docx, docxtpl, python-multipart, openpyxl

### Installation Steps
1. Clone this repository
2. Install required packages:
   ```
   pip install fastapi uvicorn pandas python-docx docxtpl python-multipart openpyxl
   ```
3. Start the server:
   ```
   cd backend
   uvicorn main:app --reload --host 0.0.0.0 --port 8004
   ```
4. In a separate terminal, start a simple HTTP server for the frontend:
   ```
   python3 -m http.server 5178
   ```
5. Open your browser and navigate to `http://localhost:5178/test.html`

## Using the System

### Excel Template Format
Use the provided `Comprehensive_Vulnerability_Template.xlsx` as a reference. The template includes the following columns:

| Column Name | Description | Example |
|-------------|-------------|---------|
| Sr No | Unique identifier for the vulnerability | VULN-001 |
| Vulnerability Name | Name of the vulnerability | SQL Injection in Login |
| Vulnerable URL | URL/parameter where vulnerability exists | /login.php?username= |
| CVSS Score | CVSS score (0-10) | 7.5 |
| Description | Detailed description of the vulnerability | The login page is vulnerable to SQL injection... |
| Impact | Impact of the vulnerability if exploited | Attackers can bypass authentication... |
| Remediation | Steps to fix the vulnerability | Use parameterized queries instead of dynamic SQL... |
| Steps | Steps to reproduce the vulnerability (each step on a new line) | Step 1: Access login page\nStep 2: Input ' OR 1=1 --... |
| Screenshot 1 | Filename for the screenshot of step 1 | login_page.png |
| Screenshot 2 | Filename for the screenshot of step 2 | sql_payload.png |
| ... | ... | ... |
| Screenshot 15 | Filename for the screenshot of step 15 | result.png |

### Screenshot Integration
The system allows up to 15 screenshots per vulnerability. Each screenshot is mapped to a step based on its number:
- Screenshot 1 corresponds to Step 1
- Screenshot 2 corresponds to Step 2
- And so on...

You only need to specify filenames in the Excel template - no need to upload screenshots separately.

### Severity Classification
The system automatically determines severity based on CVSS score:
- Critical: 9.0-10.0
- High: 7.0-8.9
- Medium: 4.0-6.9
- Low: 0.1-3.9
- Informational: 0.0 or not specified

### Generating Reports
1. Open `http://localhost:5178/test.html` in your browser
2. Upload your Excel file with vulnerabilities and screenshot references
3. Enter the client name
4. Click "Generate Report"
5. The report will be generated and downloaded automatically

## Troubleshooting

If you encounter issues:
1. Ensure your Excel file follows the required format with all necessary columns
2. Check that the server is running on port 8004
3. Look for error messages in the browser console or server logs
4. Verify that you have the required Python packages installed

## Example Excel Files
- `Step_Screenshot_Template.xlsx`: Basic template with step-specific screenshots
- `Comprehensive_Vulnerability_Template.xlsx`: Comprehensive template with multiple vulnerability examples and screenshots 