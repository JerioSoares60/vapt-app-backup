# MitKat Report Generator - Setup and Configuration Guide

## Overview
This guide explains how to set up and use the MitKat Report Generator, which creates VAPT reports based on the MitKat template format.

## Prerequisites
1. Python 3.8+ with required packages:
   - `fastapi`
   - `python-docx`
   - `docxtpl`
   - `pandas`
   - `openpyxl`
   - `matplotlib`
   - `numpy`

2. Template file: `MitKat_Template.docx` must be placed in the `backend` directory

## Template Structure

The MitKat template should have the following structure:

### Page 1: Front Page
- Client Name placeholder: `{{ CLIENT_NAME }}`
- Report Title placeholder: `{{ REPORT_TITLE }}`
- Report To placeholder: `{{ REPORT_TO }}`

### Page 2: Document Control
- Report Release Date: `{{ REPORT_RELEASE_DATE }}`
- Type of Audit: `{{ TYPE_OF_AUDIT }}`
- Type of Audit Report: `{{ TYPE_OF_AUDIT_REPORT }}`
- Period: `{{ PERIOD }}`
- Document Title: `{{ DOCUMENT_TITLE }}`
- Document ID: `{{ DOCUMENT_ID }}`
- Document Version: `{{ DOCUMENT_VERSION }}`
- Prepared by: `{{ PREPARED_BY }}`
- Reviewed by: `{{ REVIEWED_BY }}`
- Approved by: `{{ APPROVED_BY }}`
- Released by: `{{ RELEASED_BY }}`
- Release Date: `{{ RELEASE_DATE }}`
- Introduction: `{{ INTRODUCTION }}`

### Pages 3-8: Executive Summary
- Overall Findings table (auto-generated)
- Vulnerability charts (auto-generated)

### Pages 9+: Observations
- Detailed vulnerability tables (auto-generated)

## Excel File Format

### Required Columns

| Column Name | Description | Example |
|------------|-------------|---------|
| `Sr No` | Serial number | 1, 2, 3 |
| `Observation/Vulnerability Title` | Name of the vulnerability | "SQL Injection" |
| `Affected Asset` | IP/URL/Application | "https://example.com" |
| `CVE/CWE` | CVE or CWE identifier | "CWE-89" |
| `Severity` | Critical, High, Medium, Low, Informational | "High" |
| `Detailed Observation` | Detailed description | "The application..." |
| `Recommendation` | Remediation steps | "Implement parameterized queries..." |
| `Reference` | External references | "https://owasp.org/..." |
| `Steps` | Proof of concept steps | "Step 1: Navigate to...\nStep 2: Enter payload..." |
| `Revalidation Status` | **NEW** - Status of revalidation | "This vulnerability is justified and patched" |
| `Screenshot` | **NEW** - Screenshot filename | "vuln1_screenshot.png" |

### Excel Example

```
Sr No | Observation/Vulnerability Title | Affected Asset | CVE/CWE | Severity | Detailed Observation | Recommendation | Reference | Steps | Revalidation Status | Screenshot
------|--------------------------------|----------------|---------|----------|---------------------|----------------|-----------|-------|---------------------|------------
1     | SQL Injection                  | https://...    | CWE-89  | High     | The application...  | Implement...   | https://  | Step 1: Navigate... | Patched     | vuln1.png
```

## POC ZIP File Structure

### Recommended Structure

```
POC.zip
├── VUL-001/
│   ├── step1.png
│   ├── step2.png
│   └── step3.png
├── VUL-002/
│   ├── step1.png
│   └── step2.png
└── VUL-003/
    └── step1.png
```

### Alternative Structure

```
POC.zip
├── #1/
│   ├── step1.png
│   └── step2.png
├── #2/
│   └── step1.png
└── #3/
    └── step1.png
```

### Naming Convention
- Folder names: `VUL-XXX` or `#X` where XXX/X corresponds to the `Sr No` in Excel
- Image names: `step1.png`, `step2.png`, etc. (case-insensitive)
- Supported formats: `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`

## API Endpoints

### 1. Form Interface
- **URL**: `/mitkat/`
- **Method**: GET
- **Description**: Serves the HTML form for report generation

### 2. Generate Report
- **URL**: `/mitkat/generate-report/`
- **Method**: POST
- **Parameters**:
  - `vulnerability_file` (File): Excel file with vulnerability data
  - `poc_zip` (File, optional): ZIP file with POC screenshots
  - `front_page_data` (Form): JSON string with front page data
  - `doc_control_data` (Form): JSON string with document control data

## Front Page Data Format

```json
{
  "client_name": "Client Name",
  "report_title": "PIPELINE MODULE VAPT FINAL REPORT",
  "report_to": "RECEIVABLES EXCHANGE OF INDIA LIMITED (RXIL)"
}
```

## Document Control Data Format

```json
{
  "report_release_date": "2025-07-21",
  "type_of_audit": "WebApplication Vulnerability Assessment & Penetration Testing",
  "type_of_audit_report": "FinalReport",
  "period": "07-07-2025 to 18-07-2025",
  "document_title": "Webapplication VAPT - Final Report",
  "document_id": "MAS-RXIL/WB/Q4/2025",
  "document_version": "1.0",
  "prepared_by": "Biswajeet Ray",
  "reviewed_by": "Prashant Mehta",
  "approved_by": "Prashant Mehta",
  "released_by": "Biswajeet Ray",
  "release_date": "2025-07-21",
  "introduction": "With a view to safeguard critical information...",
  "document_change_history": [],
  "distribution_list": [],
  "engagement_scope": [],
  "auditing_team": [],
  "tools_software": []
}
```

## Tables Generated

### Overall Findings Table (Page 3+)
Columns:
- Sr. No.
- Affected Asset
- Observation/Vulnerability Title
- CWE/CWE
- Severity
- New or Repeat Observation

### Detailed Observations Tables (Pages 9, 10, 11+)
Each vulnerability gets its own table with:
- Sr. No., Observation/Vulnerability Title, Affected Asset
- CVE/CWE, Severity, New or Repeat Observation
- Detailed Observation/Vulnerable Point
- Recommendation
- Reference (if provided)
- References to evidence/Proof of Concept (with screenshots)
- Revalidation Status (if provided)

## Configuration Variables

### Template Path
Located in `generate_mitkat_report_endpoint()`:
```python
template_path = os.path.join(get_script_dir(), "MitKat_Template.docx")
```

### Upload Directory
```python
UPLOAD_DIR = "uploads"
```

### Severity Colors
Defined in `get_severity_colors()`:
- Critical: `#990000`
- High: `#FF0000`
- Medium: `#FFCC00`
- Low: `#00b050`
- Informational: `#0070c0`

## Usage Steps

1. **Prepare Excel File**
   - Fill in all required columns
   - Add Revalidation Status and Screenshot columns if needed
   - Save as `.xlsx` format

2. **Prepare POC ZIP** (Optional)
   - Create folders named `VUL-001`, `VUL-002`, etc. (or `#1`, `#2`, etc.)
   - Place screenshots in respective folders
   - Name images as `step1.png`, `step2.png`, etc.
   - Zip the folder structure

3. **Access Form**
   - Navigate to `/mitkat/` in your browser
   - Fill in front page data
   - Fill in document control data
   - Upload Excel file
   - Upload POC ZIP (if available)

4. **Generate Report**
   - Click "Generate MitKat Report"
   - Wait for processing
   - Download the generated report

## Troubleshooting

### Template Not Found
- Ensure `MitKat_Template.docx` is in the `backend` directory
- Check file permissions

### Excel Parsing Errors
- Verify column names match exactly (case-insensitive)
- Check for empty rows
- Ensure data types are correct

### POC Images Not Appearing
- Verify ZIP structure matches expected format
- Check folder naming (VUL-001 or #1)
- Ensure image filenames contain step numbers
- Verify image file formats are supported

### Missing Data in Report
- Check that all required form fields are filled
- Verify Excel columns are properly named
- Ensure template placeholders match variable names

## Notes

- The system automatically maps Excel columns (case-insensitive)
- POC images are matched by vulnerability number (Sr No)
- Screenshots are embedded in the report at appropriate step locations
- Revalidation Status is displayed in green if provided
- All tables are auto-formatted with proper styling and colors

