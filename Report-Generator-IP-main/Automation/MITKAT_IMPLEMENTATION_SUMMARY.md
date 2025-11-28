# MitKat Report Generator - Implementation Summary

## ✅ What Has Been Implemented

### 1. New Report Generator Functions
- `parse_mitkat_vulnerabilities_excel()` - Parses Excel with Revalidation Status and Screenshot columns
- `index_mitkat_poc_images()` - Indexes POC images from ZIP file
- `create_mitkat_observations_table()` - Creates detailed vulnerability tables for pages 9, 10, 11+
- `generate_mitkat_report()` - Main report generation function
- `insert_mitkat_overall_findings()` - Inserts overall findings table and charts

### 2. API Endpoints
- `GET /mitkat/` - HTML form interface
- `POST /mitkat/generate-report/` - Report generation endpoint

### 3. Excel Format Support
The parser now supports:
- **Standard columns**: Sr No, Observation, Affected Asset, CVE/CWE, Severity, Detailed Observation, Recommendation, Reference, Steps
- **NEW columns**: Revalidation Status, Screenshot

### 4. POC ZIP Structure
Supports two folder naming conventions:
- `VUL-001/`, `VUL-002/`, etc. (recommended)
- `#1/`, `#2/`, etc. (alternative)

Image naming: `step1.png`, `step2.png`, etc.

### 5. HTML Form
Complete form interface with:
- Front page data input (Client Name, Report Title, Report To)
- Document control data input (all metadata fields)
- File upload for Excel and POC ZIP
- Progress tracking and result display

## 📋 Configuration Required

### 1. Template File
Place `MitKat_Template.docx` in the `backend` directory with these placeholders:

**Front Page:**
- `{{ CLIENT_NAME }}`
- `{{ REPORT_TITLE }}`
- `{{ REPORT_TO }}`

**Document Control:**
- `{{ REPORT_RELEASE_DATE }}`
- `{{ TYPE_OF_AUDIT }}`
- `{{ TYPE_OF_AUDIT_REPORT }}`
- `{{ PERIOD }}`
- `{{ DOCUMENT_TITLE }}`
- `{{ DOCUMENT_ID }}`
- `{{ DOCUMENT_VERSION }}`
- `{{ PREPARED_BY }}`
- `{{ REVIEWED_BY }}`
- `{{ APPROVED_BY }}`
- `{{ RELEASED_BY }}`
- `{{ RELEASE_DATE }}`
- `{{ INTRODUCTION }}`

### 2. Excel Column Names (Case-Insensitive)
The parser will find these columns automatically:
- `Sr No` / `Sr.No` / `Serial No`
- `Observation` / `Vulnerability Title` / `Title`
- `Affected Asset` / `IP` / `URL` / `Application`
- `CVE/CWE` / `CVE` / `CWE`
- `Severity` / `Risk`
- `Detailed Observation` / `Description` / `Details`
- `Recommendation` / `Remediation`
- `Reference` / `References`
- `Steps` / `Evidence` / `PoC`
- `Revalidation Status` (NEW)
- `Screenshot` (NEW)

### 3. POC ZIP Path Structure
**Recommended:**
```
POC.zip
└── VUL-001/
    ├── step1.png
    ├── step2.png
    └── step3.png
```

**Alternative:**
```
POC.zip
└── #1/
    ├── step1.png
    └── step2.png
```

## 🎯 Variables for Tables (Pages 9, 10, 11+)

The `create_mitkat_observations_table()` function creates tables with:

### Table Structure:
1. **Header Row (2 columns):**
   - Left: Sr No, Observation/Vulnerability Title, Affected Asset
   - Right: CVE/CWE, Severity (color-coded), New or Repeat Observation

2. **Content Rows:**
   - Detailed Observation/Vulnerable Point
   - Recommendation
   - Reference (if provided)
   - References to evidence/Proof of Concept (with embedded screenshots)
   - Revalidation Status (if provided, displayed in green)

### Key Variables Used:
- `vuln.get('sr_no')` - Serial number
- `vuln.get('observation')` - Vulnerability title
- `vuln.get('affected_asset')` - IP/URL/Application
- `vuln.get('cve_cwe')` - CVE/CWE identifier
- `vuln.get('severity')` - Severity level (for color coding)
- `vuln.get('detailed_observation')` - Detailed description
- `vuln.get('recommendation')` - Remediation steps
- `vuln.get('reference')` - External references
- `vuln.get('steps_with_screenshots')` - Array of step objects with text and screenshot
- `vuln.get('revalidation_status')` - Revalidation status text
- `vuln.get('screenshot')` - Screenshot filename
- `vuln.get('new_or_repeat')` - New or Repeat Observation status

## 📁 File Locations

- **Backend code**: `Report-Generator-IP-main/Automation/backend/main.py`
- **HTML form**: Served via `/mitkat/` endpoint
- **Template**: `Report-Generator-IP-main/Automation/backend/MitKat_Template.docx` (you need to create this)
- **Upload directory**: `uploads/`
- **Documentation**: `Report-Generator-IP-main/Automation/MITKAT_SETUP_GUIDE.md`

## 🚀 Usage Flow

1. User navigates to `/mitkat/`
2. Fills in front page data (Client Name, Report Title, Report To)
3. Fills in document control data (all metadata)
4. Uploads Excel file with vulnerabilities
5. Uploads POC ZIP file (optional)
6. Clicks "Generate MitKat Report"
7. System:
   - Parses Excel file
   - Extracts Revalidation Status and Screenshot columns
   - Indexes POC images from ZIP
   - Generates report with template
   - Inserts overall findings table and charts
   - Creates detailed observations tables for each vulnerability
   - Embeds screenshots in appropriate steps
   - Returns downloadable Word document

## 🔧 Customization Points

### Severity Colors
Edit `get_severity_colors()` function to change color scheme:
```python
colors = {
    "Critical": {"row1_bg": "#990000", "row2_bg": "#FF3333", "font": "#990000"},
    "High": {"row1_bg": "#FF0000", "row2_bg": "#FF6666", "font": "#FF0000"},
    # ... etc
}
```

### Table Formatting
Edit `create_mitkat_observations_table()` to modify:
- Column widths
- Font sizes
- Cell alignment
- Row structure

### POC Image Sizing
Edit image width in `create_mitkat_observations_table()`:
```python
img_run.add_picture(screenshot_path, width=Inches(5))  # Change 5 to desired width
```

## 📝 Notes

- All Excel column matching is case-insensitive
- POC images are matched by vulnerability number (Sr No from Excel)
- Screenshots are embedded inline with step descriptions
- Revalidation Status appears in green if provided
- Tables are automatically formatted with proper styling
- Each vulnerability gets its own page (page break after each table)

## ⚠️ Important Reminders

1. **Template File**: You must create `MitKat_Template.docx` and place it in the `backend` directory
2. **Excel Format**: Ensure your Excel file has the required columns (case-insensitive matching)
3. **POC ZIP**: Use the recommended folder structure (`VUL-001/`, `VUL-002/`, etc.)
4. **Image Formats**: Supported formats are `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp`
5. **Step Numbers**: Image filenames should contain step numbers (e.g., `step1.png`, `step2.png`)

## 🎉 Ready to Use!

The implementation is complete and ready for testing. Simply:
1. Create your `MitKat_Template.docx` file
2. Prepare your Excel file with the required columns
3. Organize your POC screenshots in the ZIP structure
4. Access `/mitkat/` and generate your report!

