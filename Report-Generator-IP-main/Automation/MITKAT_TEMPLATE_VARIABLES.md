# MitKat Template Variables Guide

This guide documents all template variables that should be used in your `MitKat_Template.docx` file for the MitKat Report Generator.

## Single Value Variables

### Front Page Variables
- `{{ CLIENT_NAME }}` - Client/Organization name
- `{{ REPORT_TITLE }}` - Report title (e.g., "PIPELINE MODULE VAPT FINAL REPORT")
- `{{ REPORT_TO }}` - Organization receiving the report

### Document Control Variables
- `{{ REPORT_RELEASE_DATE }}` - Report release date
- `{{ TYPE_OF_AUDIT }}` - Type of audit
- `{{ TYPE_OF_AUDIT_REPORT }}` - Type of audit report
- `{{ PERIOD }}` - Audit period (e.g., "07-07-2025 to 18-07-2025")
- `{{ DOCUMENT_TITLE }}` - Document title
- `{{ DOCUMENT_ID }}` - Document ID
- `{{ DOCUMENT_VERSION }}` - Document version (e.g., "1.0")
- `{{ PREPARED_BY }}` - Name of person who prepared the document
- `{{ REVIEWED_BY }}` - Name of person who reviewed the document
- `{{ APPROVED_BY }}` - Name of person who approved the document
- `{{ RELEASED_BY }}` - Name of person who released the document
- `{{ RELEASE_DATE }}` - Release date
- `{{ INTRODUCTION }}` - Introduction text

---

## Multi-Row Table Variables (Lists/Arrays)

These variables contain arrays of objects that can have multiple entries. Use Jinja2 `{% for %}` loops in your Word template to iterate through them.

### 1. Document Change History

**Variable Name:** `DOCUMENT_CHANGE_HISTORY`

**Structure:** List of dictionaries with the following fields:
- `version` - Version number (e.g., "1.0", "1.1")
- `date` - Date of change
- `remarks` - Remarks/Reason for change

**Template Usage in Word:**
```
{% for change in DOCUMENT_CHANGE_HISTORY %}
{{ change.version }} | {{ change.date }} | {{ change.remarks }}
{% endfor %}
```

**Example Data Structure:**
```json
[
  {
    "version": "1.0",
    "date": "2025-07-21",
    "remarks": "Initial release"
  },
  {
    "version": "1.1",
    "date": "2025-07-25",
    "remarks": "Updated vulnerability details"
  }
]
```

**Table Columns in Template:**
1. Version
2. Date
3. Remarks / Reason of change

---

### 2. Document Distribution List

**Variable Name:** `DISTRIBUTION_LIST`

**Structure:** List of dictionaries with the following fields:
- `name` - Recipient name
- `organization` - Organization name
- `designation` - Job designation/title
- `email` - Email address

**Template Usage in Word:**
```
{% for dist in DISTRIBUTION_LIST %}
{{ dist.name }} | {{ dist.organization }} | {{ dist.designation }} | {{ dist.email }}
{% endfor %}
```

**Example Data Structure:**
```json
[
  {
    "name": "Mr Sanil Pandit",
    "organization": "RXIL",
    "designation": "CISO",
    "email": "Sanil.Pandit@rxil.in"
  },
  {
    "name": "John Doe",
    "organization": "Client Corp",
    "designation": "IT Manager",
    "email": "john.doe@client.com"
  }
]
```

**Table Columns in Template:**
1. Name
2. Organization
3. Designation
4. Email Id

---

### 3. Engagement Scope

**Variable Name:** `ENGAGEMENT_SCOPE`

**Structure:** List of dictionaries with the following fields:
- `sr_no` - Serial number (e.g., 1, 2, 3)
- `asset_description` - Description of the asset (e.g., "Web Application")
- `criticality` - Criticality level (e.g., "Critical", "High", "Medium", "Low")
- `url` - URL of the asset (e.g., "https://nt2.treds.in" or "NA")
- `location` - Physical or logical location (e.g., "NA" or "Data Center A")
- `hash_value` - Hash value for applications (e.g., "NA" or actual hash)
- `version` - Version number for applications (e.g., "NA" or "v2.1.0")
- `other_details` - Other details such as make/model for network devices (e.g., "NA" or device details)
- `internal_ip` - Internal IP address (optional)
- `public_ip` - Public IP address (optional)

**Template Usage in Word:**
```
{% for scope in ENGAGEMENT_SCOPE %}
{{ scope.sr_no }} | {{ scope.asset_description }} | {{ scope.criticality }} | {{ scope.url }} | {{ scope.location }} | {{ scope.hash_value }} | {{ scope.version }} | {{ scope.other_details }}
{% endfor %}
```

**Example Data Structure:**
```json
[
  {
    "sr_no": 1,
    "asset_description": "Web Application",
    "criticality": "Critical",
    "url": "https://nt2.treds.in",
    "location": "NA",
    "hash_value": "NA",
    "version": "NA",
    "other_details": "NA"
  },
  {
    "sr_no": 2,
    "asset_description": "API Server",
    "criticality": "High",
    "url": "https://api.example.com",
    "location": "AWS us-east-1",
    "hash_value": "SHA256:abc123...",
    "version": "v2.1.0",
    "other_details": "NA"
  }
]
```

**Table Columns in Template:**
1. S. No.
2. Asset Description
3. Criticality of Asset
4. Url
5. Location
6. Hash Value (in case of applications)
7. Version (in case of applications)
8. Other details such as make and model in case of network devices or security devices

---

### 4. Details of the Auditing Team

**Variable Name:** `AUDITING_TEAM`

**Structure:** List of dictionaries with the following fields:
- `sr_no` - Serial number (e.g., 1, 2, 3)
- `name` - Team member name
- `designation` - Job designation/title
- `email` - Email address
- `qualifications` - Professional qualifications/certifications (e.g., "CAP, CNSP, LFCS")
- `certin_listed` - Whether listed on CERT-In website ("Yes" or "No")

**Template Usage in Word:**
```
{% for team in AUDITING_TEAM %}
{{ team.sr_no }} | {{ team.name }} | {{ team.designation }} | {{ team.email }} | {{ team.qualifications }} | {{ team.certin_listed }}
{% endfor %}
```

**Example Data Structure:**
```json
[
  {
    "sr_no": 1,
    "name": "Biswajeet Ray",
    "designation": "Infosec Analyst - Team Lead",
    "email": "biswajeet.ray@mitkatadvisory.com",
    "qualifications": "CAP, CNSP, LFCS",
    "certin_listed": "No"
  },
  {
    "sr_no": 2,
    "name": "Shruti Patil",
    "designation": "Security Analyst",
    "email": "shruti.patil@mitkatadvisory.com",
    "qualifications": "CSIL-CI, CAP",
    "certin_listed": "No"
  }
]
```

**Table Columns in Template:**
1. S. No.
2. Name
3. Designation
4. Email Id
5. Professional Qualifications/Certifications
6. Whether the resource has been listed in the Snapshot information published on CERT-In's website (Yes/No)

---

### 5. Tools/Software Used

**Variable Name:** `TOOLS_SOFTWARE`

**Structure:** List of dictionaries with the following fields:
- `sr_no` - Serial number (e.g., 1, 2, 3)
- `name` - Name of the tool/software
- `version` - Version number of the tool
- `type` - Type of tool ("Opensource" or "Licensed")

**Template Usage in Word:**
```
{% for tool in TOOLS_SOFTWARE %}
{{ tool.sr_no }} | {{ tool.name }} | {{ tool.version }} | {{ tool.type }}
{% endfor %}
```

**Example Data Structure:**
```json
[
  {
    "sr_no": 1,
    "name": "Burp Suite Professional",
    "version": "2024.1",
    "type": "Licensed"
  },
  {
    "sr_no": 2,
    "name": "Nmap",
    "version": "7.94",
    "type": "Opensource"
  },
  {
    "sr_no": 3,
    "name": "OWASP ZAP",
    "version": "2.14.0",
    "type": "Opensource"
  }
]
```

**Table Columns in Template:**
1. S. No.
2. Name of Tool/Software
3. Version
4. Type (Opensource/Licensed)

---

## How to Use in Word Template

### Step 1: Create a Table
1. In your Word document, create a table with the appropriate number of columns
2. Add header row with column names
3. Add one data row (this will be used as a template row)

### Step 2: Add Jinja2 Loop
1. Select the data row (not the header row)
2. Wrap the row content with Jinja2 loop syntax:

**Example for Document Change History:**
```
{% for change in DOCUMENT_CHANGE_HISTORY %}
[Row content with {{ change.version }}, {{ change.date }}, {{ change.remarks }}]
{% endfor %}
```

### Step 3: Using docxtpl Table Syntax
In Word templates, you can use docxtpl's table row syntax. For a table row, use:

```
{% tr for change in DOCUMENT_CHANGE_HISTORY %}
{{ change.version }} | {{ change.date }} | {{ change.remarks }}
{% endtr %}
```

Or if you have a table already created in Word, you can use:
```
{% for change in DOCUMENT_CHANGE_HISTORY %}
[Table row with cells containing {{ change.version }}, {{ change.date }}, {{ change.remarks }}]
{% endfor %}
```

### Step 4: Handle Empty Lists
To handle cases where lists might be empty, use conditional statements:

```
{% if DOCUMENT_CHANGE_HISTORY %}
{% for change in DOCUMENT_CHANGE_HISTORY %}
{{ change.version }} | {{ change.date }} | {{ change.remarks }}
{% endfor %}
{% else %}
No change history available.
{% endif %}
```

---

## Complete Example Template Structure

Here's how your Word template should look for the Document Control Page:

### Document Preparation Section
```
Document Title: {{ DOCUMENT_TITLE }}
Document ID: {{ DOCUMENT_ID }}
Document Version: {{ DOCUMENT_VERSION }}
Prepared by: {{ PREPARED_BY }}
Reviewed by: {{ REVIEWED_BY }}
Approved by: {{ APPROVED_BY }}
Released by: {{ RELEASED_BY }}
Release date: {{ RELEASE_DATE }}
```

### Document Change History Table
```
Version | Date | Remarks / Reason of change
{% for change in DOCUMENT_CHANGE_HISTORY %}
{{ change.version }} | {{ change.date }} | {{ change.remarks }}
{% endfor %}
```

### Document Distribution List Table
```
Name | Organization | Designation | Email Id
{% for dist in DISTRIBUTION_LIST %}
{{ dist.name }} | {{ dist.organization }} | {{ dist.designation }} | {{ dist.email }}
{% endfor %}
```

### Engagement Scope Table
```
S. No. | Asset Description | Criticality of Asset | Url | Location | Hash Value | Version | Other details
{% for scope in ENGAGEMENT_SCOPE %}
{{ scope.sr_no }} | {{ scope.asset_description }} | {{ scope.criticality }} | {{ scope.url }} | {{ scope.location }} | {{ scope.hash_value }} | {{ scope.version }} | {{ scope.other_details }}
{% endfor %}
```

### Details of Auditing Team Table
```
S. No. | Name | Designation | Email Id | Professional Qualifications/Certifications | CERT-In Listed
{% for team in AUDITING_TEAM %}
{{ team.sr_no }} | {{ team.name }} | {{ team.designation }} | {{ team.email }} | {{ team.qualifications }} | {{ team.certin_listed }}
{% endfor %}
```

### Tools/Software Used Table
```
S. No. | Name of Tool/Software | Version | Type
{% for tool in TOOLS_SOFTWARE %}
{{ tool.sr_no }} | {{ tool.name }} | {{ tool.version }} | {{ tool.type }}
{% endfor %}
```

---

## Notes

1. **Variable Names are Case-Sensitive**: Use exact variable names as shown (e.g., `DOCUMENT_CHANGE_HISTORY`, not `document_change_history`)

2. **Empty Lists**: If a list is empty (`[]`), the loop will simply not execute, and no rows will be added

3. **Field Names**: Field names within each dictionary (e.g., `version`, `date`, `remarks`) are lowercase and use underscores

4. **Data Format**: The backend expects these variables as JSON arrays in the `doc_control_data` parameter

5. **Template Testing**: Test your template with sample data to ensure the loops work correctly

6. **Word Table Formatting**: Make sure your table has proper borders and formatting. The loop will add rows but won't change the table structure

---

## Backend Implementation

These variables are already implemented in the backend code (`main.py`):

```python
context = {
    # ... other variables ...
    'DOCUMENT_CHANGE_HISTORY': doc_control_data.get('document_change_history', []),
    'DISTRIBUTION_LIST': doc_control_data.get('distribution_list', []),
    'ENGAGEMENT_SCOPE': doc_control_data.get('engagement_scope', []),
    'AUDITING_TEAM': doc_control_data.get('auditing_team', []),
    'TOOLS_SOFTWARE': doc_control_data.get('tools_software', []),
}
```

The HTML form currently sends empty arrays for these fields. To populate them, you'll need to add form inputs similar to the `type3.py` implementation, or provide the data via the API directly.

