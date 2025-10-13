# Cert-IN Template Variables Guide

## Overview
This guide lists all the template variables that need to be added to your `CSS Certin temp.docx` template for the Cert-IN Report Generator to work properly.

## Template Variables to Add to Your Word Document

### 1. Basic Report Information
Replace the following placeholders in your Word template:

```
{{CLIENT_NAME}} - Client Name
{{REPORT_NAME}} - Web/Network Initial Report Name  
{{REPORT_RELEASE_DATE}} - Report Release Date
{{TYPE_OF_AUDIT}} - Type of Audit
{{TYPE_OF_AUDIT_REPORT}} - Type of Audit Report
{{PERIOD}} - Period
```

### 2. Document Control
```
{{DOCUMENT_TITLE}} - Document Title
{{DOCUMENT_ID}} - Document ID
{{DOCUMENT_VERSION}} - Document Version
{{PREPARED_BY}} - Prepared by
{{REVIEWED_BY}} - Reviewed by
{{APPROVED_BY}} - Approved by
{{RELEASED_BY}} - Released by
{{RELEASE_DATE}} - Release Date
```

### 3. Document Change History
For the document change history table, use this structure:
```
{% for change in DOCUMENT_CHANGE_HISTORY %}
{{change.version}} | {{change.date}} | {{change.remarks}}
{% endfor %}
```

### 4. Document Distribution List
For the distribution list table, use this structure:
```
{% for dist in DISTRIBUTION_LIST %}
{{dist.name}} | {{dist.organization}} | {{dist.designation}} | {{dist.email}}
{% endfor %}
```

### 5. Engagement Scope
For the engagement scope table, use this structure:
```
{% for scope in ENGAGEMENT_SCOPE %}
{{scope.sr_no}} | {{scope.asset_description}} | {{scope.criticality}} | {{scope.internal_ip}} | {{scope.url}} | {{scope.public_ip}} | {{scope.location}} | {{scope.hash_value}} | {{scope.version}} | {{scope.other_details}}
{% endfor %}
```

### 6. Details of Auditing Team
For the auditing team table, use this structure:
```
{% for team in AUDITING_TEAM %}
{{team.name}} | {{team.designation}} | {{team.email}} | {{team.qualifications}} | {{team.certin_listed}}
{% endfor %}
```

### 7. Audit Activities and Timelines
For the audit activities table, use this structure:
```
{% for activity in AUDIT_ACTIVITIES %}
{{activity.task}} | {{activity.date}}
{% endfor %}
```

### 8. Tools/Software Used
For the tools/software table, use this structure:
```
{% for tool in TOOLS_SOFTWARE %}
{{tool.sr_no}} | {{tool.name}} | {{tool.version}} | {{tool.type}}
{% endfor %}
```

### 9. Additional Variables
```
{{GENERATION_DATE}} - Current date when report is generated
{{GENERATION_TIME}} - Current time when report is generated
```

## How to Edit Your Word Template

### Step 1: Open Your Template
1. Open `CSS Certin temp.docx` in Microsoft Word
2. Go to the pages that need to be populated (1, 4, 5, 6, 7)

### Step 2: Replace Static Text with Variables
1. Find the static text that needs to be dynamic
2. Replace it with the corresponding template variable
3. For example, if you see "Client Name: [Static Text]", replace it with "Client Name: {{CLIENT_NAME}}"

### Step 3: Handle Tables
For tables with multiple rows:
1. Create the table structure with headers
2. In the first data row, use the template variables with the `{% for %}` loop
3. The system will automatically generate multiple rows based on the form data

### Step 4: Save the Template
1. Save the template as `CSS Certin temp.docx`
2. Make sure it's in the same directory as `type3.py`

## Example Template Edits

### Before (Static):
```
Client Name: ABC Company
Report Title: Security Assessment Report
Date: 18-08-2025
```

### After (Dynamic):
```
Client Name: {{CLIENT_NAME}}
Report Title: {{DOCUMENT_TITLE}}
Date: {{REPORT_RELEASE_DATE}}
```

### Table Example (Before):
```
| Name | Designation | Email |
|------|-------------|-------|
| John Doe | Security Analyst | john@example.com |
| Jane Smith | Senior Analyst | jane@example.com |
```

### Table Example (After):
```
| Name | Designation | Email |
|------|-------------|-------|
{% for team in AUDITING_TEAM %}
| {{team.name}} | {{team.designation}} | {{team.email}} |
{% endfor %}
```

## Testing Your Template

1. After editing your template, test it by:
   - Going to `/type3/` in your browser
   - Filling out the form with sample data
   - Generating a report
   - Checking if all variables are properly replaced

2. If variables are not replaced, check:
   - Variable names are exactly as specified (case-sensitive)
   - Variables are enclosed in double curly braces `{{}}`
   - For loops use the correct syntax `{% for item in LIST %}`
   - Template is saved in the correct location

## Notes

- All variables are case-sensitive
- Use exactly the variable names as specified
- For tables, the system will automatically handle multiple rows
- Empty fields will be replaced with empty strings
- Date fields should be in the format provided by the form (YYYY-MM-DD)

## Support

If you encounter issues with template variables:
1. Check the variable names match exactly
2. Ensure proper syntax for loops
3. Test with simple variables first
4. Check the generated report for any remaining `{{}}` placeholders
