# Template Variables Guide for Standardized Excel Format

This guide documents the template variables that should be used in Word document templates for all report generators.

## Common Variables (All Templates)

### Metadata Variables
- `{{ CLIENT_NAME }}` or `{{ client_name }}` - Client/Organization name
- `{{ PROJECT_NAME }}` or `{{ project_name }}` - Project/Engagement name
- `{{ TESTER_NAME }}` or `{{ tester_name }}` - Name of the tester/auditor

### Asset Summary Table
Use a loop to display asset-level summaries:

```jinja2
{% for asset in assets %}
{{ asset.asset }} - {{ asset.purpose }}
Status: {{ asset.status }}
Critical: {{ asset.critical }}
High: {{ asset.high }}
Medium: {{ asset.medium }}
Low: {{ asset.low }}
Informational: {{ asset.informational }}
Total: {{ asset.total }}
{% endfor %}
```

### Severity Counts (Overall)
- `{{ severity_counts.critical }}` - Total critical vulnerabilities
- `{{ severity_counts.high }}` - Total high vulnerabilities
- `{{ severity_counts.medium }}` - Total medium vulnerabilities
- `{{ severity_counts.low }}` - Total low vulnerabilities
- `{{ severity_counts.informational }}` - Total informational findings
- `{{ severity_counts.total }}` - Total vulnerabilities

## Vulnerability Details Loop

All templates should use a loop to iterate through vulnerabilities:

```jinja2
{% for vuln in vulnerabilities %}

### Basic Information
- Serial Number: {{ vuln.sr_no }}
- Title/Observation: {{ vuln.observation }}
- Severity: {{ vuln.severity }}
- Status: {{ vuln.status }}
- Type: {{ vuln.new_or_re }}

### Technical Details
- CVE/CWE: {{ vuln.cve_cwe }}
- CVSS Score: {{ vuln.cvss }}
- CVSS Vector: {{ vuln.cvss_vector }}
- Affected Asset: {{ vuln.affected_asset }}
- IP/URL/Application: {{ vuln.ip_url_app }}

### Description
- Summary: {{ vuln.observation_summary }}
- Detailed Description: {{ vuln.detailed_observation }}

### Remediation
- Recommendation: {{ vuln.recommendation }}
- Reference: {{ vuln.reference }}
- Evidence/PoC: {{ vuln.evidence }}

### Steps to Reproduce
{% if vuln.steps %}
{% for step in vuln.steps %}
Step {{ step.number }}: {{ step.content }}
{% endfor %}
{% endif %}

### Screenshots
{% if vuln.screenshots %}
{% for screenshot in vuln.screenshots %}
[Screenshot: {{ screenshot }}]
{% endfor %}
{% endif %}

### Metadata
- Tester: {{ vuln.tester }}
- Project: {{ vuln.project }}
- Client: {{ vuln.client }}

{% endfor %}
```

## Template-Specific Variables

### Type 3 (Cert-IN) Template
Uses uppercase variable names:
- `{{ CLIENT_NAME }}`
- `{{ PROJECT_NAME }}`
- `{{ TESTER_NAME }}`
- `{{ vulnerabilities }}`
- `{{ assets }}`

### Type 2 Template
Uses lowercase variable names:
- `{{ client_name }}`
- `{{ project_name }}`
- `{{ tester_name }}`
- `{{ vulnerabilities }}`
- `{{ severity_summary }}`

### Type 4 / Main Template
Uses lowercase variable names:
- `{{ client_name }}`
- `{{ project_name }}`
- `{{ tester_name }}`
- `{{ vulnerabilities }}`
- `{{ severity_counts }}`

## Conditional Rendering

### Check if value exists before displaying:
```jinja2
{% if vuln.cve_cwe %}
CVE/CWE: {{ vuln.cve_cwe }}
{% endif %}
```

### Display default value if empty:
```jinja2
{{ vuln.cvss or 'N/A' }}
```

### Check for steps before rendering:
```jinja2
{% if vuln.steps and vuln.steps|length > 0 %}
Steps to Reproduce:
{% for step in vuln.steps %}
{{ step.number }}. {{ step.content }}
{% endfor %}
{% endif %}
```

## Excel Column Mapping

The parser automatically maps these Excel columns (case-insensitive):

| Standard Key | Excel Column Names (any of these) |
|-------------|-----------------------------------|
| asset | Asset, Hostname, Asset/Hostname |
| tester_name | Tester_Name, Tester, Auditor |
| project | Project, Project Name |
| client | Client, Client Name |
| observation | Observation, Title, Vulnerability Name |
| severity | Severity, Risk, Risk Level |
| status | Status, Vuln Status |
| cve_cwe | CVE/CWE, CVE, CWE |
| cvss | CVSS, CVSS Score |
| affected_asset | Affected Asset, Vulnerable Asset |
| ip_url_app | IP/URL/App, Target, Endpoint |
| detailed_observation | Detailed Observation/Vulnerability, Details |
| recommendation | Recommendation, Remediation, Fix |
| reference | Reference, References, Links |
| evidence | Evidence / Proof of Concept, PoC |
| step_1 to step_9 | Step 1, Step 2, ... Step 9 |
| screenshot | Screenshot (multiple columns) |

## Notes

1. **Empty Values**: If a column is blank in Excel, the template will receive an empty string `''`. Use conditional checks to avoid displaying empty fields.

2. **Multiple Screenshots**: The parser collects all columns with "screenshot" in the name into a list. Loop through them in the template.

3. **Steps**: Steps are automatically numbered and collected. They will only appear if the Excel has content in Step columns.

4. **Flexible Column Names**: The parser is case-insensitive and handles variations in column names (spaces, underscores, slashes).

5. **Default Values**: If critical columns like client_name, project_name, or tester_name are missing, the parser provides defaults, but these should be updated in the Excel.

