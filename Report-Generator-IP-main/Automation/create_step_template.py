import pandas as pd
import numpy as np

# Create a template with step-specific screenshots
data = {
    'Sr No': ['TEST-001', 'TEST-002'],
    'Vulnerability Name': [
        'SQL Injection in Login', 
        'Cross-Site Scripting (XSS)'
    ],
    'Vulnerable URL': [
        '/login.php?username=', 
        '/search.php?q='
    ],
    'CVSS Score': [8.5, 6.1],
    'Description': [
        'The login page is vulnerable to SQL injection attacks, allowing attackers to bypass authentication and access sensitive data.',
        'The search functionality is vulnerable to XSS attacks, allowing attackers to inject and execute malicious scripts.'
    ],
    'Impact': [
        'The impact of SQL Injection vulnerabilities can be severe and far-reaching for an organization. Successful exploitation can lead to unauthorized access to sensitive database information, including personal user data, financial records, and intellectual property.',
        'The exploitation of Cross-Site Scripting vulnerabilities can have significant consequences for both users and the organization. Attackers can hijack user sessions, steal authentication cookies, and impersonate legitimate users.'
    ],
    'Remediation': [
        'Use parameterized queries or prepared statements instead of dynamic SQL queries.',
        'Implement input validation and output encoding to prevent script injection.'
    ],
    'Steps': [
        'Step 1: Go to login page\nStep 2: Enter payload \' OR 1=1 --\nStep 3: Observe authentication bypass',
        'Step 1: Go to search page\nStep 2: Enter payload <script>alert("XSS")</script>\nStep 3: Observe script execution'
    ],
}

# Create data for Screenshot 1 through Screenshot 15
for i in range(1, 16):
    screenshot_key = f'Screenshot {i}'
    # Add data for the first 3 screenshots (matching number of steps), leave others empty
    if i <= 3:
        data[screenshot_key] = [
            f'sql_step{i}.png',
            f'xss_step{i}.png'
        ]
    else:
        data[screenshot_key] = ['', '']

# Create DataFrame and save as Excel
df = pd.DataFrame(data)
df.to_excel('Step_Screenshot_Template.xlsx', index=False)
print('Created template with 15 screenshot columns: Step_Screenshot_Template.xlsx') 