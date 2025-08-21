import pandas as pd

# Create a minimal test template with all required columns
data = {
    'Sr No': ['TEST-001', 'TEST-002'],
    'Vulnerability Name': [
        'Test SQL Injection', 
        'Test XSS'
    ],
    'Vulnerable URL': [
        '/login.php?username=', 
        '/search.php?q='
    ],
    'CVSS Score': [8.5, 6.1],
    'Description': [
        'Test description for SQL injection vulnerability.',
        'Test description for XSS vulnerability.'
    ],
    'Remediation': [
        'Use parameterized queries.',
        'Implement output encoding.'
    ],
    'Evidence': [
        'Screenshot of SQL injection.',
        'Screenshot of XSS.'
    ],
    'Steps': [
        'Step 1: Go to login\nStep 2: Enter payload\nStep 3: Observe result',
        'Step 1: Go to search\nStep 2: Enter <script> tag\nStep 3: Observe alert'
    ]
}

# Create DataFrame and save as Excel
df = pd.DataFrame(data)
df.to_excel('Test_Template.xlsx', index=False)
print('Created test template: Test_Template.xlsx') 