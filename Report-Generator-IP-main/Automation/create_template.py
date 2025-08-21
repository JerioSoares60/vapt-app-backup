import pandas as pd
import numpy as np

# Create a template with more comprehensive example entries
data = {
    'Sr No': ['EC-001', 'EC-002', 'EC-003', 'EC-004', 'EC-005'],
    'Vulnerability Name': [
        'Unauthenticated File Upload', 
        'SQL Injection in Login', 
        'Cross-Site Scripting (XSS)', 
        'Insecure Direct Object References',
        'Sensitive Data Exposure'
    ],
    'Vulnerable URL': [
        '/upload.php?file=', 
        '/login.php?username=', 
        '/search.php?q=', 
        '/profile.php?id=', 
        '/api/users/data'
    ],
    'CVSS Score': [9.8, 7.5, 6.1, 5.5, 8.2],
    'Description': [
        'This vulnerability allows unauthenticated attackers to upload malicious files to the server, potentially leading to remote code execution.',
        'The login page is vulnerable to SQL injection attacks, allowing attackers to bypass authentication and access sensitive data.',
        'The search functionality is vulnerable to XSS attacks, allowing attackers to inject and execute malicious scripts.',
        'The application does not properly validate user access to resources, allowing unauthorized access to protected data.',
        'The application transmits sensitive user data without proper encryption, exposing it to potential interception.'
    ],
    'Remediation': [
        'Implement proper file type validation, sanitization, and authentication before allowing file uploads.',
        'Use parameterized queries or prepared statements instead of dynamic SQL queries.',
        'Implement input validation and output encoding to prevent script injection.',
        'Implement proper authorization checks for all user-accessible resources.',
        'Ensure all sensitive data is encrypted during transmission and storage using strong algorithms.'
    ],
    'Evidence': [
        'Screenshot of successful shell access after uploading a PHP shell file.',
        'Screenshot showing database contents accessed through SQL injection payload.',
        'Screenshot showing JavaScript alert box execution through the search field.',
        'Screenshot showing unauthorized access to another user\'s profile data.',
        'Network capture showing plaintext data transmission of sensitive information.'
    ],
    'Steps': [
        'Step 1: Access /upload.php\nStep 2: Upload malicious PHP file\nStep 3: Access the uploaded file to get shell access',
        'Step 1: Access login page\nStep 2: Input username=\' OR 1=1 --\nStep 3: Observe authentication bypass',
        'Step 1: Go to search page\nStep 2: Input <script>alert("XSS")</script>\nStep 3: Observe script execution',
        'Step 1: Login as low-privilege user\nStep 2: Access /profile.php?id=1\nStep 3: Observe admin data access',
        'Step 1: Login to application\nStep 2: Capture network traffic\nStep 3: Observe plaintext transmission of credentials'
    ]
}

# Create DataFrame and save as Excel
df = pd.DataFrame(data)
df.to_excel('Comprehensive_Vulnerability_Template.xlsx', index=False)
print('Created comprehensive template: Comprehensive_Vulnerability_Template.xlsx') 