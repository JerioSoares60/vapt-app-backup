import pandas as pd
import numpy as np

# Create a comprehensive template with step-specific screenshots for multiple severity levels
data = {
    'Sr No': ['VULN-001', 'VULN-002', 'VULN-003', 'VULN-004', 'VULN-005'],
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
    'Vulnerable Parameter': [
        'file', 
        'username', 
        'q', 
        'id', 
        'None'
    ],
    'CVSS Score': [9.8, 7.5, 6.1, 5.5, 8.2],
    'Description': [
        'This vulnerability allows unauthenticated attackers to upload malicious files to the server, potentially leading to remote code execution. The application fails to properly validate the uploaded file type, content, and size.',
        'The login page is vulnerable to SQL injection attacks, allowing attackers to bypass authentication and access sensitive data. The application directly includes user input in SQL queries without proper sanitization.',
        'The search functionality is vulnerable to XSS attacks, allowing attackers to inject and execute malicious scripts. User input from the search query is rendered without proper encoding.',
        'The application does not properly validate user access to resources, allowing unauthorized access to protected data. The system relies solely on user-supplied IDs without proper authorization checks.',
        'The application transmits sensitive user data without proper encryption, exposing it to potential interception. API responses contain plaintext sensitive information.'
    ],
    'Impact': [
        'Critical impact as attackers can achieve complete system compromise by uploading and executing malicious code. This can lead to unauthorized access to all system resources, data theft, and establishing persistence on the server.',
        'High impact as attackers can bypass authentication mechanisms to access unauthorized data, potentially compromising all user accounts and sensitive information stored in the database.',
        'Medium impact as attackers can execute arbitrary JavaScript in victims\' browsers, potentially stealing session cookies, hijacking user sessions, or performing actions on behalf of victims.',
        'Medium impact as attackers can access information belonging to other users, violating confidentiality and potentially leading to privacy breaches and unauthorized data access.',
        'High impact as sensitive data exposure can lead to identity theft, financial fraud, and regulatory compliance violations. Exposed data may include personal information, credentials, and financial details.'
    ],
    'Remediation': [
        'Implement strict file type validation using content inspection rather than relying on extensions. Set file size limits and store uploaded files outside the web root directory. Implement proper authentication before allowing uploads.',
        'Use parameterized queries or prepared statements instead of dynamic SQL queries. Apply input validation and sanitization for all user inputs used in database operations.',
        'Implement context-sensitive output encoding for all user-supplied data. Use Content Security Policy (CSP) headers to restrict execution of injected scripts.',
        'Implement proper access control checks for all user-accessible resources. Use indirect references that are mapped server-side to actual resource identifiers.',
        'Implement proper encryption for all sensitive data in transit and at rest. Use HTTPS for all connections and proper hashing for stored passwords.'
    ],
    'Steps': [
        'Step 1: Access /upload.php\nStep 2: Upload malicious PHP file\nStep 3: Access the uploaded file to get shell access',
        'Step 1: Access login page\nStep 2: Input username=\' OR 1=1 --\nStep 3: Observe authentication bypass',
        'Step 1: Go to search page\nStep 2: Input <script>alert("XSS")</script>\nStep 3: Observe script execution',
        'Step 1: Login as low-privilege user\nStep 2: Access /profile.php?id=1\nStep 3: Observe admin data access',
        'Step 1: Login to application\nStep 2: Capture network traffic\nStep 3: Observe plaintext transmission of credentials'
    ],
}

# Create data for Screenshot 1 through Screenshot 15
for i in range(1, 16):
    screenshot_key = f'Screenshot {i}'
    # Add data for the first 3 screenshots (matching number of steps), leave others empty
    if i <= 3:
        data[screenshot_key] = [
            f'file_upload_step{i}.png',
            f'sql_injection_step{i}.png',
            f'xss_step{i}.png',
            f'idor_step{i}.png',
            f'sensitive_data_step{i}.png'
        ]
    else:
        data[screenshot_key] = ['', '', '', '', '']

# Create DataFrame and save as Excel
df = pd.DataFrame(data)
df.to_excel('Comprehensive_Vulnerability_Template.xlsx', index=False)
print('Created comprehensive template with 15 screenshot columns: Comprehensive_Vulnerability_Template.xlsx') 