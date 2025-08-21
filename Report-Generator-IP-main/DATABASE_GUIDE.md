# Database Access Guide

## Database Location
The application uses SQLite database located at:
```
Report-Generator-IP-main/Automation/backend/data.db
```

## Database Schema

### Tables

#### 1. `dashboard_datasets`
Stores uploaded dashboard Excel files and metadata.
- `id` - Primary key
- `title` - Dashboard title
- `project_name` - Project name
- `file_path` - Path to stored Excel file
- `uploaded_by_email` - User email who uploaded
- `uploaded_by_name` - User name who uploaded
- `uploaded_at` - Upload timestamp

#### 2. `audit_logs`
Stores user activity logs.
- `id` - Primary key
- `user_email` - User email
- `user_name` - User name
- `action` - Action performed (login, generate-report, etc.)
- `metadata_json` - Additional action details (JSON)
- `ip_address` - User IP address
- `user_agent` - Browser/device info
- `created_at` - Timestamp

#### 3. `project_history` (NEW)
Stores cumulative project evaluation data.
- `id` - Primary key
- `project_name` - Project name (indexed)
- `total_vulnerabilities` - Total vulnerabilities across all evaluations
- `unique_vulnerabilities` - Count of unique vulnerability types
- `critical_count` - Critical severity count
- `high_count` - High severity count
- `medium_count` - Medium severity count
- `low_count` - Low severity count
- `informational_count` - Informational severity count
- `first_evaluated` - First evaluation date
- `last_evaluated` - Last evaluation date
- `evaluation_count` - Number of times project was evaluated
- `uploaded_by_email` - User who uploaded
- `uploaded_by_name` - User name
- `vulnerability_details` - JSON string of vulnerability names and counts

## Local Database Access

### Method 1: SQLite Browser (Recommended)
1. Download and install **DB Browser for SQLite** from: https://sqlitebrowser.org/
2. Open the application
3. Click "Open Database"
4. Navigate to: `Report-Generator-IP-main/Automation/backend/data.db`
5. You can now:
   - Browse tables
   - Execute SQL queries
   - Export data
   - Modify data

### Method 2: Command Line (SQLite3)
```bash
# Navigate to the database directory
cd Report-Generator-IP-main/Automation/backend

# Open SQLite console
sqlite3 data.db

# List all tables
.tables

# View table schema
.schema dashboard_datasets
.schema audit_logs
.schema project_history

# Query examples
SELECT * FROM project_history ORDER BY last_evaluated DESC;
SELECT project_name, total_vulnerabilities, evaluation_count FROM project_history;
SELECT COUNT(*) as total_projects FROM project_history;

# Exit
.quit
```

### Method 3: Python Script
Create a file `db_query.py`:
```python
import sqlite3
import os

# Database path
db_path = "Report-Generator-IP-main/Automation/backend/data.db"

def query_database():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Example queries
    print("=== Project History ===")
    cursor.execute("SELECT project_name, total_vulnerabilities, evaluation_count FROM project_history")
    for row in cursor.fetchall():
        print(f"Project: {row[0]}, Total Vulns: {row[1]}, Evaluations: {row[2]}")
    
    print("\n=== Recent Audit Logs ===")
    cursor.execute("SELECT user_name, action, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 10")
    for row in cursor.fetchall():
        print(f"User: {row[0]}, Action: {row[1]}, Date: {row[2]}")
    
    conn.close()

if __name__ == "__main__":
    query_database()
```

## AWS Database Access

### When Hosted on AWS EC2

#### Method 1: SSH into EC2 and Access Locally
```bash
# SSH into your EC2 instance
ssh -i your-key.pem ec2-user@your-ec2-ip

# Navigate to application directory
cd /path/to/your/app/Automation/backend

# Access database
sqlite3 data.db

# Run queries
SELECT * FROM project_history;
.quit
```

#### Method 2: Copy Database to Local Machine
```bash
# From your local machine, copy database from EC2
scp -i your-key.pem ec2-user@your-ec2-ip:/path/to/your/app/Automation/backend/data.db ./local_copy.db

# Now open with DB Browser for SQLite
```

#### Method 3: Web-based SQLite Viewer
1. Install a web-based SQLite viewer on your EC2 instance
2. Access via web browser at `http://your-ec2-ip:port`

### When Using AWS RDS (If Migrated)
If you migrate to AWS RDS (PostgreSQL/MySQL), you'll need to:
1. Update database connection strings
2. Modify SQLAlchemy models for the new database type
3. Use AWS RDS console or database clients to access

## Useful SQL Queries

### Project History Queries
```sql
-- Get all projects with their vulnerability counts
SELECT project_name, total_vulnerabilities, unique_vulnerabilities, 
       critical_count, high_count, medium_count, low_count, informational_count
FROM project_history 
ORDER BY last_evaluated DESC;

-- Get projects evaluated more than once
SELECT project_name, evaluation_count, first_evaluated, last_evaluated
FROM project_history 
WHERE evaluation_count > 1
ORDER BY evaluation_count DESC;

-- Get total vulnerabilities by severity across all projects
SELECT 
    SUM(critical_count) as total_critical,
    SUM(high_count) as total_high,
    SUM(medium_count) as total_medium,
    SUM(low_count) as total_low,
    SUM(informational_count) as total_informational
FROM project_history;

-- Get projects with most critical vulnerabilities
SELECT project_name, critical_count
FROM project_history 
WHERE critical_count > 0
ORDER BY critical_count DESC;
```

### Audit Log Queries
```sql
-- Get recent user activities
SELECT user_name, action, created_at, metadata_json
FROM audit_logs 
ORDER BY created_at DESC 
LIMIT 20;

-- Get login statistics
SELECT user_email, COUNT(*) as login_count
FROM audit_logs 
WHERE action = 'login'
GROUP BY user_email
ORDER BY login_count DESC;

-- Get dashboard uploads
SELECT user_name, project_name, uploaded_at
FROM audit_logs al
JOIN dashboard_datasets dd ON al.metadata_json LIKE '%' || dd.title || '%'
WHERE al.action = 'dashboard-upload'
ORDER BY al.created_at DESC;
```

### Dashboard Datasets Queries
```sql
-- Get all uploaded dashboards
SELECT title, project_name, uploaded_by_name, uploaded_at
FROM dashboard_datasets 
ORDER BY uploaded_at DESC;

-- Get dashboards by project
SELECT title, uploaded_at, uploaded_by_name
FROM dashboard_datasets 
WHERE project_name = 'Your Project Name'
ORDER BY uploaded_at DESC;
```

## Database Backup and Restore

### Backup
```bash
# Local backup
cp Report-Generator-IP-main/Automation/backend/data.db backup_$(date +%Y%m%d_%H%M%S).db

# AWS EC2 backup
ssh -i your-key.pem ec2-user@your-ec2-ip "cp /path/to/app/Automation/backend/data.db /tmp/backup_$(date +%Y%m%d_%H%M%S).db"
scp -i your-key.pem ec2-user@your-ec2-ip:/tmp/backup_*.db ./
```

### Restore
```bash
# Stop the application first
# Then restore
cp backup_file.db Report-Generator-IP-main/Automation/backend/data.db
```

## Database Maintenance

### Cleanup Old Data
```sql
-- Delete audit logs older than 1 year
DELETE FROM audit_logs WHERE created_at < datetime('now', '-1 year');

-- Delete dashboard datasets older than 2 years
DELETE FROM dashboard_datasets WHERE uploaded_at < datetime('now', '-2 years');
```

### Optimize Database
```sql
-- In SQLite console
VACUUM;
ANALYZE;
```

## Troubleshooting

### Common Issues
1. **Database locked**: Stop the application before accessing
2. **Permission denied**: Check file permissions on data.db
3. **Corrupted database**: Restore from backup

### Reset Database (Development Only)
```bash
# Delete and recreate database
rm Report-Generator-IP-main/Automation/backend/data.db
# Restart the application - it will create a new database
```

## Security Notes
- The database contains sensitive project information
- Always backup before making changes
- Use read-only access when possible
- Consider encrypting the database file for production
- Regularly backup the database file
