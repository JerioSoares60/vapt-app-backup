# AWS Cloud Migration Guide
## Complete Migration from SQLite to AWS Aurora/RDS + S3

This guide will help you migrate your VAPT Report Generator from local SQLite to AWS cloud services with full monitoring and analytics.

## 🎯 **What We'll Achieve:**
- ✅ Migrate from SQLite to AWS Aurora PostgreSQL
- ✅ Store all files (reports, images, Excel) in AWS S3
- ✅ Set up comprehensive usage monitoring
- ✅ Enable team-wide access with proper security
- ✅ Track employee usage patterns and analytics

---

## 📋 **Step 1: AWS RDS PostgreSQL Setup**

### 1.1 Create RDS PostgreSQL Instance

1. **Login to AWS Console** → Go to RDS service
2. **Click "Create database"**
3. **Configure Database:**
   ```
   Engine type: PostgreSQL
   Version: PostgreSQL 15.4 (or latest)
   Templates: Production (for team access)
   DB instance identifier: vapt-report-db
   Master username: vaptadmin
   Master password: [Create strong password - save it!]
   DB instance class: db.t3.micro (start small, scale later)
   Storage: 20 GB (General Purpose SSD)
   ```

4. **Network & Security:**
   ```
   VPC: Default VPC
   Subnet group: Default
   Public access: Yes (for initial setup)
   VPC security groups: Create new
   Security group name: vapt-db-sg
   ```

5. **Additional Configuration:**
   ```
   Database name: vapt_reports
   Port: 5432
   Backup retention: 7 days
   Monitoring: Enable Performance Insights
   ```

6. **Click "Create database"** (takes 5-10 minutes)

### 1.2 Configure Security Group

1. **Go to EC2 → Security Groups**
2. **Find "vapt-db-sg"**
3. **Add Inbound Rules:**
   ```
   Type: PostgreSQL
   Port: 5432
   Source: Your EC2 security group ID
   Description: Allow EC2 to RDS
   ```

---

## 📋 **Step 2: AWS S3 Setup for File Storage**

### 2.1 Create S3 Buckets

1. **Go to S3 service**
2. **Create 3 buckets:**

   **Bucket 1: Reports Storage**
   ```
   Bucket name: vapt-reports-[your-company-name]
   Region: Same as your EC2
   Block all public access: Yes
   Versioning: Enable
   ```

   **Bucket 2: Excel Files**
   ```
   Bucket name: vapt-excel-files-[your-company-name]
   Region: Same as your EC2
   Block all public access: Yes
   ```

   **Bucket 3: Images/Screenshots**
   ```
   Bucket name: vapt-images-[your-company-name]
   Region: Same as your EC2
   Block all public access: Yes
   ```

### 2.2 Create IAM User for S3 Access

1. **Go to IAM → Users → Create user**
2. **Username:** `vapt-s3-user`
3. **Attach policies directly:**
   - `AmazonS3FullAccess` (for now, we'll restrict later)
4. **Create access key** → Save Access Key ID and Secret

---

## 📋 **Step 3: Database Migration Script**

### 3.1 Create Migration Script

Create `migrate_to_aws.py`:

```python
#!/usr/bin/env python3
"""
Migration script from SQLite to AWS Aurora PostgreSQL
"""

import sqlite3
import psycopg2
import os
import sys
from datetime import datetime

# Database configurations
SQLITE_DB = 'vapt_reports.db'  # Your current SQLite file
POSTGRES_CONFIG = {
    'host': 'your-rds-endpoint.amazonaws.com',
    'port': 5432,
    'database': 'vapt_reports',
    'user': 'vaptadmin',
    'password': 'your-rds-password'
}

def migrate_database():
    """Migrate all data from SQLite to PostgreSQL"""
    
    # Connect to SQLite
    sqlite_conn = sqlite3.connect(SQLITE_DB)
    sqlite_cursor = sqlite_conn.cursor()
    
    # Connect to PostgreSQL
    postgres_conn = psycopg2.connect(**POSTGRES_CONFIG)
    postgres_cursor = postgres_conn.cursor()
    
    try:
        # Create tables in PostgreSQL
        create_tables(postgres_cursor)
        
        # Migrate data
        migrate_users(sqlite_cursor, postgres_cursor)
        migrate_dashboard_datasets(sqlite_cursor, postgres_cursor)
        migrate_project_history(sqlite_cursor, postgres_cursor)
        migrate_audit_logs(sqlite_cursor, postgres_cursor)
        
        postgres_conn.commit()
        print("✅ Migration completed successfully!")
        
    except Exception as e:
        postgres_conn.rollback()
        print(f"❌ Migration failed: {e}")
        raise
    finally:
        sqlite_conn.close()
        postgres_conn.close()

def create_tables(cursor):
    """Create all required tables in PostgreSQL"""
    
    tables = [
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS dashboard_datasets (
            id SERIAL PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            project_name VARCHAR(255),
            file_path TEXT,
            uploaded_by_email VARCHAR(255),
            uploaded_by_name VARCHAR(255),
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            s3_bucket VARCHAR(255),
            s3_key VARCHAR(500)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS project_history (
            id SERIAL PRIMARY KEY,
            project_name VARCHAR(255) NOT NULL,
            total_vulnerabilities INTEGER DEFAULT 0,
            unique_vulnerabilities INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            informational_count INTEGER DEFAULT 0,
            last_evaluated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            evaluation_count INTEGER DEFAULT 1,
            vulnerability_details TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS project_evaluation_events (
            id SERIAL PRIMARY KEY,
            project_name VARCHAR(255) NOT NULL,
            total_vulnerabilities INTEGER DEFAULT 0,
            unique_vulnerabilities INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            informational_count INTEGER DEFAULT 0,
            uploaded_by_email VARCHAR(255),
            uploaded_by_name VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_email VARCHAR(255),
            user_name VARCHAR(255),
            action VARCHAR(255),
            metadata_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS usage_analytics (
            id SERIAL PRIMARY KEY,
            user_email VARCHAR(255),
            action_type VARCHAR(100),
            resource_type VARCHAR(100),
            file_size BIGINT,
            processing_time INTEGER,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
    
    for table_sql in tables:
        cursor.execute(table_sql)
        print(f"✅ Created table: {table_sql.split()[5]}")

def migrate_users(sqlite_cursor, postgres_cursor):
    """Migrate users data"""
    sqlite_cursor.execute("SELECT * FROM users")
    users = sqlite_cursor.fetchall()
    
    for user in users:
        postgres_cursor.execute("""
            INSERT INTO users (email, name, created_at, last_login)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (email) DO NOTHING
        """, user)
    
    print(f"✅ Migrated {len(users)} users")

def migrate_dashboard_datasets(sqlite_cursor, postgres_cursor):
    """Migrate dashboard datasets"""
    sqlite_cursor.execute("SELECT * FROM dashboard_datasets")
    datasets = sqlite_cursor.fetchall()
    
    for dataset in datasets:
        postgres_cursor.execute("""
            INSERT INTO dashboard_datasets 
            (title, project_name, file_path, uploaded_by_email, uploaded_by_name, uploaded_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, dataset)
    
    print(f"✅ Migrated {len(datasets)} dashboard datasets")

def migrate_project_history(sqlite_cursor, postgres_cursor):
    """Migrate project history"""
    sqlite_cursor.execute("SELECT * FROM project_history")
    projects = sqlite_cursor.fetchall()
    
    for project in projects:
        postgres_cursor.execute("""
            INSERT INTO project_history 
            (project_name, total_vulnerabilities, unique_vulnerabilities, 
             critical_count, high_count, medium_count, low_count, 
             informational_count, last_evaluated, evaluation_count, vulnerability_details)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, project)
    
    print(f"✅ Migrated {len(projects)} project history records")

def migrate_audit_logs(sqlite_cursor, postgres_cursor):
    """Migrate audit logs"""
    sqlite_cursor.execute("SELECT * FROM audit_logs")
    logs = sqlite_cursor.fetchall()
    
    for log in logs:
        postgres_cursor.execute("""
            INSERT INTO audit_logs (user_email, user_name, action, metadata_json, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """, log)
    
    print(f"✅ Migrated {len(logs)} audit logs")

if __name__ == "__main__":
    print("🚀 Starting database migration to AWS Aurora...")
    migrate_database()
    print("🎉 Migration completed! Your data is now in AWS Aurora.")
```

---

## 📋 **Step 4: Update Application Configuration**

### 4.1 Create AWS Configuration File

Create `aws_config.py`:

```python
"""
AWS Configuration for VAPT Report Generator
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Database Configuration
DATABASE_CONFIG = {
    'host': os.getenv('AWS_RDS_HOST', 'your-rds-endpoint.amazonaws.com'),
    'port': int(os.getenv('AWS_RDS_PORT', 5432)),
    'database': os.getenv('AWS_RDS_DATABASE', 'vapt_reports'),
    'user': os.getenv('AWS_RDS_USER', 'vaptadmin'),
    'password': os.getenv('AWS_RDS_PASSWORD'),
}

# S3 Configuration
S3_CONFIG = {
    'reports_bucket': os.getenv('S3_REPORTS_BUCKET', 'vapt-reports-yourcompany'),
    'excel_bucket': os.getenv('S3_EXCEL_BUCKET', 'vapt-excel-files-yourcompany'),
    'images_bucket': os.getenv('S3_IMAGES_BUCKET', 'vapt-images-yourcompany'),
    'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
    'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
    'region': os.getenv('AWS_REGION', 'ap-south-1')
}

# Analytics Configuration
ANALYTICS_CONFIG = {
    'track_usage': True,
    'track_file_sizes': True,
    'track_processing_times': True,
    'track_user_actions': True
}
```

### 4.2 Update Environment Variables

Create `.env` file:

```bash
# AWS RDS Configuration
AWS_RDS_HOST=your-rds-endpoint.amazonaws.com
AWS_RDS_PORT=5432
AWS_RDS_DATABASE=vapt_reports
AWS_RDS_USER=vaptadmin
AWS_RDS_PASSWORD=your-secure-password

# AWS S3 Configuration
S3_REPORTS_BUCKET=vapt-reports-yourcompany
S3_EXCEL_BUCKET=vapt-excel-files-yourcompany
S3_IMAGES_BUCKET=vapt-images-yourcompany
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=ap-south-1

# Application Configuration
DATABASE_URL=postgresql://vaptadmin:password@your-rds-endpoint.amazonaws.com:5432/vapt_reports
```

---

## 📋 **Step 5: Update Application Code for Cloud Storage**

### 5.1 Create S3 Service Module

Create `s3_service.py`:

```python
"""
AWS S3 Service for file storage
"""

import boto3
import os
from datetime import datetime
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

class S3Service:
    def __init__(self, config: Dict[str, Any]):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=config['aws_access_key_id'],
            aws_secret_access_key=config['aws_secret_access_key'],
            region_name=config['region']
        )
        self.reports_bucket = config['reports_bucket']
        self.excel_bucket = config['excel_bucket']
        self.images_bucket = config['images_bucket']
    
    def upload_report(self, file_path: str, user_email: str) -> str:
        """Upload generated report to S3"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            s3_key = f"reports/{user_email}/{timestamp}_{os.path.basename(file_path)}"
            
            self.s3_client.upload_file(file_path, self.reports_bucket, s3_key)
            
            logger.info(f"Report uploaded to S3: {s3_key}")
            return s3_key
            
        except Exception as e:
            logger.error(f"Failed to upload report: {e}")
            raise
    
    def upload_excel(self, file_path: str, user_email: str) -> str:
        """Upload Excel file to S3"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            s3_key = f"excel/{user_email}/{timestamp}_{os.path.basename(file_path)}"
            
            self.s3_client.upload_file(file_path, self.excel_bucket, s3_key)
            
            logger.info(f"Excel uploaded to S3: {s3_key}")
            return s3_key
            
        except Exception as e:
            logger.error(f"Failed to upload Excel: {e}")
            raise
    
    def upload_image(self, file_path: str, user_email: str, vulnerability_id: str) -> str:
        """Upload image/screenshot to S3"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            s3_key = f"images/{user_email}/{vulnerability_id}/{timestamp}_{os.path.basename(file_path)}"
            
            self.s3_client.upload_file(file_path, self.images_bucket, s3_key)
            
            logger.info(f"Image uploaded to S3: {s3_key}")
            return s3_key
            
        except Exception as e:
            logger.error(f"Failed to upload image: {e}")
            raise
    
    def get_download_url(self, bucket: str, s3_key: str, expiration: int = 3600) -> str:
        """Generate presigned URL for file download"""
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket, 'Key': s3_key},
                ExpiresIn=expiration
            )
            return url
        except Exception as e:
            logger.error(f"Failed to generate download URL: {e}")
            raise
    
    def delete_file(self, bucket: str, s3_key: str) -> bool:
        """Delete file from S3"""
        try:
            self.s3_client.delete_object(Bucket=bucket, Key=s3_key)
            logger.info(f"File deleted from S3: {s3_key}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete file: {e}")
            return False
```

### 5.2 Create Usage Analytics Module

Create `analytics_service.py`:

```python
"""
Usage Analytics Service for tracking user activities
"""

from datetime import datetime
from typing import Dict, Any, Optional
import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)

class AnalyticsService:
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def track_user_action(self, user_email: str, action_type: str, 
                         resource_type: str, metadata: Dict[str, Any] = None,
                         ip_address: str = None, user_agent: str = None):
        """Track user action for analytics"""
        try:
            # Insert into usage_analytics table
            self.db.execute(text("""
                INSERT INTO usage_analytics 
                (user_email, action_type, resource_type, metadata_json, 
                 ip_address, user_agent, created_at)
                VALUES (:user_email, :action_type, :resource_type, :metadata_json,
                        :ip_address, :user_agent, :created_at)
            """), {
                'user_email': user_email,
                'action_type': action_type,
                'resource_type': resource_type,
                'metadata_json': json.dumps(metadata) if metadata else None,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'created_at': datetime.utcnow()
            })
            
            self.db.commit()
            logger.info(f"Tracked action: {action_type} by {user_email}")
            
        except Exception as e:
            logger.error(f"Failed to track user action: {e}")
            self.db.rollback()
    
    def track_file_upload(self, user_email: str, file_path: str, file_size: int,
                         processing_time: int, file_type: str):
        """Track file upload with metrics"""
        metadata = {
            'file_path': file_path,
            'file_size': file_size,
            'processing_time': processing_time,
            'file_type': file_type
        }
        
        self.track_user_action(
            user_email=user_email,
            action_type='file_upload',
            resource_type=file_type,
            metadata=metadata
        )
    
    def track_report_generation(self, user_email: str, report_type: str,
                              processing_time: int, vulnerability_count: int):
        """Track report generation"""
        metadata = {
            'report_type': report_type,
            'processing_time': processing_time,
            'vulnerability_count': vulnerability_count
        }
        
        self.track_user_action(
            user_email=user_email,
            action_type='report_generation',
            resource_type=report_type,
            metadata=metadata
        )
    
    def get_usage_statistics(self, start_date: datetime = None, end_date: datetime = None):
        """Get usage statistics for analytics dashboard"""
        try:
            query = """
                SELECT 
                    user_email,
                    action_type,
                    resource_type,
                    COUNT(*) as action_count,
                    AVG(processing_time) as avg_processing_time,
                    SUM(file_size) as total_file_size
                FROM usage_analytics
                WHERE created_at >= :start_date AND created_at <= :end_date
                GROUP BY user_email, action_type, resource_type
                ORDER BY action_count DESC
            """
            
            result = self.db.execute(text(query), {
                'start_date': start_date or datetime.min,
                'end_date': end_date or datetime.max
            })
            
            return result.fetchall()
            
        except Exception as e:
            logger.error(f"Failed to get usage statistics: {e}")
            return []
    
    def get_user_activity_summary(self, user_email: str):
        """Get activity summary for specific user"""
        try:
            query = """
                SELECT 
                    action_type,
                    COUNT(*) as count,
                    MAX(created_at) as last_activity,
                    AVG(processing_time) as avg_processing_time
                FROM usage_analytics
                WHERE user_email = :user_email
                GROUP BY action_type
                ORDER BY count DESC
            """
            
            result = self.db.execute(text(query), {'user_email': user_email})
            return result.fetchall()
            
        except Exception as e:
            logger.error(f"Failed to get user activity: {e}")
            return []
```

---

## 📋 **Step 6: Update Main Application Files**

### 6.1 Update Database Connection

Update your main application to use PostgreSQL:

```python
# In your main.py or app.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from aws_config import DATABASE_CONFIG

# Create PostgreSQL engine
DATABASE_URL = f"postgresql://{DATABASE_CONFIG['user']}:{DATABASE_CONFIG['password']}@{DATABASE_CONFIG['host']}:{DATABASE_CONFIG['port']}/{DATABASE_CONFIG['database']}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

### 6.2 Update File Storage

Update your file handling to use S3:

```python
# In your type2.py or main.py
from s3_service import S3Service
from aws_config import S3_CONFIG

s3_service = S3Service(S3_CONFIG)

# When saving files, upload to S3
def save_report_to_cloud(file_path: str, user_email: str):
    s3_key = s3_service.upload_report(file_path, user_email)
    return s3_key
```

---

## 📋 **Step 7: Deployment Steps**

### 7.1 Install Required Packages

```bash
# On your EC2 instance
sudo -u vaptapp /opt/vapt-venv/bin/pip install psycopg2-binary boto3 python-dotenv
```

### 7.2 Update Requirements

Add to `requirements-aws.txt`:

```
psycopg2-binary==2.9.9
boto3==1.34.0
python-dotenv==1.0.0
```

### 7.3 Run Migration

```bash
# On your EC2 instance
cd /opt/vapt-app/current/Report-Generator-IP-main
sudo -u vaptapp python3 migrate_to_aws.py
```

### 7.4 Update Application

```bash
# Update your application files
sudo -u vaptapp bash -lc 'cd /opt/vapt-app/current && git pull origin main'
sudo systemctl restart vapt-app
```

---

## 📋 **Step 8: Monitoring and Analytics Dashboard**

### 8.1 Create Analytics Dashboard

Create `analytics_dashboard.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Usage Analytics Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>VAPT System Usage Analytics</h1>
    
    <div id="user-activity-chart">
        <canvas id="activityChart"></canvas>
    </div>
    
    <div id="file-usage-stats">
        <h2>File Usage Statistics</h2>
        <table id="usageTable">
            <thead>
                <tr>
                    <th>User</th>
                    <th>Action Type</th>
                    <th>Count</th>
                    <th>Last Activity</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
    
    <script>
        // Load analytics data
        async function loadAnalytics() {
            const response = await fetch('/analytics/usage-stats');
            const data = await response.json();
            
            // Update charts and tables
            updateCharts(data);
            updateTables(data);
        }
        
        function updateCharts(data) {
            // Create usage charts
            const ctx = document.getElementById('activityChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.users,
                    datasets: [{
                        label: 'Report Generations',
                        data: data.report_counts,
                        backgroundColor: '#2d6cdf'
                    }]
                }
            });
        }
        
        function updateTables(data) {
            const tbody = document.getElementById('usageTable').querySelector('tbody');
            tbody.innerHTML = data.usage_stats.map(stat => `
                <tr>
                    <td>${stat.user_email}</td>
                    <td>${stat.action_type}</td>
                    <td>${stat.action_count}</td>
                    <td>${new Date(stat.last_activity).toLocaleString()}</td>
                </tr>
            `).join('');
        }
        
        // Load analytics on page load
        loadAnalytics();
    </script>
</body>
</html>
```

---

## 🎯 **Final Result:**

After completing these steps, you'll have:

✅ **AWS Aurora PostgreSQL** - All data stored in cloud database  
✅ **AWS S3 Storage** - All files (reports, Excel, images) in cloud storage  
✅ **Usage Analytics** - Track who uses what, when, and how much  
✅ **Team Access** - Multiple users can access from anywhere  
✅ **Scalable Infrastructure** - Easy to scale up as your team grows  
✅ **Cost Monitoring** - Track usage and costs per user/project  

## 💰 **Estimated Monthly Costs:**
- **RDS PostgreSQL (db.t3.micro)**: ~$15-20/month
- **S3 Storage (100GB)**: ~$2-3/month  
- **Data Transfer**: ~$1-2/month
- **Total**: ~$20-25/month for small team

Would you like me to help you implement any specific part of this migration?
