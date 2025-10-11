"""
AWS Configuration for VAPT Report Generator
Cloud infrastructure configuration for Aurora PostgreSQL and S3
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

# Cloud Storage Paths
CLOUD_PATHS = {
    'reports': 'reports/',
    'excel_files': 'excel/',
    'images': 'images/',
    'temp': 'temp/'
}

def get_database_url():
    """Get PostgreSQL database URL for SQLAlchemy"""
    return f"postgresql://{DATABASE_CONFIG['user']}:{DATABASE_CONFIG['password']}@{DATABASE_CONFIG['host']}:{DATABASE_CONFIG['port']}/{DATABASE_CONFIG['database']}"

def validate_config():
    """Validate that all required configuration is present"""
    required_db_vars = ['AWS_RDS_HOST', 'AWS_RDS_PASSWORD']
    required_s3_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
    
    missing_vars = []
    
    for var in required_db_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    for var in required_s3_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    return True
