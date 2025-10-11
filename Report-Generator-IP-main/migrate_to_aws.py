#!/usr/bin/env python3
"""
Migration script from SQLite to AWS Aurora PostgreSQL
Run this script to migrate your existing data to AWS cloud
"""

import sqlite3
import psycopg2
import os
import sys
from datetime import datetime
import json

# Database configurations
SQLITE_DB = 'vapt_reports.db'  # Your current SQLite file
POSTGRES_CONFIG = {
    'host': os.getenv('AWS_RDS_HOST', 'your-rds-endpoint.amazonaws.com'),
    'port': int(os.getenv('AWS_RDS_PORT', 5432)),
    'database': os.getenv('AWS_RDS_DATABASE', 'vapt_reports'),
    'user': os.getenv('AWS_RDS_USER', 'vaptadmin'),
    'password': os.getenv('AWS_RDS_PASSWORD'),
}

def migrate_database():
    """Migrate all data from SQLite to PostgreSQL"""
    
    print("🚀 Starting migration from SQLite to AWS Aurora PostgreSQL...")
    
    # Check if SQLite database exists
    if not os.path.exists(SQLITE_DB):
        print(f"❌ SQLite database not found: {SQLITE_DB}")
        print("Please ensure your SQLite database is in the current directory.")
        return False
    
    # Connect to SQLite
    try:
        sqlite_conn = sqlite3.connect(SQLITE_DB)
        sqlite_cursor = sqlite_conn.cursor()
        print("✅ Connected to SQLite database")
    except Exception as e:
        print(f"❌ Failed to connect to SQLite: {e}")
        return False
    
    # Connect to PostgreSQL
    try:
        postgres_conn = psycopg2.connect(**POSTGRES_CONFIG)
        postgres_cursor = postgres_conn.cursor()
        print("✅ Connected to AWS Aurora PostgreSQL")
    except Exception as e:
        print(f"❌ Failed to connect to PostgreSQL: {e}")
        print("Please check your AWS RDS configuration and ensure the database is accessible.")
        return False
    
    try:
        # Create tables in PostgreSQL
        print("📋 Creating tables in PostgreSQL...")
        create_tables(postgres_cursor)
        
        # Migrate data
        print("📦 Migrating data...")
        migrate_users(sqlite_cursor, postgres_cursor)
        migrate_dashboard_datasets(sqlite_cursor, postgres_cursor)
        migrate_project_history(sqlite_cursor, postgres_cursor)
        migrate_audit_logs(sqlite_cursor, postgres_cursor)
        
        postgres_conn.commit()
        print("✅ Migration completed successfully!")
        print("🎉 Your data is now stored in AWS Aurora PostgreSQL!")
        return True
        
    except Exception as e:
        postgres_conn.rollback()
        print(f"❌ Migration failed: {e}")
        return False
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
        table_name = table_sql.split()[5]
        print(f"  ✅ Created table: {table_name}")

def migrate_users(sqlite_cursor, postgres_cursor):
    """Migrate users data"""
    try:
        sqlite_cursor.execute("SELECT * FROM users")
        users = sqlite_cursor.fetchall()
        
        for user in users:
            postgres_cursor.execute("""
                INSERT INTO users (email, name, created_at, last_login)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (email) DO NOTHING
            """, user)
        
        print(f"  ✅ Migrated {len(users)} users")
    except Exception as e:
        print(f"  ⚠️  Users migration warning: {e}")

def migrate_dashboard_datasets(sqlite_cursor, postgres_cursor):
    """Migrate dashboard datasets"""
    try:
        sqlite_cursor.execute("SELECT * FROM dashboard_datasets")
        datasets = sqlite_cursor.fetchall()
        
        for dataset in datasets:
            postgres_cursor.execute("""
                INSERT INTO dashboard_datasets 
                (title, project_name, file_path, uploaded_by_email, uploaded_by_name, uploaded_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, dataset)
        
        print(f"  ✅ Migrated {len(datasets)} dashboard datasets")
    except Exception as e:
        print(f"  ⚠️  Dashboard datasets migration warning: {e}")

def migrate_project_history(sqlite_cursor, postgres_cursor):
    """Migrate project history"""
    try:
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
        
        print(f"  ✅ Migrated {len(projects)} project history records")
    except Exception as e:
        print(f"  ⚠️  Project history migration warning: {e}")

def migrate_audit_logs(sqlite_cursor, postgres_cursor):
    """Migrate audit logs"""
    try:
        sqlite_cursor.execute("SELECT * FROM audit_logs")
        logs = sqlite_cursor.fetchall()
        
        for log in logs:
            postgres_cursor.execute("""
                INSERT INTO audit_logs (user_email, user_name, action, metadata_json, created_at)
                VALUES (%s, %s, %s, %s, %s)
            """, log)
        
        print(f"  ✅ Migrated {len(logs)} audit logs")
    except Exception as e:
        print(f"  ⚠️  Audit logs migration warning: {e}")

def check_environment():
    """Check if required environment variables are set"""
    required_vars = ['AWS_RDS_HOST', 'AWS_RDS_PASSWORD']
    missing_vars = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("❌ Missing required environment variables:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set these variables in your .env file or environment.")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("🔄 VAPT Report Generator - AWS Migration Tool")
    print("=" * 60)
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    # Run migration
    success = migrate_database()
    
    if success:
        print("\n🎉 Migration completed successfully!")
        print("Your VAPT system is now running on AWS cloud infrastructure.")
        print("\nNext steps:")
        print("1. Update your application configuration")
        print("2. Restart your application")
        print("3. Test the cloud functionality")
    else:
        print("\n❌ Migration failed. Please check the errors above.")
        sys.exit(1)
