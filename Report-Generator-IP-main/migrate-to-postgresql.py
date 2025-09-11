#!/usr/bin/env python3
"""
Database Migration Script: SQLite to PostgreSQL
This script helps migrate your existing SQLite database to PostgreSQL on AWS RDS
"""

import os
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_sqlite(db_path):
    """Connect to SQLite database"""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to SQLite: {e}")
        return None

def connect_postgresql(connection_string):
    """Connect to PostgreSQL database"""
    try:
        conn = psycopg2.connect(connection_string)
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to PostgreSQL: {e}")
        return None

def get_sqlite_tables(sqlite_conn):
    """Get list of tables from SQLite"""
    cursor = sqlite_conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row['name'] for row in cursor.fetchall()]
    cursor.close()
    return tables

def get_table_schema(sqlite_conn, table_name):
    """Get table schema from SQLite"""
    cursor = sqlite_conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    cursor.close()
    return columns

def create_postgresql_table(pg_conn, table_name, columns):
    """Create table in PostgreSQL"""
    cursor = pg_conn.cursor()
    
    # Map SQLite types to PostgreSQL types
    type_mapping = {
        'INTEGER': 'INTEGER',
        'REAL': 'DOUBLE PRECISION',
        'TEXT': 'TEXT',
        'BLOB': 'BYTEA',
        'NUMERIC': 'NUMERIC'
    }
    
    # Build CREATE TABLE statement
    column_definitions = []
    for col in columns:
        col_name = col['name']
        col_type = col['type']
        col_notnull = 'NOT NULL' if col['notnull'] else ''
        col_pk = 'PRIMARY KEY' if col['pk'] else ''
        
        pg_type = type_mapping.get(col_type, 'TEXT')
        definition = f"{col_name} {pg_type} {col_notnull} {col_pk}".strip()
        column_definitions.append(definition)
    
    create_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        {', '.join(column_definitions)}
    );
    """
    
    try:
        cursor.execute(create_sql)
        pg_conn.commit()
        logger.info(f"Created table: {table_name}")
        return True
    except Exception as e:
        logger.error(f"Failed to create table {table_name}: {e}")
        pg_conn.rollback()
        return False

def migrate_data(sqlite_conn, pg_conn, table_name):
    """Migrate data from SQLite to PostgreSQL"""
    cursor_sqlite = sqlite_conn.cursor()
    cursor_pg = pg_conn.cursor()
    
    try:
        # Get all data from SQLite
        cursor_sqlite.execute(f"SELECT * FROM {table_name}")
        rows = cursor_sqlite.fetchall()
        
        if not rows:
            logger.info(f"No data to migrate for table: {table_name}")
            return True
        
        # Get column names
        columns = [description[0] for description in cursor_sqlite.description]
        placeholders = ', '.join(['%s'] * len(columns))
        
        # Insert data into PostgreSQL
        insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
        
        for row in rows:
            values = [row[col] for col in columns]
            cursor_pg.execute(insert_sql, values)
        
        pg_conn.commit()
        logger.info(f"Migrated {len(rows)} rows from table: {table_name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to migrate data from table {table_name}: {e}")
        pg_conn.rollback()
        return False
    finally:
        cursor_sqlite.close()
        cursor_pg.close()

def main():
    """Main migration function"""
    print("🚀 SQLite to PostgreSQL Migration Script")
    print("=======================================")
    
    # Configuration
    sqlite_db_path = input("Enter SQLite database path (default: Automation/backend/data.db): ").strip()
    if not sqlite_db_path:
        sqlite_db_path = "Automation/backend/data.db"
    
    pg_connection_string = input("Enter PostgreSQL connection string: ").strip()
    if not pg_connection_string:
        print("❌ PostgreSQL connection string is required!")
        return
    
    # Test connections
    print("\n🔌 Testing database connections...")
    
    sqlite_conn = connect_sqlite(sqlite_db_path)
    if not sqlite_conn:
        print("❌ Failed to connect to SQLite database")
        return
    
    pg_conn = connect_postgresql(pg_connection_string)
    if not pg_conn:
        print("❌ Failed to connect to PostgreSQL database")
        sqlite_conn.close()
        return
    
    print("✅ Both database connections successful!")
    
    # Get tables from SQLite
    tables = get_sqlite_tables(sqlite_conn)
    print(f"\n📋 Found {len(tables)} tables: {', '.join(tables)}")
    
    # Confirm migration
    confirm = input("\n⚠️  This will overwrite existing data in PostgreSQL. Continue? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Migration cancelled")
        return
    
    # Start migration
    print("\n🔄 Starting migration...")
    
    success_count = 0
    total_tables = len(tables)
    
    for table_name in tables:
        print(f"\n📊 Migrating table: {table_name}")
        
        # Get table schema
        columns = get_table_schema(sqlite_conn, table_name)
        
        # Create table in PostgreSQL
        if create_postgresql_table(pg_conn, table_name, columns):
            # Migrate data
            if migrate_data(sqlite_conn, pg_conn, table_name):
                success_count += 1
                print(f"✅ Successfully migrated: {table_name}")
            else:
                print(f"❌ Failed to migrate data: {table_name}")
        else:
            print(f"❌ Failed to create table: {table_name}")
    
    # Migration summary
    print(f"\n🎯 Migration completed!")
    print(f"   Successfully migrated: {success_count}/{total_tables} tables")
    
    if success_count == total_tables:
        print("✅ All tables migrated successfully!")
    else:
        print("⚠️  Some tables failed to migrate. Check logs above.")
    
    # Cleanup
    sqlite_conn.close()
    pg_conn.close()
    
    print("\n📋 Next steps:")
    print("1. Update your .env file with the new DATABASE_URL")
    print("2. Restart your application")
    print("3. Test all functionality")
    print("4. Verify data integrity")

if __name__ == "__main__":
    main()
