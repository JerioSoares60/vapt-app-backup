#!/bin/bash

# AWS Cloud Deployment Script for VAPT Report Generator
# This script sets up the cloud infrastructure and migrates data

set -e  # Exit on any error

echo "🚀 Starting AWS Cloud Deployment for VAPT Report Generator"
echo "=================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if running as correct user
if [ "$EUID" -eq 0 ]; then
    print_error "Please don't run this script as root. Run as vaptapp user."
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "migrate_to_aws.py" ]; then
    print_error "Please run this script from the Report-Generator-IP-main directory"
    exit 1
fi

print_info "Step 1: Installing required packages..."

# Install required Python packages
sudo -u vaptapp /opt/vapt-venv/bin/pip install psycopg2-binary boto3 python-dotenv

print_status "Required packages installed"

print_info "Step 2: Setting up environment configuration..."

# Check if .env file exists
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating from example..."
    cp env.example .env
    print_warning "Please edit .env file with your AWS credentials before continuing"
    print_warning "Required variables:"
    print_warning "  - AWS_RDS_HOST"
    print_warning "  - AWS_RDS_PASSWORD"
    print_warning "  - AWS_ACCESS_KEY_ID"
    print_warning "  - AWS_SECRET_ACCESS_KEY"
    print_warning "  - S3 bucket names"
    echo ""
    read -p "Press Enter after updating .env file..."
fi

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
    print_status "Environment variables loaded"
else
    print_error ".env file not found. Please create it first."
    exit 1
fi

print_info "Step 3: Testing AWS RDS connection..."

# Test database connection
python3 -c "
import psycopg2
import os
try:
    conn = psycopg2.connect(
        host=os.getenv('AWS_RDS_HOST'),
        port=int(os.getenv('AWS_RDS_PORT', 5432)),
        database=os.getenv('AWS_RDS_DATABASE'),
        user=os.getenv('AWS_RDS_USER'),
        password=os.getenv('AWS_RDS_PASSWORD')
    )
    conn.close()
    print('✅ Database connection successful')
except Exception as e:
    print(f'❌ Database connection failed: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    print_error "Database connection failed. Please check your RDS configuration."
    exit 1
fi

print_info "Step 4: Testing AWS S3 connection..."

# Test S3 connection
python3 -c "
import boto3
import os
try:
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION')
    )
    s3.list_buckets()
    print('✅ S3 connection successful')
except Exception as e:
    print(f'❌ S3 connection failed: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    print_error "S3 connection failed. Please check your AWS credentials."
    exit 1
fi

print_info "Step 5: Running database migration..."

# Run migration
python3 migrate_to_aws.py

if [ $? -ne 0 ]; then
    print_error "Migration failed. Please check the errors above."
    exit 1
fi

print_status "Database migration completed"

print_info "Step 6: Setting up S3 buckets..."

# Set up S3 buckets
python3 -c "
from s3_service import S3Service
from aws_config import S3_CONFIG
import os

# Load environment variables
for line in open('.env'):
    if line.strip() and not line.startswith('#'):
        key, value = line.strip().split('=', 1)
        os.environ[key] = value

s3_service = S3Service(S3_CONFIG)
if s3_service.setup_buckets():
    print('✅ S3 buckets are ready')
else:
    print('❌ Failed to set up S3 buckets')
    exit(1)
"

if [ $? -ne 0 ]; then
    print_error "S3 bucket setup failed."
    exit 1
fi

print_status "S3 buckets are ready"

print_info "Step 7: Updating application configuration..."

# Update requirements
echo "psycopg2-binary==2.9.9" >> requirements-aws.txt
echo "boto3==1.34.0" >> requirements-aws.txt
echo "python-dotenv==1.0.0" >> requirements-aws.txt

print_status "Application configuration updated"

print_info "Step 8: Restarting application..."

# Restart the application
sudo systemctl restart vapt-app

if [ $? -eq 0 ]; then
    print_status "Application restarted successfully"
else
    print_warning "Application restart failed. Please check manually."
fi

print_info "Step 9: Testing cloud functionality..."

# Test cloud functionality
python3 -c "
from aws_config import validate_config
try:
    validate_config()
    print('✅ Cloud configuration is valid')
except Exception as e:
    print(f'❌ Configuration error: {e}')
    exit(1)
"

if [ $? -ne 0 ]; then
    print_error "Configuration validation failed."
    exit 1
fi

print_status "Cloud functionality test passed"

echo ""
echo "🎉 AWS Cloud Deployment Completed Successfully!"
echo "=================================================="
echo ""
print_info "Your VAPT Report Generator is now running on AWS cloud infrastructure:"
echo "  📊 Database: AWS Aurora PostgreSQL"
echo "  📁 File Storage: AWS S3"
echo "  📈 Analytics: Usage tracking enabled"
echo "  👥 Team Access: Multi-user cloud access"
echo ""
print_info "Next steps:"
echo "  1. Test the application at your EC2 URL"
echo "  2. Generate a test report to verify cloud storage"
echo "  3. Check the analytics dashboard"
echo "  4. Set up monitoring and alerts"
echo ""
print_info "Estimated monthly cost: $20-25 for small team usage"
echo ""
print_status "Deployment completed! 🚀"
