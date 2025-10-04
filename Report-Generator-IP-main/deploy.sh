#!/bin/bash

# VAPT App Deployment Script for AWS EC2
# This script can be run manually on the EC2 instance to update the code

set -e  # Exit on any error

echo "🚀 Starting VAPT App deployment..."

# Configuration
APP_DIR="/opt/vapt-app"
VENV_DIR="/opt/vapt-venv"
REPO_URL="git@github.com:JerioSoares60/vapt-app-backup.git"
SERVICE_NAME="vapt-app"

# Create timestamp for new release
TIMESTAMP=$(date +%Y%m%d%H%M%S)
RELEASE_DIR="$APP_DIR/releases/$TIMESTAMP"

echo "📁 Creating new release directory: $RELEASE_DIR"

# Create the release directory
sudo mkdir -p "$RELEASE_DIR"
sudo chown vaptapp:vaptapp "$RELEASE_DIR"

# Clone the latest code
echo "📥 Cloning latest code from GitHub..."
sudo -u vaptapp bash -lc "export HOME=/home/vaptapp; git clone --depth=1 $REPO_URL $RELEASE_DIR"

# Update the current symlink
echo "🔗 Updating current symlink..."
sudo -u vaptapp bash -lc "ln -sfn $RELEASE_DIR $APP_DIR/current"

# Install/update Python dependencies
echo "📦 Installing/updating Python dependencies..."
sudo -u vaptapp "$VENV_DIR/bin/pip" install -r "$APP_DIR/current/Report-Generator-IP-main/requirements-aws.txt"

# Restart the application service
echo "🔄 Restarting application service..."
sudo systemctl restart $SERVICE_NAME

# Wait for service to start
echo "⏳ Waiting for service to start..."
sleep 5

# Check if the service is running
if sudo systemctl is-active --quiet $SERVICE_NAME; then
    echo "✅ Deployment successful! Service is running."
    sudo systemctl status $SERVICE_NAME --no-pager
else
    echo "❌ Deployment failed! Service is not running."
    echo "📋 Recent service logs:"
    sudo journalctl -u $SERVICE_NAME -n 20 --no-pager
    exit 1
fi

# Clean up old releases (keep last 5)
echo "🧹 Cleaning up old releases..."
cd "$APP_DIR/releases"
ls -t | tail -n +6 | xargs -r rm -rf

echo "🎉 Deployment completed successfully!"
echo "🌐 Application should be available at: https://13.202.112.84"
