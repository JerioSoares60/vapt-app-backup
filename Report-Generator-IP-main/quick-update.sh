#!/bin/bash

# Quick update script for immediate deployment
# Run this on EC2 when you want to update immediately

echo "🔄 Quick update starting..."

# Stop the service
sudo systemctl stop vapt-app

# Navigate to current app directory
cd /opt/vapt-app/current/Report-Generator-IP-main

# Pull latest changes
sudo -u vaptapp bash -lc "export HOME=/home/vaptapp; git pull origin main"

# Install any new dependencies
sudo -u vaptapp /opt/vapt-venv/bin/pip install -r requirements-aws.txt

# Restart the service
sudo systemctl start vapt-app

# Check status
sleep 3
if sudo systemctl is-active --quiet vapt-app; then
    echo "✅ Quick update successful!"
    sudo systemctl status vapt-app --no-pager
else
    echo "❌ Quick update failed!"
    sudo journalctl -u vapt-app -n 10 --no-pager
fi
