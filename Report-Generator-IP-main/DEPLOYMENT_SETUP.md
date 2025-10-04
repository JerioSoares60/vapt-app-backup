# Automated Deployment Setup for AWS EC2

This guide explains how to set up automated deployment from GitHub to your AWS EC2 instance.

## Prerequisites

1. Your code is already deployed on EC2
2. SSH access to your EC2 instance
3. GitHub repository with your code

## Setup Steps

### 1. Configure GitHub Secrets

Go to your GitHub repository → Settings → Secrets and variables → Actions, and add these secrets:

- `EC2_HOST`: Your EC2 public IP (e.g., `13.202.112.84`)
- `EC2_USERNAME`: Your EC2 username (e.g., `ec2-user`)
- `EC2_SSH_KEY`: Your private SSH key content (the entire content of your `.pem` file)

### 2. Set up SSH Deploy Key on EC2

Run these commands on your EC2 instance:

```bash
# Create SSH key for GitHub access
sudo -u vaptapp ssh-keygen -t rsa -b 4096 -C "vaptapp-deploy" -f /home/vaptapp/.ssh/id_rsa -N ""

# Display the public key
sudo -u vaptapp cat /home/vaptapp/.ssh/id_rsa.pub
```

Copy the public key output and add it to your GitHub repository:
1. Go to your GitHub repository → Settings → Deploy keys
2. Click "Add deploy key"
3. Paste the public key content
4. Give it a title like "VAPT App Deploy Key"
5. Check "Allow write access" if you need it

### 3. Test the Setup

1. Make a small change to your code
2. Commit and push to the `main` branch
3. Check the Actions tab in your GitHub repository
4. The deployment should start automatically

## Manual Deployment Options

### Option 1: Use the deploy script
```bash
# On EC2, run:
sudo chmod +x /opt/vapt-app/current/Report-Generator-IP-main/deploy.sh
sudo /opt/vapt-app/current/Report-Generator-IP-main/deploy.sh
```

### Option 2: Quick update (if already deployed)
```bash
# On EC2, run:
sudo chmod +x /opt/vapt-app/current/Report-Generator-IP-main/quick-update.sh
sudo /opt/vapt-app/current/Report-Generator-IP-main/quick-update.sh
```

### Option 3: Manual git pull
```bash
# On EC2, run:
sudo systemctl stop vapt-app
cd /opt/vapt-app/current/Report-Generator-IP-main
sudo -u vaptapp bash -lc "export HOME=/home/vaptapp; git pull origin main"
sudo -u vaptapp /opt/vapt-venv/bin/pip install -r requirements-aws.txt
sudo systemctl start vapt-app
```

## How It Works

1. **Automatic Deployment**: When you push code to the `main` branch, GitHub Actions automatically:
   - Connects to your EC2 instance via SSH
   - Creates a new release directory with timestamp
   - Clones the latest code
   - Updates the current symlink
   - Installs/updates dependencies
   - Restarts the service
   - Cleans up old releases

2. **Manual Deployment**: You can run the deployment scripts manually on EC2 for immediate updates

3. **Rollback**: If something goes wrong, you can manually point the symlink to a previous release directory

## Troubleshooting

### Check service status:
```bash
sudo systemctl status vapt-app
```

### View recent logs:
```bash
sudo journalctl -u vapt-app -n 50 --no-pager
```

### Check if the deployment worked:
```bash
curl -k https://13.202.112.84/health
```

### Manual rollback to previous release:
```bash
# List available releases
ls -la /opt/vapt-app/releases/

# Point to a previous release (replace TIMESTAMP with actual timestamp)
sudo -u vaptapp ln -sfn /opt/vapt-app/releases/TIMESTAMP /opt/vapt-app/current
sudo systemctl restart vapt-app
```

## Security Notes

- The SSH key is stored securely in GitHub Secrets
- Only the `vaptapp` user can access the application files
- Old releases are automatically cleaned up to save disk space
- The deployment process includes error checking and rollback capabilities
