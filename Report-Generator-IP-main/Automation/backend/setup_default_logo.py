#!/usr/bin/env python
"""
Setup script to install the default CyberSmith logo.

This script reads the attached logo image, converts it to base64,
and sends it to the API endpoint to be saved as the default logo.

Usage:
    python setup_default_logo.py

Requirements:
    - requests
    - The FastAPI server must be running on localhost:8004
"""

import os
import sys
import base64
import requests
import argparse

def setup_default_logo(logo_path, api_url="http://localhost:8004/upload-default-logo/"):
    """Upload the default logo to the API."""
    try:
        # Check if file exists
        if not os.path.exists(logo_path):
            print(f"Error: Logo file {logo_path} not found")
            return False
        
        # Read the image and convert to base64
        with open(logo_path, "rb") as image_file:
            base64_bytes = base64.b64encode(image_file.read())
            base64_string = base64_bytes.decode('utf-8')
        
        # Upload to API
        payload = {"base64_image": base64_string}
        response = requests.post(api_url, json=payload)
        
        if response.status_code == 200:
            print("Default logo successfully uploaded and saved")
            return True
        else:
            print(f"Error: HTTP {response.status_code} - {response.text}")
            return False
    
    except Exception as e:
        print(f"Error uploading default logo: {str(e)}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Setup the default CyberSmith logo')
    parser.add_argument('--logo', default='cybersmith_logo.png',
                        help='Path to logo image file (default: cybersmith_logo.png)')
    parser.add_argument('--api', default='http://localhost:8004/upload-default-logo/',
                        help='API endpoint URL (default: http://localhost:8004/upload-default-logo/)')
    
    args = parser.parse_args()
    
    if setup_default_logo(args.logo, args.api):
        sys.exit(0)
    else:
        sys.exit(1) 