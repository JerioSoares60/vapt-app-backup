#!/usr/bin/env python3
"""
Debug script for POC image mapping
This script helps debug why POC screenshots are not being found
"""

import os
import sys
import zipfile
import tempfile
from pathlib import Path

def debug_poc_images(zip_path, expected_ips=None):
    """
    Debug POC image extraction from ZIP file
    """
    print("🔍 POC Image Debug Tool")
    print("=" * 50)
    
    if not os.path.exists(zip_path):
        print(f"❌ ZIP file not found: {zip_path}")
        return
    
    print(f"📁 Analyzing ZIP file: {zip_path}")
    
    # Extract ZIP to temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        print(f"📂 Extracting to: {temp_dir}")
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
        except Exception as e:
            print(f"❌ Failed to extract ZIP: {e}")
            return
        
        # Find POC Screenshots folder
        screenshots_root = None
        for root, dirs, files in os.walk(temp_dir):
            for d in dirs:
                if d.strip().lower().startswith('poc screenshots'):
                    screenshots_root = os.path.join(root, d)
                    break
            if screenshots_root:
                break
        
        if not screenshots_root:
            print("❌ POC Screenshots folder not found")
            print("📋 Available folders:")
            for root, dirs, files in os.walk(temp_dir):
                for d in dirs:
                    print(f"  - {os.path.join(root, d)}")
            return
        
        print(f"✅ Found POC Screenshots folder: {screenshots_root}")
        
        # Analyze structure
        print("\n📊 ZIP Structure Analysis:")
        print("-" * 30)
        
        for ip_folder in os.listdir(screenshots_root):
            ip_path = os.path.join(screenshots_root, ip_folder)
            if not os.path.isdir(ip_path):
                continue
            
            print(f"\n🌐 IP: {ip_folder}")
            
            for severity in os.listdir(ip_path):
                severity_path = os.path.join(ip_path, severity)
                if not os.path.isdir(severity_path):
                    continue
                
                print(f"  📊 Severity: {severity}")
                
                for vuln_id in os.listdir(severity_path):
                    vuln_path = os.path.join(severity_path, vuln_id)
                    if os.path.isdir(vuln_path) and vuln_id.lower().startswith("vul-"):
                        print(f"    🔍 Vulnerability: {vuln_id}")
                        
                        images = []
                        for fname in os.listdir(vuln_path):
                            if fname.lower().endswith(('.png', '.jpg', '.jpeg')):
                                images.append(fname)
                        
                        if images:
                            print(f"      📸 Images found: {images}")
                            
                            # Show what keys would be generated
                            for i, img in enumerate(images, 1):
                                print(f"        Key {i}: {vuln_id.lower()}_step{i}")
                                print(f"        Key {i}: {vuln_id.lower()}step{i}")
                                print(f"        Key {i}: step{i}")
                                print(f"        Key {i}: {img.lower()}")
                        else:
                            print(f"      ❌ No images found")
        
        # Test specific IPs if provided
        if expected_ips:
            print(f"\n🎯 Testing Expected IPs: {expected_ips}")
            print("-" * 40)
            
            for expected_ip in expected_ips:
                ip_path = os.path.join(screenshots_root, expected_ip)
                if os.path.exists(ip_path):
                    print(f"✅ IP {expected_ip} found")
                    
                    for severity in os.listdir(ip_path):
                        severity_path = os.path.join(ip_path, severity)
                        if os.path.isdir(severity_path):
                            print(f"  📊 Severity: {severity}")
                            
                            for vuln_id in os.listdir(severity_path):
                                vuln_path = os.path.join(severity_path, vuln_id)
                                if os.path.isdir(vuln_path) and vuln_id.lower().startswith("vul-"):
                                    images = [f for f in os.listdir(vuln_path) if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
                                    print(f"    🔍 {vuln_id}: {len(images)} images")
                                    for img in images:
                                        print(f"      📸 {img}")
                else:
                    print(f"❌ IP {expected_ip} not found")

def main():
    if len(sys.argv) < 2:
        print("Usage: python debug_poc_images.py <zip_file_path> [expected_ips...]")
        print("Example: python debug_poc_images.py POC_Screenshots1.zip 172.19.0.155 34.93.151.193")
        return
    
    zip_path = sys.argv[1]
    expected_ips = sys.argv[2:] if len(sys.argv) > 2 else None
    
    debug_poc_images(zip_path, expected_ips)

if __name__ == "__main__":
    main()
