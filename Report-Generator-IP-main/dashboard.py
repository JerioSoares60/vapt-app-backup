"""
Complete Dashboard & Analytics Module - Comprehensive monitoring for all report generators
"""
import os
import pandas as pd
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from db import get_db, AuditLog, CertINReport
import json

# Create dashboard app
dashboard_app = FastAPI(title="Complete Dashboard & Analytics", version="1.0.0")

def extract_comprehensive_data_from_excel(file_path):
    """Extract comprehensive employee and project data from Excel using standardized format.
    - Column detection is case-insensitive and tolerant to minor naming differences
    - Supports the standardized Excel format with all fields
    """
    try:
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        from excel_parser import StandardExcelParser
        
        # Use the unified parser
        parser = StandardExcelParser(file_path)
        if not parser.load():
            return {'error': 'Failed to load Excel file'}
        
        vulnerabilities = parser.extract_vulnerabilities()
        employees = parser.extract_employee_data()
        projects = parser.extract_project_data()
        assets = parser.extract_asset_summary()
        
        # Build comprehensive data structure
        df = parser.df

        # Build a normalized column name index for flexible lookups
        def _normalize(name: str) -> str:
            return ''.join(ch.lower() for ch in str(name).strip() if ch.isalnum())

        normalized_to_real = { _normalize(col): col for col in df.columns }

        def find_col(candidates):
            for cand in candidates:
                key = _normalize(cand)
                if key in normalized_to_real:
                    return normalized_to_real[key]
            # Fall back to fuzzy: try startswith for partials
            for real in df.columns:
                if any(_normalize(real).startswith(_normalize(c)) for c in candidates):
                    return real
            return None
        data = {
            'employees': {},
            'projects': {},
            'clients': {},
            'assets': {},
            'vulnerabilities': [],
            'summary': {
                'total_vulnerabilities': len(df),
                'total_employees': 0,
                'total_projects': 0,
                'total_clients': 0,
                'total_assets': 0,
                'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            }
        }
        
        # Employee columns to check (in order of preference)
        employee_columns = ['Tester_Name', 'Tester Name', 'ReportedBy', 'Tester', 'Employee_Name', 'Employee Name', 'Name', 'Analyst']
        employee_col = None
        for col in employee_columns:
            if col in df.columns:
                employee_col = col
                break
        
        # Project/Client/Asset columns to check
        project_columns = ['Project', 'Project_Name', 'Project Name', 'ProjectName', 'Assessment']
        client_columns = ['Client_Name', 'Client Name', 'ClientName', 'Client', 'Organization']
        asset_columns = ['Asset/Hostname', 'Asset Hostname', 'Asset_Hostname', 'Hostname', 'Asset', 'URL', 'IP', 'IP_Address', 'Target']
        purpose_columns = ['Instant purpose', 'Instant Purpose', 'Purpose', 'Asset_Purpose', 'Application_Type']
        status_columns = ['VAPT Status', 'VAPT_Status', 'Assessment_Status', 'Status']
        severity_columns = ['Severity', 'Risk', 'Risk Level', 'Risk_Level', 'Priority']
        date_columns = ['Date', 'Created_Date', 'Created Date', 'Reported_Date', 'Assessment_Date']
        
        # Vulnerability detail columns
        title_columns = ['Vulnerability Title', 'Title', 'Vulnerability_Name', 'Vulnerability Name', 'Observation_Title']
        description_columns = ['Description', 'Vulnerability_Description', 'Vulnerability Description', 'Detailed_Observation', 'Vulnerable_Point']
        cve_columns = ['CVE/CWE', 'CVE', 'CWE', 'CVE_CWE']
        cvss_columns = ['CVSS', 'CVSS Score', 'CVSS_Score', 'CVSS_Vector']
        affected_asset_columns = ['Affected Asset', 'Affected_Asset', 'Target_Asset', 'Asset_IP', 'Affected Asset ie. IP/URL/Application etc.']
        recommendation_columns = ['Recommendation', 'Remediation', 'Solution', 'Fix']
        reference_columns = ['Reference', 'References', 'Links', 'URL']
        
        # Step columns (look for Step1, Step2, etc.)
        step_columns = []
        for i in range(1, 10):  # Check for up to 9 steps
            step_cols = [f'Step{i}', f'Step {i}', f'PoC_Step{i}', f'Proof_of_Concept_Step{i}']
            step_columns.extend(step_cols)
        
        project_col = find_col(project_columns)
        client_col = find_col(client_columns)
        asset_col = find_col(asset_columns)
        purpose_col = find_col(purpose_columns)
        status_col = find_col(status_columns)
        severity_col = find_col(severity_columns)
        date_col = find_col(date_columns)

        # Optional per-row count columns (use when available)
        count_col_critical = find_col(['Critical'])
        count_col_high = find_col(['High'])
        count_col_medium = find_col(['Medium'])
        count_col_low = find_col(['Low'])
        count_col_info = find_col(['Informational', 'Information', 'Info'])
        count_col_total = find_col(['Total'])
        
        # Process each row
        for idx, row in df.iterrows():
            # Employee data
            if employee_col:
                employee_name = str(row.get(employee_col, '')).strip()
                if employee_name and employee_name != 'nan':
                    if employee_name not in data['employees']:
                        data['employees'][employee_name] = {
                            'name': employee_name,
                            'total_vulnerabilities': 0,
                            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                            'projects': set(),
                            'clients': set(),
                            'last_activity': None,
                            'avg_severity_score': 0
                        }
                    
                    data['employees'][employee_name]['total_vulnerabilities'] += 1
                    
                    # Severity counting
                    if severity_col:
                        severity = str(row.get(severity_col, '')).strip().lower()
                        if 'critical' in severity or '5' in severity:
                            data['employees'][employee_name]['critical'] += 1
                            data['summary']['severity_breakdown']['Critical'] += 1
                        elif 'high' in severity or '4' in severity:
                            data['employees'][employee_name]['high'] += 1
                            data['summary']['severity_breakdown']['High'] += 1
                        elif 'medium' in severity or '3' in severity:
                            data['employees'][employee_name]['medium'] += 1
                            data['summary']['severity_breakdown']['Medium'] += 1
                        elif 'low' in severity or '2' in severity:
                            data['employees'][employee_name]['low'] += 1
                            data['summary']['severity_breakdown']['Low'] += 1
                        else:
                            data['employees'][employee_name]['info'] += 1
                            data['summary']['severity_breakdown']['Info'] += 1
                    
                    # Project and client tracking
                    if project_col:
                        project_name = str(row.get(project_col, '')).strip()
                        if project_name and project_name != 'nan':
                            data['employees'][employee_name]['projects'].add(project_name)
                    
                    if client_col:
                        client_name = str(row.get(client_col, '')).strip()
                        if client_name and client_name != 'nan':
                            data['employees'][employee_name]['clients'].add(client_name)
            
            # Project data
            if project_col:
                project_name = str(row.get(project_col, '')).strip()
                if project_name and project_name != 'nan':
                    if project_name not in data['projects']:
                        data['projects'][project_name] = {
                            'name': project_name,
                            'total_vulnerabilities': 0,
                            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                            'employees': set(),
                            'clients': set(),
                            'last_activity': None
                        }
                    
                    data['projects'][project_name]['total_vulnerabilities'] += 1
                    
                    if employee_col and employee_name:
                        data['projects'][project_name]['employees'].add(employee_name)
                    
                    if client_col:
                        client_name = str(row.get(client_col, '')).strip()
                        if client_name and client_name != 'nan':
                            data['projects'][project_name]['clients'].add(client_name)
            
            # Asset data
            if asset_col:
                asset_name = str(row.get(asset_col, '')).strip()
                if asset_name and asset_name != 'nan':
                    if asset_name not in data['assets']:
                        data['assets'][asset_name] = {
                            'name': asset_name,
                            'purpose': str(row.get(purpose_col, '')).strip() if purpose_col else 'Unknown',
                            'status': str(row.get(status_col, '')).strip() if status_col else 'Unknown',
                            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                            'total_vulnerabilities': 0,
                            'employees': set(),
                            'projects': set(),
                            'clients': set()
                        }
                    
                    # Prefer explicit count columns if present; otherwise derive from single severity
                    if all(col is not None for col in [count_col_critical, count_col_high, count_col_medium, count_col_low, count_col_info]):
                        c = int(row.get(count_col_critical) or 0)
                        h = int(row.get(count_col_high) or 0)
                        m = int(row.get(count_col_medium) or 0)
                        l = int(row.get(count_col_low) or 0)
                        i = int(row.get(count_col_info) or 0)
                        data['assets'][asset_name]['critical'] += c
                        data['assets'][asset_name]['high'] += h
                        data['assets'][asset_name]['medium'] += m
                        data['assets'][asset_name]['low'] += l
                        data['assets'][asset_name]['info'] += i
                        total_here = c + h + m + l + i
                        data['assets'][asset_name]['total_vulnerabilities'] += total_here
                    else:
                        data['assets'][asset_name]['total_vulnerabilities'] += 1
                        if severity_col:
                            severity = str(row.get(severity_col, '')).strip().lower()
                            if 'critical' in severity or '5' in severity:
                                data['assets'][asset_name]['critical'] += 1
                            elif 'high' in severity or '4' in severity:
                                data['assets'][asset_name]['high'] += 1
                            elif 'medium' in severity or '3' in severity:
                                data['assets'][asset_name]['medium'] += 1
                            elif 'low' in severity or '2' in severity:
                                data['assets'][asset_name]['low'] += 1
                            else:
                                data['assets'][asset_name]['info'] += 1
                    
                    # Track related entities
                    if employee_col and employee_name:
                        data['assets'][asset_name]['employees'].add(employee_name)
                    if project_col and project_name:
                        data['assets'][asset_name]['projects'].add(project_name)
                    if client_col and client_name:
                        data['assets'][asset_name]['clients'].add(client_name)
            
            # Client data
            if client_col:
                client_name = str(row.get(client_col, '')).strip()
                if client_name and client_name != 'nan':
                    if client_name not in data['clients']:
                        data['clients'][client_name] = {
                            'name': client_name,
                            'total_vulnerabilities': 0,
                            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                            'projects': set(),
                            'employees': set(),
                            'last_activity': None
                        }
                    
                    data['clients'][client_name]['total_vulnerabilities'] += 1
                    
                    if project_col and project_name:
                        data['clients'][client_name]['projects'].add(project_name)
                    
                    if employee_col and employee_name:
                        data['clients'][client_name]['employees'].add(employee_name)
            
            # Extract vulnerability details for each row
            vuln_detail = {
                'observation_number': idx + 1,
                'severity': str(row.get(severity_col, '')).strip() if severity_col else 'Unknown',
                'status': str(row.get(status_col, '')).strip() if status_col else 'Open',
                'title': '',
                'description': '',
                'cve_cwe': '',
                'cvss': '',
                'affected_asset': '',
                'recommendation': '',
                'reference': '',
                'steps': [],
                'employee': employee_name if employee_col else 'Unknown',
                'project': project_name if project_col else 'Unknown',
                'client': client_name if client_col else 'Unknown'
            }
            
            # Extract vulnerability details
            for col in title_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['title'] = str(row[col]).strip()
                    break
            
            for col in description_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['description'] = str(row[col]).strip()
                    break
            
            for col in cve_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['cve_cwe'] = str(row[col]).strip()
                    break
            
            for col in cvss_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['cvss'] = str(row[col]).strip()
                    break
            
            for col in affected_asset_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['affected_asset'] = str(row[col]).strip()
                    break
            
            for col in recommendation_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['recommendation'] = str(row[col]).strip()
                    break
            
            for col in reference_columns:
                if col in df.columns and pd.notna(row[col]):
                    vuln_detail['reference'] = str(row[col]).strip()
                    break
            
            # Extract steps (look for Step1, Step2, etc.)
            for i in range(1, 10):
                step_cols = [f'Step{i}', f'Step {i}', f'PoC_Step{i}', f'Proof_of_Concept_Step{i}']
                for col in step_cols:
                    if col in df.columns and pd.notna(row[col]):
                        vuln_detail['steps'].append({
                            'step_number': i,
                            'content': str(row[col]).strip()
                        })
                        break
            
            data['vulnerabilities'].append(vuln_detail)
        
        # Convert sets to counts and calculate performance scores
        for emp_name, emp_data in data['employees'].items():
            emp_data['projects'] = list(emp_data['projects'])
            emp_data['clients'] = list(emp_data['clients'])
            emp_data['project_count'] = len(emp_data['projects'])
            emp_data['client_count'] = len(emp_data['clients'])
            
            # Calculate performance score
            score = (emp_data['critical'] * 10 + emp_data['high'] * 5 + 
                    emp_data['medium'] * 2 + emp_data['low'] * 1)
            emp_data['performance_score'] = min(score, 100)
        
        for proj_name, proj_data in data['projects'].items():
            proj_data['employees'] = list(proj_data['employees'])
            proj_data['clients'] = list(proj_data['clients'])
            proj_data['employee_count'] = len(proj_data['employees'])
            proj_data['client_count'] = len(proj_data['clients'])
        
        for client_name, client_data in data['clients'].items():
            client_data['projects'] = list(client_data['projects'])
            client_data['employees'] = list(client_data['employees'])
            client_data['project_count'] = len(client_data['projects'])
            client_data['employee_count'] = len(client_data['employees'])
        
        # Convert asset sets to counts
        for asset_name, asset_data in data['assets'].items():
            asset_data['employees'] = list(asset_data['employees'])
            asset_data['projects'] = list(asset_data['projects'])
            asset_data['clients'] = list(asset_data['clients'])
            asset_data['employee_count'] = len(asset_data['employees'])
            asset_data['project_count'] = len(asset_data['projects'])
            asset_data['client_count'] = len(asset_data['clients'])
        
        # Update summary counts
        data['summary']['total_employees'] = len(data['employees'])
        data['summary']['total_projects'] = len(data['projects'])
        data['summary']['total_clients'] = len(data['clients'])
        data['summary']['total_assets'] = len(data['assets'])
        
        return data
        
    except Exception as e:
        print(f"Error extracting comprehensive data: {e}")
        return None

async def get_usage_logs(db: Session, limit: int = 200):
    """Get comprehensive usage logs from database"""
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
        return [
            {
                'id': log.id,
                'user_email': log.user_email,
                'user_name': log.user_name,
                'action': log.action,
                'details': log.metadata_json or '',
                'timestamp': log.created_at.isoformat(),
                'ip_address': log.ip_address,
                'date': log.created_at.strftime('%Y-%m-%d'),
                'time': log.created_at.strftime('%H:%M:%S')
            }
            for log in logs
        ]
    except Exception as e:
        print(f"Error getting usage logs: {e}")
        return []

async def get_report_statistics(db: Session):
    """Get comprehensive report generation statistics"""
    try:
        # Get Cert-IN reports
        certin_reports = db.query(CertINReport).all()
        
        # Get usage logs for additional stats
        usage_logs = await get_usage_logs(db, 1000)
        
        # Calculate daily activity
        daily_activity = {}
        user_activity = {}
        action_breakdown = {}
        
        for log in usage_logs:
            date = log['date']
            user = log['user_email']
            action = log['action']
            
            # Daily activity
            if date not in daily_activity:
                daily_activity[date] = 0
            daily_activity[date] += 1
            
            # User activity
            if user not in user_activity:
                user_activity[user] = {'total_actions': 0, 'actions': {}}
            user_activity[user]['total_actions'] += 1
            
            if action not in user_activity[user]['actions']:
                user_activity[user]['actions'][action] = 0
            user_activity[user]['actions'][action] += 1
            
            # Action breakdown
            if action not in action_breakdown:
                action_breakdown[action] = 0
            action_breakdown[action] += 1
        
        stats = {
            'total_reports': len(certin_reports),
            'total_actions': len(usage_logs),
            'active_users': len(user_activity),
            'active_days': len(daily_activity),
            'reports_by_type': {
                'Cert-IN Reports': len(certin_reports),
                'Type-1 Reports': action_breakdown.get('generate-report-type1', 0),
                'Type-2 Reports': action_breakdown.get('generate-report-type2', 0)
            },
            'daily_activity': daily_activity,
            'user_activity': user_activity,
            'action_breakdown': action_breakdown,
            'recent_activity': usage_logs[:10]  # Last 10 activities
        }
        
        return stats
    except Exception as e:
        print(f"Error getting report statistics: {e}")
        return {'total_reports': 0, 'total_actions': 0, 'active_users': 0, 'active_days': 0, 'reports_by_type': {}, 'daily_activity': {}, 'user_activity': {}, 'action_breakdown': {}, 'recent_activity': []}

@dashboard_app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Complete dashboard with comprehensive analytics"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Complete Dashboard & Analytics</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .container { max-width: 1600px; margin: 0 auto; }
            h1 { color: white; text-align: center; margin-bottom: 30px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
            .nav-buttons { text-align: center; margin-bottom: 30px; }
            .btn { background-color: #28a745; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; margin: 5px; text-decoration: none; display: inline-block; font-weight: bold; }
            .btn:hover { background-color: #218838; }
            .btn-secondary { background-color: #6c757d; }
            .btn-secondary:hover { background-color: #5a6268; }
            .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .chart-container { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .stat-card { background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 25px; border-radius: 12px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
            .stat-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
            .stat-label { font-size: 1em; opacity: 0.9; }
            .table-container { background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); margin-bottom: 20px; }
            .data-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            .data-table th, .data-table td { padding: 15px; text-align: left; border-bottom: 2px solid #f8f9fa; }
            .data-table th { background: linear-gradient(135deg, #667eea, #764ba2); color: white; font-weight: bold; }
            .data-table tr:hover { background-color: #f8f9fa; }
            .severity-critical { color: #dc3545; font-weight: bold; }
            .severity-high { color: #fd7e14; font-weight: bold; }
            .severity-medium { color: #ffc107; font-weight: bold; }
            .severity-low { color: #28a745; font-weight: bold; }
            .upload-section { background: white; padding: 25px; border-radius: 12px; margin-bottom: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
            .tab-container { margin-bottom: 20px; }
            .tab-buttons { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
            .tab-content { display: none; }
            .tab-content.active { display: block; }
            .search-box { margin-bottom: 15px; }
            .search-box input { padding: 12px; width: 300px; border: 2px solid #e9ecef; border-radius: 6px; font-size: 14px; }
            .search-box input:focus { outline: none; border-color: #667eea; }
            .excel-requirements { background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #2196f3; }
            .excel-requirements h4 { color: #1976d2; margin-top: 0; }
            .excel-requirements ul { margin: 10px 0; }
            .excel-requirements li { margin: 5px 0; }
            .performance-badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
            .performance-excellent { background: #d4edda; color: #155724; }
            .performance-good { background: #d1ecf1; color: #0c5460; }
            .performance-average { background: #fff3cd; color: #856404; }
            .performance-poor { background: #f8d7da; color: #721c24; }
            
            /* Vulnerability Box Styles */
            .vulnerability-box { 
                display: flex; 
                gap: 10px; 
                margin: 10px 0; 
                align-items: center;
            }
            .severity-box { 
                padding: 8px 16px; 
                border-radius: 4px; 
                font-weight: bold; 
                color: white;
                text-align: center;
                min-width: 100px;
            }
            .severity-critical { background-color: #dc3545; }
            .severity-high { background-color: #fd7e14; }
            .severity-medium { background-color: #ffc107; color: #212529; }
            .severity-low { background-color: #28a745; }
            .severity-info { background-color: #17a2b8; }
            .status-box { 
                padding: 8px 16px; 
                border-radius: 4px; 
                font-weight: bold; 
                color: white;
                text-align: center;
                min-width: 80px;
            }
            .status-open { background-color: #ffc107; color: #212529; }
            .status-closed { background-color: #28a745; }
            .status-pending { background-color: #17a2b8; }
            
            .vulnerability-detail { 
                background: white; 
                margin: 20px 0; 
                padding: 25px; 
                border-radius: 12px; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                border-left: 4px solid #667eea;
            }
            .vulnerability-header { 
                display: flex; 
                justify-content: space-between; 
                align-items: center; 
                margin-bottom: 20px;
                flex-wrap: wrap;
                gap: 10px;
            }
            .vulnerability-title { 
                font-size: 1.4em; 
                font-weight: bold; 
                color: #333;
                margin: 0;
            }
            .vulnerability-info { 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                gap: 15px; 
                margin: 20px 0;
            }
            .info-item { 
                display: flex; 
                flex-direction: column;
            }
            .info-label { 
                font-weight: bold; 
                color: #667eea; 
                margin-bottom: 5px;
            }
            .info-value { 
                color: #333; 
                background: #f8f9fa; 
                padding: 8px; 
                border-radius: 4px;
            }
            .vulnerability-description { 
                margin: 20px 0; 
                line-height: 1.6;
                color: #333;
            }
            .steps-container { 
                margin: 20px 0;
            }
            .step-item { 
                margin: 15px 0; 
                padding: 15px; 
                background: #f8f9fa; 
                border-radius: 8px; 
                border-left: 4px solid #667eea;
            }
            .step-number { 
                font-weight: bold; 
                color: #667eea; 
                margin-bottom: 10px;
            }
            .step-content { 
                color: #333; 
                line-height: 1.5;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Complete Dashboard & Analytics</h1>
            
            <div class="nav-buttons">
                <a href="/report_formats.html" class="btn btn-secondary">← Back to Report Formats</a>
                <button onclick="loadAllData()" class="btn">🔄 Refresh All Data</button>
            </div>
            
            <div class="upload-section">
                <h3>📁 Upload Excel File for Comprehensive Analysis</h3>
                <div class="excel-requirements">
                    <h4>📋 Required Excel Columns for Complete Analysis:</h4>
                    <ul>
                        <li><strong>Employee Identification:</strong> Tester_Name, ReportedBy, Tester, Employee_Name, Name, or Analyst</li>
                        <li><strong>Project Information:</strong> Project, Project_Name, ProjectName, or Assessment</li>
                        <li><strong>Client Information:</strong> Client_Name, ClientName, Client, or Organization</li>
                        <li><strong>Severity/Risk:</strong> Severity, Risk, Risk_Level, or Priority</li>
                        <li><strong>Date Information:</strong> Date, Created_Date, Reported_Date, or Assessment_Date (optional)</li>
                    </ul>
                    <p><strong>Note:</strong> The system will automatically detect which columns are available and use the best match.</p>
                </div>
                <input type="file" id="excelFile" accept=".xlsx,.xls" style="margin-bottom: 15px; padding: 10px;">
                <button onclick="analyzeComprehensiveData()" class="btn">🚀 Analyze Complete Data</button>
            </div>
            
            <div class="tab-container">
                <div class="tab-buttons">
                    <button onclick="showTab('overview-tab')" class="btn" id="overview-tab-btn">📊 Overview</button>
                    <button onclick="showTab('asset-table-tab')" class="btn" id="asset-table-tab-btn">📋 Asset VAPT Table</button>
                    <button onclick="showTab('vulnerability-details-tab')" class="btn" id="vulnerability-details-tab-btn">🔍 Vulnerability Details</button>
                    <button onclick="showTab('employee-tab')" class="btn" id="employee-tab-btn">👥 Employee Analytics</button>
                    <button onclick="showTab('project-tab')" class="btn" id="project-tab-btn">📁 Project Analytics</button>
                    <button onclick="showTab('client-tab')" class="btn" id="client-tab-btn">🏢 Client Analytics</button>
                    <button onclick="showTab('usage-tab')" class="btn" id="usage-tab-btn">📋 Usage Logs</button>
                    <button onclick="showTab('stats-tab')" class="btn" id="stats-tab-btn">📈 System Statistics</button>
                </div>
                
                <div id="overview-tab" class="tab-content active">
                    <div id="overview-content" style="display: none;">
                        <div class="stats-grid" id="overview-stats-grid"></div>
                        <div class="dashboard-grid">
                            <div class="chart-container">
                                <h3>📊 Severity Distribution</h3>
                                <canvas id="severityOverviewChart"></canvas>
                            </div>
                            <div class="chart-container">
                                <h3>👥 Top Performers</h3>
                                <canvas id="topPerformersChart"></canvas>
                            </div>
                        </div>
                        <div class="chart-container">
                            <h3>📈 Activity Timeline</h3>
                            <canvas id="activityTimelineChart"></canvas>
                        </div>
                    </div>
                </div>
                
                <div id="asset-table-tab" class="tab-content">
                    <div class="table-container">
                        <h3>📋 Dynamic Asset VAPT Status Table</h3>
                        <div class="search-box">
                            <input type="text" id="assetSearch" placeholder="Search assets..." onkeyup="filterAssetTable()">
                        </div>
                        <table class="data-table" id="assetTable">
                            <thead>
                                <tr style="background: linear-gradient(135deg, #667eea, #764ba2); color: white;">
                                    <th style="background: #8e24aa; color: white;">Sr. No.</th>
                                    <th style="background: #8e24aa; color: white;">Asset/Hostname</th>
                                    <th style="background: #8e24aa; color: white;">Instant Purpose</th>
                                    <th style="background: #8e24aa; color: white;">VAPT Status</th>
                                    <th style="background: #dc3545; color: white;">Critical</th>
                                    <th style="background: #fd7e14; color: white;">High</th>
                                    <th style="background: #ffc107; color: white;">Medium</th>
                                    <th style="background: #28a745; color: white;">Low</th>
                                    <th style="background: #17a2b8; color: white;">Informational</th>
                                    <th style="background: #8e24aa; color: white;">Total</th>
                                    <th style="background: #8e24aa; color: white;">Tester Name</th>
                                </tr>
                            </thead>
                            <tbody id="assetTableBody"></tbody>
                            <tfoot>
                                <tr style="background: #f8f9fa; font-weight: bold;">
                                    <td colspan="4" style="text-align: left; background: #e9ecef;">Overall Findings</td>
                                    <td id="totalCritical" style="background: #dc3545; color: white; font-weight: bold;">0</td>
                                    <td id="totalHigh" style="background: #fd7e14; color: white; font-weight: bold;">0</td>
                                    <td id="totalMedium" style="background: #ffc107; color: white; font-weight: bold;">0</td>
                                    <td id="totalLow" style="background: #28a745; color: white; font-weight: bold;">0</td>
                                    <td id="totalInfo" style="background: #17a2b8; color: white; font-weight: bold;">0</td>
                                    <td id="totalAll" style="background: #8e24aa; color: white; font-weight: bold;">0</td>
                                    <td></td>
                                </tr>
                            </tfoot>
                        </table>
                        <div style="margin-top: 15px;">
                            <button onclick="addAssetRow()" style="background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                                ➕ Add New Asset Row
                            </button>
                        </div>
                    </div>
                </div>
                
                <div id="vulnerability-details-tab" class="tab-content">
                    <div id="vulnerability-details-content" style="display: none;">
                        <div class="search-box">
                            <input type="text" id="vulnSearch" placeholder="Search vulnerabilities..." onkeyup="filterVulnerabilityDetails()">
                        </div>
                        <div id="vulnerabilityDetailsContainer"></div>
                    </div>
                </div>
                
                <div id="employee-tab" class="tab-content">
                    <div class="table-container">
                        <h3>👥 Employee Performance Analysis</h3>
                        <div class="search-box">
                            <input type="text" id="employeeSearch" placeholder="Search employees..." onkeyup="filterEmployeeTable()">
                        </div>
                        <table class="data-table" id="employeeTable">
                            <thead>
                                <tr>
                                    <th>Employee</th>
                                    <th>Projects</th>
                                    <th>Clients</th>
                                    <th>Total Vulns</th>
                                    <th>Critical</th>
                                    <th>High</th>
                                    <th>Medium</th>
                                    <th>Low</th>
                                    <th>Performance</th>
                                </tr>
                            </thead>
                            <tbody id="employeeTableBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <div id="project-tab" class="tab-content">
                    <div class="table-container">
                        <h3>📁 Project Analysis</h3>
                        <div class="search-box">
                            <input type="text" id="projectSearch" placeholder="Search projects..." onkeyup="filterProjectTable()">
                        </div>
                        <table class="data-table" id="projectTable">
                            <thead>
                                <tr>
                                    <th>Project Name</th>
                                    <th>Clients</th>
                                    <th>Team Size</th>
                                    <th>Total Vulns</th>
                                    <th>Critical</th>
                                    <th>High</th>
                                    <th>Medium</th>
                                    <th>Low</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody id="projectTableBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <div id="client-tab" class="tab-content">
                    <div class="table-container">
                        <h3>🏢 Client Analysis</h3>
                        <div class="search-box">
                            <input type="text" id="clientSearch" placeholder="Search clients..." onkeyup="filterClientTable()">
                        </div>
                        <table class="data-table" id="clientTable">
                            <thead>
                                <tr>
                                    <th>Client Name</th>
                                    <th>Projects</th>
                                    <th>Team Size</th>
                                    <th>Total Vulns</th>
                                    <th>Critical</th>
                                    <th>High</th>
                                    <th>Medium</th>
                                    <th>Low</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody id="clientTableBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <div id="usage-tab" class="tab-content">
                    <div class="table-container">
                        <h3>📋 System Usage Logs</h3>
                        <div class="search-box">
                            <input type="text" id="usageSearch" placeholder="Search logs..." onkeyup="filterUsageTable()">
                        </div>
                        <table class="data-table" id="usageTable">
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>Time</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Details</th>
                                    <th>IP Address</th>
                                </tr>
                            </thead>
                            <tbody id="usageTableBody"></tbody>
                        </table>
                    </div>
                </div>
                
                <div id="stats-tab" class="tab-content">
                    <div class="stats-grid" id="system-stats-grid"></div>
                    <div class="dashboard-grid">
                        <div class="chart-container">
                            <h3>📊 Report Types</h3>
                            <canvas id="reportTypeChart"></canvas>
                        </div>
                        <div class="chart-container">
                            <h3>👥 User Activity</h3>
                            <canvas id="userActivityChart"></canvas>
                        </div>
                    </div>
                    <div class="chart-container">
                        <h3>📈 Daily Activity Trend</h3>
                        <canvas id="dailyActivityChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let comprehensiveData = null;
            let usageLogs = [];
            let systemStats = {};
            let charts = {};

            // Tab functionality
            function showTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                document.querySelectorAll('.tab-buttons .btn').forEach(btn => {
                    btn.style.backgroundColor = '#28a745';
                });
                
                document.getElementById(tabName).classList.add('active');
                document.getElementById(tabName + '-btn').style.backgroundColor = '#218838';
            }

            // Load all data
            async function loadAllData() {
                try {
                    await Promise.all([
                        loadUsageLogs(),
                        loadSystemStats()
                    ]);
                } catch (error) {
                    console.error('Error loading data:', error);
                }
            }

            // Comprehensive data analysis
            async function analyzeComprehensiveData() {
                const fileInput = document.getElementById('excelFile');
                const file = fileInput.files[0];
                
                if (!file) {
                    alert('Please select an Excel file');
                    return;
                }

                const formData = new FormData();
                formData.append('excel_file', file);

                try {
                    const response = await fetch('/dashboard/analyze-comprehensive/', {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        throw new Error('Analysis failed');
                    }

                    comprehensiveData = await response.json();
                    displayOverview();
                    updateAssetTable();
                    updateVulnerabilityDetails();
                    updateEmployeeTable();
                    updateProjectTable();
                    updateClientTable();
                } catch (error) {
                    alert('Error analyzing file: ' + error.message);
                }
            }

            function displayOverview() {
                if (!comprehensiveData) return;
                
                document.getElementById('overview-content').style.display = 'block';
                updateOverviewStats();
                createOverviewCharts();
            }

            function updateOverviewStats() {
                const statsGrid = document.getElementById('overview-stats-grid');
                const summary = comprehensiveData.summary;
                
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${summary.total_employees}</div>
                        <div class="stat-label">Active Employees</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${summary.total_projects}</div>
                        <div class="stat-label">Active Projects</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${summary.total_clients}</div>
                        <div class="stat-label">Active Clients</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${summary.total_vulnerabilities}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${summary.severity_breakdown.Critical}</div>
                        <div class="stat-label">Critical Issues</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${summary.severity_breakdown.High}</div>
                        <div class="stat-label">High Risk Issues</div>
                    </div>
                `;
            }

            function createOverviewCharts() {
                // Severity Distribution Chart
                const ctx1 = document.getElementById('severityOverviewChart').getContext('2d');
                if (charts.severityOverview) charts.severityOverview.destroy();
                
                const severityData = comprehensiveData.summary.severity_breakdown;
                charts.severityOverview = new Chart(ctx1, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(severityData),
                        datasets: [{
                            data: Object.values(severityData),
                            backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745', '#6c757d']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });

                // Top Performers Chart
                const ctx2 = document.getElementById('topPerformersChart').getContext('2d');
                if (charts.topPerformers) charts.topPerformers.destroy();
                
                const topPerformers = Object.values(comprehensiveData.employees)
                    .sort((a, b) => b.performance_score - a.performance_score)
                    .slice(0, 5);
                
                charts.topPerformers = new Chart(ctx2, {
                    type: 'bar',
                    data: {
                        labels: topPerformers.map(emp => emp.name),
                        datasets: [{
                            label: 'Performance Score',
                            data: topPerformers.map(emp => emp.performance_score),
                            backgroundColor: '#667eea',
                            borderColor: '#764ba2',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true, max: 100 }
                        }
                    }
                });
            }

            function updateAssetTable() {
                if (!comprehensiveData) return;
                
                const tbody = document.getElementById('assetTableBody');
                tbody.innerHTML = '';
                
                let totalCritical = 0, totalHigh = 0, totalMedium = 0, totalLow = 0, totalInfo = 0, totalAll = 0;

                Object.values(comprehensiveData.assets).forEach((asset, index) => {
                    const total = asset.critical + asset.high + asset.medium + asset.low + asset.info;
                    totalCritical += asset.critical;
                    totalHigh += asset.high;
                    totalMedium += asset.medium;
                    totalLow += asset.low;
                    totalInfo += asset.info;
                    totalAll += total;
                    
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${index + 1}</td>
                        <td>${asset.name}</td>
                        <td>${asset.purpose}</td>
                        <td>${asset.status}</td>
                        <td class="severity-critical">${asset.critical}</td>
                        <td class="severity-high">${asset.high}</td>
                        <td class="severity-medium">${asset.medium}</td>
                        <td class="severity-low">${asset.low}</td>
                        <td class="severity-info">${asset.info}</td>
                        <td><strong>${total}</strong></td>
                        <td>${asset.employees.join(', ') || 'Unknown'}</td>
                    `;
                    tbody.appendChild(row);
                });
                
                // Update totals
                document.getElementById('totalCritical').textContent = totalCritical;
                document.getElementById('totalHigh').textContent = totalHigh;
                document.getElementById('totalMedium').textContent = totalMedium;
                document.getElementById('totalLow').textContent = totalLow;
                document.getElementById('totalInfo').textContent = totalInfo;
                document.getElementById('totalAll').textContent = totalAll;
            }

            function updateVulnerabilityDetails() {
                if (!comprehensiveData) return;
                
                const container = document.getElementById('vulnerabilityDetailsContainer');
                container.innerHTML = '';
                
                document.getElementById('vulnerability-details-content').style.display = 'block';

                comprehensiveData.vulnerabilities.forEach(vuln => {
                    const vulnDiv = document.createElement('div');
                    vulnDiv.className = 'vulnerability-detail';
                    
                    const severityClass = getSeverityClass(vuln.severity);
                    const statusClass = getStatusClass(vuln.status);
                    
                    let stepsHtml = '';
                    if (vuln.steps && vuln.steps.length > 0) {
                        stepsHtml = `
                            <div class="steps-container">
                                <h4>Proof of Concept Steps:</h4>
                                ${vuln.steps.map(step => `
                                    <div class="step-item">
                                        <div class="step-number">Step ${step.step_number}:</div>
                                        <div class="step-content">${step.content}</div>
                                    </div>
                                `).join('')}
                            </div>
                        `;
                    }
                    
                    vulnDiv.innerHTML = `
                        <div class="vulnerability-header">
                            <h3 class="vulnerability-title">Observation #${vuln.observation_number}</h3>
                            <div class="vulnerability-box">
                                <div class="severity-box ${severityClass}">Severity: ${vuln.severity}</div>
                                <div class="status-box ${statusClass}">Status: ${vuln.status}</div>
                            </div>
                        </div>
                        
                        <div class="vulnerability-info">
                            <div class="info-item">
                                <div class="info-label">CVE/CWE:</div>
                                <div class="info-value">${vuln.cve_cwe || 'N/A'}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">CVSS Score:</div>
                                <div class="info-value">${vuln.cvss || 'N/A'}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Affected Asset:</div>
                                <div class="info-value">${vuln.affected_asset || 'N/A'}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Tester:</div>
                                <div class="info-value">${vuln.employee}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Project:</div>
                                <div class="info-value">${vuln.project}</div>
                            </div>
                            <div class="info-item">
                                <div class="info-label">Client:</div>
                                <div class="info-value">${vuln.client}</div>
                            </div>
                        </div>
                        
                        <div class="vulnerability-description">
                            <h4>Vulnerability Title:</h4>
                            <p><strong>${vuln.title || 'No title provided'}</strong></p>
                            
                            <h4>Detailed Description:</h4>
                            <p>${vuln.description || 'No description provided'}</p>
                            
                            ${vuln.recommendation ? `
                                <h4>Recommendation:</h4>
                                <p>${vuln.recommendation}</p>
                            ` : ''}
                            
                            ${vuln.reference ? `
                                <h4>Reference:</h4>
                                <p><a href="${vuln.reference}" target="_blank">${vuln.reference}</a></p>
                            ` : ''}
                        </div>
                        
                        ${stepsHtml}
                    `;
                    
                    container.appendChild(vulnDiv);
                });
            }

            function getSeverityClass(severity) {
                const sev = severity.toLowerCase();
                if (sev.includes('critical')) return 'severity-critical';
                if (sev.includes('high')) return 'severity-high';
                if (sev.includes('medium')) return 'severity-medium';
                if (sev.includes('low')) return 'severity-low';
                return 'severity-info';
            }

            function getStatusClass(status) {
                const stat = status.toLowerCase();
                if (stat.includes('closed') || stat.includes('fixed')) return 'status-closed';
                if (stat.includes('pending')) return 'status-pending';
                return 'status-open';
            }

            function addAssetRow() {
                const tbody = document.getElementById('assetTableBody');
                const rowCount = tbody.children.length;
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${rowCount + 1}</td>
                    <td><input type="text" placeholder="Asset/Hostname" style="width: 100%; border: none; padding: 8px;"></td>
                    <td><input type="text" placeholder="Purpose" style="width: 100%; border: none; padding: 8px;"></td>
                    <td><input type="text" placeholder="Status" style="width: 100%; border: none; padding: 8px;"></td>
                    <td><input type="number" min="0" value="0" style="width: 60px; border: none; padding: 8px; text-align: center;"></td>
                    <td><input type="number" min="0" value="0" style="width: 60px; border: none; padding: 8px; text-align: center;"></td>
                    <td><input type="number" min="0" value="0" style="width: 60px; border: none; padding: 8px; text-align: center;"></td>
                    <td><input type="number" min="0" value="0" style="width: 60px; border: none; padding: 8px; text-align: center;"></td>
                    <td><input type="number" min="0" value="0" style="width: 60px; border: none; padding: 8px; text-align: center;"></td>
                    <td><strong>0</strong></td>
                    <td><input type="text" placeholder="Tester Name" style="width: 100%; border: none; padding: 8px;"></td>
                `;
                tbody.appendChild(row);
            }

            function updateEmployeeTable() {
                if (!comprehensiveData) return;
                
                const tbody = document.getElementById('employeeTableBody');
                tbody.innerHTML = '';

                Object.values(comprehensiveData.employees).forEach(emp => {
                    const performanceClass = getPerformanceClass(emp.performance_score);
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${emp.name}</td>
                        <td>${emp.project_count}</td>
                        <td>${emp.client_count}</td>
                        <td>${emp.total_vulnerabilities}</td>
                        <td class="severity-critical">${emp.critical}</td>
                        <td class="severity-high">${emp.high}</td>
                        <td class="severity-medium">${emp.medium}</td>
                        <td class="severity-low">${emp.low}</td>
                        <td><span class="performance-badge ${performanceClass}">${emp.performance_score}%</span></td>
                    `;
                    tbody.appendChild(row);
                });
            }

            function updateProjectTable() {
                if (!comprehensiveData) return;
                
                const tbody = document.getElementById('projectTableBody');
                tbody.innerHTML = '';

                Object.values(comprehensiveData.projects).forEach(proj => {
                    const riskLevel = calculateRiskLevel(proj);
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${proj.name}</td>
                        <td>${proj.client_count}</td>
                        <td>${proj.employee_count}</td>
                        <td>${proj.total_vulnerabilities}</td>
                        <td class="severity-critical">${proj.critical}</td>
                        <td class="severity-high">${proj.high}</td>
                        <td class="severity-medium">${proj.medium}</td>
                        <td class="severity-low">${proj.low}</td>
                        <td><span class="performance-badge ${getRiskClass(riskLevel)}">${riskLevel}</span></td>
                    `;
                    tbody.appendChild(row);
                });
            }

            function updateClientTable() {
                if (!comprehensiveData) return;
                
                const tbody = document.getElementById('clientTableBody');
                tbody.innerHTML = '';

                Object.values(comprehensiveData.clients).forEach(client => {
                    const riskLevel = calculateRiskLevel(client);
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${client.name}</td>
                        <td>${client.project_count}</td>
                        <td>${client.employee_count}</td>
                        <td>${client.total_vulnerabilities}</td>
                        <td class="severity-critical">${client.critical}</td>
                        <td class="severity-high">${client.high}</td>
                        <td class="severity-medium">${client.medium}</td>
                        <td class="severity-low">${client.low}</td>
                        <td><span class="performance-badge ${getRiskClass(riskLevel)}">${riskLevel}</span></td>
                    `;
                    tbody.appendChild(row);
                });
            }

            function getPerformanceClass(score) {
                if (score >= 80) return 'performance-excellent';
                if (score >= 60) return 'performance-good';
                if (score >= 40) return 'performance-average';
                return 'performance-poor';
            }

            function calculateRiskLevel(item) {
                const criticalWeight = 10;
                const highWeight = 5;
                const mediumWeight = 2;
                const lowWeight = 1;
                
                const riskScore = (item.critical * criticalWeight + item.high * highWeight + 
                                 item.medium * mediumWeight + item.low * lowWeight);
                
                if (riskScore >= 50) return 'High';
                if (riskScore >= 20) return 'Medium';
                if (riskScore >= 5) return 'Low';
                return 'Minimal';
            }

            function getRiskClass(riskLevel) {
                switch(riskLevel) {
                    case 'High': return 'performance-poor';
                    case 'Medium': return 'performance-average';
                    case 'Low': return 'performance-good';
                    default: return 'performance-excellent';
                }
            }

            // Usage logs
            async function loadUsageLogs() {
                try {
                    const response = await fetch('/dashboard/usage-logs/');
                    if (response.ok) {
                        usageLogs = await response.json();
                        updateUsageTable();
                    }
                } catch (error) {
                    console.error('Error loading usage logs:', error);
                }
            }

            function updateUsageTable() {
                const tbody = document.getElementById('usageTableBody');
                tbody.innerHTML = '';

                usageLogs.forEach(log => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${log.date}</td>
                        <td>${log.time}</td>
                        <td>${log.user_email}</td>
                        <td>${log.action}</td>
                        <td>${log.details}</td>
                        <td>${log.ip_address}</td>
                    `;
                    tbody.appendChild(row);
                });
            }

            // System statistics
            async function loadSystemStats() {
                try {
                    const response = await fetch('/dashboard/report-stats/');
                    if (response.ok) {
                        systemStats = await response.json();
                        updateSystemStats();
                        createSystemCharts();
                    }
                } catch (error) {
                    console.error('Error loading system stats:', error);
                }
            }

            function updateSystemStats() {
                const statsGrid = document.getElementById('system-stats-grid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${systemStats.total_reports || 0}</div>
                        <div class="stat-label">Total Reports</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${systemStats.total_actions || 0}</div>
                        <div class="stat-label">Total Actions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${systemStats.active_users || 0}</div>
                        <div class="stat-label">Active Users</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${systemStats.active_days || 0}</div>
                        <div class="stat-label">Active Days</div>
                    </div>
                `;
            }

            function createSystemCharts() {
                // Report Type Chart
                const ctx1 = document.getElementById('reportTypeChart').getContext('2d');
                if (charts.reportType) charts.reportType.destroy();
                
                const typeData = systemStats.reports_by_type || {};
                charts.reportType = new Chart(ctx1, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(typeData),
                        datasets: [{
                            data: Object.values(typeData),
                            backgroundColor: ['#667eea', '#764ba2', '#f093fb']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });

                // Daily Activity Chart
                const ctx2 = document.getElementById('dailyActivityChart').getContext('2d');
                if (charts.dailyActivity) charts.dailyActivity.destroy();
                
                const dailyData = systemStats.daily_activity || {};
                const sortedDates = Object.keys(dailyData).sort();
                
                charts.dailyActivity = new Chart(ctx2, {
                    type: 'line',
                    data: {
                        labels: sortedDates,
                        datasets: [{
                            label: 'Daily Activity',
                            data: sortedDates.map(date => dailyData[date]),
                            backgroundColor: '#667eea',
                            borderColor: '#764ba2',
                            borderWidth: 3,
                            fill: false,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            }

            // Search functionality
            function filterAssetTable() {
                const searchTerm = document.getElementById('assetSearch').value.toLowerCase();
                filterTable('assetTable', searchTerm);
            }

            function filterVulnerabilityDetails() {
                const searchTerm = document.getElementById('vulnSearch').value.toLowerCase();
                const vulnerabilities = document.querySelectorAll('.vulnerability-detail');
                
                vulnerabilities.forEach(vuln => {
                    const text = vuln.textContent.toLowerCase();
                    vuln.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }

            function filterEmployeeTable() {
                const searchTerm = document.getElementById('employeeSearch').value.toLowerCase();
                filterTable('employeeTable', searchTerm);
            }

            function filterProjectTable() {
                const searchTerm = document.getElementById('projectSearch').value.toLowerCase();
                filterTable('projectTable', searchTerm);
            }

            function filterClientTable() {
                const searchTerm = document.getElementById('clientSearch').value.toLowerCase();
                filterTable('clientTable', searchTerm);
            }

            function filterUsageTable() {
                const searchTerm = document.getElementById('usageSearch').value.toLowerCase();
                filterTable('usageTable', searchTerm);
            }

            function filterTable(tableId, searchTerm) {
                const rows = document.querySelectorAll(`#${tableId} tbody tr`);
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }

            // Load initial data
            window.onload = function() {
                loadAllData();
            };
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@dashboard_app.post("/analyze-comprehensive/")
async def analyze_comprehensive_data(request: Request):
    """Analyze comprehensive data from uploaded Excel file"""
    try:
        form = await request.form()
        excel_file = form.get('excel_file')
        
        if not excel_file:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Save file temporarily
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        temp_path = os.path.join(upload_dir, f"temp_comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
        content = await excel_file.read()
        with open(temp_path, "wb") as f:
            f.write(content)
        
        # Extract comprehensive data
        comprehensive_data = extract_comprehensive_data_from_excel(temp_path)
        
        # Clean up
        os.remove(temp_path)
        
        if comprehensive_data is None:
            raise HTTPException(status_code=500, detail="Failed to extract data from Excel file")
        
        return JSONResponse(content=comprehensive_data)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing comprehensive data: {str(e)}")

@dashboard_app.get("/usage-logs/")
async def get_usage_logs_endpoint(db: Session = Depends(get_db)):
    """Get usage logs from database"""
    try:
        logs = await get_usage_logs(db)
        return JSONResponse(content=logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting usage logs: {str(e)}")

@dashboard_app.get("/report-stats/")
async def get_report_statistics_endpoint(db: Session = Depends(get_db)):
    """Get report generation statistics"""
    try:
        stats = await get_report_statistics(db)
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting report stats: {str(e)}")