"""
Unified Excel Parser for all Report Generators
Handles the standardized Excel format with flexible column matching
"""
import pandas as pd
import os
from typing import Dict, List, Any, Optional
import re


class StandardExcelParser:
    """
    Parser for standardized Excel format used across all report generators.
    Supports flexible column matching with case-insensitive detection.
    """
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.df = None
        self.column_map = {}
        
    def _normalize_column_name(self, name: str) -> str:
        """Normalize column name for matching (lowercase, no spaces/special chars)"""
        return ''.join(ch.lower() for ch in str(name).strip() if ch.isalnum())
    
    def _find_column(self, candidates: List[str]) -> Optional[str]:
        """Find first matching column from candidates list"""
        normalized_map = {self._normalize_column_name(col): col for col in self.df.columns}
        
        for candidate in candidates:
            normalized = self._normalize_column_name(candidate)
            if normalized in normalized_map:
                return normalized_map[normalized]
        
        # Try partial match (startswith)
        for real_col in self.df.columns:
            normalized_real = self._normalize_column_name(real_col)
            for candidate in candidates:
                normalized_cand = self._normalize_column_name(candidate)
                if normalized_real.startswith(normalized_cand) or normalized_cand.startswith(normalized_real):
                    return real_col
        
        return None
    
    def load(self) -> bool:
        """Load and parse Excel file"""
        try:
            self.df = pd.read_excel(self.file_path)
            self._build_column_map()
            return True
        except Exception as e:
            print(f"Error loading Excel file: {e}")
            return False
    
    def _build_column_map(self):
        """Build mapping of standard column names to actual column names in Excel"""
        # Define column aliases
        column_definitions = {
            'asset': ['Asset/Hostname', 'Asset Hostname', 'Asset_Hostname', 'Hostname', 'Asset', 'URL', 'IP', 'Target'],
            'purpose': ['Instant purpose', 'Instant Purpose', 'Purpose', 'Asset_Purpose', 'Application_Type'],
            'vapt_status': ['VAPT Status', 'VAPT_Status', 'Assessment_Status', 'Status Column', 'Overall_Status'],
            'severity_status': ['Severity Status', 'Severity_Status', 'Status_Summary'],
            'tester_name': ['Tester_Name', 'Tester Name', 'ReportedBy', 'Tester', 'Employee_Name', 'Analyst'],
            'project': ['Project', 'Project_Name', 'Project Name', 'ProjectName', 'Assessment'],
            'client': ['Client_Name', 'Client Name', 'ClientName', 'Client', 'Organization'],
            'sr_no': ['Sr.no.', 'Sr no', 'Sr_no', 'Serial_No', 'S.No', 'S No', 'Number', '#'],
            'observation': ['Observation', 'Observation_ID', 'ID', 'Vuln_ID'],
            'severity': ['Severity', 'Risk', 'Risk Level', 'Risk_Level', 'Priority'],
            'status': ['Status', 'Remediation_Status', 'Fix_Status'],
            'new_or_re': ['New or Re', 'New_or_Re', 'Type', 'Test_Type'],
            'cve_cwe': ['CVE/CWE', 'CVE', 'CWE', 'CVE_CWE'],
            'cvss': ['CVSS', 'CVSS Score', 'CVSS_Score'],
            'cvss_vector': ['CVSS Vector', 'CVSS_Vector', 'Vector'],
            'affected_asset': ['Affected Asset ie. IP/URL/Application etc.', 'Affected Asset', 'Affected_Asset', 'Target'],
            'vulnerability_title': ['Observation/Vulnerability Title', 'Vulnerability Title', 'Title', 'Vulnerability_Name', 'Vulnerability Name'],
            'detailed_observation': ['Detailed Observation/Vulnerable Point', 'Detailed Observation', 'Description', 'Vulnerability_Description', 'Vulnerable_Point'],
            'recommendation': ['Vulnerability Recommendation', 'Recommendation', 'Remediation', 'Solution', 'Fix'],
            'reference': ['Reference', 'References', 'Links', 'URL', 'External_Links'],
            'critical_count': ['Critical'],
            'high_count': ['High'],
            'medium_count': ['Medium'],
            'low_count': ['Low'],
            'info_count': ['Informational', 'Info'],
            'total_count': ['Total'],
            'date': ['Date', 'Created_Date', 'Created Date', 'Reported_Date', 'Assessment_Date']
        }
        
        # Build the column map
        for key, candidates in column_definitions.items():
            found_col = self._find_column(candidates)
            if found_col:
                self.column_map[key] = found_col
        
        # Find step columns (Evidence/PoC columns)
        self.column_map['steps'] = []
        for col in self.df.columns:
            col_lower = str(col).lower()
            if any(keyword in col_lower for keyword in ['evidence', 'proof', 'screenshot', 'poc', 'step']):
                # Check if it's a step column (might be numbered)
                self.column_map['steps'].append(col)
        
        print(f"✅ Mapped columns: {list(self.column_map.keys())}")
    
    def get_value(self, row, key: str, default=''):
        """Get value from row using column map"""
        if key not in self.column_map:
            return default
        
        col_name = self.column_map[key]
        value = row.get(col_name, default)
        
        # Handle NaN and None
        if pd.isna(value):
            return default
        
        return str(value).strip()
    
    def extract_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Extract vulnerability data from Excel"""
        vulnerabilities = []
        
        for idx, row in self.df.iterrows():
            # Skip rows where observation/sr_no is empty
            sr_no = self.get_value(row, 'sr_no')
            observation = self.get_value(row, 'observation')
            
            if not sr_no and not observation:
                continue
            
            # Extract steps (Evidence/PoC)
            steps = []
            if 'steps' in self.column_map:
                for step_col in self.column_map['steps']:
                    step_value = row.get(step_col, '')
                    if pd.notna(step_value) and str(step_value).strip():
                        steps.append({
                            'step_name': step_col,
                            'step_content': str(step_value).strip()
                        })
            
            vuln = {
                # Basic identification
                'sr_no': sr_no or str(idx + 1),
                'observation': observation,
                'severity': self.get_value(row, 'severity', 'Medium'),
                'status': self.get_value(row, 'status', 'Open'),
                'new_or_re': self.get_value(row, 'new_or_re'),
                
                # Asset and project info
                'asset': self.get_value(row, 'asset'),
                'purpose': self.get_value(row, 'purpose'),
                'vapt_status': self.get_value(row, 'vapt_status'),
                'tester_name': self.get_value(row, 'tester_name'),
                'project': self.get_value(row, 'project'),
                'client': self.get_value(row, 'client'),
                'date': self.get_value(row, 'date'),
                
                # Technical details
                'cve_cwe': self.get_value(row, 'cve_cwe'),
                'cvss': self.get_value(row, 'cvss', '0.0'),
                'cvss_vector': self.get_value(row, 'cvss_vector'),
                'affected_asset': self.get_value(row, 'affected_asset'),
                
                # Vulnerability details
                'vulnerability_title': self.get_value(row, 'vulnerability_title'),
                'detailed_observation': self.get_value(row, 'detailed_observation'),
                'recommendation': self.get_value(row, 'recommendation'),
                'reference': self.get_value(row, 'reference'),
                
                # Evidence/PoC steps
                'steps': steps,
                'has_steps': len(steps) > 0,
                
                # Counts (if available)
                'critical_count': self.get_value(row, 'critical_count', '0'),
                'high_count': self.get_value(row, 'high_count', '0'),
                'medium_count': self.get_value(row, 'medium_count', '0'),
                'low_count': self.get_value(row, 'low_count', '0'),
                'info_count': self.get_value(row, 'info_count', '0'),
                'total_count': self.get_value(row, 'total_count', '0'),
            }
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def extract_employee_data(self) -> List[Dict[str, Any]]:
        """Extract employee/tester data for dashboard"""
        employees = {}
        
        for _, row in self.df.iterrows():
            tester_name = self.get_value(row, 'tester_name')
            if not tester_name or tester_name == '':
                continue
            
            if tester_name not in employees:
                employees[tester_name] = {
                    'name': tester_name,
                    'total_vulnerabilities': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0,
                    'projects': set(),
                    'clients': set()
                }
            
            employees[tester_name]['total_vulnerabilities'] += 1
            
            # Count by severity
            severity = self.get_value(row, 'severity', '').lower()
            if 'critical' in severity:
                employees[tester_name]['critical'] += 1
            elif 'high' in severity:
                employees[tester_name]['high'] += 1
            elif 'medium' in severity:
                employees[tester_name]['medium'] += 1
            elif 'low' in severity:
                employees[tester_name]['low'] += 1
            else:
                employees[tester_name]['info'] += 1
            
            # Track projects and clients
            project = self.get_value(row, 'project')
            client = self.get_value(row, 'client')
            if project:
                employees[tester_name]['projects'].add(project)
            if client:
                employees[tester_name]['clients'].add(client)
        
        # Convert sets to lists for JSON serialization
        for emp_data in employees.values():
            emp_data['projects'] = list(emp_data['projects'])
            emp_data['clients'] = list(emp_data['clients'])
        
        return list(employees.values())
    
    def extract_project_data(self) -> List[Dict[str, Any]]:
        """Extract project data for dashboard"""
        projects = {}
        
        for _, row in self.df.iterrows():
            project = self.get_value(row, 'project')
            if not project or project == '':
                continue
            
            if project not in projects:
                projects[project] = {
                    'name': project,
                    'client': self.get_value(row, 'client'),
                    'total_vulnerabilities': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0,
                    'assets': set(),
                    'testers': set()
                }
            
            projects[project]['total_vulnerabilities'] += 1
            
            # Count by severity
            severity = self.get_value(row, 'severity', '').lower()
            if 'critical' in severity:
                projects[project]['critical'] += 1
            elif 'high' in severity:
                projects[project]['high'] += 1
            elif 'medium' in severity:
                projects[project]['medium'] += 1
            elif 'low' in severity:
                projects[project]['low'] += 1
            else:
                projects[project]['info'] += 1
            
            # Track assets and testers
            asset = self.get_value(row, 'asset')
            tester = self.get_value(row, 'tester_name')
            if asset:
                projects[project]['assets'].add(asset)
            if tester:
                projects[project]['testers'].add(tester)
        
        # Convert sets to lists
        for proj_data in projects.values():
            proj_data['assets'] = list(proj_data['assets'])
            proj_data['testers'] = list(proj_data['testers'])
        
        return list(projects.values())
    
    def extract_asset_summary(self) -> List[Dict[str, Any]]:
        """Extract asset summary for dashboard table"""
        assets = {}
        
        for _, row in self.df.iterrows():
            asset = self.get_value(row, 'asset')
            if not asset or asset == '':
                continue
            
            if asset not in assets:
                assets[asset] = {
                    'asset': asset,
                    'purpose': self.get_value(row, 'purpose'),
                    'vapt_status': self.get_value(row, 'vapt_status'),
                    'severity_status': self.get_value(row, 'severity_status'),
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0,
                    'total': 0,
                    'tester': self.get_value(row, 'tester_name'),
                    'project': self.get_value(row, 'project'),
                    'client': self.get_value(row, 'client')
                }
            
            # Check if row has count columns or needs to be counted
            if self.column_map.get('critical_count'):
                # Use count columns if available
                assets[asset]['critical'] += int(self.get_value(row, 'critical_count', '0') or 0)
                assets[asset]['high'] += int(self.get_value(row, 'high_count', '0') or 0)
                assets[asset]['medium'] += int(self.get_value(row, 'medium_count', '0') or 0)
                assets[asset]['low'] += int(self.get_value(row, 'low_count', '0') or 0)
                assets[asset]['info'] += int(self.get_value(row, 'info_count', '0') or 0)
                assets[asset]['total'] += int(self.get_value(row, 'total_count', '0') or 0)
            else:
                # Count by severity if no count columns
                severity = self.get_value(row, 'severity', '').lower()
                if 'critical' in severity:
                    assets[asset]['critical'] += 1
                elif 'high' in severity:
                    assets[asset]['high'] += 1
                elif 'medium' in severity:
                    assets[asset]['medium'] += 1
                elif 'low' in severity:
                    assets[asset]['low'] += 1
                else:
                    assets[asset]['info'] += 1
                assets[asset]['total'] += 1
        
        return list(assets.values())


def parse_excel_for_report(file_path: str, report_type: str = 'type1') -> Dict[str, Any]:
    """
    Unified function to parse Excel for any report type.
    
    Args:
        file_path: Path to Excel file
        report_type: 'type1', 'type2', or 'type3'
    
    Returns:
        Dictionary with parsed data tailored for the report type
    """
    parser = StandardExcelParser(file_path)
    
    if not parser.load():
        return {'error': 'Failed to load Excel file'}
    
    # Extract all data
    vulnerabilities = parser.extract_vulnerabilities()
    employees = parser.extract_employee_data()
    projects = parser.extract_project_data()
    assets = parser.extract_asset_summary()
    
    return {
        'vulnerabilities': vulnerabilities,
        'employees': employees,
        'projects': projects,
        'assets': assets,
        'summary': {
            'total_vulnerabilities': len(vulnerabilities),
            'total_employees': len(employees),
            'total_projects': len(projects),
            'total_assets': len(assets),
            'critical_count': sum(v['severity'].lower() == 'critical' for v in vulnerabilities),
            'high_count': sum(v['severity'].lower() == 'high' for v in vulnerabilities),
            'medium_count': sum(v['severity'].lower() == 'medium' for v in vulnerabilities),
            'low_count': sum(v['severity'].lower() == 'low' for v in vulnerabilities),
            'info_count': sum(v['severity'].lower() in ['informational', 'info'] for v in vulnerabilities)
        }
    }

