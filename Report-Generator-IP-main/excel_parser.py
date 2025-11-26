"""
Unified Excel Parser for Standardized VAPT Report Format
This module provides a single source of truth for parsing the standardized Excel format
used across all report generators (main.py, type2.py, type3.py, type4.py)
"""

import pandas as pd
import re
from typing import Dict, List, Any, Optional, Tuple
import os


def normalize_column_name(col: str) -> str:
    """
    Normalize column names for flexible matching.
    Converts to lowercase, removes extra spaces, and standardizes separators.
    """
    if not isinstance(col, str):
        return str(col).lower().strip()
    
    # Remove extra whitespace and convert to lowercase
    normalized = ' '.join(col.lower().strip().split())
    
    # Replace common separators with space
    normalized = normalized.replace('_', ' ').replace('-', ' ').replace('/', ' ')
    
    return normalized


# Column mapping dictionary - maps various possible column names to standard keys
COLUMN_MAPPINGS = {
    # Asset Information
    'asset': ['asset', 'hostname', 'asset hostname', 'asset/hostname', 'host'],
    'instant_purpose': ['instant purpose', 'purpose', 'asset purpose'],
    'vapt_status': ['vapt status', 'status', 'assessment status'],
    
    # Severity Counts (for asset-level summary)
    'critical_count': ['critical', 'critical count'],
    'high_count': ['high', 'high count'],
    'medium_count': ['medium', 'medium count'],
    'low_count': ['low', 'low count'],
    'informational_count': ['informational', 'info', 'informational count'],
    'total_count': ['total', 'total count', 'total vulnerabilities'],
    
    # Tester and Project Information
    'tester_name': ['tester name', 'tester', 'auditor', 'auditor name', 'tested by'],
    'project': ['project', 'project name', 'engagement'],
    'client': ['client', 'client name', 'organization'],
    
    # Vulnerability Details
    'sr_no': ['sr no', 'sr.no', 'sr.no.', 'serial no', 'serial number', 's.no', 's no', 'no', '#'],
    'observation': ['observation', 'title', 'vulnerability name', 'vuln name', 'finding'],
    'severity': ['severity', 'risk', 'risk level', 'impact'],
    'status': ['status', 'vuln status', 'finding status'],
    'new_or_re': ['new or re', 'new re', 'type', 'finding type'],
    'cve_cwe': ['cve cwe', 'cve/cwe', 'cve', 'cwe', 'identifier'],
    'cvss': ['cvss', 'cvss score', 'score'],
    'cvss_vector': ['cvss vector', 'cvss string', 'vector'],
    'affected_asset': ['affected asset', 'affected system', 'vulnerable asset'],
    'ip_url_app': ['ip url app', 'ip/url/app', 'target', 'endpoint', 'url', 'ip'],
    'observation_vuln': ['observation vulnerability', 'observation/vulnerability', 'description', 'summary'],
    'detailed_observation': ['detailed observation vulnerability', 'detailed observation', 'detailed description', 'details'],
    'recommendation': ['recommendation', 'remediation', 'fix', 'solution', 'mitigation'],
    'reference': ['reference', 'references', 'links', 'external references'],
    'evidence': ['evidence proof of concept', 'evidence', 'proof of concept', 'poc', 'evidence / proof of concept'],
    
    # Screenshot columns (dynamic - can be multiple)
    'screenshot': ['screenshot', 'screen shot', 'image', 'poc image'],
    
    # Steps columns (for detailed reproduction steps)
    'step_1': ['step 1', 'step1', 'steps 1'],
    'step_2': ['step 2', 'step2', 'steps 2'],
    'step_3': ['step 3', 'step3', 'steps 3'],
    'step_4': ['step 4', 'step4', 'steps 4'],
    'step_5': ['step 5', 'step5', 'steps 5'],
    'step_6': ['step 6', 'step6', 'steps 6'],
    'step_7': ['step 7', 'step7', 'steps 7'],
    'step_8': ['step 8', 'step8', 'steps 8'],
    'step_9': ['step 9', 'step9', 'steps 9'],
}


def find_column(df: pd.DataFrame, standard_key: str) -> Optional[str]:
    """
    Find the actual column name in the DataFrame that matches the standard key.
    Returns the actual column name from the DataFrame, or None if not found.
    """
    if standard_key not in COLUMN_MAPPINGS:
        return None
    
    possible_names = COLUMN_MAPPINGS[standard_key]
    df_columns_normalized = {normalize_column_name(col): col for col in df.columns}
    
    for possible_name in possible_names:
        normalized_possible = normalize_column_name(possible_name)
        if normalized_possible in df_columns_normalized:
            return df_columns_normalized[normalized_possible]
    
    return None


def find_screenshot_columns(df: pd.DataFrame) -> List[str]:
    """
    Find all screenshot columns in the DataFrame.
    Returns a list of actual column names that contain screenshots.
    """
    screenshot_cols = []
    for col in df.columns:
        normalized = normalize_column_name(col)
        if 'screenshot' in normalized or 'screen shot' in normalized or 'image' in normalized:
            screenshot_cols.append(col)
    
    return screenshot_cols


def find_step_columns(df: pd.DataFrame) -> Dict[int, str]:
    """
    Find all step columns in the DataFrame.
    Returns a dictionary mapping step numbers to actual column names.
    """
    step_cols = {}
    for col in df.columns:
        normalized = normalize_column_name(col)
        # Match patterns like "step 1", "step1", "steps 1", etc.
        match = re.search(r'step\s*(\d+)', normalized)
        if match:
            step_num = int(match.group(1))
            step_cols[step_num] = col
    
    return step_cols


def safe_get_value(row: pd.Series, col_name: Optional[str], default: Any = '') -> Any:
    """
    Safely get a value from a row, handling None column names and NaN values.
    """
    if col_name is None:
        return default
    
    if col_name not in row.index:
        return default
    
    value = row[col_name]
    
    # Handle NaN, None, and empty strings
    if pd.isna(value) or value is None or (isinstance(value, str) and value.strip() == ''):
        return default
    
    return value


def parse_excel_data(excel_file_path: str) -> Dict[str, Any]:
    """
    Parse the standardized Excel format and extract all relevant data.
    Each report type uploads its own Excel file with the same format.
    
    Returns a dictionary containing:
    - metadata: Dict with client, project, tester info
    - assets: List of asset summaries with vulnerability counts
    - vulnerabilities: List of detailed vulnerability information
    - raw_df: The original DataFrame for custom processing
    """
    
    # Read the Excel file (first sheet - each report type has its own Excel file)
    df = pd.read_excel(excel_file_path)
    print(f"📊 Reading Excel file")
    
    print(f"📊 Excel file loaded: {len(df)} rows, {len(df.columns)} columns")
    print(f"📋 Available columns: {list(df.columns)}")
    
    # Find all relevant columns
    col_asset = find_column(df, 'asset')
    col_instant_purpose = find_column(df, 'instant_purpose')
    col_vapt_status = find_column(df, 'vapt_status')
    col_critical = find_column(df, 'critical_count')
    col_high = find_column(df, 'high_count')
    col_medium = find_column(df, 'medium_count')
    col_low = find_column(df, 'low_count')
    col_info = find_column(df, 'informational_count')
    col_total = find_column(df, 'total_count')
    col_tester = find_column(df, 'tester_name')
    col_project = find_column(df, 'project')
    col_client = find_column(df, 'client')
    col_sr_no = find_column(df, 'sr_no')
    col_observation = find_column(df, 'observation')
    col_severity = find_column(df, 'severity')
    col_status = find_column(df, 'status')
    col_new_or_re = find_column(df, 'new_or_re')
    col_cve_cwe = find_column(df, 'cve_cwe')
    col_cvss = find_column(df, 'cvss')
    col_cvss_vector = find_column(df, 'cvss_vector')
    col_affected_asset = find_column(df, 'affected_asset')
    col_ip_url = find_column(df, 'ip_url_app')
    col_obs_vuln = find_column(df, 'observation_vuln')
    col_detailed_obs = find_column(df, 'detailed_observation')
    col_recommendation = find_column(df, 'recommendation')
    col_reference = find_column(df, 'reference')
    col_evidence = find_column(df, 'evidence')
    
    screenshot_cols = find_screenshot_columns(df)
    step_cols = find_step_columns(df)
    
    print(f"✅ Column mapping:")
    print(f"   Observation: {col_observation}")
    print(f"   Severity: {col_severity}")
    print(f"   Tester: {col_tester}")
    print(f"   Project: {col_project}")
    print(f"   Client: {col_client}")
    print(f"   Steps found: {len(step_cols)} ({list(step_cols.keys())})")
    print(f"   Screenshots found: {len(screenshot_cols)}")
    
    # Extract metadata (from first row or most common values)
    metadata = {
        'client': safe_get_value(df.iloc[0], col_client, 'Client Name') if col_client else 'Client Name',
        'project': safe_get_value(df.iloc[0], col_project, 'Project Name') if col_project else 'Project Name',
        'tester': safe_get_value(df.iloc[0], col_tester, 'Tester Name') if col_tester else 'Tester Name',
    }
    
    # If metadata is empty in first row, try to find first non-empty value
    for key in ['client', 'project', 'tester']:
        if metadata[key] in ['', 'Client Name', 'Project Name', 'Tester Name']:
            col_name = col_client if key == 'client' else (col_project if key == 'project' else col_tester)
            if col_name:
                for _, row in df.iterrows():
                    val = safe_get_value(row, col_name)
                    if val and val != '':
                        metadata[key] = val
                        break
    
    # Extract asset-level summaries
    assets = []
    seen_assets = set()
    
    for _, row in df.iterrows():
        asset_name = safe_get_value(row, col_asset)
        if asset_name and asset_name not in seen_assets:
            seen_assets.add(asset_name)
            assets.append({
                'asset': asset_name,
                'purpose': safe_get_value(row, col_instant_purpose),
                'status': safe_get_value(row, col_vapt_status),
                'critical': safe_get_value(row, col_critical, 0),
                'high': safe_get_value(row, col_high, 0),
                'medium': safe_get_value(row, col_medium, 0),
                'low': safe_get_value(row, col_low, 0),
                'informational': safe_get_value(row, col_info, 0),
                'total': safe_get_value(row, col_total, 0),
            })
    
    # Extract vulnerability details
    vulnerabilities = []
    
    # Check if we have the observation column
    if not col_observation:
        print("⚠️ WARNING: 'Observation' column not found! Cannot extract vulnerabilities.")
        print("   Looking for variations of: observation, title, vulnerability name, etc.")
        print(f"   Please ensure your Excel has one of these column names (case-insensitive)")
        return {
            'metadata': metadata,
            'assets': assets,
            'vulnerabilities': [],
            'raw_df': df
        }
    
    for idx, row in df.iterrows():
        # Skip rows without observation/vulnerability title
        obs_title = safe_get_value(row, col_observation)
        if not obs_title or obs_title == '':
            continue
        
        # Extract steps
        steps = []
        for step_num in sorted(step_cols.keys()):
            step_content = safe_get_value(row, step_cols[step_num])
            if step_content and step_content != '':
                steps.append({
                    'number': step_num,
                    'content': step_content
                })
        
        # Extract screenshots
        screenshots = []
        for screenshot_col in screenshot_cols:
            screenshot_val = safe_get_value(row, screenshot_col)
            if screenshot_val and screenshot_val != '':
                screenshots.append(screenshot_val)
        
        vuln = {
            'sr_no': safe_get_value(row, col_sr_no, idx + 1),
            'observation': obs_title,
            'severity': safe_get_value(row, col_severity, 'Medium'),
            'status': safe_get_value(row, col_status, 'Open'),
            'new_or_re': safe_get_value(row, col_new_or_re, 'New'),
            'cve_cwe': safe_get_value(row, col_cve_cwe),
            'cvss': safe_get_value(row, col_cvss),
            'cvss_vector': safe_get_value(row, col_cvss_vector),
            'affected_asset': safe_get_value(row, col_affected_asset),
            'ip_url_app': safe_get_value(row, col_ip_url),
            'observation_summary': safe_get_value(row, col_obs_vuln),
            'detailed_observation': safe_get_value(row, col_detailed_obs),
            'recommendation': safe_get_value(row, col_recommendation),
            'reference': safe_get_value(row, col_reference),
            'evidence': safe_get_value(row, col_evidence),
            'steps': steps,
            'screenshots': screenshots,
            'tester': safe_get_value(row, col_tester, metadata['tester']),
            'project': safe_get_value(row, col_project, metadata['project']),
            'client': safe_get_value(row, col_client, metadata['client']),
        }
        
        vulnerabilities.append(vuln)
    
    return {
        'metadata': metadata,
        'assets': assets,
        'vulnerabilities': vulnerabilities,
        'raw_df': df
    }


def get_severity_counts(vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Calculate severity counts from vulnerability list.
    """
    counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'informational': 0,
        'total': 0
    }
    
    for vuln in vulnerabilities:
        severity = str(vuln.get('severity', '')).lower()
        counts['total'] += 1
        
        if 'critical' in severity:
            counts['critical'] += 1
        elif 'high' in severity:
            counts['high'] += 1
        elif 'medium' in severity:
            counts['medium'] += 1
        elif 'low' in severity:
            counts['low'] += 1
        elif 'info' in severity or 'informational' in severity:
            counts['informational'] += 1
    
    return counts


def format_for_template(parsed_data: Dict[str, Any], template_type: str = 'generic') -> Dict[str, Any]:
    """
    Format the parsed data for specific template types.
    
    Args:
        parsed_data: Output from parse_excel_data()
        template_type: One of 'generic', 'certin', 'type2', 'type4'
    
    Returns:
        Dictionary formatted for the specific template
    """
    
    metadata = parsed_data['metadata']
    assets = parsed_data['assets']
    vulnerabilities = parsed_data['vulnerabilities']
    
    if template_type == 'certin' or template_type == 'type3':
        # Format for Cert-IN template
        return {
            'CLIENT_NAME': metadata['client'],
            'PROJECT_NAME': metadata['project'],
            'TESTER_NAME': metadata['tester'],
            'vulnerabilities': vulnerabilities,
            'assets': assets,
            'severity_counts': get_severity_counts(vulnerabilities),
        }
    
    elif template_type == 'type2':
        # Format for Type2 template
        return {
            'client_name': metadata['client'],
            'project_name': metadata['project'],
            'tester_name': metadata['tester'],
            'vulnerabilities': vulnerabilities,
            'assets': assets,
            'severity_summary': get_severity_counts(vulnerabilities),
        }
    
    elif template_type == 'type4' or template_type == 'main':
        # Format for Type4/Main template
        return {
            'client_name': metadata['client'],
            'project_name': metadata['project'],
            'tester_name': metadata['tester'],
            'vulnerabilities': vulnerabilities,
            'assets': assets,
            'severity_counts': get_severity_counts(vulnerabilities),
        }
    
    else:
        # Generic format
        return {
            'metadata': metadata,
            'assets': assets,
            'vulnerabilities': vulnerabilities,
            'severity_counts': get_severity_counts(vulnerabilities),
        }
