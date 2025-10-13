from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import os
import pandas as pd
from docxtpl import DocxTemplate
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from datetime import datetime
import traceback
import tempfile
import json
import re
import zipfile
from sqlalchemy.orm import Session
from db import get_db, AuditLog, CertINReport

# Version tracking
VERSION = "2.0.0"

app = FastAPI()

# Add session middleware for session access
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecret"),
    https_only=False,  # Set to True for production with HTTPS
    same_site="lax",
    session_cookie="reportgen_session"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directory to store uploaded files
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def sanitize_filename(filename):
    """Sanitize filename to prevent XSS and path traversal"""
    if not filename:
        return "upload.xlsx"
    # Remove dangerous characters and keep only alphanumeric, dots, hyphens, underscores
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    return safe_name

def read_vulnerability_excel(file_path):
    """Read vulnerability data from existing Excel file"""
    try:
        df = pd.read_excel(file_path)
        # Convert to list of dictionaries for template
        vulnerabilities = []
        for _, row in df.iterrows():
            vuln_data = {}
            for col in df.columns:
                vuln_data[col] = str(row[col]) if pd.notna(row[col]) else ""
            vulnerabilities.append(vuln_data)
        return vulnerabilities
    except Exception as e:
        print(f"Error reading vulnerability Excel: {e}")
        return []

async def process_poc_zip_files(poc_files, vulnerabilities):
    """Process uploaded PoC zip files and map them to vulnerabilities"""
    poc_mapping = {}
    
    for poc_file in poc_files:
        if not poc_file.filename:
            continue
            
        # Save zip file temporarily
        temp_zip_path = os.path.join(UPLOAD_DIR, f"temp_{poc_file.filename}")
        content = await poc_file.read()
        with open(temp_zip_path, "wb") as f:
            f.write(content)
        
        # Extract zip file to a common directory
        extract_dir = os.path.join(UPLOAD_DIR, "poc_images")
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Get list of all extracted images
            all_images = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                        all_images.append({
                            'filename': file,
                            'path': os.path.join(root, file),
                            'step_number': extract_step_number(file)
                        })
            
            # Sort by step number
            all_images.sort(key=lambda x: x['step_number'])
            
            # Map images to vulnerabilities based on observation number
            for i, vuln in enumerate(vulnerabilities, 1):
                # Find images that correspond to this observation
                vuln_images = []
                for img in all_images:
                    # Check if image filename contains step number that matches this observation
                    step_num = extract_step_number(img['filename'])
                    if step_num == i or f"step{step_num}" in img['filename'].lower():
                        vuln_images.append(img)
                
                if vuln_images:
                    poc_mapping[f"OBS-{i:03d}"] = vuln_images
            
        except Exception as e:
            print(f"Error extracting PoC zip: {e}")
        
        # Clean up temp zip
        os.remove(temp_zip_path)
    
    return poc_mapping

def extract_step_number(filename):
    """Extract step number from filename (e.g., step1.png -> 1)"""
    import re
    match = re.search(r'step(\d+)', filename.lower())
    return int(match.group(1)) if match else 999

def generate_vulnerability_sections(vulnerabilities, poc_mapping):
    """Generate vulnerability sections for the report"""
    vulnerability_sections = []
    
    for i, vuln in enumerate(vulnerabilities, 1):
        # Extract data from Excel columns (case-insensitive matching)
        vuln_id = vuln.get('Vulnerability_ID', f'OBS-{i:03d}')
        severity = vuln.get('Severity', 'Medium')
        status = vuln.get('Status', 'Open')
        cve_cwe = vuln.get('CVE_CWE', '')
        cvss = vuln.get('CVSS', '0.0')
        cvss_vector = vuln.get('CVSS_Vector', '')
        affected_asset = vuln.get('Affected_Asset', '')
        title = vuln.get('Vulnerability_Title', '')
        description = vuln.get('Detailed_Description', '')
        impact = vuln.get('Impact', '')
        recommendations = vuln.get('Recommendations', '')
        reproduction_steps = vuln.get('Reproduction_Steps', '')
        
        # Get PoC images for this vulnerability
        obs_key = f"OBS-{i:03d}"
        poc_images = poc_mapping.get(obs_key, [])
        
        # Generate recommendations list
        recommendations_list = []
        if recommendations:
            # Split by newlines or numbers and clean up
            rec_lines = [line.strip() for line in recommendations.split('\n') if line.strip()]
            for line in rec_lines:
                # Remove numbering if present
                clean_line = re.sub(r'^\d+\.\s*', '', line)
                if clean_line:
                    recommendations_list.append(clean_line)
        
        vulnerability_section = {
            'observation_number': i,
            'vulnerability_id': vuln_id,
            'severity': severity,
            'status': status,
            'cve_cwe': cve_cwe,
            'cvss': cvss,
            'cvss_vector': cvss_vector,
            'affected_asset': affected_asset,
            'title': title,
            'description': description,
            'impact': impact,
            'recommendations': recommendations_list,
            'reproduction_steps': reproduction_steps,
            'poc_images': poc_images,
            'has_poc': len(poc_images) > 0
        }
        
        vulnerability_sections.append(vulnerability_section)
    
    return vulnerability_sections

def create_landscape_vulnerability_box(doc, vulnerability_section):
    """Create a landscape-oriented vulnerability box similar to type2.py but in landscape mode"""
    from docx.shared import Inches, Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import parse_xml
    from docx.oxml.ns import nsdecls, qn
    
    # Create a table for the vulnerability box
    table = doc.add_table(rows=1, cols=1)
    table.style = 'Table Grid'
    
    # Get severity colors
    severity = vulnerability_section.get('severity', 'Medium')
    severity_colors = {
        'Critical': {'bg': '#990000', 'text': '#FFFFFF'},
        'High': {'bg': '#FF0000', 'text': '#FFFFFF'},
        'Medium': {'bg': '#FFCC00', 'text': '#000000'},
        'Low': {'bg': '#009933', 'text': '#FFFFFF'},
        'Informational': {'bg': '#3399CC', 'text': '#FFFFFF'}
    }
    colors = severity_colors.get(severity, severity_colors['Medium'])
    
    # Header row with severity and status
    header_cell = table.rows[0].cells[0]
    header_para = header_cell.paragraphs[0]
    header_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    # Add observation number
    obs_run = header_para.add_run(f"Observation: #{vulnerability_section['observation_number']}")
    obs_run.font.name = 'Altone Trial'
    obs_run.font.size = Pt(14)
    obs_run.font.bold = True
    obs_run.font.color.rgb = RGBColor(0, 0, 0)
    
    # Add severity and status in colored boxes
    severity_run = header_para.add_run(f" | Severity: {severity}")
    severity_run.font.name = 'Altone Trial'
    severity_run.font.size = Pt(14)
    severity_run.font.bold = True
    severity_run.font.color.rgb = RGBColor(255, 255, 255)
    
    status_run = header_para.add_run(f" | Status: {vulnerability_section.get('status', 'Open')}")
    status_run.font.name = 'Altone Trial'
    status_run.font.size = Pt(14)
    status_run.font.bold = True
    status_run.font.color.rgb = RGBColor(0, 0, 0)
    
    # Apply background color to header
    shading_elm = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{colors["bg"]}"/>')
    header_cell._element.get_or_add_tcPr().append(shading_elm)
    
    # Add vulnerability details
    details_para = header_cell.add_paragraph()
    details_para.alignment = WD_ALIGN_PARAGRAPH.LEFT
    
    # CVE/CWE
    if vulnerability_section.get('cve_cwe'):
        cve_run = details_para.add_run(f"CVE/CWE: {vulnerability_section['cve_cwe']}\n")
        cve_run.font.name = 'Altone Trial'
        cve_run.font.size = Pt(11)
        cve_run.font.bold = True
    
    # CVSS
    if vulnerability_section.get('cvss'):
        cvss_run = details_para.add_run(f"CVSS: {vulnerability_section['cvss']}\n")
        cvss_run.font.name = 'Altone Trial'
        cvss_run.font.size = Pt(11)
        cvss_run.font.bold = True
    
    # CVSS Vector
    if vulnerability_section.get('cvss_vector'):
        vector_run = details_para.add_run(f"CVSS Vector: {vulnerability_section['cvss_vector']}\n")
        vector_run.font.name = 'Altone Trial'
        vector_run.font.size = Pt(11)
        vector_run.font.bold = True
    
    # Affected Asset
    if vulnerability_section.get('affected_asset'):
        asset_run = details_para.add_run(f"Affected Asset: {vulnerability_section['affected_asset']}\n")
        asset_run.font.name = 'Altone Trial'
        asset_run.font.size = Pt(11)
        asset_run.font.bold = True
    
    # Vulnerability Title
    if vulnerability_section.get('title'):
        title_run = details_para.add_run(f"Vulnerability Title: {vulnerability_section['title']}\n")
        title_run.font.name = 'Altone Trial'
        title_run.font.size = Pt(11)
        title_run.font.bold = True
    
    # Detailed Description
    if vulnerability_section.get('description'):
        desc_para = header_cell.add_paragraph()
        desc_run = desc_para.add_run("Detailed Observation/Vulnerable Point:\n")
        desc_run.font.name = 'Altone Trial'
        desc_run.font.size = Pt(11)
        desc_run.font.bold = True
        
        desc_text_run = desc_para.add_run(vulnerability_section['description'])
        desc_text_run.font.name = 'Altone Trial'
        desc_text_run.font.size = Pt(11)
        desc_text_run.font.bold = False
    
    # Impact
    if vulnerability_section.get('impact'):
        impact_para = header_cell.add_paragraph()
        impact_run = impact_para.add_run("Impact:\n")
        impact_run.font.name = 'Altone Trial'
        impact_run.font.size = Pt(11)
        impact_run.font.bold = True
        
        impact_text_run = impact_para.add_run(vulnerability_section['impact'])
        impact_text_run.font.name = 'Altone Trial'
        impact_text_run.font.size = Pt(11)
        impact_text_run.font.bold = False
    
    # Recommendations
    if vulnerability_section.get('recommendations'):
        rec_para = header_cell.add_paragraph()
        rec_run = rec_para.add_run("Recommendations:\n")
        rec_run.font.name = 'Altone Trial'
        rec_run.font.size = Pt(11)
        rec_run.font.bold = True
        
        for i, rec in enumerate(vulnerability_section['recommendations'], 1):
            rec_text_run = rec_para.add_run(f"{i}. {rec}\n")
            rec_text_run.font.name = 'Altone Trial'
            rec_text_run.font.size = Pt(11)
            rec_text_run.font.bold = False
    
    # Proof of Concept with images
    if vulnerability_section.get('has_poc') and vulnerability_section.get('poc_images'):
        poc_para = header_cell.add_paragraph()
        poc_run = poc_para.add_run("Evidence/Proof of Concept:\n")
        poc_run.font.name = 'Altone Trial'
        poc_run.font.size = Pt(11)
        poc_run.font.bold = True
        
        for i, poc_img in enumerate(vulnerability_section['poc_images'], 1):
            step_para = header_cell.add_paragraph()
            step_run = step_para.add_run(f"Step {i}:\n")
            step_run.font.name = 'Altone Trial'
            step_run.font.size = Pt(11)
            step_run.font.bold = True
            
            # Add the image
            if os.path.exists(poc_img['path']):
                img_para = header_cell.add_paragraph()
                img_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                img_run = img_para.add_run()
                img_run.add_picture(poc_img['path'], width=Inches(4))
            else:
                missing_para = header_cell.add_paragraph()
                missing_run = missing_para.add_run(f"[Image missing: {poc_img['filename']}]")
                missing_run.font.name = 'Altone Trial'
                missing_run.font.size = Pt(10)
                missing_run.font.italic = True
    
    return table

def generate_certin_report_from_form(data, template_path, output_path, vulnerability_data=None, poc_mapping=None):
    """Generate Cert-IN report from form data and template"""
    try:
        # Load the template
        doc = DocxTemplate(template_path)
        
        # Parse JSON fields
        document_change_history = json.loads(data.get('document_change_history', '[]'))
        distribution_list = json.loads(data.get('distribution_list', '[]'))
        engagement_scope = json.loads(data.get('engagement_scope', '[]'))
        auditing_team = json.loads(data.get('auditing_team', '[]'))
        audit_activities = json.loads(data.get('audit_activities', '[]'))
        tools_software = json.loads(data.get('tools_software', '[]'))
        
        # Process vulnerability data if provided
        vulnerability_sections = []
        if vulnerability_data and poc_mapping:
            vulnerability_sections = generate_vulnerability_sections(vulnerability_data, poc_mapping)
        
        # Prepare context for template
        context = {
            # Basic Report Information
            'CLIENT_NAME': data.get('client_name', ''),
            'REPORT_NAME': data.get('report_name', ''),
            'REPORT_RELEASE_DATE': data.get('report_release_date', ''),
            'TYPE_OF_AUDIT': data.get('type_of_audit', ''),
            'TYPE_OF_AUDIT_REPORT': data.get('type_of_audit_report', ''),
            'PERIOD': data.get('period', ''),
            
            # Document Control
            'DOCUMENT_TITLE': data.get('document_title', ''),
            'DOCUMENT_ID': data.get('document_id', ''),
            'DOCUMENT_VERSION': data.get('document_version', ''),
            'PREPARED_BY': data.get('prepared_by', ''),
            'REVIEWED_BY': data.get('reviewed_by', ''),
            'APPROVED_BY': data.get('approved_by', ''),
            'RELEASED_BY': data.get('released_by', ''),
            'RELEASE_DATE': data.get('release_date', ''),
            
            # Document Change History
            'DOCUMENT_CHANGE_HISTORY': document_change_history,
            
            # Distribution List
            'DISTRIBUTION_LIST': distribution_list,
            
            # Engagement Scope
            'ENGAGEMENT_SCOPE': engagement_scope,
            
            # Auditing Team
            'AUDITING_TEAM': auditing_team,
            
            # Audit Activities
            'AUDIT_ACTIVITIES': audit_activities,
            
            # Tools/Software
            'TOOLS_SOFTWARE': tools_software,
            
            # Vulnerability Data
            'VULNERABILITIES': vulnerability_sections,
            'HAS_VULNERABILITIES': len(vulnerability_sections) > 0,
            'VULNERABILITY_COUNT': len(vulnerability_sections),
            
            # Additional fields
            'GENERATION_DATE': datetime.now().strftime('%d %B %Y'),
            'GENERATION_TIME': datetime.now().strftime('%H:%M:%S'),
        }
        
        # Render the template
        doc.render(context)
        
        # Save the document temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as tmp:
            doc.save(tmp.name)
            tmp_path = tmp.name
        
        # Open with python-docx for dynamic vulnerability boxes
        from docx import Document
        doc = Document(tmp_path)
        
        # Add vulnerability sections if they exist
        if vulnerability_sections:
            # Add a page break before vulnerabilities
            doc.add_page_break()
            
            # Add heading for vulnerabilities
            vuln_heading = doc.add_paragraph()
            vuln_run = vuln_heading.add_run("Detailed Observations")
            vuln_run.font.name = 'Altone Trial'
            vuln_run.font.size = Pt(18)
            vuln_run.font.bold = True
            vuln_run.font.color.rgb = RGBColor(106, 68, 154)
            
            # Add each vulnerability box
            for i, vuln_section in enumerate(vulnerability_sections):
                create_landscape_vulnerability_box(doc, vuln_section)
                
                # Add page break between vulnerabilities (except for the last one)
                if i < len(vulnerability_sections) - 1:
                    doc.add_page_break()
        
        # Save the final document
        doc.save(output_path)
        
        # Clean up temp file
        os.remove(tmp_path)
        
        return True
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the Cert-IN form interface"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cert-IN Report Generator</title>
        <style>
            body { font-family: Altone Trial, sans-serif; margin: 20px; background-color: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #6923d0; text-align: center; margin-bottom: 30px; }
            .form-section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
            .form-section h3 { color: #6923d0; margin-top: 0; border-bottom: 2px solid #6923d0; padding-bottom: 10px; }
            .form-row { display: flex; gap: 20px; margin-bottom: 15px; }
            .form-group { flex: 1; }
            .form-group label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
            .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            .form-group textarea { height: 60px; resize: vertical; }
            .dynamic-list { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }
            .dynamic-item { display: flex; gap: 10px; margin-bottom: 10px; align-items: end; }
            .dynamic-item input { flex: 1; }
            .btn { background-color: #6923d0; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; }
            .btn:hover { background-color: #5a1fb8; }
            .btn-secondary { background-color: #6c757d; }
            .btn-secondary:hover { background-color: #5a6268; }
            .btn-danger { background-color: #dc3545; }
            .btn-danger:hover { background-color: #c82333; }
            .btn-success { background-color: #28a745; }
            .btn-success:hover { background-color: #218838; }
            .progress { display: none; margin: 20px 0; }
            .progress-bar { background-color: #6923d0; height: 20px; border-radius: 4px; width: 0%; transition: width 0.3s; }
            .result { display: none; margin: 20px 0; padding: 15px; border-radius: 4px; }
            .result.success { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
            .result.error { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Cert-IN Report Generator</h1>
            <div style="text-align:center;margin-bottom:16px;">
                <a href="/report_formats.html" class="btn btn-secondary" style="text-decoration:none;display:inline-block;">← Back to Report Formats</a>
            </div>
            <p style="text-align: center; color: #666; margin-bottom: 30px;">
                Generate Cert-IN compliant reports with document control pages
            </p>
            
            <form id="certinForm">
                <!-- Basic Report Information -->
                <div class="form-section">
                    <h3>📋 Basic Report Information</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="client_name">Client Name *</label>
                            <input type="text" id="client_name" name="client_name" required>
                        </div>
                        <div class="form-group">
                            <label for="report_name">Web/Network Initial Report Name *</label>
                            <input type="text" id="report_name" name="report_name" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="report_release_date">Report Release Date *</label>
                            <input type="date" id="report_release_date" name="report_release_date" required>
                        </div>
                        <div class="form-group">
                            <label for="type_of_audit">Type of Audit *</label>
                            <select id="type_of_audit" name="type_of_audit" required>
                                <option value="">Select Type</option>
                                <option value="Security assessment (VAPT) - WEB & Network">Security assessment (VAPT) - WEB & Network</option>
                                <option value="Security assessment (VAPT) - WEB">Security assessment (VAPT) - WEB</option>
                                <option value="Security assessment (VAPT) - Network">Security assessment (VAPT) - Network</option>
                                <option value="Penetration Testing">Penetration Testing</option>
                                <option value="Vulnerability Assessment">Vulnerability Assessment</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="type_of_audit_report">Type of Audit Report *</label>
                            <select id="type_of_audit_report" name="type_of_audit_report" required>
                                <option value="">Select Type</option>
                                <option value="First Audit Report">First Audit Report</option>
                                <option value="Follow-up Audit Report">Follow-up Audit Report</option>
                                <option value="Final Audit Report">Final Audit Report</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="period">Period *</label>
                            <input type="text" id="period" name="period" placeholder="e.g., 23-07-2025 to 02-08-2025" required>
                        </div>
                    </div>
                </div>

                <!-- Document Control -->
                <div class="form-section">
                    <h3>📄 Document Control</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="document_title">Document Title *</label>
                            <input type="text" id="document_title" name="document_title" required>
                        </div>
                        <div class="form-group">
                            <label for="document_id">Document ID *</label>
                            <input type="text" id="document_id" name="document_id" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="document_version">Document Version *</label>
                            <input type="text" id="document_version" name="document_version" value="1.0" required>
                        </div>
                        <div class="form-group">
                            <label for="prepared_by">Prepared by *</label>
                            <input type="text" id="prepared_by" name="prepared_by" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="reviewed_by">Reviewed by *</label>
                            <input type="text" id="reviewed_by" name="reviewed_by" required>
                        </div>
                        <div class="form-group">
                            <label for="approved_by">Approved by *</label>
                            <input type="text" id="approved_by" name="approved_by" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label for="released_by">Released by *</label>
                            <input type="text" id="released_by" name="released_by" required>
                        </div>
                        <div class="form-group">
                            <label for="release_date">Release Date *</label>
                            <input type="date" id="release_date" name="release_date" required>
                        </div>
                    </div>
                </div>

                <!-- Document Change History -->
                <div class="form-section">
                    <h3>📝 Document Change History</h3>
                    <div id="changeHistoryList">
                        <div class="dynamic-item">
                            <input type="text" name="change_version[]" placeholder="Version" required>
                            <input type="date" name="change_date[]" required>
                            <input type="text" name="change_remarks[]" placeholder="Remarks/Reason of change" required>
                            <button type="button" class="btn btn-danger" onclick="removeChangeHistory(this)">Remove</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="addChangeHistory()">+ Add Change History</button>
                </div>

                <!-- Document Distribution List -->
                <div class="form-section">
                    <h3>📧 Document Distribution List</h3>
                    <div id="distributionList">
                        <div class="dynamic-item">
                            <input type="text" name="dist_name[]" placeholder="Name" required>
                            <input type="text" name="dist_organization[]" placeholder="Organization" required>
                            <input type="text" name="dist_designation[]" placeholder="Designation" required>
                            <input type="email" name="dist_email[]" placeholder="Email ID" required>
                            <button type="button" class="btn btn-danger" onclick="removeDistribution(this)">Remove</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="addDistribution()">+ Add Distribution</button>
                </div>

                <!-- Engagement Scope -->
                <div class="form-section">
                    <h3>🎯 Engagement Scope</h3>
                    <div id="engagementScopeList">
                        <div class="dynamic-item">
                            <input type="number" name="scope_sr_no[]" placeholder="S. No">
                            <input type="text" name="scope_asset[]" placeholder="Asset Description">
                            <input type="text" name="scope_criticality[]" placeholder="Criticality">
                            <input type="text" name="scope_internal_ip[]" placeholder="Internal IP">
                            <input type="text" name="scope_url[]" placeholder="URL or NA">
                            <input type="text" name="scope_public_ip[]" placeholder="Public IP">
                            <input type="text" name="scope_location[]" placeholder="Location">
                            <input type="text" name="scope_hash[]" placeholder="Hash Value">
                            <input type="text" name="scope_version[]" placeholder="Version">
                            <input type="text" name="scope_other[]" placeholder="Other Details">
                            <button type="button" class="btn btn-danger" onclick="removeEngagementScope(this)">Remove</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="addEngagementScope()">+ Add Asset</button>
                </div>

                <!-- Details of Auditing Team -->
                <div class="form-section">
                    <h3>👥 Details of Auditing Team</h3>
                    <div id="auditingTeamList">
                        <div class="dynamic-item">
                            <input type="text" name="team_name[]" placeholder="Name" required>
                            <input type="text" name="team_designation[]" placeholder="Designation" required>
                            <input type="email" name="team_email[]" placeholder="Email ID" required>
                            <input type="text" name="team_qualifications[]" placeholder="Qualifications/Certifications" required>
                            <select name="team_certin_listed[]" required>
                                <option value="">CERT-In Listed?</option>
                                <option value="Yes">Yes</option>
                                <option value="No">No</option>
                            </select>
                            <button type="button" class="btn btn-danger" onclick="removeAuditingTeam(this)">Remove</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="addAuditingTeam()">+ Add Team Member</button>
                </div>

                <!-- Audit Activities and Timelines -->
                <div class="form-section">
                    <h3>📅 Audit Activities and Timelines</h3>
                    <div id="auditActivitiesList">
                        <div class="dynamic-item">
                            <input type="text" name="activity_task[]" placeholder="Activity/Task" required>
                            <input type="date" name="activity_date[]" required>
                            <button type="button" class="btn btn-danger" onclick="removeAuditActivity(this)">Remove</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="addAuditActivity()">+ Add Activity</button>
                </div>

                <!-- Tools/Software Used -->
                <div class="form-section">
                    <h3>🛠️ Tools/Software Used</h3>
                    <div id="toolsSoftwareList">
                        <div class="dynamic-item">
                            <input type="number" name="tool_sr_no[]" placeholder="S. No" required>
                            <input type="text" name="tool_name[]" placeholder="Name of Tool/Software" required>
                            <input type="text" name="tool_version[]" placeholder="Version" required>
                            <select name="tool_type[]" required>
                                <option value="">Type</option>
                                <option value="Opensource">Opensource</option>
                                <option value="Licensed">Licensed</option>
                            </select>
                            <button type="button" class="btn btn-danger" onclick="removeToolSoftware(this)">Remove</button>
                        </div>
                    </div>
                    <button type="button" class="btn btn-secondary" onclick="addToolSoftware()">+ Add Tool</button>
                </div>

                <!-- Vulnerability Data Upload -->
                <div class="form-section">
                    <h3>🔍 Vulnerability Data (Optional)</h3>
                    <div class="form-group">
                        <label for="vulnerability_file">Upload Vulnerability Excel File (certin_vulnerability_format.xlsx)</label>
                        <input type="file" id="vulnerability_file" name="vulnerability_file" accept=".xlsx,.xls">
                        <small style="color: #666;">If not provided, vulnerability section will be empty</small>
                    </div>
                    
                    <div class="form-group">
                        <label for="poc_files">Upload PoC Zip File (Single file containing all images)</label>
                        <input type="file" id="poc_files" name="poc_files" accept=".zip">
                        <small style="color: #666;">
                            <strong>Single Zip File:</strong> Upload one zip file containing all PoC images<br>
                            <strong>Image Naming:</strong> step1.png, step2.png, step3.png, etc.
                        </small>
                    </div>
                    
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin-top: 10px;">
                        <h4 style="margin-top: 0; color: #6923d0;">📋 PoC File Structure Guide</h4>
                        <p><strong>Single Zip File:</strong> Upload one zip file containing all PoC images</p>
                        <p><strong>Image Naming Convention:</strong></p>
                        <ul>
                            <li><code>step1.png</code> - First step of Observation #1</li>
                            <li><code>step2.png</code> - Second step of Observation #1</li>
                            <li><code>step3.png</code> - First step of Observation #2</li>
                            <li><code>step4.png</code> - Second step of Observation #2</li>
                            <li>... (images will be automatically mapped to observations)</li>
                        </ul>
                        <p><strong>Note:</strong> Images will be automatically mapped to observations based on their step numbers and order in the Excel file.</p>
                    </div>
                </div>

                <!-- Submit Button -->
                <div style="text-align: center; margin-top: 30px;">
                    <button type="submit" class="btn btn-success" style="font-size: 18px; padding: 15px 30px;">
                        🚀 Generate Cert-IN Report
                    </button>
                </div>
            </form>

            <!-- Progress Bar -->
            <div class="progress" id="progress">
                <div style="background-color: #f0f0f0; border-radius: 4px; padding: 10px;">
                    <div id="progressText">Processing...</div>
                    <div class="progress-bar" id="progressBar"></div>
                </div>
            </div>

            <!-- Result -->
            <div class="result" id="result"></div>
        </div>

        <script>
            // CSRF token fetch
            let CSRF_TOKEN = null;
            (async () => {
                try {
                    const res = await fetch('/csrf-token', { credentials: 'same-origin' });
                    if (res.ok) {
                        const data = await res.json().catch(() => ({}));
                        CSRF_TOKEN = data.csrf_token || data.token || data.csrf || null;
                    }
                } catch (_) {}
            })();

            // Dynamic form functions
            function addChangeHistory() {
                const container = document.getElementById('changeHistoryList');
                const div = document.createElement('div');
                div.className = 'dynamic-item';
                div.innerHTML = `
                    <input type="text" name="change_version[]" placeholder="Version" required>
                    <input type="date" name="change_date[]" required>
                    <input type="text" name="change_remarks[]" placeholder="Remarks/Reason of change" required>
                    <button type="button" class="btn btn-danger" onclick="removeChangeHistory(this)">Remove</button>
                `;
                container.appendChild(div);
            }

            function removeChangeHistory(button) {
                button.parentElement.remove();
            }

            function addDistribution() {
                const container = document.getElementById('distributionList');
                const div = document.createElement('div');
                div.className = 'dynamic-item';
                div.innerHTML = `
                    <input type="text" name="dist_name[]" placeholder="Name" required>
                    <input type="text" name="dist_organization[]" placeholder="Organization" required>
                    <input type="text" name="dist_designation[]" placeholder="Designation" required>
                    <input type="email" name="dist_email[]" placeholder="Email ID" required>
                    <button type="button" class="btn btn-danger" onclick="removeDistribution(this)">Remove</button>
                `;
                container.appendChild(div);
            }

            function removeDistribution(button) {
                button.parentElement.remove();
            }

            function addEngagementScope() {
                const container = document.getElementById('engagementScopeList');
                const div = document.createElement('div');
                div.className = 'dynamic-item';
                div.innerHTML = `
                    <input type="number" name="scope_sr_no[]" placeholder="S. No" required>
                    <input type="text" name="scope_asset[]" placeholder="Asset Description" required>
                    <input type="text" name="scope_criticality[]" placeholder="Criticality" required>
                    <input type="text" name="scope_internal_ip[]" placeholder="Internal IP">
                    <input type="url" name="scope_url[]" placeholder="URL">
                    <input type="text" name="scope_public_ip[]" placeholder="Public IP">
                    <input type="text" name="scope_location[]" placeholder="Location">
                    <input type="text" name="scope_hash[]" placeholder="Hash Value">
                    <input type="text" name="scope_version[]" placeholder="Version">
                    <input type="text" name="scope_other[]" placeholder="Other Details">
                    <button type="button" class="btn btn-danger" onclick="removeEngagementScope(this)">Remove</button>
                `;
                container.appendChild(div);
            }

            function removeEngagementScope(button) {
                button.parentElement.remove();
            }

            function addAuditingTeam() {
                const container = document.getElementById('auditingTeamList');
                const div = document.createElement('div');
                div.className = 'dynamic-item';
                div.innerHTML = `
                    <input type="text" name="team_name[]" placeholder="Name" required>
                    <input type="text" name="team_designation[]" placeholder="Designation" required>
                    <input type="email" name="team_email[]" placeholder="Email ID" required>
                    <input type="text" name="team_qualifications[]" placeholder="Qualifications/Certifications" required>
                    <select name="team_certin_listed[]" required>
                        <option value="">CERT-In Listed?</option>
                        <option value="Yes">Yes</option>
                        <option value="No">No</option>
                    </select>
                    <button type="button" class="btn btn-danger" onclick="removeAuditingTeam(this)">Remove</button>
                `;
                container.appendChild(div);
            }

            function removeAuditingTeam(button) {
                button.parentElement.remove();
            }

            function addAuditActivity() {
                const container = document.getElementById('auditActivitiesList');
                const div = document.createElement('div');
                div.className = 'dynamic-item';
                div.innerHTML = `
                    <input type="text" name="activity_task[]" placeholder="Activity/Task" required>
                    <input type="date" name="activity_date[]" required>
                    <button type="button" class="btn btn-danger" onclick="removeAuditActivity(this)">Remove</button>
                `;
                container.appendChild(div);
            }

            function removeAuditActivity(button) {
                button.parentElement.remove();
            }

            function addToolSoftware() {
                const container = document.getElementById('toolsSoftwareList');
                const div = document.createElement('div');
                div.className = 'dynamic-item';
                div.innerHTML = `
                    <input type="number" name="tool_sr_no[]" placeholder="S. No" required>
                    <input type="text" name="tool_name[]" placeholder="Name of Tool/Software" required>
                    <input type="text" name="tool_version[]" placeholder="Version" required>
                    <select name="tool_type[]" required>
                        <option value="">Type</option>
                        <option value="Opensource">Opensource</option>
                        <option value="Licensed">Licensed</option>
                    </select>
                    <button type="button" class="btn btn-danger" onclick="removeToolSoftware(this)">Remove</button>
                `;
                container.appendChild(div);
            }

            function removeToolSoftware(button) {
                button.parentElement.remove();
            }

            // Form submission
            document.getElementById('certinForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const formData = new FormData();
                const form = document.getElementById('certinForm');
                
                // Collect all form data
                for (let element of form.elements) {
                    if (element.name && element.type !== 'file') {
                        if (element.type === 'checkbox') {
                            if (element.checked) {
                                formData.append(element.name, element.value);
                            }
                        } else {
                            formData.append(element.name, element.value);
                        }
                    }
                }
                
                // Handle file uploads
                const vulnerabilityFile = document.getElementById('vulnerability_file').files[0];
                if (vulnerabilityFile) {
                    formData.append('vulnerability_file', vulnerabilityFile);
                }
                
                // Handle PoC zip file (single file)
                const pocFile = document.getElementById('poc_files').files[0];
                if (pocFile) {
                    formData.append('poc_files', pocFile);
                }
                
                // Process dynamic arrays
                const changeVersions = document.querySelectorAll('input[name="change_version[]"]');
                const changeDates = document.querySelectorAll('input[name="change_date[]"]');
                const changeRemarks = document.querySelectorAll('input[name="change_remarks[]"]');
                
                const changeHistory = [];
                for (let i = 0; i < changeVersions.length; i++) {
                    changeHistory.push({
                        version: changeVersions[i].value,
                        date: changeDates[i].value,
                        remarks: changeRemarks[i].value
                    });
                }
                formData.append('document_change_history', JSON.stringify(changeHistory));
                
                // Similar processing for other dynamic arrays...
                const distNames = document.querySelectorAll('input[name="dist_name[]"]');
                const distOrgs = document.querySelectorAll('input[name="dist_organization[]"]');
                const distDesignations = document.querySelectorAll('input[name="dist_designation[]"]');
                const distEmails = document.querySelectorAll('input[name="dist_email[]"]');
                
                const distributionList = [];
                for (let i = 0; i < distNames.length; i++) {
                    distributionList.push({
                        name: distNames[i].value,
                        organization: distOrgs[i].value,
                        designation: distDesignations[i].value,
                        email: distEmails[i].value
                    });
                }
                formData.append('distribution_list', JSON.stringify(distributionList));
                
                // Engagement Scope
                const scopeSrNos = document.querySelectorAll('input[name="scope_sr_no[]"]');
                const scopeAssets = document.querySelectorAll('input[name="scope_asset[]"]');
                const scopeCriticalities = document.querySelectorAll('input[name="scope_criticality[]"]');
                const scopeInternalIPs = document.querySelectorAll('input[name="scope_internal_ip[]"]');
                const scopeURLs = document.querySelectorAll('input[name="scope_url[]"]');
                const scopePublicIPs = document.querySelectorAll('input[name="scope_public_ip[]"]');
                const scopeLocations = document.querySelectorAll('input[name="scope_location[]"]');
                const scopeHashes = document.querySelectorAll('input[name="scope_hash[]"]');
                const scopeVersions = document.querySelectorAll('input[name="scope_version[]"]');
                const scopeOthers = document.querySelectorAll('input[name="scope_other[]"]');
                
                const engagementScope = [];
                for (let i = 0; i < scopeSrNos.length; i++) {
                    engagementScope.push({
                        sr_no: scopeSrNos[i].value,
                        asset_description: scopeAssets[i].value,
                        criticality: scopeCriticalities[i].value,
                        internal_ip: scopeInternalIPs[i].value,
                        url: (scopeURLs[i].value && scopeURLs[i].value.toUpperCase() !== 'NA') ? scopeURLs[i].value : '',
                        public_ip: scopePublicIPs[i].value,
                        location: scopeLocations[i].value,
                        hash_value: scopeHashes[i].value,
                        version: scopeVersions[i].value,
                        other_details: scopeOthers[i].value
                    });
                }
                formData.append('engagement_scope', JSON.stringify(engagementScope));
                
                // Auditing Team
                const teamNames = document.querySelectorAll('input[name="team_name[]"]');
                const teamDesignations = document.querySelectorAll('input[name="team_designation[]"]');
                const teamEmails = document.querySelectorAll('input[name="team_email[]"]');
                const teamQualifications = document.querySelectorAll('input[name="team_qualifications[]"]');
                const teamCertinListed = document.querySelectorAll('select[name="team_certin_listed[]"]');
                
                const auditingTeam = [];
                for (let i = 0; i < teamNames.length; i++) {
                    auditingTeam.push({
                        name: teamNames[i].value,
                        designation: teamDesignations[i].value,
                        email: teamEmails[i].value,
                        qualifications: teamQualifications[i].value,
                        certin_listed: teamCertinListed[i].value
                    });
                }
                formData.append('auditing_team', JSON.stringify(auditingTeam));
                
                // Audit Activities
                const activityTasks = document.querySelectorAll('input[name="activity_task[]"]');
                const activityDates = document.querySelectorAll('input[name="activity_date[]"]');
                
                const auditActivities = [];
                for (let i = 0; i < activityTasks.length; i++) {
                    auditActivities.push({
                        task: activityTasks[i].value,
                        date: activityDates[i].value
                    });
                }
                formData.append('audit_activities', JSON.stringify(auditActivities));
                
                // Tools/Software
                const toolSrNos = document.querySelectorAll('input[name="tool_sr_no[]"]');
                const toolNames = document.querySelectorAll('input[name="tool_name[]"]');
                const toolVersions = document.querySelectorAll('input[name="tool_version[]"]');
                const toolTypes = document.querySelectorAll('select[name="tool_type[]"]');
                
                const toolsSoftware = [];
                for (let i = 0; i < toolSrNos.length; i++) {
                    toolsSoftware.push({
                        sr_no: toolSrNos[i].value,
                        name: toolNames[i].value,
                        version: toolVersions[i].value,
                        type: toolTypes[i].value
                    });
                }
                formData.append('tools_software', JSON.stringify(toolsSoftware));
                
                try {
                    document.getElementById('progress').style.display = 'block';
                    document.getElementById('progressText').textContent = 'Generating report...';
                    document.getElementById('progressBar').style.width = '50%';
                    
                    const response = await fetch('/type3/generate-report/', {
                        method: 'POST',
                        headers: CSRF_TOKEN ? { 'X-CSRF-Token': CSRF_TOKEN } : {},
                        body: formData,
                        credentials: 'same-origin'
                    });
                    
                    if (!response.ok) {
                        let msg = 'Report generation failed';
                        try {
                            const errorData = await response.json();
                            msg = errorData.detail || JSON.stringify(errorData);
                        } catch (e) {
                            const txt = await response.text();
                            if (txt) msg = txt;
                        }
                        throw new Error(msg);
                    }
                    
                    const result = await response.json();
                    
                    document.getElementById('progressText').textContent = 'Report generated successfully!';
                    document.getElementById('progressBar').style.width = '100%';
                    
                    document.getElementById('result').innerHTML = `
                        <h3>✅ Report Generated Successfully!</h3>
                        <p><strong>Filename:</strong> ${result.filename}</p>
                        <a href="${result.download_url}" download class="btn btn-success">
                            📥 Download Report
                        </a>
                    `;
                    document.getElementById('result').className = 'result success';
                    document.getElementById('result').style.display = 'block';
                    
                } catch (error) {
                    document.getElementById('progress').style.display = 'none';
                    document.getElementById('result').innerHTML = `
                        <h3>❌ Error</h3>
                        <p>${error.message}</p>
                    `;
                    document.getElementById('result').className = 'result error';
                    document.getElementById('result').style.display = 'block';
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/generate-report/")
async def generate_report(
    request: Request,
    db: Session = Depends(get_db),
    **form_data
):
    """Generate Cert-IN report from form data"""
    try:
        print(f"Starting Cert-IN report generation from form - Version {VERSION}")
        
        # Extract form data
        data = dict(form_data)
        
        # Handle vulnerability file upload if provided
        vulnerability_data = []
        poc_mapping = {}
        
        if 'vulnerability_file' in data and data['vulnerability_file']:
            # Save uploaded file temporarily
            vulnerability_file = data['vulnerability_file']
            temp_path = os.path.join(UPLOAD_DIR, f"temp_vuln_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
            content = await vulnerability_file.read()
            with open(temp_path, "wb") as f:
                f.write(content)
            
            # Read vulnerability data
            vulnerability_data = read_vulnerability_excel(temp_path)
            
            # Clean up temp file
            os.remove(temp_path)
        
        # Handle PoC zip file if provided
        if 'poc_files' in data and data['poc_files']:
            poc_file = data['poc_files']
            poc_mapping = await process_poc_zip_files([poc_file], vulnerability_data)
        
        # Template path
        template_path = os.path.join(os.path.dirname(__file__), "CSS Certin temp.docx")
        if not os.path.exists(template_path):
            raise HTTPException(status_code=404, detail="Cert-IN template not found")
        
        # Generate output filename
        client_name = data.get('client_name', 'Client')
        report_filename = f"{client_name} Cert-IN Report {datetime.now().strftime('%Y-%d-%m')}.docx"
        output_path = os.path.join(UPLOAD_DIR, report_filename)
        
        # Generate report with vulnerability data and PoC mapping
        generate_certin_report_from_form(data, template_path, output_path, vulnerability_data, poc_mapping)
        
        # Save to database
        try:
            user = request.session.get('user') or {}
            certin_report = CertINReport(
                client_name=data.get('client_name', ''),
                report_name=data.get('report_name', ''),
                report_release_date=data.get('report_release_date', ''),
                type_of_audit=data.get('type_of_audit', ''),
                type_of_audit_report=data.get('type_of_audit_report', ''),
                period=data.get('period', ''),
                document_title=data.get('document_title', ''),
                document_id=data.get('document_id', ''),
                document_version=data.get('document_version', ''),
                prepared_by=data.get('prepared_by', ''),
                reviewed_by=data.get('reviewed_by', ''),
                approved_by=data.get('approved_by', ''),
                released_by=data.get('released_by', ''),
                release_date=data.get('release_date', ''),
                document_change_history=data.get('document_change_history', '[]'),
                distribution_list=data.get('distribution_list', '[]'),
                engagement_scope=data.get('engagement_scope', '[]'),
                auditing_team=data.get('auditing_team', '[]'),
                audit_activities=data.get('audit_activities', '[]'),
                tools_software=data.get('tools_software', '[]'),
                created_by_email=user.get('email', 'unknown'),
                created_by_name=user.get('name'),
                file_path=output_path
            )
            db.add(certin_report)
            db.commit()
        except Exception as e:
            print(f"Error saving to database: {e}")
        
        print(f"Cert-IN report generation completed successfully - Version {VERSION}")
        
        # Log the action
        try:
            user = request.session.get('user') or {}
            db.add(AuditLog(
                user_email=user.get('email'),
                user_name=user.get('name'),
                action='generate-certin-report-form',
                metadata_json=json.dumps({
                    'client_name': data.get('client_name'),
                    'template_used': 'CSS Certin temp.docx',
                    'version': VERSION,
                    'has_vulnerability_data': len(vulnerability_data) > 0,
                    'has_poc_data': len(poc_mapping) > 0,
                    'vulnerability_count': len(vulnerability_data),
                    'poc_count': len(poc_mapping)
                }),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get('user-agent')
            ))
            db.commit()
        except Exception as e:
            print(f"Error logging audit: {e}")
        
        return JSONResponse(
            content={
                "message": "Cert-IN report generated successfully",
                "filename": report_filename,
                "download_url": f"/type3/download/{report_filename}",
                "vulnerability_count": len(vulnerability_data),
                "poc_count": len(poc_mapping)
            },
            status_code=200
        )
        
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download/{filename}")
async def download_report(filename: str):
    """Download generated report"""
    try:
        # Sanitize filename
        safe_filename = sanitize_filename(filename)
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Report not found")
        
        return FileResponse(
            path=file_path,
            filename=safe_filename,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/")
async def list_reports(request: Request, db: Session = Depends(get_db)):
    """List all generated Cert-IN reports"""
    try:
        user = request.session.get('user')
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        reports = db.query(CertINReport).order_by(CertINReport.created_at.desc()).limit(50).all()
        
        return [
            {
                "id": report.id,
                "client_name": report.client_name,
                "report_name": report.report_name,
                "document_title": report.document_title,
                "created_at": report.created_at.isoformat(),
                "created_by": report.created_by_name,
                "download_url": f"/type3/download/{os.path.basename(report.file_path)}" if report.file_path else None
            }
            for report in reports
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)