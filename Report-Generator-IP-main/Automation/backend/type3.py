from fastapi import FastAPI, UploadFile, File, HTTPException, Form, Request, Depends
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import os
import sys
import pandas as pd
from docxtpl import DocxTemplate
from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from datetime import datetime
import traceback
import tempfile
import json
import re
import zipfile
import io
from sqlalchemy.orm import Session
from db import get_db, AuditLog, CertINReport

# Add parent directory to path to import excel_parser
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from excel_parser import parse_excel_data, format_for_template

VERSION = "2.2.0"

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "supersecret"),
    https_only=False,
    same_site="lax",
    session_cookie="reportgen_session"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def sanitize_filename(filename):
    if not filename:
        return "upload.xlsx"
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    return safe_name

def read_vulnerability_excel(file_path):
    """
    Read vulnerability data from Excel using standardized parser with fallback to legacy parsing.
    Converts the new format to legacy format for compatibility with existing code.
    """
    # Try standardized parser first
    try:
        parsed_data = parse_excel_data(file_path)
        
        # Check if we got valid data
        if parsed_data and parsed_data.get('vulnerabilities'):
            print(f"✅ Parsed Excel with standardized parser")
            print(f"   Metadata: {parsed_data['metadata']}")
            print(f"   Assets: {len(parsed_data['assets'])} assets")
            print(f"   Vulnerabilities: {len(parsed_data['vulnerabilities'])} vulnerabilities")
            
            # Convert to legacy format expected by rest of type3.py code
            vulnerabilities = []
            for idx, vuln in enumerate(parsed_data['vulnerabilities'], 1):
                vuln_data = {
                    # Map new format to old format
                    'observation_number': str(vuln.get('sr_no', idx)),
                    'observation': vuln.get('observation', vuln.get('sr_no', idx)),
                    'new_or_repeat': vuln.get('new_or_re', 'New'),
                    'asset': vuln.get('affected_asset', ''),
                    'purpose': '',  # Not directly in vuln, would come from assets
                    'vapt_status': vuln.get('status', 'Open'),
                    'tester_name': vuln.get('tester', parsed_data['metadata']['tester']),
                    'project': vuln.get('project', parsed_data['metadata']['project']),
                    'client': vuln.get('client', parsed_data['metadata']['client']),
                    'cve_cwe': vuln.get('cve_cwe', ''),
                    'cvss': str(vuln.get('cvss', '')),
                    'cvss_version': '',  # Can be extracted from cvss_vector if needed
                    'cvss_vector': vuln.get('cvss_vector', ''),
                    'affected_asset': vuln.get('affected_asset', '') or vuln.get('ip_url_app', ''),
                    'title': vuln.get('observation', ''),
                    'description': vuln.get('detailed_observation', '') or vuln.get('observation_summary', ''),
                    'recommendation': vuln.get('recommendation', ''),
                    'reference': vuln.get('reference', ''),
                    'evidence': vuln.get('evidence', ''),
                    'severity': vuln.get('severity', 'Medium'),
                    'status': vuln.get('status', 'Open'),
                    # Count fields (not used in type3 but kept for compatibility)
                    'critical': '',
                    'high': '',
                    'medium': '',
                    'low': '',
                    'informational': '',
                    'total': ''
                }
                
                # If evidence is empty but we have steps, create evidence text from steps
                if not vuln_data['evidence'] and vuln.get('steps'):
                    evidence_lines = []
                    for step in vuln['steps']:
                        evidence_lines.append(f"Step {step['number']}: {step['content']}")
                    vuln_data['evidence'] = '\n'.join(evidence_lines)
                
                vulnerabilities.append(vuln_data)
                print(f"📄 Row {idx}: Tester={vuln_data['tester_name']}, Project={vuln_data['project']}, Client={vuln_data['client']}, Title={vuln_data['title'][:50]}")
            
            print(f"✅ Converted {len(vulnerabilities)} vulnerabilities to legacy format")
            return vulnerabilities
        else:
            print("⚠️ Standardized parser returned no vulnerabilities, falling back to legacy parsing")
            raise Exception("No vulnerabilities found in standardized parser")
            
    except Exception as e:
        print(f"⚠️ Standardized parser failed: {e}")
        print("📋 Falling back to legacy Excel parsing...")
        traceback.print_exc()
        
        # FALLBACK: Use original/legacy parsing logic
        # If you had a legacy parser before, restore it here
        # For now, return empty to avoid breaking
        return []

async def process_poc_zip_files(poc_files, vulnerabilities):
    """
    Process PoC zip with structure: POC_certIN.zip/POC_certIN/#1, #2, etc.
    Each folder contains images for that specific observation only
    """
    poc_mapping = {}
    
    for poc_file in poc_files:
        if not poc_file.filename:
            continue
            
        temp_zip_path = os.path.join(UPLOAD_DIR, f"temp_{poc_file.filename}")
        content = await poc_file.read()
        with open(temp_zip_path, "wb") as f:
            f.write(content)
        
        extract_dir = os.path.join(UPLOAD_DIR, "poc_images")
        # Clean extract directory to prevent contamination from previous uploads
        if os.path.exists(extract_dir):
            import shutil
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            with zipfile.ZipFile(temp_zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            print(f"✅ Extracted zip to: {extract_dir}")
            
            # Find all observation folders (#1, #2, #3, etc.)
            for root, dirs, files in os.walk(extract_dir):
                for dir_name in dirs:
                    # Check if directory name matches #1, #2, etc.
                    match = re.match(r'#(\d+)', dir_name)
                    if match:
                        obs_num = int(match.group(1))
                        obs_key = f"OBS-{obs_num:03d}"
                        obs_folder = os.path.join(root, dir_name)
                        
                        print(f"📁 Found observation folder: {obs_folder} for {obs_key}")
                        
                        # Get all images in this observation folder ONLY
                        obs_images = []
                        for img_file in sorted(os.listdir(obs_folder)):
                            if img_file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                                img_path = os.path.join(obs_folder, img_file)
                                
                                # Extract step number from filename
                                step_match = re.search(r'step[_\-\s]?(\d+)', img_file.lower())
                                if step_match:
                                    step_num = int(step_match.group(1))
                                else:
                                    # Try just extracting a number
                                    num_match = re.search(r'(\d+)', img_file)
                                    step_num = int(num_match.group(1)) if num_match else len(obs_images) + 1
                                
                                obs_images.append({
                                    'filename': img_file,
                                    'path': img_path,
                                    'step_number': step_num
                                })
                                print(f"  🖼️  Found image: {img_file} (Step {step_num})")
                        
                        # Sort images by step number
                        obs_images.sort(key=lambda x: x['step_number'])
                        
                        if obs_images:
                            poc_mapping[obs_key] = obs_images
                            print(f"✅ Mapped {len(obs_images)} images to {obs_key}")
            
        except Exception as e:
            print(f"Error extracting PoC zip: {e}")
            traceback.print_exc()
        finally:
            if os.path.exists(temp_zip_path):
                os.remove(temp_zip_path)
    
    print(f"🎯 Final PoC mapping keys: {list(poc_mapping.keys())}")
    for key, images in poc_mapping.items():
        print(f"   {key}: {len(images)} images")
    return poc_mapping

def parse_evidence_steps(evidence_text):
    """Parse evidence/PoC text to extract step descriptions"""
    if not evidence_text or evidence_text.lower() in ['nan', 'none', '']:
        return []
    
    steps = []
    
    # Try to split by "Step X:" pattern
    step_pattern = re.compile(r'Step\s*(\d+)\s*[:\-]?\s*(.+?)(?=Step\s*\d+|$)', re.IGNORECASE | re.DOTALL)
    matches = step_pattern.findall(evidence_text)
    
    if matches:
        for step_num, step_desc in matches:
            steps.append({
                'number': int(step_num),
                'description': step_desc.strip()
            })
    else:
        # If no step pattern, split by newlines and number each
        lines = [line.strip() for line in evidence_text.split('\n') if line.strip()]
        for i, line in enumerate(lines, 1):
            steps.append({
                'number': i,
                'description': line
            })
    
    return steps

def generate_vulnerability_sections(vulnerabilities, poc_mapping):
    """Generate vulnerability sections with proper data extraction"""
    vulnerability_sections = []
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\nProcessing vulnerability {i}:")
        print(f"Available keys: {list(vuln.keys())}")
        
        # Extract data using standard keys from normalized mapping
        obs_num = vuln.get('observation_number', str(i))
        new_or_repeat = vuln.get('new_or_repeat', 'New')
        cve_cwe = vuln.get('cve_cwe', '')
        cvss_version = vuln.get('cvss_version', '')
        affected_asset = vuln.get('affected_asset', '')
        title = vuln.get('title', '')
        description = vuln.get('description', '')
        recommendation = vuln.get('recommendation', '')
        reference = vuln.get('reference', '')
        evidence_text = vuln.get('evidence', '')
        
        # Extract severity and other metadata
        severity = vuln.get('severity', 'Medium')
        cvss = vuln.get('cvss', '')
        cvss_vector = vuln.get('cvss_vector', '')
        status = vuln.get('status', 'Open')
        
        print(f"Extracted - Title: {title}, CVE: {cve_cwe}, Asset: {affected_asset}")
        
        # Parse evidence steps from Excel - ensure evidence_text is a string
        if not isinstance(evidence_text, str):
            evidence_text = str(evidence_text) if evidence_text and not (isinstance(evidence_text, float) and pd.isna(evidence_text)) else ''
        evidence_steps = parse_evidence_steps(evidence_text)
        
        # Get PoC images for this observation
        obs_key = f"OBS-{i:03d}"
        poc_images = poc_mapping.get(obs_key, [])
        
        print(f"Found {len(poc_images)} PoC images for {obs_key}")
        print(f"Found {len(evidence_steps)} evidence steps from Excel")
        
        # Match images with step descriptions
        matched_poc = []
        for idx, img in enumerate(poc_images):
            step_desc = ''
            if idx < len(evidence_steps):
                step_desc = evidence_steps[idx]['description']
            
            matched_poc.append({
                'filename': img['filename'],
                'path': img['path'],
                'step_number': idx + 1,
                'description': step_desc
            })
        
        # Process recommendations
        recommendations_list = []
        if recommendation and isinstance(recommendation, str):
            rec_lines = [line.strip() for line in recommendation.split('\n') if line.strip()]
            for line in rec_lines:
                clean_line = re.sub(r'^\d+\.\s*', '', line)
                if clean_line:
                    recommendations_list.append(clean_line)
        
        vulnerability_section = {
            'observation_number': i,
            'new_or_repeat': new_or_repeat,
            'severity': severity,
            'status': status,
            'cve_cwe': cve_cwe,
            'cvss': cvss,
            'cvss_version': cvss_version,
            'cvss_vector': cvss_vector,
            'affected_asset': affected_asset,
            'title': title,
            'description': description,
            'recommendations': recommendations_list,
            'reference': reference,
            'poc_images': matched_poc,
            'has_poc': len(matched_poc) > 0
        }
        
        vulnerability_sections.append(vulnerability_section)
        print(f"Created section with {len(matched_poc)} PoC images")
    
    return vulnerability_sections



def create_landscape_vulnerability_box(doc, vulnerability_section):
    """Create properly formatted vulnerability box matching expected layout"""
    import os
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import parse_xml
    from docx.oxml.ns import nsdecls

    # helper to set explicit cell width so Word respects it
    def set_cell_width(cell, width_inches):
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        # width in twentieths of a point (dxa) is what Word expects - but python-docx uses w:w with type="dxa"
        tcPr.append(parse_xml(f'<w:tcW {nsdecls("w")} w:w="{int(width_inches * 914400/914400*1440)}" w:type="dxa"/>'))

    # compact paragraph formatting helper
    def make_para(cell, align=WD_ALIGN_PARAGRAPH.LEFT):
        p = cell.paragraphs[0]
        p.alignment = align
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1
        p.text = ""  # clear any runs
        return p

    # Create table with 2 header rows initially
    table = doc.add_table(rows=2, cols=3)
    table.style = 'Table Grid'
    # Try to prevent Word from auto-fitting
    try:
        table.autofit = False
    except Exception:
        pass

    # Determine page usable width so we can size columns reasonably
    section = doc.sections[-1]
    page_usable_width = section.page_width - section.left_margin - section.right_margin

    # choose column widths (as Inches) that add up to page width (approx)
    # You can tweak these to match your template (example: 3.2 / 1.4 / 1.4)
    col_widths_in = [Inches(3.2), Inches(1.9), Inches(1.9)]

    # set each column width on both column object and each cell
    for col_idx, w in enumerate(col_widths_in):
        try:
            table.columns[col_idx].width = w
        except Exception:
            # some python-docx versions don't allow setting columns; fall back to per-cell width
            pass
        for row in table.rows:
            set_cell_width(row.cells[col_idx], w.inches if hasattr(w, 'inches') else float(w))

    # ---------- Header row 1: Observation | Severity | Status ----------
    # Observation cell
    cell_obs = table.rows[0].cells[0]
    p_obs = make_para(cell_obs, WD_ALIGN_PARAGRAPH.LEFT)
    r_obs = p_obs.add_run(f"Observation: #{vulnerability_section.get('observation_number','1')}")
    r_obs.font.name = 'Altone Trial'
    r_obs.font.size = Pt(11)
    r_obs.font.bold = True

    # Severity cell with colored background
    severity = vulnerability_section.get('severity', 'Medium').strip()
    severity_colors = {
        'Critical': {'bg': '990000', 'text': 'FFFFFF'},
        'High': {'bg': 'FF0000', 'text': 'FFFFFF'},
        'Medium': {'bg': 'FFCC00', 'text': '000000'},
        'Low': {'bg': '009933', 'text': 'FFFFFF'},
        'Informational': {'bg': '3399CC', 'text': 'FFFFFF'}
    }
    colors = severity_colors.get(severity, severity_colors['Medium'])

    cell_sev = table.rows[0].cells[1]
    p_sev = make_para(cell_sev, WD_ALIGN_PARAGRAPH.CENTER)
    r_sev = p_sev.add_run(f"Severity: {severity}")
    r_sev.font.name = 'Altone Trial'
    r_sev.font.size = Pt(11)
    r_sev.font.bold = True
    # set text color
    if colors['text'] == 'FFFFFF':
        r_sev.font.color.rgb = RGBColor(255, 255, 255)
    else:
        r_sev.font.color.rgb = RGBColor(0, 0, 0)
    # shading (w:fill expects hex without #)
    cell_sev._element.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="{colors["bg"]}"/>'))

    # Status cell (yellow)
    cell_status = table.rows[0].cells[2]
    p_stat = make_para(cell_status, WD_ALIGN_PARAGRAPH.CENTER)
    status_text = vulnerability_section.get('status', 'Open')
    r_stat = p_stat.add_run(f"Status: {status_text}")
    r_stat.font.name = 'Altone Trial'
    r_stat.font.size = Pt(11)
    r_stat.font.bold = True
    cell_status._element.get_or_add_tcPr().append(parse_xml(f'<w:shd {nsdecls("w")} w:fill="FFD966"/>'))

    # ---------- Row 2: New/Repeat & CVSS (merge across 3 cols) ----------
    cvss_cell = table.rows[1].cells[0]
    cvss_cell.merge(table.rows[1].cells[1])
    cvss_cell.merge(table.rows[1].cells[2])
    cvss_para = make_para(cvss_cell, WD_ALIGN_PARAGRAPH.LEFT)

    # New or Repeat
    new_or_repeat = vulnerability_section.get('new_or_repeat', 'New')
    nor_run = cvss_para.add_run(f"New or Repeat Observation: {new_or_repeat}")
    nor_run.font.name = 'Altone Trial'
    nor_run.font.size = Pt(10)
    nor_run.font.bold = True
    cvss_para.add_run("    ")

    # CVSS
    if vulnerability_section.get('cvss'):
        cvss_run = cvss_para.add_run(f"CVSS: {vulnerability_section['cvss']}")
        cvss_run.font.name = 'Altone Trial'
        cvss_run.font.size = Pt(10)
        cvss_run.font.bold = True

    # ---------- Content row (merged across 3 cols) ----------
    content_row = table.add_row()
    # merge all three cells in content_row so we get one wide cell
    content_cell = content_row.cells[0]
    content_cell.merge(content_row.cells[1])
    content_cell.merge(content_row.cells[2])
    # clear paragraphs in content_cell
    for p in content_cell.paragraphs:
        p.text = ""

    def add_bold_label_paragraph(parent_cell, label, text, is_url=False, underline=False):
        p = parent_cell.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1
        run_label = p.add_run(label)
        run_label.font.name = 'Altone Trial'
        run_label.font.size = Pt(10)
        run_label.font.bold = True
        # Ensure text is a string (handle NaN/float values)
        if text is None or (isinstance(text, float) and pd.isna(text)):
            text = ''
        text = str(text)
        run_value = p.add_run(text)
        run_value.font.name = 'Altone Trial'
        run_value.font.size = Pt(10)
        if is_url:
            run_value.font.color.rgb = RGBColor(0, 0, 255)
            run_value.font.underline = True
        if underline:
            run_value.font.underline = True
        return p

    # CVSS Version Ref
    if vulnerability_section.get('cvss_version'):
        add_bold_label_paragraph(content_cell, "CVSS Version Ref: ", vulnerability_section['cvss_version'])

    # CVE/CWE
    if vulnerability_section.get('cve_cwe'):
        add_bold_label_paragraph(content_cell, "CVE/CWE: ", vulnerability_section['cve_cwe'])

    # CVSS Vector
    if vulnerability_section.get('cvss_vector'):
        add_bold_label_paragraph(content_cell, "CVSS Vector: ", vulnerability_section['cvss_vector'])

    # Affected Asset
    if vulnerability_section.get('affected_asset'):
        add_bold_label_paragraph(content_cell, "Affected Asset i.e. IP/URL/Application etc.: ", vulnerability_section['affected_asset'], is_url=True)

    # Vulnerability Title
    if vulnerability_section.get('title'):
        add_bold_label_paragraph(content_cell, "Observation/ Vulnerability Title: ", vulnerability_section['title'])

    # Detailed Observation
    if vulnerability_section.get('description'):
        add_bold_label_paragraph(content_cell, "Detailed Observation/ Vulnerable Point: ", vulnerability_section['description'])

    # Recommendations
    if vulnerability_section.get('recommendations'):
        p = content_cell.add_paragraph()
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run("Recommendation:\n")
        run.font.name = 'Altone Trial'
        run.font.size = Pt(10)
        run.font.bold = True
        for i, rec in enumerate(vulnerability_section['recommendations'], 1):
            rp = content_cell.add_paragraph(f"{i}. {rec}")
            rp.paragraph_format.space_before = Pt(0)
            rp.paragraph_format.space_after = Pt(0)
            rr = rp.runs[0]
            rr.font.name = 'Altone Trial'
            rr.font.size = Pt(10)

    # Reference
    if vulnerability_section.get('reference'):
        add_bold_label_paragraph(content_cell, "Reference:\n", vulnerability_section['reference'], is_url=True)

    # Evidence/Proof of Concept images
    if vulnerability_section.get('has_poc') and vulnerability_section.get('poc_images'):
        poc_label = content_cell.add_paragraph()
        poc_label.paragraph_format.space_before = Pt(0)
        poc_label.paragraph_format.space_after = Pt(0)
        pl = poc_label.add_run("Evidence / Proof of Concept:\n")
        pl.font.name = 'Altone Trial'
        pl.font.size = Pt(10)
        pl.font.bold = True

        # compute max image width based on page usable width minus a small margin
        max_img_width = page_usable_width - Inches(0.4)
        # convert to Inches for add_picture (python-docx uses Inches)
        try:
            max_img_width_in = Inches(max_img_width.inches)
        except Exception:
            # fallback if page_usable_width is already an Inches-like object
            max_img_width_in = Inches(5)

        for poc_img in vulnerability_section['poc_images']:
            step_para = content_cell.add_paragraph()
            step_para.paragraph_format.space_before = Pt(0)
            step_para.paragraph_format.space_after = Pt(0)
            step_text = f"Step {poc_img.get('step_number','')}: "
            if poc_img.get('description'):
                step_text += poc_img['description']
            step_run = step_para.add_run(step_text)
            step_run.font.name = 'Altone Trial'
            step_run.font.size = Pt(10)
            step_run.font.bold = True

            # Add the image if present
            img_path = poc_img.get('path') or poc_img.get('filename')
            if img_path and os.path.exists(img_path):
                img_para = content_cell.add_paragraph()
                img_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                img_run = img_para.add_run()
                try:
                    img_run.add_picture(img_path, width=max_img_width_in)
                except Exception as e:
                    err_p = content_cell.add_paragraph(f"[Image error: {os.path.basename(img_path)}: {e}]")
                    err_p.runs[0].italic = True
            else:
                missing_p = content_cell.add_paragraph(f"[Image missing: {poc_img.get('filename', 'unknown')}]")
                missing_p.runs[0].italic = True

    return table


def generate_certin_report_from_form(data, template_path, output_path, vulnerability_data=None, poc_mapping=None):
    """Generate Cert-IN report from form data and template"""
    try:
        safe_template_path = _sanitize_docx_jinja_placeholders(template_path)
        doc = DocxTemplate(safe_template_path)
        
        document_change_history = json.loads(data.get('document_change_history', '[]'))
        distribution_list = json.loads(data.get('distribution_list', '[]'))
        engagement_scope = json.loads(data.get('engagement_scope', '[]'))
        auditing_team = json.loads(data.get('auditing_team', '[]'))
        audit_activities = json.loads(data.get('audit_activities', '[]'))
        tools_software = json.loads(data.get('tools_software', '[]'))
        
        vulnerability_sections = []
        client_name_from_excel = ''
        project_name_from_excel = ''
        if vulnerability_data and poc_mapping is not None:
            vulnerability_sections = generate_vulnerability_sections(vulnerability_data, poc_mapping)
            # Extract client/project from first vulnerability row if not provided in form
            if vulnerability_data:
                client_name_from_excel = vulnerability_data[0].get('client', '')
                project_name_from_excel = vulnerability_data[0].get('project', '')
                print(f"📊 Extracted from Excel - Client: {client_name_from_excel}, Project: {project_name_from_excel}")
        
        # Use form data as primary, fall back to Excel data
        final_client_name = data.get('client_name', '') or client_name_from_excel
        final_report_name = data.get('report_name', '') or project_name_from_excel
        
        context = {
            'CLIENT_NAME': final_client_name,
            'REPORT_NAME': final_report_name,
            'REPORT_RELEASE_DATE': data.get('report_release_date', ''),
            'TYPE_OF_AUDIT': data.get('type_of_audit', ''),
            'TYPE_OF_AUDIT_REPORT': data.get('type_of_audit_report', ''),
            'PERIOD': data.get('period', ''),
            'DOCUMENT_TITLE': data.get('document_title', ''),
            'DOCUMENT_ID': data.get('document_id', ''),
            'DOCUMENT_VERSION': data.get('document_version', ''),
            'PREPARED_BY': data.get('prepared_by', ''),
            'REVIEWED_BY': data.get('reviewed_by', ''),
            'APPROVED_BY': data.get('approved_by', ''),
            'RELEASED_BY': data.get('released_by', ''),
            'RELEASE_DATE': data.get('release_date', ''),
            'DOCUMENT_CHANGE_HISTORY': document_change_history,
            'DISTRIBUTION_LIST': distribution_list,
            'ENGAGEMENT_SCOPE': engagement_scope,
            'AUDITING_TEAM': auditing_team,
            'AUDIT_ACTIVITIES': audit_activities,
            'TOOLS_SOFTWARE': tools_software,
            'VULNERABILITIES': vulnerability_sections,
            'HAS_VULNERABILITIES': len(vulnerability_sections) > 0,
            'VULNERABILITY_COUNT': len(vulnerability_sections),
            'GENERATION_DATE': datetime.now().strftime('%d %B %Y'),
            'GENERATION_TIME': datetime.now().strftime('%H:%M:%S'),
        }
        
        doc.render(context)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".docx") as tmp:
            doc.save(tmp.name)
            tmp_path = tmp.name
        
        from docx import Document
        doc = Document(tmp_path)
        
        if vulnerability_sections:
            doc.add_page_break()
            
            vuln_heading = doc.add_paragraph()
            vuln_heading.alignment = WD_ALIGN_PARAGRAPH.CENTER
            vuln_run = vuln_heading.add_run("Detailed Observations")
            vuln_run.font.name = 'Altone Trial'
            vuln_run.font.size = Pt(18)
            vuln_run.font.bold = True
            vuln_run.font.color.rgb = RGBColor(106, 68, 154)
            
            for i, vuln_section in enumerate(vulnerability_sections):
                create_landscape_vulnerability_box(doc, vuln_section)
                
                if i < len(vulnerability_sections) - 1:
                    doc.add_page_break()
        
        doc.save(output_path)
        os.remove(tmp_path)
        
        return True
        
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

def _sanitize_docx_jinja_placeholders(template_path: str) -> str:
    try:
        with open(template_path, 'rb') as f:
            original_bytes = f.read()
        zin = zipfile.ZipFile(io.BytesIO(original_bytes))
        out_buf = io.BytesIO()
        zout = zipfile.ZipFile(out_buf, 'w', zipfile.ZIP_DEFLATED)
        
        pattern_expr = re.compile(r"(\{\{\s*)([^}]+?)(\s*\}\})")
        
        def _normalize_print_statement(inner: str) -> str:
            inner = inner.strip()
            if inner == "Audit.sr_no":
                inner = "team.sr_no"
            
            chars = []
            for ch in inner:
                if re.match(r"[A-Za-z0-9_.]", ch):
                    chars.append(ch)
                elif ch.isspace():
                    chars.append('_')
                else:
                    chars.append('_')
            return ''.join(chars)
        
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename.startswith('word/') and item.filename.endswith('.xml'):
                xml = data.decode('utf-8', errors='ignore')
                xml = pattern_expr.sub(lambda m: m.group(1) + _normalize_print_statement(m.group(2)) + m.group(3), xml)
                data = xml.encode('utf-8')
            zout.writestr(item, data)
        zin.close()
        zout.close()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.docx') as tmpf:
            tmpf.write(out_buf.getvalue())
            return tmpf.name
    except Exception:
        return template_path

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
            body { font-family: Calibri, sans-serif; margin: 20px; background-color: #f5f5f5; }
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
            .info-box { background-color: #e7f3ff; border-left: 4px solid #2196F3; padding: 15px; margin: 15px 0; }
            .info-box h4 { margin-top: 0; color: #2196F3; }
            .info-box code { background-color: #fff; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Cert-IN Report Generator v2.2</h1>
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
                    <h3>🔍 Vulnerability Data (Required)</h3>
                    
                    <div class="info-box">
                        <h4>📋 Excel Format Requirements</h4>
                        <p><strong>Required columns (any case/spacing):</strong></p>
                        <ul>
                            <li><code>New or Repeat Observation</code></li>
                            <li><code>CVE/CWE</code></li>
                            <li><code>CVSS Version Ref</code></li>
                            <li><code>Affected Asset i.e. IP/URL/Application etc.</code></li>
                            <li><code>Observation/ Vulnerability Title</code></li>
                            <li><code>Detailed Observation/ Vulnerable Point</code></li>
                            <li><code>Recommendation</code></li>
                            <li><code>Reference</code></li>
                            <li><code>Evidence / Proof of Concept</code> - Write step descriptions here</li>
                        </ul>
                        <p><strong>Note:</strong> Column names are case-insensitive and flexible with spaces</p>
                    </div>
                    
                    <div class="form-group">
                        <label for="vulnerability_file">Upload Vulnerability Excel File *</label>
                        <input type="file" id="vulnerability_file" name="vulnerability_file" accept=".xlsx,.xls" required>
                    </div>
                    
                    <div class="info-box">
                        <h4>📁 PoC Zip Structure Requirements</h4>
                        <p><strong>Folder Structure:</strong></p>
                        <code>POC_certIN.zip/POC_certIN/#1, #2, #3</code>
                        <p><strong>Example:</strong></p>
                        <ul>
                            <li><code>POC_certIN/#1/step1.png</code> → Observation #1, Step 1</li>
                            <li><code>POC_certIN/#1/step2.png</code> → Observation #1, Step 2</li>
                            <li><code>POC_certIN/#2/step1.png</code> → Observation #2, Step 1</li>
                        </ul>
                        <p><strong>Important:</strong> Each <code>#N</code> folder contains ONLY images for that observation</p>
                    </div>
                    
                    <div class="form-group">
                        <label for="poc_files">Upload PoC Zip File *</label>
                        <input type="file" id="poc_files" name="poc_files" accept=".zip" required>
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

            document.getElementById('certinForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const formData = new FormData();
                const form = document.getElementById('certinForm');
                
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
                
                const vulnerabilityFile = document.getElementById('vulnerability_file').files[0];
                if (vulnerabilityFile) {
                    formData.append('vulnerability_file', vulnerabilityFile);
                }
                
                const pocFile = document.getElementById('poc_files').files[0];
                if (pocFile) {
                    formData.append('poc_files', pocFile);
                }
                
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
                
                const teamNames = document.querySelectorAll('input[name="team_name[]"]');
                const teamDesignations = document.querySelectorAll('input[name="team_designation[]"]');
                const teamEmails = document.querySelectorAll('input[name="team_email[]"]');
                const teamQualifications = document.querySelectorAll('input[name="team_qualifications[]"]');
                const teamCertinListed = document.querySelectorAll('select[name="team_certin_listed[]"]');
                
                const auditingTeam = [];
                for (let i = 0; i < teamNames.length; i++) {
                    auditingTeam.push({
                        sr_no: i + 1,
                        name: teamNames[i].value,
                        designation: teamDesignations[i].value,
                        email: teamEmails[i].value,
                        qualifications: teamQualifications[i].value,
                        certin_listed: teamCertinListed[i].value
                    });
                }
                formData.append('auditing_team', JSON.stringify(auditingTeam));
                
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
                        <p><strong>Vulnerabilities:</strong> ${result.vulnerability_count}</p>
                        <p><strong>PoC Images:</strong> ${result.poc_count} observations with images</p>
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
    db: Session = Depends(get_db)
):
    """Generate Cert-IN report from form data"""
    try:
        print(f"Starting Cert-IN report generation - Version {VERSION}")

        form = await request.form()
        data = {k: form.get(k) for k in form.keys()}

        vulnerability_data = []
        poc_mapping = {}

        if 'vulnerability_file' in data and data['vulnerability_file']:
            vulnerability_file = data['vulnerability_file']
            temp_path = os.path.join(UPLOAD_DIR, f"temp_vuln_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
            content = await vulnerability_file.read()
            with open(temp_path, "wb") as f:
                f.write(content)

            vulnerability_data = read_vulnerability_excel(temp_path)
            os.remove(temp_path)

        if 'poc_files' in data and data['poc_files']:
            poc_file = data['poc_files']
            poc_mapping = await process_poc_zip_files([poc_file], vulnerability_data)

        template_path = os.path.join(os.path.dirname(__file__), "CSS Certin temp.docx")
        if not os.path.exists(template_path):
            raise HTTPException(status_code=404, detail="Cert-IN template not found")

        client_name = data.get('client_name', 'Client')
        raw_filename = f"{client_name}_Cert-IN_Report_{datetime.now().strftime('%Y-%m-%d')}.docx"
        output_path = os.path.join(UPLOAD_DIR, raw_filename)

        generate_certin_report_from_form(data, template_path, output_path, vulnerability_data, poc_mapping)

        safe_filename = os.path.basename(output_path).replace(" ", "_")
        safe_output_path = os.path.join(os.path.dirname(output_path), safe_filename)

        if output_path != safe_output_path:
            os.rename(output_path, safe_output_path)

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
                file_path=safe_output_path
            )
            db.add(certin_report)
            db.commit()
        except Exception as e:
            print(f"Error saving to database: {e}")

        print(f"Report generated successfully - Version {VERSION}")

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
                "filename": safe_filename,
                "download_url": f"/type3/download/{safe_filename}",
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