"""
Employee Dashboard Module - Aggregates data from all report generators
"""
import os
import pandas as pd
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from db import get_db, AuditLog, CertINReport
import json

# Create dashboard app
dashboard_app = FastAPI(title="Employee Dashboard", version="1.0.0")

def extract_employee_data_from_excel(file_path):
    """Extract employee data from Excel for dashboard tracking"""
    try:
        df = pd.read_excel(file_path)
        employees = {}
        
        # Check for various employee name columns
        employee_columns = ['Tester_Name', 'ReportedBy', 'Tester', 'Employee_Name', 'Name']
        employee_col = None
        for col in employee_columns:
            if col in df.columns:
                employee_col = col
                break
        
        if employee_col:
            for _, row in df.iterrows():
                tester_name = str(row.get(employee_col, '')).strip()
                if tester_name and tester_name != 'nan':
                    if tester_name not in employees:
                        employees[tester_name] = {
                            'name': tester_name,
                            'total_vulnerabilities': 0,
                            'critical': 0,
                            'high': 0,
                            'medium': 0,
                            'low': 0,
                            'info': 0,
                            'reports_generated': 0,
                            'last_activity': None,
                            'client_name': str(row.get('Client_Name', '')).strip() or 'Unknown',
                            'project_name': str(row.get('Project', '')).strip() or 'Unknown'
                        }
                    
                    employees[tester_name]['total_vulnerabilities'] += 1
                    
                    # Count by severity if available
                    severity = str(row.get('Severity', '')).strip().lower()
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
        
        return list(employees.values())
    except Exception as e:
        print(f"Error extracting employee data: {e}")
        return []

async def get_usage_logs(db: Session, limit: int = 100):
    """Get usage logs from database"""
    try:
        logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
        return [
            {
                'id': log.id,
                'user_email': log.user_email,
                'action': log.action,
                'details': log.metadata_json or '',
                'timestamp': log.created_at.isoformat(),
                'ip_address': log.ip_address
            }
            for log in logs
        ]
    except Exception as e:
        print(f"Error getting usage logs: {e}")
        return []

async def get_report_statistics(db: Session):
    """Get report generation statistics"""
    try:
        # Get Cert-IN reports
        certin_reports = db.query(CertINReport).all()
        
        stats = {
            'total_reports': len(certin_reports),
            'reports_by_type': {
                'Cert-IN Reports': len(certin_reports),
                'Type-1 Reports': 0,  # Will be updated when we add tracking
                'Type-2 Reports': 0   # Will be updated when we add tracking
            },
            'reports_by_month': {},
            'reports_by_user': {}
        }
        
        for report in certin_reports:
            # Monthly stats
            month_key = report.created_at.strftime('%Y-%m')
            stats['reports_by_month'][month_key] = stats['reports_by_month'].get(month_key, 0) + 1
            
            # User stats
            user_email = report.created_by_email or 'Unknown'
            stats['reports_by_user'][user_email] = stats['reports_by_user'].get(user_email, 0) + 1
        
        return stats
    except Exception as e:
        print(f"Error getting report statistics: {e}")
        return {'total_reports': 0, 'reports_by_type': {}, 'reports_by_month': {}, 'reports_by_user': {}}

@dashboard_app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    """Main dashboard page with employee tracking and usage logs"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Employee Dashboard & Usage Analytics</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
            .container { max-width: 1400px; margin: 0 auto; }
            h1 { color: #6923d0; text-align: center; margin-bottom: 30px; }
            .nav-buttons { text-align: center; margin-bottom: 30px; }
            .btn { background-color: #6923d0; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 5px; text-decoration: none; display: inline-block; }
            .btn:hover { background-color: #5a1fb8; }
            .btn-success { background-color: #28a745; }
            .btn-info { background-color: #17a2b8; }
            .btn-warning { background-color: #ffc107; color: #212529; }
            .dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .stat-card { background: linear-gradient(135deg, #6923d0, #8b5cf6); color: white; padding: 20px; border-radius: 8px; text-align: center; }
            .stat-number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
            .stat-label { font-size: 0.9em; opacity: 0.9; }
            .employee-table, .usage-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            .employee-table th, .employee-table td, .usage-table th, .usage-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            .employee-table th, .usage-table th { background-color: #6923d0; color: white; }
            .severity-critical { color: #dc3545; font-weight: bold; }
            .severity-high { color: #fd7e14; font-weight: bold; }
            .severity-medium { color: #ffc107; font-weight: bold; }
            .severity-low { color: #28a745; font-weight: bold; }
            .upload-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
            .tab-container { margin-bottom: 20px; }
            .tab-buttons { display: flex; gap: 10px; margin-bottom: 20px; }
            .tab-content { display: none; }
            .tab-content.active { display: block; }
            .search-box { margin-bottom: 15px; }
            .search-box input { padding: 8px; width: 300px; border: 1px solid #ddd; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>📊 Employee Dashboard & Usage Analytics</h1>
            
            <div class="nav-buttons">
                <a href="/report_formats.html" class="btn">← Back to Report Formats</a>
                <button onclick="loadDashboard()" class="btn btn-success">📊 Refresh Dashboard</button>
                <button onclick="loadUsageLogs()" class="btn btn-info">📋 Load Usage Logs</button>
                <button onclick="loadReportStats()" class="btn btn-warning">📈 Report Statistics</button>
            </div>
            
            <div class="upload-section">
                <h3>📁 Upload Excel File for Employee Analysis</h3>
                <input type="file" id="excelFile" accept=".xlsx,.xls" style="margin-bottom: 10px;">
                <button onclick="analyzeEmployees()" class="btn">Analyze Employee Performance</button>
            </div>
            
            <div class="tab-container">
                <div class="tab-buttons">
                    <button onclick="showTab('employee-tab')" class="btn" id="employee-tab-btn">👥 Employee Performance</button>
                    <button onclick="showTab('usage-tab')" class="btn" id="usage-tab-btn">📋 Usage Logs</button>
                    <button onclick="showTab('stats-tab')" class="btn" id="stats-tab-btn">📈 Report Statistics</button>
                </div>
                
                <div id="employee-tab" class="tab-content active">
                    <div id="employee-dashboard-content" style="display: none;">
                        <div class="stats-grid" id="stats-grid"></div>
                        <div class="dashboard-grid">
                            <div class="chart-container">
                                <h3>Total Vulnerabilities by Employee</h3>
                                <canvas id="employeeChart"></canvas>
                            </div>
                            <div class="chart-container">
                                <h3>Severity Distribution</h3>
                                <canvas id="severityChart"></canvas>
                            </div>
                        </div>
                        
                        <div class="chart-container">
                            <h3>📋 Employee Performance Table</h3>
                            <div class="search-box">
                                <input type="text" id="employeeSearch" placeholder="Search employees..." onkeyup="filterEmployeeTable()">
                            </div>
                            <table class="employee-table" id="employeeTable">
                                <thead>
                                    <tr>
                                        <th>Employee Name</th>
                                        <th>Client Name</th>
                                        <th>Project</th>
                                        <th>Total Vulnerabilities</th>
                                        <th>Critical</th>
                                        <th>High</th>
                                        <th>Medium</th>
                                        <th>Low</th>
                                        <th>Info</th>
                                        <th>Reports Generated</th>
                                        <th>Last Activity</th>
                                        <th>Performance Score</th>
                                    </tr>
                                </thead>
                                <tbody id="employeeTableBody"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div id="usage-tab" class="tab-content">
                    <div class="chart-container">
                        <h3>📋 User Activity Logs</h3>
                        <div class="search-box">
                            <input type="text" id="usageSearch" placeholder="Search logs..." onkeyup="filterUsageTable()">
                        </div>
                        <table class="usage-table" id="usageTable">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>User Email</th>
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
                    <div class="chart-container">
                        <h3>📈 Report Generation Statistics</h3>
                        <div class="stats-grid" id="report-stats-grid"></div>
                        <div class="dashboard-grid">
                            <div class="chart-container">
                                <h3>Reports by Type</h3>
                                <canvas id="reportTypeChart"></canvas>
                            </div>
                            <div class="chart-container">
                                <h3>Reports by Month</h3>
                                <canvas id="reportMonthChart"></canvas>
                            </div>
                        </div>
                        <div class="chart-container">
                            <h3>Reports by User</h3>
                            <canvas id="reportUserChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let employeeData = [];
            let usageLogs = [];
            let reportStats = {};
            let employeeChart, severityChart, reportTypeChart, reportMonthChart, reportUserChart;

            // Tab functionality
            function showTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Remove active class from all buttons
                document.querySelectorAll('.tab-buttons .btn').forEach(btn => {
                    btn.style.backgroundColor = '#6923d0';
                });
                
                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                
                // Highlight active button
                document.getElementById(tabName + '-btn').style.backgroundColor = '#5a1fb8';
            }

            // Load dashboard data
            async function loadDashboard() {
                try {
                    await loadUsageLogs();
                    await loadReportStats();
                } catch (error) {
                    console.error('Error loading dashboard:', error);
                }
            }

            // Employee analysis
            async function analyzeEmployees() {
                const fileInput = document.getElementById('excelFile');
                const file = fileInput.files[0];
                
                if (!file) {
                    alert('Please select an Excel file');
                    return;
                }

                const formData = new FormData();
                formData.append('excel_file', file);

                try {
                    const response = await fetch('/dashboard/analyze-employees/', {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        throw new Error('Analysis failed');
                    }

                    employeeData = await response.json();
                    displayEmployeeDashboard();
                } catch (error) {
                    alert('Error analyzing file: ' + error.message);
                }
            }

            function displayEmployeeDashboard() {
                document.getElementById('employee-dashboard-content').style.display = 'block';
                updateEmployeeStats();
                createEmployeeCharts();
                updateEmployeeTable();
            }

            function updateEmployeeStats() {
                const statsGrid = document.getElementById('stats-grid');
                const totalEmployees = employeeData.length;
                const totalVulns = employeeData.reduce((sum, emp) => sum + emp.total_vulnerabilities, 0);
                const totalCritical = employeeData.reduce((sum, emp) => sum + emp.critical, 0);
                const avgPerEmployee = totalVulns / totalEmployees || 0;

                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${totalEmployees}</div>
                        <div class="stat-label">Total Employees</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${totalVulns}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${totalCritical}</div>
                        <div class="stat-label">Critical Issues</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${avgPerEmployee.toFixed(1)}</div>
                        <div class="stat-label">Avg per Employee</div>
                    </div>
                `;
            }

            function createEmployeeCharts() {
                // Employee Chart
                const ctx1 = document.getElementById('employeeChart').getContext('2d');
                if (employeeChart) employeeChart.destroy();
                
                employeeChart = new Chart(ctx1, {
                    type: 'bar',
                    data: {
                        labels: employeeData.map(emp => emp.name),
                        datasets: [{
                            label: 'Total Vulnerabilities',
                            data: employeeData.map(emp => emp.total_vulnerabilities),
                            backgroundColor: '#6923d0',
                            borderColor: '#5a1fb8',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });

                // Severity Chart
                const ctx2 = document.getElementById('severityChart').getContext('2d');
                if (severityChart) severityChart.destroy();
                
                const severityData = {
                    'Critical': employeeData.reduce((sum, emp) => sum + emp.critical, 0),
                    'High': employeeData.reduce((sum, emp) => sum + emp.high, 0),
                    'Medium': employeeData.reduce((sum, emp) => sum + emp.medium, 0),
                    'Low': employeeData.reduce((sum, emp) => sum + emp.low, 0),
                    'Info': employeeData.reduce((sum, emp) => sum + emp.info, 0)
                };

                severityChart = new Chart(ctx2, {
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
            }

            function updateEmployeeTable() {
                const tbody = document.getElementById('employeeTableBody');
                tbody.innerHTML = '';

                employeeData.forEach(emp => {
                    const performanceScore = calculatePerformanceScore(emp);
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${emp.name}</td>
                        <td>${emp.client_name || 'Unknown'}</td>
                        <td>${emp.project_name || 'Unknown'}</td>
                        <td>${emp.total_vulnerabilities}</td>
                        <td class="severity-critical">${emp.critical}</td>
                        <td class="severity-high">${emp.high}</td>
                        <td class="severity-medium">${emp.medium}</td>
                        <td class="severity-low">${emp.low}</td>
                        <td>${emp.info}</td>
                        <td>${emp.reports_generated || 0}</td>
                        <td>${emp.last_activity || 'N/A'}</td>
                        <td><strong>${performanceScore.toFixed(1)}%</strong></td>
                    `;
                    tbody.appendChild(row);
                });
            }

            function calculatePerformanceScore(emp) {
                const criticalWeight = 10;
                const highWeight = 5;
                const mediumWeight = 2;
                const lowWeight = 1;
                
                const score = (emp.critical * criticalWeight + 
                              emp.high * highWeight + 
                              emp.medium * mediumWeight + 
                              emp.low * lowWeight) / 
                              Math.max(emp.total_vulnerabilities, 1) * 10;
                
                return Math.min(score, 100);
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
                        <td>${new Date(log.timestamp).toLocaleString()}</td>
                        <td>${log.user_email}</td>
                        <td>${log.action}</td>
                        <td>${log.details}</td>
                        <td>${log.ip_address}</td>
                    `;
                    tbody.appendChild(row);
                });
            }

            // Report statistics
            async function loadReportStats() {
                try {
                    const response = await fetch('/dashboard/report-stats/');
                    if (response.ok) {
                        reportStats = await response.json();
                        updateReportStats();
                    }
                } catch (error) {
                    console.error('Error loading report stats:', error);
                }
            }

            function updateReportStats() {
                const statsGrid = document.getElementById('report-stats-grid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number">${reportStats.total_reports || 0}</div>
                        <div class="stat-label">Total Reports</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${Object.keys(reportStats.reports_by_user || {}).length}</div>
                        <div class="stat-label">Active Users</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${Object.keys(reportStats.reports_by_month || {}).length}</div>
                        <div class="stat-label">Active Months</div>
                    </div>
                `;

                createReportCharts();
            }

            function createReportCharts() {
                // Report Type Chart
                const ctx1 = document.getElementById('reportTypeChart').getContext('2d');
                if (reportTypeChart) reportTypeChart.destroy();
                
                const typeData = reportStats.reports_by_type || {};
                reportTypeChart = new Chart(ctx1, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(typeData),
                        datasets: [{
                            data: Object.values(typeData),
                            backgroundColor: ['#6923d0', '#28a745', '#17a2b8']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });

                // Report Month Chart
                const ctx2 = document.getElementById('reportMonthChart').getContext('2d');
                if (reportMonthChart) reportMonthChart.destroy();
                
                const monthData = reportStats.reports_by_month || {};
                reportMonthChart = new Chart(ctx2, {
                    type: 'line',
                    data: {
                        labels: Object.keys(monthData).sort(),
                        datasets: [{
                            label: 'Reports Generated',
                            data: Object.keys(monthData).sort().map(month => monthData[month]),
                            backgroundColor: '#6923d0',
                            borderColor: '#5a1fb8',
                            borderWidth: 2,
                            fill: false
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });

                // Report User Chart
                const ctx3 = document.getElementById('reportUserChart').getContext('2d');
                if (reportUserChart) reportUserChart.destroy();
                
                const userData = reportStats.reports_by_user || {};
                reportUserChart = new Chart(ctx3, {
                    type: 'bar',
                    data: {
                        labels: Object.keys(userData),
                        datasets: [{
                            label: 'Reports Generated',
                            data: Object.values(userData),
                            backgroundColor: '#28a745',
                            borderColor: '#20c997',
                            borderWidth: 1
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
            function filterEmployeeTable() {
                const searchTerm = document.getElementById('employeeSearch').value.toLowerCase();
                const rows = document.querySelectorAll('#employeeTableBody tr');
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }

            function filterUsageTable() {
                const searchTerm = document.getElementById('usageSearch').value.toLowerCase();
                const rows = document.querySelectorAll('#usageTableBody tr');
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }

            // Load initial data
            window.onload = function() {
                loadDashboard();
            };
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@dashboard_app.post("/analyze-employees/")
async def analyze_employees(request: Request):
    """Analyze employee performance from uploaded Excel file"""
    try:
        form = await request.form()
        excel_file = form.get('excel_file')
        
        if not excel_file:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Save file temporarily
        upload_dir = "uploads"
        os.makedirs(upload_dir, exist_ok=True)
        temp_path = os.path.join(upload_dir, f"temp_emp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
        content = await excel_file.read()
        with open(temp_path, "wb") as f:
            f.write(content)
        
        # Extract employee data
        employee_data = extract_employee_data_from_excel(temp_path)
        
        # Clean up
        os.remove(temp_path)
        
        return JSONResponse(content=employee_data)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing employees: {str(e)}")

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
