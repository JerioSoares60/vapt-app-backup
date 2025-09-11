# VAPT Report Generator - Comprehensive Documentation

## Overview

The VAPT Report Generator is a comprehensive web application designed to automate the creation of Vulnerability Assessment and Penetration Testing (VAPT) reports. Built with FastAPI and modern web technologies, it streamlines the process of converting Excel vulnerability data into professionally formatted Word documents.

## 🚀 Key Features

### Core Functionality
- **Excel Template Processing**: Upload Excel files containing vulnerability data with embedded screenshot references
- **Automated Report Generation**: Generate comprehensive Word documents with professional formatting
- **Screenshot Integration**: Automatically embed up to 15 screenshots per vulnerability
- **Severity Classification**: Automatic CVSS-based severity categorization (Critical, High, Medium, Low, Informational)
- **Multi-format Support**: Support for various Excel templates and Word output formats

### User Management & Security
- **Azure SSO Integration**: Secure authentication via Azure Active Directory
- **Session Management**: Secure session handling with encrypted cookies
- **Role-based Access**: Restricted dashboard access for authorized users
- **Audit Logging**: Comprehensive activity tracking and user audit trails

### Dashboard & Analytics
- **Project Tracking**: Monitor project history and vulnerability statistics
- **Data Visualization**: Charts and graphs for vulnerability distribution
- **File Management**: Upload and manage dashboard datasets
- **Historical Analysis**: Track vulnerability trends over time

## 🏗️ Architecture

### Technology Stack
- **Backend**: FastAPI (Python 3.11+)
- **Database**: SQLite (local) / PostgreSQL (production)
- **Authentication**: Azure Active Directory (OAuth2)
- **Frontend**: HTML/CSS/JavaScript with Jinja2 templates
- **File Processing**: pandas, python-docx, openpyxl
- **Deployment**: Docker, AWS EC2, Nginx

### Application Structure
```
Report-Generator-IP-main/
├── app.py                    # Main FastAPI application
├── app-aws.py               # AWS deployment version
├── auth.py                  # Azure SSO authentication
├── db.py                    # Database models and operations
├── db-aws.py               # AWS database configuration
├── Automation/
│   ├── backend/
│   │   ├── main.py         # Type-1 report generation
│   │   ├── type2.py        # Type-2 report generation
│   │   └── data.db         # SQLite database
│   └── report_formats.html # Frontend interface
├── templates/              # HTML templates
├── static/                 # Static assets
└── uploads/               # File storage
```

## 🔧 Installation & Setup

### Prerequisites
- Python 3.11+
- Azure AD application configured
- Required Python packages (see requirements.txt)

### Local Development Setup
1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Report-Generator-IP-main
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   Create `.env` file in `Automation/backend/`:
   ```bash
   # Azure SSO Configuration
   AZURE_CLIENT_ID=your_azure_client_id
   AZURE_CLIENT_SECRET=your_azure_client_secret
   AZURE_TENANT_ID=your_azure_tenant_id
   AZURE_REDIRECT_URI=http://localhost:8000/auth/callback
   
   # Application Configuration
   ALLOWED_EMAIL_DOMAIN=cybersmithsecure.com
   SESSION_SECRET_KEY=your_session_secret_key
   ```

5. **Start the application**
   ```bash
   uvicorn app:app --reload --host 0.0.0.0 --port 8000
   ```

6. **Access the application**
   - Open browser: `http://localhost:8000`
   - Login with Azure SSO credentials

## 📊 API Endpoints

### Authentication Endpoints
- `GET /login` - Login page
- `POST /auth/login` - Initiate Azure SSO login
- `GET /auth/callback` - Azure SSO callback
- `GET /logout` - Logout user
- `GET /me` - Get current user info

### Report Generation Endpoints
- `POST /type1/generate-report/` - Generate Type-1 VAPT report
- `POST /type2/generate-report/` - Generate Type-2 VAPT report
- `GET /type1/` - Type-1 report interface
- `GET /type2/` - Type-2 report interface

### Dashboard Endpoints
- `GET /dashboard` - Dashboard interface (restricted access)
- `POST /dashboard/upload` - Upload dashboard dataset
- `GET /dashboard-datasets` - List dashboard datasets
- `GET /dashboard/analytics` - Get analytics data

### Utility Endpoints
- `GET /health` - Health check endpoint
- `GET /report_formats.html` - Report formats page
- `GET /static/{file_path}` - Static file serving

## 📋 Excel Template Format

### Required Columns
| Column Name | Description | Example |
|-------------|-------------|---------|
| Sr No | Unique identifier | VULN-001 |
| Vulnerability Name | Name of vulnerability | SQL Injection in Login |
| Vulnerable URL | URL/parameter | /login.php?username= |
| CVSS Score | CVSS score (0-10) | 7.5 |
| Description | Detailed description | The login page is vulnerable... |
| Impact | Impact if exploited | Attackers can bypass... |
| Remediation | Fix steps | Use parameterized queries... |
| Steps | Reproduction steps | Step 1: Access login page... |
| Screenshot 1-15 | Screenshot filenames | login_page.png |

### Severity Classification
- **Critical**: 9.0-10.0 CVSS
- **High**: 7.0-8.9 CVSS
- **Medium**: 4.0-6.9 CVSS
- **Low**: 0.1-3.9 CVSS
- **Informational**: 0.0 or not specified

## 🗄️ Database Schema

### Tables

#### `dashboard_datasets`
- Stores uploaded dashboard Excel files
- Fields: id, title, project_name, file_path, uploaded_by_email, uploaded_by_name, uploaded_at

#### `audit_logs`
- Tracks user activities and system events
- Fields: id, user_email, user_name, action, metadata_json, ip_address, user_agent, created_at

#### `project_history`
- Cumulative project evaluation data
- Fields: id, project_name, total_vulnerabilities, unique_vulnerabilities, severity_counts, evaluation_dates

## 🔐 Security Features

### Authentication & Authorization
- Azure Active Directory integration
- Session-based authentication
- Role-based access control
- Domain-restricted access (cybersmithsecure.com)

### Data Protection
- Encrypted session cookies
- Secure file upload handling
- Input validation and sanitization
- SQL injection prevention

### Audit & Compliance
- Comprehensive audit logging
- User activity tracking
- IP address logging
- User agent tracking

## 🚀 Deployment

### AWS EC2 Deployment
1. **Infrastructure Setup**
   - VPC with public/private subnets
   - Security groups configuration
   - RDS PostgreSQL database
   - Application Load Balancer

2. **Application Deployment**
   ```bash
   # Run deployment script
   chmod +x aws-deploy.sh
   ./aws-deploy.sh
   ```

3. **Environment Configuration**
   ```bash
   # Production environment variables
   DATABASE_URL=postgresql://user:pass@rds-endpoint:5432/vapt_reports
   AZURE_REDIRECT_URI=https://your-domain.com/auth/callback
   ENVIRONMENT=production
   ```

### Docker Deployment
```bash
# Build and run with Docker
docker build -t vapt-app .
docker run -p 8000:8000 vapt-app
```

## 📈 Monitoring & Maintenance

### Health Checks
- Application health endpoint: `/health`
- Database connectivity monitoring
- File system health checks

### Logging
- Application logs via systemd journal
- Nginx access/error logs
- Database query logging
- User activity audit logs

### Backup & Recovery
- Automated database backups
- File system backups
- Configuration backups
- Disaster recovery procedures

## 🧪 Testing

### Test Coverage
- Unit tests for core functionality
- Integration tests for API endpoints
- Authentication flow testing
- File upload/download testing
- Database operation testing

### Test Data
- Sample Excel templates provided
- Test vulnerability data
- Mock authentication scenarios
- Performance testing datasets

## 🔧 Configuration

### Environment Variables
```bash
# Database
DATABASE_URL=sqlite:///./data.db  # or PostgreSQL URL

# Azure SSO
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
AZURE_REDIRECT_URI=http://localhost:8000/auth/callback

# Application
ALLOWED_EMAIL_DOMAIN=cybersmithsecure.com
SESSION_SECRET_KEY=your_secret_key
ENVIRONMENT=development
PORT=8000
```

### File Upload Configuration
- Maximum file size: 50MB
- Allowed formats: .xlsx, .docx, .jpg, .png
- Upload directory: `uploads/`
- Automatic file validation

## 🐛 Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify Azure AD configuration
   - Check redirect URI settings
   - Validate client credentials

2. **Database Connection Issues**
   - Check database URL format
   - Verify database server status
   - Test connection manually

3. **File Upload Problems**
   - Check file size limits
   - Verify file format support
   - Check disk space availability

4. **Report Generation Errors**
   - Validate Excel template format
   - Check screenshot file availability
   - Verify template file integrity

### Debug Mode
```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
uvicorn app:app --reload --log-level debug
```

## 📚 API Documentation

### Interactive Documentation
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- OpenAPI Schema: `http://localhost:8000/openapi.json`

### Example API Calls
```bash
# Health check
curl http://localhost:8000/health

# Get current user
curl -H "Cookie: session=..." http://localhost:8000/me

# Upload dashboard dataset
curl -X POST -F "file=@dataset.xlsx" -F "title=Test Dataset" http://localhost:8000/dashboard/upload
```

## 🔄 Version History

### Current Version: 2.1
- Enhanced report generation
- Improved dashboard analytics
- Azure SSO integration
- AWS deployment support
- Comprehensive audit logging

### Previous Versions
- v2.0: Dashboard system implementation
- v1.5: Multi-format report support
- v1.0: Basic report generation

## 📞 Support & Contact

### Technical Support
- Email: developer@cybersmithsecure.com
- Documentation: See AWS_DEPLOYMENT_GUIDE.md and DATABASE_GUIDE.md
- Issues: Report via project repository

### Development Team
- Lead Developer: Sarvesh Salgaonkar
- Organization: CyberSmith Secure
- Domain: cybersmithsecure.com

## 📄 License

This application is proprietary software developed for CyberSmith Secure. All rights reserved.

---

**Last Updated**: January 2025
**Version**: 2.1
**Status**: Production Ready
