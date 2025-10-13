import os
from datetime import datetime
from typing import Generator

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base, Session


# SQLite DB under Automation/backend for convenience
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "Automation", "backend", "data.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class DashboardDataset(Base):
    __tablename__ = "dashboard_datasets"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    project_name = Column(String(255), nullable=True)
    file_path = Column(String(1024), nullable=False)
    uploaded_by_email = Column(String(255), nullable=False)
    uploaded_by_name = Column(String(255), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=True)
    user_name = Column(String(255), nullable=True)
    action = Column(String(255), nullable=False)
    metadata_json = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ProjectHistory(Base):
    __tablename__ = "project_history"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String(255), nullable=False, index=True)
    total_vulnerabilities = Column(Integer, default=0)
    unique_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    informational_count = Column(Integer, default=0)
    first_evaluated = Column(DateTime, default=datetime.utcnow)
    last_evaluated = Column(DateTime, default=datetime.utcnow)
    evaluation_count = Column(Integer, default=1)
    uploaded_by_email = Column(String(255), nullable=False)
    uploaded_by_name = Column(String(255), nullable=True)
    vulnerability_details = Column(Text, nullable=True)  # JSON string of vulnerability names and counts


class ProjectEvaluationEvent(Base):
    __tablename__ = "project_evaluation_events"

    id = Column(Integer, primary_key=True, index=True)
    project_name = Column(String(255), nullable=False, index=True)
    total_vulnerabilities = Column(Integer, default=0)
    unique_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    informational_count = Column(Integer, default=0)
    vulnerability_details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    uploaded_by_email = Column(String(255), nullable=True)
    uploaded_by_name = Column(String(255), nullable=True)


class CertINReport(Base):
    __tablename__ = "certin_reports"

    id = Column(Integer, primary_key=True, index=True)
    client_name = Column(String(255), nullable=False)
    report_name = Column(String(255), nullable=False)
    report_release_date = Column(String(50), nullable=False)
    type_of_audit = Column(String(255), nullable=False)
    type_of_audit_report = Column(String(255), nullable=False)
    period = Column(String(100), nullable=False)
    document_title = Column(String(255), nullable=False)
    document_id = Column(String(100), nullable=False)
    document_version = Column(String(50), nullable=False)
    prepared_by = Column(String(255), nullable=False)
    reviewed_by = Column(String(255), nullable=False)
    approved_by = Column(String(255), nullable=False)
    released_by = Column(String(255), nullable=False)
    release_date = Column(String(50), nullable=False)
    
    # JSON fields for complex data
    document_change_history = Column(Text, nullable=True)  # JSON array
    distribution_list = Column(Text, nullable=True)  # JSON array
    engagement_scope = Column(Text, nullable=True)  # JSON array
    auditing_team = Column(Text, nullable=True)  # JSON array
    audit_activities = Column(Text, nullable=True)  # JSON array
    tools_software = Column(Text, nullable=True)  # JSON array
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_email = Column(String(255), nullable=False)
    created_by_name = Column(String(255), nullable=True)
    file_path = Column(String(1024), nullable=True)  # Path to generated report


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_connection() -> bool:
    """Test database connection"""
    try:
        db = SessionLocal()
        # Simple query to test connection
        db.execute("SELECT 1")
        db.close()
        return True
    except Exception:
        return False


