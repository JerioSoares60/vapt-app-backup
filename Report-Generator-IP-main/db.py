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


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


