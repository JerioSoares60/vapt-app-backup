import os
from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://vapt_admin:password@localhost:5432/vapt_reports"
)

# Parse DATABASE_URL if it's in the format: postgresql://user:pass@host:port/db
if DATABASE_URL.startswith("postgresql://"):
    # Extract components for connection pooling
    try:
        from urllib.parse import urlparse
        parsed = urlparse(DATABASE_URL)
        host = parsed.hostname
        port = parsed.port or 5432
        database = parsed.path[1:]  # Remove leading slash
        username = parsed.username
        password = parsed.password
        
        # Create engine with connection pooling
        engine = create_engine(
            DATABASE_URL,
            poolclass=QueuePool,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False  # Set to True for debugging
        )
    except Exception as e:
        logger.error(f"Error parsing DATABASE_URL: {e}")
        # Fallback to SQLite
        engine = create_engine("sqlite:///./data.db", echo=False)
else:
    # Fallback to SQLite
    engine = create_engine("sqlite:///./data.db", echo=False)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models
Base = declarative_base()

def init_db():
    """Initialize database tables"""
    try:
        # Import all models to ensure they're registered
        from .db import DashboardDataset, AuditLog, ProjectHistory, ProjectEvaluationEvent
        
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Create indexes for better performance
        with engine.connect() as conn:
            # Create indexes for commonly queried fields
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(user_email)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_project_history_project_name ON project_history(project_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_project_history_evaluation_date ON project_history(evaluation_date)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_datasets_uploaded_at ON dashboard_datasets(uploaded_at)")
            
        logger.info("Database indexes created successfully")
        
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

def get_db() -> Session:
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@contextmanager
def get_db_context():
    """Context manager for database sessions"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_connection():
    """Test database connection"""
    try:
        with engine.connect() as conn:
            result = conn.execute("SELECT 1")
            logger.info("Database connection successful")
            return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

# Health check function
def db_health_check():
    """Check database health for monitoring"""
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": str(e)}
