"""
Usage Analytics Service for tracking user activities
Provides comprehensive analytics and monitoring for the VAPT system
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import json
import logging
from sqlalchemy.orm import Session
from sqlalchemy import text

logger = logging.getLogger(__name__)

class AnalyticsService:
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def track_user_action(self, user_email: str, action_type: str, 
                         resource_type: str, metadata: Dict[str, Any] = None,
                         ip_address: str = None, user_agent: str = None,
                         file_size: int = None, processing_time: int = None):
        """Track user action for analytics"""
        try:
            # Insert into usage_analytics table
            self.db.execute(text("""
                INSERT INTO usage_analytics 
                (user_email, action_type, resource_type, metadata_json, 
                 ip_address, user_agent, file_size, processing_time, created_at)
                VALUES (:user_email, :action_type, :resource_type, :metadata_json,
                        :ip_address, :user_agent, :file_size, :processing_time, :created_at)
            """), {
                'user_email': user_email,
                'action_type': action_type,
                'resource_type': resource_type,
                'metadata_json': json.dumps(metadata) if metadata else None,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'file_size': file_size,
                'processing_time': processing_time,
                'created_at': datetime.utcnow()
            })
            
            self.db.commit()
            logger.info(f"Tracked action: {action_type} by {user_email}")
            
        except Exception as e:
            logger.error(f"Failed to track user action: {e}")
            self.db.rollback()
    
    def track_file_upload(self, user_email: str, file_path: str, file_size: int,
                         processing_time: int, file_type: str, project_name: str = None):
        """Track file upload with metrics"""
        metadata = {
            'file_path': file_path,
            'file_size': file_size,
            'processing_time': processing_time,
            'file_type': file_type,
            'project_name': project_name
        }
        
        self.track_user_action(
            user_email=user_email,
            action_type='file_upload',
            resource_type=file_type,
            metadata=metadata,
            file_size=file_size,
            processing_time=processing_time
        )
    
    def track_report_generation(self, user_email: str, report_type: str,
                              processing_time: int, vulnerability_count: int,
                              project_name: str = None):
        """Track report generation"""
        metadata = {
            'report_type': report_type,
            'processing_time': processing_time,
            'vulnerability_count': vulnerability_count,
            'project_name': project_name
        }
        
        self.track_user_action(
            user_email=user_email,
            action_type='report_generation',
            resource_type=report_type,
            metadata=metadata,
            processing_time=processing_time
        )
    
    def track_dashboard_access(self, user_email: str, dashboard_section: str,
                             ip_address: str = None, user_agent: str = None):
        """Track dashboard access"""
        metadata = {
            'dashboard_section': dashboard_section
        }
        
        self.track_user_action(
            user_email=user_email,
            action_type='dashboard_access',
            resource_type='dashboard',
            metadata=metadata,
            ip_address=ip_address,
            user_agent=user_agent
        )
    
    def get_usage_statistics(self, start_date: datetime = None, end_date: datetime = None) -> List[Dict]:
        """Get usage statistics for analytics dashboard"""
        try:
            if not start_date:
                start_date = datetime.utcnow() - timedelta(days=30)
            if not end_date:
                end_date = datetime.utcnow()
            
            query = """
                SELECT 
                    user_email,
                    action_type,
                    resource_type,
                    COUNT(*) as action_count,
                    AVG(processing_time) as avg_processing_time,
                    SUM(file_size) as total_file_size,
                    MAX(created_at) as last_activity
                FROM usage_analytics
                WHERE created_at >= :start_date AND created_at <= :end_date
                GROUP BY user_email, action_type, resource_type
                ORDER BY action_count DESC
            """
            
            result = self.db.execute(text(query), {
                'start_date': start_date,
                'end_date': end_date
            })
            
            return [dict(row._mapping) for row in result.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to get usage statistics: {e}")
            return []
    
    def get_user_activity_summary(self, user_email: str, days: int = 30) -> List[Dict]:
        """Get activity summary for specific user"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            query = """
                SELECT 
                    action_type,
                    resource_type,
                    COUNT(*) as count,
                    MAX(created_at) as last_activity,
                    AVG(processing_time) as avg_processing_time,
                    SUM(file_size) as total_file_size
                FROM usage_analytics
                WHERE user_email = :user_email AND created_at >= :start_date
                GROUP BY action_type, resource_type
                ORDER BY count DESC
            """
            
            result = self.db.execute(text(query), {
                'user_email': user_email,
                'start_date': start_date
            })
            
            return [dict(row._mapping) for row in result.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to get user activity: {e}")
            return []
    
    def get_system_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get overall system metrics"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Total users
            users_query = """
                SELECT COUNT(DISTINCT user_email) as total_users
                FROM usage_analytics
                WHERE created_at >= :start_date
            """
            users_result = self.db.execute(text(users_query), {'start_date': start_date})
            total_users = users_result.fetchone()[0] if users_result.fetchone() else 0
            
            # Total reports generated
            reports_query = """
                SELECT COUNT(*) as total_reports
                FROM usage_analytics
                WHERE action_type = 'report_generation' AND created_at >= :start_date
            """
            reports_result = self.db.execute(text(reports_query), {'start_date': start_date})
            total_reports = reports_result.fetchone()[0] if reports_result.fetchone() else 0
            
            # Total file uploads
            uploads_query = """
                SELECT COUNT(*) as total_uploads, SUM(file_size) as total_size
                FROM usage_analytics
                WHERE action_type = 'file_upload' AND created_at >= :start_date
            """
            uploads_result = self.db.execute(text(uploads_query), {'start_date': start_date})
            uploads_row = uploads_result.fetchone()
            total_uploads = uploads_row[0] if uploads_row else 0
            total_size = uploads_row[1] if uploads_row and uploads_row[1] else 0
            
            # Average processing time
            processing_query = """
                SELECT AVG(processing_time) as avg_processing_time
                FROM usage_analytics
                WHERE processing_time IS NOT NULL AND created_at >= :start_date
            """
            processing_result = self.db.execute(text(processing_query), {'start_date': start_date})
            avg_processing = processing_result.fetchone()[0] if processing_result.fetchone() else 0
            
            return {
                'total_users': total_users,
                'total_reports': total_reports,
                'total_uploads': total_uploads,
                'total_size_bytes': total_size,
                'avg_processing_time': avg_processing,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    def get_top_users(self, limit: int = 10, days: int = 30) -> List[Dict]:
        """Get top users by activity"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            query = """
                SELECT 
                    user_email,
                    COUNT(*) as total_actions,
                    COUNT(CASE WHEN action_type = 'report_generation' THEN 1 END) as reports_generated,
                    COUNT(CASE WHEN action_type = 'file_upload' THEN 1 END) as files_uploaded,
                    MAX(created_at) as last_activity
                FROM usage_analytics
                WHERE created_at >= :start_date
                GROUP BY user_email
                ORDER BY total_actions DESC
                LIMIT :limit
            """
            
            result = self.db.execute(text(query), {
                'start_date': start_date,
                'limit': limit
            })
            
            return [dict(row._mapping) for row in result.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to get top users: {e}")
            return []
    
    def get_daily_activity(self, days: int = 30) -> List[Dict]:
        """Get daily activity breakdown"""
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            query = """
                SELECT 
                    DATE(created_at) as activity_date,
                    COUNT(*) as total_actions,
                    COUNT(DISTINCT user_email) as active_users,
                    COUNT(CASE WHEN action_type = 'report_generation' THEN 1 END) as reports_generated
                FROM usage_analytics
                WHERE created_at >= :start_date
                GROUP BY DATE(created_at)
                ORDER BY activity_date DESC
            """
            
            result = self.db.execute(text(query), {'start_date': start_date})
            return [dict(row._mapping) for row in result.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to get daily activity: {e}")
            return []
