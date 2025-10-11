"""
AWS S3 Service for file storage
Handles all file uploads, downloads, and management in AWS S3
"""

import boto3
import os
from datetime import datetime
from typing import Optional, Dict, Any
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class S3Service:
    def __init__(self, config: Dict[str, Any]):
        """Initialize S3 service with AWS configuration"""
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=config['aws_access_key_id'],
            aws_secret_access_key=config['aws_secret_access_key'],
            region_name=config['region']
        )
        self.reports_bucket = config['reports_bucket']
        self.excel_bucket = config['excel_bucket']
        self.images_bucket = config['images_bucket']
        self.region = config['region']
    
    def upload_report(self, file_path: str, user_email: str, report_type: str = "type2") -> str:
        """Upload generated report to S3"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(file_path)
            s3_key = f"reports/{user_email}/{report_type}/{timestamp}_{filename}"
            
            self.s3_client.upload_file(file_path, self.reports_bucket, s3_key)
            
            logger.info(f"Report uploaded to S3: {s3_key}")
            return s3_key
            
        except ClientError as e:
            logger.error(f"Failed to upload report: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error uploading report: {e}")
            raise
    
    def upload_excel(self, file_path: str, user_email: str, project_name: str = None) -> str:
        """Upload Excel file to S3"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(file_path)
            project_folder = f"{project_name}/" if project_name else ""
            s3_key = f"excel/{user_email}/{project_folder}{timestamp}_{filename}"
            
            self.s3_client.upload_file(file_path, self.excel_bucket, s3_key)
            
            logger.info(f"Excel uploaded to S3: {s3_key}")
            return s3_key
            
        except ClientError as e:
            logger.error(f"Failed to upload Excel: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error uploading Excel: {e}")
            raise
    
    def upload_image(self, file_path: str, user_email: str, vulnerability_id: str, step_number: int = None) -> str:
        """Upload image/screenshot to S3"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(file_path)
            step_folder = f"step{step_number}/" if step_number else ""
            s3_key = f"images/{user_email}/{vulnerability_id}/{step_folder}{timestamp}_{filename}"
            
            self.s3_client.upload_file(file_path, self.images_bucket, s3_key)
            
            logger.info(f"Image uploaded to S3: {s3_key}")
            return s3_key
            
        except ClientError as e:
            logger.error(f"Failed to upload image: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error uploading image: {e}")
            raise
    
    def get_download_url(self, bucket: str, s3_key: str, expiration: int = 3600) -> str:
        """Generate presigned URL for file download"""
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket, 'Key': s3_key},
                ExpiresIn=expiration
            )
            return url
        except ClientError as e:
            logger.error(f"Failed to generate download URL: {e}")
            raise
    
    def delete_file(self, bucket: str, s3_key: str) -> bool:
        """Delete file from S3"""
        try:
            self.s3_client.delete_object(Bucket=bucket, Key=s3_key)
            logger.info(f"File deleted from S3: {s3_key}")
            return True
        except ClientError as e:
            logger.error(f"Failed to delete file: {e}")
            return False
    
    def list_user_files(self, user_email: str, file_type: str = "reports") -> list:
        """List all files for a specific user"""
        try:
            bucket = self.reports_bucket if file_type == "reports" else self.excel_bucket
            prefix = f"{file_type}/{user_email}/"
            
            response = self.s3_client.list_objects_v2(
                Bucket=bucket,
                Prefix=prefix
            )
            
            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    files.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'],
                        'download_url': self.get_download_url(bucket, obj['Key'])
                    })
            
            return files
            
        except ClientError as e:
            logger.error(f"Failed to list user files: {e}")
            return []
    
    def get_file_info(self, bucket: str, s3_key: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific file"""
        try:
            response = self.s3_client.head_object(Bucket=bucket, Key=s3_key)
            return {
                'size': response['ContentLength'],
                'last_modified': response['LastModified'],
                'content_type': response.get('ContentType', 'application/octet-stream'),
                'etag': response['ETag']
            }
        except ClientError as e:
            logger.error(f"Failed to get file info: {e}")
            return None
    
    def create_bucket_if_not_exists(self, bucket_name: str) -> bool:
        """Create S3 bucket if it doesn't exist"""
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
            logger.info(f"Bucket {bucket_name} already exists")
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                try:
                    self.s3_client.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={'LocationConstraint': self.region}
                    )
                    logger.info(f"Created bucket: {bucket_name}")
                    return True
                except ClientError as create_error:
                    logger.error(f"Failed to create bucket: {create_error}")
                    return False
            else:
                logger.error(f"Error checking bucket: {e}")
                return False
    
    def setup_buckets(self) -> bool:
        """Set up all required S3 buckets"""
        buckets = [self.reports_bucket, self.excel_bucket, self.images_bucket]
        
        for bucket in buckets:
            if not self.create_bucket_if_not_exists(bucket):
                return False
        
        logger.info("All S3 buckets are ready")
        return True
