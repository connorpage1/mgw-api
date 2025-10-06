"""
AWS S3 service for file storage and management
"""
import boto3
from botocore.exceptions import ClientError
import os
from utils.logger import logger

class S3Service:
    """Service for AWS S3 operations"""
    
    def __init__(self):
        self.client = None
        self.bucket_name = None
        self._initialize()
    
    def _initialize(self):
        """Initialize S3 client and configuration"""
        try:
            # Check if S3 is configured
            aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
            aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
            aws_region = os.environ.get('AWS_REGION', 'us-east-1')
            self.bucket_name = os.environ.get('S3_BUCKET_NAME')
            
            if not all([aws_access_key, aws_secret_key, self.bucket_name]):
                logger.warning("S3 not configured - missing required environment variables")
                return
            
            self.client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                region_name=aws_region
            )
            logger.info("S3 service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize S3 service: {e}")
            self.client = None
    
    def is_configured(self):
        """Check if S3 is properly configured"""
        return self.client is not None and self.bucket_name is not None
    
    def upload_file(self, file_path, s3_key, content_type=None):
        """Upload a file to S3"""
        if not self.is_configured():
            raise Exception("S3 not configured")
        
        try:
            extra_args = {}
            if content_type:
                extra_args['ContentType'] = content_type
            
            self.client.upload_file(file_path, self.bucket_name, s3_key, ExtraArgs=extra_args)
            logger.info(f"File uploaded to S3: {s3_key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            return False
    
    def generate_presigned_url(self, s3_key, expires_in=86400):
        """Generate a presigned URL for file access"""
        if not self.is_configured():
            return None
        
        try:
            return self.client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': s3_key},
                ExpiresIn=expires_in
            )
        except ClientError as e:
            logger.error(f"Failed to generate presigned URL: {e}")
            return None
    
    def delete_file(self, s3_key):
        """Delete a file from S3"""
        if not self.is_configured():
            return False
        
        try:
            self.client.delete_object(Bucket=self.bucket_name, Key=s3_key)
            logger.info(f"File deleted from S3: {s3_key}")
            return True
            
        except ClientError as e:
            logger.error(f"S3 delete failed: {e}")
            return False

# Global S3 service instance
s3_service = S3Service()