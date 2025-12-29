"""
File management models for STL files, videos, and upload tracking
"""
from datetime import datetime
import uuid
from . import db

class STLFile(db.Model):
    """STL file uploads for CNC/3D printing projects"""
    __tablename__ = 'stl_files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(255), nullable=True)  # For S3 storage
    local_path = db.Column(db.String(255), nullable=True)  # For local storage
    file_size = db.Column(db.Integer, nullable=False)
    file_hash = db.Column(db.String(64), nullable=True)  # SHA-256 hash of file content
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_viewed = db.Column(db.DateTime)
    view_count = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    tags = db.Column(db.String(500))
    
    # User who uploaded the file (stored as email since no local User model)
    uploaded_by = db.Column(db.String(255), nullable=False)
    
    # Parent-child file relationships
    parent_file_id = db.Column(db.String(36), db.ForeignKey('stl_files.id'), nullable=True)
    is_partial = db.Column(db.Boolean, default=False)
    
    # Screenshot for quick preview
    screenshot_s3_key = db.Column(db.String(255), nullable=True)  # S3 key for screenshot image
    
    # Relationships
    videos = db.relationship('VideoFile', backref='stl_file', lazy=True, cascade='all, delete-orphan')
    parent_file = db.relationship('STLFile', remote_side=[id], backref='child_files')
    
    # Display flags
    is_featured = db.Column(db.Boolean, default=False)  # For tourist display
    
    def __repr__(self):
        return f'<STLFile {self.original_filename}>'
    
    def get_screenshot_url(self):
        """Generate presigned URL for screenshot if it exists"""
        if not self.screenshot_s3_key:
            return None
        
        try:
            # Import here to avoid circular imports
            from services.s3_service import s3_service
            return s3_service.generate_presigned_url(self.screenshot_s3_key)
        except Exception as e:
            # Import here to avoid circular imports
            from utils.logger import logger
            logger.error(f"Error generating screenshot URL: {e}")
            return None
    
    def to_dict(self):
        """Convert STL file to dictionary for API responses"""
        return {
            'id': self.id,
            'filename': self.original_filename,
            'size': self.file_size,
            'upload_date': self.upload_timestamp.isoformat() if self.upload_timestamp else None,
            'last_viewed': self.last_viewed.isoformat() if self.last_viewed else None,
            'view_count': self.view_count,
            'description': self.description,
            'tags': self.tags.split(',') if self.tags else [],
            'is_featured': self.is_featured,
            'uploaded_by': self.uploaded_by,
            'is_partial': self.is_partial,
            'parent_file_id': self.parent_file_id,
            'parent_file': self.parent_file.original_filename if self.parent_file else None,
            'child_files': [{'id': child.id, 'filename': child.original_filename} for child in self.child_files],
            'screenshot_url': self.get_screenshot_url()
        }

class VideoFile(db.Model):
    """Video file uploads associated with STL files"""
    __tablename__ = 'video_files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(255), nullable=True)
    local_path = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.Integer, nullable=False)
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    associated_stl_id = db.Column(db.String(36), db.ForeignKey('stl_files.id'), nullable=True)
    
    # User who uploaded the file (stored as email since no local User model)
    uploaded_by = db.Column(db.String(255), nullable=False)
    
    def __repr__(self):
        return f'<VideoFile {self.original_filename}>'
    
    def to_dict(self):
        """Convert video file to dictionary for API responses"""
        return {
            'id': self.id,
            'filename': self.original_filename,
            'size': self.file_size,
            'upload_date': self.upload_timestamp.isoformat() if self.upload_timestamp else None,
            'description': self.description,
            'associated_stl_id': self.associated_stl_id,
            'uploaded_by': self.uploaded_by
        }

class FileUploadLog(db.Model):
    """Audit log for file upload activities"""
    __tablename__ = 'file_upload_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)  # 'stl' or 'video'
    file_size = db.Column(db.Integer, nullable=False)
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    uploaded_by = db.Column(db.String(255), nullable=False)
    
    def __repr__(self):
        return f'<FileUploadLog {self.filename}>'