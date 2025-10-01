# app.py - Complete Mardi Gras API with Full CRUD and Admin GUI
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, abort, current_app, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token
from flask_cors import CORS
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import os
import json
import secrets
from sqlalchemy import func, or_, text, desc
from functools import wraps
import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from itsdangerous import URLSafeTimedSerializer
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from collections import defaultdict
from time import time
from flask_wtf.csrf import CSRFProtect
import uuid
import mimetypes
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
import logging

# Load environment variables
from dotenv import load_dotenv
# Railway provides environment variables directly, but load .env for local development
if os.path.exists('.env.local'):
    load_dotenv('.env.local')
elif os.path.exists('.env'):
    load_dotenv('.env')

# For Railway deployment, ensure we can start without .env files
load_dotenv()  # This will load from system environment if no .env file

# App Configuration
app = Flask(__name__)

# Basic Flask Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
# Database configuration - Railway provides DATABASE_URL
database_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/mardi_gras_dev.db')
# Fix for Railway PostgreSQL URL format (postgresql:// vs postgres://)
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# CORS Configuration
ALLOWED_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000,http://localhost:8000,http://localhost:5555,http://localhost:5556,file://').split(',')

# Mail Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 'on']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

# File Upload Configuration
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')

# AWS S3 Configuration
app.config['S3_BUCKET'] = os.environ.get('S3_BUCKET_NAME', '')
app.config['AWS_ACCESS_KEY_ID'] = os.environ.get('AWS_ACCESS_KEY_ID')
app.config['AWS_SECRET_ACCESS_KEY'] = os.environ.get('AWS_SECRET_ACCESS_KEY')
app.config['AWS_REGION'] = os.environ.get('AWS_REGION', 'us-east-1')

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
cors = CORS(app, origins=ALLOWED_ORIGINS, resources={
    r"/pixie/api/*": {"origins": "*"},  # Allow all origins for Pixie API endpoints
    r"/api/*": {"origins": ALLOWED_ORIGINS},  # Restrict other API endpoints
    r"/*": {"origins": ALLOWED_ORIGINS}  # Default restriction for all other routes
})
mail = Mail(app)

# CSRF Protection Configuration
app.config['WTF_CSRF_TIME_LIMIT'] = 28800  # 8 hours in seconds (8 * 60 * 60)
app.config['WTF_CSRF_SSL_STRICT'] = False   # Allow CSRF over HTTP in development
csrf = CSRFProtect(app)

# CSRF Error Handler
@app.errorhandler(400)
def handle_bad_request(e):
    """Handle 400 errors including CSRF token errors"""
    error_description = str(e.description) if hasattr(e, 'description') else str(e)
    
    # Check if this is a CSRF error
    if 'csrf' in error_description.lower() or 'token' in error_description.lower():
        logger.warning(f"CSRF error: {error_description} from IP: {request.remote_addr}")
        
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return jsonify({
                'error': 'CSRF token validation failed', 
                'csrf_error': True,
                'message': 'Security token expired. Please refresh and try again.'
            }), 400
        else:
            flash('Security token expired. Please refresh the page and try again.', 'error')
            return redirect(request.referrer or url_for('admin_dashboard'))
    
    # Handle other 400 errors
    return f"Bad Request: {error_description}", 400

# Setup logging for file uploads
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize S3 client
try:
    if app.config['AWS_ACCESS_KEY_ID'] and app.config['AWS_SECRET_ACCESS_KEY']:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=app.config['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=app.config['AWS_SECRET_ACCESS_KEY'],
            region_name=app.config['AWS_REGION']
        )
        logger.info("S3 client initialized successfully")
    else:
        s3_client = None
        logger.info("S3 credentials not provided, using local storage only")
except Exception as e:
    logger.warning(f"S3 client initialization failed: {e}")
    s3_client = None

# CSRF Configuration - Enable for web forms, but disable for API endpoints if they exist
@app.context_processor
def inject_csrf_token():
    """Make CSRF token available in all templates"""
    from flask_wtf.csrf import generate_csrf
    return dict(csrf_token=generate_csrf)

# Security Headers
@app.after_request
def add_security_headers(response):
    """Add modern security headers to all responses"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # XSS Protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Strict Transport Security (HTTPS only in production)
    if not app.debug:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
        "font-src 'self' cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# JWT Blacklist
blacklisted_tokens = set()

# Simple in-memory rate limiter
login_attempts = defaultdict(list)

def is_rate_limited(identifier, max_attempts=5, window_minutes=15):
    """Simple rate limiting - max_attempts per window_minutes"""
    now = time()
    window_start = now - (window_minutes * 60)
    
    # Clean old attempts
    login_attempts[identifier] = [
        attempt_time for attempt_time in login_attempts[identifier] 
        if attempt_time > window_start
    ]
    
    # Check if limit exceeded
    if len(login_attempts[identifier]) >= max_attempts:
        return True
    
    return False

def record_login_attempt(identifier):
    """Record a failed login attempt"""
    login_attempts[identifier].append(time())

def cleanup_expired_tokens():
    """Clean up expired password reset tokens"""
    expired_tokens = PasswordResetToken.query.filter(
        PasswordResetToken.expires_at < datetime.utcnow()
    ).all()
    
    for token in expired_tokens:
        db.session.delete(token)
    
    db.session.commit()
    return len(expired_tokens)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    return jwt_payload['jti'] in blacklisted_tokens

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==================== MODELS ====================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=True)
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True)
    
    # Login tracking
    current_login_at = db.Column(db.DateTime())
    current_login_ip = db.Column(db.String(45))
    last_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer, default=0)
    
    # API Access
    api_key = db.Column(db.String(255), unique=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    roles = db.relationship('Role', secondary='roles_users', backref=db.backref('users', lazy='dynamic'))

    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    @property
    def display_name(self):
        """Return the user's display name (first name, or username, or email)"""
        if self.first_name:
            return self.first_name
        elif self.username:
            return self.username
        else:
            return self.email.split('@')[0]
    @property
    def is_active(self):
        return self.active
    @property
    def is_authenticated(self):
        return True
    @property
    def is_anonymous(self):
        return False
    def get_id(self):
        return str(self.id)
    
    def set_password(self, password):
        """Set user password using secure hasher"""
        self.password = secure_hasher.hash_password(password)

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class PasswordResetToken(db.Model):
    """Track one-time use password reset tokens for security"""
    __tablename__ = 'password_reset_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = db.Column(db.String(255), unique=True, nullable=False)  # Hashed token
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    user = db.relationship('User', backref='reset_tokens')

class Category(db.Model):
    __tablename__ = 'categories'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    sort_order = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'sort_order': self.sort_order,
            'is_active': self.is_active,
            'term_count': len([term for term in self.terms if term.is_active])
        }

class Term(db.Model):
    __tablename__ = 'terms'
    
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(200), unique=True, nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    pronunciation = db.Column(db.String(200), nullable=False)
    definition = db.Column(db.Text, nullable=False)
    etymology = db.Column(db.Text)
    example = db.Column(db.Text)
    difficulty = db.Column(db.String(20), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)
    view_count = db.Column(db.Integer, default=0)
    is_featured = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    category_rel = db.relationship('Category', backref='terms')
    
    def to_dict(self, include_related=False):
        data = {
            'id': self.id,
            'term': self.term,
            'slug': self.slug,
            'pronunciation': self.pronunciation,
            'definition': self.definition,
            'etymology': self.etymology,
            'example': self.example,
            'difficulty': self.difficulty,
            'category': self.category_rel.name if self.category_rel else 'Unknown',
            'category_slug': self.category_rel.slug if self.category_rel else '',
            'category_id': self.category_id,
            'view_count': self.view_count,
            'is_featured': self.is_featured,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_related:
            data['related_terms'] = [rt.to_dict() for rt in self.get_related_terms()]
        
        return data
    
    def get_related_terms(self, limit=5):
        """Get related terms based on category"""
        return Term.query.filter(
            Term.category_id == self.category_id,
            Term.id != self.id,
            Term.is_active == True
        ).order_by(func.random()).limit(limit).all()

class STLFile(db.Model):
    __tablename__ = 'stl_files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(255), nullable=True)  # For S3 storage
    local_path = db.Column(db.String(255), nullable=True)  # For local storage
    file_size = db.Column(db.Integer, nullable=False)
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    last_viewed = db.Column(db.DateTime)
    view_count = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    tags = db.Column(db.String(500))
    
    # User who uploaded the file
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Parent-child file relationships
    parent_file_id = db.Column(db.String(36), db.ForeignKey('stl_files.id'), nullable=True)
    is_partial = db.Column(db.Boolean, default=False)
    
    # Screenshot for quick preview
    screenshot_s3_key = db.Column(db.String(255), nullable=True)  # S3 key for screenshot image
    
    # Relationships
    videos = db.relationship('VideoFile', backref='stl_file', lazy=True, cascade='all, delete-orphan')
    uploader = db.relationship('User', backref='uploaded_stl_files')
    parent_file = db.relationship('STLFile', remote_side=[id], backref='child_files')
    
    # Display flags
    is_featured = db.Column(db.Boolean, default=False)  # For tourist display
    
    def __repr__(self):
        return f'<STLFile {self.original_filename}>'
    
    def get_screenshot_url(self):
        """Generate presigned URL for screenshot if it exists"""
        if not self.screenshot_s3_key or not s3_client:
            return None
        
        try:
            return s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': app.config['S3_BUCKET'], 'Key': self.screenshot_s3_key},
                ExpiresIn=86400  # 24 hours
            )
        except Exception as e:
            logger.error(f"Error generating screenshot URL: {e}")
            return None
    
    def to_dict(self):
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
            'uploaded_by': self.uploader.email if self.uploader else None,
            'is_partial': self.is_partial,
            'parent_file_id': self.parent_file_id,
            'parent_file': self.parent_file.original_filename if self.parent_file else None,
            'child_files': [{'id': child.id, 'filename': child.original_filename} for child in self.child_files],
            'screenshot_url': self.get_screenshot_url()
        }

class VideoFile(db.Model):
    __tablename__ = 'video_files'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = db.Column(db.String(255), nullable=False)
    s3_key = db.Column(db.String(255), nullable=True)
    local_path = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.Integer, nullable=False)
    upload_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.Text)
    associated_stl_id = db.Column(db.String(36), db.ForeignKey('stl_files.id'), nullable=True)
    
    # User who uploaded the file
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploader = db.relationship('User', backref='uploaded_video_files')
    
    def __repr__(self):
        return f'<VideoFile {self.original_filename}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.original_filename,
            'size': self.file_size,
            'upload_date': self.upload_timestamp.isoformat() if self.upload_timestamp else None,
            'description': self.description,
            'associated_stl_id': self.associated_stl_id,
            'uploaded_by': self.uploader.email if self.uploader else None
        }

class FileUploadLog(db.Model):
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
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploader = db.relationship('User', backref='file_upload_logs')
    
    def __repr__(self):
        return f'<FileUploadLog {self.filename}>'

# ==================== PASSWORD HASHER ====================

class SecurePasswordHasher:
    """Secure password hasher using Argon2id"""
    
    def __init__(self):
        self.ph = PasswordHasher(
            memory_cost=65536,   # 64 MB
            time_cost=2,         # 2 iterations
            parallelism=4,       # 4 parallel threads
            hash_len=32,         # 32 byte hash
            salt_len=16          # 16 byte salt
        )
    
    def hash_password(self, password: str) -> str:
        """Hash password with Argon2id"""
        return self.ph.hash(password)
    
    def verify_password(self, password: str, hash_str: str) -> bool:
        """Verify password against hash"""
        try:
            self.ph.verify(hash_str, password)
            return True
        except VerifyMismatchError:
            return False
        except Exception:
            return False

# Initialize password hasher
secure_hasher = SecurePasswordHasher()

# ==================== FILE UPLOAD UTILITY FUNCTIONS ====================

def superadmin_required(f):
    """Decorator for superadmin-only routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        user = current_user
        if not user.active or not user.has_role('superadmin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename, file_type='stl'):
    """Check if file extension is allowed"""
    if file_type == 'stl':
        return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'stl'
    elif file_type == 'video':
        allowed_extensions = {'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'mkv'}
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
    return False

def upload_to_s3(file_obj, s3_key):
    """Upload file to S3"""
    # Skip S3 if bucket name is empty or S3 client is not available
    if not s3_client or not app.config['S3_BUCKET']:
        logger.info("S3 not configured, skipping S3 upload")
        return False
    
    try:
        s3_client.upload_fileobj(
            file_obj, 
            app.config['S3_BUCKET'], 
            s3_key,
            ExtraArgs={'ServerSideEncryption': 'AES256'}
        )
        logger.info(f"Successfully uploaded {s3_key} to S3")
        return True
    except ClientError as e:
        logger.error(f"Error uploading to S3: {e}")
        return False

def save_local_file(file_obj, local_path):
    """Save file locally as fallback"""
    try:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        file_obj.save(local_path)
        logger.info(f"Successfully saved file locally: {local_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving file locally: {e}")
        return False

def generate_stl_screenshot(stl_file_id, stl_s3_key=None, stl_local_path=None):
    """Generate screenshot by calling pixie-viewer-v2 service"""
    try:
        import requests
        import tempfile
        import io
        
        # Determine the STL file URL for pixie-viewer
        if stl_s3_key and s3_client:
            # Generate presigned URL for STL file
            stl_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': app.config['S3_BUCKET'], 'Key': stl_s3_key},
                ExpiresIn=3600  # 1 hour
            )
        elif stl_local_path:
            # For local files, we'd need to serve them temporarily
            # This is more complex and would require a local web server
            logger.warning("Screenshot generation from local files not yet implemented")
            return None
        else:
            logger.error("No valid STL source for screenshot generation")
            return None
        
        # Call screenshot generation service
        # For now, we'll create a placeholder implementation
        # You would call a headless browser service or pixie-viewer API
        screenshot_data = generate_screenshot_via_headless_browser(stl_url)
        
        if screenshot_data:
            # Upload screenshot to S3
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            screenshot_s3_key = f"screenshots/{timestamp}_{stl_file_id}.png"
            
            # Upload screenshot to S3
            screenshot_file = io.BytesIO(screenshot_data)
            if upload_to_s3(screenshot_file, screenshot_s3_key):
                return screenshot_s3_key
        
        return None
        
    except Exception as e:
        logger.error(f"Error generating screenshot: {e}")
        return None

def generate_screenshot_via_headless_browser(stl_url):
    """Generate screenshot using pixie-v2 screenshot service"""
    try:
        import requests
        import base64
        
        # Call pixie-v2 screenshot service
        screenshot_service_url = os.environ.get(
            'PIXIE_SCREENSHOT_URL', 
            'http://localhost:3000/api/screenshot'
        )
        
        logger.info(f"Requesting screenshot from pixie-v2 service for: {stl_url}")
        
        # Make request to screenshot service
        response = requests.post(
            screenshot_service_url,
            json={"stl_url": stl_url},
            timeout=60  # Allow up to 60 seconds for screenshot generation
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success') and data.get('screenshot'):
                # Decode base64 screenshot
                screenshot_bytes = base64.b64decode(data['screenshot'])
                logger.info(f"Successfully generated screenshot ({len(screenshot_bytes)} bytes)")
                return screenshot_bytes
            else:
                logger.error(f"Screenshot service returned error: {data.get('error', 'Unknown error')}")
        else:
            logger.error(f"Screenshot service HTTP error: {response.status_code} - {response.text}")
        
        return None
        
    except requests.exceptions.Timeout:
        logger.error("Screenshot generation timed out (60s limit)")
        return None
    except requests.exceptions.ConnectionError:
        service_url = screenshot_service_url.replace('/api/screenshot', '')
        logger.error(f"Could not connect to screenshot service at {service_url}. Check PIXIE_SCREENSHOT_URL environment variable.")
        return None
    except ImportError:
        logger.error("requests library not available for screenshot generation")
        return None
    except Exception as e:
        logger.error(f"Error in headless browser screenshot: {e}")
        return None

def generate_presigned_url(s3_key, expiration=3600):
    """Generate presigned URL for S3 object"""
    if not s3_client:
        return None
    
    try:
        response = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': app.config['S3_BUCKET'], 'Key': s3_key},
            ExpiresIn=expiration
        )
        return response
    except ClientError as e:
        logger.error(f"Error generating presigned URL: {e}")
        return None

def log_file_upload(filename, file_type, file_size, user_id, success=True, error_message=None):
    """Log file upload attempt"""
    try:
        upload_log = FileUploadLog(
            filename=filename,
            file_type=file_type,
            file_size=file_size,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            success=success,
            error_message=error_message,
            uploaded_by=user_id
        )
        db.session.add(upload_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Error logging upload: {e}")

# ==================== ADMIN GUI AUTHENTICATION ====================

def admin_required(f):
    """Decorator for admin-only web routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        user = current_user
        if not user.active or not (user.has_role('admin') or user.has_role('superadmin')):
            logout_user()
            session.pop('admin_user_id', None)
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== ADMIN DASHBOARD FOR ALL APPS ====================

@app.route('/admin')
@admin_required
def admin_root():
    """Admin root - redirect to main dashboard"""
    return redirect(url_for('admin_main_dashboard'))

@app.route('/admin/dashboard')
@admin_required
def admin_main_dashboard():
    """Main admin dashboard for managing all apps"""
    # You can add more app stats here as you add more modules
    stats = {
        'glossary_terms': Term.query.count(),
        'glossary_categories': Category.query.count(),
        'users': User.query.count(),
        'active_users': User.query.filter_by(active=True).count(),
        'stl_files': STLFile.query.count(),
        'video_files': VideoFile.query.count(),
        'total_file_uploads': FileUploadLog.query.count(),
        # Add more as needed
    }
    return render_template('admin/main_dashboard.html', stats=stats)

@app.route('/admin/csrf-token', methods=['GET'])
@admin_required
def admin_refresh_csrf_token():
    """Endpoint to refresh CSRF token for long-running admin sessions"""
    try:
        from flask_wtf.csrf import generate_csrf
        new_token = generate_csrf()
        
        return jsonify({
            'success': True,
            'csrf_token': new_token,
            'message': 'CSRF token refreshed successfully'
        })
    except Exception as e:
        logger.error(f"Error refreshing CSRF token: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to refresh CSRF token'
        }), 500

@app.route('/admin/glossary/dashboard')
@admin_required
def admin_glossary_dashboard():
    """Glossary admin dashboard landing page"""
    stats = {
        'terms': Term.query.count(),
        'categories': Category.query.count(),
        # Add more glossary-specific stats if needed
    }
    return render_template('admin/glossary_dashboard.html', stats=stats)

# ==================== ADMIN GLOSSARY ROUTES (NAMESPACED) ====================

@app.route('/admin/glossary/terms')
@admin_required
def admin_glossary_terms_list():
    """List all terms for admin, with show/hide inactive toggle and sorting"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    category_id = request.args.get('category', type=int)
    show_inactive = request.args.get('show_inactive', '0') == '1'
    sort = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')

    query = Term.query

    if search:
        query = query.filter(or_(
            Term.term.ilike(f'%{search}%'),
            Term.definition.ilike(f'%{search}%')
        ))

    if category_id:
        query = query.filter(Term.category_id == category_id)

    if not show_inactive:
        query = query.filter(Term.is_active == True)

    # Handle sorting
    sort_column = Term.created_at  # default
    if sort == 'term':
        sort_column = Term.term
    elif sort == 'category':
        sort_column = Category.name
        query = query.join(Category, Term.category_id == Category.id)
    elif sort == 'difficulty':
        sort_column = Term.difficulty
    elif sort == 'views':
        sort_column = Term.view_count
    elif sort == 'status':
        sort_column = Term.is_active
    elif sort == 'created_at':
        sort_column = Term.created_at

    # Apply ordering
    if order == 'desc':
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(sort_column)

    terms = query.paginate(
        page=page, per_page=20, error_out=False
    )

    categories = Category.query.filter_by(is_active=True).all()

    return render_template('admin/terms_list.html', 
                         terms=terms, 
                         categories=categories, 
                         search=search, 
                         category_id=category_id,
                         show_inactive=show_inactive,
                         sort=sort,
                         order=order)

@app.route('/admin/glossary/terms/new', methods=['GET', 'POST'])
@admin_required
def admin_glossary_term_new():
    return admin_term_new()

@app.route('/admin/glossary/terms/<int:term_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_glossary_term_edit(term_id):
    return admin_term_edit(term_id)

@app.route('/admin/glossary/terms/<int:term_id>/delete', methods=['POST'])
@admin_required
def admin_glossary_term_delete(term_id):
    return admin_term_delete(term_id)

@app.route('/admin/glossary/categories')
@admin_required
def admin_glossary_categories_list():
    return admin_categories_list()

@app.route('/admin/glossary/categories/new', methods=['GET', 'POST'])
@admin_required
def admin_glossary_category_new():
    return admin_category_new()

@app.route('/admin/glossary/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_glossary_category_edit(category_id):
    return admin_category_edit(category_id)

@app.route('/admin/glossary/categories/<int:category_id>/delete', methods=['POST'])
@admin_required
def admin_glossary_category_delete(category_id):
    return admin_category_delete(category_id)

@app.route('/admin/glossary/categories/<int:category_id>/restore', methods=['POST'])
@admin_required
def admin_glossary_category_restore(category_id):
    return admin_category_restore(category_id)

@app.route('/admin/glossary/bulk-upload', methods=['GET', 'POST'])
@admin_required
def admin_glossary_bulk_upload_proxy():
    return admin_glossary_bulk_upload()

# ==================== API AUTHENTICATION ROUTES ====================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login endpoint with rate limiting"""
    try:
        error = None
        if request.method == 'GET':
            return render_template('admin/login.html', error=error)
    except Exception as e:
        return f"GET Error: {str(e)} ({type(e).__name__})", 500
    
    # POST request handling with comprehensive error catching
    try:
        # Rate limiting based on IP address
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if is_rate_limited(client_ip):
            error = 'Too many failed attempts. Please try again in 15 minutes.'
            return render_template('admin/login.html', error=error), 429
        
        data = request.get_json() if request.is_json else request.form
        if not data or not data.get('email') or not data.get('password'):
            error = 'Email and password required.'
            return render_template('admin/login.html', error=error)
        
        user = User.query.filter_by(email=data['email'], active=True).first()
        if not user or not secure_hasher.verify_password(data['password'], user.password):
            # Record failed attempt for rate limiting
            record_login_attempt(client_ip)
            error = 'Invalid credentials.'
            return render_template('admin/login.html', error=error)
        
        # Update login tracking
        user.last_login_at = user.current_login_at
        user.last_login_ip = user.current_login_ip
        user.current_login_at = datetime.utcnow()
        user.current_login_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        user.login_count = (user.login_count or 0) + 1
        db.session.commit()
        login_user(user)
        session['admin_user_id'] = user.id
        flash(f'Welcome back, {user.display_name}!', 'success')
        return redirect(url_for('admin_main_dashboard'))
        
    except Exception as e:
        import traceback
        app.logger.error(f"POST Login error: {str(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        try:
            db.session.rollback()
        except:
            pass
        return f"POST Error: {str(e)} ({type(e).__name__}) - Check logs for full traceback", 500




@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def secure_logout():
    """Secure logout"""
    from flask_jwt_extended import get_jwt
    
    jti = get_jwt()['jti']
    blacklisted_tokens.add(jti)
    
    return jsonify({'message': 'Successfully logged out'})

# ==================== PUBLIC API ROUTES ====================

@app.route('/glossary/terms')
def api_terms():
    """Get terms with filtering"""
    query = request.args.get('search', '').strip()
    category_slug = request.args.get('category', '').strip()
    difficulty = request.args.get('difficulty', '').strip()
    # Remove limit entirely - get all terms
    limit_param = request.args.get('limit', type=int)
    if limit_param and limit_param > 0:
        limit = min(limit_param, 2000)  # Cap at 2000 for safety
    else:
        limit = None  # No limit
    
    # Build query
    terms_query = Term.query.join(Category).filter(
        Term.is_active == True,
        Category.is_active == True
    )
    
    if query:
        search_filter = or_(
            Term.term.ilike(f'%{query}%'),
            Term.definition.ilike(f'%{query}%')
        )
        terms_query = terms_query.filter(search_filter)
    
    if category_slug:
        terms_query = terms_query.filter(Category.slug == category_slug)
    
    if difficulty and difficulty in ['tourist', 'local', 'expert']:
        terms_query = terms_query.filter(Term.difficulty == difficulty)
    
    # Execute query
    if limit:
        terms = terms_query.order_by(Term.term).limit(limit).all()
    else:
        terms = terms_query.order_by(Term.term).all()
    
    return jsonify({
        'terms': [term.to_dict() for term in terms],
        'count': len(terms)
    })

@app.route('/glossary/term/<slug>')
def api_term_detail(slug):
    """Get single term"""
    term = Term.query.filter_by(slug=slug, is_active=True).first()
    if not term:
        return jsonify({'error': 'Term not found'}), 404
    
    # Increment view count
    term.view_count += 1
    db.session.commit()
    
    return jsonify(term.to_dict(include_related=True))

@app.route('/glossary/categories')
def api_categories():
    """Get all categories"""
    categories = Category.query.filter_by(is_active=True).order_by(Category.sort_order, Category.name).all()
    return jsonify({
        'categories': [cat.to_dict() for cat in categories]
    })

@app.route('/glossary/stats')
def api_stats():
    """Get API statistics"""
    stats = {
        'total_terms': Term.query.filter_by(is_active=True).count(),
        'total_categories': Category.query.filter_by(is_active=True).count(),
        'total_views': db.session.query(func.sum(Term.view_count)).scalar() or 0,
        'difficulty_breakdown': {
            'tourist': Term.query.filter_by(difficulty='tourist', is_active=True).count(),
            'local': Term.query.filter_by(difficulty='local', is_active=True).count(),
            'expert': Term.query.filter_by(difficulty='expert', is_active=True).count()
        }
    }
    return jsonify(stats)

@app.route('/glossary/random')
def api_random_term():
    """Get random term"""
    term = Term.query.filter_by(is_active=True).order_by(func.random()).first()
    if term:
        return jsonify(term.to_dict())
    return jsonify({'error': 'No terms found'}), 404

# ==================== COMPLETE CRUD API ROUTES ====================

@app.route('/admin/terms', methods=['GET'])
@jwt_required()
def admin_get_terms():
    """Admin: Get all terms"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    terms = Term.query.order_by(desc(Term.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'terms': [term.to_dict() for term in terms.items],
        'total': terms.total,
        'pages': terms.pages,
        'current_page': terms.page,
        'has_next': terms.has_next,
        'has_prev': terms.has_prev
    })

@app.route('/admin/terms', methods=['POST'])
@jwt_required()
def admin_create_term():
    """Admin: Create new term"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    
    required_fields = ['term', 'pronunciation', 'definition', 'difficulty', 'category_id']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    if Term.query.filter_by(term=data['term']).first():
        return jsonify({'error': 'Term already exists'}), 400
    
    category = Category.query.get(data['category_id'])
    if not category:
        return jsonify({'error': 'Invalid category'}), 400
    
    term = Term(
        term=data['term'],
        slug=create_slug(data['term']),
        pronunciation=data['pronunciation'],
        definition=data['definition'],
        etymology=data.get('etymology', ''),
        example=data.get('example', ''),
        difficulty=data['difficulty'],
        category_id=data['category_id'],
        is_featured=data.get('is_featured', False)
    )
    
    try:
        db.session.add(term)
        db.session.commit()
        return jsonify(term.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create term'}), 500

@app.route('/admin/terms/<int:term_id>', methods=['GET'])
@jwt_required()
def admin_get_term(term_id):
    """Admin: Get single term"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    term = Term.query.get(term_id)
    if not term:
        return jsonify({'error': 'Term not found'}), 404
    
    return jsonify(term.to_dict(include_related=True))

@app.route('/admin/terms/<int:term_id>', methods=['PUT'])
@jwt_required()
def admin_update_term(term_id):
    """Admin: Update term"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    term = Term.query.get(term_id)
    if not term:
        return jsonify({'error': 'Term not found'}), 404
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['term', 'pronunciation', 'definition', 'difficulty', 'category_id']
    for field in required_fields:
        if field in data and not data[field]:
            return jsonify({'error': f'{field} cannot be empty'}), 400
    
    # Check if term name is taken by another term
    if 'term' in data and data['term'] != term.term:
        existing_term = Term.query.filter_by(term=data['term']).first()
        if existing_term:
            return jsonify({'error': 'Term name already exists'}), 400
    
    # Check if category exists
    if 'category_id' in data:
        category = Category.query.get(data['category_id'])
        if not category:
            return jsonify({'error': 'Invalid category'}), 400
    
    # Update fields
    if 'term' in data:
        term.term = data['term']
        term.slug = create_slug(data['term'])
    if 'pronunciation' in data:
        term.pronunciation = data['pronunciation']
    if 'definition' in data:
        term.definition = data['definition']
    if 'etymology' in data:
        term.etymology = data['etymology']
    if 'example' in data:
        term.example = data['example']
    if 'difficulty' in data:
        term.difficulty = data['difficulty']
    if 'category_id' in data:
        term.category_id = data['category_id']
    if 'is_featured' in data:
        term.is_featured = bool(data['is_featured'])
    if 'is_active' in data:
        term.is_active = bool(data['is_active'])
    
    term.updated_at = datetime.utcnow()
    
    try:
        db.session.commit()
        return jsonify(term.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update term'}), 500

@app.route('/admin/terms/<int:term_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_term(term_id):
    """Admin: Delete term (soft delete)"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    term = Term.query.get(term_id)
    if not term:
        return jsonify({'error': 'Term not found'}), 404
    
    # Check if we should hard delete or soft delete
    hard_delete = request.args.get('hard', 'false').lower() == 'true'
    
    try:
        if hard_delete:
            db.session.delete(term)
        else:
            term.is_active = False
            term.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': f'Term {"permanently deleted" if hard_delete else "deactivated"} successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete term'}), 500

# ==================== CATEGORY CRUD ====================

@app.route('/admin/categories', methods=['GET'])
@jwt_required()
def admin_get_categories():
    """Admin: Get all categories"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    categories = Category.query.order_by(Category.sort_order, Category.name).all()
    return jsonify({
        'categories': [cat.to_dict() for cat in categories]
    })

@app.route('/admin/categories', methods=['POST'])
@jwt_required()
def admin_create_category():
    """Admin: Create new category"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    
    required_fields = ['name']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'{field} is required'}), 400
    
    if Category.query.filter_by(name=data['name']).first():
        return jsonify({'error': 'Category already exists'}), 400
    
    category = Category(
        name=data['name'],
        slug=create_slug(data['name']),
        description=data.get('description', ''),
        sort_order=data.get('sort_order', 0),
        is_active=data.get('is_active', True)
    )
    
    try:
        db.session.add(category)
        db.session.commit()
        return jsonify(category.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create category'}), 500

@app.route('/admin/categories/<int:category_id>', methods=['PUT'])
@jwt_required()
def admin_update_category(category_id):
    """Admin: Update category"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    data = request.get_json()
    
    # Check if name is taken by another category
    if 'name' in data and data['name'] != category.name:
        existing_category = Category.query.filter_by(name=data['name']).first()
        if existing_category:
            return jsonify({'error': 'Category name already exists'}), 400
    
    # Update fields
    if 'name' in data:
        category.name = data['name']
        category.slug = create_slug(data['name'])
    if 'description' in data:
        category.description = data['description']
    if 'sort_order' in data:
        category.sort_order = data['sort_order']
    if 'is_active' in data:
        category.is_active = bool(data['is_active'])
    
    try:
        db.session.commit()
        return jsonify(category.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update category'}), 500

@app.route('/admin/categories/<int:category_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_category(category_id):
    """Admin: Delete category"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not (user.has_role('admin') or user.has_role('superadmin')):
        return jsonify({'error': 'Admin access required'}), 403
    
    category = Category.query.get(category_id)
    if not category:
        return jsonify({'error': 'Category not found'}), 404
    
    # Check if category has terms
    term_count = Term.query.filter_by(category_id=category_id, is_active=True).count()
    if term_count > 0:
        return jsonify({
            'error': f'Cannot delete category with {term_count} active terms. Move or delete terms first.'
        }), 400
    
    try:
        category.is_active = False
        db.session.commit()
        
        return jsonify({'message': 'Category deactivated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to delete category'}), 500

# ==================== BULK UPLOAD ROUTE ====================

@app.route('/admin/bulk-upload', methods=['GET', 'POST'])
@admin_required
def admin_glossary_bulk_upload():
    """Bulk upload terms and categories from JSON file"""
    if request.method == 'POST':
        file = request.files.get('json_file')
        if not file or not file.filename.endswith('.json'):
            flash('Please upload a valid JSON file.', 'error')
            return render_template('admin/bulk_upload.html')
        try:
            data = json.load(file)
            # Bulk upload categories
            categories_data = data.get('categories', [])
            for cat in categories_data:
                category = Category.query.filter_by(name=cat['name']).first()
                if not category:
                    category = Category(
                        name=cat['name'],
                        slug=create_slug(cat['name']),
                        description=cat.get('description', ''),
                        is_active=cat.get('is_active', True)
                    )
                    db.session.add(category)
            db.session.commit()
            # Bulk upload terms
            terms_data = data.get('terms', [])
            for t in terms_data:
                # Find category by name or id
                category = None
                if 'category_id' in t:
                    category = Category.query.get(t['category_id'])
                elif 'category' in t:
                    category = Category.query.filter_by(name=t['category']).first()
                if not category:
                    continue  # skip terms with no valid category
                if Term.query.filter_by(term=t['term']).first():
                    continue  # skip duplicates
                term = Term(
                    term=t['term'],
                    slug=create_slug(t['term']),
                    pronunciation=t.get('pronunciation', ''),
                    definition=t.get('definition', ''),
                    etymology=t.get('etymology', ''),
                    example=t.get('example', ''),
                    difficulty=t.get('difficulty', 'tourist'),
                    category_id=category.id,
                    is_featured=t.get('is_featured', False),
                    is_active=t.get('is_active', True)
                )
                db.session.add(term)
            db.session.commit()
            flash('Bulk upload successful!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Bulk upload failed: {e}', 'error')
    return render_template('admin/bulk_upload.html')

# ==================== HELPER FUNCTIONS ====================

# Helper functions to call the original admin glossary logic for namespaced routes
from flask import redirect, url_for

def admin_term_new():
    if request.method == 'POST':
        form = request.form
        term = form.get('term', '').strip()
        pronunciation = form.get('pronunciation', '').strip()
        definition = form.get('definition', '').strip()
        etymology = form.get('etymology', '').strip()
        example = form.get('example', '').strip()
        difficulty = form.get('difficulty', 'easy').strip()
        category_id = form.get('category_id', type=int)
        is_featured = bool(form.get('is_featured'))
        is_active = bool(form.get('is_active', True))
        # Validation
        errors = []
        if not term:
            errors.append('Term is required.')
        if not pronunciation:
            errors.append('Pronunciation is required.')
        if not definition:
            errors.append('Definition is required.')
        if not category_id:
            errors.append('Category is required.')
        slug = create_slug(term)
        if Term.query.filter_by(term=term).first():
            errors.append('A term with this name already exists.')
        elif Term.query.filter_by(slug=slug).first():
            errors.append('A term with this slug already exists. Please choose a different name.')
        if errors:
            flash(' '.join(errors), 'danger')
            return render_template('admin/term_form.html', form_data=form, categories=Category.query.filter_by(is_active=True).all())
        # Create term
        new_term = Term(
            term=term,
            slug=slug,
            pronunciation=pronunciation,
            definition=definition,
            etymology=etymology,
            example=example,
            difficulty=difficulty,
            category_id=category_id,
            is_featured=is_featured,
            is_active=is_active
        )
        db.session.add(new_term)
        db.session.commit()
        flash('Term created successfully.', 'success')
        return redirect(url_for('admin_glossary_terms_list'))
    categories = Category.query.filter_by(is_active=True).all()
    return render_template('admin/term_form.html', categories=categories)

def admin_term_edit(term_id):
    term = Term.query.get_or_404(term_id)
    if request.method == 'POST':
        form = request.form
        term.term = form.get('term', '').strip()
        term.slug = create_slug(term.term)
        term.pronunciation = form.get('pronunciation', '').strip()
        term.definition = form.get('definition', '').strip()
        term.etymology = form.get('etymology', '').strip()
        term.example = form.get('example', '').strip()
        term.difficulty = form.get('difficulty', 'easy').strip()
        term.category_id = form.get('category_id', type=int)
        term.is_featured = bool(form.get('is_featured'))
        term.is_active = bool(form.get('is_active', True))
        # Validation
        errors = []
        if not term.term:
            errors.append('Term is required.')
        if not term.pronunciation:
            errors.append('Pronunciation is required.')
        if not term.definition:
            errors.append('Definition is required.')
        if not term.category_id:
            errors.append('Category is required.')
        if errors:
            flash(' '.join(errors), 'danger')
            return render_template('admin/term_form.html', term=term, form_data=form, categories=Category.query.filter_by(is_active=True).all())
        db.session.commit()
        flash('Term updated successfully.', 'success')
        return redirect(url_for('admin_glossary_terms_list'))
    categories = Category.query.filter_by(is_active=True).all()
    return render_template('admin/term_form.html', term=term, categories=categories)

def admin_term_delete(term_id):
    term = Term.query.get_or_404(term_id)
    if request.method == 'POST':
        db.session.delete(term)
        db.session.commit()
        flash('Term permanently deleted.', 'success')
        return redirect(url_for('admin_glossary_terms_list'))
    # GET: Show confirmation page
    return render_template('admin/confirm_delete.html', object=term, object_type='term', cancel_url=url_for('admin_glossary_terms_list'))

def admin_categories_list():
    # Render the categories list for the glossary admin
    categories = Category.query.order_by(Category.name).all()
    # Move 'Core Terms' and 'Krewes' to the front
    core = [cat for cat in categories if cat.name == 'Core Terms']
    krewes = [cat for cat in categories if cat.name == 'Krewes']
    others = [cat for cat in categories if cat.name not in ('Core Terms', 'Krewes')]
    ordered = core + krewes + others
    show_inactive = request.args.get('show_inactive', '0') == '1'
    if not show_inactive:
        ordered = [cat for cat in ordered if cat.is_active]
    return render_template('admin/categories_list.html', categories=ordered, show_inactive=show_inactive)

def admin_category_new():
    if request.method == 'POST':
        form = request.form
        name = form.get('name', '').strip()
        description = form.get('description', '').strip()
        is_active = bool(form.get('is_active', True))
        # Validation
        errors = []
        if not name:
            errors.append('Name is required.')
        if errors:
            flash(' '.join(errors), 'danger')
            return render_template('admin/category_form.html', form_data=form)
        new_category = Category(
            name=name,
            slug=create_slug(name),
            description=description,
            is_active=is_active
        )
        db.session.add(new_category)
        db.session.commit()
        flash('Category created successfully.', 'success')
        return redirect(url_for('admin_glossary_categories_list'))
    return render_template('admin/category_form.html')

def admin_category_edit(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        form = request.form
        category.name = form.get('name', '').strip()
        category.slug = create_slug(category.name)
        category.description = form.get('description', '').strip()
        category.is_active = bool(form.get('is_active', True))
        # Validation
        errors = []
        if not category.name:
            errors.append('Name is required.')
        if errors:
            flash(' '.join(errors), 'danger')
            return render_template('admin/category_form.html', category=category, form_data=form)
        db.session.commit()
        flash('Category updated successfully.', 'success')
        return redirect(url_for('admin_glossary_categories_list'))
    return render_template('admin/category_form.html', category=category)

def admin_category_delete(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        # Check if category has terms
        term_count = Term.query.filter_by(category_id=category_id, is_active=True).count()
        if term_count > 0:
            flash(f'Cannot delete category with {term_count} active terms. Move or delete terms first.', 'error')
            return redirect(url_for('admin_glossary_categories_list'))
        
        try:
            # Soft delete instead of hard delete
            category.is_active = False
            db.session.commit()
            flash('Category deactivated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Failed to delete category.', 'error')
        
        return redirect(url_for('admin_glossary_categories_list'))
    # GET: Show confirmation page
    return render_template('admin/confirm_delete.html', object=category, object_type='category', cancel_url=url_for('admin_glossary_categories_list'))

def admin_category_restore(category_id):
    category = Category.query.get_or_404(category_id)
    category.is_active = True
    db.session.commit()
    flash('Category restored.', 'success')
    return redirect(url_for('admin_glossary_categories_list'))

# ==================== USER MANAGEMENT ROUTES ====================

def is_superadmin(user):
    return any(role.name == 'superadmin' for role in user.roles)

@app.route('/admin/users')
@admin_required
def admin_users_list():
    user = current_user
    if not is_superadmin(user):
        abort(403)
    users = User.query.all()
    return render_template('admin/users_list.html', users=users)

@app.route('/admin/users/new', methods=['GET', 'POST'])
@admin_required
def admin_user_new():
    user = current_user
    if not is_superadmin(user):
        abort(403)
    all_roles = Role.query.all()
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        role_id = request.form.get('role')
        if User.query.filter_by(email=email).first():
            flash('User already exists.', 'danger')
            return render_template('admin/user_form.html', all_roles=all_roles, form_data=request.form)
        # Generate a temporary password that will be replaced when user sets their password
        import secrets
        temp_password = secrets.token_urlsafe(32)
        new_user = User(
            email=email,
            first_name=first_name if first_name else None,
            last_name=last_name if last_name else None,
            password=secure_hasher.hash_password(temp_password)
        )
        if role_id:
            role = Role.query.get(int(role_id))
            if role:
                new_user.roles = [role]
        db.session.add(new_user)
        db.session.commit()
        try:
            send_set_password_email(new_user)
            flash('User created and setup email sent.', 'success')
        except Exception as e:
            # Email sending failed, but user was still created successfully
            flash('User created successfully. Email setup failed - please manually provide login credentials.', 'warning')
            print(f'Email sending error: {e}')
        return redirect(url_for('admin_users_list'))
    return render_template('admin/user_form.html', all_roles=all_roles)

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_user_edit(user_id):
    user = current_user
    if not is_superadmin(user):
        abort(403)
    edit_user = User.query.get_or_404(user_id)
    all_roles = Role.query.all()
    if request.method == 'POST':
        edit_user.email = request.form.get('email').strip().lower()
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        edit_user.first_name = first_name if first_name else None
        edit_user.last_name = last_name if last_name else None
        role_id = request.form.get('role')
        if role_id:
            role = Role.query.get(int(role_id))
            if role:
                edit_user.roles = [role]
        else:
            edit_user.roles = []
        db.session.commit()
        flash('User updated.', 'success')
        return redirect(url_for('admin_users_list'))
    return render_template('admin/user_form.html', user=edit_user, all_roles=all_roles)

@app.route('/admin/users/<int:user_id>/delete-confirm', methods=['GET'])
@admin_required
def admin_user_delete_confirm(user_id):
    user = current_user
    if not is_superadmin(user):
        abort(403)
    del_user = User.query.get_or_404(user_id)
    if del_user.id == user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users_list'))
    
    return render_template('admin/confirm_delete_user.html', 
                         user_to_delete=del_user,
                         cancel_url=url_for('admin_users_list'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_user_delete(user_id):
    user = current_user
    if not is_superadmin(user):
        abort(403)
    del_user = User.query.get_or_404(user_id)
    if del_user.id == user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users_list'))
    
    # Delete associated password reset tokens first to avoid foreign key constraint issues
    PasswordResetToken.query.filter_by(user_id=user_id).delete()
    
    # Now delete the user
    db.session.delete(del_user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users_list'))

@app.route('/admin/users/<int:user_id>/reset-password', methods=['GET', 'POST'])
@admin_required
def admin_user_reset_password(user_id):
    user = current_user
    if not is_superadmin(user):
        abort(403)
    reset_user = User.query.get_or_404(user_id)
    try:
        send_password_reset_email(reset_user)
        flash('Password reset email sent successfully.', 'success')
    except Exception as e:
        flash('Password reset email failed to send. Please check email configuration or contact the user manually.', 'warning')
        print(f'Email sending error: {e}')
    return redirect(url_for('admin_users_list'))

# Email sending logic

def safe_send_email(msg):
    """Safely send an email with proper error handling"""
    # Check if email is configured
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        return False, "Email not configured. Please set MAIL_USERNAME and MAIL_PASSWORD environment variables."
    
    try:
        mail.send(msg)
        return True, None
    except ConnectionRefusedError:
        return False, "SMTP server connection refused. Please check email server configuration."
    except Exception as e:
        return False, str(e)

def send_set_password_email(user):
    """Send setup email for new users"""
    token = generate_password_token(user)
    url = url_for('set_password', token=token, _external=True)
    msg = Message('Set up your Mardi Gras Admin password', recipients=[user.email])
    msg.html = render_template('email/welcome_set_password.html', set_password_url=url)
    
    success, error = safe_send_email(msg)
    if not success:
        raise Exception(f"Failed to send setup email: {error}")

def send_password_reset_email(user):
    """Send password reset email"""
    token = generate_password_token(user)
    url = url_for('set_password', token=token, _external=True)
    msg = Message('Reset your Mardi Gras Admin password', recipients=[user.email])
    msg.html = render_template('email/password_reset.html', reset_url=url)
    
    success, error = safe_send_email(msg)
    if not success:
        raise Exception(f"Failed to send password reset email: {error}")

def generate_password_token(user):
    """Generate secure one-time password reset token"""
    import hashlib
    
    # Generate a secure random token
    raw_token = secrets.token_urlsafe(32)
    
    # Hash the token for database storage
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    
    # Clean up old tokens for this user
    PasswordResetToken.query.filter_by(user_id=user.id).delete()
    
    # Create new token record
    expires_at = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
    token_record = PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at
    )
    db.session.add(token_record)
    db.session.commit()
    
    # Return the raw token (not hashed) for the URL
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps({'token': raw_token, 'user_id': user.id})

@app.route('/set-password/<token>', methods=['GET', 'POST'])
def set_password(token):
    """Secure password reset with one-time tokens"""
    import hashlib
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    
    try:
        # Decode the token
        data = s.loads(token, max_age=3600)  # 1 hour max age
        raw_token = data['token']
        user_id = data['user_id']
        
        # Hash the token to find it in database
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        # Find the token record
        token_record = PasswordResetToken.query.filter_by(
            user_id=user_id,
            token_hash=token_hash,
            used=False
        ).first()
        
        if not token_record:
            flash('Invalid or expired token.', 'error')
            return redirect(url_for('login'))
        
        # Check if token has expired
        if datetime.utcnow() > token_record.expires_at:
            flash('Token has expired. Please request a new password reset.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
            
    except Exception as e:
        flash('Invalid or expired token.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('set_password.html', user=user)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('set_password.html', user=user)
            
        user.set_password(password)
        
        # Mark token as used (one-time use security)
        token_record.used = True
        token_record.used_at = datetime.utcnow()
        
        db.session.commit()
        flash('Password set successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('set_password.html', user=user)

# ==================== UTILITY FUNCTIONS ====================

def create_slug(text):
    """Create URL-friendly slug"""
    if not text:
        return ''
    
    text = str(text)[:200]
    slug = re.sub(r'[^\w\s-]', '', text.lower())
    slug = re.sub(r'[-\s]+', '-', slug)
    return slug.strip('-')

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/admin'):
        # Check if user is authenticated for admin routes
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return render_template('admin/404.html'), 404
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/admin'):
        return render_template('admin/500.html'), 500
    return jsonify({'error': 'Internal server error'}), 500

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authentication required'}), 401

# ==================== ROOT ROUTE ====================

@app.route('/')
def root():
    """Root route - redirect to admin interface"""
    return redirect(url_for('login'))

# ==================== SUPERADMIN FILE UPLOAD ROUTES ====================

@app.route('/admin/files/upload/stl', methods=['POST'])
@superadmin_required
def upload_stl():
    """Superadmin: Upload STL file"""
    if 'file' not in request.files:
        flash('No file provided', 'error')
        return redirect(url_for('admin_files_list'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_files_list'))
    
    if not allowed_file(file.filename, 'stl'):
        flash('Invalid file type. Only STL files allowed', 'error')
        return redirect(url_for('admin_files_list'))
    
    # Generate unique identifiers
    file_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    # Get file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    # Prepare storage paths
    s3_key = f"stl/{timestamp}_{file_id}/{original_filename}"
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stl', f"{timestamp}_{file_id}", original_filename)
    
    # Try S3 upload first, fallback to local storage
    upload_success = False
    stored_s3_key = None
    stored_local_path = None
    
    if s3_client:
        try:
            if upload_to_s3(file, s3_key):
                upload_success = True
                stored_s3_key = s3_key
                # Don't seek after S3 upload as file may be closed
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            # Continue to local storage fallback
    
    if not upload_success:
        # Fallback to local storage
        # Reset file pointer if file is still open
        try:
            file.seek(0)
        except ValueError:
            # File is closed, cannot fallback to local storage
            logger.error("File is closed, cannot save to local storage")
        else:
            if save_local_file(file, local_path):
                upload_success = True
                stored_local_path = local_path
    
    if not upload_success:
        log_file_upload(original_filename, 'stl', file_size, current_user.id, False, 'Failed to upload to both S3 and local storage')
        flash('Failed to upload file', 'error')
        return redirect(url_for('admin_files_list'))
    
    # Handle parent file relationship
    parent_file_id = request.form.get('parent_file_id')
    is_partial = request.form.get('is_partial') == 'true'
    
    # Save to database
    try:
        stl_file = STLFile(
            id=file_id,
            original_filename=original_filename,
            s3_key=stored_s3_key,
            local_path=stored_local_path,
            file_size=file_size,
            description=request.form.get('description', ''),
            tags=request.form.get('tags', ''),
            uploaded_by=current_user.id,
            parent_file_id=parent_file_id if parent_file_id else None,
            is_partial=is_partial
        )
        db.session.add(stl_file)
        db.session.commit()
        
        # Generate screenshot asynchronously (in background)
        # Use threading to not block the upload response
        import threading
        
        def generate_screenshot_async():
            try:
                screenshot_s3_key = generate_stl_screenshot(file_id, stored_s3_key, stored_local_path)
                if screenshot_s3_key:
                    # Update database in a new session
                    with app.app_context():
                        stl_file_update = STLFile.query.get(file_id)
                        if stl_file_update:
                            stl_file_update.screenshot_s3_key = screenshot_s3_key
                            db.session.commit()
                            logger.info(f"Screenshot generated for STL file {file_id}: {screenshot_s3_key}")
                else:
                    logger.warning(f"Failed to generate screenshot for STL file {file_id}")
            except Exception as e:
                logger.error(f"Error generating screenshot for STL file {file_id}: {e}")
        
        # Start screenshot generation in background thread
        screenshot_thread = threading.Thread(target=generate_screenshot_async)
        screenshot_thread.daemon = True
        screenshot_thread.start()
        
        log_file_upload(original_filename, 'stl', file_size, current_user.id, True)
        flash(f'STL file "{original_filename}" uploaded successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error: {e}")
        log_file_upload(original_filename, 'stl', file_size, current_user.id, False, str(e))
        flash('Failed to save file metadata', 'error')
    
    return redirect(url_for('admin_files_list'))

@app.route('/admin/files/upload/video', methods=['POST'])
@superadmin_required
def upload_video():
    """Superadmin: Upload video file"""
    if 'file' not in request.files:
        flash('No file provided', 'error')
        return redirect(url_for('admin_files_list'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_files_list'))
    
    if not allowed_file(file.filename, 'video'):
        flash('Invalid file type. Only video files allowed', 'error')
        return redirect(url_for('admin_files_list'))
    
    # Generate unique identifiers
    file_id = str(uuid.uuid4())
    original_filename = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    # Get file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    # Prepare storage paths
    s3_key = f"video/{timestamp}_{file_id}/{original_filename}"
    local_path = os.path.join(app.config['UPLOAD_FOLDER'], 'video', f"{timestamp}_{file_id}", original_filename)
    
    # Try S3 upload first, fallback to local storage
    upload_success = False
    stored_s3_key = None
    stored_local_path = None
    
    if s3_client:
        if upload_to_s3(file, s3_key):
            upload_success = True
            stored_s3_key = s3_key
            file.seek(0)
    
    if not upload_success:
        if save_local_file(file, local_path):
            upload_success = True
            stored_local_path = local_path
    
    if not upload_success:
        log_file_upload(original_filename, 'video', file_size, current_user.id, False, 'Failed to upload to both S3 and local storage')
        flash('Failed to upload file', 'error')
        return redirect(url_for('admin_files_list'))
    
    # Validate STL association if provided
    stl_id = request.form.get('stl_id')
    if stl_id:
        stl_file = STLFile.query.get(stl_id)
        if not stl_file:
            flash('Associated STL file not found', 'error')
            return redirect(url_for('admin_files_list'))
    
    # Save to database
    try:
        video_file = VideoFile(
            id=file_id,
            original_filename=original_filename,
            s3_key=stored_s3_key,
            local_path=stored_local_path,
            file_size=file_size,
            description=request.form.get('description', ''),
            associated_stl_id=stl_id,
            uploaded_by=current_user.id
        )
        db.session.add(video_file)
        db.session.commit()
        
        log_file_upload(original_filename, 'video', file_size, current_user.id, True)
        flash(f'Video file "{original_filename}" uploaded successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database error: {e}")
        log_file_upload(original_filename, 'video', file_size, current_user.id, False, str(e))
        flash('Failed to save file metadata', 'error')
    
    return redirect(url_for('admin_files_list'))

@app.route('/admin/files/dashboard')
@superadmin_required
def admin_files_dashboard():
    """Superadmin: Files dashboard landing page"""
    stats = {
        'stl_files': STLFile.query.count(),
        'video_files': VideoFile.query.count(),
        'total_file_uploads': FileUploadLog.query.count(),
    }
    
    # Get recent files for dashboard display
    recent_stl_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).limit(5).all()
    recent_video_files = VideoFile.query.order_by(VideoFile.upload_timestamp.desc()).limit(5).all()
    
    # Combine and sort recent files
    recent_files = []
    for stl in recent_stl_files:
        recent_files.append({
            'id': stl.id,
            'filename': stl.original_filename,
            'type': 'stl',
            'size': stl.file_size,
            'upload_date': stl.upload_timestamp
        })
    for video in recent_video_files:
        recent_files.append({
            'id': video.id,
            'filename': video.original_filename,
            'type': 'video',
            'size': video.file_size,
            'upload_date': video.upload_timestamp
        })
    
    # Sort by upload date and limit to 10
    recent_files = sorted(recent_files, key=lambda x: x['upload_date'], reverse=True)[:10]
    
    # Get all STL files for video upload modal
    stl_files = STLFile.query.order_by(STLFile.original_filename).all()
    
    return render_template('admin/files_dashboard.html', 
                         stats=stats, 
                         recent_files=recent_files,
                         stl_files=stl_files)

@app.route('/admin/files')
@superadmin_required
def admin_files_list():
    """Superadmin: List all uploaded files"""
    stl_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).all()
    video_files = VideoFile.query.order_by(VideoFile.upload_timestamp.desc()).all()
    
    return render_template('admin/files_list.html', 
                         stl_files=stl_files, 
                         video_files=video_files)

@app.route('/admin/files/stl/<file_id>')
@superadmin_required
def admin_view_stl_file(file_id):
    """Superadmin: View STL file details"""
    stl_file = STLFile.query.get_or_404(file_id)
    
    # Update view statistics
    stl_file.last_viewed = datetime.utcnow()
    stl_file.view_count = (stl_file.view_count or 0) + 1
    db.session.commit()
    
    # Generate download URL
    download_url = None
    if stl_file.s3_key:
        download_url = generate_presigned_url(stl_file.s3_key)
    elif stl_file.local_path and os.path.exists(stl_file.local_path):
        download_url = url_for('admin_download_stl_file', file_id=file_id)
    
    return render_template('admin/stl_file_detail.html', 
                         stl_file=stl_file, 
                         download_url=download_url)

@app.route('/admin/files/video/<file_id>')
@superadmin_required
def admin_view_video_file(file_id):
    """Superadmin: View video file details"""
    video_file = VideoFile.query.get_or_404(file_id)
    
    # Generate download URL
    download_url = None
    if video_file.s3_key:
        download_url = generate_presigned_url(video_file.s3_key)
    elif video_file.local_path and os.path.exists(video_file.local_path):
        download_url = url_for('admin_download_video_file', file_id=file_id)
    
    return render_template('admin/video_file_detail.html', 
                         video_file=video_file, 
                         download_url=download_url)

@app.route('/admin/files/stl/<file_id>/download')
@superadmin_required
def admin_download_stl_file(file_id):
    """Superadmin: Download STL file from local storage"""
    stl_file = STLFile.query.get_or_404(file_id)
    
    if not stl_file.local_path or not os.path.exists(stl_file.local_path):
        flash('File not found on local storage', 'error')
        return redirect(url_for('admin_view_stl_file', file_id=file_id))
    
    return send_file(
        stl_file.local_path,
        as_attachment=True,
        download_name=stl_file.original_filename,
        mimetype='application/octet-stream'
    )

@app.route('/admin/files/video/<file_id>/download')
@superadmin_required
def admin_download_video_file(file_id):
    """Superadmin: Download video file from local storage"""
    video_file = VideoFile.query.get_or_404(file_id)
    
    if not video_file.local_path or not os.path.exists(video_file.local_path):
        flash('File not found on local storage', 'error')
        return redirect(url_for('admin_view_video_file', file_id=file_id))
    
    return send_file(
        video_file.local_path,
        as_attachment=True,
        download_name=video_file.original_filename
    )

@app.route('/admin/files/stl/<file_id>/delete', methods=['POST'])
@superadmin_required
def admin_delete_stl_file(file_id):
    """Superadmin: Delete STL file"""
    stl_file = STLFile.query.get_or_404(file_id)
    
    # Delete from S3 if stored there
    if stl_file.s3_key and s3_client:
        try:
            s3_client.delete_object(Bucket=app.config['S3_BUCKET'], Key=stl_file.s3_key)
            logger.info(f"Deleted {stl_file.s3_key} from S3")
        except ClientError as e:
            logger.error(f"Error deleting from S3: {e}")
    
    # Delete local file if exists
    if stl_file.local_path and os.path.exists(stl_file.local_path):
        try:
            os.remove(stl_file.local_path)
            logger.info(f"Deleted local file: {stl_file.local_path}")
        except Exception as e:
            logger.error(f"Error deleting local file: {e}")
    
    # Delete from database
    db.session.delete(stl_file)
    db.session.commit()
    
    flash(f'STL file "{stl_file.original_filename}" deleted successfully', 'success')
    return redirect(url_for('admin_files_list'))

@app.route('/admin/files/video/<file_id>/delete', methods=['POST'])
@superadmin_required
def admin_delete_video_file(file_id):
    """Superadmin: Delete video file"""
    video_file = VideoFile.query.get_or_404(file_id)
    
    # Delete from S3 if stored there
    if video_file.s3_key and s3_client:
        try:
            s3_client.delete_object(Bucket=app.config['S3_BUCKET'], Key=video_file.s3_key)
            logger.info(f"Deleted {video_file.s3_key} from S3")
        except ClientError as e:
            logger.error(f"Error deleting from S3: {e}")
    
    # Delete local file if exists
    if video_file.local_path and os.path.exists(video_file.local_path):
        try:
            os.remove(video_file.local_path)
            logger.info(f"Deleted local file: {video_file.local_path}")
        except Exception as e:
            logger.error(f"Error deleting local file: {e}")
    
    # Delete from database
    db.session.delete(video_file)
    db.session.commit()
    
    flash(f'Video file "{video_file.original_filename}" deleted successfully', 'success')
    return redirect(url_for('admin_files_list'))

@app.route('/admin/files/stl/<file_id>/feature', methods=['POST'])
@superadmin_required
def admin_set_featured_file(file_id):
    """Superadmin: Set which STL file is featured for tourists"""
    # Unfeature all files
    STLFile.query.update({STLFile.is_featured: False})
    
    # Feature the selected file
    new_featured = STLFile.query.get_or_404(file_id)
    new_featured.is_featured = True
    
    db.session.commit()
    
    flash(f'STL file "{new_featured.original_filename}" is now featured for tourists', 'success')
    return redirect(url_for('admin_files_list'))

@app.route('/admin/files/stl/<file_id>/relationships', methods=['POST'])
@superadmin_required
def admin_update_stl_relationships(file_id):
    """Superadmin: Update parent-child relationships for an STL file"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        # Get form data
        is_partial = request.form.get('is_partial') == 'true'
        parent_file_id = request.form.get('parent_file_id')
        
        # Validate parent file if provided
        parent_file = None
        if parent_file_id:
            parent_file = STLFile.query.get(parent_file_id)
            if not parent_file:
                return jsonify({'error': 'Parent file not found'}), 400
            
            # Prevent circular relationships
            if parent_file_id == file_id:
                return jsonify({'error': 'A file cannot be its own parent'}), 400
            
            # Check if proposed parent is actually a child of this file
            if stl_file.id == parent_file.parent_file_id:
                return jsonify({'error': 'Cannot create circular relationship: proposed parent is a child of this file'}), 400
            
            # Check deeper circular relationships
            def check_circular_relationship(potential_parent, target_file_id, depth=0):
                if depth > 10:  # Prevent infinite recursion
                    return False
                if potential_parent.parent_file_id == target_file_id:
                    return True
                if potential_parent.parent_file and potential_parent.parent_file_id:
                    return check_circular_relationship(potential_parent.parent_file, target_file_id, depth + 1)
                return False
            
            if check_circular_relationship(parent_file, file_id):
                return jsonify({'error': 'Cannot create circular relationship in the file hierarchy'}), 400
        
        # Update the file
        stl_file.is_partial = is_partial
        stl_file.parent_file_id = parent_file_id if parent_file_id else None
        
        db.session.commit()
        
        # Return updated file data
        return jsonify({
            'success': True,
            'message': 'Relationships updated successfully',
            'file': {
                'id': stl_file.id,
                'is_partial': stl_file.is_partial,
                'parent_file_id': stl_file.parent_file_id,
                'parent_file_name': stl_file.parent_file.original_filename if stl_file.parent_file else None
            }
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating relationships for file {file_id}: {e}")
        return jsonify({'error': 'Failed to update relationships'}), 500

@app.route('/admin/files/stl/available-parents/<file_id>')
@superadmin_required
def admin_get_available_parents(file_id):
    """Get available parent files for a given STL file (excludes self and children)"""
    try:
        current_file = STLFile.query.get_or_404(file_id)
        
        # Get all non-partial files except current file and its children
        available_parents = STLFile.query.filter(
            STLFile.is_partial == False,
            STLFile.id != file_id,
            STLFile.parent_file_id != file_id
        ).order_by(STLFile.original_filename).all()
        
        # Convert to JSON
        parents = []
        for file in available_parents:
            parents.append({
                'id': file.id,
                'filename': file.original_filename,
                'upload_date': file.upload_timestamp.strftime('%Y-%m-%d')
            })
        
        return jsonify({'parents': parents})
        
    except Exception as e:
        logger.error(f"Error getting available parents for file {file_id}: {e}")
        return jsonify({'error': 'Failed to get available parents'}), 500

# ==================== PUBLIC PIXIE API ENDPOINTS ====================

@app.route('/pixie/api/featured', methods=['GET'])
def pixie_api_featured():
    """Public API: Get featured STL file for Pixie tourist viewer"""
    try:
        # Get the featured STL file
        featured_file = STLFile.query.filter_by(is_featured=True).first()
        
        if not featured_file:
            return jsonify({'error': 'No featured file set'}), 404
        
        # Generate download URL
        download_url = None
        if featured_file.s3_key and s3_client:
            try:
                download_url = generate_presigned_url(featured_file.s3_key, expiration=3600)
            except Exception as e:
                logger.error(f"Error generating presigned URL: {e}")
        
        if not download_url and featured_file.local_path:
            # For local files, use our download endpoint
            download_url = f"/pixie/api/download/stl/{featured_file.id}"
        
        response_data = {
            'id': featured_file.id,
            'filename': featured_file.original_filename,
            'size': featured_file.file_size,
            'upload_date': featured_file.upload_timestamp.isoformat(),
            'view_count': featured_file.view_count or 0,
            'description': featured_file.description or '',
            'tags': featured_file.tags.split(',') if featured_file.tags else [],
            'download_url': download_url,
            'screenshot_url': featured_file.get_screenshot_url()
        }
        
        # Update view count
        featured_file.last_viewed = datetime.utcnow()
        featured_file.view_count = (featured_file.view_count or 0) + 1
        db.session.commit()
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error getting featured file: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/pixie/api/past-projects', methods=['GET'])
def pixie_api_past_projects():
    """Public API: Get recent STL files for browsing past projects"""
    try:
        # Get recent STL files (last 10)
        past_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).limit(10).all()
        
        if not past_files:
            return jsonify({'projects': []}), 200
        
        projects = []
        for file in past_files:
            # Generate download URL
            download_url = None
            if file.s3_key and s3_client:
                try:
                    download_url = generate_presigned_url(file.s3_key, expiration=3600)
                except Exception as e:
                    logger.error(f"Error generating presigned URL: {e}")
            
            if not download_url and file.local_path:
                download_url = f"/pixie/api/download/stl/{file.id}"
            
            if download_url:  # Only include files that have valid download URLs
                projects.append({
                    'id': file.id,
                    'filename': file.original_filename,
                    'description': file.description or "Custom CNC Creation",
                    'size': file.file_size,
                    'upload_date': file.upload_timestamp.isoformat(),
                    'download_url': download_url,
                    'screenshot_url': file.get_screenshot_url(),
                    'tags': file.tags.split(',') if file.tags else [],
                    'view_count': file.view_count,
                    'is_featured': file.is_featured,
                    'is_partial': file.is_partial,
                    'parent_file_id': file.parent_file_id
                })
        
        return jsonify({'projects': projects})
        
    except Exception as e:
        logger.error(f"Error getting past projects: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/pixie/api/download/stl/<file_id>', methods=['GET'])
def pixie_api_download_stl(file_id):
    """Public API: Download STL file for Pixie viewer"""
    try:
        stl_file = STLFile.query.get_or_404(file_id)
        
        if not stl_file.local_path or not os.path.exists(stl_file.local_path):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(
            stl_file.local_path,
            as_attachment=False,  # Allow inline viewing for STL viewer
            download_name=stl_file.original_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        logger.error(f"Error downloading STL file: {e}")
        return jsonify({'error': 'File not found'}), 404

# ==================== HEALTH CHECK ====================

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '3.0.0-full-crud'
    })

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize database"""
    try:
        print("🔄 Initializing database with CRUD support...")
        
        # Create all tables
        db.create_all()
        print("✅ Database tables created")
        
        # Create default categories if none exist
        if Category.query.count() == 0:
            default_categories = [
                {'name': 'Core Terms', 'description': 'Essential Carnival vocabulary', 'sort_order': 1},
                {'name': 'Krewes', 'description': 'Carnival organizations and societies', 'sort_order': 2},
                {'name': 'Food & Drink', 'description': 'Traditional Carnival cuisine', 'sort_order': 3},
                {'name': 'Throws', 'description': 'Items thrown from parade floats', 'sort_order': 4},
                {'name': 'Parades', 'description': 'Parade terminology and logistics', 'sort_order': 5},
            ]
            
            for cat_data in default_categories:
                category = Category(
                    name=cat_data['name'],
                    slug=create_slug(cat_data['name']),
                    description=cat_data['description'],
                    sort_order=cat_data['sort_order'],
                    is_active=True
                )
                db.session.add(category)
            
            db.session.commit()
            print(f"✅ Created {len(default_categories)} default categories")
        
        # Create default roles if they don't exist
        default_roles = ['superadmin', 'admin', 'user']
        for role_name in default_roles:
            if not Role.query.filter_by(name=role_name).first():
                role = Role(name=role_name)
                db.session.add(role)
        db.session.commit()
        print(f"✅ Created default roles: {', '.join(default_roles)}")
        
        # Create admin user
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@dev.local')
        admin_user = User.query.filter_by(email=admin_email).first()
        if not admin_user:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'DevAdmin123!@#')
            admin_user = User(
                email=admin_email,
                username=os.environ.get('ADMIN_USERNAME', 'admin'),
                password=secure_hasher.hash_password(admin_password),
                active=True
            )
            # Generate API key
            admin_user.api_key = secrets.token_urlsafe(32)
            db.session.add(admin_user)
            db.session.commit()
            # Assign superadmin role
            superadmin_role = Role.query.filter_by(name='superadmin').first()
            admin_user.roles.append(superadmin_role)
            db.session.commit()
            print(f"✅ Admin user created: {admin_email}")
            print(f"🔑 Admin API Key: {admin_user.api_key}")
            print(f"🌐 Admin GUI: http://localhost:5555/admin")
        
        # Create upload directory
        upload_dir = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        os.makedirs(os.path.join(upload_dir, 'stl'), exist_ok=True)
        os.makedirs(os.path.join(upload_dir, 'video'), exist_ok=True)
        print(f"✅ Upload directories created: {upload_dir}")
        
        print("✅ Full CRUD database initialization completed with file upload support!")
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ Database initialization failed: {e}")
        import traceback
        traceback.print_exc()
        raise

@app.route('/admin/logout')
@admin_required
def admin_logout():
    """Log out admin user from session and redirect to login page"""
    logout_user()
    session.pop('admin_user_id', None)
    return redirect(url_for('login'))

@app.context_processor
def inject_now_and_user():
    from flask_login import current_user
    return {'now': datetime.utcnow, 'current_user': current_user}

@app.route('/admin/account', methods=['GET', 'POST'])
@admin_required
def admin_account():
    user = current_user
    message = error = None
    if request.method == 'POST':
        # Update name fields
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        user.first_name = first_name if first_name else None
        user.last_name = last_name if last_name else None
        
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if new_password:
            if new_password != confirm_password:
                error = 'Passwords do not match.'
            elif len(new_password) < 8:
                error = 'Password must be at least 8 characters.'
            else:
                # Set new password
                user.password = secure_hasher.hash_password(new_password)
                db.session.commit()
                message = 'Account updated successfully.'
        else:
            # Just update name fields without password
            db.session.commit()
            message = 'Account updated successfully.'
    return render_template('admin/account.html', user=user, message=message, error=error)

# Database migration endpoint
@app.route('/admin/migrate-database', methods=['GET', 'POST'])
@jwt_required(optional=True)
def migrate_database():
    """Migrate database schema for new columns"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Recreate STL tables with new schema to ensure compatibility
            with db.engine.connect() as conn:
                # Drop and recreate stl_file table
                conn.execute(text("DROP TABLE IF EXISTS stl_file"))
                conn.commit()
                
            # Recreate all tables with updated schema
            db.create_all()
            
            # Recreate default data
            init_default_data()
            
            flash('Database schema updated successfully! All tables recreated with new schema.', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            flash(f'Migration error: {str(e)}', 'error')
            logger.error(f"Migration error: {str(e)}")
            return render_template('admin/migrate.html', error=str(e))
    
    return render_template('admin/migrate.html')

# Production initialization
def init_production_app():
    """Initialize app for production deployment"""
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            print("✅ Database tables initialized")
        except Exception as e:
            print(f"⚠️ Database initialization warning: {e}")

# Initialize database tables on startup
init_production_app()

if __name__ == '__main__':
    print("🚀 Starting Mardi Gras API with Full CRUD & Admin GUI...")
    
    # Initialize database for local development
    with app.app_context():
        init_db()
    
    # Start server
    port = int(os.environ.get('PORT', 5555))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() in ['true', '1', 'on']
    
    print(f"🌐 Server starting on http://localhost:{port}")
    print(f"👨‍💼 Admin GUI: http://localhost:{port}/admin")
    
    app.run(debug=debug, host='0.0.0.0', port=port)