"""
Configuration management for the Mardi Gras API
"""
import os
import secrets
from dotenv import load_dotenv

# Load environment variables
if os.path.exists('.env.local'):
    load_dotenv('.env.local')
elif os.path.exists('.env'):
    load_dotenv('.env')

# For Railway deployment, ensure we can start without .env files
load_dotenv()  # This will load from system environment if no .env file

class Config:
    """Base configuration class"""
    
    # Basic Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Session Configuration
    SESSION_COOKIE_SECURE = os.environ.get('RAILWAY_ENVIRONMENT_NAME') is not None  # Only secure in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Database configuration
    @staticmethod
    def get_database_url():
        """Get properly formatted database URL"""
        database_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/mardi_gras_dev.db')
        
        # Fix for Railway PostgreSQL URL format (postgresql:// vs postgres://)
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
        # Railway managed PostgreSQL - try disabling SSL verification
        if 'postgresql://' in database_url and 'railway' in database_url:
            if '?' not in database_url:
                database_url += '?sslmode=disable'
            elif 'sslmode=' not in database_url:
                database_url += '&sslmode=disable'
        
        return database_url
    
    SQLALCHEMY_DATABASE_URI = get_database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # CORS Configuration
    default_origins = 'http://localhost:3000,http://localhost:5555,https://pixieview-demo.up.railway.app'
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', default_origins).split(',')
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = False  # Tokens don't expire by default
    
    # Mail Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 'on']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)
    
    # AWS S3 Configuration
    S3_BUCKET = os.environ.get('S3_BUCKET_NAME')
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
    
    # Upload Configuration
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    
    # CSRF Configuration
    WTF_CSRF_TIME_LIMIT = None  # No time limit on CSRF tokens
    WTF_CSRF_SSL_STRICT = False  # Allow CSRF over HTTP in development
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block'
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    WTF_CSRF_SSL_STRICT = True  # Enforce HTTPS for CSRF in production

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Configuration mapping
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config(env=None):
    """Get configuration class based on environment"""
    if env is None:
        env = os.environ.get('FLASK_ENV', 'development')
    
    return config_map.get(env, DevelopmentConfig)