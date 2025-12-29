"""
Mardi Gras API - Pure API Service
A clean API service for managing glossary terms and file uploads with OAuth2 integration
"""

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
import os

# Import configuration and utilities
from config import get_config
from utils.logger import logger

# Import models and services
from models import db
from services.oauth2_service import OAuth2Service

# Import route blueprints
from routes import register_routes

def create_app(config_name=None):
    """Application factory pattern"""
    
    app = Flask(__name__)
    
    # Handle HTTPS proxy for Railway deployment
    if os.environ.get('RAILWAY_ENVIRONMENT_NAME'):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_class = get_config(config_name)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    
    # Initialize OAuth2 service
    app.oauth2_service = OAuth2Service(
        auth_service_url=app.config.get('AUTH_SERVICE_URL', 'https://auth.mardigrasworld.com'),
        jwt_secret_key=app.config.get('JWT_SECRET_KEY')
    )
    
    # CORS Configuration
    cors = CORS(app, 
        origins=app.config['ALLOWED_ORIGINS'], 
        supports_credentials=True,
        resources={
            r"/pixie/api/*": {"origins": app.config['ALLOWED_ORIGINS'], "supports_credentials": True},  # Allow credentials for admin endpoints
            r"/api/*": {"origins": app.config['ALLOWED_ORIGINS'], "supports_credentials": True},  # Restrict other API endpoints
            r"/*": {"origins": app.config['ALLOWED_ORIGINS'], "supports_credentials": True}  # Default restriction for all other routes
        })
    
    # Mail Configuration (for notifications only)
    mail = Mail(app)
    
    # Template filters
    @app.template_filter('strftime')
    def strftime_filter(dt, format='%Y-%m-%d'):
        """Format datetime for templates"""
        if dt is None:
            return ""
        return dt.strftime(format)
    
    # Security headers
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        for header, value in app.config['SECURITY_HEADERS'].items():
            response.headers[header] = value
        return response
    
    # Error handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        """Handle 400 Bad Request errors"""
        # Enhanced CSRF error handling
        error_description = str(e)
        is_csrf_error = 'CSRF' in error_description or 'csrf' in error_description.lower()
        
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Bad Request', 
                'message': error_description,
                'csrf_error': is_csrf_error
            }), 400
        
        # For web forms, provide more helpful error info in development
        if app.debug and is_csrf_error:
            logger.warning(f"CSRF Error: {error_description} for {request.path}")
            logger.warning(f"Request headers: {dict(request.headers)}")
            logger.warning(f"Form data: {request.form}")
        
        return jsonify({'error': 'Bad Request', 'message': error_description}), 400
    
    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle 404 Not Found errors"""
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not Found', 'message': 'Resource not found'}), 404
        return jsonify({'error': 'Not Found', 'message': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle 500 Internal Server errors"""
        logger.error(f"Internal server error: {e}")
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
        return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
    
    # Main routes
    @app.route('/')
    def index():
        """Main application index"""
        return jsonify({
            'service': 'mardi-gras-api',
            'version': '3.0.0',
            'description': 'Pure API service for Mardi Gras glossary and file management',
            'endpoints': {
                'health': '/health',
                'glossary': '/glossary',
                'files': '/files',
                'api': '/api',
                'pixie': '/pixie'
            }
        })
    
    @app.route('/health')
    def health_check():
        """Main health check endpoint"""
        return jsonify({
            'status': 'ok',
            'service': 'mardi-gras-api',
            'version': '2.0.0',
            'timestamp': datetime.utcnow().isoformat()
        })
    
    # Register all route blueprints
    register_routes(app)
    
    # All routes are now API routes - no CSRF needed
    
    # Database initialization
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
    
    return app

# Create the Flask application
app = create_app()

if __name__ == '__main__':
    logger.info("Starting Mardi Gras API server...")
    
    # Debug configuration
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('PORT', 5555))
    
    logger.info(f"Environment: {os.environ.get('FLASK_ENV', 'development')}")
    logger.info(f"Debug mode: {debug_mode}")
    logger.info(f"Port: {port}")
    logger.info(f"Database URL configured: {'Yes' if app.config['SQLALCHEMY_DATABASE_URI'] else 'No'}")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode
    )