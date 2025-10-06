"""
Mardi Gras API - Refactored Flask Application
A clean, modular API for managing glossary terms, user authentication, and file uploads
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required
from flask_cors import CORS
from flask_mail import Mail
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import os
import secrets

# Import configuration and utilities
from config import get_config
from utils.logger import logger

# Import models and services
from models import db, User
from services.auth_service import secure_hasher, rate_limiter

# Import route blueprints
from routes import register_routes

def create_app(config_name=None):
    """Application factory pattern"""
    
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    config_class = get_config(config_name)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    
    # JWT Configuration
    jwt = JWTManager(app)
    
    # CORS Configuration
    cors = CORS(app, origins=app.config['ALLOWED_ORIGINS'], resources={
        r"/pixie/api/*": {"origins": "*"},  # Allow all origins for Pixie API endpoints
        r"/api/*": {"origins": app.config['ALLOWED_ORIGINS']},  # Restrict other API endpoints
        r"/*": {"origins": app.config['ALLOWED_ORIGINS']}  # Default restriction for all other routes
    })
    
    # Mail Configuration
    mail = Mail(app)
    
    # CSRF Protection Configuration
    csrf = CSRFProtect(app)
    
    # Flask-Login Configuration
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        """Load user for Flask-Login"""
        return User.query.get(int(user_id))
    
    # JWT Token Blacklist (in production, use Redis or database)
    blacklisted_tokens = set()
    
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        """Check if JWT token is blacklisted"""
        return jwt_payload['jti'] in blacklisted_tokens
    
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
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Bad Request', 'message': str(e)}), 400
        return render_template('admin/400.html'), 400
    
    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle 404 Not Found errors"""
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not Found', 'message': 'Resource not found'}), 404
        return render_template('admin/404.html'), 404
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle 500 Internal Server errors"""
        logger.error(f"Internal server error: {e}")
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
        return render_template('admin/500.html'), 500
    
    # Main routes
    @app.route('/')
    def index():
        """Main application index"""
        return redirect(url_for('admin.dashboard'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Main login endpoint"""
        if request.method == 'GET':
            return render_template('admin/login.html')
        
        try:
            # Rate limiting based on IP address
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            if rate_limiter.is_rate_limited(client_ip):
                error = 'Too many failed attempts. Please try again in 15 minutes.'
                return render_template('admin/login.html', error=error), 429
            
            data = request.get_json() if request.is_json else request.form
            if not data or not data.get('email') or not data.get('password'):
                error = 'Email and password required.'
                return render_template('admin/login.html', error=error)
            
            user = User.query.filter_by(email=data['email'], active=True).first()
            if not user or not secure_hasher.verify_password(data['password'], user.password):
                # Record failed attempt for rate limiting
                rate_limiter.record_login_attempt(client_ip)
                error = 'Invalid credentials.'
                return render_template('admin/login.html', error=error)
            
            # Update login tracking
            user.last_login_at = user.current_login_at
            user.last_login_ip = user.current_login_ip
            user.current_login_at = datetime.utcnow()
            user.current_login_ip = client_ip
            user.login_count = (user.login_count or 0) + 1
            db.session.commit()
            
            # Log the user in
            login_user(user, remember=True)
            logger.info(f"User logged in: {user.email}")
            
            # Handle JSON vs form requests
            if request.is_json:
                return jsonify({'success': True, 'redirect': url_for('admin.dashboard')})
            else:
                return redirect(url_for('admin.dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            error = 'An error occurred during login. Please try again.'
            return render_template('admin/login.html', error=error), 500
    
    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        """Main logout endpoint"""
        logout_user()
        return redirect(url_for('login'))
    
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
    
    # Exempt API routes from CSRF protection
    from routes.pixie_routes import pixie_bp
    from routes.api_routes import api_bp  
    from routes.glossary_routes import glossary_bp
    
    csrf.exempt(pixie_bp)
    csrf.exempt(api_bp)
    csrf.exempt(glossary_bp)
    
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