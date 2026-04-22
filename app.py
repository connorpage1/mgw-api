"""
Mardi Gras API - Pure API Service.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail
from sqlalchemy import text
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime, timezone
import os

# Rate limiting (optional, falls back gracefully if not available)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

# Import configuration and utilities
from config import get_config
from utils.logger import logger

# Import models and services
from models import db
from services.oauth2_service import OAuth2Service
from services.tour_eval_service import seed_default_tour_eval_catalog

# Import route blueprints
from routes import register_routes

def create_app(config_name=None):
    """Application factory pattern."""
    app = Flask(__name__)

    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    config_class = get_config(config_name)
    app.config.from_object(config_class)
    config_class.init_app(app)

    # Handle reverse proxies in production deployments
    if app.config.get('TRUST_PROXY_FIX'):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize extensions
    db.init_app(app)

    # Initialize rate limiting (if available)
    if LIMITER_AVAILABLE:
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=["1000 per hour", "100 per minute"],
            storage_uri="memory://"
        )
        app.limiter = limiter
        logger.info("Rate limiting enabled")
    else:
        app.limiter = None
        logger.warning("Rate limiting not available - install Flask-Limiter for production")

    # Initialize OAuth2 service
    app.oauth2_service = OAuth2Service(
        auth_service_url=app.config.get('AUTH_SERVICE_URL', 'https://auth.mardigrasworld.com'),
        jwt_secret_key=app.config.get('JWT_SECRET_KEY')
    )

    # CORS Configuration
    CORS(
        app,
        origins=app.config['ALLOWED_ORIGINS'],
        supports_credentials=True,
        resources={
            r"/pixie/api/*": {
                "origins": app.config['ALLOWED_ORIGINS'],
                "supports_credentials": True,
            },
            r"/api/*": {
                "origins": app.config['ALLOWED_ORIGINS'],
                "supports_credentials": True,
            },
            r"/*": {
                "origins": app.config['ALLOWED_ORIGINS'],
                "supports_credentials": True,
            },
        },
    )

    # Mail Configuration (for notifications only)
    Mail(app)

    # Template filters
    @app.template_filter('strftime')
    def strftime_filter(dt, format='%Y-%m-%d'):
        """Format datetime for templates."""
        if dt is None:
            return ""
        return dt.strftime(format)

    # Security headers
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        for header, value in app.config['SECURITY_HEADERS'].items():
            response.headers[header] = value
        return response

    # Error handlers
    @app.errorhandler(RequestEntityTooLarge)
    def handle_request_too_large(e):
        """Return a JSON response for oversized uploads."""
        max_size_mb = app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)
        return jsonify({
            'error': 'Payload Too Large',
            'message': f'Uploaded files must be smaller than {max_size_mb} MB',
        }), 413

    @app.errorhandler(400)
    def handle_bad_request(e):
        """Handle 400 Bad Request errors."""
        # Enhanced CSRF error handling
        error_description = str(e)
        is_csrf_error = 'CSRF' in error_description or 'csrf' in error_description.lower()

        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Bad Request',
                'message': error_description,
                'csrf_error': is_csrf_error,
            }), 400

        # For web forms, provide more helpful error info in development
        if app.debug and is_csrf_error:
            logger.warning(f"CSRF Error: {error_description} for {request.path}")
            logger.warning(f"Request headers: {dict(request.headers)}")
            logger.warning(f"Form data: {request.form}")

        return jsonify({'error': 'Bad Request', 'message': error_description}), 400

    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle 404 Not Found errors."""
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Not Found', 'message': 'Resource not found'}), 404
        return jsonify({'error': 'Not Found', 'message': 'Resource not found'}), 404

    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle 500 Internal Server errors."""
        logger.exception("Internal server error")
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
        return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500

    def _database_health():
        """Run a lightweight database readiness check."""
        try:
            db.session.execute(text("SELECT 1"))
            return {'status': 'ok'}
        except Exception:
            db.session.rollback()
            logger.exception("Database health check failed")
            return {'status': 'error', 'message': 'database unavailable'}

    # Main routes
    @app.route('/')
    def index():
        """Main application index."""
        return jsonify({
            'service': app.config['APP_NAME'],
            'version': app.config['APP_VERSION'],
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
        """Main health check endpoint."""
        database = _database_health()
        status_code = 200 if database['status'] == 'ok' else 503
        return jsonify({
            'status': 'ok' if status_code == 200 else 'degraded',
            'service': app.config['APP_NAME'],
            'version': app.config['APP_VERSION'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'checks': {
                'database': database,
            },
        }), status_code
    # Register all route blueprints
    register_routes(app)

    # All routes are now API routes - no CSRF needed

    # Optional database initialization for local/dev bootstrapping
    with app.app_context():
        try:
            if app.config.get('AUTO_INIT_DB'):
                db.create_all()
                logger.info("Database tables created successfully")
            else:
                logger.info("Skipping automatic database initialization")

            if app.config.get('AUTO_SEED_TOUR_EVAL'):
                seed_default_tour_eval_catalog()
                logger.info("Tour evaluation catalog seeded successfully")
            else:
                logger.info("Skipping automatic tour evaluation seeding")
        except Exception as e:
            logger.error(f"Startup initialization error: {e}")

    return app

# Create the Flask application
app = create_app()

if __name__ == '__main__':
    logger.info("Starting Mardi Gras API server...")

    # Debug configuration
    debug_mode = app.config.get('DEBUG', False)
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