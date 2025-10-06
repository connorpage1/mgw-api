"""
Route handlers for the Mardi Gras API
"""
from flask import Blueprint

# Import all route blueprints
from .auth_routes import auth_bp
from .admin_routes import admin_bp
from .api_routes import api_bp
from .glossary_routes import glossary_bp
from .file_routes import file_bp
from .pixie_routes import pixie_bp

def register_routes(app):
    """Register all route blueprints with the Flask app"""
    
    # Authentication routes
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    # Admin interface routes
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    # Main API routes
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Public glossary routes
    app.register_blueprint(glossary_bp, url_prefix='/glossary')
    
    # File management routes
    app.register_blueprint(file_bp, url_prefix='/files')
    
    # Pixie viewer API routes
    app.register_blueprint(pixie_bp, url_prefix='/pixie')

__all__ = ['register_routes']