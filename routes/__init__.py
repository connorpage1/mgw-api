"""
Route handlers for the Mardi Gras API
"""
from flask import Blueprint

# Import all route blueprints
from .api_routes import api_bp
from .customer_routes import customer_bp
from .glossary_routes import glossary_bp
from .file_routes import file_bp
from .pixie_routes import pixie_bp
from .tour_eval_routes import tour_eval_bp

def register_routes(app):
    """Register all route blueprints with the Flask app"""
    
    # Main API routes
    app.register_blueprint(api_bp, url_prefix='/api')

    # Tour evaluation routes
    app.register_blueprint(tour_eval_bp, url_prefix='/api')

    # Customer data routes
    app.register_blueprint(customer_bp, url_prefix='/api/customers')
    
    # Public glossary routes
    app.register_blueprint(glossary_bp, url_prefix='/glossary')
    
    # File management routes
    app.register_blueprint(file_bp, url_prefix='/files')
    
    # Pixie viewer API routes
    app.register_blueprint(pixie_bp, url_prefix='/pixie')

__all__ = ['register_routes']
