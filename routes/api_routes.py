"""
Main API routes for CRUD operations
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Term, Category, STLFile
from utils.logger import logger

api_bp = Blueprint('api', __name__)

@api_bp.route('/health')
def health_check():
    """API health check endpoint"""
    return jsonify({
        'status': 'ok',
        'service': 'mardi-gras-api',
        'version': '2.0.0'
    })

# Additional API routes for CRUD operations would be implemented here
# For brevity, including just the health check
# The full implementation would include:
# - User management
# - Term CRUD
# - Category CRUD  
# - File management
# - etc.