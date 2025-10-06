"""
Authentication routes for login, logout, and JWT management
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt, create_access_token, create_refresh_token, get_jwt_identity
from datetime import datetime, timedelta
from models import db, User
from services.auth_service import secure_hasher, rate_limiter
from utils.logger import logger

auth_bp = Blueprint('auth', __name__)

# JWT Blacklist (in production, use Redis or database)
blacklisted_tokens = set()

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def secure_logout():
    """Secure logout - blacklist the JWT token"""
    try:
        jti = get_jwt()['jti']
        blacklisted_tokens.add(jti)
        return jsonify({'message': 'Successfully logged out'})
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500