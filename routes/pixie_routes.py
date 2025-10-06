"""
Pixie viewer API routes for authentication and file access
"""
from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, create_access_token, create_refresh_token, get_jwt_identity
from datetime import datetime, timedelta
import os
from models import db, User, STLFile
from services.auth_service import secure_hasher, rate_limiter
from utils.logger import logger

pixie_bp = Blueprint('pixie', __name__)

@pixie_bp.route('/api/auth/login', methods=['POST'])
def pixie_api_login():
    """JWT-based login endpoint for Pixie viewer"""
    try:
        # Rate limiting based on IP address
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if rate_limiter.is_rate_limited(client_ip):
            return jsonify({
                'success': False,
                'error': 'Rate Limited',
                'message': 'Too many failed attempts. Please try again in 15 minutes.',
                'code': 'RATE_LIMITED'
            }), 429
        
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({
                'success': False,
                'error': 'Missing Credentials',
                'message': 'Username and password are required.',
                'code': 'MISSING_CREDENTIALS'
            }), 400
        
        # Try to find user by email (username field)
        user = User.query.filter_by(email=data['username'], active=True).first()
        if not user or not secure_hasher.verify_password(data['password'], user.password):
            # Record failed attempt for rate limiting
            rate_limiter.record_login_attempt(client_ip)
            return jsonify({
                'success': False,
                'error': 'Invalid Credentials',
                'message': 'The username or password you entered is incorrect.',
                'code': 'INVALID_CREDENTIALS'
            }), 401
        
        # Update login tracking
        user.last_login = datetime.utcnow()
        user.login_count = (user.login_count or 0) + 1
        db.session.commit()
        
        # Create JWT tokens
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(hours=8)  # 8 hour sessions for Pixie viewer
        )
        refresh_token = create_refresh_token(
            identity=user.id,
            expires_delta=timedelta(days=7)  # 7 day refresh
        )
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'role': user.role
            },
            'expires_in': 8 * 60 * 60  # 8 hours in seconds
        })
        
    except Exception as e:
        logger.error(f"Error in pixie API login: {e}")
        return jsonify({
            'success': False,
            'error': 'System Error',
            'message': 'An unexpected error occurred. Please try again.',
            'code': 'SYSTEM_ERROR'
        }), 500

@pixie_bp.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def pixie_api_refresh():
    """Refresh JWT token for Pixie viewer"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.active:
            return jsonify({
                'success': False,
                'error': 'User Not Found',
                'message': 'User account is not active or does not exist.',
                'code': 'USER_INACTIVE'
            }), 401
        
        # Create new access token
        access_token = create_access_token(
            identity=user.id,
            expires_delta=timedelta(hours=8)
        )
        
        return jsonify({
            'success': True,
            'access_token': access_token,
            'expires_in': 8 * 60 * 60
        })
        
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        return jsonify({
            'success': False,
            'error': 'Token Refresh Failed',
            'message': 'Unable to refresh authentication token.',
            'code': 'REFRESH_FAILED'
        }), 500

@pixie_bp.route('/api/auth/verify', methods=['GET'])
@jwt_required()
def pixie_api_verify():
    """Verify JWT token and return user info"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.active:
            return jsonify({
                'success': False,
                'error': 'User Not Found',
                'message': 'User account is not active or does not exist.',
                'code': 'USER_INACTIVE'
            }), 401
        
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'role': user.role
            },
            'authenticated': True
        })
        
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return jsonify({
            'success': False,
            'error': 'Token Verification Failed',
            'message': 'Unable to verify authentication token.',
            'code': 'VERIFICATION_FAILED'
        }), 500

@pixie_bp.route('/api/featured', methods=['GET'])
def pixie_api_featured():
    """Public API: Get featured STL file for Pixie tourist viewer"""
    try:
        # Get the featured STL file
        featured_file = STLFile.query.filter_by(is_featured=True).first()
        
        if not featured_file:
            return jsonify({
                'message': 'No featured project available',
                'featured': None
            })
        
        # Update view count
        featured_file.view_count = (featured_file.view_count or 0) + 1
        featured_file.last_viewed = datetime.utcnow()
        db.session.commit()
        
        # Generate download URL
        download_url = f"/pixie/api/download/stl/{featured_file.id}"
        
        return jsonify({
            'featured': {
                'id': featured_file.id,
                'filename': featured_file.original_filename,
                'description': featured_file.description or "Featured CNC Creation",
                'size': featured_file.file_size,
                'upload_date': featured_file.upload_timestamp.isoformat(),
                'download_url': download_url,
                'screenshot_url': featured_file.get_screenshot_url(),
                'tags': featured_file.tags.split(',') if featured_file.tags else [],
                'view_count': featured_file.view_count
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting featured file: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@pixie_bp.route('/api/past-projects', methods=['GET'])
def pixie_api_past_projects():
    """Public API: Get recent STL files for browsing past projects"""
    try:
        # Get recent STL files (last 10)
        past_files = STLFile.query.order_by(STLFile.upload_timestamp.desc()).limit(10).all()
        
        projects = []
        for file in past_files:
            # Generate download URL
            download_url = f"/pixie/api/download/stl/{file.id}"
            
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

@pixie_bp.route('/api/download/stl/<file_id>', methods=['GET'])
@jwt_required(optional=True)
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