"""
Authentication routes for login, logout, and JWT management
"""
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session, current_app, abort
from flask_jwt_extended import jwt_required, get_jwt, create_access_token, create_refresh_token, get_jwt_identity
from flask_login import login_user, logout_user, current_user
from datetime import datetime, timedelta
import os
from models import db, User
from services.auth_service import secure_hasher, rate_limiter
from utils.logger import logger

auth_bp = Blueprint('auth', __name__)

# JWT Blacklist (in production, use Redis or database)
blacklisted_tokens = set()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page and handler"""
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('email', '').strip()  # Using email field name from form
            password = request.form.get('password', '')
            
            if not username or not password:
                flash('Username and password are required', 'error')
                return render_template('admin/login.html')
            
            # Find user by email
            user = User.query.filter_by(email=username).first()
            
            if user and user.active and secure_hasher.verify_password(password, user.password):
                if user.has_role('admin') or user.has_role('superadmin'):
                    login_user(user)
                    flash(f'Welcome back, {user.display_name}!', 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('admin.dashboard'))
                else:
                    flash('Admin access required', 'error')
            else:
                flash('Invalid username or password', 'error')
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login failed. Please try again.', 'error')
    
    return render_template('admin/login.html')

@auth_bp.route('/debug-csrf', methods=['GET'])
def debug_csrf():
    """Debug route to check CSRF configuration (only in development)"""
    if not current_app.debug and not os.environ.get('RAILWAY_ENVIRONMENT_NAME'):
        abort(404)
    
    from flask_wtf.csrf import generate_csrf
    
    debug_info = {
        'csrf_token': generate_csrf(),
        'session_keys': list(session.keys()),
        'environment': os.environ.get('FLASK_ENV', 'unknown'),
        'railway_env': os.environ.get('RAILWAY_ENVIRONMENT_NAME'),
        'csrf_config': {
            'WTF_CSRF_SSL_STRICT': current_app.config.get('WTF_CSRF_SSL_STRICT'),
            'WTF_CSRF_TIME_LIMIT': current_app.config.get('WTF_CSRF_TIME_LIMIT'),
            'SECRET_KEY_SET': bool(current_app.config.get('SECRET_KEY')),
        },
        'request_info': {
            'is_secure': request.is_secure,
            'scheme': request.scheme,
            'host': request.host,
            'referrer': request.referrer,
        }
    }
    
    return jsonify(debug_info)

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