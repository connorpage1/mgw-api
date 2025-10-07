"""
API Token authentication service
"""
import hashlib
from functools import wraps
from flask import request, jsonify, g
from models import AppToken, App
from utils.logger import logger

def validate_api_token(token):
    """
    Validate an API token and return the associated app if valid
    
    Args:
        token (str): The API token to validate
        
    Returns:
        tuple: (is_valid, app_instance, token_instance)
    """
    if not token:
        return False, None, None
    
    # Hash the provided token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Find the token in database
    app_token = AppToken.query.filter_by(token_hash=token_hash, active=True).first()
    
    if not app_token:
        return False, None, None
    
    # Check if the associated app is active
    if not app_token.app.active:
        return False, None, None
    
    # Update usage statistics
    from datetime import datetime
    app_token.last_used_at = datetime.utcnow()
    app_token.last_used_ip = request.remote_addr
    app_token.usage_count += 1
    
    # Commit the usage tracking update
    from models import db
    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"Error updating token usage: {e}")
        db.session.rollback()
    
    return True, app_token.app, app_token

def api_token_required(f):
    """
    Decorator to require valid API token for endpoints
    
    Looks for token in:
    1. Authorization header: Bearer <token>
    2. X-API-Key header: <token>
    3. Query parameter: ?api_key=<token>
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check Authorization header (Bearer token)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Check X-API-Key header
        elif request.headers.get('X-API-Key'):
            token = request.headers.get('X-API-Key')
        
        # Check query parameter
        elif request.args.get('api_key'):
            token = request.args.get('api_key')
        
        if not token:
            return jsonify({
                'error': 'Authentication required',
                'message': 'API token must be provided via Authorization header (Bearer token), X-API-Key header, or api_key query parameter'
            }), 401
        
        # Validate token
        is_valid, app, app_token = validate_api_token(token)
        
        if not is_valid:
            return jsonify({
                'error': 'Invalid token',
                'message': 'The provided API token is invalid or has been revoked'
            }), 401
        
        # Store app info in Flask's g context for use in the endpoint
        g.current_app = app
        g.current_token = app_token
        
        return f(*args, **kwargs)
    
    return decorated_function