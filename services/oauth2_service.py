"""
OAuth2 service for validating tokens from the mardi-gras-auth service
"""
import requests
import jwt
from functools import wraps
from flask import request, jsonify, current_app
from utils.logger import logger

class OAuth2Service:
    """Service for OAuth2 token validation"""
    
    def __init__(self, auth_service_url, jwt_secret_key):
        self.auth_service_url = auth_service_url.rstrip('/')
        self.jwt_secret_key = jwt_secret_key
    
    def validate_token(self, token):
        """Validate OAuth2 access token with auth service"""
        try:
            # Try to decode JWT token locally first
            payload = jwt.decode(token, self.jwt_secret_key, algorithms=['HS256'])
            return {
                'valid': True,
                'user_id': payload.get('sub'),
                'app_id': payload.get('app_id'),
                'scopes': payload.get('scopes', []),
                'exp': payload.get('exp')
            }
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return {'valid': False, 'error': 'Token expired'}
        except jwt.InvalidTokenError:
            logger.warning("Invalid token format")
            return {'valid': False, 'error': 'Invalid token'}
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return {'valid': False, 'error': 'Token validation failed'}
    
    def introspect_token(self, token):
        """Introspect token with auth service for detailed info"""
        try:
            response = requests.post(
                f"{self.auth_service_url}/oauth/introspect",
                data={'token': token},
                timeout=5
            )
            return response.json() if response.status_code == 200 else {'active': False}
        except Exception as e:
            logger.error(f"Token introspection failed: {e}")
            return {'active': False}

def require_oauth2(scopes=None):
    """Decorator to require OAuth2 authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            oauth2_service = current_app.oauth2_service
            
            validation_result = oauth2_service.validate_token(token)
            
            if not validation_result.get('valid'):
                return jsonify({'error': validation_result.get('error', 'Invalid token')}), 401
            
            # Check scopes if required
            if scopes:
                token_scopes = validation_result.get('scopes', [])
                if not any(scope in token_scopes for scope in scopes):
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user context to request
            request.oauth2_user = validation_result
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Convenience decorator for admin endpoints
require_admin = require_oauth2(['admin'])