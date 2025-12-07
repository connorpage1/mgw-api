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
        """Validate OAuth2 access token with auth service using /api/validate_token endpoint"""
        try:
            response = requests.post(
                f"{self.auth_service_url}/api/validate_token",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
                logger.warning(f"Token validation failed: {response.status_code}, {error_data}")
                return {'valid': False, 'error': error_data.get('error', 'Token validation failed')}
                
        except requests.exceptions.Timeout:
            logger.error("Auth service timeout")
            return {'valid': False, 'error': 'Auth service timeout'}
        except requests.exceptions.RequestException as e:
            logger.error(f"Auth service request failed: {e}")
            return {'valid': False, 'error': 'Auth service unavailable'}
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
    
    def get_user_permissions(self, token, app_name="mardi_gras_admin"):
        """Get user permissions for a specific app"""
        user_data = self.validate_token(token)
        if not user_data or not user_data.get("valid"):
            return None
        return user_data.get("app_roles", {}).get(app_name, [])

def require_oauth2(permissions=None):
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
            
            # Check permissions if required
            if permissions:
                user_permissions = oauth2_service.get_user_permissions(token)
                if not user_permissions or not any(p in user_permissions for p in permissions):
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user context to request
            request.oauth2_user = validation_result
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Convenience decorator for admin endpoints
require_admin = require_oauth2(['admin', 'admin_read'])