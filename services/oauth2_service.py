"""
OAuth2 service for validating tokens from the mardi-gras-auth service
"""
import requests
from functools import wraps
from flask import request, jsonify, current_app, g
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
            
            token = auth_header.split(' ', 1)[1]
            oauth2_service = current_app.oauth2_service
            
            validation_result = oauth2_service.validate_token(token)
            
            if not validation_result.get('valid'):
                error_message = validation_result.get('error', 'Invalid token')
                # Enhanced security logging
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                user_agent = request.headers.get('User-Agent', 'Unknown')
                endpoint = request.endpoint
                logger.warning(
                    f"Authentication failure - IP: {client_ip}, "
                    f"Endpoint: {endpoint}, UA: {user_agent}, "
                    f"Error: {error_message}"
                )
                return jsonify({'error': 'Authentication failed'}), 401
            
            # Check permissions if required
            if permissions:
                user_permissions = oauth2_service.get_user_permissions(token)
                if not user_permissions or not any(p in user_permissions for p in permissions):
                    return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user context to request
            g.oauth2_user = validation_result
            request.oauth2_user = validation_result
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_oauth2_if_enabled(config_key, permissions=None):
    """Require OAuth2 only when the given app config flag is enabled."""
    def decorator(f):
        protected_view = require_oauth2(permissions)(f)

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_app.config.get(config_key, False):
                return f(*args, **kwargs)
            return protected_view(*args, **kwargs)

        return decorated_function

    return decorator

# Convenience decorator for admin endpoints
require_admin = require_oauth2(['admin', 'admin_read'])
