"""
OAuth2 Migration Example for Mardi Gras API

This file demonstrates how to replace JWT authentication with OAuth2 SSO authentication
using the services/oauth2_service.py middleware.

Before Migration (JWT):
    @app.route('/admin/terms', methods=['POST'])
    @jwt_required()
    def admin_create_term():
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        # ... rest of function

After Migration (OAuth2):
    @app.route('/admin/terms', methods=['POST'])
    @require_oauth2(["admin", "terms_write"])
    def admin_create_term():
        user = get_current_user()  # from g.current_user
        # ... rest of function

Key Changes:
1. Replace @jwt_required() with @require_oauth2()
2. Replace get_jwt_identity() with get_current_user()
3. Add permission-based authorization
4. Remove local User model dependency
5. Use centralized SSO authentication
"""

from flask import Flask, request, jsonify, g
from services.oauth2_service import (
    require_oauth2, 
    require_oauth2_optional,
    get_current_user,
    get_user_permissions,
    check_user_permission,
    is_admin,
    is_superadmin
)

app = Flask(__name__)

# =============================================================================
# MIGRATION EXAMPLES
# =============================================================================

# Example 1: Basic protected route
# BEFORE (JWT):
"""
@app.route('/auth/logout', methods=['POST'])
@jwt_required()
def secure_logout():
    from flask_jwt_extended import get_jwt
    jti = get_jwt()['jti']
    # ... logout logic
"""

# AFTER (OAuth2):
@app.route('/auth/logout', methods=['POST'])
@require_oauth2()  # Just require authentication, no specific permissions
def secure_logout():
    """OAuth2 logout - revoke token with auth service"""
    user = get_current_user()
    # Token revocation handled by auth service
    return jsonify({"message": "Logged out successfully"})


# Example 2: Admin route with permission check
# BEFORE (JWT):
"""
@app.route('/admin/terms', methods=['POST'])
@jwt_required()
def admin_create_term():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    # ... create term logic
"""

# AFTER (OAuth2):
@app.route('/admin/terms', methods=['POST'])
@require_oauth2(["admin", "terms_write"])  # Require admin OR terms_write permission
def admin_create_term():
    """Admin: Create new term with OAuth2 authentication"""
    user = get_current_user()  # User data from auth service
    
    # Permission already checked by decorator
    data = request.get_json()
    
    # Create term logic here
    return jsonify({
        "message": "Term created successfully",
        "created_by": user.get("email")
    })


# Example 3: Optional authentication
# BEFORE (JWT):
"""
@app.route('/glossary/stats', methods=['GET'])
@jwt_required(optional=True)
def api_stats():
    user_id = get_jwt_identity()
    user = User.query.get(user_id) if user_id else None
    
    # Different behavior based on authentication
    if user:
        # Return detailed stats for authenticated users
        pass
    else:
        # Return basic stats for public
        pass
"""

# AFTER (OAuth2):
@app.route('/glossary/stats', methods=['GET'])
@require_oauth2_optional()  # Optional authentication
def api_stats():
    """Get API statistics - different data based on auth status"""
    user = get_current_user()  # None if not authenticated
    
    if user:
        # Return detailed stats for authenticated users
        return jsonify({
            "detailed_stats": True,
            "user_email": user.get("email"),
            "total_terms": 150,
            "user_contributions": 25
        })
    else:
        # Return basic stats for public
        return jsonify({
            "total_terms": 150,
            "public_stats": True
        })


# Example 4: App-specific permissions
@app.route('/admin/files', methods=['GET'])
@require_oauth2(["files_read"], app_name="mardi_gras_api")
def admin_get_files():
    """Get files - requires files_read permission in mardi_gras_api app"""
    user = get_current_user()
    
    return jsonify({
        "files": [],
        "user_permissions": get_user_permissions("mardi_gras_api")
    })


# Example 5: Multiple app permissions
@app.route('/admin/cross-app-data', methods=['GET'])
@require_oauth2(["admin"])  # Global admin required
def get_cross_app_data():
    """Access data across multiple apps - requires global admin"""
    user = get_current_user()
    
    # Check specific app permissions within the function
    pixie_perms = get_user_permissions("pixie_viewer")
    admin_perms = get_user_permissions("mardi_gras_admin")
    
    return jsonify({
        "pixie_permissions": pixie_perms,
        "admin_permissions": admin_perms,
        "is_superadmin": is_superadmin()
    })


# Example 6: Conditional permission checks
@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@require_oauth2()  # Basic auth required, detailed perms checked inside
def update_user(user_id):
    """Update user with conditional permission checks"""
    current_user = get_current_user()
    
    # Superadmins can edit anyone
    if is_superadmin():
        pass
    # Users can only edit themselves
    elif current_user.get("id") == user_id:
        pass
    # App admins can edit users in their apps
    elif check_user_permission("admin", "mardi_gras_admin"):
        pass
    else:
        return jsonify({"error": "Permission denied"}), 403
    
    # Update logic here
    return jsonify({"message": "User updated successfully"})


# =============================================================================
# ENVIRONMENT CONFIGURATION
# =============================================================================

# Add this to your app.py configuration section:
"""
# OAuth2 Configuration (add to existing config)
import os

# Auth service URL for token validation
AUTH_SERVICE_URL = os.environ.get('AUTH_SERVICE_URL', 'http://localhost:5559')

# CORS origins - update to include auth service
ALLOWED_ORIGINS = os.environ.get('CORS_ORIGINS', 
    'http://localhost:3000,http://localhost:3001,http://localhost:5559').split(',')

# Update CORS to allow auth service
cors = CORS(app, 
    origins=ALLOWED_ORIGINS,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    supports_credentials=True
)
"""

# =============================================================================
# STEP-BY-STEP MIGRATION PROCESS
# =============================================================================

"""
Step 1: Add OAuth2 service
1. Copy services/oauth2_service.py to your project
2. Add 'requests==2.31.0' to requirements.txt
3. Set AUTH_SERVICE_URL environment variable

Step 2: Update imports in app.py
# Remove these JWT imports:
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token

# Add these OAuth2 imports:
from services.oauth2_service import (
    require_oauth2, 
    require_oauth2_optional,
    get_current_user,
    is_admin,
    is_superadmin
)

Step 3: Replace decorators
Find and replace patterns:
- @jwt_required() → @require_oauth2()
- @jwt_required(optional=True) → @require_oauth2_optional()

Step 4: Replace user access patterns
- get_jwt_identity() → get_current_user()
- User.query.get(user_id) → get_current_user() (user data comes from auth service)

Step 5: Update permission checks
Replace local permission checks with OAuth2 permission system:
- user.is_admin → is_admin() or check_user_permission("admin")
- Custom role checks → check_user_permission("specific_permission")

Step 6: Environment variables
Set these environment variables:
- AUTH_SERVICE_URL=http://localhost:5559 (or production auth service URL)
- CORS_ORIGINS=http://localhost:3001,http://localhost:5559 (include auth service)

Step 7: Remove JWT configuration
Remove or comment out JWT configuration:
# app.config['JWT_SECRET_KEY'] = ...
# jwt = JWTManager(app)

Step 8: Test the migration
1. Start auth service
2. Start API service
3. Test OAuth2 flow with React admin
4. Verify permissions work correctly
"""

# =============================================================================
# PERMISSION MAPPING
# =============================================================================

"""
Map your existing permission checks to OAuth2 app-specific roles:

Existing Check                     →  OAuth2 Permission
user.is_admin                     →  check_user_permission("admin")
user.can_edit_terms               →  check_user_permission("terms_write")
user.can_view_files               →  check_user_permission("files_read")
user.can_upload_files             →  check_user_permission("files_write")
user.is_superuser                 →  is_superadmin()

App-specific permissions are defined in the auth service:
- mardi_gras_api: admin, terms_read, terms_write, files_read, files_write
- mardi_gras_admin: admin, users_read, users_write
- pixie_viewer: admin, files_read
"""

if __name__ == "__main__":
    print("This is a migration example file.")
    print("Copy the patterns above to update your app.py file.")
    print("See the step-by-step process at the bottom of this file.")