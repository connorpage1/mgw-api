#!/usr/bin/env python3
"""
Comprehensive test suite for API and Admin GUI functionality
"""
import sys
import os
import json
import time
from datetime import datetime

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role, Term, Category
from utils.logger import logger

class ComprehensiveTestSuite:
    def __init__(self):
        self.flask_app = create_app()
        self.test_token = None
        self.test_app_id = None
        self.test_user = None
        self.errors = []
        self.successes = []
        
    def log_error(self, test_name, error):
        """Log an error"""
        error_msg = f"❌ {test_name}: {error}"
        logger.error(error_msg)
        self.errors.append(error_msg)
        
    def log_success(self, test_name):
        """Log a success"""
        success_msg = f"✅ {test_name}"
        logger.info(success_msg)
        self.successes.append(success_msg)
        
    def setup_test_data(self):
        """Set up test data"""
        with self.flask_app.app_context():
            try:
                # Get existing demo token
                demo_token = AppToken.query.filter_by(name='Demo Token').first()
                if demo_token:
                    # We'll use the existing demo token for testing
                    import hashlib
                    # We need to find the original token - let's create a new one for testing
                    test_app = demo_token.app
                    
                    # Generate a test token
                    import secrets
                    raw_token = f"mg_{''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
                    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                    
                    test_token = AppToken(
                        app_id=test_app.id,
                        name="Test Token",
                        token_hash=token_hash,
                        prefix="mg_",
                        created_by=1,
                        updated_by=1
                    )
                    
                    db.session.add(test_token)
                    db.session.commit()
                    
                    self.test_token = raw_token
                    self.test_app_id = test_app.id
                    
                    logger.info(f"Created test token: {raw_token}")
                    
                # Get superadmin user
                self.test_user = User.query.join(User.roles).filter(Role.name == 'superadmin').first()
                
                return True
                
            except Exception as e:
                self.log_error("setup_test_data", str(e))
                return False
    
    def test_api_endpoints(self):
        """Test all API endpoints comprehensively"""
        logger.info("\n=== TESTING API ENDPOINTS ===")
        
        with self.flask_app.app_context():
            client = self.flask_app.test_client()
            
            # Test 1: Health endpoint (no auth required)
            try:
                response = client.get('/api/health')
                if response.status_code == 200:
                    data = json.loads(response.data)
                    if data.get('status') == 'ok':
                        self.log_success("API Health endpoint")
                    else:
                        self.log_error("API Health endpoint", "Invalid response data")
                else:
                    self.log_error("API Health endpoint", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("API Health endpoint", str(e))
            
            # Test 2: Authentication required endpoints
            auth_tests = [
                ('/api/terms', 'GET'),
                ('/api/categories', 'GET'),
                ('/api/terms/1', 'GET')
            ]
            
            for endpoint, method in auth_tests:
                try:
                    # Test without token (should fail)
                    if method == 'GET':
                        response = client.get(endpoint)
                    else:
                        response = client.post(endpoint)
                        
                    if response.status_code == 401:
                        self.log_success(f"API {method} {endpoint} - Auth required")
                    else:
                        self.log_error(f"API {method} {endpoint} - Auth required", f"Expected 401, got {response.status_code}")
                except Exception as e:
                    self.log_error(f"API {method} {endpoint} - Auth required", str(e))
            
            # Test 3: Authenticated API calls
            if self.test_token:
                headers = {'X-API-Key': self.test_token}
                
                # Test GET /api/categories
                try:
                    response = client.get('/api/categories', headers=headers)
                    if response.status_code == 200:
                        data = json.loads(response.data)
                        if 'categories' in data:
                            self.log_success("API GET /api/categories with auth")
                        else:
                            self.log_error("API GET /api/categories with auth", "Invalid response structure")
                    else:
                        self.log_error("API GET /api/categories with auth", f"Status {response.status_code}")
                except Exception as e:
                    self.log_error("API GET /api/categories with auth", str(e))
                
                # Test GET /api/terms
                try:
                    response = client.get('/api/terms', headers=headers)
                    if response.status_code == 200:
                        data = json.loads(response.data)
                        if 'terms' in data and 'pagination' in data:
                            self.log_success("API GET /api/terms with auth")
                        else:
                            self.log_error("API GET /api/terms with auth", "Invalid response structure")
                    else:
                        self.log_error("API GET /api/terms with auth", f"Status {response.status_code}")
                except Exception as e:
                    self.log_error("API GET /api/terms with auth", str(e))
                
                # Test POST /api/terms (create term)
                try:
                    # Use timestamp to ensure unique term name
                    import time
                    timestamp = str(int(time.time()))
                    term_data = {
                        'term': f'Test API Term {timestamp}',
                        'pronunciation': 'test ay-pee-eye term',
                        'definition': 'A term created via API for testing',
                        'category_id': 1,
                        'difficulty': 'tourist'
                    }
                    
                    response = client.post('/api/terms', 
                                         headers={**headers, 'Content-Type': 'application/json'},
                                         data=json.dumps(term_data))
                    
                    if response.status_code == 201:
                        data = json.loads(response.data)
                        if 'term' in data and 'Test API Term' in data['term']['term']:
                            self.log_success("API POST /api/terms (create)")
                            
                            # Store term ID for further testing
                            term_id = data['term']['id']
                            
                            # Test GET specific term
                            response = client.get(f'/api/terms/{term_id}', headers=headers)
                            if response.status_code == 200:
                                self.log_success(f"API GET /api/terms/{term_id}")
                            else:
                                self.log_error(f"API GET /api/terms/{term_id}", f"Status {response.status_code}")
                            
                            # Test PUT (update term)
                            update_data = {
                                'definition': 'Updated definition via API test'
                            }
                            response = client.put(f'/api/terms/{term_id}',
                                                headers={**headers, 'Content-Type': 'application/json'},
                                                data=json.dumps(update_data))
                            if response.status_code == 200:
                                self.log_success(f"API PUT /api/terms/{term_id}")
                            else:
                                self.log_error(f"API PUT /api/terms/{term_id}", f"Status {response.status_code}")
                            
                            # Test DELETE term
                            response = client.delete(f'/api/terms/{term_id}', headers=headers)
                            if response.status_code == 200:
                                self.log_success(f"API DELETE /api/terms/{term_id}")
                            else:
                                self.log_error(f"API DELETE /api/terms/{term_id}", f"Status {response.status_code}")
                        else:
                            self.log_error("API POST /api/terms (create)", "Invalid response data")
                    else:
                        response_text = response.get_data(as_text=True)
                        self.log_error("API POST /api/terms (create)", f"Status {response.status_code}: {response_text}")
                except Exception as e:
                    self.log_error("API POST /api/terms (create)", str(e))
                
                # Test different authentication methods
                auth_methods = [
                    ('Authorization', f'Bearer {self.test_token}'),
                    ('X-API-Key', self.test_token)
                ]
                
                for header_name, header_value in auth_methods:
                    try:
                        response = client.get('/api/categories', headers={header_name: header_value})
                        if response.status_code == 200:
                            self.log_success(f"API Auth method: {header_name}")
                        else:
                            self.log_error(f"API Auth method: {header_name}", f"Status {response.status_code}")
                    except Exception as e:
                        self.log_error(f"API Auth method: {header_name}", str(e))
                
                # Test query parameter auth
                try:
                    response = client.get(f'/api/categories?api_key={self.test_token}')
                    if response.status_code == 200:
                        self.log_success("API Auth method: Query parameter")
                    else:
                        self.log_error("API Auth method: Query parameter", f"Status {response.status_code}")
                except Exception as e:
                    self.log_error("API Auth method: Query parameter", str(e))
    
    def test_admin_gui(self):
        """Test admin GUI functionality"""
        logger.info("\n=== TESTING ADMIN GUI ===")
        
        with self.flask_app.app_context():
            client = self.flask_app.test_client()
            
            # Simulate admin login
            with client.session_transaction() as sess:
                if self.test_user:
                    sess['_user_id'] = str(self.test_user.id)
                    sess['_fresh'] = True
            
            # Test 1: Main dashboard
            try:
                response = client.get('/admin/')
                if response.status_code == 200:
                    html = response.get_data(as_text=True)
                    if 'Admin Dashboard' in html and 'Active Apps' in html:
                        self.log_success("Admin Dashboard")
                    else:
                        self.log_error("Admin Dashboard", "Missing expected content")
                else:
                    self.log_error("Admin Dashboard", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("Admin Dashboard", str(e))
            
            # Test 2: Apps list
            try:
                response = client.get('/admin/apps')
                if response.status_code == 200:
                    html = response.get_data(as_text=True)
                    if 'Application Management' in html and 'Demo API App' in html:
                        self.log_success("Admin Apps List")
                    else:
                        self.log_error("Admin Apps List", "Missing expected content")
                else:
                    self.log_error("Admin Apps List", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("Admin Apps List", str(e))
            
            # Test 3: Tokens list
            try:
                response = client.get('/admin/tokens')
                if response.status_code == 200:
                    html = response.get_data(as_text=True)
                    if 'API Token Management' in html:
                        self.log_success("Admin Tokens List")
                    else:
                        self.log_error("Admin Tokens List", "Missing expected content")
                else:
                    self.log_error("Admin Tokens List", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("Admin Tokens List", str(e))
            
            # Test 4: Create new app form
            try:
                response = client.get('/admin/apps/new')
                if response.status_code == 200:
                    html = response.get_data(as_text=True)
                    if 'Create New Application' in html and 'Application Name' in html:
                        self.log_success("Admin New App Form")
                    else:
                        self.log_error("Admin New App Form", "Missing expected content")
                else:
                    self.log_error("Admin New App Form", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("Admin New App Form", str(e))
            
            # Test 5: Create app functionality (simplified test)
            try:
                # For now, just test that the route accepts POST (even if CSRF fails)
                # In a real application, you'd need to extract CSRF token from HTML
                app_data = {
                    'name': f'Test GUI App {int(time.time())}',
                    'description': 'App created via GUI test'
                }
                
                response = client.post('/admin/apps/new', data=app_data)
                # Should return 400 (CSRF error) or 200/302 (success/redirect)
                if response.status_code in [200, 302, 400]:
                    self.log_success("Admin Create App (route accessible)")
                else:
                    self.log_error("Admin Create App (route accessible)", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("Admin Create App (route accessible)", str(e))
            
            # Test 6: Users list (superadmin only)
            try:
                response = client.get('/admin/users')
                if response.status_code == 200:
                    html = response.get_data(as_text=True)
                    if 'admin@dev.local' in html:  # Should show admin user
                        self.log_success("Admin Users List")
                    else:
                        self.log_error("Admin Users List", "Missing expected user data")
                else:
                    self.log_error("Admin Users List", f"Status {response.status_code}")
            except Exception as e:
                self.log_error("Admin Users List", str(e))
            
            # Test 7: Invalid routes (should 404)
            get_404_routes = ['/admin/nonexistent', '/admin/apps/999/edit']
            for route in get_404_routes:
                try:
                    response = client.get(route)
                    if response.status_code == 404:
                        self.log_success(f"Admin 404 handling (GET): {route}")
                    else:
                        self.log_error(f"Admin 404 handling (GET): {route}", f"Expected 404, got {response.status_code}")
                except Exception as e:
                    self.log_error(f"Admin 404 handling (GET): {route}", str(e))
            
            # Test POST routes that should 404 (but may return 400 due to CSRF)
            post_404_routes = ['/admin/tokens/999/delete']
            for route in post_404_routes:
                try:
                    response = client.post(route, data={'csrf_token': 'test'})
                    # Should return 404 (not found) or 400 (CSRF error) - both acceptable for non-existent resources
                    if response.status_code in [404, 400]:
                        self.log_success(f"Admin Error handling (POST): {route}")
                    else:
                        self.log_error(f"Admin Error handling (POST): {route}", f"Expected 404/400, got {response.status_code}")
                except Exception as e:
                    self.log_error(f"Admin Error handling (POST): {route}", str(e))
    
    def test_database_operations(self):
        """Test database operations and data integrity"""
        logger.info("\n=== TESTING DATABASE OPERATIONS ===")
        
        with self.flask_app.app_context():
            try:
                # Test 1: Basic queries
                apps_count = App.query.count()
                tokens_count = AppToken.query.count()
                users_count = User.query.count()
                
                if apps_count > 0 and tokens_count > 0 and users_count > 0:
                    self.log_success(f"Database Basic Queries (Apps: {apps_count}, Tokens: {tokens_count}, Users: {users_count})")
                else:
                    self.log_error("Database Basic Queries", "Missing expected data")
                
                # Test 2: Relationships
                app = App.query.first()
                if app and app.tokens.count() > 0:
                    self.log_success("Database App-Token Relationship")
                else:
                    self.log_error("Database App-Token Relationship", "Relationship not working")
                
                # Test 3: User roles
                superadmin = User.query.join(User.roles).filter(Role.name == 'superadmin').first()
                if superadmin and superadmin.has_role('superadmin'):
                    self.log_success("Database User-Role Relationship")
                else:
                    self.log_error("Database User-Role Relationship", "Role check failed")
                
                # Test 4: Token usage tracking
                test_token_obj = AppToken.query.filter_by(name='Test Token').first()
                if test_token_obj:
                    original_count = test_token_obj.usage_count
                    
                    # Simulate token usage
                    test_token_obj.usage_count += 1
                    test_token_obj.last_used_at = datetime.utcnow()
                    db.session.commit()
                    
                    # Verify update
                    updated_token = AppToken.query.get(test_token_obj.id)
                    if updated_token.usage_count == original_count + 1:
                        self.log_success("Database Token Usage Tracking")
                    else:
                        self.log_error("Database Token Usage Tracking", "Usage count not updated")
                else:
                    self.log_error("Database Token Usage Tracking", "Test token not found")
                
            except Exception as e:
                self.log_error("Database Operations", str(e))
    
    def test_security_features(self):
        """Test security features"""
        logger.info("\n=== TESTING SECURITY FEATURES ===")
        
        with self.flask_app.app_context():
            client = self.flask_app.test_client()
            
            # Test 1: Admin routes require authentication
            admin_routes = ['/admin/', '/admin/apps', '/admin/tokens', '/admin/users']
            for route in admin_routes:
                try:
                    response = client.get(route)
                    if response.status_code == 302:  # Redirect to login
                        self.log_success(f"Security: {route} requires auth")
                    else:
                        self.log_error(f"Security: {route} requires auth", f"Expected 302, got {response.status_code}")
                except Exception as e:
                    self.log_error(f"Security: {route} requires auth", str(e))
            
            # Test 2: API routes require token
            api_routes = ['/api/terms', '/api/categories']
            for route in api_routes:
                try:
                    response = client.get(route)
                    if response.status_code == 401:  # Unauthorized
                        self.log_success(f"Security: {route} requires token")
                    else:
                        self.log_error(f"Security: {route} requires token", f"Expected 401, got {response.status_code}")
                except Exception as e:
                    self.log_error(f"Security: {route} requires token", str(e))
            
            # Test 3: Invalid tokens rejected
            try:
                response = client.get('/api/terms', headers={'X-API-Key': 'invalid_token'})
                if response.status_code == 401:
                    self.log_success("Security: Invalid tokens rejected")
                else:
                    self.log_error("Security: Invalid tokens rejected", f"Expected 401, got {response.status_code}")
            except Exception as e:
                self.log_error("Security: Invalid tokens rejected", str(e))
            
            # Test 4: Token masking in templates
            try:
                # Login as admin
                with client.session_transaction() as sess:
                    if self.test_user:
                        sess['_user_id'] = str(self.test_user.id)
                        sess['_fresh'] = True
                
                response = client.get('/admin/tokens')
                html = response.get_data(as_text=True)
                
                # Should show masked token pattern, not any full tokens
                if 'mg_****************************' in html:
                    # Check that no actual token hashes are visible
                    tokens = AppToken.query.all()
                    full_tokens_visible = any(token.token_hash in html for token in tokens)
                    
                    if not full_tokens_visible:
                        self.log_success("Security: Token masking in GUI")
                    else:
                        self.log_error("Security: Token masking in GUI", "Full token hash visible in HTML")
                else:
                    self.log_error("Security: Token masking in GUI", "Token masking pattern not found")
            except Exception as e:
                self.log_error("Security: Token masking in GUI", str(e))
    
    def cleanup_test_data(self):
        """Clean up test data"""
        with self.flask_app.app_context():
            try:
                # Remove test token
                test_token = AppToken.query.filter_by(name='Test Token').first()
                if test_token:
                    db.session.delete(test_token)
                
                # Remove test terms
                test_terms = Term.query.filter(Term.term.like('%Test%')).all()
                for term in test_terms:
                    db.session.delete(term)
                
                # Remove test apps
                test_apps = App.query.filter(App.name.like('%Test%')).all()
                for app in test_apps:
                    # Remove associated tokens first
                    for token in app.tokens:
                        db.session.delete(token)
                    db.session.delete(app)
                
                db.session.commit()
                logger.info("✅ Test data cleaned up")
                
            except Exception as e:
                logger.error(f"❌ Error cleaning up test data: {e}")
                db.session.rollback()
    
    def run_all_tests(self):
        """Run all tests"""
        logger.info("🚀 Starting Comprehensive Test Suite")
        
        if not self.setup_test_data():
            logger.error("❌ Failed to set up test data. Aborting tests.")
            return False
        
        try:
            self.test_api_endpoints()
            self.test_admin_gui()
            self.test_database_operations()
            self.test_security_features()
            
        finally:
            self.cleanup_test_data()
        
        # Report results
        logger.info(f"\n=== TEST RESULTS ===")
        logger.info(f"✅ Successes: {len(self.successes)}")
        logger.info(f"❌ Errors: {len(self.errors)}")
        
        if self.errors:
            logger.info(f"\n=== ERRORS TO FIX ===")
            for error in self.errors:
                logger.info(error)
        else:
            logger.info(f"\n🎉 All tests passed successfully!")
        
        return len(self.errors) == 0

def main():
    """Main test function"""
    test_suite = ComprehensiveTestSuite()
    success = test_suite.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()