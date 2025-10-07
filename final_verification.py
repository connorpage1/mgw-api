#!/usr/bin/env python3
"""
Final verification that all systems are working
"""
import sys
import os
import json

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role, Term, Category
from utils.logger import logger

def final_verification():
    """Final verification of the entire system"""
    
    logger.info("🎯 FINAL SYSTEM VERIFICATION")
    logger.info("=" * 50)
    
    flask_app = create_app()
    issues = []
    
    with flask_app.app_context():
        # 1. Database Health Check
        try:
            apps_count = App.query.count()
            tokens_count = AppToken.query.count()
            users_count = User.query.count()
            categories_count = Category.query.count()
            
            logger.info(f"📊 DATABASE STATUS:")
            logger.info(f"   Apps: {apps_count}")
            logger.info(f"   Tokens: {tokens_count}")
            logger.info(f"   Users: {users_count}")
            logger.info(f"   Categories: {categories_count}")
            
            if apps_count > 0 and tokens_count > 0 and users_count > 0:
                logger.info("   ✅ Database healthy")
            else:
                issues.append("Database missing required data")
                
        except Exception as e:
            issues.append(f"Database connection error: {e}")
        
        # 2. App and Token Relationships
        try:
            app = App.query.first()
            if app and app.tokens.count() > 0:
                logger.info("✅ App-Token relationships working")
                
                # Test token masking
                token = app.tokens.first()
                masked = token.masked_token
                if 'mg_****************************' in masked:
                    logger.info("✅ Token masking working")
                else:
                    issues.append(f"Token masking incorrect: {masked}")
            else:
                issues.append("No app-token relationships found")
        except Exception as e:
            issues.append(f"App-Token relationship error: {e}")
        
        # 3. User Role System
        try:
            superadmin = User.query.join(User.roles).filter(Role.name == 'superadmin').first()
            if superadmin and superadmin.has_role('superadmin'):
                logger.info("✅ User role system working")
            else:
                issues.append("Superadmin role system not working")
        except Exception as e:
            issues.append(f"User role error: {e}")
        
        # 4. API Endpoints
        client = flask_app.test_client()
        
        # Health endpoint
        try:
            response = client.get('/api/health')
            if response.status_code == 200:
                data = json.loads(response.data)
                if data.get('status') == 'ok':
                    logger.info("✅ API health endpoint working")
                else:
                    issues.append("API health endpoint returning wrong data")
            else:
                issues.append(f"API health endpoint status: {response.status_code}")
        except Exception as e:
            issues.append(f"API health endpoint error: {e}")
        
        # Authentication required
        try:
            response = client.get('/api/terms')
            if response.status_code == 401:
                logger.info("✅ API authentication enforced")
            else:
                issues.append(f"API authentication not enforced: {response.status_code}")
        except Exception as e:
            issues.append(f"API authentication test error: {e}")
        
        # 5. Admin Interface
        try:
            response = client.get('/admin/')
            if response.status_code == 302:  # Redirect to login
                logger.info("✅ Admin authentication enforced")
            else:
                issues.append(f"Admin authentication not enforced: {response.status_code}")
        except Exception as e:
            issues.append(f"Admin interface error: {e}")
        
        # Test with admin login
        try:
            # Set up session properly
            with client.session_transaction() as sess:
                sess['_user_id'] = str(superadmin.id)
                sess['_fresh'] = True
            
            # Test admin pages in the same session
            admin_pages = ['/admin/', '/admin/apps', '/admin/tokens']
            for page in admin_pages:
                response = client.get(page)
                if response.status_code == 200:
                    logger.info(f"✅ Admin page {page} accessible")
                elif response.status_code == 302:
                    # 302 is expected if authentication isn't working - check if it's going to login
                    location = response.headers.get('Location', '')
                    if 'login' in location:
                        issues.append(f"Admin page {page} authentication failed (redirects to login)")
                    else:
                        logger.info(f"✅ Admin page {page} redirects properly")
                else:
                    issues.append(f"Admin page {page} error: {response.status_code}")
                    
        except Exception as e:
            issues.append(f"Admin login test error: {e}")
        
        # 6. API Token Authentication (create temporary token for testing)
        try:
            demo_token = AppToken.query.first()
            if demo_token:
                import secrets
                import hashlib
                
                # Create test token
                raw_token = f"mg_{''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
                token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                
                test_token = AppToken(
                    app_id=demo_token.app_id,
                    name="Final Test Token",
                    token_hash=token_hash,
                    prefix="mg_",
                    created_by=1,
                    updated_by=1
                )
                
                db.session.add(test_token)
                db.session.commit()
                
                try:
                    # Test different auth methods
                    auth_methods = [
                        ('X-API-Key', raw_token),
                        ('Authorization', f'Bearer {raw_token}')
                    ]
                    
                    for header_name, header_value in auth_methods:
                        response = client.get('/api/categories', headers={header_name: header_value})
                        if response.status_code == 200:
                            logger.info(f"✅ API {header_name} auth working")
                        else:
                            issues.append(f"API {header_name} auth failed: {response.status_code}")
                    
                    # Test query parameter
                    response = client.get(f'/api/categories?api_key={raw_token}')
                    if response.status_code == 200:
                        logger.info("✅ API query parameter auth working")
                    else:
                        issues.append(f"API query parameter auth failed: {response.status_code}")
                        
                finally:
                    # Clean up
                    db.session.delete(test_token)
                    db.session.commit()
                    
        except Exception as e:
            issues.append(f"API token test error: {e}")
    
    # Final Report
    logger.info("\n" + "=" * 50)
    logger.info("🎯 FINAL VERIFICATION RESULTS")
    logger.info("=" * 50)
    
    if not issues:
        logger.info("🎉 ALL SYSTEMS WORKING PERFECTLY!")
        logger.info("✅ API endpoints functional")
        logger.info("✅ App-based token system active")
        logger.info("✅ Admin interface secure")
        logger.info("✅ Database operations healthy")
        logger.info("✅ Authentication systems working")
        logger.info("✅ Security features enabled")
        
        logger.info("\n🚀 SYSTEM READY FOR PRODUCTION USE!")
        return True
    else:
        logger.info(f"❌ FOUND {len(issues)} ISSUES:")
        for i, issue in enumerate(issues, 1):
            logger.info(f"   {i}. {issue}")
        return False

if __name__ == "__main__":
    success = final_verification()
    sys.exit(0 if success else 1)