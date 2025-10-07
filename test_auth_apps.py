#!/usr/bin/env python3
"""
Test apps route with authentication simulation
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role
from utils.logger import logger

def test_apps_with_auth():
    """Test the apps route with simulated authentication"""
    flask_app = create_app()
    
    with flask_app.app_context():
        try:
            # Get a superadmin user
            superadmin_role = Role.query.filter_by(name='superadmin').first()
            if not superadmin_role:
                logger.error("No superadmin role found")
                return False
            
            superadmin_user = User.query.join(User.roles).filter(Role.name == 'superadmin').first()
            if not superadmin_user:
                logger.error("No superadmin user found")
                return False
            
            logger.info(f"Found superadmin user: {superadmin_user.email}")
            
            # Test the apps_list route with authentication
            with flask_app.test_client() as client:
                # Simulate login by setting session
                with client.session_transaction() as sess:
                    sess['_user_id'] = str(superadmin_user.id)
                    sess['_fresh'] = True
                
                logger.info("Testing /admin/apps with authentication...")
                response = client.get('/admin/apps')
                
                logger.info(f"Response status: {response.status_code}")
                
                if response.status_code == 200:
                    logger.info("✅ Apps route works correctly")
                    
                    # Check response content
                    html = response.get_data(as_text=True)
                    if 'Demo API App' in html:
                        logger.info("✅ Response contains expected app data")
                    else:
                        logger.warning("⚠️ Response doesn't contain expected app data")
                    
                    if 'Error loading apps' in html or 'error' in html.lower():
                        logger.warning("⚠️ Response contains error messages")
                        # Print first 500 chars to see what's wrong
                        logger.info(f"Response preview: {html[:500]}...")
                    
                    return True
                    
                elif response.status_code == 302:
                    logger.warning("⚠️ Still redirecting - authentication didn't work")
                    logger.info(f"Redirect location: {response.headers.get('Location')}")
                    return False
                else:
                    logger.error(f"❌ Unexpected status code: {response.status_code}")
                    logger.info(f"Response: {response.get_data(as_text=True)[:500]}")
                    return False
            
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

if __name__ == "__main__":
    success = test_apps_with_auth()
    sys.exit(0 if success else 1)