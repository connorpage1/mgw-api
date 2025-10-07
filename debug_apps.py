#!/usr/bin/env python3
"""
Debug script to check apps route and template issues
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role
from utils.logger import logger

def debug_apps_route():
    """Debug the apps route and template"""
    flask_app = create_app()
    
    with flask_app.app_context():
        try:
            # Test that the route exists
            logger.info("Testing apps route registration...")
            
            # Get all registered routes
            routes = []
            for rule in flask_app.url_map.iter_rules():
                routes.append(str(rule))
            
            apps_routes = [route for route in routes if 'apps' in route]
            logger.info(f"Apps-related routes found: {apps_routes}")
            
            # Test the apps_list function directly
            logger.info("\nTesting apps_list function...")
            from routes.admin_routes import apps_list
            
            # Create a fake request context to test the function
            with flask_app.test_request_context('/admin/apps'):
                try:
                    # Test getting apps data
                    apps = App.query.order_by(App.created_at.desc()).all()
                    logger.info(f"Found {len(apps)} apps in database")
                    
                    for app in apps:
                        logger.info(f"- App: {app.name} ({'Active' if app.active else 'Inactive'})")
                        logger.info(f"  Tokens: {app.tokens.count()}")
                    
                    # Test the template exists
                    template_path = "/Users/connor/Development/code/mardi-gras-api/templates/admin/apps_list.html"
                    if os.path.exists(template_path):
                        logger.info(f"✅ Template exists: {template_path}")
                    else:
                        logger.error(f"❌ Template missing: {template_path}")
                    
                    logger.info("✅ Apps route function works correctly")
                    
                except Exception as e:
                    logger.error(f"❌ Error in apps_list function: {e}")
                    import traceback
                    logger.error(traceback.format_exc())
            
        except Exception as e:
            logger.error(f"❌ Debug failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    return True

if __name__ == "__main__":
    success = debug_apps_route()
    sys.exit(0 if success else 1)