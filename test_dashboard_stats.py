#!/usr/bin/env python3
"""
Test dashboard statistics to see if the error is there
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role
from utils.logger import logger

def test_dashboard_stats():
    """Test the dashboard statistics specifically"""
    flask_app = create_app()
    
    with flask_app.app_context():
        try:
            # Test each statistic individually
            logger.info("Testing dashboard statistics...")
            
            # Test apps count
            try:
                total_apps = App.query.filter_by(active=True).count()
                logger.info(f"✅ Total apps: {total_apps}")
            except Exception as e:
                logger.error(f"❌ Error querying apps: {e}")
            
            # Test tokens count
            try:
                total_tokens = AppToken.query.filter_by(active=True).count()
                logger.info(f"✅ Total tokens: {total_tokens}")
            except Exception as e:
                logger.error(f"❌ Error querying tokens: {e}")
            
            # Test the apps_list route function specifically
            logger.info("\nTesting apps_list route...")
            try:
                apps = App.query.order_by(App.created_at.desc()).all()
                logger.info(f"✅ Apps query successful: {len(apps)} apps")
                
                # Check if the route function itself works
                from routes.admin_routes import apps_list
                logger.info(f"✅ apps_list function imported successfully")
                
            except Exception as e:
                logger.error(f"❌ Error in apps_list: {e}")
                import traceback
                logger.error(traceback.format_exc())
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

if __name__ == "__main__":
    success = test_dashboard_stats()
    sys.exit(0 if success else 1)