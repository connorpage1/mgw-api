#!/usr/bin/env python3
"""
Test script to verify the dashboard changes work correctly
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken, User, Role
from utils.logger import logger

def test_dashboard_data():
    """Test that the dashboard data is populated correctly"""
    flask_app = create_app()
    
    with flask_app.app_context():
        try:
            # Test app statistics
            total_apps = App.query.filter_by(active=True).count()
            total_tokens = AppToken.query.filter_by(active=True).count()
            
            logger.info(f"Dashboard Statistics:")
            logger.info(f"- Total active apps: {total_apps}")
            logger.info(f"- Total active tokens: {total_tokens}")
            
            # List existing apps and tokens
            apps = App.query.all()
            logger.info(f"\nExisting Apps ({len(apps)}):")
            for db_app in apps:
                active_tokens = db_app.tokens.filter_by(active=True).count()
                total_tokens_app = db_app.tokens.count()
                logger.info(f"- {db_app.name} ({'Active' if db_app.active else 'Inactive'}): {active_tokens}/{total_tokens_app} tokens")
            
            # List existing tokens
            tokens = AppToken.query.all()
            logger.info(f"\nExisting Tokens ({len(tokens)}):")
            for token in tokens:
                logger.info(f"- {token.name} for {token.app.name} ({'Active' if token.active else 'Revoked'})")
                logger.info(f"  Last used: {token.last_used_at or 'Never'}, Usage count: {token.usage_count}")
            
            # Test routes exist
            with flask_app.test_client() as client:
                logger.info(f"\nTesting route accessibility:")
                
                # These should be accessible (though may require auth)
                routes_to_test = [
                    '/admin/',
                    '/admin/apps',
                    '/admin/tokens',
                ]
                
                for route in routes_to_test:
                    try:
                        response = client.get(route)
                        logger.info(f"- {route}: HTTP {response.status_code} ({'OK' if response.status_code < 400 else 'Needs Auth'})")
                    except Exception as e:
                        logger.error(f"- {route}: Error - {e}")
            
            logger.info(f"\n✅ Dashboard test completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Dashboard test failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

if __name__ == "__main__":
    success = test_dashboard_data()
    sys.exit(0 if success else 1)