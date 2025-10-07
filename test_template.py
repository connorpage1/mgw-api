#!/usr/bin/env python3
"""
Test template rendering
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, App, AppToken
from utils.logger import logger

def test_template_rendering():
    """Test template rendering with actual data"""
    flask_app = create_app()
    
    with flask_app.app_context():
        try:
            # Get real apps data
            apps = App.query.order_by(App.created_at.desc()).all()
            logger.info(f"Testing template with {len(apps)} apps")
            
            # Try to render the template
            from flask import render_template
            
            try:
                html = render_template('admin/apps_list.html', apps=apps)
                logger.info("✅ Template rendered successfully")
                logger.info(f"HTML length: {len(html)} characters")
                
                # Check for specific content
                if 'Demo API App' in html:
                    logger.info("✅ Template contains expected app data")
                else:
                    logger.warning("⚠️ Template doesn't contain expected app data")
                
                # Check for errors in HTML
                if 'error' in html.lower() or 'exception' in html.lower():
                    logger.warning("⚠️ Template might contain error messages")
                
                return True
                
            except Exception as e:
                logger.error(f"❌ Template rendering failed: {e}")
                import traceback
                logger.error(traceback.format_exc())
                return False
            
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

if __name__ == "__main__":
    success = test_template_rendering()
    sys.exit(0 if success else 1)