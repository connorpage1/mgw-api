"""
Migration script to move from user API keys to app-based tokens
"""
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from models import db, User, App, AppToken
from utils.logger import logger
import secrets
import hashlib

def migrate_user_tokens_to_apps():
    """
    Migrate existing user API keys to app-based tokens
    """
    app = create_app()
    
    with app.app_context():
        try:
            # Create tables
            logger.info("Creating new App and AppToken tables...")
            db.create_all()
            
            # Check if there are any existing apps and tokens
            existing_apps = App.query.count()
            existing_tokens = AppToken.query.count()
            
            logger.info(f"Found {existing_apps} existing apps and {existing_tokens} existing tokens")
            
            if existing_apps == 0:
                logger.info("No existing apps found. Creating default demo app...")
                
                # Get the first superadmin user for ownership
                superadmin = User.query.join(User.roles).filter_by(name='superadmin').first()
                if not superadmin:
                    logger.warning("No superadmin found, using first user")
                    superadmin = User.query.first()
                
                if superadmin:
                    # Create a demo app
                    demo_app = App(
                        name="Demo API App",
                        description="Default API application for testing",
                        created_by=superadmin.id,
                        updated_by=superadmin.id
                    )
                    db.session.add(demo_app)
                    db.session.flush()  # Get the app ID
                    
                    # Generate a new API token
                    raw_token = f"mg_{''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(32))}"
                    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
                    
                    # Create token record
                    app_token = AppToken(
                        app_id=demo_app.id,
                        name="Demo Token",
                        token_hash=token_hash,
                        prefix="mg_",
                        created_by=superadmin.id,
                        updated_by=superadmin.id
                    )
                    db.session.add(app_token)
                    
                    logger.info(f"Created demo app and token: {raw_token}")
                    logger.info("Save this token for testing!")
                else:
                    logger.error("No users found in database")
            
            # Commit the migration
            db.session.commit()
            logger.info("Migration completed successfully")
            
            logger.info("NOTE: App and token tables have been created successfully.")
            logger.info("You can now manage apps and tokens through the admin interface.")
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            db.session.rollback()
            raise

if __name__ == "__main__":
    migrate_user_tokens_to_apps()