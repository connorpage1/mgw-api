#!/usr/bin/env python3
"""
Database initialization script to ensure all tables exist
"""
from app import create_app
from models import db
from utils.logger import logger

def init_database():
    """Initialize the database with all required tables"""
    app = create_app()
    
    with app.app_context():
        try:
            logger.info("Creating all database tables...")
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Test that we can query each table
            from models import User, Category, Term, STLFile
            
            logger.info("Testing table access...")
            
            user_count = User.query.count()
            logger.info(f"Users table: {user_count} records")
            
            category_count = Category.query.count()
            logger.info(f"Categories table: {category_count} records")
            
            term_count = Term.query.count()
            logger.info(f"Terms table: {term_count} records")
            
            file_count = STLFile.query.count()
            logger.info(f"STL Files table: {file_count} records")
            
            logger.info("✅ All tables accessible")
            
        except Exception as e:
            logger.error(f"❌ Database initialization error: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

if __name__ == '__main__':
    init_database()