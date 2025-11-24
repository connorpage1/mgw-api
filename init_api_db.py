#!/usr/bin/env python3
"""
API Database Initialization Script
Initialize database tables for the pure API service
"""

import os
import sys
from app import create_app, db
from models import Category, Term
from utils.logger import logger

def init_database():
    """Initialize database with tables and sample data"""
    logger.info("🚀 Initializing API database...")
    
    app = create_app()
    with app.app_context():
        try:
            # Create all tables
            logger.info("📋 Creating database tables...")
            db.create_all()
            logger.info("✅ Database tables created successfully")
            
            # Create default categories if they don't exist
            logger.info("📂 Creating default categories...")
            default_categories = [
                {
                    'name': 'Core Terms',
                    'slug': 'core-terms',
                    'description': 'Essential Mardi Gras terminology',
                    'sort_order': 0
                },
                {
                    'name': 'Krewes',
                    'slug': 'krewes',
                    'description': 'Organizations that organize parades and events',
                    'sort_order': 1
                },
                {
                    'name': 'Traditions',
                    'slug': 'traditions',
                    'description': 'Traditional customs and practices',
                    'sort_order': 2
                }
            ]
            
            for cat_data in default_categories:
                existing_category = Category.query.filter_by(slug=cat_data['slug']).first()
                if not existing_category:
                    category = Category(**cat_data)
                    db.session.add(category)
                    logger.info(f"✅ Created category: {cat_data['name']}")
                else:
                    logger.info(f"⚪ Category already exists: {cat_data['name']}")
            
            # Create sample terms if they don't exist
            logger.info("📝 Creating sample terms...")
            sample_terms = [
                {
                    'term': 'Krewe',
                    'pronunciation': 'KROO',
                    'definition': 'An organization that organizes Mardi Gras parades and events',
                    'difficulty': 'tourist',
                    'category_id': 1
                },
                {
                    'term': 'Throw',
                    'pronunciation': 'THROW',
                    'definition': 'An item tossed from floats to the crowd during parades',
                    'difficulty': 'tourist',
                    'category_id': 1
                }
            ]
            
            for term_data in sample_terms:
                existing_term = Term.query.filter_by(term=term_data['term']).first()
                if not existing_term:
                    term = Term(**term_data)
                    db.session.add(term)
                    logger.info(f"✅ Created term: {term_data['term']}")
                else:
                    logger.info(f"⚪ Term already exists: {term_data['term']}")
            
            # Commit all changes
            db.session.commit()
            logger.info("✅ Database initialization completed successfully")
            
            # Display summary
            category_count = Category.query.count()
            term_count = Term.query.count()
            logger.info(f"📊 Database summary:")
            logger.info(f"   Categories: {category_count}")
            logger.info(f"   Terms: {term_count}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            db.session.rollback()
            raise
            
        logger.info("🎭 Mardi Gras API database is ready!")

if __name__ == '__main__':
    init_database()