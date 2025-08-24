#!/usr/bin/env python3
"""
Production Database Initialization Script for Railway Deployment
Run this once after first deployment to set up database tables and initial data.
"""

import os
import sys
from app import app, db, User, Role, Category, Term, secure_hasher
import secrets

def init_database():
    """Initialize database with tables and essential data"""
    print("🚀 Initializing production database...")
    
    with app.app_context():
        try:
            # Create all tables
            print("📋 Creating database tables...")
            db.create_all()
            print("✅ Database tables created successfully")
            
            # Create default roles
            print("👥 Creating default roles...")
            roles_data = ['superadmin', 'admin', 'editor', 'viewer']
            
            for role_name in roles_data:
                existing_role = Role.query.filter_by(name=role_name).first()
                if not existing_role:
                    role = Role(name=role_name)
                    db.session.add(role)
                    print(f"  ➕ Created role: {role_name}")
                else:
                    print(f"  ✓ Role already exists: {role_name}")
            
            db.session.commit()
            
            # Create default categories
            print("📚 Creating default categories...")
            categories_data = [
                {'name': 'Core Terms', 'description': 'Essential Mardi Gras terminology'},
                {'name': 'Krewes', 'description': 'Organizations that organize parades'},
                {'name': 'Food & Drinks', 'description': 'Traditional Mardi Gras cuisine'},
                {'name': 'Music & Dance', 'description': 'Musical traditions'},
                {'name': 'History', 'description': 'Historical context and origins'},
                {'name': 'Traditions', 'description': 'Customs and practices'}
            ]
            
            for cat_data in categories_data:
                existing_cat = Category.query.filter_by(name=cat_data['name']).first()
                if not existing_cat:
                    # Generate slug from name
                    slug = cat_data['name'].lower().replace(' ', '-').replace('&', 'and')
                    category = Category(
                        name=cat_data['name'],
                        slug=slug,
                        description=cat_data['description'],
                        is_active=True
                    )
                    db.session.add(category)
                    print(f"  ➕ Created category: {cat_data['name']}")
                else:
                    print(f"  ✓ Category already exists: {cat_data['name']}")
            
            db.session.commit()
            
            # Check if admin user exists
            admin_user = User.query.filter_by(email='admin@mardigras.com').first()
            if not admin_user:
                print("👤 Creating default admin user...")
                
                # Generate secure temporary password
                temp_password = secrets.token_urlsafe(16)
                
                # Get superadmin role
                superadmin_role = Role.query.filter_by(name='superadmin').first()
                
                admin_user = User(
                    email='admin@mardigras.com',
                    first_name='Admin',
                    last_name='User',
                    password=secure_hasher.hash_password(temp_password),
                    active=True
                )
                
                if superadmin_role:
                    admin_user.roles = [superadmin_role]
                
                db.session.add(admin_user)
                db.session.commit()
                
                print(f"✅ Admin user created!")
                print(f"📧 Email: admin@mardigras.com")
                print(f"🔑 Temporary Password: {temp_password}")
                print("⚠️  IMPORTANT: Change this password after first login!")
            else:
                print("✓ Admin user already exists")
            
            print("\n🎉 Database initialization completed successfully!")
            print("\n📝 Next steps:")
            print("1. Log in with the admin credentials above")
            print("2. Change the admin password immediately")
            print("3. Create additional users as needed")
            print("4. Start adding terms and categories")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            sys.exit(1)

if __name__ == '__main__':
    init_database()