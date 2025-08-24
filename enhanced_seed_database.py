# enhanced_seed_database.py - Enhanced Database seeding script with authentication
import json
import os
import secrets
from app import app, db, Category, Term, User, create_slug, Role, secure_hasher

def create_admin_user():
    """Create default admin user if none exists"""
    # Look for existing superadmin user
    admin = User.query.filter(User.roles.any(Role.name == 'superadmin')).first()
    if admin:
        print(f"✅ Superadmin user already exists: {admin.email}")
        return admin
    
    # Create superadmin role if it doesn't exist
    superadmin_role = Role.query.filter_by(name='superadmin').first()
    if not superadmin_role:
        superadmin_role = Role(name='superadmin')
        db.session.add(superadmin_role)
        db.session.commit()
        print("✅ Created superadmin role")
    
    # Create admin user
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@test.local')
    admin_password = os.environ.get('ADMIN_PASSWORD', 'TestAdmin123!')
    
    admin = User(
        username=os.environ.get('ADMIN_USERNAME', 'testadmin'),
        email=admin_email,
        first_name='Test',
        last_name='Admin',
        password=secure_hasher.hash_password(admin_password),
        active=True,
        api_key=secrets.token_urlsafe(32)
    )
    
    db.session.add(admin)
    db.session.commit()
    
    # Assign superadmin role
    admin.roles.append(superadmin_role)
    db.session.commit()
    print(f"✅ Assigned superadmin role to user: {admin.email}")
    
    print(f"✅ Created admin user: {admin.email}")
    print(f"🔐 Password: {admin_password}")
    print(f"🔑 Admin API Key: {admin.api_key}")
    print(f"⚠️  Please save these credentials!")
    
    return admin

def create_api_users():
    """Create sample API users for testing"""
    # Create a regular user role if it doesn't exist
    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user')
        db.session.add(user_role)
        db.session.commit()
        print("✅ Created user role")
    
    # Create a regular test user
    if not User.query.filter_by(email='user@test.local').first():
        test_password = 'TestUser123!'
        api_user = User(
            username='testuser',
            email='user@test.local',
            first_name='Test',
            last_name='User',
            password=secure_hasher.hash_password(test_password),
            active=True,
            api_key=secrets.token_urlsafe(32)
        )
        
        db.session.add(api_user)
        db.session.commit()
        
        # Assign user role
        api_user.roles.append(user_role)
        db.session.commit()
        print(f"✅ Assigned user role to: {api_user.email}")
        
        print(f"✅ Created test user: {api_user.email}")
        print(f"🔐 Password: {test_password}")
        print(f"🔑 API User Key: {api_user.api_key}")

def seed_categories():
    """Seed categories from predefined data"""
    categories_data = [
        {'name': 'Core Terms', 'icon': '⭐', 'description': 'Essential Carnival vocabulary', 'sort_order': 1},
        {'name': 'Krewes', 'icon': '👑', 'description': 'Carnival organizations and societies', 'sort_order': 2},
        {'name': 'Food & Drink', 'icon': '🎂', 'description': 'Traditional Carnival cuisine', 'sort_order': 3},
        {'name': 'Throws', 'icon': '📿', 'description': 'Items thrown from parade floats', 'sort_order': 4},
        {'name': 'Parades', 'icon': '🎪', 'description': 'Parade terminology and logistics', 'sort_order': 5},
        {'name': 'Music & Culture', 'icon': '🎵', 'description': 'Musical traditions and performances', 'sort_order': 6},
        {'name': 'Local Slang', 'icon': '💬', 'description': 'New Orleans expressions and dialect', 'sort_order': 7},
        {'name': 'Culture', 'icon': '🎨', 'description': 'Cultural traditions and practices', 'sort_order': 8},
        {'name': 'Locations', 'icon': '📍', 'description': 'Important Carnival venues and routes', 'sort_order': 9},
        {'name': 'Viewing', 'icon': '👀', 'description': 'Parade watching and etiquette', 'sort_order': 10},
        {'name': 'Balls & Events', 'icon': '🎩', 'description': 'Formal Carnival celebrations', 'sort_order': 11},
        {'name': 'Royalty & Titles', 'icon': '👑', 'description': 'Carnival hierarchy and honors', 'sort_order': 12},
        {'name': 'Regional', 'icon': '🌎', 'description': 'Carnival celebrations across the region', 'sort_order': 13},
        {'name': 'Tourism', 'icon': '✈️', 'description': 'Visitor information and services', 'sort_order': 14},
        {'name': 'Seasonal', 'icon': '📅', 'description': 'Carnival calendar and timing', 'sort_order': 15},
        {'name': 'Historical', 'icon': '📜', 'description': 'Carnival history and evolution', 'sort_order': 16}
    ]
    
    category_map = {}
    
    for cat_data in categories_data:
        # Check if category exists
        existing = Category.query.filter_by(name=cat_data['name']).first()
        if existing:
            category_map[cat_data['name']] = existing.id
            continue
            
        # Create new category
        category = Category(
            name=cat_data['name'],
            slug=create_slug(cat_data['name']),
            description=cat_data['description'],
            sort_order=cat_data['sort_order'],
            is_active=True
        )
        db.session.add(category)
        db.session.flush()  # Get the ID
        category_map[cat_data['name']] = category.id
    
    db.session.commit()
    print(f"✅ Seeded {len(categories_data)} categories")
    return category_map

def seed_terms_from_json(json_file_path):
    """Seed terms from JSON file"""
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ JSON file not found: {json_file_path}")
        return
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in {json_file_path}: {e}")
        return
    
    # Get category mapping
    category_map = {cat.name: cat.id for cat in Category.query.all()}
    
    terms_added = 0
    terms_updated = 0
    terms_skipped = 0
    
    for term_data in data.get('terms', []):
        try:
            # Check if term exists
            existing_term = Term.query.filter_by(term=term_data['term']).first()
            
            # Get category ID
            category_id = category_map.get(term_data['category'])
            if not category_id:
                print(f"⚠️  Category not found for term '{term_data['term']}': {term_data['category']}")
                terms_skipped += 1
                continue
            
            if existing_term:
                # Update existing term
                existing_term.pronunciation = term_data['pronunciation']
                existing_term.definition = term_data['definition']
                existing_term.etymology = term_data.get('etymology', '')
                existing_term.example = term_data.get('example', '')
                existing_term.difficulty = term_data['difficulty']
                existing_term.category_id = category_id
                existing_term.is_active = True
                terms_updated += 1
            else:
                # Create new term
                term = Term(
                    term=term_data['term'],
                    slug=create_slug(term_data['term']),
                    pronunciation=term_data['pronunciation'],
                    definition=term_data['definition'],
                    etymology=term_data.get('etymology', ''),
                    example=term_data.get('example', ''),
                    difficulty=term_data['difficulty'],
                    category_id=category_id,
                    is_active=True
                )
                db.session.add(term)
                terms_added += 1
        
        except Exception as e:
            print(f"❌ Error processing term '{term_data.get('term', 'unknown')}': {e}")
            terms_skipped += 1
            continue
    
    try:
        db.session.commit()
        print(f"✅ Added {terms_added} new terms")
        print(f"✅ Updated {terms_updated} existing terms")
        if terms_skipped > 0:
            print(f"⚠️  Skipped {terms_skipped} terms due to errors")
        
        # Set a random featured term if none exists
        if not Term.query.filter_by(is_featured=True, is_active=True).first():
            random_term = Term.query.filter_by(is_active=True).order_by(db.func.random()).first()
            if random_term:
                random_term.is_featured = True
                db.session.commit()
                print(f"✅ Set featured term: {random_term.term}")
                
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error saving terms: {e}")

def cleanup_inactive_data():
    """Clean up any duplicate or problematic data"""
    # Remove any duplicate categories
    categories = Category.query.all()
    seen_names = set()
    duplicates = []
    
    for cat in categories:
        if cat.name in seen_names:
            duplicates.append(cat)
        else:
            seen_names.add(cat.name)
    
    if duplicates:
        for dup in duplicates:
            # Move terms to the first occurrence of the category
            original = Category.query.filter_by(name=dup.name).first()
            for term in dup.terms:
                term.category_id = original.id
            db.session.delete(dup)
        
        db.session.commit()
        print(f"✅ Cleaned up {len(duplicates)} duplicate categories")
    
    # Remove any terms without valid categories
    orphaned_terms = Term.query.filter(~Term.category_id.in_(
        db.session.query(Category.id).filter_by(is_active=True)
    )).all()
    
    if orphaned_terms:
        for term in orphaned_terms:
            term.is_active = False
        db.session.commit()
        print(f"✅ Deactivated {len(orphaned_terms)} orphaned terms")

def generate_sample_api_documentation():
    """Generate sample API documentation"""
    doc = """
# Mardi Gras Glossary API Documentation

## Base URL
https://api.mardigrasworld.com

## Authentication

### JWT Authentication (for admin operations)
```bash
# Login to get JWT token
curl -X POST https://api.mardigrasworld.com/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "your_password"}'

# Use JWT token in subsequent requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  https://api.mardigrasworld.com/admin/terms
```

### API Key Authentication (for public API access)
```bash
# Use API key in header
curl -H "X-API-Key: YOUR_API_KEY" \\
  https://api.mardigrasworld.com/glossary/terms
```

## Public Endpoints (Rate Limited)

### Get Terms
```bash
GET /glossary/terms
GET /glossary/terms?search=mardi&category=core-terms&difficulty=tourist&limit=50
```

### Get Single Term
```bash
GET /glossary/term/{slug}
```

### Get Categories
```bash
GET /glossary/categories
```

### Search Suggestions
```bash
GET /glossary/search/suggestions?q=mar
```

### Random Term
```bash
GET /glossary/random
```

### Statistics
```bash
GET /glossary/stats
```

## Admin Endpoints (JWT Required)

### Manage Terms
```bash
GET /admin/terms
POST /admin/terms
PUT /admin/terms/{id}
DELETE /admin/terms/{id}
```

### Analytics
```bash
GET /admin/analytics/usage?days=30
```

## Rate Limits
- Public API: 100 requests per hour
- Search suggestions: 200 requests per hour
- Admin API: No limits (with valid JWT)

## Response Format
All responses are JSON with consistent structure:
```json
{
  "terms": [...],
  "count": 25,
  "total": 150
}
```

Error responses:
```json
{
  "error": "Description of error"
}
```
"""
    
    with open('API_DOCUMENTATION.md', 'w') as f:
        f.write(doc)
    
    print("✅ Generated API documentation")

def main():
    """Main seeding function"""
    with app.app_context():
        print("🚀 Starting enhanced database seeding...")
        
        # Create tables if they don't exist
        db.create_all()
        print("✅ Database tables ready")
        
        # Create admin and API users
        create_admin_user()
        create_api_users()
        
        # Seed categories first
        category_map = seed_categories()
        
        # Try to seed from JSON file
        json_file = 'mardi_gras_glossary_data.json'
        if os.path.exists(json_file):
            print(f"📄 Loading terms from {json_file}")
            seed_terms_from_json(json_file)
        else:
            print(f"⚠️  {json_file} not found")
        
        # Clean up any problematic data
        cleanup_inactive_data()
        
        # Generate API documentation
        generate_sample_api_documentation()
        
        # Print final statistics
        total_terms = Term.query.filter_by(is_active=True).count()
        total_categories = Category.query.filter_by(is_active=True).count()
        total_users = User.query.filter_by(active=True).count()
        
        print(f"\n🎉 Enhanced seeding complete!")
        print(f"📊 Final counts:")
        print(f"   📚 Categories: {total_categories}")
        print(f"   📖 Terms: {total_terms}")
        print(f"   👥 API Users: {total_users}")
        
        if total_terms > 0:
            print(f"\n📈 Breakdown by difficulty:")
            for difficulty in ['tourist', 'local', 'expert']:
                count = Term.query.filter_by(difficulty=difficulty, is_active=True).count()
                print(f"   {difficulty.title()}: {count}")
        
        print(f"\n🔧 Next steps:")
        print(f"   1. Update environment variables with secure passwords")
        print(f"   2. Deploy to your chosen platform (Render, Heroku, etc.)")
        print(f"   3. Configure your domain DNS to point api.mardigrasworld.com to your deployment")
        print(f"   4. Test the API endpoints with the provided documentation")

if __name__ == '__main__':
    main()