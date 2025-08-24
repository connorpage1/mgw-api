# enhanced_seed_database.py - Enhanced Database seeding script with authentication
import json
import os
import secrets
from app import app, db, Category, Term, APIUser, create_slug

def create_admin_user():
    """Create default admin user if none exists"""
    admin = APIUser.query.filter_by(is_admin=True).first()
    if admin:
        print(f"✅ Admin user already exists: {admin.username}")
        return admin
    
    # Create admin user
    admin = APIUser(
        username=os.environ.get('ADMIN_USERNAME', 'admin'),
        email=os.environ.get('ADMIN_EMAIL', 'admin@mardigrasworld.com'),
        is_admin=True,
        is_active=True
    )
    admin.set_password(os.environ.get('ADMIN_PASSWORD', 'change_me_please'))
    admin.generate_api_key()
    
    db.session.add(admin)
    db.session.commit()
    
    print(f"✅ Created admin user: {admin.username}")
    print(f"🔑 Admin API Key: {admin.api_key}")
    print(f"⚠️  Please save the API key and change the default password!")
    
    return admin

def create_api_users():
    """Create sample API users for testing"""
    # Create a regular API user
    if not APIUser.query.filter_by(username='api_user').first():
        api_user = APIUser(
            username='api_user',
            email='api@mardigrasworld.com',
            is_admin=False,
            is_active=True
        )
        api_user.set_password('secure_password_123')
        api_user.generate_api_key()
        
        db.session.add(api_user)
        db.session.commit()
        
        print(f"✅ Created API user: {api_user.username}")
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
            icon=cat_data['icon'],
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
        total_users = APIUser.query.filter_by(is_active=True).count()
        
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