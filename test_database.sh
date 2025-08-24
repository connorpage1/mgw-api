#!/bin/bash
echo "🧪 Testing database..."

source venv/bin/activate 2>/dev/null || true
source .env.local

# Test database queries
python3 -c "
from app import app, db, User, Term, Category

with app.app_context():
    try:
        user_count = User.query.count()
        print(f'✅ Users in database: {user_count}')
        
        term_count = Term.query.count()
        category_count = Category.query.count()
        
        print(f'✅ Terms: {term_count}')
        print(f'✅ Categories: {category_count}')
        
    except Exception as e:
        print(f'❌ Database test failed: {e}')
        exit(1)
"

echo "✅ Database test completed"
