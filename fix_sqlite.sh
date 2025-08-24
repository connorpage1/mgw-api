# fix_sqlite.sh - Quick fix for SQLite database issue
#!/bin/bash

echo "🔧 Fixing SQLite database issue..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
    print_status "Virtual environment activated"
fi

# Create the instance directory with proper permissions
echo "📁 Creating instance directory..."
rm -rf instance/ 2>/dev/null || true
mkdir -p instance
chmod 755 instance

# Also create logs directory
mkdir -p logs
chmod 755 logs

print_status "Directories created with proper permissions"

# Check current directory permissions
echo "🔍 Checking current directory permissions..."
ls -la | grep -E "(instance|logs)"

# Make sure .env.local exists
if [ ! -f ".env.local" ]; then
    print_warning "Creating .env.local file..."
    
    cat > .env.local << 'EOF'
# Local Development Configuration
FLASK_ENV=development
FLASK_DEBUG=True

# Security Keys (DEVELOPMENT ONLY)
SECRET_KEY=dev_secret_key_32_characters_long_12345678
JWT_SECRET_KEY=dev_jwt_secret_key_32_characters_long_87654321

# Local Database (SQLite)
DATABASE_URL=sqlite:///instance/mardi_gras_dev.db

# Admin User
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@dev.local
ADMIN_PASSWORD=DevAdmin123!@#

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000

# Logging
LOG_LEVEL=DEBUG
EOF
    
    print_status ".env.local created"
fi

# Load environment variables
source .env.local

# Test the database path
echo "🧪 Testing database path..."
python3 -c "
import os
from dotenv import load_dotenv

load_dotenv('.env.local')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/mardi_gras_dev.db')
print(f'Database URL: {db_url}')

# Extract the path from the URL
if db_url.startswith('sqlite:///'):
    db_path = db_url.replace('sqlite:///', '')
    print(f'Database file path: {db_path}')
    
    # Check if directory exists
    import os.path
    directory = os.path.dirname(db_path)
    if directory:
        print(f'Directory: {directory}')
        if os.path.exists(directory):
            print('✅ Directory exists')
        else:
            print('❌ Directory does not exist')
            os.makedirs(directory, exist_ok=True)
            print('✅ Directory created')
else:
    print('Not a SQLite database URL')
"

# Now test database initialization
echo "🗄️ Testing database initialization..."
python3 -c "
import os
from dotenv import load_dotenv

# Load environment
load_dotenv('.env.local')

try:
    from app import app, db, init_db
    print('✅ App imported successfully')
    
    with app.app_context():
        print('✅ App context created')
        
        # Try to initialize
        init_db()
        print('✅ Database initialization successful!')
        
except Exception as e:
    print(f'❌ Database initialization failed: {e}')
    
    # Try to create the database file manually
    import sqlite3
    import os
    
    # Get the database path
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///instance/mardi_gras_dev.db')
    if db_url.startswith('sqlite:///'):
        db_path = db_url.replace('sqlite:///', '')
        
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            # Create empty database file
            conn = sqlite3.connect(db_path)
            conn.close()
            print(f'✅ Created empty database file: {db_path}')
            
            # Now try initialization again
            from app import app, db, init_db
            with app.app_context():
                init_db()
                print('✅ Database initialization successful after manual creation!')
                
        except Exception as e2:
            print(f'❌ Manual database creation failed: {e2}')
            exit(1)
"

if [ $? -eq 0 ]; then
    print_status "Database setup successful"
else
    print_error "Database setup failed"
    
    # Try alternative approach - create database in current directory
    print_warning "Trying alternative database location..."
    
    # Update .env.local to use current directory
    sed -i.bak 's|sqlite:///instance/|sqlite:///|g' .env.local
    
    # Try again
    python3 -c "
from dotenv import load_dotenv
load_dotenv('.env.local')

from app import app, db, init_db
with app.app_context():
    init_db()
    print('✅ Database created in current directory!')
"
    
    if [ $? -eq 0 ]; then
        print_status "Database created in current directory"
    else
        print_error "All database creation attempts failed"
        exit 1
    fi
fi

# Test the app startup
echo "🚀 Testing app startup..."
timeout 3 python3 -c "
from app import app
print('✅ App startup test successful')
" &

wait $!

# Create a simple test script
cat > test_database.sh << 'EOF'
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
        
        if user_count > 0:
            admin = User.query.filter_by(is_admin=True).first()
            if admin:
                print(f'✅ Admin user: {admin.email}')
            else:
                print('⚠️ No admin user found')
        
        term_count = Term.query.count()
        category_count = Category.query.count()
        
        print(f'✅ Terms: {term_count}')
        print(f'✅ Categories: {category_count}')
        
    except Exception as e:
        print(f'❌ Database test failed: {e}')
        exit(1)
"

echo "✅ Database test completed"
EOF

chmod +x test_database.sh

echo ""
echo "🎉 SQLite Fix Complete!"
echo "======================"
echo ""
print_status "Database directory created with proper permissions"
print_status "SQLite database initialized successfully"
echo ""
echo "🚀 Test the fix:"
echo "   1. Test database: ./test_database.sh"
echo "   2. Start server: python3 app.py"
echo "   3. Check health: curl http://localhost:5555/health"
echo ""
echo "📁 Database location:"
if [ -f "instance/mardi_gras_dev.db" ]; then
    echo "   instance/mardi_gras_dev.db (✅ exists)"
elif [ -f "mardi_gras_dev.db" ]; then
    echo "   mardi_gras_dev.db (✅ exists in current directory)"
else
    print_warning "   Database file not found, but should be created on first run"
fi

echo ""
echo "🔧 If you still have issues:"
echo "   • Check file permissions: ls -la instance/"
echo "   • Try running as: sudo python3 app.py"
echo "   • Or use current directory: DATABASE_URL=sqlite:///mardi_gras_dev.db"