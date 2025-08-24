# fix_app.sh - Quick fix for the database initialization issue
#!/bin/bash

echo "🔧 Fixing Mardi Gras API setup issue..."

# Colors for output
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

# Step 1: Check if we're in the right directory
if [ ! -f "app.py" ]; then
    print_error "app.py not found. Please run this script in your project directory."
    exit 1
fi

# Step 2: Replace the broken app.py with the corrected version
echo "🔄 Backing up current app.py..."
cp app.py app.py.backup

echo "📝 The app.py file had a syntax error (unterminated string)."
echo "   Please replace your app.py with the corrected version from the latest artifact."
echo ""
echo "🎯 To fix this quickly:"
echo "   1. Copy the complete 'Corrected Complete app.py File' artifact"
echo "   2. Replace your current app.py file with it"
echo "   3. Run this script again to continue setup"
echo ""

# Check if the file still has syntax errors
echo "🧪 Testing current app.py for syntax errors..."
if python3 -m py_compile app.py 2>/dev/null; then
    print_status "app.py syntax is correct!"
else
    print_error "app.py still has syntax errors. Please replace it with the corrected version."
    echo ""
    echo "Python syntax check output:"
    python3 -m py_compile app.py
    exit 1
fi

# Step 3: Ensure environment is loaded
if [ ! -f ".env.local" ]; then
    print_warning ".env.local not found. Creating it..."
    
    cat > .env.local << 'EOF'
# Local Development Configuration
FLASK_ENV=development
FLASK_DEBUG=True

# Security Keys (DEVELOPMENT ONLY)
SECRET_KEY=dev_secret_key_32_characters_long_12345678
JWT_SECRET_KEY=dev_jwt_secret_key_32_characters_long_87654321
SECURITY_PASSWORD_SALT=dev_salt_32_characters_long_abcdef123456

# Local Database (SQLite)
DATABASE_URL=sqlite:///instance/mardi_gras_dev.db

# Local Redis
REDIS_URL=redis://:devpass@localhost:6379/0

# Admin User
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@dev.local
ADMIN_PASSWORD=DevAdmin123!@#

# Email (MailHog)
MAIL_SERVER=localhost
MAIL_PORT=1025
MAIL_USE_TLS=false
MAIL_USERNAME=dev@test.local
MAIL_PASSWORD=devpass
SECURITY_EMAIL_SENDER=noreply@dev.local

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000

# Logging
LOG_LEVEL=DEBUG
EOF
    
    print_status ".env.local created"
fi

# Step 4: Load environment and test
echo "🔄 Loading environment..."
source .env.local

# Step 5: Ensure Python virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    if [ -d "venv" ]; then
        echo "🐍 Activating Python virtual environment..."
        source venv/bin/activate
        print_status "Virtual environment activated"
    else
        print_warning "No virtual environment found. Creating one..."
        python3 -m venv venv
        source venv/bin/activate
        print_status "Virtual environment created and activated"
    fi
fi

# Step 6: Install/upgrade dependencies
echo "📦 Installing required dependencies..."
pip install --upgrade pip

# Install core dependencies individually to catch issues
echo "Installing Flask and extensions..."
pip install Flask==3.0.0 Flask-SQLAlchemy==3.1.1 Flask-Security-Too==5.3.2

echo "Installing JWT and security..."
pip install Flask-JWT-Extended==4.6.0 argon2-cffi==23.1.0

echo "Installing rate limiting and CORS..."
pip install Flask-Limiter==3.5.0 Flask-CORS==4.0.0 redis==5.0.1

echo "Installing utilities..."
pip install python-dotenv==1.0.0 Flask-Mail==0.9.1 Flask-WTF==1.2.1

print_status "Dependencies installed"

# Step 7: Ensure instance directory exists
mkdir -p instance
mkdir -p logs

# Step 8: Test database initialization
echo "🗄️ Testing database initialization..."
python3 -c "
import sys
sys.path.insert(0, '.')

try:
    from app import init_db
    print('✅ Successfully imported init_db function')
    
    # Test the initialization
    init_db()
    print('✅ Database initialization completed successfully!')
    
except ImportError as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
except SyntaxError as e:
    print(f'❌ Syntax error in app.py: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Database initialization failed: {e}')
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    print_status "Database initialization successful!"
else
    print_error "Database initialization failed. Check the error above."
    exit 1
fi

# Step 9: Test the Flask app startup
echo "🚀 Testing Flask app startup..."
timeout 10 python3 -c "
import sys
sys.path.insert(0, '.')

try:
    from app import app
    print('✅ Flask app imported successfully')
    
    with app.app_context():
        print('✅ Flask app context works')
        
    print('✅ Flask app startup test completed')
    
except Exception as e:
    print(f'❌ Flask app startup failed: {e}')
    sys.exit(1)
" &

wait $!

if [ $? -eq 0 ]; then
    print_status "Flask app startup test successful!"
else
    print_error "Flask app startup test failed."
    exit 1
fi

# Step 10: Check if Docker services are running
echo "🐳 Checking Docker services..."
if docker-compose -f docker-compose.dev.yml ps 2>/dev/null | grep -q "Up"; then
    print_status "Docker services are running"
else
    print_warning "Docker services not running. Starting them..."
    
    if [ -f "docker-compose.dev.yml" ]; then
        docker-compose -f docker-compose.dev.yml up -d
        sleep 5
        print_status "Docker services started"
    else
        print_warning "docker-compose.dev.yml not found. You may need to run the full setup."
    fi
fi

# Step 11: Final verification
echo "🧪 Running final verification..."

# Test health endpoint
echo "Testing Flask app..."
python3 app.py &
APP_PID=$!
sleep 3

# Check if app is responding
if curl -s http://localhost:5555/health | grep -q "healthy"; then
    print_status "Flask app is responding correctly!"
    
    # Test a few more endpoints
    echo "Testing API endpoints..."
    
    if curl -s http://localhost:5555/glossary/terms | grep -q "terms"; then
        print_status "Terms endpoint working"
    else
        print_warning "Terms endpoint may have issues"
    fi
    
    if curl -s http://localhost:5555/glossary/categories | grep -q "categories"; then
        print_status "Categories endpoint working"
    else
        print_warning "Categories endpoint may have issues"
    fi
    
else
    print_warning "Flask app may not be responding yet"
fi

# Stop the test app
kill $APP_PID 2>/dev/null
wait $APP_PID 2>/dev/null

echo ""
echo "🎉 Setup Fix Complete!"
echo "======================"
echo ""
print_status "Your Mardi Gras API is now properly configured!"
echo ""
echo "🚀 To start developing:"
echo "   ./start_dev_server.sh"
echo ""
echo "🧪 To test the API:"
echo "   ./test_api.sh"
echo ""
echo "📊 Available services:"
echo "   • API: http://localhost:5555"
echo "   • MailHog: http://localhost:8025"
echo "   • Redis: localhost:6379"
echo ""
echo "🔧 If you still have issues:"
echo "   1. Make sure you replaced app.py with the corrected version"
echo "   2. Check logs: tail -f logs/mardi_gras_api.log"
echo "   3. Restart services: docker-compose -f docker-compose.dev.yml restart"
echo ""

# Create a simple test script
cat > test_fixed_setup.sh << 'EOF'
#!/bin/bash
echo "🧪 Testing fixed setup..."

# Activate environment
source venv/bin/activate
source .env.local

# Test Python imports
python3 -c "
from app import app, db, User, Term, Category
print('✅ All imports successful')

with app.app_context():
    print(f'✅ Database tables: {len(db.metadata.tables)} tables')
    print(f'✅ Users: {User.query.count()}')
    print(f'✅ Terms: {Term.query.count()}')
    print(f'✅ Categories: {Category.query.count()}')
"

echo "✅ Setup test completed successfully!"
EOF

chmod +x test_fixed_setup.sh

print_status "Created test_fixed_setup.sh for verification"
echo ""
echo "Run './test_fixed_setup.sh' to verify everything is working!"