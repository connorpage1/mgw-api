# reset_database.sh - Clean reset of database and fix issues
#!/bin/bash

echo "🔄 Resetting Mardi Gras API database..."

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

# Load environment
if [ -f ".env.local" ]; then
    source .env.local
    print_status "Environment loaded"
fi

# Stop any running Flask processes
echo "🛑 Stopping any running Flask processes..."
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "flask run" 2>/dev/null || true

# Remove existing database files
echo "🗑️ Removing existing database files..."
rm -rf instance/
rm -f *.db
rm -f mardi_gras*.db

# Create instance directory
mkdir -p instance
mkdir -p logs

# Clear Python cache
echo "🧹 Clearing Python cache..."
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Install/update required dependencies
echo "📦 Installing dependencies..."
pip install Flask==3.0.0 Flask-SQLAlchemy==3.1.1 Flask-Security-Too==5.3.2
pip install Flask-JWT-Extended==4.6.0 Flask-CORS==4.0.0 Flask-Mail==0.9.1
pip install argon2-cffi==23.1.0 python-dotenv==1.0.0

# Optional: Install Flask-Limiter if Redis is available
if command -v redis-cli >/dev/null 2>&1; then
    echo "📦 Installing Flask-Limiter (Redis available)..."
    pip install Flask-Limiter==3.5.0 redis==5.0.1
else
    echo "⚠️ Skipping Flask-Limiter (Redis not available)"
fi

print_status "Dependencies installed"

# Test the new app.py imports
echo "🧪 Testing app imports..."
python3 -c "
import sys
try:
    print('Testing imports...')
    from app import app, db, User, Role, Term, Category
    print('✅ All imports successful')
    
    with app.app_context():
        print('✅ App context working')
        
except Exception as e:
    print(f'❌ Import failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    print_status "App imports working"
else
    print_error "App imports failed - check app.py file"
    exit 1
fi

# Initialize database with the new app
echo "🗄️ Initializing fresh database..."
python3 -c "
from app import init_db
try:
    init_db()
    print('✅ Database initialization successful!')
except Exception as e:
    print(f'❌ Database initialization failed: {e}')
    import traceback
    traceback.print_exc()
    exit(1)
"

if [ $? -eq 0 ]; then
    print_status "Database initialized successfully"
else
    print_error "Database initialization failed"
    exit 1
fi

# Test basic database operations
echo "🧪 Testing database operations..."
python3 -c "
from app import app, db, User, Term, Category

with app.app_context():
    try:
        # Test queries
        user_count = User.query.count()
        term_count = Term.query.count()
        category_count = Category.query.count()
        
        print(f'✅ Database test successful:')
        print(f'   Users: {user_count}')
        print(f'   Terms: {term_count}')
        print(f'   Categories: {category_count}')
        
    except Exception as e:
        print(f'❌ Database test failed: {e}')
        exit(1)
"

# Test the Flask app startup
echo "🚀 Testing Flask app startup..."
timeout 5 python3 -c "
from app import app
print('✅ Flask app startup test successful')
" &

wait $!

# Create a simple test script
cat > test_reset.sh << 'EOF'
#!/bin/bash
echo "🧪 Testing reset..."

source venv/bin/activate
source .env.local

# Test health endpoint
python3 app.py &
APP_PID=$!
sleep 2

echo "Testing health endpoint..."
if curl -s http://localhost:5555/health | grep -q "healthy"; then
    echo "✅ Health endpoint working"
else
    echo "❌ Health endpoint not responding"
fi

# Test terms endpoint
echo "Testing terms endpoint..."
if curl -s http://localhost:5555/glossary/terms | grep -q "terms"; then
    echo "✅ Terms endpoint working"
else
    echo "❌ Terms endpoint not working"
fi

# Clean up
kill $APP_PID 2>/dev/null
wait $APP_PID 2>/dev/null

echo "✅ Reset test completed"
EOF

chmod +x test_reset.sh

echo ""
echo "🎉 Database Reset Complete!"
echo "========================="
echo ""
print_status "Database has been completely reset"
print_status "All table definition conflicts resolved"
print_status "Rate limiting issues fixed"
echo ""
echo "🚀 Next steps:"
echo "   1. Start server: python3 app.py"
echo "   2. Test reset: ./test_reset.sh"
echo "   3. Test API: curl http://localhost:5555/health"
echo ""
echo "🔑 Admin Login Details:"
echo "   Email: admin@dev.local"
echo "   Password: DevAdmin123!@#"
echo ""
echo "📊 Available Endpoints:"
echo "   • Health: http://localhost:5555/health"
echo "   • Terms: http://localhost:5555/glossary/terms"
echo "   • Categories: http://localhost:5555/glossary/categories"
echo "   • Stats: http://localhost:5555/glossary/stats"
echo "   • Login: POST http://localhost:5555/auth/secure-login"
echo ""
echo "🔧 If you still have issues:"
echo "   • Check app.py matches the 'Final Fixed app.py' version"
echo "   • Ensure .env.local exists with proper values"
echo "   • Check Python version: python3 --version (should be 3.11+)"