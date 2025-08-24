# dev_quickstart.sh - Complete Development Environment Setup
#!/bin/bash

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${PURPLE}"
    echo "============================================"
    echo " $1"
    echo "============================================"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_status "Python $PYTHON_VERSION found"
    else
        print_error "Python 3 is required. Please install from python.org"
        exit 1
    fi
    
    # Check Docker
    if command -v docker &> /dev/null; then
        print_status "Docker found"
    else
        print_error "Docker is required. Please install from docker.com"
        exit 1
    fi
    
    # Check Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_status "Docker Compose found"
    else
        print_error "Docker Compose is required"
        exit 1
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        print_status "Git found"
    else
        print_warning "Git not found. Version control recommended"
    fi
}

# Create project structure
create_project_structure() {
    print_header "Creating Project Structure"
    
    # Create directories
    mkdir -p {tests/{unit,integration,security,performance,e2e},logs,instance,templates/{admin,security},static/{css,js}}
    
    # Create .gitignore
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
env.bak/
venv.bak/

# Environment variables
.env
.env.local
.env.production
.env.test

# Database
*.db
*.sqlite3
instance/

# Logs
logs/
*.log

# Test results
htmlcov/
.coverage
.pytest_cache/
test_report.html
security_report.json
safety_report.json

# IDE
.vscode/
.idea/
*.swp
*.swo

# Docker
docker-compose.override.yml

# OS
.DS_Store
Thumbs.db

# Backup files
*.bak
*.backup
EOF

    print_status "Project structure created"
}

# Create development environment file
create_dev_environment() {
    print_header "Creating Development Environment"
    
    cat > .env.local << 'EOF'
# Local Development Configuration
FLASK_ENV=development
FLASK_DEBUG=True

# Security Keys (DEVELOPMENT ONLY - NOT FOR PRODUCTION)
SECRET_KEY=dev_secret_key_32_characters_long_12345678
JWT_SECRET_KEY=dev_jwt_secret_key_32_characters_long_87654321
SECURITY_PASSWORD_SALT=dev_salt_32_characters_long_abcdef123456

# Local Database (SQLite for development)
DATABASE_URL=sqlite:///instance/mardi_gras_dev.db

# Local Redis (Docker)
REDIS_URL=redis://:devpass@localhost:6379/0

# Admin User (Development)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@dev.local
ADMIN_PASSWORD=DevAdmin123!@#

# Email (Local - using MailHog)
MAIL_SERVER=localhost
MAIL_PORT=1025
MAIL_USE_TLS=false
MAIL_USERNAME=dev@test.local
MAIL_PASSWORD=devpass
SECURITY_EMAIL_SENDER=noreply@dev.local

# CORS (Allow local development)
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000,http://localhost:5173

# Rate Limiting (Relaxed for development)
RATELIMIT_STORAGE_URL=redis://:devpass@localhost:6379/1

# Logging
LOG_LEVEL=DEBUG
EOF

    print_status "Development environment file created (.env.local)"
}

# Create Docker Compose for development services
create_docker_compose() {
    print_header "Creating Development Services Configuration"
    
    cat > docker-compose.dev.yml << 'EOF'
version: '3.8'

services:
  # Redis for local development
  dev_redis:
    image: redis:7-alpine
    container_name: mardi_gras_dev_redis
    command: redis-server --requirepass devpass --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - dev_redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "devpass", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  # MailHog for email testing
  mailhog:
    image: mailhog/mailhog:latest
    container_name: mardi_gras_dev_mail
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "1025"]
      interval: 10s
      timeout: 3s
      retries: 5

  # Optional: PostgreSQL for production-like development
  dev_postgres:
    image: postgres:15-alpine
    container_name: mardi_gras_dev_postgres
    environment:
      POSTGRES_DB: mardi_gras_dev
      POSTGRES_USER: devuser
      POSTGRES_PASSWORD: devpass
    ports:
      - "5432:5432"
    volumes:
      - dev_postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U devuser -d mardi_gras_dev"]
      interval: 10s
      timeout: 5s
      retries: 5
    profiles:
      - postgres  # Optional profile

  # Optional: pgAdmin for database management
  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: mardi_gras_dev_pgadmin
    environment:
      PGADMIN_DEFAULT_EMAIL: admin@dev.local
      PGADMIN_DEFAULT_PASSWORD: devpass
    ports:
      - "5050:80"
    depends_on:
      - dev_postgres
    profiles:
      - tools

volumes:
  dev_redis_data:
  dev_postgres_data:

networks:
  default:
    name: mardi_gras_dev_network
EOF

    print_status "Docker Compose configuration created"
}

# Setup Python virtual environment
setup_python_environment() {
    print_header "Setting Up Python Environment"
    
    # Create virtual environment
    print_info "Creating virtual environment..."
    python3 -m venv venv
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source venv/bin/activate
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip
    
    # Install dependencies
    if [ -f "requirements.txt" ]; then
        print_info "Installing dependencies from requirements.txt..."
        pip install -r requirements.txt
    else
        print_info "Installing core dependencies..."
        pip install Flask==3.0.0 Flask-SQLAlchemy==3.1.1 Flask-Security-Too==5.3.2 \
                   Flask-JWT-Extended==4.6.0 Flask-Limiter==3.5.0 Flask-CORS==4.0.0 \
                   argon2-cffi==23.1.0 redis==5.0.1 python-dotenv==1.0.0
    fi
    
    print_status "Python environment setup complete"
}

# Start development services
start_services() {
    print_header "Starting Development Services"
    
    print_info "Starting Docker services..."
    docker-compose -f docker-compose.dev.yml up -d
    
    # Wait for services to be ready
    print_info "Waiting for services to be ready..."
    sleep 10
    
    # Check service health
    if docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
        print_status "Development services started successfully"
    else
        print_error "Some services failed to start"
        docker-compose -f docker-compose.dev.yml logs
        exit 1
    fi
}

# Initialize the application
initialize_application() {
    print_header "Initializing Application"
    
    # Load environment
    source .env.local
    source venv/bin/activate
    
    # Check if app.py exists
    if [ ! -f "app.py" ]; then
        print_error "app.py not found. Please ensure all project files are in place."
        print_info "You need to copy the ultra-secure app.py from the artifacts."
        exit 1
    fi
    
    # Initialize database
    print_info "Initializing database..."
    python -c "
try:
    from app import init_db
    init_db()
    print('✅ Database initialized successfully!')
except Exception as e:
    print(f'❌ Database initialization failed: {e}')
    exit(1)
"
    
    # Seed database if script exists
    if [ -f "enhanced_seed_database.py" ]; then
        print_info "Seeding database with sample data..."
        python enhanced_seed_database.py
    else
        print_warning "Seed script not found. You'll need to create data manually."
    fi
    
    print_status "Application initialized"
}

# Create helper scripts
create_helper_scripts() {
    print_header "Creating Helper Scripts"
    
    # Development server script
    cat > start_dev_server.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting Mardi Gras API Development Server..."

# Load environment
source .env.local
source venv/bin/activate

# Start the Flask app
echo "Starting on http://localhost:5555"
echo "Press Ctrl+C to stop"
python app.py
EOF

    # Test runner script
    cat > run_dev_tests.sh << 'EOF'
#!/bin/bash
echo "🧪 Running Development Tests..."

source venv/bin/activate

# Run quick development tests
if [ -d "tests" ]; then
    echo "Running unit tests..."
    pytest tests/unit/ -v --tb=short
    
    echo "Running integration tests..."
    pytest tests/integration/ -v --tb=short
else
    echo "⚠️ Test directory not found"
fi
EOF

    # API test script
    cat > test_api.sh << 'EOF'
#!/bin/bash
echo "🌐 Testing API Endpoints..."

API_URL="http://localhost:5555"

echo "Testing health endpoint..."
curl -s "$API_URL/health" | python -m json.tool

echo -e "\nTesting terms endpoint..."
curl -s "$API_URL/glossary/terms?limit=3" | python -m json.tool

echo -e "\nTesting categories endpoint..."
curl -s "$API_URL/glossary/categories" | python -m json.tool

echo -e "\nTesting authentication..."
curl -s -X POST "$API_URL/auth/secure-login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@dev.local","password":"DevAdmin123!@#"}' | python -m json.tool
EOF

    # Cleanup script
    cat > cleanup_dev.sh << 'EOF'
#!/bin/bash
echo "🧹 Cleaning up development environment..."

# Stop Docker services
docker-compose -f docker-compose.dev.yml down -v

# Clean up development files
rm -rf instance/
rm -rf logs/
rm -rf htmlcov/
rm -rf .pytest_cache/
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Remove Docker volumes
docker volume rm $(docker volume ls -q | grep mardi_gras_dev) 2>/dev/null || true

echo "✅ Development environment cleaned up"
EOF

    # Make scripts executable
    chmod +x start_dev_server.sh run_dev_tests.sh test_api.sh cleanup_dev.sh
    
    print_status "Helper scripts created"
}

# Create development documentation
create_dev_docs() {
    print_header "Creating Development Documentation"
    
    cat > README_DEV.md << 'EOF'
# Mardi Gras API - Development Guide

## Quick Start

1. **Start development services:**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

2. **Activate Python environment:**
   ```bash
   source venv/bin/activate
   ```

3. **Start the development server:**
   ```bash
   ./start_dev_server.sh
   ```

4. **Test the API:**
   ```bash
   ./test_api.sh
   ```

## Development URLs

- **API**: http://localhost:5555
- **MailHog UI**: http://localhost:8025 (email testing)
- **pgAdmin**: http://localhost:5050 (database management, if using PostgreSQL)

## Development Commands

- **Start server**: `./start_dev_server.sh`
- **Run tests**: `./run_dev_tests.sh`
- **Test API**: `./test_api.sh`
- **Clean up**: `./cleanup_dev.sh`

## Project Structure

```
mardi-gras-api/
├── app.py                 # Main application
├── requirements.txt       # Python dependencies
├── .env.local            # Development environment
├── docker-compose.dev.yml # Development services
├── tests/                # Test suite
├── logs/                 # Application logs
└── instance/             # Database and app data
```

## Development Features

- ✅ **Hot Reload**: Code changes automatically restart the server
- ✅ **Debug Mode**: Detailed error pages and debugging
- ✅ **Email Testing**: MailHog captures all emails
- ✅ **Redis Caching**: Full caching functionality
- ✅ **Security Testing**: All security features enabled
- ✅ **Database Management**: SQLite for easy development

## API Testing

### Authentication
```bash
# Login
curl -X POST http://localhost:5555/auth/secure-login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@dev.local","password":"DevAdmin123!@#"}'

# Use the returned access_token for authenticated requests
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:5555/admin/terms
```

### Public Endpoints
```bash
# Get terms
curl http://localhost:5555/glossary/terms

# Search terms
curl "http://localhost:5555/glossary/terms?search=mardi"

# Get categories
curl http://localhost:5555/glossary/categories

# Get single term
curl http://localhost:5555/glossary/term/mardi-gras
```

## Troubleshooting

### Services won't start
```bash
# Check Docker status
docker-compose -f docker-compose.dev.yml ps

# View logs
docker-compose -f docker-compose.dev.yml logs

# Restart services
docker-compose -f docker-compose.dev.yml restart
```

### Database issues
```bash
# Reset database
rm instance/mardi_gras_dev.db
python -c "from app import init_db; init_db()"
python enhanced_seed_database.py
```

### Python environment issues
```bash
# Recreate virtual environment
rm -rf venv/
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
EOF

    print_status "Development documentation created (README_DEV.md)"
}

# Final setup and verification
verify_setup() {
    print_header "Verifying Development Setup"
    
    # Check if services are running
    print_info "Checking Docker services..."
    if docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
        print_status "Docker services are running"
    else
        print_warning "Some Docker services may not be ready"
    fi
    
    # Check Redis connectivity
    print_info "Testing Redis connection..."
    if docker-compose -f docker-compose.dev.yml exec -T dev_redis redis-cli -a devpass ping 2>/dev/null | grep -q "PONG"; then
        print_status "Redis is accessible"
    else
        print_warning "Redis connection test failed"
    fi
    
    # Check if MailHog is accessible
    print_info "Testing MailHog..."
    if curl -s http://localhost:8025/api/v2/messages &>/dev/null; then
        print_status "MailHog is accessible"
    else
        print_warning "MailHog may not be ready yet"
    fi
    
    # Check Python environment
    if [ -f "venv/bin/activate" ]; then
        print_status "Python virtual environment is ready"
    else
        print_warning "Python virtual environment may have issues"
    fi
    
    # Check if app.py exists
    if [ -f "app.py" ]; then
        print_status "Application file found"
    else
        print_error "app.py not found - you need to add the application files"
    fi
}

# Display next steps
show_next_steps() {
    print_header "Development Environment Ready! 🎉"
    
    echo -e "${GREEN}"
    echo "Your Mardi Gras API development environment is set up!"
    echo ""
    echo "📋 Next Steps:"
    echo ""
    echo "1. Add the application files:"
    echo "   • Copy the ultra-secure app.py from the artifacts"
    echo "   • Copy requirements.txt with all dependencies"
    echo "   • Copy the testing files and configurations"
    echo ""
    echo "2. Start developing:"
    echo "   • Run: ./start_dev_server.sh"
    echo "   • API will be at: http://localhost:5555"
    echo ""
    echo "3. Test your API:"
    echo "   • Run: ./test_api.sh"
    echo "   • Or use: curl http://localhost:5555/health"
    echo ""
    echo "4. Development tools:"
    echo "   • MailHog UI: http://localhost:8025"
    echo "   • Redis: localhost:6379 (password: devpass)"
    echo ""
    echo "5. Run tests:"
    echo "   • Run: ./run_dev_tests.sh"
    echo ""
    echo "📁 Important files created:"
    echo "   • .env.local (development environment)"
    echo "   • docker-compose.dev.yml (services)"
    echo "   • start_dev_server.sh (start server)"
    echo "   • test_api.sh (test endpoints)"
    echo "   • cleanup_dev.sh (cleanup environment)"
    echo "   • README_DEV.md (development guide)"
    echo ""
    echo "🔧 Helpful commands:"
    echo "   • Start: ./start_dev_server.sh"
    echo "   • Test: ./test_api.sh"
    echo "   • Clean: ./cleanup_dev.sh"
    echo ""
    echo "🐛 Troubleshooting:"
    echo "   • Check logs: docker-compose -f docker-compose.dev.yml logs"
    echo "   • Restart services: docker-compose -f docker-compose.dev.yml restart"
    echo "   • Full reset: ./cleanup_dev.sh && ./dev_quickstart.sh"
    echo -e "${NC}"
    
    if [ ! -f "app.py" ]; then
        echo ""
        print_warning "Remember to add the application files before starting the server!"
        echo ""
        echo "Files you need to add:"
        echo "  • app.py (ultra-secure Flask application)"
        echo "  • requirements.txt (Python dependencies)"
        echo "  • enhanced_seed_database.py (database seeding)"
        echo "  • All testing files and configurations"
    fi
}

# Main execution
main() {
    echo -e "${PURPLE}"
    echo "🚀 Mardi Gras API - Development Environment Setup"
    echo "================================================="
    echo -e "${NC}"
    echo ""
    
    check_prerequisites
    create_project_structure
    create_dev_environment
    create_docker_compose
    setup_python_environment
    start_services
    create_helper_scripts
    create_dev_docs
    
    # Only initialize if app.py exists
    if [ -f "app.py" ]; then
        initialize_application
    else
        print_warning "Skipping app initialization - app.py not found"
        print_info "Add the application files, then run: python -c 'from app import init_db; init_db()'"
    fi
    
    verify_setup
    show_next_steps
}

# Run main function
main "$@"