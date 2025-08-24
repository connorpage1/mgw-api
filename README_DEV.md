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
