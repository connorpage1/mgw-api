# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Application Management
- **Run development server**: `python app.py`
- **Initialize database**: `python init_api_db.py` (creates tables and sample data)

### Production Deployment
- **Railway deployment**: Uses `gunicorn app:app` (defined in Procfile)
- **Database initialization**: Run `python init_api_db.py` after first deployment

## Architecture Overview

### Application Structure
This is a **pure Flask API service** that integrates with OAuth2 SSO authentication:

- **App Factory Pattern**: `create_app()` function in `app.py` initializes all components
- **Blueprint Organization**: Routes split across functional modules in `/routes/`
- **Model Layer**: SQLAlchemy models in `/models/` with clear separation by domain
- **Service Layer**: OAuth2 integration and external services in `/services/`

### Key Components

#### OAuth2 Integration
- **Token-based auth**: OAuth2Service validates JWT tokens from mardi-gras-auth service
- **Middleware decorators**: `require_oauth2()` and `require_admin()` for endpoint protection
- **No local authentication**: All auth handled by separate SSO service

#### Database Architecture
- **Development**: SQLite (`instance/mardi_gras_dev.db`)
- **Production**: PostgreSQL via Railway
- **Models**: Glossary (Terms/Categories), File management, App tokens (no User models)

#### Route Blueprint Structure
- `api_routes.py` - RESTful API endpoints (OAuth2 protected admin functions)
- `glossary_routes.py` - Public glossary API (no auth required)
- `file_routes.py` - File upload/management (OAuth2 protected)
- `pixie_routes.py` - 3D viewer integration (mixed auth)

### Configuration Management
- **Environment-based config** in `/config/__init__.py`
- **OAuth2 settings**: `AUTH_SERVICE_URL`, `JWT_SECRET_KEY`
- **Railway deployment**: Automatic PostgreSQL URL handling
- **CORS**: Configured for admin.mardigrasworld.com and auth.mardigrasworld.com

### File Organization Patterns
- **Models**: Domain-separated (`glossary.py`, `files.py`, `app.py`) - NO user.py
- **Services**: OAuth2 integration (`oauth2_service.py`), external services (`s3_service.py`, `email_service.py`)
- **Templates**: Only email templates in `/templates/email/` - NO admin templates
- **Static assets**: Removed - frontend handled by separate React app

### Integration Points
- **OAuth2 SSO**: Token validation with mardi-gras-auth service
- **AWS S3**: File storage with configurable bucket
- **Email**: SMTP-based notifications (minimal usage)
- **External APIs**: Pixie 3D viewer integration
- **CORS**: Configured for React admin frontend

### Development Notes
- **Pure API**: No HTML templates or forms - JSON responses only
- **Token validation**: OAuth2 middleware validates JWT tokens from auth service
- **Environment requirements**: Must set AUTH_SERVICE_URL and JWT_SECRET_KEY
- **Database migrations**: Manual approach - update models and run init script

### Security Model
- **No local auth**: All authentication delegated to mardi-gras-auth service
- **Token-based**: JWT tokens validated on each protected request
- **Scoped access**: OAuth2 scopes control API access levels
- **CORS protection**: Restricts origins to authorized domains