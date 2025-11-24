# 🎭 Mardi Gras API

A pure Flask API service for managing Mardi Gras terminology and glossary content. Integrates with OAuth2 SSO authentication and provides RESTful endpoints for consumption by the React admin frontend.

## 🚀 Live Application

- **Production URL:** https://mgw-api-production.up.railway.app
- **API Documentation:** Available at root endpoint
- **Health Check:** https://mgw-api-production.up.railway.app/health

## ✨ Features

- 📚 **Glossary API**: Full CRUD operations for terms and categories via REST API
- 🔐 **OAuth2 Integration**: Token-based authentication with mardi-gras-auth service
- 📊 **Public API**: Open endpoints for glossary consumption
- 🔍 **Search & Filter**: Advanced filtering for terms and categories
- 📁 **File Management**: STL and video file upload/management APIs
- 🎭 **Pixie Integration**: 3D viewer API endpoints
- 🛡️ **CORS Protection**: Configured for authorized origins
- ⚡ **Pure JSON**: All responses in JSON format for frontend consumption

## 🏗️ Architecture

- **API Service**: Flask + SQLAlchemy + PostgreSQL
- **Authentication**: OAuth2 integration with mardi-gras-auth service
- **Frontend**: Separate React application (admin.mardigrasworld.com)
- **Token Validation**: JWT with PyJWT
- **Email**: Flask-Mail with SMTP (minimal usage)
- **Deployment**: Railway.app with PostgreSQL service

## 📋 Requirements

- Python 3.8+
- PostgreSQL (production) / SQLite (development)
- Flask and extensions (see requirements.txt)

## 🔧 Installation & Setup

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd mardi-gras-api
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables**
   ```bash
   export AUTH_SERVICE_URL=https://auth.mardigrasworld.com
   export JWT_SECRET_KEY=your-shared-jwt-secret
   export DATABASE_URL=sqlite:///instance/mardi_gras_dev.db
   ```

5. **Initialize database**
   ```bash
   python init_api_db.py
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

### Production Deployment (Railway)

The application is configured for Railway deployment with:
- PostgreSQL database service
- Environment variables for configuration
- Gunicorn WSGI server
- Health check endpoint

## 🔐 Authentication

### Admin Login
- **URL**: `/login`
- **Default Credentials**: 
  - Email: `admin@mardigras.com`
  - Password: See deployment logs for generated password

### API Authentication
- JWT tokens required for admin API endpoints
- Bearer token authentication
- Token expiration: 24 hours

## 📡 API Endpoints

### Public Endpoints

#### Glossary Terms
- **GET** `/glossary/terms` - Get all terms with filtering
  - Query parameters: `difficulty`, `category`, `search`, `sort`, `limit`, `offset`
- **GET** `/glossary/term/<slug>` - Get specific term by slug
- **GET** `/glossary/random` - Get random term

#### Categories
- **GET** `/glossary/categories` - Get all active categories

#### Statistics
- **GET** `/glossary/stats` - Get API statistics and metrics

#### Health Check
- **GET** `/health` - Application health status

### Admin Web Interface

#### Dashboard
- **GET** `/admin` - Redirect to main dashboard
- **GET** `/admin/dashboard` - Main admin dashboard
- **GET** `/admin/glossary/dashboard` - Glossary-specific dashboard

#### Term Management
- **GET** `/admin/glossary/terms` - List all terms with sorting/filtering
- **GET** `/admin/glossary/terms/new` - New term form
- **POST** `/admin/glossary/terms/new` - Create new term
- **GET** `/admin/glossary/terms/<id>/edit` - Edit term form
- **POST** `/admin/glossary/terms/<id>/edit` - Update term
- **POST** `/admin/glossary/terms/<id>/delete` - Delete term

#### Category Management
- **GET** `/admin/glossary/categories` - List all categories
- **GET** `/admin/glossary/categories/new` - New category form
- **POST** `/admin/glossary/categories/new` - Create new category
- **GET** `/admin/glossary/categories/<id>/edit` - Edit category form
- **POST** `/admin/glossary/categories/<id>/edit` - Update category
- **POST** `/admin/glossary/categories/<id>/delete` - Delete category
- **POST** `/admin/glossary/categories/<id>/restore` - Restore deleted category

#### User Management
- **GET** `/admin/users` - List all users
- **GET** `/admin/users/new` - New user form
- **POST** `/admin/users/new` - Create new user
- **GET** `/admin/users/<id>/edit` - Edit user form
- **POST** `/admin/users/<id>/edit` - Update user
- **GET** `/admin/users/<id>/delete-confirm` - Delete confirmation page
- **POST** `/admin/users/<id>/delete` - Delete user
- **GET** `/admin/users/<id>/reset-password` - Reset password form
- **POST** `/admin/users/<id>/reset-password` - Send password reset email

#### Bulk Operations
- **GET** `/admin/glossary/bulk-upload` - Bulk upload form
- **POST** `/admin/glossary/bulk-upload` - Process CSV upload

#### Account Management
- **GET** `/admin/account` - Account settings form
- **POST** `/admin/account` - Update account settings
- **GET** `/admin/logout` - Logout

### Admin API Endpoints (JWT Required)

#### Terms API
- **GET** `/admin/terms` - List terms (JSON)
- **POST** `/admin/terms` - Create term (JSON)
- **GET** `/admin/terms/<id>` - Get specific term (JSON)
- **PUT** `/admin/terms/<id>` - Update term (JSON)
- **DELETE** `/admin/terms/<id>` - Delete term (JSON)

#### Categories API
- **GET** `/admin/categories` - List categories (JSON)
- **POST** `/admin/categories` - Create category (JSON)
- **PUT** `/admin/categories/<id>` - Update category (JSON)
- **DELETE** `/admin/categories/<id>` - Delete category (JSON)

### Authentication Endpoints
- **GET** `/login` - Login form
- **POST** `/login` - Process login
- **POST** `/auth/logout` - Logout (JWT required)
- **GET** `/set-password/<token>` - Password reset form
- **POST** `/set-password/<token>` - Set new password

## 📊 Data Models

### Term
```json
{
  "id": 1,
  "term": "Krewe",
  "pronunciation": "KROO",
  "definition": "An organization that organizes Mardi Gras parades",
  "difficulty": "tourist",
  "category_id": 2,
  "slug": "krewe",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:00:00Z"
}
```

### Category
```json
{
  "id": 1,
  "name": "Core Terms",
  "slug": "core-terms",
  "description": "Essential Mardi Gras terminology",
  "sort_order": 0,
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z"
}
```

### User
```json
{
  "id": 1,
  "email": "admin@mardigras.com",
  "first_name": "Admin",
  "last_name": "User",
  "active": true,
  "roles": ["superadmin"],
  "created_at": "2024-01-01T00:00:00Z"
}
```

## 🛡️ Security Features

- **CSRF Protection**: All forms protected against CSRF attacks
- **Rate Limiting**: Login attempt protection (15 failed attempts = 15-minute lockout)
- **Password Hashing**: Argon2 secure password hashing
- **JWT Tokens**: Secure API authentication with expiration
- **Role-based Access**: Granular permissions (superadmin, admin, editor, viewer)
- **Input Validation**: Server-side validation for all inputs
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries

## 📈 Monitoring

- **Health Check**: `/health` endpoint for monitoring
- **Statistics**: Built-in analytics for terms, categories, and usage
- **Logging**: Comprehensive application and error logging

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | Auto-generated |
| `JWT_SECRET_KEY` | JWT signing key | Auto-generated |
| `DATABASE_URL` | PostgreSQL connection string | SQLite (dev) |
| `FLASK_ENV` | Environment (production/development) | development |
| `FLASK_DEBUG` | Debug mode | False |
| `MAIL_SERVER` | SMTP server | smtp.gmail.com |
| `MAIL_USERNAME` | SMTP username | - |
| `MAIL_PASSWORD` | SMTP password | - |
| `CORS_ORIGINS` | Allowed CORS origins | - |

## 🧪 Testing

Run the test suite:
```bash
pytest
```

Test specific functionality:
```bash
pytest tests/test_api.py
pytest tests/test_auth.py
```

## 📁 Project Structure

```
mardi-gras-api/
├── app.py                 # Main Flask application
├── init_production_db.py  # Database initialization
├── requirements.txt       # Python dependencies
├── railway.json          # Railway deployment config
├── start.sh              # Production startup script
├── Procfile              # Railway process file
├── templates/            # Jinja2 templates
│   └── admin/           # Admin interface templates
├── static/              # Static assets (CSS, JS, images)
└── tests/               # Test suite
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🎭 About Mardi Gras

This API serves the Mardi Gras World educational platform, providing comprehensive terminology and cultural information about New Orleans' most famous celebration.

---

**🤖 Generated with [Claude Code](https://claude.ai/code)**