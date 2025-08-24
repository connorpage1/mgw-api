
# Mardi Gras Glossary API Documentation

## Base URL
https://api.mardigrasworld.com

## Authentication

### JWT Authentication (for admin operations)
```bash
# Login to get JWT token
curl -X POST https://api.mardigrasworld.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your_password"}'

# Use JWT token in subsequent requests
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  https://api.mardigrasworld.com/admin/terms
```

### API Key Authentication (for public API access)
```bash
# Use API key in header
curl -H "X-API-Key: YOUR_API_KEY" \
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
