#!/bin/bash

echo "🚀 Starting Mardi Gras API..."

# Print environment info
echo "Environment: ${FLASK_ENV:-development}"
echo "Python version: $(python --version)"
echo "Database URL configured: ${DATABASE_URL:+Yes}"

# Run the Flask app with gunicorn
exec gunicorn app:app \
    --bind 0.0.0.0:${PORT:-5000} \
    --workers 1 \
    --timeout 120 \
    --max-requests 1000 \
    --preload \
    --access-logfile - \
    --error-logfile -