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
