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
