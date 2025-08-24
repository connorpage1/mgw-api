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
