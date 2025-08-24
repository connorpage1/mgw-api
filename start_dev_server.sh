#!/bin/bash
echo "🚀 Starting Mardi Gras API Development Server..."

# Load environment
source .env.local
source venv/bin/activate

# Start the Flask app
echo "Starting on http://localhost:5555"
echo "Press Ctrl+C to stop"
python app.py
