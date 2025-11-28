#!/bin/bash
# Startup script for the backend server
# This script starts the FastAPI backend server with proper configuration

cd "$(dirname "$0")"

echo "Starting Report Generator Backend Server..."
echo "=========================================="

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
elif [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Check if .env file exists
ENV_FILE="Automation/backend/.env"
if [ ! -f "$ENV_FILE" ]; then
    echo "⚠️  Warning: .env file not found at $ENV_FILE"
    echo "   Please create it with required environment variables"
fi

# Get port from environment or use default
PORT=${PORT:-8000}
HOST=${HOST:-0.0.0.0}

echo "Starting server on $HOST:$PORT..."
echo ""

# Start uvicorn server
uvicorn app:app \
    --host "$HOST" \
    --port "$PORT" \
    --reload \
    --log-level info \
    --access-log

