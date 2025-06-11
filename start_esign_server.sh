#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting eSign Server${NC}"
echo "===================="

# Change to project directory
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Create logs directory if it doesn't exist
mkdir -p logs

# Kill existing process if running
if [ -f .server.pid ]; then
    OLD_PID=$(cat .server.pid)
    if ps -p $OLD_PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping existing server (PID: $OLD_PID)...${NC}"
        kill $OLD_PID 2>/dev/null
        sleep 2
    fi
    rm .server.pid
fi

# Also check if port is in use
if lsof -Pi :8090 -sTCP:LISTEN -t >/dev/null ; then
    echo -e "${YELLOW}Port 8090 is in use, killing existing process...${NC}"
    lsof -ti:8090 | xargs kill -9 2>/dev/null
    sleep 1
fi

# Set environment variables
export PORT=8090
export LOG_LEVEL=debug
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=atharvaz
export DB_NAME=esign_db

echo -e "${YELLOW}Configuration:${NC}"
echo "  Port: $PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  Database: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
echo ""

# Start server
LOG_FILE="logs/server_$(date +%Y%m%d_%H%M%S).log"
echo -e "${YELLOW}Starting server...${NC}"

go run cmd/server/main_debug.go > $LOG_FILE 2>&1 &
PID=$!

# Save PID
echo $PID > .server.pid

# Wait a moment for server to start
sleep 3

# Check if server started successfully
if ps -p $PID > /dev/null; then
    echo -e "${GREEN}✓ Server started successfully${NC}"
    echo "  PID: $PID"
    echo "  Log file: $LOG_FILE"
    echo "  URL: http://localhost:8090"
    echo ""
    echo -e "${YELLOW}Useful commands:${NC}"
    echo "  tail -f $LOG_FILE          # View logs"
    echo "  curl http://localhost:8090/health  # Check health"
    echo "  kill $PID                          # Stop server"
    echo ""
    
    # Test health endpoint
    echo -e "${YELLOW}Testing health endpoint...${NC}"
    sleep 2
    if curl -s http://localhost:8090/health > /dev/null; then
        echo -e "${GREEN}✓ Health check passed${NC}"
    else
        echo -e "${RED}✗ Health check failed${NC}"
    fi
else
    echo -e "${RED}✗ Failed to start server${NC}"
    echo "Check the log file for errors:"
    echo "  tail -n 50 $LOG_FILE"
    rm .server.pid
    exit 1
fi