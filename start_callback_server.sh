#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Callback Test Server${NC}"
echo "============================"

# Change to project directory
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Create logs directory if it doesn't exist
mkdir -p logs

# Kill existing process if running
if [ -f .callback.pid ]; then
    OLD_PID=$(cat .callback.pid)
    if ps -p $OLD_PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping existing callback server (PID: $OLD_PID)...${NC}"
        kill $OLD_PID 2>/dev/null
        sleep 2
    fi
    rm .callback.pid
fi

# Also check if port is in use
if lsof -Pi :8091 -sTCP:LISTEN -t >/dev/null ; then
    echo -e "${YELLOW}Port 8091 is in use, killing existing process...${NC}"
    lsof -ti:8091 | xargs kill -9 2>/dev/null
    sleep 1
fi

# Start callback server
LOG_FILE="logs/callback_$(date +%Y%m%d_%H%M%S).log"
echo -e "${YELLOW}Starting callback server on port 8091...${NC}"

go run test-callback-server.go > $LOG_FILE 2>&1 &
PID=$!

# Save PID
echo $PID > .callback.pid

# Wait a moment for server to start
sleep 2

# Check if server started successfully
if ps -p $PID > /dev/null; then
    echo -e "${GREEN}✓ Callback server started successfully${NC}"
    echo "  PID: $PID"
    echo "  Log file: $LOG_FILE"
    echo "  URL: http://localhost:8091"
    echo ""
    echo -e "${YELLOW}This server will:${NC}"
    echo "  - Receive eSign callbacks on /callback"
    echo "  - Display decoded responses"
    echo "  - Log all callback data"
    echo ""
    echo -e "${YELLOW}Useful commands:${NC}"
    echo "  tail -f $LOG_FILE          # View logs"
    echo "  curl http://localhost:8091 # View web interface"
    echo "  kill $PID                  # Stop server"
    echo ""
    
    # Test if server is responding
    if curl -s http://localhost:8091 > /dev/null; then
        echo -e "${GREEN}✓ Callback server is responding${NC}"
    else
        echo -e "${RED}✗ Callback server not responding${NC}"
    fi
else
    echo -e "${RED}✗ Failed to start callback server${NC}"
    echo "Check the log file for errors:"
    echo "  tail -n 50 $LOG_FILE"
    rm .callback.pid
    exit 1
fi