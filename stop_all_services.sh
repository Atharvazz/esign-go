#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${RED}Stopping All eSign Services${NC}"
echo "=========================="

# Change to project directory
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Stop main server
if [ -f .server.pid ]; then
    PID=$(cat .server.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping eSign server (PID: $PID)...${NC}"
        kill $PID 2>/dev/null
        sleep 1
        
        # Force kill if still running
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}Force killing eSign server...${NC}"
            kill -9 $PID 2>/dev/null
        fi
        echo -e "${GREEN}✓ eSign server stopped${NC}"
    else
        echo -e "${YELLOW}eSign server not running (stale PID file)${NC}"
    fi
    rm .server.pid
else
    echo -e "${YELLOW}No eSign server PID file found${NC}"
fi

# Stop callback server
if [ -f .callback.pid ]; then
    PID=$(cat .callback.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping callback server (PID: $PID)...${NC}"
        kill $PID 2>/dev/null
        sleep 1
        
        # Force kill if still running
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}Force killing callback server...${NC}"
            kill -9 $PID 2>/dev/null
        fi
        echo -e "${GREEN}✓ Callback server stopped${NC}"
    else
        echo -e "${YELLOW}Callback server not running (stale PID file)${NC}"
    fi
    rm .callback.pid
else
    echo -e "${YELLOW}No callback server PID file found${NC}"
fi

# Kill any remaining processes on our ports
echo -e "${YELLOW}Checking for processes on ports...${NC}"

if lsof -Pi :8090 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${YELLOW}Killing processes on port 8090...${NC}"
    lsof -ti:8090 | xargs kill -9 2>/dev/null
    echo -e "${GREEN}✓ Port 8090 cleared${NC}"
fi

if lsof -Pi :8091 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${YELLOW}Killing processes on port 8091...${NC}"
    lsof -ti:8091 | xargs kill -9 2>/dev/null
    echo -e "${GREEN}✓ Port 8091 cleared${NC}"
fi

# Check for any go run processes
GO_PROCESSES=$(pgrep -f "go run cmd/server/main_debug.go|go run test-callback-server.go" | wc -l)
if [ $GO_PROCESSES -gt 0 ]; then
    echo -e "${YELLOW}Found $GO_PROCESSES go run process(es), killing...${NC}"
    pkill -f "go run cmd/server/main_debug.go"
    pkill -f "go run test-callback-server.go"
    echo -e "${GREEN}✓ Go processes killed${NC}"
fi

echo ""
echo -e "${GREEN}All services stopped successfully!${NC}"
echo ""
echo -e "${YELLOW}To start services again:${NC}"
echo "  ./start_esign_server.sh    # Start main server only"
echo "  ./start_callback_server.sh # Start callback server only"
echo "  ./run_test_env.sh         # Start all services"