#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}eSign Services Status Check${NC}"
echo "=========================="
echo ""

# Change to project directory
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Function to check service status
check_service() {
    local service_name=$1
    local pid_file=$2
    local port=$3
    local health_url=$4
    
    echo -e "${YELLOW}$service_name:${NC}"
    
    # Check PID file
    if [ -f $pid_file ]; then
        PID=$(cat $pid_file)
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "  PID: ${GREEN}$PID (running)${NC}"
        else
            echo -e "  PID: ${RED}$PID (not running - stale PID file)${NC}"
        fi
    else
        echo -e "  PID: ${YELLOW}No PID file${NC}"
    fi
    
    # Check port
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        PORT_PID=$(lsof -Pi :$port -sTCP:LISTEN -t)
        echo -e "  Port $port: ${GREEN}In use (PID: $PORT_PID)${NC}"
    else
        echo -e "  Port $port: ${RED}Not in use${NC}"
    fi
    
    # Check health/connectivity
    if [ ! -z "$health_url" ]; then
        if curl -s --max-time 2 $health_url > /dev/null; then
            echo -e "  Health: ${GREEN}✓ Responding${NC}"
            
            # For main server, get additional info
            if [[ $health_url == *"/health"* ]]; then
                HEALTH_DATA=$(curl -s $health_url 2>/dev/null)
                if [ ! -z "$HEALTH_DATA" ]; then
                    BUILD=$(echo $HEALTH_DATA | grep -o '"build":"[^"]*"' | cut -d'"' -f4)
                    if [ ! -z "$BUILD" ]; then
                        echo -e "  Build: $BUILD"
                    fi
                fi
            fi
        else
            echo -e "  Health: ${RED}✗ Not responding${NC}"
        fi
    fi
    
    echo ""
}

# Check main eSign server
check_service "eSign Server" ".server.pid" "8090" "http://localhost:8090/health"

# Check callback server
check_service "Callback Server" ".callback.pid" "8091" "http://localhost:8091"

# Check database
echo -e "${YELLOW}PostgreSQL Database:${NC}"
if pg_isready > /dev/null 2>&1; then
    echo -e "  Status: ${GREEN}✓ Running${NC}"
    
    # Try to connect to esign_db
    if psql -U atharvaz -d esign_db -c "SELECT 1;" > /dev/null 2>&1; then
        echo -e "  Database 'esign_db': ${GREEN}✓ Accessible${NC}"
        
        # Get table count
        TABLE_COUNT=$(psql -U atharvaz -d esign_db -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | xargs)
        if [ ! -z "$TABLE_COUNT" ]; then
            echo -e "  Tables: $TABLE_COUNT"
        fi
    else
        echo -e "  Database 'esign_db': ${RED}✗ Not accessible${NC}"
    fi
else
    echo -e "  Status: ${RED}✗ Not running${NC}"
fi
echo ""

# Check log files
echo -e "${YELLOW}Recent Log Files:${NC}"
if [ -d "logs" ]; then
    # Find most recent server log
    LATEST_SERVER_LOG=$(ls -t logs/server_*.log 2>/dev/null | head -1)
    if [ ! -z "$LATEST_SERVER_LOG" ]; then
        echo -e "  Latest server log: $LATEST_SERVER_LOG"
        ERRORS=$(grep -c "ERROR" "$LATEST_SERVER_LOG" 2>/dev/null || echo "0")
        echo -e "    Errors: $ERRORS"
    fi
    
    # Find most recent callback log
    LATEST_CALLBACK_LOG=$(ls -t logs/callback_*.log 2>/dev/null | head -1)
    if [ ! -z "$LATEST_CALLBACK_LOG" ]; then
        echo -e "  Latest callback log: $LATEST_CALLBACK_LOG"
    fi
else
    echo -e "  ${YELLOW}No logs directory found${NC}"
fi
echo ""

# Quick commands
echo -e "${BLUE}Quick Commands:${NC}"
echo "  Start all:      ./run_test_env.sh"
echo "  Start server:   ./start_esign_server.sh"
echo "  Start callback: ./start_callback_server.sh"
echo "  Stop all:       ./stop_all_services.sh"
echo "  View logs:      tail -f logs/server_*.log"
echo ""

# Test URLs
if lsof -Pi :8090 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${BLUE}Test URLs:${NC}"
    echo "  Test Interface: http://localhost:8090/test-esign-enhanced.html"
    echo "  Health Check:   http://localhost:8090/health"
    echo "  Debug Info:     http://localhost:8090/debug/info"
fi

if lsof -Pi :8091 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "  Callback Server: http://localhost:8091"
fi