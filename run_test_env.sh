#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting eSign Test Environment${NC}"
echo "================================="

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null ; then
        return 0
    else
        return 1
    fi
}

# Kill existing processes on our ports
echo -e "\n${YELLOW}Cleaning up existing processes...${NC}"
if check_port 8090; then
    echo "Killing process on port 8090..."
    lsof -ti:8090 | xargs kill -9 2>/dev/null
fi

if check_port 8091; then
    echo "Killing process on port 8091..."
    lsof -ti:8091 | xargs kill -9 2>/dev/null
fi

# Start the main server
echo -e "\n${YELLOW}Starting eSign server on port 8090...${NC}"
go run cmd/server/main_debug.go > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Start the callback server
echo -e "\n${YELLOW}Starting callback server on port 8091...${NC}"
go run test-callback-server.go > callback.log 2>&1 &
CALLBACK_PID=$!
echo "Callback server PID: $CALLBACK_PID"

# Wait for servers to start
echo -e "\n${YELLOW}Waiting for servers to start...${NC}"
sleep 3

# Check if servers are running
echo -e "\n${YELLOW}Checking server status...${NC}"
if curl -s http://localhost:8090/health > /dev/null; then
    echo -e "${GREEN}✓ Main server is running${NC}"
else
    echo -e "${RED}✗ Main server failed to start${NC}"
    echo "Check server.log for errors"
fi

if curl -s http://localhost:8091 > /dev/null; then
    echo -e "${GREEN}✓ Callback server is running${NC}"
else
    echo -e "${RED}✗ Callback server failed to start${NC}"
    echo "Check callback.log for errors"
fi

echo -e "\n${GREEN}Test Environment Ready!${NC}"
echo "========================"
echo -e "\n${YELLOW}Quick Start URLs:${NC}"
echo "  Main Server:        http://localhost:8090"
echo "  Test Interface:     http://localhost:8090/test-esign-enhanced.html"
echo "  Original Test Form: http://localhost:8090/test-esign-form.html"
echo "  Callback Server:    http://localhost:8091"
echo ""
echo -e "${YELLOW}API Endpoints:${NC}"
echo "  Health Check:    GET  http://localhost:8090/health"
echo "  Create Request:  POST http://localhost:8090/authenticate/esign-doc"
echo "  Send OTP:       POST http://localhost:8090/authenticate/api/v2/auth/send-otp"
echo "  Verify OTP:     POST http://localhost:8090/authenticate/api/v2/auth/verify-otp"
echo ""
echo -e "${YELLOW}Logs:${NC}"
echo "  tail -f server.log      # Main server logs"
echo "  tail -f callback.log    # Callback server logs"
echo ""
echo -e "${YELLOW}To stop all servers:${NC}"
echo "  kill $SERVER_PID $CALLBACK_PID"
echo "  OR"
echo "  ./stop_test_env.sh"
echo ""

# Create stop script
cat > stop_test_env.sh << EOF
#!/bin/bash
echo "Stopping test environment..."
kill $SERVER_PID $CALLBACK_PID 2>/dev/null
lsof -ti:8090 | xargs kill -9 2>/dev/null
lsof -ti:8091 | xargs kill -9 2>/dev/null
echo "Done!"
EOF

chmod +x stop_test_env.sh

# Keep script running
echo -e "${GREEN}Press Ctrl+C to stop all servers${NC}"
wait