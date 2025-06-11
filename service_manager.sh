#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Change to project directory
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Function to display menu
show_menu() {
    clear
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}    eSign Service Manager       ${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
    echo -e "${GREEN}Individual Service Control:${NC}"
    echo "  1) Start eSign Server (port 8090)"
    echo "  2) Start Callback Server (port 8091)"
    echo "  3) Stop eSign Server"
    echo "  4) Stop Callback Server"
    echo ""
    echo -e "${BLUE}Batch Operations:${NC}"
    echo "  5) Start All Services"
    echo "  6) Stop All Services"
    echo "  7) Restart All Services"
    echo ""
    echo -e "${YELLOW}Monitoring & Testing:${NC}"
    echo "  8) Check Service Status"
    echo "  9) View eSign Server Logs"
    echo " 10) View Callback Server Logs"
    echo " 11) Open Test Interface"
    echo " 12) Test Health Endpoint"
    echo ""
    echo -e "${RED}Other:${NC}"
    echo " 13) Clear All Logs"
    echo " 14) Database Status"
    echo "  0) Exit"
    echo ""
}

# Function to press enter to continue
press_enter() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read
}

# Function to tail logs
view_logs() {
    local log_pattern=$1
    local latest_log=$(ls -t logs/${log_pattern}_*.log 2>/dev/null | head -1)
    
    if [ ! -z "$latest_log" ]; then
        echo -e "${GREEN}Viewing: $latest_log${NC}"
        echo -e "${YELLOW}Press Ctrl+C to stop viewing logs${NC}"
        echo ""
        tail -f "$latest_log"
    else
        echo -e "${RED}No log files found matching pattern: ${log_pattern}${NC}"
        press_enter
    fi
}

# Main loop
while true; do
    show_menu
    echo -n "Enter your choice [0-14]: "
    read choice
    
    case $choice in
        1)
            echo -e "\n${GREEN}Starting eSign Server...${NC}"
            ./start_esign_server.sh
            press_enter
            ;;
        2)
            echo -e "\n${GREEN}Starting Callback Server...${NC}"
            ./start_callback_server.sh
            press_enter
            ;;
        3)
            echo -e "\n${RED}Stopping eSign Server...${NC}"
            if [ -f .server.pid ]; then
                kill $(cat .server.pid) 2>/dev/null
                rm .server.pid
                echo "eSign server stopped"
            else
                echo "eSign server not running"
            fi
            press_enter
            ;;
        4)
            echo -e "\n${RED}Stopping Callback Server...${NC}"
            if [ -f .callback.pid ]; then
                kill $(cat .callback.pid) 2>/dev/null
                rm .callback.pid
                echo "Callback server stopped"
            else
                echo "Callback server not running"
            fi
            press_enter
            ;;
        5)
            echo -e "\n${GREEN}Starting All Services...${NC}"
            ./start_esign_server.sh
            echo ""
            ./start_callback_server.sh
            press_enter
            ;;
        6)
            echo -e "\n${RED}Stopping All Services...${NC}"
            ./stop_all_services.sh
            press_enter
            ;;
        7)
            echo -e "\n${YELLOW}Restarting All Services...${NC}"
            ./stop_all_services.sh
            echo ""
            sleep 2
            ./start_esign_server.sh
            echo ""
            ./start_callback_server.sh
            press_enter
            ;;
        8)
            echo ""
            ./check_services_status.sh
            press_enter
            ;;
        9)
            view_logs "server"
            ;;
        10)
            view_logs "callback"
            ;;
        11)
            echo -e "\n${GREEN}Opening Test Interface...${NC}"
            if command -v open > /dev/null; then
                open "http://localhost:8090/test-esign-enhanced.html"
            elif command -v xdg-open > /dev/null; then
                xdg-open "http://localhost:8090/test-esign-enhanced.html"
            else
                echo "Please open: http://localhost:8090/test-esign-enhanced.html"
            fi
            press_enter
            ;;
        12)
            echo -e "\n${GREEN}Testing Health Endpoint...${NC}"
            if curl -s http://localhost:8090/health > /dev/null; then
                echo -e "${GREEN}✓ Health check passed${NC}"
                curl -s http://localhost:8090/health | jq . 2>/dev/null || curl -s http://localhost:8090/health
            else
                echo -e "${RED}✗ Health check failed${NC}"
            fi
            press_enter
            ;;
        13)
            echo -e "\n${YELLOW}Clearing all logs...${NC}"
            if [ -d "logs" ]; then
                rm -f logs/*.log
                echo "All logs cleared"
            else
                echo "No logs directory found"
            fi
            press_enter
            ;;
        14)
            echo -e "\n${BLUE}Database Status:${NC}"
            if pg_isready > /dev/null 2>&1; then
                echo -e "${GREEN}✓ PostgreSQL is running${NC}"
                
                if psql -U atharvaz -d esign_db -c "SELECT COUNT(*) as table_count FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null; then
                    echo -e "${GREEN}✓ Database 'esign_db' is accessible${NC}"
                else
                    echo -e "${RED}✗ Cannot connect to database 'esign_db'${NC}"
                    echo "Try: createdb esign_db"
                fi
            else
                echo -e "${RED}✗ PostgreSQL is not running${NC}"
                echo "Start PostgreSQL first"
            fi
            press_enter
            ;;
        0)
            echo -e "\n${YELLOW}Exiting...${NC}"
            exit 0
            ;;
        *)
            echo -e "\n${RED}Invalid option. Please try again.${NC}"
            press_enter
            ;;
    esac
done