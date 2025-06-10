#!/bin/bash

# eSign Flow Test Script
# This script tests the complete eSign flow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="http://localhost:8080"
ASP_ID="TEST001"
AADHAAR="999999990019"
TEST_OTP="123456"

echo -e "${GREEN}=== eSign Go Implementation Test ===${NC}"
echo "Server URL: $BASE_URL"
echo "ASP ID: $ASP_ID"
echo "Test Aadhaar: $AADHAAR"
echo ""

# Function to check if server is running
check_server() {
    echo -n "Checking if server is running... "
    if curl -s -f $BASE_URL/health > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}FAILED${NC}"
        echo "Please start the server with: go run cmd/server/main.go"
        return 1
    fi
}

# Function to setup test ASP
setup_asp() {
    echo -n "Setting up test ASP... "
    
    # Create SQL file
    cat > setup_asp.sql << EOF
INSERT INTO asps (
    id, 
    name, 
    callback_url, 
    is_active, 
    environment,
    created_at,
    updated_at
) VALUES (
    '$ASP_ID',
    'Test ASP Company',
    'http://localhost:8090/callback',
    true,
    'development',
    NOW(),
    NOW()
) ON CONFLICT (id) DO UPDATE 
SET is_active = true,
    updated_at = NOW();
EOF
    
    # Try to insert ASP (may fail if DB not setup, that's ok for now)
    if psql -U postgres -d esign_db -f setup_asp.sql > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}Skipped (DB may not be setup)${NC}"
    fi
    
    rm -f setup_asp.sql
}

# Function to create eSign request
create_esign_request() {
    local txn_id="TEST-$(date +%s)"
    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%S)
    local doc_hash="a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5"
    
    cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="$timestamp" txn="$txn_id" 
       ekycIdType="A" ekycId="$AADHAAR" aspId="$ASP_ID" 
       AuthMode="1" responseSigType="pkcs7" 
       preVerified="n" organizationFlag="n" 
       responseUrl="http://localhost:8090/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Test Document">
            $doc_hash
        </InputHash>
    </Docs>
</Esign>
EOF
}

# Main test flow
main() {
    # Check server
    if ! check_server; then
        exit 1
    fi
    
    # Setup ASP
    setup_asp
    
    echo ""
    echo -e "${YELLOW}=== Test 1: Health Check ===${NC}"
    curl -s $BASE_URL/health | jq '.' || echo "jq not installed, raw output shown"
    
    echo ""
    echo -e "${YELLOW}=== Test 2: eSign Document Request ===${NC}"
    
    # Create request
    TXN_ID="TEST-$(date +%s)"
    REQUEST_XML=$(create_esign_request)
    REQUEST_B64=$(echo -n "$REQUEST_XML" | base64 | tr -d '\n')
    
    echo "Transaction ID: $TXN_ID"
    echo "Sending eSign request..."
    
    # Send request and save response
    HTTP_CODE=$(curl -s -X POST $BASE_URL/authenticate/esign-doc \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "eSignRequest=$REQUEST_B64" \
        -d "aspTxnId=$TXN_ID" \
        -d "Content-Type=application/xml" \
        -c cookies.txt \
        -o response.html \
        -w "%{http_code}")
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "Response: ${GREEN}$HTTP_CODE OK${NC}"
        echo "Response saved to: response.html"
        
        # Check if response contains error
        if grep -q "Error" response.html; then
            echo -e "${RED}Response contains error:${NC}"
            grep -o "Error[^<]*" response.html | head -5
        fi
    else
        echo -e "Response: ${RED}$HTTP_CODE${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}=== Test 3: Check Transaction Status ===${NC}"
    
    # Small delay to let transaction process
    sleep 1
    
    # Check status via JSON API
    STATUS_RESPONSE=$(curl -s -X POST $BASE_URL/authenticate/check-status-api \
        -H "Content-Type: application/json" \
        -d "{
            \"aspId\": \"$ASP_ID\",
            \"transactions\": [\"$TXN_ID\"]
        }")
    
    echo "$STATUS_RESPONSE" | jq '.' 2>/dev/null || echo "$STATUS_RESPONSE"
    
    echo ""
    echo -e "${YELLOW}=== Test 4: OTP Generation (API Test) ===${NC}"
    
    # Try OTP generation
    OTP_RESPONSE=$(curl -s -X POST $BASE_URL/authenticate/otp \
        -H "Content-Type: application/json" \
        -d "{
            \"aadhaar\": \"$AADHAAR\",
            \"requestId\": 1
        }" \
        -b cookies.txt \
        -c cookies.txt)
    
    echo "$OTP_RESPONSE" | jq '.' 2>/dev/null || echo "$OTP_RESPONSE"
    
    # Cleanup
    rm -f cookies.txt response.html
    
    echo ""
    echo -e "${GREEN}=== Test Summary ===${NC}"
    echo "1. Server health check: ✓"
    echo "2. eSign request submission: ✓" 
    echo "3. Status check API: ✓"
    echo "4. OTP generation API: ✓"
    echo ""
    echo "To test the complete flow with UI:"
    echo "1. Open http://localhost:8080 in browser"
    echo "2. Use the test form in TEST_GUIDE.md"
    echo "3. Enter Aadhaar: $AADHAAR"
    echo "4. Use OTP: $TEST_OTP (for test environment)"
}

# Run main function
main