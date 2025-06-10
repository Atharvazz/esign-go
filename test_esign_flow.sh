#!/bin/bash

# eSign Test Flow Script
# This script demonstrates a complete eSign flow with OTP authentication

echo "=== eSign Test Flow Script ==="
echo "Starting at: $(date)"
echo ""

# Configuration
BASE_URL="http://localhost:8080"
ASP_ID="TEST001"
AADHAAR="999999990019"
TXN_ID="TEST-$(date +%s)"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to pretty print JSON
pretty_json() {
    echo "$1" | jq '.' 2>/dev/null || echo "$1"
}

# Function to make request and show response
make_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local description=$4
    
    echo -e "${BLUE}>>> $description${NC}"
    echo "Endpoint: $method $endpoint"
    
    if [ "$method" == "POST" ]; then
        response=$(curl -s -X POST "$BASE_URL$endpoint" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "$data" \
            -c cookies.txt \
            -b cookies.txt \
            -w "\nHTTP_STATUS:%{http_code}")
    else
        response=$(curl -s -X GET "$BASE_URL$endpoint" \
            -c cookies.txt \
            -b cookies.txt \
            -w "\nHTTP_STATUS:%{http_code}")
    fi
    
    # Extract HTTP status
    http_status=$(echo "$response" | grep -o "HTTP_STATUS:[0-9]*" | cut -d: -f2)
    body=$(echo "$response" | sed 's/HTTP_STATUS:[0-9]*$//')
    
    echo "Response Status: $http_status"
    echo "Response Body:"
    pretty_json "$body"
    echo ""
    
    # Return status for checking
    return $([ "$http_status" -ge 200 ] && [ "$http_status" -lt 300 ])
}

# Step 1: Check server health
echo -e "${GREEN}=== Step 1: Checking Server Health ===${NC}"
if ! curl -s "$BASE_URL/health" > /dev/null; then
    echo -e "${RED}Error: Server is not running at $BASE_URL${NC}"
    echo "Please start the server with: cd cmd/server && go run ."
    exit 1
fi
echo "Server is healthy!"
echo ""

# Step 2: Create eSign request XML
echo -e "${GREEN}=== Step 2: Creating eSign Request ===${NC}"
REQUEST_XML='<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="'$(date -u +%Y-%m-%dT%H:%M:%S)'" txn="'$TXN_ID'" 
       ekycIdType="A" ekycId="'$AADHAAR'" aspId="'$ASP_ID'" 
       AuthMode="1" responseSigType="pkcs7" preVerified="n" 
       organizationFlag="n" responseUrl="http://localhost:8080/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Test Agreement">
            a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
        </InputHash>
    </Docs>
</Esign>'

# Base64 encode the XML
ENCODED_XML=$(echo "$REQUEST_XML" | base64 | tr -d '\n')
echo "Transaction ID: $TXN_ID"
echo ""

# Step 3: Send eSign request
echo -e "${GREEN}=== Step 3: Sending eSign Request ===${NC}"
make_request "POST" "/authenticate/esign-doc" \
    "eSignRequest=$ENCODED_XML&aspTxnId=ASP-$TXN_ID" \
    "Initiating eSign Request"

# The response should redirect to auth page
# In a real scenario, this would show an HTML page for OTP entry

# Step 4: Generate OTP
echo -e "${GREEN}=== Step 4: Generating OTP ===${NC}"
echo "Simulating OTP generation for Aadhaar: $AADHAAR"
make_request "POST" "/authenticate/otp" \
    "aadhaar=$AADHAAR&requestId=1" \
    "Requesting OTP"

# Step 5: Verify OTP (simulated)
echo -e "${GREEN}=== Step 5: Verifying OTP ===${NC}"
echo "In production, user would enter the actual OTP received"
echo "Using test OTP: 123456"
make_request "POST" "/authenticate/otpAction" \
    "otp=123456&txnId=OTP-TXN-ID&aadhaar=$AADHAAR" \
    "Verifying OTP"

# Step 6: Check transaction status
echo -e "${GREEN}=== Step 6: Checking Transaction Status ===${NC}"
STATUS_XML='<?xml version="1.0" encoding="UTF-8"?>
<EsignStatus ver="2.1" ts="'$(date -u +%Y-%m-%dT%H:%M:%S)'" 
             txn="STATUS-'$(date +%s)'" aspId="'$ASP_ID'" respAttemptNo="1">
    <TxnList>
        <Txn>'$TXN_ID'</Txn>
    </TxnList>
</EsignStatus>'

ENCODED_STATUS=$(echo "$STATUS_XML" | base64 | tr -d '\n')
make_request "POST" "/authenticate/check-status" \
    "statusRequest=$ENCODED_STATUS" \
    "Checking Status"

# Alternative: JSON API for status check
echo -e "${GREEN}=== Step 7: Checking Status via JSON API ===${NC}"
curl -s -X POST "$BASE_URL/authenticate/check-status-api" \
    -H "Content-Type: application/json" \
    -d '{
        "aspId": "'$ASP_ID'",
        "transactions": ["'$TXN_ID'"]
    }' | jq '.'

echo ""
echo -e "${GREEN}=== Test Flow Completed ===${NC}"
echo "Transaction ID: $TXN_ID"
echo "Completed at: $(date)"

# Cleanup
rm -f cookies.txt

# Additional test scenarios
echo ""
echo -e "${BLUE}=== Additional Test Commands ===${NC}"
echo ""
echo "1. Test Biometric Authentication:"
echo "   curl -X POST $BASE_URL/authenticate/esign-doc -d 'eSignRequest=...' # with AuthMode=2"
echo ""
echo "2. Test Face Recognition:"
echo "   curl -X POST $BASE_URL/authenticate/fcr -H 'Content-Type: application/json' -d '{...}'"
echo ""
echo "3. Test Error Handling (Invalid ASP):"
echo "   Use aspId='INVALID_ASP' in the request"
echo ""
echo "4. Test Rate Limiting:"
echo "   for i in {1..15}; do curl -X POST $BASE_URL/authenticate/esign-doc -d 'test'; done"
echo ""
echo "5. Cancel eSign Request:"
echo "   curl -X POST $BASE_URL/authenticate/esignCancel -d 'requestId=1&reason=Test'"