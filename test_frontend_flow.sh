#!/bin/bash

echo "🔍 Testing eSign Frontend Flow"
echo "================================"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test 1: Check health endpoints
echo -e "\n${BLUE}1. Testing Health Endpoints${NC}"
echo -n "   Main Server (8090): "
if curl -s http://localhost:8090/health | grep -q "healthy"; then
    echo -e "${GREEN}✓ Healthy${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

echo -n "   Callback Server (8091): "
if curl -s http://localhost:8091/health | grep -q "healthy"; then
    echo -e "${GREEN}✓ Healthy${NC}"
else
    echo -e "${RED}✗ Failed${NC}"
fi

# Test 2: Check template rendering
echo -e "\n${BLUE}2. Testing Template Rendering${NC}"
echo -n "   Auth page: "
if curl -s http://localhost:8090/test | grep -q "eSign Authentication"; then
    echo -e "${GREEN}✓ Renders correctly${NC}"
else
    echo -e "${RED}✗ Failed to render${NC}"
fi

# Test 3: Test API endpoint
echo -e "\n${BLUE}3. Testing API Endpoint${NC}"
echo -n "   POST /api/test: "
RESPONSE=$(curl -s -X POST http://localhost:8090/api/test \
    -H "Content-Type: application/json" \
    -d '{"test": "data", "rid": 12345}')

if echo "$RESPONSE" | grep -q "success"; then
    echo -e "${GREEN}✓ API working${NC}"
    echo "   Response: $RESPONSE"
else
    echo -e "${RED}✗ API failed${NC}"
fi

# Test 4: Check static files
echo -e "\n${BLUE}4. Testing Static Files${NC}"
echo -n "   Test Form: "
if curl -s http://localhost:8090/test-esign-form.html | grep -q "form"; then
    echo -e "${GREEN}✓ Accessible${NC}"
else
    echo -e "${RED}✗ Not found${NC}"
fi

# Test 5: List available templates
echo -e "\n${BLUE}5. Available Templates${NC}"
echo "   The following authentication templates are available:"
echo "   - auth.html (OTP authentication)"
echo "   - auth_biometric.html (Biometric base)"
echo "   - auth_biometric_fingerprint.html (Fingerprint)"
echo "   - auth_biometric_iris.html (Iris scan)"
echo "   - auth_offline_kyc.html (Offline KYC)"
echo "   - auth_okyc.html (Online KYC)"
echo "   - auth_otp_ux.html (Enhanced OTP)"

echo -e "\n${YELLOW}📌 Manual Testing Steps:${NC}"
echo "1. Open http://localhost:8090/test in your browser"
echo "2. View the authentication page"
echo "3. Try http://localhost:8090/test-esign-form.html for form testing"
echo "4. Use callback URL: http://localhost:8091/callback"
echo ""
echo "The callback server will log all received callbacks in the terminal."

echo -e "\n${GREEN}✅ Frontend services are ready for testing!${NC}"