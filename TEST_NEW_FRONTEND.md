# Testing Guide for New Frontend Implementation

## Prerequisites

1. **Database Setup**
   ```bash
   # Ensure PostgreSQL is running
   # Create database if not exists
   createdb esign_db
   
   # Run migrations (tables will be created automatically)
   ```

2. **Start the Server**
   ```bash
   cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
   go run cmd/server/main_debug.go
   ```
   
   The server will start on `http://localhost:8090`

## Testing Different Authentication Flows

### 1. Test OTP Authentication (Standard Flow)

**Step 1: Create Test Request**
```bash
# Use the existing test form
open http://localhost:8090/test-esign-form.html
```

**Step 2: Submit eSign Request**
- Fill in the test form with:
  - ASP ID: `TEST001`
  - Transaction ID: `TEST-TXN-001`
  - Callback URL: `http://localhost:8090/callback`
  - Select Auth Mode: `OTP`

**Step 3: Test Enhanced UX**
- After submitting, append `?ux=enhanced` to the auth URL
- Example: `http://localhost:8090/authenticate/auth-ra?tid=XXX&ux=enhanced`

### 2. Test Biometric Authentication

**Fingerprint Authentication:**
```bash
# Direct URL with biometric type
http://localhost:8090/authenticate/auth-ra?tid=XXX&bio_type=fingerprint
```

**Iris Authentication:**
```bash
# Direct URL with iris type
http://localhost:8090/authenticate/auth-ra?tid=XXX&bio_type=iris
```

**Biometric Selection Page:**
```bash
# Without bio_type parameter, shows selection page
http://localhost:8090/authenticate/auth-ra?tid=XXX
# (when auth mode is 2)
```

### 3. Test Custom ASP Views

**HDFC Bank Theme:**
```bash
# Modify test request to use HDFC ASP ID
# In test-esign-form.html, set:
aspId = "HDFC"
```

**Karnataka Government Theme:**
```bash
# Set ASP ID to KARNATAKA-GOV
aspId = "KARNATAKA-GOV"
```

### 4. Test Offline KYC Flow

**Direct Template Test:**
```bash
# Create a test request with auth mode 4
# Then access:
http://localhost:8090/authenticate/auth-ra?tid=XXX
```

## Testing with cURL

### 1. Create eSign Request
```bash
curl -X POST http://localhost:8090/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "msg=$(cat test_esign_request_encoded.txt)"
```

### 2. Test Modern API Endpoints

**Send OTP:**
```bash
curl -X POST http://localhost:8090/authenticate/api/v2/auth/send-otp \
  -H "Content-Type: application/json" \
  -H "Cookie: esign-session=YOUR_SESSION_COOKIE" \
  -d '{
    "rid": 1234567890,
    "uid": "999999999999",
    "aspId": "TEST001"
  }'
```

**Verify OTP:**
```bash
curl -X POST http://localhost:8090/authenticate/api/v2/auth/verify-otp \
  -H "Content-Type: application/json" \
  -H "Cookie: esign-session=YOUR_SESSION_COOKIE" \
  -d '{
    "rid": 1234567890,
    "uid": "999999999999",
    "otpTxn": "txn-id-from-send-otp",
    "otp": "123456"
  }'
```

**Biometric Auth:**
```bash
curl -X POST http://localhost:8090/authenticate/api/v2/auth/biometric \
  -H "Content-Type: application/json" \
  -H "Cookie: esign-session=YOUR_SESSION_COOKIE" \
  -d '{
    "rid": 1234567890,
    "uid": "999999999999",
    "authType": "BIOMETRIC_FP",
    "biometricData": {
      "type": "FMR",
      "data": "base64-encoded-biometric-data"
    },
    "deviceInfo": {
      "id": "device-123",
      "name": "Test Device"
    }
  }'
```

## Quick Test Script

Create a file `test_frontend.sh`:

```bash
#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Testing eSign Frontend Implementation"
echo "====================================="

# Check if server is running
echo -n "Checking server status... "
if curl -s http://localhost:8090/health > /dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "Please start the server first: go run cmd/server/main_debug.go"
    exit 1
fi

# Test template endpoints
echo -e "\nTesting Template Endpoints:"
echo "------------------------"

endpoints=(
    "/authenticate/auth/otp"
    "/authenticate/auth/biometric"
    "/authenticate/auth/biometric/fingerprint"
    "/authenticate/auth/biometric/iris"
    "/authenticate/auth/offline-kyc"
)

for endpoint in "${endpoints[@]}"; do
    echo -n "Testing $endpoint... "
    status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8090$endpoint)
    if [ $status -eq 200 ] || [ $status -eq 302 ]; then
        echo -e "${GREEN}OK ($status)${NC}"
    else
        echo -e "${RED}FAILED ($status)${NC}"
    fi
done

echo -e "\nDone!"
```

Make it executable:
```bash
chmod +x test_frontend.sh
./test_frontend.sh
```

## Debug Mode Testing

1. **Enable Debug Logging**
   ```bash
   export LOG_LEVEL=debug
   go run cmd/server/main_debug.go
   ```

2. **Check Template Loading**
   ```bash
   # Visit debug endpoint
   curl http://localhost:8090/debug/info
   ```

3. **Test Specific Templates**
   ```bash
   # Test if templates are loading correctly
   curl http://localhost:8090/debug/templates
   ```

## Browser Testing with Developer Tools

1. **Open Chrome DevTools** (F12)
2. **Network Tab**: Monitor API calls
3. **Console Tab**: Check for JavaScript errors
4. **Application Tab**: Inspect cookies and session storage

## Common Issues and Solutions

### Issue: "Session expired or invalid"
**Solution:** Clear cookies and start fresh:
```javascript
// In browser console
document.cookie.split(";").forEach(function(c) { 
    document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/"); 
});
```

### Issue: "Template not found"
**Solution:** Check template paths:
```bash
# List all templates
find templates -name "*.html" | sort
```

### Issue: "Invalid request format"
**Solution:** Check request payload in browser DevTools Network tab

## Testing Checklist

- [ ] OTP Authentication Flow
  - [ ] Standard UI
  - [ ] Enhanced UX UI
  - [ ] Error handling
  
- [ ] Biometric Authentication
  - [ ] Fingerprint flow
  - [ ] Iris flow
  - [ ] Device selection
  
- [ ] Offline KYC
  - [ ] File upload
  - [ ] Share code validation
  
- [ ] Custom ASP Views
  - [ ] HDFC theme
  - [ ] Karnataka Gov theme
  - [ ] Multi-language support
  
- [ ] Error Pages
  - [ ] Session expired
  - [ ] Authentication failed
  - [ ] Request cancelled
  
- [ ] API Endpoints
  - [ ] Send OTP API
  - [ ] Verify OTP API
  - [ ] Biometric API
  - [ ] Cancel API

## Monitoring Logs

```bash
# Watch server logs
tail -f server.log

# Watch specific request
grep "request_id" server.log

# Watch errors only
tail -f server.log | grep -E "ERROR|WARN"
```