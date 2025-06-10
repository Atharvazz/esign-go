# eSign Go Implementation Testing Guide

## Prerequisites

1. **Database Setup**
```bash
# Create database and tables
psql -U postgres
CREATE DATABASE esign_db;
\c esign_db

# Run migrations (tables will be created automatically)
# The Go app will run migrations on startup
```

2. **Start the Server**
```bash
# From the esign-go directory
go run cmd/server/main.go

# Or build and run
go build -o esign-server cmd/server/main.go
./esign-server
```

3. **Setup Test ASP**
```bash
# Insert a test ASP into the database
psql -U postgres -d esign_db << EOF
INSERT INTO asps (
    id, 
    name, 
    callback_url, 
    is_active, 
    environment,
    created_at,
    updated_at
) VALUES (
    'TEST001',
    'Test ASP Company',
    'http://localhost:8090/callback',
    true,
    'development',
    NOW(),
    NOW()
) ON CONFLICT (id) DO NOTHING;
EOF
```

## Test Flows

### 1. Complete OTP-Based eSign Flow

#### Step 1: Generate Document Hash
```bash
# Create a test document
echo "This is a test document for eSign" > test-document.txt

# Generate SHA256 hash
DOCUMENT_HASH=$(sha256sum test-document.txt | cut -d' ' -f1)
echo "Document Hash: $DOCUMENT_HASH"
```

#### Step 2: Create and Send eSign Request
```bash
# Set variables
ASP_ID="TEST001"
TXN_ID="TEST-$(date +%s)"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S)
AADHAAR="999999990019"  # Test Aadhaar for sandbox

# Create the XML request
cat > esign_request.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="$TIMESTAMP" txn="$TXN_ID" 
       ekycIdType="A" ekycId="$AADHAAR" aspId="$ASP_ID" 
       AuthMode="1" responseSigType="pkcs7" 
       preVerified="n" organizationFlag="n" 
       responseUrl="http://localhost:8090/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Test Document">
            $DOCUMENT_HASH
        </InputHash>
    </Docs>
</Esign>
EOF

# Base64 encode the XML
REQUEST_B64=$(cat esign_request.xml | base64 | tr -d '\n')

# Send the request
echo "Sending eSign request..."
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_B64" \
  -d "aspTxnId=$TXN_ID" \
  -d "Content-Type=application/xml" \
  -c cookies.txt \
  -L -v > response.html

echo "Response saved to response.html"
```

#### Step 3: Manual Browser Flow (Recommended for UI Testing)
1. Open browser and go to: `http://localhost:8080`
2. Use the test HTML form below:

```html
<!-- Save as test-esign-form.html -->
<!DOCTYPE html>
<html>
<head>
    <title>eSign Test Form</title>
</head>
<body>
    <h1>eSign Test Form</h1>
    <form method="POST" action="http://localhost:8080/authenticate/esign-doc">
        <label>eSign Request (Base64):</label><br>
        <textarea name="eSignRequest" rows="10" cols="80">
<!-- Paste your REQUEST_B64 here -->
        </textarea><br><br>
        
        <label>ASP Transaction ID:</label><br>
        <input type="text" name="aspTxnId" value="TEST-001"><br><br>
        
        <label>Content Type:</label><br>
        <input type="text" name="Content-Type" value="application/xml"><br><br>
        
        <button type="submit">Submit eSign Request</button>
    </form>
</body>
</html>
```

#### Step 4: API Testing for OTP Flow
```bash
# After being redirected to auth page, generate OTP
curl -X POST http://localhost:8080/authenticate/otp \
  -H "Content-Type: application/json" \
  -d '{
    "aadhaar": "999999990019",
    "requestId": 1
  }' \
  -b cookies.txt \
  -c cookies.txt

# Sample response:
# {
#   "status": "1",
#   "msg": "OTP sent successfully",
#   "txn": "OTP-TXN-123",
#   "rc": 3
# }

# Verify OTP (use 123456 for test environment)
curl -X POST http://localhost:8080/authenticate/otpAction \
  -H "Content-Type: application/json" \
  -d '{
    "otp": "123456",
    "txnId": "OTP-TXN-123",
    "aadhaar": "999999990019",
    "requestId": 1
  }' \
  -b cookies.txt \
  -c cookies.txt
```

### 2. Biometric Authentication Flow

```bash
# Create biometric request (AuthMode=2 for fingerprint)
cat > bio_request.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="$(date -u +%Y-%m-%dT%H:%M:%S)" txn="BIO-$(date +%s)" 
       ekycIdType="A" ekycId="999999990019" aspId="TEST001" 
       AuthMode="2" responseSigType="pkcs7" 
       preVerified="n" organizationFlag="n" 
       responseUrl="http://localhost:8090/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Biometric Test">
            a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
        </InputHash>
    </Docs>
</Esign>
EOF

# Submit biometric data (simulated)
curl -X POST http://localhost:8080/authenticate/postRequestdata \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'PidData=<?xml version="1.0" encoding="UTF-8"?><PidData><Resp errCode="0" errInfo="Success" fCount="1" fType="2" nmPoints="30" qScore="70"/><DeviceInfo dpId="MANTRA.MSIPL" rdsId="MANTRA.WIN.001" rdsVer="1.0.4" mi="MFS100"/><Skey ci="20250605">TEST_SESSION_KEY</Skey><Hmac>TEST_HMAC</Hmac><Data type="X">TEST_BIOMETRIC_DATA</Data></PidData>' \
  -d "requestId=1" \
  -d "Biometric=FMR" \
  -b cookies.txt
```

### 3. Check Transaction Status

```bash
# Check status using XML API
STATUS_XML=$(cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<EsignStatus ver="2.1" ts="$(date -u +%Y-%m-%dT%H:%M:%S)" 
             txn="STATUS-$(date +%s)" aspId="TEST001" 
             respAttemptNo="1">
    <TxnList>
        <Txn>$TXN_ID</Txn>
    </TxnList>
</EsignStatus>
EOF
)

curl -X POST http://localhost:8080/authenticate/check-status \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "statusRequest=$(echo "$STATUS_XML" | base64 | tr -d '\n')"

# Or use JSON API
curl -X POST http://localhost:8080/authenticate/check-status-api \
  -H "Content-Type: application/json" \
  -d "{
    \"aspId\": \"TEST001\",
    \"transactions\": [\"$TXN_ID\"]
  }"
```

## Testing Tools

### 1. Postman Collection
Import the `eSign_API_Collection.postman_collection.json` file into Postman for easy API testing.

### 2. Automated Test Script
```bash
#!/bin/bash
# save as test-esign-flow.sh

set -e

echo "=== eSign Flow Test Script ==="

# Configuration
BASE_URL="http://localhost:8080"
ASP_ID="TEST001"
AADHAAR="999999990019"

# Step 1: Health Check
echo "1. Checking server health..."
curl -s $BASE_URL/health | jq

# Step 2: Create eSign Request
echo -e "\n2. Creating eSign request..."
TXN_ID="TEST-$(date +%s)"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S)

REQUEST_XML="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Esign ver=\"2.1\" sc=\"Y\" ts=\"$TIMESTAMP\" txn=\"$TXN_ID\" 
       ekycIdType=\"A\" ekycId=\"$AADHAAR\" aspId=\"$ASP_ID\" 
       AuthMode=\"1\" responseSigType=\"pkcs7\" 
       preVerified=\"n\" organizationFlag=\"n\" 
       responseUrl=\"http://localhost:8090/callback\">
    <Docs>
        <InputHash id=\"1\" hashAlgorithm=\"SHA256\" docInfo=\"Test Document\">
            a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
        </InputHash>
    </Docs>
</Esign>"

REQUEST_B64=$(echo -n "$REQUEST_XML" | base64)

# Step 3: Send eSign Request
echo -e "\n3. Sending eSign request..."
RESPONSE=$(curl -s -X POST $BASE_URL/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_B64" \
  -d "aspTxnId=$TXN_ID" \
  -c cookies.txt \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
echo "Response Code: $HTTP_CODE"

# Step 4: Check Transaction Status
echo -e "\n4. Checking transaction status..."
sleep 2

curl -s -X POST $BASE_URL/authenticate/check-status-api \
  -H "Content-Type: application/json" \
  -d "{
    \"aspId\": \"$ASP_ID\",
    \"transactions\": [\"$TXN_ID\"]
  }" | jq

echo -e "\n=== Test completed ==="
```

### 3. Mock Callback Server
```go
// Save as mock-callback-server.go
package main

import (
    "fmt"
    "io"
    "net/http"
    "time"
)

func main() {
    http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
        fmt.Printf("[%s] Received callback\n", time.Now().Format("15:04:05"))
        fmt.Printf("Method: %s\n", r.Method)
        fmt.Printf("Headers: %v\n", r.Header)
        
        body, _ := io.ReadAll(r.Body)
        fmt.Printf("Body: %s\n", string(body))
        
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("Callback received"))
    })
    
    fmt.Println("Mock callback server running on :8090")
    http.ListenAndServe(":8090", nil)
}

// Run with: go run mock-callback-server.go
```

## Database Verification

```sql
-- Check transactions
SELECT id, asp_id, asp_txn_id, status, request_time, response_time 
FROM transactions 
ORDER BY created_at DESC 
LIMIT 10;

-- Check request details
SELECT id, request_id, transition, created_at 
FROM authenticate_txn_dtls 
ORDER BY created_at DESC 
LIMIT 10;

-- Check ASPs
SELECT * FROM asps;
```

## Common Issues and Solutions

1. **Template Not Found Error**
   - Ensure server is running from the esign-go directory
   - Check that templates/*.html files exist
   - Restart server after template changes

2. **Database Connection Error**
   - Verify PostgreSQL is running
   - Check database credentials in config.yaml
   - Ensure database exists

3. **ASP Not Found**
   - Insert test ASP using SQL above
   - Check ASP ID in request matches database

4. **Rate Limiting**
   - Wait between requests
   - Check rate limit configuration
   - Use different ASP IDs for testing

## Test Scenarios

1. **Happy Path**: Complete OTP flow with valid data
2. **Invalid ASP**: Use non-existent ASP ID
3. **Expired Request**: Send request with old timestamp
4. **Rate Limiting**: Send multiple requests quickly
5. **Cancel Flow**: Test cancel endpoint
6. **Biometric Flow**: Test with mock biometric data
7. **Status Check**: Verify transaction status

## Monitoring

```bash
# Watch server logs
tail -f server.log

# Monitor database
watch -n 1 'psql -U postgres -d esign_db -c "SELECT COUNT(*) as total, status FROM transactions GROUP BY status;"'

# Check API health
while true; do curl -s http://localhost:8080/health | jq; sleep 5; done
```