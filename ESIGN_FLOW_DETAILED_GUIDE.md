# Comprehensive eSign Flow Understanding

## Table of Contents
1. [Overview](#overview)
2. [Key Concepts](#key-concepts)
3. [Complete Flow Diagram](#complete-flow-diagram)
4. [Detailed Flow States](#detailed-flow-states)
5. [Step-by-Step Implementation](#step-by-step-implementation)
6. [Error Handling](#error-handling)
7. [Security Considerations](#security-considerations)

## Overview

The eSign service enables digital signing of documents using Aadhaar-based authentication. It follows the UIDAI eSign 2.1 specification and provides a secure, legally valid digital signature service.

### Core Components
1. **ASP (Application Service Provider)**: The client application requesting eSign
2. **ESP (eSign Service Provider)**: Our service that facilitates signing
3. **UIDAI**: Provides authentication and KYC services
4. **End User**: Person signing the document

### Authentication Methods
1. **OTP (One Time Password)**: SMS-based authentication
2. **Biometric - Fingerprint**: Using fingerprint scanner
3. **Biometric - Iris**: Using iris scanner
4. **Offline KYC**: Pre-downloaded KYC XML

## Key Concepts

### 1. Document Hash
- Documents are never sent to ESP
- Only SHA256 hash of the document is sent
- Multiple documents can be signed in one session

### 2. Request States
```
INITIATED (-1) → OTP_SENT → OTP_VERIFIED → KYC_FETCHED → SIGNED (0)
                     ↓            ↓             ↓            ↓
                  FAILED (1)   FAILED (1)   FAILED (1)   FAILED (1)
                     ↓            ↓             ↓            ↓
                 EXPIRED (2)   EXPIRED (2)  EXPIRED (2)  EXPIRED (2)
```

### 3. Session Management
- Each request has a unique transaction ID
- Sessions are maintained using Redis
- Timeout: 30 minutes

### 4. Security Layers
- ASP authentication via digital signature
- Request expiry (5 minutes)
- Duplicate request prevention
- Rate limiting
- XML signature validation

## Complete Flow Diagram

```
┌─────────────┐     1. eSign Request      ┌─────────────┐
│     ASP     │ ─────────────────────────> │     ESP     │
│  (Client)   │                            │  (eSign)    │
└─────────────┘                            └─────────────┘
      ↑                                           │
      │                                           │ 2. Validate & Store
      │                                           ↓
      │                                    ┌─────────────┐
      │ 8. Signed Response                 │   Database  │
      │    (Callback)                      └─────────────┘
      │                                           │
      │                                           │ 3. Redirect to Auth
      │                                           ↓
      │                                    ┌─────────────┐
      │                                    │    User     │
      │                                    │   Browser   │
      │                                    └─────────────┘
      │                                           │
      │                                           │ 4. Choose Auth Method
      │                                           ↓
      │                                    ┌─────────────┐
      │                                    │   UIDAI     │ ← 5. Auth Request
      │                                    │  Services   │
      │                                    └─────────────┘
      │                                           │
      │                                           │ 6. KYC Response
      │                                           ↓
      │                                    ┌─────────────┐
      │                                    │    ESP      │ ← 7. Generate Signature
      └─────────────────────────────────── │  Signing    │
                                          └─────────────┘
```

## Detailed Flow States

### State 1: Request Initiation
**Status**: `INITIATED (-1)`
- ASP sends digitally signed request
- ESP validates ASP credentials
- Request stored in database
- Session created

### State 2: Authentication Selection
**Status**: `REQUEST_AUTHORISED`
- User redirected to authentication page
- Auth method selected (OTP/Bio/Offline)
- Request tracking initiated

### State 3: Authentication Process
**Status**: `OTP_SENT` / `BIO_SUBMITTED`
- User provides authentication
- UIDAI validates credentials
- Multiple attempts allowed (configurable)

### State 4: KYC Verification
**Status**: `OTP_VERIFIED` / `BIO_VERIFIED`
- KYC data fetched from UIDAI
- User photo and demographics retrieved
- Data encrypted and stored

### State 5: Document Signing
**Status**: `KYC_FETCHED` → `SIGNED (0)`
- Digital certificate generated
- Document hash signed
- PKCS#7 signature created

### State 6: Response Delivery
**Status**: `COMPLETED`
- Signed response sent to ASP
- Callback URL invoked
- Transaction logged

## Step-by-Step Implementation

### Step 1: ASP Registration
Before any signing can happen, ASP must be registered:

```bash
# Register ASP in database
psql -U esign -d esign_db -h localhost << EOF
INSERT INTO asps (
    id, 
    name, 
    public_key, 
    callback_url, 
    is_active, 
    require_signature
) VALUES (
    'ASP001',
    'Test ASP Company',
    '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx5V1Gpw9nF8HKmWr5NYH
... (your public key) ...
-----END PUBLIC KEY-----',
    'https://your-asp-server.com/esign/callback',
    true,
    true
);
EOF
```

### Step 2: Generate Document Hash
ASP must generate SHA256 hash of the document:

```bash
# Generate document hash
DOCUMENT_HASH=$(sha256sum document.pdf | cut -d' ' -f1)
echo "Document Hash: $DOCUMENT_HASH"
```

### Step 3: Create eSign Request XML
```bash
# Set variables
ASP_ID="ASP001"
TXN_ID="ASP-$(date +%s)"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S)
AADHAAR="999999990019"  # Test Aadhaar
AUTH_MODE="1"  # 1=OTP, 2=Fingerprint, 3=Iris

# Create request XML
cat > esign_request.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="$TIMESTAMP" txn="$TXN_ID" 
       ekycIdType="A" ekycId="$AADHAAR" aspId="$ASP_ID" 
       AuthMode="$AUTH_MODE" responseSigType="pkcs7" 
       preVerified="n" organizationFlag="n" 
       responseUrl="https://your-asp-server.com/esign/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Loan Agreement">
            $DOCUMENT_HASH
        </InputHash>
    </Docs>
</Esign>
EOF

# Sign the XML (if ASP requires signature)
# This would use ASP's private key to create signature
```

### Step 4: Send eSign Request
```bash
# Base64 encode the request
REQUEST_B64=$(base64 -w 0 esign_request.xml)

# Send request to ESP
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_B64" \
  -d "aspTxnId=$TXN_ID" \
  -d "Content-Type=application/xml" \
  -c cookies.txt \
  -L -v \
  > esign_response.html

# The response will be HTML redirect page
# In production, this would redirect user's browser
```

### Step 5: User Authentication Flow

#### 5a. OTP Flow
```bash
# User enters Aadhaar on the auth page
# Then clicks "Send OTP"

# 1. Generate OTP request
curl -X POST http://localhost:8080/authenticate/otp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "aadhaar": "999999990019",
    "requestId": 1
  }' \
  -b cookies.txt \
  -c cookies.txt

# Response:
# {
#   "success": "1",
#   "frm": "<form>...</form>",
#   "msg": "OTP sent successfully",
#   "txn": "UIDAI-OTP-TXN-ID",
#   "rc": 3
# }

# 2. User receives OTP on mobile
# 3. Submit OTP for verification
curl -X POST http://localhost:8080/authenticate/otpAction \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "otp": "123456",
    "txnId": "UIDAI-OTP-TXN-ID",
    "aadhaar": "999999990019",
    "requestId": 1
  }' \
  -b cookies.txt \
  -c cookies.txt

# Response:
# {
#   "success": "1",
#   "frm": "<form>Processing...</form>",
#   "msg": "Authentication successful"
# }
```

#### 5b. Biometric Flow (Fingerprint)
```bash
# 1. User is shown biometric capture page
# 2. Capture fingerprint using RD service

# Sample PID data from biometric device
PID_DATA='<?xml version="1.0" encoding="UTF-8"?>
<PidData>
    <Resp errCode="0" errInfo="Success" fCount="1" fType="2" 
          nmPoints="30" qScore="70"/>
    <DeviceInfo dpId="MANTRA.MSIPL" rdsId="MANTRA.WIN.001" 
                rdsVer="1.0.4" mi="MFS100" mc="DEVICE_CERT"/>
    <Skey ci="20250605">ENCRYPTED_SESSION_KEY_BASE64</Skey>
    <Hmac>HMAC_OF_PID_BLOCK</Hmac>
    <Data type="X">ENCRYPTED_BIOMETRIC_DATA_BASE64</Data>
    <additional_info>
        <Param name="srno" value="1234567"/>
        <Param name="ts" value="2025-06-05T12:30:45"/>
        <Param name="wadh" value="WADH_VALUE"/>
    </additional_info>
</PidData>'

# 3. Submit biometric data
curl -X POST http://localhost:8080/authenticate/postRequestdata \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "PidData=$(echo "$PID_DATA" | base64 -w 0)" \
  -d "requestId=1" \
  -d "Biometric=FMR" \
  -b cookies.txt \
  -c cookies.txt
```

#### 5c. Offline KYC Flow
```bash
# 1. User uploads offline KYC ZIP file
# 2. Extract and validate

# Generate OTP for offline KYC
curl -X POST http://localhost:8080/authenticate/okycOtp \
  -H "Content-Type: application/json" \
  -d '{
    "aadhaarNumber": "999999990019",
    "captcha": "ABC123",
    "shareCode": "1234"
  }'

# Response:
# {
#   "status": "success",
#   "refId": "OKYC-REF-123",
#   "message": "OTP sent"
# }

# 3. Verify offline KYC with OTP
curl -X POST http://localhost:8080/authenticate/okycOtpVerifyAction \
  -H "Content-Type: application/json" \
  -d '{
    "refId": "OKYC-REF-123",
    "otp": "123456",
    "xmlData": "BASE64_ENCODED_OFFLINE_KYC_XML",
    "shareCode": "1234",
    "requestId": 1
  }' \
  -b cookies.txt
```

### Step 6: Document Signing Process
After successful authentication, the signing happens automatically:

```bash
# Internal process (not directly callable):
# 1. KYC data is fetched
# 2. Digital certificate is generated for user
# 3. Document hash is signed using the certificate
# 4. PKCS#7 signature is created
# 5. Response XML is generated

# The signed response looks like:
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" ts="2025-06-05T12:35:00" txn="ASP-1234567890" 
       resCode="200" errCode="" errMsg="">
    <Signatures>
        <DocSignature id="1">
            PKCS#7_SIGNATURE_BASE64_ENCODED
        </DocSignature>
    </Signatures>
    <UserX509Certificate>
        USER_CERTIFICATE_BASE64_ENCODED
    </UserX509Certificate>
    <Resp status="1">
        <ts>2025-06-05T12:35:00</ts>
    </Resp>
</Esign>
```

### Step 7: ASP Callback
ESP sends the signed response to ASP's callback URL:

```bash
# This is what ASP receives at callback URL
# POST https://your-asp-server.com/esign/callback
# Content-Type: application/xml
# Body: Signed eSign response XML

# ASP should:
# 1. Verify ESP's signature on the response
# 2. Extract PKCS#7 signature
# 3. Store the signature with the document
# 4. Verify the signature against document hash
```

### Step 8: Check Transaction Status
ASP can check status anytime:

```bash
# Create status request
STATUS_XML=$(cat << EOF
<?xml version="1.0" encoding="UTF-8"?>
<EsignStatus ver="2.1" ts="$(date -u +%Y-%m-%dT%H:%M:%S)" 
             txn="STATUS-$(date +%s)" aspId="ASP001" 
             respAttemptNo="1">
    <TxnList>
        <Txn>$TXN_ID</Txn>
    </TxnList>
</EsignStatus>
EOF
)

# Send status check request
curl -X POST http://localhost:8080/authenticate/check-status \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "statusRequest=$(echo "$STATUS_XML" | base64 -w 0)"

# Or use JSON API
curl -X POST http://localhost:8080/authenticate/check-status-api \
  -H "Content-Type: application/json" \
  -d "{
    \"aspId\": \"ASP001\",
    \"transactions\": [\"$TXN_ID\"]
  }"
```

## Complete Flow Example

Here's a complete working example for OTP-based signing:

```bash
#!/bin/bash

# Configuration
ESP_URL="http://localhost:8080"
ASP_ID="ASP001"
AADHAAR="999999990019"
DOCUMENT="test-document.pdf"

echo "=== eSign Complete Flow Example ==="

# Step 1: Generate document hash
echo "1. Generating document hash..."
DOC_HASH=$(sha256sum "$DOCUMENT" | cut -d' ' -f1)
echo "   Document: $DOCUMENT"
echo "   Hash: $DOC_HASH"

# Step 2: Create eSign request
echo "2. Creating eSign request..."
TXN_ID="ASP-$(date +%s)"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S)

REQUEST_XML="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Esign ver=\"2.1\" sc=\"Y\" ts=\"$TIMESTAMP\" txn=\"$TXN_ID\" 
       ekycIdType=\"A\" ekycId=\"$AADHAAR\" aspId=\"$ASP_ID\" 
       AuthMode=\"1\" responseSigType=\"pkcs7\" 
       preVerified=\"n\" organizationFlag=\"n\" 
       responseUrl=\"http://localhost:9090/callback\">
    <Docs>
        <InputHash id=\"1\" hashAlgorithm=\"SHA256\" docInfo=\"Test Document\">
            $DOC_HASH
        </InputHash>
    </Docs>
</Esign>"

# Step 3: Send request
echo "3. Sending eSign request..."
REQUEST_B64=$(echo "$REQUEST_XML" | base64 -w 0)

RESPONSE=$(curl -s -X POST $ESP_URL/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_B64" \
  -d "aspTxnId=$TXN_ID" \
  -c cookies.txt \
  -w "\nHTTP_CODE:%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
echo "   Response Code: $HTTP_CODE"

# Step 4: Generate OTP
echo "4. Generating OTP..."
read -p "   Enter Aadhaar number: " USER_AADHAAR

OTP_RESPONSE=$(curl -s -X POST $ESP_URL/authenticate/otp \
  -H "Content-Type: application/json" \
  -d "{
    \"aadhaar\": \"$USER_AADHAAR\",
    \"requestId\": 1
  }" \
  -b cookies.txt \
  -c cookies.txt)

echo "   OTP Response: $OTP_RESPONSE"
OTP_TXN=$(echo "$OTP_RESPONSE" | jq -r '.txn')

# Step 5: Verify OTP
echo "5. Verifying OTP..."
read -p "   Enter OTP received on mobile: " USER_OTP

VERIFY_RESPONSE=$(curl -s -X POST $ESP_URL/authenticate/otpAction \
  -H "Content-Type: application/json" \
  -d "{
    \"otp\": \"$USER_OTP\",
    \"txnId\": \"$OTP_TXN\",
    \"aadhaar\": \"$USER_AADHAAR\",
    \"requestId\": 1
  }" \
  -b cookies.txt)

echo "   Verification Response: $VERIFY_RESPONSE"

# Step 6: Check status
echo "6. Checking transaction status..."
sleep 2

STATUS_RESPONSE=$(curl -s -X POST $ESP_URL/authenticate/check-status-api \
  -H "Content-Type: application/json" \
  -d "{
    \"aspId\": \"$ASP_ID\",
    \"transactions\": [\"$TXN_ID\"]
  }")

echo "   Status: $STATUS_RESPONSE"

# Step 7: Handle callback
echo "7. Waiting for callback..."
echo "   In production, ESP will send signed response to your callback URL"
echo "   Transaction ID: $TXN_ID"

# Cleanup
rm -f cookies.txt

echo "=== Flow completed ==="
```

## Error Handling

### Common Error Scenarios

1. **Invalid ASP (ESP-001)**
```bash
# Response when ASP is not registered
{
  "errCode": "ESP-001",
  "errMsg": "Invalid ASP ID or ASP not active"
}
```

2. **Expired Request (ESP-003)**
```bash
# Request older than 5 minutes
{
  "errCode": "ESP-003",
  "errMsg": "Request has expired"
}
```

3. **Authentication Failed (ESP-004)**
```bash
# Wrong OTP or biometric mismatch
{
  "errCode": "ESP-004",
  "errMsg": "Authentication failed"
}
```

4. **Rate Limit Exceeded (ESP-429)**
```bash
# Too many requests
{
  "errCode": "ESP-429",
  "errMsg": "Rate limit exceeded. Try after sometime"
}
```

### Retry Logic
```bash
# For transient failures, implement exponential backoff
for i in {1..3}; do
    echo "Attempt $i..."
    
    # Make request
    RESPONSE=$(curl -s -w "\n%{http_code}" ...)
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    
    if [ "$HTTP_CODE" -eq 200 ]; then
        echo "Success!"
        break
    fi
    
    # Exponential backoff
    SLEEP_TIME=$((2 ** i))
    echo "Failed. Retrying after ${SLEEP_TIME}s..."
    sleep $SLEEP_TIME
done
```

## Security Considerations

### 1. ASP Security
- Always sign requests with your private key
- Verify ESP's signature on responses
- Use HTTPS for callbacks
- Implement request timeouts

### 2. Document Security
- Never send actual documents
- Verify hash after signing
- Store signatures securely
- Maintain audit trails

### 3. User Privacy
- Don't store Aadhaar numbers
- Encrypt KYC data at rest
- Implement data retention policies
- Follow UIDAI guidelines

### 4. Network Security
```bash
# Use HTTPS in production
ESP_URL="https://esign.example.com"

# Verify SSL certificate
curl --cacert esp-ca.crt \
     --cert asp-client.crt \
     --key asp-client.key \
     $ESP_URL/authenticate/health
```

## Testing Different Scenarios

### 1. Multiple Documents
```bash
# Sign multiple documents in one request
REQUEST_XML="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Esign ver=\"2.1\" sc=\"Y\" ts=\"$TIMESTAMP\" txn=\"$TXN_ID\" 
       ekycIdType=\"A\" ekycId=\"$AADHAAR\" aspId=\"$ASP_ID\" 
       AuthMode=\"1\" responseSigType=\"pkcs7\">
    <Docs>
        <InputHash id=\"1\" hashAlgorithm=\"SHA256\" docInfo=\"Document 1\">
            $(sha256sum doc1.pdf | cut -d' ' -f1)
        </InputHash>
        <InputHash id=\"2\" hashAlgorithm=\"SHA256\" docInfo=\"Document 2\">
            $(sha256sum doc2.pdf | cut -d' ' -f1)
        </InputHash>
        <InputHash id=\"3\" hashAlgorithm=\"SHA256\" docInfo=\"Document 3\">
            $(sha256sum doc3.pdf | cut -d' ' -f1)
        </InputHash>
    </Docs>
</Esign>"
```

### 2. Cancel Request
```bash
# User cancels during authentication
curl -X POST $ESP_URL/authenticate/esignCancel \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "kid=1" \
  -d "cr=User cancelled the request" \
  -b cookies.txt
```

### 3. Biometric with WADH
```bash
# Calculate WADH for fingerprint
WADH=$(echo -n "2.5FYNNN" | sha256sum | cut -d' ' -f1)
echo "WADH for Fingerprint: $WADH"

# For Iris
WADH_IRIS=$(echo -n "2.5IYNNN" | sha256sum | cut -d' ' -f1)
echo "WADH for Iris: $WADH_IRIS"
```

## Monitoring and Debugging

### 1. Enable Debug Logging
```yaml
# config.yaml
debug:
  logRequests: true
  logResponses: true
  prettyPrint: true
```

### 2. Monitor Transactions
```bash
# View transaction logs
psql -U esign -d esign_db << EOF
SELECT 
    id,
    asp_id,
    asp_txn_id,
    status,
    request_time,
    response_time,
    client_ip
FROM transactions
WHERE asp_id = 'ASP001'
ORDER BY request_time DESC
LIMIT 10;
EOF
```

### 3. Check Rate Limits
```bash
# Monitor rate limit hits
curl -X GET $ESP_URL/metrics | grep rate_limit
```

## Production Checklist

- [ ] Configure production database
- [ ] Set up Redis cluster
- [ ] Install SSL certificates
- [ ] Configure rate limits
- [ ] Set up monitoring
- [ ] Enable audit logging
- [ ] Configure backup strategy
- [ ] Set up load balancer
- [ ] Configure firewall rules
- [ ] Document runbooks

## Conclusion

This comprehensive guide covers the complete eSign flow from request initiation to signature delivery. The key to successful implementation is understanding the state transitions and handling errors gracefully. Always test thoroughly in a staging environment before production deployment.