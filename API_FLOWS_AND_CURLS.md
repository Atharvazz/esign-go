# eSign API Flows and CURL Commands

## Overview
The eSign service follows the UIDAI eSign 2.1 specification. The typical flow involves:
1. ASP sends eSign request with document hash
2. User authenticates (OTP/Biometric/Iris)
3. KYC data is fetched from UIDAI
4. Digital signature is created
5. Signed response is sent back to ASP

## Complete Flow Examples

### 1. OTP-Based eSign Flow

#### Step 1: Initiate eSign Request
```bash
# Create base64 encoded XML request
REQUEST_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2025-06-05T12:00:00" txn="TEST-TXN-001" ekycIdType="A" 
       ekycId="999999990019" aspId="TEST001" AuthMode="1" 
       responseSigType="pkcs7" preVerified="n" organizationFlag="n" 
       responseUrl="https://example.com/esign/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Sample Agreement">
            a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5
        </InputHash>
    </Docs>
</Esign>' | base64 -w 0)

# Send eSign request
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_XML" \
  -d "aspTxnId=ASP-TXN-001" \
  -d "Content-Type=application/xml" \
  -c cookies.txt \
  -L -v

# This will redirect to auth page, save the redirect URL
```

#### Step 2: Generate OTP
```bash
# Using the session from previous request
curl -X POST http://localhost:8080/authenticate/otp \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "aadhaar=999999990019" \
  -d "requestId=1" \
  -b cookies.txt \
  -c cookies.txt

# Response:
# {
#   "status": "success",
#   "message": "OTP sent successfully",
#   "txnId": "OTP-TXN-ID"
# }
```

#### Step 3: Verify OTP
```bash
curl -X POST http://localhost:8080/authenticate/otpAction \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "otp=123456" \
  -d "txnId=OTP-TXN-ID" \
  -d "aadhaar=999999990019" \
  -b cookies.txt \
  -c cookies.txt

# This completes authentication and generates the signature
```

### 2. Biometric-Based eSign Flow

#### Step 1: Initiate eSign Request (Fingerprint)
```bash
REQUEST_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2025-06-05T12:00:00" txn="BIO-TXN-001" ekycIdType="A" 
       ekycId="999999990019" aspId="TEST001" AuthMode="2" 
       responseSigType="pkcs7" preVerified="n" organizationFlag="n" 
       responseUrl="https://example.com/esign/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Loan Agreement">
            b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7
        </InputHash>
    </Docs>
</Esign>' | base64 -w 0)

curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_XML" \
  -d "aspTxnId=ASP-BIO-001" \
  -c cookies.txt \
  -L
```

#### Step 2: Submit Biometric Data
```bash
# Biometric data format (PID block)
BIOMETRIC_DATA='<?xml version="1.0" encoding="UTF-8"?>
<PidData>
    <Resp errCode="0" errInfo="Success" fCount="1" fType="2" nmPoints="30" qScore="70"/>
    <DeviceInfo dpId="MANTRA.MSIPL" rdsId="MANTRA.WIN.001" rdsVer="1.0.4" mi="MFS100" mc="MIIEGDCCAwCgAwIBAgIEAQAAADANBgkqhkiG9w0BAQsFADCB6jEqMCgGA1UEAxMhRFMgTWFudHJhIFNvZnRlY2ggSW5kaWEgUHZ0IEx0ZCA3MUMwQQYDVQQzEzpCIDIwMyBTaGFwYXRoIEhleGEgb3Bwb3NpdGUgR3VqYXJhdCBIaWdoIENvdXJ0IFMgRyBIaWdod2F5MRIwEAYDVQQJEwlBaG1lZGFiYWQxEDAOBgNVBAgTB0d1amFyYXQxHTAbBgNVBAsTFFRlY2huaWNhbCBEZXBhcnRtZW50MSUwIwYDVQQKExxNYW50cmEgU29mdGVjaCBJbmRpYSBQdnQgTHRkMQswCQYDVQQGEwJJTjAeFw0yMzEyMjgwNTI1MDJaFw0yMzEyMjgwNTQ1MDJaMIGwMSUwIwYDVQQDExxNYW50cmEgU29mdGVjaCBJbmRpYSBQdnQgTHRkMR4wHAYDVQQLExVCaW9tZXRyaWMgTWFudWZhY3R1cmUxDjAMBgNVBAoTBU1TSVBMMRIwEAYDVQQHEwlBSE1FREFCQUQxEDAOBgNVBAgTB0dVSkFSQVQxCzAJBgNVBAYTAklOMSQwIgYJKoZIhvcNAQkBFhVzdXBwb3J0QG1hbnRyYXRlYy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaNmkr077p8A0sJ0D3aLLeU/RwbWSj5mCsXYmQ1mUg8MkdBJLSEZBzUl3QQG3pWseLM3MqCz4GcjlXcvLvp71v0sXgJQqQiRX7Q3FGFdyf7ZqmBoVfvI7J1DdPvByhPXFgKfFBUzoOQQR2KQx8cXNUWgUtUTpwUVJRJcVR8+ty1b8oo9zZMd3hShIV0gF5YvNNHZprmGwF8PNVzR8SqFTbmDSDhh+VTNMrtM8hKqJGsqM5U7WFNj7p5xYMNviQKG4EvmNjUeE3HA8KM8WLBnS/lOx6JKnbLJLRXCBKVJGvUq9oVRMdBdTTjCJVhY+sgVFKB/aSn7YFeU3D3ad/Bk3xAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAKqvu1xMD8JLpKAHH6NLXbQPWt6xupTzfEIl6iR0n5RK7cNNXDW2PfpMbI8Y8IDAuUAQxVVN6uY6gRJES8g9HCCYUUjJGEb4vhHb+WI7Bqd2ESMB7hPveWL6yaOSRN9majdsJt8PeCCzP7xgOPKDDM7L9YGGkH5r4rEpnH8V/J8RlFGYlBJEd8g6jDO5bqM3Qd4lCsvVoMTkON4viPZdrWLekulKJHPFB3WxvNQsYPtjGsxZ5ztsFi2vkMBvQPLqUrbVPB7DqgYQ/d3yJPJcBT8kWWU3vhGOjPYTPgHCQPafmCCaVKPCKdJNLNpvQOvJ8pNNVJPB9LyqQtQnSP7BN8="/>
    <Skey ci="20250605">ENCRYPTED_SESSION_KEY</Skey>
    <Hmac>HMAC_VALUE</Hmac>
    <Data type="X">ENCRYPTED_PID_DATA</Data>
</PidData>'

curl -X POST http://localhost:8080/authenticate/postRequestdata \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "PidData=$(echo "$BIOMETRIC_DATA" | base64 -w 0)" \
  -d "requestId=1" \
  -b cookies.txt \
  -c cookies.txt
```

### 3. Iris-Based eSign Flow

#### Step 1: Initiate eSign Request (Iris)
```bash
REQUEST_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2025-06-05T12:00:00" txn="IRIS-TXN-001" ekycIdType="A" 
       ekycId="999999990019" aspId="TEST001" AuthMode="3" 
       responseSigType="pkcs7" preVerified="n" organizationFlag="n" 
       responseUrl="https://example.com/esign/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Property Document">
            c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8
        </InputHash>
    </Docs>
</Esign>' | base64 -w 0)

curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_XML" \
  -d "aspTxnId=ASP-IRIS-001" \
  -c cookies.txt \
  -L
```

### 4. Check Transaction Status

#### Check Status Request
```bash
# Create status check XML
STATUS_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<EsignStatus ver="2.1" ts="2025-06-05T12:00:00" txn="STATUS-CHECK-001" 
             aspId="TEST001" respAttemptNo="1">
    <TxnList>
        <Txn>TEST-TXN-001</Txn>
        <Txn>BIO-TXN-001</Txn>
        <Txn>IRIS-TXN-001</Txn>
    </TxnList>
</EsignStatus>' | base64 -w 0)

# Check status
curl -X POST http://localhost:8080/authenticate/check-status \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "statusRequest=$STATUS_XML"

# Response will be XML with status of each transaction
```

#### Check Status API (JSON)
```bash
curl -X POST http://localhost:8080/authenticate/check-status-api \
  -H "Content-Type: application/json" \
  -d '{
    "aspId": "TEST001",
    "transactions": ["TEST-TXN-001", "BIO-TXN-001"]
  }'

# JSON Response:
# {
#   "status": "success",
#   "transactions": [
#     {
#       "txn": "TEST-TXN-001",
#       "status": "COMPLETED",
#       "timestamp": "2025-06-05T12:30:00Z"
#     },
#     {
#       "txn": "BIO-TXN-001",
#       "status": "PENDING",
#       "timestamp": "2025-06-05T12:25:00Z"
#     }
#   ]
# }
```

### 5. Cancel eSign Request

```bash
curl -X POST http://localhost:8080/authenticate/esignCancel \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "requestId=1" \
  -d "reason=User cancelled the request" \
  -b cookies.txt \
  -c cookies.txt

# Response:
# {
#   "status": "success",
#   "message": "eSign request cancelled successfully"
# }
```

### 6. Direct eSign Processing (Pre-authenticated)

```bash
# For pre-authenticated requests where KYC is already available
REQUEST_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2025-06-05T12:00:00" txn="PRE-AUTH-001" ekycIdType="A" 
       ekycId="999999990019" aspId="TEST001" AuthMode="1" 
       responseSigType="pkcs7" preVerified="y" organizationFlag="n" 
       responseUrl="https://example.com/esign/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Pre-authenticated Document">
            d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9
        </InputHash>
    </Docs>
    <Signature>PRE_AUTH_SIGNATURE</Signature>
</Esign>' | base64 -w 0)

curl -X POST http://localhost:8080/authenticate/es \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_XML"
```

### 7. Offline KYC Flow

#### Step 1: Generate OTP for Offline KYC
```bash
curl -X POST http://localhost:8080/authenticate/okycOtpView \
  -H "Content-Type: application/json" \
  -d '{
    "aadhaarNumber": "999999990019",
    "shareCode": "1234",
    "requestId": "OKYC-REQ-001"
  }'

# Response:
# {
#   "status": "success",
#   "txnId": "OKYC-TXN-001",
#   "message": "OTP sent for offline KYC"
# }
```

#### Step 2: Verify Offline KYC OTP
```bash
curl -X POST http://localhost:8080/authenticate/okycVerify \
  -H "Content-Type: application/json" \
  -d '{
    "txnId": "OKYC-TXN-001",
    "otp": "123456",
    "xmlData": "BASE64_ENCODED_OFFLINE_KYC_XML"
  }'
```

### 8. Face Recognition Flow

```bash
# Face recognition for additional verification
curl -X POST http://localhost:8080/authenticate/fcr \
  -H "Content-Type: application/json" \
  -d '{
    "requestId": "1",
    "faceImage": "BASE64_ENCODED_FACE_IMAGE",
    "aadhaarNumber": "999999990019"
  }' \
  -b cookies.txt

# Response:
# {
#   "status": "success",
#   "matchScore": 95.5,
#   "verified": true
# }
```

## Testing Tips

### 1. Test ASP Setup
First, ensure you have a test ASP in the database:
```bash
psql -U esign -d esign_db -h localhost -c "
INSERT INTO asps (id, name, public_key, callback_url, is_active, require_signature) 
VALUES ('TEST001', 'Test ASP', '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----', 
'https://example.com/callback', true, false) 
ON CONFLICT (id) DO NOTHING;"
```

### 2. Session Management
Always use `-c cookies.txt -b cookies.txt` to maintain session across requests.

### 3. Base64 Encoding
On macOS, use `base64` without `-w 0`. On Linux, use `base64 -w 0` to avoid line wrapping.

### 4. View Redirect Response
Use `-L -v` to follow redirects and see verbose output:
```bash
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "eSignRequest=$REQUEST_XML" \
  -L -v
```

### 5. Test Error Scenarios

#### Invalid ASP ID
```bash
REQUEST_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2025-06-05T12:00:00" txn="ERROR-001" 
       aspId="INVALID_ASP" AuthMode="1">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256">test</InputHash>
    </Docs>
</Esign>' | base64)

curl -X POST http://localhost:8080/authenticate/esign-doc \
  -d "eSignRequest=$REQUEST_XML"
```

#### Expired Request
```bash
REQUEST_XML=$(echo '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2020-01-01T12:00:00" txn="EXPIRED-001" 
       aspId="TEST001" AuthMode="1">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256">test</InputHash>
    </Docs>
</Esign>' | base64)

curl -X POST http://localhost:8080/authenticate/esign-doc \
  -d "eSignRequest=$REQUEST_XML"
```

## Response Formats

### Successful eSign Response
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" ts="2025-06-05T12:30:00" txn="TEST-TXN-001" 
       resCode="200" errCode="" errMsg="">
    <Signatures>
        <DocSignature id="1">BASE64_PKCS7_SIGNATURE</DocSignature>
    </Signatures>
    <UserX509Certificate>BASE64_USER_CERTIFICATE</UserX509Certificate>
    <Resp status="1">
        <ts>2025-06-05T12:30:00</ts>
    </Resp>
</Esign>
```

### Error Response
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" ts="2025-06-05T12:30:00" txn="TEST-TXN-001" 
       resCode="400" errCode="ESP-001" errMsg="Invalid ASP ID">
    <Resp status="0">
        <ts>2025-06-05T12:30:00</ts>
    </Resp>
</Esign>
```

## Webhook/Callback

The ASP's callback URL will receive a POST request with the signed response:
```bash
# Sample callback implementation
curl -X POST https://your-asp-server.com/esign/callback \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" ts="2025-06-05T12:30:00" txn="TEST-TXN-001">
    <!-- Full signed response -->
</Esign>'
```

## Rate Limiting

The API has rate limiting enabled:
- `/authenticate/esign-doc`: 10 requests per minute
- `/authenticate/check-status`: 20 requests per minute

Test rate limiting:
```bash
# This will trigger rate limiting after 10 requests
for i in {1..15}; do
  echo "Request $i:"
  curl -X POST http://localhost:8080/authenticate/esign-doc \
    -d "eSignRequest=test" \
    -w "\nHTTP Status: %{http_code}\n"
  sleep 1
done
```

## Health Check

```bash
# Basic health check
curl http://localhost:8080/health

# With jq formatting
curl -s http://localhost:8080/health | jq

# Continuous monitoring
watch -n 5 'curl -s http://localhost:8080/health | jq'
```

## Debug Mode

To see detailed request/response logs, ensure debug mode is enabled in config:
```yaml
debug:
  logRequests: true
  logResponses: true
  prettyPrint: true
```

Then monitor logs:
```bash
# Run server with debug output
go run . 2>&1 | tee server.log

# In another terminal, filter logs
tail -f server.log | grep -E "(REQUEST|RESPONSE|ERROR)"
```