# eSign API Quick Reference

## Base URL
```
http://localhost:8080
```

## Authentication Flows

### 🔐 OTP Authentication Flow
```bash
# 1. Initiate eSign
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -d "eSignRequest=BASE64_XML&aspTxnId=ASP-123"

# 2. Generate OTP
curl -X POST http://localhost:8080/authenticate/otp \
  -d "aadhaar=999999990019&requestId=1"

# 3. Verify OTP
curl -X POST http://localhost:8080/authenticate/otpAction \
  -d "otp=123456&txnId=OTP-TXN-ID&aadhaar=999999990019"
```

### 🖐️ Biometric Authentication Flow
```bash
# 1. Initiate eSign (AuthMode=2)
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -d "eSignRequest=BASE64_XML&aspTxnId=ASP-BIO-123"

# 2. Submit Biometric
curl -X POST http://localhost:8080/authenticate/postRequestdata \
  -d "PidData=BASE64_PID_DATA&requestId=1"
```

### 👁️ Iris Authentication Flow
```bash
# Same as biometric but with AuthMode=3 in XML
```

## Utility Endpoints

### 📊 Check Status
```bash
# XML Format
curl -X POST http://localhost:8080/authenticate/check-status \
  -d "statusRequest=BASE64_STATUS_XML"

# JSON Format
curl -X POST http://localhost:8080/authenticate/check-status-api \
  -H "Content-Type: application/json" \
  -d '{"aspId":"TEST001","transactions":["TXN-123"]}'
```

### ❌ Cancel eSign
```bash
curl -X POST http://localhost:8080/authenticate/esignCancel \
  -d "requestId=1&reason=User cancelled"
```

### 🏃 Direct Processing (Pre-authenticated)
```bash
curl -X POST http://localhost:8080/authenticate/es \
  -d "eSignRequest=BASE64_XML_WITH_SIGNATURE"
```

### 👤 Face Recognition
```bash
curl -X POST http://localhost:8080/authenticate/fcr \
  -H "Content-Type: application/json" \
  -d '{"requestId":"1","faceImage":"BASE64_IMAGE","aadhaarNumber":"999999990019"}'
```

### ❤️ Health Check
```bash
curl http://localhost:8080/health
```

## Request XML Structure

### Basic eSign Request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="2025-06-05T12:00:00" txn="UNIQUE-TXN-ID" 
       ekycIdType="A" ekycId="999999990019" aspId="TEST001" 
       AuthMode="1" responseSigType="pkcs7" preVerified="n" 
       organizationFlag="n" responseUrl="https://callback.url">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Document Title">
            SHA256_HASH_OF_DOCUMENT
        </InputHash>
    </Docs>
</Esign>
```

### Status Check Request
```xml
<?xml version="1.0" encoding="UTF-8"?>
<EsignStatus ver="2.1" ts="2025-06-05T12:00:00" txn="STATUS-TXN-ID" 
             aspId="TEST001" respAttemptNo="1">
    <TxnList>
        <Txn>TXN-ID-1</Txn>
        <Txn>TXN-ID-2</Txn>
    </TxnList>
</EsignStatus>
```

## AuthMode Values
- `1` = OTP
- `2` = Fingerprint  
- `3` = Iris

## Response Codes
- `200` = Success
- `400` = Bad Request
- `401` = Unauthorized
- `429` = Rate Limited
- `500` = Server Error

## Common Error Codes
- `ESP-001` = Invalid ASP ID
- `ESP-002` = Invalid XML Format
- `ESP-003` = Expired Request
- `ESP-004` = Authentication Failed
- `ESP-005` = KYC Fetch Failed
- `ESP-006` = Signing Failed

## Rate Limits
- `/authenticate/esign-doc`: 10 req/min
- `/authenticate/check-status`: 20 req/min

## Testing Tips

### Generate Test Hash
```bash
echo -n "Your document content" | sha256sum | cut -d' ' -f1
```

### Base64 Encode XML
```bash
# macOS
echo "$XML" | base64

# Linux
echo "$XML" | base64 -w 0
```

### Pretty Print XML Response
```bash
curl ... | xmllint --format -
```

### Save & Use Session
```bash
# Save cookies
curl ... -c cookies.txt

# Use saved cookies
curl ... -b cookies.txt
```

## Quick Test Commands

### Test with minimal XML
```bash
XML='<Esign ver="2.1" ts="'$(date -u +%Y-%m-%dT%H:%M:%S)'" txn="TEST-'$(date +%s)'" aspId="TEST001" AuthMode="1"><Docs><InputHash id="1">test</InputHash></Docs></Esign>'

curl -X POST http://localhost:8080/authenticate/esign-doc \
  -d "eSignRequest=$(echo $XML | base64)"
```

### Monitor Server Logs
```bash
# Terminal 1: Run server
go run .

# Terminal 2: Watch logs
tail -f server.log | grep -E "(REQUEST|RESPONSE|ERROR)"
```

### Test Rate Limiting
```bash
for i in {1..15}; do 
  curl -X POST http://localhost:8080/authenticate/esign-doc \
    -d "eSignRequest=test" -w "\n%{http_code}\n"
  sleep 0.5
done
```