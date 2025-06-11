# eSign Server Troubleshooting Guide

## Current Issue Analysis

Based on the logs, I can see:

### ✅ What's Working:
- Main server is running on port 8080
- Requests are being received at `/authenticate/esign-doc`
- Logging and security masking is working
- Database connection is healthy

### ❌ Current Error:
```
ERRO[...] XSD validation failed error="missing required attribute: AuthMode"
DEBU[...] Creating error response ext_code=ESP-102 int_code=ESP-102 message="Invalid request format"
```

## Root Cause

The XML request is missing required attributes. The server expects a properly formatted eSign 2.1 XML request with all mandatory fields.

## Required XML Format

Here's the correct eSign 2.1 XML format:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" 
       ts="2025-06-10T17:37:23.810Z" 
       txn="TEST-TXN-001" 
       ekycId="123456789012" 
       ekycIdType="A" 
       aspId="TEST-ASP-001" 
       AuthMode="1" 
       responseSigType="pkcs7" 
       responseUrl="http://localhost:8091/callback" 
       sc="Y">
    <Docs>
        <InputHash id="1" 
                   hashAlgorithm="SHA256" 
                   docInfo="Test Document">
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        </InputHash>
    </Docs>
</Esign>
```

## Required Attributes Explanation

| Attribute | Description | Example Value |
|-----------|-------------|---------------|
| `ver` | eSign version | "2.1" |
| `ts` | Timestamp (ISO format) | "2025-06-10T17:37:23.810Z" |
| `txn` | Transaction ID | "TEST-TXN-001" |
| `ekycId` | Aadhaar number | "123456789012" |
| `ekycIdType` | ID type (A=Aadhaar) | "A" |
| `aspId` | ASP identifier | "TEST-ASP-001" |
| `AuthMode` | Authentication mode | "1" (OTP), "2" (Biometric), "3" (Iris) |
| `responseSigType` | Response signature type | "pkcs7" |
| `responseUrl` | Callback URL | "http://localhost:8091/callback" |
| `sc` | Signature Certificate | "Y" |

## Authentication Modes

| AuthMode | Description |
|----------|-------------|
| 1 | OTP Authentication |
| 2 | Fingerprint Biometric |
| 3 | Iris Biometric |
| 4 | Face Recognition |
| 5 | Offline KYC |

## Quick Fix - Test with Valid XML

### 1. Create a test XML file:

```bash
cat > test_valid_esign_request.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" 
       ts="2025-06-10T18:00:00.000Z" 
       txn="TEST-TXN-001" 
       ekycId="123456789012" 
       ekycIdType="A" 
       aspId="TEST-ASP-001" 
       AuthMode="1" 
       responseSigType="pkcs7" 
       responseUrl="http://localhost:8091/callback" 
       sc="Y">
    <Docs>
        <InputHash id="1" 
                   hashAlgorithm="SHA256" 
                   docInfo="Test Document">
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        </InputHash>
    </Docs>
</Esign>
EOF
```

### 2. Test with curl:

```bash
# URL encode the XML
XML_CONTENT=$(cat test_valid_esign_request.xml | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read()))")

# Send POST request
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "msg=$XML_CONTENT"
```

### 3. Or use the frontend form:

1. Open: http://localhost:3000/esign-test.html
2. Fill in the form with proper values:
   - Transaction ID: TEST-TXN-001
   - Aadhaar Number: 123456789012
   - ASP ID: TEST-ASP-001
   - Auth Mode: 1 (for OTP)
   - Callback URL: http://localhost:8091/callback

## Frontend Form Validation

Make sure the frontend forms are generating the correct XML. Check:

1. **All required fields are filled**
2. **AuthMode is set correctly**
3. **Timestamp format is ISO 8601**
4. **Aadhaar number is 12 digits**
5. **Callback URL is reachable**

## Monitoring the Fix

### Watch the logs:
```bash
tail -f logs/main_debug_server.log | grep -E "(ERRO|DEBU|INFO)"
```

### Check callback server:
```bash
tail -f logs/callback_server.log
```

### Expected Success Log:
```
INFO[...] req_start_authAndEkyc request_id="..."
DEBU[...] Inside PreValidateAndPrepare
DEBU[...] XML validation passed
INFO[...] Authentication flow initiated
INFO[...] req_end_authAndEkyc request_id="..."
```

## Common Issues and Fixes

### Issue 1: Missing AuthMode
**Error**: `missing required attribute: AuthMode`
**Fix**: Add `AuthMode="1"` to the Esign root element

### Issue 2: Invalid Timestamp
**Error**: `invalid timestamp format`
**Fix**: Use ISO 8601 format: `YYYY-MM-DDTHH:MM:SS.sssZ`

### Issue 3: Invalid Aadhaar
**Error**: `invalid Aadhaar format`
**Fix**: Use 12-digit number for ekycId

### Issue 4: Missing Callback URL
**Error**: `invalid response URL`
**Fix**: Ensure responseUrl is a valid HTTP URL

## Test Authentication Flows

### 1. OTP Flow Test:
```xml
<Esign ... AuthMode="1" ...>
```
Expected: Redirect to OTP input page

### 2. Biometric Flow Test:
```xml
<Esign ... AuthMode="2" ...>
```
Expected: Redirect to fingerprint capture page

### 3. Iris Flow Test:
```xml
<Esign ... AuthMode="3" ...>
```
Expected: Redirect to iris scan page

## Next Steps

1. **Fix the XML format** in your test requests
2. **Use proper AuthMode values**
3. **Ensure all required attributes are present**
4. **Test with the corrected XML**
5. **Monitor logs for successful validation**

The server is working correctly - it's just enforcing proper XML validation as per eSign 2.1 specification!