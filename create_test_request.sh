#!/bin/bash

# Get current timestamp in RFC3339 format with timezone
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Create XML with current timestamp
cat > test_esign_request_current.xml <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<Esign ver="2.1" sc="Y" ts="${TIMESTAMP}" txn="TEST-001" 
       aspId="TEST001" 
       AuthMode="1" responseSigType="pkcs7" 
       preVerified="n" organizationFlag="n" 
       responseUrl="http://localhost:8080/callback">
    <Docs>
        <InputHash id="1" hashAlgorithm="SHA256" docInfo="Test Document">a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5</InputHash>
    </Docs>
</Esign>
EOF

# Encode in base64
base64 -i test_esign_request_current.xml -o test_esign_request_current_encoded.txt

# Send request
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "msg=$(cat test_esign_request_current_encoded.txt | tr -d '\n')" \
  -v