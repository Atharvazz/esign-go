#!/bin/bash

# Print the encoded data
echo "Base64 content:"
cat test_esign_request_encoded.txt
echo ""
echo "Length: $(wc -c < test_esign_request_encoded.txt)"

# URL encode the data
ENCODED=$(cat test_esign_request_encoded.txt | python3 -c "import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip()))")

echo ""
echo "URL encoded length: ${#ENCODED}"

# Send request with proper URL encoding
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "msg=${ENCODED}" \
  -v