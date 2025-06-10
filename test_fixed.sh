#!/bin/bash

# Read the encoded request
ENCODED_REQUEST=$(cat test_esign_request_fixed_encoded.txt | tr -d '\n')

# Send the request
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "msg=${ENCODED_REQUEST}" \
  -v