#!/bin/bash

# Read the encoded request
ENCODED_REQUEST=$(cat test_esign_request_encoded.txt)

# Send the request
curl -X POST http://localhost:8080/authenticate/esign-doc \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "msg=${ENCODED_REQUEST}" \
  -v