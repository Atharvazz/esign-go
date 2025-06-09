#!/bin/bash

# Create directory for test keys
mkdir -p test-keys

# Generate RSA private key
openssl genrsa -out test-keys/private.key 2048

# Generate public key from private key
openssl rsa -in test-keys/private.key -pubout -out test-keys/public.key

# Generate self-signed certificate
openssl req -new -x509 -key test-keys/private.key -out test-keys/certificate.crt -days 365 \
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=Test Organization/OU=Development/CN=localhost"

# Generate CA private key
openssl genrsa -out test-keys/ca-private.key 2048

# Generate CA certificate
openssl req -new -x509 -key test-keys/ca-private.key -out test-keys/ca-certificate.crt -days 365 \
    -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=Test CA/OU=Development/CN=Test CA"

echo "Test keys generated successfully!"