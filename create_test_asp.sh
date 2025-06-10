#!/bin/bash

# Create test ASP in database
psql -U esign_user -d esign_db <<EOF
INSERT INTO asps (asp_id, name, cert_user_cn, cert_serial_no, cert_valid_from, cert_valid_to, status, aum_id, org_name, quota_mode, overdraft, available_quota, created_at, updated_at)
VALUES (
    'TEST001',
    'Test ASP',
    'CN=Test ASP,O=Test Organization,C=IN',
    '12345',
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '365 days',
    'ACTIVE',
    'AUM001',
    'Test Organization',
    'DISABLED',
    0,
    1000,
    NOW(),
    NOW()
);
EOF

echo "Test ASP created successfully"