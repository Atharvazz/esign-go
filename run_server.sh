#!/bin/bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
go run cmd/server/main_debug.go 2>&1 | tee server_debug.log &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"
sleep 5
echo "=== Server Output ==="
cat server_debug.log | head -200
echo "=== Killing server ==="
kill $SERVER_PID 2>/dev/null || true