# Manual Service Startup Guide

## Prerequisites
Make sure you're in the project directory:
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
```

## 1. Main eSign Server (Port 8080)

### Start Command:
```bash
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go
```

### Or run in background:
```bash
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go > logs/main_debug_server.log 2>&1 &
```

### Verify it's running:
```bash
curl http://localhost:8080/health
```

## 2. Callback Server (Port 8091)

### Start Command:
```bash
go run mock-callback-server.go
```

### Or run in background:
```bash
go run mock-callback-server.go > logs/callback_server.log 2>&1 &
```

### Verify it's running:
```bash
curl http://localhost:8091/health
```

## 3. Test Server (Port 8090) - Optional

### Start Command:
```bash
go run test_server3.go
```

### Or run in background:
```bash
go run test_server3.go > logs/test_server.log 2>&1 &
```

### Verify it's running:
```bash
curl http://localhost:8090/health
```

## Starting All Services Together

### Option 1: Run each in a separate terminal
Open 3 terminal windows and run each command in its own terminal.

### Option 2: Use the startup script
```bash
./start_all_services.sh
```

### Option 3: Start all in background
```bash
# Start main server
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go > logs/main_debug_server.log 2>&1 &
echo "Main server PID: $!"

# Start callback server
go run mock-callback-server.go > logs/callback_server.log 2>&1 &
echo "Callback server PID: $!"

# Optional: Start test server
go run test_server3.go > logs/test_server.log 2>&1 &
echo "Test server PID: $!"
```

## Checking Service Status

### Check if services are running:
```bash
ps aux | grep -E "go run|main_debug" | grep -v grep
```

### Check which ports are in use:
```bash
lsof -i :8080,8090,8091 | grep LISTEN
```

### View logs:
```bash
# Main server logs
tail -f logs/main_debug_server.log

# Callback server logs
tail -f logs/callback_server.log

# Test server logs
tail -f logs/test_server.log
```

## Stopping Services

### Stop all services:
```bash
pkill -f "go run" && pkill -f "main_debug"
```

### Stop specific service by port:
```bash
# Find PID by port
lsof -ti :8080  # For main server
lsof -ti :8091  # For callback server

# Kill by PID
kill <PID>
```

## Common Issues

### Port already in use
If you get "bind: address already in use", find and kill the process:
```bash
lsof -ti :8080 | xargs kill
```

### Database connection error
Make sure PostgreSQL is running and database exists:
```bash
psql -U atharvaz -d esign_db -c "SELECT 1;"
```

## Testing the Services

### Test main server:
```bash
curl http://localhost:8080/health
curl http://localhost:8080/debug/templates
```

### Test callback server:
```bash
curl http://localhost:8091/health
curl -X POST http://localhost:8091/callback \
  -H "Content-Type: application/json" \
  -d '{"test": "data"}'
```

### Test with form:
Open in browser: http://localhost:8090/test-esign-form.html