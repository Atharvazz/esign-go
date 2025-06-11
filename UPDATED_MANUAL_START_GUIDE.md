# Updated Manual Service Startup Guide

## Prerequisites
Make sure you're in the project directory:
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
```

## Service Overview

### Core Services (Choose One Main Server)

**Option A: Main eSign Server (Full Featured)**
- Port: 8080
- Purpose: Production-like eSign server with all features
- Command: `PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go`

**Option B: Test Server (Simple Testing)**  
- Port: 8090
- Purpose: Simple server for quick testing
- Command: `go run test_server3.go`

### Additional Services

**Callback Server (Choose One)**
- **Port 8091**: Mock callback server (recommended)
- **Port 8090**: Test server callback (if using Option B)

**Frontend Server**
- Port: 3000
- Purpose: HTML forms and test interface

## Manual Startup Instructions

### Quick Start (Recommended Setup)

**Terminal 1 - Main eSign Server:**
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go
```

**Terminal 2 - Callback Server:**
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
go run mock-callback-server.go
```

**Terminal 3 - Frontend Server:**
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go/frontend
go run serve.go
```

### Alternative Setup (Simpler Testing)

**Terminal 1 - Test Server:**
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go
go run test_server3.go
```

**Terminal 2 - Frontend Server:**
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go/frontend
go run serve.go
```

## Service URLs After Startup

### Main Server Setup:
- **Main API**: http://localhost:8080
- **Callback Server**: http://localhost:8091
- **Frontend**: http://localhost:3000

### Test Server Setup:
- **Test Server**: http://localhost:8090 (includes callback at /callback)
- **Frontend**: http://localhost:3000

## Verification Commands

### Check if services are running:
```bash
# Check running processes
ps aux | grep -E "go run|main_debug|test_server|mock-callback|serve" | grep -v grep

# Check ports in use
lsof -i :8080,8090,8091,3000 | grep LISTEN
```

### Test service health:
```bash
# Main server (if running)
curl http://localhost:8080/health

# Test server (if running)  
curl http://localhost:8090/health

# Callback server (if running)
curl http://localhost:8091/health

# Frontend server
curl http://localhost:3000/index.html | head -5
```

## Frontend Access Points

### Main Test Interface:
- **Home**: http://localhost:3000/index.html
- **eSign Test**: http://localhost:3000/esign-test.html (Fixed form)
- **Status Check**: http://localhost:3000/check-status.html

### Direct Server Access:
- **Test Form**: http://localhost:8090/test-esign-form.html (if using test server)
- **Template Showcase**: http://localhost:8090/showcase (if using test server)

## Background Startup (Optional)

If you prefer to run services in background:

```bash
# Main setup
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go > logs/main_server.log 2>&1 &
go run mock-callback-server.go > logs/callback_server.log 2>&1 &
cd frontend && go run serve.go > ../logs/frontend_server.log 2>&1 &
cd ..

# Check logs
tail -f logs/main_server.log
tail -f logs/callback_server.log  
tail -f logs/frontend_server.log
```

## Stopping Services

### Stop all background services:
```bash
pkill -f "go run" && pkill -f "main_debug" && pkill -f "test_server" && pkill -f "mock-callback" && pkill -f "serve.go"
```

### Stop specific services:
```bash
# Find process IDs
lsof -ti :8080  # Main server
lsof -ti :8090  # Test server  
lsof -ti :8091  # Callback server
lsof -ti :3000  # Frontend server

# Kill specific process
kill <PID>
```

## Important Configuration

### Current Frontend Form Settings:
- **Callback URL**: http://localhost:8091/callback (uses mock callback server)
- **Main API URL**: http://localhost:8080/authenticate/esign-doc

### If using test server setup:
You may want to update the frontend callback URL to use port 8090:
```bash
# Edit frontend form to use test server callback
sed -i '' 's/:8091/:8090/g' frontend/esign-test.html
```

## Common Issues

### Database Connection Error:
```bash
# Check if PostgreSQL is running
psql -U atharvaz -d esign_db -c "SELECT 1;"
```

### Port Already in Use:
```bash
# Find and kill process using port
lsof -ti :8080 | xargs kill
```

### Template Not Found:
- Make sure you're in the correct directory
- Check that templates/ directory exists

## Recommended Testing Flow

1. **Start services** using one of the setups above
2. **Open frontend**: http://localhost:3000/esign-test.html
3. **Fill form** with test data (form has defaults)
4. **Submit** and follow authentication flow
5. **Check callback logs** for responses
6. **Monitor server logs** for processing details

All services are now stopped and ready for manual startup! 🎯