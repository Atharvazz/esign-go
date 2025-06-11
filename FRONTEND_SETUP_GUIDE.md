# Frontend Setup Guide

## Frontend Overview

The frontend consists of static HTML files that provide a user interface for testing the eSign functionality. There are multiple ways to access the frontend.

## Option 1: Dedicated Frontend Server (Recommended)

### Start the frontend server:
```bash
# Navigate to frontend directory
cd frontend

# Start the frontend server
go run serve.go
```

### Or run in background:
```bash
cd frontend
go run serve.go > ../logs/frontend_server.log 2>&1 &
cd ..
```

### Access URLs:
- **Main Portal**: http://localhost:3000/index.html
- **eSign Test Interface**: http://localhost:3000/esign-test.html  
- **Status Checker**: http://localhost:3000/check-status.html
- **Redirect Handler**: http://localhost:3000/redirect.html

## Option 2: Through Main Server Templates

The main eSign server (port 8080) serves the authentication templates:

### Template URLs:
- **OTP Auth**: http://localhost:8080/authenticate/auth-ra
- **Biometric Auth**: http://localhost:8080/authenticate/postRequestdata
- **Status Check**: http://localhost:8080/authenticate/check-status

## Option 3: Test Server Frontend (Port 8090)

If you start the test server, you can access:

### Test URLs:
- **Template Showcase**: http://localhost:8090/showcase
- **Test Form**: http://localhost:8090/test-esign-form.html
- **Enhanced Test**: http://localhost:8090/test-esign-enhanced.html
- **Simple Test**: http://localhost:8090/test

## Complete Frontend Startup

### Start all services with frontend:

```bash
# 1. Start Main eSign Server (Port 8080)
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go > logs/main_debug_server.log 2>&1 &

# 2. Start Callback Server (Port 8091) 
go run mock-callback-server.go > logs/callback_server.log 2>&1 &

# 3. Start Frontend Server (Port 3000)
cd frontend && go run serve.go > ../logs/frontend_server.log 2>&1 &
cd ..

# 4. Optional: Start Test Server (Port 8090)
go run test_server3.go > logs/test_server.log 2>&1 &
```

### Verify all services:
```bash
echo "Checking services..."
echo "Main Server (8080):" && curl -s http://localhost:8080/health | jq .status
echo "Callback Server (8091):" && curl -s http://localhost:8091/health | jq .status  
echo "Frontend Server (3000):" && curl -s http://localhost:3000/index.html | head -1
echo "Test Server (8090):" && curl -s http://localhost:8090/health | jq .status
```

## Frontend Features

### 1. Main Portal (index.html)
- Overview of available services
- Quick links to test interfaces
- Service status indicators

### 2. eSign Test Interface (esign-test.html)
- Form to submit eSign requests
- Different authentication modes
- Real-time testing

### 3. Status Checker (check-status.html)
- Check transaction status
- ASP ID and Transaction ID lookup
- Status history

### 4. Redirect Handler (redirect.html)
- Handles callback responses
- Displays results from eSign operations
- Error handling

## Configuration

### Frontend Server Configuration:
- **Port**: 3000 (default)
- **CORS**: Enabled for API calls
- **Static Files**: Served from frontend directory

### Backend Integration:
The frontend is configured to work with:
- **Main API**: http://localhost:8080
- **Callback URL**: http://localhost:8091/callback

## Testing Workflow

### Complete End-to-End Test:

1. **Start all services** (as shown above)

2. **Open frontend**: http://localhost:3000/index.html

3. **Test eSign flow**:
   - Go to eSign Test Interface
   - Fill in test data
   - Submit request
   - Follow authentication flow
   - Check callback logs

4. **Monitor logs**:
   ```bash
   # Watch all logs
   tail -f logs/*.log
   
   # Or individual logs
   tail -f logs/main_debug_server.log    # Main server
   tail -f logs/callback_server.log      # Callbacks  
   tail -f logs/frontend_server.log      # Frontend
   ```

## Quick Start Script

Create a `start_all_with_frontend.sh`:
```bash
#!/bin/bash
echo "Starting all eSign services with frontend..."

# Start main server
PORT=8080 LOG_LEVEL=debug go run cmd/server/main_debug.go > logs/main_debug_server.log 2>&1 &
echo "Main server started on port 8080"

# Start callback server  
go run mock-callback-server.go > logs/callback_server.log 2>&1 &
echo "Callback server started on port 8091"

# Start frontend
cd frontend && go run serve.go > ../logs/frontend_server.log 2>&1 &
cd ..
echo "Frontend server started on port 3000"

# Optional: Start test server
go run test_server3.go > logs/test_server.log 2>&1 &
echo "Test server started on port 8090"

echo ""
echo "All services started! Access points:"
echo "  🌐 Frontend:     http://localhost:3000"
echo "  🔧 Main API:     http://localhost:8080" 
echo "  📞 Callbacks:    http://localhost:8091"
echo "  🧪 Test Server:  http://localhost:8090"
```

Make it executable:
```bash
chmod +x start_all_with_frontend.sh
./start_all_with_frontend.sh
```