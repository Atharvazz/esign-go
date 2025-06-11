# Starting eSign Services Individually

## Prerequisites

Ensure PostgreSQL is running and the database exists:
```bash
# Check if PostgreSQL is running
pg_isready

# Create database if needed
createdb esign_db

# Or connect to PostgreSQL and create
psql -U postgres -c "CREATE DATABASE esign_db;"
```

## 1. Start the Main eSign Server

### Option A: Using go run (Development)
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Start with default settings
go run cmd/server/main_debug.go

# Or with custom port
PORT=8090 go run cmd/server/main_debug.go

# With debug logging
LOG_LEVEL=debug go run cmd/server/main_debug.go

# With all options
PORT=8090 LOG_LEVEL=debug go run cmd/server/main_debug.go
```

### Option B: Build and Run
```bash
# Build the server
go build -o esign-server cmd/server/main_debug.go

# Run the server
./esign-server

# Run in background
./esign-server > server.log 2>&1 &

# Get the PID
echo $!
```

### Option C: Using a startup script
Create `start_main_server.sh`:
```bash
#!/bin/bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

echo "Starting eSign server..."
LOG_FILE="server_$(date +%Y%m%d_%H%M%S).log"

# Set environment variables
export PORT=8090
export LOG_LEVEL=debug
export DB_HOST=localhost
export DB_PORT=5432
export DB_USER=atharvaz
export DB_NAME=esign_db

# Start server
go run cmd/server/main_debug.go > logs/$LOG_FILE 2>&1 &
PID=$!

echo "Server started with PID: $PID"
echo "Log file: logs/$LOG_FILE"
echo "Server URL: http://localhost:8090"

# Save PID for stopping later
echo $PID > .server.pid
```

## 2. Start the Callback Test Server

### Option A: Direct Run
```bash
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Run callback server
go run test-callback-server.go

# Or in background
go run test-callback-server.go > callback.log 2>&1 &
```

### Option B: With Custom Port
Modify `test-callback-server.go` or use environment variable:
```bash
# Create a version that reads port from environment
PORT=8091 go run test-callback-server.go
```

## 3. Start Individual Components

### Database Connection Test
```bash
# Test database connection
go run -tags test test_db_connection.go
```

### Template Server Only
```bash
# Serve static files and templates only
go run frontend/serve.go
```

## Individual Service Scripts

### Create start scripts for each service:

**start_esign_server.sh**
```bash
#!/bin/bash
echo "Starting eSign Server on port 8090..."
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Kill existing process if running
if [ -f .server.pid ]; then
    kill $(cat .server.pid) 2>/dev/null
    rm .server.pid
fi

# Start new instance
go run cmd/server/main_debug.go > logs/server.log 2>&1 &
echo $! > .server.pid

echo "Started with PID: $(cat .server.pid)"
echo "Logs: tail -f logs/server.log"
```

**start_callback_server.sh**
```bash
#!/bin/bash
echo "Starting Callback Server on port 8091..."
cd /Users/atharvaz/Documents/ESIGN_FINAL/esign-go

# Kill existing process
lsof -ti:8091 | xargs kill -9 2>/dev/null

# Start new instance
go run test-callback-server.go > logs/callback.log 2>&1 &
echo $! > .callback.pid

echo "Started with PID: $(cat .callback.pid)"
echo "URL: http://localhost:8091"
```

**stop_all_services.sh**
```bash
#!/bin/bash
echo "Stopping all services..."

# Stop main server
if [ -f .server.pid ]; then
    kill $(cat .server.pid) 2>/dev/null
    rm .server.pid
    echo "Stopped eSign server"
fi

# Stop callback server
if [ -f .callback.pid ]; then
    kill $(cat .callback.pid) 2>/dev/null
    rm .callback.pid
    echo "Stopped callback server"
fi

# Kill any remaining processes on our ports
lsof -ti:8090 | xargs kill -9 2>/dev/null
lsof -ti:8091 | xargs kill -9 2>/dev/null

echo "All services stopped"
```

## Using systemd (Linux/Production)

### Create systemd service for eSign server:

**/etc/systemd/system/esign-server.service**
```ini
[Unit]
Description=eSign Server
After=network.target postgresql.service

[Service]
Type=simple
User=atharvaz
WorkingDirectory=/Users/atharvaz/Documents/ESIGN_FINAL/esign-go
ExecStart=/usr/local/go/bin/go run cmd/server/main_debug.go
Restart=on-failure
RestartSec=5

# Environment variables
Environment="PORT=8090"
Environment="LOG_LEVEL=info"
Environment="DB_HOST=localhost"
Environment="DB_PORT=5432"
Environment="DB_USER=atharvaz"
Environment="DB_NAME=esign_db"

[Install]
WantedBy=multi-user.target
```

### Manage with systemctl:
```bash
# Reload systemd
sudo systemctl daemon-reload

# Start service
sudo systemctl start esign-server

# Stop service
sudo systemctl stop esign-server

# Check status
sudo systemctl status esign-server

# Enable on boot
sudo systemctl enable esign-server

# View logs
journalctl -u esign-server -f
```

## Using Docker (Alternative)

### Create docker-compose for individual services:

**docker-compose.yml**
```yaml
version: '3.8'

services:
  esign-server:
    build: .
    ports:
      - "8090:8090"
    environment:
      - PORT=8090
      - DB_HOST=db
      - DB_PORT=5432
      - DB_USER=atharvaz
      - DB_PASSWORD=
      - DB_NAME=esign_db
    depends_on:
      - db
    volumes:
      - ./logs:/app/logs

  callback-server:
    build:
      context: .
      dockerfile: Dockerfile.callback
    ports:
      - "8091:8091"
    volumes:
      - ./logs:/app/logs

  db:
    image: postgres:13
    environment:
      - POSTGRES_USER=atharvaz
      - POSTGRES_DB=esign_db
      - POSTGRES_HOST_AUTH_METHOD=trust
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Run individual services:
```bash
# Start only the main server
docker-compose up esign-server

# Start only the callback server
docker-compose up callback-server

# Start only the database
docker-compose up db

# Start all in background
docker-compose up -d

# Stop specific service
docker-compose stop esign-server

# View logs
docker-compose logs -f esign-server
```

## Monitoring Individual Services

### Check if services are running:
```bash
# Check ports
lsof -i :8090  # Main server
lsof -i :8091  # Callback server

# Check processes
ps aux | grep "go run"

# Health check
curl http://localhost:8090/health
```

### Monitor logs in real-time:
```bash
# Terminal 1 - Main server logs
tail -f logs/server.log

# Terminal 2 - Callback server logs
tail -f logs/callback.log

# Terminal 3 - PostgreSQL logs
tail -f /usr/local/var/log/postgresql@14.log
```

## Troubleshooting

### Port already in use:
```bash
# Find and kill process on port
lsof -ti:8090 | xargs kill -9
```

### Database connection issues:
```bash
# Test connection
psql -U atharvaz -d esign_db -c "SELECT 1;"

# Check PostgreSQL status
brew services list | grep postgresql  # macOS
systemctl status postgresql           # Linux
```

### Template loading issues:
```bash
# Verify templates directory
ls -la templates/

# Check template loading
curl http://localhost:8090/debug/info
```