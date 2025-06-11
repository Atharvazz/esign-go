# Callback URL Options

## Current Running Services:

### Port 8090 - Test Server ✅
- **URL**: http://localhost:8090/callback
- **Status**: Now includes callback endpoint
- **Features**: Basic callback logging and JSON response

### Port 8091 - Mock Callback Server ✅  
- **URL**: http://localhost:8091/callback
- **Status**: Full featured callback server
- **Features**: Detailed logging, headers analysis, JSON parsing

## Callback URL Configuration:

### Option 1: Use Test Server (8090)
```
http://localhost:8090/callback
```
**Pros**: Same server as your test interface
**Cons**: Basic callback handling

### Option 2: Use Mock Callback Server (8091) - Recommended
```
http://localhost:8091/callback
```
**Pros**: Full featured, detailed logging, designed for callbacks
**Cons**: Different server

## Frontend Form Updates:

I've already updated the frontend forms to use port 8091 (recommended), but you can change it:

### Update Frontend to use 8090:
```bash
# Edit the form
sed -i '' 's/:8091/:8090/g' frontend/esign-test.html
```

### Update Frontend to use 8091 (current):
```bash
# Already set to 8091 - no change needed
```

## Test Both Options:

### Test 8090:
```bash
curl http://localhost:8090/callback
```

### Test 8091:
```bash  
curl http://localhost:8091/callback
```

## Current Status:
- ✅ Both callback endpoints are working
- ✅ Frontend forms point to 8091 (recommended)
- ✅ You can use either one

## Recommendation:
Use **port 8091** for callbacks as it provides more detailed logging and is specifically designed for eSign callback handling.