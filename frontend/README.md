# eSign Frontend Testing Interface

A complete web-based testing interface for the eSign Go implementation, inspired by the Java implementation's UI/UX patterns.

## Features

- 🎨 Modern, responsive Bootstrap 5 UI
- 📝 Step-by-step eSign request creation
- 🔍 Transaction status checking
- 📊 Bulk status checking support
- 🧪 Pre-filled test data for easy testing
- 📱 Mobile-friendly design

## Quick Start

### Option 1: Using the Go Static Server

```bash
# From the frontend directory
cd frontend
go run serve.go

# Server will start on http://localhost:3000
```

### Option 2: Using Python's Simple HTTP Server

```bash
# Python 3
python3 -m http.server 3000

# Python 2
python -m SimpleHTTPServer 3000
```

### Option 3: Using Node.js http-server

```bash
# Install globally
npm install -g http-server

# Run from frontend directory
http-server -p 3000
```

## Pages Overview

### 1. **Main Portal** (`index.html`)
- Service overview dashboard
- Quick test form
- Real-time server status indicator
- Links to all test interfaces

### 2. **eSign Test Interface** (`esign-test.html`)
- **Step 1**: Configure request parameters
  - ASP ID, Transaction ID
  - Authentication mode selection
  - Aadhaar/VID input
- **Step 2**: Add documents
  - Manual hash input or file upload
  - Multiple document support
  - SHA-256 hash calculation
- **Step 3**: Review and submit
  - Request preview
  - Generated XML display
  - Confirmation before submission

### 3. **Status Checker** (`check-status.html`)
- Single transaction lookup
- Bulk transaction status check
- Visual timeline of transaction steps
- Status badges with color coding

### 4. **Redirect Handler** (`redirect.html`)
- Auto-submission form
- Loading animation
- Mimics Java implementation's redirect behavior

## Test Data

The interface comes pre-configured with test data:

- **ASP ID**: `TEST001`
- **Test Aadhaar**: `999999990019`
- **Test OTP**: `123456`
- **Sample Document Hash**: `a5f3c6d7e8b9a0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5`

## Complete Testing Flow

1. **Start the servers**:
   ```bash
   # Terminal 1: Start eSign backend
   cd ..
   go run cmd/server/main.go

   # Terminal 2: Start frontend
   cd frontend
   go run serve.go

   # Terminal 3: Start mock callback server (optional)
   cd ..
   go run mock-callback-server.go
   ```

2. **Open the frontend**:
   - Navigate to http://localhost:3000
   - Click "Start eSign Test"

3. **Create eSign Request**:
   - Fill in the form (pre-populated with test data)
   - Add one or more documents
   - Review and submit

4. **Complete Authentication**:
   - You'll be redirected to the authentication page
   - Enter Aadhaar: `999999990019`
   - Enter OTP: `123456`

5. **Check Status**:
   - Go back to the main portal
   - Click "Check Status"
   - Enter your transaction ID

## Features Comparison with Java Implementation

| Feature | Java Implementation | Go Frontend |
|---------|-------------------|-------------|
| JSP Templates | ✅ | ❌ (Static HTML) |
| AngularJS | ✅ | ❌ (Vanilla JS) |
| Bootstrap | ✅ v3.x | ✅ v5.x |
| Step-wise Flow | ✅ | ✅ |
| Custom Templates | ✅ | 🔧 (Planned) |
| Security Features | ✅ | ✅ |
| Mobile Responsive | ✅ | ✅ |

## Security Features

Following the Java implementation's security patterns:

- Right-click disabled on sensitive pages
- F12 developer tools prevention (optional)
- Back button prevention on auth pages
- Session-based flow control
- Auto-timeout on idle

## Customization

### Adding Custom Themes

1. Create a `custom-themes` directory
2. Add CSS files for different ASPs
3. Modify the HTML to load themes dynamically

### Adding New Pages

1. Create new HTML file in the frontend directory
2. Follow the existing Bootstrap structure
3. Add navigation links in `index.html`

## API Integration

The frontend expects the backend to be running on `http://localhost:8080` with these endpoints:

- `/health` - Health check
- `/authenticate/esign-doc` - Submit eSign request
- `/authenticate/check-status-api` - Check transaction status
- `/authenticate/otp` - Generate OTP
- `/authenticate/otpAction` - Verify OTP

## Troubleshooting

1. **CORS Issues**: Ensure the backend has proper CORS headers
2. **Connection Refused**: Check if backend is running on port 8080
3. **404 Errors**: Verify the file paths and server root directory

## Future Enhancements

- [ ] WebSocket support for real-time status updates
- [ ] File drag-and-drop for document upload
- [ ] Batch document signing interface
- [ ] Admin dashboard with analytics
- [ ] Multi-language support
- [ ] PWA capabilities

## Development

```bash
# Watch for changes (using entr)
find . -name "*.html" -o -name "*.css" -o -name "*.js" | entr -r go run serve.go

# Format HTML files
prettier --write "*.html"

# Minify for production
html-minifier --collapse-whitespace --remove-comments -o dist/ *.html
```