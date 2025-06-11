# eSign Frontend Testing Checklist

## Quick Start

1. **Start the test environment:**
   ```bash
   ./run_test_env.sh
   ```

2. **Open the enhanced test interface:**
   ```
   http://localhost:8090/test-esign-enhanced.html
   ```

## Testing Flows

### ✅ Standard OTP Flow
1. [ ] Click "OTP Authentication - Standard UI"
2. [ ] Enter test Aadhaar: 999999999999
3. [ ] Check consent checkbox
4. [ ] Click "Get OTP"
5. [ ] Enter any 6-digit OTP
6. [ ] Verify success/error handling

### ✅ Enhanced UX OTP Flow  
1. [ ] Click "OTP Authentication - Enhanced UX"
2. [ ] Observe modern UI with progress indicators
3. [ ] Test OTP timer countdown
4. [ ] Test "Show/Hide" Aadhaar toggle
5. [ ] Test auto-focus on OTP inputs
6. [ ] Test paste functionality for OTP

### ✅ Biometric Fingerprint Flow
1. [ ] Click "Biometric - Fingerprint"
2. [ ] Check consent checkbox
3. [ ] Enter Aadhaar/VID
4. [ ] Select mock device from dropdown
5. [ ] Click "Capture Fingerprint"
6. [ ] Verify loading animation
7. [ ] Check quality score display

### ✅ Biometric Iris Flow
1. [ ] Click "Biometric - Iris"
2. [ ] Select eye option (Left/Right/Both)
3. [ ] Test device selection
4. [ ] Test capture simulation
5. [ ] Verify iris preview update

### ✅ Offline KYC Flow
1. [ ] Click "Offline KYC"
2. [ ] Test file drag-and-drop
3. [ ] Test file size validation
4. [ ] Enter 4-digit share code
5. [ ] Test show/hide share code
6. [ ] Verify file info display

### ✅ Custom ASP Themes

#### HDFC Bank Theme
1. [ ] Click "HDFC Bank Theme"
2. [ ] Verify HDFC branding (blue theme)
3. [ ] Check custom buttons and styling
4. [ ] Verify security message
5. [ ] Test complete flow with HDFC theme

#### Karnataka Government Theme
1. [ ] Click "Karnataka Government Theme"
2. [ ] Verify government branding
3. [ ] Test language selector
4. [ ] Click audio consent buttons
5. [ ] Verify bilingual labels

### ✅ Error Scenarios

1. **Session Timeout**
   - [ ] Wait 15+ minutes
   - [ ] Try to proceed
   - [ ] Verify expired session page

2. **Invalid Aadhaar**
   - [ ] Enter 11 digits
   - [ ] Enter alphabets
   - [ ] Leave empty
   - [ ] Verify error messages

3. **Network Errors**
   - [ ] Stop the server
   - [ ] Try to submit
   - [ ] Verify error handling

### ✅ API Testing

1. **Send OTP API**
   ```bash
   curl -X POST http://localhost:8090/authenticate/api/v2/auth/send-otp \
     -H "Content-Type: application/json" \
     -d '{"rid": 123, "uid": "999999999999"}'
   ```

2. **Verify OTP API**
   ```bash
   curl -X POST http://localhost:8090/authenticate/api/v2/auth/verify-otp \
     -H "Content-Type: application/json" \
     -d '{"rid": 123, "uid": "999999999999", "otpTxn": "xxx", "otp": "123456"}'
   ```

### ✅ Browser Compatibility

Test on:
- [ ] Chrome
- [ ] Firefox
- [ ] Safari
- [ ] Edge

### ✅ Mobile Responsiveness

Test on:
- [ ] iPhone (375px)
- [ ] iPad (768px)
- [ ] Desktop (1920px)

### ✅ Callback Testing

1. [ ] Submit a request
2. [ ] Complete authentication
3. [ ] Check callback server logs
4. [ ] Verify response structure

## Common Test Data

| Field | Test Value |
|-------|-----------|
| Aadhaar | 999999999999 |
| VID | 9999999999999999 |
| OTP | 123456 |
| Share Code | 1234 |
| ASP ID | TEST001 |

## Debugging

### Check Logs
```bash
# Main server logs
tail -f server.log

# Callback server logs  
tail -f callback.log

# Filter for errors
tail -f server.log | grep ERROR
```

### Check Template Loading
```bash
curl http://localhost:8090/debug/info
```

### Clear Session
```javascript
// In browser console
document.cookie = "esign-session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
```

## Notes

- Mock UIDAI responses return errors (expected in test environment)
- Biometric devices are simulated (no real device needed)
- All test Aadhaar numbers are accepted
- Callback server shows all responses on http://localhost:8091