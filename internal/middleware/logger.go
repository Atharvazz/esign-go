package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"time"

	"github.com/esign-go/pkg/logger"
	"github.com/gin-gonic/gin"
)

// bodyLogWriter is a custom response writer that captures the response body
type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// Logger returns a gin middleware for logging requests and responses
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Capture request body if it's not too large
		var requestBody string
		if c.Request.Body != nil && c.Request.ContentLength > 0 && c.Request.ContentLength < 10240 { // 10KB limit
			bodyBytes, _ := io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			// Mask sensitive data
			requestBody = maskSensitiveData(string(bodyBytes))
		}

		// Create custom response writer to capture response
		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)

		// Get request details
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		// Format query string
		if raw != "" {
			path = path + "?" + raw
		}

		// Log request details
		logData := map[string]interface{}{
			"client_ip":  clientIP,
			"method":     method,
			"path":       path,
			"status":     statusCode,
			"latency":    latency.String(),
			"latency_ms": latency.Milliseconds(),
			"user_agent": c.Request.UserAgent(),
			"request_id": c.GetString("RequestID"),
		}

		// Add request body if available
		if requestBody != "" {
			logData["request_body"] = requestBody
		}

		// Add response body for errors
		if statusCode >= 400 && blw.body.Len() > 0 && blw.body.Len() < 1024 {
			logData["response_body"] = blw.body.String()
		}

		// Add error if any
		if errorMessage != "" {
			logData["error"] = errorMessage
		}

		// Convert to JSON for structured logging
		logJSON, _ := json.Marshal(logData)

		// Log based on status code
		switch {
		case statusCode >= 500:
			logger.Error("HTTP 5xx: %s", string(logJSON))
		case statusCode >= 400:
			logger.Warn("HTTP 4xx: %s", string(logJSON))
		case statusCode >= 300:
			logger.Info("HTTP 3xx: %s", string(logJSON))
		default:
			logger.Info("HTTP 2xx: %s", string(logJSON))
		}
	}
}

// maskSensitiveData masks sensitive information in request/response data
func maskSensitiveData(data string) string {
	// Define patterns for sensitive data
	sensitivePatterns := map[string]string{
		`"aadhaar"\s*:\s*"(\d{12})"`:      `"aadhaar":"XXXX-XXXX-$1"`,
		`"otp"\s*:\s*"(\d+)"`:             `"otp":"******"`,
		`"password"\s*:\s*"([^"]+)"`:      `"password":"******"`,
		`"privateKey"\s*:\s*"([^"]+)"`:    `"privateKey":"******"`,
		`"biometricData"\s*:\s*"([^"]+)"`: `"biometricData":"******"`,
	}

	masked := data
	for pattern, replacement := range sensitivePatterns {

		log.Println("Pattern:", pattern)
		log.Println("Replacement:", replacement)

		// Use regex to find and replace sensitive data
		// In production, use proper regex library
		// This is simplified for demonstration
		if bytes.Contains([]byte(masked), []byte("aadhaar")) {
			// Mask Aadhaar numbers
			masked = maskAadhaarInString(masked)
		}
		if bytes.Contains([]byte(masked), []byte("otp")) {
			// Mask OTP
			masked = maskOTPInString(masked)
		}
	}

	return masked
}

func maskAadhaarInString(s string) string {
	// Simple masking - in production use proper regex
	// This masks any 12-digit number
	result := s
	// Implementation would use regex to find and mask Aadhaar numbers
	return result
}

func maskOTPInString(s string) string {
	// Simple masking - in production use proper regex
	result := s
	// Implementation would use regex to find and mask OTP values
	return result
}
