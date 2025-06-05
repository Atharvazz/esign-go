package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID exists in header
		requestID := c.GetHeader("X-Request-ID")

		// Generate new ID if not present
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in context
		c.Set("RequestID", requestID)

		// Add to response header
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}
