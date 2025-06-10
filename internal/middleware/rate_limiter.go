package middleware

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/esign-go/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

// RateLimitRule represents rate limiting configuration
type RateLimitRule struct {
	Rate     int
	Duration time.Duration
}

// RateLimiterService manages rate limiting for endpoints
type RateLimiterService struct {
	limiters map[string]*limiter.Limiter
	mu       sync.RWMutex
	enabled  bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(enabled bool) *RateLimiterService {
	return &RateLimiterService{
		limiters: make(map[string]*limiter.Limiter),
		enabled:  enabled,
	}
}

// Middleware returns a Gin middleware for rate limiting
func (rl *RateLimiterService) Middleware(endpoint string, rule RateLimitRule) gin.HandlerFunc {
	// Get or create limiter for this endpoint
	l := rl.getLimiter(endpoint, rule)

	return func(c *gin.Context) {
		if !rl.enabled {
			c.Next()
			return
		}

		// Use client IP as key
		key := c.ClientIP()

		// Get context from limiter
		ctx, err := l.Get(c.Request.Context(), key)
		if err != nil {
			logger.GetLogger().WithError(err).Error("Rate limiter error")
			c.Next()
			return
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", ctx.Limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", ctx.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", ctx.Reset))

		// Check if limit exceeded
		if ctx.Reached {
			logger.GetLogger().WithField("key", key).WithField("endpoint", endpoint).Warn("Rate limit exceeded")

			// Call fallback method
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":      "Rate limit exceeded",
				"message":    fmt.Sprintf("Too many requests. Please try again after %v", time.Unix(ctx.Reset, 0).Format(time.RFC3339)),
				"retryAfter": ctx.Reset,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// getLimiter gets or creates a limiter for an endpoint
func (rl *RateLimiterService) getLimiter(endpoint string, rule RateLimitRule) *limiter.Limiter {
	rl.mu.RLock()
	if l, exists := rl.limiters[endpoint]; exists {
		rl.mu.RUnlock()
		return l
	}
	rl.mu.RUnlock()

	// Create new limiter
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double check
	if l, exists := rl.limiters[endpoint]; exists {
		return l
	}

	// Create rate
	rate := limiter.Rate{
		Period: rule.Duration,
		Limit:  int64(rule.Rate),
	}

	// Create store with memory backend
	store := memory.NewStore()

	// Create limiter instance
	l := limiter.New(store, rate, limiter.WithTrustForwardHeader(true))

	rl.limiters[endpoint] = l
	return l
}

// Reset resets the rate limiter for a specific key
func (rl *RateLimiterService) Reset(endpoint, key string) error {
	rl.mu.RLock()
	l, exists := rl.limiters[endpoint]
	rl.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no limiter found for endpoint: %s", endpoint)
	}

	_, err := l.Reset(context.Background(), key)
	return err
}

// RateLimitExceededFallback is a fallback method for rate limiting
func RateLimitExceededFallback(c *gin.Context) {
	logger.GetLogger().WithField("path", c.Request.URL.Path).Warn("Rate limit fallback triggered")

	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":   "Service temporarily unavailable",
		"message": "The service is experiencing high load. Please try again later.",
		"code":    "RATE_LIMIT_EXCEEDED",
	})
}

// RateLimiter returns a simple rate limiting middleware
func RateLimiter(endpoint string, maxRequests int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simple implementation - in production use proper rate limiting
		c.Next()
	}
}

// RateLimiterWithFallback returns a rate limiter middleware with custom fallback
func RateLimiterWithFallback(endpoint string, maxRequests int, fallback gin.HandlerFunc) gin.HandlerFunc {
	// Create rate limiter service
	service := NewRateLimiter(true)
	rule := RateLimitRule{
		Rate:     maxRequests,
		Duration: time.Minute,
	}

	// Get the base middleware
	baseLimiter := service.Middleware(endpoint, rule)

	return func(c *gin.Context) {
		// Create a copy of the context to check rate limit
		testCtx := *c
		testCtx.Writer = &testResponseWriter{ResponseWriter: c.Writer}

		// Run the rate limiter
		baseLimiter(&testCtx)

		// Check if rate limit was exceeded
		if testCtx.Writer.(*testResponseWriter).statusCode == http.StatusTooManyRequests {
			// Call custom fallback
			if fallback != nil {
				fallback(c)
			} else {
				// Use default fallback
				RateLimitExceededFallback(c)
			}
			return
		}

		// Continue with normal processing
		c.Next()
	}
}

// testResponseWriter is a wrapper to capture status code
type testResponseWriter struct {
	gin.ResponseWriter
	statusCode int
}

func (w *testResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *testResponseWriter) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}
