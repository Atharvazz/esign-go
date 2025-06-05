package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/esign-go/internal/config"
	"github.com/esign-go/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
)

// RateLimiter manages rate limiting for endpoints
type RateLimiter struct {
	limiters map[string]*limiter.Limiter
	mu       sync.RWMutex
	config   config.RateLimitConfig
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*limiter.Limiter),
		config:   cfg,
	}
}

// Middleware returns a Gin middleware for rate limiting
func (rl *RateLimiter) Middleware(endpoint string, rule config.RateLimitRule) gin.HandlerFunc {
	// Get or create limiter for this endpoint
	l := rl.getLimiter(endpoint, rule)

	return func(c *gin.Context) {
		if !rl.config.Enabled {
			c.Next()
			return
		}

		// Use client IP as key
		key := c.ClientIP()

		// Get context from limiter
		ctx, err := l.Get(c.Request.Context(), key)
		if err != nil {
			logger.Error("Rate limiter error: %v", err)
			c.Next()
			return
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", ctx.Limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", ctx.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", ctx.Reset))

		// Check if limit exceeded
		if ctx.Reached {
			logger.Warn("Rate limit exceeded for %s on %s", key, endpoint)

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
func (rl *RateLimiter) getLimiter(endpoint string, rule config.RateLimitRule) *limiter.Limiter {
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
func (rl *RateLimiter) Reset(endpoint, key string) error {
	rl.mu.RLock()
	l, exists := rl.limiters[endpoint]
	rl.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no limiter found for endpoint: %s", endpoint)
	}

	return l.Reset(nil, key)
}

// RateLimitExceededFallback is a fallback method for rate limiting
func RateLimitExceededFallback(c *gin.Context) {
	logger.Warn("Rate limit fallback triggered for %s", c.Request.URL.Path)

	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":   "Service temporarily unavailable",
		"message": "The service is experiencing high load. Please try again later.",
		"code":    "RATE_LIMIT_EXCEEDED",
	})
}
