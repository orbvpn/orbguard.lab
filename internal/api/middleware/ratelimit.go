package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"orbguard-lab/internal/config"
	"orbguard-lab/internal/infrastructure/cache"
)

// RateLimiter returns middleware that implements rate limiting
func RateLimiter(c *cache.RedisCache, cfg config.RateLimitConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip rate limiting for OPTIONS
			if r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Get client identifier (API key or IP)
			clientID := getClientID(r)

			// Check rate limit
			allowed, remaining, resetTime, err := c.CheckRateLimit(
				r.Context(),
				clientID,
				int64(cfg.RequestsPerMinute),
				time.Minute,
			)

			if err != nil {
				// On error, allow request but log
				next.ServeHTTP(w, r)
				return
			}

			// Set rate limit headers
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.RequestsPerMinute))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(time.Until(resetTime).Seconds()), 10))
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientID returns a unique identifier for the client
func getClientID(r *http.Request) string {
	// First try API key
	if apiKey := GetAPIKey(r.Context()); apiKey != "" {
		return fmt.Sprintf("key:%s", apiKey)
	}

	// Fall back to IP address
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}

	return fmt.Sprintf("ip:%s", ip)
}
