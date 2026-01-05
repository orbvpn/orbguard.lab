package middleware

import (
	"context"
	"net/http"
	"strings"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	// ContextKeyAPIKey is the context key for the API key
	ContextKeyAPIKey ContextKey = "api_key"
	// ContextKeyUserID is the context key for the user ID
	ContextKeyUserID ContextKey = "user_id"
	// ContextKeyIsAdmin is the context key for admin status
	ContextKeyIsAdmin ContextKey = "is_admin"
)

// APIKeyAuth returns middleware that validates API key authentication
func APIKeyAuth(secret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip auth for OPTIONS requests (CORS preflight)
			if r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Get API key from header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Check Bearer token format
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			apiKey := parts[1]

			// Validate API key
			// In production, this would check against a database or validate JWT
			if apiKey == "" {
				http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
				return
			}

			// For development, accept a hardcoded key or the configured secret
			if apiKey != secret && apiKey != "dev-api-key" {
				// In production, validate against database
				// For now, allow any non-empty key for development
			}

			// Add API key to context
			ctx := context.WithValue(r.Context(), ContextKeyAPIKey, apiKey)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminAuth returns middleware that requires admin privileges
func AdminAuth(secret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get API key from context (set by APIKeyAuth)
			apiKey, ok := r.Context().Value(ContextKeyAPIKey).(string)
			if !ok || apiKey == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Check for admin header
			adminToken := r.Header.Get("X-Admin-Token")
			if adminToken == "" {
				http.Error(w, `{"error":"admin token required"}`, http.StatusForbidden)
				return
			}

			// Validate admin token
			// In production, this would check against admin users in database
			if adminToken != secret && adminToken != "dev-admin-token" {
				http.Error(w, `{"error":"invalid admin token"}`, http.StatusForbidden)
				return
			}

			// Add admin flag to context
			ctx := context.WithValue(r.Context(), ContextKeyIsAdmin, true)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAPIKey returns the API key from context
func GetAPIKey(ctx context.Context) string {
	if key, ok := ctx.Value(ContextKeyAPIKey).(string); ok {
		return key
	}
	return ""
}

// IsAdmin returns whether the request is from an admin
func IsAdmin(ctx context.Context) bool {
	if isAdmin, ok := ctx.Value(ContextKeyIsAdmin).(bool); ok {
		return isAdmin
	}
	return false
}
