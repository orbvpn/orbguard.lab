package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"orbguard-lab/internal/config"
	"orbguard-lab/pkg/logger"
)

// RedisCache wraps the Redis client with typed operations
type RedisCache struct {
	client    *redis.Client
	keyPrefix string
	logger    *logger.Logger
}

// NewRedis creates a new Redis client
func NewRedis(ctx context.Context, cfg config.RedisConfig, log *logger.Logger) (*RedisCache, error) {
	log = log.WithComponent("redis")
	log.Info().Str("host", cfg.Host).Int("port", cfg.Port).Msg("connecting to Redis")

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping Redis: %w", err)
	}

	log.Info().Msg("connected to Redis successfully")

	return &RedisCache{
		client:    client,
		keyPrefix: cfg.KeyPrefix,
		logger:    log,
	}, nil
}

// Client returns the underlying Redis client
func (c *RedisCache) Client() *redis.Client {
	return c.client
}

// Close closes the Redis connection
func (c *RedisCache) Close() error {
	c.logger.Info().Msg("closing Redis connection")
	return c.client.Close()
}

// key prepends the namespace prefix to a key
func (c *RedisCache) key(k string) string {
	return c.keyPrefix + k
}

// Get retrieves a value from cache
func (c *RedisCache) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, c.key(key)).Result()
}

// GetJSON retrieves and unmarshals a JSON value from cache
func (c *RedisCache) GetJSON(ctx context.Context, key string, dest any) error {
	data, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), dest)
}

// Set stores a value in cache with optional TTL
func (c *RedisCache) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	return c.client.Set(ctx, c.key(key), value, ttl).Err()
}

// SetJSON marshals and stores a value in cache
func (c *RedisCache) SetJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}
	return c.Set(ctx, key, string(data), ttl)
}

// Delete removes a key from cache
func (c *RedisCache) Delete(ctx context.Context, keys ...string) error {
	prefixedKeys := make([]string, len(keys))
	for i, k := range keys {
		prefixedKeys[i] = c.key(k)
	}
	return c.client.Del(ctx, prefixedKeys...).Err()
}

// Exists checks if a key exists
func (c *RedisCache) Exists(ctx context.Context, keys ...string) (int64, error) {
	prefixedKeys := make([]string, len(keys))
	for i, k := range keys {
		prefixedKeys[i] = c.key(k)
	}
	return c.client.Exists(ctx, prefixedKeys...).Result()
}

// Expire sets a TTL on a key
func (c *RedisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.client.Expire(ctx, c.key(key), ttl).Err()
}

// TTL returns the remaining TTL for a key
func (c *RedisCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.client.TTL(ctx, c.key(key)).Result()
}

// Incr increments an integer value
func (c *RedisCache) Incr(ctx context.Context, key string) (int64, error) {
	return c.client.Incr(ctx, c.key(key)).Result()
}

// IncrBy increments an integer value by a given amount
func (c *RedisCache) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return c.client.IncrBy(ctx, c.key(key), value).Result()
}

// SetNX sets a value only if the key does not exist (for distributed locks)
func (c *RedisCache) SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	return c.client.SetNX(ctx, c.key(key), value, ttl).Result()
}

// HGet gets a field from a hash
func (c *RedisCache) HGet(ctx context.Context, key, field string) (string, error) {
	return c.client.HGet(ctx, c.key(key), field).Result()
}

// HSet sets a field in a hash
func (c *RedisCache) HSet(ctx context.Context, key string, values ...any) error {
	return c.client.HSet(ctx, c.key(key), values...).Err()
}

// HGetAll gets all fields from a hash
func (c *RedisCache) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	return c.client.HGetAll(ctx, c.key(key)).Result()
}

// SAdd adds members to a set
func (c *RedisCache) SAdd(ctx context.Context, key string, members ...any) error {
	return c.client.SAdd(ctx, c.key(key), members...).Err()
}

// SMembers returns all members of a set
func (c *RedisCache) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.client.SMembers(ctx, c.key(key)).Result()
}

// SIsMember checks if a value is a member of a set
func (c *RedisCache) SIsMember(ctx context.Context, key string, member any) (bool, error) {
	return c.client.SIsMember(ctx, c.key(key), member).Result()
}

// ZAdd adds members to a sorted set
func (c *RedisCache) ZAdd(ctx context.Context, key string, members ...redis.Z) error {
	return c.client.ZAdd(ctx, c.key(key), members...).Err()
}

// ZRangeByScore returns members within a score range
func (c *RedisCache) ZRangeByScore(ctx context.Context, key string, opt *redis.ZRangeBy) ([]string, error) {
	return c.client.ZRangeByScore(ctx, c.key(key), opt).Result()
}

// Publish publishes a message to a channel
func (c *RedisCache) Publish(ctx context.Context, channel string, message any) error {
	return c.client.Publish(ctx, channel, message).Err()
}

// Subscribe subscribes to channels
func (c *RedisCache) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
	return c.client.Subscribe(ctx, channels...)
}

// Pipeline returns a Redis pipeline for batch operations
func (c *RedisCache) Pipeline() redis.Pipeliner {
	return c.client.Pipeline()
}

// TxPipeline returns a transactional Redis pipeline
func (c *RedisCache) TxPipeline() redis.Pipeliner {
	return c.client.TxPipeline()
}

// Cache key constants for OrbGuard
const (
	// Indicator cache keys
	KeyIndicatorPrefix = "cache:indicator:"
	KeyMobileAndroid   = "cache:mobile:android"
	KeyMobileIOS       = "cache:mobile:ios"
	KeyPegasusDomains  = "cache:pegasus:domains"
	KeyPegasusHashes   = "cache:pegasus:hashes"
	KeyPegasusAll      = "cache:pegasus:all"

	// Rate limiting keys
	KeyRateLimitPrefix = "rate_limit:"

	// Scheduler keys
	KeySchedulerQueue  = "scheduler:queue"
	KeySchedulerLock   = "scheduler:lock:"

	// Stats keys
	KeyStats           = "cache:stats"
	KeyStatsVersion    = "cache:stats:version"

	// Sync version for mobile apps
	KeySyncVersion     = "sync:version"
)

// CacheIndicator caches an indicator by its hash
func (c *RedisCache) CacheIndicator(ctx context.Context, hash string, data any, ttl time.Duration) error {
	return c.SetJSON(ctx, KeyIndicatorPrefix+hash, data, ttl)
}

// GetCachedIndicator retrieves a cached indicator
func (c *RedisCache) GetCachedIndicator(ctx context.Context, hash string, dest any) error {
	return c.GetJSON(ctx, KeyIndicatorPrefix+hash, dest)
}

// IncrementSyncVersion increments and returns the new sync version
func (c *RedisCache) IncrementSyncVersion(ctx context.Context) (int64, error) {
	return c.Incr(ctx, KeySyncVersion)
}

// GetSyncVersion returns the current sync version
func (c *RedisCache) GetSyncVersion(ctx context.Context) (int64, error) {
	val, err := c.Get(ctx, KeySyncVersion)
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var version int64
	_, err = fmt.Sscanf(val, "%d", &version)
	return version, err
}

// AcquireLock attempts to acquire a distributed lock
func (c *RedisCache) AcquireLock(ctx context.Context, lockKey string, ttl time.Duration) (bool, error) {
	return c.SetNX(ctx, KeySchedulerLock+lockKey, "locked", ttl)
}

// ReleaseLock releases a distributed lock
func (c *RedisCache) ReleaseLock(ctx context.Context, lockKey string) error {
	return c.Delete(ctx, KeySchedulerLock+lockKey)
}

// CheckRateLimit checks and increments the rate limit counter
// Returns (allowed, remaining, resetTime, error)
func (c *RedisCache) CheckRateLimit(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, time.Time, error) {
	now := time.Now()
	windowKey := fmt.Sprintf("%s%s:%d", KeyRateLimitPrefix, key, now.Unix()/int64(window.Seconds()))

	pipe := c.Pipeline()
	incr := pipe.Incr(ctx, c.key(windowKey))
	pipe.Expire(ctx, c.key(windowKey), window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, time.Time{}, err
	}

	count := incr.Val()
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	resetTime := now.Add(window)

	return count <= limit, remaining, resetTime, nil
}
