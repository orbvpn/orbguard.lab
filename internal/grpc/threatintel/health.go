package threatintel

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database"
)

// RegisterHealthServer registers the gRPC health check service
func RegisterHealthServer(grpcServer *grpc.Server, db *database.PostgresDB, cache *cache.RedisCache) {
	healthServer := health.NewServer()

	// Register health check for the main service
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("threatintel.v1.ThreatIntelligenceService", grpc_health_v1.HealthCheckResponse_SERVING)

	// Start background health checker
	go func() {
		ctx := context.Background()
		for {
			// Check database health
			dbHealthy := true
			if db != nil {
				if err := db.Pool().Ping(ctx); err != nil {
					dbHealthy = false
				}
			}

			// Check Redis health
			redisHealthy := true
			if cache != nil {
				if _, err := cache.Client().Ping(ctx).Result(); err != nil {
					redisHealthy = false
				}
			}

			// Update overall health status
			if dbHealthy && redisHealthy {
				healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
				healthServer.SetServingStatus("threatintel.v1.ThreatIntelligenceService", grpc_health_v1.HealthCheckResponse_SERVING)
			} else {
				healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
				healthServer.SetServingStatus("threatintel.v1.ThreatIntelligenceService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
			}

			// Check every 10 seconds
			select {
			case <-ctx.Done():
				return
			case <-context.Background().Done():
				return
			default:
				// Continue
			}
			// Sleep for 10 seconds (simple approach)
			ctx2, cancel := context.WithTimeout(ctx, 10e9) // 10 seconds
			<-ctx2.Done()
			cancel()
		}
	}()

	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
}
