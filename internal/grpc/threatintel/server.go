package threatintel

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// Server implements the ThreatIntelligenceService gRPC server
type Server struct {
	UnimplementedThreatIntelligenceServiceServer

	aggregator *services.Aggregator
	cache      *cache.RedisCache
	logger     *logger.Logger
}

// NewServer creates a new gRPC server
func NewServer(agg *services.Aggregator, c *cache.RedisCache, log *logger.Logger) *Server {
	return &Server{
		aggregator: agg,
		cache:      c,
		logger:     log.WithComponent("grpc-server"),
	}
}

// Register registers the server with a gRPC server
func (s *Server) Register(grpcServer *grpc.Server) {
	RegisterThreatIntelligenceServiceServer(grpcServer, s)
}

// CheckIndicators checks if indicators are malicious
func (s *Server) CheckIndicators(ctx context.Context, req *CheckIndicatorsRequest) (*CheckIndicatorsResponse, error) {
	if len(req.Indicators) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no indicators provided")
	}

	if len(req.Indicators) > 1000 {
		return nil, status.Error(codes.InvalidArgument, "maximum 1000 indicators per request")
	}

	results := make([]*CheckResult, len(req.Indicators))

	for i, ind := range req.Indicators {
		// TODO: Check against database
		results[i] = &CheckResult{
			Value:       ind.Value,
			Type:        ind.Type,
			IsMalicious: false,
			Severity:    Severity_SEVERITY_UNSPECIFIED,
			Confidence:  0,
		}
	}

	return &CheckIndicatorsResponse{Results: results}, nil
}

// GetThreatStats returns aggregated statistics
func (s *Server) GetThreatStats(ctx context.Context, req *GetThreatStatsRequest) (*ThreatStatsResponse, error) {
	// Get stats from cache or compute
	var stats models.Stats
	if err := s.cache.GetJSON(ctx, cache.KeyStats, &stats); err != nil {
		// Return empty stats
		stats = models.Stats{
			LastUpdate: time.Now(),
		}
	}

	return &ThreatStatsResponse{
		TotalIndicators: int64(stats.TotalIndicators),
		IndicatorsByType: map[string]int64{
			"domain":  int64(stats.IndicatorsByType["domain"]),
			"ip":      int64(stats.IndicatorsByType["ip"]),
			"hash":    int64(stats.IndicatorsByType["hash"]),
			"url":     int64(stats.IndicatorsByType["url"]),
			"process": int64(stats.IndicatorsByType["process"]),
			"package": int64(stats.IndicatorsByType["package"]),
		},
		IndicatorsBySeverity: map[string]int64{
			"critical": int64(stats.IndicatorsBySeverity["critical"]),
			"high":     int64(stats.IndicatorsBySeverity["high"]),
			"medium":   int64(stats.IndicatorsBySeverity["medium"]),
			"low":      int64(stats.IndicatorsBySeverity["low"]),
			"info":     int64(stats.IndicatorsBySeverity["info"]),
		},
		TotalSources:       int32(stats.TotalSources),
		ActiveSources:      int32(stats.ActiveSources),
		TotalCampaigns:     int32(stats.TotalCampaigns),
		ActiveCampaigns:    int32(stats.ActiveCampaigns),
		PegasusIndicators:  int64(stats.PegasusIndicators),
		MobileIndicators:   int64(stats.MobileIndicators),
		CriticalIndicators: int64(stats.CriticalIndicators),
		LastUpdate:         timestamppb.New(stats.LastUpdate),
		TodayNewIocs:       int64(stats.TodayNewIOCs),
		WeeklyNewIocs:      int64(stats.WeeklyNewIOCs),
		DataVersion:        stats.DataVersion,
	}, nil
}

// StreamNewThreats streams new threats in real-time
func (s *Server) StreamNewThreats(req *StreamThreatsRequest, stream ThreatIntelligenceService_StreamNewThreatsServer) error {
	s.logger.Info().Msg("client connected to threat stream")

	// TODO: Subscribe to NATS/Redis pub-sub for real-time updates
	// For now, just keep the connection open with heartbeats

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			s.logger.Info().Msg("client disconnected from threat stream")
			return nil
		case <-ticker.C:
			// Send heartbeat / no-op
			// In production, we'd send actual threat updates here
		}
	}
}

// ShouldBlockDomain checks if a domain should be blocked
func (s *Server) ShouldBlockDomain(ctx context.Context, req *BlockCheckRequest) (*BlockCheckResponse, error) {
	if req.Domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}

	// TODO: Check domain against database
	// For now, return not blocked

	s.logger.Debug().
		Str("domain", req.Domain).
		Str("client_ip", req.ClientIp).
		Str("server_id", req.ServerId).
		Msg("domain check")

	return &BlockCheckResponse{
		ShouldBlock: false,
		Severity:    Severity_SEVERITY_UNSPECIFIED,
		Reason:      "",
		Confidence:  0,
	}, nil
}

// ReportNetworkThreat reports a threat from VPN traffic
func (s *Server) ReportNetworkThreat(ctx context.Context, req *NetworkThreatReport) (*ReportResponse, error) {
	if req.IndicatorValue == "" {
		return nil, status.Error(codes.InvalidArgument, "indicator_value is required")
	}

	s.logger.Info().
		Str("value", req.IndicatorValue).
		Str("type", req.IndicatorType.String()).
		Str("server_id", req.ServerId).
		Msg("received network threat report")

	// TODO: Store report in database

	return &ReportResponse{
		Success:  true,
		Message:  "Report received",
		ReportId: "pending",
	}, nil
}

// GetIndicator retrieves a single indicator
func (s *Server) GetIndicator(ctx context.Context, req *GetIndicatorRequest) (*GetIndicatorResponse, error) {
	if req.Value == "" {
		return nil, status.Error(codes.InvalidArgument, "value is required")
	}

	// TODO: Look up in database

	return &GetIndicatorResponse{
		Found:     false,
		Indicator: nil,
	}, nil
}

// ListIndicators retrieves a list of indicators
func (s *Server) ListIndicators(ctx context.Context, req *ListIndicatorsRequest) (*ListIndicatorsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	// TODO: Fetch from database with filters

	return &ListIndicatorsResponse{
		Indicators: []*Indicator{},
		Total:      0,
		HasMore:    false,
	}, nil
}

// GetCampaign retrieves a campaign
func (s *Server) GetCampaign(ctx context.Context, req *GetCampaignRequest) (*GetCampaignResponse, error) {
	if req.Id == "" && req.Slug == "" {
		return nil, status.Error(codes.InvalidArgument, "id or slug is required")
	}

	// Check default campaigns
	slug := req.Slug
	if slug == "" {
		slug = req.Id
	}

	for _, c := range models.DefaultCampaigns() {
		if c.Slug == slug || c.ID.String() == slug {
			return &GetCampaignResponse{
				Found: true,
				Campaign: &Campaign{
					Id:             c.ID.String(),
					Name:           c.Name,
					Slug:           c.Slug,
					Description:    c.Description,
					Status:         string(c.Status),
					TargetSectors:  c.TargetSectors,
					FirstSeen:      timestamppb.New(c.FirstSeen),
					LastSeen:       timestamppb.New(c.LastSeen),
					IndicatorCount: int64(c.IndicatorCount),
				},
			}, nil
		}
	}

	return &GetCampaignResponse{Found: false}, nil
}

// ListCampaigns lists campaigns
func (s *Server) ListCampaigns(ctx context.Context, req *ListCampaignsRequest) (*ListCampaignsResponse, error) {
	campaigns := models.DefaultCampaigns()

	result := make([]*Campaign, 0, len(campaigns))
	for _, c := range campaigns {
		if req.ActiveOnly && c.Status != models.CampaignStatusActive {
			continue
		}
		result = append(result, &Campaign{
			Id:             c.ID.String(),
			Name:           c.Name,
			Slug:           c.Slug,
			Description:    c.Description,
			Status:         string(c.Status),
			TargetSectors:  c.TargetSectors,
			FirstSeen:      timestamppb.New(c.FirstSeen),
			LastSeen:       timestamppb.New(c.LastSeen),
			IndicatorCount: int64(c.IndicatorCount),
		})
	}

	return &ListCampaignsResponse{
		Campaigns: result,
		Total:     int64(len(result)),
	}, nil
}

// UnimplementedThreatIntelligenceServiceServer is a placeholder for unimplemented methods
type UnimplementedThreatIntelligenceServiceServer struct{}

func (UnimplementedThreatIntelligenceServiceServer) CheckIndicators(context.Context, *CheckIndicatorsRequest) (*CheckIndicatorsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckIndicators not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) GetThreatStats(context.Context, *GetThreatStatsRequest) (*ThreatStatsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetThreatStats not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) StreamNewThreats(*StreamThreatsRequest, ThreatIntelligenceService_StreamNewThreatsServer) error {
	return status.Errorf(codes.Unimplemented, "method StreamNewThreats not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) ShouldBlockDomain(context.Context, *BlockCheckRequest) (*BlockCheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ShouldBlockDomain not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) ReportNetworkThreat(context.Context, *NetworkThreatReport) (*ReportResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ReportNetworkThreat not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) GetIndicator(context.Context, *GetIndicatorRequest) (*GetIndicatorResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetIndicator not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) ListIndicators(context.Context, *ListIndicatorsRequest) (*ListIndicatorsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListIndicators not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) GetCampaign(context.Context, *GetCampaignRequest) (*GetCampaignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCampaign not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) ListCampaigns(context.Context, *ListCampaignsRequest) (*ListCampaignsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListCampaigns not implemented")
}
func (UnimplementedThreatIntelligenceServiceServer) mustEmbedUnimplementedThreatIntelligenceServiceServer() {}

// UnsafeThreatIntelligenceServiceServer may be embedded to opt out of forward compatibility for this service.
type UnsafeThreatIntelligenceServiceServer interface {
	mustEmbedUnimplementedThreatIntelligenceServiceServer()
}
