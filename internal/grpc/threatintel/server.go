package threatintel

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/internal/streaming"
	"orbguard-lab/pkg/logger"
)

// Server implements the ThreatIntelligenceService gRPC server
type Server struct {
	UnimplementedThreatIntelligenceServiceServer

	aggregator *services.Aggregator
	repos      *repository.Repositories
	cache      *cache.RedisCache
	eventBus   *streaming.EventBus
	logger     *logger.Logger
}

// NewServer creates a new gRPC server
func NewServer(agg *services.Aggregator, repos *repository.Repositories, c *cache.RedisCache, eb *streaming.EventBus, log *logger.Logger) *Server {
	return &Server{
		aggregator: agg,
		repos:      repos,
		cache:      c,
		eventBus:   eb,
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

	// If no repository, return empty results
	if s.repos == nil {
		for i, ind := range req.Indicators {
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

	// Extract values for batch lookup
	values := make([]string, len(req.Indicators))
	for i, ind := range req.Indicators {
		values[i] = strings.ToLower(ind.Value)
	}

	// Batch lookup in database
	found, err := s.repos.Indicators.CheckBatch(ctx, values)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to check indicators batch")
		return nil, status.Error(codes.Internal, "database error")
	}

	// Create lookup map
	foundMap := make(map[string]*models.Indicator)
	for _, ind := range found {
		foundMap[strings.ToLower(ind.Value)] = ind
	}

	// Build results
	for i, ind := range req.Indicators {
		val := strings.ToLower(ind.Value)
		if dbInd, ok := foundMap[val]; ok {
			results[i] = &CheckResult{
				Value:       ind.Value,
				Type:        ind.Type,
				IsMalicious: true,
				Severity:    modelSeverityToProto(dbInd.Severity),
				Confidence:  dbInd.Confidence,
				Tags:        dbInd.Tags,
				Description: dbInd.Description,
				CampaignId:  uuidToString(dbInd.CampaignID),
			}
		} else {
			results[i] = &CheckResult{
				Value:       ind.Value,
				Type:        ind.Type,
				IsMalicious: false,
				Severity:    Severity_SEVERITY_UNSPECIFIED,
				Confidence:  0,
			}
		}
	}

	s.logger.Debug().
		Int("requested", len(req.Indicators)).
		Int("found", len(found)).
		Msg("checked indicators batch")

	return &CheckIndicatorsResponse{Results: results}, nil
}

// GetThreatStats returns aggregated statistics
func (s *Server) GetThreatStats(ctx context.Context, req *GetThreatStatsRequest) (*ThreatStatsResponse, error) {
	response := &ThreatStatsResponse{
		IndicatorsByType:     make(map[string]int64),
		IndicatorsBySeverity: make(map[string]int64),
		LastUpdate:           timestamppb.Now(),
	}

	// Try to get stats from database
	if s.repos != nil {
		// Get indicator stats
		indicatorStats, err := s.repos.Indicators.GetStats(ctx)
		if err == nil {
			response.TotalIndicators = indicatorStats.TotalCount
			response.PegasusIndicators = indicatorStats.PegasusCount
			response.MobileIndicators = indicatorStats.MobileCount
			response.CriticalIndicators = indicatorStats.CriticalCount
			response.TodayNewIocs = indicatorStats.TodayNew
			response.WeeklyNewIocs = indicatorStats.WeeklyNew

			// Copy type stats
			for k, v := range indicatorStats.ByType {
				response.IndicatorsByType[k] = v
			}
			for k, v := range indicatorStats.BySeverity {
				response.IndicatorsBySeverity[k] = v
			}
		}

		// Get source stats
		sourceStats, err := s.repos.Sources.GetStats(ctx)
		if err == nil {
			response.TotalSources = int32(sourceStats.TotalCount)
			response.ActiveSources = int32(sourceStats.ActiveCount)
		}
	}

	// Get data version from cache
	if s.cache != nil {
		if version, err := s.cache.GetSyncVersion(ctx); err == nil {
			response.DataVersion = version
		}
	}

	// Fallback: try cache for complete stats
	var cachedStats models.Stats
	if err := s.cache.GetJSON(ctx, cache.KeyStats, &cachedStats); err == nil {
		if cachedStats.TotalIndicators > 0 {
			response.TotalCampaigns = int32(cachedStats.TotalCampaigns)
			response.ActiveCampaigns = int32(cachedStats.ActiveCampaigns)
		}
	}

	return response, nil
}

// StreamNewThreats streams new threats in real-time
func (s *Server) StreamNewThreats(req *StreamThreatsRequest, stream ThreatIntelligenceService_StreamNewThreatsServer) error {
	s.logger.Info().Msg("client connected to threat stream")

	ctx := stream.Context()

	// Build subscription from request
	sub := &streaming.Subscription{}

	if req.MinSeverity != Severity_SEVERITY_UNSPECIFIED {
		sub.MinSeverity = protoSeverityToModel(req.MinSeverity)
	}
	if len(req.Types) > 0 {
		sub.Types = protoTypesToModel(req.Types)
	}
	if len(req.Platforms) > 0 {
		sub.Platforms = req.Platforms
	}
	if len(req.Tags) > 0 {
		sub.Tags = req.Tags
	}
	sub.PegasusOnly = req.PegasusOnly

	// Subscribe to event bus
	var eventCh <-chan *streaming.ThreatEvent
	var unsubscribe func()

	if s.eventBus != nil {
		eventCh, unsubscribe = s.eventBus.Subscribe(ctx, sub)
		defer unsubscribe()
	} else {
		// No event bus, use empty channel
		ch := make(chan *streaming.ThreatEvent)
		eventCh = ch
		defer close(ch)
	}

	// Heartbeat ticker
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("client disconnected from threat stream")
			return nil

		case event, ok := <-eventCh:
			if !ok {
				s.logger.Info().Msg("event channel closed")
				return nil
			}

			// Convert streaming event to proto
			threatUpdate := &ThreatUpdate{
				Id:             event.ID,
				Type:           string(event.Type),
				Timestamp:      timestamppb.New(event.Timestamp),
				IndicatorId:    event.IndicatorID,
				IndicatorValue: event.IndicatorValue,
				IndicatorType:  modelTypeToProto(event.IndicatorType),
				Severity:       modelSeverityToProto(event.Severity),
				Confidence:     event.Confidence,
				Description:    event.Description,
				Tags:           event.Tags,
				Platforms:      event.Platforms,
				CampaignId:     event.CampaignID,
				CampaignName:   event.CampaignName,
				SourceSlug:     event.SourceSlug,
				SourceName:     event.SourceName,
			}

			if err := stream.Send(threatUpdate); err != nil {
				s.logger.Warn().Err(err).Msg("failed to send threat update")
				return err
			}

			s.logger.Debug().
				Str("indicator", event.IndicatorValue).
				Str("type", string(event.Type)).
				Msg("streamed threat update")

		case <-ticker.C:
			// Send heartbeat to keep connection alive
			heartbeat := &ThreatUpdate{
				Type:      "heartbeat",
				Timestamp: timestamppb.Now(),
			}
			if err := stream.Send(heartbeat); err != nil {
				s.logger.Warn().Err(err).Msg("failed to send heartbeat")
				return err
			}
		}
	}
}

// ShouldBlockDomain checks if a domain should be blocked
func (s *Server) ShouldBlockDomain(ctx context.Context, req *BlockCheckRequest) (*BlockCheckResponse, error) {
	if req.Domain == "" {
		return nil, status.Error(codes.InvalidArgument, "domain is required")
	}

	domain := strings.ToLower(req.Domain)

	// Check repository if available
	if s.repos != nil {
		indicator, err := s.repos.Indicators.GetByValue(ctx, domain, models.IndicatorTypeDomain)
		if err == nil && indicator != nil {
			s.logger.Info().
				Str("domain", domain).
				Str("severity", string(indicator.Severity)).
				Float64("confidence", indicator.Confidence).
				Msg("blocking malicious domain")

			return &BlockCheckResponse{
				ShouldBlock: true,
				Severity:    modelSeverityToProto(indicator.Severity),
				Reason:      indicator.Description,
				CampaignId:  uuidToString(indicator.CampaignID),
				Tags:        indicator.Tags,
				Confidence:  indicator.Confidence,
			}, nil
		}
	}

	s.logger.Debug().
		Str("domain", req.Domain).
		Str("client_ip", req.ClientIp).
		Str("server_id", req.ServerId).
		Msg("domain check - not blocked")

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

	if s.repos == nil {
		return &GetIndicatorResponse{Found: false}, nil
	}

	// Convert proto type to model type
	iocType := protoTypeToModel(req.Type)
	if iocType == "" {
		iocType = models.IndicatorTypeDomain // Default
	}

	indicator, err := s.repos.Indicators.GetByValue(ctx, strings.ToLower(req.Value), iocType)
	if err != nil {
		s.logger.Debug().Err(err).Str("value", req.Value).Msg("indicator not found")
		return &GetIndicatorResponse{Found: false}, nil
	}

	return &GetIndicatorResponse{
		Found:     true,
		Indicator: modelIndicatorToProto(indicator),
	}, nil
}

// ListIndicators retrieves a list of indicators
func (s *Server) ListIndicators(ctx context.Context, req *ListIndicatorsRequest) (*ListIndicatorsResponse, error) {
	limit := int(req.Limit)
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	if s.repos == nil {
		return &ListIndicatorsResponse{
			Indicators: []*Indicator{},
			Total:      0,
			HasMore:    false,
		}, nil
	}

	// Build filter from request
	filter := repository.IndicatorFilter{
		Types:         protoTypesToModel(req.Types),
		Severities:    protoSeveritiesToModel(req.Severities),
		Tags:          req.Tags,
		MinConfidence: req.MinConfidence,
		PegasusOnly:   req.PegasusOnly,
		Limit:         limit,
		Offset:        int(req.Offset),
	}

	// Parse campaign ID if provided
	if req.CampaignId != "" {
		if campaignUUID, err := uuid.Parse(req.CampaignId); err == nil {
			filter.CampaignID = &campaignUUID
		}
	}

	// Parse time filters
	if req.FirstSeenAfter != nil {
		t := req.FirstSeenAfter.AsTime()
		filter.FirstSeenAfter = &t
	}
	if req.LastSeenAfter != nil {
		t := req.LastSeenAfter.AsTime()
		filter.LastSeenAfter = &t
	}

	// Fetch from database
	indicators, total, err := s.repos.Indicators.List(ctx, filter)
	if err != nil {
		s.logger.Error().Err(err).Msg("failed to list indicators")
		return nil, status.Error(codes.Internal, "database error")
	}

	// Convert to proto
	protoIndicators := make([]*Indicator, len(indicators))
	for i, ind := range indicators {
		protoIndicators[i] = modelIndicatorToProto(ind)
	}

	hasMore := int64(filter.Offset+len(indicators)) < total

	return &ListIndicatorsResponse{
		Indicators: protoIndicators,
		Total:      total,
		HasMore:    hasMore,
		NextCursor: "", // Could implement cursor-based pagination later
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
