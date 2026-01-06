package handlers

import (
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/internal/domain/services/desktop_security"
	"orbguard-lab/internal/domain/services/digital_footprint"
	"orbguard-lab/internal/forensics"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/internal/streaming"
	"orbguard-lab/pkg/logger"
)

// Handlers holds all API handlers
type Handlers struct {
	Health          *HealthHandler
	Intelligence    *IntelligenceHandler
	Stats           *StatsHandler
	Campaigns       *CampaignsHandler
	Actors          *ActorsHandler
	Sources         *SourcesHandler
	Admin           *AdminHandler
	TAXII           *TAXIIHandler
	Streaming       *StreamingHandler
	SMS             *SMSHandler
	URL             *URLHandler
	DarkWeb         *DarkWebHandler
	AppSecurity     *AppSecurityHandler
	NetworkSecurity *NetworkSecurityHandler
	Graph           *GraphHandler
	YARA            *YARAHandler
	Correlation     *CorrelationHandler
	MITRE           *MITREHandler
	ML              *MLHandler
	Privacy         *PrivacyHandler
	DeviceSecurity  *DeviceSecurityHandler
	QRSecurity      *QRSecurityHandler
	Enterprise      *EnterpriseHandler
	OrbNet          *OrbNetHandler
	Forensics       *ForensicsHandler
	Footprint       *FootprintHandler
	DesktopSecurity *DesktopSecurityHandler
	Webhooks        *WebhookHandler
	Playbooks       *PlaybookHandler
	Analytics       *AnalyticsHandler
	Integrations    *IntegrationsHandler
}

// Dependencies holds dependencies for handlers
type Dependencies struct {
	Aggregator            *services.Aggregator
	Normalizer            *services.Normalizer
	Deduplicator          *services.Deduplicator
	Scorer                *services.Scorer
	Scheduler             *services.Scheduler
	Cache                 *cache.RedisCache
	Logger                *logger.Logger
	Repos                 *repository.Repositories
	EventBus              *streaming.EventBus
	WSHub                 *streaming.WebSocketHub
	URLService            *services.URLReputationService
	DarkWebMonitor        *services.DarkWebMonitor
	AppAnalyzer           *services.AppAnalyzer
	NetworkSecurity       *services.NetworkSecurityService
	GraphService          *services.GraphService
	YARAService           *services.YARAService
	CorrelationEngine     *services.CorrelationEngine
	MITREService          *services.MITREService
	MLService             *services.MLService
	PrivacyService        *services.PrivacyService
	DeviceSecurityService *services.DeviceSecurityService
	QRSecurityService     *services.QRSecurityService
	STIXTAXIIService      *services.STIXTAXIIService
	EnterpriseService     *services.EnterpriseService
	OrbNetService         *services.OrbNetService
	ForensicsService      *forensics.Service
	FootprintScanner      *digital_footprint.Scanner
	PersistenceScanner    *desktop_security.PersistenceScanner
	CodeVerifier          *desktop_security.CodeSigningVerifier
	NetworkMonitor        *desktop_security.NetworkMonitor
	BrowserScanner        *desktop_security.BrowserExtensionScanner
	VTClient              *desktop_security.VirusTotalClient
	WebhookService        *services.WebhookService
	PlaybookService       *services.PlaybookService
	AnalyticsService      *services.AnalyticsService
	IntegrationService    *services.IntegrationService
}

// NewHandlers creates all handlers
func NewHandlers(deps Dependencies) *Handlers {
	return &Handlers{
		Health:          NewHealthHandler(deps.Cache, deps.Repos, deps.Logger),
		Intelligence:    NewIntelligenceHandler(deps.Repos, deps.Cache, deps.Logger),
		Stats:           NewStatsHandler(deps.Repos, deps.Cache, deps.Logger),
		Campaigns:       NewCampaignsHandler(deps.Repos, deps.Logger),
		Actors:          NewActorsHandler(deps.Repos, deps.Logger),
		Sources:         NewSourcesHandler(deps.Repos, deps.Aggregator, deps.Logger),
		Admin:           NewAdminHandler(deps.Aggregator, deps.Scheduler, deps.Logger),
		TAXII:           NewTAXIIHandler(deps.STIXTAXIIService, deps.Logger),
		Streaming:       NewStreamingHandler(deps.WSHub, deps.EventBus, deps.Logger),
		SMS:             NewSMSHandler(deps.Repos, deps.Cache, deps.Logger),
		URL:             NewURLHandler(deps.URLService, deps.Logger),
		DarkWeb:         NewDarkWebHandler(deps.DarkWebMonitor, deps.Logger),
		AppSecurity:     NewAppSecurityHandler(deps.AppAnalyzer, deps.Logger),
		NetworkSecurity: NewNetworkSecurityHandler(deps.NetworkSecurity, deps.Logger),
		Graph:           NewGraphHandler(deps.GraphService, deps.Logger),
		YARA:            NewYARAHandler(deps.YARAService, deps.Logger),
		Correlation:     NewCorrelationHandler(deps.CorrelationEngine, deps.Logger),
		MITRE:           NewMITREHandler(deps.MITREService, deps.Logger),
		ML:              NewMLHandler(deps.MLService, deps.Logger),
		Privacy:         NewPrivacyHandler(deps.PrivacyService, deps.Logger),
		DeviceSecurity:  NewDeviceSecurityHandler(deps.DeviceSecurityService, deps.Logger),
		QRSecurity:      NewQRSecurityHandler(deps.QRSecurityService, deps.Logger),
		Enterprise:      NewEnterpriseHandler(deps.EnterpriseService, deps.Logger),
		OrbNet:          NewOrbNetHandler(deps.OrbNetService, deps.Logger),
		Forensics:       NewForensicsHandler(deps.ForensicsService, deps.Logger),
		Footprint:       NewFootprintHandler(deps.FootprintScanner, deps.Logger),
		DesktopSecurity: NewDesktopSecurityHandler(DesktopSecurityDeps{
			PersistenceScanner: deps.PersistenceScanner,
			CodeVerifier:       deps.CodeVerifier,
			NetworkMonitor:     deps.NetworkMonitor,
			BrowserScanner:     deps.BrowserScanner,
			VTClient:           deps.VTClient,
			Logger:             deps.Logger,
		}),
		Webhooks:     NewWebhookHandler(deps.Logger, deps.WebhookService),
		Playbooks:    NewPlaybookHandler(deps.Logger, deps.PlaybookService),
		Analytics:    NewAnalyticsHandler(deps.Logger, deps.AnalyticsService),
		Integrations: NewIntegrationsHandler(deps.IntegrationService),
	}
}
