package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"orbguard-lab/internal/api/handlers"
	apimiddleware "orbguard-lab/internal/api/middleware"
	"orbguard-lab/internal/config"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// Router holds dependencies for the API router
type Router struct {
	config   config.Config
	handlers *handlers.Handlers
	cache    *cache.RedisCache
	logger   *logger.Logger
}

// NewRouter creates a new Router instance
func NewRouter(cfg config.Config, h *handlers.Handlers, c *cache.RedisCache, log *logger.Logger) *Router {
	return &Router{
		config:   cfg,
		handlers: h,
		cache:    c,
		logger:   log.WithComponent("router"),
	}
}

// Setup sets up the Chi router with all routes and middleware
func (r *Router) Setup() http.Handler {
	router := chi.NewRouter()

	// Core middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(apimiddleware.Logger(r.logger))
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	// CORS
	router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   r.config.CORS.AllowedOrigins,
		AllowedMethods:   r.config.CORS.AllowedMethods,
		AllowedHeaders:   r.config.CORS.AllowedHeaders,
		AllowCredentials: r.config.CORS.AllowCredentials,
		MaxAge:           r.config.CORS.MaxAge,
	}))

	// Rate limiting
	if r.config.RateLimit.Enabled {
		router.Use(apimiddleware.RateLimiter(r.cache, r.config.RateLimit))
	}

	// Public routes
	router.Group(func(pub chi.Router) {
		// Health check
		pub.Get("/health", r.handlers.Health.Check)
		pub.Get("/ready", r.handlers.Health.Ready)

		// Public stats
		pub.Get("/api/v1/stats", r.handlers.Stats.Get)
	})

	// API v1 routes (authenticated)
	router.Route("/api/v1", func(api chi.Router) {
		// Auth middleware for protected routes
		api.Use(apimiddleware.APIKeyAuth(r.config.JWT.Secret))

		// Intelligence endpoints
		api.Route("/intelligence", func(intel chi.Router) {
			// Get all indicators
			intel.Get("/", r.handlers.Intelligence.List)

			// Pegasus-specific indicators
			intel.Get("/pegasus", r.handlers.Intelligence.ListPegasus)

			// Mobile-specific indicators
			intel.Get("/mobile", r.handlers.Intelligence.ListMobile)
			intel.Get("/mobile/sync", r.handlers.Intelligence.MobileSync)

			// Community-reported indicators
			intel.Get("/community", r.handlers.Intelligence.ListCommunity)

			// Check indicator(s)
			intel.Get("/check", r.handlers.Intelligence.Check)
			intel.Post("/check/batch", r.handlers.Intelligence.CheckBatch)

			// Report new threat
			intel.Post("/report", r.handlers.Intelligence.Report)
		})

		// Campaign endpoints
		api.Route("/campaigns", func(campaigns chi.Router) {
			campaigns.Get("/", r.handlers.Campaigns.List)
			campaigns.Get("/{slug}", r.handlers.Campaigns.Get)
			campaigns.Get("/{slug}/indicators", r.handlers.Campaigns.ListIndicators)
		})

		// Threat actors endpoints
		api.Route("/actors", func(actors chi.Router) {
			actors.Get("/", r.handlers.Actors.List)
			actors.Get("/{id}", r.handlers.Actors.Get)
		})

		// Sources endpoints
		api.Route("/sources", func(sources chi.Router) {
			sources.Get("/", r.handlers.Sources.List)
			sources.Get("/{slug}", r.handlers.Sources.Get)
		})

		// SMS/Smishing protection endpoints
		api.Route("/sms", func(sms chi.Router) {
			sms.Post("/analyze", r.handlers.SMS.Analyze)
			sms.Post("/analyze/batch", r.handlers.SMS.AnalyzeBatch)
			sms.Post("/check-url", r.handlers.SMS.CheckURL)
			sms.Get("/patterns", r.handlers.SMS.GetPatterns)
			sms.Get("/stats", r.handlers.SMS.GetStats)
		})

		// URL/Safe Web protection endpoints
		api.Route("/url", func(url chi.Router) {
			// URL checking
			url.Post("/check", r.handlers.URL.CheckURL)
			url.Post("/check/batch", r.handlers.URL.BatchCheckURLs)

			// Domain reputation
			url.Get("/reputation/{domain}", r.handlers.URL.GetReputation)

			// Stats
			url.Get("/stats", r.handlers.URL.GetStats)

			// Whitelist/blacklist management
			url.Get("/whitelist", r.handlers.URL.GetWhitelist)
			url.Post("/whitelist", r.handlers.URL.AddToWhitelist)
			url.Get("/blacklist", r.handlers.URL.GetBlacklist)
			url.Post("/blacklist", r.handlers.URL.AddToBlacklist)
			url.Delete("/list/{id}", r.handlers.URL.RemoveFromList)

			// DNS blocking rules (for OrbNet VPN)
			url.Get("/dns-rules", r.handlers.URL.GetDNSBlockRules)

			// Block page data
			url.Get("/block-page", r.handlers.URL.GetBlockPage)

			// User feedback/reporting
			url.Post("/report", r.handlers.URL.ReportURL)
		})

		// Dark Web Monitoring endpoints
		api.Route("/darkweb", func(dw chi.Router) {
			// Breach checking
			dw.Post("/check/email", r.handlers.DarkWeb.CheckEmail)
			dw.Post("/check/password", r.handlers.DarkWeb.CheckPassword)

			// Asset monitoring
			dw.Get("/monitor", r.handlers.DarkWeb.GetMonitoredAssets)
			dw.Post("/monitor", r.handlers.DarkWeb.AddMonitoredAsset)
			dw.Delete("/monitor/{id}", r.handlers.DarkWeb.RemoveMonitoredAsset)

			// Status and alerts
			dw.Get("/status", r.handlers.DarkWeb.GetMonitoringStatus)
			dw.Get("/alerts", r.handlers.DarkWeb.GetAlerts)
			dw.Post("/alerts/{id}/ack", r.handlers.DarkWeb.AcknowledgeAlert)

			// Breaches
			dw.Get("/breaches", r.handlers.DarkWeb.GetBreaches)
			dw.Get("/breaches/{name}", r.handlers.DarkWeb.GetBreachByName)

			// Stats and refresh
			dw.Get("/stats", r.handlers.DarkWeb.GetStats)
			dw.Post("/refresh", r.handlers.DarkWeb.RefreshMonitoring)
		})

		// App Security Suite endpoints
		api.Route("/apps", func(apps chi.Router) {
			// App analysis
			apps.Post("/analyze", r.handlers.AppSecurity.AnalyzeApp)
			apps.Post("/analyze/batch", r.handlers.AppSecurity.AnalyzeBatch)

			// App reputation
			apps.Get("/reputation/{package}", r.handlers.AppSecurity.GetAppReputation)

			// Sideloaded app detection
			apps.Post("/sideloaded", r.handlers.AppSecurity.CheckSideloaded)

			// Privacy audit
			apps.Post("/privacy-report", r.handlers.AppSecurity.GetPrivacyReport)

			// Reference data
			apps.Get("/trackers", r.handlers.AppSecurity.GetKnownTrackers)
			apps.Get("/permissions/dangerous", r.handlers.AppSecurity.GetDangerousPermissions)

			// Stats and reporting
			apps.Get("/stats", r.handlers.AppSecurity.GetStats)
			apps.Post("/report", r.handlers.AppSecurity.ReportApp)
		})

		// Network Security endpoints
		api.Route("/network", func(net chi.Router) {
			// Wi-Fi security
			net.Post("/wifi/audit", r.handlers.NetworkSecurity.AuditWiFi)
			net.Get("/wifi/security-types", r.handlers.NetworkSecurity.GetWiFiSecurityInfo)

			// DNS protection
			net.Post("/dns/check", r.handlers.NetworkSecurity.CheckDNS)
			net.Get("/dns/providers", r.handlers.NetworkSecurity.GetDNSProviders)
			net.Get("/dns/providers/{ip}", r.handlers.NetworkSecurity.GetDNSProvider)
			net.Post("/dns/configure", r.handlers.NetworkSecurity.ConfigureDNS)

			// Network attack detection
			net.Post("/arp/check", r.handlers.NetworkSecurity.CheckARPSpoofing)
			net.Post("/ssl/check", r.handlers.NetworkSecurity.CheckSSL)
			net.Get("/attacks/types", r.handlers.NetworkSecurity.GetAttackTypes)

			// VPN integration
			net.Post("/vpn/recommend", r.handlers.NetworkSecurity.GetVPNRecommendation)
			net.Get("/vpn/config", r.handlers.NetworkSecurity.GetVPNConfig)
			net.Put("/vpn/config", r.handlers.NetworkSecurity.UpdateVPNConfig)

			// Full network audit
			net.Post("/audit/full", r.handlers.NetworkSecurity.FullNetworkAudit)

			// Stats
			net.Get("/stats", r.handlers.NetworkSecurity.GetStats)
		})

		// Threat Graph endpoints (Neo4j correlation)
		api.Route("/graph", func(graph chi.Router) {
			// Correlation queries
			graph.Get("/correlation/{id}", r.handlers.Graph.GetCorrelation)
			graph.Get("/related/{id}", r.handlers.Graph.FindRelated)
			graph.Get("/temporal/{id}", r.handlers.Graph.GetTemporalCorrelation)

			// Infrastructure analysis
			graph.Get("/shared-infrastructure", r.handlers.Graph.FindSharedInfrastructure)

			// Campaign detection
			graph.Get("/detect-campaigns", r.handlers.Graph.DetectCampaigns)

			// TTP analysis
			graph.Get("/ttp-similarity", r.handlers.Graph.GetTTPSimilarity)

			// Graph traversal and search
			graph.Post("/traverse", r.handlers.Graph.TraverseGraph)
			graph.Post("/search", r.handlers.Graph.SearchGraph)

			// Relationship management
			graph.Post("/relationship", r.handlers.Graph.CreateRelationship)

			// Sync, relationship building, and stats
			graph.Post("/sync", r.handlers.Graph.SyncFromPostgres)
			graph.Post("/build-relationships", r.handlers.Graph.BuildRelationships)
			graph.Get("/stats", r.handlers.Graph.GetStats)
		})

		// YARA Rules Engine endpoints
		api.Route("/yara", func(yara chi.Router) {
			// Scanning
			yara.Post("/scan", r.handlers.YARA.Scan)
			yara.Post("/scan/apk", r.handlers.YARA.ScanAPK)
			yara.Post("/scan/ipa", r.handlers.YARA.ScanIPA)
			yara.Post("/quick-scan", r.handlers.YARA.QuickScan)

			// Rule management
			yara.Get("/rules", r.handlers.YARA.ListRules)
			yara.Get("/rules/{id}", r.handlers.YARA.GetRule)
			yara.Post("/rules", r.handlers.YARA.AddRule)
			yara.Delete("/rules/{id}", r.handlers.YARA.DeleteRule)

			// Parsing and validation
			yara.Post("/parse", r.handlers.YARA.ParseRule)

			// User submissions
			yara.Post("/submit", r.handlers.YARA.SubmitRule)

			// Metadata
			yara.Get("/categories", r.handlers.YARA.GetCategories)
			yara.Get("/stats", r.handlers.YARA.GetStats)

			// Admin
			yara.Post("/reload", r.handlers.YARA.ReloadRules)
		})

		// Correlation Engine endpoints
		api.Route("/correlation", func(corr chi.Router) {
			// Main correlation
			corr.Post("/", r.handlers.Correlation.Correlate)
			corr.Post("/batch", r.handlers.Correlation.CorrelateBatch)
			corr.Post("/analyze", r.handlers.Correlation.AnalyzeValue)

			// Single indicator correlation
			corr.Get("/indicator/{id}", r.handlers.Correlation.CorrelateIndicator)
			corr.Get("/indicator/{id}/temporal", r.handlers.Correlation.GetTemporalCorrelation)
			corr.Get("/indicator/{id}/infrastructure", r.handlers.Correlation.GetInfrastructureOverlap)
			corr.Get("/indicator/{id}/ttp", r.handlers.Correlation.GetTTPCorrelation)

			// Campaign matching
			corr.Post("/campaigns/match", r.handlers.Correlation.MatchCampaigns)
			corr.Get("/campaigns/detect", r.handlers.Correlation.DetectCampaigns)

			// Clustering
			corr.Post("/cluster", r.handlers.Correlation.ClusterIndicators)

			// Stats
			corr.Get("/stats", r.handlers.Correlation.GetStats)
		})

		// MITRE ATT&CK endpoints
		api.Route("/mitre", func(mitre chi.Router) {
			// Tactics
			mitre.Get("/tactics", r.handlers.MITRE.ListTactics)
			mitre.Get("/tactics/{id}", r.handlers.MITRE.GetTactic)

			// Techniques
			mitre.Get("/techniques", r.handlers.MITRE.ListTechniques)
			mitre.Get("/techniques/search", r.handlers.MITRE.SearchTechniques)
			mitre.Get("/techniques/{id}", r.handlers.MITRE.GetTechnique)

			// Mitigations
			mitre.Get("/mitigations", r.handlers.MITRE.ListMitigations)
			mitre.Get("/mitigations/{id}", r.handlers.MITRE.GetMitigation)

			// Groups (threat actors)
			mitre.Get("/groups", r.handlers.MITRE.ListGroups)
			mitre.Get("/groups/{id}", r.handlers.MITRE.GetGroup)

			// Software (malware/tools)
			mitre.Get("/software", r.handlers.MITRE.ListSoftware)
			mitre.Get("/software/{id}", r.handlers.MITRE.GetSoftware)

			// Matrix view
			mitre.Get("/matrix", r.handlers.MITRE.GetMatrix)

			// Navigator export
			mitre.Post("/navigator/export", r.handlers.MITRE.ExportNavigatorLayer)

			// Stats and admin
			mitre.Get("/stats", r.handlers.MITRE.GetStats)
			mitre.Post("/reload", r.handlers.MITRE.Reload)
		})

		// Machine Learning endpoints
		api.Route("/ml", func(ml chi.Router) {
			// Entity/IOC extraction from text
			ml.Post("/extract/entities", r.handlers.ML.ExtractEntities)
			ml.Post("/extract/indicators", r.handlers.ML.ExtractIndicators)

			// Analysis
			ml.Post("/analyze", r.handlers.ML.AnalyzeValue)
			ml.Get("/analyze/{id}", r.handlers.ML.EnrichIndicator)

			// Anomaly detection
			ml.Post("/anomalies/detect", r.handlers.ML.DetectAnomalies)

			// Clustering
			ml.Post("/cluster", r.handlers.ML.ClusterIndicators)

			// Severity prediction
			ml.Post("/severity/predict", r.handlers.ML.PredictSeverity)

			// Model management
			ml.Get("/models", r.handlers.ML.GetStats)
			ml.Get("/models/{model}", r.handlers.ML.GetModelInfo)
			ml.Post("/models/train", r.handlers.ML.Train)
			ml.Post("/models/{model}/train", r.handlers.ML.TrainModel)

			// Features
			ml.Get("/features", r.handlers.ML.GetFeatures)

			// Stats
			ml.Get("/stats", r.handlers.ML.GetStats)
		})

		// Privacy Protection Suite endpoints
		api.Route("/privacy", func(priv chi.Router) {
			// Privacy event recording
			priv.Post("/events", r.handlers.Privacy.RecordEvent)
			priv.Post("/camera", r.handlers.Privacy.RecordCameraAccess)
			priv.Post("/microphone", r.handlers.Privacy.RecordMicrophoneAccess)
			priv.Post("/clipboard", r.handlers.Privacy.RecordClipboardAccess)
			priv.Post("/screen", r.handlers.Privacy.RecordScreenEvent)

			// Clipboard protection
			priv.Post("/clipboard/check", r.handlers.Privacy.CheckClipboard)

			// Tracker management
			priv.Get("/trackers", r.handlers.Privacy.GetTrackers)
			priv.Get("/trackers/{id}", r.handlers.Privacy.GetTracker)
			priv.Get("/trackers/check/{domain}", r.handlers.Privacy.CheckDomain)
			priv.Post("/trackers/should-block", r.handlers.Privacy.ShouldBlockDomain)
			priv.Post("/trackers/blocklist", r.handlers.Privacy.GetBlockList)

			// Privacy audit
			priv.Post("/audit", r.handlers.Privacy.AuditPrivacy)

			// Stats and info
			priv.Get("/stats/{device_id}", r.handlers.Privacy.GetStats)
			priv.Get("/service/stats", r.handlers.Privacy.GetServiceStats)

			// Reference data
			priv.Get("/patterns", r.handlers.Privacy.GetSensitivePatterns)
			priv.Get("/event-types", r.handlers.Privacy.GetPrivacyEventTypes)
			priv.Get("/risk-levels", r.handlers.Privacy.GetRiskLevels)
		})

		// Device Security endpoints (Anti-theft, SIM monitoring, OS vulnerabilities)
		api.Route("/device", func(dev chi.Router) {
			// Reference data (must come before parameterized routes)
			dev.Get("/vulnerabilities/known", r.handlers.DeviceSecurity.GetKnownVulnerabilities)
			dev.Get("/security-info", r.handlers.DeviceSecurity.GetLatestSecurityInfo)
			dev.Get("/service/stats", r.handlers.DeviceSecurity.GetStats)

			// Device registration and management
			dev.Post("/register", r.handlers.DeviceSecurity.RegisterDevice)
			dev.Get("/{device_id}", r.handlers.DeviceSecurity.GetDevice)
			dev.Put("/{device_id}", r.handlers.DeviceSecurity.UpdateDevice)

			// Anti-theft remote commands
			dev.Post("/{device_id}/locate", r.handlers.DeviceSecurity.Locate)
			dev.Post("/{device_id}/lock", r.handlers.DeviceSecurity.Lock)
			dev.Post("/{device_id}/wipe", r.handlers.DeviceSecurity.Wipe)
			dev.Post("/{device_id}/ring", r.handlers.DeviceSecurity.Ring)
			dev.Post("/{device_id}/command", r.handlers.DeviceSecurity.IssueCommand)
			dev.Get("/{device_id}/commands/pending", r.handlers.DeviceSecurity.GetPendingCommands)
			dev.Post("/{device_id}/commands/{command_id}/ack", r.handlers.DeviceSecurity.AcknowledgeCommand)

			// Device status management
			dev.Post("/{device_id}/mark-lost", r.handlers.DeviceSecurity.MarkLost)
			dev.Post("/{device_id}/mark-stolen", r.handlers.DeviceSecurity.MarkStolen)
			dev.Post("/{device_id}/mark-recovered", r.handlers.DeviceSecurity.MarkRecovered)

			// Location tracking
			dev.Post("/{device_id}/location", r.handlers.DeviceSecurity.UpdateLocation)
			dev.Get("/{device_id}/location/history", r.handlers.DeviceSecurity.GetLocationHistory)

			// SIM monitoring
			dev.Post("/{device_id}/sim", r.handlers.DeviceSecurity.ReportSIM)
			dev.Get("/{device_id}/sim", r.handlers.DeviceSecurity.GetCurrentSIMs)
			dev.Get("/{device_id}/sim/history", r.handlers.DeviceSecurity.GetSIMHistory)
			dev.Post("/{device_id}/sim/trusted", r.handlers.DeviceSecurity.AddTrustedSIM)

			// Thief selfie capture
			dev.Post("/{device_id}/selfie", r.handlers.DeviceSecurity.RecordThiefSelfie)
			dev.Get("/{device_id}/selfies", r.handlers.DeviceSecurity.GetThiefSelfies)

			// Anti-theft settings
			dev.Get("/{device_id}/settings", r.handlers.DeviceSecurity.GetSettings)
			dev.Put("/{device_id}/settings", r.handlers.DeviceSecurity.UpdateSettings)

			// OS vulnerability auditing
			dev.Post("/vulnerabilities/audit", r.handlers.DeviceSecurity.AuditOSVulnerabilities)

			// Overall device security status
			dev.Get("/{device_id}/security-status", r.handlers.DeviceSecurity.GetSecurityStatus)
		})

		// QR Code Security endpoints (Quishing protection)
		api.Route("/qr", func(qr chi.Router) {
			// QR code scanning and analysis
			qr.Post("/scan", r.handlers.QRSecurity.Scan)
			qr.Post("/scan/batch", r.handlers.QRSecurity.ScanBatch)

			// URL checking (for QR codes containing URLs)
			qr.Post("/check-url", r.handlers.QRSecurity.CheckURL)

			// Safe preview before opening
			qr.Post("/preview", r.handlers.QRSecurity.Preview)

			// Reference data
			qr.Get("/content-types", r.handlers.QRSecurity.GetContentTypes)
			qr.Get("/threat-types", r.handlers.QRSecurity.GetThreatTypes)
			qr.Get("/suspicious-tlds", r.handlers.QRSecurity.GetSuspiciousTLDs)
			qr.Get("/url-shorteners", r.handlers.QRSecurity.GetURLShorteners)

			// Stats
			qr.Get("/stats", r.handlers.QRSecurity.GetStats)
		})

		// Enterprise endpoints (MDM, Zero Trust, SIEM, Compliance)
		api.Route("/enterprise", func(ent chi.Router) {
			// Overview and stats
			ent.Get("/overview", r.handlers.Enterprise.GetEnterpriseOverview)
			ent.Get("/stats", r.handlers.Enterprise.GetEnterpriseStats)

			// MDM/UEM Integration
			ent.Route("/mdm", func(mdm chi.Router) {
				mdm.Get("/integrations", r.handlers.Enterprise.ListMDMIntegrations)
				mdm.Post("/integrations", r.handlers.Enterprise.CreateMDMIntegration)
				mdm.Get("/integrations/{id}", r.handlers.Enterprise.GetMDMIntegration)
				mdm.Delete("/integrations/{id}", r.handlers.Enterprise.DeleteMDMIntegration)
				mdm.Post("/integrations/{id}/sync", r.handlers.Enterprise.SyncMDMDevices)
				mdm.Get("/integrations/{id}/devices", r.handlers.Enterprise.ListMDMDevices)
				mdm.Post("/alerts", r.handlers.Enterprise.SendMDMThreatAlert)
				mdm.Get("/stats", r.handlers.Enterprise.GetMDMStats)
			})

			// Zero Trust / Conditional Access
			ent.Route("/zerotrust", func(zt chi.Router) {
				zt.Post("/posture", r.handlers.Enterprise.AssessDevicePosture)
				zt.Post("/evaluate", r.handlers.Enterprise.EvaluateAccess)
				zt.Get("/policies", r.handlers.Enterprise.ListPolicies)
				zt.Post("/policies", r.handlers.Enterprise.CreatePolicy)
				zt.Get("/policies/{id}", r.handlers.Enterprise.GetPolicy)
				zt.Put("/policies/{id}", r.handlers.Enterprise.UpdatePolicy)
				zt.Delete("/policies/{id}", r.handlers.Enterprise.DeletePolicy)
				zt.Get("/stats", r.handlers.Enterprise.GetZeroTrustStats)
			})

			// SIEM Integration
			ent.Route("/siem", func(siem chi.Router) {
				siem.Get("/integrations", r.handlers.Enterprise.ListSIEMIntegrations)
				siem.Post("/integrations", r.handlers.Enterprise.CreateSIEMIntegration)
				siem.Get("/integrations/{id}", r.handlers.Enterprise.GetSIEMIntegration)
				siem.Delete("/integrations/{id}", r.handlers.Enterprise.DeleteSIEMIntegration)
				siem.Post("/events", r.handlers.Enterprise.SendSIEMEvent)
				siem.Get("/stats", r.handlers.Enterprise.GetSIEMStats)
			})

			// Compliance Reporting
			ent.Route("/compliance", func(comp chi.Router) {
				comp.Get("/frameworks", r.handlers.Enterprise.GetSupportedFrameworks)
				comp.Get("/reports", r.handlers.Enterprise.ListComplianceReports)
				comp.Post("/reports", r.handlers.Enterprise.GenerateComplianceReport)
				comp.Get("/reports/{id}", r.handlers.Enterprise.GetComplianceReport)
				comp.Get("/devices/{id}", r.handlers.Enterprise.GetDeviceComplianceStatus)
				comp.Get("/findings", r.handlers.Enterprise.ListFindings)
				comp.Post("/findings", r.handlers.Enterprise.CreateFinding)
				comp.Get("/findings/{id}", r.handlers.Enterprise.GetFinding)
				comp.Post("/findings/{id}/resolve", r.handlers.Enterprise.ResolveFinding)
				comp.Get("/stats", r.handlers.Enterprise.GetComplianceStats)
			})
		})

		// OrbNet VPN Integration endpoints
		api.Route("/orbnet", func(orbnet chi.Router) {
			// DNS Filtering
			orbnet.Post("/dns/block", r.handlers.OrbNet.ShouldBlockDomain)
			orbnet.Post("/dns/block/batch", r.handlers.OrbNet.CheckDomainBatch)

			// Block Rules
			orbnet.Get("/rules", r.handlers.OrbNet.ListBlockRules)
			orbnet.Post("/rules", r.handlers.OrbNet.AddBlockRule)
			orbnet.Get("/rules/{id}", r.handlers.OrbNet.GetBlockRule)
			orbnet.Delete("/rules/{id}", r.handlers.OrbNet.RemoveBlockRule)
			orbnet.Post("/emergency-block", r.handlers.OrbNet.EmergencyBlock)

			// Servers
			orbnet.Get("/servers", r.handlers.OrbNet.ListServers)
			orbnet.Post("/servers", r.handlers.OrbNet.RegisterServer)
			orbnet.Get("/servers/{id}", r.handlers.OrbNet.GetServer)
			orbnet.Put("/servers/{id}/status", r.handlers.OrbNet.UpdateServerStatus)

			// Threat Sync
			orbnet.Post("/sync", r.handlers.OrbNet.SyncThreatData)

			// Dashboard & Stats
			orbnet.Get("/dashboard", r.handlers.OrbNet.GetDashboardStats)
			orbnet.Get("/categories", r.handlers.OrbNet.GetCategories)
		})

		// Forensic Analysis endpoints (Pegasus/Spyware detection)
		api.Route("/forensics", func(forensics chi.Router) {
			// iOS Forensics
			forensics.Post("/ios/shutdown-log", r.handlers.Forensics.AnalyzeShutdownLog)
			forensics.Post("/ios/shutdown-log/upload", r.handlers.Forensics.UploadShutdownLog)
			forensics.Post("/ios/backup", r.handlers.Forensics.AnalyzeBackup)
			forensics.Post("/ios/data-usage", r.handlers.Forensics.AnalyzeDataUsage)
			forensics.Post("/ios/sysdiagnose", r.handlers.Forensics.AnalyzeSysdiagnose)

			// Android Forensics
			forensics.Post("/android/logcat", r.handlers.Forensics.AnalyzeLogcat)
			forensics.Post("/android/logcat/upload", r.handlers.Forensics.UploadLogcat)

			// Comprehensive Analysis
			forensics.Post("/full", r.handlers.Forensics.FullAnalysis)
			forensics.Post("/quick-check", r.handlers.Forensics.QuickCheck)

			// IOC database (Citizen Lab/Amnesty MVT integration)
			forensics.Get("/iocs/stats", r.handlers.Forensics.GetIOCStats)

			// Capabilities and documentation
			forensics.Get("/capabilities", r.handlers.Forensics.GetCapabilities)
		})

		// Digital Footprint endpoints (Data broker removal, privacy)
		api.Route("/footprint", func(footprint chi.Router) {
			// Scan digital footprint
			footprint.Post("/scan", r.handlers.Footprint.Scan)
			footprint.Post("/quick-scan", r.handlers.Footprint.QuickScan)

			// Data brokers
			footprint.Get("/brokers", r.handlers.Footprint.GetBrokers)
			footprint.Get("/brokers/categories", r.handlers.Footprint.GetCategories)
			footprint.Get("/brokers/{id}", r.handlers.Footprint.GetBroker)

			// Data removal requests
			footprint.Post("/removal", r.handlers.Footprint.RequestRemoval)
			footprint.Post("/removal/batch", r.handlers.Footprint.RequestBatchRemoval)
			footprint.Get("/removal/{id}", r.handlers.Footprint.GetRemovalStatus)

			// Stats
			footprint.Get("/stats", r.handlers.Footprint.GetStats)
		})

		// Desktop Security endpoints (KnockKnock/LuLu-style)
		api.Route("/desktop", func(desktop chi.Router) {
			// Persistence scanning
			desktop.Post("/persistence/scan", r.handlers.DesktopSecurity.ScanPersistence)
			desktop.Post("/persistence/quick-scan", r.handlers.DesktopSecurity.QuickScanPersistence)
			desktop.Post("/persistence/scan-path", r.handlers.DesktopSecurity.ScanPath)

			// Code signing verification
			desktop.Post("/codesign/verify", r.handlers.DesktopSecurity.VerifyCodeSigning)
			desktop.Post("/codesign/verify-batch", r.handlers.DesktopSecurity.VerifyCodeSigningBatch)

			// Network monitoring (LuLu-style)
			desktop.Get("/network/connections", r.handlers.DesktopSecurity.GetNetworkConnections)
			desktop.Get("/network/listening", r.handlers.DesktopSecurity.GetListeningPorts)
			desktop.Get("/network/outbound", r.handlers.DesktopSecurity.GetOutboundConnections)

			// Firewall rules
			desktop.Get("/network/rules", r.handlers.DesktopSecurity.GetFirewallRules)
			desktop.Post("/network/rules", r.handlers.DesktopSecurity.AddFirewallRule)
			desktop.Delete("/network/rules/{id}", r.handlers.DesktopSecurity.DeleteFirewallRule)
			desktop.Post("/network/block-ip", r.handlers.DesktopSecurity.BlockIP)

			// Browser extension scanning
			desktop.Post("/browser/extensions/scan", r.handlers.DesktopSecurity.ScanBrowserExtensions)

			// VirusTotal integration
			desktop.Get("/virustotal/hash/{hash}", r.handlers.DesktopSecurity.LookupHash)
			desktop.Post("/virustotal/file", r.handlers.DesktopSecurity.LookupFile)
			desktop.Post("/virustotal/batch", r.handlers.DesktopSecurity.LookupHashBatch)
			desktop.Get("/virustotal/ip/{ip}", r.handlers.DesktopSecurity.LookupIP)

			// Full security scan
			desktop.Post("/scan/full", r.handlers.DesktopSecurity.FullSecurityScan)
		})

		// Webhooks endpoints
		r.handlers.Webhooks.RegisterRoutes(api)

		// Playbooks endpoints
		r.handlers.Playbooks.RegisterRoutes(api)

		// Analytics endpoints
		r.handlers.Analytics.RegisterRoutes(api)

		// Integrations endpoints
		r.handlers.Integrations.RegisterRoutes(api)

		// Scam Detection endpoints (AI-powered)
		r.handlers.ScamDetection.RegisterRoutes(api)

		// Admin endpoints
		api.Route("/admin", func(admin chi.Router) {
			// Require admin auth
			admin.Use(apimiddleware.AdminAuth(r.config.JWT.Secret))

			// Force update
			admin.Post("/update", r.handlers.Admin.TriggerUpdate)
			admin.Post("/update/{source}", r.handlers.Admin.TriggerSourceUpdate)

			// Reports management
			admin.Get("/reports", r.handlers.Admin.ListReports)
			admin.Get("/reports/{id}", r.handlers.Admin.GetReport)
			admin.Post("/reports/{id}/approve", r.handlers.Admin.ApproveReport)
			admin.Post("/reports/{id}/reject", r.handlers.Admin.RejectReport)

			// Stats
			admin.Get("/stats/detailed", r.handlers.Admin.DetailedStats)
		})
	})

	// TAXII 2.1 endpoints (optional)
	if r.config.STIX.Enabled && r.config.STIX.TAXIIServer.Enabled {
		router.Route("/taxii2", func(taxii chi.Router) {
			taxii.Get("/", r.handlers.TAXII.Discovery)
			taxii.Get("/collections", r.handlers.TAXII.ListCollections)
			taxii.Get("/collections/{id}", r.handlers.TAXII.GetCollection)
			taxii.Get("/collections/{id}/objects", r.handlers.TAXII.GetObjects)
			taxii.Post("/collections/{id}/objects", r.handlers.TAXII.AddObjects)
		})
	}

	// WebSocket streaming endpoint (real-time threat updates for mobile apps)
	router.Get("/ws/threats", r.handlers.Streaming.HandleWebSocket)
	router.Get("/api/v1/streaming/stats", r.handlers.Streaming.GetStats)

	return router
}
