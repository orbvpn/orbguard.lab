package handlers

import (
	"encoding/json"
	"net/http"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// QRSecurityHandler handles QR code security API requests
type QRSecurityHandler struct {
	service *services.QRSecurityService
	logger  *logger.Logger
}

// NewQRSecurityHandler creates a new QR security handler
func NewQRSecurityHandler(service *services.QRSecurityService, log *logger.Logger) *QRSecurityHandler {
	return &QRSecurityHandler{
		service: service,
		logger:  log.WithComponent("qr-security-handler"),
	}
}

// Scan handles POST /api/v1/qr/scan
func (h *QRSecurityHandler) Scan(w http.ResponseWriter, r *http.Request) {
	var req models.QRScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Content == "" {
		h.respondError(w, http.StatusBadRequest, "content is required")
		return
	}

	result, err := h.service.AnalyzeQRCode(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to analyze QR code")
		h.respondError(w, http.StatusInternalServerError, "failed to analyze QR code")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// ScanBatch handles POST /api/v1/qr/scan/batch
func (h *QRSecurityHandler) ScanBatch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Items []models.QRScanRequest `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Items) == 0 {
		h.respondError(w, http.StatusBadRequest, "items is required")
		return
	}

	if len(req.Items) > 50 {
		h.respondError(w, http.StatusBadRequest, "maximum 50 items allowed")
		return
	}

	results := make([]*models.QRScanResult, 0, len(req.Items))
	for _, item := range req.Items {
		result, err := h.service.AnalyzeQRCode(r.Context(), &item)
		if err != nil {
			h.logger.Warn().Err(err).Str("content", item.Content[:min(50, len(item.Content))]).Msg("failed to analyze QR code in batch")
			continue
		}
		results = append(results, result)
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"results":   results,
		"processed": len(results),
		"total":     len(req.Items),
	})
}

// CheckURL handles POST /api/v1/qr/check-url
func (h *QRSecurityHandler) CheckURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL      string `json:"url"`
		DeviceID string `json:"device_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URL == "" {
		h.respondError(w, http.StatusBadRequest, "url is required")
		return
	}

	// Create a QR scan request with the URL
	scanReq := &models.QRScanRequest{
		Content:  req.URL,
		DeviceID: req.DeviceID,
	}

	result, err := h.service.AnalyzeQRCode(r.Context(), scanReq)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to check URL")
		h.respondError(w, http.StatusInternalServerError, "failed to check URL")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// Preview handles POST /api/v1/qr/preview
func (h *QRSecurityHandler) Preview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Content == "" {
		h.respondError(w, http.StatusBadRequest, "content is required")
		return
	}

	// Analyze the QR code
	scanReq := &models.QRScanRequest{Content: req.Content}
	result, err := h.service.AnalyzeQRCode(r.Context(), scanReq)
	if err != nil {
		h.respondError(w, http.StatusInternalServerError, "failed to preview QR code")
		return
	}

	// Return a preview-focused response
	preview := map[string]interface{}{
		"content_type": result.ContentType,
		"is_safe":      result.IsSafe,
		"should_block": result.ShouldBlock,
		"threat_level": result.ThreatLevel,
		"warnings":     result.Warnings,
	}

	// Add content-specific preview info
	if result.ParsedContent != nil {
		switch result.ContentType {
		case models.QRContentURL:
			if result.ParsedContent.URL != nil {
				preview["url"] = map[string]interface{}{
					"host":   result.ParsedContent.URL.Host,
					"scheme": result.ParsedContent.URL.Scheme,
					"path":   result.ParsedContent.URL.Path,
				}
			}
		case models.QRContentWiFi:
			if result.ParsedContent.WiFi != nil {
				preview["wifi"] = map[string]interface{}{
					"ssid":     result.ParsedContent.WiFi.SSID,
					"security": result.ParsedContent.WiFi.Security,
					"is_open":  result.ParsedContent.WiFi.IsOpenNetwork,
				}
			}
		case models.QRContentEmail:
			if result.ParsedContent.Email != nil {
				preview["email"] = map[string]interface{}{
					"address": result.ParsedContent.Email.Address,
					"subject": result.ParsedContent.Email.Subject,
				}
			}
		case models.QRContentPhone:
			if result.ParsedContent.Phone != nil {
				preview["phone"] = map[string]interface{}{
					"number":     result.ParsedContent.Phone.Number,
					"is_premium": result.ParsedContent.Phone.IsPremium,
				}
			}
		case models.QRContentCrypto:
			if result.ParsedContent.Crypto != nil {
				preview["crypto"] = map[string]interface{}{
					"currency":      result.ParsedContent.Crypto.Currency,
					"address":       result.ParsedContent.Crypto.Address[:min(20, len(result.ParsedContent.Crypto.Address))] + "...",
					"amount":        result.ParsedContent.Crypto.Amount,
					"valid_address": result.ParsedContent.Crypto.IsValidAddress,
				}
			}
		}
	}

	h.respondJSON(w, http.StatusOK, preview)
}

// GetContentTypes handles GET /api/v1/qr/content-types
func (h *QRSecurityHandler) GetContentTypes(w http.ResponseWriter, r *http.Request) {
	types := h.service.GetContentTypes()

	typeInfo := make([]map[string]string, 0, len(types))
	descriptions := map[models.QRContentType]string{
		models.QRContentURL:     "Web URL (http/https)",
		models.QRContentText:    "Plain text content",
		models.QRContentEmail:   "Email address (mailto:)",
		models.QRContentPhone:   "Phone number (tel:)",
		models.QRContentSMS:     "SMS message (sms:)",
		models.QRContentWiFi:    "WiFi credentials",
		models.QRContentVCard:   "Contact card (vCard)",
		models.QRContentGeo:     "Geographic location",
		models.QRContentEvent:   "Calendar event",
		models.QRContentCrypto:  "Cryptocurrency address",
		models.QRContentAppLink: "App deep link",
	}

	for _, t := range types {
		typeInfo = append(typeInfo, map[string]string{
			"type":        string(t),
			"description": descriptions[t],
		})
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"content_types": typeInfo,
		"count":         len(typeInfo),
	})
}

// GetThreatTypes handles GET /api/v1/qr/threat-types
func (h *QRSecurityHandler) GetThreatTypes(w http.ResponseWriter, r *http.Request) {
	types := h.service.GetThreatTypes()

	typeInfo := make([]map[string]string, 0, len(types))
	descriptions := map[models.QRThreatType]string{
		models.QRThreatPhishing:          "Phishing attempt to steal credentials",
		models.QRThreatMalware:           "Links to malware download",
		models.QRThreatScam:              "Financial scam or fraud",
		models.QRThreatCryptoScam:        "Cryptocurrency scam or invalid address",
		models.QRThreatFakeLogin:         "Fake login page",
		models.QRThreatDataHarvesting:    "Attempts to harvest personal data",
		models.QRThreatMaliciousRedirect: "Redirects to malicious site",
		models.QRThreatSuspiciousWiFi:    "Insecure or suspicious WiFi network",
		models.QRThreatTyposquatting:     "Domain mimicking legitimate brand",
		models.QRThreatURLShortener:      "URL shortener hiding destination",
		models.QRThreatSuspiciousTLD:     "Uses suspicious top-level domain",
		models.QRThreatIPAddress:         "Uses IP address instead of domain",
		models.QRThreatEncodedURL:        "Obfuscated or encoded URL",
	}

	for _, t := range types {
		typeInfo = append(typeInfo, map[string]string{
			"type":        string(t),
			"description": descriptions[t],
		})
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"threat_types": typeInfo,
		"count":        len(typeInfo),
	})
}

// GetSuspiciousTLDs handles GET /api/v1/qr/suspicious-tlds
func (h *QRSecurityHandler) GetSuspiciousTLDs(w http.ResponseWriter, r *http.Request) {
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"tlds":  models.SuspiciousTLDs,
		"count": len(models.SuspiciousTLDs),
		"description": "Top-level domains commonly associated with malicious sites",
	})
}

// GetURLShorteners handles GET /api/v1/qr/url-shorteners
func (h *QRSecurityHandler) GetURLShorteners(w http.ResponseWriter, r *http.Request) {
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"shorteners":  models.KnownURLShorteners,
		"count":       len(models.KnownURLShorteners),
		"description": "URL shortening services that may hide malicious URLs",
	})
}

// GetStats handles GET /api/v1/qr/stats
func (h *QRSecurityHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.service.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

func (h *QRSecurityHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *QRSecurityHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
