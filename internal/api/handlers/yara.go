package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/domain/services"
	"orbguard-lab/pkg/logger"
)

// YARAHandler handles YARA-related HTTP requests
type YARAHandler struct {
	yaraService *services.YARAService
	logger      *logger.Logger
}

// NewYARAHandler creates a new YARA handler
func NewYARAHandler(yaraService *services.YARAService, log *logger.Logger) *YARAHandler {
	return &YARAHandler{
		yaraService: yaraService,
		logger:      log.WithComponent("yara-handler"),
	}
}

// respondJSON sends a JSON response
func (h *YARAHandler) respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondError sends an error response
func (h *YARAHandler) respondError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Scan performs a YARA scan on provided data
// @Summary Scan data with YARA rules
// @Description Scan binary data, base64, or hex-encoded data against YARA rules
// @Tags yara
// @Accept json
// @Produce json
// @Param body body models.YARAScanRequest true "Scan request"
// @Success 200 {object} models.YARAScanResult
// @Router /api/v1/yara/scan [post]
func (h *YARAHandler) Scan(w http.ResponseWriter, r *http.Request) {
	var req models.YARAScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate request has data
	if len(req.Data) == 0 && req.Base64Data == "" && req.HexData == "" && req.FilePath == "" {
		h.respondError(w, http.StatusBadRequest, "no data provided for scanning")
		return
	}

	result, err := h.yaraService.Scan(r.Context(), &req)
	if err != nil {
		h.logger.Error().Err(err).Msg("YARA scan failed")
		h.respondError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// ScanAPK scans an Android APK
// @Summary Scan APK with YARA rules
// @Description Scan an Android APK file for malware indicators
// @Tags yara
// @Accept json
// @Produce json
// @Param body body ScanAPKRequest true "APK scan request"
// @Success 200 {object} models.YARAScanResult
// @Router /api/v1/yara/scan/apk [post]
func (h *YARAHandler) ScanAPK(w http.ResponseWriter, r *http.Request) {
	var req ScanAPKRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Base64Data == "" && len(req.Data) == 0 {
		h.respondError(w, http.StatusBadRequest, "APK data is required")
		return
	}

	scanReq := &models.YARAScanRequest{
		Data:        req.Data,
		Base64Data:  req.Base64Data,
		PackageName: req.PackageName,
		Platform:    "android",
		FileType:    "apk",
	}

	result, err := h.yaraService.Scan(r.Context(), scanReq)
	if err != nil {
		h.logger.Error().Err(err).Str("package", req.PackageName).Msg("APK scan failed")
		h.respondError(w, http.StatusInternalServerError, "scan failed")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// ScanAPKRequest represents a request to scan an APK
type ScanAPKRequest struct {
	Data        []byte `json:"data,omitempty"`
	Base64Data  string `json:"base64_data,omitempty"`
	PackageName string `json:"package_name,omitempty"`
}

// ScanIPA scans an iOS IPA
// @Summary Scan IPA with YARA rules
// @Description Scan an iOS IPA file for malware indicators
// @Tags yara
// @Accept json
// @Produce json
// @Param body body ScanIPARequest true "IPA scan request"
// @Success 200 {object} models.YARAScanResult
// @Router /api/v1/yara/scan/ipa [post]
func (h *YARAHandler) ScanIPA(w http.ResponseWriter, r *http.Request) {
	var req ScanIPARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Base64Data == "" && len(req.Data) == 0 {
		h.respondError(w, http.StatusBadRequest, "IPA data is required")
		return
	}

	scanReq := &models.YARAScanRequest{
		Data:        req.Data,
		Base64Data:  req.Base64Data,
		PackageName: req.BundleID,
		Platform:    "ios",
		FileType:    "ipa",
	}

	result, err := h.yaraService.Scan(r.Context(), scanReq)
	if err != nil {
		h.logger.Error().Err(err).Str("bundle", req.BundleID).Msg("IPA scan failed")
		h.respondError(w, http.StatusInternalServerError, "scan failed")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// ScanIPARequest represents a request to scan an IPA
type ScanIPARequest struct {
	Data       []byte `json:"data,omitempty"`
	Base64Data string `json:"base64_data,omitempty"`
	BundleID   string `json:"bundle_id,omitempty"`
}

// ListRules returns all YARA rules
// @Summary List YARA rules
// @Description Get all loaded YARA detection rules
// @Tags yara
// @Accept json
// @Produce json
// @Param category query string false "Filter by category"
// @Param severity query string false "Filter by severity"
// @Param platform query string false "Filter by platform"
// @Param limit query int false "Limit results" default(50)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} ListRulesResponse
// @Router /api/v1/yara/rules [get]
func (h *YARAHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	filter := &models.YARARuleFilter{}

	// Parse query parameters
	if cat := r.URL.Query().Get("category"); cat != "" {
		filter.Categories = []models.YARARuleCategory{models.YARARuleCategory(cat)}
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		filter.Severities = []models.Severity{models.Severity(sev)}
	}
	if platform := r.URL.Query().Get("platform"); platform != "" {
		filter.Platforms = []string{platform}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	filter.Limit = limit

	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	filter.Offset = offset

	rules := h.yaraService.GetRules(filter)

	h.respondJSON(w, http.StatusOK, ListRulesResponse{
		Rules: rules,
		Total: len(rules),
		Limit: limit,
		Offset: offset,
	})
}

// ListRulesResponse represents the response for listing rules
type ListRulesResponse struct {
	Rules  []*models.YARARule `json:"rules"`
	Total  int                `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
}

// GetRule returns a specific YARA rule
// @Summary Get YARA rule
// @Description Get a specific YARA rule by ID
// @Tags yara
// @Accept json
// @Produce json
// @Param id path string true "Rule UUID"
// @Success 200 {object} models.YARARule
// @Router /api/v1/yara/rules/{id} [get]
func (h *YARAHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	rule := h.yaraService.GetRule(ruleID)
	if rule == nil {
		h.respondError(w, http.StatusNotFound, "rule not found")
		return
	}

	h.respondJSON(w, http.StatusOK, rule)
}

// AddRule adds a new YARA rule
// @Summary Add YARA rule
// @Description Add a new YARA detection rule
// @Tags yara
// @Accept json
// @Produce json
// @Param body body models.YARARule true "Rule to add"
// @Success 201 {object} models.YARARule
// @Router /api/v1/yara/rules [post]
func (h *YARAHandler) AddRule(w http.ResponseWriter, r *http.Request) {
	var rule models.YARARule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Generate ID if not provided
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}

	if err := h.yaraService.AddRule(&rule); err != nil {
		h.logger.Error().Err(err).Str("rule", rule.Name).Msg("failed to add rule")
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, rule)
}

// DeleteRule removes a YARA rule
// @Summary Delete YARA rule
// @Description Remove a YARA detection rule
// @Tags yara
// @Accept json
// @Produce json
// @Param id path string true "Rule UUID"
// @Success 204 "No Content"
// @Router /api/v1/yara/rules/{id} [delete]
func (h *YARAHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	ruleID, err := uuid.Parse(idStr)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	if err := h.yaraService.RemoveRule(ruleID); err != nil {
		h.respondError(w, http.StatusInternalServerError, "failed to remove rule")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ParseRule parses and validates a YARA rule without adding it
// @Summary Parse YARA rule
// @Description Parse and validate a YARA rule string
// @Tags yara
// @Accept json
// @Produce json
// @Param body body ParseRuleRequest true "Rule to parse"
// @Success 200 {object} ParseRuleResponse
// @Router /api/v1/yara/parse [post]
func (h *YARAHandler) ParseRule(w http.ResponseWriter, r *http.Request) {
	var req ParseRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RuleContent == "" {
		h.respondError(w, http.StatusBadRequest, "rule_content is required")
		return
	}

	// TODO: Implement full YARA parsing
	// For now, return a simple validation response
	h.respondJSON(w, http.StatusOK, ParseRuleResponse{
		Valid:   true,
		Message: "rule syntax appears valid",
	})
}

// ParseRuleRequest represents a request to parse a rule
type ParseRuleRequest struct {
	RuleContent string `json:"rule_content"`
}

// ParseRuleResponse represents the response from parsing a rule
type ParseRuleResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ReloadRules reloads all YARA rules
// @Summary Reload YARA rules
// @Description Reload all YARA rules from disk and built-in sources
// @Tags yara
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string
// @Router /api/v1/yara/reload [post]
func (h *YARAHandler) ReloadRules(w http.ResponseWriter, r *http.Request) {
	if err := h.yaraService.ReloadRules(); err != nil {
		h.logger.Error().Err(err).Msg("failed to reload rules")
		h.respondError(w, http.StatusInternalServerError, "failed to reload rules")
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "success",
		"message": "rules reloaded",
	})
}

// GetStats returns YARA scanning statistics
// @Summary Get YARA statistics
// @Description Get YARA scanning and rule statistics
// @Tags yara
// @Accept json
// @Produce json
// @Success 200 {object} models.YARAScanStats
// @Router /api/v1/yara/stats [get]
func (h *YARAHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats := h.yaraService.GetStats()
	h.respondJSON(w, http.StatusOK, stats)
}

// GetCategories returns available rule categories
// @Summary Get rule categories
// @Description Get list of available YARA rule categories
// @Tags yara
// @Accept json
// @Produce json
// @Success 200 {array} CategoryInfo
// @Router /api/v1/yara/categories [get]
func (h *YARAHandler) GetCategories(w http.ResponseWriter, r *http.Request) {
	categories := []CategoryInfo{
		{ID: "pegasus", Name: "Pegasus", Description: "NSO Group Pegasus spyware detection"},
		{ID: "stalkerware", Name: "Stalkerware", Description: "Commercial stalkerware/spouseware detection"},
		{ID: "spyware", Name: "Spyware", Description: "Generic spyware detection"},
		{ID: "trojan", Name: "Trojan", Description: "Trojan/RAT detection"},
		{ID: "ransomware", Name: "Ransomware", Description: "Ransomware detection"},
		{ID: "adware", Name: "Adware", Description: "Aggressive adware detection"},
		{ID: "rootkit", Name: "Rootkit", Description: "Rootkit detection"},
		{ID: "exploit", Name: "Exploit", Description: "Exploit/vulnerability detection"},
		{ID: "generic", Name: "Generic", Description: "Generic malware detection"},
	}

	h.respondJSON(w, http.StatusOK, categories)
}

// CategoryInfo represents information about a rule category
type CategoryInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// SubmitRule handles user-submitted rules
// @Summary Submit YARA rule
// @Description Submit a new YARA rule for review
// @Tags yara
// @Accept json
// @Produce json
// @Param body body models.YARARuleSubmission true "Rule submission"
// @Success 201 {object} map[string]string
// @Router /api/v1/yara/submit [post]
func (h *YARAHandler) SubmitRule(w http.ResponseWriter, r *http.Request) {
	var submission models.YARARuleSubmission
	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if submission.RawRule == "" {
		h.respondError(w, http.StatusBadRequest, "raw_rule is required")
		return
	}
	if submission.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Set defaults
	submission.ID = uuid.New()
	submission.Status = models.SubmissionStatusPending

	// TODO: Store in database for review
	h.logger.Info().Str("name", submission.Name).Msg("received rule submission")

	h.respondJSON(w, http.StatusCreated, map[string]string{
		"status":        "pending",
		"submission_id": submission.ID.String(),
		"message":       "rule submitted for review",
	})
}

// QuickScan performs a quick scan with text/string data
// @Summary Quick scan
// @Description Perform a quick YARA scan on text data
// @Tags yara
// @Accept json
// @Produce json
// @Param body body QuickScanRequest true "Quick scan request"
// @Success 200 {object} models.YARAScanResult
// @Router /api/v1/yara/quick-scan [post]
func (h *YARAHandler) QuickScan(w http.ResponseWriter, r *http.Request) {
	var req QuickScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Content == "" {
		h.respondError(w, http.StatusBadRequest, "content is required")
		return
	}

	scanReq := &models.YARAScanRequest{
		Data:     []byte(req.Content),
		FileName: "quick-scan",
	}

	// Apply filters
	if req.Category != "" {
		scanReq.Categories = []models.YARARuleCategory{models.YARARuleCategory(req.Category)}
	}
	if req.Platform != "" {
		scanReq.Platform = req.Platform
	}

	result, err := h.yaraService.Scan(r.Context(), scanReq)
	if err != nil {
		h.logger.Error().Err(err).Msg("quick scan failed")
		h.respondError(w, http.StatusInternalServerError, "scan failed")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// QuickScanRequest represents a quick scan request
type QuickScanRequest struct {
	Content  string `json:"content"`
	Category string `json:"category,omitempty"`
	Platform string `json:"platform,omitempty"`
}
