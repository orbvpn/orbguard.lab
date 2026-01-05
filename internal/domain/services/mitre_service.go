package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// MITREService provides MITRE ATT&CK functionality
type MITREService struct {
	cache    *cache.RedisCache
	logger   *logger.Logger
	dataDir  string

	// In-memory data store
	mu            sync.RWMutex
	tactics       map[string]*models.MITRETactic
	techniques    map[string]*models.MITRETechnique
	mitigations   map[string]*models.MITREMitigation
	groups        map[string]*models.MITREGroup
	software      map[string]*models.MITRESoftware
	dataSources   map[string]*models.MITREDataSource
	relationships []models.MITRERelationship

	// Indexes for fast lookup
	tacticsByShortName   map[string]*models.MITRETactic
	techniquesByTactic   map[string][]*models.MITRETechnique
	techniquesByPlatform map[string][]*models.MITRETechnique

	// Version info
	enterpriseVersion string
	mobileVersion     string
	lastLoaded        time.Time
}

// STIXBundle represents the STIX 2.0 bundle format from ATT&CK
type STIXBundle struct {
	Type        string            `json:"type"`
	ID          string            `json:"id"`
	SpecVersion string            `json:"spec_version"`
	Objects     []json.RawMessage `json:"objects"`
}

// STIXObject represents a generic STIX object for type detection
type STIXObject struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Created    string   `json:"created"`
	Modified   string   `json:"modified"`
	Revoked    bool     `json:"revoked"`
	Deprecated bool     `json:"x_mitre_deprecated"`
}

// NewMITREService creates a new MITRE ATT&CK service
func NewMITREService(dataDir string, c *cache.RedisCache, log *logger.Logger) *MITREService {
	svc := &MITREService{
		cache:                c,
		logger:               log.WithComponent("mitre-service"),
		dataDir:              dataDir,
		tactics:              make(map[string]*models.MITRETactic),
		techniques:           make(map[string]*models.MITRETechnique),
		mitigations:          make(map[string]*models.MITREMitigation),
		groups:               make(map[string]*models.MITREGroup),
		software:             make(map[string]*models.MITRESoftware),
		dataSources:          make(map[string]*models.MITREDataSource),
		tacticsByShortName:   make(map[string]*models.MITRETactic),
		techniquesByTactic:   make(map[string][]*models.MITRETechnique),
		techniquesByPlatform: make(map[string][]*models.MITRETechnique),
	}

	// Load embedded data on startup
	if err := svc.LoadEmbeddedData(); err != nil {
		log.Warn().Err(err).Msg("failed to load embedded MITRE data")
	}

	return svc
}

// LoadEmbeddedData loads the embedded MITRE ATT&CK data
func (s *MITREService) LoadEmbeddedData() error {
	s.logger.Info().Msg("loading embedded MITRE ATT&CK data")

	// Load mobile-specific tactics and techniques (embedded)
	s.loadMobileTactics()
	s.loadMobileTechniques()

	s.lastLoaded = time.Now()
	s.logger.Info().
		Int("tactics", len(s.tactics)).
		Int("techniques", len(s.techniques)).
		Msg("embedded MITRE data loaded")

	return nil
}

// LoadFromFiles loads ATT&CK data from JSON files
func (s *MITREService) LoadFromFiles(enterpriseFile, mobileFile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info().Msg("loading MITRE ATT&CK data from files")

	// Load enterprise ATT&CK
	if enterpriseFile != "" {
		if err := s.loadSTIXFile(enterpriseFile, models.MITREDomainEnterprise); err != nil {
			s.logger.Warn().Err(err).Str("file", enterpriseFile).Msg("failed to load enterprise ATT&CK")
		}
	}

	// Load mobile ATT&CK
	if mobileFile != "" {
		if err := s.loadSTIXFile(mobileFile, models.MITREDomainMobile); err != nil {
			s.logger.Warn().Err(err).Str("file", mobileFile).Msg("failed to load mobile ATT&CK")
		}
	}

	// Build indexes
	s.buildIndexes()

	s.lastLoaded = time.Now()
	s.logger.Info().
		Int("tactics", len(s.tactics)).
		Int("techniques", len(s.techniques)).
		Int("mitigations", len(s.mitigations)).
		Int("groups", len(s.groups)).
		Msg("MITRE ATT&CK data loaded from files")

	return nil
}

// loadSTIXFile loads a STIX bundle JSON file
func (s *MITREService) loadSTIXFile(filePath string, domain models.MITREDomain) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("failed to parse STIX bundle: %w", err)
	}

	for _, objData := range bundle.Objects {
		var obj STIXObject
		if err := json.Unmarshal(objData, &obj); err != nil {
			continue
		}

		switch obj.Type {
		case "x-mitre-tactic":
			s.parseTactic(objData, domain)
		case "attack-pattern":
			s.parseTechnique(objData, domain)
		case "course-of-action":
			s.parseMitigation(objData, domain)
		case "intrusion-set":
			s.parseGroup(objData, domain)
		case "malware", "tool":
			s.parseSoftware(objData, domain)
		case "relationship":
			s.parseRelationship(objData)
		}
	}

	return nil
}

// parseTactic parses a tactic from STIX
func (s *MITREService) parseTactic(data json.RawMessage, domain models.MITREDomain) {
	var raw struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		ShortName   string `json:"x_mitre_shortname"`
		ExternalRefs []struct {
			SourceName string `json:"source_name"`
			ExternalID string `json:"external_id"`
			URL        string `json:"url"`
		} `json:"external_references"`
		Created  string `json:"created"`
		Modified string `json:"modified"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	var tacticID, url string
	for _, ref := range raw.ExternalRefs {
		if ref.SourceName == "mitre-attack" {
			tacticID = ref.ExternalID
			url = ref.URL
			break
		}
	}

	if tacticID == "" {
		return
	}

	created, _ := time.Parse(time.RFC3339, raw.Created)
	modified, _ := time.Parse(time.RFC3339, raw.Modified)

	tactic := &models.MITRETactic{
		ID:          tacticID,
		STIXID:      raw.ID,
		Name:        raw.Name,
		Description: raw.Description,
		ShortName:   raw.ShortName,
		Domain:      domain,
		URL:         url,
		Created:     created,
		Modified:    modified,
	}

	s.tactics[tacticID] = tactic
	s.tacticsByShortName[raw.ShortName] = tactic
}

// parseTechnique parses a technique from STIX
func (s *MITREService) parseTechnique(data json.RawMessage, domain models.MITREDomain) {
	var raw struct {
		Type        string `json:"type"`
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		KillChainPhases []struct {
			PhaseName string `json:"phase_name"`
		} `json:"kill_chain_phases"`
		Platforms          []string `json:"x_mitre_platforms"`
		IsSubtechnique     bool     `json:"x_mitre_is_subtechnique"`
		PermissionsRequired []string `json:"x_mitre_permissions_required"`
		DataSources        []string `json:"x_mitre_data_sources"`
		DefenseBypassed    []string `json:"x_mitre_defense_bypassed"`
		Detection          string   `json:"x_mitre_detection"`
		Deprecated         bool     `json:"x_mitre_deprecated"`
		Revoked            bool     `json:"revoked"`
		ExternalRefs []struct {
			SourceName string `json:"source_name"`
			ExternalID string `json:"external_id"`
			URL        string `json:"url"`
		} `json:"external_references"`
		Created  string `json:"created"`
		Modified string `json:"modified"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	var techniqueID, url string
	for _, ref := range raw.ExternalRefs {
		if ref.SourceName == "mitre-attack" {
			techniqueID = ref.ExternalID
			url = ref.URL
			break
		}
	}

	if techniqueID == "" {
		return
	}

	created, _ := time.Parse(time.RFC3339, raw.Created)
	modified, _ := time.Parse(time.RFC3339, raw.Modified)

	// Extract tactic names
	var tactics []string
	for _, kcp := range raw.KillChainPhases {
		tactics = append(tactics, kcp.PhaseName)
	}

	// Determine parent ID for sub-techniques
	var parentID string
	if raw.IsSubtechnique && strings.Contains(techniqueID, ".") {
		parts := strings.Split(techniqueID, ".")
		parentID = parts[0]
	}

	technique := &models.MITRETechnique{
		ID:                  techniqueID,
		STIXID:              raw.ID,
		Name:                raw.Name,
		Description:         raw.Description,
		IsSubTechnique:      raw.IsSubtechnique,
		ParentID:            parentID,
		Tactics:             tactics,
		Platforms:           raw.Platforms,
		Domain:              domain,
		PermissionsRequired: raw.PermissionsRequired,
		DataSources:         raw.DataSources,
		DefenseBypassed:     raw.DefenseBypassed,
		Detection:           raw.Detection,
		URL:                 url,
		Deprecated:          raw.Deprecated,
		Revoked:             raw.Revoked,
		Created:             created,
		Modified:            modified,
	}

	s.techniques[techniqueID] = technique
}

// parseMitigation parses a mitigation from STIX
func (s *MITREService) parseMitigation(data json.RawMessage, domain models.MITREDomain) {
	var raw struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Deprecated  bool   `json:"x_mitre_deprecated"`
		ExternalRefs []struct {
			SourceName string `json:"source_name"`
			ExternalID string `json:"external_id"`
			URL        string `json:"url"`
		} `json:"external_references"`
		Created  string `json:"created"`
		Modified string `json:"modified"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	var mitigationID, url string
	for _, ref := range raw.ExternalRefs {
		if ref.SourceName == "mitre-attack" {
			mitigationID = ref.ExternalID
			url = ref.URL
			break
		}
	}

	if mitigationID == "" {
		return
	}

	created, _ := time.Parse(time.RFC3339, raw.Created)
	modified, _ := time.Parse(time.RFC3339, raw.Modified)

	mitigation := &models.MITREMitigation{
		ID:          mitigationID,
		STIXID:      raw.ID,
		Name:        raw.Name,
		Description: raw.Description,
		Domain:      domain,
		URL:         url,
		Deprecated:  raw.Deprecated,
		Created:     created,
		Modified:    modified,
	}

	s.mitigations[mitigationID] = mitigation
}

// parseGroup parses a threat group from STIX
func (s *MITREService) parseGroup(data json.RawMessage, domain models.MITREDomain) {
	var raw struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Aliases     []string `json:"aliases"`
		Deprecated  bool     `json:"x_mitre_deprecated"`
		ExternalRefs []struct {
			SourceName string `json:"source_name"`
			ExternalID string `json:"external_id"`
			URL        string `json:"url"`
		} `json:"external_references"`
		Created  string `json:"created"`
		Modified string `json:"modified"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	var groupID, url string
	for _, ref := range raw.ExternalRefs {
		if ref.SourceName == "mitre-attack" {
			groupID = ref.ExternalID
			url = ref.URL
			break
		}
	}

	if groupID == "" {
		return
	}

	created, _ := time.Parse(time.RFC3339, raw.Created)
	modified, _ := time.Parse(time.RFC3339, raw.Modified)

	group := &models.MITREGroup{
		ID:          groupID,
		STIXID:      raw.ID,
		Name:        raw.Name,
		Description: raw.Description,
		Aliases:     raw.Aliases,
		Domain:      domain,
		URL:         url,
		Deprecated:  raw.Deprecated,
		Created:     created,
		Modified:    modified,
	}

	s.groups[groupID] = group
}

// parseSoftware parses malware/tool from STIX
func (s *MITREService) parseSoftware(data json.RawMessage, domain models.MITREDomain) {
	var raw struct {
		Type        string   `json:"type"`
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Aliases     []string `json:"x_mitre_aliases"`
		Platforms   []string `json:"x_mitre_platforms"`
		Deprecated  bool     `json:"x_mitre_deprecated"`
		ExternalRefs []struct {
			SourceName string `json:"source_name"`
			ExternalID string `json:"external_id"`
			URL        string `json:"url"`
		} `json:"external_references"`
		Created  string `json:"created"`
		Modified string `json:"modified"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	var softwareID, url string
	for _, ref := range raw.ExternalRefs {
		if ref.SourceName == "mitre-attack" {
			softwareID = ref.ExternalID
			url = ref.URL
			break
		}
	}

	if softwareID == "" {
		return
	}

	created, _ := time.Parse(time.RFC3339, raw.Created)
	modified, _ := time.Parse(time.RFC3339, raw.Modified)

	sw := &models.MITRESoftware{
		ID:          softwareID,
		STIXID:      raw.ID,
		Name:        raw.Name,
		Description: raw.Description,
		Type:        raw.Type,
		Aliases:     raw.Aliases,
		Platforms:   raw.Platforms,
		Domain:      domain,
		URL:         url,
		Deprecated:  raw.Deprecated,
		Created:     created,
		Modified:    modified,
	}

	s.software[softwareID] = sw
}

// parseRelationship parses a relationship from STIX
func (s *MITREService) parseRelationship(data json.RawMessage) {
	var raw struct {
		ID               string `json:"id"`
		SourceRef        string `json:"source_ref"`
		TargetRef        string `json:"target_ref"`
		RelationshipType string `json:"relationship_type"`
		Description      string `json:"description"`
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}

	rel := models.MITRERelationship{
		ID:               raw.ID,
		SourceRef:        raw.SourceRef,
		TargetRef:        raw.TargetRef,
		RelationshipType: raw.RelationshipType,
		Description:      raw.Description,
	}

	s.relationships = append(s.relationships, rel)
}

// buildIndexes builds lookup indexes
func (s *MITREService) buildIndexes() {
	s.techniquesByTactic = make(map[string][]*models.MITRETechnique)
	s.techniquesByPlatform = make(map[string][]*models.MITRETechnique)

	for _, tech := range s.techniques {
		// Index by tactic
		for _, tactic := range tech.Tactics {
			s.techniquesByTactic[tactic] = append(s.techniquesByTactic[tactic], tech)
		}

		// Index by platform
		for _, platform := range tech.Platforms {
			s.techniquesByPlatform[platform] = append(s.techniquesByPlatform[platform], tech)
		}
	}

	// Count techniques per tactic
	for tacticID, tactic := range s.tactics {
		if techs, ok := s.techniquesByTactic[tactic.ShortName]; ok {
			s.tactics[tacticID].TechniqueCount = len(techs)
		}
	}
}

// loadMobileTactics loads embedded mobile-specific tactics
func (s *MITREService) loadMobileTactics() {
	mobileTactics := []models.MITRETactic{
		{ID: "TA0027", Name: "Initial Access", ShortName: "initial-access", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0027"},
		{ID: "TA0041", Name: "Execution", ShortName: "execution", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0041"},
		{ID: "TA0028", Name: "Persistence", ShortName: "persistence", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0028"},
		{ID: "TA0029", Name: "Privilege Escalation", ShortName: "privilege-escalation", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0029"},
		{ID: "TA0030", Name: "Defense Evasion", ShortName: "defense-evasion", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0030"},
		{ID: "TA0031", Name: "Credential Access", ShortName: "credential-access", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0031"},
		{ID: "TA0032", Name: "Discovery", ShortName: "discovery", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0032"},
		{ID: "TA0033", Name: "Lateral Movement", ShortName: "lateral-movement", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0033"},
		{ID: "TA0035", Name: "Collection", ShortName: "collection", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0035"},
		{ID: "TA0037", Name: "Command and Control", ShortName: "command-and-control", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0037"},
		{ID: "TA0036", Name: "Exfiltration", ShortName: "exfiltration", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0036"},
		{ID: "TA0034", Name: "Impact", ShortName: "impact", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0034"},
		{ID: "TA0038", Name: "Network Effects", ShortName: "network-effects", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0038"},
		{ID: "TA0039", Name: "Remote Service Effects", ShortName: "remote-service-effects", Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/tactics/TA0039"},
	}

	for i := range mobileTactics {
		s.tactics[mobileTactics[i].ID] = &mobileTactics[i]
		s.tacticsByShortName[mobileTactics[i].ShortName] = &mobileTactics[i]
	}
}

// loadMobileTechniques loads embedded mobile-specific techniques
func (s *MITREService) loadMobileTechniques() {
	// Key mobile techniques for spyware/stalkerware detection
	mobileTechniques := []models.MITRETechnique{
		// Initial Access
		{ID: "T1660", Name: "Phishing", Tactics: []string{"initial-access"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1660"},
		{ID: "T1456", Name: "Drive-by Compromise", Tactics: []string{"initial-access"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1456"},
		{ID: "T1664", Name: "Exploitation for Initial Access", Tactics: []string{"initial-access"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1664"},
		{ID: "T1461", Name: "Lockscreen Bypass", Tactics: []string{"initial-access"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1461"},
		{ID: "T1474", Name: "Supply Chain Compromise", Tactics: []string{"initial-access"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1474"},

		// Persistence
		{ID: "T1398", Name: "Boot or Logon Initialization Scripts", Tactics: []string{"persistence"}, Platforms: []string{"Android"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1398"},
		{ID: "T1624", Name: "Event Triggered Execution", Tactics: []string{"persistence"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1624"},

		// Privilege Escalation
		{ID: "T1404", Name: "Exploitation for Privilege Escalation", Tactics: []string{"privilege-escalation"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1404"},
		{ID: "T1626", Name: "Abuse Elevation Control Mechanism", Tactics: []string{"privilege-escalation", "defense-evasion"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1626"},

		// Defense Evasion
		{ID: "T1406", Name: "Obfuscated Files or Information", Tactics: []string{"defense-evasion"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1406"},
		{ID: "T1628", Name: "Hide Artifacts", Tactics: []string{"defense-evasion"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1628"},
		{ID: "T1407", Name: "Download New Code at Runtime", Tactics: []string{"defense-evasion"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1407"},
		{ID: "T1630", Name: "Indicator Removal on Host", Tactics: []string{"defense-evasion"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1630"},
		{ID: "T1629", Name: "Impair Defenses", Tactics: []string{"defense-evasion"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1629"},

		// Credential Access
		{ID: "T1417", Name: "Input Capture", Tactics: []string{"credential-access", "collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1417"},
		{ID: "T1634", Name: "Credentials from Password Store", Tactics: []string{"credential-access"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1634"},

		// Discovery
		{ID: "T1418", Name: "Software Discovery", Tactics: []string{"discovery"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1418"},
		{ID: "T1420", Name: "File and Directory Discovery", Tactics: []string{"discovery"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1420"},
		{ID: "T1422", Name: "System Network Configuration Discovery", Tactics: []string{"discovery"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1422"},
		{ID: "T1426", Name: "System Information Discovery", Tactics: []string{"discovery"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1426"},

		// Collection - KEY FOR SPYWARE/STALKERWARE
		{ID: "T1429", Name: "Audio Capture", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1429"},
		{ID: "T1512", Name: "Video Capture", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1512"},
		{ID: "T1513", Name: "Screen Capture", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1513"},
		{ID: "T1430", Name: "Location Tracking", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1430"},
		{ID: "T1414", Name: "Clipboard Data", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1414"},
		{ID: "T1533", Name: "Data from Local System", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1533"},
		{ID: "T1636", Name: "Protected User Data", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1636"},
		{ID: "T1636.001", Name: "Protected User Data: Calendar Entries", IsSubTechnique: true, ParentID: "T1636", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1636/001"},
		{ID: "T1636.002", Name: "Protected User Data: Call Log", IsSubTechnique: true, ParentID: "T1636", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1636/002"},
		{ID: "T1636.003", Name: "Protected User Data: Contact List", IsSubTechnique: true, ParentID: "T1636", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1636/003"},
		{ID: "T1636.004", Name: "Protected User Data: SMS Messages", IsSubTechnique: true, ParentID: "T1636", Tactics: []string{"collection"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1636/004"},

		// Command and Control
		{ID: "T1437", Name: "Application Layer Protocol", Tactics: []string{"command-and-control"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1437"},
		{ID: "T1481", Name: "Web Service", Tactics: []string{"command-and-control"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1481"},
		{ID: "T1509", Name: "Non-Standard Port", Tactics: []string{"command-and-control"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1509"},
		{ID: "T1521", Name: "Encrypted Channel", Tactics: []string{"command-and-control"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1521"},

		// Exfiltration
		{ID: "T1639", Name: "Exfiltration Over Alternative Protocol", Tactics: []string{"exfiltration"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1639"},
		{ID: "T1646", Name: "Exfiltration Over C2 Channel", Tactics: []string{"exfiltration"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1646"},

		// Impact
		{ID: "T1447", Name: "Delete Device Data", Tactics: []string{"impact"}, Platforms: []string{"Android", "iOS"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1447"},
		{ID: "T1448", Name: "Carrier Billing Fraud", Tactics: []string{"impact"}, Platforms: []string{"Android"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1448"},
		{ID: "T1582", Name: "SMS Control", Tactics: []string{"impact"}, Platforms: []string{"Android"}, Domain: models.MITREDomainMobile, URL: "https://attack.mitre.org/techniques/T1582"},
	}

	for i := range mobileTechniques {
		s.techniques[mobileTechniques[i].ID] = &mobileTechniques[i]
	}

	s.buildIndexes()
}

// GetTactic gets a tactic by ID
func (s *MITREService) GetTactic(id string) *models.MITRETactic {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tactics[id]
}

// GetTacticByShortName gets a tactic by short name
func (s *MITREService) GetTacticByShortName(shortName string) *models.MITRETactic {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tacticsByShortName[shortName]
}

// ListTactics lists all tactics
func (s *MITREService) ListTactics(domain models.MITREDomain) []*models.MITRETactic {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.MITRETactic
	for _, tactic := range s.tactics {
		if domain == "" || tactic.Domain == domain {
			result = append(result, tactic)
		}
	}

	// Sort by ID
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// GetTechnique gets a technique by ID
func (s *MITREService) GetTechnique(id string) *models.MITRETechnique {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.techniques[id]
}

// ListTechniques lists techniques with optional filtering
func (s *MITREService) ListTechniques(filter *models.MITRETechniqueFilter) []*models.MITRETechnique {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.MITRETechnique

	for _, tech := range s.techniques {
		// Apply filters
		if filter != nil {
			// Filter by domain
			if filter.Domain != "" && tech.Domain != filter.Domain {
				continue
			}

			// Filter by tactic
			if filter.TacticID != "" {
				found := false
				for _, t := range tech.Tactics {
					if t == filter.TacticID {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			// Filter by platform
			if filter.Platform != "" {
				found := false
				for _, p := range tech.Platforms {
					if strings.EqualFold(p, filter.Platform) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			// Filter by sub-technique
			if filter.IsSubTechnique != nil && tech.IsSubTechnique != *filter.IsSubTechnique {
				continue
			}

			// Exclude revoked
			if !filter.IncludeRevoked && tech.Revoked {
				continue
			}

			// Search query
			if filter.Query != "" {
				query := strings.ToLower(filter.Query)
				if !strings.Contains(strings.ToLower(tech.Name), query) &&
					!strings.Contains(strings.ToLower(tech.ID), query) &&
					!strings.Contains(strings.ToLower(tech.Description), query) {
					continue
				}
			}
		}

		result = append(result, tech)
	}

	// Sort by ID
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	// Apply pagination
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(result) {
			result = result[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(result) {
			result = result[:filter.Limit]
		}
	}

	return result
}

// GetTechniquesByTactic gets techniques for a tactic
func (s *MITREService) GetTechniquesByTactic(tacticShortName string) []*models.MITRETechnique {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.techniquesByTactic[tacticShortName]
}

// GetTechniquesByPlatform gets techniques for a platform
func (s *MITREService) GetTechniquesByPlatform(platform string) []*models.MITRETechnique {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.techniquesByPlatform[platform]
}

// SearchTechniques searches across all technique fields
func (s *MITREService) SearchTechniques(query string) []*models.MITRETechnique {
	return s.ListTechniques(&models.MITRETechniqueFilter{Query: query})
}

// GetMitigation gets a mitigation by ID
func (s *MITREService) GetMitigation(id string) *models.MITREMitigation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mitigations[id]
}

// ListMitigations lists all mitigations
func (s *MITREService) ListMitigations() []*models.MITREMitigation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.MITREMitigation
	for _, m := range s.mitigations {
		result = append(result, m)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// GetGroup gets a threat group by ID
func (s *MITREService) GetGroup(id string) *models.MITREGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.groups[id]
}

// ListGroups lists all threat groups
func (s *MITREService) ListGroups() []*models.MITREGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.MITREGroup
	for _, g := range s.groups {
		result = append(result, g)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// GetSoftware gets software by ID
func (s *MITREService) GetSoftware(id string) *models.MITRESoftware {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.software[id]
}

// ListSoftware lists all software
func (s *MITREService) ListSoftware() []*models.MITRESoftware {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.MITRESoftware
	for _, sw := range s.software {
		result = append(result, sw)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ID < result[j].ID
	})

	return result
}

// AutoMapIndicator auto-maps an indicator to MITRE techniques based on keywords/patterns
func (s *MITREService) AutoMapIndicator(ctx context.Context, indicator *models.Indicator) []models.MITREMapping {
	var mappings []models.MITREMapping

	// Combine value, tags, and description for analysis
	text := strings.ToLower(indicator.Value)
	for _, tag := range indicator.Tags {
		text += " " + strings.ToLower(tag)
	}

	// Check for explicit MITRE technique IDs in tags
	techniquePattern := regexp.MustCompile(`[Tt](1\d{3})(?:\.\d{3})?`)
	matches := techniquePattern.FindAllString(text, -1)
	for _, match := range matches {
		techID := strings.ToUpper(match)
		if s.GetTechnique(techID) != nil {
			mappings = append(mappings, models.MITREMapping{
				ID:          uuid.New(),
				IndicatorID: indicator.ID,
				TechniqueID: techID,
				Confidence:  0.9, // High confidence for explicit mentions
				MappingType: "auto",
				Source:      "tag-extraction",
				CreatedAt:   time.Now(),
			})
		}
	}

	// Keyword-based mapping
	for keyword, techniques := range models.TechniqueKeywordMap {
		if strings.Contains(text, keyword) {
			for _, techID := range techniques {
				// Avoid duplicates
				duplicate := false
				for _, m := range mappings {
					if m.TechniqueID == techID {
						duplicate = true
						break
					}
				}
				if !duplicate {
					mappings = append(mappings, models.MITREMapping{
						ID:          uuid.New(),
						IndicatorID: indicator.ID,
						TechniqueID: techID,
						Confidence:  0.7, // Medium confidence for keyword matches
						MappingType: "auto",
						Source:      "keyword:" + keyword,
						CreatedAt:   time.Now(),
					})
				}
			}
		}
	}

	return mappings
}

// AutoMapIndicators auto-maps multiple indicators
func (s *MITREService) AutoMapIndicators(ctx context.Context, indicators []*models.Indicator) *models.MITREAutoMapResult {
	startTime := time.Now()

	result := &models.MITREAutoMapResult{
		TotalIndicators: len(indicators),
	}

	for _, ind := range indicators {
		mappings := s.AutoMapIndicator(ctx, ind)
		if len(mappings) > 0 {
			result.MappedCount++
			for _, m := range mappings {
				mapping := models.MITREIndicatorMapping{
					MITREMapping: m,
					Technique:    s.GetTechnique(m.TechniqueID),
				}
				result.Mappings = append(result.Mappings, mapping)
			}
		} else {
			result.SkippedCount++
		}
	}

	result.ProcessingTime = time.Since(startTime)
	return result
}

// GenerateNavigatorLayer generates an ATT&CK Navigator layer
func (s *MITREService) GenerateNavigatorLayer(name, description string, techniques []string, domain models.MITREDomain) *models.NavigatorLayer {
	// Count technique occurrences
	techCounts := make(map[string]int)
	for _, techID := range techniques {
		techCounts[techID]++
	}

	// Find max count for scoring
	maxCount := 1
	for _, count := range techCounts {
		if count > maxCount {
			maxCount = count
		}
	}

	// Build technique scores
	var techScores []models.NavigatorTechniqueScore
	for techID, count := range techCounts {
		score := (count * 100) / maxCount
		color := s.getScoreColor(score)

		techScores = append(techScores, models.NavigatorTechniqueScore{
			TechniqueID: techID,
			Score:       score,
			Color:       color,
			Enabled:     true,
			Comment:     fmt.Sprintf("Count: %d", count),
		})
	}

	domainStr := string(domain)
	if domainStr == "" {
		domainStr = "mobile-attack"
	}

	layer := &models.NavigatorLayer{
		Name:        name,
		Version:     "4.5",
		Domain:      domainStr,
		Description: description,
		Filters: models.NavigatorFilters{
			Platforms: []string{"Android", "iOS"},
		},
		Sorting:     3,
		HideDisabled: false,
		Techniques:  techScores,
		Gradient: models.NavigatorGradient{
			Colors:   []string{"#ffffff", "#ff6666"},
			MinValue: 0,
			MaxValue: 100,
		},
		Layout: models.NavigatorLayout{
			Layout:                "side",
			ShowID:                true,
			ShowName:              true,
			ShowAggregateScores:   true,
			CountUnscored:         false,
			AggregateFunction:     "average",
			ExpandedSubtechniques: "all",
		},
		ShowTacticRowBackground:       true,
		TacticRowBackground:           "#dddddd",
		SelectTechniquesAcrossTactics: true,
		SelectSubtechniquesWithParent: true,
	}

	return layer
}

// getScoreColor returns a color based on score
func (s *MITREService) getScoreColor(score int) string {
	switch {
	case score >= 80:
		return "#ff0000" // Red
	case score >= 60:
		return "#ff6600" // Orange
	case score >= 40:
		return "#ffcc00" // Yellow
	case score >= 20:
		return "#99cc00" // Light green
	default:
		return "#66ff66" // Green
	}
}

// GetStats returns MITRE service statistics
func (s *MITREService) GetStats() *models.MITREStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Count sub-techniques
	subTechCount := 0
	for _, tech := range s.techniques {
		if tech.IsSubTechnique {
			subTechCount++
		}
	}

	// Count techniques by tactic
	techByTactic := make(map[string]int)
	for tactic, techs := range s.techniquesByTactic {
		techByTactic[tactic] = len(techs)
	}

	// Count techniques by platform
	techByPlatform := make(map[string]int)
	for platform, techs := range s.techniquesByPlatform {
		techByPlatform[platform] = len(techs)
	}

	return &models.MITREStats{
		TotalTactics:         len(s.tactics),
		TotalTechniques:      len(s.techniques) - subTechCount,
		TotalSubTechniques:   subTechCount,
		TotalMitigations:     len(s.mitigations),
		TotalGroups:          len(s.groups),
		TotalSoftware:        len(s.software),
		TotalDataSources:     len(s.dataSources),
		TotalRelationships:   len(s.relationships),
		TechniquesByTactic:   techByTactic,
		TechniquesByPlatform: techByPlatform,
		EnterpriseVersion:    s.enterpriseVersion,
		MobileVersion:        s.mobileVersion,
		LastLoaded:           s.lastLoaded,
	}
}

// Reload reloads MITRE data from files
func (s *MITREService) Reload(enterpriseFile, mobileFile string) error {
	return s.LoadFromFiles(enterpriseFile, mobileFile)
}
