package ios

import (
	"database/sql"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"orbguard-lab/internal/forensics/models"
	"orbguard-lab/pkg/logger"
)

// DataUsageParser parses iOS DataUsage.sqlite for network anomalies
type DataUsageParser struct {
	logger *logger.Logger
}

// NewDataUsageParser creates a new DataUsage parser
func NewDataUsageParser(log *logger.Logger) *DataUsageParser {
	return &DataUsageParser{
		logger: log.WithComponent("datausage-parser"),
	}
}

// Known suspicious patterns in process/bundle names
var suspiciousProcessPatterns = []struct {
	Pattern *regexp.Regexp
	Reason  string
	Score   float64
}{
	{regexp.MustCompile(`(?i)^[a-f0-9]{8,}$`), "Process name is hexadecimal (potential implant)", 0.8},
	{regexp.MustCompile(`(?i)^[a-z]{1,3}$`), "Very short process name (like 'bh')", 0.7},
	{regexp.MustCompile(`(?i)roleaccount`), "Known Pegasus process", 0.95},
	{regexp.MustCompile(`(?i)pcsd`), "Known Predator process", 0.95},
	{regexp.MustCompile(`(?i)cfprefsd.*\d+`), "Unusual cfprefsd variant", 0.6},
	{regexp.MustCompile(`(?i)implant`), "Implant in name", 0.9},
	{regexp.MustCompile(`(?i)backdoor`), "Backdoor in name", 0.9},
}

// Known legitimate system processes with high network usage
var legitimateHighUsageProcesses = map[string]bool{
	"nsurlsessiond":      true,
	"apsd":               true,
	"cloudd":             true,
	"identityservicesd":  true,
	"imagent":            true,
	"mediaserverd":       true,
	"rapportd":           true,
	"parsecd":            true,
	"mDNSResponder":      true,
	"CommCenter":         true,
	"assistantd":         true,
	"suggestd":           true,
	"mobileassetd":       true,
	"softwareupdated":    true,
	"itunescloudd":       true,
	"mediaanalysisd":     true,
	"Preferences":        true,
	"AppStore":           true,
	"Safari":             true,
	"MobileSafari":       true,
	"Mail":               true,
	"MobileMail":         true,
	"Music":              true,
	"Podcasts":           true,
	"Photos":             true,
}

// Parse analyzes DataUsage.sqlite and returns forensic results
func (p *DataUsageParser) Parse(dbPath string) (*models.ForensicResult, error) {
	result := models.NewForensicResult("", "ios", models.ForensicScanTypeDataUsage)

	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("failed to open DataUsage.sqlite: %w", err)
	}
	defer db.Close()

	p.logger.Info().Str("path", dbPath).Msg("analyzing DataUsage.sqlite")

	timeline := models.NewTimeline()
	entries := make([]models.DataUsageEntry, 0)

	// Query for process network usage
	query := `
		SELECT
			ZPROCNAME as process_name,
			ZBUNDLENAME as bundle_id,
			ZWIFIIN as wifi_in,
			ZWIFIOUT as wifi_out,
			ZWWANIN as cellular_in,
			ZWWANOUT as cellular_out,
			ZFIRSTTIMESTAMP as first_ts,
			ZLASTTIMESTAMP as last_ts
		FROM ZPROCESS
		WHERE (ZWIFIIN + ZWIFIOUT + ZWWANIN + ZWWANOUT) > 0
		ORDER BY (ZWIFIIN + ZWIFIOUT + ZWWANIN + ZWWANOUT) DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		// Try alternative schema (iOS versions vary)
		query = `
			SELECT
				ZPROCNAME,
				ZBUNDLENAME,
				ZWIFIIN,
				ZWIFIOUT,
				ZWWANIN,
				ZWWANOUT,
				ZFIRSTTIMESTAMP,
				ZLASTTIMESTAMP
			FROM ZLIVEUSAGE
			WHERE (ZWIFIIN + ZWIFIOUT + ZWWANIN + ZWWANOUT) > 0
		`
		rows, err = db.Query(query)
		if err != nil {
			return nil, fmt.Errorf("failed to query DataUsage.sqlite: %w", err)
		}
	}
	defer rows.Close()

	for rows.Next() {
		var entry models.DataUsageEntry
		var firstTS, lastTS sql.NullFloat64
		var bundleID, processName sql.NullString

		if err := rows.Scan(
			&processName,
			&bundleID,
			&entry.WiFiIn,
			&entry.WiFiOut,
			&entry.CellularIn,
			&entry.CellularOut,
			&firstTS,
			&lastTS,
		); err != nil {
			continue
		}

		if processName.Valid {
			entry.ProcessName = processName.String
		}
		if bundleID.Valid {
			entry.BundleID = bundleID.String
		}

		// Convert Core Data timestamps (seconds since 2001-01-01)
		coreDataEpoch := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		if firstTS.Valid {
			entry.FirstTimestamp = coreDataEpoch.Add(time.Duration(firstTS.Float64) * time.Second)
		}
		if lastTS.Valid {
			entry.LastTimestamp = coreDataEpoch.Add(time.Duration(lastTS.Float64) * time.Second)
		}

		entry.TotalBytes = entry.WiFiIn + entry.WiFiOut + entry.CellularIn + entry.CellularOut

		entries = append(entries, entry)
	}

	// Analyze entries for anomalies
	for i := range entries {
		entry := &entries[i]

		// Check for suspicious process patterns
		p.analyzeEntry(entry)

		if entry.IsSuspicious {
			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeNetworkAnomaly,
				Severity:    p.getSeverity(entry.SuspiciousScore),
				Confidence:  entry.SuspiciousScore,
				Title:       "Suspicious Network Activity",
				Description: entry.Reason,
				ProcessName: entry.ProcessName,
				Evidence: map[string]any{
					"bundle_id":       entry.BundleID,
					"wifi_in":         entry.WiFiIn,
					"wifi_out":        entry.WiFiOut,
					"cellular_in":     entry.CellularIn,
					"cellular_out":    entry.CellularOut,
					"total_bytes":     entry.TotalBytes,
					"first_timestamp": entry.FirstTimestamp,
					"last_timestamp":  entry.LastTimestamp,
				},
			}

			// Add MITRE techniques for network anomalies
			anomaly.MITRETechniques = []string{
				"T1041",     // Exfiltration Over C2 Channel
				"T1095",     // Non-Application Layer Protocol
				"T1571",     // Non-Standard Port
				"T1573",     // Encrypted Channel
			}

			result.AddAnomaly(anomaly)

			// Add to timeline
			timeline.AddEvent(models.TimelineEvent{
				ID:           uuid.New().String(),
				Timestamp:    entry.FirstTimestamp,
				Type:         models.TimelineEventTypeNetworkConn,
				Source:       "datausage",
				Title:        "Network Activity: " + entry.ProcessName,
				Description:  entry.Reason,
				ProcessName:  entry.ProcessName,
				BundleID:     entry.BundleID,
				IsSuspicious: true,
				Severity:     p.getSeverity(entry.SuspiciousScore),
				AnomalyID:    anomaly.ID,
				Metadata: map[string]any{
					"total_bytes": entry.TotalBytes,
					"duration":    entry.LastTimestamp.Sub(entry.FirstTimestamp).String(),
				},
			})
		}
	}

	// Detect data exfiltration patterns
	p.detectExfiltrationPatterns(entries, result, timeline)

	// Detect threats based on anomalies
	threats := p.detectThreats(result.Anomalies)
	for _, threat := range threats {
		result.AddThreat(threat)
	}

	timeline.Sort()
	result.Timeline = timeline.ToEvents()

	result.RawData["total_processes"] = len(entries)
	result.RawData["suspicious_processes"] = len(result.Anomalies)

	result.Complete()
	return result, nil
}

// analyzeEntry analyzes a single DataUsage entry for anomalies
func (p *DataUsageParser) analyzeEntry(entry *models.DataUsageEntry) {
	score := 0.0
	reasons := make([]string, 0)

	processName := entry.ProcessName
	if processName == "" {
		processName = entry.BundleID
	}

	// Skip known legitimate processes
	if legitimateHighUsageProcesses[processName] {
		return
	}

	// Check for suspicious process patterns
	for _, pattern := range suspiciousProcessPatterns {
		if pattern.Pattern.MatchString(processName) {
			score += pattern.Score
			reasons = append(reasons, pattern.Reason)
		}
	}

	// Check for unknown processes with high data usage
	// Spyware often exfiltrates significant amounts of data
	if entry.TotalBytes > 100*1024*1024 { // More than 100MB
		if !legitimateHighUsageProcesses[processName] {
			score += 0.4
			reasons = append(reasons, fmt.Sprintf("High data usage (%d MB) by unknown process", entry.TotalBytes/(1024*1024)))
		}
	}

	// Check for asymmetric traffic (lots of upload, little download)
	// This is characteristic of data exfiltration
	uploadTotal := entry.WiFiOut + entry.CellularOut
	downloadTotal := entry.WiFiIn + entry.CellularIn
	if uploadTotal > 0 && downloadTotal > 0 {
		ratio := float64(uploadTotal) / float64(downloadTotal)
		if ratio > 10 { // Upload is 10x download
			score += 0.5
			reasons = append(reasons, "Suspicious upload/download ratio (potential data exfiltration)")
		}
	}

	// Check for cellular-only traffic (potential C2 avoiding WiFi monitoring)
	if entry.CellularIn+entry.CellularOut > 0 && entry.WiFiIn+entry.WiFiOut == 0 {
		if entry.TotalBytes > 10*1024*1024 { // More than 10MB cellular-only
			score += 0.3
			reasons = append(reasons, "Cellular-only traffic (may avoid WiFi network monitoring)")
		}
	}

	// Check for processes with names mimicking system processes
	if p.isMimickingSystemProcess(processName) {
		score += 0.6
		reasons = append(reasons, "Process name mimics legitimate system process")
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	if score >= 0.4 {
		entry.IsSuspicious = true
		entry.SuspiciousScore = score
		entry.Reason = strings.Join(reasons, "; ")
	}
}

// isMimickingSystemProcess checks if a process name is similar to but not exactly a system process
func (p *DataUsageParser) isMimickingSystemProcess(name string) bool {
	lowerName := strings.ToLower(name)

	// Check for case differences with legitimate processes
	for legit := range legitimateHighUsageProcesses {
		if strings.ToLower(legit) == lowerName && legit != name {
			return true
		}
	}

	// Check for typosquatting-like names
	mimicPatterns := []string{
		"com.apple.",  // Fake Apple bundle IDs
		"springboard", // Lowercase SpringBoard
		"commcenter",  // Lowercase CommCenter
		"locationd",   // Legitimate but often mimicked
	}

	for _, pattern := range mimicPatterns {
		if strings.Contains(lowerName, pattern) && !legitimateHighUsageProcesses[name] {
			return true
		}
	}

	return false
}

// detectExfiltrationPatterns looks for coordinated data exfiltration patterns
func (p *DataUsageParser) detectExfiltrationPatterns(entries []models.DataUsageEntry, result *models.ForensicResult, timeline *models.Timeline) {
	// Look for multiple suspicious processes active in similar timeframes
	// This may indicate coordinated spyware activity

	suspiciousEntries := make([]models.DataUsageEntry, 0)
	for _, e := range entries {
		if e.IsSuspicious {
			suspiciousEntries = append(suspiciousEntries, e)
		}
	}

	if len(suspiciousEntries) < 2 {
		return
	}

	// Check for overlapping timeframes
	for i := 0; i < len(suspiciousEntries); i++ {
		for j := i + 1; j < len(suspiciousEntries); j++ {
			entry1 := suspiciousEntries[i]
			entry2 := suspiciousEntries[j]

			// Check if timeframes overlap
			if p.timeframesOverlap(entry1.FirstTimestamp, entry1.LastTimestamp,
				entry2.FirstTimestamp, entry2.LastTimestamp) {

				anomaly := models.Anomaly{
					ID:          uuid.New().String(),
					Type:        models.AnomalyTypeDataExfiltration,
					Severity:    models.ForensicSeverityCritical,
					Confidence:  0.85,
					Title:       "Coordinated Data Exfiltration Pattern",
					Description: fmt.Sprintf("Multiple suspicious processes (%s, %s) active in overlapping timeframes", entry1.ProcessName, entry2.ProcessName),
					Evidence: map[string]any{
						"process_1":    entry1.ProcessName,
						"process_2":    entry2.ProcessName,
						"combined_bytes": entry1.TotalBytes + entry2.TotalBytes,
					},
					MITRETechniques: []string{
						"T1041",     // Exfiltration Over C2 Channel
						"T1048",     // Exfiltration Over Alternative Protocol
						"T1020",     // Automated Exfiltration
					},
				}
				result.AddAnomaly(anomaly)
			}
		}
	}
}

// timeframesOverlap checks if two time ranges overlap
func (p *DataUsageParser) timeframesOverlap(start1, end1, start2, end2 time.Time) bool {
	return start1.Before(end2) && start2.Before(end1)
}

// getSeverity converts confidence score to severity
func (p *DataUsageParser) getSeverity(score float64) models.ForensicSeverity {
	switch {
	case score >= 0.9:
		return models.ForensicSeverityCritical
	case score >= 0.7:
		return models.ForensicSeverityHigh
	case score >= 0.5:
		return models.ForensicSeverityMedium
	case score >= 0.3:
		return models.ForensicSeverityLow
	default:
		return models.ForensicSeverityInfo
	}
}

// detectThreats analyzes anomalies for specific threat indicators
func (p *DataUsageParser) detectThreats(anomalies []models.Anomaly) []models.DetectedThreat {
	threats := make([]models.DetectedThreat, 0)

	hasExfiltration := false
	hasPegasusIndicator := false
	totalSuspiciousBytes := int64(0)

	anomalyIDs := make([]string, 0)

	for _, a := range anomalies {
		anomalyIDs = append(anomalyIDs, a.ID)

		if a.Type == models.AnomalyTypeDataExfiltration {
			hasExfiltration = true
		}

		if strings.Contains(a.Description, "Pegasus") || strings.Contains(a.Description, "bh") {
			hasPegasusIndicator = true
		}

		if bytes, ok := a.Evidence["total_bytes"].(int64); ok {
			totalSuspiciousBytes += bytes
		}
	}

	if hasExfiltration && hasPegasusIndicator {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypePegasus,
			Name:        "NSO Group Pegasus - Data Exfiltration",
			Confidence:  0.80,
			Severity:    models.ForensicSeverityCritical,
			Description: fmt.Sprintf("Network usage patterns consistent with Pegasus spyware data exfiltration (%d MB transferred)", totalSuspiciousBytes/(1024*1024)),
			Attribution: "NSO Group",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1041",     // Exfiltration Over C2 Channel
				"T1573",     // Encrypted Channel
				"T1020",     // Automated Exfiltration
			},
			Remediation: []string{
				"Device is likely fully compromised",
				"All data on device should be considered accessed",
				"Preserve device for forensic analysis",
				"Contact Citizen Lab or Amnesty Tech",
			},
		})
	} else if hasExfiltration {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypeGenericSpyware,
			Name:        "Potential Data Exfiltration",
			Confidence:  0.65,
			Severity:    models.ForensicSeverityHigh,
			Description: "Suspicious network patterns indicate potential data exfiltration by unknown malware",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			Remediation: []string{
				"Conduct full forensic analysis",
				"Review all network connections",
				"Consider device compromised",
			},
		})
	}

	return threats
}
