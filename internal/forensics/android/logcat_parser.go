package android

import (
	"bufio"
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/forensics/models"
	"orbguard-lab/pkg/logger"
)

// LogcatParser parses Android logcat output for forensic analysis
type LogcatParser struct {
	logger *logger.Logger
}

// NewLogcatParser creates a new logcat parser
func NewLogcatParser(log *logger.Logger) *LogcatParser {
	return &LogcatParser{
		logger: log.WithComponent("logcat-parser"),
	}
}

// Suspicious patterns in logcat that may indicate spyware
var suspiciousLogPatterns = []struct {
	Pattern *regexp.Regexp
	Reason  string
	Score   float64
	Tags    []string
}{
	// Root/privilege escalation indicators
	{regexp.MustCompile(`(?i)su\s+root|gained root|root\s+shell|setuid.*root`), "Root access attempt", 0.9, []string{"root", "privilege_escalation"}},
	{regexp.MustCompile(`(?i)selinux.*permissive|selinux.*disabled`), "SELinux disabled/permissive", 0.85, []string{"selinux", "security_bypass"}},

	// Process injection indicators
	{regexp.MustCompile(`(?i)ptrace.*attach|process.*inject|dlopen.*suspicious`), "Process injection attempt", 0.9, []string{"injection", "persistence"}},
	{regexp.MustCompile(`(?i)xposed|frida|substrate`), "Hooking framework detected", 0.8, []string{"hooking", "tampering"}},

	// Known spyware indicators
	{regexp.MustCompile(`(?i)pegasus|chrysaor|lipizzan|skygofree|predator`), "Known spyware name", 0.95, []string{"spyware", "apt"}},
	{regexp.MustCompile(`(?i)cereals|equus|monstermind`), "Known spyware codename", 0.95, []string{"spyware", "apt"}},

	// Surveillance activity
	{regexp.MustCompile(`(?i)start.*recording|camera.*capture|mic.*record|screen.*capture`), "Surveillance activity", 0.7, []string{"surveillance", "privacy"}},
	{regexp.MustCompile(`(?i)location.*track|gps.*monitor|geofence`), "Location tracking", 0.5, []string{"tracking", "privacy"}},
	{regexp.MustCompile(`(?i)sms.*intercept|call.*intercept|keylog`), "Communication interception", 0.85, []string{"interception", "surveillance"}},

	// Data exfiltration
	{regexp.MustCompile(`(?i)upload.*contacts|exfil.*data|send.*credentials`), "Data exfiltration", 0.9, []string{"exfiltration", "data_theft"}},
	{regexp.MustCompile(`(?i)c2\s+server|command.*control|beacon.*send`), "C2 communication", 0.85, []string{"c2", "network"}},

	// Persistence mechanisms
	{regexp.MustCompile(`(?i)boot.*receiver|start.*service.*boot|autostart`), "Boot persistence", 0.5, []string{"persistence", "autostart"}},
	{regexp.MustCompile(`(?i)device.*admin|lock.*screen|wipe.*device`), "Device admin abuse", 0.7, []string{"device_admin", "control"}},

	// Exploit indicators
	{regexp.MustCompile(`(?i)heap.*spray|buffer.*overflow|use.*after.*free`), "Exploit attempt", 0.9, []string{"exploit", "vulnerability"}},
	{regexp.MustCompile(`(?i)adb.*shell|remote.*shell|reverse.*shell`), "Shell access", 0.75, []string{"shell", "remote_access"}},

	// Suspicious package activity
	{regexp.MustCompile(`(?i)hide.*icon|launcher.*hide|stealth.*mode`), "App hiding behavior", 0.8, []string{"stealth", "hiding"}},
	{regexp.MustCompile(`(?i)accessibility.*service.*enable|overlay.*permission`), "Suspicious permission use", 0.6, []string{"permissions", "abuse"}},

	// Stalkerware specific
	{regexp.MustCompile(`(?i)track.*spouse|monitor.*child|spy.*partner`), "Stalkerware activity", 0.95, []string{"stalkerware", "domestic"}},
	{regexp.MustCompile(`(?i)mspy|flexispy|cerberus|cocospy|spyic|hoverwatch`), "Known stalkerware", 0.95, []string{"stalkerware"}},

	// Encryption/obfuscation
	{regexp.MustCompile(`(?i)decrypt.*key|aes.*decrypt|xor.*decode`), "Cryptographic operations", 0.4, []string{"crypto", "obfuscation"}},

	// Unusual system access
	{regexp.MustCompile(`(?i)/proc/.*mem|/dev/mem|/dev/kmem`), "Direct memory access", 0.85, []string{"memory", "kernel"}},
	{regexp.MustCompile(`(?i)/system/.*write|remount.*rw`), "System partition write", 0.8, []string{"system", "modification"}},
}

// Known legitimate log patterns to exclude (reduce false positives)
var legitimatePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)google.*play.*service`),
	regexp.MustCompile(`(?i)android\.permission\..*GRANTED`), // Normal permission grants
	regexp.MustCompile(`(?i)gms\..*start`),
	regexp.MustCompile(`(?i)firebase`),
}

// Logcat entry regex patterns for different formats
var logcatPatterns = []*regexp.Regexp{
	// threadtime format: MM-DD HH:MM:SS.mmm PID TID PRIORITY TAG: MESSAGE
	regexp.MustCompile(`^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s*(.*)$`),
	// brief format: PRIORITY/TAG(PID): MESSAGE
	regexp.MustCompile(`^([VDIWEF])/([^(]+)\(\s*(\d+)\):\s*(.*)$`),
	// time format: MM-DD HH:MM:SS.mmm PRIORITY/TAG(PID): MESSAGE
	regexp.MustCompile(`^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+([VDIWEF])/([^(]+)\(\s*(\d+)\):\s*(.*)$`),
}

// Parse parses logcat data and returns forensic results
func (p *LogcatParser) Parse(data []byte) (*models.ForensicResult, error) {
	result := models.NewForensicResult("", "android", models.ForensicScanTypeLogcat)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	entries := make([]models.LogcatEntry, 0)
	timeline := models.NewTimeline()

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		entry, ok := p.parseLine(line, lineNum)
		if !ok {
			continue
		}

		entries = append(entries, entry)

		// Analyze for suspicious patterns
		isSuspicious, score, reason, tags := p.analyzeEntry(entry)
		if isSuspicious {
			entry.IsSuspicious = true
			entry.Reason = reason

			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeProcessAnomaly,
				Severity:    p.getSeverity(score),
				Confidence:  score,
				Title:       "Suspicious Logcat Entry",
				Description: reason,
				ProcessPID:  entry.PID,
				Timestamp:   &entry.Timestamp,
				Evidence: map[string]any{
					"tag":      entry.Tag,
					"message":  entry.Message,
					"priority": entry.Priority,
					"tid":      entry.TID,
					"tags":     tags,
				},
			}

			// Map to MITRE techniques based on tags
			anomaly.MITRETechniques = p.mapToMITRE(tags)

			result.AddAnomaly(anomaly)

			// Add to timeline
			timeline.AddEvent(models.TimelineEvent{
				ID:           uuid.New().String(),
				Timestamp:    entry.Timestamp,
				Type:         models.TimelineEventTypeAnomaly,
				Source:       "logcat",
				Title:        entry.Tag + ": " + truncate(entry.Message, 50),
				Description:  reason,
				PID:          entry.PID,
				IsSuspicious: true,
				Severity:     p.getSeverity(score),
				AnomalyID:    anomaly.ID,
				Metadata: map[string]any{
					"priority": entry.Priority,
					"tags":     tags,
				},
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Analyze patterns across entries
	p.analyzePatterns(entries, result, timeline)

	// Detect threats
	threats := p.detectThreats(result.Anomalies)
	for _, threat := range threats {
		result.AddThreat(threat)
	}

	timeline.Sort()
	result.Timeline = timeline.ToEvents()

	result.RawData["total_entries"] = len(entries)
	result.RawData["suspicious_entries"] = len(result.Anomalies)

	result.Complete()
	return result, nil
}

// parseLine parses a single logcat line
func (p *LogcatParser) parseLine(line string, lineNum int) (models.LogcatEntry, bool) {
	entry := models.LogcatEntry{}

	// Try each pattern
	for _, pattern := range logcatPatterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) > 0 {
			switch len(matches) {
			case 7: // threadtime format
				ts, _ := time.Parse("01-02 15:04:05.000", matches[1])
				// Use current year
				entry.Timestamp = time.Date(time.Now().Year(), ts.Month(), ts.Day(),
					ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(), time.Local)
				entry.PID, _ = strconv.Atoi(matches[2])
				entry.TID, _ = strconv.Atoi(matches[3])
				entry.Priority = matches[4]
				entry.Tag = strings.TrimSpace(matches[5])
				entry.Message = matches[6]
				return entry, true

			case 5: // brief format
				entry.Timestamp = time.Now() // No timestamp in brief format
				entry.Priority = matches[1]
				entry.Tag = strings.TrimSpace(matches[2])
				entry.PID, _ = strconv.Atoi(matches[3])
				entry.Message = matches[4]
				return entry, true

			case 6: // time format
				ts, _ := time.Parse("01-02 15:04:05.000", matches[1])
				entry.Timestamp = time.Date(time.Now().Year(), ts.Month(), ts.Day(),
					ts.Hour(), ts.Minute(), ts.Second(), ts.Nanosecond(), time.Local)
				entry.Priority = matches[2]
				entry.Tag = strings.TrimSpace(matches[3])
				entry.PID, _ = strconv.Atoi(matches[4])
				entry.Message = matches[5]
				return entry, true
			}
		}
	}

	return entry, false
}

// analyzeEntry analyzes a single logcat entry for suspicious content
func (p *LogcatParser) analyzeEntry(entry models.LogcatEntry) (bool, float64, string, []string) {
	// Check if it matches legitimate patterns first
	fullLine := entry.Tag + ": " + entry.Message
	for _, legit := range legitimatePatterns {
		if legit.MatchString(fullLine) {
			return false, 0, "", nil
		}
	}

	// Check against suspicious patterns
	for _, pattern := range suspiciousLogPatterns {
		if pattern.Pattern.MatchString(entry.Tag) || pattern.Pattern.MatchString(entry.Message) {
			return true, pattern.Score, pattern.Reason, pattern.Tags
		}
	}

	return false, 0, "", nil
}

// mapToMITRE maps tags to MITRE ATT&CK techniques
func (p *LogcatParser) mapToMITRE(tags []string) []string {
	mitre := make([]string, 0)
	tagMap := make(map[string]bool)
	for _, t := range tags {
		tagMap[t] = true
	}

	if tagMap["root"] || tagMap["privilege_escalation"] {
		mitre = append(mitre, "T1548") // Abuse Elevation Control Mechanism
	}
	if tagMap["injection"] || tagMap["persistence"] {
		mitre = append(mitre, "T1055") // Process Injection
	}
	if tagMap["hooking"] {
		mitre = append(mitre, "T1179") // Hooking
	}
	if tagMap["surveillance"] || tagMap["privacy"] {
		mitre = append(mitre,
			"T1429", // Audio Capture
			"T1512", // Video Capture
			"T1417", // Input Capture
		)
	}
	if tagMap["tracking"] {
		mitre = append(mitre, "T1430") // Location Tracking
	}
	if tagMap["interception"] {
		mitre = append(mitre,
			"T1636.002", // Protected User Data: Call Log
			"T1636.003", // Protected User Data: Contact List
			"T1636.004", // Protected User Data: SMS Messages
		)
	}
	if tagMap["exfiltration"] || tagMap["data_theft"] {
		mitre = append(mitre, "T1041") // Exfiltration Over C2 Channel
	}
	if tagMap["c2"] {
		mitre = append(mitre,
			"T1071", // Application Layer Protocol
			"T1571", // Non-Standard Port
		)
	}
	if tagMap["exploit"] {
		mitre = append(mitre, "T1203") // Exploitation for Client Execution
	}
	if tagMap["stealth"] || tagMap["hiding"] {
		mitre = append(mitre, "T1628") // Hide Artifacts
	}
	if tagMap["stalkerware"] || tagMap["domestic"] {
		mitre = append(mitre,
			"T1430", // Location Tracking
			"T1429", // Audio Capture
			"T1636", // Protected User Data
		)
	}

	return mitre
}

// analyzePatterns looks for patterns across multiple entries
func (p *LogcatParser) analyzePatterns(entries []models.LogcatEntry, result *models.ForensicResult, timeline *models.Timeline) {
	// Look for rapid suspicious activity (burst of malicious operations)
	suspiciousEntries := make([]models.LogcatEntry, 0)
	for _, e := range entries {
		if e.IsSuspicious {
			suspiciousEntries = append(suspiciousEntries, e)
		}
	}

	// Detect burst activity (multiple suspicious events in short window)
	if len(suspiciousEntries) >= 3 {
		// Check if multiple events within 1 second
		for i := 0; i < len(suspiciousEntries)-2; i++ {
			window := suspiciousEntries[i : i+3]
			duration := window[2].Timestamp.Sub(window[0].Timestamp)

			if duration <= time.Second {
				anomaly := models.Anomaly{
					ID:          uuid.New().String(),
					Type:        models.AnomalyTypeProcessAnomaly,
					Severity:    models.ForensicSeverityCritical,
					Confidence:  0.9,
					Title:       "Burst of Suspicious Activity Detected",
					Description: "Multiple suspicious operations occurred within 1 second - indicates automated malware execution",
					Timestamp:   &window[0].Timestamp,
					Evidence: map[string]any{
						"event_count": 3,
						"duration_ms": duration.Milliseconds(),
						"tags":        []string{window[0].Tag, window[1].Tag, window[2].Tag},
					},
					MITRETechniques: []string{
						"T1059", // Command and Scripting Interpreter
						"T1106", // Native API
					},
				}
				result.AddAnomaly(anomaly)
			}
		}
	}

	// Look for process spawning suspicious children
	pidActivity := make(map[int][]models.LogcatEntry)
	for _, e := range entries {
		pidActivity[e.PID] = append(pidActivity[e.PID], e)
	}

	for pid, pidEntries := range pidActivity {
		suspCount := 0
		for _, e := range pidEntries {
			if e.IsSuspicious {
				suspCount++
			}
		}

		// Process with multiple suspicious operations
		if suspCount >= 5 {
			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeProcessAnomaly,
				Severity:    models.ForensicSeverityHigh,
				Confidence:  0.85,
				Title:       "Process with Multiple Suspicious Operations",
				Description: "Single process performed multiple suspicious operations - likely malware",
				ProcessPID:  pid,
				Evidence: map[string]any{
					"suspicious_operations": suspCount,
					"total_operations":      len(pidEntries),
				},
			}
			result.AddAnomaly(anomaly)
		}
	}
}

// getSeverity converts confidence score to severity
func (p *LogcatParser) getSeverity(score float64) models.ForensicSeverity {
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
func (p *LogcatParser) detectThreats(anomalies []models.Anomaly) []models.DetectedThreat {
	threats := make([]models.DetectedThreat, 0)

	// Count indicators
	pegasusScore := 0.0
	stalkerwareScore := 0.0
	genericSpywareScore := 0.0
	rootkitScore := 0.0

	anomalyIDs := make([]string, 0)
	allMITRE := make(map[string]bool)

	for _, a := range anomalies {
		anomalyIDs = append(anomalyIDs, a.ID)

		for _, tech := range a.MITRETechniques {
			allMITRE[tech] = true
		}

		// Check evidence tags
		if tags, ok := a.Evidence["tags"].([]string); ok {
			for _, tag := range tags {
				switch tag {
				case "spyware", "apt":
					pegasusScore += a.Confidence
				case "stalkerware", "domestic":
					stalkerwareScore += a.Confidence
				case "surveillance", "interception", "exfiltration":
					genericSpywareScore += a.Confidence
				case "root", "kernel", "privilege_escalation":
					rootkitScore += a.Confidence
				}
			}
		}

		// Check description
		lowerDesc := strings.ToLower(a.Description)
		if strings.Contains(lowerDesc, "pegasus") || strings.Contains(lowerDesc, "chrysaor") {
			pegasusScore += 1.0
		}
		if strings.Contains(lowerDesc, "stalkerware") || strings.Contains(lowerDesc, "spy partner") {
			stalkerwareScore += 1.0
		}
	}

	// Build MITRE list
	mitreTechniques := make([]string, 0, len(allMITRE))
	for tech := range allMITRE {
		mitreTechniques = append(mitreTechniques, tech)
	}

	// Create threat entries
	if pegasusScore >= 2.0 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:            models.InfectionTypePegasus,
			Name:            "NSO Group Pegasus/Chrysaor (Android)",
			Confidence:      min(pegasusScore/4, 1.0),
			Severity:        models.ForensicSeverityCritical,
			Description:     "Logcat patterns consistent with Pegasus/Chrysaor Android spyware",
			Attribution:     "NSO Group",
			LastActive:      &now,
			AnomalyIDs:      anomalyIDs,
			MITRETechniques: mitreTechniques,
			Remediation: []string{
				"Device is fully compromised",
				"Do NOT factory reset - preserve evidence",
				"Contact Citizen Lab or security researchers",
				"Consider all data on device accessed",
			},
		})
	}

	if stalkerwareScore >= 2.0 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypeStalkerware,
			Name:        "Stalkerware/Spouseware Detected",
			Confidence:  min(stalkerwareScore/3, 1.0),
			Severity:    models.ForensicSeverityHigh,
			Description: "Evidence of stalkerware monitoring activity in system logs",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1430", // Location Tracking
				"T1429", // Audio Capture
				"T1417", // Input Capture
			},
			Remediation: []string{
				"Someone may be monitoring your device",
				"If you feel unsafe, do NOT confront the installer",
				"Contact local authorities or domestic violence hotline",
				"Have a safety plan before removing the app",
			},
		})
	}

	if rootkitScore >= 2.0 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypeGenericSpyware,
			Name:        "Rootkit/Advanced Persistent Malware",
			Confidence:  min(rootkitScore/4, 1.0),
			Severity:    models.ForensicSeverityCritical,
			Description: "Root-level access and kernel manipulation detected",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1014", // Rootkit
				"T1548", // Abuse Elevation Control
			},
			Remediation: []string{
				"Device boot chain may be compromised",
				"Factory reset may not remove infection",
				"Consider device permanently compromised",
				"Seek professional forensic assistance",
			},
		})
	}

	if genericSpywareScore >= 3.0 && pegasusScore < 2.0 && stalkerwareScore < 2.0 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:            models.InfectionTypeGenericSpyware,
			Name:            "Generic Android Spyware",
			Confidence:      min(genericSpywareScore/5, 1.0),
			Severity:        models.ForensicSeverityHigh,
			Description:     "Multiple spyware-like behaviors detected in system logs",
			LastActive:      &now,
			AnomalyIDs:      anomalyIDs,
			MITRETechniques: mitreTechniques,
			Remediation: []string{
				"Review installed applications",
				"Check device administrator apps",
				"Consider factory reset after backup",
				"Enable Google Play Protect",
			},
		})
	}

	return threats
}

// Helper functions
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
