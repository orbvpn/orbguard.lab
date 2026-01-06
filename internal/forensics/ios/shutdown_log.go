package ios

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

// Known Pegasus/Predator/Reign suspicious paths based on Kaspersky and Citizen Lab research
var suspiciousPaths = []string{
	"/private/var/db/",
	"/private/var/tmp/",
	"/private/var/mobile/Library/SMS/",
	"/private/var/mobile/Library/Preferences/",
	"/private/var/root/",
	"/private/var/mobile/Library/Caches/",
	"/private/var/containers/Bundle/Application/",
	"/usr/libexec/",
	"/System/Library/PrivateFrameworks/",
}

// Known legitimate processes that may appear in shutdown logs
var legitimateProcesses = map[string]bool{
	"SpringBoard":         true,
	"backboardd":          true,
	"mediaserverd":        true,
	"assistantd":          true,
	"locationd":           true,
	"bluetoothd":          true,
	"wifid":               true,
	"configd":             true,
	"launchd":             true,
	"kernel_task":         true,
	"mDNSResponder":       true,
	"UserEventAgent":      true,
	"apsd":                true,
	"distnoted":           true,
	"fseventsd":           true,
	"notifyd":             true,
	"powerd":              true,
	"symptomsd":           true,
	"thermalmonitord":     true,
	"CommCenter":          true,
	"aggregated":          true,
	"callservicesd":       true,
	"cloudd":              true,
	"coreduetd":           true,
	"healthd":             true,
	"imagent":             true,
	"iMessage":            true,
	"identityservicesd":   true,
	"kbd":                 true,
	"lsd":                 true,
	"mobileassetd":        true,
	"mobileslideshow":     true,
	"Music":               true,
	"networkd":            true,
	"nsurlsessiond":       true,
	"parsecd":             true,
	"photoanalysisd":      true,
	"rapportd":            true,
	"replayd":             true,
	"runningboardd":       true,
	"screenshotserviced":  true,
	"sharingd":            true,
	"softwareupdated":     true,
	"suggestd":            true,
	"Spotlight":           true,
	"syslogd":             true,
	"timed":               true,
	"wcd":                 true,
	"watchdogd":           true,
}

// Known Pegasus-associated process names
var pegasusProcessNames = []string{
	"bh",                  // Common Pegasus process
	"roleaccountd",        // Pegasus masquerading
	"gatekeeperd",         // Pegasus masquerading (not the real gatekeeper)
	"pcsd",                // Predator process
	"servicemanager",      // Common spyware
	"commcenter",          // Fake CommCenter (lowercase)
	"mobilemail",          // Fake MobileMail (lowercase)
	"xpcproxy",            // Abused XPC proxy
	"cfprefsd",            // Sometimes abused
	"msf",                 // Metasploit
	"implant",             // Generic implant
	"agent",               // Generic agent
}

// ShutdownLogParser parses iOS shutdown.log files
type ShutdownLogParser struct {
	logger *logger.Logger
}

// NewShutdownLogParser creates a new shutdown log parser
func NewShutdownLogParser(log *logger.Logger) *ShutdownLogParser {
	return &ShutdownLogParser{
		logger: log.WithComponent("shutdown-log-parser"),
	}
}

// Regular expressions for parsing shutdown log entries
var (
	// Format: YYYY-MM-DD HH:MM:SS.mmm tz pid process[pid]: message
	logEntryPattern = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+[+-]\d{4}\s+(\d+)\s+([^[]+)\[(\d+)\]:\s*(.*)$`)

	// Client termination pattern
	clientPattern = regexp.MustCompile(`Removing client pid (\d+) (.+) with reason (.+)`)

	// Process path pattern
	pathPattern = regexp.MustCompile(`path:\s*([^\s,]+)`)

	// Shutdown delay pattern
	delayPattern = regexp.MustCompile(`delay:\s*([\d.]+)`)

	// Reboot/shutdown event patterns
	rebootPattern   = regexp.MustCompile(`(reboot|shutdown|SpringBoard|SIGTERM)`)
	shutdownPattern = regexp.MustCompile(`System shutdown`)
)

// Parse parses shutdown.log data and returns forensic results
func (p *ShutdownLogParser) Parse(data []byte) (*models.ForensicResult, error) {
	result := models.NewForensicResult("", "ios", models.ForensicScanTypeShutdownLog)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	entries := make([]models.ShutdownLogEntry, 0)
	processOccurrences := make(map[string]*models.StickyProcess)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		entry, err := p.parseLine(line)
		if err != nil {
			continue // Skip unparseable lines
		}

		entries = append(entries, entry)

		// Track process occurrences across reboots
		if entry.ProcessName != "" {
			key := entry.ProcessName
			if entry.Path != "" {
				key = entry.Path
			}

			if sp, exists := processOccurrences[key]; exists {
				sp.LastSeen = entry.Timestamp
				sp.RebootCount++
				sp.TotalDelayMs += int64(entry.DelaySeconds * 1000)
			} else {
				processOccurrences[key] = &models.StickyProcess{
					ProcessName:  entry.ProcessName,
					Path:         entry.Path,
					FirstSeen:    entry.Timestamp,
					LastSeen:     entry.Timestamp,
					RebootCount:  1,
					TotalDelayMs: int64(entry.DelaySeconds * 1000),
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Analyze for anomalies
	timeline := models.NewTimeline()

	// Check for sticky processes (processes appearing across multiple reboots)
	for _, sp := range processOccurrences {
		sp.AvgDelayMs = sp.TotalDelayMs / int64(sp.RebootCount)

		// Analyze suspiciousness
		sp.IsSuspicious, sp.SuspiciousScore, sp.Reason = p.analyzeProcess(sp)

		if sp.IsSuspicious {
			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeStickyProcess,
				Severity:    p.getSeverity(sp.SuspiciousScore),
				Confidence:  sp.SuspiciousScore,
				Title:       "Suspicious Sticky Process Detected",
				Description: sp.Reason,
				ProcessName: sp.ProcessName,
				Path:        sp.Path,
				Evidence: map[string]any{
					"reboot_count":    sp.RebootCount,
					"total_delay_ms":  sp.TotalDelayMs,
					"avg_delay_ms":    sp.AvgDelayMs,
					"first_seen":      sp.FirstSeen,
					"last_seen":       sp.LastSeen,
				},
			}

			// Add MITRE techniques for persistent processes
			anomaly.MITRETechniques = []string{
				"T1547",     // Boot or Logon Autostart Execution
				"T1053",     // Scheduled Task/Job
				"T1037",     // Boot or Logon Initialization Scripts
			}

			result.AddAnomaly(anomaly)

			// Add to timeline
			timeline.AddEvent(models.TimelineEvent{
				ID:          uuid.New().String(),
				Timestamp:   sp.FirstSeen,
				Type:        models.TimelineEventTypeProcessStart,
				Source:      "shutdown_log",
				Title:       "Sticky Process: " + sp.ProcessName,
				Description: sp.Reason,
				ProcessName: sp.ProcessName,
				Path:        sp.Path,
				IsSuspicious: true,
				Severity:    p.getSeverity(sp.SuspiciousScore),
				AnomalyID:   anomaly.ID,
			})
		}
	}

	// Detect shutdown/reboot events and add to timeline
	for _, entry := range entries {
		if rebootPattern.MatchString(entry.RawLine) {
			eventType := models.TimelineEventTypeShutdown
			if strings.Contains(entry.RawLine, "reboot") {
				eventType = models.TimelineEventTypeReboot
			}

			timeline.AddEvent(models.TimelineEvent{
				ID:          uuid.New().String(),
				Timestamp:   entry.Timestamp,
				Type:        eventType,
				Source:      "shutdown_log",
				Title:       entry.EventType,
				Description: entry.RawLine,
				ProcessName: entry.ProcessName,
				PID:         entry.PID,
			})
		}
	}

	// Detect Pegasus/Predator/Reign indicators
	threats := p.detectThreats(processOccurrences)
	for _, threat := range threats {
		result.AddThreat(threat)
	}

	timeline.Sort()
	result.Timeline = timeline.ToEvents()

	// Store raw data for later analysis
	result.RawData["entries_count"] = len(entries)
	result.RawData["process_count"] = len(processOccurrences)
	result.RawData["reboot_count"] = p.countReboots(entries)

	result.Complete()
	return result, nil
}

// parseLine parses a single shutdown log line
func (p *ShutdownLogParser) parseLine(line string) (models.ShutdownLogEntry, error) {
	entry := models.ShutdownLogEntry{
		RawLine: line,
	}

	// Try to match standard log format
	matches := logEntryPattern.FindStringSubmatch(line)
	if len(matches) >= 5 {
		// Parse timestamp
		ts, err := time.Parse("2006-01-02 15:04:05.000", matches[1])
		if err == nil {
			entry.Timestamp = ts
		}

		// Parse PID
		pid, _ := strconv.Atoi(matches[2])
		entry.PID = pid

		entry.ProcessName = strings.TrimSpace(matches[3])

		// Parse message for additional info
		message := matches[5]
		entry.EventType = "log"

		// Check for client termination
		if clientMatches := clientPattern.FindStringSubmatch(message); len(clientMatches) > 0 {
			entry.EventType = "client_termination"
		}

		// Extract path if present
		if pathMatches := pathPattern.FindStringSubmatch(message); len(pathMatches) > 0 {
			entry.Path = pathMatches[1]
		}

		// Extract delay if present
		if delayMatches := delayPattern.FindStringSubmatch(message); len(delayMatches) > 0 {
			delay, _ := strconv.ParseFloat(delayMatches[1], 64)
			entry.DelaySeconds = delay
		}
	}

	return entry, nil
}

// analyzeProcess determines if a process is suspicious
func (p *ShutdownLogParser) analyzeProcess(sp *models.StickyProcess) (bool, float64, string) {
	score := 0.0
	reasons := make([]string, 0)

	// Check if it's a known legitimate process
	if legitimateProcesses[sp.ProcessName] {
		return false, 0.0, ""
	}

	// Check for known Pegasus process names
	for _, pegName := range pegasusProcessNames {
		if strings.EqualFold(sp.ProcessName, pegName) {
			score += 0.9
			reasons = append(reasons, "Process name matches known Pegasus/spyware indicator: "+pegName)
		}
	}

	// Check for suspicious paths (Kaspersky method)
	for _, suspPath := range suspiciousPaths {
		if strings.HasPrefix(sp.Path, suspPath) {
			score += 0.7
			reasons = append(reasons, "Process path in suspicious location: "+suspPath)
		}
	}

	// Check for processes appearing across many reboots
	if sp.RebootCount >= 3 {
		score += 0.3
		reasons = append(reasons, "Process persisted across "+strconv.Itoa(sp.RebootCount)+" reboots")
	}

	// Check for unusual process names (very short, random-looking)
	if len(sp.ProcessName) <= 3 && !legitimateProcesses[sp.ProcessName] {
		score += 0.4
		reasons = append(reasons, "Suspiciously short process name")
	}

	// Check for processes with high shutdown delay (may indicate persistence mechanism)
	if sp.AvgDelayMs > 5000 { // More than 5 seconds average delay
		score += 0.2
		reasons = append(reasons, "High average shutdown delay")
	}

	// Check for lowercase versions of legitimate processes (common masquerading)
	lowerName := strings.ToLower(sp.ProcessName)
	for legitName := range legitimateProcesses {
		if lowerName == strings.ToLower(legitName) && sp.ProcessName != legitName {
			score += 0.8
			reasons = append(reasons, "Process name mimics legitimate process with different casing")
		}
	}

	// Normalize score
	if score > 1.0 {
		score = 1.0
	}

	isSuspicious := score >= 0.5
	reason := strings.Join(reasons, "; ")

	return isSuspicious, score, reason
}

// getSeverity converts confidence score to severity
func (p *ShutdownLogParser) getSeverity(score float64) models.ForensicSeverity {
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

// detectThreats analyzes processes for specific threat indicators
func (p *ShutdownLogParser) detectThreats(processes map[string]*models.StickyProcess) []models.DetectedThreat {
	threats := make([]models.DetectedThreat, 0)

	pegasusIndicators := 0
	predatorIndicators := 0
	unknownAPTIndicators := 0

	anomalyIDs := make([]string, 0)

	for _, sp := range processes {
		if !sp.IsSuspicious {
			continue
		}

		anomalyIDs = append(anomalyIDs, sp.ProcessName)

		// Check for specific threat patterns

		// Pegasus indicators
		if strings.Contains(strings.ToLower(sp.Path), "/private/var/db/") ||
			strings.Contains(strings.ToLower(sp.ProcessName), "bh") ||
			strings.Contains(strings.ToLower(sp.ProcessName), "roleaccount") {
			pegasusIndicators++
		}

		// Predator indicators
		if strings.Contains(strings.ToLower(sp.ProcessName), "pcsd") ||
			strings.Contains(strings.ToLower(sp.Path), "/private/var/tmp/") {
			predatorIndicators++
		}

		// Generic APT indicators
		if sp.RebootCount >= 5 && sp.SuspiciousScore >= 0.7 {
			unknownAPTIndicators++
		}
	}

	// Create threat entries based on indicators
	if pegasusIndicators >= 2 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypePegasus,
			Name:        "NSO Group Pegasus",
			Confidence:  0.85,
			Severity:    models.ForensicSeverityCritical,
			Description: "Multiple indicators consistent with NSO Group's Pegasus spyware detected in shutdown logs",
			Attribution: "NSO Group (Israel)",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1059.007", // Command and Scripting Interpreter: JavaScript
				"T1203",     // Exploitation for Client Execution
				"T1547.001", // Boot or Logon Autostart Execution
				"T1055",     // Process Injection
				"T1041",     // Exfiltration Over C2 Channel
			},
			Remediation: []string{
				"Do NOT factory reset - preserve evidence",
				"Disconnect from network immediately",
				"Contact Citizen Lab or Amnesty Tech for assistance",
				"Document everything for legal purposes",
				"Consider device compromise complete - all data may be accessed",
			},
		})
	}

	if predatorIndicators >= 2 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypePredator,
			Name:        "Cytrox/Intellexa Predator",
			Confidence:  0.80,
			Severity:    models.ForensicSeverityCritical,
			Description: "Indicators consistent with Cytrox/Intellexa Predator spyware detected",
			Attribution: "Cytrox/Intellexa (Greece/Cyprus)",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1204.002", // User Execution: Malicious Link
				"T1190",     // Exploit Public-Facing Application
				"T1547",     // Boot or Logon Autostart Execution
				"T1041",     // Exfiltration Over C2 Channel
			},
			Remediation: []string{
				"Preserve device for forensic analysis",
				"Seek professional security assistance",
				"Report to relevant authorities",
			},
		})
	}

	if unknownAPTIndicators >= 3 && pegasusIndicators == 0 && predatorIndicators == 0 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypeUnknownAPT,
			Name:        "Unknown APT-Level Spyware",
			Confidence:  0.70,
			Severity:    models.ForensicSeverityHigh,
			Description: "Persistent suspicious processes detected that indicate potential APT-level spyware",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1547", // Boot or Logon Autostart Execution
				"T1055", // Process Injection
			},
			Remediation: []string{
				"Conduct full forensic analysis",
				"Consider device compromised",
				"Seek professional security assistance",
			},
		})
	}

	return threats
}

// countReboots counts reboot events in the log entries
func (p *ShutdownLogParser) countReboots(entries []models.ShutdownLogEntry) int {
	count := 0
	for _, e := range entries {
		if strings.Contains(e.RawLine, "reboot") || strings.Contains(e.EventType, "shutdown") {
			count++
		}
	}
	return count
}
