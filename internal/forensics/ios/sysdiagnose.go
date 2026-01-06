package ios

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/forensics/models"
	"orbguard-lab/pkg/logger"
)

// SysdiagnoseParser parses iOS sysdiagnose archives for forensic analysis
type SysdiagnoseParser struct {
	logger            *logger.Logger
	shutdownLogParser *ShutdownLogParser
	dataUsageParser   *DataUsageParser
}

// NewSysdiagnoseParser creates a new sysdiagnose parser
func NewSysdiagnoseParser(log *logger.Logger) *SysdiagnoseParser {
	return &SysdiagnoseParser{
		logger:            log.WithComponent("sysdiagnose-parser"),
		shutdownLogParser: NewShutdownLogParser(log),
		dataUsageParser:   NewDataUsageParser(log),
	}
}

// Key files within sysdiagnose that are forensically relevant
var sysdiagnoseFiles = map[string]string{
	"shutdown.log":                    "logs/shutdown/shutdown.log",
	"system.log":                      "system_logs.logarchive",
	"powerlogs":                       "logs/powerlogs",
	"mobileactivation":                "logs/MobileActivation",
	"mobile_container_manager":        "logs/MobileContainerManager",
	"wifi":                            "WiFi",
	"lockdownd":                       "logs/lockdownd",
	"datausage":                       "logs/Networking/netusage.sqlite",
	"network_usage":                   "logs/Networking",
	"crashes":                         "crashes_and_spins",
	"itunesstore":                     "logs/itunesstored",
	"accessibility_tcc":               "logs/Accessibility/TCC.db",
	"locationd":                       "logs/locationd",
	"springboard":                     "logs/SpringBoard",
	"aggregated":                      "logs/aggregated",
	"mobile_installation":             "logs/MobileInstallation",
	"appinstallation":                 "logs/AppInstallation",
}

// Suspicious patterns in sysdiagnose logs
var sysdiagnoseSuspiciousPatterns = []struct {
	FilePattern string
	Pattern     *regexp.Regexp
	Reason      string
	Score       float64
}{
	// Process injection/hooking
	{"system_logs", regexp.MustCompile(`(?i)dlopen.*private/var/`), "Dynamic library loading from suspicious path", 0.8},
	{"system_logs", regexp.MustCompile(`(?i)ptrace|process_inject`), "Process injection attempt", 0.9},

	// Pegasus/Predator specific
	{"*", regexp.MustCompile(`(?i)/private/var/db/[a-f0-9]+`), "Suspicious path pattern (Pegasus)", 0.9},
	{"*", regexp.MustCompile(`(?i)/private/var/tmp/[a-f0-9]+`), "Suspicious path pattern (Predator)", 0.9},
	{"*", regexp.MustCompile(`(?i)bh\b|roleaccount|pcsd`), "Known spyware process name", 0.95},

	// Exploitation indicators
	{"crashes", regexp.MustCompile(`(?i)SIGABRT|SIGSEGV|EXC_BAD_ACCESS`), "Crash possibly indicating exploit", 0.5},
	{"crashes", regexp.MustCompile(`(?i)JavaScriptCore|WebKit.*crash`), "WebKit crash (potential exploit vector)", 0.7},
	{"crashes", regexp.MustCompile(`(?i)iMessage|imagent.*crash`), "iMessage crash (potential zero-click)", 0.8},

	// Persistence mechanisms
	{"springboard", regexp.MustCompile(`(?i)launchd.*suspicious|daemon.*unknown`), "Unknown daemon registered", 0.7},
	{"mobile_installation", regexp.MustCompile(`(?i)install.*failed.*signature`), "Failed signature check", 0.6},

	// Data access patterns
	{"locationd", regexp.MustCompile(`(?i)unauthorized.*location|location.*denied.*override`), "Location access anomaly", 0.6},
	{"accessibility_tcc", regexp.MustCompile(`(?i)kTCCService.*Microphone|kTCCService.*Camera`), "Sensitive permission granted", 0.4},

	// Network anomalies
	{"wifi", regexp.MustCompile(`(?i)captive.*portal.*bypass|ssl.*error.*ignore`), "Network security bypass", 0.7},
	{"network_usage", regexp.MustCompile(`(?i)high.*data.*unknown|exfiltration`), "Unusual network activity", 0.6},
}

// Parse analyzes a sysdiagnose archive and returns forensic results
func (p *SysdiagnoseParser) Parse(archivePath string) (*models.ForensicResult, error) {
	result := models.NewForensicResult("", "ios", models.ForensicScanTypeSysdiagnose)

	p.logger.Info().Str("path", archivePath).Msg("analyzing sysdiagnose archive")

	// Determine archive type and extract
	extractedFiles, tempDir, err := p.extractArchive(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract archive: %w", err)
	}
	defer os.RemoveAll(tempDir)

	timeline := models.NewTimeline()

	// Process each extracted file
	for filename, content := range extractedFiles {
		p.analyzeFile(filename, content, result, timeline)
	}

	// Look for shutdown.log specifically and run detailed analysis
	if shutdownLogContent, ok := extractedFiles["shutdown.log"]; ok {
		shutdownResult, err := p.shutdownLogParser.Parse(shutdownLogContent)
		if err == nil {
			// Merge shutdown.log results
			for _, a := range shutdownResult.Anomalies {
				a.ID = uuid.New().String() // Ensure unique IDs
				result.AddAnomaly(a)
			}
			for _, t := range shutdownResult.DetectedThreats {
				result.AddThreat(t)
			}
			for _, e := range shutdownResult.Timeline {
				timeline.AddEvent(e)
			}
		}
	}

	// Analyze crash logs for exploitation indicators
	p.analyzeCrashLogs(extractedFiles, result, timeline)

	// Analyze network data
	p.analyzeNetworkData(extractedFiles, result, timeline)

	// Detect coordinated suspicious activity patterns
	p.detectCoordinatedActivity(result, timeline)

	// Extract device info from sysdiagnose
	p.extractDeviceInfo(extractedFiles, result)

	timeline.Sort()
	result.Timeline = timeline.ToEvents()

	result.RawData["files_analyzed"] = len(extractedFiles)
	result.RawData["archive_path"] = archivePath

	result.Complete()

	p.logger.Info().
		Int("anomalies", result.TotalAnomalies).
		Int("threats", len(result.DetectedThreats)).
		Float64("infection_likelihood", result.InfectionLikelihood).
		Msg("sysdiagnose analysis complete")

	return result, nil
}

// extractArchive extracts a sysdiagnose archive (tar.gz or zip)
func (p *SysdiagnoseParser) extractArchive(archivePath string) (map[string][]byte, string, error) {
	files := make(map[string][]byte)

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "sysdiagnose-*")
	if err != nil {
		return nil, "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Determine archive type
	ext := strings.ToLower(filepath.Ext(archivePath))
	if ext == ".gz" || strings.HasSuffix(archivePath, ".tar.gz") {
		err = p.extractTarGz(archivePath, tempDir, files)
	} else if ext == ".zip" {
		err = p.extractZip(archivePath, tempDir, files)
	} else {
		// Try reading as directory
		err = p.readDirectory(archivePath, files)
	}

	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", err
	}

	return files, tempDir, nil
}

// extractTarGz extracts a tar.gz archive
func (p *SysdiagnoseParser) extractTarGz(archivePath, tempDir string, files map[string][]byte) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Check if this is a file we're interested in
		basename := filepath.Base(header.Name)
		for key, pattern := range sysdiagnoseFiles {
			if strings.Contains(header.Name, pattern) || basename == pattern {
				content, err := io.ReadAll(tr)
				if err != nil {
					continue
				}
				files[key] = content
				break
			}
		}

		// Also store by basename for pattern matching
		if header.Size < 50*1024*1024 { // Skip files > 50MB
			content, err := io.ReadAll(tr)
			if err != nil {
				continue
			}
			files[basename] = content
		}
	}

	return nil
}

// extractZip extracts a zip archive
func (p *SysdiagnoseParser) extractZip(archivePath, tempDir string, files map[string][]byte) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		basename := filepath.Base(f.Name)
		for key, pattern := range sysdiagnoseFiles {
			if strings.Contains(f.Name, pattern) || basename == pattern {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				content, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					continue
				}
				files[key] = content
				break
			}
		}

		// Also store by basename
		if f.FileInfo().Size() < 50*1024*1024 {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}
			files[basename] = content
		}
	}

	return nil
}

// readDirectory reads files from an extracted directory
func (p *SysdiagnoseParser) readDirectory(dirPath string, files map[string][]byte) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.IsDir() {
			return nil
		}
		if info.Size() > 50*1024*1024 {
			return nil // Skip large files
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		basename := filepath.Base(path)
		relPath, _ := filepath.Rel(dirPath, path)

		for key, pattern := range sysdiagnoseFiles {
			if strings.Contains(relPath, pattern) || basename == pattern {
				files[key] = content
				break
			}
		}
		files[basename] = content

		return nil
	})
}

// analyzeFile analyzes a single file for suspicious patterns
func (p *SysdiagnoseParser) analyzeFile(filename string, content []byte, result *models.ForensicResult, timeline *models.Timeline) {
	contentStr := string(content)

	for _, pattern := range sysdiagnoseSuspiciousPatterns {
		// Check if pattern applies to this file
		if pattern.FilePattern != "*" && !strings.Contains(filename, pattern.FilePattern) {
			continue
		}

		matches := pattern.Pattern.FindAllStringIndex(contentStr, -1)
		for _, match := range matches {
			// Extract context around match
			start := match[0] - 100
			if start < 0 {
				start = 0
			}
			end := match[1] + 100
			if end > len(contentStr) {
				end = len(contentStr)
			}
			context := contentStr[start:end]

			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeFileAnomaly,
				Severity:    p.getSeverity(pattern.Score),
				Confidence:  pattern.Score,
				Title:       "Suspicious Pattern in Sysdiagnose",
				Description: pattern.Reason,
				Path:        filename,
				Evidence: map[string]any{
					"pattern":    pattern.Pattern.String(),
					"context":    context,
					"match_pos":  match[0],
				},
			}

			result.AddAnomaly(anomaly)

			// Add to timeline with approximate time
			now := time.Now()
			timeline.AddEvent(models.TimelineEvent{
				ID:           uuid.New().String(),
				Timestamp:    now, // Could be extracted from log line if available
				Type:         models.TimelineEventTypeAnomaly,
				Source:       "sysdiagnose:" + filename,
				Title:        pattern.Reason,
				Description:  fmt.Sprintf("Found in %s", filename),
				Path:         filename,
				IsSuspicious: true,
				Severity:     p.getSeverity(pattern.Score),
				AnomalyID:    anomaly.ID,
			})
		}
	}
}

// analyzeCrashLogs analyzes crash logs for exploitation indicators
func (p *SysdiagnoseParser) analyzeCrashLogs(files map[string][]byte, result *models.ForensicResult, timeline *models.Timeline) {
	// Look for crash logs
	for filename, content := range files {
		if !strings.Contains(strings.ToLower(filename), "crash") &&
			!strings.Contains(strings.ToLower(filename), "spin") &&
			!strings.HasSuffix(filename, ".ips") {
			continue
		}

		contentStr := string(content)

		// Check for WebKit/JavaScriptCore crashes (common exploit vector)
		if strings.Contains(contentStr, "JavaScriptCore") ||
			strings.Contains(contentStr, "WebKit") {

			// Look for specific exploit indicators
			exploitIndicators := []string{
				"JIT",
				"ArrayBuffer",
				"TypedArray",
				"Use-after-free",
				"heap corruption",
				"out of bounds",
			}

			for _, indicator := range exploitIndicators {
				if strings.Contains(contentStr, indicator) {
					anomaly := models.Anomaly{
						ID:          uuid.New().String(),
						Type:        models.AnomalyTypeCrashAnomaly,
						Severity:    models.ForensicSeverityHigh,
						Confidence:  0.75,
						Title:       "Potential Exploit Crash Detected",
						Description: fmt.Sprintf("WebKit/JSC crash with %s indicator", indicator),
						Path:        filename,
						MITRETechniques: []string{
							"T1203", // Exploitation for Client Execution
							"T1059.007", // JavaScript
						},
					}
					result.AddAnomaly(anomaly)
					break
				}
			}
		}

		// Check for iMessage/imagent crashes (zero-click vector)
		if strings.Contains(contentStr, "imagent") ||
			strings.Contains(contentStr, "IMTransferAgent") ||
			strings.Contains(contentStr, "MessagesBlastDoor") {

			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeCrashAnomaly,
				Severity:    models.ForensicSeverityCritical,
				Confidence:  0.80,
				Title:       "iMessage Component Crash",
				Description: "Crash in iMessage processing - potential zero-click exploit indicator",
				Path:        filename,
				MITRETechniques: []string{
					"T1203", // Exploitation for Client Execution
					"T1204", // User Execution (zero-click bypasses this)
				},
			}
			result.AddAnomaly(anomaly)
		}
	}
}

// analyzeNetworkData analyzes network-related files for anomalies
func (p *SysdiagnoseParser) analyzeNetworkData(files map[string][]byte, result *models.ForensicResult, timeline *models.Timeline) {
	// Look for network configuration and usage anomalies
	for filename, content := range files {
		if !strings.Contains(strings.ToLower(filename), "network") &&
			!strings.Contains(strings.ToLower(filename), "wifi") &&
			!strings.Contains(strings.ToLower(filename), "netusage") {
			continue
		}

		contentStr := string(content)

		// Check for VPN bypass indicators
		if strings.Contains(contentStr, "VPN") {
			if strings.Contains(contentStr, "bypass") ||
				strings.Contains(contentStr, "split tunnel") ||
				strings.Contains(contentStr, "leak") {
				anomaly := models.Anomaly{
					ID:          uuid.New().String(),
					Type:        models.AnomalyTypeNetworkAnomaly,
					Severity:    models.ForensicSeverityMedium,
					Confidence:  0.6,
					Title:       "Potential VPN Bypass",
					Description: "Network logs indicate possible VPN bypass activity",
					Path:        filename,
				}
				result.AddAnomaly(anomaly)
			}
		}

		// Check for suspicious DNS queries
		suspiciousDNSPatterns := []string{
			".onion", // Tor
			".i2p",   // I2P
			"duckdns.org",
			"no-ip.org",
			"ddns.net",
		}
		for _, pattern := range suspiciousDNSPatterns {
			if strings.Contains(contentStr, pattern) {
				anomaly := models.Anomaly{
					ID:          uuid.New().String(),
					Type:        models.AnomalyTypeNetworkAnomaly,
					Severity:    models.ForensicSeverityMedium,
					Confidence:  0.65,
					Title:       "Suspicious DNS Pattern",
					Description: fmt.Sprintf("DNS pattern %s found in network logs", pattern),
					Path:        filename,
				}
				result.AddAnomaly(anomaly)
			}
		}
	}
}

// detectCoordinatedActivity looks for coordinated suspicious activity
func (p *SysdiagnoseParser) detectCoordinatedActivity(result *models.ForensicResult, timeline *models.Timeline) {
	// Count anomalies by type
	typeCounts := make(map[models.AnomalyType]int)
	for _, a := range result.Anomalies {
		typeCounts[a.Type]++
	}

	// If multiple different anomaly types, likely coordinated attack
	if len(typeCounts) >= 3 {
		anomaly := models.Anomaly{
			ID:          uuid.New().String(),
			Type:        models.AnomalyTypeProcessAnomaly,
			Severity:    models.ForensicSeverityCritical,
			Confidence:  0.85,
			Title:       "Coordinated Attack Indicators",
			Description: fmt.Sprintf("Multiple anomaly types detected (%d types) suggesting coordinated attack", len(typeCounts)),
			Evidence: map[string]any{
				"anomaly_types": typeCounts,
			},
			MITRETechniques: []string{
				"T1059", // Command and Scripting Interpreter
				"T1055", // Process Injection
				"T1041", // Exfiltration Over C2 Channel
			},
		}
		result.AddAnomaly(anomaly)

		// Add threat if sufficient evidence
		if result.TotalAnomalies >= 5 {
			now := time.Now()
			anomalyIDs := make([]string, 0)
			for _, a := range result.Anomalies {
				anomalyIDs = append(anomalyIDs, a.ID)
			}

			result.AddThreat(models.DetectedThreat{
				Type:        models.InfectionTypeUnknownAPT,
				Name:        "Advanced Persistent Threat Indicators",
				Confidence:  0.75,
				Severity:    models.ForensicSeverityCritical,
				Description: "Multiple forensic indicators suggest sophisticated spyware infection",
				LastActive:  &now,
				AnomalyIDs:  anomalyIDs,
				MITRETechniques: []string{
					"T1059", "T1055", "T1041", "T1547",
				},
				Remediation: []string{
					"Preserve device for professional forensic analysis",
					"Do not factory reset without expert guidance",
					"Contact security professionals",
				},
			})
		}
	}
}

// extractDeviceInfo extracts device information from sysdiagnose
func (p *SysdiagnoseParser) extractDeviceInfo(files map[string][]byte, result *models.ForensicResult) {
	// Look for device info files
	for filename, content := range files {
		contentStr := string(content)

		// Extract iOS version
		if strings.Contains(contentStr, "ProductVersion") {
			scanner := bufio.NewScanner(bytes.NewReader(content))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "ProductVersion") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						result.RawData["ios_version"] = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "ProductName") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						result.RawData["product_name"] = strings.TrimSpace(parts[1])
					}
				}
				if strings.Contains(line, "SerialNumber") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						result.RawData["serial_number"] = strings.TrimSpace(parts[1])
					}
				}
			}
		}

		// Extract sysdiagnose timestamp
		if strings.Contains(filename, "sysdiagnose") && strings.Contains(filename, "_") {
			// Try to parse timestamp from filename like sysdiagnose_2024.01.01_12-00-00
			parts := strings.Split(filename, "_")
			if len(parts) >= 2 {
				result.RawData["sysdiagnose_date"] = parts[1]
			}
		}
	}
}

// getSeverity converts confidence score to severity
func (p *SysdiagnoseParser) getSeverity(score float64) models.ForensicSeverity {
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
