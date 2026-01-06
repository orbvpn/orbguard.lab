package ios

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"orbguard-lab/internal/forensics/models"
	"orbguard-lab/pkg/logger"
)

// Suspicious domains and paths known to be associated with spyware
var suspiciousBackupPaths = []struct {
	Pattern string
	Reason  string
	Score   float64
}{
	{"/private/var/db/", "Known Pegasus staging directory", 0.9},
	{"/private/var/tmp/", "Known Predator staging directory", 0.9},
	{"/private/var/mobile/Library/SMS/Attachments/", "SMS attachments - potential exploit delivery", 0.5},
	{"/private/var/mobile/Library/Caches/", "Cache directory - potential staging", 0.4},
	{"/Library/Preferences/com.apple.", "System preferences tampering", 0.3},
	{"/private/var/root/", "Root user directory - unusual for apps", 0.8},
	{"/private/var/containers/Shared/", "Shared container - potential data staging", 0.4},
	{"/private/var/mobile/Library/AddressBook/", "Address book access", 0.3},
	{"/private/var/mobile/Library/Calendar/", "Calendar access", 0.3},
	{"/private/var/mobile/Library/Photos/", "Photo library access", 0.3},
	{"/private/var/mobile/Library/Voicemail/", "Voicemail access", 0.5},
	{"/private/var/wireless/Library/CallHistory/", "Call history database", 0.5},
}

// Known malicious file patterns
var maliciousFilePatterns = []struct {
	Pattern *regexp.Regexp
	Reason  string
	Score   float64
}{
	{regexp.MustCompile(`(?i)\.dylib$`), "Dynamic library - potential payload", 0.6},
	{regexp.MustCompile(`(?i)\.plist$.*bridge`), "Bridge plist - potential C2 config", 0.7},
	{regexp.MustCompile(`(?i)roleaccount`), "Known Pegasus indicator", 0.95},
	{regexp.MustCompile(`(?i)pcsd`), "Known Predator indicator", 0.95},
	{regexp.MustCompile(`(?i)implant`), "Generic implant indicator", 0.8},
	{regexp.MustCompile(`(?i)\.framework/.+[a-f0-9]{8,}`), "Framework with hash name - suspicious", 0.7},
	{regexp.MustCompile(`(?i)bh$`), "Known Pegasus process name", 0.9},
}

// BackupParser parses iOS backup files (iTunes/Finder backups)
type BackupParser struct {
	logger *logger.Logger
}

// NewBackupParser creates a new iOS backup parser
func NewBackupParser(log *logger.Logger) *BackupParser {
	return &BackupParser{
		logger: log.WithComponent("backup-parser"),
	}
}

// Manifest represents the Manifest.plist structure
type Manifest struct {
	BackupKeyBag    []byte `plist:"BackupKeyBag"`
	Lockdown        any    `plist:"Lockdown"`
	Applications    any    `plist:"Applications"`
	IsEncrypted     bool   `plist:"IsEncrypted"`
	Version         string `plist:"Version"`
	Date            string `plist:"Date"`
	SystemDomainsVersion string `plist:"SystemDomainsVersion"`
	WasPasscodeSet  bool   `plist:"WasPasscodeSet"`
}

// ManifestDBEntry represents an entry from Manifest.db
type ManifestDBEntry struct {
	FileID       string
	Domain       string
	RelativePath string
	Flags        int
	File         []byte
}

// Parse analyzes an iOS backup directory and returns forensic results
func (p *BackupParser) Parse(backupPath string) (*models.ForensicResult, error) {
	result := models.NewForensicResult("", "ios", models.ForensicScanTypeBackup)

	// Check if backup exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("backup path does not exist: %s", backupPath)
	}

	p.logger.Info().Str("path", backupPath).Msg("analyzing iOS backup")

	timeline := models.NewTimeline()
	files := make([]models.BackupFileInfo, 0)

	// Parse Manifest.db (SQLite database)
	manifestDB := filepath.Join(backupPath, "Manifest.db")
	if _, err := os.Stat(manifestDB); err == nil {
		dbFiles, err := p.parseManifestDB(manifestDB)
		if err != nil {
			p.logger.Warn().Err(err).Msg("failed to parse Manifest.db")
		} else {
			files = append(files, dbFiles...)
		}
	}

	// Parse Info.plist for backup metadata
	infoPlist := filepath.Join(backupPath, "Info.plist")
	if _, err := os.Stat(infoPlist); err == nil {
		if info, err := p.parseInfoPlist(infoPlist); err == nil {
			result.RawData["device_name"] = info["Device Name"]
			result.RawData["product_name"] = info["Product Name"]
			result.RawData["product_version"] = info["Product Version"]
			result.RawData["serial_number"] = info["Serial Number"]
			result.RawData["last_backup_date"] = info["Last Backup Date"]
		}
	}

	// Analyze files for anomalies
	for _, file := range files {
		// Check for suspicious paths
		for _, pattern := range suspiciousBackupPaths {
			if strings.Contains(file.RelativePath, pattern.Pattern) ||
				strings.Contains(file.Domain, pattern.Pattern) {
				file.IsSuspicious = true
				file.SuspiciousScore = pattern.Score
				file.Reason = pattern.Reason
				break
			}
		}

		// Check for malicious file patterns
		for _, mp := range maliciousFilePatterns {
			if mp.Pattern.MatchString(file.RelativePath) {
				file.IsSuspicious = true
				if mp.Score > file.SuspiciousScore {
					file.SuspiciousScore = mp.Score
					file.Reason = mp.Reason
				}
				break
			}
		}

		// Create anomaly for suspicious files
		if file.IsSuspicious {
			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeFileAnomaly,
				Severity:    p.getSeverity(file.SuspiciousScore),
				Confidence:  file.SuspiciousScore,
				Title:       "Suspicious File in Backup",
				Description: file.Reason,
				Path:        file.RelativePath,
				Timestamp:   &file.ModifiedAt,
				Evidence: map[string]any{
					"domain":        file.Domain,
					"file_id":       file.FileID,
					"size":          file.Size,
					"modified_at":   file.ModifiedAt,
					"is_encrypted":  file.IsEncrypted,
				},
			}

			result.AddAnomaly(anomaly)

			// Add to timeline
			timeline.AddEvent(models.TimelineEvent{
				ID:           uuid.New().String(),
				Timestamp:    file.ModifiedAt,
				Type:         models.TimelineEventTypeFileModified,
				Source:       "backup",
				Title:        "Suspicious File: " + filepath.Base(file.RelativePath),
				Description:  file.Reason,
				Path:         file.RelativePath,
				IsSuspicious: true,
				Severity:     p.getSeverity(file.SuspiciousScore),
				AnomalyID:    anomaly.ID,
				Metadata: map[string]any{
					"domain":  file.Domain,
					"file_id": file.FileID,
					"size":    file.Size,
				},
			})
		}
	}

	// Scan actual backup files for IOC matches
	p.scanBackupFiles(backupPath, result, timeline)

	// Detect threats based on anomalies
	threats := p.detectThreats(result.Anomalies)
	for _, threat := range threats {
		result.AddThreat(threat)
	}

	timeline.Sort()
	result.Timeline = timeline.ToEvents()

	result.RawData["total_files"] = len(files)
	result.RawData["suspicious_files"] = len(result.Anomalies)

	result.Complete()
	return result, nil
}

// parseManifestDB parses the Manifest.db SQLite database
func (p *BackupParser) parseManifestDB(dbPath string) ([]models.BackupFileInfo, error) {
	db, err := sql.Open("sqlite3", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("failed to open Manifest.db: %w", err)
	}
	defer db.Close()

	files := make([]models.BackupFileInfo, 0)

	query := `SELECT fileID, domain, relativePath, flags, file FROM Files`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query Manifest.db: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var entry ManifestDBEntry
		if err := rows.Scan(&entry.FileID, &entry.Domain, &entry.RelativePath, &entry.Flags, &entry.File); err != nil {
			continue
		}

		file := models.BackupFileInfo{
			FileID:       entry.FileID,
			Domain:       entry.Domain,
			RelativePath: entry.RelativePath,
			IsEncrypted:  entry.Flags&1 != 0, // Encrypted flag
		}

		// Parse plist blob for metadata
		if len(entry.File) > 0 {
			metadata := p.parseBplist(entry.File)
			if modTime, ok := metadata["LastModified"].(time.Time); ok {
				file.ModifiedAt = modTime
			}
			if size, ok := metadata["Size"].(int64); ok {
				file.Size = size
			}
		}

		files = append(files, file)
	}

	return files, nil
}

// parseBplist attempts to parse a binary plist blob
func (p *BackupParser) parseBplist(data []byte) map[string]any {
	result := make(map[string]any)

	// Basic binary plist parsing for common fields
	// In production, use a proper bplist parser like howett.net/plist
	// This is a simplified version

	return result
}

// parseInfoPlist parses Info.plist for backup metadata
func (p *BackupParser) parseInfoPlist(plistPath string) (map[string]any, error) {
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return nil, err
	}

	result := make(map[string]any)

	// Try XML plist format first
	var xmlData struct {
		Dict struct {
			Keys   []string `xml:"key"`
			Values []string `xml:"string"`
		} `xml:"dict"`
	}

	if err := xml.Unmarshal(data, &xmlData); err == nil {
		for i, key := range xmlData.Dict.Keys {
			if i < len(xmlData.Dict.Values) {
				result[key] = xmlData.Dict.Values[i]
			}
		}
	}

	return result, nil
}

// scanBackupFiles scans actual backup files for IOC matches
func (p *BackupParser) scanBackupFiles(backupPath string, result *models.ForensicResult, timeline *models.Timeline) {
	// Walk through backup directory and hash files
	err := filepath.Walk(backupPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if info.IsDir() {
			return nil
		}

		// Skip large files (over 10MB) for performance
		if info.Size() > 10*1024*1024 {
			return nil
		}

		// Calculate SHA256 hash
		hash, err := p.hashFile(path)
		if err != nil {
			return nil
		}

		// Check against known malicious hashes
		if p.isKnownMaliciousHash(hash) {
			anomaly := models.Anomaly{
				ID:          uuid.New().String(),
				Type:        models.AnomalyTypeIOCMatch,
				Severity:    models.ForensicSeverityCritical,
				Confidence:  0.99,
				Title:       "Known Malicious File Hash Detected",
				Description: fmt.Sprintf("File matches known malicious hash: %s", hash[:16]),
				Path:        path,
				IOCMatch: &models.IOCMatch{
					IOCType: "sha256",
					Value:   hash,
					Source:  "internal_ioc_db",
				},
			}
			result.AddAnomaly(anomaly)
		}

		return nil
	})

	if err != nil {
		p.logger.Warn().Err(err).Msg("error walking backup directory")
	}
}

// hashFile calculates SHA256 hash of a file
func (p *BackupParser) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// isKnownMaliciousHash checks if hash matches known malicious files
// In production, this would check against a database of known IOCs
func (p *BackupParser) isKnownMaliciousHash(hash string) bool {
	// Known Pegasus-related hashes (examples - would be loaded from IOC database)
	knownHashes := map[string]bool{
		// These are placeholder hashes - real implementation would use IOC database
		"a1b2c3d4e5f6...": true,
	}
	return knownHashes[hash]
}

// getSeverity converts confidence score to severity
func (p *BackupParser) getSeverity(score float64) models.ForensicSeverity {
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
func (p *BackupParser) detectThreats(anomalies []models.Anomaly) []models.DetectedThreat {
	threats := make([]models.DetectedThreat, 0)

	pegasusScore := 0.0
	predatorScore := 0.0
	stalkerwareScore := 0.0

	anomalyIDs := make([]string, 0)

	for _, a := range anomalies {
		anomalyIDs = append(anomalyIDs, a.ID)

		if strings.Contains(strings.ToLower(a.Description), "pegasus") ||
			strings.Contains(strings.ToLower(a.Path), "/private/var/db/") {
			pegasusScore += a.Confidence
		}

		if strings.Contains(strings.ToLower(a.Description), "predator") ||
			strings.Contains(strings.ToLower(a.Path), "pcsd") {
			predatorScore += a.Confidence
		}

		if strings.Contains(strings.ToLower(a.Description), "stalkerware") ||
			strings.Contains(strings.ToLower(a.Description), "spy") {
			stalkerwareScore += a.Confidence
		}
	}

	if pegasusScore >= 1.5 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypePegasus,
			Name:        "NSO Group Pegasus",
			Confidence:  min(pegasusScore/3, 1.0),
			Severity:    models.ForensicSeverityCritical,
			Description: "Backup contains files consistent with Pegasus infection",
			Attribution: "NSO Group",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			MITRETechniques: []string{
				"T1430",     // Location Tracking
				"T1429",     // Audio Capture
				"T1512",     // Video Capture
				"T1417",     // Input Capture
				"T1636.002", // Protected User Data: Call Log
				"T1636.003", // Protected User Data: Contact List
				"T1636.004", // Protected User Data: SMS Messages
			},
			Remediation: []string{
				"Preserve backup for forensic analysis",
				"Do not restore this backup to any device",
				"Contact security professionals immediately",
			},
		})
	}

	if predatorScore >= 1.5 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypePredator,
			Name:        "Cytrox Predator",
			Confidence:  min(predatorScore/3, 1.0),
			Severity:    models.ForensicSeverityCritical,
			Description: "Backup contains files consistent with Predator infection",
			Attribution: "Cytrox/Intellexa",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			Remediation: []string{
				"Preserve backup for forensic analysis",
				"Seek professional security assistance",
			},
		})
	}

	if stalkerwareScore >= 1.0 {
		now := time.Now()
		threats = append(threats, models.DetectedThreat{
			Type:        models.InfectionTypeStalkerware,
			Name:        "Stalkerware Detected",
			Confidence:  min(stalkerwareScore/2, 1.0),
			Severity:    models.ForensicSeverityHigh,
			Description: "Backup contains indicators of stalkerware/spouseware",
			LastActive:  &now,
			AnomalyIDs:  anomalyIDs,
			Remediation: []string{
				"If you feel unsafe, contact local authorities",
				"Do not confront the potential installer",
				"Seek help from domestic violence resources if applicable",
			},
		})
	}

	return threats
}

// Helper function
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
