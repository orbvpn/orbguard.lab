package desktop_security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"howett.net/plist"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// PersistenceScanner scans for persistence mechanisms on the system
type PersistenceScanner struct {
	locationDB    *PersistenceLocationDB
	cache         *cache.RedisCache
	logger        *logger.Logger
	knownGoodDB   *KnownGoodDB
	platform      models.DesktopPlatform
	homeDir       string
}

// NewPersistenceScanner creates a new persistence scanner
func NewPersistenceScanner(redisCache *cache.RedisCache, log *logger.Logger) *PersistenceScanner {
	platform := detectPlatform()
	homeDir := getHomeDir()

	return &PersistenceScanner{
		locationDB:  NewPersistenceLocationDB(),
		cache:       redisCache,
		logger:      log.WithComponent("persistence-scanner"),
		knownGoodDB: NewKnownGoodDB(),
		platform:    platform,
		homeDir:     homeDir,
	}
}

// detectPlatform detects the current operating system
func detectPlatform() models.DesktopPlatform {
	switch runtime.GOOS {
	case "darwin":
		return models.DesktopPlatformMacOS
	case "windows":
		return models.DesktopPlatformWindows
	case "linux":
		return models.DesktopPlatformLinux
	default:
		return models.DesktopPlatformLinux // Default to Linux
	}
}

// getHomeDir returns the user's home directory
func getHomeDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// Scan performs a comprehensive persistence scan
func (s *PersistenceScanner) Scan(ctx context.Context) (*models.PersistenceScanResult, error) {
	startTime := time.Now()

	result := &models.PersistenceScanResult{
		ID:        uuid.New(),
		Platform:  s.platform,
		Hostname:  getHostname(),
		OSVersion: getOSVersion(),
		StartedAt: startTime,
		Items:     []models.PersistenceItem{},
		Errors:    []string{},
	}

	// Get locations for current platform
	locations := s.locationDB.GetLocations(s.platform)
	s.logger.Info().
		Str("platform", string(s.platform)).
		Int("locations", len(locations)).
		Msg("starting persistence scan")

	// Scan each location
	for _, loc := range locations {
		items, err := s.scanLocation(ctx, loc)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", loc.Path, err))
			s.logger.Debug().Err(err).Str("path", loc.Path).Msg("scan location failed")
			continue
		}
		result.Items = append(result.Items, items...)
	}

	// Count items by risk level
	for _, item := range result.Items {
		result.TotalItems++
		switch item.RiskLevel {
		case models.PersistenceRiskCritical:
			result.CriticalItems++
		case models.PersistenceRiskHigh:
			result.HighRiskItems++
		case models.PersistenceRiskMedium:
			result.MediumRiskItems++
		case models.PersistenceRiskLow:
			result.LowRiskItems++
		case models.PersistenceRiskClean, models.PersistenceRiskInfo:
			result.CleanItems++
		}
	}

	// Calculate risk score
	result.CalculateRiskScore()

	// Generate recommendations
	result.Recommendations = s.generateRecommendations(result)

	// Finalize
	completedAt := time.Now()
	result.CompletedAt = &completedAt
	result.Duration = completedAt.Sub(startTime).String()

	s.logger.Info().
		Int("total_items", result.TotalItems).
		Int("critical", result.CriticalItems).
		Int("high", result.HighRiskItems).
		Float64("risk_score", result.RiskScore).
		Str("duration", result.Duration).
		Msg("persistence scan completed")

	return result, nil
}

// scanLocation scans a specific persistence location
func (s *PersistenceScanner) scanLocation(ctx context.Context, loc models.PersistenceLocation) ([]models.PersistenceItem, error) {
	var items []models.PersistenceItem

	// Expand path
	path := s.expandPath(loc.Path)

	// Check if path exists
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Path doesn't exist, not an error
		}
		return nil, err
	}

	if info.IsDir() {
		// Scan directory
		pattern := loc.FilePattern
		if pattern == "" {
			pattern = "*"
		}

		entries, err := filepath.Glob(filepath.Join(path, pattern))
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			select {
			case <-ctx.Done():
				return items, ctx.Err()
			default:
			}

			item, err := s.parseItem(ctx, entry, loc)
			if err != nil {
				s.logger.Debug().Err(err).Str("path", entry).Msg("parse item failed")
				continue
			}
			if item != nil {
				items = append(items, *item)
			}
		}
	} else {
		// Single file
		item, err := s.parseItem(ctx, path, loc)
		if err != nil {
			return nil, err
		}
		if item != nil {
			items = append(items, *item)
		}
	}

	return items, nil
}

// parseItem parses a persistence item from a file
func (s *PersistenceScanner) parseItem(ctx context.Context, path string, loc models.PersistenceLocation) (*models.PersistenceItem, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Skip directories for now (except .app bundles, .kext, etc.)
	if info.IsDir() && !s.isBundle(path) {
		return nil, nil
	}

	item := &models.PersistenceItem{
		ID:       uuid.New(),
		Platform: s.platform,
		Type:     loc.Type,
		Name:     filepath.Base(path),
		Path:     path,
		Scope:    loc.Scope,
		FoundAt:  time.Now(),
		Enabled:  true,
	}

	// Set timestamps
	modTime := info.ModTime()
	item.ModifiedAt = &modTime

	// Parse based on type
	switch loc.Type {
	case models.PersistenceLaunchAgent, models.PersistenceLaunchDaemon:
		if err := s.parsePlist(item); err != nil {
			s.logger.Debug().Err(err).Str("path", path).Msg("plist parse failed")
		}
	case models.PersistenceShellConfig:
		if err := s.parseShellConfig(item); err != nil {
			s.logger.Debug().Err(err).Str("path", path).Msg("shell config parse failed")
		}
	case models.PersistenceCronJob, models.PersistenceCrontab:
		if err := s.parseCrontab(item); err != nil {
			s.logger.Debug().Err(err).Str("path", path).Msg("crontab parse failed")
		}
	case models.PersistenceSystemdService, models.PersistenceSystemdTimer:
		if err := s.parseSystemdUnit(item); err != nil {
			s.logger.Debug().Err(err).Str("path", path).Msg("systemd unit parse failed")
		}
	case models.PersistenceKernelExtension, models.PersistenceSystemExtension:
		if err := s.parseBundle(item); err != nil {
			s.logger.Debug().Err(err).Str("path", path).Msg("bundle parse failed")
		}
	}

	// Hash binary if available
	if item.BinaryPath != "" {
		if hash, err := s.hashFile(item.BinaryPath); err == nil {
			item.BinaryHash = hash
		}
		if binaryInfo, err := os.Stat(item.BinaryPath); err == nil {
			item.BinarySize = binaryInfo.Size()
		}
	}

	// Check code signing (macOS)
	if s.platform == models.DesktopPlatformMacOS && item.BinaryPath != "" {
		s.checkCodeSigning(item)
	}

	// Assess risk
	s.assessRisk(item, loc)

	return item, nil
}

// parsePlist parses a macOS plist file
func (s *PersistenceScanner) parsePlist(item *models.PersistenceItem) error {
	file, err := os.Open(item.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	var data map[string]interface{}
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return err
	}

	// Store raw content
	if raw, err := json.MarshalIndent(data, "", "  "); err == nil {
		item.RawContent = string(raw)
	}

	// Extract label
	if label, ok := data["Label"].(string); ok {
		item.Name = label
	}

	// Extract program/command
	if program, ok := data["Program"].(string); ok {
		item.Command = program
		item.BinaryPath = program
	} else if args, ok := data["ProgramArguments"].([]interface{}); ok && len(args) > 0 {
		var argStrings []string
		for _, arg := range args {
			if s, ok := arg.(string); ok {
				argStrings = append(argStrings, s)
			}
		}
		if len(argStrings) > 0 {
			item.Command = strings.Join(argStrings, " ")
			item.BinaryPath = argStrings[0]
			if len(argStrings) > 1 {
				item.Arguments = argStrings[1:]
			}
		}
	}

	// Extract flags
	if runAtLoad, ok := data["RunAtLoad"].(bool); ok {
		item.RunAtLoad = runAtLoad
	}
	if keepAlive, ok := data["KeepAlive"]; ok {
		switch v := keepAlive.(type) {
		case bool:
			item.KeepAlive = v
		case map[string]interface{}:
			item.KeepAlive = true
		}
	}
	if disabled, ok := data["Disabled"].(bool); ok {
		item.Enabled = !disabled
	}

	return nil
}

// parseShellConfig parses shell config files for suspicious content
func (s *PersistenceScanner) parseShellConfig(item *models.PersistenceItem) error {
	content, err := os.ReadFile(item.Path)
	if err != nil {
		return err
	}

	item.RawContent = string(content)

	// Look for suspicious patterns
	suspiciousPatterns := []string{
		`curl.*\|.*sh`,
		`wget.*\|.*sh`,
		`base64.*-d`,
		`eval.*\$\(`,
		`nc\s+-[el]`,
		`/dev/tcp/`,
		`mkfifo`,
		`openssl.*-connect`,
	}

	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.MatchString(pattern, string(content)); matched {
			item.RiskReasons = append(item.RiskReasons, fmt.Sprintf("Contains suspicious pattern: %s", pattern))
		}
	}

	return nil
}

// parseCrontab parses crontab entries
func (s *PersistenceScanner) parseCrontab(item *models.PersistenceItem) error {
	content, err := os.ReadFile(item.Path)
	if err != nil {
		return err
	}

	item.RawContent = string(content)

	// Parse cron entries
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Basic cron format: min hour day month dow command
		parts := strings.Fields(line)
		if len(parts) >= 6 {
			command := strings.Join(parts[5:], " ")
			item.Command = command
			// Try to extract binary path
			cmdParts := strings.Fields(command)
			if len(cmdParts) > 0 {
				item.BinaryPath = cmdParts[0]
			}
		}
	}

	return nil
}

// parseSystemdUnit parses systemd unit files
func (s *PersistenceScanner) parseSystemdUnit(item *models.PersistenceItem) error {
	content, err := os.ReadFile(item.Path)
	if err != nil {
		return err
	}

	item.RawContent = string(content)

	// Parse unit file
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecStart=") {
			execStart := strings.TrimPrefix(line, "ExecStart=")
			item.Command = execStart
			// Extract binary path (handle - prefix)
			cmdParts := strings.Fields(strings.TrimPrefix(execStart, "-"))
			if len(cmdParts) > 0 {
				item.BinaryPath = cmdParts[0]
			}
		} else if strings.HasPrefix(line, "Description=") {
			item.Description = strings.TrimPrefix(line, "Description=")
		}
	}

	// Check if enabled
	item.Enabled = s.isSystemdUnitEnabled(item.Name)

	return nil
}

// parseBundle parses macOS bundles (kext, app, etc.)
func (s *PersistenceScanner) parseBundle(item *models.PersistenceItem) error {
	// Look for Info.plist
	infoPlistPath := filepath.Join(item.Path, "Contents", "Info.plist")
	if _, err := os.Stat(infoPlistPath); os.IsNotExist(err) {
		// Try root level
		infoPlistPath = filepath.Join(item.Path, "Info.plist")
	}

	if _, err := os.Stat(infoPlistPath); err == nil {
		file, err := os.Open(infoPlistPath)
		if err != nil {
			return err
		}
		defer file.Close()

		var data map[string]interface{}
		decoder := plist.NewDecoder(file)
		if err := decoder.Decode(&data); err == nil {
			if bundleID, ok := data["CFBundleIdentifier"].(string); ok {
				item.Name = bundleID
			}
			if version, ok := data["CFBundleShortVersionString"].(string); ok {
				item.Description = fmt.Sprintf("Version %s", version)
			}
			if executable, ok := data["CFBundleExecutable"].(string); ok {
				item.BinaryPath = filepath.Join(item.Path, "Contents", "MacOS", executable)
			}
		}
	}

	return nil
}

// checkCodeSigning checks code signing status on macOS
func (s *PersistenceScanner) checkCodeSigning(item *models.PersistenceItem) {
	if item.BinaryPath == "" {
		item.CodeSigning = models.CodeSigningUnknown
		return
	}

	// Use codesign to verify
	cmd := exec.Command("codesign", "-dv", "--verbose=4", item.BinaryPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		item.CodeSigning = models.CodeSigningNotSigned
		item.RiskReasons = append(item.RiskReasons, "Binary is not signed")
		return
	}

	outputStr := string(output)

	// Parse output
	if strings.Contains(outputStr, "Authority=Apple Root CA") {
		item.CodeSigning = models.CodeSigningAppleSystem
	} else if strings.Contains(outputStr, "Authority=Developer ID") {
		item.CodeSigning = models.CodeSigningDeveloperID
		// Extract team ID
		if match := regexp.MustCompile(`TeamIdentifier=([A-Z0-9]+)`).FindStringSubmatch(outputStr); len(match) > 1 {
			item.SigningTeamID = match[1]
		}
	} else if strings.Contains(outputStr, "Authority=Apple Mac OS Application Signing") {
		item.CodeSigning = models.CodeSigningAppleStore
	} else if strings.Contains(outputStr, "Signature=adhoc") {
		item.CodeSigning = models.CodeSigningAdHoc
		item.RiskReasons = append(item.RiskReasons, "Binary has ad-hoc signature")
	} else {
		item.CodeSigning = models.CodeSigningValid
	}

	// Extract signing identity
	if match := regexp.MustCompile(`Authority=(.+)`).FindStringSubmatch(outputStr); len(match) > 1 {
		item.SigningIdentity = match[1]
	}
}

// assessRisk assesses the risk level of a persistence item
func (s *PersistenceScanner) assessRisk(item *models.PersistenceItem, loc models.PersistenceLocation) {
	riskScore := 0.0

	// Base risk from location
	riskScore += loc.RiskFactor * 10

	// Check if known good
	if item.BinaryHash != "" {
		if s.knownGoodDB.IsKnownGood(item.BinaryHash) {
			item.IsKnownGood = true
			item.RiskLevel = models.PersistenceRiskClean
			return
		}
	}

	// Code signing assessment
	switch item.CodeSigning {
	case models.CodeSigningAppleSystem:
		riskScore -= 10
	case models.CodeSigningAppleStore, models.CodeSigningMicrosoft:
		riskScore -= 5
	case models.CodeSigningDeveloperID:
		riskScore -= 2
	case models.CodeSigningNotSigned:
		riskScore += 20
		item.RiskReasons = append(item.RiskReasons, "Binary is unsigned")
	case models.CodeSigningAdHoc:
		riskScore += 15
		item.RiskReasons = append(item.RiskReasons, "Binary has ad-hoc signature")
	case models.CodeSigningInvalid:
		riskScore += 30
		item.RiskReasons = append(item.RiskReasons, "Code signature is invalid")
	}

	// Check binary path
	if item.BinaryPath != "" {
		// Suspicious paths
		suspiciousPaths := []string{"/tmp/", "/var/tmp/", "~/.cache/", "/dev/shm/"}
		for _, sp := range suspiciousPaths {
			if strings.Contains(item.BinaryPath, sp) {
				riskScore += 25
				item.RiskReasons = append(item.RiskReasons, fmt.Sprintf("Binary in suspicious location: %s", sp))
			}
		}

		// Check if binary exists
		if _, err := os.Stat(item.BinaryPath); os.IsNotExist(err) {
			riskScore += 10
			item.RiskReasons = append(item.RiskReasons, "Referenced binary does not exist")
		}
	}

	// Check command for suspicious patterns
	if item.Command != "" {
		suspiciousPatterns := []struct {
			pattern string
			score   float64
			reason  string
		}{
			{`curl.*\|.*sh`, 30, "Downloads and executes script"},
			{`wget.*\|.*sh`, 30, "Downloads and executes script"},
			{`base64.*-d`, 20, "Base64 decode execution"},
			{`/dev/tcp/`, 35, "Bash network connection"},
			{`nc\s+-[el]`, 30, "Netcat listener/reverse shell"},
			{`python.*-c`, 15, "Python one-liner execution"},
			{`perl.*-e`, 15, "Perl one-liner execution"},
			{`osascript.*-e`, 15, "AppleScript execution"},
			{`launchctl.*bootout`, 20, "Manipulates launch services"},
		}

		for _, sp := range suspiciousPatterns {
			if matched, _ := regexp.MatchString(sp.pattern, item.Command); matched {
				riskScore += sp.score
				item.RiskReasons = append(item.RiskReasons, sp.reason)
			}
		}
	}

	// High-risk persistence types
	highRiskTypes := []models.PersistenceType{
		models.PersistenceKernelExtension,
		models.PersistenceAuthorizationPlugin,
		models.PersistenceLSAPackage,
		models.PersistenceAppInit,
		models.PersistenceWMISubscription,
	}
	for _, hrt := range highRiskTypes {
		if item.Type == hrt {
			riskScore += 15
			item.RiskReasons = append(item.RiskReasons, "High-risk persistence type")
			break
		}
	}

	// Determine risk level
	switch {
	case riskScore >= 50:
		item.RiskLevel = models.PersistenceRiskCritical
	case riskScore >= 35:
		item.RiskLevel = models.PersistenceRiskHigh
	case riskScore >= 20:
		item.RiskLevel = models.PersistenceRiskMedium
	case riskScore >= 10:
		item.RiskLevel = models.PersistenceRiskLow
	default:
		item.RiskLevel = models.PersistenceRiskClean
	}
}

// generateRecommendations generates security recommendations
func (s *PersistenceScanner) generateRecommendations(result *models.PersistenceScanResult) []string {
	var recommendations []string

	if result.CriticalItems > 0 {
		recommendations = append(recommendations, "Critical items detected - immediate investigation recommended")
	}

	// Count unsigned items
	unsignedCount := 0
	for _, item := range result.Items {
		if item.CodeSigning == models.CodeSigningNotSigned || item.CodeSigning == models.CodeSigningAdHoc {
			unsignedCount++
		}
	}
	if unsignedCount > 0 {
		recommendations = append(recommendations, fmt.Sprintf("%d unsigned/ad-hoc binaries found - verify legitimacy", unsignedCount))
	}

	// Check for suspicious locations
	suspiciousLocationCount := 0
	for _, item := range result.Items {
		for _, reason := range item.RiskReasons {
			if strings.Contains(reason, "suspicious location") {
				suspiciousLocationCount++
				break
			}
		}
	}
	if suspiciousLocationCount > 0 {
		recommendations = append(recommendations, fmt.Sprintf("%d items in suspicious locations - investigate immediately", suspiciousLocationCount))
	}

	if result.HighRiskItems > 0 {
		recommendations = append(recommendations, "Review high-risk persistence items and verify legitimacy")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No significant issues detected")
	}

	return recommendations
}

// Helper functions

func (s *PersistenceScanner) expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(s.homeDir, path[2:])
	}
	return path
}

func (s *PersistenceScanner) isBundle(path string) bool {
	bundleExts := []string{".app", ".kext", ".bundle", ".plugin", ".saver", ".mdimporter", ".qlgenerator"}
	for _, ext := range bundleExts {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func (s *PersistenceScanner) hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *PersistenceScanner) isSystemdUnitEnabled(unitName string) bool {
	cmd := exec.Command("systemctl", "is-enabled", unitName)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == "enabled"
}

func getHostname() string {
	hostname, _ := os.Hostname()
	return hostname
}

func getOSVersion() string {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("sw_vers", "-productVersion")
		if output, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	case "linux":
		if content, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				}
			}
		}
	}
	return runtime.GOOS
}

// KnownGoodDB provides a database of known good hashes
type KnownGoodDB struct {
	hashes map[string]models.KnownGoodHash
}

// NewKnownGoodDB creates a new known good database
func NewKnownGoodDB() *KnownGoodDB {
	db := &KnownGoodDB{
		hashes: make(map[string]models.KnownGoodHash),
	}
	db.loadBuiltinHashes()
	return db
}

// IsKnownGood checks if a hash is known good
func (db *KnownGoodDB) IsKnownGood(hash string) bool {
	_, exists := db.hashes[strings.ToLower(hash)]
	return exists
}

// AddHash adds a known good hash
func (db *KnownGoodDB) AddHash(hash models.KnownGoodHash) {
	db.hashes[strings.ToLower(hash.Hash)] = hash
}

// loadBuiltinHashes loads built-in known good hashes
func (db *KnownGoodDB) loadBuiltinHashes() {
	// Apple system binaries are verified via code signing instead
	// This is a placeholder for future known good hash database
}

// QuickScan performs a quick scan of high-priority locations only
func (s *PersistenceScanner) QuickScan(ctx context.Context) (*models.PersistenceScanResult, error) {
	startTime := time.Now()

	result := &models.PersistenceScanResult{
		ID:        uuid.New(),
		Platform:  s.platform,
		Hostname:  getHostname(),
		OSVersion: getOSVersion(),
		StartedAt: startTime,
		Items:     []models.PersistenceItem{},
		Errors:    []string{},
	}

	// Get only priority 1 locations
	locations := s.locationDB.GetLocations(s.platform)
	var priorityLocations []models.PersistenceLocation
	for _, loc := range locations {
		if loc.Priority == 1 {
			priorityLocations = append(priorityLocations, loc)
		}
	}

	s.logger.Info().
		Str("platform", string(s.platform)).
		Int("locations", len(priorityLocations)).
		Msg("starting quick persistence scan")

	for _, loc := range priorityLocations {
		items, err := s.scanLocation(ctx, loc)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", loc.Path, err))
			continue
		}
		result.Items = append(result.Items, items...)
	}

	// Count and finalize
	for _, item := range result.Items {
		result.TotalItems++
		switch item.RiskLevel {
		case models.PersistenceRiskCritical:
			result.CriticalItems++
		case models.PersistenceRiskHigh:
			result.HighRiskItems++
		case models.PersistenceRiskMedium:
			result.MediumRiskItems++
		case models.PersistenceRiskLow:
			result.LowRiskItems++
		default:
			result.CleanItems++
		}
	}

	result.CalculateRiskScore()
	result.Recommendations = s.generateRecommendations(result)

	completedAt := time.Now()
	result.CompletedAt = &completedAt
	result.Duration = completedAt.Sub(startTime).String()

	return result, nil
}

// ScanPath scans a specific path for persistence items
func (s *PersistenceScanner) ScanPath(ctx context.Context, path string) ([]models.PersistenceItem, error) {
	// Determine location type based on path
	loc := models.PersistenceLocation{
		Path:       path,
		Platform:   s.platform,
		RiskFactor: 1.0,
	}

	// Try to match to known location
	for _, knownLoc := range s.locationDB.GetLocations(s.platform) {
		if strings.Contains(path, s.expandPath(knownLoc.Path)) {
			loc = knownLoc
			loc.Path = path
			break
		}
	}

	return s.scanLocation(ctx, loc)
}
