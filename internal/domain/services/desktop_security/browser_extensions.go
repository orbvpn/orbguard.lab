package desktop_security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// BrowserExtensionScanner scans for browser extensions across all browsers
type BrowserExtensionScanner struct {
	logger   *logger.Logger
	platform models.DesktopPlatform
	homeDir  string

	// Known malicious extensions
	knownMalicious map[string]string // extensionID -> reason
}

// BrowserProfile represents a browser profile
type BrowserProfile struct {
	Browser     string `json:"browser"`
	ProfileName string `json:"profile_name"`
	ProfilePath string `json:"profile_path"`
}

// NewBrowserExtensionScanner creates a new browser extension scanner
func NewBrowserExtensionScanner(log *logger.Logger) *BrowserExtensionScanner {
	scanner := &BrowserExtensionScanner{
		logger:         log.WithComponent("browser-extension-scanner"),
		platform:       detectPlatform(),
		homeDir:        getHomeDir(),
		knownMalicious: make(map[string]string),
	}
	scanner.loadKnownMalicious()
	return scanner
}

// loadKnownMalicious loads known malicious extension IDs
func (s *BrowserExtensionScanner) loadKnownMalicious() {
	// Known malicious Chrome extension IDs
	maliciousExtensions := map[string]string{
		// Examples of known malicious extensions (not exhaustive)
		"example-malicious-id": "Known crypto miner",
	}

	for id, reason := range maliciousExtensions {
		s.knownMalicious[id] = reason
	}
}

// Scan scans all browsers for extensions
func (s *BrowserExtensionScanner) Scan(ctx context.Context) ([]models.BrowserExtension, error) {
	var allExtensions []models.BrowserExtension

	// Scan each browser
	browsers := []struct {
		name    string
		scanner func(context.Context) ([]models.BrowserExtension, error)
	}{
		{"Chrome", s.scanChrome},
		{"Firefox", s.scanFirefox},
		{"Safari", s.scanSafari},
		{"Edge", s.scanEdge},
		{"Brave", s.scanBrave},
		{"Opera", s.scanOpera},
	}

	for _, browser := range browsers {
		extensions, err := browser.scanner(ctx)
		if err != nil {
			s.logger.Debug().Err(err).Str("browser", browser.name).Msg("scan failed")
			continue
		}
		allExtensions = append(allExtensions, extensions...)
	}

	s.logger.Info().
		Int("total_extensions", len(allExtensions)).
		Msg("browser extension scan complete")

	return allExtensions, nil
}

// scanChrome scans Chrome/Chromium extensions
func (s *BrowserExtensionScanner) scanChrome(ctx context.Context) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	// Get Chrome profile paths
	chromePaths := s.getChromePaths()

	for _, chromePath := range chromePaths {
		// Find all profiles
		profiles, err := s.findChromeProfiles(chromePath)
		if err != nil {
			continue
		}

		for _, profile := range profiles {
			extPath := filepath.Join(profile.ProfilePath, "Extensions")
			if _, err := os.Stat(extPath); os.IsNotExist(err) {
				continue
			}

			profileExtensions, err := s.scanChromeExtensionsDir(extPath, "chrome", profile.ProfileName)
			if err != nil {
				continue
			}
			extensions = append(extensions, profileExtensions...)
		}
	}

	return extensions, nil
}

// getChromePaths returns Chrome data paths based on platform
func (s *BrowserExtensionScanner) getChromePaths() []string {
	switch s.platform {
	case models.DesktopPlatformMacOS:
		return []string{
			filepath.Join(s.homeDir, "Library/Application Support/Google/Chrome"),
			filepath.Join(s.homeDir, "Library/Application Support/Chromium"),
		}
	case models.DesktopPlatformWindows:
		localAppData := os.Getenv("LOCALAPPDATA")
		return []string{
			filepath.Join(localAppData, "Google/Chrome/User Data"),
			filepath.Join(localAppData, "Chromium/User Data"),
		}
	case models.DesktopPlatformLinux:
		return []string{
			filepath.Join(s.homeDir, ".config/google-chrome"),
			filepath.Join(s.homeDir, ".config/chromium"),
		}
	}
	return nil
}

// findChromeProfiles finds all Chrome profiles
func (s *BrowserExtensionScanner) findChromeProfiles(chromePath string) ([]BrowserProfile, error) {
	var profiles []BrowserProfile

	entries, err := os.ReadDir(chromePath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if name == "Default" || strings.HasPrefix(name, "Profile ") {
			profiles = append(profiles, BrowserProfile{
				Browser:     "chrome",
				ProfileName: name,
				ProfilePath: filepath.Join(chromePath, name),
			})
		}
	}

	return profiles, nil
}

// scanChromeExtensionsDir scans a Chrome extensions directory
func (s *BrowserExtensionScanner) scanChromeExtensionsDir(extPath, browser, profile string) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	entries, err := os.ReadDir(extPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		extensionID := entry.Name()
		extDir := filepath.Join(extPath, extensionID)

		// Find latest version
		versions, err := os.ReadDir(extDir)
		if err != nil || len(versions) == 0 {
			continue
		}

		// Get the latest version directory
		var latestVersion string
		for _, v := range versions {
			if v.IsDir() && v.Name() > latestVersion {
				latestVersion = v.Name()
			}
		}

		if latestVersion == "" {
			continue
		}

		versionDir := filepath.Join(extDir, latestVersion)
		ext, err := s.parseChromeExtension(versionDir, extensionID, browser, profile)
		if err != nil {
			continue
		}

		extensions = append(extensions, *ext)
	}

	return extensions, nil
}

// parseChromeExtension parses a Chrome extension manifest
func (s *BrowserExtensionScanner) parseChromeExtension(versionDir, extensionID, browser, profile string) (*models.BrowserExtension, error) {
	manifestPath := filepath.Join(versionDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}

	var manifest struct {
		Name            string   `json:"name"`
		Version         string   `json:"version"`
		Description     string   `json:"description"`
		Author          string   `json:"author"`
		Homepage        string   `json:"homepage_url"`
		Permissions     []string `json:"permissions"`
		HostPermissions []string `json:"host_permissions"`
		ContentScripts  []struct {
			Matches []string `json:"matches"`
		} `json:"content_scripts"`
		Background struct {
			ServiceWorker string   `json:"service_worker"`
			Scripts       []string `json:"scripts"`
		} `json:"background"`
	}

	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}

	ext := &models.BrowserExtension{
		ID:              uuid.New(),
		Browser:         browser,
		ExtensionID:     extensionID,
		Name:            manifest.Name,
		Version:         manifest.Version,
		Description:     manifest.Description,
		Author:          manifest.Author,
		Homepage:        manifest.Homepage,
		Permissions:     manifest.Permissions,
		HostPermissions: manifest.HostPermissions,
		InstallPath:     versionDir,
		ProfilePath:     filepath.Dir(filepath.Dir(versionDir)),
		Enabled:         true, // Assume enabled if present
		FoundAt:         time.Now(),
	}

	// Check if from web store
	ext.IsFromStore = s.isFromWebStore(extensionID, browser)

	// Assess risk
	s.assessExtensionRisk(ext)

	return ext, nil
}

// isFromWebStore checks if extension is from official store
func (s *BrowserExtensionScanner) isFromWebStore(extensionID, browser string) bool {
	// Chrome Web Store extensions have specific ID patterns
	// and are typically 32 lowercase alphanumeric characters
	if browser == "chrome" || browser == "edge" || browser == "brave" {
		matched, _ := regexp.MatchString(`^[a-z]{32}$`, extensionID)
		return matched
	}
	return false
}

// assessExtensionRisk assesses the risk level of an extension
func (s *BrowserExtensionScanner) assessExtensionRisk(ext *models.BrowserExtension) {
	riskScore := 0.0

	// Check known malicious
	if reason, known := s.knownMalicious[ext.ExtensionID]; known {
		ext.IsKnownMalware = true
		ext.RiskLevel = models.PersistenceRiskCritical
		ext.RiskReasons = append(ext.RiskReasons, reason)
		return
	}

	// Dangerous permissions
	dangerousPerms := map[string]float64{
		"<all_urls>":              20,
		"http://*/*":              15,
		"https://*/*":             10,
		"webRequest":              15,
		"webRequestBlocking":      25,
		"cookies":                 15,
		"history":                 10,
		"tabs":                    5,
		"storage":                 2,
		"activeTab":               5,
		"clipboardRead":           15,
		"clipboardWrite":          10,
		"nativeMessaging":         20,
		"management":              15,
		"privacy":                 10,
		"proxy":                   15,
		"debugger":                25,
		"contentSettings":         10,
		"downloads":               10,
		"bookmarks":               5,
		"geolocation":             10,
		"desktopCapture":          20,
		"tabCapture":              20,
		"identity":                15,
		"identity.email":          10,
	}

	for _, perm := range ext.Permissions {
		if score, dangerous := dangerousPerms[perm]; dangerous {
			riskScore += score
			ext.RiskReasons = append(ext.RiskReasons, fmt.Sprintf("Permission: %s", perm))
		}
	}

	// Host permissions
	for _, host := range ext.HostPermissions {
		if host == "<all_urls>" || host == "*://*/*" {
			riskScore += 20
			ext.RiskReasons = append(ext.RiskReasons, "Access to all websites")
		} else if strings.Contains(host, "*") {
			riskScore += 5
		}
	}

	// Not from store is risky
	if !ext.IsFromStore {
		riskScore += 15
		ext.RiskReasons = append(ext.RiskReasons, "Not from official store")
	}

	// Determine risk level
	switch {
	case riskScore >= 50:
		ext.RiskLevel = models.PersistenceRiskHigh
	case riskScore >= 30:
		ext.RiskLevel = models.PersistenceRiskMedium
	case riskScore >= 10:
		ext.RiskLevel = models.PersistenceRiskLow
	default:
		ext.RiskLevel = models.PersistenceRiskClean
	}
}

// scanFirefox scans Firefox extensions
func (s *BrowserExtensionScanner) scanFirefox(ctx context.Context) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	firefoxPath := s.getFirefoxPath()
	if firefoxPath == "" {
		return extensions, nil
	}

	// Find profiles
	profilesPath := filepath.Join(firefoxPath, "profiles.ini")
	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		return extensions, nil
	}

	// Scan profile directories
	entries, err := os.ReadDir(firefoxPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		if !strings.Contains(entry.Name(), ".") {
			continue // Firefox profiles have format "xxxx.ProfileName"
		}

		profilePath := filepath.Join(firefoxPath, entry.Name())
		profileExts, err := s.scanFirefoxProfile(profilePath, entry.Name())
		if err != nil {
			continue
		}
		extensions = append(extensions, profileExts...)
	}

	return extensions, nil
}

// getFirefoxPath returns Firefox profile path
func (s *BrowserExtensionScanner) getFirefoxPath() string {
	switch s.platform {
	case models.DesktopPlatformMacOS:
		return filepath.Join(s.homeDir, "Library/Application Support/Firefox/Profiles")
	case models.DesktopPlatformWindows:
		appData := os.Getenv("APPDATA")
		return filepath.Join(appData, "Mozilla/Firefox/Profiles")
	case models.DesktopPlatformLinux:
		return filepath.Join(s.homeDir, ".mozilla/firefox")
	}
	return ""
}

// scanFirefoxProfile scans a Firefox profile for extensions
func (s *BrowserExtensionScanner) scanFirefoxProfile(profilePath, profileName string) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	// Check extensions.json
	extFile := filepath.Join(profilePath, "extensions.json")
	data, err := os.ReadFile(extFile)
	if err != nil {
		return extensions, nil
	}

	var extData struct {
		Addons []struct {
			ID              string `json:"id"`
			Name            string `json:"name,omitempty"`
			DefaultLocale   struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"defaultLocale"`
			Version         string   `json:"version"`
			Type            string   `json:"type"`
			Active          bool     `json:"active"`
			Path            string   `json:"path"`
			UserDisabled    bool     `json:"userDisabled"`
			SourceURI       string   `json:"sourceURI"`
			Permissions     []string `json:"userPermissions"`
		} `json:"addons"`
	}

	if err := json.Unmarshal(data, &extData); err != nil {
		return nil, err
	}

	for _, addon := range extData.Addons {
		if addon.Type != "extension" {
			continue
		}

		name := addon.Name
		if name == "" {
			name = addon.DefaultLocale.Name
		}

		ext := models.BrowserExtension{
			ID:          uuid.New(),
			Browser:     "firefox",
			ExtensionID: addon.ID,
			Name:        name,
			Version:     addon.Version,
			Description: addon.DefaultLocale.Description,
			Permissions: addon.Permissions,
			InstallPath: addon.Path,
			ProfilePath: profilePath,
			Enabled:     addon.Active && !addon.UserDisabled,
			FoundAt:     time.Now(),
		}

		// Check if from AMO (addons.mozilla.org)
		ext.IsFromStore = strings.Contains(addon.SourceURI, "addons.mozilla.org")

		s.assessExtensionRisk(&ext)
		extensions = append(extensions, ext)
	}

	return extensions, nil
}

// scanSafari scans Safari extensions (macOS only)
func (s *BrowserExtensionScanner) scanSafari(ctx context.Context) ([]models.BrowserExtension, error) {
	if s.platform != models.DesktopPlatformMacOS {
		return nil, nil
	}

	var extensions []models.BrowserExtension

	// Modern Safari extensions are App Extensions
	extPaths := []string{
		filepath.Join(s.homeDir, "Library/Safari/Extensions"),
		filepath.Join(s.homeDir, "Library/Containers"),
	}

	for _, extPath := range extPaths {
		if _, err := os.Stat(extPath); os.IsNotExist(err) {
			continue
		}

		// Walk the extensions directory
		_ = filepath.Walk(extPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if strings.HasSuffix(path, ".safariextz") || strings.HasSuffix(path, ".appex") {
				ext := models.BrowserExtension{
					ID:          uuid.New(),
					Browser:     "safari",
					ExtensionID: filepath.Base(path),
					Name:        strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
					InstallPath: path,
					Enabled:     true,
					FoundAt:     time.Now(),
				}
				extensions = append(extensions, ext)
			}
			return nil
		})
	}

	return extensions, nil
}

// scanEdge scans Microsoft Edge extensions
func (s *BrowserExtensionScanner) scanEdge(ctx context.Context) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	var edgePath string
	switch s.platform {
	case models.DesktopPlatformMacOS:
		edgePath = filepath.Join(s.homeDir, "Library/Application Support/Microsoft Edge")
	case models.DesktopPlatformWindows:
		localAppData := os.Getenv("LOCALAPPDATA")
		edgePath = filepath.Join(localAppData, "Microsoft/Edge/User Data")
	case models.DesktopPlatformLinux:
		edgePath = filepath.Join(s.homeDir, ".config/microsoft-edge")
	}

	if edgePath == "" {
		return extensions, nil
	}

	profiles, err := s.findChromeProfiles(edgePath) // Edge uses same structure as Chrome
	if err != nil {
		return extensions, nil
	}

	for _, profile := range profiles {
		extPath := filepath.Join(profile.ProfilePath, "Extensions")
		if _, err := os.Stat(extPath); os.IsNotExist(err) {
			continue
		}

		profileExtensions, err := s.scanChromeExtensionsDir(extPath, "edge", profile.ProfileName)
		if err != nil {
			continue
		}
		extensions = append(extensions, profileExtensions...)
	}

	return extensions, nil
}

// scanBrave scans Brave browser extensions
func (s *BrowserExtensionScanner) scanBrave(ctx context.Context) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	var bravePath string
	switch s.platform {
	case models.DesktopPlatformMacOS:
		bravePath = filepath.Join(s.homeDir, "Library/Application Support/BraveSoftware/Brave-Browser")
	case models.DesktopPlatformWindows:
		localAppData := os.Getenv("LOCALAPPDATA")
		bravePath = filepath.Join(localAppData, "BraveSoftware/Brave-Browser/User Data")
	case models.DesktopPlatformLinux:
		bravePath = filepath.Join(s.homeDir, ".config/BraveSoftware/Brave-Browser")
	}

	if bravePath == "" {
		return extensions, nil
	}

	profiles, err := s.findChromeProfiles(bravePath)
	if err != nil {
		return extensions, nil
	}

	for _, profile := range profiles {
		extPath := filepath.Join(profile.ProfilePath, "Extensions")
		if _, err := os.Stat(extPath); os.IsNotExist(err) {
			continue
		}

		profileExtensions, err := s.scanChromeExtensionsDir(extPath, "brave", profile.ProfileName)
		if err != nil {
			continue
		}
		extensions = append(extensions, profileExtensions...)
	}

	return extensions, nil
}

// scanOpera scans Opera browser extensions
func (s *BrowserExtensionScanner) scanOpera(ctx context.Context) ([]models.BrowserExtension, error) {
	var extensions []models.BrowserExtension

	var operaPath string
	switch s.platform {
	case models.DesktopPlatformMacOS:
		operaPath = filepath.Join(s.homeDir, "Library/Application Support/com.operasoftware.Opera")
	case models.DesktopPlatformWindows:
		appData := os.Getenv("APPDATA")
		operaPath = filepath.Join(appData, "Opera Software/Opera Stable")
	case models.DesktopPlatformLinux:
		operaPath = filepath.Join(s.homeDir, ".config/opera")
	}

	if operaPath == "" {
		return extensions, nil
	}

	extPath := filepath.Join(operaPath, "Extensions")
	if _, err := os.Stat(extPath); os.IsNotExist(err) {
		return extensions, nil
	}

	return s.scanChromeExtensionsDir(extPath, "opera", "Default")
}

// GetHighRiskExtensions filters extensions by risk level
func (s *BrowserExtensionScanner) GetHighRiskExtensions(extensions []models.BrowserExtension) []models.BrowserExtension {
	var highRisk []models.BrowserExtension

	for _, ext := range extensions {
		if ext.RiskLevel == models.PersistenceRiskHigh || ext.RiskLevel == models.PersistenceRiskCritical || ext.IsKnownMalware {
			highRisk = append(highRisk, ext)
		}
	}

	return highRisk
}

// GetBrowserCount returns count of extensions per browser
func (s *BrowserExtensionScanner) GetBrowserCount(extensions []models.BrowserExtension) map[string]int {
	counts := make(map[string]int)

	for _, ext := range extensions {
		counts[ext.Browser]++
	}

	return counts
}

// init platform detection
func init() {
	_ = runtime.GOOS
}
