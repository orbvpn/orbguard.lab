package desktop_security

import (
	"github.com/google/uuid"
	"orbguard-lab/internal/domain/models"
)

// PersistenceLocationDB provides access to persistence locations database
type PersistenceLocationDB struct {
	locations map[models.DesktopPlatform][]models.PersistenceLocation
}

// NewPersistenceLocationDB creates a new persistence location database
func NewPersistenceLocationDB() *PersistenceLocationDB {
	db := &PersistenceLocationDB{
		locations: make(map[models.DesktopPlatform][]models.PersistenceLocation),
	}
	db.loadLocations()
	return db
}

// GetLocations returns all locations for a platform
func (db *PersistenceLocationDB) GetLocations(platform models.DesktopPlatform) []models.PersistenceLocation {
	return db.locations[platform]
}

// GetLocationsByType returns locations by persistence type
func (db *PersistenceLocationDB) GetLocationsByType(platform models.DesktopPlatform, pType models.PersistenceType) []models.PersistenceLocation {
	var result []models.PersistenceLocation
	for _, loc := range db.locations[platform] {
		if loc.Type == pType {
			result = append(result, loc)
		}
	}
	return result
}

// Count returns total number of locations
func (db *PersistenceLocationDB) Count() int {
	total := 0
	for _, locs := range db.locations {
		total += len(locs)
	}
	return total
}

func (db *PersistenceLocationDB) loadLocations() {
	db.loadMacOSLocations()
	db.loadWindowsLocations()
	db.loadLinuxLocations()
}

// loadMacOSLocations loads macOS persistence locations (KnockKnock-style)
func (db *PersistenceLocationDB) loadMacOSLocations() {
	locations := []models.PersistenceLocation{
		// Launch Agents - User
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceLaunchAgent,
			Path:        "~/Library/LaunchAgents",
			Description: "User Launch Agents - Run at user login",
			Scope:       "user",
			FilePattern: "*.plist",
			Priority:    1,
			RiskFactor:  1.0,
		},
		// Launch Agents - System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceLaunchAgent,
			Path:        "/Library/LaunchAgents",
			Description: "System Launch Agents - Run for all users",
			Scope:       "system",
			FilePattern: "*.plist",
			Priority:    1,
			RiskFactor:  1.2,
		},
		// Launch Daemons - System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceLaunchDaemon,
			Path:        "/Library/LaunchDaemons",
			Description: "System Launch Daemons - Run at boot as root",
			Scope:       "system",
			FilePattern: "*.plist",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Launch Daemons - Apple System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceLaunchDaemon,
			Path:        "/System/Library/LaunchDaemons",
			Description: "Apple System Launch Daemons",
			Scope:       "system",
			FilePattern: "*.plist",
			Priority:    2,
			RiskFactor:  0.1, // Usually safe
		},
		// Login Items - User
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceLoginItem,
			Path:        "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
			Description: "macOS Login Items (modern)",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.0,
		},
		// Legacy Login Items
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceLoginItem,
			Path:        "~/Library/Preferences/com.apple.loginitems.plist",
			Description: "macOS Login Items (legacy plist)",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.0,
		},
		// Kernel Extensions
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceKernelExtension,
			Path:        "/Library/Extensions",
			Description: "Third-party Kernel Extensions",
			Scope:       "system",
			FilePattern: "*.kext",
			Priority:    1,
			RiskFactor:  2.0, // High risk - kernel level
		},
		// System Extensions
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceSystemExtension,
			Path:        "/Library/SystemExtensions",
			Description: "System Extensions (modern replacement for kexts)",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Cron Jobs - User
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceCronJob,
			Path:        "/var/at/tabs",
			Description: "User crontabs",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Cron Jobs - System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceCronJob,
			Path:        "/etc/crontab",
			Description: "System crontab",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Cron Directories
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceCronJob,
			Path:        "/etc/cron.d",
			Description: "Cron drop-in directory",
			Scope:       "system",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Periodic Scripts
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistencePeriodicScript,
			Path:        "/etc/periodic/daily",
			Description: "Daily periodic scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistencePeriodicScript,
			Path:        "/etc/periodic/weekly",
			Description: "Weekly periodic scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistencePeriodicScript,
			Path:        "/etc/periodic/monthly",
			Description: "Monthly periodic scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.2,
		},
		// At Jobs
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceAtJob,
			Path:        "/var/at/jobs",
			Description: "Scheduled at jobs",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.3,
		},
		// Authorization Plugins
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceAuthorizationPlugin,
			Path:        "/Library/Security/SecurityAgentPlugins",
			Description: "Security Agent Plugins (auth)",
			Scope:       "system",
			FilePattern: "*.bundle",
			Priority:    1,
			RiskFactor:  2.0, // High risk
		},
		// Directory Services Plugins
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceDirectoryService,
			Path:        "/Library/DirectoryServices/PlugIns",
			Description: "Directory Services Plugins",
			Scope:       "system",
			FilePattern: "*.dsplug",
			Priority:    2,
			RiskFactor:  1.5,
		},
		// Spotlight Importers
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceSpotlightImporter,
			Path:        "/Library/Spotlight",
			Description: "Spotlight Importers",
			Scope:       "system",
			FilePattern: "*.mdimporter",
			Priority:    2,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceSpotlightImporter,
			Path:        "~/Library/Spotlight",
			Description: "User Spotlight Importers",
			Scope:       "user",
			FilePattern: "*.mdimporter",
			Priority:    2,
			RiskFactor:  1.2,
		},
		// QuickLook Plugins
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceQuickLookPlugin,
			Path:        "/Library/QuickLook",
			Description: "QuickLook Plugins",
			Scope:       "system",
			FilePattern: "*.qlgenerator",
			Priority:    2,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceQuickLookPlugin,
			Path:        "~/Library/QuickLook",
			Description: "User QuickLook Plugins",
			Scope:       "user",
			FilePattern: "*.qlgenerator",
			Priority:    2,
			RiskFactor:  1.2,
		},
		// Screen Savers
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceScreenSaver,
			Path:        "/Library/Screen Savers",
			Description: "System Screen Savers",
			Scope:       "system",
			FilePattern: "*.saver",
			Priority:    3,
			RiskFactor:  1.0,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceScreenSaver,
			Path:        "~/Library/Screen Savers",
			Description: "User Screen Savers",
			Scope:       "user",
			FilePattern: "*.saver",
			Priority:    3,
			RiskFactor:  1.0,
		},
		// Shell Config Files
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "~/.zshrc",
			Description: "Zsh config - runs on shell start",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "~/.zprofile",
			Description: "Zsh profile - runs on login",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "~/.zshenv",
			Description: "Zsh env - runs always",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.4,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "~/.bashrc",
			Description: "Bash config",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "~/.bash_profile",
			Description: "Bash profile",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "/etc/zshrc",
			Description: "System Zsh config",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceShellConfig,
			Path:        "/etc/bashrc",
			Description: "System Bash config",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Emond
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceEmond,
			Path:        "/etc/emond.d/rules",
			Description: "Event Monitor Daemon rules",
			Scope:       "system",
			FilePattern: "*.plist",
			Priority:    2,
			RiskFactor:  1.5,
		},
		// Browser Extensions - Safari
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceBrowserExtension,
			Path:        "~/Library/Safari/Extensions",
			Description: "Safari Extensions",
			Scope:       "user",
			FilePattern: "*.safariextz",
			Priority:    2,
			RiskFactor:  1.1,
		},
		// Browser Extensions - Chrome
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceBrowserExtension,
			Path:        "~/Library/Application Support/Google/Chrome/Default/Extensions",
			Description: "Chrome Extensions",
			Scope:       "user",
			Priority:    2,
			RiskFactor:  1.1,
		},
		// Browser Extensions - Firefox
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformMacOS,
			Type:        models.PersistenceBrowserExtension,
			Path:        "~/Library/Application Support/Firefox/Profiles",
			Description: "Firefox Extensions",
			Scope:       "user",
			FilePattern: "*/extensions",
			Priority:    2,
			RiskFactor:  1.1,
		},
	}

	db.locations[models.DesktopPlatformMacOS] = locations
}

// loadWindowsLocations loads Windows persistence locations
func (db *PersistenceLocationDB) loadWindowsLocations() {
	locations := []models.PersistenceLocation{
		// Registry Run Keys - Current User
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceRegistryRun,
			Path:        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			Description: "Current User Run key - programs run at login",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Registry Run Keys - Local Machine
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceRegistryRun,
			Path:        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			Description: "Local Machine Run key - programs run at boot",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Registry RunOnce Keys
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceRegistryRunOnce,
			Path:        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			Description: "User RunOnce key",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.4,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceRegistryRunOnce,
			Path:        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
			Description: "Machine RunOnce key",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Startup Folders
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceStartupFolder,
			Path:        "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
			Description: "User Startup folder",
			Scope:       "user",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceStartupFolder,
			Path:        "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
			Description: "All Users Startup folder",
			Scope:       "system",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.4,
		},
		// Scheduled Tasks
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceScheduledTask,
			Path:        "C:\\Windows\\System32\\Tasks",
			Description: "Windows Scheduled Tasks",
			Scope:       "system",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Services
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceService,
			Path:        "HKLM\\System\\CurrentControlSet\\Services",
			Description: "Windows Services",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// WMI Subscriptions
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceWMISubscription,
			Path:        "WMI:root\\subscription",
			Description: "WMI Event Subscriptions",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.8, // Often used by malware
		},
		// AppInit DLLs
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceAppInit,
			Path:        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs",
			Description: "AppInit DLLs - loaded into all processes",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  2.0, // High risk
		},
		// Image File Execution Options
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceImageFileExecution,
			Path:        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
			Description: "IFEO - debugger hijacking",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.8,
		},
		// Print Monitors
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistencePrintMonitor,
			Path:        "HKLM\\System\\CurrentControlSet\\Control\\Print\\Monitors",
			Description: "Print Monitor DLLs",
			Scope:       "system",
			Priority:    2,
			RiskFactor:  1.5,
		},
		// LSA Packages
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceLSAPackage,
			Path:        "HKLM\\System\\CurrentControlSet\\Control\\Lsa",
			Description: "LSA Authentication Packages",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  2.0, // High risk
		},
		// Winlogon
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceWinlogon,
			Path:        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
			Description: "Winlogon Shell/Userinit",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.8,
		},
		// Netsh Helper DLLs
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceNetshHelper,
			Path:        "HKLM\\Software\\Microsoft\\NetSh",
			Description: "Netsh Helper DLLs",
			Scope:       "system",
			Priority:    2,
			RiskFactor:  1.5,
		},
		// COM Hijacking
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceCOMHijack,
			Path:        "HKCU\\Software\\Classes\\CLSID",
			Description: "User COM Object Hijacking",
			Scope:       "user",
			Priority:    2,
			RiskFactor:  1.6,
		},
		// BITS Jobs
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceBITSJob,
			Path:        "BITS:Jobs",
			Description: "Background Intelligent Transfer Service Jobs",
			Scope:       "system",
			Priority:    2,
			RiskFactor:  1.4,
		},
		// Browser Extensions - Chrome
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceBrowserExtension,
			Path:        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Extensions",
			Description: "Chrome Extensions",
			Scope:       "user",
			Priority:    2,
			RiskFactor:  1.1,
		},
		// Browser Extensions - Edge
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceBrowserExtension,
			Path:        "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Extensions",
			Description: "Edge Extensions",
			Scope:       "user",
			Priority:    2,
			RiskFactor:  1.1,
		},
		// Browser Extensions - Firefox
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformWindows,
			Type:        models.PersistenceBrowserExtension,
			Path:        "%APPDATA%\\Mozilla\\Firefox\\Profiles",
			Description: "Firefox Extensions",
			Scope:       "user",
			FilePattern: "*/extensions",
			Priority:    2,
			RiskFactor:  1.1,
		},
	}

	db.locations[models.DesktopPlatformWindows] = locations
}

// loadLinuxLocations loads Linux persistence locations
func (db *PersistenceLocationDB) loadLinuxLocations() {
	locations := []models.PersistenceLocation{
		// Systemd Services - System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceSystemdService,
			Path:        "/etc/systemd/system",
			Description: "System systemd services",
			Scope:       "system",
			FilePattern: "*.service",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Systemd Services - User
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceSystemdService,
			Path:        "~/.config/systemd/user",
			Description: "User systemd services",
			Scope:       "user",
			FilePattern: "*.service",
			Priority:    1,
			RiskFactor:  1.2,
		},
		// Systemd Services - Lib
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceSystemdService,
			Path:        "/lib/systemd/system",
			Description: "Package-installed systemd services",
			Scope:       "system",
			FilePattern: "*.service",
			Priority:    2,
			RiskFactor:  1.0,
		},
		// Systemd Timers
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceSystemdTimer,
			Path:        "/etc/systemd/system",
			Description: "System systemd timers",
			Scope:       "system",
			FilePattern: "*.timer",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Init.d
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceInitD,
			Path:        "/etc/init.d",
			Description: "SysV init scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// rc.local
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceRcLocal,
			Path:        "/etc/rc.local",
			Description: "rc.local startup script",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Crontab - System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/etc/crontab",
			Description: "System crontab",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.4,
		},
		// Cron directories
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/etc/cron.d",
			Description: "Cron drop-in directory",
			Scope:       "system",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/etc/cron.daily",
			Description: "Daily cron scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/etc/cron.hourly",
			Description: "Hourly cron scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.2,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/etc/cron.weekly",
			Description: "Weekly cron scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.1,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/etc/cron.monthly",
			Description: "Monthly cron scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.1,
		},
		// User crontabs
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceCrontab,
			Path:        "/var/spool/cron/crontabs",
			Description: "User crontabs",
			Scope:       "user",
			FilePattern: "*",
			Priority:    1,
			RiskFactor:  1.3,
		},
		// Anacron
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceAnacron,
			Path:        "/etc/anacrontab",
			Description: "Anacron configuration",
			Scope:       "system",
			Priority:    2,
			RiskFactor:  1.2,
		},
		// XDG Autostart - System
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceXDGAutostart,
			Path:        "/etc/xdg/autostart",
			Description: "System autostart applications",
			Scope:       "system",
			FilePattern: "*.desktop",
			Priority:    1,
			RiskFactor:  1.2,
		},
		// XDG Autostart - User
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceXDGAutostart,
			Path:        "~/.config/autostart",
			Description: "User autostart applications",
			Scope:       "user",
			FilePattern: "*.desktop",
			Priority:    1,
			RiskFactor:  1.1,
		},
		// Shell config - Bash
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBashProfile,
			Path:        "~/.bashrc",
			Description: "User bash config",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBashProfile,
			Path:        "~/.bash_profile",
			Description: "User bash profile",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBashProfile,
			Path:        "~/.profile",
			Description: "User profile",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.3,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBashProfile,
			Path:        "/etc/profile",
			Description: "System profile",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBashProfile,
			Path:        "/etc/profile.d",
			Description: "System profile drop-in",
			Scope:       "system",
			FilePattern: "*.sh",
			Priority:    1,
			RiskFactor:  1.4,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBashProfile,
			Path:        "/etc/bash.bashrc",
			Description: "System bash config",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.5,
		},
		// Modprobe
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceModprobe,
			Path:        "/etc/modprobe.d",
			Description: "Kernel module configuration",
			Scope:       "system",
			FilePattern: "*.conf",
			Priority:    2,
			RiskFactor:  1.5,
		},
		// Udev rules
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceUdevRule,
			Path:        "/etc/udev/rules.d",
			Description: "Udev rules - device events",
			Scope:       "system",
			FilePattern: "*.rules",
			Priority:    2,
			RiskFactor:  1.4,
		},
		// MOTD
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceMotd,
			Path:        "/etc/update-motd.d",
			Description: "Dynamic MOTD scripts",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.3,
		},
		// SSHRC
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceSSHRC,
			Path:        "/etc/ssh/sshrc",
			Description: "SSH RC script - runs on SSH login",
			Scope:       "system",
			Priority:    1,
			RiskFactor:  1.6,
		},
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceSSHRC,
			Path:        "~/.ssh/rc",
			Description: "User SSH RC script",
			Scope:       "user",
			Priority:    1,
			RiskFactor:  1.4,
		},
		// APT Hooks
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceAPTHook,
			Path:        "/etc/apt/apt.conf.d",
			Description: "APT configuration hooks",
			Scope:       "system",
			FilePattern: "*",
			Priority:    2,
			RiskFactor:  1.3,
		},
		// Browser Extensions - Chrome
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBrowserExtension,
			Path:        "~/.config/google-chrome/Default/Extensions",
			Description: "Chrome Extensions",
			Scope:       "user",
			Priority:    2,
			RiskFactor:  1.1,
		},
		// Browser Extensions - Firefox
		{
			ID:          uuid.New(),
			Platform:    models.DesktopPlatformLinux,
			Type:        models.PersistenceBrowserExtension,
			Path:        "~/.mozilla/firefox",
			Description: "Firefox Extensions",
			Scope:       "user",
			FilePattern: "*/extensions",
			Priority:    2,
			RiskFactor:  1.1,
		},
	}

	db.locations[models.DesktopPlatformLinux] = locations
}
