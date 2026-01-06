package models

import (
	"sort"
	"time"
)

// TimelineEventType represents the type of timeline event
type TimelineEventType string

const (
	TimelineEventTypeShutdown     TimelineEventType = "shutdown"
	TimelineEventTypeReboot       TimelineEventType = "reboot"
	TimelineEventTypeProcessStart TimelineEventType = "process_start"
	TimelineEventTypeProcessEnd   TimelineEventType = "process_end"
	TimelineEventTypeFileCreated  TimelineEventType = "file_created"
	TimelineEventTypeFileModified TimelineEventType = "file_modified"
	TimelineEventTypeFileDeleted  TimelineEventType = "file_deleted"
	TimelineEventTypeNetworkConn  TimelineEventType = "network_connection"
	TimelineEventTypeAppInstall   TimelineEventType = "app_install"
	TimelineEventTypeAppUninstall TimelineEventType = "app_uninstall"
	TimelineEventTypeAppUpdate    TimelineEventType = "app_update"
	TimelineEventTypeAppLaunch    TimelineEventType = "app_launch"
	TimelineEventTypeCrash        TimelineEventType = "crash"
	TimelineEventTypeSMS          TimelineEventType = "sms"
	TimelineEventTypeCall         TimelineEventType = "call"
	TimelineEventTypeBackup       TimelineEventType = "backup"
	TimelineEventTypeRestore      TimelineEventType = "restore"
	TimelineEventTypeExploit      TimelineEventType = "exploit"
	TimelineEventTypeAnomaly      TimelineEventType = "anomaly"
)

// TimelineEvent represents an event in the forensic timeline
type TimelineEvent struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	Type        TimelineEventType `json:"type"`
	Source      string            `json:"source"` // shutdown_log, backup, sysdiagnose, logcat, etc.
	Title       string            `json:"title"`
	Description string            `json:"description"`
	ProcessName string            `json:"process_name,omitempty"`
	PID         int               `json:"pid,omitempty"`
	Path        string            `json:"path,omitempty"`
	BundleID    string            `json:"bundle_id,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Port        int               `json:"port,omitempty"`
	IsSuspicious bool             `json:"is_suspicious"`
	Severity    ForensicSeverity  `json:"severity,omitempty"`
	AnomalyID   string            `json:"anomaly_id,omitempty"`
	RelatedIDs  []string          `json:"related_ids,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

// Timeline represents a chronological sequence of forensic events
type Timeline struct {
	Events         []TimelineEvent `json:"events"`
	StartTime      time.Time       `json:"start_time"`
	EndTime        time.Time       `json:"end_time"`
	TotalEvents    int             `json:"total_events"`
	SuspiciousCount int            `json:"suspicious_count"`
	Sources        []string        `json:"sources"`
}

// NewTimeline creates a new timeline
func NewTimeline() *Timeline {
	return &Timeline{
		Events:  make([]TimelineEvent, 0),
		Sources: make([]string, 0),
	}
}

// AddEvent adds an event to the timeline
func (t *Timeline) AddEvent(event TimelineEvent) {
	t.Events = append(t.Events, event)
	t.TotalEvents = len(t.Events)

	if event.IsSuspicious {
		t.SuspiciousCount++
	}

	// Track sources
	sourceExists := false
	for _, s := range t.Sources {
		if s == event.Source {
			sourceExists = true
			break
		}
	}
	if !sourceExists && event.Source != "" {
		t.Sources = append(t.Sources, event.Source)
	}
}

// Sort sorts events chronologically
func (t *Timeline) Sort() {
	sort.Slice(t.Events, func(i, j int) bool {
		return t.Events[i].Timestamp.Before(t.Events[j].Timestamp)
	})

	if len(t.Events) > 0 {
		t.StartTime = t.Events[0].Timestamp
		t.EndTime = t.Events[len(t.Events)-1].Timestamp
	}
}

// FilterByType filters events by type
func (t *Timeline) FilterByType(eventType TimelineEventType) []TimelineEvent {
	filtered := make([]TimelineEvent, 0)
	for _, event := range t.Events {
		if event.Type == eventType {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// FilterByTimeRange filters events within a time range
func (t *Timeline) FilterByTimeRange(start, end time.Time) []TimelineEvent {
	filtered := make([]TimelineEvent, 0)
	for _, event := range t.Events {
		if (event.Timestamp.Equal(start) || event.Timestamp.After(start)) &&
			(event.Timestamp.Equal(end) || event.Timestamp.Before(end)) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// FilterSuspicious returns only suspicious events
func (t *Timeline) FilterSuspicious() []TimelineEvent {
	filtered := make([]TimelineEvent, 0)
	for _, event := range t.Events {
		if event.IsSuspicious {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// GetEventClusters identifies clusters of events that occurred close together
// This can help identify potential exploitation windows
func (t *Timeline) GetEventClusters(windowDuration time.Duration) [][]TimelineEvent {
	if len(t.Events) == 0 {
		return nil
	}

	t.Sort()
	clusters := make([][]TimelineEvent, 0)
	currentCluster := []TimelineEvent{t.Events[0]}

	for i := 1; i < len(t.Events); i++ {
		if t.Events[i].Timestamp.Sub(t.Events[i-1].Timestamp) <= windowDuration {
			currentCluster = append(currentCluster, t.Events[i])
		} else {
			if len(currentCluster) > 1 {
				clusters = append(clusters, currentCluster)
			}
			currentCluster = []TimelineEvent{t.Events[i]}
		}
	}

	if len(currentCluster) > 1 {
		clusters = append(clusters, currentCluster)
	}

	return clusters
}

// FindSuspiciousPatterns identifies patterns that may indicate compromise
func (t *Timeline) FindSuspiciousPatterns() []SuspiciousPattern {
	patterns := make([]SuspiciousPattern, 0)

	// Pattern 1: Rapid app install/process activity after SMS/iMessage
	// (potential zero-click exploit)
	t.Sort()
	for i := 0; i < len(t.Events); i++ {
		if t.Events[i].Type == TimelineEventTypeSMS || t.Events[i].Type == TimelineEventTypeAnomaly {
			// Look for suspicious activity within 5 minutes
			window := t.FilterByTimeRange(t.Events[i].Timestamp, t.Events[i].Timestamp.Add(5*time.Minute))
			suspiciousInWindow := 0
			for _, e := range window {
				if e.IsSuspicious {
					suspiciousInWindow++
				}
			}
			if suspiciousInWindow >= 3 {
				patterns = append(patterns, SuspiciousPattern{
					Name:        "zero_click_indicator",
					Description: "Multiple suspicious events following SMS/message activity",
					Confidence:  0.7,
					Severity:    ForensicSeverityCritical,
					EventIDs:    getEventIDs(window),
					TimeRange:   TimeRange{Start: t.Events[i].Timestamp, End: t.Events[i].Timestamp.Add(5 * time.Minute)},
				})
			}
		}
	}

	// Pattern 2: Unusual boot-time activity (sticky processes)
	rebootEvents := t.FilterByType(TimelineEventTypeReboot)
	for _, reboot := range rebootEvents {
		window := t.FilterByTimeRange(reboot.Timestamp, reboot.Timestamp.Add(2*time.Minute))
		suspiciousInWindow := 0
		for _, e := range window {
			if e.IsSuspicious && e.Type == TimelineEventTypeProcessStart {
				suspiciousInWindow++
			}
		}
		if suspiciousInWindow >= 2 {
			patterns = append(patterns, SuspiciousPattern{
				Name:        "persistent_process",
				Description: "Suspicious processes starting immediately after reboot",
				Confidence:  0.8,
				Severity:    ForensicSeverityHigh,
				EventIDs:    getEventIDs(window),
				TimeRange:   TimeRange{Start: reboot.Timestamp, End: reboot.Timestamp.Add(2 * time.Minute)},
			})
		}
	}

	// Pattern 3: Data exfiltration indicators (large network activity during unusual hours)
	networkEvents := t.FilterByType(TimelineEventTypeNetworkConn)
	for _, ne := range networkEvents {
		hour := ne.Timestamp.Hour()
		if (hour >= 1 && hour <= 5) && ne.IsSuspicious {
			patterns = append(patterns, SuspiciousPattern{
				Name:        "night_exfiltration",
				Description: "Suspicious network activity during nighttime hours",
				Confidence:  0.6,
				Severity:    ForensicSeverityMedium,
				EventIDs:    []string{ne.ID},
				TimeRange:   TimeRange{Start: ne.Timestamp, End: ne.Timestamp},
			})
		}
	}

	return patterns
}

// SuspiciousPattern represents a detected pattern of suspicious activity
type SuspiciousPattern struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Confidence  float64          `json:"confidence"`
	Severity    ForensicSeverity `json:"severity"`
	EventIDs    []string         `json:"event_ids"`
	TimeRange   TimeRange        `json:"time_range"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Helper function to extract event IDs
func getEventIDs(events []TimelineEvent) []string {
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	return ids
}

// Merge merges another timeline into this one
func (t *Timeline) Merge(other *Timeline) {
	for _, event := range other.Events {
		t.AddEvent(event)
	}
	t.Sort()
}

// ToJSON returns the timeline as events slice (for JSON marshaling)
func (t *Timeline) ToEvents() []TimelineEvent {
	t.Sort()
	return t.Events
}
