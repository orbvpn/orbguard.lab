package services

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// SchedulerJob represents a scheduled job
type SchedulerJob struct {
	ID          uuid.UUID
	Name        string
	SourceSlug  string
	ScheduledAt time.Time
	ExecuteAt   time.Time
	Status      JobStatus
	Result      *JobResult
}

// JobStatus represents the status of a scheduled job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusSkipped   JobStatus = "skipped"
)

// JobResult holds the result of a job execution
type JobResult struct {
	Success      bool          `json:"success"`
	Error        string        `json:"error,omitempty"`
	Duration     time.Duration `json:"duration"`
	NewIOCs      int           `json:"new_iocs"`
	UpdatedIOCs  int           `json:"updated_iocs"`
	CompletedAt  time.Time     `json:"completed_at"`
}

// Scheduler manages the scheduling of source updates
type Scheduler struct {
	aggregator *Aggregator
	cache      *cache.RedisCache
	logger     *logger.Logger

	mu      sync.RWMutex
	jobs    map[uuid.UUID]*SchedulerJob
	running bool
	stopCh  chan struct{}
}

// NewScheduler creates a new Scheduler
func NewScheduler(aggregator *Aggregator, cache *cache.RedisCache, log *logger.Logger) *Scheduler {
	return &Scheduler{
		aggregator: aggregator,
		cache:      cache,
		logger:     log.WithComponent("scheduler"),
		jobs:       make(map[uuid.UUID]*SchedulerJob),
		stopCh:     make(chan struct{}),
	}
}

// Start starts the scheduler
func (s *Scheduler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.logger.Info().Msg("scheduler started")

	// Schedule initial jobs for all sources
	s.scheduleAllSources()

	// Main scheduler loop
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.Stop()
			return ctx.Err()
		case <-s.stopCh:
			return nil
		case <-ticker.C:
			s.processJobs(ctx)
		}
	}
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.stopCh)
	s.logger.Info().Msg("scheduler stopped")
}

// ScheduleSource schedules a job for a specific source
func (s *Scheduler) ScheduleSource(slug string, executeAt time.Time) *SchedulerJob {
	job := &SchedulerJob{
		ID:          uuid.New(),
		Name:        "fetch-" + slug,
		SourceSlug:  slug,
		ScheduledAt: time.Now(),
		ExecuteAt:   executeAt,
		Status:      JobStatusPending,
	}

	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()

	s.logger.Info().
		Str("job_id", job.ID.String()).
		Str("source", slug).
		Time("execute_at", executeAt).
		Msg("job scheduled")

	return job
}

// ScheduleNow schedules a job to run immediately
func (s *Scheduler) ScheduleNow(slug string) *SchedulerJob {
	return s.ScheduleSource(slug, time.Now())
}

// GetJob returns a job by ID
func (s *Scheduler) GetJob(id uuid.UUID) (*SchedulerJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	return job, ok
}

// ListPendingJobs returns all pending jobs
func (s *Scheduler) ListPendingJobs() []*SchedulerJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pending := make([]*SchedulerJob, 0)
	for _, job := range s.jobs {
		if job.Status == JobStatusPending {
			pending = append(pending, job)
		}
	}
	return pending
}

// CancelJob cancels a pending job
func (s *Scheduler) CancelJob(id uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.jobs[id]
	if !ok || job.Status != JobStatusPending {
		return false
	}

	job.Status = JobStatusSkipped
	return true
}

// scheduleAllSources creates initial jobs for all sources
func (s *Scheduler) scheduleAllSources() {
	stats := s.aggregator.Stats()
	s.logger.Info().Int("sources", stats.EnabledConnectors).Msg("scheduling all sources")

	// In a real implementation, we'd iterate through registered connectors
	// and schedule based on their update intervals
}

// processJobs checks for and executes due jobs
func (s *Scheduler) processJobs(ctx context.Context) {
	now := time.Now()

	s.mu.RLock()
	var dueJobs []*SchedulerJob
	for _, job := range s.jobs {
		if job.Status == JobStatusPending && job.ExecuteAt.Before(now) {
			dueJobs = append(dueJobs, job)
		}
	}
	s.mu.RUnlock()

	for _, job := range dueJobs {
		s.executeJob(ctx, job)
	}
}

// executeJob executes a single job
func (s *Scheduler) executeJob(ctx context.Context, job *SchedulerJob) {
	// Acquire distributed lock to prevent duplicate execution
	lockKey := "job:" + job.SourceSlug
	acquired, err := s.cache.AcquireLock(ctx, lockKey, 10*time.Minute)
	if err != nil || !acquired {
		s.logger.Warn().Str("source", job.SourceSlug).Msg("could not acquire lock, skipping")
		return
	}
	defer s.cache.ReleaseLock(ctx, lockKey)

	s.mu.Lock()
	job.Status = JobStatusRunning
	s.mu.Unlock()

	start := time.Now()
	s.logger.Info().Str("job_id", job.ID.String()).Str("source", job.SourceSlug).Msg("executing job")

	// Execute the fetch
	err = s.aggregator.RunSource(ctx, job.SourceSlug)

	duration := time.Since(start)
	result := &JobResult{
		Duration:    duration,
		CompletedAt: time.Now(),
	}

	s.mu.Lock()
	if err != nil {
		job.Status = JobStatusFailed
		result.Success = false
		result.Error = err.Error()
	} else {
		job.Status = JobStatusCompleted
		result.Success = true
	}
	job.Result = result
	s.mu.Unlock()

	// Schedule next run
	conn, ok := s.aggregator.GetConnector(job.SourceSlug)
	if ok {
		nextRun := time.Now().Add(conn.UpdateInterval())
		s.ScheduleSource(job.SourceSlug, nextRun)
	}

	s.logger.Info().
		Str("job_id", job.ID.String()).
		Str("source", job.SourceSlug).
		Bool("success", result.Success).
		Dur("duration", duration).
		Msg("job completed")
}

// Stats returns scheduler statistics
func (s *Scheduler) Stats() SchedulerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := SchedulerStats{
		Running:      s.running,
		TotalJobs:    len(s.jobs),
		PendingJobs:  0,
		RunningJobs:  0,
		CompletedJobs: 0,
		FailedJobs:   0,
	}

	for _, job := range s.jobs {
		switch job.Status {
		case JobStatusPending:
			stats.PendingJobs++
		case JobStatusRunning:
			stats.RunningJobs++
		case JobStatusCompleted:
			stats.CompletedJobs++
		case JobStatusFailed:
			stats.FailedJobs++
		}
	}

	return stats
}

// SchedulerStats holds scheduler statistics
type SchedulerStats struct {
	Running       bool `json:"running"`
	TotalJobs     int  `json:"total_jobs"`
	PendingJobs   int  `json:"pending_jobs"`
	RunningJobs   int  `json:"running_jobs"`
	CompletedJobs int  `json:"completed_jobs"`
	FailedJobs    int  `json:"failed_jobs"`
}

// SourceSchedule represents the schedule for a source
type SourceSchedule struct {
	SourceSlug     string        `json:"source_slug"`
	UpdateInterval time.Duration `json:"update_interval"`
	LastFetch      *time.Time    `json:"last_fetch"`
	NextFetch      *time.Time    `json:"next_fetch"`
	Status         models.SourceStatus `json:"status"`
}
