package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/pkg/logger"
)

// PlaybookService manages playbook registration and execution
type PlaybookService struct {
	playbooks      map[uuid.UUID]*models.Playbook
	executions     []models.PlaybookExecution
	webhookService *WebhookService
	cache          *cache.RedisCache
	logger         *logger.Logger

	mu            sync.RWMutex
	executionCh   chan *executionJob
	stopCh        chan struct{}
	wg            sync.WaitGroup
	workerCount   int

	// Action handlers
	actionHandlers map[models.ActionType]ActionHandler

	// Rate limiting
	executionCounts map[uuid.UUID]*executionCounter
}

// executionJob represents a playbook execution job
type executionJob struct {
	playbook  *models.Playbook
	trigger   *models.PlaybookTrigger
	inputData map[string]interface{}
}

// executionCounter tracks executions for rate limiting
type executionCounter struct {
	hourly  int
	daily   int
	lastReset time.Time
}

// ActionHandler is a function that executes an action
type ActionHandler func(ctx context.Context, action *models.PlaybookAction, inputData map[string]interface{}) (map[string]interface{}, error)

// PlaybookServiceConfig contains configuration for the playbook service
type PlaybookServiceConfig struct {
	WorkerCount int
	QueueSize   int
}

// NewPlaybookService creates a new playbook service
func NewPlaybookService(webhookSvc *WebhookService, cache *cache.RedisCache, log *logger.Logger, cfg *PlaybookServiceConfig) *PlaybookService {
	if cfg == nil {
		cfg = &PlaybookServiceConfig{
			WorkerCount: 5,
			QueueSize:   500,
		}
	}

	svc := &PlaybookService{
		playbooks:       make(map[uuid.UUID]*models.Playbook),
		executions:      make([]models.PlaybookExecution, 0),
		webhookService:  webhookSvc,
		cache:           cache,
		logger:          log.WithComponent("playbook-service"),
		executionCh:     make(chan *executionJob, cfg.QueueSize),
		stopCh:          make(chan struct{}),
		workerCount:     cfg.WorkerCount,
		actionHandlers:  make(map[models.ActionType]ActionHandler),
		executionCounts: make(map[uuid.UUID]*executionCounter),
	}

	// Register default action handlers
	svc.registerDefaultHandlers()

	// Start workers
	svc.startWorkers()

	return svc
}

// registerDefaultHandlers registers the default action handlers
func (s *PlaybookService) registerDefaultHandlers() {
	// Notification actions
	s.actionHandlers[models.ActionTypeSendWebhook] = s.handleSendWebhook
	s.actionHandlers[models.ActionTypeSendSlack] = s.handleSendSlack
	s.actionHandlers[models.ActionTypeSendTeams] = s.handleSendTeams
	s.actionHandlers[models.ActionTypeSendEmail] = s.handleSendEmail
	s.actionHandlers[models.ActionTypeSendPagerDuty] = s.handleSendPagerDuty
	s.actionHandlers[models.ActionTypeSendSMS] = s.handleSendSMS

	// Blocking actions
	s.actionHandlers[models.ActionTypeBlockIP] = s.handleBlockIP
	s.actionHandlers[models.ActionTypeBlockDomain] = s.handleBlockDomain
	s.actionHandlers[models.ActionTypeBlockHash] = s.handleBlockHash
	s.actionHandlers[models.ActionTypeBlockURL] = s.handleBlockURL

	// Data actions
	s.actionHandlers[models.ActionTypeAddTag] = s.handleAddTag
	s.actionHandlers[models.ActionTypeRemoveTag] = s.handleRemoveTag
	s.actionHandlers[models.ActionTypeUpdateSeverity] = s.handleUpdateSeverity
	s.actionHandlers[models.ActionTypeCreateAlert] = s.handleCreateAlert
	s.actionHandlers[models.ActionTypeEnrichIndicator] = s.handleEnrichIndicator

	// Integration actions
	s.actionHandlers[models.ActionTypeCallAPI] = s.handleCallAPI
	s.actionHandlers[models.ActionTypeTriggerPlaybook] = s.handleTriggerPlaybook
}

// startWorkers starts the execution worker goroutines
func (s *PlaybookService) startWorkers() {
	for i := 0; i < s.workerCount; i++ {
		s.wg.Add(1)
		go s.executionWorker(i)
	}
	s.logger.Info().Int("workers", s.workerCount).Msg("playbook execution workers started")
}

// executionWorker processes playbook executions
func (s *PlaybookService) executionWorker(id int) {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug().Int("worker", id).Msg("playbook worker stopping")
			return
		case job := <-s.executionCh:
			s.executePlaybook(context.Background(), job)
		}
	}
}

// Stop stops the playbook service
func (s *PlaybookService) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info().Msg("playbook service stopped")
}

// RegisterPlaybook registers a new playbook
func (s *PlaybookService) RegisterPlaybook(ctx context.Context, playbook *models.Playbook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if playbook.ID == uuid.Nil {
		playbook.ID = uuid.New()
	}

	// Validate playbook
	if err := s.validatePlaybook(playbook); err != nil {
		return fmt.Errorf("invalid playbook: %w", err)
	}

	playbook.CreatedAt = time.Now()
	playbook.UpdatedAt = time.Now()

	s.playbooks[playbook.ID] = playbook

	s.logger.Info().
		Str("playbook_id", playbook.ID.String()).
		Str("name", playbook.Name).
		Int("triggers", len(playbook.Triggers)).
		Int("actions", len(playbook.Actions)).
		Msg("playbook registered")

	return nil
}

// validatePlaybook validates a playbook configuration
func (s *PlaybookService) validatePlaybook(playbook *models.Playbook) error {
	if playbook.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(playbook.Triggers) == 0 {
		return fmt.Errorf("at least one trigger is required")
	}
	if len(playbook.Actions) == 0 {
		return fmt.Errorf("at least one action is required")
	}

	// Validate actions
	for _, action := range playbook.Actions {
		if action.ID == "" {
			return fmt.Errorf("action ID is required")
		}
		if _, ok := s.actionHandlers[action.Type]; !ok {
			return fmt.Errorf("unsupported action type: %s", action.Type)
		}
	}

	return nil
}

// UpdatePlaybook updates an existing playbook
func (s *PlaybookService) UpdatePlaybook(ctx context.Context, playbook *models.Playbook) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.playbooks[playbook.ID]
	if !ok {
		return fmt.Errorf("playbook not found: %s", playbook.ID)
	}

	// Preserve statistics
	playbook.TotalExecutions = existing.TotalExecutions
	playbook.SuccessExecutions = existing.SuccessExecutions
	playbook.FailedExecutions = existing.FailedExecutions
	playbook.LastExecutedAt = existing.LastExecutedAt
	playbook.CreatedAt = existing.CreatedAt

	playbook.UpdatedAt = time.Now()
	s.playbooks[playbook.ID] = playbook

	s.logger.Info().
		Str("playbook_id", playbook.ID.String()).
		Str("name", playbook.Name).
		Msg("playbook updated")

	return nil
}

// DeletePlaybook deletes a playbook
func (s *PlaybookService) DeletePlaybook(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.playbooks[id]; !ok {
		return fmt.Errorf("playbook not found: %s", id)
	}

	delete(s.playbooks, id)
	delete(s.executionCounts, id)

	s.logger.Info().Str("playbook_id", id.String()).Msg("playbook deleted")

	return nil
}

// GetPlaybook retrieves a playbook by ID
func (s *PlaybookService) GetPlaybook(ctx context.Context, id uuid.UUID) (*models.Playbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	playbook, ok := s.playbooks[id]
	if !ok {
		return nil, fmt.Errorf("playbook not found: %s", id)
	}

	return playbook, nil
}

// ListPlaybooks returns all playbooks
func (s *PlaybookService) ListPlaybooks(ctx context.Context) ([]*models.Playbook, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	playbooks := make([]*models.Playbook, 0, len(s.playbooks))
	for _, p := range s.playbooks {
		playbooks = append(playbooks, p)
	}

	return playbooks, nil
}

// EnablePlaybook enables a playbook
func (s *PlaybookService) EnablePlaybook(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	playbook, ok := s.playbooks[id]
	if !ok {
		return fmt.Errorf("playbook not found: %s", id)
	}

	playbook.Enabled = true
	playbook.UpdatedAt = time.Now()

	return nil
}

// DisablePlaybook disables a playbook
func (s *PlaybookService) DisablePlaybook(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	playbook, ok := s.playbooks[id]
	if !ok {
		return fmt.Errorf("playbook not found: %s", id)
	}

	playbook.Enabled = false
	playbook.UpdatedAt = time.Now()

	return nil
}

// TriggerEvent processes an event and triggers matching playbooks
func (s *PlaybookService) TriggerEvent(ctx context.Context, eventType string, data map[string]interface{}) error {
	s.mu.RLock()
	matching := s.findMatchingPlaybooks(eventType, data)
	s.mu.RUnlock()

	if len(matching) == 0 {
		s.logger.Debug().
			Str("event", eventType).
			Msg("no playbooks matched event")
		return nil
	}

	// Queue executions
	for _, pb := range matching {
		job := &executionJob{
			playbook: pb.playbook,
			trigger:  pb.trigger,
			inputData: data,
		}

		select {
		case s.executionCh <- job:
			s.logger.Debug().
				Str("playbook_id", pb.playbook.ID.String()).
				Str("event", eventType).
				Msg("playbook execution queued")
		default:
			s.logger.Warn().
				Str("playbook_id", pb.playbook.ID.String()).
				Msg("execution queue full, dropping playbook")
		}
	}

	s.logger.Info().
		Str("event", eventType).
		Int("playbooks", len(matching)).
		Msg("event triggered playbooks")

	return nil
}

// playbookMatch represents a matched playbook and its trigger
type playbookMatch struct {
	playbook *models.Playbook
	trigger  *models.PlaybookTrigger
}

// findMatchingPlaybooks finds playbooks that match the event
func (s *PlaybookService) findMatchingPlaybooks(eventType string, data map[string]interface{}) []playbookMatch {
	var matching []playbookMatch

	for _, playbook := range s.playbooks {
		if !playbook.Enabled {
			continue
		}

		// Check rate limiting
		if !s.checkRateLimit(playbook) {
			continue
		}

		// Check triggers
		for i := range playbook.Triggers {
			trigger := &playbook.Triggers[i]
			if s.triggerMatches(trigger, eventType, data) {
				// Check conditions
				if s.conditionsMatch(playbook.Conditions, data) {
					matching = append(matching, playbookMatch{
						playbook: playbook,
						trigger:  trigger,
					})
					break // Only match once per playbook
				}
			}
		}
	}

	return matching
}

// triggerMatches checks if a trigger matches the event
func (s *PlaybookService) triggerMatches(trigger *models.PlaybookTrigger, eventType string, data map[string]interface{}) bool {
	if trigger.Type != models.TriggerTypeEvent {
		return false
	}

	// Check event type
	if trigger.EventType != "" && trigger.EventType != eventType {
		// Check wildcard match
		if !strings.HasSuffix(trigger.EventType, ".*") {
			return false
		}
		prefix := strings.TrimSuffix(trigger.EventType, ".*")
		if !strings.HasPrefix(eventType, prefix) {
			return false
		}
	}

	// Check filters
	if trigger.Filters != nil {
		return s.triggerFiltersMatch(trigger.Filters, data)
	}

	return true
}

// triggerFiltersMatch checks if trigger filters match the data
func (s *PlaybookService) triggerFiltersMatch(filters *models.PlaybookTriggerFilters, data map[string]interface{}) bool {
	// Check severity
	if filters.MinSeverity != "" {
		if severity, ok := data["severity"].(string); ok {
			if !playbookSeverityAtLeast(severity, filters.MinSeverity) {
				return false
			}
		}
	}

	// Check indicator type
	if len(filters.IndicatorTypes) > 0 {
		if iocType, ok := data["indicator_type"].(string); ok {
			if !playbookSliceContains(filters.IndicatorTypes, iocType) {
				return false
			}
		}
	}

	// Check platforms
	if len(filters.Platforms) > 0 {
		if platforms, ok := data["platforms"].([]string); ok {
			if !playbookSliceHasAny(platforms, filters.Platforms) {
				return false
			}
		}
	}

	// Check required tags
	if len(filters.RequiredTags) > 0 {
		if tags, ok := data["tags"].([]string); ok {
			if !playbookSliceHasAll(tags, filters.RequiredTags) {
				return false
			}
		}
	}

	// Check confidence
	if filters.MinConfidence > 0 {
		if confidence, ok := data["confidence"].(float64); ok {
			if confidence < filters.MinConfidence {
				return false
			}
		}
	}

	return true
}

// conditionsMatch checks if all conditions are met
func (s *PlaybookService) conditionsMatch(conditions []models.PlaybookCondition, data map[string]interface{}) bool {
	for _, condition := range conditions {
		if !s.conditionMatches(&condition, data) {
			return false
		}
	}
	return true
}

// conditionMatches checks if a single condition is met
func (s *PlaybookService) conditionMatches(condition *models.PlaybookCondition, data map[string]interface{}) bool {
	value, ok := data[condition.Field]
	if !ok {
		if condition.Type == models.ConditionTypeExists {
			result := false
			if condition.Negate {
				result = !result
			}
			return result
		}
		return false
	}

	result := s.evaluateCondition(condition.Operator, value, condition.Value)
	if condition.Negate {
		result = !result
	}

	return result
}

// evaluateCondition evaluates a condition operator
func (s *PlaybookService) evaluateCondition(op models.ConditionOperator, actual, expected interface{}) bool {
	switch op {
	case models.OperatorEquals:
		return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
	case models.OperatorNotEquals:
		return fmt.Sprintf("%v", actual) != fmt.Sprintf("%v", expected)
	case models.OperatorContains:
		return strings.Contains(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", expected))
	case models.OperatorStartsWith:
		return strings.HasPrefix(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", expected))
	case models.OperatorEndsWith:
		return strings.HasSuffix(fmt.Sprintf("%v", actual), fmt.Sprintf("%v", expected))
	case models.OperatorMatches:
		pattern, ok := expected.(string)
		if !ok {
			return false
		}
		matched, _ := regexp.MatchString(pattern, fmt.Sprintf("%v", actual))
		return matched
	case models.OperatorIn:
		if list, ok := expected.([]interface{}); ok {
			for _, item := range list {
				if fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", item) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// checkRateLimit checks if the playbook has hit rate limits
func (s *PlaybookService) checkRateLimit(playbook *models.Playbook) bool {
	if playbook.Settings == nil {
		return true
	}

	counter, ok := s.executionCounts[playbook.ID]
	if !ok {
		counter = &executionCounter{lastReset: time.Now()}
		s.executionCounts[playbook.ID] = counter
	}

	// Reset counters if needed
	now := time.Now()
	if now.Sub(counter.lastReset) > time.Hour {
		counter.hourly = 0
		if now.Sub(counter.lastReset) > 24*time.Hour {
			counter.daily = 0
		}
		counter.lastReset = now
	}

	// Check hourly limit
	if playbook.Settings.MaxExecutionsPerHour > 0 {
		if counter.hourly >= playbook.Settings.MaxExecutionsPerHour {
			return false
		}
	}

	// Check daily limit
	if playbook.Settings.MaxExecutionsPerDay > 0 {
		if counter.daily >= playbook.Settings.MaxExecutionsPerDay {
			return false
		}
	}

	return true
}

// executePlaybook executes a playbook
func (s *PlaybookService) executePlaybook(ctx context.Context, job *executionJob) {
	playbook := job.playbook
	startTime := time.Now()

	execution := models.PlaybookExecution{
		ID:           uuid.New(),
		PlaybookID:   playbook.ID,
		PlaybookName: playbook.Name,
		TriggerType:  job.trigger.Type,
		TriggerEvent: job.trigger.EventType,
		Status:       models.ExecutionStatusRunning,
		StartedAt:    startTime,
		InputData:    job.inputData,
		ActionResults: make([]models.ActionResult, 0, len(playbook.Actions)),
	}

	s.logger.Info().
		Str("playbook_id", playbook.ID.String()).
		Str("execution_id", execution.ID.String()).
		Msg("starting playbook execution")

	// Update rate limit counters
	s.mu.Lock()
	if counter, ok := s.executionCounts[playbook.ID]; ok {
		counter.hourly++
		counter.daily++
	}
	s.mu.Unlock()

	// Execute actions
	outputData := make(map[string]interface{})
	var executionErr error

	for _, action := range playbook.Actions {
		actionResult := s.executeAction(ctx, &action, job.inputData, outputData)
		execution.ActionResults = append(execution.ActionResults, actionResult)

		if actionResult.Status == models.ExecutionStatusFailed {
			if !action.ContinueOnError {
				if playbook.Settings != nil && playbook.Settings.StopOnFirstFailure {
					executionErr = fmt.Errorf("action %s failed: %s", action.ID, actionResult.Error)
					execution.ErrorAction = action.ID
					break
				}
			}
		}

		// Merge action output into aggregate output
		for k, v := range actionResult.Output {
			outputData[k] = v
		}
	}

	// Update execution status
	completedAt := time.Now()
	execution.CompletedAt = &completedAt
	execution.Duration = completedAt.Sub(startTime)
	execution.OutputData = outputData

	if executionErr != nil {
		execution.Status = models.ExecutionStatusFailed
		execution.Error = executionErr.Error()
	} else {
		execution.Status = models.ExecutionStatusSuccess
	}

	// Update playbook statistics
	s.mu.Lock()
	playbook.TotalExecutions++
	if execution.Status == models.ExecutionStatusSuccess {
		playbook.SuccessExecutions++
	} else {
		playbook.FailedExecutions++
		playbook.LastError = execution.Error
	}
	playbook.LastExecutedAt = completedAt

	// Store execution (keep last 100)
	s.executions = append(s.executions, execution)
	if len(s.executions) > 100 {
		s.executions = s.executions[1:]
	}
	s.mu.Unlock()

	s.logger.Info().
		Str("playbook_id", playbook.ID.String()).
		Str("execution_id", execution.ID.String()).
		Str("status", string(execution.Status)).
		Dur("duration", execution.Duration).
		Msg("playbook execution completed")
}

// executeAction executes a single action
func (s *PlaybookService) executeAction(ctx context.Context, action *models.PlaybookAction, inputData, outputData map[string]interface{}) models.ActionResult {
	startTime := time.Now()

	result := models.ActionResult{
		ActionID:   action.ID,
		ActionName: action.Name,
		ActionType: action.Type,
		Status:     models.ExecutionStatusRunning,
		StartedAt:  startTime,
	}

	// Get handler
	handler, ok := s.actionHandlers[action.Type]
	if !ok {
		result.Status = models.ExecutionStatusFailed
		result.Error = fmt.Sprintf("no handler for action type: %s", action.Type)
		completedAt := time.Now()
		result.CompletedAt = &completedAt
		result.Duration = completedAt.Sub(startTime)
		return result
	}

	// Merge input and output data for context
	mergedData := make(map[string]interface{})
	for k, v := range inputData {
		mergedData[k] = v
	}
	for k, v := range outputData {
		mergedData[k] = v
	}

	// Apply timeout if configured
	execCtx := ctx
	if action.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, action.Timeout)
		defer cancel()
	}

	// Execute action
	output, err := handler(execCtx, action, mergedData)

	completedAt := time.Now()
	result.CompletedAt = &completedAt
	result.Duration = completedAt.Sub(startTime)
	result.Output = output

	if err != nil {
		result.Status = models.ExecutionStatusFailed
		result.Error = err.Error()
		s.logger.Warn().
			Str("action", action.ID).
			Str("type", string(action.Type)).
			Err(err).
			Msg("action failed")
	} else {
		result.Status = models.ExecutionStatusSuccess
		s.logger.Debug().
			Str("action", action.ID).
			Str("type", string(action.Type)).
			Dur("duration", result.Duration).
			Msg("action completed")
	}

	return result
}

// TriggerManually triggers a playbook manually
func (s *PlaybookService) TriggerManually(ctx context.Context, playbookID uuid.UUID, inputData map[string]interface{}) (*models.PlaybookExecution, error) {
	s.mu.RLock()
	playbook, ok := s.playbooks[playbookID]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("playbook not found: %s", playbookID)
	}

	// Find manual trigger or use first trigger
	var trigger *models.PlaybookTrigger
	for i := range playbook.Triggers {
		if playbook.Triggers[i].Type == models.TriggerTypeManual {
			trigger = &playbook.Triggers[i]
			break
		}
	}
	if trigger == nil && len(playbook.Triggers) > 0 {
		trigger = &playbook.Triggers[0]
	}

	job := &executionJob{
		playbook:  playbook,
		trigger:   trigger,
		inputData: inputData,
	}

	// Execute synchronously for manual triggers
	s.executePlaybook(ctx, job)

	// Return the latest execution
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := len(s.executions) - 1; i >= 0; i-- {
		if s.executions[i].PlaybookID == playbookID {
			return &s.executions[i], nil
		}
	}

	return nil, fmt.Errorf("execution not found")
}

// GetExecutions returns recent executions
func (s *PlaybookService) GetExecutions(ctx context.Context, playbookID *uuid.UUID, limit int) ([]models.PlaybookExecution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	var result []models.PlaybookExecution

	for i := len(s.executions) - 1; i >= 0 && len(result) < limit; i-- {
		exec := s.executions[i]
		if playbookID == nil || exec.PlaybookID == *playbookID {
			result = append(result, exec)
		}
	}

	return result, nil
}

// GetStats returns playbook statistics
func (s *PlaybookService) GetStats(ctx context.Context) *models.PlaybookStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &models.PlaybookStats{
		ExecutionsByStatus: make(map[string]int64),
		TopPlaybooks:       make([]models.PlaybookSummary, 0),
	}

	var totalSuccess, totalFailed int64
	var totalDuration time.Duration

	for _, p := range s.playbooks {
		stats.TotalPlaybooks++
		if p.Enabled {
			stats.EnabledPlaybooks++
		}
		stats.TotalExecutions += p.TotalExecutions
		totalSuccess += p.SuccessExecutions
		totalFailed += p.FailedExecutions
	}

	if stats.TotalExecutions > 0 {
		stats.SuccessRate = float64(totalSuccess) / float64(stats.TotalExecutions) * 100
	}

	// Calculate average execution time from recent executions
	for _, exec := range s.executions {
		totalDuration += exec.Duration
		stats.ExecutionsByStatus[string(exec.Status)]++
	}
	if len(s.executions) > 0 {
		stats.AverageExecutionTime = totalDuration / time.Duration(len(s.executions))
	}

	return stats
}

// GetTemplates returns available playbook templates
func (s *PlaybookService) GetTemplates() []models.PlaybookTemplate {
	return models.DefaultPlaybookTemplates()
}

// CreateFromTemplate creates a playbook from a template
func (s *PlaybookService) CreateFromTemplate(ctx context.Context, templateID string, name string) (*models.Playbook, error) {
	templates := models.DefaultPlaybookTemplates()

	var template *models.PlaybookTemplate
	for i := range templates {
		if templates[i].ID == templateID {
			template = &templates[i]
			break
		}
	}

	if template == nil {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	if name == "" {
		name = template.Name
	}

	playbook := &models.Playbook{
		Name:        name,
		Description: template.Description,
		Enabled:     false, // Disabled by default
		Tags:        template.Tags,
		Triggers:    template.Triggers,
		Conditions:  template.Conditions,
		Actions:     template.Actions,
		Settings:    template.Settings,
	}

	if err := s.RegisterPlaybook(ctx, playbook); err != nil {
		return nil, err
	}

	return playbook, nil
}

// Action handlers (simplified implementations)

func (s *PlaybookService) handleSendWebhook(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing send_webhook action")
	return map[string]interface{}{"webhook_sent": true}, nil
}

func (s *PlaybookService) handleSendSlack(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing send_slack action")
	return map[string]interface{}{"slack_sent": true}, nil
}

func (s *PlaybookService) handleSendTeams(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing send_teams action")
	return map[string]interface{}{"teams_sent": true}, nil
}

func (s *PlaybookService) handleSendEmail(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing send_email action")
	return map[string]interface{}{"email_sent": true}, nil
}

func (s *PlaybookService) handleSendPagerDuty(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing send_pagerduty action")
	return map[string]interface{}{"pagerduty_sent": true}, nil
}

func (s *PlaybookService) handleSendSMS(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing send_sms action")
	return map[string]interface{}{"sms_sent": true}, nil
}

func (s *PlaybookService) handleBlockIP(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing block_ip action")
	return map[string]interface{}{"ip_blocked": true}, nil
}

func (s *PlaybookService) handleBlockDomain(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing block_domain action")
	return map[string]interface{}{"domain_blocked": true}, nil
}

func (s *PlaybookService) handleBlockHash(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing block_hash action")
	return map[string]interface{}{"hash_blocked": true}, nil
}

func (s *PlaybookService) handleBlockURL(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing block_url action")
	return map[string]interface{}{"url_blocked": true}, nil
}

func (s *PlaybookService) handleAddTag(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing add_tag action")
	return map[string]interface{}{"tags_added": true}, nil
}

func (s *PlaybookService) handleRemoveTag(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing remove_tag action")
	return map[string]interface{}{"tags_removed": true}, nil
}

func (s *PlaybookService) handleUpdateSeverity(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing update_severity action")
	return map[string]interface{}{"severity_updated": true}, nil
}

func (s *PlaybookService) handleCreateAlert(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing create_alert action")
	alertID := uuid.New().String()
	return map[string]interface{}{"alert_created": true, "alert_id": alertID}, nil
}

func (s *PlaybookService) handleEnrichIndicator(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing enrich_indicator action")
	return map[string]interface{}{"enriched": true}, nil
}

func (s *PlaybookService) handleCallAPI(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing call_api action")
	return map[string]interface{}{"api_called": true}, nil
}

func (s *PlaybookService) handleTriggerPlaybook(ctx context.Context, action *models.PlaybookAction, data map[string]interface{}) (map[string]interface{}, error) {
	s.logger.Info().Str("action", action.ID).Msg("executing trigger_playbook action")
	return map[string]interface{}{"playbook_triggered": true}, nil
}

// Helper functions

func playbookSeverityAtLeast(actual, minimum string) bool {
	levels := map[string]int{
		"low": 1, "medium": 2, "high": 3, "critical": 4,
	}
	return levels[strings.ToLower(actual)] >= levels[strings.ToLower(minimum)]
}

func playbookSliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func playbookSliceHasAny(slice, items []string) bool {
	for _, item := range items {
		if playbookSliceContains(slice, item) {
			return true
		}
	}
	return false
}

func playbookSliceHasAll(slice, items []string) bool {
	for _, item := range items {
		if !playbookSliceContains(slice, item) {
			return false
		}
	}
	return true
}
