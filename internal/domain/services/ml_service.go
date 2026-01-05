package services

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/internal/infrastructure/cache"
	"orbguard-lab/internal/infrastructure/database/repository"
	"orbguard-lab/pkg/logger"
)

// MLService orchestrates all ML operations for threat intelligence
type MLService struct {
	featureExtractor  *FeatureExtractor
	isolationForest   *IsolationForest
	kmeans            *KMeans
	randomForest      *RandomForest
	entityExtractor   *EntityExtractor
	repos             *repository.Repositories
	cache             *cache.RedisCache
	logger            *logger.Logger

	// Training state
	lastTrainedAt     time.Time
	trainingInProgress atomic.Bool
	trainingMu        sync.Mutex

	// Stats
	totalPredictions   atomic.Int64
	totalAnomalies     atomic.Int64
	totalEntities      atomic.Int64
	cacheHits          atomic.Int64
	cacheMisses        atomic.Int64
}

// MLServiceConfig holds configuration for the ML service
type MLServiceConfig struct {
	IsolationForest IsolationForestConfig
	KMeans          KMeansConfig
	RandomForest    RandomForestConfig
	AutoTrain       bool
	TrainInterval   time.Duration
	MinTrainingSize int
}

// DefaultMLServiceConfig returns default configuration
func DefaultMLServiceConfig() MLServiceConfig {
	return MLServiceConfig{
		IsolationForest: DefaultIsolationForestConfig(),
		KMeans:          DefaultKMeansConfig(),
		RandomForest:    DefaultRandomForestConfig(),
		AutoTrain:       true,
		TrainInterval:   24 * time.Hour,
		MinTrainingSize: 100,
	}
}

// NewMLService creates a new ML service
func NewMLService(
	config MLServiceConfig,
	repos *repository.Repositories,
	c *cache.RedisCache,
	log *logger.Logger,
) *MLService {
	return &MLService{
		featureExtractor: NewFeatureExtractor(log),
		isolationForest:  NewIsolationForest(config.IsolationForest, log),
		kmeans:           NewKMeans(config.KMeans, log),
		randomForest:     NewRandomForest(config.RandomForest, log),
		entityExtractor:  NewEntityExtractor(log),
		repos:            repos,
		cache:            c,
		logger:           log.WithComponent("ml-service"),
	}
}

// EnrichIndicator enriches an indicator with ML analysis
func (s *MLService) EnrichIndicator(ctx context.Context, indicator *models.Indicator) (*models.MLEnrichmentResult, error) {
	startTime := time.Now()
	s.totalPredictions.Add(1)

	result := &models.MLEnrichmentResult{
		IndicatorID: indicator.ID,
		EnrichedAt:  time.Now(),
	}

	// Extract features
	features := s.featureExtractor.ExtractFeatures(indicator)
	result.Features = features

	// Convert to feature vector
	vector := s.featureExtractor.FeaturesToVector(indicator.ID, indicator.Type, features)

	// Anomaly detection
	if s.isolationForest.IsTrained() {
		anomalyScore := s.isolationForest.PredictOne(vector)
		result.AnomalyScore = &anomalyScore
		if anomalyScore.IsAnomaly {
			s.totalAnomalies.Add(1)
		}
	}

	// Cluster assignment
	if s.kmeans.IsTrained() {
		clusterResult := s.kmeans.Predict([]*models.FeatureVector{vector})
		if len(clusterResult.Assignments) > 0 {
			result.ClusterAssignment = &clusterResult.Assignments[0]
		}
	}

	// Severity prediction
	if s.randomForest.IsTrained() {
		predictions := s.randomForest.Predict([]*models.FeatureVector{vector})
		if len(predictions) > 0 {
			result.SeverityPrediction = &predictions[0]
		}
	}

	result.ProcessingTime = time.Since(startTime)

	return result, nil
}

// EnrichBatch enriches multiple indicators
func (s *MLService) EnrichBatch(ctx context.Context, indicators []*models.Indicator) ([]*models.MLEnrichmentResult, error) {
	results := make([]*models.MLEnrichmentResult, len(indicators))

	for i, ind := range indicators {
		result, err := s.EnrichIndicator(ctx, ind)
		if err != nil {
			s.logger.Error().Err(err).Str("indicator_id", ind.ID.String()).Msg("failed to enrich indicator")
			continue
		}
		results[i] = result
	}

	return results, nil
}

// DetectAnomalies runs anomaly detection on indicators
func (s *MLService) DetectAnomalies(ctx context.Context, indicators []*models.Indicator) (*models.AnomalyDetectionResult, error) {
	startTime := time.Now()

	if !s.isolationForest.IsTrained() {
		return nil, nil
	}

	// Extract feature vectors
	vectors := s.featureExtractor.ExtractBatchFeatures(indicators)

	// Run anomaly detection
	scores := s.isolationForest.Predict(vectors)

	// Calculate statistics
	anomalyCount := 0
	var sum, sumSq, min, max float64
	min = 1.0

	for _, score := range scores {
		if score.IsAnomaly {
			anomalyCount++
		}
		sum += score.Score
		sumSq += score.Score * score.Score
		if score.Score < min {
			min = score.Score
		}
		if score.Score > max {
			max = score.Score
		}
	}

	n := float64(len(scores))
	mean := sum / n
	variance := (sumSq / n) - (mean * mean)
	stdDev := 0.0
	if variance > 0 {
		stdDev = variance
	}

	return &models.AnomalyDetectionResult{
		TotalProcessed: len(indicators),
		AnomalyCount:   anomalyCount,
		Scores:         scores,
		Statistics: models.AnomalyStats{
			MeanScore:   mean,
			StdDevScore: stdDev,
			MinScore:    min,
			MaxScore:    max,
			AnomalyRate: float64(anomalyCount) / n,
		},
		ProcessingTime: time.Since(startTime),
	}, nil
}

// ClusterIndicators clusters indicators into groups
func (s *MLService) ClusterIndicators(ctx context.Context, indicators []*models.Indicator, k int) (*models.ClusteringResult, error) {
	if len(indicators) == 0 {
		return nil, nil
	}

	// Extract feature vectors
	vectors := s.featureExtractor.ExtractBatchFeatures(indicators)

	// Create temporary K-Means with specified k
	config := DefaultKMeansConfig()
	config.K = k
	km := NewKMeans(config, s.logger)

	// Train and predict
	if err := km.Train(vectors); err != nil {
		return nil, err
	}

	return km.Predict(vectors), nil
}

// PredictSeverity predicts severity for indicators
func (s *MLService) PredictSeverity(ctx context.Context, indicators []*models.Indicator) (*models.SeverityPredictionResult, error) {
	startTime := time.Now()

	if !s.randomForest.IsTrained() {
		return nil, nil
	}

	// Extract feature vectors
	vectors := s.featureExtractor.ExtractBatchFeatures(indicators)

	// Run predictions
	predictions := s.randomForest.Predict(vectors)

	return &models.SeverityPredictionResult{
		TotalProcessed: len(indicators),
		Predictions:    predictions,
		ProcessingTime: time.Since(startTime),
	}, nil
}

// ExtractEntities extracts entities from text
func (s *MLService) ExtractEntities(text string) *models.EntityExtractionResult {
	result := s.entityExtractor.ExtractEntities(text)
	s.totalEntities.Add(int64(len(result.Entities)))
	return result
}

// ExtractIndicatorsFromText extracts IOCs from text
func (s *MLService) ExtractIndicatorsFromText(text string) []models.ExtractedIndicator {
	return s.entityExtractor.ExtractIndicators(text)
}

// Train trains all ML models on existing data
func (s *MLService) Train(ctx context.Context) (*models.MLTrainingResult, error) {
	if !s.trainingInProgress.CompareAndSwap(false, true) {
		return &models.MLTrainingResult{
			Success: false,
			Error:   "training already in progress",
		}, nil
	}
	defer s.trainingInProgress.Store(false)

	s.trainingMu.Lock()
	defer s.trainingMu.Unlock()

	startTime := time.Now()

	// Fetch training data from database
	var indicators []*models.Indicator
	var err error

	if s.repos != nil {
		filter := repository.IndicatorFilter{
			Limit:  10000,
			Offset: 0,
		}
		indicators, _, err = s.repos.Indicators.List(ctx, filter)
		if err != nil {
			return &models.MLTrainingResult{
				Success: false,
				Error:   err.Error(),
			}, err
		}
	}

	if len(indicators) < 100 {
		return &models.MLTrainingResult{
			Success: false,
			Error:   "insufficient training data",
		}, nil
	}

	// Extract features
	vectors := s.featureExtractor.ExtractBatchFeatures(indicators)

	// Train Isolation Forest
	if err := s.isolationForest.Train(vectors); err != nil {
		s.logger.Error().Err(err).Msg("failed to train isolation forest")
	}

	// Train K-Means
	optimalK := s.kmeans.OptimalK(vectors, 10)
	kmeansConfig := DefaultKMeansConfig()
	kmeansConfig.K = optimalK
	s.kmeans = NewKMeans(kmeansConfig, s.logger)
	if err := s.kmeans.Train(vectors); err != nil {
		s.logger.Error().Err(err).Msg("failed to train k-means")
	}

	// Train Random Forest (need labels)
	labels := make([]models.Severity, len(indicators))
	for i, ind := range indicators {
		labels[i] = ind.Severity
	}
	if err := s.randomForest.Train(vectors, labels); err != nil {
		s.logger.Error().Err(err).Msg("failed to train random forest")
	}

	s.lastTrainedAt = time.Now()

	return &models.MLTrainingResult{
		ModelType:      "all",
		Version:        "1.0",
		TrainingSize:   len(indicators),
		TrainingTime:   time.Since(startTime),
		Success:        true,
		Metrics: map[string]float64{
			"isolation_forest_threshold": s.isolationForest.threshold,
			"kmeans_silhouette":          s.kmeans.silhouette,
			"random_forest_accuracy":     s.randomForest.accuracy,
		},
	}, nil
}

// TrainModel trains a specific model
func (s *MLService) TrainModel(ctx context.Context, modelType string) (*models.MLTrainingResult, error) {
	if !s.trainingInProgress.CompareAndSwap(false, true) {
		return &models.MLTrainingResult{
			Success: false,
			Error:   "training already in progress",
		}, nil
	}
	defer s.trainingInProgress.Store(false)

	startTime := time.Now()

	// Fetch training data
	var indicators []*models.Indicator
	var err error

	if s.repos != nil {
		filter := repository.IndicatorFilter{
			Limit:  10000,
			Offset: 0,
		}
		indicators, _, err = s.repos.Indicators.List(ctx, filter)
		if err != nil {
			return nil, err
		}
	}

	if len(indicators) < 100 {
		return &models.MLTrainingResult{
			Success: false,
			Error:   "insufficient training data",
		}, nil
	}

	vectors := s.featureExtractor.ExtractBatchFeatures(indicators)

	result := &models.MLTrainingResult{
		ModelType:    modelType,
		Version:      "1.0",
		TrainingSize: len(indicators),
		Metrics:      make(map[string]float64),
	}

	switch modelType {
	case "isolation_forest", "anomaly":
		if err := s.isolationForest.Train(vectors); err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Metrics["threshold"] = s.isolationForest.threshold
		}

	case "kmeans", "clustering":
		if err := s.kmeans.Train(vectors); err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Metrics["silhouette"] = s.kmeans.silhouette
			result.Metrics["inertia"] = s.kmeans.inertia
		}

	case "random_forest", "severity":
		labels := make([]models.Severity, len(indicators))
		for i, ind := range indicators {
			labels[i] = ind.Severity
		}
		if err := s.randomForest.Train(vectors, labels); err != nil {
			result.Error = err.Error()
		} else {
			result.Success = true
			result.Metrics["accuracy"] = s.randomForest.accuracy
		}

	default:
		result.Error = "unknown model type"
	}

	result.TrainingTime = time.Since(startTime)

	return result, nil
}

// GetStats returns ML service statistics
func (s *MLService) GetStats() *models.MLServiceStats {
	modelInfos := []models.MLModelInfo{
		s.isolationForest.GetModelInfo(),
		s.kmeans.GetModelInfo(),
		s.randomForest.GetModelInfo(),
	}

	modelsLoaded := 0
	for _, m := range modelInfos {
		if m.Status == "ready" {
			modelsLoaded++
		}
	}

	totalCacheOps := s.cacheHits.Load() + s.cacheMisses.Load()
	hitRate := 0.0
	if totalCacheOps > 0 {
		hitRate = float64(s.cacheHits.Load()) / float64(totalCacheOps)
	}

	return &models.MLServiceStats{
		ModelsLoaded:           modelsLoaded,
		Models:                 modelInfos,
		TotalPredictions:       s.totalPredictions.Load(),
		TotalAnomalies:         s.totalAnomalies.Load(),
		TotalClusters:          s.kmeans.k,
		TotalEntitiesExtracted: s.totalEntities.Load(),
		LastTrainedAt:          s.lastTrainedAt,
		CacheHitRate:           hitRate,
	}
}

// GetModelInfo returns information about a specific model
func (s *MLService) GetModelInfo(modelType string) *models.MLModelInfo {
	switch modelType {
	case "isolation_forest", "anomaly":
		info := s.isolationForest.GetModelInfo()
		return &info
	case "kmeans", "clustering":
		info := s.kmeans.GetModelInfo()
		return &info
	case "random_forest", "severity":
		info := s.randomForest.GetModelInfo()
		return &info
	default:
		return nil
	}
}

// IsReady returns whether the ML service is ready (at least one model trained)
func (s *MLService) IsReady() bool {
	return s.isolationForest.IsTrained() || s.kmeans.IsTrained() || s.randomForest.IsTrained()
}

// GetFeatureNames returns the list of feature names used by the ML models
func (s *MLService) GetFeatureNames() []string {
	return s.featureExtractor.GetFeatureNames()
}

// FindOptimalClusters finds the optimal number of clusters for the data
func (s *MLService) FindOptimalClusters(ctx context.Context, indicators []*models.Indicator, maxK int) int {
	vectors := s.featureExtractor.ExtractBatchFeatures(indicators)
	return s.kmeans.OptimalK(vectors, maxK)
}

// AnalyzeIndicator provides comprehensive ML analysis of a single indicator
func (s *MLService) AnalyzeIndicator(ctx context.Context, indicatorID uuid.UUID) (*models.MLEnrichmentResult, error) {
	if s.repos == nil {
		return nil, nil
	}

	indicator, err := s.repos.Indicators.GetByID(ctx, indicatorID)
	if err != nil {
		return nil, err
	}

	return s.EnrichIndicator(ctx, indicator)
}
