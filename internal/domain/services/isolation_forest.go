package services

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// IsolationForest implements the Isolation Forest anomaly detection algorithm
type IsolationForest struct {
	trees           []*isolationTree
	numTrees        int
	sampleSize      int
	maxDepth        int
	threshold       float64
	contamination   float64
	featureNames    []string
	trained         bool
	trainingSize    int
	trainingTime    time.Time
	avgPathLength   float64
	mu              sync.RWMutex
	logger          *logger.Logger
}

// isolationTree represents a single tree in the forest
type isolationTree struct {
	root        *isolationNode
	heightLimit int
}

// isolationNode represents a node in an isolation tree
type isolationNode struct {
	splitFeature int
	splitValue   float64
	left         *isolationNode
	right        *isolationNode
	size         int // number of samples at this node (for external nodes)
	isExternal   bool
}

// IsolationForestConfig holds configuration for the forest
type IsolationForestConfig struct {
	NumTrees      int     // Number of trees (default: 100)
	SampleSize    int     // Subsample size (default: 256)
	Contamination float64 // Expected proportion of anomalies (default: 0.1)
	RandomSeed    int64   // Random seed for reproducibility
}

// DefaultIsolationForestConfig returns default configuration
func DefaultIsolationForestConfig() IsolationForestConfig {
	return IsolationForestConfig{
		NumTrees:      100,
		SampleSize:    256,
		Contamination: 0.1,
		RandomSeed:    time.Now().UnixNano(),
	}
}

// NewIsolationForest creates a new Isolation Forest
func NewIsolationForest(config IsolationForestConfig, log *logger.Logger) *IsolationForest {
	if config.NumTrees <= 0 {
		config.NumTrees = 100
	}
	if config.SampleSize <= 0 {
		config.SampleSize = 256
	}
	if config.Contamination <= 0 || config.Contamination >= 1 {
		config.Contamination = 0.1
	}

	rand.Seed(config.RandomSeed)

	// Calculate max depth based on sample size
	maxDepth := int(math.Ceil(math.Log2(float64(config.SampleSize))))

	return &IsolationForest{
		numTrees:      config.NumTrees,
		sampleSize:    config.SampleSize,
		maxDepth:      maxDepth,
		contamination: config.Contamination,
		logger:        log.WithComponent("isolation-forest"),
	}
}

// Train trains the isolation forest on the given feature vectors
func (f *IsolationForest) Train(vectors []*models.FeatureVector) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	startTime := time.Now()
	n := len(vectors)

	if n == 0 {
		return nil
	}

	// Extract feature names from first vector
	if len(vectors[0].Features) > 0 {
		f.featureNames = make([]string, 0, len(vectors[0].Features))
		for name := range vectors[0].Features {
			f.featureNames = append(f.featureNames, name)
		}
		sort.Strings(f.featureNames) // Ensure consistent ordering
	}

	// Convert vectors to matrix format
	data := make([][]float64, n)
	for i, v := range vectors {
		data[i] = v.Normalized
	}

	// Adjust sample size if needed
	sampleSize := f.sampleSize
	if sampleSize > n {
		sampleSize = n
	}

	// Recalculate max depth
	f.maxDepth = int(math.Ceil(math.Log2(float64(sampleSize))))

	// Build trees
	f.trees = make([]*isolationTree, f.numTrees)
	for i := 0; i < f.numTrees; i++ {
		// Random subsample
		sample := f.subsample(data, sampleSize)
		f.trees[i] = f.buildTree(sample)
	}

	// Calculate average path length for normalization
	f.avgPathLength = f.averagePathLength(float64(sampleSize))

	// Calculate threshold based on contamination
	scores := make([]float64, n)
	for i, v := range vectors {
		scores[i] = f.calculateScore(v.Normalized)
	}
	sort.Float64s(scores)
	thresholdIdx := int(float64(n) * (1 - f.contamination))
	if thresholdIdx >= n {
		thresholdIdx = n - 1
	}
	f.threshold = scores[thresholdIdx]

	f.trained = true
	f.trainingSize = n
	f.trainingTime = time.Now()

	f.logger.Info().
		Int("trees", f.numTrees).
		Int("sample_size", sampleSize).
		Int("training_size", n).
		Float64("threshold", f.threshold).
		Dur("duration", time.Since(startTime)).
		Msg("isolation forest trained")

	return nil
}

// Predict returns anomaly scores for the given vectors
func (f *IsolationForest) Predict(vectors []*models.FeatureVector) []models.AnomalyScore {
	f.mu.RLock()
	defer f.mu.RUnlock()

	scores := make([]models.AnomalyScore, len(vectors))

	for i, v := range vectors {
		score := f.predictOne(v)
		scores[i] = score
	}

	return scores
}

// PredictOne returns anomaly score for a single vector
func (f *IsolationForest) PredictOne(vector *models.FeatureVector) models.AnomalyScore {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.predictOne(vector)
}

// predictOne internal prediction (no lock)
func (f *IsolationForest) predictOne(vector *models.FeatureVector) models.AnomalyScore {
	if !f.trained || len(f.trees) == 0 {
		return models.AnomalyScore{
			IndicatorID: vector.IndicatorID,
			Score:       0.5,
			IsAnomaly:   false,
			Method:      "isolation_forest",
			ComputedAt:  time.Now(),
		}
	}

	score := f.calculateScore(vector.Normalized)
	contributors := f.findContributors(vector)

	return models.AnomalyScore{
		IndicatorID:  vector.IndicatorID,
		Score:        score,
		IsAnomaly:    score >= f.threshold,
		Threshold:    f.threshold,
		Confidence:   f.calculateConfidence(score),
		Contributors: contributors,
		Method:       "isolation_forest",
		ComputedAt:   time.Now(),
	}
}

// calculateScore calculates the anomaly score for a data point
func (f *IsolationForest) calculateScore(point []float64) float64 {
	if len(f.trees) == 0 {
		return 0.5
	}

	// Calculate average path length across all trees
	totalPath := 0.0
	for _, tree := range f.trees {
		totalPath += f.pathLength(point, tree.root, 0)
	}
	avgPath := totalPath / float64(len(f.trees))

	// Calculate anomaly score using the formula: 2^(-avgPath / c(n))
	// where c(n) is the average path length of unsuccessful search in BST
	score := math.Pow(2, -avgPath/f.avgPathLength)

	return score
}

// pathLength calculates the path length for a point in a tree
func (f *IsolationForest) pathLength(point []float64, node *isolationNode, currentDepth int) float64 {
	if node == nil || node.isExternal {
		// External node - add expected path length for remaining isolation
		if node != nil && node.size > 1 {
			return float64(currentDepth) + f.averagePathLength(float64(node.size))
		}
		return float64(currentDepth)
	}

	// Traverse tree
	if node.splitFeature < len(point) {
		if point[node.splitFeature] < node.splitValue {
			return f.pathLength(point, node.left, currentDepth+1)
		}
		return f.pathLength(point, node.right, currentDepth+1)
	}

	return float64(currentDepth)
}

// averagePathLength calculates c(n) - the average path length of unsuccessful search in BST
func (f *IsolationForest) averagePathLength(n float64) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	// c(n) = 2H(n-1) - (2(n-1)/n)
	// where H(i) is the harmonic number approximated by ln(i) + 0.5772156649 (Euler's constant)
	h := math.Log(n-1) + 0.5772156649
	return 2*h - (2*(n-1))/n
}

// buildTree builds a single isolation tree
func (f *IsolationForest) buildTree(data [][]float64) *isolationTree {
	return &isolationTree{
		root:        f.buildNode(data, 0),
		heightLimit: f.maxDepth,
	}
}

// buildNode recursively builds tree nodes
func (f *IsolationForest) buildNode(data [][]float64, depth int) *isolationNode {
	n := len(data)

	// Terminal conditions
	if depth >= f.maxDepth || n <= 1 {
		return &isolationNode{
			size:       n,
			isExternal: true,
		}
	}

	// Get number of features
	numFeatures := 0
	if n > 0 && len(data[0]) > 0 {
		numFeatures = len(data[0])
	}
	if numFeatures == 0 {
		return &isolationNode{
			size:       n,
			isExternal: true,
		}
	}

	// Randomly select a feature
	feature := rand.Intn(numFeatures)

	// Find min and max values for this feature
	minVal := data[0][feature]
	maxVal := data[0][feature]
	for _, point := range data[1:] {
		if point[feature] < minVal {
			minVal = point[feature]
		}
		if point[feature] > maxVal {
			maxVal = point[feature]
		}
	}

	// If all values are the same, make this an external node
	if minVal == maxVal {
		return &isolationNode{
			size:       n,
			isExternal: true,
		}
	}

	// Random split value between min and max
	splitValue := minVal + rand.Float64()*(maxVal-minVal)

	// Partition data
	var leftData, rightData [][]float64
	for _, point := range data {
		if point[feature] < splitValue {
			leftData = append(leftData, point)
		} else {
			rightData = append(rightData, point)
		}
	}

	// Handle edge cases where all data goes to one side
	if len(leftData) == 0 || len(rightData) == 0 {
		return &isolationNode{
			size:       n,
			isExternal: true,
		}
	}

	return &isolationNode{
		splitFeature: feature,
		splitValue:   splitValue,
		left:         f.buildNode(leftData, depth+1),
		right:        f.buildNode(rightData, depth+1),
		isExternal:   false,
	}
}

// subsample creates a random subsample of the data
func (f *IsolationForest) subsample(data [][]float64, size int) [][]float64 {
	n := len(data)
	if size >= n {
		return data
	}

	// Fisher-Yates shuffle for first 'size' elements
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	for i := 0; i < size; i++ {
		j := i + rand.Intn(n-i)
		indices[i], indices[j] = indices[j], indices[i]
	}

	sample := make([][]float64, size)
	for i := 0; i < size; i++ {
		sample[i] = data[indices[i]]
	}

	return sample
}

// calculateConfidence calculates confidence based on score distance from threshold
func (f *IsolationForest) calculateConfidence(score float64) float64 {
	// Higher confidence when score is far from threshold
	distance := math.Abs(score - f.threshold)
	// Normalize to [0, 1] with sigmoid-like function
	return 1 / (1 + math.Exp(-10*(distance-0.1)))
}

// findContributors identifies features contributing most to the anomaly
func (f *IsolationForest) findContributors(vector *models.FeatureVector) []string {
	if len(f.featureNames) == 0 || len(vector.Features) == 0 {
		return nil
	}

	// Calculate feature contributions by measuring score change when feature is removed
	type contribution struct {
		name  string
		value float64
	}

	contributions := make([]contribution, 0, len(f.featureNames))
	baseScore := f.calculateScore(vector.Normalized)

	for i, name := range f.featureNames {
		if i >= len(vector.Normalized) {
			break
		}

		// Create modified vector with this feature set to median (0.5 after normalization)
		modified := make([]float64, len(vector.Normalized))
		copy(modified, vector.Normalized)
		modified[i] = 0.5

		newScore := f.calculateScore(modified)
		contrib := math.Abs(baseScore - newScore)

		contributions = append(contributions, contribution{name, contrib})
	}

	// Sort by contribution
	sort.Slice(contributions, func(i, j int) bool {
		return contributions[i].value > contributions[j].value
	})

	// Return top 5 contributors
	result := make([]string, 0, 5)
	for i := 0; i < len(contributions) && i < 5; i++ {
		if contributions[i].value > 0.01 { // Only include significant contributors
			result = append(result, contributions[i].name)
		}
	}

	return result
}

// IsTrained returns whether the forest has been trained
func (f *IsolationForest) IsTrained() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.trained
}

// GetModelInfo returns information about the trained model
func (f *IsolationForest) GetModelInfo() models.MLModelInfo {
	f.mu.RLock()
	defer f.mu.RUnlock()

	status := "not_trained"
	if f.trained {
		status = "ready"
	}

	return models.MLModelInfo{
		Name:         "IsolationForest",
		Version:      "1.0",
		Type:         "anomaly_detection",
		TrainedAt:    f.trainingTime,
		TrainingSize: f.trainingSize,
		Parameters: map[string]interface{}{
			"num_trees":     f.numTrees,
			"sample_size":   f.sampleSize,
			"max_depth":     f.maxDepth,
			"contamination": f.contamination,
			"threshold":     f.threshold,
		},
		FeatureNames: f.featureNames,
		Status:       status,
	}
}
