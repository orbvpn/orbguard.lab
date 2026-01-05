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

// RandomForest implements Random Forest classification for severity prediction
type RandomForest struct {
	trees            []*decisionTree
	numTrees         int
	maxDepth         int
	minSamplesLeaf   int
	maxFeatures      int
	classes          []models.Severity
	classToIndex     map[models.Severity]int
	featureNames     []string
	featureImportance map[string]float64
	trained          bool
	trainingTime     time.Time
	trainingSize     int
	accuracy         float64
	mu               sync.RWMutex
	logger           *logger.Logger
}

// decisionTree represents a single tree in the forest
type decisionTree struct {
	root *dtNode
}

// dtNode represents a node in a decision tree
type dtNode struct {
	feature     int       // Feature index for split
	threshold   float64   // Split threshold
	left        *dtNode   // Left child (feature < threshold)
	right       *dtNode   // Right child (feature >= threshold)
	isLeaf      bool
	prediction  int       // Class index (for leaf nodes)
	probability []float64 // Class probabilities (for leaf nodes)
	importance  float64   // Split importance
}

// RandomForestConfig holds configuration
type RandomForestConfig struct {
	NumTrees       int   // Number of trees (default: 100)
	MaxDepth       int   // Maximum tree depth (default: 10)
	MinSamplesLeaf int   // Minimum samples in leaf (default: 5)
	MaxFeatures    int   // Max features to consider (default: sqrt(n_features))
	RandomSeed     int64 // Random seed
}

// DefaultRandomForestConfig returns default configuration
func DefaultRandomForestConfig() RandomForestConfig {
	return RandomForestConfig{
		NumTrees:       100,
		MaxDepth:       10,
		MinSamplesLeaf: 5,
		MaxFeatures:    0, // Will be set to sqrt(n_features)
		RandomSeed:     time.Now().UnixNano(),
	}
}

// NewRandomForest creates a new Random Forest classifier
func NewRandomForest(config RandomForestConfig, log *logger.Logger) *RandomForest {
	if config.NumTrees <= 0 {
		config.NumTrees = 100
	}
	if config.MaxDepth <= 0 {
		config.MaxDepth = 10
	}
	if config.MinSamplesLeaf <= 0 {
		config.MinSamplesLeaf = 5
	}

	rand.Seed(config.RandomSeed)

	// Define severity classes
	classes := []models.Severity{
		models.SeverityInfo,
		models.SeverityLow,
		models.SeverityMedium,
		models.SeverityHigh,
		models.SeverityCritical,
	}

	classToIndex := make(map[models.Severity]int)
	for i, c := range classes {
		classToIndex[c] = i
	}

	return &RandomForest{
		numTrees:       config.NumTrees,
		maxDepth:       config.MaxDepth,
		minSamplesLeaf: config.MinSamplesLeaf,
		maxFeatures:    config.MaxFeatures,
		classes:        classes,
		classToIndex:   classToIndex,
		logger:         log.WithComponent("random-forest"),
	}
}

// Train trains the random forest on labeled data
func (rf *RandomForest) Train(vectors []*models.FeatureVector, labels []models.Severity) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	startTime := time.Now()
	n := len(vectors)

	if n == 0 || len(labels) != n {
		return nil
	}

	// Extract feature names
	if len(vectors[0].Features) > 0 {
		rf.featureNames = make([]string, 0, len(vectors[0].Features))
		for name := range vectors[0].Features {
			rf.featureNames = append(rf.featureNames, name)
		}
		sort.Strings(rf.featureNames)
	}

	// Convert data
	data := make([][]float64, n)
	for i, v := range vectors {
		data[i] = v.Normalized
	}

	// Convert labels to indices
	labelIndices := make([]int, n)
	for i, label := range labels {
		labelIndices[i] = rf.classToIndex[label]
	}

	// Set max features if not specified
	numFeatures := len(data[0])
	if rf.maxFeatures <= 0 {
		rf.maxFeatures = int(math.Sqrt(float64(numFeatures)))
		if rf.maxFeatures < 1 {
			rf.maxFeatures = 1
		}
	}

	// Build trees
	rf.trees = make([]*decisionTree, rf.numTrees)
	rf.featureImportance = make(map[string]float64)

	for i := 0; i < rf.numTrees; i++ {
		// Bootstrap sample
		sampleData, sampleLabels := rf.bootstrapSample(data, labelIndices)

		// Build tree
		rf.trees[i] = rf.buildTree(sampleData, sampleLabels, numFeatures)
	}

	// Normalize feature importance
	totalImportance := 0.0
	for _, imp := range rf.featureImportance {
		totalImportance += imp
	}
	if totalImportance > 0 {
		for name := range rf.featureImportance {
			rf.featureImportance[name] /= totalImportance
		}
	}

	// Calculate training accuracy
	correct := 0
	for i, v := range vectors {
		pred := rf.predictClass(v.Normalized)
		if pred == labelIndices[i] {
			correct++
		}
	}
	rf.accuracy = float64(correct) / float64(n)

	rf.trained = true
	rf.trainingTime = time.Now()
	rf.trainingSize = n

	rf.logger.Info().
		Int("trees", rf.numTrees).
		Int("training_size", n).
		Float64("accuracy", rf.accuracy).
		Dur("duration", time.Since(startTime)).
		Msg("random forest trained")

	return nil
}

// Predict predicts severity for vectors
func (rf *RandomForest) Predict(vectors []*models.FeatureVector) []models.SeverityPrediction {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	predictions := make([]models.SeverityPrediction, len(vectors))

	for i, v := range vectors {
		predictions[i] = rf.predictOne(v)
	}

	return predictions
}

// predictOne predicts severity for a single vector
func (rf *RandomForest) predictOne(vector *models.FeatureVector) models.SeverityPrediction {
	if !rf.trained || len(rf.trees) == 0 {
		return models.SeverityPrediction{
			IndicatorID:       vector.IndicatorID,
			PredictedSeverity: models.SeverityMedium,
			Confidence:        0.5,
			ModelVersion:      "1.0",
			PredictedAt:       time.Now(),
		}
	}

	// Get predictions from all trees
	votes := make([]float64, len(rf.classes))
	for _, tree := range rf.trees {
		probs := rf.treePredictProba(tree.root, vector.Normalized)
		for c, p := range probs {
			votes[c] += p
		}
	}

	// Normalize to probabilities
	totalVotes := float64(len(rf.trees))
	probabilities := make(map[models.Severity]float64)
	maxProb := 0.0
	maxClass := 0

	for c, v := range votes {
		prob := v / totalVotes
		probabilities[rf.classes[c]] = prob
		if prob > maxProb {
			maxProb = prob
			maxClass = c
		}
	}

	// Get feature importance for this prediction
	importance := rf.getFeatureImportance()

	// Generate explanation
	explanation := rf.generateExplanation(rf.classes[maxClass], maxProb, importance)

	return models.SeverityPrediction{
		IndicatorID:       vector.IndicatorID,
		PredictedSeverity: rf.classes[maxClass],
		Confidence:        maxProb,
		Probabilities:     probabilities,
		FeatureImportance: importance,
		Explanation:       explanation,
		ModelVersion:      "1.0",
		PredictedAt:       time.Now(),
	}
}

// predictClass predicts class index for a point (internal use)
func (rf *RandomForest) predictClass(point []float64) int {
	votes := make([]int, len(rf.classes))

	for _, tree := range rf.trees {
		classIdx := rf.treePredictClass(tree.root, point)
		votes[classIdx]++
	}

	// Return class with most votes
	maxVotes := 0
	maxClass := 0
	for c, v := range votes {
		if v > maxVotes {
			maxVotes = v
			maxClass = c
		}
	}

	return maxClass
}

// treePredictClass predicts class for a single tree
func (rf *RandomForest) treePredictClass(node *dtNode, point []float64) int {
	if node == nil {
		return 0
	}

	for !node.isLeaf {
		if node.feature < len(point) && point[node.feature] < node.threshold {
			node = node.left
		} else {
			node = node.right
		}
		if node == nil {
			return 0
		}
	}

	return node.prediction
}

// treePredictProba predicts class probabilities for a single tree
func (rf *RandomForest) treePredictProba(node *dtNode, point []float64) []float64 {
	if node == nil {
		return make([]float64, len(rf.classes))
	}

	for !node.isLeaf {
		if node.feature < len(point) && point[node.feature] < node.threshold {
			node = node.left
		} else {
			node = node.right
		}
		if node == nil {
			return make([]float64, len(rf.classes))
		}
	}

	return node.probability
}

// buildTree builds a single decision tree
func (rf *RandomForest) buildTree(data [][]float64, labels []int, numFeatures int) *decisionTree {
	return &decisionTree{
		root: rf.buildNode(data, labels, 0, numFeatures),
	}
}

// buildNode recursively builds tree nodes
func (rf *RandomForest) buildNode(data [][]float64, labels []int, depth int, numFeatures int) *dtNode {
	n := len(data)

	// Calculate class distribution
	classCounts := make([]int, len(rf.classes))
	for _, label := range labels {
		classCounts[label]++
	}

	// Check stopping conditions
	if depth >= rf.maxDepth || n <= rf.minSamplesLeaf || rf.isPure(classCounts) {
		return rf.createLeaf(classCounts, n)
	}

	// Find best split
	bestFeature, bestThreshold, bestGain := rf.findBestSplit(data, labels, classCounts, numFeatures)

	if bestGain <= 0 {
		return rf.createLeaf(classCounts, n)
	}

	// Update feature importance
	if bestFeature < len(rf.featureNames) {
		featureName := rf.featureNames[bestFeature]
		rf.featureImportance[featureName] += bestGain * float64(n)
	}

	// Split data
	leftData, leftLabels, rightData, rightLabels := rf.splitData(data, labels, bestFeature, bestThreshold)

	if len(leftData) == 0 || len(rightData) == 0 {
		return rf.createLeaf(classCounts, n)
	}

	return &dtNode{
		feature:    bestFeature,
		threshold:  bestThreshold,
		left:       rf.buildNode(leftData, leftLabels, depth+1, numFeatures),
		right:      rf.buildNode(rightData, rightLabels, depth+1, numFeatures),
		isLeaf:     false,
		importance: bestGain,
	}
}

// createLeaf creates a leaf node
func (rf *RandomForest) createLeaf(classCounts []int, total int) *dtNode {
	// Find majority class
	maxCount := 0
	prediction := 0
	for c, count := range classCounts {
		if count > maxCount {
			maxCount = count
			prediction = c
		}
	}

	// Calculate probabilities
	probability := make([]float64, len(classCounts))
	if total > 0 {
		for c, count := range classCounts {
			probability[c] = float64(count) / float64(total)
		}
	}

	return &dtNode{
		isLeaf:      true,
		prediction:  prediction,
		probability: probability,
	}
}

// findBestSplit finds the best split using Gini impurity
func (rf *RandomForest) findBestSplit(data [][]float64, labels []int, classCounts []int, numFeatures int) (int, float64, float64) {
	n := len(data)
	if n == 0 || len(data[0]) == 0 {
		return 0, 0, 0
	}

	dims := len(data[0])
	currentGini := rf.giniImpurity(classCounts, n)

	bestFeature := -1
	bestThreshold := 0.0
	bestGain := 0.0

	// Randomly select features to consider
	features := rf.selectRandomFeatures(dims)

	for _, feature := range features {
		// Get unique values for this feature
		values := make([]float64, n)
		for i, point := range data {
			values[i] = point[feature]
		}
		sort.Float64s(values)

		// Try thresholds between unique values
		for i := 0; i < n-1; i++ {
			if values[i] == values[i+1] {
				continue
			}
			threshold := (values[i] + values[i+1]) / 2

			// Calculate split gain
			leftCounts := make([]int, len(rf.classes))
			rightCounts := make([]int, len(rf.classes))
			leftTotal := 0
			rightTotal := 0

			for j, point := range data {
				if point[feature] < threshold {
					leftCounts[labels[j]]++
					leftTotal++
				} else {
					rightCounts[labels[j]]++
					rightTotal++
				}
			}

			if leftTotal == 0 || rightTotal == 0 {
				continue
			}

			// Weighted Gini impurity after split
			leftGini := rf.giniImpurity(leftCounts, leftTotal)
			rightGini := rf.giniImpurity(rightCounts, rightTotal)
			weightedGini := (float64(leftTotal)*leftGini + float64(rightTotal)*rightGini) / float64(n)

			gain := currentGini - weightedGini

			if gain > bestGain {
				bestGain = gain
				bestFeature = feature
				bestThreshold = threshold
			}
		}
	}

	return bestFeature, bestThreshold, bestGain
}

// giniImpurity calculates Gini impurity
func (rf *RandomForest) giniImpurity(counts []int, total int) float64 {
	if total == 0 {
		return 0
	}

	impurity := 1.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		impurity -= p * p
	}
	return impurity
}

// isPure checks if all samples belong to one class
func (rf *RandomForest) isPure(classCounts []int) bool {
	nonZero := 0
	for _, count := range classCounts {
		if count > 0 {
			nonZero++
		}
	}
	return nonZero <= 1
}

// splitData splits data based on feature and threshold
func (rf *RandomForest) splitData(data [][]float64, labels []int, feature int, threshold float64) ([][]float64, []int, [][]float64, []int) {
	var leftData, rightData [][]float64
	var leftLabels, rightLabels []int

	for i, point := range data {
		if point[feature] < threshold {
			leftData = append(leftData, point)
			leftLabels = append(leftLabels, labels[i])
		} else {
			rightData = append(rightData, point)
			rightLabels = append(rightLabels, labels[i])
		}
	}

	return leftData, leftLabels, rightData, rightLabels
}

// selectRandomFeatures randomly selects features to consider
func (rf *RandomForest) selectRandomFeatures(numFeatures int) []int {
	if rf.maxFeatures >= numFeatures {
		features := make([]int, numFeatures)
		for i := range features {
			features[i] = i
		}
		return features
	}

	// Random selection without replacement
	indices := make([]int, numFeatures)
	for i := range indices {
		indices[i] = i
	}

	// Fisher-Yates shuffle for first maxFeatures elements
	for i := 0; i < rf.maxFeatures; i++ {
		j := i + rand.Intn(numFeatures-i)
		indices[i], indices[j] = indices[j], indices[i]
	}

	return indices[:rf.maxFeatures]
}

// bootstrapSample creates a bootstrap sample of the data
func (rf *RandomForest) bootstrapSample(data [][]float64, labels []int) ([][]float64, []int) {
	n := len(data)
	sampleData := make([][]float64, n)
	sampleLabels := make([]int, n)

	for i := 0; i < n; i++ {
		idx := rand.Intn(n)
		sampleData[i] = data[idx]
		sampleLabels[i] = labels[idx]
	}

	return sampleData, sampleLabels
}

// getFeatureImportance returns feature importance map
func (rf *RandomForest) getFeatureImportance() map[string]float64 {
	importance := make(map[string]float64)
	for name, imp := range rf.featureImportance {
		importance[name] = imp
	}
	return importance
}

// generateExplanation generates human-readable explanation
func (rf *RandomForest) generateExplanation(severity models.Severity, confidence float64, importance map[string]float64) string {
	// Find top 3 contributing features
	type featureImp struct {
		name string
		imp  float64
	}
	features := make([]featureImp, 0, len(importance))
	for name, imp := range importance {
		features = append(features, featureImp{name, imp})
	}
	sort.Slice(features, func(i, j int) bool {
		return features[i].imp > features[j].imp
	})

	explanation := "Predicted " + string(severity)
	if confidence >= 0.8 {
		explanation += " with high confidence"
	} else if confidence >= 0.5 {
		explanation += " with moderate confidence"
	} else {
		explanation += " with low confidence"
	}

	if len(features) > 0 {
		explanation += ". Key factors: "
		for i := 0; i < len(features) && i < 3; i++ {
			if i > 0 {
				explanation += ", "
			}
			explanation += features[i].name
		}
	}

	return explanation
}

// IsTrained returns whether the model has been trained
func (rf *RandomForest) IsTrained() bool {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.trained
}

// GetModelInfo returns information about the trained model
func (rf *RandomForest) GetModelInfo() models.MLModelInfo {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	status := "not_trained"
	if rf.trained {
		status = "ready"
	}

	return models.MLModelInfo{
		Name:         "RandomForest",
		Version:      "1.0",
		Type:         "classification",
		TrainedAt:    rf.trainingTime,
		TrainingSize: rf.trainingSize,
		Accuracy:     rf.accuracy,
		Parameters: map[string]interface{}{
			"num_trees":        rf.numTrees,
			"max_depth":        rf.maxDepth,
			"min_samples_leaf": rf.minSamplesLeaf,
			"max_features":     rf.maxFeatures,
			"num_classes":      len(rf.classes),
		},
		FeatureNames: rf.featureNames,
		Status:       status,
	}
}
