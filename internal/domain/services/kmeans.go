package services

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// KMeans implements K-Means clustering for indicator grouping
type KMeans struct {
	k              int
	maxIterations  int
	tolerance      float64
	centroids      [][]float64
	assignments    []int
	featureNames   []string
	trained        bool
	trainingTime   time.Time
	trainingSize   int
	silhouette     float64
	inertia        float64
	mu             sync.RWMutex
	logger         *logger.Logger
}

// KMeansConfig holds configuration for K-Means
type KMeansConfig struct {
	K             int     // Number of clusters
	MaxIterations int     // Maximum iterations (default: 100)
	Tolerance     float64 // Convergence tolerance (default: 1e-4)
	RandomSeed    int64   // Random seed
}

// DefaultKMeansConfig returns default configuration
func DefaultKMeansConfig() KMeansConfig {
	return KMeansConfig{
		K:             5,
		MaxIterations: 100,
		Tolerance:     1e-4,
		RandomSeed:    time.Now().UnixNano(),
	}
}

// NewKMeans creates a new K-Means clustering model
func NewKMeans(config KMeansConfig, log *logger.Logger) *KMeans {
	if config.K <= 0 {
		config.K = 5
	}
	if config.MaxIterations <= 0 {
		config.MaxIterations = 100
	}
	if config.Tolerance <= 0 {
		config.Tolerance = 1e-4
	}

	rand.Seed(config.RandomSeed)

	return &KMeans{
		k:             config.K,
		maxIterations: config.MaxIterations,
		tolerance:     config.Tolerance,
		logger:        log.WithComponent("kmeans"),
	}
}

// Train trains the K-Means model on feature vectors
func (km *KMeans) Train(vectors []*models.FeatureVector) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	startTime := time.Now()
	n := len(vectors)

	if n == 0 {
		return nil
	}
	if n < km.k {
		km.k = n
	}

	// Extract feature names from first vector
	if len(vectors[0].Features) > 0 {
		km.featureNames = make([]string, 0, len(vectors[0].Features))
		for name := range vectors[0].Features {
			km.featureNames = append(km.featureNames, name)
		}
		sort.Strings(km.featureNames)
	}

	// Convert to matrix format
	data := make([][]float64, n)
	for i, v := range vectors {
		data[i] = v.Normalized
	}

	// Initialize centroids using K-Means++
	km.initializeCentroidsKMeansPP(data)

	// Run K-Means iterations
	km.assignments = make([]int, n)
	var prevInertia float64 = math.MaxFloat64

	for iter := 0; iter < km.maxIterations; iter++ {
		// Assignment step
		km.assignClusters(data)

		// Update step
		km.updateCentroids(data)

		// Calculate inertia (sum of squared distances to centroids)
		km.inertia = km.calculateInertia(data)

		// Check convergence
		if math.Abs(prevInertia-km.inertia) < km.tolerance {
			km.logger.Debug().
				Int("iteration", iter).
				Float64("inertia", km.inertia).
				Msg("K-Means converged")
			break
		}
		prevInertia = km.inertia
	}

	// Calculate silhouette score
	km.silhouette = km.calculateSilhouetteScore(data)

	km.trained = true
	km.trainingTime = time.Now()
	km.trainingSize = n

	km.logger.Info().
		Int("k", km.k).
		Int("training_size", n).
		Float64("inertia", km.inertia).
		Float64("silhouette", km.silhouette).
		Dur("duration", time.Since(startTime)).
		Msg("K-Means trained")

	return nil
}

// Predict assigns vectors to clusters
func (km *KMeans) Predict(vectors []*models.FeatureVector) *models.ClusteringResult {
	km.mu.RLock()
	defer km.mu.RUnlock()

	startTime := time.Now()
	assignments := make([]models.ClusterAssignment, len(vectors))
	outlierCount := 0

	// Calculate mean distance for outlier detection
	meanDist := km.calculateMeanDistanceToCentroids(vectors)
	outlierThreshold := meanDist * 2.0 // Points > 2x mean distance are outliers

	for i, v := range vectors {
		clusterID, distance := km.nearestCentroid(v.Normalized)
		confidence := 1.0 / (1.0 + distance) // Higher distance = lower confidence
		isOutlier := distance > outlierThreshold

		if isOutlier {
			outlierCount++
		}

		assignments[i] = models.ClusterAssignment{
			IndicatorID: v.IndicatorID,
			ClusterID:   clusterID,
			Distance:    distance,
			Confidence:  confidence,
			IsOutlier:   isOutlier,
		}
	}

	// Build cluster information
	clusters := km.buildClusterInfo(vectors, assignments)

	return &models.ClusteringResult{
		K:              km.k,
		Clusters:       clusters,
		Assignments:    assignments,
		Silhouette:     km.silhouette,
		Inertia:        km.inertia,
		OutlierCount:   outlierCount,
		ProcessingTime: time.Since(startTime),
	}
}

// initializeCentroidsKMeansPP initializes centroids using K-Means++ algorithm
func (km *KMeans) initializeCentroidsKMeansPP(data [][]float64) {
	n := len(data)
	if n == 0 || len(data[0]) == 0 {
		return
	}

	dims := len(data[0])
	km.centroids = make([][]float64, km.k)

	// Choose first centroid randomly
	firstIdx := rand.Intn(n)
	km.centroids[0] = make([]float64, dims)
	copy(km.centroids[0], data[firstIdx])

	// Choose remaining centroids
	distances := make([]float64, n)
	for c := 1; c < km.k; c++ {
		// Calculate distance to nearest centroid for each point
		totalDist := 0.0
		for i, point := range data {
			minDist := math.MaxFloat64
			for j := 0; j < c; j++ {
				dist := km.euclideanDistance(point, km.centroids[j])
				if dist < minDist {
					minDist = dist
				}
			}
			distances[i] = minDist * minDist // Use squared distance
			totalDist += distances[i]
		}

		// Choose next centroid with probability proportional to squared distance
		target := rand.Float64() * totalDist
		cumulative := 0.0
		chosenIdx := 0
		for i, d := range distances {
			cumulative += d
			if cumulative >= target {
				chosenIdx = i
				break
			}
		}

		km.centroids[c] = make([]float64, dims)
		copy(km.centroids[c], data[chosenIdx])
	}
}

// assignClusters assigns each point to nearest centroid
func (km *KMeans) assignClusters(data [][]float64) {
	for i, point := range data {
		km.assignments[i], _ = km.nearestCentroid(point)
	}
}

// updateCentroids recalculates centroids based on assignments
func (km *KMeans) updateCentroids(data [][]float64) {
	if len(data) == 0 || len(data[0]) == 0 {
		return
	}

	dims := len(data[0])
	counts := make([]int, km.k)
	newCentroids := make([][]float64, km.k)
	for c := 0; c < km.k; c++ {
		newCentroids[c] = make([]float64, dims)
	}

	// Sum up points per cluster
	for i, point := range data {
		cluster := km.assignments[i]
		counts[cluster]++
		for d := 0; d < dims; d++ {
			newCentroids[cluster][d] += point[d]
		}
	}

	// Calculate mean
	for c := 0; c < km.k; c++ {
		if counts[c] > 0 {
			for d := 0; d < dims; d++ {
				newCentroids[c][d] /= float64(counts[c])
			}
			km.centroids[c] = newCentroids[c]
		}
	}
}

// nearestCentroid finds the nearest centroid for a point
func (km *KMeans) nearestCentroid(point []float64) (int, float64) {
	if len(km.centroids) == 0 {
		return 0, 0
	}

	minDist := math.MaxFloat64
	minIdx := 0

	for i, centroid := range km.centroids {
		dist := km.euclideanDistance(point, centroid)
		if dist < minDist {
			minDist = dist
			minIdx = i
		}
	}

	return minIdx, minDist
}

// euclideanDistance calculates Euclidean distance between two points
func (km *KMeans) euclideanDistance(a, b []float64) float64 {
	if len(a) != len(b) {
		return math.MaxFloat64
	}

	sum := 0.0
	for i := range a {
		diff := a[i] - b[i]
		sum += diff * diff
	}
	return math.Sqrt(sum)
}

// calculateInertia calculates sum of squared distances to centroids
func (km *KMeans) calculateInertia(data [][]float64) float64 {
	inertia := 0.0
	for i, point := range data {
		cluster := km.assignments[i]
		dist := km.euclideanDistance(point, km.centroids[cluster])
		inertia += dist * dist
	}
	return inertia
}

// calculateSilhouetteScore calculates silhouette coefficient
func (km *KMeans) calculateSilhouetteScore(data [][]float64) float64 {
	n := len(data)
	if n <= 1 || km.k <= 1 {
		return 0
	}

	silhouettes := make([]float64, n)

	for i, point := range data {
		cluster := km.assignments[i]

		// Calculate a(i): mean distance to other points in same cluster
		sameClusterDist := 0.0
		sameClusterCount := 0
		for j, other := range data {
			if i != j && km.assignments[j] == cluster {
				sameClusterDist += km.euclideanDistance(point, other)
				sameClusterCount++
			}
		}
		var a float64
		if sameClusterCount > 0 {
			a = sameClusterDist / float64(sameClusterCount)
		}

		// Calculate b(i): min mean distance to points in other clusters
		b := math.MaxFloat64
		for c := 0; c < km.k; c++ {
			if c == cluster {
				continue
			}
			otherClusterDist := 0.0
			otherClusterCount := 0
			for j, other := range data {
				if km.assignments[j] == c {
					otherClusterDist += km.euclideanDistance(point, other)
					otherClusterCount++
				}
			}
			if otherClusterCount > 0 {
				meanDist := otherClusterDist / float64(otherClusterCount)
				if meanDist < b {
					b = meanDist
				}
			}
		}

		// Calculate silhouette
		if b == math.MaxFloat64 {
			silhouettes[i] = 0
		} else if a < b {
			silhouettes[i] = 1 - a/b
		} else if a > b {
			silhouettes[i] = b/a - 1
		} else {
			silhouettes[i] = 0
		}
	}

	// Return mean silhouette
	sum := 0.0
	for _, s := range silhouettes {
		sum += s
	}
	return sum / float64(n)
}

// calculateMeanDistanceToCentroids calculates mean distance for outlier detection
func (km *KMeans) calculateMeanDistanceToCentroids(vectors []*models.FeatureVector) float64 {
	if len(vectors) == 0 {
		return 0
	}

	totalDist := 0.0
	for _, v := range vectors {
		_, dist := km.nearestCentroid(v.Normalized)
		totalDist += dist
	}
	return totalDist / float64(len(vectors))
}

// buildClusterInfo builds detailed cluster information
func (km *KMeans) buildClusterInfo(vectors []*models.FeatureVector, assignments []models.ClusterAssignment) []models.Cluster {
	clusters := make([]models.Cluster, km.k)

	// Initialize clusters
	for c := 0; c < km.k; c++ {
		clusters[c] = models.Cluster{
			ID:       c,
			Centroid: km.centroids[c],
			Members:  make([]uuid.UUID, 0),
		}
	}

	// Assign members and calculate density
	clusterDistances := make([][]float64, km.k)
	for c := range clusterDistances {
		clusterDistances[c] = make([]float64, 0)
	}

	for i, assignment := range assignments {
		c := assignment.ClusterID
		clusters[c].Size++
		clusters[c].Members = append(clusters[c].Members, vectors[i].IndicatorID)
		clusterDistances[c] = append(clusterDistances[c], assignment.Distance)
	}

	// Calculate density (inverse of mean distance)
	for c := 0; c < km.k; c++ {
		if len(clusterDistances[c]) > 0 {
			meanDist := 0.0
			for _, d := range clusterDistances[c] {
				meanDist += d
			}
			meanDist /= float64(len(clusterDistances[c]))
			if meanDist > 0 {
				clusters[c].Density = 1.0 / meanDist
			}
		}

		// Calculate top features for this cluster
		clusters[c].TopFeatures = km.calculateTopFeatures(c)
	}

	return clusters
}

// calculateTopFeatures identifies most distinctive features for a cluster
func (km *KMeans) calculateTopFeatures(clusterID int) []models.ClusterFeature {
	if clusterID >= len(km.centroids) || len(km.centroids[clusterID]) == 0 {
		return nil
	}

	centroid := km.centroids[clusterID]

	// Calculate overall mean across all centroids
	dims := len(centroid)
	globalMean := make([]float64, dims)
	for _, c := range km.centroids {
		for d := 0; d < dims && d < len(c); d++ {
			globalMean[d] += c[d]
		}
	}
	for d := 0; d < dims; d++ {
		globalMean[d] /= float64(km.k)
	}

	// Calculate feature importance as deviation from global mean
	type featureImportance struct {
		index      int
		importance float64
		value      float64
	}
	importances := make([]featureImportance, 0, dims)

	for d := 0; d < dims && d < len(centroid); d++ {
		importance := math.Abs(centroid[d] - globalMean[d])
		importances = append(importances, featureImportance{
			index:      d,
			importance: importance,
			value:      centroid[d],
		})
	}

	// Sort by importance
	sort.Slice(importances, func(i, j int) bool {
		return importances[i].importance > importances[j].importance
	})

	// Return top 5 features
	result := make([]models.ClusterFeature, 0, 5)
	for i := 0; i < len(importances) && i < 5; i++ {
		name := "feature_" + string(rune('A'+i))
		if importances[i].index < len(km.featureNames) {
			name = km.featureNames[importances[i].index]
		}
		result = append(result, models.ClusterFeature{
			Name:       name,
			MeanValue:  importances[i].value,
			Importance: importances[i].importance,
		})
	}

	return result
}

// OptimalK uses elbow method to find optimal number of clusters
func (km *KMeans) OptimalK(vectors []*models.FeatureVector, maxK int) int {
	if len(vectors) < 2 {
		return 1
	}
	if maxK > len(vectors) {
		maxK = len(vectors)
	}
	if maxK < 2 {
		maxK = 2
	}

	// Convert to matrix
	data := make([][]float64, len(vectors))
	for i, v := range vectors {
		data[i] = v.Normalized
	}

	inertias := make([]float64, maxK)

	// Calculate inertia for each k
	for k := 1; k <= maxK; k++ {
		tempKM := &KMeans{
			k:             k,
			maxIterations: 50,
			tolerance:     1e-3,
		}
		tempKM.initializeCentroidsKMeansPP(data)
		tempKM.assignments = make([]int, len(data))

		for iter := 0; iter < tempKM.maxIterations; iter++ {
			tempKM.assignClusters(data)
			tempKM.updateCentroids(data)
		}

		inertias[k-1] = tempKM.calculateInertia(data)
	}

	// Find elbow point using second derivative
	optimalK := 1
	maxSecondDeriv := 0.0

	for k := 2; k < maxK; k++ {
		// Second derivative: f''(k) ≈ f(k-1) - 2*f(k) + f(k+1)
		secondDeriv := inertias[k-2] - 2*inertias[k-1] + inertias[k]
		if secondDeriv > maxSecondDeriv {
			maxSecondDeriv = secondDeriv
			optimalK = k
		}
	}

	return optimalK
}

// IsTrained returns whether the model has been trained
func (km *KMeans) IsTrained() bool {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.trained
}

// GetModelInfo returns information about the trained model
func (km *KMeans) GetModelInfo() models.MLModelInfo {
	km.mu.RLock()
	defer km.mu.RUnlock()

	status := "not_trained"
	if km.trained {
		status = "ready"
	}

	return models.MLModelInfo{
		Name:         "KMeans",
		Version:      "1.0",
		Type:         "clustering",
		TrainedAt:    km.trainingTime,
		TrainingSize: km.trainingSize,
		Accuracy:     km.silhouette, // Use silhouette as quality metric
		Parameters: map[string]interface{}{
			"k":              km.k,
			"max_iterations": km.maxIterations,
			"tolerance":      km.tolerance,
			"silhouette":     km.silhouette,
			"inertia":        km.inertia,
		},
		FeatureNames: km.featureNames,
		Status:       status,
	}
}
