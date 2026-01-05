# Machine Learning API

The ML API provides machine learning capabilities for threat intelligence analysis, including anomaly detection, clustering, severity prediction, and NLP-based entity extraction.

## Base URL

```
/api/v1/ml
```

## Authentication

All endpoints require API key authentication via the `X-API-Key` header.

---

## Entity Extraction

### Extract Entities from Text

Extract all entities (IOCs, malware names, actors, etc.) from text.

```
POST /api/v1/ml/extract/entities
```

**Request Body:**
```json
{
  "text": "The APT29 group deployed Pegasus spyware targeting 192.168.1.1 via malicious domain evil.tk. The attack exploited CVE-2023-12345 using technique T1566."
}
```

**Response:**
```json
{
  "source_text": "The APT29 group deployed...",
  "entities": [
    {
      "text": "APT29",
      "type": "threat_actor",
      "start_pos": 4,
      "end_pos": 9,
      "confidence": 1.0,
      "normalized": "apt29"
    },
    {
      "text": "Pegasus",
      "type": "malware",
      "start_pos": 26,
      "end_pos": 33,
      "confidence": 1.0,
      "normalized": "pegasus"
    },
    {
      "text": "192.168.1.1",
      "type": "ip_address",
      "start_pos": 59,
      "end_pos": 70,
      "confidence": 0.3,
      "normalized": "192.168.1.1"
    },
    {
      "text": "evil.tk",
      "type": "domain",
      "start_pos": 92,
      "end_pos": 99,
      "confidence": 0.85,
      "normalized": "evil.tk"
    },
    {
      "text": "CVE-2023-12345",
      "type": "cve",
      "start_pos": 124,
      "end_pos": 138,
      "confidence": 1.0,
      "normalized": "CVE-2023-12345"
    },
    {
      "text": "T1566",
      "type": "mitre_technique",
      "start_pos": 155,
      "end_pos": 160,
      "confidence": 1.0,
      "normalized": "T1566"
    }
  ],
  "entity_counts": {
    "ip_address": 1,
    "domain": 1,
    "cve": 1,
    "mitre_technique": 1,
    "threat_actor": 1,
    "malware": 1
  },
  "indicators": [
    {
      "value": "192.168.1.1",
      "type": "ip",
      "confidence": 0.3
    },
    {
      "value": "evil.tk",
      "type": "domain",
      "confidence": 0.85
    }
  ],
  "processing_time": "1.2ms"
}
```

### Extract IOCs Only

Extract only Indicators of Compromise from text.

```
POST /api/v1/ml/extract/indicators
```

**Request Body:**
```json
{
  "text": "Check these IOCs: 8.8.8.8, evil.com, d41d8cd98f00b204e9800998ecf8427e"
}
```

**Response:**
```json
{
  "indicators": [
    {
      "value": "8.8.8.8",
      "type": "ip",
      "confidence": 0.95,
      "context": "8.8.8.8"
    },
    {
      "value": "evil.com",
      "type": "domain",
      "confidence": 0.85,
      "context": "evil.com"
    },
    {
      "value": "d41d8cd98f00b204e9800998ecf8427e",
      "type": "hash",
      "confidence": 0.9,
      "context": "d41d8cd98f00b204e9800998ecf8427e"
    }
  ],
  "count": 3
}
```

---

## ML Analysis

### Analyze Value

Perform ML analysis on a raw value.

```
POST /api/v1/ml/analyze
```

**Request Body:**
```json
{
  "value": "malicious-domain.tk",
  "type": "domain"
}
```

**Response:**
```json
{
  "indicator_id": "generated-uuid",
  "features": {
    "length": 19,
    "entropy": 3.42,
    "numeric_ratio": 0.0,
    "special_char_ratio": 0.1,
    "subdomain_count": 0,
    "tld_risk": 0.9,
    "current_severity": 0,
    "current_confidence": 0
  },
  "anomaly_score": {
    "score": 0.72,
    "is_anomaly": true,
    "threshold": 0.65,
    "confidence": 0.8,
    "contributors": ["tld_risk", "entropy"],
    "method": "isolation_forest"
  },
  "cluster_assignment": {
    "cluster_id": 3,
    "distance": 0.15,
    "confidence": 0.87,
    "is_outlier": false
  },
  "severity_prediction": {
    "predicted_severity": "high",
    "confidence": 0.78,
    "probabilities": {
      "critical": 0.1,
      "high": 0.78,
      "medium": 0.1,
      "low": 0.02,
      "info": 0.0
    },
    "explanation": "Predicted high with moderate confidence. Key factors: tld_risk, entropy, special_char_ratio"
  },
  "enriched_at": "2024-01-15T10:30:00Z",
  "processing_time": "5.2ms"
}
```

### Analyze Indicator by ID

Get ML analysis for an existing indicator.

```
GET /api/v1/ml/analyze/{id}
```

---

## Anomaly Detection

### Detect Anomalies

Run anomaly detection on a set of indicators.

```
POST /api/v1/ml/anomalies/detect
```

**Request Body:**
```json
{
  "indicator_ids": [
    "uuid-1",
    "uuid-2",
    "uuid-3"
  ]
}
```

**Response:**
```json
{
  "total_processed": 3,
  "anomaly_count": 1,
  "scores": [
    {
      "indicator_id": "uuid-1",
      "score": 0.42,
      "is_anomaly": false,
      "threshold": 0.65,
      "confidence": 0.75
    },
    {
      "indicator_id": "uuid-2",
      "score": 0.78,
      "is_anomaly": true,
      "threshold": 0.65,
      "confidence": 0.88,
      "contributors": ["entropy", "source_count"]
    }
  ],
  "statistics": {
    "mean_score": 0.55,
    "std_dev_score": 0.18,
    "min_score": 0.42,
    "max_score": 0.78,
    "anomaly_rate": 0.33
  },
  "processing_time": "12ms"
}
```

---

## Clustering

### Cluster Indicators

Group indicators into clusters based on feature similarity.

```
POST /api/v1/ml/cluster
```

**Request Body:**
```json
{
  "indicator_ids": ["uuid-1", "uuid-2", "..."],
  "k": 5
}
```

**Response:**
```json
{
  "k": 5,
  "clusters": [
    {
      "id": 0,
      "size": 15,
      "density": 2.3,
      "label": "High-risk domains",
      "top_features": [
        {
          "name": "tld_risk",
          "mean_value": 0.85,
          "importance": 0.42
        },
        {
          "name": "entropy",
          "mean_value": 0.72,
          "importance": 0.28
        }
      ],
      "suggested_campaign": {
        "name": "DGA-based Infrastructure",
        "confidence": 0.75
      }
    }
  ],
  "assignments": [
    {
      "indicator_id": "uuid-1",
      "cluster_id": 0,
      "distance": 0.12,
      "confidence": 0.92,
      "is_outlier": false
    }
  ],
  "silhouette_score": 0.68,
  "inertia": 124.5,
  "outlier_count": 3,
  "processing_time": "45ms"
}
```

---

## Severity Prediction

### Predict Severity

Predict severity levels for indicators using Random Forest.

```
POST /api/v1/ml/severity/predict
```

**Request Body:**
```json
{
  "indicator_ids": ["uuid-1", "uuid-2"]
}
```

**Response:**
```json
{
  "total_processed": 2,
  "predictions": [
    {
      "indicator_id": "uuid-1",
      "predicted_severity": "high",
      "confidence": 0.82,
      "probabilities": {
        "critical": 0.05,
        "high": 0.82,
        "medium": 0.10,
        "low": 0.03,
        "info": 0.0
      },
      "feature_importance": {
        "tld_risk": 0.25,
        "entropy": 0.18,
        "source_count": 0.15
      },
      "explanation": "Predicted high with high confidence. Key factors: tld_risk, entropy, source_count"
    }
  ],
  "processing_time": "8ms"
}
```

---

## Model Management

### Get All Models

Get information about all loaded ML models.

```
GET /api/v1/ml/models
```

**Response:**
```json
{
  "models_loaded": 3,
  "models": [
    {
      "name": "IsolationForest",
      "version": "1.0",
      "type": "anomaly_detection",
      "trained_at": "2024-01-15T10:00:00Z",
      "training_size": 10000,
      "parameters": {
        "num_trees": 100,
        "sample_size": 256,
        "contamination": 0.1,
        "threshold": 0.65
      },
      "feature_names": ["length", "entropy", "..."],
      "status": "ready"
    },
    {
      "name": "KMeans",
      "version": "1.0",
      "type": "clustering",
      "trained_at": "2024-01-15T10:00:00Z",
      "training_size": 10000,
      "accuracy": 0.72,
      "parameters": {
        "k": 8,
        "silhouette": 0.68,
        "inertia": 124.5
      },
      "status": "ready"
    },
    {
      "name": "RandomForest",
      "version": "1.0",
      "type": "classification",
      "trained_at": "2024-01-15T10:00:00Z",
      "training_size": 10000,
      "accuracy": 0.85,
      "parameters": {
        "num_trees": 100,
        "max_depth": 10,
        "num_classes": 5
      },
      "status": "ready"
    }
  ],
  "total_predictions": 15420,
  "total_anomalies": 892,
  "total_clusters": 8,
  "total_entities_extracted": 45000,
  "last_trained_at": "2024-01-15T10:00:00Z",
  "cache_hit_rate": 0.72
}
```

### Get Specific Model

Get information about a specific model.

```
GET /api/v1/ml/models/{model}
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `model` | string | Model type: `isolation_forest`, `kmeans`, `random_forest`, `anomaly`, `clustering`, `severity` |

### Train All Models

Train/retrain all ML models on current data.

```
POST /api/v1/ml/models/train
```

**Response:**
```json
{
  "model_type": "all",
  "version": "1.0",
  "training_size": 10000,
  "training_time": "45s",
  "success": true,
  "metrics": {
    "isolation_forest_threshold": 0.65,
    "kmeans_silhouette": 0.68,
    "random_forest_accuracy": 0.85
  }
}
```

### Train Specific Model

Train a specific ML model.

```
POST /api/v1/ml/models/{model}/train
```

---

## Features

### Get Feature List

Get the list of features used by ML models.

```
GET /api/v1/ml/features
```

**Response:**
```json
{
  "features": [
    "length",
    "entropy",
    "numeric_ratio",
    "special_char_ratio",
    "uppercase_ratio",
    "subdomain_count",
    "path_depth",
    "query_param_count",
    "has_ip",
    "has_port",
    "tld_risk",
    "domain_age",
    "is_private",
    "is_reserved",
    "asn_risk",
    "geo_risk",
    "first_seen_days",
    "last_seen_days",
    "source_count",
    "campaign_count",
    "related_count",
    "severity",
    "confidence",
    "report_count"
  ],
  "count": 24
}
```

---

## Statistics

### Get ML Stats

Get overall ML service statistics.

```
GET /api/v1/ml/stats
```

---

## Supported Entity Types

| Entity Type | Description | Example |
|-------------|-------------|---------|
| `ip_address` | IPv4/IPv6 addresses | `192.168.1.1` |
| `domain` | Domain names | `evil.com` |
| `url` | Full URLs | `https://evil.com/malware` |
| `email` | Email addresses | `attacker@evil.com` |
| `hash` | MD5, SHA1, SHA256 hashes | `d41d8cd98f00b204...` |
| `cve` | CVE identifiers | `CVE-2023-12345` |
| `mitre_technique` | MITRE ATT&CK techniques | `T1566`, `T1566.001` |
| `bitcoin_address` | Bitcoin wallet addresses | `1BvBMSEYstWetqT...` |
| `registry_key` | Windows registry keys | `HKLM\Software\...` |
| `file_path` | File system paths | `/usr/bin/malware` |
| `malware` | Known malware names | `Pegasus`, `Emotet` |
| `threat_actor` | Known threat groups | `APT29`, `Lazarus` |
| `campaign` | Known campaigns | `SolarWinds`, `Log4Shell` |
| `organization` | Organization names | (contextual extraction) |
| `date` | Date mentions | `2024-01-15` |

---

## ML Algorithms

### Isolation Forest (Anomaly Detection)

- **Purpose**: Detect anomalous indicators that don't fit normal patterns
- **Parameters**: 100 trees, 256 sample size, 10% contamination
- **Output**: Anomaly score (0-1), threshold-based classification

### K-Means (Clustering)

- **Purpose**: Group similar indicators for campaign detection
- **Parameters**: Auto-determined K using elbow method
- **Output**: Cluster assignments, silhouette score, campaign suggestions

### Random Forest (Classification)

- **Purpose**: Predict severity level of new indicators
- **Parameters**: 100 trees, max depth 10, Gini impurity
- **Output**: Severity prediction with confidence and feature importance

---

## Error Responses

```json
{
  "error": "error message",
  "details": "detailed error information"
}
```

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid API key |
| 404 | Not Found - Resource or model not found |
| 500 | Internal Server Error |
