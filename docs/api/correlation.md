# Correlation Engine API

The Correlation Engine provides advanced threat intelligence correlation capabilities, including temporal analysis, infrastructure overlap detection, TTP matching, and campaign auto-detection.

## Base URL

All correlation endpoints require authentication and are prefixed with:
```
/api/v1/correlation
```

## Endpoints

### POST /

Perform full correlation analysis on a set of indicators.

**Request Body:**
```json
{
  "indicator_ids": ["uuid1", "uuid2", "uuid3"],
  "indicator_values": ["192.168.1.1", "malicious.com"],
  "types": ["temporal", "infrastructure", "ttp", "campaign", "network"],
  "min_confidence": 0.5,
  "time_range": {
    "start": "2025-01-01T00:00:00Z",
    "end": "2025-01-31T00:00:00Z"
  },
  "include_evidence": true,
  "max_results": 50
}
```

**Response:**
```json
{
  "request_id": "uuid",
  "correlations": [
    {
      "id": "uuid",
      "type": "infrastructure",
      "strength": "strong",
      "confidence": 0.85,
      "description": "5 IPs share subnet 192.168.1.0/24",
      "indicators": ["uuid1", "uuid2", "uuid3"],
      "evidence": {
        "network_patterns": [
          {
            "type": "same_subnet",
            "pattern": "192.168.1.0/24",
            "ips": ["192.168.1.1", "192.168.1.2"],
            "count": 5
          }
        ]
      },
      "created_at": "2025-01-05T12:00:00Z"
    }
  ],
  "clusters": [
    {
      "id": "uuid",
      "name": "Infrastructure Cluster",
      "indicators": [...],
      "cluster_type": "infrastructure",
      "confidence": 0.85,
      "common_traits": ["shared subnet: 192.168.1.0/24"],
      "suggested_campaign": {
        "name": "Potential Campaign abc123",
        "confidence": 0.7,
        "indicator_count": 5
      }
    }
  ],
  "campaign_matches": [
    {
      "campaign_id": "uuid",
      "campaign_name": "Pegasus 2025",
      "confidence": 0.75,
      "matching_indicators": 3,
      "shared_patterns": ["pegasus"]
    }
  ],
  "actor_matches": [
    {
      "actor_id": "uuid",
      "actor_name": "NSO Group",
      "confidence": 0.8,
      "matched_ttps": ["T1566", "T1055"],
      "matched_infra": ["malicious.com"]
    }
  ],
  "statistics": {
    "total_indicators": 10,
    "correlations_found": 5,
    "clusters_formed": 2,
    "campaigns_matched": 1,
    "actors_matched": 1,
    "average_confidence": 0.75,
    "strongest_correlation": 0.85
  },
  "processing_time": "125ms",
  "generated_at": "2025-01-05T12:00:00Z"
}
```

### POST /batch

Correlate multiple indicators by ID.

**Request Body:**
```json
{
  "indicator_ids": ["uuid1", "uuid2", "uuid3"]
}
```

**Response:** Same as POST /

### POST /analyze

Analyze a single indicator value.

**Request Body:**
```json
{
  "value": "192.168.1.1"
}
```

**Response:** Same as POST /

---

## Single Indicator Correlation

### GET /indicator/{id}

Get full correlation for a single indicator.

**Response:** Same as POST /

### GET /indicator/{id}/temporal

Get temporal correlations for an indicator.

**Query Parameters:**
- `window` - Time window (1h, 24h, 7d)

**Response:**
```json
{
  "correlations": [
    {
      "type": "temporal",
      "strength": "very_strong",
      "confidence": 0.95,
      "description": "10 indicators appeared within 1_hour window",
      "evidence": {
        "temporal_links": [
          {
            "window_start": "2025-01-05T10:00:00Z",
            "window_end": "2025-01-05T11:00:00Z",
            "count": 10,
            "indicators": ["1.1.1.1", "2.2.2.2"]
          }
        ]
      }
    }
  ]
}
```

### GET /indicator/{id}/infrastructure

Get infrastructure overlap for an indicator.

**Response:**
```json
{
  "correlations": [
    {
      "type": "infrastructure",
      "strength": "strong",
      "confidence": 0.8,
      "description": "5 IPs share subnet 192.168.1.0/24",
      "evidence": {
        "network_patterns": [...],
        "domain_patterns": [...],
        "shared_infra": [...]
      }
    }
  ],
  "clusters": [...]
}
```

### GET /indicator/{id}/ttp

Get TTP (Tactics, Techniques, Procedures) correlations.

**Response:**
```json
{
  "correlations": [
    {
      "type": "ttp",
      "strength": "moderate",
      "confidence": 0.6,
      "description": "5 indicators share MITRE technique T1566",
      "evidence": {
        "ttp_matches": [
          {
            "technique_id": "T1566",
            "technique_name": "Phishing"
          }
        ]
      }
    }
  ]
}
```

---

## Campaign Correlation

### POST /campaigns/match

Match indicators to existing campaigns.

**Request Body:**
```json
{
  "indicator_ids": ["uuid1", "uuid2"]
}
```

**Response:**
```json
{
  "campaign_matches": [
    {
      "campaign_id": "uuid",
      "campaign_name": "Pegasus Campaign",
      "confidence": 0.85,
      "matching_indicators": 5,
      "shared_patterns": ["pegasus", "nso"]
    }
  ],
  "actor_matches": [
    {
      "actor_id": "uuid",
      "actor_name": "NSO Group",
      "confidence": 0.9,
      "matched_ttps": ["T1055", "T1566"],
      "matched_infra": ["example.com"]
    }
  ]
}
```

### GET /campaigns/detect

Auto-detect potential campaigns from uncategorized indicators.

**Query Parameters:**
- `limit` - Maximum suggestions (default: 10)

**Response:**
```json
{
  "suggestions": [
    {
      "name": "Potential Campaign abc123",
      "description": "Auto-detected cluster of 15 related indicators",
      "confidence": 0.75,
      "indicator_count": 15,
      "time_range": {
        "start": "2025-01-01T00:00:00Z",
        "end": "2025-01-05T00:00:00Z"
      },
      "common_patterns": ["shared subnet: 10.0.0.0/24"],
      "suggested_actor": "Unknown",
      "mitre_techniques": ["T1566"]
    }
  ],
  "count": 3
}
```

---

## Clustering

### POST /cluster

Cluster a set of indicators by similarity.

**Request Body:**
```json
{
  "indicator_ids": ["uuid1", "uuid2", "uuid3", "uuid4", "uuid5"]
}
```

**Response:**
```json
{
  "clusters": [
    {
      "id": "uuid",
      "name": "Infrastructure Cluster",
      "indicators": [
        {
          "id": "uuid1",
          "type": "ip",
          "value": "192.168.1.1",
          "severity": "high",
          "first_seen": "2025-01-01T00:00:00Z"
        }
      ],
      "cluster_type": "infrastructure",
      "confidence": 0.85,
      "common_traits": ["shared subnet: 192.168.1.0/24"],
      "suggested_campaign": {
        "name": "Potential Campaign",
        "confidence": 0.7
      }
    }
  ],
  "statistics": {
    "total_indicators": 5,
    "clusters_formed": 2
  }
}
```

---

## Statistics

### GET /stats

Get correlation engine statistics.

**Response:**
```json
{
  "total_correlations": 15420,
  "correlations_by_type": {
    "temporal": 5000,
    "infrastructure": 8000,
    "ttp": 1500,
    "campaign": 920
  },
  "correlations_by_strength": {
    "weak": 3000,
    "moderate": 5000,
    "strong": 5420,
    "very_strong": 2000
  },
  "campaigns_detected": 45,
  "clusters_formed": 234,
  "average_processing_time": "85ms",
  "last_processed_at": "2025-01-05T12:00:00Z"
}
```

---

## Correlation Types

| Type | Description |
|------|-------------|
| `temporal` | Indicators appearing within the same time window |
| `infrastructure` | Shared IP subnets, domain patterns, ASN, registrar |
| `ttp` | Shared MITRE ATT&CK techniques |
| `campaign` | Matching existing campaigns |
| `network` | Network-based correlations (URL domains, etc.) |
| `behavioral` | Similar behavioral patterns (future) |

## Correlation Strength

| Strength | Confidence Range | Description |
|----------|------------------|-------------|
| `very_strong` | 90-100% | High confidence, strong evidence |
| `strong` | 70-89% | Good confidence, multiple evidence |
| `moderate` | 50-69% | Medium confidence, some evidence |
| `weak` | 0-49% | Low confidence, minimal evidence |

## Evidence Types

### Temporal Links
```json
{
  "window_start": "timestamp",
  "window_end": "timestamp",
  "count": 10,
  "indicators": ["value1", "value2"]
}
```

### Network Patterns
```json
{
  "type": "same_subnet|same_asn|same_hosting",
  "pattern": "192.168.0.0/24",
  "ips": ["ip1", "ip2"],
  "count": 5
}
```

### Domain Patterns
```json
{
  "pattern": "typosquat-common",
  "domains": ["googgle.com", "gooogle.com"],
  "similarity": 0.9
}
```

### TTP Matches
```json
{
  "technique_id": "T1566",
  "technique_name": "Phishing",
  "actors": ["Actor1"],
  "campaigns": ["Campaign1"]
}
```

### Shared Infrastructure
```json
{
  "type": "ip|asn|registrar|nameserver",
  "value": "AS12345",
  "indicators": ["indicator1", "indicator2"],
  "count": 5
}
```

## Error Responses

```json
{
  "error": "Error message",
  "details": "Additional context"
}
```

| Status | Description |
|--------|-------------|
| 400 | Invalid request (missing indicators, bad format) |
| 404 | Indicator not found |
| 500 | Correlation engine error |

## Configuration

The correlation engine uses these default thresholds:

| Setting | Default | Description |
|---------|---------|-------------|
| `temporal_window_short` | 1 hour | Short time correlation window |
| `temporal_window_medium` | 24 hours | Medium time correlation window |
| `temporal_window_long` | 7 days | Long time correlation window |
| `min_temporal_overlap` | 3 | Minimum indicators for temporal correlation |
| `min_shared_infra` | 2 | Minimum shared infrastructure |
| `ip_subnet_mask` | /24 | IP subnet grouping |
| `domain_similarity_min` | 70% | Minimum domain similarity |
| `min_ttp_overlap` | 2 | Minimum shared techniques |
| `min_campaign_indicators` | 5 | Minimum for campaign suggestion |
| `campaign_confidence_min` | 60% | Minimum campaign confidence |
