# Graph API - Neo4j Threat Intelligence Correlation

The Graph API provides threat intelligence correlation using Neo4j graph database. It enables discovery of relationships between indicators, campaigns, threat actors, and shared infrastructure.

## Base URL

```
/api/v1/graph
```

## Authentication

All endpoints require API key authentication:
```
Authorization: Bearer <api-key>
```

## Endpoints

### Get Indicator Correlation

Returns correlation data for an indicator including related indicators, campaigns, actors, and infrastructure.

```http
GET /api/v1/graph/correlation/{id}
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| id | UUID | Indicator UUID |

**Response:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "primary_indicator": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "type": "domain",
    "value": "malicious.example.com",
    "severity": "critical",
    "confidence": 0.95,
    "first_seen": "2024-01-15T10:30:00Z",
    "last_seen": "2024-01-20T14:45:00Z",
    "tags": ["pegasus", "c2"],
    "source": "citizenlab"
  },
  "related_indicators": [
    {
      "indicator": {
        "id": "...",
        "type": "ip",
        "value": "192.168.1.100"
      },
      "relation_type": "RESOLVES",
      "relation_strength": 0.9,
      "path_length": 1
    }
  ],
  "campaigns": [
    {
      "id": "...",
      "slug": "pegasus",
      "name": "Pegasus",
      "is_active": true
    }
  ],
  "threat_actors": [
    {
      "id": "...",
      "name": "NSO Group",
      "country": "Israel"
    }
  ],
  "infrastructure": [],
  "total_relations": 15,
  "risk_score": 9.5,
  "correlation_score": 0.87,
  "generated_at": "2024-01-20T16:00:00Z"
}
```

---

### Find Related Indicators

Finds indicators related to a given indicator through the threat graph.

```http
GET /api/v1/graph/related/{id}
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| id | UUID | Indicator UUID |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| max_depth | int | 2 | Maximum traversal depth (1-5) |
| limit | int | 50 | Maximum results (max 200) |

**Response:**
```json
[
  {
    "indicator": {
      "id": "...",
      "type": "ip",
      "value": "10.0.0.1",
      "severity": "high"
    },
    "relation_type": "HOSTED_ON",
    "relation_strength": 0.85,
    "path_length": 1
  }
]
```

---

### Find Temporal Correlation

Finds indicators that appeared around the same time as the given indicator.

```http
GET /api/v1/graph/temporal/{id}
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| id | UUID | Indicator UUID |

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| window | duration | 24h | Time window (e.g., 24h, 7d, 168h) |

**Response:**
```json
{
  "time_window": "24h0m0s",
  "indicators": [
    {
      "id": "...",
      "type": "domain",
      "value": "example.com",
      "first_seen": "2024-01-15T10:00:00Z"
    }
  ],
  "first_seen": "2024-01-15T08:00:00Z",
  "last_seen": "2024-01-15T20:00:00Z",
  "activity_spikes": []
}
```

---

### Find Shared Infrastructure

Identifies indicators that share infrastructure (IPs, domains, ASNs).

```http
GET /api/v1/graph/shared-infrastructure
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| limit | int | 50 | Maximum results (max 200) |

**Response:**
```json
{
  "shared_asn": [
    {
      "asn": "AS12345",
      "asn_name": "Evil Hosting Inc",
      "indicators": [...],
      "campaigns": ["pegasus"],
      "count": 15
    }
  ],
  "shared_registrar": [...],
  "shared_ip_range": [...],
  "similar_domains": [...]
}
```

---

### Detect Campaigns

Auto-detects potential new campaigns based on shared infrastructure patterns.

```http
GET /api/v1/graph/detect-campaigns
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| min_shared | int | 2 | Minimum shared infrastructure |
| limit | int | 20 | Maximum results (max 100) |

**Response:**
```json
[
  {
    "proposed_name": "unknown-campaign-2024-01",
    "indicators": [...],
    "common_patterns": ["*.malicious.com", "similar-naming-*"],
    "shared_infrastructure": ["AS12345", "192.168.0.0/24"],
    "time_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-20T00:00:00Z"
    },
    "confidence": 0.75,
    "suggested_actor": "Unknown"
  }
]
```

---

### Get TTP Similarity

Calculates TTP (Tactics, Techniques, Procedures) similarity between threat actors.

```http
GET /api/v1/graph/ttp-similarity
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| actor1 | UUID | First actor UUID |
| actor2 | UUID | Second actor UUID |

**Response:**
```json
{
  "actor1": "550e8400-e29b-41d4-a716-446655440001",
  "actor2": "550e8400-e29b-41d4-a716-446655440002",
  "shared_tactics": ["TA0001", "TA0002"],
  "shared_techniques": ["T1566", "T1059"],
  "similarity": 0.65
}
```

---

### Traverse Graph

Performs a custom graph traversal from a starting node.

```http
POST /api/v1/graph/traverse
```

**Request Body:**
```json
{
  "start_node_id": "550e8400-e29b-41d4-a716-446655440000",
  "direction": "both",
  "relation_types": ["PART_OF", "ATTRIBUTED_TO"],
  "max_depth": 3,
  "limit": 100,
  "include_nodes": ["Campaign", "ThreatActor"],
  "exclude_nodes": []
}
```

**Direction options:** `outgoing`, `incoming`, `both`

**Response:**
```json
{
  "nodes": [
    {
      "id": "...",
      "type": "Campaign",
      "labels": ["Campaign"],
      "properties": {...}
    }
  ],
  "relationships": [
    {
      "id": "...",
      "type": "PART_OF",
      "source_id": "...",
      "target_id": "...",
      "confidence": 0.9
    }
  ],
  "total_nodes": 25,
  "total_relations": 30,
  "query_time": "15ms"
}
```

---

### Search Graph

Searches across all node types in the threat graph.

```http
POST /api/v1/graph/search
```

**Request Body:**
```json
{
  "query": "pegasus",
  "node_types": ["Indicator", "Campaign"],
  "severity": "critical",
  "time_range": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "limit": 50,
  "max_depth": 2
}
```

---

### Create Relationship

Creates a relationship between two entities in the graph.

```http
POST /api/v1/graph/relationship
```

**Request Body:**
```json
{
  "source_id": "550e8400-e29b-41d4-a716-446655440001",
  "target_id": "550e8400-e29b-41d4-a716-446655440002",
  "relation_type": "RELATED_TO",
  "confidence": 0.8
}
```

**Relation Types:**
- `INDICATES` - Indicator points to target
- `ATTRIBUTED_TO` - Attribution to actor
- `PART_OF` - Part of campaign
- `USED_BY` - Used by actor/campaign
- `DELIVERS` - Delivers malware
- `COMMUNICATES_WITH` - C2 communication
- `RESOLVES` - Domain resolves to IP
- `HOSTED_ON` - Hosted on infrastructure
- `SIMILAR_TO` - Similar pattern
- `RELATED_TO` - General relationship
- `EXPLOITS` - Exploits vulnerability
- `USES_TECHNIQUE` - Uses MITRE technique

**Response:**
```json
{
  "status": "success",
  "message": "relationship created"
}
```

---

### Sync from PostgreSQL

Triggers a sync from PostgreSQL to Neo4j (admin operation).

```http
POST /api/v1/graph/sync
```

**Response:**
```json
{
  "status": "success",
  "message": "sync completed"
}
```

---

### Get Graph Statistics

Returns statistics about the threat graph.

```http
GET /api/v1/graph/stats
```

**Response:**
```json
{
  "total_nodes": 15000,
  "total_relationships": 45000,
  "nodes_by_type": {
    "Indicator": 12000,
    "Campaign": 50,
    "ThreatActor": 30,
    "Infrastructure": 2000,
    "MITREAttack": 500
  },
  "relations_by_type": {
    "PART_OF": 5000,
    "ATTRIBUTED_TO": 500,
    "RESOLVES": 10000
  },
  "average_connections": 3.5,
  "most_connected_nodes": [
    {
      "node_id": "...",
      "node_type": "Campaign",
      "label": "Pegasus",
      "connections": 5000
    }
  ],
  "last_updated": "2024-01-20T16:00:00Z"
}
```

---

## Node Types

| Type | Description |
|------|-------------|
| Indicator | IOC (domain, IP, hash, etc.) |
| Campaign | Threat campaign (Pegasus, Predator) |
| ThreatActor | Threat actor (NSO Group, APT28) |
| Infrastructure | Hosting infrastructure |
| MITREAttack | MITRE ATT&CK technique |

## Use Cases

### 1. Investigate an Indicator
```bash
# Get full correlation for an indicator
curl -H "Authorization: Bearer $API_KEY" \
  "https://api.orbguard.com/api/v1/graph/correlation/$INDICATOR_ID"
```

### 2. Find Campaign Attribution
```bash
# Traverse from indicator to find campaigns
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"start_node_id":"...", "direction":"outgoing", "relation_types":["PART_OF"]}' \
  "https://api.orbguard.com/api/v1/graph/traverse"
```

### 3. Detect New Campaigns
```bash
# Auto-detect campaigns from infrastructure patterns
curl -H "Authorization: Bearer $API_KEY" \
  "https://api.orbguard.com/api/v1/graph/detect-campaigns?min_shared=3"
```

### 4. Compare Threat Actors
```bash
# Calculate TTP similarity between actors
curl -H "Authorization: Bearer $API_KEY" \
  "https://api.orbguard.com/api/v1/graph/ttp-similarity?actor1=$ID1&actor2=$ID2"
```
