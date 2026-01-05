# MITRE ATT&CK API

The MITRE ATT&CK API provides access to threat intelligence mapped to the MITRE ATT&CK framework, with a focus on mobile threats. It includes tactics, techniques, mitigations, threat groups, and software from the ATT&CK knowledge base.

## Base URL

```
/api/v1/mitre
```

## Authentication

All endpoints require API key authentication via the `X-API-Key` header.

---

## Tactics

### List Tactics

Get all MITRE ATT&CK tactics.

```
GET /api/v1/mitre/tactics
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Filter by domain: `mobile-attack`, `enterprise-attack`, `ics-attack` |

**Response:**
```json
{
  "tactics": [
    {
      "id": "TA0027",
      "stix_id": "x-mitre-tactic--0a93fd8e-4a83-4c15-8203-db290e5f0676",
      "name": "Initial Access",
      "short_name": "initial-access",
      "description": "The adversary is trying to get into your mobile device...",
      "domain": "mobile-attack",
      "technique_count": 8,
      "url": "https://attack.mitre.org/tactics/TA0027"
    }
  ],
  "count": 14
}
```

### Get Tactic

Get a specific tactic by ID or short name.

```
GET /api/v1/mitre/tactics/{id}
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Tactic ID (e.g., `TA0027`) or short name (e.g., `initial-access`) |

**Response:**
```json
{
  "tactic": {
    "id": "TA0027",
    "name": "Initial Access",
    "short_name": "initial-access",
    "description": "The adversary is trying to get into your mobile device..."
  },
  "techniques": [
    {
      "id": "T1660",
      "name": "Phishing"
    }
  ]
}
```

---

## Techniques

### List Techniques

Get MITRE ATT&CK techniques with filtering.

```
GET /api/v1/mitre/techniques
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `tactic` | string | Filter by tactic short name (e.g., `initial-access`) |
| `platform` | string | Filter by platform: `Android`, `iOS` |
| `domain` | string | Filter by domain: `mobile-attack`, `enterprise-attack` |
| `sub_techniques` | boolean | Filter sub-techniques only (`true`) or parent techniques only (`false`) |
| `include_revoked` | boolean | Include revoked techniques (default: false) |
| `q` | string | Search query for name/description |
| `limit` | integer | Maximum results to return |
| `offset` | integer | Offset for pagination |

**Response:**
```json
{
  "techniques": [
    {
      "id": "T1404",
      "stix_id": "attack-pattern--351c0927-2fc1-4a2c-ad84-cbbee7eb8172",
      "name": "Exploit OS Vulnerability",
      "description": "An adversary may exploit operating system vulnerabilities...",
      "is_sub_technique": false,
      "tactics": ["privilege-escalation"],
      "platforms": ["Android", "iOS"],
      "domain": "mobile-attack",
      "url": "https://attack.mitre.org/techniques/T1404"
    }
  ],
  "count": 42,
  "filter": {
    "domain": "mobile-attack"
  }
}
```

### Get Technique

Get a specific technique by ID.

```
GET /api/v1/mitre/techniques/{id}
```

**Path Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | Technique ID (e.g., `T1404` or `T1636.004` for sub-techniques) |

**Response:**
```json
{
  "technique": {
    "id": "T1404",
    "name": "Exploit OS Vulnerability",
    "description": "An adversary may exploit operating system vulnerabilities...",
    "platforms": ["Android", "iOS"],
    "tactics": ["privilege-escalation"],
    "detection": "Mobile security products can potentially detect...",
    "mitigations": [
      {
        "id": "M1001",
        "name": "Security Updates"
      }
    ]
  },
  "sub_techniques": []
}
```

### Search Techniques

Search techniques by keyword.

```
GET /api/v1/mitre/techniques/search?q={query}
```

**Query Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `q` | string | Yes | Search query |

**Response:**
```json
{
  "query": "keylog",
  "techniques": [
    {
      "id": "T1417",
      "name": "Input Capture",
      "description": "Adversaries may capture user input..."
    }
  ],
  "count": 1
}
```

---

## Mitigations

### List Mitigations

Get all MITRE ATT&CK mitigations.

```
GET /api/v1/mitre/mitigations
```

**Response:**
```json
{
  "mitigations": [
    {
      "id": "M1001",
      "name": "Security Updates",
      "description": "Install security updates..."
    }
  ],
  "count": 15
}
```

### Get Mitigation

Get a specific mitigation by ID.

```
GET /api/v1/mitre/mitigations/{id}
```

---

## Groups (Threat Actors)

### List Groups

Get all known threat groups from MITRE ATT&CK.

```
GET /api/v1/mitre/groups
```

**Response:**
```json
{
  "groups": [
    {
      "id": "G0016",
      "name": "APT29",
      "aliases": ["Cozy Bear", "The Dukes"],
      "description": "APT29 is a threat group...",
      "techniques": ["T1566", "T1059"]
    }
  ],
  "count": 25
}
```

### Get Group

Get a specific threat group by ID.

```
GET /api/v1/mitre/groups/{id}
```

---

## Software (Malware/Tools)

### List Software

Get all known malware and tools from MITRE ATT&CK.

```
GET /api/v1/mitre/software
```

**Response:**
```json
{
  "software": [
    {
      "id": "S0289",
      "name": "Pegasus for Android",
      "type": "malware",
      "description": "Pegasus for Android is a spyware...",
      "platforms": ["Android"],
      "techniques": ["T1404", "T1417", "T1429", "T1512"]
    }
  ],
  "count": 30
}
```

### Get Software

Get specific software by ID.

```
GET /api/v1/mitre/software/{id}
```

---

## Matrix

### Get Matrix

Get the full ATT&CK matrix for a domain.

```
GET /api/v1/mitre/matrix
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | string | Domain: `mobile-attack` (default), `enterprise-attack`, `ics-attack` |

**Response:**
```json
{
  "domain": "mobile-attack",
  "name": "mobile-attack Matrix",
  "tactics": [...],
  "techniques": [...],
  "mitigations": [...],
  "groups": [...],
  "software": [...]
}
```

---

## ATT&CK Navigator Export

### Export Navigator Layer

Export techniques as an ATT&CK Navigator layer for visualization.

```
POST /api/v1/mitre/navigator/export
```

**Request Body:**
```json
{
  "name": "OrbGuard Detected Threats",
  "description": "Techniques detected by OrbGuard",
  "techniques": ["T1404", "T1417", "T1429", "T1512", "T1533"],
  "domain": "mobile-attack"
}
```

**Response:** (Downloads as JSON file)
```json
{
  "name": "OrbGuard Detected Threats",
  "version": "4.4",
  "domain": "mobile-attack",
  "description": "Techniques detected by OrbGuard",
  "filters": {
    "platforms": ["Android", "iOS"]
  },
  "techniques": [
    {
      "techniqueID": "T1404",
      "score": 1,
      "color": "#ff6666",
      "enabled": true
    }
  ],
  "gradient": {
    "colors": ["#ffffff", "#ff6666"],
    "minValue": 0,
    "maxValue": 1
  }
}
```

The exported layer can be imported directly into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visualization.

---

## Statistics

### Get Stats

Get statistics about loaded MITRE ATT&CK data.

```
GET /api/v1/mitre/stats
```

**Response:**
```json
{
  "total_tactics": 14,
  "total_techniques": 42,
  "total_sub_techniques": 28,
  "total_mitigations": 15,
  "total_groups": 25,
  "total_software": 30,
  "total_data_sources": 0,
  "total_relationships": 0,
  "techniques_by_tactic": {
    "initial-access": 8,
    "execution": 5,
    "persistence": 4,
    "collection": 12
  },
  "techniques_by_platform": {
    "Android": 38,
    "iOS": 35
  },
  "enterprise_version": "",
  "mobile_version": "embedded",
  "last_loaded": "2024-01-15T10:30:00Z"
}
```

---

## Admin Operations

### Reload Data

Reload MITRE ATT&CK data from files.

```
POST /api/v1/mitre/reload
```

**Response:**
```json
{
  "message": "MITRE data reloaded",
  "stats": {
    "total_tactics": 14,
    "total_techniques": 42
  }
}
```

---

## Mobile Threat Mapping

OrbGuard automatically maps detected threats to MITRE ATT&CK techniques. The following keywords trigger automatic mapping:

| Keyword | Mapped Techniques |
|---------|-------------------|
| `pegasus` | T1404, T1407, T1417, T1429, T1512, T1533 |
| `spyware` | T1417, T1429, T1512, T1533, T1636 |
| `stalkerware` | T1417, T1430, T1512, T1533, T1636 |
| `keylogger` | T1417 |
| `camera` | T1512 |
| `microphone` | T1429 |
| `sms` | T1636.004, T1582 |
| `location` | T1430 |
| `contacts` | T1636.003 |
| `rooting` | T1404 |
| `jailbreak` | T1398 |
| `phishing` | T1566, T1660 |
| `smishing` | T1660 |

---

## Key Mobile Techniques

| Technique ID | Name | Description |
|--------------|------|-------------|
| T1404 | Exploit OS Vulnerability | Exploiting OS vulnerabilities for privilege escalation |
| T1407 | Download New Code at Runtime | Downloading additional malicious code |
| T1417 | Input Capture | Capturing user input including keylogging |
| T1429 | Audio Capture | Recording microphone/audio |
| T1430 | Location Tracking | Tracking device location |
| T1512 | Video Capture | Capturing camera video/photos |
| T1533 | Data from Local System | Collecting files and data |
| T1636 | Protected User Data | Accessing contacts, calendar, SMS, call logs |
| T1660 | Phishing | Delivering malware via phishing messages |

---

## Error Responses

```json
{
  "error": "technique not found",
  "details": ""
}
```

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing or invalid API key |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error |
