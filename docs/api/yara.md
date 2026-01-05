# YARA Rules Engine API

The YARA Rules Engine provides malware detection capabilities through pattern matching rules. This pure-Go implementation supports scanning for Pegasus, stalkerware, and other mobile threats without external dependencies.

## Base URL

All YARA endpoints require authentication and are prefixed with:
```
/api/v1/yara
```

## Endpoints

### POST /scan

Perform a full YARA scan on provided data.

**Request Body:**
```json
{
  "data": "base64_encoded_bytes",
  "base64_data": "alternative_base64_input",
  "hex_data": "optional_hex_input",
  "file_name": "app.apk",
  "file_type": "apk",
  "package_name": "com.example.app",
  "platform": "android",
  "rule_ids": ["uuid1", "uuid2"],
  "categories": ["pegasus", "stalkerware", "spyware"],
  "min_severity": "medium"
}
```

**Response:**
```json
{
  "id": "scan-uuid",
  "scan_time": "125ms",
  "matches": [
    {
      "rule_id": "uuid",
      "rule_name": "Pegasus_Process_Injection",
      "description": "Detects Pegasus process injection patterns",
      "category": "pegasus",
      "severity": "critical",
      "strings_matched": [
        {
          "identifier": "$injection_pattern",
          "offset": 12345,
          "data": "matched string"
        }
      ],
      "metadata": {
        "author": "OrbGuard",
        "reference": "https://example.com/report"
      }
    }
  ],
  "rules_used": 10,
  "data_size": 1048576,
  "is_malicious": true,
  "risk_score": 9.5,
  "max_severity": "critical",
  "scanned_at": "2025-01-05T12:00:00Z"
}
```

### POST /scan/apk

Scan an Android APK file with mobile-specific rules.

**Request Body:**
```json
{
  "data": "base64_encoded_apk",
  "package_name": "com.example.app"
}
```

**Response:** Same as `/scan` with Android-specific context.

### POST /scan/ipa

Scan an iOS IPA file with iOS-specific rules.

**Request Body:**
```json
{
  "data": "base64_encoded_ipa",
  "bundle_id": "com.example.app"
}
```

**Response:** Same as `/scan` with iOS-specific context.

### POST /quick-scan

Perform a quick scan with reduced rule set for fast results.

**Request Body:**
```json
{
  "data": "base64_encoded_bytes",
  "platform": "android"
}
```

**Response:** Same as `/scan` but faster with fewer rules.

---

## Rule Management

### GET /rules

List all loaded YARA rules with optional filtering.

**Query Parameters:**
- `category` - Filter by category (pegasus, stalkerware, spyware, trojan, etc.)
- `severity` - Filter by severity (critical, high, medium, low, info)
- `status` - Filter by status (active, deprecated, testing)
- `platform` - Filter by platform (android, ios, all)
- `limit` - Number of results (default: 50)
- `offset` - Pagination offset

**Response:**
```json
{
  "rules": [
    {
      "id": "uuid",
      "name": "Pegasus_Network_Beacon",
      "description": "Detects Pegasus C2 communication patterns",
      "category": "pegasus",
      "severity": "critical",
      "status": "active",
      "platforms": ["android", "ios"],
      "tags": ["nso-group", "spyware", "targeted"],
      "created_at": "2025-01-01T00:00:00Z"
    }
  ],
  "total": 10,
  "limit": 50,
  "offset": 0
}
```

### GET /rules/{id}

Get a specific rule by ID.

**Response:**
```json
{
  "id": "uuid",
  "name": "Pegasus_Process_Injection",
  "description": "Detects Pegasus process injection techniques",
  "category": "pegasus",
  "severity": "critical",
  "status": "active",
  "strings": [
    {
      "identifier": "$injection_pattern",
      "value": "\\x00\\x48\\x89\\xe5",
      "type": "hex",
      "modifiers": ["nocase"]
    }
  ],
  "conditions": [
    {
      "expression": "any of them"
    }
  ],
  "platforms": ["android", "ios"],
  "metadata": {
    "author": "OrbGuard Security",
    "reference": "https://citizenlab.ca/pegasus",
    "cve": [],
    "mitre_attack": ["T1055"]
  },
  "created_at": "2025-01-01T00:00:00Z"
}
```

### POST /rules

Add a new YARA rule (admin only).

**Request Body:**
```json
{
  "name": "Custom_Stalkerware_Detection",
  "description": "Detects specific stalkerware package",
  "category": "stalkerware",
  "severity": "high",
  "strings": [
    {
      "identifier": "$pkg_name",
      "value": "com.stalker.app",
      "type": "text"
    }
  ],
  "conditions": [
    {
      "expression": "$pkg_name"
    }
  ],
  "platforms": ["android"],
  "tags": ["stalkerware", "privacy"]
}
```

**Response:**
```json
{
  "id": "new-rule-uuid",
  "message": "Rule added successfully"
}
```

### DELETE /rules/{id}

Remove a YARA rule (admin only).

**Response:**
```json
{
  "message": "Rule deleted successfully"
}
```

---

## Rule Parsing & Validation

### POST /parse

Parse and validate a YARA rule without adding it.

**Request Body:**
```json
{
  "source": "rule TestRule { strings: $a = \"test\" condition: $a }"
}
```

**Response:**
```json
{
  "valid": true,
  "rule": {
    "name": "TestRule",
    "strings": [...],
    "conditions": [...]
  },
  "warnings": []
}
```

### POST /submit

Submit a community-contributed rule for review.

**Request Body:**
```json
{
  "name": "Community_Detection_Rule",
  "source": "rule CommunityRule { ... }",
  "description": "Detects specific threat",
  "category": "spyware",
  "submitter_email": "researcher@example.com",
  "references": ["https://blog.example.com/analysis"]
}
```

**Response:**
```json
{
  "submission_id": "uuid",
  "status": "pending_review",
  "message": "Thank you for your submission"
}
```

---

## Metadata & Stats

### GET /categories

Get all available rule categories.

**Response:**
```json
{
  "categories": [
    {"name": "pegasus", "description": "NSO Group Pegasus spyware", "count": 3},
    {"name": "stalkerware", "description": "Commercial stalkerware apps", "count": 2},
    {"name": "spyware", "description": "Generic spyware patterns", "count": 5},
    {"name": "trojan", "description": "Mobile trojans", "count": 0},
    {"name": "ransomware", "description": "Mobile ransomware", "count": 0},
    {"name": "adware", "description": "Aggressive adware", "count": 0},
    {"name": "rootkit", "description": "Rootkit detection", "count": 0},
    {"name": "exploit", "description": "Exploit patterns", "count": 0}
  ]
}
```

### GET /stats

Get YARA engine statistics.

**Response:**
```json
{
  "total_scans": 15420,
  "total_matches": 234,
  "malicious_detected": 234,
  "average_scan_time": "45ms",
  "rules_loaded": 10,
  "by_category": {
    "pegasus": 3,
    "stalkerware": 2,
    "spyware": 5
  },
  "by_severity": {
    "critical": 3,
    "high": 4,
    "medium": 2,
    "low": 1
  }
}
```

### POST /reload

Reload all YARA rules from disk (admin only).

**Response:**
```json
{
  "message": "Rules reloaded successfully",
  "rules_loaded": 10
}
```

---

## Rule Categories

| Category | Description |
|----------|-------------|
| `pegasus` | NSO Group Pegasus spyware patterns |
| `stalkerware` | Commercial stalkerware/spouseware |
| `spyware` | Generic spyware detection |
| `trojan` | Mobile banking trojans and RATs |
| `ransomware` | Mobile ransomware patterns |
| `adware` | Aggressive adware behavior |
| `rootkit` | Rootkit and privilege escalation |
| `exploit` | Known exploit patterns |

## Severity Levels

| Level | Score | Description |
|-------|-------|-------------|
| `critical` | 10.0 | Immediate threat (e.g., Pegasus) |
| `high` | 7.5 | Serious threat requiring action |
| `medium` | 5.0 | Moderate risk |
| `low` | 2.5 | Minor concern |
| `info` | 1.0 | Informational only |

## Built-in Rules

The YARA engine includes 10 built-in detection rules:

### Pegasus Detection (3 rules)
- `Pegasus_Process_Injection` - Process injection patterns
- `Pegasus_Network_Beacon` - C2 communication signatures
- `Pegasus_Filesystem_Artifacts` - Known file artifacts

### Stalkerware Detection (2 rules)
- `Stalkerware_Location_Tracking` - GPS monitoring patterns
- `Stalkerware_SMS_Interception` - SMS access patterns

### Generic Spyware Detection (5 rules)
- `Spyware_Keylogger` - Keylogging behavior
- `Spyware_Screen_Capture` - Screen recording patterns
- `Spyware_Audio_Recording` - Microphone access patterns
- `Spyware_Camera_Access` - Camera surveillance patterns
- `Spyware_Contact_Exfiltration` - Contact theft patterns

## Error Responses

```json
{
  "error": "Error message",
  "code": "YARA_SCAN_ERROR",
  "details": "Additional context"
}
```

| Code | Description |
|------|-------------|
| `YARA_SCAN_ERROR` | Scan failed |
| `YARA_INVALID_DATA` | Invalid input data |
| `YARA_RULE_NOT_FOUND` | Rule ID not found |
| `YARA_INVALID_RULE` | Rule validation failed |
| `YARA_PARSE_ERROR` | Rule syntax error |
