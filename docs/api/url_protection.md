# URL Protection / Safe Web API

## Overview

The URL Protection API provides real-time URL safety checking, reputation scoring, and blocking capabilities. It integrates with Google Safe Browsing API and our own threat intelligence database.

## Endpoints

### POST /api/v1/url/check

Check a single URL for threats.

**Request:**
```json
{
  "url": "https://suspicious-domain.xyz/login",
  "device_id": "device-123",
  "source": "browser"
}
```

**Response:**
```json
{
  "url": "https://suspicious-domain.xyz/login",
  "domain": "suspicious-domain.xyz",
  "is_safe": false,
  "should_block": true,
  "category": "phishing",
  "threat_level": "high",
  "confidence": 0.92,
  "description": "Domain matches known phishing patterns",
  "warnings": [
    "Domain uses a high-risk TLD",
    "This domain appears to be impersonating a legitimate website"
  ],
  "block_reason": "Domain matches known phishing patterns",
  "allow_override": false,
  "campaign_name": "",
  "threat_actor_name": "",
  "cache_hit": false,
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/url/check/batch

Check multiple URLs in a single request.

**Request:**
```json
{
  "urls": [
    "https://google.com",
    "https://malware-test.xyz/download",
    "https://amaz0n-login.xyz/verify"
  ],
  "device_id": "device-123",
  "source": "browser"
}
```

**Response:**
```json
{
  "results": [
    {
      "url": "https://google.com",
      "domain": "google.com",
      "is_safe": true,
      "should_block": false,
      "category": "safe",
      "threat_level": "info",
      "confidence": 1.0
    },
    {
      "url": "https://malware-test.xyz/download",
      "domain": "malware-test.xyz",
      "is_safe": false,
      "should_block": true,
      "category": "malware",
      "threat_level": "critical"
    },
    {
      "url": "https://amaz0n-login.xyz/verify",
      "domain": "amaz0n-login.xyz",
      "is_safe": false,
      "should_block": true,
      "category": "phishing",
      "threat_level": "high"
    }
  ],
  "total_count": 3,
  "safe_count": 1,
  "block_count": 2,
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### GET /api/v1/url/reputation/{domain}

Get reputation data for a specific domain.

**Response:**
```json
{
  "id": "uuid",
  "url": "malicious-domain.xyz",
  "domain": "malicious-domain.xyz",
  "category": "malware",
  "threat_level": "critical",
  "confidence": 0.95,
  "is_malicious": true,
  "is_blocked": true,
  "sources": ["threat-intel-db"],
  "first_seen": "2024-01-01T00:00:00Z",
  "last_seen": "2024-01-05T10:00:00Z",
  "last_checked": "2024-01-05T10:00:00Z",
  "tags": ["malware", "pegasus"],
  "description": "Known Pegasus spyware C2 domain",
  "campaign_id": "uuid",
  "ip_address": "1.2.3.4",
  "asn": "AS12345",
  "country": "RU"
}
```

### GET /api/v1/url/stats

Get URL protection statistics.

**Response:**
```json
{
  "total_checks": 50000,
  "blocked_count": 250,
  "by_category": {
    "phishing": 120,
    "malware": 80,
    "scam": 30,
    "spam": 20
  },
  "by_threat_level": {
    "critical": 50,
    "high": 100,
    "medium": 70,
    "low": 30
  },
  "top_blocked_domains": [
    {"domain": "malware-test.xyz", "count": 25},
    {"domain": "phishing-site.com", "count": 18}
  ],
  "last_24_hours": {
    "checks": 2500,
    "blocked": 15
  }
}
```

### GET /api/v1/url/dns-rules

Get DNS blocking rules for VPN integration (OrbNet).

**Response:**
```json
{
  "rules": [
    {
      "id": "uuid",
      "domain": "malware.xyz",
      "block_type": "exact",
      "category": "malware",
      "threat_level": "critical",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-05T00:00:00Z"
    },
    {
      "id": "uuid",
      "domain": "*.phishing-domain.com",
      "block_type": "wildcard",
      "category": "phishing",
      "threat_level": "high",
      "is_active": true
    }
  ],
  "count": 1500,
  "updated_at": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/url/whitelist

Add a URL/domain to the whitelist.

**Request:**
```json
{
  "domain": "internal-tool.company.com",
  "reason": "Internal company tool"
}
```

**Response:**
```json
{
  "id": "uuid",
  "domain": "internal-tool.company.com",
  "list_type": "whitelist",
  "reason": "Internal company tool",
  "created_by": "api",
  "created_at": "2024-01-05T10:00:00Z",
  "is_active": true
}
```

### POST /api/v1/url/blacklist

Add a URL/domain to the blacklist.

**Request:**
```json
{
  "domain": "suspicious-site.xyz",
  "reason": "Reported by security team"
}
```

### GET /api/v1/url/whitelist

Get all whitelisted entries.

### GET /api/v1/url/blacklist

Get all blacklisted entries.

### DELETE /api/v1/url/list/{id}

Remove an entry from whitelist/blacklist.

### GET /api/v1/url/block-page

Get data for rendering a block page UI.

**Query Parameters:**
- `url` - The blocked URL

**Response:**
```json
{
  "url": "https://malware.xyz/download",
  "domain": "malware.xyz",
  "category": "malware",
  "threat_level": "critical",
  "reason": "This website contains harmful software",
  "allow_override": false,
  "override_token": "",
  "report_url": "/api/v1/url/report",
  "timestamp": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/url/report

Report a false positive or missed threat.

**Request:**
```json
{
  "url": "https://legitimate-site.com",
  "report_type": "false_positive",
  "comment": "This is my company's legitimate website",
  "device_id": "device-123"
}
```

**Report Types:**
- `false_positive` - URL was incorrectly blocked
- `missed_threat` - URL should have been blocked but wasn't
- `feedback` - General feedback

## URL Categories

| Category | Description |
|----------|-------------|
| `safe` | URL is safe |
| `unknown` | No reputation data available |
| `phishing` | Phishing/credential stealing |
| `malware` | Contains or distributes malware |
| `scam` | Known scam website |
| `spam` | Spam/unwanted content |
| `adult` | Adult content |
| `gambling` | Gambling website |
| `drugs` | Illegal drug sales |
| `cryptojacking` | Cryptocurrency mining scripts |
| `ransomware` | Ransomware distribution |
| `command_and_control` | C2 server for malware |
| `botnet` | Botnet infrastructure |
| `exploit` | Exploit kit hosting |
| `drive_by_download` | Drive-by download attacks |
| `suspicious` | General suspicious indicators |
| `uncategorized` | Malicious but not categorized |

## Threat Levels

| Level | Description |
|-------|-------------|
| `info` | Safe, informational |
| `low` | Minor risk, proceed with caution |
| `medium` | Moderate risk, warnings shown |
| `high` | High risk, blocked by default |
| `critical` | Critical threat, always blocked |

## Detection Methods

OrbGuard uses multiple detection methods:

1. **Threat Intelligence Database** - Checks against our aggregated threat feeds
2. **Phishing Pattern Detection** - Regex patterns for known phishing campaigns
3. **Typosquatting Detection** - Identifies lookalike domains (e.g., paypa1.com)
4. **URL Characteristics Analysis**:
   - Suspicious TLDs (.xyz, .tk, etc.)
   - IP addresses instead of domains
   - Excessive subdomains
   - Encoded characters
   - Homograph attacks (mixed scripts)
5. **Google Safe Browsing** - Integration with Google's threat database

## Mobile Integration

### Android (VPN-based blocking)

```kotlin
// Get DNS blocking rules for local DNS filtering
val rules = orbGuardApi.getDNSRules()

// Configure VPN DNS with blocklist
val vpnDns = VpnDnsResolver(rules)
```

### Android (Accessibility Service)

```kotlin
// Monitor browser URL bar
class UrlMonitorService : AccessibilityService() {
    override fun onAccessibilityEvent(event: AccessibilityEvent) {
        val url = extractBrowserUrl(event)
        if (url != null) {
            checkUrlSafety(url)
        }
    }

    private fun checkUrlSafety(url: String) {
        val result = orbGuardApi.checkUrl(url)
        if (result.shouldBlock) {
            showBlockingOverlay(result)
        }
    }
}
```

### iOS (Content Blocker)

```json
[
  {
    "trigger": {
      "url-filter": ".*malware\\.xyz.*"
    },
    "action": {
      "type": "block"
    }
  }
]
```

## Rate Limits

- Single URL check: 200 requests/minute
- Batch check: 20 requests/minute (max 100 URLs per batch)
- DNS rules: 10 requests/minute

## Caching

- Safe URLs are cached for 5 minutes
- Blocked URLs are cached for 1 hour
- DNS rules should be refreshed every 15 minutes

## Authentication

All endpoints require API key authentication:
```
Authorization: Bearer <api_key>
```

## VPN Integration (OrbNet)

For OrbNet VPN integration, the `/dns-rules` endpoint provides all domains to block at the DNS level. The VPN client should:

1. Fetch DNS rules on startup and every 15 minutes
2. Intercept DNS queries and block matching domains
3. Show a block page for blocked domains
4. Allow users to report false positives
