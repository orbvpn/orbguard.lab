# Dark Web Monitoring API

## Overview

The Dark Web Monitoring API provides data breach detection, credential monitoring, and real-time alerts for compromised data. Integrates with Have I Been Pwned (HIBP) API for breach detection.

## Endpoints

### POST /api/v1/darkweb/check/email

Check if an email address has been involved in any data breaches.

**Request:**
```json
{
  "email": "user@example.com",
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "email": "user@example.com",
  "is_breached": true,
  "breach_count": 5,
  "breaches": [
    {
      "id": "uuid",
      "name": "LinkedIn",
      "title": "LinkedIn",
      "domain": "linkedin.com",
      "breach_date": "2012-05-05T00:00:00Z",
      "added_date": "2016-05-21T00:00:00Z",
      "pwn_count": 164611595,
      "description": "In May 2012, LinkedIn had 6.5 million...",
      "data_classes": ["Email addresses", "Passwords"],
      "is_verified": true,
      "severity": "critical"
    }
  ],
  "exposed_data_types": ["Email addresses", "Passwords", "Phone numbers"],
  "first_breach": "2012-05-05T00:00:00Z",
  "latest_breach": "2023-08-15T00:00:00Z",
  "risk_level": "critical",
  "recommendations": [
    "Change your password immediately on the affected services",
    "Use a unique password for each account",
    "Enable two-factor authentication on all accounts"
  ],
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/darkweb/check/password

Check if a password has been exposed in data breaches (uses k-anonymity - password is never sent to HIBP).

**Request:**
```json
{
  "password": "hunter2",
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "is_breached": true,
  "breach_count": 17847,
  "risk_level": "critical",
  "message": "CRITICAL: This password has appeared 17847 times in data breaches. It is extremely compromised and must be changed immediately!",
  "checked_at": "2024-01-05T10:00:00Z"
}
```

**Risk Levels:**
- `safe` - Not found in any breaches
- `weak` - Found in <10 breaches
- `compromised` - Found in 10-99 breaches
- `high_risk` - Found in 100-999 breaches
- `critical` - Found in 1000+ breaches

### POST /api/v1/darkweb/monitor

Add an asset for continuous dark web monitoring.

**Request:**
```json
{
  "asset_type": "email",
  "value": "user@example.com",
  "user_id": "user-123",
  "device_id": "device-123"
}
```

**Asset Types:**
- `email` - Email address
- `phone` - Phone number
- `username` - Username
- `credit_card` - Credit card number (stored securely)

**Response:**
```json
{
  "id": "uuid",
  "user_id": "user-123",
  "device_id": "device-123",
  "asset_type": "email",
  "asset_hash": "sha256...",
  "display_name": "u***r@example.com",
  "is_active": true,
  "created_at": "2024-01-05T10:00:00Z",
  "last_checked": "2024-01-05T10:00:00Z",
  "breach_count": 3,
  "alerts": [
    {
      "id": "uuid",
      "breach_name": "LinkedIn",
      "severity": "high",
      "data_exposed": ["Email addresses", "Passwords"],
      "detected_at": "2024-01-05T10:00:00Z",
      "is_read": false,
      "actions": [
        {"id": "view_details", "label": "View Details", "action": "view_details"},
        {"id": "change_password", "label": "Change Password", "action": "change_password"}
      ]
    }
  ]
}
```

### GET /api/v1/darkweb/monitor

Get all monitored assets for a user.

**Query Parameters:**
- `user_id` - User ID (optional, defaults to "default")

**Response:**
```json
{
  "assets": [
    {
      "id": "uuid",
      "asset_type": "email",
      "display_name": "u***r@example.com",
      "breach_count": 3,
      "last_checked": "2024-01-05T10:00:00Z"
    }
  ],
  "count": 1
}
```

### DELETE /api/v1/darkweb/monitor/{id}

Remove an asset from monitoring.

### GET /api/v1/darkweb/status

Get overall dark web monitoring status for a user.

**Response:**
```json
{
  "is_enabled": true,
  "monitored_assets": 3,
  "total_breaches": 12,
  "unread_alerts": 2,
  "last_scan": "2024-01-05T10:00:00Z",
  "next_scan": "2024-01-06T10:00:00Z",
  "risk_level": "high",
  "assets": [
    {
      "id": "uuid",
      "asset_type": "email",
      "display_name": "u***r@example.com",
      "breach_count": 3
    }
  ]
}
```

### GET /api/v1/darkweb/alerts

Get all breach alerts for a user.

**Response:**
```json
{
  "unread": [
    {
      "id": "uuid",
      "asset_id": "uuid",
      "breach_name": "LinkedIn",
      "severity": "critical",
      "data_exposed": ["Email addresses", "Passwords"],
      "detected_at": "2024-01-05T10:00:00Z",
      "is_read": false,
      "actions": [...]
    }
  ],
  "read": [...],
  "unread_count": 2,
  "total_count": 5
}
```

### POST /api/v1/darkweb/alerts/{id}/ack

Acknowledge/mark an alert as read.

**Response:**
```json
{
  "status": "acknowledged"
}
```

### GET /api/v1/darkweb/breaches

Get information about all known breaches.

**Response:**
```json
{
  "breaches": [...],
  "count": 500
}
```

### GET /api/v1/darkweb/breaches/{name}

Get details of a specific breach by name.

**Response:**
```json
{
  "name": "LinkedIn",
  "title": "LinkedIn",
  "domain": "linkedin.com",
  "breach_date": "2012-05-05T00:00:00Z",
  "pwn_count": 164611595,
  "description": "In May 2012, LinkedIn had 6.5 million...",
  "data_classes": ["Email addresses", "Passwords"],
  "severity": "critical"
}
```

### GET /api/v1/darkweb/stats

Get dark web monitoring statistics.

**Response:**
```json
{
  "total_checks": 10000,
  "breaches_found": 250,
  "passwords_checked": 5000,
  "compromised_count": 500,
  "by_asset_type": {
    "email": 8000,
    "phone": 1500,
    "username": 500
  },
  "by_severity": {
    "critical": 50,
    "high": 100,
    "medium": 75,
    "low": 25
  },
  "last_24_hours": {
    "checks": 500,
    "breaches": 15
  }
}
```

### POST /api/v1/darkweb/refresh

Trigger a refresh of all monitored assets.

**Response:**
```json
{
  "status": "refreshed"
}
```

## Breach Severity Levels

| Level | Description |
|-------|-------------|
| `low` | Minor data exposure (usernames, email addresses only) |
| `medium` | Moderate exposure (includes phone, DOB, address) |
| `high` | Significant exposure (includes passwords or security questions) |
| `critical` | Severe exposure (includes SSN, credit cards, financial data) |

## Data Classes and Risk

| Data Class | Risk Level |
|------------|------------|
| Passwords | Critical |
| Credit cards | Critical |
| Bank account numbers | Critical |
| Social security numbers | Critical |
| Passport numbers | Critical |
| Auth tokens | Critical |
| Security questions and answers | High |
| Phone numbers | Medium |
| Dates of birth | Medium |
| Physical addresses | Medium |
| Email addresses | Low |
| Usernames | Low |

## Password Checking (k-Anonymity)

The password check endpoint uses k-anonymity to protect user passwords:

1. Password is hashed with SHA-1 locally
2. Only the first 5 characters of the hash are sent to HIBP
3. HIBP returns all hash suffixes matching the prefix
4. Local matching is performed to check if the password was breached

**Security Note:** Your actual password is NEVER sent to any external service.

## Mobile Integration

### Android Implementation

```kotlin
class BreachChecker(private val api: OrbGuardApi) {

    suspend fun checkEmail(email: String): BreachCheckResult {
        return api.checkEmailBreach(email)
    }

    suspend fun checkPassword(password: String): PasswordCheckResult {
        return api.checkPasswordBreach(password)
    }

    suspend fun startMonitoring(email: String) {
        api.addMonitoredAsset(
            assetType = "email",
            value = email
        )
    }
}
```

### Real-time Notifications

When a new breach is detected for a monitored asset, a push notification is sent:

```json
{
  "type": "new_breach",
  "severity": "critical",
  "title": "New Data Breach Alert",
  "message": "Your email (u***r@example.com) was found in the LinkedIn breach.",
  "actions": [
    {"label": "View Details", "action": "view_details"},
    {"label": "Change Password", "action": "change_password"}
  ]
}
```

## Rate Limits

- Email checks: 50 requests/minute (HIBP API limit)
- Password checks: 100 requests/minute
- Asset monitoring: 10 additions/hour

## Authentication

All endpoints require API key authentication:
```
Authorization: Bearer <api_key>
```

## HIBP API Configuration

To enable full HIBP integration, configure the API key in config:

```yaml
hibp:
  enabled: true
  api_key: "your-hibp-api-key"
```

Get an API key at: https://haveibeenpwned.com/API/Key
