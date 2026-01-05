# App Security Suite API

## Overview

The App Security Suite API provides comprehensive app analysis including permission risk assessment, privacy auditing, sideloaded app detection, and threat intelligence matching.

## Endpoints

### POST /api/v1/apps/analyze

Analyze a single app for security and privacy risks.

**Request:**
```json
{
  "package_name": "com.example.malicious",
  "app_name": "Free VPN",
  "version": "1.2.3",
  "version_code": 123,
  "permissions": [
    "android.permission.READ_SMS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA"
  ],
  "install_source": "sideloaded",
  "signing_info": {
    "certificate_hash": "abc123...",
    "is_debug_signed": false
  },
  "sdk_versions": {
    "min_sdk": 21,
    "target_sdk": 33
  },
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "id": "uuid",
  "package_name": "com.example.malicious",
  "app_name": "Free VPN",
  "risk_level": "high",
  "risk_score": 0.78,
  "permission_risk": {
    "risk_score": 0.85,
    "risk_level": "critical",
    "dangerous_permissions": [
      {
        "permission": "android.permission.READ_SMS",
        "risk_level": "critical",
        "description": "Read SMS messages - can access sensitive 2FA codes"
      },
      {
        "permission": "android.permission.ACCESS_FINE_LOCATION",
        "risk_level": "high",
        "description": "Access precise location - can track user movements"
      }
    ],
    "dangerous_combos": [
      {
        "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "risk_level": "critical",
        "description": "Can read SMS and send data to internet - potential banking trojan behavior"
      }
    ],
    "total_permissions": 4,
    "dangerous_count": 2,
    "normal_count": 2
  },
  "privacy_risk": {
    "risk_score": 0.7,
    "risk_level": "high",
    "trackers_detected": [
      {
        "name": "Facebook Ads",
        "package_prefix": "com.facebook.ads",
        "company": "Meta",
        "category": "advertising",
        "privacy_impact": "high"
      }
    ],
    "data_collection": ["location", "device_info", "usage_patterns"],
    "network_access": true,
    "can_track_location": true,
    "can_access_contacts": false,
    "can_access_camera": true,
    "can_access_microphone": false
  },
  "security_risk": {
    "risk_score": 0.65,
    "risk_level": "medium",
    "is_sideloaded": true,
    "is_debug_signed": false,
    "targets_old_sdk": false,
    "has_network_security_config": true,
    "allows_cleartext": false
  },
  "threat_intel_match": {
    "is_known_threat": false,
    "matched_indicators": [],
    "malware_family": null,
    "confidence": 0
  },
  "recommendations": [
    {
      "type": "permission",
      "severity": "critical",
      "title": "Revoke SMS Permission",
      "description": "This VPN app has no legitimate reason to read SMS messages. This is a common behavior of banking trojans.",
      "action": "revoke_permission",
      "action_data": {"permission": "android.permission.READ_SMS"}
    },
    {
      "type": "app",
      "severity": "high",
      "title": "Consider Uninstalling",
      "description": "This app was installed from outside the Play Store and requests dangerous permission combinations.",
      "action": "uninstall"
    }
  ],
  "analyzed_at": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/apps/analyze/batch

Analyze multiple apps in a single request.

**Request:**
```json
{
  "apps": [
    {
      "package_name": "com.example.app1",
      "app_name": "App One",
      "permissions": ["android.permission.INTERNET"]
    },
    {
      "package_name": "com.example.app2",
      "app_name": "App Two",
      "permissions": ["android.permission.READ_CONTACTS", "android.permission.INTERNET"]
    }
  ],
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "results": [
    { "...analysis for app1..." },
    { "...analysis for app2..." }
  ],
  "summary": {
    "total_apps": 2,
    "critical_risk": 0,
    "high_risk": 1,
    "medium_risk": 1,
    "low_risk": 0,
    "safe": 0
  },
  "analyzed_at": "2024-01-05T10:00:00Z"
}
```

### GET /api/v1/apps/reputation/{package}

Get reputation data for a specific app package.

**Response:**
```json
{
  "package_name": "com.example.app",
  "risk_level": "safe",
  "risk_score": 0.1,
  "is_verified": true,
  "developer": {
    "name": "Example Inc.",
    "verified": true
  },
  "play_store_rating": 4.5,
  "total_installs": "1M+",
  "first_seen": "2022-01-01T00:00:00Z",
  "reports": {
    "malware": 0,
    "privacy": 2,
    "scam": 0
  }
}
```

### POST /api/v1/apps/sideloaded

Check which apps are sideloaded (installed outside official app stores).

**Request:**
```json
{
  "apps": [
    {
      "package_name": "com.example.app1",
      "app_name": "App One",
      "install_source": "com.android.vending"
    },
    {
      "package_name": "com.example.app2",
      "app_name": "App Two",
      "install_source": "unknown"
    }
  ],
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "device_id": "device-123",
  "total_apps": 2,
  "sideloaded_count": 1,
  "sideloaded_apps": [
    {
      "package_name": "com.example.app2",
      "app_name": "App Two",
      "install_source": "unknown",
      "risk_level": "medium",
      "recommendation": "Verify the source of this app"
    }
  ],
  "play_store_count": 1,
  "system_app_count": 0,
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/apps/privacy-report

Generate a comprehensive privacy report for all installed apps.

**Request:**
```json
{
  "apps": [
    {
      "package_name": "com.example.app1",
      "app_name": "App One",
      "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"]
    },
    {
      "package_name": "com.example.app2",
      "app_name": "App Two",
      "permissions": ["android.permission.READ_CONTACTS", "android.permission.CAMERA"]
    }
  ],
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "device_id": "device-123",
  "generated_at": "2024-01-05T10:00:00Z",
  "overall_privacy_score": 65,
  "overall_privacy_grade": "C",
  "summary": {
    "total_apps_analyzed": 2,
    "apps_with_trackers": 1,
    "total_trackers": 3,
    "apps_accessing_location": 1,
    "apps_accessing_contacts": 1,
    "apps_accessing_camera": 1,
    "apps_with_dangerous_permissions": 2
  },
  "privacy_by_category": {
    "location": {
      "apps_count": 1,
      "risk_level": "medium",
      "apps": ["com.example.app1"]
    },
    "contacts": {
      "apps_count": 1,
      "risk_level": "high",
      "apps": ["com.example.app2"]
    },
    "camera": {
      "apps_count": 1,
      "risk_level": "medium",
      "apps": ["com.example.app2"]
    }
  },
  "tracker_summary": {
    "by_company": {
      "Google": 2,
      "Facebook": 1
    },
    "by_category": {
      "analytics": 2,
      "advertising": 1
    }
  },
  "recommendations": [
    {
      "priority": "high",
      "title": "Review Contact Access",
      "description": "1 app has access to your contacts. Review if this is necessary.",
      "apps": ["com.example.app2"]
    }
  ],
  "app_details": [
    { "...detailed analysis for each app..." }
  ]
}
```

### GET /api/v1/apps/trackers

Get list of known tracker SDKs.

**Response:**
```json
{
  "trackers": [
    {
      "package_prefix": "com.google.firebase.analytics",
      "name": "Firebase Analytics",
      "company": "Google",
      "category": "analytics",
      "privacy_impact": "medium",
      "website": "https://firebase.google.com/docs/analytics"
    },
    {
      "package_prefix": "com.facebook.ads",
      "name": "Facebook Ads",
      "company": "Meta",
      "category": "advertising",
      "privacy_impact": "high",
      "website": "https://developers.facebook.com/docs/audience-network"
    }
  ],
  "count": 15,
  "last_updated": "2024-01-05T00:00:00Z"
}
```

### GET /api/v1/apps/permissions/dangerous

Get list of dangerous permission combinations.

**Response:**
```json
{
  "dangerous_combos": [
    {
      "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
      "risk_level": "critical",
      "description": "Can read SMS and send data to internet - potential banking trojan behavior"
    },
    {
      "permissions": ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
      "risk_level": "critical",
      "description": "Can record audio and send to internet - potential spyware behavior"
    },
    {
      "permissions": ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
      "risk_level": "high",
      "description": "Can harvest contacts and exfiltrate - common in data theft malware"
    },
    {
      "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET", "android.permission.ACCESS_BACKGROUND_LOCATION"],
      "risk_level": "high",
      "description": "Can track location in background - stalkerware behavior"
    }
  ],
  "count": 9
}
```

### GET /api/v1/apps/stats

Get app security statistics.

**Response:**
```json
{
  "total_apps_analyzed": 50000,
  "malware_detected": 150,
  "high_risk_apps": 500,
  "sideloaded_detected": 2000,
  "trackers_detected": 15000,
  "by_risk_level": {
    "critical": 150,
    "high": 500,
    "medium": 2000,
    "low": 5000,
    "safe": 42350
  },
  "top_trackers": [
    {"name": "Firebase Analytics", "count": 25000},
    {"name": "Facebook Ads", "count": 15000},
    {"name": "Google Ads", "count": 12000}
  ],
  "last_24_hours": {
    "analyzed": 1000,
    "threats": 5
  }
}
```

### POST /api/v1/apps/report

Report a suspicious app.

**Request:**
```json
{
  "package_name": "com.malicious.app",
  "report_type": "malware",
  "description": "App requests unusual permissions and shows suspicious behavior",
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "status": "received",
  "message": "Thank you for your report. It will be reviewed by our team."
}
```

## Risk Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| `safe` | 0.0 - 0.2 | App appears safe with minimal risk |
| `low` | 0.2 - 0.4 | Minor risk indicators present |
| `medium` | 0.4 - 0.6 | Moderate risk, review recommended |
| `high` | 0.6 - 0.8 | High risk, consider removing |
| `critical` | 0.8 - 1.0 | Critical threat, immediate action required |

## Dangerous Permission Categories

| Category | Permissions | Risk |
|----------|-------------|------|
| **SMS Access** | READ_SMS, RECEIVE_SMS, SEND_SMS | Critical - can intercept 2FA codes |
| **Location** | ACCESS_FINE_LOCATION, ACCESS_BACKGROUND_LOCATION | High - can track movements |
| **Camera/Mic** | CAMERA, RECORD_AUDIO | Critical - surveillance capability |
| **Contacts** | READ_CONTACTS, WRITE_CONTACTS | High - data harvesting |
| **Phone** | READ_PHONE_STATE, CALL_PHONE | High - call interception |
| **Storage** | READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE | Medium - file access |

## Install Sources

| Source | Description | Default Risk |
|--------|-------------|--------------|
| `play_store` | Google Play Store | Low |
| `galaxy_store` | Samsung Galaxy Store | Low |
| `amazon_appstore` | Amazon Appstore | Low |
| `huawei_appgallery` | Huawei AppGallery | Low |
| `f_droid` | F-Droid (open source) | Low |
| `sideloaded` | APK installed manually | High |
| `adb` | Installed via ADB | Medium |
| `system` | Pre-installed system app | Low |
| `unknown` | Unknown source | High |

## Mobile Integration

### Android Implementation

1. **Get Installed Apps:**
   ```kotlin
   fun getInstalledApps(): List<AppInfo> {
       val pm = context.packageManager
       return pm.getInstalledApplications(PackageManager.GET_META_DATA)
           .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
           .map { app ->
               AppInfo(
                   packageName = app.packageName,
                   appName = pm.getApplicationLabel(app).toString(),
                   permissions = pm.getPackageInfo(
                       app.packageName,
                       PackageManager.GET_PERMISSIONS
                   ).requestedPermissions?.toList() ?: emptyList(),
                   installSource = getInstallSource(app.packageName)
               )
           }
   }
   ```

2. **Background Scanning:**
   ```kotlin
   class AppScanWorker(context: Context, params: WorkerParameters) :
       CoroutineWorker(context, params) {

       override suspend fun doWork(): Result {
           val apps = getInstalledApps()
           val analysis = apiClient.analyzeBatch(apps)

           // Notify user of high-risk apps
           analysis.results
               .filter { it.riskLevel in listOf("high", "critical") }
               .forEach { notifyUser(it) }

           return Result.success()
       }
   }
   ```

3. **Schedule Periodic Scans:**
   ```kotlin
   val scanRequest = PeriodicWorkRequestBuilder<AppScanWorker>(
       24, TimeUnit.HOURS
   ).build()

   WorkManager.getInstance(context).enqueueUniquePeriodicWork(
       "app_security_scan",
       ExistingPeriodicWorkPolicy.KEEP,
       scanRequest
   )
   ```

### iOS Implementation

iOS restricts access to installed apps. Alternative approaches:
- Enterprise MDM solutions for managed devices
- VPN-based network traffic analysis
- URL scheme detection for specific apps

## Rate Limits

- Single analysis: 100 requests/minute
- Batch analysis: 10 requests/minute (max 100 apps per batch)
- Privacy report: 5 requests/minute

## Authentication

All endpoints require API key authentication:
```
Authorization: Bearer <api_key>
```
