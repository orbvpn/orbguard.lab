# SMS/Smishing Protection API

## Overview

The SMS Protection API provides real-time analysis of SMS messages for phishing, smishing, and executive impersonation attacks.

## Endpoints

### POST /api/v1/sms/analyze

Analyze a single SMS message for threats.

**Request:**
```json
{
  "sender": "USPS",
  "body": "Your package is on hold. Click here to reschedule delivery: https://usps-delivery.xyz/track",
  "timestamp": "2024-01-05T10:00:00Z",
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "id": "uuid",
  "message_id": "uuid",
  "is_threat": true,
  "threat_level": "high",
  "threat_type": "delivery_scam",
  "confidence": 0.92,
  "description": "High threat level - message contains multiple suspicious indicators",
  "recommendations": [
    "Do NOT click the link to usps-delivery.xyz - it is a known malicious domain",
    "The sender claims to be USPS but this could be spoofed - contact them directly via official channels"
  ],
  "urls": [
    {
      "url": "https://usps-delivery.xyz/track",
      "domain": "usps-delivery.xyz",
      "is_malicious": true,
      "is_shortened": false,
      "category": "phishing",
      "threat_details": "Domain matches known phishing patterns",
      "confidence": 0.9
    }
  ],
  "pattern_matches": [
    {
      "pattern_name": "usps_delivery_scam",
      "pattern_type": "delivery_scam",
      "matched_text": "USPS...delivery...on hold...Click",
      "confidence": 0.85,
      "description": "Fake delivery notification with link"
    }
  ],
  "sender_analysis": {
    "is_short_code": false,
    "is_alphanumeric": true,
    "is_spoofed": false,
    "is_known_brand": true,
    "brand_name": "USPS",
    "risk_score": 0.5,
    "notes": "Sender claims to be USPS - verify authenticity"
  },
  "intent_analysis": {
    "primary_intent": "urgent_action_request",
    "urgency": 0.6,
    "fear_factor": 0.4,
    "reward_promise": 0.0,
    "action_required": true,
    "personal_data": false,
    "financial_data": false,
    "suspicious_flags": ["urgency_language"]
  },
  "analyzed_at": "2024-01-05T10:00:01Z"
}
```

### POST /api/v1/sms/analyze/batch

Analyze multiple SMS messages in a single request.

**Request:**
```json
{
  "messages": [
    {
      "sender": "BANK",
      "body": "Your account has been suspended. Verify now: http://bank-verify.tk",
      "timestamp": "2024-01-05T10:00:00Z"
    },
    {
      "sender": "+1234567890",
      "body": "Hey, just confirming our meeting tomorrow at 3pm",
      "timestamp": "2024-01-05T10:01:00Z"
    }
  ],
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "results": [
    { "...analysis for message 1..." },
    { "...analysis for message 2..." }
  ],
  "total_count": 2,
  "threat_count": 1,
  "analyzed_at": "2024-01-05T10:00:02Z"
}
```

### POST /api/v1/sms/check-url

Check if a specific URL is malicious.

**Request:**
```json
{
  "url": "https://amaz0n-order.xyz/verify"
}
```

**Response:**
```json
{
  "url": "https://amaz0n-order.xyz/verify",
  "is_malicious": true,
  "category": "phishing",
  "threat_level": "high",
  "confidence": 0.9,
  "details": "Amazon typosquatting domain"
}
```

### GET /api/v1/sms/patterns

Get detection patterns for local/offline analysis.

**Response:**
```json
{
  "version": "1.0.0",
  "last_updated": "2024-01-05T10:00:00Z",
  "urgency_words": ["urgent", "immediately", "now", "asap", ...],
  "fear_words": ["suspended", "blocked", "unauthorized", ...],
  "reward_words": ["won", "winner", "prize", ...],
  "personal_words": ["ssn", "password", "pin", ...],
  "financial_words": ["credit card", "bank account", ...],
  "url_shorteners": ["bit.ly", "tinyurl.com", ...],
  "suspicious_tlds": [".xyz", ".top", ".club", ...]
}
```

### GET /api/v1/sms/stats

Get SMS threat statistics.

**Response:**
```json
{
  "total_analyzed": 10000,
  "threats_detected": 150,
  "threats_by_type": {
    "phishing": 60,
    "smishing": 40,
    "scam": 30,
    "bank_fraud": 15,
    "delivery_scam": 5
  },
  "last_24_hours": {
    "analyzed": 500,
    "threats": 12
  }
}
```

## Threat Types

| Type | Description |
|------|-------------|
| `phishing` | Generic phishing attempt |
| `smishing` | SMS-based phishing |
| `malware` | Contains malware links |
| `scam` | General scam message |
| `spam` | Unwanted commercial message |
| `impersonation` | Sender impersonation |
| `executive_impersonation` | CEO/executive impersonation (BEC) |
| `bank_fraud` | Fake bank notification |
| `delivery_scam` | Fake delivery notification |
| `tech_support_scam` | Fake tech support |
| `premium_rate` | Premium rate number scam |
| `suspicious_link` | Contains suspicious URL |

## Threat Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| `safe` | 0.0 - 0.2 | Message appears safe |
| `low` | 0.2 - 0.4 | Minor suspicious indicators |
| `medium` | 0.4 - 0.6 | Some suspicious elements |
| `high` | 0.6 - 0.8 | Multiple suspicious indicators |
| `critical` | 0.8 - 1.0 | Highly likely threat |

## Mobile Integration

### Android Implementation

1. **Request SMS Permission:**
   ```xml
   <uses-permission android:name="android.permission.READ_SMS" />
   <uses-permission android:name="android.permission.RECEIVE_SMS" />
   ```

2. **Register SMS Receiver:**
   ```kotlin
   class SMSReceiver : BroadcastReceiver() {
       override fun onReceive(context: Context, intent: Intent) {
           val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
           for (message in messages) {
               // Send to API for analysis
               SMSAnalyzerService.analyze(
                   sender = message.originatingAddress,
                   body = message.messageBody
               )
           }
       }
   }
   ```

3. **Background Inbox Scanner:**
   ```kotlin
   // Periodically scan inbox for threats
   class SMSScanner(private val context: Context) {
       fun scanInbox(): List<AnalysisResult> {
           val messages = readSmsInbox()
           return apiClient.analyzeBatch(messages)
       }
   }
   ```

### iOS Implementation

iOS does not allow direct SMS access. Alternative approaches:
- Share extension for detecting links in Messages
- Safari content blocker for URL filtering
- iMessage extension for link preview safety

## Rate Limits

- Single analysis: 100 requests/minute
- Batch analysis: 10 requests/minute (max 100 messages per batch)

## Authentication

All endpoints require API key authentication:
```
Authorization: Bearer <api_key>
```
