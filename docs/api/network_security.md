# Network Security API

## Overview

The Network Security API provides comprehensive network protection including Wi-Fi security auditing, DNS protection, attack detection (ARP spoofing, evil twin, MITM), SSL/TLS verification, and VPN integration with OrbNet.

## Endpoints

### POST /api/v1/network/wifi/audit

Perform a comprehensive Wi-Fi security audit.

**Request:**
```json
{
  "current_network": {
    "ssid": "CoffeeShop_WiFi",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "security_type": "wpa2",
    "signal_level": -65,
    "frequency": 2437,
    "channel": 6,
    "is_connected": true,
    "is_hidden": false
  },
  "nearby_networks": [
    {
      "ssid": "CoffeeShop_WiFi",
      "bssid": "11:22:33:44:55:66",
      "security_type": "open",
      "signal_level": -55
    },
    {
      "ssid": "Free_WiFi",
      "bssid": "AA:BB:CC:11:22:33",
      "security_type": "open",
      "signal_level": -70
    }
  ],
  "gateway_ip": "192.168.1.1",
  "dns_ip": "8.8.8.8",
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "id": "uuid",
  "network": {
    "ssid": "CoffeeShop_WiFi",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "security_type": "wpa2",
    "signal_level": -65
  },
  "risk_level": "critical",
  "risk_score": 0.85,
  "security_issues": [
    {
      "type": "public_network",
      "severity": "medium",
      "title": "Public Wi-Fi Network",
      "description": "This appears to be a public Wi-Fi network. Public networks are common targets for attackers.",
      "mitigation": "Use VPN when connected to public Wi-Fi, avoid sensitive transactions"
    }
  ],
  "rogue_ap_detected": [],
  "evil_twin_detected": [
    {
      "ssid": "CoffeeShop_WiFi",
      "legit_bssid": "AA:BB:CC:DD:EE:FF",
      "evil_bssid": "11:22:33:44:55:66",
      "signal_diff": 10,
      "security_diff": true,
      "risk_level": "critical",
      "confidence": 0.9,
      "description": "Potential evil twin detected for 'CoffeeShop_WiFi'",
      "recommendation": "Do not connect to this network. If already connected, use VPN immediately.",
      "detected_at": "2024-01-05T10:00:00Z"
    }
  ],
  "recommendations": [
    {
      "priority": "critical",
      "title": "Evil Twin Attack Detected",
      "description": "A malicious access point is impersonating this network. Do not transmit sensitive data.",
      "action": "enable_vpn"
    }
  ],
  "audited_at": "2024-01-05T10:00:00Z"
}
```

### GET /api/v1/network/wifi/security-types

Get information about Wi-Fi security types and their risks.

**Response:**
```json
{
  "security_types": [
    {
      "type": "open",
      "risk_level": "critical",
      "description": "Open network with no encryption - all traffic is visible to attackers"
    },
    {
      "type": "wep",
      "risk_level": "critical",
      "description": "WEP encryption is broken and can be cracked in minutes"
    },
    {
      "type": "wpa",
      "risk_level": "high",
      "description": "WPA has known vulnerabilities - WPA2 or WPA3 recommended"
    },
    {
      "type": "wpa2",
      "risk_level": "low",
      "description": "WPA2 is secure for most use cases, but WPA3 is preferred"
    },
    {
      "type": "wpa3",
      "risk_level": "safe",
      "description": "WPA3 provides the strongest Wi-Fi security currently available"
    }
  ]
}
```

### POST /api/v1/network/dns/check

Check DNS security and detect hijacking.

**Request:**
```json
{
  "current_dns": "192.168.1.1",
  "gateway_ip": "192.168.1.1",
  "device_id": "device-123",
  "test_domains": true,
  "check_leaks": true,
  "check_hijack": true
}
```

**Response:**
```json
{
  "id": "uuid",
  "current_dns": "192.168.1.1",
  "is_secure": false,
  "is_encrypted": false,
  "encryption_type": "none",
  "provider": null,
  "is_hijacked": false,
  "hijack_details": null,
  "leak_detected": true,
  "leak_details": {
    "leaked_to_isp": true,
    "description": "DNS queries are not encrypted and may be visible to your ISP",
    "detected_at": "2024-01-05T10:00:00Z"
  },
  "security_issues": [
    {
      "type": "unknown_dns",
      "severity": "medium",
      "title": "Unknown DNS Server",
      "description": "DNS server 192.168.1.1 is not a recognized trusted provider",
      "mitigation": "Consider switching to a trusted DNS provider like Cloudflare (1.1.1.1) or Quad9 (9.9.9.9)"
    },
    {
      "type": "dns_leak",
      "severity": "medium",
      "title": "Potential DNS Leak",
      "description": "Your DNS queries are not encrypted and could be monitored",
      "mitigation": "Enable DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)"
    }
  ],
  "recommendations": [
    {
      "priority": "high",
      "title": "Enable Encrypted DNS",
      "description": "Use DNS-over-HTTPS (DoH) for privacy. Recommended: Cloudflare (1.1.1.1) or Quad9 (9.9.9.9).",
      "action": "enable_doh"
    }
  ],
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### GET /api/v1/network/dns/providers

Get list of trusted DNS providers.

**Response:**
```json
{
  "providers": [
    {
      "name": "Cloudflare",
      "primary_ip": "1.1.1.1",
      "secondary_ip": "1.0.0.1",
      "doh_url": "https://cloudflare-dns.com/dns-query",
      "dot_host": "one.one.one.one",
      "supports_doh": true,
      "supports_dot": true,
      "blocks_malware": false,
      "blocks_ads": false,
      "privacy_rating": "excellent",
      "country": "US",
      "is_trusted": true
    },
    {
      "name": "Quad9",
      "primary_ip": "9.9.9.9",
      "secondary_ip": "149.112.112.112",
      "doh_url": "https://dns.quad9.net/dns-query",
      "dot_host": "dns.quad9.net",
      "supports_doh": true,
      "supports_dot": true,
      "blocks_malware": true,
      "blocks_ads": false,
      "privacy_rating": "excellent",
      "country": "CH",
      "is_trusted": true
    }
  ],
  "count": 8
}
```

### POST /api/v1/network/dns/configure

Configure DNS settings for the device.

**Request:**
```json
{
  "primary_dns": "1.1.1.1",
  "secondary_dns": "1.0.0.1",
  "is_encrypted": true,
  "encryption_type": "doh",
  "provider": "cloudflare",
  "block_malicious": true,
  "block_ads": false,
  "block_trackers": false
}
```

**Response:**
```json
{
  "status": "configured",
  "config": {
    "primary_dns": "1.1.1.1",
    "secondary_dns": "1.0.0.1",
    "is_encrypted": true,
    "encryption_type": "doh"
  },
  "message": "DNS configuration saved. Apply on device to take effect."
}
```

### POST /api/v1/network/arp/check

Check for ARP spoofing attacks.

**Request:**
```json
{
  "arp_table": [
    {
      "ip_address": "192.168.1.1",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "is_gateway": true
    },
    {
      "ip_address": "192.168.1.100",
      "mac_address": "11:22:33:44:55:66"
    },
    {
      "ip_address": "192.168.1.1",
      "mac_address": "99:88:77:66:55:44"
    }
  ],
  "gateway_ip": "192.168.1.1",
  "gateway_mac": "AA:BB:CC:DD:EE:FF",
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "id": "uuid",
  "is_spoof_detected": true,
  "alerts": [
    {
      "id": "uuid",
      "type": "arp_spoofing",
      "severity": "critical",
      "title": "ARP Spoofing Attack",
      "description": "Multiple MAC addresses claiming IP 192.168.1.1: [AA:BB:CC:DD:EE:FF, 99:88:77:66:55:44]",
      "evidence": ["IP 192.168.1.1 has MACs: [AA:BB:CC:DD:EE:FF, 99:88:77:66:55:44]"],
      "mitigation": "Use VPN to encrypt all traffic, avoid sensitive activities on this network",
      "detected_at": "2024-01-05T10:00:00Z"
    }
  ],
  "suspicious_macs": [],
  "duplicate_ips": ["192.168.1.1"],
  "recommendations": [
    {
      "priority": "critical",
      "title": "ARP Spoofing Detected - Enable VPN",
      "description": "An attacker may be intercepting your traffic. Enable VPN immediately.",
      "action": "enable_vpn"
    },
    {
      "priority": "high",
      "title": "Avoid Sensitive Activities",
      "description": "Do not perform banking or enter passwords on this network.",
      "action": "avoid_sensitive"
    }
  ],
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### POST /api/v1/network/ssl/check

Check SSL/TLS security for a host.

**Request:**
```json
{
  "host": "example.com",
  "port": 443,
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "id": "uuid",
  "host": "example.com",
  "port": 443,
  "is_secure": true,
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "CN=DigiCert SHA2 Secure Server CA",
    "serial_number": "123456789",
    "not_before": "2023-01-01T00:00:00Z",
    "not_after": "2025-01-01T00:00:00Z",
    "is_expired": false,
    "is_self_signed": false,
    "is_valid": true,
    "public_key_algorithm": "RSA",
    "key_size": 2048
  },
  "tls_version": "TLS 1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "is_valid_chain": true,
  "security_issues": [],
  "recommendations": [],
  "checked_at": "2024-01-05T10:00:00Z"
}
```

### GET /api/v1/network/attacks/types

Get list of network attack types and their descriptions.

**Response:**
```json
{
  "attack_types": [
    {
      "type": "arp_spoofing",
      "title": "ARP Spoofing Attack",
      "description": "An attacker is sending fake ARP messages to intercept network traffic",
      "severity": "critical",
      "mitigation": "Use VPN to encrypt all traffic, avoid sensitive activities on this network"
    },
    {
      "type": "evil_twin",
      "title": "Evil Twin Attack",
      "description": "A fake Wi-Fi network is impersonating a legitimate one to steal data",
      "severity": "critical",
      "mitigation": "Verify network authenticity, use VPN, avoid sensitive activities"
    },
    {
      "type": "dns_hijacking",
      "title": "DNS Hijacking",
      "description": "Your DNS queries are being redirected to malicious DNS servers",
      "severity": "critical",
      "mitigation": "Configure secure DNS (1.1.1.1 or 9.9.9.9), use VPN"
    },
    {
      "type": "ssl_stripping",
      "title": "SSL Stripping Attack",
      "description": "An attacker is downgrading secure HTTPS connections to unencrypted HTTP",
      "severity": "critical",
      "mitigation": "Only visit sites with HTTPS, use VPN, enable HSTS in browser"
    },
    {
      "type": "mitm",
      "title": "Man-in-the-Middle Attack",
      "description": "An attacker is intercepting communications between you and the server",
      "severity": "critical",
      "mitigation": "Use VPN immediately, disconnect from this network if possible"
    }
  ],
  "count": 9
}
```

### POST /api/v1/network/vpn/recommend

Get VPN usage recommendation based on network conditions.

**Request:**
```json
{
  "wifi_audit": {
    "risk_level": "high",
    "risk_score": 0.75,
    "security_issues": [
      {
        "type": "weak_encryption",
        "severity": "critical"
      }
    ],
    "evil_twin_detected": []
  },
  "dns_check": {
    "is_secure": false,
    "is_encrypted": false,
    "is_hijacked": false
  }
}
```

**Response:**
```json
{
  "should_connect": true,
  "reason": "Network has significant security risks - VPN recommended",
  "priority": "recommended",
  "network_risk": "high"
}
```

### GET /api/v1/network/vpn/config

Get VPN configuration for OrbNet integration.

**Response:**
```json
{
  "auto_connect": false,
  "auto_connect_on_public_wifi": true,
  "auto_connect_on_mobile_data": false,
  "kill_switch": true,
  "dns_protection": true,
  "threat_blocking": true,
  "split_tunneling": false,
  "excluded_apps": [],
  "preferred_protocol": "wireguard",
  "preferred_location": null
}
```

### PUT /api/v1/network/vpn/config

Update VPN configuration.

**Request:**
```json
{
  "auto_connect": true,
  "auto_connect_on_public_wifi": true,
  "auto_connect_on_mobile_data": false,
  "kill_switch": true,
  "dns_protection": true,
  "threat_blocking": true,
  "split_tunneling": true,
  "excluded_apps": ["com.spotify.music", "com.netflix.mediaclient"],
  "preferred_protocol": "wireguard",
  "preferred_location": "us-east"
}
```

**Response:**
```json
{
  "status": "updated",
  "config": { "...updated config..." },
  "message": "VPN configuration updated"
}
```

### POST /api/v1/network/audit/full

Perform a full network security audit (Wi-Fi + DNS + ARP + SSL).

**Request:**
```json
{
  "wifi": {
    "current_network": {
      "ssid": "HomeNetwork",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "security_type": "wpa2"
    },
    "nearby_networks": []
  },
  "dns": {
    "current_dns": "8.8.8.8",
    "check_leaks": true,
    "check_hijack": true
  },
  "arp": {
    "arp_table": [
      {"ip_address": "192.168.1.1", "mac_address": "AA:BB:CC:DD:EE:FF", "is_gateway": true}
    ],
    "gateway_ip": "192.168.1.1"
  },
  "ssl": [
    {"host": "bank.example.com", "port": 443}
  ],
  "device_id": "device-123"
}
```

**Response:**
```json
{
  "device_id": "device-123",
  "wifi": { "...wifi audit result..." },
  "dns": { "...dns check result..." },
  "arp": { "...arp check result..." },
  "ssl": [ { "...ssl check result..." } ],
  "overall_risk": {
    "risk_score": 0.35,
    "risk_level": "low"
  },
  "vpn_recommendation": {
    "should_connect": false,
    "reason": "Network appears safe - VPN optional",
    "priority": "optional",
    "network_risk": "low"
  }
}
```

### GET /api/v1/network/stats

Get network security statistics.

**Response:**
```json
{
  "total_scans": 10000,
  "wifi_audits": 5000,
  "dns_checks": 3000,
  "attacks_detected": 150,
  "attacks_by_type": {
    "evil_twin": 50,
    "arp_spoofing": 40,
    "dns_hijacking": 30,
    "rogue_ap": 20,
    "ssl_stripping": 10
  },
  "rogue_aps_detected": 75,
  "evil_twins_detected": 50,
  "dns_hijacks_detected": 30,
  "unsecure_networks": 2000,
  "vpn_connections_forced": 500,
  "last_24_hours": {
    "scans": 200,
    "attacks_detected": 5,
    "rogue_aps": 2,
    "evil_twins": 1
  }
}
```

## Risk Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| `safe` | 0.0 - 0.2 | Network appears safe |
| `low` | 0.2 - 0.4 | Minor security concerns |
| `medium` | 0.4 - 0.6 | Moderate risk, VPN recommended |
| `high` | 0.6 - 0.8 | High risk, VPN strongly recommended |
| `critical` | 0.8 - 1.0 | Critical threat, immediate action required |

## Attack Types

| Type | Severity | Description |
|------|----------|-------------|
| `arp_spoofing` | Critical | Fake ARP messages to intercept traffic |
| `dns_spoofing` | Critical | DNS responses manipulated for redirection |
| `ssl_stripping` | Critical | HTTPS downgraded to HTTP |
| `mitm` | Critical | Traffic interception between client and server |
| `evil_twin` | Critical | Fake Wi-Fi impersonating legitimate network |
| `rogue_ap` | High | Unauthorized access point |
| `dns_hijacking` | Critical | DNS queries redirected to malicious servers |
| `captive_portal` | Medium | Suspicious login portal |
| `deauth` | High | Forced disconnection (prelude to evil twin) |

## Wi-Fi Security Types

| Type | Risk Level | Recommendation |
|------|------------|----------------|
| `open` | Critical | Never use without VPN |
| `wep` | Critical | Avoid - easily cracked |
| `wpa` | High | Upgrade to WPA2/WPA3 |
| `wpa2` | Low | Secure for most use cases |
| `wpa3` | Safe | Best available security |

## Trusted DNS Providers

| Provider | Primary | Malware Blocking | DoH Support |
|----------|---------|------------------|-------------|
| Cloudflare | 1.1.1.1 | No | Yes |
| Cloudflare Security | 1.1.1.2 | Yes | Yes |
| Quad9 | 9.9.9.9 | Yes | Yes |
| Google | 8.8.8.8 | No | Yes |
| AdGuard | 94.140.14.14 | Yes | Yes |
| OpenDNS | 208.67.222.222 | Yes | Yes |

## Mobile Integration

### Android Implementation

1. **Get Connected Wi-Fi Info:**
   ```kotlin
   fun getWiFiInfo(): WiFiNetwork? {
       val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
       val info = wifiManager.connectionInfo
       return WiFiNetwork(
           ssid = info.ssid.removeSurrounding("\""),
           bssid = info.bssid,
           signalLevel = info.rssi,
           frequency = info.frequency
       )
   }
   ```

2. **Scan Nearby Networks:**
   ```kotlin
   fun scanNetworks(): List<WiFiNetwork> {
       val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
       return wifiManager.scanResults.map { result ->
           WiFiNetwork(
               ssid = result.SSID,
               bssid = result.BSSID,
               securityType = getSecurityType(result.capabilities),
               signalLevel = result.level
           )
       }
   }
   ```

3. **Get ARP Table:**
   ```kotlin
   fun getARPTable(): List<ARPEntry> {
       val entries = mutableListOf<ARPEntry>()
       File("/proc/net/arp").useLines { lines ->
           lines.drop(1).forEach { line ->
               val parts = line.split("\\s+".toRegex())
               if (parts.size >= 4) {
                   entries.add(ARPEntry(
                       ipAddress = parts[0],
                       macAddress = parts[3]
                   ))
               }
           }
       }
       return entries
   }
   ```

4. **Auto-Connect VPN on Unsafe Network:**
   ```kotlin
   class NetworkSecurityMonitor : BroadcastReceiver() {
       override fun onReceive(context: Context, intent: Intent) {
           val result = apiClient.auditWiFi(getCurrentNetwork())
           if (result.riskLevel in listOf("high", "critical")) {
               OrbNetVPN.connect()
           }
       }
   }
   ```

### iOS Implementation

```swift
import NetworkExtension

func getWiFiInfo() -> WiFiNetwork? {
    guard let interfaces = CNCopySupportedInterfaces() as? [String],
          let interface = interfaces.first,
          let info = CNCopyCurrentNetworkInfo(interface as CFString) as? [String: Any] else {
        return nil
    }

    return WiFiNetwork(
        ssid: info[kCNNetworkInfoKeySSID as String] as? String ?? "",
        bssid: info[kCNNetworkInfoKeyBSSID as String] as? String ?? ""
    )
}
```

## Rate Limits

- Wi-Fi audit: 30 requests/minute
- DNS check: 60 requests/minute
- ARP check: 30 requests/minute
- SSL check: 60 requests/minute
- Full audit: 10 requests/minute

## Authentication

All endpoints require API key authentication:
```
Authorization: Bearer <api_key>
```
