package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"orbguard-lab/internal/sources"
	"orbguard-lab/internal/sources/free/phishing"
	"orbguard-lab/pkg/logger"
)

func main() {
	// Initialize logger
	log := logger.NewDevelopment()

	// Get API key from environment or use the one provided
	apiKey := os.Getenv("ORBGUARD_SOURCES_GOOGLE_SAFEBROWSING_API_KEY")
	if apiKey == "" {
		apiKey = "AIzaSyAls_vsqyw0KCr9G1G2v4pMhsjqOp3qaHY"
	}

	fmt.Println("===========================================")
	fmt.Println("Google Safe Browsing Connector Test")
	fmt.Println("===========================================")
	fmt.Printf("API Key: %s...%s\n", apiKey[:10], apiKey[len(apiKey)-4:])
	fmt.Println()

	// Create connector
	connector := phishing.NewSafeBrowsingConnector(log)

	// Configure with API key
	err := connector.Configure(sources.ConnectorConfig{
		Enabled:        true,
		UpdateInterval: 30 * time.Minute,
		APIKey:         apiKey,
	})
	if err != nil {
		fmt.Printf("❌ Failed to configure connector: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Test 1: Fetch threat list updates
	fmt.Println("📋 Test 1: Fetching threat list updates...")
	fmt.Println("-------------------------------------------")
	result, err := connector.Fetch(ctx)
	if err != nil {
		fmt.Printf("❌ Fetch failed: %v\n", err)
	} else {
		fmt.Printf("✅ Fetch successful!\n")
		fmt.Printf("   - Duration: %v\n", result.Duration)
		fmt.Printf("   - Total fetched: %d indicators\n", result.TotalFetched)
		fmt.Printf("   - Success: %v\n", result.Success)
		if len(result.RawIndicators) > 0 {
			fmt.Printf("   - Sample indicator: %+v\n", result.RawIndicators[0])
		}
	}
	fmt.Println()

	// Test 2: URL Lookup with known safe URLs
	fmt.Println("🔍 Test 2: Looking up known safe URLs...")
	fmt.Println("-------------------------------------------")
	safeURLs := []string{
		"https://www.google.com",
		"https://www.github.com",
		"https://www.apple.com",
	}

	matches, err := connector.LookupURLs(ctx, safeURLs)
	if err != nil {
		fmt.Printf("❌ URL lookup failed: %v\n", err)
	} else {
		fmt.Printf("✅ URL lookup successful!\n")
		fmt.Printf("   - URLs checked: %d\n", len(safeURLs))
		fmt.Printf("   - Threats found: %d\n", len(matches))
		if len(matches) == 0 {
			fmt.Println("   - All URLs are safe (as expected)")
		}
	}
	fmt.Println()

	// Test 3: URL Lookup with known test URLs
	// Google provides test URLs for Safe Browsing API testing
	fmt.Println("🔍 Test 3: Looking up Google's test URLs...")
	fmt.Println("-------------------------------------------")
	testURLs := []string{
		"http://malware.testing.google.test/testing/malware/",
		"http://testsafebrowsing.appspot.com/s/phishing.html",
		"http://testsafebrowsing.appspot.com/s/malware.html",
	}

	matches, err = connector.LookupURLs(ctx, testURLs)
	if err != nil {
		fmt.Printf("❌ Test URL lookup failed: %v\n", err)
	} else {
		fmt.Printf("✅ Test URL lookup completed!\n")
		fmt.Printf("   - URLs checked: %d\n", len(testURLs))
		fmt.Printf("   - Threats found: %d\n", len(matches))
		for _, match := range matches {
			fmt.Printf("   - ⚠️  %s\n", match.URL)
			fmt.Printf("        Threat: %s | Platform: %s | Severity: %s\n",
				match.ThreatType, match.PlatformType, match.Severity)
		}
	}
	fmt.Println()

	// Test 4: URL Lookup with suspicious-looking URLs (for demonstration)
	fmt.Println("🔍 Test 4: Looking up suspicious URLs...")
	fmt.Println("-------------------------------------------")
	suspiciousURLs := []string{
		"http://suspicious-phishing-test.com/login/bank",
		"http://free-iphone-winner.com/claim",
	}

	matches, err = connector.LookupURLs(ctx, suspiciousURLs)
	if err != nil {
		fmt.Printf("❌ Suspicious URL lookup failed: %v\n", err)
	} else {
		fmt.Printf("✅ Suspicious URL lookup completed!\n")
		fmt.Printf("   - URLs checked: %d\n", len(suspiciousURLs))
		fmt.Printf("   - Threats found: %d\n", len(matches))
		if len(matches) == 0 {
			fmt.Println("   - No threats found (URLs not in Google's database)")
		}
		for _, match := range matches {
			fmt.Printf("   - ⚠️  %s: %s (%s)\n", match.URL, match.ThreatType, match.Severity)
		}
	}
	fmt.Println()

	fmt.Println("===========================================")
	fmt.Println("Test completed!")
	fmt.Println("===========================================")
}
