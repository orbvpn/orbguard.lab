package desktop_security

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"orbguard-lab/internal/domain/models"
	"orbguard-lab/pkg/logger"
)

// CodeSigningVerifier verifies code signatures on binaries
type CodeSigningVerifier struct {
	logger   *logger.Logger
	platform models.DesktopPlatform
}

// NewCodeSigningVerifier creates a new code signing verifier
func NewCodeSigningVerifier(log *logger.Logger) *CodeSigningVerifier {
	return &CodeSigningVerifier{
		logger:   log.WithComponent("code-signing-verifier"),
		platform: detectPlatform(),
	}
}

// SigningInfo contains detailed code signing information
type SigningInfo struct {
	Status           models.CodeSigningStatus `json:"status"`
	IsSigned         bool                     `json:"is_signed"`
	IsValid          bool                     `json:"is_valid"`
	TeamID           string                   `json:"team_id,omitempty"`
	SigningIdentity  string                   `json:"signing_identity,omitempty"`
	SigningAuthority string                   `json:"signing_authority,omitempty"`
	CertChain        []CertInfo               `json:"cert_chain,omitempty"`
	Entitlements     map[string]interface{}   `json:"entitlements,omitempty"`
	Flags            []string                 `json:"flags,omitempty"`
	Timestamp        *time.Time               `json:"timestamp,omitempty"`
	IsNotarized      bool                     `json:"is_notarized"`
	IsHardened       bool                     `json:"is_hardened"`
	Errors           []string                 `json:"errors,omitempty"`
	RawOutput        string                   `json:"raw_output,omitempty"`
}

// CertInfo contains certificate information
type CertInfo struct {
	Subject      string     `json:"subject"`
	Issuer       string     `json:"issuer"`
	SerialNumber string     `json:"serial_number,omitempty"`
	NotBefore    *time.Time `json:"not_before,omitempty"`
	NotAfter     *time.Time `json:"not_after,omitempty"`
	IsExpired    bool       `json:"is_expired"`
	IsCA         bool       `json:"is_ca"`
}

// Verify verifies the code signature of a binary
func (v *CodeSigningVerifier) Verify(ctx context.Context, path string) (*SigningInfo, error) {
	switch v.platform {
	case models.DesktopPlatformMacOS:
		return v.verifyMacOS(ctx, path)
	case models.DesktopPlatformWindows:
		return v.verifyWindows(ctx, path)
	case models.DesktopPlatformLinux:
		return v.verifyLinux(ctx, path)
	default:
		return &SigningInfo{
			Status:   models.CodeSigningUnknown,
			IsSigned: false,
			Errors:   []string{"Unsupported platform"},
		}, nil
	}
}

// verifyMacOS verifies code signing on macOS using codesign
func (v *CodeSigningVerifier) verifyMacOS(ctx context.Context, path string) (*SigningInfo, error) {
	info := &SigningInfo{
		Status:   models.CodeSigningUnknown,
		IsSigned: false,
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		info.Errors = append(info.Errors, "File does not exist")
		return info, nil
	}

	// Run codesign verification
	cmd := exec.CommandContext(ctx, "codesign", "-dv", "--verbose=4", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String() + stderr.String()
	info.RawOutput = output

	if err != nil {
		// Check if it's unsigned or invalid
		if strings.Contains(output, "code object is not signed at all") {
			info.Status = models.CodeSigningNotSigned
			info.IsSigned = false
			return info, nil
		}
		if strings.Contains(output, "invalid signature") {
			info.Status = models.CodeSigningInvalid
			info.IsSigned = true
			info.IsValid = false
			info.Errors = append(info.Errors, "Invalid signature")
			return info, nil
		}
		info.Errors = append(info.Errors, err.Error())
		return info, nil
	}

	info.IsSigned = true

	// Parse codesign output
	v.parseCodesignOutput(output, info)

	// Verify signature validity
	verifyCmd := exec.CommandContext(ctx, "codesign", "-v", "--strict", path)
	if err := verifyCmd.Run(); err != nil {
		info.IsValid = false
		info.Errors = append(info.Errors, "Signature verification failed")
	} else {
		info.IsValid = true
	}

	// Check for notarization
	v.checkNotarization(ctx, path, info)

	// Check entitlements
	v.extractEntitlements(ctx, path, info)

	// Determine final status
	v.determineStatus(info)

	return info, nil
}

// parseCodesignOutput parses codesign verbose output
func (v *CodeSigningVerifier) parseCodesignOutput(output string, info *SigningInfo) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Authority=") {
			authority := strings.TrimPrefix(line, "Authority=")
			if info.SigningAuthority == "" {
				info.SigningAuthority = authority
			}
			info.CertChain = append(info.CertChain, CertInfo{
				Subject: authority,
			})
		}

		if strings.HasPrefix(line, "TeamIdentifier=") {
			info.TeamID = strings.TrimPrefix(line, "TeamIdentifier=")
		}

		if strings.HasPrefix(line, "Identifier=") {
			info.SigningIdentity = strings.TrimPrefix(line, "Identifier=")
		}

		if strings.HasPrefix(line, "Signature=") {
			sigType := strings.TrimPrefix(line, "Signature=")
			if sigType == "adhoc" {
				info.Status = models.CodeSigningAdHoc
			}
		}

		if strings.HasPrefix(line, "Timestamp=") {
			timestampStr := strings.TrimPrefix(line, "Timestamp=")
			if t, err := time.Parse("Jan 2, 2006 at 3:04:05 PM MST", timestampStr); err == nil {
				info.Timestamp = &t
			}
		}

		if strings.Contains(line, "flags=") {
			if match := regexp.MustCompile(`flags=0x[0-9a-f]+\(([^)]+)\)`).FindStringSubmatch(line); len(match) > 1 {
				info.Flags = strings.Split(match[1], ",")
				for _, flag := range info.Flags {
					if strings.TrimSpace(flag) == "runtime" {
						info.IsHardened = true
					}
				}
			}
		}
	}
}

// checkNotarization checks if the binary is notarized
func (v *CodeSigningVerifier) checkNotarization(ctx context.Context, path string, info *SigningInfo) {
	cmd := exec.CommandContext(ctx, "spctl", "-a", "-v", path)
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "accepted") {
		if strings.Contains(string(output), "Notarized Developer ID") {
			info.IsNotarized = true
		}
	}
}

// extractEntitlements extracts entitlements from the binary
func (v *CodeSigningVerifier) extractEntitlements(ctx context.Context, path string, info *SigningInfo) {
	cmd := exec.CommandContext(ctx, "codesign", "-d", "--entitlements", "-", "--xml", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return
	}

	// Parse entitlements (simplified - in production would use plist parsing)
	outputStr := string(output)
	info.Entitlements = make(map[string]interface{})

	// Check for common dangerous entitlements
	dangerousEntitlements := []string{
		"com.apple.security.cs.disable-library-validation",
		"com.apple.security.cs.allow-unsigned-executable-memory",
		"com.apple.security.cs.allow-dyld-environment-variables",
		"com.apple.security.cs.debugger",
		"com.apple.security.get-task-allow",
	}

	for _, ent := range dangerousEntitlements {
		if strings.Contains(outputStr, ent) {
			info.Entitlements[ent] = true
		}
	}
}

// determineStatus determines the final signing status
func (v *CodeSigningVerifier) determineStatus(info *SigningInfo) {
	if !info.IsSigned {
		info.Status = models.CodeSigningNotSigned
		return
	}

	if !info.IsValid {
		info.Status = models.CodeSigningInvalid
		return
	}

	if info.Status == models.CodeSigningAdHoc {
		return
	}

	// Check authority chain
	if len(info.CertChain) > 0 {
		authority := info.CertChain[0].Subject
		if strings.Contains(authority, "Apple Root CA") || strings.Contains(authority, "Software Signing") {
			info.Status = models.CodeSigningAppleSystem
		} else if strings.Contains(authority, "Mac App Store") {
			info.Status = models.CodeSigningAppleStore
		} else if strings.Contains(authority, "Developer ID") {
			info.Status = models.CodeSigningDeveloperID
		} else {
			info.Status = models.CodeSigningValid
		}
	} else {
		info.Status = models.CodeSigningValid
	}
}

// verifyWindows verifies code signing on Windows using signtool/powershell
func (v *CodeSigningVerifier) verifyWindows(ctx context.Context, path string) (*SigningInfo, error) {
	info := &SigningInfo{
		Status:   models.CodeSigningUnknown,
		IsSigned: false,
	}

	// Use PowerShell to check signature
	psScript := fmt.Sprintf(`
		$sig = Get-AuthenticodeSignature -FilePath '%s'
		@{
			Status = $sig.Status.ToString()
			SignerCertificate = @{
				Subject = $sig.SignerCertificate.Subject
				Issuer = $sig.SignerCertificate.Issuer
				NotBefore = $sig.SignerCertificate.NotBefore.ToString('o')
				NotAfter = $sig.SignerCertificate.NotAfter.ToString('o')
			}
			TimeStamperCertificate = if($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
		} | ConvertTo-Json
	`, path)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		info.Errors = append(info.Errors, err.Error())
		return info, nil
	}

	info.RawOutput = string(output)

	// Parse output
	if strings.Contains(string(output), "\"Status\": \"Valid\"") {
		info.IsSigned = true
		info.IsValid = true
		info.Status = models.CodeSigningValid

		// Check if Microsoft signed
		if strings.Contains(string(output), "Microsoft") {
			info.Status = models.CodeSigningMicrosoft
		}
	} else if strings.Contains(string(output), "\"Status\": \"NotSigned\"") {
		info.IsSigned = false
		info.Status = models.CodeSigningNotSigned
	} else {
		info.IsSigned = true
		info.IsValid = false
		info.Status = models.CodeSigningInvalid
	}

	return info, nil
}

// verifyLinux verifies signatures on Linux (limited support)
func (v *CodeSigningVerifier) verifyLinux(ctx context.Context, path string) (*SigningInfo, error) {
	info := &SigningInfo{
		Status:   models.CodeSigningUnknown,
		IsSigned: false,
	}

	// Check for GPG signature in .sig or .asc file
	sigPath := path + ".sig"
	ascPath := path + ".asc"

	var sigFile string
	if _, err := os.Stat(sigPath); err == nil {
		sigFile = sigPath
	} else if _, err := os.Stat(ascPath); err == nil {
		sigFile = ascPath
	}

	if sigFile != "" {
		cmd := exec.CommandContext(ctx, "gpg", "--verify", sigFile, path)
		output, err := cmd.CombinedOutput()
		info.RawOutput = string(output)

		if err == nil && strings.Contains(string(output), "Good signature") {
			info.IsSigned = true
			info.IsValid = true
			info.Status = models.CodeSigningValid

			// Extract signer
			if match := regexp.MustCompile(`Good signature from "([^"]+)"`).FindStringSubmatch(string(output)); len(match) > 1 {
				info.SigningIdentity = match[1]
			}
		} else {
			info.IsSigned = true
			info.IsValid = false
			info.Status = models.CodeSigningInvalid
		}
	}

	// Check ELF signature (requires pesign or sbsign)
	if strings.HasSuffix(path, ".ko") || strings.HasSuffix(path, ".efi") {
		// Check kernel module signature
		cmd := exec.CommandContext(ctx, "modinfo", path)
		output, err := cmd.CombinedOutput()
		if err == nil {
			if strings.Contains(string(output), "sig_id:") {
				info.IsSigned = true
				info.Status = models.CodeSigningValid
			}
		}
	}

	return info, nil
}

// VerifyBatch verifies multiple binaries
func (v *CodeSigningVerifier) VerifyBatch(ctx context.Context, paths []string) map[string]*SigningInfo {
	results := make(map[string]*SigningInfo)

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		info, err := v.Verify(ctx, path)
		if err != nil {
			info = &SigningInfo{
				Status: models.CodeSigningUnknown,
				Errors: []string{err.Error()},
			}
		}
		results[path] = info
	}

	return results
}

// ExtractCertificateChain extracts the certificate chain from a signed binary
func (v *CodeSigningVerifier) ExtractCertificateChain(ctx context.Context, path string) ([]CertInfo, error) {
	var certs []CertInfo

	switch v.platform {
	case models.DesktopPlatformMacOS:
		// Extract certificates using security framework
		cmd := exec.CommandContext(ctx, "codesign", "-d", "--extract-certificates", path)
		_ = cmd.Run() // Creates codesign0, codesign1, etc.

		// Read extracted certificates
		for i := 0; i < 10; i++ { // Max 10 certs in chain
			certFile := fmt.Sprintf("codesign%d", i)
			if _, err := os.Stat(certFile); os.IsNotExist(err) {
				break
			}

			certData, err := os.ReadFile(certFile)
			if err != nil {
				continue
			}
			defer os.Remove(certFile)

			// Parse DER certificate
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				// Try PEM
				block, _ := pem.Decode(certData)
				if block != nil {
					cert, err = x509.ParseCertificate(block.Bytes)
				}
				if err != nil {
					continue
				}
			}

			certInfo := CertInfo{
				Subject:      cert.Subject.String(),
				Issuer:       cert.Issuer.String(),
				SerialNumber: cert.SerialNumber.String(),
				NotBefore:    &cert.NotBefore,
				NotAfter:     &cert.NotAfter,
				IsExpired:    time.Now().After(cert.NotAfter),
				IsCA:         cert.IsCA,
			}
			certs = append(certs, certInfo)
		}
	}

	return certs, nil
}

// IsTrustedDeveloper checks if a team ID is in the trusted developers list
func (v *CodeSigningVerifier) IsTrustedDeveloper(teamID string) bool {
	// Apple and common trusted team IDs
	trustedTeamIDs := map[string]bool{
		"EQHXZ8M8AV": true, // Apple
		"59GAB85EFG": true, // Microsoft
		"Software Signing": true,
	}
	return trustedTeamIDs[teamID]
}

// GetRiskForSigningStatus returns risk assessment for a signing status
func GetRiskForSigningStatus(status models.CodeSigningStatus) models.PersistenceRiskLevel {
	switch status {
	case models.CodeSigningAppleSystem, models.CodeSigningMicrosoft:
		return models.PersistenceRiskClean
	case models.CodeSigningAppleStore:
		return models.PersistenceRiskLow
	case models.CodeSigningDeveloperID, models.CodeSigningValid:
		return models.PersistenceRiskLow
	case models.CodeSigningAdHoc:
		return models.PersistenceRiskMedium
	case models.CodeSigningNotSigned:
		return models.PersistenceRiskHigh
	case models.CodeSigningInvalid, models.CodeSigningRevoked, models.CodeSigningExpired:
		return models.PersistenceRiskCritical
	default:
		return models.PersistenceRiskMedium
	}
}

// Platform-specific verification helper
func isPlatformSupported() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows" || runtime.GOOS == "linux"
}
