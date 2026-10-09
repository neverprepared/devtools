// Package castore reads CA certificates out of the macOS keychains and off the
// wire, identifies the ones belonging to a TLS-inspecting proxy, and writes
// them back out as a PEM bundle.
//
// The problem it solves: behind corporate TLS inspection, every tool with its
// own trust store (pip, npm, go, aws, git, cargo) fails with "self-signed
// certificate in certificate chain" because the inspection CA is in the system
// keychain and nowhere else. Those tools want a PEM file.
package castore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/neverprepared/devtools/internal/osx"
)

// Keychain paths. The login keychain is where user-mode agents (Netskope,
// mitmproxy) install their root; the system keychain is where MDM puts one.
const (
	LoginKeychain  = "login.keychain-db"
	SystemKeychain = "/Library/Keychains/System.keychain"
	AppleRoots     = "/System/Library/Keychains/SystemRootCertificates.keychain"
)

// Source labels where a certificate came from.
type Source string

const (
	SourceLogin  Source = "login"
	SourceSystem Source = "system"
	SourceApple  Source = "apple-roots"
	SourceWire   Source = "wire"
	SourceFile   Source = "file"
)

// Cert is one certificate plus the classification that decides whether it
// belongs in an inspection bundle.
type Cert struct {
	Fingerprint  string `json:"fingerprint"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	CommonName   string `json:"common_name"`
	Source       Source `json:"source"`
	Vendor       string `json:"vendor,omitempty"`
	IsCA         bool   `json:"is_ca"`
	SelfSigned   bool   `json:"self_signed"`
	InAppleRoots bool   `json:"in_apple_roots"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	DaysLeft     int    `json:"days_left"`
	Reason       string `json:"reason,omitempty"`

	X509 *x509.Certificate `json:"-"`
}

// Expired reports whether the certificate is outside its validity window.
func (c Cert) Expired() bool {
	now := time.Now()
	return now.Before(c.X509.NotBefore) || now.After(c.X509.NotAfter)
}

// PEM re-encodes the certificate.
func (c Cert) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.X509.Raw})
}

// vendors are the TLS-inspection products whose roots show up on corporate
// laptops, matched case-insensitively against the certificate subject. The
// local interception tools are included because a forgotten mitmproxy or Burp
// root in your trust store is worth seeing too.
var vendors = []struct {
	Name    string
	Pattern *regexp.Regexp
}{
	{"Netskope", regexp.MustCompile(`(?i)netskope`)},
	{"Zscaler", regexp.MustCompile(`(?i)zscaler`)},
	{"Palo Alto", regexp.MustCompile(`(?i)palo\s*alto|pan-os|panorama`)},
	{"Blue Coat / Symantec", regexp.MustCompile(`(?i)blue\s*coat|bluecoat|proxysg`)},
	{"Forcepoint / Websense", regexp.MustCompile(`(?i)forcepoint|websense`)},
	{"Fortinet", regexp.MustCompile(`(?i)fortinet|fortigate|fortiguard`)},
	{"McAfee / Skyhigh", regexp.MustCompile(`(?i)mcafee|skyhigh`)},
	{"Cisco Umbrella", regexp.MustCompile(`(?i)umbrella|opendns|cisco.*root`)},
	{"Sophos", regexp.MustCompile(`(?i)sophos`)},
	{"Check Point", regexp.MustCompile(`(?i)check\s*point|checkpoint`)},
	{"Trend Micro", regexp.MustCompile(`(?i)trend\s*micro`)},
	{"Barracuda", regexp.MustCompile(`(?i)barracuda`)},
	{"iboss", regexp.MustCompile(`(?i)\biboss\b`)},
	{"Menlo Security", regexp.MustCompile(`(?i)menlo`)},
	{"Cloudflare Gateway", regexp.MustCompile(`(?i)cloudflare.*(gateway|for teams|warp)`)},
	{"Microsoft Defender for Cloud Apps", regexp.MustCompile(`(?i)defender for cloud apps|mcas`)},
	{"Sangfor", regexp.MustCompile(`(?i)sangfor`)},
	{"Untangle / Arista", regexp.MustCompile(`(?i)untangle`)},
	{"Kaspersky", regexp.MustCompile(`(?i)kaspersky`)},
	{"ESET", regexp.MustCompile(`(?i)\beset\b`)},
	{"Bitdefender", regexp.MustCompile(`(?i)bitdefender`)},
	{"mitmproxy", regexp.MustCompile(`(?i)mitmproxy`)},
	{"Burp Suite", regexp.MustCompile(`(?i)portswigger|burp`)},
	{"Charles Proxy", regexp.MustCompile(`(?i)charles\s*proxy|xk72`)},
	{"Fiddler", regexp.MustCompile(`(?i)fiddler|do_not_trust`)},
	{"Proxyman", regexp.MustCompile(`(?i)proxyman`)},
	{"Squid", regexp.MustCompile(`(?i)squid.*proxy`)},
}

// DetectVendor names the inspection product a certificate belongs to, or "".
func DetectVendor(c *x509.Certificate) string {
	hay := c.Subject.String() + " " + strings.Join(c.Subject.Organization, " ")
	for _, v := range vendors {
		if v.Pattern.MatchString(hay) {
			return v.Name
		}
	}
	return ""
}

// VendorNames lists the products this package recognises.
func VendorNames() []string {
	out := make([]string, 0, len(vendors))
	for _, v := range vendors {
		out = append(out, v.Name)
	}
	return out
}

// Fingerprint is the SHA-256 of the DER encoding, colon-separated, which is
// what openssl and the Keychain Access UI both show.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// describe builds a Cert from a parsed certificate.
func describe(c *x509.Certificate, source Source) Cert {
	cn := c.Subject.CommonName
	if cn == "" && len(c.Subject.Organization) > 0 {
		cn = c.Subject.Organization[0]
	}
	return Cert{
		Fingerprint: Fingerprint(c),
		Subject:     c.Subject.String(),
		Issuer:      c.Issuer.String(),
		CommonName:  cn,
		Source:      source,
		Vendor:      DetectVendor(c),
		IsCA:        c.IsCA,
		SelfSigned:  c.Subject.String() == c.Issuer.String(),
		NotBefore:   c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:    int(time.Until(c.NotAfter).Hours() / 24),
		X509:        c,
	}
}

// ParsePEM parses every certificate in a PEM stream, skipping anything that is
// not a certificate block. Unparseable blocks are skipped rather than fatal: a
// keychain can hold a certificate newer Go cannot read, and one bad entry must
// not cost you the rest of the bundle.
func ParsePEM(data []byte, source Source) []Cert {
	var out []Cert
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, describe(c, source))
	}
}

// LoginKeychainPath resolves the user's login keychain.
func LoginKeychainPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Keychains", LoginKeychain), nil
}

// ReadKeychain exports every certificate from a keychain as PEM.
//
// This shells out to /usr/bin/security because it is the only supported way to
// read the macOS trust stores without cgo. Certificates are public, so this
// never prompts for a password; private keys are never touched.
func ReadKeychain(ctx context.Context, path string, source Source) ([]Cert, error) {
	// Every keychain read funnels through here, so this is the only platform
	// gate the package needs. Without it a Linux build reports the confusing
	// "exec: security: executable file not found" instead of the real reason.
	if !osx.Supported() {
		return nil, &osx.ErrUnsupported{What: "the macOS keychain"}
	}

	cmd := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p", path)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("security find-certificate %s: %w: %s",
			path, err, strings.TrimSpace(errOut.String()))
	}
	return ParsePEM(out.Bytes(), source), nil
}

// AppleRootFingerprints is the set of fingerprints Apple ships, used to tell an
// injected CA apart from a legitimate public root.
func AppleRootFingerprints(ctx context.Context) (map[string]bool, error) {
	certs, err := ReadKeychain(ctx, AppleRoots, SourceApple)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(certs))
	for _, c := range certs {
		set[c.Fingerprint] = true
	}
	return set, nil
}

// Dedup removes repeated certificates, keeping the first occurrence so the
// earliest source in the scan order wins.
func Dedup(certs []Cert) []Cert {
	seen := map[string]bool{}
	var out []Cert
	for _, c := range certs {
		if seen[c.Fingerprint] {
			continue
		}
		seen[c.Fingerprint] = true
		out = append(out, c)
	}
	return out
}

// Sort orders certificates for stable output: vendor-identified first, then by
// common name.
func Sort(certs []Cert) {
	sort.SliceStable(certs, func(i, j int) bool {
		a, b := certs[i], certs[j]
		if (a.Vendor != "") != (b.Vendor != "") {
			return a.Vendor != ""
		}
		if a.CommonName != b.CommonName {
			return a.CommonName < b.CommonName
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// SelectOptions controls which certificates count as inspection CAs.
type SelectOptions struct {
	// Include is extra subject patterns to treat as inspection CAs, for an
	// internal CA no vendor list will ever know about.
	Include []*regexp.Regexp
	// AllNonAppleCAs widens selection to every CA not in Apple's root store.
	AllNonAppleCAs bool
	// KeepExpired retains expired certificates instead of dropping them.
	KeepExpired bool
}

// Select picks the inspection CAs out of a scanned set and records why each one
// was chosen. appleFPs may be nil, in which case nothing is excluded for being
// a public root.
func Select(certs []Cert, appleFPs map[string]bool, o SelectOptions) []Cert {
	var out []Cert
	for _, c := range certs {
		c.InAppleRoots = appleFPs[c.Fingerprint]

		// A leaf or intermediate is no use in a trust bundle.
		if !c.IsCA {
			continue
		}
		// Apple's own roots are already trusted everywhere; shipping them as
		// "inspection CAs" would be wrong.
		if c.InAppleRoots {
			continue
		}
		if !o.KeepExpired && c.Expired() {
			continue
		}

		switch {
		case c.Vendor != "":
			c.Reason = "known inspection vendor: " + c.Vendor
		case matchesAny(o.Include, c.Subject):
			c.Reason = "matched --include"
		case c.Source == SourceWire:
			c.Reason = "presented on the wire by a TLS-inspecting proxy"
		case o.AllNonAppleCAs:
			c.Reason = "CA not in Apple's root store"
		default:
			continue
		}
		out = append(out, c)
	}
	return Dedup(out)
}

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// WritePEM writes certificates as a PEM bundle. With comments, each entry is
// preceded by a human-readable header; PEM parsers ignore text outside the
// BEGIN/END markers, but --no-comments exists for the rare strict one.
func WritePEM(certs []Cert, comments bool) []byte {
	var b bytes.Buffer
	if comments {
		fmt.Fprintf(&b, "# Generated by devtools ca export on %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(&b, "# %d certificate(s)\n\n", len(certs))
	}
	for _, c := range certs {
		if comments {
			fmt.Fprintf(&b, "# Subject:     %s\n", c.Subject)
			fmt.Fprintf(&b, "# Issuer:      %s\n", c.Issuer)
			fmt.Fprintf(&b, "# Fingerprint: SHA256:%s\n", c.Fingerprint)
			fmt.Fprintf(&b, "# Validity:    %s to %s\n", c.NotBefore, c.NotAfter)
			fmt.Fprintf(&b, "# Source:      %s\n", c.Source)
			if c.Reason != "" {
				fmt.Fprintf(&b, "# Selected:    %s\n", c.Reason)
			}
		}
		b.Write(c.PEM())
		if comments {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// DefaultDir is where exported bundles live by default.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "devtools", "ca"), nil
}

// WriteFile writes a bundle to disk, creating parent directories.
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// VerifyBundle re-reads a written bundle and counts what parses, so a broken
// file is caught here rather than by pip three days later.
func VerifyBundle(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	certs := ParsePEM(data, SourceFile)
	if len(certs) == 0 {
		return 0, fmt.Errorf("%s contains no parseable certificates", path)
	}
	// A bundle has to load into a pool for any tool to accept it.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return len(certs), fmt.Errorf("%s did not load as a certificate pool", path)
	}
	return len(certs), nil
}
