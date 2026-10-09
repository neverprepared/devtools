package web

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

// TLSInfo is what the handshake told us about the server's certificate.
type TLSInfo struct {
	Version     string   `json:"version"`
	CipherSuite string   `json:"cipher_suite"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	DNSNames    []string `json:"dns_names,omitempty"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	DaysLeft    int      `json:"days_left"`
	ChainLength int      `json:"chain_length"`
	SelfSigned  bool     `json:"self_signed"`

	// Verification is split so a report can say which half failed: a chain the
	// system does not trust is a different problem from a cert for the wrong name.
	ChainTrusted  bool    `json:"chain_trusted"`
	ChainError    string  `json:"chain_error,omitempty"`
	NameMatches   bool    `json:"name_matches"`
	NameError     string  `json:"name_error,omitempty"`
	ElapsedMS     float64 `json:"elapsed_ms"`
	HandshakeHost string  `json:"handshake_host"`
}

// Valid reports whether the certificate would satisfy a normal client.
func (t TLSInfo) Valid() bool { return t.ChainTrusted && t.NameMatches }

// ProbeTLS handshakes with addr while presenting serverName as SNI, then
// inspects and verifies the certificate itself. Verification is deliberately
// skipped during the handshake so that a bad certificate can still be
// described rather than collapsing into one opaque error.
func ProbeTLS(ctx context.Context, addr, serverName string, minVersion uint16) (TLSInfo, error) {
	info := TLSInfo{HandshakeHost: serverName}

	dialer := &net.Dialer{}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // verified manually below
		MinVersion:         minVersion,
	})
	info.ElapsedMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		return info, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.Version = tls.VersionName(state.Version)
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	info.ChainLength = len(state.PeerCertificates)
	if len(state.PeerCertificates) == 0 {
		return info, fmt.Errorf("server presented no certificate")
	}

	leaf := state.PeerCertificates[0]
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	info.DNSNames = leaf.DNSNames
	info.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	info.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	info.DaysLeft = int(math.Floor(time.Until(leaf.NotAfter).Hours() / 24))
	info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()

	// Chain trust, ignoring the hostname.
	roots, _ := x509.SystemCertPool()
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		info.ChainError = err.Error()
	} else {
		info.ChainTrusted = true
	}

	// Hostname, ignoring the chain.
	if err := leaf.VerifyHostname(serverName); err != nil {
		info.NameError = err.Error()
	} else {
		info.NameMatches = true
	}
	return info, nil
}

// SANSummary renders the SAN list compactly for a one-line report.
func (t TLSInfo) SANSummary(max int) string {
	if len(t.DNSNames) == 0 {
		return "no SANs"
	}
	if len(t.DNSNames) <= max {
		return strings.Join(t.DNSNames, ", ")
	}
	return fmt.Sprintf("%s, +%d more", strings.Join(t.DNSNames[:max], ", "), len(t.DNSNames)-max)
}

// CommonName pulls the CN out of a subject string for terse output.
func CommonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	return subject
}

// ParseTLSVersion maps a friendly name to a tls constant.
func ParseTLSVersion(s string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "default":
		return 0, nil
	case "1.0", "tls1.0", "10":
		return tls.VersionTLS10, nil
	case "1.1", "tls1.1", "11":
		return tls.VersionTLS11, nil
	case "1.2", "tls1.2", "12":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3", "13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unknown TLS version %q (want 1.0, 1.1, 1.2 or 1.3)", s)
	}
}
