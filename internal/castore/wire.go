package castore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Observation is what a live handshake revealed about who signed it.
type Observation struct {
	Target string `json:"target"`
	Addr   string `json:"addr"`

	// Chain is the certificate chain exactly as the server presented it.
	Chain []Cert `json:"chain"`

	// Root is the CA the chain actually verified against, when it verified.
	Root *Cert `json:"root,omitempty"`

	// Inspecting is the answer to the real question: was this connection
	// signed by a locally installed CA rather than a public one?
	Inspecting bool   `json:"inspecting"`
	Verified   bool   `json:"verified"`
	VerifyErr  string `json:"verify_error,omitempty"`
}

// Leaf returns the server certificate.
func (o Observation) Leaf() *Cert {
	if len(o.Chain) == 0 {
		return nil
	}
	return &o.Chain[0]
}

// ObserveChain handshakes with target and reports which CA signed the
// connection.
//
// Detection cannot rely on verification failing: an inspection proxy installs
// its root into your keychain precisely so that verification succeeds. So the
// chain is verified, and then the root it verified against is checked for
// membership in Apple's shipped root store. A root that is trusted locally but
// is not one Apple ships is, by definition, something installed on this
// machine to sign traffic.
func ObserveChain(ctx context.Context, target string, timeout time.Duration, localCAs []Cert, appleFPs map[string]bool) (*Observation, error) {
	host, addr, err := splitTarget(target)
	if err != nil {
		return nil, err
	}
	obs := &Observation{Target: target, Addr: addr}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // the chain is inspected, not trusted
	})
	if err != nil {
		return obs, fmt.Errorf("handshake with %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return obs, fmt.Errorf("%s presented no certificate", addr)
	}
	for _, c := range state.PeerCertificates {
		obs.Chain = append(obs.Chain, describe(c, SourceWire))
	}

	// Roots: the system pool, plus every CA found in the local keychains. The
	// explicit additions matter because a root installed in the login keychain
	// may not surface through SystemCertPool.
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	sourceOf := map[string]Cert{}
	for _, c := range localCAs {
		if !c.IsCA {
			continue
		}
		roots.AddCert(c.X509)
		sourceOf[c.Fingerprint] = c
	}

	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}

	leaf := state.PeerCertificates[0]
	chains, verifyErr := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	if verifyErr != nil {
		obs.VerifyErr = verifyErr.Error()
		return obs, nil
	}
	obs.Verified = true

	// The last certificate of a verified chain is the root it anchored to.
	chain := chains[0]
	rootCert := chain[len(chain)-1]
	root := describe(rootCert, SourceWire)
	root.InAppleRoots = appleFPs[root.Fingerprint]
	if known, ok := sourceOf[root.Fingerprint]; ok {
		root.Source = known.Source
	}
	if !root.InAppleRoots {
		obs.Inspecting = true
		root.Reason = "signed this connection but is not an Apple-shipped root"
	}
	obs.Root = &root
	return obs, nil
}

// splitTarget accepts a URL, a host, or a host:port and returns the SNI name
// and the dial address.
func splitTarget(target string) (host, addr string, err error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", "", fmt.Errorf("no target given")
	}
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("bad target %q: %w", target, err)
	}
	if u.Hostname() == "" {
		return "", "", fmt.Errorf("bad target %q: no host", target)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return u.Hostname(), net.JoinHostPort(u.Hostname(), port), nil
}
