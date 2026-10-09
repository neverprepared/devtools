package castore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// inspectedServer stands up a TLS server whose certificate is signed by a CA
// of our making, which is exactly the shape of an intercepted connection.
func inspectedServer(t *testing.T, caCN string) (*httptest.Server, Cert) {
	t.Helper()
	ca, caKey := mintCA(t, caCN, time.Now().Add(1000*time.Hour))
	leaf, leafKey := mintLeaf(t, "intercepted.example", ca, caKey)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.Raw, ca.Raw}, // server sends leaf + the signing CA
		PrivateKey:  leafKey,
	}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, describe(ca, SourceLogin)
}

func TestObserveChainDetectsInspection(t *testing.T) {
	srv, caCert := inspectedServer(t, "caadmin.netskope.com")

	// The CA is installed locally (so verification succeeds) but is not one
	// Apple ships. That combination is the signature of TLS inspection.
	local := []Cert{caCert}
	appleFPs := map[string]bool{} // our CA is deliberately absent

	obs, err := ObserveChain(context.Background(), srv.URL, 5*time.Second, local, appleFPs)
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Verified {
		t.Fatalf("chain should verify against the locally installed CA: %s", obs.VerifyErr)
	}
	if !obs.Inspecting {
		t.Fatal("a locally installed, non-Apple root means inspection")
	}
	if obs.Root == nil {
		t.Fatal("the verifying root should be reported")
	}
	if obs.Root.CommonName != "caadmin.netskope.com" {
		t.Errorf("root CN = %q", obs.Root.CommonName)
	}
	if obs.Root.Vendor != "Netskope" {
		t.Errorf("root vendor = %q, want Netskope", obs.Root.Vendor)
	}
	if obs.Root.Source != SourceLogin {
		t.Errorf("root source = %q, want the keychain it was found in", obs.Root.Source)
	}
	if !strings.Contains(obs.Root.Reason, "not an Apple-shipped root") {
		t.Errorf("root reason = %q", obs.Root.Reason)
	}
	if leaf := obs.Leaf(); leaf == nil || leaf.CommonName != "intercepted.example" {
		t.Errorf("leaf = %+v", leaf)
	}
	if len(obs.Chain) != 2 {
		t.Errorf("chain length = %d, want the leaf and its CA", len(obs.Chain))
	}

	// The observed root feeds straight into an export.
	selected := Select([]Cert{*obs.Root}, appleFPs, SelectOptions{})
	if len(selected) != 1 {
		t.Error("the observed root should be selectable for export")
	}
}

func TestObserveChainNoInspectionWhenRootIsApples(t *testing.T) {
	srv, caCert := inspectedServer(t, "Some Public Root CA")

	// Same setup, except this root is one Apple ships. Nothing is intercepting.
	local := []Cert{caCert}
	appleFPs := map[string]bool{caCert.Fingerprint: true}

	obs, err := ObserveChain(context.Background(), srv.URL, 5*time.Second, local, appleFPs)
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Verified {
		t.Fatalf("chain should verify: %s", obs.VerifyErr)
	}
	if obs.Inspecting {
		t.Error("a chain anchored to an Apple-shipped root is not inspection")
	}
	if obs.Root == nil || !obs.Root.InAppleRoots {
		t.Errorf("root should be marked as an Apple root: %+v", obs.Root)
	}
}

func TestObserveChainUninstalledRoot(t *testing.T) {
	srv, _ := inspectedServer(t, "Unknown Proxy CA")

	// The proxy's root is NOT installed, so verification fails outright. This
	// is the case where every tool is already broken, inspection or not.
	obs, err := ObserveChain(context.Background(), srv.URL, 5*time.Second, nil, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if obs.Verified {
		t.Error("an uninstalled root should not verify")
	}
	if obs.VerifyErr == "" {
		t.Error("the verification error should be reported")
	}
	// The chain is still captured, so the CA can be exported from it.
	if len(obs.Chain) != 2 {
		t.Fatalf("chain length = %d", len(obs.Chain))
	}
	if !obs.Chain[1].IsCA {
		t.Error("the presented CA should be recognisable in the chain")
	}
}

func TestObserveChainRejectsUnreachable(t *testing.T) {
	srv, _ := inspectedServer(t, "whatever")
	url := srv.URL
	srv.Close()

	if _, err := ObserveChain(context.Background(), url, 2*time.Second, nil, nil); err == nil {
		t.Error("an unreachable target should error")
	}
}

func TestObserveChainAcceptsPublicInternet(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		t.Skip("no system pool")
	}
	obs, err := ObserveChain(context.Background(), "example.com", 15*time.Second, nil, nil)
	if err != nil {
		t.Skipf("no outbound network: %v", err)
	}
	if !obs.Verified {
		t.Errorf("a public site should verify: %s", obs.VerifyErr)
	}
	// With a nil Apple set nothing can be confirmed as Apple-shipped, so this
	// reports inspection. That is why the CLI always loads the real set.
	if obs.Root == nil {
		t.Error("a root should be reported")
	}
}

func TestSplitTarget(t *testing.T) {
	for _, tc := range []struct{ in, host, addr string }{
		{"example.com", "example.com", "example.com:443"},
		{"https://example.com", "example.com", "example.com:443"},
		{"https://example.com:8443/path", "example.com", "example.com:8443"},
		{"example.com:9000", "example.com", "example.com:9000"},
		{"  example.com  ", "example.com", "example.com:443"},
	} {
		host, addr, err := splitTarget(tc.in)
		if err != nil {
			t.Fatalf("splitTarget(%q): %v", tc.in, err)
		}
		if host != tc.host || addr != tc.addr {
			t.Errorf("splitTarget(%q) = %q, %q; want %q, %q", tc.in, host, addr, tc.host, tc.addr)
		}
	}
	for _, bad := range []string{"", "   ", "https://"} {
		if _, _, err := splitTarget(bad); err == nil {
			t.Errorf("splitTarget(%q) should fail", bad)
		}
	}
}
