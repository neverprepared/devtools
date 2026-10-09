package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixtureCA writes a self-signed CA PEM named cn and returns its path, so the
// ca commands can be exercised without depending on this machine's keychain.
func fixtureCA(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{cn}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10000 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// keychainless is the flag pair that keeps a test off this machine's keychains.
var keychainless = []string{"--no-login-keychain", "--no-system-keychain"}

func TestCAExportFromFileToStdout(t *testing.T) {
	fixture := fixtureCA(t, "caadmin.netskope.com")

	args := append([]string{"ca", "export", "--stdout", "--from-file", fixture}, keychainless...)
	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	if !strings.Contains(out, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("no certificate in output:\n%s", out)
	}
	if !strings.Contains(out, "known inspection vendor: Netskope") {
		t.Errorf("the selection reason should be recorded in the bundle:\n%s", out)
	}
	// The emitted bundle has to load as a pool, comments and all.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(out)) {
		t.Error("the exported bundle does not load as a certificate pool")
	}
}

func TestCAExportNoCommentsIsBarePEM(t *testing.T) {
	fixture := fixtureCA(t, "Zscaler Root CA")

	args := append([]string{"ca", "export", "--stdout", "--no-comments", "--from-file", fixture}, keychainless...)
	out, err := run(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "#") {
		t.Errorf("--no-comments should emit bare PEM:\n%s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "-----BEGIN CERTIFICATE-----") {
		t.Errorf("output should start with the PEM header:\n%s", out)
	}
}

func TestCAExportWritesFileAndVerifies(t *testing.T) {
	fixture := fixtureCA(t, "caadmin.netskope.com")
	dest := filepath.Join(t.TempDir(), "sub", "mitm.pem")

	args := append([]string{"ca", "export", "-o", dest, "--from-file", fixture}, keychainless...)
	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "wrote "+dest) {
		t.Errorf("output should name the file:\n%s", out)
	}
	if !strings.Contains(out, "NODE_EXTRA_CA_CERTS") {
		t.Errorf("a default export should explain the two bundle shapes:\n%s", out)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Error("the written file does not load as a certificate pool")
	}
}

func TestCAExportUnknownCANeedsInclude(t *testing.T) {
	fixture := fixtureCA(t, "Example Corp Internal Root")

	// An internal CA no vendor list knows is not exported by default.
	args := append([]string{"ca", "export", "--stdout", "--from-file", fixture}, keychainless...)
	out, err := run(t, args...)
	if err == nil {
		t.Fatalf("an unrecognised CA should not be exported by default:\n%s", out)
	}
	if !strings.Contains(err.Error(), "--include") {
		t.Errorf("the error should point at --include: %v", err)
	}

	// --include selects it.
	args = append([]string{"ca", "export", "--stdout", "--from-file", fixture, "--include", "Example Corp Internal"}, keychainless...)
	out, err = run(t, args...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "matched --include") {
		t.Errorf("the reason should record the match:\n%s", out)
	}

	// So does --all-non-apple.
	args = append([]string{"ca", "export", "--stdout", "--all-non-apple", "--from-file", fixture}, keychainless...)
	if _, err := run(t, args...); err != nil {
		t.Errorf("--all-non-apple should select it: %v", err)
	}
}

func TestCAExportRejectsBadInclude(t *testing.T) {
	args := append([]string{"ca", "export", "--stdout", "--include", "([“"}, keychainless...)
	if _, err := run(t, args...); err == nil {
		t.Error("a bad --include regexp should be rejected")
	}
}

func TestCAExportDryRun(t *testing.T) {
	fixture := fixtureCA(t, "caadmin.netskope.com")
	dest := filepath.Join(t.TempDir(), "should-not-exist.pem")

	args := append([]string{"ca", "export", "-n", "-o", dest, "--from-file", fixture}, keychainless...)
	out, err := run(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "dry-run: would write") {
		t.Errorf("output:\n%s", out)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("--dry-run must not write the file")
	}
}

func TestCAListJSON(t *testing.T) {
	fixture := fixtureCA(t, "caadmin.netskope.com")

	args := append([]string{"ca", "list", "--json", "--from-file", fixture}, keychainless...)
	out, err := run(t, args...)
	// A found inspection CA is a warning, which is not an error without --strict.
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var rep map[string]any
	if jsonErr := json.Unmarshal([]byte(out), &rep); jsonErr != nil {
		t.Fatalf("--json did not produce JSON: %v\n%s", jsonErr, out)
	}
	if rep["command"] != "ca list" {
		t.Errorf("command = %v", rep["command"])
	}
	certs, ok := rep["data"].(map[string]any)["certificates"].([]any)
	if !ok || len(certs) != 1 {
		t.Fatalf("certificates = %v", rep["data"])
	}
	first := certs[0].(map[string]any)
	if first["common_name"] != "caadmin.netskope.com" {
		t.Errorf("common_name = %v", first["common_name"])
	}
	if first["vendor"] != "Netskope" {
		t.Errorf("vendor = %v", first["vendor"])
	}
}

func TestCAListEmpty(t *testing.T) {
	args := append([]string{"ca", "list"}, keychainless...)
	out, err := run(t, args...)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "no TLS-inspection CAs found") {
		t.Errorf("output:\n%s", out)
	}
	if !strings.Contains(out, "devtools ca detect") {
		t.Errorf("an empty result should suggest detect:\n%s", out)
	}
}

func TestCAEnvRoutesVariablesCorrectly(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca-bundle.pem")
	mitm := filepath.Join(dir, "mitm-ca.pem")
	for _, p := range []string{bundle, mitm} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	out, err := run(t, "ca", "env", "--bundle", bundle, "--mitm", mitm)
	if err != nil {
		t.Fatal(err)
	}

	// The distinction that matters: variables that REPLACE a trust store get
	// the full bundle, and Node, which ADDS, gets the inspection-only file.
	for _, name := range []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "CARGO_HTTP_CAINFO"} {
		want := "export " + name + "=\"" + bundle + "\""
		if !strings.Contains(out, want) {
			t.Errorf("%s should get the full bundle:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "export NODE_EXTRA_CA_CERTS=\""+mitm+"\"") {
		t.Errorf("NODE_EXTRA_CA_CERTS should get the inspection-only file:\n%s", out)
	}
	if strings.Contains(out, "# missing:") {
		t.Errorf("both files exist, so nothing should be reported missing:\n%s", out)
	}
	if !strings.Contains(out, "keytool") {
		t.Errorf("Java needs a keystore and the output should say so:\n%s", out)
	}
}

func TestCAEnvReportsMissingBundles(t *testing.T) {
	dir := t.TempDir()
	out, err := run(t, "ca", "env",
		"--bundle", filepath.Join(dir, "nope-bundle.pem"),
		"--mitm", filepath.Join(dir, "nope-mitm.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, "# missing:") != 2 {
		t.Errorf("both missing files should be reported:\n%s", out)
	}
	if !strings.Contains(out, "devtools ca export --full-bundle") {
		t.Errorf("the missing full bundle should name the right command:\n%s", out)
	}
}
