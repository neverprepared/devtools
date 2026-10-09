package castore

import (
	"crypto/x509"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestFingerprintFormat(t *testing.T) {
	ca, _ := mintCA(t, "fp test", time.Now().Add(time.Hour))
	fp := Fingerprint(ca)

	if len(fp) != 95 { // 32 bytes -> 64 hex chars + 31 colons
		t.Errorf("fingerprint is %d chars, want 95: %s", len(fp), fp)
	}
	if fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint should be upper case: %s", fp)
	}
	if strings.Count(fp, ":") != 31 {
		t.Errorf("want 31 separators: %s", fp)
	}
	// Same input, same fingerprint; different input, different fingerprint.
	if Fingerprint(ca) != fp {
		t.Error("fingerprint is not stable")
	}
	other, _ := mintCA(t, "other", time.Now().Add(time.Hour))
	if Fingerprint(other) == fp {
		t.Error("different certificates share a fingerprint")
	}
}

func TestDetectVendor(t *testing.T) {
	for _, tc := range []struct{ cn, want string }{
		{"caadmin.netskope.com", "Netskope"},
		{"Zscaler Root CA", "Zscaler"},
		{"zscaler intermediate", "Zscaler"},
		{"Palo Alto Networks Inc", "Palo Alto"},
		{"Blue Coat ProxySG", "Blue Coat / Symantec"},
		{"bluecoat appliance", "Blue Coat / Symantec"},
		{"Forcepoint Cloud CA", "Forcepoint / Websense"},
		{"FortiGate CA", "Fortinet"},
		{"McAfee Web Gateway", "McAfee / Skyhigh"},
		{"Cisco Umbrella Root CA", "Cisco Umbrella"},
		{"mitmproxy", "mitmproxy"},
		{"PortSwigger CA", "Burp Suite"},
		{"DO_NOT_TRUST_FiddlerRoot", "Fiddler"},
		{"DigiCert Global Root CA", ""},
		{"Example Corp Internal Root", ""},
	} {
		ca, _ := mintCA(t, tc.cn, time.Now().Add(time.Hour))
		if got := DetectVendor(ca); got != tc.want {
			t.Errorf("DetectVendor(%q) = %q, want %q", tc.cn, got, tc.want)
		}
	}
	if len(VendorNames()) < 20 {
		t.Errorf("only %d vendors known", len(VendorNames()))
	}
}

func TestParsePEM(t *testing.T) {
	a, _ := mintCA(t, "cert a", time.Now().Add(time.Hour))
	b, _ := mintCA(t, "cert b", time.Now().Add(time.Hour))

	var sb strings.Builder
	sb.WriteString("# a leading comment, as devtools writes\n")
	sb.Write(describe(a, SourceFile).PEM())
	// A non-certificate block has to be skipped, not fatal.
	sb.WriteString("-----BEGIN RSA PRIVATE KEY-----\nbm90IGEgY2VydA==\n-----END RSA PRIVATE KEY-----\n")
	sb.WriteString("# another comment\n")
	sb.Write(describe(b, SourceFile).PEM())
	// A CERTIFICATE block holding garbage must also be skipped, so one bad
	// keychain entry does not cost the whole bundle.
	sb.WriteString("-----BEGIN CERTIFICATE-----\nZ2FyYmFnZQ==\n-----END CERTIFICATE-----\n")

	got := ParsePEM([]byte(sb.String()), SourceLogin)
	if len(got) != 2 {
		t.Fatalf("want 2 certificates, got %d", len(got))
	}
	if got[0].CommonName != "cert a" || got[1].CommonName != "cert b" {
		t.Errorf("parsed the wrong certificates: %q, %q", got[0].CommonName, got[1].CommonName)
	}
	if got[0].Source != SourceLogin {
		t.Errorf("source = %q", got[0].Source)
	}
	if ParsePEM([]byte("not pem at all"), SourceFile) != nil {
		t.Error("non-PEM input should parse to nothing")
	}
}

func TestDescribe(t *testing.T) {
	ca, key := mintCA(t, "describe-ca", time.Now().Add(72*time.Hour))
	leaf, _ := mintLeaf(t, "leaf.example", ca, key)

	dca := describe(ca, SourceLogin)
	if !dca.IsCA || !dca.SelfSigned {
		t.Errorf("CA classification wrong: %+v", dca)
	}
	if dca.DaysLeft != 2 { // 72h, minus the backdated hour
		t.Errorf("DaysLeft = %d, want 2", dca.DaysLeft)
	}
	if dca.Expired() {
		t.Error("a live certificate should not be expired")
	}

	dleaf := describe(leaf, SourceWire)
	if dleaf.IsCA || dleaf.SelfSigned {
		t.Errorf("leaf classification wrong: %+v", dleaf)
	}
	if dleaf.CommonName != "leaf.example" {
		t.Errorf("CommonName = %q", dleaf.CommonName)
	}

	expired, _ := mintCA(t, "old", time.Now().Add(-time.Minute))
	if !describe(expired, SourceLogin).Expired() {
		t.Error("an expired certificate should report Expired")
	}
}

func TestSelectPolicy(t *testing.T) {
	vendor, _ := mintCA(t, "caadmin.netskope.com", time.Now().Add(1000*time.Hour))
	internal, _ := mintCA(t, "Example Corp Internal Root", time.Now().Add(1000*time.Hour))
	publicRoot, _ := mintCA(t, "Public Root CA", time.Now().Add(1000*time.Hour))
	expired, _ := mintCA(t, "Zscaler Old Root", time.Now().Add(-time.Hour))
	notCA := mintLeafOnly(t, "leaf.example")

	all := []Cert{
		describe(vendor, SourceLogin),
		describe(internal, SourceSystem),
		describe(publicRoot, SourceLogin),
		describe(expired, SourceLogin),
		describe(notCA, SourceLogin),
	}
	appleFPs := map[string]bool{Fingerprint(publicRoot): true}

	// Default: only recognised vendors.
	got := Select(all, appleFPs, SelectOptions{})
	if len(got) != 1 || got[0].CommonName != "caadmin.netskope.com" {
		t.Fatalf("default selection = %v", names(got))
	}
	if !strings.Contains(got[0].Reason, "Netskope") {
		t.Errorf("reason = %q", got[0].Reason)
	}

	// --include reaches an internal CA no vendor list knows.
	got = Select(all, appleFPs, SelectOptions{
		Include: []*regexp.Regexp{regexp.MustCompile(`(?i)example corp internal`)},
	})
	if len(got) != 2 {
		t.Fatalf("--include selection = %v", names(got))
	}

	// --all-non-apple takes every CA except Apple's own.
	got = Select(all, appleFPs, SelectOptions{AllNonAppleCAs: true})
	if len(got) != 2 { // vendor + internal; expired and non-CA still excluded
		t.Fatalf("--all-non-apple selection = %v", names(got))
	}
	for _, c := range got {
		if c.InAppleRoots {
			t.Error("an Apple root leaked into the selection")
		}
		if !c.IsCA {
			t.Error("a non-CA leaked into the selection")
		}
	}

	// --keep-expired brings back the stale vendor root.
	got = Select(all, appleFPs, SelectOptions{KeepExpired: true})
	if len(got) != 2 {
		t.Fatalf("--keep-expired selection = %v", names(got))
	}

	// With no knowledge of Apple's store, nothing is excluded for being public.
	got = Select(all, nil, SelectOptions{AllNonAppleCAs: true})
	if len(got) != 3 {
		t.Fatalf("nil appleFPs selection = %v", names(got))
	}

	// A wire-observed root is always taken: it signed the live connection.
	wire := describe(internal, SourceWire)
	got = Select([]Cert{wire}, appleFPs, SelectOptions{})
	if len(got) != 1 || !strings.Contains(got[0].Reason, "on the wire") {
		t.Fatalf("wire selection = %v (%+v)", names(got), got)
	}
}

func names(certs []Cert) []string {
	var out []string
	for _, c := range certs {
		out = append(out, c.CommonName)
	}
	return out
}

func TestDedupAndSort(t *testing.T) {
	a, _ := mintCA(t, "zeta", time.Now().Add(time.Hour))
	b, _ := mintCA(t, "alpha", time.Now().Add(time.Hour))
	vendorCA, _ := mintCA(t, "Zscaler Root CA", time.Now().Add(time.Hour))

	certs := []Cert{
		describe(a, SourceLogin),
		describe(b, SourceSystem),
		describe(a, SourceSystem), // duplicate by fingerprint
		describe(vendorCA, SourceLogin),
	}
	deduped := Dedup(certs)
	if len(deduped) != 3 {
		t.Fatalf("Dedup kept %d, want 3", len(deduped))
	}
	// The first occurrence wins, so the login source is preserved.
	for _, c := range deduped {
		if c.CommonName == "zeta" && c.Source != SourceLogin {
			t.Errorf("Dedup kept the wrong copy: %s", c.Source)
		}
	}

	Sort(deduped)
	if deduped[0].CommonName != "Zscaler Root CA" {
		t.Errorf("vendor-identified certificates should sort first, got %v", names(deduped))
	}
	if deduped[1].CommonName != "alpha" || deduped[2].CommonName != "zeta" {
		t.Errorf("the rest should sort by common name, got %v", names(deduped))
	}
}

func TestWritePEMRoundTrips(t *testing.T) {
	a, _ := mintCA(t, "caadmin.netskope.com", time.Now().Add(1000*time.Hour))
	b, _ := mintCA(t, "Zscaler Root CA", time.Now().Add(1000*time.Hour))
	certs := []Cert{describe(a, SourceLogin), describe(b, SourceSystem)}
	certs[0].Reason = "known inspection vendor: Netskope"

	withComments := WritePEM(certs, true)
	text := string(withComments)
	for _, want := range []string{
		"# Generated by devtools ca export",
		"# Subject:",
		"# Fingerprint: SHA256:" + certs[0].Fingerprint,
		"# Selected:    known inspection vendor: Netskope",
		"-----BEGIN CERTIFICATE-----",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// The whole claim of the comment format: parsers still accept it.
	if got := ParsePEM(withComments, SourceFile); len(got) != 2 {
		t.Fatalf("commented bundle round-tripped to %d certificates", len(got))
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(withComments) {
		t.Error("a commented bundle must still load as a certificate pool")
	}

	bare := WritePEM(certs, false)
	if strings.Contains(string(bare), "#") {
		t.Error("--no-comments output should carry no comments")
	}
	if got := ParsePEM(bare, SourceFile); len(got) != 2 {
		t.Errorf("bare bundle round-tripped to %d certificates", len(got))
	}
}

func TestVerifyBundle(t *testing.T) {
	dir := t.TempDir()
	a, _ := mintCA(t, "bundle test", time.Now().Add(time.Hour))

	good := dir + "/good.pem"
	if err := WriteFile(good, WritePEM([]Cert{describe(a, SourceLogin)}, true)); err != nil {
		t.Fatal(err)
	}
	n, err := VerifyBundle(good)
	if err != nil || n != 1 {
		t.Errorf("VerifyBundle(good) = %d, %v", n, err)
	}

	empty := dir + "/empty.pem"
	if err := WriteFile(empty, []byte("# nothing here\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(empty); err == nil {
		t.Error("an empty bundle should not verify")
	}

	if _, err := VerifyBundle(dir + "/missing.pem"); err == nil {
		t.Error("a missing bundle should not verify")
	}
}

func TestWriteFileCreatesParents(t *testing.T) {
	path := t.TempDir() + "/nested/deeper/bundle.pem"
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(path); err == nil {
		t.Error("the written content was not a bundle, so it should not verify")
	}
}
