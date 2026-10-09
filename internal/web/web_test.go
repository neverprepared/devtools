package web

import (
	"net"
	"net/http"
	"testing"

	"github.com/neverprepared/devtools/internal/check"
)

func TestNormalizeURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"example.com", "https://example.com/"},
		{"example.com:8443", "https://example.com:8443/"},
		{"http://example.com", "http://example.com/"},
		{"https://example.com/health", "https://example.com/health"},
		{"  example.com  ", "https://example.com/"},
		{"https://1.2.3.4:9000/x?y=1", "https://1.2.3.4:9000/x?y=1"},
	} {
		u, err := NormalizeURL(tc.in)
		if err != nil {
			t.Fatalf("NormalizeURL(%q): %v", tc.in, err)
		}
		if u.String() != tc.want {
			t.Errorf("NormalizeURL(%q) = %q, want %q", tc.in, u.String(), tc.want)
		}
	}
	for _, bad := range []string{"", "   ", "ftp://example.com", "https://"} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) should fail", bad)
		}
	}
}

func TestScope(t *testing.T) {
	for _, tc := range []struct{ ip, want string }{
		{"10.0.0.1", "private"},
		{"172.16.5.4", "private"},
		{"192.168.1.1", "private"},
		{"172.32.0.1", "public"}, // just outside 172.16/12
		{"8.8.8.8", "public"},
		{"127.0.0.1", "loopback"},
		{"169.254.1.1", "link-local"},
		{"100.64.0.1", "cgnat"},
		{"100.128.0.1", "public"}, // just outside 100.64/10
		{"fd00::1", "private"},
		{"2606:4700::1", "public"},
		{"::1", "loopback"},
	} {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := Scope(ip); got != tc.want {
			t.Errorf("Scope(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestDNSInfoClassification(t *testing.T) {
	priv := DNSInfo{Addrs: []AddrInfo{{IP: "10.0.0.1", Scope: "private"}, {IP: "10.0.0.2", Scope: "private"}}}
	if !priv.Private() || priv.Mixed() {
		t.Error("an all-private answer should be Private and not Mixed")
	}

	mixed := DNSInfo{Addrs: []AddrInfo{{IP: "10.0.0.1", Scope: "private"}, {IP: "8.8.8.8", Scope: "public"}}}
	if mixed.Private() || !mixed.Mixed() {
		t.Error("a split answer should be Mixed and not Private")
	}

	pub := DNSInfo{Addrs: []AddrInfo{{IP: "8.8.8.8", Scope: "public"}}}
	if pub.Private() || pub.Mixed() {
		t.Error("an all-public answer should be neither")
	}

	var empty DNSInfo
	if empty.Private() {
		t.Error("an empty answer is not private")
	}

	if got := mixed.IPs(); len(got) != 2 || got[0] != "10.0.0.1" {
		t.Errorf("IPs() = %v", got)
	}
}

func TestResolverNaming(t *testing.T) {
	_, name, err := Resolver("")
	if err != nil {
		t.Fatal(err)
	}
	if name[:6] != "system" {
		t.Errorf("default resolver name = %q, want a system prefix", name)
	}

	_, name, err = Resolver("10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if name != "10.0.0.2:53" {
		t.Errorf("resolver name = %q, want the port appended", name)
	}

	_, name, err = Resolver("10.0.0.2:5353")
	if err != nil {
		t.Fatal(err)
	}
	if name != "10.0.0.2:5353" {
		t.Errorf("resolver name = %q, want the given port kept", name)
	}
}

func TestParseTLSVersion(t *testing.T) {
	for _, ok := range []string{"", "1.0", "1.1", "1.2", "1.3", "TLS1.2", "13"} {
		if _, err := ParseTLSVersion(ok); err != nil {
			t.Errorf("ParseTLSVersion(%q) = %v", ok, err)
		}
	}
	if _, err := ParseTLSVersion("2.0"); err == nil {
		t.Error("ParseTLSVersion(\"2.0\") should fail")
	}
}

func TestCommonName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"CN=example.com,O=Example Inc", "example.com"},
		{"O=Example Inc,CN=api.example.com", "api.example.com"},
		{"O=No CN Here", "O=No CN Here"},
	} {
		if got := CommonName(tc.in); got != tc.want {
			t.Errorf("CommonName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSANSummary(t *testing.T) {
	none := TLSInfo{}
	if got := none.SANSummary(3); got != "no SANs" {
		t.Errorf("SANSummary = %q", got)
	}
	few := TLSInfo{DNSNames: []string{"a", "b"}}
	if got := few.SANSummary(3); got != "a, b" {
		t.Errorf("SANSummary = %q", got)
	}
	many := TLSInfo{DNSNames: []string{"a", "b", "c", "d", "e"}}
	if got := many.SANSummary(2); got != "a, b, +3 more" {
		t.Errorf("SANSummary = %q", got)
	}
}

func TestTLSInfoValid(t *testing.T) {
	if (TLSInfo{ChainTrusted: true, NameMatches: true}).Valid() != true {
		t.Error("trusted + matching should be valid")
	}
	for _, bad := range []TLSInfo{
		{ChainTrusted: true},
		{NameMatches: true},
		{},
	} {
		if bad.Valid() {
			t.Errorf("%+v should not be valid", bad)
		}
	}
}

func TestSecurityHeaderReview(t *testing.T) {
	full := http.Header{}
	full.Set("Strict-Transport-Security", "max-age=63072000")
	full.Set("Content-Security-Policy", "default-src 'self'")
	full.Set("X-Content-Type-Options", "nosniff")
	full.Set("Referrer-Policy", "no-referrer")
	full.Set("X-Frame-Options", "DENY")
	if got := SecurityHeaderReview(full, true); got.Status != check.Pass {
		t.Errorf("a complete header set should pass: %s", got.Detail)
	}

	// CSP frame-ancestors stands in for X-Frame-Options.
	noXFO := full.Clone()
	noXFO.Del("X-Frame-Options")
	noXFO.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	if got := SecurityHeaderReview(noXFO, true); got.Status != check.Pass {
		t.Errorf("frame-ancestors should satisfy frame protection: %s", got.Detail)
	}

	// HSTS is meaningless over plain HTTP, so its absence is not flagged.
	noHSTS := full.Clone()
	noHSTS.Del("Strict-Transport-Security")
	if got := SecurityHeaderReview(noHSTS, false); got.Status != check.Pass {
		t.Errorf("HSTS should not be required over http: %s", got.Detail)
	}
	if got := SecurityHeaderReview(noHSTS, true); got.Status != check.Warn {
		t.Error("HSTS should be required over https")
	}

	if got := SecurityHeaderReview(http.Header{}, true); got.Status != check.Warn {
		t.Error("an empty header set should warn")
	}
}
