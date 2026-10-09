package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/neverprepared/devtools/internal/check"
)

// step finds a report step by name.
func step(t *testing.T, rep *check.Report, name string) check.Result {
	t.Helper()
	for _, s := range rep.Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no step named %q in %v", name, names(rep))
	return check.Result{}
}

func names(rep *check.Report) []string {
	var out []string
	for _, s := range rep.Steps {
		out = append(out, s.Name)
	}
	return out
}

// hasStepPrefix reports whether any step name starts with prefix, for the
// per-address tcp steps.
func hasStepPrefix(rep *check.Report, prefix string) bool {
	for _, s := range rep.Steps {
		if strings.HasPrefix(s.Name, prefix) {
			return true
		}
	}
	return false
}

func TestRunPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL + "/health"
	o.ExpectStatus, _ = check.ParseStatusMatcher("2xx")
	body, _ := check.ParseBodyExpectation(`"status":"ok"`)
	o.ExpectBody = []check.BodyExpectation{body}
	header, _ := check.ParseHeaderExpectation("cache-control=no-store")
	o.ExpectHeaders = []check.HeaderExpectation{header}

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	if got := step(t, rep, "dns").Status; got != check.Pass {
		t.Errorf("dns = %s", got)
	}
	if got := step(t, rep, "tls").Status; got != check.Skip {
		t.Errorf("tls over plain http should be skipped, got %s", got)
	}
	if got := step(t, rep, "http").Status; got != check.Pass {
		t.Errorf("http = %s", got)
	}
	for _, name := range []string{"expect status", "body", "header cache-control"} {
		if got := step(t, rep, name).Status; got != check.Pass {
			t.Errorf("%s = %s (%s)", name, got, step(t, rep, name).Detail)
		}
	}
	if !hasStepPrefix(rep, "tcp ") {
		t.Errorf("no per-address tcp step in %v", names(rep))
	}
	if rep.Timing == nil || rep.Timing.TotalMS <= 0 {
		t.Error("timing should be populated")
	}
	// The loopback answer should be classified, not called public.
	if dns, ok := rep.Data["dns"].(DNSInfo); !ok || dns.Addrs[0].Scope != "loopback" {
		t.Errorf("dns data = %+v", rep.Data["dns"])
	}
}

func TestRunUntrustedTLSStillReportsResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "served anyway")
	}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	// httptest's certificate is signed by its own throwaway CA.
	tlsStep := step(t, rep, "tls")
	if tlsStep.Status != check.Fail {
		t.Errorf("tls = %s, want fail for an untrusted chain", tlsStep.Status)
	}
	if !strings.Contains(tlsStep.Detail, "not trusted") {
		t.Errorf("tls detail = %q", tlsStep.Detail)
	}
	// The point of the design: the request still happens so the report can
	// show that the server itself is healthy.
	httpStep := step(t, rep, "http")
	if httpStep.Status != check.Pass {
		t.Errorf("http = %s (%s), want the response to be reported anyway", httpStep.Status, httpStep.Detail)
	}
	if rep.Finalize(false) != check.ExitFailed {
		t.Error("an untrusted chain should still fail the overall check")
	}

	// -k downgrades the verification failure to a warning.
	o.Insecure = true
	rep, err = Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := step(t, rep, "tls").Status; got != check.Warn {
		t.Errorf("tls with --insecure = %s, want warn", got)
	}
	if got := rep.Finalize(false); got != check.ExitOK {
		t.Errorf("exit with --insecure = %d, want 0", got)
	}
}

func TestRunCertInfo(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}

	info, ok := rep.Data["tls"].(TLSInfo)
	if !ok {
		t.Fatalf("no tls data: %+v", rep.Data)
	}
	if info.Version == "" || info.CipherSuite == "" {
		t.Errorf("handshake details missing: %+v", info)
	}
	if info.DaysLeft <= 0 {
		t.Errorf("DaysLeft = %d, want a live certificate", info.DaysLeft)
	}
	if info.ChainTrusted {
		t.Error("httptest's throwaway CA should not be trusted")
	}
	if !info.NameMatches {
		t.Errorf("httptest's cert should cover 127.0.0.1: %s", info.NameError)
	}
	if got := step(t, rep, "cert").Status; got != check.Pass {
		t.Errorf("cert = %s, want pass for a long-lived cert", got)
	}
}

func TestRunCertExpiryWarning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL
	// httptest's cert is valid for years, so demand an absurd runway to force
	// the warning branch.
	o.WarnCertDays = 100000

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	cert := step(t, rep, "cert")
	if cert.Status != check.Warn {
		t.Errorf("cert = %s, want warn", cert.Status)
	}
	if !strings.Contains(cert.Detail, "expires in") {
		t.Errorf("cert detail = %q", cert.Detail)
	}
}

func TestRunRedirectChain(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/one":
			http.Redirect(w, r, "/two", http.StatusFound)
		case "/two":
			http.Redirect(w, r, "/three", http.StatusFound)
		default:
			fmt.Fprint(w, "done")
		}
	}))
	defer final.Close()

	o := DefaultOptions()
	o.Target = final.URL + "/one"
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	hops := step(t, rep, "redirects")
	if hops.Status != check.Pass || len(hops.Notes) != 2 {
		t.Errorf("redirects = %s with %d notes, want pass with 2", hops.Status, len(hops.Notes))
	}
	if got := step(t, rep, "http").Status; got != check.Pass {
		t.Errorf("http = %s", got)
	}

	// --no-follow reports the first hop without chasing it.
	o.Follow = false
	rep, err = Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := step(t, rep, "redirects").Status; got != check.Skip {
		t.Errorf("redirects with --no-follow = %s, want skip", got)
	}
	if !strings.Contains(step(t, rep, "http").Detail, "302") {
		t.Errorf("http should report the redirect status: %q", step(t, rep, "http").Detail)
	}
}

func TestRunServerErrorsAndStatusSeverity(t *testing.T) {
	for _, tc := range []struct {
		code int
		want check.Status
	}{
		{200, check.Pass},
		{404, check.Warn}, // a 4xx is the endpoint answering, not the chain breaking
		{503, check.Fail},
	} {
		code := tc.code
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		o := DefaultOptions()
		o.Target = srv.URL
		rep, err := Run(context.Background(), o)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got := step(t, rep, "http").Status; got != tc.want {
			t.Errorf("status %d -> %s, want %s", code, got, tc.want)
		}
	}
}

func TestRunBodyTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 4096)+"NEEDLE")
	}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL
	o.MaxBody = 128
	body, _ := check.ParseBodyExpectation("NEEDLE")
	o.ExpectBody = []check.BodyExpectation{body}

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	res := step(t, rep, "body")
	if res.Status != check.Fail {
		t.Errorf("body = %s, want fail: the needle is past the read limit", res.Status)
	}
	// The report has to say why, or the failure is a lie.
	joined := strings.Join(res.Notes, " ")
	if !strings.Contains(joined, "truncated") {
		t.Errorf("a truncation note is missing: %v", res.Notes)
	}
	if info, ok := rep.Data["http"].(*HTTPInfo); !ok || !info.BodyTrimmed {
		t.Error("BodyTrimmed should be set")
	}
}

func TestRunResolveToBypassesDNS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Host)
	}))
	defer srv.Close()

	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	o := DefaultOptions()
	o.Target = "http://service.invalid:" + port + "/"
	o.ResolveTo = "127.0.0.1"

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := step(t, rep, "dns").Status; got != check.Skip {
		t.Errorf("dns with --resolve-to = %s, want skip", got)
	}
	if got := step(t, rep, "http").Status; got != check.Pass {
		t.Errorf("http = %s (%s)", got, step(t, rep, "http").Detail)
	}
	// Host and SNI stay the original name even though the dial went elsewhere.
	info := rep.Data["http"].(*HTTPInfo)
	if !strings.Contains(string(info.Body()), "service.invalid") {
		t.Errorf("the Host header should survive --resolve-to, got %q", info.Body())
	}

	o.ResolveTo = "not-an-ip"
	if _, err := Run(context.Background(), o); err == nil {
		t.Error("--resolve-to with a non-IP should fail")
	}
}

func TestRunHostHeaderOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Host)
	}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL
	o.HostHeader = "vhost.example.com"
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	info := rep.Data["http"].(*HTTPInfo)
	if string(info.Body()) != "vhost.example.com" {
		t.Errorf("Host header = %q, want the override", info.Body())
	}
}

func TestRunMaxTTFB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
	}))
	defer srv.Close()

	o := DefaultOptions()
	o.Target = srv.URL
	o.MaxTTFB = time.Millisecond
	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := step(t, rep, "expect ttfb").Status; got != check.Fail {
		t.Errorf("expect ttfb = %s, want fail", got)
	}

	o.MaxTTFB = 30 * time.Second
	rep, err = Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := step(t, rep, "expect ttfb").Status; got != check.Pass {
		t.Errorf("expect ttfb = %s, want pass", got)
	}
}

func TestRunUnreachablePort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	o := DefaultOptions()
	o.Target = url
	o.Timeout = 2 * time.Second

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := step(t, rep, "tcp").Status; got != check.Fail {
		t.Errorf("tcp summary = %s, want fail", got)
	}
	// The chain stops at the first broken link rather than reporting noise.
	for _, s := range rep.Steps {
		if s.Name == "http" {
			t.Error("the HTTP phase should not run when nothing is listening")
		}
	}
	if rep.Finalize(false) != check.ExitFailed {
		t.Error("want exit 2")
	}
}

func TestRunBadTarget(t *testing.T) {
	o := DefaultOptions()
	o.Target = "ftp://example.com"
	if _, err := Run(context.Background(), o); err == nil {
		t.Error("an unsupported scheme should be a usage error, not a report")
	}

	o = DefaultOptions()
	o.Target = "https://example.com"
	o.MinTLS = "9.9"
	if _, err := Run(context.Background(), o); err == nil {
		t.Error("a bad --min-tls should be a usage error")
	}
}

func TestRunDNSFailureStopsChain(t *testing.T) {
	o := DefaultOptions()
	o.Target = "https://this-name-does-not-exist.invalid/"
	o.Timeout = 5 * time.Second

	rep, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	dns := step(t, rep, "dns")
	if dns.Status != check.Fail {
		t.Errorf("dns = %s, want fail", dns.Status)
	}
	// The hint is the whole point for private endpoints.
	if !strings.Contains(strings.Join(dns.Notes, " "), "--resolver") {
		t.Errorf("the resolver hint is missing: %v", dns.Notes)
	}
	if len(rep.Steps) != 1 {
		t.Errorf("the chain should stop at DNS, got %v", names(rep))
	}
}
