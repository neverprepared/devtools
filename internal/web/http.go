package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/neverprepared/devtools/internal/check"
)

// Hop is one step of a redirect chain.
type Hop struct {
	Status   int    `json:"status"`
	URL      string `json:"url"`
	Location string `json:"location,omitempty"`
}

// HTTPInfo is the outcome of the request phase.
type HTTPInfo struct {
	URL         string       `json:"url"`
	Method      string       `json:"method"`
	Status      int          `json:"status"`
	StatusText  string       `json:"status_text"`
	Proto       string       `json:"proto"`
	Hops        []Hop        `json:"hops,omitempty"`
	Headers     http.Header  `json:"headers"`
	BodyBytes   int64        `json:"body_bytes"`
	BodyTrimmed bool         `json:"body_trimmed,omitempty"`
	RemoteAddr  string       `json:"remote_addr,omitempty"`
	Timing      check.Timing `json:"timing"`

	body []byte
}

// Body returns the (possibly truncated) response body.
func (h HTTPInfo) Body() []byte { return h.body }

// requestOptions is the subset of Options the HTTP phase needs.
type requestOptions struct {
	Method       string
	Headers      []string
	HostHeader   string
	SNI          string
	PinHost      string // hostname whose dials get redirected to PinAddr
	PinPort      string // only dials to this port are pinned
	PinAddr      string // host:port actually dialled
	Insecure     bool
	MinTLS       uint16
	Follow       bool
	MaxRedirects int
	MaxBody      int64
	UserAgent    string
	Timeout      time.Duration
}

// Request performs the HTTP request, recording the redirect chain and a
// per-phase timing breakdown.
//
// The connection is pinned to the address the earlier phases probed, so the
// report describes one consistent path rather than two independent resolutions.
// Redirects to a different host resolve normally.
func Request(ctx context.Context, target string, o requestOptions) (*HTTPInfo, error) {
	info := &HTTPInfo{URL: target, Method: o.Method}

	transport := &http.Transport{
		// Pinned dialling is incompatible with proxy semantics, so this goes
		// direct. CheckProxyEnv reports when that differs from curl.
		Proxy:               nil,
		DisableKeepAlives:   true,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: o.Timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			d := &net.Dialer{Timeout: o.Timeout}
			// Pin only the exact host:port the earlier phases probed. A
			// redirect to another host, or to the same host on another port
			// (the usual http -> https bounce), must resolve normally.
			host, port, err := net.SplitHostPort(addr)
			if err == nil && o.PinAddr != "" && port == o.PinPort && strings.EqualFold(host, o.PinHost) {
				addr = o.PinAddr
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         o.SNI,
			InsecureSkipVerify: o.Insecure,
			MinVersion:         o.MinTLS,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			last := via[len(via)-1]
			info.Hops = append(info.Hops, Hop{
				URL:      last.URL.String(),
				Location: req.URL.String(),
			})
			if !o.Follow {
				return http.ErrUseLastResponse
			}
			if len(via) > o.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", o.MaxRedirects)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, o.Method, target, nil)
	if err != nil {
		return info, err
	}
	for _, h := range o.Headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return info, fmt.Errorf("--header %q is not Name: Value", h)
		}
		req.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if o.UserAgent != "" {
		req.Header.Set("User-Agent", o.UserAgent)
	}
	if o.HostHeader != "" {
		req.Host = o.HostHeader
	}

	var (
		start                            = time.Now()
		dnsStart, connectStart, tlsStart time.Time
		t                                = &info.Timing
	)
	// Each field is recorded once: on a redirect chain the trace fires per
	// connection, and the first connection is the one being diagnosed.
	setOnce := func(dst *float64, d time.Duration) {
		if *dst == 0 {
			*dst = float64(d.Microseconds()) / 1000
		}
	}
	trace := &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:      func(httptrace.DNSDoneInfo) { setOnce(&t.DNSMS, time.Since(dnsStart)) },
		ConnectStart: func(string, string) { connectStart = time.Now() },
		ConnectDone: func(_, addr string, err error) {
			if err == nil {
				setOnce(&t.ConnectMS, time.Since(connectStart))
				// Last wins: after a redirect the HTTP step describes the
				// final response, so name the host that actually served it.
				info.RemoteAddr = addr
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			setOnce(&t.TLSMS, time.Since(tlsStart))
		},
		GotFirstResponseByte: func() { setOnce(&t.TTFBMS, time.Since(start)) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := client.Do(req)
	if err != nil {
		t.TotalMS = float64(time.Since(start).Microseconds()) / 1000
		return info, err
	}
	defer resp.Body.Close()

	limit := o.MaxBody
	if limit <= 0 {
		limit = 256 << 10
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(body)) > limit {
		body, info.BodyTrimmed = body[:limit], true
	}
	t.TotalMS = float64(time.Since(start).Microseconds()) / 1000

	info.Status = resp.StatusCode
	info.StatusText = resp.Status
	info.Proto = resp.Proto
	info.Headers = resp.Header
	info.body = body
	info.BodyBytes = int64(len(body))
	if resp.Request != nil && resp.Request.URL != nil {
		info.URL = resp.Request.URL.String()
	}
	if readErr != nil {
		return info, fmt.Errorf("reading body: %w", readErr)
	}
	return info, nil
}

// securityHeaders are the response headers whose absence is worth a nudge.
var securityHeaders = []struct {
	Name  string
	Why   string
	HTTPS bool // only meaningful over TLS
}{
	{Name: "Strict-Transport-Security", Why: "no HSTS", HTTPS: true},
	{Name: "Content-Security-Policy", Why: "no CSP"},
	{Name: "X-Content-Type-Options", Why: "no nosniff"},
	{Name: "Referrer-Policy", Why: "no referrer policy"},
}

// SecurityHeaderReview reports which recommended headers are missing. It is
// advisory: a missing header is a warning, never a failure.
func SecurityHeaderReview(h http.Header, https bool) check.Result {
	var missing []string
	for _, sh := range securityHeaders {
		if sh.HTTPS && !https {
			continue
		}
		if h.Get(sh.Name) == "" {
			missing = append(missing, sh.Why)
		}
	}
	// CSP frame-ancestors supersedes X-Frame-Options; accept either.
	if h.Get("X-Frame-Options") == "" && !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors") {
		missing = append(missing, "no frame protection")
	}
	if len(missing) == 0 {
		return check.OK("security headers", "HSTS, CSP, nosniff, referrer and frame protection all present")
	}
	return check.Warnf("security headers", "%s", strings.Join(missing, ", "))
}

// CheckProxyEnv reports a proxy configuration that would change how other
// tools behave, since this command always connects directly.
func CheckProxyEnv(target *url.URL) string {
	var set []string
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if v := os.Getenv(name); v != "" {
			set = append(set, name+"="+v)
		}
	}
	if len(set) == 0 {
		return ""
	}
	if noProxy := os.Getenv("NO_PROXY") + os.Getenv("no_proxy"); noProxy != "" &&
		strings.Contains(noProxy, target.Hostname()) {
		return ""
	}
	return strings.Join(set, ", ")
}
