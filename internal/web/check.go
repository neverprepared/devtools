// Package web diagnoses an HTTP endpoint by walking the chain in order - DNS,
// TCP, TLS, then HTTP - so a report names the first link that is broken rather
// than collapsing every possible cause into one opaque error.
package web

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/neverprepared/devtools/internal/check"
)

// Options configures a check run.
type Options struct {
	Target string

	// Transport
	Method       string
	Headers      []string
	HostHeader   string
	SNI          string
	ResolveTo    string // force the connection to this IP, keeping Host and SNI
	DNSServer    string // query this resolver instead of the system one
	Timeout      time.Duration
	Insecure     bool
	MinTLS       string
	Follow       bool
	MaxRedirects int
	MaxBody      int64
	UserAgent    string

	// Expectations
	ExpectStatus  check.StatusMatcher
	ExpectBody    []check.BodyExpectation
	ExpectHeaders []check.HeaderExpectation
	MaxTTFB       time.Duration

	// Policy
	WarnCertDays int
	ProbeAllIPs  bool
}

// DefaultOptions returns the tuned defaults.
func DefaultOptions() Options {
	return Options{
		Method:       "GET",
		Timeout:      10 * time.Second,
		Follow:       true,
		MaxRedirects: 10,
		MaxBody:      256 << 10,
		UserAgent:    "devtools-web-check",
		WarnCertDays: 30,
		ProbeAllIPs:  true,
	}
}

// maxProbedIPs caps the TCP phase so a name with a large answer set does not
// turn one check into a port scan.
const maxProbedIPs = 8

// Run walks the chain and returns a report. The error return is for problems
// that prevented the check from running at all (a bad URL, a bad flag); a
// failed check is reported in the Report, not as an error.
func Run(ctx context.Context, o Options) (*check.Report, error) {
	target, err := NormalizeURL(o.Target)
	if err != nil {
		return nil, err
	}
	o.Target = target.String()

	rep := check.NewReport("web check", o.Target)
	host := target.Hostname()
	port := target.Port()
	https := target.Scheme == "https"
	if port == "" {
		if https {
			port = "443"
		} else {
			port = "80"
		}
	}
	sni := o.SNI
	if sni == "" {
		sni = host
	}
	minTLS, err := ParseTLSVersion(o.MinTLS)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}

	if proxies := CheckProxyEnv(target); proxies != "" {
		rep.Add(check.Warnf("proxy env", "%s is set but this check connects directly, so curl may behave differently", proxies))
	}

	// --- DNS ---
	pinned := ""
	if o.ResolveTo != "" {
		ip := net.ParseIP(o.ResolveTo)
		if ip == nil {
			return nil, fmt.Errorf("--resolve-to %q is not an IP address", o.ResolveTo)
		}
		pinned = net.JoinHostPort(o.ResolveTo, port)
		rep.Add(check.Skipf("dns", "skipped: --resolve-to pins %s (%s)", o.ResolveTo, Scope(ip)))
	} else {
		resolver, resolverName, err := Resolver(o.DNSServer)
		if err != nil {
			return nil, err
		}
		dnsCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		info, err := LookupHost(dnsCtx, resolver, resolverName, host)
		cancel()
		rep.Set("dns", info)

		if err != nil {
			rep.Add(check.Failf("dns", "%s did not resolve via %s: %v", host, resolverName, err).
				Note("a private name that fails here usually means the wrong resolver, not a missing record: retry with --resolver <vpc-resolver-ip>"))
			rep.Finalize(false)
			return rep, nil
		}

		res := check.OK("dns", "%s -> %s via %s", host, strings.Join(info.IPs(), ", "), info.Resolver).
			Elapsed(time.Duration(info.ElapsedMS * float64(time.Millisecond)))
		if info.CNAME != "" {
			res = res.Note("CNAME %s", info.CNAME)
		}
		switch {
		case info.Mixed():
			res.Status = check.Warn
			res = res.Note("answer mixes private and public addresses, which usually means a split-horizon zone is only half in place")
		case info.Private():
			res = res.Note("all addresses are private, as a private endpoint should be")
		}
		rep.Add(res)

		// --- TCP ---
		probe := info.Addrs
		if !o.ProbeAllIPs && len(probe) > 1 {
			probe = probe[:1]
		}
		if len(probe) > maxProbedIPs {
			probe = probe[:maxProbedIPs]
		}
		var reachable []string
		for _, a := range probe {
			addr := net.JoinHostPort(a.IP, port)
			start := time.Now()
			d := net.Dialer{Timeout: o.Timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			elapsed := time.Since(start)
			if err != nil {
				rep.Add(check.Failf("tcp "+a.IP, "%s unreachable: %v", addr, err).Elapsed(elapsed))
				continue
			}
			_ = conn.Close()
			reachable = append(reachable, a.IP)
			rep.Add(check.OK("tcp "+a.IP, "%s open", addr).Elapsed(elapsed))
		}
		if len(reachable) == 0 {
			rep.Add(check.Failf("tcp", "none of the %d probed address(es) accepted a connection on port %s",
				len(probe), port))
			rep.Finalize(false)
			return rep, nil
		}
		if len(reachable) < len(probe) {
			rep.Add(check.Warnf("tcp", "%d of %d addresses reachable, so some targets behind this name are down",
				len(reachable), len(probe)))
		}
		pinned = net.JoinHostPort(reachable[0], port)
	}

	// --- TLS ---
	insecureHTTP := o.Insecure
	if https {
		tlsCtx, cancel := context.WithTimeout(ctx, o.Timeout)
		info, err := ProbeTLS(tlsCtx, pinned, sni, minTLS)
		cancel()
		rep.Set("tls", info)

		if err != nil {
			rep.Add(check.Failf("tls", "handshake with %s (SNI %s) failed: %v", pinned, sni, err))
			rep.Finalize(false)
			return rep, nil
		}

		handshake := check.OK("tls", "%s, %s", info.Version, info.CipherSuite).
			Elapsed(time.Duration(info.ElapsedMS * float64(time.Millisecond)))
		switch {
		case !info.ChainTrusted && !info.NameMatches:
			handshake = check.Failf("tls", "certificate is untrusted and for the wrong name").
				Note("chain: %s", info.ChainError).
				Note("name: %s", info.NameError)
		case !info.ChainTrusted:
			handshake = check.Failf("tls", "certificate chain is not trusted: %s", info.ChainError)
			switch {
			case strings.Contains(info.ChainError, "expired or is not yet valid"):
				handshake = handshake.Note("the chain failed on validity dates, not on the CA: see the cert line below")
			case strings.Contains(info.ChainError, "unknown authority"):
				handshake = handshake.Note("chain length %d; a private CA has to be in the system keychain to be trusted here", info.ChainLength)
			}
		case !info.NameMatches:
			handshake = check.Failf("tls", "certificate is not valid for %s: %s", sni, info.NameError).
				Note("SANs: %s", info.SANSummary(6))
		}
		if o.Insecure && handshake.Status == check.Fail {
			handshake.Status = check.Warn
			handshake = handshake.Note("downgraded to a warning by --insecure")
		}
		rep.Add(handshake)
		// Keep going over an untrusted connection so the report can still show
		// what the server returns; that distinction is the useful part.
		if handshake.Status == check.Fail {
			insecureHTTP = true
		}

		cert := check.OK("cert", "CN=%s, issuer=%s, %d days left (expires %s)",
			CommonName(info.Subject), CommonName(info.Issuer), info.DaysLeft, info.NotAfter)
		switch {
		case info.DaysLeft < 0:
			cert = check.Failf("cert", "expired %d days ago (%s)", -info.DaysLeft, info.NotAfter)
		case info.DaysLeft <= o.WarnCertDays:
			cert = check.Warnf("cert", "expires in %d days (%s), issuer=%s",
				info.DaysLeft, info.NotAfter, CommonName(info.Issuer))
		}
		if info.SelfSigned {
			cert = cert.Note("self-signed")
		}
		if len(info.DNSNames) > 0 {
			cert = cert.Note("SANs: %s", info.SANSummary(6))
		}
		rep.Add(cert)
	} else {
		rep.Add(check.Skipf("tls", "plain HTTP, no handshake"))
	}

	// --- HTTP ---
	reqCtx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	resp, err := Request(reqCtx, o.Target, requestOptions{
		Method:       o.Method,
		Headers:      o.Headers,
		HostHeader:   o.HostHeader,
		SNI:          sni,
		PinHost:      host,
		PinPort:      port,
		PinAddr:      pinned,
		Insecure:     insecureHTTP,
		MinTLS:       minTLS,
		Follow:       o.Follow,
		MaxRedirects: o.MaxRedirects,
		MaxBody:      o.MaxBody,
		UserAgent:    o.UserAgent,
		Timeout:      o.Timeout,
	})
	if resp != nil {
		rep.Timing = &resp.Timing
		// The request dials a pinned address, so its trace records no lookup;
		// show the DNS phase's own measurement instead.
		if rep.Timing.DNSMS == 0 {
			if info, ok := rep.Data["dns"].(DNSInfo); ok {
				rep.Timing.DNSMS = info.ElapsedMS
			}
		}
		rep.Set("http", resp)
	}
	if err != nil {
		rep.Add(check.Failf("http", "%s %s failed: %v", o.Method, o.Target, err))
		rep.Finalize(false)
		return rep, nil
	}

	httpRes := check.OK("http", "%s %s", resp.StatusText, resp.Proto).
		Elapsed(time.Duration(resp.Timing.TotalMS * float64(time.Millisecond)))
	if resp.Status >= 500 {
		httpRes.Status = check.Fail
	} else if resp.Status >= 400 {
		httpRes.Status = check.Warn
	}
	if resp.RemoteAddr != "" {
		httpRes = httpRes.Note("served by %s", resp.RemoteAddr)
	}
	if ct := resp.Headers.Get("Content-Type"); ct != "" {
		truncated := ""
		if resp.BodyTrimmed {
			truncated = " (truncated at --max-body)"
		}
		httpRes = httpRes.Note("%s, %d bytes read%s", ct, resp.BodyBytes, truncated)
	}
	rep.Add(httpRes)

	if len(resp.Hops) > 0 {
		res := check.OK("redirects", "%d hop(s) to %s", len(resp.Hops), resp.URL)
		for _, h := range resp.Hops {
			res = res.Note("%s -> %s", h.URL, h.Location)
		}
		if !o.Follow {
			res.Status = check.Skip
			res.Detail = fmt.Sprintf("%d hop(s) not followed (--no-follow)", len(resp.Hops))
		}
		rep.Add(res)
	}

	// --- assertions ---
	if !o.ExpectStatus.IsZero() {
		if o.ExpectStatus.Match(resp.Status) {
			rep.Add(check.OK("expect status", "%d matches %s", resp.Status, o.ExpectStatus))
		} else {
			rep.Add(check.Failf("expect status", "got %d, want %s", resp.Status, o.ExpectStatus))
		}
	}
	for _, h := range o.ExpectHeaders {
		rep.Add(h.Check(resp.Headers))
	}
	for _, b := range o.ExpectBody {
		res := b.Check(resp.Body())
		if res.Status == check.Fail && resp.BodyTrimmed {
			res = res.Note("body was truncated at %d bytes; raise --max-body", o.MaxBody)
		}
		rep.Add(res)
	}
	if o.MaxTTFB > 0 {
		ttfb := time.Duration(resp.Timing.TTFBMS * float64(time.Millisecond))
		if ttfb <= o.MaxTTFB {
			rep.Add(check.OK("expect ttfb", "%s within %s", ttfb.Round(time.Millisecond), o.MaxTTFB))
		} else {
			rep.Add(check.Failf("expect ttfb", "%s exceeds %s", ttfb.Round(time.Millisecond), o.MaxTTFB))
		}
	}

	rep.Add(SecurityHeaderReview(resp.Headers, https))
	return rep, nil
}

// NormalizeURL accepts the shapes people actually type: a bare host, a
// host:port, or a full URL. A bare host defaults to https.
func NormalizeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no target given")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("bad target %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported scheme %q (want http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("bad target %q: no host", raw)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}
