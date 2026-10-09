package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/check"
	"github.com/neverprepared/devtools/internal/web"
)

func newWebCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Diagnose and assert on HTTP endpoints",
	}
	cmd.AddCommand(newWebCheckCmd())
	return cmd
}

func newWebCheckCmd() *cobra.Command {
	o := web.DefaultOptions()
	var (
		expectStatus string
		expectBody   []string
		expectHeader []string
		noFollow     bool
		firstIPOnly  bool
	)

	cmd := &cobra.Command{
		Use:     "check <url|host>",
		Aliases: []string{"get"},
		Short:   "Walk DNS, TCP, TLS and HTTP in order and report the first broken link",
		Long: `Diagnose an HTTP endpoint one layer at a time.

Each phase is probed separately so the report names what is actually broken
instead of collapsing every cause into one error: DNS resolution (and which
resolver answered, and whether the answer is private), TCP reachability of every
resolved address, the TLS handshake with chain trust and hostname match reported
separately, then the HTTP request with a per-phase timing breakdown.

A bare host is assumed to be https. Exit codes: 0 all good, 2 a step or
assertion failed, 3 warnings only with --strict, 1 the check could not run.

Examples:
  devtools web check example.com
  devtools web check https://api.internal/health --expect-status 200 --expect-body '"ok"'
  devtools web check https://app.internal --resolver 10.0.0.2
  devtools web check https://app.internal --resolve-to 10.1.2.3
  devtools web check https://app.internal --expect-header 'cache-control~no-store' --strict
  devtools web check https://api.internal/health --json | jq .data.tls.days_left`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			o.Target = args[0]
			o.Follow = !noFollow
			o.ProbeAllIPs = !firstIPOnly

			if expectStatus != "" {
				m, err := check.ParseStatusMatcher(expectStatus)
				if err != nil {
					return fmt.Errorf("--expect-status: %w", err)
				}
				o.ExpectStatus = m
			}
			for _, spec := range expectBody {
				b, err := check.ParseBodyExpectation(spec)
				if err != nil {
					return fmt.Errorf("--expect-body: %w", err)
				}
				o.ExpectBody = append(o.ExpectBody, b)
			}
			for _, spec := range expectHeader {
				h, err := check.ParseHeaderExpectation(spec)
				if err != nil {
					return fmt.Errorf("--expect-header: %w", err)
				}
				o.ExpectHeaders = append(o.ExpectHeaders, h)
			}

			rep, err := web.Run(c.Context(), o)
			if err != nil {
				return err
			}
			return emitReport(c, rep)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&o.Method, "method", "X", o.Method, "HTTP method")
	f.StringArrayVarP(&o.Headers, "header", "H", nil, "request header as 'Name: Value' (repeatable)")
	f.StringVar(&o.HostHeader, "host", "", "override the Host header (test a vhost without DNS)")
	f.StringVar(&o.SNI, "sni", "", "override the TLS server name (defaults to the URL host)")
	f.StringVar(&o.ResolveTo, "resolve-to", "", "connect to this IP, keeping Host and SNI (bypass DNS entirely)")
	f.StringVar(&o.DNSServer, "resolver", "", "query this DNS server instead of the system resolver")
	f.DurationVar(&o.Timeout, "timeout", o.Timeout, "per-phase timeout")
	f.BoolVarP(&o.Insecure, "insecure", "k", false, "downgrade certificate failures to warnings")
	f.StringVar(&o.MinTLS, "min-tls", "", "require at least this TLS version (1.0, 1.1, 1.2, 1.3)")
	f.BoolVar(&noFollow, "no-follow", false, "report redirects without following them")
	f.IntVar(&o.MaxRedirects, "max-redirects", o.MaxRedirects, "redirect limit")
	f.Int64Var(&o.MaxBody, "max-body", o.MaxBody, "bytes of body to read for assertions")
	f.StringVar(&o.UserAgent, "user-agent", o.UserAgent, "User-Agent header")
	f.BoolVar(&firstIPOnly, "first-ip-only", false, "probe only the first resolved address instead of all of them")
	f.IntVar(&o.WarnCertDays, "warn-cert-days", o.WarnCertDays, "warn when the certificate expires within this many days")

	f.StringVar(&expectStatus, "expect-status", "", "assert the status code: 200, 2xx, or a list like 200,204")
	f.StringArrayVar(&expectBody, "expect-body", nil, "assert the body contains text, ~regex, or !text for absence (repeatable)")
	f.StringArrayVar(&expectHeader, "expect-header", nil, "assert a header: Name, Name=value, Name~regex, or !Name (repeatable)")
	f.DurationVar(&o.MaxTTFB, "max-ttfb", 0, "assert time to first byte stays under this")

	return cmd
}

// emitReport renders a report in the requested format and converts its exit
// code into an error cobra can carry out to main.
func emitReport(c *cobra.Command, rep *check.Report) error {
	code := rep.Finalize(g.strict)

	w := c.OutOrStdout()
	if g.json {
		if err := rep.RenderJSON(w); err != nil {
			return err
		}
	} else {
		rep.RenderText(w)
	}
	if code == check.ExitOK {
		return nil
	}
	return &ExitError{Code: code}
}
